//! cwrunix-subid-map: the only setuid component of the CWRUnix login
//! sandbox, plus the in-sandbox client shims. Roles, selected by argv[0]:
//!
//!   cwrunix-subid-map <pid>
//!       Host side (setuid root via a security.wrappers entry in the server
//!       config), called by `cwrunix-sandbox login`: write the OUTER user
//!       namespace's full id map for the caller's freshly-unshared child:
//!           0  <caller id>  1        (root-in-ns = the member; tooling)
//!           1  <subid start>  131072 (the member's subordinate range)
//!       The range is computed from the caller's own id — nothing about the
//!       map is attacker-controlled. The target must be owned by the caller
//!       and still unmapped; the kernel enforces the rest (single write;
//!       outer ids must exist in the parent namespace). Ranges are disjoint
//!       per id and start above NixOS' auto-allocation pool.
//!
//!   newuidmap <pid> <inner> <outer> <count> ...   (and newgidmap)
//!       In-sandbox CLIENT (plain symlink, no privilege — bwrap mounts are
//!       MS_NOSUID, so setuid tricks can't work there): forwards the request
//!       to the session's map agent over /run/cwrunix-subid.d/subid, passing
//!       an O_PATH handle to the target's /proc dir via SCM_RIGHTS (pids
//!       from nested namespaces are meaningless to the agent). The agent
//!       validates the fixed shape and does the privileged write.

use std::process::ExitCode;

/// authentik issues LDAP uidNumbers/gidNumbers starting at 2000 (see
/// nixos/admins/tev.nix in the server config). Ids outside this range get
/// the single-uid sandbox instead.
const ID_MIN: u32 = 2000;
const ID_MAX: u32 = 12000;
/// First allocated subid for id 2000; each id gets 2*64k (one id drives the
/// in-sandbox agent's kuid, the rest backs the container range).
const SUBID_BASE: u64 = 1_910_000_000;
const SUBID_COUNT: u64 = 2 * 65536;

/// Where the client shim finds the session's map agent.
const AGENT_SOCKET: &str = "/run/cwrunix-subid.d/subid";

fn fail(msg: impl std::fmt::Display) -> ! {
    eprintln!("cwrunix-subid-map: {msg}");
    std::process::exit(1);
}

fn getuid() -> u32 {
    unsafe { libc::getuid() }
}

fn getgid() -> u32 {
    unsafe { libc::getgid() }
}

/// The target process must be owned by the caller and sit in a freshly
/// created (unmapped) user namespace. Directory ownership via stat renders
/// in our own namespace view, consistent with getuid()/getgid().
fn check_target(pid: u32, uid: u32, gid: u32) {
    use std::os::unix::fs::MetadataExt;
    let dir = format!("/proc/{pid}");
    let meta = std::fs::metadata(&dir)
        .unwrap_or_else(|_| fail(format!("process {pid} not found or not yours")));
    if meta.uid() != uid || meta.gid() != gid {
        fail(format!("process {pid} is not owned by uid {uid}"));
    }
    for kind in ["uid_map", "gid_map"] {
        let map = std::fs::read_to_string(format!("/proc/{pid}/{kind}"))
            .unwrap_or_else(|e| fail(format!("reading /proc/{pid}/{kind}: {e}")));
        if !map.is_empty() {
            fail(format!("process {pid} already has an id map"));
        }
    }
}

fn write_map(pid: u32, kind: &str, content: &str) {
    std::fs::write(format!("/proc/{pid}/{kind}"), content)
        .unwrap_or_else(|e| fail(format!("writing /proc/{pid}/{kind}: {e}")));
}

/// Host role: `cwrunix-subid-map <pid>`.
fn host_map() -> ExitCode {
    let arg = std::env::args().nth(1).unwrap_or_else(|| fail("missing pid"));
    let pid: u32 = arg.parse().unwrap_or_else(|_| fail(format!("bad pid '{arg}'")));
    let uid = getuid();
    let gid = getgid();
    if !(ID_MIN..ID_MAX).contains(&uid) || !(ID_MIN..ID_MAX).contains(&gid) {
        fail(format!("uid/gid {uid}/{gid} outside member range"));
    }
    check_target(pid, uid, gid);

    let subuid = SUBID_BASE + u64::from(uid - ID_MIN) * SUBID_COUNT;
    let subgid = SUBID_BASE + u64::from(gid - ID_MIN) * SUBID_COUNT;
    write_map(pid, "uid_map", &format!("0 {uid} 1\n1 {subuid} {SUBID_COUNT}\n"));
    write_map(pid, "gid_map", &format!("0 {gid} 1\n1 {subgid} {SUBID_COUNT}\n"));
    ExitCode::SUCCESS
}

/// The agent runs in the INITIAL pid namespace while callers (e.g. podman
/// inside the sandbox) pass pids from nested namespaces — and a process
/// cannot see its own outer pid (NSpid only shows the reader's own level).
/// So instead of translating the number, we pass an O_PATH handle to the
/// target's /proc dir over the socket (SCM_RIGHTS): an fd pins the exact
/// task, works across namespaces, and carries no access rights — the agent
/// re-verifies everything and re-opens the map file with its own privilege.
fn open_proc_dir(pid: u32) -> i32 {
    let path = std::ffi::CString::new(format!("/proc/{pid}")).unwrap();
    let fd = unsafe { libc::open(path.as_ptr(), libc::O_PATH | libc::O_DIRECTORY | libc::O_CLOEXEC) };
    if fd < 0 {
        fail(format!(
            "opening /proc/{pid}: {}",
            std::io::Error::last_os_error()
        ));
    }
    fd
}

/// Send `data` and `fd` in a single message (fd travels via SCM_RIGHTS).
fn send_with_fd(sock: &std::os::unix::net::UnixStream, data: &[u8], fd: i32) {
    use std::os::unix::io::AsRawFd;
    let mut iov = libc::iovec {
        iov_base: data.as_ptr() as *mut _,
        iov_len: data.len(),
    };
    let mut cspace = [0u8; unsafe { libc::CMSG_SPACE(4) } as usize];
    let mut msg: libc::msghdr = unsafe { std::mem::zeroed() };
    msg.msg_iov = &mut iov;
    msg.msg_iovlen = 1;
    msg.msg_control = cspace.as_mut_ptr() as *mut _;
    msg.msg_controllen = cspace.len() as _;
    unsafe {
        let cmsg = libc::CMSG_FIRSTHDR(&msg);
        (*cmsg).cmsg_level = libc::SOL_SOCKET;
        (*cmsg).cmsg_type = libc::SCM_RIGHTS;
        (*cmsg).cmsg_len = libc::CMSG_LEN(4) as _;
        std::ptr::copy_nonoverlapping(&fd, libc::CMSG_DATA(cmsg) as *mut i32, 1);
        let n = libc::sendmsg(sock.as_raw_fd(), &msg, 0);
        if n < 0 {
            fail(format!("sending to the map agent: {}", std::io::Error::last_os_error()));
        }
    }
}

/// In-sandbox client role (argv[0] = newuidmap/newgidmap): parse the stock
/// helper's argument format and forward it to the session's map agent.
/// Exit status is 0 only when the agent answers "ok".
fn sandbox_client(is_uid: bool) -> ExitCode {
    use std::io::Read;
    use std::os::unix::net::UnixStream;

    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.len() < 5 || !(args.len() - 1).is_multiple_of(3) {
        fail(format!(
            "usage: {} <pid> <inner> <outer> <count> ...",
            if is_uid { "newuidmap" } else { "newgidmap" }
        ));
    }
    let pid: u32 = args[0].parse().unwrap_or_else(|_| fail("bad pid"));
    for t in &args[1..] {
        t.parse::<u32>()
            .unwrap_or_else(|_| fail(format!("bad number '{t}'")));
    }
    let kind = if is_uid { "uid" } else { "gid" };
    let request = format!("{kind}\n{}\n", args[1..].join(" "));
    let dirfd = open_proc_dir(pid);

    let mut sock = UnixStream::connect(AGENT_SOCKET)
        .unwrap_or_else(|e| fail(format!("connecting to the session map agent: {e}")));
    send_with_fd(&sock, request.as_bytes(), dirfd);
    unsafe { libc::close(dirfd) };
    if let Err(e) = sock.shutdown(std::net::Shutdown::Write) {
        fail(format!("writing to the map agent: {e}"));
    }
    let mut reply = String::new();
    if let Err(e) = sock.read_to_string(&mut reply) {
        fail(format!("reading from the map agent: {e}"));
    }
    let ok = reply.trim_end() == "ok";
    if !ok {
        eprintln!("cwrunix-subid-map: agent refused: {}", reply.trim_end());
    }
    if ok {
        ExitCode::SUCCESS
    } else {
        ExitCode::FAILURE
    }
}

fn main() -> ExitCode {
    let argv0 = std::env::args().next().unwrap_or_default();
    let base = std::path::Path::new(&argv0)
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or("");
    match base {
        "newuidmap" => sandbox_client(true),
        "newgidmap" => sandbox_client(false),
        _ => host_map(),
    }
}
