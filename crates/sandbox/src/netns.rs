//! Inner setup shim: runs in the outer user+net+mount namespace created by
//! `login` (see there for the namespace layout). Replaces netns-setup.sh.

use crate::util::*;
use std::{
    ffi::OsString,
    fs,
    os::unix::process::CommandExt,
    path::PathBuf,
    process::{Child, Command, ExitCode},
    time::Duration,
};

struct Flags {
    ip: PathBuf,
    bindfs: PathBuf,
    subid_map_bin: PathBuf,
    /// bwrap argv, then the payload argv, split on a bare "--".
    bwrap_argv: Vec<String>,
    payload: Vec<OsString>,
}

fn parse_args(args: &[OsString]) -> Flags {
    let mut f = Flags {
        ip: PathBuf::new(),
        bindfs: PathBuf::new(),
        subid_map_bin: PathBuf::new(),
        bwrap_argv: Vec::new(),
        payload: Vec::new(),
    };
    let mut it = args.iter();
    while let Some(arg) = it.next() {
        let Some(s) = arg.to_str() else {
            fail("non-utf8 argument")
        };
        if s == "--" {
            let rest: Vec<_> = it.cloned().collect();
            let mut split = rest.splitn(2, |a| a == "--");
            f.bwrap_argv = split
                .next()
                .unwrap_or_default()
                .iter()
                .map(|a| a.to_string_lossy().into_owned())
                .collect();
            f.payload = split.next().unwrap_or_default().to_vec();
            if f.bwrap_argv.is_empty() || f.payload.is_empty() {
                fail("netns-setup needs a bwrap argv and a payload argv");
            }
            return f;
        }
        let value = it
            .next()
            .unwrap_or_else(|| fail(format!("{s} needs a value")));
        match s {
            "--ip" => f.ip = value.clone().into(),
            "--bindfs" => f.bindfs = value.clone().into(),
            "--subid-map-bin" => f.subid_map_bin = value.clone().into(),
            _ => fail(format!("unknown flag {s}")),
        }
    }
    fail("netns-setup: missing '--' separator")
}

/// A spawned child that is SIGKILLed when we die (and whose own children
/// chain the same).
fn spawn_pdeathsig(mut cmd: Command) -> Child {
    unsafe {
        cmd.pre_exec(|| {
            libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL, 0, 0, 0);
            Ok(())
        });
    }
    cmd.spawn()
        .unwrap_or_else(|e| io_fail(format!("spawning child: {e}")))
}

/// Spawn our own binary in `role` inside a fresh user namespace.
fn spawn_userns_holder(role: &str) -> Child {
    let exe = std::env::current_exe().unwrap_or_else(|e| io_fail(format!("current_exe: {e}")));
    let mut cmd = Command::new(exe);
    cmd.arg(role);
    // Never let our own re-exec guard leak into the child.
    cmd.env_remove("CWRUNIX_REEXECED");
    unsafe {
        cmd.pre_exec(|| {
            if libc::unshare(libc::CLONE_NEWUSER) != 0 {
                return Err(std::io::Error::last_os_error());
            }
            libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL, 0, 0, 0);
            Ok(())
        });
    }
    cmd.spawn()
        .unwrap_or_else(|e| io_fail(format!("spawning {role}: {e}")))
}

fn run_ip(ip: &PathBuf, args: &[&str]) -> bool {
    Command::new(ip)
        .args(args)
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

/// Open /proc/<pid>/ns/user and clear CLOEXEC so bwrap inherits the fd.
fn open_ns_fd(pid: u32) -> i32 {
    use std::os::unix::io::IntoRawFd;
    let f = fs::File::open(format!("/proc/{pid}/ns/user"))
        .unwrap_or_else(|e| io_fail(format!("opening userns fd of {pid}: {e}")));
    let fd = f.into_raw_fd();
    unsafe {
        if libc::fcntl(fd, libc::F_SETFD, 0) != 0 {
            io_fail("clearing cloexec on userns fd");
        }
    }
    fd
}

pub fn main(args: &[OsString]) -> ExitCode {
    let mut flags = parse_args(args);

    // We were spawned unmapped (hence capless); once the parent writes our
    // id map, re-exec — exec'ing with euid 0 in this namespace is what
    // grants its capabilities.
    if std::env::var_os("CWRUNIX_REEXECED").is_none() {
        let mapped = wait_until(
            || {
                fs::read_to_string("/proc/self/uid_map")
                    .map(|s| !s.is_empty())
                    .unwrap_or(false)
            },
            Duration::from_secs(10),
        );
        if !mapped {
            fail("id map handshake timed out");
        }
        let err = Command::new("/proc/self/exe")
            .arg("netns-setup")
            .args(args)
            .env("CWRUNIX_REEXECED", "1")
            .exec();
        io_fail(format!("re-exec: {err}"));
    }
    // The privilege-gaining re-exec cleared our pdeathsig; re-arm it so the
    // session still tears down if the outer login process dies.
    rearm_pdeathsig();
    note("netns-setup: mapped + re-exec'd");

    let uid_map = fs::read_to_string("/proc/self/uid_map").unwrap_or_default();
    let full = uid_map.lines().count() > 1;

    // Loopback, then wait for slirp4netns (started from the outside by the
    // parent) to create tap0.
    if !run_ip(&flags.ip, &["link", "set", "dev", "lo", "up"]) {
        io_fail("bringing up loopback");
    }
    let tap_up = wait_until(
        || run_ip(&flags.ip, &["link", "show", "dev", "tap0"]),
        Duration::from_secs(10),
    );
    note(if tap_up { "tap0 up" } else { "tap0 TIMEOUT" });
    if !tap_up {
        eprintln!("login-sandbox: warning: slirp4netns did not create tap0; continuing without network");
    } else {
        for cmd in [
            vec!["addr", "add", "10.0.2.100/24", "dev", "tap0"],
            vec!["link", "set", "tap0", "up"],
            vec!["route", "add", "default", "via", "10.0.2.2"],
        ] {
            if !run_ip(&flags.ip, &cmd) {
                io_fail(format!("configuring tap0 ({cmd:?})"));
            }
        }
    }

    // Read-only FUSE mirror of /nix: page-cache-isolates the store from the
    // host (see login.rs). bindfs(1) reaps itself when the session's private
    // mount namespace dies; pdeathsig covers the rest.
    let fuse_mnt = std::env::var_os("CWRUNIX_NIX_FUSE_MNT")
        .map(PathBuf::from)
        .unwrap_or_else(|| fail("CWRUNIX_NIX_FUSE_MNT unset"));
    let mut bindfs_cmd = Command::new(&flags.bindfs);
    bindfs_cmd.args([
        "-f",
        "-o",
        "ro,entry_timeout=300,attr_timeout=300,negative_timeout=1",
        "/nix",
    ]);
    bindfs_cmd.arg(&fuse_mnt);
    #[allow(clippy::zombie_processes)] // reaped by the pdeathsig cascade, not wait()
    spawn_pdeathsig(bindfs_cmd);
    let up = wait_until(
        || {
            fs::read_to_string("/proc/self/mounts")
                .map(|m| {
                    m.lines().any(|l| {
                        l.split_whitespace()
                            .nth(1)
                            .map(|m| m == fuse_mnt.to_string_lossy())
                            .unwrap_or(false)
                    })
                })
                .unwrap_or(false)
        },
        Duration::from_secs(10),
    );
    if !up {
        fail("FUSE mirror of /nix failed to mount");
    }
    note("fuse mirror mounted");

    let mut bwrap_argv = std::mem::take(&mut flags.bwrap_argv);
    if full {
        let subid_map_bin = flags.subid_map_bin.clone();
        full_mode_setup(&subid_map_bin, &mut bwrap_argv);
    }

    let mut cmd = Command::new(&bwrap_argv[0]);
    cmd.args(&bwrap_argv[1..]).arg("--").args(&flags.payload);
    let mut child = spawn_pdeathsig(cmd);
    note("bwrap spawned");
    let status = child.wait();
    note("bwrap exited");
    match status {
        Ok(s) => ExitCode::from(s.code().unwrap_or(1) as u8),
        Err(e) => io_fail(format!("waiting for bwrap: {e}")),
    }
}

/// The multi-uid path: create the two nested user namespaces bwrap needs
/// (U2 = setup ns, U3 = payload ns; see the design comment in login.rs),
/// link the in-sandbox map-helper shims, spawn the map agent, and splice
/// the namespace args into the bwrap argv.
fn full_mode_setup(subid_map_bin: &PathBuf, bwrap_argv: &mut Vec<String>) {
    let uidmap_dir = std::env::var_os("CWRUNIX_UIDMAP_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|| fail("CWRUNIX_UIDMAP_DIR unset"));

    // U2: bwrap's setup namespace. Its holder re-execs for caps, then spawns
    // and maps U3 (each namespace's map is written from its direct parent).
    #[allow(clippy::zombie_processes)]
    let u2 = spawn_userns_holder("holder-u2");
    let u2_pid = u2.id();
    if !wait_until(
        || ns_differs_from_self(u2_pid, "user") || !pid_alive(u2_pid),
        Duration::from_secs(10),
    ) {
        fail("U2 holder never entered its user namespace");
    }
    // U2: 0 -> U1's 0 (bwrap setup + the member's real id), 1 -> U1's 1
    // (the map agent's kuid, a subordinate id), 65536+ -> U1's 2.. (the
    // container range).
    fs::write(
        format!("/proc/{u2_pid}/uid_map"),
        "0 0 1\n1 1 1\n65536 2 65536\n",
    )
    .unwrap_or_else(|e| io_fail(format!("writing U2 uid_map: {e}")));
    fs::write(
        format!("/proc/{u2_pid}/gid_map"),
        "0 0 1\n1 1 1\n65536 2 65536\n",
    )
    .unwrap_or_else(|e| io_fail(format!("writing U2 gid_map: {e}")));

    // holder-u2 signals via the marker once U3 exists and is mapped.
    let u3_marker = uidmap_dir.join("u3");
    let got = wait_until(|| u3_marker.exists(), Duration::from_secs(10));
    note(if got { "u3 marker seen" } else { "u3 marker TIMEOUT" });
    if !got {
        fail("U3 namespace setup timed out");
    }
    let u3_pid: u32 = fs::read_to_string(&u3_marker)
        .unwrap_or_else(|e| io_fail(format!("reading u3 marker: {e}")))
        .trim()
        .parse()
        .unwrap_or_else(|_| fail("bad u3 pid in marker"));

    // The in-sandbox newuidmap/newgidmap: plain symlinks (client mode of
    // the subid-map binary — bwrap mounts are MS_NOSUID, so no setuid trick
    // can work here). The actual privileged write is done by the session's
    // map agent, which lives in the payload namespace with a subid kuid
    // (uid 0 there) and serves /run/cwrunix-subid.d/subid.
    let bin_dir = uidmap_dir.parent().unwrap().join("bin");
    for name in ["newuidmap", "newgidmap"] {
        let dest = bin_dir.join(name);
        std::os::unix::fs::symlink(subid_map_bin, &dest)
            .unwrap_or_else(|e| io_fail(format!("linking {name}: {e}")));
    }

    let fd_u2 = open_ns_fd(u2_pid);
    let fd_u3 = open_ns_fd(u3_pid);

    // Spawn the map agent inside U3 (joining a descendant userns grants its
    // caps; setuid to 0 there — a subid outside — keeps them across exec).
    spawn_map_agent(fd_u3, &uidmap_dir);

    // Splice the namespace/uid/cap args in behind the bwrap path.
    let ns_args: Vec<String> = vec![
        "--userns".into(),
        fd_u2.to_string(),
        "--userns2".into(),
        fd_u3.to_string(),
        "--uid".into(),
        "0".into(),
        "--gid".into(),
        "0".into(),
        "--cap-drop".into(),
        "ALL".into(),
    ];
    bwrap_argv.splice(1..1, ns_args);

    // Tell the parent the payload is about to start (its relaunch-on-failure
    // check keys off this).
    fs::write(uidmap_dir.join("bwrap-started"), "").unwrap_or_else(|e| io_fail(format!("marker: {e}")));
}

/// The U2 namespace holder + U3 bootstrap. Runs unmapped and capless until
/// netns-setup writes U2's map; then re-execs (caps) and sets up U3.
pub fn holder_u2(args: &[OsString]) -> ! {
    if std::env::var_os("CWRUNIX_REEXECED").is_none() {
        let mapped = wait_until(
            || {
                fs::read_to_string("/proc/self/uid_map")
                    .map(|s| !s.is_empty())
                    .unwrap_or(false)
            },
            Duration::from_secs(10),
        );
        if !mapped {
            fail("holder-u2: id map handshake timed out");
        }
        let err = Command::new("/proc/self/exe")
            .arg("holder-u2")
            .args(args)
            .env("CWRUNIX_REEXECED", "1")
            .exec();
        io_fail(format!("holder-u2 re-exec: {err}"));
    }
    // Same privilege-gaining re-exec as netns-setup: pdeathsig was cleared;
    // re-arm so we die with netns-setup (and cascade to the U3 holder).
    rearm_pdeathsig();
    note("holder-u2: mapped + re-exec'd");

    let uidmap_dir = std::env::var_os("CWRUNIX_UIDMAP_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|| fail("CWRUNIX_UIDMAP_DIR unset"));
    let uid: u32 = std::env::var("CWRUNIX_MEMBER_UID")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or_else(|| fail("CWRUNIX_MEMBER_UID unset"));
    let gid: u32 = std::env::var("CWRUNIX_MEMBER_GID")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or_else(|| fail("CWRUNIX_MEMBER_GID unset"));

    // U3: the payload namespace. Its map (written from here, its parent):
    // the member's own ids at their own number, the helper's owner at 0,
    // and the container range at 65536+.
    #[allow(clippy::zombie_processes)]
    let u3 = spawn_userns_holder("holder");
    let u3_pid = u3.id();
    if !wait_until(
        || ns_differs_from_self(u3_pid, "user") || !pid_alive(u3_pid),
        Duration::from_secs(10),
    ) {
        fail("U3 holder never entered its user namespace");
    }
    fs::write(
        format!("/proc/{u3_pid}/uid_map"),
        format!("{uid} 0 1\n0 1 1\n65536 65536 65536\n"),
    )
    .unwrap_or_else(|e| io_fail(format!("writing U3 uid_map: {e}")));
    fs::write(
        format!("/proc/{u3_pid}/gid_map"),
        format!("{gid} 0 1\n0 1 1\n65536 65536 65536\n"),
    )
    .unwrap_or_else(|e| io_fail(format!("writing U3 gid_map: {e}")));

    fs::write(uidmap_dir.join("u3"), format!("{u3_pid}\n"))
        .unwrap_or_else(|e| io_fail(format!("writing u3 marker: {e}")));
    park()
}

/// Spawn the session's map agent inside the payload namespace (U3): it
/// joins U3 (granting its capabilities), becomes uid 0 there — whose kuid
/// is the member's first subordinate id, never the member — and execs. The
/// result keeps full caps scoped to U3 and its descendants (container
/// namespaces), which is exactly what's needed to write their id maps.
fn spawn_map_agent(fd_u3: i32, uidmap_dir: &std::path::Path) {
    let exe = std::env::current_exe().unwrap_or_else(|e| io_fail(format!("current_exe: {e}")));
    let mut cmd = Command::new(exe);
    cmd.arg("map-agent");
    unsafe {
        cmd.pre_exec(move || {
            if libc::setns(fd_u3, libc::CLONE_NEWUSER) != 0 {
                return Err(std::io::Error::last_os_error());
            }
            if libc::setgroups(0, std::ptr::null()) != 0
                || libc::setgid(0) != 0
                || libc::setuid(0) != 0
            {
                return Err(std::io::Error::last_os_error());
            }
            libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL, 0, 0, 0);
            Ok(())
        });
    }
    #[allow(clippy::zombie_processes)]
    cmd.spawn()
        .unwrap_or_else(|e| io_fail(format!("spawning map agent: {e}")));

    let sock = uidmap_dir.parent().unwrap().join("sock.d").join("subid");
    let sock_up = wait_until(|| sock.exists(), Duration::from_secs(10));
    note(if sock_up {
        "agent socket up"
    } else {
        "agent socket TIMEOUT"
    });
    if !sock_up {
        fail("map agent did not start");
    }
}

/// The session's map agent (the "map-agent" role): serves fixed-shape
/// id-map writes for descendants of the payload namespace (container
/// namespaces created by podman). Runs as uid 0 in U3 with a subid kuid;
/// validation mirrors the in-sandbox portion of cwrunix-subid-map.
pub fn map_agent() -> ExitCode {
    use std::os::unix::net::UnixListener;

    // Our exec was privilege-gaining (setns + setuid 0 in pre_exec), which
    // cleared the pdeathsig armed there; re-arm so the agent dies with the
    // session.
    rearm_pdeathsig();
    note("map-agent: up");
    let uidmap_dir = std::env::var_os("CWRUNIX_UIDMAP_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|| fail("CWRUNIX_UIDMAP_DIR unset"));
    let member_uid: u32 = std::env::var("CWRUNIX_MEMBER_UID")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or_else(|| fail("CWRUNIX_MEMBER_UID unset"));
    let member_gid: u32 = std::env::var("CWRUNIX_MEMBER_GID")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or_else(|| fail("CWRUNIX_MEMBER_GID unset"));

    let sock_path = uidmap_dir.parent().unwrap().join("sock.d").join("subid");
    let _ = fs::remove_file(&sock_path);
    let listener = UnixListener::bind(&sock_path)
        .unwrap_or_else(|e| io_fail(format!("binding {}: {e}", sock_path.display())));
    // The agent runs with a subid kuid; the socket file would default to
    // 0755 and the member (its only legitimate client) couldn't connect.
    // The parent dir is member-owned 0700 and requests are peer-checked,
    // so world-writable-here is safe.
    fs::set_permissions(&sock_path, std::os::unix::fs::PermissionsExt::from_mode(0o666))
        .unwrap_or_else(|e| io_fail(format!("chmod socket: {e}")));

    for conn in listener.incoming() {
        match conn {
            Ok(stream) => {
                std::thread::spawn(move || {
                    let reply = agent_handle(stream, member_uid, member_gid);
                    let _ = reply;
                });
            }
            Err(_) => break,
        }
    }
    ExitCode::SUCCESS
}

fn agent_handle(
    mut stream: std::os::unix::net::UnixStream,
    member_uid: u32,
    member_gid: u32,
) -> std::io::Result<()> {
    use std::io::Write;

    let reply = agent_validate(&mut stream, member_uid, member_gid);
    let text = match &reply {
        Ok(()) => "ok\n".to_string(),
        Err(msg) => format!("err {msg}\n"),
    };
    stream.write_all(text.as_bytes())?;
    Ok(())
}

/// Receive one small request message plus the client's O_PATH handle to
/// the target's /proc/<pid> dir (SCM_RIGHTS — see crates/subid-map).
fn recv_with_fd(stream: &std::os::unix::net::UnixStream) -> std::io::Result<(String, Option<i32>)> {
    use std::os::unix::io::AsRawFd;
    let mut buf = [0u8; 256];
    let mut iov = libc::iovec {
        iov_base: buf.as_mut_ptr() as *mut _,
        iov_len: buf.len(),
    };
    let mut cspace = [0u8; unsafe { libc::CMSG_SPACE(4) } as usize];
    let mut msg: libc::msghdr = unsafe { std::mem::zeroed() };
    msg.msg_iov = &mut iov;
    msg.msg_iovlen = 1;
    msg.msg_control = cspace.as_mut_ptr() as *mut _;
    msg.msg_controllen = cspace.len() as _;
    let n = unsafe { libc::recvmsg(stream.as_raw_fd(), &mut msg, 0) };
    if n < 0 {
        return Err(std::io::Error::last_os_error());
    }
    let mut fd = None;
    unsafe {
        let cmsg = libc::CMSG_FIRSTHDR(&msg);
        if !cmsg.is_null()
            && (*cmsg).cmsg_level == libc::SOL_SOCKET
            && (*cmsg).cmsg_type == libc::SCM_RIGHTS
        {
            let mut v = 0i32;
            std::ptr::copy_nonoverlapping(libc::CMSG_DATA(cmsg) as *const i32, &mut v, 1);
            fd = Some(v);
        }
    }
    Ok((
        String::from_utf8_lossy(&buf[..n as usize]).into_owned(),
        fd,
    ))
}

fn agent_validate(
    stream: &mut std::os::unix::net::UnixStream,
    member_uid: u32,
    member_gid: u32,
) -> Result<(), String> {
    stream
        .set_read_timeout(Some(Duration::from_secs(10)))
        .map_err(|e| e.to_string())?;

    // Authenticate the connecting peer: must run as the member themself
    // (the socket path already gates on directory ownership; this covers
    // anything that managed to reach it, e.g. if the member ever binds it
    // into a container).
    {
        use std::os::unix::io::AsRawFd;
        let mut cred: libc::ucred = unsafe { std::mem::zeroed() };
        let mut len = std::mem::size_of::<libc::ucred>() as libc::socklen_t;
        if unsafe {
            libc::getsockopt(
                stream.as_raw_fd(),
                libc::SOL_SOCKET,
                libc::SO_PEERCRED,
                &mut cred as *mut _ as *mut _,
                &mut len,
            )
        } != 0
        {
            return Err(std::io::Error::last_os_error().to_string());
        }
        // The member's uid number is the same inside the payload namespace
        // (U3 maps inner $uid -> the member), so this is rendering-agnostic.
        if cred.uid != member_uid {
            return Err(format!("peer uid {} is not the session member", cred.uid));
        }
    }

    // One message: "<uid|gid>\n<inner> <outer> <count> ...\n" plus the
    // client's O_PATH handle to the target's /proc dir.
    let (text, dirfd) = recv_with_fd(stream).map_err(|e| e.to_string())?;
    let dirfd = dirfd.ok_or("no process handle received")?;
    let result = validate_and_write(dirfd, &text, member_uid, member_gid);
    unsafe { libc::close(dirfd) };
    result
}

fn validate_and_write(
    dirfd: i32,
    text: &str,
    member_uid: u32,
    member_gid: u32,
) -> Result<(), String> {
    let mut lines = text.lines();
    let (is_uid, member) = match lines.next().unwrap_or("") {
        "uid" => (true, member_uid),
        "gid" => (false, member_gid),
        other => return Err(format!("bad kind '{other}'")),
    };
    let nums: Vec<u32> = lines
        .next()
        .unwrap_or("")
        .split_whitespace()
        .map(|t| t.parse())
        .collect::<Result<_, _>>()
        .map_err(|_| "bad numbers".to_string())?;
    if nums.len() != 6 {
        return Err("bad request".into());
    }
    let expected = [0, member, 1, 1, 65536, 65536];
    if nums != expected {
        return Err("map does not match the sandbox's fixed shape".into());
    }

    // The handle must point at a /proc/<pid> dir of a member-owned process
    // whose id map is still empty (a freshly-unshared namespace).
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    if unsafe { libc::fstat(dirfd, &mut st) } != 0 {
        return Err(std::io::Error::last_os_error().to_string());
    }
    if st.st_uid != member_uid || st.st_gid != member_gid {
        return Err("target process is not the member's".into());
    }
    let kind = if is_uid { "uid_map" } else { "gid_map" };
    let existing = read_at(dirfd, kind, libc::O_RDONLY)?;
    if !existing.is_empty() {
        return Err("target process is already mapped".into());
    }

    let mut content = String::new();
    for t in nums.chunks_exact(3) {
        content.push_str(&format!("{} {} {}\n", t[0], t[1], t[2]));
    }
    let fd = open_at(dirfd, kind, libc::O_WRONLY)?;
    let ok = unsafe {
        libc::write(fd, content.as_ptr() as *const _, content.len())
    };
    let saved = std::io::Error::last_os_error();
    unsafe { libc::close(fd) };
    if ok < 0 {
        return Err(saved.to_string());
    }
    Ok(())
}

fn open_at(dirfd: i32, name: &str, flags: i32) -> Result<i32, String> {
    let name = std::ffi::CString::new(name).unwrap();
    let fd = unsafe { libc::openat(dirfd, name.as_ptr(), flags | libc::O_CLOEXEC) };
    if fd < 0 {
        return Err(std::io::Error::last_os_error().to_string());
    }
    Ok(fd)
}

fn read_at(dirfd: i32, name: &str, flags: i32) -> Result<String, String> {
    let fd = open_at(dirfd, name, flags)?;
    let mut buf = [0u8; 1024];
    let n = unsafe { libc::read(fd, buf.as_mut_ptr() as *mut _, buf.len()) };
    let saved = std::io::Error::last_os_error();
    unsafe { libc::close(fd) };
    if n < 0 {
        return Err(saved.to_string());
    }
    Ok(String::from_utf8_lossy(&buf[..n as usize]).into_owned())
}
