//! cwrunix-subid-map: the only privileged component of the CWRUnix login
//! sandbox. Setuid-root on the host (a NixOS security.wrappers entry in the
//! server config); the in-sandbox copy is setuid too, but its owner maps to
//! uid 0 only inside the payload namespace, so its power is scoped there.
//!
//! Two roles, selected by argv[0]:
//!
//!   cwrunix-subid-map <pid>
//!       Host side, called by `cwrunix-sandbox login`: write the OUTER user
//!       namespace's full id map. Both maps:
//!           0      <caller id>            1       (root-in-ns = the member)
//!           1      <subid start>          131072  (member's subid range)
//!       The start is computed from the caller's own id — nothing about the
//!       map is attacker-controlled.
//!
//!   newuidmap <pid> <inner> <outer> <count> ...   (and newgidmap)
//!       In-sandbox, called by podman for a container namespace: validate
//!       the request against the fixed shape [(0, own id, 1),
//!       (1, 65536, 65536)] and write it. Behaves like shadow's newuidmap
//!       but needs no /etc/subuid — the sandbox's namespace layout fixes the
//!       shape by construction.
//!
//! Safety model (both roles): the target process must be owned by the
//! caller and live in a FRESH (still unmapped) user namespace; the kernel
//! additionally enforces the single-write rule and that outer ids exist in
//! the parent namespace. Member ranges are disjoint per id and start above
//! NixOS' auto-allocation pool (100000..~1.9e9).

use std::process::ExitCode;

/// authentik issues LDAP uidNumbers/gidNumbers starting at 2000 (see
/// nixos/admins/tev.nix in the server config). Ids outside this range get
/// the single-uid sandbox instead.
const ID_MIN: u32 = 2000;
const ID_MAX: u32 = 12000;
/// First allocated subid for uid/gid 2000; each id gets 2*64k.
const SUBID_BASE: u64 = 1_910_000_000;
const SUBID_COUNT: u64 = 2 * 65536;

/// Where the container range sits inside the sandbox's outer namespace
/// (and where the in-sandbox helper expects podman's container maps to land).
const CONTAINER_BASE: u32 = 65536;
const CONTAINER_COUNT: u32 = 65536;

fn fail(msg: impl std::fmt::Display) -> ! {
    eprintln!("cwrunix-subid-map: {msg}");
    std::process::exit(1);
}

fn io_fail(msg: impl std::fmt::Display) -> ! {
    let err = std::io::Error::last_os_error();
    eprintln!("cwrunix-subid-map: {msg}: {err}");
    std::process::exit(1);
}

fn getuid() -> u32 {
    unsafe { libc::getuid() }
}

fn getgid() -> u32 {
    unsafe { libc::getgid() }
}

/// The target process must be owned by the caller and sit in a freshly
/// created (unmapped) user namespace. Comparing directory ownership via
/// stat is namespace-view-consistent (both sides render in our namespace).
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
            .unwrap_or_else(|e| io_fail(format!("reading /proc/{pid}/{kind}: {e}")));
        if !map.is_empty() {
            fail(format!("process {pid} already has an id map"));
        }
    }
}

fn parse_pid() -> u32 {
    let arg = std::env::args().nth(1).unwrap_or_else(|| fail("missing pid"));
    arg.parse::<u32>()
        .unwrap_or_else(|_| fail(format!("bad pid '{arg}'")))
}

/// Host role: write the outer namespace's full map for the caller's own
/// freshly-unshared child. `cwrunix-subid-map <pid>`.
fn host_map() -> ExitCode {
    let pid = parse_pid();
    let uid = getuid();
    let gid = getgid();
    if !(ID_MIN..ID_MAX).contains(&uid) || !(ID_MIN..ID_MAX).contains(&gid) {
        fail(format!("uid/gid {uid}/{gid} outside member range"));
    }
    check_target(pid, uid, gid);

    let subuid = SUBID_BASE + u64::from(uid - ID_MIN) * SUBID_COUNT;
    let subgid = SUBID_BASE + u64::from(gid - ID_MIN) * SUBID_COUNT;
    let uid_map = format!("0 {uid} 1\n1 {subuid} {SUBID_COUNT}\n");
    let gid_map = format!("0 {gid} 1\n1 {subgid} {SUBID_COUNT}\n");
    write_file_or_die(&format!("/proc/{pid}/uid_map"), &uid_map);
    write_file_or_die(&format!("/proc/{pid}/gid_map"), &gid_map);
    ExitCode::SUCCESS
}

/// In-sandbox role (argv[0] = newuidmap/newgidmap): stock-helper argument
/// format, but the valid shape is fixed by the sandbox layout.
fn sandbox_map(is_uid: bool) -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let usage = "usage: newuidmap <pid> <inner> <outer> <count> ...";
    if args.len() < 5 || !(args.len() - 1).is_multiple_of(3) {
        fail(usage);
    }
    let pid: u32 = args[0].parse().unwrap_or_else(|_| fail("bad pid"));
    let own = if is_uid { getuid() } else { getgid() };
    let expected = format!("0 {own} 1\n1 {CONTAINER_BASE} {CONTAINER_COUNT}\n");

    let mut map = String::new();
    for triplet in args[1..].chunks_exact(3) {
        let inner: u32 = triplet[0].parse().unwrap_or_else(|_| fail("bad inner id"));
        let outer: u32 = triplet[1].parse().unwrap_or_else(|_| fail("bad outer id"));
        let count: u32 = triplet[2].parse().unwrap_or_else(|_| fail("bad count"));
        map.push_str(&format!("{inner} {outer} {count}\n"));
    }
    if map != expected {
        fail("map does not match the sandbox's fixed shape");
    }
    check_target(pid, getuid(), getgid());
    let kind = if is_uid { "uid_map" } else { "gid_map" };
    write_file_or_die(&format!("/proc/{pid}/{kind}"), &map);
    ExitCode::SUCCESS
}

fn write_file_or_die(path: &str, content: &str) {
    if let Err(e) = std::fs::write(path, content) {
        io_fail(format!("writing {path}: {e}"));
    }
}

fn main() -> ExitCode {
    let argv0 = std::env::args()
        .next()
        .unwrap_or_default();
    let base = std::path::Path::new(&argv0)
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or("");
    match base {
        "newuidmap" => sandbox_map(true),
        "newgidmap" => sandbox_map(false),
        _ => host_map(),
    }
}
