//! Inner setup shim: runs in the outer user+net+mount namespace created by
//! `login` (see there for the namespace layout). Replaces netns-setup.sh.

use crate::util::*;
use std::{
    ffi::OsString,
    fs,
    os::unix::{
        ffi::OsStrExt,
        process::CommandExt,
    },
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

    let mut bwrap_argv = std::mem::take(&mut flags.bwrap_argv);
    if full {
        let subid_map_bin = flags.subid_map_bin.clone();
        full_mode_setup(&subid_map_bin, &mut bwrap_argv);
    }

    let mut cmd = Command::new(&bwrap_argv[0]);
    cmd.args(&bwrap_argv[1..]).arg("--").args(&flags.payload);
    let mut child = spawn_pdeathsig(cmd);
    let status = child.wait();
    match status {
        Ok(s) => ExitCode::from(s.code().unwrap_or(1) as u8),
        Err(e) => io_fail(format!("waiting for bwrap: {e}")),
    }
}

/// The multi-uid path: create the two nested user namespaces bwrap needs
/// (U2 = setup ns, U3 = payload ns; see the design comment in login.rs),
/// prepare the in-sandbox setuid map helpers, and splice the namespace args
/// into the bwrap argv.
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
    // U2: 0 -> U1's 0 (bwrap setup), 1 -> U1's 1 (the in-sandbox helper's
    // owner), 65536+ -> U1's 2.. (the container range).
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
    if !got {
        fail("U3 namespace setup timed out");
    }
    let u3_pid: u32 = fs::read_to_string(&u3_marker)
        .unwrap_or_else(|e| io_fail(format!("reading u3 marker: {e}")))
        .trim()
        .parse()
        .unwrap_or_else(|_| fail("bad u3 pid in marker"));

    // The in-sandbox newuidmap/newgidmap: stock shadow binaries, copied and
    // chowned to the first subid so that executing one inside the payload
    // namespace grants uid 0 there (and thus CAP_SETUID for the container
    // map). Inert on the host (the owner is just a subordinate id).
    let bin_dir = uidmap_dir.parent().unwrap().join("bin");
    for name in ["newuidmap", "newgidmap"] {
        let dest = bin_dir.join(name);
        fs::copy(subid_map_bin, &dest).unwrap_or_else(|e| io_fail(format!("copying {name}: {e}")));
        unsafe {
            let cpath = std::ffi::CString::new(dest.as_os_str().as_bytes()).unwrap();
            if libc::chown(cpath.as_ptr(), 1, 1) != 0 {
                io_fail(format!("chowning {name}: {}", std::io::Error::last_os_error()));
            }
        }
        let mut perms = fs::metadata(&dest)
            .unwrap_or_else(|e| io_fail(format!("stat {name}: {e}")))
            .permissions();
        use std::os::unix::fs::PermissionsExt;
        perms.set_mode(0o4755);
        fs::set_permissions(&dest, perms).unwrap_or_else(|e| io_fail(format!("chmod {name}: {e}")));
    }

    let fd_u2 = open_ns_fd(u2_pid);
    let fd_u3 = open_ns_fd(u3_pid);

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
