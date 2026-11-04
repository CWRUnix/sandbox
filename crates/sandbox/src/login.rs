//! Outer orchestration: identity, per-session /etc, the id-map handshake,
//! slirp4netns. Replaces the old login-sandbox.sh — see
//! nixos/sandbox/default.nix in the server config for the design comments.

use crate::util::*;
use std::{
    ffi::{OsStr, OsString},
    fs,
    os::unix::process::CommandExt,
    path::{Path, PathBuf},
    process::{Child, Command, ExitCode},
    time::Duration,
};

/// Setuid helper writing the outer namespace's id map (see crates/subid-map).
/// Created by the server config's security.wrappers entry.
const HOST_SUBID_MAP: &str = "/run/wrappers/bin/cwrunix-subid-map";

/// The member-visible home inside the sandbox is this subdirectory of their
/// real home. Unsandboxed contexts (PAM, the systemd user manager, the job
/// broker) operate on the REAL home, which sandboxed code can therefore
/// never write — this closes the whole class of "plant a file the
/// unsandboxed context consumes" attacks (user units in
/// ~/.config/systemd/user, ~/.pam_environment, ...). Keep in sync with
/// crates/jobs (HOME_SUBDIR).
const HOME_SUBDIR: &str = "sandbox";

struct Flags {
    bwrap: PathBuf,
    slirp4netns: PathBuf,
    ip: PathBuf,
    bindfs: PathBuf,
    sandbox_profile: String,
    containers_config: String,
    subid_map_bin: PathBuf,
    systemctl: Option<PathBuf>,
    jobs_sock: Option<PathBuf>,
    trailing: Vec<OsString>,
}

fn parse_flags(args: &[OsString]) -> Flags {
    let mut f = Flags {
        bwrap: PathBuf::new(),
        slirp4netns: PathBuf::new(),
        ip: PathBuf::new(),
        bindfs: PathBuf::new(),
        sandbox_profile: String::new(),
        containers_config: String::new(),
        subid_map_bin: PathBuf::new(),
        systemctl: None,
        jobs_sock: None,
        trailing: Vec::new(),
    };
    let mut it = args.iter();
    while let Some(arg) = it.next() {
        let Some(s) = arg.to_str() else {
            fail("non-utf8 argument")
        };
        if s == "--" {
            // Explicit end-of-flags: the rest is the payload, verbatim.
            f.trailing = it.cloned().collect();
            break;
        }
        if !s.starts_with("--") {
            // first non-flag: the sshd-style payload invocation begins here
            let mut rest = vec![arg.clone()];
            rest.extend(it.cloned());
            f.trailing = rest;
            break;
        }
        let value = it
            .next()
            .unwrap_or_else(|| fail(format!("{s} needs a value")));
        match s {
            "--bwrap" => f.bwrap = value.clone().into(),
            "--slirp4netns" => f.slirp4netns = value.clone().into(),
            "--ip" => f.ip = value.clone().into(),
            "--bindfs" => f.bindfs = value.clone().into(),
            "--sandbox-profile" => f.sandbox_profile = value.to_string_lossy().into_owned(),
            "--containers-config" => f.containers_config = value.to_string_lossy().into_owned(),
            "--subid-map-bin" => f.subid_map_bin = value.clone().into(),
            "--systemctl" => f.systemctl = Some(value.clone().into()),
            "--jobs-sock" => f.jobs_sock = Some(value.clone().into()),
            _ => fail(format!("unknown flag {s}")),
        }
    }
    for (name, val) in [
        ("--bwrap", &f.bwrap),
        ("--slirp4netns", &f.slirp4netns),
        ("--ip", &f.ip),
        ("--bindfs", &f.bindfs),
        ("--subid-map-bin", &f.subid_map_bin),
    ] {
        if val.as_os_str().is_empty() {
            fail(format!("missing required flag {name}"));
        }
    }
    if f.sandbox_profile.is_empty() || f.containers_config.is_empty() {
        fail("missing --sandbox-profile or --containers-config");
    }
    f
}

/// The member-range check (the setuid helper re-validates it; see
/// subid-map.c). Anything outside gets the single-uid sandbox.
fn subids_available(uid: u32, gid: u32) -> bool {
    (2000..12000).contains(&uid)
        && (2000..12000).contains(&gid)
        && Path::new(HOST_SUBID_MAP).exists()
}

/// Store-path-sourced conveniences (opengl-driver, terminfo, locale) are
/// resolved now and rebound through the FUSE mirror ($etc/nix) so the
/// sandbox never shares the host's page cache for them.
fn compute_resolved_binds(etc: &Path) -> Vec<String> {
    let mut out = Vec::new();
    for (host, dest) in [
        ("/run/opengl-driver", "/run/opengl-driver"),
        ("/run/current-system/sw/share/terminfo", "/usr/share/terminfo"),
        ("/run/current-system/sw/lib/locale", "/usr/lib/locale"),
    ] {
        let Ok(resolved) = fs::canonicalize(host) else {
            continue; // absent (e.g. GPU-less test VM): skip
        };
        let resolved = resolved.to_string_lossy().into_owned();
        if let Some(store_part) = resolved.strip_prefix("/nix") {
            out.push("--ro-bind".into());
            out.push(format!("{}/nix{}", etc.display(), store_part));
            out.push(dest.into());
        } else {
            out.push("--ro-bind-try".into());
            out.push(host.into());
            out.push(dest.into());
        }
    }
    out
}

struct Session {
    uid: u32,
    gid: u32,
    user: String,
    home: PathBuf,
    /// What actually gets bound at `home`: the per-member subdirectory of
    /// the real home (see HOME_SUBDIR).
    sandbox_home: PathBuf,
    jobs_sock: Option<PathBuf>,
    etc: PathBuf,
    inner_shell: String,
}

impl Session {
    /// The bwrap argument list. In full (multi-uid) mode the userns/uid/cap
    /// args are inserted by netns-setup (it owns the namespace fds); in
    /// single mode this is exactly the deployed single-uid invocation.
    fn bwrap_args(&self, flags: &Flags, full: bool, resolved: &[String]) -> Vec<String> {
        let mut a: Vec<String> = vec![flags.bwrap.to_string_lossy().into_owned()];
        if !full {
            a.push("--unshare-user-try".into());
            a.extend(["--uid".into(), self.uid.to_string()]);
            a.extend(["--gid".into(), self.gid.to_string()]);
        }
        a.extend([
            "--unshare-ipc".into(),
            "--unshare-pid".into(),
            "--unshare-uts".into(),
            "--unshare-cgroup-try".into(),
            "--die-with-parent".into(),
            "--clearenv".into(),
        ]);
        let path_prefix = if full { "/etc/cwrunix/bin:" } else { "" };
        let envs: Vec<(String, String)> = vec![
            ("HOME".into(), self.home.to_string_lossy().into_owned()),
            ("USER".into(), self.user.clone()),
            ("LOGNAME".into(), self.user.clone()),
            ("SHELL".into(), self.inner_shell.clone()),
            (
                "TERM".into(),
                std::env::var("TERM").unwrap_or_else(|_| "xterm-256color".into()),
            ),
            ("LANG".into(), "en_US.UTF-8".into()),
            (
                "PATH".into(),
                format!(
                    "{}{}/bin:{}/.nix-profile/bin:{}/.local/state/nix/profile/bin:/nix/var/nix/profiles/default/bin",
                    path_prefix,
                    flags.sandbox_profile,
                    self.home.display(),
                    self.home.display()
                ),
            ),
            (
                "NIX_CONFIG".into(),
                "experimental-features = nix-command flakes".into(),
            ),
            (
                "NIX_SSL_CERT_FILE".into(),
                "/etc/ssl/certs/ca-bundle.crt".into(),
            ),
            ("SSL_CERT_FILE".into(), "/etc/ssl/certs/ca-bundle.crt".into()),
            (
                "LOCALE_ARCHIVE".into(),
                "/usr/lib/locale/locale-archive".into(),
            ),
            ("XDG_RUNTIME_DIR".into(), format!("/run/user/{}", self.uid)),
        ];
        for (k, v) in envs {
            a.extend(["--setenv".into(), k, v]);
        }
        let nix_mirror = format!("{}/nix", self.etc.display());
        let strip = |p: &str| p.strip_prefix("/nix").unwrap_or(p).to_string();
        a.extend([
            "--hostname".into(),
            "zeus".into(),
            "--tmpfs".into(),
            "/tmp".into(),
            "--tmpfs".into(),
            "/sys".into(),
            "--dir".into(),
            "/sys/fs/cgroup".into(),
            // podman >= 6 requires cgroup2 magic here; bind the user's OWN
            // systemd slice (read-only), never the host tree.
            "--ro-bind-try".into(),
            format!("/sys/fs/cgroup/user.slice/user-{}.slice", self.uid),
            "/sys/fs/cgroup".into(),
            "--dev".into(),
            "/dev".into(),
            "--dev-bind-try".into(),
            "/dev/net/tun".into(),
            "/dev/net/tun".into(),
            "--dev-bind-try".into(),
            "/dev/fuse".into(),
            "/dev/fuse".into(),
            "--proc".into(),
            "/proc".into(),
            "--ro-bind".into(),
            nix_mirror.clone(),
            "/nix".into(),
            "--bind".into(),
            "/nix/var/nix/daemon-socket".into(),
            "/nix/var/nix/daemon-socket".into(),
            "--bind".into(),
            self.sandbox_home.to_string_lossy().into_owned(),
            self.home.to_string_lossy().into_owned(),
            "--dev-bind-try".into(),
            "/dev/dri".into(),
            "/dev/dri".into(),
            "--tmpfs".into(),
            format!("/run/user/{}", self.uid),
        ]);
        // The job broker's socket (a plain file bind; connecting needs it
        // read-write). Absent when the user manager couldn't be reached.
        if let Some(sock) = &self.jobs_sock {
            a.extend([
                "--bind".into(),
                sock.to_string_lossy().into_owned(),
                "/run/cwrunix-jobs.ctl".into(),
            ]);
        }
        for f in ["passwd", "group", "hosts", "resolv.conf", "nsswitch.conf"] {
            a.extend([
                "--ro-bind".into(),
                format!("{}/{}", self.etc.display(), f),
                format!("/etc/{f}"),
            ]);
        }
        a.extend([
            "--ro-bind".into(),
            format!("{}{}/etc/ssl", nix_mirror, strip(&flags.sandbox_profile)),
            "/etc/ssl".into(),
        ]);
        a.extend([
            "--ro-bind".into(),
            format!("{}{}/etc/containers", nix_mirror, strip(&flags.containers_config)),
            "/etc/containers".into(),
        ]);
        if full {
            a.extend([
                "--ro-bind".into(),
                format!("{}/subuid", self.etc.display()),
                "/etc/subuid".into(),
                "--ro-bind".into(),
                format!("{}/subgid", self.etc.display()),
                "/etc/subgid".into(),
                "--ro-bind".into(),
                format!("{}/bin", self.etc.display()),
                "/etc/cwrunix/bin".into(),
                "--bind".into(),
                format!("{}/sock.d", self.etc.display()),
                "/run/cwrunix-subid.d".into(),
            ]);
        }
        a.extend(resolved.iter().cloned());
        a.extend([
            "--symlink".into(),
            format!("{}/bin/bash", flags.sandbox_profile),
            "/bin/sh".into(),
            "--chdir".into(),
            self.home.to_string_lossy().into_owned(),
        ]);
        a
    }
}

/// Spawn the inner shim inside the fresh user+net+mount namespaces
/// (unshare happens in the child's pre-exec; mount propagation stays
/// private so the FUSE staging mount never touches the host's table).
/// pdeathsig cascades teardown if the login process dies for any reason.
fn spawn_netns(
    flags: &Flags,
    etc: &Path,
    session: &Session,
    bwrap_args: &[String],
    payload: &[OsString],
    full: bool,
) -> Child {
    let exe = std::env::current_exe().unwrap_or_else(|e| io_fail(format!("current_exe: {e}")));
    let mut cmd = Command::new(exe);
    cmd.arg("netns-setup")
        .arg("--ip")
        .arg(&flags.ip)
        .arg("--bindfs")
        .arg(&flags.bindfs)
        .arg("--subid-map-bin")
        .arg(&flags.subid_map_bin)
        .arg("--")
        .args(bwrap_args)
        .arg("--")
        .args(payload);
    cmd.env("CWRUNIX_NIX_FUSE_MNT", format!("{}/nix", etc.display()));
    if full {
        cmd.env("CWRUNIX_UIDMAP_DIR", format!("{}/uidmap", etc.display()));
        cmd.env("CWRUNIX_MEMBER_UID", session.uid.to_string());
        cmd.env("CWRUNIX_MEMBER_GID", session.gid.to_string());
    }
    unsafe {
        cmd.pre_exec(|| {
            if libc::unshare(libc::CLONE_NEWUSER | libc::CLONE_NEWNET | libc::CLONE_NEWNS) != 0 {
                return Err(std::io::Error::last_os_error());
            }
            if libc::mount(
                std::ptr::null(),
                c"/".as_ptr(),
                std::ptr::null(),
                libc::MS_REC | libc::MS_PRIVATE,
                std::ptr::null(),
            ) != 0 {
                return Err(std::io::Error::last_os_error());
            }
            libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL, 0, 0, 0);
            Ok(())
        });
    }
    cmd.spawn()
        .unwrap_or_else(|e| io_fail(format!("spawning netns-setup: {e}")))
}

/// Single-uid fallback: the unprivileged cross-process single-line own-id
/// write the kernel allows.
fn write_single_maps(pid: u32, uid: u32, gid: u32) -> std::io::Result<()> {
    fs::write(format!("/proc/{pid}/uid_map"), format!("0 {uid} 1\n"))?;
    fs::write(format!("/proc/{pid}/setgroups"), "deny\n")?;
    fs::write(format!("/proc/{pid}/gid_map"), format!("0 {gid} 1\n"))?;
    Ok(())
}

/// Wait for the child's fresh user namespace, then write its id map: the
/// full map via the setuid helper, or the single own-id line ourselves.
/// Returns true if the child got the full map, false for the single-uid
/// map, and None if the helper failed mid-write (the caller should kill
/// and relaunch the child in single-uid mode — a half-written map can
/// never be repaired, the kernel only allows one write).
fn map_child(pid: u32, uid: u32, gid: u32, full: bool) -> Option<bool> {
    let entered = wait_until(
        || ns_differs_from_self(pid, "user") || !pid_alive(pid),
        Duration::from_secs(10),
    );
    note(if entered {
        "child userns observed"
    } else {
        "child userns TIMEOUT"
    });
    if !entered {
        fail("child never entered its user namespace");
    }
    if full {
        let ok = Command::new(HOST_SUBID_MAP)
            .arg(pid.to_string())
            .status()
            .map(|s| s.success())
            .unwrap_or(false);
        return if ok { Some(true) } else { None };
    }
    write_single_maps(pid, uid, gid).unwrap_or_else(|e| io_fail(format!("writing id map: {e}")));
    Some(false)
}

fn write(path: impl AsRef<Path>, content: impl AsRef<str>) {
    fs::write(path, content.as_ref()).unwrap_or_else(|e| io_fail(format!("writing: {e}")));
}

/// Bring up the per-user job broker socket (best-effort; jobs are simply
/// unavailable in this session when the user manager can't be reached) and
/// return the path to bind into the sandbox. daemon-reload picks up unit
/// files deployed after the manager started.
fn setup_jobs_socket(flags: &Flags) -> Option<PathBuf> {
    let sock = flags.jobs_sock.clone()?;
    let systemctl = flags.systemctl.clone()?;
    for action in ["daemon-reload", "start"] {
        let mut cmd = Command::new(&systemctl);
        cmd.arg("--user").arg(action);
        if action == "start" {
            cmd.arg("cwrunix-jobsd.socket");
        }
        let ok = cmd
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status()
            .map(|s| s.success())
            .unwrap_or(false);
        if !ok {
            eprintln!(
                "login-sandbox: warning: job broker unavailable (systemctl --user {action} failed)"
            );
            return None;
        }
    }
    let ok = sock.exists();
    note(if ok {
        "job broker socket up"
    } else {
        "job broker socket missing"
    });
    if ok { Some(sock) } else { None }
}

pub fn main(args: &[OsString]) -> ExitCode {
    let flags = parse_flags(args);
    let uid = getuid();
    let gid = getgid();
    let (user, home) =
        passwd_entry(uid).unwrap_or_else(|| fail(format!("no passwd entry for uid {uid}")));
    // Debug/escape hatch for admin testing (sshd never sets this).
    let home = std::env::var_os("CWRUNIX_SANDBOX_HOME")
        .map(PathBuf::from)
        .unwrap_or(home);
    if !home.is_dir() {
        fail(format!(
            "{user} has no usable home directory ({})",
            home.display()
        ));
    }
    // The member-visible home is a fixed subdirectory of the real home
    // (HOME_SUBDIR). Create it on first login; refuse anything that isn't
    // a plain member-owned directory.
    let sandbox_home = home.join(HOME_SUBDIR);
    {
        use std::os::unix::fs::MetadataExt;
        match fs::symlink_metadata(&sandbox_home) {
            Ok(m) if m.file_type().is_dir() && m.uid() == uid => {}
            Ok(_) => fail(format!(
                "{} is not a member-owned directory",
                sandbox_home.display()
            )),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                fs::create_dir(&sandbox_home)
                    .unwrap_or_else(|e| io_fail(format!("creating {}: {e}", sandbox_home.display())));
            }
            Err(e) => io_fail(format!("stat {}: {e}", sandbox_home.display())),
        }
    }
    let group = group_name(gid).unwrap_or_else(|| "users".into());

    let inner_shell = format!("{}/bin/zsh", flags.sandbox_profile);
    let payload: Vec<OsString> = match flags.trailing.split_first() {
        // sshd-style: a bare "-c <cmd>" invocation goes through the shell.
        Some((a, rest)) if a.as_os_str() == OsStr::new("-c") => {
            let cmd = rest.first().cloned().unwrap_or_default();
            vec![OsString::from(&inner_shell), "-c".into(), cmd]
        }
        // Anything else (e.g. from the job broker) is exec'd verbatim.
        Some(_) => flags.trailing.clone(),
        None => vec![OsString::from(&inner_shell), "-l".into()],
    };

    // Per-session /etc + FUSE staging + handshake dir, cleaned up by logind
    // with the session runtime dir.
    let runtime_dir = std::env::var_os("XDG_RUNTIME_DIR")
        .map(PathBuf::from)
        .filter(|p| p.is_dir())
        .unwrap_or_else(|| PathBuf::from(format!("/run/user/{uid}")));
    let runtime_dir = if runtime_dir.is_dir() {
        runtime_dir
    } else {
        PathBuf::from("/tmp")
    };
    let etc = mktemp_dir(&runtime_dir).unwrap_or_else(|e| io_fail(format!("mktemp: {e}")));
    fs::create_dir(etc.join("nix")).unwrap_or_else(|e| io_fail(format!("mkdir: {e}")));

    write(
        etc.join("passwd"),
        format!(
            "root:x:0:0:root:/root:/bin/bash\n{user}:x:{uid}:{gid}:{user}:{}:{inner_shell}\nnobody:x:65534:65534:nobody:/nonexistent:/sbin/nologin\n",
            home.display()
        ),
    );
    write(etc.join("group"), format!("root:x:0:\n{group}:x:{gid}:\nnogroup:x:65534:\n"));
    write(etc.join("resolv.conf"), "nameserver 10.0.2.3\noptions edns0\n");
    write(etc.join("hosts"), "127.0.0.1 localhost\n::1 localhost\n");
    write(
        etc.join("nsswitch.conf"),
        "passwd: files\ngroup: files\nshadow: files\nhosts: files dns\n",
    );

    let mut full = subids_available(uid, gid);
    if full {
        // podman's view of the subid space: the container range lives at
        // 65536 in the payload namespace (see subid-map's map layout).
        // Only the USERNAME line: tools that also fall back to uid-based
        // lookups (podman) would otherwise merge both entries and
        // double-allocate the range.
        write(etc.join("subuid"), format!("{user}:65536:65536\n"));
        write(etc.join("subgid"), format!("{group}:65536:65536\n"));
        fs::create_dir(etc.join("bin")).unwrap_or_else(|e| io_fail(format!("mkdir: {e}")));
        fs::create_dir(etc.join("uidmap")).unwrap_or_else(|e| io_fail(format!("mkdir: {e}")));
        fs::create_dir(etc.join("sock.d")).unwrap_or_else(|e| io_fail(format!("mkdir: {e}")));
    }

    let session = Session {
        uid,
        gid,
        user,
        home,
        sandbox_home,
        jobs_sock: setup_jobs_socket(&flags),
        etc,
        inner_shell,
    };
    let resolved = compute_resolved_binds(&session.etc);

    loop {
        let bwrap_args = session.bwrap_args(&flags, full, &resolved);
        note(if full { "spawning (multi-uid)" } else { "spawning (single-uid)" });
        let mut child = spawn_netns(&flags, &session.etc, &session, &bwrap_args, &payload, full);
        let pid = child.id();
        let child_full = match map_child(pid, uid, gid, full) {
            Some(f) => {
                note(if f { "map: full" } else { "map: single" });
                f
            }
            None => {
                // The setuid helper failed mid-map (the map can never be
                // half-repaired): kill this child and relaunch single-uid.
                eprintln!("login-sandbox: warning: subordinate id mapping failed; using single-uid sandbox");
                let _ = child.kill();
                let _ = child.wait();
                full = false;
                continue;
            }
        };

        // slirp4netns must attach after the child actually entered its net
        // namespace (else it grabs the HOST netns handle and fails).
        let net_ready = wait_until(
            || ns_differs_from_self(pid, "net") || !pid_alive(pid),
            Duration::from_secs(10),
        );
        note(if net_ready {
            "netns observed"
        } else {
            "netns TIMEOUT"
        });
        let mut slirp_cmd = Command::new(&flags.slirp4netns);
        slirp_cmd
            .args(["--mtu=65520", "--disable-host-loopback"])
            .arg(pid.to_string())
            .arg("tap0")
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null());
        unsafe {
            // If the login process dies, slirp dies too.
            slirp_cmd.pre_exec(|| {
                libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL, 0, 0, 0);
                Ok(())
            });
        }
        #[allow(clippy::zombie_processes)] // exits with the session's netns
        let mut slirp = slirp_cmd
            .spawn()
            .unwrap_or_else(|e| io_fail(format!("spawning slirp4netns: {e}")));

        let status = child.wait();
        note("child exited");
        let _ = slirp.kill();

        // Full-mode setup can fail before bwrap starts (e.g. a kernel that
        // refuses the nested maps); the member still gets a sandbox.
        let bwrap_started = session.etc.join("uidmap/bwrap-started").exists();
        if child_full && !bwrap_started {
            eprintln!("login-sandbox: warning: multi-uid setup failed; retrying single-uid");
            full = false;
            continue;
        }
        match status {
            Ok(s) => return ExitCode::from(s.code().unwrap_or(1) as u8),
            Err(e) => io_fail(format!("waiting for sandbox: {e}")),
        }
    }
}
