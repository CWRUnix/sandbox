use std::{
    ffi::OsStr,
    fs, io,
    os::unix::ffi::OsStrExt,
    path::{Path, PathBuf},
    time::{Duration, Instant},
};

/// Member-facing errors keep the login-sandbox name (journal history).
pub fn fail(msg: impl std::fmt::Display) -> ! {
    eprintln!("login-sandbox: {msg}");
    std::process::exit(1);
}

pub fn io_fail(msg: impl std::fmt::Display) -> ! {
    let err = io::Error::last_os_error();
    eprintln!("login-sandbox: {msg}: {err}");
    std::process::exit(1);
}

pub fn getuid() -> u32 {
    unsafe { libc::getuid() }
}

pub fn getgid() -> u32 {
    unsafe { libc::getgid() }
}

/// NSS lookup via glibc (LDAP members resolve through sssd). The returned
/// pointer is static, so copy the strings out immediately; we are
/// single-threaded at every call site.
pub fn passwd_entry(uid: u32) -> Option<(String, PathBuf)> {
    unsafe {
        let pw = libc::getpwuid(uid);
        if pw.is_null() {
            return None;
        }
        let name = std::ffi::CStr::from_ptr((*pw).pw_name)
            .to_string_lossy()
            .into_owned();
        let dir = PathBuf::from(OsStr::from_bytes(
            std::ffi::CStr::from_ptr((*pw).pw_dir).to_bytes(),
        ));
        Some((name, dir))
    }
}

pub fn group_name(gid: u32) -> Option<String> {
    unsafe {
        let gr = libc::getgrgid(gid);
        if gr.is_null() {
            return None;
        }
        Some(
            std::ffi::CStr::from_ptr((*gr).gr_name)
                .to_string_lossy()
                .into_owned(),
        )
    }
}

/// Poll `cond` every 50 ms until it holds or `timeout` elapses.
pub fn wait_until(mut cond: impl FnMut() -> bool, timeout: Duration) -> bool {
    let deadline = Instant::now() + timeout;
    loop {
        if cond() {
            return true;
        }
        if Instant::now() >= deadline {
            return false;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
}

fn read_link_string(path: &Path) -> Option<String> {
    fs::read_link(path)
        .ok()
        .map(|p| p.to_string_lossy().into_owned())
}

/// True when the process's namespace handle for `ns` differs from ours —
/// i.e. it has performed its unshare(2). False once the process is gone.
pub fn ns_differs_from_self(pid: u32, ns: &str) -> bool {
    let ours = read_link_string(Path::new(&format!("/proc/self/ns/{ns}")));
    let theirs = read_link_string(Path::new(&format!("/proc/{pid}/ns/{ns}")));
    match (theirs, ours) {
        (Some(t), Some(o)) => t != o,
        _ => false,
    }
}

pub fn pid_alive(pid: u32) -> bool {
    Path::new(&format!("/proc/{pid}")).exists()
}

pub fn mktemp_dir(parent: &Path) -> io::Result<PathBuf> {
    let pid = std::process::id();
    for i in 0..100u32 {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.subsec_nanos())
            .unwrap_or(0);
        let candidate = parent.join(format!(
            "login-sandbox.{:08x}",
            nanos ^ (pid << 12) ^ (i << 20)
        ));
        match fs::create_dir(&candidate) {
            Ok(()) => return Ok(candidate),
            Err(e) if e.kind() == io::ErrorKind::AlreadyExists => continue,
            Err(e) => return Err(e),
        }
    }
    Err(io::Error::new(
        io::ErrorKind::AlreadyExists,
        "mktemp: too many collisions",
    ))
}

/// Park the process forever (namespace holder).
pub fn park() -> ! {
    loop {
        std::thread::park();
    }
}
