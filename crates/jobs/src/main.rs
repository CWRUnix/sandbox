//! cwrunix-jobs: background job broker for sandboxed members.
//!
//! Sessions are ephemeral — everything a member runs dies with their login
//! sandbox. This crate lets them hand a command to their systemd user
//! manager instead: the broker wraps it in a FRESH login sandbox as a
//! transient user unit, so jobs get exactly the same isolation and quotas
//! as sessions but outlive them (lingering keeps the user manager running;
//! see nixos/sandbox/default.nix in the server config).
//!
//! One binary, two roles dispatched on argv[0]:
//!   cwrunix-jobsd   the broker: socket-activated (LISTEN_FDS) per-user
//!                   service, or binds CWRUNIX_JOBS_SOCK itself (dev).
//!   cwrunix-job     the in-sandbox client (submit/list/status/stop/log).
//!
//! The broker is STATELESS: job state lives in systemd (units named
//! cwrunix-job-<id>) and in the log files under the member-visible home.
//! It may die or be restarted at any time. Trust boundary: the broker runs
//! as the member themself and only ever touches that member's own user
//! manager, and only ever runs the fixed login-sandbox wrapper — the
//! peer-uid check is hygiene, not the load-bearing control.
//!
//! Wire protocol (one request per connection, newline-framed; argv is
//! length-prefixed to stay binary-safe):
//!   submit <argc>\n    then argc times: <len>\n<raw arg bytes>
//!       -> "ok <id>\n" | "err <msg>\n"
//!   list\n             -> "job <id> <active> <sub>\n"* "end\n"
//!   status <id>\n      -> "ok <active> <sub> <exitstatus>\n" | "err <msg>\n"
//!   stop <id>\n        -> "ok\n" | "err <msg>\n"

use std::{
    ffi::{OsStr, OsString},
    fs,
    io::{BufRead, BufReader, Read, Write},
    os::unix::{
        ffi::{OsStrExt, OsStringExt},
        io::{AsRawFd, FromRawFd},
        net::{UnixListener, UnixStream},
    },
    path::{Path, PathBuf},
    process::{Command, ExitCode},
    time::Duration,
};

/// Keep in sync with crates/sandbox/src/login.rs (HOME_SUBDIR).
const HOME_SUBDIR: &str = "sandbox";
/// Transient unit names are always <prefix>-<id>; the broker refuses to
/// touch anything else in the member's manager.
const UNIT_PREFIX: &str = "cwrunix-job";
/// Log directory, relative to the member-VISIBLE home (i.e. the subdir).
const LOG_REL: &str = ".local/share/cwrunix-jobs";

const MAX_ARGC: usize = 64;
const MAX_ARG_LEN: usize = 8192;
const MAX_ID: u32 = 999_999;

fn fail(msg: impl std::fmt::Display) -> ! {
    eprintln!("cwrunix-job: {msg}");
    std::process::exit(1);
}

struct Cfg {
    systemd_run: String,
    systemctl: String,
    login_sandbox: String,
    max_jobs: usize,
    runtime_max_sec: u64,
    log_limit_bytes: u64,
}

impl Cfg {
    fn from_env() -> Cfg {
        let env = |k: &str, d: &str| std::env::var(k).unwrap_or_else(|_| d.into());
        let num = |k: &str, d: u64| {
            std::env::var(k)
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(d)
        };
        Cfg {
            systemd_run: env("CWRUNIX_SYSTEMD_RUN", "systemd-run"),
            systemctl: env("CWRUNIX_SYSTEMCTL", "systemctl"),
            login_sandbox: env("CWRUNIX_LOGIN_SANDBOX", "/etc/cwrunix/login-sandbox"),
            max_jobs: num("CWRUNIX_MAX_JOBS", 4) as usize,
            runtime_max_sec: num("CWRUNIX_RUNTIME_MAX_SEC", 24 * 3600),
            log_limit_bytes: num("CWRUNIX_JOB_LOG_LIMIT", 512 * 1024 * 1024),
        }
    }
}

// ---------------------------------------------------------------- broker

fn daemon() -> ExitCode {
    let listener = activation_socket().unwrap_or_else(|| {
        let path =
            std::env::var("CWRUNIX_JOBS_SOCK").unwrap_or_else(|_| "/run/cwrunix-jobs.ctl".into());
        let _ = fs::remove_file(&path);
        UnixListener::bind(&path).unwrap_or_else(|e| fail(format!("bind {path}: {e}")))
    });
    let cfg = Cfg::from_env();
    for stream in listener.incoming().map_while(Result::ok) {
        let mut stream = stream;
        let reply = request(&mut stream, &cfg).unwrap_or_else(|e| format!("err {e}\n"));
        let _ = stream.write_all(reply.as_bytes());
    }
    ExitCode::SUCCESS
}

/// The socket passed by systemd socket activation (fd 3), if any.
fn activation_socket() -> Option<UnixListener> {
    let nfds: i32 = std::env::var("LISTEN_FDS").ok()?.parse().ok()?;
    let pid: u32 = std::env::var("LISTEN_PID").ok()?.parse().ok()?;
    if nfds != 1 || pid != std::process::id() {
        return None;
    }
    Some(unsafe { UnixListener::from_raw_fd(3) })
}

/// The connecting peer's uid (SO_PEERCRED; rendered in our user namespace,
/// which for a user service is the initial one).
fn peer_uid(stream: &UnixStream) -> Result<u32, String> {
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
    Ok(cred.uid)
}

fn request(stream: &mut UnixStream, cfg: &Cfg) -> Result<String, String> {
    if peer_uid(stream)? != unsafe { libc::getuid() } {
        return Err("peer is not the owner of this broker".into());
    }
    stream
        .set_read_timeout(Some(Duration::from_secs(10)))
        .map_err(|e| e.to_string())?;
    let mut reader = BufReader::new(stream);
    let mut line = String::new();
    reader.read_line(&mut line).map_err(|e| e.to_string())?;
    let mut parts = line.split_whitespace();
    match parts.next().unwrap_or("") {
        "submit" => {
            let argc: usize = parts
                .next()
                .and_then(|a| a.parse().ok())
                .ok_or("bad submit")?;
            if argc == 0 || argc > MAX_ARGC {
                return Err("bad argc".into());
            }
            let mut argv: Vec<OsString> = Vec::with_capacity(argc);
            for _ in 0..argc {
                let mut len_line = String::new();
                reader.read_line(&mut len_line).map_err(|e| e.to_string())?;
                let len: usize = len_line.trim().parse().map_err(|_| "bad arg length")?;
                if len > MAX_ARG_LEN {
                    return Err("arg too long".into());
                }
                let mut buf = vec![0u8; len];
                reader.read_exact(&mut buf).map_err(|e| e.to_string())?;
                argv.push(OsString::from_vec(buf));
            }
            submit(&argv, cfg)
        }
        "list" => list(cfg),
        "status" => status(parts.next().unwrap_or(""), cfg),
        "stop" => stop(parts.next().unwrap_or(""), cfg),
        other => Err(format!("unknown request '{other}'")),
    }
}

/// Job ids are small integers, only ever embedded in broker-generated unit
/// names — validate strictly so no unit outside our prefix can be named.
fn parse_id(s: &str) -> Result<u32, String> {
    if s.is_empty() || s.len() > 6 || !s.bytes().all(|b| b.is_ascii_digit()) {
        return Err("bad job id".into());
    }
    let id: u32 = s.parse().map_err(|_| "bad job id")?;
    if id == 0 || id > MAX_ID {
        return Err("bad job id".into());
    }
    Ok(id)
}

/// (id, active, sub) for every cwrunix-job unit, e.g. extra=["--all"] or
/// ["--state=active,activating"].
fn list_units(cfg: &Cfg, extra: &[&str]) -> Result<Vec<(u32, String, String)>, String> {
    let out = Command::new(&cfg.systemctl)
        .args([
            "--user",
            "list-units",
            "--type=service",
            "--no-legend",
            "--no-pager",
            "--plain",
        ])
        .args(extra)
        .arg(format!("{UNIT_PREFIX}-*"))
        .output()
        .map_err(|e| format!("systemctl: {e}"))?;
    if !out.status.success() {
        return Err(stderr_line("systemctl", &out.stderr));
    }
    let mut v = Vec::new();
    for line in String::from_utf8_lossy(&out.stdout).lines() {
        let mut f = line.split_whitespace();
        let (Some(unit), Some(_load), Some(active), Some(sub)) =
            (f.next(), f.next(), f.next(), f.next())
        else {
            continue;
        };
        let Some(id) = unit
            .strip_prefix(&format!("{UNIT_PREFIX}-"))
            .and_then(|s| s.strip_suffix(".service"))
            .and_then(|s| s.parse::<u32>().ok())
        else {
            continue;
        };
        v.push((id, active.to_string(), sub.to_string()));
    }
    Ok(v)
}

fn stderr_line(tool: &str, stderr: &[u8]) -> String {
    let msg = String::from_utf8_lossy(stderr);
    let msg = msg.lines().next().unwrap_or("failed").trim();
    format!("{tool}: {msg}")
}

fn submit(argv: &[OsString], cfg: &Cfg) -> Result<String, String> {
    let home = std::env::var_os("HOME")
        .map(PathBuf::from)
        .ok_or("HOME is unset")?;
    let visible_home = home.join(HOME_SUBDIR);
    let log_dir = visible_home.join(LOG_REL);
    fs::create_dir_all(&log_dir).map_err(|e| format!("creating {}: {e}", log_dir.display()))?;

    if list_units(cfg, &["--state=active,activating"])?.len() >= cfg.max_jobs {
        return Err(format!("job limit reached ({} concurrent)", cfg.max_jobs));
    }
    let base_id = list_units(cfg, &["--all"])?
        .iter()
        .map(|(id, _, _)| id + 1)
        .max()
        .unwrap_or(1);

    let mut last_err = String::new();
    for id in base_id..base_id + 3 {
        if id > MAX_ID {
            break;
        }
        let log = log_dir.join(format!("{id}.log"));
        // Ids recycle after unit GC; don't mix the previous job's log in.
        let _ = fs::remove_file(&log);
        match run_job(id, argv, cfg, &visible_home, &log) {
            Ok(()) => return Ok(format!("ok {id}\n")),
            // Concurrent submit grabbed the same id; try the next one.
            Err(e) if e.contains("already exists") => last_err = e,
            Err(e) => return Err(e),
        }
    }
    Err(if last_err.is_empty() {
        "job id space exhausted".into()
    } else {
        last_err
    })
}

fn run_job(
    id: u32,
    argv: &[OsString],
    cfg: &Cfg,
    visible_home: &Path,
    log: &Path,
) -> Result<(), String> {
    let unit = format!("{UNIT_PREFIX}-{id}");
    let out = Command::new(&cfg.systemd_run)
        .args([
            OsStr::new("--user"),
            OsStr::new("--quiet"),
            OsStr::new("--unit"),
            OsStr::new(&unit),
            OsStr::new("--property"),
            OsStr::new(&format!("RuntimeMaxSec={}", cfg.runtime_max_sec)),
            OsStr::new("--property"),
            OsStr::new(&format!("LimitFSIZE={}", cfg.log_limit_bytes)),
            OsStr::new("--property"),
            OsStr::new(&format!("StandardOutput=append:{}", log.display())),
            OsStr::new("--property"),
            OsStr::new(&format!("StandardError=append:{}", log.display())),
            OsStr::new("--property"),
            OsStr::new(&format!("SyslogIdentifier={unit}")),
            OsStr::new("--property"),
            OsStr::new(&format!("WorkingDirectory={}", visible_home.display())),
            OsStr::new("--"),
            OsStr::new(&cfg.login_sandbox),
            OsStr::new("--"),
        ])
        .args(argv)
        .stdin(std::process::Stdio::null())
        .output()
        .map_err(|e| format!("systemd-run: {e}"))?;
    if out.status.success() {
        Ok(())
    } else {
        Err(stderr_line("systemd-run", &out.stderr))
    }
}

fn list(cfg: &Cfg) -> Result<String, String> {
    let mut out = String::new();
    for (id, active, sub) in list_units(cfg, &["--all"])? {
        out.push_str(&format!("job {id} {active} {sub}\n"));
    }
    out.push_str("end\n");
    Ok(out)
}

fn status(id_str: &str, cfg: &Cfg) -> Result<String, String> {
    let id = parse_id(id_str)?;
    let unit = format!("{UNIT_PREFIX}-{id}.service");
    let out = Command::new(&cfg.systemctl)
        .args([
            "--user",
            "show",
            &unit,
            "-p",
            "LoadState,ActiveState,SubState,ExecMainStatus",
            "--value",
        ])
        .output()
        .map_err(|e| format!("systemctl: {e}"))?;
    if !out.status.success() {
        return Err(stderr_line("systemctl", &out.stderr));
    }
    let stdout = String::from_utf8_lossy(&out.stdout);
    let lines: Vec<&str> = stdout.lines().collect();
    if lines.len() < 4 || lines[0] == "not-found" {
        return Err("no such job (finished jobs are reaped; check the log file)".into());
    }
    Ok(format!("ok {} {} {}\n", lines[1], lines[2], lines[3]))
}

fn stop(id_str: &str, cfg: &Cfg) -> Result<String, String> {
    let id = parse_id(id_str)?;
    let unit = format!("{UNIT_PREFIX}-{id}.service");
    let out = Command::new(&cfg.systemctl)
        .args(["--user", "stop", &unit])
        .output()
        .map_err(|e| format!("systemctl: {e}"))?;
    if out.status.success() {
        Ok("ok\n".into())
    } else {
        Err(stderr_line("systemctl", &out.stderr))
    }
}

// ---------------------------------------------------------------- client

fn sock_path() -> String {
    std::env::var("CWRUNIX_JOBS_SOCK").unwrap_or_else(|_| "/run/cwrunix-jobs.ctl".into())
}

fn rpc(sock: &str, request: &[u8]) -> Result<String, String> {
    let mut s = UnixStream::connect(sock).map_err(|e| format!("connecting to the broker: {e}"))?;
    s.write_all(request).map_err(|e| e.to_string())?;
    let mut reply = String::new();
    s.read_to_string(&mut reply).map_err(|e| e.to_string())?;
    if let Some(msg) = reply.trim_start().strip_prefix("err ") {
        return Err(msg.trim_end().to_string());
    }
    Ok(reply)
}

fn usage() -> ! {
    eprintln!(
        "usage:
  cwrunix-job submit [--] <cmd> [args...]   run a command in the background
  cwrunix-job list                          list jobs
  cwrunix-job status <id>                   show job state + exit status
  cwrunix-job stop <id>                     stop a running job
  cwrunix-job log <id>                      print a job's log file
Jobs run in their own login sandbox and keep running after you log out.
Logs are plain files: ~/.local/share/cwrunix-jobs/<id>.log"
    );
    std::process::exit(2);
}

fn client() -> ExitCode {
    let args: Vec<OsString> = std::env::args_os().skip(1).collect();
    let sock = sock_path();
    let cmd = args.first().map(|a| a.to_string_lossy().into_owned());
    let code = match (cmd.as_deref(), args.get(1..).unwrap_or(&[])) {
        (Some("submit"), rest) => {
            let rest = if rest.first().map(|a| a.as_os_str()) == Some(OsStr::new("--")) {
                &rest[1..]
            } else {
                rest
            };
            if rest.is_empty() {
                usage();
            }
            let mut req = format!("submit {}\n", rest.len()).into_bytes();
            for a in rest {
                req.extend_from_slice(format!("{}\n", a.as_bytes().len()).as_bytes());
                req.extend_from_slice(a.as_bytes());
            }
            match rpc(&sock, &req) {
                Ok(reply) => match reply.trim().strip_prefix("ok ") {
                    Some(id) => {
                        println!("submitted job {id}");
                        println!("log: ~/.local/share/cwrunix-jobs/{id}.log");
                        0
                    }
                    None => {
                        eprintln!("cwrunix-job: bad reply: {}", reply.trim());
                        1
                    }
                },
                Err(e) => {
                    eprintln!("cwrunix-job: {e}");
                    1
                }
            }
        }
        (Some("list"), _) => match rpc(&sock, b"list\n") {
            Ok(reply) => {
                let mut shown = false;
                for line in reply.lines() {
                    if line == "end" {
                        break;
                    }
                    if let Some(rest) = line.strip_prefix("job ") {
                        shown = true;
                        println!("{rest}");
                    }
                }
                if !shown {
                    println!("no jobs");
                }
                0
            }
            Err(e) => {
                eprintln!("cwrunix-job: {e}");
                1
            }
        },
        (Some(op @ ("status" | "stop")), [id, ..]) => {
            let Some(id) = id.to_str().filter(|s| parse_id(s).is_ok()) else {
                usage();
            };
            match rpc(&sock, format!("{op} {id}\n").as_bytes()) {
                Ok(reply) => {
                    println!("{}", reply.trim().trim_start_matches("ok "));
                    0
                }
                Err(e) => {
                    eprintln!("cwrunix-job: {e}");
                    1
                }
            }
        }
        (Some("log"), [id, ..]) => {
            let Some(id) = id.to_str().and_then(|s| s.parse::<u32>().ok()) else {
                usage();
            };
            let home = std::env::var_os("HOME")
                .map(PathBuf::from)
                .unwrap_or_else(|| fail("HOME is unset"));
            let path = home.join(LOG_REL).join(format!("{id}.log"));
            match fs::File::open(&path) {
                Ok(mut f) => {
                    let _ = std::io::copy(&mut f, &mut std::io::stdout());
                    0
                }
                Err(e) => {
                    eprintln!("cwrunix-job: {}: {e}", path.display());
                    1
                }
            }
        }
        _ => usage(),
    };
    ExitCode::from(code)
}

fn main() -> ExitCode {
    let argv0 = std::env::args().next().unwrap_or_default();
    let base = Path::new(&argv0)
        .file_name()
        .map(|s| s.to_string_lossy().into_owned())
        .unwrap_or_default();
    if base == "cwrunix-jobsd" {
        daemon()
    } else {
        client()
    }
}
