//! cwrunix-sandbox: the CWRUnix member login sandbox — one binary, several
//! roles (the server config's nixos/sandbox/ has the design comments):
//!
//!   login        forced login shell for remote (LDAP) users; outer
//!                orchestration (identity, /etc, id maps, slirp4netns)
//!   netns-setup  inner setup shim, spawned by `login` inside the outer
//!                user+net+mount namespaces (network, FUSE /nix mirror,
//!                nested-userns plumbing, bwrap)
//!   holder-u2    the U2 namespace holder: after its map lands it re-execs
//!                (gaining caps) and creates+maps U3, the payload namespace
//!   holder       parked holder keeping a namespace alive for an fd
//!
//! The only privileged component anywhere is cwrunix-subid-map (separate
//! crate/binary, setuid via a security.wrappers entry on the host).

mod login;
mod netns;
mod util;

use std::process::ExitCode;

fn main() -> ExitCode {
    let mut argv = std::env::args_os();
    let _argv0 = argv.next();
    let args: Vec<_> = argv.collect();
    let Some(role) = args.first().and_then(|a| a.to_str()) else {
        util::fail("usage: cwrunix-sandbox <login|netns-setup|holder-u2|holder> ...");
    };
    match role {
        "login" => login::main(&args[1..]),
        "netns-setup" => netns::main(&args[1..]),
        "holder-u2" => netns::holder_u2(&args[1..]),
        "holder" => util::park(),
        other => util::fail(format!("unknown role '{other}'")),
    }
}
