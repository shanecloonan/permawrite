//! Shared stdout readers with deadlines for multi-process `mfnd` smokes (**M2.3.27**).

use std::io::{BufRead, BufReader};
use std::net::SocketAddr;
use std::process::ChildStdout;
use std::time::{Duration, Instant};

fn github_actions_runner() -> bool {
    std::env::var("GITHUB_ACTIONS").is_ok()
}

/// Wait for `mfnd_serve_listening=` (longer on GitHub Actions runners).
pub fn serve_listen_timeout() -> Duration {
    Duration::from_secs(if github_actions_runner() { 90 } else { 30 })
}

/// Wait for a single log line prefix (dial ok, p2p listening, …).
pub fn p2p_line_timeout() -> Duration {
    Duration::from_secs(if github_actions_runner() { 120 } else { 90 })
}

/// Wait for `mfnd_p2p_sync_end` after block pull.
pub fn p2p_sync_end_timeout() -> Duration {
    Duration::from_secs(if github_actions_runner() { 300 } else { 180 })
}

/// Skips unrelated stdout lines (parallel tests may share a console).
pub fn read_mfnd_serve_listening_addr(
    out_reader: &mut BufReader<ChildStdout>,
    timeout: Duration,
) -> SocketAddr {
    let line = read_stdout_line_with_prefix(out_reader, "mfnd_serve_listening=", timeout);
    line.strip_prefix("mfnd_serve_listening=")
        .expect("listening prefix")
        .trim()
        .parse()
        .expect("parse socket addr")
}

/// Read until a line starts with `prefix`, or panic on timeout / early exit.
pub fn read_stdout_line_with_prefix(
    out: &mut BufReader<ChildStdout>,
    prefix: &str,
    timeout: Duration,
) -> String {
    let deadline = Instant::now() + timeout;
    let mut line = String::new();
    loop {
        if Instant::now() >= deadline {
            panic!("timeout ({timeout:?}) waiting for `{prefix}` (last line={line:?})");
        }
        line.clear();
        let n = out.read_line(&mut line).expect("read mfnd stdout");
        if n == 0 {
            panic!("mfnd exited before `{prefix}` (last line={line:?})");
        }
        if line.starts_with(prefix) {
            return line;
        }
    }
}

/// Read until `mfnd_p2p_sync_end` or fail on `mfnd_p2p_sync_abort`.
pub fn read_stdout_until_p2p_sync_end(
    out: &mut BufReader<ChildStdout>,
    timeout: Duration,
) -> String {
    read_stdout_until_prefix(
        out,
        "mfnd_p2p_sync_end ",
        Some("mfnd_p2p_sync_abort "),
        timeout,
    )
}

/// Generic prefix waiter with optional abort prefix.
pub fn read_stdout_until_prefix(
    out: &mut BufReader<ChildStdout>,
    ok_prefix: &str,
    abort_prefix: Option<&str>,
    timeout: Duration,
) -> String {
    let deadline = Instant::now() + timeout;
    let mut line = String::new();
    loop {
        if Instant::now() >= deadline {
            panic!("timeout ({timeout:?}) waiting for `{ok_prefix}` (last line={line:?})");
        }
        line.clear();
        let n = out.read_line(&mut line).expect("read mfnd stdout");
        if n == 0 {
            panic!("mfnd exited before `{ok_prefix}` (last line={line:?})");
        }
        if line.starts_with(ok_prefix) {
            return line;
        }
        if let Some(abort) = abort_prefix {
            if line.starts_with(abort) {
                panic!("mfnd aborted: {line}");
            }
        }
    }
}
