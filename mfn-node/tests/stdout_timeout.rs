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
    Duration::from_secs(if github_actions_runner() { 120 } else { 30 })
}

/// Wait for a single log line prefix (dial ok, p2p listening, …).
pub fn p2p_line_timeout() -> Duration {
    Duration::from_secs(if github_actions_runner() { 150 } else { 90 })
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

/// Read until every prefix in `prefixes` has been seen once (any order);
/// returns the first matching line per prefix, in `prefixes` order.
///
/// M2.5.50 moved `mfnd_p2p_listening=` ahead of `mfnd_serve_listening=` on
/// stdout, so sequential prefix reads that assume the old order silently
/// discard the earlier line and then block forever. Startup announcements
/// must be collected order-independently.
pub fn read_stdout_lines_with_prefixes_any_order(
    out: &mut BufReader<ChildStdout>,
    prefixes: &[&str],
    timeout: Duration,
) -> Vec<String> {
    let deadline = Instant::now() + timeout;
    let mut found: Vec<Option<String>> = vec![None; prefixes.len()];
    let mut line = String::new();
    while found.iter().any(|f| f.is_none()) {
        if Instant::now() >= deadline {
            let missing: Vec<&str> = prefixes
                .iter()
                .zip(&found)
                .filter(|(_, f)| f.is_none())
                .map(|(p, _)| *p)
                .collect();
            panic!("timeout ({timeout:?}) waiting for {missing:?} (last line={line:?})");
        }
        line.clear();
        let n = out.read_line(&mut line).expect("read mfnd stdout");
        if n == 0 {
            let missing: Vec<&str> = prefixes
                .iter()
                .zip(&found)
                .filter(|(_, f)| f.is_none())
                .map(|(p, _)| *p)
                .collect();
            panic!("mfnd exited before {missing:?} (last line={line:?})");
        }
        for (i, prefix) in prefixes.iter().enumerate() {
            if found[i].is_none() && line.starts_with(prefix) {
                found[i] = Some(line.clone());
            }
        }
    }
    found
        .into_iter()
        .map(|f| f.expect("collected line"))
        .collect()
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
