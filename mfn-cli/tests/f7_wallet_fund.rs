//! Wait until a wallet has enough owned UTXOs for F7 `min_input_count=2` uploads.

use std::path::Path;
use std::process::Command;
use std::thread;
use std::time::{Duration, Instant};

/// Minimum owned outputs before reference wallet uploads under production policy.
pub const F7_MIN_OWNED_FOR_TX: usize = 2;

fn parse_stdout_field(stdout: &str, key: &str) -> String {
    let prefix = format!("{key}=");
    stdout
        .lines()
        .find_map(|line| line.strip_prefix(&prefix).map(str::to_string))
        .unwrap_or_else(|| panic!("stdout missing {prefix}:\n{stdout}"))
}

fn wallet_scan(spawn_cli: &dyn Fn() -> Command, rpc: &str, wallet: &Path) {
    let out = spawn_cli()
        .args(["--rpc", rpc, "--wallet"])
        .arg(wallet)
        .args(["wallet", "scan"])
        .output()
        .expect("wallet scan");
    assert!(
        out.status.success(),
        "scan stderr={}",
        String::from_utf8_lossy(&out.stderr)
    );
}

fn wallet_owned_count(spawn_cli: &dyn Fn() -> Command, rpc: &str, wallet: &Path) -> usize {
    let out = spawn_cli()
        .args(["--rpc", rpc, "--wallet"])
        .arg(wallet)
        .args(["wallet", "balance"])
        .output()
        .expect("wallet balance");
    assert!(
        out.status.success(),
        "balance stderr={}",
        String::from_utf8_lossy(&out.stderr)
    );
    parse_stdout_field(&String::from_utf8_lossy(&out.stdout), "owned_count")
        .parse()
        .expect("owned_count usize")
}

/// Scan + poll until the wallet owns at least [`F7_MIN_OWNED_FOR_TX`] spendable outputs.
pub fn wait_wallet_f7_ready(
    spawn_cli: &dyn Fn() -> Command,
    rpc: &str,
    wallet: &Path,
    timeout: Duration,
) {
    let deadline = Instant::now() + timeout;
    loop {
        wallet_scan(spawn_cli, rpc, wallet);
        let owned = wallet_owned_count(spawn_cli, rpc, wallet);
        if owned >= F7_MIN_OWNED_FOR_TX {
            return;
        }
        if Instant::now() >= deadline {
            panic!(
                "timeout: wallet needs >= {} owned outputs for F7 upload (last owned_count={owned})",
                F7_MIN_OWNED_FOR_TX
            );
        }
        thread::sleep(Duration::from_millis(200));
    }
}
