//! Integration smoke tests for the `mfnd` binary (M2.1.1 + M2.1.2).

use std::path::PathBuf;
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

fn mfnd() -> Command {
    Command::new(env!("CARGO_BIN_EXE_mfnd"))
}

fn unique_data_dir(test: &str) -> PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock")
        .as_nanos();
    std::env::temp_dir().join(format!(
        "permawrite-mfnd-{test}-{}-{nanos}",
        std::process::id()
    ))
}

#[test]
fn mfnd_status_boots_genesis_without_checkpoint() {
    let dir = unique_data_dir("status_no_ckpt");
    let out = mfnd()
        .args(["--data-dir"])
        .arg(&dir)
        .arg("status")
        .output()
        .expect("spawn mfnd");
    assert!(
        out.status.success(),
        "stderr={}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("tip_height=0"), "stdout={stdout}");
    assert!(
        stdout.contains("had_checkpoint_on_disk=false"),
        "stdout={stdout}"
    );
    assert!(stdout.contains("validator_count=0"), "stdout={stdout}");
    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn mfnd_save_then_status_sees_checkpoint() {
    let dir = unique_data_dir("save_status");
    assert!(mfnd()
        .args(["--data-dir"])
        .arg(&dir)
        .arg("save")
        .status()
        .expect("spawn")
        .success());
    let out = mfnd()
        .args(["--data-dir"])
        .arg(&dir)
        .arg("status")
        .output()
        .expect("spawn mfnd status");
    assert!(out.status.success());
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("had_checkpoint_on_disk=true"),
        "stdout={stdout}"
    );
    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn mfnd_status_with_json_genesis_spec() {
    let dir = unique_data_dir("genesis_spec");
    let spec = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("testdata/devnet_one_validator.json");
    let out = mfnd()
        .args(["--data-dir"])
        .arg(&dir)
        .arg("--genesis")
        .arg(&spec)
        .arg("status")
        .output()
        .expect("spawn mfnd");
    assert!(
        out.status.success(),
        "stderr={}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("tip_height=0"), "stdout={stdout}");
    assert!(stdout.contains("validator_count=1"), "stdout={stdout}");
    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn mfnd_errors_without_data_dir() {
    let out = mfnd().arg("status").output().expect("spawn");
    assert!(!out.status.success());
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("--data-dir") || stderr.contains("data-dir"),
        "stderr={stderr}"
    );
}
