//! Integration smoke tests for the `mfnd` binary (M2.1.1 + M2.1.2 + M2.1.3 + M2.1.4).

use std::path::PathBuf;
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

/// Seeds aligned with `testdata/devnet_one_validator.json` validator index 0.
const DEVNET_SOLO_VRF_SEED_HEX: &str =
    "0101010101010101010101010101010101010101010101010101010101010101";
const DEVNET_SOLO_BLS_SEED_HEX: &str =
    "6565656565656565656565656565656565656565656565656565656565656565";

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

#[test]
fn mfnd_step_requires_solo_seed_env() {
    let dir = unique_data_dir("step_no_env");
    let spec = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("testdata/devnet_one_validator.json");
    let out = mfnd()
        .args(["--data-dir"])
        .arg(&dir)
        .arg("--genesis")
        .arg(&spec)
        .env_remove("MFND_SOLO_VRF_SEED_HEX")
        .env_remove("MFND_SOLO_BLS_SEED_HEX")
        .arg("step")
        .output()
        .expect("spawn mfnd step");
    assert!(
        !out.status.success(),
        "expected failure without seeds, stdout={}",
        String::from_utf8_lossy(&out.stdout)
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("MFND_SOLO_VRF_SEED_HEX") || stderr.contains("MFND_SOLO_BLS_SEED_HEX"),
        "stderr={stderr}"
    );
    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn mfnd_step_twice_advances_tip_under_devnet_spec() {
    let dir = unique_data_dir("step_twice");
    let spec = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("testdata/devnet_one_validator.json");
    let run_step = || {
        mfnd()
            .args(["--data-dir"])
            .arg(&dir)
            .arg("--genesis")
            .arg(&spec)
            .env("MFND_SOLO_VRF_SEED_HEX", DEVNET_SOLO_VRF_SEED_HEX)
            .env("MFND_SOLO_BLS_SEED_HEX", DEVNET_SOLO_BLS_SEED_HEX)
            .arg("step")
            .output()
            .expect("spawn mfnd step")
    };
    let o1 = run_step();
    assert!(
        o1.status.success(),
        "stderr={}",
        String::from_utf8_lossy(&o1.stderr)
    );
    let stdout1 = String::from_utf8_lossy(&o1.stdout);
    assert!(stdout1.contains("new_tip_height=1"), "stdout={stdout1}");
    let o2 = run_step();
    assert!(
        o2.status.success(),
        "stderr={}",
        String::from_utf8_lossy(&o2.stderr)
    );
    let stdout2 = String::from_utf8_lossy(&o2.stdout);
    assert!(stdout2.contains("new_tip_height=2"), "stdout={stdout2}");
    let st = mfnd()
        .args(["--data-dir"])
        .arg(&dir)
        .arg("--genesis")
        .arg(&spec)
        .arg("status")
        .output()
        .expect("spawn mfnd status");
    assert!(st.status.success());
    let stout = String::from_utf8_lossy(&st.stdout);
    assert!(stout.contains("tip_height=2"), "stdout={stout}");
    assert!(
        stout.contains("had_checkpoint_on_disk=true"),
        "stdout={stout}"
    );
    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn mfnd_step_blocks_advances_tip_in_one_invocation() {
    let dir = unique_data_dir("step_blocks");
    let spec = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("testdata/devnet_one_validator.json");
    let out = mfnd()
        .args(["--data-dir"])
        .arg(&dir)
        .arg("--genesis")
        .arg(&spec)
        .arg("--blocks")
        .arg("3")
        .env("MFND_SOLO_VRF_SEED_HEX", DEVNET_SOLO_VRF_SEED_HEX)
        .env("MFND_SOLO_BLS_SEED_HEX", DEVNET_SOLO_BLS_SEED_HEX)
        .arg("step")
        .output()
        .expect("spawn mfnd step --blocks 3");
    assert!(
        out.status.success(),
        "stderr={}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("new_tip_height=3"), "stdout={stdout}");
    let st = mfnd()
        .args(["--data-dir"])
        .arg(&dir)
        .arg("--genesis")
        .arg(&spec)
        .arg("status")
        .output()
        .expect("spawn mfnd status");
    assert!(st.status.success());
    let stout = String::from_utf8_lossy(&st.stdout);
    assert!(stout.contains("tip_height=3"), "stdout={stout}");
    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn mfnd_step_rejects_empty_validator_genesis() {
    let dir = unique_data_dir("step_empty_vals");
    let out = mfnd()
        .args(["--data-dir"])
        .arg(&dir)
        .env("MFND_SOLO_VRF_SEED_HEX", DEVNET_SOLO_VRF_SEED_HEX)
        .env("MFND_SOLO_BLS_SEED_HEX", DEVNET_SOLO_BLS_SEED_HEX)
        .arg("step")
        .output()
        .expect("spawn mfnd step");
    assert!(!out.status.success());
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("exactly one validator") || stderr.contains("got 0"),
        "stderr={stderr}"
    );
    std::fs::remove_dir_all(&dir).ok();
}
