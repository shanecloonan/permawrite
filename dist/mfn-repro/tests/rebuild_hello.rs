//! Two compiles of the same source, with the release flags, must match.

use std::fs;
use std::process::Command;

use mfn_repro::{hash_bytes, rustflags_for};

#[test]
fn hello_world_rebuilds_to_the_same_bytes() {
    let root = std::env::temp_dir().join(format!("mfn-repro-hello-{}", std::process::id()));
    let _ = fs::remove_dir_all(&root);
    fs::create_dir_all(&root).unwrap();
    fs::write(root.join("hello.rs"), "fn main() {}\n").unwrap();
    let flags = rustflags_for("x86_64-unknown-linux-gnu", &root.display().to_string());
    let first = compile(&root, &flags, "hello-a");
    let second = compile(&root, &flags, "hello-b");
    assert_eq!(hash_bytes(&first), hash_bytes(&second));
    assert!(!first.is_empty());
    let _ = fs::remove_dir_all(&root);
}

fn compile(dir: &std::path::Path, flags: &str, out_name: &str) -> Vec<u8> {
    let out = dir.join(out_name);
    let status = Command::new("rustc")
        .current_dir(dir)
        .env("SOURCE_DATE_EPOCH", "1700000000")
        .env("LC_ALL", "C")
        .env("TZ", "UTC")
        .arg("--edition")
        .arg("2021")
        .args(flags.split_whitespace())
        .arg("hello.rs")
        .arg("-o")
        .arg(&out)
        .status()
        .expect("rustc");
    assert!(status.success(), "rustc failed with {flags}");
    fs::read(out).unwrap()
}
