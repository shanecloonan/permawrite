//! Pack a directory into a deterministic ustar archive and print its SHA-256.

use std::env;
use std::fs;
use std::process::ExitCode;

use mfn_source_archive::{archive_sha256, pack, read_tree};

fn main() -> ExitCode {
    let mut args = env::args().skip(1);
    let dir = args.next().unwrap_or_else(|| ".".into());
    let out = args.next();
    let entries = match read_tree(std::path::Path::new(&dir)) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("{e}");
            return ExitCode::from(1);
        }
    };
    let bytes = match pack(&entries) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("{e}");
            return ExitCode::from(1);
        }
    };
    let digest = archive_sha256(&bytes);
    if let Some(path) = out {
        if let Err(e) = fs::write(&path, &bytes) {
            eprintln!("{e}");
            return ExitCode::from(1);
        }
    }
    println!("source-archive sha256={digest} files={}", entries.len());
    ExitCode::SUCCESS
}
