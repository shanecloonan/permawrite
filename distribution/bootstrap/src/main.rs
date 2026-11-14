//! Check a directory against a bootstrap document. Does not open a socket.

use std::env;
use std::fs;
use std::process::ExitCode;

use mfn_bootstrap::{check_dir, parse};

fn main() -> ExitCode {
    let mut args = env::args().skip(1);
    let doc_path = args.next().unwrap_or_else(|| "bootstrap.txt".into());
    let dir = args.next().unwrap_or_else(|| ".".into());
    let text = match fs::read_to_string(&doc_path) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("{e}");
            return ExitCode::from(1);
        }
    };
    let doc = match parse(&text) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("{e}");
            return ExitCode::from(1);
        }
    };
    match check_dir(std::path::Path::new(&dir), &doc) {
        Ok(()) => {
            println!(
                "bootstrap ok files={} urls={} bundle={}",
                doc.files.len(),
                doc.urls.len(),
                doc.bundle_sha256
            );
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("{e}");
            ExitCode::from(1)
        }
    }
}
