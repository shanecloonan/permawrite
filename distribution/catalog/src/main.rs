//! Print the newest release whose mirrors agree.

use std::env;
use std::fs;
use std::process::ExitCode;

use mfn_catalog::{parse, select};

fn main() -> ExitCode {
    let path = env::args().nth(1).unwrap_or_else(|| "catalog.txt".into());
    let text = match fs::read_to_string(&path) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("{e}");
            return ExitCode::from(1);
        }
    };
    let catalog = match parse(&text) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("{e}");
            return ExitCode::from(1);
        }
    };
    match select(&catalog) {
        Ok(choice) => {
            println!(
                "catalog ok version={} mirrors={} bundle={}",
                choice.version, choice.mirrors, choice.bundle_sha256
            );
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("{e}");
            ExitCode::from(1)
        }
    }
}
