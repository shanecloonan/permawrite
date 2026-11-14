//! Say whether a self-host layout leaks.

use std::env;
use std::process::ExitCode;

use mfn_doctor::audit_dir;

fn main() -> ExitCode {
    let dir = env::args().nth(1).unwrap_or_else(|| ".".into());
    match audit_dir(std::path::Path::new(&dir)) {
        Ok(report) => {
            print!("{}", report.render());
            if report.ok() {
                ExitCode::SUCCESS
            } else {
                ExitCode::from(1)
            }
        }
        Err(e) => {
            eprintln!("{e}");
            ExitCode::from(1)
        }
    }
}
