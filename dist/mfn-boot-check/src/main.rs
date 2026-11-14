//! `mfn-boot-check` — read an env file and a unit file, then say if boot is Tor-only.

use std::env;
use std::fs;
use std::process::ExitCode;

use mfn_boot_check::check_boot;

fn main() -> ExitCode {
    let args: Vec<String> = env::args().skip(1).collect();
    let (Some(env_path), Some(unit_path)) = (flag(&args, "--env"), flag(&args, "--unit")) else {
        println!("mfn-boot-check --env FILE --unit FILE");
        return ExitCode::SUCCESS;
    };
    let env_text = match fs::read_to_string(env_path) {
        Ok(t) => t,
        Err(err) => {
            eprintln!("{err}");
            return ExitCode::from(1);
        }
    };
    let unit_text = match fs::read_to_string(unit_path) {
        Ok(t) => t,
        Err(err) => {
            eprintln!("{err}");
            return ExitCode::from(1);
        }
    };
    match check_boot(&env_text, &unit_text) {
        Ok(()) => {
            println!("ok tor-only");
            ExitCode::SUCCESS
        }
        Err(err) => {
            eprintln!("{err}");
            ExitCode::from(1)
        }
    }
}

fn flag<'a>(args: &'a [String], name: &str) -> Option<&'a str> {
    args.windows(2)
        .find(|w| w[0] == name)
        .map(|w| w[1].as_str())
}
