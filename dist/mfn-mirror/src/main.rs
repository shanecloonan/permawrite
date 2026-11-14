//! `mfn-mirror` — print the CID, magnet, and chain root of a file.

use std::env;
use std::fs;
use std::process::ExitCode;

use mfn_mirror::{describe, verify, MirrorRecord};

fn main() -> ExitCode {
    let args: Vec<String> = env::args().skip(1).collect();
    match args.first().map(String::as_str) {
        Some("describe") => describe_cmd(&args[1..]),
        Some("verify") => verify_cmd(&args[1..]),
        _ => {
            println!("mfn-mirror describe --name NAME --file PATH\nmfn-mirror verify --record FILE --file PATH");
            ExitCode::SUCCESS
        }
    }
}

fn describe_cmd(args: &[String]) -> ExitCode {
    let (Some(name), Some(path)) = (flag(args, "--name"), flag(args, "--file")) else {
        eprintln!("describe needs --name and --file");
        return ExitCode::from(2);
    };
    let bytes = match fs::read(path) {
        Ok(b) => b,
        Err(err) => {
            eprintln!("{err}");
            return ExitCode::from(1);
        }
    };
    match describe(name, &bytes) {
        Ok(record) => {
            print!("{}", record.render());
            ExitCode::SUCCESS
        }
        Err(err) => {
            eprintln!("{err}");
            ExitCode::from(1)
        }
    }
}

fn verify_cmd(args: &[String]) -> ExitCode {
    let (Some(record_path), Some(path)) = (flag(args, "--record"), flag(args, "--file")) else {
        eprintln!("verify needs --record and --file");
        return ExitCode::from(2);
    };
    let text = match fs::read_to_string(record_path) {
        Ok(t) => t,
        Err(err) => {
            eprintln!("{err}");
            return ExitCode::from(1);
        }
    };
    let record = match MirrorRecord::parse(&text) {
        Ok(r) => r,
        Err(err) => {
            eprintln!("{err}");
            return ExitCode::from(1);
        }
    };
    let bytes = match fs::read(path) {
        Ok(b) => b,
        Err(err) => {
            eprintln!("{err}");
            return ExitCode::from(1);
        }
    };
    match verify(&bytes, &record) {
        Ok(()) => {
            println!("ok {}", record.cid);
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
