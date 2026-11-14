//! `mfn-repro` — print the reproducible-build profile, hash a directory,
//! or fail if two directories are not byte-identical.

use std::env;
use std::path::Path;
use std::process::ExitCode;

use mfn_repro::{
    compare, format_checksums, hash_tree, parse_checksums, plan, verify_tree, PROFILE_NAME,
};

fn main() -> ExitCode {
    let mut args = env::args().skip(1);
    let cmd = args.next().unwrap_or_else(|| "plan".to_string());
    match cmd.as_str() {
        "plan" => {
            let workspace = args.next().unwrap_or_else(|| {
                env::current_dir()
                    .map(|p| p.display().to_string())
                    .unwrap_or_else(|_| "/permawrite".to_string())
            });
            print!("{}", plan(&workspace));
            ExitCode::SUCCESS
        }
        "hash" => hash_cmd(args.next()),
        "compare" => compare_cmd(args.next(), args.next()),
        "verify" => verify_cmd(args.next(), args.next()),
        "help" | "-h" | "--help" => {
            eprintln!(
                "{PROFILE_NAME}\nusage: mfn-repro plan [WORKSPACE]\n       mfn-repro hash DIR\n       mfn-repro compare DIR_A DIR_B\n       mfn-repro verify DIR CHECKSUMS"
            );
            ExitCode::SUCCESS
        }
        other => {
            eprintln!("unknown command {other}");
            ExitCode::from(2)
        }
    }
}

fn hash_cmd(dir: Option<String>) -> ExitCode {
    let Some(dir) = dir else {
        eprintln!("hash needs a directory");
        return ExitCode::from(2);
    };
    match hash_tree(Path::new(&dir)) {
        Ok(files) => {
            print!("{}", format_checksums(&files));
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("{e}");
            ExitCode::from(1)
        }
    }
}

fn compare_cmd(left: Option<String>, right: Option<String>) -> ExitCode {
    let (Some(left), Some(right)) = (left, right) else {
        eprintln!("compare needs two directories");
        return ExitCode::from(2);
    };
    let left_h = match hash_tree(Path::new(&left)) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("{e}");
            return ExitCode::from(1);
        }
    };
    let right_h = match hash_tree(Path::new(&right)) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("{e}");
            return ExitCode::from(1);
        }
    };
    match compare(&left_h, &right_h) {
        Ok(()) => {
            println!("repro compare ok files={}", left_h.len());
            ExitCode::SUCCESS
        }
        Err(bad) => {
            for item in &bad {
                eprintln!(
                    "mismatch {} left={} right={}",
                    item.rel,
                    item.left.as_deref().unwrap_or("-"),
                    item.right.as_deref().unwrap_or("-")
                );
            }
            ExitCode::from(1)
        }
    }
}

fn verify_cmd(dir: Option<String>, checksums: Option<String>) -> ExitCode {
    let (Some(dir), Some(checksums)) = (dir, checksums) else {
        eprintln!("verify needs DIR and CHECKSUMS");
        return ExitCode::from(2);
    };
    let text = match std::fs::read_to_string(&checksums) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("io error at {checksums}: {e}");
            return ExitCode::from(1);
        }
    };
    let expected = match parse_checksums(&text) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("{e}");
            return ExitCode::from(1);
        }
    };
    match verify_tree(Path::new(&dir), &expected) {
        Ok(()) => {
            println!("repro verify ok files={}", expected.len());
            ExitCode::SUCCESS
        }
        Err(bad) => {
            for item in bad {
                eprintln!(
                    "mismatch {} left={} right={}",
                    item.rel,
                    item.left.as_deref().unwrap_or("-"),
                    item.right.as_deref().unwrap_or("-")
                );
            }
            ExitCode::from(1)
        }
    }
}
