//! `mfn-repro` — print a reproducible build plan or compare two hash manifests.

use std::env;
use std::fs;
use std::io::{self, Read, Write};
use std::process::ExitCode;

use mfn_repro::{compare_manifests, parse_manifest, source_inventory, ReproPlan};

fn main() -> ExitCode {
    let mut args = env::args().skip(1);
    let cmd = args.next().unwrap_or_else(|| "help".to_string());
    match cmd.as_str() {
        "plan" => cmd_plan(args),
        "compare" => cmd_compare(args),
        "inventory" => cmd_inventory(args),
        "help" | "--help" | "-h" => {
            println!("{}", HELP);
            ExitCode::SUCCESS
        }
        other => {
            eprintln!("unknown command {other}\n{HELP}");
            ExitCode::from(2)
        }
    }
}

const HELP: &str = "\
mfn-repro plan --epoch SECONDS --target TRIPLE [--root PATH]
mfn-repro compare LEFT.sha256 RIGHT.sha256
mfn-repro inventory PATH [PATH...]
";

fn cmd_plan(args: impl Iterator<Item = String>) -> ExitCode {
    let (epoch, target, root) = match parse_plan_args(args) {
        Ok(v) => v,
        Err(err) => {
            eprintln!("{err}");
            return ExitCode::from(2);
        }
    };
    let plan = ReproPlan::new(epoch, target, root);
    let mut out = io::stdout().lock();
    let _ = writeln!(out, "rustc={}", plan.rustc);
    let _ = writeln!(out, "target={}", plan.target);
    let _ = write!(out, "{}", plan.shell_exports());
    for bin in plan.binaries {
        let _ = writeln!(out, "binary={bin}");
    }
    if plan.hides_builder_path() {
        ExitCode::SUCCESS
    } else {
        eprintln!("plan does not remap the workspace path");
        ExitCode::from(1)
    }
}

fn parse_plan_args(args: impl Iterator<Item = String>) -> Result<(u64, String, String), String> {
    let args: Vec<String> = args.collect();
    let mut epoch = None;
    let mut target = None;
    let mut root = env::current_dir()
        .map(|p| p.display().to_string())
        .unwrap_or_else(|_| ".".to_string());
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--epoch" => {
                i += 1;
                let raw = args.get(i).ok_or("--epoch needs a unix timestamp")?;
                epoch = Some(raw.parse::<u64>().map_err(|_| format!("bad epoch {raw}"))?);
            }
            "--target" => {
                i += 1;
                target = Some(args.get(i).ok_or("--target needs a triple")?.clone());
            }
            "--root" => {
                i += 1;
                root = args.get(i).ok_or("--root needs a path")?.clone();
            }
            other => return Err(format!("unknown plan argument {other}")),
        }
        i += 1;
    }
    Ok((
        epoch.ok_or("--epoch is required")?,
        target.ok_or("--target is required")?,
        root,
    ))
}

fn cmd_compare(args: impl Iterator<Item = String>) -> ExitCode {
    let args: Vec<String> = args.collect();
    if args.len() != 2 {
        eprintln!("compare needs LEFT.sha256 RIGHT.sha256");
        return ExitCode::from(2);
    }
    let left = match read_manifest(&args[0]) {
        Ok(v) => v,
        Err(err) => {
            eprintln!("{}: {err}", args[0]);
            return ExitCode::from(1);
        }
    };
    let right = match read_manifest(&args[1]) {
        Ok(v) => v,
        Err(err) => {
            eprintln!("{}: {err}", args[1]);
            return ExitCode::from(1);
        }
    };
    let report = compare_manifests(&left, &right);
    if report.is_match() {
        println!("match artifacts={}", left.len());
        ExitCode::SUCCESS
    } else {
        for name in &report.mismatched {
            println!("mismatch {name}");
        }
        for name in &report.only_left {
            println!("only-left {name}");
        }
        for name in &report.only_right {
            println!("only-right {name}");
        }
        ExitCode::from(1)
    }
}

fn read_manifest(path: &str) -> Result<Vec<mfn_repro::compare::HashEntry>, String> {
    let text = if path == "-" {
        let mut buf = String::new();
        io::stdin()
            .read_to_string(&mut buf)
            .map_err(|e| e.to_string())?;
        buf
    } else {
        fs::read_to_string(path).map_err(|e| e.to_string())?
    };
    parse_manifest(&text).map_err(|e| e.to_string())
}

fn cmd_inventory(args: impl Iterator<Item = String>) -> ExitCode {
    let paths: Vec<String> = args.collect();
    if paths.is_empty() {
        eprintln!("inventory needs at least one path");
        return ExitCode::from(2);
    }
    match source_inventory(&paths) {
        Ok(inv) => {
            print!("{}", inv.render());
            ExitCode::SUCCESS
        }
        Err(err) => {
            eprintln!("{err}");
            ExitCode::from(1)
        }
    }
}
