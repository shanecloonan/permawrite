//! `mfn-source-bundle` — pack a file list into a deterministic ustar.

use std::env;
use std::fs;
use std::process::ExitCode;

use mfn_source_bundle::{bundle_sha256, pack, SourceFile};

fn main() -> ExitCode {
    let args: Vec<String> = env::args().skip(1).collect();
    if args.first().map(String::as_str) != Some("pack") {
        println!("mfn-source-bundle pack --epoch SECONDS --file REL=PATH --out FILE");
        return ExitCode::SUCCESS;
    }
    let Some(epoch) = flag(&args, "--epoch") else {
        eprintln!("--epoch is required");
        return ExitCode::from(2);
    };
    let Some(out) = flag(&args, "--out") else {
        eprintln!("--out is required");
        return ExitCode::from(2);
    };
    let epoch: u64 = match epoch.parse() {
        Ok(v) => v,
        Err(_) => return ExitCode::from(2),
    };
    let mut files = Vec::new();
    let mut i = 0;
    while i < args.len() {
        if args[i] == "--file" {
            let Some(spec) = args.get(i + 1) else {
                return ExitCode::from(2);
            };
            let Some((rel, path)) = spec.split_once('=') else {
                return ExitCode::from(2);
            };
            let bytes = match fs::read(path) {
                Ok(b) => b,
                Err(err) => {
                    eprintln!("{err}");
                    return ExitCode::from(1);
                }
            };
            files.push(SourceFile {
                path: rel.to_string(),
                bytes,
            });
            i += 2;
            continue;
        }
        i += 1;
    }
    match pack(&files, epoch) {
        Ok(archive) => {
            if let Err(err) = fs::write(out, &archive) {
                eprintln!("{err}");
                return ExitCode::from(1);
            }
            println!("{}", bundle_sha256(&archive));
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
