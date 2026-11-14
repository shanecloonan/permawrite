//! Write a Tor-only node layout, or print it.

use std::env;
use std::fs;
use std::path::Path;
use std::process::ExitCode;

use mfn_node_setup::{render, DialMode};

fn main() -> ExitCode {
    let mut args = env::args().skip(1);
    let mut mode = DialMode::TorOnly { onion: None };
    let mut out: Option<String> = None;
    let mut data = "/var/lib/permawrite".to_string();
    let mut genesis = "/var/lib/permawrite/genesis.json".to_string();
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--onion" => {
                let Some(onion) = args.next() else {
                    eprintln!("missing --onion value");
                    return ExitCode::from(2);
                };
                mode = DialMode::TorOnly { onion: Some(onion) };
            }
            "--allow-clearnet" => {
                let Some(seed) = args.next() else {
                    eprintln!("missing clearnet seed");
                    return ExitCode::from(2);
                };
                mode = DialMode::Clearnet { seed };
            }
            "--data-dir" => {
                let Some(v) = args.next() else {
                    eprintln!("missing --data-dir");
                    return ExitCode::from(2);
                };
                data = v;
            }
            "--genesis" => {
                let Some(v) = args.next() else {
                    eprintln!("missing --genesis");
                    return ExitCode::from(2);
                };
                genesis = v;
            }
            "--write" => {
                let Some(v) = args.next() else {
                    eprintln!("missing --write directory");
                    return ExitCode::from(2);
                };
                out = Some(v);
            }
            "--plan-only" | "--help" | "-h" => {}
            other => {
                eprintln!("unknown argument {other}");
                return ExitCode::from(2);
            }
        }
    }
    let layout = match render(&data, &genesis, &mode) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("{e}");
            return ExitCode::from(1);
        }
    };
    if let Some(dir) = out {
        let dir = Path::new(&dir);
        if let Err(e) = fs::create_dir_all(dir) {
            eprintln!("{e}");
            return ExitCode::from(1);
        }
        let files = [
            ("permawrite-node.service", layout.systemd.as_str()),
            ("permawrite-torrc", layout.torrc.as_str()),
            ("Containerfile", layout.containerfile.as_str()),
            ("entrypoint.sh", layout.entrypoint.as_str()),
            ("run.sh", layout.run_sh.as_str()),
        ];
        for (name, body) in files {
            if let Err(e) = fs::write(dir.join(name), body) {
                eprintln!("{e}");
                return ExitCode::from(1);
            }
        }
        println!("wrote tor-only node layout to {}", dir.display());
    } else {
        print!("{}", layout.systemd);
    }
    ExitCode::SUCCESS
}
