//! `mfn-node-setup` — write a Tor-only observer unit into a directory.

use std::env;
use std::fs;
use std::path::Path;
use std::process::ExitCode;

use mfn_node_setup::{render, Listen, NodePlan};

fn main() -> ExitCode {
    let args: Vec<String> = env::args().skip(1).collect();
    if args.is_empty() || args.iter().any(|a| a == "--help" || a == "-h") {
        println!("{HELP}");
        return ExitCode::SUCCESS;
    }
    let mut plan = NodePlan::tor_only_observer();
    let mut out_dir = None;
    let mut i = 0;
    while i < args.len() {
        let arg = args[i].as_str();
        let next = args.get(i + 1).map(String::as_str);
        match arg {
            "--out" => {
                out_dir = next.map(str::to_string);
                i += 2;
            }
            "--rpc" => {
                plan.rpc = match next.and_then(|v| Listen::parse(v).ok()) {
                    Some(v) => v,
                    None => {
                        eprintln!("--rpc must be a loopback host:port");
                        return ExitCode::from(2);
                    }
                };
                i += 2;
            }
            "--peer" => {
                let Some(peer) = next else {
                    eprintln!("--peer needs an onion address");
                    return ExitCode::from(2);
                };
                plan.onion_peers.push(peer.to_string());
                i += 2;
            }
            other => {
                eprintln!("unknown argument {other}\n{HELP}");
                return ExitCode::from(2);
            }
        }
    }
    let Some(dir) = out_dir else {
        eprintln!("--out is required");
        return ExitCode::from(2);
    };
    let files = match render(&plan) {
        Ok(f) => f,
        Err(err) => {
            eprintln!("{err}");
            return ExitCode::from(1);
        }
    };
    if let Err(err) = write_all(Path::new(&dir), &files) {
        eprintln!("{err}");
        return ExitCode::from(1);
    }
    println!("wrote {dir}");
    ExitCode::SUCCESS
}

const HELP: &str = "\
mfn-node-setup --out DIR [--rpc 127.0.0.1:18731] [--peer NAME.onion:8333]
";

fn write_all(dir: &Path, files: &mfn_node_setup::SetupFiles) -> std::io::Result<()> {
    fs::create_dir_all(dir)?;
    fs::write(dir.join("observer.env"), &files.env_file)?;
    fs::write(dir.join("permawrite-observer.service"), &files.systemd_unit)?;
    fs::write(dir.join("torrc"), &files.torrc)?;
    fs::write(dir.join("Containerfile"), &files.containerfile)?;
    fs::write(dir.join("run-container.sh"), &files.container_run)?;
    Ok(())
}
