//! `mfn-install` — copy files after their signed hash list checks out.

use std::env;
use std::fs;
use std::path::Path;
use std::process::ExitCode;

use mfn_crypto::SchnorrKeypair;
use mfn_install::{install, sign_plan, InstallFile, Plan};

fn main() -> ExitCode {
    let args: Vec<String> = env::args().skip(1).collect();
    match args.first().map(String::as_str) {
        Some("sign") => sign(&args[1..]),
        Some("install") => install_cmd(&args[1..]),
        _ => {
            println!(
                "mfn-install sign --key-seed HEX --file NAME=PATH --out PLAN\n\
                 mfn-install install --dest DIR --from DIR --plan PLAN --signer HEX"
            );
            ExitCode::SUCCESS
        }
    }
}

fn sign(args: &[String]) -> ExitCode {
    let (Some(seed), Some(out)) = (flag(args, "--key-seed"), flag(args, "--out")) else {
        eprintln!("sign needs --key-seed and --out");
        return ExitCode::from(2);
    };
    let key = match key_from_hex(seed) {
        Ok(k) => k,
        Err(err) => {
            eprintln!("{err}");
            return ExitCode::from(2);
        }
    };
    let mut files = Vec::new();
    let mut i = 0;
    while i < args.len() {
        if args[i] == "--file" {
            let Some(spec) = args.get(i + 1) else {
                return ExitCode::from(2);
            };
            let Some((name, path)) = spec.split_once('=') else {
                return ExitCode::from(2);
            };
            let bytes = match fs::read(path) {
                Ok(b) => b,
                Err(err) => {
                    eprintln!("{err}");
                    return ExitCode::from(1);
                }
            };
            files.push(InstallFile {
                name: name.to_string(),
                bytes,
            });
            i += 2;
            continue;
        }
        i += 1;
    }
    let plan = match sign_plan(files, &key) {
        Ok(p) => p,
        Err(err) => {
            eprintln!("{err}");
            return ExitCode::from(1);
        }
    };
    match write_plan(out, &plan) {
        Ok(()) => {
            println!("signed {}", hex::encode(plan.signer));
            ExitCode::SUCCESS
        }
        Err(err) => {
            eprintln!("{err}");
            ExitCode::from(1)
        }
    }
}

fn install_cmd(args: &[String]) -> ExitCode {
    let (Some(dest), Some(from), Some(plan_path), Some(signer)) = (
        flag(args, "--dest"),
        flag(args, "--from"),
        flag(args, "--plan"),
        flag(args, "--signer"),
    ) else {
        eprintln!("install needs --dest --from --plan --signer");
        return ExitCode::from(2);
    };
    let expected = match decode32(signer) {
        Ok(b) => b,
        Err(err) => {
            eprintln!("{err}");
            return ExitCode::from(2);
        }
    };
    let text = match fs::read_to_string(plan_path) {
        Ok(t) => t,
        Err(err) => {
            eprintln!("{err}");
            return ExitCode::from(1);
        }
    };
    let plan = match read_plan(&text, Path::new(from)) {
        Ok(p) => p,
        Err(err) => {
            eprintln!("{err}");
            return ExitCode::from(1);
        }
    };
    match install(Path::new(dest), &plan, &expected) {
        Ok(()) => {
            println!("installed {}", plan.files.len());
            ExitCode::SUCCESS
        }
        Err(err) => {
            eprintln!("{err}");
            ExitCode::from(1)
        }
    }
}

fn write_plan(path: &str, plan: &Plan) -> Result<(), String> {
    let body = plan.canonical_hashes().map_err(|e| e.to_string())?;
    let text = format!(
        "{body}signer {}\nsignature {}\n",
        hex::encode(plan.signer),
        hex::encode(plan.signature)
    );
    fs::write(path, text).map_err(|e| e.to_string())
}

fn read_plan(text: &str, from: &Path) -> Result<Plan, String> {
    let mut files = Vec::new();
    let mut signer = None;
    let mut signature = None;
    for line in text.lines() {
        if line.is_empty() || line == "permawrite-install v1" {
            continue;
        }
        let (key, rest) = line.split_once(' ').ok_or("bad plan line")?;
        match key {
            "file" => {
                let mut parts = rest.split(' ');
                let name = parts.next().ok_or("file name")?;
                let _digest = parts.next().ok_or("digest")?;
                let _size = parts.next().ok_or("size")?;
                let bytes = fs::read(from.join(name)).map_err(|e| e.to_string())?;
                files.push(InstallFile {
                    name: name.to_string(),
                    bytes,
                });
            }
            "signer" => signer = Some(decode32(rest)?),
            "signature" => signature = Some(decode64(rest)?),
            other => return Err(format!("unknown field {other}")),
        }
    }
    Ok(Plan {
        files,
        signer: signer.ok_or("missing signer")?,
        signature: signature.ok_or("missing signature")?,
    })
}

fn key_from_hex(text: &str) -> Result<SchnorrKeypair, String> {
    let seed = decode32(text)?;
    let scalar = mfn_crypto::bytes_to_scalar(&seed);
    Ok(SchnorrKeypair {
        priv_key: scalar,
        pub_key: mfn_crypto::generator_g() * scalar,
    })
}

fn decode32(text: &str) -> Result<[u8; 32], String> {
    if text.len() != 64 {
        return Err("expected 64 hex characters".into());
    }
    let bytes = hex::decode(text).map_err(|e| e.to_string())?;
    let mut out = [0u8; 32];
    out.copy_from_slice(&bytes);
    Ok(out)
}

fn decode64(text: &str) -> Result<[u8; 64], String> {
    if text.len() != 128 {
        return Err("expected 128 hex characters".into());
    }
    let bytes = hex::decode(text).map_err(|e| e.to_string())?;
    let mut out = [0u8; 64];
    out.copy_from_slice(&bytes);
    Ok(out)
}

fn flag<'a>(args: &'a [String], name: &str) -> Option<&'a str> {
    args.windows(2)
        .find(|w| w[0] == name)
        .map(|w| w[1].as_str())
}
