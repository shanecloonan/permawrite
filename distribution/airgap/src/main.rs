//! Sign a transfer offline, or verify the broadcast bytes.

use std::env;
use std::fs;
use std::process::ExitCode;

use mfn_airgap::{keys_from_json, request_from_json, sign_offline, verify_broadcast};

fn main() -> ExitCode {
    let mut args = env::args().skip(1);
    match args.next().as_deref() {
        Some("sign") => sign_cmd(&mut args),
        Some("verify") => verify_cmd(&mut args),
        _ => {
            eprintln!(
                "usage: mfn-airgap sign --request FILE --keys FILE --tx FILE --blindings FILE\n       mfn-airgap verify --tx FILE"
            );
            ExitCode::from(2)
        }
    }
}

fn take(args: &mut impl Iterator<Item = String>, flag: &str) -> Option<String> {
    let got = args.next()?;
    if got != flag {
        return None;
    }
    args.next()
}

fn sign_cmd(args: &mut impl Iterator<Item = String>) -> ExitCode {
    let Some(request_path) = take(args, "--request") else {
        eprintln!("need --request FILE");
        return ExitCode::from(2);
    };
    let Some(keys_path) = take(args, "--keys") else {
        eprintln!("need --keys FILE");
        return ExitCode::from(2);
    };
    let Some(tx_path) = take(args, "--tx") else {
        eprintln!("need --tx FILE");
        return ExitCode::from(2);
    };
    let Some(blind_path) = take(args, "--blindings") else {
        eprintln!("need --blindings FILE");
        return ExitCode::from(2);
    };
    let request_text = match fs::read_to_string(&request_path) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("{e}");
            return ExitCode::from(1);
        }
    };
    let request = match request_from_json(&request_text) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("{e}");
            return ExitCode::from(1);
        }
    };
    let keys_text = match fs::read_to_string(&keys_path) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("{e}");
            return ExitCode::from(1);
        }
    };
    let keys = match keys_from_json(&keys_text) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("{e}");
            return ExitCode::from(1);
        }
    };
    match sign_offline(&request, &keys) {
        Ok(signed) => {
            if let Err(e) = fs::write(&tx_path, &signed.broadcast) {
                eprintln!("{e}");
                return ExitCode::from(1);
            }
            let blind = serde_json::json!({
                "tx_id": signed.tx_id_hex,
                "output_blindings_hex": signed.private_blindings_hex,
            });
            if let Err(e) = fs::write(&blind_path, format!("{blind}\n")) {
                eprintln!("{e}");
                return ExitCode::from(1);
            }
            println!("airgap sign ok tx_id={}", signed.tx_id_hex);
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("{e}");
            ExitCode::from(1)
        }
    }
}

fn verify_cmd(args: &mut impl Iterator<Item = String>) -> ExitCode {
    let Some(tx_path) = take(args, "--tx") else {
        eprintln!("need --tx FILE");
        return ExitCode::from(2);
    };
    let bytes = match fs::read(&tx_path) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("{e}");
            return ExitCode::from(1);
        }
    };
    match verify_broadcast(&bytes) {
        Ok(id) => {
            println!("airgap verify ok tx_id={id}");
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("{e}");
            ExitCode::from(1)
        }
    }
}
