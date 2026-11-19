//! `mfn-airgap` — watch-only export, sign offline, verify online.

use std::env;
use std::fs;
use std::path::Path;
use std::process::ExitCode;

use mfn_airgap::{
    load_seed_file, sign_request, verify_signed, watch_only, PaymentRequest, SignedRequest,
};
use mfn_crypto::point_to_bytes;
use mfn_wallet::wallet_from_seed;

fn main() -> ExitCode {
    let args: Vec<String> = env::args().skip(1).collect();
    match args.first().map(String::as_str) {
        Some("watch") => watch(&args[1..]),
        Some("sign") => sign(&args[1..]),
        Some("verify") => verify(&args[1..]),
        _ => {
            println!(
                "mfn-airgap watch --seed FILE\nmfn-airgap sign --seed FILE --request FILE --out FILE\nmfn-airgap verify --signed FILE --spend-pub HEX"
            );
            ExitCode::SUCCESS
        }
    }
}

fn watch(args: &[String]) -> ExitCode {
    let Some(path) = flag(args, "--seed") else {
        eprintln!("watch needs --seed");
        return ExitCode::from(2);
    };
    match load_seed_file(Path::new(path)) {
        Ok(seed) => {
            print!("{}", watch_only(&seed));
            ExitCode::SUCCESS
        }
        Err(err) => {
            eprintln!("{err}");
            ExitCode::from(1)
        }
    }
}

fn sign(args: &[String]) -> ExitCode {
    let (Some(seed_path), Some(request_path), Some(out)) = (
        flag(args, "--seed"),
        flag(args, "--request"),
        flag(args, "--out"),
    ) else {
        eprintln!("sign needs --seed --request --out");
        return ExitCode::from(2);
    };
    let seed = match load_seed_file(Path::new(seed_path)) {
        Ok(s) => s,
        Err(err) => {
            eprintln!("{err}");
            return ExitCode::from(1);
        }
    };
    let text = match fs::read_to_string(request_path) {
        Ok(t) => t,
        Err(err) => {
            eprintln!("{err}");
            return ExitCode::from(1);
        }
    };
    let request = match PaymentRequest::parse(&text) {
        Ok(r) => r,
        Err(err) => {
            eprintln!("{err}");
            return ExitCode::from(1);
        }
    };
    let signed = match sign_request(&seed, &request) {
        Ok(s) => s,
        Err(err) => {
            eprintln!("{err}");
            return ExitCode::from(1);
        }
    };
    let rendered = match signed.render() {
        Ok(t) => t,
        Err(err) => {
            eprintln!("{err}");
            return ExitCode::from(1);
        }
    };
    if rendered.contains(&hex::encode(seed)) {
        eprintln!("refusing to write a file that contains the seed");
        return ExitCode::from(1);
    }
    if let Err(err) = fs::write(out, rendered) {
        eprintln!("{err}");
        return ExitCode::from(1);
    }
    let keys = wallet_from_seed(&seed);
    println!("signed {}", hex::encode(point_to_bytes(&keys.spend_pub())));
    ExitCode::SUCCESS
}

fn verify(args: &[String]) -> ExitCode {
    let (Some(path), Some(spend)) = (flag(args, "--signed"), flag(args, "--spend-pub")) else {
        eprintln!("verify needs --signed and --spend-pub");
        return ExitCode::from(2);
    };
    if spend.len() != 64 {
        eprintln!("spend pub must be 64 hex characters");
        return ExitCode::from(2);
    }
    let bytes = match hex::decode(spend) {
        Ok(b) => b,
        Err(_) => return ExitCode::from(2),
    };
    let mut expected = [0u8; 32];
    expected.copy_from_slice(&bytes);
    let text = match fs::read_to_string(path) {
        Ok(t) => t,
        Err(err) => {
            eprintln!("{err}");
            return ExitCode::from(1);
        }
    };
    let signed = match SignedRequest::parse(&text) {
        Ok(s) => s,
        Err(err) => {
            eprintln!("{err}");
            return ExitCode::from(1);
        }
    };
    match verify_signed(&signed, &expected) {
        Ok(()) => {
            println!("ok");
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
