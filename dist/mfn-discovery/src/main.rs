//! `mfn-discovery` — sign or check a card of onion gateways and magnets.

use std::env;
use std::process::ExitCode;

use mfn_crypto::SchnorrKeypair;
use mfn_discovery::{sign_card, verify_card, DiscoveryCard};

fn main() -> ExitCode {
    let args: Vec<String> = env::args().skip(1).collect();
    match args.first().map(String::as_str) {
        Some("sign") => {
            let Some(seed) = flag(&args, "--key-seed") else {
                eprintln!("sign needs --key-seed");
                return ExitCode::from(2);
            };
            let key = match key_from_hex(seed) {
                Ok(k) => k,
                Err(err) => {
                    eprintln!("{err}");
                    return ExitCode::from(2);
                }
            };
            let onions = values(&args, "--onion");
            let magnets = values(&args, "--magnet");
            match sign_card(onions, magnets, "", &key) {
                Ok(card) => {
                    let body = match card.canonical() {
                        Ok(t) => t,
                        Err(err) => {
                            eprintln!("{err}");
                            return ExitCode::from(1);
                        }
                    };
                    print!(
                        "{body}signer {}\nsignature {}\n",
                        hex::encode(card.signer),
                        hex::encode(card.signature)
                    );
                    ExitCode::SUCCESS
                }
                Err(err) => {
                    eprintln!("{err}");
                    ExitCode::from(1)
                }
            }
        }
        Some("verify") => {
            let (Some(signer), Some(signature)) =
                (flag(&args, "--signer"), flag(&args, "--signature"))
            else {
                eprintln!("verify needs --signer and --signature");
                return ExitCode::from(2);
            };
            let expected = match decode32(signer) {
                Ok(b) => b,
                Err(err) => {
                    eprintln!("{err}");
                    return ExitCode::from(2);
                }
            };
            let signature = match decode64(signature) {
                Ok(b) => b,
                Err(err) => {
                    eprintln!("{err}");
                    return ExitCode::from(2);
                }
            };
            let card = DiscoveryCard {
                onions: values(&args, "--onion"),
                magnets: values(&args, "--magnet"),
                source_sha256: String::new(),
                signer: expected,
                signature,
            };
            match verify_card(&card, &expected) {
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
        _ => {
            println!("mfn-discovery sign --key-seed HEX --onion HOST.onion --magnet MAGNET");
            ExitCode::SUCCESS
        }
    }
}

fn values(args: &[String], name: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut i = 0;
    while i + 1 < args.len() {
        if args[i] == name {
            out.push(args[i + 1].clone());
        }
        i += 1;
    }
    out
}

fn flag<'a>(args: &'a [String], name: &str) -> Option<&'a str> {
    args.windows(2)
        .find(|w| w[0] == name)
        .map(|w| w[1].as_str())
}

fn key_from_hex(text: &str) -> Result<SchnorrKeypair, String> {
    let seed = decode32(text)?;
    let scalar = mfn_crypto::bytes_to_scalar(&seed);
    Ok(SchnorrKeypair {
        priv_key: scalar,
        pub_key: mfn_crypto::generator_g() * scalar,
    })
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

fn decode32(text: &str) -> Result<[u8; 32], String> {
    if text.len() != 64 {
        return Err("expected 64 hex characters".into());
    }
    let bytes = hex::decode(text).map_err(|e| e.to_string())?;
    let mut out = [0u8; 32];
    out.copy_from_slice(&bytes);
    Ok(out)
}
