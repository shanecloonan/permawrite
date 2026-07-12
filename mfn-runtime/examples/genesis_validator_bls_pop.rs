//! Genesis validator BLS register proof-of-possession helper (Path B ceremony).
//!
//! ```text
//! cargo run -p mfn-runtime --example genesis_validator_bls_pop -- --genesis PATH.json
//! cargo run -p mfn-runtime --example genesis_validator_bls_pop -- --genesis PATH.json --verify
//! ```

use std::env;
use std::path::PathBuf;

use mfn_runtime::{
    genesis_config_from_json_bytes, validator_bls_register_sig_hex,
    verify_genesis_validator_bls_pop_json, ValidatorPopInputs,
};
use serde::Deserialize;

#[derive(Debug, Deserialize)]
struct GenesisFile {
    #[serde(default)]
    require_validator_bls_pop: Option<u8>,
    validators: Vec<ValidatorRow>,
}

#[derive(Debug, Deserialize)]
struct ValidatorRow {
    index: u32,
    vrf_seed_hex: String,
    bls_seed_hex: String,
    stake: u64,
    #[serde(default)]
    payout_seed_hex: Option<String>,
    #[serde(default)]
    omit_payout: bool,
    #[serde(default)]
    bls_register_sig_hex: Option<String>,
}

fn parse_seed(field: &str, s: &str) -> Result<[u8; 32], String> {
    let t = s.trim().trim_start_matches("0x").trim_start_matches("0X");
    let bytes = hex::decode(t).map_err(|e| format!("{field}: {e}"))?;
    if bytes.len() != 32 {
        return Err(format!("{field}: expected 32 bytes, got {}", bytes.len()));
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&bytes);
    Ok(out)
}

fn usage() -> ! {
    eprintln!(
        "usage: genesis_validator_bls_pop --genesis PATH.json [--verify]\n\
         \n\
         Without --verify: print expected bls_register_sig_hex per validator.\n\
         With --verify: run genesis_config_from_json_bytes PoP gate on the file."
    );
    std::process::exit(2);
}

fn main() {
    let mut genesis: Option<PathBuf> = None;
    let mut verify = false;
    let mut args = env::args().skip(1);
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--genesis" => genesis = args.next().map(PathBuf::from),
            "--verify" => verify = true,
            "-h" | "--help" => usage(),
            other => {
                eprintln!("unknown argument: {other}");
                usage();
            }
        }
    }
    let genesis = genesis.unwrap_or_else(|| {
        eprintln!("--genesis PATH.json is required");
        usage();
    });

    if verify {
        match verify_genesis_validator_bls_pop_json(&genesis) {
            Ok(()) => {
                println!("genesis_validator_bls_pop: verify OK {}", genesis.display());
            }
            Err(e) => {
                eprintln!("genesis_validator_bls_pop: verify FAIL {e}");
                std::process::exit(1);
            }
        }
        return;
    }

    let bytes = std::fs::read(&genesis).unwrap_or_else(|e| {
        eprintln!("read {}: {e}", genesis.display());
        std::process::exit(1);
    });
    let file: GenesisFile = serde_json::from_slice(&bytes).unwrap_or_else(|e| {
        eprintln!("parse JSON: {e}");
        std::process::exit(1);
    });
    let _ = genesis_config_from_json_bytes(&bytes).expect("constitution + spec shape");

    for v in &file.validators {
        let vrf_field = format!("validators[{}].vrf_seed_hex", v.index);
        let bls_field = format!("validators[{}].bls_seed_hex", v.index);
        let vrf_seed = parse_seed(&vrf_field, &v.vrf_seed_hex).unwrap_or_else(|e| {
            eprintln!("{e}");
            std::process::exit(1);
        });
        let bls_seed = parse_seed(&bls_field, &v.bls_seed_hex).unwrap_or_else(|e| {
            eprintln!("{e}");
            std::process::exit(1);
        });
        let payout_seed = match &v.payout_seed_hex {
            None => None,
            Some(s) => {
                let f = format!("validators[{}].payout_seed_hex", v.index);
                Some(parse_seed(&f, s).unwrap_or_else(|e| {
                    eprintln!("{e}");
                    std::process::exit(1);
                }))
            }
        };
        let sig_hex = validator_bls_register_sig_hex(&ValidatorPopInputs {
            stake: v.stake,
            vrf_seed,
            bls_seed,
            payout_seed,
            omit_payout: v.omit_payout,
        })
        .unwrap_or_else(|e| {
            eprintln!("validators[{}]: {e}", v.index);
            std::process::exit(1);
        });
        println!(
            "validators[{}] stake={} bls_register_sig_hex={}",
            v.index, v.stake, sig_hex
        );
        if let Some(got) = &v.bls_register_sig_hex {
            if got.trim().eq_ignore_ascii_case(&sig_hex) {
                println!("  existing sig: OK");
            } else {
                eprintln!("  existing sig: MISMATCH");
                std::process::exit(1);
            }
        }
    }
    if file.require_validator_bls_pop == Some(1) {
        println!("require_validator_bls_pop=1 (ceremony mode)");
    }
}
