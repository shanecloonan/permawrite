//! Human-editable genesis chain spec (JSON, version 1) for operators and tests (M2.1.2).
//!
//! Maps a small declarative file into [`mfn_consensus::GenesisConfig`]. This
//! is **not** the canonical on-wire genesis block — that remains
//! [`mfn_consensus::build_genesis`]. The spec exists so every node can agree on
//! `timestamp`, `ConsensusParams`, and validator key material derived from
//! explicit 32-byte seeds before the first block is produced.

use std::fs;
use std::path::Path;

use mfn_bls::bls_keygen_from_seed;
use mfn_consensus::{
    ConsensusParams, GenesisConfig, Validator, ValidatorPayout, DEFAULT_EMISSION_PARAMS,
};
use mfn_crypto::stealth_wallet_from_seed;
use mfn_crypto::vrf::vrf_keygen_from_seed;
use mfn_storage::DEFAULT_ENDOWMENT_PARAMS;
use serde::Deserialize;
use thiserror::Error;

/// Errors loading or interpreting a genesis JSON spec.
#[derive(Debug, Error)]
pub enum GenesisSpecError {
    /// Failed to read the spec file from disk.
    #[error("read genesis spec `{}`: {source}", path.display())]
    Io {
        /// Path attempted.
        path: std::path::PathBuf,
        /// Underlying IO error.
        #[source]
        source: std::io::Error,
    },

    /// Spec file is not valid UTF-8.
    #[error("genesis spec is not valid utf-8: {0}")]
    Utf8(#[from] std::str::Utf8Error),

    /// JSON parse failure.
    #[error("parse genesis spec json: {0}")]
    Json(#[from] serde_json::Error),

    /// Spec declares an unsupported format version.
    #[error("unsupported genesis spec version {0} (only version 1 is defined)")]
    UnsupportedVersion(u32),

    /// Hex decoding failed for a seed field.
    #[error("invalid hex for {field}: {source}")]
    BadHex {
        /// Field name (e.g. `validators[0].vrf_seed_hex`).
        field: String,
        /// Hex crate error.
        #[source]
        source: hex::FromHexError,
    },

    /// A seed decoded to the wrong byte length.
    #[error("{field}: expected 32 bytes after hex decode, got {got}")]
    WrongSeedLen {
        /// Field name.
        field: String,
        /// Actual decoded length.
        got: usize,
    },

    /// VRF key derivation failed.
    #[error("vrf keygen for validator index {index}: {message}")]
    VrfKeygen {
        /// Validator table index.
        index: u32,
        /// Underlying crypto error text.
        message: String,
    },

    /// Validator indices must be `0 .. N-1` in ascending order without gaps.
    #[error(
        "validators must use contiguous indices 0..N-1 in order; got index {got} at position {pos}"
    )]
    BadValidatorIndexOrder {
        /// Position in the spec file array.
        pos: usize,
        /// Index field read from JSON.
        got: u32,
    },

    /// `omit_payout = true` cannot be combined with `payout_seed_hex`.
    #[error("validator index {0}: omit_payout conflicts with payout_seed_hex")]
    ConflictingPayoutOptions(u32),
}

fn parse_seed32(field: &str, s: &str) -> Result<[u8; 32], GenesisSpecError> {
    let t = s.trim();
    let t = t
        .strip_prefix("0x")
        .unwrap_or(t)
        .strip_prefix("0X")
        .unwrap_or(t);
    let bytes = hex::decode(t).map_err(|source| GenesisSpecError::BadHex {
        field: field.to_string(),
        source,
    })?;
    if bytes.len() != 32 {
        return Err(GenesisSpecError::WrongSeedLen {
            field: field.to_string(),
            got: bytes.len(),
        });
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&bytes);
    Ok(out)
}

/// Parse exactly 32 bytes from a 64-character hex string (optional `0x` / `0X` prefix).
///
/// Used by `mfnd step` for [`std::env::var`] seeds; decoding rules match the
/// `vrf_seed_hex` / `bls_seed_hex` fields in [`genesis_config_from_json_bytes`].
pub fn hex_seed32(field: &str, s: &str) -> Result<[u8; 32], GenesisSpecError> {
    parse_seed32(field, s)
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct GenesisFile {
    version: u32,
    timestamp: u64,
    #[serde(default)]
    consensus: Option<ConsensusSection>,
    #[serde(default)]
    validators: Vec<ValidatorSection>,
}

#[derive(Debug, Deserialize, Default)]
#[serde(deny_unknown_fields)]
struct ConsensusSection {
    expected_proposers_per_slot: Option<f64>,
    quorum_stake_bps: Option<u32>,
    liveness_max_consecutive_missed: Option<u32>,
    liveness_slash_bps: Option<u32>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ValidatorSection {
    index: u32,
    vrf_seed_hex: String,
    bls_seed_hex: String,
    stake: u64,
    #[serde(default)]
    payout_seed_hex: Option<String>,
    /// When true, on-chain `payout` is `None` (coinbase burns).
    #[serde(default)]
    omit_payout: bool,
}

fn merge_consensus(base: ConsensusParams, file: Option<ConsensusSection>) -> ConsensusParams {
    let Some(c) = file else {
        return base;
    };
    ConsensusParams {
        expected_proposers_per_slot: c
            .expected_proposers_per_slot
            .unwrap_or(base.expected_proposers_per_slot),
        quorum_stake_bps: c.quorum_stake_bps.unwrap_or(base.quorum_stake_bps),
        liveness_max_consecutive_missed: c
            .liveness_max_consecutive_missed
            .unwrap_or(base.liveness_max_consecutive_missed),
        liveness_slash_bps: c.liveness_slash_bps.unwrap_or(base.liveness_slash_bps),
    }
}

/// Parse genesis configuration from UTF-8 JSON bytes (version 1).
///
/// # Errors
///
/// Returns [`GenesisSpecError`] for version mismatch, bad hex, bad validator
/// indices, or VRF derivation failure.
pub fn genesis_config_from_json_bytes(bytes: &[u8]) -> Result<GenesisConfig, GenesisSpecError> {
    let text = std::str::from_utf8(bytes).map_err(GenesisSpecError::Utf8)?;
    let file: GenesisFile = serde_json::from_str(text)?;
    if file.version != 1 {
        return Err(GenesisSpecError::UnsupportedVersion(file.version));
    }

    let base_consensus = ConsensusParams::default();
    let params = merge_consensus(base_consensus, file.consensus);

    let mut rows = file.validators;
    rows.sort_by_key(|v| v.index);
    for (pos, v) in rows.iter().enumerate() {
        if v.index != pos as u32 {
            return Err(GenesisSpecError::BadValidatorIndexOrder { pos, got: v.index });
        }
    }

    let mut validators = Vec::with_capacity(rows.len());
    for v in rows {
        if v.omit_payout && v.payout_seed_hex.is_some() {
            return Err(GenesisSpecError::ConflictingPayoutOptions(v.index));
        }
        let vrf_field = format!("validators[{}].vrf_seed_hex", v.index);
        let bls_field = format!("validators[{}].bls_seed_hex", v.index);
        let vrf_seed = parse_seed32(&vrf_field, &v.vrf_seed_hex)?;
        let bls_seed = parse_seed32(&bls_field, &v.bls_seed_hex)?;
        let vrf = vrf_keygen_from_seed(&vrf_seed).map_err(|e| GenesisSpecError::VrfKeygen {
            index: v.index,
            message: e.to_string(),
        })?;
        let bls = bls_keygen_from_seed(&bls_seed);
        let payout = if v.omit_payout {
            None
        } else {
            let pseed = match &v.payout_seed_hex {
                Some(s) => {
                    let f = format!("validators[{}].payout_seed_hex", v.index);
                    parse_seed32(&f, s)?
                }
                None => bls_seed,
            };
            let w = stealth_wallet_from_seed(&pseed);
            Some(ValidatorPayout {
                view_pub: w.view_pub,
                spend_pub: w.spend_pub,
            })
        };
        validators.push(Validator {
            index: v.index,
            vrf_pk: vrf.pk,
            bls_pk: bls.pk,
            stake: v.stake,
            payout,
        });
    }

    Ok(GenesisConfig {
        timestamp: file.timestamp,
        initial_outputs: Vec::new(),
        initial_storage: Vec::new(),
        validators,
        params,
        emission_params: DEFAULT_EMISSION_PARAMS,
        endowment_params: DEFAULT_ENDOWMENT_PARAMS,
        bonding_params: None,
    })
}

/// Load and parse a genesis spec from `path` (JSON, UTF-8).
///
/// # Errors
///
/// Returns [`GenesisSpecError`] for IO failures or any [`genesis_config_from_json_bytes`] error.
pub fn genesis_config_from_json_path(path: &Path) -> Result<GenesisConfig, GenesisSpecError> {
    let bytes = fs::read(path).map_err(|source| GenesisSpecError::Io {
        path: path.to_path_buf(),
        source,
    })?;
    genesis_config_from_json_bytes(&bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    const ONE_VAL: &str = include_str!("../testdata/devnet_one_validator.json");

    #[test]
    fn one_validator_spec_loads() {
        let g = genesis_config_from_json_bytes(ONE_VAL.as_bytes()).expect("parse");
        assert_eq!(g.timestamp, 1_700_000_000);
        assert_eq!(g.validators.len(), 1);
        assert_eq!(g.validators[0].index, 0);
        assert_eq!(g.validators[0].stake, 1_000_000);
        assert!(g.validators[0].payout.is_some());
        assert!((g.params.expected_proposers_per_slot - 10.0).abs() < f64::EPSILON);
    }

    #[test]
    fn rejects_wrong_version() {
        let s = r#"{"version":2,"timestamp":0,"validators":[]}"#;
        assert!(matches!(
            genesis_config_from_json_bytes(s.as_bytes()),
            Err(GenesisSpecError::UnsupportedVersion(2))
        ));
    }

    #[test]
    fn rejects_noncontiguous_indices() {
        let s = r#"{"version":1,"timestamp":0,"validators":[{"index":1,"vrf_seed_hex":"0101010101010101010101010101010101010101010101010101010101010101","bls_seed_hex":"6565656565656565656565656565656565656565656565656565656565656565","stake":1}]}"#;
        assert!(matches!(
            genesis_config_from_json_bytes(s.as_bytes()),
            Err(GenesisSpecError::BadValidatorIndexOrder { pos: 0, got: 1 })
        ));
    }
}
