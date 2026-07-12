//! Human-editable genesis chain spec (JSON, version 1) for operators and tests
//! (M2.1.2 + **M2.1.7** optional `synthetic_decoy_utxos` for local ring decoys).
//!
//! Maps a small declarative file into [`mfn_consensus::GenesisConfig`]. This
//! is **not** the canonical on-wire genesis block — that remains
//! [`mfn_consensus::build_genesis`]. The spec exists so every node can agree on
//! `timestamp`, `ConsensusParams`, and validator key material derived from
//! explicit 32-byte seeds before the first block is produced.

use std::fs;
use std::path::Path;

use mfn_bls::{bls_keygen_from_seed, decode_signature};
use mfn_consensus::{
    validate_constitution, verify_register_sig, ConsensusParams, ConstitutionError, GenesisConfig,
    GenesisOutput, GenesisStorageOperator, Validator, ValidatorPayout, DEFAULT_EMISSION_PARAMS,
};
use mfn_crypto::point::{generator_g, generator_h};
use mfn_crypto::scalar::bytes_to_scalar;
use mfn_crypto::stealth_wallet_from_seed;
use mfn_crypto::vrf::vrf_keygen_from_seed;
use mfn_storage::{EndowmentParams, DEFAULT_ENDOWMENT_PARAMS};
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

    /// Storage-operator indices must be `0 .. N-1` in ascending order without gaps.
    #[error(
        "storage_operators must use contiguous indices 0..N-1 in order; got index {got} at position {pos}"
    )]
    BadStorageOperatorIndexOrder {
        /// Position in the spec file array.
        pos: usize,
        /// Index field read from JSON.
        got: u32,
    },

    /// Duplicate operator payout identity in the genesis spec.
    #[error("storage_operators[{index}]: duplicate operator payout identity")]
    DuplicateStorageOperatorIdentity {
        /// Position in the spec file array.
        index: usize,
    },

    /// Operator bond below `min_storage_operator_bond` in the endowment section.
    #[error(
        "storage_operators[{index}]: bond_amount {bond_amount} below min_storage_operator_bond {min_bond}"
    )]
    StorageOperatorBondTooLow {
        /// Position in the spec file array.
        index: usize,
        /// Bond amount from JSON.
        bond_amount: u64,
        /// Required minimum from merged endowment params.
        min_bond: u64,
    },

    /// `require_registered_operators` requires `operator_salted_challenges`.
    #[error("endowment.require_registered_operators requires operator_salted_challenges = 1")]
    RegisteredOperatorsRequiresSaltedChallenges,

    /// `storage_operators` entries require `require_registered_operators` when non-empty.
    #[error("storage_operators requires endowment.require_registered_operators = 1")]
    StorageOperatorsRequireRegisteredFlag,

    /// `synthetic_decoy_utxos` exceeds the hard cap (local devnets only).
    #[error("synthetic_decoy_utxos {0} exceeds maximum {1}")]
    SyntheticDecoyCountTooLarge(u32, u32),

    /// Validator BLS register PoP signature failed verification.
    #[error("validators[{index}]: invalid BLS register proof-of-possession signature")]
    InvalidValidatorBlsPop {
        /// Validator `index` from the spec row.
        index: u32,
    },

    /// Ceremony genesis requires `bls_register_sig_hex` per validator.
    #[error(
        "validators[{index}]: missing required bls_register_sig_hex (require_validator_bls_pop=1)"
    )]
    MissingValidatorBlsPop {
        /// Validator `index` from the spec row.
        index: u32,
    },

    /// BLS signature field has wrong byte length or failed decode.
    #[error("{field}: BLS signature must be 96 bytes, got {got}")]
    WrongBlsSigLen {
        /// JSON field name.
        field: String,
        /// Byte length observed (or reported length on decode failure).
        got: usize,
    },

    /// The spec's parameters violate a constitutional invariant
    /// (**F5:PM13**): zero tail emission, sub-uniform or sub-16 rings,
    /// or degenerate endowment pricing. No operator-supplied genesis may
    /// start a chain that breaks the permanence/privacy floor.
    #[error("genesis spec violates the constitution: {0}")]
    Constitution(#[from] ConstitutionError),
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

fn parse_bls_sig(field: &str, s: &str) -> Result<mfn_bls::BlsSignature, GenesisSpecError> {
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
    if bytes.len() != mfn_bls::BLS_SIGNATURE_BYTES {
        return Err(GenesisSpecError::WrongBlsSigLen {
            field: field.to_string(),
            got: bytes.len(),
        });
    }
    decode_signature(&bytes).map_err(|_| GenesisSpecError::WrongBlsSigLen {
        field: field.to_string(),
        got: bytes.len(),
    })
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
    /// Optional count of synthetic `GenesisOutput` rows (not spendable by any
    /// wallet in the spec) to widen the on-chain UTXO set for **local** ring
    /// decoys. Capped at [`MAX_SYNTHETIC_DECOY_UTXOS`].
    #[serde(default)]
    synthetic_decoy_utxos: Option<u32>,
    #[serde(default)]
    consensus: Option<ConsensusSection>,
    #[serde(default)]
    endowment: Option<EndowmentSection>,
    #[serde(default)]
    validators: Vec<ValidatorSection>,
    #[serde(default)]
    storage_operators: Vec<StorageOperatorSection>,
    /// When `1`, every validator row must carry a valid
    /// `bls_register_sig_hex` (BLS PoP over the register payload). Use for
    /// Path B genesis ceremonies; default `0` keeps toy/devnet specs valid.
    #[serde(default)]
    require_validator_bls_pop: Option<u8>,
}

#[derive(Debug, Deserialize, Default)]
#[serde(deny_unknown_fields)]
struct ConsensusSection {
    expected_proposers_per_slot: Option<f64>,
    quorum_stake_bps: Option<u32>,
    liveness_max_consecutive_missed: Option<u32>,
    liveness_slash_bps: Option<u32>,
    min_ring_size: Option<u32>,
    uniform_ring_size: Option<u32>,
}

#[derive(Debug, Deserialize, Default)]
#[serde(deny_unknown_fields)]
struct EndowmentSection {
    cost_per_byte_year_ppb: Option<u64>,
    inflation_ppb: Option<u64>,
    real_yield_ppb: Option<u64>,
    min_replication: Option<u8>,
    max_replication: Option<u8>,
    slots_per_year: Option<u64>,
    proof_reward_window_slots: Option<u64>,
    require_endowment_opening: Option<u8>,
    operator_salted_challenges: Option<u8>,
    require_registered_operators: Option<u8>,
    min_storage_operator_bond: Option<u64>,
    operator_audit_missed_cap: Option<u8>,
    operator_slash_bps: Option<u32>,
    require_endowment_range_proof: Option<u8>,
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
    /// Optional BLS proof-of-possession over the register signing hash
    /// (same payload as on-chain `BondOp::Register`). Required when
    /// `require_validator_bls_pop` is `1`; recommended for ceremony review.
    #[serde(default)]
    bls_register_sig_hex: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct StorageOperatorSection {
    index: u32,
    payout_seed_hex: String,
    #[serde(default)]
    bond_amount: u64,
}

/// Upper bound for [`GenesisFile::synthetic_decoy_utxos`] (devnet / tests).
pub const MAX_SYNTHETIC_DECOY_UTXOS: u32 = 4096;

fn synthetic_genesis_outputs(
    timestamp: u64,
    count: u32,
) -> Result<Vec<GenesisOutput>, GenesisSpecError> {
    if count > MAX_SYNTHETIC_DECOY_UTXOS {
        return Err(GenesisSpecError::SyntheticDecoyCountTooLarge(
            count,
            MAX_SYNTHETIC_DECOY_UTXOS,
        ));
    }
    let mut out = Vec::with_capacity(count as usize);
    for i in 0..count {
        let mut seed = [0u8; 32];
        seed[0..8].copy_from_slice(&timestamp.to_le_bytes());
        seed[8..12].copy_from_slice(&i.to_le_bytes());
        seed[12..16].copy_from_slice(b"MFD1");
        let sp = bytes_to_scalar(&seed);
        seed[16] = 0x01;
        let bp = bytes_to_scalar(&seed);
        seed[16] = 0x02;
        let vp = bytes_to_scalar(&seed);
        out.push(GenesisOutput {
            one_time_addr: generator_g() * sp,
            amount: (generator_g() * bp) + (generator_h() * vp),
        });
    }
    Ok(out)
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
        min_ring_size: c.min_ring_size.unwrap_or(base.min_ring_size),
        uniform_ring_size: c.uniform_ring_size.unwrap_or(base.uniform_ring_size),
    }
}

fn merge_endowment(base: EndowmentParams, file: Option<EndowmentSection>) -> EndowmentParams {
    let Some(e) = file else {
        return base;
    };
    EndowmentParams {
        cost_per_byte_year_ppb: e
            .cost_per_byte_year_ppb
            .unwrap_or(base.cost_per_byte_year_ppb),
        inflation_ppb: e.inflation_ppb.unwrap_or(base.inflation_ppb),
        real_yield_ppb: e.real_yield_ppb.unwrap_or(base.real_yield_ppb),
        min_replication: e.min_replication.unwrap_or(base.min_replication),
        max_replication: e.max_replication.unwrap_or(base.max_replication),
        slots_per_year: e.slots_per_year.unwrap_or(base.slots_per_year),
        proof_reward_window_slots: e
            .proof_reward_window_slots
            .unwrap_or(base.proof_reward_window_slots),
        require_endowment_opening: e
            .require_endowment_opening
            .unwrap_or(base.require_endowment_opening),
        operator_salted_challenges: e
            .operator_salted_challenges
            .unwrap_or(base.operator_salted_challenges),
        require_registered_operators: e
            .require_registered_operators
            .unwrap_or(base.require_registered_operators),
        min_storage_operator_bond: e
            .min_storage_operator_bond
            .unwrap_or(base.min_storage_operator_bond),
        operator_audit_missed_cap: e
            .operator_audit_missed_cap
            .unwrap_or(base.operator_audit_missed_cap),
        operator_slash_bps: e.operator_slash_bps.unwrap_or(base.operator_slash_bps),
        require_endowment_range_proof: e
            .require_endowment_range_proof
            .unwrap_or(base.require_endowment_range_proof),
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
    let endowment_params = merge_endowment(DEFAULT_ENDOWMENT_PARAMS, file.endowment);
    // Constitutional gate (F5:PM13): every operator-supplied genesis must
    // satisfy the invariants reference clients refuse to fork away —
    // permanent tail emission, uniform rings >= 16, sane endowment pricing.
    validate_constitution(&params, &DEFAULT_EMISSION_PARAMS, &endowment_params)?;

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

        let pop_field = format!("validators[{}].bls_register_sig_hex", v.index);
        let pop_sig = if let Some(hex) = &v.bls_register_sig_hex {
            Some(parse_bls_sig(&pop_field, hex)?)
        } else if file.require_validator_bls_pop == Some(1) {
            return Err(GenesisSpecError::MissingValidatorBlsPop { index: v.index });
        } else {
            None
        };
        if let Some(sig) = pop_sig {
            if !verify_register_sig(v.stake, &vrf.pk, &bls.pk, payout.as_ref(), &sig) {
                return Err(GenesisSpecError::InvalidValidatorBlsPop { index: v.index });
            }
        }
    }

    let initial_outputs = match file.synthetic_decoy_utxos {
        None | Some(0) => Vec::new(),
        Some(n) => synthetic_genesis_outputs(file.timestamp, n)?,
    };

    if !file.storage_operators.is_empty() {
        if endowment_params.require_registered_operators == 0 {
            return Err(GenesisSpecError::StorageOperatorsRequireRegisteredFlag);
        }
        if endowment_params.operator_salted_challenges == 0 {
            return Err(GenesisSpecError::RegisteredOperatorsRequiresSaltedChallenges);
        }
    }

    let mut op_rows = file.storage_operators;
    op_rows.sort_by_key(|o| o.index);
    for (pos, o) in op_rows.iter().enumerate() {
        if o.index != pos as u32 {
            return Err(GenesisSpecError::BadStorageOperatorIndexOrder { pos, got: o.index });
        }
    }

    let mut initial_storage_operators = Vec::with_capacity(op_rows.len());
    let mut prev_op_id: Option<[u8; 32]> = None;
    for o in op_rows {
        let field = format!("storage_operators[{}].payout_seed_hex", o.index);
        let pseed = parse_seed32(&field, &o.payout_seed_hex)?;
        let w = stealth_wallet_from_seed(&pseed);
        if endowment_params.min_storage_operator_bond > 0
            && o.bond_amount < endowment_params.min_storage_operator_bond
        {
            return Err(GenesisSpecError::StorageOperatorBondTooLow {
                index: o.index as usize,
                bond_amount: o.bond_amount,
                min_bond: endowment_params.min_storage_operator_bond,
            });
        }
        let id = mfn_storage::operator_identity_from_payout(&w.view_pub, &w.spend_pub);
        if let Some(prev) = prev_op_id {
            if id <= prev {
                return Err(GenesisSpecError::DuplicateStorageOperatorIdentity {
                    index: o.index as usize,
                });
            }
        }
        prev_op_id = Some(id);
        initial_storage_operators.push(GenesisStorageOperator {
            operator_view_pub: w.view_pub,
            operator_spend_pub: w.spend_pub,
            bond_amount: o.bond_amount,
        });
    }

    Ok(GenesisConfig {
        timestamp: file.timestamp,
        initial_outputs,
        initial_storage: Vec::new(),
        initial_storage_operators,
        validators,
        params,
        emission_params: DEFAULT_EMISSION_PARAMS,
        endowment_params,
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
    const SYNTH: &str = include_str!("../testdata/devnet_one_validator_synth_decoys.json");

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
    fn synth_decoys_spec_loads() {
        let g = genesis_config_from_json_bytes(SYNTH.as_bytes()).expect("parse");
        assert_eq!(g.initial_outputs.len(), 24);
        assert_eq!(g.validators.len(), 1);
    }

    #[test]
    fn rejects_synthetic_decoy_count_too_large() {
        let s = r#"{"version":1,"timestamp":0,"synthetic_decoy_utxos":99999,"validators":[]}"#;
        assert!(matches!(
            genesis_config_from_json_bytes(s.as_bytes()),
            Err(GenesisSpecError::SyntheticDecoyCountTooLarge(99999, _))
        ));
    }

    #[test]
    fn rejects_unconstitutional_ring_policy() {
        // F5:PM13 — no operator-supplied genesis may lower the uniform
        // ring floor below 16 or disable uniformity.
        let low = r#"{"version":1,"timestamp":0,"consensus":{"min_ring_size":8,"uniform_ring_size":8},"validators":[]}"#;
        assert!(matches!(
            genesis_config_from_json_bytes(low.as_bytes()),
            Err(GenesisSpecError::Constitution(_))
        ));
        let non_uniform =
            r#"{"version":1,"timestamp":0,"consensus":{"uniform_ring_size":0},"validators":[]}"#;
        assert!(matches!(
            genesis_config_from_json_bytes(non_uniform.as_bytes()),
            Err(GenesisSpecError::Constitution(_))
        ));
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

    #[test]
    fn endowment_section_overrides_defaults() {
        let s = r#"{"version":1,"timestamp":0,"endowment":{"require_endowment_opening":1},"validators":[]}"#;
        let g = genesis_config_from_json_bytes(s.as_bytes()).expect("parse");
        assert_eq!(g.endowment_params.require_endowment_opening, 1);
    }

    #[test]
    fn storage_operators_section_loads() {
        let s = r#"{"version":1,"timestamp":0,"endowment":{"operator_salted_challenges":1,"require_registered_operators":1},"storage_operators":[{"index":0,"payout_seed_hex":"c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3","bond_amount":0}],"validators":[]}"#;
        let g = genesis_config_from_json_bytes(s.as_bytes()).expect("parse");
        assert_eq!(g.initial_storage_operators.len(), 1);
        assert_eq!(g.endowment_params.require_registered_operators, 1);
    }

    #[test]
    fn rejects_storage_operators_without_registered_flag() {
        let s = r#"{"version":1,"timestamp":0,"endowment":{"operator_salted_challenges":1},"storage_operators":[{"index":0,"payout_seed_hex":"c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3","bond_amount":0}],"validators":[]}"#;
        assert!(matches!(
            genesis_config_from_json_bytes(s.as_bytes()),
            Err(GenesisSpecError::StorageOperatorsRequireRegisteredFlag)
        ));
    }

    #[test]
    fn require_validator_bls_pop_rejects_missing_signature() {
        let s = r#"{"version":1,"timestamp":0,"require_validator_bls_pop":1,"validators":[{"index":0,"vrf_seed_hex":"0101010101010101010101010101010101010101010101010101010101010101","bls_seed_hex":"6565656565656565656565656565656565656565656565656565656565656565","stake":1}]}"#;
        assert!(matches!(
            genesis_config_from_json_bytes(s.as_bytes()),
            Err(GenesisSpecError::MissingValidatorBlsPop { index: 0 })
        ));
    }

    #[test]
    fn validator_bls_pop_accepts_register_signature() {
        use mfn_consensus::sign_register;
        use mfn_crypto::vrf::vrf_keygen_from_seed;

        let vrf_seed = [0x01u8; 32];
        let bls_seed = [0x65u8; 32];
        let vrf = vrf_keygen_from_seed(&vrf_seed).expect("vrf");
        let bls = bls_keygen_from_seed(&bls_seed);
        let payout_wallet = mfn_crypto::stealth_wallet_from_seed(&bls_seed);
        let payout = ValidatorPayout {
            view_pub: payout_wallet.view_pub,
            spend_pub: payout_wallet.spend_pub,
        };
        let sig = sign_register(1, &vrf.pk, &bls.pk, Some(&payout), &bls.sk);
        let sig_hex = hex::encode(mfn_bls::encode_signature(&sig));
        let s = format!(
            r#"{{"version":1,"timestamp":0,"validators":[{{"index":0,"vrf_seed_hex":"{}","bls_seed_hex":"{}","stake":1,"bls_register_sig_hex":"{}"}}]}}"#,
            hex::encode(vrf_seed),
            hex::encode(bls_seed),
            sig_hex
        );
        genesis_config_from_json_bytes(s.as_bytes()).expect("valid pop");
    }

    #[test]
    fn validator_bls_pop_rejects_wrong_signature() {
        use mfn_consensus::sign_register;
        use mfn_crypto::vrf::vrf_keygen_from_seed;

        let vrf_seed = [0x01u8; 32];
        let bls_seed = [0x65u8; 32];
        let vrf = vrf_keygen_from_seed(&vrf_seed).expect("vrf");
        let bls = bls_keygen_from_seed(&bls_seed);
        let payout_wallet = mfn_crypto::stealth_wallet_from_seed(&bls_seed);
        let payout = ValidatorPayout {
            view_pub: payout_wallet.view_pub,
            spend_pub: payout_wallet.spend_pub,
        };
        // Signed for stake 999, but spec row declares stake 1.
        let sig = sign_register(999, &vrf.pk, &bls.pk, Some(&payout), &bls.sk);
        let sig_hex = hex::encode(mfn_bls::encode_signature(&sig));
        let s = format!(
            r#"{{"version":1,"timestamp":0,"validators":[{{"index":0,"vrf_seed_hex":"{}","bls_seed_hex":"{}","stake":1,"bls_register_sig_hex":"{}"}}]}}"#,
            hex::encode(vrf_seed),
            hex::encode(bls_seed),
            sig_hex
        );
        assert!(matches!(
            genesis_config_from_json_bytes(s.as_bytes()),
            Err(GenesisSpecError::InvalidValidatorBlsPop { index: 0 })
        ));
    }

    #[test]
    fn public_devnet_v1_genesis_id_unchanged() {
        use mfn_consensus::{apply_genesis, block_id, build_genesis};
        let json = include_str!("../../mfn-node/testdata/public_devnet_v1.json");
        let cfg = genesis_config_from_json_bytes(json.as_bytes()).expect("parse");
        let genesis = build_genesis(&cfg);
        let manifest: serde_json::Value = serde_json::from_str(include_str!(
            "../../mfn-node/testdata/public_devnet_v1.manifest.json"
        ))
        .expect("manifest");
        let want = manifest["genesis_id"].as_str().expect("genesis_id");
        assert_eq!(hex::encode(block_id(&genesis.header)), want);
        let state = apply_genesis(&genesis, &cfg).expect("apply");
        assert_eq!(state.storage_operators.len(), 2);
        assert_eq!(cfg.endowment_params.require_registered_operators, 1);
    }
}
