//! Light-chain follower state for browser wallets (**M4.11**).

use mfn_consensus::{
    decode_block_header, decode_bond_op, decode_slash_evidence, BondOp, SlashEvidence,
};
use mfn_light::{LightChain, LightChainError};
use serde::{Deserialize, Serialize};

use crate::core::WasmCoreError;
use crate::header_verify_core::{consensus_from_json, validators_from_json};

#[derive(Deserialize)]
struct EvolutionJson {
    slashings: Vec<String>,
    bond_ops: Vec<String>,
}

#[derive(Serialize)]
struct LightChainStepOk {
    ok: bool,
    checkpoint_hex: String,
    tip_height: u32,
    tip_block_id: String,
    validator_count: usize,
}

#[derive(Serialize)]
struct LightChainStepErr {
    ok: bool,
    error: String,
}

fn decode_hex_list(items: &[String], label: &str) -> Result<Vec<Vec<u8>>, WasmCoreError> {
    let mut out = Vec::with_capacity(items.len());
    for (i, hex_s) in items.iter().enumerate() {
        let t = hex_s
            .trim()
            .strip_prefix("0x")
            .or_else(|| hex_s.trim().strip_prefix("0X"))
            .unwrap_or(hex_s.trim());
        let bytes =
            hex::decode(t).map_err(|e| WasmCoreError::InvalidHex(format!("{label}[{i}]: {e}")))?;
        out.push(bytes);
    }
    Ok(out)
}

/// Decode the follow row's evolution section for the chain at
/// `header_version`. Slash blobs are version-tagged from header v3 and
/// carry bound equivocation evidence from v8 (**B-330**); the legacy
/// equivocation codec alone would refuse them (**B-331**).
fn parse_evolution(
    evolution_json: &str,
    header_version: u32,
) -> Result<(Vec<SlashEvidence>, Vec<BondOp>), WasmCoreError> {
    let body: EvolutionJson = serde_json::from_str(evolution_json)
        .map_err(|e| WasmCoreError::InvalidHex(e.to_string()))?;
    let slash_bytes = decode_hex_list(&body.slashings, "slashings")?;
    let mut slashings = Vec::with_capacity(slash_bytes.len());
    for (i, bytes) in slash_bytes.iter().enumerate() {
        slashings.push(
            decode_slash_evidence(bytes, header_version)
                .map_err(|e| WasmCoreError::InvalidHex(format!("slashings[{i}]: {e}")))?,
        );
    }
    let bond_bytes = decode_hex_list(&body.bond_ops, "bond_ops")?;
    let mut bond_ops = Vec::with_capacity(bond_bytes.len());
    for bytes in bond_bytes {
        bond_ops.push(
            decode_bond_op(&bytes)
                .map_err(|e| WasmCoreError::InvalidHex(format!("bond_ops: {e}")))?,
        );
    }
    Ok((slashings, bond_ops))
}

fn light_error_message(e: LightChainError) -> String {
    format!("{e}")
}

/// Encode a genesis-trust bootstrap checkpoint (tip height 0) from chain params JSON.
pub fn light_chain_bootstrap_checkpoint_hex(trust_json: &str) -> Result<String, WasmCoreError> {
    let chain = light_chain_from_trust_json(trust_json)?;
    Ok(hex::encode(chain.encode_checkpoint()))
}

/// Restore a [`LightChain`] from checkpoint bytes (from `get_light_snapshot` RPC).
pub fn light_chain_from_checkpoint_hex(checkpoint_hex: &str) -> Result<LightChain, WasmCoreError> {
    let bytes = decode_hex_payload(checkpoint_hex)?;
    LightChain::decode_checkpoint(&bytes).map_err(|e| WasmCoreError::InvalidHex(format!("{e}")))
}

/// Bootstrap a follower at genesis tip from `get_chain_params`-shaped trust JSON.
///
/// `trust_json` must include `validators`, `consensus`, and `bonding` objects.
pub fn light_chain_from_trust_json(trust_json: &str) -> Result<LightChain, WasmCoreError> {
    use mfn_consensus::{BondingParams, GenesisConfig};

    let v: serde_json::Value =
        serde_json::from_str(trust_json).map_err(|e| WasmCoreError::InvalidHex(e.to_string()))?;
    let validators = validators_from_json(
        &serde_json::to_string(&v["validators"])
            .map_err(|e| WasmCoreError::InvalidHex(e.to_string()))?,
    )?;
    let params = consensus_from_json(
        &serde_json::to_string(&v["consensus"])
            .map_err(|e| WasmCoreError::InvalidHex(e.to_string()))?,
    )?;
    let bonding: BondingParams = {
        let b = &v["bonding"];
        BondingParams {
            min_validator_stake: b["min_validator_stake"]
                .as_u64()
                .ok_or_else(|| WasmCoreError::InvalidHex("bonding.min_validator_stake".into()))?,
            unbond_delay_heights: b["unbond_delay_heights"]
                .as_u64()
                .and_then(|n| u32::try_from(n).ok())
                .ok_or_else(|| WasmCoreError::InvalidHex("bonding.unbond_delay_heights".into()))?,
            max_entry_churn_per_epoch: b["max_entry_churn_per_epoch"]
                .as_u64()
                .and_then(|n| u32::try_from(n).ok())
                .ok_or_else(|| {
                    WasmCoreError::InvalidHex("bonding.max_entry_churn_per_epoch".into())
                })?,
            max_exit_churn_per_epoch: b["max_exit_churn_per_epoch"]
                .as_u64()
                .and_then(|n| u32::try_from(n).ok())
                .ok_or_else(|| {
                    WasmCoreError::InvalidHex("bonding.max_exit_churn_per_epoch".into())
                })?,
            slots_per_epoch: b["slots_per_epoch"]
                .as_u64()
                .and_then(|n| u32::try_from(n).ok())
                .ok_or_else(|| WasmCoreError::InvalidHex("bonding.slots_per_epoch".into()))?,
        }
    };
    let genesis_id_hex = v["genesis_id"]
        .as_str()
        .ok_or_else(|| WasmCoreError::InvalidHex("missing genesis_id".into()))?;
    let genesis_id = parse_hex32(genesis_id_hex, "genesis_id")?;

    let cfg = GenesisConfig {
        timestamp: 0,
        initial_outputs: Vec::new(),
        initial_storage: Vec::new(),
        initial_storage_operators: Vec::new(),
        validators,
        params,
        emission_params: mfn_consensus::DEFAULT_EMISSION_PARAMS,
        endowment_params: mfn_storage::DEFAULT_ENDOWMENT_PARAMS,
        bonding_params: Some(bonding),
        header_version: 1,
    };
    let chain = mfn_light::LightChain::from_genesis(mfn_light::LightChainConfig::new(cfg));
    if chain.genesis_id() != &genesis_id {
        return Err(WasmCoreError::InvalidHex(
            "trust genesis_id does not match derived genesis".into(),
        ));
    }
    Ok(chain)
}

fn parse_hex32(s: &str, label: &str) -> Result<[u8; 32], WasmCoreError> {
    let t = s
        .trim()
        .strip_prefix("0x")
        .or_else(|| s.strip_prefix("0X"))
        .unwrap_or(s.trim());
    if t.len() != 64 {
        return Err(WasmCoreError::InvalidHex(format!(
            "{label} must be 64 hex chars"
        )));
    }
    let mut out = [0u8; 32];
    hex::decode_to_slice(t, &mut out).map_err(|e| WasmCoreError::InvalidHex(e.to_string()))?;
    Ok(out)
}

fn decode_hex_payload(hex_str: &str) -> Result<Vec<u8>, WasmCoreError> {
    let t = hex_str
        .trim()
        .strip_prefix("0x")
        .or_else(|| hex_str.trim().strip_prefix("0X"))
        .unwrap_or(hex_str.trim());
    hex::decode(t).map_err(|e| WasmCoreError::InvalidHex(e.to_string()))
}

fn chain_step_ok(chain: &LightChain) -> Result<String, WasmCoreError> {
    let body = LightChainStepOk {
        ok: true,
        checkpoint_hex: hex::encode(chain.encode_checkpoint()),
        tip_height: chain.tip_height(),
        tip_block_id: hex::encode(chain.tip_id()),
        validator_count: chain.trusted_validators().len(),
    };
    serde_json::to_string(&body).map_err(|e| WasmCoreError::InvalidHex(e.to_string()))
}

/// Verify a header against the checkpoint's trusted validator set (no state advance).
pub fn light_chain_verify_header_json(
    checkpoint_hex: &str,
    header_hex: &str,
) -> Result<String, WasmCoreError> {
    let chain = light_chain_from_checkpoint_hex(checkpoint_hex)?;
    let header = decode_block_header(&decode_hex_payload(header_hex)?)
        .map_err(|e| WasmCoreError::InvalidHex(e.to_string()))?;
    match mfn_consensus::verify_header(&header, chain.trusted_validators(), chain.params()) {
        Ok(check) => {
            let body = serde_json::json!({
                "ok": true,
                "block_id": hex::encode(mfn_consensus::block_id(&header)),
                "check": {
                    "producer_index": check.producer_index,
                    "signing_stake": check.signing_stake,
                    "total_stake": check.total_stake,
                    "quorum_required": check.quorum_required,
                    "validator_count": check.validator_count,
                }
            });
            serde_json::to_string(&body).map_err(|e| WasmCoreError::InvalidHex(e.to_string()))
        }
        Err(e) => {
            let body = LightChainStepErr {
                ok: false,
                error: format!("{e}"),
            };
            serde_json::to_string(&body).map_err(|e| WasmCoreError::InvalidHex(e.to_string()))
        }
    }
}

/// Advance follower state after a cryptographically verified header + evolution body.
pub fn light_chain_apply_evolution_json(
    checkpoint_hex: &str,
    header_hex: &str,
    evolution_json: &str,
) -> Result<String, WasmCoreError> {
    let mut chain = light_chain_from_checkpoint_hex(checkpoint_hex)?;
    let header = decode_block_header(&decode_hex_payload(header_hex)?)
        .map_err(|e| WasmCoreError::InvalidHex(e.to_string()))?;
    let (slashings, bond_ops) = parse_evolution(evolution_json, header.version)?;
    match chain.apply_trusted_evolution(&header, &slashings, &bond_ops) {
        Ok(_tip) => chain_step_ok(&chain),
        Err(e) => {
            let body = LightChainStepErr {
                ok: false,
                error: light_error_message(e),
            };
            serde_json::to_string(&body).map_err(|e| WasmCoreError::InvalidHex(e.to_string()))
        }
    }
}

#[cfg(all(test, feature = "wasm-full"))]
mod b331_tests {
    use super::*;
    use mfn_bls::{bls_keygen_from_seed, bls_sign};
    use mfn_consensus::slashing::{BoundEquivocationEvidence, EquivocationEvidence};
    use mfn_consensus::{
        encode_slash_evidence, header_signing_bytes, header_signing_hash_from_bytes, BlockHeader,
        HEADER_VERSION, HEADER_VERSION_EQUIVOCATION_BIND, HEADER_VERSION_FRAUD_SLASH,
    };

    fn preimage(version: u32, salt: u8) -> Vec<u8> {
        header_signing_bytes(&BlockHeader {
            version,
            prev_hash: [1u8; 32],
            height: 4,
            slot: 4,
            timestamp: 400,
            tx_root: [salt; 32],
            storage_root: [0u8; 32],
            bond_root: [0u8; 32],
            slashing_root: [0u8; 32],
            storage_proof_root: [0u8; 32],
            validator_root: [0u8; 32],
            claims_root: [0u8; 32],
            producer_proof: Vec::new(),
            utxo_root: [0u8; 32],
        })
    }

    fn legacy_blob(version: u32) -> String {
        let bls = bls_keygen_from_seed(&[9u8; 32]);
        let (a, b) = ([5u8; 32], [6u8; 32]);
        let ev = SlashEvidence::Equivocation(EquivocationEvidence {
            height: 4,
            slot: 4,
            voter_index: 0,
            header_hash_a: a,
            sig_a: bls_sign(&a, &bls.sk),
            header_hash_b: b,
            sig_b: bls_sign(&b, &bls.sk),
        });
        hex::encode(encode_slash_evidence(&ev, version))
    }

    fn bound_blob() -> String {
        let bls = bls_keygen_from_seed(&[9u8; 32]);
        let (a, b) = (
            preimage(HEADER_VERSION_EQUIVOCATION_BIND, 1),
            preimage(HEADER_VERSION_EQUIVOCATION_BIND, 2),
        );
        let ev = SlashEvidence::BoundEquivocation(BoundEquivocationEvidence {
            height: 4,
            slot: 4,
            voter_index: 0,
            sig_a: bls_sign(&header_signing_hash_from_bytes(&a), &bls.sk),
            sig_b: bls_sign(&header_signing_hash_from_bytes(&b), &bls.sk),
            signing_a: a,
            signing_b: b,
        });
        hex::encode(encode_slash_evidence(&ev, HEADER_VERSION_EQUIVOCATION_BIND))
    }

    fn evolution_json(slashings: &[String]) -> String {
        serde_json::json!({ "slashings": slashings, "bond_ops": [] }).to_string()
    }

    #[test]
    fn legacy_row_still_parses_on_header_v1() {
        let json = evolution_json(&[legacy_blob(HEADER_VERSION)]);
        let (slashings, bond_ops) = parse_evolution(&json, HEADER_VERSION).expect("v1 row");
        assert_eq!(slashings.len(), 1);
        assert!(matches!(slashings[0], SlashEvidence::Equivocation(_)));
        assert!(bond_ops.is_empty());
    }

    #[test]
    fn tagged_row_parses_on_header_v3() {
        let json = evolution_json(&[legacy_blob(HEADER_VERSION_FRAUD_SLASH)]);
        let (slashings, _) =
            parse_evolution(&json, HEADER_VERSION_FRAUD_SLASH).expect("tagged v3 row");
        assert!(matches!(slashings[0], SlashEvidence::Equivocation(_)));
    }

    #[test]
    fn bound_row_parses_on_header_v8_and_is_refused_below() {
        let json = evolution_json(&[bound_blob()]);
        let (slashings, _) =
            parse_evolution(&json, HEADER_VERSION_EQUIVOCATION_BIND).expect("bound v8 row");
        assert!(matches!(slashings[0], SlashEvidence::BoundEquivocation(_)));
        let err = parse_evolution(&json, HEADER_VERSION_FRAUD_SLASH).expect_err("v3 refuses bound");
        assert!(format!("{err}").contains("slashings[0]"), "{err}");
    }

    #[test]
    fn malformed_row_names_its_index() {
        let json = evolution_json(&[legacy_blob(HEADER_VERSION), "deadbeef".into()]);
        let err = parse_evolution(&json, HEADER_VERSION).expect_err("truncated blob");
        assert!(format!("{err}").contains("slashings[1]"), "{err}");
    }
}
