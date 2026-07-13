//! Light-chain follower state for browser wallets (**M4.11**).

use mfn_consensus::{decode_block_header, decode_bond_op, decode_evidence, BondOp, SlashEvidence};
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

fn parse_evolution(
    evolution_json: &str,
) -> Result<(Vec<SlashEvidence>, Vec<BondOp>), WasmCoreError> {
    let body: EvolutionJson = serde_json::from_str(evolution_json)
        .map_err(|e| WasmCoreError::InvalidHex(e.to_string()))?;
    let slash_bytes = decode_hex_list(&body.slashings, "slashings")?;
    let mut slashings = Vec::with_capacity(slash_bytes.len());
    for bytes in slash_bytes {
        slashings.push(SlashEvidence::Equivocation(
            decode_evidence(&bytes)
                .map_err(|e| WasmCoreError::InvalidHex(format!("slashings: {e}")))?,
        ));
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
    let (slashings, bond_ops) = parse_evolution(evolution_json)?;
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
