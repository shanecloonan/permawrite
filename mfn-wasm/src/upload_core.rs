//! Storage-upload transaction construction for browser wallets (**M4.6**).

use std::collections::HashSet;

use curve25519_dalek::edwards::EdwardsPoint;
use mfn_consensus::{encode_transaction, tx_id, Recipient};
use mfn_crypto::point::point_from_bytes;
use mfn_storage::{
    build_storage_proof, chunk_data, decode_storage_commitment, encode_storage_proof,
    merkle_tree_from_chunks, storage_commitment_hash, verify_storage_proof,
    DEFAULT_ENDOWMENT_PARAMS,
};
use mfn_wallet::production_tx_rng;
use mfn_wallet::{
    build_decoy_pool_from_sources, build_storage_upload, estimate_minimum_fee_for_upload,
    wallet_from_seed, ClaimingIdentity, StorageUploadPlan, StoredOwnedOutput, TransferRecipient,
    UtxoDecoySource,
};
use serde::{Deserialize, Serialize};

use crate::core::WasmCoreError;

#[derive(Debug, Serialize, Deserialize)]
struct UtxoJson {
    height: u32,
    one_time_addr_hex: String,
    commit_hex: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct RecipientJson {
    view_pub_hex: String,
    spend_pub_hex: String,
    value: u64,
}

#[derive(Debug, Serialize, Deserialize)]
struct StorageUploadPlanJson {
    inputs: Vec<StoredOwnedOutput>,
    anchor: RecipientJson,
    replication: u8,
    fee: u64,
    ring_size: usize,
    current_height: u64,
    decoy_utxos: Vec<UtxoJson>,
    #[serde(default)]
    exclude_one_time_addrs_hex: Vec<String>,
    #[serde(default = "default_fee_to_treasury_bps")]
    fee_to_treasury_bps: u16,
    #[serde(default)]
    chunk_size: Option<u32>,
    #[serde(default)]
    change_recipients: Vec<RecipientJson>,
    #[serde(default)]
    extra_hex: String,
    #[serde(default)]
    message_hex: String,
}

fn default_fee_to_treasury_bps() -> u16 {
    9000
}

#[derive(Serialize)]
struct StorageUploadResultJson {
    tx_hex: String,
    tx_id: String,
    data_root: String,
    commitment_hash: String,
    burden: String,
    min_fee: u64,
}

fn parse_point32(hex_str: &str, field: &str) -> Result<EdwardsPoint, WasmCoreError> {
    let t = hex_str.trim();
    let t = t
        .strip_prefix("0x")
        .or_else(|| t.strip_prefix("0X"))
        .unwrap_or(t);
    if t.len() != 64 {
        return Err(WasmCoreError::InvalidHex(format!(
            "{field} must be 64 hex characters (got {})",
            t.len()
        )));
    }
    let mut b = [0u8; 32];
    hex::decode_to_slice(t, &mut b)
        .map_err(|e| WasmCoreError::InvalidHex(format!("{field}: {e}")))?;
    point_from_bytes(&b).map_err(|e| WasmCoreError::InvalidHex(format!("{field}: {e}")))
}

fn parse_exclude_addrs(addrs: &[String]) -> Result<HashSet<[u8; 32]>, WasmCoreError> {
    let mut set = HashSet::new();
    for a in addrs {
        let t = a.trim();
        if t.is_empty() {
            continue;
        }
        let t = t
            .strip_prefix("0x")
            .or_else(|| t.strip_prefix("0X"))
            .unwrap_or(t);
        if t.len() != 64 {
            return Err(WasmCoreError::InvalidHex(format!(
                "exclude addr must be 64 hex chars (got {})",
                t.len()
            )));
        }
        let mut key = [0u8; 32];
        hex::decode_to_slice(t, &mut key).map_err(|e| WasmCoreError::InvalidHex(e.to_string()))?;
        set.insert(key);
    }
    Ok(set)
}

fn utxos_from_json(rows: &[UtxoJson]) -> Result<Vec<UtxoDecoySource>, WasmCoreError> {
    rows.iter()
        .map(|u| {
            Ok(UtxoDecoySource {
                height: u.height,
                one_time_addr: parse_point32(&u.one_time_addr_hex, "one_time_addr")?,
                commit: parse_point32(&u.commit_hex, "commit")?,
            })
        })
        .collect()
}

fn recipient_from_json(r: &RecipientJson) -> Result<TransferRecipient, WasmCoreError> {
    Ok(TransferRecipient {
        recipient: Recipient {
            view_pub: parse_point32(&r.view_pub_hex, "view_pub")?,
            spend_pub: parse_point32(&r.spend_pub_hex, "spend_pub")?,
        },
        value: r.value,
    })
}

/// Minimum fee for a storage upload (JSON number as string).
pub fn upload_min_fee_json(
    data_len: u64,
    replication: u8,
    fee_to_treasury_bps: u16,
) -> Result<String, WasmCoreError> {
    let min_fee = estimate_minimum_fee_for_upload(
        data_len,
        replication,
        &DEFAULT_ENDOWMENT_PARAMS,
        fee_to_treasury_bps,
    )
    .map_err(|e| WasmCoreError::Storage(e.to_string()))?;
    serde_json::to_string(&min_fee).map_err(|e| WasmCoreError::Storage(e.to_string()))
}

/// Build and sign a storage-anchored upload transaction.
pub fn build_storage_upload_json(
    seed: &[u8; 32],
    data: &[u8],
    plan_json: &str,
) -> Result<String, WasmCoreError> {
    let plan: StorageUploadPlanJson = serde_json::from_str(plan_json)
        .map_err(|e| WasmCoreError::InvalidHex(format!("upload plan json: {e}")))?;

    let mut inputs = Vec::with_capacity(plan.inputs.len());
    for stored in &plan.inputs {
        inputs.push(
            stored
                .to_owned()
                .map_err(|e| WasmCoreError::InvalidHex(e.to_string()))?,
        );
    }
    let input_refs: Vec<_> = inputs.iter().collect();

    let anchor = recipient_from_json(&plan.anchor)?;
    let anchor_recipient = anchor.recipient;

    let mut change_tr: Vec<TransferRecipient> = plan
        .change_recipients
        .iter()
        .map(recipient_from_json)
        .collect::<Result<Vec<_>, _>>()?;

    let input_total: u64 = inputs
        .iter()
        .map(|o| o.value)
        .fold(0u64, u64::saturating_add);
    let change_explicit: u64 = change_tr
        .iter()
        .map(|r| r.value)
        .fold(0u64, u64::saturating_add);
    let needed_base = anchor
        .value
        .saturating_add(plan.fee)
        .saturating_add(change_explicit);
    if input_total < needed_base {
        return Err(WasmCoreError::Storage(format!(
            "insufficient funds: need {needed_base}, have {input_total}"
        )));
    }
    let auto_change = input_total.saturating_sub(needed_base);
    if auto_change > 0 {
        change_tr.push(TransferRecipient {
            recipient: anchor_recipient,
            value: auto_change,
        });
    }

    let sources = utxos_from_json(&plan.decoy_utxos)?;
    let excludes = parse_exclude_addrs(&plan.exclude_one_time_addrs_hex)?;
    let decoy_pool = build_decoy_pool_from_sources(&sources, excludes);

    let extra = decode_extra_hex(&plan.extra_hex)?;
    let mut authorship_claims = Vec::new();
    if !plan.message_hex.trim().is_empty() {
        if !extra.is_empty() {
            return Err(WasmCoreError::Storage(
                "cannot set both extra_hex and message_hex (authorship uses MFEX extra)".into(),
            ));
        }
        let msg = decode_extra_hex(&plan.message_hex)?;
        let endowment = mfn_storage::required_endowment(
            data.len() as u64,
            plan.replication,
            &DEFAULT_ENDOWMENT_PARAMS,
        )
        .map_err(|e| WasmCoreError::Storage(e.to_string()))?;
        let endowment_u64 = u64::try_from(endowment).map_err(|_| {
            WasmCoreError::Storage(format!("required_endowment {endowment} exceeds u64::MAX"))
        })?;
        let built = mfn_storage::build_storage_commitment(
            data,
            endowment_u64,
            plan.chunk_size.map(|c| c as usize),
            plan.replication,
            None,
        )
        .map_err(|e| WasmCoreError::Storage(e.to_string()))?;
        let commit_hash = storage_commitment_hash(&built.commit);
        let identity = ClaimingIdentity::from_seed(seed);
        let claim = identity
            .sign_storage_claim(built.commit.data_root, commit_hash, &msg)
            .map_err(|e| WasmCoreError::Storage(e.to_string()))?;
        authorship_claims.push(claim);
    }

    let mut rng = production_tx_rng;
    let upload_plan = StorageUploadPlan {
        inputs: &input_refs,
        anchor,
        data,
        replication: plan.replication,
        chunk_size: plan.chunk_size.map(|c| c as usize),
        endowment_blinding: None,
        endowment_params: &DEFAULT_ENDOWMENT_PARAMS,
        fee_to_treasury_bps: plan.fee_to_treasury_bps,
        change_recipients: &change_tr,
        fee: plan.fee,
        extra: &extra,
        authorship_claims: &authorship_claims,
        ring_size: plan.ring_size,
        decoy_pool: &decoy_pool,
        current_height: plan.current_height,
        rng: &mut rng,
    };

    let art =
        build_storage_upload(upload_plan).map_err(|e| WasmCoreError::Storage(e.to_string()))?;
    let id = tx_id(&art.signed.tx);
    let commit_hash = storage_commitment_hash(&art.built.commit);
    let json = StorageUploadResultJson {
        tx_hex: hex::encode(encode_transaction(&art.signed.tx)),
        tx_id: hex::encode(id),
        data_root: hex::encode(art.built.commit.data_root),
        commitment_hash: hex::encode(commit_hash),
        burden: art.burden.to_string(),
        min_fee: art.min_fee,
    };
    serde_json::to_string(&json).map_err(|e| WasmCoreError::Storage(e.to_string()))
}

fn prove_parse_hex32(field: &str, hex_str: &str) -> Result<[u8; 32], WasmCoreError> {
    let t = hex_str.trim();
    let t = t
        .strip_prefix("0x")
        .or_else(|| t.strip_prefix("0X"))
        .unwrap_or(t);
    if t.len() != 64 {
        return Err(WasmCoreError::InvalidHex(format!(
            "{field} must be 64 hex characters (got {})",
            t.len()
        )));
    }
    let mut out = [0u8; 32];
    hex::decode_to_slice(t, &mut out)
        .map_err(|e| WasmCoreError::InvalidHex(format!("{field}: {e}")))?;
    Ok(out)
}

/// Build a SPoRA storage proof for the given payload and on-chain commitment (JSON).
pub fn build_storage_proof_json(
    seed_hex: &str,
    data: &[u8],
    prev_block_id_hex: &str,
    slot: u32,
    commitment_wire_hex: &str,
) -> Result<String, WasmCoreError> {
    let seed = crate::core::parse_seed_hex(seed_hex)?;
    let prev = prove_parse_hex32("prev_block_id", prev_block_id_hex)?;
    let wire = hex::decode(commitment_wire_hex.trim().trim_start_matches("0x"))
        .map_err(|e| WasmCoreError::InvalidHex(format!("commitment_wire_hex: {e}")))?;
    let commit = decode_storage_commitment(&wire)
        .map_err(|e| WasmCoreError::Storage(format!("decode_storage_commitment: {e}")))?;
    if u64::try_from(data.len()).unwrap_or(u64::MAX) != commit.size_bytes {
        return Err(WasmCoreError::Storage(format!(
            "data length {} != commitment size_bytes {}",
            data.len(),
            commit.size_bytes
        )));
    }
    let chunks = chunk_data(data, commit.chunk_size as usize)
        .map_err(|e| WasmCoreError::Storage(format!("chunk_data: {e}")))?;
    let chunk_refs: Vec<&[u8]> = chunks.iter().map(|c| &c[..]).collect();
    let tree =
        merkle_tree_from_chunks(&chunk_refs).map_err(|e| WasmCoreError::Storage(e.to_string()))?;
    if tree.root() != commit.data_root {
        return Err(WasmCoreError::Storage(
            "payload bytes do not match commitment data_root".into(),
        ));
    }
    let keys = wallet_from_seed(&seed);
    let proof = build_storage_proof(
        &commit,
        &prev,
        slot,
        data,
        &tree,
        keys.view_pub(),
        keys.spend_pub(),
    )
    .map_err(|e| WasmCoreError::Storage(format!("build_storage_proof: {e}")))?;
    let c_hash = storage_commitment_hash(&commit);
    #[derive(Serialize)]
    struct Out {
        proof_wire_hex: String,
        commitment_hash: String,
        chunk_index: u32,
    }
    serde_json::to_string(&Out {
        proof_wire_hex: hex::encode(encode_storage_proof(&proof)),
        commitment_hash: hex::encode(c_hash),
        chunk_index: proof.proof.index as u32,
    })
    .map_err(|e| WasmCoreError::Storage(e.to_string()))
}

/// Verify a SPoRA storage proof against commitment, prev block id, and slot (JSON).
pub fn verify_storage_proof_json(
    commitment_wire_hex: &str,
    prev_block_id_hex: &str,
    slot: u32,
    proof_wire_hex: &str,
) -> Result<String, WasmCoreError> {
    let prev = prove_parse_hex32("prev_block_id", prev_block_id_hex)?;
    let commit = decode_storage_commitment(
        &hex::decode(commitment_wire_hex.trim().trim_start_matches("0x"))
            .map_err(|e| WasmCoreError::InvalidHex(format!("commitment_wire_hex: {e}")))?,
    )
    .map_err(|e| WasmCoreError::Storage(format!("decode_storage_commitment: {e}")))?;
    let proof = mfn_storage::decode_storage_proof(
        &hex::decode(proof_wire_hex.trim().trim_start_matches("0x"))
            .map_err(|e| WasmCoreError::InvalidHex(format!("proof_wire_hex: {e}")))?,
    )
    .map_err(|e| WasmCoreError::Storage(format!("decode_storage_proof: {e}")))?;
    let check = verify_storage_proof(&commit, &prev, slot, &proof);
    #[derive(Serialize)]
    struct V {
        valid: bool,
        check: String,
    }
    serde_json::to_string(&V {
        valid: check.is_valid(),
        check: format!("{check:?}"),
    })
    .map_err(|e| WasmCoreError::Storage(e.to_string()))
}

/// Return one Merkle chunk of data as hex (JSON) for HTTP chunk serving.
pub fn storage_chunk_hex_json(
    data: &[u8],
    chunk_size: u32,
    index: u32,
) -> Result<String, WasmCoreError> {
    let chunks = chunk_data(data, chunk_size as usize)
        .map_err(|e| WasmCoreError::Storage(format!("chunk_data: {e}")))?;
    let chunk = chunks
        .get(index as usize)
        .ok_or_else(|| WasmCoreError::Storage(format!("chunk index {index} out of range")))?;
    #[derive(Serialize)]
    struct C {
        index: u32,
        chunk_hex: String,
    }
    serde_json::to_string(&C {
        index,
        chunk_hex: hex::encode(chunk),
    })
    .map_err(|e| WasmCoreError::Storage(e.to_string()))
}

fn decode_extra_hex(extra_hex: &str) -> Result<Vec<u8>, WasmCoreError> {
    let t = extra_hex.trim();
    if t.is_empty() {
        return Ok(Vec::new());
    }
    let t = t
        .strip_prefix("0x")
        .or_else(|| t.strip_prefix("0X"))
        .unwrap_or(t);
    hex::decode(t).map_err(|e| WasmCoreError::InvalidHex(format!("extra_hex: {e}")))
}

#[cfg(all(test, feature = "wasm-full"))]
mod tests {
    use super::*;

    #[test]
    fn upload_min_fee_increases_with_size() {
        let small = upload_min_fee_json(1_000, 3, 9000).expect("small");
        let big = upload_min_fee_json(1_000_000, 3, 9000).expect("big");
        let s: u64 = serde_json::from_str(&small).expect("parse");
        let b: u64 = serde_json::from_str(&big).expect("parse");
        assert!(b >= s);
    }
    #[test]
    fn wasm_build_and_verify_storage_proof_round_trip() {
        use mfn_storage::{build_storage_commitment, DEFAULT_CHUNK_SIZE};
        let data: Vec<u8> = (0..256 * 1024).map(|i| (i % 251) as u8).collect();
        let built = build_storage_commitment(&data, 1_000, Some(DEFAULT_CHUNK_SIZE), 3, None)
            .expect("commit");
        let wire = hex::encode(mfn_storage::encode_storage_commitment(&built.commit));
        let built_json = build_storage_proof_json(
            &hex::encode([9u8; 32]),
            &data,
            &hex::encode([42u8; 32]),
            7,
            &wire,
        )
        .expect("build");
        let v: serde_json::Value = serde_json::from_str(&built_json).expect("parse");
        let verify_json = verify_storage_proof_json(
            &wire,
            &hex::encode([42u8; 32]),
            7,
            v["proof_wire_hex"].as_str().unwrap(),
        )
        .expect("verify");
        let ok: serde_json::Value = serde_json::from_str(&verify_json).expect("parse verify");
        assert_eq!(ok["valid"], true);
    }
}
