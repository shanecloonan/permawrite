//! Storage-upload transaction construction for browser wallets (**M4.6**).

use std::collections::HashSet;

use curve25519_dalek::edwards::EdwardsPoint;
use mfn_consensus::{encode_transaction, tx_id, Recipient};
use mfn_crypto::crypto_random;
use mfn_crypto::point::point_from_bytes;
use mfn_storage::{storage_commitment_hash, DEFAULT_ENDOWMENT_PARAMS};
use mfn_wallet::{
    build_decoy_pool_from_sources, build_storage_upload, estimate_minimum_fee_for_upload,
    ClaimingIdentity, StorageUploadPlan, StoredOwnedOutput, TransferRecipient, UtxoDecoySource,
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

    let mut rng = crypto_random;
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
}
