//! Storage-upload transaction construction for browser wallets (**M4.6**).

use std::collections::HashSet;

use curve25519_dalek::edwards::EdwardsPoint;
use mfn_consensus::{encode_transaction, tx_id, Recipient};
use mfn_crypto::point::point_from_bytes;
use mfn_storage::{
    build_storage_proof, chunk_data, decode_storage_commitment, encode_storage_proof,
    merkle_tree_from_chunks, storage_commitment_hash, validate_endowment_params,
    verify_storage_proof, EndowmentParams, DEFAULT_ENDOWMENT_PARAMS,
};
use mfn_wallet::production_tx_rng;
use mfn_wallet::{
    build_decoy_pool_from_sources, build_storage_upload, estimate_minimum_fee_for_upload,
    wallet_from_seed, ClaimingIdentity, StorageUploadPlan, StoredOwnedOutput, TransferRecipient,
    UtxoDecoySource, WALLET_MIN_RING_SIZE, WALLET_MIN_TX_INPUTS,
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
    /// Live chain endowment policy from `get_chain_params` (M4.8 / B1 phase 2).
    #[serde(default)]
    endowment: EndowmentPlanJson,
}

fn default_fee_to_treasury_bps() -> u16 {
    9000
}

/// Optional endowment-policy overrides from `get_chain_params.endowment` (M4.8).
#[derive(Debug, Serialize, Deserialize, Default)]
struct EndowmentPlanJson {
    #[serde(default)]
    cost_per_byte_year_ppb: Option<u64>,
    #[serde(default)]
    inflation_ppb: Option<u64>,
    #[serde(default)]
    real_yield_ppb: Option<u64>,
    #[serde(default)]
    min_replication: Option<u8>,
    #[serde(default)]
    max_replication: Option<u8>,
    #[serde(default)]
    slots_per_year: Option<u64>,
    #[serde(default)]
    proof_reward_window_slots: Option<u64>,
    #[serde(default)]
    require_endowment_opening: Option<u8>,
    #[serde(default)]
    require_endowment_range_proof: Option<u8>,
    #[serde(default)]
    operator_salted_challenges: Option<u8>,
    #[serde(default)]
    require_registered_operators: Option<u8>,
    #[serde(default)]
    min_storage_operator_bond: Option<u64>,
    #[serde(default)]
    operator_audit_missed_cap: Option<u8>,
    #[serde(default)]
    operator_slash_bps: Option<u32>,
}

fn merge_endowment_params(plan: &EndowmentPlanJson) -> Result<EndowmentParams, WasmCoreError> {
    let mut p = DEFAULT_ENDOWMENT_PARAMS;
    if let Some(v) = plan.cost_per_byte_year_ppb {
        p.cost_per_byte_year_ppb = v;
    }
    if let Some(v) = plan.inflation_ppb {
        p.inflation_ppb = v;
    }
    if let Some(v) = plan.real_yield_ppb {
        p.real_yield_ppb = v;
    }
    if let Some(v) = plan.min_replication {
        p.min_replication = v;
    }
    if let Some(v) = plan.max_replication {
        p.max_replication = v;
    }
    if let Some(v) = plan.slots_per_year {
        p.slots_per_year = v;
    }
    if let Some(v) = plan.proof_reward_window_slots {
        p.proof_reward_window_slots = v;
    }
    if let Some(v) = plan.require_endowment_opening {
        p.require_endowment_opening = v;
    }
    if let Some(v) = plan.require_endowment_range_proof {
        p.require_endowment_range_proof = v;
    }
    if let Some(v) = plan.operator_salted_challenges {
        p.operator_salted_challenges = v;
    }
    if let Some(v) = plan.require_registered_operators {
        p.require_registered_operators = v;
    }
    if let Some(v) = plan.min_storage_operator_bond {
        p.min_storage_operator_bond = v;
    }
    if let Some(v) = plan.operator_audit_missed_cap {
        p.operator_audit_missed_cap = v;
    }
    if let Some(v) = plan.operator_slash_bps {
        p.operator_slash_bps = v;
    }
    validate_endowment_params(&p).map_err(|e| WasmCoreError::Storage(e.to_string()))?;
    Ok(p)
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
    if plan.ring_size < WALLET_MIN_RING_SIZE {
        return Err(WasmCoreError::InvalidHex(format!(
            "ring size {} below wallet minimum {WALLET_MIN_RING_SIZE}",
            plan.ring_size
        )));
    }
    if plan.inputs.len() < WALLET_MIN_TX_INPUTS {
        // B-197: actionable parity with CLI `require_f7_owned_input_floor` (**B-189**).
        return Err(WasmCoreError::InvalidHex(format!(
            "input count {} below wallet minimum {WALLET_MIN_TX_INPUTS} \
             (F7 privacy floor; need a second spendable input — faucet dual-send)",
            plan.inputs.len()
        )));
    }
    let endowment_params = merge_endowment_params(&plan.endowment)?;

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
        let padded = mfn_storage::pad_to_storage_size_bucket(data);
        let endowment = mfn_storage::required_endowment(
            padded.len() as u64,
            plan.replication,
            &endowment_params,
        )
        .map_err(|e| WasmCoreError::Storage(e.to_string()))?;
        let endowment_u64 = u64::try_from(endowment).map_err(|_| {
            WasmCoreError::Storage(format!("required_endowment {endowment} exceeds u64::MAX"))
        })?;
        let built = mfn_storage::build_storage_commitment(
            &padded,
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
        endowment_params: &endowment_params,
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
    let data = mfn_storage::pad_to_storage_size_bucket(data);
    if u64::try_from(data.len()).unwrap_or(u64::MAX) != commit.size_bytes {
        return Err(WasmCoreError::Storage(format!(
            "data length {} != commitment size_bytes {}",
            data.len(),
            commit.size_bytes
        )));
    }
    let chunks = chunk_data(&data, commit.chunk_size as usize)
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
        &data,
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

#[cfg(test)]
mod merge_tests {
    use super::*;

    #[test]
    fn merge_endowment_params_accepts_range_proof_flag() {
        let plan = EndowmentPlanJson {
            require_endowment_range_proof: Some(1),
            ..Default::default()
        };
        let p = merge_endowment_params(&plan).expect("merge");
        assert_eq!(p.require_endowment_range_proof, 1);
    }

    #[test]
    fn merge_endowment_params_rejects_opening_and_range_together() {
        let plan = EndowmentPlanJson {
            require_endowment_opening: Some(1),
            require_endowment_range_proof: Some(1),
            ..Default::default()
        };
        assert!(merge_endowment_params(&plan).is_err());
    }
}

#[cfg(all(test, feature = "wasm-full"))]
mod tests {
    use super::*;

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

    #[test]
    fn wasm_storage_upload_attaches_mfer_when_range_proof_required() {
        use curve25519_dalek::scalar::Scalar;
        use mfn_consensus::extra_codec::parse_mfex_extra;
        use mfn_consensus::{
            decode_transaction, sign_transaction, InputSpec, OutputSpec, Recipient,
        };
        use mfn_crypto::clsag::ClsagRing;
        use mfn_crypto::random_scalar;
        use mfn_crypto::{generator_g, generator_h};
        use mfn_storage::verify_endowment_range_proof_wire;
        use mfn_wallet::scan::scan_transaction;
        use mfn_wallet::wallet_from_seed;

        fn fake_input(value: u64, ring_size: usize) -> InputSpec {
            let signer_spend = random_scalar();
            let signer_idx = 0usize;
            let mut p = Vec::with_capacity(ring_size);
            let mut c = Vec::with_capacity(ring_size);
            let signer_blinding = random_scalar();
            let signer_p = generator_g() * signer_spend;
            let signer_c =
                (generator_g() * signer_blinding) + (generator_h() * Scalar::from(value));
            for i in 0..ring_size {
                if i == signer_idx {
                    p.push(signer_p);
                    c.push(signer_c);
                } else {
                    let s = random_scalar();
                    p.push(generator_g() * s);
                    c.push((generator_g() * random_scalar()) + (generator_h() * random_scalar()));
                }
            }
            InputSpec {
                ring: ClsagRing { p, c },
                signer_idx,
                spend_priv: signer_spend,
                value,
                blinding: signer_blinding,
            }
        }

        const SEED: [u8; 32] = [0x43u8; 32];
        let me = wallet_from_seed(&SEED);
        let recipient = Recipient {
            view_pub: me.view_pub(),
            spend_pub: me.spend_pub(),
        };
        let mut owned_inputs = Vec::with_capacity(2);
        let mut owned_value = 0u64;
        for value in [30_000_000u64, 20_000_000u64] {
            let signed = sign_transaction(
                vec![fake_input(value + 1, 16)],
                vec![OutputSpec::ToRecipient {
                    recipient,
                    value,
                    storage: None,
                }],
                1,
                Vec::new(),
            )
            .expect("sign");
            let scan = scan_transaction(&signed.tx, 1, &me, &HashSet::new());
            assert_eq!(scan.recovered.len(), 1);
            owned_value = owned_value.saturating_add(scan.recovered[0].value);
            owned_inputs.push(StoredOwnedOutput::from_owned(&scan.recovered[0]));
        }

        let mut decoy_utxos = Vec::new();
        for i in 0..20u32 {
            let s = random_scalar();
            let p = generator_g() * s;
            let c = (generator_g() * random_scalar()) + (generator_h() * random_scalar());
            decoy_utxos.push(UtxoJson {
                height: i,
                one_time_addr_hex: hex::encode(p.compress().to_bytes()),
                commit_hex: hex::encode(c.compress().to_bytes()),
            });
        }

        let data = b"wasm mfer upload";
        let replication: u8 = 3;
        let fee = 100_000u64;
        let anchor_value = 1_000u64;
        let change_value = owned_value.saturating_sub(anchor_value).saturating_sub(fee);
        let plan = StorageUploadPlanJson {
            inputs: owned_inputs,
            anchor: RecipientJson {
                view_pub_hex: hex::encode(me.view_pub().compress().to_bytes()),
                spend_pub_hex: hex::encode(me.spend_pub().compress().to_bytes()),
                value: anchor_value,
            },
            replication,
            fee,
            ring_size: WALLET_MIN_RING_SIZE,
            current_height: 1,
            decoy_utxos,
            exclude_one_time_addrs_hex: vec![],
            fee_to_treasury_bps: 9000,
            change_recipients: vec![RecipientJson {
                view_pub_hex: hex::encode(me.view_pub().compress().to_bytes()),
                spend_pub_hex: hex::encode(me.spend_pub().compress().to_bytes()),
                value: change_value,
            }],
            extra_hex: String::new(),
            message_hex: String::new(),
            endowment: EndowmentPlanJson {
                require_endowment_range_proof: Some(1),
                ..Default::default()
            },
            chunk_size: None,
        };
        let plan_str = serde_json::to_string(&plan).expect("plan json");
        let out = build_storage_upload_json(&SEED, data, &plan_str).expect("wasm upload");
        let v: serde_json::Value = serde_json::from_str(&out).expect("parse result");
        let tx_bytes = hex::decode(v["tx_hex"].as_str().expect("tx_hex")).expect("decode tx hex");
        let tx = decode_transaction(&tx_bytes).expect("decode tx");
        let parsed = parse_mfex_extra(&tx.extra).expect("mfex");
        assert_eq!(parsed.endowment_range_proofs.len(), 1);
        assert!(parsed.endowment_openings.is_empty());
        let sc = tx.outputs[0].storage.as_ref().expect("storage output");
        let burden: u128 = v["burden"]
            .as_str()
            .expect("burden")
            .parse()
            .expect("burden u128");
        let required = u64::try_from(burden).expect("burden u64");
        assert!(verify_endowment_range_proof_wire(
            sc,
            required,
            &parsed.endowment_range_proofs[0].proof_bytes,
        ));
    }

    #[test]
    fn upload_min_fee_increases_with_size() {
        let small = upload_min_fee_json(1_000, 3, 9000).expect("small");
        let big = upload_min_fee_json(1_000_000, 3, 9000).expect("big");
        let s: u64 = serde_json::from_str(&small).expect("parse");
        let b: u64 = serde_json::from_str(&big).expect("parse");
        assert!(b >= s);
    }

    /// B-167/B-172: upload JSON boundary refuses sub-floor rings.
    #[test]
    fn build_storage_upload_json_rejects_ring_below_minimum() {
        let plan = StorageUploadPlanJson {
            inputs: vec![],
            anchor: RecipientJson {
                view_pub_hex: "00".repeat(32),
                spend_pub_hex: "00".repeat(32),
                value: 1,
            },
            replication: 3,
            fee: 1,
            ring_size: WALLET_MIN_RING_SIZE - 1,
            current_height: 1,
            decoy_utxos: vec![],
            exclude_one_time_addrs_hex: vec![],
            fee_to_treasury_bps: 9000,
            change_recipients: vec![],
            extra_hex: String::new(),
            message_hex: String::new(),
            endowment: EndowmentPlanJson::default(),
            chunk_size: None,
        };
        let plan_str = serde_json::to_string(&plan).expect("plan json");
        let seed = [0u8; 32];
        let err = build_storage_upload_json(&seed, b"x", &plan_str).expect_err("must reject");
        let msg = err.to_string();
        assert!(msg.contains("below wallet minimum"), "unexpected: {msg}");
    }

    /// B-168/B-172: upload JSON boundary refuses one-input plans (F7).
    #[test]
    fn build_storage_upload_json_rejects_single_input_plan() {
        let owned = StoredOwnedOutput {
            one_time_addr_hex: "00".repeat(32),
            commit_hex: "00".repeat(32),
            value: 1,
            blinding_hex: "00".repeat(32),
            one_time_spend_hex: "00".repeat(32),
            key_image_hex: "00".repeat(32),
            tx_id_hex: "00".repeat(32),
            output_idx: 0,
            height: 1,
        };
        let plan = StorageUploadPlanJson {
            inputs: vec![owned],
            anchor: RecipientJson {
                view_pub_hex: "00".repeat(32),
                spend_pub_hex: "00".repeat(32),
                value: 1,
            },
            replication: 3,
            fee: 1,
            ring_size: WALLET_MIN_RING_SIZE,
            current_height: 1,
            decoy_utxos: vec![],
            exclude_one_time_addrs_hex: vec![],
            fee_to_treasury_bps: 9000,
            change_recipients: vec![],
            extra_hex: String::new(),
            message_hex: String::new(),
            endowment: EndowmentPlanJson::default(),
            chunk_size: None,
        };
        let plan_str = serde_json::to_string(&plan).expect("plan json");
        let seed = [0u8; 32];
        let err = build_storage_upload_json(&seed, b"x", &plan_str).expect_err("must reject");
        let msg = err.to_string();
        assert!(
            msg.contains("input count") && msg.contains("F7") && msg.contains("faucet dual-send"),
            "unexpected: {msg}"
        );
    }
}
