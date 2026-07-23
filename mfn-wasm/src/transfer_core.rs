//! CLSAG transfer construction for browser wallets (**M4.3**).

use std::collections::HashSet;

use curve25519_dalek::edwards::EdwardsPoint;
use mfn_consensus::{encode_transaction, tx_id, Recipient};
use mfn_crypto::point::point_from_bytes;
use mfn_wallet::production_tx_rng;
use mfn_wallet::{
    build_decoy_pool_from_sources, build_transfer, StoredOwnedOutput, TransferPlan,
    TransferRecipient, UtxoDecoySource, WALLET_MIN_RING_SIZE, WALLET_MIN_TX_INPUTS,
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
struct TransferPlanJson {
    inputs: Vec<StoredOwnedOutput>,
    recipients: Vec<RecipientJson>,
    fee: u64,
    ring_size: usize,
    current_height: u64,
    decoy_utxos: Vec<UtxoJson>,
    #[serde(default)]
    exclude_one_time_addrs_hex: Vec<String>,
    #[serde(default)]
    extra_hex: String,
}

#[derive(Serialize)]
struct TransferResultJson {
    tx_hex: String,
    tx_id: String,
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

/// Build a sorted decoy-pool JSON preview from public UTXO rows.
pub fn decoy_pool_preview_json(
    decoy_utxos_json: &str,
    exclude_addrs_hex: &[String],
) -> Result<String, WasmCoreError> {
    let rows: Vec<UtxoJson> = serde_json::from_str(decoy_utxos_json)
        .map_err(|e| WasmCoreError::InvalidHex(format!("decoy_utxos json: {e}")))?;
    let sources = utxos_from_json(&rows)?;
    let excludes = parse_exclude_addrs(exclude_addrs_hex)?;
    let pool = build_decoy_pool_from_sources(&sources, excludes);
    #[derive(Serialize)]
    struct Entry {
        height: u64,
        one_time_addr_hex: String,
        commit_hex: String,
    }
    let out: Vec<Entry> = pool
        .iter()
        .map(|c| Entry {
            height: c.height,
            one_time_addr_hex: hex::encode(c.data.0.compress().to_bytes()),
            commit_hex: hex::encode(c.data.1.compress().to_bytes()),
        })
        .collect();
    serde_json::to_string(&out).map_err(|e| WasmCoreError::InvalidHex(e.to_string()))
}

/// Sign a CLSAG transfer from a JSON plan (see [`TransferPlanJson`]).
pub fn build_transfer_json(plan_json: &str) -> Result<String, WasmCoreError> {
    let plan: TransferPlanJson = serde_json::from_str(plan_json)
        .map_err(|e| WasmCoreError::InvalidHex(format!("transfer plan json: {e}")))?;
    if plan.ring_size < WALLET_MIN_RING_SIZE {
        // B-217: parity with CLI refuse text (wallet/consensus floor).
        return Err(WasmCoreError::InvalidHex(format!(
            "ring size {} below wallet/consensus floor {WALLET_MIN_RING_SIZE}",
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

    let mut inputs = Vec::with_capacity(plan.inputs.len());
    for stored in &plan.inputs {
        inputs.push(
            stored
                .to_owned()
                .map_err(|e| WasmCoreError::InvalidHex(e.to_string()))?,
        );
    }
    let input_refs: Vec<_> = inputs.iter().collect();

    let mut recipients = Vec::with_capacity(plan.recipients.len());
    for r in &plan.recipients {
        recipients.push(TransferRecipient {
            recipient: Recipient {
                view_pub: parse_point32(&r.view_pub_hex, "view_pub")?,
                spend_pub: parse_point32(&r.spend_pub_hex, "spend_pub")?,
            },
            value: r.value,
        });
    }

    let sources = utxos_from_json(&plan.decoy_utxos)?;
    let excludes = parse_exclude_addrs(&plan.exclude_one_time_addrs_hex)?;
    let decoy_pool = build_decoy_pool_from_sources(&sources, excludes);

    let extra = decode_extra_hex(&plan.extra_hex)?;

    let mut rng = production_tx_rng;
    let transfer = TransferPlan {
        inputs: &input_refs,
        recipients: &recipients,
        fee: plan.fee,
        extra: &extra,
        ring_size: plan.ring_size,
        decoy_pool: &decoy_pool,
        current_height: plan.current_height,
        rng: &mut rng,
    };
    let signed = build_transfer(transfer).map_err(|e| WasmCoreError::InvalidHex(e.to_string()))?;
    let id = tx_id(&signed.tx);
    let json = TransferResultJson {
        tx_hex: hex::encode(encode_transaction(&signed.tx)),
        tx_id: hex::encode(id),
    };
    serde_json::to_string(&json).map_err(|e| WasmCoreError::InvalidHex(e.to_string()))
}

#[cfg(all(test, feature = "wasm-full"))]
mod tests {
    use curve25519_dalek::scalar::Scalar;
    use mfn_consensus::{sign_transaction, InputSpec, OutputSpec, Recipient};
    use mfn_crypto::clsag::ClsagRing;
    use mfn_crypto::point::{generator_g, generator_h};
    use mfn_crypto::scalar::random_scalar;
    use mfn_wallet::{scan_transaction, wallet_from_seed, StoredOwnedOutput};

    use super::*;

    fn fake_input(value: u64, ring_size: usize) -> InputSpec {
        let signer_idx = ring_size / 2;
        let mut p = Vec::with_capacity(ring_size);
        let mut c = Vec::with_capacity(ring_size);
        let signer_spend = random_scalar();
        let signer_blinding = random_scalar();
        let signer_p = generator_g() * signer_spend;
        let signer_c = (generator_g() * signer_blinding) + (generator_h() * Scalar::from(value));
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

    #[test]
    fn build_transfer_json_round_trip() {
        const SEED: [u8; 32] = [0x42u8; 32];
        let me = wallet_from_seed(&SEED);
        let recipient = Recipient {
            view_pub: me.view_pub(),
            spend_pub: me.spend_pub(),
        };
        let signed = sign_transaction(
            vec![fake_input(1_000_000, 16)],
            vec![OutputSpec::ToRecipient {
                recipient,
                value: 999_000,
                storage: None,
            }],
            1_000,
            Vec::new(),
        )
        .expect("sign");
        let scan = scan_transaction(&signed.tx, 7, &me, &HashSet::new());
        assert_eq!(scan.recovered.len(), 1);
        let owned_a = StoredOwnedOutput::from_owned(&scan.recovered[0]);
        let signed_b = sign_transaction(
            vec![fake_input(500_000 + 1_000, 16)],
            vec![OutputSpec::ToRecipient {
                recipient,
                value: 500_000,
                storage: None,
            }],
            1_000,
            Vec::new(),
        )
        .expect("sign b");
        let scan_b = scan_transaction(&signed_b.tx, 7, &me, &HashSet::new());
        assert_eq!(scan_b.recovered.len(), 1);
        let owned_b = StoredOwnedOutput::from_owned(&scan_b.recovered[0]);

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

        let plan = TransferPlanJson {
            inputs: vec![owned_a, owned_b],
            recipients: vec![RecipientJson {
                view_pub_hex: hex::encode(me.view_pub().compress().to_bytes()),
                spend_pub_hex: hex::encode(me.spend_pub().compress().to_bytes()),
                value: 1_498_000,
            }],
            fee: 1_000,
            ring_size: WALLET_MIN_RING_SIZE,
            current_height: 7,
            decoy_utxos,
            exclude_one_time_addrs_hex: vec![],
            extra_hex: String::new(),
        };
        let plan_str = serde_json::to_string(&plan).expect("plan json");
        let out = build_transfer_json(&plan_str).expect("build");
        assert!(out.contains("tx_hex"));
        assert!(out.contains("tx_id"));
    }

    /// B-167: WASM boundary refuses sub-floor rings with an honest error
    /// (not a decoy-pool or hex decode mislabel).
    #[test]
    fn build_transfer_json_rejects_ring_below_minimum() {
        let plan = TransferPlanJson {
            inputs: vec![],
            recipients: vec![RecipientJson {
                view_pub_hex: "00".repeat(32),
                spend_pub_hex: "00".repeat(32),
                value: 1,
            }],
            fee: 1,
            ring_size: WALLET_MIN_RING_SIZE - 1,
            current_height: 1,
            decoy_utxos: vec![],
            exclude_one_time_addrs_hex: vec![],
            extra_hex: String::new(),
        };
        let plan_str = serde_json::to_string(&plan).expect("plan json");
        let err = build_transfer_json(&plan_str).expect_err("must reject");
        let msg = err.to_string();
        assert!(
            msg.contains("wallet/consensus floor"),
            "unexpected error: {msg}"
        );
        assert!(
            msg.contains(&(WALLET_MIN_RING_SIZE - 1).to_string()),
            "unexpected error: {msg}"
        );
    }

    /// B-168: WASM JSON builders fail closed on one-input plans (F7 floor).
    #[test]
    fn build_transfer_json_rejects_single_input() {
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
        let plan = TransferPlanJson {
            inputs: vec![owned],
            recipients: vec![RecipientJson {
                view_pub_hex: "00".repeat(32),
                spend_pub_hex: "00".repeat(32),
                value: 1,
            }],
            fee: 1,
            ring_size: WALLET_MIN_RING_SIZE,
            current_height: 1,
            decoy_utxos: vec![],
            exclude_one_time_addrs_hex: vec![],
            extra_hex: String::new(),
        };
        let plan_str = serde_json::to_string(&plan).expect("plan json");
        let err = build_transfer_json(&plan_str).expect_err("must reject");
        let msg = err.to_string();
        assert!(
            msg.contains("input count") && msg.contains("F7") && msg.contains("faucet dual-send"),
            "unexpected error: {msg}"
        );
    }
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
