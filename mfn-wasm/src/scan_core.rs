//! Block / transaction scanning for browser wallets (**M4.2**).

use std::collections::HashSet;

use mfn_consensus::{decode_block, decode_transaction, BlockDecodeError, TxDecodeError};
use mfn_wallet::{scan_block, scan_transaction, wallet_from_seed, BlockScan, TxScan, WalletKeys};
use serde::Serialize;

use crate::core::WasmCoreError;

/// JSON view of a recovered output (no secret spend scalars).
#[derive(Serialize)]
struct RecoveredOutputJson {
    tx_id: String,
    output_idx: u32,
    height: u32,
    value: u64,
    key_image: String,
    one_time_addr: String,
    commit: String,
}

#[derive(Serialize)]
struct TxScanJson {
    tx_id: String,
    recovered: Vec<RecoveredOutputJson>,
    spent_key_images: Vec<String>,
}

#[derive(Serialize)]
struct BlockScanJson {
    height: u32,
    txs: Vec<TxScanJson>,
    gross_received: u64,
    matched_spent: usize,
}

fn parse_key_images_hex(lines: &[String]) -> Result<HashSet<[u8; 32]>, WasmCoreError> {
    let mut set = HashSet::new();
    for line in lines {
        let t = line.trim();
        if t.is_empty() {
            continue;
        }
        let h = t
            .strip_prefix("0x")
            .or_else(|| t.strip_prefix("0X"))
            .unwrap_or(t);
        if h.len() != 64 {
            return Err(WasmCoreError::InvalidHex(format!(
                "key image must be 64 hex chars (got {})",
                h.len()
            )));
        }
        let mut ki = [0u8; 32];
        hex::decode_to_slice(h, &mut ki).map_err(|e| WasmCoreError::InvalidHex(e.to_string()))?;
        set.insert(ki);
    }
    Ok(set)
}

fn tx_scan_to_json(tx_id: [u8; 32], scan: &TxScan) -> TxScanJson {
    TxScanJson {
        tx_id: hex::encode(tx_id),
        recovered: scan
            .recovered
            .iter()
            .map(|o| RecoveredOutputJson {
                tx_id: hex::encode(o.tx_id),
                output_idx: o.output_idx,
                height: o.height,
                value: o.value,
                key_image: hex::encode(o.key_image.compress().to_bytes()),
                one_time_addr: hex::encode(o.one_time_addr.compress().to_bytes()),
                commit: hex::encode(o.commit.compress().to_bytes()),
            })
            .collect(),
        spent_key_images: scan.spent_key_images.iter().map(hex::encode).collect(),
    }
}

fn keys_from_seed(seed: &[u8; 32]) -> WalletKeys {
    wallet_from_seed(seed)
}

/// Scan a wire-encoded transaction for outputs owned by `seed`.
pub fn scan_transaction_hex_json(
    seed: &[u8; 32],
    tx_hex: &str,
    height: u32,
    owned_key_images_hex: &[String],
) -> Result<String, WasmCoreError> {
    let tx_bytes = decode_hex_payload(tx_hex)?;
    let tx = decode_transaction(&tx_bytes)
        .map_err(|e: TxDecodeError| WasmCoreError::InvalidHex(e.to_string()))?;
    let keys = keys_from_seed(seed);
    let owned = parse_key_images_hex(owned_key_images_hex)?;
    let scan = scan_transaction(&tx, height, &keys, &owned);
    let tx_id = mfn_consensus::tx_id(&tx);
    let json = tx_scan_to_json(tx_id, &scan);
    serde_json::to_string(&json).map_err(|e| WasmCoreError::InvalidHex(e.to_string()))
}

/// Scan a wire-encoded block; height is taken from the block header.
pub fn scan_block_hex_json(
    seed: &[u8; 32],
    block_hex: &str,
    owned_key_images_hex: &[String],
) -> Result<String, WasmCoreError> {
    let block_bytes = decode_hex_payload(block_hex)?;
    let block = decode_block(&block_bytes)
        .map_err(|e: BlockDecodeError| WasmCoreError::InvalidHex(e.to_string()))?;
    let height = block.header.height;
    let keys = keys_from_seed(seed);
    let owned = parse_key_images_hex(owned_key_images_hex)?;
    let scan = scan_block(&block, &keys, &owned);
    let json = block_scan_to_json(height, &scan);
    serde_json::to_string(&json).map_err(|e| WasmCoreError::InvalidHex(e.to_string()))
}

fn block_scan_to_json(height: u32, scan: &BlockScan) -> BlockScanJson {
    BlockScanJson {
        height,
        txs: scan
            .txs
            .iter()
            .map(|(tx_id, ts)| tx_scan_to_json(*tx_id, ts))
            .collect(),
        gross_received: scan.gross_received,
        matched_spent: scan.matched_spent,
    }
}

fn decode_hex_payload(hex_str: &str) -> Result<Vec<u8>, WasmCoreError> {
    let t = hex_str
        .trim()
        .strip_prefix("0x")
        .or_else(|| hex_str.trim().strip_prefix("0X"))
        .unwrap_or(hex_str.trim());
    hex::decode(t).map_err(|e| WasmCoreError::InvalidHex(e.to_string()))
}

#[cfg(all(test, feature = "wasm-full"))]
mod tests {
    use std::collections::HashSet;

    use mfn_consensus::{sign_transaction, InputSpec, OutputSpec, Recipient};
    use mfn_crypto::clsag::ClsagRing;
    use mfn_crypto::point::{generator_g, generator_h};
    use mfn_crypto::scalar::random_scalar;
    use mfn_wallet::{scan_transaction, wallet_from_seed};

    use super::*;
    use crate::core::parse_seed_hex;

    fn fake_input(value: u64, ring_size: usize) -> InputSpec {
        let signer_idx = ring_size / 2;
        let mut p = Vec::with_capacity(ring_size);
        let mut c = Vec::with_capacity(ring_size);
        let signer_spend = random_scalar();
        let signer_blinding = random_scalar();
        let signer_p = generator_g() * signer_spend;
        let signer_c = (generator_g() * signer_blinding)
            + (generator_h() * curve25519_dalek::scalar::Scalar::from(value));
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
    fn wasm_scan_transaction_hex_recovers_payment() {
        const SEED: [u8; 32] = [0x42u8; 32];
        let me = wallet_from_seed(&SEED);
        let recipient = Recipient {
            view_pub: me.view_pub(),
            spend_pub: me.spend_pub(),
        };
        let signed = sign_transaction(
            vec![fake_input(1_000_000, 4)],
            vec![OutputSpec::ToRecipient {
                recipient,
                value: 999_000,
                storage: None,
            }],
            1_000,
            Vec::new(),
        )
        .expect("sign");
        let tx_hex = hex::encode(mfn_consensus::encode_transaction(&signed.tx));
        let json = scan_transaction_hex_json(&SEED, &tx_hex, 7, &[]).expect("scan");
        assert!(json.contains("\"value\":999000"));
        assert!(json.contains("\"height\":7"));

        let direct = scan_transaction(&signed.tx, 7, &me, &HashSet::new());
        assert_eq!(direct.recovered.len(), 1);
        assert_eq!(direct.recovered[0].value, 999_000);
    }

    #[test]
    fn parse_seed_and_key_images_round_trip() {
        let seed = parse_seed_hex(&format!("0x{}", hex::encode([0x11u8; 32]))).unwrap();
        let imgs = vec!["00".repeat(32)];
        let set = parse_key_images_hex(&imgs).unwrap();
        assert_eq!(set.len(), 1);
        let _ = keys_from_seed(&seed);
    }
}
