//! BLS header verification for browser light clients (**M4.10**).

use curve25519_dalek::edwards::CompressedEdwardsY;
use mfn_bls::decode_public_key;
use mfn_consensus::{
    block_id, decode_block_header, verify_header, BlockHeader, ConsensusParams, HeaderCheck,
    HeaderVerifyError, Validator, ValidatorPayout, DEFAULT_CONSENSUS_PARAMS,
};
use serde::{Deserialize, Serialize};

use crate::core::WasmCoreError;

#[derive(Serialize)]
struct HeaderVerifyOk {
    ok: bool,
    block_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    check: Option<HeaderCheckJson>,
}

#[derive(Serialize)]
struct HeaderVerifyErr {
    ok: bool,
    error: String,
}

#[derive(Serialize)]
struct HeaderCheckJson {
    producer_index: u32,
    signing_stake: u64,
    total_stake: u64,
    quorum_required: u64,
    validator_count: usize,
}

#[derive(Deserialize)]
struct ValidatorJson {
    index: u32,
    stake: u64,
    vrf_pk_hex: String,
    bls_pk_hex: String,
    payout: Option<PayoutJson>,
}

#[derive(Deserialize)]
struct PayoutJson {
    view_pub_hex: String,
    spend_pub_hex: String,
}

#[derive(Deserialize)]
struct ConsensusParamsJson {
    expected_proposers_per_slot: f64,
    quorum_stake_bps: u32,
    liveness_max_consecutive_missed: u32,
    liveness_slash_bps: u32,
    #[serde(default)]
    min_ring_size: Option<u32>,
    #[serde(default)]
    uniform_ring_size: Option<u32>,
}

fn decode_hex32(s: &str, label: &str) -> Result<[u8; 32], WasmCoreError> {
    let t = s
        .trim()
        .strip_prefix("0x")
        .or_else(|| s.trim().strip_prefix("0X"))
        .unwrap_or(s.trim());
    if t.len() != 64 {
        return Err(WasmCoreError::InvalidHex(format!(
            "{label} must be 64 hex chars (got {})",
            t.len()
        )));
    }
    let mut out = [0u8; 32];
    hex::decode_to_slice(t, &mut out).map_err(|e| WasmCoreError::InvalidHex(e.to_string()))?;
    Ok(out)
}

fn decode_hex48(s: &str, label: &str) -> Result<[u8; 48], WasmCoreError> {
    let t = s
        .trim()
        .strip_prefix("0x")
        .or_else(|| s.trim().strip_prefix("0X"))
        .unwrap_or(s.trim());
    if t.len() != 96 {
        return Err(WasmCoreError::InvalidHex(format!(
            "{label} must be 96 hex chars (got {})",
            t.len()
        )));
    }
    let bytes = hex::decode(t).map_err(|e| WasmCoreError::InvalidHex(e.to_string()))?;
    let mut out = [0u8; 48];
    out.copy_from_slice(&bytes);
    Ok(out)
}

fn parse_point32(
    bytes: [u8; 32],
    label: &str,
) -> Result<curve25519_dalek::EdwardsPoint, WasmCoreError> {
    CompressedEdwardsY(bytes)
        .decompress()
        .ok_or_else(|| WasmCoreError::InvalidHex(format!("invalid {label} Edwards point")))
}

pub(crate) fn validators_from_json(json: &str) -> Result<Vec<Validator>, WasmCoreError> {
    let rows: Vec<ValidatorJson> =
        serde_json::from_str(json).map_err(|e| WasmCoreError::InvalidHex(e.to_string()))?;
    let mut out = Vec::with_capacity(rows.len());
    for row in rows {
        let vrf_bytes = decode_hex32(&row.vrf_pk_hex, "vrf_pk_hex")?;
        let bls_bytes = decode_hex48(&row.bls_pk_hex, "bls_pk_hex")?;
        let vrf_pk = parse_point32(vrf_bytes, "vrf_pk")?;
        let bls_pk = decode_public_key(&bls_bytes)
            .map_err(|e| WasmCoreError::InvalidHex(format!("bls_pk: {e}")))?;
        let payout = match row.payout {
            None => None,
            Some(p) => {
                let view =
                    parse_point32(decode_hex32(&p.view_pub_hex, "view_pub_hex")?, "view_pub")?;
                let spend = parse_point32(
                    decode_hex32(&p.spend_pub_hex, "spend_pub_hex")?,
                    "spend_pub",
                )?;
                Some(ValidatorPayout {
                    view_pub: view,
                    spend_pub: spend,
                })
            }
        };
        out.push(Validator {
            index: row.index,
            vrf_pk,
            bls_pk,
            stake: row.stake,
            payout,
        });
    }
    Ok(out)
}

pub(crate) fn consensus_from_json(json: &str) -> Result<ConsensusParams, WasmCoreError> {
    let p: ConsensusParamsJson =
        serde_json::from_str(json).map_err(|e| WasmCoreError::InvalidHex(e.to_string()))?;
    Ok(ConsensusParams {
        expected_proposers_per_slot: p.expected_proposers_per_slot,
        quorum_stake_bps: p.quorum_stake_bps,
        liveness_max_consecutive_missed: p.liveness_max_consecutive_missed,
        liveness_slash_bps: p.liveness_slash_bps,
        min_ring_size: p
            .min_ring_size
            .unwrap_or(DEFAULT_CONSENSUS_PARAMS.min_ring_size),
        uniform_ring_size: p
            .uniform_ring_size
            .unwrap_or(DEFAULT_CONSENSUS_PARAMS.uniform_ring_size),
    })
}

fn header_from_hex(header_hex: &str) -> Result<BlockHeader, WasmCoreError> {
    let t = header_hex
        .trim()
        .strip_prefix("0x")
        .or_else(|| header_hex.trim().strip_prefix("0X"))
        .unwrap_or(header_hex.trim());
    let bytes = hex::decode(t).map_err(|e| WasmCoreError::InvalidHex(e.to_string()))?;
    decode_block_header(&bytes).map_err(|e| WasmCoreError::InvalidHex(e.to_string()))
}

fn check_to_json(c: &HeaderCheck) -> HeaderCheckJson {
    HeaderCheckJson {
        producer_index: c.producer_index,
        signing_stake: c.signing_stake,
        total_stake: c.total_stake,
        quorum_required: c.quorum_required,
        validator_count: c.validator_count,
    }
}

fn header_error_message(e: HeaderVerifyError) -> String {
    match e {
        HeaderVerifyError::ValidatorRootMismatch => {
            "validator_root mismatch (trusted set does not match header)".into()
        }
        HeaderVerifyError::GenesisHeader => {
            "genesis header cannot be BLS-verified (bootstrap from genesis config)".into()
        }
        HeaderVerifyError::ProducerProofDecode(s) => format!("producer_proof decode: {s}"),
        HeaderVerifyError::FinalityRejected(c) => format!("finality rejected: {c:?}"),
        HeaderVerifyError::EmptyTrustedSet => "trusted validator set is empty".into(),
    }
}

/// Recompute `block_id` from wire header bytes (independent of RPC `block_id` field).
pub fn block_id_from_header_hex_json(header_hex: &str) -> Result<String, WasmCoreError> {
    let header = header_from_hex(header_hex)?;
    Ok(hex::encode(block_id(&header)))
}

/// Verify BLS finality on a header against a trusted validator set + consensus params.
pub fn verify_header_hex_json(
    header_hex: &str,
    validators_json: &str,
    consensus_json: &str,
) -> Result<String, WasmCoreError> {
    let header = header_from_hex(header_hex)?;
    let bid = hex::encode(block_id(&header));
    let validators = validators_from_json(validators_json)?;
    let params = consensus_from_json(consensus_json)?;
    match verify_header(&header, &validators, &params) {
        Ok(check) => {
            let body = HeaderVerifyOk {
                ok: true,
                block_id: bid,
                check: Some(check_to_json(&check)),
            };
            serde_json::to_string(&body).map_err(|e| WasmCoreError::InvalidHex(e.to_string()))
        }
        Err(e) => {
            let body = HeaderVerifyErr {
                ok: false,
                error: header_error_message(e),
            };
            serde_json::to_string(&body).map_err(|e| WasmCoreError::InvalidHex(e.to_string()))
        }
    }
}

#[cfg(all(test, feature = "wasm-full"))]
mod tests {
    use super::*;

    #[test]
    fn validators_json_round_trip_errors_on_empty() {
        assert!(validators_from_json("[]").is_ok());
        assert!(validators_from_json("not-json").is_err());
    }
}
