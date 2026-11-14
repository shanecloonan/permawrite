//! B-318. Local phase-4c witness envelope. Not a header field and not gossip.
//!
//! The bytes are `MFVW`, version 1, then a JSON object of the claimed outputs
//! and the Plonky3 proof. A blob bigger than one mebibyte is refused before
//! parsing. Checking the bytes runs [`verify_aggregated_outputs`] and does
//! not divide the fee or hash the path.

use serde::{Deserialize, Serialize};

use crate::validity_stark_plonky3::{
    verify_aggregated_outputs, AggregateError, AggregatedOutputs, AggregatedProof,
};

const MAGIC: &[u8] = b"MFVW";
const VERSION: u8 = 1;
/// One mebibyte. A larger blob is refused before JSON parsing.
pub const MAX_WITNESS_BYTES: usize = 1 << 20;

#[derive(Serialize)]
struct Envelope<'a> {
    outputs: &'a AggregatedOutputs,
    proof: &'a AggregatedProof,
}

#[derive(Deserialize)]
struct OwnedEnvelope {
    outputs: AggregatedOutputs,
    proof: AggregatedProof,
}

/// Encode a proof and the outputs it was checked against.
pub fn encode_aggregated_witness(
    outputs: &AggregatedOutputs,
    proof: &AggregatedProof,
) -> Result<Vec<u8>, AggregateError> {
    let body = serde_json::to_vec(&Envelope { outputs, proof })
        .map_err(|_| AggregateError::WitnessMalformed)?;
    let total = MAGIC.len() + 1 + body.len();
    if total > MAX_WITNESS_BYTES {
        return Err(AggregateError::WitnessTooLarge);
    }
    let mut bytes = Vec::with_capacity(total);
    bytes.extend_from_slice(MAGIC);
    bytes.push(VERSION);
    bytes.extend_from_slice(&body);
    Ok(bytes)
}

/// Check a witness envelope. Returns the outputs the proof carries.
pub fn verify_aggregated_witness(bytes: &[u8]) -> Result<AggregatedOutputs, AggregateError> {
    if bytes.len() > MAX_WITNESS_BYTES {
        return Err(AggregateError::WitnessTooLarge);
    }
    if bytes.len() < MAGIC.len() + 1 || &bytes[..MAGIC.len()] != MAGIC {
        return Err(AggregateError::WitnessMalformed);
    }
    if bytes[MAGIC.len()] != VERSION {
        return Err(AggregateError::WitnessVersion);
    }
    let owned: OwnedEnvelope = serde_json::from_slice(&bytes[MAGIC.len() + 1..])
        .map_err(|_| AggregateError::WitnessMalformed)?;
    verify_aggregated_outputs(&owned.outputs, &owned.proof)?;
    Ok(owned.outputs)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::validity_stark_plonky3::{babybear_merkle_root, prove_aggregated, AggregatedClaim};

    fn claim() -> AggregatedClaim {
        AggregatedClaim {
            fee_sum: 2_000,
            fee_to_treasury_bps: 2_500,
            treasury_fee: 500,
            producer_fee: 1_500,
            leaves_a: vec![11, 12, 13],
            index_a: 0,
            leaves_b: vec![21, 22, 23, 24],
            index_b: 3,
            tx_count: 2,
            spora_count: 1,
            parent_digest: [9, 8, 7, 6],
        }
    }

    fn outputs_of(claim: &AggregatedClaim) -> AggregatedOutputs {
        let product = u128::from(claim.fee_sum) * u128::from(claim.fee_to_treasury_bps);
        AggregatedOutputs {
            fee_sum: claim.fee_sum,
            fee_to_treasury_bps: claim.fee_to_treasury_bps,
            treasury_fee: claim.treasury_fee,
            producer_fee: claim.producer_fee,
            remainder: u32::try_from(product % 10_000).unwrap(),
            leaf_a: claim.leaves_a[claim.index_a as usize],
            root_a: babybear_merkle_root(&claim.leaves_a).unwrap(),
            index_a: claim.index_a,
            leaf_b: claim.leaves_b[claim.index_b as usize],
            root_b: babybear_merkle_root(&claim.leaves_b).unwrap(),
            index_b: claim.index_b,
            tx_count: claim.tx_count,
            spora_count: claim.spora_count,
            parent_digest: claim.parent_digest,
        }
    }

    #[test]
    fn b318_witness_envelope_roundtrips_and_rejects_bad_bytes() {
        let claim = claim();
        let proof = prove_aggregated(&claim).unwrap();
        let outputs = outputs_of(&claim);
        let bytes = encode_aggregated_witness(&outputs, &proof).unwrap();
        assert_eq!(verify_aggregated_witness(&bytes).unwrap(), outputs);

        assert_eq!(
            verify_aggregated_witness(b"nope"),
            Err(AggregateError::WitnessMalformed)
        );
        let mut wrong_version = bytes.clone();
        wrong_version[4] = 9;
        assert_eq!(
            verify_aggregated_witness(&wrong_version),
            Err(AggregateError::WitnessVersion)
        );
        let mut truncated = bytes;
        truncated.truncate(8);
        assert_eq!(
            verify_aggregated_witness(&truncated),
            Err(AggregateError::WitnessMalformed)
        );
    }

    #[test]
    fn b321_witness_over_one_mebibyte_is_refused() {
        let mut huge = vec![0u8; MAX_WITNESS_BYTES + 1];
        huge[..4].copy_from_slice(b"MFVW");
        huge[4] = 1;
        assert_eq!(
            verify_aggregated_witness(&huge),
            Err(AggregateError::WitnessTooLarge)
        );
        let at_cap = vec![0u8; MAX_WITNESS_BYTES];
        at_cap_is_malformed_not_too_large(&at_cap);
    }

    fn at_cap_is_malformed_not_too_large(bytes: &[u8]) {
        assert_eq!(bytes.len(), MAX_WITNESS_BYTES);
        assert_eq!(
            verify_aggregated_witness(bytes),
            Err(AggregateError::WitnessMalformed)
        );
    }
}
