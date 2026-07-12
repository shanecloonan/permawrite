//! Fraud-proof V1 P2P tag reservation (**F5** phase 0).
//!
//! Consensus verification lives in `mfn_consensus::fraud_proof`. This module
//! only reserves the gossip tag and frames the consensus wire bytes so phase 1
//! can fan out challenges without renumbering the tag space.

/// Interactive fraud-proof gossip tag (`0x13`, **F5** phase 0).
pub const FRAUD_PROOF_V1_TAG: u8 = 0x13;

/// Encoded [`mfn_consensus::fraud_proof`] payload with leading tag.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FraudProofV1(pub Vec<u8>);

impl FraudProofV1 {
    /// Tag + consensus `encode_body_root_fraud_proof` bytes.
    #[must_use]
    pub fn encode_payload(consensus_wire: &[u8]) -> Vec<u8> {
        let mut out = Vec::with_capacity(1 + consensus_wire.len());
        out.push(FRAUD_PROOF_V1_TAG);
        out.extend_from_slice(consensus_wire);
        out
    }

    /// Decode tag + body; returns the consensus wire without the tag.
    pub fn decode_payload(payload: &[u8]) -> Result<Self, FraudProofV1DecodeError> {
        if payload.is_empty() {
            return Err(FraudProofV1DecodeError::TooShort);
        }
        if payload[0] != FRAUD_PROOF_V1_TAG {
            return Err(FraudProofV1DecodeError::UnknownTag(payload[0]));
        }
        Ok(Self(payload[1..].to_vec()))
    }
}

/// Failure decoding a [`FraudProofV1`] frame.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum FraudProofV1DecodeError {
    /// Empty payload.
    #[error("fraud proof frame too short")]
    TooShort,
    /// Wrong leading tag.
    #[error("unknown fraud proof tag {0:#x}")]
    UnknownTag(u8),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tag_round_trip() {
        let body = vec![1, 2, 3, 4];
        let wire = FraudProofV1::encode_payload(&body);
        assert_eq!(wire[0], FRAUD_PROOF_V1_TAG);
        let decoded = FraudProofV1::decode_payload(&wire).expect("decode");
        assert_eq!(decoded.0, body);
    }
}
