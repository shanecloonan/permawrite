//! Validity-proof V1 P2P tag reservation (**F5** phase 4a).
//!
//! Consensus verification lives in `mfn_consensus::validity_proof`. This module
//! reserves gossip tag `0x14` and frames consensus wire bytes.

/// Succinct validity-proof gossip tag (`0x14`, **F5** phase 4a).
pub const VALIDITY_PROOF_V1_TAG: u8 = 0x14;

/// Encoded [`mfn_consensus::validity_proof`] payload with leading tag.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValidityProofV1(pub Vec<u8>);

impl ValidityProofV1 {
    /// Tag + consensus `encode_validity_proof_v1` bytes.
    #[must_use]
    pub fn encode_payload(consensus_wire: &[u8]) -> Vec<u8> {
        let mut out = Vec::with_capacity(1 + consensus_wire.len());
        out.push(VALIDITY_PROOF_V1_TAG);
        out.extend_from_slice(consensus_wire);
        out
    }

    /// Decode tag + body; returns the consensus wire without the tag.
    pub fn decode_payload(payload: &[u8]) -> Result<Self, ValidityProofV1DecodeError> {
        if payload.is_empty() {
            return Err(ValidityProofV1DecodeError::TooShort);
        }
        if payload[0] != VALIDITY_PROOF_V1_TAG {
            return Err(ValidityProofV1DecodeError::UnknownTag(payload[0]));
        }
        Ok(Self(payload[1..].to_vec()))
    }
}

/// Failure decoding a [`ValidityProofV1`] frame.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ValidityProofV1DecodeError {
    /// Empty payload.
    #[error("validity proof frame too short")]
    TooShort,
    /// Wrong leading tag.
    #[error("unknown validity proof tag {0:#x}")]
    UnknownTag(u8),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tag_round_trip() {
        let body = vec![1, 2, 3, 4];
        let wire = ValidityProofV1::encode_payload(&body);
        assert_eq!(wire[0], VALIDITY_PROOF_V1_TAG);
        let decoded = ValidityProofV1::decode_payload(&wire).expect("decode");
        assert_eq!(decoded.0, body);
    }
}
