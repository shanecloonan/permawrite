//! STARK validity digest stub (**F5** phase 4b).

use mfn_crypto::dhash;
use mfn_crypto::domain::{VALIDITY_STARK_BATCH_V1, VALIDITY_STARK_STUB_PROOF};
use std::sync::OnceLock;
use thiserror::Error;

/// Expected `proof_bytes` length for the phase **4b** digest stub.
pub const STARK_DIGEST_STUB_PROOF_LEN: usize = 32;

/// Build the deterministic phase **4b** batch circuit digest.
#[must_use]
pub fn validity_stark_batch_v1_circuit_digest() -> [u8; 32] {
    static DIGEST: OnceLock<[u8; 32]> = OnceLock::new();
    *DIGEST.get_or_init(|| dhash(VALIDITY_STARK_BATCH_V1, &[b"tx+coinbase+spora-batch-v1"]))
}

/// Build deterministic stub proof bytes bound to parent checkpoint + block wire.
#[must_use]
pub fn stark_digest_stub_proof_bytes(
    parent_checkpoint: &[u8],
    block_wire: &[u8],
    circuit_digest: &[u8; 32],
) -> [u8; 32] {
    dhash(
        VALIDITY_STARK_STUB_PROOF,
        &[parent_checkpoint, block_wire, circuit_digest],
    )
}

/// STARK stub verification errors.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum StarkStubError {
    /// Wrong proof byte length.
    #[error("stark stub proof length {len} != {expected}")]
    InvalidProofLength {
        /// Actual length.
        len: usize,
        /// Expected length.
        expected: usize,
    },
    /// Circuit digest does not match the batch v1 id.
    #[error("stark stub circuit digest mismatch")]
    CircuitDigestMismatch,
    /// Proof digest does not match the witness binding.
    #[error("stark stub proof digest mismatch")]
    ProofDigestMismatch,
}

/// Verify stub proof bytes against witness binding, then defer to replay STF.
pub fn verify_stark_digest_stub(
    parent_checkpoint: &[u8],
    block_wire: &[u8],
    circuit_digest: &[u8; 32],
    proof_bytes: &[u8],
) -> Result<(), StarkStubError> {
    if proof_bytes.len() != STARK_DIGEST_STUB_PROOF_LEN {
        return Err(StarkStubError::InvalidProofLength {
            len: proof_bytes.len(),
            expected: STARK_DIGEST_STUB_PROOF_LEN,
        });
    }
    let expected_circuit = validity_stark_batch_v1_circuit_digest();
    if *circuit_digest != expected_circuit {
        return Err(StarkStubError::CircuitDigestMismatch);
    }
    let expected = stark_digest_stub_proof_bytes(parent_checkpoint, block_wire, circuit_digest);
    if proof_bytes != expected {
        return Err(StarkStubError::ProofDigestMismatch);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn circuit_digest_is_stable() {
        assert_eq!(
            validity_stark_batch_v1_circuit_digest(),
            validity_stark_batch_v1_circuit_digest()
        );
    }
}
