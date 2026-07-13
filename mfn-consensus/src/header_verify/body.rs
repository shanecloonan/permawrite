//! Stateless block body root verification.

#![allow(unused_imports)]

use super::internal::*;

/* ----------------------------------------------------------------------- *
 *  Body verification (M2.0.7)                                              *
 * ----------------------------------------------------------------------- */

/// Failure modes of [`verify_block_body`]. Each variant carries the
/// header's claimed root (`expected`) and the root the verifier
/// computed from the delivered body (`got`) so callers can log a
/// useful diagnostic.
#[derive(Clone, Debug, thiserror::Error, PartialEq, Eq)]
pub enum BodyVerifyError {
    /// `header.tx_root` doesn't equal `tx_merkle_root(&block.txs)`.
    /// The delivered txs are not the txs the header was signed over.
    #[error("tx_root mismatch")]
    TxRootMismatch {
        /// Root the header claims (the value the producer BLS-signed
        /// over via `header_signing_hash`).
        expected: [u8; 32],
        /// Root the verifier computed from `block.txs`.
        got: [u8; 32],
    },

    /// `header.bond_root` doesn't equal `bond_merkle_root(&block.bond_ops)`.
    #[error("bond_root mismatch")]
    BondRootMismatch {
        /// Root the header claims.
        expected: [u8; 32],
        /// Root the verifier computed from `block.bond_ops`.
        got: [u8; 32],
    },

    /// `header.slashing_root` doesn't equal `slashing_merkle_root(&block.slashings)`.
    /// (Leaves are canonicalized per M2.0.1, so pair-swap inside an
    /// evidence pair is a no-op — but a different set of evidences,
    /// or a different number, moves the root.)
    #[error("slashing_root mismatch")]
    SlashingRootMismatch {
        /// Root the header claims.
        expected: [u8; 32],
        /// Root the verifier computed from `block.slashings`.
        got: [u8; 32],
    },

    /// `header.storage_proof_root` doesn't equal
    /// `storage_proof_merkle_root(&block.storage_proofs)`.
    /// (Order is producer-emit; see M2.0.2.)
    #[error("storage_proof_root mismatch")]
    StorageProofRootMismatch {
        /// Root the header claims.
        expected: [u8; 32],
        /// Root the verifier computed from `block.storage_proofs`.
        got: [u8; 32],
    },

    /// `header.claims_root` didn't match the Merkle root over verified
    /// authorship claim leaves (M2.2.x).
    #[error("claims_root mismatch")]
    ClaimsRootMismatch {
        /// Root the header claims.
        expected: [u8; 32],
        /// Root the verifier computed from `block.txs` extras.
        got: [u8; 32],
    },

    /// Malformed `MFEX` / `MFCL` or an invalid claim signature in some tx.
    #[error("authorship claims body invalid: {0}")]
    AuthorshipClaimsBody(String),
}

/// Verify that a delivered [`Block`] body matches the five
/// header-bound body roots that are pure functions of the block body
/// alone:
///
/// - [`BlockHeader::tx_root`] == `tx_merkle_root(&block.txs)`
/// - [`BlockHeader::bond_root`] == `bond_merkle_root(&block.bond_ops)`
/// - [`BlockHeader::slashing_root`] == `slashing_merkle_root(&block.slashings)`
/// - [`BlockHeader::storage_proof_root`] == `storage_proof_merkle_root(&block.storage_proofs)`
/// - [`BlockHeader::claims_root`] == Merkle root over verified authorship
///   claim leaves in block order (non-coinbase txs; see M2.2.x)
///
/// Combined with [`verify_header`] — which verifies that
/// `header_signing_hash` was BLS-signed by a quorum of the trusted
/// validator set, and `header_signing_hash` binds all five of these
/// roots — this gives a light client cryptographic confidence that
/// the delivered body is **the** body the producer signed over. A
/// malicious peer cannot deliver a tampered body without one of
/// these checks rejecting.
///
/// ## What this function does *not* verify
///
/// - [`BlockHeader::storage_root`] — depends on cross-block dedup
///   against the chain's `storage` map. Stateless verification of
///   this root has a false-positive rate when blocks contain
///   re-anchoring txs (which `apply_block` silently filters out).
///   A future light-client slice that maintains a `storage` shadow
///   set could add this check.
/// - [`BlockHeader::utxo_root`] — depends on the cumulative UTXO
///   accumulator. Same reasoning: requires state.
/// - [`BlockHeader::validator_root`] — already verified via the
///   trust anchor in [`verify_header`].
///
/// Both state-dependent roots are *already cryptographically bound*
/// through the BLS aggregate signing `header_signing_hash` (which
/// includes them). So even though a stateless verifier can't
/// independently recompute them, a forged block can't smuggle them
/// past [`verify_header`].
///
/// ## Determinism
///
/// Pure function. No IO, no allocation beyond what the underlying
/// `*_merkle_root` helpers require. Calling this with the same
/// `&Block` returns byte-for-byte the same result.
///
/// # Errors
///
/// See variants of [`BodyVerifyError`].
pub fn verify_block_body(block: &Block) -> Result<(), BodyVerifyError> {
    let tx_root = tx_merkle_root(&block.txs);
    if tx_root != block.header.tx_root {
        return Err(BodyVerifyError::TxRootMismatch {
            expected: block.header.tx_root,
            got: tx_root,
        });
    }

    let bond_root = bond_section_merkle_root(&block.bond_ops, &block.storage_operator_ops);
    if bond_root != block.header.bond_root {
        return Err(BodyVerifyError::BondRootMismatch {
            expected: block.header.bond_root,
            got: bond_root,
        });
    }

    let slashing_root = slashing_merkle_root_for_version(&block.slashings, block.header.version);
    if slashing_root != block.header.slashing_root {
        return Err(BodyVerifyError::SlashingRootMismatch {
            expected: block.header.slashing_root,
            got: slashing_root,
        });
    }

    let storage_proof_root = storage_proof_merkle_root(&block.storage_proofs);
    if storage_proof_root != block.header.storage_proof_root {
        return Err(BodyVerifyError::StorageProofRootMismatch {
            expected: block.header.storage_proof_root,
            got: storage_proof_root,
        });
    }

    let claim_leaves = collect_claim_merkle_leaves_for_txs(&block.txs, block.header.height)
        .map_err(|e| BodyVerifyError::AuthorshipClaimsBody(e.to_string()))?;
    let claims_root = claims_merkle_root(&claim_leaves);
    if claims_root != block.header.claims_root {
        return Err(BodyVerifyError::ClaimsRootMismatch {
            expected: block.header.claims_root,
            got: claims_root,
        });
    }

    Ok(())
}

/* ----------------------------------------------------------------------- *
 *  Unit tests                                                              *
 * ----------------------------------------------------------------------- */
