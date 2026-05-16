//! Authorship claims indexed in [`crate::block::ChainState`] (M2.2.x).

use mfn_crypto::authorship::{
    encode_authorship_claim, verify_claim, AuthorshipClaim, UNBOUND_COMMIT_HASH,
};
use mfn_crypto::domain::CLAIM_LEAF;
use mfn_crypto::hash::dhash;
use mfn_crypto::merkle::merkle_root_or_zero;

use crate::block::StorageEntry;
use crate::coinbase::is_coinbase_shaped;
use crate::extra_codec::parse_mfex_authorship_claims;
use crate::transaction::{tx_id, TransactionWire};
use std::collections::HashMap;

/// Index key: (`data_root`, compressed claiming pubkey bytes).
pub type AuthorshipClaimKey = ([u8; 32], [u8; 32]);

/// Build the canonical [`AuthorshipClaimKey`] for a claim.
pub fn authorship_claim_key(claim: &AuthorshipClaim) -> AuthorshipClaimKey {
    (
        claim.data_root,
        claim.claim_pubkey.compress().to_bytes(),
    )
}

/// One accepted authorship claim anchored at `height` / `tx_id`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AuthorshipClaimRecord {
    /// Full signed claim (MFCL payload semantics).
    pub claim: AuthorshipClaim,
    /// Transaction that carried the claim in `extra`.
    pub tx_id: [u8; 32],
    /// Block height where the claim was accepted.
    pub height: u32,
    /// Index of the transaction within [`crate::block::Block::txs`].
    pub tx_index: u32,
    /// Index of this claim within that transaction's parsed claim list.
    pub claim_index: u32,
}

impl AuthorshipClaimRecord {
    /// Merkle leaf / id for deduplication.
    pub fn leaf_hash(&self) -> mfn_crypto::Result<[u8; 32]> {
        authorship_claim_merkle_leaf(
            &self.claim,
            &self.tx_id,
            self.tx_index,
            self.claim_index,
            self.height,
        )
    }
}

/// Merkle leaf hash for one claim occurrence (binds wire + position).
pub fn authorship_claim_merkle_leaf(
    claim: &AuthorshipClaim,
    tx_id: &[u8; 32],
    tx_index: u32,
    claim_index: u32,
    height: u32,
) -> mfn_crypto::Result<[u8; 32]> {
    let wire = encode_authorship_claim(claim)?;
    Ok(dhash(
        CLAIM_LEAF,
        &[
            wire.as_slice(),
            tx_id.as_slice(),
            &tx_index.to_be_bytes(),
            &claim_index.to_be_bytes(),
            &height.to_be_bytes(),
        ],
    ))
}

/// Merkle root over claim leaves in **block order** (tx index, then claim index).
/// Empty slice ⇒ `[0u8; 32]` sentinel.
pub fn claims_merkle_root(leaves: &[[u8; 32]]) -> [u8; 32] {
    merkle_root_or_zero(leaves)
}

/// Verified claims + merkle leaves for one transaction ([`verified_claims_for_tx`]).
pub type VerifiedTxClaims = (Vec<AuthorshipClaim>, Vec<[u8; 32]>);

/// Result of [`verified_claims_for_tx`].
pub type VerifiedClaimsForTxResult = Result<VerifiedTxClaims, AuthorshipClaimVerifyError>;

/// Parse and verify signatures; returns `(claims, leaf_hashes)` in parse order.
pub fn verified_claims_for_tx(
    tx: &TransactionWire,
    tx_index: u32,
    height: u32,
) -> VerifiedClaimsForTxResult {
    let claims =
        parse_mfex_authorship_claims(&tx.extra).map_err(AuthorshipClaimVerifyError::Parse)?;
    let tid = tx_id(tx);
    let mut leaves = Vec::with_capacity(claims.len());
    for (i, c) in claims.iter().enumerate() {
        let i_u32 = u32::try_from(i).map_err(|_| AuthorshipClaimVerifyError::TooManyClaims)?;
        let ok = verify_claim(c).map_err(AuthorshipClaimVerifyError::Crypto)?;
        if !ok {
            return Err(AuthorshipClaimVerifyError::BadSignature {
                tx_index,
                claim_index: i_u32,
            });
        }
        let lh = authorship_claim_merkle_leaf(c, &tid, tx_index, i_u32, height)
            .map_err(AuthorshipClaimVerifyError::Crypto)?;
        leaves.push(lh);
    }
    Ok((claims, leaves))
}

/// Errors when verifying authorship claims for a transaction.
#[derive(Debug, thiserror::Error)]
pub enum AuthorshipClaimVerifyError {
    /// Structured `extra` parse failure.
    #[error("extra MFEX/MFCL parse: {0}")]
    Parse(#[from] crate::extra_codec::ExtraClaimsParseError),
    /// Schnorr / digest error.
    #[error("crypto: {0:?}")]
    Crypto(mfn_crypto::CryptoError),
    /// Signature did not verify.
    #[error("invalid authorship signature at tx_index {tx_index} claim_index {claim_index}")]
    BadSignature {
        /// Transaction index in block.
        tx_index: u32,
        /// Claim index in tx.
        claim_index: u32,
    },
    /// Claim count overflow (defensive).
    #[error("too many claims in one transaction")]
    TooManyClaims,
    /// Non-zero `commit_hash` does not match an anchored storage commitment.
    #[error(
        "authorship claim commit_hash not anchored or data_root mismatch at tx_index {tx_index} claim_index {claim_index}"
    )]
    CommitHashNotAnchored {
        /// Transaction index in block.
        tx_index: u32,
        /// Claim index in tx.
        claim_index: u32,
    },
    /// Same (`data_root`, `claim_pubkey`) already indexed.
    #[error(
        "duplicate authorship claim for data_root and claim_pubkey at tx_index {tx_index} claim_index {claim_index}"
    )]
    DuplicateClaimKey {
        /// Transaction index in block.
        tx_index: u32,
        /// Claim index in tx.
        claim_index: u32,
    },
}

/// Returns `Ok(())` when `claim`'s optional storage binding is satisfied by `storage`.
pub fn check_claim_storage_binding(
    claim: &AuthorshipClaim,
    storage: &HashMap<[u8; 32], StorageEntry>,
) -> bool {
    if claim.commit_hash == UNBOUND_COMMIT_HASH {
        return true;
    }
    storage
        .get(&claim.commit_hash)
        .is_some_and(|e| e.commit.data_root == claim.data_root)
}

/// Returns `Ok(())` when (`data_root`, `claim_pubkey`) is not already in `claims`.
pub fn check_claim_key_unique(
    claim: &AuthorshipClaim,
    claims: &std::collections::BTreeMap<AuthorshipClaimKey, AuthorshipClaimRecord>,
) -> bool {
    !claims.contains_key(&authorship_claim_key(claim))
}

impl From<mfn_crypto::CryptoError> for AuthorshipClaimVerifyError {
    fn from(e: mfn_crypto::CryptoError) -> Self {
        AuthorshipClaimVerifyError::Crypto(e)
    }
}

/// Build a persistent record (also used when indexing into [`crate::block::ChainState`]).
pub fn claim_to_record(
    claim: &AuthorshipClaim,
    tx_id: [u8; 32],
    height: u32,
    tx_index: u32,
    claim_index: u32,
) -> AuthorshipClaimRecord {
    AuthorshipClaimRecord {
        claim: claim.clone(),
        tx_id,
        height,
        tx_index,
        claim_index,
    }
}

/// Collect Merkle leaves for every non-coinbase tx, in block order (for headers).
pub fn collect_claim_merkle_leaves_for_txs(
    txs: &[TransactionWire],
    height: u32,
) -> Result<Vec<[u8; 32]>, AuthorshipClaimVerifyError> {
    let mut out = Vec::new();
    for (ti, tx) in txs.iter().enumerate() {
        if ti == 0 && is_coinbase_shaped(tx) {
            continue;
        }
        let (_clist, leaves) = verified_claims_for_tx(tx, ti as u32, height)?;
        out.extend_from_slice(&leaves);
    }
    Ok(out)
}

/// Pack `MFEX` ‖ v1 ‖ concatenated [`encode_authorship_claim`] outputs.
pub fn build_mfex_extra(claims: &[AuthorshipClaim]) -> mfn_crypto::Result<Vec<u8>> {
    let mut out = Vec::new();
    out.extend_from_slice(crate::extra_codec::MFEX_MAGIC);
    out.push(crate::extra_codec::MFEX_VERSION);
    for c in claims {
        out.extend_from_slice(&encode_authorship_claim(c)?);
    }
    Ok(out)
}
