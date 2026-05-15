//! Errors surfaced by [`mfn_wallet`](crate).
//!
//! Wallet operations distinguish four failure axes:
//!
//! - **Input shape** — caller passed something structurally wrong (e.g.
//!   empty recipient list, fee but no spendable outputs).
//! - **Insufficient state** — wallet's owned-UTXO set or the supplied
//!   decoy pool cannot cover the request.
//! - **Storage-upload policy** — caller-supplied upload would be
//!   rejected by the mempool's storage-anchoring gate (replication out
//!   of range, treasury share below required endowment, endowment
//!   doesn't fit in `u64`, fee routing disabled). These mirror the
//!   `AdmitError` variants the mempool / chain raise, but the wallet
//!   surfaces them *before* signing so the caller never wastes CLSAG
//!   work on a tx the network would reject.
//! - **Underlying crypto** — `mfn-crypto` / `mfn-consensus` /
//!   `mfn-storage` rejected a primitive (range-proof construction
//!   failed, CLSAG balance check failed, endowment math overflowed).
//!   These are flattened via `#[from]` so a caller can `?` them without
//!   rewriting matches every time the upstream error grows.

use thiserror::Error;

/// Top-level error type for wallet operations.
#[derive(Debug, Error)]
pub enum WalletError {
    /// `Wallet::build_transfer` was called with an empty recipient list.
    #[error("no recipients supplied")]
    NoRecipients,

    /// Authorship claim message exceeds the consensus wire limit.
    #[error("claim message length {got} exceeds max {max}")]
    ClaimMessageTooLong {
        /// Bytes supplied.
        got: usize,
        /// [`mfn_crypto::authorship::MAX_CLAIM_MESSAGE_LEN`].
        max: usize,
    },

    /// Caller asked to send `requested` atomic units but the wallet only
    /// holds `available` in unspent owned outputs (plus fee, if any).
    #[error("insufficient funds: requested {requested}, available {available}")]
    InsufficientFunds {
        /// Total `Σ recipients.value + fee` requested.
        requested: u64,
        /// Total spendable balance currently in the wallet.
        available: u64,
    },

    /// A specific owned-output index was named for spending but is not
    /// (or no longer) in the wallet's spendable set.
    #[error("unknown owned output: {0}")]
    UnknownOwnedOutput(String),

    /// Caller asked for a ring size that the supplied decoy pool cannot
    /// satisfy even after the gamma sampler's fallback to uniform.
    ///
    /// The wallet itself will not silently drop ring size for caller
    /// safety — Monero-style anonymity-set degradation should be an
    /// explicit caller decision.
    #[error("decoy pool too small: ring_size {ring_size}, pool {pool_size}")]
    DecoyPoolTooSmall {
        /// Requested ring size (real + decoys).
        ring_size: usize,
        /// Number of distinct candidates the caller provided.
        pool_size: usize,
    },

    /// The encrypted-amount blob on a candidate output decoded under our
    /// view-key but did NOT open the Pedersen commitment. The output is
    /// not ours (XOR-pad collision artifact). Surfaced as a hard error
    /// only by the `*_strict` scan helpers; the lenient default just
    /// drops the output silently.
    #[error("pedersen commitment does not open with decrypted (value, blinding)")]
    PedersenOpenMismatch,

    /// Storage upload was requested at a replication factor outside the
    /// chain's configured `[min_replication, max_replication]` band.
    ///
    /// The mempool's storage-anchoring gate would reject this tx as
    /// `AdmitError::StorageReplicationTooLow` /
    /// `AdmitError::StorageReplicationTooHigh`; the wallet rejects
    /// earlier with an actionable error so the caller never wastes
    /// signing work.
    #[error("upload replication {got} out of range [{min}, {max}]")]
    UploadReplicationOutOfRange {
        /// Caller-supplied replication factor.
        got: u8,
        /// Chain's configured minimum.
        min: u8,
        /// Chain's configured maximum.
        max: u8,
    },

    /// Caller's fee is below the floor that satisfies the storage
    /// treasury burden for this upload.
    ///
    /// Mirrors the mempool's `UploadUnderfunded` gate
    /// (`fee · fee_to_treasury_bps / 10000 ≥ Σ required_endowment`). We
    /// hoist it to the wallet so the caller learns the minimum fee
    /// *before* signing — a freshly-signed tx that the mempool would
    /// reject is wasted CLSAG work + leaks the spent inputs to anyone
    /// scraping the wire.
    #[error(
        "upload underfunded: fee {fee} → treasury share {treasury_share}, burden {burden}, minimum fee {min_fee}"
    )]
    UploadUnderfunded {
        /// Caller-supplied fee.
        fee: u64,
        /// Computed `fee · fee_to_treasury_bps / 10000`.
        treasury_share: u128,
        /// Sum of `required_endowment` over all newly anchored
        /// commitments in this upload (always one for now).
        burden: u128,
        /// Smallest fee that would satisfy the gate.
        min_fee: u64,
    },

    /// The upload's required endowment exceeds `u64::MAX` base units.
    ///
    /// `StorageCommitment::endowment` is a Pedersen commitment to a
    /// `u64` scalar; representations larger than that cannot fit. At
    /// default endowment params this corresponds to uploads larger than
    /// several exabytes — pathological / adversarial sizing.
    #[error("upload burden {burden} exceeds u64::MAX (cannot be committed)")]
    UploadEndowmentExceedsU64 {
        /// Computed `required_endowment` value.
        burden: u128,
    },

    /// The chain's `fee_to_treasury_bps` is zero: no positive fee can
    /// fund any storage burden.
    ///
    /// Surfaced for safety; default chain params set this to `9000`
    /// (90%), so this branch only fires on a misconfigured genesis.
    #[error("fee_to_treasury_bps is zero — no positive fee can fund any storage burden")]
    UploadTreasuryRouteDisabled,

    /// Endowment math returned a typed error (params validation,
    /// arithmetic overflow). Forwarded verbatim from `mfn-storage`.
    #[error(transparent)]
    Endowment(#[from] mfn_storage::EndowmentError),

    /// Storage commitment construction returned a typed error (e.g.
    /// invalid chunk size, too many chunks for the chosen size, Merkle
    /// build failure). Forwarded verbatim from `mfn-storage`.
    #[error(transparent)]
    Spora(#[from] mfn_storage::SporaError),

    /// Underlying `mfn-crypto` error (e.g. `hash_to_point` failure on
    /// derived key-image base).
    #[error(transparent)]
    Crypto(#[from] mfn_crypto::CryptoError),

    /// Underlying `mfn-consensus::sign_transaction` error.
    #[error(transparent)]
    TxBuild(#[from] mfn_consensus::TxBuildError),
}
