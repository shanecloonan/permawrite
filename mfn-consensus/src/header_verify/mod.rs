//! Light-client verification primitives.
//!
//! This module hosts the **pure, state-free** verification functions
//! a light client uses to follow the chain without holding a full
//! [`crate::block::ChainState`]:
//!
//! - [`verify_header`] (M2.0.5) — given a trusted pre-block validator
//!   set and a [`BlockHeader`], verify the header's consensus-critical
//!   commitments (validator-set commitment + producer proof + BLS
//!   finality aggregate).
//! - [`verify_block_body`] (M2.0.7) — given a [`crate::block::Block`],
//!   re-derive the five body-bound Merkle roots that are pure
//!   functions of the block body (`tx_root`, `bond_root`,
//!   `slashing_root`, `storage_proof_root`, `claims_root`) and verify they match
//!   the header. The other two header-bound roots (`storage_root`,
//!   `utxo_root`) are state-dependent and out-of-scope for stateless
//!   verification — they're already cryptographically bound through
//!   the BLS aggregate verified by [`verify_header`]. **`utxo_root` is
//!   not in `header_signing_bytes` on v1 headers** — it is bound only
//!   transitively one block later via `block_id` → `prev_hash`. Use
//!   [`UTXO_ROOT_QUORUM_CONFIRMATION_LAG`] / [`utxo_root_quorum_confirmation_lag`]
//!   before consuming tip `utxo_root` for deposits or OoM proofs. v2+
//!   headers ([`UTXO_ROOT_DIRECT_QUORUM_HEADER_VERSION`]) include
//!   `utxo_root` in the BLS message directly.
//!
//! ## Why this primitive exists
//!
//! After milestones M2.0 / M2.0.1 / M2.0.2 the [`BlockHeader`] binds
//! every block-body element (txs, bond ops, slashings, the pre-block
//! validator set, and storage proofs) under the producer's BLS
//! aggregate. That means a verifier holding *only* the header chain
//! can structurally re-derive every body root from a body delivered
//! out-of-band, *and* — crucially — verify that the header itself was
//! BLS-signed by a quorum of the validator set it claims to commit
//! to. This module is the verification half of that contract.
//!
//! `apply_block` already does all the same cryptographic checks
//! internally as part of Phase 0 + Phase 1 of the state-transition
//! function (see [`crate::block::apply_block`]). But `apply_block`
//! requires a full [`crate::block::ChainState`] — it needs to
//! actually mutate state, run the storage-proof phase, settle
//! unbonds, etc. A light client doesn't have a `ChainState`. It has
//! a header chain plus a *trusted starting validator set* (typically
//! the genesis config). [`verify_header`] is the part of `apply_block`
//! that's safe to run with only that.
//!
//! ## Chain of trust
//!
//! The light-client model is:
//!
//! ```text
//!  trusted starting validators (e.g. genesis cfg.validators)
//!         │
//!         ▼
//!  verify_header(header_1, trusted_validators_0, params)  ──► OK
//!         │
//!         │  (caller replays block_1.bond_ops / slashings / unbonds
//!         │   against trusted_validators_0 to derive
//!         │   trusted_validators_1 — body needed for this step)
//!         ▼
//!  verify_header(header_2, trusted_validators_1, params)  ──► OK
//!         │
//!         ▼
//!         …
//! ```
//!
//! [`verify_header`] alone only handles a single hop. Walking the
//! whole chain (and tracking the trusted validator-set evolution as
//! it rotates through `BondOp`s and slashings) is the job of the
//! future `mfn-light` crate. Splitting the concerns this way keeps
//! the *cryptographic* primitive pure: same inputs, same outputs,
//! no IO, no async, no clock.
//!
//! ## Not in scope
//!
//! - **Header chain linkage.** Confirming `header.prev_hash ==
//!   block_id(prev_header)` and `header.height == prev_height + 1`
//!   is the caller's responsibility — chained headers are verified
//!   by whoever decides which chain to follow (in practice the
//!   `mfn-light::LightChain` driver).
//! - **State-dependent body roots.** `storage_root` and `utxo_root`
//!   are functions of accumulated chain state, not pure functions of
//!   the block body. A stateless verifier can't independently
//!   recompute them from the body alone. On **v1** headers the BLS
//!   aggregate does **not** sign `utxo_root` (see
//!   [`UTXO_ROOT_QUORUM_CONFIRMATION_LAG`]); on **v2+** it does.

mod body;
mod header;
mod internal;
mod types;

#[cfg(test)]
mod tests;

pub use body::{verify_block_body, BodyVerifyError};
pub use header::verify_header;
pub use types::{
    utxo_root_quorum_confirmation_lag, HeaderCheck, HeaderVerifyError,
    UTXO_ROOT_DIRECT_QUORUM_HEADER_VERSION, UTXO_ROOT_QUORUM_CONFIRMATION_LAG,
};
