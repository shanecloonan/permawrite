//! Validator-mode finality + validator-set evolution invariants.
//!
//! Covers pre-block finality quorum, pre-block `validator_root`, atomic
//! liveness stats/stake updates, header body-root binding (bond, slashing,
//! tx, storage_proof, claims, utxo, storage), unbond-settlement root evolution, equivocation during
//! unbond delay, entry/exit churn caps and epoch reset, duplicate/invalid slash
//! rejection, bond-op admission rejects (duplicate vrf, duplicate unbond,
//! stake below minimum, same-block register-then-unbond, same-block duplicate
//! vrf batch, zombie unbond, forged/unknown unbond, duplicate unbond after
//! pending request, bond rejection treasury preservation), chain linkage
//! (prev_hash), finality proof integrity (msg mismatch, tampered blob,
//! signing_stake claim, producer index), producer VRF/BLS verification
//! failures, aggregate signature integrity, bond epoch counter persistence,
//! checkpoint roundtrip of bond counters, missing/malformed producer proof,
//! explicit sub-quorum `QuorumNotMet`, zero-stake liveness skip after equivocation,
//! monotonic register index assignment, register stats/treasury credits,
//! slash-forfeiture treasury credits in validator mode, liveness sign resets
//! consecutive misses, unbond settlement clears pending queue, bond epoch rollover,
//! producer proof index/secrets mismatch, cast_vote refusing ineligible
//! producer, pending_unbonds + validator_stats + equivocation slash checkpoint
//! roundtrips, valid-then-invalid slash batch atomicity, sub-quorum liveness
//! stats preservation,
//! plus rejection preserving caller state.
//! Empty blocks only — no privacy txs, storage proofs, or coinbase.
#![allow(unused_imports)]

mod bond_ops;
mod epoch_checkpoint;
mod finality_rejection;
mod header_roots;
mod liveness;
mod pre_block;
mod producer_proof;
mod slashing;
mod support;
