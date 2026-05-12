# M2.0.5 — Light-header verification primitive

**Status:** ✓ shipped (mainnet-ready, byte-for-byte aligned with `apply_block`).

This note records the rationale, surface, and tests added by milestone **M2.0.5**. It is the first user-facing payoff of the M2.0.x "header binds every body element" series ([M2.0](./M2_VALIDATOR_ROOT.md), **M2.0.1**, [M2.0.2](./M2_STORAGE_PROOF_ROOT.md)): the pure function a light client uses to follow the chain without holding the full `ChainState`.

---

## Why

Through M2.0–M2.0.2 the [`BlockHeader`] grew commitments to every block-body element (txs, bond ops, slashings, the pre-block validator set, and storage proofs). Then in M2.0.3–M2.0.4 the `mfn-node` crate exposed a `Chain` driver and a 3-stage producer protocol so we can *make* such headers end-to-end. The remaining question was the symmetric one:

> Given just a header and a trusted starting validator set — *no* `ChainState`, no UTXO tree, no storage tree — can a verifier independently confirm that a real quorum of the right validators signed this header?

That's the operative question for every off-the-shelf consumer of the chain:

- **Mobile / browser wallets.** Bandwidth-constrained, can't hold the full state. Need to verify a remote node's claim "your tx is in block N" without trusting the node.
- **Bridges and light relays.** Same shape: read a header chain, verify each header under a trust anchor (genesis validators), and trust *only* the cryptographic conclusion.
- **Audit tooling.** Sometimes you want to verify a single archival header out of the blue. You don't want to replay 5 years of blocks to do it.

`apply_block` already does all the cryptographic checks internally, but it requires a full `ChainState` (storage tree, UTXO tree, validator stats, treasury) and *mutates* it. That's the wrong shape for a light client. M2.0.5 splits the cryptographic half out into a pure, allocation-cheap function.

---

## What shipped

### Module

[`mfn_consensus::header_verify`](../mfn-consensus/src/header_verify.rs) — a new module added to `mfn-consensus`. Re-exported at the crate root as:

```rust
pub use mfn_consensus::{verify_header, HeaderCheck, HeaderVerifyError};
```

Living in `mfn-consensus` (not in a new `mfn-light` crate) is deliberate: the verification logic is part of the consensus *spec*, and keeping it spec-local means there's only one source of truth for "what makes a header valid". A future `mfn-light` crate will wrap this primitive with chain-traversal, persistence, and P2P sync, but the cryptographic primitive is consensus-canonical.

### API

```rust
pub fn verify_header(
    header: &BlockHeader,
    trusted_validators: &[Validator],
    params: &ConsensusParams,
) -> Result<HeaderCheck, HeaderVerifyError>;

pub struct HeaderCheck {
    pub producer_index:   u32,
    pub signing_stake:    u64,
    pub total_stake:      u64,
    pub quorum_required:  u64,
    pub validator_count:  usize,
    pub quorum_reached:   bool,    // always true on Ok; exposed for stricter callers
}

pub enum HeaderVerifyError {
    ValidatorRootMismatch,
    GenesisHeader,
    ProducerProofDecode(String),
    FinalityRejected(ConsensusCheck),
    EmptyTrustedSet,
}
```

### Checks performed (in this exact order)

| # | Check | Failure → |
|---|---|---|
| 1 | `trusted_validators` is non-empty | `EmptyTrustedSet` |
| 2 | `validator_set_root(trusted_validators) == header.validator_root` (the trust anchor) | `ValidatorRootMismatch` |
| 3 | `header.producer_proof` is non-empty (genesis-style headers can't be light-verified — they *are* the trust anchor) | `GenesisHeader` |
| 4 | `header.producer_proof` decodes as a `FinalityProof` | `ProducerProofDecode(_)` |
| 5 | `verify_finality_proof(...)` returns `ConsensusCheck::Ok` — covers producer VRF + ed25519 + slot eligibility, BLS aggregate over the header signing hash, signing-stake-bitmap consistency, and quorum threshold | `FinalityRejected(_)` |

Every check is the same byte-for-byte check `apply_block` runs in Phase 0–1. The agreement is exercised by the integration test `verify_header_agrees_with_apply_block_across_three_blocks` (see below).

### Determinism + safety

- **Pure function.** No IO, no async, no clock, no global state. Identical inputs always produce identical outputs.
- **No allocation in the happy path beyond what `verify_finality_proof` requires** (BLS pubkey vector + signing-stake bitmap iteration).
- **`#![forbid(unsafe_code)]`** inherited from the crate.
- **No state mutation possible.** All arguments are `&` references; the only return surface is `Result<HeaderCheck, HeaderVerifyError>`.

### Chain-of-trust model

The function only handles **one hop**. The light-client model is:

```text
 trusted starting validators (e.g. genesis_cfg.validators)
        │
        ▼
 verify_header(header_1, trusted_validators_0, params)  ──► Ok
        │
        │  (replay block_1.bond_ops / slashings / unbonds
        │   against trusted_validators_0 to derive
        │   trusted_validators_1 — body needed for this step)
        ▼
 verify_header(header_2, trusted_validators_1, params)  ──► Ok
        │
        ▼
        …
```

Walking the chain and tracking trusted-validator evolution as it rotates through `BondOp`s, slashings, and unbond settlements is the job of the future `mfn-light` crate. Splitting concerns this way keeps the *cryptographic* primitive pure: same inputs, same outputs.

---

## Test matrix

| # | Test | Layer | Asserts |
|---|---|---|---|
| 1 | `verify_header_accepts_real_signed_block` | `header_verify.rs` unit | Happy path: real signed block 1 verifies; producer index, signing stake, quorum stats correct |
| 2 | `verify_header_rejects_tampered_validator_root` | unit | `ValidatorRootMismatch` |
| 3 | `verify_header_rejects_wrong_trusted_set` | unit | Different stake → different root → `ValidatorRootMismatch` |
| 4 | `verify_header_rejects_tampered_producer_proof` | unit | `FinalityRejected(_)` or `ProducerProofDecode(_)` |
| 5 | `verify_header_rejects_empty_trusted_set` | unit | `EmptyTrustedSet` |
| 6 | `verify_header_rejects_empty_producer_proof` | unit | `GenesisHeader` (typed, not cryptic) |
| 7 | `verify_header_rejects_truncated_producer_proof` | unit | `ProducerProofDecode(_)` |
| 8 | `verify_header_rejects_tampered_height` | unit | Header-hash domain → `FinalityRejected(_)` |
| 9 | `verify_header_rejects_tampered_slot` | unit | VRF/producer-sig domain → `FinalityRejected(_)` |
| 10 | `verify_header_is_deterministic` | unit | Repeated verification yields byte-identical `HeaderCheck` |
| 11 | `verify_header_agrees_with_apply_block_across_three_blocks` | `mfn-node/tests/light_header_verify.rs` integration | For each of 3 real BLS-signed blocks, `verify_header` accepts iff `apply_block` accepts |
| 12 | `verify_header_works_with_post_block_trusted_set_when_no_rotation` | integration | Validator-set stability invariant: pre/post-block trusted sets verify the same header when no rotation occurs |
| 13 | `tampered_header_is_rejected_by_both_verify_header_and_apply_block` | integration | Symmetric rejection: validator_root / producer_proof / height tamper all rejected by both layers; clean block still applies afterwards |

10 new unit tests + 3 new integration tests = **13 new tests**, all passing. Workspace total moved 349 → 362.

---

## What's intentionally *not* in M2.0.5

- **Multi-hop chain following.** `verify_header` covers one header against one trusted set. Walking the chain (replaying bond ops / slashings / unbond settlements to evolve the trusted set) is the future `mfn-light` crate.
- **Body verification.** Recomputing `tx_root`, `bond_root`, `slashing_root`, `storage_proof_root`, or `storage_root` from a delivered body and comparing to the header is a separate (and trivial) layer on top of the existing `*_merkle_root` helpers. Not coupled here.
- **Header chain linkage.** Confirming `header.prev_hash == block_id(prev_header)` and `header.height == prev_height + 1` is the caller's responsibility — chained headers are verified by whoever decides which chain to follow.
- **Persistence / RPC / P2P.** All daemon concerns. Future milestones.

---

## Code map

| Crate | File | New / changed |
|---|---|---|
| `mfn-consensus` | `src/header_verify.rs` | new module |
| `mfn-consensus` | `src/lib.rs` | re-exports `verify_header`, `HeaderCheck`, `HeaderVerifyError` |
| `mfn-node` | `tests/light_header_verify.rs` | new integration test file |
| `docs/M2_LIGHT_HEADER_VERIFY.md` | this doc | new |

No protocol-level wire change. No header-field change. No new domain tag. M2.0.5 is purely a new *verification* surface on top of the wire format M2.0.x finalized.

---

## What this unlocks

- **`mfn-light` crate.** The natural next milestone: a header-chain follower that takes a `GenesisConfig`, ingests a stream of headers + body deltas, evolves the trusted validator set across rotations, and exposes a `verify_tip(...)` API.
- **Mobile / browser wallets.** Compile `mfn-consensus` to WASM, ship `verify_header` to the client, give it a trusted genesis validator set, and let it independently verify the tip of every block its remote-node tells it about.
- **Bridges.** A reader on chain X can verify Permawrite block headers given the canonical genesis validator set + a follower for validator-set evolution.
- **Audit tooling.** Stateless "is this archival header genuine?" tooling.

The header has been earning the right to be light-verifiable for three milestones; M2.0.5 cashes it in.
