# Roadmap

> **Audience.** Anyone trying to understand "what's done, what's coming, and in what order."
> The tier system maps the conceptual roadmap onto concrete code milestones.

---

## Where we are right now

| Layer | Crate | Tests | Status |
|---|---|---:|---|
| ed25519 primitives + ZK | `mfn-crypto` | 145 | ✓ live |
| BLS12-381 + committee aggregation | `mfn-bls` | 16 | ✓ live |
| Permanent-storage primitives (+ **M2.0.2 storage-proof merkle root**) | `mfn-storage` | 39 | ✓ live |
| Chain state machine (SPoRA verify + liveness slashing + **M1 validator rotation** + **M1.5 BLS-authenticated Register** + **M2.0 validator-set merkle root** + **M2.0.1 slashing merkle root** + **M2.0.2 storage-proof merkle root** + **M2.0.5 light-header verifier** + **M2.0.7 light-body verifier** + **M2.0.8 shared validator_evolution helpers**) | `mfn-consensus` | 161 | ✓ live |
| Node-side glue (**M2.0.3 `Chain` driver** + **M2.0.4 producer helpers** + **M2.0.5 light-header agreement tests**) | `mfn-node` | 17 | ✓ live (skeleton) |
| Light-client chain follower (**M2.0.6 header-chain follower** + **M2.0.7 body-root verification** + **M2.0.8 validator-set evolution**) | `mfn-light` | 34 | ✓ live |
| Canonical wire codec | (in `mfn-crypto::codec`) | — | ✓ live (will extract) |
| **Total** | | **412** | All checks green |

**Posture.** We've built the consensus core *and* the validator-rotation layer. There's no daemon, no mempool, no P2P, no wallet CLI yet. The roadmap below lays out the path from "consensus state machine in a test harness" to "running network."

---

## Tier system

The four tiers describe **monotonic privacy strength**. Each tier adds capabilities; none breaks earlier ones. A tx that verifies under Tier 1 rules continues to verify under Tier 4 rules.

| Tier | Status | Headline | Privacy strength |
|---|---|---|---|
| **Tier 1** | ✓ Live | CLSAG rings (16) + Bulletproofs + gamma decoys | Monero-equivalent |
| **Tier 2** | □ Near-term | Bulletproof+ transcripts, transcript-graph mitigations, ring 32–64 | Monero-plus |
| **Tier 3** | □ Mid-term | OoM proofs over the **entire UTXO accumulator** | Strictly dominates ring sigs |
| **Tier 4** | □ Long-term | Recursive SNARK proof aggregation (one proof per block) | Strictly dominates Tier 3 in cost; same privacy |

Storage permanence is mostly independent of the privacy tier — already at production strength in Tier 1.

---

## Milestone M0 — Consensus core (✓ shipped)

Everything described in [`ARCHITECTURE.md`](./ARCHITECTURE.md). Specifically:

- All cryptographic primitives in `mfn-crypto`.
- BLS aggregation in `mfn-bls`.
- SPoRA + endowment math in `mfn-storage`.
- Full state-transition function in `mfn-consensus::apply_block`:
  - Header validation
  - Finality proof verification
  - Tx verification (CLSAG, Pedersen balance, range proofs)
  - **Ring-membership chain guard** (closes counterfeit-input attack)
  - Cross-block key-image uniqueness
  - Equivocation slashing
  - Storage upload endowment burden enforcement
  - SPoRA storage-proof verification + PPB-accrual yield
  - Two-sided treasury settlement (with emission backstop)
  - **Liveness tracking + multiplicative slashing**

Test count: 279 passing across the workspace at the close of M0. Zero `unsafe`. Zero clippy warnings.

---

## Milestone M1 — Validator rotation (✓ shipped)

Full design note: [**docs/M1_VALIDATOR_ROTATION.md**](./M1_VALIDATOR_ROTATION.md). Validator rotation is now fully implemented end-to-end: register, exit, delayed settlement, slashing during the delay, per-epoch churn caps, and the burn-on-bond / slash-to-treasury economic loop.

**Why it was next.** At the close of M0 the validator set was frozen at genesis. Without rotation, the chain could not onboard new validators or recycle slots vacated by zero-stake (liveness-slashed-to-floor or equivocation-zeroed) ones — the largest *structural* hole left in the protocol layer.

### What shipped

- **`BondOp::Register`** — burn-on-bond, **BLS-authenticated by the operator's own voting key** (M1.5). The validator's declared stake is credited to `treasury`, the new validator is appended with a fresh `ValidatorStats` row, and a deterministic `next_validator_index` counter ensures indices are never reused. The signature commits to `(stake, vrf_pk, bls_pk, payout)` under domain `MFBN-1/register-op-sig`, so an adversarial relayer cannot replay a leaked op or swap in their own keys.
- **`BondOp::Unbond`** — BLS-signed authorization over a domain-separated payload (`MFBN-1/unbond-op-sig` ‖ `validator_index`). Enqueued into `pending_unbonds: BTreeMap<u32, PendingUnbond>` with `unlock_height = height + unbond_delay_blocks`.
- **Delayed settlement.** At `height ≥ unlock_height`, the entry is popped, the validator's stake is zeroed (becomes a non-signing zombie), and the originally bonded MFN remains in the treasury — a permanent contribution to the permanence endowment. Explicit operator payouts are intentionally deferred.
- **Per-epoch entry / exit churn caps.** `max_entry_churn_per_epoch` and `max_exit_churn_per_epoch` (defaults: 4 each), enforced via `try_register_entry_churn` / `try_register_exit_churn`. Oversubscribed unbonds spill cleanly into subsequent blocks without losing their delay accounting.
- **Treasury credit on slash.** Both equivocation slashing (full stake forfeit) and liveness slashing (multiplicative forfeit) credit the lost amount to `treasury` using saturating `u128` arithmetic — the same sink that funds storage operators.
- **Atomicity.** Bond ops are applied as a single all-or-nothing batch per block: any rejection (bad signature, churn cap, unknown validator, …) rolls back the entire bond-op set so `bond_root` remains the binding commitment.
- **Header v1 carries `bond_root`.** A separate Merkle root over the block's bond ops (Option A from the design note). Empty bond-op vector → `[0u8; 32]` sentinel.

### Closed economic-symmetry property

Combined, burn-on-bond + slash-to-treasury give the chain a closed economic loop:

- Every base unit a validator commits via `BondOp::Register` is credited to the treasury.
- Every base unit a validator forfeits via equivocation or liveness slashing is credited to the treasury.
- Every base unit paid out to storage operators via `accrue_proof_reward` drains the treasury (with the emission backstop).

Validator bonds are a **one-way contribution** to the permanence endowment in M1. Operator payouts on settlement are explicitly deferred to a future milestone.

### Test matrix (delivered)

- ✓ Bond accepted → validator appears with correct index, fresh stats row, eligible in the next VRF cycle. *(`block::tests::bond_op_round_trip` + `bond_apply` cases.)*
- ✓ Burn-on-bond credits treasury *(`burn_on_bond_credits_treasury`, `burn_on_bond_aggregates_multiple_registers`).*
- ✓ Equivocation evidence credits treasury *(`equivocation_slash_credits_treasury_via_apply_block`).*
- ✓ Liveness slash credits treasury *(`liveness_slash_credits_treasury`, `liveness_slash_treasury_compounds_with_validator_stake`).*
- ✓ Entry / exit churn caps enforced deterministically *(`bonding::tests::entry_churn_cap`, `exit_churn_cap`; apply-side in `block::tests`).*
- ✓ Unbond submitted → validator still slashable during the delay *(`unbond_lifecycle_equivocation_during_delay_still_slashes` in `tests/integration.rs`).*
- ✓ Settlement at `unlock_height` zeros stake + leaves bonded MFN in treasury *(`unbond_lifecycle_request_delay_settle`).*
- ✓ Oversubscribed unbonds spill across blocks honoring the per-epoch exit cap *(`unbond_lifecycle_exit_churn_cap_spills_to_next_block`).*
- ✓ TS interop: `BondOp::Register` byte parity with the `cloonan-group` smoke reference *(`bond_register_wire_matches_cloonan_ts_smoke_reference`).*
- ✓ TS interop: `BondOp::Unbond` byte parity with the `cloonan-group` smoke reference *(`bond_unbond_wire_matches_cloonan_ts_smoke_reference`).*
- ✓ M1.5 — `Register` sig is payload-bound and operator-bound; forged signatures reject atomically at `apply_block` *(`register_sig_is_bound_to_bls_pk_and_payload`, `register_signing_hash_is_domain_separated`, `block::tests::register_rejects_invalid_signature`).*

### Deferred to a future milestone

- **Explicit operator payout on settlement** (coinbase output augmentation or a dedicated payout transaction class). The M1 design intentionally leaves bonded MFN in the treasury rather than introducing a new wire shape mid-milestone.
- **Storage-operator bonding** (separate from validator bonding, for a future "premium" replica tier).

---

## Milestone M2.0 — Validator-set Merkle root (✓ shipped)

**Why it was next.** With validator rotation live (M1) the `Validator` set drifts every block. M0/M1 already gave each block header a tx/storage/bond/utxo root commitment; the missing one was a binding commitment to the validator set the block was *produced against*. Adding it now unlocks:

- **Light clients.** A header now self-describes the validator set it was validated against — so a client holding only the header chain can verify producer eligibility and committee quorum without holding the live validator list.
- **Long-range attack resistance.** Forking history requires either (a) re-presenting the exact pre-block validator set, or (b) regenerating consistent BLS aggregates over a different `validator_root` — both are constrained by past bond-op authorization and slashing evidence.
- **Closing the root-commitment family.** The header now binds `tx_root`, `bond_root`, `validator_root`, `storage_root`, `utxo_root` — txs, validator-set deltas, the live validator set, newly anchored storage, and the post-block UTXO accumulator.

### What shipped

- **`VALIDATOR_LEAF` domain tag** (`MFBN-1/validator-leaf`).
- **`validator_leaf_bytes` / `validator_leaf_hash` / `validator_set_root`** in `mfn-consensus::consensus`, deterministically committing each `Validator`'s `(index, stake, vrf_pk, bls_pk, payout?)`. `ValidatorStats` is intentionally excluded — liveness counters churn every block and would force a needless re-hash of every leaf; light clients verifying a finality bitmap need `(index, stake, bls_pk)` only.
- **`BlockHeader.validator_root: [u8; 32]`**, included in both `header_signing_bytes` (the BLS-signed pre-image) and `block_header_bytes` (the full header, used for `block_id`).
- **Pre-block semantics.** The root commits to the validator set held by the chain state *before* applying the block, i.e. the set Phase 0's producer-proof and finality bitmap are verified against. Rotation / slashing / unbond settlement applied **by** this block move the **next** header's root.
- **`apply_block` Phase 1 check.** Reconstructs `validator_set_root(&state.validators)` and rejects mismatching headers with a new `BlockError::ValidatorRootMismatch`. The check runs *before* finality verification, so a tampered `validator_root` is rejected even if (somehow) the BLS aggregate were valid.
- **Genesis convention.** Genesis commits `validator_root = [0u8; 32]` (the pre-genesis validator set is empty); the block at height 1 commits to `validator_set_root(&cfg.validators)`.

### Test matrix (delivered)

- ✓ Empty validator set → all-zero sentinel.
- ✓ Leaf bytes depend on every field (`index`, `stake`, `vrf_pk`, `bls_pk`, `payout` flag).
- ✓ `VALIDATOR_LEAF` is domain-separated (cross-domain dhash differs).
- ✓ Stake changes move the root (slashing / rotation).
- ✓ Ordering matters (canonical chain-stored order, not a sorted multiset).
- ✓ Registering a validator moves the root.
- ✓ `build_unsealed_header` commits the pre-block root.
- ✓ Tampered `header.validator_root` rejected by `apply_block` (both legacy/no-validator mode and a fully signed multi-validator block).
- ✓ Multi-block invariant: each header's `validator_root` equals the pre-block set's root.
- ✓ Equivocation slash moves the **next** header's root.
- ✓ Unbond settlement moves the **next** header's root.

### Deferred to a future milestone

- **TS-side reference port for `validator_leaf_bytes` and `validator_set_root`.** Rust-side golden vectors are pinned in `validator_root_wire_matches_cloonan_ts_smoke_reference` (canonical bytes + leaf hash for both with-payout and no-payout branches, plus the root over a two-validator set); the matching TS smoke fixture will land in `cloonan-group` next.
- **Light-client crate.** The header is now self-describing, but a separate `mfn-light` crate is intentionally postponed until the node daemon (M2.x) is up — without a real chain to query, there's nothing for the light client to verify against.

---

## Milestone M2.0.1 — Slashing-evidence Merkle root (✓ shipped)

**Why it was next.** With M2.0 the header committed the *pre-block* validator set, but `block.slashings` (the equivocation evidence list) was still un-rooted. A light client would have to trust that a header's apparent slashings list was the producer's actual choice. Adding `slashing_root` closes that gap and finishes the header commitment family: every part of the block body except the producer-proof itself is now header-rooted.

### What shipped

- **`SLASHING_LEAF` domain tag** (`MFBN-1/slashing-leaf`).
- **`slashing_leaf_hash` / `slashing_merkle_root`** in `mfn-consensus::slashing`. Each leaf is the domain-separated hash of one [`SlashEvidence`] in its **canonicalized** form (pair-order normalized) — so swapping `(hash_a, sig_a)` / `(hash_b, sig_b)` cannot forge a different leaf.
- **`BlockHeader.slashing_root: [u8; 32]`**, included in both `header_signing_bytes` and `block_header_bytes`. Empty slashings list → all-zero sentinel.
- **`build_unsealed_header` gained a `slashings: &[SlashEvidence]` parameter** so producers commit the root alongside everything else when building the unsealed header.
- **`apply_block` Phase 1 check + `BlockError::SlashingRootMismatch`.** Runs before finality verification (defense in depth, same posture as `validator_root`).
- **TS-parity golden vector** under the existing `bls_keygen_from_seed([1..=48])` convention. Exercises both the no-swap branch (`e0`, header_hash_a < header_hash_b in emit order) and the swap branch (`e1`, header_hash_a > header_hash_b) plus the Merkle root over both.

### Test matrix (delivered)

- ✓ Empty list → zero sentinel.
- ✓ Pair-order swap inside a single evidence is leaf-invariant.
- ✓ Field-level sensitivity (height, voter_index, …) — each materially changes the leaf.
- ✓ Adding evidence moves the root.
- ✓ Order across evidence pieces is committed (Merkle structure).
- ✓ Leaf domain-separated (`MFBN-1/slashing-leaf` not confusable with any other dhash domain).
- ✓ Tampered `header.slashing_root` rejected by `apply_block` (legacy/no-validator mode).
- ✓ Tampered `header.slashing_root` in a fully BLS-signed block rejected.
- ✓ TS-parity golden vector pinned.

### Deferred

- **TS-side reference port for `slashing_leaf_hash` + `slashing_merkle_root`.** Same pattern as `validator_root` — Rust pins the bytes; TS mirrors.

---

## Milestone M2.0.2 — Storage-proof Merkle root (✓ shipped)

**Why it was next.** M2.0 committed the pre-block validator set; M2.0.1 committed equivocation evidence. The last un-rooted body element was `block.storage_proofs` — the SPoRA proofs that drive yield payouts against locked endowments. Without a header binding, a light client could see commitments land (`storage_root`) and see the post-block UTXO accumulator (`utxo_root`), but had no header-level handle on the intermediate "which proofs landed this block" question. Adding `storage_proof_root` closes that gap and finishes the **header-binds-the-body** invariant: every block-body element is now rooted under the header.

### What shipped

- **`STORAGE_PROOF_LEAF` domain tag** (`MFBN-1/storage-proof-leaf`).
- **`storage_proof_leaf_hash` / `storage_proof_merkle_root`** in `mfn-storage::spora`. Each leaf is `dhash(STORAGE_PROOF_LEAF, encode_storage_proof(p))` — the same canonical SPoRA wire bytes the verifier already consumes, so there's no second encoding to keep in sync.
- **`BlockHeader.storage_proof_root: [u8; 32]`**, included in both `header_signing_bytes` and `block_header_bytes`. Empty proofs list → all-zero sentinel.
- **`build_unsealed_header` gained a `storage_proofs: &[StorageProof]` parameter** so producers commit the root alongside everything else when building the unsealed header.
- **`apply_block` Phase 1 check + `BlockError::StorageProofRootMismatch`.** Runs before per-proof verification (defense in depth, same posture as the other body roots).
- **Order semantics — producer-emit, not sorted.** The chain pays yield to the first proof that lands per commitment; sorting would lose that alignment and force the applier to re-sort just to verify the header. Per-commitment duplicates are rejected separately, so emit order is the only ordering choice across distinct commitments.
- **TS-parity golden vector.** Two hand-built proofs (`p0`: 0-sibling boundary; `p1`: 2-sibling with mixed `right_side`) pin leaf hashes + Merkle root. See [`docs/interop/TS_STORAGE_PROOF_ROOT_GOLDEN_VECTORS.md`](./interop/TS_STORAGE_PROOF_ROOT_GOLDEN_VECTORS.md).

### Test matrix (delivered)

- ✓ Empty list → zero sentinel.
- ✓ Leaf is deterministic (same proof → same hash).
- ✓ Leaf changes with proof content (commit_hash, chunk, siblings).
- ✓ Adding a proof moves the root.
- ✓ Order across proofs is committed (Merkle structure).
- ✓ Leaf domain-separated (`MFBN-1/storage-proof-leaf` not confusable with any other dhash domain).
- ✓ `apply_block` rejects a header whose `storage_proof_root` doesn't match the body (legacy / no-validator path).
- ✓ Tampered `header.storage_proof_root` in a fully BLS-signed block rejected.
- ✓ Positive path: `storage_proof_flow_at_genesis_plus_block1` builds a real proof, threads it through `build_unsealed_header` + `seal_block`, and the chain accepts it.
- ✓ TS-parity golden vector pinned.

### Closed the "header binds every body element" invariant

After M2.0.2, the header commits to:

```text
tx_root, bond_root, slashing_root, validator_root, storage_proof_root, storage_root, utxo_root
```

— every input the state machine consumes, plus the post-block accumulator. The only structural exception is `producer_proof`, which is *part of* the header (the BLS aggregate signs over everything else).

See the full design note in [`docs/M2_STORAGE_PROOF_ROOT.md`](./M2_STORAGE_PROOF_ROOT.md).

### Deferred

- **TS-side reference port for `storage_proof_leaf_hash` + `storage_proof_merkle_root`.** Same pattern as the other M2.0.x vectors — Rust pins the bytes; TS mirrors.
- **Sparse-Merkle variant.** A future `mfn-light` could use a sparse storage-proof root keyed by `commit_hash` for log-size "did commitment C have a proof land in block N?" audits.

---

## Milestone M2.0.3 — `mfn-node` crate skeleton (✓ shipped)

**Why it was next.** With M2.0.x done the consensus surface is **finished as a specification**: every body element is header-rooted, every header is BLS-signed by a quorum, every validator-set transition is authenticated, every byte format is canonical. The next strategic question is "how do we go from STF-in-a-test-harness to running-chain-in-a-process?" — and the answer starts with extracting the live-chain orchestration from the test harness and into a real, dedicated crate. M2.0.3 lands that crate with the smallest useful artifact: an in-memory `Chain` driver.

### What shipped

- **New workspace member `mfn-node`** ([`mfn-node/`](../mfn-node/) — Cargo.toml, lib.rs, README, src/, tests/).
- **`Chain` driver** in [`mfn-node::chain`](../mfn-node/src/chain.rs):
  - Owns a [`ChainState`]; applies blocks sequentially through `apply_block`.
  - Public read-only accessors: `tip_height`, `tip_id`, `genesis_id`, `validators`, `total_stake`, `treasury`, `state`.
  - Cheap diagnostic snapshot via [`ChainStats`].
  - Apply API: `apply(&block) -> Result<[u8; 32], ChainError>`. On success the chain moves to the new tip; on failure the state is **byte-for-byte unchanged**.
- **`ChainConfig` + `ChainError`** typed wrappers around `GenesisConfig` / `BlockError`. `ChainError::Reject` carries the proposed block id alongside the structured rejection list — RPC handlers and tests can log it without re-hashing.
- **Integration test [`tests/single_validator_flow.rs`](../mfn-node/tests/single_validator_flow.rs)**: a 1-validator chain runs through 3 real BLS-signed blocks via the driver, asserting every block moves height + tip_id and the validator set / treasury stay consistent. Plus a "replay is rejected, state preserved" test that demonstrates the driver's never-partially-commit contract.

### Design — why a separate crate?

`mfn-consensus` is the **specification**: STF + canonical wire formats. It must remain library-pure (no IO, no async, no clock) so it can be ported to a future `mfn-light` crate, a `mfn-wasm` binding, and any number of independent implementations.

`mfn-node` is the **first orchestration layer**. It tracks the live chain tip, owns `ChainState`, and is where mempool / P2P / RPC will eventually attach. Even at the skeleton stage that separation matters: a light client wants `apply_block` but not a `Chain` driver, and a daemon wants a `Chain` driver but shouldn't be reimplementing one against the spec.

### Test matrix (delivered, 10 tests)

- ✓ `from_genesis_lands_at_height_zero` — construction → `tip_height = Some(0)`, `tip_id == genesis_id`, empty validator set.
- ✓ `apply_two_empty_blocks_in_sequence` — back-to-back empty-block application advances height + tip_id deterministically.
- ✓ `block_with_wrong_prev_hash_is_rejected_state_untouched` — bad-prev-hash rejected; `ChainStats` snapshot unchanged after.
- ✓ `block_with_wrong_height_is_rejected` — bad-height rejected; state preserved.
- ✓ `stats_track_block_application` — `ChainStats` reflects post-block state.
- ✓ `genesis_is_deterministic_across_constructions` — same config → same genesis_id; same `ChainStats`.
- ✓ `tip_id_equals_genesis_id_at_construction` — invariant at height 0.
- ✓ `one_validator_three_blocks_advance_through_chain_driver` — full BLS-signed end-to-end loop.
- ✓ `chain_stats_agree_with_individual_accessors_after_run` — snapshot ↔ accessor parity after 3 blocks.
- ✓ `replaying_a_block_is_rejected_state_preserved` — never-partially-commit contract.

### What's deliberately *not* in M2.0.3

These are the next M2.x sub-milestones (each scoped to be small enough to land "small but right"):

- **Producer-helper module** — wraps the consensus-layer building blocks into a clean three-stage protocol. **Shipped in M2.0.4 below.**
- **Light-header-verification primitive** — given a trusted validator set, verify a header's `validator_root`, producer-proof, and BLS aggregate. Building block for `mfn-light`. **Shipped in M2.0.5 below.**
- **`mfn-light` crate skeleton** — header-chain follower with chain linkage + cryptographic verification, stable validator set. **Shipped in M2.0.6 below.**
- **Light-client body verification** — adds `apply_block(&Block)` that re-derives `tx_root` / `bond_root` / `slashing_root` / `storage_proof_root` from the body and matches them against the (now-authenticated) header. **Shipped in M2.0.7 below.**
- **M2.0.8 — Light-client validator-set evolution** — walk `block.bond_ops` / `block.slashings` / pending-unbond settlements / liveness slashes to derive the next trusted validator set. First "long-running light client" milestone.
- **Mempool primitives** — pending-tx admission, fee ordering, replace-by-fee. Pure library, attaches around `Chain`.
- **Persistent store (`mfn-node::store`)** — RocksDB-backed deterministic chain-state persistence + snapshot/replay.
- **RPC server (`mfn-node::rpc`)** — JSON-RPC + WebSocket. Block / tx / balance / storage-status queries.
- **Daemon binary (`bin/mfnd`)** — the entrypoint that wires it all together.

Each will be its own commit. The user-stated principle ("commit and push periodically when something whole is done no matter how big or small") makes this the right shape.

---

## Milestone M2.0.4 — Block-producer helpers in `mfn-node` (✓ shipped)

**Why it was next.** M2.0.3 landed the chain *consumer* (`Chain::apply`). The natural complement is the chain *producer*: a clean library that takes a chain state + producer keys + body inputs and returns a `Block` ready to apply. Without this, every test, RPC handler, and future producer loop has to reimplement ~100 lines of producer-proof + vote + aggregate + seal boilerplate. With this, the operation is one or three function calls.

### What shipped

- **`mfn-node::producer` module** ([`mfn-node/src/producer.rs`](../mfn-node/src/producer.rs)).
- **Three-stage protocol** mirroring the actual consensus flow:
  1. [`producer::build_proposal`] — slot-eligible producer builds an unsealed header committing every body element, runs the VRF + ed25519 producer proof, returns a [`BlockProposal`].
  2. [`producer::vote_on_proposal`] — any committee member BLS-signs the proposal's `header_hash` via `cast_vote`, returns a `CommitteeVote`.
  3. [`producer::seal_proposal`] — producer aggregates collected votes via `finalize`, packages the `FinalityProof`, and `seal_block`s the result.
- **One-call convenience** [`producer::produce_solo_block`] for the single-validator case (producer = sole voter). Runs all three stages in one call.
- **`BlockInputs`** — caller-provided body lists (`txs`, `bond_ops`, `slashings`, `storage_proofs`) + slot timing.
- **`BlockProposal`** — the byte string a producer would send out on the P2P wire for voters to sign over.
- **`ProducerError`** with the *non-eligibility* case carved out as a typed variant (`NotSlotEligible { height, slot }`) so callers can distinguish "skip this slot" from "something is broken".

### Refactored

The integration test [`tests/single_validator_flow.rs`](../mfn-node/tests/single_validator_flow.rs) is now ~80 lines shorter — `produce_and_apply` collapsed from ~70 lines of producer-proof + vote + aggregate + seal boilerplate to a 10-line `BlockInputs { … }` + `produce_solo_block` call. This is the load-bearing demonstration that the new API is actually useful.

### Test matrix (delivered, +4 net new tests)

- ✓ `produce_solo_block_yields_an_applyable_block` — the headline contract: the helper produces a block that `chain.apply` accepts.
- ✓ `produce_solo_block_five_in_a_row` — 5-block sequential production drives the chain forward; block ids change each time.
- ✓ `build_proposal_refuses_ineligible_producer` — stake-zero validator → typed `NotSlotEligible` error (not a panic, not an opaque error).
- ✓ `staged_api_equivalent_to_solo_helper` — same chain → same block-id whether you use the staged API or the convenience function (determinism contract).

### Why a three-stage protocol?

The future P2P producer loop will *not* do all three stages locally:

- A slot-eligible validator builds + broadcasts a `BlockProposal` (stage 1).
- Other committee members receive it, vote, and ship their `CommitteeVote` back over the wire (stage 2).
- The producer (or any node with a quorum of votes) aggregates and seals (stage 3).

Building the API as three stages from day one means the P2P layer can be a pure transport — it never needs to crack open intermediate state. The solo helper is just sugar over the same path for tests and single-node deployments.

---

## Milestone M2.0.5 — Light-header verification primitive (✓ shipped)

**Why it was next.** Through M2.0–M2.0.2 every block-body element became header-bound; M2.0.3 + M2.0.4 made it possible to *produce* and *consume* those blocks via the `mfn-node::Chain` driver. The remaining question — "given just a header and a trusted starting validator set, can a stateless verifier confirm a real quorum signed this header?" — is the user-facing payoff of the whole M2.0.x series, and the foundational primitive for `mfn-light` (and, transitively, for mobile/browser wallets, bridges, and audit tooling).

`apply_block` already runs every cryptographic check the verifier needs, but it requires a full `ChainState` and *mutates* it. That's the wrong shape for a light client. M2.0.5 carves the cryptographic half out into a pure, allocation-cheap function.

### What shipped

- **`mfn_consensus::header_verify` module** ([`mfn-consensus/src/header_verify.rs`](../mfn-consensus/src/header_verify.rs)).
- **`verify_header(header, trusted_validators, params)`** — single-hop pure-function header verification. No IO, no async, no clock, no state mutation. Returns a typed `Result<HeaderCheck, HeaderVerifyError>`.
- **Five checks, in order:**
  1. `trusted_validators` is non-empty → otherwise `EmptyTrustedSet`.
  2. `validator_set_root(trusted_validators) == header.validator_root` (the trust anchor) → otherwise `ValidatorRootMismatch`.
  3. `header.producer_proof` is non-empty (genesis-style headers are the trust anchor, not light-verifiable) → otherwise `GenesisHeader`.
  4. `header.producer_proof` decodes as a `FinalityProof` → otherwise `ProducerProofDecode(_)`.
  5. `verify_finality_proof(…)` returns `ConsensusCheck::Ok` (covers producer VRF + ed25519 + slot eligibility + BLS aggregate over the header signing hash + signing-stake-bitmap consistency + quorum threshold) → otherwise `FinalityRejected(_)`.
- **`HeaderCheck`** — successful-verification stats (producer index, signing stake, total stake, computed quorum, validator count). Exposed so callers writing stricter quorum policies than the chain's 2/3 can compare numbers directly.
- Lives in `mfn-consensus` (not in a new crate) deliberately: the verification logic is part of the consensus *spec*. A future `mfn-light` crate will wrap this with chain traversal / persistence / sync.

### Test matrix (delivered, +13 net new tests)

Unit (10, in `mfn-consensus`):
- ✓ `verify_header_accepts_real_signed_block` — happy path.
- ✓ `verify_header_rejects_tampered_validator_root` — `ValidatorRootMismatch`.
- ✓ `verify_header_rejects_wrong_trusted_set` — different stake → different root → `ValidatorRootMismatch`.
- ✓ `verify_header_rejects_tampered_producer_proof` — BLS aggregate breaks.
- ✓ `verify_header_rejects_empty_trusted_set` — typed `EmptyTrustedSet`, not panic.
- ✓ `verify_header_rejects_empty_producer_proof` — typed `GenesisHeader`, not cryptic.
- ✓ `verify_header_rejects_truncated_producer_proof` — `ProducerProofDecode(_)`.
- ✓ `verify_header_rejects_tampered_height` — header-hash domain change → `FinalityRejected(_)`.
- ✓ `verify_header_rejects_tampered_slot` — VRF/producer-sig domain change → `FinalityRejected(_)`.
- ✓ `verify_header_is_deterministic` — repeated calls byte-identical.

Integration (3, in `mfn-node/tests/light_header_verify.rs`):
- ✓ `verify_header_agrees_with_apply_block_across_three_blocks` — the load-bearing invariant: for each of 3 real BLS-signed blocks, `verify_header` accepts iff `apply_block` accepts.
- ✓ `verify_header_works_with_post_block_trusted_set_when_no_rotation` — validator-set-stability invariant.
- ✓ `tampered_header_is_rejected_by_both_verify_header_and_apply_block` — symmetric rejection across both layers; clean block still applies afterwards.

### What's *not* in M2.0.5

- **Multi-hop chain following.** `verify_header` covers one header against one trusted set. Evolving the trusted validator set as blocks rotate / slash / unbond is the future `mfn-light` crate.
- **Body verification.** Recomputing `tx_root`, `bond_root`, `slashing_root`, `storage_proof_root` from a body and comparing to the header is a separate layer on top of existing `*_merkle_root` helpers. **Shipped in M2.0.7 below.**
- **Header chain linkage.** Confirming `prev_hash` and `height` continuity is the caller's job — chained headers are verified by whoever decides which chain to follow.
- **Persistence / RPC / P2P.** Daemon concerns. Future milestones.

### What this unlocks

- **`mfn-light` crate.** The natural next milestone: a header-chain follower built on `verify_header` that ingests headers + body deltas, evolves the trusted set across rotations, and exposes `verify_tip(...)`.
- **WASM / mobile wallets.** Compile `mfn-consensus` to WASM, ship `verify_header` to the client, give it a trusted genesis validator set, let it independently verify every tip a remote node claims.
- **Bridges.** A reader on chain X can verify Permawrite headers given the canonical genesis + a follower for validator-set evolution.

See [`docs/M2_LIGHT_HEADER_VERIFY.md`](./M2_LIGHT_HEADER_VERIFY.md) for the full design note.

---

## Milestone M2.0.6 — `mfn-light` crate skeleton: header-chain follower (✓ shipped)

**Why it was next.** M2.0.5 surfaced the pure-function `verify_header` primitive. The natural first consumer is a chain follower: a struct holding a tip pointer + a trusted validator set, applying headers one at a time. That's the foundational shape every downstream light-client artifact (browser wallet, WASM bindings, bridge contract, audit tool) will compose around.

`apply_block` + `Chain` in `mfn-node` give us the *full-node* orchestrator, owning a `ChainState`. `mfn-light` is the *light-client* orchestrator: same `mfn-consensus` spec crate, completely different state model. Tip pointer + trusted validators only — no UTXO tree, no storage tree, no validator-stats history.

### What shipped

- **`mfn-light`** — a new workspace crate. Dependency graph is intentionally pure-Rust (`mfn-crypto`, `mfn-bls`, `mfn-storage`, `mfn-consensus`, `thiserror`) — no `tokio`, no `rocksdb`, no `libp2p` — so the same code compiles to `wasm32-unknown-unknown`.
- **`LightChain`** struct holding `trusted_validators` + `params` + `tip_height` + `tip_id` + `genesis_id`.
- **`LightChain::from_genesis(LightChainConfig)`** — infallible constructor. Genesis is a trust anchor; the light client trusts the config by construction.
- **`LightChain::apply_header(&BlockHeader)`** — four checks in order: height monotonicity → prev_hash linkage → `verify_header` (M2.0.5) → tip advance. Returns `AppliedHeader { block_id, check }` with the `HeaderCheck` stats from the underlying verifier. State is byte-for-byte untouched on any failure.
- **Typed `LightChainError`**: `HeightMismatch`, `PrevHashMismatch`, `HeaderVerify { height, source: HeaderVerifyError }`.
- **Read-only accessors**: `tip_height`, `tip_id`, `genesis_id`, `trusted_validators`, `params`, `total_stake`, `stats`.

### Architectural insight surfaced

Two `GenesisConfig`s with identical `initial_outputs` / `initial_storage` / `timestamp` but **different `validators`** produce **byte-for-byte identical genesis headers** — `build_genesis` deliberately commits to the *pre-genesis* (empty) validator set in `validator_root`, since the genesis block itself *installs* the initial set. Consequence: `prev_hash` linkage alone does **not** distinguish parallel chains that share a minimal genesis. The defence-in-depth that catches cross-chain header injection is **M2.0's `validator_root` commitment** — every post-genesis header's `validator_root` reflects the set the producer was signing under, so a header from chain B is rejected by a light chain bootstrapped from chain A as `HeaderVerifyError::ValidatorRootMismatch`. This is exercised by `light_chain_rejects_header_from_different_chain`.

### Test matrix (delivered, +12 net new tests)

Unit (7, in `mfn-light/src/chain.rs`):
- ✓ `from_genesis_lands_at_height_zero` — tip = genesis_id, validator count + total stake match.
- ✓ `from_genesis_is_deterministic_across_constructions` — repeated construction → identical genesis_id / tip_id.
- ✓ `apply_header_accepts_real_signed_block` — producer-side-built real signed block 1 applies cleanly.
- ✓ `apply_header_rejects_wrong_prev_hash` — typed `PrevHashMismatch`, state preserved.
- ✓ `apply_header_rejects_wrong_height` — typed `HeightMismatch`, state preserved.
- ✓ `apply_header_rejects_tampered_validator_root` — typed `HeaderVerify { ValidatorRootMismatch }`, state preserved.
- ✓ `stats_agree_with_individual_accessors` — `stats()` matches every accessor.

Integration (5, in `mfn-light/tests/follow_chain.rs`):
- ✓ `light_chain_follows_full_chain_across_three_blocks` — load-bearing: a `LightChain` and a full `mfn_node::Chain` reach identical tips on every block of a real 3-block chain.
- ✓ `light_chain_rejects_skipped_header_with_state_preserved` — applying block 2 to a light chain at h=0 → typed error, state preserved.
- ✓ `light_chain_rejects_header_from_different_chain` — cross-chain header injection caught by `validator_root` mismatch (architectural-insight test).
- ✓ `light_chain_recovers_after_rejected_header` — tampered header rejected, state preserved, clean block applies on top.
- ✓ `light_chain_surfaces_validator_root_mismatch_through_typed_error` — `HeaderVerifyError::ValidatorRootMismatch` surfaces through the wrapped `LightChainError::HeaderVerify { source }`.

### What's intentionally *not* in M2.0.6

- **Body verification** — shipped in M2.0.7 below.
- **Validator-set evolution across rotations** — shipped in M2.0.8 below. M2.0.6 / M2.0.7 follow a chain through any *stable-validator window*; M2.0.8 mirrors `mfn-consensus`'s evolution byte-for-byte via a shared pure-helper module so light clients follow indefinitely.
- **Re-org / fork choice** — single canonical header chain.
- **Persistence** — state lives in memory.

### What this unlocks

- **M2.0.7 + M2.0.8** — shipped. The production-ready light client now follows the chain across arbitrary rotations.
- **WASM bindings (`mfn-wasm`)** — the dependency graph is intentionally pure-Rust so this is just `wasm-bindgen` glue away.
- **Cross-chain bridges** — same `verify_header` + chain follower, embedded in another chain's smart contracts.

See [`docs/M2_LIGHT_CHAIN.md`](./M2_LIGHT_CHAIN.md) for the full design note.

---

## Milestone M2.0.7 — Light-client body verification (✓ shipped)

**Why it was next.** After M2.0.6 a light client could prove a *header* was BLS-signed by a quorum of the trusted validator set, but it couldn't prove a *delivered body* was the body the producer signed over. A malicious peer could ship a genuine header next to a substituted body — replaced txs, dropped storage proofs, swapped bond ops — and a header-only client would have no way to notice. M2.0.7 closes that gap.

The full header-binds-body invariant was structurally in place since M2.0.2 (the producer's BLS aggregate signs over `header_signing_hash`, which folds `tx_root` / `bond_root` / `slashing_root` / `storage_proof_root`). M2.0.7 is the **verification half**: a stateless function that recomputes those four roots from a delivered `&Block` and checks each against the header. The result: every `(header, body)` pair the light client accepts is cryptographically pinned to the same producer endorsement.

### What shipped

- **`mfn-consensus::verify_block_body(&Block) -> Result<(), BodyVerifyError>`** — pure, stateless. Re-derives `tx_root` / `bond_root` / `slashing_root` / `storage_proof_root` from `block.<field>` and matches each against `block.header`. Lives in the same module as `verify_header` (`mfn-consensus::header_verify`) — the two halves of the "light-client verification primitives" surface.
- **Typed `BodyVerifyError`** — one variant per root (`TxRootMismatch`, `BondRootMismatch`, `SlashingRootMismatch`, `StorageProofRootMismatch`), each carrying `{ expected, got }` for diagnostics / peer scoring.
- **`mfn-light::LightChain::apply_block(&Block) -> Result<AppliedBlock, LightChainError>`** — the full-block analogue of `apply_header`. Five steps in order: height monotonicity → prev_hash linkage → `verify_header` → `verify_block_body` → tip advance. State is byte-for-byte untouched on any failure.
- **New `AppliedBlock` outcome type** + **new `LightChainError::BodyMismatch { height, source: BodyVerifyError }`** variant.
- **Ordering rationale documented**: header verification runs *before* body verification so the distinction "forged header" vs "right header, wrong body" surfaces cleanly through different error variants.

### Test matrix (delivered, +20 net new tests, 374 → 394 total)

`mfn-consensus::header_verify` unit (+8):
- ✓ `verify_block_body_accepts_consistent_block` — real signed block passes.
- ✓ `verify_block_body_rejects_tampered_tx_root` — flipping a byte in `header.tx_root` → typed `TxRootMismatch { expected, got }`.
- ✓ `verify_block_body_rejects_tampered_bond_root` — typed `BondRootMismatch`.
- ✓ `verify_block_body_rejects_tampered_slashing_root` — typed `SlashingRootMismatch`.
- ✓ `verify_block_body_rejects_tampered_storage_proof_root` — typed `StorageProofRootMismatch`.
- ✓ `verify_block_body_rejects_tampered_tx_body` — body-side tamper (push duplicate tx) → typed `TxRootMismatch`.
- ✓ `verify_block_body_is_deterministic` — repeated verification returns identical `Ok(())`.
- ✓ `verify_block_body_accepts_genesis` — empty-body genesis is consistent.

`mfn-light` unit (+7):
- ✓ `apply_block_accepts_real_signed_block` — real signed block 1 applies cleanly.
- ✓ `apply_block_rejects_tampered_tx_root_in_header` — header-field tamper → `HeaderVerify` (BLS signature breaks first).
- ✓ `apply_block_rejects_tampered_tx_body` — body-only tamper → `BodyMismatch { TxRootMismatch }`, state preserved.
- ✓ `apply_block_rejects_wrong_prev_hash` — linkage fires first.
- ✓ `apply_block_rejects_wrong_height` — linkage fires first.
- ✓ `apply_block_chains_across_two_blocks` — two real blocks apply via `apply_block`, tip advances.
- ✓ `apply_header_and_apply_block_agree_on_tip` — both paths produce identical final stats for clean chains.

`mfn-light` integration (+5):
- ✓ `light_chain_apply_block_follows_full_chain_across_three_blocks` — load-bearing: `LightChain` via `apply_block` mirrors `mfn_node::Chain` tip-for-tip across 3 real blocks.
- ✓ `light_chain_apply_block_rejects_body_tx_tamper_with_state_preserved` — pushing a duplicate tx into `block.txs` → typed `BodyMismatch { TxRootMismatch }`, state preserved.
- ✓ `light_chain_apply_block_rejects_storage_proof_body_tamper` — injecting a stray `StorageProof` → typed `BodyMismatch { StorageProofRootMismatch }`, state preserved.
- ✓ `light_chain_apply_block_recovers_after_body_rejection` — rejected tampered body preserves state, pristine body applies on top.
- ✓ `light_chain_apply_block_and_apply_header_agree_on_clean_chains` — body verification is *additive*: clean chains produce identical stats via either method.

### What's intentionally *not* in M2.0.7

- **`storage_root` / `utxo_root` verification.** Both are state-dependent (`storage_root` needs cross-block dedup against the chain's `storage` map; `utxo_root` is the cumulative accumulator). They're already cryptographically covered by the BLS aggregate signing `header_signing_hash`; a forged block can't smuggle either past `verify_header`. Independent re-derivation is out of scope for stateless verification.
- **Validator-set evolution** — still the M2.0.8 slice.
- **Re-org / fork choice** — single canonical chain.
- **Persistence** — state in memory.

### What this unlocks

- **M2.0.8 — validator-set evolution.** With body verification working, the light client now has trusted access to `block.bond_ops` and `block.slashings`. The next step is to actually walk those deltas and evolve `trusted_validators` across rotations — the first real "long-running light client" milestone.
- **Wallets.** A wallet has cryptographic proof that the txs in a block are the ones the producer signed over, so it can confidently extract its outputs without trusting the serving node's body.
- **Storage-availability auditing.** Trusted access to `block.storage_proofs` enables an audit client to replay SPoRA sampling locally and verify the network's storage availability claims.
- **Bridges / oracles.** A reader on another chain can prove "Permawrite block N at height H contains tx T" by relaying the header + body + Merkle path, all verifiable with the M2.0.5 + M2.0.7 primitives.

See [`docs/M2_LIGHT_BODY_VERIFY.md`](./M2_LIGHT_BODY_VERIFY.md) for the full design note.

---

## Milestone M2.0.8 — Light-client validator-set evolution (✓ shipped)

**Why it was next.** M2.0.5 / M2.0.6 / M2.0.7 let a light client follow a chain through *stable-validator windows*. The instant the chain rotates — a `BondOp::Register` adds a validator, an equivocation slashing zeros one, an unbond settles, a liveness slash reduces a stake — the next block's `verify_header` fails with `ValidatorRootMismatch` because the chain's new validator_root commits to a set the light client doesn't know about. M2.0.8 closes that gap: light clients now follow indefinitely from a single genesis bootstrap.

The architectural keystone: the four phases that mutate the validator set inside `apply_block` (equivocation slashing, liveness slashing, bond ops, unbond settlements) are **extracted into a shared `mfn-consensus::validator_evolution` module**. Both the full node (`apply_block`) and the light client (`LightChain::apply_block`) call the same pure functions, so drift between the two implementations is **structurally impossible**.

### What shipped

- **`mfn-consensus::validator_evolution`** — new module with four pure helpers + the `BondEpochCounters` / `EquivocationOutcome` / `LivenessOutcome` / `BondOpError` types. Bitmap extractor (`finality_bitmap_from_header`) so light clients can drive Phase B without re-decoding the producer proof.
- **`mfn-consensus::block::apply_block` refactor** — four inlined phases replaced with single-line calls to the new helpers. Byte-for-byte equivalent to the pre-refactor implementation: **all 161 mfn-consensus unit tests + 14 integration tests pass unchanged**.
- **`mfn-light::LightChain` extension** — shadow state (`validator_stats`, `pending_unbonds`, `BondEpochCounters`, `bonding_params`) initialized in `from_genesis` to mirror `apply_genesis` byte-for-byte. `apply_block` now runs the four evolution phases on staging copies and atomically commits.
- **`LightChainError::EvolutionFailed`** — new variant for the defense-in-depth path where bond ops are invalid (would only fire under Byzantine quorum).
- **`AppliedBlock` extensions** — now reports `validators_added`, `validators_slashed_equivocation`, `validators_slashed_liveness`, `validators_unbond_settled` so callers can audit per-block deltas.

### Test matrix

- **8 new mfn-consensus unit tests** for the four phase helpers (no-op / happy path / edge cases).
- **8 new mfn-light unit tests** for `from_genesis` shadow-state initialization, per-block stat advance, drift detection via next-block `validator_root` check, and the headline `validator_set_root` invariant.
- **2 new mfn-light integration tests**:
  - `light_chain_follows_register_then_unbond_rotation_across_five_blocks` — a real 5-block scenario (Register v1 at block 1, Unbond v1 at block 3, settle at block 5) with `validator_set_root` agreement asserted after every block.
  - `light_chain_rejects_tampered_bond_op_with_body_mismatch` — defense-in-depth check that body-root verification fires *before* evolution.

### What's intentionally *not* in M2.0.8

- **Light-client surfaces for slashing audit.** The light client currently mirrors `apply_block`'s soft-skip semantics for invalid slashings (advances the chain, doesn't surface them as errors). A future slice could add an `EquivocationCheck`-style outcome to `AppliedBlock`.
- **Liveness audit.** The bitmap is BLS-signed-over in `header_signing_hash`, so the chain itself enforces its faithfulness. A future slice could surface the decoded bitmap on `AppliedBlock::voted_indices`.
- **Persistence.** Shadow state lives in memory.
- **Re-org / fork choice.** Single canonical chain.

### What this unlocks

- **Trustless long-running light clients.** Wallets, dashboards, and bridges can follow Permawrite indefinitely from a single genesis bootstrap.
- **M2.1 — Multi-node testnet.** Light clients can join the testnet as first-class observers.
- **M2.2 — Light-client P2P sync.** Header-first / body-on-demand sync protocols can be built on top.
- **M2.3+ — In-browser wallets.** `mfn-light` is WASM-compatible and now follows rotations.

See [`docs/M2_LIGHT_VALIDATOR_EVOLUTION.md`](./M2_LIGHT_VALIDATOR_EVOLUTION.md) for the full design note.

---

## Milestone M2.x — Node daemon (`mfn-node`)

**Goal.** Bring the chain online. A daemon that:

- Listens for P2P peers and gossips blocks + txs.
- Maintains a mempool with replace-by-fee policy.
- Persists chain state to disk (RocksDB-based, deterministic).
- Exposes JSON-RPC for wallets.
- Runs the producer + voter logic when configured as a validator.

### Components

| Module | Purpose |
|---|---|
| `mempool.rs` | Pending-tx admission, fee ordering, eviction. |
| `network.rs` | libp2p / direct-TCP P2P gossip. Block + tx propagation. |
| `store.rs` | RocksDB-backed persistent chain state. Snapshot/replay/restore. |
| `rpc.rs` | JSON-RPC + WebSocket. Block, tx, balance, storage-status queries. |
| `runner.rs` | Block production loop, finality voting loop, mempool flush. |
| `bin/mfnd.rs` | The daemon entrypoint. |

### Phases

- **M2.1 — Single-node demo.** No P2P; just `apply_block` driven by an RPC harness. Validates the chain state machine works end-to-end in a long-running process.
- **M2.2 — Multi-node testnet.** Add P2P + mempool. Run a 3-validator local testnet that produces real finalized blocks.
- **M2.3 — Public testnet.** Documentation + bootstrapping nodes; invite external operators.

### Not in M2.x

- Light clients (M4).
- Cross-chain bridges (M5+).

---

## Milestone M3 — Wallet CLI (`mfn-wallet`)

**Goal.** A reference wallet that exercises every primitive: receives privacy txs, sends privacy txs, performs storage uploads, submits storage proofs (if operator-mode).

### Components

| Module | Purpose |
|---|---|
| `wallet.rs` | Keypair generation, address derivation, scanning. |
| `rpc-client.rs` | Talks to `mfn-node` over JSON-RPC. |
| `tx-builder.rs` | Wraps `mfn-consensus::sign_transaction` with decoy selection. |
| `bin/mfn-cli.rs` | CLI entrypoint: `mfn-cli send …`, `mfn-cli upload …`, etc. |

### Scope

- Stealth address generation + scanning.
- CLSAG-signed sends.
- Storage uploads (chunks, builds commitment, locks endowment).
- (Operator mode) Generates SPoRA proofs on a stored corpus.

---

## Milestone M4 — WASM bindings (`mfn-wasm`)

**Goal.** Run the same primitives in a browser.

The TypeScript reference implementation (`cloonan-group/lib/network`) exists for in-browser experimentation. WASM bindings let the *same Rust crate* power the browser, eliminating the cross-implementation drift risk.

### Use cases

- In-browser wallets (web extensions).
- Public demo pages.
- Light-client verification of finality proofs in browser.

### Not before M2

WASM bindings to a daemon-less Rust core are only useful when there's a daemon to talk to.

---

## Milestone M5 — Production hardening

These are work items that are individually small but cross-cutting:

- **Long-running emission/treasury simulation.** Drive `apply_block` for 10⁶ blocks with realistic tx mix; verify treasury never goes negative, emission rates match the curve.
- **Proptest fuzzing of `apply_block`.** Randomized inputs; reject any panic / inconsistency. Target: 24-hour fuzz campaign with no findings.
- **Independent cryptographic review.** External third-party audit of `mfn-crypto`, `mfn-bls`, `mfn-storage`, and `apply_block`.
- **Performance benchmarking.** Block throughput, tx verification rate, storage-proof verification rate. Compare against Monero / Arweave baselines.
- **Spec finalization.** Write a formal MFBN-1 RFC document for cross-implementation conformance testing.

---

## Tier-level rollouts

### Tier 1 → Tier 2

**What changes:** range proofs upgrade from Bulletproofs to **Bulletproof+** (Bünz et al. 2020). Smaller transcripts (~30% size reduction) at no security cost.

**What stays the same:** CLSAG, stealth addresses, Pedersen commitments, key images.

**Implementation lift:** ~500 LoC, ~20 tests. The bulletproof+ verifier is a small delta from the existing bulletproof verifier.

**When:** post-M2 (need a network running before optimizing transcript size becomes urgent).

### Tier 2 → Tier 3

**What changes:** transactions use **OoM proofs** ([`mfn_crypto::oom`](../mfn-crypto/src/oom.rs)) instead of CLSAG rings. The "ring" becomes the **entire UTXO accumulator** — proof asserts membership in the accumulator with log-size witness.

**What stays the same:** stealth addresses, Pedersen commitments, range proofs (Bulletproof+).

**Implementation lift:** ~2000 LoC, ~50 tests. Major. Includes:

- Wallet-side OoM proof generation (already implemented primitive; needs wallet integration).
- Chain-side OoM proof verification (already implemented primitive; needs `verify_transaction` integration).
- Decoy selection becomes degenerate — the "decoys" are *all unspent outputs*. Wallet simplification.
- Wire-format breaking change. Hard fork.

**When:** mid-term. The primitive is ready; the wallet + tx pipeline integration is what's left.

### Tier 3 → Tier 4

**What changes:** instead of one OoM proof per input per tx, blocks aggregate **all input proofs + all range proofs + all balance checks** into a single recursive SNARK. Verifier cost per block drops to constant.

**What stays the same:** the underlying mathematical guarantees.

**Implementation lift:** very large. Requires a deployed SNARK backend (likely STARK-based for transparency; alternately Halo2 / Nova for recursion). Months to years.

**When:** long-term. Speculative.

---

## What we deliberately don't have on the roadmap

- **Smart contracts (Solidity-style VM).** Out of scope. Permawrite is a payments + storage chain. Adding general-purpose compute would explode the attack surface and slow consensus. If general compute is needed, it lives off-chain with on-chain settlement.
- **Cross-chain bridges as a v1 feature.** Bridges are a major design surface in their own right. We'd rather ship a working standalone chain and let third-party bridges connect via the BLS finality proof.
- **Tail-emission-style governance tokens.** No governance NFTs, no DAO infrastructure. Parameter changes happen via hard forks with explicit community signaling, Bitcoin-style.
- **MEV protection beyond what's natural.** Privacy txs already hide tx contents, which structurally prevents most MEV. Beyond that, no explicit MEV-mitigation features at v1.

These are scope-discipline choices, not philosophical hostility. Each one is conceivable as a future upgrade if the network's needs evolve.

---

## How to follow progress

- **Repo-level:** the `main` branch is always green (CI gates: fmt + clippy + tests on Linux/macOS/Windows). Commits are small, frequent, and self-describing.
- **Crate-level:** each crate's README has its test count. Watch for it to grow.
- **Doc-level:** [`PORTING.md`](../PORTING.md) tracks the TS → Rust module porting status one row at a time.
- **Issue-level (future):** when GitHub issues open, they'll be labeled by milestone.

---

## See also

- [`OVERVIEW.md`](./OVERVIEW.md) — the project's vision
- [`ARCHITECTURE.md`](./ARCHITECTURE.md) — current technical state
- [`PRIVACY.md`](./PRIVACY.md), [`STORAGE.md`](./STORAGE.md), [`CONSENSUS.md`](./CONSENSUS.md), [`ECONOMICS.md`](./ECONOMICS.md) — subsystem deep dives
- [`GLOSSARY.md`](./GLOSSARY.md) — terminology
