# Roadmap

> **Audience.** Anyone trying to understand "what's done, what's coming, and in what order."
> The tier system maps the conceptual roadmap onto concrete code milestones.

---

## Where we are right now

| Layer | Crate | Tests | Status |
|---|---|---:|---|
| ed25519 primitives + ZK (+ **M2.0.15 `UtxoTreeState` codec**) | `mfn-crypto` | 154 | ✓ live |
| BLS12-381 + committee aggregation | `mfn-bls` | 16 | ✓ live |
| Permanent-storage primitives (+ **M2.0.2 storage-proof merkle root** + **M2.0.10 storage-commitment codec**) | `mfn-storage` | 44 | ✓ live |
| Chain state machine (SPoRA verify + liveness slashing + **M1 validator rotation** + **M1.5 BLS-authenticated Register** + **M2.0 validator-set merkle root** + **M2.0.1 slashing merkle root** + **M2.0.2 storage-proof merkle root** + **M2.0.5 light-header verifier** + **M2.0.7 light-body verifier** + **M2.0.8 shared validator_evolution helpers** + **M2.0.9 round-trippable header codec** + **M2.0.10 full-block codec** + **M2.0.15 chain-state checkpoint codec** + **M2.0.16 shared `checkpoint_codec` between light + chain checkpoints**) | `mfn-consensus` | 206 | ✓ live |
| Node-side glue (**M2.0.3 `Chain` driver** + **M2.0.4 producer helpers** + **M2.0.5 light-header agreement tests** + **M2.0.12 mempool** + **M2.0.13 storage-anchoring admission** + **M2.0.15 `Chain::checkpoint` / `Chain::from_checkpoint`** + **M2.1.0 `ChainStore` filesystem checkpoint store** + **M2.1.1 `mfnd` reference binary** + **M2.1.2 JSON genesis spec (`--genesis`)** + **M2.1.3 `mfnd step`** + **M2.1.4 mempool-aware step + `--blocks N`** + **M2.1.5 `mfnd --checkpoint-each`** + **M2.1.6 `mfnd serve` TCP `get_tip` / `submit_tx`** + **M2.1.6.1 serve `submit_tx` TCP integration tests** + **M2.1.7 `chain.blocks` append log + optional `synthetic_decoy_utxos` + serve `submit_tx` happy path** + **M2.1.8 JSON-RPC 2.0 response envelope on `serve`** + **M2.1.8.1 `submit_tx` array `params`** + **M2.1.9 `read_block_log_validated`** + **M2.1.10 `serve` `get_block`** + **M2.1.11 `serve` `get_block_header`** + **M2.1.12 `serve` `get_mempool`** + **M2.1.13 `serve` `get_mempool_tx`** + **M2.1.14 `serve` `remove_mempool_tx`** + **M2.1.15 `serve` `clear_mempool`** + **M2.1.16 `serve` `get_checkpoint`** + **M2.1.17 `serve` `save_checkpoint`** + **M2.1.18 `serve` `list_methods`**) | `mfn-node` | 160 | ✓ live (skeleton + mempool + checkpoint persistence + `mfnd` + genesis + solo step + narrow TCP serve + block sidecar + JSON-RPC responses) |
| Light-client chain follower (**M2.0.6 header-chain follower** + **M2.0.7 body-root verification** + **M2.0.8 validator-set evolution** + **M2.0.9 checkpoint serialization** + **M2.0.10 raw-block-byte sync proof** + **M2.0.16 shared `checkpoint_codec` import**) | `mfn-light` | 58 | ✓ live |
| Confidential wallet (**M2.0.11 stealth scan + transfer building** + **M2.0.14 storage-upload construction**) | `mfn-wallet` | 42 | ✓ live (skeleton) |
| Canonical wire codec | (in `mfn-crypto::codec`) | — | ✓ live (will extract) |
| **Total** | | **680** | All checks green (+ 2 ignored) |

**Posture.** We've built the consensus core *and* the validator-rotation layer. The `mfnd` binary exercises checkpoint load/save, can boot from a shared JSON genesis spec (`--genesis`), advances a solo devnet via `step` (mempool-aware, with `--blocks N` and optional `--checkpoint-each` for per-block durability) when operator seeds are set in the environment, persists an append-only **`chain.blocks`** log after each applied block (M2.1.7) with optional **validated replay** against the checkpoint tip (M2.1.9), and can **`serve`** a minimal TCP line protocol (`get_tip`, `submit_tx`, **`get_block`**, **`get_block_header`**, **`get_mempool`**, **`get_mempool_tx`**, **`remove_mempool_tx`**, **`clear_mempool`**, **`get_checkpoint`**, **`save_checkpoint`**, **`list_methods`**) whose responses follow **JSON-RPC 2.0** (M2.1.8: `jsonrpc`, `id`, `result` / structured `error`) with **`submit_tx`** accepting either object or one-element array **`params`** (M2.1.8.1) for local tools; **`get_block`** (M2.1.10) returns canonical block bytes from the validated log; **`get_block_header`** (M2.1.11) returns header bytes + `block_id` without the body; **`get_mempool`** (M2.1.12) returns `mempool_len` + sorted pending **`tx_ids`**, including after a successful **`submit_tx`** in subprocess tests; **`get_mempool_tx`** (M2.1.13) returns **`tx_hex`** for a pending id or **`MEMPOOL_TX_NOT_FOUND`** when absent; **`remove_mempool_tx`** (M2.1.14) evicts by id when present (`removed` + `pool_len`); **`clear_mempool`** (M2.1.15) drops every pending tx at once (`cleared_count` + `pool_len`); **`get_checkpoint`** (M2.1.16) returns in-memory [`Chain::encode_checkpoint`](../mfn-node/src/chain.rs) bytes as hex (`checkpoint_hex` + `byte_len`); **`save_checkpoint`** (M2.1.17) persists via [`ChainStore::save`](../mfn-node/src/store.rs) (IO errors **`-32004`**); **`list_methods`** (M2.1.18) returns a lexicographically sorted **`methods`** array of every implemented JSON-RPC method name (including **`list_methods`**); P2P, batching, HTTP/WebSocket RPC, and the wallet CLI remain on the roadmap below.

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

## Milestone M2.0.9 — Canonical header codec + LightChain checkpoint (✓ shipped)

**Why it was next.** M2.0.8 made light clients follow the chain indefinitely from a *running* state. But every M2.0.8 light client still had to start from genesis: there was no way to *save* the trusted state, snapshot it to disk, ship it to a peer, or restore it after a crash. M2.0.9 closes that gap. It also adds the missing inverse of `block_header_bytes` — `decode_block_header` — which is the foundation for every future wire-format consumer (P2P, RPC, dump-and-replay).

### What shipped

- **`mfn-crypto::domain::LIGHT_CHECKPOINT`** — new domain-separated hash tag (`MFBN-1/light-checkpoint`) used by the checkpoint integrity tag.
- **`mfn-consensus::decode_block_header`** — inverse of `block_header_bytes`. Typed `HeaderDecodeError` covers truncation, varint overflow, version-out-of-range, oversized producer-proof length, and trailing bytes. Property tests prove the codec has no dead bytes.
- **`mfn-light::checkpoint`** — new module containing the `CheckpointParts` bundle, the deterministic `encode_checkpoint_bytes` / `decode_checkpoint_bytes` codec, and a typed `LightCheckpointError`. Trailing `dhash(LIGHT_CHECKPOINT, payload)` tag catches arbitrary corruption. Cross-field invariants enforced on decode (`StatsLengthMismatch`, `DuplicateValidatorIndex`, `PendingUnbondsNotSorted`, `NextIndexBelowAssigned`, …).
- **`mfn-light::LightChain::{encode_checkpoint, decode_checkpoint}`** — thin methods marshalling the `LightChain`'s private state through `CheckpointParts`. Encoding is deterministic byte-for-byte; restore is bit-for-bit equal to the saved chain.

### Test matrix

- **7 new `mfn-consensus` unit tests** for the header codec (round-trip, empty `producer_proof`, every-prefix truncation, trailing bytes, version overflow, no-dead-bytes property, golden vector pinning the 274-byte genesis-shaped header).
- **13 new `mfn-light::checkpoint` unit tests** for the pure codec (empty round-trip, full surface, f64 bits round-trip, bad magic, version reject, payload + tag tamper, truncation, duplicate indices, `next_validator_index` invariant, invalid BLS PK, invalid payout flag, linear-size growth).
- **5 new `mfn-light::chain` unit tests** for the `LightChain`-level API (genesis round-trip, mid-chain resume, per-byte tamper rejection scan, public-accessor equality, deterministic encoded length).
- **3 new `mfn-light::tests::follow_chain` integration tests**, including the headline `light_chain_checkpoint_round_trips_mid_chain_and_resumes` — two parallel light chains follow a real `Chain` for 2 blocks, one is snapshotted to bytes and restored, both then follow the chain for 3 more blocks, and *every* `AppliedBlock` outcome, tip, validator-stat, bond-counter, and validator-set root must agree byte-for-byte at every step.

### What's intentionally *not* in M2.0.9

- **Full `Block` codec (`encode_block` / `decode_block`).** Shipped in M2.0.10 (see below).
- **Persistent storage adapter.** The crate produces bytes; whether a caller writes them to disk / S3 / IPFS / Arweave is intentionally outside `mfn-light`'s remit.
- **Multi-version codec.** Today version 1 is the only known version. When we bump it, the `version` switch in `decode_checkpoint_bytes` is the extension point.

### What this unlocks

- **Wallet UX.** Mobile / browser wallets can resume in milliseconds instead of replaying from genesis.
- **Light-client P2P.** Peers can ship signed `(checkpoint, header_chain)` pairs to bootstrap newly-joining clients fast.
- **Header-first sync.** `decode_block_header` is the foundation for the future "Headers" message protocol.
- **M2.0.10** — `TransactionWire` round-trip codec → full `Block::encode` / `Block::decode` (now shipped).

See [`docs/M2_LIGHT_CHECKPOINT.md`](./M2_LIGHT_CHECKPOINT.md) for the full design note.

---

## Milestone M2.0.10 — Canonical transaction + full-block wire codec (✓ shipped)

**Why it was next.** M2.0.9 gave the chain a round-trippable header and restartable light-client checkpoints, but the block *body* still lived only as in-memory Rust structs. That is not enough for P2P, disk persistence, raw-byte RPC, or a light client that receives `Block` bytes from an untrusted peer. M2.0.10 makes a finalized block a canonical byte string: encode once, ship anywhere, decode deterministically, and verify with the same header/body/root checks already implemented.

### What shipped

- **`mfn-storage::{encode_storage_commitment, decode_storage_commitment}`** — lossless full-struct storage-commitment codec. `storage_commitment_hash` still hashes the same field order; the new codec carries the complete commitment inside storage-bearing transaction outputs instead of collapsing it to a 32-byte hash.
- **`mfn-consensus::{encode_transaction, decode_transaction}`** — full `TransactionWire` codec covering tx version, tx public key, fee, `extra`, all CLSAG input rings + signatures, all output commitments + Bulletproof range proofs + encrypted amounts, and optional full storage commitments. `TxDecodeError` is typed (`VersionOutOfRange`, `InvalidStorageFlag`, `RingColumnLenMismatch`, `NonCanonicalBlob`, `TrailingBytes`, etc.).
- **Strict nested canonicality.** CLSAG and Bulletproof blobs are decoded and re-encoded to reject non-canonical tails. Storage commitments, slashing evidence, and storage proofs now enforce trailing-byte rejection. Storage-proof sibling-side flags are restricted to `0`/`1`.
- **`mfn-consensus::{encode_block, decode_block}`** — full `Block` codec:

```text
block_header_bytes(header)
varint(txs.len)             || blob(encode_transaction(tx))*
varint(bond_ops.len)        || blob(encode_bond_op(op))*
varint(slashings.len)       || blob(encode_evidence(evidence))*
varint(storage_proofs.len)  || blob(encode_storage_proof(proof))*
```

- **`BlockDecodeError`** — typed decode surface for header errors, body framing errors, per-section item errors (`Transaction`, `BondOp`, `Slashing`, `StorageProof`), oversize counts, and trailing bytes.
- **Allocation-hardening.** Attacker-controlled section counts are never passed into `Vec::with_capacity`; the decoder grows vectors only as bytes are successfully consumed, so malformed `2^64-1 items` claims fail as codec errors instead of aborting the process.

### Test matrix

- **5 new `mfn-storage::commitment` tests** for commitment codec round-trip, fixed 81-byte shape, every-prefix truncation rejection, trailing-byte rejection, and hash preservation after decode.
- **7 new `mfn-consensus::transaction` tests** for simple tx round-trip, multi-input + storage-bearing round-trip, raw-output round-trip, every-prefix truncation rejection, trailing-byte rejection, invalid storage-flag rejection, and exact storage-commitment preservation.
- **6 new `mfn-consensus::block` tests** for empty-body block round-trip, header-prefix invariant, trailing-byte rejection, every-prefix truncation rejection, huge-count allocation-hardening, and the 278-byte empty-body golden shape (274-byte header + four zero-count varints).
- **2 new `mfn-light::tests::follow_chain` integration tests**:
  - `block_codec_round_trips_real_blocks_and_feeds_light_chain` — produce real BLS-signed blocks with `mfn-node`, encode to bytes, decode with `decode_block`, then apply the decoded blocks to both `mfn-node::Chain` and `LightChain::apply_block`, asserting identical tips for 3 blocks.
  - `block_codec_rejects_real_block_trailing_bytes` — raw block bytes are self-delimiting and reject appended garbage before consensus verification.

### What this unlocks

- **P2P block gossip.** A block can now be the byte payload of a network message; peers decode it deterministically and then run `verify_header` / `verify_block_body` / `apply_block`.
- **Disk persistence.** A node can persist canonical block bytes and replay them later without bespoke serde or Rust-version-dependent struct layout.
- **Raw-byte light sync.** A light client can receive bytes, decode to `Block`, and feed the result into `LightChain::apply_block` — proven end-to-end by the new integration test.
- **RPC / archival APIs.** `get_block_bytes(height)` can become a stable API surface: clients verify the same bytes that consensus hashes.

See [`docs/M2_BLOCK_CODEC.md`](./M2_BLOCK_CODEC.md) for the full design note.

---

## Milestone M2.0.11 — `mfn-wallet`: confidential wallet primitives (✓ shipped)

**Why it was next.** Through M2.0.10 every consensus primitive was correct *and* canonical on the wire, but nothing in the workspace was **consumer-facing**. A `Chain` could apply blocks, a `LightChain` could verify them, the codec could round-trip every byte — but no piece of the system could answer the human-level question *"how much money do I have, and how do I send some to someone else?"*. M2.0.11 ships that piece.

### What shipped

- **`mfn-wallet` crate** — first consumer-facing crate in the workspace. Pure-Rust, IO-free, WASM-friendly. Depends on `mfn-consensus` + `mfn-crypto` + `mfn-storage`.
- **`Wallet`** — top-level state container holding `WalletKeys` + an owned-UTXO map + a key-image reverse index + a scan-height watermark.
- **`WalletKeys` + `wallet_from_seed`** — wraps `StealthWallet` and adds deterministic seed-based key derivation (`hash_to_scalar` with domain-separated `MFW_SEED_VIEW_V1` / `MFW_SEED_SPEND_V1` tags).
- **`OwnedOutput`** — compact record of every recovered output: one-time-address, Pedersen commitment, decrypted `(value, blinding)`, one-time spend scalar, **precomputed key image**, plus tx-id / output-idx / height bookkeeping. The eager key-image precomputation makes both *local* double-spend prevention and *cross-device* spend detection O(1).
- **`scan_transaction` / `scan_block`** — walk every output, run `indexed_stealth_detect`, decrypt the amount blob, **and** verify the on-chain Pedersen commitment opens to the decrypted `(value, blinding)`. The Pedersen-open check is the binding step that turns the XOR-pad-shaped `decrypt_output_amount` into a sound "this output is mine" predicate — without it, an attacker could grind `r_pub` values until our wallet mistakenly claims phantom UTXOs. Coinbase outputs use the same flow with a cheap deterministic-`r_pub` shortcut. Spends of owned UTXOs are detected by matching each tx input's key image against the wallet's index.
- **`build_transfer` + `TransferPlan`** — assemble CLSAG-signed transfer txs. Caller supplies a slice of `&OwnedOutput` inputs, a `TransferRecipient` list, a fee, a ring size, and a `DecoyCandidate<(P, C)>` pool. The helper samples decoys via `select_gamma_decoys`, picks a uniformly random `signer_idx` per input, builds the `InputSpec` ring, and delegates to `mfn_consensus::sign_transaction` for the RingCT ceremony.
- **`DecoyPoolBuilder` + `build_decoy_pool`** — assemble the `&[DecoyCandidate<RingMember>]` slice `select_gamma_decoys` expects. Walks `ChainState::utxo`, excludes the wallet's own UTXOs (and optionally the real input), and emits a height-sorted pool.
- **`Wallet::build_transfer`** — convenience method wrapping all of the above: greedy largest-first coin selection over owned UTXOs, automatic decoy-pool construction, automatic change-output to self, automatic local mark-spent so the next `build_transfer` doesn't double-spend before the tx mines.
- **`Wallet::ingest_block`** — the single mutation entry point. Calls `scan_block`, evicts spent owned UTXOs, inserts recovered outputs (plus their key images into the reverse index), advances the scan watermark.

### Test matrix (+28 tests, 460 → 488 passing workspace-wide)

- **4 keys tests** — seed determinism, seed independence, view/spend independence, `StealthPubKeys` round-trip.
- **5 owned tests** — Pedersen-open happy / wrong-value / wrong-blinding, key-image determinism + variance, `owned_balance` sum.
- **7 scan tests** — recover payment-to-us, skip payment-to-someone-else, find one of many outputs, recover our coinbase, skip others' coinbase, aggregate over a block, key-image marks spent, **Pedersen-open protects against grinding**.
- **8 wallet tests** — coinbase credits, idempotent on unrelated blocks, two-block accumulation, `select_inputs` largest-first / multi-input / insufficient-funds, `mark_spent_by_utxo_key` evicts + idempotent, ingest detects external spend by key-image match.
- **2 end-to-end integration tests** in `mfn-wallet/tests/end_to_end.rs`:
  - `wallet_round_trip_through_full_chain_and_light_chain` — drives `mfn_node::Chain` + `mfn_light::LightChain` through 4 blocks (3 coinbase-only + 1 Alice → Bob transfer). Both wallets and both chains end up at the same tip id; Bob's balance is exactly `transfer_value`; Alice's balance reflects `block4_emission + producer_fee − transfer_value − fee` against the pre-build_transfer baseline.
  - `wallet_rejects_transfer_when_below_balance` — pins the `InsufficientFunds` error path through the full `build_transfer` API.

### What this unlocks

- **`mfn-cli wallet`** — the next milestone wraps `Wallet` + a `ChainConfig` (or a `LightChainConfig`) into a command-line binary. `mfn-cli wallet new / scan / balance / send` becomes the canonical way to interact with a running testnet node.
- **Single-node demo with a real user.** Once the CLI ships, a single machine running `mfn-node` + `mfn-cli wallet` is a working *node + wallet* pair — the first time the chain is end-to-end useful to a human operator.
- **Mempool design pressure.** Having a real wallet that emits canonical `TransactionWire`s forces the next milestone (mempool admit + relay) to handle a concrete tx supply, not a hypothetical one.
- **WASM browser wallet.** Pure-Rust + IO-free means `wasm-pack build --target web` Just Works once we add a `wasm` feature flag — likely a follow-up milestone bundled with the first browser-wallet PoC.

See [`docs/M2_WALLET.md`](./M2_WALLET.md) for the full design note.

---

## Milestone M2.0.12 — `mfn-node::mempool`: in-memory transaction pool (✓ shipped)

**Why it was next.** M2.0.11 shipped a wallet that signs `TransactionWire`s. M2.0.4 shipped a producer that consumes `BlockInputs.txs` and seals blocks. Between them there was no holding pen — no place for a signed tx to wait until a producer was ready to include it, no place to reject conflicting submissions before they hit the chain, no place to enforce fee priority. M2.0.12 ships that holding pen as a pure, in-memory, deterministic primitive that the future P2P relay layer, persistent mempool, and RPC handlers will all attach to.

### What shipped

`mfn-node::mempool` adds **one new module + 18 new tests**:

- **`Mempool` struct** keyed by `tx_id` with an O(1) key-image reverse index. Stores wire-form txs plus cached metadata (`tx_id`, `fee`, key-image bytes, admission height).
- **`MempoolConfig`** — `max_entries` (size cap) + `min_fee` (local-policy floor).
- **`admit(tx, &ChainState)`** — eight gates, all-or-nothing:
  1. Reject coinbases (`inputs.is_empty()`).
  2. Reject storage-anchoring txs (typed `StorageTxsNotYetSupported`, deferred).
  3. Local min-fee policy.
  4. `verify_transaction` (CLSAG + range proofs + balance + within-tx ki dedup).
  5. Ring-membership chain guard against `state.utxo` (with `entry.commit == c` match).
  6. Cross-chain double-spend guard against `state.spent_key_images`.
  7. Mempool-internal key-image conflict → **replace-by-fee** (strictly-higher fee wins, ties rejected).
  8. Size-cap eviction (lowest-fee victim, only if new tx strictly outpays).
- **`drain(max)`** — pops up to `max` entries in highest-fee-first order with `tx_id` tie-break (byte-deterministic block bodies).
- **`remove_mined(&Block)`** — evicts entries whose key images appear in a newly-applied block. Idempotent for unrelated blocks.
- **`evict(tx_id)` / `clear()` / `iter()` / `contains()` / `get()`** — bookkeeping API.
- **Typed `AdmitError`** — 10 variants covering every reject path, each carrying enough context for an RPC layer to surface useful errors (`TxInvalid`, `RingMemberNotInUtxoSet`, `RingMemberCommitMismatch`, `KeyImageAlreadyOnChain`, `ReplaceTooLow`, `BelowMinFee`, `DuplicateTx`, `PoolFull`, `StorageTxsNotYetSupported`, `NoInputs`).
- **`AdmitOutcome`** — distinguishes `Fresh`, `ReplacedByFee { displaced }`, `EvictedLowest { evicted }` so future P2P relay can forward txs correctly.

### Test matrix

**Unit (15 tests in `mfn-node/src/mempool.rs`):**

- `admit_happy_path_fresh` — plain admission of a wallet-signed tx.
- `admit_rejects_coinbase_shaped_tx` — `NoInputs` for `inputs.is_empty()`.
- `admit_rejects_storage_anchoring_tx` — `StorageTxsNotYetSupported`.
- `admit_rejects_below_min_fee` — local policy floor enforced.
- `admit_rejects_unbalanced_tx` — post-hoc-mutated tx fails `verify_transaction`.
- `admit_rejects_ring_member_not_in_utxo_set` — ring members must be in chain UTXO set.
- `rbf_accepts_strictly_higher_fee` — RBF happy path.
- `rbf_rejects_equal_or_lower_fee` — equal fee = no replacement.
- `duplicate_tx_id_is_rejected` — idempotent re-submission surfaces typed error.
- `size_cap_evicts_lowest_fee_when_pool_full` — eviction policy under pressure.
- `drain_orders_by_fee_descending_then_tx_id` — fee priority + deterministic tie-break.
- `remove_mined_evicts_txs_with_block_key_images` — post-block cleanup.
- `remove_mined_is_idempotent_when_unrelated` — unrelated blocks are a no-op.
- `evict_by_id_returns_true_when_present` — manual eviction.
- `drained_tx_can_be_applied_to_chain` — bytes survive the mempool round-trip unchanged.

**Integration (3 tests in `mfn-node/tests/mempool_integration.rs`):**

- `wallet_to_mempool_to_producer_to_chain_round_trip` — full lifecycle: 3 coinbase blocks fund Alice, she signs a transfer to Bob, the tx goes through `Mempool::admit` → `drain` → `produce_solo_block` → `Chain::apply` → `LightChain::apply_block` → wallet ingest. Bob receives `transfer_value`; Alice's balance reflects `block_emission + producer_fee − transfer − fee`; both chains end at the same tip id.
- `mempool_evicts_tx_after_block_includes_it_via_remove_mined` — producer builds with a tx but doesn't drain; `remove_mined` evicts it after `apply`.
- `mempool_admit_after_chain_advanced_still_works` — tx signed at height 1, chain advanced to height 2, mempool admits at height 2 (ring members still valid, key images still unspent).

### What this unlocks

- **Complete tx submission path** without any test-only scaffolding.
- **Foundation for single-node daemon** — `loop { sleep(slot); drain; produce; apply; remove_mined; }`.
- **Foundation for P2P relay** — `Mempool::admit` is the gate; admitted txs are forwarded.
- **Foundation for RPC** — `submit_tx` is a thin wrapper around `Mempool::admit`; typed errors map to HTTP status codes.

See [`docs/M2_MEMPOOL.md`](./M2_MEMPOOL.md) for the full design note.

---

## Milestone M2.0.13 — Storage-anchoring transactions in the mempool (✓ shipped)

**Why it was next.** M2.0.12 advertised exactly one typed deferment: `AdmitError::StorageTxsNotYetSupported`. That made the privacy half of the chain end-to-end usable but left the permanence half disconnected from the submission pipeline. M2.0.13 closes that gap, turning the mempool into a *complete* admission primitive that gates both privacy spends and storage anchors on the same terms as `apply_block`.

### What shipped

- **A new step (6) in the admit gate** — for each output with `storage: Some(sc)`, the mempool now mirrors `apply_block` byte-for-byte: enforce replication bounds against `state.endowment_params`, compute `mfn_storage::required_endowment(size_bytes, replication, &params)` for each *new* anchor, sum into `tx_burden`, then require `treasury_share = fee * fee_to_treasury_bps / 10_000 ≥ tx_burden`. Already-anchored data roots (`state.storage.contains_key(&h)`) and within-tx duplicates (`seen_in_tx` `HashSet`) are silently skipped, exactly as on chain.
- **Four typed `AdmitError` variants** mirroring `mfn_consensus::BlockError`:
  - `StorageReplicationTooLow { tx_id_hex, output, got, min }`
  - `StorageReplicationTooHigh { tx_id_hex, output, got, max }`
  - `EndowmentMathFailed { tx_id_hex, output, reason }`
  - `UploadUnderfunded { tx_id_hex, burden, treasury_share, fee, fee_to_treasury_bps }`
- **Removed `AdmitError::StorageTxsNotYetSupported`** — small intentional API break, replaced by the four richer variants above.
- **No new dependencies** — `mfn-storage` was already in the closure; the new imports are `required_endowment` + `storage_commitment_hash`.

### Test matrix

**Unit (+8 tests; one replaced):**

- `admit_storage_tx_happy_path` — well-formed 1 KB / replication-3 / fee=100 → admits as `Fresh`.
- `admit_storage_tx_rejects_replication_too_low` — `replication=2` against `min=3` → `StorageReplicationTooLow`.
- `admit_storage_tx_rejects_replication_too_high` — `replication=33` against `max=32` → `StorageReplicationTooHigh`.
- `admit_storage_tx_rejects_underfunded` — same upload at `fee=1` → `UploadUnderfunded`.
- `admit_storage_tx_silently_skips_already_anchored_root` — pre-seeded `state.storage` → admits at `fee=1` because the burden is zero.
- `admit_storage_tx_silently_skips_within_tx_duplicate` — two outputs anchoring the same `data_root` in one tx → admits cleanly without double-counting.
- `admit_storage_tx_mixed_outputs_with_regular_payment` — one storage anchor + one plain payment → admits.
- `admit_storage_tx_burden_scales_with_size` — same fee, 16× the size → `UploadUnderfunded`.

**Integration (+3 tests):**

- `storage_tx_through_full_mempool_producer_chain_pipeline` — full pipeline: mempool admits → drain → producer builds block → chain applies → `state.storage[hash]` is populated → re-admission rejected via `KeyImageAlreadyOnChain`.
- `storage_tx_underfunded_is_rejected_by_mempool_before_producer` — proves the mempool catches what the chain catches, so the producer can't accidentally build an `UploadUnderfunded` block.
- `already_anchored_storage_tx_silently_skips_burden_in_mempool` — pre-seeded genesis with the storage commitment → a fresh tx anchoring the same `data_root` admits at `fee=1`.

### What this unlocks

- Permanence transactions ride the **same submission wire** as privacy spends. No special-case mempool, no separate storage daemon.
- The wallet can grow `build_storage_upload(...)` (M2.0.14) with confidence that its output will be admissible by both mempool and chain.
- A user-facing RPC built on M2.0.12 + M2.0.13 accepts uploads via the same `submit_tx` endpoint, with `AdmitError` driving HTTP status responses.
- The fusion of privacy and permanence is now **end-to-end testable at the submission layer** — same admit call gates both halves, enforcing the same economic relation (`treasury_share ≥ burden`) the chain enforces at block-application time.

See [`docs/M2_STORAGE_MEMPOOL.md`](./M2_STORAGE_MEMPOOL.md) for the full design note.

---

## Milestone M2.0.14 — `Wallet::build_storage_upload` (✓ shipped)

**Why it was next.** After M2.0.13, the mempool could admit both privacy spends and storage anchors on equal terms — but only `Wallet::build_transfer` existed in the wallet crate. Anyone wanting to actually upload data had to hand-construct a `sign_transaction` call with an `OutputSpec` carrying a `StorageCommitment`, with no decoy sampling, no coin selection, no change handling, and no typed errors for any of the mempool's rejection conditions. M2.0.14 promotes storage uploads to a *first-class wallet operation*, mirroring the API ergonomics and typed-error safety of the transfer path.

### What shipped

- **New module `mfn-wallet/src/upload.rs`** — low-level `build_storage_upload(plan)` adapter + `StorageUploadPlan` input struct + `UploadArtifacts` return type + the pure `estimate_minimum_fee_for_upload(...)` helper.
- **New `Wallet` methods**:
  - `Wallet::recipient()` — packages the wallet's view-pub + spend-pub into the canonical "send to self" handle.
  - `Wallet::build_storage_upload(data, replication, fee, anchor_recipient, anchor_value, chunk_size, ring_size, &chain_state, extra, rng)` — full high-level path: greedy coin selection, decoy pool, change output, CLSAG ceremony, RingCT seal.
  - `Wallet::build_storage_upload_with_blinding(...)` — same but pins the Pedersen blinding for deterministic uploads (tests, reproducible audit trails).
  - `Wallet::upload_min_fee(data_len, replication, &chain_state)` — convenience that reads endowment params + `fee_to_treasury_bps` straight from chain state.
- **Five new `WalletError` variants** that mirror every mempool / chain storage gate, raised **before** signing so the wallet never wastes CLSAG work or leaks key images on a doomed tx:
  - `UploadReplicationOutOfRange { got, min, max }`
  - `UploadUnderfunded { fee, treasury_share, burden, min_fee }` — the `min_fee` field gives the caller the exact value to retry with
  - `UploadEndowmentExceedsU64 { burden }`
  - `UploadTreasuryRouteDisabled`
  - `Endowment(EndowmentError)` + `Spora(SporaError)` — typed forwards from `mfn-storage`
- **`UploadArtifacts` returns more than the tx** — `BuiltCommitment` (Merkle tree + endowment blinding) for SPoRA chunk-serving + endowment-opening later, plus the computed `burden` and `min_fee` for wallet UX.

### Test matrix

**Unit (`mfn-wallet/src/upload.rs`, +11 tests):**

- `happy_path_anchors_data_and_returns_artifacts` — round-trip; storage commit on output[0]; blinding opens the Pedersen.
- `replication_below_min_rejected_with_typed_error` / `replication_above_max_rejected_with_typed_error`
- `fee_below_minimum_rejected_with_actionable_min_fee` — error carries the correct `min_fee`; paying it clears the gate.
- `fee_to_treasury_bps_zero_yields_typed_error_when_burden_positive`
- `empty_data_zero_burden_zero_min_fee_is_fine` — anchoring `&[]` is a valid commitment with zero burden.
- `estimate_minimum_fee_is_monotonic_in_size_at_fixed_replication`
- `estimate_minimum_fee_satisfies_gate_exactly` — for a 4×4 grid of (size, repl), `min_fee` clears the gate and `min_fee - 1` does not.
- `estimate_minimum_fee_rejects_replication_out_of_range`
- `insufficient_funds_on_unbalanced_inputs`
- `pinned_blinding_is_returned_for_later_endowment_opening`

**Integration (`mfn-wallet/tests/end_to_end.rs`, +3 tests):**

- `wallet_storage_upload_through_mempool_producer_and_chain` — full stack: Alice's wallet builds an upload → `Mempool::admit` accepts it as `Fresh` → producer drains + builds block 4 → `Chain::apply` anchors the commitment, asserting `state.storage[storage_commitment_hash(&art.built.commit)]` is populated with the correct `size_bytes`, `replication`, and `last_proven_height=4`. The `LightChain` follows in lockstep to the same tip id. Alice's balance reflects (block-4 emission + producer tip − fee) because anchor + change both come back to self.
- `wallet_storage_upload_rejects_insufficient_funds_before_signing` — coin selection fails before any signing work happens.
- `wallet_storage_upload_rejects_fee_too_low_before_signing` — wallet returns `UploadUnderfunded { min_fee }` with the exact actionable retry value.

### What this unlocks

- **The permanence half is end-to-end accessible through the wallet** — same API ergonomics as the transfer path. A consumer of `mfn-wallet` can permanently anchor data with one method call.
- The future `mfn-cli wallet upload` and WASM bindings have a real API to sit on top of.
- M2.0.15 (persistent chain state) and M2.1.0 (single-node daemon) now have the *complete* wallet surface to integrate against — both privacy and permanence operations are first-class.

See [`docs/M2_WALLET_UPLOAD.md`](./M2_WALLET_UPLOAD.md) for the full design note.

---

## Milestone M2.0.15 — `ChainState` checkpoint codec (✓ shipped)

**Why it was next.** After M2.0.14 the full privacy+permanence transaction surface is built — wallet, mempool, chain, light client. But every full-node `ChainState` still lives **entirely in memory**: a single process restart wipes the entire chain. The single-node daemon (M2.1.0) cannot ship without persistence; M2.0.15 is the deterministic IO-free byte codec that makes persistence possible. It's the same primitive M2.0.9 gave the `LightChain`, lifted to the full-node `ChainState`.

### What shipped

- **New module `mfn-consensus/src/chain_checkpoint.rs`** — the canonical wire codec for the full-node `ChainState` plus the chain's `genesis_id` pointer.
  - `ChainCheckpoint { genesis_id, state }` bundle type.
  - `encode_chain_checkpoint(&ChainCheckpoint) -> Vec<u8>` — deterministic, infallible.
  - `decode_chain_checkpoint(&[u8]) -> Result<ChainCheckpoint, ChainCheckpointError>` — strict; rejects every malformed shape with a typed variant (`BadMagic`, `UnsupportedVersion`, `Truncated`, `VarintOverflow`, `LengthOverflow`, `InvalidHeightFlag`, `StatsLengthMismatch`, `DuplicateValidatorIndex`, `NextIndexBelowAssigned`, `InvalidVrfPublicKey`, `InvalidBlsPublicKey`, `InvalidPayoutViewPub`, `InvalidPayoutSpendPub`, `InvalidPayoutFlag`, `PendingUnbondsNotSorted`, `UtxoNotSorted`, `InvalidUtxoCommit`, `SpentKeyImagesNotSorted`, `StorageNotSorted`, `InvalidStorageCommitment`, `InvalidUtxoTree`, `IntegrityCheckFailed`, `TrailingBytes`).
  - Wire layout: magic `b"MFCC"` + `u32` version + payload (every `ChainState` field, hash-maps sorted by key) + 32-byte trailing integrity tag `dhash(CHAIN_CHECKPOINT, &[payload])`.
- **`UtxoTreeState` codec in `mfn-crypto`** — `encode_utxo_tree_state` / `decode_utxo_tree_state` with new `UtxoTreeDecodeError` enum (Truncated, VarintOverflow, LengthOverflow, LeafCountExceedsCapacity, DepthOutOfRange, NodesNotSorted, TrailingBytes); new accessors `UtxoTreeState::nodes_iter` and `UtxoTreeState::from_parts` so the type's serialisation lives co-located with the type itself. `zeros` is **not** serialised — recomputed from `UTXO_TREE_DEPTH` on decode.
- **New `CHAIN_CHECKPOINT = b"MFBN-1/chain-checkpoint"` domain tag** in `mfn-crypto/src/domain.rs`, fully separated from `LIGHT_CHECKPOINT` so a light-checkpoint byte stream fed to the full-node decoder fails the integrity check rather than partially decoding.
- **`Chain` driver glue in `mfn-node`**:
  - `Chain::checkpoint()` → `ChainCheckpoint` (owned bundle).
  - `Chain::encode_checkpoint()` → `Vec<u8>` (canonical bytes).
  - `Chain::from_checkpoint(cfg, ChainCheckpoint)` → `Result<Self, ChainError>` — restores in-process state, re-derives the local genesis_id from `ChainConfig`, and rejects any mismatch with `ChainError::GenesisMismatch { expected, got }`.
  - `Chain::from_checkpoint_bytes(cfg, &[u8])` → `Result<Self, ChainError>` — decode + restore in one step.
  - New `ChainError::CheckpointDecode(ChainCheckpointError)` and `ChainError::GenesisMismatch { expected, got }` variants — every restoration failure mode surfaces as a typed error.

### Test matrix

**`mfn-crypto::utxo_tree` (+9 tests, brings utxo_tree module to 25):**

- `utxo_tree_codec_empty_round_trip` — empty tree round-trips, root preserved.
- `utxo_tree_codec_many_leaves_round_trip` — 16-leaf tree round-trips; every membership proof verifies leaf-for-leaf against the restored root.
- `utxo_tree_codec_is_deterministic_independent_of_append_order` — same history, identical bytes.
- `utxo_tree_codec_rejects_truncation` — every prefix of a valid blob fails decode.
- `utxo_tree_codec_rejects_trailing_bytes` — `TrailingBytes`.
- `utxo_tree_codec_rejects_unsorted_nodes` — strict-ascending `(depth, index)` constraint.
- `utxo_tree_codec_rejects_depth_out_of_range` — `depth > UTXO_TREE_DEPTH`.
- `utxo_tree_codec_rejects_leaf_count_above_capacity` — `leaf_count > 2^32`.

**`mfn-consensus::chain_checkpoint` (+13 tests):**

- `pre_genesis_round_trip` — pre-genesis (no height, empty maps) round-trips.
- `rich_round_trip_preserves_every_field` — 3 validators (mixed payouts), pending unbond, 10 UTXOs, 5 spent key images, 4 storage anchors, populated `utxo_tree`; round-trips field-by-field + re-encoding determinism.
- `encode_is_independent_of_hashmap_iteration_order` — semantically equal states encode to identical bytes.
- `rejects_bad_magic` / `rejects_unsupported_version` / `detects_payload_tamper` / `detects_tag_tamper` / `rejects_truncated_below_minimum` — every header / integrity failure surfaces correctly.
- `rejects_duplicate_validator_index` / `rejects_stats_validators_mismatch` / `rejects_next_index_at_or_below_max_assigned` — every cross-field invariant enforced.
- `rejects_trailing_bytes_after_tag` — surfaces as `IntegrityCheckFailed` (by design, every byte before the tag is part of the integrity payload).
- `light_checkpoint_bytes_fail_chain_decode` — domain separation between the two checkpoint families is enforced.

**`mfn-node::chain` (+5 unit tests, +3 integration tests):**

- `checkpoint_round_trip_at_genesis` — round-trip at height 0.
- `checkpoint_after_three_blocks_round_trips` — 3-block chain round-trips; both chains advance on the same block 4 to byte-identical state.
- `from_checkpoint_rejects_foreign_genesis` — `GenesisMismatch` when the caller's genesis disagrees.
- `from_checkpoint_bytes_rejects_tamper` — `CheckpointDecode(IntegrityCheckFailed)`.
- `chain_checkpoint_integration::checkpoint_round_trip_after_three_real_blocks_advances_in_lockstep` — drives the full producer pipeline (3 real BLS-signed blocks with coinbase emission + validator stats) → checkpoint → restore → both chains accept an identical block 4 and end at byte-identical encoded state. This is the ground-truth contract for the M2.1 daemon: a restart must yield a chain that produces the same blocks and responds the same way to network input.
- `chain_checkpoint_integration::encode_checkpoint_is_deterministic_on_non_trivial_chain` — re-encoding twice yields identical bytes.
- `chain_checkpoint_integration::from_checkpoint_rejects_foreign_genesis_through_real_chain` — `GenesisMismatch` on a non-trivial chain.

### Scope decisions (what M2.0.15 explicitly does **not** do)

- **No file IO.** The codec is `&[u8] ↔ Vec<u8>`. M2.1.0 later added the first daemon-side file snapshot store (`mfn_node::ChainStore`); richer sled / RocksDB layouts remain future work.
- **No incremental persistence.** Encoder produces a full snapshot per call. Block-log persistence is a future M2.x; this codec is the safety net that bounds replay cost in either case.
- **No mfn-light consolidation.** `mfn-light::checkpoint` and `mfn-consensus::chain_checkpoint` duplicate four small sub-encoders (`encode_validator`, etc). Wire bytes match byte-for-byte; consolidation is a future micro-milestone.
- **No `mfn-store` crate.** That naming is reserved for the future RocksDB/sled backend that consumes this codec.

### What this unlocks

- **M2.1.0 single-node daemon.** Boot reads snapshot or runs genesis; shutdown atomically writes a snapshot. No more "chain dies with the process."
- **State-root-consistent fast sync.** Two nodes that have applied the same blocks produce byte-identical encoded checkpoints; their `dhash(CHAIN_CHECKPOINT, &[payload])` is a checkpoint root a future fast-sync RPC can verify against the network.
- **Long-running test harnesses.** Tests can snapshot mid-run and resume — enables chaos/restart-style tests.
- **Debuggability.** Faulty chains can be encoded and byte-diffed against a known-good twin; typed decode errors localise drift to a single field name.

See [`docs/M2_CHAIN_CHECKPOINT.md`](./M2_CHAIN_CHECKPOINT.md) for the full design note.

---

## Milestone M2.0.16 — Shared checkpoint sub-encoder consolidation (✓ shipped)

**Why it was next.** M2.0.9 (`mfn-light::checkpoint`) and M2.0.15 (`mfn-consensus::chain_checkpoint`) shipped two checkpoint codecs that — by *design* — emit byte-identical sub-encodings for every shared building block: validators, validator-stats, pending-unbonds, consensus-params, bonding-params. Each codec carried its own private copy of those sub-encoders. Convention kept them aligned; no compiler-enforced invariant did. M2.0.16 lifts the shared sub-encoders into a single source of truth so any future drift would surface immediately as either a build error or a per-field unit-test failure.

### What shipped

- **`mfn-consensus/src/checkpoint_codec.rs`** — a new public module that hosts:
  - The shared error enum [`CheckpointReadError`](../mfn-consensus/src/checkpoint_codec.rs) with every per-field decode failure (truncation, varint overflow, length overflow, invalid VRF / BLS / payout public keys, invalid payout flag, validator-stats length mismatch, duplicate validator index, pending-unbonds not strictly ascending, `next_validator_index` ≤ max assigned).
  - Shared encoders: `encode_validator`, `encode_validator_stats`, `encode_pending_unbond`, `encode_consensus_params`, `encode_bonding_params`.
  - Shared decoders: `decode_validator`, `decode_validator_stats`, `decode_pending_unbond`, `decode_consensus_params`, `decode_bonding_params`.
  - Shared primitives: `read_fixed`, `read_u8/u16/u32/u64/u128`, `read_varint`, `read_len`, `read_edwards_point` (+ `EdwardsReadError`).
  - A cross-validator invariant check `check_validator_assignment` that both codecs now call to enforce duplicate-index detection + `next_validator_index > max(validator.index)` in **one place**.
- **`mfn-consensus::chain_checkpoint`** — now imports from `checkpoint_codec` and removes all duplicated inline encoders / decoders / read helpers. `ChainCheckpointError` adds a single `Read(CheckpointReadError)` variant with `#[from]`; the chain-specific framing (magic, version, integrity tag, height flag, UTXO / spent-key-image / storage sort-order, `InvalidUtxoTree`, `InvalidStorageCommitment`, `TrailingBytes`, `IntegrityCheckFailed`) stays put.
- **`mfn-light::checkpoint`** — same surgery. `LightCheckpointError` adds `Read(CheckpointReadError)` with `#[from]`, all duplicated inline encoders/decoders removed; framing-specific variants (`BadMagic`, `UnsupportedVersion`, `IntegrityCheckFailed`, `TrailingBytes`, `PendingUnbondIndexMismatch`) stay. The encode body now calls `encode_consensus_params` / `encode_bonding_params` for the frozen-params block instead of inlining the 8+24 raw bytes.
- **Byte-identity anchor test** in `mfn-light::checkpoint` —  `embedded_validator_block_matches_shared_encoder_byte_for_byte` builds a `CheckpointParts` with 3 validators, encodes it via `encode_checkpoint_bytes`, then re-encodes the same 3 validators with the shared `encode_validator` and asserts the two byte windows are equal. If the two codecs ever drift, this test fails on the next CI run.

### Test matrix

- **`mfn-consensus::checkpoint_codec` — 12 new unit tests** covering: validator round-trip (with + without payout), validator-stats round-trip, pending-unbond round-trip, consensus-params round-trip with f64-bits invariance, bonding-params round-trip, invalid payout-flag rejection, validator-decoder truncation at every byte offset, validator-assignment-check accepts well-formed lists, rejects duplicate indices, rejects `next ≤ max`, accepts any `next` for an empty list, deterministic encode of `DEFAULT_CONSENSUS_PARAMS`.
- **`mfn-consensus::chain_checkpoint` — all 13 existing tests** continue to pass with mechanical match updates (`Truncated` → `Read(CheckpointReadError::Truncated)` etc.).
- **`mfn-light::checkpoint` — all 40 existing unit tests + 17 follow-chain integration tests** continue to pass, plus 1 new byte-identity anchor test.
- Workspace **+13 tests** total: 558 → **571**.

### Properties preserved (must-haves)

- **Byte-for-byte wire compatibility.** Every byte produced by `encode_checkpoint_bytes` (light) and `encode_chain_checkpoint` (full-node) is identical to its M2.0.15 counterpart. Existing checkpoint files / network payloads continue to decode unchanged.
- **No consensus impact.** Nothing in the state-transition function or genesis hashing was touched; the codec is a serialisation concern that lives outside `apply_block`.
- **Error fidelity.** Every previously-distinct per-field error variant is still reachable, just through `LightCheckpointError::Read(CheckpointReadError::...)` / `ChainCheckpointError::Read(CheckpointReadError::...)` instead of inline. Callers gain a `Display`-transparent error chain via `#[error(transparent)]`.

### Scope decisions (what M2.0.16 explicitly does **not** do)

- **No version bump.** `LIGHT_CHECKPOINT_VERSION` and `CHAIN_CHECKPOINT_VERSION` stay at `1`. The codec is the same; only its Rust-side organisation changed.
- **No new wire fields.** Refactor only. Adding fields requires a version bump per the existing forward-compatibility plan.
- **No `mfn-store` crate.** Still reserved for the future RocksDB / sled persistence backend.
- **No mempool / network / RPC work.** Those are M2.1+ tier milestones.

### What this unlocks

- **One source of truth** for "what a validator's wire bytes look like." When M2.1+ adds a fast-sync RPC or a JSONRPC `getCheckpoint`, every layer agrees on the encoding by construction.
- **Cheaper to add fields.** Any future per-field addition (e.g. a new `Validator` attribute, or a `ConsensusParams` knob) touches one encoder + one decoder + one test family.
- **Compiler-enforced cohesion.** If someone adds a new field to `Validator` without updating the shared encoder, both `mfn-light` and `mfn-consensus` tests fail in unison — drift is impossible to merge silently.

---

## Milestone M2.1.0 — `mfn-node::store` filesystem checkpoint store (✓ shipped)

**Why it was next.** M2.0.15 gave the full-node `ChainState` deterministic checkpoint bytes, and M2.0.16 made the shared checkpoint sub-encoders non-drifting. The next daemon-critical gap was the actual IO boundary: a process needs to boot from persisted bytes if present, fall back to genesis if not, and publish the latest state on shutdown without corrupting the last good snapshot. M2.1.0 is that smallest durable persistence primitive.

### What shipped

- **`mfn-node/src/store.rs`** — a stdlib-only filesystem checkpoint store over `Chain::encode_checkpoint` and `Chain::from_checkpoint_bytes`.
- **`ChainStore`** — directory-owned, single-writer store with:
  - `ChainStore::new(root)` — configure a store directory without touching disk.
  - `load(cfg)` — read `chain.checkpoint` if present, restore it against the caller's `ChainConfig`, and return `Ok(None)` if no snapshot exists.
  - `load_or_genesis(cfg)` — daemon boot primitive: restore checkpoint or construct a fresh genesis chain.
  - `save(&chain)` — write canonical checkpoint bytes to `chain.checkpoint.tmp`, `sync_all` the temp file, rotate old `chain.checkpoint` to `chain.checkpoint.bak`, then publish the temp file as the new primary.
  - `clear()` — remove primary, backup, and temp files.
- **`StoreError`** — typed error boundary:
  - `Io { op, path, source }` for filesystem failures.
  - `Chain(ChainError)` for malformed / foreign-genesis checkpoint restore failures or genesis construction failures.
- **Backup-slot recovery** — loads prefer `chain.checkpoint`, but if primary is absent they try `chain.checkpoint.bak`. This covers the interrupted-save window after old primary rotation but before new-primary publication, including Windows where `std::fs::rename` cannot portably replace an existing destination.

### Test matrix

- `missing_snapshot_loads_none_and_boots_genesis` — no files → `load` returns `None`; `load_or_genesis` boots height 0 and does not create a checkpoint implicitly.
- `save_then_load_round_trips_chain_checkpoint` — save a genesis chain, load it, compare `ChainStats` and byte-identical checkpoint re-encoding.
- `load_rejects_checkpoint_from_foreign_genesis` — saved checkpoint restored with a different `GenesisConfig` surfaces `ChainError::GenesisMismatch` through `StoreError::Chain`.
- `load_recovers_from_backup_when_primary_is_missing` — simulates an interrupted rotation by moving primary to backup; `load` recovers from backup bytes.
- `save_removes_stale_temp_file_and_clear_removes_all_store_files` — stale temp is removed before save; second save creates backup; `clear` deletes primary / backup / temp.

Workspace **+5 tests** total: 571 → **576**.

### Scope decisions

- **No RocksDB / sled yet.** M2.1.0 is a full-snapshot file store. Block-log replay, compaction, retention, pruning, checksummed metadata, and column families remain future M2.x work.
- **No async runtime.** The store is synchronous and stdlib-only. The daemon can call it on boot/shutdown without committing the repo to `tokio` or any runtime choice yet.
- **No RPC / P2P / clock.** This is the persistence floor under those layers, not the layers themselves.
- **No checkpoint version bump.** The store consumes M2.0.15 checkpoint v1 bytes unchanged.

### What this unlocks

- **M2.1 single-node daemon boot path.** The daemon can now express: `let chain = store.load_or_genesis(cfg)?; ...; store.save(&chain)?;`.
- **Restart/chaos tests.** Long-running harnesses can persist, drop process state, reload, and continue against byte-identical `ChainState`.
- **RPC-ready introspection.** Future `getCheckpoint` / `saveCheckpoint` / `restoreCheckpoint` RPC handlers have a small stable backend to call.

---

## Milestone M2.1.1 — `mfnd` reference binary (✓ shipped)

**Why it was next.** M2.1.0 proved the filesystem checkpoint lifecycle in unit tests, but operators still had no first-class process entrypoint. M2.1.1 ships the minimal `mfnd` binary so boot, status introspection, explicit save, and graceful shutdown (Ctrl+C → checkpoint write) are exercised end-to-end under `cargo test` and in manual runs.

### What shipped

- **`mfn-node/src/bin/mfnd.rs`** — thin `main` calling [`mfn_node::mfnd_main`].
- **`mfn-node/src/mfnd_cli.rs`** — argument parsing and commands:
  - `mfnd --data-dir <DIR> status` — prints tip height / tip id / genesis id / whether a durable checkpoint existed on disk before this boot.
  - `mfnd --data-dir <DIR> save` — `load_or_genesis` then `ChainStore::save`.
  - `mfnd --data-dir <DIR> run` — load-or-genesis, then wait for graceful shutdown: **Unix** installs `ctrlc` and saves on Ctrl+C; **Windows** waits for Enter (avoids a `windows-sys` dependency that breaks `windows-gnu` toolchains missing `dlltool`), then saves.
- **`mfn-node/src/demo_genesis.rs`** — fixed empty-validator dev genesis shared with store tests, until deployment-specific genesis files are wired.
- **`ChainStore::has_any_checkpoint`** — true when primary or backup checkpoint exists (ignores `.tmp` staging files).

### Test matrix

- `store` unit tests extended for `has_any_checkpoint` (including temp-only → false).
- `mfnd_smoke` integration tests: status on empty dir, save→status, missing `--data-dir` error path.

Workspace **+6 tests** total: 576 → **582**.

### Scope decisions

- **No block production loop** in `run` yet — the process only demonstrates persistence + operator ergonomics.
- **No JSON-RPC / P2P.** Those remain later M2.x milestones.
- **Default genesis** — without `--genesis`, `mfnd` still uses the built-in empty-validator dev config; production networks must distribute an agreed spec file (or equivalent) out-of-band.

### What this unlocks

- **Operator-visible lifecycle** — the same `load_or_genesis` / `save` path a future full daemon will use, now runnable from the shell.
- **Signal-safe shutdown hook (Unix)** — Ctrl+C path saves before `process::exit`; Windows uses Enter instead so `windows-gnu` hosts stay buildable without `windows-sys`.

---

## Milestone M2.1.2 — JSON genesis spec + `mfnd --genesis` (✓ shipped)

**Why it was next.** M2.1.1 always used a built-in empty-validator genesis. Real devnets—even single-validator ones—need a reproducible way to agree on `timestamp`, `ConsensusParams`, and validator keys before the first block. M2.1.2 adds a versioned JSON spec and wires it into `mfnd` without touching consensus wire formats.

### What shipped

- **`mfn-node/src/genesis_spec.rs`** — `genesis_config_from_json_bytes` / `genesis_config_from_json_path`, typed [`GenesisSpecError`], `serde` + `serde_json` with `deny_unknown_fields` on every table.
- **`mfn_crypto::stealth_wallet_from_seed`** — deterministic payout keys for validators whose spec omits `payout_seed_hex` (defaults to deriving payout stealth keys from the BLS seed material).
- **`mfnd --genesis PATH`** (alias `--genesis-spec`) — optional path alongside `--data-dir`; when absent, behavior matches M2.1.1 (`demo_genesis`).
- **`mfnd status`** — prints `validator_count` for quick sanity checks.
- **`mfn-node/testdata/devnet_one_validator.json`** — example single-validator spec aligned with `single_validator_flow` seeds.

### Test matrix

- `genesis_spec` unit tests: golden file parse, wrong `version`, non-contiguous validator indices.
- `mfnd_smoke`: `mfnd_status_with_json_genesis_spec` — exercises `--genesis` against the checked-in JSON.

Workspace **+6 tests** total: 582 → **588**.

### Scope decisions

- **JSON only (no TOML crate).** Human operators can still edit the file by hand; CI and nodes parse it with `serde_json`.
- **No emission/endowment overrides in v1** — specs always inherit `DEFAULT_EMISSION_PARAMS` / `DEFAULT_ENDOWMENT_PARAMS` and `bonding_params: None`.
- **No genesis UTXO / storage entries in v1** — empty `initial_outputs` / `initial_storage` only; richer fixtures are a future spec version bump.

### What this unlocks

- **Multi-operator devnets** — same file checked into a repo or distributed out-of-band yields byte-identical `GenesisConfig` and therefore identical `genesis_id`.
- **Wallet / producer integration** — downstream tools can generate JSON from a higher-level UI while the daemon keeps a single loader.

---

## Milestone M2.1.3 — `mfnd step` solo block + checkpoint (✓ shipped)

**Why it was next.** M2.1.2 made devnet genesis reproducible, but operators still had no first-class shell path to **produce** the next block and persist it through the same `ChainStore` lifecycle as `save` / `run`. `step` closes that gap for the single-validator + payout case used in local demos.

### What shipped

- **`mfnd step`** — loads chain (`load_or_genesis`), requires exactly one genesis validator with a **payout** (coinbase route), reads `MFND_SOLO_VRF_SEED_HEX` and `MFND_SOLO_BLS_SEED_HEX` (64 hex chars, same decoding rules as JSON seeds), checks derived keys match validator index 0, builds coinbase via `emission_at_height` + `build_coinbase`, calls `produce_solo_block`, `Chain::apply`, then `ChainStore::save`.
- **`genesis_spec::hex_seed32`** — public helper for env parsing (wraps the same 32-byte hex rules as the JSON spec).
- **Monotonic block timestamp** — `genesis.timestamp + height` for the block being produced (deterministic devnet clock).

### Test matrix

- `mfnd_smoke`: `mfnd_step_twice_advances_tip_under_devnet_spec`, `mfnd_step_requires_solo_seed_env`, `mfnd_step_rejects_empty_validator_genesis`.
- `mfnd_cli::tests::parse_args_step`.

Workspace **+4 tests** total vs the M2.1.2 release line count: **588 → 592** passing.

### Scope decisions

- **Solo-only** — multi-validator scheduling and networking remain later M2.x work; mempool-driven block bodies are now exercised in `mfnd step` (M2.1.4).
- **Secrets in env** — convenient for CI and local scripts; production deployments will move to key files / HSM paths without changing consensus.

### What this unlocks

- **Scriptable devnets** — CI and operators can advance height N with N invocations of `mfnd step`, reusing the same checkpoint files as `status` / `run`.

---

## Milestone M2.1.4 — mempool-aware `mfnd step` + `--blocks N` (✓ shipped)

**Why it was next.** M2.1.3 proved solo production through the daemon, but each block bypassed the [`Mempool`] entirely — unlike every integration test that models real block bodies. Wiring the same drain → coinbase-fee → `remove_mined` path into `mfnd` keeps the reference binary aligned with the wallet→mempool→producer pipeline and prepares for a future RPC admit surface without changing consensus.

### What shipped

- **In-process [`Mempool`] per `step` run** — before each block, `drain` up to 256 txs (fee-priority); coinbase amount is `emission(height) + producer_fee_share(Σ tx fees)` using live `fee_to_treasury_bps` from chain state (same split as `apply_block`).
- **`--blocks N`** — optional flag (only with `step`; default 1; max 10_000) to apply N sequential blocks in one process invocation; by default **one** checkpoint after the final block. Use **`--checkpoint-each`** (M2.1.5) to persist after every block.
- **CLI validation** — `--blocks` rejected for non-`step` commands.

### Test matrix

- `mfnd_cli` unit tests: `parse_args_step_blocks`, `parse_args_blocks_rejected_without_step`.
- `mfnd_smoke`: `mfnd_step_blocks_advances_tip_in_one_invocation`.

Workspace **+3 tests** vs the M2.1.3 line count: **592 → 595** passing.

### Scope decisions

- **Ephemeral mempool** — no persistence between `mfnd` invocations; txs must be re-admitted after each process exit until JSON-RPC exists.
- **Drain cap** — 256 txs per block matches devnet scale; production caps may follow wire limits in a later milestone.

### What this unlocks

- **Single binary CI loops** — one `mfnd … step --blocks 100` warms state without subprocess overhead.
- **RPC-shaped producer** — the next layer only needs to call `Mempool::admit` between steps.

---

## Milestone M2.1.5 — `mfnd --checkpoint-each` per-block persistence (✓ shipped)

**Why it was next.** M2.1.4 batched `step --blocks N` for throughput, but a crash mid-run could lose all progress after the last disk sync. For long local simulations and fault-injection harnesses, operators need an explicit **durability knob** without changing consensus.

### What shipped

- **`--checkpoint-each`** — boolean flag (only with `step`): after each successful `apply`, `ChainStore::save` runs immediately. Stdout emits one `step_checkpoint tip_height=…` line per save for scripting.
- **Default unchanged** — without the flag, `step` / `step --blocks N` still performs a single checkpoint at the end of the run (M2.1.4 behavior).

### Test matrix

- `mfnd_cli`: `parse_args_step_checkpoint_each`, `parse_args_checkpoint_each_rejected_without_step`.
- `mfnd_smoke`: `mfnd_step_checkpoint_each_writes_after_each_block`.

Workspace **+3 tests** vs the M2.1.4 line count: **595 → 598** passing.

### Scope decisions

- **No fsync policy tuning yet** — the store already `sync_all`s staged bytes; richer durability tiers (e.g. two-phase + WAL) stay in future `store` milestones.
- **Mempool still ephemeral** — checkpointing does not snapshot the mempool; only chain state is durable.

### What this unlocks

- **Long `step --blocks` runs** — progress survives process death between heights when operators opt in.
- **Chaos / crash-recovery tests** — kill `mfnd` between `step_checkpoint` lines and resume from disk.

---

## Milestone M2.1.6 — `mfnd serve` minimal TCP control plane (✓ shipped)

**Why it was next.** `step` is a batch harness; long-lived daemons need a **single process** that keeps chain + mempool warm while wallets and integration tests attach without spawning a new `mfnd` per RPC-shaped call. Full JSON-RPC is still downstream; this milestone ships the smallest **blocking TCP** surface that is trivial to drive from any language: one connection, one request line, one response line, then close.

### What shipped

- **`mfnd serve`** — loads chain + store like other subcommands, holds an in-memory [`Mempool`], and listens on **`--rpc-listen HOST:PORT`** (default **`127.0.0.1:18731`**; **`127.0.0.1:0`** is allowed for ephemeral ports in tests). The first stdout line is **`mfnd_serve_listening=<SocketAddr>`** so harnesses can parse the bound address.
- **Line protocol** — each accepted TCP client may send **one** UTF-8 line (no embedded newlines); the server replies with **one** JSON line and closes. Since **M2.1.8**, every response is a JSON-RPC 2.0 object (`jsonrpc`, `id`, `result` or `error`); the original M2.1.6 slice used ad-hoc `ok` / `error` string fields.
- **`get_tip`** — returns `tip_height`, `tip_id`, `genesis_id` (64-char lowercase hex), `validator_count`, `mempool_len`.
- **`submit_tx`** — `params` is either `{"tx_hex": "…"}` (optional `0x`) or a one-element JSON array `["…"]` with the same hex (**M2.1.8.1**); decoded tx is passed to `Mempool::admit`; response reports admission outcome or typed refusal.
- **`--rpc-listen`** is accepted **only** with `serve` (rejected for `step` / `status` / …). **`serve`** does not require solo `step` env seeds (read-only tip query + mempool admission only).
- **Unix Ctrl+C** — `ctrlc::set_handler` exits the process cleanly (no checkpoint-on-exit in this slice; operators use `save` / `step` for disk durability).

### Test matrix

- `mfnd_cli`: `parse_args_serve`, `parse_args_serve_rpc_listen`, `parse_args_rpc_listen_rejected_without_serve`.
- `mfnd_smoke`: `mfnd_serve_get_tip_over_tcp` (via shared `spawn_mfnd_serve` / `tcp_request_json` helpers since M2.1.6.1).

Workspace **+4 tests** vs the M2.1.5 line count: **598 → 602** passing.

### Scope decisions

- **JSON-RPC 2.0 envelope (M2.1.8)** — responses carry `"jsonrpc":"2.0"`, echo `id` (or `null`), and either `result` or `error` with numeric `code` (standard `-32700`…`-32603` plus **`-32001`** for mempool `admit` refusal). Still **no batching**, subscriptions, or HTTP; NDJSON-over-TCP remains the transport.
- **Blocking accept loop** — one client at a time on the main thread matches the rest of `mfn-node`'s synchronous contract; a threaded/async server is deferred.

### What this unlocks

- **Wallet / tool integration** — submit txs and observe tip against a long-lived local node.
- **Future P2P harness** — the same process can later grow a second listener without redesigning the chain ownership model.

---

## Milestone M2.1.6.1 — `serve` `submit_tx` TCP regression harness (✓ shipped)

**Why it was next.** M2.1.6 shipped `submit_tx` on the wire but only exercised `get_tip` end-to-end against the real `mfnd` binary. Tooling and future JSON-RPC need **stable error surfaces** (malformed hex vs truncated codec vs mempool policy refusals); subprocess tests lock that contract before a richer RPC layer wraps the same handlers.

### What shipped

- **`tests/mfnd_smoke.rs`** — `spawn_mfnd_serve` + `tcp_request_json` helpers; `mfnd_serve_get_tip_over_tcp` refactored to use them.

### Test matrix

- `mfnd_serve_submit_tx_rejects_bad_hex`
- `mfnd_serve_submit_tx_rejects_truncated_wire`
- `mfnd_serve_submit_tx_rejects_coinbase_shaped_wire` (canonical `encode_transaction` of an empty-input `TransactionWire` → `Mempool::admit` `NoInputs`)
- `mfnd_serve_submit_tx_rejects_missing_tx_hex`

Workspace **+4 tests** vs the M2.1.6 line count: **602 → 606** passing.

### Scope decisions

- **No successful `submit_tx` happy path over TCP in M2.1.6.1 alone** — that landed in **M2.1.7** once `chain.blocks` + optional genesis `synthetic_decoy_utxos` made subprocess wallet replay possible.

### What this unlocks

- **Safe iteration on `mfnd_serve::handle_client`** — refactors to JSON-RPC framing can keep these subprocess assertions green.

---

## Milestone M2.1.7 — `chain.blocks` append log + genesis decoy pool + `submit_tx` happy path (✓ shipped)

**Why it was next.** M2.1.6.1 deliberately deferred a successful `submit_tx` over the real `mfnd serve` binary because checkpoints do not carry enough information to rebuild a wallet's scan state. Operators still need a **cheap, deterministic block sidecar** long before a full archive node exists.

### What shipped

- **`chain.blocks`** — after every successful `apply` in `mfnd step`, `ChainStore::append_block` appends `u64_be(len) || encode_block(block)` to an append-only file under the data directory; `ChainStore::read_block_log` reads it back; `ChainStore::clear` removes it alongside checkpoint files.
- **Genesis JSON `synthetic_decoy_utxos`** (optional, capped at `mfn_node::MAX_SYNTHETIC_DECOY_UTXOS`) — version-1 specs can request deterministic synthetic `GenesisOutput` rows so local devnets have a decoy ring pool even before multi-block coinbase accumulation.
- **Testdata** — [`testdata/devnet_one_validator_synth_decoys.json`](../mfn-node/testdata/devnet_one_validator_synth_decoys.json) (24 synthetic outputs + the existing solo validator).
- **`mfnd_smoke`** — `mfnd_step_writes_block_log_then_serve_submit_tx_admits_transfer` proves: `step` → one log record → wallet ingest (`build_genesis` + replayed block) using **`stealth_wallet_from_seed`** keys matching the validator payout derivation → signed transfer → `submit_tx` returns `Fresh` against a live `serve`.

### Test matrix

- `genesis_spec`: `synth_decoys_spec_loads`, `rejects_synthetic_decoy_count_too_large`.
- `store`: `read_block_log_empty_when_missing`, `clear_removes_block_log`.
- `mfnd_smoke`: `mfnd_step_writes_block_log_then_serve_submit_tx_admits_transfer`.

Workspace **+5 tests** vs the M2.1.6.1 line count: **606 → 611** passing.

### Scope decisions

- **Not a fork-choice replay engine** — `read_block_log` performs no linkage checks; callers treat the checkpoint as authoritative state and use the log only for wallet / tooling replay.
- **Payout keys vs `wallet_from_seed`** — JSON genesis payouts still use `mfn_crypto::stealth_wallet_from_seed` on the validator BLS seed (M2.1.2 behaviour). Wallets scanning coinbases in tests must use the same derivation (`WalletKeys::from_stealth(stealth_wallet_from_seed(&bls_seed))`), not `mfn_wallet::wallet_from_seed`.

### What this unlocks

- **CI-level `mfnd serve` admission tests** with real CLSAG transfers.
- **Future `mfn-cli`** can stream `chain.blocks` after bootstrap without inventing a second serialization.

---

## Milestone M2.1.8 — `mfnd serve` JSON-RPC 2.0 responses (✓ shipped)

**Why it was next.** M2.1.6 / M2.1.6.1 established a stable TCP harness and error taxonomy, but the wire used ad-hoc `ok` / `error` strings. Standard **JSON-RPC 2.0** responses let wallets, SDKs, and future `rpc` modules share one parsing model without changing the transport (still **one request line, one response line, close**).

### What shipped

- **`parse_and_dispatch_serve`** — central dispatcher used by the TCP loop (since **M2.1.10**: takes [`ChainStore`] + in-memory [`Chain`](../mfn-node/src/chain.rs) + [`Mempool`](../mfn-node/src/mempool.rs)); returns a single [`serde_json::Value`] with `jsonrpc`, `id`, and `result` or `error`.
- **Request rules** — `method` must be a JSON string. Optional `jsonrpc`; when present it must be `"2.0"`. Omitted `id` is treated as `null` and echoed (the server **always** emits one response line per connection).
- **Error codes** — `-32700` parse error; `-32600` invalid request; `-32601` method not found; `-32602` invalid params (bad hex, `decode_transaction`, missing `tx_hex`, wrong param types); `-32603` reserved for internal failures; **`-32001`** mempool `admit` refusal (message carries `AdmitError` display string prefixed with `mempool admit:`; see [`mempool.rs`](../mfn-node/src/mempool.rs)).
- **`mfnd_smoke`** — assertions upgraded to parse JSON-RPC; **`mfnd_serve_get_tip_jsonrpc_echoes_id`** locks `id` round-trip; coinbase-shaped wire asserts **`-32001`**.
- **Unit tests** (`mfnd_serve::tests`) — eight cases covering empty body, malformed JSON, bad `jsonrpc`, unknown method, `get_tip` success, `id` echo, missing `tx_hex`, non-string `method`.

Workspace **+9 tests** vs the M2.1.7 line count: **611 → 620** passing.

### Scope decisions

- **No batch arrays**, **no notifications semantics** (TCP always responds once), **no HTTP** — same deliberate surface as M2.1.6 with a stricter envelope only.

### What this unlocks

- **`mfn-cli` / SDK** can treat `serve` as a baby JSON-RPC endpoint while the full `rpc` crate is still under construction.

---

## Milestone M2.1.8.1 — `submit_tx` positional `params` array (✓ shipped)

**Why it was next.** JSON-RPC clients often emit **positional** `params` as a JSON array. Accepting `params: ["<hex>"]` alongside `params: {"tx_hex":"…"}` removes friction for generated clients without changing the TCP transport.

### What shipped

- **`extract_submit_tx_hex`** in [`mfnd_serve.rs`](../mfn-node/src/mfnd_serve.rs) — `submit_tx` reads hex from either form; hex decode errors use a neutral **`hex decode:`** prefix.
- **Five new unit tests** + **`mfnd_serve_submit_tx_array_params_rejects_bad_hex`** in `mfnd_smoke`.

Workspace **+6 tests** vs the M2.1.8 line count: **620 → 626** passing.

### Scope decisions

- **Only the first array element** is read; multi-arg batches remain out of scope until a real `rpc` module exists.

---

## Milestone M2.1.9 — `read_block_log_validated` (✓ shipped)

**Why it was next.** `read_block_log` returns bytes blindly; a corrupted or truncated `chain.blocks` next to a valid checkpoint would only fail later during wallet replay. Validating **count + height + `prev_hash` + terminal `block_id`** against the loaded [`Chain`](../mfn-node/src/chain.rs) catches mixed directories and operator mistakes early.

### What shipped

- **[`ChainStore::read_block_log_validated`](../mfn-node/src/store.rs)** — requires `log.len() == tip_height`, heights `1..=tip`, `prev_hash` chain from `genesis_id` to `tip_id`.
- **`store` unit tests** — empty log at genesis; count mismatch after appending a genesis-shaped row.
- **`mfnd_smoke`** — **`mfnd_step_block_log_passes_validated_read`** after one real `step`.

Workspace **+3 tests** vs the M2.1.8.1 line count: **626 → 629** passing.

### Scope decisions

- **Not fork-choice** — single canonical checkpoint + append log; no reorg replay.

---

## Milestone M2.1.10 — `serve` `get_block` (✓ shipped)

**Why it was next.** Wallets and tools need a narrow way to fetch canonical block bytes for heights `1..=tip_height` without re-running production logic. Reusing **`read_block_log_validated`** keeps `serve` aligned with the checkpoint tip and rejects mismatched directories.

### What shipped

- **`get_block`** in [`mfnd_serve.rs`](../mfn-node/src/mfnd_serve.rs) — `params` as `{"height": N}` or `[N]`; success returns `height` + `block_hex` (`encode_block`); **`read_block_log_validated`** failures map to JSON-RPC code **`-32002`** (`BLOCK_LOG_STORE`); bad height / missing params use **`-32602`** (`INVALID_PARAMS`).
- **Five new `mfnd_serve` unit tests** + **`mfnd_serve_get_block_over_tcp_after_step`** in `mfnd_smoke`.

Workspace **+6 tests** vs the M2.1.9 line count: **629 → 635** passing.

### Scope decisions

- **One block per request** — batch ranges stay out until a fuller `rpc` module exists.

---

## Milestone M2.1.11 — `serve` `get_block_header` (✓ shipped)

**Why it was next.** Light clients and tools often need linkage + `block_id` without paying for full `encode_block` bodies. Returning canonical [`block_header_bytes`](../mfn-consensus/src/block.rs) plus hex [`block_id`](../mfn-consensus/src/block.rs) reuses the same validated `chain.blocks` slice as **`get_block`**.

### What shipped

- **`get_block_header`** in [`mfnd_serve.rs`](../mfn-node/src/mfnd_serve.rs) — same `params` as **`get_block`**; success returns `height`, `block_id`, `header_hex`; shared internal **`read_validated_blocks_for_height`** with **`get_block`**.
- **Three new `mfnd_serve` unit tests** + **`get_block_header`** assertions added to **`mfnd_serve_get_block_over_tcp_after_step`** (`mfnd_smoke`).

Workspace **+3 tests** vs the M2.1.10 line count: **635 → 638** passing.

### Scope decisions

- **No separate `get_genesis_header`** — height `0` remains out of scope for both height methods until a caller need is proven.

---

## Milestone M2.1.12 — `serve` `get_mempool` (✓ shipped)

**Why it was next.** Wallets and integrators need a cheap snapshot of the pending set without pulling block bodies.

### What shipped

- **`get_mempool`** in [`mfnd_serve.rs`](../mfn-node/src/mfnd_serve.rs) — `params` must be omitted, `null`, `{}`, or `[]`; success returns `mempool_len` and sorted lowercase-hex **`tx_ids`** for every pending tx.
- **Four new `mfnd_serve` unit tests** + **`mfnd_serve_get_mempool_over_tcp_empty`** + **`mfnd_serve_get_mempool_lists_tx_after_submit`** (non-empty pool + id list) in `mfnd_smoke`.

Workspace **+6 tests** vs the M2.1.11 line count: **638 → 644** passing.

### Scope decisions

- **Sorted ids** — lexicographic order on hex strings for deterministic responses; pool internal iteration order is not part of the API contract.

---

## Milestone M2.1.13 — `serve` `get_mempool_tx` (✓ shipped)

**Why it was next.** Callers that already have a `tx_id` (from `submit_tx`, `get_mempool`, or wallet tooling) need the canonical `encode_transaction` bytes without scanning the full id list.

### What shipped

- **`get_mempool_tx`** in [`mfnd_serve.rs`](../mfn-node/src/mfnd_serve.rs) — `params` as `{"tx_id": "<64 hex>"}` or `["<64 hex>"]` (optional `0x`); success returns `tx_id` + `tx_hex`; missing pool entry maps to **`-32003`** (`MEMPOOL_TX_NOT_FOUND`).
- **Eight new `mfnd_serve` unit tests** + **`get_mempool_tx`** round-trip folded into **`mfnd_serve_get_mempool_lists_tx_after_submit`** (`mfnd_smoke`).

Workspace **+8 tests** vs the M2.1.12 line count: **644 → 652** passing.

### Scope decisions

- **One tx per request** — no batch fetch until a fuller `rpc` module exists.

---

## Milestone M2.1.14 — `serve` `remove_mempool_tx` (✓ shipped)

**Why it was next.** Local operators and tests need an explicit way to drop a pending tx from the in-memory pool without producing a block.

### What shipped

- **`remove_mempool_tx`** in [`mfnd_serve.rs`](../mfn-node/src/mfnd_serve.rs) — same **`tx_id`** `params` as **`get_mempool_tx`**; calls [`Mempool::evict`](../mfn-node/src/mempool.rs); success always returns `removed` + `pool_len` (no error when the id is absent).
- **Eight new `mfnd_serve` unit tests** + **`remove_mempool_tx`** + empty **`get_mempool`** folded into **`mfnd_serve_get_mempool_lists_tx_after_submit`** (`mfnd_smoke`).

Workspace **+8 tests** vs the M2.1.13 line count: **652 → 660** passing.

### Scope decisions

- **Idempotent semantics** — `removed: false` when the tx was not in the pool (no `MEMPOOL_TX_NOT_FOUND` error), so clients can safely retry.

---

## Milestone M2.1.15 — `serve` `clear_mempool` (✓ shipped)

**Why it was next.** Operators and long-lived local tests sometimes need to wipe the entire pending set at once rather than evicting tx by tx; the pool already exposes [`Mempool::clear`](../mfn-node/src/mempool.rs).

### What shipped

- **`clear_mempool`** in [`mfnd_serve.rs`](../mfn-node/src/mfnd_serve.rs) — same empty-only `params` rule as **`get_mempool`** (omit, `null`, `{}`, or `[]`); calls `Mempool::clear`; success returns **`cleared_count`** (entries removed) and **`pool_len`** (always `0` on success).
- **Four new `mfnd_serve` unit tests** + **`mfnd_serve_clear_mempool_after_submit`** in `mfnd_smoke`.

Workspace **+5 tests** vs the M2.1.14 line count: **660 → 665** passing.

### Scope decisions

- **`cleared_count` not `tx_ids`** — callers who need ids can `get_mempool` first; this method is only for bulk teardown.

---

## Milestone M2.1.16 — `serve` `get_checkpoint` (✓ shipped)

**Why it was next.** Wallets and light tooling need the same canonical checkpoint bytes `mfnd save` would write, without shelling out to `save` or re-reading `chain.checkpoint` from disk while the daemon holds the authoritative in-memory [`Chain`](../mfn-node/src/chain.rs).

### What shipped

- **`get_checkpoint`** in [`mfnd_serve.rs`](../mfn-node/src/mfnd_serve.rs) — same empty-only `params` rule as **`get_mempool`**; calls [`Chain::encode_checkpoint`](../mfn-node/src/chain.rs); success returns **`checkpoint_hex`** (lowercase hex) and **`byte_len`**.
- **Four new `mfnd_serve` unit tests** + **`mfnd_serve_get_checkpoint_round_trips_over_tcp_after_step`** in `mfnd_smoke`.

Workspace **+5 tests** vs the M2.1.15 line count: **665 → 670** passing.

### Scope decisions

- **In-memory snapshot** — not a fresh `read()` of `chain.checkpoint`; reflects the live `serve` process state (matches `save` only after the same updates).

---

## Milestone M2.1.17 — `serve` `save_checkpoint` (✓ shipped)

**Why it was next.** Long-lived **`serve`** processes need the same durable snapshot path as **`mfnd save`** without exiting; [`ChainStore::save`](../mfn-node/src/store.rs) already implements atomic rotation.

### What shipped

- **`save_checkpoint`** in [`mfnd_serve.rs`](../mfn-node/src/mfnd_serve.rs) — same empty-only `params` rule as **`get_mempool`**; calls **`ChainStore::save`**; success returns **`bytes_written`**, **`checkpoint_path`**, **`backup_path`**; failures map to **`-32004`** (`CHECKPOINT_SAVE`).
- **Four new `mfnd_serve` unit tests** + **`mfnd_serve_save_checkpoint_creates_checkpoint_file`** in `mfnd_smoke`.

Workspace **+5 tests** vs the M2.1.16 line count: **670 → 675** passing.

### Scope decisions

- **Same semantics as `mfnd save`** — primary/backup rotation; not a separate “export only” path.

---

## Milestone M2.1.18 — `serve` `list_methods` (✓ shipped)

**Why it was next.** Long-lived **`serve`** processes accumulate JSON-RPC methods; clients and operators need a **stable, self-describing** way to enumerate what the daemon implements without hard-coding method lists.

### What shipped

- **`list_methods`** in [`mfnd_serve.rs`](../mfn-node/src/mfnd_serve.rs) — same empty-only `params` rule as **`get_mempool`**; success returns **`methods`**: every implemented method name as a JSON string, **lexicographically sorted** (includes **`list_methods`**). [`serve_rpc_methods_json_result`](../mfn-node/src/mfnd_serve.rs) must stay in sync with [`dispatch_serve_methods`](../mfn-node/src/mfnd_serve.rs) `match` arms.
- **Four new `mfnd_serve` unit tests** + **`mfnd_serve_list_methods_over_tcp`** in `mfnd_smoke`.

Workspace **+5 tests** vs the M2.1.17 line count: **675 → 680** passing.

### Scope decisions

- **Sorted strings** — stable wire shape for diffing and scripted clients; not an OpenRPC document yet.

---

## Milestone series M2.2 — Authorship claim layer (in progress)

**Why now.** Permanent storage is content-addressed and **anonymous-by-default** at the RingCT layer: `StorageCommitment` must not grow an author field. Permaweb-style discovery still needs an **optional**, **cryptographically verifiable** signal (“this stable pubkey attests this `data_root` + short message”) without a second token type and without weakening financial privacy.

**Normative spec.** [**docs/AUTHORSHIP.md**](./AUTHORSHIP.md) (domain tag `MFBN-1/AUTHORSHIP/v1`, digest, Schnorr signature, `MFCL` per-claim encoding, optional `MFEX` multi-payload `extra`, `ChainState` claims index, header `claims_root`, RPC sketch).

**Sub-milestones (implementation order).**

| Id | Deliverable |
|----|----------------|
| **M2.2.0** | `mfn-crypto`: `AuthorshipClaim` digest + `sign_claim` / `verify_claim` + tests + domain constant. |
| **M2.2.1** | `mfn-crypto`: `encode_authorship_claim` / `decode_authorship_claim` (`MFCL` + version) + typed decode errors + golden vectors. |
| **M2.2.2** | `mfn-consensus`: `extra_codec` — `MFEX` envelope + strict parse when prefixed; legacy opaque `extra` otherwise. |
| **M2.2.3** | `mfn-consensus`: `apply_block` validates every claim (signature, limits); bad sig rejects block. |
| **M2.2.4** | `mfn-consensus`: `ChainState.claims` map + checkpoint codec round-trip + replay idempotency. |
| **M2.2.5** | `mfn-consensus`: `BlockHeader.claims_root` + `verify_block_body` + light-client agreement tests. |
| **M2.2.6** | `mfn-wallet`: `ClaimingIdentity` + standalone claim tx path + e2e mempool → block. |
| **M2.2.7** | `mfn-wallet`: `build_storage_upload_with_claims` bundles claims in `extra` + e2e storage + claims. |
| **M2.2.8** | `mfn-node` `mfnd serve`: `get_claims_for`, `get_claims_by_pubkey`, `list_recent_uploads` + TCP tests. |
| **M2.2.9** | Docs pass (AUTHORSHIP + cross-links; this roadmap row marked shipped). |
| **M2.2.10** | `mfn-node`: derived indexer views for discovery (no consensus change). |

**Renumbering note.** An earlier roadmap draft used “M2.2” for **multi-node P2P**. That work is **M2.3 — Multi-node testnet** in the phase list below; **M2.4 — Public testnet** follows. The numeric **M2.2.x** patch series is reserved for authorship claims so specs and code refer to one unambiguous label.

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
| `store.rs` | M2.1.0 file checkpoint store is live; **M2.1.7** append-only `chain.blocks` + `read_block_log`; **M2.1.9** `read_block_log_validated`; future RocksDB/sled snapshot + fork-choice replay extends it. |
| `rpc.rs` | JSON-RPC + WebSocket. Block, tx, balance, storage-status queries. |
| `runner.rs` | Block production loop, finality voting loop, mempool flush. |
| `bin/mfnd.rs` | **M2.1.1** — reference daemon (`status` / `save` / `run`); **M2.1.3–M2.1.5** — `step`, mempool drain, `--blocks N`, `--checkpoint-each`; **M2.1.6** — `serve` + `--rpc-listen`; **M2.1.7** — `chain.blocks` append on `step`; **M2.1.8** — JSON-RPC 2.0 responses on `serve`; **M2.1.8.1** — `submit_tx` array `params`; **M2.1.9** — validated block log read; **M2.1.10** — `serve` `get_block`; **M2.1.11** — `serve` `get_block_header`; **M2.1.12** — `serve` `get_mempool`; **M2.1.13** — `serve` `get_mempool_tx`; **M2.1.14** — `serve` `remove_mempool_tx`; **M2.1.15** — `serve` `clear_mempool`; **M2.1.16** — `serve` `get_checkpoint`; **M2.1.17** — `serve` `save_checkpoint`; **M2.1.18** — `serve` `list_methods`. Full producer loop attaches later. |

### Phases

- **M2.1 — Single-node demo.** No P2P; `apply_block` is driven by **`step`** and, for local integration, a minimal **`serve`** TCP line server (`get_tip`, `submit_tx`, **`get_block`**, **`get_block_header`**, **`get_mempool`**, **`get_mempool_tx`**, **`remove_mempool_tx`**, **`clear_mempool`**, **`get_checkpoint`**, **`save_checkpoint`**, **`list_methods`**) with **JSON-RPC 2.0 responses (M2.1.8)** and **`submit_tx`** **array `params` (M2.1.8.1)**; **`chain.blocks`** can be checked with **`read_block_log_validated` (M2.1.9)** and read over **`serve`** via **`get_block` (M2.1.10)** or **`get_block_header` (M2.1.11)**; **`get_mempool` (M2.1.12)** snapshots the pending set; **`get_mempool_tx` (M2.1.13)** fetches one pending tx by id; **`remove_mempool_tx` (M2.1.14)** evicts by id when present; **`clear_mempool` (M2.1.15)** clears the pool in one call; **`get_checkpoint` (M2.1.16)** returns canonical checkpoint bytes for the live chain state; **`save_checkpoint` (M2.1.17)** writes that state through **`ChainStore::save`**; **`list_methods` (M2.1.18)** lists every implemented JSON-RPC method name (sorted). A full `rpc` module (HTTP/WebSocket, richer methods) lands in a later sub-milestone.
- **M2.3 — Multi-node testnet.** Add P2P + mempool. Run a 3-validator local testnet that produces real finalized blocks.
- **M2.4 — Public testnet.** Documentation + bootstrapping nodes; invite external operators.

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
