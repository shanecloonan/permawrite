# Roadmap

> **Audience.** Anyone trying to understand "what's done, what's coming, and in what order."
> The tier system maps the conceptual roadmap onto concrete code milestones.

---

## Where we are right now

| Layer | Crate | Tests | Status |
|---|---|---:|---|
| ed25519 primitives + ZK | `mfn-crypto` | 145 | ✓ live |
| BLS12-381 + committee aggregation | `mfn-bls` | 16 | ✓ live |
| Permanent-storage primitives | `mfn-storage` | 32 | ✓ live |
| Chain state machine (SPoRA verify + liveness slashing + **M1 validator rotation** + **M1.5 BLS-authenticated Register** + **M2.0 validator-set merkle root**) | `mfn-consensus` | 124 | ✓ live |
| Canonical wire codec | (in `mfn-crypto::codec`) | — | ✓ live (will extract) |
| **Total** | | **317** | All checks green |

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
