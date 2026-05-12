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
| Chain state machine (incl. SPoRA verify + liveness slashing) | `mfn-consensus` | 81 | ✓ live |
| Canonical wire codec | (in `mfn-crypto::codec`) | — | ✓ live (will extract) |
| **Total** | | **279** | All checks green |

**Posture.** We've built the consensus core. There's no daemon, no mempool, no P2P, no wallet CLI yet. The roadmap below lays out the path from "consensus state machine in a test harness" to "running network."

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

Test count: 279 passing across the workspace. Zero `unsafe`. Zero clippy warnings.

---

## Milestone M1 — Validator rotation (next major)

Full design note: [**docs/M1_VALIDATOR_ROTATION.md**](./M1_VALIDATOR_ROTATION.md). Default parameters and pure validation helpers live in `mfn_consensus::bonding` (wired into `apply_block` in a follow-up PR).

**Why this is next.** Today the validator set is frozen at genesis. This is the largest *structural* hole left in the protocol layer. Without rotation, the chain can't onboard new validators or remove zero-stake (liveness-slashed-to-floor or equivocation-zeroed) ones.

### Scope

- **Bond transaction.** New variant of `TransactionWire` that locks a stake amount and registers a new `Validator` entry.
- **Unbond transaction.** Initiates withdrawal of a bond; subject to an unbond delay (≥ max evidence window, so equivocation slashing can still take effect after intent-to-unbond).
- **Entry/exit queues.** Bounded per-epoch churn. Default: at most 4 validators in or out per epoch (epoch = some multiple of the slot frequency).
- **Validator-stats reset.** New validators get fresh `ValidatorStats`; departing validators have their slot freed.
- **Storage operator bond (separate from validator bond — optional, for "premium" replica tier).**

### Open design questions

- Single bond per validator vs. multiple delegations (decided: single, for simplicity).
- Slashed validators' bonds: fully burned, fully donated to treasury, or partially returned? (Tentative: fully donated to treasury.)
- Cooldown: 14 days at slot rate? Longer? Tied to economic security margin?

### Tests we'll write

- Bond tx via `apply_block` extends validator set.
- Unbond delay enforced.
- Late equivocation slashing applies despite intent-to-unbond.
- Entry/exit queues bounded.
- Treasury credited on slash.

**Estimated scope.** ~1500 LoC + ~30 tests. Comparable to liveness-slashing work.

---

## Milestone M2 — Node daemon (`mfn-node`)

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

- **M2a — Single-node demo.** No P2P; just `apply_block` driven by an RPC harness. Validates the chain state machine works end-to-end in a long-running process.
- **M2b — Multi-node testnet.** Add P2P + mempool. Run a 3-validator local testnet that produces real finalized blocks.
- **M2c — Public testnet.** Documentation + bootstrapping nodes; invite external operators.

### Not in M2

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
