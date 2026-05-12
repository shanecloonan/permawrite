# `mfn-light`

Light-client chain follower for Permawrite. Built on top of [`mfn_consensus::verify_header`](../mfn-consensus/src/header_verify.rs) (M2.0.5), [`mfn_consensus::verify_block_body`](../mfn-consensus/src/header_verify.rs) (M2.0.7), and the shared [`mfn_consensus::validator_evolution`](../mfn-consensus/src/validator_evolution.rs) module (M2.0.8). The foundation for wallets, WASM browser clients, and cross-chain bridges.

**Tests:** 34 passing (22 unit + 12 integration, 1 ignored placeholder) &nbsp;·&nbsp; **`unsafe`:** forbidden &nbsp;·&nbsp; **Clippy:** clean

---

## Status (M2.0.6 header follower + M2.0.7 body verification + M2.0.8 validator-set evolution)

This is a **production-ready light-client artifact**: a `LightChain` struct that follows the Permawrite chain across arbitrary rotations from a single genesis bootstrap, with full cryptographic verification at every step.

`LightChain` owns:

- **Identity + tip.** `genesis_id`, `tip_height`, `tip_id`.
- **Params (frozen at genesis).** `ConsensusParams`, `BondingParams`.
- **Trusted validator set.** `trusted_validators: Vec<Validator>`, evolved per block.
- **Shadow state for evolution (M2.0.8).** `validator_stats` (per-validator liveness counters), `pending_unbonds` (in-flight exit queue), `BondEpochCounters` (`bond_epoch_id`, `bond_epoch_entry_count`, `bond_epoch_exit_count`, `next_validator_index`).

Two forward-application paths:

- **`apply_header(&BlockHeader)`** (M2.0.6) — strict monotonicity, `prev_hash` linkage, `verify_header`, tip advance. **Does not** evolve the validator set, so it's only useful for stable-validator windows or header-first sync.
- **`apply_block(&Block)`** (M2.0.7 + M2.0.8) — the above *plus* `verify_block_body` (re-derives the four header-bound body roots) *plus* validator-set evolution (mirrors `apply_block`'s four phases byte-for-byte via the shared `validator_evolution` module). After this returns, the light client's trusted set is the same set the next block's header will commit to.

After a successful `apply_block`, the light client has cryptographic proof that the `(header, body)` pair it accepted is byte-for-byte what some honest 2/3-stake quorum signed over AND its trusted set is correctly evolved — closing both the "right header, wrong body" attack surface and the "can't follow across rotations" gap.

On any failure the chain state is byte-for-byte untouched. Typed errors distinguish forged headers (`HeaderVerify`) from header-honest / body-tampered pairs (`BodyMismatch`) from Byzantine-quorum-signed bad bond ops (`EvolutionFailed`).

Demonstrated end-to-end in [`tests/follow_chain.rs`](tests/follow_chain.rs) against real chains produced by `mfn-node`'s `produce_solo_block` helper:

- **3-block stable-validator chain.** `LightChain` and `Chain` reach the same tip on every block via *either* `apply_header` or `apply_block`.
- **5-block rotation chain.** `Register` at block 1, `Unbond` at block 3, settlement at block 5. The light client's evolved trusted set matches the full node's by `validator_set_root` after every block.

---

## What this crate does NOT do (yet)

- **No state-dependent body roots.** `storage_root` and `utxo_root` depend on chain state (storage-commitment dedup map, UTXO accumulator) — out of scope for stateless verification. Both are already cryptographically covered by the BLS aggregate signing `header_signing_hash` (caught by `verify_header`).
- **No light-client surfaces for slashing audit.** The light client mirrors `apply_block`'s soft-skip semantics for invalid slashings (advances the chain, doesn't surface them as errors). A future slice may add an `EquivocationCheck`-style outcome to `AppliedBlock`.
- **No re-org / fork choice.** Single canonical header chain. P2P + fork-choice are higher-up daemon concerns.
- **No persistence.** Tip + trusted validators + shadow state live in memory.

---

## Public API

```rust
use mfn_light::{
    LightChain, LightChainConfig,
    AppliedHeader, AppliedBlock,
    LightChainError,
    BondEpochCounters, BondingParams, PendingUnbond, ValidatorStats,
};

// Bootstrap from a GenesisConfig — same config the full node uses.
let mut light = LightChain::from_genesis(LightChainConfig::new(genesis_cfg));
assert_eq!(light.tip_height(), 0);
assert_eq!(light.tip_id(), light.genesis_id());

// --- Header-only path (M2.0.6) ---
// Useful when the body isn't delivered yet (e.g. bulk header sync).
let applied: AppliedHeader = light.apply_header(&block.header)?;

// --- Full-block path (M2.0.7 + M2.0.8) ---
// Adds body-root verification + validator-set evolution.
let applied: AppliedBlock = light.apply_block(&block)?;
// AppliedBlock carries the per-block validator-set deltas:
let _ = applied.validators_added;             // BondOp::Register successes
let _ = applied.validators_slashed_equivocation;
let _ = applied.validators_slashed_liveness;
let _ = applied.validators_unbond_settled;

// Read-only accessors.
let h: u32                          = light.tip_height();
let tip: &[u8;32]                   = light.tip_id();
let genesis: &[u8;32]               = light.genesis_id();
let vals: &[Validator]              = light.trusted_validators();
let stats: &[ValidatorStats]        = light.validator_stats();   // M2.0.8
let pending: &BTreeMap<u32, PendingUnbond> = light.pending_unbonds(); // M2.0.8
let counters: &BondEpochCounters    = light.bond_counters();     // M2.0.8
let nvi: u32                        = light.next_validator_index();
let params: &ConsensusParams        = light.params();
let bparams: &BondingParams         = light.bonding_params();    // M2.0.8
let total: u64                      = light.total_stake();
let snapshot = light.stats();
```

`LightChain::from_genesis` is infallible: deriving the genesis `block_id` is an infallible hash, the trusted validators come straight from `cfg.genesis.validators`, and the shadow state is initialized **byte-for-byte equal** to what the full node's `apply_genesis` produces (default-stats per validator, empty pending queue, `next_validator_index = max(v.index) + 1`, bonding params from genesis override or `DEFAULT_BONDING_PARAMS`).

### `apply_block` error semantics

```rust
pub enum LightChainError {
    HeightMismatch    { expected: u32, got: u32 },
    PrevHashMismatch  { height: u32, expected: [u8;32], got: [u8;32] },
    HeaderVerify      { height: u32, source: HeaderVerifyError },
    BodyMismatch      { height: u32, source: BodyVerifyError },   // M2.0.7
    EvolutionFailed   { height: u32, index: usize, message: String },  // M2.0.8
}
```

`apply_block`'s checks run in order: linkage → `verify_header` → `verify_block_body` → validator-set evolution → tip advance. The typed errors give a clean diagnostic distinction:

- **`HeaderVerify`** = forged header (BLS signature breaks, wrong `validator_root`, etc.).
- **`BodyMismatch`** = right header, wrong body (peer delivered a substituted body for an authentic header).
- **`EvolutionFailed`** = right header + body, but a bond op is invalid (Byzantine quorum scenario; should not occur on honest chains).

All of these reject atomically — chain tip + trusted set + shadow state preserved.

### The cross-block audit invariant (M2.0.8 keystone)

After `apply_block(n)` succeeds, the light client's evolved `trusted_validators` MUST equal the full node's `state.validators` after the same block — or the next `apply_block(n+1)` fails with `HeaderVerify { ValidatorRootMismatch }`. Why: block `n+1`'s header commits to the post-block-`n` validator set in its `validator_root` field (M2.0), and `verify_header` checks this against the trusted set.

**The chain's own headers audit the light client's evolution.** Drift is detected at the very next block.

---

## Why a separate crate?

`mfn-consensus` is the **spec** (state-transition function, wire formats, shared validator-evolution helpers). `mfn-node` is the **full-node orchestrator** (`Chain` driver, producer helpers, future mempool / RPC / store / P2P). `mfn-light` is the **light-client orchestrator**: same spec crate, completely different state model.

A light client:

- Has **no `ChainState`** — no UTXO tree, no storage tree, no validator-stats history beyond what's needed to evolve the trusted set.
- Tracks a tip pointer + trusted validator set + small (O(validators + pending_unbonds)) shadow state.
- Must run in environments where `mfn-node`'s eventual dependencies (RocksDB, libp2p, …) won't be available: in a browser as WASM, on a mobile device, in a constrained embedded context.

Splitting into its own crate keeps the dependency graph tight (`mfn-consensus`, `mfn-bls`, `mfn-storage`, `mfn-crypto` — pure-Rust spec deps only) so the same code can compile cleanly to `wasm32-unknown-unknown`. It also lets `mfn-light` and `mfn-node` evolve at different cadences without one's daemon concerns leaking into the other's tightness.

---

## Test categories

- **Unit (`chain::tests`, 22 tests)** —
  - **M2.0.6 set (7).** `from_genesis` lands at height 0 with tip = genesis id; genesis deterministic across constructions; real signed block 1 applies cleanly via `apply_header`; wrong `prev_hash` / wrong height / tampered `validator_root` are typed errors with state preserved; `stats()` agrees with individual accessors.
  - **M2.0.7 set (7).** `apply_block` happy path; header-field tamper → `HeaderVerify` (BLS breaks first); body-only tamper → `BodyMismatch { TxRootMismatch }` with state preserved; linkage errors fire before body verification; `apply_block` chains across two real blocks; `apply_header` and `apply_block` agree on clean chains.
  - **M2.0.8 set (8).** `from_genesis` initializes shadow state correctly; empty-validators genesis sets `next_validator_index = 0`; `total_signed` increments for a voting validator on every block; body tamper preserves `validator_stats`; simulated trusted-set drift caught by next block's `ValidatorRootMismatch`; `AppliedBlock` deltas are zero for no-event chains; `validator_set_root` matches the next block's claimed root after every applied block (the headline invariant).
- **Integration (`tests/follow_chain.rs`, 12 tests)** —
  - **M2.0.6 set (5).** `LightChain` follows a full `mfn_node::Chain` through 3 real BLS-signed blocks reaching identical tips; skipped headers rejected with state preserved; cross-chain header-injection caught by `validator_root` check (load-bearing demonstration of why M2.0 matters); recovery after a rejected header; typed-error surface of `ValidatorRootMismatch`.
  - **M2.0.7 set (5).** Full-chain `apply_block` agreement across 3 blocks; body-tx-tamper rejection with state preserved; body-storage_proof-tamper rejection; recovery after body rejection; `apply_header` / `apply_block` agreement on clean chains.
  - **M2.0.8 set (2).** 5-block rotation chain (`Register` at block 1, `Unbond` at block 3, settlement at block 5) with `validator_set_root` agreement asserted after every block; tampered bond op in a fresh block caught by `BondRootMismatch` before evolution runs.
  - **M2.0.8.x set (1, ignored).** Placeholder for hand-signed Byzantine block fixture (reserved).

```bash
cargo test -p mfn-light
```

---

## Safety contract

- `#![forbid(unsafe_code)]`.
- No IO. No clock. No async runtime. No background threads.
- All public methods are deterministic and re-entrant-safe.
- `LightChain` clones cheaply (small fixed-size header + `Vec<Validator>` + a few small auxiliary collections).
- `LightChain: Send` (every field is `Send`). Not `Sync` by default — wrap in a `Mutex` if shared across threads is needed; intended pattern is single-owner.

---

## Dependencies

```
mfn-crypto    = path      # primitives, codec
mfn-bls       = path      # BLS verification (transitive via mfn-consensus)
mfn-storage   = path      # storage roots (transitive via mfn-consensus)
mfn-consensus = path      # BlockHeader, Block, verify_header, verify_block_body,
                          # validator_evolution helpers, build_genesis, block_id
thiserror     = "1.0"

[dev-dependencies]
mfn-node      = path      # produce_solo_block in integration tests
hex           = "0.4"
```

No async runtime, no networking, no on-disk store. Same pattern as `mfn-node`: stay pure-library; daemon concerns attach upstream.

---

## See also

- [`docs/M2_LIGHT_HEADER_VERIFY.md`](../docs/M2_LIGHT_HEADER_VERIFY.md) — the M2.0.5 primitive (header verification).
- [`docs/M2_LIGHT_BODY_VERIFY.md`](../docs/M2_LIGHT_BODY_VERIFY.md) — the M2.0.7 primitive (body-root verification).
- [`docs/M2_LIGHT_VALIDATOR_EVOLUTION.md`](../docs/M2_LIGHT_VALIDATOR_EVOLUTION.md) — the M2.0.8 design note (shared validator-evolution module + light-client integration).
- [`docs/M2_LIGHT_CHAIN.md`](../docs/M2_LIGHT_CHAIN.md) — the M2.0.6 chain-follower design note.
- [`docs/ROADMAP.md`](../docs/ROADMAP.md) — phased rollout.
- [`mfn-consensus`](../mfn-consensus/README.md) — the spec this crate consumes.
- [`mfn-node`](../mfn-node/README.md) — the full-node analogue.
