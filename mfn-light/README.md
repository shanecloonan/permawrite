# `mfn-light`

Light-client chain follower for Permawrite. Built on top of [`mfn_consensus::verify_header`](../mfn-consensus/src/header_verify.rs) (M2.0.5), [`mfn_consensus::verify_block_body`](../mfn-consensus/src/header_verify.rs) (M2.0.7), the shared [`mfn_consensus::validator_evolution`](../mfn-consensus/src/validator_evolution.rs) module (M2.0.8), the M2.0.9 checkpoint codec, and the M2.0.10 full-block wire codec. The foundation for wallets, WASM browser clients, and cross-chain bridges.

**Tests:** 57 passing (40 unit + 17 integration, 1 ignored placeholder) &nbsp;·&nbsp; **`unsafe`:** forbidden &nbsp;·&nbsp; **Clippy:** clean

---

## Status (M2.0.6 + M2.0.7 + M2.0.8 + M2.0.9 + M2.0.10)

This is a **production-ready light-client artifact**: a `LightChain` struct that follows the Permawrite chain across arbitrary rotations from a single genesis bootstrap, with full cryptographic verification at every step, a self-contained byte-deterministic checkpoint codec so the chain survives restarts, and an integration-proven path from canonical raw block bytes to `LightChain::apply_block`.

`LightChain` owns:

- **Identity + tip.** `genesis_id`, `tip_height`, `tip_id`.
- **Params (frozen at genesis).** `ConsensusParams`, `BondingParams`.
- **Trusted validator set.** `trusted_validators: Vec<Validator>`, evolved per block.
- **Shadow state for evolution (M2.0.8).** `validator_stats` (per-validator liveness counters), `pending_unbonds` (in-flight exit queue), `BondEpochCounters` (`bond_epoch_id`, `bond_epoch_entry_count`, `bond_epoch_exit_count`, `next_validator_index`).

Three application paths:

- **`apply_header(&BlockHeader)`** (M2.0.6) — strict monotonicity, `prev_hash` linkage, `verify_header`, tip advance. **Does not** evolve the validator set, so it's only useful for stable-validator windows or header-first sync.
- **`apply_block(&Block)`** (M2.0.7 + M2.0.8) — the above *plus* `verify_block_body` (re-derives the four header-bound body roots) *plus* validator-set evolution (mirrors `apply_block`'s four phases byte-for-byte via the shared `validator_evolution` module). After this returns, the light client's trusted set is the same set the next block's header will commit to.
- **`encode_checkpoint` / `decode_checkpoint`** (M2.0.9) — the chain's full state (tip + identity + params + validators + stats + pending unbonds + counters) serialises to a self-contained, byte-deterministic, integrity-tagged blob and restores bit-for-bit.

After a successful `apply_block`, the light client has cryptographic proof that the `(header, body)` pair it accepted is byte-for-byte what some honest 2/3-stake quorum signed over AND its trusted set is correctly evolved.

On any failure the chain state is byte-for-byte untouched. Typed errors distinguish forged headers (`HeaderVerify`) from header-honest / body-tampered pairs (`BodyMismatch`) from Byzantine-quorum-signed bad bond ops (`EvolutionFailed`) from corrupted checkpoints (`LightCheckpointError::*`).

Demonstrated end-to-end in [`tests/follow_chain.rs`](tests/follow_chain.rs) against real chains produced by `mfn-node`'s `produce_solo_block` helper:

- **3-block stable-validator chain.** `LightChain` and `Chain` reach the same tip on every block via *either* `apply_header` or `apply_block`.
- **5-block rotation chain.** `Register` at block 1, `Unbond` at block 3, settlement at block 5. The light client's evolved trusted set matches the full node's by `validator_set_root` after every block.
- **Mid-chain snapshot resume (M2.0.9).** A `LightChain` follows 2 blocks, gets snapshotted to bytes, is restored on a fresh process, then follows 3 more blocks in lockstep with a non-snapshotted twin.
- **Raw block byte sync (M2.0.10).** Real `mfn-node` blocks are encoded with `encode_block`, decoded from bytes with `decode_block`, and applied to both the full node and light chain with identical tips.

---

## What this crate does NOT do (yet)

- **No state-dependent body roots.** `storage_root` and `utxo_root` depend on chain state (storage-commitment dedup map, UTXO accumulator) — out of scope for stateless verification. Both are already cryptographically covered by the BLS aggregate signing `header_signing_hash` (caught by `verify_header`).
- **No light-client surfaces for slashing audit.** The light client mirrors `apply_block`'s soft-skip semantics for invalid slashings (advances the chain, doesn't surface them as errors). A future slice may add an `EquivocationCheck`-style outcome to `AppliedBlock`.
- **No re-org / fork choice.** Single canonical header chain. P2P + fork-choice are higher-up daemon concerns.
- **No persistence adapter.** The crate produces / consumes bytes; whether a caller writes them to disk / S3 / IPFS / Arweave is intentionally outside this crate's remit.

---

## Public API

```rust
use mfn_light::{
    LightChain, LightChainConfig,
    AppliedHeader, AppliedBlock,
    LightChainError, LightCheckpointError,
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

// --- Raw block byte path (M2.0.10) ---
let decoded = mfn_consensus::decode_block(&network_bytes)?;
let applied: AppliedBlock = light.apply_block(&decoded)?;

// --- Checkpoint path (M2.0.9) ---
let bytes: Vec<u8> = light.encode_checkpoint();           // self-contained snapshot
let restored: LightChain = LightChain::decode_checkpoint(&bytes)?; // bit-for-bit equal
assert_eq!(restored.tip_id(), light.tip_id());

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

### `decode_checkpoint` error semantics (M2.0.9)

```rust
pub enum LightCheckpointError {
    BadMagic { got: [u8; 4] },
    UnsupportedVersion { got: u32 },
    Truncated { field: &'static str, needed: usize },
    VarintOverflow { field: &'static str },
    LengthOverflow { got: u64, field: &'static str },
    InvalidVrfPublicKey { index: usize },
    InvalidBlsPublicKey { index: usize, source: BlsError },
    InvalidPayoutViewPub { index: usize },
    InvalidPayoutSpendPub { index: usize },
    InvalidPayoutFlag { index: usize, flag: u8 },
    StatsLengthMismatch { validators: usize, stats: usize },
    DuplicateValidatorIndex { index: u32 },
    PendingUnbondsNotSorted { index: usize },
    PendingUnbondIndexMismatch { index: usize, expected: u32, got: u32 },
    NextIndexBelowAssigned { next: u32, max_assigned: u32 },
    IntegrityCheckFailed,
    TrailingBytes { remaining: usize },
}
```

A trailing 32-byte `dhash(LIGHT_CHECKPOINT, payload)` tag dominates the byte-level checks — any single byte flip anywhere in the payload (or in the tag itself) surfaces as `IntegrityCheckFailed`. Cross-field invariants are still enforced post-tag-verify as defence-in-depth (e.g. `next_validator_index > max(validator.index)`), so a hypothetical hash collision still can't deliver a self-inconsistent payload.

See [`docs/M2_LIGHT_CHECKPOINT.md`](../docs/M2_LIGHT_CHECKPOINT.md) for the full wire layout.

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

Splitting into its own crate keeps the dependency graph tight (`mfn-consensus`, `mfn-bls`, `mfn-storage`, `mfn-crypto`, `curve25519-dalek` — pure-Rust spec deps only) so the same code can compile cleanly to `wasm32-unknown-unknown`. It also lets `mfn-light` and `mfn-node` evolve at different cadences without one's daemon concerns leaking into the other's tightness.

---

## Test categories

- **Unit (40 tests)** —
  - `chain::tests` (27 tests). M2.0.6 (7), M2.0.7 (7), M2.0.8 (8), **M2.0.9 (5)**: genesis round-trip, mid-chain resume + accept of next block in lockstep, single-byte tamper rejection sweep, public-accessor equality across the round-trip, deterministic encoded length.
  - `checkpoint::tests` (13 tests). **M2.0.9.** Empty round-trip, full surface (validators with/without payout + stats + pending unbonds), f64 round-trip across NaN / ±∞ / subnormals / π, bad-magic / unknown-version / payload tamper / tag tamper / truncation rejections, duplicate-index / `next_validator_index` / invalid-BLS-pk / invalid-payout-flag invariant rejections, linear-size growth.
- **Integration (`tests/follow_chain.rs`, 18 tests)** —
  - **M2.0.6 set (5).** `LightChain` follows a full `mfn_node::Chain` through 3 real BLS-signed blocks reaching identical tips; skipped headers rejected with state preserved; cross-chain header-injection caught by `validator_root` check (load-bearing demonstration of why M2.0 matters); recovery after a rejected header; typed-error surface of `ValidatorRootMismatch`.
  - **M2.0.7 set (5).** Full-chain `apply_block` agreement across 3 blocks; body-tx-tamper rejection with state preserved; body-storage_proof-tamper rejection; recovery after body rejection; `apply_header` / `apply_block` agreement on clean chains.
  - **M2.0.8 set (2).** 5-block rotation chain (`Register` at block 1, `Unbond` at block 3, settlement at block 5) with `validator_set_root` agreement asserted after every block; tampered bond op in a fresh block caught by `BondRootMismatch` before evolution runs.
  - **M2.0.9 set (3).** Headline mid-chain checkpoint resume across 5 real blocks; integrity-tag detection of real-chain tampering; checkpoint carries `genesis_id` for chain-identity callers.
  - **M2.0.10 set (2).** Real canonical block bytes round-trip through `encode_block` / `decode_block` and feed `LightChain::apply_block` in lockstep with `mfn-node::Chain`; trailing bytes after a real block reject before consensus verification.
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
- `encode_checkpoint` is byte-deterministic; equal `LightChain` states produce byte-identical output (foundation for content-addressable snapshot storage).

---

## Dependencies

```
mfn-crypto       = path      # primitives, codec, LIGHT_CHECKPOINT domain tag
mfn-bls          = path      # BLS verification + 48-byte pk codec
mfn-storage      = path      # storage roots (transitive via mfn-consensus)
mfn-consensus    = path      # BlockHeader, Block, verify_header, verify_block_body,
                             # validator_evolution helpers, build_genesis, block_id,
                             # decode_block_header (M2.0.9),
                             # encode_block / decode_block (M2.0.10)
curve25519-dalek = workspace # Edwards-point decompression in the checkpoint codec
thiserror        = "1.0"

[dev-dependencies]
mfn-node         = path      # produce_solo_block in integration tests
hex              = "0.4"
```

No async runtime, no networking, no on-disk store. Same pattern as `mfn-node`: stay pure-library; daemon concerns attach upstream.

---

## See also

- [`docs/M2_LIGHT_HEADER_VERIFY.md`](../docs/M2_LIGHT_HEADER_VERIFY.md) — the M2.0.5 primitive (header verification).
- [`docs/M2_LIGHT_BODY_VERIFY.md`](../docs/M2_LIGHT_BODY_VERIFY.md) — the M2.0.7 primitive (body-root verification).
- [`docs/M2_LIGHT_VALIDATOR_EVOLUTION.md`](../docs/M2_LIGHT_VALIDATOR_EVOLUTION.md) — the M2.0.8 design note (shared validator-evolution module + light-client integration).
- [`docs/M2_LIGHT_CHECKPOINT.md`](../docs/M2_LIGHT_CHECKPOINT.md) — the M2.0.9 design note (header codec + checkpoint serialization).
- [`docs/M2_BLOCK_CODEC.md`](../docs/M2_BLOCK_CODEC.md) — the M2.0.10 design note (transaction + full-block codec).
- [`docs/M2_LIGHT_CHAIN.md`](../docs/M2_LIGHT_CHAIN.md) — the M2.0.6 chain-follower design note.
- [`docs/ROADMAP.md`](../docs/ROADMAP.md) — phased rollout.
- [`mfn-consensus`](../mfn-consensus/README.md) — the spec this crate consumes.
- [`mfn-node`](../mfn-node/README.md) — the full-node analogue.
