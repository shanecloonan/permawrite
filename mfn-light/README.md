# `mfn-light`

Light-client chain follower for Permawrite. Built on top of [`mfn_consensus::verify_header`](../mfn-consensus/src/header_verify.rs) (M2.0.5) and [`mfn_consensus::verify_block_body`](../mfn-consensus/src/header_verify.rs) (M2.0.7). The foundation for wallets, WASM browser clients, and cross-chain bridges.

**Tests:** 24 passing (14 unit + 10 integration) &nbsp;·&nbsp; **`unsafe`:** forbidden &nbsp;·&nbsp; **Clippy:** clean

---

## Status (M2.0.6 header-chain follower + M2.0.7 body-root verification)

This is the **smallest useful light-client artifact**: a `LightChain` struct that holds a trusted validator set, a tip pointer (`tip_height` + `tip_id`), and a genesis id; and that applies forward through either:

- **`apply_header(&BlockHeader)`** (M2.0.6 — header-only) — strict monotonicity, `prev_hash` linkage, `verify_header`, tip advance.
- **`apply_block(&Block)`** (M2.0.7 — full block) — the above *plus* `verify_block_body`: re-derives `tx_root` / `bond_root` / `slashing_root` / `storage_proof_root` from the delivered body and matches each against the (now-authenticated) header.

After a successful `apply_block`, the light client has cryptographic proof that the `(header, body)` pair it accepted is byte-for-byte the one some honest 2/3-stake quorum signed over — closing the "right header, wrong body" attack surface a header-only client leaves open.

On any failure the chain state is byte-for-byte untouched (pure-function `verify_header` / `verify_block_body` underneath; no partial commits). Typed errors distinguish forged headers (`HeaderVerify`) from header-honest / body-tampered pairs (`BodyMismatch`).

Demonstrated end-to-end in [`tests/follow_chain.rs`](tests/follow_chain.rs) against a real 3-block chain produced by `mfn-node`'s `produce_solo_block` helper: a `LightChain` and a full `Chain` reach the same tip on every block via *either* `apply_header` or `apply_block`.

---

## What this slice does NOT do (yet)

- **No state-dependent body roots.** `storage_root` and `utxo_root` depend on chain state (storage-commitment dedup map, UTXO accumulator) — out of scope for stateless verification. Both are already cryptographically covered by the BLS aggregate signing `header_signing_hash` (caught by `verify_header`).
- **No validator-set evolution.** Processing `BondOp::Register` / `BondOp::Unbond`, equivocation slashings, liveness slashings, and pending-unbond settlements to derive `trusted_validators_{n+1}` from `trusted_validators_n` is **M2.0.8** work. Until then, callers following a chain *across* a rotation should re-bootstrap from a freshly-trusted checkpoint. For chains in stable-validator regimes (the common case) the current slice is sufficient.
- **No re-org / fork choice.** Single canonical header chain. P2P + fork-choice are higher-up daemon concerns.
- **No persistence.** Tip + trusted validators live in memory.

These omissions are explicit so each slice ships as something *whole*: M2.0.6 was "follow a chain with a stable validator set"; M2.0.7 is "verify the body matches the header"; M2.0.8 will be "evolve the trusted set across rotations".

---

## Public API

```rust
use mfn_light::{
    LightChain, LightChainConfig,
    AppliedHeader, AppliedBlock,
    LightChainError,
};

// Bootstrap from a GenesisConfig — same config the full node uses.
let mut light = LightChain::from_genesis(LightChainConfig::new(genesis_cfg));
assert_eq!(light.tip_height(), 0);
assert_eq!(light.tip_id(), light.genesis_id());

// --- Header-only path (M2.0.6) ---
// Useful when the body isn't delivered yet (e.g. bulk header sync).
let applied: AppliedHeader = light.apply_header(&block.header)?;

// --- Full-block path (M2.0.7) ---
// Adds body-root verification against the (now-authenticated) header.
let applied: AppliedBlock = light.apply_block(&block)?;

// Read-only accessors.
let h: u32                = light.tip_height();
let tip: &[u8;32]         = light.tip_id();
let genesis: &[u8;32]     = light.genesis_id();
let vals: &[Validator]    = light.trusted_validators();
let params: &ConsensusParams = light.params();
let total: u64            = light.total_stake();
let stats = light.stats();
```

`LightChain::from_genesis` is infallible: deriving the genesis `block_id` is an infallible hash, and the trusted validators are simply copied out of `cfg.genesis.validators`. (The full-node `apply_genesis` performs additional validation that's not needed for light-client bootstrap — the light client trusts the config it was given by construction.)

### `apply_block` error semantics

```rust
pub enum LightChainError {
    HeightMismatch    { expected: u32, got: u32 },
    PrevHashMismatch  { height: u32, expected: [u8;32], got: [u8;32] },
    HeaderVerify      { height: u32, source: HeaderVerifyError },
    BodyMismatch      { height: u32, source: BodyVerifyError },   // NEW in M2.0.7
}
```

`apply_block`'s checks run in order: linkage → `verify_header` → `verify_block_body` → tip advance. Header verification fires **before** body verification, so the typed errors give a clean distinction:

- **`HeaderVerify`** = "this header isn't genuine" (BLS signature breaks, wrong `validator_root`, etc.).
- **`BodyMismatch`** = "this header is genuine, but the body the peer delivered doesn't match what it committed to".

Either is a hard reject; downstream tooling (peer scoring, sync logic, alerts) can act differently on each.

---

## Why a separate crate?

`mfn-consensus` is the **spec** (state-transition function, wire formats). `mfn-node` is the **full-node orchestrator** (`Chain` driver, producer helpers, future mempool / RPC / store / P2P). `mfn-light` is the **light-client orchestrator**: same spec crate, completely different state model.

A light client:

- Has **no `ChainState`** — no UTXO tree, no storage tree, no validator-stats history.
- Tracks just a tip pointer + a trusted validator set.
- Must run in environments where `mfn-node`'s eventual dependencies (RocksDB, libp2p, …) won't be available: in a browser as WASM, on a mobile device, in a constrained embedded context.

Splitting into its own crate keeps the dependency graph tight (`mfn-consensus`, `mfn-bls`, `mfn-storage`, `mfn-crypto` — pure-Rust spec deps only) so the same code can compile cleanly to `wasm32-unknown-unknown`. It also lets `mfn-light` and `mfn-node` evolve at different cadences without one's daemon concerns leaking into the other's tightness.

---

## Test categories

- **Unit (`chain::tests`, 14 tests)** — M2.0.6 set (7): `from_genesis` lands at height 0 with tip = genesis id; genesis deterministic across constructions; real signed block 1 applies cleanly via `apply_header`; wrong `prev_hash` / wrong height / tampered `validator_root` are typed errors with state preserved; `stats()` agrees with individual accessors. M2.0.7 set (7): `apply_block` happy path; header-field tamper → `HeaderVerify` (BLS breaks first); body-only tamper → `BodyMismatch { TxRootMismatch }` with state preserved; linkage errors fire before body verification; `apply_block` chains across two real blocks; `apply_header` and `apply_block` agree on clean chains.
- **Integration (`tests/follow_chain.rs`, 10 tests)** — M2.0.6 set (5): `LightChain` follows a full `mfn_node::Chain` through 3 real BLS-signed blocks reaching identical tips; skipped headers rejected with state preserved; cross-chain header-injection caught by `validator_root` check (load-bearing demonstration of why M2.0 matters); recovery after a rejected header; typed-error surface of `ValidatorRootMismatch`. M2.0.7 set (5): full-chain `apply_block` agreement across 3 blocks; body-tx-tamper rejection with state preserved; body-storage_proof-tamper rejection; recovery after body rejection; `apply_header` / `apply_block` agreement on clean chains.

```bash
cargo test -p mfn-light
```

---

## Safety contract

- `#![forbid(unsafe_code)]`.
- No IO. No clock. No async runtime. No background threads.
- All public methods are deterministic and re-entrant-safe.
- `LightChain` clones cheaply (one `Vec<Validator>` + small fixed fields).
- `LightChain: Send` (every field is `Send`). Not `Sync` by default — wrap in a `Mutex` if shared across threads is needed; intended pattern is single-owner.

---

## Dependencies

```
mfn-crypto    = path      # primitives, codec
mfn-bls       = path      # BLS verification (transitive via mfn-consensus)
mfn-storage   = path      # storage roots (transitive via mfn-consensus)
mfn-consensus = path      # BlockHeader, Block, verify_header, verify_block_body, build_genesis, block_id
thiserror     = "1.0"

[dev-dependencies]
mfn-node      = path      # produce_solo_block in integration tests
hex           = "0.4"
```

No async runtime, no networking, no on-disk store. Same pattern as `mfn-node`: stay pure-library; daemon concerns attach upstream.

---

## See also

- [`docs/M2_LIGHT_HEADER_VERIFY.md`](../docs/M2_LIGHT_HEADER_VERIFY.md) — the M2.0.5 primitive (header verification).
- [`docs/M2_LIGHT_BODY_VERIFY.md`](../docs/M2_LIGHT_BODY_VERIFY.md) — the M2.0.7 primitive (body-root verification) + `apply_block` design note.
- [`docs/M2_LIGHT_CHAIN.md`](../docs/M2_LIGHT_CHAIN.md) — the M2.0.6 chain-follower design note.
- [`docs/ROADMAP.md`](../docs/ROADMAP.md) — phased rollout (M2.0.8 validator-set evolution next).
- [`mfn-consensus`](../mfn-consensus/README.md) — the spec this crate consumes.
- [`mfn-node`](../mfn-node/README.md) — the full-node analogue.
