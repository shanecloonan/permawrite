# `mfn-light`

Header-only light-client chain follower for Permawrite. Built on top of [`mfn_consensus::verify_header`](../mfn-consensus/src/header_verify.rs) (M2.0.5). The foundation for wallets, WASM browser clients, and cross-chain bridges.

**Tests:** 12 passing (7 unit + 5 integration) &nbsp;·&nbsp; **`unsafe`:** forbidden &nbsp;·&nbsp; **Clippy:** clean

---

## Status (M2.0.6 — header-chain follower skeleton)

This is the **smallest useful light-client artifact**: a `LightChain` struct that holds a trusted validator set, a tip pointer (`tip_height` + `tip_id`), and a genesis id; and that applies header-by-header through `apply_header(&BlockHeader)`. Each `apply_header` call:

1. Checks `header.height == tip_height + 1` (strict monotonicity).
2. Checks `header.prev_hash == tip_id` (chain linkage).
3. Runs `mfn_consensus::verify_header(header, trusted_validators, params)` (cryptographic verification — `validator_root` match + producer proof + BLS finality aggregate).
4. Advances tip to `block_id(header)`.

On any failure the chain state is byte-for-byte untouched (pure-function `verify_header` underneath; no partial commits).

Demonstrated end-to-end in [`tests/follow_chain.rs`](tests/follow_chain.rs) against a real 3-block chain produced by `mfn-node`'s `produce_solo_block` helper: a `LightChain` and a full `Chain` reach the same tip on every block.

---

## What this slice does NOT do (yet)

- **No body verification.** Recomputing `tx_root` / `bond_root` / `slashing_root` / `storage_proof_root` / `storage_root` from a delivered body and comparing them to the header is **M2.0.7** work — separate slice.
- **No validator-set evolution.** Processing `BondOp::Register` / `BondOp::Unbond`, equivocation slashings, liveness slashings, and pending-unbond settlements to derive `trusted_validators_{n+1}` from `trusted_validators_n` is **M2.0.8** work. Until then, callers following a chain *across* a rotation should re-bootstrap from a freshly-trusted checkpoint. For chains in stable-validator regimes (the common case) the current slice is sufficient.
- **No re-org / fork choice.** Single canonical header chain. P2P + fork-choice are higher-up daemon concerns.
- **No persistence.** Tip + trusted validators live in memory.

These omissions are explicit so each slice ships as something *whole*: M2.0.6 is "follow a chain with a stable validator set"; M2.0.7 will add "verify the body roots from the header"; M2.0.8 will add "evolve the trusted set across rotations".

---

## Public API

```rust
use mfn_light::{LightChain, LightChainConfig, AppliedHeader, LightChainError};

// Bootstrap from a GenesisConfig — same config the full node uses.
let mut light = LightChain::from_genesis(LightChainConfig::new(genesis_cfg));
assert_eq!(light.tip_height(), 0);
assert_eq!(light.tip_id(), light.genesis_id());

// Follow the header chain one header at a time. Returns the new
// tip's block_id and the HeaderCheck stats from verify_header.
let applied: AppliedHeader = light.apply_header(&block.header)?;
assert_eq!(light.tip_height(), applied_height);

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

- **Unit (`chain::tests`, 7 tests)** — `from_genesis` lands at height 0 with tip = genesis id; genesis is deterministic across constructions; real signed block 1 applies cleanly; wrong `prev_hash` / wrong height / tampered `validator_root` are typed errors with state preserved; `stats()` agrees with individual accessors.
- **Integration (`tests/follow_chain.rs`, 5 tests)** — a `LightChain` follows a full `mfn_node::Chain` through 3 real BLS-signed blocks reaching identical tips; skipped headers rejected with state preserved; cross-chain header-injection caught by `validator_root` check (load-bearing demonstration of why M2.0 matters for light clients); recovery after a rejected header; typed-error surface of `ValidatorRootMismatch` through the wrapped `LightChainError::HeaderVerify`.

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
mfn-consensus = path      # BlockHeader, verify_header, build_genesis, block_id
thiserror     = "1.0"

[dev-dependencies]
mfn-node      = path      # produce_solo_block in integration tests
hex           = "0.4"
```

No async runtime, no networking, no on-disk store. Same pattern as `mfn-node`: stay pure-library; daemon concerns attach upstream.

---

## See also

- [`docs/M2_LIGHT_HEADER_VERIFY.md`](../docs/M2_LIGHT_HEADER_VERIFY.md) — the M2.0.5 primitive this crate composes.
- [`docs/M2_LIGHT_CHAIN.md`](../docs/M2_LIGHT_CHAIN.md) — design note for this slice.
- [`docs/ROADMAP.md`](../docs/ROADMAP.md) — phased rollout (M2.0.7 body verification, M2.0.8 validator-set evolution).
- [`mfn-consensus`](../mfn-consensus/README.md) — the spec this crate consumes.
- [`mfn-node`](../mfn-node/README.md) — the full-node analogue.
