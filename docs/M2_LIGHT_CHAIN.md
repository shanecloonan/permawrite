# M2.0.6 — `mfn-light` crate skeleton: header-chain follower

**Status:** ✓ shipped (M2.0.6 slice — header following with stable validator set).

This note records the rationale, surface, and tests added by milestone **M2.0.6**. It is the first slice of the `mfn-light` crate — the user-facing light client built on top of [M2.0.5's `verify_header`](./M2_LIGHT_HEADER_VERIFY.md) primitive.

---

## Why

The M2.0.x series finished the "header binds every body element" invariant and shipped the pure-function `verify_header` primitive. The natural next step is the *first* consumer of that primitive: a chain follower that tracks the tip header-by-header.

`apply_block` in `mfn-consensus` + `Chain` in `mfn-node` give us a full-node orchestrator that owns a `ChainState`. But the whole point of a light client is to *not* own that state — to track the chain with just a tip pointer + a trusted validator set, suitable for:

- **Mobile / browser wallets.** Compile `mfn-consensus` + `mfn-light` to WASM, give the client a trusted `GenesisConfig` (or a checkpoint), and let it independently verify the tip of every block a remote node tells it about.
- **Cross-chain bridges.** A reader on another chain can follow Permawrite headers given the canonical genesis + the validator-set evolution rules.
- **Audit tooling.** "Is this archival header genuine and on the canonical chain?" without replaying years of blocks.

M2.0.6 is the **skeleton**: just enough surface to follow a chain through a *stable validator-set window* (no rotation). M2.0.7 will add body verification, M2.0.8 will add rotation handling.

---

## What shipped

### New crate

[`mfn-light`](../mfn-light/) — a workspace-member crate.

Dependency closure (no `tokio`, no `rocksdb`, no `libp2p` — pure-Rust consensus-spec deps only, so the same crate can compile to `wasm32-unknown-unknown` for in-browser use):

```toml
[dependencies]
mfn-crypto    = path     # primitives, codec
mfn-bls       = path     # BLS (transitive via mfn-consensus)
mfn-storage   = path     # storage roots (transitive via mfn-consensus)
mfn-consensus = path     # BlockHeader, verify_header, build_genesis, block_id
thiserror     = "1.0"

[dev-dependencies]
mfn-node      = path     # produce_solo_block — used only by integration tests
hex           = "0.4"
```

### API

```rust
pub struct LightChain { /* trusted_validators, params, tip_height, tip_id, genesis_id */ }
pub struct LightChainConfig { pub genesis: GenesisConfig }
pub struct LightChainStats { /* height, tip_id, genesis_id, validator_count, total_stake */ }

pub struct AppliedHeader {
    pub block_id: [u8; 32],
    pub check: HeaderCheck,
}

pub enum LightChainError {
    PrevHashMismatch { height, expected, got },
    HeightMismatch   { expected, got },
    HeaderVerify     { height, source: HeaderVerifyError },
}

impl LightChain {
    pub fn from_genesis(cfg: LightChainConfig) -> Self;     // infallible
    pub fn apply_header(&mut self, header: &BlockHeader)
        -> Result<AppliedHeader, LightChainError>;
    pub fn tip_height(&self)        -> u32;
    pub fn tip_id(&self)            -> &[u8; 32];
    pub fn genesis_id(&self)        -> &[u8; 32];
    pub fn trusted_validators(&self) -> &[Validator];
    pub fn params(&self)            -> &ConsensusParams;
    pub fn total_stake(&self)       -> u64;
    pub fn stats(&self)             -> LightChainStats;
}
```

### `apply_header` checks (in order)

| # | Check | Failure → |
|---|---|---|
| 1 | `header.height == tip_height + 1` (strict monotonicity — no batches, no reorders) | `HeightMismatch` |
| 2 | `header.prev_hash == tip_id` (chain linkage) | `PrevHashMismatch` |
| 3 | `verify_header(header, trusted_validators, params)` returns `Ok` (validator-root match + producer proof + BLS finality aggregate) | `HeaderVerify { source }` |
| 4 | Advance `tip_height += 1`, `tip_id = block_id(header)` | (infallible; no partial commits) |

On any failure the light chain's state is **byte-for-byte untouched**.

### Why `from_genesis` is infallible

Light-client bootstrap is fundamentally a *trust assertion* on the caller's side: "I trust this `GenesisConfig`". Given that trust, the light client just needs to compute the genesis `block_id` (an infallible hash of the genesis header) and copy `cfg.validators` into the trusted set. The full-node `apply_genesis` performs additional validation (endowment parameters, validator stat array initialization, treasury setup, …) that's not relevant to light-client operation — none of those produce a different `block_id` or a different validator set. So the constructor returns `Self`, not `Result<Self, _>`.

This is a deliberate API simplification that matches the threat model.

### Architectural insight discovered during testing

`build_genesis` produces a header with `validator_root = [0u8; 32]` — it commits to the *pre-genesis* validator set (empty), since the genesis block itself *installs* the initial set. Consequence: two `GenesisConfig`s with identical `initial_outputs` / `initial_storage` / `timestamp` but **different `validators`** produce **byte-for-byte identical genesis headers**. So `genesis_id_A == genesis_id_B`.

This means `prev_hash` linkage alone does *not* distinguish parallel chains that share a minimal genesis. The defence-in-depth that catches cross-chain header injection is **M2.0's `validator_root`** commitment: every post-genesis header's `validator_root` reflects the set the producer was signing under, so a header from chain B (signed under chain B's validators) will be rejected by a light chain bootstrapped from chain A (trusting chain A's validators) — exactly as `HeaderVerifyError::ValidatorRootMismatch`.

This is documented in the integration test `light_chain_rejects_header_from_different_chain` and is the load-bearing motivation for why the M2.0 validator-set commitment was the right structural change.

---

## Test matrix

| # | Test | Layer | Asserts |
|---|---|---|---|
| 1 | `from_genesis_lands_at_height_zero` | unit | tip_height = 0, tip = genesis, validator count + total stake match |
| 2 | `from_genesis_is_deterministic_across_constructions` | unit | repeated construction → same genesis_id and tip_id |
| 3 | `apply_header_accepts_real_signed_block` | unit | a producer-side-built real BLS-signed block 1 applies cleanly through the light chain |
| 4 | `apply_header_rejects_wrong_prev_hash` | unit | tampered `prev_hash` → typed `PrevHashMismatch`, state preserved |
| 5 | `apply_header_rejects_wrong_height` | unit | tampered `height` → typed `HeightMismatch`, state preserved |
| 6 | `apply_header_rejects_tampered_validator_root` | unit | tampered `validator_root` → typed `HeaderVerify { ValidatorRootMismatch }`, state preserved |
| 7 | `stats_agree_with_individual_accessors` | unit | `stats()` matches each accessor |
| 8 | `light_chain_follows_full_chain_across_three_blocks` | integration | `LightChain` and `mfn_node::Chain` reach identical tips on every block of a real 3-block chain |
| 9 | `light_chain_rejects_skipped_header_with_state_preserved` | integration | applying block 2 to a light chain at h=0 → `HeightMismatch`, state preserved |
| 10 | `light_chain_rejects_header_from_different_chain` | integration | cross-chain header injection caught by `validator_root` mismatch (genesis ids collide by minimal-config construction; `validator_root` is the protection) |
| 11 | `light_chain_recovers_after_rejected_header` | integration | tampered header rejected, state preserved, clean block still applies on top |
| 12 | `light_chain_surfaces_validator_root_mismatch_through_typed_error` | integration | `HeaderVerifyError::ValidatorRootMismatch` surfaces through `LightChainError::HeaderVerify { source }` |

12 new tests total: 7 unit + 5 integration. Workspace test count moved 362 → 374.

---

## What's intentionally *not* in M2.0.6

- **Body verification.** Reconstructing every body Merkle root from a delivered body and asserting it matches the header is a separate concern. This is the M2.0.7 slice — the light client will accept a `(&BlockHeader, &Block)` pair and assert both the header is verifiable *and* the body roots match.
- **Validator-set evolution.** Walking `block.bond_ops`, `block.slashings`, liveness slashing (whatever portion of it can be replayed from the bitmap), and pending-unbond settlements to derive the *next* trusted validator set is the M2.0.8 slice. Until then, callers crossing a rotation boundary should re-bootstrap from a freshly-trusted checkpoint.
- **Re-org / fork choice.** Single canonical header chain only.
- **Persistence.** State lives in memory. A future `mfn-light::store` module would add disk snapshots.

These omissions are *deliberate*: each slice ships as something complete in itself. M2.0.6 is "follow a header chain through a stable-validator window"; that's a wholly useful artifact today.

---

## Code map

| Crate | File | New / changed |
|---|---|---|
| `mfn-light` | `Cargo.toml` | new (workspace member) |
| `mfn-light` | `src/lib.rs` | new — crate root with `pub mod chain` |
| `mfn-light` | `src/chain.rs` | new — `LightChain`, `LightChainConfig`, `LightChainStats`, `AppliedHeader`, `LightChainError`, + 7 unit tests |
| `mfn-light` | `tests/follow_chain.rs` | new — 5 integration tests against a real `mfn-node::Chain` |
| `mfn-light` | `README.md` | new |
| `Cargo.toml` (workspace root) | added `mfn-light` to members | modified |
| `docs/M2_LIGHT_CHAIN.md` | this doc | new |

No protocol-level wire change. No header-field change. No new domain tag. M2.0.6 is purely a new *crate* on top of the existing `mfn-consensus` spec surface.

---

## What this unlocks

- **M2.0.7 — Body-root verification.** Extend `apply_header` to take a body and re-derive `tx_root` / `bond_root` / `slashing_root` / `storage_proof_root` / `storage_root`. Trivial layer on existing `*_merkle_root` helpers.
- **M2.0.8 — Validator-set evolution.** Walk body deltas (bond ops, slashings, unbond settlements) to evolve trusted_validators across rotations. The first real "long-running light client" milestone.
- **WASM bindings (`mfn-wasm`).** Compile `mfn-consensus` + `mfn-light` to WASM, ship to browsers. The dependency graph is intentionally pure-Rust to make this clean.
- **Cross-chain bridges.** Same `verify_header` + chain follower, embedded in another chain's smart contracts.

The light client has been earning the right to exist for six milestones (M2.0 / M2.0.1 / M2.0.2 closed the header-binds-body invariant; M2.0.3 / M2.0.4 made full-node chains end-to-end; M2.0.5 surfaced the pure verifier). M2.0.6 is the first piece that compiles to a browser.
