# M2.0.7 — Light-client body verification

**Status:** ✓ shipped (M2.0.7 slice — header + body verification on top of `mfn-light`).

This note records the rationale, surface, and tests added by milestone **M2.0.7**. It builds directly on [M2.0.5's `verify_header`](./M2_LIGHT_HEADER_VERIFY.md) primitive and the [M2.0.6 `mfn-light` chain follower](./M2_LIGHT_CHAIN.md): with M2.0.6 a light client can prove a header was BLS-signed by a quorum of the trusted validator set; with **M2.0.7 it can additionally prove that a delivered body is byte-for-byte the body the producer signed over**.

---

## Why

After M2.0.6 a light client could already follow a header chain and trust the cryptographic authenticity of every header. But "header verified" only proves the *commitment values* in the header are genuine — it doesn't prove the body sitting next to that header is the one the producer actually used to compute those commitments.

A malicious peer could deliver a genuine (BLS-signed) header alongside a *substituted* body — replacing txs, dropping storage proofs, swapping a bond op for a slashing — and a header-only light client would have no way to detect the swap. The header's tx_root would be correct (signed-over) but it would no longer match the recomputed root of the delivered txs.

M2.0.7 closes this gap. The light client now re-derives the four body-bound Merkle roots that are pure functions of the block body and checks them against the (now authenticated) header. Combined with M2.0.5's BLS verification, this gives the light client cryptographic confidence that the **(header, body)** pair it accepted is exactly what some honest 2/3-stake quorum endorsed.

---

## What shipped

### 1. `mfn-consensus::verify_block_body` (the pure primitive)

```rust
pub fn verify_block_body(block: &Block) -> Result<(), BodyVerifyError>;

pub enum BodyVerifyError {
    TxRootMismatch          { expected: [u8; 32], got: [u8; 32] },
    BondRootMismatch        { expected: [u8; 32], got: [u8; 32] },
    SlashingRootMismatch    { expected: [u8; 32], got: [u8; 32] },
    StorageProofRootMismatch{ expected: [u8; 32], got: [u8; 32] },
}
```

Re-derives the four header-bound body roots from `block.<field>` and matches each against the corresponding field of `block.header`. Pure, stateless, allocation-cheap. Lives in the same module as `verify_header` ([`mfn-consensus::header_verify`](../mfn-consensus/src/header_verify.rs)) because they're the two halves of the same "light-client verification primitives" surface.

| # | Check | Failure → |
|---|---|---|
| 1 | `header.tx_root == tx_merkle_root(&block.txs)` | `TxRootMismatch { expected, got }` |
| 2 | `header.bond_root == bond_merkle_root(&block.bond_ops)` | `BondRootMismatch { expected, got }` |
| 3 | `header.slashing_root == slashing_merkle_root(&block.slashings)` | `SlashingRootMismatch { expected, got }` |
| 4 | `header.storage_proof_root == storage_proof_merkle_root(&block.storage_proofs)` | `StorageProofRootMismatch { expected, got }` |

The `expected` field carries the value the *header* claimed (i.e. what the producer BLS-signed over); `got` is the value the verifier recomputed from the delivered body. Useful for peer scoring / log diagnostics.

### 2. `mfn-light::LightChain::apply_block` (the consumer)

```rust
impl LightChain {
    pub fn apply_block(&mut self, block: &Block)
        -> Result<AppliedBlock, LightChainError>;
}

pub struct AppliedBlock {
    pub block_id: [u8; 32],
    pub check: HeaderCheck,
}

pub enum LightChainError {
    PrevHashMismatch { /* … */ },
    HeightMismatch   { /* … */ },
    HeaderVerify     { height: u32, source: HeaderVerifyError },
    BodyMismatch     { height: u32, source: BodyVerifyError },   // NEW in M2.0.7
}
```

`apply_block` is the full-block analogue of M2.0.6's `apply_header`. Steps, in order:

| # | Check | Failure → |
|---|---|---|
| 1 | `header.height == tip_height + 1` (strict monotonicity) | `HeightMismatch` |
| 2 | `header.prev_hash == tip_id` (chain linkage) | `PrevHashMismatch` |
| 3 | `verify_header(&block.header, trusted_validators, params)` | `HeaderVerify { source }` |
| 4 | **`verify_block_body(block)`** — body root reconstruction | `BodyMismatch { source }` |
| 5 | Advance `tip_height += 1`, `tip_id = block_id(&block.header)` | (infallible) |

On any failure the light chain's state is **byte-for-byte untouched** (no partial commits).

### Ordering rationale: header before body

Body verification runs *after* header verification because the diagnostic distinction matters:

- **`HeaderVerify`** = "this header isn't genuine" — produced by a forger or tampered with by a peer.
- **`BodyMismatch`** = "this header *is* genuine, but the delivered body doesn't match what it committed to" — the body was tampered after signing, or the peer delivered the wrong body for this header.

Both are hard rejects, but downstream tooling (peer scoring, syncer behaviour, alerts) wants to distinguish "wrong header" from "wrong body for a right header". Running header verification first gives that distinction for free.

---

## What this primitive does **not** verify

Two header-bound roots are *not* covered by `verify_block_body`:

| Root | Why not | Already covered by |
|---|---|---|
| `storage_root` | depends on cross-block dedup against the chain's `storage` map. A stateless verifier can't distinguish "new commitment in this block" from "re-anchor of an already-seen commitment" — `apply_block` silently filters the latter, so a stateless re-derivation has a false-positive rate when a block contains re-anchoring txs (which the protocol permits). | BLS aggregate over `header_signing_hash` (includes `storage_root`) → caught by M2.0.5 `verify_header`. |
| `utxo_root` | depends on the cumulative UTXO accumulator (post-block projection). State-dependent by nature. | Same — BLS aggregate covers it. |

These aren't lying-around vulnerabilities: a forged block can't smuggle a fake `storage_root` or `utxo_root` past `verify_header`, because the BLS aggregate signs over `header_signing_hash` which folds them in. The only thing a stateless verifier loses is the ability to independently *recompute* those two roots, and the only consequence is that a future light-client slice that wants to verify them (e.g. for inclusion proofs against the UTXO tree) must additionally maintain enough shadow state to do so.

`validator_root` is also a header-bound root, but it's the trust anchor of `verify_header` itself — the light client compares the header's `validator_root` against the canonical root of its *trusted* validator set. So it's verified, just not re-derived from the body.

---

## Test matrix

### `mfn-consensus::header_verify` unit tests (M2.0.7 slice)

| # | Test | Asserts |
|---|---|---|
| 1 | `verify_block_body_accepts_consistent_block` | a real signed block (built by `build_unsealed_header` which sets every root consistently) passes |
| 2 | `verify_block_body_rejects_tampered_tx_root` | flipping a byte in `header.tx_root` → typed `TxRootMismatch { expected, got }` with `got` matching the *un-tampered* re-derived root |
| 3 | `verify_block_body_rejects_tampered_bond_root` | flipping a byte in `header.bond_root` → typed `BondRootMismatch` |
| 4 | `verify_block_body_rejects_tampered_slashing_root` | flipping a byte in `header.slashing_root` → typed `SlashingRootMismatch` |
| 5 | `verify_block_body_rejects_tampered_storage_proof_root` | flipping a byte in `header.storage_proof_root` → typed `StorageProofRootMismatch` |
| 6 | `verify_block_body_rejects_tampered_tx_body` | pushing a duplicate tx into `block.txs` → typed `TxRootMismatch` (body-side tamper, header pristine) |
| 7 | `verify_block_body_is_deterministic` | repeated verification returns byte-for-byte the same `Ok(())` |
| 8 | `verify_block_body_accepts_genesis` | the genesis block (all-empty bodies, all-zero-sentinel roots) is body-consistent |

### `mfn-light` unit tests (M2.0.7 slice)

| # | Test | Asserts |
|---|---|---|
| 9 | `apply_block_accepts_real_signed_block` | real signed block 1 applies via `apply_block`, tip advances to height 1, producer index + signing stake reported |
| 10 | `apply_block_rejects_tampered_tx_root_in_header` | tampering a *header* field → `HeaderVerify` (BLS signature breaks before body check) |
| 11 | `apply_block_rejects_tampered_tx_body` | tampering the *body* without touching header → `BodyMismatch { TxRootMismatch }`, state preserved |
| 12 | `apply_block_rejects_wrong_prev_hash` | linkage fires before body verification |
| 13 | `apply_block_rejects_wrong_height` | linkage fires before body verification |
| 14 | `apply_block_chains_across_two_blocks` | apply two real blocks via `apply_block`, tip and height advance correctly |
| 15 | `apply_header_and_apply_block_agree_on_tip` | header-only vs full-block paths produce identical final stats for clean chains |

### `mfn-light` integration tests (M2.0.7 slice)

| # | Test | Asserts |
|---|---|---|
| 16 | `light_chain_apply_block_follows_full_chain_across_three_blocks` | `LightChain` via `apply_block` matches `mfn_node::Chain` tip-for-tip across 3 real blocks |
| 17 | `light_chain_apply_block_rejects_body_tx_tamper_with_state_preserved` | tampering `block.txs` (push a duplicate) → `BodyMismatch { TxRootMismatch }`, light chain state preserved |
| 18 | `light_chain_apply_block_rejects_storage_proof_body_tamper` | injecting a stray `StorageProof` into `block.storage_proofs` → `BodyMismatch { StorageProofRootMismatch }`, state preserved |
| 19 | `light_chain_apply_block_recovers_after_body_rejection` | rejected tampered body → preserved state → pristine body applies cleanly on top |
| 20 | `light_chain_apply_block_and_apply_header_agree_on_clean_chains` | for clean chains, `apply_header` and `apply_block` reach identical final stats — body verification is purely additive |

**20 new tests total** (8 in `mfn-consensus`, 7 unit + 5 integration in `mfn-light`). Workspace test count moved 374 → 394.

---

## What's intentionally *not* in M2.0.7

- **Validator-set evolution.** Walking `block.bond_ops` + `block.slashings` + pending-unbond settlements + liveness slashing to derive the next trusted validator set is the M2.0.8 slice. Until then, callers crossing a rotation boundary still need to re-bootstrap.
- **State-dependent root verification.** `storage_root` and `utxo_root` would require maintaining shadow state in the light client. Out of scope for "header + body Merkle commitments" — these are best done in a future slice if/when a light client needs UTXO inclusion proofs.
- **Re-org / fork choice.** Single canonical chain only.
- **Persistence.** State still lives in memory.

Each slice ships something complete in itself. M2.0.7 is "follow a chain through a stable-validator window, cryptographically verifying every (header, body) pair you accept." That's enough for a wallet to safely interpret block contents delivered by an untrusted node.

---

## Code map

| Crate | File | New / changed |
|---|---|---|
| `mfn-consensus` | `src/header_verify.rs` | extended — `verify_block_body`, `BodyVerifyError`, + 8 unit tests; module doc-comment + scope updated |
| `mfn-consensus` | `src/lib.rs` | re-export `verify_block_body`, `BodyVerifyError` |
| `mfn-light` | `src/chain.rs` | extended — `LightChain::apply_block`, `AppliedBlock`, `LightChainError::BodyMismatch` variant, + 7 unit tests |
| `mfn-light` | `src/lib.rs` | re-export `AppliedBlock`; crate doc-comment updated for M2.0.7 |
| `mfn-light` | `tests/follow_chain.rs` | + 5 integration tests for `apply_block` |
| `docs/M2_LIGHT_BODY_VERIFY.md` | this doc | new |

No protocol-level wire change. No header-field change. No new domain tag. M2.0.7 is purely additive verification logic on top of the M2.0.x commitment family.

---

## What this unlocks

- **M2.0.8 — Validator-set evolution.** Body verification gives the light client trusted access to `block.bond_ops` / `block.slashings`. The next step is to actually walk those deltas and evolve `trusted_validators` so the light client survives rotations.
- **Wallet inclusion proofs.** A wallet now has cryptographic proof that the txs in a block are the txs the producer signed over — enough to confidently extract its own outputs without trusting the serving node.
- **Storage-availability auditing.** A light client can now trust that the storage proofs in a block are the ones the producer emitted, so it can replay the SPoRA sampling locally to audit the network's storage availability claims.
- **Bridge / oracle correctness.** A reader on another chain can prove "Permawrite block N at height H contains tx T" by relaying the block header (cheap, fixed size), the body, and the Merkle inclusion path — all verifiable with the M2.0.5 + M2.0.7 primitives.

After M2.0.7 the light client compiles to "anybody can ship a wallet" rather than "anybody can sync the header chain." That's a meaningful step up the trust-minimisation ladder.
