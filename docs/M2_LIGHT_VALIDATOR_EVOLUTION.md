# Milestone M2.0.8 — Light-client validator-set evolution

> **Status:** ✓ Shipped. Tests: 412 passing (workspace).
> Code: `mfn-consensus/src/validator_evolution.rs` (new module),
> `mfn-consensus/src/block.rs` (apply_block refactored to consume it),
> `mfn-light/src/chain.rs` (LightChain evolves trusted set per block).

## TL;DR

After M2.0.5 / M2.0.6 / M2.0.7 a light client can cryptographically
verify a block's header *and* body against a *fixed* trusted validator
set. That is enough to follow a chain through any window where the
validator set is stable, but **the moment the chain rotates** (a
`BondOp::Register` adds a validator, an equivocation slashing zeros
one, an unbond settlement disables one, a liveness slash reduces a
stake) the light client's `verify_header` call on the *next* block
fails with `ValidatorRootMismatch`: the chain's header now commits to
a set the light client doesn't know about.

M2.0.8 closes that gap by making the light client **evolve its
trusted validator set deterministically across rotations**, byte-for-byte
the same way the full node does in `mfn_consensus::apply_block`.

The key insight: the full node's validator-set evolution is *already*
a pure function of `(pre-block validator set, block.bond_ops,
block.slashings, finality bitmap, height, params)`. We extract it
into a shared `mfn-consensus::validator_evolution` module so that the
full node and the light client call **the same code** to mutate the
set. No drift is possible by construction — if the light client's
evolution disagrees with the full node's, the very next block's
`verify_header` rejects with `ValidatorRootMismatch` because the
header's pre-block `validator_root` commits to the (correct) full-node
view.

## Why this matters for the project's goals

Permawrite's privacy + permanence mission requires a chain anyone can
follow trustlessly from anywhere — including resource-constrained
devices (mobile wallets, in-browser apps, embedded clients). A light
client that can *only* follow stable-validator windows is not
trustless across the long term: every rotation forces a re-bootstrap
from a freshly-trusted checkpoint, defeating the entire point of
chain following.

With M2.0.8 a `mfn-light` chain can follow indefinitely from a single
genesis bootstrap. That unblocks:

- Trustless wallet UIs running headless verification in the user's
  browser tab.
- Mobile clients that follow the chain in the background and verify
  inclusion proofs against their locally-trusted tip.
- Cross-shard / cross-chain light bridges that need a long-running
  attested view of Permawrite's state without operating a full node.

## Architecture: single source of truth

Pre-M2.0.8 layout:

```
mfn-consensus::block::apply_block      [full-node state transition]
  ├── inlined: equivocation slashing
  ├── inlined: liveness slashing
  ├── inlined: bond ops (simulate_bond_ops private helper)
  └── inlined: unbond settlements
```

M2.0.8 layout:

```
mfn-consensus::validator_evolution     [shared pure helpers]
  ├── apply_equivocation_slashings(&mut [Validator], &[SlashEvidence])
  ├── apply_liveness_evolution(&mut [Validator], &mut Vec<ValidatorStats>, &[u8] bitmap, &ConsensusParams)
  ├── apply_bond_ops_evolution(height, &mut counters, &mut Vec<Validator>, &mut Vec<ValidatorStats>, &mut BTreeMap, &BondingParams, &[BondOp])
  └── apply_unbond_settlements(height, &mut counters, &BondingParams, &mut [Validator], &mut BTreeMap)

mfn-consensus::block::apply_block      [full-node state transition]
  ├── calls apply_equivocation_slashings    ← single line replacement
  ├── calls apply_liveness_evolution        ← single line replacement
  ├── calls apply_bond_ops_evolution        ← single line replacement
  └── calls apply_unbond_settlements        ← single line replacement

mfn-light::chain::apply_block          [light-client chain follower]
  ├── linkage + verify_header + verify_block_body
  └── calls the same four functions on a staged copy of trusted_validators
```

**The byte-for-byte parity guarantee is structural:** there is no
hand-written mirror of the evolution logic in `mfn-light`. Both
consumers call the same module.

## The four phases (recap)

### Phase A — Equivocation slashing

Inputs: pre-block validators, `block.slashings`.

For each slash evidence:
1. **Canonicalize** via `slashing::canonicalize` (so swapping the
   `(hash_a, sig_a) / (hash_b, sig_b)` pair cannot forge a different
   leaf).
2. **Dedupe** within the block (reject duplicate `voter_index`).
3. **Verify** via `slashing::verify_evidence` (two BLS verifies +
   hash-match-but-bytes-differ).
4. On success, **zero** `validators[voter_index].stake`.

Returns: forfeited stake total (caller credits the permanence
treasury) + a per-slash error list. Failed slashings do **not** abort
the phase; they're surfaced as `EquivocationError::{Duplicate,
Invalid}`.

### Phase B — Liveness slashing

Inputs: pre-block validators, `validator_stats`, finality bitmap
(decoded from `header.producer_proof`), `ConsensusParams`.

Walk each non-zero-stake validator:
- Bit set ⇒ `stats.consecutive_missed = 0`, `total_signed += 1`.
- Bit clear ⇒ `stats.consecutive_missed += 1`, `total_missed += 1`.
- If `consecutive_missed >= liveness_max_consecutive_missed`:
  multiplicatively reduce stake by `liveness_slash_bps`, increment
  `liveness_slashes`, reset `consecutive_missed = 0`.

Returns: liveness burn total (caller credits treasury).

Zero-stake (already-zombie) validators are skipped — they're awaiting
rotation reap and shouldn't be slashed twice.

### Phase C — Bond ops

Inputs: height, `BondEpochCounters`, validators, validator_stats,
`pending_unbonds`, `BondingParams`, `block.bond_ops`.

For each op (atomically — first failure rolls back):
- **Register**: verify `min_validator_stake`, verify BLS register sig,
  reject duplicate `vrf_pk`, consume entry-churn budget, assign
  `next_validator_index`, append to validators + default-stats,
  burn stake to treasury (returned as aggregate).
- **Unbond**: find validator by index, reject if already zombie,
  reject duplicate-unbond, verify BLS unbond sig, compute
  `unlock_height = height + unbond_delay_heights`, enqueue.

Atomic semantics: either *all* ops apply or *none*. This matches
`apply_block`'s `BlockError::BondOpRejected` behavior — a bad
bond-ops list rejects the entire block.

### Phase D — Unbond settlements

Inputs: height, `BondEpochCounters`, `BondingParams`, validators,
`pending_unbonds`.

Walk pending_unbonds in deterministic sorted-by-`validator_index`
order. For each entry whose `unlock_height <= height` AND that fits
in the remaining exit-churn budget for `bond_counters.bond_epoch_id`:
- Consume exit-churn budget.
- Zero the validator's stake.
- Remove from `pending_unbonds`.

Stops at the first entry that can't be admitted (churn full); the
remaining due entries are held over to the next block.

## Light-client integration: `LightChain::apply_block`

Pre-M2.0.8:

```text
apply_block:
  (1) height linkage         ──► HeightMismatch
  (2) prev_hash linkage      ──► PrevHashMismatch
  (3) verify_header          ──► HeaderVerify
  (4) verify_block_body      ──► BodyMismatch
  (5) tip = block_id(header)
```

Post-M2.0.8:

```text
apply_block:
  (1) height linkage         ──► HeightMismatch
  (2) prev_hash linkage      ──► PrevHashMismatch
  (3) verify_header          ──► HeaderVerify
  (4) verify_block_body      ──► BodyMismatch
  ── staged copies created for validator-set evolution ──
  (5a) apply_equivocation_slashings (staged)   ── EquivocationError surfaced as silent skip
  (5b) apply_liveness_evolution     (staged)   ── decodes finality bitmap from header
  (5c) apply_bond_ops_evolution     (staged)   ──► EvolutionFailed (atomic)
  (5d) apply_unbond_settlements     (staged)
  ── atomic commit ──
  (6) trusted_validators = staged_validators
      validator_stats     = staged_stats
      pending_unbonds     = staged_pending
      bond_counters       = staged_counters
      tip = block_id(header)
```

### New `LightChainError` variants

- **`EvolutionFailed { height, index, message }`** — bond ops were
  rejected. In an honest chain, 2/3-stake quorum signed a header
  whose body commits to bond ops `mfn-consensus` would also reject.
  That's a Byzantine fault; the light client guards against it
  defensively even though it shouldn't happen with honest majority.

Existing variants (`HeightMismatch`, `PrevHashMismatch`,
`HeaderVerify`, `BodyMismatch`) are unchanged. Equivocation-slashing
errors are *not* surfaced — the full node's `apply_block` happily
applies the *valid* slashings even when some entries in the slashing
list are individually invalid (it reports them as `BlockError` but
still advances the chain). The light client mirrors that behavior.

### Atomicity

`apply_block` always commits **all or none** of:
- tip pointer
- trusted_validators
- validator_stats
- pending_unbonds
- bond_counters

If any phase rejects (or any earlier check fails), the light chain
is byte-for-byte identical to its pre-call state. This is the
contract every test relies on, and what makes "retry after
rejection" safe.

### `AppliedBlock` extensions

The success path now reports:
- `validators_added: u32` (successful Register ops)
- `validators_slashed_equivocation: u32` (valid SlashEvidence entries)
- `validators_slashed_liveness: u32` (liveness-slashes that fired)
- `validators_unbond_settled: u32` (unlock-height-reached settlements)

Together with the new tip, these are the audit trail of what changed
in the trusted set for this block.

## The cross-block audit (key invariant)

After `apply_block(n)` succeeds, the light client's evolved trusted
set MUST equal the full node's `state.validators` after the same
block, otherwise the next `apply_block(n+1)` will fail with
`HeaderVerify { ValidatorRootMismatch }`. Why:

1. Block `n+1`'s header commits to `validator_root_after_block_n` in
   its `validator_root` field (M2.0).
2. `verify_header` recomputes `validator_set_root(&trusted_validators)`
   and compares it against `header.validator_root`.
3. If the light client's trusted set drifted from the full node's
   during block `n`'s evolution, those roots will differ.

This is the **single most important property** of the M2.0.8 design:
the chain's own headers audit the light client's evolution. There is
no "soft" inconsistency window — drift is detected at the very next
block.

## Test matrix

### Unit tests (mfn-consensus::validator_evolution, 8 new)

1. `equivocation_empty_input_is_noop` — empty slashings = no mutation.
2. `liveness_clears_consecutive_missed_on_signed_bit` — sign clears
   counter; threshold trip slashes; counter resets.
3. `liveness_skips_zero_stake_validators` — zombies untouched.
4. `liveness_resizes_stats_when_misaligned` — stats array auto-extends.
5. `bond_ops_empty_is_noop` — empty bond_ops = no mutation.
6. `unbond_settlements_empty_pending_is_noop` — empty queue = no
   mutation.
7. `unbond_settlements_zeros_validator_at_unlock_height` — settles
   when `unlock_height <= height`.
8. `bitmap_extract_empty_proof_returns_none` — bitmap extractor on
   genesis-style header returns None.

### Unit tests (mfn-light, 8 new)

1. `from_genesis_initializes_shadow_state` — initialization mirrors
   `apply_genesis`.
2. `from_genesis_empty_validators_indexes_at_zero` — corner case for
   bootstrapping without validators.
3. `apply_block_increments_total_signed_for_voting_validator` — stats
   advance per block.
4. `apply_block_total_signed_advances_across_blocks` — stats advance
   across multiple blocks.
5. `apply_block_body_tamper_preserves_validator_stats` — atomicity:
   stats untouched on rejection.
6. `evolution_drift_caught_by_next_block_validator_root_check` —
   simulated drift caught by next block.
7. `applied_block_counts_are_zero_for_no_event_chain` — no-event
   chains report zero deltas.
8. `validator_set_root_matches_next_block_header_after_apply` — the
   headline invariant.

### Integration tests (mfn-light::tests::follow_chain, 2 new)

1. `light_chain_follows_register_then_unbond_rotation_across_five_blocks`
   — 5-block scenario: Register v1, normal, Unbond v1, normal,
   settle. Asserts `validator_set_root` agreement at every step,
   `AppliedBlock` deltas match.
2. `light_chain_rejects_tampered_bond_op_with_body_mismatch` — a
   tampered bond op in a previously-valid block is caught by
   `BodyMismatch / BondRootMismatch` *before* evolution runs.

Plus one ignored-placeholder integration test (`light_chain_rejects_invalid_bond_op_signature_via_evolution_failed`)
reserved for the M2.0.8.x slice that ships a fixture for hand-signed
Byzantine blocks.

## What's not in scope for M2.0.8

- **Stake recomputation cross-check.** The light client could
  optionally re-verify the slashing evidence the same way the chain
  does. We don't currently surface invalid slashings as light-client
  errors (we mirror `apply_block`'s "soft skip" behavior). A future
  slice could surface them via a new `EquivocationCheck`-style
  outcome on `AppliedBlock`.
- **Liveness-slash audit.** The light client trusts that the finality
  bitmap in the header faithfully reflects which validators voted —
  it has to, since the bitmap is BLS-signed-over in
  `header_signing_hash`. A future slice could surface the bitmap to
  consumers as `AppliedBlock::voted_indices` for application-layer
  analysis.
- **Persistence.** All shadow state lives in memory. Adding a serde
  layer to checkpoint `LightChain` is straightforward and orthogonal
  to this design.
- **Re-org / fork choice.** Single canonical header chain only.

## What this unlocks for downstream milestones

- **M2.1 — Multi-node testnet.** A multi-node testnet can include
  `mfn-light` consumers (e.g. wallet UIs, monitoring dashboards)
  that follow rotations without ever talking to a full node beyond
  the initial bootstrap.
- **Light-client P2P sync (M2.2).** Now that `LightChain::apply_block`
  evolves correctly across rotations, a peer-to-peer gossip layer
  can deliver block headers + bodies and the light client can verify
  them independently.
- **In-browser wallets (M2.3+).** The WASM-friendly `mfn-light` crate
  has the building block needed for a no-trust browser wallet that
  follows the chain itself and verifies inclusion proofs locally.
