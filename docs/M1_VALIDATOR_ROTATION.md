# M1 — Validator rotation (design specification)

> **Status.** Specification + default parameters + pure validation helpers in `mfn-consensus::bonding`. **Not yet wired** into `apply_block` or the TypeScript reference; the next PRs must update TS (`lib/network/`) in lockstep for any wire change.

## Problem statement

Today `ChainState::validators` is cloned from [`GenesisConfig`](../mfn-consensus/src/block.rs) at `apply_genesis` and only **mutated in-place** for slashing (stake set to zero). There is no path to:

- onboard a new validator with economic stake,
- schedule stake exit without breaking the evidence window for equivocation,
- cap how many validators enter or leave per epoch (stability / light-client cost).

M1 adds **rotation** while preserving everything already enforced: VRF lottery keyed by validator index, BLS finality bitmap alignment, liveness stats aligned 1:1 with `validators`, and treasury credit on slash.

## Design principles

1. **Determinism.** Every rotation decision is a pure function of committed block state + explicit transactions (no off-chain registry).
2. **Evidence safety.** An unbonding validator remains subject to [`SlashEvidence`](../mfn-consensus/src/slashing.rs) until any configured delay has passed **and** the chain has processed the exit (slash can still zero a “pending exit” validator).
3. **Bounded churn.** Limit validators added or removed per **epoch** so the set cannot thrash under griefing; exact defaults live in [`bonding::DEFAULT_BONDING_PARAMS`](../mfn-consensus/src/bonding.rs).
4. **Single bond per validator** (roadmap decision). No delegation graph in M1; one `Validator` row ↔ one operator-controlled bond.
5. **Byte parity with TS.** Any on-wire `Bond` / `Unbond` / header field must be mirrored in `cloonan-group/lib/network/` before mainnet claims.

## Epoch model

Define `slots_per_epoch` as a **consensus parameter** (new field on `ConsensusParams` in a follow-up PR, or carried in `BondingParams` only—implementation choice). Default starting point:

```text
epoch_id = floor(height / slots_per_epoch)   // genesis height 0 ⇒ epoch 0
```

Churn counters reset at epoch boundaries: “how many validators **entered** this epoch” and “how many **fully exited** this epoch”.

## Chain state extensions (planned)

The following are **not implemented yet**; they document the intended `ChainState` growth:

| Field | Purpose |
| --- | --- |
| `pending_unbonds` | Queue of `(validator_index, unlock_height, stake_returned)` sorted deterministically. |
| `next_validator_index` | Monotonic counter for fresh `Validator::index` (never reuse indices in one chain history). |
| `epoch_churn_entry` / `epoch_churn_exit` | Counters for the active epoch; reset when `epoch_id` increments. |

`validator_stats` stays aligned by **index** with `validators`; removing a validator from the middle is **forbidden**—instead mark `stake = 0` and optionally **compact** only at controlled boundaries (post-M1 discussion) or keep tombstones for index stability. **M1 recommendation:** keep fixed-length `validators` for the lifetime of an epoch; apply exits only at epoch end after unbond delay, compacting into a new vector in deterministic order (e.g. sort surviving validators by index, then append new entrants sorted by bond tx order).

## Transaction / block body shape (options)

**Option A — Separate merkle root (header v2).** Add `bond_root` to `BlockHeader` and `Vec<BondOp>` to `Block`. Clean separation from RingCT `TransactionWire`; mempool treats bond ops separately.

**Option B — New `TransactionWire` version.** Encode bond/unbond as `version = 2` with empty inputs/outputs and typed `extra` payload. Maximizes reuse of `tx_root` but couples mempool validation to tx versioning.

**Recommendation for implementation:** **Option A** for clarity and auditability; bump `HEADER_VERSION` only when `bond_root` is non-zero or always commit a hash of empty vec for one release (soft transition).

## Bond operation (logical)

A **bond** includes at minimum:

- `stake_amount` (≥ `min_validator_stake`),
- `vrf_pk`, `bls_pk` (already modeled on [`Validator`](../mfn-consensus/src/consensus.rs)),
- `payout: Option<ValidatorPayout>` (stealth payout for rewards),
- **Proof of payment:** either a referenced UTXO spend inside the same block’s `txs`, or an explicit burn-to-treasury / lock script path. *Exact funding rule is the largest open design item; default proposal: bond tx includes a Schnorr signature over a new domain tag proving control of a funding UTXO consumed in the same block.*

Unbond:

- `validator_index`,
- `signature` from that validator’s BLS or VRF key material (prevents griefing unbond of others),
- optional partial unbond if we allow stake decrease without exit (M1 can require **full exit** only).

## Slashed stake disposition

Per roadmap: **treasury credit** (not burn) so permanence funding benefits from misbehavior penalties. Exact `u128` credit path must not overflow; mirror existing treasury math style in `apply_block`.

## Test matrix (M1 completion criteria)

- Bond accepted → validator appears with correct index, stats row, eligible in VRF same epoch rules as chosen.
- Unbond submitted → validator still slashable until delay elapses.
- Equivocation evidence for validator in unbond window → stake zeroed, treasury credited.
- Churn cap: N+1-th bond in same epoch rejected with deterministic error.
- Entry/exit with empty / max-sized validator sets (property tests optional).

## Code map

| Piece | Location |
| --- | --- |
| Defaults + pure checks | [`mfn-consensus/src/bonding.rs`](../mfn-consensus/src/bonding.rs) |
| State transition (future) | `mfn-consensus/src/block.rs` — `apply_block` |
| Wire encode/decode (future) | `mfn-crypto::codec` + TS `codec.ts` |
| Reference TS (future) | `cloonan-group/lib/network/bonding.ts` (new) |

## References

- [ROADMAP.md](./ROADMAP.md) — Milestone M1 section
- [CONSENSUS.md](./CONSENSUS.md) — VRF + BLS + finality
- [ARCHITECTURE.md](./ARCHITECTURE.md) — `apply_block` ordering
