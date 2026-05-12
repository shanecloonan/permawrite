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

Per roadmap: **treasury credit** (not burn) so permanence funding benefits from misbehavior penalties. Implemented in [`apply_block`](../mfn-consensus/src/block.rs) — both equivocation slashing (full stake forfeit) and liveness slashing (multiplicative forfeit) credit the lost amount to [`ChainState::treasury`](../mfn-consensus/src/block.rs) using saturating `u128` arithmetic.

## Bond funding (M1 economic model)

Validator registration is **burn-on-bond**: every successful [`BondOp::Register`] adds its declared `stake` to [`ChainState::treasury`]. This is the cleanest funding model — it requires no extra wire fields, no separate Schnorr proof of UTXO consumption, and it makes the chain's permanence-funding pool the canonical sink for validator economic commitment.

Combined with slash-to-treasury, this gives M1 a **closed economic-symmetry property**:

- Every base unit a validator commits via `BondOp::Register` is credited to the treasury.
- Every base unit a validator forfeits via equivocation or liveness slashing is credited to the treasury.
- Every base unit paid out to storage operators via [`accrue_proof_reward`](../mfn-storage/src/endowment.rs) drains the treasury (with emission backstop).

There is no path today for stake to flow *out* of the treasury back to a validator — that's the job of [unbond settlement](#unbond-flow-future-work) (next milestone). Until then, validator bonds are a one-way contribution to permanence.

### Funding the bond input (open question)

The above model assumes the producer who included the `BondOp::Register` had the moral authority to do so on behalf of the bonded operator. In a permissionless mempool a bond op without authorization could be replayed by an adversary. The two leading options:

1. **Schnorr-over-bond-bytes by operator's BLS key.** Simpler to verify; reuses existing primitives. Adds a `sig` field to `BondOp::Register`.
2. **UTXO consumption tied to bond bytes via a public-message hash.** Stronger funding proof but requires a new tx variant.

This is the largest remaining wire-format question for M1. Today's `BondOp::Register` is **unauthenticated** — sufficient for the consensus integration tests but explicitly insecure for a permissionless mempool. **Sealing this is a hard precondition for mainnet.**

## Unbond flow (future work)

## Unbond flow (future work)

Unbond support adds:

- `BondOp::Unbond { validator_index, sig }` — BLS-signed authorization by the validator's own key.
- `ChainState::pending_unbonds: BTreeMap<u32, PendingUnbond { unlock_height, stake_at_request }>` keyed by validator index.
- Settlement phase in `apply_block` (runs before liveness so the unbonded validator is excluded from the bitmap for this block):
  - At `height >= unlock_height`, the entry is popped; the validator's `stake` is set to `0`; the operator's payout is funded via an augmented coinbase output (treasury debit, emission-backstopped exactly like storage rewards).
  - Exit churn cap (`max_exit_churn_per_epoch`) enforced via `try_register_exit_churn` per settled validator.
- Late equivocation slashing during the unbond delay still routes to treasury (validator entry is still in `validators` with non-zero stake).

## Test matrix (M1 completion criteria)

- ✓ Bond accepted → validator appears with correct index, stats row, eligible in VRF same epoch rules as chosen. *(block::tests::bond_op_round_trip in `bond_wire.rs`; apply-side in `block.rs`.)*
- ✓ Burn-on-bond credits treasury *(block::tests::burn_on_bond_credits_treasury, burn_on_bond_aggregates_multiple_registers).*
- ✓ Equivocation evidence credits treasury *(block::tests::equivocation_slash_credits_treasury_via_apply_block).*
- ✓ Liveness slash credits treasury *(block::tests::liveness_slash_credits_treasury, liveness_slash_treasury_compounds_with_validator_stake).*
- ✓ Churn cap: N+1-th bond in same epoch rejected with deterministic error *(bonding::tests::entry_churn_cap; apply-side in block::tests).*
- □ Unbond submitted → validator still slashable until delay elapses. *(pending — M1.2.)*
- □ Settlement at unlock height debits treasury + zeros stake. *(pending — M1.2.)*

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
