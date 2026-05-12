# M1 — Validator rotation (design + as-shipped reference)

> **Status.** **Shipped.** `BondOp::Register` (burn-on-bond) and `BondOp::Unbond` (BLS-signed, delayed settlement) are wired through the full `apply_block` state-transition function with per-epoch entry / exit churn caps, atomic rollback, and slash-to-treasury parity. The only remaining tickets are (a) mempool-grade authorization for `BondOp::Register` and (b) the optional explicit operator payout on settlement — both deferred to a future milestone (see [§ Future work](#future-work)). TS reference parity is in place for `BondOp::Register`; the unbond vector is queued for the next interop bump.

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

## Chain state extensions (shipped)

The following fields were added to [`ChainState`](../mfn-consensus/src/block.rs) as part of M1:

| Field | Purpose |
| --- | --- |
| `bonding_params: BondingParams` | Per-chain rotation knobs — min stake, unbond delay, churn caps, `slots_per_epoch`. Defaults via [`DEFAULT_BONDING_PARAMS`](../mfn-consensus/src/bonding.rs); overridable via `GenesisConfig::bonding_params: Option<BondingParams>`. |
| `bond_epoch_id: u64` | Currently active rotation epoch (`floor(height / slots_per_epoch)`). |
| `bond_epoch_entry_count: u32` | Count of `BondOp::Register` ops accepted in the current epoch. Reset when `bond_epoch_id` increments. |
| `bond_epoch_exit_count: u32` | Count of `BondOp::Unbond` ops accepted in the current epoch. Same reset rule. |
| `next_validator_index: u32` | Monotonic counter for fresh `Validator::index`. Indices are **never reused**, even after a validator is slashed to zero stake or unbonded. |
| `pending_unbonds: BTreeMap<u32, PendingUnbond>` | Queued unbonds keyed by `validator_index` for O(log n) settlement and naturally deterministic ordering. Each entry stores `unlock_height`, `stake_at_request`, and `request_height`. |

`validator_stats` stays aligned by **index** with `validators`; removing a validator from the middle is **forbidden**. Instead, unbond settlement (and equivocation slashing) marks `stake = 0` and the entry becomes a non-signing zombie — kept in place so existing indices remain stable for finality bitmaps, evidence references, and historical liveness stats. Compaction (if ever needed) is a deliberate future operation that would require a hard-fork wire bump.

## Transaction / block body shape (as shipped)

**Option A — Separate merkle root.** `BlockHeader` carries `bond_root: [u8; 32]` (zero sentinel for empty bond-op blocks) and `Block` carries `bond_ops: Vec<BondOp>`. Bond ops are validated and applied in their own phase of `apply_block`, decoupled from the RingCT `TransactionWire` pipeline — clean for mempool admission, auditing, and future per-op fee rules. `HEADER_VERSION` remains `1`; the on-wire compatibility break is the addition of the `bond_root` field, which is committed every block (even when empty) so the binding root over `bond_ops` is always present.

## Bond operations (as shipped)

The on-wire enum is [`BondOp`](../mfn-consensus/src/bond_wire.rs):

```rust
pub enum BondOp {
    Register {
        stake:   u64,                       // ≥ bonding_params.min_validator_stake
        vrf_pk:  EdwardsPoint,
        bls_pk:  BlsPublicKey,
        payout:  Option<ValidatorPayout>,   // stealth payout (deferred — see Future work)
    },
    Unbond {
        validator_index: u32,
        sig:             BlsSignature,      // over dhash(UNBOND_OP_SIG, validator_index.to_be_bytes())
    },
}
```

### `BondOp::Register`

- Stake amount validated by [`bonding::validate_stake`](../mfn-consensus/src/bonding.rs) (must satisfy `min_validator_stake`).
- `vrf_pk` must be unique across the active validator set (collision rejection).
- Per-epoch entry-churn cap enforced via `try_register_entry_churn`.
- On success: a new `Validator` row is appended with `index = next_validator_index`, `next_validator_index += 1`, a fresh `ValidatorStats` row is appended in lockstep, and `stake` base units are **burned into `treasury`** (the canonical permanence sink).
- M1 deliberately leaves `BondOp::Register` **unauthenticated on the wire**. Sufficient for the consensus integration test harness and the deterministic block builder; insufficient for a permissionless mempool. See [§ Future work — mempool authorization](#future-work).

### `BondOp::Unbond`

- `validator_index` must reference an existing validator with non-zero stake (zombie validators are rejected).
- `sig` is verified via [`verify_unbond_sig`](../mfn-consensus/src/bond_wire.rs), domain-separated under `MFBN-1/unbond-op-sig` so a leaked signature cannot be replayed at a different index on any fork.
- Duplicate enqueues are rejected (one `PendingUnbond` per validator at a time).
- Per-epoch exit-churn cap enforced via `try_register_exit_churn`.
- On success: a `PendingUnbond { validator_index, unlock_height = height + unbond_delay_blocks, stake_at_request, request_height }` is inserted into `pending_unbonds`. The validator's stake stays live and they remain in the active set — including for VRF eligibility, finality voting, and slashing — until settlement.

### Atomicity guarantee

Bond ops are simulated against the *pre-bond* view of the chain via [`simulate_bond_ops`](../mfn-consensus/src/block.rs). Any failure (bad signature, churn-cap exhaustion, unknown validator, vrf-key collision, …) rolls back the **entire** bond-op set for the block. The block-level commitment is `bond_root = merkle_root_or_zero({bond_op_leaf_hash(op) for op in block.bond_ops})`; a partial prefix is never committed.

## Slashed stake disposition (shipped)

**Treasury credit** (not burn). Implemented in [`apply_block`](../mfn-consensus/src/block.rs) — both equivocation slashing (full stake forfeit) and liveness slashing (multiplicative forfeit) credit the lost amount to [`ChainState::treasury`](../mfn-consensus/src/block.rs) using saturating `u128` arithmetic. The protocol treats the treasury as the chain's permanence-funding pool; slashes therefore directly subsidize the storage operators a malicious validator was undermining.

## Bond funding (M1 economic model)

Validator registration is **burn-on-bond**: every successful `BondOp::Register` adds its declared `stake` to `ChainState::treasury`. This is the cleanest funding model — it requires no extra wire fields, no separate Schnorr proof of UTXO consumption, and it makes the chain's permanence-funding pool the canonical sink for validator economic commitment.

Combined with slash-to-treasury, this gives M1 a **closed economic-symmetry property**:

- Every base unit a validator commits via `BondOp::Register` is credited to the treasury.
- Every base unit a validator forfeits via equivocation or liveness slashing is credited to the treasury.
- Every base unit paid out to storage operators via [`accrue_proof_reward`](../mfn-storage/src/endowment.rs) drains the treasury (with emission backstop).

There is no path today for stake to flow *out* of the treasury back to a validator. Bonded MFN remains in the treasury after settlement as a permanent contribution to permanence funding. Explicit operator payouts on settlement are deferred (see [§ Future work](#future-work)).

## Unbond flow (shipped)

The unbond pipeline runs through `apply_block` in two well-separated phases:

### Phase A — Bond ops applied

`simulate_bond_ops` walks `block.bond_ops` in order. For `BondOp::Unbond { validator_index, sig }`:

1. Verify the BLS authorization signature against the validator's stored `bls_pk` and the domain-separated payload `dhash(UNBOND_OP_SIG, validator_index.to_be_bytes())`.
2. Reject if `validator_index` is unknown, refers to a zombie (`stake == 0`), or already has a pending unbond.
3. Enforce `max_exit_churn_per_epoch` via `try_register_exit_churn`.
4. Append `PendingUnbond { validator_index, unlock_height = height + unbond_delay_blocks, stake_at_request, request_height }` to `pending_unbonds`.

The validator's `stake` is **unchanged** by enqueueing; they remain in the active set, eligible for the VRF lottery, finality voting, and (importantly) **slashing** for the duration of the delay.

### Phase B — Settlement

After equivocation slashing and liveness updates, but before the final state-root recomputation, `apply_block` walks `pending_unbonds` in ascending `validator_index` order. For each entry whose `unlock_height ≤ height`:

- Set `validators[validator_index].stake = 0` (zombie).
- Remove the entry from `pending_unbonds`.
- Account the settlement against `max_exit_churn_per_epoch` (oversubscribed settlements cleanly spill into subsequent blocks).
- The originally bonded MFN stays in the treasury; no MFN is paid out in M1.

Because settlement runs **after** slashing, a validator who unbonds and then equivocates during the delay is still fully forfeited and credits the treasury — there's no path for an attacker to "rage-quit" to escape consequences for misbehavior committed inside the delay window.

### Mempool authorization for `BondOp::Register` (open question)

Unbond is BLS-authenticated end-to-end. Register is not — today's `BondOp::Register` carries `(stake, vrf_pk, bls_pk, payout)` with no signature. This is sufficient for the deterministic in-process block builder used by the integration tests, but explicitly insecure for a permissionless mempool: an adversary could replay a serialized Register op for any operator's keys.

The two leading designs:

1. **Schnorr-over-bond-bytes by the operator's BLS key.** Simplest; one new field on `BondOp::Register`; reuses the existing BLS primitive. Likely path.
2. **UTXO consumption tied to bond bytes via a public-message hash.** Strongest funding proof; introduces a new tx variant.

Sealing this is a **hard precondition for mainnet** and is the only remaining wire-format question for the rotation layer.

## Test matrix (M1 completion criteria — all green)

- ✓ Bond accepted → validator appears with correct index, fresh stats row, eligible in the next VRF cycle. *(`block::tests::bond_op_round_trip`, plus apply-side cases.)*
- ✓ Burn-on-bond credits treasury *(`burn_on_bond_credits_treasury`, `burn_on_bond_aggregates_multiple_registers`).*
- ✓ Equivocation evidence credits treasury *(`equivocation_slash_credits_treasury_via_apply_block`).*
- ✓ Liveness slash credits treasury *(`liveness_slash_credits_treasury`, `liveness_slash_treasury_compounds_with_validator_stake`).*
- ✓ Entry-churn cap: `N+1`-th bond in same epoch rejected with a deterministic error *(`bonding::tests::entry_churn_cap`; apply-side in `block::tests`).*
- ✓ Exit-churn cap: oversubscribed unbonds spill across blocks honoring the per-epoch cap *(`bonding::tests::exit_churn_cap`; `unbond_lifecycle_exit_churn_cap_spills_to_next_block` in `tests/integration.rs`).*
- ✓ Unbond submitted → validator still slashable during the delay *(`unbond_lifecycle_equivocation_during_delay_still_slashes`).*
- ✓ Settlement at `unlock_height` zeros stake + leaves bonded MFN in treasury *(`unbond_lifecycle_request_delay_settle`).*
- ✓ Unbond signature is domain-separated and index-bound *(`bond_wire::tests::unbond_signing_hash_is_domain_separated`, `unbond_sig_does_not_verify_under_different_index`).*
- ✓ Bond-op wire is byte-identical with the TS reference for `Register` *(`bond_register_wire_matches_cloonan_ts_smoke_reference`).*

## Future work

These are explicit, not bugs:

1. **Mempool-grade authorization for `BondOp::Register`** — Schnorr-over-bond-bytes is the leading design (see [§ Mempool authorization](#mempool-authorization-for-bondopregister-open-question)). Hard precondition for mainnet.
2. **Explicit operator payout on settlement.** Today the bonded MFN stays in the treasury on `unbond → settle`. A future milestone can re-introduce a payout (either via an augmented coinbase output, or a dedicated payout transaction class) without breaking the rotation primitive shipped here.
3. **TS interop vector for `BondOp::Unbond`.** Queued — `BondOp::Register` parity is already enforced; the unbond vector will land alongside the next TS-bond bump.
4. **Storage-operator bonding.** Separate from validator bonding. Out of scope for M1.

## Code map

| Piece | Location |
| --- | --- |
| Defaults + pure checks | [`mfn-consensus/src/bonding.rs`](../mfn-consensus/src/bonding.rs) |
| Wire encode/decode + BLS-signed authorization | [`mfn-consensus/src/bond_wire.rs`](../mfn-consensus/src/bond_wire.rs) |
| State transition (`apply_block` + bond-op phase + settlement phase) | [`mfn-consensus/src/block.rs`](../mfn-consensus/src/block.rs) |
| Domain separation tags (`UNBOND_OP_SIG`) | [`mfn-crypto/src/domain.rs`](../mfn-crypto/src/domain.rs) |
| Integration tests (`unbond_lifecycle` module) | [`mfn-consensus/tests/integration.rs`](../mfn-consensus/tests/integration.rs) |
| TS reference smoke vector | [`docs/interop/TS_BOND_GOLDEN_VECTORS.md`](./interop/TS_BOND_GOLDEN_VECTORS.md) |

## References

- [ROADMAP.md](./ROADMAP.md) — Milestone M1 section
- [CONSENSUS.md](./CONSENSUS.md) — VRF + BLS + finality
- [ECONOMICS.md](./ECONOMICS.md) — burn-on-bond + slash-to-treasury closed loop
- [ARCHITECTURE.md](./ARCHITECTURE.md) — `apply_block` phase ordering
