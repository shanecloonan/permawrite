# B5 — Operator bonding + slashing for failed audits

Lane **6** (permanence depth) owns B5 research and implementation. Cross-lane with **4** for consensus `apply_block` wiring and **M5** proptests.

## Problem

SPoRA today is carrot-only: prove → get paid; vanish → forego future reward. An operator who earned endowment-funded payouts for months and then deletes data keeps everything. Permanence requires a *stick* aligned with B3 operator-salted replication and B4 proactive repair.

## Phased delivery

| Phase | Scope | Status |
| --- | --- | --- |
| **5a** | Inert `EndowmentParams` slash knobs + checkpoint **v8** + validation | **Shipped** (`e81d33e`) |
| **5b** | Retained slashable bond + per-operator miss stats + checkpoint **v9** | **Shipped** (this commit) |
| **5c** | Bond slash execution → treasury; operator deregistration on zero bond | Planned |
| **5d** | Public devnet enable + M5 proptests (honest / missing / equivocating operators) | Planned |

## Protocol parameters (5a — inert until 5b)

Frozen in `EndowmentParams` (checkpoint v8):

| Field | Type | Default | Meaning |
| --- | --- | --- | --- |
| `operator_audit_missed_cap` | `u8` | `0` | Consecutive missed operator-salted SPoRA challenges before slash. `0` = disabled. |
| `operator_slash_bps` | `u32` | `0` | Fraction of bonded stake sent to treasury on slash (basis points). Must be `1..=10000` when cap > 0. |

Validation (`validate_endowment_params`):

- `operator_audit_missed_cap > 0` requires `operator_salted_challenges > 0` (B3 substrate).
- When cap > 0, `operator_slash_bps` must be in `1..=10000`.
- When cap = 0, slash bps are ignored (may remain 0).

No consensus behavior changes in 5a — params round-trip in checkpoints and genesis JSON only.

## Intended runtime (5b–5c sketch)

1. **Registration (B3 + B5 phase 5b).** Operators register with bonded stake (`StorageOperatorOp::Register`, `min_storage_operator_bond`). `bond_amount` is **retained** in `StorageOperatorEntry` as slashable collateral (no treasury burn on register).
2. **Challenge window.** Each block height defines a deterministic operator-salted SPoRA challenge from public chain state (block id, data root, operator payout key, replication slot index). No payload bytes required on-chain.
3. **Accounting.** For each registered operator, consensus tracks `consecutive_missed_audits`. A valid proof in a block resets the counter; absence increments it.
4. **Slash.** When `consecutive_missed_audits >= operator_audit_missed_cap`, slash `bond_amount * operator_slash_bps / 10000` to `ChainState::treasury`, reduce bond, reset or deregister if bond hits zero.
5. **Repair loop.** Treasury inflows fund B4 repair incentives and future operator recruitment.

## Griefing analysis

### Producer cannot withhold challenge material

Salted challenges (B3) derive from data already committed on-chain (`data_root`, `size_bytes`, chunk geometry) and public block headers. A block producer cannot censor the *definition* of the challenge without rejecting the whole block — the challenge inputs are header-visible.

### No slash from unavailable user payloads

Slash triggers on **missing valid SPoRA proofs**, not on “operator failed to serve a chunk to a peer.” Retrieval (M7.11) stays out-of-consensus; audits use the same proof shape as payout (already verified in `apply_block`).

### False positives (honest but offline)

An operator who retains data but stops proving will accrue missed counts — **intended**. Economic bond aligns liveness with permanence. Operators should run redundant proving daemons (same model as validator liveness slashing).

### Malicious accusation

Only consensus-verified SPoRA proofs count as success. There is no third-party “accuse” opcode — counters move only via `apply_block` proof verification, mirroring validator liveness (missed votes, not gossip accusations).

### Collusion / operator set

Each operator pubkey is tracked independently (B3 per-operator dedup). One honest operator cannot be slashed because a colluding operator proved for a different slot.

### Griefing via registration spam

`min_storage_operator_bond` (B3) plus slash-to-treasury makes registration costly; duplicate payout keys already reject (M5.50 proptests).

### Parameter tuning

- **`operator_audit_missed_cap`:** high enough to absorb brief outages (target: hours–days at 12s slots, not single-block flakes).
- **`operator_slash_bps`:** partial slashes (e.g. 250–1000 bps) per event allow recovery; repeated misses compound via consecutive counter.

## Wire / state additions (5b — shipped)

`ChainState` extension (checkpoint **v9**):

```text
storage_operator_stats: BTreeMap<[u8;32], StorageOperatorStats>
  consecutive_missed_audits: u8
  last_audit_height: u32
```

Audit evolution runs in `apply_block` after storage proofs and operator ops, using the **pre-proof** storage snapshot to decide whether a global stale challenge was active (so same-block proofs count as compliance). No separate block section — folded into the existing proof walk.

## Testing plan (5d)

- Unit: slash math (bond floor, treasury credit, bps edge cases).
- `block_apply`: cap−1 misses no slash; cap-th miss slashes; proof resets counter.
- M5 proptest: mixed honest/missing operators, treasury identity over multi-block chains.
- Nightly: no behavior change until public devnet enables non-zero cap.

## See also

- [`PERMANENCE_HARDENING.md`](./PERMANENCE_HARDENING.md) §B5
- [`STORAGE.md`](./STORAGE.md) — SPoRA proof verification
- B3 operator registry: `mfn-consensus/src/storage_operator_wire.rs`
- B4 repair: `mfn-node/src/p2p_repair_sweep.rs`
