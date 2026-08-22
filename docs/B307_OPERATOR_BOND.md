# B-307 — Size `min_storage_operator_bond` so B5 slashing has collateral

**Status:** **B-307** calibration helper + Path A pin (this unit). **Not** a `DEFAULT_ENDOWMENT_PARAMS` flip. **Not** B-13c. **Not** Path B / **PM1** enable.
**Owner:** lane 6 · **Does not change** live Path A genesis
**Depends on:** **B5** slash-to-treasury (already on public devnet)
**Blocks:** honest Path B genesis that turns on operator skin-in-the-game instead of a 2.5% slash of zero

## Why this exists

Public Path A already runs the B5 stick:

| Knob | Path A today |
| --- | --- |
| `operator_salted_challenges` | `1` |
| `require_registered_operators` | `1` |
| `operator_audit_missed_cap` | `48` (~24 min at 30s slots) |
| `operator_slash_bps` | `250` (2.5% of bond per cap breach) |
| `min_storage_operator_bond` | **`0`** |
| genesis `bond_amount` | **`0`** for both storage operators |

Slash amount is `bond · slash_bps / 10000`. With a zero bond that is **always 0**. An operator can accept uploads, miss audits, and keep every prior payout. That is [`PROBLEMS.md` §1](./PROBLEMS.md#1-storage-operators-have-limited-skin-in-the-game-bonding-is-opt-in) and the CSV “weak / optional operator skin-in-the-game” row.

## Target (no privacy/permanence tradeoff)

Keep registration open on Path A. Size the **Path B** floor so one B5 slash covers one year of 1 GiB × `min_replication` storage cost (`C₀`). Ring / SPoRA / endowment sizing stay unchanged.

| Config | `min_storage_operator_bond` | Role |
| --- | --- | --- |
| Path A today | `0` | Optional / bondless (unchanged this unit) |
| Path B / **PM1** | [`recommended_min_storage_operator_bond`](../mfn-storage/src/endowment.rs) | Floor ≈ `C₀(1 GiB) / 0.025` so a 2.5% slash equals that C₀ |

`recommended_min_storage_operator_bond` is:

```text
ceil(C₀(1 GiB, min_replication) · 10_000 / effective_slash_bps)
```

`effective_slash_bps` is `operator_slash_bps` when audits are on (`cap > 0` and `slash_bps > 0`); otherwise [`RECOMMENDED_OPERATOR_SLASH_BPS`](../mfn-storage/src/endowment.rs) = **250** (the Path A / B5 stick).

At default / Path A 250 bps this is **25_769_800** base units (~0.258 MFN). One slash then equals `C₀(1 GiB × 3)`. Full-forfeiture (`slash_bps = 10000`) sizes the bond to `C₀` itself.

### Why not flip DEFAULT or Path A genesis?

Raising `min_storage_operator_bond` rejects Path A's `bond_amount: 0` operators at genesis load. That is a new chain, not a parameter tweak. Standing board rule: no DEFAULT endowment flip on Path A.

Path B sets `endowment.min_storage_operator_bond` in genesis JSON (loader already merges it) and funds each `storage_operators[].bond_amount` to at least that floor. Live Path A enable is a named ceremony after **B-25**, same class as **B-306b**.

## Tests (pass in this unit)

- Helper equals `ceil(C₀(1 GiB, 3) · 10000 / 250)` at DEFAULT (slash knobs 0 → 250 design target).
- One 2.5% slash of that bond equals `C₀`.
- With `cap = 48` and `slash_bps = 10000`, helper equals `C₀`.
- `DEFAULT_ENDOWMENT_PARAMS.min_storage_operator_bond == 0`.
- Public devnet genesis keeps min bond `0` and stays **below** the helper.

## Follow-ups (not this unit)

| Id | Item |
| --- | --- |
| **PM1** | Enable `min_storage_operator_bond = recommended_min_storage_operator_bond` on Path B / after B-25; genesis `bond_amount` must meet the floor |
| **B-306b** | Independent: drip + proof-prize backstop in the same Path B ceremony |

## See also

- [`B5_OPERATOR_SLASHING.md`](./B5_OPERATOR_SLASHING.md)
- [`B306C_PROOF_REWARD_BACKSTOP.md`](./B306C_PROOF_REWARD_BACKSTOP.md)
- [`PATH_B_GENESIS_FREEZE.md`](./PATH_B_GENESIS_FREEZE.md)
- [`PROBLEMS.md` §1](./PROBLEMS.md#1-storage-operators-have-limited-skin-in-the-game-bonding-is-opt-in)
