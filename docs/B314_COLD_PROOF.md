# B-314 — Per-commitment cold-proof cadence helper (not wired)

**Status:** **B-314** / **PM19** cadence + bounty helper + Path A honesty (this unit). **Not** a DEFAULT endowment flip. **Not** B-13c. **Not** wired into `apply_block` / B5 audit evolution.
**Owner:** lane 6 · **Does not change** live Path A coinbase, SPoRA selection, or B5 miss accounting
**Depends on:** `proof_reward_window_slots` (7_200); B5 global any-stale already shipped
**Blocks:** later per-commit audit / bounty wire (after **PM1** bonds so slash has collateral; couples to PM12 / PM39)

## Why this exists

CSV / [`PROBLEMS.md` §5](./PROBLEMS.md#5-adverse-selection-on-which-data-actually-gets-reliably-stored): operators prefer hot, large, recently challenged files. B5 `storage_audit_challenge_active` is **global** — if *any* commitment is older than one proof window, *every* operator owes *a* proof. Proving a popular file resets `consecutive_missed_audits` while an archival `commit_hash` can sit unproven forever.

[`F5.md` PM19](./F5.md) wants a **per-commitment** minimum proof frequency that still fires for old files, plus bounty escalation after N missed windows.

## Target (no privacy/permanence tradeoff)

Keep Path A STF unchanged. Do not inspect file bytes or per-user amounts. Cadence is slots + `commit` age only.

| Helper | Meaning |
| --- | --- |
| `recommended_min_proof_interval_slots(age, params)` | Age 0 → hot window (7_200). Age ≥ 1 year → **216_000** (~30 days). Linear in between. Never 0. |
| `cold_proof_overdue(last_proven, now, age, params)` | `elapsed >= interval` |
| `missed_proof_windows(...)` | `elapsed / interval` |
| `recommended_cold_reward_multiplier_bps(missed)` | 10_000 + 1_000×missed, cap **20_000** (2.0×) |

Never-proven / newly anchored files should pass `age_slots = 0` so the first proof is due on the **hot** window, not the 30-day cap.

### Why not wire this unit?

Per-commit overdue in `apply_block` is a coinbase/slash fork (operators who only prove hot files would start missing). Path A bonds are still **0**, so a slash would still be zero. Wire after **PM1** + a named ceremony. PM39 (epoch lottery over the full `commit` set) can *select* which overdue file to elevate; this helper is the *deadline*.

## Tests (pass in this unit)

- Hot interval = DEFAULT `proof_reward_window_slots` = 7_200; max = 30× that; age span = `slots_per_year`.
- Interval grows with age; year-old files still overdue at the 30-day cap (not exempt).
- Overdue at `elapsed == interval`; not overdue at `interval - 1`; clock-skew `now < last` is not overdue.
- Bounty 0 → 10000, 1 → 11000, 10+ → 20000.
- Path A genesis window stays 7_200.

## Follow-ups (not this unit)

| Id | Item |
| --- | --- |
| Per-commit B5 | Miss counters keyed by `(operator, commit_hash)` using `cold_proof_overdue` |
| **PM39** | Epoch lottery over overdue commits (selection; this helper is the deadline) |
| **PM12** | Repair bounty = `storage_proof_reward · multiplier_bps / 10000` |
| **PM1** | Bonds so a miss slash is non-zero |

## See also

- [`B308_SPORA_LOTTERY.md`](./B308_SPORA_LOTTERY.md) (who wins a window; this unit is *whether a file is due*)
- [`B307_OPERATOR_BOND.md`](./B307_OPERATOR_BOND.md)
- [`B5_OPERATOR_SLASHING.md`](./B5_OPERATOR_SLASHING.md)
