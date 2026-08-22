# B-312 — Treasury runway metric helper (not RPC)

**Status:** **B-312** PM22 metric + Path A honesty (this unit). **Not** a `DEFAULT_EMISSION_PARAMS` flip. **Not** B-13c. **Not** wired into RPC / `apply_block`. **Not** an on-chain oracle.
**Owner:** lane 6 · **Does not change** live Path A coinbase or fee split
**Depends on:** **B-28** draft treasury floor (`1_000_000`); **B-309** fee-shift helper
**Blocks:** honest PM22 RPC/UI (call this helper; do not invent a second formula)

## Why this exists

CSV / [`PROBLEMS.md` §2](./PROBLEMS.md#2-r--0-default-makes-permanence-heavily-dependent-on-continuous-high-privacy-transaction-volume): fee drought is **silent** until proofs fail. Drip, prize-size, fee-shift, and the mint cap name *what to do*. They do not name *how long the buffer lasts*.

[`F5.md` PM22](./F5.md) wants a chain-derived **runway** = treasury / trailing payout rate, with alerts below a threshold. Amounts are aggregate — not a privacy leak.

[`treasury_runway_slots`](../mfn-consensus/src/emission.rs) is that division. [`RunwayObservation::alert`](../mfn-consensus/src/emission.rs) is the alert class B-28 scripts and a later RPC can share.

## Target (no privacy/permanence tradeoff)

Keep Path A STF and fee split unchanged. Do not expose per-user amounts.

| Signal | Meaning |
| --- | --- |
| `runway_slots = None` | Payout is 0 — nothing is draining (`NoDrain` if above floor) |
| `BelowFloor` | `treasury ≤ 1_000_000` (B-28) — floor wins over short/healthy |
| `Short` | Runway `< 7_200` slots (~1 proof-reward window / 1 day) |
| `Healthy` | Above floor and runway ≥ 7_200 |

[`RECOMMENDED_RUNWAY_WARN_SLOTS`](../mfn-consensus/src/emission.rs) = **7_200**, matching default `proof_reward_window_slots`.

Honesty pin: Path A pre-enable treasury ~2.9e6 with prize `0.1 MFN`/slot is **Short** (0 slots). The 0.1 MFN prize is larger than that buffer — another reason **B-306c** shrinks it before relying on treasury drain time.

### Why not wire RPC this unit?

RPC/UI is lane 2/7 surface. The bug to avoid is two formulas (script vs consensus). This unit is the single function. Scripts keep asserting the B-28 **floor**; they can call `alert()` later without changing Path A.

## Tests (pass in this unit)

- Warn window = 7_200 = default proof window.
- Zero payout above floor → `NoDrain`.
- Empty treasury → `BelowFloor` (even if payout is 0).
- Runway == 7_200 → `Healthy`; 7_199 → `Short`.
- Path A prize vs 2_909_711 treasury → 0 slots / `Short`; fee split stays 9000.

## Follow-ups (not this unit)

| Id | Item |
| --- | --- |
| **PM22 RPC** | `get_treasury_runway` returns `runway_slots` + `alert` from this helper |
| **B-28 scripts** | Optionally fail-closed on `Short` / `BelowFloor` (live Path A prize makes `Short` the honest default until B-306b) |
| **B-20** | Fee-shift still a separate fork; this metric is the *when*, not the lever |

## See also

- [`B309_FEE_SHIFT.md`](./B309_FEE_SHIFT.md)
- [`B311_BACKSTOP_CAP.md`](./B311_BACKSTOP_CAP.md)
- [`FEES.md` §5.5](./FEES.md#55-producertreasury-runway-fee-shift-b-20--helper-landed-not-armed)
