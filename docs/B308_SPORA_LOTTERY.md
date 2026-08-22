# B-308 — Windowed SPoRA lottery ranking helper

**Status:** **B-308** ranking helper + Path A honesty (this unit). **Not** wired into `apply_block`. **Not** B-44. **Not** a Path A coinbase fork.
**Owner:** lane 6 · **Does not change** live Path A proof inclusion
**Depends on:** none for the helper; **B-44** wiring depends on **B-32**
**Blocks:** honest **B-44** sequencing (one ranking, not a second hash)

## Why this exists

CSV / [`PROBLEMS.md` §6](./PROBLEMS.md#6-spora-proof-winning-is-a-pure-first-to-publish-latency-race): SPoRA payout is a first-to-publish race. `apply_block` iterates `block.storage_proofs` in **body order**. Operators with a faster path to the producer get paid; equal-capability operators farther away do not. That is a permanence risk (storage concentrates next to producers).

[`F5.md` PM3](./F5.md) / [`ROADMAP.md` B-44](./ROADMAP.md#b-44--pm3-work-package-lane-46--after-b-32) is the consensus change: accept every valid proof in a window, then pick winners by lottery. Full wiring touches the proof pool and Phase 5 of `apply_block`, and it is a coinbase fork. It also needs ≥2 real operators (**B-32**) or the lottery is a no-op on a one-host Path A.

This unit lands the **pure ranking** so B-44 does not invent a second hash.

## Target (no privacy/permanence tradeoff)

Keep Path A first-to-publish. Do not skip SPoRA verification. Do not merge storage into validator duties.

| Surface | Today (Path A) | After B-44 |
| --- | --- | --- |
| Who is paid | First valid proofs in body order (up to `replication` distinct operators per commit under B3) | In-window valid proofs ranked by [`rank_spora_lottery`](../mfn-storage/src/lottery.rs); out-of-window rejected |
| Seed | n/a | [`spora_lottery_window_seed(prior_block_id, window_start_slot)`](../mfn-storage/src/lottery.rs) — **prior** sealed block, not producer VRF (leader bias) |
| Domain | unused | `MFBN-1/spora-lottery` ([`SPORA_LOTTERY`](../mfn-crypto/src/domain.rs)) |

`rank_spora_lottery`:

- Dedup operator ids, ignore input order.
- Score = `dhash(SPORA_LOTTERY, "rank" ‖ seed ‖ operator_id)`.
- Sort `(score, id)`; take `max_winners`.
- Tests prove two operators both win across different seeds (equal-latency fairness).

### Why not wire apply_block in this unit?

Paying lottery winners instead of body-first proofs changes which coinbase outputs are valid. Path A has one live host. Standing board: slash matrix frozen; no silent coinbase fork; **B-44 after B-32**.

## Tests (pass in this unit)

- Window seed is deterministic and changes with slot / prior `block_id`.
- Ranking is permutation-invariant.
- Same seed → same singleton winner.
- Two operators both appear as winner across ≤10_000 seeds.
- Empty set / `max_winners = 0` → empty.
- Cap + duplicate ids.

`apply_block` is **not** called. Path A inclusion stays body-order until B-44.

## Follow-ups (not this unit)

| Id | Item |
| --- | --- |
| **B-44** | Wire proof pool + `apply_block` to this helper after **B-32**; reject out-of-window proofs; emission identity still holds |
| **B-32** | Distinct-host multi-op evidence (lane 4+7) |

## See also

- [`PROBLEMS.md` §6](./PROBLEMS.md#6-spora-proof-winning-is-a-pure-first-to-publish-latency-race)
- [`F5.md` PM3](./F5.md)
- [`DECENTRALIZATION.md`](./DECENTRALIZATION.md)
- [`B307_OPERATOR_BOND.md`](./B307_OPERATOR_BOND.md)
