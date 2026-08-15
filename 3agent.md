# 3agent — three-seat session cockpit

> **Authority:** [`AGENTS.md`](./AGENTS.md) wins every disagreement (claims, backlog, §6, pipeline).
> **This file:** human-facing Done / Doing / Next for up to **three concurrent agents**.
> **History:** retired 3agent session dumps live in [`docs/AGENTS_LEDGER.md`](./docs/AGENTS_LEDGER.md).
> **Release gates:** still tick [`docs/TESTNET_CHECKLIST.md`](./docs/TESTNET_CHECKLIST.md) and mirror TL in [`docs/TESTNET_LAUNCH.md`](./docs/TESTNET_LAUNCH.md).

Update this cockpit in the **same commit** as the unit it describes. If it drifts from `AGENTS.md` §5, fix the board first, then mirror here.

## Seats (map to lanes)

| Seat | Focus | Owns (lanes) | Does not steal |
| --- | --- | --- | --- |
| **A** RC/CI | CI, Nightly, board integrity | Lanes 1–2 | **B-296**, protocol tests |
| **B** Protocol/Privacy | Consensus / privacy / economics | Lanes 4–5–6 | **B-296**, Nightly cancel, VPS/faucet |
| **C** Testnet/Onboarding | VPS / JOIN / faucet / launch | Lanes 3+7 | Protocol tests, CI cancel |

Lane **6** (permanence sims) arms day-of L4; park under seat A or B when claimed — never silent.

## Live seats (NOW)

Synced at Seat B **B-305** unused MFEO refuse. `#31907077988` rust GREEN / scripts FAIL (Seat A). Nightly `#31861932921` **GREEN**. Lane7 Path A **22565** / last_proven **22560**.

| Seat | Done | Doing | Next |
| --- | --- | --- | --- |
| **A** RC/CI | `go` requires `gates.ci.commit` == manifest commit (`b0bd1caa`); VRF `edd1bc65` | *Idle* | Fix scripts FAIL `#31907077988`; **B-26** after B-15 |
| **B** Protocol/Privacy | **B-305** unused MFEO refuse (this commit) | *Idle* | **B-35** still Phase 3 / B-25; no B-13c |
| **C** Testnet/Onboarding | Path A **22565** (`160a9b07`); **B-42** last_proven **22560** | *Idle* | 2nd host B-32 |

### Hard locks (all seats)

1. **B-15 lock:** do **not** run parallel `join-testnet-rehearsal*` on Hetzner; prefer not to restart `faucet-http` / thrash `mfnd-hub` while tip sealing.
2. **CI concurrency:** if GitHub CI is in_progress on main, prefer [skip ci] for docs/ops; never cancel a healthy run. Tip CI `#31907077988` rust GREEN / scripts FAIL (Seat A); Nightly `#31861932921` GREEN.
3. **Foreign WIP:** never stage lane4 `apply_block_proptest.rs` / B-275 body, or another seat's uncommitted files. Seat C owns `onchain-tx-storm*` for **B-277**.
4. **Privacy/permanence first:** no silent ring/SPoRA/endowment downgrades for speed.
5. **Lane7 VPS apply:** restart `observer-rpc-proxy` + `testnet-frontend` only — never mfnd / faucet-http.

## Critical path (shared)

```text
L4 public testnet harden
  ├─ Seat C: B-15 JOIN SUMMARY + Path A lag close + B-229 VPS apply
  ├─ Seat B: sixteenth prove matrix (B-241→B-242…) → B-32 (needs 2nd host)
  ├─ Seat A/B+lane6: B-13a GREEN pin → B-40 / B-25 permanence gate
  └─ Seat A: green CI+Nightly pins on heads
→ TL-9 invites: B-42 → B-14 (seat C) after B-15 PASS
```

## Collaboration protocol

1. **SYNC** `AGENTS.md` §5–§8 + this file + `git log -15` + `gh run list` (when API allows).
2. **CLAIM** on `AGENTS.md` §5 first (lane Doing + claim base), then mirror the seat row here.
3. **BUILD / PROVE / LAND** per `AGENTS.md` §3; tick TESTNET checklist when a release gate closes.
4. **CLOSE:** clear seat Doing (or claim next), prepend `AGENTS.md` §8, keep this cockpit ≤ one screen of Now.

## Chat announcement (copy)

```text
3agent — Seat A: Done go requires gates.ci.commit == manifest commit / Doing idle / Next fix scripts FAIL #31904265430
3agent — Seat B: Done B-305 unused MFEO refuse / Doing idle / Next B-35 still Phase 3
3agent — Seat C: Done Path A tip-22565 lag OK=7 / Doing idle / Next 2nd host B-32
(AGENTS.md §5 remains the claim surface)
```
