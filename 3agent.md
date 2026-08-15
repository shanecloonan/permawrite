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

Synced at Seat B **B-268e** CLOSE. Tip CI `#31872756568` rust/OS **GREEN** / scripts FAIL (Seat A). Nightly `#31861932921` **GREEN**. Seat C tip-22495 stall recover stands.

| Seat | Done | Doing | Next |
| --- | --- | --- | --- |
| **A** RC/CI | `go` refuses Path A toy keys (`c8037401`); bonded ops (`71a7ad7a`) | *Idle* | Fix signoff-validate go+red-CI (`#31867337251` FAIL); do not steal B-42 |
| **B** Protocol/Privacy | **B-268e** (this commit); **B-268d** (`6015797c`) | *Idle* | **B-35** pad; no B-13c |
| **C** Testnet/Onboarding | Path A **22495** (`a6cd75f6`); B-42 last_proven **22492** | **tip-22495 stall recover** (claim base `a6cd75f6`) | faucet HTTP F7; 2nd host B-32 |

### Hard locks (all seats)

1. **B-15 lock:** do **not** run parallel `join-testnet-rehearsal*` on Hetzner; prefer not to restart `faucet-http` / thrash `mfnd-hub` while tip sealing.
2. **CI concurrency:** if GitHub CI is in_progress on main, prefer [skip ci] for docs/ops; never cancel a healthy run. Landing B-268e full CI; `#31872756568` rust GREEN / scripts FAIL (Seat A); Nightly `#31861932921` GREEN.
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
3agent — Seat A: Done go refuses Path A toy keys (`c8037401`) / Doing idle / Next fix signoff-validate (#31867337251 FAIL)
3agent — Seat B: Done B-268e overlay bps>10000 fail-closed / Doing idle / Next B-35 pad
3agent — Seat C: Done Path A tip-22495 / Doing tip-22495 stall recover / Next faucet HTTP F7; 2nd host B-32
(AGENTS.md §5 remains the claim surface)
```
