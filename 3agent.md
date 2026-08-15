# 3agent — three-seat session cockpit

> **Authority:** [`AGENTS.md`](./AGENTS.md) wins every disagreement (claims, backlog, §6, pipeline).
> **This file:** human-facing Done / Doing / Next for up to **three concurrent agents**.
> **History:** retired 3agent session dumps live in [`docs/AGENTS_LEDGER.md`](./docs/AGENTS_LEDGER.md).
> **Release gates:** still tick [`docs/TESTNET_CHECKLIST.md`](./docs/TESTNET_CHECKLIST.md) and mirror TL in [`docs/TESTNET_LAUNCH.md`](./docs/TESTNET_LAUNCH.md).

Update this cockpit in the **same commit** as the unit it describes. If it drifts from `AGENTS.md` §5, fix the board first, then mirror here.

## Seats (map to lanes)

| Seat | Focus | Owns (lanes) | Does not steal |
| --- | --- | --- | --- |
| **A** RC/CI | Tip CI `#31857970110` GREEN on B-293 | *Idle* | Pin / Nightly; do not cancel healthy tip CI |
| **B** Protocol/Privacy | **B-294** twentieth asymmetric re-slash | Lane 4 protocol tests | **B-295** op1 re-slash; do not steal B-296 / B-268b |
| **C** Testnet/Onboarding | **B-291** tall-tip mesh recover (this commit) | *Idle* | **B-296** dual-payment storm; **B-42**; 2nd host B-32 |

Lane **6** (permanence sims) arms day-of L4; park under seat A or B when claimed — never silent.

## Live seats (NOW)

Synced at B-291 CLOSE. Tip restored ~22350; seat C Next **B-296** storm.

| Seat | Done | Doing | Next |
| --- | --- | --- | --- |
| **A** RC/CI | Tip CI `#31857970110` GREEN on B-293 | *Idle* | Pin / Nightly; do not cancel healthy tip CI |
| **B** Protocol/Privacy | **B-294** | *Idle* | **B-295** twentieth op1 re-slash; after 2 hosts: live **B-32** |
| **C** Testnet/Onboarding | **B-291** mesh recover (this commit) | *Idle* | **B-296** dual-payment storm; **B-42**; 2nd host B-32 |

### Hard locks (all seats)

1. **B-15 lock:** do **not** run parallel `join-testnet-rehearsal*` on Hetzner; prefer not to restart `faucet-http` / thrash `mfnd-hub` while tip sealing.
2. **CI concurrency:** if GitHub CI is in_progress on main, prefer [skip ci] for docs/ops; never cancel a healthy run. Lane6 **B-13a-512** landed; lane4 may push **B-246** after this tip CI settles.
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
3agent — Seat A: Done watch / Doing idle / Next pin+Nightly
3agent — Seat B: Done B-259 seventeenth settle-reset / Doing B-261 dual settle (body ready) / Next land after GREEN
3agent — Seat C: Done B-244 health + B-243 Path A / Doing idle / Next B-42 after B-15 clear
(AGENTS.md §5 remains the claim surface)
```
