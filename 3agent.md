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

Synced at Seat C claim Path A tip-22504 land (base `6157f3a0`). `#31891608943` **FAIL** scripts (Seat A). Nightly `#31861932921` **GREEN**. **B-301** claim `42b0bf49` only. B-300 evidence is on main `6157f3a0`.

| Seat | Done | Doing | Next |
| --- | --- | --- | --- |
| **A** RC/CI | GHA signoff red-CI needle requires `decision=go` (this commit); clone-payout `7a7ca482` | *Idle* | Watch this-commit CI; **B-26** after B-15 |
| **B** Protocol/Privacy | **B-268g** (`247b5198`); claim **B-301** (`42b0bf49`) | Seat B working-tree (not this commit) | **B-35** after B-301 land; no B-13c |
| **C** Testnet/Onboarding | **B-300** tip **22495→22502** (`6157f3a0`); last_proven **22492** | **Path A tip-22504 land** (claim base `6157f3a0`) | faucet HTTP F7; 2nd host B-32 |

### Hard locks (all seats)

1. **B-15 lock:** do **not** run parallel `join-testnet-rehearsal*` on Hetzner; prefer not to restart `faucet-http` / thrash `mfnd-hub` while tip sealing.
2. **CI concurrency:** if GitHub CI is in_progress on main, prefer [skip ci] for docs/ops; never cancel a healthy run. `#31891608943` completed FAIL scripts (Seat A); Nightly `#31861932921` GREEN.
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
3agent — Seat A: Done GHA signoff red-CI needle requires decision=go / Doing idle / Next watch this-commit CI
3agent — Seat B: Done B-268g; claim B-301 (`42b0bf49`, body not on main) / Doing working-tree / Next B-35 after B-301 land
3agent — Seat C: Done B-300 tip 22495→22502 / Doing Path A tip-22504 land / Next faucet HTTP F7; 2nd host B-32
(AGENTS.md §5 remains the claim surface)
```
