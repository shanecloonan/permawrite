# 3agent — three-seat session cockpit

> **Authority:** [`AGENTS.md`](./AGENTS.md) wins every disagreement (claims, backlog, §6, pipeline).
> **This file:** human-facing Done / Doing / Next for up to **three concurrent agents**.
> **History:** retired 3agent session dumps live in [`docs/AGENTS_LEDGER.md`](./docs/AGENTS_LEDGER.md).
> **Release gates:** still tick [`docs/TESTNET_CHECKLIST.md`](./docs/TESTNET_CHECKLIST.md) and mirror TL in [`docs/TESTNET_LAUNCH.md`](./docs/TESTNET_LAUNCH.md).

Update this cockpit in the **same commit** as the unit it describes. If it drifts from `AGENTS.md` §5, fix the board first, then mirror here.

## Seats (map to lanes)

| Seat | Focus | Owns (lanes) | Does not steal |
| --- | --- | --- | --- |
| **A** RC/CI | **B-28** GREEN; **B-40** runbook | B-13a-512 claimed — hold for B-241 tip CI | Land 512 sims; human B-33; arm B-40 |
| **B** Protocol / Privacy | `apply_block`, SPoRA/slash matrix, wallet ring defaults | 4 + 5 | Hetzner mfnd/faucet restarts (C), Nightly dispatch (A) |
| **C** Testnet/Onboarding | **B-245** arm-ready NOT READY; **B-244**; **B-243** | *Idle* | Human **2nd host** for B-32; after B-15: **B-42** |

Lane **6** (permanence sims) arms day-of L4; park under seat A or B when claimed — never silent.

## Live seats (NOW)

Synced at lane7 **B-244** CLOSE (health OK lag=1). Lane4 keeps B-242. Watch tip CI `#31102959528`.

| Seat | Done | Doing | Next |
| --- | --- | --- | --- |
| **A** RC/CI | **B-28** GREEN; **B-40** runbook | B-13a-512 claimed — hold for B-241 tip CI | Land 512 sims; human B-33; arm B-40 |
| **B** Protocol/Privacy | **B-241** (5c5e7253); watch tip CI | **B-242** sixteenth re-slash (lane4; body ready) | After 2 hosts: live **B-32** |
| **C** Testnet/Onboarding | **B-245** arm-ready NOT READY; **B-244**; **B-243** | *Idle* | Human **2nd host** for B-32; after B-15: **B-42** |

### Hard locks (all seats)

1. **B-15 lock:** do **not** run parallel `join-testnet-rehearsal*` on Hetzner; prefer not to restart `faucet-http` / thrash `mfnd-hub` while tip sealing.
2. **CI concurrency:** if GitHub CI is in_progress on main, prefer [skip ci] for docs/ops; never cancel a healthy run. **Hold B-242 Rust until B-241 tip CI GREEN.**
3. **Foreign WIP:** never stage `onchain-tx-storm*`, lane4 `apply_block_proptest.rs`, `mfn-cli/Cargo.toml`, rc-audit dry-run JSON, or another seat's uncommitted files.
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
3agent — Seat B: Done B-241 / Doing B-242 re-slash (body ready) / Next B-32 (2 hosts)
3agent — Seat C: Done B-244 health + B-243 Path A / Doing idle / Next B-42 after B-15 clear
(AGENTS.md §5 remains the claim surface)
```
