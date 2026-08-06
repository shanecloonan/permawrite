# 3agent — three-seat session cockpit

> **Authority:** [`AGENTS.md`](./AGENTS.md) wins every disagreement (claims, backlog, §6, pipeline).
> **This file:** human-facing Done / Doing / Next for up to **three concurrent agents**.
> **History:** retired 3agent session dumps live in [`docs/AGENTS_LEDGER.md`](./docs/AGENTS_LEDGER.md).
> **Release gates:** still tick [`docs/TESTNET_CHECKLIST.md`](./docs/TESTNET_CHECKLIST.md) and mirror TL in [`docs/TESTNET_LAUNCH.md`](./docs/TESTNET_LAUNCH.md).

Update this cockpit in the **same commit** as the unit it describes. If it drifts from `AGENTS.md` §5, fix the board first, then mirror here.

## Seats (map to lanes)

| Seat | Focus | Owns (lanes) | Does not steal |
| --- | --- | --- | --- |
| **A — RC / CI** | Mesh, CI/Nightly, board integrity, release evidence | 1 + 2 | Protocol tests (B), VPS JOIN / Path A live apply (C) |
| **B — Protocol / Privacy** | `apply_block`, SPoRA/slash matrix, wallet ring defaults | 4 + 5 | Hetzner mfnd/faucet restarts (C), Nightly dispatch (A) |
| **C — Testnet / Onboarding** | JOIN evidence, Path A, faucet/observer/VPS, invite-load | 3 + 7 | Consensus proptest edits (B), board-encoding guards alone (A) |

Lane **6** (permanence sims) arms day-of L4; park under seat A or B when claimed — never silent.

## Live seats (NOW)

Synced at B-238 claim. Watch tip CI on B-237; body ready for land after GREEN.

| Seat | Done | Doing | Next |
| --- | --- | --- | --- |
| **A** RC/CI | **B-20** draft; HTTP GREEN; **B-28** draft | *Idle* | Human B-33 go; **B-40** day-of L4 |
| **B** Protocol/Privacy | **B-237** (7203e1a); watch tip CI | **B-238** sixteenth dual settle (lane4; body ready) | After 2 hosts: live **B-32** |
| **C** Testnet/Onboarding | **B-229** tall-tip header cache; **B-33** telemetry archive | wave115+ density; VPS proxy+frontend apply | Path A lag; JOIN SUMMARY; **B-42** invite-load |

### Hard locks (all seats)

1. **B-15 lock:** do **not** run parallel `join-testnet-rehearsal*` on Hetzner; prefer not to restart `faucet-http` / thrash `mfnd-hub` while tip sealing.
2. **CI concurrency:** if GitHub CI is in_progress on main, prefer [skip ci] for docs/ops; never cancel a healthy run. **Hold B-238 Rust until B-237 tip CI GREEN.**
3. **Foreign WIP:** never stage `onchain-tx-storm*`, `mfn-cli/Cargo.toml`, rc-audit dry-run JSON, or another seat's uncommitted files.
4. **Privacy/permanence first:** no silent ring/SPoRA/endowment downgrades for speed.

## Critical path (shared)

```text
L4 public testnet harden
  ├─ Seat C: B-15 JOIN SUMMARY + Path A lag close
  ├─ Seat B: fifteenth prove matrix (B-232→B-233→B-234…) → B-32 (needs 2nd host)
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
3agent — Seat A: Done B-231 GREEN / Doing watch B-232 #31075611260 / Next pin+Nightly
3agent — Seat B: Done B-237 sixteenth settle-reset slash / Doing B-238 dual settle (body ready) / Next land after GREEN
3agent — Seat C: Done B-229 + B-33 telemetry / Doing wave115+ + VPS proxy / Next Path A lag + SUMMARY
(AGENTS.md §5 remains the claim surface)
```
