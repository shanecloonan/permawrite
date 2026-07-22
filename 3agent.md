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

Synced from `AGENTS.md` §5 at B-141 land. Tip/ckpt outside-in: tip≈5291, Path A max=5290, lag≈1 (healthy).

| Seat | Done | Doing | Next |
| --- | --- | --- | --- |
| **A** RC/CI | **CI `#29903453186` GREEN** on B-177; watch B-178 head CI; **B-15** PASS | *Idle* — watch B-178 | Do not cancel healthy in_progress |
| **B** Protocol/Privacy | **B-178** ninth asymmetric (this commit); **B-176** GREEN | *Idle* — next **B-179** ninth op1 asymmetric | After 2 hosts: live **B-32** → **B-44** → full **B-24** |
| **C** Testnet/Onboarding | **B-15** wave59/60 tall-tip; JOIN PASS tip=5322 | *Idle*/Doing per AGENTS | No parallel Hetzner JOIN |


### Hard locks (all seats)

1. **B-15 lock:** do **not** run parallel `join-testnet-rehearsal*` on Hetzner; prefer not to restart `faucet-http` / thrash `mfnd-hub` while tip sealing.
2. **CI concurrency:** if GitHub CI is `in_progress` on `main`, prefer `[skip ci]` for docs/ops; never cancel a healthy run.
3. **Foreign WIP:** never stage another seat's uncommitted files (today: seat B `mfn-consensus/tests/apply_block_proptest.rs`).
4. **Privacy/permanence first:** no silent ring/SPoRA/endowment downgrades for speed.

## Critical path (shared)

```text
L4 public testnet harden
  ├─ Seat C: B-15 JOIN SUMMARY (re-pin tip-5290)
  ├─ Seat B: B-132 close fifth-offense prove matrix → (later) B-32 multi-op
  └─ Seat A: green CI+Nightly pins on heads
→ Phase 1 permanence: B-40 + B-13a → B-25 (seat A/B with lane 6)
→ TL-9 invites: B-42 → B-14 (seat C) after B-15 PASS
```

## Collaboration protocol

1. **SYNC** `AGENTS.md` §5–§8 + this file + `git log -15` + `gh run list` (when API allows).
2. **CLAIM** on `AGENTS.md` §5 first (lane Doing + claim base), then mirror the seat row here.
3. **BUILD / PROVE / LAND** per `AGENTS.md` §3; tick TESTNET checklist when a release gate closes.
4. **CLOSE:** clear seat Doing (or claim next), prepend `AGENTS.md` §8, keep this cockpit ≤ one screen of Now.

## Chat announcement (copy)

```text
3agent — Seat A: Done / Doing / Next
3agent — Seat B: Done / Doing / Next
3agent — Seat C: Done / Doing / Next
(AGENTS.md §5 remains the claim surface)
```
