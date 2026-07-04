# 3agent Coordination

This file coordinates the three active Permawrite agent lanes. Keep using `docs/TESTNET_CHECKLIST.md`, `docs/ROADMAP.md`, `docs/TESTNET.md`, and the operator runbooks as the detailed source of truth; this file is the cross-agent handoff board for current work, completed units, and next work.

Permawrite is pre-audit experimental software. Do not mark public-testnet readiness complete until the exact release commit has green GitHub CI, local CI mirror evidence, ignored/nightly coverage where required, release evidence, archive validation, and named human sign-off.

## Update Protocol

- Update this file at the start or end of every coherent agent unit.
- Record the exact lane owner, current unit, status, blockers, and next handoff.
- Do not claim another agent's uncommitted work; mention it as "observed local work" until it lands on `main`.
- Continue updating `docs/TESTNET_CHECKLIST.md` for durable release-readiness tasks.
- Commit and push completed units to `main` after the required local CI mirror passes.
- **Do not push while CI is in progress** — concurrency `cancel-in-progress` aborts the matrix (~70 min on Linux/macOS).

## Current Board

| Agent | Lane | Current Unit | Status | Next Handoff |
| --- | --- | --- | --- | --- |
| Agent 1 | Core protocol, consensus, economics | **M2.5.3** pushed (`95739e4`). | **Done** — CI #505 green (all OS). | RC Validation → Nightly #50. |
| Agent 2 | Security, RPC, ops, release evidence | **M2.5.3** evidence. | **Ready** — CI #505 green. | `release-evidence-95739e4` + RC audit dry-run. |
| Agent 3 | Wallet, storage, faucet, onboarding | **M2.5.3** mempool harness. | **Done** — ring-16 node tests on `95739e4`. | Nightly #50 after green CI. |

## Recently Completed

- **M2.5.3** (`95739e4`) — mempool_integration + mfnd_smoke + mfn-runtime/mempool ring-16; CI #505 **GREEN**.
- **M2.5.2** (`434b444`) — integration ring-2 decoys + checkpoint offsets. CI #503 **FAILED** (node tests ring-2/4/8).
- **M2.5.0** (`0e10470`) — ring-16 privacy + operator-direct SPoRA coinbase outputs.
- Nightly ignored **PASS** (#48 on `052e507`).

## Agent 1 Detailed Plan

### Done

- [x] M2.5.0–M2.5.2 core + integration harness.
- [x] **M2.5.3** pushed (`95739e4`) — node/mempool ring-16 alignment.

### In Progress

- [ ] RC Validation → Nightly #50 (ignored + participant + observer rehearsal).

### Next

- [ ] RC Validation → Nightly #50 (ignored + participant + observer rehearsal).
- [ ] `release-evidence-<sha>` + RC audit dry-run.
- [ ] Linux 30s-slot soak (manual **Linux Soak Audit**, ~35 min).
- [ ] Operator sign-off.

## Agent 3 Detailed Plan

### Done

- [x] `WALLET_MIN_RING_SIZE = 16`; CLI smokes; end_to_end/wasm tests.
- [x] M2.5.3 mempool_integration (6/6), mfnd_smoke, runtime mempool unit tests.

### Next

- [ ] Full green Nightly #50 — blocked on green CI #505.

## Agent 2 Detailed Plan

- [ ] `release-evidence-95739e4` after CI #505 green.
- [ ] Operator sign-off after Nightly + Linux soak.

## Shared Release-Candidate Gates

- Green GitHub CI — **PASS** CI #505 on `95739e4` (1h 10m, all OS).
- Nightly ignored — **PASS** (#48); full Nightly rehearsal — pending green CI.
- Linux 30s-slot soak — Windows done; Linux manual dispatch pending.
- Human sign-off — pending.

## Cross-Agent Blockers

- CI #503 failed on ring-2/4/8 — fixed in M2.5.3 (`95739e4`); CI #505 green.
