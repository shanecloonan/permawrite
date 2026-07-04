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
| Agent 1 | Core protocol, consensus, economics | **M2.5.3** node test ring-16 fix. | **In progress** — CI #503 failed (mempool ring-2/4/8); local fix ready. | Push after green local ci-check → CI #504. |
| Agent 2 | Security, RPC, ops, release evidence | **M2.5.3** evidence. | **Waiting** — blocked on green CI. | `release-evidence-<sha>` after CI green. |
| Agent 3 | Wallet, storage, faucet, onboarding | **M2.5.3** mempool harness. | **In progress** — ring-16 mempool + mfnd smoke (uncommitted). | Nightly #50 after CI green. |

## Recently Completed

- **M2.5.2** (`434b444`) — integration ring-2 decoys + multi-output coinbase; checkpoint tamper offset helpers. CI #503 **FAILED** (node tests still ring-2/4/8).
- **M2.5.1** (`0313f4d`) — block_apply + emission_simulation ring-16 harness.
- **M2.5.0** (`0e10470`) — ring-16 privacy + operator-direct SPoRA coinbase outputs.
- Nightly ignored **PASS** (#48 on `052e507`).

## Agent 1 Detailed Plan

### Done

- [x] M2.5.0 core: `block_coinbase_specs`, operator payout keys, `RingPolicy::PRODUCTION` (uniform 16).
- [x] M2.5.1 clippy + proptest + block_apply + emission_simulation ring-16.
- [x] M2.5.2 integration ring-2 + checkpoint offset helpers (`434b444`).

### In Progress

- [ ] **M2.5.3** — `mempool_integration.rs`, `mfnd_smoke.rs`, `mfn-runtime/mempool.rs` ring-16 (49/49 node+mempool tests pass locally).
- [ ] Local `scripts/ci-check.ps1` green → push → CI #504.

### Next

- [ ] Green CI → RC Validation → Nightly #50.
- [ ] `release-evidence-<sha>` + RC audit dry-run.
- [ ] Linux 30s-slot soak (manual **Linux Soak Audit**, ~35 min).
- [ ] Operator sign-off.

## Agent 3 Detailed Plan

### Done

- [x] `WALLET_MIN_RING_SIZE = 16` in `mfn-wallet`.
- [x] All `mfn-cli` integration smokes `--ring-size 16`.
- [x] `end_to_end`, wasm transfer tests ring-16.

### In Progress

- [ ] `mempool_integration.rs`, `mfnd_smoke.rs`, `mfn-runtime/mempool.rs` ring-16 alignment (49/49 pass locally).

### Next

- [ ] Full green Nightly #50 — blocked on green CI.

## Agent 2 Detailed Plan

- [ ] Release evidence after M2.5.3 CI green.
- [ ] Operator sign-off after Nightly + Linux soak.

## Shared Release-Candidate Gates

- Green GitHub CI — **FAILED** CI #503 on `434b444` (mempool ring-2/4, mfnd_smoke ring-8); fix in M2.5.3.
- Nightly ignored — **PASS** (#48); full Nightly rehearsal — pending green CI + #50.
- Linux 30s-slot soak — Windows done; Linux manual dispatch pending.
- Human sign-off — pending.

## Cross-Agent Blockers

- CI #503 failed all three OS test jobs on node integration tests (ring size 2/4/8 vs min 16). M2.5.3 fix uncommitted; push after local ci-check.
- CI #503 complete — safe to push M2.5.3 without cancelling in-flight runs.
