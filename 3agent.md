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
| Agent 1 | Core protocol, consensus, economics | **M2.5.2** integration.rs fix. | **In progress** — M2.5.1 CI #502 failed on integration tests; fix ready locally. | Push → CI #503 → Nightly #50. |
| Agent 2 | Security, RPC, ops, release evidence | **M2.5.2** evidence. | **Waiting** — after green CI on integration fix. | Release evidence after CI green. |
| Agent 3 | Wallet, storage, faucet, onboarding | **M2.5.1** wallet ring-16. | **Done** — on `main` via `a4e70c9`. | Nightly #50 after CI green. |

## Recently Completed

- **M2.5.0** (`0e10470`) — ring-16 privacy + operator-direct SPoRA coinbase outputs (consensus/storage/node).
- **M2.4.89** (`f57dc9f`) — CI Linux hardening (threads=2, retry, GHA timeouts); CI #493 cancelled by M2.5.0 push.
- **M2.4.88** (`297ec27`) — observer boot hardening for Linux Nightly.
- Nightly ignored **PASS** (#48 on `052e507`).

## Agent 1 Detailed Plan

### Done

- [x] M2.5.0 core: `block_coinbase_specs`, operator payout keys on storage proofs, `RingPolicy::PRODUCTION` (uniform 16).
- [x] M2.5.1 clippy fixes (`apply.rs`, `spora.rs` doc, treasury test allows).
- [x] M2.5.1 `apply_block_proptest` harness — ring-16 genesis decoys, multi-output coinbase via `st.endowment_params` (PPB fix).
- [x] M2.5.1 `block_apply.rs` ring-16 rejection tests.
- [x] **M2.5.1** pushed (`0313f4d`, `4aafeea`) — block_apply + emission_simulation ring-16.
- [ ] **M2.5.2** — integration.rs multi-output coinbase + ring-2 decoys (CI #502 failed ubuntu/macOS test).

### In Progress

- [ ] Push M2.5.2 → green CI #503 (`ci-check-m252-integration.log`).
- [ ] RC Validation → Nightly #50.

### Next

- [ ] `release-evidence-<sha>` + RC audit dry-run.
- [ ] Linux 30s-slot soak (manual **Linux Soak Audit**, ~35 min).
- [ ] Operator sign-off.

## Agent 3 Detailed Plan

### Done

- [x] `WALLET_MIN_RING_SIZE = 16` in `mfn-wallet` (spend + upload builders).
- [x] All `mfn-cli` integration smokes updated to `--ring-size 16`.
- [x] `end_to_end`, `mempool_integration`, wasm transfer tests updated for ring-16.

### Next

- [ ] Full green Nightly #50 — blocked on green CI.

## Agent 2 Detailed Plan

- [ ] Release evidence after M2.5.1 fix commit CI green.
- [ ] Operator sign-off after Nightly + Linux soak.

## Shared Release-Candidate Gates

- Green GitHub CI — **FAIL** CI #502 on `4aafeea` (integration tests); M2.5.2 fix pending.
- Nightly ignored — **PASS** (#48); full Nightly rehearsal — pending green CI + #50.
- Linux 30s-slot soak — Windows done; Linux manual dispatch pending.
- Human sign-off — pending.

## Cross-Agent Blockers

- M2.5.0 CI red blocks RC Validation and Nightly #50 until M2.5.1 lands.
- **Do not push while CI in flight.**
- CI #493 (`f57dc9f`) cancelled when M2.5.0 landed — expected.
