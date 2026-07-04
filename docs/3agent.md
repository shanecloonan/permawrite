# Three-Agent Coordination Checklist

See the root [`3agent.md`](../3agent.md) board for the latest cross-agent handoff table.

## Agent 1: Core Protocol, Consensus, Networking, Sync

- **Doing:** M2.5.3 — mempool_integration + mfnd_smoke + mfn-runtime/mempool ring-16 after CI #503 failure on `434b444`.
- **Done:** M2.5.2 (`434b444`) integration + checkpoint offsets; M2.5.1 proptest harness; M2.5.0 ring-16 + operator coinbase (`0e10470`).
- **Next:** Push M2.5.3 → green CI #504 → RC Validation → Nightly #50.

## Agent 2: Security, RPC, Ops, Release Readiness

- **Doing:** Await green CI on M2.5.3 for `release-evidence-<sha>`.
- **Done:** `release-evidence-052e507` on `7008d0a`; SECURITY_CONSIDERATIONS updated for closed M2.5.0 items.

## Agent 3: Wallet, Storage, Faucet, Onboarding

- **Done:** `WALLET_MIN_RING_SIZE=16`; all CLI smokes `--ring-size 16`; wallet/mempool/wasm tests updated (`a4e70c9`).
- **Next:** Full green Nightly #50 after M2.5.3 CI green.

## Cross-Agent Blockers

- CI #503 failed on `434b444` — node integration tests still used ring-2/4/8; M2.5.3 fix local.
- **Do not push while CI in flight** — concurrency `cancel-in-progress` aborts the matrix (~70 min).
