# Three-Agent Coordination Checklist

See the root [`3agent.md`](../3agent.md) board for the latest cross-agent handoff table.

## Agent 1: Core Protocol, Consensus, Networking, Sync

- **Doing:** M2.5.1 — push ring-16 CI fix after local ci-check green (`ci-check-m251-final.log`).
- **Done:** M2.5.0 core (`0e10470`); M2.4.89 CI Linux hardening (`f57dc9f`); apply_block_proptest 29/29 + PPB coinbase endowment fix.
- **Next:** Green CI on M2.5.1 fix commit → RC Validation → Nightly #50.

## Agent 2: Security, RPC, Ops, Release Readiness

- **Doing:** Await green CI for `release-evidence` on M2.5.1 fix commit.
- **Done:** `release-evidence-052e507` on `7008d0a`.

## Agent 3: Wallet, Storage, Faucet, Onboarding

- **Done (local):** `WALLET_MIN_RING_SIZE=16`; all CLI smokes `--ring-size 16`; wallet/mempool/wasm tests updated.
- **Next:** Full green Nightly #50 after M2.5.1 CI green.

## Cross-Agent Blockers

- M2.5.1 fix commit pending push; CI #494 failed on bare `0e10470`.
- **Do not push while CI in flight** — concurrency `cancel-in-progress` aborts the matrix (~70 min).
