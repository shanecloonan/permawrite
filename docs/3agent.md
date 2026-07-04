# Three-Agent Coordination Checklist

See the root [`3agent.md`](../3agent.md) board for the latest cross-agent handoff table.

## Agent 1: Core Protocol, Consensus, Networking, Sync

- **Doing:** Monitor CI #522 on `4dbd5c7`; then Nightly #55.
- **Done:** M2.5.8 (`eb64408`/`4dbd5c7`) — GHA startup polls **600s**; root cause confirmed (302s = `HUB_POLL_MAX=300`).
- **Next:** Green Nightly #55 → Linux soak → operator sign-off.

## Agent 2: Security, RPC, Ops, Release Readiness

- **Done:** `release-evidence-f5f45bf` + RC audit dry-run (go).
- **Next:** Refresh evidence after green Nightly on `4dbd5c7`.

## Agent 3: Wallet, Storage, Faucet, Onboarding

- **Done:** M2.5.8 — single-sample health-check; curl RPC fallback; hub tip≥2; GHA timeout flags in nightly.yml.
- **Next:** Green Nightly participant + observer on `4dbd5c7`.

## Cross-Agent Blockers

- Nightly #52–#54 failed at **302s smoke step** (legacy 300s hub P2P poll); fixed in `eb64408`. Awaiting Nightly #55.
