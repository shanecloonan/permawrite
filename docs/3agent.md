# Three-Agent Coordination Checklist

See the root [`3agent.md`](../3agent.md) board for the latest cross-agent handoff table.

## Agent 1: Core Protocol, Consensus, Networking, Sync

- **Doing:** Watch Nightly #47 on `648ae0d` (run 28680468122).
- **Done:** CI success on `648ae0d`; RC Validation auto-dispatch success.
- **Next:** Linux Soak Audit after Nightly green.

## Agent 2: Security, RPC, Ops, Release Readiness

- **Doing:** Archive `release-evidence-648ae0d` + RC audit decision=go.
- **Done:** `release-evidence-5384ae2` chain.
- **Next:** Operator sign-off after Nightly + Linux soak.

## Agent 3: Wallet, Storage, Faucet, Onboarding

- **Doing:** Nightly all 3 jobs in progress on `648ae0d`.
- **Next:** Archive Linux rehearsal evidence from workflow artifacts.

## Cross-Agent Blockers

- Linux Soak Audit still manual (~35 min).
- Do not push commits that re-dispatch/cancel Nightly while #47 runs.
