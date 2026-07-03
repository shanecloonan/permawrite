# Three-Agent Coordination Checklist

See the root [`3agent.md`](../3agent.md) board for the latest cross-agent handoff table.

## Agent 1: Core Protocol, Consensus, Networking, Sync

- **Doing:** Watch Nightly on `5384ae2`; prep Linux Soak Audit dispatch.
- **Done:** M2.4.83 CI success + RC Validation success on `5384ae2`.
- **Next:** Linux Soak Audit after Nightly green.

## Agent 2: Security, RPC, Ops, Release Readiness

- **Doing:** Archive `release-evidence-5384ae2` + RC audit decision=go.
- **Done:** `release-evidence-e6e8d86` (first full green CI).
- **Next:** Operator sign-off after Nightly + Linux soak.

## Agent 3: Wallet, Storage, Faucet, Onboarding

- **Doing:** Nightly running with `checkout_sha=5384ae2` (ignored + both rehearsal jobs).
- **Next:** Archive rehearsal evidence from Nightly artifacts.

## Cross-Agent Blockers

- Linux Soak Audit still manual (~35 min); dispatch via Actions UI or `dispatch-rc-workflows.ps1 -LinuxSoakAudit` with `GH_TOKEN`.
