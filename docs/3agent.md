# Three-Agent Coordination Checklist

See the root [`3agent.md`](../3agent.md) board for the latest cross-agent handoff table.

## Agent 1: Core Protocol, Consensus, Networking, Sync

- **M2.4.74 done:** `linux-soak-audit.yml` GitHub workflow for Linux 30s-slot soak + artifact upload.
- **Next:** Dispatch workflow; archive Linux evidence to `scripts/public-devnet-v1/evidence/`.

## Agent 2: Security, RPC, Ops, Release Readiness

- **M2.4.74 done:** `release-evidence-9536efb.*` + `rc-audit-dry-run-9536efb-*.json` (decision=go).
- **Next:** CI green on push; operator sign-off.

## Agent 3: Wallet, Storage, Faucet, Onboarding

- **Next:** Manually dispatch **Nightly** on `main`; confirm both rehearsal jobs green.

## Cross-Agent Blockers

- CI queue backlog on GitHub Actions.
- Last cron Nightly predates observer rehearsal job (M2.4.72).
