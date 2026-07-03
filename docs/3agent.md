# Three-Agent Coordination Checklist

See the root [`3agent.md`](../3agent.md) board for the latest cross-agent handoff table.

## Agent 1: Core Protocol, Consensus, Networking, Sync

- **M2.4.73 done:** Linux `soak.sh` parity (`--min-final-height`, convergence retries, `--archive-evidence`); bash soak lock via `ports-env-lib.sh`.
- **Next:** Linux 30s-slot soak evidence capture.

## Agent 2: Security, RPC, Ops, Release Readiness

- **M2.4.73 done:** `release-rc-audit-dry-run.ps1` archived decision=go with M2.4.70 soak evidence.
- **Next:** Green CI + operator human sign-off.

## Agent 3: Wallet, Storage, Faucet, Onboarding

- **M2.4.72/73:** nightly observer job + `ci-ignored` mirror for both rehearsal smokes.
- **Next:** Confirm first green Linux nightly (both jobs).

## Cross-Agent Blockers

- `gh` not authenticated locally; use GitHub Actions UI for CI/nightly status.
- Linux 30s-slot soak evidence not yet captured (Windows evidence archived).
