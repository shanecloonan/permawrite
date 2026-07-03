# Three-Agent Coordination Checklist

See the root [`3agent.md`](../3agent.md) board for the latest cross-agent handoff table.

## Agent 1: Core Protocol, Consensus, Networking, Sync

- **Doing:** M2.4.76 CI queue cleanup workflow + P2P upload transport retry.
- **Done:** M2.4.70 Windows 30s soak; M2.4.75 dispatch helpers.
- **Next:** Linux Soak Audit workflow dispatch + archive artifact.

## Agent 2: Security, RPC, Ops, Release Readiness

- **Doing:** release-evidence for `ad18d94`; push triggers CI queue cleanup.
- **Next:** RC audit dry-run; monitor CI green.

## Agent 3: Wallet, Storage, Faucet, Onboarding

- **Done:** Observer rehearsal PASS + UTF-8 evidence fix + `-ArchiveEvidence` on smoke script.
- **Next:** Green Linux Nightly (both rehearsal jobs) via dispatch.

## Cross-Agent Blockers

- CI queue backlog — resolved by `ci-queue-cleanup.yml` on next push to `main`.
