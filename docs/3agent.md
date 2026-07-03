# Three-Agent Coordination Checklist

See the root [`3agent.md`](../3agent.md) board for the latest cross-agent handoff table.

## Agent 1: Core Protocol, Consensus, Networking, Sync

- **Doing:** M2.4.77 fix `ci-queue-cleanup.yml` UTF-8 encoding (GitHub rejected UTF-16).
- **Done:** M2.4.76 upload retry, dispatch REST fallback, observer evidence archive.
- **Next:** Confirm CI queue cleanup succeeds; dispatch Linux Soak Audit.

## Agent 2: Security, RPC, Ops, Release Readiness

- **Done:** `release-evidence-ad18d94` + RC audit decision=go.
- **Next:** CI green on latest `main` after queue cleanup.

## Agent 3: Wallet, Storage, Faucet, Onboarding

- **Done:** Observer rehearsal PASS + `-ArchiveEvidence` UTF-8 no BOM.
- **Next:** Green Linux Nightly (both jobs).

## Cross-Agent Blockers

- CI backlog — M2.4.77 cleanup workflow must parse (UTF-8 fix) before it can cancel stale runs.
