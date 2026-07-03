# Three-Agent Coordination Checklist

See the root [`3agent.md`](../3agent.md) board for the latest cross-agent handoff table.

## Agent 1: Core Protocol, Consensus, Networking, Sync

- **Blocked:** CI #490 on `7008d0a` failed (ubuntu/macOS tests, likely flake; scripts-only commit).
- **Next:** M2.4.87 push → green CI → Nightly #49 with hub poll 300s.

## Agent 2: Security, RPC, Ops, Release Readiness

- **Done:** `release-evidence-052e507` committed with M2.4.86.
- **Next:** `release-evidence-7008d0a` after CI green.

## Agent 3: Wallet, Storage, Faucet, Onboarding

- **Done:** Windows `--no-build` participant rehearsal PASS locally.
- **Waiting:** Nightly #49 after M2.4.86 hub poll fix lands on green CI.

## Cross-Agent Blockers

- Do not push during CI; docs-only pushes cancel in-flight matrix.
- Nightly rehearsal still failing on `052e507` (#48); M2.4.86 hub poll 300s not yet validated (CI red).
