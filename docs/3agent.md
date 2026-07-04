# Three-Agent Coordination Checklist

See the root [`3agent.md`](../3agent.md) board for the latest cross-agent handoff table.

## Agent 1: Core Protocol, Consensus, Networking, Sync

- **Doing:** M2.4.89 — board truth + CI re-run after CI #492 ubuntu-only flake on `297ec27`.
- **Done:** M2.4.88 observer boot hardening pushed (`297ec27`).
- **Next:** Green CI #493 → RC Validation → Nightly #49.

## Agent 2: Security, RPC, Ops, Release Readiness

- **Doing:** Await green CI for `release-evidence-297ec27`.
- **Done:** `release-evidence-052e507` on `7008d0a`.

## Agent 3: Wallet, Storage, Faucet, Onboarding

- **Partial:** Ignored Nightly PASS (#48); full Nightly blocked on green CI.
- **Next:** Full green Nightly #49 after CI #493.

## Cross-Agent Blockers

- CI #492 failed ubuntu test only (run `28687976097`); macos/windows green — re-run via M2.4.89 push.
- Observed local WIP: storage-operator payout in Rust crates — incomplete; not on `main`.
