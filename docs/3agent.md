# Three-Agent Coordination Checklist

See the root [`3agent.md`](../3agent.md) board for the latest cross-agent handoff table.

## Agent 1: Core Protocol, Consensus, Networking, Sync

- **Doing:** M2.4.88 — observer boot hardening (fatal poll, multi-peer dials, GHA 300s catch-up).
- **Done:** M2.4.87 on `70b0adb`; local Windows rehearsal PASS.
- **Next:** Push M2.4.88 after CI #491 green → Nightly #49.

## Agent 2: Security, RPC, Ops, Release Readiness

- **Doing:** Await green CI for `release-evidence-70b0adb`.
- **Done:** `release-evidence-052e507` on `7008d0a`.

## Agent 3: Wallet, Storage, Faucet, Onboarding

- **Partial:** Ignored Nightly PASS (#48); observer rehearsal pending M2.4.88.
- **Next:** Full green Nightly #49 after M2.4.88 lands.

## Cross-Agent Blockers

- CI #491 on `70b0adb` must finish before M2.4.88 push (cancel-in-progress).
- Observed local WIP: storage-operator payout in Rust crates — incomplete; not part of M2.4.88.
