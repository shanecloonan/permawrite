# Three-Agent Coordination Checklist

This file coordinates the three Permawrite build lanes. Keep it current alongside
`docs/TESTNET_CHECKLIST.md`; the checklist tracks milestone completion, while this
file tracks who is actively doing what, what is done, and what should happen next.

See also the root [`3agent.md`](../3agent.md) board for the latest cross-agent handoff table.

## Operating Rules

- Pull latest `main` before starting new work when the tree is safe to update.
- Do not overwrite another agent's uncommitted work.
- Keep changes scoped to the active lane unless a cross-lane blocker prevents progress.
- Update this file whenever an agent starts a unit, ships it, discovers a blocker, or hands off work.
- Before pushing `main`, run the local CI mirror and then inspect GitHub CI.

## Agent 1: Core Protocol, Consensus, Networking, Sync

Current:

- **M2.4.68 shipped** — observer rehearsal PASS archived; next: 30s-slot hub audit.

Next:

- 30s-slot long-run hub daemon lifetime audit.
- Monitor Linux nightly rehearsal smoke.

## Agent 2: Security, RPC, Ops, Release Readiness

Current:

- Monitor GitHub CI on M2.4.68; first nightly participant-rehearsal-smoke run.

Next:

- Release-readiness gates from `docs/TESTNET_CHECKLIST.md`.

## Agent 3: Wallet, Storage, Faucet, Onboarding

Current:

- **M2.4.68 shipped** — `-WithObserver -MinHubHeight 5` Windows PASS + archived evidence.

Done:

- M2.4.67 nightly promotion; M2.4.64 rehearsal PASS.

Next:

- Confirm Linux nightly rehearsal smoke green.

## Cross-Agent Blockers

- Local `gh` unauthenticated — use Actions UI or `gh auth login` to monitor CI/nightly.
