# Three-Agent Coordination Checklist

See the root [`3agent.md`](../3agent.md) board for the latest cross-agent handoff table.

## Agent 1: Core Protocol, Consensus, Networking, Sync

- **Doing:** M2.4.78 `rc-validation-after-ci.yml` (Nightly auto-dispatch on green CI).
- **Done:** M2.4.77 CI queue cleanup UTF-8 fix (success on `d6298d4`).
- **Next:** Linux Soak Audit manual dispatch + archive artifact.

## Agent 2: Security, RPC, Ops, Release Readiness

- **Doing:** Monitor CI `d6298d4` in_progress.
- **Next:** release-evidence for green commit.

## Agent 3: Wallet, Storage, Faucet, Onboarding

- **Doing:** bash `--archive-evidence` + Nightly job wiring.
- **Next:** Green Nightly on exact CI commit (auto via rc-validation).

## Cross-Agent Blockers

- Linux 30s-slot soak: manual dispatch only (90min); Windows evidence archived.
