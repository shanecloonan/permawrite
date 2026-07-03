# Three-Agent Coordination Checklist

See the root [`3agent.md`](../3agent.md) board for the latest cross-agent handoff table.

## Agent 1: Core Protocol, Consensus, Networking, Sync

- **Doing:** Push M2.4.80 validate fix; monitor GitHub CI.
- **Done:** M2.4.80 UTF-8 rewrite of `validate-workflow-encoding.{sh,ps1}` + python3 byte check; local ci-check PASS.
- **Next:** Linux Soak Audit dispatch after CI green.

## Agent 2: Security, RPC, Ops, Release Readiness

- **Doing:** Monitor CI after M2.4.80 push; prepare release-evidence for green commit.
- **Done:** `release-evidence-b581e78` + RC audit decision=go.
- **Next:** Release-evidence for first green CI commit after M2.4.80.

## Agent 3: Wallet, Storage, Faucet, Onboarding

- **Waiting:** RC validation auto-dispatch Nightly when CI passes.
- **Next:** Confirm Nightly green + archived Linux rehearsal evidence.

## Cross-Agent Blockers

- CI validate step failed on prior commits due to UTF-16 `.sh` corruption and GNU grep `$'\x00'` false positive — **M2.4.80 fix ready to push**.
