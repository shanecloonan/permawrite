# Three-Agent Coordination Checklist

See the root [`3agent.md`](../3agent.md) board for the latest cross-agent handoff table.

## Agent 1: Core Protocol, Consensus, Networking, Sync

- **Doing:** M2.4.80 fix validate-workflow-encoding.sh grep false positive (python3 byte check).
- **Done:** M2.4.79 UTF-8 workflow guard + CI queue cleanup success.
- **Next:** Linux Soak Audit dispatch after CI green.

## Agent 2: Security, RPC, Ops, Release Readiness

- **Doing:** Monitor CI after M2.4.80 validate fix.
- **Done:** `release-evidence-b581e78` + RC audit decision=go.
- **Next:** Release-evidence for first green CI commit after fix.

## Agent 3: Wallet, Storage, Faucet, Onboarding

- **Waiting:** RC validation auto-dispatch Nightly when CI passes.
- **Next:** Confirm Nightly green + archived Linux rehearsal evidence.

## Cross-Agent Blockers

- CI validate step failed on `db5b2b9` due to grep `$'\x00'` matching all files — **M2.4.80** fix in flight.
