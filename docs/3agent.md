# Three-Agent Coordination Checklist

See the root [`3agent.md`](../3agent.md) board for the latest cross-agent handoff table.

## Agent 1: Core Protocol, Consensus, Networking, Sync

- **Done:** M2.5.8–M2.5.9 GHA startup + tip poll fixes; M2.5.18 CI #543 **GREEN**.
- **Done:** M2.5.19 — GHA hub tip 900s; health-check 600s; hub liveness 300s; voter-dial soft-continue when hub tip≥2 + both voters P2P listening.
- **Next:** Push M2.5.19 → CI green → Nightly #56 → Linux soak.

## Agent 2: Security, RPC, Ops, Release Readiness

- **Done:** M2.5.14–M2.5.18 evidence refresh + inline Nightly dispatch.
- **Next:** `release-evidence-refresh-for-head` after green Nightly #56.

## Agent 3: Wallet, Storage, Faucet, Onboarding

- **Done:** M2.5.11–M2.5.16 smoke evidence pipeline + assert gates.
- **Done:** Nightly #55 partial — ignored **PASS**; smokes **FAIL** ~11m (not 302s).
- **Next:** M2.5.19 → Nightly #56 participant+observer green.

## Cross-Agent Blockers

- Nightly #55 confirmed startup fix (11m class); **M2.5.19** extends GHA waits + voter-dial soft gate.
- Do **not** mark Nightly green until all three jobs pass on the exact RC commit.
