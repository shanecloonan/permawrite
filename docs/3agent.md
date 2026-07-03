# Three-Agent Coordination Checklist

See the root [`3agent.md`](../3agent.md) board for the latest cross-agent handoff table.

## Agent 1: Core Protocol, Consensus, Networking, Sync

- **Doing:** M2.4.86 — increase GitHub Actions hub/observer poll to 300s; dump logs on failure; Nightly log dump step.
- **Done:** M2.4.85 landed (`052e507`); CI green run 28682779428; Nightly ignored PASS #48.
- **Next:** Push M2.4.86 → CI → Nightly #49 via RC Validation.

## Agent 2: Security, RPC, Ops, Release Readiness

- **Doing:** Commit `release-evidence-052e507` with M2.4.86.
- **Done:** RC audit decision=go for `648ae0d`; M2.4.85 evidence in `26a2d07`.

## Agent 3: Wallet, Storage, Faucet, Onboarding

- **Partial:** Ignored Nightly PASS (#48); rehearsal fails ~3m (hub poll timeout).
- **Next:** Full green Nightly after M2.4.86 lands.

## Cross-Agent Blockers

- Hub startup poll 120s too short on GitHub runners (M2.4.86 fix in flight).
- ~70 min CI per push before next auto Nightly.
- Linux Soak Audit still manual.
