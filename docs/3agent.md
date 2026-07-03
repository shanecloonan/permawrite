# Three-Agent Coordination Checklist

See the root [`3agent.md`](../3agent.md) board for the latest cross-agent handoff table.

## Agent 1: Core Protocol, Consensus, Networking, Sync

- **Doing:** M2.4.83 fix Nightly auto-dispatch (`ref: main` + `checkout_sha` input).
- **Done:** M2.4.82 first full green CI on `e6e8d86` (all 9 jobs).
- **Next:** Linux Soak Audit after Nightly green.

## Agent 2: Security, RPC, Ops, Release Readiness

- **Done:** `release-evidence-e6e8d86` + RC audit decision=go with CI success URL.
- **Next:** Operator sign-off after Nightly + Linux soak.

## Agent 3: Wallet, Storage, Faucet, Onboarding

- **Doing:** Await first green Nightly on exact green commit via fixed RC validation.
- **Next:** Confirm both rehearsal jobs green + archive evidence.

## Cross-Agent Blockers

- Do not push while CI is running (Linux/macOS tests ~70 min).
- Linux Soak Audit needs Actions UI or `GH_TOKEN`.