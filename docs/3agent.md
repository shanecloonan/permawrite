# Three-Agent Coordination Checklist

See the root [`3agent.md`](../3agent.md) board for the latest cross-agent handoff table.

## Agent 1: Core Protocol, Consensus, Networking, Sync

- **Doing:** Monitor CI #524 on `318407a`; push `96327da` after green.
- **Done:** M2.5.8 (`eb64408`/`4dbd5c7`) — 600s GHA startup polls; Nightly #54 post-mortem (302s = `HUB_POLL_MAX=300`).
- **Done:** M2.5.9 (`318407a`/`96327da`) — shared `query_tip_height` with nc/curl get_status fallback.
- **Next:** Green Nightly #55 → Linux soak → operator sign-off.

## Agent 2: Security, RPC, Ops, Release Readiness

- **Done:** `release-evidence-f5f45bf` + RC audit dry-run (go).
- **Next:** Refresh evidence after green Nightly on M2.5.9 commit.

## Agent 3: Wallet, Storage, Faucet, Onboarding

- **Done:** M2.5.8 — single-sample health-check; curl RPC fallback; hub tip≥2; GHA timeout flags.
- **Done:** Smoke wrappers default `participant-rehearsal-smoke/evidence/` and pass through to `participant-rehearsal`.
- **Done:** Windows draft202012 venv python passthrough in `ci-check.ps1`.
- **Done:** M2.5.9 — fund-wallet/permanence-demo tip query parity.
- **Done:** M2.5.10 pushed (`994d1a9`); CI #527 running on GitHub.
- **Next:** Green CI #527 → Nightly participant + observer.

## Cross-Agent Blockers

- Nightly #52–#54 failed at **302s** (legacy 300s hub P2P poll); fixed in `eb64408` + M2.5.9 tip fallback.
- CI #522 **cancelled** by concurrent pushes; CI #524 **IN PROGRESS** on `318407a`.
- Do **not** push `96327da` until CI #524 completes (cancel-in-progress).
