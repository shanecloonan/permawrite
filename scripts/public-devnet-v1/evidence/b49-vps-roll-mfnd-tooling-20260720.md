# B-49 — vps-roll-mfnd tooling (2026-07-20)

## Why

Lane 7 must roll `mfnd` after CI GREEN for **B-45** (salted SPoRA) without ad-hoc restart thrash that caused tip-4031 (B-46). Board also asks for **B-48** soft-EAGAIN quarantine on the binary — that code was **not** on `main` at tooling land (local lane-4 WIP only); do not claim tip-stall immunity until B-48 commits.

## Delivered

- `scripts/public-devnet-v1/vps-roll-mfnd.sh` (`--plan-only` / `--apply`)
- `scripts/public-devnet-v1/vps-roll-mfnd-rehearsal-smoke.sh` wired into `ci-check`
- Flow: pull → build mfnd/mfn-cli → `vps-soften-mfnd-requires` → restart voters → restart hub → wait tip advance
- Never touches `faucet-http` / `observer-rpc-proxy`

## Live apply

Only after CI GREEN on the head. Prefer waiting for B-48 land if tip-stall hardening is required in the same roll.
