# B-61 — roll CI via public API + RPC listen wait + tip-4173 (2026-07-20)

## Why

B-60.1 refused rolls when `gh` was missing on the VPS. Operators should not need a GitHub token on the producer host for a public repo. Cold hub restarts also need an explicit RPC-listen wait before tip-advance polling (chain.blocks replay).

## Changes

1. CI preflight: `gh run list` if available, else `api.github.com` workflow runs for `ci.yml` on `main`.
2. After `systemctl restart mfnd-hub`: wait up to 300s for `:18731` listen / tip readable (exit 5 if not).
3. Tip-advance wait extended to 240s.
4. Path A checkpoint tip **4173** (entries=10).

## Verify

- `vps-roll-mfnd.sh --plan-only` / rehearsal smoke
- On VPS with CI in progress: `--apply` should exit 4 via public API without `gh`
