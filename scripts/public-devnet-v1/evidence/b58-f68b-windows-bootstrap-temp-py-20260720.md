# B-58 / F68b - Windows bootstrap temp .py (2026-07-20)

## Problem (wave12)

B-57 advertised python TCP snapshot but `-Apply` still failed with `File "<string>", line 3` because multiline `python -c` here-strings are unreliable under Windows PowerShell 5.1.

## Fix

Write `max_tip.py`, `get_light_snapshot.py`, and `pin_wallet.py` into a temp dir; invoke as `python script.py args...` (no multiline `-c`, no mfn-cli `--params` JSON).

## Smoke (SSH tunnel to VPS observer :18734)

```
log_max_tip=4159
snapshot_ok attempt=1
pinned scan_height=4159
```

Subsequent `wallet light-scan --checkpoint-log` exited 1 with F45 (`no attestation at tip_height 4161`) - tip advanced past log max; not an F68 failure.

## Deploy

Client-side only; `git pull` on VPS for docs. No service restart.