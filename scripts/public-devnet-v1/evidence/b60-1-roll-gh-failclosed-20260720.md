# B-60.1 — roll CI gate fail-closed without gh (2026-07-20)

## Incident

B-60 preflight WARN-continued when `gh` missing on VPS. A smoke `--apply --skip-build` then restarted hub/voters while CI `#29717107514` was still in progress. Hub spent ~2–3 minutes at 100% CPU replaying `chain.blocks` before RPC listen; tip briefly stuck at 4171.

## Fix

Missing `gh` now **exit 4** unless `MFN_ROLL_ALLOW_RED_CI=1`.

## Ops note

After hub restart, wait for RPC `:18731` listen (CPU drop from 100%) before declaring tip-stall. Do not thrash `systemctl restart mfnd-hub` during load.
