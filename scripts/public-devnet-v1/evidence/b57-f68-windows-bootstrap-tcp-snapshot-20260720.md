# B-57 / F68 - Windows bootstrap checkpoint pin (2026-07-20)

## Problem

`bootstrap-wallet-from-checkpoint-log.ps1 -Apply` failed 8x with:

```text
invalid --params JSON: key must be a string at line 1 column 2
```

Root cause (wave11): Windows PowerShell 5.1 strips double quotes when passing arguments to native executables, so `{"height":4148}` arrives as `{height:4148}`.

## Fix

- Rewrite `.ps1` as UTF-8 (prior edits left UTF-16).
- Fetch `get_light_snapshot` via **Python TCP JSON-RPC**, then pin wallet JSON and run `wallet light-scan --checkpoint-log` + `wallet status`.
- `-PlanOnly` documents the F68 path.

## Smoke

| Path | Result |
| --- | --- |
| `powershell -File ... -PlanOnly` | PASS |
| Public proxy `http://5.161.201.73:8787/rpc` `get_light_snapshot(4148)` | OK (`ckpt_len=1452`) |
| VPS TCP `127.0.0.1:18734` same method | OK (`ckpt_len=1452`) |

Lane 3: re-run Windows `-Apply` against a local observer when convenient; no VPS service restart required (client-side helper).
