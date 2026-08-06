# B-248 - Invite-load preflight harness (B-42 toward live)

**Unit:** B-248 (elevates B-42 plan gate; does **not** close live invite-load)
**When:** 2026-08-06T13:30:00Z (approx)
**B-15-safe:** no JOIN; no faucet/mfnd restart
**Do not steal:** lane4 **B-246**; lane6 **B-13a-512**

## What landed

- `invite-load-smoke-rehearsal.sh` / `.ps1`: `--plan-only` (ci-check), `--apply` preflight, `--live` arm gate
- Live JOIN requires `MFN_INVITE_LOAD_ALLOW_LIVE=1` + `--live`; JOIN still operator-driven
- Default `--apply` exits PASS with `serialize-with-reason` (held during B-15)

## Live prove (Windows outside-in)

```text
powershell -File scripts/public-devnet-v1/invite-load-smoke-rehearsal.ps1 -Apply
```

| Check | Result |
| --- | --- |
| plan-only | PASS |
| proxy /health | ok tip~16302 |
| faucet /health | ok busy=false pending=0 |
| seeds 19001-19003 | OPEN |
| serialize_with_reason | need_-Live_flag (correct while B-15 / unarmed) |

Preflight transcript: `invite-load-preflight-20260806T133250Z.txt`

## Next

After lane3 B-15 clear: arm `MFN_INVITE_LOAD_ALLOW_LIVE=1` + staggered JOIN x2 → archive `invite-load-smoke-*.txt` to close **B-42**.
