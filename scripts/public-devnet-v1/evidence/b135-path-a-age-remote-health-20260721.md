# B-135 Path A age_sec + remote public health (2026-07-21)

## Summary

Lane 1 extended tip-ckpt lag assert:
- ge_sec from Path A published_at (unix)
- informational HEALTH pings to public proxy + faucet (never restart)

| Field | Value |
| --- | --- |
| tip / ckpt_max / lag | 5287 / 4851 / 436 |
| age_sec | 52462 (~14.6h) |
| HEALTH | proxy=ok faucet=ok |
| Evidence | outside-in-tip-ckpt-lag-20260721T180421Z.txt |

## Diagnosis for lane 7

Public mesh/RPC/faucet healthy. Path A jsonl stale ~14h — B-85 timer / republish path, not hub tip stall. No Path A publish from lane 1 (B-15 + lane ownership).
