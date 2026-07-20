# B-85 - Near-tip Path A checkpoint if lag (2026-07-20)

## Why

JOIN F45 hard-fails when Path A log lags live tip by tens of blocks. Manual republish races other agents; automate lag-gated publish.

## Tooling

| Path | Role |
| --- | --- |
| `publish-near-tip-checkpoint-if-lag.sh` | `--plan-only` / `--apply` |
| rehearsal smoke `.sh`/`.ps1` | ci-check plan gate |
| `MFN_CKPT_LAG_THRESHOLD` | default 16 |

Also published exact-tip **4567** (entries=20) with this unit. B-85 `--apply` SKIP at lag=0 after publish.

## Proof (Hetzner)

```
new_ckpt 4567
publish-near-tip-checkpoint-if-lag: tip=4567 ckpt_max=4567 lag=0 threshold=16
publish-near-tip-checkpoint-if-lag: SKIP lag below threshold
publish-near-tip-checkpoint-if-lag: PASS plan-only
CI #29764280042 GREEN on e45c9ec (B-84)
```

Never faucet/mfnd. OPERATORS: B-85 cron note + F105 proxy-prove wait.
