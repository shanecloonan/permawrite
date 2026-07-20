# B-89 - Path A timer assert + land helper + tip-4624 (2026-07-20)

## Why

B-88 timer runs on Hetzner; agents need a fail-closed health check and a one-command scp when VPS tip ahead of repo (JOIN F45).

## Tooling

| Path | Role |
| --- | --- |
| ssert-path-a-near-tip-timer.sh | VPS: timer active, units present, last oneshot not failed |
| land-path-a-checkpoint-from-vps.sh | agent host: scp jsonl if remote tip > local |
| path-a-near-tip-ops-rehearsal-smoke.* | ci-check plan gate |

Also landed tip-**4624** (lag=18 fire; entries=23).

## Proof

```
CI #29771537059 GREEN on 3a0efff (B-88)
publish-near-tip-checkpoint-if-lag: tip=4624 ckpt_max=4606 lag=18
checkpoint_log_verify_ok entries=23
path-a-near-tip-ops-rehearsal-smoke: PASS plan-only
never=faucet-http mfnd
```