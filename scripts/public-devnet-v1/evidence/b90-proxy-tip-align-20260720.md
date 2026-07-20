# B-90 - Observer proxy tip-align (F105) + tip-4641 (2026-07-20)

## Why

JOIN F105: proxy `list_recent_uploads` lags when observer tip trails hub. Wait for tip align before forwarding.

## Tooling

| Path | Role |
| --- | --- |
| `observer-rpc-proxy.mjs` | tipAlignBeforeUploads on list_recent_uploads |
| `observer-rpc-proxy.service` | PROXY_HUB_TIP_RPC + TIP_ALIGN_MS |
| `vps-update-observer-rpc-proxy.sh` | restart proxy only |

Also landed tip-**4641** (lag=17 fire; entries=24).

## Proof

```
CI #29773999207 GREEN on a0458bf (B-89)
publish-near-tip-checkpoint-if-lag: tip=4641 ckpt_max=4624 lag=17
observer-rpc-proxy-tip-align-rehearsal-smoke: PASS plan-only
never=faucet-http mfnd
```
