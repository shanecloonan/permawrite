# B-91 - Public testnet health assert + tip-4662 (2026-07-20)

## Why

B-90 CI `#29776397760` cancelled by B-34 push. Agents need one VPS command to verify timer + tip-align proxy + faucet + Path A lag.

## Tooling

| Path | Role |
| --- | --- |
| `assert-public-testnet-health.sh` | --plan-only / --apply on VPS |
| rehearsal smoke `.sh`/`.ps1` | ci-check plan gate |

Also landed tip-**4662** (lag=21 fire; entries=25). Re-proves B-90 stack under full CI.

## Proof

```
CI #29777008854 GREEN on c752992 (B-34)
B-90 CI #29776397760 cancelled (cancel-in-progress)
publish-near-tip-checkpoint-if-lag: tip=4662 lag=21 entries=25
assert-public-testnet-health-rehearsal-smoke: PASS plan-only
never=faucet-http mfnd observer-rpc-proxy restart
```
