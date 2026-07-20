# B-88 - Path A lag timer + tip-4606 (2026-07-20)

## Why

B-85 lag gate works, but manual republish races JOIN waves. Install a 30m systemd timer on Hetzner. Also land tip-**4606** (lag=22 fire). Document F107/F108 sticky-mempool JOIN mitigations in OPERATORS.

## Tooling

| Path | Role |
| --- | --- |
| systemd/path-a-near-tip-ckpt.service | oneshot B-85 apply |
| systemd/path-a-near-tip-ckpt.timer | every 30m |
| ps-install-near-tip-ckpt-timer.sh | --plan-only / --apply |
| rehearsal smoke .sh/.ps1 | ci-check plan gate |

## Proof

```
CI #29769164562 GREEN on ed3c51e (B-87)
publish-near-tip-checkpoint-if-lag: tip=4606 ckpt_max=4584 lag=22
checkpoint_log_verify_ok entries=22
never=faucet-http mfnd
```

After VPS timer install: systemctl is-active path-a-near-tip-ckpt.timer.