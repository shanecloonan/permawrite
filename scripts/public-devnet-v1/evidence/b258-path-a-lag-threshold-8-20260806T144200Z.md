# B-258 Path A timer lag threshold 16->8 (2026-08-06)

## Unit
Lane 7: tighten Path A near-tip auto-publish so tall-tip JOIN soft-pin does not wait for lag=16 (B-252/B-256 already published manually at 8).

## Changes
- `systemd/path-a-near-tip-ckpt.service` `MFN_CKPT_LAG_THRESHOLD=8`
- `publish-near-tip-checkpoint-if-lag` default 8
- `assert-public-testnet-health` / outside-in tip-ckpt lag defaults 8
- OPERATORS + install rehearsal smoke needle

## Live prove (Hetzner)
- `vps-install-near-tip-ckpt-timer.sh --apply` OK
- Environment includes `MFN_CKPT_LAG_THRESHOLD=8`
- `assert-public-testnet-health --apply` OK tip=16336 ckpt=16330 lag=6 threshold=8
- faucet idle; p2p-forward hygiene OK; no mfnd/faucet restart

## Never
JOIN during B-15; fake B-32 READY; cancel tip CI #31109005252

## Verdict
PASS — timer will republish at lag>=8 without manual override.