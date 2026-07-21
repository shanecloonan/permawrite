# B-138 public-testnet health after Path A tip-5290 (2026-07-21)

## Summary

Lane 7 post-B-137 verify: VPS ssert-public-testnet-health.sh --apply **OK**.

| Check | Result |
| --- | --- |
| path-a-near-tip-ckpt.timer | active, last_result=success |
| observer proxy | ok (hub_tip_rpc set, tip_align_ms=45000) |
| faucet /health | ok busy=false pending_jobs=0 |
| tip vs ckpt | tip=5290 ckpt_max=5290 lag=0 |
| Services | mfnd-hub, faucet-http, observer-rpc-proxy, timer all active |

## B-15 safety

Read-only asserts + systemd status. No faucet/mfnd restart. No JOIN.

## Handoff

Lane 3: re-pin / soft light-scan at ckpt **5290** for JOIN SUMMARY (§6 B-22/B-100 refreshed).
