# B-136 tip-ckpt lag health_ok FAIL reason (2026-07-21)

## Summary

When tip lag exceeds threshold, FAIL reason now distinguishes:
- health_ok → 
ecommended_action=path_a_republish (lane 7)
- health_degraded → 
ecommended_action=diagnose_public_health

| Field | Value |
| --- | --- |
| tip / lag / age_sec | 5288 / 437 / ~52549 |
| HEALTH | proxy=ok faucet=ok |
| reason | tip_lag>=threshold;health_ok |
| recommended_action | path_a_republish |
| Evidence | outside-in-tip-ckpt-lag-20260721T180548Z.txt |

No Path A publish from lane 1.
