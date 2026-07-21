# B-127 outside-in tip-ckpt lag assert (2026-07-21)

## Summary

Lane 1 adds a B-15-safe outside-in probe: public get_tip vs local Path A checkpoints.jsonl max tip. Fail-closed when lag >= 16. Does **not** publish Path A (lane 7). Wired plan-only into ci-check.

| Field | Value |
| --- | --- |
| Tooling | ssert-outside-in-tip-ckpt-lag.{sh,ps1} + rehearsal smokes |
| Live probe | tip=5215 ckpt_max=4851 lag=364 (FAIL as expected) |
| Owner handoff | Lane 7 Path A republish (B-85/B-100 pattern) |

## B-15 safety

Read-only public proxy + local jsonl. Never faucet/mfnd/JOIN/Path A publish.
