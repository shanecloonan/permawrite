# B-133 outside-in soak refresh (2026-07-21 tip-5285)

## Summary

Lane 1 refreshed invite-head soak via public observer proxy. Tip advancing (permanence live). Path A checkpoint lag worsened — handed to lane 7 via AGENTS.md section 6 (do not Path A publish from lane 1 during B-15).

| Field | Value |
| --- | --- |
| Soak evidence | outside-in-invite-soak-20260721T175511Z.txt |
| Soak assert | OK |
| Tip | 5283 -> 5285 (delta=2) |
| Nightly pin | 29852343531 |
| CI pin | 29852461441 |
| Head at capture | 63b62c9 |
| Tip-ckpt lag evidence | outside-in-tip-ckpt-lag-20260721T175543Z.txt |
| Path A ckpt max | 4851 (lag=432) |

## B-15 safety

Read-only public proxy + local jsonl. Never faucet/mfnd/JOIN/Path A publish.
