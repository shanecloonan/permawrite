# B-129 tip-ckpt lag auto-evidence (2026-07-21)

## Summary

Lane 1 extends B-127 so --apply / -Apply auto-archives a lag probe transcript under evidence/ (soak parity). Disable with --no-archive / -NoArchive.

| Field | Value |
| --- | --- |
| Live probe | tip=5233 ckpt_max=4851 lag=382 (FAIL) |
| Evidence | outside-in-tip-ckpt-lag-20260721T161508Z.txt |
| Handoff | Lane 7 Path A republish (section 6) |

## B-15 safety

Read-only public proxy + local jsonl. Never faucet/mfnd/JOIN/Path A publish.
