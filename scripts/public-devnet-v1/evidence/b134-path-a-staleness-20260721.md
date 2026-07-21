# B-134 Path A staleness fields + §8 repair (2026-07-21)

## Summary

Lane 1:
1. Repaired corrupted AGENTS.md §8 session-log header (B-133 claim splice).
2. Extended tip-ckpt lag assert with Path A staleness: ckpt_entries, published_at, 	ip_block_id.

| Field | Value |
| --- | --- |
| Live tip | 5287 |
| ckpt_max | 4851 |
| lag | 436 |
| ckpt_entries | 33 |
| published_at | 1784604599Z |
| tip_block_id | fabdeb6f0f1c4feef6efb1e8fbe505dead8bd01ba7400d5a104ff0b1129a187a |
| Evidence | outside-in-tip-ckpt-lag-20260721T180241Z.txt |

## Lane boundary

Does **not** publish Path A (lane 7). §6 tip-lag request remains Open. B-15-safe.
