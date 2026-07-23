# Live testnet permanence density — session findings waves 100–112 (2026-07-23)

## Scorecard

| Wave | Wallet | Result | last_proven | Notes |
| --- | --- | --- | --- | --- |
| 100 | tessa | PASS | 6621 | milestone |
| 101 | uma | FAIL F107 | — | wipe #1 |
| 102–104 | vera/wade/xan | PASS | 6652–6678 | |
| 105 | yara | FAIL F107 | — | wipe #2 |
| 106 | zeke | FAIL F114 | — | faucet hub 111 |
| 107–108 | aria/blake | PASS | 6754–6768 | |
| 109 | cyra | FAIL F107 | — | wipe #3 |
| 110 | dax | FAIL F115 | — | tip_id diverge pre-upload; wipe #4 |
| 111 | eden | PASS | 6809 | post-F115 |
| 112 | finn | PASS | 6824 | F95; streak x2 |

**JOIN:** 74 → **81** · tip~6824 · F45 lag **1520** · 3× F107 + 1× F114 + 1× F115

## Highest-signal findings

1. **F107** — density tax; wipe intervals x20/x3/x2.
2. **F114** — faucet hub 111 can be transient (no faucet restart).
3. **F115** — post-wipe tip_id diverge (mem=0) blocks upload; wipe recovers (waves 111–112 PASS).
4. **F45 lag cliff** — lag~1520 vs ckpt 5290; Path A republish urgent.
5. **F95** — ~15m cooldown still paces many waves.
6. Continuous `[skip ci]` docs on main.

## Next

wave113+ density; Path A republish (lane 7).
