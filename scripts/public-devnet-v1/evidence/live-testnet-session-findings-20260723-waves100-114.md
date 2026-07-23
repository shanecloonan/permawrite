# Live testnet permanence density — session findings waves 100–114 (2026-07-23)

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
| 110 | dax | FAIL F115 | — | tip_id diverge; wipe #4 |
| 111–114 | eden/finn/gina/hugo | PASS | 6809–6848 | post-F115 streak **x4** |

**JOIN:** 74 → **83** · tip~6848 · F45 lag **1549** · 3× F107 + 1× F114 + 1× F115

## Highest-signal findings

1. **F107** — density tax; wipe intervals x20/x3/x2.
2. **F114** — faucet hub Connection refused can be transient.
3. **F115** — post-wipe tip_id diverge (mem=0) blocks upload; wipe recovers (111–114 PASS).
4. **F45 lag cliff** — lag~1549 vs ckpt 5290; Path A republish urgent.
5. **F95** — still paces many consecutive faucet waves.
6. Docs pushed `[skip ci]` after each wave.

## Next

wave115+ density; Path A republish (lane 7); human SUMMARY when invite window opens.
