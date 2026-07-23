# Live testnet permanence density — session findings waves 100–110 (2026-07-23)

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
| 110 | dax | FAIL F115 | — | funded; tip_id diverge pre-upload; wipe #4 |

**JOIN:** 74 → **79** · tip~6797 · F45 lag **1498** · 3× F107 + 1× F114 + 1× F115

## Highest-signal findings

1. **F107 density tax** — wipe intervals x20 / x3 / x2 under Fresh-upload loops.
2. **F114** — faucet hub Connection refused can be transient; no faucet restart.
3. **F115 (new)** — after wipe+resync, local tip can fork ahead of proxy (mem=0) and block upload tip_id gate; wipe again.
4. **F45 lag cliff** — lag~1498 vs ckpt 5290; Path A republish urgent.
5. **F95** — still paces many waves.

## Next

wave111+ after wipe#4 resync; Path A republish (lane 7).
