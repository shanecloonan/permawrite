# Live testnet permanence density — session findings waves 100–109 (2026-07-23)

## Scorecard

| Wave | Wallet | Result | last_proven | Notes |
| --- | --- | --- | --- | --- |
| 100 | tessa | PASS | 6621 | milestone; F95 |
| 101 | uma | FAIL F107 | — | wipe #1 |
| 102–104 | vera/wade/xan | PASS | 6652–6678 | streak x3 |
| 105 | yara | FAIL F107 | — | wipe #2 |
| 106 | zeke | FAIL F114 | — | faucet hub 111 |
| 107–108 | aria/blake | PASS | 6754–6768 | F114 recovered |
| 109 | cyra | FAIL F107 | — | wipe #3 (streak only x2) |

**JOIN:** 74 → **79** · tip~6784 · F45 lag **1479** · **3× F107 wipes** + 1× F114 today

## Highest-signal findings

1. **F107 is the density tax** — wipe intervals of x20 / x3 / x2 under Fresh-upload loops.
2. **F114** — hub Connection refused can be transient; no faucet restart required for recovery.
3. **F45 lag cliff** — lag~1479 vs ckpt 5290; Path A republish urgent for JOIN UX.
4. **F95** — ~15m cooldown still paces many waves.
5. Continuous `[skip ci]` docs on main after each wave.

## Next

wave110+ after wipe#3 resync; Path A republish (lane 7); human SUMMARY when invite window opens.
