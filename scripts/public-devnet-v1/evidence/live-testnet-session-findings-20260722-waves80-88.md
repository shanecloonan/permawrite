# Live testnet permanence density — session findings waves 80–88 (2026-07-22)

**Lane:** 3 · public-devnet-v1 · observer wiped once after wave80 F107

## Scorecard

| Wave | Wallet | Result | last_proven | Fund | Notes |
| --- | --- | --- | --- | --- | --- |
| 80 | zara | **PROVE FAIL** | — | faucet-F101b | F107 → wipe |
| 81 | aster | **PASS** | 5972 | faucet-F101b | F108 recovery |
| 82 | brynn | **PASS** | 5982 | faucet-F101b | |
| 83 | coral | **PASS** | 5993 | faucet-F101b | F95 |
| 84 | dante | **PASS** | 6002 | faucet-F101b | lag>700 |
| 85 | eden | **PASS** | 6017 | faucet-retry-F101b | F95 |
| 86 | felix | **PASS** | 6026 | faucet-F101b | |
| 87 | gryph | **PASS** | 6040 | faucet-retry | F95 |
| 88 | haven | **PASS** | 6050 | faucet-F101b | lag=751 |

**JOIN:** 54 → **62** proxy-proven · tip~6050 · ckpt 5290 · F45 lag **751**

## Findings (compressed)

1. **F107/F108** — sticky local_only+mem=1 is the density breaker; wipe+resync restores multi-hour PASS streaks.
2. **F95** — 429 on waves 83/85/87; 600s retry works.
3. **F45** — lag 658→751; Path A frozen at 5290; soft JOIN mandatory.
4. **F110/F101b** — dominant successful fund path at tall tip.
5. Docs pushed to main `[skip ci]` after each wave.

## Next

wave89+ density; lane7 Path A republish; human SUMMARY when invite window opens.
