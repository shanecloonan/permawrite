# Live testnet permanence density — session findings waves 80–92 (2026-07-22)

**Lane:** 3 · public-devnet-v1 · observer wiped once after wave80 F107

## Scorecard

| Wave | Wallet | Result | last_proven | Fund | Notes |
| --- | --- | --- | --- | --- | --- |
| 80 | zara | **PROVE FAIL** | — | faucet-F101b | F107 → wipe |
| 81–90 | aster…juno | **PASS** x10 | 5972–6070 | mostly faucet-F101b | F95 on 83/85/87 |
| 91 | kade | **PASS** | 6083 | faucet-F101b | |
| 92 | luna | **PASS** | 6094 | faucet-F101b | lag=794 |

**JOIN:** 54 → **66** proxy-proven · tip~6094 · ckpt 5290 · F45 lag **794** · post-wipe streak **x12**

## Highest-signal findings

1. **F107/F108** — sticky local_only+mem=1 is the density breaker; wipe+resync restored a 12-wave PASS streak.
2. **F95** — 429 on 83/85/87; 600s retry works; recent waves avoided cooldown.
3. **F45** — lag 658→794; Path A frozen at 5290; soft JOIN mandatory; approaching lag 800.
4. **F110/F101b** — dominant tall-tip fund path; zero bal TIMEOUTs post-wipe.
5. Docs pushed `[skip ci]` after each wave to main.

## Next

wave93+ density; lane7 Path A republish; human SUMMARY when invite window opens.
