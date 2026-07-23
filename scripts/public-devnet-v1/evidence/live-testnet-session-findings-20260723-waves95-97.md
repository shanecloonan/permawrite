# Live testnet permanence density — session findings waves 95–97 (2026-07-22/23)

**Lane:** 3 · public-devnet-v1

## Scorecard

| Wave | Wallet | Result | last_proven | Fund | Notes |
| --- | --- | --- | --- | --- | --- |
| 95 | orin | **PASS** | 6128 | faucet-retry-F101b | F95 |
| 96 | pax | **PASS** | 6141 | faucet-retry-F101b | F95; lag=838 |
| 97a | quill | **INTERRUPTED** | — | partial F101b | overnight session kill tip~6151 |
| 97b | quill | **PASS** | 6586 | faucet-F101b | F113 recover; lag=1286 |

**JOIN:** 68 → **71** proxy-proven · tip~6586 · ckpt 5290 · F45 lag **1286**

## Highest-signal findings

1. **F45 overnight cliff** — lag 838→1286 when density pauses while chain advances and Path A stays at 5290.
2. **F113** — tall-tip `get_light_snapshot` needs ≥300s + retry; hung snapshot can wedge local RPC until mfnd restart (data dir keep OK if not F107).
3. **F95** — still paces dense loops (95–96); wave97 funded clean after spacing.
4. **Upload tip-slip** — recoverable with short re-wait; distinct from F107 sticky mem=1.
5. Docs on main `[skip ci]` including ops resume note `7ba87202`.

## Next

wave98+; lane7 Path A republish urgently; human SUMMARY when invite window opens.
