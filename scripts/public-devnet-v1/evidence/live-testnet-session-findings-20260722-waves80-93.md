# Live testnet permanence density — session findings waves 80–93 (2026-07-22)

**Lane:** 3 · public-devnet-v1 · observer wiped once after wave80 F107

## Scorecard (this continuation)

| Wave | Wallet | Result | last_proven | Fund | Notes |
| --- | --- | --- | --- | --- | --- |
| 80 | zara | **PROVE FAIL** | — | faucet-F101b | F107 → wipe |
| 81–92 | aster…luna | **PASS** x12 | 5972–6094 | faucet-F101b (+F95 x3) | post-wipe streak |
| 93 | moss | **PASS** | 6104 | faucet-F101b | **F45 lag>805** |

**JOIN:** 54 → **67** proxy-proven · tip~6104 · ckpt 5290 · F45 lag **805** · post-wipe streak **x13**

## Highest-signal findings

1. **F107/F108** — sticky local_only+mem=1 broke wave80; wipe restored 13-wave PASS streak.
2. **F45 critical** — lag crossed **800** (805); Path A still 5290; hard checkpoint-log JOIN blocked.
3. **F95** — 429 on 83/85/87 earlier; recent waves clean.
4. **F110/F101b** — standing tall-tip fund recipe; no bal TIMEOUTs post-wipe.
5. Docs on main `[skip ci]` after each wave.

## Next

wave94+; lane7 Path A republish urgently; human SUMMARY when invite window opens.
