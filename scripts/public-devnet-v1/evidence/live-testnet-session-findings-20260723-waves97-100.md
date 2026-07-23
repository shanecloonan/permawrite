# Live testnet permanence density — session findings waves 97–100 (2026-07-23)

**Lane:** 3 · public-devnet-v1 · observer restarted once (F113; no wipe)

## Scorecard

| Wave | Wallet | Result | last_proven | Fund | Notes |
| --- | --- | --- | --- | --- | --- |
| 97 | quill | **PASS** | 6586 | faucet-F101b | F113 resume after overnight interrupt |
| 98 | riven | **PASS** | 6599 | faucet-F101b | |
| 99 | soren | **PASS** | 6607 | faucet-F101b | |
| 100 | tessa | **PASS** | 6621 | faucet-retry-F101b | **wave100 milestone**; F95 |

**JOIN:** 70 → **74** proxy-proven · tip~6621 · ckpt 5290 · F45 lag **1318** · post-wipe streak **x20** (81–100)

## Highest-signal findings

1. **Wave 100 milestone** — 100 outside-in permanence probes; recipe stable at tip~66xx.
2. **F45 overnight cliff** — lag 838→1318 after idle night with Path A frozen at 5290; Path A republish is a hard JOIN UX unblock.
3. **F113** — tall-tip `get_light_snapshot` needs ≥300s+retry; hung snapshot can wedge RPC until mfnd restart (data-dir keep OK if not F107).
4. **F95** — still paces dense loops (wave100 hit 429).
5. **F110/F101b** — standing tall-tip fund path; tip-slip at upload recoverable.
6. Docs pushed to main `[skip ci]` after each wave + ops resume note.

## Next

wave101+ density; lane7 Path A republish urgently; human SUMMARY when invite window opens.
