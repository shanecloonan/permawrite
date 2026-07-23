# Live testnet permanence density — session findings waves 100–103 (2026-07-23)

**Lane:** 3 · public-devnet-v1

## Scorecard

| Wave | Wallet | Result | last_proven | Fund | Notes |
| --- | --- | --- | --- | --- | --- |
| 100 | tessa | **PASS** | 6621 | faucet-retry-F101b | **wave100 milestone**; F95 |
| 101 | uma | **FAIL** | — | faucet-retry-F101b | **F107** sticky mem=1 → wipe |
| 102 | vera | **PASS** | 6652 | faucet-F101b | post-wipe recovery (~6 min resync) |
| 103 | wade | **PASS** | 6662 | faucet-F101b | post-wipe streak x2 |

**JOIN:** 74 → **76** proxy-proven (uma FAIL no increment) · tip~6662 · ckpt 5290 · F45 lag **1363**

## Highest-signal findings

1. **Wave 100 milestone** then immediate **F107** on wave101 — 20-wave streak is not immortality; sticky mem=1 still forces wipe.
2. **F107 wipe recovers** — wave102 PASS on fresh `b15-fresh` after tip_id match; F108 (restart-only) still insufficient.
3. **F45 lag cliff** — 1318→1363; Path A republish (lane 7) remains urgent for JOIN UX.
4. **F95** — paced wave100/101; waves 102–103 clean faucet.
5. Docs pushed `[skip ci]` per wave; honor §6 (no faucet restart / no parallel Hetzner JOIN).

## Next

wave104+ density; Path A republish; human SUMMARY when invite window opens.
