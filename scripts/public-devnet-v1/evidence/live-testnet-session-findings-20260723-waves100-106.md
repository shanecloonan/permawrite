# Live testnet permanence density — session findings waves 100–106 (2026-07-23)

## Scorecard

| Wave | Wallet | Result | last_proven | Notes |
| --- | --- | --- | --- | --- |
| 100 | tessa | PASS | 6621 | milestone; F95 |
| 101 | uma | FAIL F107 | — | wipe #1 |
| 102 | vera | PASS | 6652 | post-wipe |
| 103 | wade | PASS | 6662 | |
| 104 | xan | PASS | 6678 | F95 |
| 105 | yara | FAIL F107 | — | wipe #2 (streak only x3) |
| 106 | zeke | FAIL F114 | — | faucet hub ECONNREFUSED 111; peer donors dry |

**JOIN:** 74 → **77** · tip~6745 · F45 lag **1403** · ckpt 5290 · 2× F107 wipes + 1× F114 fund break

## Highest-signal findings

1. **F107 recurrence variable** — x20 then x3 post-wipe streaks before sticky mem=1.
2. **F114** — faucet job can fail with hub Connection refused (111) even when HTTP /faucet accepts; not F95.
3. **F45 lag cliff** — lag~1403; Path A republish still urgent (lane 7).
4. **Peer fallback brittle** after density (donors owned=1 / TIMEOUT).
5. Docs pushed `[skip ci]` continuously; §6 honored (no faucet restart).

## Next

Re-probe faucet/hub; wave107+ if fund path healthy; Path A republish; escalate F114 to lane 7 if 111 persists.
