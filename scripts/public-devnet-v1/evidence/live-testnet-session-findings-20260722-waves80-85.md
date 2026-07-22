# Live testnet permanence density — session findings waves 80–85 (2026-07-22)

**Lane:** 3 (B-15 outside-in)
**Network:** public-devnet-v1 · seeds `5.161.201.73:19001–19003` · proxy `:8787/rpc` · faucet `:8788`
**Observer:** local `mfnd` `127.0.0.1:18734` · wiped once mid-session (`live-testnet-data-divergent-20260722-112926`)

## Scorecard

| Wave | Wallet | Result | last_proven | Fund | Notes | Docs commit |
| --- | --- | --- | --- | --- | --- | --- |
| 80 | zara | **PROVE FAIL** | — | faucet-F101b | F107 sticky mem=1 | `96111f61` |
| 81 | aster | **PASS** | 5972 | faucet-F101b | F108 wipe recovery | `9a118a77` |
| 82 | brynn | **PASS** | 5982 | faucet-F101b | clean F110 | `2a2c00a2` |
| 83 | coral | **PASS** | 5993 | faucet-F101b | F95 429+600s | `c2cdc1fe` |
| 84 | dante | **PASS** | 6002 | faucet-F101b | F45 lag crossed 700 | (wave84 push) |
| 85 | eden | **PASS** | 6017 | faucet-retry-F101b | F95 again | this |

**JOIN scorecard:** 54 → **59** proxy-proven (zara excluded).
**Tip / Path A:** tip~6017 · ckpt=**5290** · F45 lag=**713**.

## Highest-signal findings

1. **F107 still real:** wave80 Fresh upload never public-proven; local mem=1 sticky while proxy mem=0.
2. **F108 wipe works:** quarantine data dir + seed resync (~6.5 min) restored permanence for waves 81–85 (5/5 PASS).
3. **F95 pacing:** waves 83 + 85 hit HTTP 429; 600s retry is mandatory for dense faucet loops.
4. **F45 lag critical:** 658 → 713 with Path A frozen at 5290; hard checkpoint-log JOIN still blocked.
5. **F110/F101b dominant:** every PASS used near-tip pins + owned=1 early exit + re-pin to owned=2.
6. **Healthy vs sticky local_only:** transient mem=1 after Fresh (~2 min) is OK; full-budget sticky is wipe-worthy.

## Ops hygiene held

- No Hetzner parallel JOIN / no faucet-http restart (§6).
- No F112 `--message` corruption (explicit token-map runners).
- Wallets / live-testnet-data* / other-lane dirty not staged.

