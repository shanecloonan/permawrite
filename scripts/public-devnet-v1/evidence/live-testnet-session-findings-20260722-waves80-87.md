# Live testnet permanence density — session findings waves 80–87 (2026-07-22)

**Lane:** 3 (B-15 outside-in)
**Network:** public-devnet-v1 · seeds `5.161.201.73:19001–19003` · proxy `:8787/rpc` · faucet `:8788`
**Observer:** wiped once (`live-testnet-data-divergent-20260722-112926`) after wave80 F107

## Scorecard

| Wave | Wallet | Result | last_proven | Fund | Notes |
| --- | --- | --- | --- | --- | --- |
| 80 | zara | **PROVE FAIL** | — | faucet-F101b | F107 sticky mem=1 → wipe |
| 81 | aster | **PASS** | 5972 | faucet-F101b | F108 recovery |
| 82 | brynn | **PASS** | 5982 | faucet-F101b | F110 |
| 83 | coral | **PASS** | 5993 | faucet-F101b | F95 |
| 84 | dante | **PASS** | 6002 | faucet-F101b | lag>700 |
| 85 | eden | **PASS** | 6017 | faucet-retry-F101b | F95 |
| 86 | felix | **PASS** | 6026 | faucet-F101b | F110 |
| 87 | gryph | **PASS** | 6040 | faucet-retry | F95 |

**JOIN scorecard:** 54 → **61** proxy-proven (zara excluded).
**Tip / Path A:** tip~6040 · ckpt=**5290** · F45 lag=**737**.

## Highest-signal findings

1. **F107/F108:** sticky local_only+mem=1 after Fresh upload is still the main density breaker; wipe+seed-resync (~6.5 min) restored a 7-wave PASS streak.
2. **F95:** HTTP 429 hit waves 83, 85, 87 — ~15m IP cooldown; 600s retry mandatory.
3. **F45:** lag 658→737 with Path A frozen at 5290; hard `--checkpoint-log` JOIN still blocked.
4. **F110/F101b:** near-tip pins + owned=1 early exit remain the reliable fund path.
5. **Healthy prove:** transient local_only (~2 min) normal; full-budget sticky = wipe.

## Ops hygiene

- Honored §6 (no Hetzner parallel JOIN / no faucet restart).
- No F112 `--message` corruption.
- Docs pushed to main with `[skip ci]` as each wave finished.
