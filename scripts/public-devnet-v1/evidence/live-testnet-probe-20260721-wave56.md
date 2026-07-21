# Live public testnet probe - wave 56 findings (2026-07-21)

**Lane:** 3 (onboarding / B-15)
**UTC window:** ~01:18Z-01:36Z (~17 min)
**Prior:** wave55 wren last_proven=4785
**Tip close:** **4794** (matched)
**Mode:** **faucet** first try (no 429); **permanence_public PASS**

## Executive verdict

| Gate | Result |
| --- | --- |
| Faucet xavier | **PASS** ~125s dual-send |
| Pin → owned=2 | **PASS** @4629 |
| Upload Fresh | **PASS** `7121030f` |
| Public prove | **PASS** last_proven=**4794** |
| Claims | **30 → 31** |
| F45 lag | **107** (ckpt 4679) TIMEOUT |
| **permanence_public** | **PASS** |

## Notes

- Back-to-back faucet success after wave55 (cooldown edge / elapsed ~15m from wren fund).
- F45 lag crossed **100** (107) — Path A republish is now a hard JOIN blocker for any `--checkpoint-log` path.
- Two consecutive clean faucet PASSes (wren→xavier) on post-wipe observer.

## Permanence board (newest)

| Commitment | Wallet | last_proven | Fund |
| --- | --- | --- | --- |
| `7121030f` | **xavier** | **4794** | faucet |
| `a88d7bcb` | wren | 4785 | faucet |
| `aefcaf80` | viv | 4763 | faucet-retry |

**JOIN scorecard:** thirty-four proxy-proven wallets.

## Artifacts

- `_wave56-results.json`, `_wave56-xavier-upload.json`, `user-wallet/xavier.json`

