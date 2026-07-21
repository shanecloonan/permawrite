# Live public testnet probe - wave 58 findings (2026-07-21)

**Lane:** 3 (onboarding / B-15)
**UTC window:** ~02:04Z-02:33Z (~29 min)
**Prior:** wave57 yuki last_proven=4808
**Tip close:** **4823** (matched)
**Mode:** faucet → F101b re-pin; **permanence_public PASS**

## Executive verdict

| Gate | Result |
| --- | --- |
| Faucet zion | done first try |
| F101b re-pin | **PASS** rounds=1 → owned=2 |
| Upload + prove | **PASS** last_proven=**4823** (`54887d55`) |
| Claims | **32 → 33** |
| F45 lag | **130** (ckpt 4679 still frozen) |
| **permanence_public** | **PASS** |

## Notes

- Second consecutive `faucet-F101b` PASS (yuki→zion) — delayed second UTXO is now a common path, not a one-off.
- F45 lag **130** and still climbing; soft JOIN only.
- Four-wave faucet streak (wren/xavier/yuki/zion) without wipe.

## Permanence board (newest)

| Commitment | Wallet | last_proven | Fund |
| --- | --- | --- | --- |
| `54887d55` | **zion** | **4823** | faucet-F101b |
| `99b7e801` | yuki | 4808 | faucet-F101b |
| `7121030f` | xavier | 4794 | faucet |

**JOIN scorecard:** thirty-six proxy-proven wallets.

## Artifacts

- `_wave58-results.json`, `_wave58-zion-upload.json`, `user-wallet/zion.json`

