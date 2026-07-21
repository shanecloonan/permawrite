# Live public testnet probe - wave 57 findings (2026-07-21)

**Lane:** 3 (onboarding / B-15)
**UTC window:** ~01:36Z-02:03Z (~27 min)
**Prior:** wave56 xavier last_proven=4794
**Tip close:** **4808** (matched)
**Mode:** faucet → **F101b re-pin** (1 round); fund_mode=`faucet-F101b`; **permanence_public PASS**

## Executive verdict

| Gate | Result |
| --- | --- |
| Faucet yuki | job done (first try) |
| Immediate pin ladder | owned<2 (F101b trigger) |
| F101b re-pin round 0 | **PASS** owned=2 / 1M |
| Upload Fresh | **PASS** `99b7e801` @4806 |
| Public prove | **PASS** last_proven=**4808** |
| Claims | **31 → 32** |
| F45 lag | **116** (ckpt 4679) |
| **permanence_public** | **PASS** |

## Finding: F101b runner path proven end-to-end

Wave51 discovered delayed second faucet UTXO; wave52+ armed an explicit F101b loop. Wave57 is the first run that **used** that loop with correct fund_mode labeling (`faucet-F101b`, f101b_rounds=1) rather than mislabeling as peer-dual-donor.

**JOIN implication:** after faucet `done`, if first pin ladder shows owned=1, wait tip + re-pin near-tip heights before failing fund.

## Permanence board (newest)

| Commitment | Wallet | last_proven | Fund |
| --- | --- | --- | --- |
| `99b7e801` | **yuki** | **4808** | faucet-F101b |
| `7121030f` | xavier | 4794 | faucet |
| `a88d7bcb` | wren | 4785 | faucet |

**JOIN scorecard:** thirty-five proxy-proven wallets.

## Artifacts

- `_wave57-results.json`, `_wave57-yuki-upload.json`, `user-wallet/yuki.json`

