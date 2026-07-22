# Live public testnet probe - wave 77 findings (2026-07-22) — permanence PASS

**Lane:** 3 (onboarding / B-15)
**UTC window:** ~14:50Z–15:19Z (~29 min; F95 600s + faucet)
**Prior:** wave76 troy UPLOAD FAIL (F112 --mestroy)
**Tip close:** **5923** (matched)
**Mode:** fixed runner + F95 retry-F101b; **permanence_public PASS**

## Executive verdict

| Gate | Result |
| --- | --- |
| Runner | rebuilt from wave74 with token replace (preserves `--message`) |
| Faucet first POST | **429** (post-troy fund cooldown) |
| F95 wait + retry | **done** ~200s |
| F110 / F101b | **PASS** |
| Upload + prove | **PASS** last_proven=**5923** `ef6cc45c` (upload rc=0) |
| Claims | **48 → 49** |
| F45 lag | **619** (ckpt 5290) |
| **permanence_public** | **PASS** |

## Findings

### F112 fix validated

Wave76 failed because `sage` substring corrupted `--message`. Wave77 runner rebuilt with explicit token map from wave74; upload accepted `--message wave77-vela-authorship` and permanence completed. Cloning rule: never global-replace short wallet name fragments.

### F95 after failed wave still applies

Troy's successful faucet (even though upload failed) burned the IP cooldown; vela needed 600s wait.

### F45 lag **619**

Soft JOIN only; Path A 5290.

## Permanence board (newest)

| Commitment | Wallet | last_proven | Fund |
| --- | --- | --- | --- |
| `ef6cc45c` | **vela** | **5923** | faucet-retry-F101b |
| `32e7ab2e` | sage | 5901 | faucet-retry-F101b |
| `480340e7` | reed | 5886 | faucet-F101b |

**JOIN scorecard:** fifty-two proxy-proven wallets.

## Artifacts

- this markdown; `_wave77-results.json` gitignored

