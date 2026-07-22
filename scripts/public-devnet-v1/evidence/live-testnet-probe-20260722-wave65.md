# Live public testnet probe - wave 65 findings (2026-07-22) — permanence PASS

**Lane:** 3 (onboarding / B-15)
**UTC window:** ~10:22Z–10:40Z (~18–20 min)
**Prior:** wave64 finn last_proven=5775
**Tip close:** **5784** (matched)
**Mode:** F110 + faucet-F101b → proxy-prove; **permanence_public PASS**

## Executive verdict

| Gate | Result |
| --- | --- |
| Faucet | done ~205s |
| F110 / F101b | **PASS** (timeouts=None) |
| Upload + prove | **PASS** last_proven=**5784** `5a47083c` |
| Claims | **38 → 39** |
| F45 lag | **486** (ckpt 5290) |
| **permanence_public** | **PASS** |

## Session arc (waves 59–65)

| Wave | Wallet | Result | last_proven | Notes |
| --- | --- | --- | --- | --- |
| 59 | aria | FUND FAIL | n/a | F109/F99 tall-tip |
| 60 | blake | PASS | 5729 | F109 poll OK; F110 deep-pin waste (~43m) |
| 61 | cleo | PASS | 5741 | F110 validated (~22m; 0 TIMEOUT) |
| 62 | devon | PASS | 5751 | F110 streak |
| 63 | ella | PASS | 5761 | F110 streak |
| 64 | finn | PASS | 5775 | Faucet ~280s |
| 65 | gwen | PASS | 5784 | F110 streak x5 |

## Findings

### Tall-tip JOIN is green under F110

Five consecutive permanence PASSes after one FUND FAIL. Operator recipe locked:
faucet poll 100x5s; near-tip pins; early F101b on owned=1; tip_id+mempool=0 upload; tip_id+proxy_has prove.

### F45 lag **486** still the honesty gap

Hard checkpoint-log TIMEOUT; soft JOIN only until Path A republish.

## Permanence board (newest)

| Commitment | Wallet | last_proven | Fund |
| --- | --- | --- | --- |
| `5a47083c` | **gwen** | **5784** | faucet-F101b |
| `da677677` | finn | 5775 | faucet-F101b |
| `8f9142a9` | ella | 5761 | faucet-F101b |

**JOIN scorecard:** forty-two proxy-proven wallets.

## Artifacts

- this markdown; `_wave65-results.json` gitignored

