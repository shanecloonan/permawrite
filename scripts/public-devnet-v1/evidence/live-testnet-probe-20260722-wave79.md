# Live public testnet probe - wave 79 findings (2026-07-22) — permanence PASS

**Lane:** 3 (onboarding / B-15)
**UTC window:** ~15:38Z–16:07Z (~29 min)
**Prior:** wave78 wynn last_proven=5932
**Tip close:** **5947**
**Mode:** faucet-retry-F101b; **permanence_public PASS**

## Executive verdict

| Gate | Result |
| --- | --- |
| Faucet | 429 then retry ~187s |
| Fund mode | `faucet-retry-F101b` |
| Upload + prove | **PASS** last_proven=**5947** `f27142c1` |
| Claims | **50 → 51** |
| F45 lag | **643** (ckpt 5290) |
| **permanence_public** | **PASS** |

## Findings

### Session arc (waves 76–79)

| Wave | Wallet | Result | Notes |
| --- | --- | --- | --- |
| 76 | troy | UPLOAD FAIL | F112 --mestroy tooling |
| 77 | vela | PASS @5923 | F112 fix + F95 retry |
| 78 | wynn | PASS @5932 | clean F110 |
| 79 | yukon | PASS @5947 | faucet-retry-F101b |

### F45 lag **643**

Soft JOIN only; Path A 5290.

## Permanence board (newest)

| Commitment | Wallet | last_proven | Fund |
| --- | --- | --- | --- |
| `f27142c1` | **yukon** | **5947** | faucet-retry-F101b |
| `7134e91b` | wynn | 5932 | faucet-F101b |
| `ef6cc45c` | vela | 5923 | faucet-retry-F101b |

**JOIN scorecard:** fifty-four proxy-proven wallets.

## Artifacts

- this markdown

