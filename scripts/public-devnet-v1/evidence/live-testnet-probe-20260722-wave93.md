# Live public testnet probe - wave 93 findings (2026-07-22) — permanence PASS

**Lane:** 3 (onboarding / B-15)
**UTC window:** open `2026-07-22T21:03Z` → close ~21:22Z (~20 min)
**Prior:** wave92 luna last_proven=6094
**Tip close:** **6104** (matched)
**Mode:** faucet-F101b; **permanence_public PASS**

## Executive verdict

| Gate | Result |
| --- | --- |
| Faucet | **done** |
| F110 / F101b | **PASS** |
| Upload + prove | **PASS** last_proven=**6104** `4c7096c6` |
| Claims | **63 → 64** |
| F45 lag | **805** (**>800**; ckpt 5290) |
| **permanence_public** | **PASS** |

## Findings

### F45 lag crossed **800**

Hard `--checkpoint-log` remains unusable. Soft JOIN / near-tip pins only. Path A republish (lane 7) is now a hard JOIN UX unblock — lag has more than doubled since tip-5290 Path A land.

### Post-wipe streak x13 (waves 81–93)

Thirteen consecutive permanence PASSes after wave80 F107 wipe.

### Session arc (waves 89–93)

| Wave | Wallet | Result | last_proven | Notes |
| --- | --- | --- | --- | --- |
| 89 | iota | PASS | 6060 | F110 |
| 90 | juno | PASS | 6070 | wave90 milestone |
| 91 | kade | PASS | 6083 | F110 |
| 92 | luna | PASS | 6094 | lag~794 |
| 93 | moss | PASS | 6104 | lag=805 (>800) |

## Permanence board (newest)

| Commitment | Wallet | last_proven | Fund |
| --- | --- | --- | --- |
| `4c7096c6` | **moss** | **6104** | faucet-F101b |
| (luna) | luna | 6094 | faucet-F101b |
| (kade) | kade | 6083 | faucet-F101b |

**JOIN scorecard:** sixty-seven proxy-proven wallets.

## Artifacts

- this markdown
