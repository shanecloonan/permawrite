# Live public testnet probe - wave 92 findings (2026-07-22) — permanence PASS

**Lane:** 3 (onboarding / B-15)
**UTC window:** open `2026-07-22T20:40Z` → close ~21:02Z (~22 min)
**Prior:** wave91 kade last_proven=6083
**Tip close:** **6094** (matched)
**Mode:** faucet-F101b; **permanence_public PASS**

## Executive verdict

| Gate | Result |
| --- | --- |
| Faucet | **done** |
| F110 / F101b | **PASS** |
| Upload + prove | **PASS** last_proven=**6094** `db928bea` |
| Claims | **62 → 63** |
| F45 lag | **794** (ckpt 5290; approaching 800) |
| **permanence_public** | **PASS** |

## Findings

### Post-wipe streak x12 (waves 81–92)

Twelve consecutive permanence PASSes after wave80 F107 wipe. Tip ~5972→6094. F45 lag **794** — Path A republish increasingly urgent.

### Session arc (waves 89–92)

| Wave | Wallet | Result | last_proven | Notes |
| --- | --- | --- | --- | --- |
| 89 | iota | PASS | 6060 | F110 |
| 90 | juno | PASS | 6070 | wave90 milestone |
| 91 | kade | PASS | 6083 | F110 |
| 92 | luna | PASS | 6094 | F110; lag=794 |

## Permanence board (newest)

| Commitment | Wallet | last_proven | Fund |
| --- | --- | --- | --- |
| `db928bea` | **luna** | **6094** | faucet-F101b |
| (kade) | kade | 6083 | faucet-F101b |
| `f1ee38e1` | juno | 6070 | faucet-F101b |

**JOIN scorecard:** sixty-six proxy-proven wallets.

## Artifacts

- this markdown
