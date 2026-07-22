# Live public testnet probe - wave 91 findings (2026-07-22) — permanence PASS

**Lane:** 3 (onboarding / B-15)
**UTC window:** open `2026-07-22T20:15Z` → close ~20:40Z (~25 min)
**Prior:** wave90 juno last_proven=6070
**Tip close:** **6083** (matched)
**Mode:** faucet-F101b; **permanence_public PASS**

## Executive verdict

| Gate | Result |
| --- | --- |
| Faucet | **done** |
| F110 / F101b | **PASS** |
| Upload + prove | **PASS** last_proven=**6083** `eafc2346` |
| Claims | **61 → 62** |
| F45 lag | **781** (ckpt 5290) |
| **permanence_public** | **PASS** |

## Findings

### Post-wipe streak x11 (waves 81–91)

Eleven consecutive permanence PASSes after wave80 F107 wipe. F45 lag **781** — Path A still frozen at 5290; soft JOIN only.

### Session arc (waves 89–91)

| Wave | Wallet | Result | last_proven | Notes |
| --- | --- | --- | --- | --- |
| 89 | iota | PASS | 6060 | F110 |
| 90 | juno | PASS | 6070 | wave90 milestone |
| 91 | kade | PASS | 6083 | F110; lag=781 |

## Permanence board (newest)

| Commitment | Wallet | last_proven | Fund |
| --- | --- | --- | --- |
| `eafc2346` | **kade** | **6083** | faucet-F101b |
| `f1ee38e1` | juno | 6070 | faucet-F101b |
| `662d06b9` | iota | 6060 | faucet-F101b |

**JOIN scorecard:** sixty-five proxy-proven wallets.

## Artifacts

- this markdown
- see `live-testnet-session-findings-20260722-waves80-90.md`
