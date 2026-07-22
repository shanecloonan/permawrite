# Live public testnet probe - wave 94 findings (2026-07-22) — permanence PASS

**Lane:** 3 (onboarding / B-15)
**UTC window:** open `2026-07-22T21:23Z` → close ~21:40Z (~18 min)
**Prior:** wave93 moss last_proven=6104
**Tip close:** **6113** (matched)
**Mode:** faucet-F101b; **permanence_public PASS**

## Executive verdict

| Gate | Result |
| --- | --- |
| Faucet | **done** |
| F110 / F101b | **PASS** |
| Upload + prove | **PASS** last_proven=**6113** `dae77944` |
| Claims | **64 → 65** |
| F45 lag | **815** (ckpt 5290) |
| **permanence_public** | **PASS** |

## Findings

### Post-wipe streak x14 (waves 81–94)

Fourteen consecutive permanence PASSes after wave80 F107 wipe. Tip ~5972→6113. F45 lag **815** (>800).

### Session arc (waves 89–94)

| Wave | Wallet | Result | last_proven | Notes |
| --- | --- | --- | --- | --- |
| 89 | iota | PASS | 6060 | F110 |
| 90 | juno | PASS | 6070 | wave90 milestone |
| 91 | kade | PASS | 6083 | F110 |
| 92 | luna | PASS | 6094 | |
| 93 | moss | PASS | 6104 | lag>800 |
| 94 | nash | PASS | 6113 | lag=815 |

## Permanence board (newest)

| Commitment | Wallet | last_proven | Fund |
| --- | --- | --- | --- |
| `dae77944` | **nash** | **6113** | faucet-F101b |
| (moss) | moss | 6104 | faucet-F101b |
| (luna) | luna | 6094 | faucet-F101b |

**JOIN scorecard:** sixty-eight proxy-proven wallets.

## Artifacts

- this markdown
- `live-testnet-session-findings-20260722-waves80-93.md`
