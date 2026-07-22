# Live public testnet probe - wave 71 findings (2026-07-22) — permanence PASS

**Lane:** 3 (onboarding / B-15)
**UTC window:** ~12:38Z–12:59Z (~21 min)
**Prior:** wave70 lena last_proven=5842
**Tip close:** **5853** (matched)
**Mode:** F110 + faucet-F101b; **permanence_public PASS**

## Executive verdict

| Gate | Result |
| --- | --- |
| Observer tip match | **PASS**; mem=0; peer_count=3 |
| Faucet | **done** first try ~196s (195842ms) |
| F110 / F101b | **PASS** (timeouts=None; early owned=1) |
| Upload + prove | **PASS** last_proven=**5853** `4e9c8758` |
| Claims | **44 → 45** |
| F45 lag | **553** (ckpt 5290) |
| **permanence_public** | **PASS** |

## Findings

### F110 streak continues at tip~5850

Clean first-try faucet (no F95). Near-tip ladder + F101b round 0 → owned=2. Zero bal TIMEOUTs. Tall-tip JOIN recipe remains stable after waves 60–70.

### F45 lag **553** — Path A 5290 still frozen

Hard checkpoint-log TIMEOUT 60s. Soft JOIN mandatory. Lag has climbed ~553 from wave70's 544; Path A republish increasingly urgent for operator UX.

### Prove-gate honesty

Same F100/F105 pattern expected: local last_proven can precede proxy_has; gate waited for tip_id match + proxy list.

## Permanence board (newest)

| Commitment | Wallet | last_proven | Fund |
| --- | --- | --- | --- |
| `4e9c8758` | **mira** | **5853** | faucet-F101b |
| `55cee933` | lena | 5842 | faucet-F101b |
| `7f6b2496` | kira | 5833 | faucet-F101b |
| `775fc539` | joss | 5819 | faucet-F101b |

**JOIN scorecard:** forty-eight proxy-proven wallets.

## Artifacts

- `_wave71-results.json` (gitignored); this markdown

## Follow-up

- Wave72+ density; Path A republish for F45.

