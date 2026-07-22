# Live public testnet probe - wave 64 findings (2026-07-22) — permanence PASS

**Lane:** 3 (onboarding / B-15)
**UTC window:** ~09:56Z–10:22Z (~26 min wall)
**Prior:** wave63 ella last_proven=5761
**Tip close:** **5775** (matched)
**Mode:** F110 + faucet-F101b → proxy-prove; **permanence_public PASS**

## Executive verdict

| Gate | Result |
| --- | --- |
| Faucet | done ~280s (280007ms) — slower end of F109 band |
| F110 / F101b | **PASS** (timeouts=None) |
| Upload + prove | **PASS** last_proven=**5775** `da677677` |
| Claims | **37 → 38** |
| F45 lag | **472** (ckpt 5290) |
| **permanence_public** | **PASS** |

## Findings

### F110 streak — fourth consecutive PASS after wave60 control

cleo/devon/ella/finn all PASS with near-tip runner. Faucet duration variance now observed: ~181s (blake) to ~280s (finn). Still under 500s poll budget.

### F45 lag **472** — still climbing

Path A 5290 vs tip ~5775. Soft JOIN mandatory.

## Permanence board (newest)

| Commitment | Wallet | last_proven | Fund |
| --- | --- | --- | --- |
| `da677677` | **finn** | **5775** | faucet-F101b |
| `8f9142a9` | ella | 5761 | faucet-F101b |
| `f00298cc` | devon | 5751 | faucet-F101b |
| `b066b4bd` | cleo | 5741 | faucet-F101b |
| `e40023df` | blake | 5729 | faucet-F101b |

**JOIN scorecard:** forty-one proxy-proven wallets.

## Artifacts

- `_wave64-results.json` (gitignored); this markdown

## Follow-up

- Wave65+ density; Path A republish when lag allows.

