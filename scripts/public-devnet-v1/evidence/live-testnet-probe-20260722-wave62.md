# Live public testnet probe - wave 62 findings (2026-07-22) — permanence PASS

**Lane:** 3 (onboarding / B-15)
**UTC window:** ~09:14Z–09:34Z (~20 min wall)
**Prior:** wave61 cleo last_proven=5741 (F110 validated)
**Tip close:** **5751** (matched)
**Mode:** F110 + faucet-F101b → proxy-prove; **permanence_public PASS**

## Executive verdict

| Gate | Result |
| --- | --- |
| Faucet | done ~201s (200660ms) |
| F110 early exit on owned=1 | **PASS** (no deep pins; timeouts=None) |
| F101b round 0 | **PASS** owned=2 |
| Upload + prove | **PASS** last_proven=**5751** `f00298cc` |
| Claims | **35 → 36** |
| F45 lag | **452** (ckpt 5290) |
| **permanence_public** | **PASS** |

## Findings

### F110 streak — second consecutive fast permanence

Wave61 (~22 min) and wave62 (~20 min) both completed faucet→prove with zero balance TIMEOUTs using near-tip ladder + early F101b. Wave60 (~43 min) remains the control case for deep-pin waste.

### F101b remains the dominant fund path

Four of five recent successes (yuki/zion/blake/cleo/devon) used faucet-F101b. Operators should budget one tip wait after first owned=1 sighting.

### F45 lag still open at **452**

Path A at 5290; tip advancing ~5740+. Soft JOIN only.

## Permanence board (newest)

| Commitment | Wallet | last_proven | Fund |
| --- | --- | --- | --- |
| `f00298cc` | **devon** | **5751** | faucet-F101b |
| `b066b4bd` | cleo | 5741 | faucet-F101b |
| `e40023df` | blake | 5729 | faucet-F101b |

**JOIN scorecard:** thirty-nine proxy-proven wallets.

## Artifacts

- `_wave62-results.json`, `_wave62-devon-upload.json` (gitignored)
- this markdown

## Follow-up

- Wave63+ density; Path A republish when lag allows.

