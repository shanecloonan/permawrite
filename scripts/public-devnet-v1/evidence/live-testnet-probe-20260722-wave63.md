# Live public testnet probe - wave 63 findings (2026-07-22) — permanence PASS

**Lane:** 3 (onboarding / B-15)
**UTC window:** ~09:36Z–09:54Z (~20 min wall)
**Prior:** wave62 devon last_proven=5751
**Tip close:** **5761** (matched)
**Mode:** F110 + faucet-F101b → proxy-prove; **permanence_public PASS**

## Executive verdict

| Gate | Result |
| --- | --- |
| Faucet | done ~252s (252135ms) |
| F110 / F101b | **PASS** (timeouts=None; early owned=1 exit) |
| Upload + prove | **PASS** last_proven=**5761** `8f9142a9` |
| Claims | **36 → 37** |
| F45 lag | **462** (ckpt 5290) |
| **permanence_public** | **PASS** |

## Findings

### F110 streak — third consecutive ~20 min permanence

blake (wave60, slow/deep pins) → cleo/devon/ella (wave61–63) all PASS with F110 runner. Tall-tip JOIN is operationally viable when:
1. Faucet poll ≥100×5s
2. Balance timeout ≥400s (rarely needed if near-tip only)
3. Near-tip pin ladder + early F101b on owned=1
4. Upload only on tip_id match + mempool=0
5. Prove gate requires tip match + proxy_has

### F45 lag **462** remains the top JOIN honesty gap

Hard checkpoint-log still TIMEOUT. Soft path is mandatory. Lane 7 Path A republish would shrink lag.

### Faucet duration variance

Ella faucet took ~252s (longer than blake ~181s / devon ~same band). Still well under 500s budget — F109 poll extension remains justified.

## Permanence board (newest)

| Commitment | Wallet | last_proven | Fund |
| --- | --- | --- | --- |
| `8f9142a9` | **ella** | **5761** | faucet-F101b |
| `f00298cc` | devon | 5751 | faucet-F101b |
| `b066b4bd` | cleo | 5741 | faucet-F101b |
| `e40023df` | blake | 5729 | faucet-F101b |

**JOIN scorecard:** forty proxy-proven wallets.

## Artifacts

- `_wave63-results.json`, `_wave63-ella-upload.json` (gitignored)
- this markdown

## Follow-up

- Wave64+ density; keep F110 runner; honor §6.

