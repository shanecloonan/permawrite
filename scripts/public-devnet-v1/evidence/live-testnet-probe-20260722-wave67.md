# Live public testnet probe - wave 67 findings (2026-07-22) — permanence PASS

**Lane:** 3 (onboarding / B-15)
**UTC window:** ~11:14Z–11:34Z (~20 min wall)
**Prior:** wave66 hugo last_proven=5800 (F95 429 path)
**Tip close:** **5810** (matched)
**Mode:** F110 + faucet-F101b (no 429 — cooldown cleared); **permanence_public PASS**

## Executive verdict

| Gate | Result |
| --- | --- |
| Faucet | **done** first try ~202s (no F95) |
| F110 / F101b | **PASS** (timeouts=None) |
| Upload + prove | **PASS** last_proven=**5810** `f1e786b4` |
| Claims | **40 → 41** |
| F45 lag | **511** (ckpt 5290) — crossed 500 |
| **permanence_public** | **PASS** |

## Findings

### F95 spacing works

Wave66 burned the IP cooldown; wave67 (~2 min after hugo close docs landed, ~15+ min after hugo faucet-retry done) got a clean first-try faucet. Density schedule: either wait >=15m after faucet success or budget F95+600s.

### F45 lag **511** — new honesty watermark

First wave with lag >500. Hard checkpoint-log still TIMEOUT. Soft JOIN remains the only viable bootstrap. Path A republish urgency increases.

### F110 streak continues

hugo (retry) + ivy (clean) both zero bal TIMEOUT. Tall-tip recipe stable.

## Permanence board (newest)

| Commitment | Wallet | last_proven | Fund |
| --- | --- | --- | --- |
| `f1e786b4` | **ivy** | **5810** | faucet-F101b |
| `a9ae8fec` | hugo | 5800 | faucet-retry-F101b |
| `5a47083c` | gwen | 5784 | faucet-F101b |

**JOIN scorecard:** forty-four proxy-proven wallets.

## Artifacts

- `_wave67-results.json` (gitignored); this markdown

## Follow-up

- Wave68+; expect F95 if started immediately; Path A republish for F45.

