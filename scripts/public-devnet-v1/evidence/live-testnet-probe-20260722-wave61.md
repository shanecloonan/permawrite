# Live public testnet probe - wave 61 findings (2026-07-22) — permanence PASS

**Lane:** 3 (onboarding / B-15)
**UTC window:** ~08:54Z–09:14Z (~22 min wall; ~1300s runner)
**Prior:** wave60 blake last_proven=5729; F110 deep-pin waste identified
**Tip close:** **5741** (tip_id matched; mempool=0)
**Mode:** F110 near-tip ladder + early F101b → upload → proxy-prove; **permanence_public PASS**

## Executive verdict

| Gate | Result |
| --- | --- |
| Observer tip match (open) | **PASS** @5731; mem=0; peer_count=3 |
| Path A ckpt_max / F45 lag | **5290** / **441** (hard TIMEOUT 60s) |
| Pin ladder | near-tip only: tip−20/−80/−150/−250 (no ckpt_max) |
| Faucet | **done** in 213703ms (~214s) |
| Post-faucet tip−20 | owned=0 |
| Post-faucet tip−80 | owned=1 → **early exit** (skip deeper; F110) |
| Balance TIMEOUTs | **0** (wave60 had 3×400s) |
| F101b round 0 | **PASS** owned=2 @ pin 5716 |
| Upload + prove | **PASS** tip=5739; last_proven=**5741**; `b066b4bd` |
| Claims | **34 → 35** |
| **permanence_public** | **PASS** |

## Findings

### F110 validated — ~20 min saved vs wave60

Wave60 spent ~20 min on three deep Path A balance TIMEOUTs. Wave61:
1. Skipped empty-wallet pin@ckpt_max before faucet.
2. Used near-tip pin ladder only.
3. On owned=1 at tip−80, skipped deeper pins and entered F101b immediately.

Wall time ~22 min vs wave60 ~43 min at similar tip height. **JOIN runners should treat deep Path A pins as optional diagnostics, not default fund path, while F45 lag ≫ 0.**

### F101b still required

Even with harden: faucet done → tip−20 owned=0 → tip−80 owned=1 → F101b wait → tip−20 owned=2. Do not declare fund fail at owned=1.

### F109 / F45

Faucet ~214s again under 100×5s budget. F45 lag **441** and still climbing (tip 5741 vs ckpt 5290). Soft JOIN only.

### Prove-gate honesty

Same F100/F105 pattern: local `last_proven` preceded `proxy_has`; gate waited for tip_id match + proxy list.

## Permanence board (newest)

| Commitment | Wallet | last_proven | Fund |
| --- | --- | --- | --- |
| `b066b4bd` | **cleo** | **5741** | faucet-F101b |
| `e40023df` | blake | 5729 | faucet-F101b |
| (zion) | zion | 4823 | faucet-F101b |

**JOIN scorecard:** thirty-eight proxy-proven wallets.

## Artifacts

- `_wave61-results.json`, `_wave61-cleo-upload.json` (gitignored `_`)
- `live-testnet-probe-20260722-wave61.md` (this file)
- `user-wallet/cleo.json` (local only)

## Follow-up

- Wave62+ continue permanence density with F110 runner.
- Path A republish (lane 7) when lag allows.

