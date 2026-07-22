# Live public testnet probe - wave 83 findings (2026-07-22) — permanence PASS

**Lane:** 3 (onboarding / B-15)
**UTC window:** open `2026-07-22T17:16Z` → close ~17:38Z (~22 min + possible F95 wait)
**Prior:** wave82 brynn last_proven=5982
**Tip close:** **5993** (matched)
**Mode:** faucet-F101b (F95 429 path observed in runner log); **permanence_public PASS**

## Executive verdict

| Gate | Result |
| --- | --- |
| Faucet | first attempt hit HTTP **429**; runner waited ~600s then funded (F95) |
| F110 / F101b | **PASS** owned=1→2 |
| Upload + prove | **PASS** last_proven=**5993** `86de6d8f` |
| Prove path | local_only→matched@5993; proxy_has True by idx 22 |
| Claims | **53 → 54** |
| F45 lag | **693** (ckpt 5290) |
| **permanence_public** | **PASS** |

## Findings

### F95 still bites after dense faucet waves

Even with healthy observer + F110, the public faucet IP cooldown (~15m) fires between waves when wall-clock between fund requests is short. Wave83 log showed `faucet 429 — wait 600s then retry once` before a successful fund. Density runners must keep the 600s retry; operators should expect ~35–40 min wall clock when 429 hits.

### F45 lag **693** — approaching 700

Path A still 5290. Soft JOIN remains mandatory. Lane 7 Path A republish is the only durable fix for hard `--checkpoint-log`.

### Post-wipe streak (waves 81–83)

| Wave | Wallet | Result | Notes |
| --- | --- | --- | --- |
| 80 | zara | PROVE FAIL | F107 → wipe |
| 81 | aster | PASS @5972 | post-wipe |
| 82 | brynn | PASS @5982 | clean F110 |
| 83 | coral | PASS @5993 | F95 + F110 |

## Permanence board (newest)

| Commitment | Wallet | last_proven | Fund |
| --- | --- | --- | --- |
| `86de6d8f` | **coral** | **5993** | faucet-F101b |
| `96804c75` | brynn | 5982 | faucet-F101b |
| `851f4f0a` | aster | 5972 | faucet-F101b |

**JOIN scorecard:** fifty-seven proxy-proven wallets.

## Artifacts

- this markdown

