# Live public testnet probe - wave 111 findings (2026-07-23) — permanence PASS (post-F115 wipe)

**Lane:** 3 (onboarding / B-15)
**UTC window:** open `2026-07-23T20:46Z` → close ~21:02Z (~16 min after wipe#4 resync)
**Prior:** wave110 dax F115 tip_id diverge → wipe #4
**Tip close:** **6809** (matched)
**Mode:** faucet-F101b; **permanence_public PASS**

## Executive verdict

| Gate | Result |
| --- | --- |
| Wipe#4 resync | **PASS** |
| Faucet / F101b | **PASS** |
| Upload + prove | **PASS** last_proven=**6809** `dd7e4fc9` |
| Claims | **76 → 77** |
| F45 lag | **1511** (ckpt 5290) |
| **permanence_public** | **PASS** |
| Post-wipe streak | **x1** (wave111 after F115 wipe) |

## Findings

### F115 wipe recovers density

Full quarantine after tip_id diverge (mem=0) restored tip match and permanence on the next wave — same ops posture as F107 wipe, different failure mode (pre-upload vs post-Fresh sticky mem).

### F45 lag **1511**

Path A still 5290; lag crossed 1500.

## Permanence board (newest)

| Commitment | Wallet | last_proven | Fund |
| --- | --- | --- | --- |
| `dd7e4fc9` | **eden** | **6809** | faucet-F101b |

**JOIN scorecard:** eighty proxy-proven wallets.
