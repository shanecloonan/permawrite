# Live public testnet probe - wave 48 findings (2026-07-20) — FUND FAIL

**Lane:** 3 (onboarding / B-15)
**UTC window:** ~21:44Z-21:58Z
**Prior:** wave47 nora last_proven=4677
**Mode:** faucet 429 → peer nora+kate; **owen never reached owned≥2**

## Executive verdict

| Gate | Result |
| --- | --- |
| Observer | tip match @4678; mem=0; no wipe |
| F45 lag | 16 (ckpt 4662) TIMEOUT |
| Faucet owen | **HTTP 429** (cooldown after nora) |
| Peer nora→owen 150k | **PASS** rc=0 (nora owned 2→0) |
| Peer kate→owen | **SKIP** owned=1 / bal≈839k (F106) |
| Owen pin@4662 post-send | owned=0 (settlement lag / height) |
| Owen pin@4612 | owned=1 / 150k only |
| Deep pins 4400/4262 | **TIMEOUT** 150s (F99) |
| Upload | **not attempted** |
| **permanence_public** | **FAIL** (fund) |

## Findings

### F106 pattern solidifies (wave46 + wave48)

Recent permanence wallets quickly become single-UTXO after their own prove burn + change consolidation:
- **kate** (wave45 PASS): balance high, owned=1 — useless as second donor
- **nora** (wave47 PASS): owned=2 briefly, one send exhausts to owned=0
- Result: peer dual-fund under faucet 429 fails unless a **pre-prove** multi-UTXO donor pool exists

**JOIN implication:** prefer faucet; if 429, either wait cooldown (~15m) or use operators/validators with known owned≥2. Do not assume last two permanence wallets can dual-fund.

### Post-send pin@ckpt_max owned=0

Immediately after nora send settled tip-wise, pin@4662 showed owen owned=0; pin@4612 found the 150k. Likely scan/checkpoint window vs inclusion height — another reason for pin ladder, but ladder cannot invent a second UTXO.

## Artifacts

- `_wave48-results.json` (owen_funded=false)
- `_wave48-nora-to-owen-150000.json`

