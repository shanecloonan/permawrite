# Live public testnet probe - wave 46 findings (2026-07-20) — FUND FAIL

**Lane:** 3 (onboarding / B-15)
**UTC window:** ~21:11Z-21:26Z
**Prior:** wave45 kate last_proven=4661 (post-wipe PASS)
**Mode:** faucet 429 → peer fallback; **liam never reached owned≥2**

## Executive verdict

| Gate | Result |
| --- | --- |
| Path A ckpt_max | **4662** |
| F45 lag at open | **0** (exact tip!) — hard scan still TIMEOUT 60s |
| Faucet liam | **HTTP 429** (cooldown after kate) |
| Peer kate→liam 150k | **PASS** rc=0 (single UTXO) |
| Peer iris→liam | **SKIP** owned=1 despite balance≈839k (F106) |
| Liam pin ladder | owned=1 / 150k only; deep pins **TIMEOUT** 150s (F99) |
| Upload / prove | **not attempted** |
| **permanence_public** | **FAIL** (unfunded for upload) |

## Findings

### F45 near-close

Path A max **4662** matched live tip at wave open (lag **0**). Hard `--checkpoint-log` still timed out at 60s — exact tip attestation is necessary but not sufficient under current scan budget. Soft JOIN still required for reliability.

### F106 donor starvation (recur)

Iris shows balance≈839k but **owned_count=1** — cannot dual-send. Kate (fresh permanence wallet) could send only one 150k input, leaving liam at owned=1. Upload needs owned≥2 (F75/F101).

**JOIN implication:** after faucet 429, need **two donors each with owned≥2**, or wait for faucet cooldown. Do not treat high balance + owned=1 as fundable.

### F99 pin timeouts

Pins at 4400/4262 timed out at 150s on tall tip (~4665). Prefer near-tip pin heights (ckpt_max, ckpt_max-50).

## Artifacts

- `_wave46-results.json` (liam_funded=false)
- kate send JSON present; no upload

