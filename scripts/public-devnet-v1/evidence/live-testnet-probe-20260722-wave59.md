# Live public testnet probe - wave 59 findings (2026-07-22) — FUND FAIL

**Lane:** 3 (onboarding / B-15)
**UTC window:** ~07:22Z-08:06Z (~44 min)
**Prior:** wave58 zion last_proven=4823; tip now ~5700; Path A ckpt_max=**5290**
**Mode:** faucet accepted then stalled; pin/balance timeouts; **permanence_public FAIL**

## Executive verdict

| Gate | Result |
| --- | --- |
| Observer tip match | **PASS** @5685; mem=0; peer_count=3 |
| Path A ckpt_max | **5290** (was 4679 in wave58 era) |
| F45 lag | **395** — hard scan TIMEOUT 60s |
| Faucet POST | accepted job `99fb50eb…` |
| Faucet poll (50×5s = 250s) | stuck **running** entire window — never `done` |
| Pin@5290/@5240/@4400/@4262 + balance | **all TIMEOUT 150s** (10 timeouts logged) |
| Peer nora/kate | bal TIMEOUT → skip (cannot confirm owned≥2) |
| Upload | **not attempted** |
| **permanence_public** | **FAIL** (fund) |

## Findings

### F109 — tall-tip faucet job budget insufficient

At tip ~5690, faucet dual-send job remained `running` for the full 250s poll budget. Earlier waves at tip ~4600–4800 typically finished in ~125–195s. Tall tip + hub load can push faucet past 250s.

**JOIN fix:** poll faucet jobs for ≥400–500s (80–100 × 5s) before treating as failed.

### F99 escalated — balance/scan timeout at tip ~5700

Even after giving up on faucet completion, every `wallet balance` after pin timed out at **150s**. Scanning ~400 blocks from Path A 5290→tip 5700 exceeds the old balance timeout. Deep pins (4400/4262) also fail (get_light_snapshot timeout).

**JOIN fix:**
1. Raise balance timeout to **400s** on tall tip
2. Prefer pin heights near live tip (tip−20, tip−80) once faucet settles, not only ckpt_max/ancient heights
3. Drop 4400/4262 from default ladder on tip > 5000

### F45 still open

Path A advanced to 5290 (B-137 era) but tip ~5700 → lag **395**. Soft JOIN remains mandatory.

## Artifacts

- `_wave59-results.json` (aria_funded=false; 10 timeouts)
- `user-wallet/aria.json` (unfunded / unknown)

## Follow-up

Wave60 runner hardened: faucet poll ≥100×5s; bal timeout 400s; near-tip pin ladder.

