# Live public testnet probe - wave 35 findings (2026-07-20)

**Lane:** 3 (onboarding / B-15)
**UTC window:** ~16:55Z-17:12Z
**Prior:** wave34 zoe last_proven=4533 (proxy-prove PASS)
**Mode:** **FAILED fund** — faucet 429 + donors owned=1 only

## Executive verdict

| Gate | Result |
| --- | --- |
| tip_id match | **PASS** (post-wipe observer healthy) |
| ckpt_max | **4532** (Path A advanced; entries grew) |
| F45 hard | rc=-1 lag=2 |
| Amy faucet | **FAIL** HTTP **429** (F95; cooldown after zoe) |
| Peer vera | skip — owned=1 / 838997 (F75 needs ≥2) |
| Peer tina | skip — owned=1 / 838997 |
| Amy funded | **FAIL** |
| Permanence | **not attempted** |

## Finding F106 - donor pool exhausted to owned=1

After many permanence loops, common peer donors (vera/tina) sit at **owned_count=1** (change leftovers). Dual-donor peer-fund cannot start without two wallets each having owned≥2, or one wallet with owned≥2.

**JOIN implication:** maintain a faucet cooldown clock; when 429, either wait `cooldown_ms` or use a donor with owned≥2. Do not burn time on owned=1 donors (wave35).

## Recovery

wave35b: faucet retry once `busy=false` (observed ready ~17:12Z).

## JOIN scorecard

Still seventeen proxy-proven wallets (zoe latest). Amy pending.
