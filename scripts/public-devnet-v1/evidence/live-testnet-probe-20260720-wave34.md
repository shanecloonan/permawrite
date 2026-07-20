# Live public testnet probe - wave 34 findings (2026-07-20)

**Lane:** 3 (onboarding / B-15)
**UTC window:** ~16:32Z wipe → ~16:54Z close
**Prior:** wave33b F104 local_only trap
**Tip close:** **4533** (matched)
**Mode:** faucet post-wipe; **proxy-prove gate PASS**

## Executive verdict

| Gate | Result |
| --- | --- |
| Wipe + fresh sync | **PASS** tip_id match @4525 (~5 min catch-up) |
| tip_id match open/close | **PASS** |
| Ports / FE | OPEN; `/` `/testnet` 200; `/join` 404 |
| F45 hard checkpoint-log | **TIMEOUT** rc=-1; lag=30 (ckpt 4496) |
| Headers object form | **PASS** |
| Zoe faucet | **PASS** 1M / owned=2 @ pin **4446** |
| tip_id match before upload | **PASS** |
| Upload bound Fresh | **PASS** `4ded4c6d` @ tip 4531 |
| Local last_proven | **PASS** **4533** status=matched |
| Proxy list has zoe | **PASS** (lagged ~100s after local matched — **F105**) |
| Claims open → close | **13 → 14** |
| claims for data_root | **PASS** claim_count=1 |
| **permanence_public** (all gates) | **PASS** |

## Wipe remediation (closes F104 for this observer)

Divergent store quarantined to `live-testnet-data-divergent-20260720-113211`. Fresh mfnd reseeding from 19001–19003 reached tip_id match. After wipe, permanence succeeded under the new gate.

Notable side observation: proxy `list_recent_uploads` now also shows `fe091b02…` (yara wave33b commitment that was stuck local_only pre-wipe). Local diverge can hide public settle; wipe restores a correct view — yara may have been public while local status lied.

## Finding F105 - proxy upload index lags local prove

Poll timeline (10s steps):

- t≈0–110s: `local_only`, proxy_has=False
- t≈120s: local `last_proven=4533` / `matched` while tip_id still mismatched and **proxy_has=False**
- t≈220s: tip_id match **and** proxy_has=True

**JOIN implication:** require proxy index, not only local `uploads status`. Local matched can precede public visibility by 1–2 minutes (F100 + F105). Wave34 gate correctly waited.

## Finding F45 timeout reconfirmed

Hard light-scan TIMEOUT 60s post-wipe; soft JOIN unaffected.

## Permanence board (newest first)

| Commitment | Wallet | last_proven | Notes |
| --- | --- | --- | --- |
| `4ded4c6d` | zoe | **4533** | wave34; faucet pin@4446; proxy-prove PASS |
| `fe091b02` | yara | (proxy listed) | wave33b; was F104 local_only pre-wipe |
| `a0d915d2` | wendy | 4487 | wave31 |
| `b90c135c` | vera | 4479 | wave30 |

## JOIN scorecard

Seventeen new-wallet public permanence loops with proxy gate: … xena, **zoe** (yara proxy-visible post-wipe; count carefully).

## Artifacts (local; not committed)

- `_wave34-results.json`, `_wave34-zoe-upload.json`, `user-wallet/zoe.json`
- `live-testnet-data/` (fresh), quarantine dir above
