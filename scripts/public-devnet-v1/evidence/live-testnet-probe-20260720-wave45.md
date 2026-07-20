# Live public testnet probe - wave 45 findings (2026-07-20) — post-wipe PASS

**Lane:** 3 (onboarding / B-15)
**UTC window:** ~20:55Z-21:10Z (~15.5 min wall)
**Prior:** wave44 jade FAIL + full data-dir wipe (`live-testnet-data-divergent-20260720-154342`)
**Tip close:** **4661** (matched)
**Mode:** **faucet** on fresh observer; mempool=0 gate; **permanence_public PASS**

## Executive verdict

| Gate | Result |
| --- | --- |
| Post-wipe sync | **PASS** tip_id match @4653+; mempool=0 |
| Faucet kate | **PASS** dual-send |
| Pin ladder → owned=2 | **PASS** @4591 |
| Upload Fresh | **PASS** `8b491ece` |
| Public prove | **PASS** last_proven=**4661** + proxy_has |
| Claims | **21 → 22** |
| F45 lag | 13 (ckpt 4641) — still TIMEOUT |
| **permanence_public** | **PASS** |

## Finding: wipe restores permanence (again)

Wave44 broke a 7-PASS streak with F104/F107. Full quarantine wipe + re-sync restored public permanence on the first post-wipe new wallet (**kate**), matching wave34 zoe after the prior wipe cycle.

**JOIN implication (reinforced):**
- Sticky `mempool=1` + no `proxy_has` ⇒ wipe (F107/F108), not restart-only.
- Fresh observer can pass immediately after tip_id rematch.
- Long-lived observers remain at risk of F104 recurrence after ~1–2h of continuous use.

## Permanence board (newest)

| Commitment | Wallet | last_proven | Fund | Notes |
| --- | --- | --- | --- | --- |
| `8b491ece` | **kate** | **4661** | faucet | wave45 post-wipe |
| `39bffdd5` | iris | 4636 | faucet | wave43 last pre-fail PASS |
| `985a944f` | jade | — | peer | wave44 FAIL not public |

**JOIN scorecard:** twenty-five proxy-proven wallets (jade excluded).

## Artifacts

- `_wave45-results.json`, `_wave45-kate-upload.json`, `user-wallet/kate.json`
- Wipe quarantine: `live-testnet-data-divergent-20260720-154342`

