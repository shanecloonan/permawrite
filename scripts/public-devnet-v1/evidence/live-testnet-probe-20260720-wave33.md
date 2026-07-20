# Live public testnet probe - wave 33 findings (2026-07-20)

**Lane:** 3 (onboarding / B-15)
**UTC window:** ~15:41Z-15:58Z
**Prior:** wave32 / xena last_proven=4496; lane7 **B-80** Path A tip-**4496** on disk (entries=16)
**Tip close:** matched (~4505+)
**Mode:** **FAILED permanence** — faucet 429 + peer-fund donors empty

## Executive verdict

| Gate | Result |
| --- | --- |
| tip_id match | **PASS** |
| Xena retrieve | **PASS** 64B |
| F45 hard after B-80 tip-4496 | **FAIL** lag=**1** (tip~4498 vs ckpt 4496) — near-miss |
| Headers | **PASS** |
| Claims at open | **13** |
| Yara faucet | **FAIL** HTTP **429** (F95) |
| Peer xena→yara | **FAIL** `insufficient funds: available 0` |
| Peer uma→yara | **FAIL** `insufficient funds: available 0` |
| Pin ladder yara | owned=0; bal TIMEOUT @4262/@4173 (F97) |
| Yara funded / upload / last_proven | **FAIL** / none |

## Finding F45 near-miss after B-80

Within minutes of Path A tip-**4496** landing, live tip was already **4497–4498**. Hard `--checkpoint-log` still fails:

```
has no attestation at tip_height 4498
```

**lag=1**. Soft JOIN remains correct. Exact-tip Path A PASS windows (wave28 @4443) are brief; operators must publish Path A at the *current* tip for hard path, or keep soft bootstrap.

## Finding F103 - pin_clean before peer-send can zero spendable balance

Donor wallets xena/uma were re-pinned at ckpt_max before send. Both reported **available 0** (`insufficient funds: requested 160000, available 0`) despite earlier wave balances. Likely interaction of pin_clean clearing `owned_outputs` + light-scan not rediscovering UTXOs (or F78 pending_spent / tip race).

**JOIN implication:** before peer-fund, confirm donor `wallet balance` shows owned≥2 *after* pin; if available 0, re-pin ladder / wait tip match / do not assume prior-wave balances persist across pin_clean.

## Finding F95 / F97 reconfirmed

Faucet still 429 under cooldown after wave32. Low pin timeouts on empty wallet.

## Recovery plan (wave33b)

1. Wait faucet `busy=false` (observed ready ~16:02Z).
2. Single runner: faucet → F101 pin ladder → upload → prove for **yara**.
3. Do not Start-Process duplicates (F102).

## JOIN scorecard

Still **sixteen** public permanence wallets (wave33 did not add). Failure documented.

## Artifacts

- `_wave33-results.json`, `_wave33-*-to-yara-150000.json` (insufficient funds)
- `user-wallet/yara.json` (unfunded)

## Follow-up wave33b

Faucet recovery funded+uploaded yara, but prove stuck **local_only** — see `live-testnet-probe-20260720-wave33b.md` (**F104**).
