# Live public testnet probe - wave 37 findings (2026-07-20)

**Lane:** 3 (onboarding / B-15)
**UTC window:** ~18:18Z 3rd wipe → ~18:38Z close
**Prior:** wave36 ben F107 sticky mempool
**Tip close:** **4585** (matched)
**Mode:** faucet + **mempool=0 pre-upload gate** → **permanence_public PASS**

## Executive verdict

| Gate | Result |
| --- | --- |
| 3rd wipe + sync mem=0 | **PASS** tip_id match @4578 |
| Restart-without-wipe (wave36 follow-up) | **FAIL** — sticky mempool **persisted** in store (F108) |
| Faucet cora | **PASS** |
| Pin@ckpt then @4517 | owned=0 then **1M/owned=2** (F101) |
| pre_upload tip_id + mempool=0 | **PASS** |
| Upload Fresh bound | **PASS** `e8da3321` |
| Prove: mempool returned to 0 | **PASS** (unlike wave36) |
| last_proven + proxy_has + tip match | **PASS** **4585** |
| Claims | **14 → 15** |
| **permanence_public** | **PASS** |

## Finding F108 - sticky mempool survives restart-without-wipe

After wave36 F107, restarting `mfnd` on the **same** data dir left `mempool_len=1`. Only a full data-dir wipe cleared it. Sticky Fresh TXs are durable in the observer store.

**JOIN implication:** if upload stuck local_only with mempool=1, wipe (quarantine data dir) — do not expect restart alone to help.

## Finding F107 mitigation validated

Requiring **tip_id match AND mempool=0** immediately before upload, then confirming mempool returns to 0 during prove, correlated with public settle. Wave36 uploaded into a polluted observer; wave37 uploaded into a clean mempool and got proxy_has=True within ~3.5 min after local matched (F105 lag still present).

## Wipe matrix update

| Wave | Wipe # | mempool gate | permanence_public |
| --- | --- | --- | --- |
| 34 zoe | 1 | no | **PASS** |
| 36 ben | 2 | no | **FAIL** F107 |
| 37 cora | 3 | **yes** | **PASS** @4585 |

## Permanence board (newest)

| Commitment | Wallet | last_proven | Notes |
| --- | --- | --- | --- |
| `e8da3321` | cora | **4585** | wave37; mempool gate |
| `4ded4c6d` | zoe | 4533 | wave34 |
| `fe091b02` | yara | (proxy) | post-wipe visibility |

## JOIN scorecard

Eighteen new-wallet public permanence loops: … zoe, **cora**.

## Artifacts

- `_wave37-results.json`, `_wave37-cora-upload.json`, `user-wallet/cora.json`
