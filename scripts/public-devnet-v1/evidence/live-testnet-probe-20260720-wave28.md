# Live public testnet probe - wave 28 findings (2026-07-20)

**Lane:** 3 (onboarding / B-15)
**UTC window:** ~13:50Z-14:12Z
**Prior:** wave27 / sam last_proven=4430
**Tip close:** **4452** (local tip_id matched proxy)
**Runner wall time:** ~22 min

## Executive verdict

| Gate | Result |
| --- | --- |
| tip_id match open/close | **PASS** |
| Seeds + 8787/8788/3000 | **OPEN** |
| FE `/` `/testnet` | **200**; `/join` **404** |
| Checkpoint-log verify (open) | **PASS** max_tip=**4415** entries=14 (local working tree) |
| F45 HARD @ live tip | **PASS** rc=0 (exact-tip attestation present) |
| F45 HARD after pin@ckpt_max | **PASS** rc=0 |
| `get_block_headers` proxy tip | **PASS** |
| Sam permanence recheck | **PASS** last_proven 4430; retrieve **64B**; proxy listed |
| `claims recent` | **8 -> 9** after tina |
| Tina faucet F7 dual-send | **PASS** ~139s; 1_000_000 |
| Tina fund visibility | pin@4262 -> 0; pin@4173 -> 1M/owned=2 (**F96**) |
| Tina upload `--message` | **PASS** bound `bce3dd28` |
| Tina last_proven | **PASS** **4452**; proxy listed; claims for PASS |

## Finding F45 - CLOSED when exact-tip attestation exists

Hard `wallet light-scan --checkpoint-log` returned **rc=0** at tip **4443** with:

```
sync_mode=light
weak_subjectivity=checked
weak_subjectivity=pinned
```

At wave open, verify reported max_tip=**4415**. During the run, the local working-tree checkpoint log gained a Path A entry at tip_height=**4443** (exact tip). That is what unblocked F45.

**JOIN implication:** F45 is not a permanent protocol failure — it is an **attestation lag** failure. Soft bootstrap remains the JOIN default until operators publish near-tip Path A entries. When an attestation exists at the live tip, hard checkpoint-log scan works.

**Observed local work (not staged by lane 3):** `mfn-node/testdata/public_devnet_v1.checkpoints.jsonl` dirty with tip-4415 and tip-4443 Path A lines (lane 7 territory). Do not commit from this lane.

## Finding F96 reconfirmed (order-independent)

After faucet `done` (~139s):

| Pin | Balance | owned |
| --- | --- | --- |
| 4262 | 0 | 0 |
| 4173 | 1000000 | 2 |

Opposite order from wave26 (4173->0, 4262->1M). Confirms scripts must retry **multiple** pin heights, not a single preferred height.

## Permanence board (wave28 close)

| Commitment | Wallet | last_proven | Proxy | Claims |
| --- | --- | --- | --- | --- |
| `bce3dd28` | tina | **4452** | yes | yes (bound) |
| `518e69ba` | sam | 4430 | yes | yes |
| `b3debb6a` | rose | 4412 | yes | yes |

## JOIN scorecard

Twelve new-wallet public permanence loops: … rose, sam, **tina**.

## Artifacts (local only)

- `user-wallet/tina.json` + upload-artifacts
- `_wave28-results.json`, `_wave28-tina-upload.json`, `_wave28-sam-retrieve.bin`
