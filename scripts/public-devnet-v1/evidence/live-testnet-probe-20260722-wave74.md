# Live public testnet probe - wave 74 findings (2026-07-22) — permanence PASS (post-wipe)

**Lane:** 3 (onboarding / B-15)
**UTC window:** ~13:48Z–14:04Z (~17 min) after F107 wipe/resync
**Prior:** wave73 opal PROVE FAIL (F107 sticky mem=1)
**Tip close:** **5886** (matched)
**Mode:** post-wipe F110 + faucet-F101b; **permanence_public PASS**

## Executive verdict

| Gate | Result |
| --- | --- |
| Observer wipe | quarantined `b15-fresh` → `live-testnet-data-divergent-20260722-084147` |
| Fresh sync seeds 19001–03 | tip_id match @5877 in ~6 min; peer_count=3 |
| Faucet | **done** ~258s |
| F110 / F101b | **PASS** |
| Upload + prove | **PASS** last_proven=**5886** `480340e7` |
| Claims | **46 → 47** |
| F45 lag | **588** (ckpt 5290) |
| **permanence_public** | **PASS** |

## Findings

### F107 wipe recovers permanence

Wave73 stuck local_only/mem=1 on the old store. After quarantine + fresh mfnd with `--p2p-dial` seeds, wave74 completed a normal faucet-F101b → prove → proxy_has path. Confirms wipe (not restart-only) is the correct recovery.

### F111 timing note

Fresh sync from tip 0→~5877 took ~350s with peer_count=3 — acceptable for JOIN after F107 wipe.

### F45 lag **588** still open

## Permanence board (newest)

| Commitment | Wallet | last_proven | Fund |
| --- | --- | --- | --- |
| `480340e7` | **reed** | **5886** | faucet-F101b (post-wipe) |
| (nico) | nico | (wave72 PASS) | faucet-F101b |
| (mira) | mira | 5853 | faucet-F101b |

**JOIN scorecard:** fifty proxy-proven wallets (opal excluded — F107).

## Artifacts

- this markdown; wipe quarantine dir (not committed)

