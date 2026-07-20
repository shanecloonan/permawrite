# Live public testnet probe - wave 40 findings (2026-07-20)

**Lane:** 3 (onboarding / B-15)
**UTC window:** ~19:13Z-19:30Z (~17 min wall)
**Prior:** wave39 erin last_proven=4602
**Tip open:** 4603 (matched) · **Tip close:** **4611** (matched)
**Mode:** faucet 429 → **peer-dual-donor** (erin+dana); mempool=0 gate; **permanence_public PASS**

---

## Executive verdict

| Gate | Result |
| --- | --- |
| Observer preflight | tip_id match @4603; mempool=0; peer_count=3 / session_count=0 (F88b) — **no wipe** |
| Ports 19001-03 / 8787 / 8788 / 3000 | all OPEN |
| Faucet `/health` | ok; wallet_scan=tip=4603; busy=false |
| Faucet frank | **HTTP 429** (cooldown after wave39) |
| Peer fund erin→frank 150k | **PASS** rc=0 |
| Peer fund dana→frank 150k | **PASS** rc=0 |
| Pin@4584 (ckpt_max) | owned=1 / 150k (F101 first pin) |
| Pin@4534 | **PASS** 300k / owned=2 |
| tip_id + mempool=0 before upload | **PASS** (waited ~8 polls / ~64s for tip catch-up) |
| Upload bound Fresh | **PASS** `8f866ea2` @ tip 4609 |
| Prove: mempool 1→0 | **PASS** by poll ~10 |
| Local last_proven ahead of tip_id match | **observed** (F100) — matched@4611 while L≠P |
| Proxy list_recent_uploads lag | **~100s** after local matched (F105) |
| last_proven + tip_id match + proxy_has | **PASS** **4611** (poll 20) |
| Claims recent total | **17 → 18** |
| FE `/` `/testnet` | 200; `/join` 404 (known) |
| F45 hard `--checkpoint-log` | TIMEOUT 60s; lag=19 (ckpt 4584 vs tip ~4603) |
| **permanence_public** | **PASS** |

---

## What happened (timeline)

1. **Open:** local observer already tip-matched to proxy @4603, mempool empty. No F107 wipe.
2. **F45:** hard light-scan against Path A log (max **4584**) timed out at live tip — lag **19** blocks. Soft JOIN path remains correct (F45).
3. **Fund:** faucet returned **429** immediately (expected ~15m cooldown after erin). Fell back to **erin + dana** peer dual-send (150k each). Both sends settled; frank scanned to **owned=2 / 300000** after pin ladder 4584→4534 (F101).
4. **Pre-upload gate:** waited until tip_id matched **and** mempool_len=0 (local briefly ahead of proxy by 1 height — F88b).
5. **Upload:** Fresh bound authorship `wave40-frank-authorship`; commitment `8f866ea2`; tx entered local mempool (len=1).
6. **Prove poll:**
   - polls 0-2: tip match, status `local_only`, mem=1, proxy_has=false
   - polls 3-8: local tip advanced ahead of proxy (F88b), still local_only / mem=1
   - poll 9: tip rematch @4610, still local_only / mem=1
   - **poll 10:** status→`matched`, last_proven=**4611**, mem→0, but tip_ids still mismatched and proxy_has=false (**F100 + F105**)
   - polls 11-19: local matched + last_proven while proxy tip lagged / list lag
   - **poll 20:** tip_id match @4611 **and** proxy_has=true → public permanence gate closed
7. **Close:** tip match @4611; claims index **17→18**; claim_count=1 for frank data_root.

---

## Permanence scorecard update

Fourth consecutive new-wallet public permanence PASS on the same post-wipe observer stack (cora → dana → erin → **frank**), with the **tip_id + mempool=0** pre-upload gate and the **triple prove gate** (last_proven AND tip_id match AND proxy list).

| Commitment | Wallet | last_proven | Fund mode | Notes |
| --- | --- | --- | --- | --- |
| `8f866ea2` | **frank** | **4611** | peer-dual-donor | wave40; after faucet 429 |
| `8af641cd` | erin | 4602 | faucet | wave39; donor this wave |
| `8d15b8e5` | dana | 4594 | peer | wave38; donor this wave |
| `e8da3321` | cora | 4585 | faucet | wave37 |

**JOIN scorecard:** twenty-one new-wallet public permanence loops (heidi…erin + **frank**).

Not counted as public permanence: yara/amy/ben (F104/F107 stuck `local_only` in earlier waves).

---

## Findings reinforced / nuanced

| ID | Observation this wave |
| --- | --- |
| **F45** | Hard ckpt-log still FAIL/TIMEOUT while Path A max (4584 in this run) << tip (~4603+). Soft bootstrap OK. Lane 7 Path A advancing separately does not close F45 until attestation ≈ live tip. |
| **F88b** | tip_id ±1 lag during prove; `session_count=0` with `peer_count=3` still normal for this observer. |
| **F95** | Faucet 429 right after wave39 success — peer dual-donor fallback remains the JOIN-safe path. |
| **F100** | Local `matched` + `last_proven` can appear **before** tip_id match; do **not** declare public settle until tip_ids equal. |
| **F101** | First pin @ckpt_max → owned=1; second pin @ckpt_max-50 → owned=2. Ladder required after peer fund. |
| **F105** | Proxy `list_recent_uploads` lagged ~10 polls (~100s) after local matched. Triple gate still correct. |
| **F106** | Peer donors (erin/dana) retained owned≥2 enough to dual-fund — opposite of common donor-starvation mode; still not guaranteed. |
| **F107** | **Not triggered** — mempool returned to 0 with tip rematch; no wipe. Continues to validate wipe-only-on-sticky-mempool rule. |

---

## Ops lessons (JOIN)

1. Serialize waves on one local RPC; never parallel JOIN against the same observer.
2. Prefer faucet; on **429**, peer dual-fund from two recent permanence wallets (≥150k each), then pin ladder until owned≥2.
3. **Upload gate:** tip_id match **and** mempool_len=0.
4. **Public prove gate:** `last_proven` **and** tip_id match **and** proxy `list_recent_uploads` contains commitment.
5. Treat local `matched` alone as provisional (F100/F105).
6. Do not restart `faucet-http` or run Hetzner JOIN during evidence (§6).

---

## Artifacts (local; wallets not committed)

- `_wave40-results.json` — machine-readable closeout
- `_wave40-frank-upload.json` — Fresh upload JSON
- `_wave40-erin-to-frank-150000.json`, `_wave40-dana-to-frank-150000.json`
- `user-wallet/frank.json` (+ donors mutated)
- Runner: `_wave40_run.py`

---

## Relation to board / L4

- Advances B-15 outside-in evidence density (twenty-one proxy-proven wallets).
- Does **not** close formal JOIN archive assert (still needs SUMMARY freeze + assert script green + human).
- Does **not** close TL-9 / B-14 invite circulation.
- Path A near-tip work remains lane 7 (ckpt lag still drives F45).

