# Live public testnet probe - wave 31 findings (2026-07-20)

**Lane:** 3 (onboarding / B-15)
**UTC window:** ~15:08Z-15:22Z
**Prior:** wave30 / vera last_proven=4479 (`bde1044` on main)
**Tip close:** **4487** (matched)
**Mode:** peer-dual-donor (faucet **429** / F95)

## Executive verdict

| Gate | Result |
| --- | --- |
| tip_id match (close) | **PASS** |
| Ports / FE | OPEN; `/` `/testnet` 200; `/join` 404 |
| Vera retrieve (wave30) | **PASS** rc=0, 64 bytes |
| F45 hard checkpoint-log | **FAIL** rc=1; lag=37 (ckpt_max=4443) |
| Headers object form | **PASS** |
| Claims open → close | **11 → 12** |
| Wendy faucet | **FAIL** HTTP **429** (F95 cooldown after wave30) |
| Peer dual-donor (uma+tina) | **PASS** both Fresh sends |
| Pin@4443 after dual send | owned=1 / 150000 only |
| Pin@4400 retry | **PASS** 300000 / owned=2 (**F101**) |
| Wendy upload bound | **PASS** `a0d915d2` |
| Wendy last_proven | **PASS** **4487** matched |
| Proxy + claims for | **PASS** |

## Permanence loop (new wallet wendy)

1. Soft tip wait + surface smoke (ports, FE, ckpt verify entries=15, max=4443).
2. Vera recheck: bal ~999k owned=2; retrieve 64B; F45 hard FAIL lag=37.
3. `wallet new` wendy → pin@4443 → `POST /faucet` → **HTTP 429 Too Many Requests** (F95; cooldown ~15m after vera).
4. Peer-fund: uma → wendy 150k Fresh; tip match; tina → wendy 150k Fresh.
5. Pin@4443: **owned=1 / 150000** (only one UTXO visible).
6. Pin@**4400**: **owned=2 / 300000** — ladder retry required (**F101**).
7. Upload `--message wave31-wendy-authorship` → bound, commitment `a0d915d29f1120253e6bb48c2b9875247bab1b3f7d98f883099ed0a8ddacf5c1`.
8. Prove: `local_only` then `last_proven=4487` appeared while tip_id still ±1 mismatched (**F100**); settled matched; proxy has wendy; claims **12**.

## Finding F95 reconfirmed

Faucet returned 429 within cooldown after wave30 faucet success. JOIN docs must document backoff using `cooldown_ms` from `/health` and peer-fund fallback with ≥2 inputs (F75/F98).

## Finding F101 - dual-donor first pin may show owned=1

After two successful peer sends (uma+tina), pin@4443 showed only **one** 150k UTXO. Pin@4400 immediately after showed **both** (300k / owned=2).

**JOIN implication:** after peer dual-fund, do not stop at first non-zero balance if owned_count < 2 — continue pin ladder (and tip settle) until owned≥2 before upload. Complements F96/F98/F99.

## Finding F45 / F100 reconfirmed

- Hard scan: no attestation at tip ~4481; lag=37 vs ckpt 4443.
- Prove polling: last_proven visible before tip_id match (F100).

## Permanence board (newest first)

| Commitment | Wallet | last_proven | Notes |
| --- | --- | --- | --- |
| `a0d915d2` | wendy | **4487** | wave31 peer-dual; pin@4400 |
| `b90c135c` | vera | 4479 | wave30; retrieve reconfirmed |
| `0916e1d6` | uma | 4466 | wave29 |
| `bce3dd28` | tina | 4452 | wave28 |

## JOIN scorecard

Fifteen new-wallet public permanence loops: … uma, vera, **wendy**.

## Artifacts (local; not committed)

- `_wave31-results.json`, `_wave31-wendy-upload.json`, `_wave31_run.py`
- `user-wallet/wendy.json`
