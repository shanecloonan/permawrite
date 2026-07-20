# Live public testnet probe - wave 32 findings (2026-07-20)

**Lane:** 3 (onboarding / B-15)
**UTC window:** ~15:23Z-15:40Z
**Prior:** wave31 / wendy last_proven=4487 (`d248ba2` on main)
**Tip close:** **4496** (matched)
**Mode:** faucet (pin@4400); **ops caveat:** accidental duplicate local runner (F102)

## Executive verdict

| Gate | Result |
| --- | --- |
| tip_id match (close) | **PASS** |
| Ports / FE | OPEN; `/` `/testnet` 200; `/join` 404 |
| Wendy retrieve | **PASS** 64 bytes |
| Wendy bal @4443 | **FAIL** TCP timeout os error **10060** (F85/F102) |
| F45 hard checkpoint-log | **FAIL** lag=46 (ckpt_max=4443) |
| Headers | **PASS** |
| Claims open → close | **12 → 13** |
| Xena faucet | job **done** ~196s; dual-send recorded |
| Pin@4443 | owned=1 / 500000 |
| Pin@4400 | **PASS** owned=3 / 1150000 (**F101** extended) |
| Xena upload bound | **PASS** `fe091b02` |
| Xena last_proven | **PASS** **4496** matched + proxy |
| Concurrent runner | **YES** — Start-Process duplicate contended RPC (**F102**) |

## Permanence loop (wallet xena)

Despite local RPC timeouts and a duplicate probe process racing the same `user-wallet/xena.json` + mfnd RPC:

1. Surface smoke OK; wendy retrieve OK; wendy balance hit **10060** (continue).
2. F45 hard FAIL lag=46.
3. New wallet xena; faucet job completed (dual-send); tip match after ~9 polls.
4. Pin ladder: @4443 owned=1; @4400 owned=3 / 1.15M (F101 — do not stop at owned=1).
5. Upload bound `fe091b027ea3cbfc9244d93788af5c776566ec15fa7d1531c01106ead3b822a6`; prove → last_proven **4496** (F100 again: proven before tip_id match); proxy + claims **13**.

Upload left `balance_after_upload=500000` / owned=1 (spare UTXO), which is healthy for follow-on ops.

## Finding F102 - concurrent local probe runners wedge RPC

An accidental second `python _wave32_run.py` (Start-Process) ran overlapping the primary battery against the same `127.0.0.1:18734` and `user-wallet/*.json`. Observed:

- `wallet balance` / pin → WinError **10060** connection timeout
- Duplicate peer-fund from vera while primary used faucet
- Faucet job address vs primary `wallet address` mismatch risk when wallet file is rewritten mid-job

**JOIN / ops rule:** serialize live probes on a given local observer. One runner per RPC endpoint. Extends F85.

## Finding F101 extended (faucet path)

Even with faucet dual-send (2×500k), first pin@4443 showed **owned=1**. Pin@4400 reached owned≥2 (here owned=3). Pin ladder required on faucet path too, not only peer-fund.

## Finding F45 / F100 reconfirmed

Hard attestation lag=46; last_proven appeared under tip_id ±1 mismatch before settle.

## Permanence board (newest first)

| Commitment | Wallet | last_proven | Notes |
| --- | --- | --- | --- |
| `fe091b02` | xena | **4496** | wave32; pin@4400; F102 race |
| `a0d915d2` | wendy | 4487 | wave31 |
| `b90c135c` | vera | 4479 | wave30 |
| `0916e1d6` | uma | 4466 | wave29 |

## JOIN scorecard

Sixteen new-wallet public permanence loops: … vera, wendy, **xena**.

## Artifacts (local; not committed)

- `_wave32-results.json`, `_wave32-wendy-upload` N/A, `_wave32-xena-upload.json`, `_wave32_run.py`
- `_wave32-stdout.txt` / `_wave32-stderr.txt` from accidental duplicate — do not commit
- `user-wallet/xena.json`
