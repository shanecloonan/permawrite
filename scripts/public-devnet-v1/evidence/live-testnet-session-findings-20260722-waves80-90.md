# Live testnet permanence density — session findings waves 80–90 (2026-07-22)

**Lane:** 3 (B-15 outside-in)
**Network:** public-devnet-v1 · seeds `5.161.201.73:19001–19003` · proxy `:8787/rpc` · faucet `:8788`
**Observer:** local `mfnd` `127.0.0.1:18734` · wiped once after wave80 (`live-testnet-data-divergent-20260722-112926`)

## Scorecard

| Wave | Wallet | Result | last_proven | Fund | Notes |
| --- | --- | --- | --- | --- | --- |
| 80 | zara | **PROVE FAIL** | — | faucet-F101b | F107 sticky mem=1 → wipe |
| 81 | aster | **PASS** | 5972 | faucet-F101b | F108 recovery |
| 82 | brynn | **PASS** | 5982 | faucet-F101b | |
| 83 | coral | **PASS** | 5993 | faucet-F101b | F95 |
| 84 | dante | **PASS** | 6002 | faucet-F101b | lag>700 |
| 85 | eden | **PASS** | 6017 | faucet-retry-F101b | F95 |
| 86 | felix | **PASS** | 6026 | faucet-F101b | |
| 87 | gryph | **PASS** | 6040 | faucet-retry | F95 |
| 88 | haven | **PASS** | 6050 | faucet-F101b | |
| 89 | iota | **PASS** | 6060 | faucet-F101b | |
| 90 | juno | **PASS** | 6070 | faucet-F101b | lag=771; wave90 milestone |

**JOIN scorecard:** 54 → **64** proxy-proven (zara excluded).
**Tip / Path A:** tip~6070 · ckpt=**5290** · F45 lag=**771**.

## Detailed findings

### 1. F107 / F108 — sticky local_only remains the only density breaker this arc

Wave80 funded+uploaded Fresh with clean tip_id+mem=0 pre-gate, then never left `local_only` while local mem=1 stuck and proxy tip advanced with mem=0. Quarantine wipe + seed resync (~6.5 min tip 0→match) restored health. Waves 81–90 then completed **10/10** permanence PASSes with only transient (~2 min) local_only windows — proving the distinction between healthy post-Fresh mem=1 and F107 sticky failure.

**Operator rule:** sticky mem=1 + no last_proven for ~3–5 min ⇒ wipe immediately; do not densify on local_only evidence.

### 2. F95 faucet IP cooldown still paces dense loops

HTTP 429 hit waves 83, 85, 87. Standing runner 600s wait+retry recovered without peer-fund. Waves 88–90 avoided 429 (spacing after prior waits). Expect ~15m cooldown after successive fund successes.

### 3. F45 hard checkpoint-log still JOIN-blocking

Every wave: `f45_hard_rc=-1`, ckpt_max=5290, lag climbed **658 → 771**. Soft / near-tip pin ladder + F101b remain mandatory. Path A republish (lane 7) is the only durable fix.

### 4. F110 / F101b is the standing tall-tip fund recipe

Near-tip pin ladder (tip−20/−80/−150/−250), early exit on owned=1, F101b re-pin to owned=2, upload only on tip_id match + mem=0, prove gated on tip match + last_proven + proxy_has. Zero bal TIMEOUTs in this post-wipe streak.

### 5. Prove path health signal

Healthy: `local_only mem=1` briefly → `st matched` + `proxy_has True` within ~2–4 min.
Unhealthy (F107): same signals for full prove budget with tip_id divergence / sticky mem=1.

### Ops hygiene held

- No Hetzner parallel JOIN / no faucet-http restart (§6).
- No F112 `--message` corruption (explicit token-map runners from `_wave74_run.py`).
- Wallets / `live-testnet-data*` / other-lane dirty files not staged.
- Docs pushed to `main` with `[skip ci]` after each wave.

## Recommended next steps

1. Continue wave91+ while observer stays tip_id-matched.
2. On next F107: wipe immediately.
3. Lane 7: Path A republish near tip to collapse F45 lag (>750).
4. Human SUMMARY sign-off when invite window opens; do not fake TL completion.
