# Live public testnet probe - wave 11 findings (2026-07-20)

**Lane:** 3 (onboarding / B-15)
**UTC window:** ~04:14Z-04:22Z
**Prior:** wave10 `2506594` / wave11 open `3b12929`
**Tip:** 4140 -> **4148+**

## Executive verdict

| Gate | Result |
| --- | --- |
| B-52 ps1 `-PlanOnly` | **PASS** |
| B-52 ps1 `-Apply` | **FAIL** — F68 PS5.1 native argv strips JSON quotes on `--params` |
| F67 pin-then-fund (Python pin) | **PASS** — eve owned_count=**2**, balance=**1_000_000** |
| Eve faucet | **PASS** — job `0f5bceb3...` done 96707 ms (after IP cooldown cleared) |
| Proxy heavy RPC (B-52) | **PASS** — `get_light_snapshot` + `get_block_headers` OK; health shows `heavy_rpc_timeout_ms=180000` |
| Tip soak | **PASS** — local tracks proxy; peers=3 sess=1 |
| Checkpoint log | max tip advanced to **4148** mid-wave (entries grew) |
| `light-scan --checkpoint-log` | still **exit 1** unless tip equals attested height (F45) |
| SPoRA pool | pool_len=**0** (cleared); wave7 upload last_proven still **4071** |
| index_errors | **3–4** (was 4674) — large improvement |

## Finding F68 (CRITICAL — Windows B-52 twin Apply broken)

`bootstrap-wallet-from-checkpoint-log.ps1 -Apply` retries 8x with:

```
invalid --params JSON: key must be a string at line 1 column 2
```

Root cause (reproduced outside Start-Process): **Windows PowerShell 5.1 strips double quotes when passing arguments to native executables**. Even:

```powershell
$paramsJson = '{"height":4148}'
& mfn-cli.exe ... --params $paramsJson
```

arrives at mfn-cli as `{height:4148}` (unquoted keys). Misleading error text blames hub EAGAIN.

**Workaround that works:** Python TCP `get_light_snapshot` + wallet JSON pin (same as wave7/10). Fix direction for lane 7: snapshot via python inside the `.ps1`, or `cmd /c` with careful escaping, or require PowerShell 7+.

## Finding F67b (pin-then-fund CONFIRMED)

Sequence on eve:

1. Python pin `scan_height=4133` + light checkpoint from snapshot
2. Wait out IP cooldown (429 once)
3. Faucet job done (2 txs)
4. Immediate `wallet balance` → temporarily owned_count=1 / 500k (second F7 UTXO not yet in scanned tip)
5. ~45s later → **owned_count=2 / balance=1000000**

So F67 fix works; allow tip catch-up after faucet dual-send tip-wait before asserting owned_count>=2.

## Finding F69 (B-52 proxy heavy RPC SUCCESS)

Post-B-52 public proxy:

| Method | Result |
| --- | --- |
| get_tip / get_status / get_block_header | OK |
| get_block_headers | OK (was TIMEOUT in wave8 F54) |
| get_light_snapshot | OK (was TIMEOUT) |
| list_utxos | OK |

`/health` now includes `rpc_timeout_ms=30000` and `heavy_rpc_timeout_ms=180000`. Outside-in bootstrap via **proxy** may now be viable (still prefer local observer for wallet keys).

## Finding F70 (SPoRA prove settlement still stale)

`operator pool` empty; uploads list still `last_proven_height=4071` for wave7 commitment while tip ~4148. Challenge path previously advanced `next_height`; inclusion/settlement still looks broken or not rolled (B-45 mfnd?).

## Eve fund record

| Field | Value |
| --- | --- |
| job_id | 0f5bceb310569789febd97b6 |
| duration_ms | 96707 |
| tx_ids | 0952e24f..., de1bbdea... |
| final | owned_count=2 balance=1000000 scan_height=4148 |

## B-15 status

| Item | Status |
| --- | --- |
| F67 pin-then-fund receive | **PASS** (eve) |
| Windows ps1 Apply | **BLOCKED** F68 |
| Proxy snapshot | **PASS** (B-52) |
| Formal JOIN SUMMARY | still need F45 tip-matched attestation or policy change |

**Ask lane 7:** fix B-52 `.ps1` F68 (do not use bare `--params` JSON through PS5.1 native argv).
**Ask lane 4/7:** last_proven stuck at 4071 with empty pool.

## Addendum A — B-55 frontend port check

| Check | Result |
| --- | --- |
| TCP :3000 | OPEN |
| GET http://5.161.201.73:3000/ | status=200 bytes=800 |


