# B-277 — Live Path A tx-storm + adversarial probes (2026-08-07)

Outside-in / on-VPS stress against public Path A (5.161.201.73). Goal: real faucet→transfer load, adversarial submit_tx, and observer-proxy visibility.

## Environment

| Surface | Endpoint | Notes |
| --- | --- | --- |
| Hub RPC | 127.0.0.1:18731 (VPS) | producer; faucet backend |
| Observer RPC | 127.0.0.1:18734 (VPS) | public proxy backend |
| Observer proxy | http://5.161.201.73:8787/rpc | public-safe methods + submit_tx |
| Faucet | http://5.161.201.73:8788 | async job API |
| Frontend | http://5.161.201.73:3000/testnet | HTTP 200 during session |
| Tip (session) | ~16611 → ~16633 | advancing |

## What worked

1. **Public proxy adversarial rejects (fail-closed)** after recovery:
   - submit_tx tx_hex=deadbeef → -32602 decode_transaction: short buffer
   - submit_tx tx_hex=abc → -32602 hex decode: Odd number of digits
   - stop → HTTP **403 Forbidden** (allowlist)
   - get_tx_count_totals / /health → 	otal_user_tx_count=378 at tip~16629
2. **Tip-height get_light_snapshot is cheap** (~2 KiB, <0.1s) on hub/observer when quiet — returns {checkpoint_hex,summary,tip_height} only.
3. **Path A checkpoint log on VPS** republished to **tip=16622** (73 entries); local mfn-node/testdata synced.
4. **Frontend** :3000/testnet reachable (200).

## Highest-signal findings (break / stress)

### F120 — Historical get_light_snapshot(height) stalls mfnd

Requesting a **non-tip** height (e.g. Path A log max 16468 / 16622 while tip is ahead) can hang the RPC for **>180–300s** even on-loopback. Concurrent callers then see proxy timeouts/502, hub tip timeouts, and observer lag.

**Mitigation:** tip-pin wallets from **current tip snapshot** instead of historical log max when F45 soft applies.

### F121 — Windows soft-pin twin crash (fixed)

light-scan-checkpoint-soft.ps1 double-quoted text containing (avoid …) made PowerShell treat (avoid as a subexpression. Fixed to single-quoted Write-Output.

### F122 — Faucet wallet UTXO bloat → 300s send timeout

/root/testnet-wallets/validator0-faucet.json at tip~16633: file **~10 MiB**, owned_count_cached=16388, pending_spent_count=480. HTTP faucet job timed out after 300000ms on wallet send (ring-size 16). Direct VPS retry with **600s** timeout also raised subprocess.TimeoutExpired on the same send while tip advanced 16633→16639 — fund path wedged on CLSAG against a bloated faucet wallet (not consensus stall).

### F123 — Observer proxy saturates under tall-tip snapshot storms

Under F120 load: public proxy timeouts then 502; /health still ok:true with rising index_errors. Do not treat proxy /health ok as RPC liveness during snapshot storms.

## Storm attempts

| Attempt | Path | Result |
| --- | --- | --- |
| A | Windows tunnel → observer bootstrap @ historical log max | hang (F120) |
| B | VPS old mfn-cli --checkpoint-log | hang (F120) |
| C | VPS tip-pin + HTTP faucet | tip-pin OK; faucet ERROR 300s (F122) |
| D | VPS tip-pin faucet + 600s direct wallet send | follow-up in log |
| Adv | Public proxy garbage/odd/stop | PASS fail-closed |


## Adversarial raw (public proxy)

`	ext
pre_tip=16629 mempool=0
garbage_deadbeef={"error":{"code":-32602,"message":"decode_transaction: transaction codec: short buffer: needed 1 more bytes"},"id":2,"jsonrpc":"2.0"}
odd_hex={"error":{"code":-32602,"message":"hex decode: Odd number of digits"},"id":3,"jsonrpc":"2.0"}
forbidden_stop=The remote server returned an error: (403) Forbidden.
tx_counts={"jsonrpc":"2.0","id":5,"result":{"tip_height":16629,"covered_heights":16629,"total_user_tx_count":378,"complete":true,"indexed_tip":16629,"cache_entries":16629}}
health_user_tx=378 tip=16629 index_errors=18
`

## Next

1. Faucet wallet hygiene / rotate (unblock invite-load).
2. Bootstrap helpers: prefer tip snapshot; never hammer historical heights on live hub.
3. Re-run dual-payment storm after faucet can fund; confirm proxy user tx count rises.
