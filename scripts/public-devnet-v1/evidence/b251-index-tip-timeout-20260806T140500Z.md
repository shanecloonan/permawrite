# B-251 — observer index tip timeout under tall-tip load (2026-08-06)

## Symptom

During B-250 cold-wallet bootstrap (get_light_snapshot on observer), observer-rpc-proxy logged:

`
index tip: mfnd RPC timeout after 30000ms
`

five times in ~2 minutes. /health showed index_errors rising while 
pc_timeout_ms=30000 and heavy_rpc_timeout_ms=180000. Background index get_tip shared the short browser RPC budget.

## Fix

- PROXY_INDEX_TIP_TIMEOUT_MS (default **90000**) for indexTick get_tip only.
- /health exposes index_tip_timeout_ms.
- systemd unit sets PROXY_INDEX_TIP_TIMEOUT_MS=90000.
- Deploy helper asserts health field >= 90000.
- Tip-align rehearsal smoke needles (.sh / .ps1).

B-15-safe: restarts **observer-rpc-proxy** only (never faucet/mfnd).

## Prove

Local: 
ode --check observer-rpc-proxy.mjs; tip-align rehearsal smoke PASS plan-only.

VPS (moneyfund): after ps-update-observer-rpc-proxy.sh --apply — index_tip_timeout_ms=90000; proxy-only restart; faucet/mfnd untouched.
