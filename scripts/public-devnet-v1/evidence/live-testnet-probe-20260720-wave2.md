# Live public testnet probe - wave 2 findings (2026-07-20)

**Lane:** 3 (onboarding / B-15)
**UTC window:** ~2026-07-20T02:05Z-02:12Z
**Prior evidence:** [live-testnet-probe-20260720-wave1.md](./live-testnet-probe-20260720-wave1.md) (fca106)
**Cross-check:** lane-7 B-41 P2P bind repair appears in progress during this window

## Executive verdict

| Check | Wave 1 (~01:47Z) | Wave 2 (~02:07Z) |
| --- | --- | --- |
| TCP 19001-19003 | FAIL | **OPEN** (all three) |
| Outside mfnd dial | peer_count=0, tip=0 | **mfnd_p2p_dial_ok=5.161.201.73:19001**, peer tip 4028, sync started |
| Local tip catch-up | stuck 0 | **climbing** (observed 0 → 916 → 1175+ within ~30s) |
| Observer proxy get_tip | PASS | **502** ECONNREFUSED 127.0.0.1:18734 (observer RPC down mid-repair) |
| Proxy /health | index_errors=0 | index_errors climbing (993 → 1062); tip frozen at 4028 |
| Faucet /health | wallet near tip | wallet_scan_height=null (hub RPC likely restarted / not ready) |

**Finding F15 (SUCCESS - B-41 outside-in confirm):** After wave-1 blocker (loopback P2P binds), public seed ports accept TCP and an outside Windows mfnd completes handshake + begins full sync from tip 0 toward ~4028. This is the missing JOIN Step 2-3 prerequisite.

**Finding F16 (OPS - expected during repair):** Public observer proxy returns HTTP 502 while VPS observer mfnd RPC is down. /health still reports ok:true with a stale index - **do not treat proxy /health ok as chain RPC liveness** during restarts. Faucet health losing wallet height fields indicates hub RPC churn.

## Evidence detail

### P2P port transition

| Time (UTC) | 19001 | 19002 | 19003 | Notes |
| --- | --- | --- | --- | --- |
| Wave 1 | FAIL | FAIL | FAIL | Loopback binds (B-31) |
| 02:07:45 | OPEN | OPEN | OPEN | First full-open recheck |
| 02:08:07-02:09:55 | OPEN | OPEN* | OPEN | *one sample 19002 FAIL briefly |

### Outside dial / sync (local mfnd restart)

`	ext
mfnd_p2p_boot_dials=5.161.201.73:19001,5.161.201.73:19002,5.161.201.73:19003
mfnd_p2p_dial_ok=5.161.201.73:19001
mfnd_p2p_peer_tip ... height=4028 tip_id=0dde4cbd46ab6c90...
mfnd_p2p_sync_start ... local_height=0 remote_height=4028
`

Status shortly after dial: peers=1 sessions=1 tip=0 (sync in flight).
~1-2 minutes later: 	ip_height=916 then 1175 with peers=1.

### Proxy / faucet during repair

- POST /rpc get_tip → **502** Error: connect ECONNREFUSED 127.0.0.1:18734
- GET /health → ok:true but index_errors rising; tip stuck **4028**
- Faucet health: wallet_* fields **null** (RPC to hub not reporting scan state)

## Implications for B-15

1. Wave-1 **P2P blocker is clearing** - full JOIN rehearsal can resume once:
   - local tip approaches live tip, and
   - faucet + observer proxy RPC backends are healthy again.
2. Keep **faucet-http lock** until a clean fund+light-scan PASS is archived (do not restart faucet mid-job).
3. Document that /health ok on the proxy is insufficient during mfnd restarts (F16).

## Next (wave 3)

- Wait for local tip ≈ remote tip
- Re-check proxy get_tip and faucet wallet heights
- Run wallet light-scan --checkpoint-log on faucet-funded alice wallet (job from wave 1)
- Attempt join-testnet-rehearsal path (PowerShell-native or Git Bash)
