# B-161 live prove — heavy CLI snapshot timeout (2026-07-21)

| Field | Value |
| --- | --- |
| Unit | B-161 (lane 5) — B-52 client twin + in-CLI F45 soft |
| Prior CI | #29878259419 GREEN on B-158/B-50 tip |
| Needle | checkpoint_log_auto_bootstrap tip=5463 |
| Soft | checkpoint_log_f45_soft_pass log_max=5463 wallet_tip=5474 |
| Final wallet | scan_height=5474 + light_checkpoint_hex set |
| Elapsed | ~80–115s (aborts at old 30s io_timeout) |
| VPS snapshot preflight tip=5434 | ~64.5s |
| Override | MFN_HEAVY_RPC_TIMEOUT_MS (default 180000) |

B-50 tall-tip JOIN auto-bootstrap is live-viable without the bash soft wrapper.
