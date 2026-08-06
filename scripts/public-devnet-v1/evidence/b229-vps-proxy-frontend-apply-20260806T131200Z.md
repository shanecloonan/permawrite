# B-229 VPS apply — observer proxy + testnet frontend (2026-08-06)

## Unit

Lane 7: deploy B-229 tall-tip header cache proxy + rebuild public testnet frontend on Hetzner.

## Host

- VPS: 5.161.201.73 (moneyfund)
- Repo: /root/permawrite @ 19301d (then evidence commit)

## Apply steps (B-15-safe)

1. git stash local checkpoint/next-env dirt; git pull --ff-only origin main
2. ash scripts/public-devnet-v1/vps-update-observer-rpc-proxy.sh --apply (restarts observer-rpc-proxy only)
3. Frontend rebuild hit OOM on 
pm ci (1.9 GiB RAM, 0 swap) -> added /swapfile 2G + fstab; then 
pm ci + 
pm run build + restart 	estnet-frontend
4. **Never** restarted aucet-http / mfnd-*

## Post-apply verification

| Check | Result |
| --- | --- |
| observer-rpc-proxy | active |
| 	estnet-frontend | active; http://127.0.0.1:3000/testnet -> 200 |
| aucet-http | active (untouched) |
| mfnd-hub | active (untouched) |
| proxy /health | ok=true, heavy_rpc_timeout_ms=180000 |
| tip index | tip_height **16290** |
| header cache | entries=65, hits=146, misses=2, upstream=2 (post-restart warm) |
| swap | /swapfile 2G enabled + fstab (needed for Next build on 2G VPS) |

## Public URLs

- Observer proxy: http://5.161.201.73:8787/rpc (+ /health)
- Testnet frontend: http://5.161.201.73:3000/testnet

## Notes

- Pre-apply health already showed header_cache_* fields (prior partial deploy); apply refreshed units to tip 19301d and rebuilt frontend with B-229 poll/timeout changes.
- Local stash on VPS: lane7-b229-pre-pull (checkpoints jsonl + next-env.d.ts) — not restored; Path A / frontend env can be re-checked next ops pass.
