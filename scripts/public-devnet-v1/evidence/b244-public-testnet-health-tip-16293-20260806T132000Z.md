# B-244 — Public-testnet health after Path A tip-16293

**Unit:** B-244 (elevates B-138 / B-91 composite)
**When:** 2026-08-06T13:20:00Z (approx)
**Host:** Hetzner 5.161.201.73 (/root/permawrite @ f2fafe)
**B-15-safe:** no faucet-http / mfnd / proxy restart

## Command

`ash
bash scripts/public-devnet-v1/assert-public-testnet-health.sh --apply
`

## Result — PASS

| Check | Verdict |
| --- | --- |
| Path A near-tip timer | OK ctive last_result=success |
| Observer proxy /health | ok; hub_tip_rpc=127.0.0.1:18731; tip_align waits=0 timeouts=0 |
| Faucet /health | ok; usy=false pending_jobs=0 |
| Tip vs ckpt lag | tip=16294 ckpt_max=16293 **lag=1** (threshold=16) |
| Frontend :3000/testnet | HTTP 200 |

`
assert-public-testnet-health: OK
`

## Notes

- Follows **B-243** Path A republish (entries=49, tip=16293).
- Tip advanced one height during assert (16293 to 16294); lag remains within threshold.
- **B-42** invite-load held until lane3 B-15 clear (no parallel JOIN on Hetzner).
