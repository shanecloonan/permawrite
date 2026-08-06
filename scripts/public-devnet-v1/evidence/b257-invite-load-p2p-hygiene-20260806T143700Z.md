# B-257 invite-load preflight p2p-forward hygiene (2026-08-06)

## Unit
Lane 7: elevate B-248 invite-load preflight with B-254/255-class p2p-forward hygiene before B-42 live JOIN.

## Changes
- `invite-load-smoke-rehearsal.sh`: on-host `systemctl` checks (failed `mfn-p2p-forward@*` + dedicated hub/19002-19004); outside-in TCP :19004 when no systemd
- python3/python/py PATH fallback (Windows Git Bash)
- `.ps1` twin needles + native :19004 check
- OPERATORS table note

## Live prove
- VPS `--apply` PASS tip~16332: p2p-forward@ clean; hub/19002/19003/19004 active; serialize-with-reason=need_--live_flag
  evidence `invite-load-preflight-20260806T143615Z.txt`
- Outside-in Windows: proxy/faucet ok tip=16333; seeds 19001-19004 OPEN

## Never
JOIN during B-15; faucet/mfnd restart; fake B-32 READY

## Verdict
PASS — B-42 day-of preflight now fails closed on broken P2P forwards.