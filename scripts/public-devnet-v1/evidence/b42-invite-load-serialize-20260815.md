# B-42 — Invite-load serialize-with-reason (2026-08-15)

**Lane:** 7 / Seat C
**never=** mfnd restart / faucet-http restart / parallel join-testnet-rehearsal

## Before / after (skeptic)

| Surface | Before | After |
| --- | --- | --- |
| invite-load -Apply | PASS (B-299) | **PASS** seeds 19001-19004 OPEN, faucet idle |
| Live JOIN x2 | not run | **serialized** — not started |
| get_light_snapshot @ ckpt 22475 | untried at this tip | observer **timeout 300s** |
| hub wallet send | worked in wave115 | **EAGAIN** (os error 11) after snapshot load |
| faucet-ops owned | 3 after wave115 refill | **1** (F7 1-input if HTTP fund) |
| Path A repo ckpt_max | 22467 | **22475** |
| last_proven newest | 22467 | **22467** (no new upload) |

Outsider verify: `powershell -File scripts/public-devnet-v1/invite-load-smoke-rehearsal.ps1 -Apply` PASS; public list_recent_uploads newest still 601cb854 last_proven=22467; repo jsonl max tip_height=22475.

## Reason

Default MFN_BOOTSTRAP_SNAPSHOT_TIMEOUT_SECS=300 was not enough at tip~22480. Snapshot hang then hub/observer EAGAIN. Did not restart mfnd/faucet. Did not run join-testnet-rehearsal.

## Not closed

Concurrent JOIN SUMMARY PASS. Retry when observer get_tip/snapshot is quiet. Live B-32 still distinct_hosts=1.
