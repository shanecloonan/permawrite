# Live public testnet probe - wave 12 findings (2026-07-20)

**Lane:** 3 (onboarding / B-15)
**UTC window:** ~04:24Z-04:28Z
**Prior:** wave11 `b0121b2` / open `ffd738e`
**Tip:** 4154 -> **4159+**
**Checkpoint:** entries=7 max_tip_height=**4148** (delta ~6-11)

## Executive verdict

| Gate | Result |
| --- | --- |
| Frontend :3000 | **PASS** — HTTP 200 landing; Next static chunks; docs links to JOIN/INVITE/OPERATORS |
| SPA routes `/join` `/faucet` `/rpc` | **404** (single-page marketing shell, not app routes) |
| F45 `light-scan --checkpoint-log` | **FAIL** exit 1 — no attestation at tip 4154 (log max 4148) |
| Eve catch-up `wallet balance` | **PASS** — scan 4154, owned=2, bal=1_000_000 |
| Eve permanence upload | **PASS** — Fresh tx `fcf8bc9b...`; commitment `129a34ce...` |
| Eve SPoRA prove | **PASS** — Fresh; **last_proven_height=4156** (settled!) |
| Eve post-upload send | **FAIL then PASS** — F71 WS mismatch; recover+re-pin; send 50k to dave |
| Dave after transfer | **550000** / owned=2 (prior 500k + 50k) |
| Eve after transfer | **938997** / owned=1 |
| F68 ps1 Apply | **FAIL** — plan claims python TCP (B-57) but embedded `python -c` here-string errors at line 3 |
| Tip soak | partial — proxy get_tip timed out once mid-script |

## Finding F71 (post-upload weak-subjectivity brick)

After eve upload (spent both UTXOs into upload+change), immediate `wallet send` failed:

```
weak-subjectivity: tip_height mismatch (trusted 4155 vs checkpoint 0)
```

Wallet state showed `scan_height=null` / empty owned while `trusted_light_summary.tip_height=4155` and a non-null `light_checkpoint_hex` that disagreed (B-29 class).

**Recovery:** re-pin via `get_light_snapshot(4148)` + `wallet balance` → balance **998997**, owned=2. Then send succeeded.

**JOIN implication:** upload→spend path needs explicit rescan/re-pin guidance; do not send immediately after upload if WS gate trips.

## Finding F72 (new upload SPoRA settlement works)

Eve upload `129a34ce...` reached `last_proven_height=**4156**` within minutes (tip ~4158). Wave7 alice upload `a20fcb43...` still stuck at **4071**. So settlement works for **new** proofs on current tip; old pool orphan remains stale (F70 narrowed).

## Finding F45 (still exact-tip)

Even with ckpt max only 6 behind tip, `light-scan --checkpoint-log` fails until an attestation exists **at the wallet tip**. Near-tip publish helps bootstrap pin, not the exit code of the JOIN-documented command while tip keeps moving.

## Finding F68b (B-57 python TCP Apply still broken on Windows)

`-PlanOnly` advertises `f68=snapshot via python TCP JSON-RPC`. `-Apply` still fails 8x with `File "<string>", line 3` — multiline `python -c $pySnap $args` here-string is not a reliable argv vehicle under Windows PowerShell. Needs temp `.py` file or `python - <<` equivalent.

## Finding F73 (B-55 frontend content)

Landing HTML (~30KB) includes:

- Brand/copy for Permawrite public testnet
- Links: JOIN_TESTNET, TESTNET_INVITE, CHECKPOINT_LOG, OPERATORS, GitHub issues
- Host string `5.161.201.73` embedded
- `/_next/static/chunks/*.js|css` assets
- No `__NEXT_DATA__` blob; `/join` `/faucet` `/api/*` return Next 404 HTML shell

Invite UX is **docs+CLI oriented**, not an in-browser wallet yet.

## Eve activity log

| Action | Result |
| --- | --- |
| upload | Fresh; tip 4155; fee 1003; artifact saved |
| prove | Fresh; pool_len=1; last_proven→4156 |
| send 50000→dave | Fresh tx `1a796453...` after F71 recovery |
| dave balance | 550000 |
| eve balance | 938997 |

## B-15 status

End-to-end outside-in loop for a tall-tip wallet now proven again: **pin → fund → receive → upload → prove (settled) → transfer**. Remaining JOIN archive blockers: F45 exact-tip exit code, F68b Windows Apply script, formal `join-testnet-rehearsal` SUMMARY.

**Ask lane 7:** write snapshot python to a temp file in `.ps1` (F68b); keep Path A ckpt within ~0-1 of tip if JOIN requires exit 0 on `--checkpoint-log`.