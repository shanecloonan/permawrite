# B-46 — tip-4031 ops hardening (lane 4)

Date: 2026-07-20 UTC
Host: 5.161.201.73
Code head on VPS: still `0efb23f` (pre **B-45** `f1459bf`)

## Symptoms (matched lane 3 wave4/5)

- Tip stuck at **4031** / `cdb54fa85473…` for extended windows
- Public observer proxy `http://5.161.201.73:8787/rpc` → **502** when `:18734` down
- Hub `get_tip` often timed out under restart storms; voters took **~2–4 min** of ~50–99% CPU before binding RPC

## Root causes

1. **`Requires=mfnd-hub.service` on voters/observer** — any `systemctl restart mfnd-hub` stopped the whole committee. Hub then quarantined `127.0.0.1:19102–19104` (~300s) for connection refused → vote fanout abort → tip freeze.
2. **Unquoted `Environment=MFN_P2P_DIAL_EXTRA=a b c`** — systemd ignored extra addresses (`Invalid environment assignment`).
3. **Parallel agent restart thrash** — hub stopped again at 02:38, 02:44, 02:51 while followers were still binding. Do **not** restart hub while voters show high CPU and no `:1873x` listen.
4. **Pre-B-45 binary** — `get_storage_challenge` error responses lack `operator_salted` fields (expected until lane 7 rolls `f1459bf`).

## Fixes applied

### Live VPS
- `Requires=` → `Wants=` on `mfnd-v1`, `mfnd-v2`, `mfnd-observer` (voters stayed up across hub restart 02:51:36)
- Quoted `MFN_P2P_DIAL_EXTRA` on `mfnd-hub.service`

### Repo (this unit)
- `vps-soften-mfnd-requires.sh` (idempotent; no restarts)
- `start-hub.sh` honors `MFN_P2P_DIAL_EXTRA` → `--p2p-dial`
- systemd unit templates: `Wants=mfnd-hub` + README note

## Tip recovery evidence (no further hub restart)

After mesh left alone with all four RPCs + socat 19001–19004 listening:

| UTC | tip_height | tip_id prefix |
| --- | ---: | --- |
| 02:54:05 | 4031 | cdb54fa85473e0a5 |
| 02:54:25 | 4032 | 285fca0b45f68461 |
| 02:55:05 | 4033 | 4d0e66d5598f40f6 |
| 02:55:19 | 4034 sealed | (hub journal `mfnd_producer_sealed height=4034 votes=2`) |

Hub journal also showed brief `mfnd_p2p_gossip_abort … os error 11` right after bind, then successful `proposal_vote_push` / seal. **Do not** interpret a short post-restart EAGAIN window as permanent stall — wait for produce+seal before thrashing restarts.

## Still open

- Lane 3: faucet EAGAIN on fund jobs (separate from tip production once tip moves)
- Lane 7: **B-45** mfnd roll after CI GREEN (no faucet restart)
- Lane 1: CI re-dispatch when Actions healthy (B-34)

## Do not

- Restart `faucet-http.service` during B-15
- `systemctl restart mfnd-hub` while followers are mid-bind or tip is already sealing