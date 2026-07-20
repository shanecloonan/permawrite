# B-31 — live RPC/faucet threat posture (2026-07-20)

Lane **7** verify against [`PUBLIC_DEVNET_THREAT_MODEL.md`](../../../docs/PUBLIC_DEVNET_THREAT_MODEL.md) + Hetzner `5.161.201.73`.
**No** `faucet-http` restart; **no** parallel JOIN (lane 3 B-15 in flight). Repo head at probe: `2fd23f1` (includes B-29 `5dc3aa8`). VPS git: `02c8df8`.

## Verdict

| Check | Result | Notes |
| --- | --- | --- |
| RPC exposure | **PASS** | Hub/voters/observer RPC on `127.0.0.1:18731–18734` only; `public_bind=false`; external TCP `:18731` refused |
| Public P2P seeds | **FAIL** | `vps-bind.env` has `MFN_P2P_LISTEN_*=127.0.0.1:1900x` (example requires `0.0.0.0`); external `:19001–19003` connection refused; UFW still allows those ports |
| Observer proxy | **PASS** (read surface) | `:8787` public; `get_status` / tip OK; operator-admin / storage-proof submit denied at proxy |
| Faucet-HTTP | **PASS** (code on disk) | `faucet-http.mjs` uses TCP `peerIp` only (R-4); XFF not trusted. **B-26** still required to confirm deployed process == R-4 after B-15 window |
| Checkpoint log | **FAIL for join UX** | Schnorr verify OK (`entries=1`, `max_tip_height=3`); live tip ~4022 — **B-22** blocked on `MFN_CHECKPOINT_LOG_SIGNER_SEED_HEX` (not on VPS) |
| DoS / halt path | **PASS** (docs) | B-30 owner matrix + halt authority landed (`2f1b4e2`); human name cells remain TL-9 |

**Invite readiness:** do **not** circulate outside JOIN invites until P2P binds are repaired and B-22 publishes a near-tip checkpoint. Privacy/permanence veto applies (lane 7 halt path).

## Evidence detail

### RPC / binds (`ss -lntp`)

- `mfnd` RPC: `127.0.0.1:18731–18734`
- `mfnd` P2P: `127.0.0.1:19001–19004` — mismatch vs `vps-bind.env.example` (`0.0.0.0`)
- `observer-rpc-proxy` / `faucet-http`: `0.0.0.0:8787` / `:8788`

Hub `mfn-cli status` (local RPC): `tip_height≈4022`, `rpc.public_bind=false`, `p2p.listen_addr=127.0.0.1:19001`, local `session_count=3`.

### External reachability

| Port | From outside / self via public IP |
| --- | --- |
| 19001–19003 | **refused** |
| 18731 | **refused** (good) |
| 8787 / 8788 | **open** |

### Faucet R-4 markers (VPS tree `02c8df8`)

`scripts/public-devnet-v1/faucet-http.mjs`: comment + `peerIp(req)` — TCP peer only; never trust `X-Forwarded-For`.

### Checkpoint log

```text
mfn-cli checkpoint-log verify …/public_devnet_v1.checkpoints.jsonl
→ checkpoint_log_verify_ok entries=1 max_tip_height=3
```

VPS file SHA-256 matches repo: `ef8ebc0b53b534d6779f09efec314c7c7ea7a7ab55f015894feb8cabc5c9450e`.

### Observed during probe (do not disturb)

Two `fund-wallet-http` / JOIN rehearsal process trees under `/tmp/join-b15-*` (lane 3). Left untouched.

## Follow-ups (ordered)

1. **After B-15 §6 lock clears:** set `MFN_P2P_LISTEN_*=0.0.0.0:1900x` in VPS `vps-bind.env`; restart **mfnd-*** only (not faucet mid-capture); confirm outside TCP to `:19001`.
2. **B-22:** human loads `MFN_CHECKPOINT_LOG_SIGNER_SEED_HEX` → `publish-checkpoint-log.sh --rpc 127.0.0.1:18731 --apply` → commit updated JSONL.
3. **B-26:** `vps-update-faucet.sh` after B-15; re-check XFF spoof cannot skip IP cooldown.
4. **B-27 / TL-9:** only after P2P + checkpoint + Nightly (B-29) green.

## Sign-off flags impacted

- `--rpc-exposure-approved` — OK for loopback RPC; **not** OK to claim internet P2P until bind fix.
- `--threat-model-reviewed` — residual "P2P/RPC DoS" owner must treat **closed seeds** as halt for invites.
