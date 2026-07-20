# Live public testnet probe — wave 13 findings (2026-07-20)

**Lane:** 3 (onboarding / B-15)
**UTC window:** ~04:28Z–04:52Z
**Prior:** wave12 `81ee789` / open `f98dc1b`
**Local observer:** `mfnd` on `127.0.0.1:18734` (data dir wiped mid-wave — see F74)
**Tip (close):** local **4175–4176** · proxy **4174–4175** (delta ≤1 after resync)
**Checkpoint log:** advanced during wave — max tip **4159 → 4173** (entries 8→10); Path A + second signer present

## Executive verdict

| Gate | Result |
| --- | --- |
| Local tip vs proxy after F74 wipe+resync | **PASS** — synced to tip ~4174 within ~4 min |
| F68b Windows bootstrap `-PlanOnly` | **PASS** (exit 0) |
| F68b Windows bootstrap without `-Apply` | **FAIL expected** — script now requires explicit `-PlanOnly` or `-Apply` |
| F68b Windows bootstrap `-Apply` (frank) | **PASS** — pin@4173, soft F45, status JSON OK |
| F45 exact-tip `light-scan --checkpoint-log` alone | **SOFT** — bootstrap soft-passes when tip races past attestation |
| Grace pin@4159 → receive verify (prior faucet) | **PASS** — `owned_count=2`, `balance=1_000_000` after divergent-store wipe |
| Tip soak (5×8s) | **PASS** — deltas `[-1,-1,0,0,0]`; proxy advanced +1 |
| Frontend `:3000/` and `/testnet` | **PASS** — HTTP 200, ~30 KB |
| SPA routes `/join` `/wallet` `/favicon.ico` | **404** (marketing shell; unchanged from F73) |
| Faucet `/health` | **PASS** — `ok:true`, wallet tip **4175**, `busy:false`, `pending_jobs:0` |
| Proxy `get_light_snapshot(4159)` | **PASS** — keys `checkpoint_hex`, `summary`, `tip_height` |
| Eve wallet post-resync | **PASS** — balance **938997**, owned=1 (matches wave12 post-send) |
| Eve `uploads status` | **PASS** — commitment `129a34ce…` matched; `last_proven_height=**4156**` still settled |
| Eve `operator challenge` | **PASS** — next_height **4177** for `129a34ce…` |
| Grace → dave transfer 100000 | **PASS** — Fresh tx `e252436a…`; fee 10000; ring_size 16 |
| Post-send balances (after F71 re-pin) | grace **890000**/owned=1; dave **650000**/owned=3 |
| F71 after grace send | **REPRO** — `trusted 4176 vs checkpoint 0`; re-pin@4173 recovers |

## Finding F74 — local tip divergence / peer quarantine (critical ops)

### Symptom
Mid-wave, local tip stuck at **4167** while proxy tip advanced to **4171**. P2P logs showed `sync_abort` / stale peer heights / peer quarantine (~300s). Catch-up dials failed; wallet scans could not see faucet UTXOs that existed on the real chain (grace fund job `done` but `owned_count=0`).

### Root cause (observed)
Local store had sealed a tip **ahead of / divergent from** seed tips. Peers offered blocks at heights the local node considered stale (e.g. peer sent ~4165 while local believed 4167). Quarantine then prevented healing.

### Recovery (reproduced)
1. Stop `mfnd`
2. Rename `live-testnet-data/` → `live-testnet-data-divergent-20260719-234040/` (not committed)
3. Fresh `mfnd` with same genesis + three public seed dials
4. Sync progress (sampled every 12s): tip 60→…→4160→**4174** in ~21 intervals (~4.2 min); final sample `local 4174 / proxy 4173` → **SYNCED**

### JOIN / B-15 implication
Outside-in observers on tall tips can silently fork-drift. Evidence checklists must compare **local tip vs proxy tip** before declaring receive-verify FAIL. Prefer wipe+resync over waiting out quarantine when delta grows and peers are quarantined.

**Ask lane 1/4:** whether B-51 (no ephemeral dial/quarantine) reduces this class of stall after VPS roll; wave13 local repro was pre-roll client store corruption/divergence, not hub.

## Finding F68b close — Windows `-Apply` now works (B-58)

Wave12 left F68b RED (`python -c` here-string line-3 errors). On this head (B-58 temp `.py` TCP snapshot):

```text
bootstrap-wallet-from-checkpoint-log.ps1 -Wallet frank.json -CheckpointLog … -Apply -Rpc 127.0.0.1:18734
→ log_max_tip=4173
→ snapshot_ok attempt=1
→ pinned scan_height=4173
→ checkpoint_log_verify_ok entries=10
→ light-scan-checkpoint-soft: F45 tip raced past attestation (log_max=4173)
→ light-scan-checkpoint-soft: PASS f45-soft
→ bootstrap-wallet-from-checkpoint-log: OK
exit 0
```

**Operator footgun:** omitting both `-PlanOnly` and `-Apply` exits 1 with `specify -PlanOnly or -Apply` (not a snapshot failure). Docs/JOIN should show the `-Apply` flag explicitly.

Frank after Apply: `owned_count=0` (never funded — bootstrap-only). Pin + soft scan path is green.

## Finding F45 — soft path vs exact-tip (delta-1 still soft)

Even with checkpoint max only **1–2** behind tip during parts of the wave, the JOIN-documented hard `wallet light-scan --checkpoint-log` still needs an attestation at the **exact** tip for exit 0. B-59/B-60 soft-pass in the bootstrap script is the workable Windows JOIN path today:

- Soft-pass message: re-publish Path A checkpoint (B-22) or re-pin for exact-tip F12
- Verdict recorded: `PASS f45-soft`

**B-15 honesty:** SUMMARY can cite bootstrap soft-pass + receive verify; do not claim hard `--checkpoint-log` exit 0 unless tip equals log max at scan time.

## Finding F67 confirmation — pin-then-scan recovers prior funds after wipe

Grace was funded earlier in wave13 (faucet job done, 2 txs) but showed `owned_count=0` while local tip was divergent (F74). After wipe+resync:

1. Python TCP `get_light_snapshot(4159)` pin into wallet (`scan_height`, `light_checkpoint_hex`, `trusted_light_summary`)
2. `wallet balance` → **immediately** `balance=1000000`, `owned_count=2`, `scan_height=4175`
3. Subsequent `wallet light-scan` — blocks_scanned=0, utxo_cache=true, same balances

So F67 remains: pin height must be **at or before** fund inclusion; funds at/after pin are found on scan. Divergent local tip was the false negative, not a missing faucet settle.

Grace address (for evidence cross-check, not a secret):
`mfc5190fa12b901c0aa507b8564add96e71bd3b71e56b3e72ca89c06cfbafe626341ee15c736518ce34460dc8b889f810c3c9bc76b97b94ad34ca4ad71918617ef8ae2d040`

## Tip soak + surface health

| Probe | Detail |
| --- | --- |
| Tip soak | 5 samples / 8s; local stayed 4175; proxy 4174→4175; deltas ≤1 |
| Faucet health | `wallet_scan_height=4175`, `wallet_tip_height=4175`, `wallet_blocks_behind=0`, dual-send config `amount_per_send=500000`, `sends=2`, `cooldown_ms=900000` |
| Frontend | `/` and `/testnet` 200 (~30019 bytes); `/join` `/wallet` 404 |
| Proxy light snapshot | OK at 4159 (pre-advance) and bootstrap used 4173 |

## Eve permanence wallet (continuity)

After resync, eve still holds wave12 post-transfer state: **938997** / owned=1. `uploads status --json`:

| commitment | last_proven | status |
| --- | --- | --- |
| `129a34ce…` (eve local) | **4156** | matched |
| `a20fcb43…` (alice wave7) | **4071** | chain_only (F70 still stale) |
| two ancient chain_only | 1915 / 1909 | unrelated history |

`operator challenge` for `129a34ce…` returns Fresh challenge at next_height **4177** — settlement path still live; no new prove attempted this wave.

## Finding F71 recurrence — post-send WS brick

Grace `wallet send` returned Fresh with `balance_after_send=0` / `owned_count_after_send=0` (change not yet visible under WS). Immediate follow-up `wallet balance` failed:

```text
weak-subjectivity: tip_height mismatch (trusted 4176 vs checkpoint 0)
```

Same class as wave12 post-upload (F71). Recovery: pin `get_light_snapshot(4173)` on grace+dave → grace **890000**, dave **650000** (prior 550k + 100k).

**JOIN note:** after any spend that empties the cached UTXO set, re-pin or `light-scan` before declaring balances; do not treat transient owned=0 as lost funds.

## Transfer activity log

| Action | Result |
| --- | --- |
| grace send 100000 → dave | Fresh tx `e252436a2bd9840e59dd785a8cb6de074b8281549bf6d0c329816da3d7a342c1` |
| tip at send | 4176 |
| grace after recover | 890000 (1_000_000 − 100_000 − 10_000) |
| dave after recover | 650000 (550_000 + 100_000) |

## B-15 status after wave13

| Outside-in step | Status |
| --- | --- |
| Seed dial + local sync | PASS (post F74 wipe) |
| Checkpoint bootstrap (Windows `.ps1 -Apply`) | **PASS** (F68b closed on this head) |
| F45 hard exact-tip | Still soft / tip-race |
| Pin → fund → receive | PASS (grace) |
| Upload → prove → transfer | PASS wave12 (eve); transfer PASS wave13 (grace→dave) |
| Formal `join-testnet-rehearsal` SUMMARY archive | Still open — prefer soft light-scan path (B-60); do not thrash Hetzner JOIN (§6) |
| Invite frontend as wallet | Not required — docs+CLI |

**Recommendation:** treat F68b as closed for B-15 Windows path; keep F45 soft-pass + F71 re-pin in JOIN copy; run SUMMARY when tip≈ckpt and local tip==proxy for ≥2 samples; always tip-diff check before wipe (F74).

## Artifacts (local only — not committed)

- `live-testnet-data-divergent-20260719-234040/` — pre-wipe divergent store
- `live-testnet-data-corrupt-20260719-230751/` — earlier corrupt backup
- `scripts/public-devnet-v1/user-wallet/{frank,grace,eve,dave}.json` — wallets
- `scripts/public-devnet-v1/evidence/_wave13-grace-send.json` — if transfer smoke lands in follow-up

## Session continuity

Next wave should: (1) grace→dave transfer smoke, (2) re-check eve `uploads status` / prove height, (3) attempt JOIN SUMMARY soft path without Hetzner parallel rehearsal, (4) re-verify F68b after any lane-7 mfnd roll (B-45/B-62).
