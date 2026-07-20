# Live public testnet probe - wave 20 findings (2026-07-20)

**Lane:** 3 (onboarding / B-15)
**UTC window:** ~08:05Z–08:40Z
**Prior:** wave19 `c36561d`
**Public tip (proxy/faucet):** **4282–4284** during close
**Local observer tip at close:** **4283** (divergent — see F88)
**Checkpoint log:** max tip **4262** (entries=11)

## Executive verdict

| Gate | Result |
| --- | --- |
| Soft bootstrap (frank, earlier wave20 open) | **PASS** (`soft_rc=0`) |
| F45 HARD `light-scan --checkpoint-log` @ tip 4271 / 4281 | **FAIL** — no attestation at exact tip (lag from ckpt 4262) |
| Grace recover after pin@4262 zero-balance | **PASS** pin@4173 → **947994 / owned=2** (F79 confirmed) |
| Peer fund judy→lisa (faucet 429 bypass) | **PASS** two Fresh sends → lisa **200000 / owned=2** |
| Lisa F45 HARD | **FAIL** (same class; tip 4281) |
| Lisa `wallet upload --message wave20-lisa-authorship` | **PASS** CLI `Fresh`; `authorship_claim=bound`; claim_message_len=22 |
| Lisa permanence (challenge / last_proven / claims-for) | **FAIL** — tx stuck in **local-only** mempool; never indexed on public tip (F88) |
| Local artifact retrieve | **PASS** 64B from wallet upload artifact |
| Karl claims index lag (F86 follow-up) | **PASS late** — `claims recent` now lists karl height **4270** (`53b5c837…`) |
| F85 RPC wedge | **REPRO** on `get_light_snapshot` after 2nd peer send; restart recovered briefly |
| Probe helper wallet corruption (F87) | **CONFIRMED** — `json.dump(path)` wrote string into karl/lisa; lisa recreated; karl spend keys lost |

## Finding F87 - probe pin helper corrupted wallet JSON

During wave20 open, a Python pin helper did `json.dump(w, f)` where `w` was the **path string**, not the wallet dict. Result: `karl.json` and `lisa.json` became JSON strings (invalid wallets).

| Wallet | Outcome |
| --- | --- |
| karl | On-chain evidence intact (upload `53b5c837…` proven **4270**); **local seed lost** unless backup exists |
| lisa | Recreated; later funded via judy peer-send |
| grace / judy / others | Unaffected |

**Ops rule:** pin helpers must `json.dump(wallet_dict, …)` only after `json.load` into a dict; assert `isinstance(wallet, dict)` before write.

## Finding F79 - pin-too-high hides older UTXOs (reconfirmed)

Grace after pin@**4262** (ckpt max): **balance=0**. Same wallet pin@**4173**: **947994 / owned=2**.

Light-scan starts at pin height; UTXOs created **before** the pin are invisible. Operators must pin at or below the oldest expected funding height (or re-pin older after faucet).

## Finding F45 HARD still fails at lag ~19–20

Checkpoint log max **4262**; live tip **4281+**. Error:

```text
…/public_devnet_v1.checkpoints.jsonl has no attestation at tip_height 4281
```

Soft bootstrap path remains the JOIN-safe path. Hard `--checkpoint-log` needs an attestation at the **exact** tip (or auto-bootstrap from log max — B-50 follow-up).

## Finding F85 - `get_light_snapshot` wedges local RPC under serial pin storms

After judy→lisa second send + dual pin@4173, local `mfnd` stopped answering TCP JSON-RPC (HTTP probe also failed). Restart **without wipe** recovered tip ~4281. Reinforces wave18: serialize pin/balance/snapshot calls; expect restart under load.

## Finding F88 - local observer tip diverge + upload stuck in orphan mempool

### Observed tip mismatch (same window)

| Source | tip_height | tip_id (prefix) | mempool |
| --- | --- | --- | --- |
| Local `127.0.0.1:18734` | **4283** | `f7436dfa…` | **1** (lisa upload `e64bb296…`) |
| Proxy `http://5.161.201.73:8787/rpc` | **4282** | `ffeaa747…` | **0** |
| Faucet `/health` wallet tip | **4284** | (synced) | n/a |

Local `get_status` showed `peer_count=3` but **`session_count=0`** while tip froze and mempool retained the upload.

### Lisa upload lifecycle

1. CLI returned `outcome=Fresh`, `tip_height=4281`, `mempool_len=1`, commitment `f3982772…`, `authorship_claim=bound`.
2. `uploads status` stayed **`local_only`** / `last_proven=null` for >3 minutes.
3. `operator challenge` / `operator prove`: `unknown storage commitment f3982772…` (never on canonical chain index).
4. `claims for` lisa `data_root` → `claim_count=0` (bound metadata not indexed because tx never settled).
5. `uploads retrieve` from **local artifact** → **64 bytes PASS** (artifact path works even when chain index missing).

**JOIN implication:** a “Fresh” upload on a diverged local observer is **not** permanence evidence. Always cross-check public tip_id / proxy `list_recent_uploads` before claiming settle. Prefer wipe+resync (F74) when tip_id diverges, then re-broadcast / re-upload.

**Related:** earlier wave13/14 F74 wipe pattern; wave19 restart-without-wipe worked only when tip_ids still matched.

## Finding F86 update - `claims recent` lag, not permanent empty

Wave19 reported empty `list_recent_claims` right after karl bound upload. Wave20 `claims recent` **does** list karl:

- height **4270**
- commit_hash `53b5c8375dfb5d64301a3bddd8296202897f35b2efaa119a3111bf7768d07e65`
- message_hex decodes to `wave19-karl-authorship`

So F86 narrows to **indexing lag / local fork blindness**, not “bound claims never appear.” Prefer `claims for DATA_ROOT` after tip_id match; allow minutes for recent index.

## Peer-fund path (faucet cooldown bypass)

Faucet returned **429** IP cooldown for lisa. Judy (owned=3) sent **100000** twice:

| Step | Result |
| --- | --- |
| judy→lisa #1 | Fresh; lisa **100000 / owned=1** |
| judy→lisa #2 | Fresh (`e3fa8884…` @ tip 4278); after restart+pin lisa **200000 / owned=2** |

Peer dual-send satisfies F7/F75 (owned≥2) without faucet when cooldown blocks JOIN.

## Permanence board (wave20)

| Commitment | Wallet | last_proven | Notes |
| --- | --- | --- | --- |
| `53b5c837…` | karl | **4270** | Still on `list_recent_uploads`; claims recent OK |
| `12a11d7d…` | grace | **4234** | Unchanged |
| `411bed87…` | judy | **4229** | Unchanged |
| `f3982772…` | lisa | **null** | Orphan local mempool only (F88) — **not** public permanence |

## JOIN micro-loop scorecard (cumulative)

| Wallet | Fund | F71 | Upload+message | Proven on public tip |
| --- | --- | --- | --- | --- |
| heidi | faucet | no | yes | yes (prior waves) |
| ivan | faucet | yes | yes | yes |
| judy | faucet | no | yes | yes |
| karl | faucet | yes | yes | **4270** |
| lisa | peer (judy) | n/a | CLI Fresh | **no** (F88 local fork) |

## Ops recommendations from this wave

1. Before any permanence claim: compare local `tip_id` to proxy `get_tip`.
2. If tip_id mismatch or `session_count=0` with frozen tip → wipe+resync (F74), do not keep uploading.
3. Pin ≤ oldest funding height (F79); clear `pending_spent_utxo_keys` on re-pin (F78).
4. Serialize `get_light_snapshot` / pin / balance (F85).
5. F45 HARD remains blocked until ckpt ≈ tip; use soft bootstrap for SUMMARY.
6. After bound upload, verify with proxy `list_recent_uploads` + `claims for` (allow lag for `claims recent`).

## Artifacts (local only — do not commit)

- `user-wallet/{lisa,judy,grace}.json` (+ lisa.upload-artifacts)
- `_wave20-results.json`, `_wave20-lisa-*.json`, `_wave20-judy-to-lisa-*.json`
- `_wave20-lisa-retrieve.bin` (64B local artifact)
- `live-testnet-data/` (divergent tip — wipe before wave21)

## Next (wave21)

1. Wipe local `live-testnet-data` and resync to public tip_id.
2. Re-fund lisa (or new wallet) on canonical tip; re-upload `--message`; prove via `operator challenge`/`prove`.
3. Draft B-15 JOIN SUMMARY from heidi/ivan/judy/karl (exclude lisa until public settle).
4. Request lane 7 near-tip checkpoint publish when lag > ~20 (F45).
