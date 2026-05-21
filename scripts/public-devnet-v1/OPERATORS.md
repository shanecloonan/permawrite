# Public devnet v1 — operator invite list (M2.4.3 / M2.4.4)

Join the **public-devnet-v1** network only if your node's `genesis_id` matches the manifest:

`7fef4492dba32d7ba652cceb5465cae86d6630a9e0a4855adf3acdc5f6b2a2df`

Use genesis file: [`mfn-node/testdata/public_devnet_v1.json`](../../mfn-node/testdata/public_devnet_v1.json).

## Seed nodes

Add your node's **public P2P listen address** (`host:port`, reachable from the internet or your LAN) to [`public_devnet_v1.manifest.json`](../../mfn-node/testdata/public_devnet_v1.manifest.json) under `seed_nodes`, then open a PR or post in the operator channel.

The manifest includes `seed_nodes_examples` (documentation only — `mfnd` ignores unknown JSON fields and reads only `seed_nodes`). Replace those placeholders with live addresses before publishing.

### Local mesh → published seeds

After `start-all.sh` / `start-all.ps1`:

1. Open `scripts/public-devnet-v1/devnet-ports.env` (see [`devnet-ports.example.env`](devnet-ports.example.env)).
2. Use `HUB_P2P` as `--p2p-dial` for committee voters (already wired in `start-voter.sh`).
3. When exposing validators on a LAN or VPS, bind P2P explicitly, e.g. `--p2p-listen 0.0.0.0:19001`, and append the **reachable** `host:port` to `seed_nodes` in the manifest.

Example manifest after three operators deploy:

```json
"seed_nodes": [
  "203.0.113.10:19001",
  "203.0.113.11:19002",
  "203.0.113.12:19003"
]
```

New peers should:

1. Build `mfnd` from this repository (or a release artifact with matching consensus).
2. Start with `--genesis` pointing at the canonical JSON (byte-identical file).
3. Boot peers: either rely on manifest `seed_nodes` (auto-merged from `public_devnet_v1.manifest.json` beside the genesis file — **M2.4.4**), and/or pass one or more `--p2p-dial host:port` flags (repeatable).
4. Verify `mfnd_chain_genesis_id=` on stdout matches the manifest; when boot peers are configured, `mfnd_p2p_boot_dials=` lists the merged dial set.
5. Run `health-check.sh` / `health-check.ps1` — all nodes must share the same `tip_height` and `tip_id` (**M2.4.6**).

## Roles

| Role | Flags | Notes |
|------|--------|--------|
| Hub | `serve --produce` | Usually validator index `0`. |
| Voter | `serve --committee-vote` | Indices `1` and `2`; set `MFND_VALIDATOR_INDEX` + seeds from genesis. |
| Observer | `serve` | No validator env; sync + RPC only. |

## Bootstrap scripts

From repo root (after `cargo build -p mfn-node --release --bin mfnd`):

| Platform | Command |
|----------|---------|
| Linux/macOS | `bash scripts/public-devnet-v1/start-all.sh` |
| Windows | `powershell -File scripts/public-devnet-v1/start-all.ps1` |

Health check: `health-check.sh` or `health-check.ps1` in the same directory (**M2.4.6** — exits non-zero if hub/voters diverge or `genesis_id` ≠ public devnet manifest).

Full runbook: [`docs/TESTNET.md`](../../docs/TESTNET.md).

## Firewall

| Port | Purpose |
|------|---------|
| P2P listen | Inbound peers (`--p2p-listen 0.0.0.0:PORT` for LAN/public; default loopback-only). |
| RPC listen | Wallets/operators (`--rpc-listen`); see [RPC exposure](#rpc-exposure-m248) below. |

## RPC exposure (M2.4.8)

`mfnd serve` exposes an **unauthenticated** JSON-RPC 2.0 line protocol on `--rpc-listen`. Any client that can open a TCP connection may:

- Read chain state (`get_tip`, `get_block`, `list_methods`, …)
- Submit transactions and storage proofs (`submit_tx`, `submit_storage_proof`, …)
- Inspect the mempool and proof pool

There is **no TLS and no API key** in v0.1 testnet builds.

| Deployment | Recommended bind | Rationale |
|------------|------------------|-----------|
| Local dev / CI | `127.0.0.1:0` (default) | OS-assigned port; not reachable from other hosts. |
| LAN validators | `127.0.0.1:PORT` + SSH tunnel for operators | Wallets/operators connect via tunnel; P2P still on `0.0.0.0` if needed. |
| Public VPS | **Do not** publish RPC to `0.0.0.0` | Use firewall deny on the RPC port; operators use VPN/SSH. P2P may be public. |

P2P and RPC are independent: you can advertise `mfnd_p2p_listening=` to the mesh while keeping RPC loopback-only.

Until RPC auth ships (post–public devnet hardening), treat `--rpc-listen 0.0.0.0` as **equivalent to root on the node** for chain control.

## Security

Validator seeds in the public genesis are **test keys only**. Do not use them on mainnet or with real funds.

Never commit wallet files, production seeds, or `peers.json` from private networks into public repos.

---

## Permanence operators (storage + SPoRA) — M6 / M7

Permawrite separates **on-chain anchors** (private `StorageCommitment` in a block) from **off-chain bytes** (chunk payloads). Validators only mine SPoRA proofs when they can read the challenged chunk. Operators run replication and proving on devnet today via `mfn-cli` and `mfn-storage-operator`.

Build both CLIs after `mfnd`:

```bash
cargo build -p mfn-node --release --bin mfnd
cargo build -p mfn-cli --release --bin mfn-cli
cargo build -p mfn-storage-operator --release --bin mfn-storage-operator
```

Point `--rpc` at any synced node's `mfnd_serve_listening=` address. Use the same `--wallet` file for upload, prove, and chunk commands.

### End-to-end flow

```text
wallet upload  →  tx mined (storage on-chain)
       ↓
replicate bytes to peers (HTTP and/or P2P ChunkV1)
       ↓
assemble local artifact  →  operator prove  →  SPoRA proof mined
```

| Stage | On-chain | Off-chain |
|-------|----------|-----------|
| Upload | Commitment + endowment in a block | `wallet.upload-artifacts/<hash>/` (payload + metadata) |
| Replicate | — | Peers hold matching chunk bytes |
| Prove | `StorageProof` in a later block | Operator uses artifact or inbox bytes |

### 1. Anchor data (any synced node)

```bash
mfn-cli --rpc 127.0.0.1:<RPC> wallet new   # once per operator
mfn-cli --rpc 127.0.0.1:<RPC> --wallet ./alice.json \
  wallet upload ./myfile.bin --fee 10000 --replication 3
```

Stdout includes `storage_commitment_hash=` and `upload_artifact_dir=`. Mine the mempool tx on a producer (stop `serve`, run `mfnd step`, or wait for the next sealed block on `--produce`).

Check status:

```bash
mfn-cli --rpc 127.0.0.1:<RPC> uploads list --limit 20
mfn-cli --rpc 127.0.0.1:<RPC> operator challenge <COMMIT_HASH_HEX>
```

### 2. Replicate chunk bytes

Pick **at least `replication` peers** (from the commitment) that store byte-identical chunks.

#### HTTP (M6) — good for observers and static fetch

On a machine that has the wallet artifact:

```bash
mfn-storage-operator serve-chunks --wallet ./alice.json --listen 127.0.0.1:18780
# GET http://127.0.0.1:18780/chunk/<commit_hex>/<index>
```

Or prove + serve in one process:

```bash
mfn-storage-operator run --once --chunk-listen 127.0.0.1:18780 \
  --wallet ./alice.json --rpc 127.0.0.1:<RPC>
```

Pull from a peer into the local artifact tree:

```bash
mfn-cli --rpc 127.0.0.1:<RPC> --wallet ./alice.json \
  operator fetch-chunk <COMMIT_HASH_HEX> 0 127.0.0.1:18780

mfn-cli --rpc 127.0.0.1:<RPC> --wallet ./alice.json \
  operator backfill <COMMIT_HASH_HEX> 127.0.0.1:18780 [more-peers...]
```

With multiple peers, `backfill` requires **byte-identical** chunks from every peer (quorum verify).

#### P2P ChunkV1 (M7) — good for `mfnd` mesh

Each `mfnd --data-dir` may contain:

```text
<data-dir>/chunk-inbox/<commit_hex>/<index>.bin
```

Push all artifact chunks over an existing P2P session (handshake + burst + `GossipEnd`):

```bash
# PEER is the remote mfnd_p2p_listening= host:port (not your own hub port)
mfn-cli --rpc 127.0.0.1:<HUB_RPC> --wallet ./alice.json \
  operator push-chunks <COMMIT_HASH_HEX> <PEER1> [PEER2 ...]

mfn-storage-operator push-chunks --wallet ./alice.json \
  <COMMIT_HASH_HEX> <PEER1> [PEER2 ...]
```

On the receiver (same `genesis_id`, caught up to the upload block):

```bash
mfn-cli --rpc 127.0.0.1:<REPLICA_RPC> operator inbox-status <COMMIT_HASH_HEX> /path/to/replica-data-dir
mfn-cli --rpc 127.0.0.1:<REPLICA_RPC> --wallet ./bob.json \
  operator assemble-inbox <COMMIT_HASH_HEX> /path/to/replica-data-dir
```

**Auto fan-out (M7.5):** When `mfnd` applies a block that adds **new** storage and already has a **complete** inbox for that commitment, it pushes `ChunkV1` to registered `peers.json` entries **and** live P2P sessions (after producer seal or inbound `BlockV1`). This does **not** run for wallet-only uploads until chunks are in the producer's inbox (usually via `push-chunks` to self or peers first).

**P2P catch-up:** Outbound `--p2p-dial` pulls missing blocks **before** blocking on gossip, so replicas can reach the upload height then receive chunks.

### 3. Submit SPoRA proof

Requires local bytes matching `data_root` (artifact or assembled inbox):

```bash
mfn-cli --rpc 127.0.0.1:<RPC> --wallet ./alice.json \
  operator prove <COMMIT_HASH_HEX>

# Or raw file (must match on-chain size_root):
mfn-cli --rpc 127.0.0.1:<RPC> operator prove <COMMIT_HASH_HEX> ./myfile.bin
```

One-shot operator loop:

```bash
mfn-storage-operator run --once --wallet ./alice.json --rpc 127.0.0.1:<RPC>
```

Inspect the node's proof mempool:

```bash
mfn-cli --rpc 127.0.0.1:<RPC> operator pool
```

After the proof is mined, `uploads list` should show a higher `last_proven_height`.

### Devnet mesh checklist

1. Start hub + voters ([bootstrap scripts](#bootstrap-scripts)); note each `mfnd_p2p_listening=`.
2. Upload on a wallet connected to the hub RPC; mine the tx.
3. `push-chunks` to two voter P2P ports (or HTTP `serve-chunks` on the uploader).
4. On each voter: `inbox-status` → `assemble-inbox` → `operator prove` when challenged.
5. Confirm identical payload hashes across peers before proving.

### CI reference (permanence)

| Test | What it proves |
|------|----------------|
| `mfn-cli` `chunk_p2p_smoke` | push → inbox → assemble → prove (single node) |
| `mfn-cli` `chunk_p2p_two_node_smoke` | hub mines, replica sync + push, matching payload |
| `mfn-cli` `chunk_p2p_three_node_smoke` | hub → two replicas via multi-peer `push-chunks` |
| `mfn-storage-operator` `chunk_http_smoke` | HTTP chunk serve matches artifact |

```bash
cargo test -p mfn-cli --release --test chunk_p2p_smoke --test chunk_p2p_two_node_smoke --test chunk_p2p_three_node_smoke
cargo test -p mfn-storage-operator --release --test chunk_http_smoke
```
