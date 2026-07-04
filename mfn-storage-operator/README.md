# `mfn-storage-operator`

Long-running storage-operator daemon for Permawrite (**M6**). Answers SPoRA challenges for every upload artifact persisted by [`mfn-cli wallet upload`](../mfn-cli/README.md) (**M3.24**) and submits proofs via `submit_storage_proof` into the node's proof pool (**M3.22** / **M3.23**).

## Build

```bash
cargo build -p mfn-storage-operator --release
```

## Run

Requires a synced JSON-RPC endpoint (your own `mfnd serve` **or** a public observer) and local upload artifacts (`wallet upload`, `operator backfill`, or `uploads fetch-http`).

Optional network manifest (`--manifest` or `MFN_OPERATOR_MANIFEST`) supplies default `observer_rpc` and `replication_peers` from e.g. `mfn-node/testdata/public_devnet_v1.manifest.json`.

```bash
# Poll every 30s (default), prove all local artifacts
mfn-storage-operator run --wallet ./alice.json --rpc 127.0.0.1:18731

# RPC-only operator: public observer + manifest defaults
mfn-storage-operator run --wallet ./replica.json \
  --manifest mfn-node/testdata/public_devnet_v1.manifest.json

# Inspect manifest-derived RPC and replication peers
mfn-storage-operator manifest-info --manifest mfn-node/testdata/public_devnet_v1.manifest.json --json

# Auth-enabled node (same key as mfnd serve --rpc-api-key / MFND_RPC_API_KEY)
mfn-storage-operator run --wallet ./alice.json --rpc-api-key <KEY>

# Single cycle (cron-friendly)
mfn-storage-operator run --wallet ./alice.json --once

# Custom interval
mfn-storage-operator run --wallet ./alice.json --interval 60

# Prove loop + chunk HTTP in one process (**M6.4**)
mfn-storage-operator run --wallet ./alice.json --chunk-listen 127.0.0.1:18780
```

## Serve chunks (replication, **M6.2**)

Expose persisted upload payloads over minimal HTTP so peers can fetch raw chunk bytes:

```bash
mfn-storage-operator serve-chunks --wallet ./alice.json --listen 127.0.0.1:18780
# GET /chunk/{commitment_hash_hex}/{chunk_index}  -> application/octet-stream
```

Integration tests in `tests/chunk_http_smoke.rs`: **M6.3** `serve-chunks` and **M6.4** `run --once --chunk-listen` both return the same bytes as the saved artifact for `GET /chunk/.../0`.

## Fetch chunks from peers (**M6.5**)

Library [`fetch_chunk_http`](src/chunk_client.rs) and CLI:

```bash
mfn-cli --wallet ./alice.json operator fetch-chunk COMMIT_HEX 0 127.0.0.1:18780
```

With `--wallet`, bytes are checked against the local upload artifact slice.

## Push chunks to P2P peers (**M7.1**)

Use the standalone helper when an operator shell only needs wallet artifact fan-out and not the broader `mfn-cli` command surface:

```bash
mfn-storage-operator push-chunks --wallet ./alice.json COMMIT_HEX 127.0.0.1:18740 --json
```

Add `--json` to capture `peers_attempted`, `peers_ok`, `peers_failed`, and per-peer `chunks_sent` or error details for replication support records.

## Backfill artifacts from peers (**M6.6**)

Replica operators can pull the full anchored payload without re-uploading:

```bash
mfn-cli --rpc 127.0.0.1:18731 --wallet ./replica.json operator backfill COMMIT_HEX 127.0.0.1:18780
```

Uses `get_storage_challenge` for dimensions, fetches every chunk, verifies `data_root`, writes `payload.bin` + `meta.bytes`. Append `replace` to overwrite an existing artifact.

Stdout uses `mfno_*` lines for scripting (cycle boundaries, per-commitment outcomes). When `mfnd serve` gates RPC writes, pass `--rpc-api-key KEY` or set `MFN_RPC_API_KEY=KEY`; `submit_storage_proof` is classified as `wallet-write`.

## Library

Other tools can call [`run_prove_cycle`](src/daemon.rs) or [`prove_from_wallet_artifact`](src/prove.rs) directly. [`mfn-cli`](../mfn-cli) re-exports [`upload_artifact_store`](src/upload_artifact_store.rs) from this crate.

## Tests

```bash
cargo test -p mfn-storage-operator
```
