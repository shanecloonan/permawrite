# `mfn-storage-operator`

Long-running storage-operator daemon for Permawrite (**M6**). Answers SPoRA challenges for every upload artifact persisted by [`mfn-cli wallet upload`](../mfn-cli/README.md) (**M3.24**) and submits proofs via `submit_storage_proof` into the node's proof pool (**M3.22** / **M3.23**).

## Build

```bash
cargo build -p mfn-storage-operator --release
```

## Run

Requires a running `mfnd serve` (JSON-RPC) and a wallet that has performed at least one `wallet upload` (so `wallet.upload-artifacts/` exists).

```bash
# Poll every 30s (default), prove all local artifacts
mfn-storage-operator run --wallet ./alice.json --rpc 127.0.0.1:18731

# Single cycle (cron-friendly)
mfn-storage-operator run --wallet ./alice.json --once

# Custom interval
mfn-storage-operator run --wallet ./alice.json --interval 60
```

## Serve chunks (replication, **M6.2**)

Expose persisted upload payloads over minimal HTTP so peers can fetch raw chunk bytes:

```bash
mfn-storage-operator serve-chunks --wallet ./alice.json --listen 127.0.0.1:18780
# GET /chunk/{commitment_hash_hex}/{chunk_index}  -> application/octet-stream
```

Stdout uses `mfno_*` lines for scripting (cycle boundaries, per-commitment outcomes).

## Library

Other tools can call [`run_prove_cycle`](src/daemon.rs) or [`prove_from_wallet_artifact`](src/prove.rs) directly. [`mfn-cli`](../mfn-cli) re-exports [`upload_artifact_store`](src/upload_artifact_store.rs) from this crate.

## Tests

```bash
cargo test -p mfn-storage-operator
```
