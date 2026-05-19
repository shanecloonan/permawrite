# M4 — WebAssembly bindings (`mfn-wasm`)

Browser hosts load the same Rust wallet and storage code as `mfn-wallet` / `mfn-cli`. JSON-RPC to a running `mfnd serve` stays in JavaScript; cryptography runs in WASM.

## Build

```bash
rustup target add wasm32-unknown-unknown
cargo build -p mfn-wasm --target wasm32-unknown-unknown --release --features wasm-full
```

For the browser demo (**M4.1**):

```bash
./scripts/build-wasm-demo.sh
# output: demo/web/pkg/
```

See [`demo/README.md`](../demo/README.md).

## JavaScript API

### M4.0 — keys + storage preview

| Export | Input | Output |
|--------|--------|--------|
| `walletAddressFromSeedHex` | 64-hex wallet seed | JSON `{"view_pub","spend_pub"}` |
| `claimPubkeyFromSeedHex` | same seed | 64-hex MFCL `claim_pubkey` |
| `storageUploadPreview` | `Uint8Array` payload, `replication` (u8) | JSON preview: `data_root`, `commitment_hash`, `required_endowment`, … |

### M4.2 — chain scan (`wasm-full` feature)

Build with `--features wasm-full`. Consensus wire decode + CLSAG scan run in WASM; BLS12-381 finality verification stays off-chain (nodes only).

| Export | Input | Output |
|--------|--------|--------|
| `scanTransactionHex` | seed hex, tx wire hex, block height, `string[]` owned key images | JSON: `tx_id`, `recovered[]`, `spent_key_images[]` |
| `scanBlockHex` | seed hex, block wire hex, owned key images | JSON: `height`, `txs[]`, `gross_received`, `matched_spent` |

Recovered outputs use [`StoredOwnedOutput`](../mfn-wallet/src/stored.rs) JSON (includes signing scalars for transfer build).

### M4.3 — CLSAG transfer build (`wasm-full`)

| Export | Input | Output |
|--------|--------|--------|
| `decoyPoolPreviewJson` | JSON array of `{height, one_time_addr_hex, commit_hex}`, exclude addrs | Sorted decoy pool JSON |
| `buildTransferJson` | Transfer plan JSON (see below) | `{tx_hex, tx_id}` |

Transfer plan shape:

```json
{
  "inputs": [ /* StoredOwnedOutput from scan */ ],
  "recipients": [{ "view_pub_hex": "…", "spend_pub_hex": "…", "value": 1000 }],
  "fee": 100,
  "ring_size": 4,
  "current_height": 12,
  "decoy_utxos": [{ "height": 1, "one_time_addr_hex": "…", "commit_hex": "…" }],
  "exclude_one_time_addrs_hex": [],
  "extra_hex": ""
}
```

`Σ inputs.value` must equal `Σ recipients.value + fee`. Supply decoys from chain UTXOs (checkpoint export, future RPC); exclude your own one-time addresses.

Seed format matches `wallet.json` (32 bytes, hex-encoded).

## CI

The `wasm32 build` job compiles `mfn-wasm` with **`wasm-full`** for `wasm32-unknown-unknown` and runs native unit tests on `mfn-wasm::core` + `scan_core`.

## Dependency cone

| Feature | Pulls | Use |
|---------|--------|-----|
| `wasm-keys` (default for smallest builds) | `mfn-wallet/wasm-keys` only | Address + claiming pubkey |
| `wasm-full` | `mfn-wallet/wasm-full` + `mfn-consensus` **without** `bls` | Browser scan / CLSAG path |

Native `mfn-cli` / nodes use `mfn-wallet/full` → `mfn-consensus` with **`bls`** (BLS12-381 finality).

## Browser demo (M4.1)

- Static UI: [`demo/web/`](../demo/web/)
- Dev RPC proxy: [`demo/proxy/rpc-proxy.mjs`](../demo/proxy/rpc-proxy.mjs) (POST `/rpc` → TCP `mfnd serve`)

## Node RPC for decoys (M4.4)

`mfnd serve` exposes **`list_utxos`**: paginated public UTXO rows (`height`, `one_time_addr_hex`, `commit_hex`) for gamma decoy pools. The demo **Load decoys from node** button calls `list_utxos` + `get_tip` and fills `decoy_utxos` / `current_height` in the transfer plan.

```json
{"jsonrpc":"2.0","method":"list_utxos","params":{"limit":500,"offset":0},"id":1}
```

## End-to-end browser transfer (M4.5)

With `wasm-full`, proxy, and `mfnd serve` running:

1. **`mfnd step`** (or sync blocks) so the chain has spendable UTXOs.
2. **`get_block`** at tip → paste `block_hex` → **scanBlockHex** → fills plan `inputs`.
3. **Load decoys from node** → `list_utxos` + `get_tip`.
4. **Build transfer** → WASM `buildTransferJson` → `tx_hex`.
5. **Submit to mempool** → RPC `submit_tx` → verify with **get_mempool**.

`submit_tx` params: `{"tx_hex":"<encode_transaction hex>"}`.

### M4.6 — storage upload (`wasm-full`)

| Export | Input | Output |
|--------|--------|--------|
| `uploadMinFee` | `data_len`, `replication`, `fee_to_treasury_bps` | JSON minimum fee (number) |
| `buildStorageUpload` | seed hex, payload bytes, upload plan JSON | `{tx_hex, tx_id, data_root, commitment_hash, burden, min_fee}` |

Upload plan shape (same decoy / input conventions as transfer):

```json
{
  "inputs": [ /* StoredOwnedOutput */ ],
  "anchor": { "view_pub_hex": "…", "spend_pub_hex": "…", "value": 1000 },
  "replication": 3,
  "fee": 50000,
  "ring_size": 4,
  "current_height": 12,
  "decoy_utxos": [ /* … */ ],
  "fee_to_treasury_bps": 9000,
  "message_hex": ""
}
```

Optional `message_hex` (UTF-8 as hex) attaches an MFCL authorship claim in `tx.extra`.

## Wallet sync (M4.7)

[`demo/web/wallet-sync.js`](../demo/web/wallet-sync.js) incrementally calls `get_block` for each height, runs `scanBlockHex`, tracks owned UTXOs and key images (with `localStorage` per seed). Use **Catch up to tip** in the demo after `mfnd step`.

## Chain params & one-click ready (M4.8)

RPC **`get_chain_params`** (no params) returns live `emission`, `endowment`, and `bonding` structs plus `treasury_base_units`, `tip_height`, and `mfn_base` / `mfn_decimals`. Wallets use `emission.fee_to_treasury_bps` when computing upload min fees.

Demo **Sync & ready (M4.8)** runs: `get_chain_params` → apply fee/replication bounds → catch-up scan → `list_utxos` decoy fill → refresh transfer/upload plans.

## Header-chain sync (M4.9)

RPC **`get_block_headers`** (`from_height`, `to_height`, max span 4096) returns compact header rows with `prev_block_id` for linkage checks. **`get_block_txs`** returns only transaction wire bytes for a height.

[`demo/web/header-sync.js`](../demo/web/header-sync.js) verifies the chain back to `genesis_id` before scanning. [`wallet-sync.js`](../demo/web/wallet-sync.js) uses `scanBlockTxsHex` instead of downloading full blocks.

## BLS header verification (M4.10)

`wasm-full` now enables `mfn-consensus/bls` in the browser (BLS12-381 via `bls12_381_plus` 0.8.18).

| Export | Role |
|--------|------|
| `verifyHeaderHex(header_hex, validators_json, consensus_json)` | Full `verify_header` (validator root + BLS finality) |
| `blockIdFromHeaderHex(header_hex)` | Recompute `block_id` locally; compare to RPC |

`get_chain_params` returns `validators` and `consensus` for the trusted set. Demo sync runs cryptographic verify on every header batch before tx scan.

## Validator-set evolution (M4.11)

| Export | Role |
|--------|------|
| `lightChainBootstrapCheckpoint(trust_json)` | Genesis checkpoint from `get_chain_params` |
| `lightChainVerifyHeader(checkpoint_hex, header_hex)` | BLS verify against evolving trusted set |
| `lightChainApplyEvolution(checkpoint_hex, header_hex, evolution_json)` | Apply slashings + bond ops; returns new checkpoint |

RPC **`get_block_evolution`** returns `slashings` / `bond_ops` wire hex. **`get_light_snapshot`** returns a follower checkpoint at the node tip (omit `params`) or at any `height ≤ tip` via block-log replay (`params`: `{"height": N}`).

Demo sync stores `permawrite-light-checkpoint:<seed>` in `localStorage` and advances it every block. If the wallet was scanned before but the checkpoint was cleared, sync resumes with `get_light_snapshot` at `lastScannedHeight` instead of genesis-trust bootstrap.

## Checkpoint resume (M4.12)

| RPC / export | Role |
|--------------|------|
| `get_light_snapshot` + `height` | Deterministic light checkpoint after block *N* (replays `chain.blocks` on the node) |
| `mfn_light::light_checkpoint_after_blocks` | Same replay primitive for tests / tooling |

Integration test `light_chain_trusted_evolution_matches_apply_block_on_rotation_chain` proves the browser path (`apply_header` + `apply_trusted_evolution`) matches full `apply_block` across register/unbond rotation.

## Roadmap

- **M4.13** — P2P header+bodies sync with weak-subjectivity checkpoints (less RPC trust).
