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

## Roadmap

- **M4.3** — In-browser CLSAG `build_transfer` + demo wiring (decoy pool from light-client / RPC).
