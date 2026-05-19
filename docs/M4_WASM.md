# M4 — WebAssembly bindings (`mfn-wasm`)

Browser hosts load the same Rust wallet and storage code as `mfn-wallet` / `mfn-cli`. JSON-RPC to a running `mfnd serve` stays in JavaScript; cryptography runs in WASM.

## Build

```bash
rustup target add wasm32-unknown-unknown
cargo build -p mfn-wasm --target wasm32-unknown-unknown --release
```

For the browser demo (**M4.1**):

```bash
./scripts/build-wasm-demo.sh
# output: demo/web/pkg/
```

See [`demo/README.md`](../demo/README.md).

## JavaScript API (M4.0)

| Export | Input | Output |
|--------|--------|--------|
| `walletAddressFromSeedHex` | 64-hex wallet seed | JSON `{"view_pub","spend_pub"}` |
| `claimPubkeyFromSeedHex` | same seed | 64-hex MFCL `claim_pubkey` |
| `storageUploadPreview` | `Uint8Array` payload, `replication` (u8) | JSON preview: `data_root`, `commitment_hash`, `required_endowment`, … |

Seed format matches `wallet.json` (32 bytes, hex-encoded).

## CI

The `wasm32 build` job in [`.github/workflows/ci.yml`](../.github/workflows/ci.yml) compiles `mfn-wasm` for `wasm32-unknown-unknown` and runs native unit tests on `mfn-wasm::core`.

## Dependency cone

`mfn-wasm` depends on `mfn-wallet` with the **`wasm-keys`** feature (stealth keys + claiming identity only). That avoids pulling `mfn-consensus` / BLS12-381 into the browser build. Full wallet signing remains on the native `full` feature (default for `mfn-cli`).

## Browser demo (M4.1)

- Static UI: [`demo/web/`](../demo/web/)
- Dev RPC proxy: [`demo/proxy/rpc-proxy.mjs`](../demo/proxy/rpc-proxy.mjs) (POST `/rpc` → TCP `mfnd serve`)

## Roadmap

- **M4.2** — CLSAG transfer / chain scan in WASM (enable `mfn-wallet/full` once BLS builds cleanly on `wasm32`).
