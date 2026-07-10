# `mfn-wasm`

WebAssembly bindings for Permawrite wallet, storage, transfer, scan, and light-verification primitives. The crate exposes the same Rust implementation used by `mfn-wallet` and `mfn-cli` through `wasm-bindgen` so browser demos and future web wallets do not fork protocol logic.

Network IO stays outside this crate. JavaScript is expected to fetch JSON-RPC data from `mfnd serve`; `mfn-wasm` handles deterministic cryptography, wallet derivation, transaction/upload construction, block scanning, and light-client verification.

## Features

- `wasm-keys` (default): wallet address derivation, claiming pubkey derivation, and storage-upload preview helpers.
- `wasm-full`: transfer construction, block/transaction scanning, storage-upload construction, BLS header verification, light-chain checkpoint/evolution helpers, quorum checks, weak-subjectivity summary helpers, and signed checkpoint log verify/cross-check (**F12** phase 3).

## Public Bindings

Core exports include:

- `wasm_wallet_address_from_seed_hex`
- `wasm_claim_pubkey_from_seed_hex`
- `wasm_storage_upload_preview`

With `wasm-full`, additional exports include:

- `wasm_build_transfer_json`
- `wasm_build_storage_upload`
- `wasm_scan_block_hex`
- `wasm_scan_block_txs_hex`
- `wasm_scan_transaction_hex`
- `wasm_verify_header_hex`
- `wasm_light_chain_verify_header`
- `wasm_light_chain_apply_evolution`
- `wasm_build_storage_proof` / `buildStorageProof` — SPoRA proof construction (same path as CLI)
- `wasm_verify_storage_proof` / `verifyStorageProof` — SPoRA proof verification
- `wasm_storage_chunk_hex` / `storageChunkHex` — extract one Merkle chunk for HTTP replication
- `wasm_light_follow_quorum_json`
- `wasm_checkpoint_log_verify` / `checkpointLogVerify` — verify signed checkpoint log JSONL (**F12** phase 3)
- `wasm_checkpoint_log_cross_check` / `checkpointLogCrossCheck` — cross-check summary vs log (**F12** phase 3)

## Build

`mfn-wasm/Cargo.toml` sets `[package.metadata.wasm-pack.profile.release] wasm-opt = false` and CI uses `wasm-pack --no-opt` so `scripts/ci-check` and GHA wasm32 builds succeed without Binaryen download flakes.

```bash
wasm-pack --log-level warn build mfn-wasm --target web --out-dir demo/web/pkg --release --features wasm-full
```

The CI mirror checks the `wasm32-unknown-unknown` build path and the `wasm-pack` package build. Treat these bindings as devnet-grade and pre-audit, matching the rest of the repository.
