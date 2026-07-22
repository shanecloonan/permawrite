# B-185 — low-level F7 two-input fail-closed (2026-07-22)

- Added `WalletError::TxInputCountBelowMinimum`.
- `build_transfer` / `build_storage_upload` refuse `inputs.len() < WALLET_MIN_TX_INPUTS`.
- Local: spend::tests 5/5 PASS; upload::tests 14/14 PASS.
- Live tip at claim window ~5787 (public RPC).
- Aligns wallet low-level with consensus F7 + WASM B-168.
