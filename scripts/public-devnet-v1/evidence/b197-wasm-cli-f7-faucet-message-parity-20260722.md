# B-197 — WASM/CLI F7 faucet dual-send error parity (2026-07-22)

- WASM transfer/upload JSON builders mention `faucet dual-send` on one-input rejects.
- CLI `map_wallet_build_err` rewrites `TxInputCountBelowMinimum` to the B-189 preflight text.
- PRIVACY + PRIVACY_HARDENING honesty: fail-closed stack (wallet/CLI/WASM/consensus).
- Privacy-floor smoke needles for WASM + `map_wallet_build_err`.
