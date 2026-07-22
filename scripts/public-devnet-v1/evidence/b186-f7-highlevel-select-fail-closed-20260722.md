# B-186 — high-level F7 two-input fail-closed (2026-07-22)

- `Wallet::select_inputs_for_tx` returns `WalletError::TxInputCountBelowMinimum` when pad cannot reach `WALLET_MIN_TX_INPUTS`.
- Closes the gap where high-level selection returned a one-input plan and only failed later inside low-level `build_transfer` (**B-185**).
- Unit: `select_inputs_for_tx_single_utxo_fails_closed`.
- PRIVACY.md honesty: reference wallet fails closed on single-UTXO spends (faucet dual-send remains required).
- Privacy-floor smoke needles for `wallet.rs` selection path.
