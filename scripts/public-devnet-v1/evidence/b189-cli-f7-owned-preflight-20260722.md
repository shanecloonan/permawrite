# B-189 — CLI F7 owned-UTXO preflight (2026-07-22)

- `require_f7_owned_input_floor` on `wallet send` / `wallet upload` after sync.
- Actionable Usage error when `owned < WALLET_MIN_TX_INPUTS` (mentions faucet dual-send).
- Unit: `require_f7_owned_input_floor_rejects_below_two`.
- Elevates B-186 high-level fail-closed into operator-facing CLI UX.
- Lane4 owns B-190 (tenth→asymmetric); this ID stays lane5.
