# B-13 pre-enable treasury telemetry baseline (**B-33**)

Captured **20260806T052834Z** against public Path A observer proxy (read-only).
Purpose: archive `treasury_base_units` + emission knobs **before** any
`subsidy_to_treasury_bps = 1000` enable (**B-13c**). Does **not** change genesis.

## Source

| Field | Value |
| --- | --- |
| RPC | `http://5.161.201.73:8787/rpc` (observer-rpc-proxy public-safe) |
| Health backend | `127.0.0.1:18734` |
| Health hub_tip_rpc | `127.0.0.1:18731` |
| Health ok | `True` |
| Method | `get_chain_params` + `get_tip` |
| Docs SHA (local capture) | `c22e4277` (B-33 UTF-8 fix; B-13a sims `bbd50ce3`) |

## Chain params (live)

| Field | Value |
| --- | --- |
| genesis_id | `454fa5d4a9bd6f59e35cf9ea7e68c096c9a271a92b2ec5931184e7f34a42a005` |
| tip_height | 16063 |
| tip_id | `314d6f57d848c989757f4cb1b8d5d748541950a5c26ab1725bdc29ed1785fbf6` |
| treasury_base_units | 2909711 |
| fee_to_treasury_bps | 9000 |
| subsidy_to_treasury_bps | 0 |
| storage_proof_reward | 10000000 |
| initial_reward | 5000000000 |
| tail_emission | 19531250 |
| validator_count | 3 |
| mempool_len | 0 |

## B-33 interpretation

- `subsidy_to_treasury_bps = 0` confirms Path A has **not** enabled the F6 tail split yet.
- `fee_to_treasury_bps = 9000` must stay unchanged in the same fork (one-lever rule).
- Treasury non-zero (`2909711`) at tip 16063 — baseline for post-enable comparison.
- Backstop rate is not a direct `get_chain_params` field; revisit via FEES.md section 5.4 + `treasury-telemetry-watch` after enable.

## Raw JSON (trimmed)

```json
{
  "get_chain_params": {
    "genesis_id": "454fa5d4a9bd6f59e35cf9ea7e68c096c9a271a92b2ec5931184e7f34a42a005",
    "tip_height": 16063,
    "treasury_base_units": "2909711",
    "emission": {
      "fee_to_treasury_bps": 9000,
      "halving_count": 8,
      "halving_period": 8000000,
      "initial_reward": 5000000000,
      "storage_proof_reward": 10000000,
      "subsidy_to_treasury_bps": 0,
      "tail_emission": 19531250
    }
  },
  "get_tip": {
    "genesis_id": "454fa5d4a9bd6f59e35cf9ea7e68c096c9a271a92b2ec5931184e7f34a42a005",
    "mempool_len": 0,
    "mempool_root": "d5cb622470ed1f504eeb058970fc71b03468392c90aef4b0b3a728c0615aaffe",
    "tip_height": 16063,
    "tip_id": "314d6f57d848c989757f4cb1b8d5d748541950a5c26ab1725bdc29ed1785fbf6",
    "validator_count": 3
  },
  "health": {
    "ok": true,
    "backend": "127.0.0.1:18734",
    "hub_tip_rpc": "127.0.0.1:18731",
    "index_tip_height": 16063
  }
}
```
