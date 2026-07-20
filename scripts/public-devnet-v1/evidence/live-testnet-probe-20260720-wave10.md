# Live public testnet probe - wave 10 open (2026-07-20)

**Lane:** 3 (onboarding / B-15)
**UTC open:** 2026-07-20T04:04Z
**Prior:** wave9 `d3213a5`
**Public/local tip:** **4131** (matched)
**Checkpoint log:** entries=5 max_tip_height=**4057** (delta ~74 — worse than wave8)

## Snapshot at open

| Check | Result |
| --- | --- |
| Seeds 19001-19003 / 8787 / 8788 | OPEN |
| Front-end 80/443 | FAIL |
| Faucet | ok; tip-synced; busy=false |
| Proxy index | complete tip 4131; index_errors=4674 |
| CI | `#29715111633` in progress — docs `[skip ci]` only |

## In flight

1. Wallet status matrix (alice/bob/carol)
2. Tip soak + get_status p2p
3. New dave wallet: fund + B-50 python bootstrap + receive verify
4. Carol permanence upload (fresh file)
5. Re-check SPoRA pool / prove path
6. Document checkpoint lag growth (F45 severity+)
