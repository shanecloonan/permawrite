# Live public testnet ops battery - wave 49b (2026-07-20)

**Lane:** 3 — faucet-cooldown filler after wave49 paula PASS
**UTC:** 2026-07-20T22:18Z

## Results

| Check | Result |
| --- | --- |
| tip_id match at open | False @ L4696 |
| mempool | 0 |
| Ports 19001-03/8787/8788/3000 | {'19001': 'OPEN', '19002': 'OPEN', '19003': 'OPEN', '8787': 'OPEN', '8788': 'OPEN', '3000': 'OPEN'} |
| FE / /testnet /join | 200 / 200 / HTTP Error 404: Not Found |
| Path A ckpt_max | 4679 |
| F45 lag | 16 |
| F45 hard light-scan | rc=-1 in 60.5s (TIMEOUT 60s) |
| get_block_headers near tip | True |
| claims/uploads totals | 24 / 36 |

## Tip flap sample (6s cadence)

```
[
  {
    "i": 0,
    "L": "4696",
    "P": 4695,
    "match": false,
    "mem": "0"
  },
  {
    "i": 1,
    "L": "4696",
    "P": 4695,
    "match": false,
    "mem": "0"
  },
  {
    "i": 2,
    "L": "4696",
    "P": 4695,
    "match": false,
    "mem": "0"
  },
  {
    "i": 3,
    "L": "4696",
    "P": 4695,
    "match": false,
    "mem": "0"
  },
  {
    "i": 4,
    "L": "4696",
    "P": 4695,
    "match": false,
    "mem": "0"
  }
]
```

## Finding

Hard checkpoint-log scan still TIMED OUT at 60s with Path A only **16** blocks behind tip — confirms F45 is not only large-lag; even single-digit lag can exceed soft JOIN's 60s budget on this Windows observer.

