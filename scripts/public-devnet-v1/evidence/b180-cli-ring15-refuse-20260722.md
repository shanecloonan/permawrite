# B-180 follow-up live prove — CLI refuse ring-size 15 (2026-07-22)

`mfn-cli wallet send ... --ring-size 15` fail-closed before network:

```
ring-size must be at least 16 (consensus minimum)
```

Public tip was ~5727 at B-180 land. Next honesty polish (B-181): align parse error text with B-167 `wallet/consensus floor` wording if still drifted.