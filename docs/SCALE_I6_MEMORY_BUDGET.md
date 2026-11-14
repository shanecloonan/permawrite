# I-6 memory budget

`MemoryBudget::for_device` sizes four caches for a 2 GiB phone or a 4 GiB
machine. The caps add up to at most 40% of that RAM. The rest is left for
the operating system and the on-disk permanence state.

`BodyCache` evicts the oldest unpinned block body when a new one does not
fit. A pinned body is not evicted. A single body larger than the cap is
rejected and the cache is left as it was. Pinned bodies that already fill
the cap cause the same refusal.

This cache is not the storage map and not the UTXO set. Those are not
evicted here.
