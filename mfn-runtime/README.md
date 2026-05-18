# `mfn-runtime`

In-process chain driver, mempool, and block-production helpers extracted from `mfn-node`.

- **`Chain`** — owns `ChainState`, applies blocks via `mfn-consensus::apply_block`.
- **`Mempool`** — admission, RBF, drain for `produce_solo_block`.
- **`producer`** — `build_proposal` / `vote_on_proposal` / `seal_proposal` / `produce_solo_block`.

No sockets or disk IO. Consumed by `mfn-node`, `mfn-rpc`, and integration tests.
