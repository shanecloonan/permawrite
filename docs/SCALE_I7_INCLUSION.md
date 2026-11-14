# I-7 light inclusion

`HeaderBook` admits a header only when its height and previous id
continue a trusted genesis id. `prove_tx` and `prove_utxo` then check a
Merkle or UTXO proof against that header's root.

A proof for a header id the book never admitted is refused. A proof
whose siblings do not reach the admitted root is refused. The book does
not send the caller's output set anywhere. The caller picks the proof
locally.

No consensus change. Path A and F-A are unchanged.
