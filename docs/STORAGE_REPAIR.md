# Operator stripe repair

An operator keeps one shard directory per commitment:

`{wallet}.upload-artifacts/{commit}/shard-00.bin` … `shard-11.bin`

The prove loop repairs that directory before it builds a proof when
`MFN_REPAIR_PEERS` is a comma-separated list of other operators' wallet
paths. The local operator id is the 32 raw bytes in
`{wallet_stem}.operator-id` next to the wallet file.

Each cycle:

1. Read the local shards. Fill any gap from a peer that still has that index.
2. If four or more shards are present, rebuild the file and write every missing `shard-NN.bin` plus `payload.bin`.
3. Seal each shard under the local operator id and the file's Merkle root (`shard-NN.seal`). Another operator's id does not open the seal.
4. If `challenge.bin` is present (84 bytes: posted height, data root, chunk index, operator index, refund point, deposit), write the matching chunk to `answer-chunk.bin`. The node still has to include that response. This crate does not edit the retrieval consensus files.

Four shards are enough. A test drops ten of operator A's shards, leaves the rest split across B and C, and checks that A recovers the plaintext, writes twelve seals, and answers the open challenge.

Header version 1 chains are unchanged. Repair does not post challenges and does not slash.
