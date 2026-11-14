# Shard stripes (header version 9)

Path A and F-A stay on header version 1. Their uploads are still one size-bucket payload. A chain whose header version is **9 or higher** accepts a new storage commitment only when it is exactly 12 equal shards.

## Layout

| Shards | Role |
| --- | --- |
| 0..3 | Data. The file, with an 8-byte length prefix, split across these four. |
| 4..11 | Parity. Any 4 of the 12 shards rebuild the file. |

`chunk_size` is the shard length (a power of two, at least 32). `num_chunks` is 12. `size_bytes` is `12 * chunk_size`. `data_root` is the Merkle root of those 12 shard hashes, so a SPoRA proof of chunk `i` is a proof that the operator holds shard `i`.

Version 8 is unused here so Seat B can take it. The constant is [`HEADER_VERSION_SHARDS`](../mfn-storage/src/stripe.rs).

## What runs

`wallet upload FILE --sharded` builds the stripe, anchors it, and writes `shard-00.bin` … `shard-11.bin` next to `payload.bin`. A chain whose `header_version` is 9 or higher stripes every upload, with or without the flag. Header version 1 does not. The operator prove loop and chunk server already read the commitment's `chunk_size`, so they serve and prove individual shards.

Header version 1 mempool and `apply_block` still use the size-bucket check. Header version 9 uses the 12-shard check in both places.

## Recovery

Drop any 8 shards. `open_shard_stripe` rebuilds the file from the rest. A string that is not a consistent code is not treated as a stripe.
