# Shard assignment

Shard `i` is stored by operator `i % operator_count`.

Set `MFN_OPERATOR_INDEX` and `MFN_OPERATOR_COUNT` on the operator daemon. At the start of each prove cycle it deletes shard files that belong to another operator.

With six operators, each keeps two shards. Any two operators hold four shards, which rebuilds the file. One operator does not. A test drops four of the six and still opens the plaintext.
