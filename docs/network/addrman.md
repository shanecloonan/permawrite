# Address manager

Learned peer addresses sit in 64 `new` buckets. A successful dial moves the
address into one of 32 `tried` buckets. The bucket is a hash of a local key
and the IPv4 /16 (or the whole host for an overlay name), with 8 slots each.
One /16 therefore cannot occupy the whole table: extra addresses from that
group evict older ones in the same bucket.

Advertisements call `learn_address`. `note_peer_success` calls `mark_dial_good`.
`select` prefers tried addresses. The table can be saved and loaded.

See [`NETWORK_ANONYMITY.md`](../NETWORK_ANONYMITY.md).
