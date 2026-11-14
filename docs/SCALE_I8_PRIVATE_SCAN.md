# I-8 private output scan

`OutputWindowRequest` is two heights. The encoding is eight bytes. It has
no view key, no spend key, and no bloom filter. Two wallets that want the
same window send the same bytes.

`scan_owned` runs `stealth_detect` on the device. Alice's hits and Bob's
hits differ. The network request does not.

No consensus change.
