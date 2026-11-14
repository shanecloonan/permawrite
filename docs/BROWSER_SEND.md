# Browser send

A send from the testnet page reads the tip header and chooses the privacy settings from that version.

- The header version is the first byte of `header_hex` (a single-byte varint). If the node does not return header bytes, the send stops.
- Below header version 5 the only legal ring is 16. A request for any other size is refused. Nothing smaller is substituted.
- At version 5 or above the page uses 64 when the decoy pool can fill it, otherwise 32. If the pool cannot fill 32, the send stops. It does not drop to 16.
- At version 6 or above fees are hidden. This page cannot sign a hidden fee yet, so it refuses the send instead of publishing a public fee.
- A payment with only one output is refused. Change is split so the transaction has two outputs.

The fee stays public on Path A because that header does not allow a hidden fee. That is the legal form, not a fallback from a hidden one.
