# Browser header check

Before the testnet page shows a balance, it can check the tip headers on the device.

It asks the node for a light snapshot (`checkpoint_hex`) and the latest header bytes (`header_hex`). `lightChainVerifyHeader` in the page's WASM then checks each header against the checkpoint's validator set. The balance stays hidden when:

- the snapshot has no checkpoint,
- a header has no bytes,
- the WASM check returns `ok: false`,
- or the check throws.

A balance number appears only after every returned header is accepted. The page does not treat the node's own tip announcement as that check.
