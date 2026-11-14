# I-10 light wallet path

`LightWallet` is the path a phone can run.

- `follow` admits a header only when it continues a trusted genesis id.
- `prove_tx` checks a Merkle proof against that header. An unknown header
  id is refused.
- `output_window` is two heights and eight bytes. It does not contain the
  view key. Two wallets asking for the same range send the same bytes.
- `scan` runs stealth detection on the device.
- `remember_body` keeps block bodies inside a byte cap and will not evict
  a pinned body to do it.

No consensus change. Path A and F-A are unchanged.
