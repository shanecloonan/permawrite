# Discovery card

When the website and the git forge are gone, a friend can still hand you a
card. The card is signed. It lists onion gateways and BitTorrent magnets.
Those are enough to fetch the software.

A card whose only location is `https://github.com/...` is refused, even when
the signature is valid. A website is not a way to survive the website being
taken down.

Check the signature against the public key the friend showed you, not against
a key that arrived in the same file as the card.

```bash
mfn-discovery sign --key-seed <64 hex> \
  --onion YOUR56CHARACTERONIONNAME.onion:80 \
  --magnet 'magnet:?xt=urn:btih:<40 hex>'
```

This does not change consensus, Path A, or F-A. It does not dial the network.
