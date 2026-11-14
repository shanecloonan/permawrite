# Content-addressed mirrors

A release file does not have to live on GitHub. `mfn-mirror` names the same
bytes three ways:

| Name | What it is |
| --- | --- |
| `sha256` | The file digest |
| `cid` | IPFS CIDv1 for a raw blob (SHA-256, base32) |
| `magnet` | BitTorrent v1 infohash of a single-file torrent |
| `data_root` | The chunk-Merkle root an upload would commit on the chain |

Anyone who already has the bytes can check all three. Anyone who has only a
magnet or a CID can fetch the bytes from whoever is seeding them, then check
the record. The project can publish that record inside a permanent upload,
so the next copy does not depend on a domain or a forge.

```bash
mfn-mirror describe --name mfnd --file ./mfnd
mfn-mirror verify --record mfnd.mirror --file ./mfnd
```

This does not change consensus, Path A, or F-A. It does not contact a network.
