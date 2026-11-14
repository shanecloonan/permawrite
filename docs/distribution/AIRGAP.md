# Air-gapped signing

A networked machine can build a transfer request. That file holds public rings, amounts, fees, and recipient addresses. It does not hold spend keys. `deny_unknown_fields` refuses a request that tries to carry a spend key.

The air-gapped machine keeps the spend scalars. `mfn-airgap sign` writes two outputs:

| File | Where it goes |
| --- | --- |
| `--tx` | Broadcast bytes. Carry this back to a networked machine. |
| `--blindings` | Output blindings and the transaction id. Do not publish this. |

Rings must be exactly 16. There must be at least two inputs and two outputs. A smaller ring is refused before a signature is produced. `verify` checks the broadcast bytes with the production ring policy.

```bash
cargo run -p mfn-airgap -- sign --request request.json --keys spend.json --tx tx.bin --blindings blindings.json
cargo run -p mfn-airgap -- verify --tx tx.bin
```

This does not change header versions, Path A, or F-A. The air-gapped machine does not open a socket.
