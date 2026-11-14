# I-1 verification baseline

Seat I scale lane. Off consensus. Path A and F-A are unchanged. No header
version, no ring-policy change, no `DEFAULT_*` flip.

The pin lives in `mfn-scale`:

| Piece | Contract |
| --- | --- |
| Merkle leaves | 1024 |
| Inclusion proofs checked | 32, evenly spaced |
| CLSAG ring | 16 (production wallet floor) |
| Borromean range proof | 16 bits, value 1000 |
| Bulletproof | 16 bits, value 1000 |
| Header-link steps | 4096 |
| Header-link digest | `b2d3715d5e56c929e37683098e05087bd86bae08c792eeb72e8477a523047c3c` |

The header-link digest is SHA-256 over `MFN-1/scale-header-link/v1`, the
previous digest, and the height as 4 big-endian bytes. It is a harness
digest for sync-throughput work. It is not `block_id` and `apply_block`
does not read it.

Ring and range proof bytes depend on OS randomness inside the existing
provers. The unit test pins acceptance, rejection of a wrong message,
rejection of a foreign Merkle leaf, and rejection of a Bulletproof whose
commitment was swapped. Sizes are pinned to the table above so a later
patch cannot quietly shrink the bench.

Wall-clock (this machine, `cargo bench -p mfn-scale --bench verify`,
criterion sample size 10). Recorded so a later unit can show a real
speedup. Times are not a CI gate.

| Bench | Point estimate (`--quick` on the agent machine) |
| --- | --- |
| `merkle_32_of_1024` | 98.6 µs |
| `clsag_ring16` | 2.68 ms |
| `range_borromean_16` | 1.98 ms |
| `bulletproof_16` | 2.79 ms |
| `header_link_4096` | 339 µs |
| `full_pass` | 7.86 ms |

Reproduce:

```text
cargo test -p mfn-scale --release
cargo bench -p mfn-scale --bench verify
```
