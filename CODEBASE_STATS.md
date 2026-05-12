# Codebase stats

Auto-generated snapshot of this repository (Rust sources, docs, diagrams, and config-like text; `target/`, `.git`, and common binary formats are excluded).

**Generated (UTC):** 2026-05-12T19:14:23.136Z

**Regenerate:** `node scripts/codebase-stats.mjs`

## Summary

| Metric | Value |
| --- | ---: |
| Source-like files scanned | 78 |
| Total lines (all scanned source-like files) | 25,735 |
| Non-empty lines | 22,102 |
| UTF-8 bytes (source-like) | 1,075,703 |
| Paths visited (before binary/huge skip) | 83 |
| Skipped (binary / non-UTF8 / over 4 MiB) | 1 |

## Lines of code by top-level directory

The first path segment (crate name, `docs`, etc.). Only source-like extensions are included.

| Directory | Files | Lines | Non-empty lines |
| --- | ---: | ---: | ---: |
| `mfn-consensus` | 13 | 9,105 | 8,442 |
| `mfn-crypto` | 22 | 6,221 | 5,564 |
| `docs` | 20 | 5,316 | 3,674 |
| `mfn-storage` | 6 | 1,816 | 1,649 |
| `mfn-node` | 6 | 1,413 | 1,271 |
| `mfn-bls` | 4 | 862 | 755 |
| `(root)` | 5 | 684 | 483 |
| `scripts` | 1 | 261 | 214 |
| `.github` | 1 | 57 | 50 |

## Lines of code by file extension

| Extension | Files | Lines | Non-empty lines | Bytes |
| --- | ---: | ---: | ---: | ---: |
| `.rs` | 41 | 18,394 | 16,906 | 669,903 |
| `.md` | 26 | 6,357 | 4,351 | 359,342 |
| `.svg` | 3 | 480 | 425 | 32,915 |
| `.mjs` | 1 | 261 | 214 | 7,024 |
| `.toml` | 6 | 186 | 156 | 5,176 |
| `.yml` | 1 | 57 | 50 | 1,343 |

## Largest source files (by line count)

| Lines | File |
| ---: | --- |
| 3,087 | `mfn-consensus/src/block.rs` |
| 1,661 | `mfn-consensus/tests/integration.rs` |
| 1,011 | `mfn-consensus/src/consensus.rs` |
| 906 | `mfn-consensus/src/transaction.rs` |
| 791 | `mfn-storage/src/spora.rs` |
| 751 | `docs/ARCHITECTURE.md` |
| 703 | `mfn-crypto/src/bulletproofs.rs` |
| 649 | `mfn-storage/src/endowment.rs` |
| 642 | `mfn-crypto/src/oom.rs` |
| 633 | `mfn-bls/src/sig.rs` |
| 576 | `docs/STORAGE.md` |
| 564 | `docs/ECONOMICS.md` |
| 553 | `mfn-consensus/src/bond_wire.rs` |
| 550 | `docs/CONSENSUS.md` |
| 504 | `mfn-node/src/producer.rs` |
| 493 | `mfn-crypto/src/utxo_tree.rs` |
| 488 | `mfn-crypto/src/clsag.rs` |
| 487 | `mfn-consensus/src/slashing.rs` |
| 475 | `mfn-crypto/src/vrf.rs` |
| 465 | `mfn-crypto/src/decoy.rs` |

## Notes

- **Lines** include blank lines and comments; **non-empty** ignores lines that are only whitespace.
- **Source-like** extensions: `.cjs`, `.js`, `.json`, `.jsx`, `.md`, `.mjs`, `.rs`, `.sh`, `.sql`, `.svg`, `.toml`, `.ts`, `.tsx`, `.yaml`, `.yml`.
- **`Cargo.lock`** and other `*.lock` files are excluded so totals emphasize authored source.
- Requires **Node.js** only to regenerate this file; the Rust workspace does not depend on Node for builds.
