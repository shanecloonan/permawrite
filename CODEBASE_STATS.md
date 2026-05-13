# Codebase stats

Auto-generated snapshot of this repository (Rust sources, docs, diagrams, and config-like text; `target/`, `.git`, and common binary formats are excluded).

**Generated (UTC):** 2026-05-13T14:52:37.569Z

**Regenerate:** `node scripts/codebase-stats.mjs`

## Summary

| Metric | Value |
| --- | ---: |
| Source-like files scanned | 92 |
| Total lines (all scanned source-like files) | 33,062 |
| Non-empty lines | 28,591 |
| UTF-8 bytes (source-like) | 1,431,054 |
| Paths visited (before binary/huge skip) | 97 |
| Skipped (binary / non-UTF8 / over 4 MiB) | 1 |

## Lines of code by top-level directory

The first path segment (crate name, `docs`, etc.). Only source-like extensions are included.

| Directory | Files | Lines | Non-empty lines |
| --- | ---: | ---: | ---: |
| `mfn-consensus` | 15 | 10,805 | 10,027 |
| `docs` | 25 | 6,859 | 4,852 |
| `mfn-crypto` | 22 | 6,228 | 5,570 |
| `mfn-light` | 6 | 3,847 | 3,511 |
| `mfn-storage` | 6 | 1,816 | 1,649 |
| `mfn-node` | 7 | 1,639 | 1,476 |
| `mfn-bls` | 4 | 862 | 755 |
| `(root)` | 5 | 688 | 487 |
| `scripts` | 1 | 261 | 214 |
| `.github` | 1 | 57 | 50 |

## Lines of code by file extension

| Extension | Files | Lines | Non-empty lines | Bytes |
| --- | ---: | ---: | ---: | ---: |
| `.rs` | 48 | 23,900 | 22,005 | 895,966 |
| `.md` | 32 | 8,151 | 5,719 | 487,849 |
| `.svg` | 3 | 480 | 425 | 32,915 |
| `.mjs` | 1 | 261 | 214 | 7,024 |
| `.toml` | 7 | 213 | 178 | 5,957 |
| `.yml` | 1 | 57 | 50 | 1,343 |

## Largest source files (by line count)

| Lines | File |
| ---: | --- |
| 3,254 | `mfn-consensus/src/block.rs` |
| 1,661 | `mfn-consensus/tests/integration.rs` |
| 1,499 | `mfn-light/src/chain.rs` |
| 1,039 | `mfn-light/src/checkpoint.rs` |
| 1,011 | `mfn-consensus/src/consensus.rs` |
| 962 | `mfn-light/tests/follow_chain.rs` |
| 906 | `mfn-consensus/src/transaction.rs` |
| 793 | `docs/ARCHITECTURE.md` |
| 791 | `mfn-storage/src/spora.rs` |
| 774 | `mfn-consensus/src/header_verify.rs` |
| 729 | `mfn-consensus/src/validator_evolution.rs` |
| 711 | `docs/ROADMAP.md` |
| 703 | `mfn-crypto/src/bulletproofs.rs` |
| 663 | `docs/CONSENSUS.md` |
| 649 | `mfn-storage/src/endowment.rs` |
| 642 | `mfn-crypto/src/oom.rs` |
| 633 | `mfn-bls/src/sig.rs` |
| 576 | `docs/STORAGE.md` |
| 564 | `docs/ECONOMICS.md` |
| 553 | `mfn-consensus/src/bond_wire.rs` |

## Notes

- **Lines** include blank lines and comments; **non-empty** ignores lines that are only whitespace.
- **Source-like** extensions: `.cjs`, `.js`, `.json`, `.jsx`, `.md`, `.mjs`, `.rs`, `.sh`, `.sql`, `.svg`, `.toml`, `.ts`, `.tsx`, `.yaml`, `.yml`.
- **`Cargo.lock`** and other `*.lock` files are excluded so totals emphasize authored source.
- Requires **Node.js** only to regenerate this file; the Rust workspace does not depend on Node for builds.
