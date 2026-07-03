# Codebase stats

Auto-generated snapshot of this repository (Rust sources, docs, diagrams, and config-like text; `target/`, `.git`, and common binary formats are excluded).

**Generated (UTC):** 2026-07-03T13:31:48.984Z

**Regenerate:** `node scripts/codebase-stats.mjs`

## Summary

| Metric | Value |
| --- | ---: |
| Source-like files scanned | 423 |
| Total lines (all scanned source-like files) | 121,278 |
| Non-empty lines | 109,136 |
| UTF-8 bytes (source-like) | 4,915,292 |
| Paths visited (before binary/huge skip) | 519 |
| Skipped (binary / non-UTF8 / over 4 MiB) | 20 |

## Lines of code by top-level directory

The first path segment (crate name, `docs`, etc.). Only source-like extensions are included.

| Directory | Files | Lines | Non-empty lines |
| --- | ---: | ---: | ---: |
| `mfn-consensus` | 67 | 28,818 | 26,958 |
| `mfn-cli` | 29 | 14,698 | 13,589 |
| `docs` | 50 | 13,201 | 9,752 |
| `mfn-node` | 34 | 11,912 | 11,019 |
| `scripts` | 98 | 9,009 | 8,057 |
| `mfn-crypto` | 23 | 7,291 | 6,564 |
| `mfn-wallet` | 15 | 4,933 | 4,524 |
| `mfn-net` | 11 | 4,659 | 4,250 |
| `mfn-runtime` | 14 | 4,394 | 4,065 |
| `mfn-rpc` | 4 | 3,996 | 3,798 |
| `mfn-light` | 6 | 3,895 | 3,556 |
| `mfn-storage-operator` | 14 | 2,830 | 2,591 |
| `demo` | 12 | 2,478 | 2,292 |
| `mfn-store` | 13 | 2,159 | 1,875 |
| `mfn-wasm` | 11 | 2,070 | 1,873 |
| `mfn-storage` | 6 | 2,005 | 1,821 |
| `.github` | 2 | 1,237 | 1,200 |
| `mfn-bls` | 4 | 865 | 757 |
| `(root)` | 6 | 797 | 564 |
| `.permawrite-devnet-v1` | 4 | 31 | 31 |

## Lines of code by file extension

| Extension | Files | Lines | Non-empty lines | Bytes |
| --- | ---: | ---: | ---: | ---: |
| `.rs` | 212 | 92,134 | 85,373 | 3,339,441 |
| `.md` | 62 | 15,664 | 11,304 | 1,065,801 |
| `.sh` | 34 | 6,038 | 5,498 | 218,404 |
| `.json` | 81 | 2,299 | 2,226 | 77,289 |
| `.js` | 7 | 1,980 | 1,856 | 64,098 |
| `.yml` | 3 | 1,240 | 1,202 | 69,471 |
| `.mjs` | 5 | 706 | 616 | 19,916 |
| `.svg` | 4 | 692 | 619 | 46,019 |
| `.toml` | 15 | 525 | 442 | 14,853 |

## Largest source files (by line count)

| Lines | File |
| ---: | --- |
| 4,589 | `mfn-consensus/tests/integration.rs` |
| 3,922 | `mfn-rpc/src/dispatch.rs` |
| 3,062 | `mfn-cli/src/cli.rs` |
| 2,784 | `mfn-consensus/tests/apply_block_proptest.rs` |
| 2,409 | `mfn-node/tests/mfnd_smoke.rs` |
| 2,350 | `docs/ROADMAP.md` |
| 2,290 | `mfn-consensus/tests/block_apply.rs` |
| 1,975 | `mfn-consensus/tests/emission_simulation.rs` |
| 1,975 | `mfn-consensus/tests/producer_treasury_settlement.rs` |
| 1,850 | `mfn-node/src/p2p_fanout.rs` |
| 1,634 | `mfn-light/src/chain.rs` |
| 1,609 | `mfn-runtime/src/mempool.rs` |
| 1,542 | `mfn-cli/src/wallet_cmd.rs` |
| 1,197 | `mfn-net/src/serve.rs` |
| 1,152 | `.github/workflows/ci.yml` |
| 1,127 | `scripts/public-devnet-v1/OPERATORS.md` |
| 1,089 | `mfn-light/tests/follow_chain.rs` |
| 1,081 | `mfn-node/src/mfnd_serve.rs` |
| 1,077 | `mfn-node/src/mfnd_cli.rs` |
| 1,019 | `mfn-consensus/tests/validator_finality_evolution/bond_ops.rs` |

## Notes

- **Lines** include blank lines and comments; **non-empty** ignores lines that are only whitespace.
- **Source-like** extensions: `.cjs`, `.js`, `.json`, `.jsx`, `.md`, `.mjs`, `.rs`, `.sh`, `.sql`, `.svg`, `.toml`, `.ts`, `.tsx`, `.yaml`, `.yml`.
- **`Cargo.lock`** and other `*.lock` files are excluded so totals emphasize authored source.
- Requires **Node.js** only to regenerate this file; the Rust workspace does not depend on Node for builds.
