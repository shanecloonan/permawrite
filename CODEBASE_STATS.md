# Codebase stats

Auto-generated snapshot of this repository (Rust sources, docs, diagrams, and config-like text; `target/`, `.git`, and common binary formats are excluded).

**Generated (UTC):** 2026-07-08T05:03:13.547Z

**Regenerate:** `node scripts/codebase-stats.mjs`

## Summary

| Metric | Value |
| --- | ---: |
| Source-like files scanned | 476 |
| Total lines (all scanned source-like files) | 139,538 |
| Non-empty lines | 125,020 |
| UTF-8 bytes (source-like) | 5,742,029 |
| Paths visited (before binary/huge skip) | 587 |
| Skipped (binary / non-UTF8 / over 4 MiB) | 24 |

## Lines of code by top-level directory

The first path segment (crate name, `docs`, etc.). Only source-like extensions are included.

| Directory | Files | Lines | Non-empty lines |
| --- | ---: | ---: | ---: |
| `mfn-consensus` | 68 | 32,127 | 30,128 |
| `docs` | 63 | 18,354 | 13,562 |
| `mfn-cli` | 31 | 14,880 | 13,756 |
| `mfn-node` | 38 | 13,936 | 12,902 |
| `scripts` | 125 | 12,126 | 10,839 |
| `mfn-crypto` | 23 | 7,494 | 6,754 |
| `mfn-wallet` | 16 | 6,060 | 5,589 |
| `mfn-net` | 12 | 5,080 | 4,645 |
| `mfn-runtime` | 14 | 4,788 | 4,444 |
| `mfn-rpc` | 6 | 4,026 | 3,823 |
| `mfn-light` | 6 | 3,966 | 3,620 |
| `mfn-storage-operator` | 14 | 3,235 | 2,977 |
| `demo` | 12 | 2,478 | 2,292 |
| `mfn-storage` | 6 | 2,413 | 2,202 |
| `mfn-wasm` | 11 | 2,289 | 2,085 |
| `mfn-store` | 13 | 2,159 | 1,875 |
| `.github` | 6 | 1,798 | 1,737 |
| `(root)` | 8 | 1,464 | 1,033 |
| `mfn-bls` | 4 | 865 | 757 |

## Lines of code by file extension

| Extension | Files | Lines | Non-empty lines | Bytes |
| --- | ---: | ---: | ---: | ---: |
| `.rs` | 223 | 100,874 | 93,647 | 3,634,872 |
| `.md` | 99 | 22,373 | 16,207 | 1,467,706 |
| `.sh` | 45 | 7,509 | 6,886 | 272,947 |
| `.json` | 71 | 3,056 | 2,988 | 129,789 |
| `.js` | 7 | 1,980 | 1,856 | 64,098 |
| `.yml` | 7 | 1,801 | 1,739 | 90,995 |
| `.mjs` | 5 | 710 | 620 | 19,973 |
| `.svg` | 4 | 692 | 619 | 46,019 |
| `.toml` | 15 | 543 | 458 | 15,630 |

## Largest source files (by line count)

| Lines | File |
| ---: | --- |
| 4,922 | `mfn-consensus/tests/integration.rs` |
| 3,490 | `mfn-consensus/tests/apply_block_proptest.rs` |
| 3,303 | `mfn-rpc/src/dispatch.rs` |
| 3,024 | `mfn-consensus/tests/block_apply.rs` |
| 2,473 | `mfn-node/tests/mfnd_smoke.rs` |
| 2,371 | `docs/ROADMAP.md` |
| 2,242 | `mfn-consensus/tests/producer_treasury_settlement.rs` |
| 2,137 | `mfn-consensus/tests/emission_simulation.rs` |
| 1,923 | `mfn-runtime/src/mempool.rs` |
| 1,767 | `mfn-cli/src/cli/parse.rs` |
| 1,635 | `mfn-light/src/chain.rs` |
| 1,602 | `mfn-node/src/p2p_fanout.rs` |
| 1,550 | `mfn-cli/src/wallet_cmd.rs` |
| 1,327 | `docs/F5.md` |
| 1,323 | `mfn-cli/src/cli.rs` |
| 1,275 | `mfn-wallet/src/wallet.rs` |
| 1,262 | `.github/workflows/ci.yml` |
| 1,259 | `mfn-node/src/mfnd_cli.rs` |
| 1,255 | `scripts/public-devnet-v1/OPERATORS.md` |
| 1,224 | `mfn-net/src/serve.rs` |

## Notes

- **Lines** include blank lines and comments; **non-empty** ignores lines that are only whitespace.
- **Source-like** extensions: `.cjs`, `.js`, `.json`, `.jsx`, `.md`, `.mjs`, `.rs`, `.sh`, `.sql`, `.svg`, `.toml`, `.ts`, `.tsx`, `.yaml`, `.yml`.
- **`Cargo.lock`** and other `*.lock` files are excluded so totals emphasize authored source.
- Requires **Node.js** only to regenerate this file; the Rust workspace does not depend on Node for builds.
