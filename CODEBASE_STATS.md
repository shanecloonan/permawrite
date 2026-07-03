# Codebase stats

Auto-generated snapshot of this repository (Rust sources, docs, diagrams, and config-like text; `target/`, `.git`, and common binary formats are excluded).

**Generated (UTC):** 2026-07-03T14:05:32.095Z

**Regenerate:** `node scripts/codebase-stats.mjs`

## Summary

| Metric | Value |
| --- | ---: |
| Source-like files scanned | 442 |
| Total lines (all scanned source-like files) | 122,275 |
| Non-empty lines | 110,050 |
| UTF-8 bytes (source-like) | 4,952,703 |
| Paths visited (before binary/huge skip) | 546 |
| Skipped (binary / non-UTF8 / over 4 MiB) | 27 |

## Lines of code by top-level directory

The first path segment (crate name, `docs`, etc.). Only source-like extensions are included.

| Directory | Files | Lines | Non-empty lines |
| --- | ---: | ---: | ---: |
| `mfn-consensus` | 67 | 28,818 | 26,958 |
| `mfn-cli` | 29 | 14,730 | 13,620 |
| `docs` | 50 | 13,205 | 9,756 |
| `mfn-node` | 34 | 11,912 | 11,019 |
| `scripts` | 116 | 9,906 | 8,879 |
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
| `.github` | 3 | 1,300 | 1,258 |
| `mfn-bls` | 4 | 865 | 757 |
| `(root)` | 6 | 799 | 564 |
| `.permawrite-devnet-v1` | 4 | 30 | 30 |

## Lines of code by file extension

| Extension | Files | Lines | Non-empty lines | Bytes |
| --- | ---: | ---: | ---: | ---: |
| `.rs` | 212 | 92,166 | 85,404 | 3,340,389 |
| `.md` | 64 | 15,776 | 11,380 | 1,069,252 |
| `.sh` | 36 | 6,343 | 5,776 | 228,271 |
| `.json` | 95 | 2,784 | 2,697 | 98,579 |
| `.js` | 7 | 1,980 | 1,856 | 64,098 |
| `.yml` | 4 | 1,303 | 1,260 | 71,326 |
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
| 2,353 | `docs/ROADMAP.md` |
| 2,290 | `mfn-consensus/tests/block_apply.rs` |
| 1,975 | `mfn-consensus/tests/emission_simulation.rs` |
| 1,975 | `mfn-consensus/tests/producer_treasury_settlement.rs` |
| 1,850 | `mfn-node/src/p2p_fanout.rs` |
| 1,634 | `mfn-light/src/chain.rs` |
| 1,609 | `mfn-runtime/src/mempool.rs` |
| 1,542 | `mfn-cli/src/wallet_cmd.rs` |
| 1,197 | `mfn-net/src/serve.rs` |
| 1,166 | `scripts/public-devnet-v1/OPERATORS.md` |
| 1,156 | `.github/workflows/ci.yml` |
| 1,089 | `mfn-light/tests/follow_chain.rs` |
| 1,081 | `mfn-node/src/mfnd_serve.rs` |
| 1,077 | `mfn-node/src/mfnd_cli.rs` |
| 1,019 | `mfn-consensus/tests/validator_finality_evolution/bond_ops.rs` |

## Notes

- **Lines** include blank lines and comments; **non-empty** ignores lines that are only whitespace.
- **Source-like** extensions: `.cjs`, `.js`, `.json`, `.jsx`, `.md`, `.mjs`, `.rs`, `.sh`, `.sql`, `.svg`, `.toml`, `.ts`, `.tsx`, `.yaml`, `.yml`.
- **`Cargo.lock`** and other `*.lock` files are excluded so totals emphasize authored source.
- Requires **Node.js** only to regenerate this file; the Rust workspace does not depend on Node for builds.
