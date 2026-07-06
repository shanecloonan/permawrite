# Codebase Improvement Findings

Engineering-quality audit of the Permawrite workspace, ordered by importance. This complements
[`PROBLEMS.md`](./PROBLEMS.md) (protocol/economic weaknesses): everything here is about the
**repository, code, and tooling**, not the protocol design.

Snapshot date: 2026-07-05. Counts below are from that snapshot and will drift; re-measure before
acting on any single number.

**Closure (2026-07-05):** M2.5.39–56 landed on `main` (`6fe1b18`). Priorities 1–8 below are **done** or **mostly done**; B-06 Nightly #63 remains the RC gate (lane 1).

---

## Priority 1 - Repo hygiene: untracked debris and `.gitignore` gaps

**Severity: High. Effort: low. Do this first.**
**Status: partially addressed by M2.5.32 (`a35b7a6`)** - `.gitignore` now covers CI logs and
board-recovery scratch patterns. Remaining work is steps 2-3 below.

- At snapshot time `git status` showed **~300 untracked files** polluting the repo root and
  `docs/`: **177** `ci-check-*.log`, dozens of `ci-watch-*` / `participant-rehearsal-*` /
  `nightly-watch-*` logs, and **~66** underscore-prefixed scratch files (`_agents_*.md`, `_*.bin`,
  `_*.tmp`) left over from agent-board encoding recovery, plus strays like `AGENTS.md.clean`,
  `AGENTS.new.md`, `.gitattributes.new`, `scripts/validate-rc.new.ps1`,
  `scripts/validate-rc-helper-scripts.ps1.restored`.
- Before M2.5.32, `.gitignore` only ignored a single log (`scripts/ci-check-last.log`).

**Remaining fix:**

1. Extend `.gitignore` - done in M2.5.32.
2. Delete the on-disk debris (it is all recovery scratch; canonical content lives on `main`).
   Ignoring it hides it from `git status`, but the files still clutter the working tree,
   searches, and backups.
3. Point CI helper logs at the OS temp dir (or `scripts/`, already ignored) instead of the repo
   root, and add `.worktrees/` to `.gitignore` if local worktrees remain in use.

## Priority 2 - Encoding workflow fragility (mojibake + repeated repair commits)

**Severity: High. This is actively costing engineering time.**
**Status: partially addressed** - M2.5.32 rebuilt `docs/AGENTS.md` clean and added a board
mojibake guard to `validate-workflow-encoding`; boards are now clean. Non-board docs still carry
mojibake.

- Recent `main` history is dominated by encoding repair: at least **10 commits** since `7690138`
  are "restore UTF-8 boards" / "fix corrupted newlines" variants (M2.5.26-M2.5.32), and the
  scratch files in Priority 1 are fallout from those repairs.
- Docs that still contain mojibake (CP-1252 renderings of UTF-8 em dashes, which show up as
  Gamma/A-circumflex character sequences) as of this snapshot: `docs/STORAGE_ACCESSIBILITY.md`
  (~25 lines), `docs/TESTNET.md` (~7 lines), `docs/CI.md` (~5 lines),
  `scripts/public-devnet-v1/OPERATORS.md` (~11 lines).
- Two conflicting `.gitattributes` strategies have circulated (`-text` pin on `main` vs
  `working-tree-encoding=UTF-8` in a scratch `.gitattributes.new`), which is how the corruption
  kept recurring.

**Fix:**

1. Keep **one** `.gitattributes` strategy for boards/docs (plain `text` is enough once files are
   genuinely UTF-8) and delete the scratch `.gitattributes.new`.
2. One-time pass: re-save every affected markdown file as UTF-8 (no BOM), replacing mojibake
   sequences with plain dashes, and strip stray literal backtick-n artifacts (PowerShell escape
   leakage) where present.
3. Root cause: markdown was being round-tripped through PowerShell string pipelines with mixed
   encodings. Prefer direct file-editing tools over `Set-Content`/heredoc round-trips; extend the
   mojibake guard beyond the boards to all of `docs/*.md` so regressions fail CI instead of
   landing.

## Priority 3 - `unwrap()`/`expect()` density in production networking paths

**Status: mostly done** - M2.5.46–48 frame/chunk + mfnd paths; clippy gate on prod unwraps.

**Severity: High for `mfn-net`/`mfn-node`; Medium elsewhere.**

- Roughly **1,100** `unwrap()`/`expect()` calls exist in non-test `src/` across the workspace.
  Hot spots in code that processes untrusted peer input or runs unattended:
  - `mfn-net`: ~149 (notably `handshake.rs` ~52, `frame.rs` ~33, `block_sync.rs` ~25)
  - `mfn-node`: ~157 (notably `p2p_fanout.rs` ~50, `mfnd_serve.rs` ~40, `p2p_boot.rs` ~26)
  - `mfn-net` also has ~11 production `panic!` sites (`block_sync.rs`, `light_follow.rs`).
- A panic in a P2P/serve path is a remote availability risk for a long-running daemon: one
  malformed frame or unexpected state should never take the node down.

**Fix:** audit `mfn-net` and `mfn-node/src/p2p_*.rs` first; convert to `Result` propagation with
`thiserror` (already a workspace dependency). Keep `expect()` only for compile-time invariants
with a message explaining why it cannot fail. Consider a clippy lint gate
(`unwrap_used`/`expect_used` at `warn` scoped to those two crates) to prevent regression.

## Priority 4 - God files in RPC, CLI, and P2P

**Status: done** - M2.5.46 `p2p_fanout` split; M2.5.52 `dispatch/` modules; M2.5.53–54 `cli/parse.rs`.

**Severity: Medium-High (maintainability, review quality, merge conflicts between lanes).**

Largest non-test source files:

| File | Lines |
| --- | --- |
| `mfn-rpc/src/dispatch.rs` | ~3,700 |
| `mfn-cli/src/cli.rs` | ~3,000 |
| `mfn-node/src/p2p_fanout.rs` | ~1,700 |
| `mfn-runtime/src/mempool.rs` | ~1,600 |
| `mfn-light/src/chain.rs` | ~1,500 |

Test-side equivalents: `mfn-consensus/tests/integration.rs` is ~4,700 lines.

**Fix:** split `dispatch.rs` by RPC method class (chain reads, mempool, wallet writes, operator
admin - the `rpc_method_class` split already exists conceptually); split `cli.rs` by subcommand
module (partially done with `wallet_cmd.rs`; finish the extraction); split `p2p_fanout.rs` by
protocol phase. With multiple agent lanes editing concurrently, smaller files directly reduce
conflict rate.

## Priority 5 - Local CI mirror is too slow for daily iteration

**Status: done** - M2.5.39–42: `-DocsOnly`/`-RustOnly` + venv cache (`.permawrite-ci-venv/`).

**Severity: Medium (developer velocity; encourages skipping the gate).**

- `scripts/ci-check.ps1` is **768 lines**; it runs release-schema/archive/signoff/evidence
  validation, script parsing, wasm build, full `cargo test --release`, and `cargo audit` - a
  50-90 minute run on Windows. There is no way to run just the part relevant to a change.
- It also creates a **fresh Python venv on every run** (jsonschema pin) - pure overhead.

**Fix:**

1. Add mode flags: `-RustOnly` (fmt+clippy+test), `-ScriptsOnly`, `-DocsOnly` so a docs-only or
   scripts-only commit does not require the full matrix locally (GHA still runs everything).
2. Cache the schema venv in a local app-data dir keyed on the requirements hash instead of
   re-creating it.

## Priority 6 - PowerShell/Bash script duplication

**Status: done** - M2.5.43 `rehearsal-poll-timeouts.*` shared constants.

**Severity: Medium (drift risk).**

- `scripts/ci-check.ps1` (768 lines) and `scripts/ci-check.sh` (617 lines) reimplement the same
  release-validation logic; `scripts/public-devnet-v1/` holds ~38 `.ps1` / ~37 `.sh` near-1:1
  pairs. Every timeout bump or logic fix has to be made twice (see the `start-all` 900s change).
- One-off repair scripts (`fix-m2527-boards.ps1`, `write-agents-boards-utf8.ps1`) linger in
  `scripts/` after their purpose passed.

**Fix:** extract shared validation fixtures/vectors so one side is generated or thin; add a CI
drift check that asserts each ps1/sh pair implements the same steps (the `--plan-only`
assertions are a good start). Delete one-off repair scripts once their unit lands.

## Priority 7 - Dependency and workspace polish

**Status: done** - M2.5.45 hoisted redb/proptest/wasm-bindgen; M2.5.56 pins `anyhow` 1.0.103 (RUSTSEC-2026-0190 cleared).

## Priority 8 - Smaller code-quality items

**Status: done** - M2.5.55 Byzantine light-chain test; mempool test `dead_code` removed. `bls_stub.rs` crate-level allow is intentional (WASM).

**Severity: Low.**

- 2 production `#[allow(dead_code)]` sites (`mfn-runtime/src/mempool.rs`,
  `mfn-node/src/p2p_fanout.rs`): move test-only helpers behind `#[cfg(test)]` instead.
- 13 `#[ignore]` tests across 7 files are nightly-only by design; keep `docs/CI.md` as the single
  place listing every one with its runtime, and keep the B-06-style "nightly green" gate for RCs.
- `mfn-consensus/tests/follow_chain.rs` has a test blocked on a missing
  hand-signed-Byzantine-block fixture; either build the fixture or downgrade to a unit-level mock
  so coverage is not silently deferred.

---

## What is already good (do not churn)

- **Zero `unsafe`** - crates use `#![forbid(unsafe_code)]`; keep it.
- **Zero `TODO`/`FIXME`/`HACK`** comments in Rust source.
- **Clear 14-crate layering** with documented boundaries and no async runtime (intentional,
  documented) - keep the discipline.
- **Deep consensus/emission test coverage** (proptests, multi-hour ignored tiers, nightly
  mirror).
- **No hardcoded secrets**; RPC auth via env vars; ci-check even asserts `GH_TOKEN` does not
  leak into watch output.
- **Rich doc set** with reading paths and a cross-cut index (`docs/README.md`).

## Suggested execution order

1. `.gitignore` + debris purge (mostly done in M2.5.32; finish the on-disk purge).
2. One-shot encoding repair of remaining docs + extend the mojibake guard to all docs.
3. `ci-check` fast-path flags + venv caching (makes everything after it cheaper).
4. `mfn-net`/`mfn-node` unwrap audit (one crate per unit, clippy gate after).
5. Split `dispatch.rs` / `cli.rs` / `p2p_fanout.rs` (one file per unit).
6. Workspace dependency hoisting + `anyhow` advisory follow-up.
