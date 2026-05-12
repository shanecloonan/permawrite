# Contributing to Permawrite

Thanks for taking the time. This project is consensus-critical financial infrastructure, so the bar for changes is intentionally high. The guidelines below exist to keep the bar that high without slowing down good work.

For the vision and context, start with [`docs/OVERVIEW.md`](./docs/OVERVIEW.md). For the technical design, [`docs/ARCHITECTURE.md`](./docs/ARCHITECTURE.md).

---

## What we want

- **Tests for everything.** Every new function, every new state-transition rule, every new error variant gets a test. The repo currently has 274 passing tests for a reason.
- **No `unsafe`.** Workspace-level `#![forbid(unsafe_code)]`. If your change can't avoid `unsafe`, the answer is almost certainly "find a different approach."
- **Determinism.** Anything that touches consensus must be byte-deterministic across runs and platforms. Integer math only; explicit endianness; no `f64` in consensus paths.
- **Domain separation.** New hash purposes need new domain tags in [`mfn-crypto/src/domain.rs`](./mfn-crypto/src/domain.rs). Reusing a tag for a different purpose is a hard fork by design.
- **Constant-time for secrets.** Secret-dependent comparisons go through `subtle::ConstantTimeEq`. Secrets implement `zeroize::Zeroize`.
- **Documentation that reads.** Sentence-case prose, plain English, brief Rustdocs on every public item, optional deeper explainer in `/docs` when the change is non-trivial.

## What we don't want

- Changes without tests.
- Style-only refactors of working code (separate PR if needed).
- New dependencies without strong justification. Every additional crate is a transitive audit-surface.
- "Optimizations" that complicate code without measurable benchmark gains.
- Floating-point math in consensus-touching paths.
- Anything that breaks byte-parity with the TypeScript reference *without* updating both sides in the same PR.

---

## Getting set up

```bash
# Install Rust (stable)
rustup install stable
rustup default stable
rustup component add rustfmt clippy

# Clone
git clone https://github.com/shanecloonan/permawrite
cd permawrite

# Verify the full gate passes locally before you start
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --release -- -D warnings
cargo test --workspace --release
```

Expected runtime: ~30-60s for clippy + tests on a modern laptop. If anything fails on a clean checkout, that's a bug worth reporting.

---

## The local check gate

Before pushing, **every** PR needs to pass these three commands locally — no exceptions:

```bash
cargo fmt --all -- --check                                   # formatting
cargo clippy --workspace --all-targets --release -- -D warnings  # zero warnings
cargo test --workspace --release                             # all tests pass
```

The `-- -D warnings` in clippy turns every warning into an error. We don't merge warnings.

CI runs these same three commands on Linux + macOS + Windows. A PR that's green locally is essentially guaranteed to be green in CI.

---

## Conventions

### Code style

- 4-space indent. Standard Rust. `cargo fmt --all` enforces.
- Module-level doc comment (`//!`) summarizing what the module does. Refer to the corresponding TS reference module by path.
- Public items get Rustdoc (`///`). Brief, sentence-case, no period at end of the first line.
- Private items get doc comments only when the *why* isn't obvious.
- No `expect`/`unwrap` outside test code. Every fallible path returns a typed `Result`.

### Naming

- Types: `UpperCamelCase`.
- Functions, variables: `snake_case`.
- Constants: `SCREAMING_SNAKE_CASE`.
- Domain tags: `MFBN-1/<dash-delimited-purpose>` (UTF-8 byte literal).
- Error variants: noun phrase describing what went wrong (`RingMemberNotInUtxoSet`, not `BadRing`).

### Module organization

A typical module follows this rough shape:

```rust
//! Module-level summary. Why this exists. What TS reference module it ports.

use ...;

pub const ...;        // public constants
pub struct ...;       // public types
pub enum ...;         // public enums (incl. error variants)

// ----------- public API -----------

pub fn ...;           // entry points

// ----------- internals -----------

fn helper(...);       // private helpers

#[cfg(test)]
mod tests {
    use super::*;
    // unit tests
}
```

### Commit messages

Match the existing style: single-line subject in **Title Case**, no conventional-commit prefix, no body unless really needed.

```
Close counterfeit-input attack + add liveness slashing (274 tests workspace-wide)
Move /about System Architecture next to Arweave + Stats
Reorder /about: move Platform Stats next to Fee Structure
```

If you need a body (rare), keep it short and prose-y. No bullet lists unless they're shipping changelog material.

### Pull requests

- One logical change per PR. "Cross-cutting" PRs are OK if they're truly cross-cutting (e.g., adding a new field to all `BlockError` variants).
- PR title = the eventual commit message subject.
- PR description: bullet list of changes + 1-paragraph "why this is correct" if the change touches consensus.

---

## Writing tests

Every new test goes in one of three places:

1. **Unit test** at the bottom of the module being tested (`#[cfg(test)] mod tests { ... }`).
2. **Integration test** in the crate's `tests/integration.rs` (cross-module flows).
3. **Doc test** in a Rustdoc comment (only when the test *is* the documentation, e.g., showing how to call a public API).

Test naming: `verb_noun_outcome` — `apply_block_rejects_unknown_commit`, `bp_verify_accepts_valid_proof`, `clsag_sign_then_verify_succeeds`.

Tests must be **deterministic**. Seed all RNGs explicitly:

```rust
use rand_core::SeedableRng;
let mut rng = rand_chacha::ChaCha20Rng::seed_from_u64(42);
```

(We don't actually depend on `rand_chacha` — there are equivalent test seeds throughout the codebase you can copy.)

---

## Adding a new domain tag

If your change involves hashing for a new purpose:

1. Add a new constant in [`mfn-crypto/src/domain.rs`](./mfn-crypto/src/domain.rs).
2. Format: `MFBN-1/<purpose-with-dashes>` (lowercase, dash-delimited).
3. Document the purpose in a Rustdoc comment.
4. **Never** reuse an existing tag for a new purpose. Doing so is a hard fork — both implementations would compute different digests.

---

## Adding consensus rules

Changes to `apply_block` are the most sensitive in the repo. A consensus-rule PR needs:

1. **Tests for the rule** (both acceptance and rejection cases).
2. **Tests for adjacent invariants** (does anything else now fail?).
3. **An integration test** demonstrating the rule end-to-end across multiple blocks.
4. **A note in `docs/ARCHITECTURE.md`** under [§ State-transition function](./docs/ARCHITECTURE.md#state-transition-function-apply_block) describing the new check.
5. **A `BlockError` variant** for any new rejection path.
6. **A line in the relevant doc** (`docs/PRIVACY.md`, `docs/STORAGE.md`, `docs/CONSENSUS.md`, or `docs/ECONOMICS.md`) explaining *why* the rule exists.

If your change is a hard fork (incompatible with existing chains), say so explicitly in the PR title.

---

## Documentation updates

When code changes, docs change. Common patterns:

| Code change | Doc change |
|---|---|
| New public function | Per-crate README's API section + Rustdoc |
| New `BlockError` variant | `docs/GLOSSARY.md § Common error variants` |
| New consensus rule | `docs/ARCHITECTURE.md § State-transition function` |
| New domain tag | `docs/ARCHITECTURE.md § Domain separation` |
| New crate | Workspace `README.md` status table + per-crate README + `PORTING.md` row |
| New roadmap item | `docs/ROADMAP.md` |
| Change to a parameter default | Both the relevant deep-dive (`PRIVACY.md`/`STORAGE.md`/etc.) AND the deep dive that explains the rationale (`ECONOMICS.md` typically) |

The `docs/README.md` cross-cut table is the source of truth for "where is X documented?" Keep it updated.

---

## Security disclosures

If you've found a vulnerability — in cryptographic primitives, encoding/decoding, consensus rules, or anywhere else — **do not open a public issue**. Follow [`SECURITY.md`](./SECURITY.md):

1. Use GitHub's private vulnerability reporting (Security tab → Report a vulnerability).
2. Or email the maintainer at the address in the most recent commit.
3. Include a proof-of-concept (ideally as a failing `cargo test`), your severity assessment, and any suggested mitigation.

Triage SLA: 72-hour acknowledgement, 7-day initial response, 30-day mitigation/disclosure plan.

---

## License

By contributing, you agree your contribution is dual-licensed under **MIT OR Apache-2.0**, matching the workspace license.

No CLA required. The dual-license agreement is implied by the contribution.

---

## Codebase stats

The repo tracks a generated line-count snapshot in [`CODEBASE_STATS.md`](./CODEBASE_STATS.md) (useful for gauging growth and review surface). Regenerate after large doc or code changes (requires [Node.js](https://nodejs.org/) only for this script—not for `cargo` builds):

```bash
node scripts/codebase-stats.mjs
```

---

## Quick reference

```
# Run the full gate
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --release -- -D warnings
cargo test --workspace --release

# Run one crate's tests
cargo test -p mfn-crypto --release
cargo test -p mfn-bls --release
cargo test -p mfn-storage --release
cargo test -p mfn-consensus --release

# Run one test by name
cargo test --workspace --release -- <test_name>

# Fix formatting
cargo fmt --all
```

---

## Questions

- Conceptual / design: open a GitHub Discussion.
- "Is this a bug or am I confused?": open a GitHub Issue.
- "Should I implement X?": open a Discussion first; consensus-touching work needs design buy-in before code.
- "Is there a way to contribute that isn't code?": yes — docs, tests, code review, vulnerability disclosure, and economic-parameter analysis are all valuable.

Thanks for being here.
