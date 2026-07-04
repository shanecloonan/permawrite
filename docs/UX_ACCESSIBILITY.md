# Normie UX assessment - mainnet readiness

**Question:** How easy or hard will Permawrite be for ordinary users when it becomes a mature mainnet L1 - and what can be improved without trading away privacy or permanence?

**Short answer:** The **protocol layer** is designed for Monero-grade privacy and Arweave-grade permanence in one chain. The **product layer** is still **devnet-grade** (~**3/10** normie-friendliness today). A capable developer can complete send, upload, claim, and storage flows end-to-end; a non-technical user cannot yet do so without hand-holding. The gap is packaging, guided flows, human-readable presentation, and unified permanence backup - **not** the core cryptography or consensus rules, which the codebase deliberately refuses to weaken.

**Priority doctrine (non-negotiable):** Permanence and privacy absolutism come first. UX must never sacrifice ring size, endowment enforcement, SPoRA verification, claiming-key separation, or deterministic consensus checks. Every improvement below is a **wrapper, presentation, or packaging** layer on top of existing protocol rules.

See also: [`OVERVIEW.md`](./OVERVIEW.md) (intuition), [`PRIVACY.md`](./PRIVACY.md) (privacy absolutes), [`STORAGE_ACCESSIBILITY.md`](./STORAGE_ACCESSIBILITY.md) (storage-specific feasibility), [`PROBLEMS.md`](./PROBLEMS.md) (honest gaps), [`ROADMAP.md`](./ROADMAP.md) (milestones).

---

## 1. Executive summary

| Dimension | Today (devnet) | Mature mainnet target | Gap type |
|---|---|---|---|
| **Privacy guarantees** | Tier 1 live (CLSAG ring 16, Bulletproofs, stealth) | Same or stronger (Tier 2-4 roadmap) | None - protocol is ahead of UX |
| **Permanence guarantees** | Endowment + SPoRA + treasury settlement live | Same | None - protocol is ahead of UX |
| **Wallet onboarding** | CLI: `wallet new` / `restore`, seed warnings | One-tap install, encrypted backup export | Product packaging |
| **Send money** | 7+ shell steps incl. daemon lifecycle | Tap send, see pending -> confirmed | Orchestration + UI |
| **Upload permanently** | CLI or browser demo; dual backup model | Drag-drop, fee quote, artifact backup wizard | Product + education |
| **Run storage operator** | Rust CLI + optional daemon | Background app / PWA with prove loop | WASM prove + packaging |
| **Error comprehension** | Protocol jargon, `key=value` output | Plain-language with exact fix steps | Presentation layer |
| **Documentation for users** | Excellent for designers; dense for participants | Quick-start + advanced split | Information architecture |

**Normie-friendliness score: 3 / 10** (devnet tooling against a mature-mainnet bar).

**Why not lower:** `OVERVIEW.md` explains the vision in plain language; wallet pre-validation catches underfunded uploads before signing; ring-size >= 16 is enforced at the CLI (no silent privacy downgrade); WASM proves browser upload is viable; rehearsal scripts document complete journeys with PASS/evidence artifacts.

**Why not higher:** No production wallet app; no prebuilt consumer packaging emphasized yet; atomic units everywhere; invisible mining/confirmation model on devnet; permanence requires a **second** backup layer most users will miss; storage prove/serve is CLI-only; browser demo needs 3+ terminals and protocol-engineer configuration.

---

## 2. Comparison to Monero and Arweave (the bar we chose)

Permawrite deliberately fuses two networks that are **notoriously hard for normies**:

| Network | What normies struggle with | Permawrite inherits? |
|---|---|---|
| **Monero** | Seed backup, sync time, ring/decoy concepts, no transparent addresses, exchange friction | Yes - same privacy model (stealth, CLSAG, Pedersen, Bulletproofs). Users must understand **one-time outputs** and **view-key scanning**, not address books. |
| **Arweave** | Endowment pricing, wallet + bundler tooling, miner hardware gate, permanence != "uploaded to IPFS" | Partially - endowment math and off-chain bytes are similar concepts, but SPoRA removes datacenter mining hardware. Users must understand **upload artifacts** are not recoverable from seed alone. |

**The fused product is strictly harder than either alone** because users must learn:

1. **Private money** (Monero-shaped) - ring signatures, stealth addresses, no public amounts.
2. **Permanent data** (Arweave-shaped) - upfront endowment, content addressing, operator replication.
3. **Two backup layers** - wallet seed restores **funds**, not **payload bytes** (see [`TESTNET.md`](./TESTNET.md)).

That difficulty is **intrinsic to the value proposition**, not a bug. UX work must **explain and guide** through these constraints, not hide them behind shortcuts that weaken privacy or permanence.

---

## 3. User-facing surfaces today

| Surface | Role | Normie readiness |
|---|---|---|
| **`mfn-cli`** | Primary wallet + operator CLI over JSON-RPC | Functional for power users; cryptic for normies |
| **`mfn-wallet`** | Library: scan, send, upload, claim | Strong internals; no UI |
| **`mfnd`** | Daemon: RPC, P2P, block production | Required infrastructure; invisible to normies if hosted |
| **`mfn-wasm`** | Browser bindings (upload, scan, transfer build) | Devnet demo; half the wallet story |
| **`demo/web/`** | WASM demo + RPC proxy | Developer harness, not a consumer app |
| **`mfn-storage-operator`** | Background SPoRA proving | CLI/daemon only |
| **Production web/mobile wallet** | - | **Does not exist** |

There is no app-store wallet, no packaged desktop GUI, and no mobile client. The closest normie path is the browser demo, which still requires building WASM, running `mfnd`, a proxy, and often manual block production.

---

## 4. User journeys - steps and friction

### 4.1 Wallet creation

**Works well:** Seed backup warnings; `wallet backup-info` for seed-free reconciliation.

**Friction:** Users must internalize **two backup layers** - wallet file (spend authority) and upload-artifacts directory (permanence payloads). Losing the seed loses funds; losing artifacts loses permanence even if the chain index still lists the upload.

### 4.2 Send (private transfer)

Typical devnet path requires ~7+ shell commands including daemon stop/start and manual block production. Cryptic: atomic units, mandatory `--ring-size 16`, no pending-confirmation UX.

### 4.3 Upload (permanent storage)

Cryptic output: `data_root`, `storage_commitment_hash`, `burden`, `min_fee`. Hidden requirement: local upload artifacts must be backed up separately from the wallet seed.

### 4.4 Claim (authorship)

Claims are **intentionally public** (claiming key != spend key). UX must explain claiming reveals authorship by design without deanonymizing the upload tx.

### 4.5 Storage operator / retrieve

Full loop spans ~10+ commands across wallet, operator, and node subsystems.

### 4.6 CLI ergonomics

No per-subcommand `--help`; `key=value` output; ~80-line usage dump on error.

---

## 5. What already works well

1. **`OVERVIEW.md`** - plain-language privacy/permanence without requiring math first.
2. **Pre-sign validation in `mfn-wallet`** - e.g. `UploadUnderfunded` with exact `min_fee` before wasting CLSAG work.
3. **Ring-size enforcement** - CLI refuses `< 16`; never silently weakens privacy for convenience.
4. **`wallet backup-info` / `uploads status`** - seed-free reconciliation for support and backup planning.
5. **`--json` mode** - structured support records for automation and help desks.
6. **Rehearsal scripts** - `participant-rehearsal`, `permanence-demo` with PASS/evidence artifacts.
7. **WASM upload + scan** - browser viability for wallet scan and upload construction.
8. **Light-client / weak-subjectivity tooling** - export/import/compare trusted summaries.
9. **Honest problem inventory** - [`PROBLEMS.md`](./PROBLEMS.md) sets expectations.
10. **Storage hardware accessibility** - SPoRA removes Arweave-style mining hardware; see [`STORAGE_ACCESSIBILITY.md`](./STORAGE_ACCESSIBILITY.md).

---

## 6. Non-negotiable invariants (UX must not weaken these)

From [`ARCHITECTURE.md`](./ARCHITECTURE.md), [`PRIVACY.md`](./PRIVACY.md), and [`PRIVACY_AND_PERMANENCE.md`](./PRIVACY_AND_PERMANENCE.md):

| Invariant | UX implication |
|---|---|
| **Confidentiality by default** | No "simple transparent send" shortcut |
| **Ring size >= 16 (consensus law)** | UI cannot default to smaller rings for "faster/cheaper" |
| **On-chain endowment enforcement** | Upload fees must cover treasury burden; no "free archive" mode |
| **Permanence = consensus + SPoRA** | Users/operators must hold bytes off-chain; artifacts matter |
| **Separate claiming identity** | Public attribution must not reuse spend/view keys |
| **Mainnet address policy** | Raw keys preferred over `mf...` prefix (see [`WALLET_ADDRESSES.md`](./WALLET_ADDRESSES.md)) |
| **Determinism / no unsafe bypass** | UX wrappers must call same primitives, not skip checks |
| **Privacy fees fund storage** | UX should explain upload costs tied to replication/size |

**Acceptable UX patterns:** human-readable amount display (wire stays atomic); guided wizards; encrypted backup bundles; pending-tx polling; error translation; progressive disclosure for advanced settings.

**Unacceptable UX patterns:** optional transparency mode; ring size below consensus minimum; skipping endowment pre-check; centralized-only payload storage without local artifact backup; merging claiming and spend keys.

---

## 7. Biggest friction points (ranked)

1. **Invisible confirmation model (devnet)** - txs finalize only after manual `mfnd step`; no pending->confirmed UX.
2. **Permanence != wallet backup** - seed restores funds, not payload bytes.
3. **Atomic units everywhere** - no humanization layer in CLI output.
4. **Command surface explosion** - wallet, uploads, operator, claims, light-subjectivity subcommands.
5. **Storage operator gap** - upload works in WASM; prove/serve is CLI-only.
6. **Browser demo complexity** - 3+ terminals, proxy, optional light relays.
7. **Protocol vocabulary in UI** - SPoRA, MFCL, storage_commitment_hash exposed to end users.
8. **Replication/discovery manual** - no operator registry.
9. **Dense participant docs** - casual path buried in operator checklists.
10. **No installable product** - Rust toolchain or manual release download required.

---

## 8. Recommended improvements (privacy/permanence-preserving)

All items call existing protocol paths; none weaken invariants in section 6.

### Phase A - Make the existing path obvious (low protocol risk)

| # | Improvement | Why it helps normies | Privacy/permanence impact |
|---|---|---|---|
| A1 | Prebuilt release binaries (`mfnd`, `mfn-cli`, `mfn-storage-operator`) | Removes Rust toolchain barrier | None |
| A2 | First-run wizard script (wallet new -> fund -> send -> upload -> retrieve) | Teaches dual-backup model | None |
| A3 | Per-subcommand `--help` with examples | Discoverability | None |
| A4 | Pending-tx messaging after `submit_tx` | Fixes confirmation confusion | None |
| A5 | Human-readable amounts (display only) | Reduces arithmetic errors | None |
| A6 | Error translation layer | Actionable errors | None |
| A7 | Unified encrypted backup export | Solves backup friction | None |
| A8 | Split docs: Quick start vs Operator manual | Information architecture | None |

### Phase B - Consumer product layer (no consensus change)

| # | Improvement | Why it helps normies | Privacy/permanence impact |
|---|---|---|---|
| B1 | Simplified web wallet (PWA) with Advanced panel | Better normie web UX | None if verification stays |
| B2 | WASM prove + chunk serve | Phone/laptop storage participation | None |
| B3 | Mobile/light desktop app with background prove loop | Always-on storage without CLI | None |
| B4 | Guided upload flow with artifact backup gate | Teaches permanence economics | None |
| B5 | Local-only encrypted address book | Reduces paste errors | None |
| B6 | Replication discovery manifest | Reduces manual push-chunks | None |
| B7 | Network badge + address policy UI | Prevents wrong-network sends | None |

### Phase C - Mainnet polish (optional protocol/coordination)

| # | Improvement | Notes |
|---|---|---|
| C1 | Latency-fair proof inclusion | See [`PROBLEMS.md`](./PROBLEMS.md) |
| C2 | Tiered operator model | Bondless casual vs bonded premium |
| C3 | Public RPC / light-client defaults | Normies should not run `mfnd` for wallet-only use |
| C4 | Fee-volume education | Honest treasury/backstop messaging |

---

## 9. What good normie UX looks like at mainnet maturity

A mature Permawrite UX **still feels harder than Venmo or Dropbox** - and it should, because the guarantees are different. Success looks like:

```text
Install Permawrite (signed binary or app store)
Create wallet -> write down seed -> confirm backup quiz
Optional: back up permanence artifacts (encrypted export)
Send: paste address -> enter "1.5 MFN" -> confirm -> pending -> confirmed
Upload: drop file -> endowment quote -> pay -> artifact backup reminder
Optional: toggle "Help store the network" -> background prove loop
```

Behind the scenes: ring 16, Bulletproofs, endowment math, SPoRA, CLSAG - **unchanged**. Users see outcomes, not wire codecs.

**Realistic target:** **7/10** normie-friendliness at mainnet - comparable to a good Monero GUI wallet plus a simplified Arweave bundler, with explicit permanence-backup education.

---

## 10. Evidence map (codebase)

| Topic | Path |
|---|---|
| Project pitch | [`README.md`](../README.md) |
| Intuitive overview | [`OVERVIEW.md`](./OVERVIEW.md) |
| Non-negotiable invariants | [`ARCHITECTURE.md`](./ARCHITECTURE.md) |
| Privacy absolutes | [`PRIVACY.md`](./PRIVACY.md) |
| Storage consumer feasibility | [`STORAGE_ACCESSIBILITY.md`](./STORAGE_ACCESSIBILITY.md) |
| Known weaknesses | [`PROBLEMS.md`](./PROBLEMS.md) |
| Participant onboarding | [`TESTNET.md`](./TESTNET.md) |
| Address policy | [`WALLET_ADDRESSES.md`](./WALLET_ADDRESSES.md) |
| CLI usage surface | [`mfn-cli/src/cli.rs`](../mfn-cli/src/cli.rs) |
| Wallet flows | [`mfn-cli/src/wallet_cmd.rs`](../mfn-cli/src/wallet_cmd.rs) |
| Browser demo | [`demo/web/index.html`](../demo/web/index.html) |

---

## 11. Conclusion

Permawrite chose the hardest possible product category: **Monero privacy plus Arweave permanence in one coin**. That choice correctly prioritizes freedom over convenience.

The work ahead is not to make Permawrite "easy like a centralized app." It is to make the **existing guarantees reachable** through installable products, guided flows, honest education about dual backup, and human-readable surfaces - without any shortcut that trades permanence or privacy for smoother onboarding.

**Assessment date:** 2026-07-03 (public devnet v1 era, pre-audit).
