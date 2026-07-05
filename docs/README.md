# Permawrite Documentation

Welcome. These docs cover the full design of Permawrite — a novel blockchain that funds permanent storage with fees from private transactions.

<p align="center">
  <img src="./img/architecture-stack.svg" alt="Permawrite crate dependency stack" width="100%">
</p>

## Reading paths

### Just want to understand what this is?

- 📖 [**OVERVIEW.md**](./OVERVIEW.md) — the project, the vision, how it works, why it's hard. Intuition first, with links to the technical specs.
- 🧭 [**PRIVACY_AND_PERMANENCE.md**](./PRIVACY_AND_PERMANENCE.md) — why financial privacy and data permanence belong in **one** network: freedom, incentives, economics, and why no single actor should control money or information.
- 📊 [**STORAGE_COST_MODEL.md**](./STORAGE_COST_MODEL.md) — per-gigabyte endowment projections, Kryder scenarios, and fiat equivalents at default params.
- 📚 [**GLOSSARY.md**](./GLOSSARY.md) — every acronym and protocol-specific term, alphabetical. Reach for it whenever you hit unfamiliar jargon.

### Want the technical design?

- 🏗 [**ARCHITECTURE.md**](./ARCHITECTURE.md) — whitepaper-grade system overview. Wire codec, domain tags, every check `apply_block` performs in order.
- 🧷 [**M1_VALIDATOR_ROTATION.md**](./M1_VALIDATOR_ROTATION.md) — Milestone M1: validator bond/unbond, churn caps, epoch model (spec + code map).
- 🔒 [**PRIVACY.md**](./PRIVACY.md) — the privacy half. Stealth addresses, Pedersen commitments, CLSAG, Bulletproofs, decoy selection, OoM, the counterfeit-input attack and how we closed it.
- 🪙 [**FUNGIBILITY.md**](./FUNGIBILITY.md) — why full anonymity makes MFN interchangeable (vs tainted coins on traceable ledgers).
- 🗄 [**STORAGE.md**](./STORAGE.md) — the permanence half. Chunking, the SPoRA proof system, the endowment formula, the PPB-precision yield accumulator.
- 💻 [**STORAGE_ACCESSIBILITY.md**](./STORAGE_ACCESSIBILITY.md) — feasibility of consumer-grade storage (vs Arweave-style hardware), current gaps, and roadmap.
- 👤 [**UX_ACCESSIBILITY.md**](./UX_ACCESSIBILITY.md) — normie UX assessment for mature mainnet: current friction, non-negotiable invariants, and privacy/permanence-preserving improvements.
- 🌐 [**DECENTRALIZATION.md**](./DECENTRALIZATION.md) — hardware profiles for every network role, how they shape decentralization, and improvements that preserve the architecture.
- 🗳 [**CONSENSUS.md**](./CONSENSUS.md) — the PoS engine. Slot model, VRF leader election, BLS finality, equivocation slashing, liveness slashing.
- 💰 [**ECONOMICS.md**](./ECONOMICS.md) — the money. Emission curve, fee split, treasury dynamics, the two-mode (r>0 yield-bearing vs r=0 deflation-funded) endowment model.
- 📈 [**SUPPLY_CURVE.md**](./SUPPLY_CURVE.md) — scheduled MFN supply by year, decade, and century, with a labeled visual curve.
- 🛡 [**SECURITY_CONSIDERATIONS.md**](./SECURITY_CONSIDERATIONS.md) — protocol-level trust assumptions and threat model: what finality does/doesn't prove, exact header-signing coverage (the `utxo_root` nuance), BLS rogue-key/PoP, VRF interop, determinism surface.
- ⚠️ [**PROBLEMS.md**](./PROBLEMS.md) — honest inventory of real economic, incentive, architectural, and protocol/security-model weaknesses (no invented problems).
- 🎲 [**CASINO_RANDOMNESS_FEASIBILITY.md**](./CASINO_RANDOMNESS_FEASIBILITY.md) — can a chain-native, provably fair casino fund the treasury/endowment? Determinism vs randomness, pros/cons, architectural verdict (not a roadmap item).
- 📜 [**SMART_CONTRACTS_FEASIBILITY.md**](./SMART_CONTRACTS_FEASIBILITY.md) — should Permawrite add general-purpose on-chain programmability? Codebase fit, privacy/permanence trade-offs, implementation cost, and verdict (do not ship).

### Want to know what's next?

- 🛣 [**ROADMAP.md**](./ROADMAP.md) — tier-by-tier rollout plan. Current state, validator rotation (M1), node daemon (M2), wallet CLI (M3), WASM (M4), Tier 2/3/4 privacy upgrades.
- ⚠️ [**PROBLEMS.md**](./PROBLEMS.md) — the real limitations and open incentive/architectural holes (required reading for anyone evaluating the design seriously).
- 🧹 [**CODEBASE_IMPROVEMENTS.md**](./CODEBASE_IMPROVEMENTS.md) — prioritized engineering-quality audit: repo hygiene, encoding workflow, unwrap density, god files, CI velocity, script duplication.

## Cross-cuts

If you're trying to understand a specific feature, here's where it's documented across the doc set:

| Feature | Layperson | Technical | Detail |
|---|---|---|---|
| Hidden senders | OVERVIEW § Privacy half | PRIVACY § CLSAG | code: `mfn-crypto/src/clsag.rs` |
| Hidden receivers | OVERVIEW § Privacy half | PRIVACY § Stealth | code: `mfn-crypto/src/stealth.rs` |
| Hidden amounts | OVERVIEW § Privacy half | PRIVACY § Pedersen | code: `mfn-crypto/src/pedersen.rs` |
| Fungibility / coin taint | OVERVIEW § Privacy half | FUNGIBILITY (full document) | PRIVACY § RingCT |
| Range proofs | OVERVIEW § Privacy half | PRIVACY § Range proofs | code: `mfn-crypto/src/bulletproofs.rs` |
| Decoy selection | OVERVIEW § Privacy half | PRIVACY § Decoy realism | code: `mfn-crypto/src/decoy.rs` |
| Storage permanence | OVERVIEW § Permanence half | STORAGE § Endowment | code: `mfn-storage/src/endowment.rs` |
| SPoRA proofs | OVERVIEW § SPoRA | STORAGE § SPoRA | code: `mfn-storage/src/spora.rs` |
| Endowment formula | OVERVIEW § Endowment | ECONOMICS § Permanence equation | code: `mfn-storage/src/endowment.rs` |
| Storage cost / GB | STORAGE_COST_MODEL (full document) | STORAGE § Endowment | code: `mfn-storage/src/endowment.rs` |
| PoS + leader election | OVERVIEW (implicit) | CONSENSUS § Leader election | code: `mfn-consensus/src/consensus/engine.rs` |
| BLS finality | OVERVIEW (implicit) | CONSENSUS § Committee finality | code: `mfn-bls/src/sig.rs` |
| Equivocation slashing | (covered) | CONSENSUS § Equivocation | code: `mfn-consensus/src/slashing.rs` |
| Liveness slashing | (covered) | CONSENSUS § Liveness | code: `mfn-consensus/src/validator_evolution/liveness.rs` |
| Counterfeit-input attack | OVERVIEW § Why this is hard | PRIVACY § Counterfeit-input | code: `mfn-consensus/src/block/apply.rs` |
| Fee/treasury split | OVERVIEW § How they fuse | ECONOMICS § Fee economics | code: `mfn-consensus/src/emission.rs` |
| Emission curve | (covered) | ECONOMICS § Emission curve | code: `mfn-consensus/src/emission.rs` |
| Supply schedule | (covered) | SUPPLY_CURVE | code: `mfn-consensus/src/emission.rs` |
| Trust assumptions & threat model | — | SECURITY_CONSIDERATIONS (full document) | — |
| Known weaknesses & open risks | — | PROBLEMS (full document) | — |
| Hardware & decentralization | — | DECENTRALIZATION (full document) | STORAGE_ACCESSIBILITY |
| Normie UX / mainnet accessibility | UX_ACCESSIBILITY (full document) | STORAGE_ACCESSIBILITY §4–5 | ROADMAP (M3/M4/M6) |

## Where to file questions

- **Conceptual / design questions:** Open a GitHub Discussion.
- **Security issues:** [`../SECURITY.md`](../SECURITY.md). **Do not** file as a public issue.
- **Bug reports:** GitHub Issues.
- **Contributions:** see [`../CONTRIBUTING.md`](../CONTRIBUTING.md).
