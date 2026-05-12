# Permawrite Documentation

Welcome. These docs cover the full design of the Permawrite blockchain — privacy-preserving, permanent-storage, single chain.

<p align="center">
  <img src="./img/architecture-stack.svg" alt="Permawrite crate dependency stack" width="100%">
</p>

## Reading paths

### Just want to understand what this is?

- 📖 [**OVERVIEW.md**](./OVERVIEW.md) — the project, the vision, how it works, why it's hard. Smart-layperson level: no heavy formulas, lots of intuition.
- 🧭 [**PRIVACY_AND_PERMANENCE.md**](./PRIVACY_AND_PERMANENCE.md) — why financial privacy and data permanence belong in **one** network (freedom, incentives, economics).
- 📚 [**GLOSSARY.md**](./GLOSSARY.md) — every acronym and protocol-specific term, alphabetical. Reach for it whenever you hit unfamiliar jargon.

### Want the technical design?

- 🏗 [**ARCHITECTURE.md**](./ARCHITECTURE.md) — whitepaper-grade system overview. Wire codec, domain tags, every check `apply_block` performs in order.
- 🔒 [**PRIVACY.md**](./PRIVACY.md) — the privacy half. Stealth addresses, Pedersen commitments, CLSAG, Bulletproofs, decoy selection, OoM, the counterfeit-input attack and how we closed it.
- 🗄 [**STORAGE.md**](./STORAGE.md) — the permanence half. Chunking, the SPoRA proof system, the endowment formula, the PPB-precision yield accumulator.
- 🗳 [**CONSENSUS.md**](./CONSENSUS.md) — the PoS engine. Slot model, VRF leader election, BLS finality, equivocation slashing, liveness slashing.
- 💰 [**ECONOMICS.md**](./ECONOMICS.md) — the money. Emission curve derivation, fee split, treasury dynamics, the `r > i` non-degeneracy condition.

### Want to know what's next?

- 🛣 [**ROADMAP.md**](./ROADMAP.md) — tier-by-tier rollout plan. Current state, validator rotation (M1), node daemon (M2), wallet CLI (M3), WASM (M4), Tier 2/3/4 privacy upgrades.

## Cross-cuts

If you're trying to understand a specific feature, here's where it's documented across the doc set:

| Feature | Layperson | Technical | Detail |
|---|---|---|---|
| Hidden senders | OVERVIEW § Privacy half | PRIVACY § CLSAG | code: `mfn-crypto/src/clsag.rs` |
| Hidden receivers | OVERVIEW § Privacy half | PRIVACY § Stealth | code: `mfn-crypto/src/stealth.rs` |
| Hidden amounts | OVERVIEW § Privacy half | PRIVACY § Pedersen | code: `mfn-crypto/src/pedersen.rs` |
| Range proofs | OVERVIEW § Privacy half | PRIVACY § Range proofs | code: `mfn-crypto/src/bulletproofs.rs` |
| Decoy selection | OVERVIEW § Privacy half | PRIVACY § Decoy realism | code: `mfn-crypto/src/decoy.rs` |
| Storage permanence | OVERVIEW § Permanence half | STORAGE § Endowment | code: `mfn-storage/src/endowment.rs` |
| SPoRA proofs | OVERVIEW § SPoRA | STORAGE § SPoRA | code: `mfn-storage/src/spora.rs` |
| Endowment formula | OVERVIEW § Endowment | ECONOMICS § Permanence equation | code: `mfn-storage/src/endowment.rs` |
| PoS + leader election | OVERVIEW (implicit) | CONSENSUS § Leader election | code: `mfn-consensus/src/consensus.rs` |
| BLS finality | OVERVIEW (implicit) | CONSENSUS § Committee finality | code: `mfn-bls/src/sig.rs` |
| Equivocation slashing | (covered) | CONSENSUS § Equivocation | code: `mfn-consensus/src/slashing.rs` |
| Liveness slashing | (covered) | CONSENSUS § Liveness | code: `mfn-consensus/src/block.rs` |
| Counterfeit-input attack | OVERVIEW § Why this is hard | PRIVACY § Counterfeit-input | code: `mfn-consensus/src/block.rs` (apply_block) |
| Fee/treasury split | OVERVIEW § How they fuse | ECONOMICS § Fee economics | code: `mfn-consensus/src/emission.rs` |
| Emission curve | (covered) | ECONOMICS § Emission curve | code: `mfn-consensus/src/emission.rs` |

## Where to file questions

- **Conceptual / design questions:** Open a GitHub Discussion.
- **Security issues:** [`../SECURITY.md`](../SECURITY.md). **Do not** file as a public issue.
- **Bug reports:** GitHub Issues.
- **Contributions:** see [`../CONTRIBUTING.md`](../CONTRIBUTING.md).
