# Fungibility and anonymity

**Question:** Why does Permawrite's full anonymity make MFN more fungible than coins on pseudonymous or transparent networks — where individual units can be "tainted" by their transaction history?

**Short answer:** On transparent and pseudonymous chains, every coin carries a public pedigree. Exchanges, custodians, and chain-analytics firms routinely label specific UTXOs or addresses as risky, stolen, or sanctioned — and refuse to treat them like any other unit. Permawrite hides sender, receiver, and amount on every regular transfer, so third parties cannot attach a durable history label to the specific MFN you receive. One unit of MFN is economically interchangeable with another in a way that traceable coins are not.

See also: [`PRIVACY.md`](./PRIVACY.md) (mechanisms), [`OVERVIEW.md § How the privacy half works`](./OVERVIEW.md#how-the-privacy-half-works-no-formulas), [`PROBLEMS.md § 9`](./PROBLEMS.md#9-decoy-selection-remains-a-statistical-not-cryptographic-privacy-property) (honest limits).

---

## 1. What fungibility means

**Fungibility** is the property that any one unit of a good is interchangeable with any other unit of the same kind. A $20 bill does not come with a biography. A merchant does not ask which previous owner held it before accepting payment.

Money works as money only when recipients do not need to audit provenance. When provenance *does* matter — when some units are treated as "clean" and others as "dirty" — fungibility breaks down. The dirty units trade at a discount, get blocked at gateways, or become unusable even though they are numerically identical on the ledger.

Blockchains inherit this problem from their accounting model. If the ledger publishes enough detail to reconstruct who paid whom, then **history becomes a property of the coin itself**.

---

## 2. Pseudonymous is not anonymous

Most public blockchains are **transparent** (Bitcoin-style) or **pseudonymous** (account-based transparent ledgers like early Ethereum).

| Property | Transparent / pseudonymous | Permawrite (RingCT) |
|---|---|---|
| **Sender** | Public address or pubkey | Hidden among ring decoys (CLSAG) |
| **Receiver** | Public address | One-time stealth output |
| **Amount** | Cleartext | Pedersen commitment + Bulletproof |
| **Stable identity on-chain** | Yes — addresses persist | No — outputs are unlinkable one-time points |
| **History label sticks to** | Specific UTXO or address | *Cannot be attached to a specific spent output* |

**Pseudonymity** means you use a nickname instead of your legal name. The nickname is still a **stable identifier**. Every payment to or from `0xABC…` or `bc1q…` adds another row to a permanent public database tied to that identifier.

**Anonymity** — in the sense Permawrite targets — means observers cannot determine *which* output was spent, *who* received a payment, or *how much* moved. There is no stable public label to build a dossier on.

---

## 3. How transaction history taints coins

On traceable ledgers, "taint" is not a protocol field. It is a **social and commercial overlay** built from public data:

1. **Chain analytics** clusters addresses by co-spend heuristics, peel chains, exchange deposits, and timing.
2. **Incident response** tags UTXOs that passed through known hacks, ransomware wallets, sanctions-listed entities, or darknet markets.
3. **Gatekeepers enforce lists** — exchanges, payment processors, and OTC desks freeze or reject deposits that graph algorithms flag as high-risk.
4. **Discount markets** emerge where "clean" BTC trades at par and flagged coins sell at 5–30% haircuts (documented in Bitcoin OTC and mixer-adjacent markets).

The taint travels **forward and backward** along the graph:

- **Forward:** Coins that touched a flagged address inherit risk scores in proportion to graph distance.
- **Backward:** Innocent recipients who accepted payment from a later-flagged address can find their UTXOs rejected upstream.

None of this requires breaking cryptography. The ledger already published the graph. Analytics firms and compliance departments are the taint engine.

### The merchant's dilemma

A business accepting transparent crypto must implicitly ask:

> "Where did *this specific coin* come from?"

That question is impossible on cash. It is routine on Bitcoin. The answer determines whether the business keeps the payment, faces account closure, or absorbs a compliance review.

**Broken fungibility is not an edge case.** It is the default outcome of a fully traceable monetary graph at scale.

---

## 4. How Permawrite restores interchangeability

Permawrite's default transaction class is **confidential**. Every regular transfer hides the three fields that chain analytics need to label individual units:

### 4.1 Hidden sender (CLSAG + key images)

Each input is authorized by a **ring signature** over 16 ring members (consensus-enforced minimum). Observers learn only: "one of these 16 UTXOs was spent." They do not learn which.

**Key images** prevent double-spending without revealing *which* key spent. The chain stores spent images, not an address book of owners.

**Fungibility effect:** You cannot mark "the UTXO at ring position 7" as tainted after the spend — the spend is intentionally ambiguous.

→ [`PRIVACY.md § CLSAG`](./PRIVACY.md#3-clsag-ring-signatures)

### 4.2 Hidden receiver (stealth addresses)

Recipients publish a long-term address, but every payment lands in a **fresh one-time output**. Scanning the chain with a view key finds your payments; public observers see unrelated random curve points.

**Fungibility effect:** There is no persistent deposit address whose inbound history can be scored. Exchange deposit clustering does not apply to the receiver side.

→ [`PRIVACY.md § Stealth addresses`](./PRIVACY.md#2-stealth-addresses)

### 4.3 Hidden amounts (RingCT)

Values are **Pedersen commitments**; the chain verifies balance without opening envelopes. **Bulletproofs** prove non-negativity without revealing magnitude.

**Fungibility effect:** Analytics cannot tier coins by value flow ("this output received exactly 6.14 MFN from a mixer") or detect structuring patterns from cleartext amounts.

→ [`PRIVACY.md § Pedersen commitments`](./PRIVACY.md#1-pedersen-commitments)

### 4.4 No public address book

Permawrite has no global registry mapping outputs to named owners. Ring membership is checked against the UTXO accumulator — existence, not identity.

**Fungibility effect:** The prerequisite for taint databases — a stable ID per economic actor — does not exist at the protocol layer.

### 4.5 Tier 3 upgrade path (stronger still)

Today's ring size is 16 (Monero parity). The roadmap's **one-of-many** proofs ([`PRIVACY.md § OoM`](./PRIVACY.md#4-one-of-many-proofs-oom--tier-3)) will let spenders prove membership in the **entire UTXO set** with logarithmic proof size. That tightens fungibility further: the real input is hidden among *all* unspent outputs that have ever existed, not among 15 decoys.

---

## 5. From privacy properties to economic interchangeability

Put the pieces together:

```text
Transparent chain     →  history is public     →  coins inherit labels     →  weak fungibility
Permawrite RingCT     →  history is hidden     →  labels cannot stick      →  strong fungibility
```

| Scenario | Transparent coin | MFN (regular transfer) |
|---|---|---|
| Exchange asks "source of funds?" | Graph trace often answers | Third party cannot trace input lineage from chain data alone |
| Merchant receives post-hoc flag on payer | Recipient's UTXO may be rejected | No visible link from payer to recipient output |
| OTC desk applies risk score | Per-UTXO or per-address score | Scoring requires off-chain leaks or metadata, not ledger fields |
| User merges small outputs ("consolidation") | Creates obvious wallet fingerprint | Ring spends do not reveal consolidation intent to observers |

This is why Monero-class privacy is often described as **fungibility by default**: the unit of account is MFN, not "MFN that touched address X."

Permawrite inherits that model and extends it with permanence on the same chain — private economic activity and durable storage share one coin whose regular transfers do not publish spend graphs.

---

## 6. Honest limits — anonymity is not magic

Fungibility improves when **history cannot be read from the ledger**. It does not eliminate all discrimination vectors:

| Limit | What still leaks | Fungibility impact |
|---|---|---|
| **Transaction metadata** | Tx count, timing, fee tier, input/output *counts* | Statistical inference remains possible |
| **Network layer** | IP addresses, peer timing, unencrypted RPC | Off-chain correlation |
| **Decoy realism** | Gamma-age sampling is statistical, not perfect ([`PROBLEMS.md § 9`](./PROBLEMS.md#9-decoy-selection-remains-a-statistical-not-cryptographic-privacy-property)) | Sophisticated analysts may bias ring guesses |
| **User behavior** | Reusing addresses, predictable spend patterns, public claiming keys | Self-inflicted linkability |
| **Coinbase transparency** | Block rewards and storage-proof payouts are structurally transparent | Fresh issuance is visible; merges into RingCT pools later |
| **Optional authorship claims** | Voluntary Schnorr signatures bind a public claiming key to `data_root` | Financial and publishing identities must stay key-separated ([`AUTHORSHIP.md`](./AUTHORSHIP.md)) |
| **Custodial policy** | Exchanges can still apply KYC/AML to *people*, not *coins* | Gatekeepers may demand identity regardless of chain privacy |

These are reasons to improve wallets, networking, and Tier 3 cryptography — not reasons to treat transparent ledgers as "good enough." A taint model built on heuristics is weaker when the underlying graph is hidden.

---

## 7. Comparison at a glance

| Network class | Example | History on-chain | Typical taint model | Fungibility |
|---|---|---|---|---|
| **Transparent UTXO** | Bitcoin | Full graph | Chain analytics + exchange blocklists | Weak — UTXO-level discrimination |
| **Transparent account** | Ethereum (base layer) | Full graph | Address scoring + contract tracing | Weak — address-level discrimination |
| **Pseudonymous + mixers** | Bitcoin + external mixer | Obfuscated but often breakable | Mixer output heuristics; regulatory hostility | Fragile — depends on mixer quality |
| **Default-private RingCT** | Monero, Permawrite | Sender/receiver/amount hidden | Cannot label specific spent outputs from ledger | Strong — units interchange by default |
| **Permawrite Tier 3 (planned)** | OoM over full UTXO set | Strongest input ambiguity | Decoy heuristics further weakened | Stronger still |

---

## 8. Why this matters for Permawrite specifically

Permawrite is not only a privacy coin. It is a **privacy coin that funds permanent storage** ([`PRIVACY_AND_PERMANENCE.md`](./PRIVACY_AND_PERMANENCE.md)). Fungibility matters twice here:

1. **As money.** Users must be able to spend MFN without proving the moral pedigree of every input. If MFN inherited Bitcoin-style taint, the privacy half would fail its basic job — and fee revenue that funds permanence would shrink.

2. **As infrastructure payment.** Storage endowments and fees are paid in the same unit. Weak fungibility would split the economy into "acceptable" and "unacceptable" MFN, undermining a single treasury and a single incentive loop ([`ECONOMICS.md`](./ECONOMICS.md)).

Strong anonymity is not a luxury feature. It is what makes **one MFN equal to another MFN** in commerce — the same way one dollar bill equals another, regardless of who held it first.

---

## See also

- [`PRIVACY.md`](./PRIVACY.md) — full cryptographic specification
- [`OVERVIEW.md`](./OVERVIEW.md) — intuition for ring signatures, stealth addresses, RingCT
- [`ARCHITECTURE.md § Design pillars`](./ARCHITECTURE.md#design-pillars) — "confidentiality by default"
- [`PRIVACY_AND_PERMANENCE.md`](./PRIVACY_AND_PERMANENCE.md) — why privacy and permanence belong together
- [`PROBLEMS.md`](./PROBLEMS.md) — statistical decoy limits and other honest gaps
