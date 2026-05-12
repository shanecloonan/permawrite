# Permawrite — Overview

> **Audience.** Smart people who want to understand what's happening without reading the formulas.
> Everything in this document has a rigorous counterpart in the [technical docs](./ARCHITECTURE.md). Anywhere you want the math, follow the **→ deep dive** links.

---

## The one-sentence pitch

**Permawrite is a blockchain that's as private as Monero and stores data more permanently than Arweave — at the same time, in the same chain, with the same coin.**

The deep idea: **the fees people pay for financial privacy** are exactly what **funds permanent data storage**.

---

## Why this doesn't exist yet

Today's "Web3 stack" splits the two things humans most want from a public ledger across two completely separate networks:

- **Monero** gives you the strongest publicly-deployed financial privacy on earth. But every transaction's payload is *just money*. You can't anchor a 4 GB scientific dataset in it. The chain isn't designed for storage permanence; it's designed for cash.
- **Arweave** gives you the strongest publicly-deployed data permanence on earth. But the transactions that pin data are *fully transparent*. Every uploader, every payer, every receiver, every byte attribution — public.

These two properties are deeply complementary and almost never coexist. If you want to anonymously archive a whistleblower document forever, you need both. If you want to pay a journalist privately *and* timestamp the source material so it can't be retroactively edited, you need both. If you want to keep medical records that simultaneously honor patient privacy and last a century, you need both.

There is no chain on earth that does both today. Permawrite is the attempt to be the first one.

---

## How the privacy half works (no formulas)

Three things are hidden by every privacy transaction on Permawrite:

### 1. *Who sent the money* — ring signatures with deniable spending

Imagine you want to sign a check, but you also want the bank to be unable to tell whether you signed it or any of 15 other people in your friend group signed it. You bring 15 other people's public keys along with your own, smear them all together with a cryptographic blender, and produce a single signature that says: **"exactly one of these 16 people signed this, and the math guarantees that, but no observer can tell which one."**

That's a **ring signature**. Permawrite uses a modern variant called **CLSAG** ("concise linkable spontaneous anonymous group" signatures — the same one Monero shipped in 2020). The "linkable" part means: while observers can't tell *which* of the 16 keys spent, they *can* tell if the same key tries to spend a second time, which is what prevents double-spending.

The mechanism the chain uses to detect "this key has spent already" is called a **key image** — a deterministic, single-use fingerprint of the real signer's private key that's revealed by the signature without revealing the key itself. The chain tracks a single growing set of "key images seen so far." A second appearance is just rejected. This is how you get **single-spend enforcement without an address book**.

Permawrite's roadmap goes further: a primitive called a **one-of-many proof** (technical name: Groth–Kohlweiss / Triptych) lets the ring size grow to **the entire UTXO set** with proof size growing only *logarithmically*. At Tier 3 of the rollout, every signature mathematically guarantees: "the real spender is one of *all unspent outputs that have ever existed*" — and the proof is still small enough to fit in a block.

> **→ Deep dive:** [`docs/PRIVACY.md § Ring signatures`](./PRIVACY.md#3-clsag-ring-signatures)

### 2. *Who received the money* — stealth addresses

You can imagine your wallet's "public address" as having two parts: a **view key** and a **spend key**. You publish the *full* public address. The sender does some cryptographic origami with their own random number plus your published address and produces a brand-new, **one-time, throwaway address** — different every single transaction — that *only you* can recognize as belonging to you.

Two consequences:

- Anyone scanning the blockchain looking for "where did money go?" sees only a wall of one-time addresses that share no visible link to any wallet.
- *You* — the holder of the matching private view key — can scan the chain and detect "this output was for me" without revealing anything about your identity.

This is the same dual-key CryptoNote stealth-address scheme Monero uses, with hashing and serialization specified bit-for-bit so that wallets in different languages produce identical addresses.

> **→ Deep dive:** [`docs/PRIVACY.md § Stealth addresses`](./PRIVACY.md#2-stealth-addresses)

### 3. *How much money moved* — Pedersen commitments

Bitcoin transactions publish amounts in cleartext. Permawrite outputs publish a *sealed envelope* — a number that mathematically commits to the amount without revealing it. The recipient knows what's inside (because the sender encrypted it for them); the network can't see it.

But here's the magic: the chain *can still verify* that **inputs equal outputs** (no money was minted out of thin air), purely by adding the sealed envelopes together algebraically. The envelopes cancel out if and only if the totals balance — *without ever opening them*.

The math involved is called a **Pedersen commitment**, and the technique of doing transaction balance-checks on hidden amounts is what makes Permawrite (and Monero) a "RingCT" chain.

There's one extra concern: a malicious user could try to encode a *negative* amount, which would also balance, and effectively print money. To prevent this, every output ships with a **range proof** — a small cryptographic certificate that says "the hidden amount is in a sensible non-negative range (0 to 2⁶⁴−1)" without revealing what it is. Permawrite uses **Bulletproofs**, the same compact log-size range proofs Monero deploys.

> **→ Deep dive:** [`docs/PRIVACY.md § Pedersen commitments + range proofs`](./PRIVACY.md#1-pedersen-commitments)

### The honest comparison to Monero

Tier 1 (today's primitives) is already close to Monero on every dimension:

| Property | Monero | Permawrite Tier 1 | Permawrite Tier 3 (planned) |
|---|---|---|---|
| Hidden senders | Ring of 16 | Ring of 16 | Ring of *all UTXOs ever* |
| Hidden receivers | ✓ stealth | ✓ stealth | ✓ stealth |
| Hidden amounts | ✓ RingCT | ✓ RingCT | ✓ RingCT |
| Public address book | ✗ none | ✗ none | ✗ none |
| Single-spend enforcement | key image | key image | key image |
| Decoy realism | gamma-age sampling | gamma-age sampling (identical) | gamma + ZK-OoM |

The point of Permawrite is not "marginally better privacy." The point is "Monero-grade privacy **plus** the ability to anchor permanent data on the same chain."

---

## How the permanence half works (no formulas)

Now we flip to the other half. How do you guarantee that a 4 GB dataset uploaded today is still retrievable in 200 years?

The naive answer ("pay storage providers monthly") fails because nobody guarantees they'll keep paying. The correct answer is: **make the storer's incentive last forever, with one upfront payment.**

### The endowment idea

Think of a university endowment. Donors give a large lump sum *once*. The endowment is invested. The university spends only the *yield* — never touches the principal — and thus the fund lasts forever, paying the same dollar amount every year (in real terms).

Permawrite does the same thing for your data:

1. You upload a file. Along with the file, you pay an **endowment fee** in MFN.
2. The endowment is sized so that, if the network is paying out a small real yield (say, 1% annual) on it forever, the yield covers the actual storage cost of your file forever — even as storage costs slowly decline.
3. Storage operators "earn" by repeatedly proving they still hold your file. Each successful proof drips a tiny fraction of the per-file yield to whoever's making the proof.

This is the **Arweave model**, refined. The crucial number is "how much endowment is enough?" — and the answer comes from a small piece of finance math:

```
required endowment = (current storage cost) × (1 + storage cost inflation)
                                              ─────────────────────────────
                                              (real yield) − (cost inflation)
```

That denominator — `real_yield − cost_inflation` — has to be positive. Otherwise your endowment isn't earning more than your file is costing, and the model is bankrupt. Permawrite **hard-codes** this check into consensus (we call it `validate_endowment_params` in code): if anyone tries to push consensus parameters that violate `r > i`, the chain rejects them.

You can think of this as the **permanence non-degeneracy constraint**. It's the single equation that mathematically guarantees infinite-horizon solvency. As long as the real yield exceeds the cost decline curve, your data will outlive the chain itself.

> **→ Deep dive:** [`docs/ECONOMICS.md § Endowment derivation`](./ECONOMICS.md#1-the-permanence-equation-derived)

### Random-access audits (SPoRA)

OK so storage operators are incentivized to keep data alive. But how do you *verify* they actually have it? They could just claim they do.

The technique is called **SPoRA — Succinct Proofs of Random Access**. The chain, every block, deterministically picks:
- A specific stored file (one of the active commitments),
- A specific 256 KiB chunk of that file (out of however many chunks it's split into),
- A specific block.

It asks: *"Show me chunk #N of file F, along with a Merkle proof that it's part of the committed Merkle root we have on file."* The proof is tiny (≈ 256 KiB of data + log(chunk_count) hashes). Verifying it costs a few microseconds. Producing it requires the operator to actually have the data on hand — they can't fake the chunk without breaking SHA-2-256.

The challenge is **deterministic from the block context**. Operators can't predict which chunk will be asked far in advance — but every node, including the operator, can compute the answer the moment a new block lands. The operator races to publish a proof; the first valid one earns the trickle of yield from that file's endowment.

> **→ Deep dive:** [`docs/STORAGE.md § SPoRA challenge/response`](./STORAGE.md#3-spora-deterministic-challenges)

### The replication factor

A single hard drive can fail. We don't trust one operator with your only copy. Every storage commitment carries an explicit `replication` factor — the minimum number of distinct operators who must each independently hold the data. The chain enforces minimum/maximum replication parameters (`min_replication`, `max_replication`) at the protocol level.

Replication is *paid for*: the endowment formula multiplies by replication. Want 5 redundant copies? You pay 5×.

### Why does this need a privacy coin?

Because of where the money comes from. The endowment isn't subsidized by infinite money-printing — that would tank the coin's purchasing power, which would tank the real yield, which would break the permanence equation.

The endowment is subsidized by **transaction fees**. Most chains burn fees, or give them all to the producer. Permawrite *splits the fee*: a configurable fraction (default 90%) goes into the **treasury**, and only the remaining slice goes to the block producer. The treasury is what pays storage operators each block.

So the chain needs ongoing fee revenue. **A pure storage chain doesn't generate enough.** People don't upload data every second; they upload it occasionally. There's no constant fee flow.

But a *privacy* chain has a constant, structural fee flow. **Anonymity has value all the time**, not just when someone wants to archive a file. Every confidential transfer pays a fee. Every fee goes 90% into the storage treasury. Privacy demand becomes the inexhaustible economic engine that funds permanence.

This isn't an afterthought — it's the design's central insight. **The privacy half is the marketing engine and the cashflow engine. The permanence half is the durable utility.** Each half needs the other to be economically viable. Together they are sustainable.

---

## How they fuse — concrete example

Let's trace one transaction through the system:

> Alice wants to (1) anonymously pay Bob 1.0 MFN and (2) anonymously anchor a 100 MB scientific dataset on-chain forever.

She constructs a single transaction with:

- **Inputs.** A ring of 16 outputs that *includes* one she actually controls (she picks 15 decoys from the chain's history using the same gamma-distributed temporal selection that Monero uses). She signs with CLSAG, revealing her key image but not which of the 16 keys she controls.
- **Outputs.**
  - A stealth address derived from Bob's public address, carrying a Pedersen commitment to 1.0 MFN.
  - A stealth address derived from her own public address, carrying a commitment to her change amount.
  - Each output ships with a Bulletproof range proof certifying its hidden amount is non-negative.
- **Storage payload.** A `StorageCommitment` containing:
  - The Merkle root of her 100 MB dataset, split into ~400 chunks of 256 KiB each.
  - The size, chunk size, chunk count, and chosen replication factor (say, 3 copies).
  - A Pedersen commitment to the endowment amount (so the *endowment too* is amount-private, but balance-checked by consensus).
- **Fee.** Say 0.01 MFN.

She submits the tx. A block producer (chosen by stake-weighted VRF for that slot) includes it. The committee finalizes the block with aggregated BLS12-381 signatures.

Inside `apply_block`:

1. **Privacy checks.** Every CLSAG ring member is verified to exist as a real UTXO in the chain's state (this is the chain-level guard that closed the *counterfeit-input attack* — without it, an attacker could fabricate ring members with bogus commitments and mint money). Every range proof is verified. The key image is checked for prior use; if seen before, the tx is rejected.
2. **Balance check.** The Pedersen commitments on inputs and outputs are summed; they must cancel out (modulo the fee adjustment). No formula needed for the user — the math is the receipt.
3. **Endowment check.** The chain computes the required endowment for Alice's storage commitment using the protocol-level formula. The fraction of the transaction fee earmarked for the treasury must be at least this amount, or the tx is rejected as *underfunded*. (No free permanence.)
4. **State updates.** Alice's spent output is marked spent (key image recorded). Bob and Alice's change outputs are added to the UTXO set. The storage commitment is registered in the chain's storage registry with `last_proven_height = 0`. The endowment funds enter the treasury.

In every subsequent block, the chain deterministically picks one stored commitment and asks: "prove chunk N of you exists." Whichever storage operator publishes a valid SPoRA proof first earns a slice of that file's accrued yield. Alice's dataset is being kept alive in real-time.

Two hundred years from now, if the permanence equation has held — if real yield has continued to exceed storage cost decline — the dataset is still recoverable, the still-living operators are still being paid out of the still-solvent treasury, and the system has worked exactly as designed.

---

## Why this is genuinely hard

Worth saying plainly: there are real reasons nobody's shipped this yet.

1. **Privacy + permanence pull in opposite directions for state size.** Privacy schemes (ring signatures, range proofs) cost bytes per tx. Permanent storage adds bytes per tx. Together you've got a chain with chunky transactions. The mitigation is OoM proofs (log-size rings) at Tier 3 and Bulletproof+ at Tier 2, both of which compress the privacy footprint by ~10x.
2. **The endowment math has to hold across decades.** If real yield drops below storage-cost inflation for any sustained period, the model becomes a slow-motion bank run. The mitigation is the hardcoded `r > i` consensus check, plus a long simulation campaign (in the roadmap) to stress-test parameter choices against historical storage-cost data.
3. **Ring-membership verification is consensus-critical and was almost the first thing to go wrong.** An earlier version of `apply_block` didn't verify that CLSAG ring members were real on-chain UTXOs — meaning an attacker could fabricate ring members with arbitrary hidden commitments and inflate balances arbitrarily. This was caught and fixed before any deployment (see the [counterfeit-input attack section](./PRIVACY.md#counterfeit-input-attack-closed) of the privacy doc). Everything not yet built carries similar latent traps; this is a chain where individual line-level mistakes can be economically catastrophic.
4. **Decoy realism is a research problem.** Even Monero's gamma-distributed decoy selection has been shown vulnerable to statistical de-anonymization in some adversarial contexts. Permawrite uses the same default, then plans to move to OoM-over-the-whole-UTXO-set at Tier 3, which strictly dominates.

These are not blockers. They're acknowledged design tensions. The project is built with the explicit posture that **anything you can't prove is wrong**.

---

## Where to read next

- **For the math of the privacy half** → [`docs/PRIVACY.md`](./PRIVACY.md)
- **For the math of the permanence half** → [`docs/STORAGE.md`](./STORAGE.md)
- **For the consensus engine (PoS + slashing)** → [`docs/CONSENSUS.md`](./CONSENSUS.md)
- **For tokenomics + the endowment formula** → [`docs/ECONOMICS.md`](./ECONOMICS.md)
- **For the whole-system architecture** → [`docs/ARCHITECTURE.md`](./ARCHITECTURE.md)
- **For the planned rollout** → [`docs/ROADMAP.md`](./ROADMAP.md)
