# Privacy and permanence as one system

Public discourse, personal records, journalism, science, and creative work all depend on two properties at once: **what you say must be able to survive**, and **how you pay and coordinate must not expose you to retaliation, profiling, or extraction**. When either property fails, freedom of thought and action erodes—not always dramatically, but steadily.

**Permawrite** is a protocol design that treats those requirements as a single engineering problem rather than two unrelated products. This repository holds its Rust implementation.

---

## Two pillars of freedom in the digital era

If you had to name the two rights that matter most once society moves online, they would be these:

**1. The right to durable expression** — to publish, record, and preserve information so that truth, evidence, and culture cannot be silently erased by platform policy, corporate bankruptcy, political pressure, or the slow rot of unmaintained servers. Permanence is not nostalgia for paper archives; it is the ability to prove *what was said, when, and in what form*, against institutions that would prefer the record to be editable after the fact.

**2. The right to private economic agency** — to pay, save, and coordinate without broadcasting an immutable graph of identity, balance, and association to every observer on the network. Financial privacy is not a niche concern for criminals; it is the difference between a whistleblower who can fund an upload without career-ending exposure and one whose bank trail becomes the story.

Neither pillar substitutes for the other. A permanent archive of traceable payments is a liability for dissidents and ordinary people alike: the document survives, but the author is trivially deanonymized through the funding trail. A private payment rail that cannot anchor durable commitments leaves ideas and evidence at the mercy of whoever controls today's hosting stack: you can move money in secret, but your words vanish when the pin expires.

These are not abstract civil-liberties talking points. They are **protocol requirements**. Anything less is a product feature, not infrastructure for an open society.

---

## Why one-time payment, funded by anonymous cash, preserves both

Most systems force a trade: pay monthly and hope the provider survives; or pay once on a transparent ledger and accept that your name is attached to every byte you archive forever. Permawrite rejects both failure modes with a specific economic shape:

### One payment, forever

Recurring subscriptions encode **dependency**. The moment you stop paying — or the moment a company decides you should — the data is gone. Permanent storage cannot be rented; it must be **capitalized**. Permawrite's endowment model asks for a single upfront payment sized to cover the network's expected storage liability across decades ([`ECONOMICS.md § 1`](./ECONOMICS.md#1-the-permanence-equation-derived)). There is no renewal invoice, no account to suspend, no "your plan expired" email.

The default calibration prepays roughly **51× the first-year storage cost** under a conservative 2%/year deflation floor — a multiple designed so that even if Kryder's law slows dramatically, commitments remain solvent while privacy-transaction fees continuously refill the treasury. Full per-gigabyte tables live in [**STORAGE_COST_MODEL.md**](./STORAGE_COST_MODEL.md).

### Anonymous cash as the funding source

An endowment paid from a traceable wallet is permanence **with a built-in confession**. Permawrite funds uploads through the same **RingCT / CLSAG** privacy layer that handles ordinary transfers: ring signatures hide *which* UTXO paid, stealth addresses hide *who* received change, Pedersen commitments hide *how much* was committed (including the endowment field on `StorageCommitment`). The chain enforces the protocol minimum; observers cannot tell whether you paid exactly that or ten times more.

This matters because **the two critical rights fail together when payment is public**. A journalist archiving source material does not want a permanent on-chain receipt linking their identity to a controversial hash. A clinic storing patient records does not want an immutable audit trail of who paid for which file. Anonymous cash is not laundering — it is the only way permanence and personal safety coexist in one transaction.

### Privacy demand pays for permanence infrastructure

The endowment alone does not mint money forever. Ongoing operator compensation flows from the **storage treasury**, filled primarily by **90% of every privacy-transaction fee**. People who use MFN as confidential cash — every day, for ordinary reasons — continuously fund the operators who answer SPoRA audits. The more the network is used as private money, the more headroom exists for the bytes already committed.

That loop is the design's central insight: **financial privacy is not a side feature subsidized by storage hype; it is the cashflow engine that makes permanence economically viable without infinite inflation.**

---

## SPoRA and how Permawrite compares to other permanence attempts

Paying once is necessary but not sufficient. Someone must still **prove they hold the bytes** years later, without trusting self-attestation or a single company's word.

### What SPoRA does

**SPoRA — Succinct Proofs of Random Access** — is Permawrite's audit primitive ([`STORAGE.md § 3`](./STORAGE.md#3-spora-deterministic-challenges)). Every block, consensus deterministically selects:

1. An active storage commitment (via the block's storage registry),
2. A specific 256 KiB chunk of that file (derived from `prev_block_id`, slot, and commitment hash),
3. And demands a **Merkle proof** that the chunk belongs to the on-chain `data_root`.

The proof is large enough to be meaningful (~256 KiB of actual data + logarithmic hashes) but cheap to verify (microseconds of SHA-256 on every node). Producing it requires the operator to **actually possess** the chunk — you cannot forge the Merkle path without breaking the hash function. The challenge is unpredictable far in advance (it depends on the not-yet-known next block id) but instantly computable once a block lands, so honest operators can prepare without an oracle.

Unlike mining-based recall, SPoRA does **not** require specialized hardware, packed replicas, or GPU provers. A laptop or NAS can be a storage operator ([`STORAGE_ACCESSIBILITY.md`](./STORAGE_ACCESSIBILITY.md)). That accessibility is not UX polish — it is what makes geographic and organizational decentralization of replicas plausible at scale.

### How existing approaches fall short

| Approach | What it optimizes | Where it breaks for the two rights |
|---|---|---|
| **Centralized cloud** | Convenience, SLA | Recurring payment + identity trail; data dies with account or company |
| **IPFS / pinning services** | Distribution | No on-chain permanence guarantee; pins are voluntary and expirable |
| **Filecoin / Sia** | Market-priced storage deals | Transparent payments; **contracts expire** — permanence requires perpetual re-deal renewal |
| **Arweave** | One-time endowment permanence | Strong permanence economics, but **transparent funding**; mining-style recall favors datacenter hardware |
| **Bitcoin inscriptions** | Censorship-resistant anchoring | No dedicated storage incentive layer; replication is social, not economically enforced |
| **Permawrite** | Privacy + permanence in one chain | One-time endowment + **anonymous** payment + **SPoRA** block audits + treasury-funded operator rewards |

Arweave proved that **deflation-funded endowments** (pay once, rely on falling storage costs) can work. Permawrite inherits that math but changes two things that matter for human rights use cases: **who can afford to store** (consumer-grade SPoRA instead of mining hardware) and **who can afford to be seen paying** (ring-confidential uploads instead of transparent wallets).

Filecoin and Sia demonstrate that market mechanisms can allocate disk — but their deal-based models encode **term limits**. True permanence is not a series of renewals; it is a capital structure that outlives any single contract counterparty. Permawrite's on-chain registry has no `unannounce_file()`; commitments are irreversible by design ([`STORAGE.md`](./STORAGE.md)).

---

## Why a fused network matters

Keeping permanence and privacy in **separate** systems forces brittle bridges: identities and payment trails leak at the seams; incentives diverge (who pays for storage if the privacy layer does not internalize the cost?); and governance splits across communities that rarely align on upgrades, security budgets, or threat models.

A **unified** layer-1 aligns incentives and threat models in one place: the same consensus rules that finalize blocks enforce both confidential transfers and storage commitments; the same economic policy routes value from usage into the mechanisms that pay operators to hold data over the long term. One coin, one treasury, one security budget — not a privacy coin that "also supports" IPFS hashes, and not a storage chain where every uploader's wallet is public.

Optional [**authorship claims**](./AUTHORSHIP.md) preserve the default: uploads are anonymous at the financial layer, but a publisher can *voluntarily* attach a Schnorr-signed attestation to a `data_root` for permaweb discovery — using a **separate publishing key**, not the stealth spend material. Identity becomes opt-in signal, not mandatory surveillance.

---

## Complementary economics (summary)

In Permawrite's economic design:

- **Uploaders** pay a one-time endowment (amount-private) that capitalizes storage liability.
- **Privacy users** pay transaction fees continuously; 90% flows to the storage treasury.
- **Operators** earn by winning SPoRA challenges and holding replicas; rewards drain the treasury (with emission backstop only if fees lag).
- **Validators** bond stake into the same treasury, converting security commitments into permanence funding.

That structure is deliberately complementary: the more the network is used as a **private** medium of exchange and coordination, the more ongoing funding exists for **permanent** retention — without treating privacy as a loss-leader or permanence as a charity subsidized by unrelated tokenomics.

For precise pricing, see [**STORAGE_COST_MODEL.md**](./STORAGE_COST_MODEL.md). For protocol mechanics, start with [ARCHITECTURE.md](./ARCHITECTURE.md) and [OVERVIEW.md](./OVERVIEW.md).

---

## Conclusion

Freedom in the digital age is not a single feature toggle. It is the conjunction of **durable expression** and **private economic agency** — the ability to leave a verifiable record that outlives any platform, and to pay for that record without surrendering your life to a permanent, searchable ledger.

One-time payment removes the subscription trap. Anonymous cash removes the funding confession. SPoRA removes the trust-me bro guarantee. Together, on one chain, they are infrastructure for the two rights that matter most when civilization's memory and its money both live on servers controlled by someone else.

Building both into one coherent network is a step toward systems where people can speak with a verifiable record and transact without surrendering their lives to a permanent, searchable ledger — two requirements that belong together if open societies are to remain viable online.
