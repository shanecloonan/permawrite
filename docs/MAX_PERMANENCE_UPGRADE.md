# Max permanence upgrade (B-315)

**Status:** design + non-consensus helpers. **Not** a Path A parameter flip. **Not** a change to `apply_block`, coinbase, or checkpoint bytes.
**Owner:** lane 6. Lane 4 wires the forks below. Lane 7 does not enable them on the live public devnet.
**Helpers:** [`solvency_stress`](../mfn-consensus/src/solvency_stress.rs), [`state_projection`](../mfn-consensus/src/state_projection.rs), [`replica_health`](../mfn-storage/src/replica_health.rs), [`recommended_credited_slots`](../mfn-storage/src/cold_proof.rs), [`fork_dropped_storage_commitments`](../mfn-consensus/src/archive_retention.rs).

This is the implementation plan for a later consensus upgrade that makes Permawrite keep data under stalled storage-cost deflation, zero fees, operator defection, and state growth. Every item below names the threat, the exact parameters (Path A stays put), the functions to call, the version gate, the order, the tests, and how it fails.

Path A today (public devnet + `DEFAULT_*`):

| Knob | Path A | Where |
| --- | --- | --- |
| `min_storage_operator_bond` | 0 | genesis endowment; B5 slash of 250 bps is live and bites nothing |
| `operator_audit_missed_cap` / `operator_slash_bps` | 48 / 250 | live, global any-stale |
| `deflation_funded_drip` | 0 | checkpoint v13 field, inert |
| `storage_proof_reward` | `MFN_BASE / 10` (0.1 MFN) | `DEFAULT_EMISSION_PARAMS` |
| `subsidy_to_treasury_bps` | 0 | F6 code shipped, value not enabled |
| `fee_to_treasury_bps` | 9000 | |
| `tail_emission` | `initial_reward >> 8` | PM13 forbids 0 |
| `real_yield_ppb` | 0 | deflation-priced endowment |
| replication audit | salted proofs on, one disk can still pose as N keys | B3 flags on, no seal |

Do not flip any of those on the live chain in the unit that implements a single row. The first fork is a **new genesis or a post-B-25 activation**, and it sets the solvency bundle atomically.

## Recommended parameter set

Pinned by `b315_defaults_are_not_the_robust_bundle` and `b315_smaller_tail_funds_fewer_files_than_robust_tail`. One reference file is 1 GiB at `min_replication` 3.

| Parameter | Robust value | Why this one |
| --- | --- | --- |
| `tail_emission` | keep `>> 8` (19_531_250 base units / block) | B-313 `>> 9` funds half as many files when fees are zero. Use `>> 9` only after fee volume is proven. PM13 still forbids 0. |
| `subsidy_to_treasury_bps` | **1000** | FEES 5.4. About 5_136_328_125_000 base units/year (~51_363 MFN) into the treasury with zero txs. |
| `storage_proof_reward` | `recommended_backstop_proof_reward` = **1763** | Window-sized C0. The 0.1 MFN prize is a bootstrap, not a backstop. |
| `deflation_funded_drip` | **1** | `accrue_proof_reward` pays C0 instead of 0. |
| cold credit | `recommended_credited_slots` summed across the year = `slots_per_year` | Hot-window credit on a cold cadence pays under C0. See failure modes. |
| `min_storage_operator_bond` | `recommended_min_storage_operator_bond` = **25_769_800** | One 2.5% slash equals C0(1 GiB x 3) = **644_245**. |
| backstop cap | `recommended_backstop_mint_cap_per_year` = 1% of annual tail | Wire only after the prize is 1763. Path A's 0.1 MFN prize already exceeds the per-slot cap. |
| `fee_to_treasury_bps` | stay **9000** in this fork | B-309 is the next lever, after this one has soaked. Do not move both. |

`C0` = 644_245 base units/year. `E0` = `required_endowment` = **32_856_500** base units (~51 x C0).

The public-devnet sample of this bundle is [`public_devnet_fa.json`](../mfn-node/testdata/public_devnet_fa.json). It does not change `public_devnet_v1.json` or `DEFAULT_*`. VPS cutover: `bash scripts/public-devnet-v1/vps-rollout-fa.sh --apply`.

Stress (`stress_solvency`, zero fees):

| Case | Result |
| --- | --- |
| Endowment only, deflation stalls (`realized_deflation_ppb = 0`) | Principal pays **51** years, then stops. |
| Endowment only, Kryder holds at `inflation_ppb` (20_000_000) | Physical cost falls. The 200-year horizon stays paid. The pricing assumption is the whole solvency story. |
| Robust bundle, 1 file, 100 years, stall, cap on | Covered, **backstop mint = 0**. Subsidy refills what the principal cannot. |
| Robust bundle, 100 years, stall, no mint | **15_248_750** reference files. File 15_248_751 needs mint or goes unmet. |
| Same with `>> 9` tail | **7_624_375** files. |
| Path A prize, cap enforced | 1 file is covered only by minting. **200** files exceed the 1% cap (`b315_path_a_prize_exceeds_the_cap_once_many_files_exist`). About 140 such files fill the whole annual cap (3_650_000_000 base units/file/year). |

That is why the robust set keeps the larger tail, turns on the 10% subsidy split, shrinks the prize, and turns on the drip together. Any intermediate state is worse: drip without shrinking the prize double-pays; shrinking the prize without full-year credit underpays cold files; the cap without the smaller prize rejects honest proofs.

## Fork order

Do not start F-B before F-A has non-zero bonds. Do not start F-C before F-B. Scale forks (F-E, F-F) never come before the teeth. Path A stays on the table above until a named genesis or a post-B-25 ceremony.

| Fork | What lands | Gate | Effort |
| --- | --- | --- | --- |
| **F-A** | Path B genesis (or v14 activation overlay): drip=1, prize=1763, subsidy bps=1000, min bond=25_769_800, existing operators must post bond before the grace or they stop earning | New `genesis_id`, or checkpoint **v14** overlay mirroring `SubsidyBpsSchedule`. Not Path A. After **B-25** if same-chain. | Moderate. Fields exist except the activation record. |
| **F-B** | `cold_proof_cadence` flag. `accrue_proof_reward` credits `recommended_credited_slots`. Per-commit overdue uses `cold_proof_overdue`. Bounty is `recommended_cold_reward_multiplier_bps` **or** the repair bounty, not both. | Checkpoint **v14** (flag byte, v13 decodes 0). Coinbase fork. After F-A so a miss slash is non-zero. | Moderate. |
| **F-C** | Unique seals (`replica_seal_root`), repair bounty, retrieval fraud kind, geo weight. | Checkpoint **v15** (per-commit seal set is not required if seals are recomputed from proofs). New fraud-proof version. After F-B. | High. |
| **F-D** | PM8 body prune for non-archival nodes. Default stays "keep bodies" until an archival role is live and the checkpoint web signs the body root. | Node policy, not a consensus delete. No version bump. | Moderate, ops. |
| **F-E** | UTXO curve-tree membership replaces ring decoy selection (P11). Depth-32 tree already exists and **overflows at 2_147_483_648 uploads** (2 outputs each). Raise depth or add an era before that. | `TX_VERSION` bump. Privacy fork. After F-A. Does not drop leaves. | High. |
| **F-F** | Recursive block validity (P18 / B-12) so stateless clients verify one witness. | Validity-proof version. Research. Unlocks F-D as a real verification path, not just an archive courtesy. | High. |
| **F-G** | PQ phases in [`PQ_MIGRATION.md`](./PQ_MIGRATION.md). Phase A (hybrid stealth) can proceed in parallel. It does not wait on F-A. Phase B before a forge-capable quantum computer. Phase C when a PQ ring exists. | Per-object version bytes already on the wire. | High / research. |

## 1. Permanence teeth

### Threat

An operator can take the endowment's economic benefit, keep one disk, and register several keys. B5 slashes a zero bond. Cold files are never the file that resets the global miss counter. `replication: 3` is priced and not audited as three failure domains.

### Parameters

- Bond floor **25_769_800**. Slash stays **250 bps**, cap **48** misses. Do not raise slash bps in the same fork.
- Cold interval: age 0 -> **7_200** slots; age >= `slots_per_year` -> **216_000** slots. Never 0. Bounty 10_000 bps + 1_000 per missed window, cap **20_000**.
- Repair bounty: 10_000 + 5_000 per missing replica, cap **25_000**. Do not stack with the cold bounty on the same proof.
- Target replicas = `min_replication` (3). Geo bar = **2** reported failure domains (`MIN_DIVERSE_FAILURE_DOMAINS`), not one region per replica.
- Concentrated geo pays **5_000** bps weight. Unknown geo pays full weight (diversity only where it is reported).

### Implementation

| Step | File | Function |
| --- | --- | --- |
| Bond check on register | `mfn-consensus/src/storage_operator_evolution.rs` | reject `bond_amount < recommended_min_storage_operator_bond` when the F-A flag is on. Grace: existing bond 0 entries may prove until `activation_height + operator_audit_missed_cap` blocks, then they are skipped for payout (not deleted). |
| Slash | `apply_block` B5 path already calls slash-to-treasury | no new formula. After the floor, 250 bps of 25_769_800 = 644_245 = C0. |
| Cold deadline | `mfn-consensus` audit evolution | replace the global any-stale bit with `cold_proof_overdue(last_proven_slot, now, age, params)` per `StorageEntry`. Age = `now - anchor_slot` (store anchor slot or use height as the lower bound). |
| Credit | `mfn-storage/src/endowment.rs` `accrue_proof_reward` | when `cold_proof_cadence == 1`, cap credited slots with `recommended_credited_slots(elapsed, age, params)` instead of `proof_reward_window_slots`. Sum across a year must equal `slots_per_year` (tested). |
| Seals | chunk encode, later | `replica_seal_root(operator_id, data_root, replica_index)` domain `MFBN-1/replica-seal-v1` (`mfn-crypto/src/domain.rs` `REPLICA_SEAL`). Not read by consensus yet. |
| Window score | proof pool / apply | `assess_replica_window`. `shortfall > 0` => payout weight 0 and `repair_bounty_multiplier_bps(shortfall)`. |
| Repair fan-out | `mfn-node/src/p2p_repair_sweep.rs` | already re-fans stale commits. Point the bounty at the same `last_proven_slot` gap. The sweep stays best-effort; the bounty is what makes a new operator show up. |

### Tests

- Bond: one slash of the floor equals `first_year_cost_base_units(1 GiB, 3)`.
- Path A genesis still loads with bond 0 (`b307` pin stays).
- `b315_credited_slots_*` and `b315_cold_cadence_plus_remainder_covers_the_year`.
- `b315_three_seals_meet_target_and_one_disk_does_not`.
- `b315_hot_window_credit_underpays_a_cold_file`.
- apply_block proptest, when wired: a single seal under three keys does not count as replication 3; a zero bond does not move the treasury.

### Failure modes

- Enabling the bond floor on Path A rejects the bondless genesis and the two live operators. That is a chain split. Do not.
- Cold deadline without the wider credit cap: operators prove on time and still earn about C0/15. They drop the file anyway.
- Stacking cold bounty and repair bounty: one proof can print 2.0x times 2.5x. Pick one escalator per proof.
- Geo required when nobody reports an ASN: every file looks concentrated and payouts halve. Unknown must pay full.
- Sybil seals that hash the plaintext without the operator id: one disk still passes. The seal input list is operator id, data root, and index.

## 2. Retrieval guarantees

### Threat

SPoRA proves a Merkle leaf was opened. It does not prove a third party can fetch the bytes. An operator can prove and refuse, or serve different bytes than the challenged chunk.

### Parameters

- Retrieval window = `proof_reward_window_slots` (**7_200**). Same window as the hot proof, so a prove-and-serve pair fits one challenge.
- Slash only on `RetrievalAudit::ProvableMismatch` or `SignedRefusal` (`retrieval_slash_eligible`).
- `Timeout` opens a repair bounty and does **not** slash (`retrieval_opens_repair_bounty`). An eclipse looks like silence.

### Implementation

| Step | File | Function |
| --- | --- | --- |
| Verdict | `mfn-storage/src/replica_health.rs` | `retrieval_slash_eligible`, `retrieval_opens_repair_bounty` |
| Fraud object | `mfn-consensus/src/fraud_proof.rs` | new kind, next to `SPORA_FRAUD_DEDUP_KIND`. Body: commit hash, chunk index, served bytes hash, operator signature. Verifier recomputes the chunk hash from the served preimage and checks it is not the Merkle leaf the proof opened. |
| Absence | do not put "no response" in a fraud proof | absence is not a proof. The bounty path is the incentive. A later DAS sampler (PM7 / PM11) can raise the bounty; it still must not slash on silence alone. |
| Serve path | `STORAGE_ACCESSIBILITY.md` get_chunk | response already wants the ChunkV2 Merkle path. Bind the response signature to `(challenge_slot, chunk_hash)`. |

### Tests

- Mismatch and signed refusal are slash-eligible. Timeout is not. Served is neither.
- When wired: a fraud proof with the wrong chunk hash is `ValidFraud`; a proof that replays the honest leaf is not; a timeout gossip message does not move a bond.

### Failure modes

- Slashing timeouts: an eclipse drains honest bonds. That is worse than a missed repair.
- Retrieval challenge that asks for a chunk the SPoRA proof did not open: the operator may not hold that index if erasure coding lands later (PM4). v1 challenges only the index just proved.
- Public retrieval leaks reads (F5 P13). The audit is operator-facing (the chain asks the prover). User reads stay a separate PIR track and are not this fork.

## 3. Funding solvency

### Threat

`r = 0` prices the endowment as if storage cost falls at `inflation_ppb` forever. If that stalls, `E0` is about 51 years of C0 and then nothing. Path A does not even drip that principal: it pays 0.1 MFN per hot-window proof (36.5 MFN/file/year) from fees or from uncapped mint. Zero fees plus that prize is a mint spiral. The tail currently all goes to producers (`subsidy_to_treasury_bps = 0`).

### Parameters

The robust row in the table at the top. Fee shift stays at 9000. Runway warn stays **7_200** slots (`treasury_runway_slots` / `RunwayAlert`). Backstop cap is 1% of annual tail, enforced only after the prize is 1763.

### Implementation

| Step | File | Function |
| --- | --- | --- |
| Model | `mfn-consensus/src/solvency_stress.rs` | `stress_solvency`, `endowment_covers_physical_years`, `max_files_covered_without_mint`, `robust_parameter_set` |
| Drip | `accrue_proof_reward` | already pays C0 when `deflation_funded_drip == 1`. F-A sets the flag. Do not change the formula. |
| Prize | genesis / activation | set `storage_proof_reward` from `recommended_backstop_proof_reward`. |
| Subsidy | `emission.rs` `subsidy_treasury_credit` | already implements the split. F-A sets bps to 1000. |
| Cap | `apply_block` mint path | if backstop mint this window would exceed `recommended_backstop_mint_cap_for_window`, refuse the extra proofs or pay from treasury only and log. Do not mint the excess. |
| Runway | RPC, later | `treasury_runway_slots` / `RunwayObservation::alert`. Do not invent a second ratio. Path A prize vs the live ~2.9e6 treasury is `Short`; say so. |
| Fee shift | not this fork | `recommended_fee_to_treasury_bps` after B-13c has soaked and B-25 (or a human waiver) says so. |

### Tests

- `b315_stall_endowment_lasts_51_years_kryder_lasts_the_horizon`
- `b315_robust_one_file_century_stall_needs_no_mint`
- `b315_smaller_tail_funds_fewer_files_than_robust_tail` (15_248_750 vs 7_624_375)
- `b315_path_a_prize_exceeds_the_cap_once_many_files_exist`
- `b315_kryder_lowers_physical_cost_and_stall_does_not`
- Existing `b306` / `b311` / `b313` pins: defaults unchanged.

### Failure modes

- Assuming Kryder in the ceremony text and not in the parameters. If deflation stalls, only the subsidy (or a top-up, PM18) keeps files funded past year 51.
- Turning the cap on while the prize is 0.1 MFN. One honest proof does not fit the per-slot cap. Proofs stop, or you special-case Path A and the cap is a lie.
- Shrinking the tail to `>> 9` in the same fork as the first subsidy split. You cut the zero-fee file count in half before you know fee volume. Keep `>> 8` for F-A.
- Paying both a full-year drip and a hot-window 0.1 MFN prize. That is the double-pay. F-A sets both numbers in one genesis.
- `FundingMode` in the helper mints when the cap is off. That matches Path A. Do not describe uncapped mint as solvency.

## 4. Governance and fork resistance

### Threat

A later client, or a captured committee, can ship a fork that deletes storage commitments, zeroes an endowment, or sets `tail_emission` to 0, and still present valid finality signatures. Permanence that a software update can revoke is not permanence.

### Parameters

No new knobs. The constitution already requires `tail_emission > 0`, uniform ring >= 16, and well-formed endowment params (`validate_constitution`). Storage maps and key images are `PermanenceKeep` / `PrivacyKeep` (`archive_retention`). `storage_may_prune`, `utxo_may_prune`, and `spent_key_image_may_prune` are const false.

### Implementation

| Step | File | Function |
| --- | --- | --- |
| Genesis | `mfn-runtime/src/genesis_spec.rs` | keep calling `validate_constitution`. F-A genesis must pass it (tail still > 0, ring still >= 16). |
| Commitment count | light client / checkpoint import | `fork_dropped_storage_commitments(parent_count, child_count)`. If true, refuse the child even when the committee signed it. Equal or larger counts are not this signal. |
| Checkpoint web | existing checkpoint log | publish the storage-commitment count and the storage Merkle root next to the header. A client that only has the previous checkpoint can see a drop without replaying. |
| Social layer | release sign-off | a `go` decision already refuses Path A toy keys and unfunded economies. Extend the human checklist (B-33) with "this fork does not shrink storage commitments and does not set tail to 0". Do not automate `go` for F-A. |
| Code review rule | constitution module comment | a PR that adds a `storage.remove` / endowment confiscation path is a constitution break even if tests are green. The M5 proptest that storage entries are insert-only stays mandatory for any `apply_block` edit. |

### Tests

- `b315_fork_that_shrinks_storage_commitments_is_refused` (10 -> 9 refuses; 10 -> 10 and 10 -> 11 do not).
- `b310_storage_and_endowment_are_permanence_keep` and the const-false prune pins.
- `zero_tail_emission_is_unconstitutional` (already).

### Failure modes

- Treating committee signatures as sufficient. They attest the fork the committee chose, including a bad one.
- Refusing every reorg that temporarily counts fewer commitments because a block was rolled back and re-included. Compare the finalized checkpoint counts, not the mempool.
- A client that "repairs" a drop by deleting local state to match the new smaller root. That is the attack succeeding. Refuse and keep the parent.

## 5. Long-horizon cryptography

### Threat

The chain outlives ed25519 and BLS12-381. Harvest-now-decrypt-later is already recording stealth ECDH. A later forgery breaks new spends, new finality, and new proofs. Amounts hidden by Pedersen stay hidden (information-theoretic). Binding does not.

### Parameters

No new numeric parameter. Hash is domain-separated SHA-512 truncated to 256 bits (`dhash`). Grover brings preimage to 2^128. That is not a migration. Do not swap the hash in place: every historical Merkle root would die.

### Implementation

Follow [`PQ_MIGRATION.md`](./PQ_MIGRATION.md). This upgrade does not reorder it.

| Phase | What | Gate |
| --- | --- | --- |
| A | Hybrid ML-KEM stealth, `s_shared = dhash(ECDH \|\| ML-KEM secret)`. Old outputs stay scannable. | New output version. Can ship beside F-A. Highest urgency because the transcripts are already archived. |
| B | Hybrid BLS + ML-DSA-65 finality. VRF output can stay EC (one slot). Validator records gain a PQ key. | Checkpoint version bump (v4 validator record in that doc; chain checkpoint is already v13, so this is the next validator-record version inside the checkpoint). |
| C | PQ ring + range proof. Unmigrated funds freeze, they are not confiscated. Storage commitments and endowments are not spent away. | `TX_VERSION` bump. Research. |
| Hash agility | New domain tags for new objects only (`REPLICA_SEAL` is one). Historical tags stay. | A new tag is not a rehash of old data. |
| Archival format | Checkpoint versions 1 through 13 already decode. `archive-export` / `archive-verify` replays `apply_block`. | Keep accepting old versions forever. A verifier that drops v13 cannot read Path A. |

### Tests

- Existing PQ doc is the plan; this unit does not add PQ crypto.
- `b315_seal_root_is_stable_and_operator_unique` pins the new domain: same inputs match; a different operator or index does not. Path A chunk hashes do not use this tag.
- A round-trip of a v13 checkpoint still decodes (existing). Do not bump the version in this unit.

### Failure modes

- Re-hashing old `data_root`s under a new function. Every stored file becomes unprovable.
- Migrating spends by confiscating unmigrated outputs. That breaks the constitution even if the cryptography is better.
- Doing signatures (phase B/C) before hybrid stealth (phase A). The privacy damage is retroactive; the forgery damage is not.

## 6. Scale without dropping permanence

### Threat

State grows with every upload. If a full node becomes exotic, the operator set shrinks and permanence becomes a handful of disks. The wrong fix is deleting commitments, spent outputs (they are decoys), or key images (they are the double-spend set).

### What is already in the tree

- `archive_retention`: only historical `chain.blocks` bodies below a finalized checkpoint are prune candidates. Path A does not prune.
- `mfn-crypto/src/utxo_tree.rs`: sparse Merkle, depth **32**, append-only, spent outputs stay. Root is in the checkpoint. Leaf cap **2^32**.
- Validity proofs: replay witness, digest stub, and a Winterfell batch-binding STARK. Not recursive block validity (B-12 / P18).
- Storage commitments are a `HashMap` keyed by commit hash, one `StorageEntry` each. No commitment accumulator yet.

### Projected bytes

Planning constants in `state_projection.rs` (not a measurement of a live store). Per upload: storage map **205** bytes, two raw UTXOs **264**, two key images **192**, block body ceiling **8_192**.

| Uploads | Raw node | PM8 (drop bodies only) | Curve-tree leaves (storage map still full) | UTXO tree |
| --- | --- | --- | --- | --- |
| 1_000_000 | 8_853_000_000 | 661_000_000 | 365_000_000 | fits |
| 100_000_000 | 100x | 66_100_000_000 | 100x the 365 MB | fits |
| 10_000_000_000 | 88_530_000_000_000 | 6_610_000_000_000 | 3_650_000_000_000 | **overflows** |

Stateless witness at 10B uploads is **2432** bytes (two sibling paths + 256 byte header allowance). That is the verifier target. The archival node still holds the leaves.

Node targets:

| Role | Holds | Target |
| --- | --- | --- |
| Stateless verifier | one witness + header | kilobytes, after F-F |
| Verifying full node | storage map + UTXO/key-image leaves, no old bodies | PM8 + curve leaves. At 1e6 uploads, hundreds of MB (Pi-class). At 10B, terabytes: not a Pi. |
| Archival node | bodies + chunk bytes | the 8 KiB/upload ceiling plus the replicas. Required before any non-archival node drops bodies. |

2_147_483_648 uploads at two outputs fills the depth-32 tree. A depth change is a network reset (the root algorithm is consensus). Schedule the era before that count, not after.

### Implementation

| Step | File | Rule |
| --- | --- | --- |
| PM8 | store / `historical_block_body_may_prune` | Non-archival nodes may drop bodies with `height < finalized checkpoint`. They may not drop `ChainState.storage`, `utxo`, `spent_key_images`, or `utxo_tree` leaves. |
| Curve tree | `utxo_tree` + P11 | Membership proof replaces the ring. Leaves stay. Do not prune spent outputs out of the tree. |
| Key images | separate accumulator, same shape as the UTXO tree | Compress the map. Do not forget a spent image. |
| Storage commitments | new sparse tree, leaf = `storage_commitment_hash` | Stateless provers carry a witness. Archival nodes and SPoRA auditors still hold the `StorageEntry` (last proven slot, pending yield). The accumulator does not replace the entry. |
| Recursive validity | `validity_stark_winterfell.rs` then B-12 | One proof per block whose public input is the previous state root and the new one, including the storage root. Until that exists, PM8 nodes cannot prove old bodies they deleted. |
| Depth | `UTXO_TREE_DEPTH` | Do not bump it quietly. A new era is a genesis or a hard fork with a documented leaf-index map. |

### Tests

- `b315_scale_points_shrink_only_by_compression` (1e6 PM8 = 661_000_000, curve = 365_000_000, 10B overflows the tree, witness < 4096).
- `b315_projection_constants_match_the_wire_comment`
- `b310_*` still says maps are not historical bodies.
- When wired: a prune pass on a fixture chain drops a body below the checkpoint and fails if it drops a storage key.

### Failure modes

- Pruning bodies before an archival role and a validity proof exist. The network can no longer audit old blocks. That is a permanence loss even if the commitment key remains.
- "Compressing" by dropping decoys. Ring privacy and any later curve-tree anonymity set both need the spent outputs.
- Letting the depth-32 tree fill and then refusing new outputs with no era plan. Uploads stop, or someone raises depth and splits the root.
- A stateless mode that trusts a peer's state root without the witness. That is an RPC, not a verifier.

## 7. Build sequence (summary)

1. **Now (this unit).** Helpers and this document. Path A unchanged.
2. **B-25** soak and human B-33. No fork before that if the fork is same-chain. A Path B genesis can be drafted earlier and not started.
3. **F-A** robust bundle + bond floor, one genesis. Subsidy 1000, prize 1763, drip 1, bond 25_769_800, tail stays `>> 8`.
4. **F-B** cold credit + per-commit deadline, after bonds are non-zero.
5. **F-C** seals, repair bounty, retrieval fraud. Timeout is not a slash.
6. **PQ phase A** whenever the wallet wire can take a hybrid output. Do not block it on F-A.
7. **F-D** optional body prune only after an archival node is actually running and checkpoint counts are published.
8. **F-E / F-F** curve-tree membership and recursive validity. Required before 2^31 uploads and before calling the chain stateless.
9. **B-309 fee shift** and **B-313 smaller tail** only after F-A has real fee volume. They are dilution and producer levers, not the zero-fee floor.

## Biggest gaps this design does not close

- No second client (PM14) and no machine-checked `apply_block` (PM15). A bug in the one Rust crate is still a chain-wide bug.
- Erasure coding (PM4 / PM46) is unspecified here beyond "seals are per replica index". k-of-n changes the retrieval challenge and the endowment price. Do it after F-C, not inside F-A.
- Endowment top-up (PM18) is the escape hatch if the 15 million reference-file zero-fee ceiling is too small and fees never arrive. It is not in F-A.
- Operator geo is only as good as the reported ASN. The protocol cannot see geography. Two reported regions is the bar, not a proof of two continents.
- The stress model holds the file population constant and uses one 1 GiB size. A flood of tiny files or a jump in `cost_per_byte_year_ppb` needs a re-run of `stress_solvency` before the ceremony, not a new formula.

## See also

- [`B306_ENDOWMENT_DRIP.md`](./B306_ENDOWMENT_DRIP.md), [`B306C_PROOF_REWARD_BACKSTOP.md`](./B306C_PROOF_REWARD_BACKSTOP.md), [`B307_OPERATOR_BOND.md`](./B307_OPERATOR_BOND.md)
- [`B309_FEE_SHIFT.md`](./B309_FEE_SHIFT.md), [`B310_STATE_RETENTION.md`](./B310_STATE_RETENTION.md), [`B311_BACKSTOP_CAP.md`](./B311_BACKSTOP_CAP.md)
- [`B312_TREASURY_RUNWAY.md`](./B312_TREASURY_RUNWAY.md), [`B313_TAIL_EMISSION.md`](./B313_TAIL_EMISSION.md), [`B314_COLD_PROOF.md`](./B314_COLD_PROOF.md)
- [`B5_OPERATOR_SLASHING.md`](./B5_OPERATOR_SLASHING.md), [`PERMANENCE_HARDENING.md`](./PERMANENCE_HARDENING.md), [`F5.md`](./F5.md), [`PROBLEMS.md`](./PROBLEMS.md)
- [`PQ_MIGRATION.md`](./PQ_MIGRATION.md), [`ECONOMICS.md`](./ECONOMICS.md), [`FEES.md`](./FEES.md), [`STORAGE.md`](./STORAGE.md)
