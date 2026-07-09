# Permanence Hardening — shipped changes and the remaining work

This document is the **implementation-level** companion to
[`STORAGE.md`](./STORAGE.md) (how the storage/permanence mechanisms work) and
[`F5.md`](./F5.md) (the high-level menu of future privacy/permanence
frontiers). Where `STORAGE.md` explains the mechanism and `F5.md` says *what*
to build and *why*, this file records **what has actually shipped** for
permanence hardening and gives the **specific, file-and-function level** plan
for the changes that have not — so the next contributor can pick an item up
without re-deriving the design. It is the permanence twin of
[`PRIVACY_HARDENING.md`](./PRIVACY_HARDENING.md).

Doctrine reminder (from [`AGENTS.md`](../AGENTS.md)): privacy and permanence
over everything. Every item here either strengthens or leaves untouched ring
policy, endowment enforcement, and SPoRA verification. Anything that changes
consensus requires a version gate and the full M5-style test treatment before
it touches `main`.

Baseline being improved on: on-chain `StorageCommitment` anchors, deterministic
per-block SPoRA challenges (`H(prev_id ‖ slot ‖ commit_hash) mod num_chunks`),
Merkle-proof storage audits, endowment pricing via `required_endowment`,
treasury-funded proof rewards, and best-effort chunk replication over P2P
gossip (`ChunkV1` frames → `chunk-inbox/` → fan-out). Known weaknesses are
catalogued in [`PROBLEMS.md`](./PROBLEMS.md) and
[`SECURITY_CONSIDERATIONS.md`](./SECURITY_CONSIDERATIONS.md).

---

## Part A — Shipped (M5.49 + M7.12, commit `890a56c`; M2.5.61, commit `1603e43`; B-11 phase 1; **B2 ChunkV2**, this commit)

The through-line of this batch: **every hop of a payload's life — anchoring,
gossip, disk, re-broadcast — must be checkable against the on-chain
commitment, and anything uncheckable must be refused.** Before these changes,
the chain verified SPoRA *proofs* rigorously but trusted the *shape* of new
commitments and trusted *peers* for replicated bytes.

### A1. Commitment-shape consensus gate (M5.49)

**Status:** shipped (`mfn-storage`, `mfn-consensus`, `mfn-runtime`).

#### The attack this closes

`StorageCommitment` declares its own geometry: `size_bytes`, `chunk_size`,
`num_chunks`. Nothing previously checked that these fields were mutually
consistent, and both the SPoRA audit and the endowment pricing *trust* them
in different places:

- The per-block challenge is derived `mod num_chunks`
  ([`chunk_index_for_challenge`](../mfn-storage/src/spora.rs)).
- The endowment price is derived from `size_bytes × replication`
  ([`required_endowment`](../mfn-storage/src/endowment.rs)).

So a commitment declaring `num_chunks: 1` for a **1 GiB** payload was
perfectly anchorable: the uploader pays the full-size endowment (or is
"paid" by whoever they defraud downstream), but the network only ever
challenges chunk index `0` — an operator can keep 256 KiB, discard the other
~4095 chunks, and pass every audit forever. The permanence guarantee is
silently void while every proof "verifies". Variants: `chunk_size: 0` or a
non-power-of-two (breaks prover/verifier re-chunking symmetry), and
`num_chunks: 0` (degenerates the challenge derivation to index 0).

#### What changed

New structural validator in
[`mfn-storage/src/commitment.rs`](../mfn-storage/src/commitment.rs), exported
from the crate root:

```91:103:mfn-storage/src/commitment.rs
pub fn expected_num_chunks(size_bytes: u64, chunk_size: u32) -> Result<u32, CommitmentShapeError> {
    if chunk_size == 0 || !chunk_size.is_power_of_two() {
        return Err(CommitmentShapeError::InvalidChunkSize(chunk_size));
    }
    if size_bytes == 0 {
        return Ok(1);
    }
    let n = size_bytes.div_ceil(u64::from(chunk_size));
    u32::try_from(n).map_err(|_| CommitmentShapeError::TooManyChunks {
        size_bytes,
        chunk_size,
    })
}
```

```125:138:mfn-storage/src/commitment.rs
pub fn validate_storage_commitment_shape(
    c: &StorageCommitment,
) -> Result<(), CommitmentShapeError> {
    let expected = expected_num_chunks(c.size_bytes, c.chunk_size)?;
    if c.num_chunks != expected {
        return Err(CommitmentShapeError::NumChunksMismatch {
            got: c.num_chunks,
            expected,
            size_bytes: c.size_bytes,
            chunk_size: c.chunk_size,
        });
    }
    Ok(())
}
```

The rules, exactly:

1. `chunk_size` must be a **positive power of two** — mirrors what
   [`build_storage_commitment`](../mfn-storage/src/spora.rs) can produce and
   what provers/verifiers re-chunk with.
2. `num_chunks == ceil(size_bytes / chunk_size)`, with the canonical
   **empty payload = 1 chunk** case (the Merkle tree always has a leaf).
   This also forces `num_chunks ≥ 1`, killing the zero-chunk degenerate.
3. A `size_bytes`/`chunk_size` pair implying more than `u32::MAX` chunks is
   rejected as `TooManyChunks` (such a commitment could never have been
   honestly built).

The structured error type `CommitmentShapeError`
(`InvalidChunkSize` / `NumChunksMismatch` / `TooManyChunks`, lines 51–83 of
`commitment.rs`) is carried verbatim inside both rejection surfaces below, so
operators see *why* in logs.

#### Enforcement point 1 — consensus (`apply_block`)

In the storage-anchoring walk of
[`mfn-consensus/src/block/apply.rs`](../mfn-consensus/src/block/apply.rs),
**before** replication bounds and endowment pricing, and only for NEW anchors
(duplicates of an already-anchored commitment stay inert):

```422:434:mfn-consensus/src/block/apply.rs
            // Geometry must be internally consistent before the anchor is
            // even priced: SPoRA challenges are derived mod `num_chunks`
            // and provers re-chunk with `chunk_size`, so a lying shape
            // voids the audit that permanence rests on (M5.49).
            if let Err(reason) = validate_storage_commitment_shape(sc) {
                errors.push(BlockError::StorageCommitmentMalformed {
                    tx: ti,
                    output: oi,
                    reason,
                });
                tx_storage_ok = false;
                break;
            }
```

A block containing such a tx is rejected with the new
[`BlockError::StorageCommitmentMalformed { tx, output, reason }`](../mfn-consensus/src/block/error.rs)
(lines 165–178) and — like every other reject path — leaves state
untouched.

#### Enforcement point 2 — mempool (byte-for-byte mirror)

The mempool's storage-anchoring gate in
[`mfn-runtime/src/mempool.rs`](../mfn-runtime/src/mempool.rs) runs the *same*
validator at the *same* position in the check order (after the
already-anchored/duplicate skip, before replication and burden pricing), so a
malformed anchor never enters the pool and never wastes a producer slot:

```523:532:mfn-runtime/src/mempool.rs
            // Shape gate mirrors `apply_block` byte-for-byte (M5.49): a
            // commitment whose declared geometry lies about the payload
            // breaks the SPoRA audit, so it never enters the pool.
            if let Err(reason) = mfn_storage::validate_storage_commitment_shape(sc) {
                return Err(AdmitError::StorageCommitmentMalformed {
                    tx_id_hex: hex_prefix(&tx_id),
                    output: oi,
                    reason,
                });
            }
```

Keeping consensus and mempool admission in lockstep matters: a check that
exists only in the mempool is advisory (a hostile producer bypasses it), and
a check that exists only in consensus lets garbage sit in every node's pool
until block inclusion fails. This pairing is the same discipline the
endowment (`UploadUnderfunded`) and replication-bounds checks already follow.

#### Why genesis and already-anchored commitments are exempt

The gate applies to **NEW** anchors only. Pre-existing anchored entries
(including any genesis-spec storage) are grandfathered — re-validating them
would make historical state re-application fragile, and downstream consumers
(`expected_chunk_len`, below) are written to be total functions that clamp
safely on any geometry.

#### Test coverage

- `mfn-storage/src/commitment.rs` unit tests: power-of-two acceptance/rejection
  sweep, `ceil` boundary cases (exact multiple vs +1 byte), empty payload = 1
  chunk, `u32` overflow → `TooManyChunks`, and validator round-trips on real
  `build_storage_commitment` outputs.
- [`mfn-consensus/tests/block_apply.rs`](../mfn-consensus/tests/block_apply.rs):
  - `apply_block_rejects_storage_commitment_with_lying_num_chunks` — a signed,
    sealed block anchoring a 16 KiB payload that declares `num_chunks: 1`
    (honest: 64) is rejected with `StorageCommitmentMalformed`, state
    unchanged.
  - `apply_block_rejects_storage_commitment_with_bad_chunk_size` — non-power-
    of-two `chunk_size` rejected end-to-end.
  - `apply_block_accepts_storage_commitment_with_consistent_shape` — control:
    the same flow with honest geometry anchors fine.
- `mfn-runtime/src/mempool.rs`:
  `admit_storage_tx_rejects_lying_num_chunks`,
  `admit_storage_tx_rejects_non_power_of_two_chunk_size`,
  `admit_storage_tx_rejects_zero_num_chunks`.

### A2. Chunk-inbox gossip authentication (M7.12)

**Status:** shipped (`mfn-node`).

#### The attack surface this closes

Replication rides on P2P gossip: peers push
[`ChunkV1`](../mfn-net/src/chunk_v1.rs) frames
(`tag ‖ commit_hash ‖ chunk_index ‖ raw bytes`), and the receiving node
persists them under `chunk-inbox/<commit_hex>/<index>` for later assembly and
fan-out. Before M7.12, `on_chunk_v1` wrote **whatever any peer sent** to disk:

- chunks for commitments that don't exist on-chain (unbounded spam →
  disk-fill DoS keyed by attacker-chosen 32-byte names);
- out-of-range indices and wrong-length bodies for real commitments;
- **overwrites** of chunks the operator already held — a malicious peer could
  corrupt a stored replica *after* the fact, so a node that had the data and
  would have passed its SPoRA audit suddenly wouldn't.

#### What changed

`on_chunk_v1` in
[`mfn-node/src/p2p_gossip.rs`](../mfn-node/src/p2p_gossip.rs) now runs a
gauntlet before any disk write (lines 74–123):

1. **Anchored-commitment lookup.** The chain state's storage registry is
   consulted under the chain mutex; an unknown `commit_hash` is
   `rejected:unknown_commit` — nothing attacker-named ever touches disk.
2. **Geometry validation** via the new
   [`validate_gossip_chunk`](../mfn-node/src/p2p_chunk_inbox.rs) (line 52):
   - `chunk_index < num_chunks` (`ChunkGossipReject::IndexOutOfRange`);
   - byte length must equal
     [`expected_chunk_len`](../mfn-node/src/p2p_chunk_inbox.rs) (line 41) —
     full `chunk_size` for interior chunks, the exact remainder for the tail
     chunk, computed with saturating arithmetic that clamps against
     `size_bytes` so it stays total even for grandfathered pre-M5.49
     geometries (`ChunkGossipReject::LengthMismatch`);
   - **single-chunk commitments are fully verified outright**: a one-leaf
     Merkle tree's root *is* the leaf hash, so
     `chunk_hash(bytes) == data_root` is checked byte-for-byte
     (`ChunkGossipReject::DataRootMismatch`). Multi-chunk frames carry no
     Merkle path today, so their content check happens at assembly time
     (A3) — closing that gap at gossip time is [§B2](#b2-merkle-path-carrying-chunk-gossip-full-per-chunk-verification).
3. **First-write-wins.** If a file already exists at the inbox path with the
   expected length, the frame is `skipped:already_present` — held bytes are
   never overwritten by gossip. A wrong-length leftover (crash debris) may
   still be repaired by a valid frame.

Every reject path returns a structured label
(`rejected:unknown_commit:…`, `rejected:chunk_invalid:…:IndexOutOfRange{…}`)
that lands in the node's gossip log for operator forensics.

#### Why "reject unknown commitments" is the right trade-off

A chunk can legitimately arrive before its anchoring block on a lagging
replica. Rejecting it costs one retransmission (the fan-out path re-offers
chunks when uploads land; a node that syncs the block later will receive the
chunks again from any peer with a complete inbox). Accepting it costs an
unbounded, unauthenticated disk-write primitive. Permanence favors the
network never storing bytes it cannot tie to an anchor.

#### Test coverage

- `mfn-node/src/p2p_chunk_inbox.rs` unit tests: `expected_chunk_len` over
  full/tail/out-of-range indices; acceptance of every true chunk of a real
  commitment; rejection of out-of-range index, wrong length, and forged
  single-chunk bytes.
- `mfn-node/src/p2p_gossip.rs` integration tests (against a real chain +
  store):
  - `on_chunk_v1_rejects_unknown_commit_without_disk_write` — unknown commit
    leaves no `chunk-inbox/` entry at all;
  - `on_chunk_v1_validates_anchored_chunks_and_protects_existing_bytes` —
    valid chunk stored; bad index/length rejected; a second, different
    same-length body for an already-held chunk is skipped and the original
    bytes survive;
  - `on_chunk_v1_fully_verifies_single_chunk_commitments` — forged bytes of
    the right length are rejected for single-chunk commitments.

### A3. Fan-out `data_root` verification (M7.12)

**Status:** shipped (`mfn-node`).

#### The propagation hazard this closes

When a new upload lands on-chain, nodes with a **complete** inbox for that
commitment fan the chunks out to peers
([`mfn-node/src/p2p_chunk_fanout.rs`](../mfn-node/src/p2p_chunk_fanout.rs)).
Completeness was previously *count*-based (`chunk_inbox_complete`): all
`num_chunks` files present. Pre-M7.12 inboxes (or local disk corruption)
could therefore contain a complete-but-wrong set of bytes, and the node would
replicate the corruption **as if it were the anchored payload** — corrupted
data spreading through the mesh wearing a valid commitment's name is the
exact inversion of permanence.

#### What changed

`load_complete_inbox_chunks` now rebuilds the Merkle tree over the loaded
chunks and requires the recomputed root to equal the anchored `data_root`
before the set becomes eligible for fan-out:

```46:61:mfn-node/src/p2p_chunk_fanout.rs
    // (M7.12) Verify against the anchored data_root before fanning out:
    // a node must never replicate bytes it cannot prove are the payload,
    // or corrupted inboxes would spread through the mesh as if permanent.
    let refs: Vec<&[u8]> = chunks.iter().map(|(_, b)| b.as_slice()).collect();
    let tree = match mfn_storage::merkle_tree_from_chunks(&refs) {
        Ok(t) => t,
        Err(e) => {
            eprintln!("mfnd_p2p_chunk_fanout_skip commit={commit_hex} merkle_err={e}");
            return None;
        }
    };
    if tree.root() != commit.data_root {
        eprintln!("mfnd_p2p_chunk_fanout_skip commit={commit_hex} data_root_mismatch=1");
        return None;
    }
    Some(chunks)
```

Combined with A2, the invariant across a payload's whole replication life is:
**bytes enter the inbox only if they are consistent with the anchor, and
leave the node only if they are *provably* the anchored payload.**

#### Test coverage

- `load_complete_inbox_chunks_refuses_corrupted_inbox` — a complete inbox
  whose first byte was flipped (valid count, valid lengths) is refused for
  fan-out.
- `load_complete_inbox_chunks_round_trip` (pre-existing) — honest inboxes
  still load, now additionally proving the verification passes on real data.

### A4. Documentation honesty fix (`STORAGE.md`)

[`STORAGE.md § Endowment is a Pedersen commitment`](./STORAGE.md#endowment-is-a-pedersen-commitment)
previously implied the chain "verifies the endowment math" against the
commitment point. It now states precisely what consensus enforces — the
**funding route** (`fee × fee_to_treasury_bps / 10_000 ≥
required_endowment(size_bytes, replication)`, else `UploadUnderfunded`) —
and, when `require_endowment_opening = 1`, the **MFEO opening binding**
(§A6). Range-proof over-payment privacy remains in [§B1](#b1-range-proof-endowment-binding-b-11-phase-2--consensus).
A permanence chain must not document guarantees it does not enforce.
A new `STORAGE.md § Structural (shape) validation — M5.49` section documents
A1 for mechanism readers.

### A5. CI trustworthiness: order-independent smoke-harness reads (M2.5.61, commit `1603e43`)

Not a protocol change, but it is why the rest of this page is *verified*
rather than merely written: M2.5.50 reordered `mfnd serve`'s startup
announcements (`mfnd_p2p_listening=` now precedes `mfnd_serve_listening=`
so devnet orchestration can poll the P2P listener early). The `mfnd_smoke`
harness read those prefixes **sequentially in the old order**, silently
discarded the P2P line, and then blocked forever on a stdout that would
never speak again (`read_line` has no mid-read deadline) — hanging
`mfnd_p2p_reconnects_saved_peers_on_restart` and
`mfnd_rpc_get_light_follow_p2p_fetches_from_peer_listener` on every platform,
deterministically. Every CI run between M2.5.50 and M2.5.61 had its test
matrix cancelled by rapid pushes before reaching the hang, so local `ci-check`
was the first full run to hit it (twice, ~55 minutes each).

The fix adds
[`read_stdout_lines_with_prefixes_any_order`](../mfn-node/tests/stdout_timeout.rs)
(line 47) — collects a set of startup prefixes in any order, panicking with
the *missing* set on timeout/EOF — and converts all six `--p2p-listen` spawn
sites in [`mfn-node/tests/mfnd_smoke.rs`](../mfn-node/tests/mfnd_smoke.rs)
to it. CI run `28774283620` on `1603e43` was the first fully green test
matrix (Ubuntu, Windows, macOS) since M2.5.50, and is the run that verifies
A1–A3 cross-platform.

Harness lesson recorded for future startup-log changes: tests must treat
startup announcements as a *set*, not a *sequence*, because announcement
order is an operational tuning knob (M2.5.50 changed it deliberately).

### A6. Pedersen endowment opening binding (B-11 phase 1, commits `3511346` / `9f0a0aa` / `0fee187`)

**Status:** shipped (`mfn-consensus`, `mfn-storage`, `mfn-wallet`, public devnet genesis).

#### The attack this closes

Before B-11, `StorageCommitment.endowment` was a Pedersen point that
consensus never opened. Uploads were funded only via the treasury fee-share
gate (`UploadUnderfunded`). The on-chain bond artifact was unverified — an
uploader could commit to `0` (or any point) with no consensus consequence
as long as fees covered `required_endowment`. Any future logic trusting the
committed point (per-endowment yield, top-ups, B6 bucket pricing) inherited
that hole.

#### What changed

**Opening reveal (design option 1 from the original B-11 plan)** is now
consensus-enforced when `endowment_params.require_endowment_opening != 0`:

1. **`MFEO` wire frames** in `tx.extra` (MFEX v2) carry `value: u64` +
   `blinding: [u8; 32]` per new storage output
   ([`extra_codec.rs`](../mfn-consensus/src/extra_codec.rs)).
2. **`apply_block`** parses openings, verifies
   `verify_endowment_opening(sc, value, blinding)` and
   `value ≥ required_endowment(size, replication)`
   ([`block/apply.rs`](../mfn-consensus/src/block/apply.rs) B-11 block).
3. **Mempool** mirrors the gate so invalid openings never enter blocks.
4. **Public devnet v1** sets `require_endowment_opening: 1` in
   [`public_devnet_v1.json`](../mfn-node/testdata/public_devnet_v1.json)
   (same `genesis_id`; operators must sync byte-identical JSON).
5. **Wallet** `mfn-cli wallet upload` attaches `MFEO` automatically when the
   network requires it.

Verifier helper:

```166:177:mfn-storage/src/spora.rs
pub fn verify_endowment_opening(
    c: &StorageCommitment,
    amount: u64,
    blinding: &curve25519_dalek::scalar::Scalar,
) -> bool {
    let recomputed = mfn_crypto::pedersen::PedersenCommitment {
        c: c.endowment,
        value: curve25519_dalek::scalar::Scalar::from(amount),
        blinding: *blinding,
    };
    mfn_crypto::pedersen::pedersen_verify(&recomputed)
}
```

**Trade-off (accepted for phase 1):** the opened endowment amount is visible
on-chain when the gate is on. `required_endowment` is already public math over
public `size_bytes`/`replication`; only *over*-payment privacy is lost. B6 size
buckets and [§B1 range-proof binding](#b1-range-proof-endowment-binding-b-11-phase-2--consensus)
are the upgrade path if amount privacy matters.

#### Test coverage

- `prop_mfeo_opening_storage_upload_treasury` — valid opening + treasury path.
- Reject without `MFEO` when `require_endowment_opening = 1`.
- `public_devnet_manifest` — genesis spec asserts `require_endowment_opening: 1`.

### A7. Merkle-path-carrying chunk gossip (B2, this commit)

**Status:** shipped (`mfn-net`, `mfn-node`, `mfn-storage`, `mfn-storage-operator`).

#### The attack this closes

[`ChunkV1`](../mfn-net/src/chunk_v1.rs) gossip could only length-gate multi-chunk
commitments at inbox time (§A2). Wrong-content-right-length bytes for an anchored
multi-chunk commitment were accepted into `chunk-inbox/` and only caught at
fan-out Merkle re-derivation (§A3) — wasting disk and mesh bandwidth, and
first-write-wins could block honest bytes until repair.

#### What changed

1. **`ChunkV2` wire** — tag `0x12` (distinct from `ChunkV1` `0x10` and
   `TxStemV1` `0x11`): `commit_hash ‖ chunk_index ‖ merkle_proof_wire ‖ chunk_bytes`
   ([`chunk_v2.rs`](../mfn-net/src/chunk_v2.rs)).
2. **Canonical proof wire** — [`encode_merkle_proof_wire`](../mfn-storage/src/spora.rs)
   / `decode_merkle_proof_wire` shared with SPoRA proof encoding.
3. **Gossip gate** — `validate_gossip_chunk_v2` verifies Merkle inclusion against
   `data_root` before any disk write ([`p2p_chunk_inbox.rs`](../mfn-node/src/p2p_chunk_inbox.rs)).
4. **Fan-out / catch-up** — complete verified inboxes fan out via `send_chunk_v2`
   with per-chunk proofs ([`p2p_chunk_fanout.rs`](../mfn-node/src/p2p_chunk_fanout.rs),
   [`p2p_fanout.rs`](../mfn-node/src/p2p_fanout.rs)).
5. **Operator push** — `mfn-storage-operator` chunk push uses `ChunkV2` only
   ([`chunk_push.rs`](../mfn-storage-operator/src/chunk_push.rs)).
6. **Compatibility** — inbound `ChunkV1` still accepted; outbound replication
   prefers `ChunkV2` when proofs are available.

#### Test coverage

- `chunk_v2` round-trip / reject missing body (`mfn-net`).
- `validate_v2_*` + `on_chunk_v2_validates_merkle_proofs_*` (`mfn-node`).
- `wallet_artifact_chunks_matches_commitment_layout` includes proof wire (`mfn-storage-operator`).

### Related shipped work (other lanes, same doctrine)

- **F5-PM10** (`b260033`) — `mfnd archive-export` / `archive-verify`
  ([`mfn-node/src/archive_export.rs`](../mfn-node/src/archive_export.rs)):
  self-verifying offline archives — full replay from genesis spec through the
  STF plus chunk Merkle re-derivation against anchored `data_root`s. The
  disaster-recovery complement to A2/A3's live-mesh integrity.
- **F5-PM13** (`df70b9c`) — `validate_constitution` gates every operator
  genesis spec (emission tail > 0, uniform ring ≥ 16, endowment pricing
  sanity), so a mis-parameterized network can't be born claiming permanence
  it can't fund.

---

## Part B — Remaining work (specific plans)

Ordered roughly by permanence impact per unit risk. Items marked
**consensus** need a version gate and M5-style proptests. Backlog IDs from
[`AGENTS.md`](../AGENTS.md) are given where they exist.

### B1. Range-proof endowment binding (B-11 phase 2) — **consensus**

**Status:** **shipped** (phases 2a–2e on `bbe1d9f`). Public devnet uses `require_endowment_range_proof: 1` with privacy-preserving `MFER` surplus proofs (same `genesis_id`). Phase 1 (`MFEO` opening reveal) remains available for other networks — see [§A6](#a6-pedersen-endowment-opening-binding-b-11-phase-1-commits-3511346--9f0a0aa--0fee187). Design: [`B1_ENDOWMENT_RANGE_PROOF.md`](./B1_ENDOWMENT_RANGE_PROOF.md).

### B2. Merkle-path-carrying chunk gossip — **SHIPPED** (see [§A7](#a7-merkle-path-carrying-chunk-gossip-b2-this-commit))

**Status:** shipped. Multi-chunk inbox writes now require Merkle inclusion proofs
on the `ChunkV2` (`0x12`) path; `ChunkV1` remains accepted inbound for mesh
compatibility. Fan-out and operator chunk push emit `ChunkV2` exclusively.

### B3. Replication accounting — make `replication` mean something at audit time — **consensus (phases 1–3 shipped; genesis flags off)**

**Problem.** `replication` is priced (`required_endowment` multiplies by it)
and bounds-checked, but **never audited** in legacy mode. `apply_block` accepts at most one
SPoRA proof per commitment per block
(`DuplicateStorageProof`, [`apply.rs`](../mfn-consensus/src/block/apply.rs)),
and proofs carry operator payout keys but no operator *identity*
that consensus tracks. The chain therefore cannot distinguish "3 independent
replicas" from "one operator with one copy answering every challenge." The
user pays for N replicas; the protocol proves ≥ 1.

**Phase 1 shipped (`mfn-storage`):** operator-salted challenge derivation —
[`operator_identity_from_payout`](../mfn-storage/src/spora.rs),
[`chunk_index_for_operator_challenge`](../mfn-storage/src/spora.rs),
[`verify_storage_proof_operator_salted`](../mfn-storage/src/spora.rs). Domain
tags `STORAGE_OPERATOR_ID` + `SPORA_OPERATOR_CHALLENGE` in
[`domain.rs`](../mfn-crypto/src/domain.rs). Unit tests prove distinct payout
keys yield independent challenge indices.

**Phase 2 shipped (`mfn-consensus`):** gated by
`EndowmentParams.operator_salted_challenges` (default `0`; checkpoint v5).
When enabled, `apply_block`:

1. Accepts up to `commit.replication` distinct operator proofs per commitment
   per block (`DuplicateStorageProofOperator`,
   `StorageProofReplicationExceeded`).
2. Verifies with [`verify_storage_proof_operator_salted`](../mfn-storage/src/spora.rs).
3. Pays each operator from a per-block frozen baseline with `replication: 1`
   while advancing commitment state once via full-replication accrual.

Public devnet genesis keeps the flag off until bonding registry + M5 proptests
land. Integration tests in [`block_apply.rs`](../mfn-consensus/tests/block_apply.rs).

**Plan (incremental — bonding + proptests next).**

1. **Operator registry binding (phase 3a — shipped, genesis off).** Optionally
   gated by `EndowmentParams.require_registered_operators` (requires B3
   `operator_salted_challenges`). Chain state holds
   `storage_operators: BTreeMap<[u8;32], StorageOperatorEntry>` (payout keys,
   registration height, `bond_amount`). Checkpoint **v6**. When the flag is
   set, `apply_block` rejects proofs whose
   `operator_identity_from_payout` is missing from the map
   (`StorageProofUnregisteredOperator`).
2. **Operator register wire (phase 3b — shipped).** [`StorageOperatorOp::Register`](../mfn-consensus/src/storage_operator_wire.rs)
   with Schnorr authorization under the payout spend key; bond escrow credits
   treasury; leaves extend `bond_root` via [`bond_section_merkle_root`](../mfn-consensus/src/storage_operator_wire.rs).
   Block body section is backward-compatible on decode (optional tail).
   `min_storage_operator_bond` in endowment params (checkpoint **v7**).
3. **Genesis operator seeding (phase 3c — shipped).** JSON `storage_operators[]`
   with `payout_seed_hex`; [`apply_genesis`](../mfn-consensus/src/block/genesis.rs)
   inserts `StorageOperatorEntry` at height 0 (no treasury burn). Public devnet
   enables B3 endowment flags with two deterministic operator seeds; rehearsal
   replica wallet restores from operator-0 seed.
4. **M5.50 proptests (shipped).** `prop_b3_duplicate_operator_rejects_after_prefix`
   plus replication-cap reject tests in
   [`apply_block_proptest.rs`](../mfn-consensus/tests/apply_block_proptest.rs).
5. **Proactive repair + staleness** (B4) — shipped; operator bonding/slashing (B5) next.

Requires: emission/treasury settlement audit under multi-operator blocks, and
heavy M5 proptesting (mixed honest/missing/equivocating operators). Sequence
*after* operator bonding exists.

**Effort:** high. **Risk:** high (consensus + economics).

### B4. Proactive replica repair (re-fan-out on staleness) — **SHIPPED** (this commit)

**Problem.** Fan-out happens when an upload lands (and on inbox completion).
If replicas later vanish — operators churn, disks die — nothing re-spreads
the data. The chain *records* staleness (`StorageEntry.last_proven_height` /
`last_proven_slot` go quiet) but nodes don't act on it.

**Shipped.** Periodic repair sweep in `mfnd` via
[`p2p_repair_sweep.rs`](../mfn-node/src/p2p_repair_sweep.rs): scans
`chain.state().storage` for entries with
`current_slot − last_proven_slot > repair_threshold_slots` where the local
inbox is complete and Merkle-verified (A3/B2 path), then re-fan-outs to
current peers. Config: `MFND_REPAIR_THRESHOLD_SLOTS` (default 14_400 =
2× anti-hoarding window), `MFND_REPAIR_INTERVAL_MS` (default 300_000 ms).
Observable log: `mfnd_p2p_repair_fanout commit=… stale_slots=…`.

**Effort:** low–moderate. **Risk:** low.

### B5. Operator bonding + slashing for failed audits — **5a–5c shipped**

**Problem.** SPoRA is carrot-only without a stick. See [`B5_OPERATOR_SLASHING.md`](./B5_OPERATOR_SLASHING.md).

**Shipped.** Phase **5a** (`e81d33e`): inert slash params, checkpoint **v8**. Phase **5b** (`643a224`): retained bond + miss stats, checkpoint **v9**. Phase **5c** (`8bdb4ab`): auto-slash to treasury + zero-bond deregister in `apply_block`. Phase **5d** (`1485e67`): public devnet enable + M5.51 proptests.

### B6. Size-bucketed commitments (`F5:P15`) — shared with privacy roadmap

`size_bytes` is exact and public — a fingerprint against known documents
(privacy) *and* the input to endowment pricing (permanence). Padding uploads
to bucket boundaries and pricing on the bucket removes the fingerprint and
simplifies B1's revealed-opening variant (the revealed value is a bucket
price, not a document-unique number). Plan details live in
[`PRIVACY_HARDENING.md § B13`](./PRIVACY_HARDENING.md#b13-size-bucketed-storage-commitments-f5p15--consensus-adjacent);
listed here because its enforcement point is the same `apply_block` pricing
walk that A1 hardened.

**Effort:** moderate. **Risk:** medium (endowment pricing).

### B7. Chunk-inbox disk quota (DoS depth) — **shipped**

**Problem.** A2 killed the *unauthenticated* disk-write primitive, but a
peer can still push valid-shaped junk for **anchored** commitments. `chunk-inbox/` had no size budget.

**Shipped.** `MFND_CHUNK_INBOX_MAX_BYTES` (default **64 GiB**, `0` disables) enforced on gossip chunk writes in `p2p_gossip` via [`save_chunk_inbox_with_quota`](../mfn-node/src/p2p_chunk_inbox.rs). Incomplete commit dirs are LRU-evicted before new writes; complete sets are never evicted. Boot log line: `mfnd_chunk_inbox_evict commit=… bytes=…`.

**Effort:** low. **Risk:** low.

### B8. Retrieval accessibility (tracked separately)

Permanence without retrieval is a tombstone. The retrieval story —
`get_chunk` RPC surface, HTTP gateway fetch, WASM prove-and-serve — is
tracked in [`STORAGE_ACCESSIBILITY.md`](./STORAGE_ACCESSIBILITY.md) (M7.11.x)
and not duplicated here; note only that B2's `ChunkV2` path format is
deliberately identical to the retrieval proof format, so gateway responses
become self-verifying for free once B2 lands.

---

## Prioritization

| Impact / effort | Items |
|---|---|
| Shipped | **A1** shape consensus gate, **A2** gossip authentication, **A3** fan-out root verification, **A4** doc honesty, **A5** CI harness fix, **B4** repair sweep, **B5** operator slashing, **B7** inbox quota |
| Cheap wins | **B4** proactive repair, **B7** inbox quota |
| High impact, moderate effort | **B1(1)** endowment opening reveal, **B2** Merkle-path gossip, **B6** size buckets (**B13 shipped**) |
| High impact, high effort | **B1(2)** range-proof binding, **B3** replication accounting (shipped), **B5** bonding + slashing ([design](./B5_OPERATOR_SLASHING.md)) |

Natural next step: **B1 design 1** (close the decorative-endowment gap with
a revealed opening behind a version gate), with **B2** as the parallel
node-layer track since it has no consensus risk.

## See also

- [`STORAGE.md`](./STORAGE.md) — how the storage/permanence mechanisms work
  (includes the M5.49 shape-validation section).
- [`PRIVACY_HARDENING.md`](./PRIVACY_HARDENING.md) — the privacy twin of this
  document.
- [`F5.md`](./F5.md) — the broader privacy/permanence frontier menu.
- [`PROBLEMS.md`](./PROBLEMS.md) /
  [`SECURITY_CONSIDERATIONS.md`](./SECURITY_CONSIDERATIONS.md) — the
  weaknesses these items answer.
- [`AGENTS.md`](../AGENTS.md) — backlog IDs (B-11) and lane ownership.
