//! On-chain retrieval challenges (**B-317**).
//!
//! SPoRA shows that some operator possessed a chunk. It does not show that
//! the operator served that chunk to anyone. A third party cannot prove a
//! refusal, so this module does not try. Refusal is defined as silence:
//! no valid [`RetrievalResponse`] by the deadline.
//!
//! The challenger is a fresh one-time refund key. The deposit is an amount,
//! not a wallet id. Nothing in the challenge names a spend key, a view key,
//! or a requester. Header versions below [`HEADER_VERSION_RETRIEVAL`] ignore
//! the section, so Path A and F-A block bytes stay as they are.
//!
//! Slashes land on the storage-operator bond (`StorageOperatorEntry::bond_amount`).
//! Validator equivocation slashing is a separate path and is not used here.

use std::collections::{BTreeMap, BTreeSet};

use curve25519_dalek::edwards::CompressedEdwardsY;
use mfn_crypto::codec::{Reader, Writer};
use mfn_crypto::hash::dhash;
use mfn_crypto::merkle::{verify_merkle_proof, MerkleProof};
use mfn_storage::{chunk_hash, decode_merkle_proof_wire, encode_merkle_proof_wire};

use crate::block::HEADER_VERSION_RETRIEVAL;

const CHALLENGE_DOMAIN: &[u8] = b"MFBN-1/retrieval-challenge";
const OP_CHALLENGE: u8 = 1;
const OP_RESPONSE: u8 = 2;

/// Blocks after the posting height in which a response still counts.
pub const RETRIEVAL_RESPONSE_WINDOW: u32 = 8;
/// Open challenges one operator may have at once.
pub const RETRIEVAL_MAX_OPEN_PER_OPERATOR: u32 = 4;
/// Open challenges one chunk may have at once.
pub const RETRIEVAL_MAX_OPEN_PER_CHUNK: u32 = 1;
/// Blocks after a valid answer before that chunk can be challenged again.
pub const RETRIEVAL_ANSWER_COOLDOWN: u32 = 16;
/// Share of the operator bond taken on silence, in basis points.
pub const RETRIEVAL_SLASH_BPS: u32 = 2_500;
/// Minimum slash when the bond can cover it. The bond itself is the hard cap.
pub const RETRIEVAL_SLASH_FLOOR: u64 = 100;
/// Maximum slash from one missed challenge.
pub const RETRIEVAL_SLASH_CAP: u64 = 1_000_000;
/// Share of a failed challenger's deposit that is forfeited, in basis points.
pub const RETRIEVAL_FALSE_FORFEIT_BPS: u32 = 2_500;
/// Share of that forfeit credited to the operator bond. The rest goes to treasury.
pub const RETRIEVAL_OPERATOR_FORFEIT_SHARE_BPS: u32 = 5_000;
/// Share of a silence slash paid to the challenger as a bounty. The rest is treasury.
pub const RETRIEVAL_CHALLENGER_BOUNTY_BPS: u32 = 5_000;
/// Largest chunk a response may carry.
pub const RETRIEVAL_MAX_CHUNK_BYTES: usize = 1 << 20;

/// Why a retrieval op or an exit was rejected.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RetrievalError {
    /// Header version is below [`HEADER_VERSION_RETRIEVAL`].
    Inactive,
    /// `operator_index` is not a bonded storage operator.
    UnknownOperator {
        /// Index named by the challenge.
        operator_index: u32,
    },
    /// A challenge must lock a non-zero deposit.
    DepositZero,
    /// The refund key is not a compressed Edwards point.
    RefundKeyInvalid,
    /// This operator or this chunk already has too many open challenges.
    RateLimit,
    /// This chunk was answered and the cooldown has not elapsed.
    Cooldown {
        /// First height at which a new challenge is allowed.
        until: u32,
    },
    /// No open challenge has this id.
    UnknownChallenge,
    /// The response arrived after the deadline.
    LateResponse,
    /// The chunk or its Merkle path does not match the stored root.
    BadChunk,
    /// A bond exit is queued or requested while a challenge is open.
    ExitBlocked {
        /// Operator that may not exit.
        operator_index: u32,
    },
    /// Retrieval bytes could not be decoded.
    Codec,
}

/// A bonded accusation that one operator must serve one chunk.
///
/// `one_time_refund` is the only key. It is a fresh point the challenger
/// generated for this challenge. The deposit was paid by a normal
/// ring-signed transaction; that transaction is not named here.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RetrievalChallenge {
    /// Merkle root of the file the operator must serve.
    pub commitment: [u8; 32],
    /// Leaf index inside that file.
    pub chunk_index: u32,
    /// Position of the operator in the sorted storage-operator set.
    pub operator_index: u32,
    /// Compressed Edwards point that receives any refund or bounty.
    pub one_time_refund: [u8; 32],
    /// Amount locked from the ring-signed funding transaction.
    pub deposit: u64,
}

/// The operator's answer: the chunk and a Merkle path to `commitment`.
#[derive(Clone, Debug)]
pub struct RetrievalResponse {
    /// Id of the open challenge, from [`challenge_id`].
    pub challenge_id: [u8; 32],
    /// Chunk bytes. Their [`chunk_hash`] is the Merkle leaf.
    pub chunk: Vec<u8>,
    /// Path from that leaf to the commitment root.
    pub proof: MerkleProof,
}

/// One body entry. Encoded only when the header version is at least 7.
#[derive(Clone, Debug)]
pub enum RetrievalOp {
    /// Lock a deposit and open a challenge.
    Challenge(RetrievalChallenge),
    /// Serve the chunk named by an open challenge.
    Response(RetrievalResponse),
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct OpenChallenge {
    commitment: [u8; 32],
    chunk_index: u32,
    operator_index: u32,
    one_time_refund: [u8; 32],
    deposit: u64,
    posted_height: u32,
    deadline: u32,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
struct ChunkId {
    commitment: [u8; 32],
    chunk_index: u32,
}

/// Open challenges, cooldowns, locked deposits, and operator-bond exits.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct RetrievalRegistry {
    open: BTreeMap<[u8; 32], OpenChallenge>,
    cooldown_until: BTreeMap<ChunkId, u32>,
    pending_exits: BTreeSet<u32>,
    escrow: u128,
    credits: BTreeMap<[u8; 32], u128>,
    /// Operator indices whose queued exit was dropped by the latest silence
    /// slash. Not checkpointed. Callers use this to drop `pending_unbonds`.
    forfeited_exits: Vec<u32>,
}

/// Deterministic slash for one missed challenge.
///
/// Proportional to the bond, then raised to the floor and cut at the cap.
/// Never larger than the bond. A zero bond slashes zero.
#[must_use]
pub fn retrieval_slash_amount(bond: u64) -> u64 {
    if bond == 0 {
        return 0;
    }
    let proportional = u128::from(bond) * u128::from(RETRIEVAL_SLASH_BPS) / 10_000;
    let proportional = u64::try_from(proportional).unwrap_or(u64::MAX);
    proportional
        .clamp(RETRIEVAL_SLASH_FLOOR, RETRIEVAL_SLASH_CAP)
        .min(bond)
}

/// Id of a challenge. The preimage is the public accusation only.
#[must_use]
pub fn challenge_id(posted_height: u32, challenge: &RetrievalChallenge) -> [u8; 32] {
    let mut pre = Vec::with_capacity(32 + 4 + 4 + 32 + 4 + 8);
    pre.extend_from_slice(&posted_height.to_be_bytes());
    pre.extend_from_slice(&challenge.commitment);
    pre.extend_from_slice(&challenge.chunk_index.to_be_bytes());
    pre.extend_from_slice(&challenge.operator_index.to_be_bytes());
    pre.extend_from_slice(&challenge.one_time_refund);
    pre.extend_from_slice(&challenge.deposit.to_be_bytes());
    dhash(CHALLENGE_DOMAIN, &[&pre])
}

impl RetrievalRegistry {
    /// Locked deposits plus amounts owed to one-time refund keys.
    #[must_use]
    pub fn accounted(&self) -> u128 {
        self.escrow + self.credits.values().copied().sum::<u128>()
    }

    /// `true` when an open challenge names this operator.
    #[must_use]
    pub fn blocks_unbond(&self, operator_index: u32) -> bool {
        self.open
            .values()
            .any(|c| c.operator_index == operator_index)
    }

    /// Queue a bond exit. Fails while a challenge against this operator is open.
    ///
    /// This is the storage-operator bond exit. It does not touch validator
    /// `pending_unbonds` or equivocation evidence.
    pub fn request_exit(&mut self, operator_index: u32) -> Result<(), RetrievalError> {
        if self.blocks_unbond(operator_index) {
            return Err(RetrievalError::ExitBlocked { operator_index });
        }
        self.pending_exits.insert(operator_index);
        Ok(())
    }

    /// Pay the operator bond back to the caller when the exit is free.
    ///
    /// Returns the bond that left the map. A queued exit whose operator is
    /// challenged does not pay. A slash drops the exit instead of paying it.
    pub fn settle_exit(
        &mut self,
        operator_index: u32,
        bonds: &mut BTreeMap<u32, u64>,
    ) -> Result<u64, RetrievalError> {
        if !self.pending_exits.contains(&operator_index) {
            return Err(RetrievalError::ExitBlocked { operator_index });
        }
        if self.blocks_unbond(operator_index) {
            return Err(RetrievalError::ExitBlocked { operator_index });
        }
        self.pending_exits.remove(&operator_index);
        let paid = bonds.remove(&operator_index).unwrap_or(0);
        Ok(paid)
    }

    /// Apply this block's retrieval ops, then slash silence whose deadline
    /// has passed. Header versions below 7 accept an empty list and change
    /// nothing.
    pub fn apply_ops(
        &mut self,
        header_version: u32,
        height: u32,
        ops: &[RetrievalOp],
        bonds: &mut BTreeMap<u32, u64>,
        treasury: &mut u128,
    ) -> Result<(), RetrievalError> {
        if header_version < HEADER_VERSION_RETRIEVAL {
            return if ops.is_empty() {
                Ok(())
            } else {
                Err(RetrievalError::Inactive)
            };
        }
        self.forfeited_exits.clear();
        for op in ops {
            match op {
                RetrievalOp::Challenge(c) => self.post(height, c, bonds)?,
                RetrievalOp::Response(r) => self.respond(height, r, bonds, treasury)?,
            }
        }
        self.expire(height, bonds, treasury);
        Ok(())
    }

    fn post(
        &mut self,
        height: u32,
        challenge: &RetrievalChallenge,
        bonds: &BTreeMap<u32, u64>,
    ) -> Result<(), RetrievalError> {
        if challenge.deposit == 0 {
            return Err(RetrievalError::DepositZero);
        }
        if CompressedEdwardsY(challenge.one_time_refund)
            .decompress()
            .is_none()
        {
            return Err(RetrievalError::RefundKeyInvalid);
        }
        if !bonds.contains_key(&challenge.operator_index) {
            return Err(RetrievalError::UnknownOperator {
                operator_index: challenge.operator_index,
            });
        }
        let open_for_op = self
            .open
            .values()
            .filter(|c| c.operator_index == challenge.operator_index)
            .count();
        if open_for_op >= RETRIEVAL_MAX_OPEN_PER_OPERATOR as usize {
            return Err(RetrievalError::RateLimit);
        }
        let chunk = ChunkId {
            commitment: challenge.commitment,
            chunk_index: challenge.chunk_index,
        };
        let open_for_chunk = self
            .open
            .values()
            .filter(|c| c.commitment == chunk.commitment && c.chunk_index == chunk.chunk_index)
            .count();
        if open_for_chunk >= RETRIEVAL_MAX_OPEN_PER_CHUNK as usize {
            return Err(RetrievalError::RateLimit);
        }
        if let Some(until) = self.cooldown_until.get(&chunk) {
            if height < *until {
                return Err(RetrievalError::Cooldown { until: *until });
            }
        }
        let id = challenge_id(height, challenge);
        let deadline = height.saturating_add(RETRIEVAL_RESPONSE_WINDOW);
        self.open.insert(
            id,
            OpenChallenge {
                commitment: challenge.commitment,
                chunk_index: challenge.chunk_index,
                operator_index: challenge.operator_index,
                one_time_refund: challenge.one_time_refund,
                deposit: challenge.deposit,
                posted_height: height,
                deadline,
            },
        );
        self.escrow = self.escrow.saturating_add(u128::from(challenge.deposit));
        Ok(())
    }

    fn respond(
        &mut self,
        height: u32,
        response: &RetrievalResponse,
        bonds: &mut BTreeMap<u32, u64>,
        treasury: &mut u128,
    ) -> Result<(), RetrievalError> {
        let Some(open) = self.open.get(&response.challenge_id).cloned() else {
            return Err(RetrievalError::UnknownChallenge);
        };
        if height > open.deadline {
            return Err(RetrievalError::LateResponse);
        }
        if response.chunk.is_empty() || response.chunk.len() > RETRIEVAL_MAX_CHUNK_BYTES {
            return Err(RetrievalError::BadChunk);
        }
        if response.proof.index != open.chunk_index as usize {
            return Err(RetrievalError::BadChunk);
        }
        let leaf = chunk_hash(&response.chunk);
        if !verify_merkle_proof(&leaf, &response.proof, &open.commitment) {
            return Err(RetrievalError::BadChunk);
        }
        self.open.remove(&response.challenge_id);
        let (refund, to_operator, to_treasury) = split_forfeit(open.deposit);
        self.escrow = self.escrow.saturating_sub(u128::from(open.deposit));
        credit(&mut self.credits, &open.one_time_refund, u128::from(refund));
        // A missing bond means the operator left the set before the answer.
        // Do not insert a new entry: that amount would never be written back
        // onto an operator and would vanish from the supply. Credit it to
        // treasury with the rest of the forfeit.
        let mut treasury_share = u128::from(to_treasury);
        if to_operator > 0 {
            if let Some(bond) = bonds.get_mut(&open.operator_index) {
                *bond = bond.saturating_add(to_operator);
            } else {
                treasury_share = treasury_share.saturating_add(u128::from(to_operator));
            }
        }
        *treasury = treasury.saturating_add(treasury_share);
        let until = height.saturating_add(RETRIEVAL_ANSWER_COOLDOWN);
        self.cooldown_until.insert(
            ChunkId {
                commitment: open.commitment,
                chunk_index: open.chunk_index,
            },
            until,
        );
        Ok(())
    }

    fn expire(&mut self, height: u32, bonds: &mut BTreeMap<u32, u64>, treasury: &mut u128) {
        let due: Vec<[u8; 32]> = self
            .open
            .iter()
            .filter(|(_, c)| height > c.deadline)
            .map(|(id, _)| *id)
            .collect();
        for id in due {
            let Some(open) = self.open.remove(&id) else {
                continue;
            };
            let bond = bonds.get(&open.operator_index).copied().unwrap_or(0);
            let slash = retrieval_slash_amount(bond);
            let bounty = u64::try_from(
                u128::from(slash) * u128::from(RETRIEVAL_CHALLENGER_BOUNTY_BPS) / 10_000,
            )
            .unwrap_or(0);
            let to_treasury = slash.saturating_sub(bounty);
            if let Some(entry) = bonds.get_mut(&open.operator_index) {
                *entry = entry.saturating_sub(slash);
            }
            self.pending_exits.remove(&open.operator_index);
            self.forfeited_exits.push(open.operator_index);
            self.escrow = self.escrow.saturating_sub(u128::from(open.deposit));
            credit(
                &mut self.credits,
                &open.one_time_refund,
                u128::from(open.deposit.saturating_add(bounty)),
            );
            *treasury = treasury.saturating_add(u128::from(to_treasury));
        }
    }

    /// Operator indices whose exit was cancelled by silence in the last
    /// [`Self::apply_ops`]. The list is cleared at the start of the next call.
    #[must_use]
    pub fn forfeited_exits(&self) -> &[u32] {
        &self.forfeited_exits
    }

    /// No open challenge, cooldown, exit, escrow, or credit.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.open.is_empty()
            && self.cooldown_until.is_empty()
            && self.pending_exits.is_empty()
            && self.escrow == 0
            && self.credits.is_empty()
    }
}

fn split_forfeit(deposit: u64) -> (u64, u64, u64) {
    let forfeit =
        u64::try_from(u128::from(deposit) * u128::from(RETRIEVAL_FALSE_FORFEIT_BPS) / 10_000)
            .unwrap_or(0);
    let to_operator = u64::try_from(
        u128::from(forfeit) * u128::from(RETRIEVAL_OPERATOR_FORFEIT_SHARE_BPS) / 10_000,
    )
    .unwrap_or(0);
    let to_treasury = forfeit.saturating_sub(to_operator);
    let refund = deposit.saturating_sub(forfeit);
    (refund, to_operator, to_treasury)
}

fn credit(credits: &mut BTreeMap<[u8; 32], u128>, key: &[u8; 32], amount: u128) {
    if amount == 0 {
        return;
    }
    let entry = credits.entry(*key).or_insert(0);
    *entry = entry.saturating_add(amount);
}

/// Encode retrieval ops for a header at version 7 or above.
#[must_use]
pub fn encode_retrieval_ops(ops: &[RetrievalOp]) -> Vec<u8> {
    let mut w = Writer::new();
    w.varint(ops.len() as u64);
    for op in ops {
        match op {
            RetrievalOp::Challenge(c) => {
                w.u8(OP_CHALLENGE);
                w.push(&c.commitment);
                w.u32(c.chunk_index);
                w.u32(c.operator_index);
                w.push(&c.one_time_refund);
                w.u64(c.deposit);
            }
            RetrievalOp::Response(r) => {
                w.u8(OP_RESPONSE);
                w.push(&r.challenge_id);
                w.blob(&r.chunk);
                w.blob(&encode_merkle_proof_wire(&r.proof));
            }
        }
    }
    w.into_bytes()
}

/// Decode retrieval ops written by [`encode_retrieval_ops`].
pub fn decode_retrieval_ops(bytes: &[u8]) -> Result<Vec<RetrievalOp>, RetrievalError> {
    let mut r = Reader::new(bytes);
    let n = r.varint().map_err(|_| RetrievalError::Codec)?;
    let n = usize::try_from(n).map_err(|_| RetrievalError::Codec)?;
    let mut out = Vec::with_capacity(n);
    for _ in 0..n {
        let tag = r.u8().map_err(|_| RetrievalError::Codec)?;
        let op = match tag {
            OP_CHALLENGE => {
                let commitment = read_arr(&mut r)?;
                let chunk_index = r.u32().map_err(|_| RetrievalError::Codec)?;
                let operator_index = r.u32().map_err(|_| RetrievalError::Codec)?;
                let one_time_refund = read_arr(&mut r)?;
                let deposit = r.u64().map_err(|_| RetrievalError::Codec)?;
                RetrievalOp::Challenge(RetrievalChallenge {
                    commitment,
                    chunk_index,
                    operator_index,
                    one_time_refund,
                    deposit,
                })
            }
            OP_RESPONSE => {
                let challenge_id = read_arr(&mut r)?;
                let chunk = r.blob().map_err(|_| RetrievalError::Codec)?.to_vec();
                let proof_bytes = r.blob().map_err(|_| RetrievalError::Codec)?;
                let proof =
                    decode_merkle_proof_wire(proof_bytes).map_err(|_| RetrievalError::Codec)?;
                RetrievalOp::Response(RetrievalResponse {
                    challenge_id,
                    chunk,
                    proof,
                })
            }
            _ => return Err(RetrievalError::Codec),
        };
        out.push(op);
    }
    if !r.end() {
        return Err(RetrievalError::Codec);
    }
    Ok(out)
}

fn read_arr(r: &mut Reader<'_>) -> Result<[u8; 32], RetrievalError> {
    let bytes = r.bytes(32).map_err(|_| RetrievalError::Codec)?;
    let mut arr = [0u8; 32];
    arr.copy_from_slice(bytes);
    Ok(arr)
}

/// Canonical bytes of the registry. Used by checkpoint version 14.
#[must_use]
pub fn encode_registry(reg: &RetrievalRegistry) -> Vec<u8> {
    let mut w = Writer::new();
    w.varint(reg.open.len() as u64);
    for (id, c) in &reg.open {
        w.push(id);
        w.push(&c.commitment);
        w.u32(c.chunk_index);
        w.u32(c.operator_index);
        w.push(&c.one_time_refund);
        w.u64(c.deposit);
        w.u32(c.posted_height);
        w.u32(c.deadline);
    }
    w.varint(reg.cooldown_until.len() as u64);
    for (chunk, until) in &reg.cooldown_until {
        w.push(&chunk.commitment);
        w.u32(chunk.chunk_index);
        w.u32(*until);
    }
    w.varint(reg.pending_exits.len() as u64);
    for idx in &reg.pending_exits {
        w.u32(*idx);
    }
    w.push(&reg.escrow.to_be_bytes());
    w.varint(reg.credits.len() as u64);
    for (key, amount) in &reg.credits {
        w.push(key);
        w.push(&amount.to_be_bytes());
    }
    w.into_bytes()
}

/// Inverse of [`encode_registry`].
pub fn decode_registry(bytes: &[u8]) -> Result<RetrievalRegistry, RetrievalError> {
    let mut r = Reader::new(bytes);
    let n_open = usize::try_from(r.varint().map_err(|_| RetrievalError::Codec)?)
        .map_err(|_| RetrievalError::Codec)?;
    let mut open = BTreeMap::new();
    for _ in 0..n_open {
        let id = read_arr(&mut r)?;
        let commitment = read_arr(&mut r)?;
        let chunk_index = r.u32().map_err(|_| RetrievalError::Codec)?;
        let operator_index = r.u32().map_err(|_| RetrievalError::Codec)?;
        let one_time_refund = read_arr(&mut r)?;
        let deposit = r.u64().map_err(|_| RetrievalError::Codec)?;
        let posted_height = r.u32().map_err(|_| RetrievalError::Codec)?;
        let deadline = r.u32().map_err(|_| RetrievalError::Codec)?;
        open.insert(
            id,
            OpenChallenge {
                commitment,
                chunk_index,
                operator_index,
                one_time_refund,
                deposit,
                posted_height,
                deadline,
            },
        );
    }
    let n_cool = usize::try_from(r.varint().map_err(|_| RetrievalError::Codec)?)
        .map_err(|_| RetrievalError::Codec)?;
    let mut cooldown_until = BTreeMap::new();
    for _ in 0..n_cool {
        let commitment = read_arr(&mut r)?;
        let chunk_index = r.u32().map_err(|_| RetrievalError::Codec)?;
        let until = r.u32().map_err(|_| RetrievalError::Codec)?;
        cooldown_until.insert(
            ChunkId {
                commitment,
                chunk_index,
            },
            until,
        );
    }
    let n_exit = usize::try_from(r.varint().map_err(|_| RetrievalError::Codec)?)
        .map_err(|_| RetrievalError::Codec)?;
    let mut pending_exits = BTreeSet::new();
    for _ in 0..n_exit {
        pending_exits.insert(r.u32().map_err(|_| RetrievalError::Codec)?);
    }
    let escrow_bytes = r.bytes(16).map_err(|_| RetrievalError::Codec)?;
    let mut escrow_arr = [0u8; 16];
    escrow_arr.copy_from_slice(escrow_bytes);
    let escrow = u128::from_be_bytes(escrow_arr);
    let n_credit = usize::try_from(r.varint().map_err(|_| RetrievalError::Codec)?)
        .map_err(|_| RetrievalError::Codec)?;
    let mut credits = BTreeMap::new();
    for _ in 0..n_credit {
        let key = read_arr(&mut r)?;
        let amount_bytes = r.bytes(16).map_err(|_| RetrievalError::Codec)?;
        let mut amount_arr = [0u8; 16];
        amount_arr.copy_from_slice(amount_bytes);
        credits.insert(key, u128::from_be_bytes(amount_arr));
    }
    if !r.end() {
        return Err(RetrievalError::Codec);
    }
    Ok(RetrievalRegistry {
        open,
        cooldown_until,
        pending_exits,
        escrow,
        credits,
        forfeited_exits: Vec::new(),
    })
}

/// Sorted operator index → bond, matching `storage_operators` key order.
#[must_use]
pub fn bonds_from_operator_entries(
    operators: &BTreeMap<[u8; 32], crate::block::StorageOperatorEntry>,
) -> BTreeMap<u32, u64> {
    operators
        .values()
        .enumerate()
        .map(|(i, entry)| (i as u32, entry.bond_amount))
        .collect()
}

/// Write bond amounts back onto the sorted operator set.
pub fn write_operator_bonds(
    operators: &mut BTreeMap<[u8; 32], crate::block::StorageOperatorEntry>,
    bonds: &BTreeMap<u32, u64>,
) {
    for (i, entry) in operators.values_mut().enumerate() {
        if let Some(bond) = bonds.get(&(i as u32)) {
            entry.bond_amount = *bond;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use mfn_crypto::hash::hash_to_point;
    use mfn_crypto::merkle::merkle_proof;
    use mfn_storage::merkle_tree_from_chunks;

    struct Books {
        liquid: u128,
        bonds: BTreeMap<u32, u64>,
        treasury: u128,
        reg: RetrievalRegistry,
    }

    impl Books {
        fn new(bond: u64) -> Self {
            let mut bonds = BTreeMap::new();
            bonds.insert(0, bond);
            Self {
                liquid: 1_000_000,
                bonds,
                treasury: 50_000,
                reg: RetrievalRegistry::default(),
            }
        }

        fn total(&self) -> u128 {
            self.liquid
                + self.treasury
                + self.reg.accounted()
                + self.bonds.values().map(|b| u128::from(*b)).sum::<u128>()
        }

        fn post(
            &mut self,
            height: u32,
            challenge: RetrievalChallenge,
        ) -> Result<(), RetrievalError> {
            let deposit = u128::from(challenge.deposit);
            self.reg.apply_ops(
                HEADER_VERSION_RETRIEVAL,
                height,
                &[RetrievalOp::Challenge(challenge)],
                &mut self.bonds,
                &mut self.treasury,
            )?;
            self.liquid -= deposit;
            Ok(())
        }

        fn respond(
            &mut self,
            height: u32,
            response: RetrievalResponse,
        ) -> Result<(), RetrievalError> {
            self.reg.apply_ops(
                HEADER_VERSION_RETRIEVAL,
                height,
                &[RetrievalOp::Response(response)],
                &mut self.bonds,
                &mut self.treasury,
            )
        }

        fn advance(&mut self, height: u32) {
            self.reg
                .apply_ops(
                    HEADER_VERSION_RETRIEVAL,
                    height,
                    &[],
                    &mut self.bonds,
                    &mut self.treasury,
                )
                .unwrap();
        }
    }

    fn refund_key(label: &[u8]) -> [u8; 32] {
        hash_to_point(label).unwrap().compress().to_bytes()
    }

    fn file() -> ([u8; 32], Vec<u8>, MerkleProof) {
        let chunks: [&[u8]; 2] = [b"alpha-chunk", b"beta-chunk-bytes"];
        let tree = merkle_tree_from_chunks(&chunks).unwrap();
        let proof = merkle_proof(&tree, 1).unwrap();
        (tree.root(), chunks[1].to_vec(), proof)
    }

    fn challenge_for(root: [u8; 32], deposit: u64, label: &[u8]) -> RetrievalChallenge {
        RetrievalChallenge {
            commitment: root,
            chunk_index: 1,
            operator_index: 0,
            one_time_refund: refund_key(label),
            deposit,
        }
    }

    #[test]
    fn b317_honest_response_clears_without_slashing() {
        let (root, chunk, proof) = file();
        let mut books = Books::new(10_000);
        let before = books.total();
        let deposit = 4_000u64;
        books
            .post(10, challenge_for(root, deposit, b"b316-once-honest"))
            .unwrap();
        assert!(books.reg.blocks_unbond(0));
        assert_eq!(books.bonds[&0], 10_000, "posting does not touch the bond");
        let id = challenge_id(10, &challenge_for(root, deposit, b"b316-once-honest"));
        let bad = RetrievalResponse {
            challenge_id: id,
            chunk: b"not-the-chunk".to_vec(),
            proof: proof.clone(),
        };
        assert_eq!(
            books.respond(12, bad).unwrap_err(),
            RetrievalError::BadChunk
        );
        assert!(books.reg.blocks_unbond(0));
        books
            .respond(
                12,
                RetrievalResponse {
                    challenge_id: id,
                    chunk,
                    proof,
                },
            )
            .unwrap();
        assert!(!books.reg.blocks_unbond(0));
        assert!(books.bonds[&0] >= 10_000, "a valid answer does not slash");
        assert_eq!(books.total(), before);
    }

    #[test]
    fn b321_forfeit_of_a_departed_operator_stays_in_treasury() {
        let (root, chunk, proof) = file();
        let mut books = Books::new(10_000);
        let deposit = 4_000u64;
        books
            .post(10, challenge_for(root, deposit, b"b321-departed"))
            .unwrap();
        books.bonds.remove(&0);
        let after_departure = books.total();
        let id = challenge_id(10, &challenge_for(root, deposit, b"b321-departed"));
        let treasury_before = books.treasury;
        books
            .respond(
                12,
                RetrievalResponse {
                    challenge_id: id,
                    chunk,
                    proof,
                },
            )
            .unwrap();
        assert!(
            books.bonds.is_empty(),
            "a valid answer must not recreate a departed operator bond"
        );
        let forfeit = u128::from(deposit) * u128::from(RETRIEVAL_FALSE_FORFEIT_BPS) / 10_000;
        assert_eq!(
            books.treasury,
            treasury_before + forfeit,
            "operator share and treasury share both stay in treasury"
        );
        assert_eq!(books.total(), after_departure);
    }

    #[test]
    fn b317_no_response_slashes_bond_and_pays_bounty() {
        let (root, _, _) = file();
        let mut books = Books::new(10_000);
        let before = books.total();
        books.reg.request_exit(0).unwrap();
        let deposit = 4_000u64;
        books
            .post(10, challenge_for(root, deposit, b"b316-once-miss"))
            .unwrap();
        let deadline = 10 + RETRIEVAL_RESPONSE_WINDOW;
        books.advance(deadline);
        assert_eq!(
            books.bonds[&0], 10_000,
            "the deadline block is still in time"
        );
        books.advance(deadline + 1);
        assert_eq!(books.reg.forfeited_exits(), &[0]);
        let slash = retrieval_slash_amount(10_000);
        assert_eq!(books.bonds[&0], 10_000 - slash);
        assert!((RETRIEVAL_SLASH_FLOOR..=RETRIEVAL_SLASH_CAP).contains(&slash));
        let bounty = slash / 2;
        let key = refund_key(b"b316-once-miss");
        assert_eq!(
            books.reg.credits[&key],
            u128::from(deposit) + u128::from(bounty)
        );
        assert!(books.treasury > 50_000);
        assert!(
            books.reg.settle_exit(0, &mut books.bonds).is_err(),
            "a missed challenge drops the exit instead of paying the old bond"
        );
        assert_eq!(books.total(), before);
        assert!(!books.reg.blocks_unbond(0));
    }

    #[test]
    fn b317_false_accusation_costs_the_challenger() {
        let (root, chunk, proof) = file();
        let mut books = Books::new(10_000);
        let deposit = 4_000u64;
        let key = refund_key(b"b316-once-false");
        books
            .post(3, challenge_for(root, deposit, b"b316-once-false"))
            .unwrap();
        let id = challenge_id(3, &challenge_for(root, deposit, b"b316-once-false"));
        books
            .respond(
                4,
                RetrievalResponse {
                    challenge_id: id,
                    chunk,
                    proof,
                },
            )
            .unwrap();
        let (refund, to_operator, to_treasury) = {
            let forfeit = deposit * u64::from(RETRIEVAL_FALSE_FORFEIT_BPS) / 10_000;
            let to_operator = forfeit * u64::from(RETRIEVAL_OPERATOR_FORFEIT_SHARE_BPS) / 10_000;
            (deposit - forfeit, to_operator, forfeit - to_operator)
        };
        assert!(refund < deposit);
        assert_eq!(books.reg.credits[&key], u128::from(refund));
        assert_eq!(books.bonds[&0], 10_000 + to_operator);
        assert_eq!(books.treasury, 50_000 + u128::from(to_treasury));
        let again = books.post(5, challenge_for(root, deposit, b"b316-once-false-2"));
        assert!(matches!(again, Err(RetrievalError::Cooldown { .. })));
        assert_eq!(books.liquid, 1_000_000 - u128::from(deposit));
    }

    #[test]
    fn b317_supply_is_conserved() {
        let (root, chunk, proof) = file();
        let mut books = Books::new(8_000);
        let start = books.total();
        books
            .post(1, challenge_for(root, 2_000, b"b316-conserve-a"))
            .unwrap();
        assert_eq!(books.total(), start);
        let id = challenge_id(1, &challenge_for(root, 2_000, b"b316-conserve-a"));
        books
            .respond(
                2,
                RetrievalResponse {
                    challenge_id: id,
                    chunk,
                    proof,
                },
            )
            .unwrap();
        assert_eq!(books.total(), start);
        books
            .post(20, challenge_for(root, 3_000, b"b316-conserve-b"))
            .unwrap();
        assert_eq!(books.total(), start);
        books.advance(20 + RETRIEVAL_RESPONSE_WINDOW + 1);
        assert_eq!(books.total(), start);
    }

    #[test]
    fn b317_open_challenge_blocks_unbond() {
        let (root, chunk, proof) = file();
        let mut books = Books::new(10_000);
        books.reg.request_exit(0).unwrap();
        books
            .post(7, challenge_for(root, 1_000, b"b316-once-exit"))
            .unwrap();
        assert_eq!(
            books.reg.request_exit(0).unwrap_err(),
            RetrievalError::ExitBlocked { operator_index: 0 }
        );
        assert_eq!(
            books.reg.settle_exit(0, &mut books.bonds).unwrap_err(),
            RetrievalError::ExitBlocked { operator_index: 0 }
        );
        assert_eq!(books.bonds[&0], 10_000);
        let id = challenge_id(7, &challenge_for(root, 1_000, b"b316-once-exit"));
        books
            .respond(
                8,
                RetrievalResponse {
                    challenge_id: id,
                    chunk,
                    proof,
                },
            )
            .unwrap();
        let paid = books.reg.settle_exit(0, &mut books.bonds).unwrap();
        assert!(paid >= 10_000);
        assert!(!books.bonds.contains_key(&0));
        books.liquid += u128::from(paid);
        assert_eq!(books.total(), 1_000_000 + 50_000 + 10_000);
    }

    #[test]
    fn b317_inactive_on_header_v1() {
        let (root, _, _) = file();
        let mut books = Books::new(10_000);
        let before = books.total();
        let err = books.reg.apply_ops(
            1,
            1,
            &[RetrievalOp::Challenge(challenge_for(root, 100, b"b316-v1"))],
            &mut books.bonds,
            &mut books.treasury,
        );
        assert_eq!(err, Err(RetrievalError::Inactive));
        assert!(books.reg.is_empty());
        assert_eq!(books.bonds[&0], 10_000);
        assert_eq!(books.total(), before);
        books
            .reg
            .apply_ops(1, 1, &[], &mut books.bonds, &mut books.treasury)
            .unwrap();
    }

    #[test]
    fn b317_registry_round_trip_and_small_bond_floor() {
        assert_eq!(retrieval_slash_amount(0), 0);
        assert_eq!(retrieval_slash_amount(40), 40);
        assert_eq!(retrieval_slash_amount(10_000), 2_500);
        let (root, _, _) = file();
        let mut books = Books::new(10_000);
        books
            .post(2, challenge_for(root, 500, b"b316-round"))
            .unwrap();
        let bytes = encode_registry(&books.reg);
        let decoded = decode_registry(&bytes).unwrap();
        assert_eq!(decoded, books.reg);
        let ops = vec![RetrievalOp::Challenge(challenge_for(
            root,
            500,
            b"b316-round",
        ))];
        let decoded = decode_retrieval_ops(&encode_retrieval_ops(&ops)).unwrap();
        match (&ops[0], &decoded[0]) {
            (RetrievalOp::Challenge(a), RetrievalOp::Challenge(b)) => assert_eq!(a, b),
            _ => panic!("challenge op did not round-trip"),
        }
    }
}
