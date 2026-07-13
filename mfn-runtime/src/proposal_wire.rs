//! P2P wire encoding for block proposals and committee votes (**M2.3.23**).

use mfn_bls::{bls_verify, encode_signature, CommitteeVote, BLS_SIGNATURE_BYTES};
use mfn_consensus::{
    block_header_bytes, decode_block_body, decode_block_header, decode_producer_proof,
    encode_block_body, encode_producer_proof, header_signing_hash, BlockBody, BlockHeader,
    ConsensusDecodeError, SlotContext,
};
use mfn_crypto::codec::{Reader, Writer};
use thiserror::Error;

use crate::producer::BlockProposal;

const PROPOSAL_MAGIC: &[u8; 4] = b"MPRP";
const PROPOSAL_VERSION: u8 = 1;
const VOTE_MAGIC: &[u8; 4] = b"MVOT";
const VOTE_VERSION: u8 = 1;

/// Errors encoding or decoding proposal/vote blobs.
#[derive(Debug, Error)]
pub enum ProposalWireError {
    /// Wrong magic bytes or unsupported version.
    #[error("bad proposal wire: {0}")]
    BadProposal(String),
    /// Wrong magic bytes or unsupported version.
    #[error("bad vote wire: {0}")]
    BadVote(String),
    /// Consensus codec failure.
    #[error("consensus decode: {0}")]
    ConsensusDecode(#[from] ConsensusDecodeError),
    /// Block body decode failure.
    #[error("block body: {0}")]
    BlockBody(#[from] mfn_consensus::BlockDecodeError),
    /// Header decode failure.
    #[error("block header: {0}")]
    BlockHeader(#[from] mfn_consensus::HeaderDecodeError),
}

/// Encode a [`BlockProposal`] for P2P `ProposalV1` (`0x0c`).
#[must_use]
pub fn encode_block_proposal(p: &BlockProposal) -> Vec<u8> {
    let body = encode_block_body(
        &p.txs,
        &p.bond_ops,
        &p.slashings,
        &p.storage_proofs,
        &p.storage_operator_ops,
        p.unsealed_header.version,
    );
    let mut w = Writer::new();
    w.push(PROPOSAL_MAGIC);
    w.u8(PROPOSAL_VERSION);
    w.u32(p.ctx.height);
    w.u32(p.ctx.slot);
    w.u64(p.unsealed_header.timestamp);
    w.push(&p.header_hash);
    w.blob(&encode_producer_proof(&p.producer_proof));
    w.blob(&block_header_bytes(&p.unsealed_header));
    w.blob(&body);
    w.into_bytes()
}

/// Decode bytes from [`encode_block_proposal`].
pub fn decode_block_proposal(bytes: &[u8]) -> Result<BlockProposal, ProposalWireError> {
    let mut r = Reader::new(bytes);
    let magic = r
        .bytes(4)
        .map_err(|_| ProposalWireError::BadProposal("truncated magic".into()))?;
    if magic != PROPOSAL_MAGIC {
        return Err(ProposalWireError::BadProposal("magic mismatch".into()));
    }
    let ver = r
        .u8()
        .map_err(|_| ProposalWireError::BadProposal("truncated version".into()))?;
    if ver != PROPOSAL_VERSION {
        return Err(ProposalWireError::BadProposal(format!(
            "unsupported version {ver}"
        )));
    }
    let height = r
        .u32()
        .map_err(|_| ProposalWireError::BadProposal("height".into()))?;
    let slot = r
        .u32()
        .map_err(|_| ProposalWireError::BadProposal("slot".into()))?;
    let timestamp = r
        .u64()
        .map_err(|_| ProposalWireError::BadProposal("timestamp".into()))?;
    let header_hash_raw = r
        .bytes(32)
        .map_err(|_| ProposalWireError::BadProposal("header_hash".into()))?;
    let mut header_hash = [0u8; 32];
    header_hash.copy_from_slice(header_hash_raw);
    let producer_proof = decode_producer_proof(
        r.blob()
            .map_err(|_| ProposalWireError::BadProposal("producer_proof".into()))?,
    )?;
    let header_bytes = r
        .blob()
        .map_err(|_| ProposalWireError::BadProposal("header".into()))?;
    let unsealed_header: BlockHeader = decode_block_header(header_bytes)?;
    let body: BlockBody = decode_block_body(
        r.blob()
            .map_err(|_| ProposalWireError::BadProposal("body".into()))?,
        unsealed_header.version,
    )?;
    if unsealed_header.timestamp != timestamp {
        return Err(ProposalWireError::BadProposal(
            "timestamp does not match unsealed header".into(),
        ));
    }
    if header_signing_hash(&unsealed_header) != header_hash {
        return Err(ProposalWireError::BadProposal(
            "header_hash does not match unsealed header".into(),
        ));
    }
    let ctx = SlotContext {
        height,
        slot,
        prev_hash: unsealed_header.prev_hash,
    };
    Ok(BlockProposal {
        unsealed_header,
        header_hash,
        ctx,
        producer_proof,
        txs: body.txs,
        bond_ops: body.bond_ops,
        slashings: body.slashings,
        storage_proofs: body.storage_proofs,
        storage_operator_ops: body.storage_operator_ops,
    })
}

/// Encode a committee vote for P2P `VoteV1` (`0x0d`).
#[must_use]
pub fn encode_committee_vote(header_hash: &[u8; 32], vote: &CommitteeVote) -> Vec<u8> {
    let mut w = Writer::new();
    w.push(VOTE_MAGIC);
    w.u8(VOTE_VERSION);
    w.push(header_hash);
    w.u32(vote.index as u32);
    w.push(&encode_signature(&vote.sig));
    w.into_bytes()
}

/// Decode bytes from [`encode_committee_vote`].
pub fn decode_committee_vote(bytes: &[u8]) -> Result<([u8; 32], CommitteeVote), ProposalWireError> {
    let mut r = Reader::new(bytes);
    let magic = r
        .bytes(4)
        .map_err(|_| ProposalWireError::BadVote("truncated magic".into()))?;
    if magic != VOTE_MAGIC {
        return Err(ProposalWireError::BadVote("magic mismatch".into()));
    }
    let ver = r
        .u8()
        .map_err(|_| ProposalWireError::BadVote("truncated version".into()))?;
    if ver != VOTE_VERSION {
        return Err(ProposalWireError::BadVote(format!(
            "unsupported version {ver}"
        )));
    }
    let hash_raw = r
        .bytes(32)
        .map_err(|_| ProposalWireError::BadVote("header_hash".into()))?;
    let mut header_hash = [0u8; 32];
    header_hash.copy_from_slice(hash_raw);
    let index = r
        .u32()
        .map_err(|_| ProposalWireError::BadVote("index".into()))? as usize;
    let sig_bytes = r
        .bytes(BLS_SIGNATURE_BYTES)
        .map_err(|_| ProposalWireError::BadVote("signature".into()))?;
    let sig = mfn_bls::decode_signature(sig_bytes)
        .map_err(|e| ProposalWireError::BadVote(format!("sig decode: {e}")))?;
    Ok((header_hash, CommitteeVote { index, sig }))
}

/// Verify a vote's BLS signature over `header_hash` for validator `bls_pk`.
#[must_use]
pub fn verify_committee_vote_sig(
    header_hash: &[u8; 32],
    vote: &CommitteeVote,
    bls_pk: &mfn_bls::BlsPublicKey,
) -> bool {
    bls_verify(&vote.sig, header_hash, bls_pk)
}

#[cfg(test)]
mod tests {
    use super::*;
    use mfn_bls::bls_sign;
    use mfn_consensus::{build_unsealed_header, try_produce_slot, Validator, ValidatorSecrets};
    use mfn_crypto::vrf::vrf_keygen_from_seed;

    fn sample_proposal() -> BlockProposal {
        let vrf = vrf_keygen_from_seed(&[7u8; 32]).unwrap();
        let bls = mfn_bls::bls_keygen_from_seed(&[8u8; 32]);
        let producer = Validator {
            index: 0,
            vrf_pk: vrf.pk,
            bls_pk: bls.pk,
            stake: 100,
            payout: None,
        };
        let secrets = ValidatorSecrets {
            index: 0,
            vrf,
            bls: bls.clone(),
        };
        let state = mfn_consensus::ChainState::default();
        let txs = vec![];
        let unsealed = build_unsealed_header(&state, &txs, &[], &[], &[], 1, 100);
        let header_hash = header_signing_hash(&unsealed);
        let ctx = SlotContext {
            height: 1,
            slot: 1,
            prev_hash: unsealed.prev_hash,
        };
        let producer_proof = try_produce_slot(&ctx, &secrets, &producer, 100, 10.0, &header_hash)
            .unwrap()
            .unwrap();
        BlockProposal {
            unsealed_header: unsealed,
            header_hash,
            ctx,
            producer_proof,
            txs,
            bond_ops: vec![],
            slashings: vec![],
            storage_proofs: vec![],
            storage_operator_ops: vec![],
        }
    }

    #[test]
    fn proposal_round_trip() {
        let p = sample_proposal();
        let bytes = encode_block_proposal(&p);
        let back = decode_block_proposal(&bytes).expect("decode");
        assert_eq!(back.header_hash, p.header_hash);
        assert_eq!(back.ctx.height, p.ctx.height);
        assert_eq!(back.txs.len(), p.txs.len());
    }

    #[test]
    fn vote_round_trip() {
        let hash = [9u8; 32];
        let bls = mfn_bls::bls_keygen_from_seed(&[3u8; 32]);
        let vote = CommitteeVote {
            index: 1,
            sig: bls_sign(&hash, &bls.sk),
        };
        let bytes = encode_committee_vote(&hash, &vote);
        let (h2, v2) = decode_committee_vote(&bytes).expect("decode");
        assert_eq!(h2, hash);
        assert_eq!(v2.index, vote.index);
        assert!(verify_committee_vote_sig(&hash, &v2, &bls.pk));
    }
}
