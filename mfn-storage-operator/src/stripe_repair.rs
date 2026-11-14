//! Repair a local shard stripe from peer operators, reseal it, and answer.
//!
//! Each operator directory is a wallet. Shards live at
//! `{wallet}.upload-artifacts/{commit}/shard-NN.bin`. When the local
//! operator is missing shards, this copies any shard a peer still has.
//! Four or more distinct shards rebuild the file. Missing local shards are
//! written back, each one is sealed under `{wallet_stem}.operator-id`, and
//! a `challenge.bin` sitting in the commitment directory is answered into
//! `answer-chunk.bin`.
//!
//! The prove loop calls this at the start of every cycle when
//! `MFN_REPAIR_PEERS` lists other wallet paths.

use std::path::{Path, PathBuf};

use mfn_storage::{
    build_storage_commitment, open_shard_stripe, prepare_shard_stripe, seal_replica,
    split_committed_stripe, StripeError, RECOMMENDED_SEAL_ROUNDS, STRIPE_SHARDS,
};

use crate::retrieval_serve::answer_retrieval_challenge;
use crate::upload_artifact_store::{upload_artifact_dir, upload_artifacts_root, PAYLOAD_FILE};

/// What one commitment's repair did.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StripeRepairReport {
    /// Commitment directory name (hex).
    pub commitment_hash_hex: String,
    /// Shards written because they were missing locally.
    pub restored: u32,
    /// Shards still absent after every peer was tried.
    pub still_missing: u32,
    /// Plaintext when at least four shards were available.
    pub recovered: bool,
    /// Shard seals written for the local operator.
    pub sealed: u32,
    /// A local retrieval challenge was answered from the restored stripe.
    pub answered: bool,
}

/// Repair every stripe under `local_wallet` using the same commitment
/// directories from `peer_wallets`.
///
/// # Errors
///
/// [`StripeError`] when a restored code does not round-trip.
pub fn repair_wallet_stripes(
    local_wallet: &Path,
    peer_wallets: &[PathBuf],
) -> Result<Vec<StripeRepairReport>, StripeError> {
    let root = upload_artifacts_root(local_wallet);
    if !root.is_dir() {
        return Ok(Vec::new());
    }
    let mut reports = Vec::new();
    let entries = std::fs::read_dir(&root).map_err(|_| StripeError::NotAStripe)?;
    for entry in entries.flatten() {
        if !entry.path().is_dir() {
            continue;
        }
        let Some(name) = entry.file_name().to_str().map(str::to_string) else {
            continue;
        };
        if name.len() != 64 {
            continue;
        }
        reports.push(repair_one(&name, local_wallet, peer_wallets)?);
    }
    Ok(reports)
}

fn repair_one(
    commit_hex: &str,
    local_wallet: &Path,
    peer_wallets: &[PathBuf],
) -> Result<StripeRepairReport, StripeError> {
    let local = upload_artifact_dir_hex(local_wallet, commit_hex);
    let mut slots = read_slots(&local);
    if slots.iter().all(|s| s.is_none()) {
        if let Ok(payload) = std::fs::read(local.join(PAYLOAD_FILE)) {
            if let Some(shards) = split_committed_stripe(&payload) {
                slots = shards.into_iter().map(Some).collect();
            }
        }
    }
    for peer_wallet in peer_wallets {
        let peer = upload_artifact_dir_hex(peer_wallet, commit_hex);
        let peer_slots = read_slots(&peer);
        for (slot, peer_shard) in slots.iter_mut().zip(peer_slots) {
            if slot.is_none() {
                *slot = peer_shard;
            }
        }
    }
    let have = slots.iter().filter(|s| s.is_some()).count();
    if have < 4 {
        return Ok(StripeRepairReport {
            commitment_hash_hex: commit_hex.to_string(),
            restored: 0,
            still_missing: u32::try_from(12usize.saturating_sub(have)).unwrap_or(12),
            recovered: false,
            sealed: 0,
            answered: false,
        });
    }
    let plain = open_shard_stripe(&slots)?;
    let prepared = prepare_shard_stripe(&plain)?;
    std::fs::create_dir_all(&local).map_err(|_| StripeError::NotAStripe)?;
    let mut restored = 0u32;
    for (i, shard) in prepared.shards.iter().enumerate() {
        let path = local.join(format!("shard-{i:02}.bin"));
        if !path.is_file() {
            std::fs::write(&path, shard).map_err(|_| StripeError::NotAStripe)?;
            restored = restored.saturating_add(1);
        }
    }
    let payload_path = local.join(PAYLOAD_FILE);
    if !payload_path.is_file() {
        std::fs::write(&payload_path, &prepared.bytes).map_err(|_| StripeError::NotAStripe)?;
    }
    let sealed = reseal(&local, local_wallet, &prepared.bytes, prepared.chunk_size);
    let answered = answer_local(&local, &prepared.bytes, prepared.chunk_size);
    let after = read_slots(&local);
    let still_missing = u32::try_from(after.iter().filter(|s| s.is_none()).count()).unwrap_or(0);
    Ok(StripeRepairReport {
        commitment_hash_hex: commit_hex.to_string(),
        restored,
        still_missing,
        recovered: still_missing == 0,
        sealed,
        answered,
    })
}

fn reseal(dir: &Path, wallet: &Path, payload: &[u8], chunk_size: u32) -> u32 {
    let Some(operator_id) = read_operator_id(wallet) else {
        return 0;
    };
    let Ok(built) = build_storage_commitment(payload, 1, Some(chunk_size as usize), 1, None) else {
        return 0;
    };
    let mut sealed = 0u32;
    let shard_len = chunk_size as usize;
    if shard_len == 0 || payload.len() % shard_len != 0 {
        return 0;
    }
    for (i, shard) in payload.chunks(shard_len).enumerate() {
        let Ok(replica) = seal_replica(
            shard,
            &operator_id,
            &built.commit.data_root,
            u8::try_from(i).unwrap_or(u8::MAX),
            RECOMMENDED_SEAL_ROUNDS,
        ) else {
            continue;
        };
        let path = dir.join(format!("shard-{i:02}.seal"));
        if std::fs::write(&path, &replica.bytes).is_ok() {
            sealed = sealed.saturating_add(1);
        }
    }
    sealed
}

fn answer_local(dir: &Path, payload: &[u8], chunk_size: u32) -> bool {
    let Ok(bytes) = std::fs::read(dir.join("challenge.bin")) else {
        return false;
    };
    let Some((posted_height, challenge)) = decode_challenge(&bytes) else {
        return false;
    };
    let Ok(response) = answer_retrieval_challenge(payload, chunk_size, posted_height, &challenge)
    else {
        return false;
    };
    std::fs::write(dir.join("answer-chunk.bin"), &response.chunk).is_ok()
}

fn decode_challenge(bytes: &[u8]) -> Option<(u32, mfn_consensus::retrieval::RetrievalChallenge)> {
    if bytes.len() != 84 {
        return None;
    }
    let posted_height = u32::from_be_bytes(bytes[0..4].try_into().ok()?);
    let mut commitment = [0u8; 32];
    commitment.copy_from_slice(&bytes[4..36]);
    let chunk_index = u32::from_be_bytes(bytes[36..40].try_into().ok()?);
    let operator_index = u32::from_be_bytes(bytes[40..44].try_into().ok()?);
    let mut one_time_refund = [0u8; 32];
    one_time_refund.copy_from_slice(&bytes[44..76]);
    let deposit = u64::from_be_bytes(bytes[76..84].try_into().ok()?);
    Some((
        posted_height,
        mfn_consensus::retrieval::RetrievalChallenge {
            commitment,
            chunk_index,
            operator_index,
            one_time_refund,
            deposit,
        },
    ))
}

fn read_operator_id(wallet: &Path) -> Option<[u8; 32]> {
    let parent = wallet.parent().unwrap_or_else(|| Path::new("."));
    let stem = wallet
        .file_stem()
        .and_then(|s| s.to_str())
        .unwrap_or("wallet");
    let bytes = std::fs::read(parent.join(format!("{stem}.operator-id"))).ok()?;
    let mut id = [0u8; 32];
    if bytes.len() != 32 {
        return None;
    }
    id.copy_from_slice(&bytes);
    Some(id)
}

fn upload_artifact_dir_hex(wallet: &Path, commit_hex: &str) -> PathBuf {
    let mut hash = [0u8; 32];
    if let Ok(bytes) = hex::decode(commit_hex) {
        if bytes.len() == 32 {
            hash.copy_from_slice(&bytes);
        }
    }
    upload_artifact_dir(wallet, &hash)
}

fn read_slots(dir: &Path) -> Vec<Option<Vec<u8>>> {
    let mut slots = Vec::with_capacity(usize::try_from(STRIPE_SHARDS).unwrap_or(12));
    for i in 0..STRIPE_SHARDS {
        let path = dir.join(format!("shard-{i:02}.bin"));
        slots.push(std::fs::read(path).ok());
    }
    slots
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::retrieval_serve::answer_retrieval_challenge;
    use curve25519_dalek::constants::ED25519_BASEPOINT_POINT;
    use mfn_consensus::retrieval::{RetrievalOp, RetrievalRegistry};
    use mfn_consensus::HEADER_VERSION_RETRIEVAL;
    use mfn_storage::{build_storage_commitment, open_replica_seal, prepare_shard_stripe};
    use std::collections::BTreeMap;

    #[test]
    fn peers_cover_a_dropout_then_the_operator_reseals_and_answers() {
        let dir = std::env::temp_dir().join(format!("mfn-repair-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let a = dir.join("a.json");
        let b = dir.join("b.json");
        let c = dir.join("c.json");
        std::fs::create_dir_all(&dir).expect("dir");
        let operator_id = [7u8; 32];
        std::fs::write(dir.join("a.operator-id"), operator_id).expect("id");
        let plain = b"operators B and C keep the file after A loses most shards".to_vec();
        let prepared = prepare_shard_stripe(&plain).expect("stripe");
        let commit = "ab".repeat(32);
        let keeps: [(&PathBuf, &[u32]); 3] = [
            (&a, &[0, 1]),
            (&b, &[2, 3, 4, 5]),
            (&c, &[6, 7, 8, 9, 10, 11]),
        ];
        for (wallet, keep) in keeps {
            let dest = upload_artifact_dir_hex(wallet, &commit);
            std::fs::create_dir_all(&dest).expect("dest");
            for i in keep {
                std::fs::write(
                    dest.join(format!("shard-{i:02}.bin")),
                    &prepared.shards[*i as usize],
                )
                .expect("shard");
            }
        }
        let built = build_storage_commitment(
            &prepared.bytes,
            1,
            Some(prepared.chunk_size as usize),
            1,
            None,
        )
        .expect("commit");
        let challenge = mfn_consensus::retrieval::RetrievalChallenge {
            commitment: built.commit.data_root,
            chunk_index: 3,
            operator_index: 0,
            one_time_refund: ED25519_BASEPOINT_POINT.compress().to_bytes(),
            deposit: 1_000,
        };
        let mut file = Vec::new();
        file.extend_from_slice(&2u32.to_be_bytes());
        file.extend_from_slice(&challenge.commitment);
        file.extend_from_slice(&challenge.chunk_index.to_be_bytes());
        file.extend_from_slice(&challenge.operator_index.to_be_bytes());
        file.extend_from_slice(&challenge.one_time_refund);
        file.extend_from_slice(&challenge.deposit.to_be_bytes());
        std::fs::write(
            upload_artifact_dir_hex(&a, &commit).join("challenge.bin"),
            &file,
        )
        .expect("challenge");

        let reports = repair_wallet_stripes(&a, &[b.clone(), c.clone()]).expect("repair");
        assert_eq!(reports.len(), 1);
        assert!(reports[0].recovered);
        assert!(reports[0].restored >= 10);
        assert_eq!(reports[0].sealed, 12);
        assert!(reports[0].answered);

        let local = upload_artifact_dir_hex(&a, &commit);
        let slots = read_slots(&local);
        assert!(slots.iter().all(|s| s.is_some()));
        let opened = open_shard_stripe(&slots).expect("open");
        assert_eq!(opened, plain);
        let seal = std::fs::read(local.join("shard-03.seal")).expect("seal");
        let unsealed =
            open_replica_seal(&seal, &operator_id, &built.commit.data_root).expect("unseal");
        assert_eq!(unsealed, prepared.shards[3]);
        let other = [8u8; 32];
        assert!(open_replica_seal(&seal, &other, &built.commit.data_root).is_err());

        let mut bonds = BTreeMap::from([(0u32, 10_000u64)]);
        let mut treasury = 0u128;
        let mut registry = RetrievalRegistry::default();
        registry
            .apply_ops(
                HEADER_VERSION_RETRIEVAL,
                2,
                &[RetrievalOp::Challenge(challenge.clone())],
                &mut bonds,
                &mut treasury,
            )
            .expect("post");
        let response =
            answer_retrieval_challenge(&prepared.bytes, prepared.chunk_size, 2, &challenge)
                .expect("answer");
        let written = std::fs::read(local.join("answer-chunk.bin")).expect("answer file");
        assert_eq!(written, response.chunk);
        registry
            .apply_ops(
                HEADER_VERSION_RETRIEVAL,
                3,
                &[RetrievalOp::Response(response)],
                &mut bonds,
                &mut treasury,
            )
            .expect("respond");
        assert!(!registry.blocks_unbond(0));
        let _ = std::fs::remove_dir_all(dir);
    }
}
