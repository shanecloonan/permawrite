//! Canonical-encoding conformance suite (**F5-P9** / `PRIVACY_HARDENING.md` §B2/§B3).
//!
//! Every wallet-controlled byte that differs between implementations
//! partitions the anonymity set into "users of wallet X". All reference
//! frontends (CLI, WASM, `Wallet`) build transactions through
//! [`mfn_wallet::build_transfer`] / [`mfn_wallet::build_storage_upload`],
//! so pinning the wire-visible choices of those two constructors pins the
//! whole reference surface. This suite is the conformance contract:
//!
//! 1. `version` is exactly `TX_VERSION` — no frontend-specific versions.
//! 2. `extra` is empty unless the caller explicitly supplies a memo /
//!    authorship claim; the wallet itself injects **zero** identifying bytes.
//! 3. Every input ring has exactly `WALLET_MIN_RING_SIZE` (= consensus
//!    production uniform ring) members — no ring-size fingerprint.
//! 4. Output count never drops below `WALLET_MIN_TX_OUTPUTS`.
//! 5. Every output's `enc_amount` is a real ciphertext (never the all-zero
//!    "no recipient" sentinel used by decoy/test constructions).
//! 6. Wire bytes are byte-canonical: `encode(decode(encode(tx))) ==
//!    encode(tx)` — there is exactly one serialization of a reference tx.
//! 7. Production RNG: reference frontends wire [`mfn_wallet::production_tx_rng`]
//!    (OS CSPRNG); only this test suite may use [`mfn_crypto::seeded_rng`].
//!
//! There is deliberately no unlock-time assertion: the wire format has no
//! such field (`TransactionWire` is `version/r_pub/inputs/outputs/fee/extra`),
//! which is itself the strongest form of the P9 "remove the field if
//! unused" recommendation. If a timelock field is ever added, this suite
//! must grow a canonical-default assertion for it.

use curve25519_dalek::scalar::Scalar;
use mfn_consensus::{
    decode_transaction, encode_transaction, verify_transaction, Recipient, RingPolicy,
    TransactionWire, TX_VERSION,
};
use mfn_crypto::point::{generator_g, generator_h};
use mfn_crypto::scalar::random_scalar;
use mfn_crypto::{seeded_rng, DecoyCandidate};
use mfn_storage::DEFAULT_ENDOWMENT_PARAMS;
use mfn_wallet::{
    build_storage_upload, build_transfer, estimate_minimum_fee_for_upload, wallet_from_seed,
    OwnedOutput, RingMember, StorageUploadPlan, TransferPlan, TransferRecipient,
    WALLET_MIN_RING_SIZE, WALLET_MIN_TX_INPUTS, WALLET_MIN_TX_OUTPUTS,
};

fn owned(value: u64) -> OwnedOutput {
    let one_time_spend = random_scalar();
    let blinding = random_scalar();
    let one_time_addr = generator_g() * one_time_spend;
    let commit = (generator_g() * blinding) + (generator_h() * Scalar::from(value));
    let key_image =
        mfn_wallet::key_image_for_owned(&one_time_addr, one_time_spend).expect("key image");
    OwnedOutput {
        one_time_addr,
        commit,
        value,
        blinding,
        one_time_spend,
        key_image,
        tx_id: [0u8; 32],
        output_idx: 0,
        height: 1,
    }
}

fn pool(n: usize) -> Vec<DecoyCandidate<RingMember>> {
    (0..n)
        .map(|i| {
            let p = generator_g() * random_scalar();
            let c =
                (generator_g() * random_scalar()) + (generator_h() * Scalar::from((i as u64) + 1));
            DecoyCandidate {
                data: (p, c),
                height: 1,
            }
        })
        .collect()
}

fn reference_transfer(seed: u32) -> TransactionWire {
    let input_a = owned(600_000);
    let input_b = owned(500_000);
    let refs = [&input_a, &input_b];
    let decoys = pool(40);
    let keys = wallet_from_seed(&[0x51u8; 32]);
    let recipient = Recipient {
        view_pub: keys.view_pub(),
        spend_pub: keys.spend_pub(),
    };
    let fee = 1_000u64;
    let recipients = [
        TransferRecipient {
            recipient,
            value: 600_000,
        },
        TransferRecipient {
            recipient,
            value: 1_100_000 - 600_000 - fee,
        },
    ];
    let mut r = seeded_rng(seed);
    let plan = TransferPlan {
        inputs: &refs,
        recipients: &recipients,
        fee,
        extra: &[],
        ring_size: WALLET_MIN_RING_SIZE,
        decoy_pool: &decoys,
        current_height: 1,
        rng: &mut r,
    };
    build_transfer(plan).expect("reference transfer").tx
}

fn reference_upload(seed: u32) -> TransactionWire {
    let params = DEFAULT_ENDOWMENT_PARAMS;
    let fee_to_treasury_bps = 9000u16;
    let data = b"conformance payload";
    let replication = params.min_replication;
    let min_fee = estimate_minimum_fee_for_upload(
        data.len() as u64,
        replication,
        &params,
        fee_to_treasury_bps,
    )
    .expect("min_fee");
    let fee = min_fee.max(1);
    let input_value = 50_000_000_000u64;
    let anchor_value = 100_000u64;
    let input_a = owned(input_value / 2);
    let input_b = owned(input_value - input_value / 2);
    let refs = [&input_a, &input_b];
    let decoys = pool(40);
    let keys = wallet_from_seed(&[0x52u8; 32]);
    let recipient = Recipient {
        view_pub: keys.view_pub(),
        spend_pub: keys.spend_pub(),
    };
    let change = [TransferRecipient {
        recipient,
        value: input_value - anchor_value - fee,
    }];
    let mut r = seeded_rng(seed);
    let plan = StorageUploadPlan {
        inputs: &refs,
        anchor: TransferRecipient {
            recipient,
            value: anchor_value,
        },
        data,
        replication,
        chunk_size: None,
        endowment_blinding: None,
        endowment_params: &params,
        fee_to_treasury_bps,
        change_recipients: &change,
        fee,
        extra: &[],
        authorship_claims: &[],
        ring_size: WALLET_MIN_RING_SIZE,
        decoy_pool: &decoys,
        current_height: 1,
        rng: &mut r,
    };
    build_storage_upload(plan)
        .expect("reference upload")
        .signed
        .tx
}

/// The conformance assertions shared by every reference-built tx kind.
fn assert_canonical(tx: &TransactionWire, kind: &str) {
    assert_eq!(tx.version, TX_VERSION, "{kind}: non-canonical tx version");
    assert!(
        tx.extra.is_empty(),
        "{kind}: wallet injected {} extra byte(s) without caller intent",
        tx.extra.len()
    );
    assert!(
        tx.outputs.len() >= WALLET_MIN_TX_OUTPUTS,
        "{kind}: below the {WALLET_MIN_TX_OUTPUTS}-output privacy floor"
    );
    assert!(
        tx.inputs.len() >= WALLET_MIN_TX_INPUTS,
        "{kind}: below the {WALLET_MIN_TX_INPUTS}-input privacy floor"
    );
    for (i, input) in tx.inputs.iter().enumerate() {
        assert_eq!(
            input.ring.p.len(),
            WALLET_MIN_RING_SIZE,
            "{kind}: input {i} ring size differs from the uniform policy"
        );
        assert_eq!(
            input.ring.c.len(),
            WALLET_MIN_RING_SIZE,
            "{kind}: input {i} commitment column differs from the uniform policy"
        );
    }
    for (i, out) in tx.outputs.iter().enumerate() {
        assert!(
            out.enc_amount.iter().any(|b| *b != 0),
            "{kind}: output {i} carries the all-zero enc_amount sentinel — \
             reference wallets must always encrypt to a real recipient"
        );
        assert!(
            out.view_tag.is_some(),
            "{kind}: output {i} missing v2 view_tag scan hint"
        );
    }

    // Byte-canonical wire form: one and only one serialization.
    let bytes = encode_transaction(tx);
    let decoded = decode_transaction(&bytes).expect("reference tx must decode");
    assert_eq!(
        encode_transaction(&decoded),
        bytes,
        "{kind}: encode/decode round trip is not byte-identical"
    );

    let v = verify_transaction(tx, &RingPolicy::PRODUCTION);
    assert!(
        v.ok,
        "{kind}: conformant tx must verify under production ring policy: {:?}",
        v.errors
    );
}

#[test]
fn reference_transfers_are_canonical() {
    // Two seeds: ring-16 CLSAG + Bulletproof construction dominates the
    // runtime; the assertions are seed-independent invariants.
    for seed in 0..2u32 {
        let tx = reference_transfer(0xC0DE_0000 + seed);
        assert_canonical(&tx, "transfer");
    }
}

#[test]
fn reference_uploads_are_canonical() {
    for seed in 0..2u32 {
        let tx = reference_upload(0xC0DE_1000 + seed);
        assert_canonical(&tx, "upload");
    }
}

/// The wallet ring floor and the consensus production uniform ring must
/// never drift apart: a wallet that signs at any other size partitions
/// its users.
#[test]
fn wallet_ring_floor_matches_consensus_uniform_policy() {
    assert_eq!(
        WALLET_MIN_RING_SIZE,
        RingPolicy::PRODUCTION.uniform_ring_size as usize
    );
    assert_eq!(
        WALLET_MIN_RING_SIZE,
        RingPolicy::PRODUCTION.min_ring_size as usize
    );
    assert_eq!(
        WALLET_MIN_TX_INPUTS,
        RingPolicy::PRODUCTION.min_input_count as usize
    );
}

/// A caller-supplied memo is carried verbatim (committed by the
/// preimage) — canonical means "no *silent* bytes", not "no memos".
#[test]
fn caller_supplied_extra_is_verbatim() {
    let input = owned(1_000_000);
    let refs = [&input];
    let decoys = pool(40);
    let keys = wallet_from_seed(&[0x53u8; 32]);
    let recipient = Recipient {
        view_pub: keys.view_pub(),
        spend_pub: keys.spend_pub(),
    };
    let fee = 1_000u64;
    let recipients = [TransferRecipient {
        recipient,
        value: 1_000_000 - fee,
    }];
    let memo = b"caller memo";
    let mut r = seeded_rng(0xC0DE_2000);
    let plan = TransferPlan {
        inputs: &refs,
        recipients: &recipients,
        fee,
        extra: memo,
        ring_size: WALLET_MIN_RING_SIZE,
        decoy_pool: &decoys,
        current_height: 1,
        rng: &mut r,
    };
    let tx = build_transfer(plan).expect("transfer with memo").tx;
    assert_eq!(tx.extra, memo, "memo must be carried verbatim");
}

/// B3 tail: reference frontends must wire the normative production RNG,
/// never a seeded PRNG. Source-scan so the contract survives refactors.
#[test]
fn reference_frontends_wire_production_tx_rng_not_seeded_rng() {
    for (label, src) in [
        (
            "cli-wallet-cmd",
            include_str!("../../mfn-cli/src/wallet_cmd.rs"),
        ),
        (
            "wasm-transfer",
            include_str!("../../mfn-wasm/src/transfer_core.rs"),
        ),
        (
            "wasm-upload",
            include_str!("../../mfn-wasm/src/upload_core.rs"),
        ),
    ] {
        assert!(
            src.contains("production_tx_rng"),
            "{label}: must import and use mfn_wallet::production_tx_rng"
        );
        assert!(
            !src.contains("seeded_rng"),
            "{label}: production path must not reference seeded_rng"
        );
        assert!(
            !src.contains("crypto_random"),
            "{label}: use production_tx_rng alias, not mfn_crypto::crypto_random directly"
        );
    }
}
