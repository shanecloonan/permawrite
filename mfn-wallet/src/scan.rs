//! Block scanning — turn raw chain bytes into owned outputs.
//!
//! The scanner walks every transaction in a [`Block`] and, for each
//! output, decides whether it belongs to the wallet. Three cases:
//!
//! 1. **Regular tx** — outputs use *random* `r_pub` chosen by the
//!    sender. We try `indexed_stealth_detect` for each output index; on
//!    a hit we decrypt the amount blob and Pedersen-open the
//!    commitment.
//! 2. **Coinbase tx** — `inputs.is_empty()`. The protocol derives
//!    `r_pub` deterministically from `(height, spend_pub)`, so the
//!    scanner is faster if it cheaply re-derives our expected `r_pub`
//!    first and only walks the output if the prefix matches. We still
//!    fall back to the same stealth-detect path because the cheap
//!    prefix match is only an optimisation — the binding check is
//!    Pedersen open.
//! 3. **Spends of our outputs** — every tx's inputs reveal a `key_image`
//!    per input. We scan against the wallet's precomputed key-image set
//!    and report which owned outputs were consumed by this block.
//!
//! This module is *pure*: it never reaches into a `Chain` or a
//! `LightChain`. Callers feed it bytes (or a decoded `Block`) and use
//! the returned [`BlockScan`] to update their wallet state.

use std::collections::HashSet;

use mfn_consensus::{
    coinbase_tx_priv, is_coinbase_shaped, tx_id as compute_tx_id, Block, TransactionWire,
};
use mfn_crypto::encrypted_amount::decrypt_output_amount;
use mfn_crypto::point::generator_g;
use mfn_crypto::stealth::{indexed_stealth_detect, indexed_stealth_spend_key};

use crate::keys::WalletKeys;
use crate::owned::{key_image_for_owned, verify_pedersen_open, OwnedOutput};

/// A single output recovered by the scanner.
///
/// This is just an [`OwnedOutput`] alias with semantic clarity: items
/// returned by [`scan_transaction`] / [`scan_block`] have already passed
/// the Pedersen-open binding check, so the caller can trust the
/// `(value, blinding)` pair without further verification.
pub type ScannedOutput = OwnedOutput;

/// Result of scanning one transaction.
#[derive(Clone, Debug, Default)]
pub struct TxScan {
    /// Outputs of this tx that belong to the wallet (always
    /// Pedersen-open-verified).
    pub recovered: Vec<ScannedOutput>,
    /// Key images of inputs in this tx that match owned outputs from
    /// the wallet's precomputed key-image set. The caller marks those
    /// outputs spent.
    pub spent_key_images: Vec<[u8; 32]>,
}

/// Result of scanning one block.
#[derive(Clone, Debug, Default)]
pub struct BlockScan {
    /// Tx-id keyed map of per-tx scan results, in block order.
    pub txs: Vec<(/* tx_id */ [u8; 32], TxScan)>,
    /// Total `Σ value` of outputs newly attributed to the wallet.
    pub gross_received: u64,
    /// Total `Σ value` of owned outputs spent by this block (best
    /// effort — only outputs whose key image was in `owned_key_images`
    /// at scan time count; the caller can refresh `OwnedOutput.value`
    /// against its local DB for the final answer).
    pub matched_spent: usize,
}

impl BlockScan {
    /// Flattened iterator over every owned output recovered in this
    /// block, in block-then-output order.
    pub fn iter_recovered(&self) -> impl Iterator<Item = &ScannedOutput> {
        self.txs.iter().flat_map(|(_, ts)| ts.recovered.iter())
    }

    /// Flattened set of key-image bytes spent in this block.
    pub fn spent_key_image_bytes(&self) -> HashSet<[u8; 32]> {
        self.txs
            .iter()
            .flat_map(|(_, ts)| ts.spent_key_images.iter().copied())
            .collect()
    }
}

/// Scan a single transaction with the wallet's keys.
///
/// `tx_height` is the height of the block this tx belongs to (used to
/// stamp the recovered outputs so the future decoy sampler can age them
/// correctly). `owned_key_images` is the wallet's precomputed set of
/// key images for its currently unspent outputs — the function reports
/// which of them appear in this tx's inputs.
///
/// The function is read-only: it does not mutate `owned_key_images`;
/// the caller is responsible for evicting matched UTXOs from its local
/// store after consuming the result.
pub fn scan_transaction(
    tx: &TransactionWire,
    tx_height: u32,
    keys: &WalletKeys,
    owned_key_images: &HashSet<[u8; 32]>,
) -> TxScan {
    let mut out = TxScan::default();

    // (1) Look for spends of our existing UTXOs by key-image match.
    for inp in &tx.inputs {
        let ki = inp.sig.key_image.compress().to_bytes();
        if owned_key_images.contains(&ki) {
            out.spent_key_images.push(ki);
        }
    }

    // (2) Walk outputs and recover ours.
    //
    // Coinbase: tx_priv is deterministic and r_pub = tx_priv·G; that
    // gives us a cheap *prefix-style* membership shortcut (re-derive
    // r_pub for our own spend_pub and compare). For regular txs the
    // sender chose r_pub randomly; we have no shortcut so we just try
    // indexed_stealth_detect on every output.
    let cb_shaped = is_coinbase_shaped(tx);
    let coinbase_shortcut_hit = if cb_shaped {
        // If a coinbase wasn't paid to us, the deterministic r_pub
        // won't match, and we skip per-output stealth detection
        // entirely — a hot-path optimisation when most blocks pay
        // someone else.
        //
        // We do NOT use this as the binding check; verify_pedersen_open
        // is still the final word.
        let our_height = u64::from(tx_height);
        let our_tx_priv = coinbase_tx_priv(our_height, &keys.spend_pub());
        let our_r_pub = generator_g() * our_tx_priv;
        our_r_pub == tx.r_pub
    } else {
        false
    };

    let cached_tx_id = compute_tx_id(tx);

    for (idx_usize, output) in tx.outputs.iter().enumerate() {
        let idx = idx_usize as u32;

        if cb_shaped && !coinbase_shortcut_hit {
            // Not our coinbase. Don't even try to scan further outputs
            // — coinbase always has exactly one output anyway.
            break;
        }

        if !indexed_stealth_detect(&tx.r_pub, &output.one_time_addr, idx, keys.inner()) {
            continue;
        }

        let dec = match decrypt_output_amount(&tx.r_pub, idx, keys.view_priv(), &output.enc_amount)
        {
            Ok(d) => d,
            Err(_) => continue,
        };

        if !verify_pedersen_open(&output.amount, dec.value, &dec.blinding) {
            // Stealth-detect can hit on outputs that aren't ours when
            // someone deliberately grinds `r_pub`. Pedersen-open is
            // the cryptographic binding check.
            continue;
        }

        let one_time_spend = indexed_stealth_spend_key(&tx.r_pub, idx, keys.inner());
        // Sanity: this scalar reconstructs the on-chain `P`.
        debug_assert_eq!(generator_g() * one_time_spend, output.one_time_addr);

        let key_image = match key_image_for_owned(&output.one_time_addr, one_time_spend) {
            Ok(ki) => ki,
            Err(_) => continue,
        };

        out.recovered.push(ScannedOutput {
            one_time_addr: output.one_time_addr,
            commit: output.amount,
            value: dec.value,
            blinding: dec.blinding,
            one_time_spend,
            key_image,
            tx_id: cached_tx_id,
            output_idx: idx,
            height: tx_height,
        });
    }

    out
}

/// Scan an entire block — runs [`scan_transaction`] over every tx in
/// the block body.
///
/// Returns a [`BlockScan`] that carries per-tx scan results plus
/// aggregate counters. The caller's wallet state is updated in
/// [`crate::Wallet::ingest_block`]; this helper is the read-only core
/// so it can be reused by view-only / observer wallets.
pub fn scan_block(
    block: &Block,
    keys: &WalletKeys,
    owned_key_images: &HashSet<[u8; 32]>,
) -> BlockScan {
    let height = block.header.height;
    let mut scan = BlockScan::default();

    for tx in &block.txs {
        let ts = scan_transaction(tx, height, keys, owned_key_images);
        let tx_id = compute_tx_id(tx);
        scan.gross_received = scan
            .gross_received
            .saturating_add(ts.recovered.iter().map(|o| o.value).sum::<u64>());
        scan.matched_spent += ts.spent_key_images.len();
        scan.txs.push((tx_id, ts));
    }

    scan
}

#[cfg(test)]
mod tests {
    use super::*;
    use curve25519_dalek::scalar::Scalar;
    use mfn_consensus::{
        build_coinbase, sign_transaction, BlockHeader, InputSpec, OutputSpec, PayoutAddress,
        Recipient,
    };
    use mfn_crypto::clsag::ClsagRing;
    use mfn_crypto::point::{generator_g, generator_h};
    use mfn_crypto::scalar::random_scalar;
    use mfn_crypto::stealth::stealth_gen;

    use crate::keys::WalletKeys;

    /// Build a fake CLSAG ring of size `n` whose `signer_idx` member is
    /// known to the caller. Lifted from `mfn-consensus`'s test helpers.
    fn fake_input(value: u64, ring_size: usize) -> InputSpec {
        let signer_idx = ring_size / 2;
        let mut p = Vec::with_capacity(ring_size);
        let mut c = Vec::with_capacity(ring_size);

        let signer_spend = random_scalar();
        let signer_blinding = random_scalar();
        let signer_p = generator_g() * signer_spend;
        let signer_c = (generator_g() * signer_blinding) + (generator_h() * Scalar::from(value));

        for i in 0..ring_size {
            if i == signer_idx {
                p.push(signer_p);
                c.push(signer_c);
            } else {
                let s = random_scalar();
                p.push(generator_g() * s);
                c.push((generator_g() * random_scalar()) + (generator_h() * random_scalar()));
            }
        }

        InputSpec {
            ring: ClsagRing { p, c },
            signer_idx,
            spend_priv: signer_spend,
            value,
            blinding: signer_blinding,
        }
    }

    fn zero_header(height: u32) -> BlockHeader {
        BlockHeader {
            version: 1,
            prev_hash: [0u8; 32],
            height,
            slot: height,
            timestamp: 0,
            tx_root: [0u8; 32],
            storage_root: [0u8; 32],
            bond_root: [0u8; 32],
            slashing_root: [0u8; 32],
            storage_proof_root: [0u8; 32],
            validator_root: [0u8; 32],
            producer_proof: Vec::new(),
            utxo_root: [0u8; 32],
        }
    }

    fn mk_block(height: u32, txs: Vec<TransactionWire>) -> Block {
        Block {
            header: zero_header(height),
            txs,
            slashings: Vec::new(),
            storage_proofs: Vec::new(),
            bond_ops: Vec::new(),
        }
    }

    #[test]
    fn scan_recovers_a_payment_to_us() {
        let me = WalletKeys::from_stealth(stealth_gen());
        let recipient = Recipient {
            view_pub: me.view_pub(),
            spend_pub: me.spend_pub(),
        };
        let signed = sign_transaction(
            vec![fake_input(1_000_000, 4)],
            vec![OutputSpec::ToRecipient {
                recipient,
                value: 999_000,
                storage: None,
            }],
            1_000,
            Vec::new(),
        )
        .expect("sign");

        let scan = scan_transaction(&signed.tx, 7, &me, &HashSet::new());
        assert_eq!(scan.recovered.len(), 1);
        let o = &scan.recovered[0];
        assert_eq!(o.value, 999_000);
        assert_eq!(o.height, 7);
        assert_eq!(o.output_idx, 0);
        assert_eq!(o.one_time_addr, signed.tx.outputs[0].one_time_addr);
    }

    #[test]
    fn scan_skips_payment_to_someone_else() {
        let me = WalletKeys::from_stealth(stealth_gen());
        let them = stealth_gen();
        let r_them = Recipient {
            view_pub: them.view_pub,
            spend_pub: them.spend_pub,
        };
        let signed = sign_transaction(
            vec![fake_input(1_000_000, 4)],
            vec![OutputSpec::ToRecipient {
                recipient: r_them,
                value: 999_000,
                storage: None,
            }],
            1_000,
            Vec::new(),
        )
        .expect("sign");

        let scan = scan_transaction(&signed.tx, 1, &me, &HashSet::new());
        assert!(scan.recovered.is_empty());
        assert!(scan.spent_key_images.is_empty());
    }

    #[test]
    fn scan_finds_one_output_among_many() {
        let me = WalletKeys::from_stealth(stealth_gen());
        let r_me = Recipient {
            view_pub: me.view_pub(),
            spend_pub: me.spend_pub(),
        };
        let them = stealth_gen();
        let r_them = Recipient {
            view_pub: them.view_pub,
            spend_pub: them.spend_pub,
        };
        let signed = sign_transaction(
            vec![fake_input(1_000_000, 6)],
            vec![
                OutputSpec::ToRecipient {
                    recipient: r_them,
                    value: 400_000,
                    storage: None,
                },
                OutputSpec::ToRecipient {
                    recipient: r_me,
                    value: 599_000,
                    storage: None,
                },
            ],
            1_000,
            Vec::new(),
        )
        .expect("sign");

        let scan = scan_transaction(&signed.tx, 4, &me, &HashSet::new());
        assert_eq!(scan.recovered.len(), 1);
        assert_eq!(scan.recovered[0].output_idx, 1);
        assert_eq!(scan.recovered[0].value, 599_000);
    }

    #[test]
    fn scan_recovers_our_coinbase() {
        let me = WalletKeys::from_stealth(stealth_gen());
        let payout = PayoutAddress {
            view_pub: me.view_pub(),
            spend_pub: me.spend_pub(),
        };
        let cb = build_coinbase(11, 50_000_000, &payout).expect("cb");

        let scan = scan_transaction(&cb, 11, &me, &HashSet::new());
        assert_eq!(scan.recovered.len(), 1);
        assert_eq!(scan.recovered[0].value, 50_000_000);
        assert_eq!(scan.recovered[0].height, 11);
        assert!(scan.spent_key_images.is_empty());
    }

    #[test]
    fn scan_skips_other_validators_coinbase() {
        let me = WalletKeys::from_stealth(stealth_gen());
        let other = stealth_gen();
        let payout_other = PayoutAddress {
            view_pub: other.view_pub,
            spend_pub: other.spend_pub,
        };
        let cb = build_coinbase(11, 50_000_000, &payout_other).expect("cb");

        let scan = scan_transaction(&cb, 11, &me, &HashSet::new());
        assert!(scan.recovered.is_empty());
    }

    #[test]
    fn scan_block_aggregates_across_txs() {
        let me = WalletKeys::from_stealth(stealth_gen());
        let r_me = Recipient {
            view_pub: me.view_pub(),
            spend_pub: me.spend_pub(),
        };
        let payout = PayoutAddress {
            view_pub: me.view_pub(),
            spend_pub: me.spend_pub(),
        };

        let cb = build_coinbase(7, 25_000_000, &payout).expect("cb");
        let pay = sign_transaction(
            vec![fake_input(1_000_000, 4)],
            vec![OutputSpec::ToRecipient {
                recipient: r_me,
                value: 999_000,
                storage: None,
            }],
            1_000,
            Vec::new(),
        )
        .expect("sign");

        let block = mk_block(7, vec![cb, pay.tx]);
        let scan = scan_block(&block, &me, &HashSet::new());

        let total: u64 = scan.iter_recovered().map(|o| o.value).sum();
        assert_eq!(total, 25_000_000 + 999_000);
        assert_eq!(scan.gross_received, total);
    }

    #[test]
    fn scan_marks_owned_utxo_spent_when_key_image_appears() {
        // Set up: pretend we own a UTXO whose key image is some
        // freshly-generated point. Then craft a tx whose input ring
        // is irrelevant but whose `sig.key_image` matches ours. We
        // expect `spent_key_images` to fire.
        //
        // We can't easily mint a fake `TxInputWire` with arbitrary
        // `sig.key_image` without round-tripping through
        // `sign_transaction`, which would yield a *different* key
        // image. Instead, sign a real tx with a `fake_input` and
        // then plug its key image into the wallet's owned-key-image
        // set as the "owned" image. The scanner sees that image in
        // tx.inputs[0].sig.key_image and reports the match.
        let me = WalletKeys::from_stealth(stealth_gen());
        let them = stealth_gen();
        let r_them = Recipient {
            view_pub: them.view_pub,
            spend_pub: them.spend_pub,
        };
        let signed = sign_transaction(
            vec![fake_input(1_000_000, 4)],
            vec![OutputSpec::ToRecipient {
                recipient: r_them,
                value: 999_000,
                storage: None,
            }],
            1_000,
            Vec::new(),
        )
        .expect("sign");

        let ki = signed.tx.inputs[0].sig.key_image.compress().to_bytes();
        let mut owned = HashSet::new();
        owned.insert(ki);

        let scan = scan_transaction(&signed.tx, 3, &me, &owned);
        assert_eq!(scan.spent_key_images, vec![ki]);
    }

    #[test]
    fn scan_pedersen_open_protects_against_grinding() {
        // If an output is structurally addressed to our spend key
        // but the encrypted-amount blob's `(v, γ)` does not open the
        // commitment, we MUST drop it. We simulate that by manually
        // building a TransactionWire whose output ticks every
        // stealth-detect box but whose `enc_amount` is all zeros (so
        // decryption yields a deterministic but wrong (v, γ)).
        let me = WalletKeys::from_stealth(stealth_gen());
        let r_me = Recipient {
            view_pub: me.view_pub(),
            spend_pub: me.spend_pub(),
        };
        let signed = sign_transaction(
            vec![fake_input(1_000_000, 4)],
            vec![OutputSpec::ToRecipient {
                recipient: r_me,
                value: 999_000,
                storage: None,
            }],
            1_000,
            Vec::new(),
        )
        .expect("sign");

        let mut tampered = signed.tx.clone();
        tampered.outputs[0].enc_amount = [0u8; mfn_crypto::ENC_AMOUNT_BYTES];

        // Stealth-detect still hits (we did not touch one_time_addr),
        // but Pedersen-open now mismatches → recovered must be empty.
        let scan = scan_transaction(&tampered, 1, &me, &HashSet::new());
        assert!(
            scan.recovered.is_empty(),
            "must drop output whose decoded (v, γ) does not open the commitment"
        );
    }
}
