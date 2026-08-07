//! Live public-testnet multi-wallet transfer storm (local tooling).
//!
//! Dual-payment transfers keep both sides above the F7 two-UTXO floor after
//! a single faucet fund. Uses a local observer TCP RPC (e.g. `:18734`).
//!
//! ```text
//! cargo run -p mfn-cli --release --bin onchain-tx-storm -- \
//!   --rpc 127.0.0.1:18734 \
//!   --alice path/alice.json --bob path/bob.json \
//!   --count 200
//! ```

use std::env;
use std::path::{Path, PathBuf};
use std::thread;
use std::time::{Duration, Instant};

use mfn_cli::light_wallet::{wallet_light_scan, LightScanParams};
use mfn_cli::rpc::RpcClient;
use mfn_cli::wallet_store::WalletFile;
use mfn_consensus::{decode_chain_checkpoint, encode_transaction, Recipient};
use mfn_wallet::{production_tx_rng, TransferRecipient, WALLET_MIN_RING_SIZE};

fn usage() -> ! {
    eprintln!(
        "usage: onchain-tx-storm --rpc HOST:PORT --alice FILE --bob FILE [--count N] [--amount N] [--fee N]"
    );
    std::process::exit(2);
}

fn take_arg(args: &mut Vec<String>, flag: &str) -> Option<String> {
    if let Some(i) = args.iter().position(|a| a == flag) {
        if i + 1 >= args.len() {
            usage();
        }
        let v = args[i + 1].clone();
        args.drain(i..=i + 1);
        Some(v)
    } else {
        None
    }
}

fn load_sync(
    path: &Path,
    client: &mut RpcClient,
) -> Result<(WalletFile, mfn_wallet::Wallet), String> {
    let mut file = WalletFile::load(path).map_err(|e| e.to_string())?;
    let mut wallet = file.to_wallet().map_err(|e| e.to_string())?;
    file.apply_pending_spends(&mut wallet)
        .map_err(|e| e.to_string())?;
    file.hydrate_wallet(&mut wallet)
        .map_err(|e| e.to_string())?;
    wallet_light_scan(path, client, &LightScanParams::default()).map_err(|e| e.to_string())?;
    // Reload after scan persisted.
    file = WalletFile::load(path).map_err(|e| e.to_string())?;
    wallet = file.to_wallet().map_err(|e| e.to_string())?;
    file.apply_pending_spends(&mut wallet)
        .map_err(|e| e.to_string())?;
    file.hydrate_wallet(&mut wallet)
        .map_err(|e| e.to_string())?;
    Ok((file, wallet))
}

fn recipient_of(wallet: &mfn_wallet::Wallet) -> Recipient {
    Recipient {
        view_pub: wallet.keys().view_pub(),
        spend_pub: wallet.keys().spend_pub(),
    }
}

fn dual_send(
    sender_path: &Path,
    dest_wallet: &mfn_wallet::Wallet,
    client: &mut RpcClient,
    amount_each: u64,
    fee: u64,
) -> Result<String, String> {
    let (mut file, mut wallet) = load_sync(sender_path, client)?;
    if wallet.owned_count() < 2 {
        return Err(format!(
            "{}: owned_count={} (need >=2 for F7)",
            sender_path.display(),
            wallet.owned_count()
        ));
    }
    let need = amount_each.saturating_mul(2).saturating_add(fee);
    if wallet.balance() < need {
        return Err(format!(
            "{}: balance={} need>={need}",
            sender_path.display(),
            wallet.balance()
        ));
    }

    let cp = client.get_checkpoint().map_err(|e| e.to_string())?;
    let state = decode_chain_checkpoint(&cp)
        .map_err(|e| format!("decode checkpoint: {e}"))?
        .state;

    let recipients = vec![
        TransferRecipient {
            recipient: recipient_of(dest_wallet),
            value: amount_each,
        },
        TransferRecipient {
            recipient: recipient_of(dest_wallet),
            value: amount_each,
        },
    ];

    let pre_owned: Vec<[u8; 32]> = wallet.owned().map(|o| o.utxo_key()).collect();
    let mut rng = production_tx_rng;
    let signed = wallet
        .build_transfer(
            &recipients,
            fee,
            WALLET_MIN_RING_SIZE,
            &state,
            &[],
            &mut rng,
        )
        .map_err(|e| format!("build_transfer: {e}"))?;

    let consumed: Vec<[u8; 32]> = pre_owned
        .into_iter()
        .filter(|k| !wallet.owned().any(|o| o.utxo_key() == *k))
        .collect();
    file.record_pending_spends(&consumed);
    file.capture_wallet_state(&wallet);
    file.save(sender_path).map_err(|e| e.to_string())?;

    let tx_bytes = encode_transaction(&signed.tx);
    let submit = client.submit_tx(&tx_bytes).map_err(|e| e.to_string())?;
    Ok(submit.tx_id)
}

fn main() {
    let mut args: Vec<String> = env::args().skip(1).collect();
    let rpc = take_arg(&mut args, "--rpc").unwrap_or_else(|| "127.0.0.1:18734".into());
    let alice_path = PathBuf::from(take_arg(&mut args, "--alice").unwrap_or_else(|| usage()));
    let bob_path = PathBuf::from(take_arg(&mut args, "--bob").unwrap_or_else(|| usage()));
    let count: usize = take_arg(&mut args, "--count")
        .and_then(|s| s.parse().ok())
        .unwrap_or(200);
    let amount_each: u64 = take_arg(&mut args, "--amount")
        .and_then(|s| s.parse().ok())
        .unwrap_or(50_000);
    let fee: u64 = take_arg(&mut args, "--fee")
        .and_then(|s| s.parse().ok())
        .unwrap_or(10_000);
    if !args.is_empty() {
        usage();
    }

    let mut client = RpcClient::new(&rpc);
    let tip = client.get_tip().expect("get_tip");
    eprintln!(
        "onchain-tx-storm: rpc={rpc} tip={} count={count} amount_each={amount_each} fee={fee}",
        tip.tip_height.unwrap_or(0)
    );

    // Warm both wallets once for dest key material.
    let (_af, alice_w) = load_sync(&alice_path, &mut client).expect("sync alice");
    let (_bf, bob_w) = load_sync(&bob_path, &mut client).expect("sync bob");
    eprintln!(
        "onchain-tx-storm: alice balance={} owned={} | bob balance={} owned={}",
        alice_w.balance(),
        alice_w.owned_count(),
        bob_w.balance(),
        bob_w.owned_count()
    );

    let t0 = Instant::now();
    let mut landed = 0usize;
    let mut from_alice = true;

    while landed < count {
        // Refresh dest snapshot keys/balances each hop.
        let (alice_file, alice_now) = load_sync(&alice_path, &mut client).expect("alice sync");
        let (bob_file, bob_now) = load_sync(&bob_path, &mut client).expect("bob sync");
        let _ = (alice_file, bob_file);

        let (sender_path, dest_w, label) = if from_alice {
            if alice_now.owned_count() >= 2
                && alice_now.balance() >= amount_each.saturating_mul(2).saturating_add(fee)
            {
                (&alice_path, &bob_now, "alice→bob")
            } else if bob_now.owned_count() >= 2
                && bob_now.balance() >= amount_each.saturating_mul(2).saturating_add(fee)
            {
                from_alice = false;
                (&bob_path, &alice_now, "bob→alice")
            } else {
                eprintln!(
                    "onchain-tx-storm: waiting for UTXOs alice(owned={} bal={}) bob(owned={} bal={})",
                    alice_now.owned_count(),
                    alice_now.balance(),
                    bob_now.owned_count(),
                    bob_now.balance()
                );
                thread::sleep(Duration::from_secs(5));
                continue;
            }
        } else if bob_now.owned_count() >= 2
            && bob_now.balance() >= amount_each.saturating_mul(2).saturating_add(fee)
        {
            (&bob_path, &alice_now, "bob→alice")
        } else if alice_now.owned_count() >= 2
            && alice_now.balance() >= amount_each.saturating_mul(2).saturating_add(fee)
        {
            from_alice = true;
            (&alice_path, &bob_now, "alice→bob")
        } else {
            eprintln!(
                "onchain-tx-storm: waiting for UTXOs alice(owned={} bal={}) bob(owned={} bal={})",
                alice_now.owned_count(),
                alice_now.balance(),
                bob_now.owned_count(),
                bob_now.balance()
            );
            thread::sleep(Duration::from_secs(5));
            continue;
        };

        match dual_send(sender_path, dest_w, &mut client, amount_each, fee) {
            Ok(tx_id) => {
                landed += 1;
                eprintln!(
                    "onchain-tx-storm: [{landed}/{count}] {label} tx_id={tx_id} elapsed={:.1}s",
                    t0.elapsed().as_secs_f64()
                );
                from_alice = !from_alice;
                // Give the mesh a beat to mine + propagate before rescan.
                thread::sleep(Duration::from_secs(3));
            }
            Err(e) => {
                eprintln!("onchain-tx-storm: send failed: {e}");
                thread::sleep(Duration::from_secs(5));
            }
        }
    }

    eprintln!(
        "onchain-tx-storm DONE: landed={landed} elapsed={:?}",
        t0.elapsed()
    );
}
