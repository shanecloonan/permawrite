//! `mfn-cli` command-line driver (**M3.0** / **M3.1**).

use std::process::ExitCode;

use serde_json::json;

use crate::claims_cmd::{claims_by_pubkey, claims_for, claims_recent, claims_roots};
use crate::light_subjectivity::{
    wallet_compare_trusted_summary, wallet_export_trusted_summary, wallet_import_trusted_summary,
    wallet_show_trusted_summary,
};
use crate::light_wallet::wallet_light_scan;
use crate::operator_cmd::{
    operator_artifacts, operator_assemble_inbox, operator_backfill, operator_challenge,
    operator_fetch_chunk, operator_inbox_status, operator_pool, operator_prove,
    operator_push_chunks, OperatorCmdError,
};
use crate::rpc::RpcClient;
use crate::uploads_cmd::{
    uploads_fetch_http, uploads_list, uploads_local, uploads_retrieve, uploads_status,
};
use crate::wallet_cmd::{
    resolve_wallet_path, wallet_address, wallet_backup_info, wallet_balance, wallet_claim,
    wallet_new, wallet_restore, wallet_scan, wallet_send, wallet_status, wallet_upload,
    WalletCmdError,
};

/// CLI parse or RPC failure.
#[derive(Debug, thiserror::Error)]
pub enum CliError {
    /// Usage or unknown command.
    #[error("{0}")]
    Usage(String),
    /// Node JSON-RPC error.
    #[error("{0}")]
    Rpc(#[from] crate::rpc::RpcError),
    /// Wallet file / scan error.
    #[error("{0}")]
    Wallet(#[from] WalletCmdError),
    /// Storage operator command error.
    #[error("{0}")]
    Operator(#[from] OperatorCmdError),
}

#[path = "cli/parse.rs"]
mod parse;

use parse::{parse_args, ClaimsSub, Cmd, OperatorSub, UploadsSub, WalletSub, MFN_RPC_API_KEY};

/// Entry for the `mfn-cli` binary.
pub fn run_cli(args: impl IntoIterator<Item = String>) -> Result<(), CliError> {
    let argv: Vec<String> = args.into_iter().skip(1).collect();
    let parsed = parse_args(&argv)?;
    let mut client = RpcClient::new(&parsed.rpc_addr);
    if parsed.rpc_tor {
        client = client.with_tor(&parsed.tor_socks5);
    }
    if let Some(api_key) = parsed.rpc_api_key.clone().or_else(|| {
        std::env::var(MFN_RPC_API_KEY)
            .ok()
            .filter(|s| !s.is_empty())
    }) {
        client = client.with_api_key(api_key);
    }
    let global_wallet_path = parsed.wallet_path.clone();
    match parsed.cmd {
        Cmd::Status => {
            let status = client.get_status()?;
            println!(
                "{}",
                serde_json::to_string_pretty(&status).unwrap_or_else(|_| status.to_string())
            );
        }
        Cmd::Tip => {
            let tip = client.get_tip()?;
            let height = tip
                .tip_height
                .map(|h| h.to_string())
                .unwrap_or_else(|| "none".to_string());
            println!("tip_height={height}");
            println!("tip_id={}", tip.tip_id);
            println!("genesis_id={}", tip.genesis_id);
            println!("validator_count={}", tip.validator_count);
            println!("mempool_len={}", tip.mempool_len);
            println!("mempool_root={}", tip.mempool_root);
        }
        Cmd::Methods => {
            for name in client.list_methods()? {
                println!("{name}");
            }
        }
        Cmd::BlockHeader { height } => {
            let hdr = client.get_block_header(height)?;
            println!("height={}", hdr.height);
            println!("block_id={}", hdr.block_id);
            println!("header_hex={}", hdr.header_hex);
        }
        Cmd::Mempool => {
            let mp = client.get_mempool()?;
            println!("mempool_len={}", mp.mempool_len);
            for id in &mp.tx_ids {
                println!("tx_id={id}");
            }
        }
        Cmd::Raw {
            method,
            params_json,
        } => {
            let params: serde_json::Value = if let Some(s) = params_json {
                serde_json::from_str(&s)
                    .map_err(|e| CliError::Usage(format!("invalid --params JSON: {e}")))?
            } else {
                json!(null)
            };
            let result = client.call(&method, params)?;
            println!(
                "{}",
                serde_json::to_string_pretty(&result).unwrap_or_else(|_| { result.to_string() })
            );
        }
        Cmd::Claims { sub } => match sub {
            ClaimsSub::For {
                data_root_hex,
                json,
            } => claims_for(&mut client, &data_root_hex, json).map_err(CliError::Usage)?,
            ClaimsSub::Recent(params) => {
                claims_recent(&mut client, &params).map_err(CliError::Usage)?
            }
            ClaimsSub::ByPubkey(params) => {
                claims_by_pubkey(&mut client, &params).map_err(CliError::Usage)?
            }
            ClaimsSub::Roots(params) => {
                claims_roots(&mut client, &params).map_err(CliError::Usage)?
            }
        },
        Cmd::Uploads { sub } => match sub {
            UploadsSub::List(params) => {
                uploads_list(&mut client, &params).map_err(CliError::Usage)?
            }
            UploadsSub::Local(params) => {
                let path = resolve_wallet_path(global_wallet_path.as_deref());
                uploads_local(&path, params).map_err(CliError::Usage)?;
            }
            UploadsSub::Status(params) => {
                let path = resolve_wallet_path(global_wallet_path.as_deref());
                uploads_status(&path, &mut client, params).map_err(CliError::Usage)?;
            }
            UploadsSub::Retrieve {
                commitment_hash_hex,
                output_path,
                force,
            } => {
                let path = resolve_wallet_path(global_wallet_path.as_deref());
                uploads_retrieve(&path, &commitment_hash_hex, &output_path, force)
                    .map_err(CliError::Usage)?;
            }
            UploadsSub::FetchHttp {
                commitment_hash_hex,
                output_path,
                peers,
                params,
            } => {
                let path = resolve_wallet_path(global_wallet_path.as_deref());
                uploads_fetch_http(
                    &path,
                    &mut client,
                    &commitment_hash_hex,
                    &peers,
                    &output_path,
                    params,
                )
                .map_err(CliError::Usage)?;
            }
        },
        Cmd::Operator { sub } => match sub {
            OperatorSub::Challenge {
                commitment_hash_hex,
                params,
            } => operator_challenge(&mut client, &commitment_hash_hex, params)?,
            OperatorSub::Prove {
                commitment_hash_hex,
                data_path,
                params,
            } => {
                let wallet = if data_path.is_none() {
                    Some(resolve_wallet_path(global_wallet_path.as_deref()))
                } else {
                    None
                };
                let payout_wallet = resolve_wallet_path(global_wallet_path.as_deref());
                operator_prove(
                    &mut client,
                    &commitment_hash_hex,
                    data_path.as_deref(),
                    wallet.as_deref(),
                    &payout_wallet,
                    params,
                )?
            }
            OperatorSub::Pool(params) => operator_pool(&mut client, params)?,
            OperatorSub::Artifacts(params) => {
                let path = resolve_wallet_path(global_wallet_path.as_deref());
                operator_artifacts(&path, params)?;
            }
            OperatorSub::FetchChunk {
                commitment_hash_hex,
                chunk_index,
                peer,
                params,
            } => {
                let wallet = Some(resolve_wallet_path(global_wallet_path.as_deref()));
                operator_fetch_chunk(
                    &peer,
                    &commitment_hash_hex,
                    chunk_index,
                    wallet.as_deref(),
                    params,
                )?
            }
            OperatorSub::Backfill {
                commitment_hash_hex,
                peers,
                params,
            } => {
                let path = resolve_wallet_path(global_wallet_path.as_deref());
                operator_backfill(&mut client, &path, &commitment_hash_hex, &peers, params)?
            }
            OperatorSub::PushChunks {
                commitment_hash_hex,
                peers,
                params,
            } => {
                let path = resolve_wallet_path(global_wallet_path.as_deref());
                operator_push_chunks(&mut client, &path, &commitment_hash_hex, &peers, params)?
            }
            OperatorSub::InboxStatus {
                commitment_hash_hex,
                data_dir,
                params,
            } => operator_inbox_status(&mut client, &data_dir, &commitment_hash_hex, params)?,
            OperatorSub::AssembleInbox {
                commitment_hash_hex,
                data_dir,
                params,
            } => {
                let path = resolve_wallet_path(global_wallet_path.as_deref());
                operator_assemble_inbox(
                    &mut client,
                    &path,
                    &data_dir,
                    &commitment_hash_hex,
                    params,
                )?
            }
        },
        Cmd::Wallet {
            sub,
            wallet_path,
            force,
        } => {
            let path = resolve_wallet_path(wallet_path.as_deref());
            match sub {
                WalletSub::New => wallet_new(&path, force)?,
                WalletSub::Restore {
                    seed_hex,
                    key_derivation,
                } => wallet_restore(&path, &seed_hex, key_derivation, force)?,
                WalletSub::Address => wallet_address(&path)?,
                WalletSub::Scan(params) => wallet_scan(&path, &mut client, params)?,
                WalletSub::LightScan(ref params) => wallet_light_scan(&path, &mut client, params)?,
                WalletSub::Balance(params) => wallet_balance(&path, &mut client, params)?,
                WalletSub::Status(params) => wallet_status(&path, &mut client, params)?,
                WalletSub::BackupInfo(params) => wallet_backup_info(&path, params)?,
                WalletSub::Send(params) => wallet_send(&path, &mut client, &params)?,
                WalletSub::Upload(params) => wallet_upload(&path, &mut client, &params)?,
                WalletSub::Claim(params) => wallet_claim(&path, &mut client, &params)?,
                WalletSub::ExportTrustedSummary(ref params) => {
                    wallet_export_trusted_summary(&path, &mut client, params)?
                }
                WalletSub::ImportTrustedSummary(ref params) => {
                    wallet_import_trusted_summary(&path, params)?
                }
                WalletSub::ShowTrustedSummary(ref params) => {
                    wallet_show_trusted_summary(&path, params)?
                }
                WalletSub::CompareTrustedSummary(ref params) => {
                    wallet_compare_trusted_summary(&path, params)?
                }
            }
        }
    }
    Ok(())
}

/// Binary exit wrapper.
pub fn cli_main() -> ExitCode {
    match run_cli(std::env::args()) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("{e}");
            ExitCode::from(1)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rpc::DEFAULT_RPC_ADDR;
    use crate::wallet_store::KeyDerivation;

    #[test]
    fn parse_tip_defaults_rpc() {
        let p = parse_args(&["tip".into()]).unwrap();
        assert_eq!(p.rpc_addr, DEFAULT_RPC_ADDR);
        assert_eq!(p.cmd, Cmd::Tip);
    }

    #[test]
    fn parse_status_defaults_rpc() {
        let p = parse_args(&["status".into()]).unwrap();
        assert_eq!(p.rpc_addr, DEFAULT_RPC_ADDR);
        assert_eq!(p.cmd, Cmd::Status);
    }

    #[test]
    fn parse_block_header_with_rpc() {
        let p = parse_args(&[
            "--rpc".into(),
            "127.0.0.1:19999".into(),
            "block-header".into(),
            "3".into(),
        ])
        .unwrap();
        assert_eq!(p.rpc_addr, "127.0.0.1:19999");
        assert_eq!(p.cmd, Cmd::BlockHeader { height: 3 });
    }

    #[test]
    fn parse_rpc_api_key() {
        let p = parse_args(&["--rpc-api-key".into(), "secret".into(), "mempool".into()]).unwrap();
        assert_eq!(p.rpc_api_key.as_deref(), Some("secret"));
        assert_eq!(p.cmd, Cmd::Mempool);
    }

    #[test]
    fn parse_tor_flags() {
        let p = parse_args(&[
            "--tor".into(),
            "--tor-socks5".into(),
            "127.0.0.1:9150".into(),
            "--rpc".into(),
            "abc123.onion:18731".into(),
            "tip".into(),
        ])
        .unwrap();
        assert!(p.rpc_tor);
        assert_eq!(p.tor_socks5, "127.0.0.1:9150");
        assert_eq!(p.rpc_addr, "abc123.onion:18731");
        assert_eq!(p.cmd, Cmd::Tip);
    }

    #[test]
    fn parse_tor_defaults_socks5() {
        let p = parse_args(&["--tor".into(), "status".into()]).unwrap();
        assert!(p.rpc_tor);
        assert_eq!(p.tor_socks5, mfn_net::DEFAULT_TOR_SOCKS5);
    }

    #[test]
    fn parse_wallet_balance_with_wallet_path() {
        let p = parse_args(&[
            "--wallet".into(),
            "/tmp/alice.json".into(),
            "wallet".into(),
            "balance".into(),
        ])
        .unwrap();
        match p.cmd {
            Cmd::Wallet {
                sub: WalletSub::Balance(params),
                wallet_path,
                force,
            } => {
                assert_eq!(wallet_path.as_deref(), Some("/tmp/alice.json"));
                assert!(!params.json);
                assert!(!force);
            }
            _ => panic!("expected wallet balance"),
        }
    }

    #[test]
    fn parse_wallet_scan_json() {
        let p = parse_args(&["wallet".into(), "scan".into(), "--json".into()]).unwrap();
        match p.cmd {
            Cmd::Wallet {
                sub: WalletSub::Scan(params),
                ..
            } => assert!(params.json),
            _ => panic!("expected wallet scan"),
        }
    }

    #[test]
    fn parse_wallet_balance_json() {
        let p = parse_args(&["wallet".into(), "balance".into(), "--json".into()]).unwrap();
        match p.cmd {
            Cmd::Wallet {
                sub: WalletSub::Balance(params),
                ..
            } => assert!(params.json),
            _ => panic!("expected wallet balance"),
        }
    }

    #[test]
    fn parse_wallet_status_json() {
        let p = parse_args(&["wallet".into(), "status".into(), "--json".into()]).unwrap();
        match p.cmd {
            Cmd::Wallet {
                sub: WalletSub::Status(params),
                ..
            } => assert!(params.json),
            _ => panic!("expected wallet status"),
        }
    }

    #[test]
    fn parse_wallet_backup_info_with_wallet_path() {
        let p = parse_args(&[
            "--wallet".into(),
            "/tmp/alice.json".into(),
            "wallet".into(),
            "backup-info".into(),
        ])
        .unwrap();
        match p.cmd {
            Cmd::Wallet {
                sub: WalletSub::BackupInfo(params),
                wallet_path,
                force,
            } => {
                assert_eq!(wallet_path.as_deref(), Some("/tmp/alice.json"));
                assert!(!params.json);
                assert!(!force);
            }
            _ => panic!("expected wallet backup-info"),
        }
    }

    #[test]
    fn parse_wallet_backup_info_json() {
        let p = parse_args(&["wallet".into(), "backup-info".into(), "--json".into()]).unwrap();
        match p.cmd {
            Cmd::Wallet {
                sub: WalletSub::BackupInfo(params),
                ..
            } => assert!(params.json),
            _ => panic!("expected wallet backup-info"),
        }
    }

    #[test]
    fn parse_wallet_send_json() {
        let view = "11".repeat(32);
        let spend = "22".repeat(32);
        let p = parse_args(&[
            "wallet".into(),
            "send".into(),
            view.clone(),
            spend.clone(),
            "1000".into(),
            "--fee".into(),
            "10".into(),
            "--json".into(),
        ])
        .unwrap();
        match p.cmd {
            Cmd::Wallet {
                sub: WalletSub::Send(params),
                ..
            } => {
                assert_eq!(params.to_view_hex, view);
                assert_eq!(params.to_spend_hex, spend);
                assert_eq!(params.amount, 1000);
                assert_eq!(params.fee, 10);
                assert!(params.json);
            }
            _ => panic!("expected wallet send"),
        }
    }

    #[test]
    fn parse_wallet_send_accepts_prefixed_address() {
        let address = crate::wallet_cmd::encode_wallet_address_hex([0x11; 32], [0x22; 32]);
        let p = parse_args(&[
            "wallet".into(),
            "send".into(),
            address,
            "1000".into(),
            "--fee".into(),
            "10".into(),
            "--json".into(),
        ])
        .unwrap();

        match p.cmd {
            Cmd::Wallet {
                sub: WalletSub::Send(params),
                ..
            } => {
                assert_eq!(params.to_view_hex, "11".repeat(32));
                assert_eq!(params.to_spend_hex, "22".repeat(32));
                assert_eq!(params.amount, 1000);
                assert_eq!(params.fee, 10);
                assert!(params.json);
            }
            _ => panic!("expected wallet send"),
        }
    }

    #[test]
    fn parse_wallet_claim_json() {
        let data_root = "33".repeat(32);
        let commit_hash = "44".repeat(32);
        let p = parse_args(&[
            "wallet".into(),
            "claim".into(),
            data_root.clone(),
            "--commit-hash".into(),
            commit_hash.clone(),
            "--message".into(),
            "hello permanence".into(),
            "--json".into(),
        ])
        .unwrap();
        match p.cmd {
            Cmd::Wallet {
                sub: WalletSub::Claim(params),
                ..
            } => {
                assert_eq!(params.data_root_hex, data_root);
                assert_eq!(params.commit_hash_hex, Some(commit_hash));
                assert_eq!(params.message, b"hello permanence");
                assert!(params.json);
            }
            _ => panic!("expected wallet claim"),
        }
    }

    #[test]
    fn parse_wallet_upload_json() {
        let p = parse_args(&[
            "wallet".into(),
            "upload".into(),
            "document.bin".into(),
            "--replication".into(),
            "3".into(),
            "--json".into(),
        ])
        .unwrap();
        match p.cmd {
            Cmd::Wallet {
                sub: WalletSub::Upload(params),
                ..
            } => {
                assert_eq!(params.file_path, std::path::PathBuf::from("document.bin"));
                assert_eq!(params.replication, 3);
                assert!(params.json);
            }
            _ => panic!("expected wallet upload"),
        }
    }

    #[test]
    fn parse_wallet_restore_with_key_derivation() {
        let seed = "44".repeat(32);
        let p = parse_args(&[
            "--wallet".into(),
            "faucet.json".into(),
            "--force".into(),
            "wallet".into(),
            "restore".into(),
            seed.clone(),
            "--key-derivation".into(),
            "payout_stealth_v1".into(),
        ])
        .unwrap();
        match p.cmd {
            Cmd::Wallet {
                sub:
                    WalletSub::Restore {
                        seed_hex,
                        key_derivation,
                    },
                wallet_path,
                force,
            } => {
                assert_eq!(seed_hex, seed);
                assert_eq!(key_derivation, KeyDerivation::PayoutStealthV1);
                assert_eq!(wallet_path.as_deref(), Some("faucet.json"));
                assert!(force);
            }
            _ => panic!("expected wallet restore"),
        }
    }

    #[test]
    fn parse_wallet_light_scan_import_trusted_summary() {
        let p = parse_args(&[
            "wallet".into(),
            "light-scan".into(),
            "--import-trusted-summary".into(),
            "trusted.json".into(),
        ])
        .unwrap();
        match p.cmd {
            Cmd::Wallet {
                sub: WalletSub::LightScan(params),
                ..
            } => {
                assert_eq!(
                    params.import_trusted_summary_path,
                    Some(std::path::PathBuf::from("trusted.json"))
                );
                assert!(params.trusted_summary_path.is_none());
            }
            _ => panic!("expected wallet light-scan"),
        }
    }

    #[test]
    fn parse_wallet_light_scan_quorum_flags() {
        let p = parse_args(&[
            "wallet".into(),
            "light-scan".into(),
            "--quorum-rpc".into(),
            "127.0.0.1:18732,127.0.0.1:18733".into(),
            "--quorum-p2p".into(),
            "127.0.0.1:18740".into(),
        ])
        .unwrap();
        match p.cmd {
            Cmd::Wallet {
                sub: WalletSub::LightScan(params),
                ..
            } => {
                assert_eq!(params.quorum_rpc_addrs.len(), 2);
                assert_eq!(params.quorum_p2p_peers, vec!["127.0.0.1:18740".to_string()]);
            }
            _ => panic!("expected wallet light-scan"),
        }
    }

    #[test]
    fn parse_wallet_light_scan_max_height() {
        let p = parse_args(&[
            "wallet".into(),
            "light-scan".into(),
            "--max-height".into(),
            "1".into(),
            "--pin-trusted-summary".into(),
        ])
        .unwrap();
        match p.cmd {
            Cmd::Wallet {
                sub: WalletSub::LightScan(params),
                ..
            } => {
                assert_eq!(params.max_height, Some(1));
                assert!(params.pin_trusted_summary);
            }
            _ => panic!("expected wallet light-scan"),
        }
    }

    #[test]
    fn parse_claims_for_subcommand() {
        let p = parse_args(&["claims".into(), "for".into(), "aa".repeat(32)]).unwrap();
        match p.cmd {
            Cmd::Claims {
                sub:
                    ClaimsSub::For {
                        data_root_hex,
                        json,
                    },
            } => {
                assert_eq!(data_root_hex.len(), 64);
                assert!(!json);
            }
            _ => panic!("expected claims for"),
        }
    }

    #[test]
    fn parse_claims_for_json() {
        let p = parse_args(&[
            "claims".into(),
            "for".into(),
            "aa".repeat(32),
            "--json".into(),
        ])
        .unwrap();
        match p.cmd {
            Cmd::Claims {
                sub:
                    ClaimsSub::For {
                        data_root_hex,
                        json,
                    },
            } => {
                assert_eq!(data_root_hex.len(), 64);
                assert!(json);
            }
            _ => panic!("expected claims for"),
        }
    }

    #[test]
    fn parse_claims_recent_limit() {
        let p = parse_args(&[
            "claims".into(),
            "recent".into(),
            "--limit".into(),
            "10".into(),
        ])
        .unwrap();
        match p.cmd {
            Cmd::Claims {
                sub: ClaimsSub::Recent(params),
            } => {
                assert_eq!(params.limit, Some(10));
                assert!(!params.json);
            }
            _ => panic!("expected claims recent"),
        }
    }

    #[test]
    fn parse_claims_by_pubkey_json() {
        let p = parse_args(&[
            "claims".into(),
            "by-pubkey".into(),
            "bb".repeat(32),
            "--limit".into(),
            "5".into(),
            "--json".into(),
        ])
        .unwrap();
        match p.cmd {
            Cmd::Claims {
                sub: ClaimsSub::ByPubkey(params),
            } => {
                assert_eq!(params.claim_pubkey_hex.len(), 64);
                assert_eq!(params.limit, Some(5));
                assert!(params.json);
            }
            _ => panic!("expected claims by-pubkey"),
        }
    }

    #[test]
    fn parse_uploads_list_include_claims() {
        let p = parse_args(&["uploads".into(), "list".into(), "--include-claims".into()]).unwrap();
        match p.cmd {
            Cmd::Uploads {
                sub: UploadsSub::List(params),
            } => {
                assert!(params.include_claims);
                assert!(!params.json);
            }
            _ => panic!("expected uploads list"),
        }
    }

    #[test]
    fn parse_uploads_list_json() {
        let p = parse_args(&[
            "uploads".into(),
            "list".into(),
            "--limit".into(),
            "5".into(),
            "--include-claims".into(),
            "--json".into(),
        ])
        .unwrap();
        match p.cmd {
            Cmd::Uploads {
                sub: UploadsSub::List(params),
            } => {
                assert_eq!(params.limit, Some(5));
                assert!(params.include_claims);
                assert!(params.json);
            }
            _ => panic!("expected uploads list"),
        }
    }

    #[test]
    fn parse_uploads_local_subcommand() {
        let p = parse_args(&["uploads".into(), "local".into()]).unwrap();
        match p.cmd {
            Cmd::Uploads {
                sub: UploadsSub::Local(params),
            } => assert!(!params.json),
            _ => panic!("expected uploads local"),
        }
    }

    #[test]
    fn parse_uploads_local_json() {
        let p = parse_args(&["uploads".into(), "local".into(), "--json".into()]).unwrap();
        match p.cmd {
            Cmd::Uploads {
                sub: UploadsSub::Local(params),
            } => assert!(params.json),
            _ => panic!("expected uploads local"),
        }
    }

    #[test]
    fn parse_uploads_status_subcommand() {
        let p = parse_args(&["uploads".into(), "status".into()]).unwrap();
        match p.cmd {
            Cmd::Uploads {
                sub: UploadsSub::Status(params),
            } => assert!(!params.json),
            _ => panic!("expected uploads status"),
        }
    }

    #[test]
    fn parse_uploads_status_json() {
        let p = parse_args(&["uploads".into(), "status".into(), "--json".into()]).unwrap();
        match p.cmd {
            Cmd::Uploads {
                sub: UploadsSub::Status(params),
            } => assert!(params.json),
            _ => panic!("expected uploads status"),
        }
    }

    #[test]
    fn parse_uploads_retrieve_subcommand() {
        let h = "56".repeat(32);
        let p = parse_args(&[
            "uploads".into(),
            "retrieve".into(),
            h.clone(),
            "out.bin".into(),
            "replace".into(),
        ])
        .unwrap();
        match p.cmd {
            Cmd::Uploads {
                sub:
                    UploadsSub::Retrieve {
                        commitment_hash_hex,
                        output_path,
                        force,
                    },
            } => {
                assert_eq!(commitment_hash_hex, h);
                assert_eq!(output_path, std::path::PathBuf::from("out.bin"));
                assert!(force);
            }
            _ => panic!("expected uploads retrieve"),
        }

        let bad = parse_args(&[
            "uploads".into(),
            "retrieve".into(),
            "aa".repeat(32),
            "out.bin".into(),
            "overwrite".into(),
        ])
        .expect_err("bad modifier");
        assert!(bad.to_string().contains("expected `replace`"));
    }

    #[test]
    fn parse_uploads_fetch_http_subcommand() {
        let h = "78".repeat(32);
        let p = parse_args(&[
            "uploads".into(),
            "fetch-http".into(),
            h.clone(),
            "restore.bin".into(),
            "127.0.0.1:18780".into(),
            "127.0.0.1:18781".into(),
            "replace".into(),
        ])
        .unwrap();
        match p.cmd {
            Cmd::Uploads {
                sub:
                    UploadsSub::FetchHttp {
                        commitment_hash_hex,
                        output_path,
                        peers,
                        params,
                    },
            } => {
                assert_eq!(commitment_hash_hex, h);
                assert_eq!(output_path, std::path::PathBuf::from("restore.bin"));
                assert_eq!(peers.len(), 2);
                assert!(params.force);
                assert!(!params.json);
            }
            _ => panic!("expected uploads fetch-http"),
        }
    }

    #[test]
    fn parse_uploads_fetch_http_json() {
        let h = "78".repeat(32);
        let p = parse_args(&[
            "uploads".into(),
            "fetch-http".into(),
            h.clone(),
            "restore.bin".into(),
            "127.0.0.1:18780".into(),
            "--json".into(),
            "replace".into(),
        ])
        .unwrap();
        match p.cmd {
            Cmd::Uploads {
                sub:
                    UploadsSub::FetchHttp {
                        commitment_hash_hex,
                        peers,
                        params,
                        ..
                    },
            } => {
                assert_eq!(commitment_hash_hex, h);
                assert_eq!(peers, vec!["127.0.0.1:18780".to_string()]);
                assert!(params.force);
                assert!(params.json);
            }
            _ => panic!("expected uploads fetch-http"),
        }
    }

    #[test]
    fn parse_operator_artifacts_subcommand() {
        let p = parse_args(&["operator".into(), "artifacts".into()]).unwrap();
        match p.cmd {
            Cmd::Operator {
                sub: OperatorSub::Artifacts(params),
            } => assert!(!params.json),
            _ => panic!("expected operator artifacts"),
        }
    }

    #[test]
    fn parse_operator_artifacts_json() {
        let p = parse_args(&["operator".into(), "artifacts".into(), "--json".into()]).unwrap();
        match p.cmd {
            Cmd::Operator {
                sub: OperatorSub::Artifacts(params),
            } => assert!(params.json),
            _ => panic!("expected operator artifacts"),
        }
    }

    #[test]
    fn parse_operator_challenge_json() {
        let h = "ab".repeat(32);
        let p = parse_args(&[
            "operator".into(),
            "challenge".into(),
            h.clone(),
            "--json".into(),
        ])
        .unwrap();
        match p.cmd {
            Cmd::Operator {
                sub:
                    OperatorSub::Challenge {
                        commitment_hash_hex,
                        params,
                    },
            } => {
                assert_eq!(commitment_hash_hex, h);
                assert!(params.json);
            }
            _ => panic!("expected operator challenge"),
        }
    }

    #[test]
    fn parse_operator_pool_json() {
        let p = parse_args(&["operator".into(), "pool".into(), "--json".into()]).unwrap();
        match p.cmd {
            Cmd::Operator {
                sub: OperatorSub::Pool(params),
            } => assert!(params.json),
            _ => panic!("expected operator pool"),
        }
    }

    #[test]
    fn parse_operator_prove_json_with_file() {
        let h = "cd".repeat(32);
        let p = parse_args(&[
            "operator".into(),
            "prove".into(),
            h.clone(),
            "payload.bin".into(),
            "--json".into(),
        ])
        .unwrap();
        match p.cmd {
            Cmd::Operator {
                sub:
                    OperatorSub::Prove {
                        commitment_hash_hex,
                        data_path,
                        params,
                    },
            } => {
                assert_eq!(commitment_hash_hex, h);
                assert_eq!(data_path, Some(std::path::PathBuf::from("payload.bin")));
                assert!(params.json);
            }
            _ => panic!("expected operator prove"),
        }
    }

    #[test]
    fn parse_operator_backfill_subcommand() {
        let h = "cd".repeat(32);
        let p = parse_args(&[
            "operator".into(),
            "backfill".into(),
            h.clone(),
            "127.0.0.1:18780".into(),
        ])
        .unwrap();
        match p.cmd {
            Cmd::Operator {
                sub:
                    OperatorSub::Backfill {
                        commitment_hash_hex,
                        peers,
                        params,
                    },
            } => {
                assert_eq!(commitment_hash_hex, h);
                assert_eq!(peers, vec!["127.0.0.1:18780".to_string()]);
                assert!(!params.force);
                assert!(!params.json);
            }
            _ => panic!("expected operator backfill"),
        }
        let p_quorum = parse_args(&[
            "operator".into(),
            "backfill".into(),
            h.clone(),
            "127.0.0.1:18780".into(),
            "127.0.0.1:18781".into(),
        ])
        .unwrap();
        match p_quorum.cmd {
            Cmd::Operator {
                sub: OperatorSub::Backfill { peers, .. },
            } => assert_eq!(peers.len(), 2),
            _ => panic!("expected backfill quorum peers"),
        }
        let p2 = parse_args(&[
            "operator".into(),
            "backfill".into(),
            h,
            "127.0.0.1:18780".into(),
            "replace".into(),
        ])
        .unwrap();
        match p2.cmd {
            Cmd::Operator {
                sub: OperatorSub::Backfill { params, .. },
            } => assert!(params.force),
            _ => panic!("expected backfill replace"),
        }
    }

    #[test]
    fn parse_operator_backfill_json() {
        let h = "cd".repeat(32);
        let p = parse_args(&[
            "operator".into(),
            "backfill".into(),
            h.clone(),
            "127.0.0.1:18780".into(),
            "--json".into(),
            "replace".into(),
        ])
        .unwrap();
        match p.cmd {
            Cmd::Operator {
                sub:
                    OperatorSub::Backfill {
                        commitment_hash_hex,
                        peers,
                        params,
                    },
            } => {
                assert_eq!(commitment_hash_hex, h);
                assert_eq!(peers, vec!["127.0.0.1:18780".to_string()]);
                assert!(params.force);
                assert!(params.json);
            }
            _ => panic!("expected operator backfill"),
        }
    }

    #[test]
    fn parse_operator_assemble_inbox_subcommand() {
        let h = "12".repeat(32);
        let p = parse_args(&[
            "operator".into(),
            "assemble-inbox".into(),
            h.clone(),
            "/tmp/node".into(),
            "replace".into(),
        ])
        .unwrap();
        match p.cmd {
            Cmd::Operator {
                sub:
                    OperatorSub::AssembleInbox {
                        commitment_hash_hex,
                        data_dir,
                        params,
                    },
            } => {
                assert_eq!(commitment_hash_hex, h);
                assert_eq!(data_dir, std::path::PathBuf::from("/tmp/node"));
                assert!(params.force);
                assert!(!params.json);
            }
            _ => panic!("expected assemble-inbox"),
        }
    }

    #[test]
    fn parse_operator_assemble_inbox_json() {
        let h = "12".repeat(32);
        let p = parse_args(&[
            "operator".into(),
            "assemble-inbox".into(),
            h.clone(),
            "/tmp/node".into(),
            "--json".into(),
            "replace".into(),
        ])
        .unwrap();
        match p.cmd {
            Cmd::Operator {
                sub:
                    OperatorSub::AssembleInbox {
                        commitment_hash_hex,
                        data_dir,
                        params,
                    },
            } => {
                assert_eq!(commitment_hash_hex, h);
                assert_eq!(data_dir, std::path::PathBuf::from("/tmp/node"));
                assert!(params.force);
                assert!(params.json);
            }
            _ => panic!("expected assemble-inbox"),
        }
    }

    #[test]
    fn parse_operator_inbox_status_subcommand() {
        let h = "34".repeat(32);
        let p = parse_args(&[
            "operator".into(),
            "inbox-status".into(),
            h.clone(),
            "C:\\node".into(),
        ])
        .unwrap();
        match p.cmd {
            Cmd::Operator {
                sub:
                    OperatorSub::InboxStatus {
                        commitment_hash_hex,
                        data_dir,
                        params,
                    },
            } => {
                assert_eq!(commitment_hash_hex, h);
                assert_eq!(data_dir, std::path::PathBuf::from("C:\\node"));
                assert!(!params.json);
            }
            _ => panic!("expected inbox-status"),
        }
    }

    #[test]
    fn parse_operator_inbox_status_json() {
        let h = "34".repeat(32);
        let p = parse_args(&[
            "operator".into(),
            "inbox-status".into(),
            h.clone(),
            "/tmp/node".into(),
            "--json".into(),
        ])
        .unwrap();
        match p.cmd {
            Cmd::Operator {
                sub:
                    OperatorSub::InboxStatus {
                        commitment_hash_hex,
                        data_dir,
                        params,
                    },
            } => {
                assert_eq!(commitment_hash_hex, h);
                assert_eq!(data_dir, std::path::PathBuf::from("/tmp/node"));
                assert!(params.json);
            }
            _ => panic!("expected inbox-status"),
        }
    }

    #[test]
    fn parse_operator_push_chunks_subcommand() {
        let h = "ef".repeat(32);
        let p = parse_args(&[
            "operator".into(),
            "push-chunks".into(),
            h.clone(),
            "127.0.0.1:18731".into(),
            "127.0.0.1:18732".into(),
        ])
        .unwrap();
        match p.cmd {
            Cmd::Operator {
                sub:
                    OperatorSub::PushChunks {
                        commitment_hash_hex,
                        peers,
                        params,
                    },
            } => {
                assert_eq!(commitment_hash_hex, h);
                assert_eq!(peers.len(), 2);
                assert!(!params.json);
            }
            _ => panic!("expected operator push-chunks"),
        }
    }

    #[test]
    fn parse_operator_push_chunks_json() {
        let h = "ef".repeat(32);
        let p = parse_args(&[
            "operator".into(),
            "push-chunks".into(),
            h.clone(),
            "127.0.0.1:18731".into(),
            "--json".into(),
        ])
        .unwrap();
        match p.cmd {
            Cmd::Operator {
                sub:
                    OperatorSub::PushChunks {
                        commitment_hash_hex,
                        peers,
                        params,
                    },
            } => {
                assert_eq!(commitment_hash_hex, h);
                assert_eq!(peers, vec!["127.0.0.1:18731".to_string()]);
                assert!(params.json);
            }
            _ => panic!("expected operator push-chunks"),
        }
    }

    #[test]
    fn parse_operator_fetch_chunk_subcommand() {
        let h = "ab".repeat(32);
        let p = parse_args(&[
            "operator".into(),
            "fetch-chunk".into(),
            h.clone(),
            "0".into(),
            "127.0.0.1:18780".into(),
        ])
        .unwrap();
        match p.cmd {
            Cmd::Operator {
                sub:
                    OperatorSub::FetchChunk {
                        commitment_hash_hex,
                        chunk_index,
                        peer,
                        params,
                    },
            } => {
                assert_eq!(commitment_hash_hex, h);
                assert_eq!(chunk_index, 0);
                assert_eq!(peer, "127.0.0.1:18780");
                assert!(!params.json);
            }
            _ => panic!("expected operator fetch-chunk"),
        }
    }

    #[test]
    fn parse_operator_fetch_chunk_json() {
        let h = "ab".repeat(32);
        let p = parse_args(&[
            "operator".into(),
            "fetch-chunk".into(),
            h.clone(),
            "0".into(),
            "127.0.0.1:18780".into(),
            "--json".into(),
        ])
        .unwrap();
        match p.cmd {
            Cmd::Operator {
                sub:
                    OperatorSub::FetchChunk {
                        commitment_hash_hex,
                        chunk_index,
                        peer,
                        params,
                    },
            } => {
                assert_eq!(commitment_hash_hex, h);
                assert_eq!(chunk_index, 0);
                assert_eq!(peer, "127.0.0.1:18780");
                assert!(params.json);
            }
            _ => panic!("expected operator fetch-chunk"),
        }
    }
}
