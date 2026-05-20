//! `mfn-cli` command-line driver (**M3.0** / **M3.1**).

use std::process::ExitCode;

use serde_json::json;

use crate::claims_cmd::{
    claims_by_pubkey, claims_for, claims_recent, claims_roots, ClaimsListParams,
};
use crate::light_subjectivity::{
    wallet_compare_trusted_summary, wallet_export_trusted_summary, wallet_import_trusted_summary,
    wallet_show_trusted_summary, CompareTrustedSummaryParams, ExportTrustedSummaryParams,
    ImportTrustedSummaryParams, ShowTrustedSummaryParams,
};
use crate::light_wallet::{wallet_light_scan, LightScanParams};
use crate::operator_cmd::{
    operator_artifacts, operator_challenge, operator_fetch_chunk, operator_pool, operator_prove,
    OperatorCmdError,
};
use crate::rpc::{RpcClient, DEFAULT_RPC_ADDR};
use crate::uploads_cmd::{uploads_list, uploads_local, uploads_status, UploadsListParams};
use crate::wallet_cmd::{
    resolve_wallet_path, wallet_address, wallet_balance, wallet_claim, wallet_new, wallet_scan,
    wallet_send, wallet_status, wallet_upload, ClaimParams, SendParams, UploadParams,
    WalletCmdError, DEFAULT_CLAIM_FEE, DEFAULT_RING_SIZE, DEFAULT_TRANSFER_FEE,
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

/// Entry for the `mfn-cli` binary.
pub fn run_cli(args: impl IntoIterator<Item = String>) -> Result<(), CliError> {
    let argv: Vec<String> = args.into_iter().skip(1).collect();
    let parsed = parse_args(&argv)?;
    let mut client = RpcClient::new(&parsed.rpc_addr);
    let global_wallet_path = parsed.wallet_path.clone();
    match parsed.cmd {
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
            ClaimsSub::For { data_root_hex } => {
                claims_for(&mut client, &data_root_hex).map_err(CliError::Usage)?
            }
            ClaimsSub::Recent(params) => {
                claims_recent(&mut client, &params).map_err(CliError::Usage)?
            }
            ClaimsSub::ByPubkey {
                claim_pubkey_hex,
                limit,
            } => {
                claims_by_pubkey(&mut client, &claim_pubkey_hex, limit).map_err(CliError::Usage)?
            }
            ClaimsSub::Roots(params) => {
                claims_roots(&mut client, &params).map_err(CliError::Usage)?
            }
        },
        Cmd::Uploads { sub } => match sub {
            UploadsSub::List(params) => {
                uploads_list(&mut client, &params).map_err(CliError::Usage)?
            }
            UploadsSub::Local => {
                let path = resolve_wallet_path(global_wallet_path.as_deref());
                uploads_local(&path).map_err(CliError::Usage)?;
            }
            UploadsSub::Status => {
                let path = resolve_wallet_path(global_wallet_path.as_deref());
                uploads_status(&path, &mut client).map_err(CliError::Usage)?;
            }
        },
        Cmd::Operator { sub } => match sub {
            OperatorSub::Challenge {
                commitment_hash_hex,
            } => operator_challenge(&mut client, &commitment_hash_hex)?,
            OperatorSub::Prove {
                commitment_hash_hex,
                data_path,
            } => {
                let wallet = if data_path.is_none() {
                    Some(resolve_wallet_path(global_wallet_path.as_deref()))
                } else {
                    None
                };
                operator_prove(
                    &mut client,
                    &commitment_hash_hex,
                    data_path.as_deref(),
                    wallet.as_deref(),
                )?
            }
            OperatorSub::Pool => operator_pool(&mut client)?,
            OperatorSub::Artifacts => {
                let path = resolve_wallet_path(global_wallet_path.as_deref());
                operator_artifacts(&path)?;
            }
            OperatorSub::FetchChunk {
                commitment_hash_hex,
                chunk_index,
                peer,
            } => {
                let wallet = Some(resolve_wallet_path(global_wallet_path.as_deref()));
                operator_fetch_chunk(&peer, &commitment_hash_hex, chunk_index, wallet.as_deref())?
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
                WalletSub::Address => wallet_address(&path)?,
                WalletSub::Scan => wallet_scan(&path, &mut client)?,
                WalletSub::LightScan(ref params) => wallet_light_scan(&path, &mut client, params)?,
                WalletSub::Balance => wallet_balance(&path, &mut client)?,
                WalletSub::Status => wallet_status(&path, &mut client)?,
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

#[derive(Debug, Clone, PartialEq, Eq)]
enum Cmd {
    Tip,
    Methods,
    BlockHeader {
        height: u32,
    },
    Mempool,
    Raw {
        method: String,
        params_json: Option<String>,
    },
    Wallet {
        sub: WalletSub,
        wallet_path: Option<String>,
        force: bool,
    },
    Claims {
        sub: ClaimsSub,
    },
    Uploads {
        sub: UploadsSub,
    },
    Operator {
        sub: OperatorSub,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum ClaimsSub {
    For {
        data_root_hex: String,
    },
    Recent(ClaimsListParams),
    ByPubkey {
        claim_pubkey_hex: String,
        limit: Option<u64>,
    },
    Roots(ClaimsListParams),
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum UploadsSub {
    List(UploadsListParams),
    Local,
    Status,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum OperatorSub {
    Challenge {
        commitment_hash_hex: String,
    },
    Prove {
        commitment_hash_hex: String,
        data_path: Option<std::path::PathBuf>,
    },
    Pool,
    Artifacts,
    FetchChunk {
        commitment_hash_hex: String,
        chunk_index: u32,
        peer: String,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum WalletSub {
    New,
    Address,
    Scan,
    LightScan(LightScanParams),
    Balance,
    Status,
    Send(SendParams),
    Upload(UploadParams),
    Claim(ClaimParams),
    ExportTrustedSummary(ExportTrustedSummaryParams),
    ImportTrustedSummary(ImportTrustedSummaryParams),
    ShowTrustedSummary(ShowTrustedSummaryParams),
    CompareTrustedSummary(CompareTrustedSummaryParams),
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct Parsed {
    rpc_addr: String,
    wallet_path: Option<String>,
    cmd: Cmd,
}

fn usage() -> &'static str {
    "usage: mfn-cli [--rpc HOST:PORT] [--wallet PATH] <COMMAND> [ARGS]\n\
     \n\
     options:\n\
       --rpc ADDR:PORT   mfnd JSON-RPC listen address (default 127.0.0.1:18731)\n\
       --wallet PATH     wallet JSON file (default wallet.json)\n\
       --params JSON     only for `call`: JSON-RPC params object/array (default null)\n\
       --force           only for `wallet new`: overwrite existing wallet file\n\
     \n\
     commands:\n\
       tip               print chain tip (get_tip)\n\
       methods           list JSON-RPC methods (list_methods)\n\
       block-header H    block header at height H (get_block_header)\n\
       mempool           list mempool tx ids (get_mempool)\n\
       call METHOD       arbitrary JSON-RPC call; prints pretty JSON result\n\
       wallet new        create wallet.json with a fresh 32-byte seed\n\
       wallet address    print view/spend public keys from wallet file\n\
       wallet scan       scan full blocks from node tip (get_block)\n\
       wallet light-scan verify headers + evolution, scan txs only (**M3.11**)\n\
                         options: --quorum-rpc HOST:PORT,... --quorum-p2p HOST:PORT,...\n\
                         --trusted-summary FILE --import-trusted-summary FILE\n\
                         --pin-trusted-summary --reset-trusted-summary --max-height N\n\
       wallet balance    scan chain and print balance\n\
       wallet status     print cached balance vs node tip (no block fetch)\n\
       wallet send VIEW_HEX SPEND_HEX AMOUNT  build CLSAG transfer and submit_tx\n\
                         options: --fee N --ring-size N --extra HEX\n\
       wallet upload FILE                 anchor FILE on-chain (storage upload + submit_tx)\n\
                         options: --replication N --fee N --anchor-value N --ring-size N\n\
                         --anchor-view HEX --anchor-spend HEX --extra HEX\n\
                         --message TEXT | --message-hex HEX (MFCL claim bound to upload)\n\
       wallet claim DATA_ROOT_HEX         publish MFCL authorship claim + submit_tx\n\
                         options: --message TEXT | --message-hex HEX --commit-hash HEX\n\
                         --fee N --ring-size N\n\
       wallet export-trusted-summary      write weak-subjectivity summary JSON (**M3.14**)\n\
                         options: --out FILE --height N --pin --from-wallet-checkpoint\n\
       wallet import-trusted-summary FILE pin weak-subjectivity summary into wallet (**M3.15**)\n\
                         options: --verify-checkpoint (match wallet light_checkpoint_hex)\n\
       wallet show-trusted-summary        print pinned or checkpoint-derived summary (**M3.16**)\n\
                         options: --from-checkpoint --json\n\
       wallet compare-trusted-summary     compare summary JSON files or vs wallet (**M3.16**)\n\
                         FILE [FILE2]  or  FILE --against-checkpoint\n\
       claims for DATA_ROOT_HEX           authorship claims for a content data_root\n\
       claims recent                      recent claims chain-wide (list_recent_claims)\n\
       claims by-pubkey PUBKEY_HEX        claims by claiming public key\n\
       claims roots                       data_roots that have claims\n\
                         options for recent/roots: --limit N --offset N\n\
                         options for by-pubkey: --limit N\n\
       uploads list                       recent storage uploads (list_recent_uploads)\n\
                         options: --limit N --offset N --include-claims\n\
       uploads local                      list persisted upload artifacts for --wallet (**M3.25**)\n\
       uploads status                     reconcile local artifacts vs chain upload index (**M3.26**)\n\
       operator challenge COMMIT_HASH_HEX  next-block SPoRA challenge (get_storage_challenge)\n\
       operator prove COMMIT_HASH_HEX [FILE]  build proof; omit FILE to use --wallet upload artifact\n\
       operator pool                      list pending proofs (get_proof_pool)\n\
       operator artifacts                 list wallet-local upload artifacts (same as uploads local)\n\
       operator fetch-chunk HASH INDEX PEER  fetch chunk from peer HOST:PORT; verify with --wallet\n"
}

fn parse_args(args: &[String]) -> Result<Parsed, CliError> {
    let mut rpc_addr = DEFAULT_RPC_ADDR.to_string();
    let mut wallet_path: Option<String> = None;
    let mut params_json: Option<String> = None;
    let mut force = false;
    let mut positional: Vec<&str> = Vec::new();
    let mut i = 0usize;
    while i < args.len() {
        let a = args[i].as_str();
        if a == "--rpc" {
            let Some(v) = args.get(i + 1) else {
                return Err(CliError::Usage("--rpc requires HOST:PORT".into()));
            };
            rpc_addr = v.clone();
            i += 2;
            continue;
        }
        if a == "--wallet" {
            let Some(v) = args.get(i + 1) else {
                return Err(CliError::Usage("--wallet requires PATH".into()));
            };
            wallet_path = Some(v.clone());
            i += 2;
            continue;
        }
        if a == "--params" {
            let Some(v) = args.get(i + 1) else {
                return Err(CliError::Usage("--params requires JSON".into()));
            };
            params_json = Some(v.clone());
            i += 2;
            continue;
        }
        if a == "--force" {
            force = true;
            i += 1;
            continue;
        }
        if a == "--include-claims" {
            positional.push(a);
            i += 1;
            continue;
        }
        if a == "--pin-trusted-summary"
            || a == "--reset-trusted-summary"
            || a == "--pin"
            || a == "--from-wallet-checkpoint"
            || a == "--from-checkpoint"
            || a == "--verify-checkpoint"
            || a == "--against-checkpoint"
            || a == "--json"
        {
            positional.push(a);
            i += 1;
            continue;
        }
        if matches!(
            a,
            "--fee"
                | "--ring-size"
                | "--extra"
                | "--replication"
                | "--anchor-value"
                | "--anchor-view"
                | "--anchor-spend"
                | "--message"
                | "--message-hex"
                | "--commit-hash"
                | "--limit"
                | "--offset"
                | "--quorum-rpc"
                | "--quorum-p2p"
                | "--trusted-summary"
                | "--import-trusted-summary"
                | "--pin-trusted-summary"
                | "--reset-trusted-summary"
                | "--out"
                | "--height"
                | "--max-height"
        ) {
            positional.push(a);
            let Some(v) = args.get(i + 1) else {
                return Err(CliError::Usage(format!(
                    "{a} requires a value\n{}",
                    usage()
                )));
            };
            positional.push(v.as_str());
            i += 2;
            continue;
        }
        if a.starts_with('-') {
            return Err(CliError::Usage(format!(
                "unknown option `{a}`\n{}",
                usage()
            )));
        }
        positional.push(a);
        i += 1;
    }
    if positional.is_empty() {
        return Err(CliError::Usage(format!("missing COMMAND\n{}", usage())));
    }
    let cmd = match positional[0] {
        "tip" => {
            if positional.len() != 1 {
                return Err(CliError::Usage(format!(
                    "tip takes no arguments\n{}",
                    usage()
                )));
            }
            Cmd::Tip
        }
        "methods" => {
            if positional.len() != 1 {
                return Err(CliError::Usage(format!(
                    "methods takes no arguments\n{}",
                    usage()
                )));
            }
            Cmd::Methods
        }
        "block-header" => {
            if positional.len() != 2 {
                return Err(CliError::Usage(format!(
                    "block-header requires HEIGHT\n{}",
                    usage()
                )));
            }
            let height: u32 = positional[1]
                .parse()
                .map_err(|_| CliError::Usage("HEIGHT must be a positive integer".into()))?;
            if height == 0 {
                return Err(CliError::Usage("HEIGHT must be at least 1".into()));
            }
            Cmd::BlockHeader { height }
        }
        "mempool" => {
            if positional.len() != 1 {
                return Err(CliError::Usage(format!(
                    "mempool takes no arguments\n{}",
                    usage()
                )));
            }
            Cmd::Mempool
        }
        "call" => {
            if positional.len() != 2 {
                return Err(CliError::Usage(format!(
                    "call requires METHOD\n{}",
                    usage()
                )));
            }
            Cmd::Raw {
                method: positional[1].to_string(),
                params_json,
            }
        }
        "wallet" => parse_wallet_cmd(&positional[1..], wallet_path.clone(), force)?,
        "claims" => parse_claims_cmd(&positional[1..])?,
        "uploads" => parse_uploads_cmd(&positional[1..])?,
        "operator" => parse_operator_cmd(&positional[1..])?,
        other => {
            return Err(CliError::Usage(format!(
                "unknown command `{other}`\n{}",
                usage()
            )));
        }
    };
    Ok(Parsed {
        rpc_addr,
        wallet_path,
        cmd,
    })
}

fn parse_claims_cmd(rest: &[&str]) -> Result<Cmd, CliError> {
    let Some(sub_name) = rest.first() else {
        return Err(CliError::Usage(format!(
            "claims requires SUBCOMMAND (for|recent|by-pubkey|roots)\n{}",
            usage()
        )));
    };
    let sub = match *sub_name {
        "for" => {
            if rest.len() != 2 {
                return Err(CliError::Usage(format!(
                    "claims for requires DATA_ROOT_HEX\n{}",
                    usage()
                )));
            }
            ClaimsSub::For {
                data_root_hex: rest[1].to_string(),
            }
        }
        "recent" => ClaimsSub::Recent(parse_claims_list_args(&rest[1..])?),
        "roots" => ClaimsSub::Roots(parse_claims_list_args(&rest[1..])?),
        "by-pubkey" => {
            let (claim_pubkey_hex, limit) = parse_claims_by_pubkey_args(&rest[1..])?;
            ClaimsSub::ByPubkey {
                claim_pubkey_hex,
                limit,
            }
        }
        other => {
            return Err(CliError::Usage(format!(
                "unknown claims subcommand `{other}`\n{}",
                usage()
            )));
        }
    };
    Ok(Cmd::Claims { sub })
}

fn parse_uploads_cmd(rest: &[&str]) -> Result<Cmd, CliError> {
    let Some(sub_name) = rest.first() else {
        return Err(CliError::Usage(format!(
            "uploads requires SUBCOMMAND (list|local|status)\n{}",
            usage()
        )));
    };
    let sub = match *sub_name {
        "list" => UploadsSub::List(parse_uploads_list_args(&rest[1..])?),
        "local" => {
            if !rest[1..].is_empty() {
                return Err(CliError::Usage(format!(
                    "uploads local takes no arguments\n{}",
                    usage()
                )));
            }
            UploadsSub::Local
        }
        "status" => {
            if !rest[1..].is_empty() {
                return Err(CliError::Usage(format!(
                    "uploads status takes no arguments\n{}",
                    usage()
                )));
            }
            UploadsSub::Status
        }
        other => {
            return Err(CliError::Usage(format!(
                "unknown uploads subcommand `{other}`\n{}",
                usage()
            )));
        }
    };
    Ok(Cmd::Uploads { sub })
}

fn parse_operator_cmd(rest: &[&str]) -> Result<Cmd, CliError> {
    let Some(sub_name) = rest.first() else {
        return Err(CliError::Usage(format!(
            "operator requires SUBCOMMAND (challenge|prove|pool|artifacts|fetch-chunk)\n{}",
            usage()
        )));
    };
    let sub = match *sub_name {
        "challenge" => {
            if rest.len() != 2 {
                return Err(CliError::Usage(format!(
                    "operator challenge requires COMMITMENT_HASH_HEX\n{}",
                    usage()
                )));
            }
            OperatorSub::Challenge {
                commitment_hash_hex: rest[1].to_string(),
            }
        }
        "prove" => {
            if rest.len() < 2 || rest.len() > 3 {
                return Err(CliError::Usage(format!(
                    "operator prove requires COMMITMENT_HASH_HEX [FILE]\n\
                     (omit FILE to load payload from --wallet upload artifact)\n{}",
                    usage()
                )));
            }
            OperatorSub::Prove {
                commitment_hash_hex: rest[1].to_string(),
                data_path: rest.get(2).map(|p| std::path::PathBuf::from(*p)),
            }
        }
        "pool" => {
            if rest.len() != 1 {
                return Err(CliError::Usage(format!(
                    "operator pool takes no arguments\n{}",
                    usage()
                )));
            }
            OperatorSub::Pool
        }
        "artifacts" => {
            if rest.len() != 1 {
                return Err(CliError::Usage(format!(
                    "operator artifacts takes no arguments\n{}",
                    usage()
                )));
            }
            OperatorSub::Artifacts
        }
        "fetch-chunk" => {
            if rest.len() != 4 {
                return Err(CliError::Usage(format!(
                    "operator fetch-chunk requires COMMITMENT_HASH_HEX CHUNK_INDEX PEER\n{}",
                    usage()
                )));
            }
            let chunk_index = rest[2]
                .parse()
                .map_err(|_| CliError::Usage(format!("invalid chunk index `{}`", rest[2])))?;
            OperatorSub::FetchChunk {
                commitment_hash_hex: rest[1].to_string(),
                chunk_index,
                peer: rest[3].to_string(),
            }
        }
        other => {
            return Err(CliError::Usage(format!(
                "unknown operator subcommand `{other}`\n{}",
                usage()
            )));
        }
    };
    Ok(Cmd::Operator { sub })
}

fn parse_uploads_list_args(rest: &[&str]) -> Result<UploadsListParams, CliError> {
    let mut limit = None;
    let mut offset = None;
    let mut include_claims = false;
    let mut i = 0usize;
    while i < rest.len() {
        let a = rest[i];
        if a == "--limit" {
            let Some(v) = rest.get(i + 1) else {
                return Err(CliError::Usage("--limit requires a value".into()));
            };
            limit = Some(
                v.parse()
                    .map_err(|_| CliError::Usage("--limit must be a positive integer".into()))?,
            );
            i += 2;
            continue;
        }
        if a == "--offset" {
            let Some(v) = rest.get(i + 1) else {
                return Err(CliError::Usage("--offset requires a value".into()));
            };
            offset =
                Some(v.parse().map_err(|_| {
                    CliError::Usage("--offset must be a non-negative integer".into())
                })?);
            i += 2;
            continue;
        }
        if a == "--include-claims" {
            include_claims = true;
            i += 1;
            continue;
        }
        return Err(CliError::Usage(format!(
            "unexpected argument `{a}` for uploads list\n{}",
            usage()
        )));
    }
    Ok(UploadsListParams {
        limit,
        offset,
        include_claims,
    })
}

fn parse_claims_list_args(rest: &[&str]) -> Result<ClaimsListParams, CliError> {
    let mut limit = None;
    let mut offset = None;
    let mut i = 0usize;
    while i < rest.len() {
        let a = rest[i];
        if a == "--limit" {
            let Some(v) = rest.get(i + 1) else {
                return Err(CliError::Usage("--limit requires a value".into()));
            };
            limit = Some(
                v.parse()
                    .map_err(|_| CliError::Usage("--limit must be a positive integer".into()))?,
            );
            i += 2;
            continue;
        }
        if a == "--offset" {
            let Some(v) = rest.get(i + 1) else {
                return Err(CliError::Usage("--offset requires a value".into()));
            };
            offset =
                Some(v.parse().map_err(|_| {
                    CliError::Usage("--offset must be a non-negative integer".into())
                })?);
            i += 2;
            continue;
        }
        return Err(CliError::Usage(format!(
            "unexpected argument `{a}`\n{}",
            usage()
        )));
    }
    Ok(ClaimsListParams { limit, offset })
}

fn parse_claims_by_pubkey_args(rest: &[&str]) -> Result<(String, Option<u64>), CliError> {
    let mut limit = None;
    let mut claim_pubkey_hex: Option<String> = None;
    let mut i = 0usize;
    while i < rest.len() {
        let a = rest[i];
        if a == "--limit" {
            let Some(v) = rest.get(i + 1) else {
                return Err(CliError::Usage("--limit requires a value".into()));
            };
            limit = Some(
                v.parse()
                    .map_err(|_| CliError::Usage("--limit must be a positive integer".into()))?,
            );
            i += 2;
            continue;
        }
        if a.starts_with('-') {
            return Err(CliError::Usage(format!(
                "unknown claims by-pubkey option `{a}`\n{}",
                usage()
            )));
        }
        if claim_pubkey_hex.is_some() {
            return Err(CliError::Usage(format!(
                "claims by-pubkey accepts one CLAIM_PUBKEY_HEX\n{}",
                usage()
            )));
        }
        claim_pubkey_hex = Some(a.to_string());
        i += 1;
    }
    let Some(hex) = claim_pubkey_hex else {
        return Err(CliError::Usage(format!(
            "claims by-pubkey requires CLAIM_PUBKEY_HEX\n{}",
            usage()
        )));
    };
    Ok((hex, limit))
}

fn parse_wallet_cmd(
    rest: &[&str],
    wallet_path: Option<String>,
    force: bool,
) -> Result<Cmd, CliError> {
    let Some(sub_name) = rest.first() else {
        return Err(CliError::Usage(format!(
            "wallet requires SUBCOMMAND (new|address|scan|light-scan|balance|status|send|upload|claim|export-trusted-summary|import-trusted-summary|show-trusted-summary|compare-trusted-summary)\n{}",
            usage()
        )));
    };
    let sub = match *sub_name {
        "light-scan" => WalletSub::LightScan(parse_wallet_light_scan_args(&rest[1..])?),
        "export-trusted-summary" => {
            WalletSub::ExportTrustedSummary(parse_wallet_export_trusted_summary_args(&rest[1..])?)
        }
        "import-trusted-summary" => {
            WalletSub::ImportTrustedSummary(parse_wallet_import_trusted_summary_args(&rest[1..])?)
        }
        "show-trusted-summary" => {
            WalletSub::ShowTrustedSummary(parse_wallet_show_trusted_summary_args(&rest[1..])?)
        }
        "compare-trusted-summary" => {
            WalletSub::CompareTrustedSummary(parse_wallet_compare_trusted_summary_args(&rest[1..])?)
        }
        "new" | "address" | "scan" | "balance" | "status" => {
            if rest.len() != 1 {
                return Err(CliError::Usage(format!(
                    "wallet {sub_name} takes no extra arguments\n{}",
                    usage()
                )));
            }
            match *sub_name {
                "new" => WalletSub::New,
                "address" => WalletSub::Address,
                "scan" => WalletSub::Scan,
                "balance" => WalletSub::Balance,
                "status" => WalletSub::Status,
                _ => unreachable!(),
            }
        }
        "send" => WalletSub::Send(parse_wallet_send_args(&rest[1..])?),
        "upload" => WalletSub::Upload(parse_wallet_upload_args(&rest[1..])?),
        "claim" => WalletSub::Claim(parse_wallet_claim_args(&rest[1..])?),
        other => {
            return Err(CliError::Usage(format!(
                "unknown wallet subcommand `{other}`\n{}",
                usage()
            )));
        }
    };
    Ok(Cmd::Wallet {
        sub,
        wallet_path,
        force,
    })
}

fn parse_wallet_light_scan_args(rest: &[&str]) -> Result<LightScanParams, CliError> {
    let mut quorum_rpc_addrs: Vec<String> = Vec::new();
    let mut quorum_p2p_peers: Vec<String> = Vec::new();
    let mut trusted_summary_path: Option<std::path::PathBuf> = None;
    let mut import_trusted_summary_path: Option<std::path::PathBuf> = None;
    let mut reset_trusted_summary = false;
    let mut pin_trusted_summary = false;
    let mut max_height: Option<u32> = None;
    let mut i = 0usize;
    while i < rest.len() {
        let a = rest[i];
        if a == "--quorum-rpc" {
            let Some(v) = rest.get(i + 1) else {
                return Err(CliError::Usage(
                    "wallet light-scan --quorum-rpc requires HOST:PORT list\n".into(),
                ));
            };
            quorum_rpc_addrs.extend(split_host_list(v));
            i += 2;
            continue;
        }
        if a == "--quorum-p2p" {
            let Some(v) = rest.get(i + 1) else {
                return Err(CliError::Usage(
                    "wallet light-scan --quorum-p2p requires HOST:PORT list\n".into(),
                ));
            };
            quorum_p2p_peers.extend(split_host_list(v));
            i += 2;
            continue;
        }
        if a == "--trusted-summary" {
            let Some(v) = rest.get(i + 1) else {
                return Err(CliError::Usage(
                    "wallet light-scan --trusted-summary requires FILE\n".into(),
                ));
            };
            trusted_summary_path = Some(std::path::PathBuf::from(v));
            i += 2;
            continue;
        }
        if a == "--import-trusted-summary" {
            let Some(v) = rest.get(i + 1) else {
                return Err(CliError::Usage(
                    "wallet light-scan --import-trusted-summary requires FILE\n".into(),
                ));
            };
            import_trusted_summary_path = Some(std::path::PathBuf::from(v));
            i += 2;
            continue;
        }
        if a == "--pin-trusted-summary" {
            pin_trusted_summary = true;
            i += 1;
            continue;
        }
        if a == "--reset-trusted-summary" {
            reset_trusted_summary = true;
            i += 1;
            continue;
        }
        if a == "--max-height" {
            let Some(v) = rest.get(i + 1) else {
                return Err(CliError::Usage(
                    "wallet light-scan --max-height requires HEIGHT\n".into(),
                ));
            };
            max_height = Some(
                v.parse()
                    .map_err(|_| CliError::Usage(format!("invalid --max-height `{v}`")))?,
            );
            i += 2;
            continue;
        }
        return Err(CliError::Usage(format!(
            "unknown wallet light-scan argument `{a}`\n{}",
            usage()
        )));
    }
    if trusted_summary_path.is_some() && import_trusted_summary_path.is_some() {
        return Err(CliError::Usage(
            "wallet light-scan: use --trusted-summary or --import-trusted-summary, not both\n"
                .into(),
        ));
    }
    Ok(LightScanParams {
        quorum_rpc_addrs,
        quorum_p2p_peers,
        trusted_summary_path,
        import_trusted_summary_path,
        reset_trusted_summary,
        pin_trusted_summary,
        update_trusted_summary: true,
        max_height,
    })
}

fn parse_wallet_export_trusted_summary_args(
    rest: &[&str],
) -> Result<ExportTrustedSummaryParams, CliError> {
    let mut output_path: Option<std::path::PathBuf> = None;
    let mut height: Option<u32> = None;
    let mut pin_wallet = false;
    let mut from_wallet_checkpoint = false;
    let mut i = 0usize;
    while i < rest.len() {
        let a = rest[i];
        if a == "--out" {
            let Some(v) = rest.get(i + 1) else {
                return Err(CliError::Usage(
                    "wallet export-trusted-summary --out requires FILE\n".into(),
                ));
            };
            output_path = Some(std::path::PathBuf::from(v));
            i += 2;
            continue;
        }
        if a == "--height" {
            let Some(v) = rest.get(i + 1) else {
                return Err(CliError::Usage(
                    "wallet export-trusted-summary --height requires N\n".into(),
                ));
            };
            height = Some(
                v.parse()
                    .map_err(|_| CliError::Usage("--height must be a positive integer".into()))?,
            );
            i += 2;
            continue;
        }
        if a == "--pin" || a == "--pin-trusted-summary" {
            pin_wallet = true;
            i += 1;
            continue;
        }
        if a == "--from-wallet-checkpoint" {
            from_wallet_checkpoint = true;
            i += 1;
            continue;
        }
        return Err(CliError::Usage(format!(
            "unknown wallet export-trusted-summary argument `{a}`\n{}",
            usage()
        )));
    }
    if from_wallet_checkpoint && height.is_some() {
        return Err(CliError::Usage(
            "--from-wallet-checkpoint cannot be combined with --height\n".into(),
        ));
    }
    Ok(ExportTrustedSummaryParams {
        output_path,
        height,
        pin_wallet,
        from_wallet_checkpoint,
    })
}

fn parse_wallet_import_trusted_summary_args(
    rest: &[&str],
) -> Result<ImportTrustedSummaryParams, CliError> {
    let mut verify_wallet_checkpoint = false;
    let mut summary_path: Option<std::path::PathBuf> = None;
    let mut i = 0usize;
    while i < rest.len() {
        let a = rest[i];
        if a == "--verify-checkpoint" {
            verify_wallet_checkpoint = true;
            i += 1;
            continue;
        }
        if summary_path.is_some() {
            return Err(CliError::Usage(format!(
                "unexpected wallet import-trusted-summary argument `{a}`\n{}",
                usage()
            )));
        }
        summary_path = Some(std::path::PathBuf::from(a));
        i += 1;
    }
    let Some(summary_path) = summary_path else {
        return Err(CliError::Usage(format!(
            "wallet import-trusted-summary requires FILE\n{}",
            usage()
        )));
    };
    Ok(ImportTrustedSummaryParams {
        summary_path,
        verify_wallet_checkpoint,
    })
}

fn parse_wallet_show_trusted_summary_args(
    rest: &[&str],
) -> Result<ShowTrustedSummaryParams, CliError> {
    let mut from_wallet_checkpoint = false;
    let mut json_only = false;
    for a in rest {
        if *a == "--from-checkpoint" || *a == "--from-wallet-checkpoint" {
            from_wallet_checkpoint = true;
            continue;
        }
        if *a == "--json" {
            json_only = true;
            continue;
        }
        return Err(CliError::Usage(format!(
            "unknown wallet show-trusted-summary argument `{a}`\n{}",
            usage()
        )));
    }
    Ok(ShowTrustedSummaryParams {
        from_wallet_checkpoint,
        json_only,
    })
}

fn parse_wallet_compare_trusted_summary_args(
    rest: &[&str],
) -> Result<CompareTrustedSummaryParams, CliError> {
    let mut against_wallet_checkpoint = false;
    let mut paths: Vec<std::path::PathBuf> = Vec::new();
    let mut i = 0usize;
    while i < rest.len() {
        let a = rest[i];
        if a == "--against-checkpoint" {
            against_wallet_checkpoint = true;
            i += 1;
            continue;
        }
        if a.starts_with('-') {
            return Err(CliError::Usage(format!(
                "unknown wallet compare-trusted-summary argument `{a}`\n{}",
                usage()
            )));
        }
        paths.push(std::path::PathBuf::from(a));
        i += 1;
    }
    let Some(left_path) = paths.first().cloned() else {
        return Err(CliError::Usage(format!(
            "wallet compare-trusted-summary requires FILE [FILE2]\n{}",
            usage()
        )));
    };
    if paths.len() > 2 {
        return Err(CliError::Usage(format!(
            "wallet compare-trusted-summary accepts at most two FILE arguments\n{}",
            usage()
        )));
    }
    if paths.len() == 2 && against_wallet_checkpoint {
        return Err(CliError::Usage(
            "--against-checkpoint applies only when comparing a single FILE to the wallet\n".into(),
        ));
    }
    Ok(CompareTrustedSummaryParams {
        left_path,
        right_path: paths.get(1).cloned(),
        against_wallet_checkpoint,
    })
}

fn split_host_list(raw: &str) -> Vec<String> {
    raw.split(&[',', ' ', '\t'][..])
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_string)
        .collect()
}

fn parse_wallet_send_args(rest: &[&str]) -> Result<SendParams, CliError> {
    let mut fee = DEFAULT_TRANSFER_FEE;
    let mut ring_size = DEFAULT_RING_SIZE;
    let mut extra: Vec<u8> = Vec::new();
    let mut positional: Vec<&str> = Vec::new();
    let mut i = 0usize;
    while i < rest.len() {
        let a = rest[i];
        if a == "--fee" {
            let Some(v) = rest.get(i + 1) else {
                return Err(CliError::Usage("--fee requires a value".into()));
            };
            fee = v
                .parse()
                .map_err(|_| CliError::Usage("--fee must be a non-negative integer".into()))?;
            i += 2;
            continue;
        }
        if a == "--ring-size" {
            let Some(v) = rest.get(i + 1) else {
                return Err(CliError::Usage("--ring-size requires a value".into()));
            };
            ring_size = v
                .parse()
                .map_err(|_| CliError::Usage("--ring-size must be an integer ≥ 2".into()))?;
            i += 2;
            continue;
        }
        if a == "--extra" {
            let Some(v) = rest.get(i + 1) else {
                return Err(CliError::Usage("--extra requires hex bytes".into()));
            };
            let t = v
                .strip_prefix("0x")
                .or_else(|| v.strip_prefix("0X"))
                .unwrap_or(v);
            extra =
                hex::decode(t).map_err(|e| CliError::Usage(format!("--extra hex decode: {e}")))?;
            i += 2;
            continue;
        }
        if a.starts_with('-') {
            return Err(CliError::Usage(format!(
                "unknown wallet send option `{a}`\n{}",
                usage()
            )));
        }
        positional.push(a);
        i += 1;
    }
    if positional.len() != 3 {
        return Err(CliError::Usage(format!(
            "wallet send requires VIEW_HEX SPEND_HEX AMOUNT\n{}",
            usage()
        )));
    }
    let amount: u64 = positional[2]
        .parse()
        .map_err(|_| CliError::Usage("AMOUNT must be a non-negative integer".into()))?;
    Ok(SendParams {
        to_view_hex: positional[0].to_string(),
        to_spend_hex: positional[1].to_string(),
        amount,
        fee,
        ring_size,
        extra,
    })
}

fn parse_wallet_upload_args(rest: &[&str]) -> Result<UploadParams, CliError> {
    use crate::wallet_cmd::{
        DEFAULT_RING_SIZE, DEFAULT_UPLOAD_ANCHOR_VALUE, DEFAULT_UPLOAD_REPLICATION,
    };

    let mut fee: Option<u64> = None;
    let mut replication = DEFAULT_UPLOAD_REPLICATION;
    let mut anchor_value = DEFAULT_UPLOAD_ANCHOR_VALUE;
    let mut ring_size = DEFAULT_RING_SIZE;
    let mut extra: Vec<u8> = Vec::new();
    let mut anchor_view: Option<String> = None;
    let mut anchor_spend: Option<String> = None;
    let mut message: Option<Vec<u8>> = None;
    let mut positional: Vec<&str> = Vec::new();
    let mut i = 0usize;
    while i < rest.len() {
        let a = rest[i];
        if a == "--message" {
            let Some(v) = rest.get(i + 1) else {
                return Err(CliError::Usage("--message requires text".into()));
            };
            message = Some(v.as_bytes().to_vec());
            i += 2;
            continue;
        }
        if a == "--message-hex" {
            let Some(v) = rest.get(i + 1) else {
                return Err(CliError::Usage("--message-hex requires hex bytes".into()));
            };
            let t = v
                .strip_prefix("0x")
                .or_else(|| v.strip_prefix("0X"))
                .unwrap_or(v);
            message = Some(
                hex::decode(t)
                    .map_err(|e| CliError::Usage(format!("--message-hex decode: {e}")))?,
            );
            i += 2;
            continue;
        }
        if a == "--fee" {
            let Some(v) = rest.get(i + 1) else {
                return Err(CliError::Usage("--fee requires a value".into()));
            };
            fee = Some(
                v.parse()
                    .map_err(|_| CliError::Usage("--fee must be a non-negative integer".into()))?,
            );
            i += 2;
            continue;
        }
        if a == "--replication" {
            let Some(v) = rest.get(i + 1) else {
                return Err(CliError::Usage("--replication requires a value".into()));
            };
            replication = v
                .parse()
                .map_err(|_| CliError::Usage("--replication must be 1..=255".into()))?;
            i += 2;
            continue;
        }
        if a == "--anchor-value" {
            let Some(v) = rest.get(i + 1) else {
                return Err(CliError::Usage("--anchor-value requires a value".into()));
            };
            anchor_value = v.parse().map_err(|_| {
                CliError::Usage("--anchor-value must be a non-negative integer".into())
            })?;
            i += 2;
            continue;
        }
        if a == "--ring-size" {
            let Some(v) = rest.get(i + 1) else {
                return Err(CliError::Usage("--ring-size requires a value".into()));
            };
            ring_size = v
                .parse()
                .map_err(|_| CliError::Usage("--ring-size must be an integer ≥ 2".into()))?;
            i += 2;
            continue;
        }
        if a == "--anchor-view" {
            let Some(v) = rest.get(i + 1) else {
                return Err(CliError::Usage("--anchor-view requires hex".into()));
            };
            anchor_view = Some(v.to_string());
            i += 2;
            continue;
        }
        if a == "--anchor-spend" {
            let Some(v) = rest.get(i + 1) else {
                return Err(CliError::Usage("--anchor-spend requires hex".into()));
            };
            anchor_spend = Some(v.to_string());
            i += 2;
            continue;
        }
        if a == "--extra" {
            let Some(v) = rest.get(i + 1) else {
                return Err(CliError::Usage("--extra requires hex bytes".into()));
            };
            let t = v
                .strip_prefix("0x")
                .or_else(|| v.strip_prefix("0X"))
                .unwrap_or(v);
            extra =
                hex::decode(t).map_err(|e| CliError::Usage(format!("--extra hex decode: {e}")))?;
            i += 2;
            continue;
        }
        if a.starts_with('-') {
            return Err(CliError::Usage(format!(
                "unknown wallet upload option `{a}`\n{}",
                usage()
            )));
        }
        positional.push(a);
        i += 1;
    }
    if positional.len() != 1 {
        return Err(CliError::Usage(format!(
            "wallet upload requires exactly one FILE path\n{}",
            usage()
        )));
    }
    Ok(UploadParams {
        file_path: std::path::PathBuf::from(positional[0]),
        replication,
        fee,
        anchor_value,
        ring_size,
        extra,
        anchor_view_hex: anchor_view,
        anchor_spend_hex: anchor_spend,
        message,
    })
}

fn parse_wallet_claim_args(rest: &[&str]) -> Result<ClaimParams, CliError> {
    let mut fee = DEFAULT_CLAIM_FEE;
    let mut ring_size = DEFAULT_RING_SIZE;
    let mut commit_hash_hex: Option<String> = None;
    let mut message: Option<Vec<u8>> = None;
    let mut positional: Vec<&str> = Vec::new();
    let mut i = 0usize;
    while i < rest.len() {
        let a = rest[i];
        if a == "--fee" {
            let Some(v) = rest.get(i + 1) else {
                return Err(CliError::Usage("--fee requires a value".into()));
            };
            fee = v
                .parse()
                .map_err(|_| CliError::Usage("--fee must be a non-negative integer".into()))?;
            i += 2;
            continue;
        }
        if a == "--ring-size" {
            let Some(v) = rest.get(i + 1) else {
                return Err(CliError::Usage("--ring-size requires a value".into()));
            };
            ring_size = v
                .parse()
                .map_err(|_| CliError::Usage("--ring-size must be an integer ≥ 2".into()))?;
            i += 2;
            continue;
        }
        if a == "--commit-hash" {
            let Some(v) = rest.get(i + 1) else {
                return Err(CliError::Usage("--commit-hash requires hex".into()));
            };
            commit_hash_hex = Some(v.to_string());
            i += 2;
            continue;
        }
        if a == "--message" {
            let Some(v) = rest.get(i + 1) else {
                return Err(CliError::Usage("--message requires text".into()));
            };
            message = Some(v.as_bytes().to_vec());
            i += 2;
            continue;
        }
        if a == "--message-hex" {
            let Some(v) = rest.get(i + 1) else {
                return Err(CliError::Usage("--message-hex requires hex bytes".into()));
            };
            let t = v
                .strip_prefix("0x")
                .or_else(|| v.strip_prefix("0X"))
                .unwrap_or(v);
            message = Some(
                hex::decode(t)
                    .map_err(|e| CliError::Usage(format!("--message-hex decode: {e}")))?,
            );
            i += 2;
            continue;
        }
        if a.starts_with('-') {
            return Err(CliError::Usage(format!(
                "unknown wallet claim option `{a}`\n{}",
                usage()
            )));
        }
        positional.push(a);
        i += 1;
    }
    if positional.len() != 1 {
        return Err(CliError::Usage(format!(
            "wallet claim requires DATA_ROOT_HEX (64 hex chars)\n{}",
            usage()
        )));
    }
    let message = message.unwrap_or_else(|| b"permawrite claim".to_vec());
    Ok(ClaimParams {
        data_root_hex: positional[0].to_string(),
        commit_hash_hex,
        message,
        fee,
        ring_size,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_tip_defaults_rpc() {
        let p = parse_args(&["tip".into()]).unwrap();
        assert_eq!(p.rpc_addr, DEFAULT_RPC_ADDR);
        assert_eq!(p.cmd, Cmd::Tip);
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
                sub: WalletSub::Balance,
                wallet_path,
                force,
            } => {
                assert_eq!(wallet_path.as_deref(), Some("/tmp/alice.json"));
                assert!(!force);
            }
            _ => panic!("expected wallet balance"),
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
                sub: ClaimsSub::For { data_root_hex },
            } => assert_eq!(data_root_hex.len(), 64),
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
            } => assert_eq!(params.limit, Some(10)),
            _ => panic!("expected claims recent"),
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
            }
            _ => panic!("expected uploads list"),
        }
    }

    #[test]
    fn parse_uploads_local_subcommand() {
        let p = parse_args(&["uploads".into(), "local".into()]).unwrap();
        match p.cmd {
            Cmd::Uploads {
                sub: UploadsSub::Local,
            } => {}
            _ => panic!("expected uploads local"),
        }
    }

    #[test]
    fn parse_uploads_status_subcommand() {
        let p = parse_args(&["uploads".into(), "status".into()]).unwrap();
        match p.cmd {
            Cmd::Uploads {
                sub: UploadsSub::Status,
            } => {}
            _ => panic!("expected uploads status"),
        }
    }

    #[test]
    fn parse_operator_artifacts_subcommand() {
        let p = parse_args(&["operator".into(), "artifacts".into()]).unwrap();
        match p.cmd {
            Cmd::Operator {
                sub: OperatorSub::Artifacts,
            } => {}
            _ => panic!("expected operator artifacts"),
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
                    },
            } => {
                assert_eq!(commitment_hash_hex, h);
                assert_eq!(chunk_index, 0);
                assert_eq!(peer, "127.0.0.1:18780");
            }
            _ => panic!("expected operator fetch-chunk"),
        }
    }
}
