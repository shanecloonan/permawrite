//! `mfn-cli` command-line driver (**M3.0** / **M3.1**).

use std::process::ExitCode;

use serde_json::json;

use crate::rpc::{RpcClient, DEFAULT_RPC_ADDR};
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
}

/// Entry for the `mfn-cli` binary.
pub fn run_cli(args: impl IntoIterator<Item = String>) -> Result<(), CliError> {
    let argv: Vec<String> = args.into_iter().skip(1).collect();
    let parsed = parse_args(&argv)?;
    let mut client = RpcClient::new(&parsed.rpc_addr);
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
                WalletSub::Balance => wallet_balance(&path, &mut client)?,
                WalletSub::Status => wallet_status(&path, &mut client)?,
                WalletSub::Send(params) => wallet_send(&path, &mut client, &params)?,
                WalletSub::Upload(params) => wallet_upload(&path, &mut client, &params)?,
                WalletSub::Claim(params) => wallet_claim(&path, &mut client, &params)?,
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
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum WalletSub {
    New,
    Address,
    Scan,
    Balance,
    Status,
    Send(SendParams),
    Upload(UploadParams),
    Claim(ClaimParams),
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct Parsed {
    rpc_addr: String,
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
       wallet scan       scan blocks from node tip through wallet file\n\
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
                         --fee N --ring-size N\n"
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
        "wallet" => parse_wallet_cmd(&positional[1..], wallet_path, force)?,
        other => {
            return Err(CliError::Usage(format!(
                "unknown command `{other}`\n{}",
                usage()
            )));
        }
    };
    Ok(Parsed { rpc_addr, cmd })
}

fn parse_wallet_cmd(
    rest: &[&str],
    wallet_path: Option<String>,
    force: bool,
) -> Result<Cmd, CliError> {
    let Some(sub_name) = rest.first() else {
        return Err(CliError::Usage(format!(
            "wallet requires SUBCOMMAND (new|address|scan|balance|status|send|upload|claim)\n{}",
            usage()
        )));
    };
    let sub = match *sub_name {
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
}
