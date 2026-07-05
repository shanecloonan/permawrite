//! CLI argument parsing for `mfn-cli`.

use crate::claims_cmd::{ClaimsByPubkeyParams, ClaimsListParams};
use crate::light_subjectivity::{
    CompareTrustedSummaryParams, ExportTrustedSummaryParams, ImportTrustedSummaryParams,
    ShowTrustedSummaryParams,
};
use crate::light_wallet::LightScanParams;
use crate::operator_cmd::{
    AssembleInboxParams, BackfillParams, InboxStatusParams, OperatorJsonParams,
};
use crate::rpc::DEFAULT_RPC_ADDR;
use crate::uploads_cmd::{UploadsFetchHttpParams, UploadsInventoryParams, UploadsListParams};
use crate::wallet_cmd::{
    decode_wallet_address_to_hex, BackupInfoParams, ClaimParams, SendParams, UploadParams,
    WalletScanParams, WalletStatusParams, DEFAULT_CLAIM_FEE, DEFAULT_RING_SIZE,
    DEFAULT_TRANSFER_FEE, DEFAULT_UPLOAD_ANCHOR_VALUE, DEFAULT_UPLOAD_REPLICATION,
    WALLET_ADDRESS_PREFIX,
};
use crate::wallet_store::KeyDerivation;

use super::CliError;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Cmd {
    Status,
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
pub(crate) enum ClaimsSub {
    For { data_root_hex: String, json: bool },
    Recent(ClaimsListParams),
    ByPubkey(ClaimsByPubkeyParams),
    Roots(ClaimsListParams),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum UploadsSub {
    List(UploadsListParams),
    Local(UploadsInventoryParams),
    Status(UploadsInventoryParams),
    Retrieve {
        commitment_hash_hex: String,
        output_path: std::path::PathBuf,
        force: bool,
    },
    FetchHttp {
        commitment_hash_hex: String,
        output_path: std::path::PathBuf,
        peers: Vec<String>,
        params: UploadsFetchHttpParams,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum OperatorSub {
    Challenge {
        commitment_hash_hex: String,
        params: OperatorJsonParams,
    },
    Prove {
        commitment_hash_hex: String,
        data_path: Option<std::path::PathBuf>,
        params: OperatorJsonParams,
    },
    Pool(OperatorJsonParams),
    Artifacts(UploadsInventoryParams),
    FetchChunk {
        commitment_hash_hex: String,
        chunk_index: u32,
        peer: String,
        params: OperatorJsonParams,
    },
    Backfill {
        commitment_hash_hex: String,
        peers: Vec<String>,
        params: BackfillParams,
    },
    PushChunks {
        commitment_hash_hex: String,
        peers: Vec<String>,
        params: OperatorJsonParams,
    },
    InboxStatus {
        commitment_hash_hex: String,
        data_dir: std::path::PathBuf,
        params: InboxStatusParams,
    },
    AssembleInbox {
        commitment_hash_hex: String,
        data_dir: std::path::PathBuf,
        params: AssembleInboxParams,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum WalletSub {
    New,
    Restore {
        seed_hex: String,
        key_derivation: KeyDerivation,
    },
    Address,
    Scan(WalletScanParams),
    LightScan(LightScanParams),
    Balance(WalletScanParams),
    Status(WalletStatusParams),
    BackupInfo(BackupInfoParams),
    Send(SendParams),
    Upload(UploadParams),
    Claim(ClaimParams),
    ExportTrustedSummary(ExportTrustedSummaryParams),
    ImportTrustedSummary(ImportTrustedSummaryParams),
    ShowTrustedSummary(ShowTrustedSummaryParams),
    CompareTrustedSummary(CompareTrustedSummaryParams),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Parsed {
    pub(crate) rpc_addr: String,
    pub(crate) rpc_api_key: Option<String>,
    pub(crate) wallet_path: Option<String>,
    pub(crate) cmd: Cmd,
}

pub(crate) const MFN_RPC_API_KEY: &str = "MFN_RPC_API_KEY";

pub(super) fn usage() -> &'static str {
    "usage: mfn-cli [--rpc HOST:PORT] [--rpc-api-key KEY] [--wallet PATH] <COMMAND> [ARGS]\n\
     \n\
     options:\n\
       --rpc ADDR:PORT   mfnd JSON-RPC listen address (default 127.0.0.1:18731)\n\
       --rpc-api-key KEY send KEY with each JSON-RPC request (or set MFN_RPC_API_KEY)\n\
       --wallet PATH     wallet JSON file (default wallet.json)\n\
       --params JSON     only for `call`: JSON-RPC params object/array (default null)\n\
       --force           for `wallet new` / `wallet restore`: overwrite existing wallet file\n\
     \n\
     commands:\n\
       status            print machine-readable node status (get_status)\n\
       tip               print chain tip (get_tip)\n\
       methods           list JSON-RPC methods (list_methods)\n\
       block-header H    block header at height H (get_block_header)\n\
       mempool           list mempool tx ids (get_mempool)\n\
       call METHOD       arbitrary JSON-RPC call; prints pretty JSON result\n\
       wallet new        create wallet.json with a fresh 32-byte seed\n\
       wallet restore SEED_HEX  restore wallet.json from a 32-byte seed\n\
                         options: --key-derivation mfn_wallet_v1|payout_stealth_v1\n\
       wallet address    print view/spend public keys from wallet file\n\
       wallet scan       scan full blocks from node tip (get_block)\n\
                         options: --json\n\
       wallet light-scan verify headers + evolution, scan txs only (**M3.11**)\n\
                         options: --quorum-rpc HOST:PORT,... --quorum-p2p HOST:PORT,...\n\
                         --trusted-summary FILE --import-trusted-summary FILE\n\
                         --pin-trusted-summary --reset-trusted-summary --max-height N\n\
       wallet balance    scan chain and print balance\n\
                         options: --json\n\
       wallet status     print cached balance vs node tip (no block fetch)\n\
                         options: --json\n\
       wallet backup-info  print wallet/artifact backup inventory (no seed output)\n\
                         options: --json\n\
wallet send ADDRESS AMOUNT  build CLSAG transfer and submit_tx\n\
wallet send VIEW_HEX SPEND_HEX AMOUNT  legacy raw-key send form\n\
                         options: --fee N --ring-size N (default 16, consensus min) --extra HEX --json\n\
       wallet upload FILE                 anchor FILE on-chain (storage upload + submit_tx)\n\
                         options: --replication N --fee N --anchor-value N --ring-size N (default 16)\n\
                         --anchor-view HEX --anchor-spend HEX --extra HEX\n\
                         --message TEXT | --message-hex HEX (MFCL claim bound to upload)\n\
                         --json\n\
       wallet claim DATA_ROOT_HEX         publish MFCL authorship claim + submit_tx\n\
                         options: --message TEXT | --message-hex HEX --commit-hash HEX\n\
                         --fee N --ring-size N (default 16) --json\n\
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
                         options for all claims queries: --json\n\
                         options for recent/roots: --limit N --offset N\n\
                         options for by-pubkey: --limit N\n\
       uploads list                       recent storage uploads (list_recent_uploads)\n\
                         options: --limit N --offset N --include-claims --json\n\
       uploads local                      list persisted upload artifacts for --wallet (**M3.25**)\n\
                        options: --json\n\
       uploads status                     reconcile local artifacts vs chain upload index (**M3.26**)\n\
                        options: --json\n\
       uploads retrieve HASH OUT [replace]  export payload.bin from a wallet artifact (**M3.27**)\n\
       uploads fetch-http HASH OUT PEER [PEER...] [replace]\n\
                         HTTP backfill chunks from peer(s), then export payload.bin (**M3.28**)\n\
                        options: --json\n\
       operator challenge COMMIT_HASH_HEX  next-block SPoRA challenge (get_storage_challenge)\n\
                         options: --json\n\
       operator prove COMMIT_HASH_HEX [FILE]  build proof; omit FILE to use --wallet upload artifact\n\
                         options: --json\n\
       operator pool                      list pending proofs (get_proof_pool)\n\
                         options: --json\n\
       operator artifacts                 list wallet-local upload artifacts (same as uploads local)\n\
                         options: --json\n\
       operator fetch-chunk HASH INDEX PEER  fetch chunk from peer HOST:PORT; verify with --wallet\n\
                         options: --json\n\
       operator backfill HASH PEER [PEER...] [replace]  HTTP fetch all chunks; quorum if multiple peers\n\
                         options: --json\n\
       operator push-chunks HASH PEER [PEER...]  P2P ChunkV1 gossip all artifact chunks to peers\n\
                         options: --json\n\
       operator inbox-status HASH DATA_DIR  list chunk-inbox indices for commitment\n\
                         options: --json\n\
       operator assemble-inbox HASH DATA_DIR [replace]  build wallet artifact from inbox\n\
                         options: --json\n"
}

pub(super) fn parse_args(args: &[String]) -> Result<Parsed, CliError> {
    let mut rpc_addr = DEFAULT_RPC_ADDR.to_string();
    let mut rpc_api_key: Option<String> = None;
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
        if a == "--rpc-api-key" {
            let Some(v) = args.get(i + 1) else {
                return Err(CliError::Usage("--rpc-api-key requires KEY".into()));
            };
            if v.is_empty() || v.starts_with('-') {
                return Err(CliError::Usage(
                    "expected non-empty KEY after --rpc-api-key".into(),
                ));
            }
            rpc_api_key = Some(v.clone());
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
                | "--key-derivation"
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
        "status" => {
            if positional.len() != 1 {
                return Err(CliError::Usage(format!(
                    "status takes no arguments\n{}",
                    usage()
                )));
            }
            Cmd::Status
        }
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
        rpc_api_key,
        wallet_path,
        cmd,
    })
}

pub(super) fn parse_claims_cmd(rest: &[&str]) -> Result<Cmd, CliError> {
    let Some(sub_name) = rest.first() else {
        return Err(CliError::Usage(format!(
            "claims requires SUBCOMMAND (for|recent|by-pubkey|roots)\n{}",
            usage()
        )));
    };
    let sub = match *sub_name {
        "for" => parse_claims_for_args(&rest[1..])?,
        "recent" => ClaimsSub::Recent(parse_claims_list_args(&rest[1..])?),
        "roots" => ClaimsSub::Roots(parse_claims_list_args(&rest[1..])?),
        "by-pubkey" => ClaimsSub::ByPubkey(parse_claims_by_pubkey_args(&rest[1..])?),
        other => {
            return Err(CliError::Usage(format!(
                "unknown claims subcommand `{other}`\n{}",
                usage()
            )));
        }
    };
    Ok(Cmd::Claims { sub })
}

pub(super) fn parse_uploads_cmd(rest: &[&str]) -> Result<Cmd, CliError> {
    let Some(sub_name) = rest.first() else {
        return Err(CliError::Usage(format!(
            "uploads requires SUBCOMMAND (list|local|status|retrieve|fetch-http)\n{}",
            usage()
        )));
    };
    let sub = match *sub_name {
        "list" => UploadsSub::List(parse_uploads_list_args(&rest[1..])?),
        "local" => UploadsSub::Local(parse_inventory_output_args("uploads local", &rest[1..])?),
        "status" => UploadsSub::Status(parse_inventory_output_args("uploads status", &rest[1..])?),
        "retrieve" => parse_uploads_retrieve_args(&rest[1..])?,
        "fetch-http" => parse_uploads_fetch_http_args(&rest[1..])?,
        other => {
            return Err(CliError::Usage(format!(
                "unknown uploads subcommand `{other}`\n{}",
                usage()
            )));
        }
    };
    Ok(Cmd::Uploads { sub })
}

pub(super) fn parse_inventory_output_args(
    command_name: &str,
    rest: &[&str],
) -> Result<UploadsInventoryParams, CliError> {
    let mut params = UploadsInventoryParams::default();
    for a in rest {
        match *a {
            "--json" => params.json = true,
            other => {
                return Err(CliError::Usage(format!(
                    "unknown {command_name} argument `{other}`\n{}",
                    usage()
                )));
            }
        }
    }
    Ok(params)
}

pub(super) fn parse_uploads_fetch_http_args(rest: &[&str]) -> Result<UploadsSub, CliError> {
    if rest.len() < 3 {
        return Err(CliError::Usage(format!(
            "uploads fetch-http requires COMMITMENT_HASH_HEX OUT PEER [PEER...] [replace] [--json]\n{}",
            usage()
        )));
    }
    let mut params = UploadsFetchHttpParams::default();
    let mut peers = Vec::new();
    for arg in &rest[2..] {
        match *arg {
            "replace" => params.force = true,
            "--json" => params.json = true,
            peer => peers.push(peer.to_string()),
        }
    }
    if peers.is_empty() {
        return Err(CliError::Usage(format!(
            "uploads fetch-http requires at least one PEER\n{}",
            usage()
        )));
    }
    Ok(UploadsSub::FetchHttp {
        commitment_hash_hex: rest[0].to_string(),
        output_path: std::path::PathBuf::from(rest[1]),
        peers,
        params,
    })
}

pub(super) fn parse_uploads_retrieve_args(rest: &[&str]) -> Result<UploadsSub, CliError> {
    if rest.len() < 2 || rest.len() > 3 {
        return Err(CliError::Usage(format!(
            "uploads retrieve requires COMMITMENT_HASH_HEX OUT [replace]\n{}",
            usage()
        )));
    }
    let force = matches!(rest.get(2), Some(&"replace"));
    if rest.len() == 3 && !force {
        return Err(CliError::Usage(format!(
            "uploads retrieve unknown modifier `{}` (expected `replace`)\n{}",
            rest[2],
            usage()
        )));
    }
    Ok(UploadsSub::Retrieve {
        commitment_hash_hex: rest[0].to_string(),
        output_path: std::path::PathBuf::from(rest[1]),
        force,
    })
}

pub(super) fn parse_operator_cmd(rest: &[&str]) -> Result<Cmd, CliError> {
    let Some(sub_name) = rest.first() else {
        return Err(CliError::Usage(format!(
            "operator requires SUBCOMMAND (challenge|prove|pool|artifacts|fetch-chunk|backfill|push-chunks|inbox-status|assemble-inbox)\n{}",
            usage()
        )));
    };
    let sub = match *sub_name {
        "challenge" => parse_operator_challenge_args(&rest[1..])?,
        "prove" => parse_operator_prove_args(&rest[1..])?,
        "pool" => OperatorSub::Pool(parse_operator_json_args("operator pool", &rest[1..])?),
        "artifacts" => OperatorSub::Artifacts(parse_inventory_output_args(
            "operator artifacts",
            &rest[1..],
        )?),
        "fetch-chunk" => parse_operator_fetch_chunk_args(&rest[1..])?,
        "backfill" => parse_operator_backfill_args(&rest[1..])?,
        "push-chunks" => parse_operator_push_chunks_args(&rest[1..])?,
        "inbox-status" => parse_operator_inbox_status_args(&rest[1..])?,
        "assemble-inbox" => parse_operator_assemble_inbox_args(&rest[1..])?,
        other => {
            return Err(CliError::Usage(format!(
                "unknown operator subcommand `{other}`\n{}",
                usage()
            )));
        }
    };
    Ok(Cmd::Operator { sub })
}

pub(super) fn parse_operator_challenge_args(rest: &[&str]) -> Result<OperatorSub, CliError> {
    let mut commitment_hash_hex: Option<String> = None;
    let mut json = false;
    for a in rest {
        if *a == "--json" {
            json = true;
            continue;
        }
        if a.starts_with('-') {
            return Err(CliError::Usage(format!(
                "unknown operator challenge option `{a}`\n{}",
                usage()
            )));
        }
        if commitment_hash_hex.is_some() {
            return Err(CliError::Usage(format!(
                "operator challenge accepts one COMMITMENT_HASH_HEX\n{}",
                usage()
            )));
        }
        commitment_hash_hex = Some((*a).to_string());
    }
    let Some(commitment_hash_hex) = commitment_hash_hex else {
        return Err(CliError::Usage(format!(
            "operator challenge requires COMMITMENT_HASH_HEX\n{}",
            usage()
        )));
    };
    Ok(OperatorSub::Challenge {
        commitment_hash_hex,
        params: OperatorJsonParams { json },
    })
}

pub(super) fn parse_operator_json_args(
    command: &str,
    rest: &[&str],
) -> Result<OperatorJsonParams, CliError> {
    let mut json = false;
    for a in rest {
        if *a == "--json" {
            json = true;
            continue;
        }
        return Err(CliError::Usage(format!(
            "unexpected argument `{a}` for {command}\n{}",
            usage()
        )));
    }
    Ok(OperatorJsonParams { json })
}

pub(super) fn parse_operator_prove_args(rest: &[&str]) -> Result<OperatorSub, CliError> {
    let mut commitment_hash_hex: Option<String> = None;
    let mut data_path: Option<std::path::PathBuf> = None;
    let mut json = false;
    for a in rest {
        if *a == "--json" {
            json = true;
            continue;
        }
        if a.starts_with('-') {
            return Err(CliError::Usage(format!(
                "unknown operator prove option `{a}`\n{}",
                usage()
            )));
        }
        if commitment_hash_hex.is_none() {
            commitment_hash_hex = Some((*a).to_string());
            continue;
        }
        if data_path.is_none() {
            data_path = Some(std::path::PathBuf::from(*a));
            continue;
        }
        return Err(CliError::Usage(format!(
            "operator prove accepts COMMITMENT_HASH_HEX [FILE]\n{}",
            usage()
        )));
    }
    let Some(commitment_hash_hex) = commitment_hash_hex else {
        return Err(CliError::Usage(format!(
            "operator prove requires COMMITMENT_HASH_HEX [FILE]\n\
             (omit FILE to load payload from --wallet upload artifact)\n{}",
            usage()
        )));
    };
    Ok(OperatorSub::Prove {
        commitment_hash_hex,
        data_path,
        params: OperatorJsonParams { json },
    })
}

pub(super) fn parse_operator_backfill_args(rest: &[&str]) -> Result<OperatorSub, CliError> {
    if rest.len() < 2 {
        return Err(CliError::Usage(format!(
            "operator backfill requires COMMITMENT_HASH_HEX PEER [PEER...] [replace] [--json]\n{}",
            usage()
        )));
    }
    let commitment_hash_hex = rest[0].to_string();
    let mut params = BackfillParams::default();
    let mut peers = Vec::new();
    for arg in &rest[1..] {
        match *arg {
            "replace" => params.force = true,
            "--json" => params.json = true,
            peer => peers.push(peer.to_string()),
        }
    }
    if peers.is_empty() {
        return Err(CliError::Usage(format!(
            "operator backfill requires at least one PEER\n{}",
            usage()
        )));
    }
    Ok(OperatorSub::Backfill {
        commitment_hash_hex,
        peers,
        params,
    })
}

pub(super) fn parse_operator_assemble_inbox_args(rest: &[&str]) -> Result<OperatorSub, CliError> {
    if rest.len() < 2 || rest.len() > 4 {
        return Err(CliError::Usage(format!(
            "operator assemble-inbox requires COMMITMENT_HASH_HEX DATA_DIR [replace] [--json]\n{}",
            usage()
        )));
    }
    let mut params = AssembleInboxParams::default();
    for modifier in &rest[2..] {
        match *modifier {
            "replace" => params.force = true,
            "--json" => params.json = true,
            other => {
                return Err(CliError::Usage(format!(
                    "operator assemble-inbox unknown modifier `{other}` (expected `replace` or `--json`)\n{}",
                    usage()
                )));
            }
        }
    }
    Ok(OperatorSub::AssembleInbox {
        commitment_hash_hex: rest[0].to_string(),
        data_dir: std::path::PathBuf::from(rest[1]),
        params,
    })
}

pub(super) fn parse_operator_inbox_status_args(rest: &[&str]) -> Result<OperatorSub, CliError> {
    if rest.len() < 2 || rest.len() > 3 {
        return Err(CliError::Usage(format!(
            "operator inbox-status requires COMMITMENT_HASH_HEX DATA_DIR [--json]\n{}",
            usage()
        )));
    }
    let mut params = InboxStatusParams::default();
    if let Some(extra) = rest.get(2) {
        if *extra != "--json" {
            return Err(CliError::Usage(format!(
                "operator inbox-status unknown modifier `{extra}` (expected `--json`)\n{}",
                usage()
            )));
        }
        params.json = true;
    }
    Ok(OperatorSub::InboxStatus {
        commitment_hash_hex: rest[0].to_string(),
        data_dir: std::path::PathBuf::from(rest[1]),
        params,
    })
}

pub(super) fn parse_operator_push_chunks_args(rest: &[&str]) -> Result<OperatorSub, CliError> {
    if rest.len() < 2 {
        return Err(CliError::Usage(format!(
            "operator push-chunks requires COMMITMENT_HASH_HEX PEER [PEER...] [--json]\n{}",
            usage()
        )));
    }
    let mut peers = Vec::new();
    let mut json = false;
    for a in &rest[1..] {
        if *a == "--json" {
            json = true;
            continue;
        }
        peers.push((*a).to_string());
    }
    if peers.is_empty() {
        return Err(CliError::Usage(format!(
            "operator push-chunks requires at least one PEER\n{}",
            usage()
        )));
    }
    Ok(OperatorSub::PushChunks {
        commitment_hash_hex: rest[0].to_string(),
        peers,
        params: OperatorJsonParams { json },
    })
}

pub(super) fn parse_operator_fetch_chunk_args(rest: &[&str]) -> Result<OperatorSub, CliError> {
    if rest.len() < 3 || rest.len() > 4 {
        return Err(CliError::Usage(format!(
            "operator fetch-chunk requires COMMITMENT_HASH_HEX CHUNK_INDEX PEER [--json]\n{}",
            usage()
        )));
    }
    let mut json = false;
    if let Some(extra) = rest.get(3) {
        if *extra != "--json" {
            return Err(CliError::Usage(format!(
                "operator fetch-chunk unknown modifier `{extra}` (expected `--json`)\n{}",
                usage()
            )));
        }
        json = true;
    }
    let chunk_index = rest[1]
        .parse()
        .map_err(|_| CliError::Usage(format!("invalid chunk index `{}`", rest[1])))?;
    Ok(OperatorSub::FetchChunk {
        commitment_hash_hex: rest[0].to_string(),
        chunk_index,
        peer: rest[2].to_string(),
        params: OperatorJsonParams { json },
    })
}

pub(super) fn parse_uploads_list_args(rest: &[&str]) -> Result<UploadsListParams, CliError> {
    let mut limit = None;
    let mut offset = None;
    let mut include_claims = false;
    let mut json = false;
    let mut i = 0usize;
    while i < rest.len() {
        let a = rest[i];
        if a == "--json" {
            json = true;
            i += 1;
            continue;
        }
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
        json,
    })
}

pub(super) fn parse_claims_for_args(rest: &[&str]) -> Result<ClaimsSub, CliError> {
    let mut data_root_hex: Option<String> = None;
    let mut json = false;
    for a in rest {
        if *a == "--json" {
            json = true;
            continue;
        }
        if a.starts_with('-') {
            return Err(CliError::Usage(format!(
                "unknown claims for option `{a}`\n{}",
                usage()
            )));
        }
        if data_root_hex.is_some() {
            return Err(CliError::Usage(format!(
                "claims for accepts one DATA_ROOT_HEX\n{}",
                usage()
            )));
        }
        data_root_hex = Some((*a).to_string());
    }
    let Some(data_root_hex) = data_root_hex else {
        return Err(CliError::Usage(format!(
            "claims for requires DATA_ROOT_HEX\n{}",
            usage()
        )));
    };
    Ok(ClaimsSub::For {
        data_root_hex,
        json,
    })
}

pub(super) fn parse_claims_list_args(rest: &[&str]) -> Result<ClaimsListParams, CliError> {
    let mut limit = None;
    let mut offset = None;
    let mut json = false;
    let mut i = 0usize;
    while i < rest.len() {
        let a = rest[i];
        if a == "--json" {
            json = true;
            i += 1;
            continue;
        }
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
    Ok(ClaimsListParams {
        limit,
        offset,
        json,
    })
}

pub(super) fn parse_claims_by_pubkey_args(rest: &[&str]) -> Result<ClaimsByPubkeyParams, CliError> {
    let mut limit = None;
    let mut json = false;
    let mut claim_pubkey_hex: Option<String> = None;
    let mut i = 0usize;
    while i < rest.len() {
        let a = rest[i];
        if a == "--json" {
            json = true;
            i += 1;
            continue;
        }
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
    Ok(ClaimsByPubkeyParams {
        claim_pubkey_hex: hex,
        limit,
        json,
    })
}

pub(super) fn parse_wallet_cmd(
    rest: &[&str],
    wallet_path: Option<String>,
    force: bool,
) -> Result<Cmd, CliError> {
    let Some(sub_name) = rest.first() else {
        return Err(CliError::Usage(format!(
            "wallet requires SUBCOMMAND (new|restore|address|scan|light-scan|balance|status|backup-info|send|upload|claim|export-trusted-summary|import-trusted-summary|show-trusted-summary|compare-trusted-summary)\n{}",
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
        "restore" => parse_wallet_restore_args(&rest[1..])?,
        "scan" => WalletSub::Scan(parse_wallet_scan_args(&rest[1..], "scan")?),
        "balance" => WalletSub::Balance(parse_wallet_scan_args(&rest[1..], "balance")?),
        "status" => WalletSub::Status(parse_wallet_status_args(&rest[1..])?),
        "backup-info" => WalletSub::BackupInfo(parse_wallet_backup_info_args(&rest[1..])?),
        "new" | "address" => {
            if rest.len() != 1 {
                return Err(CliError::Usage(format!(
                    "wallet {sub_name} takes no extra arguments\n{}",
                    usage()
                )));
            }
            match *sub_name {
                "new" => WalletSub::New,
                "address" => WalletSub::Address,
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

pub(super) fn parse_wallet_restore_args(rest: &[&str]) -> Result<WalletSub, CliError> {
    let mut seed_hex: Option<String> = None;
    let mut key_derivation = KeyDerivation::MfnWalletV1;
    let mut i = 0usize;
    while i < rest.len() {
        let a = rest[i];
        if a == "--key-derivation" {
            let Some(v) = rest.get(i + 1) else {
                return Err(CliError::Usage(
                    "wallet restore --key-derivation requires mfn_wallet_v1 or payout_stealth_v1\n"
                        .into(),
                ));
            };
            key_derivation = parse_key_derivation_label(v)?;
            i += 2;
            continue;
        }
        if a.starts_with('-') {
            return Err(CliError::Usage(format!(
                "unknown wallet restore argument `{a}`\n{}",
                usage()
            )));
        }
        if seed_hex.is_some() {
            return Err(CliError::Usage(format!(
                "wallet restore accepts exactly one SEED_HEX\n{}",
                usage()
            )));
        }
        seed_hex = Some(a.to_string());
        i += 1;
    }
    let Some(seed_hex) = seed_hex else {
        return Err(CliError::Usage(format!(
            "wallet restore requires SEED_HEX\n{}",
            usage()
        )));
    };
    Ok(WalletSub::Restore {
        seed_hex,
        key_derivation,
    })
}

pub(super) fn parse_wallet_backup_info_args(rest: &[&str]) -> Result<BackupInfoParams, CliError> {
    let mut params = BackupInfoParams::default();
    for a in rest {
        match *a {
            "--json" => params.json = true,
            other => {
                return Err(CliError::Usage(format!(
                    "unknown wallet backup-info argument `{other}`\n{}",
                    usage()
                )));
            }
        }
    }
    Ok(params)
}

pub(super) fn parse_wallet_scan_args(
    rest: &[&str],
    sub_name: &str,
) -> Result<WalletScanParams, CliError> {
    let mut params = WalletScanParams::default();
    for a in rest {
        match *a {
            "--json" => params.json = true,
            other => {
                return Err(CliError::Usage(format!(
                    "unknown wallet {sub_name} argument `{other}`\n{}",
                    usage()
                )));
            }
        }
    }
    Ok(params)
}

pub(super) fn parse_wallet_status_args(rest: &[&str]) -> Result<WalletStatusParams, CliError> {
    let mut params = WalletStatusParams::default();
    for a in rest {
        match *a {
            "--json" => params.json = true,
            other => {
                return Err(CliError::Usage(format!(
                    "unknown wallet status argument `{other}`\n{}",
                    usage()
                )));
            }
        }
    }
    Ok(params)
}

pub(super) fn parse_key_derivation_label(raw: &str) -> Result<KeyDerivation, CliError> {
    match raw {
        "mfn_wallet_v1" => Ok(KeyDerivation::MfnWalletV1),
        "payout_stealth_v1" => Ok(KeyDerivation::PayoutStealthV1),
        other => Err(CliError::Usage(format!(
            "unknown key derivation `{other}` (expected mfn_wallet_v1 or payout_stealth_v1)"
        ))),
    }
}

pub(super) fn parse_wallet_light_scan_args(rest: &[&str]) -> Result<LightScanParams, CliError> {
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

pub(super) fn parse_wallet_export_trusted_summary_args(
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

pub(super) fn parse_wallet_import_trusted_summary_args(
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

pub(super) fn parse_wallet_show_trusted_summary_args(
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

pub(super) fn parse_wallet_compare_trusted_summary_args(
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

pub(super) fn parse_wallet_send_args(rest: &[&str]) -> Result<SendParams, CliError> {
    let mut fee = DEFAULT_TRANSFER_FEE;
    let mut ring_size = DEFAULT_RING_SIZE;
    let mut extra: Vec<u8> = Vec::new();
    let mut json = false;
    let mut positional: Vec<&str> = Vec::new();
    let mut i = 0usize;
    while i < rest.len() {
        let a = rest[i];
        if a == "--json" {
            json = true;
            i += 1;
            continue;
        }
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
                .map_err(|_| CliError::Usage("--ring-size must be an integer ΓëÑ 2".into()))?;
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
    if positional.len() != 2 && positional.len() != 3 {
        return Err(CliError::Usage(format!(
            "wallet send requires ADDRESS AMOUNT or VIEW_HEX SPEND_HEX AMOUNT\n{}",
            usage()
        )));
    }
    let (to_view_hex, to_spend_hex, amount_raw) = if positional.len() == 2 {
        if !positional[0].starts_with(WALLET_ADDRESS_PREFIX) {
            return Err(CliError::Usage(format!(
                "wallet send ADDRESS form requires an `{WALLET_ADDRESS_PREFIX}`-prefixed address"
            )));
        }
        let (view, spend) = decode_wallet_address_to_hex(positional[0])
            .map_err(|e| CliError::Usage(e.to_string()))?;
        (view, spend, positional[1])
    } else {
        (
            positional[0].to_string(),
            positional[1].to_string(),
            positional[2],
        )
    };
    let amount: u64 = amount_raw
        .parse()
        .map_err(|_| CliError::Usage("AMOUNT must be a non-negative integer".into()))?;
    Ok(SendParams {
        to_view_hex,
        to_spend_hex,
        amount,
        fee,
        ring_size,
        extra,
        json,
    })
}

pub(super) fn parse_wallet_upload_args(rest: &[&str]) -> Result<UploadParams, CliError> {
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
    let mut json = false;
    let mut positional: Vec<&str> = Vec::new();
    let mut i = 0usize;
    while i < rest.len() {
        let a = rest[i];
        if a == "--json" {
            json = true;
            i += 1;
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
                .map_err(|_| CliError::Usage("--ring-size must be an integer ΓëÑ 2".into()))?;
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
        json,
    })
}

pub(super) fn parse_wallet_claim_args(rest: &[&str]) -> Result<ClaimParams, CliError> {
    let mut fee = DEFAULT_CLAIM_FEE;
    let mut ring_size = DEFAULT_RING_SIZE;
    let mut commit_hash_hex: Option<String> = None;
    let mut message: Option<Vec<u8>> = None;
    let mut json = false;
    let mut positional: Vec<&str> = Vec::new();
    let mut i = 0usize;
    while i < rest.len() {
        let a = rest[i];
        if a == "--json" {
            json = true;
            i += 1;
            continue;
        }
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
                .map_err(|_| CliError::Usage("--ring-size must be an integer ΓëÑ 2".into()))?;
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
        json,
    })
}
