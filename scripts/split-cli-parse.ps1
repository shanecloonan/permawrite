# Extract mfn-cli/src/cli/parse.rs and shrink cli.rs (B-07). Source: HEAD monolith only.
$ErrorActionPreference = "Stop"
$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
Set-Location $repoRoot

& (Join-Path $PSScriptRoot "gen-cli-parse.ps1")

$orig = @(git show HEAD:mfn-cli/src/cli.rs)
$src = Join-Path $repoRoot "mfn-cli/src/cli.rs"

$trimImports = @(
    "use std::process::ExitCode;",
    "",
    "use serde_json::json;",
    "",
    "use crate::claims_cmd::{claims_by_pubkey, claims_for, claims_recent, claims_roots};",
    "use crate::light_subjectivity::{",
    "    wallet_compare_trusted_summary, wallet_export_trusted_summary, wallet_import_trusted_summary,",
    "    wallet_show_trusted_summary,",
    "};",
    "use crate::light_wallet::wallet_light_scan;",
    "use crate::operator_cmd::{",
    "    operator_artifacts, operator_assemble_inbox, operator_backfill, operator_challenge,",
    "    operator_fetch_chunk, operator_inbox_status, operator_pool, operator_prove,",
    "    operator_push_chunks, OperatorCmdError,",
    "};",
    "use crate::rpc::RpcClient;",
    "use crate::uploads_cmd::{",
    "    uploads_fetch_http, uploads_list, uploads_local, uploads_retrieve, uploads_status,",
    "};",
    "use crate::wallet_cmd::{",
    "    resolve_wallet_path, wallet_address, wallet_backup_info, wallet_balance, wallet_claim,",
    "    wallet_new, wallet_restore, wallet_scan, wallet_send, wallet_status, wallet_upload,",
    "    WalletCmdError,",
    "};",
    ""
)

$mods = @(
    "",
    "#[path = `"cli/parse.rs`"]",
    "mod parse;",
    "",
    "use parse::{parse_args, Cmd, ClaimsSub, MFN_RPC_API_KEY, OperatorSub, UploadsSub, WalletSub};",
    ""
)

$out = New-Object System.Collections.Generic.List[string]
$out.Add($orig[0])
$out.Add($orig[1])
$out.AddRange([string[]]$trimImports)
for ($i = 36; $i -le 304; $i++) { $out.Add($orig[$i]) }
$out.AddRange([string[]]$mods)
for ($i = 2044; $i -lt $orig.Length; $i++) { $out.Add($orig[$i]) }

$utf8 = New-Object System.Text.UTF8Encoding $false
[System.IO.File]::WriteAllLines($src, $out, $utf8)
Write-Host "cli.rs: $($orig.Length) -> $($out.Count) lines"
