# Generate mfn-cli/src/cli/parse.rs from HEAD cli.rs (B-07 split).
$ErrorActionPreference = "Stop"
$root = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
Set-Location $root

$orig = @(git show HEAD:mfn-cli/src/cli.rs)
$body = $orig[306..2043]

$header = @(
    "//! CLI argument parsing for ``mfn-cli``.",
    "",
    "use crate::claims_cmd::{ClaimsByPubkeyParams, ClaimsListParams};",
    "use crate::light_subjectivity::{",
    "    CompareTrustedSummaryParams, ExportTrustedSummaryParams, ImportTrustedSummaryParams,",
    "    ShowTrustedSummaryParams,",
    "};",
    "use crate::light_wallet::LightScanParams;",
    "use crate::operator_cmd::{",
    "    AssembleInboxParams, BackfillParams, InboxStatusParams, OperatorJsonParams,",
    "};",
    "use crate::rpc::DEFAULT_RPC_ADDR;",
    "use crate::uploads_cmd::{UploadsFetchHttpParams, UploadsInventoryParams, UploadsListParams};",
    "use crate::wallet_cmd::{",
    "    decode_wallet_address_to_hex, BackupInfoParams, ClaimParams, SendParams, UploadParams,",
    "    WalletScanParams, WalletStatusParams, DEFAULT_CLAIM_FEE, DEFAULT_RING_SIZE,",
    "    DEFAULT_TRANSFER_FEE, DEFAULT_UPLOAD_ANCHOR_VALUE, DEFAULT_UPLOAD_REPLICATION,",
    "    WALLET_ADDRESS_PREFIX,",
    "};",
    "use crate::wallet_store::KeyDerivation;",
    "",
    "use super::CliError;",
    ""
)

$out = New-Object System.Collections.Generic.List[string]
foreach ($h in $header) { $out.Add($h) }
$inParsed = $false
foreach ($line in $body) {
    if ($line -ceq "struct Parsed {") { $inParsed = $true }
    if ($inParsed -and $line -ceq "}") { $inParsed = $false }

    if ($line -ceq "enum Cmd {") {
        $out.Add("pub(crate) enum Cmd {")
    }
    elseif ($line -clike "enum ClaimsSub*") { $out.Add("pub(crate) $line") }
    elseif ($line -clike "enum UploadsSub*") { $out.Add("pub(crate) $line") }
    elseif ($line -clike "enum OperatorSub*") { $out.Add("pub(crate) $line") }
    elseif ($line -clike "enum WalletSub*") { $out.Add("pub(crate) $line") }
    elseif ($line -clike "struct Parsed*") { $out.Add("pub(crate) $line") }
    elseif ($line -ceq "    rpc_addr: String,") { $out.Add("    pub(crate) rpc_addr: String,") }
    elseif ($line -ceq "    rpc_api_key: Option<String>,") { $out.Add("    pub(crate) rpc_api_key: Option<String>,") }
    elseif ($line -ceq "    wallet_path: Option<String>," -and $inParsed) { $out.Add("    pub(crate) wallet_path: Option<String>,") }
    elseif ($line -ceq "    cmd: Cmd,") { $out.Add("    pub(crate) cmd: Cmd,") }
    elseif ($line -clike "const MFN_RPC_API_KEY*") { $out.Add("pub(crate) $line") }
    elseif ($line -clike "fn parse_*") { $out.Add("pub(super) $line") }
    elseif ($line -ceq "fn parse_args(args: &[String]) -> Result<Parsed, CliError> {") { $out.Add("pub(super) $line") }
    elseif ($line -clike "fn usage()*") { $out.Add("pub(super) $line") }
    else { $out.Add($line) }
}

$dir = Join-Path $root "mfn-cli/src/cli"
New-Item -ItemType Directory -Force -Path $dir | Out-Null
$utf8 = New-Object System.Text.UTF8Encoding $false
[System.IO.File]::WriteAllLines((Join-Path $dir "parse.rs"), $out, $utf8)
Write-Host "Wrote $($out.Count) lines to mfn-cli/src/cli/parse.rs"
