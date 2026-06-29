# Full participant rehearsal: fund wallet -> upload -> restore -> verify -> prove -> support bundle.
param(
    [string]$Rpc = "",
    [string]$FaucetWallet = "",
    [string]$RehearsalDir = "",
    [string]$PayloadPath = "",
    [string]$ChunkListen = "127.0.0.1:18780",
    [UInt64]$Amount = 1000000,
    [UInt64]$Fee = 10000,
    [int]$RingSize = 8,
    [int]$WaitMinedSeconds = 180,
    [int]$WaitUploadSeconds = 180,
    [int]$WaitProofSeconds = 180,
    [string]$BundleDir = "",
    [switch]$NoBuild,
    [switch]$PlanOnly
)
$ErrorActionPreference = "Stop"

$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$RepoRoot = (Resolve-Path (Join-Path $ScriptDir "..\..")).Path
$PortsFile = Join-Path $ScriptDir "devnet-ports.env"
$Root = if ($RehearsalDir) { $RehearsalDir } else { Join-Path $ScriptDir "participant-rehearsal" }
$UploaderWallet = Join-Path $Root "uploader.json"
$ReplicaWallet = Join-Path $Root "replica.json"

function Read-PortsFile {
    if (-not (Test-Path $PortsFile)) { return @{} }
    $ports = @{}
    Get-Content $PortsFile | ForEach-Object {
        if ($_ -match "^([^=]+)=(.*)$") { $ports[$Matches[1]] = $Matches[2] }
    }
    return $ports
}

function Resolve-Rpc {
    if ($Rpc) { return $Rpc }
    $ports = Read-PortsFile
    if ($ports["HUB_RPC"]) { return $ports["HUB_RPC"] }
    throw "participant-rehearsal: pass -Rpc HOST:PORT or run start-all.ps1 first"
}

function Invoke-ScriptChecked {
    param([string]$Script, [string[]]$Args, [string]$Label)
    $out = & $Script @Args 2>&1
    $code = $LASTEXITCODE
    $text = ($out | Out-String).Trim()
    if ($code -ne 0) {
        throw "participant-rehearsal: $Label failed with exit=$code`n$text"
    }
    if ($text) { Write-Host $text }
    return $text
}

function Parse-TokenField {
    param([string]$Text, [string]$Key)
    $pattern = "(^|\s)$([regex]::Escape($Key))=([^\s]+)"
    $match = [regex]::Match($Text, $pattern)
    if (-not $match.Success) {
        throw "participant-rehearsal: stdout missing $Key=<value>`n$Text"
    }
    return $match.Groups[3].Value
}

if ($Amount -eq 0) { throw "Amount must be greater than 0" }
if ($RingSize -lt 2) { throw "RingSize must be >= 2" }
if ($WaitMinedSeconds -lt 0) { throw "WaitMinedSeconds must be >= 0" }
if ($WaitUploadSeconds -lt 1) { throw "WaitUploadSeconds must be >= 1" }
if ($WaitProofSeconds -lt 0) { throw "WaitProofSeconds must be >= 0" }

if ($PlanOnly) {
    $planRpc = try { Resolve-Rpc } catch { "<pass -Rpc HOST:PORT or run start-all.ps1>" }
    $planFaucet = if ($FaucetWallet) { $FaucetWallet } else { "<required -FaucetWallet PATH for real run>" }
    Write-Host "participant-rehearsal: plan"
    Write-Host "  rpc=$planRpc"
    Write-Host "  rehearsal_dir=$Root"
    Write-Host "  faucet_wallet=$planFaucet"
    Write-Host "  uploader_wallet=$UploaderWallet"
    Write-Host "  replica_wallet=$ReplicaWallet"
    Write-Host "  chunk_listen=$ChunkListen"
    Write-Host "  flow=fund-wallet -> permanence-demo upload/discover/fetch-http/prove/hash-check -> support-bundle"
    Write-Host "  note=real mode requires a funded faucet wallet with public-devnet/test funds only"
    exit 0
}

if (-not $FaucetWallet) { throw "participant-rehearsal: -FaucetWallet PATH is required outside -PlanOnly" }
if (-not (Test-Path $FaucetWallet)) { throw "participant-rehearsal: faucet wallet not found: $FaucetWallet" }

$RpcAddr = Resolve-Rpc
New-Item -ItemType Directory -Force -Path $Root | Out-Null

Push-Location $RepoRoot
try {
    if (-not $NoBuild) {
        cargo build -p mfn-cli --release --bin mfn-cli
        if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
        cargo build -p mfn-storage-operator --release --bin mfn-storage-operator
        if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
    }

    $fundScript = Join-Path $ScriptDir "fund-wallet.ps1"
    $fundArgs = @(
        "-Rpc", $RpcAddr,
        "-FaucetWallet", $FaucetWallet,
        "-RecipientWallet", $UploaderWallet,
        "-Amount", "$Amount",
        "-Fee", "$Fee",
        "-RingSize", "$RingSize",
        "-WaitMinedSeconds", "$WaitMinedSeconds",
        "-NoBuild"
    )
    Invoke-ScriptChecked $fundScript $fundArgs "fund-wallet" | Out-Null

    $demoScript = Join-Path $ScriptDir "permanence-demo.ps1"
    $demoArgs = @(
        "-Rpc", $RpcAddr,
        "-WalletDir", $Root,
        "-ChunkListen", $ChunkListen,
        "-WaitUploadSeconds", "$WaitUploadSeconds",
        "-WaitProofSeconds", "$WaitProofSeconds",
        "-NoBuild"
    )
    if ($PayloadPath) { $demoArgs += @("-PayloadPath", $PayloadPath) }
    $demoOut = Invoke-ScriptChecked $demoScript $demoArgs "permanence-demo"
    $commit = Parse-TokenField $demoOut "commitment_hash"
    $restoredSha = Parse-TokenField $demoOut "restored_sha256"
    $restoredPath = Parse-TokenField $demoOut "restored_path"

    $supportScript = Join-Path $ScriptDir "support-bundle.ps1"
    $supportArgs = @(
        "-Rpc", $RpcAddr,
        "-Wallet", $ReplicaWallet,
        "-CommitHash", $commit,
        "-NoBuild"
    )
    if ($BundleDir) { $supportArgs += @("-OutputDir", $BundleDir) }
    $supportOut = Invoke-ScriptChecked $supportScript $supportArgs "support-bundle"
    $bundle = Parse-TokenField $supportOut "output_dir"

    Write-Host "participant-rehearsal: PASS commitment_hash=$commit restored_sha256=$restoredSha restored_path=$restoredPath support_bundle=$bundle"
} finally {
    Pop-Location
}
