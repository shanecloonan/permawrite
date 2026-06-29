# Collect participant-safe JSON diagnostics for public-devnet support.
param(
    [string]$Rpc = "",
    [string]$RpcApiKey = "",
    [string]$Wallet = "",
    [string]$CommitHash = "",
    [string]$DataRoot = "",
    [string]$ClaimPubkey = "",
    [string]$OutputDir = "",
    [switch]$NoBuild,
    [switch]$PlanOnly
)
$ErrorActionPreference = "Stop"

$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$RepoRoot = (Resolve-Path (Join-Path $ScriptDir "..\..")).Path
$PortsFile = Join-Path $ScriptDir "devnet-ports.env"

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
    throw "support-bundle: pass -Rpc HOST:PORT or run start-all.ps1 first"
}

function Resolve-Bin {
    $exe = if ($IsWindows -or $env:OS -eq "Windows_NT") { "mfn-cli.exe" } else { "mfn-cli" }
    $path = Join-Path $RepoRoot "target\release\$exe"
    if (-not (Test-Path $path)) {
        throw "support-bundle: missing $path; rerun without -NoBuild or build mfn-cli --release"
    }
    return $path
}

function Add-PlannedCommand {
    param([System.Collections.Generic.List[object]]$Commands, [string]$Name, [string[]]$CliArgs)
    $Commands.Add([pscustomobject]@{
        name = $Name
        cli_args = $CliArgs
    }) | Out-Null
}

function Get-PlannedCommands {
    param([string]$RpcAddr)
    $commands = New-Object System.Collections.Generic.List[object]
    $rpcArgs = @("--rpc", $RpcAddr)
    if ($RpcApiKey) { $rpcArgs += @("--rpc-api-key", $RpcApiKey) }
    Add-PlannedCommand $commands "uploads-list" ($rpcArgs + @("uploads", "list", "--include-claims", "--json"))
    Add-PlannedCommand $commands "operator-pool" ($rpcArgs + @("operator", "pool", "--json"))
    if ($Wallet) {
        Add-PlannedCommand $commands "wallet-status" ($rpcArgs + @("--wallet", $Wallet, "wallet", "status", "--json"))
        Add-PlannedCommand $commands "wallet-backup-info" @("--wallet", $Wallet, "wallet", "backup-info", "--json")
        Add-PlannedCommand $commands "uploads-local" @("--wallet", $Wallet, "uploads", "local", "--json")
        Add-PlannedCommand $commands "uploads-status" ($rpcArgs + @("--wallet", $Wallet, "uploads", "status", "--json"))
        Add-PlannedCommand $commands "operator-artifacts" @("--wallet", $Wallet, "operator", "artifacts", "--json")
    }
    if ($CommitHash) {
        Add-PlannedCommand $commands "operator-challenge" ($rpcArgs + @("operator", "challenge", $CommitHash, "--json"))
    }
    if ($DataRoot) {
        Add-PlannedCommand $commands "claims-for" ($rpcArgs + @("claims", "for", $DataRoot, "--json"))
    }
    if ($ClaimPubkey) {
        Add-PlannedCommand $commands "claims-by-pubkey" ($rpcArgs + @("claims", "by-pubkey", $ClaimPubkey, "--json"))
    }
    return $commands
}

function Invoke-BundleCommand {
    param([string]$MfnCli, [string]$BundleDir, [string]$Name, [string[]]$CliArgs)
    $stdoutFile = Join-Path $BundleDir "$Name.json"
    $stderrFile = Join-Path $BundleDir "$Name.err.txt"
    New-Item -ItemType File -Force -Path $stdoutFile | Out-Null
    New-Item -ItemType File -Force -Path $stderrFile | Out-Null
    & $MfnCli @CliArgs 2> $stderrFile | Set-Content -Path $stdoutFile -Encoding utf8
    $code = $LASTEXITCODE
    $stderrLen = (Get-Item $stderrFile).Length
    if ($stderrLen -eq 0) { Remove-Item $stderrFile }
    return [pscustomobject]@{
        name = $Name
        exit_code = $code
        stdout = (Split-Path -Leaf $stdoutFile)
        stderr = if ($stderrLen -eq 0) { $null } else { (Split-Path -Leaf $stderrFile) }
    }
}

function Format-DisplayArgs {
    param([string[]]$CliArgs)
    $display = New-Object System.Collections.Generic.List[string]
    $skipValue = $false
    foreach ($arg in $CliArgs) {
        if ($skipValue) {
            $display.Add("<KEY>") | Out-Null
            $skipValue = $false
            continue
        }
        $display.Add($arg) | Out-Null
        if ($arg -eq "--rpc-api-key") { $skipValue = $true }
    }
    return ($display -join " ")
}

$RpcAddr = Resolve-Rpc
$planned = Get-PlannedCommands $RpcAddr

if ($PlanOnly) {
    $walletText = if ($Wallet) { $Wallet } else { "<none; wallet-local diagnostics skipped>" }
    $commitText = if ($CommitHash) { $CommitHash } else { "<none; challenge diagnostics skipped>" }
    $dataRootText = if ($DataRoot) { $DataRoot } else { "<none; claims-for skipped>" }
    $claimPubkeyText = if ($ClaimPubkey) { $ClaimPubkey } else { "<none; claims-by-pubkey skipped>" }
    Write-Host "support-bundle: plan"
    Write-Host "  rpc=$RpcAddr"
    Write-Host "  rpc_api_key_set=$([bool]$RpcApiKey)"
    Write-Host "  wallet=$walletText"
    Write-Host "  commit_hash=$commitText"
    Write-Host "  data_root=$dataRootText"
    Write-Host "  claim_pubkey=$claimPubkeyText"
    foreach ($cmd in $planned) {
        Write-Host "  mfn-cli $(Format-DisplayArgs $cmd.cli_args) > $($cmd.name).json"
    }
    Write-Host "  note=commands are read-only/local-inspection; this script does not send funds, scan wallets, upload data, or submit proofs"
    exit 0
}

Push-Location $RepoRoot
try {
    if (-not $NoBuild) {
        cargo build -p mfn-cli --release --bin mfn-cli
    }
    $MfnCli = Resolve-Bin
    $BundleDir = if ($OutputDir) {
        $OutputDir
    } else {
        $stamp = (Get-Date).ToUniversalTime().ToString("yyyyMMddTHHmmssZ")
        Join-Path $ScriptDir "support-bundle\$stamp"
    }
    New-Item -ItemType Directory -Force -Path $BundleDir | Out-Null

    $results = New-Object System.Collections.Generic.List[object]
    foreach ($cmd in $planned) {
        Write-Host "support-bundle: capture=$($cmd.name)"
        $results.Add((Invoke-BundleCommand $MfnCli $BundleDir $cmd.name $cmd.cli_args)) | Out-Null
    }

    $manifest = [pscustomobject]@{
        generated_at_utc = (Get-Date).ToUniversalTime().ToString("o")
        rpc = $RpcAddr
        rpc_api_key_set = [bool]$RpcApiKey
        wallet = if ($Wallet) { $Wallet } else { $null }
        commit_hash = if ($CommitHash) { $CommitHash } else { $null }
        data_root = if ($DataRoot) { $DataRoot } else { $null }
        claim_pubkey = if ($ClaimPubkey) { $ClaimPubkey } else { $null }
        read_only = $true
        commands = $results
    }
    $manifest | ConvertTo-Json -Depth 8 | Set-Content -Path (Join-Path $BundleDir "manifest.json") -Encoding utf8
    Write-Host "support-bundle: output_dir=$BundleDir"
    if (($results | Where-Object { $_.exit_code -ne 0 }).Count -gt 0) {
        throw "support-bundle: one or more captures failed; inspect manifest.json and *.err.txt"
    }
} finally {
    Pop-Location
}
