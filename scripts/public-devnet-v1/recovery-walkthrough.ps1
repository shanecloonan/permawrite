# Guided recovery: support bundle -> recovery plan -> restore -> hash verify -> optional proof.
param(
    [string]$Rpc = "127.0.0.1:<RPC>",
    [string]$RpcApiKey = "",
    [string]$Wallet = "./wallet.json",
    [string]$CommitHash = "<COMMIT_HASH_HEX>",
    [string[]]$Peer = @(),
    [string]$DataDir = "",
    [string]$OutputPath = "./restored.bin",
    [string]$ExpectedSha256 = "",
    [string]$BundleDir = "",
    [switch]$Replace,
    [switch]$Prove,
    [switch]$NoBuild,
    [switch]$PlanOnly
)
$ErrorActionPreference = "Stop"

$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$RepoRoot = (Resolve-Path (Join-Path $ScriptDir "..\..")).Path

function Resolve-Bin {
    $exe = if ($IsWindows -or $env:OS -eq "Windows_NT") { "mfn-cli.exe" } else { "mfn-cli" }
    $path = Join-Path $RepoRoot "target\release\$exe"
    if (-not (Test-Path $path)) {
        throw "recovery-walkthrough: missing $path; rerun without -NoBuild or build mfn-cli --release"
    }
    return $path
}

function Invoke-Checked {
    param([string]$Exe, [string[]]$CliArgs, [string]$Label)
    $oldErrorActionPreference = $ErrorActionPreference
    $ErrorActionPreference = "Continue"
    try {
        $out = & $Exe @CliArgs 2>&1
    } finally {
        $ErrorActionPreference = $oldErrorActionPreference
    }
    $code = $LASTEXITCODE
    $text = ($out | Out-String).Trim()
    if ($code -ne 0) {
        throw "recovery-walkthrough: $Label failed with exit=$code`n$text"
    }
    if ($text) { Write-Host $text }
}

$restoreMode = if ($Peer.Count -gt 0) {
    "http"
} elseif ($DataDir) {
    "p2p-inbox"
} else {
    "none"
}

if ($PlanOnly) {
    Write-Host "recovery-walkthrough: plan"
    Write-Host "  rpc=$Rpc"
    Write-Host "  rpc_api_key_set=$([bool]$RpcApiKey)"
    Write-Host "  wallet=$Wallet"
    Write-Host "  commit_hash=$CommitHash"
    Write-Host "  restore_mode=$restoreMode"
    Write-Host "  output_path=$OutputPath"
    Write-Host "  expected_sha256=$(if ($ExpectedSha256) { $ExpectedSha256.ToLowerInvariant() } else { '<not checked>' })"
    Write-Host "  flow=support-bundle -> recovery-plan -> restore -> optional sha256 verify -> optional operator prove"
    Write-Host "  note=real mode mutates only wallet-local artifact/output files, and only proves when -Prove is set"
    exit 0
}

if ($restoreMode -eq "none") {
    throw "recovery-walkthrough: pass at least one -Peer for HTTP restore or -DataDir for P2P inbox restore"
}

Push-Location $RepoRoot
try {
    if (-not $NoBuild) {
        cargo build -p mfn-cli --release --bin mfn-cli
    }
    $MfnCli = Resolve-Bin

    $supportBundle = Join-Path $ScriptDir "support-bundle.ps1"
    $supportArgs = @("-Rpc", $Rpc, "-Wallet", $Wallet, "-CommitHash", $CommitHash, "-NoBuild")
    if ($RpcApiKey) { $supportArgs += @("-RpcApiKey", $RpcApiKey) }
    if ($Peer.Count -gt 0) { $supportArgs += @("-Peer", $Peer[0]) }
    if ($DataDir) { $supportArgs += @("-DataDir", $DataDir) }
    if ($BundleDir) { $supportArgs += @("-OutputDir", $BundleDir) }
    & $supportBundle @supportArgs
    if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

    $recoveryPlan = Join-Path $ScriptDir "recovery-plan.ps1"
    $planArgs = @("-Rpc", $Rpc, "-Wallet", $Wallet, "-CommitHash", $CommitHash, "-OutputPath", $OutputPath)
    foreach ($p in $Peer) { $planArgs += @("-Peer", $p) }
    if ($DataDir) { $planArgs += @("-DataDir", $DataDir) }
    if ($Replace) { $planArgs += "-Replace" }
    & $recoveryPlan @planArgs
    if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

    $rpcArgs = @("--rpc", $Rpc)
    if ($RpcApiKey) { $rpcArgs += @("--rpc-api-key", $RpcApiKey) }

    if ($restoreMode -eq "http") {
        $args = $rpcArgs + @("--wallet", $Wallet, "uploads", "fetch-http", $CommitHash, $OutputPath) + $Peer
        if ($Replace) { $args += "replace" }
        $args += "--json"
        Invoke-Checked $MfnCli $args "uploads fetch-http"
    } else {
        Invoke-Checked $MfnCli ($rpcArgs + @("operator", "inbox-status", $CommitHash, $DataDir, "--json")) "operator inbox-status"
        $assembleArgs = $rpcArgs + @("--wallet", $Wallet, "operator", "assemble-inbox", $CommitHash, $DataDir)
        if ($Replace) { $assembleArgs += "replace" }
        $assembleArgs += "--json"
        Invoke-Checked $MfnCli $assembleArgs "operator assemble-inbox"
        $retrieveArgs = @("--wallet", $Wallet, "uploads", "retrieve", $CommitHash, $OutputPath)
        if ($Replace) { $retrieveArgs += "replace" }
        Invoke-Checked $MfnCli $retrieveArgs "uploads retrieve"
    }

    $restoredSha = (Get-FileHash -Algorithm SHA256 $OutputPath).Hash.ToLowerInvariant()
    if ($ExpectedSha256 -and $restoredSha -ne $ExpectedSha256.ToLowerInvariant()) {
        throw "recovery-walkthrough: restored hash mismatch expected=$($ExpectedSha256.ToLowerInvariant()) restored=$restoredSha"
    }
    Write-Host "recovery-walkthrough: restored_sha256=$restoredSha"

    if ($Prove) {
        Invoke-Checked $MfnCli ($rpcArgs + @("--wallet", $Wallet, "operator", "prove", $CommitHash, "--json")) "operator prove"
    }

    Write-Host "recovery-walkthrough: PASS output_path=$OutputPath"
} finally {
    Pop-Location
}
