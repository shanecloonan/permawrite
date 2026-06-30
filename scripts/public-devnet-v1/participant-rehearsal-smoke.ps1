# Real-run local smoke for participant-rehearsal against the public-devnet helper mesh.
param(
    [string]$Rpc = "",
    [string]$FaucetWallet = "",
    [string]$RehearsalDir = "",
    [int]$WaitAfterStartSeconds = 30,
    [int]$WaitMinedSeconds = 240,
    [int]$WaitUploadSeconds = 240,
    [int]$WaitProofSeconds = 240,
    [switch]$NoStart,
    [switch]$NoStop,
    [switch]$NoBuild,
    [switch]$PlanOnly
)
$ErrorActionPreference = "Stop"

$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$RepoRoot = (Resolve-Path (Join-Path $ScriptDir "..\..")).Path
$PortsFile = Join-Path $ScriptDir "devnet-ports.env"
$SmokeRoot = if ($RehearsalDir) { $RehearsalDir } else { Join-Path $ScriptDir "participant-rehearsal-smoke" }
$Faucet = if ($FaucetWallet) { $FaucetWallet } else { Join-Path $SmokeRoot "validator0-faucet.json" }
$UseBundledTestFaucet = -not $FaucetWallet
$RunDir = Join-Path $SmokeRoot "run"
$TestFaucetSeed = "6565656565656565656565656565656565656565656565656565656565656565"

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
    throw "participant-rehearsal-smoke: missing HUB_RPC; run start-all.ps1 or omit -NoStart"
}

function Resolve-MfnCli {
    $exe = if ($IsWindows -or $env:OS -eq "Windows_NT") { "mfn-cli.exe" } else { "mfn-cli" }
    $releaseDir = Join-Path (Join-Path $RepoRoot "target") "release"
    $path = Join-Path $releaseDir $exe
    if (-not (Test-Path $path)) { throw "participant-rehearsal-smoke: missing $path after build" }
    return $path
}

if ($WaitAfterStartSeconds -lt 0) { throw "WaitAfterStartSeconds must be >= 0" }
if ($WaitMinedSeconds -lt 0) { throw "WaitMinedSeconds must be >= 0" }
if ($WaitUploadSeconds -lt 1) { throw "WaitUploadSeconds must be >= 1" }
if ($WaitProofSeconds -lt 0) { throw "WaitProofSeconds must be >= 0" }

if ($PlanOnly) {
    $planRpc = try { Resolve-Rpc } catch { if ($NoStart) { "<existing HUB_RPC or -Rpc required>" } else { "<start-all.ps1 will write HUB_RPC>" } }
    Write-Host "participant-rehearsal-smoke: plan"
    Write-Host "  rpc=$planRpc"
    Write-Host "  smoke_dir=$SmokeRoot"
    Write-Host "  faucet_wallet=$Faucet"
    Write-Host "  rehearsal_dir=$RunDir"
    Write-Host "  flow=stop stale mesh -> start-all -> restore/check test faucet -> participant-rehearsal -> stop mesh"
    Write-Host "  warning=default wallet uses public validator-0 test payout seed only for local/public devnet rehearsal; custom faucet wallets are never overwritten"
    exit 0
}

$startedMesh = $false
Push-Location $RepoRoot
try {
    New-Item -ItemType Directory -Force -Path $SmokeRoot | Out-Null
    if (-not $NoStart) {
        powershell -NoProfile -File (Join-Path $ScriptDir "stop-all.ps1") -AllMfnd
        powershell -NoProfile -File (Join-Path $ScriptDir "start-all.ps1")
        $startedMesh = $true
        if ($WaitAfterStartSeconds -gt 0) { Start-Sleep -Seconds $WaitAfterStartSeconds }
    }
    $RpcAddr = Resolve-Rpc

    if (-not $NoBuild) {
        cargo build -p mfn-cli --release --bin mfn-cli
        if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
        cargo build -p mfn-storage-operator --release --bin mfn-storage-operator
        if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
    }
    $MfnCli = Resolve-MfnCli
    if ($UseBundledTestFaucet) {
        & $MfnCli --wallet $Faucet --force wallet restore $TestFaucetSeed --key-derivation payout_stealth_v1
        if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
    } elseif (-not (Test-Path $Faucet)) {
        throw "participant-rehearsal-smoke: faucet wallet not found: $Faucet"
    }
    & $MfnCli --rpc $RpcAddr --wallet $Faucet wallet scan | Out-Null
    if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
    $balanceOut = & $MfnCli --rpc $RpcAddr --wallet $Faucet wallet balance
    if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
    $balanceText = ($balanceOut | Out-String)
    if ($balanceText -notmatch "(^|\s)balance=(\d+)") {
        throw "participant-rehearsal-smoke: faucet wallet balance output missing balance=<value>`n$balanceText"
    }
    $faucetBalance = [UInt64]$Matches[2]
    Write-Host "participant-rehearsal-smoke: faucet_balance=$faucetBalance"
    if ($faucetBalance -eq 0) {
        throw "participant-rehearsal-smoke: faucet wallet has zero spendable balance after scan; fund the faucet on this devnet or rerun with -FaucetWallet pointing at a funded operator wallet"
    }

    powershell -NoProfile -File (Join-Path $ScriptDir "participant-rehearsal.ps1") `
        -Rpc $RpcAddr `
        -FaucetWallet $Faucet `
        -RehearsalDir $RunDir `
        -WaitMinedSeconds $WaitMinedSeconds `
        -WaitUploadSeconds $WaitUploadSeconds `
        -WaitProofSeconds $WaitProofSeconds `
        -NoBuild
    if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
    Write-Host "participant-rehearsal-smoke: PASS rpc=$RpcAddr rehearsal_dir=$RunDir"
} finally {
    if ($startedMesh -and -not $NoStop) {
        powershell -NoProfile -File (Join-Path $ScriptDir "stop-all.ps1")
    }
    Pop-Location
}
