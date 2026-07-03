# Real-run local smoke for participant-rehearsal against the public-devnet helper mesh.
param(
    [string]$Rpc = "",
    [string]$FaucetWallet = "",
    [string]$RehearsalDir = "",
    [int]$WaitAfterStartSeconds = -1,
    [int]$WaitFaucetSeconds = 240,
    [int]$WaitMinedSeconds = 240,
    [int]$WaitUploadSeconds = 360,
    [int]$WaitProofSeconds = 240,
    [int]$MinHubHeight = 0,
    [int]$WaitMinHubHeightSeconds = 180,
    [int]$WaitObserverCatchUpSeconds = 180,
    [switch]$WithObserver,
    [switch]$NoStart,
    [switch]$NoStop,
    [switch]$NoBuild,
    [switch]$PlanOnly,
    [switch]$ArchiveEvidence
)
$ErrorActionPreference = "Stop"

$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$RepoRoot = (Resolve-Path (Join-Path $ScriptDir "..\..")).Path
$PortsFile = Join-Path $ScriptDir "devnet-ports.env"
. (Join-Path $ScriptDir "ports-env-lib.ps1")
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

function Get-WalletBalance {
    param([string]$MfnCli, [string]$RpcAddr, [string]$WalletPath)
    & $MfnCli --rpc $RpcAddr --wallet $WalletPath wallet scan | Out-Null
    if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
    $balanceOut = & $MfnCli --rpc $RpcAddr --wallet $WalletPath wallet balance
    if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
    $balanceText = ($balanceOut | Out-String)
    if ($balanceText -notmatch "(^|\s)balance=(\d+)") {
        throw "participant-rehearsal-smoke: faucet wallet balance output missing balance=<value>`n$balanceText"
    }
    return [UInt64]$Matches[2]
}

function Get-TipHeightText {
    param([string]$MfnCli, [string]$RpcAddr)
    $tipOut = & $MfnCli --rpc $RpcAddr tip 2>$null
    if ($LASTEXITCODE -ne 0) { return "unknown" }
    $tipText = ($tipOut | Out-String)
    if ($tipText -match "(^|\s)tip_height=([0-9]+)") { return $Matches[2] }
    if ($tipText -match "(^|\s)tip_height=none") { return "0" }
    return "unknown"
}

function Archive-RehearsalSmokeEvidence {
    param(
        [string]$RpcAddr,
        [string]$FinalHubHeight,
        [string]$ObserverRpc,
        [string]$ObserverHeight
    )
    $evidenceDir = Join-Path $ScriptDir "evidence"
    New-Item -ItemType Directory -Force -Path $evidenceDir | Out-Null
    $observerLabel = if ($WithObserver) { "observer" } else { "no-observer" }
    $stamp = (Get-Date).ToUniversalTime().ToString("yyyyMMddTHHmmssZ")
    $path = Join-Path $evidenceDir "participant-rehearsal-$observerLabel-windows-$stamp.txt"
    $commit = ""
    try {
        Push-Location $RepoRoot
        $commit = (git rev-parse --short HEAD 2>$null)
    } finally {
        Pop-Location
    }
    $cmd = "participant-rehearsal-smoke.ps1"
    if ($WithObserver) { $cmd += " -WithObserver" }
    if ($MinHubHeight -gt 0) { $cmd += " -MinHubHeight $MinHubHeight" }
    $lines = New-Object System.Collections.Generic.List[string]
    [void]$lines.Add("# Participant rehearsal smoke - $observerLabel (Windows)")
    [void]$lines.Add("# Generated: $stamp")
    [void]$lines.Add("# Command: $cmd")
    if ($commit) { [void]$lines.Add("# Commit: $commit") }
    [void]$lines.Add("")
    [void]$lines.Add("SUMMARY: PASS")
    [void]$lines.Add("")
    [void]$lines.Add("Hub RPC=$RpcAddr")
    if ($WithObserver -and $ObserverRpc) {
        [void]$lines.Add("Observer RPC=$ObserverRpc")
    }
    [void]$lines.Add("")
    [void]$lines.Add("participant-rehearsal-smoke: PASS with_observer=$($WithObserver.IsPresent) hub_tip_height=$FinalHubHeight min_hub_height=$MinHubHeight")
    if ($WithObserver -and $ObserverHeight -ne "unknown") {
        [void]$lines.Add("participant-rehearsal-smoke: post_rehearsal observer_tip_height=$ObserverHeight observer_rpc=$ObserverRpc")
    }
    $enc = Get-DevnetPortsEncoding
    [System.IO.File]::WriteAllLines($path, $lines.ToArray(), $enc)
    Write-Host "participant-rehearsal-smoke: EVIDENCE archived=$path"
}

function Wait-FaucetBalance {
    param([string]$MfnCli, [string]$RpcAddr, [string]$WalletPath, [int]$TimeoutSeconds)
    $deadline = (Get-Date).AddSeconds($TimeoutSeconds)
    do {
        $balance = Get-WalletBalance $MfnCli $RpcAddr $WalletPath
        $tipHeight = Get-TipHeightText $MfnCli $RpcAddr
        Write-Host "participant-rehearsal-smoke: faucet_balance=$balance hub_tip_height=$tipHeight"
        if ($balance -gt 0) { return $balance }
        if ($TimeoutSeconds -le 0) { break }
        Start-Sleep -Seconds 5
    } while ((Get-Date) -lt $deadline)
    $tipHeight = Get-TipHeightText $MfnCli $RpcAddr
    throw "participant-rehearsal-smoke: faucet wallet has zero spendable balance after ${TimeoutSeconds}s (hub_tip_height=$tipHeight); wait for producer rewards, fund the faucet on this devnet, or rerun with -FaucetWallet pointing at a funded operator wallet"
}

function Get-LatestObserverRpc {
    $ports = Read-PortsFile
    $rpc = $ports["OBSERVER_RPC"]
    $obsLog = Join-Path $ScriptDir "logs\observer.log"
    if (Test-Path $obsLog) {
        $m = Select-String -Path $obsLog -Pattern "mfnd_serve_listening=(.+)" | Select-Object -Last 1
        if ($m) {
            $logRpc = $m.Matches.Groups[1].Value.Trim()
            if ($logRpc) { return $logRpc }
        }
    }
    return $rpc
}

function Assert-MeshHeights {
    param([string]$MfnCli, [string]$HubRpc)
    $hubHeight = Get-TipHeightText $MfnCli $HubRpc
    if ($hubHeight -notmatch '^\d+$') {
        throw "participant-rehearsal-smoke: hub tip_height unreadable after rehearsal: $hubHeight"
    }
    Write-Host "participant-rehearsal-smoke: post_rehearsal hub_tip_height=$hubHeight"
    if ($MinHubHeight -gt 0 -and [int]$hubHeight -lt $MinHubHeight) {
        throw "participant-rehearsal-smoke: hub tip_height=$hubHeight below required MinHubHeight=$MinHubHeight"
    }
    if (-not $WithObserver) { return }
    $catchupDeadline = (Get-Date).AddSeconds($WaitObserverCatchUpSeconds)
    do {
        $hubHeight = Get-TipHeightText $MfnCli $HubRpc
        $observerRpc = Get-LatestObserverRpc
        if (-not $observerRpc) {
            throw "participant-rehearsal-smoke: -WithObserver but OBSERVER_RPC missing from $PortsFile and logs"
        }
        $observerHeight = Get-TipHeightText $MfnCli $observerRpc
        if ($observerHeight -notmatch '^\d+$') {
            throw "participant-rehearsal-smoke: observer tip_height unreadable: $observerHeight"
        }
        if ([int]$observerHeight -ge [int]$hubHeight) {
            Write-Host "participant-rehearsal-smoke: post_rehearsal observer_tip_height=$observerHeight observer_rpc=$observerRpc"
            return
        }
        Write-Host "participant-rehearsal-smoke: observer_catchup_wait hub_tip_height=$hubHeight observer_tip_height=$observerHeight observer_rpc=$observerRpc"
        Start-Sleep -Seconds 5
    } while ((Get-Date) -lt $catchupDeadline)
    throw "participant-rehearsal-smoke: observer tip_height=$observerHeight lagged hub tip_height=$hubHeight after ${WaitObserverCatchUpSeconds}s"
}

function Wait-MinHubHeight {
    param([string]$MfnCli, [string]$HubRpc, [int]$Target, [int]$TimeoutSeconds)
    if ($Target -le 0) { return }
    $height = Get-TipHeightText $MfnCli $HubRpc
    if ($height -match '^\d+$' -and [int]$height -ge $Target) {
        Write-Host "participant-rehearsal-smoke: min_hub_height already satisfied hub_tip_height=$height target=$Target"
        return
    }
    if ($TimeoutSeconds -le 0) { return }
    $deadline = (Get-Date).AddSeconds($TimeoutSeconds)
    do {
        $height = Get-TipHeightText $MfnCli $HubRpc
        Write-Host "participant-rehearsal-smoke: min_hub_height_wait hub_tip_height=$height target=$Target"
        if ($height -match '^\d+$' -and [int]$height -ge $Target) { return }
        Start-Sleep -Seconds 5
    } while ((Get-Date) -lt $deadline)
    throw "participant-rehearsal-smoke: hub tip_height=$height below min_hub_height=$Target after ${TimeoutSeconds}s"
}

if ($WaitAfterStartSeconds -lt 0) {
    $WaitAfterStartSeconds = if ($WithObserver) { 45 } else { 30 }
}
if ($WaitFaucetSeconds -lt 0) { throw "WaitFaucetSeconds must be >= 0" }
if ($WaitMinedSeconds -lt 0) { throw "WaitMinedSeconds must be >= 0" }
if ($WaitUploadSeconds -lt 1) { throw "WaitUploadSeconds must be >= 1" }
if ($WaitProofSeconds -lt 0) { throw "WaitProofSeconds must be >= 0" }
if ($MinHubHeight -lt 0) { throw "MinHubHeight must be >= 0" }
if ($WaitMinHubHeightSeconds -lt 0) { throw "WaitMinHubHeightSeconds must be >= 0" }
if ($WaitObserverCatchUpSeconds -lt 0) { throw "WaitObserverCatchUpSeconds must be >= 0" }

if ($PlanOnly) {
    $planRpc = try { Resolve-Rpc } catch { if ($NoStart) { "<existing HUB_RPC or -Rpc required>" } else { "<start-all.ps1 will write HUB_RPC>" } }
    Write-Host "participant-rehearsal-smoke: plan"
    Write-Host "  rpc=$planRpc"
    Write-Host "  smoke_dir=$SmokeRoot"
    Write-Host "  faucet_wallet=$Faucet"
    Write-Host "  rehearsal_dir=$RunDir"
    Write-Host "  wait_faucet_seconds=$WaitFaucetSeconds"
    Write-Host "  wait_after_start_seconds=$WaitAfterStartSeconds"
    Write-Host "  with_observer=$($WithObserver.IsPresent)"
    Write-Host "  min_hub_height=$MinHubHeight"
    Write-Host "  wait_min_hub_height_seconds=$WaitMinHubHeightSeconds"
    Write-Host "  wait_observer_catchup_seconds=$WaitObserverCatchUpSeconds"
    Write-Host "  flow=stop stale mesh -> start-all -> restore/check test faucet -> wait faucet balance -> participant-rehearsal -> stop mesh"
    Write-Host "  warning=default wallet uses public validator-0 test payout seed only for local/public devnet rehearsal; custom faucet wallets are never overwritten"
    exit 0
}

$startedMesh = $false
Push-Location $RepoRoot
try {
    New-Item -ItemType Directory -Force -Path $SmokeRoot | Out-Null
    if (-not $NoBuild) {
        cargo build -p mfn-cli --release --bin mfn-cli
        if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
        cargo build -p mfn-storage-operator --release --bin mfn-storage-operator
        if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
    }
    if (-not $NoStart) {
        if (-not $env:SLOT_MS) { $env:SLOT_MS = "10000" }
        if ($WithObserver) {
            Remove-Item Env:MFN_DEVNET_NO_OBSERVER -ErrorAction SilentlyContinue
        } else {
            $env:MFN_DEVNET_NO_OBSERVER = "1"
        }
        powershell -NoProfile -File (Join-Path $ScriptDir "stop-all.ps1") -AllMfnd -RemovePortsFile
        . (Join-Path $ScriptDir "start-all.ps1")
        $startedMesh = $true
        if ($WaitAfterStartSeconds -gt 0) { Start-Sleep -Seconds $WaitAfterStartSeconds }
    }
    $RpcAddr = Resolve-Rpc

    $MfnCli = Resolve-MfnCli
    if ($UseBundledTestFaucet) {
        & $MfnCli --wallet $Faucet --force wallet restore $TestFaucetSeed --key-derivation payout_stealth_v1
        if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
    } elseif (-not (Test-Path $Faucet)) {
        throw "participant-rehearsal-smoke: faucet wallet not found: $Faucet"
    }
    Wait-FaucetBalance $MfnCli $RpcAddr $Faucet $WaitFaucetSeconds | Out-Null
    if (Test-Path $RunDir) {
        Remove-Item -Recurse -Force $RunDir
        Write-Host "participant-rehearsal-smoke: cleared rehearsal_dir=$RunDir"
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
    Wait-MinHubHeight $MfnCli $RpcAddr $MinHubHeight $WaitMinHubHeightSeconds
    Assert-MeshHeights $MfnCli $RpcAddr
    $finalHubHeight = Get-TipHeightText $MfnCli $RpcAddr
    $observerRpc = ""
    $observerHeight = "unknown"
    if ($WithObserver) {
        $observerRpc = Get-LatestObserverRpc
        if ($observerRpc) {
            $observerHeight = Get-TipHeightText $MfnCli $observerRpc
        }
    }
    Write-Host "participant-rehearsal-smoke: PASS rpc=$RpcAddr rehearsal_dir=$RunDir with_observer=$($WithObserver.IsPresent) hub_tip_height=$finalHubHeight min_hub_height=$MinHubHeight"
    if ($ArchiveEvidence) {
        Archive-RehearsalSmokeEvidence -RpcAddr $RpcAddr -FinalHubHeight $finalHubHeight -ObserverRpc $observerRpc -ObserverHeight $observerHeight
    }
} finally {
    if ($startedMesh -and -not $NoStop) {
        powershell -NoProfile -File (Join-Path $ScriptDir "stop-all.ps1") -AllMfnd -RemovePortsFile
    }
    Pop-Location
}
