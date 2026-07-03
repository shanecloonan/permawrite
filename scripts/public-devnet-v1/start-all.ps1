# Build mfnd, start hub + two committee voters; write devnet-ports.env (M2.4.3).
param(
    [switch]$NoBuild
)
$ErrorActionPreference = "Stop"
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$RepoRoot = (Resolve-Path (Join-Path $ScriptDir "..\..")).Path
$LogDir = Join-Path $ScriptDir "logs"
$PortsFile = Join-Path $ScriptDir "devnet-ports.env"
. (Join-Path $ScriptDir "ports-env-lib.ps1")
New-Item -ItemType Directory -Force -Path $LogDir | Out-Null

if ($env:MFN_DEVNET_SKIP_BUILD -eq "1") { $NoBuild = $true }
$Mfnd = Join-Path $RepoRoot "target\release\mfnd.exe"
if (-not $NoBuild) {
    Write-Host "Building mfnd..."
    Push-Location $RepoRoot
    cargo build -p mfn-node --release --bin mfnd
    Pop-Location
} elseif (-not (Test-Path $Mfnd)) {
    throw "start-all: missing mfnd at target\release\mfnd.exe; omit -NoBuild or build first"
} else {
    Write-Host "start-all: using existing mfnd ($Mfnd)"
}
$env:MFND = $Mfnd
$Genesis = Join-Path $RepoRoot "mfn-node\testdata\public_devnet_v1.json"
$SlotMs = if ($env:SLOT_MS) { [int]$env:SLOT_MS } else { 30000 }

function Start-MfndRole {
    param(
        [string[]]$CliArgs,
        [string]$StdoutLog,
        [string]$StderrLog,
        [string]$ValidatorIndex = "",
        [string]$VrfSeedHex = "",
        [string]$BlsSeedHex = ""
    )
    $oldIndex = $env:MFND_VALIDATOR_INDEX
    $oldVrf = $env:MFND_VRF_SEED_HEX
    $oldBls = $env:MFND_BLS_SEED_HEX
    try {
        if ($ValidatorIndex) {
            $env:MFND_VALIDATOR_INDEX = $ValidatorIndex
            $env:MFND_VRF_SEED_HEX = $VrfSeedHex
            $env:MFND_BLS_SEED_HEX = $BlsSeedHex
        } else {
            Remove-Item Env:MFND_VALIDATOR_INDEX -ErrorAction SilentlyContinue
            Remove-Item Env:MFND_VRF_SEED_HEX -ErrorAction SilentlyContinue
            Remove-Item Env:MFND_BLS_SEED_HEX -ErrorAction SilentlyContinue
        }
        return Start-Process -FilePath $Mfnd -ArgumentList $CliArgs -WorkingDirectory $RepoRoot -RedirectStandardOutput $StdoutLog -RedirectStandardError $StderrLog -PassThru
    } finally {
        if ($null -ne $oldIndex) { $env:MFND_VALIDATOR_INDEX = $oldIndex } else { Remove-Item Env:MFND_VALIDATOR_INDEX -ErrorAction SilentlyContinue }
        if ($null -ne $oldVrf) { $env:MFND_VRF_SEED_HEX = $oldVrf } else { Remove-Item Env:MFND_VRF_SEED_HEX -ErrorAction SilentlyContinue }
        if ($null -ne $oldBls) { $env:MFND_BLS_SEED_HEX = $oldBls } else { Remove-Item Env:MFND_BLS_SEED_HEX -ErrorAction SilentlyContinue }
    }
}

$StopAllScript = Join-Path $ScriptDir "stop-all.ps1"
Assert-SoakNotActive -ScriptDir $ScriptDir -Caller "start-all"
if (Test-Path $StopAllScript) {
    if ($env:MFN_SOAK_BOOTSTRAP -eq "1") {
        & $StopAllScript -Force
    } else {
        & $StopAllScript
    }
} else {
    Get-Process mfnd -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
}
Remove-DevnetPortsFile -Path $PortsFile
Start-Sleep -Seconds 1
$DataRoot = Join-Path $RepoRoot ".permawrite-devnet-v1"
if (Test-Path $DataRoot) {
    Remove-Item -Recurse -Force $DataRoot
    Write-Host "Cleared local devnet data root: $DataRoot"
}
$hubLog = Join-Path $LogDir "v0.log"
$hubErr = Join-Path $LogDir "v0.err.log"
$hubDataDir = Join-Path $DataRoot "v0"
New-Item -ItemType Directory -Force -Path $hubDataDir | Out-Null
$hubProc = Start-MfndRole `
    -CliArgs @(
        "--data-dir", $hubDataDir, "--genesis", $Genesis, "--store", "fs",
        "--rpc-listen", "127.0.0.1:0", "--p2p-listen", "127.0.0.1:0",
        "--slot-duration-ms", "$SlotMs", "serve", "--produce"
    ) `
    -StdoutLog $hubLog `
    -StderrLog $hubErr `
    -ValidatorIndex "0" `
    -VrfSeedHex "0101010101010101010101010101010101010101010101010101010101010101" `
    -BlsSeedHex "6565656565656565656565656565656565656565656565656565656565656565"
Set-DevnetPort -Path $PortsFile -Key "HUB_PID" -Value "$($hubProc.Id)"
$HubP2p = $null
$HubRpc = $null
$HubPollMax = if ($env:GITHUB_ACTIONS) { 300 } else { 60 }
for ($i = 1; $i -le $HubPollMax; $i++) {
    $text = $null
    if (Test-Path $hubLog) {
        $text = Get-Content $hubLog -Raw -ErrorAction SilentlyContinue
        if ($text -match "mfnd_p2p_listening=([^\r\n]+)") { $HubP2p = $Matches[1].Trim() }
        if ($text -match "mfnd_serve_listening=([^\r\n]+)") { $HubRpc = $Matches[1].Trim() }
        if ($HubP2p -and $HubRpc) { break }
    }
    if ($env:GITHUB_ACTIONS -and ($i % 30 -eq 0)) {
        if ($text -and ($text -match "mfnd_serve_listening=")) {
            Write-Host "start-all: hub RPC ready, waiting for P2P ($i/${HubPollMax}s)..."
        } else {
            Write-Host "start-all: waiting for hub startup ($i/${HubPollMax}s)..."
        }
    }
    Start-Sleep -Seconds 1
}
if (-not $HubP2p) {
    Write-Host "hub failed to print P2P listen within ${HubPollMax}s; tail $($hubLog):" -ForegroundColor Red
    if (Test-Path $hubLog) { Get-Content $hubLog -Tail 100 | Write-Host }
    throw "Hub did not print P2P listen within ${HubPollMax}s. See $hubLog"
}
Set-DevnetPort -Path $PortsFile -Key "HUB_P2P" -Value $HubP2p
Set-DevnetPort -Path $PortsFile -Key "HUB_RPC" -Value $HubRpc
$env:HUB_P2P = $HubP2p
Write-Host "Hub P2P=$HubP2p RPC=$HubRpc"
Start-Sleep -Seconds 2
$env:HUB_P2P = $HubP2p
$v1Log = Join-Path $LogDir "v1.log"
$v1Err = Join-Path $LogDir "v1.err.log"
$v1DataDir = Join-Path $DataRoot "v1"
New-Item -ItemType Directory -Force -Path $v1DataDir | Out-Null
$v1Proc = Start-MfndRole `
    -CliArgs @(
        "--data-dir", $v1DataDir, "--genesis", $Genesis, "--store", "fs",
        "--rpc-listen", "127.0.0.1:0", "--p2p-listen", "127.0.0.1:0",
        "--p2p-dial", $HubP2p, "--slot-duration-ms", "$SlotMs", "serve", "--committee-vote"
    ) `
    -StdoutLog $v1Log `
    -StderrLog $v1Err `
    -ValidatorIndex "1" `
    -VrfSeedHex "0202020202020202020202020202020202020202020202020202020202020202" `
    -BlsSeedHex "7676767676767676767676767676767676767676767676767676767676767676"
Set-DevnetPort -Path $PortsFile -Key "V1_PID" -Value "$($v1Proc.Id)"
Start-Sleep -Seconds 2
$v2Log = Join-Path $LogDir "v2.log"
$v2Err = Join-Path $LogDir "v2.err.log"
$v2DataDir = Join-Path $DataRoot "v2"
New-Item -ItemType Directory -Force -Path $v2DataDir | Out-Null
$v2Proc = Start-MfndRole `
    -CliArgs @(
        "--data-dir", $v2DataDir, "--genesis", $Genesis, "--store", "fs",
        "--rpc-listen", "127.0.0.1:0", "--p2p-listen", "127.0.0.1:0",
        "--p2p-dial", $HubP2p, "--slot-duration-ms", "$SlotMs", "serve", "--committee-vote"
    ) `
    -StdoutLog $v2Log `
    -StderrLog $v2Err `
    -ValidatorIndex "2" `
    -VrfSeedHex "0303030303030303030303030303030303030303030303030303030303030303" `
    -BlsSeedHex "8787878787878787878787878787878787878787878787878787878787878787"
Set-DevnetPort -Path $PortsFile -Key "V2_PID" -Value "$($v2Proc.Id)"
Start-Sleep -Seconds 2
if ($env:MFN_DEVNET_NO_OBSERVER -eq "1") {
    Write-Host "Skipping observer (MFN_DEVNET_NO_OBSERVER=1)"
} else {
$obsLog = Join-Path $LogDir "observer.log"
$obsErr = Join-Path $LogDir "observer.err.log"
$obsDataDir = Join-Path $DataRoot "observer"
New-Item -ItemType Directory -Force -Path $obsDataDir | Out-Null
$obsProc = Start-MfndRole `
    -CliArgs @(
        "--data-dir", $obsDataDir, "--genesis", $Genesis, "--store", "fs",
        "--rpc-listen", "127.0.0.1:0", "--p2p-listen", "127.0.0.1:0",
        "--p2p-dial", $HubP2p, "serve"
    ) `
    -StdoutLog $obsLog `
    -StderrLog $obsErr
Set-DevnetPort -Path $PortsFile -Key "OBSERVER_PID" -Value "$($obsProc.Id)"
$ObserverRpc = $null
$ObserverPollMax = if ($env:GITHUB_ACTIONS) { 300 } else { 60 }
for ($i = 1; $i -le $ObserverPollMax; $i++) {
    if (Test-Path $obsLog) {
        $m = Select-String -Path $obsLog -Pattern "mfnd_serve_listening=([^\r\n]+)" | Select-Object -First 1
        if ($m) {
            $ObserverRpc = $m.Matches.Groups[1].Value.Trim()
            break
        }
    }
    Start-Sleep -Seconds 1
}
if ($ObserverRpc) {
    Set-DevnetPort -Path $PortsFile -Key "OBSERVER_RPC" -Value $ObserverRpc
    Write-Host "Observer RPC=$ObserverRpc"
} else {
    Write-Host "Observer RPC not ready within ${ObserverPollMax}s; tail $($obsLog):" -ForegroundColor Yellow
    if (Test-Path $obsLog) { Get-Content $obsLog -Tail 100 | Write-Host }
}
}
Write-Host "Started jobs. Logs: $LogDir  Ports: $PortsFile"
Write-Host "After ~30s run: .\health-check.ps1"
$required = @("HUB_PID", "HUB_P2P", "HUB_RPC", "V1_PID", "V2_PID")
if ($env:MFN_DEVNET_NO_OBSERVER -ne "1") {
    $required += @("OBSERVER_PID", "OBSERVER_RPC")
}
$written = Read-DevnetPortsFile -Path $PortsFile
foreach ($key in $required) {
    if (-not $written[$key]) {
        throw "start-all: $key missing from $PortsFile after startup"
    }
}
