# Build mfnd, start hub + two voters; write devnet-ports.env (M2.4.3).
$ErrorActionPreference = "Stop"
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$RepoRoot = (Resolve-Path (Join-Path $ScriptDir "..\..")).Path
$LogDir = Join-Path $ScriptDir "logs"
$PortsFile = Join-Path $ScriptDir "devnet-ports.env"
New-Item -ItemType Directory -Force -Path $LogDir | Out-Null
Write-Host "Building mfnd..."
Push-Location $RepoRoot
cargo build -p mfn-node --release --bin mfnd
Pop-Location
$Mfnd = Join-Path $RepoRoot "target\release\mfnd.exe"
$env:MFND = $Mfnd
Get-Process mfnd -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
Start-Sleep -Seconds 1
$hubLog = Join-Path $LogDir "v0.log"
$hubErr = Join-Path $LogDir "v0.err.log"
$hubProc = Start-Process -FilePath "powershell" -ArgumentList @(
    "-NoProfile", "-File", (Join-Path $ScriptDir "start-hub.ps1")
) -WorkingDirectory $RepoRoot -RedirectStandardOutput $hubLog -RedirectStandardError $hubErr -PassThru
"HUB_PID=$($hubProc.Id)" | Set-Content $PortsFile
$HubP2p = $null
$HubRpc = $null
for ($i = 0; $i -lt 60; $i++) {
    if (Test-Path $hubLog) {
        $text = Get-Content $hubLog -Raw -ErrorAction SilentlyContinue
        if ($text -match "mfnd_p2p_listening=([^\r\n]+)") { $HubP2p = $Matches[1].Trim() }
        if ($text -match "mfnd_serve_listening=([^\r\n]+)") { $HubRpc = $Matches[1].Trim() }
        if ($HubP2p -and $HubRpc) { break }
    }
    Start-Sleep -Seconds 1
}
if (-not $HubP2p) {
    throw "Hub did not print P2P listen within 60s. See $hubLog"
}
Add-Content $PortsFile "HUB_P2P=$HubP2p"
Add-Content $PortsFile "HUB_RPC=$HubRpc"
$env:HUB_P2P = $HubP2p
Write-Host "Hub P2P=$HubP2p RPC=$HubRpc"
Start-Sleep -Seconds 2
$env:HUB_P2P = $HubP2p
$v1Log = Join-Path $LogDir "v1.log"
$v1Err = Join-Path $LogDir "v1.err.log"
$v1Proc = Start-Process -FilePath "powershell" -ArgumentList @(
    "-NoProfile", "-File", (Join-Path $ScriptDir "start-voter.ps1"), "-Index", "1"
) -WorkingDirectory $RepoRoot -RedirectStandardOutput $v1Log -RedirectStandardError $v1Err -PassThru
"V1_PID=$($v1Proc.Id)" | Add-Content $PortsFile
Start-Sleep -Seconds 2
$v2Log = Join-Path $LogDir "v2.log"
$v2Err = Join-Path $LogDir "v2.err.log"
$v2Proc = Start-Process -FilePath "powershell" -ArgumentList @(
    "-NoProfile", "-File", (Join-Path $ScriptDir "start-voter.ps1"), "-Index", "2"
) -WorkingDirectory $RepoRoot -RedirectStandardOutput $v2Log -RedirectStandardError $v2Err -PassThru
"V2_PID=$($v2Proc.Id)" | Add-Content $PortsFile
Start-Sleep -Seconds 2
$obsLog = Join-Path $LogDir "observer.log"
$obsErr = Join-Path $LogDir "observer.err.log"
$obsProc = Start-Process -FilePath "powershell" -ArgumentList @(
    "-NoProfile", "-File", (Join-Path $ScriptDir "start-observer.ps1")
) -WorkingDirectory $RepoRoot -RedirectStandardOutput $obsLog -RedirectStandardError $obsErr -PassThru
"OBSERVER_PID=$($obsProc.Id)" | Add-Content $PortsFile
$ObserverRpc = $null
for ($i = 0; $i -lt 60; $i++) {
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
    Add-Content $PortsFile "OBSERVER_RPC=$ObserverRpc"
    Write-Host "Observer RPC=$ObserverRpc"
} else {
    Write-Host "Observer RPC not ready within 60s; health-check may skip observer (see $obsLog)"
}
Write-Host "Started jobs. Logs: $LogDir  Ports: $PortsFile"
Write-Host "After ~30s run: .\health-check.ps1"
