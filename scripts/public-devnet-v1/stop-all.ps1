# Stop public-devnet processes recorded by start-all.ps1.
param(
    [switch]$AllMfnd,
    [switch]$DryRun
)
$ErrorActionPreference = "Stop"

$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$PortsFile = Join-Path $ScriptDir "devnet-ports.env"

function Read-PortsFile {
    if (-not (Test-Path $PortsFile)) { return @{} }
    $ports = @{}
    Get-Content $PortsFile | ForEach-Object {
        if ($_ -match "^([^=]+)=(.*)$") { $ports[$Matches[1]] = $Matches[2] }
    }
    return $ports
}

function Stop-Pid {
    param([string]$Name, [int]$ProcessId)
    $proc = Get-Process -Id $ProcessId -ErrorAction SilentlyContinue
    if (-not $proc) {
        Write-Host "stop-all: skip $Name pid=$ProcessId not_running"
        return
    }
    if ($DryRun) {
        Write-Host "stop-all: dry_run stop $Name pid=$ProcessId process=$($proc.ProcessName)"
        return
    }
    Stop-Process -Id $ProcessId -Force -ErrorAction SilentlyContinue
    Write-Host "stop-all: stopped $Name pid=$ProcessId"
}

$ports = Read-PortsFile
foreach ($key in @("OBSERVER_PID", "V2_PID", "V1_PID", "HUB_PID")) {
    if (-not $ports[$key]) { continue }
    $pidValue = 0
    if ([int]::TryParse($ports[$key], [ref]$pidValue)) {
        Stop-Pid $key $pidValue
    } else {
        Write-Host "stop-all: skip $key invalid_pid=$($ports[$key])"
    }
}

if ($AllMfnd) {
    $processes = @(Get-Process mfnd -ErrorAction SilentlyContinue)
    foreach ($proc in $processes) {
        Stop-Pid "mfnd" $proc.Id
    }
}

if (-not $DryRun -and (Test-Path $PortsFile)) {
    Remove-Item -Force $PortsFile
    Write-Host "stop-all: removed $PortsFile"
}

Write-Host "stop-all: done"
