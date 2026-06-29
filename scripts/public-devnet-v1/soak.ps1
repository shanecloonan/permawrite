# Long-running local public-devnet soak for hub + voters + observer.
param(
    [int]$DurationMinutes = 30,
    [int]$CheckIntervalSeconds = 60,
    [int]$StallSamples = 2,
    [int]$StallIntervalSeconds = 35,
    [int]$MinHeightDelta = 1,
    [switch]$NoStart
)
$ErrorActionPreference = "Stop"

if ($DurationMinutes -lt 1) { throw "DurationMinutes must be >= 1" }
if ($CheckIntervalSeconds -lt 0) { throw "CheckIntervalSeconds must be >= 0" }
if ($StallSamples -lt 1) { throw "StallSamples must be >= 1" }
if ($StallIntervalSeconds -lt 0) { throw "StallIntervalSeconds must be >= 0" }
if ($MinHeightDelta -lt 1) { throw "MinHeightDelta must be >= 1" }

$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$PortsFile = Join-Path $ScriptDir "devnet-ports.env"
$HealthScript = Join-Path $ScriptDir "health-check.ps1"
$StartAllScript = Join-Path $ScriptDir "start-all.ps1"
$LogDir = Join-Path $ScriptDir "logs"

function Read-PortsFile {
    if (-not (Test-Path $PortsFile)) { throw "Missing $PortsFile - run start-all.ps1 first" }
    $ports = @{}
    Get-Content $PortsFile | ForEach-Object {
        if ($_ -match "^([^=]+)=(.*)$") { $ports[$Matches[1]] = $Matches[2] }
    }
    return $ports
}

function Assert-ProcessAlive {
    param([hashtable]$Ports, [string]$Key)
    $pidText = $Ports[$Key]
    if (-not $pidText) { throw "soak: $Key missing in $PortsFile" }
    $proc = Get-Process -Id ([int]$pidText) -ErrorAction SilentlyContinue
    if (-not $proc) { throw "soak: process $Key=$pidText is not running" }
}

function Assert-LogContains {
    param([string]$Name, [string]$Path, [string]$Pattern)
    if (-not (Test-Path $Path)) { throw "soak: missing $Name log at $Path" }
    $hit = Select-String -Path $Path -Pattern $Pattern -SimpleMatch | Select-Object -First 1
    if (-not $hit) { throw "soak: $Name log missing '$Pattern'" }
}

function Assert-P2pLogs {
    Assert-LogContains "v1" (Join-Path $LogDir "v1.log") "mfnd_p2p_dial_ok="
    Assert-LogContains "v2" (Join-Path $LogDir "v2.log") "mfnd_p2p_dial_ok="
    Assert-LogContains "observer" (Join-Path $LogDir "observer.log") "mfnd_p2p_dial_ok="
}

if (-not $NoStart) {
    Write-Host "soak: starting public-devnet-v1 mesh"
    & $StartAllScript
} else {
    Write-Host "soak: using existing public-devnet-v1 mesh"
}

$deadline = (Get-Date).AddMinutes($DurationMinutes)
$iteration = 0
while ((Get-Date) -lt $deadline) {
    $iteration += 1
    Write-Host "soak: iteration=$iteration deadline=$($deadline.ToString("o"))"
    $ports = Read-PortsFile
    foreach ($key in "HUB_PID", "V1_PID", "V2_PID", "OBSERVER_PID") {
        Assert-ProcessAlive $ports $key
    }
    Assert-P2pLogs

    $oldSamples = [Environment]::GetEnvironmentVariable("MFN_HEALTH_STALL_SAMPLES")
    $oldInterval = [Environment]::GetEnvironmentVariable("MFN_HEALTH_STALL_INTERVAL_SECONDS")
    $oldDelta = [Environment]::GetEnvironmentVariable("MFN_HEALTH_MIN_HEIGHT_DELTA")
    try {
        [Environment]::SetEnvironmentVariable("MFN_HEALTH_STALL_SAMPLES", "$StallSamples", "Process")
        [Environment]::SetEnvironmentVariable("MFN_HEALTH_STALL_INTERVAL_SECONDS", "$StallIntervalSeconds", "Process")
        [Environment]::SetEnvironmentVariable("MFN_HEALTH_MIN_HEIGHT_DELTA", "$MinHeightDelta", "Process")
        & $HealthScript
    } finally {
        [Environment]::SetEnvironmentVariable("MFN_HEALTH_STALL_SAMPLES", $oldSamples, "Process")
        [Environment]::SetEnvironmentVariable("MFN_HEALTH_STALL_INTERVAL_SECONDS", $oldInterval, "Process")
        [Environment]::SetEnvironmentVariable("MFN_HEALTH_MIN_HEIGHT_DELTA", $oldDelta, "Process")
    }

    if ((Get-Date).AddSeconds($CheckIntervalSeconds) -lt $deadline -and $CheckIntervalSeconds -gt 0) {
        Start-Sleep -Seconds $CheckIntervalSeconds
    }
}

Write-Host "soak: PASS duration_minutes=$DurationMinutes iterations=$iteration"
