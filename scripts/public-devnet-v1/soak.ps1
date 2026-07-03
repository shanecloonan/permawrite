# Long-running local public-devnet soak for hub + voters + observer.
param(
    [int]$DurationMinutes = 30,
    [int]$CheckIntervalSeconds = 60,
    [int]$StallSamples = 2,
    [int]$StallIntervalSeconds = 0,
    [int]$MinHeightDelta = 1,
    [switch]$RestartObserverOnce,
    [int]$RestartTimeoutSeconds = 180,
    [switch]$NoStart
)
$ErrorActionPreference = "Stop"

if ($DurationMinutes -lt 1) { throw "DurationMinutes must be >= 1" }
if ($CheckIntervalSeconds -lt 0) { throw "CheckIntervalSeconds must be >= 0" }
if ($StallSamples -lt 1) { throw "StallSamples must be >= 1" }
if ($StallIntervalSeconds -lt 0) { throw "StallIntervalSeconds must be >= 0" }
if ($MinHeightDelta -lt 1) { throw "MinHeightDelta must be >= 1" }
if ($RestartTimeoutSeconds -lt 1) { throw "RestartTimeoutSeconds must be >= 1" }

$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$PortsFile = Join-Path $ScriptDir "devnet-ports.env"
$HealthScript = Join-Path $ScriptDir "health-check.ps1"
$StartAllScript = Join-Path $ScriptDir "start-all.ps1"
$LogDir = Join-Path $ScriptDir "logs"
. (Join-Path $ScriptDir "ports-env-lib.ps1")
$StartedAt = Get-Date
$SoakSamples = New-Object System.Collections.Generic.List[string]
$SoakRestarts = New-Object System.Collections.Generic.List[string]
$LastFailure = $null
$SummaryWritten = $false
$P2pLogTimeoutSeconds = 120

function Read-PortsFile {
    return Read-DevnetPortsFile -Path $PortsFile
}

function Assert-ProcessAlive {
    param([hashtable]$Ports, [string]$Key)
    $pidText = $Ports[$Key]
    if (-not $pidText) { throw "soak: $Key missing in $PortsFile" }
    $proc = Get-Process -Id ([int]$pidText) -ErrorAction SilentlyContinue
    if (-not $proc) {
        $logHint = switch ($Key) {
            "HUB_PID" { Join-Path $LogDir "v0.err.log" }
            "V1_PID" { Join-Path $LogDir "v1.err.log" }
            "V2_PID" { Join-Path $LogDir "v2.err.log" }
            "OBSERVER_PID" { Join-Path $LogDir "observer.err.log" }
            default { $null }
        }
        $tail = ""
        if ($logHint -and (Test-Path $logHint)) {
            $tail = (Get-Content $logHint -Tail 5) -join " | "
        }
        $extra = if ($tail) { " last_stderr=$tail" } else { "" }
        throw "soak: process $Key=$pidText is not running$extra"
    }
}

function Assert-LogContains {
    param([string]$Name, [string]$Path, [string]$Pattern)
    if (-not (Test-Path $Path)) { throw "soak: missing $Name log at $Path" }
    $hit = Select-String -Path $Path -Pattern $Pattern -SimpleMatch | Select-Object -First 1
    if (-not $hit) { throw "soak: $Name log missing '$Pattern'" }
}

function Assert-P2pLogs {
    $deadline = (Get-Date).AddSeconds($P2pLogTimeoutSeconds)
    $v1Log = Join-Path $LogDir "v1.log"
    $v2Log = Join-Path $LogDir "v2.log"
    $observerLog = Join-Path $LogDir "observer.log"
    while ((Get-Date) -lt $deadline) {
        $v1Ready = (Test-Path $v1Log) -and (Select-String -Path $v1Log -Pattern "mfnd_p2p_dial_ok=" -SimpleMatch -Quiet)
        $v2Ready = (Test-Path $v2Log) -and (Select-String -Path $v2Log -Pattern "mfnd_p2p_dial_ok=" -SimpleMatch -Quiet)
        $observerReady = (Test-Path $observerLog) -and (Select-String -Path $observerLog -Pattern "mfnd_p2p_dial_ok=" -SimpleMatch -Quiet)
        if ($v1Ready -and $v2Ready -and $observerReady) { return }
        Start-Sleep -Seconds 1
    }
    Assert-LogContains "v1" $v1Log "mfnd_p2p_dial_ok="
    Assert-LogContains "v2" $v2Log "mfnd_p2p_dial_ok="
    Assert-LogContains "observer" $observerLog "mfnd_p2p_dial_ok="
}

function Wait-ForMeshProduction {
    $timeout = [Math]::Max(120, ($StallIntervalSeconds * 4) + 60)
    $deadline = (Get-Date).AddSeconds($timeout)
    Write-Host "soak: waiting for converged first block (timeout=${timeout}s)"
    $oldSamples = [Environment]::GetEnvironmentVariable("MFN_HEALTH_STALL_SAMPLES")
    $oldInterval = [Environment]::GetEnvironmentVariable("MFN_HEALTH_STALL_INTERVAL_SECONDS")
    $oldDelta = [Environment]::GetEnvironmentVariable("MFN_HEALTH_MIN_HEIGHT_DELTA")
    $oldRequireAll = [Environment]::GetEnvironmentVariable("MFN_HEALTH_REQUIRE_ALL_ROLES")
    try {
        [Environment]::SetEnvironmentVariable("MFN_HEALTH_STALL_SAMPLES", "1", "Process")
        [Environment]::SetEnvironmentVariable("MFN_HEALTH_STALL_INTERVAL_SECONDS", "0", "Process")
        [Environment]::SetEnvironmentVariable("MFN_HEALTH_MIN_HEIGHT_DELTA", "1", "Process")
        [Environment]::SetEnvironmentVariable("MFN_HEALTH_REQUIRE_ALL_ROLES", "0", "Process")
        while ((Get-Date) -lt $deadline) {
            $ports = Read-PortsFile
            Assert-ProcessAlive $ports "HUB_PID"
            Assert-P2pLogs
            try {
                $healthOutput = & $HealthScript 2>&1 6>&1
                $healthOutput | ForEach-Object { Write-Host $_ }
                $passLine = ($healthOutput | ForEach-Object { "$_" } | Where-Object { $_ -match "^health-check: PASS shared tip height=([0-9]+)" } | Select-Object -Last 1)
                if ($passLine -match "^health-check: PASS shared tip height=([0-9]+)") {
                    $hubHeight = $Matches[1]
                    if ([int]$hubHeight -ge 1) {
                        Write-Host "soak: WARMUP phase=hub_produced hub_tip_height=$hubHeight"
                        break
                    }
                }
            } catch {
                # Hub may still be scanning slots; retry until timeout.
            }
            Start-Sleep -Seconds 5
        }
        if ((Get-Date) -ge $deadline) {
            throw "soak: FAIL mesh hub did not reach tip_height>=1 within ${timeout}s"
        }
        [Environment]::SetEnvironmentVariable("MFN_HEALTH_REQUIRE_ALL_ROLES", "1", "Process")
        $convergeDeadline = (Get-Date).AddSeconds($timeout)
        while ((Get-Date) -lt $convergeDeadline) {
            $ports = Read-PortsFile
            Assert-ProcessAlive $ports "HUB_PID"
            Assert-ProcessAlive $ports "V1_PID"
            Assert-ProcessAlive $ports "V2_PID"
            Assert-ProcessAlive $ports "OBSERVER_PID"
            Assert-P2pLogs
            try {
                $healthOutput = & $HealthScript 2>&1 6>&1
                $healthOutput | ForEach-Object { Write-Host $_ }
                $passLine = ($healthOutput | ForEach-Object { "$_" } | Where-Object { $_ -match "^health-check: PASS shared tip height=([0-9]+)" } | Select-Object -Last 1)
                if ($passLine -match "^health-check: PASS shared tip height=([0-9]+)") {
                    $hubHeight = $Matches[1]
                    if ([int]$hubHeight -ge 1) {
                        Write-Host "soak: WARMUP phase=converged hub_tip_height=$hubHeight"
                        return
                    }
                }
            } catch {
                # Followers/observer still catching up; retry until timeout.
            }
            Start-Sleep -Seconds 5
        }
        throw "soak: FAIL mesh did not converge to tip_height>=1 within ${timeout}s"
    } finally {
        [Environment]::SetEnvironmentVariable("MFN_HEALTH_STALL_SAMPLES", $oldSamples, "Process")
        [Environment]::SetEnvironmentVariable("MFN_HEALTH_STALL_INTERVAL_SECONDS", $oldInterval, "Process")
        [Environment]::SetEnvironmentVariable("MFN_HEALTH_MIN_HEIGHT_DELTA", $oldDelta, "Process")
        [Environment]::SetEnvironmentVariable("MFN_HEALTH_REQUIRE_ALL_ROLES", $oldRequireAll, "Process")
    }
}
function Add-SoakSample {
    param([int]$Iteration, [object[]]$HealthOutput)
    $roles = New-Object System.Collections.Generic.List[string]
    $genesis = "unknown"
    $finalHeight = "unknown"
    $finalId = "unknown"
    foreach ($item in $HealthOutput) {
        $line = "$item"
        if ($line -match "^(hub|v1|v2|observer):?\s+tip_height=([^ ]+)\s+tip_id=([^ ]+)\s+genesis_id=([^ ]+)\s+p2p_sessions=([^ ]+)\s+p2p_peers=([^ ]+)") {
            $role = $Matches[1]
            $roles.Add("${role}:height=$($Matches[2]),sessions=$($Matches[5]),peers=$($Matches[6])")
            if ($genesis -eq "unknown") { $genesis = $Matches[4] }
            continue
        }
        if ($line -match "^health-check: PASS shared tip height=([0-9]+) id=([^ ]+)") {
            $finalHeight = $Matches[1]
            $finalId = $Matches[2]
        }
    }
    $roleText = if ($roles.Count -gt 0) { $roles -join ";" } else { "none" }
    $script:SoakSamples.Add("iteration=$Iteration final_height=$finalHeight final_tip_id=$finalId genesis_id=$genesis roles=$roleText")
}
function Get-HealthRoleField {
    param([object[]]$HealthOutput, [string]$Role, [string]$Field)
    foreach ($item in $HealthOutput) {
        $line = "$item"
        if ($line -match "^$([Regex]::Escape($Role)):?\s+(.+)$") {
            foreach ($part in $Matches[1].Split(" ")) {
                $kv = $part.Split("=", 2)
                if ($kv.Count -eq 2 -and $kv[0] -eq $Field) { return $kv[1] }
            }
        }
    }
    return "unknown"
}
function Get-LatestLogValue {
    param([string]$Path, [string]$Prefix)
    if (-not (Test-Path $Path)) { return $null }
    $value = $null
    Get-Content $Path -ErrorAction SilentlyContinue | ForEach-Object {
        if ($_.StartsWith($Prefix)) { $script:latestLogValue = $_.Substring($Prefix.Length).Trim() }
    }
    $value = $script:latestLogValue
    Remove-Variable -Name latestLogValue -Scope Script -ErrorAction SilentlyContinue
    return $value
}
function Set-ObserverPortLine {
    param([string]$Key, [string]$Value)
    Set-DevnetPort -Path $PortsFile -Key $Key -Value $Value
}
function Rotate-ObserverLogFile {
    param([string]$Source, [string]$Dest, [int]$MaxWaitSeconds = 15)
    if (-not (Test-Path $Source)) { return }
    $deadline = (Get-Date).AddSeconds($MaxWaitSeconds)
    while ((Get-Date) -lt $deadline) {
        try {
            Move-Item -Force $Source $Dest -ErrorAction Stop
            return
        } catch {
            Start-Sleep -Milliseconds 500
        }
    }
    Copy-Item -Force $Source $Dest
    Clear-Content $Source
}
function Invoke-ObserverRestartProbe {
    param([int]$Iteration, [object[]]$PreHealthOutput)
    $ports = Read-PortsFile
    $oldPid = $ports["OBSERVER_PID"]
    $oldRpc = if ($ports["OBSERVER_RPC"]) { $ports["OBSERVER_RPC"] } else { "unknown" }
    $hubP2p = $ports["HUB_P2P"]
    if (-not $hubP2p) { throw "soak: HUB_P2P missing in $PortsFile" }
    $preHubHeight = Get-HealthRoleField $PreHealthOutput "hub" "tip_height"
    $preObserverHeight = Get-HealthRoleField $PreHealthOutput "observer" "tip_height"
    $marker = "iteration-$Iteration-$([DateTimeOffset]::UtcNow.ToUnixTimeSeconds())"
    Write-Host "soak: restarting observer iteration=$Iteration old_pid=$oldPid old_rpc=$oldRpc marker=$marker"
    if ($oldPid) {
        $oldProc = Get-Process -Id ([int]$oldPid) -ErrorAction SilentlyContinue
        if ($oldProc) {
            Stop-Process -Id ([int]$oldPid) -Force -ErrorAction SilentlyContinue
            $waitDeadline = (Get-Date).AddSeconds(15)
            while ((Get-Date) -lt $waitDeadline) {
                if (-not (Get-Process -Id ([int]$oldPid) -ErrorAction SilentlyContinue)) { break }
                Start-Sleep -Milliseconds 250
            }
        }
    }
    $obsLog = Join-Path $LogDir "observer.log"
    $obsErr = Join-Path $LogDir "observer.err.log"
    Rotate-ObserverLogFile $obsLog (Join-Path $LogDir "observer.before-restart-$marker.log")
    Rotate-ObserverLogFile $obsErr (Join-Path $LogDir "observer.before-restart-$marker.err.log")
    $repoRoot = (Resolve-Path (Join-Path $ScriptDir "..\..")).Path
    $mfnd = if ($env:MFND) { $env:MFND } else { Join-Path $repoRoot "target\release\mfnd.exe" }
    $genesis = Join-Path $repoRoot "mfn-node\testdata\public_devnet_v1.json"
    $dataDir = Join-Path $repoRoot ".permawrite-devnet-v1\observer"
    New-Item -ItemType Directory -Force -Path $dataDir | Out-Null
    $newProc = Start-Process -FilePath $mfnd -ArgumentList @(
        "--data-dir", $dataDir, "--genesis", $genesis, "--store", "fs",
        "--rpc-listen", "127.0.0.1:0", "--p2p-listen", "127.0.0.1:0",
        "--p2p-dial", $hubP2p, "serve"
    ) -WorkingDirectory $repoRoot -RedirectStandardOutput $obsLog -RedirectStandardError $obsErr -PassThru
    Set-ObserverPortLine "OBSERVER_PID" "$($newProc.Id)"
    $deadline = (Get-Date).AddSeconds($RestartTimeoutSeconds)
    $observerRpc = $null
    while ((Get-Date) -lt $deadline) {
        if (-not (Get-Process -Id $newProc.Id -ErrorAction SilentlyContinue)) {
            $script:LastFailure = "iteration=$Iteration command=restart-observer pid=$($newProc.Id) exited_early"
            throw $script:LastFailure
        }
        $observerRpc = Get-LatestLogValue $obsLog "mfnd_serve_listening="
        if ($observerRpc) { break }
        Start-Sleep -Seconds 1
    }
    if (-not $observerRpc) {
        $script:LastFailure = "iteration=$Iteration command=restart-observer missing_observer_rpc timeout_seconds=$RestartTimeoutSeconds"
        throw $script:LastFailure
    }
    Set-ObserverPortLine "OBSERVER_RPC" $observerRpc
    while ((Get-Date) -lt $deadline) {
        $oldSamples = [Environment]::GetEnvironmentVariable("MFN_HEALTH_STALL_SAMPLES")
        try {
            [Environment]::SetEnvironmentVariable("MFN_HEALTH_STALL_SAMPLES", "1", "Process")
            $healthOutput = & $HealthScript 2>&1 6>&1
            $healthOutput | ForEach-Object { Write-Host $_ }
            $postHubHeight = Get-HealthRoleField $healthOutput "hub" "tip_height"
            $postObserverHeight = Get-HealthRoleField $healthOutput "observer" "tip_height"
            $record = "iteration=$Iteration role=observer old_pid=$oldPid new_pid=$($newProc.Id) old_rpc=$oldRpc new_rpc=$observerRpc pre_hub_height=$preHubHeight pre_observer_height=$preObserverHeight post_hub_height=$postHubHeight post_observer_height=$postObserverHeight"
            $script:SoakRestarts.Add($record)
            Write-Host "soak: RESTART $record"
            return
        } catch {
            Start-Sleep -Seconds 2
        } finally {
            [Environment]::SetEnvironmentVariable("MFN_HEALTH_STALL_SAMPLES", $oldSamples, "Process")
        }
    }
    $script:LastFailure = "iteration=$Iteration command=restart-observer catchup_timeout_seconds=$RestartTimeoutSeconds"
    throw $script:LastFailure
}
function Write-SoakSummary {
    param([string]$Status)
    $endedAt = Get-Date
    $elapsedSeconds = [int][Math]::Floor(($endedAt - $StartedAt).TotalSeconds)
    Write-Host "soak: SUMMARY status=$Status started_at=$($StartedAt.ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")) ended_at=$($endedAt.ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")) elapsed_seconds=$elapsedSeconds duration_minutes=$DurationMinutes iterations=$iteration"
    foreach ($sample in $SoakSamples) {
        Write-Host "soak: SAMPLE $sample"
    }
    foreach ($restart in $SoakRestarts) {
        Write-Host "soak: RESTART $restart"
    }
    if ($LastFailure) {
        Write-Host "soak: FAILURE $LastFailure"
    }
    $script:SummaryWritten = $true
}
trap {
    if (-not $script:LastFailure) {
        $script:LastFailure = "error=$($_.Exception.Message)"
    }
    if (-not $script:SummaryWritten) {
        Write-SoakSummary "FAIL"
    }
    break
}

if (-not $NoStart) {
    if (-not $env:SLOT_MS) {
        $env:SLOT_MS = "10000"
        Write-Host "soak: SLOT_MS=$($env:SLOT_MS) (local soak default; override with env SLOT_MS)"
    }
    if ($StallIntervalSeconds -le 0) {
        $slotSec = [Math]::Max(1, [int]$env:SLOT_MS / 1000)
        $StallIntervalSeconds = ($slotSec * 5) + 15
        Write-Host "soak: StallIntervalSeconds=$StallIntervalSeconds (auto from SLOT_MS)"
    }
    $foreign = @(Get-Process mfnd -ErrorAction SilentlyContinue)
    if ($foreign.Count -gt 0) {
        Write-Host "soak: WARN $($foreign.Count) mfnd process(es) already running (pids=$($foreign.Id -join ',')); stop CI/integration tests before soak"
    }
    Write-Host "soak: starting public-devnet-v1 mesh"
    & $StartAllScript
} else {
    if ($StallIntervalSeconds -le 0) {
        $slotMs = if ($env:SLOT_MS) { [int]$env:SLOT_MS } else { 10000 }
        $slotSec = [Math]::Max(1, $slotMs / 1000)
        $StallIntervalSeconds = ($slotSec * 5) + 15
        Write-Host "soak: StallIntervalSeconds=$StallIntervalSeconds (auto from SLOT_MS)"
    }
    Write-Host "soak: using existing public-devnet-v1 mesh"
}

Wait-ForMeshProduction

if ($StallIntervalSeconds -gt 0) {
    Write-Host "soak: post-warmup stabilization sleep=${StallIntervalSeconds}s"
    Start-Sleep -Seconds $StallIntervalSeconds
}

$deadline = (Get-Date).AddMinutes($DurationMinutes)
$iteration = 0
$observerRestartDone = $false
$iterBudgetSeconds = [Math]::Max(180, ($StallIntervalSeconds * $StallSamples) + 90)
while ((Get-Date) -lt $deadline) {
    if ((Get-Date).AddSeconds($iterBudgetSeconds) -ge $deadline) {
        Write-Host "soak: stopping (insufficient time for another iteration; budget=${iterBudgetSeconds}s)"
        break
    }
    $iteration += 1
    Write-Host "soak: iteration=$iteration deadline=$($deadline.ToString("o")) budget=${iterBudgetSeconds}s"
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
        $healthOutput = @()
        $healthDeadline = (Get-Date).AddSeconds($iterBudgetSeconds)
        while ((Get-Date) -lt $healthDeadline) {
            try {
                $healthOutput = & $HealthScript 2>&1 6>&1
                break
            } catch {
                $msg = "$($_.Exception.Message)"
                if ($msg -match "diverged|unreachable|p2p sessions=|actively refused|No connection could be made|stalled height") {
                    Start-Sleep -Seconds 5
                    continue
                }
                $healthOutput | ForEach-Object { Write-Host $_ }
                $script:LastFailure = "iteration=$iteration command=health-check error=$msg"
                throw
            }
        }
        if ($healthOutput.Count -eq 0) {
            $script:LastFailure = "iteration=$iteration command=health-check convergence_timeout"
            throw $script:LastFailure
        }
        $healthOutput | ForEach-Object { Write-Host $_ }
        Add-SoakSample $iteration $healthOutput
        if ($RestartObserverOnce -and -not $observerRestartDone) {
            Invoke-ObserverRestartProbe $iteration $healthOutput
            $observerRestartDone = $true
        }
    } finally {
        [Environment]::SetEnvironmentVariable("MFN_HEALTH_STALL_SAMPLES", $oldSamples, "Process")
        [Environment]::SetEnvironmentVariable("MFN_HEALTH_STALL_INTERVAL_SECONDS", $oldInterval, "Process")
        [Environment]::SetEnvironmentVariable("MFN_HEALTH_MIN_HEIGHT_DELTA", $oldDelta, "Process")
    }

    if ((Get-Date).AddSeconds($CheckIntervalSeconds) -lt $deadline -and $CheckIntervalSeconds -gt 0) {
        Start-Sleep -Seconds $CheckIntervalSeconds
    }
}

Write-SoakSummary "PASS"
