# Query get_status on hub + voters; require matching tip, public genesis_id, and live P2P sessions.
$ErrorActionPreference = "Stop"
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$PortsFile = Join-Path $ScriptDir "devnet-ports.env"
. (Join-Path $ScriptDir "ports-env-lib.ps1")
$ExpectedGenesisId = "454fa5d4a9bd6f59e35cf9ea7e68c096c9a271a92b2ec5931184e7f34a42a005"
$ports = Read-DevnetPortsFile -Path $PortsFile
$HubRpc = $ports["HUB_RPC"]
if (-not $HubRpc) { throw "HUB_RPC missing in $PortsFile" }
$Req = '{"jsonrpc":"2.0","method":"get_status","id":1}'
function Get-HealthEnvInt {
    param([string]$Name, [int]$Default, [int]$Min)
    $raw = [Environment]::GetEnvironmentVariable($Name)
    if (-not $raw) { return $Default }
    $value = 0
    if (-not [int]::TryParse($raw, [ref]$value) -or $value -lt $Min) {
        throw "health-check: $Name must be an integer >= $Min"
    }
    return $value
}
$StallSamples = Get-HealthEnvInt "MFN_HEALTH_STALL_SAMPLES" 1 1
$StallIntervalSeconds = Get-HealthEnvInt "MFN_HEALTH_STALL_INTERVAL_SECONDS" 30 0
$MinHeightDelta = Get-HealthEnvInt "MFN_HEALTH_MIN_HEIGHT_DELTA" 1 1
$MinP2pSessions = Get-HealthEnvInt "MFN_HEALTH_MIN_P2P_SESSIONS" 1 0
$RequireAllRoles = Get-HealthEnvInt "MFN_HEALTH_REQUIRE_ALL_ROLES" 1 0
function Query-Status {
    param([string]$Name, [string]$Addr, [switch]$RequireMinP2pSessions)
    $parts = $Addr.Split(":")
    $rpcHost = $parts[0]
    $port = [int]$parts[1]
    $client = New-Object System.Net.Sockets.TcpClient
    $client.Connect($rpcHost, $port)
    $stream = $client.GetStream()
    $writer = New-Object System.IO.StreamWriter($stream)
    $writer.WriteLine($Req)
    $writer.Flush()
    $reader = New-Object System.IO.StreamReader($stream)
    $line = $reader.ReadLine()
    $client.Close()
    if (-not $line) { throw "health-check: $Name RPC empty response" }
    $json = $line | ConvertFrom-Json
    if ($json.error) { throw "health-check: $Name RPC error $($json.error)" }
    $height = $json.result.chain.tip_height
    $id = $json.result.chain.tip_id
    $genesis = $json.result.chain.genesis_id
    $p2pSessions = $json.result.p2p.session_count
    $p2pPeers = $json.result.p2p.peer_count
    if (-not $id -or $id -eq "none") { throw "health-check: $Name has no tip_id" }
    if ($genesis -ne $ExpectedGenesisId) {
        throw "health-check: $Name genesis_id=$genesis expected $ExpectedGenesisId"
    }
    if ($RequireMinP2pSessions -and $MinP2pSessions -gt 0) {
        if ($null -eq $p2pSessions) { throw "health-check: $Name returned no p2p.session_count" }
        $sessionValue = [int64]$p2pSessions
        if ($sessionValue -lt $MinP2pSessions) {
            throw "health-check: FAIL $Name p2p sessions=$sessionValue min=$MinP2pSessions"
        }
    }
    $heightValue = if ($null -eq $height) { 0 } else { [int64]$height }
    $h = if ($null -eq $height) { "null" } else { "$height" }
    $sessionText = if ($null -eq $p2pSessions) { "null" } else { "$p2pSessions" }
    $peerText = if ($null -eq $p2pPeers) { "null" } else { "$p2pPeers" }
    Write-Host "${Name}: tip_height=$h tip_id=$id genesis_id=$genesis p2p_sessions=$sessionText p2p_peers=$peerText"
    return @{ Height = $heightValue; Id = $id }
}
function Invoke-ConvergenceCheck {
    $hub = Query-Status "hub" $HubRpc -RequireMinP2pSessions
    if ($RequireAllRoles -eq 0) {
        return @{ Height = $hub.Height; Id = $hub.Id }
    }
    $refHeight = $hub.Height
    $refId = $hub.Id
    foreach ($v in 1, 2) {
        $log = Join-Path $ScriptDir "logs\v$v.log"
        if (-not (Test-Path $log)) {
            if ($RequireAllRoles -gt 0) { throw "health-check: FAIL missing v$v log at $log" }
            Write-Host "health-check: skip v$v (no log; MFN_HEALTH_REQUIRE_ALL_ROLES=0)"
            continue
        }
        $m = Select-String -Path $log -Pattern "mfnd_serve_listening=(.+)" | Select-Object -First 1
        if (-not $m) {
            if ($RequireAllRoles -gt 0) { throw "health-check: FAIL missing v$v RPC in $log" }
            Write-Host "health-check: skip v$v (no RPC in log; MFN_HEALTH_REQUIRE_ALL_ROLES=0)"
            continue
        }
        $tip = Query-Status "v$v" $m.Matches.Groups[1].Value
        if ($tip.Height -ne $refHeight -or $tip.Id -ne $refId) {
            throw "health-check: FAIL v$v diverged from hub"
        }
    }
    $ObserverRpc = $ports["OBSERVER_RPC"]
    if ($ObserverRpc) {
        $obs = Query-Status "observer" $ObserverRpc
        if ($obs.Height -ne $refHeight -or $obs.Id -ne $refId) {
            throw "health-check: FAIL observer diverged from hub"
        }
    } else {
        $obsLog = Join-Path $ScriptDir "logs\observer.log"
        if (Test-Path $obsLog) {
            $m = Select-String -Path $obsLog -Pattern "mfnd_serve_listening=(.+)" | Select-Object -First 1
            if ($m) {
                $obs = Query-Status "observer" $m.Matches.Groups[1].Value
                if ($obs.Height -ne $refHeight -or $obs.Id -ne $refId) {
                    throw "health-check: FAIL observer diverged from hub"
                }
            } else {
                if ($RequireAllRoles -gt 0) { throw "health-check: FAIL missing observer RPC in $obsLog" }
                Write-Host "health-check: skip observer (no RPC in log; MFN_HEALTH_REQUIRE_ALL_ROLES=0)"
            }
        } elseif ($RequireAllRoles -gt 0) {
            throw "health-check: FAIL missing observer log at $obsLog"
        }
    }
    return @{ Height = $refHeight; Id = $refId }
}
$first = Invoke-ConvergenceCheck
$last = $first
for ($sample = 2; $sample -le $StallSamples; $sample++) {
    Write-Host "health-check: waiting ${StallIntervalSeconds}s before sample $sample/$StallSamples"
    if ($StallIntervalSeconds -gt 0) { Start-Sleep -Seconds $StallIntervalSeconds }
    $last = Invoke-ConvergenceCheck
}
if ($StallSamples -gt 1) {
    $delta = [int64]$last.Height - [int64]$first.Height
    if ($delta -lt $MinHeightDelta) {
        throw "health-check: FAIL stalled height first=$($first.Height) last=$($last.Height) samples=$StallSamples min_delta=$MinHeightDelta"
    }
    Write-Host "health-check: PASS shared tip height=$($last.Height) id=$($last.Id) advanced_by=$delta samples=$StallSamples"
} else {
    Write-Host "health-check: PASS shared tip height=$($last.Height) id=$($last.Id)"
}
