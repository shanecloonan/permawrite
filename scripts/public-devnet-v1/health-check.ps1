# Query get_tip on hub + voters; require matching tip_height/tip_id and public genesis_id (M2.4.3 / M2.4.6).
$ErrorActionPreference = "Stop"
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$PortsFile = Join-Path $ScriptDir "devnet-ports.env"
$ExpectedGenesisId = "7fef4492dba32d7ba652cceb5465cae86d6630a9e0a4855adf3acdc5f6b2a2df"
if (-not (Test-Path $PortsFile)) { throw "Missing $PortsFile - run start-all.ps1 first" }
$ports = @{}
Get-Content $PortsFile | ForEach-Object {
    if ($_ -match "^([^=]+)=(.*)$") { $ports[$Matches[1]] = $Matches[2] }
}
$HubRpc = $ports["HUB_RPC"]
if (-not $HubRpc) { throw "HUB_RPC missing in $PortsFile" }
$Req = '{"jsonrpc":"2.0","method":"get_tip","id":1}'
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
function Query-Tip {
    param([string]$Name, [string]$Addr)
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
    $height = $json.result.tip_height
    $id = $json.result.tip_id
    $genesis = $json.result.genesis_id
    if (-not $id -or $id -eq "none") { throw "health-check: $Name has no tip_id" }
    if ($genesis -ne $ExpectedGenesisId) {
        throw "health-check: $Name genesis_id=$genesis expected $ExpectedGenesisId"
    }
    $heightValue = if ($null -eq $height) { 0 } else { [int64]$height }
    $h = if ($null -eq $height) { "null" } else { "$height" }
    Write-Host "${Name}: tip_height=$h tip_id=$id genesis_id=$genesis"
    return @{ Height = $heightValue; Id = $id }
}
function Invoke-ConvergenceCheck {
    $hub = Query-Tip "hub" $HubRpc
    $refHeight = $hub.Height
    $refId = $hub.Id
    foreach ($v in 1, 2) {
        $log = Join-Path $ScriptDir "logs\v$v.log"
        if (-not (Test-Path $log)) {
            Write-Host "health-check: skip v$v (no log)"
            continue
        }
        $m = Select-String -Path $log -Pattern "mfnd_serve_listening=(.+)" | Select-Object -First 1
        if (-not $m) {
            Write-Host "health-check: skip v$v (no RPC in log)"
            continue
        }
        $tip = Query-Tip "v$v" $m.Matches.Groups[1].Value
        if ($tip.Height -ne $refHeight -or $tip.Id -ne $refId) {
            throw "health-check: FAIL v$v diverged from hub"
        }
    }
    $ObserverRpc = $ports["OBSERVER_RPC"]
    if ($ObserverRpc) {
        $obs = Query-Tip "observer" $ObserverRpc
        if ($obs.Height -ne $refHeight -or $obs.Id -ne $refId) {
            throw "health-check: FAIL observer diverged from hub"
        }
    } else {
        $obsLog = Join-Path $ScriptDir "logs\observer.log"
        if (Test-Path $obsLog) {
            $m = Select-String -Path $obsLog -Pattern "mfnd_serve_listening=(.+)" | Select-Object -First 1
            if ($m) {
                $obs = Query-Tip "observer" $m.Matches.Groups[1].Value
                if ($obs.Height -ne $refHeight -or $obs.Id -ne $refId) {
                    throw "health-check: FAIL observer diverged from hub"
                }
            } else {
                Write-Host "health-check: skip observer (no RPC in log)"
            }
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
