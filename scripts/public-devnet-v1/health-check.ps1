# Query get_tip on hub + voters; require matching tip_height/tip_id and public genesis_id (M2.4.3 / M2.4.6).
$ErrorActionPreference = "Stop"
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$PortsFile = Join-Path $ScriptDir "devnet-ports.env"
$ExpectedGenesisId = "7fef4492dba32d7ba652cceb5465cae86d6630a9e0a4855adf3acdc5f6b2a2df"
if (-not (Test-Path $PortsFile)) { throw "Missing $PortsFile — run start-all.ps1 first" }
$ports = @{}
Get-Content $PortsFile | ForEach-Object {
    if ($_ -match "^([^=]+)=(.*)$") { $ports[$Matches[1]] = $Matches[2] }
}
$HubRpc = $ports["HUB_RPC"]
if (-not $HubRpc) { throw "HUB_RPC missing in $PortsFile" }
$Req = '{"jsonrpc":"2.0","method":"get_tip","id":1}'
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
    $h = if ($null -eq $height) { "null" } else { "$height" }
    Write-Host "${Name}: tip_height=$h tip_id=$id genesis_id=$genesis"
    return @{ Height = $height; Id = $id }
}
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
Write-Host "health-check: PASS shared tip height=$refHeight id=$refId"
