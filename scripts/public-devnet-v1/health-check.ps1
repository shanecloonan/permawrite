# JSON-RPC get_tip against hub (and voters if logs exist) (M2.4.3).
$ErrorActionPreference = "Stop"
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$PortsFile = Join-Path $ScriptDir "devnet-ports.env"
if (-not (Test-Path $PortsFile)) { throw "Missing $PortsFile — run start-all.ps1 first" }
$ports = @{}
Get-Content $PortsFile | ForEach-Object {
    if ($_ -match "^([^=]+)=(.*)$") { $ports[$Matches[1]] = $Matches[2] }
}
$HubRpc = $ports["HUB_RPC"]
if (-not $HubRpc) { throw "HUB_RPC missing in $PortsFile" }
$Req = '{"jsonrpc":"2.0","method":"get_tip","id":1}'
function Query-Tip($Name, $Addr) {
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
    Write-Host "${Name}: $line"
}
Query-Tip "hub" $HUB_RPC
foreach ($v in 1, 2) {
    $log = Join-Path $ScriptDir "logs\v$v.log"
    if (Test-Path $log) {
        $m = Select-String -Path $log -Pattern "mfnd_serve_listening=(.+)" | Select-Object -First 1
        if ($m) { Query-Tip "v$v" $m.Matches.Groups[1].Value }
    }
}
