# Lane 6 / F6: read-only treasury telemetry for fee-drought revisit triggers (FEES.md §5).
param(
    [switch]$PlanOnly,
    [switch]$Json,
    [string]$Rpc = ""
)
$ErrorActionPreference = "Stop"

$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$RepoRoot = (Resolve-Path (Join-Path $ScriptDir "..\..")).Path
$FeesDoc = Join-Path $RepoRoot "docs\FEES.md"

function Invoke-MfndRpcHttp {
    param(
        [Parameter(Mandatory = $true)][string]$RpcUrl,
        [Parameter(Mandatory = $true)][string]$RequestJson
    )
    # Prefer HttpWebRequest: PowerShell curl -d mangles JSON quotes.
    $req = [System.Net.HttpWebRequest]::Create($RpcUrl)
    $req.Method = "POST"
    $req.ContentType = "application/json"
    $req.Timeout = 60000
    $bytes = [System.Text.Encoding]::UTF8.GetBytes($RequestJson)
    $req.ContentLength = $bytes.Length
    $stream = $req.GetRequestStream()
    $stream.Write($bytes, 0, $bytes.Length)
    $stream.Close()
    $resp = $req.GetResponse()
    $reader = New-Object System.IO.StreamReader($resp.GetResponseStream())
    try { return $reader.ReadToEnd() } finally { $reader.Close(); $resp.Close() }
}

function Invoke-MfndRpcLine {
    param(
        [Parameter(Mandatory = $true)][string]$RpcAddr,
        [Parameter(Mandatory = $true)][string]$RequestJson
    )
    $hostPart, $portPart = $RpcAddr -split ":", 2
    if (-not $portPart) { throw "treasury-telemetry-watch: invalid --rpc $RpcAddr (expected HOST:PORT)" }
    $client = [System.Net.Sockets.TcpClient]::new()
    try {
        $client.Connect($hostPart, [int]$portPart)
        $stream = $client.GetStream()
        $writer = New-Object System.IO.StreamWriter($stream)
        $writer.WriteLine($RequestJson)
        $writer.Flush()
        $reader = New-Object System.IO.StreamReader($stream)
        return $reader.ReadLine()
    } finally {
        $client.Close()
    }
}

if (-not (Test-Path -LiteralPath $FeesDoc)) {
    throw "treasury-telemetry-watch: missing $FeesDoc"
}

if ($PlanOnly -or -not $Rpc) {
    Write-Host "treasury-telemetry-watch: plan"
    Write-Host "  rpc_method=get_chain_params"
    Write-Host "  fields=treasury_base_units,tip_height,emission.fee_to_treasury_bps,emission.subsidy_to_treasury_bps"
    Write-Host "  triggers=docs/FEES.md §5.4 revisit (treasury pinned near zero + backstop majority blocks)"
    Write-Host "  command=treasury-telemetry-watch.ps1 -Rpc 127.0.0.1:18731"
    Write-Host "  http_example=treasury-telemetry-watch.ps1 -Rpc http://127.0.0.1:8787/rpc"
    if ($Json) {
        [ordered]@{
            schema_version = "treasury-telemetry-watch.v1"
            mode           = "plan-only"
            rpc_method     = "get_chain_params"
            revisit_doc    = "docs/FEES.md#5-parameter-review-2026-07-should-fees-rise-and-should-the-tail-feed-the-treasury"
        } | ConvertTo-Json -Depth 4
    }
    Write-Host "treasury-telemetry-watch: PASS plan-only"
    exit 0
}

$reqJson = '{"jsonrpc":"2.0","method":"get_chain_params","id":1}'
if ($Rpc -match '^https?://') {
    $line = Invoke-MfndRpcHttp -RpcUrl $Rpc -RequestJson $reqJson
} else {
    $line = Invoke-MfndRpcLine -RpcAddr $Rpc -RequestJson $reqJson
}
if (-not $line) {
    throw "treasury-telemetry-watch: RPC query failed for $Rpc"
}
$result = ($line | ConvertFrom-Json).result
if (-not $result) {
    throw "treasury-telemetry-watch: empty get_chain_params result from $Rpc"
}

$report = [ordered]@{
    schema_version      = "treasury-telemetry-watch.v1"
    mode                = "live"
    rpc                 = $Rpc
    treasury_base_units = [string]$result.treasury_base_units
    tip_height          = $result.tip_height
    fee_to_treasury_bps = $result.emission.fee_to_treasury_bps
    subsidy_to_treasury_bps = $result.emission.subsidy_to_treasury_bps
    revisit_doc         = "docs/FEES.md#5-parameter-review-2026-07-should-fees-rise-and-should-the-tail-feed-the-treasury"
}

if ($Json) {
    $report | ConvertTo-Json -Depth 4
} else {
    Write-Host "treasury-telemetry-watch: rpc=$Rpc treasury_base_units=$($report.treasury_base_units) tip_height=$($report.tip_height) fee_to_treasury_bps=$($report.fee_to_treasury_bps) subsidy_to_treasury_bps=$($report.subsidy_to_treasury_bps)"
    Write-Host "treasury-telemetry-watch: revisit triggers in docs/FEES.md §5.4"
}
