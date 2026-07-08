# Lane 7 / TL-8: preview or apply seed_nodes for internet-facing VPS (P2P only).
param(
    [string]$PublicIp = "",
    [string]$BindFile = "",
    [switch]$Apply
)
$ErrorActionPreference = "Stop"

$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$RepoRoot = (Resolve-Path (Join-Path $ScriptDir "..\..")).Path
$ManifestPath = Join-Path $RepoRoot "mfn-node\testdata\public_devnet_v1.manifest.json"
if (-not $BindFile) {
    $BindFile = Join-Path $ScriptDir "vps-bind.env"
}

function Read-BindPort {
    param([string]$Name, [hashtable]$Vars)
    $listen = $Vars[$Name]
    if (-not $listen) {
        throw "publish-seed-nodes: missing $Name in $BindFile"
    }
    return ($listen -split ":", 2)[-1]
}

if (-not (Test-Path $BindFile)) {
    throw "publish-seed-nodes: missing $BindFile (copy vps-bind.env.example)"
}

$bind = @{}
Get-Content -LiteralPath $BindFile | ForEach-Object {
    $line = $_.Trim()
    if ($line -match '^\s*#' -or $line -eq "") { return }
    if ($line -match '^([A-Za-z_][A-Za-z0-9_]*)=(.*)$') {
        $bind[$Matches[1]] = $Matches[2].Trim()
    }
}

if (-not $PublicIp) {
    try {
        $PublicIp = (Invoke-WebRequest -Uri "https://api.ipify.org" -UseBasicParsing -TimeoutSec 5).Content.Trim()
    } catch {
        $PublicIp = ""
    }
}
if (-not $PublicIp) {
    throw "publish-seed-nodes: set -PublicIp or ensure api.ipify.org is reachable"
}

$hubPort = Read-BindPort "MFN_P2P_LISTEN_HUB" $bind
$v1Port = Read-BindPort "MFN_P2P_LISTEN_V1" $bind
$v2Port = Read-BindPort "MFN_P2P_LISTEN_V2" $bind
$seeds = @(
    "${PublicIp}:${hubPort}",
    "${PublicIp}:${v1Port}",
    "${PublicIp}:${v2Port}"
)

Write-Host "publish-seed-nodes: TL-8 preview public_ip=$PublicIp"
Write-Host "publish-seed-nodes: seeds=$($seeds -join ', ')"
Write-Host ""
Write-Host '"seed_nodes": ['
for ($i = 0; $i -lt $seeds.Count; $i++) {
    $comma = if ($i -lt $seeds.Count - 1) { "," } else { "" }
    Write-Host ('  "' + $seeds[$i] + '"' + $comma)
}
Write-Host ']'

if (-not $Apply) {
    Write-Host ""
    Write-Host "publish-seed-nodes: dry-run only; re-run with -Apply after TL-7 sign-off"
    exit 0
}

if (-not (Test-Path $ManifestPath)) {
    throw "publish-seed-nodes: missing manifest $ManifestPath"
}

$doc = Get-Content -Raw -Encoding UTF8 $ManifestPath | ConvertFrom-Json
$doc.seed_nodes = $seeds
$json = ($doc | ConvertTo-Json -Depth 8)
[System.IO.File]::WriteAllText($ManifestPath, $json + "`n", [System.Text.UTF8Encoding]::new($false))
Write-Host "publish-seed-nodes: OK applied - commit manifest + run launch-go-no-go.ps1"
