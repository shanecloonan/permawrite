# Lane 7 / TL-8: plan-only publish-seed-nodes rehearsal gate (Windows).
param(
    [switch]$PlanOnly
)
$ErrorActionPreference = "Stop"

$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$RepoRoot = (Resolve-Path (Join-Path $ScriptDir "..\..")).Path
$Doc = Join-Path $RepoRoot "docs\VPS_SINGLE_BOX_LAUNCH.md"
$Invite = Join-Path $RepoRoot "docs\TESTNET_INVITE.md"
$Ops = Join-Path $RepoRoot "scripts\public-devnet-v1\OPERATORS.md"
$Publish = Join-Path $ScriptDir "publish-seed-nodes.ps1"
$Manifest = Join-Path $RepoRoot "mfn-node\testdata\public_devnet_v1.manifest.json"
$BindExample = Join-Path $ScriptDir "vps-bind.env.example"
$FixtureIp = "203.0.113.1"

foreach ($path in @($Doc, $Invite, $Ops, $Publish, $Manifest, $BindExample)) {
    if (-not (Test-Path -LiteralPath $path)) {
        throw "publish-seed-nodes-rehearsal-smoke: missing $path"
    }
}

$docNeedles = @("publish-seed-nodes.sh", "TL-8", "Never publish RPC", "seed_nodes")
foreach ($n in $docNeedles) {
    if (-not (Select-String -LiteralPath $Doc -Pattern ([regex]::Escape($n)) -Quiet)) {
        throw "publish-seed-nodes-rehearsal-smoke: VPS_SINGLE_BOX_LAUNCH.md missing: $n"
    }
}
$inviteNeedles = @("seed_nodes", "public_devnet_v1.manifest.json", "checkpointLogVerify")
foreach ($n in $inviteNeedles) {
    if (-not (Select-String -LiteralPath $Invite -Pattern ([regex]::Escape($n)) -Quiet)) {
        throw "publish-seed-nodes-rehearsal-smoke: TESTNET_INVITE.md missing: $n"
    }
}
if (-not (Select-String -LiteralPath $Ops -Pattern "publish-seed-nodes" -Quiet)) {
    throw "publish-seed-nodes-rehearsal-smoke: OPERATORS.md missing publish-seed-nodes"
}

$bind = @{}
Get-Content -LiteralPath $BindExample | ForEach-Object {
    $line = $_.Trim()
    if ($line -match '^\s*#' -or $line -eq "") { return }
    if ($line -match '^([A-Za-z_][A-Za-z0-9_]*)=(.*)$') {
        $bind[$Matches[1]] = $Matches[2].Trim()
    }
}
function Read-BindPort {
    param([string]$Name)
    $listen = $bind[$Name]
    if (-not $listen) {
        throw "publish-seed-nodes-rehearsal-smoke: missing $Name in vps-bind.env.example"
    }
    return ($listen -split ":", 2)[-1]
}
$hubPort = Read-BindPort "MFN_P2P_LISTEN_HUB"
$v1Port = Read-BindPort "MFN_P2P_LISTEN_V1"
$v2Port = Read-BindPort "MFN_P2P_LISTEN_V2"
foreach ($port in @($hubPort, $v1Port, $v2Port)) {
    $seed = "${FixtureIp}:${port}"
    if ($seed -notmatch '^\d+\.\d+\.\d+\.\d+:\d+$') {
        throw "publish-seed-nodes-rehearsal-smoke: invalid fixture seed $seed"
    }
}
if ($hubPort -ne "19001" -or $v1Port -ne "19002" -or $v2Port -ne "19003") {
    throw "publish-seed-nodes-rehearsal-smoke: unexpected fixture ports $hubPort $v1Port $v2Port"
}

Write-Host "publish-seed-nodes-rehearsal-smoke: plan"
Write-Host "  flow=publish-seed-nodes.ps1 -PublicIp VPS_IP [-Apply]"
Write-Host "  fixture_bind=vps-bind.env.example"
Write-Host "  fixture_preview=${FixtureIp}:19001,19002,19003"
Write-Host "  manifest=mfn-node/testdata/public_devnet_v1.manifest.json"
Write-Host "  invite=docs/TESTNET_INVITE.md"
Write-Host "  live_rehearsal=human VPS after TL-7 sign-off"

if ($PlanOnly -or -not $PSBoundParameters.ContainsKey("PlanOnly")) {
    Write-Host "publish-seed-nodes-rehearsal-smoke: PASS plan-only"
    exit 0
}

throw "publish-seed-nodes-rehearsal-smoke: live mode not implemented; run publish-seed-nodes.ps1 on VPS"
