# Lane 7 / TL-8: plan-only TESTNET_INVITE.md packet rehearsal gate (Windows).
param(
    [switch]$PlanOnly
)
$ErrorActionPreference = "Stop"

$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$RepoRoot = (Resolve-Path (Join-Path $ScriptDir "..\..")).Path
$Invite = Join-Path $RepoRoot "docs\TESTNET_INVITE.md"
$Genesis = Join-Path $RepoRoot "mfn-node\testdata\public_devnet_v1.json"
$Manifest = Join-Path $RepoRoot "mfn-node\testdata\public_devnet_v1.manifest.json"
$Ops = Join-Path $RepoRoot "scripts\public-devnet-v1\OPERATORS.md"
$CheckpointDoc = Join-Path $RepoRoot "docs\CHECKPOINT_LOG.md"

foreach ($path in @($Invite, $Genesis, $Manifest, $Ops, $CheckpointDoc)) {
    if (-not (Test-Path -LiteralPath $path)) {
        throw "testnet-invite-rehearsal-smoke: missing $path"
    }
}

$manifestDoc = Get-Content -Raw -Encoding UTF8 $Manifest | ConvertFrom-Json
$expectedGenesis = $manifestDoc.genesis_id
$inviteText = Get-Content -Raw -LiteralPath $Invite

$needles = @(
    "public-devnet-v1",
    $expectedGenesis,
    "public_devnet_v1.manifest.json",
    "public_devnet_v1.checkpoints.jsonl",
    "checkpointLogVerify",
    "checkpointLogCrossCheck",
    "What we do not publish",
    "Never share",
    "host:port"
)
foreach ($n in $needles) {
    if ($inviteText -notmatch [regex]::Escape($n)) {
        throw "testnet-invite-rehearsal-smoke: TESTNET_INVITE.md missing: $n"
    }
}

foreach ($n in @("TESTNET_INVITE.md", "publish-seed-nodes")) {
    if (-not (Select-String -LiteralPath $Ops -Pattern ([regex]::Escape($n)) -Quiet)) {
        throw "testnet-invite-rehearsal-smoke: OPERATORS.md missing: $n"
    }
}

if ($inviteText -match 'seed_nodes[^\n]*1873[0-9]') {
    throw "testnet-invite-rehearsal-smoke: invite must not advertise RPC ports in seed_nodes examples"
}

Write-Host "testnet-invite-rehearsal-smoke: plan"
Write-Host "  invite=docs/TESTNET_INVITE.md"
Write-Host "  genesis_id=$expectedGenesis"
Write-Host "  live_rehearsal=share invite after TL-8 publish-seed-nodes --apply + checkpoint log"

if ($PlanOnly -or -not $PSBoundParameters.ContainsKey("PlanOnly")) {
    Write-Host "testnet-invite-rehearsal-smoke: PASS plan-only"
    exit 0
}

throw "testnet-invite-rehearsal-smoke: live mode not implemented"
