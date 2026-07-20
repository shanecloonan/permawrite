# B-32: plan-only multi-op evidence assert + ROADMAP wiring gate (no live mesh).
param(
    [switch]$PlanOnly,
    [switch]$Help
)
$ErrorActionPreference = "Stop"
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$RepoRoot = (Resolve-Path (Join-Path $ScriptDir "../..")).Path
$Roadmap = Join-Path $RepoRoot "docs/ROADMAP.md"
$Permanence = Join-Path $RepoRoot "docs/PERMANENCE_HARDENING.md"
$Assert = Join-Path $ScriptDir "assert-b3-multi-op-evidence.ps1"
$Fixture = Join-Path $ScriptDir "fixtures/b3-multi-op-evidence-v1/b3-multi-op-linux-20260720T000000Z.txt"

if ($Help) {
    Write-Host @"
usage: b3-multi-op-evidence-rehearsal-smoke.ps1 [-PlanOnly]

Validates assert-b3-multi-op-evidence + B-32 doc wiring (no live operators).
"@
    exit 0
}

foreach ($f in @($Roadmap, $Assert, $Fixture)) {
    if (-not (Test-Path -LiteralPath $f -PathType Leaf)) {
        throw "b3-multi-op-evidence-rehearsal-smoke: missing $f"
    }
}

$roadmapText = Get-Content -LiteralPath $Roadmap -Raw
foreach ($needle in @("B-32", "b3-multi-op", "assert-b3-multi-op-evidence")) {
    if ($roadmapText -notlike "*$needle*") {
        throw "b3-multi-op-evidence-rehearsal-smoke: ROADMAP.md missing: $needle"
    }
}

if (Test-Path -LiteralPath $Permanence -PathType Leaf) {
    $permText = Get-Content -LiteralPath $Permanence -Raw
    if ($permText -notlike "*B-32*") {
        Write-Host "b3-multi-op-evidence-rehearsal-smoke: WARN PERMANENCE_HARDENING.md missing B-32 (non-fatal)"
    }
}

& $Assert -EvidenceFile $Fixture | Out-Host

Write-Host "b3-multi-op-evidence-rehearsal-smoke: plan"
Write-Host "  assert=assert-b3-multi-op-evidence.sh|.ps1"
Write-Host "  fixture=fixtures/b3-multi-op-evidence-v1/"
Write-Host "  live=archive b3-multi-op-<date>.txt after >=2 operators prove SPoRA (arm day-of L4)"
Write-Host "b3-multi-op-evidence-rehearsal-smoke: PASS plan-only"
exit 0