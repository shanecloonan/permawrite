# Lane 7 / TL-6: plan-only VPS participant evidence assert + launch-status PASS gate.
param(
    [switch]$PlanOnly
)
$ErrorActionPreference = "Stop"

$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$RepoRoot = (Resolve-Path (Join-Path $ScriptDir "..\..")).Path
$Ops = Join-Path $ScriptDir "OPERATORS.md"
$Assert = Join-Path $ScriptDir "assert-vps-participant-rehearsal-evidence.ps1"
$LaunchStatus = Join-Path $ScriptDir "launch-status.ps1"
$Fixture = Join-Path $ScriptDir "fixtures/vps-participant-rehearsal-evidence-v1/vps-participant-rehearsal-observer-linux-20260712T000000Z.txt"

foreach ($f in @($Ops, $Assert, $LaunchStatus, $Fixture)) {
    if (-not (Test-Path -LiteralPath $f)) {
        throw "vps-participant-rehearsal-evidence-rehearsal-smoke: missing $f"
    }
}

$opsText = Get-Content -Raw -LiteralPath $Ops
if ($opsText -notmatch "assert-vps-participant-rehearsal-evidence") {
    throw "vps-participant-rehearsal-evidence-rehearsal-smoke: OPERATORS.md missing assert-vps-participant-rehearsal-evidence"
}

& $Assert -EvidenceFile $Fixture

$tmpEvidence = Join-Path ([System.IO.Path]::GetTempPath()) ("permawrite-participant-evidence-" + [guid]::NewGuid().ToString("n"))
New-Item -ItemType Directory -Force -Path $tmpEvidence | Out-Null
try {
    Copy-Item -LiteralPath $Fixture -Destination (Join-Path $tmpEvidence (Split-Path -Leaf $Fixture))
    $env:MFN_PUBLIC_DEVNET_EVIDENCE_DIR = $tmpEvidence
    $json = (& $LaunchStatus -Json | Out-String).Trim()
    $doc = $json | ConvertFrom-Json
    if (-not $doc.vps_rehearsal_evidence) {
        throw "vps-participant-rehearsal-evidence-rehearsal-smoke: launch-status must set vps_rehearsal_evidence=true for fixture"
    }
} finally {
    Remove-Item -Recurse -Force -LiteralPath $tmpEvidence -ErrorAction SilentlyContinue
    Remove-Item Env:MFN_PUBLIC_DEVNET_EVIDENCE_DIR -ErrorAction SilentlyContinue
}

Write-Host "vps-participant-rehearsal-evidence-rehearsal-smoke: plan"
Write-Host "  assert=assert-vps-participant-rehearsal-evidence.ps1"
Write-Host "  fixture=fixtures/vps-participant-rehearsal-evidence-v1/"
Write-Host "  launch-status=vps_rehearsal_evidence=true on fixture"

if ($PlanOnly -or -not $PSBoundParameters.ContainsKey("PlanOnly")) {
    Write-Host "vps-participant-rehearsal-evidence-rehearsal-smoke: PASS plan-only"
    exit 0
}

throw "vps-participant-rehearsal-evidence-rehearsal-smoke: live mode not implemented"
