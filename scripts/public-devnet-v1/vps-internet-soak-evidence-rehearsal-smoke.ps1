# Lane 7 / TL-5: plan-only VPS soak evidence assert + launch-status PASS detection gate.
param(
    [switch]$PlanOnly
)

$ErrorActionPreference = "Stop"
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$RepoRoot = (Resolve-Path (Join-Path $ScriptDir "..\..")).Path
$Ops = Join-Path $ScriptDir "OPERATORS.md"
$Assert = Join-Path $ScriptDir "assert-vps-internet-soak-evidence.ps1"
$LaunchStatus = Join-Path $ScriptDir "launch-status.ps1"
$Fixture = Join-Path $ScriptDir "fixtures/vps-internet-soak-evidence-v1/vps-internet-soak-linux-30s-slot-20260712T000000Z.txt"

foreach ($f in @($Ops, $Assert, $LaunchStatus, $Fixture)) {
    if (-not (Test-Path -LiteralPath $f)) {
        throw "vps-internet-soak-evidence-rehearsal-smoke: missing $f"
    }
}

$opsText = Get-Content -Raw -LiteralPath $Ops
if ($opsText -notmatch "assert-vps-internet-soak-evidence") {
    throw "vps-internet-soak-evidence-rehearsal-smoke: OPERATORS.md missing assert-vps-internet-soak-evidence"
}
$launchText = Get-Content -Raw -LiteralPath $LaunchStatus
if ($launchText -notmatch "soak: SUMMARY status=PASS") {
    throw "vps-internet-soak-evidence-rehearsal-smoke: launch-status.ps1 must detect soak: SUMMARY status=PASS"
}

& $Assert -EvidenceFile $Fixture

$tmpEvidence = Join-Path ([System.IO.Path]::GetTempPath()) ("permawrite-soak-evidence-" + [guid]::NewGuid().ToString("n"))
New-Item -ItemType Directory -Force -Path $tmpEvidence | Out-Null
try {
    Copy-Item -LiteralPath $Fixture -Destination (Join-Path $tmpEvidence (Split-Path -Leaf $Fixture))
    $env:MFN_PUBLIC_DEVNET_EVIDENCE_DIR = $tmpEvidence
    $json = (& $LaunchStatus -Json | Out-String).Trim()
    $doc = $json | ConvertFrom-Json
    if (-not $doc.vps_soak_evidence) {
        throw "vps-internet-soak-evidence-rehearsal-smoke: launch-status must set vps_soak_evidence=true for fixture"
    }
} finally {
    Remove-Item -Recurse -Force -LiteralPath $tmpEvidence -ErrorAction SilentlyContinue
    Remove-Item Env:MFN_PUBLIC_DEVNET_EVIDENCE_DIR -ErrorAction SilentlyContinue
}

Write-Host "vps-internet-soak-evidence-rehearsal-smoke: plan"
Write-Host "  assert=assert-vps-internet-soak-evidence.ps1"
Write-Host "  fixture=fixtures/vps-internet-soak-evidence-v1/"
Write-Host "  launch-status=vps_soak_evidence=true on fixture"

if ($PlanOnly -or -not $PSBoundParameters.ContainsKey("PlanOnly")) {
    Write-Host "vps-internet-soak-evidence-rehearsal-smoke: PASS plan-only"
    exit 0
}

throw "vps-internet-soak-evidence-rehearsal-smoke: live mode not implemented"
