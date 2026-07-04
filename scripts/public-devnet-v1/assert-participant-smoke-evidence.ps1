# Fail unless participant-rehearsal-smoke staged audit-ready evidence exists.
param(
    [string]$EvidenceDir = ""
)
$ErrorActionPreference = "Stop"

$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
if (-not $EvidenceDir) {
    $EvidenceDir = Join-Path $ScriptDir "participant-rehearsal-smoke/evidence"
}
$LogPath = Join-Path $EvidenceDir "participant-rehearsal.log"
$BundleDir = Join-Path $EvidenceDir "support-bundle"
$ManifestPath = Join-Path $BundleDir "manifest.json"

if (-not (Test-Path -LiteralPath $LogPath -PathType Leaf)) {
    throw "assert-participant-smoke-evidence: missing $LogPath"
}
if (-not (Test-Path -LiteralPath $BundleDir -PathType Container)) {
    throw "assert-participant-smoke-evidence: missing support bundle directory $BundleDir"
}
$logText = Get-Content -LiteralPath $LogPath -Raw
if ($logText -notmatch "participant-rehearsal: PASS commitment_hash=[0-9a-fA-F]+ restored_sha256=[0-9a-fA-F]{64} restored_path=\S+ support_bundle=") {
    throw "assert-participant-smoke-evidence: $LogPath missing final PASS line"
}
if (-not (Test-Path -LiteralPath $ManifestPath -PathType Leaf)) {
    throw "assert-participant-smoke-evidence: missing $ManifestPath"
}
Write-Host "assert-participant-smoke-evidence: OK evidence_dir=$EvidenceDir"
