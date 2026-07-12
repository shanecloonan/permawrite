# Fail unless a TL-6 VPS participant rehearsal evidence transcript is audit-ready.
param(
    [Parameter(Mandatory = $true)][string]$EvidenceFile
)
$ErrorActionPreference = "Stop"

if (-not (Test-Path -LiteralPath $EvidenceFile)) {
    throw "assert-vps-participant-rehearsal-evidence: missing $EvidenceFile"
}

$base = Split-Path -Leaf $EvidenceFile
if ($base -notlike "vps-participant-rehearsal-*") {
    throw "assert-vps-participant-rehearsal-evidence: expected vps-participant-rehearsal-*.txt got $base"
}

$text = Get-Content -Raw -LiteralPath $EvidenceFile
if ($text -notmatch [regex]::Escape("# TL-6 internet-facing VPS participant rehearsal")) {
    throw "assert-vps-participant-rehearsal-evidence: $EvidenceFile missing TL-6 VPS header"
}
if ($text -notmatch "(?m)^SUMMARY: PASS$") {
    throw "assert-vps-participant-rehearsal-evidence: $EvidenceFile missing SUMMARY: PASS"
}
if ($text -notmatch "participant-rehearsal-smoke: PASS with_observer=true") {
    throw "assert-vps-participant-rehearsal-evidence: $EvidenceFile missing observer PASS line"
}
if ($text -notmatch "hub_tip_height=(\d+) min_hub_height=(\d+)") {
    throw "assert-vps-participant-rehearsal-evidence: $EvidenceFile missing hub height summary"
}
$hubHeight = [int]$Matches[1]
$minHeight = [int]$Matches[2]
if ($hubHeight -lt $minHeight) {
    throw "assert-vps-participant-rehearsal-evidence: hub_tip_height=$hubHeight < min_hub_height=$minHeight"
}

Write-Host "assert-vps-participant-rehearsal-evidence: OK evidence_file=$EvidenceFile hub_tip_height=$hubHeight"
