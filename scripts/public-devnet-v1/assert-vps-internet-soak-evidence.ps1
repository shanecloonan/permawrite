# Fail unless a TL-5 VPS internet soak evidence transcript is audit-ready.
param(
    [Parameter(Mandatory = $true)][string]$EvidenceFile
)
$ErrorActionPreference = "Stop"

if (-not (Test-Path -LiteralPath $EvidenceFile)) {
    throw "assert-vps-internet-soak-evidence: missing $EvidenceFile"
}

$base = Split-Path -Leaf $EvidenceFile
if ($base -notlike "vps-internet-soak-linux-*") {
    throw "assert-vps-internet-soak-evidence: expected vps-internet-soak-linux-*.txt got $base"
}

$text = Get-Content -Raw -LiteralPath $EvidenceFile
if ($text -notmatch [regex]::Escape("# TL-5 internet-facing VPS soak")) {
    throw "assert-vps-internet-soak-evidence: $EvidenceFile missing TL-5 VPS header"
}
if ($text -notmatch "soak: SUMMARY status=PASS") {
    throw "assert-vps-internet-soak-evidence: $EvidenceFile missing soak: SUMMARY status=PASS"
}
if ($text -notmatch "soak: SAMPLE ") {
    throw "assert-vps-internet-soak-evidence: $EvidenceFile missing soak: SAMPLE lines"
}
$expectedGenesis = "454fa5d4a9bd6f59e35cf9ea7e68c096c9a271a92b2ec5931184e7f34a42a005"
if ($text -notmatch [regex]::Escape("genesis_id=$expectedGenesis")) {
    throw "assert-vps-internet-soak-evidence: $EvidenceFile missing genesis_id=$expectedGenesis"
}

Write-Host "assert-vps-internet-soak-evidence: OK evidence_file=$EvidenceFile"
