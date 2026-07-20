# Fail unless a B-32 B3 multi-op SPoRA evidence transcript is audit-ready.
param(
    [Parameter(Mandatory = $true)]
    [string]$EvidenceFile
)
$ErrorActionPreference = "Stop"
if (-not (Test-Path -LiteralPath $EvidenceFile -PathType Leaf)) {
    throw "assert-b3-multi-op-evidence: missing $EvidenceFile"
}
$base = [System.IO.Path]::GetFileName($EvidenceFile)
if ($base -notlike "b3-multi-op-*") {
    throw "assert-b3-multi-op-evidence: expected b3-multi-op-*.txt got $base"
}
$text = Get-Content -LiteralPath $EvidenceFile -Raw
if ($text -notmatch [regex]::Escape("# B-32 B3 multi-op SPoRA evidence")) {
    throw "assert-b3-multi-op-evidence: missing B-32 header"
}
if ($text -notmatch "(?m)^SUMMARY: PASS$") {
    throw "assert-b3-multi-op-evidence: missing SUMMARY: PASS"
}
if ($text -notmatch "(?m)^operator_count=(\d+)$") {
    throw "assert-b3-multi-op-evidence: missing operator_count"
}
$opCount = [int]$Matches[1]
if ($opCount -lt 2) {
    throw "assert-b3-multi-op-evidence: need operator_count>=2 got $opCount"
}
foreach ($key in @("distinct_hosts", "distinct_payouts", "spora_proofs_from_both")) {
    if ($text -notmatch "(?m)^${key}=true$") {
        throw "assert-b3-multi-op-evidence: missing ${key}=true"
    }
}
if ($text -notmatch "(?m)^commitment_hash=[0-9a-fA-F]{64}$") {
    throw "assert-b3-multi-op-evidence: missing commitment_hash=64hex"
}
if ($text -notmatch "(?m)^tip_height=(\d+)$") {
    throw "assert-b3-multi-op-evidence: missing tip_height"
}
$tip = [int64]$Matches[1]
if ($tip -le 0) {
    throw "assert-b3-multi-op-evidence: invalid tip_height=$tip"
}
Write-Host "assert-b3-multi-op-evidence: OK evidence_file=$EvidenceFile operator_count=$opCount tip_height=$tip"