# Fail unless a B-15 JOIN_TESTNET live rehearsal evidence transcript is audit-ready.
param(
    [Parameter(Mandatory = $true)][string]$EvidenceFile
)
$ErrorActionPreference = "Stop"

if (-not (Test-Path -LiteralPath $EvidenceFile)) {
    throw "assert-join-testnet-rehearsal-evidence: missing $EvidenceFile"
}

$base = Split-Path -Leaf $EvidenceFile
if ($base -notlike "join-testnet-rehearsal-*") {
    throw "assert-join-testnet-rehearsal-evidence: expected join-testnet-rehearsal-*.txt got $base"
}

$text = Get-Content -Raw -LiteralPath $EvidenceFile
if ($text -notmatch [regex]::Escape("# B-15 live testnet JOIN_TESTNET participant rehearsal")) {
    throw "assert-join-testnet-rehearsal-evidence: $EvidenceFile missing B-15 header"
}
if ($text -notmatch "(?m)^SUMMARY: PASS$") {
    throw "assert-join-testnet-rehearsal-evidence: $EvidenceFile missing SUMMARY: PASS"
}
if ($text -notmatch "join-testnet-rehearsal-smoke: PASS faucet_http=true light_scan_checkpoint=true observer_proxy=true") {
    throw "assert-join-testnet-rehearsal-evidence: $EvidenceFile missing smoke PASS line"
}
if ($text -notmatch "join-testnet-rehearsal: PASS .*faucet_http=true light_scan_checkpoint=true") {
    throw "assert-join-testnet-rehearsal-evidence: $EvidenceFile missing rehearsal PASS line"
}
if ($text -notmatch "(?m)^tip_height=(\d+)$") {
    throw "assert-join-testnet-rehearsal-evidence: $EvidenceFile missing tip_height"
}
$tipHeight = [int]$Matches[1]
if ($tipHeight -le 0) {
    throw "assert-join-testnet-rehearsal-evidence: invalid tip_height=$tipHeight"
}

Write-Host "assert-join-testnet-rehearsal-evidence: OK evidence_file=$EvidenceFile tip_height=$tipHeight"
