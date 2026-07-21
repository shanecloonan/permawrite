# Fail unless a B-27 outside-in invite-head soak evidence transcript is audit-ready.
param(
    [Parameter(Mandatory = $true, Position = 0)]
    [string]$EvidenceFile
)
$ErrorActionPreference = "Stop"
$ExpectedGenesis = if ($env:MFN_EXPECTED_GENESIS_ID) { $env:MFN_EXPECTED_GENESIS_ID } else { "454fa5d4a9bd6f59e35cf9ea7e68c096c9a271a92b2ec5931184e7f34a42a005" }

if (-not (Test-Path $EvidenceFile)) {
    throw "assert-outside-in-invite-soak-evidence: missing $EvidenceFile"
}
$base = Split-Path -Leaf $EvidenceFile
if ($base -notlike "outside-in-invite-soak-*") {
    throw "assert-outside-in-invite-soak-evidence: expected outside-in-invite-soak-*.txt got $base"
}
$text = Get-Content -Raw -Path $EvidenceFile
if ($text -notmatch "# B-27 outside-in invite-head soak") {
    throw "assert-outside-in-invite-soak-evidence: missing B-27 header"
}
if ($text -notmatch "never=faucet-http mfnd restart join-testnet-rehearsal") {
    throw "assert-outside-in-invite-soak-evidence: missing never= conflict guard"
}
if ($text -notmatch "soak: SUMMARY status=PASS") {
    throw "assert-outside-in-invite-soak-evidence: missing soak: SUMMARY status=PASS"
}
if ($text -notmatch "soak: SAMPLE ") {
    throw "assert-outside-in-invite-soak-evidence: missing soak: SAMPLE lines"
}
if ($text -notmatch [regex]::Escape("genesis_id=$ExpectedGenesis")) {
    throw "assert-outside-in-invite-soak-evidence: missing genesis_id=$ExpectedGenesis"
}

# B-96: permanence evidence must pin green Nightly + CI (auto-emitted by soak).
if ($text -notmatch '(?m)^# nightly_run=[0-9]+\s*$') {
    throw "assert-outside-in-invite-soak-evidence: missing # nightly_run=<id> pin"
}
if ($text -notmatch '(?m)^# ci_run=[0-9]+\s*$') {
    throw "assert-outside-in-invite-soak-evidence: missing # ci_run=<id> pin"
}
Write-Host "assert-outside-in-invite-soak-evidence: OK evidence_file=$EvidenceFile"
