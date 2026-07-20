# B-27 / lane 1: outside-in invite-head soak via public observer proxy (Windows twin).
param(
    [switch]$PlanOnly,
    [switch]$NoArchive
)
$ErrorActionPreference = "Stop"
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$RepoRoot = if ($env:MFN_REPO_ROOT) { $env:MFN_REPO_ROOT } else { (Resolve-Path (Join-Path $ScriptDir "..\..")).Path }
$ProxyUrl = if ($env:MFN_OUTSIDE_IN_PROXY_URL) { $env:MFN_OUTSIDE_IN_PROXY_URL } else { "http://5.161.201.73:8787/rpc" }
$ExpectedGenesis = if ($env:MFN_EXPECTED_GENESIS_ID) { $env:MFN_EXPECTED_GENESIS_ID } else { "454fa5d4a9bd6f59e35cf9ea7e68c096c9a271a92b2ec5931184e7f34a42a005" }
$Samples = if ($env:MFN_OUTSIDE_IN_SOAK_SAMPLES) { [int]$env:MFN_OUTSIDE_IN_SOAK_SAMPLES } else { 6 }
$IntervalS = if ($env:MFN_OUTSIDE_IN_SOAK_INTERVAL_S) { [int]$env:MFN_OUTSIDE_IN_SOAK_INTERVAL_S } else { 45 }
$MinDelta = if ($env:MFN_OUTSIDE_IN_SOAK_MIN_DELTA) { [int]$env:MFN_OUTSIDE_IN_SOAK_MIN_DELTA } else { 1 }
$EvidenceDir = Join-Path $ScriptDir "evidence"

if ($PlanOnly) {
    Write-Host "outside-in-invite-soak: plan"
    Write-Host "  unit=B-27"
    Write-Host "  proxy=$ProxyUrl"
    Write-Host "  samples=$Samples interval_s=$IntervalS min_delta=$MinDelta"
    Write-Host "  never=faucet-http mfnd restart join-testnet-rehearsal"
    Write-Host "  assert=assert-outside-in-invite-soak-evidence.ps1"
    Write-Host "outside-in-invite-soak: PASS plan-only"
    exit 0
}

Push-Location $RepoRoot
try {
    $headSha = (git rev-parse HEAD 2>$null)
    if (-not $headSha) { $headSha = "unknown" }
} finally {
    Pop-Location
}
$ts = (Get-Date).ToUniversalTime().ToString("yyyyMMddTHHmmssZ")
$lines = New-Object System.Collections.Generic.List[string]
$lines.Add("# B-27 outside-in invite-head soak (public observer proxy)")
$lines.Add("# head_sha=$headSha")
$lines.Add("# proxy=$ProxyUrl")
$lines.Add("# samples=$Samples interval_s=$IntervalS min_delta=$MinDelta")
$lines.Add("# never=faucet-http mfnd restart join-testnet-rehearsal")
if ($env:MFN_B27_NIGHTLY_RUN) { $lines.Add("# nightly_run=$($env:MFN_B27_NIGHTLY_RUN)") }
if ($env:MFN_B27_CI_RUN) { $lines.Add("# ci_run=$($env:MFN_B27_CI_RUN)") }

function Get-Tip {
    $body = '{"jsonrpc":"2.0","id":1,"method":"get_tip","params":[]}'
    $r = Invoke-WebRequest -Uri $ProxyUrl -Method POST -Body $body -ContentType "application/json" -TimeoutSec 30 -UseBasicParsing
    return ($r.Content | ConvertFrom-Json).result
}

$firstH = $null
$lastH = $null
for ($i = 1; $i -le $Samples; $i++) {
    $tip = Get-Tip
    if ($tip.genesis_id -ne $ExpectedGenesis) {
        throw "outside-in-invite-soak: FAIL genesis_id mismatch got=$($tip.genesis_id)"
    }
    $sample = "soak: SAMPLE i=$i tip_height=$($tip.tip_height) tip_id=$($tip.tip_id) genesis_id=$($tip.genesis_id) validator_count=$($tip.validator_count)"
    $lines.Add($sample)
    Write-Host $sample
    if ($null -eq $firstH) { $firstH = [int]$tip.tip_height }
    $lastH = [int]$tip.tip_height
    if ($i -lt $Samples) { Start-Sleep -Seconds $IntervalS }
}

$delta = $lastH - $firstH
$status = "PASS"
$reason = "ok"
if ($delta -lt $MinDelta) {
    $status = "FAIL"
    $reason = "tip_stall first=$firstH last=$lastH delta=$delta min_delta=$MinDelta"
}
$summary = "soak: SUMMARY status=$status first_tip_height=$firstH last_tip_height=$lastH delta=$delta samples=$Samples genesis_id=$ExpectedGenesis head_sha=$headSha reason=$reason"
$lines.Add($summary)
Write-Host $summary

if (-not $NoArchive) {
    New-Item -ItemType Directory -Force -Path $EvidenceDir | Out-Null
    $out = Join-Path $EvidenceDir "outside-in-invite-soak-$ts.txt"
    Set-Content -Path $out -Value $lines -Encoding utf8
    Write-Host "soak: EVIDENCE archived=$out status=$status"
}
if ($status -ne "PASS") { throw "outside-in-invite-soak: FAIL $reason" }
Write-Host "outside-in-invite-soak: PASS delta=$delta last_tip_height=$lastH"
