# Lane 7 / TL-9: plan-only launch-go-no-go schema rehearsal (Windows).
param(
    [switch]$PlanOnly
)
# NOTE: intentionally "Continue", not "Stop" - see launch-go-no-go.ps1 for why:
# capturing a native command's stderr via `2>&1` throws under EAP "Stop" even
# when the destination is discarded. All failure signaling below is explicit
# (`throw`), which is unaffected by $ErrorActionPreference.
$ErrorActionPreference = "Continue"

$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$RepoRoot = (Resolve-Path (Join-Path $ScriptDir "..\..")).Path
$Ops = Join-Path $RepoRoot "scripts\public-devnet-v1\OPERATORS.md"
$Playbook = Join-Path $RepoRoot "docs\TESTNET_LAUNCH.md"

foreach ($path in @($Ops, $Playbook)) {
    if (-not (Test-Path -LiteralPath $path)) {
        throw "launch-go-no-go-rehearsal-smoke: missing $path"
    }
}
if (-not (Select-String -LiteralPath $Ops -Pattern "launch-go-no-go" -Quiet)) {
    throw "launch-go-no-go-rehearsal-smoke: OPERATORS.md missing launch-go-no-go"
}

# Capture output via the call operator (not Start-Process + redirected files): on Windows
# CI runners, Start-Process -RedirectStandardOutput/-Wait can return before the redirected
# files are fully flushed to disk, intermittently yielding truncated/empty captures.
$rawOutput = & powershell -NoProfile -File (Join-Path $ScriptDir "launch-go-no-go.ps1") -Json 2>&1
$exitCode = $LASTEXITCODE
$combined = ($rawOutput | Out-String)

if ($combined -notmatch '\{[\s\S]*"schema_version"\s*:\s*"launch-go-no-go\.v1"[\s\S]*\}') {
    throw "launch-go-no-go-rehearsal-smoke: JSON block missing from launch-go-no-go.ps1 -Json output"
}
$jsonText = $Matches[0]
$report = $jsonText | ConvertFrom-Json

if ($report.schema_version -ne "launch-go-no-go.v1") {
    throw "launch-go-no-go-rehearsal-smoke: expected launch-go-no-go.v1 got $($report.schema_version)"
}
$expectedGenesis = "454fa5d4a9bd6f59e35cf9ea7e68c096c9a271a92b2ec5931184e7f34a42a005"
if ($report.genesis_id -ne $expectedGenesis) {
    throw "launch-go-no-go-rehearsal-smoke: unexpected genesis_id $($report.genesis_id)"
}
if ($report.seed_nodes_count -ge 3 -and $exitCode -eq 0) {
    if (-not $report.automatable_pass) {
        throw "launch-go-no-go-rehearsal-smoke: post-TL-8 automatable_pass must be true when seed_nodes>=3 and exit 0"
    }
} else {
    if ($report.automatable_pass -ne $false) {
        throw "launch-go-no-go-rehearsal-smoke: pre-launch automatable_pass must be false"
    }
    if ($exitCode -eq 0) {
        throw "launch-go-no-go-rehearsal-smoke: expected non-zero exit before TL-5/TL-6 VPS evidence"
    }
}

Write-Host "launch-go-no-go-rehearsal-smoke: plan"
Write-Host "  schema=$($report.schema_version)"
Write-Host "  genesis_id=$($report.genesis_id)"
Write-Host "  seed_nodes_count=$($report.seed_nodes_count)"
Write-Host "  automatable_pass=$($report.automatable_pass)"
Write-Host "  checkpoint=Schnorr verify required when seed_nodes>=3 (mfn-cli checkpoint-log verify)"
Write-Host "  helper=launch-go-no-go.ps1 [-Json]"

if ($PlanOnly -or -not $PSBoundParameters.ContainsKey("PlanOnly")) {
    Write-Host "launch-go-no-go-rehearsal-smoke: PASS plan-only"
    exit 0
}

throw "launch-go-no-go-rehearsal-smoke: live mode not implemented"
