# P32 / Lane 7: plan-only role-separated VPS env template rehearsal (Windows).
param(
    [switch]$PlanOnly
)
$ErrorActionPreference = "Stop"

$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$RepoRoot = (Resolve-Path (Join-Path $ScriptDir "..\..")).Path
$Doc = Join-Path $RepoRoot "docs\REFERENCE_TOPOLOGY.md"
$Provision = Join-Path $RepoRoot "docs\VPS_PROVISION.md"

foreach ($path in @($Doc, $Provision)) {
    if (-not (Test-Path -LiteralPath $path)) {
        throw "vps-role-templates-rehearsal-smoke: missing $path"
    }
}

$validatorTpl = Join-Path $ScriptDir "vps-role-validator.env.example"
$observerTpl = Join-Path $ScriptDir "vps-role-observer.env.example"
$operatorTpl = Join-Path $ScriptDir "vps-role-operator.env.example"
$walletTpl = Join-Path $ScriptDir "vps-role-wallet.env.example"

foreach ($path in @($validatorTpl, $observerTpl, $operatorTpl, $walletTpl)) {
    if (-not (Test-Path -LiteralPath $path)) {
        throw "vps-role-templates-rehearsal-smoke: missing $path"
    }
    $base = Split-Path -Leaf $path
    if (-not (Select-String -LiteralPath $Doc -Pattern ([regex]::Escape($base)) -Quiet)) {
        throw "vps-role-templates-rehearsal-smoke: REFERENCE_TOPOLOGY.md missing $base"
    }
}

if (-not (Select-String -LiteralPath $Provision -Pattern "vps-role-" -Quiet)) {
    throw "vps-role-templates-rehearsal-smoke: VPS_PROVISION.md missing vps-role- cross-link"
}

$validatorText = Get-Content -Raw -LiteralPath $validatorTpl
$observerText = Get-Content -Raw -LiteralPath $observerTpl
$operatorText = Get-Content -Raw -LiteralPath $operatorTpl
$walletText = Get-Content -Raw -LiteralPath $walletTpl

if ($validatorText -notmatch "MFND_PM23_HARD_FAIL=1") {
    throw "vps-role-templates-rehearsal-smoke: validator template missing MFND_PM23_HARD_FAIL=1"
}
if ($operatorText -notmatch "MFN_STORAGE_OPERATOR_PM23_HARD_FAIL=1" -and $operatorText -notmatch "MFND_PM23_HARD_FAIL=1") {
    throw "vps-role-templates-rehearsal-smoke: operator template missing PM23 hard-fail env"
}

foreach ($forbidden in @("MFND_VALIDATOR_INDEX", "MFND_VRF_SEED", "MFND_BLS_SEED")) {
    if ($observerText -match [regex]::Escape($forbidden)) {
        throw "vps-role-templates-rehearsal-smoke: observer template must not include $forbidden"
    }
}
foreach ($forbidden in @("MFN_WALLET", "mfn-storage-operator", "MFN_OPERATOR_DATA")) {
    if ($validatorText -match [regex]::Escape($forbidden)) {
        throw "vps-role-templates-rehearsal-smoke: validator template must not reference $forbidden"
    }
}
foreach ($forbidden in @("mfn-storage-operator", "manifest-info", "MFN_OPERATOR_DATA")) {
    if ($walletText -match [regex]::Escape($forbidden)) {
        throw "vps-role-templates-rehearsal-smoke: wallet template must not reference $forbidden"
    }
}

Write-Host "vps-role-templates-rehearsal-smoke: plan"
Write-Host "  docs=docs/REFERENCE_TOPOLOGY.md docs/VPS_PROVISION.md"
Write-Host "  templates=validator observer operator wallet"
Write-Host "  pm23=validator MFND_PM23_HARD_FAIL=1; operator storage-operator hard-fail"
Write-Host "  separation=observer no validator seeds; validator no wallet/operator paths"

if ($PlanOnly -or -not $PSBoundParameters.ContainsKey("PlanOnly")) {
    Write-Host "vps-role-templates-rehearsal-smoke: PASS plan-only"
    exit 0
}

throw "vps-role-templates-rehearsal-smoke: live mode not implemented"
