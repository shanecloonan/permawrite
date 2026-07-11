# P32 phase 4a / PM23: plan-only operator-manifest separation rehearsal (Windows).
param(
    [switch]$PlanOnly
)
$ErrorActionPreference = "Stop"

$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$RepoRoot = (Resolve-Path (Join-Path $ScriptDir "..\..")).Path
$Doc = Join-Path $RepoRoot "docs\REFERENCE_TOPOLOGY.md"
$Priv = Join-Path $RepoRoot "docs\PRIVACY_HARDENING.md"

foreach ($path in @($Doc, $Priv)) {
    if (-not (Test-Path -LiteralPath $path)) {
        throw "pm23-operator-manifest-rehearsal-smoke: missing $path"
    }
}

$docNeedles = @(
    "PM23",
    "Operator manifests",
    "stay off wallet machines",
    "operator-manifest separation"
)
foreach ($n in $docNeedles) {
    if (-not (Select-String -LiteralPath $Doc -Pattern ([regex]::Escape($n)) -Quiet)) {
        throw "pm23-operator-manifest-rehearsal-smoke: REFERENCE_TOPOLOGY.md missing: $n"
    }
}
if (-not (Select-String -LiteralPath $Priv -Pattern "PM23" -Quiet)) {
    throw "pm23-operator-manifest-rehearsal-smoke: PRIVACY_HARDENING.md missing PM23"
}

$walletTpl = Join-Path $ScriptDir "vps-role-wallet.env.example"
$validatorTpl = Join-Path $ScriptDir "vps-role-validator.env.example"
$operatorTpl = Join-Path $ScriptDir "vps-role-operator.env.example"
foreach ($path in @($walletTpl, $validatorTpl, $operatorTpl)) {
    if (-not (Test-Path -LiteralPath $path)) {
        throw "pm23-operator-manifest-rehearsal-smoke: missing $path"
    }
}

$walletText = Get-Content -Raw -LiteralPath $walletTpl
foreach ($forbidden in @("mfn-storage-operator", "manifest-info", "MFN_OPERATOR_DATA")) {
    if ($walletText -match [regex]::Escape($forbidden)) {
        throw "pm23-operator-manifest-rehearsal-smoke: wallet template must not reference $forbidden"
    }
}

$validatorText = Get-Content -Raw -LiteralPath $validatorTpl
foreach ($forbidden in @("MFN_WALLET", "mfn-storage-operator", "MFN_OPERATOR_DATA")) {
    if ($validatorText -match [regex]::Escape($forbidden)) {
        throw "pm23-operator-manifest-rehearsal-smoke: validator template must not reference $forbidden"
    }
}

$operatorText = Get-Content -Raw -LiteralPath $operatorTpl
if ($operatorText -notmatch "MFN_OPERATOR_DATA") {
    throw "pm23-operator-manifest-rehearsal-smoke: operator template missing MFN_OPERATOR_DATA"
}
if ($operatorText -match "MFND_VALIDATOR_INDEX" -or $operatorText -match "MFND_VRF_SEED") {
    throw "pm23-operator-manifest-rehearsal-smoke: operator template must not include validator seeds"
}

$topology = Join-Path $RepoRoot "mfn-node\src\role_topology.rs"
$pm23Rs = Join-Path $RepoRoot "mfn-storage-operator\src\pm23.rs"
if (-not (Select-String -LiteralPath $topology -Pattern "mfnd_pm23_warning" -Quiet)) {
    throw "pm23-operator-manifest-rehearsal-smoke: role_topology.rs missing mfnd_pm23_warning lint"
}
if (-not (Test-Path -LiteralPath $pm23Rs) -or -not (Select-String -LiteralPath $pm23Rs -Pattern "mfn_storage_operator_pm23_warning" -Quiet)) {
    throw "pm23-operator-manifest-rehearsal-smoke: mfn-storage-operator missing PM23 runtime lint"
}

Write-Host "pm23-operator-manifest-rehearsal-smoke: plan"
Write-Host "  flow=REFERENCE_TOPOLOGY PM23 rules + vps-role-*.env.example separation"
Write-Host "  wallet=no operator manifest / mfn-storage-operator paths"
Write-Host "  validator=no wallet or operator manifest paths"
Write-Host "  operator=operator data only; no validator seeds"
Write-Host "  runtime=mfnd_pm23_warning + mfn_storage_operator_pm23_warning (warn-only; MFND_PM23_HARD_FAIL=1)"
Write-Host "  docs=docs/REFERENCE_TOPOLOGY.md docs/PRIVACY_HARDENING.md"

if ($PlanOnly -or -not $PSBoundParameters.ContainsKey("PlanOnly")) {
    Write-Host "pm23-operator-manifest-rehearsal-smoke: PASS plan-only"
    exit 0
}

throw "pm23-operator-manifest-rehearsal-smoke: live mode not implemented"
