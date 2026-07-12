# Lane 7 / TL-5: plan-only VPS_PROVISION.md rehearsal gate (Windows).
param(
    [switch]$PlanOnly
)
$ErrorActionPreference = "Stop"

$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$RepoRoot = (Resolve-Path (Join-Path $ScriptDir "..\..")).Path
$Doc = Join-Path $RepoRoot "docs\VPS_PROVISION.md"
$Ops = Join-Path $RepoRoot "scripts\public-devnet-v1\OPERATORS.md"
$BindExample = Join-Path $ScriptDir "vps-bind.env.example"

foreach ($path in @($Doc, $Ops, $BindExample)) {
    if (-not (Test-Path -LiteralPath $path)) {
        throw "vps-provision-rehearsal-smoke: missing $path"
    }
}

$needles = @(
    "vps-preflight.sh",
    "vps-execution-checklist",
    "vps-internet-soak.sh",
    "vps-launch-ceremony",
    "publish-seed-nodes",
    "TESTNET_INVITE.md",
    "VPS_SINGLE_BOX_LAUNCH.md"
)
$docText = Get-Content -Raw -LiteralPath $Doc
foreach ($n in $needles) {
    if ($docText -notmatch [regex]::Escape($n)) {
        throw "vps-provision-rehearsal-smoke: VPS_PROVISION.md missing: $n"
    }
}
if (-not (Select-String -LiteralPath $Ops -Pattern "VPS_PROVISION.md" -Quiet)) {
    throw "vps-provision-rehearsal-smoke: OPERATORS.md missing VPS_PROVISION.md cross-link"
}
$bindText = Get-Content -Raw -LiteralPath $BindExample
if ($bindText -notmatch "MFND_PM23_HARD_FAIL=1") {
    throw "vps-provision-rehearsal-smoke: vps-bind.env.example missing MFND_PM23_HARD_FAIL=1"
}

$validatorTpl = Join-Path $ScriptDir "vps-role-validator.env.example"
$operatorTpl = Join-Path $ScriptDir "vps-role-operator.env.example"
foreach ($path in @($validatorTpl, $operatorTpl)) {
    if (-not (Test-Path -LiteralPath $path)) {
        throw "vps-provision-rehearsal-smoke: missing $path"
    }
}
$validatorText = Get-Content -Raw -LiteralPath $validatorTpl
$operatorText = Get-Content -Raw -LiteralPath $operatorTpl
if ($validatorText -notmatch "MFND_PM23_HARD_FAIL=1") {
    throw "vps-provision-rehearsal-smoke: validator template missing MFND_PM23_HARD_FAIL=1"
}
if ($operatorText -notmatch "MFN_STORAGE_OPERATOR_PM23_HARD_FAIL=1" -and $operatorText -notmatch "MFND_PM23_HARD_FAIL=1") {
    throw "vps-provision-rehearsal-smoke: operator template missing PM23 hard-fail env"
}

Write-Host "vps-provision-rehearsal-smoke: plan"
Write-Host "  docs=docs/VPS_PROVISION.md"
Write-Host "  flow=provision -> preflight -> soak -> ceremony -> TL-8"
Write-Host "  pm23=vps-bind + vps-role-validator MFND_PM23_HARD_FAIL=1; operator MFN_STORAGE_OPERATOR_PM23_HARD_FAIL=1"
Write-Host "  live_rehearsal=human VPS provision before TL-5"

if ($PlanOnly -or -not $PSBoundParameters.ContainsKey("PlanOnly")) {
    Write-Host "vps-provision-rehearsal-smoke: PASS plan-only"
    exit 0
}

throw "vps-provision-rehearsal-smoke: live mode not implemented"
