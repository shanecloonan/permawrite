# Lane 7 / TL-5: plan-only vps-preflight rehearsal gate (Windows).
param(
    [switch]$PlanOnly
)
$ErrorActionPreference = "Stop"

$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$RepoRoot = (Resolve-Path (Join-Path $ScriptDir "..\..")).Path
$Doc = Join-Path $RepoRoot "docs\VPS_SINGLE_BOX_LAUNCH.md"
$Ops = Join-Path $RepoRoot "scripts\public-devnet-v1\OPERATORS.md"
$Preflight = Join-Path $ScriptDir "vps-preflight.sh"
$BindExample = Join-Path $ScriptDir "vps-bind.env.example"

foreach ($path in @($Doc, $Ops, $Preflight, $BindExample)) {
    if (-not (Test-Path -LiteralPath $path)) {
        throw "vps-preflight-rehearsal-smoke: missing $path"
    }
}

$docNeedles = @("vps-preflight.sh", "vps-internet-soak.sh", "vps-bind.env")
foreach ($n in $docNeedles) {
    if (-not (Select-String -LiteralPath $Doc -Pattern ([regex]::Escape($n)) -Quiet)) {
        throw "vps-preflight-rehearsal-smoke: VPS_SINGLE_BOX_LAUNCH.md missing: $n"
    }
}
if (-not (Select-String -LiteralPath $Ops -Pattern "vps-preflight" -Quiet)) {
    throw "vps-preflight-rehearsal-smoke: OPERATORS.md missing vps-preflight"
}

$preflightText = Get-Content -Raw -LiteralPath $Preflight
foreach ($required in @(
    "vps-bind-lib.sh",
    "mfn-storage-operator",
    "454fa5d4a9bd6f59e35cf9ea7e68c096c9a271a92b2ec5931184e7f34a42a005",
    "vps-internet-soak.sh"
)) {
    if ($preflightText -notmatch [regex]::Escape($required)) {
        throw "vps-preflight-rehearsal-smoke: vps-preflight.sh missing: $required"
    }
}

Write-Host "vps-preflight-rehearsal-smoke: plan"
Write-Host "  flow=vps-preflight.sh -> vps-internet-soak.sh"
Write-Host "  bind_template=vps-bind.env.example"
Write-Host "  docs=docs/VPS_SINGLE_BOX_LAUNCH.md"
Write-Host "  live_rehearsal=human VPS before TL-5 soak"

if ($PlanOnly -or -not $PSBoundParameters.ContainsKey("PlanOnly")) {
    Write-Host "vps-preflight-rehearsal-smoke: PASS plan-only"
    exit 0
}

throw "vps-preflight-rehearsal-smoke: live mode not implemented; run vps-preflight.sh on VPS"
