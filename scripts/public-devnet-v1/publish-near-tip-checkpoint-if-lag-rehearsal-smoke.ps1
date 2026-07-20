param(
    [switch]$PlanOnly,
    [switch]$Help
)
$ErrorActionPreference = "Stop"
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
if ($Help) {
    Write-Host "usage: publish-near-tip-checkpoint-if-lag-rehearsal-smoke.ps1 [-PlanOnly]"
    exit 0
}
$assert = Join-Path $ScriptDir "publish-near-tip-checkpoint-if-lag.sh"
if (-not (Test-Path -LiteralPath $assert)) {
    throw "publish-near-tip-checkpoint-if-lag-rehearsal-smoke: missing $assert"
}
$needles = @(
    "publish-near-tip-checkpoint-if-lag",
    "B-85",
    "lag_threshold",
    "never=faucet-http",
    "bootstrap-path-a-checkpoint-signer"
)
$text = Get-Content -LiteralPath $assert -Raw
foreach ($n in $needles) {
    if ($text -notlike "*$n*") {
        throw "publish-near-tip-checkpoint-if-lag-rehearsal-smoke: missing needle $n"
    }
}
$bashPath = $null
foreach ($candidate in @(
        "C:\msys64\usr\bin\bash.exe",
        "C:\Program Files\Git\bin\bash.exe",
        "C:\Program Files\Git\usr\bin\bash.exe"
    )) {
    if (Test-Path -LiteralPath $candidate) { $bashPath = $candidate; break }
}
if (-not $bashPath) {
    $cmd = Get-Command bash -ErrorAction SilentlyContinue
    if ($cmd) { $bashPath = $cmd.Source }
}
if ($bashPath) {
    $bashDir = Split-Path -Parent $bashPath
    $prevPath = $env:Path
    try {
        $env:Path = "$bashDir;C:\msys64\usr\bin;$prevPath"
        $plan = (& $bashPath $assert --plan-only 2>&1) -join "`n"
    } finally {
        $env:Path = $prevPath
    }
    if ($plan -notmatch "publish-near-tip-checkpoint-if-lag: PASS plan-only") {
        $plan | ForEach-Object { [Console]::Error.WriteLine($_) }
        exit 1
    }
} elseif ($text -notlike "*publish-near-tip-checkpoint-if-lag: PASS plan-only*") {
    throw "publish-near-tip-checkpoint-if-lag-rehearsal-smoke: no bash and missing PASS marker"
}
Write-Host "publish-near-tip-checkpoint-if-lag-rehearsal-smoke: PASS plan-only"
exit 0