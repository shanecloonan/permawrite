param(
    [switch]$PlanOnly,
    [switch]$Help
)
$ErrorActionPreference = "Stop"
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
if ($Help) {
    Write-Host @"
usage: b32-arm-ready-rehearsal-smoke.ps1 [-PlanOnly]
Validates assert-b32-arm-ready.sh plan gate (B-79; no live second host).
"@
    exit 0
}
$assert = Join-Path $ScriptDir "assert-b32-arm-ready.sh"
if (-not (Test-Path -LiteralPath $assert)) { throw "b32-arm-ready-rehearsal-smoke: missing $assert" }
$needles = @("assert-b32-arm-ready", "B-79", "B-32", "distinct_hosts", "never=faucet-http", "lib-ci-roll-gate")
$text = Get-Content -LiteralPath $assert -Raw
foreach ($n in $needles) {
    if ($text -notlike "*$n*") { throw "b32-arm-ready-rehearsal-smoke: missing needle $n" }
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
    if ($plan -notmatch "assert-b32-arm-ready: PASS plan-only") {
        $plan | ForEach-Object { [Console]::Error.WriteLine($_) }
        exit 1
    }
} elseif ($text -notlike "*assert-b32-arm-ready: PASS plan-only*") {
    throw "b32-arm-ready-rehearsal-smoke: no bash and assert missing PASS plan-only marker"
}
Write-Host "b32-arm-ready-rehearsal-smoke: PASS plan-only"
exit 0
