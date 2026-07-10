# Lane 5 / F12 phase 5: plan-only demo web checkpoint-log WASM wiring gate (Windows).
param(
    [switch]$PlanOnly
)
$ErrorActionPreference = "Stop"

$RepoRoot = (Resolve-Path (Join-Path (Split-Path -Parent $MyInvocation.MyCommand.Path) "..\..")).Path
$Index = Join-Path $RepoRoot "demo\web\index.html"
$Main = Join-Path $RepoRoot "demo\web\main.js"
$Doc = Join-Path $RepoRoot "docs\M4_WASM.md"

foreach ($path in @($Index, $Main, $Doc)) {
    if (-not (Test-Path -LiteralPath $path)) {
        throw "demo-web-f12-rehearsal-smoke: missing $path"
    }
}

$needles = @(
    "checkpointLogVerify",
    "checkpointLogCrossCheck",
    "btn-checkpoint-log-verify",
    "btn-checkpoint-log-cross-check"
)
$indexText = Get-Content -Raw -LiteralPath $Index
$mainText = Get-Content -Raw -LiteralPath $Main
foreach ($n in $needles) {
    if ($indexText -notmatch [regex]::Escape($n) -and $mainText -notmatch [regex]::Escape($n)) {
        throw "demo-web-f12-rehearsal-smoke: demo/web missing: $n"
    }
}
if ($mainText -notmatch "checkpointLogVerify") {
    throw "demo-web-f12-rehearsal-smoke: main.js must import checkpointLogVerify"
}
if ($mainText -notmatch "checkpointLogCrossCheck") {
    throw "demo-web-f12-rehearsal-smoke: main.js must import checkpointLogCrossCheck"
}

Write-Host "demo-web-f12-rehearsal-smoke: plan"
Write-Host "  ui=demo/web/index.html#checkpoint-log"
Write-Host "  wasm=checkpointLogVerify checkpointLogCrossCheck"
Write-Host "  docs=docs/M4_WASM.md"

if ($PlanOnly -or -not $PSBoundParameters.ContainsKey("PlanOnly")) {
    Write-Host "demo-web-f12-rehearsal-smoke: PASS plan-only"
    exit 0
}

throw "demo-web-f12-rehearsal-smoke: live mode not implemented"
