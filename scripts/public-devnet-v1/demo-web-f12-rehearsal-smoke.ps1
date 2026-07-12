# Lane 5 / F12 phase 5: demo web checkpoint-log WASM wiring + live crypto smoke (Windows).
param(
    [switch]$PlanOnly,
    [switch]$Live
)
$ErrorActionPreference = "Stop"

$RepoRoot = (Resolve-Path (Join-Path (Split-Path -Parent $MyInvocation.MyCommand.Path) "..\..")).Path
$Index = Join-Path $RepoRoot "demo\web\index.html"
$Main = Join-Path $RepoRoot "demo\web\main.js"
$Doc = Join-Path $RepoRoot "docs\M4_WASM.md"

$RehearsalSeedHex = if ($env:MFN_CHECKPOINT_LOG_REHEARSAL_SIGNER_SEED_HEX) {
    $env:MFN_CHECKPOINT_LOG_REHEARSAL_SIGNER_SEED_HEX
} else {
    "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"
}
$RehearsalSignerId = if ($env:MFN_CHECKPOINT_LOG_REHEARSAL_SIGNER_ID) {
    $env:MFN_CHECKPOINT_LOG_REHEARSAL_SIGNER_ID
} else {
    "permawrite-rehearsal-maintainer"
}

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
$docText = Get-Content -Raw -LiteralPath $Doc
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
if ($docText -notmatch "checkpointLogVerify") {
    throw "demo-web-f12-rehearsal-smoke: M4_WASM.md missing checkpointLogVerify"
}

Write-Host "demo-web-f12-rehearsal-smoke: plan"
Write-Host "  ui=demo/web/index.html#checkpoint-log"
Write-Host "  wasm=checkpointLogVerify checkpointLogCrossCheck"
Write-Host "  docs=docs/M4_WASM.md"
Write-Host "  live=sign fixture -> mfn-cli verify/cross-check -> cargo test mfn-wasm checkpoint_log"

if ($PlanOnly -or -not $Live) {
    Write-Host "demo-web-f12-rehearsal-smoke: PASS plan-only"
    exit 0
}

$Mcli = Join-Path $RepoRoot "target\release\mfn-cli.exe"
if (-not (Test-Path -LiteralPath $Mcli)) {
    throw "demo-web-f12-rehearsal-smoke: build mfn-cli release first (cargo build -p mfn-cli --release)"
}

$Tmp = Join-Path $env:TEMP ("mfn-demo-f12-" + [Guid]::NewGuid().ToString("N"))
New-Item -ItemType Directory -Path $Tmp | Out-Null
try {
    $Summary = Join-Path $Tmp "trusted-summary.json"
    $Log = Join-Path $Tmp "checkpoints.jsonl"
    $summaryObj = [ordered]@{
        genesis_id         = ("aa" * 32)
        tip_height         = 42
        tip_block_id       = ("bb" * 32)
        validator_count    = 3
        validator_set_root = ("cc" * 32)
        checkpoint_digest  = ("dd" * 32)
    }
    [System.IO.File]::WriteAllText($Summary, (($summaryObj | ConvertTo-Json -Depth 4) + "`n"))

    Push-Location $RepoRoot
    & $Mcli checkpoint-log sign --summary $Summary --signer-id $RehearsalSignerId `
        --signer-seed-hex $RehearsalSeedHex --append $Log | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "checkpoint-log sign failed" }
    & $Mcli checkpoint-log verify $Log
    if ($LASTEXITCODE -ne 0) { throw "checkpoint-log verify failed" }
    $cross = & $Mcli checkpoint-log cross-check --summary $Summary --log $Log
    $crossText = ($cross | Out-String)
    Write-Host $crossText
    if ($crossText -notmatch "checkpoint_log=matched") {
        throw "demo-web-f12-rehearsal-smoke: expected checkpoint_log=matched"
    }
    cargo test -p mfn-wasm --release --features wasm-full checkpoint_log_core -- --nocapture
    if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
    Write-Host "demo-web-f12-rehearsal-smoke: PASS live signer_id=$RehearsalSignerId"
} finally {
    Pop-Location -ErrorAction SilentlyContinue
    Remove-Item -Recurse -Force $Tmp -ErrorAction SilentlyContinue
}
