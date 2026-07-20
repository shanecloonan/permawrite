param(
    [switch]$PlanOnly,
    [switch]$Help
)
$ErrorActionPreference = "Stop"
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
if ($Help) {
    Write-Host "usage: vps-install-near-tip-ckpt-timer-rehearsal-smoke.ps1 [-PlanOnly]"
    exit 0
}
$install = Join-Path $ScriptDir "vps-install-near-tip-ckpt-timer.sh"
$svc = Join-Path $ScriptDir "systemd\path-a-near-tip-ckpt.service"
$tmr = Join-Path $ScriptDir "systemd\path-a-near-tip-ckpt.timer"
foreach ($p in @($install, $svc, $tmr)) {
    if (-not (Test-Path -LiteralPath $p)) { throw "vps-install-near-tip-ckpt-timer-rehearsal-smoke: missing $p" }
}
$needles = @("vps-install-near-tip-ckpt-timer", "B-88", "path-a-near-tip-ckpt.timer", "never=faucet-http", "publish-near-tip-checkpoint-if-lag")
$text = Get-Content -LiteralPath $install -Raw
foreach ($n in $needles) {
    if ($text -notlike "*$n*") { throw "vps-install-near-tip-ckpt-timer-rehearsal-smoke: missing needle $n" }
}
$svcText = Get-Content -LiteralPath $svc -Raw
if ($svcText -notlike "*publish-near-tip-checkpoint-if-lag.sh --apply*") { throw "missing ExecStart apply" }
$tmrText = Get-Content -LiteralPath $tmr -Raw
if ($tmrText -notlike "*OnUnitActiveSec=30min*") { throw "missing timer interval" }
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
    $prePath = $env:Path
    try {
        $env:Path = "$bashDir;C:\msys64\usr\bin;$prePath"
        $plan = (& $bashPath $install --plan-only 2>&1) -join "`n"
    } finally {
        $env:Path = $prePath
    }
    if ($plan -notmatch "vps-install-near-tip-ckpt-timer: PASS plan-only") {
        $plan | ForEach-Object { [Console]::Error.WriteLine($_) }
        exit 1
    }
} elseif ($text -notlike "*vps-install-near-tip-ckpt-timer: PASS plan-only*") {
    throw "vps-install-near-tip-ckpt-timer-rehearsal-smoke: no bash and missing PASS marker"
}
Write-Host "vps-install-near-tip-ckpt-timer-rehearsal-smoke: PASS plan-only"
exit 0