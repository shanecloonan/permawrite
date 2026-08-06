# B-42 / B-248 Windows twin — plan gate + B-15-safe invite-load preflight (no JOIN unless armed).
param(
    [switch]$PlanOnly,
    [switch]$Apply,
    [switch]$Live
)
$ErrorActionPreference = "Stop"
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$bashScript = Join-Path $ScriptDir "invite-load-smoke-rehearsal.sh"

if (-not (Test-Path -LiteralPath $bashScript)) {
    throw "invite-load-smoke-rehearsal: missing $bashScript"
}

if (-not $PlanOnly -and -not $Apply -and -not $Live) {
    throw "invite-load-smoke-rehearsal: specify -PlanOnly, -Apply, or -Live"
}

# Prefer bash when available (Git Bash / WSL); else native preflight for -Apply.
$bash = Get-Command bash -ErrorAction SilentlyContinue
if ($bash) {
    $args = @()
    if ($PlanOnly) { $args += "--plan-only" }
    elseif ($Live) { $args += "--live" }
    else { $args += "--apply" }
    & bash $bashScript @args
    if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
    exit 0
}

if ($PlanOnly) {
    $text = Get-Content -LiteralPath $bashScript -Raw
    foreach ($n in @("invite-load-smoke-rehearsal", "B-42", "B-248", "serialize-with-reason", "MFN_INVITE_LOAD_ALLOW_LIVE", "never=faucet-http")) {
        if ($text -notlike "*$n*") { throw "invite-load-smoke-rehearsal: missing needle $n" }
    }
    Write-Host "invite-load-smoke-rehearsal: plan"
    Write-Host "  unit=B-42"
    Write-Host "invite-load-smoke-rehearsal: PASS plan-only"
    exit 0
}

# Native -Apply preflight (public endpoints)
$ProxyHealth = if ($env:MFN_PROXY_HEALTH) { $env:MFN_PROXY_HEALTH } else { "http://5.161.201.73:8787/health" }
$FaucetHealth = if ($env:MFN_FAUCET_HEALTH) { $env:MFN_FAUCET_HEALTH } else { "http://5.161.201.73:8788/health" }
$PublicHost = if ($env:MFN_INVITE_PUBLIC_HOST) { $env:MFN_INVITE_PUBLIC_HOST } else { "5.161.201.73" }

Write-Host "invite-load-smoke-rehearsal: apply preflight"
Write-Host "  unit=B-42/B-248"
$proxy = Invoke-RestMethod -Uri $ProxyHealth -TimeoutSec 10
if ($proxy.ok -ne $true) { throw "invite-load-smoke-rehearsal: FAIL proxy ok!=true" }
Write-Host "invite-load-smoke-rehearsal: proxy ok tip=$($proxy.index.tip_height)"
$faucet = Invoke-RestMethod -Uri $FaucetHealth -TimeoutSec 10
if ($faucet.ok -ne $true) { throw "invite-load-smoke-rehearsal: FAIL faucet ok!=true" }
Write-Host "invite-load-smoke-rehearsal: faucet ok busy=$($faucet.busy) pending_jobs=$($faucet.pending_jobs)"
foreach ($port in 19001, 19002, 19003) {
    $r = Test-NetConnection -ComputerName $PublicHost -Port $port -WarningAction SilentlyContinue
    if (-not $r.TcpTestSucceeded) { throw "invite-load-smoke-rehearsal: FAIL seed port $port" }
}
Write-Host "invite-load-smoke-rehearsal: seeds ok host=$PublicHost ports=19001,19002,19003"

if ($Live -and $env:MFN_INVITE_LOAD_ALLOW_LIVE -eq "1") {
    if ($faucet.busy -eq $true) { throw "invite-load-smoke-rehearsal: FAIL refuse -Live while faucet busy" }
    Write-Host "invite-load-smoke-rehearsal: PASS live-armed-preflight (JOIN operator-driven)"
    exit 0
}

$reason = "MFN_INVITE_LOAD_ALLOW_LIVE_unset"
if ($Live -and $env:MFN_INVITE_LOAD_ALLOW_LIVE -ne "1") { $reason = "MFN_INVITE_LOAD_ALLOW_LIVE_unset" }
elseif (-not $Live) { $reason = "need_-Live_flag" }
if ($faucet.busy -eq $true) { $reason = "faucet_busy" }

$EvidenceDir = if ($env:MFN_INVITE_LOAD_EVIDENCE_DIR) { $env:MFN_INVITE_LOAD_EVIDENCE_DIR } else { Join-Path $ScriptDir "evidence" }
New-Item -ItemType Directory -Force -Path $EvidenceDir | Out-Null
$stamp = (Get-Date).ToUniversalTime().ToString("yyyyMMddTHHmmssZ")
$ev = Join-Path $EvidenceDir "invite-load-preflight-$stamp.txt"
@(
    "invite-load-smoke-rehearsal: preflight"
    "unit=B-248"
    "status=PASS"
    "serialize_with_reason=$reason"
    "proxy_health=$ProxyHealth"
    "faucet_health=$FaucetHealth"
    "faucet_busy=$($faucet.busy)"
    "faucet_pending=$($faucet.pending_jobs)"
    "public_host=$PublicHost"
    "seed_ports=19001,19002,19003"
    "live_armed=$($env:MFN_INVITE_LOAD_ALLOW_LIVE)"
    "never=join-testnet-rehearsal_without_ALLOW_LIVE"
) | Set-Content -LiteralPath $ev -Encoding utf8
Write-Host "invite-load-smoke-rehearsal: PASS preflight serialize-with-reason=$reason evidence=$ev"
exit 0
