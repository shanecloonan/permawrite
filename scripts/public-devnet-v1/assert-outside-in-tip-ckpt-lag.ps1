# B-127 / lane 1: outside-in tip vs Path A checkpoint lag (Windows twin).
# B-15-safe: never restarts faucet/mfnd/proxy; never runs JOIN. Does not publish Path A (lane 7).
param(
    [switch]$PlanOnly,
    [switch]$Apply
)
$ErrorActionPreference = "Stop"
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$RepoRoot = if ($env:MFN_REPO_ROOT) { $env:MFN_REPO_ROOT } else { (Resolve-Path (Join-Path $ScriptDir "../..")).Path }
$LogPath = if ($env:MFN_CHECKPOINT_LOG) { $env:MFN_CHECKPOINT_LOG } else { Join-Path $RepoRoot "mfn-node\testdata\public_devnet_v1.checkpoints.jsonl" }
$ProxyUrl = if ($env:MFN_OUTSIDE_IN_PROXY_URL) { $env:MFN_OUTSIDE_IN_PROXY_URL } else { "http://5.161.201.73:8787/rpc" }
$ExpectedGenesis = if ($env:MFN_EXPECTED_GENESIS_ID) { $env:MFN_EXPECTED_GENESIS_ID } else { "454fa5d4a9bd6f59e35cf9ea7e68c096c9a271a92b2ec5931184e7f34a42a005" }
$LagThreshold = if ($env:MFN_CKPT_LAG_THRESHOLD) { [int]$env:MFN_CKPT_LAG_THRESHOLD } else { 16 }

if (-not $PlanOnly -and -not $Apply) {
    throw "assert-outside-in-tip-ckpt-lag: specify -PlanOnly or -Apply"
}

if ($PlanOnly) {
    Write-Host "assert-outside-in-tip-ckpt-lag: plan"
    Write-Host "  unit=B-127"
    Write-Host "  proxy=$ProxyUrl"
    Write-Host "  checkpoint_log=$LogPath"
    Write-Host "  lag_threshold=$LagThreshold"
    Write-Host "  never=faucet-http mfnd restart join-testnet-rehearsal path-a-publish"
    Write-Host "assert-outside-in-tip-ckpt-lag: PASS plan-only"
    exit 0
}

if (-not (Test-Path $LogPath)) {
    throw "assert-outside-in-tip-ckpt-lag: missing checkpoint log $LogPath"
}

$body = '{"jsonrpc":"2.0","id":1,"method":"get_tip","params":[]}'
$resp = Invoke-RestMethod -Uri $ProxyUrl -Method POST -Body $body -ContentType "application/json" -TimeoutSec 30
$tipH = [int]$resp.result.tip_height
$tipId = [string]$resp.result.tip_id
$genesis = [string]$resp.result.genesis_id
if ($genesis -ne $ExpectedGenesis) {
    throw "assert-outside-in-tip-ckpt-lag: FAIL genesis_id mismatch got=$genesis"
}

$ckptMax = 0
Get-Content -Path $LogPath | ForEach-Object {
    if (-not $_.Trim()) { return }
    $o = $_ | ConvertFrom-Json
    $h = 0
    if ($o.summary -and $o.summary.tip_height) { $h = [int]$o.summary.tip_height }
    if ($h -gt $ckptMax) { $ckptMax = $h }
}

$lag = $tipH - $ckptMax
Write-Host "assert-outside-in-tip-ckpt-lag: tip=$tipH ckpt_max=$ckptMax lag=$lag threshold=$LagThreshold tip_id=$tipId"
if ($lag -ge $LagThreshold) {
    throw "assert-outside-in-tip-ckpt-lag: FAIL tip lag >= threshold (lane7: publish-near-tip-checkpoint-if-lag --apply then land jsonl)"
}
Write-Host "assert-outside-in-tip-ckpt-lag: OK tip=$tipH ckpt_max=$ckptMax lag=$lag"
