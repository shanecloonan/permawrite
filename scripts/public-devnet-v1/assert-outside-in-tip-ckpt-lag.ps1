# B-127 / B-129 / B-134 / B-135 / B-136 / lane 1: outside-in tip vs Path A checkpoint lag (Windows twin).
# B-15-safe: never restarts faucet/mfnd/proxy; never runs JOIN. Does not publish Path A (lane 7).
param(
    [switch]$PlanOnly,
    [switch]$Apply,
    [switch]$NoArchive
)
$ErrorActionPreference = "Stop"
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$RepoRoot = if ($env:MFN_REPO_ROOT) { $env:MFN_REPO_ROOT } else { (Resolve-Path (Join-Path $ScriptDir "../..")).Path }
$LogPath = if ($env:MFN_CHECKPOINT_LOG) { $env:MFN_CHECKPOINT_LOG } else { Join-Path $RepoRoot "mfn-node\testdata\public_devnet_v1.checkpoints.jsonl" }
$ProxyUrl = if ($env:MFN_OUTSIDE_IN_PROXY_URL) { $env:MFN_OUTSIDE_IN_PROXY_URL } else { "http://5.161.201.73:8787/rpc" }
$ExpectedGenesis = if ($env:MFN_EXPECTED_GENESIS_ID) { $env:MFN_EXPECTED_GENESIS_ID } else { "454fa5d4a9bd6f59e35cf9ea7e68c096c9a271a92b2ec5931184e7f34a42a005" }
$LagThreshold = if ($env:MFN_CKPT_LAG_THRESHOLD) { [int]$env:MFN_CKPT_LAG_THRESHOLD } else { 16 }
$EvidenceDir = if ($env:MFN_OUTSIDE_IN_LAG_EVIDENCE_DIR) { $env:MFN_OUTSIDE_IN_LAG_EVIDENCE_DIR } else { Join-Path $ScriptDir "evidence" }
$ProxyHealthUrl = if ($env:MFN_OUTSIDE_IN_PROXY_HEALTH_URL) { $env:MFN_OUTSIDE_IN_PROXY_HEALTH_URL } else { ($ProxyUrl -replace "/rpc$","/health") }
$FaucetHealthUrl = if ($env:MFN_OUTSIDE_IN_FAUCET_HEALTH_URL) { $env:MFN_OUTSIDE_IN_FAUCET_HEALTH_URL } else { "http://5.161.201.73:8788/health" }

if (-not $PlanOnly -and -not $Apply) {
    throw "assert-outside-in-tip-ckpt-lag: specify -PlanOnly or -Apply"
}

if ($PlanOnly) {
    Write-Host "assert-outside-in-tip-ckpt-lag: plan"
    Write-Host "  unit=B-127+B-129+B-134+B-135+B-136"
    Write-Host "  proxy=$ProxyUrl"
    Write-Host "  checkpoint_log=$LogPath"
    Write-Host "  lag_threshold=$LagThreshold"
    Write-Host "  staleness=ckpt_entries,published_at,tip_block_id,age_sec"
    Write-Host "  remote_health=proxy+faucet"
    Write-Host "  fail_reason=health_ok|outage (B-136)"
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
$ckptEntries = 0
$ckptPublishedAt = ""
$ckptTipBlockId = ""
Get-Content -Path $LogPath | ForEach-Object {
    if (-not $_.Trim()) { return }
    $o = $_ | ConvertFrom-Json
    $ckptEntries++
    $h = 0
    if ($o.summary -and $o.summary.tip_height) { $h = [int]$o.summary.tip_height }
    if ($h -ge $ckptMax) {
        $ckptMax = $h
        $ckptPublishedAt = [string]$o.published_at
        if ($o.summary -and $o.summary.tip_block_id) {
            $ckptTipBlockId = [string]$o.summary.tip_block_id
        }
    }
}

$ckptAgeSec = -1
$rawPub = $ckptPublishedAt.TrimEnd("Zz".ToCharArray())
if ($rawPub -match "^[0-9]+$") {
    $epoch = [DateTimeOffset]::UtcNow.ToUnixTimeSeconds()
    $ckptAgeSec = [Math]::Max(0, [int]($epoch - [int64]$rawPub))
}

$lag = $tipH - $ckptMax
$line = "assert-outside-in-tip-ckpt-lag: tip=$tipH ckpt_max=$ckptMax lag=$lag threshold=$LagThreshold tip_id=$tipId"
$staleness = "assert-outside-in-tip-ckpt-lag: STALENESS ckpt_entries=$ckptEntries published_at=$ckptPublishedAt tip_block_id=$ckptTipBlockId age_sec=$ckptAgeSec"
Write-Host $line
Write-Host $staleness

function Get-MfnPublicHealthStatus([string]$Url) {
    try {
        $r = Invoke-WebRequest -Uri $Url -TimeoutSec 15 -UseBasicParsing
        $body = [string]$r.Content
        if ($body -match '"ok"\s*:\s*true') { return "ok" }
        return "bad_body"
    } catch {
        return "unreachable"
    }
}
$proxyHealthStatus = Get-MfnPublicHealthStatus $ProxyHealthUrl
$faucetHealthStatus = Get-MfnPublicHealthStatus $FaucetHealthUrl
$health = "assert-outside-in-tip-ckpt-lag: HEALTH proxy=$proxyHealthStatus faucet=$faucetHealthStatus proxy_url=$ProxyHealthUrl faucet_url=$FaucetHealthUrl"
Write-Host $health

$status = "OK"
$reason = "ok"
$recommendedAction = "none"
if ($lag -ge $LagThreshold) {
    $status = "FAIL"
    if ($proxyHealthStatus -eq "ok" -and $faucetHealthStatus -eq "ok") {
        $reason = "tip_lag>=threshold;health_ok"
        $recommendedAction = "path_a_republish"
    } else {
        $reason = "tip_lag>=threshold;health_degraded"
        $recommendedAction = "diagnose_public_health"
    }
}

if (-not $NoArchive) {
    New-Item -ItemType Directory -Force -Path $EvidenceDir | Out-Null
    try { $headSha = (git -C $RepoRoot rev-parse HEAD 2>$null) } catch { $headSha = "unknown" }
    if (-not $headSha) { $headSha = "unknown" }
    $stamp = (Get-Date).ToUniversalTime().ToString("yyyyMMddTHHmmssZ")
    $out = Join-Path $EvidenceDir "outside-in-tip-ckpt-lag-$stamp.txt"
    $failLine = if ($status -eq "FAIL") {
        if ($recommendedAction -eq "path_a_republish") {
            "assert-outside-in-tip-ckpt-lag: FAIL tip lag >= threshold health_ok (lane7: publish-near-tip-checkpoint-if-lag --apply then land jsonl)"
        } else {
            "assert-outside-in-tip-ckpt-lag: FAIL tip lag >= threshold health_degraded (diagnose proxy/faucet; lane7 Path A after recovery)"
        }
    } else {
        "assert-outside-in-tip-ckpt-lag: OK tip=$tipH ckpt_max=$ckptMax lag=$lag"
    }
    @(
        "# B-127 outside-in tip-ckpt lag probe (public observer proxy)",
        "# B-129 auto-archive",
        "# B-134 Path A staleness",
        "# B-135 age_sec + remote public health",
        "# B-136 health_ok FAIL reason",
        "# head_sha=$headSha",
        "# proxy=$ProxyUrl",
        "# checkpoint_log=$LogPath",
        "# lag_threshold=$LagThreshold",
        "# never=faucet-http mfnd restart join-testnet-rehearsal path-a-publish",
        $line,
        $staleness,
        $health,
        $failLine,
        "assert-outside-in-tip-ckpt-lag: SUMMARY status=$status tip=$tipH ckpt_max=$ckptMax lag=$lag ckpt_entries=$ckptEntries published_at=$ckptPublishedAt age_sec=$ckptAgeSec proxy_health=$proxyHealthStatus faucet_health=$faucetHealthStatus reason=$reason recommended_action=$recommendedAction"
    ) | Set-Content -Path $out -Encoding utf8
    Write-Host "assert-outside-in-tip-ckpt-lag: EVIDENCE archived=$out status=$status"
}

if ($status -eq "FAIL") {
    if ($recommendedAction -eq "path_a_republish") {
        throw "assert-outside-in-tip-ckpt-lag: FAIL tip lag >= threshold health_ok (lane7: publish-near-tip-checkpoint-if-lag --apply then land jsonl)"
    } else {
        throw "assert-outside-in-tip-ckpt-lag: FAIL tip lag >= threshold health_degraded (diagnose proxy/faucet; lane7 Path A after recovery)"
    }
}
Write-Host "assert-outside-in-tip-ckpt-lag: OK tip=$tipH ckpt_max=$ckptMax lag=$lag"
