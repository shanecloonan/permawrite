# Fund alice via public faucet, then ping-pong dual-payment transfers on the live chain.
# B-296: AmountEach=50000 deadlocks after the first hop (dest has 2x50k=100k < 110k need).
# Default 10000 keeps both sides above the F7 two-UTXO + fee floor.
# Uses a local TCP JSON-RPC tunnel to VPS hub/observer (default 127.0.0.1:18731 hub).
# Prefer hub for submit_tx under load; observer proxy is for public visibility checks.
# Never restarts faucet/mfnd.
#
# Tall-tip note (B-277): get_light_snapshot(height) for historical heights can stall
# mfnd for minutes; tip-height snapshot is cheap. Bootstrap prefers tip pin when the
# Path A log max is behind tip (F45 soft), instead of hanging on log_max_tip.
param(
  [string]$Rpc = "127.0.0.1:18731",
  [string]$FaucetUrl = "http://5.161.201.73:8788",
  [string]$WalletDir = "",
  [int]$Count = 12,
  [int]$AmountEach = 10000,
  [int]$Fee = 10000,
  [switch]$SkipBuild
)

$ErrorActionPreference = "Stop"
$Repo = (Resolve-Path (Join-Path $PSScriptRoot "..\..")).Path
if (-not $WalletDir) {
  $WalletDir = Join-Path $Repo "live-testnet-data\onchain-storm"
}
New-Item -ItemType Directory -Force -Path $WalletDir | Out-Null
$Alice = Join-Path $WalletDir "alice.json"
$Bob = Join-Path $WalletDir "bob.json"
$Cli = Join-Path $Repo "target\release\mfn-cli.exe"
$Storm = Join-Path $Repo "target\release\onchain-tx-storm.exe"

if (-not $SkipBuild) {
  Write-Host "onchain-tx-storm.ps1: building release bins..."
  Push-Location $Repo
  try {
    cargo build -p mfn-cli --release --bin mfn-cli --bin onchain-tx-storm
  } finally {
    Pop-Location
  }
}
if (-not (Test-Path $Cli)) { throw "missing $Cli" }
if (-not (Test-Path $Storm)) { throw "missing $Storm - build with: cargo build -p mfn-cli --release --bin onchain-tx-storm" }

if (-not (Test-Path $Alice)) {
  & $Cli --wallet $Alice wallet new
}
if (-not (Test-Path $Bob)) {
  & $Cli --wallet $Bob wallet new
}

$addrOut = & $Cli --wallet $Alice wallet address 2>&1 | Out-String
$address = ($addrOut -split "`n" | Where-Object { $_ -match '^address=' } | Select-Object -First 1) -replace '^address=', ''
$address = $address.Trim()
if (-not $address.StartsWith("mf")) {
  throw "could not read alice address: $addrOut"
}
Write-Host "onchain-tx-storm.ps1: alice=$address"

# F67: pin from newest Path A checkpoint log BEFORE faucet so tall-tip scan finds UTXOs.
$CkptCandidates = @(
  (Join-Path $Repo "mfn-node\testdata\public_devnet_v1.checkpoints.jsonl"),
  (Join-Path $Repo "live-testnet-data\b165-prove\public_devnet_v1.checkpoints.jsonl")
) | Where-Object { Test-Path $_ }
$Ckpt = $null
$CkptTip = -1
foreach ($c in $CkptCandidates) {
  $last = Get-Content $c | Select-Object -Last 1
  if ($last -match '"tip_height"\s*:\s*(\d+)') {
    $t = [int]$Matches[1]
    if ($t -gt $CkptTip) { $CkptTip = $t; $Ckpt = $c }
  }
}
if (-not $Ckpt) {
  throw "no Path A checkpoint log found under mfn-node/testdata or live-testnet-data"
}
# B-277: prefer tip-pin via soft twin (avoids historical get_light_snapshot stalls).
Write-Host "onchain-tx-storm.ps1: F67 tip/soft pin alice+bob from $Ckpt (log_max=$CkptTip)"
$env:MFN_HEAVY_RPC_TIMEOUT_MS = if ($env:MFN_HEAVY_RPC_TIMEOUT_MS) { $env:MFN_HEAVY_RPC_TIMEOUT_MS } else { "300000" }
$soft = Join-Path $PSScriptRoot "light-scan-checkpoint-soft.ps1"
& powershell -File $soft -Apply -Wallet $Alice -Rpc $Rpc -Log $Ckpt -Mcli $Cli
& powershell -File $soft -Apply -Wallet $Bob -Rpc $Rpc -Log $Ckpt -Mcli $Cli

$health = Invoke-RestMethod -Uri "$FaucetUrl/health" -TimeoutSec 15
Write-Host "onchain-tx-storm.ps1: faucet busy=$($health.busy) pending=$($health.pending_jobs)"
if ($health.busy) {
  throw "faucet busy - refuse to queue during B-15; retry when idle"
}

$claim = Invoke-RestMethod -Uri "$FaucetUrl/faucet" -Method Post -ContentType "application/json" -Body (@{ address = $address } | ConvertTo-Json) -TimeoutSec 30
Write-Host "onchain-tx-storm.ps1: faucet job_id=$($claim.job_id)"
$deadline = (Get-Date).AddMinutes(15)
do {
  Start-Sleep -Seconds 3
  $job = Invoke-RestMethod -Uri "$FaucetUrl/faucet/job?id=$($claim.job_id)" -TimeoutSec 30
  Write-Host "onchain-tx-storm.ps1: job status=$($job.status)"
  if ($job.status -eq "error") { throw "faucet job error: $($job | ConvertTo-Json -Compress)" }
  if ((Get-Date) -gt $deadline) { throw "faucet job timeout" }
} while ($job.status -ne "done")

Write-Host "onchain-tx-storm.ps1: waiting for alice owned_count>=2 via light-scan"
$waitDeadline = (Get-Date).AddMinutes(8)
do {
  & $Cli --rpc $Rpc --wallet $Alice wallet light-scan | Out-Null
  $st = & $Cli --rpc $Rpc --wallet $Alice wallet status 2>&1 | Out-String
  Write-Host $st.Trim()
  $owned = 0
  if ($st -match 'owned_count_cached=(\d+)') { $owned = [int]$Matches[1] }
  elseif ($st -match 'owned_count=(\d+)') { $owned = [int]$Matches[1] }
  if ($owned -ge 2) { break }
  if ((Get-Date) -gt $waitDeadline) { throw "alice not funded in time" }
  Start-Sleep -Seconds 10
} while ($true)

& $Cli --rpc $Rpc --wallet $Bob wallet light-scan | Out-Null

Write-Host "onchain-tx-storm.ps1: starting dual-payment storm count=$Count"
& $Storm --rpc $Rpc --alice $Alice --bob $Bob --count $Count --amount $AmountEach --fee $Fee
Write-Host "onchain-tx-storm.ps1: DONE"
