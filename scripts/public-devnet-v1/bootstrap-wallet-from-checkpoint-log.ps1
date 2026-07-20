# B-50 / B-52 (F56): Windows twin of bootstrap-wallet-from-checkpoint-log.sh
# Honesty: wallet light-scan --checkpoint-log only cross-checks after sync.
param(
  [switch]$PlanOnly,
  [switch]$Apply,
  [string]$Wallet = "",
  [string]$Rpc = $(if ($env:MFN_BOOTSTRAP_RPC) { $env:MFN_BOOTSTRAP_RPC } else { "127.0.0.1:18731" }),
  [string]$Log = "",
  [string]$Mcli = ""
)

$ErrorActionPreference = "Stop"
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$RepoRoot = if ($env:MFN_REPO_ROOT) { $env:MFN_REPO_ROOT } else { (Resolve-Path (Join-Path $ScriptDir "../..")).Path }
if (-not $Log) {
  $Log = Join-Path $RepoRoot "mfn-node/testdata/public_devnet_v1.checkpoints.jsonl"
}
if (-not $Mcli) {
  $Mcli = if ($env:MCLI) { $env:MCLI } else { Join-Path $RepoRoot "target/release/mfn-cli.exe" }
  if (-not (Test-Path $Mcli)) {
    $Mcli = Join-Path $RepoRoot "target/release/mfn-cli"
  }
}

if (-not $PlanOnly -and -not $Apply) {
  Write-Error "bootstrap-wallet-from-checkpoint-log.ps1: specify -PlanOnly or -Apply"
}
if ($PlanOnly) {
  Write-Output "bootstrap-wallet-from-checkpoint-log: plan"
  Write-Output "  unit=B-50/B-52"
  Write-Output "  flow=log max tip -> get_light_snapshot(height) -> patch wallet -> light-scan --checkpoint-log"
  Write-Output "  honesty=checkpoint-log alone does not bootstrap; see JOIN_TESTNET.md"
  Write-Output "  twin=Windows PowerShell (F56)"
  Write-Output "bootstrap-wallet-from-checkpoint-log: PASS plan-only"
  exit 0
}

if (-not $Wallet) { Write-Error "--Wallet required" }
if (-not (Test-Path $Mcli)) { Write-Error "mfn-cli missing: $Mcli" }
if (-not (Test-Path $Log)) { Write-Error "log missing: $Log" }
if (-not (Test-Path $Wallet)) { Write-Error "wallet missing: $Wallet" }

$py = "import json; from pathlib import Path; tips=[]; p=Path(r'" + ($Log -replace "'","''") + "');" +
  "[tips.append(int(json.loads(line)['summary']['tip_height'])) for line in p.read_text(encoding='utf-8').splitlines() if line.strip()]; print(max(tips))"
$maxTip = [int]((python -c $py).Trim())
Write-Output "bootstrap-wallet-from-checkpoint-log: log_max_tip=$maxTip rpc=$Rpc"

$tmp = Join-Path ([System.IO.Path]::GetTempPath()) ("mfn-ckpt-boot-" + [guid]::NewGuid().ToString("n"))
New-Item -ItemType Directory -Path $tmp | Out-Null
try {
  $snapOut = Join-Path $tmp "snap.json"
  $snapErr = Join-Path $tmp "snap.err"
  $ok = $false
  for ($i = 1; $i -le 8; $i++) {
    $paramsJson = "{`"height`":$maxTip}"
    $p = Start-Process -FilePath $Mcli -ArgumentList @(
      "--rpc", $Rpc, "call", "get_light_snapshot", "--params", $paramsJson
    ) -NoNewWindow -Wait -PassThru -RedirectStandardOutput $snapOut -RedirectStandardError $snapErr
    if ($p.ExitCode -eq 0) {
      $ok = $true
      Write-Output "bootstrap-wallet-from-checkpoint-log: snapshot_ok attempt=$i"
      break
    }
    $errBit = ""
    if (Test-Path $snapErr) {
      $rawErr = (Get-Content -Raw $snapErr) -replace "`r?`n", " "
      if ($rawErr.Length -gt 160) { $errBit = $rawErr.Substring(0, 160) } else { $errBit = $rawErr }
    }
    Write-Output "bootstrap-wallet-from-checkpoint-log: snapshot_retry=$i $errBit"
    Start-Sleep -Seconds ($i + 1)
  }
  if (-not $ok) {
    Write-Error "get_light_snapshot failed (hub EAGAIN under load?). Retry when tip is quiet."
  }

  $wEsc = $Wallet -replace "'","''"
  $sEsc = $snapOut -replace "'","''"
  $pin = "import json; from pathlib import Path; wallet_path=Path(r'" + $wEsc + "'); snap_path=Path(r'" + $sEsc + "'); expect=" + $maxTip + "; snap=json.loads(snap_path.read_text(encoding='utf-8')); r=snap.get('result', snap); assert isinstance(r, dict) and 'checkpoint_hex' in r; tip=int(r['tip_height']); assert tip==expect; w=json.loads(wallet_path.read_text(encoding='utf-8')); w['scan_height']=tip; w['light_checkpoint_hex']=r['checkpoint_hex'];
if r.get('summary'): w['trusted_light_summary']=r['summary']; wallet_path.write_text(json.dumps(w, indent=2)+chr(10), encoding='utf-8'); print('bootstrap-wallet-from-checkpoint-log: pinned scan_height='+str(tip))"
  python -c $pin

  & $Mcli --rpc $Rpc --wallet $Wallet wallet light-scan --checkpoint-log $Log
  if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
  & $Mcli --rpc $Rpc --wallet $Wallet wallet status --json
  if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
  Write-Output "bootstrap-wallet-from-checkpoint-log: OK"
} finally {
  Remove-Item -Recurse -Force $tmp -ErrorAction SilentlyContinue
}