# B-50 / B-52 / B-54 / B-57 / B-58 / B-59 (F45 soft): Windows twin of bootstrap-wallet-from-checkpoint-log.sh
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
  if (-not (Test-Path $Mcli)) { $Mcli = Join-Path $RepoRoot "target/release/mfn-cli" }
}

if (-not $PlanOnly -and -not $Apply) {
  Write-Error "bootstrap-wallet-from-checkpoint-log.ps1: specify -PlanOnly or -Apply"
}
if ($PlanOnly) {
  Write-Output "bootstrap-wallet-from-checkpoint-log: plan"
  Write-Output "  unit=B-50/B-52/B-54/B-57/B-58/B-59"
  Write-Output "  f67=pin BEFORE faucet fund"
  Write-Output "  f68=snapshot via temp .py TCP JSON-RPC"
  Write-Output "  f45=soft-pass when tip races past latest Schnorr attestation"
  Write-Output "  flow=log max tip -> get_light_snapshot(height) -> patch wallet -> light-scan soft"
  Write-Output "  honesty=checkpoint-log alone does not bootstrap; see JOIN_TESTNET.md"
  Write-Output "bootstrap-wallet-from-checkpoint-log: PASS plan-only"
  exit 0
}

if (-not $Wallet) { Write-Error "-Wallet required" }
if (-not (Test-Path $Mcli)) { Write-Error "mfn-cli missing: $Mcli" }
if (-not (Test-Path $Log)) { Write-Error "log missing: $Log" }
if (-not (Test-Path $Wallet)) { Write-Error "wallet missing: $Wallet" }

$utf8enc = New-Object System.Text.UTF8Encoding $false
$tmp = Join-Path ([System.IO.Path]::GetTempPath()) ("mfn-ckpt-boot-" + [guid]::NewGuid().ToString("n"))
New-Item -ItemType Directory -Path $tmp | Out-Null
try {
  $maxPy = Join-Path $tmp "max_tip.py"
  [System.IO.File]::WriteAllText($maxPy, (@(
    "import json"
    "from pathlib import Path"
    "import sys"
    "p = Path(sys.argv[1])"
    "tips = [int(json.loads(l)['summary']['tip_height']) for l in p.read_text(encoding='utf-8').splitlines() if l.strip()]"
    "print(max(tips))"
  ) -join "`n") + "`n", $utf8enc)
  $maxTip = [int]((& python $maxPy $Log).Trim())
  Write-Output "bootstrap-wallet-from-checkpoint-log: log_max_tip=$maxTip rpc=$Rpc"

  $snapPy = Join-Path $tmp "get_light_snapshot.py"
  [System.IO.File]::WriteAllText($snapPy, (@(
    "import json, socket, sys"
    "from pathlib import Path"
    "host, port, height, out = sys.argv[1], int(sys.argv[2]), int(sys.argv[3]), sys.argv[4]"
    "req = json.dumps({'jsonrpc':'2.0','id':1,'method':'get_light_snapshot','params':{'height':height}}) + chr(10)"
    "s = socket.create_connection((host, port), timeout=180)"
    "s.sendall(req.encode())"
    "buf = b''"
    "while b'\n' not in buf:"
    "    chunk = s.recv(65536)"
    "    if not chunk: break"
    "    buf += chunk"
    "s.close()"
    "obj = json.loads(buf.decode('utf-8', errors='replace').strip())"
    "if obj.get('error'): raise SystemExit(str(obj['error'])[:300])"
    "Path(out).write_text(json.dumps(obj, indent=2) + chr(10), encoding='utf-8')"
    "print('snapshot_ok')"
  ) -join "`n") + "`n", $utf8enc)

  $pinPy = Join-Path $tmp "pin_wallet.py"
  [System.IO.File]::WriteAllText($pinPy, (@(
    "import json, sys"
    "from pathlib import Path"
    "wallet_path, snap_path, expect = Path(sys.argv[1]), Path(sys.argv[2]), int(sys.argv[3])"
    "snap = json.loads(snap_path.read_text(encoding='utf-8'))"
    "r = snap.get('result', snap)"
    "assert isinstance(r, dict) and 'checkpoint_hex' in r"
    "tip = int(r['tip_height'])"
    "assert tip == expect, 'snapshot tip %s != log max %s' % (tip, expect)"
    "w = json.loads(wallet_path.read_text(encoding='utf-8'))"
    "w['scan_height'] = tip"
    "w['light_checkpoint_hex'] = r['checkpoint_hex']"
    "if r.get('summary'): w['trusted_light_summary'] = r['summary']"
    "wallet_path.write_text(json.dumps(w, indent=2) + chr(10), encoding='utf-8')"
    "print('bootstrap-wallet-from-checkpoint-log: pinned scan_height=' + str(tip))"
  ) -join "`n") + "`n", $utf8enc)

  $snapOut = Join-Path $tmp "snap.json"
  $ok = $false
  $rpcHost, $rpcPort = $Rpc.Split(":")[0], [int]$Rpc.Split(":")[1]
  for ($i = 1; $i -le 8; $i++) {
    $err = ""
    try {
      $out = & python $snapPy $rpcHost $rpcPort $maxTip $snapOut 2>&1
      if ($LASTEXITCODE -eq 0 -and (Test-Path $snapOut)) {
        $ok = $true
        Write-Output "bootstrap-wallet-from-checkpoint-log: snapshot_ok attempt=$i"
        break
      }
      $err = ($out | Out-String) -replace "`r?`n", " "
    } catch { $err = $_.Exception.Message }
    if ($err.Length -gt 160) { $err = $err.Substring(0, 160) }
    Write-Output "bootstrap-wallet-from-checkpoint-log: snapshot_retry=$i $err"
    Start-Sleep -Seconds ($i + 1)
  }
  if (-not $ok) { Write-Error "get_light_snapshot failed (hub EAGAIN under load?). Retry when tip is quiet." }

  & python $pinPy $Wallet $snapOut $maxTip
  if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

  & $Mcli checkpoint-log verify $Log
  if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

  & $Mcli --rpc $Rpc --wallet $Wallet wallet light-scan
  if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

  $scanErr = Join-Path $tmp "scan.err"
  $p = Start-Process -FilePath $Mcli -ArgumentList @("--rpc", $Rpc, "--wallet", $Wallet, "wallet", "light-scan", "--checkpoint-log", $Log) -NoNewWindow -Wait -PassThru -RedirectStandardOutput $scanErr -RedirectStandardError (Join-Path $tmp "scan2.err")
  $msg = ""
  if (Test-Path $scanErr) { $msg += Get-Content -Raw $scanErr }
  $e2 = Join-Path $tmp "scan2.err"
  if (Test-Path $e2) { $msg += Get-Content -Raw $e2 }
  if ($p.ExitCode -eq 0) {
    Write-Output "light-scan-checkpoint-soft: PASS exact-tip"
  } elseif ($msg -match "has no attestation at tip_height") {
    Write-Output "light-scan-checkpoint-soft: F45 tip raced past attestation (log_max=$maxTip)"
    Write-Output "light-scan-checkpoint-soft: WARN soft-pass - re-publish Path A checkpoint (B-22) or re-pin for exact-tip F12"
    Write-Output "light-scan-checkpoint-soft: PASS f45-soft"
  } else {
    Write-Output $msg
    exit $p.ExitCode
  }

  & $Mcli --rpc $Rpc --wallet $Wallet wallet status --json
  if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
  Write-Output "bootstrap-wallet-from-checkpoint-log: OK"
} finally {
  Remove-Item -Recurse -Force $tmp -ErrorAction SilentlyContinue
}