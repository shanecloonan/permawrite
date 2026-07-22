# B-59 / B-161 / F45: Windows twin of light-scan-checkpoint-soft.sh
# Exact-tip Schnorr attestation is still required when tip == log entry; if the live tip
# has moved past the latest signed height, pin+scan remains valid and we soft-pass.
# B-161: mfn-cli light-scan --checkpoint-log also soft-passes F45 in-process; this wrapper
# remains for older binaries, rehearsal needles, and explicit soft-path ops.
param(
  [switch]$PlanOnly,
  [string]$Rpc = "",
  [string]$Wallet = "",
  [string]$Log = "",
  [string]$Mcli = ""
)

$ErrorActionPreference = "Stop"
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$RepoRoot = if ($env:MFN_REPO_ROOT) { $env:MFN_REPO_ROOT } else { (Resolve-Path (Join-Path $ScriptDir "../..")).Path }
if (-not $Mcli) {
  $Mcli = if ($env:MCLI) { $env:MCLI } else { Join-Path $RepoRoot "target/release/mfn-cli.exe" }
  if (-not (Test-Path $Mcli)) { $Mcli = Join-Path $RepoRoot "target/release/mfn-cli" }
}

if ($PlanOnly) {
  Write-Output "light-scan-checkpoint-soft: plan"
  Write-Output "  unit=B-59/B-161"
  Write-Output "  f45=soft-pass when tip raced past latest Schnorr attestation"
  Write-Output "  hard=checkpoint-log verify still required; disagreement at attested height still fails"
  Write-Output "  note=B-161 in-CLI soft-pass; wrapper for older binaries + rehearsal"
  Write-Output "light-scan-checkpoint-soft: PASS plan-only"
  exit 0
}

if (-not $Rpc -or -not $Wallet -or -not $Log) {
  Write-Error "light-scan-checkpoint-soft.ps1: -Rpc -Wallet -Log required (or -PlanOnly)"
}
if (-not (Test-Path $Mcli)) { Write-Error "mfn-cli missing: $Mcli" }
if (-not (Test-Path $Wallet)) { Write-Error "wallet missing: $Wallet" }
if (-not (Test-Path $Log)) { Write-Error "log missing: $Log" }

& $Mcli checkpoint-log verify $Log
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

& $Mcli --rpc $Rpc --wallet $Wallet wallet light-scan
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

$tmp = Join-Path ([System.IO.Path]::GetTempPath()) ("mfn-f45-" + [guid]::NewGuid().ToString("n"))
New-Item -ItemType Directory -Path $tmp | Out-Null
try {
  $outFile = Join-Path $tmp "scan.out"
  $errFile = Join-Path $tmp "scan.err"
  $p = Start-Process -FilePath $Mcli -ArgumentList @(
    "--rpc", $Rpc, "--wallet", $Wallet, "wallet", "light-scan", "--checkpoint-log", $Log
  ) -NoNewWindow -Wait -PassThru -RedirectStandardOutput $outFile -RedirectStandardError $errFile
  $msg = ""
  if (Test-Path $outFile) { $msg += Get-Content -Raw $outFile }
  if (Test-Path $errFile) { $msg += Get-Content -Raw $errFile }

  if ($p.ExitCode -eq 0) {
    if ($msg.Trim().Length -gt 0) { Write-Output $msg.TrimEnd() }
    if ($msg -match "checkpoint_log_f45_soft_pass") {
      Write-Output "light-scan-checkpoint-soft: PASS f45-soft (in-cli B-161)"
      exit 0
    }
    Write-Output "light-scan-checkpoint-soft: PASS exact-tip"
    exit 0
  }

  # B-161 in-CLI soft-pass prints checkpoint_log_f45_soft_pass and exits 0; older binaries
  # still hit the hard F45 error string — soft-pass here with the same honesty bounds.
  if ($msg -match "checkpoint_log_f45_soft_pass" -or $msg -match "has no attestation at tip_height") {
    $utf8enc = New-Object System.Text.UTF8Encoding $false
    $maxPy = Join-Path $tmp "max_tip.py"
    [System.IO.File]::WriteAllText($maxPy, (@(
      "import json"
      "from pathlib import Path"
      "import sys"
      "tips = [int(json.loads(l)['summary']['tip_height']) for l in Path(sys.argv[1]).read_text(encoding='utf-8').splitlines() if l.strip()]"
      "print(max(tips) if tips else 0)"
    ) -join "`n") + "`n", $utf8enc)
    $scanPy = Join-Path $tmp "scan_h.py"
    [System.IO.File]::WriteAllText($scanPy, (@(
      "import json"
      "from pathlib import Path"
      "import sys"
      "w = json.loads(Path(sys.argv[1]).read_text(encoding='utf-8'))"
      "print(w.get('scan_height') or 0)"
    ) -join "`n") + "`n", $utf8enc)
    $maxTip = (& python $maxPy $Log).Trim()
    $scanH = (& python $scanPy $Wallet).Trim()
    Write-Output "light-scan-checkpoint-soft: F45 tip raced past attestation (log_max=$maxTip scan_height=$scanH)"
    Write-Output "light-scan-checkpoint-soft: WARN soft-pass - re-publish Path A checkpoint (B-22) or re-pin for exact-tip F12"
    Write-Output "light-scan-checkpoint-soft: PASS f45-soft"
    exit 0
  }

  Write-Output $msg
  exit $p.ExitCode
} finally {
  Remove-Item -Recurse -Force $tmp -ErrorAction SilentlyContinue
}
