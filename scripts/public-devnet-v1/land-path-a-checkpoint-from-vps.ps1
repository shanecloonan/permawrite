# B-97 / lane 7: Windows twin of land-path-a-checkpoint-from-vps.sh
# Copy Path A checkpoint log from VPS when remote tip > local tip.
# B-15-safe: never touches faucet/mfnd. Does not commit (agent commits).
param(
  [switch]$PlanOnly,
  [switch]$Apply,
  [switch]$Help
)
$ErrorActionPreference = "Stop"
if ($Help) {
  Write-Host "usage: land-path-a-checkpoint-from-vps.ps1 [-PlanOnly|-Apply]"
  exit 0
}
if (-not $PlanOnly -and -not $Apply) {
  Write-Error "land-path-a-checkpoint-from-vps: specify -PlanOnly or -Apply"
  exit 1
}
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$RepoRoot = if ($env:MFN_REPO_ROOT) { $env:MFN_REPO_ROOT } else { (Resolve-Path (Join-Path $ScriptDir "../..")).Path }
$LogPath = if ($env:MFN_CHECKPOINT_LOG) { $env:MFN_CHECKPOINT_LOG } else { Join-Path $RepoRoot "mfn-node/testdata/public_devnet_v1.checkpoints.jsonl" }
$VpsHost = if ($env:MFN_VPS_HOST) { $env:MFN_VPS_HOST } else { "root@5.161.201.73" }
$VpsLog = if ($env:MFN_VPS_CHECKPOINT_LOG) { $env:MFN_VPS_CHECKPOINT_LOG } else { "/root/permawrite/mfn-node/testdata/public_devnet_v1.checkpoints.jsonl" }

if ($PlanOnly) {
  Write-Host "land-path-a-checkpoint-from-vps: plan"
  Write-Host "  unit=B-89/B-97"
  Write-Host "  flow=compare tip_height -> scp VPS jsonl if remote ahead"
  Write-Host "  never=faucet-http mfnd restart git-commit"
  Write-Host "land-path-a-checkpoint-from-vps: PASS plan-only"
  exit 0
}

function Get-MaxTip([string]$Path) {
  if (-not (Test-Path -LiteralPath $Path)) { return 0 }
  $mx = 0
  foreach ($line in Get-Content -LiteralPath $Path -Encoding utf8) {
    if ([string]::IsNullOrWhiteSpace($line)) { continue }
    $d = $line | ConvertFrom-Json
    $h = 0
    if ($null -ne $d.summary -and $null -ne $d.summary.tip_height) { $h = [int]$d.summary.tip_height }
    if ($h -gt $mx) { $mx = $h }
  }
  return $mx
}

$localTip = Get-MaxTip $LogPath
$tmp = Join-Path ([System.IO.Path]::GetTempPath()) ("path-a-ckpt-" + [guid]::NewGuid().ToString() + ".jsonl")
try {
  scp -o BatchMode=yes -o ConnectTimeout=15 "${VpsHost}:${VpsLog}" $tmp
  if ($LASTEXITCODE -ne 0) { throw "scp failed exit=$LASTEXITCODE" }
  $remoteTip = Get-MaxTip $tmp
  Write-Host "land-path-a-checkpoint-from-vps: local_tip=$localTip remote_tip=$remoteTip"
  if ($remoteTip -le $localTip) {
    Write-Host "land-path-a-checkpoint-from-vps: SKIP remote not ahead"
    exit 0
  }
  Copy-Item -LiteralPath $tmp -Destination $LogPath -Force
  Write-Host "land-path-a-checkpoint-from-vps: OK updated $LogPath to tip=$remoteTip (commit when ready)"
} finally {
  if (Test-Path -LiteralPath $tmp) { Remove-Item -LiteralPath $tmp -Force -ErrorAction SilentlyContinue }
}