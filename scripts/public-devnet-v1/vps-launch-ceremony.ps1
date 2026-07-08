# Lane 7: VPS launch ceremony — status and plan (TL-5 through TL-9).
param(
    [switch]$PlanOnly,
    [switch]$Check
)
$ErrorActionPreference = "Stop"
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path

if ($PlanOnly) {
    @'
vps-launch-ceremony: ordered VPS path (Lane 7)

  TL-5  bash scripts/public-devnet-v1/vps-preflight.sh
        bash scripts/public-devnet-v1/vps-internet-soak.sh

  TL-6  bash scripts/public-devnet-v1/vps-participant-rehearsal.sh --no-start --no-stop

  TL-7  human sign-off - docs/TESTNET_GENESIS_CEREMONY.md

  TL-8  bash scripts/public-devnet-v1/publish-seed-nodes.sh --public-ip YOUR_IP --apply

  TL-9  bash scripts/public-devnet-v1/launch-go-no-go.sh

Docs: docs/VPS_PROVISION.md  docs/VPS_SINGLE_BOX_LAUNCH.md
'@ | Write-Host
    exit 0
}

Write-Host "vps-launch-ceremony: === launch-status ==="
& powershell -NoProfile -File (Join-Path $ScriptDir "launch-status.ps1")
Write-Host ""

if ($Check) {
    Write-Host "vps-launch-ceremony: === launch-go-no-go ==="
    & powershell -NoProfile -File (Join-Path $ScriptDir "launch-go-no-go.ps1")
    exit $LASTEXITCODE
}

$evidenceDir = Join-Path $ScriptDir "evidence"
$hasSoak = [bool](Get-ChildItem -Path $evidenceDir -Filter "vps-internet-soak-linux-*" -ErrorAction SilentlyContinue)
$hasRehearsal = [bool](Get-ChildItem -Path $evidenceDir -Filter "vps-participant-rehearsal-*" -ErrorAction SilentlyContinue)
$manifestPath = Join-Path (Resolve-Path (Join-Path $ScriptDir "..\..")).Path "mfn-node\testdata\public_devnet_v1.manifest.json"
$seedCount = 0
if (Test-Path $manifestPath) {
    $seedCount = @((Get-Content -Raw $manifestPath | ConvertFrom-Json).seed_nodes).Count
}

if ($hasSoak -or $hasRehearsal -or $seedCount -gt 0) {
    Write-Host "vps-launch-ceremony: === launch-go-no-go (evidence or seeds present) ==="
    & powershell -NoProfile -File (Join-Path $ScriptDir "launch-go-no-go.ps1")
} else {
    Write-Host "vps-launch-ceremony: skip go/no-go (no VPS evidence yet); use -Check to force"
    Write-Host "vps-launch-ceremony: next: vps-internet-soak.sh on Linux VPS"
}
