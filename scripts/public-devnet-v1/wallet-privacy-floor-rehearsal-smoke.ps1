# B-172: Windows twin of wallet-privacy-floor-rehearsal-smoke.sh
param([switch]$PlanOnly)
$ErrorActionPreference = "Stop"
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$RepoRoot = (Resolve-Path (Join-Path $ScriptDir "../..")).Path
$needles = @(
  @("mfn-wallet/src/lib.rs", "WALLET_MIN_RING_SIZE: usize = 16"),
  @("mfn-wallet/src/lib.rs", "WALLET_MIN_TX_INPUTS: usize = 2"),
  @("mfn-wallet/src/error.rs", "RingSizeBelowMinimum"),
  @("mfn-wallet/src/spend.rs", "RingSizeBelowMinimum"),
  @("mfn-cli/src/cli/parse.rs", "wallet/consensus floor"),
  @("mfn-wasm/src/transfer_core.rs", "WALLET_MIN_RING_SIZE"),
  @("mfn-wasm/src/transfer_core.rs", "WALLET_MIN_TX_INPUTS"),
  @("mfn-wasm/src/upload_core.rs", "WALLET_MIN_TX_INPUTS"),
  @("mfn-wasm/src/transfer_core.rs", "F7 privacy floor"),
  @("mfn-cli/src/wallet_cmd.rs", "DEFAULT_RING_SIZE: usize = WALLET_MIN_RING_SIZE"),
  @("docs/PRIVACY.md", "CLI-only"),
  @("docs/CHECKPOINT_LOG.md", "Honesty (B-168)")
)
foreach ($pair in $needles) {
  $path = Join-Path $RepoRoot $pair[0]
  $txt = Get-Content -Raw $path
  if ($txt -notmatch [regex]::Escape($pair[1])) {
    Write-Error "missing needle '$($pair[1])' in $($pair[0])"
  }
}
Write-Output "wallet-privacy-floor-rehearsal-smoke: PASS plan-only"
if (-not $PlanOnly) { exit 0 }