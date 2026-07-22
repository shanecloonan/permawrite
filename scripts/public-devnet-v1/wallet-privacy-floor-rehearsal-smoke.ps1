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
foreach ($wasmFile in @("mfn-wasm/src/transfer_core.rs", "mfn-wasm/src/upload_core.rs")) {
  $wasmTxt = Get-Content -Raw (Join-Path $RepoRoot $wasmFile)
  if ($wasmTxt -match "ring_size: 16,") {
    Write-Error "WASM still hardcodes ring_size: 16 in $wasmFile (B-177)"
  }
}
$uploadTxt = Get-Content -Raw (Join-Path $RepoRoot "mfn-wallet/src/upload.rs")
if ($uploadTxt -match "ring_size: 16,") {
  Write-Error "mfn-wallet upload.rs still hardcodes ring_size: 16 (B-180)"
}
$parseTxt = Get-Content -Raw (Join-Path $RepoRoot "mfn-cli/src/cli/parse.rs")
if ($parseTxt -notmatch [regex]::Escape("default 16, wallet/consensus floor")) {
  Write-Error "missing CLI usage wallet/consensus floor for ring-size (B-182)"
}
if ($parseTxt -match "consensus min") {
  Write-Error "CLI usage still says consensus min (B-182)"
}
foreach ($pair in @(
  @("mfn-wallet/src/error.rs", "TxInputCountBelowMinimum"),
  @("mfn-wallet/src/spend.rs", "TxInputCountBelowMinimum"),
  @("mfn-wallet/src/upload.rs", "TxInputCountBelowMinimum")
)) {
  $txt = Get-Content -Raw (Join-Path $RepoRoot $pair[0])
  if ($txt -notmatch [regex]::Escape($pair[1])) {
    Write-Error "missing needle '$($pair[1])' in $($pair[0]) (B-185)"
  }
}
Write-Output "wallet-privacy-floor-rehearsal-smoke: PASS plan-only"
if (-not $PlanOnly) { exit 0 }