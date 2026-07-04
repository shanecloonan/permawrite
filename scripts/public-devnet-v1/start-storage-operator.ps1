# One-command storage operator: prove loop against any synced RPC (M6 / decentralization Phase A).
# RPC-only path — no local mfnd required when MFN_RPC or manifest observer_rpc is set.
param(
    [string]$Wallet = $(if ($env:MFN_WALLET) { $env:MFN_WALLET } else { "" })
)
$ErrorActionPreference = "Stop"
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$RepoRoot = (Resolve-Path (Join-Path $ScriptDir "..\..")).Path
$Mfno = if ($env:MFNO) { $env:MFNO } else { Join-Path $RepoRoot "target\release\mfn-storage-operator.exe" }
$ManifestPath = Join-Path $RepoRoot "mfn-node\testdata\public_devnet_v1.manifest.json"
if (-not $Wallet) { $Wallet = Join-Path $RepoRoot "wallet.json" }
$PortsFile = Join-Path $ScriptDir "devnet-ports.env"
if (-not $env:MFN_RPC -and (Test-Path $PortsFile)) {
    . (Join-Path $ScriptDir "ports-env-lib.ps1")
    $ports = Read-DevnetPortsFile -Path $PortsFile
    if ($ports["OBSERVER_RPC"]) { $env:MFN_RPC = $ports["OBSERVER_RPC"] }
}
if (-not $env:MFN_OPERATOR_MANIFEST) { $env:MFN_OPERATOR_MANIFEST = $ManifestPath }
$extra = @()
if ($env:MFN_CHUNK_LISTEN) { $extra += @("--chunk-listen", $env:MFN_CHUNK_LISTEN) }
if ($env:MFN_ONCE -eq "1") { $extra += "--once" }
if ($env:MFN_JSON -eq "1") { $extra += "--json" }
& $Mfno run --wallet $Wallet @extra