# Start committee voter 1 or 2; requires $env:HUB_P2P (M2.4.3).
param(
    [Parameter(Mandatory = $true)]
    [ValidateSet("1", "2")]
    [string]$Index
)
$ErrorActionPreference = "Stop"
if (-not $env:HUB_P2P) { throw "Set HUB_P2P to hub mfnd_p2p_listening address" }
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$RepoRoot = (Resolve-Path (Join-Path $ScriptDir "..\..")).Path
$Mfnd = if ($env:MFND) { $env:MFND } else { Join-Path $RepoRoot "target\release\mfnd.exe" }
$Genesis = Join-Path $RepoRoot "mfn-node\testdata\public_devnet_v1.json"
$DataDir = if ($env:DATA_DIR) { $env:DATA_DIR } else { Join-Path $RepoRoot ".permawrite-devnet-v1\v$Index" }
$SlotMs = if ($env:SLOT_MS) { [int]$env:SLOT_MS } else { 30000 }
New-Item -ItemType Directory -Force -Path $DataDir | Out-Null
$env:MFND_VALIDATOR_INDEX = $Index
if ($Index -eq "1") {
    $env:MFND_VRF_SEED_HEX = "0202020202020202020202020202020202020202020202020202020202020202"
    $env:MFND_BLS_SEED_HEX = "7676767676767676767676767676767676767676767676767676767676767676"
} else {
    $env:MFND_VRF_SEED_HEX = "0303030303030303030303030303030303030303030303030303030303030303"
    $env:MFND_BLS_SEED_HEX = "8787878787878787878787878787878787878787878787878787878787878787"
}
& $Mfnd --data-dir $DataDir --genesis $Genesis --store fs `
    --rpc-listen 127.0.0.1:0 --p2p-listen 127.0.0.1:0 `
    --p2p-dial $env:HUB_P2P --slot-duration-ms $SlotMs serve --committee-vote
