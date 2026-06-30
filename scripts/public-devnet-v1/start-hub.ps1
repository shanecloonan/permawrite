# Start validator 0 (hub producer) for public-devnet-v1 (M2.4.3).
$ErrorActionPreference = "Stop"
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$RepoRoot = (Resolve-Path (Join-Path $ScriptDir "..\..")).Path
$Config = @{
    GENESIS_SPEC = "mfn-node/testdata/public_devnet_v1.json"
    SLOT_MS      = if ($env:SLOT_MS) { [int]$env:SLOT_MS } else { 30000 }
    DATA_ROOT    = ".permawrite-devnet-v1"
}
$Mfnd = if ($env:MFND) { $env:MFND } else { Join-Path $RepoRoot "target\release\mfnd.exe" }
$Genesis = Join-Path $RepoRoot $Config.GENESIS_SPEC
$DataDir = if ($env:DATA_DIR) { $env:DATA_DIR } else { Join-Path $RepoRoot ($Config.DATA_ROOT + "\v0") }
New-Item -ItemType Directory -Force -Path $DataDir | Out-Null
$env:MFND_VALIDATOR_INDEX = "0"
$env:MFND_VRF_SEED_HEX = "0101010101010101010101010101010101010101010101010101010101010101"
$env:MFND_BLS_SEED_HEX = "6565656565656565656565656565656565656565656565656565656565656565"
& $Mfnd --data-dir $DataDir --genesis $Genesis --store fs `
    --rpc-listen 127.0.0.1:0 --p2p-listen 127.0.0.1:0 `
    --slot-duration-ms $Config.SLOT_MS serve --produce
