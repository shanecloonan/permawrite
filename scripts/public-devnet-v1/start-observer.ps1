# Start non-validator observer; requires $env:HUB_P2P (M2.4.9).
$ErrorActionPreference = "Stop"
if (-not $env:HUB_P2P) { throw "Set HUB_P2P to hub mfnd_p2p_listening address" }
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$RepoRoot = (Resolve-Path (Join-Path $ScriptDir "..\..")).Path
$Mfnd = if ($env:MFND) { $env:MFND } else { Join-Path $RepoRoot "target\release\mfnd.exe" }
$Genesis = Join-Path $RepoRoot "mfn-node\testdata\public_devnet_v1.json"
$DataDir = if ($env:DATA_DIR) { $env:DATA_DIR } else { Join-Path $RepoRoot ".permawrite-devnet-v1\observer" }
New-Item -ItemType Directory -Force -Path $DataDir | Out-Null
Remove-Item Env:MFND_VALIDATOR_INDEX -ErrorAction SilentlyContinue
Remove-Item Env:MFND_VRF_SEED_HEX -ErrorAction SilentlyContinue
Remove-Item Env:MFND_BLS_SEED_HEX -ErrorAction SilentlyContinue
& $Mfnd --data-dir $DataDir --genesis $Genesis --store fs `
    --rpc-listen 127.0.0.1:0 --p2p-listen 127.0.0.1:0 `
    --p2p-dial $env:HUB_P2P --slot-duration-ms 30000 serve
