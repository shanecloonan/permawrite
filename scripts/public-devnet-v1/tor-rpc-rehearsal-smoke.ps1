# B8.3: plan-only Tor RPC participant smoke (Windows parity).
param(
    [string]$Rpc = "YOURSEED.onion:18731",
    [switch]$Live
)
$ErrorActionPreference = "Stop"

$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$RepoRoot = (Resolve-Path (Join-Path $ScriptDir "..\..")).Path

if ($Rpc -notmatch '\.onion:') {
    throw "tor-rpc-rehearsal-smoke: --Rpc must be .onion:PORT (got $Rpc)"
}

$Socks5 = if ($env:MFND_TOR_SOCKS5) { $env:MFND_TOR_SOCKS5 } else { "127.0.0.1:9050" }

Write-Host "tor-rpc-rehearsal-smoke: plan"
Write-Host "  flow=mfn-cli --tor --rpc $Rpc status -> tip"
Write-Host "  tor_socks5=$Socks5"
Write-Host "  docs=docs/TOR_P2P.md#wallet-json-rpc-over-tor-b83"

if (-not $Live) {
    Write-Host "tor-rpc-rehearsal-smoke: PASS plan-only"
    exit 0
}

Set-Location $RepoRoot
$Mcli = if ($env:MCLI) { $env:MCLI } else { Join-Path $RepoRoot "target\release\mfn-cli.exe" }
if (-not (Test-Path -LiteralPath $Mcli)) {
    throw "tor-rpc-rehearsal-smoke: build mfn-cli release first or set MCLI="
}

$env:MFN_CLI_RPC_TOR = "1"
$env:MFND_TOR_SOCKS5 = $Socks5

& $Mcli --tor --rpc $Rpc --tor-socks5 $Socks5 status
& $Mcli --tor --rpc $Rpc --tor-socks5 $Socks5 tip
Write-Host "tor-rpc-rehearsal-smoke: PASS live"
