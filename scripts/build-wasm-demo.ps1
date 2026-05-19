# Build mfn-wasm for the browser demo (M4.1).
$ErrorActionPreference = "Stop"
Set-Location (Join-Path $PSScriptRoot "..")

if (-not (Get-Command wasm-pack -ErrorAction SilentlyContinue)) {
    Write-Error "wasm-pack not found; run: cargo install wasm-pack --locked"
}

rustup target add wasm32-unknown-unknown 2>$null

wasm-pack build mfn-wasm `
    --target web `
    --out-dir demo/web/pkg `
    --release

Write-Host "WASM demo built -> demo/web/pkg/"
