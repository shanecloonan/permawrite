# Build mfn-wasm for the browser demo (M4.1).
$ErrorActionPreference = "Stop"
Set-Location (Join-Path $PSScriptRoot "..")

if (-not (Get-Command wasm-pack -ErrorAction SilentlyContinue)) {
    Write-Error "wasm-pack not found; run: cargo install wasm-pack --locked"
}

rustup target add wasm32-unknown-unknown 2>$null

# wasm-pack 0.15 mis-parses a prior package.json when `files`/`sideEffects` are arrays.
Remove-Item -Recurse -Force mfn-wasm/demo/web/pkg -ErrorAction SilentlyContinue

wasm-pack --log-level warn build mfn-wasm `
    --target web `
    --out-dir demo/web/pkg `
    --release `
    --features wasm-full

Write-Host "WASM demo built -> demo/web/pkg/"
