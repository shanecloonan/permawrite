# Mirror .github/workflows/ci.yml locally before pushing to main.
$ErrorActionPreference = "Stop"
Set-Location (Join-Path $PSScriptRoot "..")

$env:CARGO_TERM_COLOR = "always"
$env:RUSTFLAGS = "-D warnings"

function Test-Command($Name) {
    return [bool](Get-Command $Name -ErrorAction SilentlyContinue)
}

$missingTools = @()
function Add-MissingCommand($Name, $InstallHint) {
    if (-not (Get-Command $Name -ErrorAction SilentlyContinue)) {
        $script:missingTools += "missing required command '$Name'. $InstallHint"
    }
}

Add-MissingCommand cargo "Install Rust from https://rustup.rs/ and reopen the shell."
Add-MissingCommand rustup "Install Rust from https://rustup.rs/ and reopen the shell."
Add-MissingCommand bash "Install Git Bash, MSYS2, or WSL and reopen the shell."
Add-MissingCommand wasm-pack "Install with: cargo install wasm-pack --locked"
Add-MissingCommand cargo-audit "Install with: cargo install cargo-audit --locked"
$isWindowsHost = [System.Environment]::OSVersion.Platform -eq [System.PlatformID]::Win32NT
if ($isWindowsHost -and -not (Test-Command dlltool)) {
    $missingTools += "missing required Windows build tool 'dlltool.exe'. Install the GNU binutils/mingw toolchain used by the local Rust target before running release tests."
}
if ($missingTools.Count -gt 0) {
    $missingTools | ForEach-Object { [Console]::Error.WriteLine($_) }
    exit 127
}

Write-Host "==> public-devnet scripts"
Get-ChildItem scripts -Filter *.ps1 -Recurse | ForEach-Object {
    $tokens = $null
    $errors = $null
    [System.Management.Automation.Language.Parser]::ParseFile($_.FullName, [ref]$tokens, [ref]$errors) | Out-Null
    if ($errors.Count -gt 0) {
        $errors | ForEach-Object { [Console]::Error.WriteLine("$($_.Extent.File): $_") }
        exit 1
    }
}
Get-ChildItem scripts -Filter *.sh -Recurse | ForEach-Object {
    bash -n $_.FullName
    if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
}

Write-Host "==> rustfmt"
cargo fmt --all --check
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

Write-Host "==> clippy"
cargo clippy --workspace --all-targets --all-features -- -D warnings
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

Write-Host "==> build mfnd + mfn-storage-operator (mfn-cli integration tests)"
cargo build -p mfn-node --bin mfnd --release
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
cargo build -p mfn-storage-operator --bin mfn-storage-operator --release
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

Write-Host "==> test (release)"
cargo test --workspace --release -- --test-threads=4
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

Write-Host "==> wasm32 build"
rustup target add wasm32-unknown-unknown
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
cargo build -p mfn-wasm --target wasm32-unknown-unknown --release --features wasm-full
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
cargo test -p mfn-wasm --release --features wasm-full
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
wasm-pack build mfn-wasm --target web --out-dir demo/web/pkg --release --features wasm-full
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

Write-Host "==> cargo audit"
cargo audit
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

Write-Host "ci-check: OK"
