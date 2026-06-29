# Public-devnet participant preflight for Windows operators.
param(
    [switch]$Strict
)
$ErrorActionPreference = "Stop"

$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$RepoRoot = (Resolve-Path (Join-Path $ScriptDir "..\..")).Path
$PortsFile = Join-Path $ScriptDir "devnet-ports.env"
$ToolchainRecovery = "See scripts/public-devnet-v1/OPERATORS.md#toolchain-recovery"

$Checks = New-Object System.Collections.Generic.List[object]

function Add-Check {
    param([string]$Name, [string]$Status, [string]$Message, [string]$Fix = "")
    $Checks.Add([pscustomobject]@{
        Name = $Name
        Status = $Status
        Message = $Message
        Fix = $Fix
    }) | Out-Null
}

function Test-Command {
    param([string]$Name)
    return $null -ne (Get-Command $Name -ErrorAction SilentlyContinue)
}

function Add-CommandCheck {
    param([string]$Name, [string]$Purpose, [bool]$Required, [string]$Fix)
    if (Test-Command $Name) {
        $path = (Get-Command $Name -ErrorAction Stop).Source
        Add-Check $Name "ok" "$Purpose available at $path"
        return
    }
    $status = if ($Required) { "fail" } else { "warn" }
    Add-Check $Name $status "$Purpose is not on PATH" $Fix
}

function Add-ReleaseBinaryCheck {
    param([string]$FileName, [string]$BuildCommand)
    $path = Join-Path $RepoRoot "target\release\$FileName"
    if (Test-Path $path) {
        Add-Check $FileName "ok" "release binary exists at $path"
    } else {
        Add-Check $FileName "warn" "release binary is missing at $path" "Run: $BuildCommand"
    }
}

function Add-MfndProcessCheck {
    $processes = @(Get-Process mfnd -ErrorAction SilentlyContinue)
    if ($processes.Count -eq 0) {
        Add-Check "mfnd processes" "ok" "no running mfnd processes detected"
        return
    }
    $ids = ($processes | ForEach-Object { $_.Id }) -join ","
    Add-Check "mfnd processes" "warn" "running mfnd processes detected: pids=$ids; Windows may lock target\release\mfnd.exe during rebuilds" "Run scripts/public-devnet-v1/stop-all.ps1 -DryRun, then stop recorded devnet PIDs before release rebuilds or CI; use -AllMfnd only for stale daemons."
}

function Add-PortsFileCheck {
    if (Test-Path $PortsFile) {
        Add-Check "devnet-ports.env" "ok" "found $PortsFile"
    } else {
        Add-Check "devnet-ports.env" "warn" "no devnet-ports.env found; helper scripts need --rpc or a started local mesh" "Run start-all.ps1 or pass -Rpc HOST:PORT to wallet/demo helpers."
    }
}

Add-CommandCheck "cargo" "Rust package manager" $true "Install Rust stable from https://rustup.rs/ and reopen the shell."
Add-CommandCheck "rustc" "Rust compiler" $true "Install Rust stable from https://rustup.rs/ and reopen the shell."
Add-CommandCheck "git" "Git client" $true "Install Git for Windows and reopen the shell."
Add-CommandCheck "node" "CODEBASE_STATS.md generator runtime" $false "Install Node.js or expose node.exe on PATH before regenerating CODEBASE_STATS.md. $ToolchainRecovery."
Add-CommandCheck "bash" "Linux/macOS helper script validator" $false "Install Git Bash, MSYS2, or WSL if you need to run or syntax-check .sh helpers on Windows. $ToolchainRecovery."
Add-CommandCheck "dlltool.exe" "GNU binutils helper required by some Windows release-test dependencies" $false "Install MSYS2 mingw-w64 binutils or another toolchain package that provides dlltool.exe, then add it to PATH. $ToolchainRecovery."
Add-CommandCheck "wasm-pack" "WASM package test runner used by the local CI mirror" $false "Install with: cargo install wasm-pack --locked. $ToolchainRecovery."
Add-CommandCheck "cargo-audit" "dependency advisory scanner used by the local CI mirror" $false "Install with: cargo install cargo-audit --locked. $ToolchainRecovery."
Add-ReleaseBinaryCheck "mfnd.exe" "cargo build -p mfn-node --release --bin mfnd"
Add-ReleaseBinaryCheck "mfn-cli.exe" "cargo build -p mfn-cli --release --bin mfn-cli"
Add-ReleaseBinaryCheck "mfn-storage-operator.exe" "cargo build -p mfn-storage-operator --release --bin mfn-storage-operator"
Add-MfndProcessCheck
Add-PortsFileCheck

$hasFailures = $false
$hasWarnings = $false
foreach ($check in $Checks) {
    $line = "preflight: status=$($check.Status) check=$($check.Name) message=$($check.Message)"
    Write-Host $line
    if ($check.Fix) {
        Write-Host "preflight: fix=$($check.Fix)"
    }
    if ($check.Status -eq "fail") { $hasFailures = $true }
    if ($check.Status -eq "warn") { $hasWarnings = $true }
}

if ($hasFailures -or ($Strict -and $hasWarnings)) {
    if ($Strict -and $hasWarnings -and -not $hasFailures) {
        Write-Host "preflight: result=warn strict=true"
    } else {
        Write-Host "preflight: result=fail"
    }
    exit 1
}

if ($hasWarnings) {
    Write-Host "preflight: result=warn"
} else {
    Write-Host "preflight: result=ok"
}
