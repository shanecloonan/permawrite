# B-36 / F10: consensus f64 arithmetic lint (see validate-consensus-f64-lint.py).
$ErrorActionPreference = "Stop"
$Root = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
$Py = $null
foreach ($name in @("python", "python3", "py")) {
    $cmd = Get-Command $name -ErrorAction SilentlyContinue | Where-Object {
        $_.Source -and ($_.Source -notmatch "WindowsApps")
    } | Select-Object -First 1
    if ($cmd) {
        $Py = $cmd.Source
        break
    }
}
if (-not $Py) {
    [Console]::Error.WriteLine("validate-consensus-f64-lint: python3 or python required")
    exit 1
}
if ($Py -match '[\\/]py\.exe$') {
    & $Py -3 (Join-Path $Root "scripts/validate-consensus-f64-lint.py")
} else {
    & $Py (Join-Path $Root "scripts/validate-consensus-f64-lint.py")
}
exit $LASTEXITCODE