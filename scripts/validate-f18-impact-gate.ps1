# B-23 / F18: privacy and permanence invariant gate (see validate-f18-impact-gate.py).
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
    [Console]::Error.WriteLine("validate-f18-impact-gate: python3 or python required")
    exit 1
}
$Script = Join-Path $Root "scripts/validate-f18-impact-gate.py"
if ($Py -match '[\\/]py\.exe$') {
    & $Py -3 $Script --self-test
    if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
    & $Py -3 $Script
} else {
    & $Py $Script --self-test
    if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
    & $Py $Script
}
exit $LASTEXITCODE
