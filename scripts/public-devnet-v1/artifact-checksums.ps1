# Generate release artifact inventory checksum rows.
param(
    [Parameter(ValueFromRemainingArguments = $true)][string[]]$Path
)
$ErrorActionPreference = "Stop"

if (-not $Path -or $Path.Count -eq 0) {
    throw "artifact-checksums: pass one or more file paths"
}

$lines = New-Object System.Collections.Generic.List[string]
$lines.Add("| Path | SHA-256 | Bytes |") | Out-Null
$lines.Add("| --- | --- | ---: |") | Out-Null

foreach ($item in $Path) {
    if (-not (Test-Path -LiteralPath $item -PathType Leaf)) {
        throw "artifact-checksums: missing file $item"
    }
    $resolved = (Resolve-Path -LiteralPath $item).Path
    $hash = (Get-FileHash -Algorithm SHA256 -LiteralPath $resolved).Hash.ToLowerInvariant()
    $bytes = (Get-Item -LiteralPath $resolved).Length
    $lines.Add("| ``$resolved`` | ``$hash`` | $bytes |") | Out-Null
}

Write-Output ($lines -join "`n")
