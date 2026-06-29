# Validate a filled release-candidate artifact inventory.
param(
    [Parameter(Mandatory = $true)][string]$Inventory
)
$ErrorActionPreference = "Stop"

if (-not (Test-Path -LiteralPath $Inventory -PathType Leaf)) {
    throw "artifact-inventory-validate: missing file $Inventory"
}

$lines = Get-Content -LiteralPath $Inventory
$issues = New-Object System.Collections.Generic.List[string]

function Test-Value {
    param([string]$Label, [string]$Value, [int]$LineNumber)
    $trimmed = $Value.Trim()
    if (-not $trimmed) {
        $script:issues.Add("line ${LineNumber}: '$Label' is required") | Out-Null
        return
    }
    if ($trimmed -match "^(?i:not applicable|n/a)$") {
        $script:issues.Add("line ${LineNumber}: '$Label' uses '$trimmed' without a reason") | Out-Null
    }
}

for ($i = 0; $i -lt $lines.Count; $i++) {
    $line = $lines[$i]
    $lineNumber = $i + 1
    if ($line -match "^\s*(?:-\s*)?(?<label>Path or URL|SHA-256|SHA-256 or archive checksum|Reviewer|Decision):\s*(?<value>.*)$") {
        Test-Value $Matches.label $Matches.value $lineNumber
    }
}

$decisionLine = $lines | Where-Object { $_ -match "^\s*Decision:\s*(.+)$" } | Select-Object -First 1
if (-not $decisionLine) {
    $issues.Add("missing final Decision field") | Out-Null
} elseif ($decisionLine -notmatch "^\s*Decision:\s*(go|no-go)\s*$") {
    $issues.Add("final Decision must be 'go' or 'no-go'") | Out-Null
}

if ($issues.Count -gt 0) {
    $issues | ForEach-Object { [Console]::Error.WriteLine("artifact-inventory-validate: $_") }
    exit 1
}

Write-Host "artifact-inventory-validate: OK"
