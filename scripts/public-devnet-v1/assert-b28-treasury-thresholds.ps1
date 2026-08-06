# Lane 6 / B-28: assert draft treasury thresholds (OPERATORS). Pre-enable Path A.
param(
    [switch]$PlanOnly,
    [switch]$Json,
    [string]$Rpc = ""
)
$ErrorActionPreference = "Stop"
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path

if ($PlanOnly -or -not $Rpc) {
    Write-Host "assert-b28-treasury-thresholds: plan"
    Write-Host "  checks=subsidy_bps==0,fee_bps==9000,treasury>=1000000"
    Write-Host "  helper=treasury-telemetry-watch"
    Write-Host "  pre_enable=true"
    Write-Host "  command=assert-b28-treasury-thresholds.ps1 -Rpc http://127.0.0.1:8787/rpc"
    if ($Json) {
        [ordered]@{
            schema_version = "assert-b28-treasury-thresholds.v1"
            mode           = "plan-only"
            pre_enable     = $true
            checks         = @("subsidy_bps==0", "fee_bps==9000", "treasury>=1000000")
        } | ConvertTo-Json -Depth 4
    }
    Write-Host "assert-b28-treasury-thresholds: PASS plan-only"
    exit 0
}

$raw = & powershell -NoProfile -File (Join-Path $ScriptDir "treasury-telemetry-watch.ps1") -Rpc $Rpc -Json
$text = ($raw | Out-String)
$start = $text.IndexOf("{")
$end = $text.LastIndexOf("}")
if ($start -lt 0 -or $end -lt 0) { throw "assert-b28-treasury-thresholds: no JSON from telemetry watch" }
$d = $text.Substring($start, $end - $start + 1) | ConvertFrom-Json
$subsidy = [int]$d.subsidy_to_treasury_bps
$fee = [int]$d.fee_to_treasury_bps
$treasury = [int64]$d.treasury_base_units
$tip = $d.tip_height
Write-Host "assert-b28-treasury-thresholds: tip=$tip treasury=$treasury fee_bps=$fee subsidy_bps=$subsidy"
$fails = @()
if ($subsidy -ne 0) { $fails += "subsidy_bps=$subsidy want 0 (pre-enable)" }
if ($fee -ne 9000) { $fails += "fee_bps=$fee want 9000" }
if ($treasury -lt 1000000) { $fails += "treasury=$treasury below floor 1000000" }
if ($fails.Count -gt 0) {
    foreach ($f in $fails) { Write-Host "assert-b28-treasury-thresholds: FAIL $f" }
    exit 1
}
Write-Host "assert-b28-treasury-thresholds: PASS"