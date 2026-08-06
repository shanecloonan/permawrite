# Lane 6 / B-28: assert draft treasury thresholds (OPERATORS).
# B-28-post land: pre|post modes; never flips genesis subsidy_bps.
# Default mode=pre (Path A pre-enable). -Mode post expects subsidy_bps=1000 after B-13c.
param(
    [switch]$PlanOnly,
    [switch]$Json,
    [ValidateSet("pre", "post")]
    [string]$Mode = "pre",
    [string]$Rpc = ""
)
$ErrorActionPreference = "Stop"
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$wantSubsidy = if ($Mode -eq "post") { 1000 } else { 0 }

if ($PlanOnly -or -not $Rpc) {
    Write-Host "assert-b28-treasury-thresholds: plan"
    Write-Host ("  mode=" + $Mode)
    Write-Host ("  checks=subsidy_bps==" + $wantSubsidy + ",fee_bps==9000,treasury>=1000000")
    Write-Host "  helper=treasury-telemetry-watch"
    Write-Host ("  pre_enable=" + ($(if ($Mode -eq "pre") { "true" } else { "false" })))
    Write-Host ("  post_enable=" + ($(if ($Mode -eq "post") { "true" } else { "false" })))
    Write-Host "  command=assert-b28-treasury-thresholds.ps1 -Mode pre -Rpc http://127.0.0.1:8787/rpc"
    if ($Json) {
        [ordered]@{
            schema_version = "assert-b28-treasury-thresholds.v1"
            mode           = "plan-only"
            assert_mode    = $Mode
            pre_enable     = ($Mode -eq "pre")
            post_enable    = ($Mode -eq "post")
            checks         = @("subsidy_bps==$wantSubsidy", "fee_bps==9000", "treasury>=1000000")
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
Write-Host "assert-b28-treasury-thresholds: tip=$tip treasury=$treasury fee_bps=$fee subsidy_bps=$subsidy mode=$Mode"
$fails = @()
if ($subsidy -ne $wantSubsidy) { $fails += "subsidy_bps=$subsidy want $wantSubsidy (mode=$Mode)" }
if ($fee -ne 9000) { $fails += "fee_bps=$fee want 9000" }
if ($treasury -lt 1000000) { $fails += "treasury=$treasury below floor 1000000" }
if ($fails.Count -gt 0) {
    foreach ($f in $fails) { Write-Host "assert-b28-treasury-thresholds: FAIL $f" }
    exit 1
}
Write-Host "assert-b28-treasury-thresholds: PASS"
