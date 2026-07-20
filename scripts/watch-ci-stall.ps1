# B-34 wrapper — delegates to watch-ci-stall.py
param(
    [switch]$PlanOnly,
    [string]$RunId = "",
    [switch]$CancelIfStalled,
    [string]$Workflow = "",
    [double]$StallMinutes = 0
)
$ErrorActionPreference = "Stop"
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$py = Join-Path $ScriptDir "watch-ci-stall.py"
$argsList = @()
if ($PlanOnly) { $argsList += "--plan-only" }
if ($RunId) { $argsList += @("--run-id", $RunId) }
if ($CancelIfStalled) { $argsList += "--cancel-if-stalled" }
if ($Workflow) { $argsList += @("--workflow", $Workflow) }
if ($StallMinutes -gt 0) { $argsList += @("--stall-minutes", "$StallMinutes") }
python $py @argsList
exit $LASTEXITCODE
