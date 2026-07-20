# B-93 wrapper — delegates to post-push-ci-watch.py
param(
  [switch]$PlanOnly,
  [string]$RunId = "",
  [switch]$CancelIfStalled
)
$ErrorActionPreference = "Stop"
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$argsList = @()
if ($PlanOnly) { $argsList += "--plan-only" }
if ($RunId) { $argsList += @("--run-id", $RunId) }
if ($CancelIfStalled) { $argsList += "--cancel-if-stalled" }
& python (Join-Path $ScriptDir "post-push-ci-watch.py") @argsList
exit $LASTEXITCODE
