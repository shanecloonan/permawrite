# B7: short public-devnet soak with Dandelion++ relay enabled (local rehearsal).
param(
    [int]$DurationMinutes = 10,
    [int]$CheckIntervalSeconds = 60,
    [int]$StallSamples = 2,
    [int]$StallIntervalSeconds = 0,
    [int]$MinHeightDelta = 1,
    [int]$MinFinalHeight = 0,
    [int]$MinSuccessfulIterations = 3,
    [switch]$RestartObserverOnce,
    [int]$RestartTimeoutSeconds = 180,
    [switch]$NoStart,
    [switch]$ArchiveEvidence
)
$ErrorActionPreference = "Stop"
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
& (Join-Path $ScriptDir "soak.ps1") @PSBoundParameters -Dandelion
