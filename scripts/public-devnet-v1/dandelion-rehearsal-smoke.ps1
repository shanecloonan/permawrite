# B7: participant-rehearsal-smoke with Dandelion++ relay enabled on the mesh.
param(
    [string]$Rpc = "",
    [string]$FaucetWallet = "",
    [string]$RehearsalDir = "",
    [string]$EvidenceDir = "",
    [int]$WaitAfterStartSeconds = -1,
    [int]$WaitFaucetSeconds = 240,
    [int]$WaitMinedSeconds = 240,
    [int]$WaitUploadSeconds = 360,
    [int]$WaitProofSeconds = 240,
    [int]$MinHubHeight = 0,
    [int]$WaitMinHubHeightSeconds = 180,
    [int]$WaitObserverCatchUpSeconds = 180,
    [switch]$WithObserver,
    [switch]$NoStart,
    [switch]$NoStop,
    [switch]$NoBuild,
    [switch]$PlanOnly,
    [switch]$ArchiveEvidence
)
$ErrorActionPreference = "Stop"
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
& (Join-Path $ScriptDir "participant-rehearsal-smoke.ps1") @PSBoundParameters -Dandelion
