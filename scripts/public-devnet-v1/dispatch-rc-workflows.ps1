# Dispatch release-candidate validation workflows on GitHub Actions (gh or GH_TOKEN/GITHUB_TOKEN).
param(
    [switch]$Nightly,
    [switch]$LinuxSoakAudit,
    [switch]$All,
    [switch]$CleanupCiQueue,
    [string]$Ref = "main",
    [string]$CheckoutSha = "",
    [string]$SlotMs = "30000",
    [string]$DurationMinutes = "35",
    [string]$MinFinalHeight = "10"
)
$ErrorActionPreference = "Stop"

$RepoRoot = (Resolve-Path (Join-Path $PSScriptRoot "..\..")).Path
Set-Location $RepoRoot

function Get-GithubToken {
    if ($env:GH_TOKEN) { return $env:GH_TOKEN }
    if ($env:GITHUB_TOKEN) { return $env:GITHUB_TOKEN }
    return ""
}

function Get-OwnerRepo {
    $remote = (git remote get-url origin 2>$null)
    if ($remote -match "github\.com[:/](?<owner>[^/]+)/(?<repo>[^/.]+)(\.git)?$") {
        return "$($Matches.owner)/$($Matches.repo)"
    }
    throw "dispatch-rc-workflows: cannot parse github.com owner/repo from origin remote"
}

function Invoke-GithubWorkflowDispatch {
    param(
        [string]$WorkflowFile,
        [hashtable]$Inputs = @{}
    )
    $token = Get-GithubToken
    if (-not $token) {
        throw "dispatch-rc-workflows: set GH_TOKEN or GITHUB_TOKEN for REST dispatch, or install gh and run gh auth login"
    }
    $ownerRepo = Get-OwnerRepo
    $parts = $ownerRepo.Split("/")
    $owner = $parts[0]
    $repo = $parts[1]
    $workflowId = $WorkflowFile
    $body = @{ ref = $Ref }
    if ($Inputs.Count -gt 0) { $body.inputs = $Inputs }
    $uri = "https://api.github.com/repos/$owner/$repo/actions/workflows/$workflowId/dispatches"
    $json = $body | ConvertTo-Json -Depth 4 -Compress
    Invoke-RestMethod -Method Post -Uri $uri -Headers @{
        Authorization = "Bearer $token"
        Accept = "application/vnd.github+json"
        "User-Agent" = "permawrite-dispatch-rc-workflows"
        "X-GitHub-Api-Version" = "2022-11-28"
    } -Body $json -ContentType "application/json" | Out-Null
}

function Invoke-GhWorkflowRun {
    param(
        [string]$WorkflowFile,
        [string[]]$FieldArgs = @()
    )
    if (-not (Get-Command gh -ErrorAction SilentlyContinue)) {
        throw "dispatch-rc-workflows: gh not installed"
    }
    $auth = gh auth status 2>&1
    if ($LASTEXITCODE -ne 0) {
        throw "dispatch-rc-workflows: gh not authenticated. Run: gh auth login"
    }
    $args = @("workflow", "run", $WorkflowFile, "--ref", $Ref) + $FieldArgs
    gh @args
    if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
}

function Start-WorkflowDispatch {
    param(
        [string]$WorkflowFile,
        [hashtable]$Inputs = @{}
    )
    if (Get-Command gh -ErrorAction SilentlyContinue) {
        try {
            $fieldArgs = @()
            foreach ($key in $Inputs.Keys) {
                $fieldArgs += "-f"
                $fieldArgs += "$key=$($Inputs[$key])"
            }
            Invoke-GhWorkflowRun -WorkflowFile $WorkflowFile -FieldArgs $fieldArgs
            return
        } catch {
            if (-not (Get-GithubToken)) { throw }
            Write-Host "dispatch-rc-workflows: gh failed ($($_.Exception.Message)); falling back to REST API"
        }
    }
    Invoke-GithubWorkflowDispatch -WorkflowFile $WorkflowFile -Inputs $Inputs
}

$dispatchNightly = $Nightly -or $All
$dispatchSoak = $LinuxSoakAudit -or $All
$dispatchCleanup = $CleanupCiQueue -or $All
if (-not $dispatchNightly -and -not $dispatchSoak -and -not $dispatchCleanup) {
    $dispatchNightly = $true
    $dispatchSoak = $true
    $dispatchCleanup = $true
}

if ($dispatchCleanup) {
    Write-Host "dispatch-rc-workflows: triggering CI Queue Cleanup on ref=$Ref"
    Start-WorkflowDispatch -WorkflowFile "ci-queue-cleanup.yml"
}

if ($dispatchNightly) {
    $nightlyInputs = @{}
    if ($CheckoutSha) {
        $nightlyInputs.checkout_sha = $CheckoutSha
        Write-Host "dispatch-rc-workflows: triggering Nightly on ref=$Ref checkout_sha=$CheckoutSha"
    } else {
        Write-Host "dispatch-rc-workflows: triggering Nightly on ref=$Ref"
    }
    Start-WorkflowDispatch -WorkflowFile "nightly.yml" -Inputs $nightlyInputs
}

if ($dispatchSoak) {
    Write-Host "dispatch-rc-workflows: triggering Linux Soak Audit on ref=$Ref (SLOT_MS=$SlotMs duration=${DurationMinutes}m min_height=$MinFinalHeight)"
    Start-WorkflowDispatch -WorkflowFile "linux-soak-audit.yml" -Inputs @{
        slot_ms = $SlotMs
        duration_minutes = $DurationMinutes
        min_final_height = $MinFinalHeight
    }
}

$ownerRepo = Get-OwnerRepo
Write-Host "dispatch-rc-workflows: OK - monitor https://github.com/$ownerRepo/actions"
