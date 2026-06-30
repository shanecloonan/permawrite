# Verify that GitHub CI is green for the exact release commit.
param(
    [string]$Commit = "",
    [string]$Workflow = "CI",
    [string]$Branch = "main",
    [string]$MockRuns = "",
    [switch]$Wait,
    [int]$TimeoutSeconds = 600,
    [int]$IntervalSeconds = 15,
    [switch]$Json
)
$ErrorActionPreference = "Stop"

$RepoRoot = Resolve-Path (Join-Path $PSScriptRoot "..\..")
Set-Location $RepoRoot

function Invoke-GitText {
    param([Parameter(ValueFromRemainingArguments = $true)][string[]]$Args)
    $output = & git @Args 2>$null
    if ($LASTEXITCODE -ne 0) { return "" }
    return (($output -join "`n").Trim())
}

function Get-RemoteSlug {
    $remote = Invoke-GitText "remote" "get-url" "origin"
    if ($remote -match "github\.com[:/](?<owner>[^/]+)/(?<repo>[^/.]+)(\.git)?$") {
        return "$($Matches.owner)/$($Matches.repo)"
    }
    return ""
}

function ConvertTo-RunList {
    param($Raw)
    if ($null -eq $Raw) { return @() }
    if ($Raw.PSObject.Properties.Name -contains "workflow_runs") {
        return @($Raw.workflow_runs)
    }
    return @($Raw)
}

function Get-RunValue {
    param($Run, [string[]]$Names)
    foreach ($name in $Names) {
        if ($Run.PSObject.Properties.Name -contains $name) {
            return $Run.$name
        }
    }
    return ""
}

function Get-WorkflowQueryName {
    param([string]$Name)
    if ($Name -eq "CI") { return "ci.yml" }
    return $Name
}

function Get-Runs {
    if ($MockRuns) {
        return ConvertTo-RunList (Get-Content -LiteralPath $MockRuns -Raw | ConvertFrom-Json)
    }

    if (Get-Command gh -ErrorAction SilentlyContinue) {
        $previousErrorActionPreference = $ErrorActionPreference
        try {
            $ErrorActionPreference = "Continue"
            $ghJson = & gh run list --workflow $Workflow --branch $Branch --limit 20 --json databaseId,headSha,status,conclusion,url 2>$null
            $ghExitCode = $LASTEXITCODE
            if ($ghExitCode -eq 0 -and $ghJson) {
                return ConvertTo-RunList ($ghJson | ConvertFrom-Json)
            }
        } catch {
            # Unauthenticated gh should not block the public GitHub API fallback.
        } finally {
            $ErrorActionPreference = $previousErrorActionPreference
        }
    }

    $slug = Get-RemoteSlug
    if (-not $slug) {
        throw "release-ci-watch: cannot infer GitHub repository from origin remote"
    }
    $workflowQuery = [System.Uri]::EscapeDataString((Get-WorkflowQueryName $Workflow))
    $branchQuery = [System.Uri]::EscapeDataString($Branch)
    $uri = "https://api.github.com/repos/$slug/actions/workflows/$workflowQuery/runs?branch=$branchQuery&per_page=20"
    $response = Invoke-RestMethod -Uri $uri -Headers @{ "User-Agent" = "permawrite-release-ci-watch" }
    return ConvertTo-RunList $response
}

function Find-CommitRun {
    param([array]$Runs, [string]$HeadCommit)
    foreach ($run in $Runs) {
        $head = Get-RunValue $run @("headSha", "head_sha")
        if ($head -eq $HeadCommit) { return $run }
    }
    return $null
}

function Emit-Result {
    param(
        [string]$State,
        [string]$Conclusion,
        [string]$Url,
        [string]$Source,
        [string]$Message,
        [int]$ExitCode
    )
    if ($Json) {
        [pscustomobject]@{
            commit = $Commit
            workflow = $Workflow
            branch = $Branch
            status = $State
            conclusion = $Conclusion
            url = $Url
            source = $Source
            message = $Message
        } | ConvertTo-Json -Depth 4
    } elseif ($ExitCode -eq 0) {
        Write-Output "release-ci-watch: OK commit=$Commit status=$State conclusion=$Conclusion source=$Source url=$Url"
    } else {
        [Console]::Error.WriteLine("release-ci-watch: $Message")
    }
    exit $ExitCode
}

if (-not $Commit) {
    $Commit = Invoke-GitText "rev-parse" "HEAD"
}
if (-not $Commit) {
    throw "release-ci-watch: unable to determine commit"
}

$deadline = (Get-Date).AddSeconds($TimeoutSeconds)
$source = if ($MockRuns) { "mock" } elseif (Get-Command gh -ErrorAction SilentlyContinue) { "gh-or-github-api" } else { "github-api" }

while ($true) {
    $run = Find-CommitRun (Get-Runs) $Commit
    if ($run) {
        $status = [string](Get-RunValue $run @("status"))
        $conclusion = [string](Get-RunValue $run @("conclusion"))
        $url = [string](Get-RunValue $run @("html_url", "url"))
        if ($status -eq "completed" -and $conclusion -eq "success") {
            Emit-Result -State $status -Conclusion $conclusion -Url $url -Source $source -Message "success" -ExitCode 0
        }
        if (-not $Wait -or $status -eq "completed") {
            Emit-Result -State $status -Conclusion $conclusion -Url $url -Source $source -Message "CI is not green for commit ${Commit}: status=$status conclusion=$conclusion url=$url" -ExitCode 1
        }
    } elseif (-not $Wait) {
        Emit-Result -State "missing" -Conclusion "" -Url "" -Source $source -Message "no CI run found for commit $Commit on branch $Branch workflow $Workflow" -ExitCode 1
    }

    if (-not $Wait -or (Get-Date) -ge $deadline) {
        Emit-Result -State "timeout" -Conclusion "" -Url "" -Source $source -Message "timed out waiting for green CI for commit $Commit" -ExitCode 1
    }
    Start-Sleep -Seconds ([Math]::Max(1, $IntervalSeconds))
}
