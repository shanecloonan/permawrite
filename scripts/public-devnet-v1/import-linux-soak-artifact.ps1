# Download Linux soak evidence from a GitHub Actions workflow run (gh or GH_TOKEN/GITHUB_TOKEN).
param(
    [string]$RunId = "",
    [string]$OutputDir = "",
    [string]$SlotMs = "30000",
    [switch]$Json
)
$ErrorActionPreference = "Stop"

$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$RepoRoot = (Resolve-Path (Join-Path $ScriptDir "..\..")).Path
Set-Location $RepoRoot

if (-not $OutputDir) {
    $OutputDir = Join-Path $ScriptDir "evidence"
}
New-Item -ItemType Directory -Force -Path $OutputDir | Out-Null

function Get-GithubToken {
    if ($env:GH_TOKEN) { return $env:GH_TOKEN }
    if ($env:GITHUB_TOKEN) { return $env:GITHUB_TOKEN }
    return ""
}

function Get-OwnerRepo {
    $remote = (git remote get-url origin 2>$null)
    if ($remote -match "github\.com[:/](?<owner>[^/]+)/(?<repo>[^/.]+)(\.git)?$") {
        return @{ Owner = $Matches.owner; Repo = $Matches.repo }
    }
    throw "import-linux-soak-artifact: cannot parse github.com owner/repo from origin remote"
}

$artifactName = "linux-soak-evidence-slot-$SlotMs"

if (Get-Command gh -ErrorAction SilentlyContinue) {
    if (-not $RunId) {
        $RunId = (gh run list --workflow linux-soak-audit.yml --limit 1 --json databaseId --jq '.[0].databaseId').Trim()
        if (-not $RunId) {
            throw "import-linux-soak-artifact: no linux-soak-audit workflow runs found"
        }
    }
    gh run download $RunId --name $artifactName --dir $OutputDir
    if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
} else {
    $token = Get-GithubToken
    if (-not $token) {
        throw "import-linux-soak-artifact: install gh or set GH_TOKEN/GITHUB_TOKEN"
    }
    $ownerRepo = Get-OwnerRepo
    if (-not $RunId) {
        $runsUri = "https://api.github.com/repos/$($ownerRepo.Owner)/$($ownerRepo.Repo)/actions/workflows/linux-soak-audit.yml/runs?per_page=1"
        $runs = Invoke-RestMethod -Uri $runsUri -Headers @{
            Authorization = "Bearer $token"
            Accept = "application/vnd.github+json"
            "User-Agent" = "permawrite-import-linux-soak-artifact"
            "X-GitHub-Api-Version" = "2022-11-28"
        }
        if (-not $runs.workflow_runs -or $runs.workflow_runs.Count -eq 0) {
            throw "import-linux-soak-artifact: no linux-soak-audit workflow runs found"
        }
        $RunId = [string]$runs.workflow_runs[0].id
    }
    $artifactsUri = "https://api.github.com/repos/$($ownerRepo.Owner)/$($ownerRepo.Repo)/actions/runs/$RunId/artifacts?per_page=100"
    $artifacts = Invoke-RestMethod -Uri $artifactsUri -Headers @{
        Authorization = "Bearer $token"
        Accept = "application/vnd.github+json"
        "User-Agent" = "permawrite-import-linux-soak-artifact"
        "X-GitHub-Api-Version" = "2022-11-28"
    }
    $artifact = $artifacts.artifacts | Where-Object { $_.name -eq $artifactName } | Select-Object -First 1
    if (-not $artifact) {
        throw "import-linux-soak-artifact: run $RunId has no artifact named $artifactName"
    }
    $zipPath = Join-Path ([System.IO.Path]::GetTempPath()) "linux-soak-$RunId.zip"
    Invoke-WebRequest -Uri $artifact.archive_download_url -Headers @{
        Authorization = "Bearer $token"
        Accept = "application/vnd.github+json"
        "User-Agent" = "permawrite-import-linux-soak-artifact"
        "X-GitHub-Api-Version" = "2022-11-28"
    } -OutFile $zipPath
    Expand-Archive -LiteralPath $zipPath -DestinationPath $OutputDir -Force
    Remove-Item -LiteralPath $zipPath -Force
}

$imported = Get-ChildItem -LiteralPath $OutputDir -Filter "soak-restart-linux-*.txt" -File |
    Sort-Object LastWriteTime -Descending |
    Select-Object -First 1
if (-not $imported) {
    throw "import-linux-soak-artifact: artifact extracted but no soak-restart-linux-*.txt found under $OutputDir"
}

Write-Host "import-linux-soak-artifact: OK path=$($imported.FullName) run_id=$RunId"
if ($Json) {
    @{
        path = $imported.FullName
        run_id = $RunId
        artifact = $artifactName
    } | ConvertTo-Json -Compress
}
