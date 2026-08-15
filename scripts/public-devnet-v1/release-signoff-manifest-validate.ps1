# Validate a release-signoff-manifest.v1 JSON decision record.
param(
    [Parameter(Mandatory = $true)][string]$Manifest
)
$ErrorActionPreference = "Stop"

$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$RepoRoot = (Resolve-Path (Join-Path $ScriptDir "..\..")).Path

if (-not (Test-Path -LiteralPath $Manifest -PathType Leaf)) {
    throw "release-signoff-manifest-validate: missing file $Manifest"
}

$doc = Get-Content -LiteralPath $Manifest -Raw | ConvertFrom-Json
$issues = New-Object System.Collections.Generic.List[string]

function Add-Issue {
    param([string]$Message)
    $script:issues.Add($Message) | Out-Null
}

function Read-GenesisEconomy {
    param($Evidence)
    $rel = ""
    if ($Evidence.economy) { $rel = [string]$Evidence.economy.genesis_path }
    $candidates = @()
    if ($rel) {
        $candidates += $rel
        $candidates += (Join-Path $RepoRoot $rel)
    }
    $path = $candidates | Where-Object { $_ -and (Test-Path -LiteralPath $_ -PathType Leaf) } | Select-Object -First 1
    if (-not $path) { return $null }
    $genesis = Get-Content -LiteralPath $path -Raw | ConvertFrom-Json
    $subsidy = 0
    $bond = 0
    if ($genesis.emission -and $null -ne $genesis.emission.subsidy_to_treasury_bps) {
        $subsidy = [int]$genesis.emission.subsidy_to_treasury_bps
    }
    if ($genesis.endowment -and $null -ne $genesis.endowment.min_storage_operator_bond) {
        $bond = [int64]$genesis.endowment.min_storage_operator_bond
    }
    return [pscustomobject]@{
        subsidy_to_treasury_bps = $subsidy
        min_storage_operator_bond = $bond
        path_a_experimental = ($subsidy -eq 0) -or ($bond -eq 0)
    }
}

function Has-Property {
    param($Object, [string]$Name)
    return $null -ne $Object -and $Object.PSObject.Properties.Name -contains $Name
}

function Require-String {
    param($Object, [string]$Name, [string]$Path)
    if (-not (Has-Property $Object $Name) -or -not ([string]$Object.$Name)) {
        Add-Issue "$Path.$Name is required"
    }
}

function Require-Bool {
    param($Object, [string]$Name, [string]$Path)
    if (-not (Has-Property $Object $Name) -or $Object.$Name -isnot [bool]) {
        Add-Issue "$Path.$Name must be boolean"
    }
}

function Validate-GateResult {
    param($Gate, [string]$Path)
    if ($null -eq $Gate) {
        Add-Issue "$Path is required"
        return
    }
    Require-String $Gate "path" $Path
    Require-String $Gate "message" $Path
    if (-not (Has-Property $Gate "status") -or $Gate.status -notin @("pass", "fail", "not provided")) {
        Add-Issue "$Path.status must be pass, fail, or not provided"
    }
}

if ($doc.schema_version -ne "release-signoff-manifest.v1") {
    Add-Issue "schema_version must be release-signoff-manifest.v1"
}
if ($doc.decision -notin @("go", "no-go")) {
    Add-Issue "decision must be go or no-go"
}
Require-String $doc "generated_utc" "manifest"
Require-String $doc "commit" "manifest"

if ($null -eq $doc.release_evidence) {
    Add-Issue "release_evidence is required"
} else {
    Require-String $doc.release_evidence "path" "release_evidence"
    Require-String $doc.release_evidence "commit" "release_evidence"
    if ($doc.release_evidence.schema_version -ne "release-evidence.v1") {
        Add-Issue "release_evidence.schema_version must be release-evidence.v1"
    }
    if ([string]$doc.commit -and [string]$doc.release_evidence.commit -and [string]$doc.commit -ne [string]$doc.release_evidence.commit) {
        Add-Issue "release_evidence.commit must match manifest commit"
    }
}

if ($null -eq $doc.gates) {
    Add-Issue "gates is required"
} else {
    Validate-GateResult $doc.gates.archive_validation "gates.archive_validation"
    Validate-GateResult $doc.gates.artifact_inventory "gates.artifact_inventory"
}

if ($null -eq $doc.approvals) {
    Add-Issue "approvals is required"
} else {
    Require-String $doc.approvals "operator" "approvals"
    Require-String $doc.approvals "reviewer" "approvals"
    Require-String $doc.approvals "notes" "approvals"
    foreach ($name in @(
        "threat_model_reviewed",
        "residual_risks_have_named_owners",
        "rpc_exposure_approved",
        "backups_and_restore_rehearsed",
        "halt_rollback_authority_agreed"
    )) {
        Require-Bool $doc.approvals $name "approvals"
    }
}

$issueCount = 0
if (Has-Property $doc "issues") {
    $issueCount = @($doc.issues).Count
} else {
    Add-Issue "issues array is required"
}

if ($doc.decision -eq "go") {
    if ($null -eq $doc.gates.ci -or $doc.gates.ci.status -ne "completed" -or $doc.gates.ci.conclusion -ne "success") {
        Add-Issue "go decision requires completed successful CI"
    }
    if ($doc.gates.archive_validation.status -ne "pass") {
        Add-Issue "go decision requires passing archive validation"
    }
    if ($doc.gates.artifact_inventory.status -ne "pass") {
        Add-Issue "go decision requires passing artifact inventory validation"
    }
    if ($issueCount -ne 0) {
        Add-Issue "go decision requires empty issues"
    }
    foreach ($name in @(
        "threat_model_reviewed",
        "residual_risks_have_named_owners",
        "rpc_exposure_approved",
        "backups_and_restore_rehearsed",
        "halt_rollback_authority_agreed"
    )) {
        if ($doc.approvals.$name -ne $true) {
            Add-Issue "go decision requires approval '$name'"
        }
    }
    $evidenceRel = [string]$doc.release_evidence.path
    $evidenceCandidates = @()
    if ($evidenceRel) {
        $evidenceCandidates += $evidenceRel
        $evidenceCandidates += (Join-Path $RepoRoot $evidenceRel)
        $manifestDir = Split-Path -Parent (Resolve-Path -LiteralPath $Manifest).Path
        $evidenceCandidates += (Join-Path $manifestDir $evidenceRel)
    }
    $evidencePath = $evidenceCandidates | Where-Object { Test-Path -LiteralPath $_ -PathType Leaf } | Select-Object -First 1
    if (-not $evidencePath) {
        Add-Issue "go decision requires readable release evidence"
    } else {
        $evidence = Get-Content -LiteralPath $evidencePath -Raw | ConvertFrom-Json
        $genesisEconomy = Read-GenesisEconomy $evidence
        if ($null -eq $genesisEconomy) {
            Add-Issue "go decision requires readable genesis at economy.genesis_path"
        } elseif ($genesisEconomy.subsidy_to_treasury_bps -le 0 -or $genesisEconomy.min_storage_operator_bond -le 0 -or $genesisEconomy.path_a_experimental) {
            Add-Issue "go decision requires funded genesis economy (subsidy>0, bond>0, path_a_experimental=false)"
        }
        $nightly = $evidence.nightly
        if ($null -eq $nightly -or [string]$nightly.status -ne "completed" -or [string]$nightly.conclusion -ne "success") {
            Add-Issue "go decision requires completed successful Nightly on bound evidence"
        }
    }
}

if ($issues.Count -gt 0) {
    $issues | ForEach-Object { [Console]::Error.WriteLine("release-signoff-manifest-validate: $_") }
    exit 1
}

Write-Output "release-signoff-manifest-validate: OK"
