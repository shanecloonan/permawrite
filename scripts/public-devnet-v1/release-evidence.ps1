# Generate a public-devnet release-candidate evidence checklist.
param(
    [string]$Rpc = "",
    [string]$RpcApiKey = "",
    [string]$OutputPath = "",
    [string]$Operator = "",
    [string]$Notes = "",
    [switch]$RunHealthCheck,
    [switch]$Json,
    [switch]$SkipCiLookup
)
$ErrorActionPreference = "Stop"

$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$RepoRoot = (Resolve-Path (Join-Path $ScriptDir "..\..")).Path
$StatsPath = Join-Path $RepoRoot "CODEBASE_STATS.md"
$ExpectedGenesisId = "454fa5d4a9bd6f59e35cf9ea7e68c096c9a271a92b2ec5931184e7f34a42a005"

function Invoke-GitText {
    param([Parameter(ValueFromRemainingArguments = $true)][string[]]$Args)
    Push-Location $RepoRoot
    try {
        $out = & git @Args 2>$null
        if ($LASTEXITCODE -ne 0) { return "" }
        return ($out -join "`n").Trim()
    } finally {
        Pop-Location
    }
}

function Get-RemoteSlug {
    $remote = Invoke-GitText "remote" "get-url" "origin"
    if ($remote -match "github\.com[:/](?<owner>[^/]+)/(?<repo>[^/.]+)(\.git)?$") {
        return "$($Matches.owner)/$($Matches.repo)"
    }
    return ""
}

function Get-CodebaseStatsTimestamp {
    if (-not (Test-Path $StatsPath)) { return "missing" }
    $line = Select-String -Path $StatsPath -Pattern "^\*\*Generated \(UTC\):\*\* (.+)$" | Select-Object -First 1
    if (-not $line) { return "missing" }
    return $line.Matches[0].Groups[1].Value
}

function Get-CiStatus {
    param([string]$Commit)
    $slug = Get-RemoteSlug
    if (-not $slug) {
        return [pscustomobject]@{ Status = "unknown"; Conclusion = ""; Url = ""; Source = "no github remote" }
    }
    try {
        if (Get-Command gh -ErrorAction SilentlyContinue) {
            $json = gh run list --workflow CI --branch main --limit 10 --json databaseId,headSha,status,conclusion,url 2>$null
            if ($LASTEXITCODE -eq 0 -and $json) {
                $runs = $json | ConvertFrom-Json
                $run = $runs | Where-Object { $_.headSha -eq $Commit } | Select-Object -First 1
                if ($run) {
                    return [pscustomobject]@{ Status = $run.status; Conclusion = $run.conclusion; Url = $run.url; Source = "gh" }
                }
            }
        }
    } catch {}
    try {
        $uri = "https://api.github.com/repos/$slug/actions/workflows/ci.yml/runs?branch=main&per_page=10"
        $resp = Invoke-RestMethod -Uri $uri -Headers @{ "User-Agent" = "permawrite-release-evidence" }
        $run = $resp.workflow_runs | Where-Object { $_.head_sha -eq $Commit } | Select-Object -First 1
        if ($run) {
            return [pscustomobject]@{ Status = $run.status; Conclusion = $run.conclusion; Url = $run.html_url; Source = "github-api" }
        }
    } catch {}
    return [pscustomobject]@{ Status = "unknown"; Conclusion = ""; Url = ""; Source = "not found" }
}

function Query-RpcStatus {
    param([string]$Addr)
    if (-not $Addr) { return $null }
    $parts = $Addr.Split(":")
    if ($parts.Count -lt 2) { throw "release-evidence: -Rpc must be HOST:PORT" }
    $rpcHost = ($parts[0..($parts.Count - 2)] -join ":").Trim("[", "]")
    $port = [int]$parts[$parts.Count - 1]
    $client = New-Object System.Net.Sockets.TcpClient
    $client.Connect($rpcHost, $port)
    $stream = $client.GetStream()
    $writer = New-Object System.IO.StreamWriter($stream)
    $request = '{"jsonrpc":"2.0","method":"get_status","id":1}'
    $writer.WriteLine($request)
    $writer.Flush()
    $reader = New-Object System.IO.StreamReader($stream)
    $line = $reader.ReadLine()
    $client.Close()
    if (-not $line) { throw "release-evidence: empty RPC status response" }
    $json = $line | ConvertFrom-Json
    if ($json.error) { throw "release-evidence: RPC error $($json.error)" }
    return $json.result
}

function Invoke-HealthEvidence {
    if (-not $RunHealthCheck) {
        return [pscustomobject]@{ Status = "not run"; Output = "" }
    }
    try {
        $out = & powershell -NoProfile -File (Join-Path $ScriptDir "health-check.ps1") 2>&1
        $code = $LASTEXITCODE
        return [pscustomobject]@{ Status = $(if ($code -eq 0) { "pass" } else { "fail" }); Output = (($out -join "`n").Trim()) }
    } catch {
        return [pscustomobject]@{ Status = "fail"; Output = "$_" }
    }
}

$head = Invoke-GitText "rev-parse" "HEAD"
$branch = Invoke-GitText "branch" "--show-current"
$dirty = Invoke-GitText "status" "--short"
$dirtyState = if ($dirty) { "dirty" } else { "clean" }
$statsGenerated = Get-CodebaseStatsTimestamp
$ci = if ($SkipCiLookup) {
    [pscustomobject]@{ Status = "unknown"; Conclusion = ""; Url = ""; Source = "skipped" }
} else {
    Get-CiStatus $head
}
$health = Invoke-HealthEvidence
$rpcStatus = Query-RpcStatus $Rpc
$generatedAt = (Get-Date).ToUniversalTime().ToString("o")

$rpcEvidence = if ($rpcStatus) {
    [pscustomobject]@{
        endpoint = $Rpc
        genesis_id = $rpcStatus.chain.genesis_id
        tip_height = $rpcStatus.chain.tip_height
        tip_id = $rpcStatus.chain.tip_id
        listen_addr = $rpcStatus.rpc.listen_addr
        public_bind = $rpcStatus.rpc.public_bind
        auth_enabled = $rpcStatus.rpc.auth_enabled
        current_in_flight = $rpcStatus.rpc.current_in_flight
        max_in_flight = $rpcStatus.rpc.max_in_flight
        p2p_session_count = $rpcStatus.p2p.session_count
        p2p_peer_count = $rpcStatus.p2p.peer_count
        note = ""
    }
} else {
    [pscustomobject]@{
        endpoint = "not provided"
        genesis_id = "unknown"
        tip_height = "unknown"
        tip_id = "unknown"
        listen_addr = "unknown"
        public_bind = "unknown"
        auth_enabled = "unknown"
        current_in_flight = "unknown"
        max_in_flight = "unknown"
        p2p_session_count = "unknown"
        p2p_peer_count = "unknown"
        note = "no RPC endpoint provided"
    }
}

$evidence = [pscustomobject]@{
    schema_version = "release-evidence.v1"
    generated_utc = $generatedAt
    commit = [pscustomobject]@{
        branch = $branch
        head = $head
        working_tree = $dirtyState
        codebase_stats_generated_utc = $statsGenerated
    }
    ci = [pscustomobject]@{
        status = $ci.Status
        conclusion = $ci.Conclusion
        source = $ci.Source
        url = $ci.Url
    }
    chain = [pscustomobject]@{
        expected_genesis_id = $ExpectedGenesisId
    }
    health = [pscustomobject]@{
        status = $health.Status
        output = $health.Output
    }
    rpc = $rpcEvidence
    operator_signoff = [pscustomobject]@{
        operator = $Operator
        threat_model_reviewed = $false
        residual_risks_have_named_owners = $false
        rpc_exposure_approved = $false
        backups_and_restore_rehearsed = $false
        halt_rollback_authority_agreed = $false
        notes = $Notes
    }
}

if ($Json) {
    $jsonText = $evidence | ConvertTo-Json -Depth 8
    if ($OutputPath) {
        Set-Content -Path $OutputPath -Value $jsonText -Encoding utf8
        Write-Host "release-evidence: wrote $OutputPath"
    } else {
        Write-Output $jsonText
    }
    exit 0
}

$lines = New-Object System.Collections.Generic.List[string]
$lines.Add("# Permawrite Release-Candidate Evidence") | Out-Null
$lines.Add("") | Out-Null
$lines.Add("Generated UTC: ``$generatedAt``") | Out-Null
$lines.Add("") | Out-Null
$lines.Add("## Commit And CI") | Out-Null
$lines.Add("") | Out-Null
$lines.Add("- Branch: ``$branch``") | Out-Null
$lines.Add("- Commit: ``$head``") | Out-Null
$lines.Add("- Working tree: ``$dirtyState``") | Out-Null
$lines.Add("- CODEBASE_STATS generated UTC: ``$statsGenerated``") | Out-Null
$lines.Add("- GitHub CI: status=``$($ci.Status)`` conclusion=``$($ci.Conclusion)`` source=``$($ci.Source)``") | Out-Null
if ($ci.Url) { $lines.Add("- GitHub CI URL: $($ci.Url)") | Out-Null }
$lines.Add("") | Out-Null
$lines.Add("## Chain And Health") | Out-Null
$lines.Add("") | Out-Null
$lines.Add("- Expected public-devnet genesis_id: ``$ExpectedGenesisId``") | Out-Null
$lines.Add("- Health check: ``$($health.Status)``") | Out-Null
if ($health.Output) {
    $lines.Add("") | Out-Null
    $lines.Add('```text') | Out-Null
    $lines.Add($health.Output) | Out-Null
    $lines.Add('```') | Out-Null
}
$lines.Add("") | Out-Null
$lines.Add("## RPC Posture") | Out-Null
$lines.Add("") | Out-Null
if ($rpcStatus) {
    $lines.Add("- RPC endpoint checked: ``$Rpc``") | Out-Null
    $lines.Add("- genesis_id: ``$($rpcStatus.chain.genesis_id)``") | Out-Null
    $lines.Add("- tip_height: ``$($rpcStatus.chain.tip_height)``") | Out-Null
    $lines.Add("- tip_id: ``$($rpcStatus.chain.tip_id)``") | Out-Null
    $lines.Add("- rpc.listen_addr: ``$($rpcStatus.rpc.listen_addr)``") | Out-Null
    $lines.Add("- rpc.public_bind: ``$($rpcStatus.rpc.public_bind)``") | Out-Null
    $lines.Add("- rpc.auth_enabled: ``$($rpcStatus.rpc.auth_enabled)``") | Out-Null
    $lines.Add("- rpc.current_in_flight / max_in_flight: ``$($rpcStatus.rpc.current_in_flight)`` / ``$($rpcStatus.rpc.max_in_flight)``") | Out-Null
    $lines.Add("- p2p.session_count / peer_count: ``$($rpcStatus.p2p.session_count)`` / ``$($rpcStatus.p2p.peer_count)``") | Out-Null
} else {
    $lines.Add("- RPC endpoint checked: ``not provided``") | Out-Null
    $lines.Add("- rpc.public_bind: ``unknown``") | Out-Null
    $lines.Add("- rpc.auth_enabled: ``unknown``") | Out-Null
}
$lines.Add("") | Out-Null
$lines.Add("## Operator Sign-Off") | Out-Null
$lines.Add("") | Out-Null
$lines.Add("- Operator: ``$Operator``") | Out-Null
$lines.Add("- Threat model reviewed: ``[ ]``") | Out-Null
$lines.Add("- Residual risks have named owners: ``[ ]``") | Out-Null
$lines.Add("- RPC exposure approved: ``[ ]``") | Out-Null
$lines.Add("- Backups and restore rehearsed: ``[ ]``") | Out-Null
$lines.Add("- Halt/rollback authority agreed: ``[ ]``") | Out-Null
$lines.Add("- Notes: ``$Notes``") | Out-Null
$text = $lines -join "`n"

if ($OutputPath) {
    Set-Content -Path $OutputPath -Value $text -Encoding utf8
    Write-Host "release-evidence: wrote $OutputPath"
} else {
    Write-Output $text
}
