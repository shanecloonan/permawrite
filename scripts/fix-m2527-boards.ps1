# M2.5.27: restore docs/AGENTS.md lane checklists; sync master board SHAs (UTF-8 safe).
param([switch]$Commit)
$ErrorActionPreference = "Stop"
$utf8 = New-Object System.Text.UTF8Encoding $false
$root = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
Set-Location $root

function Read-GitBlobText {
    param([string]$RevPath)
    $hash = (& git rev-parse $RevPath).Trim()
    $tmp = Join-Path $env:TEMP "permawrite-blob-$hash.bin"
    if (Test-Path $tmp) { Remove-Item $tmp -Force }
    $psi = New-Object System.Diagnostics.ProcessStartInfo
    $psi.FileName = "git"
    $psi.Arguments = "cat-file blob $hash"
    $psi.RedirectStandardOutput = $true
    $psi.UseShellExecute = $false
    $p = [Diagnostics.Process]::Start($psi)
    $fs = [IO.File]::Create($tmp)
    $p.StandardOutput.BaseStream.CopyTo($fs)
    $fs.Close()
    $p.WaitForExit()
    if ($p.ExitCode -ne 0) { throw "git cat-file failed for $RevPath" }
    $bytes = [IO.File]::ReadAllBytes($tmp)
    Remove-Item $tmp -Force
    if ($bytes.Length -ge 2 -and $bytes[0] -eq 0xFF -and $bytes[1] -eq 0xFE) {
        return [Text.Encoding]::Unicode.GetString($bytes)
    }
    if ($bytes.Length -ge 2 -and $bytes[0] -eq 0xFE -and $bytes[1] -eq 0xFF) {
        return [Text.Encoding]::BigEndianUnicode.GetString($bytes)
    }
    if (($bytes | Where-Object { $_ -eq 0 }).Count -ge 3) {
        return [Text.Encoding]::Unicode.GetString($bytes)
    }
    return [Text.Encoding]::UTF8.GetString($bytes)
}

function Write-Utf8 {
    param([string]$Path, [string]$Text)
    [IO.File]::WriteAllText((Join-Path $root $Path), $Text, $utf8)
}

$agentsHead = Read-GitBlobText "HEAD:AGENTS.md"
if ($agentsHead -match 'M2\.5\.31') {
    Write-Host "AGENTS.md: HEAD already at M2.5.31+; skipping stale M2.5.27 template"
} else {
    $agents = Read-GitBlobText "5680ff9:AGENTS.md"
    $agents = $agents -replace '(?s)## CI gate \(2026-07-04\).*?## Current board', @"
## CI gate (2026-07-05)

**M2.5.27** (__COMMIT__) - wait for green GHA CI before next push; **B-06** Nightly #56 + **B-05** Linux soak follow.

## Current board
"@
    $agents = $agents -replace '(?s)\| \*\*2\*\* \|[^\n]+\n', "| **2** | M2.5.27 docs/AGENTS.md mirror restore | **Done** - __COMMIT__ | B-05 soak evidence |`n"
    $agents = $agents -replace '(?s)\| \*\*3\*\* \|[^\n]+\n', "| **3** | M7.11 STORAGE_ACCESSIBILITY section 0 | **Done** - ``bb9600b`` | Monitor Nightly #56 (B-06) |`n"
    $agents = $agents -replace '(?s)\| \*\*6\*\* \|[^\n]+\n', "| **6** | M5.48 emission deep-sim tier closure | **Done** - ``77f2fe1`` | B-05 / B-06 monitor |`n"
    $agents = $agents -replace '(?s)## Recently completed\r?\n\r?\n.*?(?=\r?\n---\r?\n\r?\n## Legacy name)', @"
## Recently completed

- **M2.5.27** (__COMMIT__) - restore ``docs/AGENTS.md`` per-lane checklists; sync master board (lane 2).
- **M2.5.26** (``a417f1e``) - UTF-8 guard for agent boards in validate-workflow-encoding (lane 2).
- **M2.5.24** (``001e2c6``) - ``validate-rc-helper-scripts`` smoke in ``ci-check`` (lane 2).
- **M7.11** (``bb9600b``) - STORAGE_ACCESSIBILITY.md section 0 (lane 3).
- **M5.48** (``77f2fe1``) - emission deep-sim tier closure (lane 6).
- **M5.47** (``db06c78``) - 256-block equivocation + 1M curve in default CI (lane 6).
- **M5.46** (``1232506``) - combined-inflow emission CI tier complete (lane 6).

"@
    Write-Utf8 "AGENTS.md" $agents
}

$docs = Read-GitBlobText "HEAD:docs/AGENTS.md"
if ($docs -notmatch 'M2\.5\.31') {
    throw "docs/AGENTS.md on HEAD missing M2.5.31; land lane-1 unit before running fix-m2527-boards"
}
$docs = $docs -replace 'Nightly #56', 'Nightly #57'
$docs = $docs -replace '\(e0a7ebd\)\.', '(`001e2c6`).'
if ($docs -notmatch 'M2\.5\.26') {
    $docs = $docs -replace '(- \[x\] M2\.5\.24[^\n]+\r?\n)', "`$1- [x] M2.5.26 - UTF-8 guard for agent boards in validate-workflow-encoding (``c71e9c3``).`n- [x] M2.5.27 - restore per-lane checklists + board sync (``e0a7ebd``).`n- [x] M2.5.28 - extend ``validate-rc-helper-scripts`` for boards + ci-check entrypoints (``dc2e032``).`n- [x] M2.5.29 - ``.gitattributes`` UTF-8 pins for boards (``4bd43f2``).`n- [x] M2.5.30 - bash validate-workflow-encoding guard path parity (``2eb8417``).`n"
}
$docs = $docs -replace 'Idle - monitor Nightly #57 after M5\.43 lands', 'Idle - monitor Nightly #57 (B-06)'
$docs = $docs -replace '\| B-06 \| Nightly #57 green \| 1 \| Blocks RC sign-off \|', '| B-06 | Nightly #57 green | 1 | Blocks RC sign-off (Nightly #56 partial) |'
Write-Utf8 "docs/AGENTS.md" $docs

# 3agent.md is maintained by lane agents; do not overwrite from stale template.

& (Join-Path $root "scripts/validate-workflow-encoding.ps1")
if ($LASTEXITCODE -ne 0) { throw "validate-workflow-encoding failed" }

if ($Commit) {
    git add AGENTS.md docs/AGENTS.md 3agent.md scripts/fix-m2527-boards.ps1
    git commit -m "M2.5.27: restore docs/AGENTS.md lane checklists; sync agent boards to landed SHAs."
    $sha = (git rev-parse --short HEAD)
    foreach ($f in @("AGENTS.md", "docs/AGENTS.md", "3agent.md")) {
        $t = [IO.File]::ReadAllText((Join-Path $root $f), [Text.Encoding]::UTF8).Replace('__COMMIT__', $sha)
        [IO.File]::WriteAllText((Join-Path $root $f), $t, $utf8)
    }
    git add AGENTS.md docs/AGENTS.md 3agent.md
    git commit -m "M2.5.27: board SHA handoff for landed unit."
    Write-Host "landed $(git rev-parse --short HEAD); boards cite $(git rev-parse --short HEAD~1)"
}

Write-Host "fix-m2527-boards: OK"
