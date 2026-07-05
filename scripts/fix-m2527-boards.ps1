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

$docs = Read-GitBlobText "001e2c6:docs/AGENTS.md"
if ($docs -match '^# Agent Coordination \(master board\)') { throw "bad docs/AGENTS.md base" }
if ($docs -notmatch 'M2.5.24') {
    $docs = $docs -replace '(- \[x\] M2.5.22[^\n]+\r?\n)', "`$1- [x] M2.5.24 - ``validate-rc-helper-scripts`` smoke in ``ci-check`` (``001e2c6``).`n- [x] M2.5.26 - UTF-8 guard for agent boards in validate-workflow-encoding (``a417f1e``).`n- [x] M2.5.27 - restore per-lane checklists + board sync (__COMMIT__).`n"
}
if ($docs -notmatch 'M7.11') {
    $docs = $docs -replace '(- \[x\] M7.10[^\n]+\r?\n)', "`$1- [x] M7.11 - STORAGE_ACCESSIBILITY.md section 0 (``bb9600b``).`n"
}
$lane6 = @"

- [x] **M5.46** - combined-inflow emission CI tier complete (``1232506``).
- [x] **M5.47** - 256-block equivocation combined-inflow + 1M curve in default CI (``db06c78``).
- [x] **M5.48** - emission deep-sim tier closure; 2048 CLSAG + 100k ``apply_block`` stay nightly (``77f2fe1``).
"@
if ($docs -notmatch 'M5.48') {
    $docs = $docs -replace '(### Idle[^\n]+\r?\n\r?\n)', "`$1$lane6"
}
$docs = $docs -replace 'this commit', '__COMMIT__'
Write-Utf8 "docs/AGENTS.md" $docs

$three = @"
# 3agent (legacy name - lanes 1-3)

> **Unified coordination:** [``AGENTS.md``](./AGENTS.md) (master board) and [``docs/AGENTS.md``](./docs/AGENTS.md) (per-lane checklists).  
> Lanes **4-6** are overflow lanes for work the RC track does not own (M5 hardening, privacy surface, permanence depth).

## Done / Doing / Next (mandatory)

Every lane agent **must announce** what they finished, what they are doing, and what they will do next - in chat and on the boards. Full protocol: [``AGENTS.md`` Agent announcement protocol](./AGENTS.md#agent-announcement-protocol-mandatory).

| When | Announce |
| --- | --- |
| Session start | Done + Doing + Next **before** coding |
| Claim unit | Update quick mirror **Doing** column + master board |
| Unit complete | Refresh **Done**; set **Next** handoff |
| Before push | Board matches the commit about to land |

## Lanes 1-3 quick mirror

| Lane | Done | Doing | Next |
| --- | --- | --- | --- |
| **1** RC core | M2.5.19 GHA rehearsal gates (``main``) | - | Nightly #56 after green CI (B-06) |
| **2** RC ops | M2.5.27 docs mirror (__COMMIT__); M2.5.26 (``a417f1e``); M2.5.24 (``001e2c6``) | - | B-05 soak evidence |
| **3** RC onboarding | M7.11 STORAGE_ACCESSIBILITY section 0 (``bb9600b``) | - | Monitor Nightly #56 smokes (B-06) |

**RC gate:** green CI on ``main`` -> auto-dispatch **Nightly #56** + **Linux Soak Audit** when evidence missing (``ci.yml``).

**Do not duplicate:** lanes 4-6 - see master board before starting M5/protocol/privacy-surface work. Lane 6 emission sim promotions are **closed** at M5.48.

Update [``AGENTS.md``](./AGENTS.md) instead of growing this file.
"@
Write-Utf8 "3agent.md" $three

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
