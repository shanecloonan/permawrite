$ErrorActionPreference = "Stop"
$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
$utf8 = New-Object System.Text.UTF8Encoding $false
$masterSrc = Join-Path $repoRoot "_agents_utf8.md"
if (-not (Test-Path $masterSrc)) { cmd /c "git cat-file -p 6430a34:AGENTS.md > _agents_utf8.md" }
$lines = [IO.File]::ReadAllLines($masterSrc, $utf8)
$sw = New-Object System.IO.StreamWriter((Join-Path $repoRoot "AGENTS.md"), $false, $utf8)
$skip = $false
foreach ($line in $lines) {
  if ($line -match '^## CI gate') { $sw.WriteLine($line); $sw.WriteLine(''); $sw.WriteLine('**M2.5.26** (this commit) - wait for green GHA CI before next push; **B-06** Nightly #56 RC gate follows.'); continue }
  if ($line -match '^\*\*M5\.45\*\*') { continue }
  if ($line -match '^\| \*\*6\*\* \| M5\.45') { $sw.WriteLine('| **6** | M5.48 emission deep-sim tier closure | **Done** - `77f2fe1` | B-06 Nightly #56 |'); continue }
  if ($line -match '^\| \*\*2\*\* \| M2\.5\.23') { $sw.WriteLine('| **2** | M2.5.26 agent board UTF-8 guard | **Done** - this commit | B-05 soak evidence |'); continue }
  if ($line -eq '## Recently completed') {
    $sw.WriteLine($line); $sw.WriteLine('')
    $sw.WriteLine('- **M2.5.26** (this commit) - UTF-8 guard for AGENTS.md boards in validate-workflow-encoding (lane 2).')
    $sw.WriteLine('- **M5.48** (`77f2fe1`) - emission deep-sim tier closure; 2048-block CLSAG + 100k empty apply_block stay nightly (lane 6).')
    $sw.WriteLine('- **M2.5.24** (`001e2c6`) - validate-rc-helper-scripts smoke in ci-check (lane 2).')
    $sw.WriteLine('- **M5.47** (`db06c78`) - 256-block equivocation + 1M curve in default CI (lane 6).')
    $skip = $true; continue
  }
  if ($skip -and $line -match '^- \*\*M') { continue }
  if ($skip -and $line -eq '---') { $skip = $false }
  $sw.WriteLine($line)
}
$sw.Close()
Write-Host "AGENTS.md OK"