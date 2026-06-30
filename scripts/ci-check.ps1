# Mirror .github/workflows/ci.yml locally before pushing to main.
$ErrorActionPreference = "Stop"
Set-Location (Join-Path $PSScriptRoot "..")

$env:CARGO_TERM_COLOR = "always"
$env:RUSTFLAGS = "-D warnings"

function Test-Command($Name) {
    return [bool](Get-Command $Name -ErrorAction SilentlyContinue)
}

foreach ($toolDir in @("C:\msys64\usr\bin", "C:\msys64\mingw64\bin")) {
    if ((Test-Path -LiteralPath $toolDir -PathType Container) -and
        -not (($env:Path -split [System.IO.Path]::PathSeparator) -contains $toolDir)) {
        $env:Path = "$toolDir$([System.IO.Path]::PathSeparator)$env:Path"
    }
}

$missingTools = @()
function Add-MissingCommand($Name, $InstallHint) {
    if (-not (Get-Command $Name -ErrorAction SilentlyContinue)) {
        $script:missingTools += "missing required command '$Name'. $InstallHint"
    }
}

Add-MissingCommand cargo "Install Rust from https://rustup.rs/ and reopen the shell."
Add-MissingCommand rustup "Install Rust from https://rustup.rs/ and reopen the shell."
Add-MissingCommand bash "Install Git Bash, MSYS2, or WSL and reopen the shell."
Add-MissingCommand wasm-pack "Install with: cargo install wasm-pack --locked"
Add-MissingCommand cargo-audit "Install with: cargo install cargo-audit --locked"
$isWindowsHost = [System.Environment]::OSVersion.Platform -eq [System.PlatformID]::Win32NT
if ($isWindowsHost -and -not (Test-Command dlltool)) {
    $missingTools += "missing required Windows build tool 'dlltool.exe'. Install the GNU binutils/mingw toolchain used by the local Rust target before running release tests."
}
if ($missingTools.Count -gt 0) {
    $missingTools | ForEach-Object { [Console]::Error.WriteLine($_) }
    exit 127
}

Write-Host "==> public-devnet scripts"
Get-ChildItem scripts -Filter *.ps1 -Recurse | ForEach-Object {
    $tokens = $null
    $errors = $null
    [System.Management.Automation.Language.Parser]::ParseFile($_.FullName, [ref]$tokens, [ref]$errors) | Out-Null
    if ($errors.Count -gt 0) {
        $errors | ForEach-Object { [Console]::Error.WriteLine("$($_.Extent.File): $_") }
        exit 1
    }
}
Get-ChildItem scripts -Filter *.sh -Recurse | ForEach-Object {
    bash -n $_.FullName
    if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
}
$httpPlan = (powershell -NoProfile -File scripts/public-devnet-v1/recovery-walkthrough.ps1 -PlanOnly -Rpc 127.0.0.1:18731 -Wallet ./alice.json -CommitHash ababab -Peer 127.0.0.1:18780 -ExpectedSha256 cdcd -Prove) -join "`n"
if ($httpPlan -notmatch "restore_mode=http" -or $httpPlan -notmatch "optional sha256 verify" -or $httpPlan -notmatch "only proves when -Prove is set") {
    $httpPlan | ForEach-Object { [Console]::Error.WriteLine($_) }
    exit 1
}
$p2pPlan = (powershell -NoProfile -File scripts/public-devnet-v1/recovery-walkthrough.ps1 -PlanOnly -Rpc 127.0.0.1:18731 -Wallet ./alice.json -CommitHash ababab -DataDir C:\tmp\replica -ExpectedSha256 cdcd) -join "`n"
if ($p2pPlan -notmatch "restore_mode=p2p-inbox" -or $p2pPlan -notmatch "support-bundle -> recovery-plan -> restore") {
    $p2pPlan | ForEach-Object { [Console]::Error.WriteLine($_) }
    exit 1
}
$rehearsalPlan = (powershell -NoProfile -File scripts/public-devnet-v1/participant-rehearsal.ps1 -PlanOnly -Rpc 127.0.0.1:18731 -FaucetWallet ./faucet.json) -join "`n"
if ($rehearsalPlan -notmatch "flow=fund-wallet -> permanence-demo upload/discover/fetch-http/prove/hash-check -> support-bundle" -or $rehearsalPlan -notmatch "public-devnet/test funds only" -or $rehearsalPlan -notmatch "outputs end with support_bundle=<dir>") {
    $rehearsalPlan | ForEach-Object { [Console]::Error.WriteLine($_) }
    exit 1
}
$smokePlan = (powershell -NoProfile -File scripts/public-devnet-v1/participant-rehearsal-smoke.ps1 -PlanOnly -Rpc 127.0.0.1:18731) -join "`n"
if ($smokePlan -notmatch "flow=stop stale mesh -> start-all -> restore/check test faucet -> wait faucet balance -> participant-rehearsal -> stop mesh" -or $smokePlan -notmatch "custom faucet wallets are never overwritten") {
    $smokePlan | ForEach-Object { [Console]::Error.WriteLine($_) }
    exit 1
}
$evidenceMarkdown = powershell -NoProfile -File scripts/public-devnet-v1/release-evidence.ps1 -Operator "ci-smoke" -SkipCiLookup
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
$evidenceText = $evidenceMarkdown -join "`n"
foreach ($required in @("# Permawrite Release-Candidate Evidence", "## Commit And CI", "## RPC Posture", "## Operator Sign-Off")) {
    if (-not $evidenceText.Contains($required)) {
        [Console]::Error.WriteLine("release-evidence.ps1 Markdown output missing '$required'")
        exit 1
    }
}
$evidenceJson = powershell -NoProfile -File scripts/public-devnet-v1/release-evidence.ps1 -Operator "ci-smoke" -Json -SkipCiLookup
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
$evidenceObject = $evidenceJson | ConvertFrom-Json
foreach ($required in @($evidenceObject.schema_version, $evidenceObject.generated_utc, $evidenceObject.commit.head, $evidenceObject.ci.status, $evidenceObject.chain.expected_genesis_id, $evidenceObject.health.status, $evidenceObject.rpc.endpoint, $evidenceObject.rpc.current_in_flight, $evidenceObject.rpc.max_in_flight, $evidenceObject.rpc.p2p_session_count, $evidenceObject.rpc.p2p_peer_count)) {
    if (-not $required) {
        [Console]::Error.WriteLine("release-evidence.ps1 JSON output is missing a required schema field")
        exit 1
    }
}
if ($evidenceObject.schema_version -ne "release-evidence.v1") {
    [Console]::Error.WriteLine("release-evidence.ps1 JSON output has unexpected schema_version")
    exit 1
}
if ($evidenceObject.operator_signoff.operator -ne "ci-smoke") {
    [Console]::Error.WriteLine("release-evidence.ps1 JSON output did not preserve operator sign-off metadata")
    exit 1
}
foreach ($jsonPath in @(
    "docs/release-evidence-v1.schema.json",
    "docs/release-evidence-v1.sample.json",
    "docs/release-signoff-manifest-v1.schema.json",
    "docs/release-signoff-manifest-v1.sample.json"
)) {
    Get-Content $jsonPath -Raw | ConvertFrom-Json | Out-Null
}
$signoffSample = Get-Content "docs/release-signoff-manifest-v1.sample.json" -Raw | ConvertFrom-Json
if ($signoffSample.schema_version -ne "release-signoff-manifest.v1" -or $signoffSample.release_evidence.schema_version -ne "release-evidence.v1" -or $signoffSample.gates.ci.conclusion -ne "success") {
    [Console]::Error.WriteLine("release-signoff-manifest-v1.sample.json has unexpected gate or schema metadata")
    exit 1
}
powershell -NoProfile -File scripts/public-devnet-v1/release-json-schema-validate.ps1 -Schema docs/release-evidence-v1.schema.json -Json docs/release-evidence-v1.sample.json | Out-Null
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
powershell -NoProfile -File scripts/public-devnet-v1/release-json-schema-validate.ps1 -Schema docs/release-signoff-manifest-v1.schema.json -Json docs/release-signoff-manifest-v1.sample.json | Out-Null
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
$schemaValidateDir = Join-Path ([System.IO.Path]::GetTempPath()) ("permawrite-schema-validate-" + [System.Guid]::NewGuid().ToString("N"))
New-Item -ItemType Directory -Force -Path $schemaValidateDir | Out-Null
try {
    $badEvidence = Join-Path $schemaValidateDir "bad-evidence.json"
    $badEvidenceObject = Get-Content "docs/release-evidence-v1.sample.json" -Raw | ConvertFrom-Json
    $badEvidenceObject | Add-Member -NotePropertyName "unexpected_release_field" -NotePropertyValue $true
    $badEvidenceObject | ConvertTo-Json -Depth 12 | Set-Content -LiteralPath $badEvidence -Encoding utf8
    $badEvidenceStdout = Join-Path $schemaValidateDir "bad-evidence.out"
    $badEvidenceStderr = Join-Path $schemaValidateDir "bad-evidence.err"
    $badEvidenceProcess = Start-Process -FilePath "powershell" -ArgumentList @(
        "-NoProfile",
        "-File",
        "scripts/public-devnet-v1/release-json-schema-validate.ps1",
        "-Schema",
        "docs/release-evidence-v1.schema.json",
        "-Json",
        $badEvidence
    ) -Wait -PassThru -NoNewWindow -RedirectStandardOutput $badEvidenceStdout -RedirectStandardError $badEvidenceStderr
    if ($badEvidenceProcess.ExitCode -eq 0) {
        [Console]::Error.WriteLine("release-json-schema-validate.ps1 accepted an unexpected release evidence field")
        exit 1
    }
    $global:LASTEXITCODE = 0
} finally {
    Remove-Item -Recurse -Force $schemaValidateDir -ErrorAction SilentlyContinue
}
powershell -NoProfile -File scripts/public-devnet-v1/release-signoff-manifest-validate.ps1 -Manifest docs/release-signoff-manifest-v1.sample.json | Out-Null
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
$signoffValidateDir = Join-Path ([System.IO.Path]::GetTempPath()) ("permawrite-signoff-validate-" + [System.Guid]::NewGuid().ToString("N"))
New-Item -ItemType Directory -Force -Path $signoffValidateDir | Out-Null
try {
    $badSignoff = Join-Path $signoffValidateDir "bad-signoff.json"
    $badSignoffObject = Get-Content "docs/release-signoff-manifest-v1.sample.json" -Raw | ConvertFrom-Json
    $badSignoffObject.gates.ci.conclusion = "failure"
    $badSignoffObject | ConvertTo-Json -Depth 12 | Set-Content -LiteralPath $badSignoff -Encoding utf8
    $badSignoffStdout = Join-Path $signoffValidateDir "bad-signoff.out"
    $badSignoffStderr = Join-Path $signoffValidateDir "bad-signoff.err"
    $badSignoffProcess = Start-Process -FilePath "powershell" -ArgumentList @(
        "-NoProfile",
        "-File",
        "scripts/public-devnet-v1/release-signoff-manifest-validate.ps1",
        "-Manifest",
        $badSignoff
    ) -Wait -PassThru -NoNewWindow -RedirectStandardOutput $badSignoffStdout -RedirectStandardError $badSignoffStderr
    if ($badSignoffProcess.ExitCode -eq 0) {
        [Console]::Error.WriteLine("release-signoff-manifest-validate.ps1 accepted a go manifest with failing CI")
        exit 1
    }
    $global:LASTEXITCODE = 0
} finally {
    Remove-Item -Recurse -Force $signoffValidateDir -ErrorAction SilentlyContinue
}
$ciWatchDir = Join-Path ([System.IO.Path]::GetTempPath()) ("permawrite-ci-watch-" + [System.Guid]::NewGuid().ToString("N"))
New-Item -ItemType Directory -Force -Path $ciWatchDir | Out-Null
try {
    $ciWatchCommit = "0123456789abcdef0123456789abcdef01234567"
    $ciWatchSuccess = Join-Path $ciWatchDir "success.json"
    @"
[
  {"headSha":"$ciWatchCommit","status":"completed","conclusion":"success","url":"https://example.invalid/success"},
  {"headSha":"ffffffffffffffffffffffffffffffffffffffff","status":"completed","conclusion":"success","url":"https://example.invalid/wrong"}
]
"@ | Set-Content -LiteralPath $ciWatchSuccess -Encoding utf8
    powershell -NoProfile -File scripts/public-devnet-v1/release-ci-watch.ps1 -Commit $ciWatchCommit -MockRuns $ciWatchSuccess | Out-Null
    if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

    $ciWatchFailure = Join-Path $ciWatchDir "failure.json"
    @"
[
  {"headSha":"$ciWatchCommit","status":"completed","conclusion":"failure","url":"https://example.invalid/failure"}
]
"@ | Set-Content -LiteralPath $ciWatchFailure -Encoding utf8
    $ciWatchFailureStdout = Join-Path $ciWatchDir "failure.out"
    $ciWatchFailureStderr = Join-Path $ciWatchDir "failure.err"
    $ciWatchFailureProcess = Start-Process -FilePath "powershell" -ArgumentList @(
        "-NoProfile",
        "-File",
        "scripts/public-devnet-v1/release-ci-watch.ps1",
        "-Commit",
        $ciWatchCommit,
        "-MockRuns",
        $ciWatchFailure
    ) -Wait -PassThru -NoNewWindow -RedirectStandardOutput $ciWatchFailureStdout -RedirectStandardError $ciWatchFailureStderr
    if ($ciWatchFailureProcess.ExitCode -eq 0) {
        [Console]::Error.WriteLine("release-ci-watch.ps1 accepted failing CI for the exact commit")
        exit 1
    }
    $global:LASTEXITCODE = 0
    $ciWatchRateLimitedStdout = Join-Path $ciWatchDir "rate-limited.out"
    $ciWatchRateLimitedStderr = Join-Path $ciWatchDir "rate-limited.err"
    $ciWatchRateLimitedProcess = Start-Process -FilePath "powershell" -ArgumentList @(
        "-NoProfile",
        "-File",
        "scripts/public-devnet-v1/release-ci-watch.ps1",
        "-Commit",
        $ciWatchCommit,
        "-MockApiErrorStatus",
        "403",
        "-Json"
    ) -Wait -PassThru -NoNewWindow -RedirectStandardOutput $ciWatchRateLimitedStdout -RedirectStandardError $ciWatchRateLimitedStderr
    if ($ciWatchRateLimitedProcess.ExitCode -eq 0) {
        [Console]::Error.WriteLine("release-ci-watch.ps1 accepted rate-limited GitHub API as green")
        exit 1
    }
    $rateLimitedObject = Get-Content -LiteralPath $ciWatchRateLimitedStdout -Raw | ConvertFrom-Json
    if ($rateLimitedObject.status -ne "rate_limited") {
        [Console]::Error.WriteLine("release-ci-watch.ps1 did not emit structured rate_limited JSON")
        exit 1
    }
    $global:LASTEXITCODE = 0
    $ciWatchAuthStdout = Join-Path $ciWatchDir "auth-api.out"
    $ciWatchAuthStderr = Join-Path $ciWatchDir "auth-api.err"
    $previousGhToken = $env:GH_TOKEN
    try {
        $env:GH_TOKEN = "ci-watch-test-token"
        $ciWatchAuthProcess = Start-Process -FilePath "powershell" -ArgumentList @(
            "-NoProfile",
            "-File",
            "scripts/public-devnet-v1/release-ci-watch.ps1",
            "-Commit",
            $ciWatchCommit,
            "-MockApiErrorStatus",
            "500",
            "-Json"
        ) -Wait -PassThru -NoNewWindow -RedirectStandardOutput $ciWatchAuthStdout -RedirectStandardError $ciWatchAuthStderr
    } finally {
        $env:GH_TOKEN = $previousGhToken
    }
    if ($ciWatchAuthProcess.ExitCode -eq 0) {
        [Console]::Error.WriteLine("release-ci-watch.ps1 accepted mocked GitHub API failure as green")
        exit 1
    }
    $authText = Get-Content -LiteralPath $ciWatchAuthStdout -Raw
    $authObject = $authText | ConvertFrom-Json
    if ($authObject.status -ne "api_error" -or $authObject.source -notmatch "auth") {
        [Console]::Error.WriteLine("release-ci-watch.ps1 did not report authenticated API fallback source")
        exit 1
    }
    if ($authText.Contains("ci-watch-test-token")) {
        [Console]::Error.WriteLine("release-ci-watch.ps1 leaked GH_TOKEN in JSON output")
        exit 1
    }
    $global:LASTEXITCODE = 0
} finally {
    Remove-Item -Recurse -Force $ciWatchDir -ErrorAction SilentlyContinue
}
$supportPlan = powershell -NoProfile -File scripts/public-devnet-v1/support-bundle.ps1 -Rpc "127.0.0.1:18731" -ReleaseEvidence docs/release-evidence-v1.sample.json -PlanOnly
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
if (-not (($supportPlan -join "`n").Contains("valid release-evidence.v1"))) {
    [Console]::Error.WriteLine("support-bundle.ps1 did not validate release-evidence.v1 in plan mode")
    exit 1
}
$dryRun = powershell -NoProfile -File scripts/public-devnet-v1/release-signoff-dry-run.ps1
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
if (-not (($dryRun -join "`n").Contains("release-signoff-dry-run: OK"))) {
    [Console]::Error.WriteLine("release-signoff-dry-run.ps1 did not complete successfully")
    exit 1
}
$checksumRows = powershell -NoProfile -File scripts/public-devnet-v1/artifact-checksums.ps1 docs/release-evidence-v1.sample.json docs/RELEASE_ARTIFACT_INVENTORY_TEMPLATE.md
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
$checksumText = $checksumRows -join "`n"
foreach ($required in @("| Path | SHA-256 | Bytes |", "release-evidence-v1.sample.json", "RELEASE_ARTIFACT_INVENTORY_TEMPLATE.md")) {
    if (-not $checksumText.Contains($required)) {
        [Console]::Error.WriteLine("artifact-checksums.ps1 output missing '$required'")
        exit 1
    }
}
$archivePlan = powershell -NoProfile -File scripts/public-devnet-v1/release-archive-dry-run.ps1 -PlanOnly -ReleaseEvidenceJson docs/release-evidence-v1.sample.json
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
if (-not (($archivePlan -join "`n").Contains("release-archive-dry-run: PLAN OK"))) {
    [Console]::Error.WriteLine("release-archive-dry-run.ps1 plan mode did not complete successfully")
    exit 1
}
$archiveDir = Join-Path ([System.IO.Path]::GetTempPath()) ("permawrite-archive-" + [System.Guid]::NewGuid().ToString("N"))
try {
    $archiveRun = powershell -NoProfile -File scripts/public-devnet-v1/release-archive-dry-run.ps1 -OutputDir $archiveDir -ReleaseEvidenceJson docs/release-evidence-v1.sample.json
    if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
    $archiveText = $archiveRun -join "`n"
    if ($archiveText -notmatch "release-archive-dry-run: OK path=(?<path>.+)$") {
        [Console]::Error.WriteLine("release-archive-dry-run.ps1 did not report an output path")
        exit 1
    }
    $archiveRoot = $Matches.path.Trim()
    foreach ($requiredPath in @(
        "README.md",
        "network/genesis.json",
        "network/checksums.sha256",
        "docs/SECURITY.md",
        "docs/OPERATORS.md",
        "evidence/release-evidence.json",
        "evidence/checksums.sha256"
    )) {
        if (-not (Test-Path -LiteralPath (Join-Path $archiveRoot $requiredPath) -PathType Leaf)) {
            [Console]::Error.WriteLine("release-archive-dry-run.ps1 missing staged artifact '$requiredPath'")
            exit 1
        }
    }
    powershell -NoProfile -File scripts/public-devnet-v1/release-archive-validate.ps1 -ArchiveDir $archiveRoot -AllowDryRun | Out-Null
    if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

    $signoffCommit = "0000000000000000000000000000000000000000"
    $signoffCiSuccess = Join-Path $archiveDir "signoff-ci-success.json"
    @"
[
  {"headSha":"$signoffCommit","status":"completed","conclusion":"success","url":"https://example.invalid/signoff-success"}
]
"@ | Set-Content -LiteralPath $signoffCiSuccess -Encoding utf8
    $signoffInventory = Join-Path $archiveDir "signoff-inventory.md"
    @'
# Inventory

- Path or URL: ./artifact
- SHA-256: 0000000000000000000000000000000000000000000000000000000000000000
- Reviewer: ci-smoke

Decision: go
'@ | Set-Content -LiteralPath $signoffInventory -Encoding utf8
    $signoffJson = powershell -NoProfile -File scripts/public-devnet-v1/release-signoff-manifest.ps1 `
        -ReleaseEvidenceJson docs/release-evidence-v1.sample.json `
        -ArchiveDir $archiveRoot `
        -Inventory $signoffInventory `
        -CiMockRuns $signoffCiSuccess `
        -Decision go `
        -Operator ci-smoke `
        -Reviewer ci-reviewer `
        -AllowDryRun `
        -ThreatModelReviewed `
        -ResidualRisksHaveOwners `
        -RpcExposureApproved `
        -BackupsRestoreRehearsed `
        -HaltRollbackAuthorityAgreed
    if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
    $signoffObject = $signoffJson | ConvertFrom-Json
    if ($signoffObject.schema_version -ne "release-signoff-manifest.v1" -or $signoffObject.decision -ne "go" -or $signoffObject.issues.Count -ne 0) {
        [Console]::Error.WriteLine("release-signoff-manifest.ps1 did not emit a clean go manifest")
        exit 1
    }
    $auditJson = powershell -NoProfile -File scripts/public-devnet-v1/release-audit-packet.ps1 `
        -ReleaseEvidenceJson docs/release-evidence-v1.sample.json `
        -SignoffManifest docs/release-signoff-manifest-v1.sample.json `
        -ArchiveDir $archiveRoot `
        -Inventory $signoffInventory `
        -CiMockRuns $signoffCiSuccess `
        -AllowDryRun `
        -Json
    if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
    $auditObject = $auditJson | ConvertFrom-Json
    if ($auditObject.schema_version -ne "release-audit-packet.v1" -or $auditObject.decision -ne "go") {
        [Console]::Error.WriteLine("release-audit-packet.ps1 did not emit a clean go packet")
        exit 1
    }
    $signoffCiFailure = Join-Path $archiveDir "signoff-ci-failure.json"
    @"
[
  {"headSha":"$signoffCommit","status":"completed","conclusion":"failure","url":"https://example.invalid/signoff-failure"}
]
"@ | Set-Content -LiteralPath $signoffCiFailure -Encoding utf8
    $signoffFailureStdout = Join-Path $archiveDir "signoff-failure.out"
    $signoffFailureStderr = Join-Path $archiveDir "signoff-failure.err"
    $signoffFailureProcess = Start-Process -FilePath "powershell" -ArgumentList @(
        "-NoProfile",
        "-File",
        "scripts/public-devnet-v1/release-signoff-manifest.ps1",
        "-ReleaseEvidenceJson",
        "docs/release-evidence-v1.sample.json",
        "-ArchiveDir",
        $archiveRoot,
        "-Inventory",
        $signoffInventory,
        "-CiMockRuns",
        $signoffCiFailure,
        "-Decision",
        "go",
        "-Operator",
        "ci-smoke",
        "-Reviewer",
        "ci-reviewer",
        "-AllowDryRun",
        "-ThreatModelReviewed",
        "-ResidualRisksHaveOwners",
        "-RpcExposureApproved",
        "-BackupsRestoreRehearsed",
        "-HaltRollbackAuthorityAgreed"
    ) -Wait -PassThru -NoNewWindow -RedirectStandardOutput $signoffFailureStdout -RedirectStandardError $signoffFailureStderr
    if ($signoffFailureProcess.ExitCode -eq 0) {
        [Console]::Error.WriteLine("release-signoff-manifest.ps1 accepted failing CI for a go decision")
        exit 1
    }
    $global:LASTEXITCODE = 0

    Add-Content -LiteralPath (Join-Path $archiveRoot "network/genesis.json") -Value "corrupt"
    $archiveValidateStdout = Join-Path $archiveDir "archive-validate.out"
    $archiveValidateStderr = Join-Path $archiveDir "archive-validate.err"
    $archiveValidateProcess = Start-Process -FilePath "powershell" -ArgumentList @(
        "-NoProfile",
        "-File",
        "scripts/public-devnet-v1/release-archive-validate.ps1",
        "-ArchiveDir",
        $archiveRoot,
        "-AllowDryRun"
    ) -Wait -PassThru -NoNewWindow -RedirectStandardOutput $archiveValidateStdout -RedirectStandardError $archiveValidateStderr
    if ($archiveValidateProcess.ExitCode -eq 0) {
        [Console]::Error.WriteLine("release-archive-validate.ps1 accepted a corrupted checksum")
        exit 1
    }
    $global:LASTEXITCODE = 0
} finally {
    Remove-Item -Recurse -Force $archiveDir -ErrorAction SilentlyContinue
}
$inventoryDir = Join-Path ([System.IO.Path]::GetTempPath()) ("permawrite-inventory-" + [System.Guid]::NewGuid().ToString("N"))
New-Item -ItemType Directory -Force -Path $inventoryDir | Out-Null
try {
    $validInventory = Join-Path $inventoryDir "valid.md"
    @'
# Inventory

- Path or URL: ./artifact
- SHA-256: 0000000000000000000000000000000000000000000000000000000000000000
- Reviewer: ci-smoke

Decision: go
'@ | Set-Content -Path $validInventory -Encoding utf8
    powershell -NoProfile -File scripts/public-devnet-v1/artifact-inventory-validate.ps1 $validInventory | Out-Null
    if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

    $invalidInventory = Join-Path $inventoryDir "invalid.md"
    @'
# Inventory

- Path or URL:
- SHA-256:
- Reviewer:

Decision:
'@ | Set-Content -Path $invalidInventory -Encoding utf8
    $invalidStdout = Join-Path $inventoryDir "invalid.out"
    $invalidStderr = Join-Path $inventoryDir "invalid.err"
    $invalidProcess = Start-Process -FilePath "powershell" -ArgumentList @(
        "-NoProfile",
        "-File",
        "scripts/public-devnet-v1/artifact-inventory-validate.ps1",
        $invalidInventory
    ) -Wait -PassThru -NoNewWindow -RedirectStandardOutput $invalidStdout -RedirectStandardError $invalidStderr
    $invalidExit = $invalidProcess.ExitCode
    if ($invalidExit -eq 0) {
        [Console]::Error.WriteLine("artifact-inventory-validate.ps1 accepted an incomplete inventory")
        exit 1
    }
    $global:LASTEXITCODE = 0
} finally {
    Remove-Item -Recurse -Force $inventoryDir -ErrorAction SilentlyContinue
}

Write-Host "==> rustfmt"
cargo fmt --all --check
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

Write-Host "==> clippy"
cargo clippy --workspace --all-targets --all-features -- -D warnings
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

Write-Host "==> build mfnd + mfn-storage-operator (mfn-cli integration tests)"
cargo build -p mfn-node --bin mfnd --release
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
cargo build -p mfn-storage-operator --bin mfn-storage-operator --release
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

Write-Host "==> test (release)"
cargo test --workspace --release -- --test-threads=4
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

Write-Host "==> wasm32 build"
rustup target add wasm32-unknown-unknown
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
cargo build -p mfn-wasm --target wasm32-unknown-unknown --release --features wasm-full
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
cargo test -p mfn-wasm --release --features wasm-full
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
wasm-pack --log-level warn build mfn-wasm --target web --out-dir demo/web/pkg --release --features wasm-full
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

Write-Host "==> cargo audit"
cargo audit
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

Write-Host "ci-check: OK"
