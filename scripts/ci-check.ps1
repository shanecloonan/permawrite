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
Add-MissingCommand python "Install Python 3 and ensure python is on PATH."
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

Write-Host "==> workflow YAML encoding (UTF-8)"
powershell -NoProfile -File scripts/validate-workflow-encoding.ps1 | Out-Null
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

Write-Host "==> RC helper scripts smoke"
powershell -NoProfile -File scripts/validate-rc-helper-scripts.ps1 | Out-Null
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

Write-Host "==> public-devnet scripts"
$schemaVenv = Join-Path ([System.IO.Path]::GetTempPath()) ("permawrite-release-schema-venv-" + [System.Guid]::NewGuid().ToString("N"))
python -m venv $schemaVenv
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
$schemaPythonCandidates = @(
    (Join-Path $schemaVenv "Scripts\python.exe"),
    (Join-Path $schemaVenv "bin\python.exe"),
    (Join-Path $schemaVenv "bin\python")
)
$schemaPython = $schemaPythonCandidates | Where-Object { Test-Path -LiteralPath $_ -PathType Leaf } | Select-Object -First 1
if (-not $schemaPython) {
    [Console]::Error.WriteLine("release schema validator venv did not contain a Python executable")
    exit 1
}
& $schemaPython -m pip install --disable-pip-version-check --require-hashes -r scripts/public-devnet-v1/requirements-release-schema.txt
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
& $schemaPython -c "import importlib.metadata; assert importlib.metadata.version('jsonschema') == '4.17.3'"
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
$env:PERMAWRITE_RELEASE_SCHEMA_PYTHON = $schemaPython
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
$rehearsalPlan = (powershell -NoProfile -File scripts/public-devnet-v1/participant-rehearsal.ps1 -PlanOnly -Rpc 127.0.0.1:18731 -FaucetWallet ./faucet.json -EvidenceDir ./participant-evidence) -join "`n"
if ($rehearsalPlan -notmatch "flow=fund-wallet -> permanence-demo upload/discover/fetch-http/prove/hash-check -> support-bundle" -or $rehearsalPlan -notmatch "public-devnet/test funds only" -or $rehearsalPlan -notmatch "outputs end with support_bundle=<dir> and evidence_log=<file>" -or $rehearsalPlan -notmatch "evidence_dir=./participant-evidence" -or $rehearsalPlan -notmatch "evidence_log=.*participant-rehearsal.log" -or $rehearsalPlan -notmatch "support_bundle=.*support-bundle") {
    $rehearsalPlan | ForEach-Object { [Console]::Error.WriteLine($_) }
    exit 1
}
$smokePlan = (powershell -NoProfile -File scripts/public-devnet-v1/participant-rehearsal-smoke.ps1 -PlanOnly -Rpc 127.0.0.1:18731) -join "`n"
if ($smokePlan -notmatch "flow=stop stale mesh -> start-all -> restore/check test faucet -> wait faucet balance -> participant-rehearsal -> stop mesh" -or $smokePlan -notmatch "custom faucet wallets are never overwritten" -or $smokePlan -notmatch "evidence_dir=.*participant-rehearsal-smoke.*evidence") {
    $smokePlan | ForEach-Object { [Console]::Error.WriteLine($_) }
    exit 1
}
$fixtureEvidenceDir = "scripts/public-devnet-v1/fixtures/participant-rehearsal-evidence-v1"
powershell -NoProfile -File scripts/public-devnet-v1/assert-participant-smoke-evidence.ps1 -EvidenceDir $fixtureEvidenceDir | Out-Null
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
$badEvidenceDir = Join-Path $env:TEMP ("permawrite-bad-evidence-" + [Guid]::NewGuid().ToString("N"))
New-Item -ItemType Directory -Force -Path $badEvidenceDir | Out-Null
$badAssertStdout = Join-Path $env:TEMP ("permawrite-bad-assert-" + [Guid]::NewGuid().ToString("N") + ".out")
$badAssertStderr = Join-Path $env:TEMP ("permawrite-bad-assert-" + [Guid]::NewGuid().ToString("N") + ".err")
$badAssertProcess = Start-Process -FilePath "powershell" -ArgumentList @(
    "-NoProfile",
    "-File",
    "scripts/public-devnet-v1/assert-participant-smoke-evidence.ps1",
    "-EvidenceDir",
    $badEvidenceDir
) -Wait -PassThru -NoNewWindow -RedirectStandardOutput $badAssertStdout -RedirectStandardError $badAssertStderr
Remove-Item -Recurse -Force $badEvidenceDir -ErrorAction SilentlyContinue
Remove-Item -Force $badAssertStdout, $badAssertStderr -ErrorAction SilentlyContinue
if ($badAssertProcess.ExitCode -eq 0) {
    [Console]::Error.WriteLine("assert-participant-smoke-evidence.ps1 accepted missing evidence directory")
    exit 1
}
$global:LASTEXITCODE = 0
powershell -NoProfile -File scripts/public-devnet-v1/release-participant-smoke-policy-check.ps1 | Out-Null
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
$badPolicyFixture = "scripts/public-devnet-v1/fixtures/policy-negative-participant-smoke-ci-snippet.yml"
$badPolicyStdout = Join-Path ([System.IO.Path]::GetTempPath()) ("permawrite-participant-policy-bad-" + [System.Guid]::NewGuid().ToString("N") + ".out")
$badPolicyStderr = Join-Path ([System.IO.Path]::GetTempPath()) ("permawrite-participant-policy-bad-" + [System.Guid]::NewGuid().ToString("N") + ".err")
$badPolicyProcess = Start-Process -FilePath "powershell" -ArgumentList @(
    "-NoProfile",
    "-File",
    "scripts/public-devnet-v1/release-participant-smoke-policy-check.ps1",
    "--path",
    $badPolicyFixture
) -Wait -PassThru -NoNewWindow -RedirectStandardOutput $badPolicyStdout -RedirectStandardError $badPolicyStderr
if ($badPolicyProcess.ExitCode -eq 0) {
    [Console]::Error.WriteLine("release-participant-smoke-policy-check.ps1 accepted a real-run participant smoke invocation")
    exit 1
}
$global:LASTEXITCODE = 0
Remove-Item -Force $badPolicyStdout, $badPolicyStderr -ErrorAction SilentlyContinue
$rcAuditOutput = Join-Path $env:TEMP ("permawrite-rc-audit-dry-run-" + [Guid]::NewGuid().ToString("N") + ".json")
powershell -NoProfile -File scripts/public-devnet-v1/release-rc-audit-dry-run.ps1 -OutputPath $rcAuditOutput -Json | Out-Null
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
$rcAuditObject = Get-Content -LiteralPath $rcAuditOutput -Raw | ConvertFrom-Json
Remove-Item -Force $rcAuditOutput -ErrorAction SilentlyContinue
if ($rcAuditObject.decision -ne "go") {
    [Console]::Error.WriteLine("release-rc-audit-dry-run.ps1 returned decision=$($rcAuditObject.decision)")
    exit 1
}
$refreshDir = Join-Path $env:TEMP ("permawrite-evidence-refresh-" + [Guid]::NewGuid().ToString("N"))
powershell -NoProfile -File scripts/public-devnet-v1/release-evidence-refresh-for-head.ps1 -AllowPendingCi -Notes "ci-check smoke" -OutputDir $refreshDir | Out-Null
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
$shortHead = (git rev-parse --short HEAD).Trim()
$refreshJson = Join-Path $refreshDir "release-evidence-$shortHead.json"
$refreshMd = Join-Path $refreshDir "release-evidence-$shortHead.md"
if (-not (Test-Path -LiteralPath $refreshJson -PathType Leaf) -or -not (Test-Path -LiteralPath $refreshMd -PathType Leaf)) {
    [Console]::Error.WriteLine("release-evidence-refresh-for-head.ps1 did not write expected evidence files")
    exit 1
}
Remove-Item -Recurse -Force $refreshDir -ErrorAction SilentlyContinue
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
    "docs/release-signoff-manifest-v1.sample.json",
    "docs/release-audit-packet-v1.schema.json",
    "docs/release-audit-packet-v1.sample.json"
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
powershell -NoProfile -File scripts/public-devnet-v1/release-json-schema-validate.ps1 -Schema docs/release-audit-packet-v1.schema.json -Json docs/release-audit-packet-v1.sample.json | Out-Null
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
foreach ($strictPair in @(
    @("docs/release-evidence-v1.schema.json", "docs/release-evidence-v1.sample.json"),
    @("docs/release-signoff-manifest-v1.schema.json", "docs/release-signoff-manifest-v1.sample.json"),
    @("docs/release-audit-packet-v1.schema.json", "docs/release-audit-packet-v1.sample.json")
)) {
    powershell -NoProfile -File scripts/public-devnet-v1/release-json-schema-draft202012.ps1 -Schema $strictPair[0] -Json $strictPair[1] -Python $schemaPython | Out-Null
    if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
}
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
    $badAudit = Join-Path $schemaValidateDir "bad-audit.json"
    $badAuditObject = Get-Content "docs/release-audit-packet-v1.sample.json" -Raw | ConvertFrom-Json
    $badAuditObject | Add-Member -NotePropertyName "unexpected_audit_field" -NotePropertyValue $true
    $badAuditObject | ConvertTo-Json -Depth 12 | Set-Content -LiteralPath $badAudit -Encoding utf8
    $badAuditStdout = Join-Path $schemaValidateDir "bad-audit.out"
    $badAuditStderr = Join-Path $schemaValidateDir "bad-audit.err"
    $badAuditProcess = Start-Process -FilePath "powershell" -ArgumentList @(
        "-NoProfile",
        "-File",
        "scripts/public-devnet-v1/release-json-schema-validate.ps1",
        "-Schema",
        "docs/release-audit-packet-v1.schema.json",
        "-Json",
        $badAudit
    ) -Wait -PassThru -NoNewWindow -RedirectStandardOutput $badAuditStdout -RedirectStandardError $badAuditStderr
    if ($badAuditProcess.ExitCode -eq 0) {
        [Console]::Error.WriteLine("release-json-schema-validate.ps1 accepted an unexpected release audit packet field")
        exit 1
    }
    $badAuditStrictStdout = Join-Path $schemaValidateDir "bad-audit-strict.out"
    $badAuditStrictStderr = Join-Path $schemaValidateDir "bad-audit-strict.err"
    $badAuditStrictProcess = Start-Process -FilePath "powershell" -ArgumentList @(
        "-NoProfile",
        "-File",
        "scripts/public-devnet-v1/release-json-schema-draft202012.ps1",
        "-Schema",
        "docs/release-audit-packet-v1.schema.json",
        "-Json",
        $badAudit,
        "-Python",
        $schemaPython
    ) -Wait -PassThru -NoNewWindow -RedirectStandardOutput $badAuditStrictStdout -RedirectStandardError $badAuditStrictStderr
    if ($badAuditStrictProcess.ExitCode -eq 0) {
        [Console]::Error.WriteLine("release-json-schema-draft202012.ps1 accepted an unexpected release audit packet field")
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
$archivePlan = powershell -NoProfile -File scripts/public-devnet-v1/release-archive-dry-run.ps1 -PlanOnly -ReleaseEvidenceJson docs/release-evidence-v1.sample.json -IncludeReleaseSchemaWheelhouse
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
$archivePlanText = $archivePlan -join "`n"
if (-not $archivePlanText.Contains("release-archive-dry-run: PLAN OK")) {
    [Console]::Error.WriteLine("release-archive-dry-run.ps1 plan mode did not complete successfully")
    exit 1
}
if (-not $archivePlanText.Contains("toolchain/wheelhouse-release-schema")) {
    [Console]::Error.WriteLine("release-archive-dry-run.ps1 plan mode did not include release-schema wheelhouse staging")
    exit 1
}
if (-not $archivePlanText.Contains("participant smoke CI policy helpers")) {
    [Console]::Error.WriteLine("release-archive-dry-run.ps1 plan mode did not include participant smoke CI policy helpers")
    exit 1
}
$archiveDir = Join-Path ([System.IO.Path]::GetTempPath()) ("permawrite-archive-" + [System.Guid]::NewGuid().ToString("N"))
try {
    $archiveRun = powershell -NoProfile -File scripts/public-devnet-v1/release-archive-dry-run.ps1 -OutputDir $archiveDir -ReleaseEvidenceJson docs/release-evidence-v1.sample.json -IncludeReleaseSchemaWheelhouse
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
        "evidence/checksums.sha256",
        "toolchain/requirements-release-schema.txt",
        "toolchain/release-participant-smoke-policy-check.py",
        "toolchain/release-participant-smoke-policy-check.ps1",
        "toolchain/wheelhouse-release-schema"
    )) {
        if (-not (Test-Path -LiteralPath (Join-Path $archiveRoot $requiredPath))) {
            [Console]::Error.WriteLine("release-archive-dry-run.ps1 missing staged artifact '$requiredPath'")
            exit 1
        }
    }
    $wheelCount = (Get-ChildItem -LiteralPath (Join-Path $archiveRoot "toolchain/wheelhouse-release-schema") -Filter *.whl -File).Count
    if ($wheelCount -lt 3) {
        [Console]::Error.WriteLine("release-archive-dry-run.ps1 staged fewer than 3 release-schema wheels")
        exit 1
    }
    powershell -NoProfile -File scripts/public-devnet-v1/release-archive-validate.ps1 -ArchiveDir $archiveRoot -AllowDryRun -RequireReleaseSchemaWheelhouse | Out-Null
    if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
    $offlineVenv = Join-Path $archiveDir ("permawrite-release-schema-offline-" + [System.Guid]::NewGuid().ToString("N"))
    python -m venv $offlineVenv
    if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
    $offlinePython = @(
        (Join-Path $offlineVenv "Scripts\python.exe"),
        (Join-Path $offlineVenv "bin\python.exe"),
        (Join-Path $offlineVenv "bin\python")
    ) | Where-Object { Test-Path -LiteralPath $_ -PathType Leaf } | Select-Object -First 1
    if (-not $offlinePython) {
        [Console]::Error.WriteLine("offline release-schema venv did not contain a Python executable")
        exit 1
    }
    $env:PERMAWRITE_RELEASE_SCHEMA_PYTHON = $offlinePython
    powershell -NoProfile -File (Join-Path $archiveRoot "toolchain/release-schema-install-offline.ps1") `
        -Wheelhouse (Join-Path $archiveRoot "toolchain/wheelhouse-release-schema")
    if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
    powershell -NoProfile -File (Join-Path $archiveRoot "toolchain/release-json-schema-draft202012.ps1") `
        -Schema docs/release-audit-packet-v1.schema.json `
        -Json docs/release-audit-packet-v1.sample.json | Out-Null
    if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
    $env:PERMAWRITE_RELEASE_SCHEMA_PYTHON = $schemaPython

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
    $participantCommit = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    $participantSha = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
    $participantLog = Join-Path $archiveDir "participant-rehearsal.log"
    $participantBundle = Join-Path $archiveDir "participant-support-bundle"
    New-Item -ItemType Directory -Force -Path $participantBundle | Out-Null
    "participant-rehearsal: PASS commitment_hash=$participantCommit restored_sha256=$participantSha restored_path=restored.bin support_bundle=$participantBundle" | Set-Content -LiteralPath $participantLog -Encoding utf8
    @"
{
  "commit_hash": "$participantCommit",
  "read_only": true,
  "commands": [
    {"name": "node-status", "exit_code": 0},
    {"name": "uploads-list", "exit_code": 0},
    {"name": "operator-pool", "exit_code": 0},
    {"name": "operator-challenge", "exit_code": 0}
  ]
}
"@ | Set-Content -LiteralPath (Join-Path $participantBundle "manifest.json") -Encoding utf8
    $auditJson = powershell -NoProfile -File scripts/public-devnet-v1/release-audit-packet.ps1 `
        -ReleaseEvidenceJson docs/release-evidence-v1.sample.json `
        -SignoffManifest docs/release-signoff-manifest-v1.sample.json `
        -ArchiveDir $archiveRoot `
        -Inventory $signoffInventory `
        -CiMockRuns $signoffCiSuccess `
        -ParticipantRehearsalLog $participantLog `
        -ParticipantSupportBundle $participantBundle `
        -AllowDryRun `
        -Json
    if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
    $auditObject = $auditJson | ConvertFrom-Json
    if ($auditObject.schema_version -ne "release-audit-packet.v1" -or $auditObject.decision -ne "go") {
        [Console]::Error.WriteLine("release-audit-packet.ps1 did not emit a clean go packet")
        exit 1
    }
    $participantCheck = $auditObject.checks | Where-Object { $_.name -eq "participant rehearsal evidence" } | Select-Object -First 1
    if (-not $participantCheck -or $participantCheck.status -ne "pass" -or $participantCheck.message -notmatch "commitment_hash=") {
        [Console]::Error.WriteLine("release-audit-packet.ps1 did not validate participant rehearsal evidence")
        exit 1
    }
    $policyCheck = $auditObject.checks | Where-Object { $_.name -eq "participant smoke CI policy" } | Select-Object -First 1
    if (-not $policyCheck -or $policyCheck.status -ne "pass") {
        [Console]::Error.WriteLine("release-audit-packet.ps1 did not validate participant smoke CI policy")
        exit 1
    }
    $auditGeneratedJson = Join-Path $archiveDir "release-audit-packet.generated.json"
    $auditJson | Set-Content -LiteralPath $auditGeneratedJson -Encoding utf8
    powershell -NoProfile -File scripts/public-devnet-v1/release-json-schema-validate.ps1 -Schema docs/release-audit-packet-v1.schema.json -Json $auditGeneratedJson | Out-Null
    if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
    powershell -NoProfile -File scripts/public-devnet-v1/release-json-schema-draft202012.ps1 -Schema docs/release-audit-packet-v1.schema.json -Json $auditGeneratedJson -Python $schemaPython | Out-Null
    if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
    $participantBadBundleLog = Join-Path $archiveDir "participant-rehearsal-bad-bundle.log"
    "participant-rehearsal: PASS commitment_hash=$participantCommit restored_sha256=$participantSha restored_path=restored.bin support_bundle=$(Join-Path $archiveDir "wrong-support-bundle")" | Set-Content -LiteralPath $participantBadBundleLog -Encoding utf8
    $participantBadStdout = Join-Path $archiveDir "participant-bad-bundle.out"
    $participantBadStderr = Join-Path $archiveDir "participant-bad-bundle.err"
    $participantBadProcess = Start-Process -FilePath "powershell" -ArgumentList @(
        "-NoProfile",
        "-File",
        "scripts/public-devnet-v1/release-audit-packet.ps1",
        "-ReleaseEvidenceJson",
        "docs/release-evidence-v1.sample.json",
        "-SignoffManifest",
        "docs/release-signoff-manifest-v1.sample.json",
        "-ArchiveDir",
        $archiveRoot,
        "-Inventory",
        $signoffInventory,
        "-CiMockRuns",
        $signoffCiSuccess,
        "-ParticipantRehearsalLog",
        $participantBadBundleLog,
        "-ParticipantSupportBundle",
        $participantBundle,
        "-AllowDryRun",
        "-Json"
    ) -Wait -PassThru -NoNewWindow -RedirectStandardOutput $participantBadStdout -RedirectStandardError $participantBadStderr
    if ($participantBadProcess.ExitCode -eq 0) {
        [Console]::Error.WriteLine("release-audit-packet.ps1 accepted mismatched participant support bundle evidence")
        exit 1
    }
    $global:LASTEXITCODE = 0
    $fixtureRoot = "scripts/public-devnet-v1/fixtures/participant-rehearsal-evidence-v1"
    $fixtureAuditJson = powershell -NoProfile -File scripts/public-devnet-v1/release-audit-packet.ps1 `
        -ReleaseEvidenceJson docs/release-evidence-v1.sample.json `
        -SignoffManifest docs/release-signoff-manifest-v1.sample.json `
        -ArchiveDir $archiveRoot `
        -Inventory (Join-Path $archiveDir "signoff-inventory.md") `
        -CiMockRuns (Join-Path $archiveDir "signoff-ci-success.json") `
        -ParticipantRehearsalLog (Join-Path $fixtureRoot "participant-rehearsal.log") `
        -ParticipantSupportBundle (Join-Path $fixtureRoot "support-bundle") `
        -AllowDryRun `
        -Json
    if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
    $fixtureAuditObject = $fixtureAuditJson | ConvertFrom-Json
    $fixtureParticipant = $fixtureAuditObject.checks | Where-Object { $_.name -eq "participant rehearsal evidence" } | Select-Object -First 1
    if (-not $fixtureParticipant -or $fixtureParticipant.status -ne "pass") {
        [Console]::Error.WriteLine("release-audit-packet.ps1 did not validate participant-rehearsal-evidence-v1 fixture")
        exit 1
    }
    $fixtureViaDirJson = powershell -NoProfile -File scripts/public-devnet-v1/release-audit-packet.ps1 `
        -ReleaseEvidenceJson docs/release-evidence-v1.sample.json `
        -SignoffManifest docs/release-signoff-manifest-v1.sample.json `
        -ArchiveDir $archiveRoot `
        -Inventory (Join-Path $archiveDir "signoff-inventory.md") `
        -CiMockRuns (Join-Path $archiveDir "signoff-ci-success.json") `
        -ParticipantEvidenceDir $fixtureRoot `
        -AllowDryRun `
        -Json
    if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
    $fixtureViaDirObject = $fixtureViaDirJson | ConvertFrom-Json
    if ($fixtureViaDirObject.participant_evidence_dir -ne $fixtureRoot) {
        [Console]::Error.WriteLine("release-audit-packet.ps1 did not emit participant_evidence_dir from -ParticipantEvidenceDir")
        exit 1
    }
    $fixtureViaDirParticipant = $fixtureViaDirObject.checks | Where-Object { $_.name -eq "participant rehearsal evidence" } | Select-Object -First 1
    if (-not $fixtureViaDirParticipant -or $fixtureViaDirParticipant.status -ne "pass") {
        [Console]::Error.WriteLine("release-audit-packet.ps1 did not validate participant evidence via -ParticipantEvidenceDir")
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
# M2.4.89 / M2.4.90: heavy M5.36–M5.39 proptest + emission sims OOM at threads=4 on Windows.
cargo test --workspace --release -- --test-threads=2
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

Write-Host "==> wasm32 build"
rustup target add wasm32-unknown-unknown
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
cargo build -p mfn-wasm --target wasm32-unknown-unknown --release --features wasm-full
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
cargo test -p mfn-wasm --release --features wasm-full
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
# wasm-pack 0.15 mis-parses a prior package.json when `files`/`sideEffects` are arrays.
Remove-Item -Recurse -Force mfn-wasm/demo/web/pkg -ErrorAction SilentlyContinue
wasm-pack --log-level warn build mfn-wasm --target web --out-dir demo/web/pkg --release --features wasm-full
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

Write-Host "==> cargo audit"
cargo audit
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

Write-Host "ci-check: OK"
