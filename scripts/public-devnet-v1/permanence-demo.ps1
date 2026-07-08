# End-to-end permanence demo: upload -> discover -> HTTP replicate -> retrieve -> prove.
param(
    [string]$Rpc = "",
    [string]$WalletDir = "",
    [string]$PayloadPath = "",
    [string]$ChunkListen = "127.0.0.1:18780",
    [int]$WaitUploadSeconds = 180,
    [int]$WaitFetchSeconds = 120,
    [int]$WaitProofSeconds = 180,
    [switch]$NoBuild,
    [switch]$PlanOnly
)
$ErrorActionPreference = "Stop"

$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$RepoRoot = (Resolve-Path (Join-Path $ScriptDir "..\..")).Path
. (Join-Path $ScriptDir "ports-env-lib.ps1")
$PortsFile = Join-Path $ScriptDir "devnet-ports.env"
$LogDir = Join-Path $ScriptDir "logs"
$DemoRoot = if ($WalletDir) {
    $WalletDir
} else {
    Join-Path $ScriptDir "permanence-demo"
}
$UploaderWallet = Join-Path $DemoRoot "uploader.json"
$ReplicaWallet = Join-Path $DemoRoot "replica.json"
# Public devnet genesis operator 0 payout seed (matches public_devnet_v1.json storage_operators[0]).
$PublicDevnetOperator0Seed = "c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3"
$RestoredPath = Join-Path $DemoRoot "restored.bin"
$ChunkLog = Join-Path $LogDir "permanence-demo-chunks.log"
$ChunkErrLog = Join-Path $LogDir "permanence-demo-chunks.err.log"

function Read-PortsFile {
    if (-not (Test-Path $PortsFile)) { return @{} }
    $ports = @{}
    Get-Content $PortsFile | ForEach-Object {
        if ($_ -match "^([^=]+)=(.*)$") { $ports[$Matches[1]] = $Matches[2] }
    }
    return $ports
}

function Get-RecordedMeshProcessStatus {
    $ports = Read-PortsFile
    $keys = @("HUB_PID", "V1_PID", "V2_PID", "OBSERVER_PID")
    $rows = @()
    foreach ($key in $keys) {
        if (-not $ports[$key]) { continue }
        $pidValue = 0
        if (-not [int]::TryParse($ports[$key], [ref]$pidValue)) {
            $rows += "$key=$($ports[$key]):invalid"
            continue
        }
        $proc = Get-Process -Id $pidValue -ErrorAction SilentlyContinue
        if ($proc) {
            $rows += "${key}=${pidValue}:running:$($proc.ProcessName)"
        } else {
            $rows += "${key}=${pidValue}:not_running"
        }
    }
    return $rows
}

function Assert-LocalMeshStillAlive {
    param([string]$LastError)
    if ($LastError -notmatch "actively refused|os error 10061|Connection refused") { return }
    $status = @(Get-RecordedMeshProcessStatus)
    if ($status.Count -eq 0) { return }
    $hubDead = $status | Where-Object { $_ -like "HUB_PID=*:not_running" }
    if ($hubDead) {
        throw "permanence-demo: local helper mesh RPC is refusing connections and recorded hub daemon is not running; process_status=$($status -join ', '); logs=$LogDir"
    }
}

function Resolve-Rpc {
    if ($Rpc) { return $Rpc }
    $ports = Read-PortsFile
    if ($ports["HUB_RPC"]) { return $ports["HUB_RPC"] }
    throw "permanence-demo: pass -Rpc HOST:PORT or run start-all.ps1 first"
}

function Resolve-Bin {
    param([string]$Name)
    $exe = if ($IsWindows -or $env:OS -eq "Windows_NT") { "$Name.exe" } else { $Name }
    $path = Join-Path $RepoRoot "target\release\$exe"
    if (-not (Test-Path $path)) {
        throw "permanence-demo: missing $path; rerun without -NoBuild or build release binaries"
    }
    return $path
}

function Invoke-Checked {
    param([string]$Exe, [string[]]$CliArgs, [string]$Label)
    $oldErrorActionPreference = $ErrorActionPreference
    $ErrorActionPreference = "Continue"
    try {
        $out = & $Exe @CliArgs 2>&1
    } finally {
        $ErrorActionPreference = $oldErrorActionPreference
    }
    $code = $LASTEXITCODE
    $text = ($out | Out-String).Trim()
    if ($code -ne 0) {
        throw "permanence-demo: $Label failed with exit=$code`n$text"
    }
    return $text
}

function Parse-Field {
    param([string]$Text, [string]$Key)
    $prefix = "$Key="
    foreach ($line in ($Text -split "`r?`n")) {
        if ($line.StartsWith($prefix)) { return $line.Substring($prefix.Length).Trim() }
    }
    throw "permanence-demo: stdout missing $prefix`n$Text"
}

function Get-TipHeightText {
    param([string]$MfnCli, [string]$RpcAddr)
    return Get-TipHeightFromRpc -RpcAddr $RpcAddr -MfnCli $MfnCli
}

function Wait-UploadsListContains {
    param([string]$MfnCli, [string]$RpcAddr, [string]$CommitHash, [int]$TimeoutSeconds)
    $deadline = (Get-Date).AddSeconds($TimeoutSeconds)
    $lastError = ""
    $lastTipHeight = ""
    $lastTipChange = [DateTime]::UtcNow
    do {
        try {
            $tipHeight = Get-TipHeightText $MfnCli $RpcAddr
            if ($tipHeight -ne $lastTipHeight) {
                $lastTipHeight = $tipHeight
                $lastTipChange = [DateTime]::UtcNow
            }
            $out = Invoke-Checked $MfnCli @("--rpc", $RpcAddr, "uploads", "list", "--limit", "50") "uploads list"
            if ($out -like "*$CommitHash*") { return $out }
            $stallLimit = if ($env:GITHUB_ACTIONS) { 480 } else { 120 }
            $stallSeconds = ([DateTime]::UtcNow - $lastTipChange).TotalSeconds
            Write-Host "permanence-demo: uploads_list_wait hub_tip_height=$tipHeight stall_seconds=$([int]$stallSeconds)"
            if ($stallSeconds -ge $stallLimit) {
                $status = @(Get-RecordedMeshProcessStatus) -join ", "
                throw "permanence-demo: hub tip stalled at height=$tipHeight for ${stallSeconds}s while waiting for commitment index; process_status=$status; logs=$LogDir"
            }
            $lastError = ""
        } catch {
            $lastError = $_.Exception.Message
            Write-Host "permanence-demo: uploads_list_wait retry_after_error=$($lastError -replace "`r?`n", " ")"
            Assert-LocalMeshStillAlive $lastError
        }
        Start-Sleep -Seconds 5
    } while ((Get-Date) -lt $deadline)
    $suffix = if ($lastError) { "; last_error=$lastError" } else { "" }
    $tipHeight = Get-TipHeightText $MfnCli $RpcAddr
    throw "permanence-demo: commitment $CommitHash was not indexed within ${TimeoutSeconds}s (hub_tip_height=$tipHeight)$suffix"
}

function Wait-FetchHttpOk {
    param(
        [string]$MfnCli,
        [string]$RpcAddr,
        [string]$ReplicaWallet,
        [string]$Commit,
        [string]$RestoredPath,
        [string]$ChunkListen,
        [int]$TimeoutSeconds
    )
    $deadline = (Get-Date).AddSeconds($TimeoutSeconds)
    $lastError = ""
    do {
        try {
            if (Test-Path $RestoredPath) { Remove-Item -Force $RestoredPath }
            $restore = Invoke-Checked $MfnCli @(
                "--rpc", $RpcAddr, "--wallet", $ReplicaWallet,
                "uploads", "fetch-http", $Commit, $RestoredPath, $ChunkListen
            ) "uploads fetch-http"
            if ($restore -like "*fetch_http=ok*") { return $restore }
            throw "permanence-demo: fetch-http did not report ok`n$restore"
        } catch {
            $lastError = $_.Exception.Message
            if ($lastError -notmatch "404|HTTP 404|not found") {
                Assert-LocalMeshStillAlive $lastError
            }
            Write-Host "permanence-demo: fetch_http_wait retry_after_error=$($lastError -replace "`r?`n", " ")"
        }
        Start-Sleep -Seconds 5
    } while ((Get-Date) -lt $deadline)
    throw "permanence-demo: fetch-http for $Commit failed within ${TimeoutSeconds}s; last_error=$lastError"
}

function Ensure-SamplePayload {
    if ($PayloadPath) { return $PayloadPath }
    $path = Join-Path $DemoRoot "payload.bin"
    if (-not (Test-Path $path)) {
        $bytes = New-Object byte[] 4096
        for ($i = 0; $i -lt $bytes.Length; $i++) { $bytes[$i] = [byte]($i % 251) }
        [System.IO.File]::WriteAllBytes($path, $bytes)
    }
    return $path
}

function Ensure-Wallet {
    param([string]$MfnCli, [string]$Path, [string]$Label)
    if (Test-Path $Path) {
        Write-Host "permanence-demo: using existing $Label wallet at $Path"
        return
    }
    Invoke-Checked $MfnCli @("--wallet", $Path, "wallet", "new") "$Label wallet new" | Out-Null
    Write-Host "permanence-demo: created $Label wallet at $Path"
}

function Ensure-RegisteredOperatorWallet {
    param([string]$MfnCli, [string]$Path, [string]$Seed, [string]$Label)
    $parent = Split-Path -Parent $Path
    if ($parent) { New-Item -ItemType Directory -Force -Path $parent | Out-Null }
    Invoke-Checked $MfnCli @("--wallet", $Path, "--force", "wallet", "restore", $Seed, "--key-derivation", "payout_stealth_v1") "$Label wallet restore" | Out-Null
    Write-Host "permanence-demo: restored $Label wallet from public devnet operator seed"
}

if ($WaitUploadSeconds -lt 1) { throw "WaitUploadSeconds must be >= 1" }
if ($WaitProofSeconds -lt 0) { throw "WaitProofSeconds must be >= 0" }

if ($PlanOnly) {
    $planRpc = try {
        Resolve-Rpc
    } catch {
        "<pass -Rpc HOST:PORT or run start-all.ps1>"
    }
    Write-Host "permanence-demo: plan"
    Write-Host "  rpc=$planRpc"
    Write-Host "  demo_dir=$DemoRoot"
    Write-Host "  chunk_listen=$ChunkListen"
    Write-Host "  flow=create/reuse wallets -> wallet upload -> uploads list -> serve-chunks -> uploads fetch-http -> operator prove -> uploads list"
    Write-Host "  note=real mode requires the uploader wallet to hold enough devnet funds; use fund-wallet.ps1 with an operator faucet wallet first"
    exit 0
}

$RpcAddr = Resolve-Rpc

New-Item -ItemType Directory -Force -Path $DemoRoot | Out-Null
New-Item -ItemType Directory -Force -Path $LogDir | Out-Null

Push-Location $RepoRoot
try {
    if (-not $NoBuild) {
        cargo build -p mfn-cli --release --bin mfn-cli
        cargo build -p mfn-storage-operator --release --bin mfn-storage-operator
    }

    $MfnCli = Resolve-Bin "mfn-cli"
    $StorageOperator = Resolve-Bin "mfn-storage-operator"
    $Payload = Ensure-SamplePayload

    Ensure-Wallet $MfnCli $UploaderWallet "uploader"
    Ensure-RegisteredOperatorWallet $MfnCli $ReplicaWallet $PublicDevnetOperator0Seed "replica"

    $upload = Invoke-Checked $MfnCli @("--rpc", $RpcAddr, "--wallet", $UploaderWallet, "wallet", "upload", $Payload, "--replication", "3") "wallet upload"
    $commit = Parse-Field $upload "storage_commitment_hash"
    $txId = Parse-Field $upload "tx_id"
    Write-Host "permanence-demo: upload tx_id=$txId commitment_hash=$commit"

    $indexed = Wait-UploadsListContains $MfnCli $RpcAddr $commit $WaitUploadSeconds
    Write-Host "permanence-demo: discover=ok commitment_hash=$commit"

    if (Test-Path $ChunkLog) { Remove-Item -Force $ChunkLog }
    if (Test-Path $ChunkErrLog) { Remove-Item -Force $ChunkErrLog }
    $chunkProc = Start-Process -FilePath $StorageOperator -ArgumentList @(
        "serve-chunks", "--wallet", $UploaderWallet, "--listen", $ChunkListen
    ) -WorkingDirectory $RepoRoot -RedirectStandardOutput $ChunkLog -RedirectStandardError $ChunkErrLog -PassThru
    try {
        Start-Sleep -Seconds 2
        if ($chunkProc.HasExited) {
            $log = if (Test-Path $ChunkLog) { Get-Content $ChunkLog -Raw } else { "" }
            $errLog = if (Test-Path $ChunkErrLog) { Get-Content $ChunkErrLog -Raw } else { "" }
            throw "permanence-demo: chunk server exited early`nstdout:`n$log`nstderr:`n$errLog"
        }

        if (Test-Path $RestoredPath) { Remove-Item -Force $RestoredPath }
        $restore = Wait-FetchHttpOk $MfnCli $RpcAddr $ReplicaWallet $commit $RestoredPath $ChunkListen $WaitFetchSeconds
        if ($restore -notlike "*fetch_http=ok*") { throw "permanence-demo: fetch-http did not report ok`n$restore" }

        $proof = Invoke-Checked $MfnCli @("--rpc", $RpcAddr, "--wallet", $ReplicaWallet, "operator", "prove", $commit) "operator prove"
        $poolLen = Parse-Field $proof "pool_len"
        Write-Host "permanence-demo: prove=ok pool_len=$poolLen"
    } finally {
        if ($chunkProc -and -not $chunkProc.HasExited) {
            Stop-Process -Id $chunkProc.Id -Force -ErrorAction SilentlyContinue
            $chunkProc.WaitForExit()
        }
    }

    $srcHash = (Get-FileHash -Algorithm SHA256 $Payload).Hash.ToLowerInvariant()
    $dstHash = (Get-FileHash -Algorithm SHA256 $RestoredPath).Hash.ToLowerInvariant()
    if ($srcHash -ne $dstHash) {
        throw "permanence-demo: restored hash mismatch source=$srcHash restored=$dstHash"
    }

    if ($WaitProofSeconds -gt 0) {
        $deadline = (Get-Date).AddSeconds($WaitProofSeconds)
        $lastProofListError = ""
        do {
            try {
                $afterProof = Invoke-Checked $MfnCli @("--rpc", $RpcAddr, "uploads", "list", "--limit", "50") "uploads list after proof"
                if ($afterProof -like "*$commit*" -and $afterProof -like "*last_proven_height=*") { break }
                $lastProofListError = ""
            } catch {
                $lastProofListError = $_.Exception.Message
                Write-Host "permanence-demo: uploads_list_after_proof_wait retry_after_error=$($lastProofListError -replace "`r?`n", " ")"
            }
            Start-Sleep -Seconds 5
        } while ((Get-Date) -lt $deadline)
    }

    Write-Host "permanence-demo: PASS commitment_hash=$commit restored_sha256=$dstHash restored_path=$RestoredPath"
} finally {
    Pop-Location
}
