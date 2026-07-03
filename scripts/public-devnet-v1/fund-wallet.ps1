# Fund a participant wallet from an operator-controlled public-devnet faucet wallet.
param(
    [string]$Rpc = "",
    [string]$FaucetWallet = "",
    [string]$RecipientWallet = "",
    [UInt64]$Amount = 1000000,
    [UInt64]$Fee = 10000,
    [int]$RingSize = 8,
    [int]$WaitMinedSeconds = 180,
    [switch]$NoBuild,
    [switch]$PlanOnly
)
$ErrorActionPreference = "Stop"

$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$RepoRoot = (Resolve-Path (Join-Path $ScriptDir "..\..")).Path
$PortsFile = Join-Path $ScriptDir "devnet-ports.env"
$DemoRoot = Join-Path $ScriptDir "permanence-demo"
$DefaultRecipientWallet = Join-Path $DemoRoot "uploader.json"

function Read-PortsFile {
    if (-not (Test-Path $PortsFile)) { return @{} }
    $ports = @{}
    Get-Content $PortsFile | ForEach-Object {
        if ($_ -match "^([^=]+)=(.*)$") { $ports[$Matches[1]] = $Matches[2] }
    }
    return $ports
}

function Resolve-Rpc {
    if ($Rpc) { return $Rpc }
    $ports = Read-PortsFile
    if ($ports["HUB_RPC"]) { return $ports["HUB_RPC"] }
    throw "fund-wallet: pass -Rpc HOST:PORT or run start-all.ps1 first"
}

function Resolve-Bin {
    $exe = if ($IsWindows -or $env:OS -eq "Windows_NT") { "mfn-cli.exe" } else { "mfn-cli" }
    $path = Join-Path $RepoRoot "target\release\$exe"
    if (-not (Test-Path $path)) {
        throw "fund-wallet: missing $path; rerun without -NoBuild or build mfn-cli --release"
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
        throw "fund-wallet: $Label failed with exit=$code`n$text"
    }
    return $text
}

function Parse-Field {
    param([string]$Text, [string]$Key)
    $prefix = "$Key="
    foreach ($line in ($Text -split "`r?`n")) {
        if ($line.StartsWith($prefix)) { return $line.Substring($prefix.Length).Trim() }
    }
    throw "fund-wallet: stdout missing $prefix`n$Text"
}

function Ensure-Wallet {
    param([string]$MfnCli, [string]$Path, [string]$Label)
    if (Test-Path $Path) {
        Write-Host "fund-wallet: using existing $Label wallet at $Path"
        return
    }
    Invoke-Checked $MfnCli @("--wallet", $Path, "wallet", "new") "$Label wallet new" | Out-Null
    Write-Host "fund-wallet: created $Label wallet at $Path"
}

function Get-WalletBalance {
    param([string]$MfnCli, [string]$RpcAddr, [string]$WalletPath, [string]$Label)
    $balanceOut = Invoke-Checked $MfnCli @("--rpc", $RpcAddr, "--wallet", $WalletPath, "wallet", "balance") "$Label wallet balance"
    $balanceText = Parse-Field $balanceOut "balance"
    return [UInt64]$balanceText
}

function Wait-RecipientBalance {
    param([string]$MfnCli, [string]$RpcAddr, [string]$WalletPath, [UInt64]$StartingBalance, [UInt64]$MinimumBalance, [int]$TimeoutSeconds)
    if ($TimeoutSeconds -le 0) { return }
    $deadline = (Get-Date).AddSeconds($TimeoutSeconds)
    $lastError = ""
    do {
        try {
            $tipHeight = Get-TipHeightText $MfnCli $RpcAddr
            Invoke-Checked $MfnCli @("--rpc", $RpcAddr, "--wallet", $WalletPath, "wallet", "scan") "recipient wallet scan" | Out-Null
            $balance = Get-WalletBalance $MfnCli $RpcAddr $WalletPath "recipient"
            Write-Host "fund-wallet: recipient_balance_wait hub_tip_height=$tipHeight balance=$balance target=$MinimumBalance"
            if ($balance -ge $MinimumBalance) {
                Write-Host "fund-wallet: recipient_balance=$balance"
                return
            }
            $lastError = ""
        } catch {
            $lastError = $_.Exception.Message
            if ($lastError -match "actively refused|Connection refused|error 10061") {
                throw "fund-wallet: hub RPC unreachable during mining wait; mesh may have stopped ($lastError)"
            }
            Write-Host "fund-wallet: recipient_balance_wait retry_after_error=$($lastError -replace "`r?`n", " ")"
        }
        Start-Sleep -Seconds 5
    } while ((Get-Date) -lt $deadline)
    $suffix = if ($lastError) { "; last_error=$lastError" } else { "" }
    $tipHeight = Get-TipHeightText $MfnCli $RpcAddr
    throw "fund-wallet: recipient balance did not increase from $StartingBalance to at least $MinimumBalance within ${TimeoutSeconds}s (hub_tip_height=$tipHeight); mine or wait for a producer block, then run wallet scan and wallet balance$suffix"
}

function Get-TipHeightText {
    param([string]$MfnCli, [string]$RpcAddr)
    $oldErrorActionPreference = $ErrorActionPreference
    $ErrorActionPreference = "Continue"
    try {
        $tipOut = & $MfnCli --rpc $RpcAddr tip 2>&1
    } finally {
        $ErrorActionPreference = $oldErrorActionPreference
    }
    if ($LASTEXITCODE -ne 0) { return "unknown" }
    $tipText = ($tipOut | Out-String)
    if ($tipText -match "(^|\s)tip_height=([0-9]+)") { return $Matches[2] }
    if ($tipText -match "(^|\s)tip_height=none") { return "0" }
    return "unknown"
}

if ($Amount -eq 0) { throw "Amount must be greater than 0" }
if ($RingSize -lt 2) { throw "RingSize must be >= 2" }
if ($WaitMinedSeconds -lt 0) { throw "WaitMinedSeconds must be >= 0" }

$Recipient = if ($RecipientWallet) { $RecipientWallet } else { $DefaultRecipientWallet }

if ($PlanOnly) {
    $planRpc = try {
        Resolve-Rpc
    } catch {
        "<pass -Rpc HOST:PORT or run start-all.ps1>"
    }
    $planFaucet = if ($FaucetWallet) { $FaucetWallet } else { "<required -FaucetWallet PATH>" }
    Write-Host "fund-wallet: plan"
    Write-Host "  rpc=$planRpc"
    Write-Host "  faucet_wallet=$planFaucet"
    Write-Host "  recipient_wallet=$Recipient"
    Write-Host "  amount=$Amount fee=$Fee ring_size=$RingSize wait_mined_seconds=$WaitMinedSeconds"
    Write-Host "  flow=create/reuse recipient wallet -> record starting balance -> refresh faucet scan/balance -> wallet address -> faucet wallet send --json -> wait for balance delta"
    Write-Host "  warning=use only public-devnet/test funds; never store real faucet seeds in this repo"
    exit 0
}

if (-not $FaucetWallet) { throw "fund-wallet: -FaucetWallet PATH is required outside -PlanOnly" }
if (-not (Test-Path $FaucetWallet)) { throw "fund-wallet: faucet wallet not found: $FaucetWallet" }

$RpcAddr = Resolve-Rpc
$RecipientParent = Split-Path -Parent $Recipient
if ($RecipientParent) {
    New-Item -ItemType Directory -Force -Path $RecipientParent | Out-Null
}

Push-Location $RepoRoot
try {
    if (-not $NoBuild) {
        cargo build -p mfn-cli --release --bin mfn-cli
    }
    $MfnCli = Resolve-Bin
    Ensure-Wallet $MfnCli $Recipient "recipient"
    $startingBalance = Get-WalletBalance $MfnCli $RpcAddr $Recipient "recipient"
    $targetBalance = $startingBalance + $Amount
    if ($targetBalance -lt $startingBalance) {
        throw "fund-wallet: recipient balance target overflow"
    }
    Write-Host "fund-wallet: recipient_starting_balance=$startingBalance target_balance=$targetBalance"
    Invoke-Checked $MfnCli @("--rpc", $RpcAddr, "--wallet", $FaucetWallet, "wallet", "scan") "faucet wallet scan" | Out-Null
    $faucetBalance = Get-WalletBalance $MfnCli $RpcAddr $FaucetWallet "faucet"
    Write-Host "fund-wallet: faucet_balance=$faucetBalance"
    if ($faucetBalance -lt ($Amount + $Fee)) {
        throw "fund-wallet: faucet balance $faucetBalance is below required $($Amount + $Fee); mine/scan the faucet wallet or choose a funded faucet"
    }

    $addr = Invoke-Checked $MfnCli @("--wallet", $Recipient, "wallet", "address") "recipient wallet address"
    $view = Parse-Field $addr "view_pub_hex"
    $spend = Parse-Field $addr "spend_pub_hex"

    $send = Invoke-Checked $MfnCli @(
        "--rpc", $RpcAddr, "--wallet", $FaucetWallet,
        "wallet", "send", $view, $spend, "$Amount",
        "--fee", "$Fee", "--ring-size", "$RingSize", "--json"
    ) "faucet wallet send"
    $sendJson = $send | ConvertFrom-Json
    $txId = [string]$sendJson.tx_id
    $mempoolLen = [string]$sendJson.mempool_len
    $outcome = [string]$sendJson.outcome
    if (-not $txId) { throw "fund-wallet: wallet send --json missing tx_id`n$send" }
    Write-Host "fund-wallet: submitted tx_id=$txId mempool_len=$mempoolLen outcome=$outcome recipient_wallet=$Recipient"
    Write-Host "fund-wallet: wait_for_mining=$WaitMinedSeconds"
    Wait-RecipientBalance $MfnCli $RpcAddr $Recipient $startingBalance $targetBalance $WaitMinedSeconds
    Write-Host "fund-wallet: PASS tx_id=$txId recipient_wallet=$Recipient amount=$Amount"
} finally {
    Pop-Location
}
