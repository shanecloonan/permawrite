# Shared devnet-ports.env read/write helpers (UTF-8 no BOM, atomic rewrite, mutex).

function Get-DevnetPortsEncoding {
    [System.Text.UTF8Encoding]::new($false)
}

if (-not $script:DevnetPortsMutex) {
    $script:DevnetPortsMutex = New-Object System.Threading.Mutex($false, "Global\PermawriteDevnetPortsEnv")
}

function Invoke-DevnetPortsLocked {
    param([scriptblock]$Action)
    if (-not $script:DevnetPortsMutex.WaitOne(30000)) {
        throw "devnet-ports: lock timeout after 30s"
    }
    try {
        return & $Action
    } finally {
        [void]$script:DevnetPortsMutex.ReleaseMutex()
    }
}

function Read-DevnetPortsFile {
    param([string]$Path)
    if (-not (Test-Path $Path)) { throw "Missing $Path - run start-all.ps1 first" }
    $ports = @{}
    $enc = Get-DevnetPortsEncoding
    foreach ($line in [System.IO.File]::ReadAllLines($Path, $enc)) {
        if ($line -match "^([^=]+)=(.*)$") {
            $key = $Matches[1].TrimStart([char]0xFEFF).Trim()
            $ports[$key] = $Matches[2]
        }
    }
    return $ports
}

function Try-Read-DevnetPortsFile {
    param([string]$Path)
    if (-not (Test-Path $Path)) { return @{} }
    try {
        return Read-DevnetPortsFile -Path $Path
    } catch {
        return @{}
    }
}

function Write-DevnetPortsFile {
    param(
        [string]$Path,
        [hashtable]$Ports
    )
    $enc = Get-DevnetPortsEncoding
    $order = @(
        "HUB_PID", "HUB_P2P", "HUB_RPC",
        "V1_PID", "V2_PID",
        "OBSERVER_PID", "OBSERVER_RPC"
    )
    $lines = New-Object System.Collections.Generic.List[string]
    foreach ($key in $order) {
        if ($Ports.ContainsKey($key) -and $Ports[$key]) {
            [void]$lines.Add("$key=$($Ports[$key])")
        }
    }
    foreach ($key in ($Ports.Keys | Sort-Object)) {
        if ($order -contains $key) { continue }
        if ($Ports[$key]) { [void]$lines.Add("$key=$($Ports[$key])") }
    }
    $tmp = "$Path.tmp.$PID"
    for ($i = 0; $i -lt 10; $i++) {
        try {
            [System.IO.File]::WriteAllLines($tmp, $lines.ToArray(), $enc)
            Move-Item -Force $tmp $Path
            return
        } catch {
            if ($i -eq 9) { throw }
            Start-Sleep -Milliseconds 200
        }
    }
}

function Set-DevnetPort {
    param(
        [string]$Path,
        [string]$Key,
        [string]$Value
    )
    Invoke-DevnetPortsLocked {
        $ports = Try-Read-DevnetPortsFile -Path $Path
        $ports[$Key] = $Value
        Write-DevnetPortsFile -Path $Path -Ports $ports
    } | Out-Null
}

function Remove-DevnetPortsFile {
    param([string]$Path)
    Invoke-DevnetPortsLocked {
        if (Test-Path $Path) {
            Remove-Item -Force $Path
        }
    } | Out-Null
}

function Get-SoakLockPath {
    param([string]$ScriptDir)
    return Join-Path $ScriptDir ".soak-active.lock"
}

function Test-SoakLockActive {
    param([string]$ScriptDir)
    $lockPath = Get-SoakLockPath -ScriptDir $ScriptDir
    if (-not (Test-Path $lockPath)) { return $false }
    $lines = Get-Content $lockPath -ErrorAction SilentlyContinue
    foreach ($line in $lines) {
        if ($line -match "^pid=(\d+)$") {
            $lockPid = [int]$Matches[1]
            if (Get-Process -Id $lockPid -ErrorAction SilentlyContinue) { return $true }
        }
    }
    return $false
}

function Assert-SoakNotActive {
    param([string]$ScriptDir, [string]$Caller)
    if ($env:MFN_SOAK_BOOTSTRAP -eq "1") { return }
    if (Test-SoakLockActive -ScriptDir $ScriptDir) {
        $lockPath = Get-SoakLockPath -ScriptDir $ScriptDir
        throw "${Caller}: soak in progress ($lockPath); wait for soak to finish or remove stale lock if no soak is running"
    }
}

function New-SoakLock {
    param([string]$ScriptDir)
    $lockPath = Get-SoakLockPath -ScriptDir $ScriptDir
    $stamp = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
    @(
        "pid=$PID"
        "started_at=$stamp"
    ) | Set-Content -Path $lockPath -Encoding utf8
}

function Remove-SoakLock {
    param([string]$ScriptDir)
    $lockPath = Get-SoakLockPath -ScriptDir $ScriptDir
    if (Test-Path $lockPath) {
        Remove-Item -Force $lockPath
    }
}

# Query hub tip height via mfn-cli, falling back to get_status JSON-RPC (M2.5.9).
function Get-TipHeightFromRpc {
    param(
        [string]$RpcAddr,
        [string]$MfnCli = ""
    )
    if ($MfnCli -and (Test-Path $MfnCli)) {
        $tipOut = & $MfnCli --rpc $RpcAddr tip 2>$null
        if ($LASTEXITCODE -eq 0) {
            $tipText = ($tipOut | Out-String)
            if ($tipText -match "(^|\s)tip_height=([0-9]+)") { return $Matches[2] }
            if ($tipText -match "(^|\s)tip_height=none") { return "0" }
        }
    }
    $hostPart, $portPart = $RpcAddr -split ":", 2
    if (-not $portPart) { return "unknown" }
    $req = '{"jsonrpc":"2.0","method":"get_status","id":1}'
    try {
        $line = Invoke-WebRequest -Uri "http://${hostPart}:${portPart}/" -Method POST -Body $req -ContentType "application/json" -TimeoutSec 5 -UseBasicParsing -ErrorAction Stop | Select-Object -ExpandProperty Content
        if ($line -match '"tip_height":(\d+)') { return $Matches[1] }
        if ($line -match '"tip_height":null') { return "0" }
    } catch {
        return "unknown"
    }
    return "unknown"
}
