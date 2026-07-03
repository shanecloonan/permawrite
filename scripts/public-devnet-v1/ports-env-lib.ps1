# Shared devnet-ports.env read/write helpers (UTF-8 no BOM, atomic rewrite).

function Get-DevnetPortsEncoding {
    [System.Text.UTF8Encoding]::new($false)
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
        [hashtable]$Ports,
        [string]$Key,
        [string]$Value
    )
    $Ports[$Key] = $Value
    Write-DevnetPortsFile -Path $Path -Ports $Ports
}
