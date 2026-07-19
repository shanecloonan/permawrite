# Validate release JSON artifacts against the repository's published schemas.
param(
    [Parameter(Mandatory = $true)][string]$Schema,
    [Parameter(Mandatory = $true)][string]$Json
)
$ErrorActionPreference = "Stop"

if (-not (Test-Path -LiteralPath $Schema -PathType Leaf)) {
    throw "release-json-schema-validate: missing schema $Schema"
}
if (-not (Test-Path -LiteralPath $Json -PathType Leaf)) {
    throw "release-json-schema-validate: missing JSON $Json"
}

$schemaDoc = Get-Content -LiteralPath $Schema -Raw | ConvertFrom-Json
$jsonDoc = Get-Content -LiteralPath $Json -Raw | ConvertFrom-Json
$issues = New-Object System.Collections.Generic.List[string]

function Add-Issue {
    param([string]$Path, [string]$Message)
    $script:issues.Add("${Path}: $Message") | Out-Null
}

function Has-Property {
    param($Object, [string]$Name)
    return $null -ne $Object -and $Object.PSObject.Properties.Name -contains $Name
}

function Get-JsonType {
    param($Value)
    if ($null -eq $Value) { return "null" }
    # pwsh 7 ConvertFrom-Json coerces ISO-8601 strings to DateTime; the JSON value is a string.
    if ($Value -is [datetime] -or $Value -is [System.DateTimeOffset]) { return "string" }
    if ($Value -is [bool]) { return "boolean" }
    if ($Value -is [byte] -or $Value -is [int16] -or $Value -is [int32] -or $Value -is [int64]) { return "integer" }
    if ($Value -is [single] -or $Value -is [double] -or $Value -is [decimal]) { return "number" }
    if ($Value -is [string]) { return "string" }
    if ($Value -is [System.Collections.IEnumerable] -and $Value -isnot [string] -and $Value -isnot [pscustomobject]) { return "array" }
    if ($Value -is [pscustomobject]) { return "object" }
    return $Value.GetType().Name
}

function Resolve-LocalRef {
    param([string]$Ref)
    if (-not $Ref.StartsWith("#/")) {
        throw "release-json-schema-validate: unsupported non-local `$ref $Ref"
    }
    $current = $script:schemaDoc
    foreach ($segment in $Ref.Substring(2).Split("/")) {
        $name = $segment.Replace("~1", "/").Replace("~0", "~")
        $current = $current.$name
    }
    return $current
}

function Convert-ToArray {
    param($Value)
    if ($null -eq $Value) { return @() }
    if ($Value -is [System.Array]) { return @($Value) }
    return @($Value)
}

function Test-SchemaNode {
    param($NodeSchema, $Value, [string]$Path)

    if (Has-Property $NodeSchema '$ref') {
        Test-SchemaNode -NodeSchema (Resolve-LocalRef $NodeSchema.'$ref') -Value $Value -Path $Path
        return
    }

    if (Has-Property $NodeSchema "const") {
        $expected = $NodeSchema.const
        if (($Value | ConvertTo-Json -Depth 20 -Compress) -ne ($expected | ConvertTo-Json -Depth 20 -Compress)) {
            Add-Issue $Path "expected const '$expected'"
        }
    }

    if (Has-Property $NodeSchema "enum") {
        $allowed = Convert-ToArray $NodeSchema.enum
        $matched = $false
        foreach ($candidate in $allowed) {
            if (($Value | ConvertTo-Json -Depth 20 -Compress) -eq ($candidate | ConvertTo-Json -Depth 20 -Compress)) {
                $matched = $true
                break
            }
        }
        if (-not $matched) {
            Add-Issue $Path "expected one of $($allowed -join ', ')"
        }
    }

    if (Has-Property $NodeSchema "type") {
        $expectedTypes = Convert-ToArray $NodeSchema.type
        $actualType = Get-JsonType $Value
        if ($expectedTypes -notcontains $actualType) {
            Add-Issue $Path "expected type $($expectedTypes -join '/'), got $actualType"
            return
        }
    }

    if ($Value -is [pscustomobject]) {
        $required = if (Has-Property $NodeSchema "required") { Convert-ToArray $NodeSchema.required } else { @() }
        $properties = if (Has-Property $NodeSchema "properties") { $NodeSchema.properties } else { [pscustomobject]@{} }
        foreach ($name in $required) {
            if (-not (Has-Property $Value $name)) {
                Add-Issue $Path "missing required property $name"
            }
        }
        if ((Has-Property $NodeSchema "additionalProperties") -and $NodeSchema.additionalProperties -eq $false) {
            $allowed = @($properties.PSObject.Properties.Name)
            foreach ($property in $Value.PSObject.Properties.Name) {
                if ($allowed -notcontains $property) {
                    Add-Issue $Path "additional property $property is not allowed"
                }
            }
        }
        foreach ($property in $properties.PSObject.Properties) {
            if (Has-Property $Value $property.Name) {
                Test-SchemaNode -NodeSchema $property.Value -Value $Value.($property.Name) -Path "$Path.$($property.Name)"
            }
        }
    }

    if ((Get-JsonType $Value) -eq "array" -and (Has-Property $NodeSchema "items")) {
        $items = Convert-ToArray $Value
        for ($i = 0; $i -lt $items.Count; $i++) {
            Test-SchemaNode -NodeSchema $NodeSchema.items -Value $items[$i] -Path "$Path[$i]"
        }
    }
}

Test-SchemaNode -NodeSchema $schemaDoc -Value $jsonDoc -Path '$'

if ($issues.Count -gt 0) {
    $issues | ForEach-Object { [Console]::Error.WriteLine("release-json-schema-validate: $_") }
    exit 1
}

Write-Output "release-json-schema-validate: OK"
