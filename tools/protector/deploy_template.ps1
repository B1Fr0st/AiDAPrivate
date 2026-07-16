[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$TemplatePath,

    [Parameter(Mandatory = $true)]
    [string]$MetadataPath,

    [Parameter(Mandatory = $false)]
    [string]$ServerUrl = "https://api.aidapro.net",

    [Parameter(Mandatory = $true)]
    [string]$AdminKeyB64,

    [Parameter(Mandatory = $false)]
    [string]$SshHost = "ruarr@23.88.62.199",

    [Parameter(Mandatory = $false)]
    [string]$SshKeyPath = (Join-Path $env:USERPROFILE ".ssh\aida_server"),

    [Parameter(Mandatory = $false)]
    [string]$RemoteTemplateDir = "/var/aida/templates"
)

$ErrorActionPreference = "Stop"

function Write-LogProgress {
    param([string]$Message)
    $ts = Get-Date -Format "yyyy-MM-dd HH:mm:ss.fff"
    Write-Host "[$ts] $Message"
}

function ConvertTo-CanonicalAdminJson {
    param([hashtable]$Data)
    $filtered = [ordered]@{}
    $keys = $Data.Keys | Where-Object { $_ -notmatch '^__' -and $_ -ne 'signature' } | Sort-Object
    foreach ($k in $keys) {
        $filtered[$k] = $Data[$k]
    }
    $sb = [System.Text.StringBuilder]::new()
    [void]$sb.Append('{')
    $first = $true
    foreach ($k in $filtered.Keys) {
        if (-not $first) { [void]$sb.Append(',') }
        $first = $false
        $keyJson = ConvertTo-Json $k -Compress
        $valJson = ConvertTo-Json $filtered[$k] -Depth 10 -Compress
        [void]$sb.Append($keyJson)
        [void]$sb.Append(':')
        [void]$sb.Append($valJson)
    }
    [void]$sb.Append('}')
    return $sb.ToString()
}

function Compute-AdminHmac {
    param([string]$CanonicalJson, [string]$KeyB64)
    $keyBytes = [System.Convert]::FromBase64String($KeyB64)
    $hmac = [System.Security.Cryptography.HMACSHA256]::new($keyBytes)
    $jsonBytes = [System.Text.Encoding]::UTF8.GetBytes($CanonicalJson)
    $hashBytes = $hmac.ComputeHash($jsonBytes)
    $hmac.Dispose()
    return [BitConverter]::ToString($hashBytes) -replace '-', '' | ForEach-Object { $_.ToLower() }
}

if (-not (Test-Path -LiteralPath $TemplatePath)) {
    Write-Error "Template binary not found: $TemplatePath"
    exit 1
}

if (-not (Test-Path -LiteralPath $MetadataPath)) {
    Write-Error "Metadata file not found: $MetadataPath"
    exit 1
}

$templateItem = Get-Item -LiteralPath $TemplatePath

Write-LogProgress "Starting template deployment"
Write-LogProgress "  Template:  $TemplatePath ($($templateItem.Length) bytes)"
Write-LogProgress "  Metadata:  $MetadataPath"
Write-LogProgress "  Server:    $ServerUrl"
Write-LogProgress "  SSH Host:  $SshHost"

Write-LogProgress "Computing SHA-256 hash of template binary"
$templateHash = (Get-FileHash -LiteralPath $TemplatePath -Algorithm SHA256).Hash
Write-LogProgress "  SHA-256:   $templateHash"

$metadataJson = Get-Content -LiteralPath $MetadataPath -Raw
try {
    $metadataObj = $metadataJson | ConvertFrom-Json
} catch {
    Write-Error "Metadata file is not valid JSON: $_"
    exit 1
}

$templateVersion = [int]$metadataObj.version
if (-not $templateVersion -or $templateVersion -le 0) {
    Write-Error "Metadata is missing a valid 'version' field"
    exit 1
}

$testVector = ""
if ($null -ne $metadataObj.test_vector) {
    $testVector = [string]$metadataObj.test_vector
} elseif ($null -ne $metadataObj.template_test_vector) {
    $testVector = [string]$metadataObj.template_test_vector
}
$testVector = $testVector.Trim().ToLower()
if (-not ($testVector -match '^[0-9a-f]{64}$')) {
    Write-Error "Metadata is missing a valid test_vector (64 hex chars)"
    exit 1
}

$metadataForServer = @{}
if ($null -ne $metadataObj.metadata -and $metadataObj.metadata -is [string]) {
    $metadataForServer = ($metadataObj.metadata | ConvertFrom-Json -AsHashtable)
} elseif ($null -ne $metadataObj.metadata) {
    $metadataForServer = $metadataObj.metadata
}

$remoteFilename = "AiDAStandalone_template_v$templateVersion.exe"
$remoteTmpPath = "$RemoteTemplateDir/.tmp_$remoteFilename"

Write-LogProgress "SCP template binary to $SshHost`:$remoteTmpPath"

$sshOpts = @('-o', 'StrictHostKeyChecking=yes', '-o', 'IdentitiesOnly=yes', '-o', 'PasswordAuthentication=no', '-i', $SshKeyPath)

$scpArgs = @('-T') + $sshOpts + @($TemplatePath, "${SshHost}:$remoteTmpPath")
Write-LogProgress "  Running: scp $scpArgs"
& scp @scpArgs
$scpExit = $LASTEXITCODE
if ($scpExit -ne 0) {
    Write-LogProgress "SCP FAILED: exit code $scpExit"
    Write-Error "Failed to SCP template binary to server"
    exit 1
}
Write-LogProgress "SCP complete"

$ts = [DateTimeOffset]::UtcNow.ToUnixTimeSeconds()
$nonceBytes = New-Object byte[] 16
$rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
$rng.GetBytes($nonceBytes)
$rng.Dispose()
$nonceHex = [BitConverter]::ToString($nonceBytes) -replace '-', '' | ForEach-Object { $_.ToLower() }

$requestBody = [ordered]@{
    version      = $templateVersion
    filename     = $remoteFilename
    file_sha256  = $templateHash.ToLower()
    file_size    = [int64]$templateItem.Length
    metadata     = $metadataForServer
    test_vector  = $testVector
    ts           = $ts
    nonce        = $nonceHex
}

$canonicalJson = ConvertTo-CanonicalAdminJson -Data $requestBody
$signatureHex = Compute-AdminHmac -CanonicalJson $canonicalJson -KeyB64 $AdminKeyB64

$sendBody = $requestBody.Clone()
$sendBody['signature'] = $signatureHex
$bodyJson = $sendBody | ConvertTo-Json -Depth 10

$activateUrl = "$ServerUrl/api/build/activate-template"

$requestHeaders = @{
    "Content-Type"     = "application/json"
    "X-Admin-Signature" = $signatureHex
}

Write-LogProgress "Calling POST $activateUrl"

try {
    $response = Invoke-WebRequest -Uri $activateUrl -Method Post -Headers $requestHeaders -Body $bodyJson -UseBasicParsing -TimeoutSec 120
} catch [System.Net.WebException] {
    $statusCode = 0
    $responseBody = ""
    if ($null -ne $_.Exception.Response) {
        $statusCode = [int]$_.Exception.Response.StatusCode
        try {
            $reader = New-Object System.IO.StreamReader($_.Exception.Response.GetResponseStream())
            $responseBody = $reader.ReadToEnd()
        } catch {}
    }
    Write-LogProgress "Activate FAILED: HTTP $statusCode"
    Write-LogProgress "  Response: $responseBody"
    Write-Error "Template activation failed with HTTP $statusCode"
    exit 1
} catch {
    Write-LogProgress "Activate FAILED: $_"
    Write-Error "Template activation failed: $_"
    exit 1
}

$statusCode = [int]$response.StatusCode
$responseContent = $response.Content

Write-LogProgress "Activate response: HTTP $statusCode"
Write-LogProgress "  Body: $responseContent"

$success = $false
$serverHash = ""
try {
    $respJson = $responseContent | ConvertFrom-Json
    if ($respJson.status -eq 'ok') {
        $success = $true
    }
    if ($null -ne $respJson.file_sha256) {
        $serverHash = [string]$respJson.file_sha256
    }
} catch {
    if ($statusCode -ge 200 -and $statusCode -lt 300) {
        $success = $true
    }
}

if (-not $success) {
    Write-LogProgress "Server rejected template activation"
    Write-LogProgress "  Response: $responseContent"
    Write-Error "Server rejected template activation"
    exit 1
}

Write-LogProgress "Server accepted template"

if ($serverHash -ne "" -and $serverHash.ToLower() -ne $templateHash.ToLower()) {
    Write-LogProgress "WARNING: Server hash mismatch"
    Write-LogProgress "  Local:  $templateHash"
    Write-LogProgress "  Server: $serverHash"
    Write-Error "Integrity check failed: server hash does not match local hash"
    exit 1
}

Write-LogProgress "Integrity check passed"
Write-LogProgress "  SHA-256: $templateHash"
Write-LogProgress "Template activation successful"
