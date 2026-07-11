[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$TemplatePath,

    [Parameter(Mandatory = $true)]
    [string]$MetadataPath,

    [Parameter(Mandatory = $false)]
    [string]$ServerUrl = "https://api.aidapro.net",

    [Parameter(Mandatory = $true)]
    [string]$ApiKey
)

$ErrorActionPreference = "Stop"

function Write-LogProgress {
    param([string]$Message)
    $ts = Get-Date -Format "yyyy-MM-dd HH:mm:ss.fff"
    Write-Host "[$ts] $Message"
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
$metadataItem = Get-Item -LiteralPath $MetadataPath

Write-LogProgress "Starting template upload"
Write-LogProgress "  Template:  $TemplatePath ($($templateItem.Length) bytes)"
Write-LogProgress "  Metadata:  $MetadataPath ($($metadataItem.Length) bytes)"
Write-LogProgress "  Server:    $ServerUrl"

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

$metadataObj | Add-Member -NotePropertyName "template_sha256" -NotePropertyValue $templateHash -Force
$metadataObj | Add-Member -NotePropertyName "template_size" -NotePropertyValue $templateItem.Length -Force
$updatedMetadataJson = $metadataObj | ConvertTo-Json -Depth 10

$boundary = "----AiDATemplateBoundary$([System.Guid]::NewGuid().ToString('N'))"
$LF = "`r`n"

$templateBytes = [System.IO.File]::ReadAllBytes($TemplatePath)
$encoding = [System.Text.Encoding]::GetEncoding("iso-8859-1")
$templateString = $encoding.GetString($templateBytes)

$bodyParts = New-Object System.Collections.Generic.List[string]

$bodyParts.Add("--$boundary$LF")
$bodyParts.Add("Content-Disposition: form-data; name=`"template`"; filename=`"$($templateItem.Name)`"$LF")
$bodyParts.Add("Content-Type: application/octet-stream$LF$LF")
$bodyParts.Add($templateString)
$bodyParts.Add("$LF--$boundary$LF")
$bodyParts.Add("Content-Disposition: form-data; name=`"metadata`"; filename=`"$($metadataItem.Name)`"$LF")
$bodyParts.Add("Content-Type: application/json$LF$LF")
$bodyParts.Add($updatedMetadataJson)
$bodyParts.Add("$LF--$boundary--$LF")

$bodyString = $bodyParts -join ''
$bodyBytes = $encoding.GetBytes($bodyString)

$uploadUrl = "$ServerUrl/api/build/upload-template"

$headers = @{
    "X-AiDA-Key"       = $ApiKey
    "X-AiDA-Hash"      = $templateHash
    "X-AiDA-Timestamp" = [DateTimeOffset]::UtcNow.ToUnixTimeSeconds().ToString()
}

Write-LogProgress "Uploading to $uploadUrl"

try {
    $response = Invoke-WebRequest -Uri $uploadUrl -Method Post -Headers $headers -Body $bodyBytes -ContentType "multipart/form-data; boundary=$boundary" -UseBasicParsing -TimeoutSec 120
} catch [System.Net.WebException] {
    $statusCode = 0
    if ($null -ne $_.Exception.Response) {
        $statusCode = [int]$_.Exception.Response.StatusCode
    }
    $responseBody = ""
    if ($null -ne $_.Exception.Response) {
        try {
            $reader = New-Object System.IO.StreamReader($_.Exception.Response.GetResponseStream())
            $responseBody = $reader.ReadToEnd()
        } catch {}
    }
    Write-LogProgress "Upload FAILED: HTTP $statusCode"
    Write-LogProgress "  Response: $responseBody"
    Write-Error "Template upload failed with HTTP $statusCode"
    exit 1
} catch {
    Write-LogProgress "Upload FAILED: $_"
    Write-Error "Template upload failed: $_"
    exit 1
}

$statusCode = [int]$response.StatusCode
$responseContent = $response.Content

Write-LogProgress "Upload complete: HTTP $statusCode"

$success = $false
$serverHash = ""
try {
    $respJson = $responseContent | ConvertFrom-Json
    if ($respJson.success -eq $true) {
        $success = $true
    }
    if ($null -ne $respJson.template_hash) {
        $serverHash = $respJson.template_hash
    }
} catch {
    if ($statusCode -ge 200 -and $statusCode -lt 300) {
        $success = $true
    }
}

if (-not $success) {
    Write-LogProgress "Upload rejected by server"
    Write-LogProgress "  Response: $responseContent"
    Write-Error "Server rejected template upload"
    exit 1
}

Write-LogProgress "Server accepted template"

if ($serverHash -ne "" -and $serverHash -ne $templateHash) {
    Write-LogProgress "WARNING: Server hash mismatch"
    Write-LogProgress "  Local:  $templateHash"
    Write-LogProgress "  Server: $serverHash"
    Write-Error "Integrity check failed: server hash does not match local hash"
    exit 1
}

Write-LogProgress "Integrity check passed"
Write-LogProgress "  SHA-256: $templateHash"
Write-LogProgress "Template upload successful"
