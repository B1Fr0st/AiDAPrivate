param(
    [Parameter(Mandatory = $true)]
    [string]$LicenseKey,

    [string]$Hwid = "test123456",

    [string]$ClientNonce = "aabbccdd11223344aabbccdd11223344",

    [string]$OutputPath = $(Join-Path $PSScriptRoot "license-validation-response.json")
)

$ErrorActionPreference = "Stop"

$timestamp = [DateTimeOffset]::UtcNow.ToUnixTimeSeconds()
$uri = "https://europe-west1-aida-license-prod.cloudfunctions.net/validateLicense"

$bodyObject = @{
    action = "validate"
    license_key = $LicenseKey
    hwid = $Hwid
    client_nonce = $ClientNonce
    timestamp = $timestamp
}

$bodyJson = $bodyObject | ConvertTo-Json -Compress

$responseObject = $null

try {
    $responseObject = Invoke-RestMethod -Method POST -Uri $uri -ContentType "application/json" -Body $bodyJson
}
catch {
    $errorResponse = $_.Exception.Response
    if ($null -ne $errorResponse) {
        $reader = New-Object System.IO.StreamReader($errorResponse.GetResponseStream())
        $rawBody = $reader.ReadToEnd()
        $reader.Dispose()

        try {
            $responseObject = $rawBody | ConvertFrom-Json
        }
        catch {
            $responseObject = [pscustomobject]@{
                status = "http_error"
                reason = $_.Exception.Message
                raw_body = $rawBody
            }
        }
    }
    else {
        throw
    }
}

$output = [pscustomobject]@{
    requested_at_utc = [DateTime]::UtcNow.ToString("o")
    request = $bodyObject
    response = $responseObject
}

$output | ConvertTo-Json -Depth 10 | Set-Content -Path $OutputPath -Encoding UTF8

Write-Host "Saved validation response to $OutputPath"
$responseObject | Format-List *