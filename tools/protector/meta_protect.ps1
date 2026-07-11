param(
    [Parameter(Mandatory=$true)]
    [string]$PersonalizerPath,

    [Parameter(Mandatory=$true)]
    [string]$ProtectorPath,

    [string]$OutputPath,
    [string]$Watermark = "DEADDEADDEADDEADDEADDEADDEADDEAD",
    [string]$Seed = "0xDEADBEEFCAFEBABE"
)

$ErrorActionPreference = "Stop"

if (-not $OutputPath) {
    $OutputPath = "$PersonalizerPath.protected"
}

if (-not (Test-Path -LiteralPath $PersonalizerPath)) {
    Write-Error "Personalizer binary not found: $PersonalizerPath"
    exit 1
}

if (-not (Test-Path -LiteralPath $ProtectorPath)) {
    Write-Error "Protector binary not found: $ProtectorPath"
    exit 1
}

Write-Host "[meta-protect] Unprotected personalizer: $PersonalizerPath"
Write-Host "[meta-protect] Protector: $ProtectorPath"
Write-Host "[meta-protect] Output: $OutputPath"

$args = @(
    "--input", $PersonalizerPath,
    "--output", $OutputPath,
    "--all",
    "--embed-watermark",
    "--watermark", $Watermark,
    "--seed", $Seed
)

Write-Host "[meta-protect] Running: $ProtectorPath $($args -join ' ')"
& $ProtectorPath @args

if ($LASTEXITCODE -ne 0) {
    Write-Error "[meta-protect] Protector failed with exit code $LASTEXITCODE"
    exit 1
}

if (-not (Test-Path -LiteralPath $OutputPath)) {
    Write-Error "[meta-protect] Output file was not created: $OutputPath"
    exit 1
}

$unprotectedSize = (Get-Item $PersonalizerPath).Length
$protectedSize = (Get-Item $OutputPath).Length
Write-Host "[meta-protect] Unprotected size: $unprotectedSize bytes"
Write-Host "[meta-protect] Protected size: $protectedSize bytes"

if ($protectedSize -lt 1024) {
    Write-Error "[meta-protect] Protected output is suspiciously small ($protectedSize bytes)"
    exit 1
}

if ($unprotectedSize -gt 0) {
    $copy = Copy-Item -LiteralPath $PersonalizerPath -Destination "$PersonalizerPath.unprotected.bak" -Force
    Write-Host "[meta-protect] Unprotected backup saved: $PersonalizerPath.unprotected.bak"
}

Move-Item -LiteralPath $OutputPath -Destination $PersonalizerPath -Force
Write-Host "[meta-protect] Meta-protected personalizer replaces original: $PersonalizerPath"
Write-Host "[meta-protect] Done. Keep the .unprotected.bak file on LO's machine only."
