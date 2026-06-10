param(
    [string]$Python = "",
    [string]$SourceRoot = "",
    [string]$OutputDir = "",
    [ValidateSet("auto", "pyinstaller", "nuitka")]
    [string]$Backend = "auto",
    [int]$Jobs = 0,
    [switch]$Force
)

$ErrorActionPreference = "Stop"

function Resolve-RepoRoot {
    $scriptDir = Split-Path -Parent $PSCommandPath
    return (Resolve-Path (Join-Path $scriptDir "..")).Path
}

function Resolve-Python {
    param([string]$Requested)
    if ($Requested) {
        $resolved = Resolve-Path -LiteralPath $Requested -ErrorAction Stop
        return $resolved.Path
    }
    $py = Get-Command py.exe -ErrorAction SilentlyContinue
    if ($py) {
        $candidate = (& $py.Source -3.12 -c "import sys; print(sys.executable)" 2>$null)
        if ($LASTEXITCODE -eq 0 -and $candidate) {
            return [string]$candidate
        }
    }
    $candidateRoots = @(
        "$env:LOCALAPPDATA\AiDA\runtimes\python\Python312-3.12.10-x64\python.exe",
        "$env:LOCALAPPDATA\Programs\Python\Python313\python.exe",
        "$env:LOCALAPPDATA\Programs\Python\Python312\python.exe"
    )
    foreach ($candidate in $candidateRoots) {
        if ($candidate -and [IO.File]::Exists($candidate)) {
            return $candidate
        }
    }
    throw "Python 3.12 or 3.13 is required to build the frozen Camoufox reverse MCP executable."
}

$repoRoot = Resolve-RepoRoot
if (-not $SourceRoot) {
    $SourceRoot = Join-Path $repoRoot "camoufox-reverse-mcp"
}
if (-not $OutputDir) {
    $OutputDir = Join-Path $repoRoot ".deps"
}

$SourceRoot = (Resolve-Path -LiteralPath $SourceRoot -ErrorAction Stop).Path
if (-not [IO.File]::Exists((Join-Path $SourceRoot "pyproject.toml"))) {
    throw "camoufox-reverse-mcp pyproject.toml was not found at $SourceRoot"
}

$Python = Resolve-Python $Python
$version = (& $Python -c "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}')")
if ($LASTEXITCODE -ne 0 -or -not ($version -match '^3\.(12|13)$')) {
    throw "Nuitka build requires Python 3.12 or 3.13; got $version from $Python"
}

New-Item -ItemType Directory -Force -Path $OutputDir | Out-Null
$OutputDir = (Resolve-Path -LiteralPath $OutputDir).Path
if ($Jobs -lt 1) {
    $Jobs = [Math]::Max(1, [Math]::Min(8, [Environment]::ProcessorCount - 1))
}
$target = Join-Path $OutputDir "AiDA_CamoufoxReverseMcp.exe"
if ([IO.File]::Exists($target) -and -not $Force) {
    Write-Output "frozen_mcp_exists=$target"
    exit 0
}

$stamp = Get-Date -Format "yyyyMMddHHmmss"
$workRoot = Join-Path $OutputDir ".camoufox-reverse-mcp-build-$stamp"
$venv = Join-Path $workRoot "venv"
$buildOut = Join-Path $workRoot "nuitka-out"
New-Item -ItemType Directory -Force -Path $workRoot | Out-Null

try {
    & $Python -m venv $venv
    if ($LASTEXITCODE -ne 0) { throw "venv creation failed" }
    $venvPython = Join-Path $venv "Scripts\python.exe"
    & $venvPython -m pip install --upgrade pip wheel setuptools nuitka zstandard ordered-set pyinstaller
    if ($LASTEXITCODE -ne 0) { throw "build dependency install failed" }
    & $venvPython -m pip install $SourceRoot
    if ($LASTEXITCODE -ne 0) { throw "camoufox-reverse-mcp dependency install failed" }
    $entry = Join-Path $workRoot "aida_camoufox_reverse_mcp_launcher.py"
    @"
from camoufox_reverse_mcp.__main__ import main

if __name__ == "__main__":
    main()
"@ | Set-Content -LiteralPath $entry -Encoding UTF8
    $selectedBackend = $Backend.ToLowerInvariant()
    if ($selectedBackend -eq "auto") { $selectedBackend = "pyinstaller" }
    if ($selectedBackend -eq "pyinstaller") {
        $pyiWork = Join-Path $workRoot "pyinstaller-work"
        $pyiSpec = Join-Path $workRoot "pyinstaller-spec"
        & $venvPython -m PyInstaller `
            --noconfirm `
            --clean `
            --onefile `
            --console `
            --noupx `
            --name AiDA_CamoufoxReverseMcp `
            --distpath $OutputDir `
            --workpath $pyiWork `
            --specpath $pyiSpec `
            --collect-submodules camoufox_reverse_mcp `
            --collect-data camoufox_reverse_mcp `
            --collect-submodules camoufox `
            --collect-data camoufox `
            --collect-submodules playwright `
            --collect-data playwright `
            --collect-submodules esprima `
            --hidden-import mcp.server.fastmcp `
            --hidden-import mcp.server.stdio `
            --hidden-import mcp.shared.session `
            --hidden-import mcp.shared.message `
            --hidden-import mcp.types `
            $entry
        if ($LASTEXITCODE -ne 0) { throw "PyInstaller build failed" }
    } elseif ($selectedBackend -eq "nuitka") {
        & $venvPython -m nuitka `
            --standalone `
            --onefile `
            --assume-yes-for-downloads `
            --remove-output `
            --disable-cache=ccache `
            --jobs=$Jobs `
            --output-dir=$buildOut `
            --output-filename=AiDA_CamoufoxReverseMcp.exe `
            --include-package=camoufox_reverse_mcp `
            --include-package-data=camoufox_reverse_mcp `
            --include-package=mcp `
            --include-package=camoufox `
            --include-package=playwright `
            --include-package=esprima `
            $entry
        if ($LASTEXITCODE -ne 0) { throw "Nuitka build failed" }
        $built = Join-Path $buildOut "AiDA_CamoufoxReverseMcp.exe"
        if (-not [IO.File]::Exists($built)) { throw "Nuitka output executable was not produced" }
        Copy-Item -LiteralPath $built -Destination $target -Force
    } else {
        throw "Unsupported backend: $Backend"
    }
    if (-not [IO.File]::Exists($target)) { throw "Frozen executable was not produced" }
    $hash = (Get-FileHash -Algorithm SHA256 -LiteralPath $target).Hash.ToLowerInvariant()
    $size = (Get-Item -LiteralPath $target).Length
    Write-Output "frozen_mcp_backend=$selectedBackend"
    Write-Output "frozen_mcp_built=$target"
    Write-Output "frozen_mcp_size=$size"
    Write-Output "frozen_mcp_sha256=$hash"
} finally {
    if ([IO.Directory]::Exists($workRoot)) {
        Remove-Item -LiteralPath $workRoot -Recurse -Force -ErrorAction SilentlyContinue
    }
}
