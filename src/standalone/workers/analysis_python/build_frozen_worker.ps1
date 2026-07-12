[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidateScript({ Test-Path -LiteralPath $_ -PathType Leaf })]
    [string]$PythonExe,
    [Parameter(Mandatory = $true)]
    [string]$OutputDirectory,
    [switch]$Force
)

$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $MyInvocation.MyCommand.Path
$python = (Resolve-Path -LiteralPath $PythonExe).Path
$output = [IO.Path]::GetFullPath($OutputDirectory)
$normalizedPython = $python.ToLowerInvariant()
if ($normalizedPython.Contains('camoufox')) { throw 'analysis Python worker build cannot use a browser runtime' }
$script = Join-Path $root 'analysis_python_worker.py'
if (-not (Test-Path -LiteralPath $script -PathType Leaf)) { throw 'analysis Python worker source is missing' }
$version = & $python -c 'import sys; print("%d.%d" % sys.version_info[:2])'
if ($LASTEXITCODE -ne 0 -or $version -notmatch '^3\.(1[1-9]|[2-9][0-9])$') { throw 'Python 3.11 or later is required to freeze the analysis worker' }
$work = Join-Path $output '.analysis-python-worker-build'
$dist = Join-Path $work 'dist'
$build = Join-Path $work 'build'
$spec = Join-Path $work 'spec'
$worker = Join-Path $dist 'AiDA_AnalysisPythonWorker.exe'
if (Test-Path -LiteralPath $worker) {
    if (-not $Force) { throw 'frozen worker already exists; pass -Force to replace it' }
    Remove-Item -LiteralPath $worker -Force
}
New-Item -ItemType Directory -Path $dist -Force | Out-Null
New-Item -ItemType Directory -Path $build -Force | Out-Null
New-Item -ItemType Directory -Path $spec -Force | Out-Null
& $python -m PyInstaller --noconfirm --clean --onefile --noupx --name AiDA_AnalysisPythonWorker --distpath $dist --workpath $build --specpath $spec $script
if ($LASTEXITCODE -ne 0 -or -not (Test-Path -LiteralPath $worker -PathType Leaf)) { throw 'frozen analysis Python worker was not produced' }
$target = Join-Path $output 'AiDA_AnalysisPythonWorker.exe'
Copy-Item -LiteralPath $worker -Destination $target -Force
Get-FileHash -Algorithm SHA256 -LiteralPath $target | Select-Object Path,Hash
