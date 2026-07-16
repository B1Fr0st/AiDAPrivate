[CmdletBinding()]
param(
    [string]$RepositoryRoot = (Join-Path $PSScriptRoot '..')
)

$ErrorActionPreference = 'Stop'
$ResolvedRepositoryRoot = [System.IO.Path]::GetFullPath($RepositoryRoot)
$DependencyRoot = [System.IO.Path]::GetFullPath((Join-Path $ResolvedRepositoryRoot '.deps'))
$Target = [System.IO.Path]::GetFullPath((Join-Path $DependencyRoot 'imgui-src'))
$LockPath = [System.IO.Path]::GetFullPath((Join-Path $ResolvedRepositoryRoot 'cmake\aida_imgui_dependency.lock.json'))
$Lock = Get-Content -Raw -LiteralPath $LockPath | ConvertFrom-Json
$ExpectedCommit = [string]$Lock.commit
$ExpectedTree = [string]$Lock.tree
$Staging = Join-Path $DependencyRoot ('imgui-src.staging.' + [Guid]::NewGuid().ToString('N'))
$Backup = Join-Path $DependencyRoot ('imgui-src.backup.' + [Guid]::NewGuid().ToString('N'))
$DependencyPrefix = $DependencyRoot.TrimEnd([System.IO.Path]::DirectorySeparatorChar) + [System.IO.Path]::DirectorySeparatorChar

if ($Lock.schemaVersion -ne 1 -or $Lock.name -cne 'dear-imgui' -or
    $Lock.version -cne '1.92.1' -or $Lock.versionNum -ne 19210 -or
    $Lock.branch -cne 'docking' -or $Lock.tag -cne 'v1.92.1-docking' -or
    $ExpectedCommit -cne '44aa9a4b3a6f27d09a4eb5770d095cbd376dfc4b' -or
    $ExpectedTree -cne '7b2a8d999b74caf2d517911dd2403abf35e86632') {
    throw 'Dear ImGui dependency lock is not the approved AiDA authority'
}
if (-not $Target.StartsWith($DependencyPrefix, [System.StringComparison]::OrdinalIgnoreCase) -or
    -not ([System.IO.Path]::GetFullPath($Staging)).StartsWith($DependencyPrefix, [System.StringComparison]::OrdinalIgnoreCase) -or
    -not ([System.IO.Path]::GetFullPath($Backup)).StartsWith($DependencyPrefix, [System.StringComparison]::OrdinalIgnoreCase)) {
    throw 'Dear ImGui dependency target escaped the repository dependency root'
}

New-Item -ItemType Directory -Path $DependencyRoot -Force | Out-Null
try {
    & git clone --filter=blob:none --no-checkout --no-tags -- $Lock.repository $Staging
    if ($LASTEXITCODE -ne 0) { throw 'Dear ImGui clone failed' }
    & git -C $Staging fetch --depth=1 origin $ExpectedCommit
    if ($LASTEXITCODE -ne 0) { throw 'Dear ImGui immutable commit fetch failed' }
    & git -C $Staging checkout --detach $ExpectedCommit
    if ($LASTEXITCODE -ne 0) { throw 'Dear ImGui immutable commit checkout failed' }
    $ActualCommit = (& git -C $Staging rev-parse HEAD).Trim()
    $ActualTree = (& git -C $Staging rev-parse 'HEAD^{tree}').Trim()
    if ($ActualCommit -cne $ExpectedCommit -or $ActualTree -cne $ExpectedTree) {
        throw 'Dear ImGui Git identity does not match the dependency lock'
    }
    $Seen = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::Ordinal)
    foreach ($File in @($Lock.files)) {
        $RelativePath = [string]$File.path
        if ($RelativePath -notmatch '^[A-Za-z0-9_.-]+(?:/[A-Za-z0-9_.-]+)*$' -or -not $Seen.Add($RelativePath)) {
            throw 'Dear ImGui dependency lock contains an invalid or duplicate path'
        }
        $AbsolutePath = [System.IO.Path]::GetFullPath((Join-Path $Staging $RelativePath))
        if (-not $AbsolutePath.StartsWith($Staging.TrimEnd([System.IO.Path]::DirectorySeparatorChar) + [System.IO.Path]::DirectorySeparatorChar, [System.StringComparison]::OrdinalIgnoreCase) -or
            -not (Test-Path -LiteralPath $AbsolutePath -PathType Leaf)) {
            throw "Dear ImGui dependency file is missing: $RelativePath"
        }
        $ActualSize = (Get-Item -LiteralPath $AbsolutePath).Length
        $ActualSha256 = (Get-FileHash -Algorithm SHA256 -LiteralPath $AbsolutePath).Hash.ToLowerInvariant()
        if ($ActualSize -ne [int64]$File.sizeBytes -or $ActualSha256 -cne [string]$File.sha256) {
            throw "Dear ImGui dependency file identity mismatch: $RelativePath"
        }
    }
    if (Test-Path -LiteralPath $Target) {
        Move-Item -LiteralPath $Target -Destination $Backup
    }
    Move-Item -LiteralPath $Staging -Destination $Target
    if (Test-Path -LiteralPath $Backup) {
        Remove-Item -Recurse -Force -LiteralPath $Backup
    }
}
catch {
    if (Test-Path -LiteralPath $Staging) {
        Remove-Item -Recurse -Force -LiteralPath $Staging
    }
    if ((Test-Path -LiteralPath $Backup) -and -not (Test-Path -LiteralPath $Target)) {
        Move-Item -LiteralPath $Backup -Destination $Target
    }
    throw
}

Write-Host "Dear ImGui $($Lock.tag) verified at $Target"
