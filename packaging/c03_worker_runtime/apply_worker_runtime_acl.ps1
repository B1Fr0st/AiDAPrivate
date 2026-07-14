[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$PackageRoot,
    [Parameter(Mandatory = $true)]
    [ValidateSet('native', 'managed', 'analysis_python')]
    [string]$Policy,
    [Parameter(Mandatory = $true)]
    [string]$WorkerManifestDigest,
    [Parameter(Mandatory = $true)]
    [string]$OutputReceipt,
    [switch]$VerifyOnly
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$nativeSource = @'
using System;
using System.Runtime.InteropServices;
public static class AidaC03AppContainer {
    [DllImport("userenv.dll", CharSet = CharSet.Unicode)]
    public static extern int CreateAppContainerProfile(string name, string displayName, string description, IntPtr capabilities, uint capabilityCount, out IntPtr sid);
    [DllImport("userenv.dll", CharSet = CharSet.Unicode)]
    public static extern int DeriveAppContainerSidFromAppContainerName(string name, out IntPtr sid);
    [DllImport("advapi32.dll", SetLastError = true)]
    public static extern IntPtr FreeSid(IntPtr sid);
}
'@
Add-Type -TypeDefinition $nativeSource -Language CSharp

function Assert-RegularPath {
    param([string]$Path, [string]$Label)
    $item = Get-Item -LiteralPath $Path -Force -ErrorAction Stop
    if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
        throw "$Label must not be a reparse point"
    }
    return $item
}

function Resolve-PackagePath {
    param([string]$Root, [string]$Relative, [string]$Label)
    if (-not $Relative -or [IO.Path]::IsPathRooted($Relative) -or $Relative.Contains('\') -or
        $Relative.Contains(':') -or ($Relative -split '/' | Where-Object { $_ -eq '' -or $_ -eq '.' -or $_ -eq '..' })) {
        throw "$Label contains an unsafe relative path"
    }
    $rootFull = [IO.Path]::GetFullPath($Root).TrimEnd([IO.Path]::DirectorySeparatorChar)
    $path = [IO.Path]::GetFullPath((Join-Path $rootFull ($Relative -replace '/', '\')))
    if (-not $path.StartsWith($rootFull + [IO.Path]::DirectorySeparatorChar, [StringComparison]::OrdinalIgnoreCase)) {
        throw "$Label escapes the package root"
    }
    $cursor = $path
    while ($cursor.Length -ge $rootFull.Length) {
        if ([IO.File]::Exists($cursor) -or [IO.Directory]::Exists($cursor)) {
            Assert-RegularPath -Path $cursor -Label $Label | Out-Null
        }
        if ([string]::Equals($cursor.TrimEnd([IO.Path]::DirectorySeparatorChar), $rootFull, [StringComparison]::OrdinalIgnoreCase)) {
            break
        }
        $cursor = Split-Path -Parent $cursor
    }
    return $path
}

function Read-Digest {
    param([string]$Path)
    $item = Assert-RegularPath -Path $Path -Label 'worker manifest digest'
    if ($item.PSIsContainer -or $item.Length -ne 65) {
        throw 'worker manifest digest has an invalid size'
    }
    $value = [IO.File]::ReadAllText($item.FullName, [Text.Encoding]::ASCII)
    if ($value -cnotmatch '^[0-9a-f]{64}\n$') {
        throw 'worker manifest digest is not canonical lowercase SHA-256 plus LF'
    }
    return $value.Substring(0, 64)
}

function Get-AppContainerSid {
    param([string]$ProfileName, [bool]$CreateIfMissing)
    [IntPtr]$pointer = [IntPtr]::Zero
    if ($CreateIfMissing) {
        $status = [AidaC03AppContainer]::CreateAppContainerProfile($ProfileName, $ProfileName, $ProfileName, [IntPtr]::Zero, 0, [ref]$pointer)
        if ($status -eq [int]0x800700B7) {
            $status = [AidaC03AppContainer]::DeriveAppContainerSidFromAppContainerName($ProfileName, [ref]$pointer)
        }
    } else {
        $status = [AidaC03AppContainer]::DeriveAppContainerSidFromAppContainerName($ProfileName, [ref]$pointer)
    }
    if ($status -ne 0 -or $pointer -eq [IntPtr]::Zero) {
        throw ('AppContainer SID derivation failed with HRESULT 0x{0:X8}' -f ([uint32]$status))
    }
    try {
        return [Security.Principal.SecurityIdentifier]::new($pointer)
    } finally {
        [void][AidaC03AppContainer]::FreeSid($pointer)
    }
}

function Get-PolicyPaths {
    param([string]$Root, [string]$SelectedPolicy)
    if ($SelectedPolicy -eq 'native') {
        $roots = @('deps/AiDA_NativeDecompilerWorker.exe', 'ghidra_specs', 'deps/ghidra_specs')
    } elseif ($SelectedPolicy -eq 'managed') {
        $roots = @(
            'deps/AiDA_ManagedDecompilerWorker.exe',
            'deps/AiDA_ManagedDecompilerWorker.dll',
            'deps/AiDA_ManagedDecompilerWorker.deps.json',
            'deps/AiDA_ManagedDecompilerWorker.runtimeconfig.json',
            'deps/ICSharpCode.Decompiler.dll',
            'deps/System.Collections.Immutable.dll',
            'deps/System.Reflection.Metadata.dll',
            'deps/dotnet'
        )
    } else {
        $roots = @('deps/AiDA_AnalysisPythonWorker.exe')
    }
    $paths = [Collections.Generic.List[string]]::new()
    foreach ($relative in $roots) {
        $path = Resolve-PackagePath -Root $Root -Relative $relative -Label 'worker runtime ACL path'
        $item = Assert-RegularPath -Path $path -Label 'worker runtime ACL path'
        $paths.Add($item.FullName)
        if ($item.PSIsContainer) {
            foreach ($child in Get-ChildItem -LiteralPath $item.FullName -Recurse -Force) {
                Assert-RegularPath -Path $child.FullName -Label 'worker runtime ACL descendant' | Out-Null
                $paths.Add($child.FullName)
            }
        }
    }
    return @($paths | Sort-Object -CaseSensitive -Unique)
}

function Set-WorkerAcl {
    param([string]$Path, [Security.Principal.SecurityIdentifier]$Sid)
    $item = Get-Item -LiteralPath $Path -Force
    $inheritance = if ($item.PSIsContainer) {
        [Security.AccessControl.InheritanceFlags]::ContainerInherit -bor [Security.AccessControl.InheritanceFlags]::ObjectInherit
    } else {
        [Security.AccessControl.InheritanceFlags]::None
    }
    $propagation = [Security.AccessControl.PropagationFlags]::None
    $allowRights = [Security.AccessControl.FileSystemRights]::ReadAndExecute -bor [Security.AccessControl.FileSystemRights]::Synchronize
    $denyRights = [Security.AccessControl.FileSystemRights]::Write -bor [Security.AccessControl.FileSystemRights]::Delete -bor
        [Security.AccessControl.FileSystemRights]::DeleteSubdirectoriesAndFiles -bor [Security.AccessControl.FileSystemRights]::ChangePermissions -bor
        [Security.AccessControl.FileSystemRights]::TakeOwnership
    $acl = Get-Acl -LiteralPath $Path
    $acl.SetAccessRuleProtection($true, $true)
    foreach ($rule in @($acl.Access | Where-Object { $_.IdentityReference.Value -eq $Sid.Value })) {
        [void]$acl.RemoveAccessRuleSpecific($rule)
    }
    [void]$acl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new($Sid, $denyRights, $inheritance, $propagation, [Security.AccessControl.AccessControlType]::Deny))
    [void]$acl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new($Sid, $allowRights, $inheritance, $propagation, [Security.AccessControl.AccessControlType]::Allow))
    Set-Acl -LiteralPath $Path -AclObject $acl
}

function Assert-WorkerAcl {
    param([string]$Path, [Security.Principal.SecurityIdentifier]$Sid)
    $acl = Get-Acl -LiteralPath $Path
    if (-not $acl.AreAccessRulesProtected) {
        throw "worker runtime ACL permits inherited DACL changes: $Path"
    }
    $rules = @($acl.Access | Where-Object { $_.IdentityReference.Value -eq $Sid.Value -and -not $_.IsInherited })
    $allow = @($rules | Where-Object { $_.AccessControlType -eq [Security.AccessControl.AccessControlType]::Allow })
    $deny = @($rules | Where-Object { $_.AccessControlType -eq [Security.AccessControl.AccessControlType]::Deny })
    if ($allow.Count -ne 1 -or $deny.Count -ne 1) {
        throw "worker runtime ACL rule cardinality is invalid: $Path"
    }
    $writeMask = [Security.AccessControl.FileSystemRights]::Write -bor [Security.AccessControl.FileSystemRights]::Delete -bor
        [Security.AccessControl.FileSystemRights]::DeleteSubdirectoriesAndFiles -bor [Security.AccessControl.FileSystemRights]::ChangePermissions -bor
        [Security.AccessControl.FileSystemRights]::TakeOwnership
    if (($allow[0].FileSystemRights -band [Security.AccessControl.FileSystemRights]::ReadAndExecute) -ne [Security.AccessControl.FileSystemRights]::ReadAndExecute -or
        ($allow[0].FileSystemRights -band $writeMask) -ne 0 -or ($deny[0].FileSystemRights -band $writeMask) -ne $writeMask) {
        throw "worker runtime ACL does not enforce read/execute without write/delete: $Path"
    }
}

function Write-AtomicJson {
    param([string]$Path, [object]$Value)
    $parent = Split-Path -Parent $Path
    New-Item -ItemType Directory -Path $parent -Force | Out-Null
    Assert-RegularPath -Path $parent -Label 'ACL receipt directory' | Out-Null
    $bytes = [Text.UTF8Encoding]::new($false, $true).GetBytes(($Value | ConvertTo-Json -Depth 16 -Compress) + "`n")
    $temporary = Join-Path $parent ('.' + [IO.Path]::GetFileName($Path) + '.' + [Guid]::NewGuid().ToString('N') + '.tmp')
    $stream = [IO.File]::Open($temporary, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write, [IO.FileShare]::None)
    try {
        $stream.Write($bytes, 0, $bytes.Length)
        $stream.Flush($true)
    } finally {
        $stream.Dispose()
    }
    if ([IO.File]::Exists($Path)) {
        Assert-RegularPath -Path $Path -Label 'existing ACL receipt' | Out-Null
        [IO.File]::Replace($temporary, $Path, $null, $true)
    } else {
        [IO.File]::Move($temporary, $Path)
    }
}

$root = (Resolve-Path -LiteralPath $PackageRoot -ErrorAction Stop).Path.TrimEnd([IO.Path]::DirectorySeparatorChar)
$rootItem = Assert-RegularPath -Path $root -Label 'package root'
if (-not $rootItem.PSIsContainer) {
    throw 'package root must be a directory'
}
$digestPath = Resolve-PackagePath -Root $root -Relative $WorkerManifestDigest -Label 'worker manifest digest'
$digest = Read-Digest -Path $digestPath
$profileName = 'AiDA.NativeWorker.' + $digest.Substring(0, 32)
$sid = Get-AppContainerSid -ProfileName $profileName -CreateIfMissing (-not $VerifyOnly)
$paths = Get-PolicyPaths -Root $root -SelectedPolicy $Policy
$expectedPathCount = if ($Policy -eq 'native') { 105 } elseif ($Policy -eq 'managed') { 207 } else { 1 }
if ($paths.Count -ne $expectedPathCount) {
    throw 'worker runtime ACL inventory violates policy'
}
if (-not $VerifyOnly) {
    foreach ($path in $paths) {
        Set-WorkerAcl -Path $path -Sid $sid
    }
}
foreach ($path in $paths) {
    Assert-WorkerAcl -Path $path -Sid $sid
}
$receiptPath = Resolve-PackagePath -Root $root -Relative $OutputReceipt -Label 'worker ACL receipt'
$receipt = [ordered]@{
    schema = 'aida.c03.worker-runtime-acl-receipt'
    schema_version = 1
    policy = $Policy
    app_container_profile = $profileName
    app_container_sid = $sid.Value
    worker_manifest_sha256 = $digest
    protected_parent_required = $true
    access = [ordered]@{
        read_execute = $true
        write = $false
        delete = $false
        change_permissions = $false
        take_ownership = $false
    }
    path_count = $paths.Count
    verified = $true
}
if (-not $VerifyOnly) {
    Write-AtomicJson -Path $receiptPath -Value $receipt
} else {
    $existing = Get-Content -LiteralPath $receiptPath -Raw -Encoding UTF8 | ConvertFrom-Json
    $existingProperties = @($existing.PSObject.Properties.Name | Sort-Object -CaseSensitive)
    $receiptProperties = @($receipt.Keys | Sort-Object -CaseSensitive)
    $existingAccessProperties = @($existing.access.PSObject.Properties.Name | Sort-Object -CaseSensitive)
    $receiptAccessProperties = @($receipt.access.Keys | Sort-Object -CaseSensitive)
    if (($existingProperties -join "`n") -cne ($receiptProperties -join "`n") -or
        ($existingAccessProperties -join "`n") -cne ($receiptAccessProperties -join "`n") -or
        $existing.schema -ne $receipt.schema -or [int]$existing.schema_version -ne 1 -or
        $existing.policy -ne $Policy -or $existing.app_container_profile -ne $profileName -or
        $existing.app_container_sid -ne $sid.Value -or $existing.worker_manifest_sha256 -ne $digest -or
        [int]$existing.path_count -ne $paths.Count -or -not [bool]$existing.protected_parent_required -or
        -not [bool]$existing.access.read_execute -or [bool]$existing.access.write -or
        [bool]$existing.access.delete -or [bool]$existing.access.change_permissions -or
        [bool]$existing.access.take_ownership -or -not [bool]$existing.verified) {
        throw 'worker runtime ACL receipt verification failed'
    }
}
$receipt | ConvertTo-Json -Depth 16 -Compress
