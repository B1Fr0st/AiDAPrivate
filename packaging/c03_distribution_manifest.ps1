[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$PackageRoot,
    [string]$Spec,
    [string]$AuthorityLock,
    [string]$OutputManifest,
    [string]$OutputDigest,
    [string]$SourceRoot,
    [string]$ApplicationStageAnchor,
    [string]$CustomerStageAnchor,
    [string]$EvidenceRoot,
    [string]$StageOwnerRoot,
    [switch]$StageCustomerPackage,
    [string]$PolicyFixtureReport,
    [switch]$StagePolicyFixture,
    [int]$FixtureMaximumFiles,
    [int]$FixtureMaximumDirectories,
    [int]$FixtureMaximumEntries,
    [int]$FixtureMaximumDepth,
    [int]$FixtureMaximumRelativePathBytes,
    [Int64]$FixtureMaximumInventoryPathBytes,
    [Int64]$FixtureMaximumEntryBytes,
    [Int64]$FixtureMaximumAggregateBytes,
    [ValidateSet('none', 'prepared', 'package-ready', 'evidence-ready', 'before-commit', 'after-commit')]
    [string]$FixturePublicationFailure = 'none',
    [ValidateSet('none', 'prepared', 'package-ready', 'evidence-ready', 'before-commit', 'after-commit')]
    [string]$FixturePublicationTermination = 'none',
    [switch]$Force
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$script:ForbiddenCustomerExtensions = [string[]]@(
    '.a', '.asm', '.bash', '.bat', '.c', '.c++', '.cc', '.cmake', '.cmd', '.cpp',
    '.cppm', '.cs', '.csproj', '.cxx', '.def', '.exp', '.fs', '.fsproj', '.go',
    '.gradle', '.h', '.hh', '.hpp', '.hxx', '.ilk', '.in', '.inc', '.inl', '.ipp',
    '.ixx', '.java', '.kt', '.kts', '.lib', '.m', '.make', '.map', '.mk', '.mm',
    '.natvis', '.nupkg', '.nuspec', '.obj', '.pdb', '.props', '.ps1', '.psd1',
    '.psm1', '.pth', '.py', '.pyc', '.pyo', '.pyz', '.rc', '.rc2', '.rs', '.s',
    '.sh', '.sln', '.snupkg', '.spec', '.swift', '.targets', '.tpp', '.vb',
    '.vbproj', '.vcxproj', '.vcxproj.filters', '.whl', '.zig', '.zsh'
)
$script:ForbiddenCustomerFileNames = [string[]]@(
    'build', 'build.bazel', 'cmakelists.txt', 'gnumakefile', 'makefile',
    'meson.build', 'workspace', 'workspace.bazel'
)
$script:ForbiddenCustomerDirectoryNames = [string[]]@(
    'c03-safe-headless', 'camoufox-reverse-mcp', 'camoufox_reverse_mcp',
    'library-packs', 'metadata', 'packs', 'sdk', 'templates'
)
$script:StockBrowserNames = [string[]]@(
    'chrome', 'chrome.exe', 'msedge', 'msedge.exe', 'stock-firefox', 'stock-firefox.exe'
)
$script:MaximumPackageFiles = 250000
$script:MaximumPackageDirectories = 65536
$script:MaximumPackageEntries = 300000
$script:MaximumPackageDepth = 64
$script:MaximumRelativePathBytes = 32768
$script:MaximumInventoryPathBytes = [Int64]268435456
$script:MaximumEntryBytes = [Int64]8589934592
$script:MaximumAggregateBytes = [Int64]17179869184
$script:MaximumStreamsPerEntry = 16
$script:ImmutableGeneration = $null
$script:SignerPolicyReceiptSha256 = $null
$script:SigningProviderReceiptSha256 = $null

function Invoke-PublicationCheckpoint {
    param([string]$Name)
    if ($FixturePublicationFailure -ceq $Name) {
        Throw-PackagePolicy -Code 'FIXTURE_PUBLICATION_FAILURE' -Path $Name
    }
    if ($FixturePublicationTermination -ceq $Name) {
        Stop-Process -Id $PID -Force
        [Environment]::FailFast('AIDA_C03_PUBLICATION_TERMINATION_' + $Name)
    }
}

if (-not ('AidaC03PackageNative' -as [type])) {
    Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;

public static class AidaC03PackageNative
{
    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    public struct WIN32_FIND_STREAM_DATA
    {
        public long StreamSize;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 296)]
        public string StreamName;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct BY_HANDLE_FILE_INFORMATION
    {
        public uint FileAttributes;
        public System.Runtime.InteropServices.ComTypes.FILETIME CreationTime;
        public System.Runtime.InteropServices.ComTypes.FILETIME LastAccessTime;
        public System.Runtime.InteropServices.ComTypes.FILETIME LastWriteTime;
        public uint VolumeSerialNumber;
        public uint FileSizeHigh;
        public uint FileSizeLow;
        public uint NumberOfLinks;
        public uint FileIndexHigh;
        public uint FileIndexLow;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct FILE_ATTRIBUTE_TAG_INFO
    {
        public uint FileAttributes;
        public uint ReparseTag;
    }

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    public static extern IntPtr FindFirstStreamW(string path, int level, out WIN32_FIND_STREAM_DATA data, uint flags);

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern bool FindNextStreamW(IntPtr handle, out WIN32_FIND_STREAM_DATA data);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern bool FindClose(IntPtr handle);

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    public static extern IntPtr CreateFileW(string path, uint access, uint share, IntPtr security, uint creation, uint flags, IntPtr templateFile);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern bool GetFileInformationByHandle(IntPtr handle, out BY_HANDLE_FILE_INFORMATION information);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern bool GetFileInformationByHandleEx(IntPtr handle, int informationClass, out FILE_ATTRIBUTE_TAG_INFO information, uint size);

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    public static extern uint GetFinalPathNameByHandleW(IntPtr handle, System.Text.StringBuilder path, uint size, uint flags);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern bool CloseHandle(IntPtr handle);
}
'@
}

function Throw-PackagePolicy {
    param([string]$Code, [string]$Path)
    throw ('AIDA_C03_PACKAGE_POLICY_' + $Code + '|' + $Path)
}

function ConvertTo-CanonicalNativePath {
    param([string]$Path, [string]$Label)
    if ([string]::IsNullOrEmpty($Path) -or $Path.Length -gt 32767 -or
        $Path -cnotmatch '^[A-Z]:/' -or
        $Path.Contains('\') -or $Path.Contains('//') -or
        ($Path.Length -gt 3 -and $Path.EndsWith('/', [StringComparison]::Ordinal))) {
        Throw-PackagePolicy -Code 'RAW_ABSOLUTE_PATH' -Path $Label
    }
    foreach ($character in $Path.ToCharArray()) {
        if ([int]$character -lt 0x20 -or [int]$character -gt 0x7e) {
            Throw-PackagePolicy -Code 'RAW_ABSOLUTE_PATH' -Path $Label
        }
    }
    $segments = @($Path.Substring(3).Split('/'))
    foreach ($segment in $segments) {
        if ([string]::IsNullOrEmpty($segment) -or $segment -eq '.' -or $segment -eq '..' -or
            $segment.EndsWith('.', [StringComparison]::Ordinal) -or
            $segment.EndsWith(' ', [StringComparison]::Ordinal) -or
            $segment.IndexOf(':', [StringComparison]::Ordinal) -ge 0) {
            Throw-PackagePolicy -Code 'RAW_ABSOLUTE_PATH' -Path $Label
        }
    }
    $native = $Path.Replace('/', '\')
    $full = [IO.Path]::GetFullPath($native).Replace('\', '/')
    if (-not [string]::Equals($full, $Path, [StringComparison]::Ordinal)) {
        Throw-PackagePolicy -Code 'RAW_ABSOLUTE_PATH' -Path $Label
    }
    return $native
}

function Get-ExactExistingPath {
    param([string]$Path, [string]$Label, [ValidateSet('Any', 'File', 'Directory')][string]$Kind = 'Any')
    $native = ConvertTo-CanonicalNativePath -Path $Path -Label $Label
    $segments = @($Path.Substring(3).Split('/'))
    $current = $Path.Substring(0, 3)
    $finalAttributes = 0
    for ($index = -1; $index -lt $segments.Count; ++$index) {
        if ($index -ge 0) {
            if (-not $current.EndsWith('/', [StringComparison]::Ordinal)) { $current += '/' }
            $current += $segments[$index]
        }
        $currentNative = $current.Replace('/', '\')
        $handle = [AidaC03PackageNative]::CreateFileW(
            $currentNative, 0, 7, [IntPtr]::Zero, 3, 0x02200000, [IntPtr]::Zero)
        if ($handle -eq [IntPtr](-1)) {
            Throw-PackagePolicy -Code 'CANONICAL_PATH_OPEN' -Path $Label
        }
        try {
            $tag = New-Object AidaC03PackageNative+FILE_ATTRIBUTE_TAG_INFO
            if (-not [AidaC03PackageNative]::GetFileInformationByHandleEx(
                    $handle, 9, [ref]$tag,
                    [Runtime.InteropServices.Marshal]::SizeOf([type]'AidaC03PackageNative+FILE_ATTRIBUTE_TAG_INFO'))) {
                Throw-PackagePolicy -Code 'CANONICAL_PATH_TAG' -Path $Label
            }
            if (($tag.FileAttributes -band 0x400) -ne 0 -or $tag.ReparseTag -ne 0) {
                Throw-PackagePolicy -Code 'REPARSE_POINT' -Path $Label
            }
            $buffer = New-Object Text.StringBuilder 32768
            $length = [AidaC03PackageNative]::GetFinalPathNameByHandleW($handle, $buffer, 32768, 0)
            if ($length -eq 0 -or $length -ge 32768) {
                Throw-PackagePolicy -Code 'CANONICAL_PATH_FINAL' -Path $Label
            }
            $final = $buffer.ToString()
            if ($final.StartsWith('\\?\UNC\', [StringComparison]::Ordinal)) {
                Throw-PackagePolicy -Code 'CANONICAL_PATH_VOLUME' -Path $Label
            }
            if ($final.StartsWith('\\?\', [StringComparison]::Ordinal)) { $final = $final.Substring(4) }
            $final = $final.Replace('\', '/')
            if ($index -lt 0 -and -not $final.EndsWith('/', [StringComparison]::Ordinal)) { $final += '/' }
            if (-not [string]::Equals($final, $current, [StringComparison]::Ordinal)) {
                Throw-PackagePolicy -Code 'CANONICAL_PATH_CASE' -Path $Label
            }
            $finalAttributes = $tag.FileAttributes
        } finally {
            [AidaC03PackageNative]::CloseHandle($handle) | Out-Null
        }
    }
    if (($Kind -eq 'File' -and ($finalAttributes -band 0x10) -ne 0) -or
        ($Kind -eq 'Directory' -and ($finalAttributes -band 0x10) -eq 0)) {
        Throw-PackagePolicy -Code 'CANONICAL_PATH_TYPE' -Path $Label
    }
    if ($Kind -eq 'File') { Assert-NoNamedStreams -Path $native | Out-Null }
    return $native
}

function Get-ExactOutputPath {
    param([string]$Path, [string]$Label)
    $native = ConvertTo-CanonicalNativePath -Path $Path -Label $Label
    $parent = [IO.Path]::GetDirectoryName($native)
    if ([string]::IsNullOrEmpty($parent)) {
        Throw-PackagePolicy -Code 'OUTPUT_PARENT' -Path $Label
    }
    $parentCanonical = $parent.Replace('\', '/')
    Get-ExactExistingPath -Path $parentCanonical -Label ($Label + ':parent') -Kind Directory | Out-Null
    if ([IO.File]::Exists($native)) {
        Get-ExactExistingPath -Path $Path -Label $Label -Kind File | Out-Null
    } elseif ([IO.Directory]::Exists($native)) {
        Throw-PackagePolicy -Code 'CANONICAL_PATH_TYPE' -Path $Label
    }
    return $native
}

function Test-AsciiAlphaNumeric {
    param([char]$Character)
    return ($Character -ge 'a' -and $Character -le 'z') -or
        ($Character -ge '0' -and $Character -le '9')
}

function Get-Utf8PathByteCount {
    param([string]$Value)
    return [Text.UTF8Encoding]::new($false, $true).GetByteCount($Value)
}

function Test-PolicyNameMatch {
    param([string]$Segment, [string]$Forbidden)
    if ([string]::Equals($Segment, $Forbidden, [StringComparison]::Ordinal)) {
        return $true
    }
    if ($Segment.Length -gt $Forbidden.Length -and
        $Segment.StartsWith($Forbidden, [StringComparison]::Ordinal) -and
        -not (Test-AsciiAlphaNumeric -Character $Segment[$Forbidden.Length])) {
        return $true
    }
    return $false
}

function Test-ForbiddenCustomerRelativePath {
    param([string]$RelativePath)
    if ([string]::IsNullOrWhiteSpace($RelativePath) -or
        (Get-Utf8PathByteCount -Value $RelativePath) -gt $script:MaximumRelativePathBytes -or
        $RelativePath[0] -eq '/' -or $RelativePath[$RelativePath.Length - 1] -eq '/') {
        return $true
    }
    foreach ($character in $RelativePath.ToCharArray()) {
        $code = [int]$character
        if ($code -lt 0x21 -or $code -gt 0x7e -or $character -in @('\', ':', '<', '>', '"', '|', '?', '*')) {
            return $true
        }
    }
    $segments = @($RelativePath -split '/')
    foreach ($segment in $segments) {
        if ([string]::IsNullOrWhiteSpace($segment) -or $segment -eq '.' -or
            $segment -eq '..' -or $segment.EndsWith('.', [StringComparison]::Ordinal)) {
            return $true
        }
        $lower = $segment.ToLowerInvariant()
        $deviceBase = $lower.Split('.')[0]
        if ($deviceBase -in @('con', 'prn', 'aux', 'nul') -or
            $deviceBase -cmatch '^(?:com|lpt)[1-9]$') {
            return $true
        }
        foreach ($name in $script:ForbiddenCustomerFileNames) {
            if (Test-PolicyNameMatch -Segment $lower -Forbidden $name) { return $true }
        }
        foreach ($directory in $script:ForbiddenCustomerDirectoryNames) {
            if (Test-PolicyNameMatch -Segment $lower -Forbidden $directory) { return $true }
        }
        if ($lower.IndexOf('.dist-info', [StringComparison]::Ordinal) -ge 0 -or
            $lower.IndexOf('.egg-info', [StringComparison]::Ordinal) -ge 0) {
            return $true
        }
        foreach ($extension in $script:ForbiddenCustomerExtensions) {
            $offset = 0
            while ($offset -lt $lower.Length) {
                $match = $lower.IndexOf($extension, $offset, [StringComparison]::Ordinal)
                if ($match -lt 0) {
                    break
                }
                $after = $match + $extension.Length
                if ($after -eq $lower.Length -or
                    -not (Test-AsciiAlphaNumeric -Character $lower[$after])) {
                    return $true
                }
                $offset = $match + 1
            }
        }
    }
    $leaf = $segments[$segments.Count - 1].ToLowerInvariant()
    foreach ($browser in $script:StockBrowserNames) {
        if (Test-PolicyNameMatch -Segment $leaf -Forbidden $browser) { return $true }
    }
    return $false
}

function Assert-ExactProperties {
    param(
        [object]$Value,
        [string[]]$Expected,
        [string]$Label
    )
    if ($null -eq $Value -or $Value -is [string] -or $Value -is [Array]) {
        throw "$Label must be an object"
    }
    $actual = @($Value.PSObject.Properties.Name | Sort-Object -CaseSensitive)
    $wanted = @($Expected | Sort-Object -CaseSensitive)
    if ($actual.Count -ne $wanted.Count) {
        throw "$Label property set is invalid"
    }
    for ($index = 0; $index -lt $wanted.Count; ++$index) {
        if (-not [string]::Equals($actual[$index], $wanted[$index], [StringComparison]::Ordinal)) {
            throw "$Label property set is invalid"
        }
    }
}

function Assert-RegularFile {
    param(
        [string]$Path,
        [string]$Label
    )
    $item = Get-Item -LiteralPath $Path -Force -ErrorAction Stop
    if ($item.PSIsContainer -or ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
        throw "$Label must be a regular non-reparse file"
    }
    Assert-NoNamedStreams -Path $item.FullName | Out-Null
    return $item
}

function Assert-NoNamedStreams {
    param([string]$Path)
    $data = New-Object AidaC03PackageNative+WIN32_FIND_STREAM_DATA
    $handle = [AidaC03PackageNative]::FindFirstStreamW($Path, 0, [ref]$data, 0)
    if ($handle -eq [IntPtr](-1)) {
        Throw-PackagePolicy -Code 'STREAM_ENUMERATION' -Path $Path
    }
    $count = 0
    try {
        while ($true) {
            ++$count
            if ($count -gt $script:MaximumStreamsPerEntry) {
                Throw-PackagePolicy -Code 'RESOURCE_STREAM_LIMIT' -Path $Path
            }
            if (-not [string]::Equals($data.StreamName, '::$DATA', [StringComparison]::Ordinal)) {
                Throw-PackagePolicy -Code 'NAMED_STREAM_FORBIDDEN' -Path $Path
            }
            $next = New-Object AidaC03PackageNative+WIN32_FIND_STREAM_DATA
            if (-not [AidaC03PackageNative]::FindNextStreamW($handle, [ref]$next)) {
                $lastError = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
                if ($lastError -ne 38) {
                    Throw-PackagePolicy -Code 'STREAM_ENUMERATION' -Path $Path
                }
                break
            }
            $data = $next
        }
    } finally {
        [AidaC03PackageNative]::FindClose($handle) | Out-Null
    }
    return $count
}

function Get-DirectoryIdentity {
    param([string]$Path)
    $handle = [AidaC03PackageNative]::CreateFileW(
        $Path, 0, 7, [IntPtr]::Zero, 3, 0x02200000, [IntPtr]::Zero)
    if ($handle -eq [IntPtr](-1)) {
        Throw-PackagePolicy -Code 'DIRECTORY_IDENTITY' -Path $Path
    }
    try {
        $information = New-Object AidaC03PackageNative+BY_HANDLE_FILE_INFORMATION
        if (-not [AidaC03PackageNative]::GetFileInformationByHandle($handle, [ref]$information)) {
            Throw-PackagePolicy -Code 'DIRECTORY_IDENTITY' -Path $Path
        }
        return ([string]$information.VolumeSerialNumber + ':' +
            ([UInt64]$information.FileIndexHigh).ToString('x8') +
            ([UInt64]$information.FileIndexLow).ToString('x8'))
    } finally {
        [AidaC03PackageNative]::CloseHandle($handle) | Out-Null
    }
}

function Assert-SingleLinkFile {
    param([string]$Path, [string]$Label)
    $handle = [AidaC03PackageNative]::CreateFileW(
        $Path, 0x80, 1, [IntPtr]::Zero, 3, 0x00200000, [IntPtr]::Zero)
    if ($handle -eq [IntPtr](-1)) {
        Throw-PackagePolicy -Code 'FILE_IDENTITY' -Path $Label
    }
    try {
        $information = New-Object AidaC03PackageNative+BY_HANDLE_FILE_INFORMATION
        if (-not [AidaC03PackageNative]::GetFileInformationByHandle($handle, [ref]$information) -or
            [UInt32]$information.NumberOfLinks -ne 1) {
            Throw-PackagePolicy -Code 'HARDLINK_FORBIDDEN' -Path $Label
        }
        $buffer = New-Object Text.StringBuilder 32768
        $length = [AidaC03PackageNative]::GetFinalPathNameByHandleW($handle, $buffer, 32768, 0)
        if ($length -eq 0 -or $length -ge 32768) {
            Throw-PackagePolicy -Code 'GENERATION_FINAL_PATH' -Path $Label
        }
        $final = $buffer.ToString()
        if ($final.StartsWith('\\?\UNC\', [StringComparison]::Ordinal)) {
            Throw-PackagePolicy -Code 'GENERATION_FINAL_VOLUME' -Path $Label
        }
        if ($final.StartsWith('\\?\', [StringComparison]::Ordinal)) {
            $final = $final.Substring(4)
        }
        if (-not [string]::Equals($final, [IO.Path]::GetFullPath($Path), [StringComparison]::Ordinal)) {
            Throw-PackagePolicy -Code 'GENERATION_FINAL_PATH' -Path $Label
        }
    } finally {
        [AidaC03PackageNative]::CloseHandle($handle) | Out-Null
    }
}

function Get-BoundedTreeInventory {
    param([string]$Root, [switch]$AllowForbiddenPaths)
    $normalizedRoot = [IO.Path]::GetFullPath($Root).TrimEnd([IO.Path]::DirectorySeparatorChar)
    $rootItem = Get-Item -LiteralPath $normalizedRoot -Force -ErrorAction Stop
    if (-not $rootItem.PSIsContainer -or
        ($rootItem.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
        Throw-PackagePolicy -Code 'REPARSE_POINT' -Path $normalizedRoot
    }
    $streamInventories = 1
    Assert-NoNamedStreams -Path $normalizedRoot | Out-Null
    $identities = [Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
    if (-not $identities.Add((Get-DirectoryIdentity -Path $normalizedRoot))) {
        Throw-PackagePolicy -Code 'DIRECTORY_CYCLE' -Path $normalizedRoot
    }
    $pending = [Collections.Generic.Queue[object]]::new()
    $pending.Enqueue([pscustomobject]@{ path = $normalizedRoot; depth = 0 })
    $files = [Collections.Generic.List[object]]::new()
    $exactPaths = [Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
    $foldedPaths = [Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    $directories = 1
    $entries = 0
    [Int64]$pathBytes = 0
    [Int64]$bytes = 0
    while ($pending.Count -ne 0) {
        $current = $pending.Dequeue()
        $discovered = [Collections.Generic.List[object]]::new()
        foreach ($entryPath in [IO.Directory]::EnumerateFileSystemEntries([string]$current.path)) {
            ++$entries
            if ($entries -gt $script:MaximumPackageEntries) {
                Throw-PackagePolicy -Code 'RESOURCE_ENTRY_LIMIT' -Path $normalizedRoot
            }
            $entryFull = [IO.Path]::GetFullPath($entryPath)
            if (-not $entryFull.StartsWith($normalizedRoot + [IO.Path]::DirectorySeparatorChar,
                    [StringComparison]::OrdinalIgnoreCase)) {
                Throw-PackagePolicy -Code 'PATH_ESCAPE' -Path $normalizedRoot
            }
            $relative = $entryFull.Substring($normalizedRoot.Length + 1).Replace('\', '/')
            $relativeBytes = Get-Utf8PathByteCount -Value $relative
            if ($relativeBytes -gt $script:MaximumRelativePathBytes) {
                Throw-PackagePolicy -Code 'RESOURCE_PATH_LIMIT' -Path $relative
            }
            $entryMemoryBytes = $relativeBytes + (Get-Utf8PathByteCount -Value $entryFull)
            if ($entryMemoryBytes -gt $script:MaximumInventoryPathBytes - $pathBytes) {
                Throw-PackagePolicy -Code 'RESOURCE_PATH_BUFFER_LIMIT' -Path $normalizedRoot
            }
            $pathBytes += $entryMemoryBytes
            $discovered.Add([pscustomobject]@{
                full_name = $entryFull
                relative_path = $relative
            })
        }
        foreach ($discoveredEntry in @($discovered | Sort-Object -Property relative_path -CaseSensitive)) {
            $item = Get-Item -LiteralPath $discoveredEntry.full_name -Force -ErrorAction Stop
            if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
                Throw-PackagePolicy -Code 'REPARSE_POINT' -Path $discoveredEntry.full_name
            }
            if (-not [string]::Equals($item.FullName, $discoveredEntry.full_name,
                    [StringComparison]::Ordinal)) {
                Throw-PackagePolicy -Code 'CANONICAL_PATH_CASE' -Path $discoveredEntry.relative_path
            }
            $relative = [string]$discoveredEntry.relative_path
            if (-not $AllowForbiddenPaths -and
                (Test-ForbiddenCustomerRelativePath -RelativePath $relative)) {
                Throw-PackagePolicy -Code 'PATH_POLICY' -Path $relative
            }
            if (-not $exactPaths.Add($relative) -or -not $foldedPaths.Add($relative)) {
                Throw-PackagePolicy -Code 'DUPLICATE_CASE_PATH' -Path $relative
            }
            ++$streamInventories
            Assert-NoNamedStreams -Path $item.FullName | Out-Null
            if ($item.PSIsContainer) {
                ++$directories
                if ($directories -gt $script:MaximumPackageDirectories) {
                    Throw-PackagePolicy -Code 'RESOURCE_DIRECTORY_LIMIT' -Path $relative
                }
                $depth = [int]$current.depth + 1
                if ($depth -gt $script:MaximumPackageDepth) {
                    Throw-PackagePolicy -Code 'RESOURCE_DEPTH_LIMIT' -Path $relative
                }
                if (-not $identities.Add((Get-DirectoryIdentity -Path $item.FullName))) {
                    Throw-PackagePolicy -Code 'DIRECTORY_CYCLE' -Path $relative
                }
                $pending.Enqueue([pscustomobject]@{ path = $item.FullName; depth = $depth })
                continue
            }
            if ($files.Count -ge $script:MaximumPackageFiles) {
                Throw-PackagePolicy -Code 'RESOURCE_FILE_LIMIT' -Path $relative
            }
            Assert-SingleLinkFile -Path $item.FullName -Label $relative
            $size = [Int64]$item.Length
            if ($size -lt 0 -or $size -gt $script:MaximumEntryBytes) {
                Throw-PackagePolicy -Code 'RESOURCE_FILE_BYTES_LIMIT' -Path $relative
            }
            if ($size -gt $script:MaximumAggregateBytes - $bytes) {
                Throw-PackagePolicy -Code 'RESOURCE_TOTAL_BYTES_LIMIT' -Path $relative
            }
            $bytes += $size
            $files.Add([pscustomobject]@{
                full_name = $item.FullName
                relative_path = $relative
                size_bytes = $size
            })
        }
    }
    $ordered = @($files | Sort-Object -Property relative_path -CaseSensitive)
    return [pscustomobject]@{
        files = $ordered
        file_count = $ordered.Count
        directory_count = $directories
        entry_count = $entries
        total_size_bytes = $bytes
        inventory_path_bytes = $pathBytes
        stream_inventory_count = $streamInventories
    }
}

function Test-ContainedPath {
    param([string]$Candidate, [string]$Root)
    $candidateFull = [IO.Path]::GetFullPath($Candidate).TrimEnd([IO.Path]::DirectorySeparatorChar)
    $rootFull = [IO.Path]::GetFullPath($Root).TrimEnd([IO.Path]::DirectorySeparatorChar)
    return [string]::Equals($candidateFull, $rootFull, [StringComparison]::OrdinalIgnoreCase) -or
        $candidateFull.StartsWith($rootFull + [IO.Path]::DirectorySeparatorChar,
            [StringComparison]::OrdinalIgnoreCase)
}

function Remove-OwnedGenerationDirectory {
    param(
        [string]$Path,
        [string]$Anchor,
        [string]$ExpectedIdentity,
        [string]$AllowedPrefix
    )
    $pathFull = [IO.Path]::GetFullPath($Path).TrimEnd([IO.Path]::DirectorySeparatorChar)
    $anchorFull = [IO.Path]::GetFullPath($Anchor).TrimEnd([IO.Path]::DirectorySeparatorChar)
    if (-not [IO.Directory]::Exists($pathFull) -or
        -not (Test-ContainedPath -Candidate $pathFull -Root $anchorFull) -or
        -not [string]::Equals((Split-Path -Parent $pathFull), $anchorFull, [StringComparison]::OrdinalIgnoreCase) -or
        -not ([IO.Path]::GetFileName($pathFull)).StartsWith($AllowedPrefix, [StringComparison]::Ordinal) -or
        (Get-DirectoryIdentity -Path $pathFull) -cne $ExpectedIdentity) {
        Throw-PackagePolicy -Code 'OWNED_GENERATION_IDENTITY' -Path $pathFull
    }
    Get-BoundedTreeInventory -Root $pathFull -AllowForbiddenPaths | Out-Null
    if ((Get-DirectoryIdentity -Path $pathFull) -cne $ExpectedIdentity) {
        Throw-PackagePolicy -Code 'OWNED_GENERATION_CHANGED' -Path $pathFull
    }
    [IO.Directory]::Delete($pathFull, $true)
}

function Test-GenerationReclaimable {
    param(
        [string]$PackagePath,
        [string]$EvidencePath,
        [string]$ManifestName,
        [string]$DigestName
    )
    foreach ($probe in @(
        [pscustomobject]@{ path = $PackagePath; flags = 0x02200000 },
        [pscustomobject]@{ path = (Join-Path $EvidencePath $ManifestName); flags = 0x00200000 },
        [pscustomobject]@{ path = (Join-Path $EvidencePath $DigestName); flags = 0x00200000 })) {
        $handle = [AidaC03PackageNative]::CreateFileW(
            [string]$probe.path, 0x80, 0, [IntPtr]::Zero, 3, [UInt32]$probe.flags,
            [IntPtr]::Zero)
        if ($handle -eq [IntPtr](-1)) {
            $errorCode = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
            if ($errorCode -eq 32 -or $errorCode -eq 33) {
                return $false
            }
            Throw-PackagePolicy -Code 'EVIDENCE_GENERATION_RECLAIM' -Path ([string]$probe.path)
        }
        [AidaC03PackageNative]::CloseHandle($handle) | Out-Null
    }
    return $true
}

function Write-PublicationJournal {
    param([string]$Path, [object]$Value)
    $bytes = [Text.UTF8Encoding]::new($false, $true).GetBytes(
        (($Value | ConvertTo-Json -Compress) + "`n"))
    Write-AtomicBytes -Path $Path -Bytes $bytes -Replace
    $identity = Get-LockedIdentity -Path $Path -Label 'publication journal' `
        -MaximumBytes 65536 -Transient -CaptureBytes
    if ($identity.size_bytes -ne $bytes.Length -or
        [Convert]::ToBase64String([byte[]]$identity.bytes) -cne
            [Convert]::ToBase64String($bytes)) {
        Throw-PackagePolicy -Code 'EVIDENCE_GENERATION_JOURNAL' -Path $Path
    }
}

function Remove-JournalOwnedDirectory {
    param(
        [string]$Path,
        [string]$Anchor,
        [string]$ExpectedIdentity,
        [string]$AllowedPrefix
    )
    if ([IO.Directory]::Exists($Path)) {
        Remove-OwnedGenerationDirectory -Path $Path -Anchor $Anchor `
            -ExpectedIdentity $ExpectedIdentity -AllowedPrefix $AllowedPrefix
    } elseif ([IO.File]::Exists($Path)) {
        Throw-PackagePolicy -Code 'EVIDENCE_GENERATION_JOURNAL_TYPE' -Path $Path
    }
}

function Recover-PublicationJournal {
    param(
        [string]$Path,
        [string]$PackageAnchor,
        [string]$PackageCandidateAnchor,
        [string]$EvidenceAnchor,
        [string]$PointerPath
    )
    if (-not [IO.File]::Exists($Path)) {
        if ([IO.Directory]::Exists($Path)) {
            Throw-PackagePolicy -Code 'EVIDENCE_GENERATION_JOURNAL_TYPE' -Path $Path
        }
        return
    }
    $journalIdentity = Get-LockedIdentity -Path $Path -Label 'publication journal' `
        -MaximumBytes 65536 -Transient -CaptureBytes
    $journal = [Text.UTF8Encoding]::new($false, $true).GetString(
        [byte[]]$journalIdentity.bytes) | ConvertFrom-Json
    Assert-ExactProperties -Value $journal -Expected @(
        'evidence_candidate', 'evidence_identity', 'evidence_generation',
        'generation_id', 'package_candidate', 'package_generation',
        'package_identity', 'phase', 'pointer_path', 'schema', 'schema_version') `
        -Label 'publication journal'
    if ($journal.schema -cne 'aida.c03.publication-journal' -or
        [int]$journal.schema_version -ne 1 -or
        [string]$journal.generation_id -cnotmatch '^[0-9a-f]{32}$' -or
        [string]$journal.phase -cnotmatch '^(prepared|package-ready|evidence-ready|before-commit|after-commit)$' -or
        -not [string]::Equals([IO.Path]::GetFullPath([string]$journal.pointer_path),
            [IO.Path]::GetFullPath($PointerPath), [StringComparison]::Ordinal) -or
        [string]$journal.package_identity -cnotmatch '^[0-9]+:[0-9a-f]{16}$' -or
        [string]$journal.evidence_identity -cnotmatch '^[0-9]+:[0-9a-f]{16}$') {
        Throw-PackagePolicy -Code 'EVIDENCE_GENERATION_JOURNAL' -Path $Path
    }
    $generationName = '.aida-c03-generation-' + [string]$journal.generation_id
    $packageGeneration = [IO.Path]::GetFullPath([string]$journal.package_generation)
    $evidenceGeneration = [IO.Path]::GetFullPath([string]$journal.evidence_generation)
    $packageCandidate = [IO.Path]::GetFullPath([string]$journal.package_candidate)
    $evidenceCandidate = [IO.Path]::GetFullPath([string]$journal.evidence_candidate)
    if (-not [string]::Equals((Split-Path -Parent $packageGeneration), $PackageAnchor,
            [StringComparison]::OrdinalIgnoreCase) -or
        -not [string]::Equals((Split-Path -Parent $evidenceGeneration), $EvidenceAnchor,
            [StringComparison]::OrdinalIgnoreCase) -or
        [IO.Path]::GetFileName($packageGeneration) -cne $generationName -or
        [IO.Path]::GetFileName($evidenceGeneration) -cne $generationName -or
        -not [string]::Equals((Split-Path -Parent $packageCandidate),
            $PackageCandidateAnchor,
            [StringComparison]::OrdinalIgnoreCase) -or
        -not [string]::Equals((Split-Path -Parent $evidenceCandidate), $EvidenceAnchor,
            [StringComparison]::OrdinalIgnoreCase) -or
        -not ([IO.Path]::GetFileName($packageCandidate)).StartsWith(
            '.aida-c03-candidate-', [StringComparison]::Ordinal) -or
        -not ([IO.Path]::GetFileName($evidenceCandidate)).StartsWith(
            '.aida-c03-evidence-candidate-', [StringComparison]::Ordinal)) {
        Throw-PackagePolicy -Code 'EVIDENCE_GENERATION_JOURNAL_PATH' -Path $Path
    }
    $currentId = $null
    if ([IO.File]::Exists($PointerPath)) {
        $pointer = [IO.File]::ReadAllText(
            $PointerPath, [Text.UTF8Encoding]::new($false, $true)) | ConvertFrom-Json
        if ($pointer.schema -ceq 'aida.c03.complete-generation-pointer' -and
            [int]$pointer.schema_version -eq 1 -and
            [string]$pointer.generation_id -cmatch '^[0-9a-f]{32}$') {
            $currentId = [string]$pointer.generation_id
        }
    }
    if ($currentId -cne [string]$journal.generation_id) {
        Remove-JournalOwnedDirectory -Path $packageGeneration -Anchor $PackageAnchor `
            -ExpectedIdentity ([string]$journal.package_identity) `
            -AllowedPrefix '.aida-c03-generation-'
        Remove-JournalOwnedDirectory -Path $evidenceGeneration -Anchor $EvidenceAnchor `
            -ExpectedIdentity ([string]$journal.evidence_identity) `
            -AllowedPrefix '.aida-c03-generation-'
    }
    Remove-JournalOwnedDirectory -Path $packageCandidate `
        -Anchor $PackageCandidateAnchor `
        -ExpectedIdentity ([string]$journal.package_identity) `
        -AllowedPrefix '.aida-c03-candidate-'
    Remove-JournalOwnedDirectory -Path $evidenceCandidate -Anchor $EvidenceAnchor `
        -ExpectedIdentity ([string]$journal.evidence_identity) `
        -AllowedPrefix '.aida-c03-evidence-candidate-'
    $journalFinal = Get-LockedIdentity -Path $Path -Label 'publication journal' `
        -MaximumBytes 65536 -Transient
    if ([string]$journalFinal.file_identity -cne [string]$journalIdentity.file_identity -or
        [string]$journalFinal.sha256 -cne [string]$journalIdentity.sha256) {
        Throw-PackagePolicy -Code 'EVIDENCE_GENERATION_JOURNAL' -Path $Path
    }
    [IO.File]::Delete($Path)
}

function Publish-CompleteGeneration {
    param(
        [object]$Stage,
        [string]$ManifestCandidate,
        [object]$ManifestIdentity,
        [string]$DigestCandidate,
        [object]$DigestIdentity,
        [string]$ManifestDestination,
        [string]$DigestDestination,
        [string]$EvidenceCandidate,
        [string]$EvidenceCandidateIdentity,
        [string]$EvidencePublicationAnchor,
        [string]$ExpectedManifestDigest,
        [switch]$Replace
    )
    $packageAnchor = [IO.Path]::GetFullPath([string]$Stage.publication_anchor).TrimEnd([IO.Path]::DirectorySeparatorChar)
    $evidenceAnchor = [IO.Path]::GetFullPath($EvidencePublicationAnchor).TrimEnd([IO.Path]::DirectorySeparatorChar)
    $generationId = [Guid]::NewGuid().ToString('N')
    $packageGeneration = Join-Path $packageAnchor ('.aida-c03-generation-' + $generationId)
    $evidenceGeneration = Join-Path $evidenceAnchor ('.aida-c03-generation-' + $generationId)
    $manifestGeneration = Join-Path $evidenceGeneration ([IO.Path]::GetFileName($ManifestDestination))
    $digestGeneration = Join-Path $evidenceGeneration ([IO.Path]::GetFileName($DigestDestination))
    $pointerPath = $ManifestDestination + '.generation-pointer.json'
    $publicationLockPath = Join-Path $evidenceAnchor '.aida-c03-publication.lock'
    $publicationJournalPath = Join-Path $evidenceAnchor '.aida-c03-publication-journal.json'
    $packageCandidateAnchor = [IO.Path]::GetFullPath(
        (Split-Path -Parent ([string]$Stage.candidate_path))).TrimEnd(
            [IO.Path]::DirectorySeparatorChar)
    $publicationLock = $null
    $journal = $null
    $packageMoved = $false
    $evidenceMoved = $false
    $pointerCommitted = $false
    try {
        if ([IO.File]::Exists($publicationLockPath)) {
            Assert-RegularFile -Path $publicationLockPath -Label 'publication lock' | Out-Null
            Assert-SingleLinkFile -Path $publicationLockPath -Label 'publication lock'
        }
        $publicationLock = [AidaC03PackageNative]::CreateFileW(
            $publicationLockPath, [UInt32]3221225472, 0, [IntPtr]::Zero, 4,
            [UInt32]0x00200080, [IntPtr]::Zero)
        if ($publicationLock -eq [IntPtr](-1)) {
            Throw-PackagePolicy -Code 'EVIDENCE_GENERATION_LOCK' -Path $publicationLockPath
        }
        $publicationLockIdentity = New-Object AidaC03PackageNative+BY_HANDLE_FILE_INFORMATION
        if (-not [AidaC03PackageNative]::GetFileInformationByHandle(
                $publicationLock, [ref]$publicationLockIdentity) -or
            [UInt32]$publicationLockIdentity.NumberOfLinks -ne 1 -or
            ([UInt32]$publicationLockIdentity.FileAttributes -band
                [UInt32]([IO.FileAttributes]::ReparsePoint)) -ne 0) {
            Throw-PackagePolicy -Code 'HARDLINK_FORBIDDEN' -Path $publicationLockPath
        }
        $publicationLockFinal = New-Object Text.StringBuilder 32768
        $publicationLockFinalLength = [AidaC03PackageNative]::GetFinalPathNameByHandleW(
            $publicationLock, $publicationLockFinal, 32768, 0)
        if ($publicationLockFinalLength -eq 0 -or $publicationLockFinalLength -ge 32768) {
            Throw-PackagePolicy -Code 'EVIDENCE_GENERATION_LOCK' -Path $publicationLockPath
        }
        $publicationLockObserved = $publicationLockFinal.ToString()
        if ($publicationLockObserved.StartsWith('\\?\UNC\', [StringComparison]::Ordinal)) {
            Throw-PackagePolicy -Code 'EVIDENCE_GENERATION_LOCK' -Path $publicationLockPath
        }
        if ($publicationLockObserved.StartsWith('\\?\', [StringComparison]::Ordinal)) {
            $publicationLockObserved = $publicationLockObserved.Substring(4)
        }
        if (-not [string]::Equals($publicationLockObserved,
                [IO.Path]::GetFullPath($publicationLockPath), [StringComparison]::Ordinal)) {
            Throw-PackagePolicy -Code 'EVIDENCE_GENERATION_LOCK' -Path $publicationLockPath
        }
        Recover-PublicationJournal -Path $publicationJournalPath `
            -PackageAnchor $packageAnchor -PackageCandidateAnchor $packageCandidateAnchor `
            -EvidenceAnchor $evidenceAnchor -PointerPath $pointerPath
        $currentGenerationId = $null
        if ([IO.File]::Exists($pointerPath)) {
            Assert-SingleLinkFile -Path $pointerPath -Label 'complete generation pointer'
            if (-not $Replace) {
                Throw-PackagePolicy -Code 'EVIDENCE_GENERATION_EXISTS' -Path $pointerPath
            }
            $currentPointerItem = Get-Item -LiteralPath $pointerPath -Force -ErrorAction Stop
            if ($currentPointerItem.Length -le 0 -or $currentPointerItem.Length -gt 65536) {
                Throw-PackagePolicy -Code 'EVIDENCE_GENERATION_POINTER' -Path $pointerPath
            }
            $currentPointer = [IO.File]::ReadAllText(
                $pointerPath, [Text.UTF8Encoding]::new($false, $true)) | ConvertFrom-Json
            Assert-ExactProperties -Value $currentPointer -Expected @(
                'digest_file_identity', 'digest_path', 'generation_id',
                'manifest_file_identity', 'manifest_path', 'manifest_sha256',
                'package_directory_identity', 'package_root', 'schema', 'schema_version') `
                -Label 'complete generation pointer'
            if ($currentPointer.schema -cne 'aida.c03.complete-generation-pointer' -or
                [int]$currentPointer.schema_version -ne 1 -or
                [string]$currentPointer.generation_id -cnotmatch '^[0-9a-f]{32}$' -or
                [string]$currentPointer.manifest_sha256 -cnotmatch '^[0-9a-f]{64}$') {
                Throw-PackagePolicy -Code 'EVIDENCE_GENERATION_POINTER' -Path $pointerPath
            }
            $currentGenerationId = [string]$currentPointer.generation_id
            $currentPackageGeneration = Join-Path $packageAnchor ('.aida-c03-generation-' + $currentGenerationId)
            $currentEvidenceGeneration = Join-Path $evidenceAnchor ('.aida-c03-generation-' + $currentGenerationId)
            if (-not [string]::Equals([IO.Path]::GetFullPath([string]$currentPointer.package_root),
                    $currentPackageGeneration, [StringComparison]::Ordinal) -or
                -not [string]::Equals((Split-Path -Parent ([IO.Path]::GetFullPath([string]$currentPointer.manifest_path))),
                    $currentEvidenceGeneration, [StringComparison]::Ordinal) -or
                -not [string]::Equals((Split-Path -Parent ([IO.Path]::GetFullPath([string]$currentPointer.digest_path))),
                    $currentEvidenceGeneration, [StringComparison]::Ordinal)) {
                Throw-PackagePolicy -Code 'EVIDENCE_GENERATION_POINTER' -Path $pointerPath
            }
        } elseif ([IO.Directory]::Exists($pointerPath)) {
            Throw-PackagePolicy -Code 'EVIDENCE_GENERATION_TYPE' -Path $pointerPath
        }
        $packageGenerations = [Collections.Generic.Dictionary[string, string]]::new(
            [StringComparer]::Ordinal)
        $evidenceGenerations = [Collections.Generic.Dictionary[string, string]]::new(
            [StringComparer]::Ordinal)
        foreach ($generationRoot in @(
            [pscustomobject]@{ anchor = $packageAnchor; map = $packageGenerations },
            [pscustomobject]@{ anchor = $evidenceAnchor; map = $evidenceGenerations })) {
            foreach ($entryPath in [IO.Directory]::EnumerateFileSystemEntries([string]$generationRoot.anchor)) {
                $name = [IO.Path]::GetFileName($entryPath)
                if (-not $name.StartsWith('.aida-c03-generation-', [StringComparison]::Ordinal)) {
                    continue
                }
                $item = Get-Item -LiteralPath $entryPath -Force -ErrorAction Stop
                $id = $name.Substring('.aida-c03-generation-'.Length)
                if (-not $item.PSIsContainer -or
                    ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0 -or
                    $id -cnotmatch '^[0-9a-f]{32}$' -or
                    $generationRoot.map.ContainsKey($id)) {
                    Throw-PackagePolicy -Code 'EVIDENCE_GENERATION_INVENTORY' -Path $entryPath
                }
                if ($generationRoot.map.Count -ge 64) {
                    Throw-PackagePolicy -Code 'EVIDENCE_GENERATION_LIMIT' -Path $entryPath
                }
                $generationRoot.map.Add($id, $item.FullName)
            }
        }
        if ($packageGenerations.Count -ne $evidenceGenerations.Count) {
            Throw-PackagePolicy -Code 'EVIDENCE_GENERATION_INCOMPLETE' -Path $generationId
        }
        $retainedGenerations = if ($null -eq $currentGenerationId) { 0 } else { 1 }
        foreach ($id in @($packageGenerations.Keys)) {
            if (-not $evidenceGenerations.ContainsKey($id)) {
                Throw-PackagePolicy -Code 'EVIDENCE_GENERATION_INCOMPLETE' -Path $id
            }
            if ($id -cne $currentGenerationId) {
                $stalePackage = $packageGenerations[$id]
                $staleEvidence = $evidenceGenerations[$id]
                if (-not (Test-GenerationReclaimable -PackagePath $stalePackage `
                        -EvidencePath $staleEvidence `
                        -ManifestName ([IO.Path]::GetFileName($ManifestDestination)) `
                        -DigestName ([IO.Path]::GetFileName($DigestDestination)))) {
                    ++$retainedGenerations
                    continue
                }
                Remove-OwnedGenerationDirectory -Path $stalePackage -Anchor $packageAnchor `
                    -ExpectedIdentity (Get-DirectoryIdentity -Path $stalePackage) `
                    -AllowedPrefix '.aida-c03-generation-'
                Remove-OwnedGenerationDirectory -Path $staleEvidence -Anchor $evidenceAnchor `
                    -ExpectedIdentity (Get-DirectoryIdentity -Path $staleEvidence) `
                    -AllowedPrefix '.aida-c03-generation-'
            }
        }
        if ($retainedGenerations -gt 8) {
            Throw-PackagePolicy -Code 'EVIDENCE_GENERATION_LIMIT' -Path $generationId
        }
        if ($null -ne $currentGenerationId -and
            (-not $packageGenerations.ContainsKey($currentGenerationId) -or
             -not $evidenceGenerations.ContainsKey($currentGenerationId))) {
            Throw-PackagePolicy -Code 'EVIDENCE_GENERATION_POINTER' -Path $pointerPath
        }
        if ([IO.Directory]::Exists($packageGeneration) -or [IO.File]::Exists($packageGeneration) -or
            [IO.Directory]::Exists($evidenceGeneration) -or [IO.File]::Exists($evidenceGeneration)) {
            Throw-PackagePolicy -Code 'EVIDENCE_GENERATION_EXISTS' -Path $generationId
        }
        $journal = [ordered]@{
            schema = 'aida.c03.publication-journal'
            schema_version = 1
            generation_id = $generationId
            phase = 'prepared'
            pointer_path = $pointerPath
            package_candidate = [string]$Stage.candidate_path
            package_identity = [string]$Stage.candidate_identity
            package_generation = $packageGeneration
            evidence_candidate = $EvidenceCandidate
            evidence_identity = $EvidenceCandidateIdentity
            evidence_generation = $evidenceGeneration
        }
        Write-PublicationJournal -Path $publicationJournalPath -Value $journal
        Invoke-PublicationCheckpoint -Name 'prepared'
        [IO.Directory]::Move([string]$Stage.candidate_path, $packageGeneration)
        $packageMoved = $true
        Set-ImmutableGenerationExpectedPathPrefix -OldRoot ([string]$Stage.candidate_path) -NewRoot $packageGeneration
        $publishedPackage = Get-BoundedTreeInventory -Root $packageGeneration
        if ($publishedPackage.file_count -ne [int]$Stage.inventory.file_count -or
            $publishedPackage.directory_count -ne [int]$Stage.inventory.directory_count -or
            $publishedPackage.entry_count -ne [int]$Stage.inventory.entry_count -or
            [Int64]$publishedPackage.total_size_bytes -ne [Int64]$Stage.inventory.total_size_bytes -or
            [Int64]$publishedPackage.inventory_path_bytes -ne [Int64]$Stage.inventory.inventory_path_bytes -or
            $publishedPackage.stream_inventory_count -ne [int]$Stage.inventory.stream_inventory_count -or
            (Get-DirectoryIdentity -Path $packageGeneration) -cne [string]$Stage.candidate_identity) {
            Throw-PackagePolicy -Code 'STAGE_EXACT_INVENTORY' -Path $packageGeneration
        }
        $journal.phase = 'package-ready'
        Write-PublicationJournal -Path $publicationJournalPath -Value $journal
        Invoke-PublicationCheckpoint -Name 'package-ready'
        [IO.Directory]::Move($EvidenceCandidate, $evidenceGeneration)
        $evidenceMoved = $true
        Set-ImmutableGenerationExpectedPathPrefix -OldRoot $EvidenceCandidate -NewRoot $evidenceGeneration
        if (-not [IO.File]::Exists($manifestGeneration) -or
            -not [IO.File]::Exists($digestGeneration) -or
            (Get-DirectoryIdentity -Path $evidenceGeneration) -cne $EvidenceCandidateIdentity) {
            Throw-PackagePolicy -Code 'EVIDENCE_GENERATION_CHANGED' -Path $evidenceGeneration
        }
        $publishedManifest = Get-LockedIdentity -Path $manifestGeneration -Label 'published distribution manifest' -MaximumBytes 16777216
        $publishedDigestIdentity = Get-LockedIdentity -Path $digestGeneration -Label 'published distribution digest' -MaximumBytes 256
        $publishedDigest = Get-LockedBytes -Path $digestGeneration -Label 'published distribution digest bytes' -MaximumBytes 256
        $publishedDigestText = [Text.Encoding]::ASCII.GetString($publishedDigest.bytes)
        if ([string]$publishedManifest.file_identity -cne [string]$ManifestIdentity.file_identity -or
            [string]$publishedManifest.sha256 -cne $ExpectedManifestDigest -or
            [string]$publishedDigestIdentity.file_identity -cne [string]$DigestIdentity.file_identity -or
            $publishedDigestText -cne ($ExpectedManifestDigest + "`n")) {
            Throw-PackagePolicy -Code 'EVIDENCE_GENERATION_CHANGED' -Path $evidenceGeneration
        }
        Assert-ImmutableGeneration
        $journal.phase = 'evidence-ready'
        Write-PublicationJournal -Path $publicationJournalPath -Value $journal
        Invoke-PublicationCheckpoint -Name 'evidence-ready'
        $pointer = [ordered]@{
            schema = 'aida.c03.complete-generation-pointer'
            schema_version = 1
            generation_id = $generationId
            package_root = $packageGeneration
            package_directory_identity = [string]$Stage.candidate_identity
            manifest_path = $manifestGeneration
            manifest_sha256 = $ExpectedManifestDigest
            manifest_file_identity = [string]$ManifestIdentity.file_identity
            digest_path = $digestGeneration
            digest_file_identity = [string]$DigestIdentity.file_identity
        }
        $pointerBytes = [Text.UTF8Encoding]::new($false, $true).GetBytes(
            (($pointer | ConvertTo-Json -Compress) + "`n"))
        $journal.phase = 'before-commit'
        Write-PublicationJournal -Path $publicationJournalPath -Value $journal
        Invoke-PublicationCheckpoint -Name 'before-commit'
        Write-AtomicBytes -Path $pointerPath -Bytes $pointerBytes -Replace:$Replace
        $pointerCommitted = $true
        $pointerIdentity = Get-LockedIdentity -Path $pointerPath -Label 'complete generation pointer' -MaximumBytes 65536
        if ($pointerIdentity.size_bytes -ne $pointerBytes.Length) {
            Throw-PackagePolicy -Code 'EVIDENCE_GENERATION_CHANGED' -Path $pointerPath
        }
        $journal.phase = 'after-commit'
        Write-PublicationJournal -Path $publicationJournalPath -Value $journal
        Invoke-PublicationCheckpoint -Name 'after-commit'
        [IO.File]::Delete($publicationJournalPath)
        return [pscustomobject]@{
            inventory = $publishedPackage
            generation_id = $generationId
            package_root = $packageGeneration
            manifest_path = $manifestGeneration
            digest_path = $digestGeneration
            pointer_path = $pointerPath
        }
    } catch {
        if (-not $pointerCommitted) {
            if ($evidenceMoved -and [IO.Directory]::Exists($evidenceGeneration) -and
                -not [IO.Directory]::Exists($EvidenceCandidate)) {
                [IO.Directory]::Move($evidenceGeneration, $EvidenceCandidate)
                Set-ImmutableGenerationExpectedPathPrefix -OldRoot $evidenceGeneration -NewRoot $EvidenceCandidate
                $evidenceMoved = $false
            }
            if ($packageMoved -and [IO.Directory]::Exists($packageGeneration) -and
                -not [IO.Directory]::Exists([string]$Stage.candidate_path)) {
                [IO.Directory]::Move($packageGeneration, [string]$Stage.candidate_path)
                Set-ImmutableGenerationExpectedPathPrefix -OldRoot $packageGeneration -NewRoot ([string]$Stage.candidate_path)
                $packageMoved = $false
            }
            if ([IO.File]::Exists($publicationJournalPath)) {
                [IO.File]::Delete($publicationJournalPath)
            }
        }
        throw
    } finally {
        if ($null -ne $publicationLock -and $publicationLock -ne [IntPtr](-1)) {
            [AidaC03PackageNative]::CloseHandle($publicationLock) | Out-Null
        }
    }
}

function Stage-SanitizedCustomerPackage {
    param(
        [string]$Source,
        [string]$Destination,
        [string]$CandidateAnchor,
        [string]$PublicationAnchor,
        [string]$SpecificationPath
    )
    $sourceFull = (Resolve-Path -LiteralPath $Source -ErrorAction Stop).Path.TrimEnd([IO.Path]::DirectorySeparatorChar)
    $sourceItem = Get-Item -LiteralPath $sourceFull -Force
    if (-not $sourceItem.PSIsContainer -or
        ($sourceItem.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
        Throw-PackagePolicy -Code 'STAGE_SOURCE' -Path $sourceFull
    }
    [IO.Directory]::CreateDirectory([IO.Path]::GetFullPath($CandidateAnchor)) | Out-Null
    [IO.Directory]::CreateDirectory([IO.Path]::GetFullPath($PublicationAnchor)) | Out-Null
    $candidateAnchorFull = (Resolve-Path -LiteralPath $CandidateAnchor -ErrorAction Stop).Path.TrimEnd([IO.Path]::DirectorySeparatorChar)
    $publicationAnchorFull = (Resolve-Path -LiteralPath $PublicationAnchor -ErrorAction Stop).Path.TrimEnd([IO.Path]::DirectorySeparatorChar)
    foreach ($anchorFull in @($candidateAnchorFull, $publicationAnchorFull)) {
        $anchorItem = Get-Item -LiteralPath $anchorFull -Force
        if (-not $anchorItem.PSIsContainer -or
            ($anchorItem.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
            Throw-PackagePolicy -Code 'STAGE_ANCHOR' -Path $anchorFull
        }
        Assert-NoNamedStreams -Path $anchorFull | Out-Null
    }
    $destinationFull = [IO.Path]::GetFullPath($Destination).TrimEnd([IO.Path]::DirectorySeparatorChar)
    if ([string]::Equals($destinationFull, $publicationAnchorFull, [StringComparison]::OrdinalIgnoreCase) -or
        [string]::Equals($candidateAnchorFull, $publicationAnchorFull, [StringComparison]::OrdinalIgnoreCase) -or
        -not (Test-ContainedPath -Candidate $destinationFull -Root $publicationAnchorFull) -or
        (Test-ContainedPath -Candidate $sourceFull -Root $candidateAnchorFull) -or
        (Test-ContainedPath -Candidate $candidateAnchorFull -Root $sourceFull) -or
        (Test-ContainedPath -Candidate $sourceFull -Root $publicationAnchorFull) -or
        (Test-ContainedPath -Candidate $publicationAnchorFull -Root $sourceFull) -or
        (Test-ContainedPath -Candidate $sourceFull -Root $destinationFull) -or
        (Test-ContainedPath -Candidate $destinationFull -Root $sourceFull)) {
        Throw-PackagePolicy -Code 'STAGE_CONTAINMENT' -Path $destinationFull
    }
    $specification = (Read-StrictJson -Path $SpecificationPath -Label 'distribution manifest spec').value
    $paths = [Collections.Generic.List[string]]::new()
    $exactPaths = [Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
    $foldedPaths = [Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    $addPath = {
        param([string]$RelativePath)
        if (Test-ForbiddenCustomerRelativePath -RelativePath $RelativePath) {
            Throw-PackagePolicy -Code 'PATH_POLICY' -Path $RelativePath
        }
        if ($exactPaths.Contains($RelativePath)) { return }
        if (-not $foldedPaths.Add($RelativePath)) {
            Throw-PackagePolicy -Code 'DUPLICATE_CASE_PATH' -Path $RelativePath
        }
        $exactPaths.Add($RelativePath) | Out-Null
        $paths.Add($RelativePath)
    }
    foreach ($artifact in @($specification.artifacts)) {
        & $addPath ([string]$artifact.relative_path)
    }
    foreach ($inventorySource in @($specification.inventory_sources)) {
        $type = [string]$inventorySource.type
        if ($type -eq 'managed_runtime_manifest_v1') {
            & $addPath ([string]$inventorySource.manifest_relative_path)
            & $addPath ([string]$inventorySource.digest_relative_path)
            $manifestPath = Resolve-SafeRelativePath -Root $sourceFull `
                -RelativePath ([string]$inventorySource.manifest_relative_path) `
                -Label 'managed runtime stage manifest'
            $managed = (Read-StrictJson -Path $manifestPath -Label 'managed runtime stage manifest').value
            foreach ($entry in @($managed.runtime.files) + @($managed.application.files)) {
                & $addPath ([string]$entry.relative_path)
            }
        } elseif ($type -eq 'ghidra_spec_manifest_v1') {
            & $addPath ([string]$inventorySource.manifest_relative_path)
            & $addPath ([string]$inventorySource.digest_relative_path)
            $manifestPath = Resolve-SafeRelativePath -Root $sourceFull `
                -RelativePath ([string]$inventorySource.manifest_relative_path) `
                -Label 'Ghidra stage manifest'
            $ghidra = (Read-StrictJson -Path $manifestPath -Label 'Ghidra stage manifest').value
            foreach ($entry in @($ghidra.specifications.files)) {
                foreach ($mirror in @($ghidra.specifications.mirrors)) {
                    & $addPath (([string]$mirror) + '/' + ([string]$entry.name))
                }
            }
        } elseif ($type -eq 'exact_tree_v1') {
            $relativeRoot = [string]$inventorySource.relative_root
            $treeRoot = Resolve-SafeRelativePath -Root $sourceFull -RelativePath $relativeRoot `
                -Label 'exact customer stage tree'
            $treeInventory = Get-BoundedTreeInventory -Root $treeRoot
            $treeEntries = [Collections.Generic.List[object]]::new()
            foreach ($entry in $treeInventory.files) {
                $identity = Get-LockedIdentity -Path $entry.full_name -Label 'exact customer stage artifact'
                $treeEntries.Add([pscustomobject]@{
                    relative_path = $entry.relative_path
                    size_bytes = $identity.size_bytes
                    sha256 = $identity.sha256
                })
                & $addPath ($relativeRoot + '/' + [string]$entry.relative_path)
            }
            if ($treeEntries.Count -ne [int]$inventorySource.expected_file_count -or
                [Int64](@($treeEntries | Measure-Object -Property size_bytes -Sum).Sum) -ne
                    [Int64]$inventorySource.expected_size_bytes -or
                (Get-CanonicalInventorySha256 -Entries @($treeEntries)) -cne
                    [string]$inventorySource.expected_inventory_sha256) {
                Throw-PackagePolicy -Code 'STAGE_EXACT_TREE_IDENTITY' -Path $relativeRoot
            }
        } elseif ($type -eq 'allowlisted_files_v1') {
            foreach ($relativePath in @($inventorySource.relative_paths)) {
                & $addPath ([string]$relativePath)
            }
        } else {
            Throw-PackagePolicy -Code 'STAGE_SOURCE_TYPE' -Path $type
        }
    }
    if ($paths.Count -gt $script:MaximumPackageFiles) {
        Throw-PackagePolicy -Code 'RESOURCE_FILE_LIMIT' -Path $destinationFull
    }
    $orderedPaths = @($paths | Sort-Object -CaseSensitive)
    $copyPlan = [Collections.Generic.List[object]]::new()
    [Int64]$copiedBytes = 0
    foreach ($relativePath in $orderedPaths) {
        $sourcePath = Resolve-SafeRelativePath -Root $sourceFull -RelativePath $relativePath `
            -Label 'customer stage source'
        $sourceIdentity = Get-LockedIdentity -Path $sourcePath -Label 'customer stage source'
        if ($sourceIdentity.size_bytes -gt $script:MaximumAggregateBytes - $copiedBytes) {
            Throw-PackagePolicy -Code 'RESOURCE_TOTAL_BYTES_LIMIT' -Path $relativePath
        }
        $copyPlan.Add([pscustomobject]@{
            relative_path = $relativePath
            source_path = $sourcePath
            size_bytes = [Int64]$sourceIdentity.size_bytes
            sha256 = [string]$sourceIdentity.sha256
        })
        $copiedBytes += [Int64]$sourceIdentity.size_bytes
    }
    if ([IO.Directory]::Exists($destinationFull)) {
        Get-BoundedTreeInventory -Root $destinationFull -AllowForbiddenPaths | Out-Null
    } elseif ([IO.File]::Exists($destinationFull)) {
        Throw-PackagePolicy -Code 'STAGE_DESTINATION_TYPE' -Path $destinationFull
    }
    $candidateFull = Join-Path $candidateAnchorFull ('.aida-c03-candidate-' + [Guid]::NewGuid().ToString('N'))
    [IO.Directory]::CreateDirectory($candidateFull) | Out-Null
    $candidateDirectoryIdentity = Get-DirectoryIdentity -Path $candidateFull
    $retainCandidate = $false
    try {
        foreach ($copyEntry in $copyPlan) {
            $relativePath = [string]$copyEntry.relative_path
            $candidatePath = [IO.Path]::GetFullPath((Join-Path $candidateFull ($relativePath -replace '/', '\')))
            $candidateDirectory = Split-Path -Parent $candidatePath
            [IO.Directory]::CreateDirectory($candidateDirectory) | Out-Null
            [IO.File]::Copy([string]$copyEntry.source_path, $candidatePath, $false)
            $candidateFileIdentity = Get-LockedIdentity -Path $candidatePath -Label 'customer stage candidate' -AllowRename
            if ([Int64]$candidateFileIdentity.size_bytes -ne [Int64]$copyEntry.size_bytes -or
                [string]$candidateFileIdentity.sha256 -cne [string]$copyEntry.sha256) {
                Throw-PackagePolicy -Code 'STAGE_COPY_IDENTITY' -Path $relativePath
            }
        }
        $candidateInventory = Get-BoundedTreeInventory -Root $candidateFull
        if ($candidateInventory.file_count -ne $orderedPaths.Count -or
            [Int64]$candidateInventory.total_size_bytes -ne $copiedBytes) {
            Throw-PackagePolicy -Code 'STAGE_EXACT_INVENTORY' -Path $candidateFull
        }
        Assert-ImmutableGeneration
        $retainCandidate = $true
        return [pscustomobject]@{
            candidate_path = $candidateFull
            candidate_identity = $candidateDirectoryIdentity
            destination_path = $destinationFull
            publication_anchor = $publicationAnchorFull
            inventory = $candidateInventory
        }
    } finally {
        if (-not $retainCandidate -and [IO.Directory]::Exists($candidateFull)) {
            Remove-OwnedGenerationDirectory -Path $candidateFull -Anchor $candidateAnchorFull -ExpectedIdentity $candidateDirectoryIdentity -AllowedPrefix '.aida-c03-candidate-'
        }
    }
}

function Start-ImmutableGeneration {
    if ($null -ne $script:ImmutableGeneration) {
        Throw-PackagePolicy -Code 'GENERATION_STATE' -Path 'already-active'
    }
    $script:ImmutableGeneration = [Collections.Generic.Dictionary[string, object]]::new(
        [StringComparer]::Ordinal)
}

function Stop-ImmutableGeneration {
    if ($null -eq $script:ImmutableGeneration) { return }
    foreach ($entry in $script:ImmutableGeneration.Values) {
        if ($null -ne $entry.stream) {
            $entry.stream.Dispose()
        }
    }
    $script:ImmutableGeneration = $null
}

function Test-IdentityEqual {
    param([object]$Left, [object]$Right)
    return [UInt32]$Left.VolumeSerialNumber -eq [UInt32]$Right.VolumeSerialNumber -and
        [UInt32]$Left.FileIndexHigh -eq [UInt32]$Right.FileIndexHigh -and
        [UInt32]$Left.FileIndexLow -eq [UInt32]$Right.FileIndexLow -and
        [UInt32]$Left.FileSizeHigh -eq [UInt32]$Right.FileSizeHigh -and
        [UInt32]$Left.FileSizeLow -eq [UInt32]$Right.FileSizeLow -and
        [UInt32]$Left.NumberOfLinks -eq 1 -and
        [UInt32]$Right.NumberOfLinks -eq 1 -and
        [Int32]$Left.LastWriteTime.dwHighDateTime -eq [Int32]$Right.LastWriteTime.dwHighDateTime -and
        [Int32]$Left.LastWriteTime.dwLowDateTime -eq [Int32]$Right.LastWriteTime.dwLowDateTime
}

function Get-FileIdentityKey {
    param([object]$Identity)
    return ([string][UInt32]$Identity.VolumeSerialNumber + ':' +
        ([UInt64][UInt32]$Identity.FileIndexHigh).ToString('x8') +
        ([UInt64][UInt32]$Identity.FileIndexLow).ToString('x8'))
}

function Get-LockedFinalPath {
    param([object]$Entry)
    $buffer = New-Object Text.StringBuilder 32768
    $length = [AidaC03PackageNative]::GetFinalPathNameByHandleW(
        $Entry.stream.SafeFileHandle.DangerousGetHandle(), $buffer, 32768, 0)
    if ($length -eq 0 -or $length -ge 32768) {
        Throw-PackagePolicy -Code 'GENERATION_FINAL_PATH' -Path ([string]$Entry.path)
    }
    $final = $buffer.ToString()
    if ($final.StartsWith('\\?\UNC\', [StringComparison]::Ordinal)) {
        Throw-PackagePolicy -Code 'GENERATION_FINAL_VOLUME' -Path ([string]$Entry.path)
    }
    if ($final.StartsWith('\\?\', [StringComparison]::Ordinal)) {
        $final = $final.Substring(4)
    }
    return $final
}

function Get-LockedIdentity {
    param(
        [string]$Path,
        [string]$Label,
        [Int64]$MaximumBytes = 8589934592,
        [switch]$AllowRename,
        [switch]$Transient,
        [switch]$CaptureBytes
    )
    $fullPath = [IO.Path]::GetFullPath($Path)
    if (-not $Transient -and $null -ne $script:ImmutableGeneration -and
        $script:ImmutableGeneration.ContainsKey($fullPath)) {
        $existing = $script:ImmutableGeneration[$fullPath]
        if ([Int64]$existing.size_bytes -gt $MaximumBytes) {
            throw "$Label size violates policy"
        }
        return [pscustomobject]@{
            size_bytes = [Int64]$existing.size_bytes
            sha256 = [string]$existing.sha256
            file_identity = [string]$existing.file_identity
            bytes = $existing.bytes
        }
    }
    Assert-RegularFile -Path $fullPath -Label $Label | Out-Null
    $share = [IO.FileShare]::Read
    if ($AllowRename) {
        $share = $share -bor [IO.FileShare]::Delete
    }
    $stream = [IO.File]::Open($fullPath, [IO.FileMode]::Open, [IO.FileAccess]::Read, $share)
    try {
        if ($stream.Length -le 0 -or $stream.Length -gt $MaximumBytes) {
            throw "$Label size violates policy"
        }
        $identityBefore = New-Object AidaC03PackageNative+BY_HANDLE_FILE_INFORMATION
        if (-not [AidaC03PackageNative]::GetFileInformationByHandle(
                $stream.SafeFileHandle.DangerousGetHandle(), [ref]$identityBefore)) {
            Throw-PackagePolicy -Code 'GENERATION_IDENTITY' -Path $fullPath
        }
        if ([UInt32]$identityBefore.NumberOfLinks -ne 1) {
            Throw-PackagePolicy -Code 'HARDLINK_FORBIDDEN' -Path $fullPath
        }
        $sha = [Security.Cryptography.SHA256]::Create()
        try {
            $digest = $sha.ComputeHash($stream)
        } finally {
            $sha.Dispose()
        }
        $capturedBytes = $null
        if ($CaptureBytes) {
            if ($stream.Length -gt [int]::MaxValue) {
                Throw-PackagePolicy -Code 'RESOURCE_FILE_BYTES_LIMIT' -Path $fullPath
            }
            $capturedBytes = [byte[]]::new([int]$stream.Length)
            $stream.Position = 0
            $capturedOffset = 0
            while ($capturedOffset -lt $capturedBytes.Length) {
                $captured = $stream.Read(
                    $capturedBytes, $capturedOffset,
                    $capturedBytes.Length - $capturedOffset)
                if ($captured -le 0) {
                    Throw-PackagePolicy -Code 'GENERATION_CHANGED' -Path $fullPath
                }
                $capturedOffset += $captured
            }
        }
        $identityAfter = New-Object AidaC03PackageNative+BY_HANDLE_FILE_INFORMATION
        if (-not [AidaC03PackageNative]::GetFileInformationByHandle(
                $stream.SafeFileHandle.DangerousGetHandle(), [ref]$identityAfter) -or
            -not (Test-IdentityEqual -Left $identityBefore -Right $identityAfter)) {
            Throw-PackagePolicy -Code 'GENERATION_CHANGED' -Path $fullPath
        }
        $capturedPath = Get-LockedFinalPath -Entry ([pscustomobject]@{ stream = $stream; path = $fullPath })
        if (-not [string]::Equals($capturedPath, $fullPath, [StringComparison]::Ordinal)) {
            Throw-PackagePolicy -Code 'GENERATION_FINAL_PATH' -Path $fullPath
        }
        $result = [pscustomobject]@{
            size_bytes = [Int64]$stream.Length
            sha256 = ([BitConverter]::ToString($digest) -replace '-', '').ToLowerInvariant()
            file_identity = Get-FileIdentityKey -Identity $identityAfter
            bytes = $capturedBytes
        }
        if (-not $Transient -and $null -ne $script:ImmutableGeneration) {
            $script:ImmutableGeneration.Add($fullPath, [pscustomobject]@{
                path = $fullPath
                stream = $stream
                identity = $identityAfter
                size_bytes = [Int64]$result.size_bytes
                sha256 = [string]$result.sha256
                file_identity = [string]$result.file_identity
                bytes = $capturedBytes
                allow_rename = [bool]$AllowRename
                expected_final_path = $fullPath
            })
            $stream = $null
        }
        return $result
    } finally {
        if ($null -ne $stream) {
            $stream.Dispose()
        }
    }
}

function Get-LockedBytes {
    param(
        [string]$Path,
        [string]$Label,
        [Int64]$MaximumBytes
    )
    $fullPath = [IO.Path]::GetFullPath($Path)
    $identity = Get-LockedIdentity -Path $fullPath -Label $Label -MaximumBytes $MaximumBytes
    if ($null -eq $script:ImmutableGeneration -or
        -not $script:ImmutableGeneration.ContainsKey($fullPath)) {
        Throw-PackagePolicy -Code 'GENERATION_STATE' -Path $fullPath
    }
    $entry = $script:ImmutableGeneration[$fullPath]
    if ($null -eq $entry.bytes) {
        if ([Int64]$entry.size_bytes -gt [Int64][int]::MaxValue) {
            Throw-PackagePolicy -Code 'RESOURCE_FILE_BYTES_LIMIT' -Path $fullPath
        }
        $bytes = New-Object byte[] ([int]$entry.size_bytes)
        $entry.stream.Position = 0
        $offset = 0
        while ($offset -lt $bytes.Length) {
            $received = $entry.stream.Read($bytes, $offset, $bytes.Length - $offset)
            if ($received -le 0) {
                Throw-PackagePolicy -Code 'GENERATION_CHANGED' -Path $fullPath
            }
            $offset += $received
        }
        $entry.bytes = $bytes
    }
    return [pscustomobject]@{
        identity = $identity
        bytes = [byte[]]$entry.bytes
    }
}

function Assert-ImmutableGeneration {
    if ($null -eq $script:ImmutableGeneration) {
        Throw-PackagePolicy -Code 'GENERATION_STATE' -Path 'not-active'
    }
    foreach ($entry in $script:ImmutableGeneration.Values) {
        $current = New-Object AidaC03PackageNative+BY_HANDLE_FILE_INFORMATION
        if (-not [AidaC03PackageNative]::GetFileInformationByHandle(
                $entry.stream.SafeFileHandle.DangerousGetHandle(), [ref]$current) -or
            -not (Test-IdentityEqual -Left $entry.identity -Right $current)) {
            Throw-PackagePolicy -Code 'GENERATION_CHANGED' -Path ([string]$entry.path)
        }
        if (-not [bool]$entry.allow_rename) {
            Get-ExactExistingPath -Path ([string]$entry.path).Replace('\', '/') -Label 'immutable generation member' -Kind File | Out-Null
        }
        $sha = [Security.Cryptography.SHA256]::Create()
        try {
            $entry.stream.Position = 0
            $digest = ([BitConverter]::ToString($sha.ComputeHash($entry.stream)) -replace '-', '').ToLowerInvariant()
        } finally {
            $sha.Dispose()
        }
        if ($digest -cne [string]$entry.sha256) {
            Throw-PackagePolicy -Code 'GENERATION_CHANGED' -Path ([string]$entry.path)
        }
        $streamPath = if ([bool]$entry.allow_rename) {
            Get-LockedFinalPath -Entry $entry
        } else {
            [string]$entry.path
        }
        if (-not [string]::Equals($streamPath, [string]$entry.expected_final_path,
                [StringComparison]::Ordinal)) {
            Throw-PackagePolicy -Code 'GENERATION_FINAL_PATH' -Path ([string]$entry.path)
        }
        Assert-NoNamedStreams -Path $streamPath | Out-Null
    }
}

function Set-ImmutableGenerationExpectedPathPrefix {
    param([string]$OldRoot, [string]$NewRoot)
    $oldFull = [IO.Path]::GetFullPath($OldRoot).TrimEnd([IO.Path]::DirectorySeparatorChar)
    $newFull = [IO.Path]::GetFullPath($NewRoot).TrimEnd([IO.Path]::DirectorySeparatorChar)
    foreach ($entry in $script:ImmutableGeneration.Values) {
        $entryPath = [string]$entry.expected_final_path
        if ([string]::Equals($entryPath, $oldFull, [StringComparison]::Ordinal) -or
            $entryPath.StartsWith($oldFull + [IO.Path]::DirectorySeparatorChar,
                [StringComparison]::Ordinal)) {
            $relative = $entryPath.Substring($oldFull.Length).TrimStart([IO.Path]::DirectorySeparatorChar)
            $entry.expected_final_path = if ([string]::IsNullOrEmpty($relative)) {
                $newFull
            } else {
                Join-Path $newFull $relative
            }
        }
    }
}

function Read-StrictJson {
    param(
        [string]$Path,
        [string]$Label
    )
    $locked = Get-LockedBytes -Path $Path -Label $Label -MaximumBytes 16777216
    $identity = $locked.identity
    $text = [Text.UTF8Encoding]::new($false, $true).GetString($locked.bytes)
    if ($text -match 'https?://|ftp://|git://|ssh://|file://|"(?:\$ref|\$id|url|uri)"\s*:') {
        throw "$Label contains a remote reference"
    }
    return [pscustomobject]@{
        identity = $identity
        value = $text | ConvertFrom-Json
    }
}

function Resolve-SafeRelativePath {
    param(
        [string]$Root,
        [string]$RelativePath,
        [string]$Label
    )
    if ([IO.Path]::IsPathRooted($RelativePath) -or
        (Test-ForbiddenCustomerRelativePath -RelativePath $RelativePath)) {
        throw "$Label contains an unsafe relative path"
    }
    $path = [IO.Path]::GetFullPath((Join-Path $Root ($RelativePath -replace '/', '\')))
    $normalizedRoot = [IO.Path]::GetFullPath($Root).TrimEnd([IO.Path]::DirectorySeparatorChar)
    if (-not $path.StartsWith($normalizedRoot + [IO.Path]::DirectorySeparatorChar, [StringComparison]::OrdinalIgnoreCase)) {
        throw "$Label escapes the package root"
    }
    $cursor = $path
    while ($cursor -and $cursor.Length -ge $normalizedRoot.Length) {
        if ([IO.Directory]::Exists($cursor) -or [IO.File]::Exists($cursor)) {
            $item = Get-Item -LiteralPath $cursor -Force
            if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
                throw "$Label crosses a reparse point"
            }
        }
        if ([string]::Equals($cursor.TrimEnd([IO.Path]::DirectorySeparatorChar), $normalizedRoot, [StringComparison]::OrdinalIgnoreCase)) {
            break
        }
        $cursor = Split-Path -Parent $cursor
    }
    $canonicalInput = $path.Replace('\', '/')
    Get-ExactExistingPath -Path $canonicalInput -Label $Label -Kind Any | Out-Null
    return $path
}

function Write-AtomicBytes {
    param(
        [string]$Path,
        [byte[]]$Bytes,
        [switch]$Replace
    )
    $parent = Split-Path -Parent $Path
    $parentItem = Get-Item -LiteralPath $parent -Force
    if (-not $parentItem.PSIsContainer -or ($parentItem.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
        throw 'manifest output directory must be a regular non-reparse directory'
    }
    if ([IO.File]::Exists($Path) -and -not $Replace) {
        throw "manifest output already exists: $Path"
    }
    if ([IO.File]::Exists($Path)) {
        Assert-RegularFile -Path $Path -Label 'existing manifest output' | Out-Null
    }
    $temporary = Join-Path $parent ('.' + [IO.Path]::GetFileName($Path) + '.' + [Guid]::NewGuid().ToString('N') + '.tmp')
    $stream = [IO.File]::Open($temporary, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write, [IO.FileShare]::None)
    try {
        $stream.Write($Bytes, 0, $Bytes.Length)
        $stream.Flush($true)
    } finally {
        $stream.Dispose()
    }
    try {
        if ([IO.File]::Exists($Path)) {
            [IO.File]::Replace($temporary, $Path, $null, $true)
        } else {
            [IO.File]::Move($temporary, $Path)
        }
    } finally {
        if ([IO.File]::Exists($temporary)) {
            [IO.File]::Delete($temporary)
        }
    }
}

function Get-CanonicalInventorySha256 {
    param([object[]]$Entries)
    $rows = @($Entries | Sort-Object -Property relative_path -CaseSensitive | ForEach-Object {
        ([string]$_.relative_path) + '|' + ([Int64]$_.size_bytes).ToString([Globalization.CultureInfo]::InvariantCulture) + '|' + ([string]$_.sha256)
    })
    $bytes = [Text.UTF8Encoding]::new($false, $true).GetBytes(($rows -join "`n"))
    $sha = [Security.Cryptography.SHA256]::Create()
    try {
        return ([BitConverter]::ToString($sha.ComputeHash($bytes)) -replace '-', '').ToLowerInvariant()
    } finally {
        $sha.Dispose()
    }
}

function Get-TextSha256 {
    param([string]$Text)
    $bytes = [Text.UTF8Encoding]::new($false, $true).GetBytes($Text)
    $sha = [Security.Cryptography.SHA256]::Create()
    try {
        return ([BitConverter]::ToString($sha.ComputeHash($bytes)) -replace '-', '').ToLowerInvariant()
    } finally {
        $sha.Dispose()
    }
}

function Assert-DigestBinding {
    param(
        [string]$ManifestPath,
        [string]$DigestPath,
        [string]$Label
    )
    $manifestIdentity = Get-LockedIdentity -Path $ManifestPath -Label "$Label manifest" -MaximumBytes 16777216
    $digestLocked = Get-LockedBytes -Path $DigestPath -Label "$Label digest" -MaximumBytes 256
    $digestIdentity = $digestLocked.identity
    if ($digestIdentity.size_bytes -ne 65) {
        throw "$Label digest has an invalid size"
    }
    $digestText = [Text.Encoding]::ASCII.GetString($digestLocked.bytes)
    if ($digestText -cnotmatch '^[0-9a-f]{64}\n$' -or $digestText.Substring(0, 64) -cne $manifestIdentity.sha256) {
        throw "$Label manifest digest binding is invalid"
    }
    return $manifestIdentity
}

function Add-PackageArtifact {
    param(
        [hashtable]$Ids,
        [hashtable]$Paths,
        [Collections.Generic.List[object]]$Output,
        [ref]$TotalBytes,
        [string]$Root,
        [string]$Id,
        [string]$Kind,
        [string]$RelativePath,
        [string]$Owner,
        [string[]]$LicenseIds,
        [object]$ExpectedIdentity = $null
    )
    if ($Id -cnotmatch '^[A-Za-z0-9_.-]{1,256}$' -or $Owner -cnotmatch '^[A-Za-z0-9_.-]{1,256}$' -or
        $Kind -notin @('application', 'application_runtime', 'worker_executable', 'worker_runtime', 'worker_manifest', 'resource_manifest', 'manifest_digest', 'acl_receipt', 'build_receipt', 'protector_receipt', 'signature_receipt', 'browser', 'reverse_mcp', 'license', 'notice', 'dependency', 'resource', 'build_evidence') -or
        $Ids.ContainsKey($Id) -or $Paths.ContainsKey($RelativePath)) {
        throw 'distribution artifact id, owner, kind, or path is invalid or duplicated'
    }
    if ($LicenseIds.Count -gt 128 -or @($LicenseIds | Where-Object { $_ -cnotmatch '^[A-Za-z0-9_.-]{1,256}$' }).Count -ne 0) {
        throw "distribution artifact license identity is invalid: $Id"
    }
    if (Test-ForbiddenCustomerRelativePath -RelativePath $RelativePath) {
        throw "customer package contains a forbidden source, SDK, package, symbol, build artifact, or stock browser: $RelativePath"
    }
    $path = Resolve-SafeRelativePath -Root $Root -RelativePath $RelativePath -Label 'distribution artifact'
    $identity = Get-LockedIdentity -Path $path -Label 'distribution artifact'
    if ($null -ne $ExpectedIdentity -and
        ([Int64]$ExpectedIdentity.size_bytes -ne [Int64]$identity.size_bytes -or
         [string]$ExpectedIdentity.sha256 -cne [string]$identity.sha256)) {
        throw "distribution artifact identity differs from its producer manifest: $RelativePath"
    }
    if ($identity.size_bytes -gt 17179869184 - [Int64]$TotalBytes.Value) {
        throw 'customer package exceeds the bounded total artifact budget'
    }
    $TotalBytes.Value = [Int64]$TotalBytes.Value + [Int64]$identity.size_bytes
    $Ids[$Id] = $true
    $Paths[$RelativePath] = $true
    $Output.Add([ordered]@{
        id = $Id
        kind = $Kind
        relative_path = $RelativePath
        size_bytes = [Int64]$identity.size_bytes
        sha256 = [string]$identity.sha256
        owner = $Owner
        license_ids = @($LicenseIds)
    })
}

function Get-ArtifactById {
    param([Collections.Generic.List[object]]$Artifacts, [string]$Id, [string]$Label)
    $matches = @($Artifacts | Where-Object { [string]$_.id -ceq $Id })
    if ($matches.Count -ne 1) {
        throw "$Label artifact identity is missing or duplicated"
    }
    return $matches[0]
}

function Assert-ProtectorReceipt {
    param([string]$Root, [object]$ReceiptArtifact, [object]$ExecutableArtifact)
    if ($ReceiptArtifact.kind -ne 'protector_receipt') {
        throw 'protector receipt artifact kind is invalid'
    }
    $path = Resolve-SafeRelativePath -Root $Root -RelativePath ([string]$ReceiptArtifact.relative_path) -Label 'protector receipt'
    $receipt = (Read-StrictJson -Path $path -Label 'protector receipt').value
    Assert-ExactProperties -Value $receipt -Expected @('artifact_relative_path', 'artifact_sha256', 'artifact_size_bytes', 'post_process', 'production_flags', 'profile', 'schema', 'schema_version', 'signer_policy_sha256', 'signing_provider_sha256', 'status', 'tool_sha256', 'verifier_sha256') -Label 'protector receipt'
    Assert-ExactProperties -Value $receipt.post_process -Expected @('codeview_records', 'coff_symbol_count', 'coff_symbol_table_pointer', 'dans_signature_count', 'debug_directory_complete', 'debug_directory_entries', 'pe_headers_complete', 'protection_checks_passed', 'protection_checks_total', 'rich_signature_count', 'unscrubbed_debug_paths') -Label 'protector post-process receipt'
    $expectedFlags = @('/Qspectre', '/sdl', '/guard:cf', '/guard:ehcont', '/guard:xfg') | Sort-Object -CaseSensitive
    $actualFlags = @($receipt.production_flags | ForEach-Object { [string]$_ } | Sort-Object -CaseSensitive -Unique)
    $expectedProfile = if ([string]$ExecutableArtifact.relative_path -ceq 'AiDAStandalone.exe') {
        'standalone-no-imports'
    } else {
        'strict-no-imports'
    }
    if ($receipt.schema -ne 'aida.protector.receipt' -or [int]$receipt.schema_version -ne 4 -or
        $receipt.status -ne 'passed' -or $receipt.profile -cne $expectedProfile -or
        $receipt.artifact_relative_path -cne [string]$ExecutableArtifact.relative_path -or
        $receipt.artifact_sha256 -cne [string]$ExecutableArtifact.sha256 -or
        [Int64]$receipt.artifact_size_bytes -ne [Int64]$ExecutableArtifact.size_bytes -or
        [string]$receipt.tool_sha256 -cnotmatch '^[0-9a-f]{64}$' -or
        [string]$receipt.verifier_sha256 -cnotmatch '^[0-9a-f]{64}$' -or
        [string]$receipt.signer_policy_sha256 -cnotmatch '^[0-9a-f]{64}$' -or
        [string]$receipt.signing_provider_sha256 -cnotmatch '^[0-9a-f]{64}$' -or
        [Int64]$receipt.post_process.protection_checks_total -le 0 -or
        [Int64]$receipt.post_process.protection_checks_passed -ne [Int64]$receipt.post_process.protection_checks_total -or
        [Int64]$receipt.post_process.coff_symbol_table_pointer -ne 0 -or
        [Int64]$receipt.post_process.coff_symbol_count -ne 0 -or
        [Int64]$receipt.post_process.debug_directory_entries -lt 0 -or
        [Int64]$receipt.post_process.debug_directory_entries -gt 4096 -or
        [Int64]$receipt.post_process.codeview_records -lt 0 -or
        [Int64]$receipt.post_process.codeview_records -gt [Int64]$receipt.post_process.debug_directory_entries -or
        [Int64]$receipt.post_process.unscrubbed_debug_paths -ne 0 -or
        [Int64]$receipt.post_process.rich_signature_count -ne 0 -or
        [Int64]$receipt.post_process.dans_signature_count -ne 0 -or
        -not [bool]$receipt.post_process.pe_headers_complete -or
        -not [bool]$receipt.post_process.debug_directory_complete -or
        $actualFlags.Count -ne $expectedFlags.Count -or
        ($actualFlags -join "`n") -cne ($expectedFlags -join "`n")) {
        throw 'protector receipt is invalid or does not bind the protected artifact'
    }
    if ($null -eq $script:SignerPolicyReceiptSha256) {
        $script:SignerPolicyReceiptSha256 = [string]$receipt.signer_policy_sha256
        $script:SigningProviderReceiptSha256 = [string]$receipt.signing_provider_sha256
    } elseif ([string]$receipt.signer_policy_sha256 -cne $script:SignerPolicyReceiptSha256 -or
        [string]$receipt.signing_provider_sha256 -cne $script:SigningProviderReceiptSha256) {
        throw 'protector receipts do not share one signing authority generation'
    }
}

function Assert-SignatureReceipt {
    param([string]$Root, [object]$ReceiptArtifact, [object]$ExecutableArtifact)
    if ($ReceiptArtifact.kind -ne 'signature_receipt') {
        throw 'signature receipt artifact kind is invalid'
    }
    $path = Resolve-SafeRelativePath -Root $Root -RelativePath ([string]$ReceiptArtifact.relative_path) -Label 'signature receipt'
    $receipt = (Read-StrictJson -Path $path -Label 'signature receipt').value
    Assert-ExactProperties -Value $receipt -Expected @('artifact_relative_path', 'artifact_sha256', 'artifact_size_bytes', 'chain_status', 'schema', 'schema_version', 'signer_policy_sha256', 'signer_thumbprint_sha256', 'signing_provider_sha256', 'status', 'timestamp_filetime', 'timestamp_status', 'timestamp_validation', 'verification_mode', 'verifier_sha256') -Label 'signature receipt'
    if ($receipt.schema -ne 'aida.signature.receipt' -or [int]$receipt.schema_version -ne 4 -or
        $receipt.status -ne 'verified' -or $receipt.verification_mode -ne 'wintrust_offline' -or
        $receipt.chain_status -ne 'trusted' -or $receipt.timestamp_status -ne 'trusted' -or
        $receipt.timestamp_validation -ne 'wintrust_provider_counter_signer' -or
        [Int64]$receipt.timestamp_filetime -le 0 -or
        $receipt.artifact_relative_path -cne [string]$ExecutableArtifact.relative_path -or
        $receipt.artifact_sha256 -cne [string]$ExecutableArtifact.sha256 -or
        [Int64]$receipt.artifact_size_bytes -ne [Int64]$ExecutableArtifact.size_bytes -or
        [string]$receipt.signer_thumbprint_sha256 -cnotmatch '^[0-9a-f]{64}$' -or
        [string]$receipt.verifier_sha256 -cnotmatch '^[0-9a-f]{64}$' -or
        [string]$receipt.signer_policy_sha256 -cne $script:SignerPolicyReceiptSha256 -or
        [string]$receipt.signing_provider_sha256 -cne $script:SigningProviderReceiptSha256) {
        throw 'signature receipt is invalid or does not bind the signed artifact'
    }
}

$productionStage = $null
$productionCandidateAnchor = $null
$evidenceCandidatePath = $null
$evidenceCandidateIdentity = $null
$evidencePublicationAnchor = $null
$evidenceRootPath = $null
$stageOwnerPath = $null
$generationPointerPath = $null
if (($FixturePublicationFailure -cne 'none' -or $FixturePublicationTermination -cne 'none') -and
    (-not $PolicyFixtureReport -or -not $StagePolicyFixture)) {
    Throw-PackagePolicy -Code 'FIXTURE_PUBLICATION_ARGUMENT' -Path (
        $FixturePublicationFailure + ':' + $FixturePublicationTermination)
}
if ($FixturePublicationFailure -cne 'none' -and
    $FixturePublicationTermination -cne 'none') {
    Throw-PackagePolicy -Code 'FIXTURE_PUBLICATION_ARGUMENT' -Path 'multiple'
}
Start-ImmutableGeneration
try {
if ($PolicyFixtureReport) {
    if ($AuthorityLock -or $OutputManifest -or $OutputDigest -or $EvidenceRoot -or $StageOwnerRoot -or
        ($StageCustomerPackage -and -not $StagePolicyFixture) -or
        ($StagePolicyFixture -and -not $StageCustomerPackage) -or
        ($StagePolicyFixture -and (-not $Spec -or -not $SourceRoot -or -not $ApplicationStageAnchor -or -not $CustomerStageAnchor)) -or
        (-not $StagePolicyFixture -and ($Spec -or $SourceRoot -or $ApplicationStageAnchor -or $CustomerStageAnchor))) {
        Throw-PackagePolicy -Code 'FIXTURE_ARGUMENTS' -Path $PackageRoot
    }
    $fixtureLimits = @(
        [pscustomobject]@{ name = 'files'; value = $FixtureMaximumFiles; maximum = $script:MaximumPackageFiles }
        [pscustomobject]@{ name = 'directories'; value = $FixtureMaximumDirectories; maximum = $script:MaximumPackageDirectories }
        [pscustomobject]@{ name = 'entries'; value = $FixtureMaximumEntries; maximum = $script:MaximumPackageEntries }
        [pscustomobject]@{ name = 'depth'; value = $FixtureMaximumDepth; maximum = $script:MaximumPackageDepth }
        [pscustomobject]@{ name = 'relative_path_bytes'; value = $FixtureMaximumRelativePathBytes; maximum = $script:MaximumRelativePathBytes }
        [pscustomobject]@{ name = 'inventory_path_bytes'; value = $FixtureMaximumInventoryPathBytes; maximum = $script:MaximumInventoryPathBytes }
        [pscustomobject]@{ name = 'entry_bytes'; value = $FixtureMaximumEntryBytes; maximum = $script:MaximumEntryBytes }
        [pscustomobject]@{ name = 'aggregate_bytes'; value = $FixtureMaximumAggregateBytes; maximum = $script:MaximumAggregateBytes }
    )
    foreach ($limit in $fixtureLimits) {
        if ([Int64]$limit.value -lt 0 -or [Int64]$limit.value -gt [Int64]$limit.maximum) {
            Throw-PackagePolicy -Code 'FIXTURE_RESOURCE_LIMIT' -Path ([string]$limit.name)
        }
    }
    if ($FixtureMaximumFiles -gt 0) { $script:MaximumPackageFiles = $FixtureMaximumFiles }
    if ($FixtureMaximumDirectories -gt 0) { $script:MaximumPackageDirectories = $FixtureMaximumDirectories }
    if ($FixtureMaximumEntries -gt 0) { $script:MaximumPackageEntries = $FixtureMaximumEntries }
    if ($FixtureMaximumDepth -gt 0) { $script:MaximumPackageDepth = $FixtureMaximumDepth }
    if ($FixtureMaximumRelativePathBytes -gt 0) { $script:MaximumRelativePathBytes = $FixtureMaximumRelativePathBytes }
    if ($FixtureMaximumInventoryPathBytes -gt 0) { $script:MaximumInventoryPathBytes = $FixtureMaximumInventoryPathBytes }
    if ($FixtureMaximumEntryBytes -gt 0) { $script:MaximumEntryBytes = $FixtureMaximumEntryBytes }
    if ($FixtureMaximumAggregateBytes -gt 0) { $script:MaximumAggregateBytes = $FixtureMaximumAggregateBytes }
    if ($StagePolicyFixture) {
        $sourceFixture = Get-ExactExistingPath -Path $SourceRoot -Label 'fixture source root' -Kind Directory
        $candidateAnchorFixture = Get-ExactExistingPath -Path $ApplicationStageAnchor -Label 'fixture application anchor' -Kind Directory
        $anchorFixture = Get-ExactExistingPath -Path $CustomerStageAnchor -Label 'fixture customer anchor' -Kind Directory
        $specFixture = Get-ExactExistingPath -Path $Spec -Label 'fixture stage specification' -Kind File
        $productionCandidateAnchor = $candidateAnchorFixture
        $productionStage = Stage-SanitizedCustomerPackage -Source $sourceFixture `
            -Destination ((ConvertTo-CanonicalNativePath -Path $PackageRoot -Label 'fixture package root')) `
            -CandidateAnchor $candidateAnchorFixture -PublicationAnchor $anchorFixture `
            -SpecificationPath $specFixture
    }
    $fixtureRoot = if ($null -ne $productionStage) {
        Get-ExactExistingPath -Path ([string]$productionStage.candidate_path) -Label 'fixture package candidate' -Kind Directory
    } else {
        Get-ExactExistingPath -Path $PackageRoot -Label 'fixture package root' -Kind Directory
    }
    $fixtureReportPath = Get-ExactOutputPath -Path $PolicyFixtureReport -Label 'fixture report'
    if (Test-ContainedPath -Candidate $fixtureReportPath -Root $fixtureRoot) {
        Throw-PackagePolicy -Code 'FIXTURE_REPORT_CONTAINMENT' -Path $fixtureReportPath
    }
    $fixtureInventory = Get-BoundedTreeInventory -Root $fixtureRoot
    $fixtureResult = [ordered]@{
        schema = 'aida.c03.package-policy-fixture.v1'
        file_count = $fixtureInventory.file_count
        directory_count = $fixtureInventory.directory_count
        entry_count = $fixtureInventory.entry_count
        total_size_bytes = $fixtureInventory.total_size_bytes
        inventory_path_bytes = $fixtureInventory.inventory_path_bytes
        stream_inventory_count = $fixtureInventory.stream_inventory_count
        package_root = if ($null -ne $productionStage) { [string]$productionStage.destination_path } else { $fixtureRoot }
    }
    $fixtureBytes = [Text.UTF8Encoding]::new($false, $true).GetBytes(
        (($fixtureResult | ConvertTo-Json -Compress) + "`n"))
    if ($null -ne $productionStage) {
        $fixtureDigestPath = $fixtureReportPath + '.sha256'
        $fixtureSha = [Security.Cryptography.SHA256]::Create()
        try {
            $fixtureDigest = ([BitConverter]::ToString($fixtureSha.ComputeHash($fixtureBytes)) -replace '-', '').ToLowerInvariant()
        } finally {
            $fixtureSha.Dispose()
        }
        $evidencePublicationAnchor = Split-Path -Parent $fixtureReportPath
        $evidenceCandidatePath = Join-Path $evidencePublicationAnchor ('.aida-c03-evidence-candidate-' + [Guid]::NewGuid().ToString('N'))
        [IO.Directory]::CreateDirectory($evidenceCandidatePath) | Out-Null
        $evidenceCandidateIdentity = Get-DirectoryIdentity -Path $evidenceCandidatePath
        $fixtureManifestCandidate = Join-Path $evidenceCandidatePath ([IO.Path]::GetFileName($fixtureReportPath))
        $fixtureDigestCandidate = Join-Path $evidenceCandidatePath ([IO.Path]::GetFileName($fixtureDigestPath))
        Write-AtomicBytes -Path $fixtureManifestCandidate -Bytes $fixtureBytes
        Write-AtomicBytes -Path $fixtureDigestCandidate -Bytes ([Text.Encoding]::ASCII.GetBytes($fixtureDigest + "`n"))
        $fixtureManifestIdentity = Get-LockedIdentity -Path $fixtureManifestCandidate -Label 'fixture generation manifest' -AllowRename
        $fixtureDigestIdentity = Get-LockedIdentity -Path $fixtureDigestCandidate -Label 'fixture generation digest' -AllowRename
        $fixturePublication = Publish-CompleteGeneration -Stage $productionStage `
            -ManifestCandidate $fixtureManifestCandidate -ManifestIdentity $fixtureManifestIdentity `
            -DigestCandidate $fixtureDigestCandidate -DigestIdentity $fixtureDigestIdentity `
            -ManifestDestination $fixtureReportPath -DigestDestination $fixtureDigestPath `
            -EvidenceCandidate $evidenceCandidatePath -EvidenceCandidateIdentity $evidenceCandidateIdentity `
            -EvidencePublicationAnchor $evidencePublicationAnchor -ExpectedManifestDigest $fixtureDigest `
            -Replace:$Force
        if (-not [IO.Directory]::Exists([string]$fixturePublication.package_root) -or
            -not [IO.File]::Exists([string]$fixturePublication.pointer_path)) {
            Throw-PackagePolicy -Code 'EVIDENCE_GENERATION_CHANGED' -Path $fixtureReportPath
        }
        $productionStage = $null
        $evidenceCandidatePath = $null
    } else {
        Write-AtomicBytes -Path $fixtureReportPath -Bytes $fixtureBytes -Replace:$Force
    }
    $fixtureResult | ConvertTo-Json -Compress
    return
}

if (-not $Spec -or -not $AuthorityLock -or -not $OutputManifest -or -not $OutputDigest) {
    Throw-PackagePolicy -Code 'PRODUCTION_ARGUMENTS' -Path $PackageRoot
}
$specPath = Get-ExactExistingPath -Path $Spec -Label 'distribution specification' -Kind File
$authorityPath = Get-ExactExistingPath -Path $AuthorityLock -Label 'source authority lock' -Kind File
$manifestOutputPath = Get-ExactOutputPath -Path $OutputManifest -Label 'distribution manifest output'
$digestOutputPath = Get-ExactOutputPath -Path $OutputDigest -Label 'distribution digest output'
if ($StageCustomerPackage) {
    if (-not $SourceRoot -or -not $ApplicationStageAnchor -or -not $CustomerStageAnchor -or
        -not $EvidenceRoot -or -not $StageOwnerRoot) {
        Throw-PackagePolicy -Code 'STAGE_ARGUMENTS' -Path $PackageRoot
    }
    $stageSource = Get-ExactExistingPath -Path $SourceRoot -Label 'customer stage source' -Kind Directory
    $productionCandidateAnchor = Get-ExactExistingPath -Path $ApplicationStageAnchor -Label 'application stage anchor' -Kind Directory
    $stageAnchor = Get-ExactExistingPath -Path $CustomerStageAnchor -Label 'customer stage anchor' -Kind Directory
    $evidenceRootPath = Get-ExactExistingPath -Path $EvidenceRoot -Label 'distribution evidence root' -Kind Directory
    $stageOwnerPath = Get-ExactExistingPath -Path $StageOwnerRoot -Label 'stage owner root' -Kind Directory
    foreach ($ownedRoot in @($productionCandidateAnchor, $stageAnchor, $evidenceRootPath)) {
        if ([string]::Equals($ownedRoot, $stageOwnerPath, [StringComparison]::OrdinalIgnoreCase) -or
            -not (Test-ContainedPath -Candidate $ownedRoot -Root $stageOwnerPath)) {
            Throw-PackagePolicy -Code 'STAGE_OWNERSHIP' -Path $ownedRoot
        }
    }
    foreach ($rootPair in @(
        [pscustomobject]@{ left = $productionCandidateAnchor; right = $stageAnchor },
        [pscustomobject]@{ left = $productionCandidateAnchor; right = $evidenceRootPath },
        [pscustomobject]@{ left = $stageAnchor; right = $evidenceRootPath })) {
        if ((Test-ContainedPath -Candidate ([string]$rootPair.left) -Root ([string]$rootPair.right)) -or
            (Test-ContainedPath -Candidate ([string]$rootPair.right) -Root ([string]$rootPair.left))) {
            Throw-PackagePolicy -Code 'STAGE_ROOT_OVERLAP' -Path ([string]$rootPair.left)
        }
    }
    if ((Test-ContainedPath -Candidate $stageSource -Root $stageOwnerPath) -or
        (Test-ContainedPath -Candidate $stageOwnerPath -Root $stageSource)) {
        Throw-PackagePolicy -Code 'STAGE_SOURCE_OVERLAP' -Path $stageSource
    }
    $stageDestination = ConvertTo-CanonicalNativePath -Path $PackageRoot -Label 'customer package root'
    $productionStage = Stage-SanitizedCustomerPackage -Source $stageSource -Destination $stageDestination `
        -CandidateAnchor $productionCandidateAnchor -PublicationAnchor $stageAnchor `
        -SpecificationPath $specPath
} elseif ($SourceRoot -or $ApplicationStageAnchor -or $CustomerStageAnchor -or $EvidenceRoot -or $StageOwnerRoot) {
    Throw-PackagePolicy -Code 'STAGE_ARGUMENTS' -Path $PackageRoot
}

$root = if ($null -ne $productionStage) {
    Get-ExactExistingPath -Path ([string]$productionStage.candidate_path) -Label 'customer package candidate' -Kind Directory
} else {
    Get-ExactExistingPath -Path $PackageRoot -Label 'customer package root' -Kind Directory
}
$rootItem = Get-Item -LiteralPath $root -Force
if (-not $rootItem.PSIsContainer -or ($rootItem.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
    throw 'package root must be a regular non-reparse directory'
}
$packageInventory = Get-BoundedTreeInventory -Root $root
$manifestPath = $manifestOutputPath
$digestPath = $digestOutputPath
if ($null -ne $productionStage) {
    $evidencePublicationAnchor = Split-Path -Parent $manifestOutputPath
    if (-not [string]::Equals($evidencePublicationAnchor, (Split-Path -Parent $digestOutputPath), [StringComparison]::OrdinalIgnoreCase) -or
        -not (Test-ContainedPath -Candidate $evidencePublicationAnchor -Root $evidenceRootPath) -or
        -not (Test-ContainedPath -Candidate $evidenceRootPath -Root $stageOwnerPath) -or
        (Test-ContainedPath -Candidate $evidenceRootPath -Root $root) -or
        (Test-ContainedPath -Candidate $root -Root $evidenceRootPath)) {
        Throw-PackagePolicy -Code 'EVIDENCE_CONTAINMENT' -Path $evidencePublicationAnchor
    }
    $evidenceCandidatePath = Join-Path $evidencePublicationAnchor ('.aida-c03-evidence-candidate-' + [Guid]::NewGuid().ToString('N'))
    [IO.Directory]::CreateDirectory($evidenceCandidatePath) | Out-Null
    $evidenceCandidateIdentity = Get-DirectoryIdentity -Path $evidenceCandidatePath
    $manifestPath = Join-Path $evidenceCandidatePath ([IO.Path]::GetFileName($manifestOutputPath))
    $digestPath = Join-Path $evidenceCandidatePath ([IO.Path]::GetFileName($digestOutputPath))
}
if ([string]::Equals($manifestPath, $digestPath, [StringComparison]::OrdinalIgnoreCase) -or
    $manifestPath.StartsWith($root + [IO.Path]::DirectorySeparatorChar, [StringComparison]::OrdinalIgnoreCase) -or
    $digestPath.StartsWith($root + [IO.Path]::DirectorySeparatorChar, [StringComparison]::OrdinalIgnoreCase)) {
    throw 'detached distribution manifest and digest must be distinct and outside the package inventory root'
}
$authorityDocument = Read-StrictJson -Path $authorityPath -Label 'source authority lock'
if ($authorityDocument.value.schema -ne 'aida.c03.worker-manifest-lock' -or [int]$authorityDocument.value.schema_version -ne 2 -or -not [bool]$authorityDocument.value.no_network_fetch) {
    throw 'source authority lock is malformed or downgraded'
}
$specDocument = Read-StrictJson -Path $specPath -Label 'distribution manifest spec'
$specification = $specDocument.value
Assert-ExactProperties -Value $specification -Expected @('artifacts', 'customer_sidecars', 'dependencies', 'distribution', 'generator', 'inventory_sources', 'schema', 'schema_version', 'workers') -Label 'distribution manifest spec'
if ($specification.schema -ne 'aida.c03.distribution-manifest-spec' -or [int]$specification.schema_version -ne 2) {
    throw 'distribution manifest spec is malformed or downgraded'
}
if (@($specification.artifacts).Count -lt 1 -or @($specification.artifacts).Count -gt 250000 -or
    @($specification.inventory_sources).Count -lt 4 -or @($specification.inventory_sources).Count -gt 32 -or
    @($specification.workers).Count -ne 3 -or @($specification.dependencies).Count -ne 30) {
    throw 'distribution manifest spec exceeds its bounded inventory contract'
}
Assert-ExactProperties -Value $specification.generator -Expected @('manifest_digest_algorithm', 'no_network_fetch', 'offline_only', 'preset') -Label 'distribution generator'
if ($specification.generator.preset -ne 'ninja-msvc-release' -or -not [bool]$specification.generator.no_network_fetch -or
    -not [bool]$specification.generator.offline_only -or $specification.generator.manifest_digest_algorithm -ne 'sha256') {
    throw 'distribution generator policy is invalid'
}
Assert-ExactProperties -Value $specification.distribution -Expected @('acl_restricted_ipc', 'arc_license_gates_required', 'disk_backed', 'exact_inventory', 'fileless_launch_forbidden', 'package_layout', 'protected', 'raw_standalone_download_forbidden') -Label 'distribution policy'
if (-not [bool]$specification.distribution.acl_restricted_ipc -or -not [bool]$specification.distribution.arc_license_gates_required -or
    -not [bool]$specification.distribution.disk_backed -or -not [bool]$specification.distribution.exact_inventory -or
    -not [bool]$specification.distribution.fileless_launch_forbidden -or -not [bool]$specification.distribution.protected -or
    -not [bool]$specification.distribution.raw_standalone_download_forbidden -or $specification.distribution.package_layout -ne 'self-contained') {
    throw 'distribution policy is invalid'
}
$artifactIds = [Collections.Generic.Dictionary[string, bool]]::new([StringComparer]::Ordinal)
$artifactPaths = [Collections.Generic.Dictionary[string, bool]]::new([StringComparer]::Ordinal)
$materializedArtifacts = [Collections.Generic.List[object]]::new()
[Int64]$totalArtifactBytes = 0
foreach ($artifact in @($specification.artifacts)) {
    Assert-ExactProperties -Value $artifact -Expected @('id', 'kind', 'license_ids', 'owner', 'relative_path') -Label 'distribution artifact spec'
    Add-PackageArtifact -Ids $artifactIds -Paths $artifactPaths -Output $materializedArtifacts `
        -TotalBytes ([ref]$totalArtifactBytes) -Root $root -Id ([string]$artifact.id) `
        -Kind ([string]$artifact.kind) -RelativePath ([string]$artifact.relative_path) `
        -Owner ([string]$artifact.owner) -LicenseIds @($artifact.license_ids | ForEach-Object { [string]$_ })
}

$inventorySourceIds = @{}
$allowlistedSource = $null
foreach ($source in @($specification.inventory_sources)) {
    $sourceType = [string]$source.type
    $sourceId = [string]$source.id
    if ($sourceId -cnotmatch '^[A-Za-z0-9_.-]{1,256}$' -or $inventorySourceIds.ContainsKey($sourceId)) {
        throw 'distribution inventory source identity is invalid or duplicated'
    }
    $inventorySourceIds[$sourceId] = $true
    if ($sourceType -eq 'managed_runtime_manifest_v1') {
        Assert-ExactProperties -Value $source -Expected @('digest_relative_path', 'expected_file_count', 'id', 'id_prefix', 'license_ids', 'manifest_relative_path', 'owner', 'type') -Label 'managed runtime inventory source'
        $managedManifestPath = Resolve-SafeRelativePath -Root $root -RelativePath ([string]$source.manifest_relative_path) -Label 'managed runtime manifest'
        $managedDigestPath = Resolve-SafeRelativePath -Root $root -RelativePath ([string]$source.digest_relative_path) -Label 'managed runtime digest'
        Assert-DigestBinding -ManifestPath $managedManifestPath -DigestPath $managedDigestPath -Label 'managed runtime' | Out-Null
        $managed = (Read-StrictJson -Path $managedManifestPath -Label 'managed runtime manifest').value
        Assert-ExactProperties -Value $managed -Expected @('application', 'inventory', 'launch', 'runtime', 'schema', 'schema_version', 'source_contract_sha256', 'target_framework') -Label 'managed runtime manifest'
        Assert-ExactProperties -Value $managed.runtime -Expected @('canonical_inventory_sha256', 'exact_inventory', 'file_count', 'files', 'framework', 'relative_root', 'runtime_identifier', 'total_size_bytes', 'version') -Label 'managed runtime inventory'
        Assert-ExactProperties -Value $managed.application -Expected @('exact_inventory', 'files') -Label 'managed application inventory'
        Assert-ExactProperties -Value $managed.launch -Expected @('dotnet_root_relative_path', 'executable_relative_path', 'hostfxr_relative_path', 'machine_runtime_fallback', 'multilevel_lookup', 'roll_forward', 'roll_forward_to_prerelease') -Label 'managed launch contract'
        Assert-ExactProperties -Value $managed.inventory -Expected @('canonical_inventory_sha256', 'file_count', 'total_size_bytes') -Label 'managed complete inventory'
        if ($managed.schema -ne 'aida.c03.managed-runtime-manifest' -or [int]$managed.schema_version -ne 1 -or
            $managed.source_contract_sha256 -cne '2ee04cc5ed3c0fdbe1dac2f59ff2ac0e0fd5b4595c042aadb9abfbbd8153c4de' -or
            $managed.target_framework -ne 'net10.0' -or -not [bool]$managed.runtime.exact_inventory -or
            -not [bool]$managed.application.exact_inventory -or [int]$managed.runtime.file_count -ne 193 -or
            [int]$managed.inventory.file_count -ne [int]$source.expected_file_count -or
            $managed.runtime.framework -ne 'Microsoft.NETCore.App' -or $managed.runtime.version -ne '10.0.9' -or
            $managed.runtime.runtime_identifier -ne 'win-x64' -or
            $managed.runtime.relative_root -ne 'deps/dotnet' -or
            [Int64]$managed.runtime.total_size_bytes -ne 80344570 -or
            $managed.launch.executable_relative_path -ne 'deps/AiDA_ManagedDecompilerWorker.exe' -or
            $managed.launch.hostfxr_relative_path -ne 'deps/dotnet/host/fxr/10.0.9/hostfxr.dll' -or
            $managed.launch.dotnet_root_relative_path -ne 'deps/dotnet' -or
            [bool]$managed.launch.multilevel_lookup -or [bool]$managed.launch.roll_forward_to_prerelease -or
            [bool]$managed.launch.machine_runtime_fallback -or $managed.launch.roll_forward -ne 'Disable' -or
            $managed.runtime.canonical_inventory_sha256 -ne '8582bda52b66ad61651a2c9bc2c705cf10b038e374f87662045397c7966b02c9') {
            throw 'managed runtime manifest contract is invalid or downgraded'
        }
        $runtimeEntries = @($managed.runtime.files)
        $applicationEntries = @($managed.application.files)
        if ($runtimeEntries.Count -ne 193 -or $applicationEntries.Count -ne 7) {
            throw 'managed runtime manifest inventory cardinality is invalid'
        }
        $runtimeCanonical = Get-CanonicalInventorySha256 -Entries $runtimeEntries
        $combinedCanonical = Get-CanonicalInventorySha256 -Entries @($runtimeEntries + $applicationEntries)
        $runtimeBytes = [Int64](@($runtimeEntries | Measure-Object -Property size_bytes -Sum).Sum)
        $applicationBytes = [Int64](@($applicationEntries | Measure-Object -Property size_bytes -Sum).Sum)
        if ($runtimeCanonical -cne [string]$managed.runtime.canonical_inventory_sha256 -or
            $combinedCanonical -cne [string]$managed.inventory.canonical_inventory_sha256 -or
            $runtimeBytes -ne [Int64]$managed.runtime.total_size_bytes -or
            $runtimeBytes + $applicationBytes -ne [Int64]$managed.inventory.total_size_bytes) {
            throw 'managed runtime manifest canonical inventory is invalid'
        }
        $managedIndex = 0
        foreach ($entry in $runtimeEntries) {
            Assert-ExactProperties -Value $entry -Expected @('relative_path', 'sha256', 'size_bytes') -Label 'managed runtime entry'
            $relative = [string]$entry.relative_path
            if (-not $relative.StartsWith('deps/dotnet/', [StringComparison]::Ordinal) -or
                $relative -match '(?i)(?:^|/)(?:sdk|packs|templates|metadata|library-packs)(?:/|$)') {
                throw 'managed runtime manifest contains a non-runtime SDK/package path'
            }
            Add-PackageArtifact -Ids $artifactIds -Paths $artifactPaths -Output $materializedArtifacts `
                -TotalBytes ([ref]$totalArtifactBytes) -Root $root -Id ('managed-dotnet-{0:D3}' -f $managedIndex) `
                -Kind 'worker_runtime' -RelativePath $relative -Owner ([string]$source.owner) `
                -LicenseIds @($source.license_ids | ForEach-Object { [string]$_ }) -ExpectedIdentity $entry
            ++$managedIndex
        }
        $managedApplicationIds = @{
            'deps/AiDA_ManagedDecompilerWorker.exe' = @('managed-worker-executable', 'worker_executable', 'apphost')
            'deps/AiDA_ManagedDecompilerWorker.dll' = @('managed-worker-assembly', 'worker_runtime', 'assembly')
            'deps/AiDA_ManagedDecompilerWorker.deps.json' = @('managed-worker-deps', 'worker_runtime', 'deps')
            'deps/AiDA_ManagedDecompilerWorker.runtimeconfig.json' = @('managed-worker-runtimeconfig', 'worker_runtime', 'runtimeconfig')
            'deps/ICSharpCode.Decompiler.dll' = @('managed-worker-provider', 'worker_runtime', 'provider')
            'deps/System.Collections.Immutable.dll' = @('managed-worker-immutable', 'worker_runtime', 'direct_dependency')
            'deps/System.Reflection.Metadata.dll' = @('managed-worker-metadata', 'worker_runtime', 'direct_dependency')
        }
        foreach ($entry in $applicationEntries) {
            Assert-ExactProperties -Value $entry -Expected @('relative_path', 'role', 'sha256', 'size_bytes') -Label 'managed application entry'
            $relative = [string]$entry.relative_path
            if (-not $managedApplicationIds.ContainsKey($relative)) {
                throw 'managed runtime manifest contains an unexpected application artifact'
            }
            $mapping = $managedApplicationIds[$relative]
            if ([string]$entry.role -cne [string]$mapping[2]) {
                throw 'managed runtime manifest contains an invalid application role'
            }
            Add-PackageArtifact -Ids $artifactIds -Paths $artifactPaths -Output $materializedArtifacts `
                -TotalBytes ([ref]$totalArtifactBytes) -Root $root -Id $mapping[0] -Kind $mapping[1] `
                -RelativePath $relative -Owner ([string]$source.owner) `
                -LicenseIds @($source.license_ids | ForEach-Object { [string]$_ }) -ExpectedIdentity $entry
        }
    } elseif ($sourceType -eq 'ghidra_spec_manifest_v1') {
        Assert-ExactProperties -Value $source -Expected @('digest_relative_path', 'expected_file_count', 'id', 'id_prefix', 'license_ids', 'manifest_relative_path', 'owner', 'type') -Label 'Ghidra specification inventory source'
        $ghidraManifestPath = Resolve-SafeRelativePath -Root $root -RelativePath ([string]$source.manifest_relative_path) -Label 'Ghidra specification manifest'
        $ghidraDigestPath = Resolve-SafeRelativePath -Root $root -RelativePath ([string]$source.digest_relative_path) -Label 'Ghidra specification digest'
        Assert-DigestBinding -ManifestPath $ghidraManifestPath -DigestPath $ghidraDigestPath -Label 'Ghidra specification' | Out-Null
        $ghidra = (Read-StrictJson -Path $ghidraManifestPath -Label 'Ghidra specification manifest').value
        Assert-ExactProperties -Value $ghidra -Expected @('producer', 'schema', 'schema_version', 'source_contract_sha256', 'specifications') -Label 'Ghidra specification manifest'
        Assert-ExactProperties -Value $ghidra.producer -Expected @('approved_generator_root', 'approved_input_root', 'executable_sha256', 'id') -Label 'Ghidra specification producer'
        Assert-ExactProperties -Value $ghidra.specifications -Expected @('canonical_inventory_sha256', 'exact_inventory', 'file_count', 'files', 'generation_id', 'mirrors') -Label 'Ghidra specification inventory'
        if ($ghidra.schema -ne 'aida.c03.ghidra-spec-manifest' -or [int]$ghidra.schema_version -ne 1 -or
            $ghidra.source_contract_sha256 -cne '880c588da681d62451d3dd5f901abc7cb86491a128a7793c8738f9bd7917f0b7' -or
            [int]$ghidra.specifications.file_count -ne 51 -or -not [bool]$ghidra.specifications.exact_inventory -or
            @($ghidra.specifications.mirrors).Count -ne 2 -or
            [string]$ghidra.specifications.mirrors[0] -cne 'ghidra_specs' -or
            [string]$ghidra.specifications.mirrors[1] -cne 'deps/ghidra_specs' -or
            @($ghidra.specifications.files).Count * 2 -ne [int]$source.expected_file_count -or
            $ghidra.producer.id -ne 'ghidra_sleigh_compiler' -or -not [bool]$ghidra.producer.approved_input_root -or
            -not [bool]$ghidra.producer.approved_generator_root -or
            [string]$ghidra.producer.executable_sha256 -cnotmatch '^[0-9a-f]{64}$' -or
            [string]$ghidra.specifications.canonical_inventory_sha256 -cnotmatch '^[0-9a-f]{64}$' -or
            [string]$ghidra.specifications.generation_id -cnotmatch '^[0-9a-f]{64}$') {
            throw 'Ghidra specification manifest contract is invalid or downgraded'
        }
        $ghidraExpectedNames = @(
            'x86-64.sla', 'x86.sla', 'ARM7_le.sla', 'ARM7_be.sla', 'AARCH64.sla', 'AARCH64BE.sla',
            'mips32le.sla', 'mips32be.sla', 'mips64le.sla', 'mips64be.sla', 'ppc_32_le.sla',
            'ppc_32_be.sla', 'ppc_64_le.sla', 'ppc_64_be.sla', 'riscv.ilp32d.sla',
            'riscv.lp64d.sla', 'x86-64.pspec', 'x86-64-win.cspec', 'x86-64-gcc.cspec',
            'x86.pspec', 'x86win.cspec', 'x86gcc.cspec', 'x86-16-real.pspec', 'x86-16.cspec',
            'x86.ldefs', 'ARMt.pspec', 'ARM.cspec', 'ARM_win.cspec', 'ARM.ldefs', 'AARCH64.pspec',
            'AARCH64.cspec', 'AARCH64_win.cspec', 'AARCH64.ldefs', 'mips32.pspec', 'mips64.pspec',
            'mips32le.cspec', 'mips32be.cspec', 'mips64le.cspec', 'mips64be.cspec', 'mips.ldefs',
            'ppc_32.pspec', 'ppc_64.pspec', 'ppc_32.cspec', 'ppc_64_le.cspec', 'ppc_64_be.cspec',
            'ppc.ldefs', 'RV32.pspec', 'RV64.pspec', 'riscv32-fp.cspec', 'riscv64-fp.cspec',
            'riscv.ldefs'
        )
        $ghidraNames = @{}
        $ghidraIndex = 0
        $ghidraCanonicalRows = ''
        foreach ($entry in @($ghidra.specifications.files)) {
            Assert-ExactProperties -Value $entry -Expected @('kind', 'name', 'sha256', 'size_bytes') -Label 'Ghidra specification entry'
            $name = [string]$entry.name
            $kind = [string]$entry.kind
            if ($ghidraIndex -ge $ghidraExpectedNames.Count -or $name -cne $ghidraExpectedNames[$ghidraIndex] -or
                $name -cnotmatch '^[A-Za-z0-9_.-]+\.(?:sla|pspec|cspec|ldefs)$' -or
                $kind -cne [IO.Path]::GetExtension($name).Substring(1) -or
                [Int64]$entry.size_bytes -le 0 -or [string]$entry.sha256 -cnotmatch '^[0-9a-f]{64}$' -or
                $ghidraNames.ContainsKey($name)) {
                throw 'Ghidra specification manifest contains an unsafe or duplicated name'
            }
            $ghidraNames[$name] = $true
            $ghidraCanonicalRows += $name + "`t" + $kind + "`t" + ([Int64]$entry.size_bytes).ToString([Globalization.CultureInfo]::InvariantCulture) + "`t" + [string]$entry.sha256 + "`n"
            foreach ($mirror in @('ghidra_specs', 'deps/ghidra_specs')) {
                $mirrorId = if ($mirror -eq 'ghidra_specs') { 'primary' } else { 'dependency' }
                Add-PackageArtifact -Ids $artifactIds -Paths $artifactPaths -Output $materializedArtifacts `
                    -TotalBytes ([ref]$totalArtifactBytes) -Root $root `
                    -Id ('ghidra-spec-{0}-{1:D2}' -f $mirrorId, $ghidraIndex) -Kind 'resource' `
                    -RelativePath ($mirror + '/' + $name) -Owner ([string]$source.owner) `
                    -LicenseIds @($source.license_ids | ForEach-Object { [string]$_ }) -ExpectedIdentity $entry
            }
            ++$ghidraIndex
        }
        $ghidraCanonical = Get-TextSha256 -Text $ghidraCanonicalRows
        $ghidraGenerationMaterial = "aida.c03.ghidra-spec-generation.v1`n" + [string]$ghidra.source_contract_sha256 + "`n" + [string]$ghidra.producer.executable_sha256 + "`n" + $ghidraCanonical + "`n"
        if ($ghidraIndex -ne $ghidraExpectedNames.Count -or
            $ghidraCanonical -cne [string]$ghidra.specifications.canonical_inventory_sha256 -or
            (Get-TextSha256 -Text $ghidraGenerationMaterial) -cne [string]$ghidra.specifications.generation_id) {
            throw 'Ghidra specification manifest generation binding is invalid'
        }
    } elseif ($sourceType -eq 'exact_tree_v1') {
        Assert-ExactProperties -Value $source -Expected @('distinguished_artifact_id', 'distinguished_relative_path', 'expected_file_count', 'expected_inventory_sha256', 'expected_size_bytes', 'id', 'id_prefix', 'kind', 'license_ids', 'owner', 'relative_root', 'type') -Label 'exact tree inventory source'
        $treeRoot = Resolve-SafeRelativePath -Root $root -RelativePath ([string]$source.relative_root) -Label 'exact tree root'
        $treeItem = Get-Item -LiteralPath $treeRoot -Force -ErrorAction Stop
        if (-not $treeItem.PSIsContainer -or ($treeItem.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
            throw 'exact tree root must be a regular non-reparse directory'
        }
        $treeInventory = Get-BoundedTreeInventory -Root $treeRoot
        $treeEntries = [Collections.Generic.List[object]]::new()
        foreach ($entry in $treeInventory.files) {
            $identity = Get-LockedIdentity -Path $entry.full_name -Label 'exact tree artifact'
            $treeEntries.Add([pscustomobject]@{ relative_path = $entry.relative_path; size_bytes = $identity.size_bytes; sha256 = $identity.sha256 })
        }
        $treeBytes = [Int64](@($treeEntries | Measure-Object -Property size_bytes -Sum).Sum)
        if ($treeEntries.Count -ne [int]$source.expected_file_count -or $treeBytes -ne [Int64]$source.expected_size_bytes -or
            (Get-CanonicalInventorySha256 -Entries @($treeEntries)) -cne [string]$source.expected_inventory_sha256) {
            throw 'exact tree inventory does not match its locked count, size, or digest'
        }
        $treeIndex = 0
        $distinguishedSeen = $false
        foreach ($entry in @($treeEntries | Sort-Object -Property relative_path -CaseSensitive)) {
            $packageRelative = ([string]$source.relative_root) + '/' + ([string]$entry.relative_path)
            if ([string]$entry.relative_path -ceq [string]$source.distinguished_relative_path) {
                $artifactId = [string]$source.distinguished_artifact_id
                $distinguishedSeen = $true
            } else {
                $artifactId = ([string]$source.id_prefix) + '-' + ('{0:D4}' -f $treeIndex)
            }
            Add-PackageArtifact -Ids $artifactIds -Paths $artifactPaths -Output $materializedArtifacts `
                -TotalBytes ([ref]$totalArtifactBytes) -Root $root -Id $artifactId -Kind ([string]$source.kind) `
                -RelativePath $packageRelative -Owner ([string]$source.owner) `
                -LicenseIds @($source.license_ids | ForEach-Object { [string]$_ }) -ExpectedIdentity $entry
            ++$treeIndex
        }
        if (-not $distinguishedSeen) {
            throw 'exact tree distinguished artifact is absent'
        }
    } elseif ($sourceType -eq 'allowlisted_files_v1') {
        if ($null -ne $allowlistedSource) {
            throw 'distribution manifest spec contains duplicate allowlisted file sources'
        }
        Assert-ExactProperties -Value $source -Expected @('distinguished_artifact_id', 'distinguished_relative_path', 'expected_file_count', 'id', 'id_prefix', 'kind', 'license_ids', 'owner', 'relative_paths', 'type') -Label 'allowlisted file inventory source'
        $allowlistedSource = $source
    } else {
        throw "distribution manifest spec contains an unsupported inventory source type: $sourceType"
    }
}

if ($null -eq $allowlistedSource) {
    throw 'distribution manifest spec lacks the exact allowlisted file inventory source'
}
$allowlistedPaths = @($allowlistedSource.relative_paths | ForEach-Object { [string]$_ })
if ($allowlistedPaths.Count -ne [int]$allowlistedSource.expected_file_count -or
    $allowlistedPaths.Count -ne 13) {
    throw 'allowlisted customer file count violates its exact contract'
}
$allowlistedSeen = [Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
$allowlistedFolded = [Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
$allowlistedIndex = 0
$allowlistedDistinguishedSeen = $false
foreach ($relativePath in $allowlistedPaths) {
    if ((Test-ForbiddenCustomerRelativePath -RelativePath $relativePath) -or
        -not $allowlistedSeen.Add($relativePath) -or
        -not $allowlistedFolded.Add($relativePath)) {
        throw 'allowlisted customer file path is unsafe, duplicated, or case-colliding'
    }
    if ($relativePath -ceq [string]$allowlistedSource.distinguished_relative_path) {
        $artifactId = [string]$allowlistedSource.distinguished_artifact_id
        $artifactKind = 'application'
        $allowlistedDistinguishedSeen = $true
    } else {
        $artifactId = ([string]$allowlistedSource.id_prefix) + '-' + ('{0:D4}' -f $allowlistedIndex)
        $artifactKind = [string]$allowlistedSource.kind
    }
    Add-PackageArtifact -Ids $artifactIds -Paths $artifactPaths -Output $materializedArtifacts `
        -TotalBytes ([ref]$totalArtifactBytes) -Root $root -Id $artifactId -Kind $artifactKind `
        -RelativePath $relativePath -Owner ([string]$allowlistedSource.owner) `
        -LicenseIds @($allowlistedSource.license_ids | ForEach-Object { [string]$_ })
    ++$allowlistedIndex
}
if (-not $allowlistedDistinguishedSeen) {
    throw 'protected standalone executable is absent from the exact allowlist'
}
$standaloneArtifact = Get-ArtifactById -Artifacts $materializedArtifacts -Id 'standalone-executable' -Label 'standalone executable'
$standaloneProtectorArtifact = Get-ArtifactById -Artifacts $materializedArtifacts -Id 'standalone-protector' -Label 'standalone protector receipt'
$standaloneSignatureArtifact = Get-ArtifactById -Artifacts $materializedArtifacts -Id 'standalone-signature' -Label 'standalone signature receipt'
if ($standaloneArtifact.kind -ne 'application' -or $standaloneArtifact.owner -ne 'standalone' -or
    $standaloneArtifact.relative_path -cne 'AiDAStandalone.exe' -or
    $standaloneProtectorArtifact.owner -ne 'standalone' -or
    $standaloneSignatureArtifact.owner -ne 'standalone') {
    throw 'protected standalone artifact classification is invalid'
}
Assert-ProtectorReceipt -Root $root -ReceiptArtifact $standaloneProtectorArtifact -ExecutableArtifact $standaloneArtifact
Assert-SignatureReceipt -Root $root -ReceiptArtifact $standaloneSignatureArtifact -ExecutableArtifact $standaloneArtifact

$expectedWorkers = @{
    native_decompiler = @('aida-native-decompiler', 3, 2, 'native')
    managed_cli_decompiler = @('aida-managed-cli-decompiler', 3, 3, 'managed')
    analysis_python = @('aida-analysis-python', 1, 1, 'analysis_python')
}
$expectedWorkerExecutables = @{
    native_decompiler = 'deps/AiDA_NativeDecompilerWorker.exe'
    managed_cli_decompiler = 'deps/AiDA_ManagedDecompilerWorker.exe'
    analysis_python = 'deps/AiDA_AnalysisPythonWorker.exe'
}
$expectedWorkerAclPathCounts = @{
    native_decompiler = 105
    managed_cli_decompiler = 207
    analysis_python = 1
}
$expectedWorkerLimits = @{
    native_decompiler = @(30000, 2147483648, 60000)
    managed_cli_decompiler = @(30000, 2147483648, 60000)
    analysis_python = @(15000, 536870912, 30000)
}
$expectedWorkerDependencies = @{
    native_decompiler = @('ghidra-worker')
    managed_cli_decompiler = @('dotnet-runtime', 'icsharpcode-decompiler', 'system-collections-immutable', 'system-reflection-metadata')
    analysis_python = @('analysis-python-worker')
}
$workerIds = @{}
foreach ($worker in @($specification.workers)) {
    Assert-ExactProperties -Value $worker -Expected @('acl_receipt_artifact', 'containment', 'dependency_ids', 'executable_artifact', 'id', 'protector_receipt_artifact', 'protocol', 'signature_receipt_artifact', 'target_execution_forbidden', 'worker_manifest_artifact', 'worker_manifest_digest_artifact') -Label 'distribution worker'
    $workerId = [string]$worker.id
    if (-not $expectedWorkers.ContainsKey($workerId) -or $workerIds.ContainsKey($workerId)) {
        throw 'distribution worker identity is invalid or duplicated'
    }
    $workerIds[$workerId] = $true
    $expectedWorker = $expectedWorkers[$workerId]
    Assert-ExactProperties -Value $worker.protocol -Expected @('hash_material_sha256', 'name', 'version', 'worker_manifest_schema_version') -Label 'distribution worker protocol'
    if ($worker.protocol.name -ne $expectedWorker[0] -or [int]$worker.protocol.version -ne [int]$expectedWorker[1] -or
        [int]$worker.protocol.worker_manifest_schema_version -ne [int]$expectedWorker[2] -or
        [string]$worker.protocol.hash_material_sha256 -cnotmatch '^[0-9a-f]{64}$' -or
        -not [bool]$worker.target_execution_forbidden) {
        throw "distribution worker protocol is invalid: $workerId"
    }
    Assert-ExactProperties -Value $worker.containment -Expected @('acl_restricted_ipc', 'authenticated_ipc', 'cancellation_replaces_worker', 'child_process_denied', 'cpu_quota_ms', 'deadline_ms', 'job_object', 'kill_on_parent_close', 'memory_quota_bytes', 'monotonic_sequence', 'network_denied', 'process_mitigations', 'restricted_token', 'unrelated_handles_denied') -Label 'distribution worker containment'
    foreach ($requiredBoolean in @('acl_restricted_ipc', 'authenticated_ipc', 'cancellation_replaces_worker', 'child_process_denied', 'job_object', 'kill_on_parent_close', 'monotonic_sequence', 'network_denied', 'process_mitigations', 'restricted_token', 'unrelated_handles_denied')) {
        if (-not [bool]$worker.containment.$requiredBoolean) {
            throw "distribution worker containment is weakened: $workerId/$requiredBoolean"
        }
    }
    $expectedLimits = $expectedWorkerLimits[$workerId]
    if ([Int64]$worker.containment.cpu_quota_ms -ne [Int64]$expectedLimits[0] -or
        [Int64]$worker.containment.memory_quota_bytes -ne [Int64]$expectedLimits[1] -or
        [Int64]$worker.containment.deadline_ms -ne [Int64]$expectedLimits[2]) {
        throw "distribution worker containment limits are invalid: $workerId"
    }
    foreach ($reference in @('executable_artifact', 'worker_manifest_artifact', 'worker_manifest_digest_artifact', 'acl_receipt_artifact', 'protector_receipt_artifact', 'signature_receipt_artifact')) {
        if (-not $artifactIds.ContainsKey([string]$worker.$reference)) {
            throw "distribution worker artifact reference is unresolved: $workerId/$reference"
        }
    }
    $executableArtifact = Get-ArtifactById -Artifacts $materializedArtifacts -Id ([string]$worker.executable_artifact) -Label 'worker executable'
    $workerManifestArtifact = Get-ArtifactById -Artifacts $materializedArtifacts -Id ([string]$worker.worker_manifest_artifact) -Label 'worker manifest'
    $manifestDigestArtifact = Get-ArtifactById -Artifacts $materializedArtifacts -Id ([string]$worker.worker_manifest_digest_artifact) -Label 'worker manifest digest'
    $aclArtifact = Get-ArtifactById -Artifacts $materializedArtifacts -Id ([string]$worker.acl_receipt_artifact) -Label 'worker ACL receipt'
    $protectorArtifact = Get-ArtifactById -Artifacts $materializedArtifacts -Id ([string]$worker.protector_receipt_artifact) -Label 'worker protector receipt'
    $signatureArtifact = Get-ArtifactById -Artifacts $materializedArtifacts -Id ([string]$worker.signature_receipt_artifact) -Label 'worker signature receipt'
    if ($executableArtifact.kind -ne 'worker_executable' -or
        $executableArtifact.relative_path -cne $expectedWorkerExecutables[$workerId] -or
        $workerManifestArtifact.kind -ne 'worker_manifest' -or
        $manifestDigestArtifact.kind -ne 'manifest_digest' -or
        $aclArtifact.kind -ne 'acl_receipt' -or
        $executableArtifact.owner -ne $workerId -or $workerManifestArtifact.owner -ne $workerId -or
        $manifestDigestArtifact.owner -ne $workerId -or $aclArtifact.owner -ne $workerId -or
        $protectorArtifact.owner -ne $workerId -or $signatureArtifact.owner -ne $workerId) {
        throw "distribution worker ACL or manifest digest artifact kind is invalid: $workerId"
    }
    $aclPath = Resolve-SafeRelativePath -Root $root -RelativePath ([string]$aclArtifact.relative_path) -Label 'worker ACL receipt'
    $acl = (Read-StrictJson -Path $aclPath -Label 'worker ACL receipt').value
    Assert-ExactProperties -Value $acl -Expected @('access', 'app_container_profile', 'app_container_sid', 'path_count', 'policy', 'protected_parent_required', 'schema', 'schema_version', 'verified', 'worker_manifest_sha256') -Label 'worker ACL receipt'
    $workerDigestPath = Resolve-SafeRelativePath -Root $root -RelativePath ([string]$manifestDigestArtifact.relative_path) -Label 'worker manifest digest'
    $workerDigest = [Text.Encoding]::ASCII.GetString(
        (Get-LockedBytes -Path $workerDigestPath -Label 'worker manifest digest' -MaximumBytes 256).bytes)
    if ($workerDigest -cnotmatch '^[0-9a-f]{64}\n$' -or
        $acl.schema -ne 'aida.c03.worker-runtime-acl-receipt' -or [int]$acl.schema_version -ne 1 -or
        $acl.policy -ne $expectedWorker[3] -or -not [bool]$acl.protected_parent_required -or -not [bool]$acl.verified -or
        [int]$acl.path_count -ne [int]$expectedWorkerAclPathCounts[$workerId] -or
        $acl.worker_manifest_sha256 -cne $workerDigest.Substring(0, 64) -or -not [bool]$acl.access.read_execute -or
        [bool]$acl.access.write -or [bool]$acl.access.delete -or [bool]$acl.access.change_permissions -or [bool]$acl.access.take_ownership) {
        throw "distribution worker ACL receipt is invalid: $workerId"
    }
    Assert-ProtectorReceipt -Root $root -ReceiptArtifact $protectorArtifact -ExecutableArtifact $executableArtifact
    Assert-SignatureReceipt -Root $root -ReceiptArtifact $signatureArtifact -ExecutableArtifact $executableArtifact
}
if ($workerIds.Count -ne 3) {
    throw 'distribution worker inventory is incomplete'
}

$authorityDependencies = @($authorityDocument.value.dependencies)
if ($authorityDependencies.Count -ne 30 -or @($specification.dependencies).Count -ne $authorityDependencies.Count) {
    throw 'distribution dependency inventory does not exactly match the source authority'
}
$authorityDependencyMap = @{}
foreach ($authorityDependency in $authorityDependencies) {
    Assert-ExactProperties -Value $authorityDependency -Expected @('components', 'id', 'license', 'ships_to_customer', 'source_paths', 'usage', 'version') -Label 'source authority dependency'
    $authorityDependencyId = [string]$authorityDependency.id
    if ($authorityDependencyId -cnotmatch '^[A-Za-z0-9_.-]{1,256}$' -or $authorityDependencyMap.ContainsKey($authorityDependencyId)) {
        throw 'source authority dependency identity is invalid or duplicated'
    }
    if ([bool]$authorityDependency.ships_to_customer -ne ([string]$authorityDependency.usage -eq 'production')) {
        throw "source authority dependency shipment decision is inconsistent: $authorityDependencyId"
    }
    $authorityDependencyMap[$authorityDependencyId] = $authorityDependency
}
$dependencyIds = @{}
foreach ($dependency in @($specification.dependencies)) {
    Assert-ExactProperties -Value $dependency -Expected @('artifact_ids', 'dependencies', 'id', 'license', 'notice_artifact_ids', 'usage', 'version') -Label 'distribution dependency'
    $dependencyId = [string]$dependency.id
    if ($dependencyId -cnotmatch '^[A-Za-z0-9_.-]{1,256}$' -or $dependencyIds.ContainsKey($dependencyId) -or
        -not $authorityDependencyMap.ContainsKey($dependencyId) -or
        [string]$dependency.usage -notin @('production', 'build_only', 'evidence_only', 'non_use')) {
        throw 'distribution dependency identity or usage is invalid'
    }
    $authorityDependency = $authorityDependencyMap[$dependencyId]
    if ([string]$dependency.version -cne [string]$authorityDependency.version -or
        [string]$dependency.usage -cne [string]$authorityDependency.usage -or
        [string]$dependency.license -cne [string]$authorityDependency.license) {
        throw "distribution dependency differs from the source authority: $dependencyId"
    }
    $dependencyIds[$dependencyId] = [string]$dependency.usage
    if ($dependency.usage -eq 'production') {
        if (@($dependency.notice_artifact_ids).Count -eq 0) {
            throw "production dependency lacks a notice: $dependencyId"
        }
        foreach ($artifactId in @($dependency.artifact_ids + $dependency.notice_artifact_ids)) {
            if (-not $artifactIds.ContainsKey([string]$artifactId)) {
                throw "production dependency artifact reference is unresolved: $dependencyId/$artifactId"
            }
        }
    } elseif (@($dependency.artifact_ids).Count -ne 0) {
        throw "non-production dependency ships an artifact: $dependencyId"
    }
}
if ($dependencyIds.Count -ne $authorityDependencyMap.Count -or
    $dependencyIds['lmdb'] -ne 'non_use' -or $dependencyIds['unicorn'] -ne 'non_use' -or
    $dependencyIds['remill'] -ne 'evidence_only' -or $dependencyIds['lief'] -ne 'evidence_only' -or
    $dependencyIds['dotnet-sdk'] -ne 'build_only' -or $dependencyIds['pyinstaller'] -ne 'build_only' -or
    $dependencyIds['dotnet-runtime'] -ne 'production') {
    throw 'distribution dependency use decisions are incomplete or weakened'
}
foreach ($dependency in @($specification.dependencies)) {
    foreach ($requiredDependencyId in @($dependency.dependencies)) {
        if (-not $dependencyIds.ContainsKey([string]$requiredDependencyId) -or
            [string]$requiredDependencyId -ceq [string]$dependency.id) {
            throw "distribution dependency graph reference is invalid: $($dependency.id)/$requiredDependencyId"
        }
    }
}
foreach ($worker in @($specification.workers)) {
    $actualWorkerDependencies = @($worker.dependency_ids | ForEach-Object { [string]$_ })
    $expectedWorkerDependencyList = @($expectedWorkerDependencies[[string]$worker.id])
    if ($actualWorkerDependencies.Count -ne $expectedWorkerDependencyList.Count -or
        ($actualWorkerDependencies -join "`n") -cne ($expectedWorkerDependencyList -join "`n")) {
        throw "worker dependency set is invalid: $($worker.id)"
    }
    foreach ($dependencyId in $actualWorkerDependencies) {
        if ($dependencyIds[[string]$dependencyId] -ne 'production') {
            throw "worker references a non-production dependency: $($worker.id)/$dependencyId"
        }
    }
}

Assert-ExactProperties -Value $specification.customer_sidecars -Expected @('browser_artifact', 'developer_source_shipped', 'environment', 'loose_python_shipped', 'only_supported_browser', 'reverse_mcp_artifact', 'stock_browser_fallback') -Label 'customer sidecar policy'
if ($specification.customer_sidecars.only_supported_browser -ne 'camoufox' -or
    $specification.customer_sidecars.browser_artifact -ne 'camoufox-executable' -or
    $specification.customer_sidecars.reverse_mcp_artifact -ne 'camoufox-reverse-mcp' -or
    [bool]$specification.customer_sidecars.developer_source_shipped -or
    [bool]$specification.customer_sidecars.loose_python_shipped -or
    [bool]$specification.customer_sidecars.stock_browser_fallback -or
    $specification.customer_sidecars.environment.AIDA_CAMOUFOX_EXECUTABLE -ne 'verified-browser' -or
    $specification.customer_sidecars.environment.AIDA_CAMOUFOX_MCP_EXECUTABLE -ne 'verified-frozen-sidecar' -or
    $specification.customer_sidecars.environment.AIDA_CAMOUFOX_PYTHON -ne 'unset-unless-verified-sidecar-runtime') {
    throw 'customer sidecar policy is incomplete or weakened'
}
$actualPaths = [Collections.Generic.Dictionary[string, bool]]::new([StringComparer]::Ordinal)
foreach ($entry in $packageInventory.files) {
    if ($actualPaths.ContainsKey([string]$entry.relative_path)) {
        throw 'package inventory contains a duplicate path'
    }
    $actualPaths[[string]$entry.relative_path] = $true
}
if ($actualPaths.Count -ne $artifactPaths.Count) {
    throw "package inventory count mismatch: expected=$($artifactPaths.Count) actual=$($actualPaths.Count)"
}
foreach ($relative in $actualPaths.Keys) {
    if (-not $artifactPaths.ContainsKey($relative)) {
        throw "package inventory contains an unlisted file: $relative"
    }
}
if ([Int64]$packageInventory.total_size_bytes -ne [Int64]$totalArtifactBytes) {
    throw 'package inventory byte count differs from its exact artifact inventory'
}
$result = [ordered]@{
    schema = 'aida.c03.distribution-manifest'
    schema_version = 2
    generator = $specification.generator
    source_authority_sha256 = $authorityDocument.identity.sha256
    distribution = $specification.distribution
    artifacts = @($materializedArtifacts)
    workers = @($specification.workers)
    dependencies = @($specification.dependencies)
    customer_sidecars = $specification.customer_sidecars
}
$json = ($result | ConvertTo-Json -Depth 32 -Compress) + "`n"
$jsonBytes = [Text.UTF8Encoding]::new($false, $true).GetBytes($json)
$sha = [Security.Cryptography.SHA256]::Create()
try {
    $manifestDigest = ([BitConverter]::ToString($sha.ComputeHash($jsonBytes)) -replace '-', '').ToLowerInvariant()
} finally {
    $sha.Dispose()
}
Write-AtomicBytes -Path $manifestPath -Bytes $jsonBytes -Replace:$Force
Write-AtomicBytes -Path $digestPath -Bytes ([Text.Encoding]::ASCII.GetBytes($manifestDigest + "`n")) -Replace:$Force
$manifestIdentity = Get-LockedIdentity -Path $manifestPath -Label 'detached distribution manifest' -MaximumBytes 16777216 -AllowRename:($null -ne $productionStage)
$digestIdentity = Get-LockedIdentity -Path $digestPath -Label 'detached distribution digest' -MaximumBytes 256 -AllowRename:($null -ne $productionStage)
$digestBytes = Get-LockedBytes -Path $digestPath -Label 'detached distribution digest bytes' -MaximumBytes 256
if ($manifestIdentity.sha256 -ne $manifestDigest -or
    [Text.Encoding]::ASCII.GetString($digestBytes.bytes) -cne ($manifestDigest + "`n")) {
    throw 'detached distribution manifest verification failed after publication'
}
if ($null -ne $productionStage) {
    $confirmedCandidate = Get-BoundedTreeInventory -Root $root
    if ($confirmedCandidate.file_count -ne $packageInventory.file_count -or
        $confirmedCandidate.directory_count -ne $packageInventory.directory_count -or
        $confirmedCandidate.entry_count -ne $packageInventory.entry_count -or
        [Int64]$confirmedCandidate.total_size_bytes -ne [Int64]$packageInventory.total_size_bytes -or
        [Int64]$confirmedCandidate.inventory_path_bytes -ne [Int64]$packageInventory.inventory_path_bytes -or
        $confirmedCandidate.stream_inventory_count -ne $packageInventory.stream_inventory_count) {
        Throw-PackagePolicy -Code 'GENERATION_CHANGED' -Path $root
    }
    Assert-ImmutableGeneration
    $publication = Publish-CompleteGeneration -Stage $productionStage `
        -ManifestCandidate $manifestPath -ManifestIdentity $manifestIdentity `
        -DigestCandidate $digestPath -DigestIdentity $digestIdentity `
        -ManifestDestination $manifestOutputPath -DigestDestination $digestOutputPath `
        -EvidenceCandidate $evidenceCandidatePath -EvidenceCandidateIdentity $evidenceCandidateIdentity `
        -EvidencePublicationAnchor $evidencePublicationAnchor -ExpectedManifestDigest $manifestDigest `
        -Replace:$Force
    $packageInventory = $publication.inventory
    $root = [string]$publication.package_root
    $manifestPath = [string]$publication.manifest_path
    $digestPath = [string]$publication.digest_path
    $generationPointerPath = [string]$publication.pointer_path
    $productionStage = $null
    $evidenceCandidatePath = $null
}
[pscustomobject]@{
    artifact_count = $materializedArtifacts.Count
    directory_count = $packageInventory.directory_count
    entry_count = $packageInventory.entry_count
    total_size_bytes = $packageInventory.total_size_bytes
    stream_inventory_count = $packageInventory.stream_inventory_count
    manifest = $manifestPath
    manifest_sha256 = $manifestDigest
    package_root = $root
    generation_pointer = $generationPointerPath
    source_authority_sha256 = $authorityDocument.identity.sha256
    verified = $true
} | ConvertTo-Json -Compress
} finally {
    try {
        if ($null -ne $productionStage -and
            [IO.Directory]::Exists([string]$productionStage.candidate_path)) {
            Remove-OwnedGenerationDirectory -Path ([string]$productionStage.candidate_path) `
                -Anchor $productionCandidateAnchor -ExpectedIdentity ([string]$productionStage.candidate_identity) `
                -AllowedPrefix '.aida-c03-candidate-'
        }
        if ($null -ne $evidenceCandidatePath -and [IO.Directory]::Exists($evidenceCandidatePath)) {
            Remove-OwnedGenerationDirectory -Path $evidenceCandidatePath -Anchor $evidencePublicationAnchor `
                -ExpectedIdentity $evidenceCandidateIdentity -AllowedPrefix '.aida-c03-evidence-candidate-'
        }
    } finally {
        Stop-ImmutableGeneration
    }
}
