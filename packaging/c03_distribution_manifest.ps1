[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$PackageRoot,
    [Parameter(Mandatory = $true)]
    [string]$Spec,
    [Parameter(Mandatory = $true)]
    [string]$AuthorityLock,
    [Parameter(Mandatory = $true)]
    [string]$OutputManifest,
    [Parameter(Mandatory = $true)]
    [string]$OutputDigest,
    [switch]$Force
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

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
    return $item
}

function Get-LockedIdentity {
    param(
        [string]$Path,
        [string]$Label,
        [Int64]$MaximumBytes = 8589934592
    )
    Assert-RegularFile -Path $Path -Label $Label | Out-Null
    $stream = [IO.File]::Open($Path, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::Read)
    try {
        if ($stream.Length -le 0 -or $stream.Length -gt $MaximumBytes) {
            throw "$Label size violates policy"
        }
        $sha = [Security.Cryptography.SHA256]::Create()
        try {
            $digest = $sha.ComputeHash($stream)
        } finally {
            $sha.Dispose()
        }
        return [pscustomobject]@{
            size_bytes = [Int64]$stream.Length
            sha256 = ([BitConverter]::ToString($digest) -replace '-', '').ToLowerInvariant()
        }
    } finally {
        $stream.Dispose()
    }
}

function Read-StrictJson {
    param(
        [string]$Path,
        [string]$Label
    )
    $identity = Get-LockedIdentity -Path $Path -Label $Label -MaximumBytes 16777216
    $stream = [IO.File]::Open($Path, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::Read)
    try {
        $reader = [IO.StreamReader]::new($stream, [Text.UTF8Encoding]::new($false, $true), $true, 65536, $true)
        try {
            $text = $reader.ReadToEnd()
        } finally {
            $reader.Dispose()
        }
    } finally {
        $stream.Dispose()
    }
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
    if (-not $RelativePath -or [IO.Path]::IsPathRooted($RelativePath) -or $RelativePath.Contains('\') -or
        $RelativePath.Contains(':') -or ($RelativePath -split '/' | Where-Object { $_ -eq '' -or $_ -eq '.' -or $_ -eq '..' })) {
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
    return $path
}

function Write-AtomicBytes {
    param(
        [string]$Path,
        [byte[]]$Bytes,
        [switch]$Replace
    )
    $parent = Split-Path -Parent $Path
    New-Item -ItemType Directory -Path $parent -Force | Out-Null
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
    $digestIdentity = Get-LockedIdentity -Path $DigestPath -Label "$Label digest" -MaximumBytes 256
    if ($digestIdentity.size_bytes -ne 65) {
        throw "$Label digest has an invalid size"
    }
    $digestText = [IO.File]::ReadAllText($DigestPath, [Text.Encoding]::ASCII)
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
        $Kind -notin @('application', 'application_runtime', 'worker_executable', 'worker_runtime', 'worker_manifest', 'resource_manifest', 'manifest_digest', 'acl_receipt', 'build_receipt', 'protector_receipt', 'signature_receipt', 'browser', 'reverse_mcp', 'license', 'notice', 'dependency', 'resource') -or
        $Ids.ContainsKey($Id) -or $Paths.ContainsKey($RelativePath)) {
        throw 'distribution artifact id, owner, kind, or path is invalid or duplicated'
    }
    if ($LicenseIds.Count -gt 128 -or @($LicenseIds | Where-Object { $_ -cnotmatch '^[A-Za-z0-9_.-]{1,256}$' }).Count -ne 0) {
        throw "distribution artifact license identity is invalid: $Id"
    }
    if ($RelativePath -match '(?i)(?:^|/)(?:camoufox[-_]reverse[-_]mcp|[^/]+\.(?:dist|egg)-info)(?:/|$)' -or
        $RelativePath -match '(?i)(?:^|/)[^/]+\.(?:py|pyc|pyo|pyz|whl|pth|spec|sln|vcxproj|vcxproj\.filters|pdb|ilk|lib|obj|exp|map|a|nupkg|snupkg|nuspec|targets|props|cs|csproj|fs|fsproj|vb|vbproj)$' -or
        $RelativePath -match '(?i)(?:^|/)(?:sdk|packs|templates|metadata|library-packs)(?:/|$)' -or
        $RelativePath -match '(?i)(?:chrome|msedge|stock-firefox)(?:\.exe)?$') {
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
    Assert-ExactProperties -Value $receipt -Expected @('artifact_relative_path', 'artifact_sha256', 'artifact_size_bytes', 'post_process', 'production_flags', 'profile', 'schema', 'schema_version', 'status', 'tool_sha256', 'verifier_sha256') -Label 'protector receipt'
    Assert-ExactProperties -Value $receipt.post_process -Expected @('debug_paths_scrubbed', 'protection_verified', 'rich_header_scrubbed', 'symbols_scrubbed') -Label 'protector post-process receipt'
    $expectedFlags = @('/Qspectre', '/sdl', '/guard:cf', '/guard:ehcont', '/guard:xfg') | Sort-Object -CaseSensitive
    $actualFlags = @($receipt.production_flags | ForEach-Object { [string]$_ } | Sort-Object -CaseSensitive -Unique)
    if ($receipt.schema -ne 'aida.protector.receipt' -or [int]$receipt.schema_version -ne 2 -or
        $receipt.status -ne 'passed' -or $receipt.profile -ne 'production' -or
        $receipt.artifact_relative_path -cne [string]$ExecutableArtifact.relative_path -or
        $receipt.artifact_sha256 -cne [string]$ExecutableArtifact.sha256 -or
        [Int64]$receipt.artifact_size_bytes -ne [Int64]$ExecutableArtifact.size_bytes -or
        [string]$receipt.tool_sha256 -cnotmatch '^[0-9a-f]{64}$' -or
        [string]$receipt.verifier_sha256 -cnotmatch '^[0-9a-f]{64}$' -or
        -not [bool]$receipt.post_process.protection_verified -or
        -not [bool]$receipt.post_process.symbols_scrubbed -or
        -not [bool]$receipt.post_process.debug_paths_scrubbed -or
        -not [bool]$receipt.post_process.rich_header_scrubbed -or
        $actualFlags.Count -ne $expectedFlags.Count -or
        ($actualFlags -join "`n") -cne ($expectedFlags -join "`n")) {
        throw 'protector receipt is invalid or does not bind the protected artifact'
    }
}

function Assert-SignatureReceipt {
    param([string]$Root, [object]$ReceiptArtifact, [object]$ExecutableArtifact)
    if ($ReceiptArtifact.kind -ne 'signature_receipt') {
        throw 'signature receipt artifact kind is invalid'
    }
    $path = Resolve-SafeRelativePath -Root $Root -RelativePath ([string]$ReceiptArtifact.relative_path) -Label 'signature receipt'
    $receipt = (Read-StrictJson -Path $path -Label 'signature receipt').value
    Assert-ExactProperties -Value $receipt -Expected @('artifact_relative_path', 'artifact_sha256', 'artifact_size_bytes', 'chain_status', 'schema', 'schema_version', 'signer_thumbprint_sha256', 'status', 'timestamp_status', 'verification_mode', 'verifier_sha256') -Label 'signature receipt'
    if ($receipt.schema -ne 'aida.signature.receipt' -or [int]$receipt.schema_version -ne 2 -or
        $receipt.status -ne 'verified' -or $receipt.verification_mode -ne 'wintrust_offline' -or
        $receipt.chain_status -ne 'trusted' -or $receipt.timestamp_status -ne 'trusted' -or
        $receipt.artifact_relative_path -cne [string]$ExecutableArtifact.relative_path -or
        $receipt.artifact_sha256 -cne [string]$ExecutableArtifact.sha256 -or
        [Int64]$receipt.artifact_size_bytes -ne [Int64]$ExecutableArtifact.size_bytes -or
        [string]$receipt.signer_thumbprint_sha256 -cnotmatch '^[0-9a-f]{64}$' -or
        [string]$receipt.verifier_sha256 -cnotmatch '^[0-9a-f]{64}$') {
        throw 'signature receipt is invalid or does not bind the signed artifact'
    }
}

$root = (Resolve-Path -LiteralPath $PackageRoot -ErrorAction Stop).Path.TrimEnd([IO.Path]::DirectorySeparatorChar)
$rootItem = Get-Item -LiteralPath $root -Force
if (-not $rootItem.PSIsContainer -or ($rootItem.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
    throw 'package root must be a regular non-reparse directory'
}
$manifestPath = [IO.Path]::GetFullPath($OutputManifest)
$digestPath = [IO.Path]::GetFullPath($OutputDigest)
if ([string]::Equals($manifestPath, $digestPath, [StringComparison]::OrdinalIgnoreCase) -or
    $manifestPath.StartsWith($root + [IO.Path]::DirectorySeparatorChar, [StringComparison]::OrdinalIgnoreCase) -or
    $digestPath.StartsWith($root + [IO.Path]::DirectorySeparatorChar, [StringComparison]::OrdinalIgnoreCase)) {
    throw 'detached distribution manifest and digest must be distinct and outside the package inventory root'
}
$authorityDocument = Read-StrictJson -Path ((Resolve-Path -LiteralPath $AuthorityLock -ErrorAction Stop).Path) -Label 'source authority lock'
if ($authorityDocument.value.schema -ne 'aida.c03.worker-manifest-lock' -or [int]$authorityDocument.value.schema_version -ne 2 -or -not [bool]$authorityDocument.value.no_network_fetch) {
    throw 'source authority lock is malformed or downgraded'
}
$specDocument = Read-StrictJson -Path ((Resolve-Path -LiteralPath $Spec -ErrorAction Stop).Path) -Label 'distribution manifest spec'
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
$artifactIds = @{}
$artifactPaths = @{}
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
$remainderSource = $null
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
        $treeEntries = [Collections.Generic.List[object]]::new()
        foreach ($entry in Get-ChildItem -LiteralPath $treeRoot -Recurse -Force | Sort-Object -Property FullName -CaseSensitive) {
            if (($entry.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
                throw "exact tree inventory contains a reparse point: $($entry.FullName)"
            }
            if ($entry.PSIsContainer) { continue }
            $relativeInTree = $entry.FullName.Substring($treeRoot.Length + 1).Replace('\', '/')
            $identity = Get-LockedIdentity -Path $entry.FullName -Label 'exact tree artifact'
            $treeEntries.Add([pscustomobject]@{ relative_path = $relativeInTree; size_bytes = $identity.size_bytes; sha256 = $identity.sha256 })
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
    } elseif ($sourceType -eq 'remainder_tree_v1') {
        if ($null -ne $remainderSource) {
            throw 'distribution manifest spec contains duplicate remainder sources'
        }
        Assert-ExactProperties -Value $source -Expected @('distinguished_artifact_id', 'distinguished_relative_path', 'expected_maximum_file_count', 'expected_minimum_file_count', 'id', 'id_prefix', 'kind', 'license_ids', 'owner', 'type') -Label 'remainder inventory source'
        $remainderSource = $source
    } else {
        throw "distribution manifest spec contains an unsupported inventory source type: $sourceType"
    }
}

if ($null -eq $remainderSource) {
    throw 'distribution manifest spec lacks the bounded remainder inventory source'
}
$remainderEntries = [Collections.Generic.List[object]]::new()
foreach ($entry in Get-ChildItem -LiteralPath $root -Recurse -Force | Sort-Object -Property FullName -CaseSensitive) {
    if (($entry.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
        throw "package remainder contains a reparse point: $($entry.FullName)"
    }
    if ($entry.PSIsContainer) { continue }
    $relative = $entry.FullName.Substring($root.Length + 1).Replace('\', '/')
    if (-not $artifactPaths.ContainsKey($relative)) {
        $remainderEntries.Add([pscustomobject]@{ path = $entry.FullName; relative_path = $relative })
    }
}
if ($remainderEntries.Count -lt [int]$remainderSource.expected_minimum_file_count -or
    $remainderEntries.Count -gt [int]$remainderSource.expected_maximum_file_count) {
    throw 'package remainder file count violates its bounded contract'
}
$remainderIndex = 0
$remainderDistinguishedSeen = $false
foreach ($entry in @($remainderEntries | Sort-Object -Property relative_path -CaseSensitive)) {
    if ([string]$entry.relative_path -ceq [string]$remainderSource.distinguished_relative_path) {
        $artifactId = [string]$remainderSource.distinguished_artifact_id
        $artifactKind = 'application'
        $remainderDistinguishedSeen = $true
    } else {
        $artifactId = ([string]$remainderSource.id_prefix) + '-' + ('{0:D4}' -f $remainderIndex)
        $artifactKind = [string]$remainderSource.kind
    }
    Add-PackageArtifact -Ids $artifactIds -Paths $artifactPaths -Output $materializedArtifacts `
        -TotalBytes ([ref]$totalArtifactBytes) -Root $root -Id $artifactId -Kind $artifactKind `
        -RelativePath ([string]$entry.relative_path) -Owner ([string]$remainderSource.owner) `
        -LicenseIds @($remainderSource.license_ids | ForEach-Object { [string]$_ })
    ++$remainderIndex
}
if (-not $remainderDistinguishedSeen) {
    throw 'protected standalone executable is absent from the package remainder'
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
    native_decompiler = @('aida-native-decompiler', 2, 2, 'native')
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
    $workerDigest = [IO.File]::ReadAllText($workerDigestPath, [Text.Encoding]::ASCII)
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
$actualPaths = @{}
foreach ($entry in Get-ChildItem -LiteralPath $root -Recurse -Force) {
    if (($entry.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
        throw "package inventory contains a reparse point: $($entry.FullName)"
    }
    if ($entry.PSIsContainer) {
        continue
    }
    $relative = $entry.FullName.Substring($root.Length + 1).Replace('\', '/')
    if ($actualPaths.ContainsKey($relative)) {
        throw 'package inventory contains a duplicate path'
    }
    $actualPaths[$relative] = $true
}
if ($actualPaths.Count -ne $artifactPaths.Count) {
    throw "package inventory count mismatch: expected=$($artifactPaths.Count) actual=$($actualPaths.Count)"
}
foreach ($relative in $actualPaths.Keys) {
    if (-not $artifactPaths.ContainsKey($relative)) {
        throw "package inventory contains an unlisted file: $relative"
    }
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
$manifestIdentity = Get-LockedIdentity -Path $manifestPath -Label 'detached distribution manifest' -MaximumBytes 16777216
if ($manifestIdentity.sha256 -ne $manifestDigest -or (Get-Content -LiteralPath $digestPath -Raw -Encoding ASCII) -cne ($manifestDigest + "`n")) {
    throw 'detached distribution manifest verification failed after publication'
}
[pscustomobject]@{
    artifact_count = $materializedArtifacts.Count
    manifest = $manifestPath
    manifest_sha256 = $manifestDigest
    package_root = $root
    source_authority_sha256 = $authorityDocument.identity.sha256
    verified = $true
} | ConvertTo-Json -Compress
