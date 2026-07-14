[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$RepositoryRoot,
    [Parameter(Mandatory = $true)]
    [string]$OutputDirectory,
    [switch]$Force
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Convert-HexToBytes {
    param([string]$Hex)
    if (-not $Hex -or ($Hex.Length % 2) -ne 0 -or $Hex -notmatch '^[0-9a-fA-F]+$') {
        throw 'invalid hexadecimal value'
    }
    $bytes = [byte[]]::new($Hex.Length / 2)
    for ($index = 0; $index -lt $bytes.Length; ++$index) {
        $bytes[$index] = [Convert]::ToByte($Hex.Substring($index * 2, 2), 16)
    }
    return $bytes
}

function Test-FixedTimeEqual {
    param(
        [byte[]]$Left,
        [byte[]]$Right
    )
    if ($null -eq $Left -or $null -eq $Right -or $Left.Length -ne $Right.Length) {
        return $false
    }
    $difference = 0
    for ($index = 0; $index -lt $Left.Length; ++$index) {
        $difference = $difference -bor ($Left[$index] -bxor $Right[$index])
    }
    return $difference -eq 0
}

function Test-HexDigestEqual {
    param(
        [string]$Left,
        [string]$Right
    )
    if ($Left -notmatch '^[0-9a-fA-F]{64}$' -or $Right -notmatch '^[0-9a-fA-F]{64}$') {
        return $false
    }
    return Test-FixedTimeEqual (Convert-HexToBytes $Left) (Convert-HexToBytes $Right)
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
    return $item
}

function Assert-NoReparseAncestors {
    param(
        [string]$Root,
        [string]$Path,
        [string]$Label
    )
    $rootPath = [IO.Path]::GetFullPath($Root).TrimEnd([IO.Path]::DirectorySeparatorChar)
    $candidate = [IO.Path]::GetFullPath($Path)
    if (-not $candidate.StartsWith($rootPath + [IO.Path]::DirectorySeparatorChar, [StringComparison]::OrdinalIgnoreCase) -and
        -not [string]::Equals($candidate, $rootPath, [StringComparison]::OrdinalIgnoreCase)) {
        throw "$Label escapes its root"
    }
    $cursor = $candidate
    if (-not [IO.Directory]::Exists($cursor)) {
        $cursor = Split-Path -Parent $cursor
    }
    while ($cursor -and $cursor.Length -ge $rootPath.Length) {
        if ([IO.Directory]::Exists($cursor) -or [IO.File]::Exists($cursor)) {
            $item = Get-Item -LiteralPath $cursor -Force
            if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
                throw "$Label crosses a reparse point"
            }
        }
        if ([string]::Equals($cursor.TrimEnd([IO.Path]::DirectorySeparatorChar), $rootPath, [StringComparison]::OrdinalIgnoreCase)) {
            break
        }
        $next = Split-Path -Parent $cursor
        if (-not $next -or [string]::Equals($next, $cursor, [StringComparison]::OrdinalIgnoreCase)) {
            throw "$Label has an invalid ancestor chain"
        }
        $cursor = $next
    }
}

function Resolve-RepositoryFile {
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
    Assert-NoReparseAncestors -Root $Root -Path $path -Label $Label
    Assert-RegularFile -Path $path -Label $Label | Out-Null
    return $path
}

function Get-LockedFileIdentity {
    param(
        [string]$Path,
        [string]$Label
    )
    Assert-RegularFile -Path $Path -Label $Label | Out-Null
    $stream = [IO.File]::Open($Path, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::Read)
    try {
        if ($stream.Length -le 0 -or $stream.Length -gt 2147483648) {
            throw "$Label size violates policy"
        }
        $sha = [Security.Cryptography.SHA256]::Create()
        try {
            $digest = $sha.ComputeHash($stream)
        } finally {
            $sha.Dispose()
        }
        return [pscustomobject]@{
            Path = [IO.Path]::GetFullPath($Path)
            SizeBytes = [Int64]$stream.Length
            Sha256 = ([BitConverter]::ToString($digest) -replace '-', '').ToLowerInvariant()
        }
    } finally {
        $stream.Dispose()
    }
}

function Read-LockedJson {
    param(
        [string]$Path,
        [string]$Label
    )
    Assert-RegularFile -Path $Path -Label $Label | Out-Null
    $stream = [IO.File]::Open($Path, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::Read)
    try {
        if ($stream.Length -le 0 -or $stream.Length -gt 16777216) {
            throw "$Label size violates policy"
        }
        $reader = [IO.StreamReader]::new($stream, [Text.UTF8Encoding]::new($false, $true), $true, 65536, $true)
        try {
            $text = $reader.ReadToEnd()
        } finally {
            $reader.Dispose()
        }
    } finally {
        $stream.Dispose()
    }
    if ($text -match 'https?://|ftp://|file://|\\\\') {
        throw "$Label contains a remote or UNC reference"
    }
    return $text | ConvertFrom-Json
}

function Get-BytesSha256 {
    param([byte[]]$Bytes)
    $sha = [Security.Cryptography.SHA256]::Create()
    try {
        return ([BitConverter]::ToString($sha.ComputeHash($Bytes)) -replace '-', '').ToLowerInvariant()
    } finally {
        $sha.Dispose()
    }
}

function Write-AtomicBytes {
    param(
        [string]$Root,
        [string]$Path,
        [byte[]]$Bytes,
        [switch]$Replace
    )
    Assert-NoReparseAncestors -Root $Root -Path $Path -Label 'package output'
    $parent = Split-Path -Parent $Path
    New-Item -ItemType Directory -Path $parent -Force | Out-Null
    Assert-NoReparseAncestors -Root $Root -Path $parent -Label 'package output directory'
    if ([IO.File]::Exists($Path) -and -not $Replace) {
        throw "package output already exists: $Path"
    }
    if ([IO.File]::Exists($Path)) {
        Assert-RegularFile -Path $Path -Label 'existing package output' | Out-Null
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

function Copy-LockedFileAtomic {
    param(
        [string]$Root,
        [string]$Source,
        [string]$Destination,
        [string]$ExpectedSha256,
        [Int64]$ExpectedSize,
        [switch]$Replace
    )
    Assert-RegularFile -Path $Source -Label 'locked package input' | Out-Null
    Assert-NoReparseAncestors -Root $Root -Path $Destination -Label 'package output'
    $parent = Split-Path -Parent $Destination
    New-Item -ItemType Directory -Path $parent -Force | Out-Null
    Assert-NoReparseAncestors -Root $Root -Path $parent -Label 'package output directory'
    if ([IO.File]::Exists($Destination) -and -not $Replace) {
        throw "package output already exists: $Destination"
    }
    if ([IO.File]::Exists($Destination)) {
        Assert-RegularFile -Path $Destination -Label 'existing package output' | Out-Null
    }
    $temporary = Join-Path $parent ('.' + [IO.Path]::GetFileName($Destination) + '.' + [Guid]::NewGuid().ToString('N') + '.tmp')
    $sourceStream = [IO.File]::Open($Source, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::Read)
    try {
        if ($sourceStream.Length -ne $ExpectedSize) {
            throw 'locked package input size changed before staging'
        }
        $buffer = [byte[]]::new(1048576)
        $sha = [Security.Cryptography.SHA256]::Create()
        $destinationStream = [IO.File]::Open($temporary, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write, [IO.FileShare]::None)
        try {
            while (($read = $sourceStream.Read($buffer, 0, $buffer.Length)) -gt 0) {
                $destinationStream.Write($buffer, 0, $read)
                $sha.TransformBlock($buffer, 0, $read, $null, 0) | Out-Null
            }
            $sha.TransformFinalBlock([byte[]]::new(0), 0, 0) | Out-Null
            $actual = ([BitConverter]::ToString($sha.Hash) -replace '-', '').ToLowerInvariant()
            if (-not (Test-HexDigestEqual $actual $ExpectedSha256)) {
                throw 'locked package input hash changed before staging'
            }
            $destinationStream.Flush($true)
        } finally {
            $destinationStream.Dispose()
            $sha.Dispose()
        }
    } catch {
        if ([IO.File]::Exists($temporary)) {
            [IO.File]::Delete($temporary)
        }
        throw
    } finally {
        $sourceStream.Dispose()
    }
    try {
        if ([IO.File]::Exists($Destination)) {
            [IO.File]::Replace($temporary, $Destination, $null, $true)
        } else {
            [IO.File]::Move($temporary, $Destination)
        }
    } finally {
        if ([IO.File]::Exists($temporary)) {
            [IO.File]::Delete($temporary)
        }
    }
    $staged = Get-LockedFileIdentity -Path $Destination -Label 'staged package output'
    if ($staged.SizeBytes -ne $ExpectedSize -or -not (Test-HexDigestEqual $staged.Sha256 $ExpectedSha256)) {
        throw 'staged package output failed identity verification'
    }
}

function New-AnalysisPythonManifest {
    param([byte[]]$WorkerHash)
    $protocol = 'aida.analysis-python.worker.frame.v1|bootstrap.v1|hmac-sha256|strict-sequence|approved-workspace-api'
    $workerPath = [Text.UTF8Encoding]::new($false, $true).GetBytes('deps/AiDA_AnalysisPythonWorker.exe')
    $protocolHash = Convert-HexToBytes (Get-BytesSha256 ([Text.UTF8Encoding]::new($false, $true).GetBytes($protocol)))
    $memory = [IO.MemoryStream]::new()
    $writer = [IO.BinaryWriter]::new($memory, [Text.UTF8Encoding]::new($false, $true), $true)
    try {
        $writer.Write([UInt32]0x4D575041)
        $writer.Write([UInt32]1)
        $writer.Write([UInt32]$workerPath.Length)
        $writer.Write($workerPath)
        $writer.Write($WorkerHash)
        $writer.Write($protocolHash)
        $writer.Write([UInt32]1)
        $writer.Flush()
        return $memory.ToArray()
    } finally {
        $writer.Dispose()
        $memory.Dispose()
    }
}

$repository = (Resolve-Path -LiteralPath $RepositoryRoot -ErrorAction Stop).Path.TrimEnd([IO.Path]::DirectorySeparatorChar)
$repositoryItem = Get-Item -LiteralPath $repository -Force
if (-not $repositoryItem.PSIsContainer -or ($repositoryItem.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
    throw 'repository root must be a regular non-reparse directory'
}
$lockPath = Resolve-RepositoryFile -Root $repository -RelativePath 'packaging/c03_worker_manifest.lock.json' -Label 'worker authority lock'
$lock = Read-LockedJson -Path $lockPath -Label 'worker authority lock'
if ($lock.schema -ne 'aida.c03.worker-manifest-lock' -or [int]$lock.schema_version -ne 2 -or -not [bool]$lock.no_network_fetch) {
    throw 'worker authority lock is malformed or downgraded'
}
$worker = $lock.analysis_python_worker
Assert-ExactProperties -Value $worker -Expected @('build_script', 'containment', 'id', 'manifest', 'network_fetch_forbidden', 'pinned_freezer_required', 'prebuilt_artifact', 'protocol', 'runtime_coupling', 'source') -Label 'analysis Python worker authority'
if ($worker.id -ne 'analysis_python' -or -not [bool]$worker.network_fetch_forbidden -or -not [bool]$worker.pinned_freezer_required -or
    -not [bool]$worker.prebuilt_artifact.required_for_staging -or -not [bool]$worker.runtime_coupling.camoufox_forbidden -or
    [int]$worker.protocol.version -ne 1 -or $worker.protocol.hash_material -ne 'aida.analysis-python.worker.frame.v1|bootstrap.v1|hmac-sha256|strict-sequence|approved-workspace-api') {
    throw 'analysis Python worker authority is malformed or downgraded'
}
$sourcePath = Resolve-RepositoryFile -Root $repository -RelativePath ([string]$worker.source.path) -Label 'analysis Python worker source'
$sourceIdentity = Get-LockedFileIdentity -Path $sourcePath -Label 'analysis Python worker source'
if (-not (Test-HexDigestEqual $sourceIdentity.Sha256 ([string]$worker.source.sha256))) {
    throw 'analysis Python worker source identity does not match the authority lock'
}
$prebuiltDirectory = [IO.Path]::GetFullPath((Join-Path $repository ([string]$worker.prebuilt_artifact.source_directory -replace '/', '\')))
Assert-NoReparseAncestors -Root $repository -Path $prebuiltDirectory -Label 'analysis Python prebuilt directory'
if (-not [IO.Directory]::Exists($prebuiltDirectory)) {
    throw "missing locked prebuilt artifact: $([IO.Path]::GetFullPath((Join-Path $repository ([string]$worker.prebuilt_artifact.source_path -replace '/', '\'))))"
}
$prebuiltItem = Get-Item -LiteralPath $prebuiltDirectory -Force
if (-not $prebuiltItem.PSIsContainer -or ($prebuiltItem.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
    throw 'analysis Python prebuilt directory must be a regular non-reparse directory'
}
if ($worker.prebuilt_artifact.identity_state -ne 'locked' -or
    [string]$worker.prebuilt_artifact.expected_sha256 -notmatch '^[0-9a-f]{64}$' -or
    [Int64]$worker.prebuilt_artifact.expected_size_bytes -le 0 -or
    [string]$worker.prebuilt_artifact.expected_signer_thumbprint_sha256 -notmatch '^[0-9a-f]{64}$' -or
    [string]$worker.prebuilt_artifact.expected_protector_tool_sha256 -notmatch '^[0-9a-f]{64}$' -or
    [string]$worker.prebuilt_artifact.expected_protector_verifier_sha256 -notmatch '^[0-9a-f]{64}$' -or
    [string]$worker.prebuilt_artifact.expected_signature_verifier_sha256 -notmatch '^[0-9a-f]{64}$') {
    throw 'analysis Python prebuilt identity is not locked; acquisition and authority update are required'
}
$workerPath = Resolve-RepositoryFile -Root $repository -RelativePath ([string]$worker.prebuilt_artifact.source_path) -Label 'analysis Python prebuilt executable'
if ($workerPath.ToLowerInvariant().Contains('camoufox')) {
    throw 'analysis Python worker cannot use a Camoufox runtime artifact'
}
$workerIdentity = Get-LockedFileIdentity -Path $workerPath -Label 'analysis Python prebuilt executable'
if ($workerIdentity.SizeBytes -ne [Int64]$worker.prebuilt_artifact.expected_size_bytes -or
    -not (Test-HexDigestEqual $workerIdentity.Sha256 ([string]$worker.prebuilt_artifact.expected_sha256))) {
    throw 'analysis Python prebuilt executable identity does not match the authority lock'
}
$signature = Get-AuthenticodeSignature -LiteralPath $workerPath
$actualThumbprint = ''
if ($null -ne $signature.SignerCertificate) {
    $certificateSha = [Security.Cryptography.SHA256]::Create()
    try {
        $actualThumbprint = ([BitConverter]::ToString($certificateSha.ComputeHash($signature.SignerCertificate.RawData)) -replace '-', '').ToLowerInvariant()
    } finally {
        $certificateSha.Dispose()
    }
}
if ($signature.Status -ne [System.Management.Automation.SignatureStatus]::Valid -or
    -not (Test-HexDigestEqual $actualThumbprint ([string]$worker.prebuilt_artifact.expected_signer_thumbprint_sha256))) {
    throw 'analysis Python prebuilt executable Authenticode verification failed'
}
$frozenPath = Resolve-RepositoryFile -Root $repository -RelativePath ([string]$worker.prebuilt_artifact.frozen_contents_path) -Label 'analysis Python frozen-content receipt'
$buildReceiptPath = Resolve-RepositoryFile -Root $repository -RelativePath ([string]$worker.prebuilt_artifact.build_receipt_path) -Label 'analysis Python build receipt'
$protectorReceiptPath = Resolve-RepositoryFile -Root $repository -RelativePath ([string]$worker.prebuilt_artifact.protector_receipt_path) -Label 'analysis Python protector receipt'
$signatureReceiptPath = Resolve-RepositoryFile -Root $repository -RelativePath ([string]$worker.prebuilt_artifact.signature_receipt_path) -Label 'analysis Python signature receipt'
$frozenIdentity = Get-LockedFileIdentity -Path $frozenPath -Label 'analysis Python frozen-content receipt'
$frozen = Read-LockedJson -Path $frozenPath -Label 'analysis Python frozen-content receipt'
Assert-ExactProperties -Value $frozen -Expected @('bytecode_files_present', 'child_process_capable', 'network_capable', 'onefile', 'schema', 'schema_version', 'source_files_present', 'wheels_present', 'worker_sha256') -Label 'analysis Python frozen-content receipt'
if ($frozen.schema -ne 'aida.analysis-python.frozen-contents-receipt' -or [int]$frozen.schema_version -ne 1 -or
    -not [bool]$frozen.onefile -or [bool]$frozen.source_files_present -or [bool]$frozen.bytecode_files_present -or
    [bool]$frozen.wheels_present -or [bool]$frozen.child_process_capable -or [bool]$frozen.network_capable -or
    -not (Test-HexDigestEqual ([string]$frozen.worker_sha256) $workerIdentity.Sha256)) {
    throw 'analysis Python frozen-content receipt is invalid'
}
$buildReceipt = Read-LockedJson -Path $buildReceiptPath -Label 'analysis Python build receipt'
Assert-ExactProperties -Value $buildReceipt -Expected @('browser_runtime_used', 'freezer', 'frozen_contents_sha256', 'network_fetch_performed', 'schema', 'schema_version', 'source_sha256', 'target_code_executed', 'worker_sha256', 'worker_size_bytes') -Label 'analysis Python build receipt'
Assert-ExactProperties -Value $buildReceipt.freezer -Expected @('environment_lock_sha256', 'name', 'version') -Label 'analysis Python freezer receipt'
if ($buildReceipt.schema -ne 'aida.analysis-python.prebuilt-build-receipt' -or [int]$buildReceipt.schema_version -ne 1 -or
    [bool]$buildReceipt.network_fetch_performed -or [bool]$buildReceipt.target_code_executed -or [bool]$buildReceipt.browser_runtime_used -or
    -not (Test-HexDigestEqual ([string]$buildReceipt.worker_sha256) $workerIdentity.Sha256) -or
    [Int64]$buildReceipt.worker_size_bytes -ne $workerIdentity.SizeBytes -or
    -not (Test-HexDigestEqual ([string]$buildReceipt.source_sha256) $sourceIdentity.Sha256) -or
    -not (Test-HexDigestEqual ([string]$buildReceipt.frozen_contents_sha256) $frozenIdentity.Sha256) -or
    $buildReceipt.freezer.name -ne $worker.prebuilt_artifact.freezer.name -or
    $buildReceipt.freezer.version -ne $worker.prebuilt_artifact.freezer.version -or
    -not (Test-HexDigestEqual ([string]$buildReceipt.freezer.environment_lock_sha256) ([string]$worker.prebuilt_artifact.freezer.environment_lock_sha256))) {
    throw 'analysis Python build receipt is invalid'
}
$protectorReceipt = Read-LockedJson -Path $protectorReceiptPath -Label 'analysis Python protector receipt'
Assert-ExactProperties -Value $protectorReceipt -Expected @('artifact_relative_path', 'artifact_sha256', 'artifact_size_bytes', 'post_process', 'production_flags', 'profile', 'schema', 'schema_version', 'status', 'tool_sha256', 'verifier_sha256') -Label 'analysis Python protector receipt'
Assert-ExactProperties -Value $protectorReceipt.post_process -Expected @('debug_paths_scrubbed', 'protection_verified', 'rich_header_scrubbed', 'symbols_scrubbed') -Label 'analysis Python protector post-process receipt'
if ($protectorReceipt.schema -ne 'aida.protector.receipt' -or [int]$protectorReceipt.schema_version -ne 2 -or
    $protectorReceipt.status -ne 'passed' -or $protectorReceipt.profile -ne 'production' -or
    $protectorReceipt.artifact_relative_path -ne $worker.prebuilt_artifact.package_relative_path -or
    -not [bool]$protectorReceipt.post_process.protection_verified -or -not [bool]$protectorReceipt.post_process.symbols_scrubbed -or
    -not [bool]$protectorReceipt.post_process.debug_paths_scrubbed -or -not [bool]$protectorReceipt.post_process.rich_header_scrubbed -or
    -not (Test-HexDigestEqual ([string]$protectorReceipt.artifact_sha256) $workerIdentity.Sha256) -or
    [Int64]$protectorReceipt.artifact_size_bytes -ne $workerIdentity.SizeBytes -or
    -not (Test-HexDigestEqual ([string]$protectorReceipt.tool_sha256) ([string]$worker.prebuilt_artifact.expected_protector_tool_sha256)) -or
    -not (Test-HexDigestEqual ([string]$protectorReceipt.verifier_sha256) ([string]$worker.prebuilt_artifact.expected_protector_verifier_sha256))) {
    throw 'analysis Python protector receipt is invalid'
}
$actualFlags = @($protectorReceipt.production_flags | ForEach-Object { [string]$_ })
$expectedFlags = @($worker.prebuilt_artifact.protector_flags | ForEach-Object { [string]$_ })
if (($actualFlags -join "`n") -cne ($expectedFlags -join "`n")) {
    throw 'analysis Python protector receipt flags do not match the authority lock'
}
$signatureReceipt = Read-LockedJson -Path $signatureReceiptPath -Label 'analysis Python signature receipt'
Assert-ExactProperties -Value $signatureReceipt -Expected @('artifact_relative_path', 'artifact_sha256', 'artifact_size_bytes', 'chain_status', 'schema', 'schema_version', 'signer_thumbprint_sha256', 'status', 'timestamp_status', 'verification_mode', 'verifier_sha256') -Label 'analysis Python signature receipt'
if ($signatureReceipt.schema -ne 'aida.signature.receipt' -or [int]$signatureReceipt.schema_version -ne 2 -or
    $signatureReceipt.status -ne 'verified' -or $signatureReceipt.verification_mode -ne 'wintrust_offline' -or
    $signatureReceipt.chain_status -ne 'trusted' -or $signatureReceipt.timestamp_status -ne 'trusted' -or
    $signatureReceipt.artifact_relative_path -ne $worker.prebuilt_artifact.package_relative_path -or
    -not (Test-HexDigestEqual ([string]$signatureReceipt.artifact_sha256) $workerIdentity.Sha256) -or
    [Int64]$signatureReceipt.artifact_size_bytes -ne $workerIdentity.SizeBytes -or
    -not (Test-HexDigestEqual ([string]$signatureReceipt.verifier_sha256) ([string]$worker.prebuilt_artifact.expected_signature_verifier_sha256)) -or
    -not (Test-HexDigestEqual ([string]$signatureReceipt.signer_thumbprint_sha256) $actualThumbprint)) {
    throw 'analysis Python signature receipt is invalid'
}
$output = [IO.Path]::GetFullPath($OutputDirectory).TrimEnd([IO.Path]::DirectorySeparatorChar)
if (-not [IO.Directory]::Exists($output)) {
    New-Item -ItemType Directory -Path $output -Force | Out-Null
}
$outputItem = Get-Item -LiteralPath $output -Force
if (-not $outputItem.PSIsContainer -or ($outputItem.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
    throw 'package output root must be a regular non-reparse directory'
}
$packageWorker = [IO.Path]::GetFullPath((Join-Path $output ([string]$worker.prebuilt_artifact.package_relative_path -replace '/', '\')))
Copy-LockedFileAtomic -Root $output -Source $workerPath -Destination $packageWorker -ExpectedSha256 $workerIdentity.Sha256 -ExpectedSize $workerIdentity.SizeBytes -Replace:$Force
$manifestBytes = New-AnalysisPythonManifest -WorkerHash (Convert-HexToBytes $workerIdentity.Sha256)
$manifestHash = Get-BytesSha256 $manifestBytes
$manifestPath = [IO.Path]::GetFullPath((Join-Path $output ([string]$worker.prebuilt_artifact.manifest_relative_path -replace '/', '\')))
$digestPath = [IO.Path]::GetFullPath((Join-Path $output ([string]$worker.prebuilt_artifact.manifest_digest_relative_path -replace '/', '\')))
Write-AtomicBytes -Root $output -Path $manifestPath -Bytes $manifestBytes -Replace:$Force
Write-AtomicBytes -Root $output -Path $digestPath -Bytes ([Text.Encoding]::ASCII.GetBytes($manifestHash + "`n")) -Replace:$Force
$receiptSources = @($frozenPath, $buildReceiptPath, $protectorReceiptPath, $signatureReceiptPath)
foreach ($receiptSource in $receiptSources) {
    $identity = Get-LockedFileIdentity -Path $receiptSource -Label 'analysis Python evidence receipt'
    $receiptDestination = Join-Path $output ('deps\evidence\analysis-python\' + [IO.Path]::GetFileName($receiptSource))
    Copy-LockedFileAtomic -Root $output -Source $receiptSource -Destination $receiptDestination -ExpectedSha256 $identity.Sha256 -ExpectedSize $identity.SizeBytes -Replace:$Force
}
$stagedWorker = Get-LockedFileIdentity -Path $packageWorker -Label 'staged analysis Python worker'
$stagedManifest = Get-LockedFileIdentity -Path $manifestPath -Label 'staged analysis Python manifest'
$stagedDigest = (Get-Content -LiteralPath $digestPath -Raw -Encoding ASCII)
if (-not (Test-HexDigestEqual $stagedWorker.Sha256 $workerIdentity.Sha256) -or
    -not (Test-HexDigestEqual $stagedManifest.Sha256 $manifestHash) -or $stagedDigest -cne ($manifestHash + "`n")) {
    throw 'analysis Python package verification failed after staging'
}
[pscustomobject]@{
    manifest = [string]$worker.prebuilt_artifact.manifest_relative_path
    manifest_sha256 = $manifestHash
    worker = [string]$worker.prebuilt_artifact.package_relative_path
    worker_sha256 = $workerIdentity.Sha256
    worker_size_bytes = $workerIdentity.SizeBytes
    verified = $true
} | ConvertTo-Json -Compress
