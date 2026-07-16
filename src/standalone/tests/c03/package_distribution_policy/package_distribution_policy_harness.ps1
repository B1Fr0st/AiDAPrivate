[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$PowerShellExecutable,
    [Parameter(Mandatory = $true)][string]$Producer,
    [Parameter(Mandatory = $true)][string]$ContractVerifier,
    [Parameter(Mandatory = $true)][string]$ProductionVerifier,
    [Parameter(Mandatory = $true)][string]$StageSpec,
    [Parameter(Mandatory = $true)][string]$PathBytePolicy,
    [Parameter(Mandatory = $true)][string]$AuthorityLock,
    [Parameter(Mandatory = $true)][string]$ProtectorTool,
    [Parameter(Mandatory = $true)][string]$ProtectorVerifier,
    [Parameter(Mandatory = $true)][string]$ScratchRoot
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Require {
    param([bool]$Condition, [string]$Message)
    if (-not $Condition) { throw $Message }
}

function Convert-ArgumentPath {
    param([string]$Path)
    return [IO.Path]::GetFullPath($Path).Replace('\', '/')
}

function Read-CompleteGeneration {
    param([string]$PointerPath)
    $pointerItem = Get-Item -LiteralPath $PointerPath -Force -ErrorAction Stop
    Require (-not $pointerItem.PSIsContainer -and $pointerItem.Length -gt 0 -and
        $pointerItem.Length -le 65536) 'complete generation pointer size is invalid'
    $pointer = [IO.File]::ReadAllText(
        $pointerItem.FullName, [Text.UTF8Encoding]::new($false, $true)) | ConvertFrom-Json
    $expected = @('digest_file_identity', 'digest_path', 'generation_id', 'manifest_file_identity',
        'manifest_path', 'manifest_sha256', 'package_directory_identity', 'package_root',
        'schema', 'schema_version')
    $actual = @($pointer.PSObject.Properties.Name | Sort-Object -CaseSensitive)
    Require ($actual.Count -eq $expected.Count) 'complete generation pointer property count is invalid'
    for ($index = 0; $index -lt $expected.Count; ++$index) {
        Require ([string]::Equals($actual[$index], $expected[$index],
            [StringComparison]::Ordinal)) 'complete generation pointer properties are invalid'
    }
    $generationName = '.aida-c03-generation-' + [string]$pointer.generation_id
    Require ($pointer.schema -ceq 'aida.c03.complete-generation-pointer' -and
        [int]$pointer.schema_version -eq 1 -and
        [string]$pointer.generation_id -cmatch '^[0-9a-f]{32}$' -and
        [string]$pointer.manifest_sha256 -cmatch '^[0-9a-f]{64}$') 'complete generation pointer contract is invalid'
    $packageRoot = [IO.Path]::GetFullPath([string]$pointer.package_root)
    $manifestPath = [IO.Path]::GetFullPath([string]$pointer.manifest_path)
    $digestPath = [IO.Path]::GetFullPath([string]$pointer.digest_path)
    Require ([IO.Path]::GetFileName($packageRoot) -ceq $generationName -and
        [IO.Path]::GetFileName((Split-Path -Parent $manifestPath)) -ceq $generationName -and
        [string]::Equals((Split-Path -Parent $manifestPath), (Split-Path -Parent $digestPath),
            [StringComparison]::Ordinal) -and
        [IO.Directory]::Exists($packageRoot) -and [IO.File]::Exists($manifestPath) -and
        [IO.File]::Exists($digestPath)) 'complete generation pointer paths are invalid'
    $manifestHash = (Get-FileHash -Algorithm SHA256 -LiteralPath $manifestPath).Hash.ToLowerInvariant()
    Require ($manifestHash -ceq [string]$pointer.manifest_sha256 -and
        [IO.File]::ReadAllText($digestPath, [Text.Encoding]::ASCII) -ceq ($manifestHash + "`n")) `
        'complete generation manifest/digest binding is invalid'
    return [pscustomobject]@{
        id = [string]$pointer.generation_id
        package_root = $packageRoot
        manifest_path = $manifestPath
        digest_path = $digestPath
        manifest_sha256 = $manifestHash
        pointer_sha256 = (Get-FileHash -Algorithm SHA256 -LiteralPath $PointerPath).Hash.ToLowerInvariant()
    }
}

function Read-BoundedText {
    param([string]$Path)
    $item = Get-Item -LiteralPath $Path -Force -ErrorAction Stop
    Require (-not $item.PSIsContainer -and $item.Length -le 1048576) 'child process output exceeded its bounded capture'
    return [IO.File]::ReadAllText($item.FullName, [Text.UTF8Encoding]::new($false, $true))
}

function Invoke-Child {
    param([string]$Executable, [string[]]$Arguments, [int]$ExpectedExit, [string]$ExpectedMarker)
    $capture = Join-Path $script:WorkRoot ('capture-' + [Guid]::NewGuid().ToString('N'))
    [IO.Directory]::CreateDirectory($capture) | Out-Null
    $stdout = Join-Path $capture 'stdout.txt'
    $stderr = Join-Path $capture 'stderr.txt'
    & $Executable @Arguments 1> $stdout 2> $stderr
    $exitCode = $LASTEXITCODE
    $output = (Read-BoundedText -Path $stdout) + (Read-BoundedText -Path $stderr)
    Require ($exitCode -eq $ExpectedExit) ('child process exit mismatch: ' + $exitCode + ' output=' + $output)
    if ($ExpectedMarker) {
        Require ($output.IndexOf($ExpectedMarker, [StringComparison]::Ordinal) -ge 0) ('child process marker missing: ' + $ExpectedMarker + ' output=' + $output)
    }
    return $output
}

function Invoke-TerminatedChild {
    param([string]$Executable, [string[]]$Arguments)
    $capture = Join-Path $script:WorkRoot ('termination-' + [Guid]::NewGuid().ToString('N'))
    [IO.Directory]::CreateDirectory($capture) | Out-Null
    $stdout = Join-Path $capture 'stdout.txt'
    $stderr = Join-Path $capture 'stderr.txt'
    $process = Start-Process -FilePath $Executable -ArgumentList $Arguments -PassThru `
        -WindowStyle Hidden -RedirectStandardOutput $stdout -RedirectStandardError $stderr
    Require ($process.WaitForExit(120000)) 'terminated publication child exceeded its deadline'
    $process.WaitForExit()
    Require ($process.ExitCode -ne 0) 'publication termination checkpoint returned success'
}

function New-CaseRoot {
    param([string]$Name)
    $root = Join-Path $script:WorkRoot $Name
    [IO.Directory]::CreateDirectory($root) | Out-Null
    return $root
}

function Set-PeUInt16 {
    param([byte[]]$Bytes, [int]$Offset, [UInt16]$Value)
    [BitConverter]::GetBytes($Value).CopyTo($Bytes, $Offset)
}

function Set-PeUInt32 {
    param([byte[]]$Bytes, [int]$Offset, [UInt32]$Value)
    [BitConverter]::GetBytes($Value).CopyTo($Bytes, $Offset)
}

function New-PePostProcessFixture {
    param(
        [string]$Path,
        [ValidateSet('clean', 'coff-symbols', 'rich', 'dans', 'codeview-path',
            'malformed-debug', 'truncated-debug')][string]$Mutation
    )
    Require ([BitConverter]::IsLittleEndian) 'PE fixture host byte order is unsupported'
    $bytes = [byte[]]::new(1024)
    Set-PeUInt16 -Bytes $bytes -Offset 0 -Value 0x5a4d
    Set-PeUInt32 -Bytes $bytes -Offset 60 -Value 0x80
    Set-PeUInt32 -Bytes $bytes -Offset 128 -Value 0x00004550
    Set-PeUInt16 -Bytes $bytes -Offset 132 -Value 0x8664
    Set-PeUInt16 -Bytes $bytes -Offset 134 -Value 1
    Set-PeUInt16 -Bytes $bytes -Offset 148 -Value 240
    Set-PeUInt16 -Bytes $bytes -Offset 150 -Value 0x0022
    Set-PeUInt16 -Bytes $bytes -Offset 152 -Value 0x020b
    Set-PeUInt32 -Bytes $bytes -Offset 184 -Value 0x1000
    Set-PeUInt32 -Bytes $bytes -Offset 188 -Value 0x200
    Set-PeUInt32 -Bytes $bytes -Offset 208 -Value 0x2000
    Set-PeUInt32 -Bytes $bytes -Offset 212 -Value 0x200
    Set-PeUInt16 -Bytes $bytes -Offset 220 -Value 3
    Set-PeUInt32 -Bytes $bytes -Offset 260 -Value 16
    [Text.Encoding]::ASCII.GetBytes('.text').CopyTo($bytes, 392)
    Set-PeUInt32 -Bytes $bytes -Offset 400 -Value 0x200
    Set-PeUInt32 -Bytes $bytes -Offset 404 -Value 0x1000
    Set-PeUInt32 -Bytes $bytes -Offset 408 -Value 0x200
    Set-PeUInt32 -Bytes $bytes -Offset 412 -Value 0x200
    Set-PeUInt32 -Bytes $bytes -Offset 428 -Value 0x60000020
    switch ($Mutation) {
        'coff-symbols' {
            Set-PeUInt32 -Bytes $bytes -Offset 140 -Value 0x300
            Set-PeUInt32 -Bytes $bytes -Offset 144 -Value 1
        }
        'rich' { [Text.Encoding]::ASCII.GetBytes('Rich').CopyTo($bytes, 64) }
        'dans' { [Text.Encoding]::ASCII.GetBytes('DanS').CopyTo($bytes, 64) }
        'codeview-path' {
            Set-PeUInt32 -Bytes $bytes -Offset 312 -Value 0x1000
            Set-PeUInt32 -Bytes $bytes -Offset 316 -Value 28
            $payload = [byte[]]::new(40)
            [Text.Encoding]::ASCII.GetBytes('RSDS').CopyTo($payload, 0)
            [Text.Encoding]::ASCII.GetBytes('C:\fixture.pdb' + [char]0).CopyTo($payload, 24)
            Set-PeUInt32 -Bytes $bytes -Offset 524 -Value 2
            Set-PeUInt32 -Bytes $bytes -Offset 528 -Value ([UInt32]$payload.Length)
            Set-PeUInt32 -Bytes $bytes -Offset 532 -Value 0x1020
            Set-PeUInt32 -Bytes $bytes -Offset 536 -Value 0x220
            $payload.CopyTo($bytes, 544)
        }
        'malformed-debug' {
            Set-PeUInt32 -Bytes $bytes -Offset 312 -Value 0x1000
            Set-PeUInt32 -Bytes $bytes -Offset 316 -Value 27
        }
        'truncated-debug' {
            Set-PeUInt32 -Bytes $bytes -Offset 312 -Value 0x1000
            Set-PeUInt32 -Bytes $bytes -Offset 316 -Value 28
            $truncated = [byte[]]::new(520)
            [Array]::Copy($bytes, $truncated, $truncated.Length)
            $bytes = $truncated
        }
    }
    [IO.File]::WriteAllBytes($Path, $bytes)
}

function Invoke-PolicyCase {
    param([string]$Root, [string]$Marker, [string[]]$Limits = @())
    $report = Join-Path $script:ReportRoot (([IO.Path]::GetFileName($Root)) + '.json')
    $arguments = @('-NoLogo', '-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass',
        '-File', (Convert-ArgumentPath $Producer), '-PackageRoot', (Convert-ArgumentPath $Root),
        '-PolicyFixtureReport', (Convert-ArgumentPath $report), '-Force') + $Limits
    Invoke-Child -Executable $PowerShellExecutable -Arguments $arguments -ExpectedExit 1 -ExpectedMarker $Marker | Out-Null
}

function Invoke-AcceptedPolicyCase {
    param([string]$Root, [string[]]$Limits = @())
    $report = Join-Path $script:ReportRoot (([IO.Path]::GetFileName($Root)) + '-' +
        [Guid]::NewGuid().ToString('N') + '.json')
    $arguments = @('-NoLogo', '-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass',
        '-File', (Convert-ArgumentPath $Producer), '-PackageRoot', (Convert-ArgumentPath $Root),
        '-PolicyFixtureReport', (Convert-ArgumentPath $report), '-Force') + $Limits
    Invoke-Child -Executable $PowerShellExecutable -Arguments $arguments -ExpectedExit 0 `
        -ExpectedMarker 'aida.c03.package-policy-fixture.v1' | Out-Null
}

foreach ($inputPath in @($PowerShellExecutable, $Producer, $ContractVerifier,
        $ProductionVerifier, $StageSpec, $PathBytePolicy, $AuthorityLock,
        $ProtectorTool, $ProtectorVerifier)) {
    Require ([IO.File]::Exists($inputPath)) ('required fixture input is absent: ' + $inputPath)
}
$scratch = [IO.Path]::GetFullPath($ScratchRoot)
[IO.Directory]::CreateDirectory($scratch) | Out-Null
$script:WorkRoot = Join-Path $scratch ('run-' + [Guid]::NewGuid().ToString('N'))
$script:ReportRoot = Join-Path $script:WorkRoot 'reports'
[IO.Directory]::CreateDirectory($script:ReportRoot) | Out-Null
$junction = $null
$symlink = $null

try {
    Invoke-Child -Executable $ContractVerifier -Arguments @() -ExpectedExit 0 -ExpectedMarker 'verified package contract fixtures' | Out-Null

    $peFixtureRoot = New-CaseRoot 'pe-post-process'
    foreach ($peCase in @(
        @('clean', 0, '"schema":"aida.c03.pe-post-process-measurement"'),
        @('coff-symbols', 1, 'final PE artifact failed measured scrub policy'),
        @('rich', 1, 'final PE artifact failed measured scrub policy'),
        @('dans', 1, 'final PE artifact failed measured scrub policy'),
        @('codeview-path', 1, 'final PE artifact failed measured scrub policy'),
        @('malformed-debug', 1, 'final artifact debug directory is malformed'),
        @('truncated-debug', 1, 'final artifact debug directory is unmapped')
    )) {
        $peFixture = Join-Path $peFixtureRoot (([string]$peCase[0]) + '.exe')
        New-PePostProcessFixture -Path $peFixture -Mutation ([string]$peCase[0])
        Invoke-Child -Executable $ProductionVerifier -Arguments @(
            'inspect-pe-post-process', '--artifact', (Convert-ArgumentPath $peFixture),
            '--deadline-ms', '120000') -ExpectedExit ([int]$peCase[1]) `
            -ExpectedMarker ([string]$peCase[2]) | Out-Null
    }

    $pathPolicy = Get-Content -LiteralPath $PathBytePolicy -Raw -Encoding UTF8 | ConvertFrom-Json
    Require ($pathPolicy.schema -ceq 'aida.c03.utf8-path-byte-policy.v1' -and
        [int]$pathPolicy.maximum_relative_path_bytes -eq 32768 -and
        [Int64]$pathPolicy.maximum_inventory_path_bytes -eq 268435456 -and
        @($pathPolicy.cases).Count -eq 12) 'UTF-8 path byte policy table is invalid'
    foreach ($case in @($pathPolicy.cases)) {
        $text = [string]$case.text
        Require ([Text.UTF8Encoding]::new($false, $true).GetByteCount($text) -eq
            [int]$case.utf8_bytes) 'PowerShell UTF-8 byte width differs from the canonical table'
        $root = New-CaseRoot ('utf8-table-' + [Guid]::NewGuid().ToString('N'))
        $path = Join-Path $root $text.Replace('/', [IO.Path]::DirectorySeparatorChar)
        [IO.Directory]::CreateDirectory((Split-Path -Parent $path)) | Out-Null
        [IO.File]::WriteAllText($path, 'x', [Text.Encoding]::ASCII)
        if ([bool]$case.customer_path_allowed) {
            Invoke-AcceptedPolicyCase -Root $root
        } else {
            Invoke-PolicyCase -Root $root -Marker 'AIDA_C03_PACKAGE_POLICY_PATH_POLICY'
        }
    }

    $valid = New-CaseRoot 'valid'
    $validFile = Join-Path $valid 'allowed.bin'
    [IO.File]::WriteAllBytes($validFile, [byte[]](1, 2, 3, 4))
    $relativeBudget = [Text.UTF8Encoding]::new($false, $true).GetByteCount('allowed.bin')
    $inventoryBudget = $relativeBudget +
        [Text.UTF8Encoding]::new($false, $true).GetByteCount([IO.Path]::GetFullPath($validFile))
    Invoke-PolicyCase -Root $valid -Marker 'AIDA_C03_PACKAGE_POLICY_RESOURCE_PATH_LIMIT' `
        -Limits @('-FixtureMaximumRelativePathBytes', ($relativeBudget - 1))
    Invoke-AcceptedPolicyCase -Root $valid `
        -Limits @('-FixtureMaximumRelativePathBytes', $relativeBudget)
    Invoke-AcceptedPolicyCase -Root $valid `
        -Limits @('-FixtureMaximumRelativePathBytes', ($relativeBudget + 1))
    Invoke-PolicyCase -Root $valid -Marker 'AIDA_C03_PACKAGE_POLICY_RESOURCE_PATH_BUFFER_LIMIT' `
        -Limits @('-FixtureMaximumInventoryPathBytes', ($inventoryBudget - 1))
    Invoke-AcceptedPolicyCase -Root $valid `
        -Limits @('-FixtureMaximumInventoryPathBytes', $inventoryBudget)
    Invoke-AcceptedPolicyCase -Root $valid `
        -Limits @('-FixtureMaximumInventoryPathBytes', ($inventoryBudget + 1))
    $hardlink = Join-Path $valid 'hardlink-alias.bin'
    New-Item -ItemType HardLink -Path $hardlink -Target $validFile -ErrorAction Stop | Out-Null
    Invoke-PolicyCase -Root $valid -Marker 'AIDA_C03_PACKAGE_POLICY_HARDLINK_FORBIDDEN'
    Remove-Item -LiteralPath $hardlink -Force
    $validReport = Join-Path $script:ReportRoot 'valid.json'
    $validArguments = @('-NoLogo', '-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass',
        '-File', (Convert-ArgumentPath $Producer), '-PackageRoot', (Convert-ArgumentPath $valid),
        '-PolicyFixtureReport', (Convert-ArgumentPath $validReport), '-Force')
    Invoke-Child -Executable $PowerShellExecutable -Arguments $validArguments -ExpectedExit 0 -ExpectedMarker 'aida.c03.package-policy-fixture.v1' | Out-Null
    $firstReportHash = (Get-FileHash -Algorithm SHA256 -LiteralPath $validReport).Hash
    Invoke-Child -Executable $PowerShellExecutable -Arguments $validArguments -ExpectedExit 0 -ExpectedMarker 'aida.c03.package-policy-fixture.v1' | Out-Null
    Require ((Get-FileHash -Algorithm SHA256 -LiteralPath $validReport).Hash -ceq $firstReportHash) 'producer policy report is not repeatable'

    $lowerDrive = (Convert-ArgumentPath $valid)
    $lowerDrive = $lowerDrive.Substring(0, 1).ToLowerInvariant() + $lowerDrive.Substring(1)
    $rawArguments = @('-NoLogo', '-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass',
        '-File', (Convert-ArgumentPath $Producer), '-PackageRoot', $lowerDrive,
        '-PolicyFixtureReport', (Convert-ArgumentPath (Join-Path $script:ReportRoot 'raw-case.json')), '-Force')
    Invoke-Child -Executable $PowerShellExecutable -Arguments $rawArguments -ExpectedExit 1 -ExpectedMarker 'AIDA_C03_PACKAGE_POLICY_RAW_ABSOLUTE_PATH' | Out-Null
    $rawArguments[8] = [IO.Path]::GetFullPath($valid)
    Invoke-Child -Executable $PowerShellExecutable -Arguments $rawArguments -ExpectedExit 1 -ExpectedMarker 'AIDA_C03_PACKAGE_POLICY_RAW_ABSOLUTE_PATH' | Out-Null
    $rawArguments[8] = (Convert-ArgumentPath $valid) + '/./nested'
    Invoke-Child -Executable $PowerShellExecutable -Arguments $rawArguments -ExpectedExit 1 -ExpectedMarker 'AIDA_C03_PACKAGE_POLICY_RAW_ABSOLUTE_PATH' | Out-Null
    $rawArguments[8] = (Convert-ArgumentPath $valid) + '.'
    Invoke-Child -Executable $PowerShellExecutable -Arguments $rawArguments -ExpectedExit 1 -ExpectedMarker 'AIDA_C03_PACKAGE_POLICY_RAW_ABSOLUTE_PATH' | Out-Null
    $rawArguments[8] = (Convert-ArgumentPath $valid) + ' '
    Invoke-Child -Executable $PowerShellExecutable -Arguments $rawArguments -ExpectedExit 1 -ExpectedMarker 'AIDA_C03_PACKAGE_POLICY_RAW_ABSOLUTE_PATH' | Out-Null

    foreach ($case in @(
        @('unicode', 'payload-' + [char]0x394 + '.bin'),
        @('control', "payload`t.bin"),
        @('suffix', 'payload.cpp.backup'),
        @('build-name', 'CMakeLists.TxT')
    )) {
        $root = New-CaseRoot ([string]$case[0])
        [IO.File]::WriteAllText((Join-Path $root ([string]$case[1])), 'x', [Text.Encoding]::ASCII)
        Invoke-PolicyCase -Root $root -Marker 'AIDA_C03_PACKAGE_POLICY_PATH_POLICY'
    }
    $directoryAlias = New-CaseRoot 'directory-alias'
    [IO.Directory]::CreateDirectory((Join-Path $directoryAlias 'SDK')) | Out-Null
    [IO.File]::WriteAllText((Join-Path $directoryAlias 'SDK/runtime.dll'), 'x', [Text.Encoding]::ASCII)
    Invoke-PolicyCase -Root $directoryAlias -Marker 'AIDA_C03_PACKAGE_POLICY_PATH_POLICY'

    $ads = New-CaseRoot 'ads'
    $adsFile = Join-Path $ads 'allowed.bin'
    [IO.File]::WriteAllText($adsFile, 'primary', [Text.Encoding]::ASCII)
    [IO.File]::WriteAllText($adsFile + ':aida-policy', 'named', [Text.Encoding]::ASCII)
    Invoke-PolicyCase -Root $ads -Marker 'AIDA_C03_PACKAGE_POLICY_NAMED_STREAM_FORBIDDEN'

    $fileLimit = New-CaseRoot 'file-limit'
    [IO.File]::WriteAllText((Join-Path $fileLimit 'one.bin'), '1')
    [IO.File]::WriteAllText((Join-Path $fileLimit 'two.bin'), '2')
    Invoke-PolicyCase -Root $fileLimit -Marker 'AIDA_C03_PACKAGE_POLICY_RESOURCE_FILE_LIMIT' -Limits @('-FixtureMaximumFiles', '1')
    Invoke-PolicyCase -Root $fileLimit -Marker 'AIDA_C03_PACKAGE_POLICY_RESOURCE_ENTRY_LIMIT' -Limits @('-FixtureMaximumEntries', '1')
    $directoryLimit = New-CaseRoot 'directory-limit'
    [IO.Directory]::CreateDirectory((Join-Path $directoryLimit 'one')) | Out-Null
    Invoke-PolicyCase -Root $directoryLimit -Marker 'AIDA_C03_PACKAGE_POLICY_RESOURCE_DIRECTORY_LIMIT' -Limits @('-FixtureMaximumDirectories', '1')
    $depthLimit = New-CaseRoot 'depth-limit'
    [IO.Directory]::CreateDirectory((Join-Path $depthLimit 'one/two')) | Out-Null
    Invoke-PolicyCase -Root $depthLimit -Marker 'AIDA_C03_PACKAGE_POLICY_RESOURCE_DEPTH_LIMIT' -Limits @('-FixtureMaximumDepth', '1')
    $byteLimit = New-CaseRoot 'byte-limit'
    [IO.File]::WriteAllBytes((Join-Path $byteLimit 'large.bin'), [byte[]](1, 2))
    Invoke-PolicyCase -Root $byteLimit -Marker 'AIDA_C03_PACKAGE_POLICY_RESOURCE_PATH_BUFFER_LIMIT' -Limits @('-FixtureMaximumInventoryPathBytes', '1')
    Invoke-PolicyCase -Root $byteLimit -Marker 'AIDA_C03_PACKAGE_POLICY_RESOURCE_FILE_BYTES_LIMIT' -Limits @('-FixtureMaximumEntryBytes', '1')
    Invoke-PolicyCase -Root $byteLimit -Marker 'AIDA_C03_PACKAGE_POLICY_RESOURCE_TOTAL_BYTES_LIMIT' -Limits @('-FixtureMaximumAggregateBytes', '1')

    $reparseTarget = New-CaseRoot 'reparse-target'
    [IO.File]::WriteAllText((Join-Path $reparseTarget 'target.bin'), 'target')
    $reparseRoot = New-CaseRoot 'reparse-root'
    $junction = Join-Path $reparseRoot 'junction'
    New-Item -ItemType Junction -Path $junction -Target $reparseTarget -ErrorAction Stop | Out-Null
    Invoke-PolicyCase -Root $reparseRoot -Marker 'AIDA_C03_PACKAGE_POLICY_REPARSE_POINT'
    Remove-Item -LiteralPath $junction -Force
    $symlink = Join-Path $reparseRoot 'symlink'
    New-Item -ItemType SymbolicLink -Path $symlink -Target $reparseTarget -ErrorAction Stop | Out-Null
    Invoke-PolicyCase -Root $reparseRoot -Marker 'AIDA_C03_PACKAGE_POLICY_REPARSE_POINT'
    Remove-Item -LiteralPath $symlink -Force

    $source = New-CaseRoot 'developer-source'
    [IO.Directory]::CreateDirectory((Join-Path $source 'resources')) | Out-Null
    [IO.File]::WriteAllText((Join-Path $source 'AiDAStandalone.exe'), 'protected-fixture')
    [IO.File]::WriteAllText((Join-Path $source 'resources/runtime.bin'), 'runtime-fixture')
    $applicationAnchor = New-CaseRoot 'application-anchor'
    $anchor = New-CaseRoot 'customer-anchor'
    $destination = Join-Path $anchor 'Release'
    $stageReport = Join-Path $script:ReportRoot 'stage.json'
    $stageArguments = @('-NoLogo', '-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass',
        '-File', (Convert-ArgumentPath $Producer), '-PackageRoot', (Convert-ArgumentPath $destination),
        '-Spec', (Convert-ArgumentPath $StageSpec), '-SourceRoot', (Convert-ArgumentPath $source),
        '-ApplicationStageAnchor', (Convert-ArgumentPath $applicationAnchor),
        '-CustomerStageAnchor', (Convert-ArgumentPath $anchor), '-StageCustomerPackage',
        '-StagePolicyFixture', '-PolicyFixtureReport', (Convert-ArgumentPath $stageReport), '-Force')
    Invoke-Child -Executable $PowerShellExecutable -Arguments $stageArguments -ExpectedExit 0 -ExpectedMarker 'aida.c03.package-policy-fixture.v1' | Out-Null
    $generationPointer = $stageReport + '.generation-pointer.json'
    $firstGeneration = Read-CompleteGeneration -PointerPath $generationPointer
    Invoke-Child -Executable $ProductionVerifier -Arguments @(
        'inspect-generation', '--generation-pointer', (Convert-ArgumentPath $generationPointer),
        '--customer-stage-anchor', (Convert-ArgumentPath $anchor),
        '--evidence-root', (Convert-ArgumentPath $script:ReportRoot),
        '--stage-owner-root', (Convert-ArgumentPath $script:WorkRoot),
        '--deadline-ms', '120000') -ExpectedExit 0 -ExpectedMarker '"generation_verified":true' | Out-Null
    Invoke-Child -Executable $ProductionVerifier -Arguments @(
        'inspect-generation', '--generation-pointer', (Convert-ArgumentPath $generationPointer),
        '--customer-stage-anchor', (Convert-ArgumentPath $applicationAnchor),
        '--evidence-root', (Convert-ArgumentPath $script:ReportRoot),
        '--stage-owner-root', (Convert-ArgumentPath $script:WorkRoot),
        '--deadline-ms', '120000') -ExpectedExit 1 `
        -ExpectedMarker 'complete generation pointer paths are invalid' | Out-Null
    $pointerHardlink = Join-Path $script:ReportRoot 'pointer-hardlink.json'
    New-Item -ItemType HardLink -Path $pointerHardlink -Target $generationPointer `
        -ErrorAction Stop | Out-Null
    Invoke-Child -Executable $ProductionVerifier -Arguments @(
        'inspect-generation', '--generation-pointer', (Convert-ArgumentPath $generationPointer),
        '--customer-stage-anchor', (Convert-ArgumentPath $anchor),
        '--evidence-root', (Convert-ArgumentPath $script:ReportRoot),
        '--stage-owner-root', (Convert-ArgumentPath $script:WorkRoot),
        '--deadline-ms', '120000') -ExpectedExit 1 `
        -ExpectedMarker 'required file identity is invalid' | Out-Null
    Remove-Item -LiteralPath $pointerHardlink -Force

    foreach ($identityPath in @($firstGeneration.manifest_path, $firstGeneration.digest_path)) {
        $identityHardlink = Join-Path $script:ReportRoot (
            'generation-identity-hardlink-' + [Guid]::NewGuid().ToString('N'))
        New-Item -ItemType HardLink -Path $identityHardlink -Target $identityPath `
            -ErrorAction Stop | Out-Null
        Invoke-Child -Executable $ProductionVerifier -Arguments @(
            'inspect-generation', '--generation-pointer', (Convert-ArgumentPath $generationPointer),
            '--customer-stage-anchor', (Convert-ArgumentPath $anchor),
            '--evidence-root', (Convert-ArgumentPath $script:ReportRoot),
            '--stage-owner-root', (Convert-ArgumentPath $script:WorkRoot),
            '--deadline-ms', '120000') -ExpectedExit 1 `
            -ExpectedMarker 'required file identity is invalid' | Out-Null
        Remove-Item -LiteralPath $identityHardlink -Force
    }

    foreach ($anchorCase in @(
        @('customer-anchor-reparse', $anchor, 'customer'),
        @('evidence-root-reparse', $script:ReportRoot, 'evidence'),
        @('stage-owner-reparse', $script:WorkRoot, 'owner')
    )) {
        $authorityReparse = Join-Path $script:WorkRoot ([string]$anchorCase[0])
        New-Item -ItemType Junction -Path $authorityReparse -Target ([string]$anchorCase[1]) `
            -ErrorAction Stop | Out-Null
        $customerArgument = if ([string]$anchorCase[2] -ceq 'customer') {
            $authorityReparse
        } else { $anchor }
        $evidenceArgument = if ([string]$anchorCase[2] -ceq 'evidence') {
            $authorityReparse
        } else { $script:ReportRoot }
        $ownerArgument = if ([string]$anchorCase[2] -ceq 'owner') {
            $authorityReparse
        } else { $script:WorkRoot }
        Invoke-Child -Executable $ProductionVerifier -Arguments @(
            'inspect-generation', '--generation-pointer', (Convert-ArgumentPath $generationPointer),
            '--customer-stage-anchor', (Convert-ArgumentPath $customerArgument),
            '--evidence-root', (Convert-ArgumentPath $evidenceArgument),
            '--stage-owner-root', (Convert-ArgumentPath $ownerArgument),
            '--deadline-ms', '120000') -ExpectedExit 1 `
            -ExpectedMarker 'path component identity is invalid' | Out-Null
        Remove-Item -LiteralPath $authorityReparse -Force
    }
    Require ([IO.File]::Exists((Join-Path $source 'AiDAStandalone.exe')) -and
        [IO.File]::Exists((Join-Path $firstGeneration.package_root 'AiDAStandalone.exe')) -and
        [IO.File]::Exists((Join-Path $firstGeneration.package_root 'resources/runtime.bin'))) 'copy-only customer stage lost source or destination artifacts'
    [IO.File]::WriteAllText((Join-Path $source 'stale.bin'), 'stale')
    Invoke-Child -Executable $PowerShellExecutable -Arguments $stageArguments -ExpectedExit 0 -ExpectedMarker 'aida.c03.package-policy-fixture.v1' | Out-Null
    $secondGeneration = Read-CompleteGeneration -PointerPath $generationPointer
    Require ($secondGeneration.id -cne $firstGeneration.id -and
        -not [IO.File]::Exists((Join-Path $secondGeneration.package_root 'stale.bin')) -and
        [IO.File]::Exists((Join-Path $source 'AiDAStandalone.exe')) -and
        [IO.File]::Exists((Join-Path $source 'stale.bin')) -and
        $secondGeneration.manifest_sha256 -ceq $firstGeneration.manifest_sha256) `
        'customer restage atomicity or repeatability violated the detached source boundary'
    $stableGeneration = $secondGeneration
    $invalidStageSpec = Join-Path $script:ReportRoot 'invalid-stage-spec.json'
    [IO.File]::WriteAllText($invalidStageSpec,
        '{"schema":"aida.c03.package-policy-stage-fixture.v1","artifacts":[{"relative_path":"missing.bin"}],"inventory_sources":[]}',
        [Text.UTF8Encoding]::new($false))
    $invalidStageArguments = @('-NoLogo', '-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass',
        '-File', (Convert-ArgumentPath $Producer), '-PackageRoot', (Convert-ArgumentPath $destination),
        '-Spec', (Convert-ArgumentPath $invalidStageSpec), '-SourceRoot', (Convert-ArgumentPath $source),
        '-ApplicationStageAnchor', (Convert-ArgumentPath $applicationAnchor),
        '-CustomerStageAnchor', (Convert-ArgumentPath $anchor), '-StageCustomerPackage',
        '-StagePolicyFixture', '-PolicyFixtureReport', (Convert-ArgumentPath $stageReport), '-Force')
    Invoke-Child -Executable $PowerShellExecutable -Arguments $invalidStageArguments -ExpectedExit 1 -ExpectedMarker 'AIDA_C03_PACKAGE_POLICY_CANONICAL_PATH_OPEN' | Out-Null
    $afterInvalid = Read-CompleteGeneration -PointerPath $generationPointer
    Require ($afterInvalid.id -ceq $stableGeneration.id -and
        $afterInvalid.pointer_sha256 -ceq $stableGeneration.pointer_sha256 -and
        [IO.File]::Exists((Join-Path $afterInvalid.package_root 'AiDAStandalone.exe')) -and
        [IO.File]::Exists((Join-Path $afterInvalid.package_root 'resources/runtime.bin'))) `
        'failed stage prevalidation changed the prior complete generation'

    foreach ($checkpoint in @('prepared', 'package-ready', 'evidence-ready', 'before-commit')) {
        $failingArguments = $stageArguments + @('-FixturePublicationFailure', $checkpoint)
        Invoke-Child -Executable $PowerShellExecutable -Arguments $failingArguments -ExpectedExit 1 `
            -ExpectedMarker ('AIDA_C03_PACKAGE_POLICY_FIXTURE_PUBLICATION_FAILURE|' + $checkpoint) | Out-Null
        $afterFailure = Read-CompleteGeneration -PointerPath $generationPointer
        Require ($afterFailure.id -ceq $stableGeneration.id -and
            $afterFailure.pointer_sha256 -ceq $stableGeneration.pointer_sha256) `
            ('pre-commit failure exposed an incomplete generation: ' + $checkpoint)
    }
    $postCommitArguments = $stageArguments + @('-FixturePublicationFailure', 'after-commit')
    Invoke-Child -Executable $PowerShellExecutable -Arguments $postCommitArguments -ExpectedExit 1 `
        -ExpectedMarker 'AIDA_C03_PACKAGE_POLICY_FIXTURE_PUBLICATION_FAILURE|after-commit' | Out-Null
    $postCommitGeneration = Read-CompleteGeneration -PointerPath $generationPointer
    Require ($postCommitGeneration.id -cne $stableGeneration.id -and
        $postCommitGeneration.manifest_sha256 -ceq $stableGeneration.manifest_sha256) `
        'post-commit failure did not retain one complete new generation'

    $stableGeneration = $postCommitGeneration
    foreach ($checkpoint in @('prepared', 'package-ready', 'evidence-ready', 'before-commit', 'after-commit')) {
        $terminatedArguments = $stageArguments + @('-FixturePublicationTermination', $checkpoint)
        Invoke-TerminatedChild -Executable $PowerShellExecutable -Arguments $terminatedArguments
        Invoke-Child -Executable $PowerShellExecutable -Arguments $stageArguments -ExpectedExit 0 `
            -ExpectedMarker 'aida.c03.package-policy-fixture.v1' | Out-Null
        $recoveredGeneration = Read-CompleteGeneration -PointerPath $generationPointer
        Require ($recoveredGeneration.manifest_sha256 -ceq $stableGeneration.manifest_sha256) `
            ('restart recovery changed manifest identity after ' + $checkpoint)
        $packageGenerations = @([IO.Directory]::EnumerateDirectories(
            $anchor, '.aida-c03-generation-*', [IO.SearchOption]::TopDirectoryOnly))
        $evidenceGenerations = @([IO.Directory]::EnumerateDirectories(
            $script:ReportRoot, '.aida-c03-generation-*', [IO.SearchOption]::TopDirectoryOnly))
        Require ($packageGenerations.Count -eq 1 -and $evidenceGenerations.Count -eq 1 -and
            -not [IO.File]::Exists((Join-Path $script:ReportRoot '.aida-c03-publication-journal.json'))) `
            ('restart recovery retained an owned orphan generation after ' + $checkpoint)
        $stableGeneration = $recoveredGeneration
    }

    $concurrentCapture = Join-Path $script:WorkRoot 'concurrent-publication'
    [IO.Directory]::CreateDirectory($concurrentCapture) | Out-Null
    $concurrentStdout = Join-Path $concurrentCapture 'stdout.txt'
    $concurrentStderr = Join-Path $concurrentCapture 'stderr.txt'
    $concurrentProcess = Start-Process -FilePath $PowerShellExecutable -ArgumentList $stageArguments `
        -PassThru -WindowStyle Hidden -RedirectStandardOutput $concurrentStdout `
        -RedirectStandardError $concurrentStderr
    $readerGenerations = [Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
    $readerGenerations.Add($stableGeneration.id) | Out-Null
    while (-not $concurrentProcess.HasExited) {
        $observedGeneration = Read-CompleteGeneration -PointerPath $generationPointer
        $readerGenerations.Add($observedGeneration.id) | Out-Null
        Start-Sleep -Milliseconds 1
    }
    $concurrentProcess.WaitForExit()
    $concurrentOutput = (Read-BoundedText -Path $concurrentStdout) +
        (Read-BoundedText -Path $concurrentStderr)
    Require ($concurrentProcess.ExitCode -eq 0 -and
        $concurrentOutput.IndexOf('aida.c03.package-policy-fixture.v1',
            [StringComparison]::Ordinal) -ge 0) 'concurrent publication failed'
    $concurrentFinal = Read-CompleteGeneration -PointerPath $generationPointer
    $readerGenerations.Add($concurrentFinal.id) | Out-Null
    Require ($readerGenerations.Count -le 2 -and
        $concurrentFinal.id -cne $stableGeneration.id -and
        $concurrentFinal.manifest_sha256 -ceq $stableGeneration.manifest_sha256) `
        'concurrent readers observed a torn or mixed generation'

    $signingFixtureRoot = New-CaseRoot 'signing-authority-point-of-use'
    $signingArtifact = Join-Path $signingFixtureRoot 'artifact.exe'
    $signingProvider = Join-Path $signingFixtureRoot 'fixture-signing-provider.exe'
    $signerPolicy = Join-Path $signingFixtureRoot 'signer-policy.json'
    [IO.File]::WriteAllBytes($signingArtifact, [byte[]](0x4d, 0x5a, 1, 2, 3, 4))
    [IO.File]::Copy($ProductionVerifier, $signingProvider, $false)
    $signingProviderHash = (Get-FileHash -Algorithm SHA256 -LiteralPath $signingProvider).Hash.ToLowerInvariant()
    $policyValue = [ordered]@{
        schema = 'aida.c03.authorized-signer-policy'
        schema_version = 1
        require_trusted_timestamp = $true
        authorized_signer_thumbprints_sha256 = @([string]::new([char]'4', 64))
        signing_provider_sha256 = $signingProviderHash
    }
    $policyText = ($policyValue | ConvertTo-Json -Compress) + "`n"
    [IO.File]::WriteAllText($signerPolicy, $policyText, [Text.UTF8Encoding]::new($false))
    $signerPolicyHash = (Get-FileHash -Algorithm SHA256 -LiteralPath $signerPolicy).Hash.ToLowerInvariant()
    $newSigningArguments = {
        param([string]$PolicyPath, [string]$ExpectedPolicy,
            [string]$ProviderPath, [string]$ExpectedProvider)
        return @('run-signing-provider', '--artifact', (Convert-ArgumentPath $signingArtifact),
            '--signer-policy', (Convert-ArgumentPath $PolicyPath),
            '--expected-signer-policy-sha256', $ExpectedPolicy,
            '--signing-provider', (Convert-ArgumentPath $ProviderPath),
            '--expected-signing-provider-sha256', $ExpectedProvider,
            '--deadline-ms', '120000')
    }
    Invoke-Child -Executable $ProductionVerifier -Arguments (
        & $newSigningArguments $signerPolicy $signerPolicyHash $signingProvider $signingProviderHash) `
        -ExpectedExit 1 -ExpectedMarker 'immutable signing provider returned failure' | Out-Null
    Invoke-Child -Executable $ProductionVerifier -Arguments (
        & $newSigningArguments $signerPolicy ([string]::new([char]'0', 64)) `
            $signingProvider $signingProviderHash) -ExpectedExit 1 `
        -ExpectedMarker 'signing authority point-of-use identity mismatch' | Out-Null
    Invoke-Child -Executable $ProductionVerifier -Arguments (
        & $newSigningArguments $signerPolicy $signerPolicyHash `
            $signingProvider ([string]::new([char]'0', 64))) -ExpectedExit 1 `
        -ExpectedMarker 'signing authority point-of-use identity mismatch' | Out-Null
    [IO.File]::WriteAllText($signerPolicy, $policyText + ' ', [Text.UTF8Encoding]::new($false))
    Invoke-Child -Executable $ProductionVerifier -Arguments (
        & $newSigningArguments $signerPolicy $signerPolicyHash $signingProvider $signingProviderHash) `
        -ExpectedExit 1 -ExpectedMarker 'signing authority point-of-use identity mismatch' | Out-Null
    [IO.File]::WriteAllText($signerPolicy, $policyText, [Text.UTF8Encoding]::new($false))

    $providerHardlink = Join-Path $signingFixtureRoot 'provider-hardlink.exe'
    New-Item -ItemType HardLink -Path $providerHardlink -Target $signingProvider `
        -ErrorAction Stop | Out-Null
    Invoke-Child -Executable $ProductionVerifier -Arguments (
        & $newSigningArguments $signerPolicy $signerPolicyHash $signingProvider $signingProviderHash) `
        -ExpectedExit 1 -ExpectedMarker 'required file identity is invalid' | Out-Null
    Remove-Item -LiteralPath $providerHardlink -Force

    $policyHardlink = Join-Path $signingFixtureRoot 'policy-hardlink.json'
    New-Item -ItemType HardLink -Path $policyHardlink -Target $signerPolicy `
        -ErrorAction Stop | Out-Null
    Invoke-Child -Executable $ProductionVerifier -Arguments (
        & $newSigningArguments $signerPolicy $signerPolicyHash $signingProvider $signingProviderHash) `
        -ExpectedExit 1 -ExpectedMarker 'required file identity is invalid' | Out-Null
    Remove-Item -LiteralPath $policyHardlink -Force

    $providerReparse = Join-Path $signingFixtureRoot 'provider-reparse.exe'
    New-Item -ItemType SymbolicLink -Path $providerReparse -Target $signingProvider `
        -ErrorAction Stop | Out-Null
    Invoke-Child -Executable $ProductionVerifier -Arguments (
        & $newSigningArguments $signerPolicy $signerPolicyHash $providerReparse $signingProviderHash) `
        -ExpectedExit 1 -ExpectedMarker 'required file identity is invalid' | Out-Null
    Remove-Item -LiteralPath $providerReparse -Force

    $policyReparse = Join-Path $signingFixtureRoot 'policy-reparse.json'
    New-Item -ItemType SymbolicLink -Path $policyReparse -Target $signerPolicy `
        -ErrorAction Stop | Out-Null
    Invoke-Child -Executable $ProductionVerifier -Arguments (
        & $newSigningArguments $policyReparse $signerPolicyHash $signingProvider $signingProviderHash) `
        -ExpectedExit 1 -ExpectedMarker 'required file identity is invalid' | Out-Null
    Remove-Item -LiteralPath $policyReparse -Force

    $missingSignerPolicy = Join-Path $script:WorkRoot 'external-authority-not-provisioned/signer-policy.json'
    $missingSigningProvider = Join-Path $script:WorkRoot 'external-authority-not-provisioned/signing-provider.exe'
    $productionArguments = @('verify-package',
        '--generation-pointer', (Convert-ArgumentPath $generationPointer),
        '--customer-stage-anchor', (Convert-ArgumentPath $anchor),
        '--evidence-root', (Convert-ArgumentPath $script:ReportRoot),
        '--stage-owner-root', (Convert-ArgumentPath $script:WorkRoot),
        '--authority-lock', (Convert-ArgumentPath $AuthorityLock),
        '--protector-tool', (Convert-ArgumentPath $ProtectorTool),
        '--protector-verifier', (Convert-ArgumentPath $ProtectorVerifier),
        '--signature-verifier', (Convert-ArgumentPath $ProductionVerifier),
        '--signer-policy', (Convert-ArgumentPath $missingSignerPolicy),
        '--expected-signer-policy-sha256', ([string]::new([char]'5', 64)),
        '--signing-provider', (Convert-ArgumentPath $missingSigningProvider),
        '--expected-signing-provider-sha256', ([string]::new([char]'6', 64)),
        '--deadline-ms', '120000')
    Invoke-Child -Executable $ProductionVerifier -Arguments $productionArguments -ExpectedExit 1 `
        -ExpectedMarker 'unable to lock required file' | Out-Null
} finally {
    foreach ($reparsePath in @($symlink, $junction)) {
        if ($reparsePath -and ([IO.Directory]::Exists($reparsePath) -or [IO.File]::Exists($reparsePath))) {
            Remove-Item -LiteralPath $reparsePath -Force -ErrorAction Stop
        }
    }
    if ([IO.Directory]::Exists($script:WorkRoot)) {
        Remove-Item -LiteralPath $script:WorkRoot -Recurse -Force
    }
}

[Console]::Out.WriteLine('aida.c03.package-distribution-policy.v1')
