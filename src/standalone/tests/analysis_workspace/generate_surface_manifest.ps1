param(
    [string]$RepositoryRoot = "",
    [string]$OutputPath = "",
    [string]$BaselinePath = ""
)

$ErrorActionPreference = "Stop"
if ([string]::IsNullOrWhiteSpace($RepositoryRoot)) {
    $RepositoryRoot = (Resolve-Path (Join-Path $PSScriptRoot "..\..\..\..")).Path
}
$RepositoryRoot = (Resolve-Path $RepositoryRoot).Path
if ([string]::IsNullOrWhiteSpace($OutputPath)) {
    $OutputPath = Join-Path $PSScriptRoot "standalone_surface_final.json"
}
if ([string]::IsNullOrWhiteSpace($BaselinePath)) {
    $BaselinePath = Join-Path $PSScriptRoot "standalone_surface_baseline.json"
}
$OutputPath = [IO.Path]::GetFullPath($OutputPath)
$BaselinePath = [IO.Path]::GetFullPath($BaselinePath)

function Get-Text([string]$Path) {
    return [IO.File]::ReadAllText($Path, [Text.UTF8Encoding]::new($false, $true))
}

function Get-FileSha256([string]$Path) {
    $algorithm = [Security.Cryptography.SHA256]::Create()
    try {
        return (-join ($algorithm.ComputeHash([IO.File]::ReadAllBytes($Path)) |
            ForEach-Object { $_.ToString('x2') })).ToUpperInvariant()
    } finally {
        $algorithm.Dispose()
    }
}

function Get-StringListSha256([string[]]$Values) {
    $unique = [Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
    foreach ($value in $Values) { [void]$unique.Add($value) }
    [string[]]$canonicalValues = @($unique)
    [Array]::Sort($canonicalValues, [StringComparer]::Ordinal)
    $canonical = ($canonicalValues -join "`n")
    $algorithm = [Security.Cryptography.SHA256]::Create()
    try {
        return (-join ($algorithm.ComputeHash([Text.Encoding]::UTF8.GetBytes($canonical)) |
            ForEach-Object { $_.ToString('x2') })).ToUpperInvariant()
    } finally {
        $algorithm.Dispose()
    }
}

function Get-OrderedStringListSha256([string[]]$Values) {
    $canonical = ($Values -join "`n")
    $algorithm = [Security.Cryptography.SHA256]::Create()
    try {
        return (-join ($algorithm.ComputeHash([Text.Encoding]::UTF8.GetBytes($canonical)) |
            ForEach-Object { $_.ToString('x2') })).ToUpperInvariant()
    } finally {
        $algorithm.Dispose()
    }
}

function Read-JsonObject([string]$Path, [string]$Contract) {
    try {
        $value = (Get-Text $Path) | ConvertFrom-Json
    } catch {
        throw "$Contract is invalid JSON: $($_.Exception.Message)"
    }
    if ($null -eq $value -or $value -is [Array]) {
        throw "$Contract root must be an object"
    }
    return $value
}

function Convert-CanonicalJson([object]$Value) {
    return ConvertTo-Json -InputObject $Value -Depth 64 -Compress
}

function Get-Relative([string]$Path) {
    $root = $RepositoryRoot.TrimEnd('\') + '\'
    if (!$Path.StartsWith($root, [StringComparison]::OrdinalIgnoreCase)) {
        throw "Path is outside repository root: $Path"
    }
    return $Path.Substring($root.Length).Replace('\', '/')
}

function Get-LineNumber([string]$Text, [int]$Index) {
    if ($Index -le 0) { return 1 }
    return 1 + ([regex]::Matches($Text.Substring(0, $Index), "`n").Count)
}

function Get-MatchingIndex([string]$Text, [int]$Start, [char]$Open, [char]$Close) {
    if ($Start -lt 0 -or $Start -ge $Text.Length -or $Text[$Start] -ne $Open) {
        throw "Invalid balanced-range start"
    }
    $depth = 0
    $quote = [char]0
    $escape = $false
    $lineComment = $false
    $blockComment = $false
    for ($index = $Start; $index -lt $Text.Length; ++$index) {
        $character = $Text[$index]
        $next = if ($index + 1 -lt $Text.Length) { $Text[$index + 1] } else { [char]0 }
        if ($lineComment) {
            if ($character -eq "`n") { $lineComment = $false }
            continue
        }
        if ($blockComment) {
            if ($character -eq '*' -and $next -eq '/') { $blockComment = $false; ++$index }
            continue
        }
        if ($quote -ne [char]0) {
            if ($escape) { $escape = $false; continue }
            if ($character -eq '\') { $escape = $true; continue }
            if ($character -eq $quote) { $quote = [char]0 }
            continue
        }
        if ($character -eq '/' -and $next -eq '/') { $lineComment = $true; ++$index; continue }
        if ($character -eq '/' -and $next -eq '*') { $blockComment = $true; ++$index; continue }
        if ($character -eq [char]39 -and (Test-CppDigitSeparator $Text $index)) { continue }
        if ($character -eq '"' -or $character -eq "'") { $quote = $character; continue }
        if ($character -eq $Open) { ++$depth; continue }
        if ($character -eq $Close) {
            --$depth
            if ($depth -eq 0) { return $index }
        }
    }
    throw "Unterminated balanced range at offset $Start"
}

function Test-CppDigitSeparator([string]$Source, [int]$Index) {
    if ($Index -le 0 -or $Index + 1 -ge $Source.Length -or $Source[$Index] -ne "'") {
        return $false
    }
    $start = $Index - 1
    while ($start -ge 0 -and ([string]$Source[$start]) -match "[A-Za-z0-9_'.]") {
        --$start
    }
    $prefix = $Source.Substring($start + 1, $Index - $start - 1)
    $previous = [string]$Source[$Index - 1]
    $next = [string]$Source[$Index + 1]
    if ($prefix -match "^0[xX][0-9A-Fa-f.pP']*$") {
        return $previous -match '[0-9A-Fa-f]' -and $next -match '[0-9A-Fa-f]'
    }
    if ($prefix -match "^0[bB][01']*$") {
        return $previous -match '[01]' -and $next -match '[01]'
    }
    return $prefix -match "^[0-9][0-9.eE']*$" -and
        $previous -match '[0-9]' -and $next -match '[0-9]'
}

function Get-CppMaskErrorContext([string]$Source, [int]$Index, [string]$Label) {
    $bounded = [Math]::Max(0, [Math]::Min($Index, $Source.Length))
    $byteOffset = [Text.Encoding]::UTF8.GetByteCount($Source.Substring(0, $bounded))
    return "source='$Label' line=$(Get-LineNumber $Source $bounded) character_offset=$bounded byte_offset=$byteOffset"
}

function Get-CppCodeMask([string]$Source, [string]$Label = '<memory>') {
    $mask = $Source.ToCharArray()
    $length = $Source.Length
    $index = 0
    while ($index -lt $length) {
        $current = $Source[$index]
        $next = if ($index + 1 -lt $length) { $Source[$index + 1] } else { [char]0 }
        if ($current -eq '/' -and $next -eq '/') {
            while ($index -lt $length -and $Source[$index] -ne "`r" -and $Source[$index] -ne "`n") {
                $mask[$index] = ' '
                ++$index
            }
            continue
        }
        if ($current -eq '/' -and $next -eq '*') {
            $commentStart = $index
            $mask[$index] = ' '
            $mask[$index + 1] = ' '
            $index += 2
            $closed = $false
            while ($index -lt $length) {
                if ($index + 1 -lt $length -and $Source[$index] -eq '*' -and
                    $Source[$index + 1] -eq '/') {
                    $mask[$index] = ' '
                    $mask[$index + 1] = ' '
                    $index += 2
                    $closed = $true
                    break
                }
                if ($Source[$index] -ne "`r" -and $Source[$index] -ne "`n") {
                    $mask[$index] = ' '
                }
                ++$index
            }
            if (!$closed) {
                throw "Unterminated C++ block comment $(Get-CppMaskErrorContext $Source $commentStart $Label)"
            }
            continue
        }
        if ($current -eq 'R' -and $next -eq '"') {
            $rawStart = $index
            $delimiterStart = $index + 2
            $opening = $Source.IndexOf('(', $delimiterStart)
            if ($opening -ge $delimiterStart -and $opening - $delimiterStart -le 16) {
                $delimiter = $Source.Substring($delimiterStart, $opening - $delimiterStart)
                if ($delimiter -notmatch '[\s\\()]') {
                    $terminator = ')' + $delimiter + '"'
                    $closing = $Source.IndexOf($terminator, $opening + 1,
                        [StringComparison]::Ordinal)
                    if ($closing -lt 0) {
                        throw "Unterminated C++ raw string literal $(Get-CppMaskErrorContext $Source $rawStart $Label)"
                    }
                    $end = $closing + $terminator.Length
                    while ($index -lt $end) {
                        if ($Source[$index] -ne "`r" -and $Source[$index] -ne "`n") {
                            $mask[$index] = ' '
                        }
                        ++$index
                    }
                    continue
                }
            }
        }
        if ($current -eq [char]39 -and (Test-CppDigitSeparator $Source $index)) {
            $mask[$index] = ' '
            ++$index
            continue
        }
        if ($current -eq [char]34 -or $current -eq [char]39) {
            $literalStart = $index
            $quote = $current
            $mask[$index] = ' '
            ++$index
            $closed = $false
            while ($index -lt $length) {
                $literal = $Source[$index]
                if ($literal -eq '\') {
                    $mask[$index] = ' '
                    ++$index
                    if ($index -lt $length) {
                        if ($Source[$index] -ne "`r" -and $Source[$index] -ne "`n") {
                            $mask[$index] = ' '
                        }
                        ++$index
                    }
                    continue
                }
                if ($literal -ne "`r" -and $literal -ne "`n") { $mask[$index] = ' ' }
                ++$index
                if ($literal -eq $quote) {
                    $closed = $true
                    break
                }
            }
            if (!$closed) {
                throw "Unterminated C++ quoted literal $(Get-CppMaskErrorContext $Source $literalStart $Label)"
            }
            continue
        }
        ++$index
    }
    return -join $mask
}

function Get-CppNamespaceRanges([string]$Source, [string]$Mask) {
    $ranges = [Collections.Generic.List[object]]::new()
    $matches = [regex]::Matches($Mask,
        '\bnamespace\s*(?<name>[A-Za-z_]\w*(?:::[A-Za-z_]\w*)*)?\s*\{')
    foreach ($match in $matches) {
        $open = $Mask.IndexOf('{', $match.Index)
        if ($open -lt 0) { continue }
        $close = Get-MatchingIndex $Mask $open '{' '}'
        $name = [string]$match.Groups['name'].Value
        if ([string]::IsNullOrWhiteSpace($name)) {
            $name = '<anonymous@' + (Get-LineNumber $Source $match.Index) + '>'
        }
        $ranges.Add([ordered]@{ name = $name; open = $open; close = $close })
    }
    return $ranges.ToArray()
}

function Get-CppNamespaceAt([object[]]$Ranges, [int]$Index) {
    $names = @($Ranges | Where-Object { $Index -gt $_.open -and $Index -lt $_.close } |
        Sort-Object { [int]$_['open'] } | ForEach-Object { [string]$_['name'] })
    return ($names -join '::')
}

function Test-CppParameterHasTopLevelDefault([string]$Parameter, [string]$Label) {
    $mask = Get-CppCodeMask $Parameter $Label
    $round = 0
    $curly = 0
    $square = 0
    for ($index = 0; $index -lt $mask.Length; ++$index) {
        $character = $mask[$index]
        switch ($character) {
            '(' { ++$round; continue }
            ')' { --$round; if ($round -lt 0) { throw "$Label has unbalanced parentheses" }; continue }
            '{' { ++$curly; continue }
            '}' { --$curly; if ($curly -lt 0) { throw "$Label has unbalanced braces" }; continue }
            '[' { ++$square; continue }
            ']' { --$square; if ($square -lt 0) { throw "$Label has unbalanced brackets" }; continue }
        }
        if ($character -ne '=' -or $round -ne 0 -or $curly -ne 0 -or $square -ne 0) {
            continue
        }
        $previous = if ($index -gt 0) { $mask[$index - 1] } else { [char]0 }
        $next = if ($index + 1 -lt $mask.Length) { $mask[$index + 1] } else { [char]0 }
        if ($previous -in @('=', '!', '<', '>', '+', '-', '*', '/', '%', '&', '|', '^') -or
            $next -eq '=') { continue }
        return $true
    }
    if ($round -ne 0 -or $curly -ne 0 -or $square -ne 0) {
        throw "$Label has unbalanced delimiters"
    }
    return $false
}

function Get-CppRegistrarDefinitions([string]$Path, [string]$Source, [string]$Mask,
                                     [bool]$RequireServerParameter = $true) {
    $relative = Get-Relative $Path
    $namespaces = @(Get-CppNamespaceRanges $Source $Mask)
    $definitions = [Collections.Generic.List[object]]::new()
    $matches = [regex]::Matches($Mask,
        '(?<![A-Za-z0-9_])(?<name>(?:[A-Za-z_]\w*::)*register_[A-Za-z0-9_]+)\s*\(')
    foreach ($match in $matches) {
        $open = $Mask.IndexOf('(', $match.Index)
        if ($open -lt 0) { continue }
        $close = Get-MatchingIndex $Mask $open '(' ')'
        $parameters = $Source.Substring($open + 1, $close - $open - 1)
        if ($RequireServerParameter -and
            $parameters -notmatch '(?:mcp_standalone::)?server_t\s*&') { continue }
        $cursor = $close + 1
        while ($cursor -lt $Mask.Length -and [char]::IsWhiteSpace($Mask[$cursor])) { ++$cursor }
        if ($cursor + 8 -le $Mask.Length -and $Mask.Substring($cursor, 8) -eq 'noexcept') {
            $cursor += 8
            while ($cursor -lt $Mask.Length -and [char]::IsWhiteSpace($Mask[$cursor])) { ++$cursor }
        }
        if ($cursor -ge $Mask.Length -or $Mask[$cursor] -ne '{') { continue }
        $bodyClose = Get-MatchingIndex $Mask $cursor '{' '}'
        $declaredName = [string]$match.Groups['name'].Value
        $namespace = Get-CppNamespaceAt $namespaces $match.Index
        $symbol = if ([string]::IsNullOrWhiteSpace($namespace)) {
            $declaredName
        } elseif ($declaredName.StartsWith($namespace + '::', [StringComparison]::Ordinal)) {
            $declaredName
        } else {
            $namespace + '::' + $declaredName
        }
        $line = Get-LineNumber $Source $match.Index
        $parameterParts = if ([string]::IsNullOrWhiteSpace($parameters)) {
            @()
        } else {
            @(Split-TopLevel $parameters)
        }
        $parameterCount = $parameterParts.Count
        $requiredParameterCount = 0
        $defaultSeen = $false
        for ($parameterIndex = 0; $parameterIndex -lt $parameterParts.Count; ++$parameterIndex) {
            $parameter = [string]$parameterParts[$parameterIndex]
            if ([string]::IsNullOrWhiteSpace($parameter)) {
                throw "Registrar definition has an empty parameter: $relative`:$line"
            }
            $hasDefault = Test-CppParameterHasTopLevelDefault $parameter `
                "Registrar parameter $relative`:$line index=$parameterIndex"
            if ($hasDefault) {
                $defaultSeen = $true
            } elseif ($defaultSeen) {
                throw "Registrar definition has a non-trailing required parameter: $relative`:$line"
            } else {
                ++$requiredParameterCount
            }
        }
        $definitions.Add([ordered]@{
            id = $relative + ':' + $line + ':' + $symbol
            symbol = $symbol
            bare_name = ($declaredName -split '::')[-1]
            namespace = $namespace
            parameters = ($parameters -replace '\s+', ' ').Trim()
            minimum_parameter_count = $requiredParameterCount
            parameter_count = $parameterCount
            file = $relative
            line = $line
            name_offset = $match.Index
            body_start = $cursor
            body_end = $bodyClose
        })
    }
    return $definitions.ToArray()
}

function Test-CppRegistrarAcceptsArgumentCount([object]$Definition, [int]$ArgumentCount) {
    if (!$Definition.Contains('minimum_parameter_count') -or
        !$Definition.Contains('parameter_count')) {
        throw "Registrar definition lacks arity metadata: $($Definition.id)"
    }
    $minimum = [int]$Definition['minimum_parameter_count']
    $maximum = [int]$Definition['parameter_count']
    if ($minimum -lt 0 -or $maximum -lt $minimum) {
        throw "Registrar definition has invalid arity metadata: $($Definition.id)"
    }
    return $ArgumentCount -ge $minimum -and $ArgumentCount -le $maximum
}

function Test-CppAnonymousNamespaceSegment([string]$Segment) {
    return [regex]::IsMatch($Segment, '^<anonymous@[0-9]+>$',
        [Text.RegularExpressions.RegexOptions]::CultureInvariant)
}

function Test-CppNamespaceContainsAnonymous([string]$Namespace) {
    return [regex]::IsMatch($Namespace, '(?:^|::)<anonymous@[0-9]+>(?:::|$)',
        [Text.RegularExpressions.RegexOptions]::CultureInvariant)
}

function Test-CppDefinitionInjectedAtScope([object]$Definition, [string]$CallerFile,
                                           [string]$Scope) {
    if (![string]::Equals([string]$Definition.file, $CallerFile,
            [StringComparison]::Ordinal)) { return $false }
    $namespace = [string]$Definition.namespace
    if ([string]::IsNullOrWhiteSpace($namespace)) { return $false }
    $segments = [Collections.Generic.List[string]]::new()
    foreach ($segment in @($namespace -split '::')) { $segments.Add($segment) }
    while ($segments.Count -gt 0 -and
           (Test-CppAnonymousNamespaceSegment $segments[$segments.Count - 1])) {
        $segments.RemoveAt($segments.Count - 1)
        if ([string]::Equals(($segments.ToArray() -join '::'), $Scope,
                [StringComparison]::Ordinal)) { return $true }
    }
    return $false
}

function Resolve-CppRegistrarTarget([object]$Caller, [string]$Callee,
                                    [object[]]$Definitions, [int]$ArgumentCount) {
    $qualified = $Callee.Contains('::')
    if ($qualified) {
        $prefixes = [Collections.Generic.List[string]]::new()
        $namespace = [string]$Caller.namespace
        while (![string]::IsNullOrWhiteSpace($namespace)) {
            $prefixes.Add($namespace + '::' + $Callee)
            $separator = $namespace.LastIndexOf('::', [StringComparison]::Ordinal)
            $namespace = if ($separator -ge 0) { $namespace.Substring(0, $separator) } else { '' }
        }
        $prefixes.Add($Callee)
        foreach ($candidateName in $prefixes) {
            $matches = @($Definitions | Where-Object {
                [string]$_.symbol -eq $candidateName -and
                (Test-CppRegistrarAcceptsArgumentCount $_ $ArgumentCount)
            })
            if ($matches.Count -gt 1) {
                throw "Ambiguous registrar definition for '$Callee' from $($Caller.id)"
            }
            if ($matches.Count -eq 1) { return $matches[0] }
        }
    } else {
        $scopes = [Collections.Generic.List[string]]::new()
        $namespace = [string]$Caller.namespace
        while (![string]::IsNullOrWhiteSpace($namespace)) {
            $scopes.Add($namespace)
            $separator = $namespace.LastIndexOf('::', [StringComparison]::Ordinal)
            $namespace = if ($separator -ge 0) { $namespace.Substring(0, $separator) } else { '' }
        }
        $scopes.Add('')
        foreach ($scope in $scopes) {
            $candidateName = if ([string]::IsNullOrWhiteSpace($scope)) {
                $Callee
            } else {
                $scope + '::' + $Callee
            }
            $matches = @($Definitions | Where-Object {
                (Test-CppRegistrarAcceptsArgumentCount $_ $ArgumentCount) -and
                ([string]$_.symbol -eq $candidateName -or
                 (Test-CppDefinitionInjectedAtScope $_ ([string]$Caller.file) $scope)) -and
                [string]$_.bare_name -eq $Callee
            })
            if ($matches.Count -gt 1) {
                $scopeLabel = if ([string]::IsNullOrWhiteSpace($scope)) { '<global>' } else { $scope }
                throw "Ambiguous registrar definition for '$Callee' at scope '$scopeLabel' from $($Caller.id)"
            }
            if ($matches.Count -eq 1) { return $matches[0] }
        }
    }
    $bare = ($Callee -split '::')[-1]
    $fallback = if ($qualified) {
        @($Definitions | Where-Object {
            (([string]$_.symbol).EndsWith('::' + $Callee, [StringComparison]::Ordinal) -or
            [string]$_.symbol -eq $Callee) -and
            (Test-CppRegistrarAcceptsArgumentCount $_ $ArgumentCount)
        })
    } else {
        @($Definitions | Where-Object {
            [string]$_.bare_name -eq $bare -and
            (Test-CppRegistrarAcceptsArgumentCount $_ $ArgumentCount) -and
            !(Test-CppNamespaceContainsAnonymous ([string]$_.namespace))
        })
    }
    if ($fallback.Count -ne 1) {
        throw "Unresolved or ambiguous registrar edge '$Callee' from $($Caller.id) candidates=$($fallback.Count)"
    }
    return $fallback[0]
}

function Test-CppRegistrarDeclaration([string]$Mask, [int]$Start, [int]$Close) {
    $after = $Close + 1
    while ($after -lt $Mask.Length -and [char]::IsWhiteSpace($Mask[$after])) { ++$after }
    if ($after -ge $Mask.Length -or $Mask[$after] -ne ';') { return $false }
    $boundary = $Start - 1
    while ($boundary -ge 0 -and $Mask[$boundary] -notin @(';', '{', '}', "`r", "`n")) {
        --$boundary
    }
    $prefix = $Mask.Substring($boundary + 1, $Start - $boundary - 1).Trim()
    if ([string]::IsNullOrWhiteSpace($prefix)) { return $false }
    if ($prefix -match '^(?:return|co_return|co_await|throw)\b') { return $false }
    $typeToken = '(?:[A-Za-z_]\w*::)*[A-Za-z_]\w*(?:\s*<[^;{}()]*>)?(?:\s*[*&]+)?'
    return $prefix -match ('^(?:(?:extern|static|inline|constexpr|consteval|constinit|' +
        'friend|virtual|explicit|typename|const|volatile)\s+)*(?:' + $typeToken +
        ')(?:\s+' + $typeToken + ')*$')
}

function Get-CppRegistrarTerminalIdentity([string]$File, [string]$Mask, [int]$Offset,
                                          [string]$Label) {
    if ($Offset -lt 0 -or $Offset -ge $Mask.Length) {
        throw "$Label has an invalid source offset: $File`:$Offset"
    }
    $match = [regex]::Match($Mask.Substring($Offset),
        '^(?:\.\s*|->\s*)?(?<callee>(?:[A-Za-z_]\w*::)*(?:register|replace)_[A-Za-z0-9_]+)\s*\(')
    if (!$match.Success) {
        throw "$Label is not anchored to a registrar call: $File`:$Offset"
    }
    $calleeOffset = $Offset + $match.Groups['callee'].Index
    $open = $Mask.IndexOf('(', $calleeOffset)
    if ($open -lt 0) {
        throw "$Label has no registrar argument list: $File`:$Offset"
    }
    [void](Get-MatchingIndex $Mask $open '(' ')')
    return [ordered]@{
        key = $File + ':' + $calleeOffset
        callee = [string]$match.Groups['callee'].Value
        character_offset = $calleeOffset
    }
}

function Get-CppPhysicalRegistrationTerminals([object]$Definition, [string]$Mask) {
    $bodyStart = [int]$Definition.body_start + 1
    $bodyLength = [int]$Definition.body_end - $bodyStart
    if ($bodyLength -le 0) { return @() }
    $terminals = [Collections.Generic.List[object]]::new()
    $bodyMask = $Mask.Substring($bodyStart, $bodyLength)
    foreach ($match in [regex]::Matches($bodyMask,
        '(?:\.|->)\s*(?<callee>(?:register|replace)_tool)\s*\(')) {
        $offset = $bodyStart + $match.Groups['callee'].Index
        $open = $Mask.IndexOf('(', $offset)
        if ($open -lt 0) {
            throw "Physical registration terminal has no argument list: $($Definition.id)"
        }
        [void](Get-MatchingIndex $Mask $open '(' ')')
        $terminals.Add([ordered]@{
            key = ([string]$Definition.file) + ':' + $offset
            callee = [string]$match.Groups['callee'].Value
            character_offset = $offset
            line = Get-LineNumber $Mask $offset
        })
    }
    return $terminals.ToArray()
}

function Get-CppRegistrarCalls([object]$Definition, [string]$Source, [string]$Mask,
                               [object[]]$Definitions,
                               [Collections.Generic.HashSet[string]]$TerminalOffsets,
                               [hashtable]$ExplicitEdges) {
    $calls = [Collections.Generic.List[object]]::new()
    $bodyStart = [int]$Definition.body_start + 1
    $bodyLength = [int]$Definition.body_end - $bodyStart
    if ($bodyLength -le 0) { return @() }
    $bodyMask = $Mask.Substring($bodyStart, $bodyLength)
    $matches = [regex]::Matches($bodyMask,
        '(?<callee>(?:[A-Za-z_]\w*::)*(?:register|replace)_[A-Za-z0-9_]+)\s*\(')
    foreach ($match in $matches) {
        $absolute = $bodyStart + $match.Index
        $callee = [string]$match.Groups['callee'].Value
        $bare = ($callee -split '::')[-1]
        $terminalKey = ([string]$Definition.file) + ':' + $absolute
        if ($TerminalOffsets.Contains($terminalKey)) { continue }
        $immediatePrevious = if ($absolute -gt 0) { $Mask[$absolute - 1] } else { [char]0 }
        $previousIndex = $absolute - 1
        while ($previousIndex -ge 0 -and [char]::IsWhiteSpace($Mask[$previousIndex])) {
            --$previousIndex
        }
        $previous = if ($previousIndex -ge 0) { $Mask[$previousIndex] } else { [char]0 }
        $open = $Mask.IndexOf('(', $absolute)
        $close = Get-MatchingIndex $Mask $open '(' ')'
        if (Test-CppRegistrarDeclaration $Mask $absolute $close) {
            throw "Registrar declaration is forbidden in reachable code: $callee from $($Definition.id)"
        }
        if ($ExplicitEdges.ContainsKey($terminalKey)) {
            $explicit = $ExplicitEdges[$terminalKey]
            if ([string]$explicit.caller_id -ne [string]$Definition.id) {
                throw "Explicit registrar edge has the wrong enclosing owner at $terminalKey"
            }
            $calls.Add([ordered]@{
                caller_id = [string]$explicit.caller_id
                callee_id = [string]$explicit.callee_id
                callee_symbol = [string]$explicit.callee_symbol
                file = [string]$Definition.file
                line = Get-LineNumber $Source $absolute
                character_offset = $absolute
                expression = [string]$explicit.expression
            })
            continue
        }
        if ($previous -eq '.' -or $previous -eq '>' -or $previous -eq ':') {
            throw "Indirect registrar edge '$callee' is not source-resolvable from $($Definition.id)"
        }
        if ($immediatePrevious -match '[A-Za-z0-9_]') { continue }
        $argumentText = $Source.Substring($open + 1, $close - $open - 1)
        $argumentCount = if ([string]::IsNullOrWhiteSpace($argumentText)) {
            0
        } else {
            @(Split-TopLevel $argumentText).Count
        }
        $target = Resolve-CppRegistrarTarget $Definition $callee $Definitions $argumentCount
        $expression = ($Source.Substring($absolute, $close - $absolute + 1) -replace '\s+', ' ').Trim()
        $calls.Add([ordered]@{
            caller_id = [string]$Definition.id
            callee_id = [string]$target.id
            callee_symbol = [string]$target.symbol
            file = [string]$Definition.file
            line = Get-LineNumber $Source $absolute
            character_offset = $absolute
            expression = $expression
        })
    }
    return $calls.ToArray()
}

function Get-UniqueCodeCall([string]$Path, [string]$Pattern, [string]$Label) {
    $source = Get-Text $Path
    $mask = Get-CppCodeMask $source $Path
    $matches = [regex]::Matches($mask, $Pattern)
    if ($matches.Count -ne 1) {
        throw "$Label must have exactly one code occurrence, observed $($matches.Count)"
    }
    $match = $matches[0]
    $open = $mask.IndexOf('(', $match.Index)
    $close = Get-MatchingIndex $mask $open '(' ')'
    return [ordered]@{
        file = Get-Relative $Path
        line = Get-LineNumber $source $match.Index
        character_offset = $match.Index
        expression = ($source.Substring($match.Index, $close - $match.Index + 1) `
            -replace '\s+', ' ').Trim()
    }
}

function Get-UniqueCodeDefinition([string]$Path, [string]$Pattern, [string]$Label) {
    $source = Get-Text $Path
    $mask = Get-CppCodeMask $source $Path
    $matches = [regex]::Matches($mask, $Pattern)
    if ($matches.Count -ne 1) {
        $locations = @($matches | Select-Object -First 16 | ForEach-Object {
            'line=' + (Get-LineNumber $source $_.Index) + ',offset=' + $_.Index
        })
        $suffix = if ($matches.Count -gt 16) { ',...+' + ($matches.Count - 16) } else { '' }
        throw "$Label definition count mismatch: expected 1, observed $($matches.Count), locations=[$($locations -join ';')$suffix], source='$(Get-Relative $Path)'"
    }
    $match = $matches[0]
    $open = $mask.IndexOf('(', $match.Index)
    if ($open -lt 0) {
        throw "$Label has no parameter list: source='$(Get-Relative $Path)' offset=$($match.Index)"
    }
    $close = Get-MatchingIndex $mask $open '(' ')'
    $cursor = $close + 1
    while ($cursor -lt $mask.Length -and [char]::IsWhiteSpace($mask[$cursor])) { ++$cursor }
    if ($cursor -ge $mask.Length -or $mask[$cursor] -ne '{') {
        throw "$Label is not a function definition: source='$(Get-Relative $Path)' line=$(Get-LineNumber $source $match.Index) offset=$($match.Index)"
    }
    return [ordered]@{
        file = Get-Relative $Path
        line = Get-LineNumber $source $match.Index
        character_offset = $match.Index
        body_start = $cursor
        body_end = Get-MatchingIndex $mask $cursor '{' '}'
        expression = ($source.Substring($match.Index, $close - $match.Index + 1) `
            -replace '\s+', ' ').Trim()
    }
}

function Get-OwnedCodeCall([string]$Path, [string]$Pattern, [string]$Label,
                           [object[]]$Definitions) {
    $call = Get-UniqueCodeCall $Path $Pattern $Label
    $owners = @($Definitions | Where-Object {
        [string]$_.file -eq [string]$call.file -and
        [int]$call.character_offset -gt [int]$_.body_start -and
        [int]$call.character_offset -lt [int]$_.body_end
    })
    if ($owners.Count -ne 1) {
        throw "$Label has $($owners.Count) enclosing function definitions"
    }
    $call.caller_id = [string]$owners[0].id
    $call.caller_symbol = [string]$owners[0].symbol
    $source = Get-Text $Path
    $mask = Get-CppCodeMask $source $Path
    $open = $mask.IndexOf('(', [int]$call.character_offset)
    $close = Get-MatchingIndex $mask $open '(' ')'
    $callSpan = $mask.Substring([int]$call.character_offset,
        $close - [int]$call.character_offset + 1)
    $registrarMatch = [regex]::Match($callSpan,
        '\b(?:register|replace)_[A-Za-z0-9_]+\s*\(')
    if (!$registrarMatch.Success) {
        throw "$Label does not contain a registrar-like call"
    }
    $call.registrar_character_offset = [int]$call.character_offset + $registrarMatch.Index
    return $call
}

function Select-UniqueCppDefinition([object[]]$Definitions, [string]$File,
                                    [string]$BareName, [string]$ParameterPattern,
                                    [string]$Label) {
    $matches = @($Definitions | Where-Object {
        [string]$_.file -eq $File -and [string]$_.bare_name -eq $BareName -and
        [string]$_.parameters -match $ParameterPattern
    })
    if ($matches.Count -ne 1) {
        throw "$Label definition count is $($matches.Count), expected one"
    }
    return $matches[0]
}

function Get-McpProductionReachability([object[]]$CppFiles, [object[]]$Registrations,
                                       [object[]]$GeneratedRegistrations,
                                       [string]$StandaloneChatPath,
                                       [string]$StandaloneToolsPath,
                                       [string]$McpServerPath,
                                       [string]$C03RegistrationPath,
                                       [string]$C03IntegrationPath) {
    $sources = @{}
    $masks = @{}
    $definitions = [Collections.Generic.List[object]]::new()
    $graphFiles = [Collections.Generic.List[object]]::new()
    $graphFilePaths = [Collections.Generic.HashSet[string]]::new(
        [StringComparer]::OrdinalIgnoreCase)
    foreach ($file in $CppFiles) {
        if ($graphFilePaths.Add([string]$file.FullName)) { $graphFiles.Add($file) }
    }
    $standaloneSourceRoot = Join-Path $RepositoryRoot 'src\standalone\src'
    foreach ($file in @(Get-ChildItem -LiteralPath $standaloneSourceRoot -Recurse -File |
        Where-Object { $_.Extension -in @('.h', '.hh', '.hpp', '.hxx', '.inl', '.ipp') } |
        Sort-Object FullName)) {
        if ($graphFilePaths.Add([string]$file.FullName)) { $graphFiles.Add($file) }
    }
    foreach ($file in @($graphFiles | Sort-Object FullName)) {
        $source = Get-Text $file.FullName
        if ($source.IndexOf('register_', [StringComparison]::Ordinal) -lt 0) { continue }
        $relative = Get-Relative $file.FullName
        $mask = Get-CppCodeMask $source $file.FullName
        $sources[$relative] = $source
        $masks[$relative] = $mask
        foreach ($definition in @(Get-CppRegistrarDefinitions $file.FullName $source $mask $false)) {
            $definitions.Add($definition)
        }
    }
    $definitionIds = [Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
    foreach ($definition in $definitions) {
        if (!$definitionIds.Add([string]$definition.id)) {
            throw "Duplicate registrar definition identity: $($definition.id)"
        }
    }
    $rootDefinitions = @($definitions | Where-Object {
        [string]$_.symbol -eq 'mcp_standalone::register_standalone_tools'
    })
    if ($rootDefinitions.Count -ne 1) {
        throw "Production MCP root registrar definition count is $($rootDefinitions.Count), expected one"
    }
    $root = $rootDefinitions[0]
    $entry = Get-UniqueCodeCall $StandaloneChatPath `
        '\bmcp_standalone::register_standalone_tools\s*\(\s*s_mcp_server\s*\)' `
        'standalone production MCP initialization call'
    $entry.root_registrar_id = [string]$root.id
    $entry.root_registrar_symbol = [string]$root.symbol

    $reachable = @{}
    $parents = @{}
    $chains = @{}
    $reachable[[string]$root.id] = $root
    $chains[[string]$root.id] = @([string]$root.id)
    $queue = [Collections.Generic.Queue[object]]::new()
    $queue.Enqueue($root)
    $edges = [Collections.Generic.List[object]]::new()
    $edgeSites = [Collections.Generic.Dictionary[string,string]]::new(
        [StringComparer]::Ordinal)
    $registrationTerminalOffsets = [Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
    $registrationTerminalEvidence = [Collections.Generic.Dictionary[string,string]]::new(
        [StringComparer]::Ordinal)
    $registrationProducerSites = [Collections.Generic.Dictionary[string,object]]::new(
        [StringComparer]::Ordinal)
    foreach ($registration in $Registrations) {
        $offset = [int]$registration.source.character_offset
        if ($offset -ge 0) {
            $file = [string]$registration.source.file
            if ([string]::IsNullOrWhiteSpace([string]$registration.name)) {
                throw "MCP registration terminal has an empty public name: $file`:$offset"
            }
            if (!$sources.ContainsKey($file) -or !$masks.ContainsKey($file)) {
                throw "MCP registration terminal source is unavailable: $file`:$offset"
            }
            $identity = Get-CppRegistrarTerminalIdentity $file $masks[$file] $offset `
                "MCP registration '$($registration.name)'"
            $key = [string]$identity['key']
            $identityCallee = [string]$identity['callee']
            $identityOffset = [int]$identity['character_offset']
            if ([int]$registration.source.line -ne
                (Get-LineNumber $sources[$file] $identityOffset)) {
                throw "MCP registration terminal line metadata is invalid: $file`:$offset"
            }
            $evidence = ([string]$registration.name) + "`t" + $file + "`t" +
                [int]$registration.source.line + "`t" + $offset + "`t" +
                ([string]$registration.source.evidence) + "`t" +
                $identityCallee + "`t" + $identityOffset
            $identityPrefix = $masks[$file].Substring($offset, $identityOffset - $offset)
            $memberTerminal = $identityPrefix -match '^(?:\.|->)'
            $producerTarget = $null
            if (!$memberTerminal -and
                ![string]::Equals([string]$registration.source.evidence, 'compat_initializer',
                    [StringComparison]::Ordinal)) {
                $owners = @($definitions | Where-Object {
                    [string]$_.file -eq $file -and
                    $identityOffset -gt [int]$_.body_start -and
                    $identityOffset -lt [int]$_.body_end
                })
                if ($owners.Count -ne 1) {
                    throw "MCP registration producer has $($owners.Count) enclosing registrars: $key"
                }
                $open = $masks[$file].IndexOf('(', $identityOffset)
                $close = Get-MatchingIndex $masks[$file] $open '(' ')'
                $argumentText = $sources[$file].Substring($open + 1, $close - $open - 1)
                $argumentCount = if ([string]::IsNullOrWhiteSpace($argumentText)) {
                    0
                } else {
                    @(Split-TopLevel $argumentText).Count
                }
                $producerTarget = Resolve-CppRegistrarTarget $owners[0] $identityCallee `
                    $definitions.ToArray() $argumentCount
            }
            if ($null -ne $producerTarget) {
                if ($registrationProducerSites.ContainsKey($key)) {
                    throw "Duplicate MCP registration producer identity: $key"
                }
                $registrationProducerSites[$key] = [ordered]@{
                    registration = $registration
                    target_id = [string]$producerTarget.id
                    target_symbol = [string]$producerTarget.symbol
                    evidence = $evidence
                }
                continue
            }
            if ($registrationTerminalEvidence.ContainsKey($key)) {
                if (![string]::Equals($registrationTerminalEvidence[$key], $evidence,
                        [StringComparison]::Ordinal)) {
                    throw "Conflicting MCP registration terminal identity: $key"
                }
                throw "Duplicate MCP registration terminal identity: $key"
            }
            $registrationTerminalEvidence[$key] = $evidence
            if (!$registrationTerminalOffsets.Add($key)) {
                throw "Duplicate MCP registration terminal offset: $key"
            }
        }
    }
    $productionRouteEntryCall = Get-OwnedCodeCall $StandaloneToolsPath `
        '\bregister_c03_compatibility_tools\s*\(\s*srv\s*\)' `
        'C03 compatibility root registrar edge' $definitions.ToArray()
    if ([string]$productionRouteEntryCall.caller_id -ne [string]$root.id) {
        throw 'C03 compatibility root registrar edge is outside the production root'
    }
    $directGraphTerminalOffsets = [Collections.Generic.HashSet[string]]::new(
        [StringComparer]::Ordinal)
    foreach ($key in $registrationTerminalOffsets) {
        [void]$directGraphTerminalOffsets.Add($key)
    }
    $helperTerminalOwners = [Collections.Generic.Dictionary[string,string]]::new(
        [StringComparer]::Ordinal)
    $physicalTerminalDefinitionOwners = [Collections.Generic.Dictionary[string,string]]::new(
        [StringComparer]::Ordinal)
    $physicalTerminalsByDefinition = @{}
    foreach ($definition in $definitions) {
        $definitionId = [string]$definition.id
        $definitionFile = [string]$definition.file
        if (!$masks.ContainsKey($definitionFile)) {
            throw "Registrar terminal source cache is unavailable: $definitionId"
        }
        $definitionTerminals = @(Get-CppPhysicalRegistrationTerminals $definition `
            $masks[$definitionFile])
        $physicalTerminalsByDefinition[$definitionId] = $definitionTerminals
        foreach ($terminal in $definitionTerminals) {
            $physicalKey = [string]$terminal['key']
            if ($physicalTerminalDefinitionOwners.ContainsKey($physicalKey)) {
                if (![string]::Equals($physicalTerminalDefinitionOwners[$physicalKey],
                        $definitionId, [StringComparison]::Ordinal)) {
                    throw "Physical registration terminal has multiple definition owners: $physicalKey"
                }
                throw "Duplicate physical registration terminal identity: $physicalKey"
            }
            $physicalTerminalDefinitionOwners[$physicalKey] = $definitionId
            [void]$directGraphTerminalOffsets.Add($physicalKey)
        }
    }
    $boundRegistrationProducerSites = [Collections.Generic.HashSet[string]]::new(
        [StringComparer]::Ordinal)
    $registrationProducerEdges = [Collections.Generic.Dictionary[string,object]]::new(
        [StringComparer]::Ordinal)
    [void]$directGraphTerminalOffsets.Add(
        ([string]$productionRouteEntryCall.file) + ':' +
        [int]$productionRouteEntryCall.registrar_character_offset)
    while ($queue.Count -gt 0) {
        $caller = $queue.Dequeue()
        $relative = [string]$caller.file
        if (!$sources.ContainsKey($relative) -or !$masks.ContainsKey($relative)) {
            throw "Registrar source cache is unavailable: $relative"
        }
        $calls = @(Get-CppRegistrarCalls $caller $sources[$relative] $masks[$relative] `
            $definitions.ToArray() $directGraphTerminalOffsets @{})
        foreach ($edge in $calls) {
            if (![string]::Equals([string]$edge.caller_id, [string]$caller.id,
                    [StringComparison]::Ordinal) -or
                ![string]::Equals([string]$edge.file, $relative,
                    [StringComparison]::Ordinal)) {
                throw "Registrar call-site ownership metadata is invalid: $($caller.id)"
            }
            $edgeOffset = [int]$edge.character_offset
            $edgeLine = [int]$edge.line
            if ($edgeOffset -le [int]$caller.body_start -or
                $edgeOffset -ge [int]$caller.body_end -or
                $edgeLine -ne (Get-LineNumber $sources[$relative] $edgeOffset) -or
                [string]::IsNullOrWhiteSpace([string]$edge.expression)) {
                throw "Registrar call-site location metadata is invalid: $($caller.id)"
            }
            $siteKey = $relative + ':' + $edgeOffset
            $siteEvidence = ([string]$edge.caller_id) + "`t" +
                ([string]$edge.callee_id) + "`t" + ([string]$edge.callee_symbol) + "`t" +
                $relative + "`t" + $edgeLine + "`t" + $edgeOffset + "`t" +
                ([string]$edge.expression)
            if ($edgeSites.ContainsKey($siteKey)) {
                if (![string]::Equals([string]$edgeSites[$siteKey], $siteEvidence,
                        [StringComparison]::Ordinal)) {
                    throw "Conflicting registrar call-site evidence: $siteKey"
                }
                throw "Duplicate registrar call-site evidence: $siteKey"
            }
            $edgeSites[$siteKey] = $siteEvidence
            $targetId = [string]$edge.callee_id
            if ($targetId -eq [string]$root.id -or
                $targetId -eq [string]$caller.id) {
                throw "Registrar has a cycle or multiple production parents: $targetId"
            }
            $targetMatches = @($definitions | Where-Object { [string]$_.id -eq $targetId })
            if ($targetMatches.Count -ne 1) {
                throw "Resolved registrar target identity is invalid: $targetId"
            }
            $target = $targetMatches[0]
            if (![string]::Equals([string]$edge.callee_symbol, [string]$target.symbol,
                    [StringComparison]::Ordinal)) {
                throw "Resolved registrar target metadata conflicts with its definition: $targetId"
            }
            if ($registrationProducerSites.ContainsKey($siteKey)) {
                $producer = $registrationProducerSites[$siteKey]
                if (![string]::Equals([string]$producer['target_id'], $targetId,
                        [StringComparison]::Ordinal) -or
                    ![string]::Equals([string]$producer['target_symbol'], [string]$target.symbol,
                        [StringComparison]::Ordinal)) {
                    throw "MCP registration producer target conflicts with its graph edge: $siteKey"
                }
                if ($registrationProducerEdges.ContainsKey($siteKey)) {
                    throw "MCP registration producer graph edge is duplicated: $siteKey"
                }
                $registrationProducerEdges[$siteKey] = $edge
            }
            if ($parents.ContainsKey($targetId)) {
                if (![string]::Equals([string]$parents[$targetId], [string]$caller.id,
                        [StringComparison]::Ordinal)) {
                    throw "Registrar has a cycle or multiple production parents: $targetId"
                }
                if (!$reachable.ContainsKey($targetId) -or !$chains.ContainsKey($targetId)) {
                    throw "Repeated registrar target has inconsistent graph state: $targetId"
                }
                $edges.Add($edge)
                continue
            }
            if ($reachable.ContainsKey($targetId) -or $chains.ContainsKey($targetId) -or
                !$chains.ContainsKey([string]$caller.id)) {
                throw "Registrar target has inconsistent graph state: $targetId"
            }
            $parents[$targetId] = [string]$caller.id
            $chains[$targetId] = @($chains[[string]$caller.id]) + @($targetId)
            $reachable[$targetId] = $target
            $edges.Add($edge)
            $queue.Enqueue($target)
        }
    }
    if ($registrationProducerEdges.Count -ne $registrationProducerSites.Count) {
        $missingProducerEdges = @($registrationProducerSites.Keys | Where-Object {
            !$registrationProducerEdges.ContainsKey($_)
        } | Sort-Object)
        throw "MCP registration producers lack exact graph edges: $($missingProducerEdges -join ', ')"
    }
    $outgoingEdgesByRegistrar = @{}
    foreach ($edge in $edges) {
        $callerId = [string]$edge.caller_id
        if (!$outgoingEdgesByRegistrar.ContainsKey($callerId)) {
            $outgoingEdgesByRegistrar[$callerId] = [Collections.Generic.List[object]]::new()
        }
        $outgoingEdgesByRegistrar[$callerId].Add($edge)
    }
    foreach ($siteKey in @($registrationProducerSites.Keys | Sort-Object)) {
        $producer = $registrationProducerSites[$siteKey]
        $producerEdge = $registrationProducerEdges[$siteKey]
        $helperId = [string]$producer['target_id']
        if (![string]::Equals([string]$producerEdge.callee_id, $helperId,
                [StringComparison]::Ordinal)) {
            throw "MCP registration producer edge target is inconsistent: $siteKey"
        }
        $helperMatches = @($definitions | Where-Object { [string]$_.id -eq $helperId })
        if ($helperMatches.Count -ne 1 -or !$reachable.ContainsKey($helperId)) {
            throw "MCP registration producer helper is not uniquely reachable: $siteKey"
        }
        $helper = $helperMatches[0]
        $terminalChain = [Collections.Generic.List[string]]::new()
        $bridgeCalls = [Collections.Generic.List[object]]::new()
        $visitedChain = [Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
        $currentId = $helperId
        $terminalOwner = $null
        $physicalTerminals = @()
        while ($true) {
            if (!$visitedChain.Add($currentId)) {
                throw "MCP registration helper chain contains a cycle: $siteKey target=$currentId"
            }
            $terminalChain.Add($currentId)
            $currentMatches = @($definitions | Where-Object { [string]$_.id -eq $currentId })
            if ($currentMatches.Count -ne 1 -or !$reachable.ContainsKey($currentId) -or
                !$physicalTerminalsByDefinition.ContainsKey($currentId)) {
                throw "MCP registration helper chain target is invalid: $siteKey target=$currentId"
            }
            $current = $currentMatches[0]
            $physicalTerminals = @($physicalTerminalsByDefinition[$currentId])
            $outgoing = @(if ($outgoingEdgesByRegistrar.ContainsKey($currentId)) {
                $outgoingEdgesByRegistrar[$currentId] | Sort-Object `
                    @{Expression={[string]$_['file']};Ascending=$true},
                    @{Expression={[int]$_['character_offset']};Ascending=$true},
                    @{Expression={[string]$_['callee_id']};Ascending=$true}
            })
            if ($physicalTerminals.Count -gt 0) {
                if ($outgoing.Count -ne 0) {
                    throw "MCP registration helper has both physical and delegated terminals: $currentId"
                }
                $terminalOwner = $current
                break
            }
            if ($outgoing.Count -ne 1) {
                throw "MCP registration helper chain has $($outgoing.Count) delegated terminals: $currentId"
            }
            $bridgeEdge = $outgoing[0]
            if (![string]::Equals([string]$bridgeEdge.caller_id, $currentId,
                    [StringComparison]::Ordinal) -or
                [string]::IsNullOrWhiteSpace([string]$bridgeEdge.expression)) {
                throw "MCP registration helper bridge call identity is invalid: $currentId"
            }
            $nextId = [string]$bridgeEdge.callee_id
            if ([string]::IsNullOrWhiteSpace($nextId) -or $nextId -eq $currentId) {
                throw "MCP registration helper bridge target is invalid: $currentId"
            }
            $bridgeCalls.Add([ordered]@{
                caller_id = $currentId
                callee_id = $nextId
                callee_symbol = [string]$bridgeEdge.callee_symbol
                file = [string]$bridgeEdge.file
                line = [int]$bridgeEdge.line
                character_offset = [int]$bridgeEdge.character_offset
                expression = [string]$bridgeEdge.expression
            })
            $currentId = $nextId
        }
        if ($null -eq $terminalOwner -or $physicalTerminals.Count -eq 0) {
            throw "MCP registration helper chain has no physical terminal: $siteKey"
        }
        $chainIds = $terminalChain.ToArray()
        $chainHash = Get-OrderedStringListSha256 $chainIds
        $terminalBindings = [Collections.Generic.List[object]]::new()
        $terminalOwnerEvidence = $helperId + "`t" + $chainHash
        foreach ($terminal in @($physicalTerminals | Sort-Object {
            [int]$_['character_offset']
        })) {
            $physicalKey = [string]$terminal['key']
            if ($registrationTerminalOffsets.Contains($physicalKey)) {
                throw "Helper physical terminal conflicts with a direct registration: $physicalKey"
            }
            if (!$physicalTerminalDefinitionOwners.ContainsKey($physicalKey) -or
                ![string]::Equals($physicalTerminalDefinitionOwners[$physicalKey],
                    [string]$terminalOwner.id, [StringComparison]::Ordinal)) {
                throw "Helper physical terminal definition owner is invalid: $physicalKey"
            }
            if ($helperTerminalOwners.ContainsKey($physicalKey) -and
                ![string]::Equals($helperTerminalOwners[$physicalKey], $terminalOwnerEvidence,
                    [StringComparison]::Ordinal)) {
                throw "Helper physical terminal has multiple registrar provenance owners: $physicalKey"
            }
            $helperTerminalOwners[$physicalKey] = $terminalOwnerEvidence
            $terminalBindings.Add([ordered]@{
                key = $physicalKey
                file = [string]$terminalOwner.file
                line = [int]$terminal['line']
                character_offset = [int]$terminal['character_offset']
                callee = [string]$terminal['callee']
                owner_id = [string]$terminalOwner.id
                owner_symbol = [string]$terminalOwner.symbol
            })
        }
        $registration = $producer['registration']
        if ($registration.source.Contains('helper_terminal_binding')) {
            throw "MCP registration producer binding is duplicated: $siteKey"
        }
        $registration.source['helper_terminal_binding'] = [ordered]@{
            producer_key = $siteKey
            helper_id = $helperId
            helper_symbol = [string]$helper.symbol
            chain = $chainIds
            chain_sha256 = $chainHash
            bridge_calls = $bridgeCalls.ToArray()
            terminal_owner_id = [string]$terminalOwner.id
            terminal_owner_symbol = [string]$terminalOwner.symbol
            terminals = $terminalBindings.ToArray()
        }
        if (!$boundRegistrationProducerSites.Add($siteKey)) {
            throw "MCP registration producer was bound more than once: $siteKey"
        }
    }
    if ($boundRegistrationProducerSites.Count -ne $registrationProducerSites.Count) {
        $missingProducerSites = @($registrationProducerSites.Keys | Where-Object {
            !$boundRegistrationProducerSites.Contains($_)
        } | Sort-Object)
        throw "MCP registration producers lack helper terminal bindings: $($missingProducerSites -join ', ')"
    }

    $standaloneToolsRelative = Get-Relative $StandaloneToolsPath
    $mcpServerRelative = Get-Relative $McpServerPath
    $c03RegistrationRelative = Get-Relative $C03RegistrationPath
    $c03IntegrationRelative = Get-Relative $C03IntegrationPath
    $serverBridge = Select-UniqueCppDefinition $definitions.ToArray() $mcpServerRelative `
        'register_c03_compatibility_tools' 'server_t\s*&' 'C03 server bridge'
    $configBridge = Select-UniqueCppDefinition $definitions.ToArray() $c03RegistrationRelative `
        'register_c03_compatibility_tools' 'tool_registry_t\s*&.*c03_compatibility_runtime_config_t' `
        'C03 runtime-config bridge'
    $waveRegistrar = Select-UniqueCppDefinition $definitions.ToArray() $c03RegistrationRelative `
        'register_wave_c_compatibility_tools' 'tool_registry_t\s*&.*c03_compatibility_runtime_config_t' `
        'C03 Wave C registrar'
    $generatedRegistrar = Select-UniqueCppDefinition $definitions.ToArray() $c03IntegrationRelative `
        'register_generated_tools' '^$' 'C03 generated registrar'
    $extensionRegistrar = Select-UniqueCppDefinition $definitions.ToArray() $c03IntegrationRelative `
        'register_extension_tools' '^$' 'C03 extension registrar'
    $entryRegistrar = Select-UniqueCppDefinition $definitions.ToArray() $c03IntegrationRelative `
        'register_entry' 'shared_ptr<mcp_server_integration_t>.*std::string\s*&' `
        'C03 per-name registrar'

    $routeSpecifications = @(
        [ordered]@{
            call = $productionRouteEntryCall
            caller = $root
            callee = $serverBridge
        },
        [ordered]@{
            call = Get-OwnedCodeCall $McpServerPath `
                '\bregister_c03_compatibility_tools\s*\(\s*server\.registry\s*\(\s*\)\s*,\s*make_application_c03_compatibility_runtime_config\s*\(\s*\)\s*\)' `
                'C03 compatibility server bridge edge' $definitions.ToArray()
            caller = $serverBridge
            callee = $configBridge
        },
        [ordered]@{
            call = Get-OwnedCodeCall $C03RegistrationPath `
                '\bregister_wave_c_compatibility_tools\s*\(\s*registry\s*,\s*std::move\s*\(\s*config\s*\)\s*\)' `
                'C03 compatibility wave registrar edge' $definitions.ToArray()
            caller = $configBridge
            callee = $waveRegistrar
        },
        [ordered]@{
            call = Get-OwnedCodeCall $C03RegistrationPath `
                '\bintegration\s*->\s*register_generated_tools\s*\(\s*\)' `
                'C03 generated compatibility registrar edge' $definitions.ToArray()
            caller = $waveRegistrar
            callee = $generatedRegistrar
        },
        [ordered]@{
            call = Get-OwnedCodeCall $C03RegistrationPath `
                '\bintegration\s*->\s*register_extension_tools\s*\(\s*\)' `
                'C03 extension registrar edge' $definitions.ToArray()
            caller = $waveRegistrar
            callee = $extensionRegistrar
        },
        [ordered]@{
            call = Get-OwnedCodeCall $C03IntegrationPath `
                '\bimpl_\s*->\s*register_entry\s*\(\s*owner\s*,\s*name\s*\)' `
                'C03 generated per-name registrar edge' $definitions.ToArray()
            caller = $generatedRegistrar
            callee = $entryRegistrar
        },
        [ordered]@{
            call = Get-OwnedCodeCall $C03IntegrationPath `
                '\bimpl_\s*->\s*register_entry\s*\(\s*owner\s*,\s*std::string\s*\(\s*name\s*\)\s*\)' `
                'C03 extension per-name registrar edge' $definitions.ToArray()
            caller = $extensionRegistrar
            callee = $entryRegistrar
        }
    )
    $generatedRouteEdges = [Collections.Generic.List[object]]::new()
    foreach ($specification in $routeSpecifications) {
        if ([string]$specification.call.caller_id -ne [string]$specification.caller.id) {
            throw "C03 route call has the wrong enclosing owner: $($specification.call.expression)"
        }
        $generatedRouteEdges.Add([ordered]@{
            caller_id = [string]$specification.caller.id
            caller_symbol = [string]$specification.caller.symbol
            callee_id = [string]$specification.callee.id
            callee_symbol = [string]$specification.callee.symbol
            file = [string]$specification.call.file
            line = [int]$specification.call.line
            character_offset = [int]$specification.call.registrar_character_offset
            expression = [string]$specification.call.expression
        })
    }
    $terminalOperationCalls = @(
        Get-OwnedCodeCall $C03IntegrationPath `
            '\bstate\.registry\s*->\s*replace_tool\s*\(\s*std::move\s*\(\s*tool\s*\)\s*\)' `
            'C03 replacement terminal registration' $definitions.ToArray()
        Get-OwnedCodeCall $C03IntegrationPath `
            '\bstate\.registry\s*->\s*register_tool\s*\(\s*std::move\s*\(\s*tool\s*\)\s*\)' `
            'C03 insertion terminal registration' $definitions.ToArray()
    )
    $terminalOperations = [Collections.Generic.List[object]]::new()
    foreach ($operation in $terminalOperationCalls) {
        if ([string]$operation.caller_id -ne [string]$entryRegistrar.id) {
            throw "C03 terminal registration is outside the per-name registrar"
        }
        $terminalOperations.Add([ordered]@{
            file = [string]$operation.file
            line = [int]$operation.line
            character_offset = [int]$operation.registrar_character_offset
            expression = [string]$operation.expression
            caller_id = [string]$operation.caller_id
            caller_symbol = [string]$operation.caller_symbol
        })
    }
    $explicitRouteEdges = @{}
    foreach ($edge in $generatedRouteEdges) {
        $key = ([string]$edge.file) + ':' + [int]$edge.character_offset
        if ($explicitRouteEdges.ContainsKey($key)) {
            throw "C03 explicit registrar route offset is duplicated: $key"
        }
        $explicitRouteEdges[$key] = $edge
    }
    $routeTerminalOffsets = [Collections.Generic.HashSet[string]]::new(
        [StringComparer]::Ordinal)
    foreach ($key in $registrationTerminalOffsets) {
        [void]$routeTerminalOffsets.Add($key)
    }
    foreach ($operation in $terminalOperations) {
        [void]$routeTerminalOffsets.Add(
            ([string]$operation.file) + ':' + [int]$operation.character_offset)
    }
    $routeDefinitions = @($root, $serverBridge, $configBridge, $waveRegistrar,
        $generatedRegistrar, $extensionRegistrar, $entryRegistrar)
    foreach ($definition in $routeDefinitions) {
        $relative = [string]$definition.file
        $observed = @(Get-CppRegistrarCalls $definition $sources[$relative] $masks[$relative] `
            $definitions.ToArray() $routeTerminalOffsets $explicitRouteEdges)
        $expected = @($generatedRouteEdges | Where-Object {
            [string]$_.caller_id -eq [string]$definition.id
        })
        if ([string]$definition.id -eq [string]$root.id) {
            $expected += @($edges | Where-Object {
                [string]$_.caller_id -eq [string]$definition.id
            })
        }
        $observedLines = @($observed | ForEach-Object {
            ([string]$_.caller_id) + "`t" + ([string]$_.callee_id) + "`t" +
            ([string]$_.file) + "`t" + [int]$_.character_offset
        } | Sort-Object)
        $expectedLines = @($expected | ForEach-Object {
            ([string]$_.caller_id) + "`t" + ([string]$_.callee_id) + "`t" +
            ([string]$_.file) + "`t" + [int]$_.character_offset
        } | Sort-Object)
        if (($observedLines -join "`n") -ne ($expectedLines -join "`n")) {
            throw "C03 registrar body has an unclassified or missing edge: $($definition.id)"
        }
    }
    $generatedRouteNodes = $routeDefinitions | ForEach-Object {
        [ordered]@{
            id = [string]$_.id
            symbol = [string]$_.symbol
            file = [string]$_.file
            line = [int]$_.line
            body_start = [int]$_.body_start
            body_end = [int]$_.body_end
            parameters = [string]$_.parameters
        }
    }
    $generatedBaseChain = @([string]$root.id, [string]$serverBridge.id,
        [string]$configBridge.id, [string]$waveRegistrar.id)
    $generatedCompatibilityChain = $generatedBaseChain + @(
        [string]$generatedRegistrar.id, [string]$entryRegistrar.id)
    $generatedExtensionChain = $generatedBaseChain + @(
        [string]$extensionRegistrar.id, [string]$entryRegistrar.id)
    $generatedBindings = [Collections.Generic.List[object]]::new()
    $generatedBindingByName = @{}
    foreach ($registration in $GeneratedRegistrations) {
        $name = [string]$registration.name
        if ($generatedBindingByName.ContainsKey($name)) {
            throw "C03 generated reachability binding is duplicated: $name"
        }
        $extension = ([string]$registration.descriptor_source).IndexOf(
            '#wave_c_extension_binding', [StringComparison]::Ordinal) -ge 0
        $chain = if ($extension) { $generatedExtensionChain } `
            else { $generatedCompatibilityChain }
        $binding = [ordered]@{
            name = $name
            branch = if ($extension) { 'extension' } else { 'generated_compatibility' }
            registrar_id = [string]$entryRegistrar.id
            registrar_symbol = [string]$entryRegistrar.symbol
            chain = $chain
            chain_sha256 = Get-OrderedStringListSha256 $chain
        }
        $registration['production_reachability'] = $binding
        $generatedBindingByName[$name] = $binding
        $generatedBindings.Add($binding)
    }
    if ($generatedBindings.Count -ne 92 -or
        @($generatedBindings | Where-Object { $_.branch -eq 'generated_compatibility' }).Count -ne 88 -or
        @($generatedBindings | Where-Object { $_.branch -eq 'extension' }).Count -ne 4) {
        throw 'C03 generated per-name reachability partition is invalid'
    }
    $generatedBindingsSorted = @($generatedBindings | Sort-Object `
        @{ Expression = { [string]$_['name'] }; Ascending = $true })
    $generatedRouteLines = [Collections.Generic.List[string]]::new()
    foreach ($node in $generatedRouteNodes) {
        $generatedRouteLines.Add('R' + "`t" + $node.id + "`t" + $node.symbol + "`t" +
            $node.file + "`t" + $node.line)
    }
    foreach ($edge in $generatedRouteEdges) {
        $generatedRouteLines.Add('E' + "`t" + $edge.caller_id + "`t" + $edge.callee_id +
            "`t" + $edge.file + "`t" + $edge.line + "`t" + $edge.character_offset +
            "`t" + $edge.expression)
    }
    foreach ($operation in $terminalOperations) {
        $generatedRouteLines.Add('T' + "`t" + $operation.caller_id + "`t" + $operation.file +
            "`t" + $operation.line + "`t" + $operation.character_offset + "`t" +
            $operation.expression)
    }
    $generatedBindingLines = @($generatedBindingsSorted | ForEach-Object {
        ([string]$_.name) + "`t" + ([string]$_.branch) + "`t" +
        ([string]$_.registrar_id) + "`t" + ([string]$_.chain_sha256)
    })
    $generatedRouteHash = Get-StringListSha256 $generatedRouteLines.ToArray()
    $generatedBindingHash = Get-StringListSha256 $generatedBindingLines

    $directCount = 0
    $projectionCount = 0
    $rowLines = [Collections.Generic.List[string]]::new()
    foreach ($registration in $Registrations) {
        $offset = [int]$registration.source.character_offset
        if ($offset -ge 0) {
            $file = [string]$registration.source.file
            $enclosing = @($definitions | Where-Object {
                [string]$_.file -eq $file -and $offset -gt [int]$_.body_start -and
                $offset -lt [int]$_.body_end
            })
            if ($enclosing.Count -ne 1) {
                throw "MCP registration '$($registration.name)' has $($enclosing.Count) enclosing registrars"
            }
            $registrar = $enclosing[0]
            $registrarId = [string]$registrar.id
            if (!$reachable.ContainsKey($registrarId)) {
                throw "MCP registration '$($registration.name)' is in an unreachable registrar: $registrarId"
            }
            $chain = @($chains[$registrarId])
            $chainHash = Get-OrderedStringListSha256 $chain
            $registration['production_reachability'] = [ordered]@{
                mode = 'direct_registration'
                registrar_id = $registrarId
                registrar_symbol = [string]$registrar.symbol
                chain = $chain
                chain_sha256 = $chainHash
            }
            ++$directCount
        } else {
            $name = [string]$registration.name
            if (!$generatedBindingByName.ContainsKey($name)) {
                throw "Legacy MCP projection lacks generated production reachability: $name"
            }
            $generatedBinding = $generatedBindingByName[$name]
            $chain = @($generatedBinding.chain)
            $chainHash = [string]$generatedBinding.chain_sha256
            $registration['production_reachability'] = [ordered]@{
                mode = 'generated_compatibility_projection'
                generated_branch = [string]$generatedBinding.branch
                registrar_id = [string]$generatedBinding.registrar_id
                registrar_symbol = [string]$generatedBinding.registrar_symbol
                chain = $chain
                chain_sha256 = $chainHash
            }
            ++$projectionCount
        }
        $rowLines.Add(([string]$registration.name) + "`t" +
            ([string]$registration.production_reachability.mode) + "`t" +
            ([string]$registration.production_reachability.registrar_id) + "`t" +
            ([string]$registration.production_reachability.chain_sha256))
    }
    if ($directCount + $projectionCount -ne $Registrations.Count) {
        throw "Production MCP reachability did not bind every resolved registration"
    }

    $registrarRows = @($reachable.Values | Sort-Object `
        @{ Expression = { [string]$_['id'] }; Ascending = $true } | ForEach-Object {
        [ordered]@{
            id = [string]$_.id
            symbol = [string]$_.symbol
            file = [string]$_.file
            line = [int]$_.line
            body_start = [int]$_.body_start
            body_end = [int]$_.body_end
            parent_id = if ([string]$_.id -eq [string]$root.id) { $null } `
                else { [string]$parents[[string]$_.id] }
            chain = @($chains[[string]$_.id])
        }
    })
    $edgeRows = @($edges | Sort-Object `
        @{Expression={[string]$_['caller_id']};Ascending=$true},
        @{Expression={[string]$_['callee_id']};Ascending=$true},
        @{Expression={[string]$_['file']};Ascending=$true},
        @{Expression={[int]$_['line']};Ascending=$true},
        @{Expression={[int]$_['character_offset']};Ascending=$true},
        @{Expression={[string]$_['expression']};Ascending=$true})
    $graphLines = [Collections.Generic.List[string]]::new()
    foreach ($registrar in $registrarRows) {
        $graphLines.Add('R' + "`t" + $registrar.id + "`t" + $registrar.symbol + "`t" +
            $registrar.file + "`t" + $registrar.line + "`t" + [string]$registrar.parent_id)
    }
    foreach ($edge in $edgeRows) {
        $graphLines.Add('E' + "`t" + $edge.caller_id + "`t" + $edge.callee_id + "`t" +
            $edge.file + "`t" + $edge.line + "`t" + $edge.character_offset + "`t" +
            $edge.expression)
    }
    $sourceFilePaths = @($registrarRows | ForEach-Object { [string]$_.file }) + @(
        Get-Relative $StandaloneChatPath
        Get-Relative $McpServerPath
        Get-Relative $C03RegistrationPath
        Get-Relative $C03IntegrationPath
    )
    return [ordered]@{
        schema_version = 1
        production_entry = $entry
        concrete_registration_count = $Registrations.Count
        direct_registration_count = $directCount
        generated_projection_count = $projectionCount
        reachable_registrar_count = $registrarRows.Count
        registrar_edge_count = $edgeRows.Count
        row_binding_sha256 = Get-StringListSha256 @($rowLines | Sort-Object)
        registrar_graph_sha256 = Get-StringListSha256 $graphLines.ToArray()
        registrars = $registrarRows
        edges = $edgeRows
        generated_route = [ordered]@{
            node_count = $generatedRouteNodes.Count
            edge_count = $generatedRouteEdges.Count
            terminal_operation_count = $terminalOperations.Count
            binding_count = $generatedBindings.Count
            generated_compatibility_count = 88
            extension_count = 4
            shared_terminal_definition_id = [string]$entryRegistrar.id
            shared_terminal_parent_ids = @(@(
                [string]$generatedRegistrar.id,
                [string]$extensionRegistrar.id
            ) | Sort-Object)
            nodes = $generatedRouteNodes
            edges = $generatedRouteEdges.ToArray()
            terminal_operations = $terminalOperations.ToArray()
            bindings = $generatedBindingsSorted
            route_sha256 = $generatedRouteHash
            binding_sha256 = $generatedBindingHash
        }
        source_files = @($sourceFilePaths | Sort-Object -Unique)
    }
}

function Get-OrdinalSourceIndex([string]$Source, [string]$Marker, [int]$Occurrence,
                                [string]$Contract) {
    if ([string]::IsNullOrEmpty($Marker) -or $Occurrence -lt 1) {
        throw "Invalid source contract selector '$Contract'"
    }
    $cursor = 0
    for ($current = 1; $current -le $Occurrence; ++$current) {
        $index = $Source.IndexOf($Marker, $cursor, [StringComparison]::Ordinal)
        if ($index -lt 0) {
            throw "Missing source contract '$Contract' occurrence $Occurrence`: $Marker"
        }
        if ($current -eq $Occurrence) { return $index }
        $cursor = $index + $Marker.Length
    }
    throw "Invalid source contract selector state '$Contract'"
}

function Get-SourceBlock([string]$Source, [string]$Marker, [string]$Contract,
                         [int]$Occurrence = 1) {
    $start = Get-OrdinalSourceIndex $Source $Marker $Occurrence $Contract
    $open = $Source.IndexOf('{', $start + $Marker.Length)
    if ($open -lt 0) { throw "Missing source block '$Contract': $Marker" }
    $close = Get-MatchingIndex $Source $open '{' '}'
    return [ordered]@{
        text = $Source.Substring($open, $close - $open + 1)
        marker_index = $start
        block_index = $open
    }
}

function Assert-SourceContains([string]$Source, [string[]]$Required, [string]$Contract) {
    foreach ($needle in $Required) {
        if ($Source.IndexOf($needle, [StringComparison]::Ordinal) -lt 0) {
            throw "Missing source contract '$Contract': $needle"
        }
    }
}

function Assert-SourceExcludes([string]$Source, [string[]]$Forbidden, [string]$Contract) {
    foreach ($needle in $Forbidden) {
        if ($Source.IndexOf($needle, [StringComparison]::Ordinal) -ge 0) {
            throw "Forbidden source contract '$Contract': $needle"
        }
    }
}

function Assert-SourceOrdered([string]$Source, [string[]]$Required, [string]$Contract) {
    $cursor = 0
    foreach ($needle in $Required) {
        $index = $Source.IndexOf($needle, $cursor, [StringComparison]::Ordinal)
        if ($index -lt 0) { throw "Missing or reordered source contract '$Contract': $needle" }
        $cursor = $index + $needle.Length
    }
}

function Get-SourceContractRecord([string]$Id, [string]$Path, [string]$Source,
                                  [string]$Marker, [string]$Symbol,
                                  [string[]]$Required, [string[]]$Forbidden = @(),
                                  [switch]$Ordered, [switch]$Block,
                                  [int]$Occurrence = 1) {
    $scope = $Source
    $markerIndex = Get-OrdinalSourceIndex $Source $Marker $Occurrence $Id
    if ($Block) {
        $sourceBlock = Get-SourceBlock $Source $Marker $Id $Occurrence
        $scope = $sourceBlock.text
    }
    if ($Ordered) { Assert-SourceOrdered $scope $Required $Id }
    else { Assert-SourceContains $scope $Required $Id }
    Assert-SourceExcludes $scope $Forbidden $Id
    return [ordered]@{
        id = $Id
        source = [ordered]@{
            file = Get-Relative $Path
            line = Get-LineNumber $Source $markerIndex
            symbol = $Symbol
        }
        evidence = @($Required)
        forbidden = @($Forbidden)
    }
}

function Split-TopLevel([string]$Text) {
    $output = [Collections.Generic.List[string]]::new()
    $start = 0
    $round = 0
    $curly = 0
    $square = 0
    $quote = [char]0
    $escape = $false
    for ($index = 0; $index -lt $Text.Length; ++$index) {
        $character = $Text[$index]
        if ($quote -ne [char]0) {
            if ($escape) { $escape = $false; continue }
            if ($character -eq '\') { $escape = $true; continue }
            if ($character -eq $quote) { $quote = [char]0 }
            continue
        }
        if ($character -eq [char]39 -and (Test-CppDigitSeparator $Text $index)) { continue }
        if ($character -eq '"' -or $character -eq "'") { $quote = $character; continue }
        switch ($character) {
            '(' { ++$round }
            ')' { --$round }
            '{' { ++$curly }
            '}' { --$curly }
            '[' { ++$square }
            ']' { --$square }
            ',' {
                if ($round -eq 0 -and $curly -eq 0 -and $square -eq 0) {
                    $output.Add($Text.Substring($start, $index - $start).Trim())
                    $start = $index + 1
                }
            }
        }
    }
    $output.Add($Text.Substring($start).Trim())
    return $output.ToArray()
}

function Get-HexContextCallInventory([string]$SourceRoot) {
    $contracts = [ordered]@{
        activate = 1
        focus_address = 3
        request_live_memory = 3
        close = 1
        active = 1
        source_name = 1
        render = 9
        last_error = 1
    }
    $counts = [ordered]@{}
    $callFiles = [Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    foreach ($name in $contracts.Keys) { $counts[$name] = 0 }
    $files = @(Get-ChildItem $SourceRoot -Recurse -File | Where-Object {
        $_.Extension -in @('.cpp', '.hpp', '.h')
    } | Sort-Object FullName)
    foreach ($file in $files) {
        $source = Get-Text $file.FullName
        foreach ($name in $contracts.Keys) {
            $marker = "hex_view::$name("
            $cursor = 0
            while ($cursor -lt $source.Length) {
                $index = $source.IndexOf($marker, $cursor, [StringComparison]::Ordinal)
                if ($index -lt 0) { break }
                $open = $index + $marker.Length - 1
                $close = Get-MatchingIndex $source $open '(' ')'
                $arguments = $source.Substring($open + 1, $close - $open - 1)
                $parts = if ([string]::IsNullOrWhiteSpace($arguments)) { @() } else {
                    @(Split-TopLevel $arguments | Where-Object { ![string]::IsNullOrWhiteSpace($_) })
                }
                if ($parts.Count -ne $contracts[$name]) {
                    $relative = Get-Relative $file.FullName
                    $line = Get-LineNumber $source $index
                    throw "Legacy hex context call shape in $relative`:$line for ${name}: expected $($contracts[$name]), observed $($parts.Count)"
                }
                $counts[$name] = [int]$counts[$name] + 1
                [void]$callFiles.Add($file.FullName)
                $cursor = $close + 1
            }
        }
    }
    foreach ($name in $contracts.Keys) {
        if ($counts[$name] -eq 0) { throw "Hex context API has no production callsites: $name" }
    }
    return [ordered]@{
        expected_argument_counts = $contracts
        observed_call_counts = $counts
        files = @($callFiles | Sort-Object | ForEach-Object { Get-Relative $_ })
        absolute_files = @($callFiles | Sort-Object)
    }
}

function Convert-CppStrings([string]$Expression) {
    $matches = [regex]::Matches($Expression, '(?:u8|u|U|L)?"(?:\\.|[^"\\])*"')
    if ($matches.Count -eq 0) { return $null }
    $builder = [Text.StringBuilder]::new()
    foreach ($match in $matches) {
        $literal = $match.Value
        $quoteIndex = $literal.IndexOf('"')
        $jsonLiteral = $literal.Substring($quoteIndex)
        try {
            $decoded = ConvertFrom-Json $jsonLiteral
        } catch {
            return $null
        }
        [void]$builder.Append([string]$decoded)
    }
    return $builder.ToString()
}

function Get-ModernShortcutSurface([string]$Path) {
    $source = Get-Text $Path
    $mask = Get-CppCodeMask $source $Path
    $bindings = [Collections.Generic.List[object]]::new()
    $identities = [Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
    $pattern = '\b(register_(?:(?:global|domain|widget|document|review)_)?shortcut|register_global_chord)\s*\('
    foreach ($match in [regex]::Matches($mask, $pattern)) {
        $open = $match.Index + $match.Value.LastIndexOf('(')
        $close = Get-MatchingIndex $source $open '(' ')'
        $arguments = @(Split-TopLevel $source.Substring($open + 1, $close - $open - 1))
        if ($arguments.Count -lt 5 -or $arguments[0].Trim() -ne 'rt') { continue }
        $bindingId = Convert-CppStrings ([string]$arguments[1])
        $actionId = Convert-CppStrings ([string]$arguments[2])
        if ([string]::IsNullOrEmpty($bindingId) -or [string]::IsNullOrEmpty($actionId)) {
            throw "Unresolved modern shortcut identity at $(Get-Relative $Path):$(Get-LineNumber $source $match.Index)"
        }
        if (!$identities.Add($bindingId)) { throw "Duplicate modern shortcut binding '$bindingId'" }
        $call = $match.Groups[1].Value
        $chordExpressions = [Collections.Generic.List[string]]::new()
        $displayIndex = 4
        if ($call -eq 'register_global_chord') {
            if ($arguments.Count -lt 6) { throw "Malformed shortcut chord '$bindingId'" }
            $chordExpressions.Add(([string]$arguments[3]).Trim())
            $chordExpressions.Add(([string]$arguments[4]).Trim())
            $displayIndex = 5
        } else {
            $chordExpressions.Add(([string]$arguments[3]).Trim())
        }
        $display = Convert-CppStrings ([string]$arguments[$displayIndex])
        if ([string]::IsNullOrEmpty($display)) { throw "Unresolved shortcut display '$bindingId'" }
        $keys = @($chordExpressions | ForEach-Object {
            @([regex]::Matches($_, 'ImGuiKey_[A-Za-z0-9_]+') | ForEach-Object { $_.Value })
        })
        if ($keys.Count -ne $chordExpressions.Count) {
            throw "Shortcut '$bindingId' does not bind exactly one key per stroke"
        }
        $bindings.Add([ordered]@{
            binding_id = $bindingId
            action_id = $actionId
            registration = $call
            chord_expressions = $chordExpressions.ToArray()
            keys = $keys
            display = $display
            source = [ordered]@{
                file = Get-Relative $Path
                line = Get-LineNumber $source $match.Index
            }
        })
    }
    if ($bindings.Count -lt 50) { throw 'Canonical shortcut registry regressed below 50 bindings' }
    return [ordered]@{
        binding_count = $bindings.Count
        bindings = @($bindings | Sort-Object @{ Expression = { [string]$_['binding_id'] } })
        source_files = @($Path)
    }
}

function Get-DefaultHints([string]$Description) {
    $hints = [Collections.Generic.List[string]]::new()
    foreach ($match in [regex]::Matches($Description, '(?i)\bdefault(?:s|ed)?(?:\s+to)?\s*[:=]?\s*([^.;,)]+)')) {
        $value = $match.Groups[1].Value.Trim()
        if ($value.Length -gt 0 -and !$hints.Contains($value)) { $hints.Add($value) }
    }
    return $hints.ToArray()
}

function Get-ParameterGroups([string]$Expression) {
    $parameters = [Collections.Generic.List[object]]::new()
    for ($index = 0; $index -lt $Expression.Length; ++$index) {
        if ($Expression[$index] -ne '{') { continue }
        try { $end = Get-MatchingIndex $Expression $index '{' '}' } catch { continue }
        $inner = $Expression.Substring($index + 1, $end - $index - 1)
        $fields = Split-TopLevel $inner
        if ($fields.Count -ge 4 -and $fields.Count -le 6) {
            $name = Convert-CppStrings $fields[0]
            $type = Convert-CppStrings $fields[1]
            $description = Convert-CppStrings $fields[2]
            $requiredText = $fields[3].Trim()
            if ($null -ne $name -and $null -ne $type -and $null -ne $description -and
                ($requiredText -eq 'true' -or $requiredText -eq 'false')) {
                $parameters.Add([ordered]@{
                    name = $name
                    type = $type
                    description = $description
                    required = $requiredText -eq 'true'
                    default_hints = @(Get-DefaultHints $description)
                })
            }
        }
    }
    $deduplicated = [Collections.Generic.List[object]]::new()
    $seen = @{}
    foreach ($parameter in $parameters) {
        if (!$seen.ContainsKey($parameter.name)) {
            $seen[$parameter.name] = $true
            $deduplicated.Add($parameter)
        }
    }
    return $deduplicated.ToArray()
}

function Resolve-ParameterExpression([string]$Expression, [string]$Source, [int]$Depth = 0) {
    if ($Depth -gt 8) { throw "Parameter resolver recursion exceeded" }
    $parameters = [Collections.Generic.List[object]]::new()
    foreach ($parameter in @(Get-ParameterGroups $Expression)) { $parameters.Add($parameter) }
    $trimmed = $Expression.Trim()
    if ($parameters.Count -eq 0 -and $trimmed -match '^(?:std::move\s*\(\s*)?([A-Za-z_]\w*)\s*\(\s*\)') {
        $functionName = $Matches[1]
        $definition = [regex]::Match($Source, "(?s)\b$([regex]::Escape($functionName))\s*\([^;{}]*\)\s*\{")
        if ($definition.Success) {
            $brace = $Source.IndexOf('{', $definition.Index)
            $end = Get-MatchingIndex $Source $brace '{' '}'
            $body = $Source.Substring($brace + 1, $end - $brace - 1)
            foreach ($baseCall in [regex]::Matches($body, '\b([A-Za-z_]\w*)\s*\(\s*\)\s*;')) {
                $candidate = $baseCall.Groups[1].Value
                if ($candidate -ne $functionName -and $candidate -notin @('clear', 'empty', 'size')) {
                    foreach ($parameter in @(Resolve-ParameterExpression "$candidate()" $Source ($Depth + 1))) {
                        $parameters.Add($parameter)
                    }
                    break
                }
            }
            foreach ($parameter in @(Get-ParameterGroups $body)) { $parameters.Add($parameter) }
        }
    }
    $deduplicated = [Collections.Generic.List[object]]::new()
    $seen = @{}
    foreach ($parameter in $parameters) {
        if (!$seen.ContainsKey($parameter.name)) {
            $seen[$parameter.name] = $true
            $deduplicated.Add($parameter)
        }
    }
    return $deduplicated.ToArray()
}

function Get-NameSet([string]$Source, [string]$FunctionName) {
    $match = [regex]::Match($Source, "(?s)\b$([regex]::Escape($FunctionName))\s*\([^;{}]*\)\s*\{")
    if (!$match.Success) { throw "Missing policy function $FunctionName" }
    $brace = $Source.IndexOf('{', $match.Index)
    $end = Get-MatchingIndex $Source $brace '{' '}'
    $body = $Source.Substring($brace + 1, $end - $brace - 1)
    return @([regex]::Matches($body, '"([A-Za-z0-9_.-]+)"') | ForEach-Object { $_.Groups[1].Value } | Sort-Object -Unique)
}

function Copy-JsonValue([object]$Value) {
    if ($null -eq $Value) { return $null }
    return (($Value | ConvertTo-Json -Depth 64 -Compress) | ConvertFrom-Json)
}

function Format-BoundedNameSet([string[]]$Values, [int]$Maximum = 64) {
    $ordered = @($Values | Sort-Object -Unique)
    $visible = @($ordered | Select-Object -First $Maximum | ForEach-Object {
        $value = [string]$_
        if ($value.Length -le 128) { $value } else { $value.Substring(0, 128) + '...' }
    })
    $suffix = if ($ordered.Count -gt $Maximum) {
        ',...+' + ($ordered.Count - $Maximum)
    } else { '' }
    return '[' + ($visible -join ',') + $suffix + ']'
}

function Assert-StringSetEqual([string[]]$Expected, [string[]]$Actual, [string]$Contract) {
    $expectedValues = @($Expected | Sort-Object -Unique)
    $actualValues = @($Actual | Sort-Object -Unique)
    $missing = @($expectedValues | Where-Object { $_ -notin $actualValues })
    $unexpected = @($actualValues | Where-Object { $_ -notin $expectedValues })
    if ($expectedValues.Count -ne $actualValues.Count) {
        throw "$Contract count mismatch: expected $($expectedValues.Count), observed $($actualValues.Count), missing=$(Format-BoundedNameSet $missing), unexpected=$(Format-BoundedNameSet $unexpected)"
    }
    for ($index = 0; $index -lt $expectedValues.Count; ++$index) {
        if (![string]::Equals($expectedValues[$index], $actualValues[$index],
                             [StringComparison]::Ordinal)) {
            throw "$Contract mismatch: expected '$($expectedValues[$index])', observed '$($actualValues[$index])', missing=$(Format-BoundedNameSet $missing), unexpected=$(Format-BoundedNameSet $unexpected)"
        }
    }
}

function Get-ToolDefinitionEntries([string]$Source, [string]$FunctionName,
                                   [string]$RelativePath) {
    $block = Get-SourceBlock $Source $FunctionName "tool definition list $FunctionName"
    $entries = [Collections.Generic.List[object]]::new()
    foreach ($match in [regex]::Matches($block.text,
        '\{\s*"([a-z][a-z0-9_]*)"\s*,\s*([A-Za-z_]\w*)')) {
        $entries.Add([ordered]@{
            name = $match.Groups[1].Value
            handler = $match.Groups[2].Value
            file = $RelativePath
            line = Get-LineNumber $Source ($block.block_index + $match.Index)
        })
    }
    if ($entries.Count -eq 0) { throw "No tool definitions found in $FunctionName" }
    return $entries.ToArray()
}

function Set-JsonProperty([object]$Object, [string]$Name, [object]$Value) {
    $Object | Add-Member -MemberType NoteProperty -Name $Name -Value $Value -Force
}

function Set-ScalarOrArraySchema([Collections.IDictionary]$Schemas,
                                 [string]$ToolName, [string]$PropertyName,
                                 [object]$ScalarSchema, [int]$MaximumItems) {
    $scalar = Copy-JsonValue $ScalarSchema
    $array = [ordered]@{
        type = 'array'
        items = Copy-JsonValue $scalar
        maxItems = $MaximumItems
    }
    Set-JsonProperty $Schemas[$ToolName].properties $PropertyName ([ordered]@{
        oneOf = @($scalar, $array)
    })
}

function Get-SchemaParameters([object]$Schema) {
    $required = [Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
    if ($null -ne $Schema.required) {
        foreach ($name in @($Schema.required)) { [void]$required.Add([string]$name) }
    }
    $parameters = [Collections.Generic.List[object]]::new()
    foreach ($property in $Schema.properties.PSObject.Properties) {
        $definition = $property.Value
        $type = if ($null -ne $definition.type) {
            [string]$definition.type
        } elseif ($null -ne $definition.oneOf) {
            'schema_union'
        } else {
            'schema'
        }
        $defaults = @()
        if ($null -ne $definition.PSObject.Properties['default']) {
            $defaults = @($definition.default)
        }
        $description = if ($null -ne $definition.description) {
            [string]$definition.description
        } else {
            'Exact property defined by the registered JSON input schema.'
        }
        $parameters.Add([ordered]@{
            name = $property.Name
            type = $type
            description = $description
            required = $required.Contains($property.Name)
            default_hints = $defaults
        })
    }
    return $parameters.ToArray()
}

function Get-C03CompatibilitySurface([string]$ContractsPath, [string]$EffectLedgerPath,
                                     [string]$ArchiveManifestPath,
                                     [string]$RegistrationPath,
                                     [string]$ServerIntegrationPath,
                                     [string]$ToolRegistrationPath,
                                     [string]$HandlerRoot,
                                     [string]$FixtureRoot) {
    $contractsDocument = Read-JsonObject $ContractsPath 'generated MCP contract ledger'
    $effectDocument = Read-JsonObject $EffectLedgerPath 'generated MCP effect ledger'
    $archiveManifest = Read-JsonObject $ArchiveManifestPath 'generated MCP archive manifest'
    if ([int]$contractsDocument.schema_version -ne 1 -or
        [int]$effectDocument.schema_version -ne 1 -or
        [int]$archiveManifest.schema_version -ne 1) {
        throw 'Generated MCP descriptor schema version is invalid'
    }
    $compatibilityNames = @($contractsDocument.compatibility_names | ForEach-Object { [string]$_ })
    $contractNames = @($contractsDocument.contracts | ForEach-Object { [string]$_.name })
    $effectNames = @($effectDocument.contracts | ForEach-Object { [string]$_.name })
    $manifestCompatibility = @($archiveManifest.compatibility_names | ForEach-Object { [string]$_ })
    $extensionNames = @($archiveManifest.aida_extensions | ForEach-Object { [string]$_ })
    $unionNames = @($archiveManifest.union_names | ForEach-Object { [string]$_ })
    Assert-StringSetEqual $compatibilityNames $contractNames 'generated MCP compatibility contracts'
    Assert-StringSetEqual $compatibilityNames $effectNames 'generated MCP effect contracts'
    Assert-StringSetEqual $compatibilityNames $manifestCompatibility 'generated MCP archive compatibility names'
    Assert-StringSetEqual (@($compatibilityNames + $extensionNames)) $unionNames 'generated MCP compatibility-extension union'
    if ($compatibilityNames.Count -ne 88 -or $extensionNames.Count -ne 4 -or
        $unionNames.Count -ne 92 -or [int]$archiveManifest.archive_tool_count -ne 88 -or
        [int]$archiveManifest.compatibility_tool_count -ne 88 -or
        [int]$archiveManifest.aida_extension_count -ne 4 -or
        [int]$archiveManifest.union_tool_count -ne 92) {
        throw 'Generated MCP compatibility cardinality is invalid'
    }
    if (@($contractsDocument.excluded_tools).Count -ne 1 -or
        [string]$contractsDocument.excluded_tools[0] -ne 'py_eval' -or
        @($archiveManifest.excluded_tools).Count -ne 1 -or
        [string]$archiveManifest.excluded_tools[0] -ne 'py_eval' -or
        $unionNames -contains 'py_eval' -or $unionNames -notcontains 'list_instances') {
        throw 'Generated MCP exclusion and proxy-local policy is invalid'
    }
    $expectedExtensions = @('analyze_funcs', 'find_insns', 'calculator', 'calculate')
    if (($extensionNames -join "`n") -ne ($expectedExtensions -join "`n")) {
        throw 'Generated MCP extension order is invalid'
    }

    $domains = [ordered]@{
        analysis = [ordered]@{
            names = @('decompile', 'disasm', 'func_profile', 'analyze_batch', 'xrefs_to',
                'xref_query', 'xrefs_to_field', 'callees', 'find_bytes', 'basic_blocks',
                'find', 'insn_query', 'export_funcs', 'callgraph')
            handler = 'analysis.cpp'
            handler_marker = 'analysis_handlers_t::invoke'
            fixture = 'analysis_handlers_harness.cpp'
            fixture_marker = 'run_analysis_handlers_harness'
        }
        composite = [ordered]@{
            names = @('analyze_function', 'analyze_component', 'diff_before_after', 'trace_data_flow')
            handler = 'composite.cpp'
            handler_marker = 'composite_handlers_t::invoke'
            fixture = 'composite_handlers_harness.cpp'
            fixture_marker = 'run_composite_handlers_harness'
        }
        core = [ordered]@{
            names = @('server_health', 'lookup_funcs', 'int_convert', 'list_funcs', 'func_query',
                'list_globals', 'entity_query', 'imports', 'imports_query', 'idb_save',
                'find_regex', 'search_text')
            handler = 'core.cpp'
            handler_marker = 'core_handlers_t::invoke'
            fixture = 'core_handlers_harness.cpp'
            fixture_marker = 'run_core_handlers_harness'
        }
        debugger = [ordered]@{
            names = @('dbg_start', 'dbg_status', 'dbg_exit', 'dbg_continue', 'dbg_run_to',
                'dbg_step_into', 'dbg_step_over', 'dbg_bps', 'dbg_add_bp', 'dbg_delete_bp',
                'dbg_toggle_bp', 'dbg_set_bp_condition', 'dbg_regs_all', 'dbg_regs_remote',
                'dbg_regs', 'dbg_gpregs_remote', 'dbg_gpregs', 'dbg_regs_named_remote',
                'dbg_regs_named', 'dbg_stacktrace', 'dbg_read', 'dbg_write')
            handler = 'debugger.cpp'
            handler_marker = 'debugger_handlers_t::invoke'
            fixture = 'debugger_handlers_harness.cpp'
            fixture_marker = 'run_debugger_handlers_harness'
        }
        memory = [ordered]@{
            names = @('get_bytes', 'get_int', 'get_string', 'get_global_value', 'patch', 'put_int')
            handler = 'memory.cpp'
            handler_marker = 'memory_handlers_t::invoke'
            fixture = 'memory_handlers_harness.cpp'
            fixture_marker = 'run_memory_handlers_harness'
        }
        modify = [ordered]@{
            names = @('add_bookmark', 'set_comments', 'append_comments', 'patch_asm', 'rename',
                'define_func', 'define_code', 'undefine', 'force_recompile', 'set_op_type', 'make_data')
            handler = 'modify.cpp'
            handler_marker = 'modify_handlers_t::invoke'
            fixture = 'modify_handlers_harness.cpp'
            fixture_marker = 'run_modify_handlers_harness'
        }
        python = [ordered]@{
            names = @('py_exec_file')
            handler = 'python.cpp'
            handler_marker = 'python_handlers_t::invoke'
            fixture = 'python_handler_harness.cpp'
            fixture_marker = 'run_python_handler_harness'
        }
        signatures = [ordered]@{
            names = @('make_signature', 'make_signature_for_function', 'make_signature_for_range',
                'find_xref_signatures')
            handler = 'signatures.cpp'
            handler_marker = 'is_signature_tool_name'
            fixture = 'signature_handlers_harness.cpp'
            fixture_marker = 'run_signature_handlers_harness'
        }
        stack = [ordered]@{
            names = @('stack_frame', 'declare_stack', 'delete_stack')
            handler = 'stack.cpp'
            handler_marker = 'stack_handlers_t::invoke'
            fixture = 'stack_handlers_harness.cpp'
            fixture_marker = 'run_stack_handlers_harness'
        }
        survey = [ordered]@{
            names = @('survey_binary')
            handler = 'survey.cpp'
            handler_marker = 'survey_handlers_t::invoke'
            fixture = 'survey_handler_harness.cpp'
            fixture_marker = 'run_survey_handler_harness'
        }
        types = [ordered]@{
            names = @('declare_type', 'enum_upsert', 'read_struct', 'search_structs', 'type_query',
                'type_inspect', 'set_type', 'type_apply_batch', 'infer_types')
            handler = 'types.cpp'
            handler_marker = 'types_handlers_t::invoke'
            fixture = 'type_handlers_harness.cpp'
            fixture_marker = 'run_type_handlers_harness'
        }
        routing_extensions = [ordered]@{
            names = @('list_instances', 'analyze_funcs', 'find_insns', 'calculator', 'calculate')
            handler = 'routing_extensions.cpp'
            handler_marker = 'routing_extension_tool_names'
            fixture = 'routing_extensions_harness.cpp'
            fixture_marker = 'run_routing_extensions_harness'
        }
    }

    $partitionNames = [Collections.Generic.List[string]]::new()
    $domainRecords = [Collections.Generic.List[object]]::new()
    $domainByName = @{}
    foreach ($domainName in $domains.Keys) {
        $domain = $domains[$domainName]
        $handlerPath = Join-Path $HandlerRoot $domain.handler
        $fixturePath = Join-Path $FixtureRoot $domain.fixture
        if (!(Test-Path -LiteralPath $handlerPath -PathType Leaf) -or
            !(Test-Path -LiteralPath $fixturePath -PathType Leaf)) {
            throw "MCP domain source is unavailable: $domainName"
        }
        $handlerSource = Get-Text $handlerPath
        $fixtureSource = Get-Text $fixturePath
        Assert-SourceContains $handlerSource @([string]$domain.handler_marker) "MCP $domainName production handler"
        Assert-SourceContains $fixtureSource @([string]$domain.fixture_marker) "MCP $domainName functional fixture"
        foreach ($name in @($domain.names)) {
            if ($domainByName.ContainsKey($name)) {
                throw "MCP compatibility domain partition contains duplicate '$name'"
            }
            $quoted = '"' + $name + '"'
            Assert-SourceContains $handlerSource @($quoted) "MCP $name production handler"
            Assert-SourceContains $fixtureSource @($quoted) "MCP $name functional fixture"
            $domainByName[$name] = $domainName
            $partitionNames.Add($name)
        }
        $domainRecords.Add([ordered]@{
            domain = $domainName
            names = @($domain.names)
            production_handler = Get-Relative $handlerPath
            handler_marker = [string]$domain.handler_marker
            functional_fixture = Get-Relative $fixturePath
            fixture_marker = [string]$domain.fixture_marker
        })
    }
    Assert-StringSetEqual $unionNames $partitionNames.ToArray() 'MCP production-handler fixture partition'

    $contractByName = @{}
    $archiveBackedNames = [Collections.Generic.List[string]]::new()
    foreach ($contract in @($contractsDocument.contracts)) {
        $name = [string]$contract.name
        if ($contractByName.ContainsKey($name)) { throw "Duplicate generated MCP contract '$name'" }
        $contractByName[$name] = $contract
        if ([bool]$contract.archive_backed) { $archiveBackedNames.Add($name) }
    }
    $proxyLocalNames = @($compatibilityNames | Where-Object { $_ -notin $archiveBackedNames })
    if ($archiveBackedNames.Count -ne 87 -or $proxyLocalNames.Count -ne 1 -or
        $proxyLocalNames[0] -ne 'list_instances') {
        throw 'Generated MCP archive-backed and proxy-local partition is invalid'
    }
    $effectByName = @{}
    foreach ($effect in @($effectDocument.contracts)) {
        $name = [string]$effect.name
        if ($effectByName.ContainsKey($name)) { throw "Duplicate generated MCP effect '$name'" }
        $effectByName[$name] = $effect
    }
    $registrationRecords = [Collections.Generic.List[object]]::new()
    foreach ($name in $compatibilityNames) {
        $contract = $contractByName[$name]
        $effect = $effectByName[$name]
        $adapterSymbol = [string]$contract.adapter_symbol
        $adapterSymbolValid = $adapterSymbol.StartsWith(
            'aida::standalone::mcp::compat::adapters::', [StringComparison]::Ordinal)
        if ($null -eq $contract.input_schema -or $null -eq $contract.output_schema -or
            $null -eq $contract.annotations -or !$adapterSymbolValid) {
            throw "Generated MCP contract is incomplete: $name"
        }
        foreach ($field in @('adapter_symbol', 'effect', 'lock', 'read_only', 'unsafe')) {
            if ((Convert-CanonicalJson $contract.$field) -ne (Convert-CanonicalJson $effect.$field)) {
                throw "Generated MCP contract/effect mismatch for $name field $field"
            }
        }
        if ([bool]$contract.routing.target_dependent -ne [bool]$effect.target_dependent) {
            throw "Generated MCP routing/effect mismatch for $name"
        }
        $routingFields = @($contract.routing.fields | ForEach-Object { [string]$_.name })
        Assert-StringSetEqual $routingFields @($effect.routing_fields | ForEach-Object { [string]$_ }) "Generated MCP routing fields for $name"
        $acceptsPid = $routingFields -contains 'pid'
        $acceptsBinName = $routingFields -contains 'bin_name'
        if ([bool]$contract.routing.target_dependent -and (!$acceptsPid -or !$acceptsBinName)) {
            throw "Target-dependent generated MCP contract lacks additive selectors: $name"
        }
        $domain = [string]$domainByName[$name]
        $domainRecord = $domains[$domain]
        $registrationRecords.Add([ordered]@{
            name = $name
            descriptor_source = Get-Relative $ContractsPath
            adapter_symbol = [string]$contract.adapter_symbol
            effect = [string]$contract.effect
            lock = [string]$contract.lock
            target_dependent = [bool]$contract.routing.target_dependent
            accepts_pid = $acceptsPid
            accepts_bin_name = $acceptsBinName
            read_only = [bool]$contract.read_only
            unsafe = [bool]$contract.unsafe
            production_handler = Get-Relative (Join-Path $HandlerRoot $domainRecord.handler)
            functional_fixture = Get-Relative (Join-Path $FixtureRoot $domainRecord.fixture)
            domain = $domain
        })
    }
    $extensionPolicies = [ordered]@{
        analyze_funcs = @('workspace_overlay_mutation', 'workspace_overlay_transaction', $true, $true, $false)
        find_insns = @('workspace_read', 'workspace_shared', $true, $true, $true)
        calculator = @('registry_read', 'registry_read', $false, $false, $true)
        calculate = @('registry_read', 'registry_read', $false, $false, $true)
    }
    foreach ($name in $extensionNames) {
        $policy = $extensionPolicies[$name]
        $domain = [string]$domainByName[$name]
        $domainRecord = $domains[$domain]
        $registrationRecords.Add([ordered]@{
            name = $name
            descriptor_source = (Get-Relative $RegistrationPath) + '#wave_c_extension_binding'
            adapter_symbol = 'aida::standalone::mcp::compat::adapters::' + $name
            effect = [string]$policy[0]
            lock = [string]$policy[1]
            target_dependent = [bool]$policy[2]
            accepts_pid = [bool]$policy[3]
            accepts_bin_name = [bool]$policy[3]
            read_only = [bool]$policy[4]
            unsafe = $false
            production_handler = Get-Relative (Join-Path $HandlerRoot $domainRecord.handler)
            functional_fixture = Get-Relative (Join-Path $FixtureRoot $domainRecord.fixture)
            domain = $domain
        })
    }

    $registrationSource = Get-Text $RegistrationPath
    $integrationSource = Get-Text $ServerIntegrationPath
    $toolRegistrationSource = Get-Text $ToolRegistrationPath
    Assert-SourceContains $toolRegistrationSource @('register_c03_compatibility_tools(srv);') 'C03 MCP production entry'
    Assert-SourceExcludes $toolRegistrationSource @('register_ida_compatibility_tools(srv)') 'C03 MCP production entry'
    Assert-SourceContains $registrationSource @(
        'integration->register_generated_tools();',
        'integration->register_extension_tools();',
        'names.size() != wave_c_compat::k_union_tool_count',
        'integration->registered_tool_count() != wave_c_compat::k_union_tool_count',
        'unique_names.find("list_instances") == unique_names.end()',
        'unique_names.find("py_eval") != unique_names.end()'
    ) 'C03 MCP generated registration'
    Assert-SourceContains $integrationSource @(
        'void mcp_server_integration_t::register_generated_tools()',
        'void mcp_server_integration_t::register_extension_tools()',
        'protocol::validate_tool_contract',
        'const auto input_validation = impl_->state.schemas.validate(',
        'const auto output_validation = impl_->state.schemas.validate('
    ) 'C03 MCP server integration'

    return [ordered]@{
        registration_count = $registrationRecords.Count
        archive_backed_count = $archiveBackedNames.Count
        proxy_local_count = $proxyLocalNames.Count
        extension_count = $extensionNames.Count
        union_names = @($unionNames)
        registrations = @($registrationRecords | Sort-Object name)
        domains = $domainRecords.ToArray()
        descriptor_artifacts = [ordered]@{
            contracts = [ordered]@{ path = Get-Relative $ContractsPath; sha256 = Get-FileSha256 $ContractsPath }
            effects = [ordered]@{ path = Get-Relative $EffectLedgerPath; sha256 = Get-FileSha256 $EffectLedgerPath }
            archive_manifest = [ordered]@{ path = Get-Relative $ArchiveManifestPath; sha256 = Get-FileSha256 $ArchiveManifestPath }
        }
        registration_source = Get-Relative $RegistrationPath
        server_integration_source = Get-Relative $ServerIntegrationPath
        source_files = @($RegistrationPath, $ServerIntegrationPath, $ToolRegistrationPath,
            $ContractsPath, $EffectLedgerPath, $ArchiveManifestPath) +
            @($domainRecords | ForEach-Object {
                Join-Path $RepositoryRoot $_.production_handler
                Join-Path $RepositoryRoot $_.functional_fixture
            })
    }
}

function Get-IdaCompatibilityInventory([string]$SchemaPath, [string]$ReadPath,
                                       [string]$MutationPath, [string]$RegistrationPath,
                                       [string]$GeneratedOverlapHandlerPath) {
    $schemaSource = Get-Text $SchemaPath
    $readSource = Get-Text $ReadPath
    $mutationSource = Get-Text $MutationPath
    $registrationSource = Get-Text $RegistrationPath
    $readNames = @(Get-NameSet $schemaSource 'read_only_tool_names')
    $mutationNames = @(Get-NameSet $schemaSource 'mutation_tool_names')
    $targetNames = @(Get-NameSet $schemaSource 'target_dependent_tool_names')
    $readEntries = @(Get-ToolDefinitionEntries $readSource 'get_read_tool_defs' (Get-Relative $ReadPath))
    $mutationEntries = @(Get-ToolDefinitionEntries $mutationSource 'get_mutation_tool_defs' (Get-Relative $MutationPath))
    Assert-StringSetEqual $readNames (@($readEntries.name) + @('list_instances', 'calculator', 'calculate')) 'IDA-compatible read registration set'
    Assert-StringSetEqual $mutationNames @($mutationEntries.name) 'IDA-compatible mutation registration set'
    Assert-StringSetEqual $targetNames (@($readEntries.name | Where-Object { $_ -ne 'int_convert' }) + @($mutationEntries.name)) 'IDA-compatible target-dependent registration set'

    Assert-SourceContains $registrationSource @(
        'register_c03_compatibility_tools(srv);'
    ) 'C03 compatibility production registration'
    Assert-SourceExcludes $registrationSource @(
        'register_ida_compatibility_tools(srv)',
        'install_ida_compat_schema_validation();'
    ) 'removed legacy IDA-compatible production registration'
    Assert-SourceContains $schemaSource @(
        's["calculator"] = s["calculate"];',
        'const json selector_bin_name = {',
        '{"minLength", 1}',
        '{"maxLength", 32768}',
        'const json selector_pid = {',
        '{"maximum", 4294967295ULL}',
        'const json aida_tx = {',
        'properties["bin_name"] = selector_bin_name;',
        'properties["pid"] = selector_pid;',
        's.at(tool_name).at("properties")["aida_tx"] = aida_tx;',
        's["lookup_funcs"]["properties"]["names"] = scalar_or_array_schema(',
        's["lookup_funcs"]["properties"]["addresses"] = scalar_or_array_schema(',
        's["set_comments"]["properties"]["items"] = scalar_or_array_schema(',
        's["declare_stack"]["properties"]["items"] = scalar_or_array_schema(',
        's["delete_stack"]["properties"]["offsets"] = scalar_or_array_schema(',
        's["infer_types"]["properties"]["items"] = scalar_or_array_schema(',
        's["analyze_funcs"]["properties"]["items"] = scalar_or_array_schema(',
        's["calculate"]["properties"]["variables"] = calculator_variables;',
        's["calculate"]["properties"]["items"]["items"]["properties"]["variables"]',
        's["calculate"]["properties"]["items"]["items"]["properties"]["mapping"]',
        's["calculate"]["properties"]["items"] = scalar_or_array_schema('
    ) 'IDA-compatible schema transforms'

    $schemas = [ordered]@{}
    $schemaPattern = 's\["(?<name>[a-z][a-z0-9_]*)"\]\s*=\s*json::parse\(R"(?<delimiter>[A-Za-z0-9_]*)\((?<body>.*?)\)\k<delimiter>"\s*\);'
    foreach ($match in [regex]::Matches($schemaSource, $schemaPattern,
        [Text.RegularExpressions.RegexOptions]::Singleline)) {
        $name = $match.Groups['name'].Value
        if ($schemas.Contains($name)) { throw "Duplicate IDA-compatible schema: $name" }
        try {
            $schema = $match.Groups['body'].Value | ConvertFrom-Json
        } catch {
            throw "Invalid source JSON schema for ${name}: $($_.Exception.Message)"
        }
        if ($schema.type -ne 'object' -or $null -eq $schema.properties -or
            $schema.additionalProperties -ne $false) {
            throw "IDA-compatible schema is not a closed object: $name"
        }
        $schemas[$name] = $schema
    }
    if (!$schemas.Contains('calculate')) { throw 'Missing IDA-compatible calculate schema' }
    $schemas['calculator'] = Copy-JsonValue $schemas['calculate']

    $selectorBinName = [ordered]@{
        type = 'string'
        minLength = 1
        maxLength = 32768
    }
    $selectorPid = [ordered]@{
        type = 'integer'
        minimum = 1
        maximum = 4294967295
    }
    $aidaTransaction = [ordered]@{
        oneOf = @(
            [ordered]@{ type = 'string'; minLength = 1; maxLength = 256 },
            [ordered]@{
                type = 'object'
                properties = [ordered]@{
                    id = [ordered]@{ type = 'string'; minLength = 1; maxLength = 256 }
                    transaction_id = [ordered]@{ type = 'string'; minLength = 1; maxLength = 256 }
                    expected_revision = [ordered]@{ type = 'integer'; minimum = 0 }
                    idempotency_key = [ordered]@{ type = 'string'; minLength = 1; maxLength = 256 }
                    dry_run = [ordered]@{ type = 'boolean' }
                }
                additionalProperties = $false
            }
        )
    }
    $calculatorIntegerValue = [ordered]@{
        oneOf = @(
            [ordered]@{ type = 'integer' },
            [ordered]@{ type = 'string'; minLength = 1; maxLength = 65536 }
        )
    }
    $calculatorVariableValue = [ordered]@{
        oneOf = @(
            [ordered]@{ type = 'integer' },
            [ordered]@{ type = 'string'; minLength = 1; maxLength = 65536 },
            [ordered]@{
                type = 'object'
                properties = [ordered]@{
                    integer = Copy-JsonValue $calculatorIntegerValue
                    bytes = [ordered]@{ type = 'string'; maxLength = 2097152 }
                    ascii = [ordered]@{ type = 'string'; maxLength = 1048576 }
                    utf8 = [ordered]@{ type = 'string'; maxLength = 1048576 }
                }
                anyOf = @(
                    [ordered]@{ required = @('integer') },
                    [ordered]@{ required = @('bytes') },
                    [ordered]@{ required = @('ascii') },
                    [ordered]@{ required = @('utf8') }
                )
                additionalProperties = $false
            }
        )
    }
    $calculatorVariables = [ordered]@{
        type = 'object'
        propertyNames = [ordered]@{ pattern = '^[A-Za-z_][A-Za-z0-9_]*$' }
        additionalProperties = $calculatorVariableValue
    }
    $calculatorMapping = Copy-JsonValue $schemas['calculate'].properties.mapping
    Set-JsonProperty $schemas['calculate'].properties 'variables' (Copy-JsonValue $calculatorVariables)
    Set-JsonProperty $schemas['calculate'].properties.items.items.properties 'variables' (Copy-JsonValue $calculatorVariables)
    Set-JsonProperty $schemas['calculate'].properties.items.items.properties 'mapping' $calculatorMapping
    foreach ($name in $targetNames) {
        if (!$schemas.Contains($name)) { throw "Target-dependent tool lacks source schema: $name" }
        Set-JsonProperty $schemas[$name].properties 'bin_name' (Copy-JsonValue $selectorBinName)
        Set-JsonProperty $schemas[$name].properties 'pid' (Copy-JsonValue $selectorPid)
    }
    foreach ($name in $mutationNames) {
        if (!$schemas.Contains($name)) { throw "Mutation tool lacks source schema: $name" }
        Set-JsonProperty $schemas[$name].properties 'aida_tx' (Copy-JsonValue $aidaTransaction)
    }

    Set-ScalarOrArraySchema $schemas 'lookup_funcs' 'names' $schemas['lookup_funcs'].properties.names.items 1000
    Set-ScalarOrArraySchema $schemas 'lookup_funcs' 'addresses' $schemas['lookup_funcs'].properties.addresses.items 1000
    Set-ScalarOrArraySchema $schemas 'set_comments' 'items' $schemas['set_comments'].properties.items.items 4096
    Set-ScalarOrArraySchema $schemas 'declare_stack' 'items' $schemas['declare_stack'].properties.items.items 4096
    Set-ScalarOrArraySchema $schemas 'delete_stack' 'offsets' ([ordered]@{ type = 'integer' }) 4096
    Set-ScalarOrArraySchema $schemas 'infer_types' 'items' $schemas['infer_types'].properties.items.items 4096
    Set-ScalarOrArraySchema $schemas 'analyze_funcs' 'items' $schemas['analyze_funcs'].properties.items.items 4096
    Set-ScalarOrArraySchema $schemas 'calculate' 'items' $schemas['calculate'].properties.items.items 128
    $schemas['calculator'] = Copy-JsonValue $schemas['calculate']

    $allNames = @($readNames + $mutationNames | Sort-Object -Unique)
    Assert-StringSetEqual $allNames @($schemas.Keys) 'IDA-compatible schema and registration set'
    $targetSet = [Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
    foreach ($name in $targetNames) { [void]$targetSet.Add($name) }
    $records = [Collections.Generic.List[object]]::new()
    foreach ($entry in $readEntries) {
        $records.Add([ordered]@{
            name = $entry.name
            description = "ida-pro-mcp compatible: $($entry.name)"
            read_only = $true
            workspace_aware = $targetSet.Contains($entry.name)
            source = $entry
            input_schema = $schemas[$entry.name]
        })
    }
    foreach ($entry in $mutationEntries) {
        $records.Add([ordered]@{
            name = $entry.name
            description = "ida-pro-mcp compatible mutation: $($entry.name)"
            read_only = $false
            workspace_aware = $true
            source = $entry
            input_schema = $schemas[$entry.name]
        })
    }
    $generatedOverlapSource = Get-Text $GeneratedOverlapHandlerPath
    $generatedOverlapHandlers = @{}
    foreach ($name in @('list_instances', 'calculator', 'calculate')) {
        $handler = Get-UniqueCodeDefinition $GeneratedOverlapHandlerPath `
            ('\bprotocol::mcp_result_t\s+' + [regex]::Escape($name) + '\s*\(') `
            "generated overlap adapter '$name'"
        $bodyText = $generatedOverlapSource.Substring(
            [int]$handler.body_start + 1,
            [int]$handler.body_end - [int]$handler.body_start - 1)
        $invokeMarker = 'handlers.invoke("' + $name + '"'
        if ($bodyText.IndexOf($invokeMarker, [StringComparison]::Ordinal) -lt 0) {
            throw "Generated overlap adapter route mismatch: name='$name', source='$($handler.file)', line=$($handler.line), offset=$($handler.character_offset), missing='$invokeMarker'"
        }
        $generatedOverlapHandlers[$name] = $handler
    }
    foreach ($name in @('list_instances', 'calculator', 'calculate')) {
        $handler = $generatedOverlapHandlers[$name]
        $description = switch ($name) {
            'list_instances' { 'List open AiDA analysis workspaces.' }
            'calculator' { 'ida-pro-mcp compatible calculator.' }
            default { 'Safe target-independent integer, bytes, hash, floating-point, and address mapping calculator' }
        }
        $records.Add([ordered]@{
            name = $name
            description = $description
            read_only = $true
            workspace_aware = $false
            source = [ordered]@{
                name = $name
                handler = 'aida::standalone::mcp::compat::adapters::' + $name
                file = [string]$handler.file
                line = [int]$handler.line
            }
            input_schema = $schemas[$name]
        })
    }
    return [ordered]@{
        records = @($records | Sort-Object name)
        schemas = $schemas
        read_only_names = $readNames
        mutation_names = $mutationNames
        target_dependent_names = $targetNames
        evidence_files = @($SchemaPath, $ReadPath, $MutationPath, $RegistrationPath,
            $GeneratedOverlapHandlerPath)
    }
}

function New-Registration([string]$Name, [string]$Description, [object[]]$Parameters,
                          [bool]$ReadOnly, [string]$Visibility, [string]$File,
                          [int]$Line, [string]$Evidence, [string]$ParameterExpression,
                          [bool]$WorkspaceAware, [int]$CharacterOffset = -1,
                          [object]$InputSchema = $null) {
    $registration = [ordered]@{
        name = $Name
        description = $Description
        parameters = @($Parameters)
        read_only = $ReadOnly
        visibility_declared = $Visibility
        visibility_effective = $Visibility
        source = [ordered]@{
            file = $File
            line = $Line
            character_offset = $CharacterOffset
            evidence = $Evidence
        }
        parameter_expression = ($ParameterExpression -replace '\s+', ' ').Trim()
        workspace_aware = $WorkspaceAware
    }
    if ($null -ne $InputSchema) {
        $registration.input_schema = $InputSchema
    }
    return $registration
}

function Get-RegistrationHelperName([string]$Source, [int]$Index) {
    foreach ($name in @('register_direct_alias', 'register_dispatch_alias')) {
        try {
            $block = Get-SourceBlock $Source ("void $name(") "MCP registration helper $name"
        } catch {
            continue
        }
        $end = $block.block_index + $block.text.Length
        if ($Index -ge $block.marker_index -and $Index -lt $end) {
            return $name
        }
    }
    return $null
}

function Get-CommandSurface([string]$Path) {
    $source = Get-Text $Path
    $builtins = Get-SourceBlock $source 'void register_builtins_locked(' 'built-in command registry'
    $names = [Collections.Generic.List[string]]::new()
    foreach ($match in [regex]::Matches($builtins.text, 'c\.name\s*=\s*"([^"]+)"\s*;')) {
        $names.Add($match.Groups[1].Value)
    }
    foreach ($match in [regex]::Matches($builtins.text,
        '\{\s*"([^"]+)"\s*,\s*"[^"]+"\s*,\s*"[^"]+"\s*\}')) {
        $names.Add($match.Groups[1].Value)
    }
    $unique = @($names | Sort-Object -Unique)
    if ($names.Count -ne 34 -or $unique.Count -ne 34) {
        throw 'Built-in command surface cardinality is invalid'
    }
    $rebuild = Get-SourceBlock $source 'void rebuild_locked()' 'command registry rebuild'
    Assert-SourceOrdered $rebuild.text @(
        'register_builtins_locked(dst);',
        'register_skills_locked(dst, taken_names);',
        'register_mcp_prompts_locked(dst, taken_names);',
        'register_mcp_tools_locked(dst, taken_names);',
        'register_agents_locked(dst, taken_names);'
    ) 'command registry producer order'
    return [ordered]@{
        builtin_count = $unique.Count
        builtin_names = $unique
        dynamic_producers = @('skills', 'mcp_prompts', 'mcp_tools', 'agents')
        source = Get-Relative $Path
        source_files = @($Path)
    }
}

function Get-TestLabSurface([string]$Root) {
    $records = [Collections.Generic.List[object]]::new()
    $keys = [Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
    $sourceFiles = [Collections.Generic.List[string]]::new()
    $macroCount = 0
    foreach ($file in @(Get-ChildItem -LiteralPath $Root -File -Filter 'test_lab_features*.cpp' |
        Sort-Object FullName)) {
        $source = Get-Text $file.FullName
        $matches = [regex]::Matches($source,
            '(?s)TESTLAB_REGISTER\s*\(\s*[^,]+,\s*"([^"]+)"\s*,\s*[^,]+,\s*"([^"]+)"')
        $allMacros = [regex]::Matches($source, 'TESTLAB_REGISTER\s*\(').Count
        if ($matches.Count -ne $allMacros) {
            throw "Unresolved Test Lab registration in $($file.FullName)"
        }
        if ($matches.Count -eq 0) { continue }
        $sourceFiles.Add($file.FullName)
        $macroCount += $matches.Count
        foreach ($match in $matches) {
            $category = $match.Groups[1].Value
            $name = $match.Groups[2].Value
            $key = $category + "`n" + $name
            if (!$keys.Add($key)) {
                throw "Duplicate Test Lab public feature '$category/$name'"
            }
            $records.Add([ordered]@{
                category = $category
                name = $name
                source = [ordered]@{
                    file = Get-Relative $file.FullName
                    line = Get-LineNumber $source $match.Index
                }
            })
        }
    }
    if ($macroCount -lt 68 -or $records.Count -ne $macroCount) {
        throw 'Test Lab public feature surface regressed below the historical baseline'
    }
    return [ordered]@{
        feature_count = $records.Count
        features = @($records | Sort-Object category, name)
        source_files = $sourceFiles.ToArray()
    }
}

function Get-WorkbenchSurface([string]$ContractsPath, [string]$ShellPath,
                              [string]$PersistencePath) {
    $contracts = Get-Text $ContractsPath
    $shell = Get-Text $ShellPath
    $persistence = Get-Text $PersistencePath
    $analysisKinds = @('disassembly', 'hex', 'pseudocode', 'graph', 'diff')
    foreach ($kind in $analysisKinds) {
        Assert-SourceContains $contracts @($kind + ' =') "workbench document kind $kind"
        Assert-SourceContains $shell @('document_kind_t::' + $kind) "workbench production document $kind"
    }
    Assert-SourceContains $shell @(
        'workbench_persistence_dto_t build_default_persistence(',
        'default_doc.identity.kind = document_kind_t::disassembly;',
        'workbench_shell_integration_t::make_default_for_analysis(',
        'workbench_shell_runtime_t::attach_analysis_workspace(',
        'output.disassembly_document = lifetime->documents->disassembly();',
        'output.hex_document = lifetime->documents->hex();',
        'output.pseudocode_document = lifetime->documents->pseudocode();',
        'output.graph_document = lifetime->documents->graph();',
        'output.diff_document = lifetime->documents->diff();',
        'persist_runtime_binding(binding);'
    ) 'workbench production shell integration'
    Assert-SourceContains $persistence @(
        '{"schema_version", std::to_string(dto.schema_version)}',
        '{"revision", std::to_string(dto.revision.value)}',
        '{"active_document", std::to_string(dto.active_document.value)}',
        'json payload_json_v10(const workbench_persistence_dto_t& dto)',
        '{"views", std::move(views)}',
        '{"panels", std::move(panels)}',
        'navigation_event_json(event)'
    ) 'workbench persistence codec'
    return [ordered]@{
        analysis_document_count = $analysisKinds.Count
        analysis_document_kinds = $analysisKinds
        default_analysis_document = 'disassembly'
        per_workspace_persistence = $true
        contracts_source = Get-Relative $ContractsPath
        shell_source = Get-Relative $ShellPath
        persistence_source = Get-Relative $PersistencePath
        source_files = @($ContractsPath, $ShellPath, $PersistencePath)
    }
}

function Get-OverlaySurface([string]$Path) {
    $source = Get-Text $Path
    $block = Get-SourceBlock $source 'enum class overlay_operation_kind_v9_t' 'overlay operation ordinals'
    $records = [Collections.Generic.List[object]]::new()
    foreach ($match in [regex]::Matches($block.text, '(?m)^\s*([A-Za-z_]\w*)\s*=\s*(\d+)\s*,?\s*$')) {
        $records.Add([ordered]@{
            name = $match.Groups[1].Value
            ordinal = [int]$match.Groups[2].Value
        })
    }
    if ($records.Count -ne 18) { throw 'Overlay operation cardinality is invalid' }
    for ($index = 0; $index -lt $records.Count; ++$index) {
        if ([int]$records[$index].ordinal -ne $index) {
            throw "Overlay operation ordinal is not contiguous at index $index"
        }
        Assert-SourceContains $source @(
            'static_assert(static_cast<std::uint8_t>(overlay_operation_kind_v9_t::' +
            [string]$records[$index].name + ') == ' + $index + ');'
        ) "overlay ordinal static assertion $index"
    }
    Assert-SourceContains $source @(
        'return ordinal <= static_cast<std::uint8_t>(overlay_operation_kind_v9_t::integer_patch);'
    ) 'legacy overlay ordinal preservation'
    return [ordered]@{
        operation_count = $records.Count
        legacy_ordinal_min = 0
        legacy_ordinal_max = 13
        appended_ordinal_min = 14
        appended_ordinal_max = 17
        operations = $records.ToArray()
        source = Get-Relative $Path
        source_files = @($Path)
    }
}

function Get-DeadPathSurface([string]$Root) {
    $retirements = @(
        [ordered]@{
            responsibility = 'production_mcp_registry_fixture'
            retired_paths = @(
                'src/standalone/tests/c03/driver_bridge_stub.cpp',
                'src/standalone/tests/c03/driver_bridge_stub.hpp',
                'src/standalone/tests/analysis_workspace/workspace_mcp_harness.cpp'
            )
            replacement_paths = @(
                'src/standalone/tests/c03/mcp_production_core/main.cpp',
                'src/standalone/tests/c03/mcp_production_core/mcp_production_core_harness.cpp',
                'src/standalone/tests/c03/mcp_production_core/mcp_production_core_harness.hpp'
            )
            cmake_markers = @(
                'TARGET aida_c03_mcp_production_core_harness PACKAGE D03 TIMEOUT 300',
                '${AIDA_C03_TEST_ROOT}/mcp_production_core/main.cpp',
                '${AIDA_C03_TEST_ROOT}/mcp_production_core/mcp_production_core_harness.cpp'
            )
        },
        [ordered]@{
            responsibility = 'combined_decompiler_quality_pipeline'
            retired_paths = @(
                'src/standalone/tests/c03/decompiler_provider_matrix/main.cpp',
                'src/standalone/tests/c03/decompiler_quality_scorer_harness_main.cpp',
                'cmake/c03_safe_headless/materialize_quality_selftest.py'
            )
            replacement_paths = @(
                'cmake/c03_safe_headless/decompiler_quality_pipeline_main.cpp',
                'src/standalone/tests/c03/decompiler_provider_matrix/provider_matrix.cpp',
                'src/standalone/tests/c03/decompiler_provider_matrix/provider_matrix.hpp',
                'src/standalone/tests/c03/decompiler_quality_scorer_harness.cpp',
                'src/standalone/tests/c03/decompiler_quality_scorer_harness.hpp'
            )
            cmake_markers = @(
                'TARGET aida_c03_a06_decompiler_quality_scorer_harness PACKAGE A06 ARGS_ENTRY',
                '${AIDA_C03_SAFE_HEADLESS_CMAKE_ROOT}/c03_safe_headless/decompiler_quality_pipeline_main.cpp',
                '${AIDA_C03_TEST_ROOT}/decompiler_provider_matrix/provider_matrix.cpp',
                '${AIDA_C03_TEST_ROOT}/decompiler_quality_scorer_harness.cpp'
            )
        }
    )
    $removed = @($retirements | ForEach-Object { @($_.retired_paths) } | Sort-Object -Unique)
    foreach ($path in $removed) {
        if (Test-Path -LiteralPath (Join-Path $Root $path)) {
            throw "Removed C03 path was restored: $path"
        }
    }
    $replacements = @($retirements | ForEach-Object { @($_.replacement_paths) } | Sort-Object -Unique)
    $replacementEvidence = [Collections.Generic.List[object]]::new()
    foreach ($path in $replacements) {
        $absolute = Join-Path $Root $path
        if (!(Test-Path -LiteralPath $absolute -PathType Leaf)) {
            throw "Required C03 replacement path is unavailable: $path"
        }
        $responsibilities = @($retirements | Where-Object { $_.replacement_paths -contains $path } |
            ForEach-Object { [string]$_.responsibility } | Sort-Object -Unique)
        $replacementEvidence.Add([ordered]@{
            path = $path
            sha256 = Get-FileSha256 $absolute
            responsibilities = $responsibilities
        })
    }
    $cmakePath = Join-Path $Root 'cmake\aida_c03_safe_headless_manifest.cmake'
    $cmakeSource = Get-Text $cmakePath
    $allCmakeMarkers = [Collections.Generic.List[string]]::new()
    foreach ($retirement in $retirements) {
        Assert-SourceContains $cmakeSource @($retirement.cmake_markers) `
            "C03 replacement graph $($retirement.responsibility)"
        foreach ($marker in @($retirement.cmake_markers)) {
            $allCmakeMarkers.Add([string]$marker)
        }
    }
    return [ordered]@{
        absent_paths = $removed
        replacement_paths = $replacements
        retirements = $retirements
        replacement_evidence = $replacementEvidence.ToArray()
        cmake_graph = [ordered]@{
            path = Get-Relative $cmakePath
            marker_count = @($allCmakeMarkers | Sort-Object -Unique).Count
            marker_sha256 = Get-StringListSha256 $allCmakeMarkers.ToArray()
        }
        source_files = @($replacements | ForEach-Object { Join-Path $Root $_ })
    }
}

$core = Join-Path $RepositoryRoot 'src\standalone\src\core'
$mcpPath = Join-Path $core 'mcp\mcp_standalone.cpp'
$mcpToolsPath = Join-Path $core 'mcp\mcp_standalone_tools.cpp'
$idaSchemaPath = Join-Path $core 'mcp\ida_compat_schemas.hpp'
$idaReadPath = Join-Path $core 'mcp\ida_compat_read.cpp'
$idaMutationPath = Join-Path $core 'mcp\ida_compat_mut.cpp'
$calculatorToolPath = Join-Path $core 'mcp\calculator_tool.cpp'
$decompilerServicePath = Join-Path $core 'analysis\workspace\decompiler_service.cpp'
$c03RegistrationPath = Join-Path $core 'mcp\compat\c03_compatibility_registration.cpp'
$c03ServerIntegrationPath = Join-Path $core 'mcp\compat\mcp_server_integration.cpp'
$standaloneChatPath = Join-Path $core 'ai\standalone_chat.cpp'
$c03HandlerRoot = Join-Path $core 'mcp\compat\handlers'
$c03FixtureRoot = Join-Path $RepositoryRoot 'src\standalone\tests\mcp_compat'
$c03DescriptorRoot = Join-Path $RepositoryRoot 'src\standalone\src\resources\mcp\ida_pro_mcp_2_0_0'
$c03ContractsPath = Join-Path $c03DescriptorRoot 'contracts.json'
$c03EffectLedgerPath = Join-Path $c03DescriptorRoot 'effect_ledger.json'
$c03ArchiveManifestPath = Join-Path $c03DescriptorRoot 'archive_manifest.json'
$mcpSource = Get-Text $mcpPath
$internalNames = @(Get-NameSet $mcpSource 'is_standalone_internal_only_tool_name')
$chatNames = @(Get-NameSet $mcpSource 'is_standalone_ide_chat_only_tool_name')
$browserNames = @(Get-NameSet $mcpSource 'is_camoufox_reverse_tool_name')
$registrations = [Collections.Generic.List[object]]::new()
$resolvedHelperEvidence = [Collections.Generic.List[object]]::new()
$unresolvedRegistrationEvidence = [Collections.Generic.List[object]]::new()
$sourceFiles = [Collections.Generic.List[string]]::new()

$files = @(Get-ChildItem $core -Recurse -File -Filter '*.cpp' | Sort-Object FullName)
foreach ($file in $files) {
    $source = Get-Text $file.FullName
    $codeMask = Get-CppCodeMask $source $file.FullName
    $relative = Get-Relative $file.FullName
    $fileContributed = $false
    $cursor = 0
    while ($cursor -lt $source.Length) {
        $match = [regex]::Match($codeMask, '\.register_tool\s*\(', [Text.RegularExpressions.RegexOptions]::None,
            [TimeSpan]::FromSeconds(2))
        if (!$match.Success) { break }
        $absolute = $cursor + $match.Index
        if ($cursor -gt 0) {
            $remaining = $codeMask.Substring($cursor)
            $match = [regex]::Match($remaining, '\.register_tool\s*\(')
            if (!$match.Success) { break }
            $absolute = $cursor + $match.Index
        }
        $open = $codeMask.IndexOf('(', $absolute)
        $close = Get-MatchingIndex $codeMask $open '(' ')'
        $argumentText = $source.Substring($open + 1, $close - $open - 1).Trim()
        $line = Get-LineNumber $source $absolute
        if ($argumentText.StartsWith('{')) {
            $initializerEnd = Get-MatchingIndex $argumentText 0 '{' '}'
            $fields = Split-TopLevel $argumentText.Substring(1, $initializerEnd - 1)
            if ($fields.Count -ge 5) {
                $name = Convert-CppStrings $fields[0]
                $description = Convert-CppStrings $fields[1]
                if ($null -ne $name -and $null -ne $description) {
                    $parameters = @(Resolve-ParameterExpression $fields[2] $source)
                    $readOnly = $fields[3].Trim() -eq 'true'
                    $trailingArguments = $argumentText.Substring($initializerEnd + 1).Trim()
                    $workspaceAware = $trailingArguments.StartsWith(',') -and
                        $trailingArguments.Substring(1).Trim().Length -gt 0
                    $visibility = if ($fields.Count -ge 6 -and $fields[5] -match 'internal_only') {
                        'internal_only'
                    } elseif ($fields.Count -ge 6 -and $fields[5] -match 'ide_chat_only') {
                        'ide_chat_only'
                    } else { 'external_visible' }
                    $registrationArgs = @{
                        Name = $name; Description = $description; Parameters = $parameters
                        ReadOnly = $readOnly; Visibility = $visibility; File = $relative
                        Line = $line; Evidence = 'direct_initializer'; ParameterExpression = $fields[2]
                        WorkspaceAware = $workspaceAware; CharacterOffset = $absolute
                    }
                    $registrations.Add((New-Registration @registrationArgs))
                    $fileContributed = $true
                } else {
                    $expression = ($fields[0] -replace '\s+', ' ').Trim()
                    $helperName = Get-RegistrationHelperName $codeMask $absolute
                    $record = [ordered]@{
                        file = $relative
                        line = $line
                        expression = $expression
                    }
                    if ($null -ne $helperName) {
                        $record.helper = $helperName
                        $resolvedHelperEvidence.Add($record)
                    } else {
                        $unresolvedRegistrationEvidence.Add($record)
                    }
                }
            }
        } elseif ($argumentText -match '^std::move\s*\(\s*([A-Za-z_]\w*)\s*\)') {
            $variable = $Matches[1]
            $prefix = $source.Substring(0, $absolute)
            $prefixMask = $codeMask.Substring(0, $absolute)
            $declarationMatches = [regex]::Matches($prefixMask, "(?:tool_def_t|mcp_standalone::tool_def_t)\s+$([regex]::Escape($variable))\b")
            if ($declarationMatches.Count -gt 0) {
                $segmentStart = $declarationMatches[$declarationMatches.Count - 1].Index
                $segment = $prefix.Substring($segmentStart)
                $segmentMask = $prefixMask.Substring($segmentStart)
                $nameMatches = [regex]::Matches($segmentMask, "$([regex]::Escape($variable))\.name\s*=\s*?([^;]+);")
                $descriptionMatches = [regex]::Matches($segmentMask, "$([regex]::Escape($variable))\.description\s*=\s*?([^;]+);")
                $paramsMatches = [regex]::Matches($segmentMask, "$([regex]::Escape($variable))\.params\s*=\s*?([^;]+);")
                $readOnlyMatches = [regex]::Matches($segmentMask, "$([regex]::Escape($variable))\.read_only\s*=\s*(true|false)\s*;")
                if ($nameMatches.Count -gt 0 -and $descriptionMatches.Count -gt 0 -and $readOnlyMatches.Count -gt 0) {
                    $nameGroup = $nameMatches[$nameMatches.Count - 1].Groups[1]
                    $descriptionGroup = $descriptionMatches[$descriptionMatches.Count - 1].Groups[1]
                    $name = Convert-CppStrings $segment.Substring($nameGroup.Index, $nameGroup.Length)
                    $description = Convert-CppStrings $segment.Substring($descriptionGroup.Index, $descriptionGroup.Length)
                    $parameterExpression = if ($paramsMatches.Count -gt 0) {
                        $group = $paramsMatches[$paramsMatches.Count - 1].Groups[1]
                        $segment.Substring($group.Index, $group.Length)
                    } else { '{}' }
                    if (![string]::IsNullOrWhiteSpace([string]$name) -and
                        ![string]::IsNullOrWhiteSpace([string]$description)) {
                        $parameters = @(Resolve-ParameterExpression $parameterExpression $source)
                        $readOnly = $readOnlyMatches[$readOnlyMatches.Count - 1].Groups[1].Value -eq 'true'
                        $registrationArgs = @{
                            Name = $name; Description = $description; Parameters = $parameters
                            ReadOnly = $readOnly; Visibility = 'external_visible'; File = $relative
                            Line = $line; Evidence = 'assigned_tool_definition'
                            ParameterExpression = $parameterExpression
                            WorkspaceAware = $false; CharacterOffset = $absolute
                        }
                        $registrations.Add((New-Registration @registrationArgs))
                        $fileContributed = $true
                    }
                }
            }
        }
        $cursor = $close + 1
    }

    $compatMatches = [regex]::Matches($codeMask,
        '(?<![.A-Za-z0-9_])register_compat\s*\(\s*srv\s*,')
    foreach ($match in $compatMatches) {
        $open = $codeMask.IndexOf('(', $match.Index)
        $close = Get-MatchingIndex $codeMask $open '(' ')'
        $line = Get-LineNumber $source $match.Index
        $arguments = @(Split-TopLevel $source.Substring($open + 1, $close - $open - 1))
        if ($arguments.Count -ne 2 -or $arguments[0].Trim() -ne 'srv') {
            throw "Invalid register_compat argument shape at $relative`:$line"
        }
        $initializer = $arguments[1].Trim()
        if (!$initializer.StartsWith('{', [StringComparison]::Ordinal)) {
            throw "register_compat requires a concrete aggregate initializer at $relative`:$line"
        }
        $initializerEnd = Get-MatchingIndex $initializer 0 '{' '}'
        if ($initializer.Substring($initializerEnd + 1).Trim().Length -ne 0) {
            throw "register_compat aggregate has trailing source tokens at $relative`:$line"
        }
        $fields = @(Split-TopLevel $initializer.Substring(1, $initializerEnd - 1))
        if ($fields.Count -ne 6) {
            throw "register_compat aggregate field count is $($fields.Count), expected 6 at $relative`:$line"
        }
        $name = Convert-CppStrings $fields[0]
        $category = Convert-CppStrings $fields[1]
        $description = Convert-CppStrings $fields[2]
        if ($null -eq $name -or $null -eq $description) {
            $compactFields = @($fields | ForEach-Object { ($_ -replace '\s+', '').Trim() })
            $fileDefinitions = @(Get-CppRegistrarDefinitions $file.FullName $source $codeMask $false)
            $owners = @($fileDefinitions | Where-Object {
                $match.Index -gt [int]$_.body_start -and $match.Index -lt [int]$_.body_end
            })
            $internalBridge = $owners.Count -eq 1 -and
                [string]$owners[0].bare_name -eq 'register_tool' -and
                [string]$category -eq 'web_vuln' -and
                $compactFields[0] -eq 'name' -and
                $compactFields[2] -eq 'description' -and
                $compactFields[3] -eq 'std::move(params)' -and
                $compactFields[4] -eq 'std::move(handler)' -and
                $compactFields[5] -eq 'read_only'
            if ($internalBridge) { continue }
            $unresolvedRegistrationEvidence.Add([ordered]@{
                file = $relative
                line = $line
                expression = ($initializer -replace '\s+', ' ').Trim()
            })
            continue
        }
        if ([string]::IsNullOrWhiteSpace($name) -or
            [string]::IsNullOrWhiteSpace($category) -or
            [string]::IsNullOrWhiteSpace($description) -or
            [string]::IsNullOrWhiteSpace($fields[4])) {
            throw "register_compat aggregate contains an empty required field at $relative`:$line"
        }
        $readOnlyText = $fields[5].Trim()
        if ($readOnlyText -notin @('true', 'false')) {
            throw "register_compat read_only is not a literal boolean at $relative`:$line"
        }
        $registrationArgs = @{
            Name = $name
            Description = $description
            Parameters = @(Resolve-ParameterExpression $fields[3] $source)
            ReadOnly = $readOnlyText -eq 'true'
            Visibility = 'external_visible'
            File = $relative
            Line = $line
            Evidence = 'compat_initializer'
            ParameterExpression = $fields[3]
            WorkspaceAware = $false
            CharacterOffset = $match.Index
        }
        $registrations.Add((New-Registration @registrationArgs))
        $fileContributed = $true
    }

    foreach ($wrapper in @('register_tool', 'register_direct_alias', 'register_dispatch_alias')) {
        $matches = [regex]::Matches($codeMask, "(?<![.A-Za-z0-9_])$wrapper\s*\(")
        foreach ($match in $matches) {
            $open = $codeMask.IndexOf('(', $match.Index)
            $close = Get-MatchingIndex $codeMask $open '(' ')'
            $after = $close + 1
            while ($after -lt $codeMask.Length -and [char]::IsWhiteSpace($codeMask[$after])) { ++$after }
            if ($after -lt $codeMask.Length -and $codeMask[$after] -eq '{') { continue }
            $arguments = Split-TopLevel $source.Substring($open + 1, $close - $open - 1)
            if ($arguments.Count -lt 3) { continue }
            $nameIndex = 1
            $descriptionIndex = if ($wrapper -eq 'register_direct_alias') { 3 } else { 2 }
            if ($arguments.Count -le $descriptionIndex) { continue }
            $name = Convert-CppStrings $arguments[$nameIndex]
            $description = Convert-CppStrings $arguments[$descriptionIndex]
            if ($null -eq $name -or $null -eq $description) { continue }
            $readOnlyIndex = -1
            for ($index = $arguments.Count - 1; $index -ge 0; --$index) {
                if ($arguments[$index].Trim() -in @('true', 'false')) { $readOnlyIndex = $index; break }
            }
            if ($readOnlyIndex -lt 0) { continue }
            if ($wrapper -eq 'register_tool') {
                $parameterExpression = $arguments[3]
            } elseif ($wrapper -eq 'register_direct_alias' -and $arguments.Count -gt 5) {
                $parameterExpression = $arguments[5]
            } else {
                $parameterExpression = 'passthrough_params()'
            }
            $parameters = @(Resolve-ParameterExpression $parameterExpression $source)
            $registrationArgs = @{
                Name = $name; Description = $description; Parameters = $parameters
                ReadOnly = ($arguments[$readOnlyIndex].Trim() -eq 'true')
                Visibility = 'external_visible'; File = $relative
                Line = (Get-LineNumber $source $match.Index); Evidence = "wrapper_$wrapper"
                ParameterExpression = $parameterExpression
                WorkspaceAware = $false; CharacterOffset = $match.Index
            }
            $registrations.Add((New-Registration @registrationArgs))
            $fileContributed = $true
        }
    }
    if ($fileContributed) { $sourceFiles.Add($file.FullName) }
}

$idaCompatibility = Get-IdaCompatibilityInventory $idaSchemaPath $idaReadPath `
    $idaMutationPath $mcpToolsPath (Join-Path $c03HandlerRoot 'routing_extensions.cpp')
$c03Compatibility = Get-C03CompatibilitySurface $c03ContractsPath $c03EffectLedgerPath `
    $c03ArchiveManifestPath $c03RegistrationPath $c03ServerIntegrationPath `
    $mcpToolsPath $c03HandlerRoot $c03FixtureRoot
$registeredNames = [Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
foreach ($registration in $registrations) {
    if (!$registeredNames.Add([string]$registration.name)) {
        throw "Duplicate statically resolved MCP registration: $($registration.name)"
    }
}
foreach ($record in $idaCompatibility.records) {
    if (!$registeredNames.Add([string]$record.name)) {
        throw "Duplicate dynamic MCP registration: $($record.name)"
    }
    $registrationArgs = @{
        Name = $record.name
        Description = $record.description
        Parameters = @(Get-SchemaParameters $record.input_schema)
        ReadOnly = [bool]$record.read_only
        Visibility = 'external_visible'
        File = $record.source.file
        Line = [int]$record.source.line
        Evidence = if ([string]$record.name -in @('list_instances', 'calculator', 'calculate')) {
            'source_resolved_generated_overlap_handler'
        } else { 'source_resolved_ida_compat_registration' }
        ParameterExpression = "ida_compat::find_schema(`"$($record.name)`")"
        WorkspaceAware = [bool]$record.workspace_aware
        InputSchema = $record.input_schema
    }
    $registrations.Add((New-Registration @registrationArgs))
}

$policyBinaryId = [ordered]@{
    name = 'binary_id'
    type = 'string'
    description = 'Optional session id to target (returned by `sessions_manage` action=list). When omitted the active session is used.'
    required = $false
    default_hints = @()
}
$workspaceBinaryId = [ordered]@{
    name = 'binary_id'
    type = 'string'
    description = 'Optional immutable workspace binary id. When all selectors are omitted exactly one open workspace must exist; otherwise TARGET_REQUIRED is returned.'
    required = $false
    default_hints = @()
}
$workspaceBinName = [ordered]@{
    name = 'bin_name'
    type = 'string'
    description = 'Optional exact workspace name or unique substring. Mutually exclusive with binary_id and pid.'
    required = $false
    default_hints = @()
}
$workspacePid = [ordered]@{
    name = 'pid'
    type = 'integer'
    description = 'Optional positive live target PID. Mutually exclusive with binary_id and bin_name.'
    required = $false
    default_hints = @()
}
foreach ($registration in $registrations) {
    if ($registration.name -in $chatNames) { $registration.visibility_effective = 'ide_chat_only' }
    elseif ($registration.name -in $internalNames) { $registration.visibility_effective = 'internal_only' }
    $hasBinary = @($registration.parameters | Where-Object { $_.name -eq 'binary_id' }).Count -ne 0
    $targetless = $registration.name.StartsWith('sessions_', [StringComparison]::Ordinal) -or
        $registration.name -eq 'list_instances' -or
        $registration.name -eq 'get_tool_descriptions' -or $registration.name -in $browserNames
    if (!$hasBinary -and !$targetless) {
        $registration.parameters = @($registration.parameters) + @(
            $(if ($registration.workspace_aware) { $workspaceBinaryId } else { $policyBinaryId }))
    }
    if ($registration.workspace_aware) {
        $hasBinName = @($registration.parameters | Where-Object { $_.name -eq 'bin_name' }).Count -ne 0
        $hasPid = @($registration.parameters | Where-Object { $_.name -eq 'pid' }).Count -ne 0
        if (!$hasBinName) {
            $registration.parameters = @($registration.parameters) + @($workspaceBinName)
        }
        if (!$hasPid) {
            $registration.parameters = @($registration.parameters) + @($workspacePid)
        }
    }
}

$registrations = @($registrations | Sort-Object @{Expression='name';Ascending=$true},
    @{Expression={$_.source.file};Ascending=$true}, @{Expression={$_.source.line};Ascending=$true})
$duplicateNames = @($registrations | Group-Object -Property { $_.name } |
    Where-Object Count -gt 1 |
    ForEach-Object { [ordered]@{ name = $_.Name; registrations = $_.Count } } | Sort-Object name)
$resolvedHelperRecords = [Collections.Generic.List[object]]::new()
foreach ($helper in $resolvedHelperEvidence) {
    $evidenceName = 'wrapper_' + [string]$helper.helper
    $concrete = @($registrations | Where-Object {
        [string]$_.source.file -eq [string]$helper.file -and
        [string]$_.source.evidence -eq $evidenceName
    } | Sort-Object name)
    if ([string]$helper.expression -ne 'alias' -or $concrete.Count -eq 0) {
        throw "MCP registration helper has no concrete source-resolved registrations: $($helper.helper)"
    }
    $resolvedHelperRecords.Add([ordered]@{
        helper = [string]$helper.helper
        file = [string]$helper.file
        line = [int]$helper.line
        expression = [string]$helper.expression
        concrete_registration_count = $concrete.Count
        concrete_registration_names = @($concrete.name)
    })
}
if ($unresolvedRegistrationEvidence.Count -ne 0) {
    $detail = @($unresolvedRegistrationEvidence | ForEach-Object {
        "$($_.file):$($_.line):$($_.expression)"
    }) -join ', '
    throw "Unresolved public MCP registrations remain: $detail"
}
$resolvedHelperNames = @($resolvedHelperRecords.helper | Sort-Object)
$resolvedHelperRegistrationCount = [int](($resolvedHelperRecords | ForEach-Object {
    [int]$_.concrete_registration_count
} | Measure-Object -Sum).Sum)
$expectedResolvedHelperNames = @('register_direct_alias', 'register_dispatch_alias') | Sort-Object
if (($resolvedHelperNames -join "`n") -ne ($expectedResolvedHelperNames -join "`n") -or
    $resolvedHelperRegistrationCount -ne 110) {
    throw 'MCP registration helper provenance cardinality is invalid'
}
$resolvedRegistrationNames = @($registrations.name | Sort-Object -Unique)
$c03UnionNames = @($c03Compatibility.union_names | Sort-Object -Unique)
$c03OverlapNames = @($c03UnionNames | Where-Object { $_ -in $resolvedRegistrationNames } | Sort-Object)
$c03GeneratedOnlyNames = @($c03UnionNames | Where-Object { $_ -notin $resolvedRegistrationNames } | Sort-Object)
$effectiveRegistrationNames = @($resolvedRegistrationNames + $c03UnionNames | Sort-Object -Unique)
if ($resolvedRegistrationNames.Count -ne $registrations.Count -or
    $c03UnionNames.Count -ne 92 -or
    ($c03OverlapNames.Count + $c03GeneratedOnlyNames.Count) -ne $c03UnionNames.Count -or
    $effectiveRegistrationNames.Count -ne ($resolvedRegistrationNames.Count + $c03GeneratedOnlyNames.Count)) {
    throw 'MCP resolved/generated/effective registration cardinality is invalid'
}
$mcpProductionReachability = Get-McpProductionReachability $files $registrations `
    $c03Compatibility.registrations $standaloneChatPath $mcpToolsPath $mcpPath $c03RegistrationPath `
    $c03ServerIntegrationPath

$resourceMatches = [regex]::Matches($mcpSource, '\{"uri",\s*"([^"]+)"\}\s*,\s*\r?\n?\s*\{"name",\s*"([^"]+)"\}\s*,\s*\r?\n?\s*\{"description",\s*"([^"]+)"\}\s*,\s*\r?\n?\s*\{"mimeType",\s*"([^"]+)"\}')
$resources = [Collections.Generic.List[object]]::new()
foreach ($match in $resourceMatches) {
    $uri = $match.Groups[1].Value
    $fields = if ($uri -eq 'standalone://driver-status') { @('ready', 'attached_pid', 'status') } else { @('info') }
    $resources.Add([ordered]@{
        uri = $uri
        name = $match.Groups[2].Value
        description = $match.Groups[3].Value
        mime_type = $match.Groups[4].Value
        result_fields = $fields
        source = [ordered]@{ file = Get-Relative $mcpPath; line = Get-LineNumber $mcpSource $match.Index }
    })
}

$globalsPath = Join-Path $RepositoryRoot 'src\standalone\src\helpers\globals.h'
$helpersPath = Join-Path $RepositoryRoot 'src\standalone\src\helpers\helpers.cpp'
$sessionHeaderPath = Join-Path $core 'session\analysis_session.hpp'
$sessionSourcePath = Join-Path $core 'session\analysis_session.cpp'
$workspaceRegistryPath = Join-Path $core 'analysis\workspace\workspace_registry.cpp'
$driverIdentityPath = Join-Path $core 'runtime\standalone_driver_identity.hpp'
$driverSourcePath = Join-Path $core 'runtime\standalone_driver.cpp'
$hexHeaderPath = Join-Path $core 'editor\hex_view.hpp'
$hexSourcePath = Join-Path $core 'editor\hex_view.cpp'
$fileBrowserPath = Join-Path $RepositoryRoot 'src\standalone\src\helpers\file_browser.cpp'
$mainPath = Join-Path $RepositoryRoot 'src\standalone\src\main.cpp'
$applicationUiRuntimePath = Join-Path $core 'ui\application_ui_runtime.cpp'
$commandRegistryPath = Join-Path $core 'ai\command_registry.cpp'
$testLabRoot = Join-Path $core 'testlab'
$workbenchContractsPath = Join-Path $core 'workbench\workbench_contracts.h'
$workbenchShellPath = Join-Path $core 'workbench\workbench_shell_integration.cpp'
$workbenchPersistencePath = Join-Path $core 'workbench\workbench_persistence.cpp'
$overlayApplyHeaderPath = Join-Path $core 'analysis\overlay_apply_engine.hpp'
$globalsSource = Get-Text $globalsPath
$helpersSource = Get-Text $helpersPath
$sessionHeader = Get-Text $sessionHeaderPath
$sessionSource = Get-Text $sessionSourcePath
$workspaceRegistrySource = Get-Text $workspaceRegistryPath
$driverIdentitySource = Get-Text $driverIdentityPath
$driverSource = Get-Text $driverSourcePath
$hexHeaderSource = Get-Text $hexHeaderPath
$hexSource = Get-Text $hexSourcePath
$fileBrowserSource = Get-Text $fileBrowserPath
$mainSource = Get-Text $mainPath
$applicationUiRuntimeSource = Get-Text $applicationUiRuntimePath
$modernShortcutSurface = Get-ModernShortcutSurface $applicationUiRuntimePath
$commandSurface = Get-CommandSurface $commandRegistryPath
$testLabSurface = Get-TestLabSurface $testLabRoot
$workbenchSurface = Get-WorkbenchSurface $workbenchContractsPath $workbenchShellPath `
    $workbenchPersistencePath
$overlaySurface = Get-OverlaySurface $overlayApplyHeaderPath
$deadPathSurface = Get-DeadPathSurface $RepositoryRoot

$centerMatch = [regex]::Match($globalsSource, '(?s)enum\s+class\s+center_view_t[^\{]*\{([^}]+)\}')
$centerViews = @()
if ($centerMatch.Success) {
    $centerViews = @($centerMatch.Groups[1].Value -split ',' | ForEach-Object {
        ($_ -replace '=.*$', '').Trim()
    } | Where-Object { $_ -match '^[A-Za-z_]\w*$' })
}
$uiActions = [Collections.Generic.List[object]]::new()
foreach ($match in [regex]::Matches($helpersSource, '(?:ImGui::MenuItem|ImGui::Button|ImGui::SmallButton|\bmenu_item)\s*\(\s*("(?:\\.|[^"\\])*")')) {
    $label = Convert-CppStrings $match.Groups[1].Value
    if ($null -ne $label) {
        $uiActions.Add([ordered]@{ label = $label; line = Get-LineNumber $helpersSource $match.Index })
    }
}
foreach ($match in [regex]::Matches($applicationUiRuntimeSource,
    '\bregister_view\s*\(\s*("(?:\\.|[^"\\])*")\s*,\s*("(?:\\.|[^"\\])*")')) {
    $label = Convert-CppStrings $match.Groups[2].Value
    if ($null -ne $label) {
        $uiActions.Add([ordered]@{ label = $label; line = Get-LineNumber $applicationUiRuntimeSource $match.Index })
    }
}
$uiActions = @($uiActions | Sort-Object `
    @{ Expression = { [string]$_['label'] } },
    @{ Expression = { [int]$_['line'] } } -Unique)
$shortcuts = [Collections.Generic.List[object]]::new()
$shortcutSourceFiles = [Collections.Generic.List[string]]::new()
$shortcutRoot = Join-Path $RepositoryRoot 'src\standalone\src'
$shortcutFiles = @(Get-ChildItem -LiteralPath $shortcutRoot -Recurse -File | Where-Object {
    $_.Extension -in @('.cpp', '.h', '.hpp')
} | Sort-Object FullName)
foreach ($file in $shortcutFiles) {
    $shortcutSource = Get-Text $file.FullName
    if ([string]::IsNullOrEmpty($shortcutSource)) { continue }
    if ($shortcutSource.IndexOf('ImGuiKey_', [StringComparison]::Ordinal) -lt 0) { continue }
    $shortcutMask = Get-CppCodeMask $shortcutSource $file.FullName
    $matches = [regex]::Matches($shortcutMask, 'ImGuiKey_[A-Za-z0-9_]+')
    if ($matches.Count -eq 0) { continue }
    $shortcutSourceFiles.Add($file.FullName)
    foreach ($match in $matches) {
        $lineStart = $shortcutSource.LastIndexOf("`n", $match.Index)
        $lineEnd = $shortcutSource.IndexOf("`n", $match.Index)
        if ($lineStart -lt 0) { $lineStart = 0 } else { ++$lineStart }
        if ($lineEnd -lt 0) { $lineEnd = $shortcutSource.Length }
        $shortcuts.Add([ordered]@{
            key = $match.Value
            line = Get-LineNumber $shortcutSource $match.Index
            expression = ($shortcutSource.Substring($lineStart, $lineEnd - $lineStart) -replace '\s+', ' ').Trim()
            source = Get-Relative $file.FullName
        })
    }
}
$requiredShortcutBindingIds = @(
    'binding.editor.save', 'binding.editor.copy', 'binding.editor.select_all',
    'binding.editor.next_document_or_session', 'binding.editor.previous_document_or_session',
    'binding.global.new', 'binding.global.explorer', 'binding.global.chat',
    'binding.global.output', 'binding.global.network', 'binding.global.debugger',
    'binding.global.scan', 'binding.global.binary_map', 'binding.global.command_palette',
    'binding.global.workspace_search', 'binding.global.preferences', 'binding.global.xrefs',
    'binding.global.deobfuscation', 'binding.global.shell.maximize',
    'binding.analysis.decompile', 'binding.output.copy_all', 'binding.output.select_all'
)
$sessionDeclarationSurface = [regex]::Replace($sessionHeader, '=\s*\{\s*\}', '= default_value')
$sessionMethods = @([regex]::Matches($sessionDeclarationSurface, '(?m)^\s*(?:static\s+)?[A-Za-z_:][A-Za-z0-9_:<>,\s*&]*\s+([A-Za-z_]\w*)\s*\([^;{}]*\)\s*(?:const\s*)?(?:noexcept\s*)?;') |
    ForEach-Object { $_.Groups[1].Value } | Sort-Object -Unique)

$sourceContracts = [Collections.Generic.List[object]]::new()
$contractArgs = @{
    Id = 'explicit_workspace_persistence'
    Path = $sessionSourcePath
    Source = $sessionSource
    Marker = 'acquire_static_workspace(const std::string& path,'
    Symbol = 'analysis_session::acquire_static_workspace'
    Occurrence = 2
    Required = @(
        'if (cancel.stop_requested())',
        'workspace_registry().open_static(request, cancel)',
        'static_workspace_gate(workspace->identity().binary_id().to_hex())',
        'install_workspace_services(workspace, database)',
        'reopen_persisted_analysis(workspace, database, cancel)',
        'baseline_analysis_service_t::start(workspace, settings,',
        'cancel.deadline()'
    )
    Ordered = $true
    Block = $true
}
$sourceContracts.Add((Get-SourceContractRecord @contractArgs))
$contractArgs = @{
    Id = 'persisted_snapshot_publication'
    Path = $sessionSourcePath
    Source = $sessionSource
    Marker = 'workspace_result_t<bool> reopen_persisted_analysis('
    Symbol = 'analysis_session::reopen_persisted_analysis'
    Required = @(
        'database->load_snapshot(workspace->normalized_image(), workspace->image(), cancel)',
        'snapshot->generation != workspace->generation()',
        'snapshot->overlay_revision != workspace->overlay_revision()',
        'database->load_search_products(',
        'persisted_products.search_index_blob.empty()',
        'search_index_t::build(',
        'restore_persisted_search_index(',
        'if (cancel.stop_requested())',
        'workspace->publish_analysis_bundle(workspace->generation()'
    )
    Ordered = $true
    Block = $true
}
$sourceContracts.Add((Get-SourceContractRecord @contractArgs))
$contractArgs = @{
    Id = 'session_cancellation_lifetime'
    Path = $sessionSourcePath
    Source = $sessionSource
    Marker = 'bool cancel_session(size_t idx)'
    Symbol = 'analysis_session::cancel_session'
    Required = @(
        'session.load_cancellation.request_cancel()',
        'session.open_task_id.reset()',
        'session.baseline_job.reset()',
        'aida::infra::executor::cancel(*open_task_id)',
        'aida::infra::taskflow_runtime::cancel(*baseline_job)',
        'workspace->request_cancel()'
    )
    Ordered = $true
    Block = $true
}
$sourceContracts.Add((Get-SourceContractRecord @contractArgs))
$contractArgs = @{
    Id = 'transactional_session_selection'
    Path = $sessionSourcePath
    Source = $sessionSource
    Marker = 'bool activate_session_transaction(size_t idx, std::string* out_error)'
    Symbol = 'analysis_session::activate_session_transaction'
    Required = @(
        'std::lock_guard<std::recursive_mutex> activation_lock(state().activation_mutex)',
        'validate_live_session_binding(session->id, workspace, &live_binding, error)',
        'ensure_driver_active_for_session(session->attached_pid',
        'validate_live_session_binding(session->id, workspace, &live_binding, error)',
        'workspace_registry().select_for_ui(workspace->identity().binary_id())',
        'candidate->ui_selected = false',
        'session->ui_selected = true',
        'state().active_idx = static_cast<int>(idx)'
    )
    Ordered = $true
    Block = $true
}
$sourceContracts.Add((Get-SourceContractRecord @contractArgs))
$contractArgs = @{
    Id = 'live_pid_creation_identity_capture'
    Path = $driverSourcePath
    Source = $driverSource
    Marker = 'bool capture_identity_impl(std::uint32_t pid, std::uint64_t preferred_module_base,'
    Symbol = 'driver_bridge::identity::capture_identity_impl'
    Required = @(
        'OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | SYNCHRONIZE',
        'GetExitCodeProcess(process, &exit_code)',
        'GetProcessTimes(process, &creation, &exit, &kernel, &user)',
        'QueryFullProcessImageNameW(process',
        'CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32',
        'out.process.creation_time_100ns = filetime_to_u64(creation)',
        'out.module.base = selected->base',
        'out_staleness = staleness_t::none'
    )
    Ordered = $true
    Block = $true
}
$sourceContracts.Add((Get-SourceContractRecord @contractArgs))
$contractArgs = @{
    Id = 'live_pid_staleness_validation'
    Path = $driverSourcePath
    Source = $driverSource
    Marker = 'validation_result_t validate_live_target_identity(const live_target_identity_t& expected)'
    Symbol = 'driver_bridge::identity::validate_live_target_identity'
    Required = @(
        'capture_identity_impl(expected.process.pid, expected.module.base',
        'result.observed.process.creation_time_100ns != expected.process.creation_time_100ns',
        'result.staleness = staleness_t::process_identity_changed',
        'result.observed.module.base != expected.module.base',
        'result.staleness = staleness_t::module_identity_changed',
        'result.matches = true'
    )
    Ordered = $true
    Block = $true
}
$sourceContracts.Add((Get-SourceContractRecord @contractArgs))
$contractArgs = @{
    Id = 'live_pid_registry_reuse_rejection'
    Path = $workspaceRegistryPath
    Source = $workspaceRegistrySource
    Marker = 'workspace_registry_t::resolve('
    Symbol = 'aida::analysis::workspace_registry_t::resolve'
    Required = @(
        'selector.process_creation_time_100ns && !selector.pid',
        'process->creation_time_100ns != *selector.process_creation_time_100ns',
        'pid_exists_with_other_creation = true',
        'workspace_error_code_t::target_stale',
        'PID was reused by a different process identity'
    )
    Ordered = $true
    Block = $true
}
$sourceContracts.Add((Get-SourceContractRecord @contractArgs))
$contractArgs = @{
    Id = 'live_session_identity_publication'
    Path = $sessionSourcePath
    Source = $sessionSource
    Marker = 'bool open_attach_session('
    Occurrence = 2
    Symbol = 'analysis_session::open_attach_session'
    Required = @(
        'capture_live_target_identity(pid, 0, source_identity',
        'ensure_driver_active_for_session(pid',
        'request.snapshot.pid = pid',
        'workspace_registry().open_live(request)',
        'make_live_session_binding(source_identity, workspace',
        'driver_bridge::identity::validate_live_target_identity(',
        'source_identity)',
        'provider->validate_current_identity()',
        'activate_session_transaction(session_index'
    )
    Ordered = $true
    Block = $true
}
$sourceContracts.Add((Get-SourceContractRecord @contractArgs))
$contractArgs = @{
    Id = 'live_identity_contract_shape'
    Path = $driverIdentityPath
    Source = $driverIdentitySource
    Marker = 'struct process_creation_identity_t'
    Symbol = 'driver_bridge::identity::process_creation_identity_t'
    Required = @(
        'std::uint32_t pid = 0;',
        'std::uint64_t creation_time_100ns = 0;',
        'std::string normalized_process_path;',
        'process_identity_changed',
        'module_identity_changed',
        'validate_live_target_identity(const live_target_identity_t& expected)'
    )
}
$sourceContracts.Add((Get-SourceContractRecord @contractArgs))
$contractArgs = @{
    Id = 'hex_explicit_workspace_api'
    Path = $hexHeaderPath
    Source = $hexHeaderSource
    Marker = 'namespace hex_view'
    Symbol = 'hex_view public API'
    Required = @(
        'void activate(const disasm_view::workspace_context_t& context);',
        'bool focus_address(const disasm_view::workspace_context_t& context,',
        'bool request_live_memory(const disasm_view::workspace_context_t& context,',
        'void close(const disasm_view::workspace_context_t& context);',
        'bool active(const disasm_view::workspace_context_t& context);',
        'std::string source_name(const disasm_view::workspace_context_t& context);',
        'std::string last_error(const disasm_view::workspace_context_t& context);'
    )
    Forbidden = @('void activate();', 'void close();', 'bool active();')
}
$sourceContracts.Add((Get-SourceContractRecord @contractArgs))
Assert-SourceExcludes $hexSource @('analysis_session::active_workspace()') 'hex explicit workspace ownership'
$contractArgs = @{
    Id = 'hex_workspace_lifecycle'
    Path = $hexSourcePath
    Source = $hexSource
    Marker = 'std::shared_ptr<workspace_hex_state_t> state_for('
    Symbol = 'hex_view::state_for'
    Required = @(
        'context.workspace->identity().binary_id()',
        'created->owner = context.workspace',
        'values.emplace(id, created)',
        'context.workspace->register_lifecycle_participant(created)'
    )
    Ordered = $true
    Block = $true
}
$sourceContracts.Add((Get-SourceContractRecord @contractArgs))
$contractArgs = @{
    Id = 'hex_workspace_cancellation_drain'
    Path = $hexSourcePath
    Source = $hexSource
    Marker = 'void workspace_hex_state_t::request_cancel() noexcept'
    Symbol = 'hex_view::workspace_hex_state_t::request_cancel'
    Required = @(
        'cancelled.store(true',
        'search->request_cancel()',
        'taskflow_runtime::cancel(patch)',
        'taskflow_runtime::cancel(search_task)',
        'unregister_state(owner_id, this)'
    )
    Ordered = $true
    Block = $true
}
$sourceContracts.Add((Get-SourceContractRecord @contractArgs))
$contractArgs = @{
    Id = 'hex_verified_provider_admission'
    Path = $fileBrowserPath
    Source = $fileBrowserSource
    Marker = 'void async_hex_fallback(const std::string& path, bool archive)'
    Symbol = 'file_browser::async_hex_fallback'
    Required = @(
        'workspace_registry_t::cancel_admission(*previous)',
        'mapped_file_provider_t::open(path)',
        'open_archive_member_provider(provider, member',
        'open_provider_workspace_request_t request',
        'request.provider = provider',
        'workspace_registry().admit_verified_provider_async('
    )
    Ordered = $true
    Block = $true
}
$sourceContracts.Add((Get-SourceContractRecord @contractArgs))
$contractArgs = @{
    Id = 'hex_provider_context_fallback'
    Path = $fileBrowserPath
    Source = $fileBrowserSource
    Marker = 'void complete_hex_preview_success('
    Symbol = 'file_browser::complete_hex_preview_success'
    Required = @(
        'workspace_registry().select_for_ui(',
        'disasm_view::capture_workspace(workspace)',
        'hex_view::activate(context)',
        'aida::ui::application_views::open_or_focus(',
        'aida::ui::stable_view_id_t("document.hex")'
    )
    Ordered = $true
    Block = $true
}
$sourceContracts.Add((Get-SourceContractRecord @contractArgs))

$queuedFlagsStart = $mainSource.IndexOf('static constexpr UINT kAidaQueuedPeekFlags',
    [StringComparison]::Ordinal)
$queuedFlagsEnd = if ($queuedFlagsStart -ge 0) { $mainSource.IndexOf(';', $queuedFlagsStart) } else { -1 }
if ($queuedFlagsStart -lt 0 -or $queuedFlagsEnd -lt 0) { throw 'Missing queued message-pump flags' }
$queuedFlags = $mainSource.Substring($queuedFlagsStart, $queuedFlagsEnd - $queuedFlagsStart + 1)
Assert-SourceContains $queuedFlags @('PM_REMOVE', 'PM_QS_INPUT', 'PM_QS_POSTMESSAGE',
    'PM_QS_PAINT', 'PM_QS_SENDMESSAGE') 'queued message-pump flags'
Assert-SourceExcludes $queuedFlags @('PM_NOREMOVE') 'queued message-pump flags'
$sendFlagsStart = $mainSource.IndexOf('static constexpr UINT kAidaSendOnlyPeekFlags',
    [StringComparison]::Ordinal)
$sendFlagsEnd = if ($sendFlagsStart -ge 0) { $mainSource.IndexOf(';', $sendFlagsStart) } else { -1 }
if ($sendFlagsStart -lt 0 -or $sendFlagsEnd -lt 0) { throw 'Missing send-only message-pump flags' }
$sendFlags = $mainSource.Substring($sendFlagsStart, $sendFlagsEnd - $sendFlagsStart + 1)
Assert-SourceContains $sendFlags @('PM_REMOVE | PM_QS_SENDMESSAGE') 'send-only message-pump flags'
Assert-SourceExcludes $sendFlags @('PM_NOREMOVE') 'send-only message-pump flags'
$pumpMarker = 'aida_tracer::mark_render_phase("peek_message_probe")'
$pumpEndMarker = 'aida_tracer::g_peek_return_count.fetch_add(1, std::memory_order_acq_rel)'
$pumpStart = $mainSource.IndexOf($pumpMarker, [StringComparison]::Ordinal)
$pumpEnd = if ($pumpStart -ge 0) {
    $mainSource.IndexOf($pumpEndMarker, $pumpStart + $pumpMarker.Length,
        [StringComparison]::Ordinal)
} else { -1 }
if ($pumpStart -lt 0 -or $pumpEnd -lt 0) { throw 'Missing primary message-pump source range' }
$pumpScope = $mainSource.Substring($pumpStart, $pumpEnd - $pumpStart + $pumpEndMarker.Length)
$pumpEvidence = @(
    'GetQueueStatus(QS_ALLINPUT)',
    'if (queue_current == 0)',
    'send_message_pending',
    'if (send_only_pending)',
    'PeekMessage(&sent_probe, nullptr, 0U, 0U, kAidaSendOnlyPeekFlags)',
    'const UINT peek_remove_flags = kAidaQueuedPeekFlags',
    'PeekMessage(&msg, peek_filter, 0U, 0U, peek_remove_flags)'
)
Assert-SourceOrdered $pumpScope $pumpEvidence 'primary message-pump invariant sequence'
$emptyQueueBlock = Get-SourceBlock $mainSource 'if (queue_current == 0)' 'empty-queue PeekMessage probe'
Assert-SourceExcludes $emptyQueueBlock.text @('break;', 'continue;', 'return') 'empty-queue PeekMessage probe'
$sourceContracts.Add([ordered]@{
    id = 'win32_message_pump_invariants'
    source = [ordered]@{
        file = Get-Relative $mainPath
        line = Get-LineNumber $mainSource $pumpStart
        symbol = 'primary Win32 message pump'
    }
    evidence = @($pumpEvidence)
    forbidden = @('PM_NOREMOVE', 'empty-queue break', 'empty-queue continue', 'empty-queue return')
})

$hexCallInventory = Get-HexContextCallInventory (Join-Path $RepositoryRoot 'src\standalone\src')
$sourceContractManifest = [ordered]@{
    contract_count = $sourceContracts.Count
    contracts = @($sourceContracts | Sort-Object id)
    hex_context_calls = [ordered]@{
        expected_argument_counts = $hexCallInventory.expected_argument_counts
        observed_call_counts = $hexCallInventory.observed_call_counts
        files = $hexCallInventory.files
    }
    ida_compatibility = [ordered]@{
        registration_count = $c03Compatibility.registration_count
        archive_backed_count = $c03Compatibility.archive_backed_count
        proxy_local_count = $c03Compatibility.proxy_local_count
        extension_count = $c03Compatibility.extension_count
        union_names = $c03Compatibility.union_names
        registrations = $c03Compatibility.registrations
        domains = $c03Compatibility.domains
        descriptor_artifacts = $c03Compatibility.descriptor_artifacts
        registration_source = $c03Compatibility.registration_source
        server_integration_source = $c03Compatibility.server_integration_source
        legacy_schema_projection = [ordered]@{
            registration_count = $idaCompatibility.records.Count
            read_only_names = $idaCompatibility.read_only_names
            mutation_names = $idaCompatibility.mutation_names
            target_dependent_names = $idaCompatibility.target_dependent_names
            schema_source = Get-Relative $idaSchemaPath
        }
    }
}

$publicSurfaceManifest = [ordered]@{
    commands = [ordered]@{
        builtin_count = $commandSurface.builtin_count
        builtin_names = $commandSurface.builtin_names
        dynamic_producers = $commandSurface.dynamic_producers
        source = $commandSurface.source
    }
    test_lab = [ordered]@{
        feature_count = $testLabSurface.feature_count
        features = $testLabSurface.features
    }
    workbench = [ordered]@{
        analysis_document_count = $workbenchSurface.analysis_document_count
        analysis_document_kinds = $workbenchSurface.analysis_document_kinds
        default_analysis_document = $workbenchSurface.default_analysis_document
        per_workspace_persistence = $workbenchSurface.per_workspace_persistence
        contracts_source = $workbenchSurface.contracts_source
        shell_source = $workbenchSurface.shell_source
        persistence_source = $workbenchSurface.persistence_source
    }
    overlay = [ordered]@{
        operation_count = $overlaySurface.operation_count
        legacy_ordinal_min = $overlaySurface.legacy_ordinal_min
        legacy_ordinal_max = $overlaySurface.legacy_ordinal_max
        appended_ordinal_min = $overlaySurface.appended_ordinal_min
        appended_ordinal_max = $overlaySurface.appended_ordinal_max
        operations = $overlaySurface.operations
        source = $overlaySurface.source
    }
    dead_paths = [ordered]@{
        absent_paths = $deadPathSurface.absent_paths
        replacement_paths = $deadPathSurface.replacement_paths
        retirements = $deadPathSurface.retirements
        replacement_evidence = $deadPathSurface.replacement_evidence
        cmake_graph = $deadPathSurface.cmake_graph
    }
}

$allEvidenceFiles = @($sourceFiles + $idaCompatibility.evidence_files +
    $c03Compatibility.source_files + $commandSurface.source_files +
    $testLabSurface.source_files + $workbenchSurface.source_files +
    $overlaySurface.source_files + $deadPathSurface.source_files +
    @($mcpProductionReachability.source_files | ForEach-Object {
        Join-Path $RepositoryRoot ([string]$_).Replace('/', '\')
    }) +
    $hexCallInventory.absolute_files + $shortcutSourceFiles.ToArray() +
    @($mcpPath, $globalsPath, $helpersPath,
    $sessionHeaderPath, $sessionSourcePath, $workspaceRegistryPath,
    $driverIdentityPath, $driverSourcePath, $hexHeaderPath, $hexSourcePath,
    $fileBrowserPath, $calculatorToolPath, $decompilerServicePath, $mainPath,
    $applicationUiRuntimePath, $PSCommandPath) | Sort-Object -Unique)
$sourceHashes = [Collections.Generic.List[object]]::new()
$sha = [Security.Cryptography.SHA256]::Create()
try {
    foreach ($path in $allEvidenceFiles) {
        $bytes = [IO.File]::ReadAllBytes($path)
        $hash = -join ($sha.ComputeHash($bytes) | ForEach-Object { $_.ToString('x2') })
        $sourceHashes.Add([ordered]@{ file = Get-Relative $path; sha256 = $hash })
    }
} finally {
    $sha.Dispose()
}

function Test-ObjectField([object]$Object, [string]$Name) {
    if ($null -eq $Object) { return $false }
    if ($Object -is [Collections.IDictionary]) { return $Object.Contains($Name) }
    return $null -ne $Object.PSObject.Properties[$Name]
}

function Get-ObjectField([object]$Object, [string]$Name) {
    if (!(Test-ObjectField $Object $Name)) { return $null }
    if ($Object -is [Collections.IDictionary]) { return $Object[$Name] }
    return $Object.PSObject.Properties[$Name].Value
}

function Get-NamedSurfaceIndex([object[]]$Values, [string]$Field, [string]$Contract) {
    $index = @{}
    foreach ($value in @($Values)) {
        $name = [string](Get-ObjectField $value $Field)
        if ([string]::IsNullOrWhiteSpace($name)) { throw "$Contract contains an empty $Field" }
        if ($index.ContainsKey($name)) { throw "$Contract contains duplicate $Field '$name'" }
        $index[$name] = $value
    }
    return $index
}

function Assert-ParameterCompatibility([object[]]$Reference, [object[]]$Candidate,
                                       [string]$Contract, [bool]$Strict) {
    if ($Strict) {
        if ((Convert-CanonicalJson @($Reference)) -ne (Convert-CanonicalJson @($Candidate))) {
            throw "Surface schema regression in $Contract parameters"
        }
        return
    }
    $candidateIndex = Get-NamedSurfaceIndex @($Candidate) 'name' "$Contract candidate parameters"
    foreach ($parameter in @($Reference)) {
        $name = [string](Get-ObjectField $parameter 'name')
        if (!$candidateIndex.ContainsKey($name)) {
            throw "Removed or renamed parameter '$name' in $Contract"
        }
        $current = $candidateIndex[$name]
        foreach ($field in @('type', 'required')) {
            if ((Convert-CanonicalJson (Get-ObjectField $parameter $field)) -ne
                (Convert-CanonicalJson (Get-ObjectField $current $field))) {
                throw "Surface schema regression in $Contract parameter '$name' field '$field'"
            }
        }
    }
    $referenceNames = @{}
    foreach ($parameter in @($Reference)) {
        $referenceNames[[string](Get-ObjectField $parameter 'name')] = $true
    }
    foreach ($parameter in @($Candidate)) {
        $name = [string](Get-ObjectField $parameter 'name')
        if (!$referenceNames.ContainsKey($name) -and [bool](Get-ObjectField $parameter 'required')) {
            throw "Additive parameter '$name' became required in $Contract"
        }
    }
}

function Assert-StringSurfaceSubset([object[]]$Reference, [object[]]$Candidate,
                                    [string]$Contract) {
    $candidateSet = [Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
    foreach ($value in @($Candidate)) { [void]$candidateSet.Add([string]$value) }
    foreach ($value in @($Reference)) {
        if (!$candidateSet.Contains([string]$value)) {
            throw "Removed or renamed $Contract '$value'"
        }
    }
}

function Assert-SurfaceCompatibility([object]$Reference, [object]$Candidate,
                                     [string]$ReferenceLabel, [bool]$Strict) {
    foreach ($field in @('schema_version', 'generator', 'mcp', 'ui', 'session')) {
        if (!(Test-ObjectField $Reference $field)) { throw "$ReferenceLabel lacks required field '$field'" }
        if (!(Test-ObjectField $Candidate $field)) { throw "Generated manifest lacks required field '$field'" }
    }
    if ([int](Get-ObjectField $Candidate 'schema_version') -lt
        [int](Get-ObjectField $Reference 'schema_version')) {
        throw "Manifest schema version regressed relative to $ReferenceLabel"
    }
    if (![string]::Equals([string](Get-ObjectField $Candidate 'generator'),
        [string](Get-ObjectField $Reference 'generator'), [StringComparison]::Ordinal)) {
        throw "Manifest generator identity changed relative to $ReferenceLabel"
    }

    $referenceMcp = Get-ObjectField $Reference 'mcp'
    $candidateMcp = Get-ObjectField $Candidate 'mcp'
    $referenceRegistrations = @((Get-ObjectField $referenceMcp 'registrations'))
    $candidateRegistrations = @((Get-ObjectField $candidateMcp 'registrations'))
    $referenceTools = Get-NamedSurfaceIndex $referenceRegistrations 'name' "$ReferenceLabel MCP registrations"
    $candidateTools = Get-NamedSurfaceIndex $candidateRegistrations 'name' 'generated MCP registrations'
    if ([int](Get-ObjectField $candidateMcp 'registration_count') -ne $candidateRegistrations.Count -or
        [int](Get-ObjectField $candidateMcp 'unique_name_count') -ne $candidateTools.Count -or
        @((Get-ObjectField $candidateMcp 'duplicate_names')).Count -ne 0) {
        throw 'Generated MCP registration count or duplicate-name contract is inconsistent'
    }
    if (Test-ObjectField $referenceMcp 'generated_union_names') {
        foreach ($field in @('generated_registration_count', 'generated_overlap_count',
            'generated_only_count', 'effective_registration_count', 'generated_union_names',
            'generated_overlap_names', 'generated_only_names', 'effective_registration_names')) {
            if (!(Test-ObjectField $candidateMcp $field)) {
                throw "Generated MCP inventory lost field '$field' relative to $ReferenceLabel"
            }
        }
        $candidateGenerated = @((Get-ObjectField $candidateMcp 'generated_union_names'))
        $candidateOverlap = @((Get-ObjectField $candidateMcp 'generated_overlap_names'))
        $candidateGeneratedOnly = @((Get-ObjectField $candidateMcp 'generated_only_names'))
        $candidateEffective = @((Get-ObjectField $candidateMcp 'effective_registration_names'))
        if ([int](Get-ObjectField $candidateMcp 'generated_registration_count') -ne
                $candidateGenerated.Count -or
            [int](Get-ObjectField $candidateMcp 'generated_overlap_count') -ne
                $candidateOverlap.Count -or
            [int](Get-ObjectField $candidateMcp 'generated_only_count') -ne
                $candidateGeneratedOnly.Count -or
            [int](Get-ObjectField $candidateMcp 'effective_registration_count') -ne
                $candidateEffective.Count) {
            throw 'Generated MCP additive inventory count is inconsistent'
        }
        Assert-StringSetEqual @((Get-ObjectField $referenceMcp 'generated_union_names')) `
            $candidateGenerated 'pinned C03 generated MCP union'
        Assert-StringSurfaceSubset @((Get-ObjectField $referenceMcp 'effective_registration_names')) `
            $candidateEffective 'effective MCP registration'
    }
    foreach ($name in $referenceTools.Keys) {
        if (!$candidateTools.ContainsKey($name)) {
            throw "Removed or renamed MCP registration '$name' relative to $ReferenceLabel"
        }
        $before = $referenceTools[$name]
        $after = $candidateTools[$name]
        $protectedFields = @('description', 'read_only', 'visibility_declared',
                              'visibility_effective')
        if (Test-ObjectField $before 'workspace_aware') {
            $protectedFields += 'workspace_aware'
        }
        foreach ($field in $protectedFields) {
            if ((Convert-CanonicalJson (Get-ObjectField $before $field)) -ne
                (Convert-CanonicalJson (Get-ObjectField $after $field))) {
                throw "MCP surface regression for '$name' field '$field' relative to $ReferenceLabel"
            }
        }
        Assert-ParameterCompatibility @((Get-ObjectField $before 'parameters')) @((Get-ObjectField $after 'parameters')) "MCP tool '$name'" $Strict
        if (Test-ObjectField $before 'input_schema') {
            if (!(Test-ObjectField $after 'input_schema') -or
                ($Strict -and
                (Convert-CanonicalJson (Get-ObjectField $before 'input_schema')) -ne
                (Convert-CanonicalJson (Get-ObjectField $after 'input_schema')))) {
                throw "Exact input schema regression for MCP tool '$name' relative to $ReferenceLabel"
            }
        }
    }

    $referenceResources = Get-NamedSurfaceIndex @((Get-ObjectField $referenceMcp 'resources')) 'uri' "$ReferenceLabel MCP resources"
    $candidateResources = Get-NamedSurfaceIndex @((Get-ObjectField $candidateMcp 'resources')) 'uri' 'generated MCP resources'
    foreach ($uri in $referenceResources.Keys) {
        if (!$candidateResources.ContainsKey($uri)) {
            throw "Removed or renamed MCP resource '$uri' relative to $ReferenceLabel"
        }
        foreach ($field in @('name', 'description', 'mime_type', 'result_fields')) {
            if ((Convert-CanonicalJson (Get-ObjectField $referenceResources[$uri] $field)) -ne
                (Convert-CanonicalJson (Get-ObjectField $candidateResources[$uri] $field))) {
                throw "MCP resource regression for '$uri' field '$field' relative to $ReferenceLabel"
            }
        }
    }

    $referenceVisibility = Get-ObjectField $referenceMcp 'visibility_policy'
    $candidateVisibility = Get-ObjectField $candidateMcp 'visibility_policy'
    foreach ($field in @('internal_only', 'ide_chat_only', 'targetless_camoufox')) {
        Assert-StringSurfaceSubset @((Get-ObjectField $referenceVisibility $field)) @((Get-ObjectField $candidateVisibility $field)) "MCP visibility policy $field"
    }
    $referenceDynamic = @((Get-ObjectField $referenceMcp 'dynamic_registration_templates'))
    $candidateDynamic = @((Get-ObjectField $candidateMcp 'dynamic_registration_templates'))
    $candidateResolvedHelpers = @((Get-ObjectField $candidateMcp 'resolved_registration_helpers'))
    foreach ($entry in $referenceDynamic) {
        $matched = @($candidateDynamic | Where-Object {
            [string](Get-ObjectField $_ 'file') -eq [string](Get-ObjectField $entry 'file') -and
            [string](Get-ObjectField $_ 'expression') -eq [string](Get-ObjectField $entry 'expression')
        }).Count -ne 0
        if (!$matched) {
            $matched = @($candidateResolvedHelpers | Where-Object {
                [string](Get-ObjectField $_ 'file') -eq [string](Get-ObjectField $entry 'file') -and
                [string](Get-ObjectField $_ 'expression') -eq [string](Get-ObjectField $entry 'expression')
            }).Count -ne 0
        }
        if (!$matched) {
            throw "Removed dynamic registration provenance relative to $ReferenceLabel"
        }
    }
    if (Test-ObjectField $referenceMcp 'unresolved_registration_count') {
        if ([int](Get-ObjectField $candidateMcp 'unresolved_registration_count') -ne 0 -or
            @((Get-ObjectField $candidateMcp 'dynamic_registration_templates')).Count -ne 0) {
            throw "Unresolved MCP registrations were introduced relative to $ReferenceLabel"
        }
        $referenceHelpers = Get-NamedSurfaceIndex @((Get-ObjectField $referenceMcp 'resolved_registration_helpers')) `
            'helper' "$ReferenceLabel resolved MCP registration helpers"
        $candidateHelpers = Get-NamedSurfaceIndex $candidateResolvedHelpers 'helper' `
            'generated resolved MCP registration helpers'
        foreach ($name in $referenceHelpers.Keys) {
            if (!$candidateHelpers.ContainsKey($name) -or
                (Convert-CanonicalJson (Get-ObjectField $referenceHelpers[$name] 'concrete_registration_names')) -ne
                (Convert-CanonicalJson (Get-ObjectField $candidateHelpers[$name] 'concrete_registration_names'))) {
                throw "Resolved MCP registration helper '$name' regressed relative to $ReferenceLabel"
            }
        }
    }
    if (Test-ObjectField $referenceMcp 'production_reachability') {
        if (!(Test-ObjectField $candidateMcp 'production_reachability')) {
            throw "Generated MCP inventory lost production reachability relative to $ReferenceLabel"
        }
        $beforeReachability = Get-ObjectField $referenceMcp 'production_reachability'
        $afterReachability = Get-ObjectField $candidateMcp 'production_reachability'
        foreach ($field in @('schema_version', 'concrete_registration_count',
            'direct_registration_count', 'generated_projection_count',
            'reachable_registrar_count', 'registrar_edge_count',
            'row_binding_sha256', 'registrar_graph_sha256')) {
            if ((Convert-CanonicalJson (Get-ObjectField $beforeReachability $field)) -ne
                (Convert-CanonicalJson (Get-ObjectField $afterReachability $field))) {
                throw "MCP production reachability field '$field' regressed relative to $ReferenceLabel"
            }
        }
        $beforeGeneratedRoute = Get-ObjectField $beforeReachability 'generated_route'
        $afterGeneratedRoute = Get-ObjectField $afterReachability 'generated_route'
        foreach ($field in @('node_count', 'edge_count', 'terminal_operation_count',
            'binding_count', 'generated_compatibility_count', 'extension_count',
            'shared_terminal_definition_id', 'shared_terminal_parent_ids',
            'route_sha256', 'binding_sha256')) {
            if (!(Test-ObjectField $beforeGeneratedRoute $field)) { continue }
            if ((Convert-CanonicalJson (Get-ObjectField $beforeGeneratedRoute $field)) -ne
                (Convert-CanonicalJson (Get-ObjectField $afterGeneratedRoute $field))) {
                throw "MCP generated production route field '$field' regressed relative to $ReferenceLabel"
            }
        }
        foreach ($name in $referenceTools.Keys) {
            if ((Convert-CanonicalJson (Get-ObjectField $referenceTools[$name] 'production_reachability')) -ne
                (Convert-CanonicalJson (Get-ObjectField $candidateTools[$name] 'production_reachability'))) {
                throw "MCP production reachability row '$name' regressed relative to $ReferenceLabel"
            }
        }
    }

    $referenceUi = Get-ObjectField $Reference 'ui'
    $candidateUi = Get-ObjectField $Candidate 'ui'
    Assert-StringSurfaceSubset @((Get-ObjectField $referenceUi 'center_views')) @((Get-ObjectField $candidateUi 'center_views')) 'center view'
    $candidateActionLabels = @((Get-ObjectField $candidateUi 'actions') | ForEach-Object {
        [string](Get-ObjectField $_ 'label')
    })
    Assert-StringSurfaceSubset @((Get-ObjectField $referenceUi 'actions') | ForEach-Object {
        [string](Get-ObjectField $_ 'label')
    }) $candidateActionLabels 'UI action'
    $candidateShortcutKeys = [Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
    foreach ($entry in @((Get-ObjectField $candidateUi 'shortcuts'))) {
        [void]$candidateShortcutKeys.Add([string](Get-ObjectField $entry 'key'))
    }
    foreach ($entry in @((Get-ObjectField $referenceUi 'shortcuts'))) {
        $key = [string](Get-ObjectField $entry 'key')
        if (!$candidateShortcutKeys.Contains($key)) {
            throw "Removed UI shortcut key relative to ${ReferenceLabel}: $key"
        }
    }
    $candidateBindings = Get-NamedSurfaceIndex @((Get-ObjectField $candidateUi 'shortcut_bindings')) `
        'binding_id' 'generated canonical shortcut bindings'
    foreach ($bindingId in $requiredShortcutBindingIds) {
        if (!$candidateBindings.ContainsKey($bindingId)) {
            throw "Required canonical shortcut binding '$bindingId' is absent"
        }
        foreach ($field in @('action_id', 'display', 'chord_expressions', 'keys', 'source')) {
            if (!(Test-ObjectField $candidateBindings[$bindingId] $field)) {
                throw "Canonical shortcut binding '$bindingId' lacks '$field' provenance"
            }
        }
    }

    $referenceSession = Get-ObjectField $Reference 'session'
    $candidateSession = Get-ObjectField $Candidate 'session'
    Assert-StringSurfaceSubset @((Get-ObjectField $referenceSession 'public_method_names')) @((Get-ObjectField $candidateSession 'public_method_names')) 'session public method'

    if (Test-ObjectField $Reference 'surface_guard') {
        if (!(Test-ObjectField $Candidate 'surface_guard') -or
            [string](Get-ObjectField (Get-ObjectField $Reference 'surface_guard') 'policy') -ne
            [string](Get-ObjectField (Get-ObjectField $Candidate 'surface_guard') 'policy')) {
            throw "Surface guard policy regressed relative to $ReferenceLabel"
        }
    }
    if (Test-ObjectField $Reference 'source_contracts') {
        if (!(Test-ObjectField $Candidate 'source_contracts')) {
            throw "Source contract inventory was removed relative to $ReferenceLabel"
        }
        $referenceContracts = Get-NamedSurfaceIndex @((Get-ObjectField (Get-ObjectField $Reference 'source_contracts') 'contracts')) 'id' "$ReferenceLabel source contracts"
        $candidateContracts = Get-NamedSurfaceIndex @((Get-ObjectField (Get-ObjectField $Candidate 'source_contracts') 'contracts')) 'id' 'generated source contracts'
        foreach ($id in $referenceContracts.Keys) {
            if (!$candidateContracts.ContainsKey($id)) {
                throw "Removed or renamed source contract '$id' relative to $ReferenceLabel"
            }
        }
        $referenceHexCalls = Get-ObjectField (Get-ObjectField (Get-ObjectField $Reference 'source_contracts') 'hex_context_calls') 'expected_argument_counts'
        $candidateHexCalls = Get-ObjectField (Get-ObjectField (Get-ObjectField $Candidate 'source_contracts') 'hex_context_calls') 'expected_argument_counts'
        if ((Convert-CanonicalJson $referenceHexCalls) -ne (Convert-CanonicalJson $candidateHexCalls)) {
            throw "Hex context source schema regressed relative to $ReferenceLabel"
        }
        $referenceCompatibility = Get-ObjectField (Get-ObjectField $Reference 'source_contracts') 'ida_compatibility'
        if (Test-ObjectField $referenceCompatibility 'union_names') {
            $candidateCompatibility = Get-ObjectField (Get-ObjectField $Candidate 'source_contracts') 'ida_compatibility'
            Assert-StringSetEqual @((Get-ObjectField $referenceCompatibility 'union_names')) `
                @((Get-ObjectField $candidateCompatibility 'union_names')) `
                'C03 generated MCP compatibility union'
            $referenceGenerated = Get-NamedSurfaceIndex @((Get-ObjectField $referenceCompatibility 'registrations')) `
                'name' "$ReferenceLabel generated MCP compatibility registrations"
            $candidateGenerated = Get-NamedSurfaceIndex @((Get-ObjectField $candidateCompatibility 'registrations')) `
                'name' 'generated MCP compatibility registrations'
            foreach ($name in $referenceGenerated.Keys) {
                if (!$candidateGenerated.ContainsKey($name)) {
                    throw "Removed C03 generated MCP registration '$name' relative to $ReferenceLabel"
                }
                foreach ($field in @('descriptor_source', 'adapter_symbol', 'effect', 'lock',
                    'target_dependent', 'accepts_pid', 'accepts_bin_name', 'read_only', 'unsafe',
                    'production_handler', 'functional_fixture', 'domain')) {
                    if ((Convert-CanonicalJson (Get-ObjectField $referenceGenerated[$name] $field)) -ne
                        (Convert-CanonicalJson (Get-ObjectField $candidateGenerated[$name] $field))) {
                        throw "C03 generated MCP registration '$name' changed field '$field' relative to $ReferenceLabel"
                    }
                }
                if (Test-ObjectField $referenceGenerated[$name] 'production_reachability') {
                    if ((Convert-CanonicalJson (Get-ObjectField $referenceGenerated[$name] 'production_reachability')) -ne
                        (Convert-CanonicalJson (Get-ObjectField $candidateGenerated[$name] 'production_reachability'))) {
                        throw "C03 generated MCP registration '$name' changed production reachability relative to $ReferenceLabel"
                    }
                }
            }
        }
    }
    if (Test-ObjectField $Reference 'public_surfaces') {
        if (!(Test-ObjectField $Candidate 'public_surfaces')) {
            throw "Public surface inventory was removed relative to $ReferenceLabel"
        }
        $referencePublic = Get-ObjectField $Reference 'public_surfaces'
        $candidatePublic = Get-ObjectField $Candidate 'public_surfaces'
        Assert-StringSurfaceSubset @((Get-ObjectField (Get-ObjectField $referencePublic 'commands') 'builtin_names')) `
            @((Get-ObjectField (Get-ObjectField $candidatePublic 'commands') 'builtin_names')) `
            'built-in command'
        $referenceFeatures = @((Get-ObjectField (Get-ObjectField $referencePublic 'test_lab') 'features') |
            ForEach-Object { [string]$_.category + "`n" + [string]$_.name })
        $candidateFeatures = @((Get-ObjectField (Get-ObjectField $candidatePublic 'test_lab') 'features') |
            ForEach-Object { [string]$_.category + "`n" + [string]$_.name })
        Assert-StringSurfaceSubset $referenceFeatures $candidateFeatures 'Test Lab feature'
        Assert-StringSetEqual @((Get-ObjectField (Get-ObjectField $referencePublic 'workbench') 'analysis_document_kinds')) `
            @((Get-ObjectField (Get-ObjectField $candidatePublic 'workbench') 'analysis_document_kinds')) `
            'workbench analysis document kinds'
        if ((Convert-CanonicalJson (Get-ObjectField $referencePublic 'overlay')) -ne
            (Convert-CanonicalJson (Get-ObjectField $candidatePublic 'overlay'))) {
            throw "Overlay ordinal surface changed relative to $ReferenceLabel"
        }
        $referenceDead = Get-ObjectField $referencePublic 'dead_paths'
        $candidateDead = Get-ObjectField $candidatePublic 'dead_paths'
        Assert-StringSetEqual @((Get-ObjectField $referenceDead 'absent_paths')) `
            @((Get-ObjectField $candidateDead 'absent_paths')) 'removed C03 paths'
        Assert-StringSetEqual @((Get-ObjectField $referenceDead 'replacement_paths')) `
            @((Get-ObjectField $candidateDead 'replacement_paths')) 'C03 replacement paths'
    }
}

function Write-AtomicUtf8([string]$Path, [string]$Content) {
    $parent = Split-Path -Parent $Path
    if (!(Test-Path -LiteralPath $parent)) {
        [void][IO.Directory]::CreateDirectory($parent)
    }
    $temporary = Join-Path $parent ((Split-Path -Leaf $Path) + '.tmp.' +
        [Guid]::NewGuid().ToString('N'))
    try {
        [IO.File]::WriteAllText($temporary, $Content, [Text.UTF8Encoding]::new($false))
        if (Test-Path -LiteralPath $Path) {
            [IO.File]::Delete($Path)
            [IO.File]::Move($temporary, $Path)
        } else {
            [IO.File]::Move($temporary, $Path)
        }
    } finally {
        if (Test-Path -LiteralPath $temporary) { [IO.File]::Delete($temporary) }
    }
}

$manifest = [ordered]@{
    schema_version = 2
    generator = 'src/standalone/tests/analysis_workspace/generate_surface_manifest.ps1'
    surface_guard = [ordered]@{
        policy = 'strict_additive_v1'
        baseline = Get-Relative $BaselinePath
        protected_mcp_fields = @('name', 'description', 'parameters', 'input_schema',
            'read_only', 'visibility_declared', 'visibility_effective', 'workspace_aware',
            'production_reachability')
        protected_resource_fields = @('uri', 'name', 'description', 'mime_type', 'result_fields')
        protected_ui_fields = @('center_views', 'actions', 'shortcuts')
        protected_session_fields = @('public_method_names')
    }
    mcp = [ordered]@{
        registration_count = $registrations.Count
        unique_name_count = @($registrations.name | Sort-Object -Unique).Count
        generated_registration_count = $c03UnionNames.Count
        generated_overlap_count = $c03OverlapNames.Count
        generated_only_count = $c03GeneratedOnlyNames.Count
        effective_registration_count = $effectiveRegistrationNames.Count
        generated_union_names = $c03UnionNames
        generated_overlap_names = $c03OverlapNames
        generated_only_names = $c03GeneratedOnlyNames
        effective_registration_names = $effectiveRegistrationNames
        registrations = $registrations
        duplicate_names = $duplicateNames
        unresolved_registration_count = $unresolvedRegistrationEvidence.Count
        resolved_helper_template_count = $resolvedHelperRecords.Count
        resolved_helper_registration_count = $resolvedHelperRegistrationCount
        dynamic_registration_templates = @($unresolvedRegistrationEvidence | Sort-Object file, line)
        resolved_registration_helpers = @($resolvedHelperRecords | Sort-Object helper)
        production_reachability = $mcpProductionReachability
        visibility_policy = [ordered]@{
            internal_only = $internalNames
            ide_chat_only = $chatNames
            targetless_camoufox = $browserNames
        }
        resources = @($resources | Sort-Object uri)
    }
    ui = [ordered]@{
        center_views = $centerViews
        actions = $uiActions
        shortcuts = @($shortcuts | Sort-Object `
            @{ Expression = { [string]$_['key'] } },
            @{ Expression = { [string]$_['source'] } },
            @{ Expression = { [int]$_['line'] } })
        shortcut_binding_count = $modernShortcutSurface.binding_count
        shortcut_bindings = $modernShortcutSurface.bindings
        required_shortcut_binding_ids = $requiredShortcutBindingIds
    }
    session = [ordered]@{
        public_method_names = $sessionMethods
        header = Get-Relative $sessionHeaderPath
        implementation = Get-Relative $sessionSourcePath
    }
    public_surfaces = $publicSurfaceManifest
    source_contracts = $sourceContractManifest
    evidence_source_hashes = @($sourceHashes | Sort-Object file)
}

if ([string]::Equals($OutputPath, $BaselinePath, [StringComparison]::OrdinalIgnoreCase)) {
    throw 'The historical baseline cannot be used as the generated output path'
}
if (!(Test-Path -LiteralPath $BaselinePath -PathType Leaf)) {
    throw "Surface baseline is unavailable: $BaselinePath"
}
try {
    $baselineManifest = (Get-Text $BaselinePath) | ConvertFrom-Json
} catch {
    throw "Surface baseline is invalid JSON: $($_.Exception.Message)"
}
Assert-SurfaceCompatibility $baselineManifest $manifest 'historical baseline' $false
if (Test-Path -LiteralPath $OutputPath -PathType Leaf) {
    try {
        $existingManifest = (Get-Text $OutputPath) | ConvertFrom-Json
    } catch {
        throw "Existing final surface inventory is invalid JSON: $($_.Exception.Message)"
    }
    Assert-SurfaceCompatibility $existingManifest $manifest 'existing final inventory' $false
}
$json = $manifest | ConvertTo-Json -Depth 64
Write-AtomicUtf8 $OutputPath ($json + "`n")
$outputBytes = [IO.File]::ReadAllBytes($OutputPath)
$hasher = [Security.Cryptography.SHA256]::Create()
try { $outputHash = -join ($hasher.ComputeHash($outputBytes) | ForEach-Object { $_.ToString('x2') }) }
finally { $hasher.Dispose() }
[ordered]@{
    output = (Resolve-Path $OutputPath).Path
    sha256 = $outputHash
    registration_count = $registrations.Count
    unique_name_count = @($registrations.name | Sort-Object -Unique).Count
    resolved_dynamic_templates = $resolvedHelperRecords.Count
    resolved_helper_registrations = $resolvedHelperRegistrationCount
    unresolved_dynamic_templates = $unresolvedRegistrationEvidence.Count
    ida_compatibility_registrations = $idaCompatibility.records.Count
    c03_compatibility_registrations = $c03Compatibility.registration_count
    effective_mcp_registrations = $effectiveRegistrationNames.Count
    reachable_mcp_registrations = $mcpProductionReachability.concrete_registration_count
    reachable_mcp_registrars = $mcpProductionReachability.reachable_registrar_count
    reachable_mcp_registrar_edges = $mcpProductionReachability.registrar_edge_count
    mcp_reachability_row_sha256 = $mcpProductionReachability.row_binding_sha256
    mcp_reachability_graph_sha256 = $mcpProductionReachability.registrar_graph_sha256
    resources = $resources.Count
    center_views = $centerViews.Count
    builtin_commands = $commandSurface.builtin_count
    test_lab_features = $testLabSurface.feature_count
    workbench_analysis_documents = $workbenchSurface.analysis_document_count
    overlay_operations = $overlaySurface.operation_count
    source_contracts = $sourceContracts.Count
} | ConvertTo-Json -Compress
