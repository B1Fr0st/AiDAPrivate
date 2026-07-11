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
        if ($character -eq '"' -or $character -eq "'") { $quote = $character; continue }
        if ($character -eq $Open) { ++$depth; continue }
        if ($character -eq $Close) {
            --$depth
            if ($depth -eq 0) { return $index }
        }
    }
    throw "Unterminated balanced range at offset $Start"
}

function Get-SourceBlock([string]$Source, [string]$Marker, [string]$Contract) {
    $start = $Source.IndexOf($Marker, [StringComparison]::Ordinal)
    if ($start -lt 0) { throw "Missing source contract '$Contract': $Marker" }
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
                                  [switch]$Ordered, [switch]$Block) {
    $scope = $Source
    $markerIndex = $Source.IndexOf($Marker, [StringComparison]::Ordinal)
    if ($markerIndex -lt 0) { throw "Missing source contract '$Id': $Marker" }
    if ($Block) {
        $sourceBlock = Get-SourceBlock $Source $Marker $Id
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
        read_live_memory = 3
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
        if ($fields.Count -eq 4) {
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

function Assert-StringSetEqual([string[]]$Expected, [string[]]$Actual, [string]$Contract) {
    $expectedValues = @($Expected | Sort-Object -Unique)
    $actualValues = @($Actual | Sort-Object -Unique)
    if ($expectedValues.Count -ne $actualValues.Count) {
        throw "$Contract count mismatch: expected $($expectedValues.Count), observed $($actualValues.Count)"
    }
    for ($index = 0; $index -lt $expectedValues.Count; ++$index) {
        if (![string]::Equals($expectedValues[$index], $actualValues[$index],
                             [StringComparison]::Ordinal)) {
            throw "$Contract mismatch: expected '$($expectedValues[$index])', observed '$($actualValues[$index])'"
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

function Get-IdaCompatibilityInventory([string]$SchemaPath, [string]$ReadPath,
                                       [string]$MutationPath, [string]$RegistrationPath,
                                       [string]$SessionRegistrationPath) {
    $schemaSource = Get-Text $SchemaPath
    $readSource = Get-Text $ReadPath
    $mutationSource = Get-Text $MutationPath
    $registrationSource = Get-Text $RegistrationPath
    $sessionRegistrationSource = Get-Text $SessionRegistrationPath
    $readNames = @(Get-NameSet $schemaSource 'read_only_tool_names')
    $mutationNames = @(Get-NameSet $schemaSource 'mutation_tool_names')
    $targetNames = @(Get-NameSet $schemaSource 'target_dependent_tool_names')
    $readEntries = @(Get-ToolDefinitionEntries $readSource 'get_read_tool_defs' (Get-Relative $ReadPath))
    $mutationEntries = @(Get-ToolDefinitionEntries $mutationSource 'get_mutation_tool_defs' (Get-Relative $MutationPath))
    Assert-StringSetEqual $readNames (@($readEntries.name) + @('list_instances', 'calculator', 'calculate')) 'IDA-compatible read registration set'
    Assert-StringSetEqual $mutationNames @($mutationEntries.name) 'IDA-compatible mutation registration set'
    Assert-StringSetEqual $targetNames (@($readEntries.name | Where-Object { $_ -ne 'int_convert' }) + @($mutationEntries.name)) 'IDA-compatible target-dependent registration set'

    Assert-SourceContains $registrationSource @(
        'install_ida_compat_schema_validation();',
        'for (const auto& definition : ida_compat::get_read_tool_defs())',
        'for (const auto& definition : ida_compat::get_mutation_tool_defs())',
        'for (const char* name : {"calculator", "calculate"})',
        'if (!register_ida_compatibility_tools(srv))'
    ) 'IDA-compatible production registration'
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
    $registrationRelative = Get-Relative $RegistrationPath
    $sessionRegistrationRelative = Get-Relative $SessionRegistrationPath
    foreach ($name in @('list_instances', 'calculator', 'calculate')) {
        $sourceText = if ($name -eq 'list_instances') { $sessionRegistrationSource } else { $registrationSource }
        $sourceFile = if ($name -eq 'list_instances') { $sessionRegistrationRelative } else { $registrationRelative }
        $nameIndex = $sourceText.IndexOf("`"$name`"", [StringComparison]::Ordinal)
        if ($nameIndex -lt 0) { throw "Missing IDA-compatible registration source: $name" }
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
                handler = if ($name -eq 'list_instances') { 'session_tools::list_instances' } else { 'tool_calculate' }
                file = $sourceFile
                line = Get-LineNumber $sourceText $nameIndex
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
        evidence_files = @($SchemaPath, $ReadPath, $MutationPath, $RegistrationPath)
    }
}

function New-Registration([string]$Name, [string]$Description, [object[]]$Parameters,
                          [bool]$ReadOnly, [string]$Visibility, [string]$File,
                          [int]$Line, [string]$Evidence, [string]$ParameterExpression,
                          [bool]$WorkspaceAware, [object]$InputSchema = $null) {
    $registration = [ordered]@{
        name = $Name
        description = $Description
        parameters = @($Parameters)
        read_only = $ReadOnly
        visibility_declared = $Visibility
        visibility_effective = $Visibility
        source = [ordered]@{ file = $File; line = $Line; evidence = $Evidence }
        parameter_expression = ($ParameterExpression -replace '\s+', ' ').Trim()
        workspace_aware = $WorkspaceAware
    }
    if ($null -ne $InputSchema) {
        $registration.input_schema = $InputSchema
    }
    return $registration
}

$core = Join-Path $RepositoryRoot 'src\standalone\src\core'
$mcpPath = Join-Path $core 'mcp\mcp_standalone.cpp'
$mcpToolsPath = Join-Path $core 'mcp\mcp_standalone_tools.cpp'
$idaSchemaPath = Join-Path $core 'mcp\ida_compat_schemas.hpp'
$idaReadPath = Join-Path $core 'mcp\ida_compat_read.cpp'
$idaMutationPath = Join-Path $core 'mcp\ida_compat_mut.cpp'
$calculatorToolPath = Join-Path $core 'mcp\calculator_tool.cpp'
$decompilerServicePath = Join-Path $core 'analysis\workspace\decompiler_service.cpp'
$sessionToolsPath = Join-Path $core 'tools\session_tools_standalone.cpp'
$mcpSource = Get-Text $mcpPath
$internalNames = @(Get-NameSet $mcpSource 'is_standalone_internal_only_tool_name')
$chatNames = @(Get-NameSet $mcpSource 'is_standalone_ide_chat_only_tool_name')
$browserNames = @(Get-NameSet $mcpSource 'is_camoufox_reverse_tool_name')
$registrations = [Collections.Generic.List[object]]::new()
$dynamicEvidence = [Collections.Generic.List[object]]::new()
$sourceFiles = [Collections.Generic.List[string]]::new()

$files = @(Get-ChildItem $core -Recurse -File -Filter '*.cpp' | Sort-Object FullName)
foreach ($file in $files) {
    $source = Get-Text $file.FullName
    $relative = Get-Relative $file.FullName
    $fileContributed = $false
    $cursor = 0
    while ($cursor -lt $source.Length) {
        $match = [regex]::Match($source, '\.register_tool\s*\(', [Text.RegularExpressions.RegexOptions]::None,
            [TimeSpan]::FromSeconds(2))
        if (!$match.Success) { break }
        $absolute = $cursor + $match.Index
        if ($cursor -gt 0) {
            $remaining = $source.Substring($cursor)
            $match = [regex]::Match($remaining, '\.register_tool\s*\(')
            if (!$match.Success) { break }
            $absolute = $cursor + $match.Index
        }
        $open = $source.IndexOf('(', $absolute)
        $close = Get-MatchingIndex $source $open '(' ')'
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
                        WorkspaceAware = $workspaceAware
                    }
                    $registrations.Add((New-Registration @registrationArgs))
                    $fileContributed = $true
                } else {
                    $dynamicEvidence.Add([ordered]@{ file = $relative; line = $line; expression = ($fields[0] -replace '\s+', ' ').Trim() })
                }
            }
        } elseif ($argumentText -match '^std::move\s*\(\s*([A-Za-z_]\w*)\s*\)') {
            $variable = $Matches[1]
            $prefix = $source.Substring(0, $absolute)
            $declarationMatches = [regex]::Matches($prefix, "(?:tool_def_t|mcp_standalone::tool_def_t)\s+$([regex]::Escape($variable))\b")
            if ($declarationMatches.Count -gt 0) {
                $segmentStart = $declarationMatches[$declarationMatches.Count - 1].Index
                $segment = $prefix.Substring($segmentStart)
                $nameMatches = [regex]::Matches($segment, "$([regex]::Escape($variable))\.name\s*=\s*([^;]+);")
                $descriptionMatches = [regex]::Matches($segment, "$([regex]::Escape($variable))\.description\s*=\s*([^;]+);")
                $paramsMatches = [regex]::Matches($segment, "$([regex]::Escape($variable))\.params\s*=\s*([^;]+);")
                $readOnlyMatches = [regex]::Matches($segment, "$([regex]::Escape($variable))\.read_only\s*=\s*(true|false)\s*;")
                if ($nameMatches.Count -gt 0 -and $descriptionMatches.Count -gt 0 -and $readOnlyMatches.Count -gt 0) {
                    $name = Convert-CppStrings $nameMatches[$nameMatches.Count - 1].Groups[1].Value
                    $description = Convert-CppStrings $descriptionMatches[$descriptionMatches.Count - 1].Groups[1].Value
                    $parameterExpression = if ($paramsMatches.Count -gt 0) { $paramsMatches[$paramsMatches.Count - 1].Groups[1].Value } else { '{}' }
                    if ($null -ne $name -and $null -ne $description) {
                        $parameters = @(Resolve-ParameterExpression $parameterExpression $source)
                        $readOnly = $readOnlyMatches[$readOnlyMatches.Count - 1].Groups[1].Value -eq 'true'
                        $registrationArgs = @{
                            Name = $name; Description = $description; Parameters = $parameters
                            ReadOnly = $readOnly; Visibility = 'external_visible'; File = $relative
                            Line = $line; Evidence = 'assigned_tool_definition'
                            ParameterExpression = $parameterExpression
                            WorkspaceAware = $false
                        }
                        $registrations.Add((New-Registration @registrationArgs))
                        $fileContributed = $true
                    }
                }
            }
        }
        $cursor = $close + 1
    }

    foreach ($wrapper in @('register_tool', 'register_direct_alias', 'register_dispatch_alias')) {
        $matches = [regex]::Matches($source, "(?<![.A-Za-z0-9_])$wrapper\s*\(")
        foreach ($match in $matches) {
            $open = $source.IndexOf('(', $match.Index)
            $close = Get-MatchingIndex $source $open '(' ')'
            $after = $close + 1
            while ($after -lt $source.Length -and [char]::IsWhiteSpace($source[$after])) { ++$after }
            if ($after -lt $source.Length -and $source[$after] -eq '{') { continue }
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
                WorkspaceAware = $false
            }
            $registrations.Add((New-Registration @registrationArgs))
            $fileContributed = $true
        }
    }
    if ($fileContributed) { $sourceFiles.Add($file.FullName) }
}

$idaCompatibility = Get-IdaCompatibilityInventory $idaSchemaPath $idaReadPath $idaMutationPath $mcpToolsPath $sessionToolsPath
$registeredNames = [Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
foreach ($registration in $registrations) {
    if (!$registeredNames.Add([string]$registration.name)) {
        throw "Duplicate statically resolved MCP registration: $($registration.name)"
    }
}
foreach ($record in $idaCompatibility.records) {
    if (!$registeredNames.Add([string]$record.name)) {
        if ([string]$record.name -eq 'list_instances') {
            foreach ($registration in $registrations) {
                if ([string]$registration.name -eq 'list_instances') {
                    $registration.input_schema = $record.input_schema
                    $registration.parameter_expression = 'ida_compat::find_schema("list_instances")'
                    $registration.source.evidence = 'source_resolved_session_list_instances_with_ida_compat_schema'
                    break
                }
            }
            continue
        }
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
        Evidence = 'source_resolved_ida_compat_registration'
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
$uiActions = @($uiActions | Sort-Object label, line -Unique)
$shortcuts = [Collections.Generic.List[object]]::new()
foreach ($match in [regex]::Matches($helpersSource, 'ImGuiKey_[A-Za-z0-9_]+')) {
    $lineStart = $helpersSource.LastIndexOf("`n", $match.Index)
    $lineEnd = $helpersSource.IndexOf("`n", $match.Index)
    if ($lineStart -lt 0) { $lineStart = 0 } else { ++$lineStart }
    if ($lineEnd -lt 0) { $lineEnd = $helpersSource.Length }
    $shortcuts.Add([ordered]@{
        key = $match.Value
        line = Get-LineNumber $helpersSource $match.Index
        expression = ($helpersSource.Substring($lineStart, $lineEnd - $lineStart) -replace '\s+', ' ').Trim()
    })
}
$sessionMethods = @([regex]::Matches($sessionHeader, '(?m)^\s*(?:static\s+)?[A-Za-z_:][A-Za-z0-9_:<>,\s*&]*\s+([A-Za-z_]\w*)\s*\([^;{}]*\)\s*(?:const\s*)?(?:noexcept\s*)?;') |
    ForEach-Object { $_.Groups[1].Value } | Sort-Object -Unique)

$sourceContracts = [Collections.Generic.List[object]]::new()
$contractArgs = @{
    Id = 'explicit_workspace_persistence'
    Path = $sessionSourcePath
    Source = $sessionSource
    Marker = 'acquire_static_workspace(const std::string& path,'
    Symbol = 'analysis_session::acquire_static_workspace'
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
        'search_index_t::build(snapshot',
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
    Marker = 'bool open_attach_session(std::uint32_t pid, std::string* out_err)'
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
        'bool read_live_memory(const disasm_view::workspace_context_t& context,',
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
        'active_center_view = center_view_t::hex_view'
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
        registration_count = $idaCompatibility.records.Count
        read_only_names = $idaCompatibility.read_only_names
        mutation_names = $idaCompatibility.mutation_names
        target_dependent_names = $idaCompatibility.target_dependent_names
        schema_source = Get-Relative $idaSchemaPath
    }
}

$allEvidenceFiles = @($sourceFiles + $idaCompatibility.evidence_files +
    $hexCallInventory.absolute_files + @($mcpPath, $globalsPath, $helpersPath,
    $sessionHeaderPath, $sessionSourcePath, $workspaceRegistryPath,
    $driverIdentityPath, $driverSourcePath, $hexHeaderPath, $hexSourcePath,
    $fileBrowserPath, $calculatorToolPath, $decompilerServicePath, $mainPath,
    $PSCommandPath) | Sort-Object -Unique)
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

function Convert-CanonicalJson([object]$Value) {
    return ConvertTo-Json -InputObject $Value -Depth 64 -Compress
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
    foreach ($entry in $referenceDynamic) {
        $matched = @($candidateDynamic | Where-Object {
            [string](Get-ObjectField $_ 'file') -eq [string](Get-ObjectField $entry 'file') -and
            [string](Get-ObjectField $_ 'expression') -eq [string](Get-ObjectField $entry 'expression')
        }).Count -ne 0
        if (!$matched) {
            throw "Removed unresolved dynamic registration template relative to $ReferenceLabel"
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
        [void]$candidateShortcutKeys.Add(
            ([string](Get-ObjectField $entry 'key')) + "`n" +
            ([string](Get-ObjectField $entry 'expression')))
    }
    foreach ($entry in @((Get-ObjectField $referenceUi 'shortcuts'))) {
        $key = ([string](Get-ObjectField $entry 'key')) + "`n" +
            ([string](Get-ObjectField $entry 'expression'))
        if (!$candidateShortcutKeys.Contains($key)) {
            throw "Removed or changed UI shortcut relative to ${ReferenceLabel}: $([string](Get-ObjectField $entry 'key'))"
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
            'read_only', 'visibility_declared', 'visibility_effective', 'workspace_aware')
        protected_resource_fields = @('uri', 'name', 'description', 'mime_type', 'result_fields')
        protected_ui_fields = @('center_views', 'actions', 'shortcuts')
        protected_session_fields = @('public_method_names')
    }
    mcp = [ordered]@{
        registration_count = $registrations.Count
        unique_name_count = @($registrations.name | Sort-Object -Unique).Count
        registrations = $registrations
        duplicate_names = $duplicateNames
        dynamic_registration_templates = @($dynamicEvidence | Sort-Object file, line)
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
        shortcuts = @($shortcuts | Sort-Object key, line)
    }
    session = [ordered]@{
        public_method_names = $sessionMethods
        header = Get-Relative $sessionHeaderPath
        implementation = Get-Relative $sessionSourcePath
    }
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
    resolved_dynamic_templates = $dynamicEvidence.Count
    unresolved_dynamic_templates = $dynamicEvidence.Count
    ida_compatibility_registrations = $idaCompatibility.records.Count
    resources = $resources.Count
    center_views = $centerViews.Count
    source_contracts = $sourceContracts.Count
} | ConvertTo-Json -Compress
