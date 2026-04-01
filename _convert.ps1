param([string]$inputFile, [string]$outputFile, [string]$namespaceName, [string]$registerFuncName, [bool]$needsEaCompat = $false)

$content = Get-Content $inputFile -Raw -Encoding UTF8

# ---- Replace namespace wrapper ----
# Remove opening "namespace <name>\n{" and replace with anonymous namespace for statics + named function
# Actually we keep all the static functions in an anonymous namespace and only expose the register function

# ---- Replace IDA types/helpers ----
if ($needsEaCompat) {
    # Replace ea_t with uint64_t
    $content = $content -replace '\bea_t\b', 'uint64_t'
    
    # Replace BADADDR
    $content = $content -replace '\bBADADDR\b', '0xFFFFFFFFFFFFFFFFULL'
    
    # Replace helpers::parse_address -> sa_parse_address
    $content = $content -replace 'helpers::parse_address', 'sa_parse_address'
    
    # Replace helpers::format_address -> sa_format_address (cast away ea_t refs)
    $content = $content -replace 'helpers::format_address', 'sa_format_address'
}

# ---- Remove anti_re:: calls ----
# Pattern: anti_re::guard_driver_self_access(...); -> // (removed for standalone)
$content = $content -replace 'anti_re::guard_driver_self_access\([^)]*\);', '/* standalone: anti-RE check removed */'
# Pattern: anti_re::is_self_target_pid(...) -> false
$content = $content -replace 'anti_re::is_self_target_pid\([^)]*\)', 'false'

# ---- Replace tool_result_t references ----
# The code already uses tool_result_t::ok() and tool_result_t::error() which will resolve to the using declaration

# ---- Replace ToolRegistry registration ----
# Change "auto& registry = ToolRegistry::instance();" -> removed (we use srv parameter)
$content = $content -replace 'auto& registry = ToolRegistry::instance\(\);\s*\r?\n', ''

# Change "registry.register_tool({" -> "register_compat(srv, {"
$content = $content -replace 'registry\.register_tool\(\{', 'register_compat(srv, {'

Write-Output "Processed $inputFile -> patterns replaced"

# Write output
[System.IO.File]::WriteAllText($outputFile, $content, [System.Text.UTF8Encoding]::new($false))
