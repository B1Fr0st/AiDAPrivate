#include "pseudocode_readability.hpp"

#include "type_graph_builder.hpp"

#include <algorithm>
#include <array>
#include <cctype>
#include <cstring>
#include <limits>
#include <map>
#include <optional>
#include <set>
#include <string>
#include <string_view>
#include <unordered_map>
#include <unordered_set>
#include <utility>
#include <vector>

namespace aida::analysis {
namespace {

enum class identifier_style_t : std::uint8_t {
    flat_lower,
    flat_upper,
    lower_snake,
    upper_snake,
    lower_camel,
    upper_camel,
    mixed
};

decompiler_diagnostic_t readability_diagnostic(
    const decompiler_diagnostic_code_t code,
    std::string key,
    const std::uint32_t ordinal)
{
    decompiler_diagnostic_t result;
    result.severity = decompiler_diagnostic_severity_t::error;
    result.code = code;
    result.localization_key = std::move(key);
    result.confidence = 100;
    result.ordinal = ordinal;
    return result;
}

std::uint32_t next_ordinal(const std::vector<decompiler_diagnostic_t>& diagnostics) noexcept
{
    std::uint32_t result = 1;
    for (const auto& diagnostic : diagnostics) {
        if (diagnostic.ordinal >= result && diagnostic.ordinal != std::numeric_limits<std::uint32_t>::max())
            result = diagnostic.ordinal + 1;
    }
    return result;
}

void append_u32(std::string& output, const std::uint32_t value)
{
    for (unsigned int shift = 0; shift != 32; shift += 8)
        output.push_back(static_cast<char>((value >> shift) & 0xffU));
}

void append_u64(std::string& output, const std::uint64_t value)
{
    for (unsigned int shift = 0; shift != 64; shift += 8)
        output.push_back(static_cast<char>((value >> shift) & 0xffULL));
}

void append_bytes(std::string& output, const std::string& value)
{
    append_u64(output, static_cast<std::uint64_t>(value.size()));
    output.append(value);
}

bool visible_text(const std::string& value) noexcept
{
    return !value.empty() && std::none_of(value.begin(), value.end(), [](const char character) {
        return character == '\r' || character == '\n' || character == '\0';
    });
}

bool valid_limits(const pseudocode_readability_limits_t& limits) noexcept
{
    return limits.max_ast_nodes != 0 && limits.max_traversal_edges != 0 && limits.max_nesting != 0 &&
           limits.max_document_bytes != 0 && limits.max_tokens != 0 && limits.max_source_maps != 0 &&
           limits.max_diagnostics != 0 && limits.max_unknowns != 0 && limits.max_baseline_bytes != 0 &&
           limits.max_fixture_id_bytes != 0 &&
           limits.max_document_bytes <= std::numeric_limits<std::uint32_t>::max() &&
           limits.max_baseline_bytes <= std::numeric_limits<std::uint32_t>::max();
}

bool expression_kind(const typed_pseudocode_ast_node_kind_t kind) noexcept
{
    return kind >= typed_pseudocode_ast_node_kind_t::assignment_expression &&
           kind <= typed_pseudocode_ast_node_kind_t::unknown_expression;
}

bool control_kind(const typed_pseudocode_ast_node_kind_t kind) noexcept
{
    switch (kind) {
    case typed_pseudocode_ast_node_kind_t::if_statement:
    case typed_pseudocode_ast_node_kind_t::while_statement:
    case typed_pseudocode_ast_node_kind_t::do_while_statement:
    case typed_pseudocode_ast_node_kind_t::for_statement:
    case typed_pseudocode_ast_node_kind_t::switch_statement:
    case typed_pseudocode_ast_node_kind_t::switch_case:
    case typed_pseudocode_ast_node_kind_t::try_statement:
    case typed_pseudocode_ast_node_kind_t::catch_clause:
    case typed_pseudocode_ast_node_kind_t::finally_clause:
        return true;
    default:
        return false;
    }
}

std::string identifier_component(std::string value)
{
    const auto scope = value.rfind("::");
    if (scope != std::string::npos)
        value.erase(0, scope + 2);
    const auto first = value.find_first_not_of('_');
    if (first == std::string::npos)
        return {};
    value.erase(0, first);
    return value;
}

identifier_style_t identifier_style(std::string value)
{
    value = identifier_component(std::move(value));
    if (value.empty())
        return identifier_style_t::mixed;
    bool has_upper = false;
    bool has_lower = false;
    bool has_underscore = false;
    for (const char raw : value) {
        const auto character = static_cast<unsigned char>(raw);
        has_upper = has_upper || std::isupper(character) != 0;
        has_lower = has_lower || std::islower(character) != 0;
        has_underscore = has_underscore || raw == '_';
    }
    if (has_underscore) {
        if (has_lower && !has_upper)
            return identifier_style_t::lower_snake;
        if (has_upper && !has_lower)
            return identifier_style_t::upper_snake;
        return identifier_style_t::mixed;
    }
    const auto first = static_cast<unsigned char>(value.front());
    if (has_lower && !has_upper)
        return identifier_style_t::flat_lower;
    if (has_upper && !has_lower)
        return identifier_style_t::flat_upper;
    if (std::islower(first) != 0)
        return identifier_style_t::lower_camel;
    if (std::isupper(first) != 0)
        return identifier_style_t::upper_camel;
    return identifier_style_t::mixed;
}

double naming_consistency(const std::set<std::string>& identifiers) noexcept
{
    if (identifiers.empty())
        return 1.0;
    std::array<std::size_t, 7> counts{};
    for (const auto& identifier : identifiers)
        ++counts[static_cast<std::size_t>(identifier_style(identifier))];
    const auto maximum = *std::max_element(counts.begin(), counts.end());
    return static_cast<double>(maximum) / static_cast<double>(identifiers.size());
}

bool complete_source_map(const decompiler_document_t& document, std::size_t& mapped_bytes) noexcept
{
    mapped_bytes = 0;
    if (document.tokens.size() != document.source_maps.size())
        return false;
    std::uint32_t expected = 0;
    for (std::size_t index = 0; index < document.tokens.size(); ++index) {
        const auto& token = document.tokens[index];
        const auto& source_map = document.source_maps[index];
        if (token.range.begin != expected || token.range.begin != source_map.document_range.begin ||
            token.range.end != source_map.document_range.end)
            return false;
        mapped_bytes += source_map.document_range.end - source_map.document_range.begin;
        expected = source_map.document_range.end;
    }
    return expected == document.rendered_text.size() && mapped_bytes == document.rendered_text.size();
}

struct traversal_result_t {
    pseudocode_readability_metrics_t metrics;
    std::set<std::string> identifiers;
    std::size_t visited_nodes = 0;
    std::size_t traversed_edges = 0;
    std::uint64_t confidence_sum = 0;
    std::uint8_t minimum_confidence = 100;
    bool valid = false;
    std::string error_key;
};

traversal_result_t traverse_ast(
    const typed_pseudocode_ast_v2_t& ast,
    const pseudocode_readability_limits_t& limits)
{
    traversal_result_t result;
    std::map<std::uint64_t, std::size_t> indices;
    for (std::size_t index = 0; index < ast.nodes.size(); ++index)
        indices.emplace(ast.nodes[index].id, index);
    const auto root = indices.find(ast.root_node_id);
    if (root == indices.end()) {
        result.error_key = "decompiler.readability.v2.root";
        return result;
    }
    struct frame_t {
        std::size_t node_index = 0;
        std::size_t next_child = 0;
        std::size_t expression_depth = 0;
        std::size_t control_depth = 0;
        bool entered = false;
    };
    std::vector<frame_t> stack;
    std::vector<bool> active(ast.nodes.size(), false);
    std::vector<bool> counted(ast.nodes.size(), false);
    stack.push_back({root->second, 0, 0, 0, false});
    while (!stack.empty()) {
        auto& frame = stack.back();
        const auto& node = ast.nodes[frame.node_index];
        if (!frame.entered) {
            if (active[frame.node_index]) {
                result.error_key = "decompiler.readability.v2.cyclic_ast";
                return result;
            }
            active[frame.node_index] = true;
            frame.entered = true;
            const bool expression = expression_kind(node.kind);
            frame.expression_depth = expression ? frame.expression_depth + 1 : 0;
            frame.control_depth = control_kind(node.kind) ? frame.control_depth + 1 : frame.control_depth;
            if ((std::max)(frame.expression_depth, frame.control_depth) > limits.max_nesting) {
                result.error_key = "decompiler.readability.v2.nesting_limit";
                return result;
            }
            result.metrics.max_expression_depth = (std::max)(result.metrics.max_expression_depth,
                static_cast<std::uint64_t>(frame.expression_depth));
            result.metrics.max_control_nesting = (std::max)(result.metrics.max_control_nesting,
                static_cast<std::uint64_t>(frame.control_depth));
            if (!counted[frame.node_index]) {
                counted[frame.node_index] = true;
                ++result.visited_nodes;
                result.confidence_sum += node.confidence;
                result.minimum_confidence = (std::min)(result.minimum_confidence, node.confidence);
                if (node.kind == typed_pseudocode_ast_node_kind_t::declaration)
                    ++result.metrics.declaration_count;
                if (node.kind == typed_pseudocode_ast_node_kind_t::cast_expression)
                    ++result.metrics.cast_count;
                if (node.kind == typed_pseudocode_ast_node_kind_t::unknown_expression)
                    ++result.metrics.dead_placeholder_count;
                if ((node.kind == typed_pseudocode_ast_node_kind_t::function_definition ||
                     node.kind == typed_pseudocode_ast_node_kind_t::declaration ||
                     node.kind == typed_pseudocode_ast_node_kind_t::identifier) &&
                    visible_text(node.stable_text))
                    result.identifiers.insert(node.stable_text);
            }
        }
        if (frame.next_child == node.child_ids.size()) {
            active[frame.node_index] = false;
            stack.pop_back();
            continue;
        }
        if (++result.traversed_edges > limits.max_traversal_edges) {
            result.error_key = "decompiler.readability.v2.traversal_limit";
            return result;
        }
        const auto child = indices.find(node.child_ids[frame.next_child++]);
        if (child == indices.end()) {
            result.error_key = "decompiler.readability.v2.missing_child";
            return result;
        }
        if (active[child->second]) {
            result.error_key = "decompiler.readability.v2.cyclic_ast";
            return result;
        }
        stack.push_back({child->second, 0, frame.expression_depth, frame.control_depth, false});
    }
    if (result.visited_nodes != ast.nodes.size()) {
        result.error_key = "decompiler.readability.v2.unreachable_node";
        return result;
    }
    result.metrics.naming_consistency_ratio = naming_consistency(result.identifiers);
    result.valid = true;
    return result;
}

sha256_digest_t baseline_capture_hash(const pseudocode_baseline_capture_t& capture)
{
    std::string canonical;
    append_u32(canonical, capture.schema_version);
    canonical.push_back(static_cast<char>(capture.provider));
    append_bytes(canonical, capture.provider_build_hash.to_hex());
    append_bytes(canonical, capture.fixture_set_hash.to_hex());
    append_bytes(canonical, capture.fixture_id);
    append_bytes(canonical, capture.rendered_text);
    append_u64(canonical, static_cast<std::uint64_t>(capture.diagnostics.size()));
    for (const auto& diagnostic : capture.diagnostics)
        append_bytes(canonical, serialize_decompiler_diagnostic(diagnostic));
    return stable_serialization_hash(canonical);
}

bool rt_is_generated_name(const std::string& name)
{
    if (name.empty())
        return false;
    static const std::vector<std::pair<std::string, bool>> prefixes = {
        {"local_", true}, {"var_", true}, {"tmp_", true}, {"stack_", true},
        {"in_", true}, {"out_", true}, {"param_", true}, {"unaff_", false},
        {"unnamed_", false}, {"uVar", true}, {"puVar", true}, {"pVar", true},
        {"iVar", true}, {"uStack", true}, {"extraout_", false},
    };
    for (const auto& [prefix, require_digits] : prefixes) {
        if (name.size() > prefix.size() && name.compare(0, prefix.size(), prefix) == 0) {
            if (!require_digits)
                return true;
            const auto rest = name.substr(prefix.size());
            if (!rest.empty() && std::all_of(rest.begin(), rest.end(),
                    [](const unsigned char c) { return std::isdigit(c) != 0; }))
                return true;
        }
    }
    if (name.size() > 1 && name[0] == 'v' && std::all_of(name.begin() + 1, name.end(),
            [](const unsigned char c) { return std::isdigit(c) != 0; }))
        return true;
    if (name.size() > 3 && name.compare(0, 3, "arg") == 0 && std::all_of(name.begin() + 3, name.end(),
            [](const unsigned char c) { return std::isdigit(c) != 0; }))
        return true;
    return false;
}

std::string rt_sanitize_identifier(const std::string& value)
{
    if (value.empty())
        return "renamed";
    std::string result;
    result.reserve(value.size());
    bool first = true;
    for (const char c : value) {
        if (first) {
            if (std::isalpha(static_cast<unsigned char>(c)) != 0 || c == '_')
                result.push_back(c);
            else
                result.push_back('_');
            first = false;
        } else {
            if (std::isalnum(static_cast<unsigned char>(c)) != 0 || c == '_')
                result.push_back(c);
        }
    }
    if (result.empty())
        return "renamed";
    return result;
}

std::string rt_to_camel_case(const std::string& value)
{
    if (value.empty())
        return {};
    std::string result;
    result.reserve(value.size());
    bool capitalize_next = false;
    bool first_word = true;
    for (std::size_t i = 0; i < value.size(); ++i) {
        const auto c = static_cast<unsigned char>(value[i]);
        if (std::isalnum(c) != 0 || c == '_') {
            if (c == '_') {
                capitalize_next = true;
                continue;
            }
            if (first_word) {
                result.push_back(static_cast<char>(std::tolower(c)));
                first_word = false;
            } else if (capitalize_next) {
                result.push_back(static_cast<char>(std::toupper(c)));
                capitalize_next = false;
            } else {
                result.push_back(static_cast<char>(std::tolower(c)));
            }
        } else {
            capitalize_next = true;
        }
    }
    if (result.empty())
        return {};
    return rt_sanitize_identifier(result);
}

std::optional<std::int64_t> rt_parse_signed(const std::string& text)
{
    if (text.empty())
        return std::nullopt;
    std::string cleaned = text;
    if (cleaned.size() > 2 && cleaned[0] == '0' && (cleaned[1] == 'x' || cleaned[1] == 'X')) {
        try {
            return static_cast<std::int64_t>(std::stoull(cleaned, nullptr, 16));
        } catch (...) {
            return std::nullopt;
        }
    }
    if (!cleaned.empty() && cleaned.back() == 'L') {
        cleaned.pop_back();
        if (!cleaned.empty() && cleaned.back() == 'L')
            cleaned.pop_back();
    }
    if (!cleaned.empty() && cleaned.back() == 'U') {
        cleaned.pop_back();
        if (!cleaned.empty() && cleaned.back() == 'U')
            cleaned.pop_back();
    }
    try {
        std::size_t pos = 0;
        const auto value = std::stoll(cleaned, &pos);
        if (pos != cleaned.size())
            return std::nullopt;
        return value;
    } catch (...) {
        return std::nullopt;
    }
}

std::string rt_format_signed(std::int64_t value)
{
    return std::to_string(value);
}

const std::unordered_map<std::string, std::vector<std::string>>& rt_api_param_names()
{
    static const std::unordered_map<std::string, std::vector<std::string>> table{
        {"CreateFileW", {"filename", "access", "share_mode", "security", "creation_disposition", "flags", "template_handle"}},
        {"CreateFileA", {"filename", "access", "share_mode", "security", "creation_disposition", "flags", "template_handle"}},
        {"ReadFile", {"handle", "buffer", "bytes_to_read", "bytes_read", "overlapped"}},
        {"WriteFile", {"handle", "buffer", "bytes_to_write", "bytes_written", "overlapped"}},
        {"CloseHandle", {"handle"}},
        {"malloc", {"size"}},
        {"calloc", {"count", "size"}},
        {"realloc", {"ptr", "size"}},
        {"free", {"ptr"}},
        {"memcpy", {"dst", "src", "size"}},
        {"memmove", {"dst", "src", "size"}},
        {"memset", {"dst", "value", "size"}},
        {"memcmp", {"lhs", "rhs", "size"}},
        {"strcpy", {"dst", "src"}},
        {"strncpy", {"dst", "src", "count"}},
        {"strcat", {"dst", "src"}},
        {"strncat", {"dst", "src", "count"}},
        {"strcmp", {"lhs", "rhs"}},
        {"strncmp", {"lhs", "rhs", "count"}},
        {"strlen", {"str"}},
        {"strchr", {"str", "character"}},
        {"strrchr", {"str", "character"}},
        {"strstr", {"str", "substr"}},
        {"sprintf", {"buffer", "format"}},
        {"snprintf", {"buffer", "size", "format"}},
        {"_snprintf", {"buffer", "size", "format"}},
        {"printf", {"format"}},
        {"fprintf", {"stream", "format"}},
        {"fopen", {"filename", "mode"}},
        {"fopen_s", {"file_ptr", "filename", "mode"}},
        {"fclose", {"stream"}},
        {"fread", {"buffer", "size", "count", "stream"}},
        {"fwrite", {"buffer", "size", "count", "stream"}},
        {"fseek", {"stream", "offset", "origin"}},
        {"ftell", {"stream"}},
        {"VirtualAlloc", {"address", "size", "allocation_type", "protect"}},
        {"VirtualFree", {"address", "size", "free_type"}},
        {"VirtualProtect", {"address", "size", "new_protect", "old_protect"}},
        {"HeapAlloc", {"heap", "flags", "size"}},
        {"HeapFree", {"heap", "flags", "ptr"}},
        {"LoadLibraryW", {"filename"}},
        {"LoadLibraryA", {"filename"}},
        {"LoadLibraryExW", {"filename", "file", "flags"}},
        {"LoadLibraryExA", {"filename", "file", "flags"}},
        {"GetProcAddress", {"module", "name"}},
        {"GetModuleHandleW", {"module_name"}},
        {"GetModuleHandleA", {"module_name"}},
        {"GetLastError", {}},
        {"SetLastError", {"error_code"}},
        {"GetProcessId", {"process"}},
        {"GetThreadId", {"thread"}},
        {"CreateThread", {"attributes", "stack_size", "start_address", "parameter", "creation_flags", "thread_id"}},
        {"TerminateProcess", {"process", "exit_code"}},
        {"GetExitCodeProcess", {"process", "exit_code"}},
        {"WaitForSingleObject", {"handle", "milliseconds"}},
        {"WaitForMultipleObjects", {"count", "handles", "wait_all", "milliseconds"}},
        {"Sleep", {"milliseconds"}},
        {"GetEnvironmentVariableW", {"name", "buffer", "size"}},
        {"GetEnvironmentVariableA", {"name", "buffer", "size"}},
        {"SetEnvironmentVariableW", {"name", "value"}},
        {"SetEnvironmentVariableA", {"name", "value"}},
        {"GetCommandLineW", {}},
        {"GetCommandLineA", {}},
        {"lstrcpyW", {"dst", "src"}},
        {"lstrcpyA", {"dst", "src"}},
        {"lstrcpynW", {"dst", "src", "length"}},
        {"lstrcpynA", {"dst", "src", "length"}},
        {"lstrlenW", {"str"}},
        {"lstrlenA", {"str"}},
        {"MultiByteToWideChar", {"code_page", "flags", "multi_byte_str", "cb_multi_byte", "wide_char_str", "cch_wide_char"}},
        {"WideCharToMultiByte", {"code_page", "flags", "wide_char_str", "cch_wide_char", "multi_byte_str", "cb_multi_byte", "default_char", "used_default_char"}},
        {"RegOpenKeyExW", {"key", "subkey", "reserved", "access", "result"}},
        {"RegOpenKeyExA", {"key", "subkey", "reserved", "access", "result"}},
        {"RegQueryValueExW", {"key", "value_name", "reserved", "type", "data", "cbdata"}},
        {"RegSetValueExW", {"key", "value_name", "reserved", "type", "data", "cbdata"}},
        {"RegCloseKey", {"key"}},
        {"RegCreateKeyExW", {"key", "subkey", "reserved", "class_name", "options", "access", "security", "result", "disposition"}},
        {"RegCreateKeyExA", {"key", "subkey", "reserved", "class_name", "options", "access", "security", "result", "disposition"}},
        {"RegDeleteKeyW", {"key", "subkey"}},
        {"RegDeleteKeyA", {"key", "subkey"}},
        {"RegDeleteValueW", {"key", "value_name"}},
        {"RegDeleteValueA", {"key", "value_name"}},
        {"RegEnumKeyExW", {"key", "index", "name", "cbname", "reserved", "class_name", "cbclass", "last_write"}},
        {"RegEnumKeyExA", {"key", "index", "name", "cbname", "reserved", "class_name", "cbclass", "last_write"}},
        {"RegEnumValueW", {"key", "index", "value_name", "cbvalue_name", "reserved", "type", "data", "cbdata"}},
        {"RegEnumValueA", {"key", "index", "value_name", "cbvalue_name", "reserved", "type", "data", "cbdata"}},
        {"RegQueryInfoKeyW", {"key", "class_name", "cbclass", "reserved", "subkey_count", "max_subkey_len", "max_class_len", "value_count", "max_value_name_len", "max_value_len", "security_descriptor_len", "last_write"}},
        {"WSASocketW", {"af", "type", "protocol", "protocol_info", "group", "flags"}},
        {"socket", {"af", "type", "protocol"}},
        {"connect", {"sock", "address", "address_len"}},
        {"send", {"sock", "buffer", "length", "flags"}},
        {"recv", {"sock", "buffer", "length", "flags"}},
        {"bind", {"sock", "address", "address_len"}},
        {"listen", {"sock", "backlog"}},
        {"accept", {"sock", "address", "address_len"}},
        {"closesocket", {"sock"}},
        {"CreateDirectoryW", {"path", "security"}},
        {"CreateDirectoryA", {"path", "security"}},
        {"DeleteFileW", {"filename"}},
        {"DeleteFileA", {"filename"}},
        {"MoveFileW", {"existing", "target"}},
        {"MoveFileA", {"existing", "target"}},
        {"MoveFileExW", {"existing", "target", "flags"}},
        {"MoveFileExA", {"existing", "target", "flags"}},
        {"CopyFileW", {"existing", "target", "fail_if_exists"}},
        {"CopyFileA", {"existing", "target", "fail_if_exists"}},
        {"FindFirstFileW", {"pattern", "find_data"}},
        {"FindFirstFileA", {"pattern", "find_data"}},
        {"FindFirstFileExW", {"pattern", "info_level", "find_data", "search_op", "search_filter", "flags"}},
        {"FindNextFileW", {"find_handle", "find_data"}},
        {"FindNextFileA", {"find_handle", "find_data"}},
        {"FindClose", {"find_handle"}},
        {"GetFileAttributesW", {"filename"}},
        {"GetFileAttributesA", {"filename"}},
        {"SetFileAttributesW", {"filename", "attributes"}},
        {"SetFileAttributesA", {"filename", "attributes"}},
        {"GetFileSize", {"file", "high_size"}},
        {"GetFileSizeEx", {"file", "size"}},
        {"SetEndOfFile", {"file"}},
        {"SetFilePointer", {"file", "distance", "high_distance", "method"}},
        {"SetFilePointerEx", {"file", "distance", "new_pointer", "method"}},
        {"FlushFileBuffers", {"file"}},
        {"CreateFileMappingW", {"file", "security", "protect", "max_size_high", "max_size_low", "name"}},
        {"CreateFileMappingA", {"file", "security", "protect", "max_size_high", "max_size_low", "name"}},
        {"MapViewOfFile", {"mapping", "access", "offset_high", "offset_low", "size"}},
        {"UnmapViewOfFile", {"address"}},
        {"FlushViewOfFile", {"address", "size"}},
        {"CreateProcessW", {"application", "command_line", "process_security", "thread_security", "inherit_handles", "creation_flags", "environment", "current_directory", "startup_info", "process_info"}},
        {"CreateProcessA", {"application", "command_line", "process_security", "thread_security", "inherit_handles", "creation_flags", "environment", "current_directory", "startup_info", "process_info"}},
        {"OpenProcess", {"access", "inherit_handle", "process_id"}},
        {"OpenThread", {"access", "inherit_handle", "thread_id"}},
        {"ResumeThread", {"thread"}},
        {"SuspendThread", {"thread"}},
        {"ExitProcess", {"exit_code"}},
        {"ExitThread", {"exit_code"}},
        {"GetCurrentProcess", {}},
        {"GetCurrentThread", {}},
        {"GetCurrentProcessId", {}},
        {"GetCurrentThreadId", {}},
        {"SwitchToThread", {}},
        {"TlsAlloc", {}},
        {"TlsGetValue", {"tls_index"}},
        {"TlsSetValue", {"tls_index", "value"}},
        {"TlsFree", {"tls_index"}},
        {"InitializeCriticalSection", {"critical_section"}},
        {"InitializeCriticalSectionEx", {"critical_section", "spin_count", "flags"}},
        {"EnterCriticalSection", {"critical_section"}},
        {"LeaveCriticalSection", {"critical_section"}},
        {"DeleteCriticalSection", {"critical_section"}},
        {"TryEnterCriticalSection", {"critical_section"}},
        {"CreateMutexW", {"security", "initial_owner", "name"}},
        {"CreateMutexA", {"security", "initial_owner", "name"}},
        {"ReleaseMutex", {"mutex"}},
        {"CreateEventW", {"security", "manual_reset", "initial_state", "name"}},
        {"CreateEventA", {"security", "manual_reset", "initial_state", "name"}},
        {"SetEvent", {"event"}},
        {"ResetEvent", {"event"}},
        {"PulseEvent", {"event"}},
        {"CreateSemaphoreW", {"security", "initial_count", "max_count", "name"}},
        {"CreateSemaphoreA", {"security", "initial_count", "max_count", "name"}},
        {"ReleaseSemaphore", {"semaphore", "release_count", "previous_count"}},
        {"InterlockedIncrement", {"addend"}},
        {"InterlockedDecrement", {"addend"}},
        {"InterlockedExchange", {"target", "value"}},
        {"InterlockedCompareExchange", {"destination", "exchange", "comparand"}},
        {"GlobalAlloc", {"flags", "size"}},
        {"GlobalFree", {"memory"}},
        {"GlobalLock", {"memory"}},
        {"GlobalUnlock", {"memory"}},
        {"LocalAlloc", {"flags", "size"}},
        {"LocalFree", {"memory"}},
        {"HeapCreate", {"flags", "initial_size", "max_size"}},
        {"HeapDestroy", {"heap"}},
        {"GetProcessHeap", {}},
        {"HeapReAlloc", {"heap", "flags", "ptr", "size"}},
        {"HeapSize", {"heap", "flags", "ptr"}},
        {"VirtualQuery", {"address", "buffer", "length"}},
        {"VirtualAllocEx", {"process", "address", "size", "allocation_type", "protect"}},
        {"VirtualFreeEx", {"process", "address", "size", "free_type"}},
        {"VirtualProtectEx", {"process", "address", "size", "new_protect", "old_protect"}},
        {"WriteProcessMemory", {"process", "address", "buffer", "size", "written"}},
        {"ReadProcessMemory", {"process", "address", "buffer", "size", "read"}},
        {"CreateRemoteThread", {"process", "security", "stack_size", "start_address", "parameter", "creation_flags", "thread_id"}},
        {"QueueUserAPC", {"apc_function", "thread", "data"}},
        {"RegisterClassExW", {"class_info"}},
        {"RegisterClassExA", {"class_info"}},
        {"CreateWindowExW", {"ex_style", "class_name", "window_name", "style", "x", "y", "width", "height", "parent", "menu", "instance", "param"}},
        {"CreateWindowExA", {"ex_style", "class_name", "window_name", "style", "x", "y", "width", "height", "parent", "menu", "instance", "param"}},
        {"DestroyWindow", {"hwnd"}},
        {"ShowWindow", {"hwnd", "show_command"}},
        {"UpdateWindow", {"hwnd"}},
        {"GetMessageW", {"message", "hwnd", "filter_min", "filter_max"}},
        {"GetMessageA", {"message", "hwnd", "filter_min", "filter_max"}},
        {"TranslateMessage", {"message"}},
        {"DispatchMessageW", {"message"}},
        {"DispatchMessageA", {"message"}},
        {"PostMessageW", {"hwnd", "message", "wparam", "lparam"}},
        {"PostMessageA", {"hwnd", "message", "wparam", "lparam"}},
        {"SendMessageW", {"hwnd", "message", "wparam", "lparam"}},
        {"SendMessageA", {"hwnd", "message", "wparam", "lparam"}},
        {"DefWindowProcW", {"hwnd", "message", "wparam", "lparam"}},
        {"DefWindowProcA", {"hwnd", "message", "wparam", "lparam"}},
        {"MessageBoxW", {"hwnd", "text", "caption", "type"}},
        {"MessageBoxA", {"hwnd", "text", "caption", "type"}},
        {"wsprintfW", {"buffer", "format"}},
        {"wsprintfA", {"buffer", "format"}},
        {"wvsprintfW", {"buffer", "format", "args"}},
        {"wvsprintfA", {"buffer", "format", "args"}},
        {"vsnprintf", {"buffer", "size", "format", "args"}},
        {"_vsnprintf", {"buffer", "size", "format", "args"}},
        {"vprintf", {"format", "args"}},
        {"puts", {"str"}},
        {"putchar", {"character"}},
        {"getchar", {}},
        {"scanf", {"format"}},
        {"sscanf", {"str", "format"}},
        {"fgets", {"buffer", "size", "stream"}},
        {"fputs", {"str", "stream"}},
        {"feof", {"stream"}},
        {"ferror", {"stream"}},
        {"fflush", {"stream"}},
        {"fgetc", {"stream"}},
        {"fputc", {"character", "stream"}},
        {"ungetc", {"character", "stream"}},
        {"rewind", {"stream"}},
        {"remove", {"filename"}},
        {"rename", {"old_name", "new_name"}},
        {"atoi", {"str"}},
        {"atol", {"str"}},
        {"atof", {"str"}},
        {"strtol", {"str", "end_ptr", "base"}},
        {"strtoul", {"str", "end_ptr", "base"}},
        {"strtod", {"str", "end_ptr"}},
        {"abs", {"value"}},
        {"labs", {"value"}},
        {"rand", {}},
        {"srand", {"seed"}},
        {"exit", {"code"}},
        {"abort", {}},
        {"_exit", {"code"}},
        {"system", {"command"}},
        {"getenv", {"name"}},
        {"_putenv", {"assignment"}},
        {"wcslen", {"str"}},
        {"wcscpy", {"dst", "src"}},
        {"wcsncpy", {"dst", "src", "count"}},
        {"wcscat", {"dst", "src"}},
        {"wcsncat", {"dst", "src", "count"}},
        {"wcscmp", {"lhs", "rhs"}},
        {"wcsncmp", {"lhs", "rhs", "count"}},
        {"wcschr", {"str", "character"}},
        {"wcsrchr", {"str", "character"}},
        {"wcsstr", {"str", "substr"}},
        {"wcstombs", {"dst", "src", "count"}},
        {"mbstowcs", {"dst", "src", "count"}},
        {"strdup", {"str"}},
        {"_strdup", {"str"}},
        {"_wcsdup", {"str"}},
        {"stricmp", {"lhs", "rhs"}},
        {"_stricmp", {"lhs", "rhs"}},
        {"_strnicmp", {"lhs", "rhs", "count"}},
        {"_wcsicmp", {"lhs", "rhs"}},
        {"_wcsnicmp", {"lhs", "rhs", "count"}},
        {"_memicmp", {"lhs", "rhs", "size"}},
        {"memcpy_s", {"dst", "dst_size", "src", "size"}},
        {"memmove_s", {"dst", "dst_size", "src", "size"}},
        {"strcpy_s", {"dst", "dst_size", "src"}},
        {"strcat_s", {"dst", "dst_size", "src"}},
        {"strncpy_s", {"dst", "dst_size", "src", "count"}},
        {"strncat_s", {"dst", "dst_size", "src", "count"}},
        {"sprintf_s", {"buffer", "size", "format"}},
        {"vsprintf_s", {"buffer", "size", "format", "args"}},
        {"_snprintf_s", {"buffer", "size", "count", "format"}},
        {"strnlen", {"str", "max_size"}},
        {"wcsnlen", {"str", "max_size"}},
        {"InternetOpenW", {"agent", "access_type", "proxy_name", "proxy_bypass", "flags"}},
        {"InternetOpenA", {"agent", "access_type", "proxy_name", "proxy_bypass", "flags"}},
        {"InternetConnectW", {"internet", "server", "port", "username", "password", "service", "flags", "context"}},
        {"InternetConnectA", {"internet", "server", "port", "username", "password", "service", "flags", "context"}},
        {"HttpOpenRequestW", {"session", "verb", "object_name", "version", "referer", "accept_types", "flags", "context"}},
        {"HttpOpenRequestA", {"session", "verb", "object_name", "version", "referer", "accept_types", "flags", "context"}},
        {"HttpSendRequestW", {"request", "headers", "headers_length", "optional", "optional_length"}},
        {"HttpSendRequestA", {"request", "headers", "headers_length", "optional", "optional_length"}},
        {"InternetReadFile", {"file", "buffer", "size", "bytes_read"}},
        {"InternetWriteFile", {"file", "buffer", "size", "bytes_written"}},
        {"InternetCloseHandle", {"handle"}},
        {"WSAStartup", {"version", "wsa_data"}},
        {"WSACleanup", {}},
        {"GetAddrInfoW", {"node", "service", "hints", "result"}},
        {"getaddrinfo", {"node", "service", "hints", "result"}},
        {"freeaddrinfo", {"addr_info"}},
        {"htons", {"host_short"}},
        {"htonl", {"host_long"}},
        {"ntohs", {"net_short"}},
        {"ntohl", {"net_long"}},
        {"inet_addr", {"address"}},
        {"setsockopt", {"sock", "level", "option_name", "option_value", "option_len"}},
        {"getsockopt", {"sock", "level", "option_name", "option_value", "option_len"}},
        {"shutdown", {"sock", "how"}},
        {"select", {"nfds", "read_fds", "write_fds", "except_fds", "timeout"}},
        {"ioctlsocket", {"sock", "command", "argument"}},
        {"recvfrom", {"sock", "buffer", "length", "flags", "from", "from_len"}},
        {"sendto", {"sock", "buffer", "length", "flags", "to", "to_len"}},
        {"WSAGetLastError", {}},
    };
    return table;
}

std::optional<std::string> rt_lookup_api_param(const std::string& api_name, std::size_t param_index)
{
    const auto& table = rt_api_param_names();
    const auto it = table.find(api_name);
    if (it == table.end() || param_index >= it->second.size())
        return std::nullopt;
    return it->second[param_index];
}

std::optional<std::string> rt_suggest_api_name(const std::string& api_name, std::size_t param_index)
{
    if (const auto exact = rt_lookup_api_param(api_name, param_index))
        return exact;
    if (!api_name.empty() && api_name.front() == '_') {
        if (const auto stripped = rt_lookup_api_param(api_name.substr(1), param_index))
            return stripped;
    }
    if (api_name.size() > 2 && api_name.compare(api_name.size() - 2, 2, "_s") == 0) {
        if (const auto unsuffixed = rt_lookup_api_param(api_name.substr(0, api_name.size() - 2), param_index))
            return unsuffixed;
    } else {
        if (const auto suffixed = rt_lookup_api_param(api_name + "_s", param_index))
            return suffixed;
    }
    if (api_name.size() > 1) {
        const char suffix = api_name.back();
        if (suffix == 'W' || suffix == 'A') {
            std::string swapped = api_name.substr(0, api_name.size() - 1);
            swapped.push_back(suffix == 'W' ? 'A' : 'W');
            if (const auto ansi_wide = rt_lookup_api_param(swapped, param_index))
                return ansi_wide;
        }
    }
    return std::nullopt;
}

std::optional<std::string> rt_suggest_type_name(const std::string& type_display)
{
    if (type_display.empty())
        return std::nullopt;
    static const std::vector<std::pair<std::string, std::string>> exact_matches{
        {"HANDLE", "handle"}, {"PHANDLE", "handle_ptr"}, {"HMODULE", "module"},
        {"HINSTANCE", "instance"}, {"HWND", "hwnd"}, {"HMENU", "menu"},
        {"HBITMAP", "bitmap"}, {"HBRUSH", "brush"}, {"HCURSOR", "cursor"},
        {"HICON", "icon"}, {"HFONT", "font"}, {"HPEN", "pen"},
        {"HRGN", "region"}, {"HDC", "dc"}, {"PWSTR", "string"},
        {"LPWSTR", "string"}, {"LPCWSTR", "string"}, {"PSTR", "string"},
        {"LPSTR", "string"}, {"LPCSTR", "string"}, {"SIZE_T", "size"},
        {"DWORD", "value"}, {"ULONG", "value"}, {"ULONG_PTR", "value"},
        {"UINT", "value"}, {"UINT32", "value"}, {"UINT64", "value"},
        {"INT", "value"}, {"INT32", "value"}, {"INT64", "value"},
        {"LONG", "value"}, {"LONGLONG", "value"}, {"BOOL", "result"},
        {"BYTE", "byte"}, {"WORD", "word"}, {"QWORD", "qword"},
        {"PVOID", "ptr"}, {"LPVOID", "ptr"}, {"HKEY", "key"},
        {"SC_HANDLE", "service_handle"}, {"SOCKET", "sock"},
        {"time_t", "time"}, {"pid_t", "pid"}, {"size_t", "size"},
        {"ssize_t", "size"}, {"ptrdiff_t", "offset"}, {"wchar_t", "wchar"},
        {"char", "ch"}, {"FILE", "file"},
    };
    for (const auto& [pattern, name] : exact_matches) {
        if (type_display == pattern)
            return name;
    }
    static const std::vector<std::pair<std::string, std::string>> suffix_matches{
        {"*", "ptr"}, {"Ptr", "ptr"}, {"Pointer", "ptr"},
        {"Handle", "handle"}, {"Context", "ctx"}, {"Buffer", "buffer"},
        {"Callback", "callback"}, {"Event", "event"}, {"Stream", "stream"},
    };
    for (const auto& [pattern, name] : suffix_matches) {
        if (type_display.size() > pattern.size() && type_display.compare(
                type_display.size() - pattern.size(), pattern.size(), pattern) == 0)
            return name;
    }
    if (type_display.size() > 6 && type_display.compare(0, 4, "LPWC") == 0)
        return "string";
    if (type_display.size() > 5 && type_display.compare(0, 3, "LPW") == 0)
        return "string";
    if (type_display.size() > 5 && type_display.compare(0, 3, "LPC") == 0)
        return "string";
    return std::nullopt;
}

bool rt_node_has_side_effects(const typed_pseudocode_ast_v2_t& ast,
    std::uint64_t node_id,
    const std::unordered_map<std::uint64_t, std::size_t>& index,
    std::unordered_set<std::uint64_t>& visited,
    std::size_t& depth,
    std::size_t max_depth)
{
    if (depth >= max_depth || !visited.insert(node_id).second)
        return true;
    ++depth;
    const auto it = index.find(node_id);
    if (it == index.end()) {
        --depth;
        return true;
    }
    const auto& node = ast.nodes[it->second];
    if (node.kind == typed_pseudocode_ast_node_kind_t::call_expression ||
        node.kind == typed_pseudocode_ast_node_kind_t::assignment_expression ||
        node.kind == typed_pseudocode_ast_node_kind_t::unknown_expression) {
        --depth;
        return true;
    }
    for (const auto child_id : node.child_ids) {
        if (rt_node_has_side_effects(ast, child_id, index, visited, depth, max_depth)) {
            --depth;
            return true;
        }
    }
    --depth;
    return false;
}

bool rt_node_has_side_effects(const typed_pseudocode_ast_v2_t& ast,
    std::uint64_t node_id,
    const std::unordered_map<std::uint64_t, std::size_t>& index)
{
    std::unordered_set<std::uint64_t> visited;
    std::size_t depth = 0;
    return rt_node_has_side_effects(ast, node_id, index, visited, depth, 512);
}

struct rt_variable_info_t {
    std::string name;
    std::uint64_t type_id = 0;
    std::vector<std::uint64_t> declaration_ids;
    std::vector<std::uint64_t> identifier_ids;
    std::vector<std::uint64_t> assignment_target_ids;
    bool is_parameter = false;
    bool is_generated = false;
    bool is_loop_counter = false;
    int loop_depth = 0;
    std::optional<std::string> api_suggested_name;
    std::optional<std::string> type_suggested_name;
    std::optional<std::string> string_suggested_name;
    std::string final_suggested_name;
};

struct rt_def_use_entry_t {
    std::string variable;
    std::uint64_t statement_id = 0;
    std::uint64_t definition_node_id = 0;
    std::uint64_t initializer_node_id = 0;
    bool is_declaration = false;
    bool has_side_effects = false;
};

constexpr std::size_t k_max_parent_chain_depth = 512;
constexpr std::size_t k_max_member_chain_depth = 8;

class rt_transformer_t {
public:
    rt_transformer_t(
        typed_pseudocode_ast_v2_t& ast,
        const type_graph_t& type_graph,
        const readability_transform_settings_t& settings,
        const decompiler_render_evidence_t& evidence)
        : ast_(ast), type_graph_(type_graph), settings_(settings), evidence_(evidence)
    {
        for (const auto& type : type_graph_.nodes)
            types_.emplace(type.id, &type);
    }

    readability_transform_result_t run()
    {
        readability_transform_result_t result;
        if (ast_.nodes.empty()) {
            result.diagnostics.push_back(rt_make_diagnostic(
                decompiler_diagnostic_code_t::malformed_ast,
                "readability.empty_ast", std::nullopt));
            return result;
        }
        if (ast_.nodes.size() > settings_.max_transform_nodes) {
            result.diagnostics.push_back(rt_make_diagnostic(
                decompiler_diagnostic_code_t::resource_limit,
                "readability.node_limit_exceeded", std::nullopt));
            return result;
        }
        build_index();
        build_evidence_maps();
        next_node_id_ = ast_.nodes.back().id + 1;
        collect_variable_info(ast_.root_node_id, 0, false, false);
        if (settings_.enable_loop_counter_naming && !work_budget_exceeded_)
            detect_loop_counters(ast_.root_node_id, 0);
        if (settings_.enable_api_call_naming && !work_budget_exceeded_)
            detect_api_calls(ast_.root_node_id);
        if (settings_.enable_string_reference_naming && !work_budget_exceeded_)
            detect_string_references(ast_.root_node_id);
        if (settings_.enable_type_based_naming && !work_budget_exceeded_)
            compute_type_based_names();
        compute_final_suggested_names();

        if (settings_.enable_variable_renaming && !variables_.empty() && !work_budget_exceeded_)
            apply_renaming();

        for (std::size_t iteration = 0; iteration < settings_.max_transform_iterations; ++iteration) {
            if (work_budget_exceeded_)
                break;
            bool changed = false;
            if (settings_.enable_expression_simplification)
                changed = simplify_expressions(ast_.root_node_id, 0, false) || changed;
            if (settings_.enable_temporary_coalescing) {
                definitions_.clear();
                uses_.clear();
                std::unordered_set<std::uint64_t> def_use_visited;
                collect_def_use(ast_.root_node_id, 0, def_use_visited);
                index_def_use();
                if (settings_.enable_single_use_inlining)
                    changed = apply_single_use_inlining() || changed;
                if (settings_.enable_copy_propagation)
                    changed = apply_copy_propagation() || changed;
                if (settings_.enable_dead_store_elimination)
                    changed = apply_dead_store_elimination() || changed;
            }
            if (!changed)
                break;
        }

        if (settings_.enable_member_name_propagation && !work_budget_exceeded_) {
            apply_member_name_propagation();
            build_index();
        }
        if (settings_.enable_cast_idiom_folding && !work_budget_exceeded_) {
            apply_cast_idiom_folding();
            build_index();
        }
        if ((settings_.enable_bit_operation_idioms || settings_.enable_magic_division_recognition) &&
            !work_budget_exceeded_) {
            apply_bit_operation_idioms();
            build_index();
        }
        if (settings_.enable_loop_intrinsic_idioms && !work_budget_exceeded_) {
            apply_loop_intrinsic_idioms();
            build_index();
        }
        if (settings_.enable_string_literal_substitution && !work_budget_exceeded_) {
            apply_string_literal_substitution();
            build_index();
        }
        if (settings_.enable_min_max_idioms && !work_budget_exceeded_) {
            apply_min_max_idioms();
            build_index();
        }
        if (settings_.enable_declaration_at_first_use && !work_budget_exceeded_) {
            apply_declaration_at_first_use();
            build_index();
        }
        if ((settings_.enable_string_comment_injection || settings_.enable_user_comment_injection ||
             settings_.enable_idiom_recognition) && !work_budget_exceeded_) {
            apply_comment_injection();
            build_index();
        }

        compact_ast();

        result.transformed = metrics_.variables_renamed > 0 ||
            metrics_.constants_folded > 0 || metrics_.identities_simplified > 0 ||
            metrics_.casts_simplified > 0 || metrics_.double_negations_simplified > 0 ||
            metrics_.comparisons_normalized > 0 || metrics_.compound_assignments_marked > 0 ||
            metrics_.temporaries_inlined > 0 || metrics_.copies_propagated > 0 ||
            metrics_.dead_stores_eliminated > 0 || metrics_.member_names_propagated > 0 ||
            metrics_.member_accesses_rewritten > 0 || metrics_.min_max_idioms_rewritten > 0 ||
            metrics_.idioms_recognized > 0 || metrics_.declarations_relocated > 0 ||
            metrics_.string_comments_injected > 0 || metrics_.user_comments_injected > 0 ||
            metrics_.nodes_removed > 0 || metrics_.string_literals_inlined > 0 ||
            metrics_.global_scalar_comments_injected > 0 || metrics_.cast_masks_folded > 0 ||
            metrics_.bit_operation_idioms_rewritten > 0 || metrics_.loop_intrinsics_rewritten > 0 ||
            metrics_.magic_divisions_recognized > 0;
        result.metrics = metrics_;
        result.diagnostics = std::move(diagnostics_);
        return result;
    }

private:
    typed_pseudocode_ast_v2_t& ast_;
    const type_graph_t& type_graph_;
    const readability_transform_settings_t settings_;
    const decompiler_render_evidence_t& evidence_;
    readability_transform_metrics_t metrics_;
    std::vector<decompiler_diagnostic_t> diagnostics_;
    std::unordered_map<std::uint64_t, std::size_t> id_index_;
    std::unordered_map<std::uint64_t, std::pair<std::uint64_t, std::size_t>> parent_map_;
    std::unordered_map<std::uint64_t, const decompiler_type_node_t*> types_;
    std::map<std::string, rt_variable_info_t> variables_;
    std::vector<rt_def_use_entry_t> definitions_;
    std::unordered_map<std::string, std::vector<std::uint64_t>> uses_;
    std::unordered_map<std::string, std::uint32_t> definition_counts_;
    std::unordered_map<std::string, std::vector<std::size_t>> definitions_by_variable_;
    std::map<std::uint64_t, std::vector<std::uint64_t>> pending_compound_removals_;
    std::unordered_map<std::string, std::string> symbol_names_;
    std::unordered_map<std::string, std::vector<std::string>> prototype_params_;
    std::unordered_map<std::string, const decompiler_string_evidence_t*> string_literals_;
    std::unordered_map<std::uint64_t, const decompiler_string_evidence_t*> string_addresses_;
    std::unordered_map<std::uint64_t, const decompiler_global_scalar_evidence_t*> global_scalars_;
    std::unordered_map<std::string, std::string> member_overlay_;
    std::unordered_map<std::uint64_t, std::vector<const decompiler_type_edge_t*>> member_edges_;
    std::unordered_map<std::string, std::vector<std::string>> user_comments_before_;
    std::unordered_map<std::string, std::vector<std::string>> user_comments_after_;
    std::vector<std::pair<std::uint64_t, std::string>> rva_comments_before_;
    std::vector<std::pair<std::uint64_t, std::string>> rva_comments_after_;
    std::uint64_t next_node_id_ = 1;
    std::size_t comments_injected_ = 0;
    std::uint32_t diagnostic_ordinal_ = 1;
    std::size_t work_units_ = 0;
    bool work_budget_exceeded_ = false;
    bool member_edges_built_ = false;

    bool consume_work(const std::size_t units = 1)
    {
        if (work_budget_exceeded_)
            return false;
        work_units_ += units;
        if (work_units_ > settings_.max_transform_work_units) {
            work_budget_exceeded_ = true;
            diagnostics_.push_back(rt_make_diagnostic(
                decompiler_diagnostic_code_t::resource_limit,
                "readability.work_budget_exceeded", std::nullopt));
            return false;
        }
        return true;
    }

    decompiler_diagnostic_t rt_make_diagnostic(
        decompiler_diagnostic_code_t code,
        std::string key,
        std::optional<source_coordinate_t> coordinate)
    {
        decompiler_diagnostic_t diag;
        diag.severity = decompiler_diagnostic_severity_t::warning;
        diag.code = code;
        diag.localization_key = std::move(key);
        diag.coordinate = std::move(coordinate);
        diag.confidence = 100;
        diag.ordinal = diagnostic_ordinal_++;
        return diag;
    }

    typed_pseudocode_ast_node_t* node(std::uint64_t id)
    {
        const auto it = id_index_.find(id);
        if (it == id_index_.end())
            return nullptr;
        return &ast_.nodes[it->second];
    }

    const typed_pseudocode_ast_node_t* node(std::uint64_t id) const
    {
        const auto it = id_index_.find(id);
        if (it == id_index_.end())
            return nullptr;
        return &ast_.nodes[it->second];
    }

    void build_index()
    {
        id_index_.clear();
        parent_map_.clear();
        for (std::size_t i = 0; i < ast_.nodes.size(); ++i) {
            id_index_.emplace(ast_.nodes[i].id, i);
            for (std::size_t j = 0; j < ast_.nodes[i].child_ids.size(); ++j)
                parent_map_.emplace(ast_.nodes[i].child_ids[j],
                    std::make_pair(ast_.nodes[i].id, j));
        }
    }

    static std::string strip_reference_marker(const std::string& value)
    {
        if (!value.empty() && value.front() == '&')
            return value.substr(1);
        return value;
    }

    void build_evidence_maps()
    {
        if (evidence_.empty())
            return;
        constexpr std::size_t k_max_evidence_map_entries = 262144;
        for (const auto& entry : evidence_.symbols) {
            if (symbol_names_.size() >= k_max_evidence_map_entries)
                break;
            if (!entry.unresolved_text.empty() && !entry.resolved_name.empty())
                symbol_names_.emplace(entry.unresolved_text, entry.resolved_name);
        }
        for (const auto& entry : evidence_.prototypes) {
            if (prototype_params_.size() >= k_max_evidence_map_entries)
                break;
            if (!entry.api_name.empty() && !entry.argument_names.empty())
                prototype_params_.emplace(entry.api_name, entry.argument_names);
        }
        for (const auto& entry : evidence_.strings) {
            if (string_literals_.size() >= k_max_evidence_map_entries)
                break;
            if (entry.reference_text.empty() || entry.utf8_content.empty())
                continue;
            string_literals_.emplace(entry.reference_text, &entry);
            const auto stripped = strip_reference_marker(entry.reference_text);
            if (stripped != entry.reference_text)
                string_literals_.emplace(stripped, &entry);
            if (entry.absolute_address != 0 && string_addresses_.size() < k_max_evidence_map_entries)
                string_addresses_.emplace(entry.absolute_address, &entry);
        }
        for (const auto& entry : evidence_.global_scalars) {
            if (global_scalars_.size() >= k_max_evidence_map_entries)
                break;
            if (entry.absolute_address != 0 && entry.size_log2 <= 3U)
                global_scalars_.emplace(entry.absolute_address, &entry);
        }
        for (const auto& entry : evidence_.members) {
            if (member_overlay_.size() >= k_max_evidence_map_entries)
                break;
            if (entry.field_name.empty())
                continue;
            member_overlay_.emplace(member_overlay_key(entry.object_type_canonical, entry.byte_offset), entry.field_name);
            if (!entry.selector_hint.empty())
                member_overlay_.emplace(
                    member_overlay_selector_key(entry.object_type_canonical, entry.selector_hint), entry.field_name);
        }
        for (const auto& entry : evidence_.user_comments) {
            if (entry.comment_text.empty())
                continue;
            if (entry.rva != 0) {
                auto& target = entry.before_statement ? rva_comments_before_ : rva_comments_after_;
                if (target.size() < k_max_evidence_map_entries)
                    target.emplace_back(entry.rva, entry.comment_text);
                continue;
            }
            if (entry.anchor_text.empty())
                continue;
            auto& target = entry.before_statement ? user_comments_before_ : user_comments_after_;
            auto& list = target[entry.anchor_text];
            if (list.size() < 8)
                list.push_back(entry.comment_text);
        }
        const auto order_rva_comments = [](std::vector<std::pair<std::uint64_t, std::string>>& values) {
            std::sort(values.begin(), values.end(),
                [](const auto& left, const auto& right) {
                    return std::tie(left.first, left.second) < std::tie(right.first, right.second);
                });
        };
        order_rva_comments(rva_comments_before_);
        order_rva_comments(rva_comments_after_);
    }

    static std::string member_overlay_key(const std::string& canonical, const std::uint64_t byte_offset)
    {
        return canonical + "#" + std::to_string(byte_offset);
    }

    static std::string member_overlay_selector_key(const std::string& canonical, const std::string& selector)
    {
        return canonical + "@" + selector;
    }

    std::string resolve_callee_name(const std::string& callee_text) const
    {
        const auto it = symbol_names_.find(callee_text);
        return it == symbol_names_.end() ? callee_text : it->second;
    }

    std::optional<std::string> suggest_call_param_name(const std::string& callee_text, const std::size_t index) const
    {
        const auto resolved = resolve_callee_name(callee_text);
        const auto evidence_it = prototype_params_.find(resolved);
        if (evidence_it != prototype_params_.end() && index < evidence_it->second.size() &&
            !evidence_it->second[index].empty())
            return evidence_it->second[index];
        return rt_suggest_api_name(resolved, index);
    }

    static std::optional<std::uint64_t> parse_address_candidate(const std::string& text)
    {
        if (text.empty())
            return std::nullopt;
        std::string candidate = strip_reference_marker(text);
        if (candidate.empty())
            return std::nullopt;
        std::size_t offset = 0;
        int base = 10;
        if (candidate.size() > 2 && candidate[0] == '0' &&
            (candidate[1] == 'x' || candidate[1] == 'X')) {
            base = 16;
            offset = 2;
        } else {
            for (const char* prefix : {"DAT_", "off_", "unk_", "DAT-", "off-", "unk-"}) {
                const auto length = std::strlen(prefix);
                if (candidate.size() > length && candidate.compare(0, length, prefix) == 0) {
                    base = 16;
                    offset = length;
                    break;
                }
            }
        }
        if (offset >= candidate.size() || candidate.size() - offset > 16)
            return std::nullopt;
        std::uint64_t value = 0;
        for (std::size_t index = offset; index < candidate.size(); ++index) {
            const char character = candidate[index];
            const auto digit = base == 16
                ? (character >= '0' && character <= '9' ? character - '0'
                    : character >= 'a' && character <= 'f' ? character - 'a' + 10
                    : character >= 'A' && character <= 'F' ? character - 'A' + 10 : -1)
                : (character >= '0' && character <= '9' ? character - '0' : -1);
            if (digit < 0)
                return std::nullopt;
            if (value > (std::numeric_limits<std::uint64_t>::max)() / 16ULL)
                return std::nullopt;
            value = value * static_cast<std::uint64_t>(base) + static_cast<std::uint64_t>(digit);
        }
        return value;
    }

    static bool generated_data_identifier(const std::string& text)
    {
        for (const char* prefix : {"DAT_", "off_", "unk_"}) {
            const auto length = std::strlen(prefix);
            if (text.size() > length && text.compare(0, length, prefix) == 0)
                return true;
        }
        return false;
    }

    const decompiler_string_evidence_t* lookup_string_address(std::uint64_t address) const
    {
        if (address == 0 || string_addresses_.empty())
            return nullptr;
        const auto it = string_addresses_.find(address);
        return it == string_addresses_.end() ? nullptr : it->second;
    }

    const decompiler_string_evidence_t* lookup_string_literal(const std::string& reference_text) const
    {
        const auto direct = string_literals_.find(reference_text);
        if (direct != string_literals_.end())
            return direct->second;
        const auto stripped = strip_reference_marker(reference_text);
        if (stripped != reference_text) {
            const auto alternate = string_literals_.find(stripped);
            if (alternate != string_literals_.end())
                return alternate->second;
        }
        if (!string_addresses_.empty()) {
            if (const auto address = parse_address_candidate(reference_text))
                return lookup_string_address(*address);
        }
        return nullptr;
    }

    std::uint64_t make_node(
        const typed_pseudocode_ast_node_kind_t kind,
        const std::uint64_t type_id,
        std::vector<std::uint64_t> children,
        std::string stable_text,
        const source_coordinate_t& coordinate,
        const std::uint8_t confidence,
        const decompiler_fact_provenance_t provenance)
    {
        typed_pseudocode_ast_node_t created;
        created.id = next_node_id_++;
        created.kind = kind;
        created.type_id = type_id;
        created.child_ids = std::move(children);
        created.stable_text = std::move(stable_text);
        created.coordinate = coordinate;
        created.confidence = confidence;
        created.provenance = provenance;
        ast_.nodes.push_back(std::move(created));
        id_index_.emplace(ast_.nodes.back().id, ast_.nodes.size() - 1);
        return ast_.nodes.back().id;
    }

    void collect_variable_info(std::uint64_t node_id, int loop_depth, bool in_loop, bool is_param_context)
    {
        std::unordered_set<std::uint64_t> visited;
        collect_variable_info_impl(node_id, loop_depth, in_loop, is_param_context, 0, visited);
    }

    void collect_variable_info_impl(std::uint64_t node_id, int loop_depth, bool in_loop,
                                     bool is_param_context, std::size_t depth,
                                     std::unordered_set<std::uint64_t>& visited)
    {
        if (depth >= settings_.max_expression_depth ||
            !visited.insert(node_id).second || !consume_work())
            return;
        const auto* n = node(node_id);
        if (n == nullptr)
            return;
        const auto kind = n->kind;
        if (kind == typed_pseudocode_ast_node_kind_t::declaration) {
            auto& info = variables_[n->stable_text];
            info.name = n->stable_text;
            info.type_id = n->type_id;
            info.declaration_ids.push_back(node_id);
            info.is_parameter = is_param_context;
            info.is_generated = rt_is_generated_name(n->stable_text);
            if (!n->child_ids.empty()) {
                for (const auto child_id : n->child_ids)
                    collect_variable_info_impl(child_id, loop_depth, in_loop, false, depth + 1, visited);
            }
            return;
        }
        if (kind == typed_pseudocode_ast_node_kind_t::identifier) {
            const auto parent_it = parent_map_.find(node_id);
            bool is_assignment_target = false;
            if (parent_it != parent_map_.end()) {
                const auto* parent = node(parent_it->second.first);
                if (parent != nullptr &&
                    parent->kind == typed_pseudocode_ast_node_kind_t::assignment_expression &&
                    parent_it->second.second == 0) {
                    is_assignment_target = true;
                }
            }
            auto& info = variables_[n->stable_text];
            info.name = n->stable_text;
            info.type_id = n->type_id;
            if (is_assignment_target)
                info.assignment_target_ids.push_back(node_id);
            else
                info.identifier_ids.push_back(node_id);
            info.is_generated = rt_is_generated_name(n->stable_text);
            return;
        }
        if (kind == typed_pseudocode_ast_node_kind_t::function_definition) {
            for (std::size_t i = 0; i + 1 < n->child_ids.size(); ++i)
                collect_variable_info_impl(n->child_ids[i], loop_depth, in_loop, true, depth + 1, visited);
            if (!n->child_ids.empty())
                collect_variable_info_impl(n->child_ids.back(), loop_depth, in_loop, false, depth + 1, visited);
            return;
        }
        bool child_in_loop = in_loop ||
            kind == typed_pseudocode_ast_node_kind_t::while_statement ||
            kind == typed_pseudocode_ast_node_kind_t::do_while_statement ||
            kind == typed_pseudocode_ast_node_kind_t::for_statement;
        int child_loop_depth = loop_depth;
        if (kind == typed_pseudocode_ast_node_kind_t::while_statement ||
            kind == typed_pseudocode_ast_node_kind_t::do_while_statement ||
            kind == typed_pseudocode_ast_node_kind_t::for_statement)
            ++child_loop_depth;
        for (const auto child_id : n->child_ids)
            collect_variable_info_impl(child_id, child_loop_depth, child_in_loop, false, depth + 1, visited);
    }

    void detect_loop_counters(std::uint64_t node_id, int depth)
    {
        std::unordered_set<std::uint64_t> visited;
        detect_loop_counters_impl(node_id, depth, visited, 0);
    }

    void detect_loop_counters_impl(std::uint64_t node_id, int depth,
                                    std::unordered_set<std::uint64_t>& visited,
                                    std::size_t traversal_depth)
    {
        if (traversal_depth >= settings_.max_expression_depth ||
            !visited.insert(node_id).second || !consume_work())
            return;
        const auto* n = node(node_id);
        if (n == nullptr)
            return;
        if (n->kind == typed_pseudocode_ast_node_kind_t::for_statement) {
            if (n->child_ids.size() == 4) {
                const auto* init = node(n->child_ids[0]);
                std::string counter_name;
                if (init != nullptr && init->kind == typed_pseudocode_ast_node_kind_t::declaration)
                    counter_name = init->stable_text;
                else if (init != nullptr && init->kind == typed_pseudocode_ast_node_kind_t::expression_statement && !init->child_ids.empty()) {
                    const auto* expr = node(init->child_ids[0]);
                    if (expr != nullptr && expr->kind == typed_pseudocode_ast_node_kind_t::assignment_expression && !expr->child_ids.empty()) {
                        const auto* left = node(expr->child_ids[0]);
                        if (left != nullptr && left->kind == typed_pseudocode_ast_node_kind_t::identifier)
                            counter_name = left->stable_text;
                    }
                }
                if (!counter_name.empty()) {
                    const auto cond_id = n->child_ids[1];
                    const auto iter_id = n->child_ids[2];
                    bool in_condition = subtree_contains_identifier(cond_id, counter_name);
                    bool modified_in_iter = subtree_modifies_identifier(iter_id, counter_name);
                    if (in_condition && modified_in_iter) {
                        auto it = variables_.find(counter_name);
                        if (it != variables_.end() && it->second.is_generated) {
                            it->second.is_loop_counter = true;
                            it->second.loop_depth = depth;
                            ++metrics_.loop_counters_named;
                        }
                    }
                }
            }
            for (const auto child_id : n->child_ids)
                detect_loop_counters_impl(child_id, depth + 1, visited, traversal_depth + 1);
            return;
        }
        if (n->kind == typed_pseudocode_ast_node_kind_t::while_statement ||
            n->kind == typed_pseudocode_ast_node_kind_t::do_while_statement) {
            const auto cond_index = n->kind == typed_pseudocode_ast_node_kind_t::while_statement ? 0 : 1;
            if (cond_index < n->child_ids.size()) {
                std::vector<std::string> cond_vars;
                collect_identifier_names(n->child_ids[cond_index], cond_vars);
                for (const auto& var_name : cond_vars) {
                    auto it = variables_.find(var_name);
                    if (it != variables_.end() && it->second.is_generated) {
                        const auto body_index = n->kind == typed_pseudocode_ast_node_kind_t::while_statement ? 1 : 0;
                        if (body_index < n->child_ids.size() &&
                            subtree_modifies_identifier(n->child_ids[body_index], var_name)) {
                            it->second.is_loop_counter = true;
                            it->second.loop_depth = depth;
                            ++metrics_.loop_counters_named;
                        }
                    }
                }
            }
            for (const auto child_id : n->child_ids)
                detect_loop_counters_impl(child_id, depth + 1, visited, traversal_depth + 1);
            return;
        }
        for (const auto child_id : n->child_ids)
            detect_loop_counters_impl(child_id, depth, visited, traversal_depth + 1);
    }

    void collect_identifier_names(std::uint64_t node_id, std::vector<std::string>& names)
    {
        std::unordered_set<std::uint64_t> visited;
        collect_identifier_names_impl(node_id, names, visited, 0);
    }

    void collect_identifier_names_impl(std::uint64_t node_id, std::vector<std::string>& names,
                                        std::unordered_set<std::uint64_t>& visited,
                                        std::size_t depth)
    {
        if (depth >= settings_.max_expression_depth ||
            !visited.insert(node_id).second || !consume_work())
            return;
        const auto* n = node(node_id);
        if (n == nullptr)
            return;
        if (n->kind == typed_pseudocode_ast_node_kind_t::identifier)
            names.push_back(n->stable_text);
        for (const auto child_id : n->child_ids)
            collect_identifier_names_impl(child_id, names, visited, depth + 1);
    }

    bool subtree_contains_identifier(std::uint64_t node_id, const std::string& name)
    {
        std::unordered_set<std::uint64_t> visited;
        return subtree_contains_identifier_impl(node_id, name, visited, 0);
    }

    bool subtree_contains_identifier_impl(std::uint64_t node_id, const std::string& name,
                                           std::unordered_set<std::uint64_t>& visited,
                                           std::size_t depth)
    {
        if (depth >= settings_.max_expression_depth ||
            !visited.insert(node_id).second || !consume_work())
            return false;
        const auto* n = node(node_id);
        if (n == nullptr)
            return false;
        if (n->kind == typed_pseudocode_ast_node_kind_t::identifier && n->stable_text == name)
            return true;
        for (const auto child_id : n->child_ids) {
            if (subtree_contains_identifier_impl(child_id, name, visited, depth + 1))
                return true;
        }
        return false;
    }

    bool subtree_modifies_identifier(std::uint64_t node_id, const std::string& name)
    {
        std::unordered_set<std::uint64_t> visited;
        return subtree_modifies_identifier_impl(node_id, name, visited, 0);
    }

    bool subtree_modifies_identifier_impl(std::uint64_t node_id, const std::string& name,
                                           std::unordered_set<std::uint64_t>& visited,
                                           std::size_t depth)
    {
        if (depth >= settings_.max_expression_depth ||
            !visited.insert(node_id).second || !consume_work())
            return false;
        const auto* n = node(node_id);
        if (n == nullptr)
            return false;
        if (n->kind == typed_pseudocode_ast_node_kind_t::assignment_expression && !n->child_ids.empty()) {
            const auto* left = node(n->child_ids[0]);
            if (left != nullptr && left->kind == typed_pseudocode_ast_node_kind_t::identifier &&
                left->stable_text == name)
                return true;
        }
        if (n->kind == typed_pseudocode_ast_node_kind_t::unary_expression &&
            (n->stable_text == "++" || n->stable_text == "--") && !n->child_ids.empty()) {
            const auto* operand = node(n->child_ids[0]);
            if (operand != nullptr && operand->kind == typed_pseudocode_ast_node_kind_t::identifier &&
                operand->stable_text == name)
                return true;
        }
        for (const auto child_id : n->child_ids) {
            if (subtree_modifies_identifier_impl(child_id, name, visited, depth + 1))
                return true;
        }
        return false;
    }

    void detect_api_calls(std::uint64_t node_id)
    {
        std::unordered_set<std::uint64_t> visited;
        detect_api_calls_impl(node_id, visited, 0);
    }

    void detect_api_calls_impl(std::uint64_t node_id,
                                std::unordered_set<std::uint64_t>& visited,
                                std::size_t depth)
    {
        if (depth >= settings_.max_expression_depth ||
            !visited.insert(node_id).second || !consume_work())
            return;
        const auto* n = node(node_id);
        if (n == nullptr)
            return;
        if (n->kind == typed_pseudocode_ast_node_kind_t::call_expression && n->child_ids.size() >= 2) {
            const auto* callee = node(n->child_ids[0]);
            if (callee != nullptr && callee->kind == typed_pseudocode_ast_node_kind_t::identifier) {
                for (std::size_t i = 1; i < n->child_ids.size(); ++i) {
                    const auto* arg = node(n->child_ids[i]);
                    if (arg != nullptr && arg->kind == typed_pseudocode_ast_node_kind_t::identifier) {
                        const auto suggested = suggest_call_param_name(callee->stable_text, i - 1);
                        if (suggested) {
                            auto it = variables_.find(arg->stable_text);
                            if (it != variables_.end() && it->second.is_generated) {
                                if (!it->second.api_suggested_name)
                                    it->second.api_suggested_name = *suggested;
                            }
                        }
                    }
                }
            }
        }
        for (const auto child_id : n->child_ids)
            detect_api_calls_impl(child_id, visited, depth + 1);
    }

    void detect_string_references(std::uint64_t node_id)
    {
        std::unordered_set<std::uint64_t> visited;
        detect_string_references_impl(node_id, visited, 0);
    }

    void detect_string_references_impl(std::uint64_t node_id,
                                        std::unordered_set<std::uint64_t>& visited,
                                        std::size_t depth)
    {
        if (depth >= settings_.max_expression_depth ||
            !visited.insert(node_id).second || !consume_work())
            return;
        const auto* n = node(node_id);
        if (n == nullptr)
            return;
        if (n->kind == typed_pseudocode_ast_node_kind_t::declaration &&
            n->child_ids.size() == 1 && rt_is_generated_name(n->stable_text)) {
            const auto* init = node(n->child_ids[0]);
            if (init != nullptr && init->kind == typed_pseudocode_ast_node_kind_t::literal) {
                const auto& text = init->stable_text;
                if (text.size() >= 2 && text.front() == '"') {
                    std::string content = text.substr(1);
                    if (!content.empty() && content.back() == '"')
                        content.pop_back();
                    suggest_string_variable_name(n->stable_text, content);
                }
            } else if (init != nullptr && init->kind == typed_pseudocode_ast_node_kind_t::identifier) {
                if (const auto* entry = lookup_string_literal(init->stable_text))
                    suggest_string_variable_name(n->stable_text, entry->utf8_content);
            }
        }
        for (const auto child_id : n->child_ids)
            detect_string_references_impl(child_id, visited, depth + 1);
    }

    void suggest_string_variable_name(const std::string& variable, const std::string& content)
    {
        std::string first_word;
        for (const char c : content) {
            if (std::isalnum(static_cast<unsigned char>(c)) != 0 || c == '_')
                first_word.push_back(c);
            else if (!first_word.empty())
                break;
        }
        if (first_word.empty())
            return;
        const auto camel = rt_to_camel_case(first_word);
        if (camel.empty())
            return;
        auto it = variables_.find(variable);
        if (it != variables_.end())
            it->second.string_suggested_name = camel;
    }

    void compute_type_based_names()
    {
        for (auto& [name, info] : variables_) {
            if (!info.is_generated || info.type_id == 0)
                continue;
            const auto type_it = types_.find(info.type_id);
            if (type_it == types_.end())
                continue;
            const auto suggested = rt_suggest_type_name(type_it->second->display_name);
            if (suggested)
                info.type_suggested_name = *suggested;
        }
        suggest_this_pointer_name();
    }

    void suggest_this_pointer_name()
    {
        const auto* function = node(ast_.root_node_id);
        if (function == nullptr ||
            function->kind != typed_pseudocode_ast_node_kind_t::function_definition ||
            function->child_ids.size() < 2)
            return;
        for (std::size_t index = 0; index + 1 < function->child_ids.size(); ++index) {
            const auto* parameter = node(function->child_ids[index]);
            if (parameter == nullptr ||
                parameter->kind != typed_pseudocode_ast_node_kind_t::declaration)
                continue;
            const auto it = variables_.find(parameter->stable_text);
            if (it == variables_.end() || !it->second.is_parameter || !it->second.is_generated ||
                it->second.type_id == 0)
                continue;
            const auto type_it = types_.find(it->second.type_id);
            if (type_it == types_.end() ||
                type_it->second->kind != decompiler_type_kind_t::pointer)
                continue;
            const auto* pointee = type_graph::find_pointee_edge(type_graph_, it->second.type_id);
            if (pointee == nullptr)
                continue;
            const auto pointee_it = types_.find(pointee->target_type_id);
            if (pointee_it == types_.end() ||
                (pointee_it->second->kind != decompiler_type_kind_t::structure &&
                 pointee_it->second->kind != decompiler_type_kind_t::class_type &&
                 pointee_it->second->kind != decompiler_type_kind_t::union_type))
                continue;
            it->second.type_suggested_name = "this";
            return;
        }
    }

    void compute_final_suggested_names()
    {
        std::set<std::string> used_names;
        for (const auto& [name, info] : variables_) {
            if (!info.is_generated)
                used_names.insert(name);
        }
        std::map<std::string, std::string> rename_map;
        for (auto& [name, info] : variables_) {
            if (!info.is_generated)
                continue;
            std::string suggested;
            if (info.is_loop_counter && settings_.enable_loop_counter_naming) {
                const char* counters[] = {"i", "j", "k", "m", "n"};
                const int idx = info.loop_depth < 5 ? info.loop_depth : 4;
                suggested = counters[idx];
            }
            if (suggested.empty() && info.api_suggested_name && settings_.enable_api_call_naming)
                suggested = *info.api_suggested_name;
            if (suggested.empty() && info.string_suggested_name && settings_.enable_string_reference_naming)
                suggested = *info.string_suggested_name;
            if (suggested.empty() && info.type_suggested_name && settings_.enable_type_based_naming)
                suggested = *info.type_suggested_name;
            if (suggested.empty())
                continue;
            std::string final_name = suggested;
            int suffix = 2;
            while (used_names.find(final_name) != used_names.end() ||
                   rename_map.find(final_name) != rename_map.end()) {
                final_name = suggested + std::to_string(suffix);
                ++suffix;
            }
            info.final_suggested_name = final_name;
            rename_map[final_name] = name;
            used_names.insert(final_name);
        }
    }

    void apply_renaming()
    {
        std::map<std::string, std::string> rename_map;
        for (const auto& [name, info] : variables_) {
            if (!info.is_generated || info.final_suggested_name.empty())
                continue;
            rename_map[name] = info.final_suggested_name;
        }
        if (rename_map.empty())
            return;
        for (auto& n : ast_.nodes) {
            if ((n.kind == typed_pseudocode_ast_node_kind_t::declaration ||
                 n.kind == typed_pseudocode_ast_node_kind_t::identifier) &&
                !n.stable_text.empty()) {
                const auto it = rename_map.find(n.stable_text);
                if (it != rename_map.end()) {
                    n.stable_text = it->second;
                    ++metrics_.variables_renamed;
                }
            }
        }
        for (const auto& [old_name, new_name] : rename_map) {
            const auto& info = variables_.at(old_name);
            if (!info.is_loop_counter && info.api_suggested_name && settings_.enable_api_call_naming)
                ++metrics_.api_call_names_applied;
            else if (!info.is_loop_counter && !info.api_suggested_name &&
                     info.string_suggested_name && settings_.enable_string_reference_naming)
                ++metrics_.string_reference_names_applied;
            else if (!info.is_loop_counter && !info.api_suggested_name &&
                     !info.string_suggested_name && info.type_suggested_name &&
                     settings_.enable_type_based_naming)
                ++metrics_.type_based_names_applied;
        }
    }

    bool simplify_expressions(std::uint64_t node_id, std::size_t depth, bool boolean_context)
    {
        std::unordered_set<std::uint64_t> visited;
        return simplify_expressions_impl(node_id, depth, boolean_context, visited);
    }

    bool simplify_expressions_impl(std::uint64_t node_id, std::size_t depth, bool boolean_context,
                                    std::unordered_set<std::uint64_t>& visited)
    {
        if (depth >= settings_.max_expression_depth ||
            !visited.insert(node_id).second || !consume_work())
            return false;
        auto* n = node(node_id);
        if (n == nullptr)
            return false;
        bool changed = false;
        bool child_boolean_context = false;
        if (n->kind == typed_pseudocode_ast_node_kind_t::if_statement ||
            n->kind == typed_pseudocode_ast_node_kind_t::while_statement) {
            for (std::size_t i = 0; i < n->child_ids.size(); ++i) {
                if (i == 0)
                    changed = simplify_expressions_impl(n->child_ids[i], depth + 1, true, visited) || changed;
                else
                    changed = simplify_expressions_impl(n->child_ids[i], depth + 1, false, visited) || changed;
            }
            return changed;
        }
        if (n->kind == typed_pseudocode_ast_node_kind_t::do_while_statement) {
            for (std::size_t i = 0; i < n->child_ids.size(); ++i) {
                if (i == 1)
                    changed = simplify_expressions_impl(n->child_ids[i], depth + 1, true, visited) || changed;
                else
                    changed = simplify_expressions_impl(n->child_ids[i], depth + 1, false, visited) || changed;
            }
            return changed;
        }
        if (n->kind == typed_pseudocode_ast_node_kind_t::for_statement) {
            for (std::size_t i = 0; i < n->child_ids.size(); ++i) {
                if (i == 1)
                    changed = simplify_expressions_impl(n->child_ids[i], depth + 1, true, visited) || changed;
                else
                    changed = simplify_expressions_impl(n->child_ids[i], depth + 1, false, visited) || changed;
            }
            return changed;
        }
        if (n->kind == typed_pseudocode_ast_node_kind_t::binary_expression &&
            (n->stable_text == "&&" || n->stable_text == "||"))
            child_boolean_context = true;
        for (const auto child_id : n->child_ids)
            changed = simplify_expressions_impl(child_id, depth + 1, child_boolean_context, visited) || changed;
        if (n->kind == typed_pseudocode_ast_node_kind_t::binary_expression) {
            if (settings_.enable_constant_folding)
                changed = try_fold_constant_binary(*n) || changed;
            if (settings_.enable_identity_simplification)
                changed = try_simplify_identity(*n) || changed;
            if (settings_.enable_comparison_normalization && boolean_context)
                changed = try_normalize_comparison(*n) || changed;
        }
        if (n->kind == typed_pseudocode_ast_node_kind_t::unary_expression) {
            if (settings_.enable_double_negation_simplification)
                changed = try_simplify_double_negation(*n) || changed;
        }
        if (n->kind == typed_pseudocode_ast_node_kind_t::cast_expression) {
            if (settings_.enable_cast_simplification)
                changed = try_simplify_redundant_cast(*n) || changed;
        }
        if (n->kind == typed_pseudocode_ast_node_kind_t::assignment_expression) {
            if (settings_.enable_compound_assignment_marking)
                changed = try_mark_compound_assignment(*n) || changed;
        }
        return changed;
    }

    bool try_fold_constant_binary(typed_pseudocode_ast_node_t& n)
    {
        if (n.child_ids.size() != 2)
            return false;
        const auto* left = node(n.child_ids[0]);
        const auto* right = node(n.child_ids[1]);
        if (left == nullptr || right == nullptr)
            return false;
        if (left->kind != typed_pseudocode_ast_node_kind_t::literal ||
            right->kind != typed_pseudocode_ast_node_kind_t::literal)
            return false;
        const auto lhs = rt_parse_signed(left->stable_text);
        const auto rhs = rt_parse_signed(right->stable_text);
        if (!lhs || !rhs)
            return false;
        const std::string op = n.stable_text;
        std::optional<std::int64_t> result;
        if (op == "+") {
            if ((*lhs > 0 && *rhs > 0 && *lhs > std::numeric_limits<std::int64_t>::max() - *rhs) ||
                (*lhs < 0 && *rhs < 0 && *lhs < std::numeric_limits<std::int64_t>::min() - *rhs))
                return false;
            result = *lhs + *rhs;
        } else if (op == "-") {
            if ((*lhs > 0 && *rhs < 0 && *lhs > std::numeric_limits<std::int64_t>::max() + *rhs) ||
                (*lhs < 0 && *rhs > 0 && *lhs < std::numeric_limits<std::int64_t>::min() + *rhs))
                return false;
            result = *lhs - *rhs;
        } else if (op == "*") {
            result = *lhs * *rhs;
        } else if (op == "<<") {
            if (*rhs < 0 || *rhs >= 64)
                return false;
            result = *lhs << *rhs;
        } else if (op == ">>") {
            if (*rhs < 0 || *rhs >= 64)
                return false;
            result = *lhs >> *rhs;
        } else if (op == "&") {
            result = *lhs & *rhs;
        } else if (op == "|") {
            result = *lhs | *rhs;
        } else if (op == "^") {
            result = *lhs ^ *rhs;
        } else if (op == "/") {
            if (*rhs == 0)
                return false;
            result = *lhs / *rhs;
        } else if (op == "%") {
            if (*rhs == 0)
                return false;
            result = *lhs % *rhs;
        } else {
            return false;
        }
        n.kind = typed_pseudocode_ast_node_kind_t::literal;
        n.stable_text = rt_format_signed(*result);
        n.child_ids.clear();
        ++metrics_.constants_folded;
        return true;
    }

    bool try_simplify_identity(typed_pseudocode_ast_node_t& n)
    {
        if (n.child_ids.size() != 2)
            return false;
        const auto* left = node(n.child_ids[0]);
        const auto* right = node(n.child_ids[1]);
        if (left == nullptr || right == nullptr)
            return false;
        const std::string op = n.stable_text;
        const bool left_is_literal = left->kind == typed_pseudocode_ast_node_kind_t::literal;
        const bool right_is_literal = right->kind == typed_pseudocode_ast_node_kind_t::literal;
        auto right_val = right_is_literal ? rt_parse_signed(right->stable_text) : std::optional<std::int64_t>{};
        auto left_val = left_is_literal ? rt_parse_signed(left->stable_text) : std::optional<std::int64_t>{};
        if (op == "+" && right_is_literal && right_val && *right_val == 0) {
            copy_node_content(n, *left);
            ++metrics_.identities_simplified;
            return true;
        }
        if (op == "+" && left_is_literal && left_val && *left_val == 0) {
            copy_node_content(n, *right);
            ++metrics_.identities_simplified;
            return true;
        }
        if (op == "-" && right_is_literal && right_val && *right_val == 0) {
            copy_node_content(n, *left);
            ++metrics_.identities_simplified;
            return true;
        }
        if (op == "*" && right_is_literal && right_val && *right_val == 1) {
            copy_node_content(n, *left);
            ++metrics_.identities_simplified;
            return true;
        }
        if (op == "*" && left_is_literal && left_val && *left_val == 1) {
            copy_node_content(n, *right);
            ++metrics_.identities_simplified;
            return true;
        }
        if (op == "*" && right_is_literal && right_val && *right_val == 0) {
            n.kind = typed_pseudocode_ast_node_kind_t::literal;
            n.stable_text = "0";
            n.child_ids.clear();
            ++metrics_.identities_simplified;
            return true;
        }
        if (op == "*" && left_is_literal && left_val && *left_val == 0) {
            n.kind = typed_pseudocode_ast_node_kind_t::literal;
            n.stable_text = "0";
            n.child_ids.clear();
            ++metrics_.identities_simplified;
            return true;
        }
        if (op == "|" && right_is_literal && right_val && *right_val == 0) {
            copy_node_content(n, *left);
            ++metrics_.identities_simplified;
            return true;
        }
        if (op == "|" && left_is_literal && left_val && *left_val == 0) {
            copy_node_content(n, *right);
            ++metrics_.identities_simplified;
            return true;
        }
        if (op == "&" && right_is_literal && right_val && *right_val == 0) {
            n.kind = typed_pseudocode_ast_node_kind_t::literal;
            n.stable_text = "0";
            n.child_ids.clear();
            ++metrics_.identities_simplified;
            return true;
        }
        if (op == "&" && left_is_literal && left_val && *left_val == 0) {
            n.kind = typed_pseudocode_ast_node_kind_t::literal;
            n.stable_text = "0";
            n.child_ids.clear();
            ++metrics_.identities_simplified;
            return true;
        }
        if (op == "&&" && left_is_literal && left_val && *left_val == 0) {
            n.kind = typed_pseudocode_ast_node_kind_t::literal;
            n.stable_text = "0";
            n.child_ids.clear();
            ++metrics_.identities_simplified;
            return true;
        }
        if (op == "||" && left_is_literal && left_val && *left_val != 0) {
            n.kind = typed_pseudocode_ast_node_kind_t::literal;
            n.stable_text = "1";
            n.child_ids.clear();
            ++metrics_.identities_simplified;
            return true;
        }
        if (op == "/" && right_is_literal && right_val && *right_val == 1) {
            copy_node_content(n, *left);
            ++metrics_.identities_simplified;
            return true;
        }
        return false;
    }

    void copy_node_content(typed_pseudocode_ast_node_t& dst, const typed_pseudocode_ast_node_t& src)
    {
        dst.kind = src.kind;
        dst.type_id = src.type_id;
        dst.child_ids = src.child_ids;
        dst.stable_text = src.stable_text;
    }

    bool try_simplify_double_negation(typed_pseudocode_ast_node_t& n)
    {
        if (n.stable_text != "!" || n.child_ids.size() != 1)
            return false;
        const auto* child = node(n.child_ids[0]);
        if (child == nullptr || child->kind != typed_pseudocode_ast_node_kind_t::unary_expression ||
            child->stable_text != "!" || child->child_ids.size() != 1)
            return false;
        const auto* grandchild = node(child->child_ids[0]);
        if (grandchild == nullptr)
            return false;
        copy_node_content(n, *grandchild);
        ++metrics_.double_negations_simplified;
        return true;
    }

    bool canonical_types_equal(const std::uint64_t left_id, const std::uint64_t right_id) const
    {
        if (left_id == right_id && left_id != 0)
            return true;
        const auto left_it = types_.find(left_id);
        const auto right_it = types_.find(right_id);
        if (left_it == types_.end() || right_it == types_.end())
            return false;
        const auto* left = left_it->second;
        const auto* right = right_it->second;
        if (left->kind != right->kind || left->canonical_name.empty() || right->canonical_name.empty())
            return false;
        return left->canonical_name == right->canonical_name;
    }

    bool try_simplify_redundant_cast(typed_pseudocode_ast_node_t& n)
    {
        if (n.child_ids.size() != 1)
            return false;
        const auto* child = node(n.child_ids[0]);
        if (child == nullptr)
            return false;
        if (child->kind == typed_pseudocode_ast_node_kind_t::cast_expression &&
            child->stable_text == n.stable_text) {
            copy_node_content(n, *child);
            ++metrics_.casts_simplified;
            return true;
        }
        if (child->kind == typed_pseudocode_ast_node_kind_t::cast_expression &&
            child->child_ids.size() == 1) {
            const auto* grandchild = node(child->child_ids[0]);
            if (grandchild != nullptr) {
                const auto child_type_it = types_.find(child->type_id);
                const auto grandchild_type_it = types_.find(grandchild->type_id);
                if (child_type_it != types_.end() && grandchild_type_it != types_.end()) {
                    const auto& ct = child_type_it->second;
                    const auto& gt = grandchild_type_it->second;
                    if (ct->kind == decompiler_type_kind_t::pointer &&
                        gt->kind == decompiler_type_kind_t::pointer &&
                        n.stable_text == child->stable_text) {
                        copy_node_content(n, *grandchild);
                        ++metrics_.casts_simplified;
                        return true;
                    }
                }
            }
        }
        if (canonical_types_equal(child->type_id, n.type_id) &&
            child->kind != typed_pseudocode_ast_node_kind_t::cast_expression) {
            copy_node_content(n, *child);
            ++metrics_.casts_simplified;
            return true;
        }
        return false;
    }

    bool unsigned_mask_for_width(const decompiler_type_node_t* type, std::uint64_t& mask) const
    {
        if (type == nullptr || type->kind != decompiler_type_kind_t::unsigned_integer ||
            !type->byte_size.has_value())
            return false;
        const auto size = *type->byte_size;
        if (size != 1 && size != 2 && size != 4)
            return false;
        mask = size == 1 ? 0xFFULL : size == 2 ? 0xFFFFULL : 0xFFFFFFFFULL;
        return true;
    }

    bool literal_unsigned_value(const typed_pseudocode_ast_node_t* value, std::uint64_t& result) const
    {
        if (value == nullptr || value->kind != typed_pseudocode_ast_node_kind_t::literal)
            return false;
        const auto parsed = rt_parse_signed(value->stable_text);
        if (!parsed || *parsed < 0)
            return false;
        result = static_cast<std::uint64_t>(*parsed);
        return true;
    }

    bool try_fold_cast_mask(typed_pseudocode_ast_node_t& n)
    {
        const auto* operand = node(n.child_ids[0]);
        if (operand == nullptr ||
            operand->kind != typed_pseudocode_ast_node_kind_t::binary_expression ||
            operand->stable_text != "&" || operand->child_ids.size() != 2)
            return false;
        std::uint64_t mask = 0;
        const auto type_it = types_.find(n.type_id);
        if (type_it == types_.end() || !unsigned_mask_for_width(type_it->second, mask))
            return false;
        std::uint64_t applied = 0;
        const auto* left = node(operand->child_ids[0]);
        const auto* right = node(operand->child_ids[1]);
        const bool right_mask = literal_unsigned_value(right, applied) && applied == mask;
        if (!right_mask && !(literal_unsigned_value(left, applied) && applied == mask))
            return false;
        const auto operand_children = operand->child_ids;
        n.kind = typed_pseudocode_ast_node_kind_t::binary_expression;
        n.stable_text = "&";
        n.child_ids = operand_children;
        ++metrics_.cast_masks_folded;
        return true;
    }

    bool try_normalize_comparison_casts(typed_pseudocode_ast_node_t& n)
    {
        if (n.child_ids.size() != 2)
            return false;
        if (n.stable_text != "==" && n.stable_text != "!=")
            return false;
        const auto* left = node(n.child_ids[0]);
        const auto* right = node(n.child_ids[1]);
        if (left == nullptr || right == nullptr)
            return false;
        bool changed = false;
        for (std::size_t side = 0; side < 2; ++side) {
            const auto* cast = node(n.child_ids[side]);
            if (cast == nullptr ||
                cast->kind != typed_pseudocode_ast_node_kind_t::cast_expression ||
                cast->child_ids.size() != 1)
                continue;
            const auto* operand = node(cast->child_ids[0]);
            if (operand == nullptr)
                continue;
            if (!canonical_types_equal(operand->type_id, cast->type_id))
                continue;
            auto* mutable_cast = node(n.child_ids[side]);
            copy_node_content(*mutable_cast, *operand);
            ++metrics_.casts_simplified;
            changed = true;
        }
        if (changed)
            return true;
        for (std::size_t side = 0; side < 2; ++side) {
            const auto* cast = node(n.child_ids[side]);
            if (cast == nullptr ||
                cast->kind != typed_pseudocode_ast_node_kind_t::cast_expression ||
                cast->child_ids.size() != 1)
                continue;
            const auto* operand = node(cast->child_ids[0]);
            if (operand == nullptr || operand->kind != typed_pseudocode_ast_node_kind_t::literal)
                continue;
            const auto* other = node(n.child_ids[side ^ 1]);
            if (other == nullptr)
                continue;
            const auto type_it = types_.find(cast->type_id);
            const auto other_it = types_.find(other->type_id);
            if (type_it == types_.end() || other_it == types_.end() ||
                !canonical_types_equal(cast->type_id, other->type_id))
                continue;
            const auto* cast_type = type_it->second;
            if (cast_type->kind != decompiler_type_kind_t::unsigned_integer &&
                cast_type->kind != decompiler_type_kind_t::signed_integer)
                continue;
            if (!cast_type->byte_size.has_value() || *cast_type->byte_size == 0 ||
                *cast_type->byte_size > 8)
                continue;
            const auto parsed = rt_parse_signed(operand->stable_text);
            if (!parsed)
                continue;
            const auto bits = *cast_type->byte_size * 8;
            if (bits < 64) {
                if (cast_type->kind == decompiler_type_kind_t::unsigned_integer) {
                    if (*parsed < 0 || static_cast<std::uint64_t>(*parsed) >= (1ULL << bits))
                        continue;
                } else {
                    const auto low = -(static_cast<std::int64_t>(1) << (bits - 1));
                    const auto high = (static_cast<std::int64_t>(1) << (bits - 1)) - 1;
                    if (*parsed < low || *parsed > high)
                        continue;
                }
            }
            auto* mutable_cast = node(n.child_ids[side]);
            copy_node_content(*mutable_cast, *operand);
            ++metrics_.casts_simplified;
            changed = true;
        }
        return changed;
    }

    bool try_cleanup_reinterpret_deref(typed_pseudocode_ast_node_t& n)
    {
        if (n.child_ids.size() != 1)
            return false;
        const auto* cast = node(n.child_ids[0]);
        if (cast == nullptr ||
            cast->kind != typed_pseudocode_ast_node_kind_t::cast_expression ||
            cast->child_ids.size() != 1)
            return false;
        const auto* address_of = node(cast->child_ids[0]);
        if (address_of == nullptr ||
            address_of->kind != typed_pseudocode_ast_node_kind_t::unary_expression ||
            address_of->stable_text != "&" || address_of->child_ids.size() != 1)
            return false;
        const auto* operand = node(address_of->child_ids[0]);
        if (operand == nullptr || operand->kind != typed_pseudocode_ast_node_kind_t::identifier)
            return false;
        if (variables_.find(operand->stable_text) == variables_.end())
            return false;
        const auto operand_it = types_.find(operand->type_id);
        const auto cast_it = types_.find(cast->type_id);
        if (operand_it == types_.end() || cast_it == types_.end())
            return false;
        const auto* operand_type = operand_it->second;
        const auto* cast_type = cast_it->second;
        const auto integer_kind = [](const decompiler_type_kind_t kind) {
            return kind == decompiler_type_kind_t::signed_integer ||
                   kind == decompiler_type_kind_t::unsigned_integer;
        };
        if (!integer_kind(operand_type->kind) || !integer_kind(cast_type->kind) ||
            !operand_type->byte_size.has_value() || !cast_type->byte_size.has_value() ||
            *operand_type->byte_size != *cast_type->byte_size)
            return false;
        copy_node_content(n, *operand);
        ++metrics_.casts_simplified;
        return true;
    }

    void apply_cast_idiom_folding()
    {
        for (auto& n : ast_.nodes) {
            if (!consume_work())
                return;
            if (n.kind == typed_pseudocode_ast_node_kind_t::cast_expression &&
                n.child_ids.size() == 1)
                try_fold_cast_mask(n);
            else if (n.kind == typed_pseudocode_ast_node_kind_t::binary_expression)
                try_normalize_comparison_casts(n);
            else if (n.kind == typed_pseudocode_ast_node_kind_t::unary_expression &&
                     n.stable_text == "*" && n.child_ids.size() == 1)
                try_cleanup_reinterpret_deref(n);
        }
    }

    bool try_mark_compound_assignment(typed_pseudocode_ast_node_t& n)
    {
        if (n.stable_text != "=" || n.child_ids.size() != 2)
            return false;
        const auto* left = node(n.child_ids[0]);
        const auto* right = node(n.child_ids[1]);
        if (left == nullptr || right == nullptr)
            return false;
        if (left->kind != typed_pseudocode_ast_node_kind_t::identifier)
            return false;
        if (right->kind != typed_pseudocode_ast_node_kind_t::binary_expression ||
            right->child_ids.size() != 2)
            return false;
        const auto* rhs_left = node(right->child_ids[0]);
        if (rhs_left == nullptr || rhs_left->kind != typed_pseudocode_ast_node_kind_t::identifier)
            return false;
        if (rhs_left->stable_text != left->stable_text)
            return false;
        const auto op = right->stable_text;
        if (op == "+" || op == "-" || op == "*" || op == "/" || op == "%" ||
            op == "<<" || op == ">>" || op == "&" || op == "|" || op == "^") {
            n.stable_text = op + "=";
            ++metrics_.compound_assignments_marked;
            return true;
        }
        return false;
    }

    bool try_normalize_comparison(typed_pseudocode_ast_node_t& n)
    {
        if (n.child_ids.size() != 2)
            return false;
        const auto* left = node(n.child_ids[0]);
        const auto* right = node(n.child_ids[1]);
        if (left == nullptr || right == nullptr)
            return false;
        if (right->kind != typed_pseudocode_ast_node_kind_t::literal)
            return false;
        const auto val = rt_parse_signed(right->stable_text);
        if (!val)
            return false;
        if (n.stable_text == "==" && *val == 0) {
            n.kind = typed_pseudocode_ast_node_kind_t::unary_expression;
            n.stable_text = "!";
            n.child_ids = {n.child_ids[0]};
            ++metrics_.comparisons_normalized;
            return true;
        }
        if (n.stable_text == "!=" && *val == 0) {
            copy_node_content(n, *left);
            ++metrics_.comparisons_normalized;
            return true;
        }
        return false;
    }

    void collect_def_use(std::uint64_t node_id, std::uint64_t parent_statement_id,
                         std::unordered_set<std::uint64_t>& visited)
    {
        if (!visited.insert(node_id).second || !consume_work())
            return;
        const auto* n = node(node_id);
        if (n == nullptr)
            return;
        if (n->kind == typed_pseudocode_ast_node_kind_t::compound_statement) {
            for (const auto child_id : n->child_ids)
                collect_def_use(child_id, child_id, visited);
            return;
        }
        if (n->kind == typed_pseudocode_ast_node_kind_t::declaration) {
            if (!n->child_ids.empty()) {
                rt_def_use_entry_t entry;
                entry.variable = n->stable_text;
                entry.statement_id = parent_statement_id;
                entry.definition_node_id = node_id;
                entry.initializer_node_id = n->child_ids[0];
                entry.is_declaration = true;
                entry.has_side_effects = rt_node_has_side_effects(ast_, n->child_ids[0], id_index_);
                definitions_.push_back(entry);
            }
            for (const auto child_id : n->child_ids)
                collect_def_use(child_id, parent_statement_id, visited);
            return;
        }
        if (n->kind == typed_pseudocode_ast_node_kind_t::expression_statement && n->child_ids.size() == 1) {
            const auto* expr = node(n->child_ids[0]);
            if (expr != nullptr && expr->kind == typed_pseudocode_ast_node_kind_t::assignment_expression &&
                expr->child_ids.size() == 2) {
                const auto* target = node(expr->child_ids[0]);
                if (target != nullptr && target->kind == typed_pseudocode_ast_node_kind_t::identifier) {
                    rt_def_use_entry_t entry;
                    entry.variable = target->stable_text;
                    entry.statement_id = parent_statement_id;
                    entry.definition_node_id = expr->child_ids[0];
                    entry.initializer_node_id = expr->child_ids[1];
                    entry.is_declaration = false;
                    entry.has_side_effects = rt_node_has_side_effects(ast_, expr->child_ids[1], id_index_);
                    definitions_.push_back(entry);
                }
            }
            for (const auto child_id : n->child_ids)
                collect_def_use(child_id, parent_statement_id, visited);
            return;
        }
        if (n->kind == typed_pseudocode_ast_node_kind_t::identifier) {
            const auto parent_it = parent_map_.find(node_id);
            bool is_write = false;
            if (parent_it != parent_map_.end()) {
                const auto* parent = node(parent_it->second.first);
                if (parent != nullptr &&
                    parent->kind == typed_pseudocode_ast_node_kind_t::assignment_expression &&
                    parent_it->second.second == 0)
                    is_write = true;
            }
            if (!is_write)
                uses_[n->stable_text].push_back(node_id);
            return;
        }
        if (n->kind == typed_pseudocode_ast_node_kind_t::if_statement ||
            n->kind == typed_pseudocode_ast_node_kind_t::while_statement ||
            n->kind == typed_pseudocode_ast_node_kind_t::do_while_statement ||
            n->kind == typed_pseudocode_ast_node_kind_t::for_statement ||
            n->kind == typed_pseudocode_ast_node_kind_t::switch_statement ||
            n->kind == typed_pseudocode_ast_node_kind_t::try_statement) {
            for (const auto child_id : n->child_ids)
                collect_def_use(child_id, child_id, visited);
            return;
        }
        for (const auto child_id : n->child_ids)
            collect_def_use(child_id, parent_statement_id, visited);
    }

    void index_def_use()
    {
        definition_counts_.clear();
        definitions_by_variable_.clear();
        for (std::size_t index = 0; index < definitions_.size(); ++index) {
            ++definition_counts_[definitions_[index].variable];
            definitions_by_variable_[definitions_[index].variable].push_back(index);
        }
    }

    std::size_t count_definitions(const std::string& var) const
    {
        const auto it = definition_counts_.find(var);
        return it == definition_counts_.end() ? 0 : it->second;
    }

    const std::vector<std::size_t>* definitions_for(const std::string& var) const
    {
        const auto it = definitions_by_variable_.find(var);
        return it == definitions_by_variable_.end() ? nullptr : &it->second;
    }

    std::size_t count_uses(const std::string& var) const
    {
        const auto it = uses_.find(var);
        return it == uses_.end() ? 0 : it->second.size();
    }

    std::uint64_t find_parent_compound(std::uint64_t node_id) const
    {
        std::uint64_t current = node_id;
        std::unordered_set<std::uint64_t> visited;
        for (std::size_t guard = 0; guard < k_max_parent_chain_depth; ++guard) {
            if (!visited.insert(current).second)
                return 0;
            const auto it = parent_map_.find(current);
            if (it == parent_map_.end())
                return 0;
            const auto parent_id = it->second.first;
            const auto* parent = node(parent_id);
            if (parent == nullptr)
                return 0;
            if (parent->kind == typed_pseudocode_ast_node_kind_t::compound_statement)
                return parent_id;
            current = parent_id;
        }
        return 0;
    }

    bool remove_statement_from_compound(std::uint64_t statement_id)
    {
        const auto compound_id = find_parent_compound(statement_id);
        if (compound_id == 0)
            return false;
        auto* compound = node(compound_id);
        if (compound == nullptr)
            return false;
        const auto it = std::find(compound->child_ids.begin(), compound->child_ids.end(), statement_id);
        if (it == compound->child_ids.end())
            return false;
        pending_compound_removals_[compound_id].push_back(statement_id);
        return true;
    }

    void flush_compound_removals()
    {
        for (auto& [compound_id, removals] : pending_compound_removals_) {
            auto* compound = node(compound_id);
            if (compound == nullptr)
                continue;
            std::unordered_set<std::uint64_t> removed;
            for (const auto statement_id : removals) {
                if (compound_id == ast_.body_node_id &&
                    compound->child_ids.size() - removed.size() <= 1)
                    continue;
                removed.insert(statement_id);
            }
            if (removed.empty())
                continue;
            std::vector<std::uint64_t> kept;
            kept.reserve(compound->child_ids.size() - removed.size());
            for (const auto child_id : compound->child_ids) {
                if (removed.find(child_id) == removed.end())
                    kept.push_back(child_id);
            }
            compound->child_ids = std::move(kept);
        }
        pending_compound_removals_.clear();
    }

    bool apply_single_use_inlining()
    {
        bool changed = false;
        for (const auto& def : definitions_) {
            if (!consume_work())
                break;
            if (count_definitions(def.variable) != 1)
                continue;
            if (count_uses(def.variable) != 1)
                continue;
            if (def.has_side_effects)
                continue;
            if (def.initializer_node_id == 0)
                continue;
            const auto* init_node = node(def.initializer_node_id);
            if (init_node == nullptr)
                continue;
            if (init_node->kind == typed_pseudocode_ast_node_kind_t::call_expression ||
                init_node->kind == typed_pseudocode_ast_node_kind_t::unknown_expression)
                continue;
            const auto uses_it = uses_.find(def.variable);
            if (uses_it == uses_.end() || uses_it->second.size() != 1)
                continue;
            const auto use_id = uses_it->second[0];
            auto* use_node = node(use_id);
            if (use_node == nullptr)
                continue;
            copy_node_content(*use_node, *init_node);
            remove_statement_from_compound(def.statement_id);
            uses_.erase(def.variable);
            definition_counts_.erase(def.variable);
            definitions_by_variable_.erase(def.variable);
            ++metrics_.temporaries_inlined;
            changed = true;
        }
        flush_compound_removals();
        return changed;
    }

    bool apply_copy_propagation()
    {
        bool changed = false;
        for (const auto& def : definitions_) {
            if (!consume_work())
                break;
            if (def.has_side_effects)
                continue;
            if (def.initializer_node_id == 0)
                continue;
            if (count_definitions(def.variable) != 1)
                continue;
            const auto* init_node = node(def.initializer_node_id);
            if (init_node == nullptr ||
                init_node->kind != typed_pseudocode_ast_node_kind_t::identifier)
                continue;
            const auto& source_var = init_node->stable_text;
            if (count_definitions(source_var) > 1)
                continue;
            const auto uses_it = uses_.find(def.variable);
            if (uses_it == uses_.end())
                continue;
            for (const auto use_id : uses_it->second) {
                auto* use_node = node(use_id);
                if (use_node == nullptr)
                    continue;
                use_node->stable_text = source_var;
                use_node->type_id = init_node->type_id;
                ++metrics_.copies_propagated;
                changed = true;
            }
        }
        return changed;
    }

    bool apply_dead_store_elimination()
    {
        bool changed = false;
        std::set<std::string> processed;
        for (const auto& def : definitions_) {
            if (!consume_work())
                break;
            if (processed.find(def.variable) != processed.end())
                continue;
            processed.insert(def.variable);
            if (count_uses(def.variable) > 0)
                continue;
            const auto* entries = definitions_for(def.variable);
            if (entries == nullptr || entries->empty())
                continue;
            bool all_safe = true;
            for (const auto index : *entries) {
                if (definitions_[index].has_side_effects) {
                    all_safe = false;
                    break;
                }
            }
            if (!all_safe)
                continue;
            for (const auto index : *entries) {
                remove_statement_from_compound(definitions_[index].statement_id);
                ++metrics_.dead_stores_eliminated;
                changed = true;
            }
        }
        flush_compound_removals();
        return changed;
    }

    void build_member_edge_index()
    {
        if (member_edges_built_)
            return;
        member_edges_built_ = true;
        for (const auto& edge : type_graph_.edges) {
            if (edge.kind != decompiler_type_edge_kind_t::member || !edge.byte_offset.has_value())
                continue;
            member_edges_[edge.source_type_id].push_back(&edge);
        }
    }

    const decompiler_type_edge_t* best_member_at(
        const std::uint64_t struct_type_id,
        const std::uint64_t byte_offset,
        const std::uint64_t preferred_type_id,
        const bool union_object) const
    {
        const auto it = member_edges_.find(struct_type_id);
        if (it == member_edges_.end())
            return nullptr;
        const decompiler_type_edge_t* best = nullptr;
        std::size_t candidates = 0;
        for (const auto* edge : it->second) {
            if (*edge->byte_offset != byte_offset)
                continue;
            ++candidates;
            if (best == nullptr || edge->confidence > best->confidence)
                best = edge;
        }
        if (best == nullptr)
            return nullptr;
        if (!union_object || candidates < 2)
            return best;
        const decompiler_type_edge_t* typed = nullptr;
        for (const auto* edge : it->second) {
            if (*edge->byte_offset != byte_offset)
                continue;
            const auto edge_type = types_.find(edge->target_type_id);
            const auto read_type = types_.find(preferred_type_id);
            if (edge_type == types_.end() || read_type == types_.end())
                continue;
            const auto* et = edge_type->second;
            const auto* rt = read_type->second;
            if (et->kind != rt->kind || et->is_signed != rt->is_signed ||
                !et->byte_size.has_value() || !rt->byte_size.has_value() ||
                *et->byte_size != *rt->byte_size)
                continue;
            if (typed != nullptr)
                return nullptr;
            typed = edge;
        }
        return typed;
    }

    void apply_member_name_propagation()
    {
        build_member_edge_index();
        for (std::size_t depth = 0; depth < k_max_member_chain_depth; ++depth) {
            bool changed = false;
            for (std::size_t index = 0; index < ast_.nodes.size(); ++index) {
                if (!consume_work())
                    return;
                auto& n = ast_.nodes[index];
                if (n.kind == typed_pseudocode_ast_node_kind_t::member_expression && n.child_ids.size() == 1) {
                    const std::string before = n.stable_text;
                    try_rename_member_selector(n);
                    changed = changed || n.stable_text != before;
                } else if (n.kind == typed_pseudocode_ast_node_kind_t::unary_expression &&
                           n.stable_text == "*" && n.child_ids.size() == 1) {
                    const auto node_id = n.id;
                    const auto before_kind = n.kind;
                    const auto before_text = n.stable_text;
                    try_rewrite_chain_member(n);
                    auto* refreshed = node(node_id);
                    if (refreshed == nullptr)
                        continue;
                    if (refreshed->kind == before_kind)
                        try_rewrite_deref_member(*refreshed);
                    changed = changed || refreshed->kind != before_kind || refreshed->stable_text != before_text;
                }
            }
            if (!changed)
                break;
        }
    }

    static std::optional<std::uint64_t> parse_field_selector_offset(const std::string& selector)
    {
        std::size_t prefix_bytes = 0;
        int base = 10;
        if (selector.size() > 8 && selector.compare(0, 8, "field_0x") == 0) {
            prefix_bytes = 8;
            base = 16;
        } else if (selector.size() > 8 && selector.compare(0, 8, "field_0X") == 0) {
            prefix_bytes = 8;
            base = 16;
        } else if (selector.size() > 6 && selector.compare(0, 6, "field_") == 0) {
            prefix_bytes = 6;
        } else if (selector.size() > 5 && selector.compare(0, 5, "field") == 0) {
            prefix_bytes = 5;
        } else {
            return std::nullopt;
        }
        const std::string digits = selector.substr(prefix_bytes);
        if (digits.empty() || digits.size() > 16)
            return std::nullopt;
        std::uint64_t parsed = 0;
        for (const char character : digits) {
            const auto digit = base == 16
                ? (character >= '0' && character <= '9' ? character - '0'
                    : character >= 'a' && character <= 'f' ? character - 'a' + 10
                    : character >= 'A' && character <= 'F' ? character - 'A' + 10 : -1)
                : (character >= '0' && character <= '9' ? character - '0' : -1);
            if (digit < 0)
                return std::nullopt;
            if (parsed > (std::numeric_limits<std::uint64_t>::max() - 15ULL) / 16ULL)
                return std::nullopt;
            parsed = parsed * static_cast<std::uint64_t>(base) + static_cast<std::uint64_t>(digit);
        }
        return parsed;
    }

    const decompiler_type_node_t* struct_type_for_object(std::uint64_t object_type_id,
                                                         std::uint64_t& struct_type_id) const
    {
        struct_type_id = object_type_id;
        const auto* type = type_graph::find_type_node(type_graph_, struct_type_id);
        if (type != nullptr && type->kind == decompiler_type_kind_t::pointer) {
            const auto* pointee = type_graph::find_pointee_edge(type_graph_, struct_type_id);
            if (pointee == nullptr)
                return nullptr;
            struct_type_id = pointee->target_type_id;
            type = type_graph::find_type_node(type_graph_, struct_type_id);
        }
        if (type == nullptr ||
            (type->kind != decompiler_type_kind_t::structure && type->kind != decompiler_type_kind_t::union_type &&
             type->kind != decompiler_type_kind_t::class_type))
            return nullptr;
        return type;
    }

    std::optional<std::string> overlay_field_name(const std::string& canonical,
                                                const std::uint64_t byte_offset,
                                                const std::string& selector) const
    {
        const auto direct = member_overlay_.find(member_overlay_key(canonical, byte_offset));
        if (direct != member_overlay_.end())
            return direct->second;
        const auto wildcard = member_overlay_.find(member_overlay_key({}, byte_offset));
        if (wildcard != member_overlay_.end())
            return wildcard->second;
        if (!selector.empty()) {
            const auto hinted = member_overlay_.find(member_overlay_selector_key(canonical, selector));
            if (hinted != member_overlay_.end())
                return hinted->second;
        }
        return std::nullopt;
    }

    static bool usable_field_name(const std::string& name)
    {
        if (name.empty() || name.size() > 128 || parse_field_selector_offset(name).has_value())
            return false;
        if (!(std::isalpha(static_cast<unsigned char>(name.front())) != 0 || name.front() == '_'))
            return false;
        return std::all_of(name.begin(), name.end(), [](const char character) {
            return std::isalnum(static_cast<unsigned char>(character)) != 0 || character == '_';
        });
    }

    void try_rename_member_selector(typed_pseudocode_ast_node_t& n)
    {
        const auto offset = parse_field_selector_offset(n.stable_text);
        if (!offset.has_value())
            return;
        const auto* object = node(n.child_ids[0]);
        if (object == nullptr)
            return;
        std::uint64_t struct_type_id = 0;
        const auto* struct_type = struct_type_for_object(object->type_id, struct_type_id);
        if (struct_type == nullptr)
            return;
        const auto* member = best_member_at(struct_type_id, *offset, n.type_id,
            struct_type->kind == decompiler_type_kind_t::union_type);
        if (member != nullptr && usable_field_name(member->stable_name)) {
            n.stable_text = member->stable_name;
            ++metrics_.member_names_propagated;
            return;
        }
        if (const auto overlay = overlay_field_name(struct_type->canonical_name, *offset, n.stable_text)) {
            if (usable_field_name(*overlay)) {
                n.stable_text = *overlay;
                ++metrics_.member_names_propagated;
            }
        }
    }

    void try_rewrite_deref_member(typed_pseudocode_ast_node_t& n)
    {
        const auto* deref_child = node(n.child_ids[0]);
        if (deref_child == nullptr)
            return;
        const typed_pseudocode_ast_node_t* address_node = deref_child;
        if (deref_child->kind == typed_pseudocode_ast_node_kind_t::cast_expression &&
            deref_child->child_ids.size() == 1) {
            const auto* cast_operand = node(deref_child->child_ids[0]);
            if (cast_operand == nullptr)
                return;
            address_node = cast_operand;
        }
        if (address_node->kind != typed_pseudocode_ast_node_kind_t::binary_expression ||
            address_node->stable_text != "+" || address_node->child_ids.size() != 2)
            return;
        const auto* base = node(address_node->child_ids[0]);
        const auto* offset_node = node(address_node->child_ids[1]);
        if (base == nullptr || offset_node == nullptr ||
            offset_node->kind != typed_pseudocode_ast_node_kind_t::literal)
            return;
        const auto parsed_offset = rt_parse_signed(offset_node->stable_text);
        if (!parsed_offset || *parsed_offset < 0 ||
            static_cast<std::uint64_t>(*parsed_offset) > (std::numeric_limits<std::uint32_t>::max)())
            return;
        const std::uint64_t offset = static_cast<std::uint64_t>(*parsed_offset);
        std::uint64_t struct_type_id = 0;
        const auto* struct_type = struct_type_for_object(base->type_id, struct_type_id);
        if (struct_type == nullptr)
            return;
        std::string field_name;
        std::uint64_t field_type_id = 0;
        const auto* member = best_member_at(struct_type_id, offset, n.type_id,
            struct_type->kind == decompiler_type_kind_t::union_type);
        if (member != nullptr && usable_field_name(member->stable_name)) {
            field_name = member->stable_name;
            if (types_.find(member->target_type_id) != types_.end())
                field_type_id = member->target_type_id;
        } else if (const auto overlay = overlay_field_name(struct_type->canonical_name, offset, {})) {
            if (usable_field_name(*overlay))
                field_name = *overlay;
        }
        if (field_name.empty())
            return;
        const auto base_id = address_node->child_ids[0];
        n.kind = typed_pseudocode_ast_node_kind_t::member_expression;
        if (field_type_id != 0)
            n.type_id = field_type_id;
        n.child_ids = {base_id};
        n.stable_text = std::move(field_name);
        ++metrics_.member_accesses_rewritten;
    }

    const typed_pseudocode_ast_node_t* unwrap_cast(const typed_pseudocode_ast_node_t* value) const
    {
        if (value != nullptr && value->kind == typed_pseudocode_ast_node_kind_t::cast_expression &&
            value->child_ids.size() == 1)
            return node(value->child_ids[0]);
        return value;
    }

    bool literal_offset(const typed_pseudocode_ast_node_t* value, std::uint64_t& offset) const
    {
        if (value == nullptr || value->kind != typed_pseudocode_ast_node_kind_t::literal)
            return false;
        const auto parsed = rt_parse_signed(value->stable_text);
        if (!parsed || *parsed < 0 ||
            static_cast<std::uint64_t>(*parsed) > (std::numeric_limits<std::uint32_t>::max)())
            return false;
        offset = static_cast<std::uint64_t>(*parsed);
        return true;
    }

    void rewrite_to_member(typed_pseudocode_ast_node_t& n,
                           const std::uint64_t base_id,
                           const std::uint64_t struct_type_id,
                           const decompiler_type_node_t& struct_type,
                           const std::uint64_t offset)
    {
        std::string field_name;
        std::uint64_t field_type_id = 0;
        const auto* member = best_member_at(struct_type_id, offset, n.type_id,
            struct_type.kind == decompiler_type_kind_t::union_type);
        if (member != nullptr && usable_field_name(member->stable_name)) {
            field_name = member->stable_name;
            if (types_.find(member->target_type_id) != types_.end())
                field_type_id = member->target_type_id;
        } else if (const auto overlay = overlay_field_name(struct_type.canonical_name, offset, {})) {
            if (usable_field_name(*overlay))
                field_name = *overlay;
        }
        if (field_name.empty())
            return;
        n.kind = typed_pseudocode_ast_node_kind_t::member_expression;
        if (field_type_id != 0)
            n.type_id = field_type_id;
        n.child_ids = {base_id};
        n.stable_text = std::move(field_name);
        ++metrics_.member_accesses_rewritten;
    }

    void try_rewrite_chain_member(typed_pseudocode_ast_node_t& n)
    {
        const auto* address_node = unwrap_cast(node(n.child_ids[0]));
        if (address_node == nullptr ||
            address_node->kind != typed_pseudocode_ast_node_kind_t::binary_expression ||
            address_node->stable_text != "+" || address_node->child_ids.size() != 2)
            return;
        const auto* first = node(address_node->child_ids[0]);
        const auto* second = node(address_node->child_ids[1]);
        if (first == nullptr || second == nullptr)
            return;
        if (second->kind == typed_pseudocode_ast_node_kind_t::literal) {
            if (first->kind == typed_pseudocode_ast_node_kind_t::member_expression ||
                first->kind == typed_pseudocode_ast_node_kind_t::index_expression) {
                std::uint64_t offset = 0;
                if (!literal_offset(second, offset))
                    return;
                std::uint64_t struct_type_id = 0;
                const auto* struct_type = struct_type_for_object(first->type_id, struct_type_id);
                if (struct_type == nullptr)
                    return;
                rewrite_to_member(n, address_node->child_ids[0], struct_type_id, *struct_type, offset);
                return;
            }
            if (first->kind == typed_pseudocode_ast_node_kind_t::binary_expression &&
                first->stable_text == "+" && first->child_ids.size() == 2) {
                std::uint64_t offset = 0;
                if (!literal_offset(second, offset))
                    return;
                try_rewrite_array_member(n, first->child_ids[0], first->child_ids[1], offset);
                return;
            }
            return;
        }
        if (first->kind != typed_pseudocode_ast_node_kind_t::literal &&
            second->kind == typed_pseudocode_ast_node_kind_t::binary_expression &&
            second->stable_text == "+" && second->child_ids.size() == 2) {
            const auto* inner_first = node(second->child_ids[0]);
            const auto* inner_second = node(second->child_ids[1]);
            if (inner_first == nullptr || inner_second == nullptr)
                return;
            if (inner_first->kind == typed_pseudocode_ast_node_kind_t::literal) {
                std::uint64_t offset = 0;
                if (!literal_offset(inner_first, offset))
                    return;
                try_rewrite_array_member(n, address_node->child_ids[0], second->child_ids[1], offset);
            }
        }
    }

    void try_rewrite_array_member(typed_pseudocode_ast_node_t& n,
                                  const std::uint64_t left_candidate_id,
                                  const std::uint64_t right_candidate_id,
                                  const std::uint64_t offset)
    {
        std::uint64_t base_candidate_id = 0;
        std::uint64_t scaled_candidate_id = 0;
        const auto* left_candidate = node(left_candidate_id);
        const auto* right_candidate = node(right_candidate_id);
        if (right_candidate != nullptr &&
            right_candidate->kind == typed_pseudocode_ast_node_kind_t::binary_expression &&
            right_candidate->stable_text == "*" && right_candidate->child_ids.size() == 2) {
            base_candidate_id = left_candidate_id;
            scaled_candidate_id = right_candidate_id;
        } else if (left_candidate != nullptr &&
                   left_candidate->kind == typed_pseudocode_ast_node_kind_t::binary_expression &&
                   left_candidate->stable_text == "*" && left_candidate->child_ids.size() == 2) {
            base_candidate_id = right_candidate_id;
            scaled_candidate_id = left_candidate_id;
        } else {
            return;
        }
        const auto* scaled = node(scaled_candidate_id);
        if (scaled == nullptr)
            return;
        const auto* scale_left = node(scaled->child_ids[0]);
        const auto* scale_right = node(scaled->child_ids[1]);
        if (scale_left == nullptr || scale_right == nullptr)
            return;
        std::uint64_t index_id = 0;
        std::uint64_t element_size = 0;
        if (scale_right->kind == typed_pseudocode_ast_node_kind_t::literal &&
            literal_offset(scale_right, element_size) && element_size != 0)
            index_id = scaled->child_ids[0];
        else if (scale_left->kind == typed_pseudocode_ast_node_kind_t::literal &&
                 literal_offset(scale_left, element_size) && element_size != 0)
            index_id = scaled->child_ids[1];
        else
            return;
        const auto* base = node(base_candidate_id);
        if (base == nullptr)
            return;
        std::uint64_t struct_type_id = 0;
        const auto* struct_type = struct_type_for_object(base->type_id, struct_type_id);
        if (struct_type == nullptr || !struct_type->byte_size.has_value() ||
            *struct_type->byte_size != element_size)
            return;
        std::string field_name;
        std::uint64_t field_type_id = 0;
        const auto* member = best_member_at(struct_type_id, offset, n.type_id,
            struct_type->kind == decompiler_type_kind_t::union_type);
        if (member != nullptr && usable_field_name(member->stable_name)) {
            field_name = member->stable_name;
            if (types_.find(member->target_type_id) != types_.end())
                field_type_id = member->target_type_id;
        } else if (const auto overlay = overlay_field_name(struct_type->canonical_name, offset, {})) {
            if (usable_field_name(*overlay))
                field_name = *overlay;
        }
        if (field_name.empty())
            return;
        const std::uint64_t node_id = n.id;
        const auto index_expr = make_node(typed_pseudocode_ast_node_kind_t::index_expression,
            struct_type_id, {base_candidate_id, index_id}, {}, n.coordinate, n.confidence, n.provenance);
        auto* mutable_node = node(node_id);
        if (mutable_node == nullptr)
            return;
        mutable_node->kind = typed_pseudocode_ast_node_kind_t::member_expression;
        if (field_type_id != 0)
            mutable_node->type_id = field_type_id;
        mutable_node->child_ids = {index_expr};
        mutable_node->stable_text = std::move(field_name);
        ++metrics_.member_accesses_rewritten;
    }

    struct magic_division_entry_t {
        std::uint32_t divisor;
        std::uint32_t multiplier;
        std::uint8_t total_shift;
    };

    static const magic_division_entry_t* lookup_magic_division(
        const std::uint64_t multiplier, const std::uint64_t total_shift)
    {
        static constexpr magic_division_entry_t k_magic_table[] = {
            {3, 0xAAAAAAABU, 33}, {5, 0xCCCCCCCDU, 34}, {6, 0xAAAAAAABU, 34},
            {9, 0x38E38E39U, 33}, {10, 0xCCCCCCCDU, 35}, {11, 0xBA2E8BA3U, 35},
            {12, 0xAAAAAAABU, 35}, {13, 0x4EC4EC4FU, 34}, {15, 0x88888889U, 35},
            {100, 0x51EB851FU, 37}, {1000, 0x10624DD3U, 38},
        };
        for (const auto& entry : k_magic_table) {
            if (entry.multiplier == multiplier && entry.total_shift == total_shift)
                return &entry;
        }
        return nullptr;
    }

    std::uint64_t integer_width_bits(const std::uint64_t type_id) const
    {
        const auto type_it = types_.find(type_id);
        if (type_it == types_.end() || !type_it->second->byte_size.has_value())
            return 0;
        const auto* type = type_it->second;
        if (type->kind != decompiler_type_kind_t::signed_integer &&
            type->kind != decompiler_type_kind_t::unsigned_integer)
            return 0;
        return *type->byte_size * 8;
    }

    bool unsigned_or_unknown_integer(const std::uint64_t type_id, const std::uint64_t width) const
    {
        const auto type_it = types_.find(type_id);
        if (type_it == types_.end())
            return true;
        const auto* type = type_it->second;
        if (type->kind == decompiler_type_kind_t::unknown)
            return true;
        if (type->kind != decompiler_type_kind_t::unsigned_integer)
            return false;
        return !type->byte_size.has_value() || *type->byte_size == width / 8;
    }

    void rewrite_to_intrinsic_call(typed_pseudocode_ast_node_t& n,
                                   std::string callee_name,
                                   const std::vector<std::uint64_t>& argument_ids)
    {
        const std::uint64_t node_id = n.id;
        const auto callee = make_node(typed_pseudocode_ast_node_kind_t::identifier,
            n.type_id, {}, std::move(callee_name), n.coordinate, n.confidence, n.provenance);
        std::vector<std::uint64_t> children{callee};
        children.insert(children.end(), argument_ids.begin(), argument_ids.end());
        auto* mutable_node = node(node_id);
        if (mutable_node == nullptr)
            return;
        mutable_node->kind = typed_pseudocode_ast_node_kind_t::call_expression;
        mutable_node->stable_text.clear();
        mutable_node->child_ids = std::move(children);
    }

    bool try_rewrite_rotate(typed_pseudocode_ast_node_t& n)
    {
        if (n.child_ids.size() != 2 || n.stable_text != "|")
            return false;
        const auto* left = node(n.child_ids[0]);
        const auto* right = node(n.child_ids[1]);
        if (left == nullptr || right == nullptr ||
            left->kind != typed_pseudocode_ast_node_kind_t::binary_expression ||
            right->kind != typed_pseudocode_ast_node_kind_t::binary_expression ||
            left->child_ids.size() != 2 || right->child_ids.size() != 2)
            return false;
        const typed_pseudocode_ast_node_t* shl = nullptr;
        const typed_pseudocode_ast_node_t* shr = nullptr;
        bool left_rotate = false;
        if (left->stable_text == "<<" && right->stable_text == ">>") {
            shl = left;
            shr = right;
            left_rotate = true;
        } else if (left->stable_text == ">>" && right->stable_text == "<<") {
            shl = right;
            shr = left;
            left_rotate = false;
        } else {
            return false;
        }
        const auto* shl_value = node(shl->child_ids[0]);
        const auto* shl_amount = node(shl->child_ids[1]);
        const auto* shr_value = node(shr->child_ids[0]);
        const auto* shr_amount = node(shr->child_ids[1]);
        if (shl_value == nullptr || shr_value == nullptr ||
            !expressions_equivalent(shl->child_ids[0], shr->child_ids[0], 0))
            return false;
        std::uint64_t forward = 0;
        std::uint64_t backward = 0;
        if (!literal_unsigned_value(shl_amount, forward) ||
            !literal_unsigned_value(shr_amount, backward))
            return false;
        const auto width = integer_width_bits(shl_value->type_id);
        if ((width != 16 && width != 32 && width != 64) || forward == 0 || backward == 0 ||
            forward + backward != width || forward >= width)
            return false;
        if (rt_node_has_side_effects(ast_, shl->child_ids[0], id_index_))
            return false;
        const std::uint64_t value_id = left_rotate ? left->child_ids[0] : right->child_ids[0];
        const std::uint64_t amount_id = left_rotate ? left->child_ids[1] : right->child_ids[1];
        rewrite_to_intrinsic_call(n, left_rotate ? "_rotl" : "_rotr", {value_id, amount_id});
        ++metrics_.bit_operation_idioms_rewritten;
        return true;
    }

    bool match_bswap_mask_shift(const typed_pseudocode_ast_node_t* term,
                                const bool expect_shifted_mask,
                                const std::uint64_t expect_mask,
                                const std::uint64_t expect_shift,
                                std::uint64_t& value_id)
    {
        if (term == nullptr || term->kind != typed_pseudocode_ast_node_kind_t::binary_expression ||
            term->child_ids.size() != 2)
            return false;
        const typed_pseudocode_ast_node_t* mask_expr = nullptr;
        if (!expect_shifted_mask) {
            if (term->stable_text != "<<")
                return false;
            std::uint64_t amount = 0;
            const auto* amount_node = node(term->child_ids[1]);
            if (!literal_unsigned_value(amount_node, amount) || amount != expect_shift)
                return false;
            mask_expr = node(term->child_ids[0]);
        } else {
            if (term->stable_text != "&")
                return false;
            mask_expr = term;
        }
        if (mask_expr == nullptr ||
            mask_expr->kind != typed_pseudocode_ast_node_kind_t::binary_expression ||
            mask_expr->stable_text != "&" || mask_expr->child_ids.size() != 2)
            return false;
        const auto* mask_value = node(mask_expr->child_ids[0]);
        const auto* mask_literal = node(mask_expr->child_ids[1]);
        std::uint64_t candidate_id = 0;
        if (expect_shifted_mask) {
            if (mask_value == nullptr ||
                mask_value->kind != typed_pseudocode_ast_node_kind_t::binary_expression ||
                mask_value->stable_text != ">>" || mask_value->child_ids.size() != 2)
                return false;
            std::uint64_t shift = 0;
            const auto* shift_amount_node = node(mask_value->child_ids[1]);
            if (!literal_unsigned_value(shift_amount_node, shift) || shift != expect_shift)
                return false;
            candidate_id = mask_value->child_ids[0];
        } else {
            candidate_id = mask_expr->child_ids[0];
        }
        std::uint64_t applied_mask = 0;
        if (!literal_unsigned_value(mask_literal, applied_mask) || applied_mask != expect_mask)
            return false;
        if (candidate_id == 0)
            return false;
        if (value_id == 0) {
            value_id = candidate_id;
            return true;
        }
        return expressions_equivalent(value_id, candidate_id, 0);
    }

    bool try_rewrite_bswap(typed_pseudocode_ast_node_t& n)
    {
        if (n.child_ids.size() != 2 || n.stable_text != "|")
            return false;
        const auto* left = node(n.child_ids[0]);
        const auto* right = node(n.child_ids[1]);
        if (left == nullptr || right == nullptr ||
            left->kind != typed_pseudocode_ast_node_kind_t::binary_expression ||
            left->stable_text != "|" || left->child_ids.size() != 2)
            return false;
        const auto* middle = node(left->child_ids[0]);
        if (middle == nullptr ||
            middle->kind != typed_pseudocode_ast_node_kind_t::binary_expression ||
            middle->stable_text != "|" || middle->child_ids.size() != 2)
            return false;
        const typed_pseudocode_ast_node_t* terms[4] = {
            node(middle->child_ids[0]), node(middle->child_ids[1]),
            node(left->child_ids[1]), right};
        std::uint64_t value_id = 0;
        static constexpr struct {
            bool shifted_mask;
            std::uint64_t mask;
            std::uint64_t shift;
        } k_term_shapes[4] = {
            {false, 0xFFULL, 24}, {false, 0xFF00ULL, 8},
            {true, 0xFF00ULL, 8}, {true, 0xFFULL, 24},
        };
        bool matched[4] = {false, false, false, false};
        std::size_t matched_count = 0;
        for (const auto* term : terms) {
            bool term_matched = false;
            for (std::size_t shape = 0; shape < 4 && !term_matched; ++shape) {
                if (matched[shape])
                    continue;
                if (match_bswap_mask_shift(term, k_term_shapes[shape].shifted_mask,
                        k_term_shapes[shape].mask, k_term_shapes[shape].shift, value_id)) {
                    matched[shape] = true;
                    term_matched = true;
                    ++matched_count;
                }
            }
            if (!term_matched)
                return false;
        }
        if (matched_count != 4 || value_id == 0)
            return false;
        const auto* value = node(value_id);
        if (value == nullptr)
            return false;
        const auto type_it = types_.find(value->type_id);
        if (type_it == types_.end() || !type_it->second->byte_size.has_value() ||
            *type_it->second->byte_size != 4)
            return false;
        if (rt_node_has_side_effects(ast_, value_id, id_index_))
            return false;
        rewrite_to_intrinsic_call(n, "_byteswap_ulong", {value_id});
        ++metrics_.bit_operation_idioms_rewritten;
        return true;
    }

    bool try_rewrite_magic_division(typed_pseudocode_ast_node_t& n)
    {
        if (n.child_ids.size() != 2 || n.stable_text != ">>")
            return false;
        const auto* multiply = node(n.child_ids[0]);
        const auto* shift_node = node(n.child_ids[1]);
        if (multiply == nullptr || shift_node == nullptr ||
            multiply->kind != typed_pseudocode_ast_node_kind_t::binary_expression ||
            multiply->stable_text != "*" || multiply->child_ids.size() != 2)
            return false;
        std::uint64_t total_shift = 0;
        if (!literal_unsigned_value(shift_node, total_shift) ||
            total_shift < 33 || total_shift > 38)
            return false;
        const auto* left = node(multiply->child_ids[0]);
        const auto* right = node(multiply->child_ids[1]);
        if (left == nullptr || right == nullptr)
            return false;
        const typed_pseudocode_ast_node_t* value_node = nullptr;
        std::uint64_t multiplier = 0;
        if (literal_unsigned_value(right, multiplier))
            value_node = left;
        else if (literal_unsigned_value(left, multiplier))
            value_node = right;
        else
            return false;
        const auto* entry = lookup_magic_division(multiplier, total_shift);
        if (entry == nullptr)
            return false;
        const typed_pseudocode_ast_node_t* dividend = value_node;
        if (dividend->kind == typed_pseudocode_ast_node_kind_t::cast_expression &&
            dividend->child_ids.size() == 1) {
            if (const auto* unwrapped = node(dividend->child_ids[0]))
                dividend = unwrapped;
        }
        if (dividend == nullptr)
            return false;
        const auto multiply_type_it = types_.find(multiply->type_id);
        if (multiply_type_it != types_.end() &&
            multiply_type_it->second->byte_size.has_value() &&
            *multiply_type_it->second->byte_size != 8)
            return false;
        if (!unsigned_or_unknown_integer(dividend->type_id, 32))
            return false;
        const std::uint64_t node_id = n.id;
        const std::uint64_t dividend_id = dividend->id;
        const auto divisor_literal = make_node(typed_pseudocode_ast_node_kind_t::literal,
            n.type_id, {}, std::to_string(entry->divisor), n.coordinate, n.confidence, n.provenance);
        auto* mutable_node = node(node_id);
        if (mutable_node == nullptr)
            return false;
        mutable_node->stable_text = "/";
        mutable_node->child_ids = {dividend_id, divisor_literal};
        ++metrics_.magic_divisions_recognized;
        return true;
    }

    void apply_bit_operation_idioms()
    {
        for (std::size_t index = 0; index < ast_.nodes.size(); ++index) {
            if (!consume_work())
                return;
            auto& n = ast_.nodes[index];
            if (n.kind != typed_pseudocode_ast_node_kind_t::binary_expression)
                continue;
            const std::uint64_t node_id = n.id;
            if (settings_.enable_bit_operation_idioms && n.stable_text == "|") {
                if (try_rewrite_rotate(n))
                    continue;
                try_rewrite_bswap(n);
            }
            if (!settings_.enable_magic_division_recognition)
                continue;
            auto* refreshed = node(node_id);
            if (refreshed == nullptr ||
                refreshed->kind != typed_pseudocode_ast_node_kind_t::binary_expression ||
                refreshed->stable_text != ">>")
                continue;
            try_rewrite_magic_division(*refreshed);
        }
    }

    struct loop_intrinsic_match_t {
        std::uint64_t destination_id = 0;
        std::uint64_t source_id = 0;
        std::uint64_t value_id = 0;
        std::uint64_t high_id = 0;
        std::uint64_t low_id = 0;
        std::uint64_t element_size = 1;
        bool is_memcpy = false;
    };

    bool extract_loop_increment(const typed_pseudocode_ast_node_t* node_value,
                                const std::string& counter) const
    {
        if (node_value == nullptr)
            return false;
        if (node_value->kind == typed_pseudocode_ast_node_kind_t::unary_expression &&
            node_value->stable_text == "++" && node_value->child_ids.size() == 1) {
            const auto* operand = node(node_value->child_ids[0]);
            return operand != nullptr &&
                operand->kind == typed_pseudocode_ast_node_kind_t::identifier &&
                operand->stable_text == counter;
        }
        if (node_value->kind == typed_pseudocode_ast_node_kind_t::assignment_expression &&
            (node_value->stable_text == "=" || node_value->stable_text == "+=") &&
            node_value->child_ids.size() == 2) {
            const auto* target = node(node_value->child_ids[0]);
            if (target == nullptr ||
                target->kind != typed_pseudocode_ast_node_kind_t::identifier ||
                target->stable_text != counter)
                return false;
            const auto* value = node(node_value->child_ids[1]);
            if (node_value->stable_text == "+=") {
                std::uint64_t amount = 0;
                return literal_unsigned_value(value, amount) && amount == 1;
            }
            if (value == nullptr ||
                value->kind != typed_pseudocode_ast_node_kind_t::binary_expression ||
                value->stable_text != "+" || value->child_ids.size() != 2)
                return false;
            const auto* left = node(value->child_ids[0]);
            const auto* right = node(value->child_ids[1]);
            std::uint64_t amount = 0;
            const bool left_counter = left != nullptr &&
                left->kind == typed_pseudocode_ast_node_kind_t::identifier &&
                left->stable_text == counter;
            const bool right_counter = right != nullptr &&
                right->kind == typed_pseudocode_ast_node_kind_t::identifier &&
                right->stable_text == counter;
            return (left_counter && literal_unsigned_value(right, amount) && amount == 1) ||
                   (right_counter && literal_unsigned_value(left, amount) && amount == 1);
        }
        return false;
    }

    std::uint64_t count_identifier_occurrences(std::uint64_t node_id,
                                               const std::string& name,
                                               std::unordered_set<std::uint64_t>& visited,
                                               std::size_t depth) const
    {
        if (depth >= 64 || !visited.insert(node_id).second)
            return 0;
        const auto* n = node(node_id);
        if (n == nullptr)
            return 0;
        std::uint64_t count = (n->kind == typed_pseudocode_ast_node_kind_t::identifier &&
            n->stable_text == name) ? 1 : 0;
        for (const auto child_id : n->child_ids)
            count += count_identifier_occurrences(child_id, name, visited, depth + 1);
        return count;
    }

    bool match_loop_store(const typed_pseudocode_ast_node_t* statement,
                          const std::string& counter,
                          loop_intrinsic_match_t& match) const
    {
        if (statement == nullptr ||
            statement->kind != typed_pseudocode_ast_node_kind_t::expression_statement ||
            statement->child_ids.size() != 1)
            return false;
        const auto* assignment = node(statement->child_ids[0]);
        if (assignment == nullptr ||
            assignment->kind != typed_pseudocode_ast_node_kind_t::assignment_expression ||
            assignment->stable_text != "=" || assignment->child_ids.size() != 2)
            return false;
        const auto* target = node(assignment->child_ids[0]);
        if (target == nullptr ||
            target->kind != typed_pseudocode_ast_node_kind_t::index_expression ||
            target->child_ids.size() != 2)
            return false;
        const auto* destination = node(target->child_ids[0]);
        const auto* subscript = node(target->child_ids[1]);
        if (destination == nullptr || subscript == nullptr ||
            destination->kind != typed_pseudocode_ast_node_kind_t::identifier ||
            subscript->kind != typed_pseudocode_ast_node_kind_t::identifier ||
            subscript->stable_text != counter)
            return false;
        match.destination_id = target->child_ids[0];
        const auto* value = node(assignment->child_ids[1]);
        if (value == nullptr)
            return false;
        if (value->kind == typed_pseudocode_ast_node_kind_t::index_expression &&
            value->child_ids.size() == 2) {
            const auto* source = node(value->child_ids[0]);
            const auto* source_subscript = node(value->child_ids[1]);
            if (source == nullptr || source_subscript == nullptr ||
                source->kind != typed_pseudocode_ast_node_kind_t::identifier ||
                source_subscript->kind != typed_pseudocode_ast_node_kind_t::identifier ||
                source_subscript->stable_text != counter ||
                source->stable_text == destination->stable_text)
                return false;
            match.is_memcpy = true;
            match.source_id = value->child_ids[0];
            match.value_id = 0;
        } else {
            std::unordered_set<std::uint64_t> visited;
            if (count_identifier_occurrences(assignment->child_ids[1], counter, visited, 0) != 0)
                return false;
            match.is_memcpy = false;
            match.value_id = assignment->child_ids[1];
        }
        if (rt_node_has_side_effects(ast_, target->child_ids[0], id_index_))
            return false;
        if (match.is_memcpy && rt_node_has_side_effects(ast_, match.source_id, id_index_))
            return false;
        if (!match.is_memcpy && rt_node_has_side_effects(ast_, match.value_id, id_index_))
            return false;
        return true;
    }

    bool element_size_for(const std::uint64_t identifier_id, std::uint64_t& element_size) const
    {
        const auto* identifier = node(identifier_id);
        if (identifier == nullptr)
            return false;
        const auto type_it = types_.find(identifier->type_id);
        if (type_it == types_.end() ||
            type_it->second->kind != decompiler_type_kind_t::pointer)
            return false;
        const auto* pointee = type_graph::find_pointee_edge(type_graph_, identifier->type_id);
        if (pointee == nullptr)
            return false;
        const auto pointee_it = types_.find(pointee->target_type_id);
        if (pointee_it == types_.end() || !pointee_it->second->byte_size.has_value() ||
            *pointee_it->second->byte_size == 0)
            return false;
        element_size = *pointee_it->second->byte_size;
        return true;
    }

    void rewrite_loop_to_intrinsic(typed_pseudocode_ast_node_t& loop_node,
                                   loop_intrinsic_match_t& match)
    {
        const std::uint64_t loop_id = loop_node.id;
        const auto loop_type_id = loop_node.type_id;
        const auto loop_coordinate = loop_node.coordinate;
        const auto loop_confidence = loop_node.confidence;
        const auto loop_provenance = loop_node.provenance;
        const auto needs_multiply = match.element_size != 1;
        const auto low_is_zero = [this](const std::uint64_t id) {
            const auto* low = node(id);
            std::uint64_t value = 0;
            return low != nullptr && low->kind == typed_pseudocode_ast_node_kind_t::literal &&
                literal_unsigned_value(low, value) && value == 0;
        };
        std::uint64_t count_expr = 0;
        if (low_is_zero(match.low_id)) {
            count_expr = match.high_id;
        } else {
            count_expr = make_node(typed_pseudocode_ast_node_kind_t::binary_expression,
                loop_type_id, {match.high_id, match.low_id}, "-",
                loop_coordinate, loop_confidence, loop_provenance);
        }
        std::uint64_t size_expr = count_expr;
        if (needs_multiply) {
            const auto element_literal = make_node(typed_pseudocode_ast_node_kind_t::literal,
                loop_type_id, {}, std::to_string(match.element_size),
                loop_coordinate, loop_confidence, loop_provenance);
            size_expr = make_node(typed_pseudocode_ast_node_kind_t::binary_expression,
                loop_type_id, {count_expr, element_literal}, "*",
                loop_coordinate, loop_confidence, loop_provenance);
        }
        const auto callee = make_node(typed_pseudocode_ast_node_kind_t::identifier,
            loop_type_id, {}, match.is_memcpy ? "memcpy" : "memset",
            loop_coordinate, loop_confidence, loop_provenance);
        std::vector<std::uint64_t> call_children{callee, match.destination_id};
        call_children.push_back(match.is_memcpy ? match.source_id : match.value_id);
        call_children.push_back(size_expr);
        const auto call = make_node(typed_pseudocode_ast_node_kind_t::call_expression,
            loop_type_id, std::move(call_children), {},
            loop_coordinate, loop_confidence, loop_provenance);
        auto* mutable_loop = node(loop_id);
        if (mutable_loop == nullptr)
            return;
        mutable_loop->kind = typed_pseudocode_ast_node_kind_t::expression_statement;
        mutable_loop->stable_text.clear();
        mutable_loop->child_ids = {call};
        ++metrics_.loop_intrinsics_rewritten;
    }

    bool try_rewrite_for_loop_intrinsic(typed_pseudocode_ast_node_t& n)
    {
        if (n.child_ids.size() != 4)
            return false;
        const auto* init = node(n.child_ids[0]);
        if (init == nullptr)
            return false;
        std::string counter;
        std::uint64_t low_id = 0;
        if (init->kind == typed_pseudocode_ast_node_kind_t::declaration &&
            init->child_ids.size() == 1) {
            counter = init->stable_text;
            low_id = init->child_ids[0];
        } else {
            const typed_pseudocode_ast_node_t* init_expression = init;
            if (init->kind == typed_pseudocode_ast_node_kind_t::expression_statement &&
                init->child_ids.size() == 1)
                init_expression = node(init->child_ids[0]);
            if (init_expression == nullptr ||
                init_expression->kind != typed_pseudocode_ast_node_kind_t::assignment_expression ||
                init_expression->stable_text != "=" || init_expression->child_ids.size() != 2)
                return false;
            const auto* target = node(init_expression->child_ids[0]);
            if (target == nullptr ||
                target->kind != typed_pseudocode_ast_node_kind_t::identifier)
                return false;
            counter = target->stable_text;
            low_id = init_expression->child_ids[1];
        }
        if (counter.empty() || low_id == 0)
            return false;
        const auto* condition = node(n.child_ids[1]);
        if (condition == nullptr ||
            condition->kind != typed_pseudocode_ast_node_kind_t::binary_expression ||
            (condition->stable_text != "<" && condition->stable_text != "!=") ||
            condition->child_ids.size() != 2)
            return false;
        const auto* condition_counter = node(condition->child_ids[0]);
        if (condition_counter == nullptr ||
            condition_counter->kind != typed_pseudocode_ast_node_kind_t::identifier ||
            condition_counter->stable_text != counter)
            return false;
        const std::uint64_t high_id = condition->child_ids[1];
        {
            std::unordered_set<std::uint64_t> visited;
            if (count_identifier_occurrences(high_id, counter, visited, 0) != 0)
                return false;
        }
        if (rt_node_has_side_effects(ast_, high_id, id_index_) ||
            rt_node_has_side_effects(ast_, low_id, id_index_))
            return false;
        const auto* iteration = node(n.child_ids[2]);
        if (!extract_loop_increment(iteration, counter))
            return false;
        const auto* body = node(n.child_ids[3]);
        if (body == nullptr ||
            body->kind != typed_pseudocode_ast_node_kind_t::compound_statement ||
            body->child_ids.size() != 1)
            return false;
        loop_intrinsic_match_t match;
        const auto* store = node(body->child_ids[0]);
        if (!match_loop_store(store, counter, match))
            return false;
        {
            std::unordered_set<std::uint64_t> total_visited;
            const auto total = count_identifier_occurrences(ast_.root_node_id, counter, total_visited, 0);
            std::unordered_set<std::uint64_t> loop_visited;
            const auto in_loop = count_identifier_occurrences(n.id, counter, loop_visited, 0);
            if (total != in_loop)
                return false;
        }
        match.high_id = high_id;
        match.low_id = low_id;
        std::uint64_t element_size = 0;
        if (!element_size_for(match.destination_id, element_size))
            return false;
        if (match.is_memcpy) {
            std::uint64_t source_element_size = 0;
            if (!element_size_for(match.source_id, source_element_size) ||
                source_element_size != element_size)
                return false;
        }
        match.element_size = element_size;
        rewrite_loop_to_intrinsic(n, match);
        return true;
    }

    bool try_rewrite_while_loop_intrinsic(typed_pseudocode_ast_node_t& n,
                                          const typed_pseudocode_ast_node_t* preceding)
    {
        if (preceding == nullptr ||
            preceding->kind != typed_pseudocode_ast_node_kind_t::expression_statement ||
            preceding->child_ids.size() != 1)
            return false;
        const auto* init_expression = node(preceding->child_ids[0]);
        if (init_expression == nullptr ||
            init_expression->kind != typed_pseudocode_ast_node_kind_t::assignment_expression ||
            init_expression->stable_text != "=" || init_expression->child_ids.size() != 2)
            return false;
        const auto* init_target = node(init_expression->child_ids[0]);
        if (init_target == nullptr ||
            init_target->kind != typed_pseudocode_ast_node_kind_t::identifier)
            return false;
        const std::string counter = init_target->stable_text;
        const std::uint64_t low_id = init_expression->child_ids[1];
        const auto* condition = node(n.child_ids[0]);
        if (condition == nullptr ||
            condition->kind != typed_pseudocode_ast_node_kind_t::binary_expression ||
            condition->stable_text != "<" || condition->child_ids.size() != 2)
            return false;
        const auto* condition_counter = node(condition->child_ids[0]);
        if (condition_counter == nullptr ||
            condition_counter->kind != typed_pseudocode_ast_node_kind_t::identifier ||
            condition_counter->stable_text != counter)
            return false;
        const std::uint64_t high_id = condition->child_ids[1];
        {
            std::unordered_set<std::uint64_t> visited;
            if (count_identifier_occurrences(high_id, counter, visited, 0) != 0)
                return false;
        }
        if (rt_node_has_side_effects(ast_, high_id, id_index_) ||
            rt_node_has_side_effects(ast_, low_id, id_index_))
            return false;
        const auto* body = node(n.child_ids[1]);
        if (body == nullptr ||
            body->kind != typed_pseudocode_ast_node_kind_t::compound_statement ||
            body->child_ids.size() != 2)
            return false;
        const auto* store = node(body->child_ids[0]);
        loop_intrinsic_match_t match;
        if (!match_loop_store(store, counter, match))
            return false;
        const auto* increment_statement = node(body->child_ids[1]);
        if (increment_statement == nullptr ||
            increment_statement->kind != typed_pseudocode_ast_node_kind_t::expression_statement ||
            increment_statement->child_ids.size() != 1 ||
            !extract_loop_increment(node(increment_statement->child_ids[0]), counter))
            return false;
        {
            std::unordered_set<std::uint64_t> total_visited;
            const auto total = count_identifier_occurrences(ast_.root_node_id, counter, total_visited, 0);
            std::unordered_set<std::uint64_t> loop_visited;
            const auto in_loop = count_identifier_occurrences(n.id, counter, loop_visited, 0);
            std::unordered_set<std::uint64_t> init_visited;
            const auto in_init = count_identifier_occurrences(preceding->id, counter, init_visited, 0);
            if (total != in_loop + in_init)
                return false;
        }
        match.high_id = high_id;
        match.low_id = low_id;
        std::uint64_t element_size = 0;
        if (!element_size_for(match.destination_id, element_size))
            return false;
        if (match.is_memcpy) {
            std::uint64_t source_element_size = 0;
            if (!element_size_for(match.source_id, source_element_size) ||
                source_element_size != element_size)
                return false;
        }
        match.element_size = element_size;
        const std::uint64_t preceding_id = preceding->id;
        rewrite_loop_to_intrinsic(n, match);
        remove_statement_from_compound(preceding_id);
        flush_compound_removals();
        return true;
    }

    void apply_loop_intrinsic_idioms()
    {
        std::vector<std::uint64_t> compounds;
        collect_compound_ids(ast_.body_node_id, compounds, 0);
        for (const auto compound_id : compounds) {
            if (!consume_work())
                return;
            const auto* compound = node(compound_id);
            if (compound == nullptr ||
                compound->kind != typed_pseudocode_ast_node_kind_t::compound_statement)
                continue;
            const auto children = compound->child_ids;
            for (std::size_t index = 0; index < children.size(); ++index) {
                auto* statement = node(children[index]);
                if (statement == nullptr)
                    continue;
                if (statement->kind == typed_pseudocode_ast_node_kind_t::for_statement) {
                    try_rewrite_for_loop_intrinsic(*statement);
                    continue;
                }
                if (statement->kind == typed_pseudocode_ast_node_kind_t::while_statement &&
                    statement->child_ids.size() == 2 && index > 0)
                    try_rewrite_while_loop_intrinsic(*statement, node(children[index - 1]));
            }
        }
    }

    void apply_min_max_idioms()
    {
        std::vector<std::uint64_t> compounds;
        collect_compound_ids(ast_.body_node_id, compounds, 0);
        for (const auto compound_id : compounds) {
            for (std::size_t index = 0;; ++index) {
                const auto* mutable_compound = node(compound_id);
                if (mutable_compound == nullptr || index >= mutable_compound->child_ids.size())
                    break;
                try_rewrite_min_max_at(compound_id, index);
            }
        }
    }

    bool expressions_equivalent(std::uint64_t left_id, std::uint64_t right_id, std::size_t depth) const
    {
        if (depth >= 16 || left_id == right_id)
            return left_id == right_id;
        const auto* left = node(left_id);
        const auto* right = node(right_id);
        if (left == nullptr || right == nullptr || left->kind != right->kind ||
            left->stable_text != right->stable_text || left->child_ids.size() != right->child_ids.size())
            return false;
        for (std::size_t index = 0; index < left->child_ids.size(); ++index) {
            if (!expressions_equivalent(left->child_ids[index], right->child_ids[index], depth + 1))
                return false;
        }
        return true;
    }

    bool extract_simple_assignment(std::uint64_t statement_id,
                                   std::string& target_name,
                                   std::uint64_t& target_node_id,
                                   std::uint64_t& value_node_id) const
    {
        const auto* statement = node(statement_id);
        if (statement == nullptr || statement->kind != typed_pseudocode_ast_node_kind_t::expression_statement ||
            statement->child_ids.size() != 1)
            return false;
        const auto* assignment = node(statement->child_ids[0]);
        if (assignment == nullptr || assignment->kind != typed_pseudocode_ast_node_kind_t::assignment_expression ||
            assignment->stable_text != "=" || assignment->child_ids.size() != 2)
            return false;
        const auto* target = node(assignment->child_ids[0]);
        if (target == nullptr || target->kind != typed_pseudocode_ast_node_kind_t::identifier)
            return false;
        target_name = target->stable_text;
        target_node_id = assignment->child_ids[0];
        value_node_id = assignment->child_ids[1];
        return true;
    }

    void try_rewrite_min_max_at(std::uint64_t compound_id, std::size_t index)
    {
        const auto* compound = node(compound_id);
        if (compound == nullptr || index >= compound->child_ids.size())
            return;
        const auto* if_node = node(compound->child_ids[index]);
        if (if_node == nullptr || if_node->kind != typed_pseudocode_ast_node_kind_t::if_statement ||
            if_node->child_ids.size() != 3)
            return;
        const auto* condition = node(if_node->child_ids[0]);
        if (condition == nullptr || condition->kind != typed_pseudocode_ast_node_kind_t::binary_expression ||
            condition->child_ids.size() != 2)
            return;
        const std::string& op = condition->stable_text;
        if (op != "<" && op != "<=" && op != ">" && op != ">=")
            return;
        const auto* then_compound = node(if_node->child_ids[1]);
        if (then_compound == nullptr || then_compound->kind != typed_pseudocode_ast_node_kind_t::compound_statement ||
            then_compound->child_ids.size() != 1)
            return;
        const auto* else_clause = node(if_node->child_ids[2]);
        if (else_clause == nullptr || else_clause->kind != typed_pseudocode_ast_node_kind_t::else_clause ||
            else_clause->child_ids.size() != 1)
            return;
        const auto* else_compound = node(else_clause->child_ids[0]);
        if (else_compound == nullptr || else_compound->kind != typed_pseudocode_ast_node_kind_t::compound_statement ||
            else_compound->child_ids.size() != 1)
            return;
        std::string then_target;
        std::string else_target;
        std::uint64_t then_target_node = 0;
        std::uint64_t else_target_node = 0;
        std::uint64_t then_value = 0;
        std::uint64_t else_value = 0;
        if (!extract_simple_assignment(then_compound->child_ids[0], then_target, then_target_node, then_value) ||
            !extract_simple_assignment(else_compound->child_ids[0], else_target, else_target_node, else_value) ||
            then_target != else_target)
            return;
        const std::uint64_t left_id = condition->child_ids[0];
        const std::uint64_t right_id = condition->child_ids[1];
        bool forward = false;
        if (expressions_equivalent(then_value, left_id, 0) && expressions_equivalent(else_value, right_id, 0))
            forward = true;
        else if (expressions_equivalent(then_value, right_id, 0) && expressions_equivalent(else_value, left_id, 0))
            forward = false;
        else
            return;
        if (rt_node_has_side_effects(ast_, left_id, id_index_) ||
            rt_node_has_side_effects(ast_, right_id, id_index_))
            return;
        std::string callee_name;
        if (op == "<" || op == "<=")
            callee_name = forward ? "min" : "max";
        else
            callee_name = forward ? "max" : "min";
        const auto* left = node(left_id);
        const auto* right = node(right_id);
        if (left == nullptr || right == nullptr)
            return;
        const std::uint64_t value_type = left->type_id != 0 ? left->type_id : right->type_id;
        const std::uint8_t confidence = (std::min)(condition->confidence, if_node->confidence);
        const auto condition_coordinate = condition->coordinate;
        const auto condition_provenance = condition->provenance;
        const auto if_coordinate = if_node->coordinate;
        const auto if_provenance = if_node->provenance;
        const auto if_type_id = if_node->type_id;
        const auto callee = make_node(typed_pseudocode_ast_node_kind_t::identifier, value_type, {},
            std::move(callee_name), condition_coordinate, confidence, condition_provenance);
        const auto call = make_node(typed_pseudocode_ast_node_kind_t::call_expression, value_type,
            {callee, left_id, right_id}, {}, condition_coordinate, confidence, condition_provenance);
        const auto assignment = make_node(typed_pseudocode_ast_node_kind_t::assignment_expression, value_type,
            {then_target_node, call}, "=", if_coordinate, confidence, if_provenance);
        const auto statement = make_node(typed_pseudocode_ast_node_kind_t::expression_statement, if_type_id,
            {assignment}, {}, if_coordinate, confidence, if_provenance);
        auto* mutable_compound = node(compound_id);
        if (mutable_compound == nullptr || index >= mutable_compound->child_ids.size())
            return;
        mutable_compound->child_ids[index] = statement;
        ++metrics_.min_max_idioms_rewritten;
    }

    void apply_declaration_at_first_use()
    {
        std::unordered_set<std::uint64_t> visited;
        if (subtree_has_jump_target(ast_.body_node_id, visited, 0))
            return;
        apply_declaration_relocation(ast_.body_node_id);
    }

    bool subtree_has_jump_target(std::uint64_t node_id,
                                 std::unordered_set<std::uint64_t>& visited,
                                 std::size_t depth)
    {
        if (depth >= settings_.max_expression_depth || !visited.insert(node_id).second ||
            !consume_work())
            return false;
        const auto* n = node(node_id);
        if (n == nullptr)
            return false;
        if (n->kind == typed_pseudocode_ast_node_kind_t::label_statement ||
            n->kind == typed_pseudocode_ast_node_kind_t::goto_statement)
            return true;
        for (const auto child_id : n->child_ids) {
            if (subtree_has_jump_target(child_id, visited, depth + 1))
                return true;
        }
        return false;
    }

    void apply_declaration_relocation(std::uint64_t compound_id)
    {
        auto* compound = node(compound_id);
        if (compound == nullptr || compound->kind != typed_pseudocode_ast_node_kind_t::compound_statement)
            return;
        auto& children = compound->child_ids;
        std::size_t index = 0;
        while (index < children.size()) {
            const auto* declaration = node(children[index]);
            if (declaration == nullptr || declaration->kind != typed_pseudocode_ast_node_kind_t::declaration ||
                !declaration->child_ids.empty() || declaration->stable_text.empty()) {
                ++index;
                continue;
            }
            const std::string name = declaration->stable_text;
            std::size_t use_index = children.size();
            for (std::size_t scan = index + 1; scan < children.size(); ++scan) {
                if (subtree_contains_identifier(children[scan], name)) {
                    use_index = scan;
                    break;
                }
            }
            if (use_index == children.size() || use_index == index + 1) {
                ++index;
                continue;
            }
            const auto declaration_id = children[index];
            bool merged = false;
            const auto* use_statement = node(children[use_index]);
            if (use_statement != nullptr && use_statement->kind == typed_pseudocode_ast_node_kind_t::expression_statement &&
                use_statement->child_ids.size() == 1) {
                const auto* assignment = node(use_statement->child_ids[0]);
                if (assignment != nullptr && assignment->kind == typed_pseudocode_ast_node_kind_t::assignment_expression &&
                    assignment->stable_text == "=" && assignment->child_ids.size() == 2) {
                    const auto* target = node(assignment->child_ids[0]);
                    if (target != nullptr && target->kind == typed_pseudocode_ast_node_kind_t::identifier &&
                        target->stable_text == name &&
                        !subtree_contains_identifier(assignment->child_ids[1], name)) {
                        auto* mutable_declaration = node(declaration_id);
                        mutable_declaration->child_ids = {assignment->child_ids[1]};
                        children.erase(children.begin() + static_cast<std::ptrdiff_t>(index));
                        children[use_index - 1] = declaration_id;
                        merged = true;
                        ++metrics_.declarations_relocated;
                    }
                }
            }
            if (!merged) {
                children.erase(children.begin() + static_cast<std::ptrdiff_t>(index));
                children.insert(children.begin() + static_cast<std::ptrdiff_t>(use_index - 1), declaration_id);
                ++metrics_.declarations_relocated;
            }
        }
    }

    static bool power_of_two(const std::uint64_t value) noexcept
    {
        return value != 0 && (value & (value - 1)) == 0;
    }

    static std::string idiom_operand_name(const typed_pseudocode_ast_node_t* operand)
    {
        std::string result;
        if (operand != nullptr &&
            (operand->kind == typed_pseudocode_ast_node_kind_t::identifier ||
             operand->kind == typed_pseudocode_ast_node_kind_t::literal))
            result = operand->stable_text;
        if (result.empty())
            return "value";
        bool clean = result.size() <= 24;
        for (const char character : result) {
            if (std::isalnum(static_cast<unsigned char>(character)) == 0 && character != '_') {
                clean = false;
                break;
            }
        }
        return clean ? result : "value";
    }

    std::optional<std::uint64_t> alignment_of_mask(const typed_pseudocode_ast_node_t* mask_node) const
    {
        if (mask_node == nullptr)
            return std::nullopt;
        if (mask_node->kind == typed_pseudocode_ast_node_kind_t::unary_expression &&
            mask_node->stable_text == "~" && mask_node->child_ids.size() == 1) {
            const auto* operand = node(mask_node->child_ids[0]);
            if (operand != nullptr && operand->kind == typed_pseudocode_ast_node_kind_t::literal) {
                const auto value = rt_parse_signed(operand->stable_text);
                if (value && *value >= 1 && power_of_two(static_cast<std::uint64_t>(*value) + 1))
                    return static_cast<std::uint64_t>(*value) + 1;
            }
            return std::nullopt;
        }
        if (mask_node->kind == typed_pseudocode_ast_node_kind_t::literal) {
            const auto value = rt_parse_signed(mask_node->stable_text);
            if (!value)
                return std::nullopt;
            const auto raw = static_cast<std::uint64_t>(*value);
            const auto aligned = ~raw + 1;
            if (aligned > 1 && power_of_two(aligned) && (raw & (aligned - 1)) == 0)
                return aligned;
        }
        return std::nullopt;
    }

    std::optional<std::string> detect_expression_idiom(const typed_pseudocode_ast_node_t& n) const
    {
        if (n.kind != typed_pseudocode_ast_node_kind_t::binary_expression || n.child_ids.size() != 2)
            return std::nullopt;
        const auto* left = node(n.child_ids[0]);
        const auto* right = node(n.child_ids[1]);
        if (left == nullptr || right == nullptr)
            return std::nullopt;
        const std::string& op = n.stable_text;
        if (op == "^" || op == "-") {
            const typed_pseudocode_ast_node_t* combine = nullptr;
            const typed_pseudocode_ast_node_t* mask = nullptr;
            if (op == "^" && left->kind == typed_pseudocode_ast_node_kind_t::binary_expression &&
                left->stable_text == "+" && left->child_ids.size() == 2) {
                combine = left;
                mask = right;
            } else if (op == "-" && left->kind == typed_pseudocode_ast_node_kind_t::binary_expression &&
                       left->stable_text == "^" && left->child_ids.size() == 2) {
                combine = left;
                mask = right;
            }
            if (combine != nullptr && mask != nullptr &&
                mask->kind == typed_pseudocode_ast_node_kind_t::binary_expression && mask->stable_text == ">>" &&
                mask->child_ids.size() == 2) {
                const auto* shift_variable = node(mask->child_ids[0]);
                const auto* shift_amount = node(mask->child_ids[1]);
                const auto amount = shift_amount != nullptr &&
                        shift_amount->kind == typed_pseudocode_ast_node_kind_t::literal
                    ? rt_parse_signed(shift_amount->stable_text)
                    : std::optional<std::int64_t>{};
                if (shift_variable != nullptr &&
                    shift_variable->kind == typed_pseudocode_ast_node_kind_t::identifier && amount &&
                    (*amount == 31 || *amount == 63)) {
                    const auto* combined_variable = node(combine->child_ids[0]);
                    if (combined_variable != nullptr &&
                        combined_variable->kind == typed_pseudocode_ast_node_kind_t::identifier &&
                        combined_variable->stable_text == shift_variable->stable_text &&
                        expressions_equivalent(combine->child_ids[1], n.child_ids[1], 0))
                        return "idiom: abs(" + idiom_operand_name(shift_variable) + ")";
                }
            }
            return std::nullopt;
        }
        if (op != "&")
            return std::nullopt;
        if (const auto aligned = alignment_of_mask(right))
            return "idiom: align_down(" + idiom_operand_name(left) + ", " + std::to_string(*aligned) + ")";
        if (left->kind == typed_pseudocode_ast_node_kind_t::binary_expression && left->stable_text == "+" &&
            left->child_ids.size() == 2) {
            const auto* addend = node(left->child_ids[1]);
            if (addend != nullptr && addend->kind == typed_pseudocode_ast_node_kind_t::literal) {
                const auto value = rt_parse_signed(addend->stable_text);
                if (value && *value > 0 && power_of_two(static_cast<std::uint64_t>(*value) + 1)) {
                    if (const auto aligned = alignment_of_mask(right);
                        aligned && *aligned == static_cast<std::uint64_t>(*value) + 1)
                        return "idiom: align_up(" + idiom_operand_name(node(left->child_ids[0])) + ", " +
                            std::to_string(*aligned) + ")";
                }
            }
        }
        if (right->kind == typed_pseudocode_ast_node_kind_t::binary_expression && right->stable_text == "-" &&
            right->child_ids.size() == 2) {
            const auto* one_node = node(right->child_ids[1]);
            const auto one_value = one_node != nullptr &&
                    one_node->kind == typed_pseudocode_ast_node_kind_t::literal
                ? rt_parse_signed(one_node->stable_text)
                : std::optional<std::int64_t>{};
            if (one_value && *one_value == 1 &&
                expressions_equivalent(n.child_ids[0], right->child_ids[0], 0))
                return "idiom: clear_lowest_bit(" + idiom_operand_name(left) + ")";
        }
        if (right->kind == typed_pseudocode_ast_node_kind_t::unary_expression && right->stable_text == "-" &&
            right->child_ids.size() == 1 && expressions_equivalent(n.child_ids[0], right->child_ids[0], 0))
            return "idiom: lowest_bit(" + idiom_operand_name(left) + ")";
        return std::nullopt;
    }

    static std::string utf8_safe_prefix(const std::string& value, const std::size_t limit)
    {
        if (value.size() <= limit)
            return value;
        std::size_t cut = limit;
        while (cut > 0 && (static_cast<unsigned char>(value[cut]) & 0xC0U) == 0x80U)
            --cut;
        return value.substr(0, cut);
    }

    static std::string escape_comment_bytes(const std::string& content)
    {
        static const char* hex_digits = "0123456789ABCDEF";
        std::string escaped;
        escaped.reserve(content.size() + 8);
        for (const unsigned char character : content) {
            switch (character) {
            case '\\': escaped.append("\\\\"); break;
            case '"': escaped.append("\\\""); break;
            case '\n': escaped.append("\\n"); break;
            case '\r': escaped.append("\\r"); break;
            case '\t': escaped.append("\\t"); break;
            default:
                if (character < 0x20U || character == 0x7FU) {
                    escaped.append("\\x");
                    escaped.push_back(hex_digits[character >> 4]);
                    escaped.push_back(hex_digits[character & 0x0FU]);
                } else {
                    escaped.push_back(static_cast<char>(character));
                }
                break;
            }
        }
        return escaped;
    }

    static std::string truncation_suffix(const bool truncated, const std::uint32_t original_byte_length)
    {
        if (!truncated)
            return {};
        return "...[" + std::to_string(original_byte_length) + " bytes]";
    }

    std::string quoted_string_comment(const std::string& content, const bool truncated,
                                      const std::uint32_t original_byte_length) const
    {
        return "\"" + escape_comment_bytes(utf8_safe_prefix(content, settings_.max_comment_bytes)) +
            truncation_suffix(truncated, original_byte_length) + "\"";
    }

    std::string plain_comment_text(const std::string& text) const
    {
        std::string cleaned;
        cleaned.reserve(text.size());
        for (const char character : text) {
            if (character == '\r' || character == '\n' || character == '\0')
                cleaned.push_back(' ');
            else
                cleaned.push_back(character);
        }
        return utf8_safe_prefix(cleaned, settings_.max_comment_bytes);
    }

    void collect_compound_ids(std::uint64_t node_id, std::vector<std::uint64_t>& out, std::size_t depth)
    {
        if (depth >= settings_.max_expression_depth || !consume_work())
            return;
        const auto* n = node(node_id);
        if (n == nullptr)
            return;
        if (n->kind == typed_pseudocode_ast_node_kind_t::compound_statement)
            out.push_back(node_id);
        for (const auto child_id : n->child_ids)
            collect_compound_ids(child_id, out, depth + 1);
    }

    const decompiler_string_evidence_t* find_string_reference(std::uint64_t node_id)
    {
        std::unordered_set<std::uint64_t> visited;
        return find_string_reference_impl(node_id, visited, 0);
    }

    const decompiler_string_evidence_t* find_string_reference_impl(std::uint64_t node_id,
                                                          std::unordered_set<std::uint64_t>& visited,
                                                          std::size_t depth)
    {
        if (depth >= settings_.max_expression_depth || !visited.insert(node_id).second ||
            !consume_work())
            return nullptr;
        const auto* n = node(node_id);
        if (n == nullptr)
            return nullptr;
        if ((n->kind == typed_pseudocode_ast_node_kind_t::identifier ||
             n->kind == typed_pseudocode_ast_node_kind_t::literal) &&
            !(n->kind == typed_pseudocode_ast_node_kind_t::literal && !n->stable_text.empty() &&
              n->stable_text.front() == '"')) {
            if (const auto* entry = lookup_string_literal(n->stable_text))
                return entry;
        }
        for (const auto child_id : n->child_ids) {
            if (const auto* found = find_string_reference_impl(child_id, visited, depth + 1))
                return found;
        }
        return nullptr;
    }

    std::optional<std::string> find_statement_idiom(std::uint64_t node_id)
    {
        std::unordered_set<std::uint64_t> visited;
        return find_statement_idiom_impl(node_id, visited, 0);
    }

    std::optional<std::string> find_statement_idiom_impl(std::uint64_t node_id,
                                                          std::unordered_set<std::uint64_t>& visited,
                                                          std::size_t depth)
    {
        if (depth >= settings_.max_expression_depth || !visited.insert(node_id).second ||
            !consume_work())
            return std::nullopt;
        const auto* n = node(node_id);
        if (n == nullptr)
            return std::nullopt;
        if (const auto idiom = detect_expression_idiom(*n))
            return idiom;
        for (const auto child_id : n->child_ids) {
            if (const auto found = find_statement_idiom_impl(child_id, visited, depth + 1))
                return found;
        }
        return std::nullopt;
    }

    std::string quoted_string_literal_text(const std::string& content, const bool is_wide,
                                           const bool truncated, const std::uint32_t original_byte_length) const
    {
        return (is_wide ? "L\"" : "\"") +
            escape_comment_bytes(utf8_safe_prefix(content, settings_.max_comment_bytes)) +
            truncation_suffix(truncated, original_byte_length) + "\"";
    }

    bool string_usage_context(const std::uint64_t node_id) const
    {
        const auto parent_it = parent_map_.find(node_id);
        if (parent_it == parent_map_.end())
            return false;
        const auto* parent = node(parent_it->second.first);
        if (parent == nullptr)
            return false;
        if (parent->kind == typed_pseudocode_ast_node_kind_t::cast_expression)
            return true;
        if (parent->kind == typed_pseudocode_ast_node_kind_t::call_expression &&
            parent_it->second.second > 0)
            return true;
        const auto* self = node(node_id);
        if (self != nullptr && self->type_id != 0) {
            const auto type_it = types_.find(self->type_id);
            if (type_it != types_.end() && type_it->second->kind == decompiler_type_kind_t::pointer)
                return true;
        }
        return false;
    }

    void apply_string_literal_substitution()
    {
        if (string_addresses_.empty())
            return;
        for (auto& n : ast_.nodes) {
            if (!consume_work())
                break;
            if (n.kind == typed_pseudocode_ast_node_kind_t::literal &&
                !n.stable_text.empty() && n.stable_text.front() != '"') {
                const auto address = parse_address_candidate(n.stable_text);
                if (!address)
                    continue;
                const auto* entry = lookup_string_address(*address);
                if (entry == nullptr || entry->utf8_content.empty())
                    continue;
                if (!string_usage_context(n.id))
                    continue;
                n.stable_text = quoted_string_literal_text(entry->utf8_content, entry->is_wide,
                    entry->truncated, entry->original_byte_length);
                ++metrics_.string_literals_inlined;
                continue;
            }
            if (n.kind == typed_pseudocode_ast_node_kind_t::identifier &&
                generated_data_identifier(n.stable_text)) {
                const auto address = parse_address_candidate(n.stable_text);
                if (!address)
                    continue;
                const auto* entry = lookup_string_address(*address);
                if (entry == nullptr || entry->utf8_content.empty())
                    continue;
                if (!string_usage_context(n.id))
                    continue;
                n.kind = typed_pseudocode_ast_node_kind_t::literal;
                n.stable_text = quoted_string_literal_text(entry->utf8_content, entry->is_wide,
                    entry->truncated, entry->original_byte_length);
                ++metrics_.string_literals_inlined;
            }
        }
    }

    std::optional<std::string> find_scalar_reference(std::uint64_t node_id)
    {
        std::unordered_set<std::uint64_t> visited;
        return find_scalar_reference_impl(node_id, visited, 0);
    }

    std::optional<std::string> find_scalar_reference_impl(std::uint64_t node_id,
                                                          std::unordered_set<std::uint64_t>& visited,
                                                          std::size_t depth)
    {
        if (depth >= settings_.max_expression_depth || !visited.insert(node_id).second ||
            !consume_work())
            return std::nullopt;
        const auto* n = node(node_id);
        if (n == nullptr)
            return std::nullopt;
        if ((n->kind == typed_pseudocode_ast_node_kind_t::identifier ||
             n->kind == typed_pseudocode_ast_node_kind_t::literal) &&
            (n->kind != typed_pseudocode_ast_node_kind_t::literal || n->stable_text.empty() ||
             n->stable_text.front() != '"')) {
            if (const auto address = parse_address_candidate(n->stable_text)) {
                const auto it = global_scalars_.find(*address);
                if (it != global_scalars_.end()) {
                    const auto* entry = it->second;
                    char buffer[64]{};
                    std::snprintf(buffer, sizeof(buffer), "= %llu (0x%llx)",
                        static_cast<unsigned long long>(entry->value),
                        static_cast<unsigned long long>(entry->value));
                    return std::string(buffer);
                }
            }
        }
        for (const auto child_id : n->child_ids) {
            if (const auto found = find_scalar_reference_impl(child_id, visited, depth + 1))
                return found;
        }
        return std::nullopt;
    }

    void collect_anchor_texts(std::uint64_t node_id,
                              std::vector<std::string>& anchors,
                              std::unordered_set<std::uint64_t>& visited,
                              std::size_t depth)
    {
        if (depth >= settings_.max_expression_depth || !visited.insert(node_id).second ||
            !consume_work())
            return;
        const auto* n = node(node_id);
        if (n == nullptr)
            return;
        if ((n->kind == typed_pseudocode_ast_node_kind_t::identifier ||
             n->kind == typed_pseudocode_ast_node_kind_t::literal ||
             n->kind == typed_pseudocode_ast_node_kind_t::member_expression) &&
            !n->stable_text.empty() &&
            std::find(anchors.begin(), anchors.end(), n->stable_text) == anchors.end())
            anchors.push_back(n->stable_text);
        for (const auto child_id : n->child_ids)
            collect_anchor_texts(child_id, anchors, visited, depth + 1);
    }

    std::vector<std::string> anchor_texts_for(std::uint64_t statement_id)
    {
        std::vector<std::string> anchors;
        std::unordered_set<std::uint64_t> visited;
        collect_anchor_texts(statement_id, anchors, visited, 0);
        return anchors;
    }

    std::uint64_t append_comment_node(std::vector<std::uint64_t>& updated,
                                      std::string text,
                                      const std::uint64_t type_id,
                                      const source_coordinate_t& coordinate,
                                      const decompiler_fact_provenance_t provenance)
    {
        const auto comment = make_node(typed_pseudocode_ast_node_kind_t::comment_statement, type_id, {},
            std::move(text), coordinate, 100, provenance);
        updated.push_back(comment);
        ++comments_injected_;
        return comment;
    }

    void emit_anchored_user_comments(
        std::uint64_t anchor_statement_id,
        const std::unordered_map<std::string, std::vector<std::string>>& comment_map,
        std::vector<std::uint64_t>& updated,
        const std::uint64_t type_id,
        const source_coordinate_t& coordinate,
        std::uint64_t& metric_counter)
    {
        if (comment_map.empty())
            return;
        const auto anchors = anchor_texts_for(anchor_statement_id);
        std::size_t emitted_for_statement = 0;
        for (const auto& anchor : anchors) {
            const auto it = comment_map.find(anchor);
            if (it == comment_map.end())
                continue;
            for (const auto& comment : it->second) {
                if (comments_injected_ >= settings_.max_comments_per_function || emitted_for_statement >= 4)
                    return;
                append_comment_node(updated, plain_comment_text(comment), type_id, coordinate,
                    decompiler_fact_provenance_t::user_overlay);
                ++emitted_for_statement;
                ++metric_counter;
            }
        }
    }

    void emit_rva_user_comments(
        std::uint64_t anchor_statement_id,
        const std::vector<std::pair<std::uint64_t, std::string>>& comment_list,
        std::vector<std::uint64_t>& updated,
        const std::uint64_t type_id,
        const source_coordinate_t& coordinate,
        std::uint64_t& metric_counter)
    {
        if (comment_list.empty())
            return;
        const auto* statement = node(anchor_statement_id);
        if (statement == nullptr || !statement->coordinate.address_range)
            return;
        const std::uint64_t begin = statement->coordinate.address_range->begin.value;
        const std::uint64_t end = statement->coordinate.address_range->end.value;
        if (end <= begin)
            return;
        const auto first = std::lower_bound(comment_list.begin(), comment_list.end(), begin,
            [](const auto& entry, const std::uint64_t address) {
                return entry.first < address;
            });
        std::size_t emitted_for_statement = 0;
        for (auto it = first; it != comment_list.end() && it->first < end; ++it) {
            if (comments_injected_ >= settings_.max_comments_per_function || emitted_for_statement >= 4)
                return;
            append_comment_node(updated, plain_comment_text(it->second), type_id, coordinate,
                decompiler_fact_provenance_t::user_overlay);
            ++emitted_for_statement;
            ++metric_counter;
        }
    }

    void apply_comment_injection()
    {
        comments_injected_ = 0;
        std::vector<std::uint64_t> compounds;
        collect_compound_ids(ast_.body_node_id, compounds, 0);
        for (const auto compound_id : compounds) {
            if (comments_injected_ >= settings_.max_comments_per_function)
                break;
            inject_comments_in_compound(compound_id);
        }
    }

    void inject_comments_in_compound(std::uint64_t compound_id)
    {
        const auto* compound = node(compound_id);
        if (compound == nullptr || compound->kind != typed_pseudocode_ast_node_kind_t::compound_statement)
            return;
        const auto original = compound->child_ids;
        std::vector<std::uint64_t> updated;
        updated.reserve(original.size());
        for (std::size_t index = 0; index < original.size(); ++index) {
            const auto statement_id = original[index];
            const auto* statement = node(statement_id);
            if (statement == nullptr) {
                updated.push_back(statement_id);
                continue;
            }
            const auto statement_type_id = statement->type_id;
            const auto statement_coordinate = statement->coordinate;
            if (index == 0 && settings_.enable_user_comment_injection) {
                emit_anchored_user_comments(statement_id, user_comments_before_, updated,
                    statement_type_id, statement_coordinate, metrics_.user_comments_injected);
            }
            if (settings_.enable_user_comment_injection)
                emit_rva_user_comments(statement_id, rva_comments_before_, updated,
                    statement_type_id, statement_coordinate, metrics_.user_comments_injected);
            updated.push_back(statement_id);
            if (comments_injected_ < settings_.max_comments_per_function) {
                std::string trailing;
                if (settings_.enable_string_comment_injection && !string_literals_.empty()) {
                    if (const auto* entry = find_string_reference(statement_id)) {
                        trailing = quoted_string_comment(entry->utf8_content, entry->truncated,
                            entry->original_byte_length);
                        ++metrics_.string_comments_injected;
                    }
                }
                if (trailing.empty() && settings_.enable_string_comment_injection &&
                    !global_scalars_.empty()) {
                    if (const auto scalar = find_scalar_reference(statement_id)) {
                        trailing = *scalar;
                        ++metrics_.global_scalar_comments_injected;
                    }
                }
                if (trailing.empty() && settings_.enable_idiom_recognition) {
                    if (const auto idiom = find_statement_idiom(statement_id)) {
                        trailing = *idiom;
                        ++metrics_.idioms_recognized;
                    }
                }
                if (!trailing.empty())
                    append_comment_node(updated, std::move(trailing), statement_type_id, statement_coordinate,
                        decompiler_fact_provenance_t::provider_semantics);
            }
            if (settings_.enable_user_comment_injection) {
                emit_anchored_user_comments(statement_id, user_comments_after_, updated,
                    statement_type_id, statement_coordinate, metrics_.user_comments_injected);
                emit_rva_user_comments(statement_id, rva_comments_after_, updated,
                    statement_type_id, statement_coordinate, metrics_.user_comments_injected);
                if (index + 1 < original.size())
                    emit_anchored_user_comments(original[index + 1], user_comments_before_, updated,
                        statement_type_id, statement_coordinate, metrics_.user_comments_injected);
            }
        }
        auto* mutable_compound = node(compound_id);
        mutable_compound->child_ids = std::move(updated);
    }

    void compact_ast()
    {
        std::unordered_set<std::uint64_t> reachable;
        mark_reachable(ast_.root_node_id, reachable);
        std::size_t original_size = ast_.nodes.size();
        std::vector<typed_pseudocode_ast_node_t> new_nodes;
        new_nodes.reserve(reachable.size());
        for (auto& n : ast_.nodes) {
            if (reachable.find(n.id) != reachable.end())
                new_nodes.push_back(std::move(n));
        }
        const std::size_t removed = original_size - new_nodes.size();
        if (removed > 0) {
            ast_.nodes = std::move(new_nodes);
            metrics_.nodes_removed += removed;
            build_index();
        }
    }

    void mark_reachable(std::uint64_t node_id, std::unordered_set<std::uint64_t>& reachable) const
    {
        if (reachable.find(node_id) != reachable.end())
            return;
        const auto it = id_index_.find(node_id);
        if (it == id_index_.end())
            return;
        reachable.insert(node_id);
        const auto& n = ast_.nodes[it->second];
        for (const auto child_id : n.child_ids)
            mark_reachable(child_id, reachable);
    }
};

}

bool pseudocode_baseline_capture_result_t::succeeded() const noexcept
{
    return capture.has_value();
}

bool pseudocode_readability_result_t::succeeded() const noexcept
{
    return report.has_value();
}

pseudocode_baseline_capture_result_t capture_pseudocode_readability_baseline(
    const pseudocode_baseline_capture_request_t& request,
    const pseudocode_readability_limits_t& limits)
{
    pseudocode_baseline_capture_result_t result;
    result.diagnostics = request.diagnostics;
    const std::uint32_t ordinal = next_ordinal(result.diagnostics);
    if (!valid_limits(limits) ||
        (request.provider != pseudocode_baseline_provider_t::ghidra_printc &&
         request.provider != pseudocode_baseline_provider_t::aida_current) ||
        request.provider_build_hash.empty() || request.fixture_set_hash.empty() ||
        !visible_text(request.fixture_id) || request.fixture_id.size() > limits.max_fixture_id_bytes ||
        request.rendered_text.empty() || request.rendered_text.size() > limits.max_baseline_bytes ||
        request.diagnostics.size() > limits.max_diagnostics) {
        result.diagnostics.push_back(readability_diagnostic(decompiler_diagnostic_code_t::invalid_contract,
            "decompiler.readability.v2.baseline_contract", ordinal));
        return result;
    }
    try {
        for (const auto& diagnostic : request.diagnostics)
            static_cast<void>(serialize_decompiler_diagnostic(diagnostic));
        pseudocode_baseline_capture_t capture;
        capture.provider = request.provider;
        capture.provider_build_hash = request.provider_build_hash;
        capture.fixture_set_hash = request.fixture_set_hash;
        capture.fixture_id = request.fixture_id;
        capture.rendered_text = request.rendered_text;
        capture.diagnostics = request.diagnostics;
        capture.rendered_text_hash = stable_serialization_hash(capture.rendered_text);
        capture.capture_hash = baseline_capture_hash(capture);
        result.capture = std::move(capture);
    } catch (const std::exception&) {
        result.diagnostics.push_back(readability_diagnostic(decompiler_diagnostic_code_t::invalid_contract,
            "decompiler.readability.v2.baseline_diagnostic", ordinal));
    }
    return result;
}

pseudocode_readability_result_t analyze_pseudocode_readability(
    const typed_pseudocode_ast_v2_t* ast,
    const decompiler_document_t* document,
    const pseudocode_readability_request_t& request)
{
    pseudocode_readability_result_t result;
    if (document != nullptr)
        result.diagnostics = document->diagnostics;
    std::uint32_t ordinal = next_ordinal(result.diagnostics);
    if (ast == nullptr || document == nullptr) {
        result.diagnostics.push_back(readability_diagnostic(decompiler_diagnostic_code_t::invalid_contract,
            "decompiler.readability.v2.ast_and_document_required", ordinal));
        return result;
    }
    if (!valid_limits(request.limits)) {
        result.diagnostics.push_back(readability_diagnostic(decompiler_diagnostic_code_t::invalid_contract,
            "decompiler.readability.v2.limits", ordinal));
        return result;
    }
    if (ast->nodes.size() > request.limits.max_ast_nodes ||
        document->rendered_text.size() > request.limits.max_document_bytes ||
        document->tokens.size() > request.limits.max_tokens ||
        document->source_maps.size() > request.limits.max_source_maps ||
        document->diagnostics.size() > request.limits.max_diagnostics ||
        document->unknowns.size() > request.limits.max_unknowns) {
        result.diagnostics.push_back(readability_diagnostic(decompiler_diagnostic_code_t::resource_limit,
            "decompiler.readability.v2.resource_limit", ordinal));
        return result;
    }
    if (!typed_ast_has_proven_function_body(*ast)) {
        result.diagnostics.push_back(readability_diagnostic(
            decompiler_diagnostic_code_t::malformed_ast,
            "decompiler.readability.v2.fabricated_body", ordinal));
        return result;
    }
    const auto ast_validation = validate_typed_pseudocode_ast(*ast);
    const auto document_validation = validate_decompiler_document(*document);
    if (!ast_validation.valid() || !document_validation.valid()) {
        result.diagnostics.insert(result.diagnostics.end(), ast_validation.diagnostics.begin(), ast_validation.diagnostics.end());
        result.diagnostics.insert(result.diagnostics.end(), document_validation.diagnostics.begin(), document_validation.diagnostics.end());
        return result;
    }
    if (!(ast->entity == document->entity) || document->ast_hash != stable_serialization_hash(*ast) ||
        stable_serialization_hash(document->ast) != stable_serialization_hash(*ast)) {
        result.diagnostics.push_back(readability_diagnostic(decompiler_diagnostic_code_t::malformed_document,
            "decompiler.readability.v2.ast_document_binding", ordinal));
        return result;
    }
    std::size_t mapped_bytes = 0;
    const bool source_map_complete = complete_source_map(*document, mapped_bytes);
    if (request.require_complete_source_map && !source_map_complete) {
        result.diagnostics.push_back(readability_diagnostic(decompiler_diagnostic_code_t::source_map_rejected,
            "decompiler.readability.v2.source_map_coverage", ordinal));
        return result;
    }
    auto traversal = traverse_ast(*ast, request.limits);
    if (!traversal.valid) {
        result.diagnostics.push_back(readability_diagnostic(
            traversal.error_key == "decompiler.readability.v2.nesting_limit" ||
                    traversal.error_key == "decompiler.readability.v2.traversal_limit"
                ? decompiler_diagnostic_code_t::resource_limit
                : decompiler_diagnostic_code_t::malformed_ast,
            std::move(traversal.error_key), ordinal));
        return result;
    }
    pseudocode_readability_report_t report;
    report.entity = document->entity;
    report.metrics = traversal.metrics;
    report.ast_node_count = ast->nodes.size();
    report.document_bytes = document->rendered_text.size();
    report.source_mapped_bytes = mapped_bytes;
    report.source_map_coverage_ratio = document->rendered_text.empty()
        ? 0.0 : static_cast<double>(mapped_bytes) / static_cast<double>(document->rendered_text.size());
    report.mean_confidence = traversal.visited_nodes == 0
        ? 0.0 : static_cast<double>(traversal.confidence_sum) / static_cast<double>(traversal.visited_nodes) / 100.0;
    report.minimum_confidence = traversal.visited_nodes == 0 ? 0 : traversal.minimum_confidence;
    report.explicit_unknown_ratio = ast->nodes.empty()
        ? 0.0 : static_cast<double>(document->unknowns.size()) / static_cast<double>(ast->nodes.size());
    report.ast_hash = stable_serialization_hash(*ast);
    report.document_hash = stable_serialization_hash(*document);
    report.source_map_hash = hash_decompiler_source_maps(document->source_maps);
    report.diagnostics = document->diagnostics;
    report.unknowns = document->unknowns;
    if (request.baseline) {
        auto baseline = capture_pseudocode_readability_baseline(*request.baseline, request.limits);
        if (!baseline.succeeded()) {
            result.diagnostics.insert(result.diagnostics.end(), baseline.diagnostics.begin(), baseline.diagnostics.end());
            return result;
        }
        report.baseline = std::move(*baseline.capture);
    }
    result.report = std::move(report);
    return result;
}

bool readability_transform_result_t::succeeded() const noexcept
{
    return transformed;
}

bool readability_transforms_enabled(const readability_transform_settings_t& settings) noexcept
{
    return settings.enable_variable_renaming || settings.enable_expression_simplification ||
        settings.enable_temporary_coalescing || settings.enable_loop_counter_naming ||
        settings.enable_api_call_naming || settings.enable_type_based_naming ||
        settings.enable_string_reference_naming || settings.enable_constant_folding ||
        settings.enable_identity_simplification || settings.enable_cast_simplification ||
        settings.enable_comparison_normalization || settings.enable_compound_assignment_marking ||
        settings.enable_double_negation_simplification || settings.enable_single_use_inlining ||
        settings.enable_copy_propagation || settings.enable_dead_store_elimination ||
        settings.enable_member_name_propagation || settings.enable_min_max_idioms ||
        settings.enable_idiom_recognition || settings.enable_declaration_at_first_use ||
        settings.enable_string_comment_injection || settings.enable_user_comment_injection ||
        settings.enable_string_literal_substitution || settings.enable_cast_idiom_folding ||
        settings.enable_bit_operation_idioms || settings.enable_loop_intrinsic_idioms ||
        settings.enable_magic_division_recognition;
}

readability_transform_settings_t to_rt_settings(const readability_transform_settings_t& settings) noexcept
{
    readability_transform_settings_t result = settings;
    if (result.max_transform_iterations < 1)
        result.max_transform_iterations = 1;
    if (result.max_transform_iterations > 16)
        result.max_transform_iterations = 16;
    if (result.max_expression_depth < 16)
        result.max_expression_depth = 16;
    if (result.max_expression_depth > 4096)
        result.max_expression_depth = 4096;
    if (result.max_comment_bytes < 16)
        result.max_comment_bytes = 16;
    if (result.max_comment_bytes > 512)
        result.max_comment_bytes = 512;
    if (result.max_comments_per_function < 1)
        result.max_comments_per_function = 1;
    if (result.max_comments_per_function > 4096)
        result.max_comments_per_function = 4096;
    if (result.max_transform_nodes < 10000)
        result.max_transform_nodes = 10000;
    if (result.max_transform_nodes > 500000)
        result.max_transform_nodes = 500000;
    if (result.max_transform_work_units < 65536)
        result.max_transform_work_units = 65536;
    if (result.max_transform_work_units > (std::size_t{1} << 26))
        result.max_transform_work_units = (std::size_t{1} << 26);
    return result;
}

readability_transform_result_t apply_readability_transforms(
    typed_pseudocode_ast_v2_t& ast,
    const type_graph_t& type_graph,
    const readability_transform_settings_t& settings)
{
    static const decompiler_render_evidence_t k_empty_evidence{};
    rt_transformer_t transformer(ast, type_graph, settings, k_empty_evidence);
    return transformer.run();
}

readability_transform_result_t apply_readability_transforms(
    typed_pseudocode_ast_v2_t& ast,
    const type_graph_t& type_graph,
    const readability_transform_settings_t& settings,
    const decompiler_render_evidence_t& evidence)
{
    rt_transformer_t transformer(ast, type_graph, settings, evidence);
    return transformer.run();
}

pseudocode_readability_result_t analyze_pseudocode_readability(
    const typed_pseudocode_ast_v2_t& ast,
    const decompiler_document_t& document,
    const pseudocode_readability_request_t& request)
{
    return analyze_pseudocode_readability(&ast, &document, request);
}

namespace {

bool local_rename_c_keyword(std::string_view name) noexcept
{
    static constexpr std::string_view k_keywords[] = {
        "auto", "break", "case", "char", "const", "continue", "default", "do", "double",
        "else", "enum", "extern", "float", "for", "goto", "if", "inline", "int", "long",
        "register", "restrict", "return", "short", "signed", "sizeof", "static", "struct",
        "switch", "typedef", "union", "unsigned", "void", "volatile", "while",
        "_Alignas", "_Alignof", "_Atomic", "_Bool", "_Complex", "_Generic", "_Imaginary",
        "_Noreturn", "_Static_assert", "_Thread_local",
        "__int8", "__int16", "__int32", "__int64", "__declspec", "__cdecl", "__stdcall",
        "__fastcall", "__thiscall", "__vectorcall", "__forceinline", "__unaligned",
        "memset", "memcpy", "memmove", "_rotl", "_rotr", "_byteswap_ulong",
        "_byteswap_uint64", "_byteswap_ushort", "min", "max",
    };
    for (const auto keyword : k_keywords) {
        if (name == keyword)
            return true;
    }
    return false;
}

bool local_rename_identifier_valid(std::string_view name) noexcept
{
    if (name.empty() || name.size() > 128)
        return false;
    const auto letter = [](const char value) {
        return (value >= 'a' && value <= 'z') || (value >= 'A' && value <= 'Z') || value == '_';
    };
    if (!letter(name.front()))
        return false;
    return std::all_of(name.begin() + 1, name.end(), [&](const char value) {
        return letter(value) || (value >= '0' && value <= '9');
    });
}

decompiler_diagnostic_t local_rename_diagnostic(std::string key, const std::uint32_t ordinal)
{
    decompiler_diagnostic_t result;
    result.severity = decompiler_diagnostic_severity_t::warning;
    result.code = decompiler_diagnostic_code_t::invalid_contract;
    result.localization_key = std::move(key);
    result.confidence = 100;
    result.ordinal = ordinal;
    return result;
}

}

pseudocode_local_rename_result_t apply_pseudocode_local_rename(
    typed_pseudocode_ast_v2_t& ast,
    const type_graph_t& type_graph,
    std::string_view old_name,
    std::string_view new_name)
{
    static_cast<void>(type_graph);
    pseudocode_local_rename_result_t result;
    std::uint32_t ordinal = 1;
    const auto reject = [&result, &ordinal](const char* key) {
        result.diagnostics.push_back(local_rename_diagnostic(key, ordinal++));
        return result;
    };
    if (ast.nodes.empty() || old_name.empty() || old_name == new_name)
        return reject("readability.local_rename.identity");
    if (!local_rename_identifier_valid(old_name) || !local_rename_identifier_valid(new_name))
        return reject("readability.local_rename.identifier");
    if (local_rename_c_keyword(new_name))
        return reject("readability.local_rename.keyword");
    std::unordered_map<std::uint64_t, std::size_t> index;
    index.reserve(ast.nodes.size());
    for (std::size_t node_index = 0; node_index < ast.nodes.size(); ++node_index)
        index.emplace(ast.nodes[node_index].id, node_index);
    const auto root = index.find(ast.root_node_id);
    if (root == index.end())
        return reject("readability.local_rename.root");
    if (ast.nodes[root->second].stable_text == old_name)
        return reject("readability.local_rename.function");
    std::size_t matches = 0;
    for (const auto& node_value : ast.nodes) {
        if (node_value.stable_text.empty())
            continue;
        if (node_value.kind == typed_pseudocode_ast_node_kind_t::member_expression &&
            node_value.stable_text == old_name)
            return reject("readability.local_rename.member_selector");
        if (node_value.stable_text == new_name &&
            (node_value.kind == typed_pseudocode_ast_node_kind_t::declaration ||
             node_value.kind == typed_pseudocode_ast_node_kind_t::identifier ||
             node_value.kind == typed_pseudocode_ast_node_kind_t::member_expression ||
             node_value.kind == typed_pseudocode_ast_node_kind_t::function_definition))
            return reject("readability.local_rename.collision");
        if ((node_value.kind == typed_pseudocode_ast_node_kind_t::declaration ||
             node_value.kind == typed_pseudocode_ast_node_kind_t::identifier) &&
            node_value.stable_text == old_name)
            ++matches;
    }
    if (matches == 0)
        return reject("readability.local_rename.absent");
    std::unordered_map<std::uint64_t, std::uint64_t> parents;
    parents.reserve(ast.nodes.size());
    for (const auto& node_value : ast.nodes) {
        for (const auto child_id : node_value.child_ids)
            parents.emplace(child_id, node_value.id);
    }
    for (const auto& node_value : ast.nodes) {
        if (node_value.kind != typed_pseudocode_ast_node_kind_t::identifier ||
            node_value.stable_text != old_name)
            continue;
        const auto parent = parents.find(node_value.id);
        if (parent == parents.end())
            continue;
        const auto parent_node = index.find(parent->second);
        if (parent_node == index.end())
            continue;
        const auto& parent_value = ast.nodes[parent_node->second];
        if (parent_value.kind == typed_pseudocode_ast_node_kind_t::call_expression &&
            !parent_value.child_ids.empty() && parent_value.child_ids.front() == node_value.id)
            return reject("readability.local_rename.resolved_callee");
    }
    std::uint64_t renamed = 0;
    for (auto& node_value : ast.nodes) {
        if ((node_value.kind == typed_pseudocode_ast_node_kind_t::declaration ||
             node_value.kind == typed_pseudocode_ast_node_kind_t::identifier) &&
            node_value.stable_text == old_name) {
            node_value.stable_text = std::string(new_name);
            ++renamed;
        }
    }
    result.applied = renamed != 0;
    result.nodes_renamed = renamed;
    return result;
}

}
