#include "pseudocode_readability.hpp"

#include <algorithm>
#include <array>
#include <cctype>
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
        {"WSASocketW", {"af", "type", "protocol", "protocol_info", "group", "flags"}},
        {"socket", {"af", "type", "protocol"}},
        {"connect", {"sock", "address", "address_len"}},
        {"send", {"sock", "buffer", "length", "flags"}},
        {"recv", {"sock", "buffer", "length", "flags"}},
        {"bind", {"sock", "address", "address_len"}},
        {"listen", {"sock", "backlog"}},
        {"accept", {"sock", "address", "address_len"}},
        {"closesocket", {"sock"}},
    };
    return table;
}

std::optional<std::string> rt_suggest_api_name(const std::string& api_name, std::size_t param_index)
{
    const auto& table = rt_api_param_names();
    const auto it = table.find(api_name);
    if (it == table.end())
        return std::nullopt;
    if (param_index >= it->second.size())
        return std::nullopt;
    return it->second[param_index];
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

constexpr std::size_t k_max_transform_nodes = 10000;
constexpr std::size_t k_max_parent_chain_depth = 512;

class rt_transformer_t {
public:
    rt_transformer_t(
        typed_pseudocode_ast_v2_t& ast,
        const type_graph_t& type_graph,
        const readability_transform_settings_t& settings)
        : ast_(ast), type_graph_(type_graph), settings_(settings)
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
        if (ast_.nodes.size() > k_max_transform_nodes) {
            result.diagnostics.push_back(rt_make_diagnostic(
                decompiler_diagnostic_code_t::resource_limit,
                "readability.node_limit_exceeded", std::nullopt));
            return result;
        }
        build_index();
        collect_variable_info(ast_.root_node_id, 0, false, false);
        if (settings_.enable_loop_counter_naming)
            detect_loop_counters(ast_.root_node_id, 0);
        if (settings_.enable_api_call_naming)
            detect_api_calls(ast_.root_node_id);
        if (settings_.enable_string_reference_naming)
            detect_string_references(ast_.root_node_id);
        if (settings_.enable_type_based_naming)
            compute_type_based_names();
        compute_final_suggested_names();

        if (settings_.enable_variable_renaming && !variables_.empty())
            apply_renaming();

        for (std::size_t iteration = 0; iteration < settings_.max_transform_iterations; ++iteration) {
            bool changed = false;
            if (settings_.enable_expression_simplification)
                changed = simplify_expressions(ast_.root_node_id, 0, false) || changed;
            if (settings_.enable_temporary_coalescing) {
                definitions_.clear();
                uses_.clear();
                std::unordered_set<std::uint64_t> def_use_visited;
                collect_def_use(ast_.root_node_id, 0, def_use_visited);
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

        compact_ast();

        result.transformed = metrics_.variables_renamed > 0 ||
            metrics_.constants_folded > 0 || metrics_.identities_simplified > 0 ||
            metrics_.casts_simplified > 0 || metrics_.double_negations_simplified > 0 ||
            metrics_.comparisons_normalized > 0 || metrics_.compound_assignments_marked > 0 ||
            metrics_.temporaries_inlined > 0 || metrics_.copies_propagated > 0 ||
            metrics_.dead_stores_eliminated > 0 || metrics_.nodes_removed > 0;
        result.metrics = metrics_;
        result.diagnostics = std::move(diagnostics_);
        return result;
    }

private:
    typed_pseudocode_ast_v2_t& ast_;
    const type_graph_t& type_graph_;
    const readability_transform_settings_t settings_;
    readability_transform_metrics_t metrics_;
    std::vector<decompiler_diagnostic_t> diagnostics_;
    std::unordered_map<std::uint64_t, std::size_t> id_index_;
    std::unordered_map<std::uint64_t, std::pair<std::uint64_t, std::size_t>> parent_map_;
    std::unordered_map<std::uint64_t, const decompiler_type_node_t*> types_;
    std::map<std::string, rt_variable_info_t> variables_;
    std::vector<rt_def_use_entry_t> definitions_;
    std::unordered_map<std::string, std::vector<std::uint64_t>> uses_;
    std::uint32_t diagnostic_ordinal_ = 1;

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
            !visited.insert(node_id).second)
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
            !visited.insert(node_id).second)
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
            !visited.insert(node_id).second)
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
            !visited.insert(node_id).second)
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
            !visited.insert(node_id).second)
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
            !visited.insert(node_id).second)
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
                        const auto suggested = rt_suggest_api_name(callee->stable_text, i - 1);
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
            !visited.insert(node_id).second)
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
                    std::string first_word;
                    for (const char c : content) {
                        if (std::isalnum(static_cast<unsigned char>(c)) != 0 || c == '_')
                            first_word.push_back(c);
                        else if (!first_word.empty())
                            break;
                    }
                    if (first_word.size() > 0) {
                        auto camel = rt_to_camel_case(first_word);
                        if (!camel.empty()) {
                            auto it = variables_.find(n->stable_text);
                            if (it != variables_.end())
                                it->second.string_suggested_name = camel;
                        }
                    }
                }
            }
        }
        for (const auto child_id : n->child_ids)
            detect_string_references_impl(child_id, visited, depth + 1);
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
            !visited.insert(node_id).second)
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
        return false;
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
        if (!visited.insert(node_id).second)
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

    std::size_t count_definitions(const std::string& var) const
    {
        std::size_t count = 0;
        for (const auto& def : definitions_)
            if (def.variable == var)
                ++count;
        return count;
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
        if (compound_id == ast_.body_node_id && compound->child_ids.size() <= 1)
            return false;
        compound->child_ids.erase(it);
        return true;
    }

    bool apply_single_use_inlining()
    {
        bool changed = false;
        for (const auto& def : definitions_) {
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
            ++metrics_.temporaries_inlined;
            changed = true;
        }
        return changed;
    }

    bool apply_copy_propagation()
    {
        bool changed = false;
        for (const auto& def : definitions_) {
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
            if (processed.find(def.variable) != processed.end())
                continue;
            processed.insert(def.variable);
            if (count_uses(def.variable) > 0)
                continue;
            std::size_t def_count = count_definitions(def.variable);
            if (def_count == 0)
                continue;
            bool all_safe = true;
            for (const auto& d : definitions_) {
                if (d.variable == def.variable && d.has_side_effects) {
                    all_safe = false;
                    break;
                }
            }
            if (!all_safe)
                continue;
            for (const auto& d : definitions_) {
                if (d.variable != def.variable)
                    continue;
                remove_statement_from_compound(d.statement_id);
                ++metrics_.dead_stores_eliminated;
                changed = true;
            }
        }
        return changed;
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
        settings.enable_copy_propagation || settings.enable_dead_store_elimination;
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
    return result;
}

readability_transform_result_t apply_readability_transforms(
    typed_pseudocode_ast_v2_t& ast,
    const type_graph_t& type_graph,
    const readability_transform_settings_t& settings)
{
    rt_transformer_t transformer(ast, type_graph, settings);
    return transformer.run();
}

pseudocode_readability_result_t analyze_pseudocode_readability(
    const typed_pseudocode_ast_v2_t& ast,
    const decompiler_document_t& document,
    const pseudocode_readability_request_t& request)
{
    return analyze_pseudocode_readability(&ast, &document, request);
}

}
