#include <algorithm>
#include <cctype>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <iterator>
#include <stdexcept>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace {

struct cmake_call_t {
    std::string command;
    std::vector<std::string> arguments;
};

std::string read_file(const std::filesystem::path& path)
{
    std::ifstream input(path, std::ios::binary);
    if (!input)
        throw std::runtime_error("unable to read " + path.string());
    return {std::istreambuf_iterator<char>(input), std::istreambuf_iterator<char>()};
}

std::string lowercase(std::string value)
{
    std::transform(value.begin(), value.end(), value.begin(), [](unsigned char value) {
        return static_cast<char>(std::tolower(value));
    });
    return value;
}

bool equals_ignore_case(std::string_view left, std::string_view right)
{
    return lowercase(std::string(left)) == lowercase(std::string(right));
}

void require_contains(const std::string& text, std::string_view needle, const std::filesystem::path& source)
{
    if (text.find(needle) == std::string::npos)
        throw std::runtime_error(source.string() + " is missing " + std::string(needle));
}

void require_absent(const std::string& text, std::string_view needle, const std::filesystem::path& source)
{
    if (text.find(needle) != std::string::npos)
        throw std::runtime_error(source.string() + " contains prohibited " + std::string(needle));
}

std::string extract_json_string_value(const std::string& json, std::string_view key)
{
    const std::string needle = "\"" + std::string(key) + "\"";
    std::size_t search_from = 0;
    while (true) {
        auto pos = json.find(needle, search_from);
        if (pos == std::string::npos)
            throw std::runtime_error("JSON is missing string key " + std::string(key));
        pos += needle.size();
        while (pos < json.size() && (json[pos] == ' ' || json[pos] == ':' || json[pos] == '\t' || json[pos] == '\n' || json[pos] == '\r'))
            ++pos;
        if (pos < json.size() && json[pos] == '"') {
            ++pos;
            std::string value;
            while (pos < json.size() && json[pos] != '"') {
                if (json[pos] == '\\' && pos + 1 < json.size())
                    ++pos;
                value.push_back(json[pos++]);
            }
            return value;
        }
        search_from = pos;
    }
}

long long extract_json_number_value(const std::string& json, std::string_view key)
{
    const std::string needle = "\"" + std::string(key) + "\"";
    std::size_t search_from = 0;
    while (true) {
        auto pos = json.find(needle, search_from);
        if (pos == std::string::npos)
            throw std::runtime_error("JSON is missing numeric key " + std::string(key));
        pos += needle.size();
        while (pos < json.size() && (json[pos] == ' ' || json[pos] == ':' || json[pos] == '\t' || json[pos] == '\n' || json[pos] == '\r'))
            ++pos;
        if (pos < json.size() && (std::isdigit(static_cast<unsigned char>(json[pos])) || json[pos] == '-')) {
            std::string number;
            while (pos < json.size() && (std::isdigit(static_cast<unsigned char>(json[pos])) || json[pos] == '-'))
                number.push_back(json[pos++]);
            return std::stoll(number);
        }
        search_from = pos;
    }
}

bool is_valid_sha256_hex(const std::string& value)
{
    if (value.size() != 64)
        return false;
    return std::all_of(value.begin(), value.end(), [](char c) {
        return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f');
    });
}

bool is_valid_hash_field(const std::string& value)
{
    return value.empty() || is_valid_sha256_hex(value);
}

std::vector<std::string> parse_gitignore_rules(std::string_view source)
{
    std::vector<std::string> rules;
    std::size_t line_begin = 0;
    while (line_begin < source.size()) {
        const auto line_end = source.find('\n', line_begin);
        auto rule = std::string(source.substr(line_begin, line_end - line_begin));
        if (!rule.empty() && rule.back() == '\r')
            rule.pop_back();
        if (!rule.empty() && rule.front() != '#')
            rules.push_back(std::move(rule));
        if (line_end == std::string_view::npos)
            break;
        line_begin = line_end + 1;
    }
    return rules;
}

std::size_t require_gitignore_rule_after(const std::vector<std::string>& rules, std::string_view expected,
    std::size_t begin, const std::filesystem::path& source)
{
    for (std::size_t index = begin; index < rules.size(); ++index) {
        if (rules[index] == expected)
            return index;
    }
    throw std::runtime_error(source.string() + " is missing required gitignore rule " + std::string(expected));
}

const std::vector<std::string>& approved_gitignore_negations()
{
    static const std::vector<std::string> rules{
        "!/src/", "!/server/", "!/tools/", "!/cmake/", "!/docs/", "!.gitignore", "!.aider*",
        "!CMakeLists.txt", "!CLAUDE.md", "!AGENTS.md", "!build-host.ps1", "!build-host.cmd",
        "!CMakePresets.json", "!/licenses/", "!/licenses/c03/", "!/licenses/c03/**", "!/packaging/",
        "!/packaging/c03_worker_manifest.schema.json", "!/packaging/c03_worker_manifest.lock.json"};
    return rules;
}

bool is_approved_gitignore_negation(std::string_view rule)
{
    const auto& approved = approved_gitignore_negations();
    return std::find(approved.begin(), approved.end(), std::string(rule)) != approved.end();
}

void verify_gitignore_negation_semantics(const std::filesystem::path& source)
{
    for (const auto& counterexample : std::vector<std::pair<std::string, bool>>{
             {"!/licenses/", true}, {"!/licenses/c03/", true}, {"!/licenses/c03/**", true},
             {"!/packaging/", true}, {"!/packaging/c03_worker_manifest.schema.json", true},
             {"!/packaging/c03_worker_manifest.lock.json", true}, {"!licenses/unrelated.txt", false},
             {"!licenses/c03/**", false}, {"!packaging/unrelated.json", false}, {"!/licenses/ ", false},
             {"!/licenses/c03/** ", false}, {"!/LICENSES/", false},
             {"!/packaging/ ", false}, {"!/packaging/c03_worker_manifest.schema.json ", false},
             {"!/licenses/**", false},
             {"!/licenses/c03/*", false}, {"!/licenses/c03/private/**", false},
             {"!/licenses/c03/**/unrelated.txt", false}, {"!/packaging/**", false},
             {"!/packaging/*.json", false}, {"!/packaging/c03_worker_manifest.*", false},
             {"!/packaging/c03_worker_manifest.schema.json/**", false}, {"!*.json", false}}) {
        if (is_approved_gitignore_negation(counterexample.first) != counterexample.second)
            throw std::runtime_error(source.string() + " has an invalid gitignore negation semantic check for " +
                counterexample.first);
    }
}

void verify_gitignore_policy(const std::filesystem::path& root)
{
    const auto source = root / ".gitignore";
    const auto rules = parse_gitignore_rules(read_file(source));
    std::size_t position = 0;
    for (const auto& expected : {"!/licenses/", "/licenses/*", "!/licenses/c03/", "!/licenses/c03/**",
             "!/packaging/", "/packaging/*", "!/packaging/c03_worker_manifest.schema.json",
             "!/packaging/c03_worker_manifest.lock.json"})
        position = require_gitignore_rule_after(rules, expected, position, source) + 1;

    verify_gitignore_negation_semantics(source);
    for (const auto& rule : rules) {
        if (!rule.empty() && rule.front() == '!' && !is_approved_gitignore_negation(rule))
            throw std::runtime_error(source.string() + " contains an unapproved negation rule " + rule);
    }
}

bool is_c03_link_token_character(char value)
{
    return (value >= 'a' && value <= 'z') || (value >= '0' && value <= '9');
}

bool contains_forbidden_link_token(std::string_view link, std::string_view token)
{
    const auto normalized_link = lowercase(std::string(link));
    const auto normalized_token = lowercase(std::string(token));
    std::size_t position = normalized_link.find(normalized_token);
    while (position != std::string::npos) {
        const auto token_end = position + normalized_token.size();
        const bool leading_boundary = position == 0 || !is_c03_link_token_character(normalized_link[position - 1]);
        const bool trailing_boundary = token_end == normalized_link.size() ||
            !is_c03_link_token_character(normalized_link[token_end]);
        if (leading_boundary && trailing_boundary)
            return true;
        position = normalized_link.find(normalized_token, position + 1);
    }
    return false;
}

bool contains_forbidden_link_token(std::string_view link)
{
    for (const auto* token : {"lmdb", "unicorn", "remill"}) {
        if (contains_forbidden_link_token(link, token))
            return true;
    }
    return false;
}

void verify_forbidden_link_semantics(const std::filesystem::path& source)
{
    for (const auto* link : {"lmdb_static", "static_lmdb", "vendor::lmdb_static", "unicorn_static",
             "static_unicorn", "vendor::unicorn_static", "remill_worker", "worker_remill",
             "vendor::remill_worker"}) {
        if (!contains_forbidden_link_token(link))
            throw std::runtime_error(source.string() + " does not reject forbidden link variant " + link);
    }
    for (const auto* link : {"libmdbx", "unicornfish", "remilling"}) {
        if (contains_forbidden_link_token(link))
            throw std::runtime_error(source.string() + " rejects a non-token link name " + link);
    }
}

std::filesystem::path locate_root(std::filesystem::path path)
{
    path = std::filesystem::absolute(path);
    while (!path.empty()) {
        if (std::filesystem::exists(path / "CMakeLists.txt") &&
            std::filesystem::exists(path / "plans"))
            return path;
        const auto parent = path.parent_path();
        if (parent == path)
            break;
        path = parent;
    }
    throw std::runtime_error("AiDA repository root was not found");
}

void require_files(const std::filesystem::path& root, const std::vector<std::string>& paths)
{
    for (const auto& relative_path : paths) {
        if (!std::filesystem::is_regular_file(root / relative_path))
            throw std::runtime_error("required C03 inventory file is missing " + relative_path);
    }
}

std::string strip_cmake_comments(std::string_view source)
{
    std::string result;
    bool quoted = false;
    bool escaped = false;
    for (std::size_t index = 0; index < source.size(); ++index) {
        const char value = source[index];
        if (!quoted && value == '#') {
            while (index < source.size() && source[index] != '\n')
                ++index;
            if (index < source.size())
                result.push_back('\n');
            continue;
        }
        result.push_back(value);
        if (value == '"' && !escaped)
            quoted = !quoted;
        escaped = value == '\\' && !escaped;
        if (value != '\\')
            escaped = false;
    }
    return result;
}

std::vector<std::string> split_cmake_arguments(std::string_view source)
{
    std::vector<std::string> arguments;
    std::size_t index = 0;
    while (index < source.size()) {
        while (index < source.size() && std::isspace(static_cast<unsigned char>(source[index])))
            ++index;
        if (index == source.size())
            break;
        std::string argument;
        if (source[index] == '"') {
            ++index;
            bool escaped = false;
            while (index < source.size()) {
                const char value = source[index++];
                if (value == '"' && !escaped)
                    break;
                argument.push_back(value);
                escaped = value == '\\' && !escaped;
                if (value != '\\')
                    escaped = false;
            }
        } else {
            while (index < source.size() && !std::isspace(static_cast<unsigned char>(source[index])))
                argument.push_back(source[index++]);
        }
        arguments.push_back(std::move(argument));
    }
    return arguments;
}

std::vector<cmake_call_t> parse_cmake_calls(const std::string& source)
{
    const auto content = strip_cmake_comments(source);
    std::vector<cmake_call_t> calls;
    std::size_t index = 0;
    while (index < content.size()) {
        while (index < content.size() && !std::isalpha(static_cast<unsigned char>(content[index])) && content[index] != '_')
            ++index;
        if (index == content.size())
            break;
        const auto command_begin = index;
        while (index < content.size() && (std::isalnum(static_cast<unsigned char>(content[index])) || content[index] == '_'))
            ++index;
        const auto command_end = index;
        while (index < content.size() && std::isspace(static_cast<unsigned char>(content[index])))
            ++index;
        if (index == content.size() || content[index] != '(')
            continue;
        ++index;
        const auto arguments_begin = index;
        std::size_t depth = 1;
        bool quoted = false;
        bool escaped = false;
        while (index < content.size() && depth != 0) {
            const char value = content[index++];
            if (value == '"' && !escaped)
                quoted = !quoted;
            if (!quoted) {
                if (value == '(')
                    ++depth;
                else if (value == ')')
                    --depth;
            }
            escaped = value == '\\' && !escaped;
            if (value != '\\')
                escaped = false;
        }
        if (depth != 0)
            throw std::runtime_error("unterminated CMake command");
        calls.push_back({lowercase(content.substr(command_begin, command_end - command_begin)),
            split_cmake_arguments(std::string_view(content).substr(arguments_begin, index - arguments_begin - 1))});
    }
    return calls;
}

const cmake_call_t& require_call(const std::vector<cmake_call_t>& calls, std::string_view command,
    const std::vector<std::string>& leading_arguments, const std::filesystem::path& source)
{
    for (const auto& call : calls) {
        if (!equals_ignore_case(call.command, command) || call.arguments.size() < leading_arguments.size())
            continue;
        bool matches = true;
        for (std::size_t index = 0; index < leading_arguments.size(); ++index) {
            if (call.arguments[index] != leading_arguments[index]) {
                matches = false;
                break;
            }
        }
        if (matches)
            return call;
    }
    throw std::runtime_error(source.string() + " is missing required CMake call " + std::string(command));
}

std::vector<cmake_call_t> require_function_body(const std::vector<cmake_call_t>& calls, std::string_view function_name,
    const std::filesystem::path& source)
{
    for (std::size_t index = 0; index < calls.size(); ++index) {
        if (calls[index].command != "function" || calls[index].arguments.empty() ||
            !equals_ignore_case(calls[index].arguments.front(), function_name))
            continue;
        std::vector<cmake_call_t> body;
        for (++index; index < calls.size(); ++index) {
            if (calls[index].command == "endfunction")
                return body;
            body.push_back(calls[index]);
        }
        break;
    }
    throw std::runtime_error(source.string() + " is missing function " + std::string(function_name));
}

bool call_has_argument(const cmake_call_t& call, std::string_view argument)
{
    return std::any_of(call.arguments.begin(), call.arguments.end(), [argument](const std::string& value) {
        return value.find(std::string(argument)) != std::string::npos;
    });
}

void require_set(const std::vector<cmake_call_t>& calls, const std::vector<std::string>& arguments,
    const std::filesystem::path& source)
{
    for (const auto& call : calls) {
        if (call.command == "set" && call.arguments == arguments)
            return;
    }
    throw std::runtime_error(source.string() + " has an incomplete CMake set policy for " + arguments.front());
}

void require_inventory_record(const std::vector<cmake_call_t>& inventory, std::string_view relative_path,
    std::string_view expected_sha256, const std::filesystem::path& source)
{
    for (const auto& call : inventory) {
        if (call.command == "aida_c03_require_file_sha256" && call.arguments.size() == 2 &&
            call.arguments[0] == relative_path && call.arguments[1] == expected_sha256)
            return;
    }
    throw std::runtime_error(source.string() + " does not pin " + std::string(relative_path));
}

void require_body_argument(const std::vector<cmake_call_t>& body, std::string_view argument,
    const std::filesystem::path& source)
{
    for (const auto& call : body) {
        if (call_has_argument(call, argument))
            return;
    }
    throw std::runtime_error(source.string() + " function body is missing " + std::string(argument));
}

void require_stage_call(const std::vector<cmake_call_t>& body, const std::vector<std::string>& arguments,
    const std::filesystem::path& source)
{
    for (const auto& call : body) {
        if (call.command == "aida_c03_stage_managed_package_notices" && call.arguments == arguments)
            return;
    }
    throw std::runtime_error(source.string() + " does not stage a required managed-package notice set");
}

void require_no_network_fetch(const std::vector<cmake_call_t>& calls, const std::filesystem::path& source)
{
    for (const auto& call : calls) {
        if (call.command == "fetchcontent_declare" || call.command == "fetchcontent_makeavailable" ||
            call.command == "externalproject_add")
            throw std::runtime_error(source.string() + " declares a network dependency command");
        if (call.command == "file" && !call.arguments.empty() && equals_ignore_case(call.arguments.front(), "download"))
            throw std::runtime_error(source.string() + " downloads a network dependency");
        if (call.command == "execute_process") {
            for (std::size_t index = 0; index + 1 < call.arguments.size(); ++index) {
                if (equals_ignore_case(call.arguments[index], "command") &&
                    ((equals_ignore_case(call.arguments[index + 1], "git") && index + 2 < call.arguments.size() &&
                         equals_ignore_case(call.arguments[index + 2], "clone")) ||
                        equals_ignore_case(call.arguments[index + 1], "curl") ||
                        equals_ignore_case(call.arguments[index + 1], "wget")))
                    throw std::runtime_error(source.string() + " executes a network dependency fetch");
            }
        }
    }
}

void verify_cmake_policy(const std::filesystem::path& root)
{
    const auto source = root / "cmake/aida_c03_dependencies.cmake";
    const auto calls = parse_cmake_calls(read_file(source));
    require_set(calls, {"AIDA_C03_NO_NETWORK_FETCH", "ON", "CACHE", "BOOL", "", "FORCE"}, source);
    require_set(calls, {"FETCHCONTENT_FULLY_DISCONNECTED", "ON", "CACHE", "BOOL", "", "FORCE"}, source);
    require_set(calls, {"FETCHCONTENT_UPDATES_DISCONNECTED", "ON", "CACHE", "BOOL", "", "FORCE"}, source);
    require_set(calls, {"AIDA_C03_FORBIDDEN_LINK_TOKENS", "lmdb", "unicorn", "remill"}, source);
    require_set(calls, {"AIDA_C03_LLVM_COMPONENT_ALLOWLIST", "Demangle", "Support"}, source);
    require_set(calls, {"AIDA_C03_MANAGED_WORKER_PACKAGES_COMPONENT_ALLOWLIST", "ICSharpCode.Decompiler", "System.Collections.Immutable", "System.Reflection.Metadata"}, source);
    require_no_network_fetch(calls, source);

    const auto inventory = require_function_body(calls, "aida_c03_verify_dependency_inventory", source);
    for (const auto& record : std::vector<std::pair<std::string, std::string>>{
             {".deps/zydis-4.1.1/LICENSE", "e5e99718209e94baaf3e9cbf6f64aa3329c9e73c63b1ab47e10f29d81974e6f3"},
             {".deps/capstone/capstone-5.0.9/LICENSE.TXT", "65e9ed46a59976eda8f5bd1ea79a680dea38dd299c760bc9a8d87a764ef5029b"},
             {".deps/nuget-offline/ICSharpCode.Decompiler.10.1.0.8386.nupkg", "a6fb2e9be86c1b73e54231e20640d4d566c52f21cba9ad99c3e9100d67e8f5af"},
             {".deps/nuget-offline/System.Collections.Immutable.9.0.0.nupkg", "fbaab954c7a87396e6e1616ca15ea705703d755e696bf3b8c96fa039d8bcc9a7"},
             {".deps/nuget-offline/System.Reflection.Metadata.9.0.0.nupkg", "6af1166dc0a1ed7829b127ac9d1dff4a0c568bfe82e4ec6347cf497ff49f4634"},
             {".deps/LIEF-0.17.6/LICENSE", "94a5b753e8d799c7aa0c0c4899c5d5f9be1a940cba73f61c6396f32db790a0be"},
             {".deps/remill-6.0.1/remill-6.0.1/LICENSE", "59899c6091b540582ed617e8eeaac4919dc985ccfc35459ee9752b699be5205b"},
             {"camoufox-135.0.1-beta.24-win.x86_64/camoufox.exe", "768937fa6a6df581d0cdc88ecffe1cf651ffebe1ad1d5667a5f75100e96acfe0"},
             {".deps/AiDA_CamoufoxReverseMcp/AiDA_CamoufoxReverseMcp.exe", "2443649a43c92b048b7f013434d169889b41f494f391359d9cc72111c6e0ee4c"}})
        require_inventory_record(inventory, record.first, record.second, source);

    const auto component_policy = require_function_body(calls, "aida_c03_require_components", source);
    require_body_argument(component_policy, "IN_LIST", source);
    require_body_argument(component_policy, "AIDA_C03_", source);
    require_body_argument(component_policy, "lmdb|unicorn|remill", source);
    require_body_argument(component_policy, "(^|[^A-Za-z0-9])(lmdb|unicorn|remill)([^A-Za-z0-9]|$)", source);

    const auto link_policy = require_function_body(calls, "aida_c03_reject_forbidden_target_links", source);
    require_body_argument(link_policy, "LINK_LIBRARIES", source);
    require_body_argument(link_policy, "INTERFACE_LINK_LIBRARIES", source);
    require_body_argument(link_policy, "AIDA_C03_FORBIDDEN_LINK_TOKENS", source);
    require_body_argument(link_policy, "TOLOWER", source);
    require_body_argument(link_policy, "(^|[^a-z0-9])${_aida_c03_forbidden}([^a-z0-9]|$)", source);
    verify_forbidden_link_semantics(source);

    const auto managed_stage = require_function_body(calls, "aida_c03_stage_managed_package_notices", source);
    require_body_argument(managed_stage, "ARCHIVE_EXTRACT", source);
    require_body_argument(managed_stage, "LICENSE.TXT", source);
    require_body_argument(managed_stage, "THIRD-PARTY-NOTICES.TXT", source);
    require_body_argument(managed_stage, "aida_c03_require_path_sha256", source);

    const auto notice_stage = require_function_body(calls, "aida_c03_stage_notices", source);
    require_call(notice_stage, "aida_c03_verify_dependency_inventory", {}, source);
    require_call(notice_stage, "aida_c03_copy_notice_as", {"${destination}", "licenses/c03/THIRD_PARTY_NOTICES.md", "THIRD_PARTY_NOTICES.md"}, source);
    require_stage_call(notice_stage, {"${destination}", ".deps/nuget-offline/System.Collections.Immutable.9.0.0.nupkg", "System.Collections.Immutable-9.0.0", "d7a68596ab69b06f51ca278a6545148e4269a9381c26d597c13df5d88e08cf5b", "40686c6447a7d5b5d3693068e4571b5f483d7ed335aeee773ef662440de4c5d5"}, source);
    require_stage_call(notice_stage, {"${destination}", ".deps/nuget-offline/System.Reflection.Metadata.9.0.0.nupkg", "System.Reflection.Metadata-9.0.0", "d7a68596ab69b06f51ca278a6545148e4269a9381c26d597c13df5d88e08cf5b", "40686c6447a7d5b5d3693068e4571b5f483d7ed335aeee773ef662440de4c5d5"}, source);

    const auto evidence_stage = require_function_body(calls, "aida_c03_stage_evidence_notices", source);
    require_call(evidence_stage, "aida_c03_verify_dependency_inventory", {}, source);
    require_body_argument(evidence_stage, ".deps/LIEF-0.17.6/LICENSE", source);
    require_body_argument(evidence_stage, ".deps/remill-6.0.1/remill-6.0.1/LICENSE", source);
    require_call(evidence_stage, "aida_c03_copy_notice", {"${destination}", "${_aida_c03_notice}"}, source);
}

void verify_lock_policy(const std::filesystem::path& root)
{
    const auto source = root / "packaging/c03_worker_manifest.lock.json";
    const auto text = read_file(source);
    for (const auto& required : {"\"no_network_fetch\": true", "\"locked_mode_required\": true",
             "\"network_sources_forbidden\": true", "\"ICSharpCode.Decompiler\"",
             "a6fb2e9be86c1b73e54231e20640d4d566c52f21cba9ad99c3e9100d67e8f5af",
             "fbaab954c7a87396e6e1616ca15ea705703d755e696bf3b8c96fa039d8bcc9a7",
             "6af1166dc0a1ed7829b127ac9d1dff4a0c568bfe82e4ec6347cf497ff49f4634",
             "\"ledger_source_path\": \"licenses/c03/THIRD_PARTY_NOTICES.md\"",
             "\"customer_ledger_relative_path\": \"notices/THIRD_PARTY_NOTICES.md\"",
             "\"managed_package_notices\"", "\"LICENSE.TXT\"", "\"THIRD-PARTY-NOTICES.TXT\"",
             "d7a68596ab69b06f51ca278a6545148e4269a9381c26d597c13df5d88e08cf5b",
             "40686c6447a7d5b5d3693068e4571b5f483d7ed335aeee773ef662440de4c5d5",
             "\"evidence_only_notices\"", ".deps/LIEF-0.17.6/LICENSE",
             ".deps/remill-6.0.1/remill-6.0.1/LICENSE", "\"evidence_only\": [\"lief\", \"remill\"]",
             "\"non_use\": [\"lmdb\", \"unicorn\"]",
             "\"llvm_component_allowlist\": [\"Demangle\", \"Support\"]",
             "\"production_link_denylist\": [\"lmdb\", \"unicorn\", \"remill\"]"})
        require_contains(text, required, source);
}

void verify_worker_schema(const std::filesystem::path& root)
{
    const auto source = root / "packaging/c03_worker_manifest.schema.json";
    const auto text = read_file(source);
    for (const auto& required : {"aida.c03.worker-manifest", "native_decompiler",
             "managed_cli_decompiler", "analysis_python", "manifest_bound", "acl_restricted",
             "session_nonce", "monotonic_sequence", "kill_on_parent_close", "restricted_token",
             "network_denied", "child_process_denied", "unrelated_handles_denied",
             "process_mitigations", "cancellation_replaces_worker", "target_execution_forbidden",
             "raw_standalone_download_forbidden", "fileless_launch_forbidden", "camoufox",
             "AIDA_CAMOUFOX_EXECUTABLE", "AIDA_CAMOUFOX_MCP_EXECUTABLE", "AIDA_CAMOUFOX_PYTHON",
             "\"notices\"", "notices/THIRD_PARTY_NOTICES.md", "managed_package_notices",
             "THIRD-PARTY-NOTICES\\\\.TXT"})
        require_contains(text, required, source);
    for (const auto& structural : {"\"additionalProperties\"", "\"required\"", "\"properties\"", "\"type\""})
        require_contains(text, structural, source);
    for (const auto& property_key : {"\"native_decompiler\"", "\"managed_cli_decompiler\"",
             "\"analysis_python\"", "\"manifest_bound\"", "\"acl_restricted\"",
             "\"session_nonce\"", "\"monotonic_sequence\"", "\"kill_on_parent_close\"",
             "\"restricted_token\"", "\"network_denied\"", "\"child_process_denied\"",
             "\"unrelated_handles_denied\"", "\"process_mitigations\"",
             "\"cancellation_replaces_worker\"", "\"target_execution_forbidden\"",
             "\"raw_standalone_download_forbidden\"", "\"fileless_launch_forbidden\"",
             "\"camoufox\"", "\"AIDA_CAMOUFOX_EXECUTABLE\"",
             "\"AIDA_CAMOUFOX_MCP_EXECUTABLE\"", "\"AIDA_CAMOUFOX_PYTHON\""})
        require_contains(text, property_key, source);
    for (const auto& prohibited : {"chrome", "edge", "firefox"})
        require_absent(text, prohibited, source);
}

void verify_native_worker_manifest(const std::filesystem::path& root)
{
    const auto source = root / "packaging/c03_native_worker_manifest.json";
    const auto text = read_file(source);

    const auto magic = extract_json_string_value(text, "magic");
    if (magic != "NWMF")
        throw std::runtime_error(source.string() + " has invalid magic '" + magic + "'");

    const auto schema_version = extract_json_number_value(text, "schema_version");
    if (schema_version != 1)
        throw std::runtime_error(source.string() + " has invalid schema_version");

    const auto format = extract_json_string_value(text, "format");
    if (format != "aida.native-worker-manifest")
        throw std::runtime_error(source.string() + " has invalid format '" + format + "'");

    const auto provider_name = extract_json_string_value(text, "name");
    if (provider_name != "aida-native-decompiler")
        throw std::runtime_error(source.string() + " has invalid provider name '" + provider_name + "'");

    const auto protocol_version = extract_json_number_value(text, "version");
    if (protocol_version != 1)
        throw std::runtime_error(source.string() + " has invalid protocol version");

    const auto hash_material = extract_json_string_value(text, "hash_material");
    if (hash_material.find("hmac-sha256") == std::string::npos ||
        hash_material.find("readonly-snapshot") == std::string::npos)
        throw std::runtime_error(source.string() + " has invalid protocol hash_material");

    const auto worker_binary_hash = extract_json_string_value(text, "worker_binary_hash");
    if (!is_valid_hash_field(worker_binary_hash))
        throw std::runtime_error(source.string() + " has invalid worker_binary_hash '" + worker_binary_hash + "'");

    const auto provider_binary_hash = extract_json_string_value(text, "provider_binary_hash");
    if (!is_valid_hash_field(provider_binary_hash))
        throw std::runtime_error(source.string() + " has invalid provider_binary_hash '" + provider_binary_hash + "'");

    const auto manifest_digest = extract_json_string_value(text, "manifest_digest");
    if (!is_valid_hash_field(manifest_digest))
        throw std::runtime_error(source.string() + " has invalid manifest_digest '" + manifest_digest + "'");
}

void verify_notice_ledger(const std::filesystem::path& root)
{
    const auto source = root / "licenses/c03/THIRD_PARTY_NOTICES.md";
    const auto text = read_file(source);
    for (const auto& required : {"Zydis", "Capstone", "Taskflow", "Ghidra", "Triton", "Z3",
             "SQLite", "Dear ImGui", "zlib", "Zstandard", "liblzma", "minizip-ng", "PCRE2",
             "nlohmann JSON", "LLVM Demangle", ".NET SDK", "ICSharpCode.Decompiler", "LIEF", "Remill",
             "aida_c03_stage_notices", "aida_c03_stage_evidence_notices",
             "System.Collections.Immutable.9.0.0.nupkg::LICENSE.TXT",
             "System.Collections.Immutable.9.0.0.nupkg::THIRD-PARTY-NOTICES.TXT",
             "System.Reflection.Metadata.9.0.0.nupkg::LICENSE.TXT",
             "System.Reflection.Metadata.9.0.0.nupkg::THIRD-PARTY-NOTICES.TXT"})
        require_contains(text, required, source);
    require_contains(read_file(root / "licenses/c03/MIT.txt"), "The MIT License (MIT)",
        root / "licenses/c03/MIT.txt");
    require_contains(read_file(root / "licenses/c03/SQLite-Public-Domain.txt"), "public domain",
        root / "licenses/c03/SQLite-Public-Domain.txt");
}

}

int main(int argc, char** argv)
{
    try {
        const auto root = locate_root(argc > 1 ? std::filesystem::path(argv[1]) : std::filesystem::current_path());
        require_files(root, {".gitignore", "cmake/aida_c03_dependencies.cmake", "licenses/c03/MIT.txt",
            "licenses/c03/SQLite-Public-Domain.txt", "licenses/c03/THIRD_PARTY_NOTICES.md", "packaging/c03_worker_manifest.schema.json",
            "packaging/c03_worker_manifest.lock.json", "packaging/c03_native_worker_manifest.json",
            ".deps/nuget-offline/ICSharpCode.Decompiler.10.1.0.8386.nupkg",
            ".deps/nuget-offline/System.Collections.Immutable.9.0.0.nupkg",
            ".deps/nuget-offline/System.Reflection.Metadata.9.0.0.nupkg", ".deps/LIEF-0.17.6/LICENSE",
            ".deps/remill-6.0.1/remill-6.0.1/LICENSE", "camoufox-135.0.1-beta.24-win.x86_64/camoufox.exe",
            ".deps/AiDA_CamoufoxReverseMcp/AiDA_CamoufoxReverseMcp.exe"});
        verify_gitignore_policy(root);
        verify_cmake_policy(root);
        verify_lock_policy(root);
        verify_worker_schema(root);
        verify_native_worker_manifest(root);
        verify_notice_ledger(root);
        std::cout << "C03 dependency inventory source contract satisfied\n";
        return 0;
    } catch (const std::exception& error) {
        std::cerr << error.what() << '\n';
        return 1;
    }
}
