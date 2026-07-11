#include "workspace_fixture_builder.hpp"

#include "../../src/core/mcp/mcp_standalone.hpp"
#include "../../src/core/mcp/ida_compat_schemas.hpp"
#include "../../src/core/mcp/schema_validator.hpp"
#include "../../src/core/tools/standalone_tools_fwd.hpp"

#include <algorithm>
#include <array>
#include <atomic>
#include <chrono>
#include <condition_variable>
#include <fstream>
#include <future>
#include <iostream>
#include <limits>
#include <map>
#include <mutex>
#include <string>
#include <unordered_set>
#include <vector>

namespace {

using namespace aida::analysis;
using namespace aida::analysis::test_fixture;
using mcp_standalone::json;
using mcp_standalone::tool_result_t;

struct workspace_overlap_gate_t {
    std::mutex mutex;
    std::condition_variable wake;
    std::size_t entered = 0;
    std::size_t active = 0;
    std::size_t peak_active = 0;
    bool release = false;
};

struct live_arguments_t {
    std::uint32_t pid = 0;
    std::uint64_t module_base = 0;
    std::uint64_t module_size = 0;
    std::string module_name;
    std::string module_path;
};

std::uint64_t parse_u64(const std::string& value)
{
    std::size_t consumed = 0;
    const auto parsed = std::stoull(value, &consumed, 0);
    if (consumed != value.size())
        throw fixture_error_t("invalid numeric harness argument");
    return parsed;
}

live_arguments_t parse_live_arguments(int argc, char** argv)
{
    live_arguments_t result;
    if (argc < 2 || ((argc - 1) % 2) != 0)
        throw fixture_error_t("live PID/module arguments must be key/value pairs");
    for (int index = 1; index + 1 < argc; index += 2) {
        const std::string key = argv[index];
        const std::string value = argv[index + 1];
        if (key == "--live-pid") result.pid = static_cast<std::uint32_t>(parse_u64(value));
        else if (key == "--module-base") result.module_base = parse_u64(value);
        else if (key == "--module-size") result.module_size = parse_u64(value);
        else if (key == "--module-name") result.module_name = value;
        else if (key == "--module-path") result.module_path = value;
        else throw fixture_error_t("unknown MCP harness argument");
    }
    if (result.pid == 0 || result.module_base == 0 || result.module_size == 0 ||
        result.module_name.empty() || result.module_path.empty())
        throw fixture_error_t("live PID/module arguments are required for stale/reuse/no-write coverage");
    return result;
}

void require_code(const tool_result_t& result, const std::string& code)
{
    if (result.success || result.error_code != code)
        throw fixture_error_t("expected MCP error code " + code + ", received " + result.error_code);
}

constexpr std::array<const char*, 24> k_ida_read_tools{{
    "lookup_funcs", "int_convert", "list_funcs", "list_globals", "imports", "decompile",
    "disasm", "xrefs_to", "xrefs_to_field", "callees", "get_bytes", "get_int",
    "get_string", "get_global_value", "stack_frame", "read_struct", "search_structs",
    "find_regex", "find_bytes", "find_insns", "find", "basic_blocks", "export_funcs",
    "callgraph"
}};

constexpr std::array<const char*, 15> k_ida_mutation_tools{{
    "add_bookmark", "set_comments", "patch_asm", "declare_type", "define_func",
    "define_code", "undefine", "declare_stack", "delete_stack", "set_type",
    "infer_types", "analyze_funcs", "rename", "patch", "put_int"
}};

std::vector<std::string> required_ida_tool_names()
{
    std::vector<std::string> names;
    names.reserve(k_ida_read_tools.size() + k_ida_mutation_tools.size() + 3);
    for (const char* name : k_ida_read_tools) names.emplace_back(name);
    for (const char* name : k_ida_mutation_tools) names.emplace_back(name);
    names.emplace_back("list_instances");
    names.emplace_back("calculator");
    names.emplace_back("calculate");
    return names;
}

bool contains_name(const std::array<const char*, 15>& names, const std::string& name)
{
    return std::find_if(names.begin(), names.end(), [&](const char* candidate) {
        return name == candidate;
    }) != names.end();
}

const mcp_standalone::tool_def_t& registered_tool(const mcp_standalone::server_t& server,
                                                  const std::string& name)
{
    const auto& tools = server.get_tools();
    const auto found = std::find_if(tools.begin(), tools.end(), [&](const auto& tool) {
        return tool.name == name;
    });
    if (found == tools.end())
        throw fixture_error_t("required MCP tool is not registered: " + name);
    return *found;
}

tool_result_t require_success(mcp_standalone::server_t& server,
                              const std::string& name,
                              json arguments)
{
    const auto result = server.call_registered_tool(name, arguments, true);
    if (!result.success)
        throw fixture_error_t(name + " handler failed with " + result.error_code + ":" + result.text);
    return result;
}

json jsonrpc_result(mcp_standalone::server_t& server,
                    const std::string& method,
                    json params)
{
    static std::atomic<std::uint64_t> next_id{1};
    const json request = {
        {"jsonrpc", "2.0"},
        {"id", next_id.fetch_add(1, std::memory_order_relaxed)},
        {"method", method},
        {"params", std::move(params)}
    };
    const auto response = json::parse(mcp_standalone::handle_body(&server, request.dump()));
    if (!response.is_object() || response.contains("error") || !response.contains("result"))
        throw fixture_error_t("JSON-RPC " + method + " failed: " + response.dump());
    return response["result"];
}

void verify_ida_registration_surface(mcp_standalone::server_t& server)
{
    const auto validator_status = mcp_standalone::ida_compat::schema_validator_status();
    if (!validator_status.valid)
        throw fixture_error_t("IDA compatibility schema validator initialization failed: " +
                              validator_status.summary());

    const auto required = required_ida_tool_names();
    std::map<std::string, std::size_t> registered_counts;
    for (const auto& tool : server.get_tools())
        ++registered_counts[tool.name];
    for (const auto& entry : registered_counts) {
        if (entry.second != 1)
            throw fixture_error_t("duplicate registered MCP tool name: " + entry.first);
    }
    if (registered_counts.count("py_eval") != 0)
        throw fixture_error_t("excluded py_eval tool was registered");

    for (const auto& name : required) {
        if (registered_counts[name] != 1)
            throw fixture_error_t("required IDA compatibility tool count mismatch: " + name);
        const auto& tool = registered_tool(server, name);
        const auto* expected_schema = mcp_standalone::ida_compat::find_schema(name);
        if (!expected_schema || tool.input_schema != *expected_schema)
            throw fixture_error_t("registered exact schema mismatch: " + name);
        const bool expected_read_only = !contains_name(k_ida_mutation_tools, name);
        if (tool.read_only != expected_read_only ||
            tool.visibility != mcp_standalone::tool_visibility_t::external_visible)
            throw fixture_error_t("registered classification mismatch: " + name);
        const bool target_dependent = mcp_standalone::ida_compat::is_target_dependent_tool(name);
        if (target_dependent != static_cast<bool>(tool.workspace_handler) ||
            target_dependent == static_cast<bool>(tool.handler))
            throw fixture_error_t("registered handler binding mismatch: " + name);
    }
    if (registered_tool(server, "infer_types").read_only ||
        registered_tool(server, "analyze_funcs").read_only)
        throw fixture_error_t("infer_types/analyze_funcs must be classified as mutating");
    if (registered_tool(server, "calculator").input_schema !=
        registered_tool(server, "calculate").input_schema)
        throw fixture_error_t("calculator/calculate schema aliases diverged");

    const auto tools_list = jsonrpc_result(server, "tools/list", json{{"detail", "full"}});
    if (!tools_list.contains("tools") || !tools_list["tools"].is_array() ||
        tools_list["_meta"].value("aidaToolListMode", std::string()) != "full")
        throw fixture_error_t("tools/list full response envelope mismatch");
    std::map<std::string, json> listed;
    for (const auto& tool : tools_list["tools"]) {
        if (!tool.is_object() || !tool.contains("name") || !tool["name"].is_string())
            throw fixture_error_t("tools/list returned a malformed tool definition");
        const std::string name = tool["name"].get<std::string>();
        if (!listed.emplace(name, tool).second)
            throw fixture_error_t("tools/list returned duplicate name: " + name);
    }
    if (listed.count("py_eval") != 0)
        throw fixture_error_t("tools/list exposed excluded py_eval");
    for (const auto& name : required) {
        const auto found = listed.find(name);
        const auto* expected_schema = mcp_standalone::ida_compat::find_schema(name);
        if (found == listed.end() || !expected_schema ||
            found->second.value("visibility", std::string()) != "external_visible" ||
            found->second.value("read_only", false) != !contains_name(k_ida_mutation_tools, name) ||
            found->second["inputSchema"] != *expected_schema ||
            found->second["annotations"].value("readOnlyHint", false) !=
                !contains_name(k_ida_mutation_tools, name) ||
            found->second["annotations"].value("destructiveHint", false) !=
                contains_name(k_ida_mutation_tools, name))
            throw fixture_error_t("tools/list exact contract mismatch: " + name);
    }

    const auto resources = jsonrpc_result(server, "resources/list", json::object());
    if (!resources.contains("resources") || !resources["resources"].is_array())
        throw fixture_error_t("resources/list response envelope mismatch");
    for (const auto& resource : resources["resources"]) {
        if (resource.contains("uri") && resource["uri"].is_string() &&
            resource["uri"].get<std::string>().rfind("ida://", 0) == 0)
            throw fixture_error_t("excluded ida:// resource was registered");
    }

    const auto before = server.get_tools().size();
    mcp_standalone::tool_def_t duplicate = registered_tool(server, "lookup_funcs");
    if (server.register_tool(std::move(duplicate)) || server.get_tools().size() != before)
        throw fixture_error_t("duplicate MCP tool registration was not rejected atomically");
}

void verify_surface_manifests()
{
    const std::filesystem::path directory = std::filesystem::path(__FILE__).parent_path();
    std::ifstream baseline_stream(directory / "standalone_surface_baseline.json");
    std::ifstream final_stream(directory / "standalone_surface_final.json");
    if (!baseline_stream || !final_stream)
        throw fixture_error_t("surface manifests are unavailable");
    json baseline;
    json final_manifest;
    baseline_stream >> baseline;
    final_stream >> final_manifest;
    std::map<std::string, json> final_tools;
    for (const auto& registration : final_manifest["mcp"]["registrations"])
        final_tools.emplace(registration["name"].get<std::string>(), registration);
    for (const auto& registration : baseline["mcp"]["registrations"]) {
        const std::string name = registration["name"].get<std::string>();
        auto current = final_tools.find(name);
        if (current == final_tools.end())
            throw fixture_error_t("removed MCP registration: " + name);
        for (const char* field : {"description", "read_only",
                                  "visibility_declared", "visibility_effective"}) {
            if (registration[field] != current->second[field])
                throw fixture_error_t("MCP contract changed for " + name + " field " + field);
        }
        const bool workspace_aware = current->second.value("workspace_aware", false);
        if (!workspace_aware) {
            if (registration["parameters"] != current->second["parameters"])
                throw fixture_error_t("MCP contract changed for " + name + " field parameters");
            continue;
        }
        auto expected = registration["parameters"];
        bool replaced_binary_id = false;
        for (auto& parameter : expected) {
            if (parameter.value("name", std::string()) != "binary_id")
                continue;
            parameter["description"] = "Optional immutable workspace binary id. When all selectors are omitted exactly one open workspace must exist; otherwise TARGET_REQUIRED is returned.";
            replaced_binary_id = true;
        }
        if (!replaced_binary_id)
            throw fixture_error_t("workspace-aware baseline registration lacks binary_id: " + name);
        expected.push_back(json{{"name", "bin_name"},
                                {"type", "string"},
                                {"description", "Optional exact workspace name or unique substring. Mutually exclusive with binary_id and pid."},
                                {"required", false},
                                {"default_hints", json::array()}});
        expected.push_back(json{{"name", "pid"},
                                {"type", "integer"},
                                {"description", "Optional positive live target PID. Mutually exclusive with binary_id and bin_name."},
                                {"required", false},
                                {"default_hints", json::array()}});
        if (expected != current->second["parameters"])
            throw fixture_error_t("workspace-aware MCP selector extension mismatch for " + name);
    }
    for (const auto& registration : final_manifest["mcp"]["registrations"]) {
        const std::string name = registration["name"].get<std::string>();
        if (name != "list_instances") {
            bool existed = false;
            for (const auto& baseline_registration : baseline["mcp"]["registrations"])
                existed = existed || baseline_registration["name"] == name;
            if (!existed)
                throw fixture_error_t("unexpected C01 MCP registration: " + name);
        }
    }
    if (final_tools.find("list_instances") == final_tools.end() ||
        final_tools.find("py_eval") != final_tools.end())
        throw fixture_error_t("required list_instances/py_eval surface disposition mismatch");
    const auto& list_instances = final_tools.at("list_instances");
    if (!list_instances["parameters"].empty() || !list_instances.value("read_only", false) ||
        list_instances.value("visibility_declared", std::string()) != "external_visible" ||
        list_instances.value("visibility_effective", std::string()) != "external_visible" ||
        !final_manifest["mcp"]["duplicate_names"].empty() ||
        final_manifest["mcp"].value("registration_count", 0u) !=
            baseline["mcp"].value("registration_count", 0u) + 1u ||
        final_manifest["mcp"].value("unique_name_count", 0u) !=
            baseline["mcp"].value("unique_name_count", 0u) + 1u)
        throw fixture_error_t("list_instances or final registration-count contract mismatch");
    if (baseline["mcp"]["dynamic_registration_templates"] !=
            final_manifest["mcp"]["dynamic_registration_templates"] ||
        baseline["mcp"]["visibility_policy"] != final_manifest["mcp"]["visibility_policy"])
        throw fixture_error_t("MCP dynamic registration or visibility policy changed");
    std::map<std::string, json> final_resources;
    for (const auto& resource : final_manifest["mcp"]["resources"])
        final_resources.emplace(resource["uri"].get<std::string>(), resource);
    for (const auto& resource : baseline["mcp"]["resources"]) {
        const std::string uri = resource["uri"].get<std::string>();
        auto current = final_resources.find(uri);
        if (current == final_resources.end())
            throw fixture_error_t("removed MCP resource: " + uri);
        for (const char* field : {"name", "description", "mime_type", "result_fields"}) {
            if (resource[field] != current->second[field])
                throw fixture_error_t("MCP resource contract changed for " + uri);
        }
    }
    for (const auto& resource : final_manifest["mcp"]["resources"]) {
        const std::string uri = resource["uri"].get<std::string>();
        if (uri.rfind("ida://", 0) == 0)
            throw fixture_error_t("excluded ida:// resource was added: " + uri);
    }
    for (const auto& view : baseline["ui"]["center_views"]) {
        if (std::find(final_manifest["ui"]["center_views"].begin(),
                      final_manifest["ui"]["center_views"].end(), view) ==
            final_manifest["ui"]["center_views"].end())
            throw fixture_error_t("removed center view: " + view.get<std::string>());
    }
    for (const auto& entry : baseline["ui"]["actions"]) {
        const auto found = std::find_if(final_manifest["ui"]["actions"].begin(),
            final_manifest["ui"]["actions"].end(), [&](const json& current) {
                return current.value("label", std::string()) == entry.value("label", std::string());
            });
        if (found == final_manifest["ui"]["actions"].end())
            throw fixture_error_t("removed UI action: " + entry.value("label", std::string()));
    }
    for (const auto& entry : baseline["ui"]["shortcuts"]) {
        const auto found = std::find_if(final_manifest["ui"]["shortcuts"].begin(),
            final_manifest["ui"]["shortcuts"].end(), [&](const json& current) {
                return current.value("key", std::string()) == entry.value("key", std::string()) &&
                    current.value("expression", std::string()) == entry.value("expression", std::string());
            });
        if (found == final_manifest["ui"]["shortcuts"].end())
            throw fixture_error_t("removed or changed UI shortcut: " +
                entry.value("key", std::string()));
    }
    for (const auto& method : baseline["session"]["public_method_names"]) {
        if (std::find(final_manifest["session"]["public_method_names"].begin(),
                      final_manifest["session"]["public_method_names"].end(), method) ==
            final_manifest["session"]["public_method_names"].end())
            throw fixture_error_t("removed session method: " + method.get<std::string>());
    }
}

struct handler_case_t {
    std::string name;
    json arguments;
    std::string result_field;
};

std::vector<handler_case_t> ida_read_handler_cases(const std::string& bin_name)
{
    std::vector<handler_case_t> cases = {
        {"lookup_funcs", {{"addresses", json::array({"0x140001000"})}}, "items"},
        {"int_convert", {{"value", "41"}, {"from_format", "hex"}, {"to_format", "decimal"}}, "output"},
        {"list_funcs", {{"offset", 0}, {"limit", 2}}, "functions"},
        {"list_globals", {{"offset", 0}, {"limit", 2}}, "globals"},
        {"imports", {{"offset", 0}, {"limit", 2}}, "imports"},
        {"decompile", {{"address", "0x140001000"}, {"use_cache", false}}, "pseudocode"},
        {"disasm", {{"address", "0x140001000"}, {"max_instructions", 8}}, "instructions"},
        {"xrefs_to", {{"address", "0x140001000"}, {"limit", 2}, {"kind", "all"}}, "xrefs"},
        {"xrefs_to_field", {{"struct_name", "HarnessRecord"}, {"field_name", "marker"}, {"limit", 2}}, "xrefs"},
        {"callees", {{"address", "0x140001000"}, {"include_indirect", true}}, "callees"},
        {"get_bytes", {{"address", "0x140001000"}, {"size", 8}, {"hex", true}}, "hex"},
        {"get_int", {{"address", "0x140001000"}, {"size", 4}, {"signed", false}, {"endian", "little"}}, "value"},
        {"get_string", {{"address", "0x140001120"}, {"max_length", 64}, {"encoding", "ascii"}}, "value"},
        {"get_global_value", {{"address", "0x140001000"}, {"size", 4}, {"as_type", "hex"}}, "value"},
        {"stack_frame", {{"address", "0x140001000"}, {"include_saved_regs", true}}, "slots"},
        {"read_struct", {{"address", "0x140001120"}, {"struct_name", "HarnessRecord"}, {"max_depth", 2}}, "fields"},
        {"search_structs", {{"name", "HarnessRecord"}, {"offset", 0}, {"limit", 2}}, "structs"},
        {"find_regex", {{"pattern", "AiDA"}, {"scope", "all"}, {"offset", 0}, {"limit", 2}}, "results"},
        {"find_bytes", {{"hex_pattern", "FF 15"}, {"offset", 0}, {"limit", 2}}, "results"},
        {"find_insns", {{"mnemonic", "call"}, {"offset", 0}, {"limit", 2}}, "results"},
        {"find", {{"query", "AiDA"}, {"kind", "all"}, {"offset", 0}, {"limit", 2}}, "results"},
        {"basic_blocks", {{"address", "0x140001000"}, {"include_instructions", true}}, "blocks"},
        {"export_funcs", {{"offset", 0}, {"limit", 2}}, "exports"},
        {"callgraph", {{"address", "0x140001000"}, {"depth", 1}, {"direction", "both"}, {"limit", 8}}, "nodes"}
    };
    for (auto& test : cases) {
        if (mcp_standalone::ida_compat::is_target_dependent_tool(test.name))
            test.arguments["bin_name"] = bin_name;
    }
    return cases;
}

std::vector<handler_case_t> ida_mutation_handler_cases(const std::string& bin_name)
{
    std::vector<handler_case_t> cases = {
        {"add_bookmark", {{"address", "0x1000"}, {"name", "harness_bookmark"}, {"comment", "compatibility dry run"}}, "items"},
        {"set_comments", {{"items", json{{"address", "0x1000"}, {"comment", "scalar comment"}}}}, "items"},
        {"patch_asm", {{"address", "0x1000"}, {"assembly", "nop"}}, "items"},
        {"declare_type", {{"name", "DryRunRecord"}, {"definition", "struct DryRunRecord { uint32_t value; };"}}, "items"},
        {"define_func", {{"address", "0x1020"}, {"end", "0x1022"}}, "items"},
        {"define_code", {{"address", "0x1020"}, {"size", 2}}, "items"},
        {"undefine", {{"address", "0x1020"}, {"size", 2}}, "items"},
        {"declare_stack", {{"address", "0x1000"}, {"items", json{{"offset", -8}, {"name", "local_value"}, {"type", "uint64_t"}, {"size", 8}}}}, "items"},
        {"delete_stack", {{"address", "0x1000"}, {"offsets", -8}}, "items"},
        {"set_type", {{"address", "0x1120"}, {"type", "uint32_t"}}, "items"},
        {"infer_types", {{"items", "0x1000"}}, "items"},
        {"analyze_funcs", {{"items", "0x1000"}}, "items"},
        {"rename", {{"address", "0x1000"}, {"name", "harness_entry"}}, "items"},
        {"patch", {{"address", "0x1000"}, {"hex_string", "90"}}, "items"},
        {"put_int", {{"address", "0x1120"}, {"value", "0x41424344"}, {"size", 4}, {"endian", "little"}}, "items"}
    };
    for (auto& test : cases) {
        test.arguments["bin_name"] = bin_name;
        test.arguments["aida_tx"] = json{{"dry_run", true}};
    }
    return cases;
}

void verify_ida_validation_and_targeting(mcp_standalone::server_t& server,
                                         const std::vector<std::shared_ptr<analysis_workspace_t>>& workspaces)
{
    if (workspaces.size() < 3)
        throw fixture_error_t("IDA target-routing coverage requires multiple workspaces");
    const auto read_cases = ida_read_handler_cases("gamma.exe");
    const auto mutation_cases = ida_mutation_handler_cases("gamma.exe");
    if (read_cases.size() != k_ida_read_tools.size() ||
        mutation_cases.size() != k_ida_mutation_tools.size())
        throw fixture_error_t("IDA compatibility handler-case inventory count mismatch");
    for (const char* name : k_ida_read_tools) {
        if (std::none_of(read_cases.begin(), read_cases.end(), [&](const auto& test) {
                return test.name == name;
            }))
            throw fixture_error_t(std::string("missing IDA read handler case: ") + name);
    }
    for (const char* name : k_ida_mutation_tools) {
        if (std::none_of(mutation_cases.begin(), mutation_cases.end(), [&](const auto& test) {
                return test.name == name;
            }))
            throw fixture_error_t(std::string("missing IDA mutation handler case: ") + name);
    }

    for (const auto& name : required_ida_tool_names())
        require_code(server.call_registered_tool(name, json{{"unexpected", true}}, true),
                     "MCP_TOOL_INPUT_SCHEMA_INVALID");

    for (const auto& test : read_cases) {
        if (!mcp_standalone::ida_compat::is_target_dependent_tool(test.name))
            continue;
        json implicit = test.arguments;
        implicit.erase("bin_name");
        implicit.erase("pid");
        require_code(server.call_registered_tool(test.name, implicit, true), "TARGET_REQUIRED");
    }
    for (const auto& test : mutation_cases) {
        json implicit = test.arguments;
        implicit.erase("bin_name");
        implicit.erase("pid");
        require_code(server.call_registered_tool(test.name, implicit, true), "TARGET_REQUIRED");
    }

    auto selected = read_cases.front().arguments;
    selected["bin_name"] = "gamma";
    if (!server.call_registered_tool(read_cases.front().name, selected, true).success)
        throw fixture_error_t("unique bin_name substring selector did not resolve");
    selected["pid"] = 1;
    require_code(server.call_registered_tool(read_cases.front().name, selected, true), "TARGET_CONFLICT");
    selected.erase("pid");
    selected["bin_name"] = "duplicate.exe";
    require_code(server.call_registered_tool(read_cases.front().name, selected, true), "TARGET_AMBIGUOUS");
    selected["bin_name"] = "missing-workspace.exe";
    require_code(server.call_registered_tool(read_cases.front().name, selected, true), "TARGET_NOT_FOUND");
    selected.erase("bin_name");
    selected["pid"] = 4294967295ULL;
    require_code(server.call_registered_tool(read_cases.front().name, selected, true), "TARGET_NOT_FOUND");

    const json non_object_request = {
        {"jsonrpc", "2.0"}, {"id", "non-object"}, {"method", "tools/call"},
        {"params", {{"name", "int_convert"}, {"arguments", json::array()}}}
    };
    const auto non_object_response = json::parse(
        mcp_standalone::handle_body(&server, non_object_request.dump()));
    if (!non_object_response.contains("error") ||
        non_object_response["error"].value("code", 0) != mcp_standalone::JSONRPC_INVALID_PARAMS ||
        non_object_response["error"]["data"].value("code", std::string()) !=
            "MCP_TOOL_ARGUMENTS_MUST_BE_OBJECT")
        throw fixture_error_t("JSON-RPC non-object arguments were not rejected before dispatch");

    auto cancelled_token = mcp_standalone::make_call_cancel_token(true);
    {
        mcp_standalone::scoped_call_cancel_t cancellation(cancelled_token);
        require_code(server.call_registered_tool("int_convert",
            json{{"value", "1"}}, true), "MCP_TOOL_INPUT_VALIDATION_CANCELLED");
    }
    const std::uint64_t now = static_cast<std::uint64_t>(GetTickCount64());
    {
        mcp_standalone::scoped_call_metadata_t metadata(
            "workspace-mcp-deadline", "workspace-mcp-deadline", "int_convert", now == 0 ? 1 : now - 1);
        require_code(server.call_registered_tool("int_convert",
            json{{"value", "1"}}, true), "MCP_TOOL_INPUT_VALIDATION_DEADLINE_EXCEEDED");
    }
}

void exercise_ida_mutation_handlers(mcp_standalone::server_t& server,
                                    const std::shared_ptr<analysis_workspace_t>& workspace)
{
    if (!workspace || !workspace->overlay())
        throw fixture_error_t("mutation handler coverage requires an overlay-backed workspace");
    const std::string selector = workspace->identity().bin_name();
    const auto before = workspace->overlay()->snapshot();

    for (const auto& test : ida_mutation_handler_cases(selector)) {
        const auto result = server.call_registered_tool(test.name, test.arguments, true);
        if (test.name == "infer_types" && !result.success) {
            if (result.error_code != "VALIDATION_FAILED" || !result.data.contains("items") ||
                !result.data["items"].is_array() || result.data["items"].size() != 1 ||
                !result.data["items"][0].contains("error"))
                throw fixture_error_t("infer_types did not return its ordered production item result");
            const std::string code = result.data["items"][0]["error"].value("code", std::string());
            if (code != "NO_INFERENCE" && code != "ANALYSIS_FAILED")
                throw fixture_error_t("infer_types returned an unexpected item error: " + code);
            continue;
        }
        if (!result.success || !result.data.value("dry_run", false) ||
            result.data.value("committed", true) || !result.data.contains(test.result_field) ||
            !result.data[test.result_field].is_array() || result.data[test.result_field].empty())
            throw fixture_error_t(test.name + " did not execute a reversible dry-run handler path");
    }
    const auto after_dry_runs = workspace->overlay()->snapshot();
    if (after_dry_runs.revision != before.revision ||
        after_dry_runs.items.size() != before.items.size())
        throw fixture_error_t("mutation dry-run changed overlay state");

    const auto ordered = server.call_registered_tool("set_comments", {
        {"bin_name", selector},
        {"items", json::array({
            json{{"address", "bad-address-0"}, {"comment", "first"}},
            json{{"address", "bad-address-1"}, {"comment", "second"}}
        })},
        {"aida_tx", {{"dry_run", true}}}
    }, true);
    require_code(ordered, "VALIDATION_FAILED");
    if (!ordered.data.contains("items") || !ordered.data["items"].is_array() ||
        ordered.data["items"].size() != 2 ||
        ordered.data["items"][0].value("index", 99u) != 0 ||
        ordered.data["items"][1].value("index", 99u) != 1 ||
        ordered.data["items"][0]["error"].value("code", std::string()) != "INVALID_PARAM" ||
        ordered.data["items"][1]["error"].value("code", std::string()) != "INVALID_PARAM")
        throw fixture_error_t("mutation per-item errors were not preserved in request order");

    auto commit = require_success(server, "declare_type", {
        {"bin_name", selector},
        {"name", "HarnessRecord"},
        {"definition", "struct HarnessRecord { uint32_t marker; uint16_t flags; };"},
        {"aida_tx", {{"expected_revision", before.revision},
                     {"idempotency_key", "workspace-mcp-declare-type"}}}
    });
    if (!commit.data.value("committed", false) || commit.data.value("dry_run", true) ||
        commit.data.value("transaction_id", 0ULL) == 0)
        throw fixture_error_t("declare_type transaction did not commit");

    const auto declaration_revision = workspace->overlay()->snapshot().revision;
    auto application = require_success(server, "set_type", {
        {"bin_name", selector},
        {"address", "0x1120"},
        {"type", "HarnessRecord"},
        {"aida_tx", {{"expected_revision", declaration_revision},
                     {"idempotency_key", "workspace-mcp-apply-type"}}}
    });
    if (!application.data.value("committed", false) || application.data.value("dry_run", true))
        throw fixture_error_t("set_type transaction did not commit");
}

void exercise_ida_read_handlers(mcp_standalone::server_t& server,
                                const std::shared_ptr<analysis_workspace_t>& workspace)
{
    if (!workspace)
        throw fixture_error_t("read handler coverage requires a workspace");
    const std::string binary_id = workspace->identity().binary_id().to_hex();
    for (const auto& test : ida_read_handler_cases(workspace->identity().bin_name())) {
        const auto result = require_success(server, test.name, test.arguments);
        if (!result.data.is_object() || !result.data.contains(test.result_field))
            throw fixture_error_t(test.name + " result omitted required field " + test.result_field);
        if (mcp_standalone::ida_compat::is_target_dependent_tool(test.name) &&
            result.data["_meta"]["aida"].value("binary_id", std::string()) != binary_id)
            throw fixture_error_t(test.name + " handler returned the wrong workspace identity");
        if (result.data.dump().size() > (1U << 20))
            throw fixture_error_t(test.name + " exceeded the compatibility result bound");
    }

    auto first_page = require_success(server, "list_funcs", {
        {"bin_name", workspace->identity().bin_name()}, {"offset", 0}, {"limit", 1}});
    if (!first_page.data["functions"].is_array() || first_page.data["functions"].size() != 1 ||
        first_page.data.value("count", 0u) != 1 || first_page.data.value("total", 0u) < 2 ||
        !first_page.data["next_offset"].is_number_integer())
        throw fixture_error_t("list_funcs first pagination page is incompatible");
    const auto next_offset = first_page.data["next_offset"].get<std::uint64_t>();
    auto second_page = require_success(server, "list_funcs", {
        {"bin_name", workspace->identity().bin_name()}, {"offset", next_offset}, {"limit", 1}});
    if (!second_page.data["functions"].is_array() || second_page.data["functions"].size() > 1 ||
        (!second_page.data["functions"].empty() &&
         second_page.data["functions"][0].value("address", std::string()) ==
             first_page.data["functions"][0].value("address", std::string())))
        throw fixture_error_t("list_funcs pagination repeated or exceeded its result limit");

    require_code(server.call_registered_tool("list_funcs", {
        {"bin_name", workspace->identity().bin_name()}, {"limit", 10001}}, true),
        "MCP_TOOL_INPUT_SCHEMA_INVALID");
    require_code(server.call_registered_tool("get_bytes", {
        {"bin_name", workspace->identity().bin_name()}, {"address", "0x140001000"},
        {"size", 65537}}, true), "MCP_TOOL_INPUT_SCHEMA_INVALID");

    auto scalar_lookup = require_success(server, "lookup_funcs", {
        {"bin_name", workspace->identity().bin_name()}, {"names", "missing-scalar-function"}});
    auto array_lookup = require_success(server, "lookup_funcs", {
        {"bin_name", workspace->identity().bin_name()},
        {"names", json::array({"missing-array-function-0", "missing-array-function-1"})}});
    if (scalar_lookup.data["items"].size() != 1 || array_lookup.data["items"].size() != 2 ||
        array_lookup.data["items"][0].value("input", std::string()) != "missing-array-function-0" ||
        array_lookup.data["items"][1].value("input", std::string()) != "missing-array-function-1" ||
        !array_lookup.data["items"][0].contains("error") ||
        !array_lookup.data["items"][1].contains("error"))
        throw fixture_error_t("lookup_funcs scalar/array normalization or ordered errors diverged");
}

void exercise_calculator_handlers(mcp_standalone::server_t& server)
{
    const json expression = {{"expression", "(1 << 65) + 3"}, {"format", "decimal"}};
    const auto calculator = require_success(server, "calculator", expression);
    const auto calculate = require_success(server, "calculate", expression);
    if (calculator.data != calculate.data ||
        calculator.data.value("value", std::string()) != "36893488147419103235")
        throw fixture_error_t("calculator aliases or arbitrary-precision result diverged");

    const auto ordered = require_success(server, "calculator", {
        {"items", json::array({
            json{{"id", "first"}, {"expression", "1 / 0"}, {"format", "decimal"}},
            json{{"id", "second"}, {"expression", "1 + 1"}, {"format", "decimal"}}
        })}
    });
    if (ordered.data.value("count", 0u) != 2 || !ordered.data["results"].is_array() ||
        ordered.data["results"][0].value("id", std::string()) != "first" ||
        ordered.data["results"][0].value("success", true) ||
        ordered.data["results"][1].value("id", std::string()) != "second" ||
        !ordered.data["results"][1].value("success", false))
        throw fixture_error_t("calculator per-item results were not preserved in request order");

    const auto scalar = require_success(server, "calculator", {
        {"items", json{{"id", "scalar"}, {"expression", "6 * 7"}, {"format", "decimal"}}}
    });
    if (scalar.data.value("count", 0u) != 1 ||
        scalar.data["results"][0].value("id", std::string()) != "scalar" ||
        !scalar.data["results"][0].value("success", false))
        throw fixture_error_t("calculator scalar item normalization failed");

    json too_many = json::array();
    for (std::size_t index = 0; index < 129; ++index)
        too_many.push_back(json{{"expression", "1"}});
    require_code(server.call_registered_tool("calculator", {{"items", std::move(too_many)}}, true),
        "MCP_TOOL_INPUT_SCHEMA_INVALID");
}

void verify_registered_handler_interrupts(mcp_standalone::server_t& server,
                                          const std::shared_ptr<analysis_workspace_t>& workspace)
{
    if (!workspace)
        throw fixture_error_t("handler interrupt coverage requires a workspace");
    auto context = mcp_standalone::workspace_request_context_t{};
    context.workspace = workspace;
    context.kind = workspace->target_kind();
    context.binary_id = workspace->identity().binary_id();
    context.analysis_revision = workspace->analysis_revision();
    context.overlay_revision = workspace->overlay_revision();

    std::atomic<bool> cancelled{true};
    context.cancellation = &cancelled;
    auto read_cancelled = registered_tool(server, "find_regex").workspace_handler(
        json{{"pattern", "AiDA"}}, context);
    require_code(read_cancelled, "CANCELLED");
    auto mutation_cancelled = registered_tool(server, "set_comments").workspace_handler(
        json{{"items", json{{"address", "0x1000"}, {"comment", "cancelled"}}}}, context);
    require_code(mutation_cancelled, "CANCELLED");

    cancelled.store(false, std::memory_order_release);
    context.deadline_ms = static_cast<std::uint64_t>(GetTickCount64());
    auto deadline = registered_tool(server, "find_regex").workspace_handler(
        json{{"pattern", "AiDA"}}, context);
    require_code(deadline, "DEADLINE_EXCEEDED");
}

void undo_ida_type_fixtures(const std::shared_ptr<analysis_workspace_t>& workspace)
{
    if (!workspace || !workspace->overlay())
        throw fixture_error_t("overlay undo coverage requires a workspace");
    const auto before = workspace->overlay()->snapshot();
    auto first = workspace->overlay()->undo(before.revision);
    if (!first || !first.value().committed || first.value().dry_run)
        throw fixture_error_t("overlay undo did not revert the type application transaction");
    const auto middle = workspace->overlay()->snapshot();
    auto second = workspace->overlay()->undo(middle.revision);
    if (!second || !second.value().committed || second.value().dry_run)
        throw fixture_error_t("overlay undo did not revert the type declaration transaction");
    const auto after = workspace->overlay()->snapshot();
    if (before.items.size() < 2 || after.items.size() + 2 != before.items.size())
        throw fixture_error_t("overlay undo did not remove both compatibility fixtures");
}

void exercise_static_routes(mcp_standalone::server_t& server,
                            const std::vector<std::shared_ptr<analysis_workspace_t>>& workspaces)
{
    auto listed = server.call_registered_tool("list_instances", json::object(), true);
    if (!listed.success || listed.data.value("count", 0) != workspaces.size() ||
        !listed.data["default_pid"].is_null())
        throw fixture_error_t("list_instances static envelope mismatch");
    require_code(server.call_registered_tool("disasm_list_functions", json::object(), true),
                 "TARGET_REQUIRED");
    require_code(server.call_registered_tool("disasm_list_functions",
        json{{"bin_name", "duplicate.exe"}}, true), "TARGET_AMBIGUOUS");
    require_code(server.call_registered_tool("disasm_list_functions",
        json{{"bin_name", "gamma.exe"}, {"pid", 1}}, true), "TARGET_CONFLICT");
    require_code(server.call_registered_tool("disasm_list_functions",
        json{{"binary_id", "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"}}, true), "TARGET_NOT_FOUND");
    auto substring = server.call_registered_tool("disasm_list_functions",
        json{{"bin_name", "gamma"}, {"offset", 0}, {"limit", 4}}, true);
    if (!substring.success)
        throw fixture_error_t("unique bin_name substring did not resolve");
    auto imports = server.call_registered_tool("analysis_query",
        json{{"action", "imports"},
             {"binary_id", workspaces.front()->identity().binary_id().to_hex()}}, true);
    if (!imports.success || !imports.data.contains("imports"))
        throw fixture_error_t("workspace analysis handler did not use the resolved target");
    const auto first_id = workspaces.front()->identity().binary_id().to_hex();
    auto instruction_va = server.call_registered_tool("disasm_get_instruction",
        json{{"address", "0x140001000"}, {"binary_id", first_id}}, true);
    auto instruction_rva = server.call_registered_tool("disasm_get_instruction",
        json{{"address", "0x1000"}, {"binary_id", first_id}}, true);
    if (!instruction_va.success || !instruction_rva.success ||
        instruction_va.data.value("address", std::string()) !=
            instruction_rva.data.value("address", std::string()) ||
        instruction_va.data.value("address", std::string()) != "0x140001000")
        throw fixture_error_t("static VA/RVA instruction normalization diverged");
    auto bounds_va = server.call_registered_tool("disasm_get_function_bounds",
        json{{"address", "0x140001000"}, {"binary_id", first_id}}, true);
    auto bounds_rva = server.call_registered_tool("disasm_get_function_bounds",
        json{{"address", "0x1000"}, {"binary_id", first_id}}, true);
    if (!bounds_va.success || !bounds_rva.success ||
        bounds_va.data.value("start", std::string()) != bounds_rva.data.value("start", std::string()) ||
        bounds_va.data.value("end", std::string()) != bounds_rva.data.value("end", std::string()))
        throw fixture_error_t("static VA/RVA function-bound normalization diverged");
    auto decompile = server.call_registered_tool("decompile_function",
        json{{"address", "0x140001000"},
             {"binary_id", workspaces.front()->identity().binary_id().to_hex()},
             {"timeout_sec", 5}}, true);
    if (!decompile.success ||
        decompile.data.value("address", std::string()) != "0x140001000" ||
        decompile.data.value("function_name", std::string()).empty() ||
        decompile.data.value("pseudocode", std::string()).find_first_not_of(" \t\r\n") ==
            std::string::npos ||
        decompile.data.value("mapped_line_count", 0u) == 0 ||
        decompile.data["_meta"]["aida"].value("binary_id", std::string()) !=
            workspaces.front()->identity().binary_id().to_hex())
        throw fixture_error_t("static public MCP decompilation did not return mapped target-explicit pseudocode");

    auto overlap_gate = std::make_shared<workspace_overlap_gate_t>();
    if (!server.register_tool({
            "workspace_overlap_probe",
            "Exercise target-explicit workspace handler overlap for the source harness.",
            {{"tool_timeout_ms", "integer", "Bounded overlap probe timeout", false}},
            true, {}},
        [overlap_gate](const json&,
            const std::shared_ptr<analysis_workspace_t>& workspace) -> tool_result_t {
            std::unique_lock<std::mutex> lock(overlap_gate->mutex);
            ++overlap_gate->entered;
            ++overlap_gate->active;
            overlap_gate->peak_active = (std::max)(overlap_gate->peak_active,
                overlap_gate->active);
            overlap_gate->wake.notify_all();
            const bool released = overlap_gate->wake.wait_for(lock,
                std::chrono::seconds(5), [&] {
                    return overlap_gate->release || mcp_standalone::current_call_cancelled();
                });
            --overlap_gate->active;
            overlap_gate->wake.notify_all();
            if (!released || mcp_standalone::current_call_cancelled())
                return tool_result_t::error("workspace overlap probe cancelled",
                    "CANCELLED", json{{"entered", overlap_gate->entered}});
            return tool_result_t::ok(json{{"binary_id",
                workspace->identity().binary_id().to_hex()}});
        }))
        throw fixture_error_t("workspace overlap probe registration failed");

    std::vector<std::future<tool_result_t>> overlap_calls;
    for (const auto& workspace : workspaces) {
        overlap_calls.push_back(std::async(std::launch::async, [&server, workspace] {
            return server.call_registered_tool("workspace_overlap_probe",
                json{{"binary_id", workspace->identity().binary_id().to_hex()},
                     {"tool_timeout_ms", 10000}}, true);
        }));
    }
    bool all_entered = false;
    std::size_t peak_active = 0;
    {
        std::unique_lock<std::mutex> lock(overlap_gate->mutex);
        all_entered = overlap_gate->wake.wait_for(lock, std::chrono::seconds(5), [&] {
            return overlap_gate->entered == workspaces.size();
        });
        peak_active = overlap_gate->peak_active;
        overlap_gate->release = true;
    }
    overlap_gate->wake.notify_all();
    for (std::size_t index = 0; index < overlap_calls.size(); ++index) {
        const auto result = overlap_calls[index].get();
        if (!result.success || result.data.value("binary_id", std::string()) !=
                workspaces[index]->identity().binary_id().to_hex())
            throw fixture_error_t("workspace overlap probe returned the wrong target identity");
    }
    if (!all_entered || peak_active < 2 || peak_active != workspaces.size())
        throw fixture_error_t("different-workspace MCP handlers were globally serialized");

    const auto selected_before = workspace_registry().selected_binary_id();
    std::vector<std::future<tool_result_t>> calls;
    for (const auto& workspace : workspaces) {
        calls.push_back(std::async(std::launch::async, [&server, workspace] {
            return server.call_registered_tool("disasm_get_instruction",
                json{{"address", "0x140001000"},
                     {"binary_id", workspace->identity().binary_id().to_hex()}}, true);
        }));
    }
    for (std::size_t index = 0; index < calls.size(); ++index) {
        const auto result = calls[index].get();
        if (!result.success || result.data["_meta"]["aida"].value("binary_id", std::string()) !=
            workspaces[index]->identity().binary_id().to_hex())
            throw fixture_error_t("concurrent workspace MCP routing mismatch");
    }
    if (workspace_registry().selected_binary_id() != selected_before)
        throw fixture_error_t("MCP request changed UI workspace selection");

    for (std::size_t index = 0; index < workspaces.size(); ++index) {
        auto result = server.call_registered_tool("disasm_annotations_manage",
            json{{"action", "set_comment"}, {"address", "0x140001000"},
                 {"comment", "mcp-" + std::to_string(index)},
                 {"binary_id", workspaces[index]->identity().binary_id().to_hex()}}, true);
        if (!result.success)
            throw fixture_error_t("workspace overlay MCP mutation failed");
    }
    for (std::size_t index = 0; index < workspaces.size(); ++index) {
        const auto overlay = workspaces[index]->overlay()->snapshot();
        if (overlay.items.size() != 1 || overlay.items.front().second.text !=
            "mcp-" + std::to_string(index))
            throw fixture_error_t("MCP overlay crossed workspace identity");
    }
    auto comment_rva = server.call_registered_tool("disasm_annotations_manage",
        json{{"action", "get_comment"}, {"address", "0x1000"}, {"binary_id", first_id}}, true);
    if (!comment_rva.success || comment_rva.data.value("comment", std::string()) != "mcp-0" ||
        comment_rva.data.value("address", std::string()) != "0x140001000")
        throw fixture_error_t("static VA/RVA overlay normalization diverged");
}

void exercise_live_routes(mcp_standalone::server_t& server, const live_arguments_t& arguments)
{
    open_live_workspace_request_t self_request;
    self_request.bin_name = "self-refusal";
    self_request.snapshot.pid = GetCurrentProcessId();
    self_request.snapshot.module_base = arguments.module_base;
    self_request.snapshot.module_size = arguments.module_size;
    self_request.snapshot.module_name = arguments.module_name;
    self_request.snapshot.module_path = arguments.module_path;
    self_request.snapshot.capture_address = {address_space_id_t::live_virtual,
        arguments.module_base, architecture_id_t::x86_64, architecture_mode_t::x86_64};
    self_request.snapshot.capture_size = (std::min<std::uint64_t>)(arguments.module_size, 1ULL << 20);
    auto self = workspace_registry().open_live(self_request);
    if (self || self.error().code != workspace_error_code_t::self_target_refused)
        throw fixture_error_t("self PID snapshot was not refused");

    auto request = self_request;
    request.bin_name = "live-fixture";
    request.snapshot.pid = arguments.pid;
    auto live = workspace_registry().open_live(request);
    if (!live)
        throw fixture_error_t(live.error().stable_code() + ":" + live.error().message);
    const auto before = sha256_provider(live.value()->provider());
    if (!before)
        throw fixture_error_t(before.error().message);
    auto listed = server.call_registered_tool("list_instances", json::object(), true);
    if (!listed.success || listed.data.value("count", 0) != 1 ||
        listed.data.value("default_pid", 0u) != arguments.pid ||
        listed.data["instances"][0].value("backend", std::string()) != "aida_driver_live")
        throw fixture_error_t("list_instances live envelope mismatch");
    auto instruction = server.call_registered_tool("disasm_get_instruction",
        json{{"pid", arguments.pid}, {"address", std::to_string(arguments.module_base)}}, true);
    if (!instruction.success || instruction.data["_meta"]["aida"].value("pid", 0u) != arguments.pid)
        throw fixture_error_t("bounded live workspace instruction query failed");
    auto compatibility_pid = server.call_registered_tool("get_bytes",
        json{{"pid", arguments.pid}, {"address", std::to_string(arguments.module_base)}, {"size", 8}}, true);
    if (compatibility_pid.success || compatibility_pid.error_code != "NO_PROVIDER" ||
        compatibility_pid.error_details["_meta"]["aida"].value("pid", 0u) != arguments.pid)
        throw fixture_error_t("IDA compatibility PID selector did not reach the resolved live handler");
    auto bulk = server.call_registered_tool("disasm_list_functions",
        json{{"pid", arguments.pid}}, true);
    require_code(bulk, "LIVE_TARGET_BULK_ANALYSIS_UNSUPPORTED");
    target_selector_t stale_selector;
    stale_selector.pid = arguments.pid;
    const auto& process = live.value()->identity().process();
    if (!process)
        throw fixture_error_t("live workspace lost its process creation identity");
    stale_selector.process_creation_time_100ns =
        process->creation_time_100ns == (std::numeric_limits<std::uint64_t>::max)()
            ? process->creation_time_100ns - 1
            : process->creation_time_100ns + 1;
    auto stale = workspace_registry().resolve(stale_selector);
    if (stale || stale.error().code != workspace_error_code_t::target_stale)
        throw fixture_error_t("internal PID-reuse identity mismatch did not return TARGET_STALE");
    auto annotation = server.call_registered_tool("disasm_annotations_manage",
        json{{"pid", arguments.pid}, {"action", "set_comment"},
             {"address", std::to_string(arguments.module_base)}, {"comment", "live-overlay"}}, true);
    if (!annotation.success)
        throw fixture_error_t("live presentation overlay failed");
    auto live_decompile = server.call_registered_tool("decompile_function",
        json{{"pid", arguments.pid},
             {"address", std::to_string(arguments.module_base)},
             {"timeout_sec", 5}}, true);
    if (!live_decompile.success)
        throw fixture_error_t("live decompile did not return a result: " + live_decompile.error_code);
    if (live_decompile.data.value("pseudocode", std::string()).find_first_not_of(" \t\r\n") ==
            std::string::npos ||
        live_decompile.data.value("mapped_line_count", 0u) == 0 ||
        live_decompile.data["_meta"]["aida"].value("pid", 0u) != arguments.pid)
        throw fixture_error_t("live decompile did not return mapped target-explicit pseudocode");
    const auto after = sha256_provider(live.value()->provider());
    if (!after || after.value() != before.value())
        throw fixture_error_t("live snapshot bytes changed after presentation overlay");
    close_workspace(live.value(), true);
    require_code(server.call_registered_tool("list_funcs",
        json{{"pid", arguments.pid}, {"offset", 0}, {"limit", 1}}, true), "TARGET_NOT_FOUND");
}

void exercise_disassemble_file_route(mcp_standalone::server_t& server,
                                     const std::filesystem::path& path)
{
    std::unordered_set<std::string> before;
    for (const auto& workspace : workspace_registry().list())
        before.insert(workspace->identity().binary_id().to_hex());
    const auto result = server.call_registered_tool("disassemble_file",
        json{{"path", path.u8string()}, {"count", 8}}, true);
    std::shared_ptr<analysis_workspace_t> created;
    for (const auto& workspace : workspace_registry().list()) {
        if (before.count(workspace->identity().binary_id().to_hex()) == 0) {
            created = workspace;
            break;
        }
    }
    try {
        if (!result.success || !result.data.contains("instructions") ||
            !result.data["instructions"].is_array() || result.data["instructions"].empty() ||
            result.data.value("instruction_count", 0u) != result.data["instructions"].size() ||
            result.data.value("exec_section_count", 0u) == 0 ||
            result.data.value("exec_byte_count", 0u) == 0 ||
            result.data["_meta"]["aida"].value("binary_id", std::string()).empty())
            throw fixture_error_t("disassemble_file did not return a real workspace publication page");
    } catch (...) {
        if (created)
            close_workspace(created, true);
        throw;
    }
    if (!created)
        throw fixture_error_t("disassemble_file did not create its canonical-profile workspace");
    close_workspace(created, true);
}

}

int main(int argc, char** argv)
{
    std::vector<std::shared_ptr<aida::analysis::analysis_workspace_t>> workspaces;
    try {
        const auto live_arguments = parse_live_arguments(argc, argv);
        verify_surface_manifests();
        fixture_root_t root("mcp");
        const std::vector<std::string> directories{"alpha", "beta", "gamma", "delta"};
        const std::vector<std::string> names{"duplicate.exe", "duplicate.exe", "gamma.exe", "delta.exe"};
        std::vector<std::filesystem::path> fixture_paths;
        for (std::size_t index = 0; index < names.size(); ++index) {
            auto path = write_bytes_fixture(root.path() / directories[index] / names[index],
                analysis_contract_pe64(static_cast<std::uint8_t>(60 + index)));
            fixture_paths.push_back(path);
            auto workspace = open_workspace(path, names[index]);
            install_services(workspace);
            analyze_workspace(workspace, static_cast<std::uint32_t>((index % 2) + 1));
            workspaces.push_back(std::move(workspace));
        }
        mcp_standalone::server_t server;
        mcp_standalone::register_standalone_tools(server);
        mcp_standalone::set_ide_lifecycle_ready(true);
        verify_ida_registration_surface(server);
        verify_ida_validation_and_targeting(server, workspaces);
        exercise_calculator_handlers(server);
        exercise_disassemble_file_route(server, fixture_paths.front());
        exercise_static_routes(server, workspaces);
        auto compatibility_workspace = workspaces[2];
        exercise_ida_mutation_handlers(server, compatibility_workspace);
        exercise_ida_read_handlers(server, compatibility_workspace);
        verify_registered_handler_interrupts(server, compatibility_workspace);
        undo_ida_type_fixtures(compatibility_workspace);
        for (std::size_t index = 1; index < workspaces.size(); ++index)
            close_workspace(workspaces[index], true);
        workspaces.erase(workspaces.begin() + 1, workspaces.end());
        auto implicit = server.call_registered_tool("disasm_list_functions",
            json{{"offset", 0}, {"limit", 4}}, true);
        if (!implicit.success)
            throw fixture_error_t("single workspace selector omission failed");
        auto implicit_compatibility = server.call_registered_tool("list_funcs",
            json{{"offset", 0}, {"limit", 1}}, true);
        if (!implicit_compatibility.success)
            throw fixture_error_t("single workspace IDA compatibility selector omission failed");
        const auto closed_id = workspaces.front()->identity().binary_id().to_hex();
        const auto closed_name = workspaces.front()->identity().bin_name();
        close_workspace(workspaces.front(), true);
        workspaces.clear();
        require_code(server.call_registered_tool("disasm_list_functions",
            json{{"binary_id", closed_id}}, true), "TARGET_NOT_FOUND");
        require_code(server.call_registered_tool("list_funcs",
            json{{"bin_name", closed_name}, {"offset", 0}, {"limit", 1}}, true),
            "TARGET_NOT_FOUND");
        exercise_live_routes(server, live_arguments);
        std::cout << "workspace_mcp_harness source contract satisfied\n";
        return 0;
    } catch (const std::exception& error) {
        for (auto& workspace : workspaces) {
            try { close_workspace(workspace, true); } catch (...) {}
        }
        std::cerr << error.what() << '\n';
        return 1;
    }
}
