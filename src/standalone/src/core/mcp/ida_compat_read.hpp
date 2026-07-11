#pragma once

#include "mcp_standalone.hpp"
#include "ida_compat_schemas.hpp"

#include <nlohmann/json.hpp>

#include <functional>
#include <string>
#include <vector>

namespace mcp_standalone::ida_compat
{
    using json = nlohmann::json;
    using read_handler_t = std::function<tool_result_t(
        const json& params,
        const workspace_request_context_t& ctx)>;

    tool_result_t tool_lookup_funcs(const json& params, const workspace_request_context_t& ctx);
    tool_result_t tool_int_convert(const json& params, const workspace_request_context_t& ctx);
    tool_result_t tool_list_funcs(const json& params, const workspace_request_context_t& ctx);
    tool_result_t tool_list_globals(const json& params, const workspace_request_context_t& ctx);
    tool_result_t tool_imports(const json& params, const workspace_request_context_t& ctx);
    tool_result_t tool_decompile(const json& params, const workspace_request_context_t& ctx);
    tool_result_t tool_disasm(const json& params, const workspace_request_context_t& ctx);
    tool_result_t tool_xrefs_to(const json& params, const workspace_request_context_t& ctx);
    tool_result_t tool_xrefs_to_field(const json& params, const workspace_request_context_t& ctx);
    tool_result_t tool_callees(const json& params, const workspace_request_context_t& ctx);
    tool_result_t tool_get_bytes(const json& params, const workspace_request_context_t& ctx);
    tool_result_t tool_get_int(const json& params, const workspace_request_context_t& ctx);
    tool_result_t tool_get_string(const json& params, const workspace_request_context_t& ctx);
    tool_result_t tool_get_global_value(const json& params, const workspace_request_context_t& ctx);
    tool_result_t tool_stack_frame(const json& params, const workspace_request_context_t& ctx);
    tool_result_t tool_read_struct(const json& params, const workspace_request_context_t& ctx);
    tool_result_t tool_search_structs(const json& params, const workspace_request_context_t& ctx);
    tool_result_t tool_find_regex(const json& params, const workspace_request_context_t& ctx);
    tool_result_t tool_find_bytes(const json& params, const workspace_request_context_t& ctx);
    tool_result_t tool_find_insns(const json& params, const workspace_request_context_t& ctx);
    tool_result_t tool_find(const json& params, const workspace_request_context_t& ctx);
    tool_result_t tool_basic_blocks(const json& params, const workspace_request_context_t& ctx);
    tool_result_t tool_export_funcs(const json& params, const workspace_request_context_t& ctx);
    tool_result_t tool_callgraph(const json& params, const workspace_request_context_t& ctx);
    tool_result_t tool_list_instances(const json& params, const workspace_request_context_t& ctx);

    struct read_tool_def_t
    {
        const char* name;
        read_handler_t handler;
    };

    std::vector<read_tool_def_t> get_read_tool_defs();
    void register_read_tools(server_t& server);
}
