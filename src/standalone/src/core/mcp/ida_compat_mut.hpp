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
    using mut_handler_t = std::function<tool_result_t(
        const json& params,
        const workspace_request_context_t& ctx)>;

    tool_result_t tool_add_bookmark(const json& params, const workspace_request_context_t& ctx);
    tool_result_t tool_set_comments(const json& params, const workspace_request_context_t& ctx);
    tool_result_t tool_patch_asm(const json& params, const workspace_request_context_t& ctx);
    tool_result_t tool_declare_type(const json& params, const workspace_request_context_t& ctx);
    tool_result_t tool_define_func(const json& params, const workspace_request_context_t& ctx);
    tool_result_t tool_define_code(const json& params, const workspace_request_context_t& ctx);
    tool_result_t tool_undefine(const json& params, const workspace_request_context_t& ctx);
    tool_result_t tool_declare_stack(const json& params, const workspace_request_context_t& ctx);
    tool_result_t tool_delete_stack(const json& params, const workspace_request_context_t& ctx);
    tool_result_t tool_set_type(const json& params, const workspace_request_context_t& ctx);
    tool_result_t tool_infer_types(const json& params, const workspace_request_context_t& ctx);
    tool_result_t tool_analyze_funcs(const json& params, const workspace_request_context_t& ctx);
    tool_result_t tool_rename(const json& params, const workspace_request_context_t& ctx);
    tool_result_t tool_patch(const json& params, const workspace_request_context_t& ctx);
    tool_result_t tool_put_int(const json& params, const workspace_request_context_t& ctx);

    struct mut_tool_def_t
    {
        const char* name;
        mut_handler_t handler;
        bool read_only = false;
    };

    std::vector<mut_tool_def_t> get_mutation_tool_defs();
    void register_mutation_tools(server_t& server);
}
