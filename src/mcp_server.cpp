#include "aida_pro.hpp"
#include "ida_utils.hpp"
#include "subagents.hpp"

#include <queue>

using json = nlohmann::json;

static constexpr int JSONRPC_PARSE_ERROR      = -32700;
static constexpr int JSONRPC_INVALID_REQUEST  = -32600;
static constexpr int JSONRPC_METHOD_NOT_FOUND = -32601;
static constexpr int JSONRPC_INVALID_PARAMS   = -32602;
static constexpr int JSONRPC_INTERNAL_ERROR   = -32603;

static const std::string& get_mcp_protocol_version()
{
    static const std::string v = OBFSTR("2024-11-05");
    return v;
}
#define MCP_PROTOCOL_VERSION get_mcp_protocol_version().c_str()

static std::string generate_session_id()
{
    static const char hex[] = "0123456789abcdef";
    std::string id;
    id.reserve(32);
    std::srand(static_cast<unsigned>(std::time(nullptr))
             ^ static_cast<unsigned>(std::clock()));
    for (int i = 0; i < 32; ++i)
        id.push_back(hex[std::rand() % 16]);
    return id;
}

struct mcp_tool_exec_request_t : public exec_request_t
{
    std::string tool_name;
    json tool_params;
    agent_tools::tool_result_t result;
    std::shared_ptr<subagents::session_record_t> session;
    uint64_t run_id = 0;

    ssize_t idaapi execute() override
    {
        subagents::execution_context_scope_t scope(session, run_id);
        result = agent_tools::ToolRegistry::instance().execute_tool(tool_name, tool_params);
        return 0;
    }
};

struct mcp_resource_exec_request_t : public exec_request_t
{
    std::string tool_name;
    json tool_params;
    agent_tools::tool_result_t result;
    std::shared_ptr<subagents::session_record_t> session;
    uint64_t run_id = 0;

    ssize_t idaapi execute() override
    {
        subagents::execution_context_scope_t scope(session, run_id);
        result = agent_tools::ToolRegistry::instance().execute_tool(tool_name, tool_params);
        return 0;
    }
};

static json make_jsonrpc_result(const json& id, const json& result)
{
    return {
        {OBFSTR_C("jsonrpc"), OBFSTR_C("2.0")},
        {OBFSTR_C("id"),      id},
        {OBFSTR_C("result"),  result}
    };
}

static json make_jsonrpc_error(const json& id, int code, const std::string& message)
{
    return {
        {OBFSTR_C("jsonrpc"), OBFSTR_C("2.0")},
        {OBFSTR_C("id"),      id},
        {OBFSTR_C("error"),   {
            {OBFSTR_C("code"),    code},
            {OBFSTR_C("message"), message}
        }}
    };
}

struct mcp_resource_def_t
{
    std::string uri;
    std::string name;
    std::string description;
    std::string mime_type;
    std::string backing_tool;
    json        backing_params;
};

static const std::vector<mcp_resource_def_t>& get_resource_definitions()
{
    static const std::vector<mcp_resource_def_t> defs = {
        {
            "ida://binary-info",
            "Binary Information",
            "Metadata about the loaded binary (filename, architecture, base address, compiler, etc.)",
            "application/json",
            "get_binary_info",
            json::object()
        },
        {
            "ida://database-info",
            "Database Information",
            "IDA database (IDB) information including analysis state and statistics",
            "application/json",
            "get_binary_info",
            json::object()
        },
        {
            "ida://segments",
            "Segments",
            "List of all memory segments in the binary",
            "application/json",
            "list_segments",
            json::object()
        },
        {
            "ida://imports",
            "Imports",
            "List of all imported functions/symbols",
            "application/json",
            "list_imports",
            json::object()
        },
        {
            "ida://exports",
            "Exports",
            "List of all exported functions/symbols",
            "application/json",
            "list_exports",
            json::object()
        },
        {
            "ida://entry-points",
            "Entry Points",
            "Program entry points",
            "application/json",
            "list_exports",
            json::object()
        },
    };
    return defs;
}

struct mcp_prompt_arg_def_t
{
    std::string name;
    std::string description;
    bool required;
};

struct mcp_prompt_def_t
{
    std::string name;
    std::string description;
    std::vector<mcp_prompt_arg_def_t> arguments;
};

static const std::vector<mcp_prompt_def_t>& get_prompt_definitions()
{
    static const std::vector<mcp_prompt_def_t> defs = {
        {
            "analyze_function",
            "Perform a detailed reverse engineering analysis of a function in the loaded binary. Returns decompiled code, cross-references, and contextual information for AI analysis.",
            {{"address", "Function address in hex (e.g., '0x140001000') or function name", true}}
        },
        {
            "decompile_function",
            "Decompile a function to C/C++ pseudocode using the Hex-Rays decompiler and present it for explanation.",
            {{"address", "Function address in hex (e.g., '0x140001000') or function name", true}}
        },
        {
            "binary_overview",
            "Get a comprehensive overview of the loaded binary including metadata, segments, imports, exports, and entry points.",
            {}
        },
        {
            "explain_address",
            "Explain what exists at a specific address in the binary - function, data, string, etc.",
            {{"address", "Address in hex (e.g., '0x140001000')", true}}
        },
        {
            "find_vulnerabilities",
            "Analyze a function for potential security vulnerabilities including buffer overflows, format string issues, integer overflows, and memory corruption.",
            {{"address", "Function address in hex (e.g., '0x140001000') or function name", true}}
        }
    };
    return defs;
}

static agent_tools::tool_result_t execute_tool_in_main_thread(
    const std::string& name,
    const json& params)
{
    if (ida_utils::is_self_target_database())
        return agent_tools::tool_result_t::error("Operation blocked.");

    const auto* tool_def = agent_tools::ToolRegistry::instance().get_tool(name);
    if (!tool_def)
        return agent_tools::tool_result_t::error("Unknown tool: " + name);

    mcp_tool_exec_request_t req;
    req.tool_name = name;
    req.tool_params = params;
    req.session = subagents::current_session_record();
    req.run_id = subagents::current_run_id();

    int mff_flag = tool_def->read_only ? MFF_READ : MFF_WRITE;
    execute_sync(req, mff_flag);

    return req.result;
}

static agent_tools::tool_result_t execute_resource_read(const mcp_resource_def_t& rdef)
{
    mcp_resource_exec_request_t req;
    req.tool_name = rdef.backing_tool;
    req.tool_params = rdef.backing_params;
    req.session = subagents::current_session_record();
    req.run_id = subagents::current_run_id();
    execute_sync(req, MFF_READ);
    return req.result;
}

static std::string snake_to_title(const std::string& name)
{
    std::string title;
    title.reserve(name.size());
    bool capitalize_next = true;
    for (char c : name)
    {
        if (c == '_')
        {
            title += ' ';
            capitalize_next = true;
        }
        else
        {
            title += capitalize_next
                ? static_cast<char>(toupper(static_cast<unsigned char>(c)))
                : c;
            capitalize_next = false;
        }
    }
    return title;
}

static std::string compact_tool_text(const std::string& text, std::size_t max_len)
{
    std::string sanitized = sanitize_utf8(text);
    std::string compact;
    compact.reserve(sanitized.size());

    bool previous_was_space = false;
    for (unsigned char ch : sanitized)
    {
        if (std::isspace(ch) != 0)
        {
            if (!compact.empty() && !previous_was_space)
            {
                compact.push_back(' ');
                previous_was_space = true;
            }
            continue;
        }

        compact.push_back(static_cast<char>(ch));
        previous_was_space = false;
    }

    while (!compact.empty() && compact.back() == ' ')
        compact.pop_back();

    if (compact.size() <= max_len)
        return compact;

    std::size_t cut = compact.rfind('.', max_len);
    if (cut == std::string::npos || cut < max_len / 2)
        cut = compact.rfind(' ', max_len);
    if (cut == std::string::npos || cut < max_len / 2)
        cut = max_len;

    compact.erase(cut);
    while (!compact.empty() && compact.back() == ' ')
        compact.pop_back();
    compact += "...";
    return compact;
}

static bool is_destructive_tool(const std::string& name)
{
    return name == "delete_function"
        || name == "delete_breakpoint"
        || name == "delete_stack_var"
        || name == "patch_bytes"
        || name == "undefine"
        || name == "write_memory"
        || name == "exit_process";
}

static bool is_idempotent_tool(const std::string& name, bool read_only)
{
    if (read_only)
        return true;
    return name != "execute_python"
        && name != "step_into"
        && name != "step_over"
        && name != "step_out"
        && name != "continue_execution"
        && name != "start_process"
        && name != "exit_process"
        && name != "run_to_address"
        && name != "suspend";
}

static bool is_mcp_exposed_tool(const agent_tools::tool_definition_t* tool)
{
    return tool && tool->category != "session";
}

static json build_mcp_tools_list()
{
    json tools = json::array();
    const auto all_tools = agent_tools::ToolRegistry::instance().get_all_tools();

    for (const auto* tool : all_tools)
    {
        if (!is_mcp_exposed_tool(tool))
            continue;

        json input_schema = json::object();
        input_schema[OBFSTR_C("type")] = "object";

        json properties = json::object();
        json required_arr = json::array();

        for (const auto& param : tool->parameters)
        {
            json p;
            p[OBFSTR_C("type")] = param.type;
            p[OBFSTR_C("description")] = compact_tool_text(param.description, 160);
            if (!param.enum_values.empty())
                p["enum"] = param.enum_values;
            if (param.type == "array" && !param.items_schema.is_null())
                p["items"] = param.items_schema;
            else if (param.type == "array")
                p["items"] = json::object({{OBFSTR_C("type"), "object"}});
            properties[param.name] = p;
            if (param.required)
                required_arr.push_back(param.name);
        }

        input_schema["properties"] = properties;
        if (!required_arr.empty())
            input_schema["required"] = required_arr;

        json annotations;
        annotations["title"]           = snake_to_title(tool->name);
        annotations["readOnlyHint"]    = tool->read_only;
        annotations["destructiveHint"] = is_destructive_tool(tool->name);
        annotations["idempotentHint"]  = is_idempotent_tool(tool->name, tool->read_only);
        annotations["openWorldHint"]   = (tool->name == "execute_python");

        json t;
        t[OBFSTR_C("name")]        = tool->name;
        t[OBFSTR_C("description")] = compact_tool_text(tool->description, 320);
        t[OBFSTR_C("inputSchema")] = input_schema;
        t["annotations"] = annotations;
        tools.push_back(t);
    }

    return tools;
}

static json handle_initialize(const json& id, const json& )
{
    json capabilities;
    capabilities[OBFSTR_C("tools")]     = {{"listChanged", true}};
    capabilities[OBFSTR_C("resources")] = {{"listChanged", true}};
    capabilities[OBFSTR_C("prompts")]   = {{"listChanged", true}};
    capabilities["logging"]   = json::object();

    json server_info;
    server_info[OBFSTR_C("name")] = OBFSTR("AiDA - IDA Pro AI Assistant");
    server_info["version"] = AIDA_VERSION;

    json result;
    result[OBFSTR_C("protocolVersion")] = MCP_PROTOCOL_VERSION;
    result[OBFSTR_C("capabilities")] = capabilities;
    result[OBFSTR_C("serverInfo")] = server_info;
    result["instructions"] =
        "MANDATORY RULE: For ALL number base conversions (hexadecimal to decimal, decimal to "
        "hexadecimal, binary conversions, computing byte representations of integers, "
        "interpreting stack-constructed byte sequences as characters, ASCII character value "
        "lookups), you MUST use the `convert_number` tool. NEVER interpret hex byte values "
        "as ASCII characters manually or convert between number bases in your head. When you "
        "see values like 0x426D416C on the stack, you MUST call `convert_number` to decode "
        "them. Simple same-base arithmetic (e.g., 108 + 2 = 110) is fine to do mentally, but "
        "if you then need to know what ASCII character 110 represents, call `convert_number` "
        "with '110'. The tool accepts single numeric literals only — not arithmetic expressions. "
        "Violations on base conversions produce incorrect results.";

    return make_jsonrpc_result(id, result);
}

static json handle_ping(const json& id)
{
    return make_jsonrpc_result(id, json::object());
}

static json handle_tools_list(const json& id)
{
    json result;
    result[OBFSTR_C("tools")] = build_mcp_tools_list();
    return make_jsonrpc_result(id, result);
}

static json handle_tools_call(const json& id, const json& params)
{
    if (!params.contains(OBFSTR_C("name")) || !params[OBFSTR_C("name")].is_string())
        return make_jsonrpc_error(id, JSONRPC_INVALID_PARAMS, "Missing required field: 'name'");

    std::string tool_name = params[OBFSTR_C("name")].get<std::string>();
    json arguments = params.contains(OBFSTR_C("arguments")) && params["arguments"].is_object()
                   ? params["arguments"]
                   : json::object();

    const auto* tool = agent_tools::ToolRegistry::instance().get_tool(tool_name);
    if (!is_mcp_exposed_tool(tool))
        return make_jsonrpc_error(id, JSONRPC_INVALID_PARAMS, "Tool is not exposed through MCP");

    auto tool_result = execute_tool_in_main_thread(tool_name, arguments);

    json content = json::array();

    if (!tool_result.output.empty())
    {
        content.push_back({
            {OBFSTR_C("type"), "text"},
            {OBFSTR_C("text"), sanitize_utf8(tool_result.output)}
        });
    }

    if (!tool_result.data.is_null() && !tool_result.data.empty())
    {
        std::string data_text = json_dump_safe(tool_result.data, 2);
        content.push_back({
            {OBFSTR_C("type"), "text"},
            {OBFSTR_C("text"), sanitize_utf8(data_text)}
        });
    }

    if (content.empty())
    {
        content.push_back({
            {OBFSTR_C("type"), "text"},
            {OBFSTR_C("text"), tool_result.success ? "Tool executed successfully (no output)." : "Tool execution failed (no details)."}
        });
    }

    json result;
    result[OBFSTR_C("content")] = content;
    if (!tool_result.success)
        result["isError"] = true;

    return make_jsonrpc_result(id, result);
}

static json handle_resources_list(const json& id)
{
    json resources = json::array();
    for (const auto& rdef : get_resource_definitions())
    {
        json r;
        r[OBFSTR_C("uri")] = rdef.uri;
        r[OBFSTR_C("name")] = rdef.name;
        r[OBFSTR_C("description")] = rdef.description;
        r["mimeType"] = rdef.mime_type;
        resources.push_back(r);
    }

    json result;
    result[OBFSTR_C("resources")] = resources;
    return make_jsonrpc_result(id, result);
}

static json handle_resources_read(const json& id, const json& params)
{
    if (!params.contains(OBFSTR_C("uri")) || !params[OBFSTR_C("uri")].is_string())
        return make_jsonrpc_error(id, JSONRPC_INVALID_PARAMS, "Missing required field: 'uri'");

    std::string uri = params[OBFSTR_C("uri")].get<std::string>();

    const mcp_resource_def_t* found = nullptr;
    for (const auto& rdef : get_resource_definitions())
    {
        if (rdef.uri == uri)
        {
            found = &rdef;
            break;
        }
    }

    if (!found)
        return make_jsonrpc_error(id, JSONRPC_INVALID_PARAMS, "Unknown resource URI: " + uri);

    auto tool_result = execute_resource_read(*found);

    std::string text_content;
    if (!tool_result.data.is_null() && !tool_result.data.empty())
        text_content = json_dump_safe(tool_result.data, 2);
    else
        text_content = sanitize_utf8(tool_result.output);

    json contents = json::array();
    contents.push_back({
        {OBFSTR_C("uri"),      found->uri},
        {"mimeType", found->mime_type},
        {OBFSTR_C("text"),     text_content}
    });

    json result;
    result["contents"] = contents;
    return make_jsonrpc_result(id, result);
}

static json handle_resources_templates_list(const json& id)
{
    json templates = json::array();

    templates.push_back({
        {"uriTemplate", "ida://function/{address}"},
        {OBFSTR_C("name"), "Function by Address"},
        {OBFSTR_C("description"), "Access a function's decompiled code by its hexadecimal address"},
        {"mimeType", "application/json"}
    });

    templates.push_back({
        {"uriTemplate", "ida://address/{address}"},
        {OBFSTR_C("name"), "Address Information"},
        {OBFSTR_C("description"), "Get detailed information about any address in the binary"},
        {"mimeType", "application/json"}
    });

    json result;
    result["resourceTemplates"] = templates;
    return make_jsonrpc_result(id, result);
}

static json handle_prompts_list(const json& id)
{
    json prompts_arr = json::array();
    for (const auto& pdef : get_prompt_definitions())
    {
        json p;
        p[OBFSTR_C("name")] = pdef.name;
        p[OBFSTR_C("description")] = pdef.description;
        if (!pdef.arguments.empty())
        {
            json args = json::array();
            for (const auto& arg : pdef.arguments)
            {
                args.push_back({
                    {OBFSTR_C("name"), arg.name},
                    {OBFSTR_C("description"), arg.description},
                    {"required", arg.required}
                });
            }
            p["arguments"] = args;
        }
        prompts_arr.push_back(p);
    }

    json result;
    result[OBFSTR_C("prompts")] = prompts_arr;
    return make_jsonrpc_result(id, result);
}

struct mcp_rag_request_t : public exec_request_t
{
    std::string addr_str;
    json rag_result;
    bool resolved = false;

    explicit mcp_rag_request_t(const std::string& addr) : addr_str(addr) {}

    ssize_t idaapi execute() override
    {
        ea_t ea = BADADDR;
        if (!addr_str.empty())
        {
            ea = get_name_ea(BADADDR, addr_str.c_str());
            if (ea == BADADDR)
            {
                try
                {
                    std::string clean = addr_str;
                    if (clean.size() > 2
                        && clean[0] == '0'
                        && (clean[1] == 'x' || clean[1] == 'X'))
                    {
                        clean = clean.substr(2);
                    }
                    ea = static_cast<ea_t>(std::stoull(clean, nullptr, 16));
                }
                catch (...) {}
            }
        }

        if (ea != BADADDR)
        {
            rag_result = ida_utils::get_full_cached_context(ea, g_settings);
            resolved = rag_result.contains("ok") && rag_result["ok"].is_boolean()
                     && rag_result["ok"].get<bool>();
        }
        return 0;
    }
};

static std::string build_rag_section(const std::string& addr_str)
{
    mcp_rag_request_t req(addr_str);
    execute_sync(req, MFF_READ);

    if (!req.resolved)
        return "";

    std::string section;
    section.reserve(4096);

    std::string metadata = json_str(req.rag_result, "binary_metadata", "");
    std::string imports  = json_str(req.rag_result, "imports_context", "");
    std::string types    = json_str(req.rag_result, "type_context", "");
    std::string callers  = json_str(req.rag_result, "xrefs_to", "");
    std::string callees  = json_str(req.rag_result, "xrefs_from", "");
    std::string locals   = json_str(req.rag_result, "local_vars", "");
    std::string strings  = json_str(req.rag_result, "string_xrefs", "");
    std::string structs  = json_str(req.rag_result, "struct_context", "");

    if (!metadata.empty())
        section += "\n## Binary Context\n```\n" + metadata + "\n```\n";
    if (!imports.empty() && imports.find("No import") == std::string::npos
                         && imports.find("No function") == std::string::npos)
        section += "\n## Imports Used by Function\n```\n" + imports + "\n```\n";
    if (!types.empty() && types.find("No custom") == std::string::npos
                       && types.find("No function") == std::string::npos
                       && types.find("not available") == std::string::npos)
        section += "\n## Referenced Types\n```\n" + types + "\n```\n";
    if (!callers.empty() && callers.find("N/A") == std::string::npos
                         && callers.find("No ") == std::string::npos)
        section += "\n## Callers (xrefs to)\n```\n" + callers + "\n```\n";
    if (!callees.empty() && callees.find("N/A") == std::string::npos
                         && callees.find("No ") == std::string::npos)
        section += "\n## Callees (xrefs from)\n```\n" + callees + "\n```\n";
    if (!locals.empty() && locals.find("N/A") == std::string::npos
                        && locals.find("No ") == std::string::npos)
        section += "\n## Local Variables\n```\n" + locals + "\n```\n";
    if (!strings.empty() && strings.find("N/A") == std::string::npos
                         && strings.find("No ") == std::string::npos)
        section += "\n## String References\n" + strings + "\n";
    if (!structs.empty() && structs.find("N/A") == std::string::npos
                         && structs.find("No ") == std::string::npos)
        section += "\n## Struct Usage\n```\n" + structs + "\n```\n";

    return section;
}

static json handle_prompts_get(const json& id, const json& params)
{
    if (!params.contains(OBFSTR_C("name")) || !params[OBFSTR_C("name")].is_string())
        return make_jsonrpc_error(id, JSONRPC_INVALID_PARAMS, "Missing required field: 'name'");

    std::string name = params[OBFSTR_C("name")].get<std::string>();
    json arguments = params.value("arguments", json::object());

    const mcp_prompt_def_t* found = nullptr;
    for (const auto& pdef : get_prompt_definitions())
    {
        if (pdef.name == name)
        {
            found = &pdef;
            break;
        }
    }

    if (!found)
        return make_jsonrpc_error(id, JSONRPC_INVALID_PARAMS, "Unknown prompt: " + name);

    json messages = json::array();

    if (name == "analyze_function" || name == "decompile_function" || name == "find_vulnerabilities")
    {
        std::string addr_str = arguments.value("address", "");
        if (addr_str.empty())
            return make_jsonrpc_error(id, JSONRPC_INVALID_PARAMS, "Missing required argument: 'address'");

        auto decomp_result = execute_tool_in_main_thread("decompile_function", {{"address", addr_str}});
        std::string code_context;
        if (decomp_result.success)
            code_context = !decomp_result.data.is_null() ? json_dump_safe(decomp_result.data, 2) : decomp_result.output;
        else
            code_context = "Decompilation failed: " + decomp_result.output;

        std::string prompt_text;
        if (name == "analyze_function")
        {
            auto xrefs_result = execute_tool_in_main_thread("get_xrefs_to", {{"address", addr_str}});
            std::string xrefs_text;
            if (xrefs_result.success)
                xrefs_text = !xrefs_result.data.is_null() ? json_dump_safe(xrefs_result.data, 2) : xrefs_result.output;

            prompt_text =
                "Analyze the following function from a binary loaded in IDA Pro.\n"
                "Provide a detailed report covering:\n"
                "1. High-level purpose of the function\n"
                "2. Detailed logic flow (step-by-step)\n"
                "3. Function arguments and return value analysis\n"
                "4. Identified programming patterns\n"
                "5. Notable observations and potential use-cases\n\n"
                "## Decompiled Code\n```cpp\n" + code_context + "\n```\n";
            if (!xrefs_text.empty())
                prompt_text += "\n## Cross-References (callers)\n```json\n" + xrefs_text + "\n```\n";
        }
        else if (name == "decompile_function")
        {
            prompt_text =
                "Here is the decompiled C/C++ pseudocode of a function from IDA Pro.\n"
                "Please analyze this code and explain:\n"
                "1. What the function does\n"
                "2. Its parameters and return value\n"
                "3. Any notable patterns or algorithms used\n\n"
                "```cpp\n" + code_context + "\n```\n";
        }
        else if (name == "find_vulnerabilities")
        {
            prompt_text =
                "Analyze the following decompiled function for security vulnerabilities.\n"
                "Check for:\n"
                "- Buffer overflows and out-of-bounds access\n"
                "- Integer overflows and truncation issues\n"
                "- Format string vulnerabilities\n"
                "- Use-after-free and double-free conditions\n"
                "- Race conditions\n"
                "- Uninitialized memory usage\n"
                "- NULL pointer dereferences\n\n"
                "## Decompiled Code\n```cpp\n" + code_context + "\n```\n";
        }

        prompt_text += build_rag_section(addr_str);

        messages.push_back({
            {"role", "user"},
            {OBFSTR_C("content"), {{OBFSTR_C("type"), "text"}, {OBFSTR_C("text"), sanitize_utf8(prompt_text)}}}
        });
    }
    else if (name == "binary_overview")
    {
        auto info_result = execute_tool_in_main_thread("get_binary_info", json::object());
        auto segments_result = execute_tool_in_main_thread("list_segments", json::object());
        auto imports_result = execute_tool_in_main_thread("list_imports", json::object());
        auto exports_result = execute_tool_in_main_thread("list_exports", json::object());
        auto entries_result = execute_tool_in_main_thread("list_exports", json::object());

        std::string overview = "Provide a comprehensive analysis of the following binary loaded in IDA Pro.\n\n";

        if (info_result.success && !info_result.data.is_null())
            overview += "## Binary Metadata\n```json\n" + json_dump_safe(info_result.data, 2) + "\n```\n\n";
        if (segments_result.success && !segments_result.data.is_null())
            overview += "## Memory Segments\n```json\n" + json_dump_safe(segments_result.data, 2) + "\n```\n\n";
        if (entries_result.success && !entries_result.data.is_null())
            overview += "## Entry Points\n```json\n" + json_dump_safe(entries_result.data, 2) + "\n```\n\n";
        if (imports_result.success && !imports_result.data.is_null())
            overview += "## Imports\n```json\n" + json_dump_safe(imports_result.data, 2) + "\n```\n\n";
        if (exports_result.success && !exports_result.data.is_null())
            overview += "## Exports\n```json\n" + json_dump_safe(exports_result.data, 2) + "\n```\n\n";

        messages.push_back({
            {"role", "user"},
            {OBFSTR_C("content"), {{OBFSTR_C("type"), "text"}, {OBFSTR_C("text"), sanitize_utf8(overview)}}}
        });
    }
    else if (name == "explain_address")
    {
        std::string addr_str = arguments.value("address", "");
        if (addr_str.empty())
            return make_jsonrpc_error(id, JSONRPC_INVALID_PARAMS, "Missing required argument: 'address'");

        auto info_result = execute_tool_in_main_thread("get_address_info", {{"address", addr_str}});

        std::string text = "Explain what exists at address " + addr_str + " in the loaded binary:\n\n";
        if (info_result.success)
        {
            if (!info_result.data.is_null())
                text += "```json\n" + json_dump_safe(info_result.data, 2) + "\n```\n";
            else
                text += info_result.output;
        }
        else
        {
            text += "Could not retrieve information: " + info_result.output;
        }

        text += build_rag_section(addr_str);

        messages.push_back({
            {"role", "user"},
            {OBFSTR_C("content"), {{OBFSTR_C("type"), "text"}, {OBFSTR_C("text"), sanitize_utf8(text)}}}
        });
    }

    static const std::string convert_number_instruction =
        "MANDATORY RULE: For ALL number base conversions (hex to decimal, decimal to hex, "
        "binary, byte representations, ASCII lookups, or any cross-base arithmetic), you MUST "
        "use the `convert_number` tool. NEVER perform number conversions manually.";

    messages.insert(messages.begin(), {
        {"role", "user"},
        {OBFSTR_C("content"), {{OBFSTR_C("type"), "text"}, {OBFSTR_C("text"), convert_number_instruction}}}
    });

    json result;
    result[OBFSTR_C("description")] = found->description;
    result[OBFSTR_C("messages")] = messages;
    return make_jsonrpc_result(id, result);
}

static json handle_completion_complete(const json& id, const json& params)
{
    json argument = params.value("argument", json::object());
    std::string arg_name = argument.value("name", "");
    std::string arg_value = argument.value("value", "");

    json values = json::array();

    if (arg_name == "address" && !arg_value.empty())
    {
        auto result = execute_tool_in_main_thread("list_functions",
            {{"filter", arg_value}, {"limit", 20}});
        if (result.success && result.data.is_array())
        {
            for (const auto& func : result.data)
            {
                std::string display;
                if (func.contains(OBFSTR_C("name")) && func[OBFSTR_C("name")].is_string())
                    display = func[OBFSTR_C("name")].get<std::string>();
                else if (func.contains("address") && func["address"].is_string())
                    display = func["address"].get<std::string>();
                if (!display.empty())
                    values.push_back(display);
            }
        }
    }

    json completion;
    completion[OBFSTR_C("values")] = values;
    completion[OBFSTR_C("total")] = values.size();
    completion[OBFSTR_C("hasMore")] = false;
    return make_jsonrpc_result(id, completion);
}

static json dispatch_single_message(const json& msg)
{
    if (!msg.is_object())
        return make_jsonrpc_error(nullptr, JSONRPC_INVALID_REQUEST, OBFSTR("Request must be a JSON object"));

    std::string method = msg.value(OBFSTR_C("method"), "");
    if (method.empty())
        return make_jsonrpc_error(msg.value(OBFSTR_C("id"), json(nullptr)), JSONRPC_INVALID_REQUEST, OBFSTR("Missing 'method' field"));

    json id = msg.contains(OBFSTR_C("id")) ? msg[OBFSTR_C("id")] : json(nullptr);
    json params = msg.value(OBFSTR_C("params"), json::object());
    bool is_notification = !msg.contains(OBFSTR_C("id"));

    if (method == OBFSTR_C("initialize"))
        return handle_initialize(id, params);

    if (method == OBFSTR_C("notifications/initialized"))
        return json();

    if (method == OBFSTR_C("ping"))
        return handle_ping(id);

    if (method == OBFSTR_C("tools/list"))
        return handle_tools_list(id);

    if (method == OBFSTR_C("tools/call"))
        return handle_tools_call(id, params);

    if (method == OBFSTR_C("resources/list"))
        return handle_resources_list(id);

    if (method == OBFSTR_C("resources/read"))
        return handle_resources_read(id, params);

    if (method == OBFSTR_C("resources/templates/list"))
        return handle_resources_templates_list(id);

    if (method == OBFSTR_C("prompts/list"))
        return handle_prompts_list(id);

    if (method == OBFSTR_C("prompts/get"))
        return handle_prompts_get(id, params);

    if (method == OBFSTR_C("completion/complete"))
        return handle_completion_complete(id, params);

    if (method == OBFSTR_C("notifications/cancelled") || method == OBFSTR_C("logging/setLevel"))
        return json();

    if (is_notification)
        return json();

    return make_jsonrpc_error(id, JSONRPC_METHOD_NOT_FOUND, OBFSTR("Unknown method: ") + method);
}

static std::string handle_mcp_body(const std::string& body)
{
    json parsed;
    try
    {
        parsed = json::parse(body);
    }
    catch (const json::parse_error& e)
    {
        return json_dump_safe(make_jsonrpc_error(nullptr, JSONRPC_PARSE_ERROR,
            std::string("JSON parse error: ") + e.what()));
    }

    if (parsed.is_array())
    {
        if (parsed.empty())
            return json_dump_safe(make_jsonrpc_error(nullptr, JSONRPC_INVALID_REQUEST, "Empty batch"));

        json responses = json::array();
        for (const auto& item : parsed)
        {
            json response = dispatch_single_message(item);
            if (!response.is_null())
                responses.push_back(response);
        }

        if (responses.empty())
            return "";
        return json_dump_safe(responses);
    }

    json response = dispatch_single_message(parsed);
    if (response.is_null())
        return "";
    return json_dump_safe(response);
}

struct sse_session_t
{
    std::string id;
    std::mutex mtx;
    std::condition_variable cv;
    std::queue<std::string> events;
    std::atomic<bool> closed{false};

    void push_event(const std::string& event)
    {
        {
            std::lock_guard<std::mutex> lk(mtx);
            events.push(event);
        }
        cv.notify_one();
    }

    bool wait_event(std::string& out, int timeout_ms)
    {
        std::unique_lock<std::mutex> lk(mtx);
        if (cv.wait_for(lk, std::chrono::milliseconds(timeout_ms),
            [this] { return !events.empty() || closed.load(std::memory_order_relaxed); }))
        {
            if (closed.load(std::memory_order_relaxed))
                return false;
            if (!events.empty())
            {
                out = std::move(events.front());
                events.pop();
                return true;
            }
        }
        return false;
    }

    void close()
    {
        closed.store(true, std::memory_order_relaxed);
        cv.notify_all();
    }
};

static std::string format_sse_event(const std::string& event_type, const std::string& data)
{
    std::string result;
    if (!event_type.empty())
        result += "event: " + event_type + "\n";

    std::istringstream iss(data);
    std::string line;
    while (std::getline(iss, line))
        result += "data: " + line + "\n";

    result += "\n";
    return result;
}

mcp_server_t::mcp_server_t() = default;

mcp_server_t::~mcp_server_t()
{
    stop();
}

bool mcp_server_t::is_running() const
{
    return _running.load();
}

int mcp_server_t::get_port() const
{
    return _running.load() ? _port : 0;
}

bool mcp_server_t::start(int port)
{
    {
        auto& lm = license_manager_t::instance();
        if (!lm.is_valid() || lm.get_runtime_nonce() == 0)
        {
            msg(OBFSTR_C("AiDA MCP: Cannot start — license not active.\n"));
            return false;
        }
    }

    if (_running.load())
    {
        msg(OBFSTR_C("AiDA MCP: Server is already running on port %d.\n"), _port);
        return true;
    }

    _stop_requested = false;
    _port = 0;

    try
    {
        _server_thread = std::thread([this, port]() { server_thread_func(port); });
    }
    catch (const std::exception& e)
    {
        msg(OBFSTR_C("AiDA MCP: Failed to start server thread: %s\n"), e.what());
        return false;
    }

    for (int i = 0; i < 50 && !_running.load() && !_stop_requested.load(); ++i)
        std::this_thread::sleep_for(std::chrono::milliseconds(20));

    if (_running.load())
    {
        size_t tool_count = agent_tools::ToolRegistry::instance().get_tool_names().size();
        msg(OBFSTR_C("AiDA MCP: Server started on http://127.0.0.1:%d\n"), _port);
        if (port > 0 && _port != port)
            msg(OBFSTR_C("AiDA MCP: Requested port %d was unavailable; using fallback port %d instead.\n"), port, _port);
        msg(OBFSTR_C("AiDA MCP: %zu tools available.\n"), tool_count);
        msg(OBFSTR_C("AiDA MCP: Streamable HTTP  -> http://127.0.0.1:%d/mcp  (also /sse)\n"), _port);
        msg(OBFSTR_C("AiDA MCP: Legacy SSE       -> http://127.0.0.1:%d/sse\n"), _port);
        return true;
    }
    else
    {
        msg(OBFSTR_C("AiDA MCP: Server failed to start on port %d (port may be in use).\n"), port);
        if (_server_thread.joinable())
            _server_thread.join();
        return false;
    }
}

void mcp_server_t::stop()
{
    if (!_running.load() && !_server_thread.joinable())
        return;

    _stop_requested = true;

    {
        std::lock_guard<std::mutex> lock(_server_mutex);
        if (_active_server)
        {
            static_cast<httplib::Server*>(_active_server)->stop();
        }
    }

    if (_server_thread.joinable())
        _server_thread.join();

    msg(OBFSTR_C("AiDA MCP: Server stopped.\n"));
}

void mcp_server_t::server_thread_func(int port)
{
    httplib::Server svr;

    {
        std::lock_guard<std::mutex> lock(_server_mutex);
        _active_server = &svr;
    }

    std::string session_id = generate_session_id();

    svr.set_default_headers({
        {"Access-Control-Allow-Origin",  "*"},
        {"Access-Control-Allow-Methods", "GET, POST, DELETE, OPTIONS"},
        {"Access-Control-Allow-Headers", "Content-Type, Mcp-Session-Id, Accept"},
        {"Access-Control-Expose-Headers", "Mcp-Session-Id"}
    });

    svr.Options(".*", [](const httplib::Request&, httplib::Response& res) {
        res.status = 204;
    });

    svr.Post("/mcp", [&session_id](const httplib::Request& req, httplib::Response& res) {
        std::string response_body = handle_mcp_body(req.body);

        res.set_header("Mcp-Session-Id", session_id);

        if (response_body.empty())
        {
            res.status = 202;
        }
        else
        {
            res.set_content(response_body, "application/json");
        }
    });

    svr.Get("/mcp", [this, &session_id](const httplib::Request& req, httplib::Response& res) {
        res.set_header("Mcp-Session-Id", session_id);

        std::string accept = req.get_header_value("Accept");
        bool wants_sse = accept.find("text/event-stream") != std::string::npos;

        if (wants_sse)
        {
            res.set_header("Cache-Control", "no-cache");
            res.set_chunked_content_provider(
                "text/event-stream",
                [this](size_t offset, httplib::DataSink& sink) -> bool {
                    if (offset == 0)
                    {
                        std::string evt = ": connected\n\n";
                        if (!sink.write(evt.c_str(), evt.size()))
                            return false;
                    }
                    for (int i = 0; i < 15; ++i)
                    {
                        std::this_thread::sleep_for(std::chrono::seconds(2));
                        if (_stop_requested.load())
                            return false;
                    }
                    std::string ka = ": keepalive\n\n";
                    return sink.write(ka.c_str(), ka.size());
                },
                nullptr
            );
        }
        else
        {
            res.set_content("event: endpoint\ndata: /mcp\n\n", "text/event-stream");
        }
    });

    svr.Delete("/mcp", [&session_id](const httplib::Request&, httplib::Response& res) {
        res.set_header("Mcp-Session-Id", session_id);
        res.status = 200;
        res.set_content("{}", "application/json");
    });

    svr.Get("/health", [](const httplib::Request&, httplib::Response& res) {
        json health;
        health["status"] = "ok";
        health["server"] = OBFSTR("AiDA MCP");
        health["version"] = AIDA_VERSION;
        health["tools_count"] = agent_tools::ToolRegistry::instance().get_tool_names().size();
        res.set_content(json_dump_safe(health), "application/json");
    });

    svr.Get("/api/tools", [](const httplib::Request&, httplib::Response& res) {
        res.set_content(json_dump_safe(build_mcp_tools_list(), 2), "application/json");
    });

    svr.Post("/api/tools/call", [](const httplib::Request& req, httplib::Response& res) {
        json body;
        try { body = json::parse(req.body); }
        catch (const json::parse_error& e)
        {
            res.status = 400;
            res.set_content(json_dump_safe({{"error", e.what()}}), "application/json");
            return;
        }

        std::string tool_name = body.value("name", "");
        json arguments = body.value("arguments", json::object());

        if (tool_name.empty())
        {
            res.status = 400;
            res.set_content(json_dump_safe({{"error", "Missing 'name' field"}}), "application/json");
            return;
        }

        const auto* tool = agent_tools::ToolRegistry::instance().get_tool(tool_name);
        if (!is_mcp_exposed_tool(tool))
        {
            res.status = 403;
            res.set_content(json_dump_safe({{"error", "Tool is not exposed through MCP"}}), "application/json");
            return;
        }

        auto tool_result = execute_tool_in_main_thread(tool_name, arguments);

        json resp;
        resp["success"] = tool_result.success;
        resp["output"] = sanitize_utf8(tool_result.output);
        if (!tool_result.data.is_null() && !tool_result.data.empty())
            resp["data"] = tool_result.data;

        res.set_content(json_dump_safe(resp, 2), "application/json");
    });

    svr.Get("/api/resources", [](const httplib::Request&, httplib::Response& res) {
        json resources = json::array();
        for (const auto& rdef : get_resource_definitions())
        {
            resources.push_back({
                {OBFSTR_C("uri"),         rdef.uri},
                {OBFSTR_C("name"),        rdef.name},
                {OBFSTR_C("description"), rdef.description},
                {"mimeType",    rdef.mime_type}
            });
        }
        res.set_content(json_dump_safe(resources, 2), "application/json");
    });

    svr.Get("/api/resources/read", [](const httplib::Request& req, httplib::Response& res) {
        std::string uri = req.get_param_value("uri");
        if (uri.empty())
        {
            res.status = 400;
            res.set_content(json_dump_safe({{"error", "Missing 'uri' query parameter"}}), "application/json");
            return;
        }

        const mcp_resource_def_t* found = nullptr;
        for (const auto& rdef : get_resource_definitions())
        {
            if (rdef.uri == uri)
            {
                found = &rdef;
                break;
            }
        }

        if (!found)
        {
            res.status = 404;
            res.set_content(json_dump_safe({{"error", "Unknown resource: " + uri}}), "application/json");
            return;
        }

        auto tool_result = execute_resource_read(*found);
        json resp;
        resp[OBFSTR_C("uri")] = found->uri;
        resp["success"] = tool_result.success;
        if (!tool_result.data.is_null() && !tool_result.data.empty())
            resp["data"] = tool_result.data;
        else
            resp[OBFSTR_C("text")] = sanitize_utf8(tool_result.output);

        res.set_content(json_dump_safe(resp, 2), "application/json");
    });

    std::map<std::string, std::shared_ptr<sse_session_t>> sse_sessions;
    std::mutex sse_mtx;

    svr.Get("/sse", [this, &sse_sessions, &sse_mtx](const httplib::Request&, httplib::Response& res) {
        auto session = std::make_shared<sse_session_t>();
        session->id = generate_session_id();

        {
            std::lock_guard<std::mutex> lk(sse_mtx);
            sse_sessions[session->id] = session;
        }

        res.set_header("Cache-Control", "no-cache");
        res.set_header("Connection", "keep-alive");
        res.set_header("X-Accel-Buffering", "no");

        res.set_chunked_content_provider(
            "text/event-stream",
            [this, session](size_t offset, httplib::DataSink& sink) -> bool {
                if (offset == 0)
                {
                    std::string evt = format_sse_event("endpoint",
                        "/message?sessionId=" + session->id);
                    if (!sink.write(evt.c_str(), evt.size()))
                    {
                        session->close();
                        return false;
                    }
                }

                std::string event;
                if (session->wait_event(event, 2000))
                {
                    if (!sink.write(event.c_str(), event.size()))
                    {
                        session->close();
                        return false;
                    }
                }
                else if (session->closed.load(std::memory_order_relaxed))
                {
                    return false;
                }
                else if (_stop_requested.load())
                {
                    session->close();
                    return false;
                }
                else
                {
                    std::string ka = ": keepalive\n\n";
                    if (!sink.write(ka.c_str(), ka.size()))
                    {
                        session->close();
                        return false;
                    }
                }

                return !session->closed.load(std::memory_order_relaxed);
            },
            [session, &sse_sessions, &sse_mtx](bool ) {
                session->close();
                std::lock_guard<std::mutex> lk(sse_mtx);
                sse_sessions.erase(session->id);
            }
        );
    });

    svr.Post("/message", [&sse_sessions, &sse_mtx](const httplib::Request& req, httplib::Response& res) {
        std::string sid = req.get_param_value("sessionId");
        if (sid.empty())
        {
            res.status = 400;
            res.set_content(json_dump_safe(make_jsonrpc_error(nullptr,
                JSONRPC_INVALID_REQUEST, "Missing sessionId query parameter")),
                "application/json");
            return;
        }

        std::shared_ptr<sse_session_t> session;
        {
            std::lock_guard<std::mutex> lk(sse_mtx);
            auto it = sse_sessions.find(sid);
            if (it == sse_sessions.end())
            {
                res.status = 404;
                res.set_content(json_dump_safe(make_jsonrpc_error(nullptr,
                    JSONRPC_INVALID_REQUEST, "Unknown or expired session: " + sid)),
                    "application/json");
                return;
            }
            session = it->second;
        }

        std::string response_body = handle_mcp_body(req.body);

        if (!response_body.empty())
        {
            std::string event = format_sse_event("message", response_body);
            session->push_event(event);
        }

        res.status = 202;
        res.set_content("Accepted", "text/plain");
    });

    svr.Post("/sse", [&session_id](const httplib::Request& req, httplib::Response& res) {
        std::string response_body = handle_mcp_body(req.body);
        res.set_header("Mcp-Session-Id", session_id);
        if (response_body.empty())
            res.status = 202;
        else
            res.set_content(response_body, "application/json");
    });

    svr.Delete("/sse", [&session_id](const httplib::Request&, httplib::Response& res) {
        res.set_header("Mcp-Session-Id", session_id);
        res.status = 200;
        res.set_content("{}", "application/json");
    });

    svr.set_socket_options([](socket_t sock) {
        int yes = 1;
        setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, reinterpret_cast<const char*>(&yes), sizeof(yes));
    });

    int bound_port = 0;
    if (port > 0 && svr.bind_to_port("127.0.0.1", port))
        bound_port = port;
    if (bound_port <= 0)
        bound_port = svr.bind_to_any_port("127.0.0.1");

    if (bound_port <= 0)
    {
        if (!_stop_requested.load())
            msg(OBFSTR_C("AiDA MCP: Failed to bind to 127.0.0.1:%d and no fallback port was available.\n"), port);

        {
            std::lock_guard<std::mutex> lock(_server_mutex);
            _active_server = nullptr;
        }
        return;
    }

    _port = bound_port;
    _running = true;

    if (!svr.listen_after_bind())
    {
        if (!_stop_requested.load())
            msg(OBFSTR_C("AiDA MCP: Listener terminated on 127.0.0.1:%d\n"), bound_port);
    }

    _running = false;

    {
        std::lock_guard<std::mutex> lock(_server_mutex);
        _active_server = nullptr;
    }
}

enum class mcp_cfg_format_t
{
    mcpservers_url,
    mcpservers_serverurl,
    vscode_mcp,
    vscode_mcp_json,
    cline_mcp,
    zed_context,
    codex_toml,
    claude_code_json,
};

struct mcp_client_def_t
{
    const char* name;
    mcp_cfg_format_t format;
    const char* win_path;
    const char* mac_path;
    const char* linux_path;
};

static const mcp_client_def_t g_mcp_client_defs[] =
{
    {
        "Amazon Q",
        mcp_cfg_format_t::mcpservers_url,
        "~/.aws/amazonq/mcp_config.json",
        "~/.aws/amazonq/mcp_config.json",
        "~/.aws/amazonq/mcp_config.json"
    },
    {
        "Antigravity IDE",
        mcp_cfg_format_t::mcpservers_url,
        "~/.gemini/antigravity/mcp_config.json",
        "~/.gemini/antigravity/mcp_config.json",
        "~/.gemini/antigravity/mcp_config.json"
    },
    {
        "Claude",
        mcp_cfg_format_t::mcpservers_url,
        "%APPDATA%/Claude/claude_desktop_config.json",
        "~/Library/Application Support/Claude/claude_desktop_config.json",
        nullptr
    },
    {
        "Copilot CLI",
        mcp_cfg_format_t::mcpservers_url,
        "~/.copilot/mcp-config.json",
        "~/.copilot/mcp-config.json",
        "~/.copilot/mcp-config.json"
    },
    {
        "Crush",
        mcp_cfg_format_t::mcpservers_url,
        "~/crush.json",
        "~/crush.json",
        "~/crush.json"
    },
    {
        "Cursor",
        mcp_cfg_format_t::mcpservers_url,
        "~/.cursor/mcp.json",
        "~/.cursor/mcp.json",
        "~/.cursor/mcp.json"
    },
    {
        "Gemini CLI",
        mcp_cfg_format_t::mcpservers_url,
        "~/.gemini/settings.json",
        "~/.gemini/settings.json",
        "~/.gemini/settings.json"
    },
    {
        "Kiro",
        mcp_cfg_format_t::mcpservers_url,
        "~/.kiro/mcp_config.json",
        "~/.kiro/mcp_config.json",
        "~/.kiro/mcp_config.json"
    },
    {
        "LM Studio",
        mcp_cfg_format_t::mcpservers_url,
        "~/.lmstudio/mcp.json",
        "~/.lmstudio/mcp.json",
        "~/.lmstudio/mcp.json"
    },
    {
        "Opencode",
        mcp_cfg_format_t::mcpservers_url,
        "~/.opencode/mcp_config.json",
        "~/.opencode/mcp_config.json",
        "~/.opencode/mcp_config.json"
    },
    {
        "Qwen Coder",
        mcp_cfg_format_t::mcpservers_url,
        "~/.qwen/settings.json",
        "~/.qwen/settings.json",
        "~/.qwen/settings.json"
    },
    {
        "Trae",
        mcp_cfg_format_t::mcpservers_url,
        "~/.trae/mcp_config.json",
        "~/.trae/mcp_config.json",
        "~/.trae/mcp_config.json"
    },
    {
        "Warp",
        mcp_cfg_format_t::mcpservers_url,
        "~/.warp/mcp_config.json",
        "~/.warp/mcp_config.json",
        "~/.warp/mcp_config.json"
    },

    {
        "Windsurf",
        mcp_cfg_format_t::mcpservers_serverurl,
        "~/.codeium/windsurf/mcp_config.json",
        "~/.codeium/windsurf/mcp_config.json",
        "~/.codeium/windsurf/mcp_config.json"
    },

    {
        "VS Code",
        mcp_cfg_format_t::vscode_mcp,
        "%APPDATA%/Code/User/settings.json",
        "~/Library/Application Support/Code/User/settings.json",
        "~/.config/Code/User/settings.json"
    },
    {
        "VS Code Insiders",
        mcp_cfg_format_t::vscode_mcp,
        "%APPDATA%/Code - Insiders/User/settings.json",
        "~/Library/Application Support/Code - Insiders/User/settings.json",
        "~/.config/Code - Insiders/User/settings.json"
    },
    {
        "Augment Code",
        mcp_cfg_format_t::vscode_mcp,
        "%APPDATA%/Code/User/settings.json",
        "~/Library/Application Support/Code/User/settings.json",
        "~/.config/Code/User/settings.json"
    },
    {
        "Qodo Gen",
        mcp_cfg_format_t::vscode_mcp,
        "%APPDATA%/Code/User/settings.json",
        "~/Library/Application Support/Code/User/settings.json",
        "~/.config/Code/User/settings.json"
    },

    {
        "VS Code (mcp.json)",
        mcp_cfg_format_t::vscode_mcp_json,
        "%APPDATA%/Code/User/mcp.json",
        "~/Library/Application Support/Code/User/mcp.json",
        "~/.config/Code/User/mcp.json"
    },
    {
        "VS Code Insiders (mcp.json)",
        mcp_cfg_format_t::vscode_mcp_json,
        "%APPDATA%/Code - Insiders/User/mcp.json",
        "~/Library/Application Support/Code - Insiders/User/mcp.json",
        "~/.config/Code - Insiders/User/mcp.json"
    },

    {
        "Cline",
        mcp_cfg_format_t::cline_mcp,
        "%APPDATA%/Code/User/globalStorage/saoudrizwan.claude-dev/settings/cline_mcp_settings.json",
        "~/Library/Application Support/Code/User/globalStorage/saoudrizwan.claude-dev/settings/cline_mcp_settings.json",
        "~/.config/Code/User/globalStorage/saoudrizwan.claude-dev/settings/cline_mcp_settings.json"
    },
    {
        "Kilo Code",
        mcp_cfg_format_t::cline_mcp,
        "%APPDATA%/Code/User/globalStorage/kilocode.kilo-code/settings/mcp_settings.json",
        "~/Library/Application Support/Code/User/globalStorage/kilocode.kilo-code/settings/mcp_settings.json",
        "~/.config/Code/User/globalStorage/kilocode.kilo-code/settings/mcp_settings.json"
    },
    {
        "Roo Code",
        mcp_cfg_format_t::cline_mcp,
        "%APPDATA%/Code/User/globalStorage/rooveterinaryinc.roo-cline/settings/mcp_settings.json",
        "~/Library/Application Support/Code/User/globalStorage/rooveterinaryinc.roo-cline/settings/mcp_settings.json",
        "~/.config/Code/User/globalStorage/rooveterinaryinc.roo-cline/settings/mcp_settings.json"
    },

    {
        "Zed",
        mcp_cfg_format_t::zed_context,
        "%APPDATA%/Zed/settings.json",
        "~/Library/Application Support/Zed/settings.json",
        "~/.config/zed/settings.json"
    },

    {
        "Codex",
        mcp_cfg_format_t::codex_toml,
        "~/.codex/config.toml",
        "~/.codex/config.toml",
        "~/.codex/config.toml"
    },

    {
        "Claude Code",
        mcp_cfg_format_t::claude_code_json,
        "~/.claude.json",
        "~/.claude.json",
        "~/.claude.json"
    },

#ifdef __APPLE__
    {
        "BoltAI",
        mcp_cfg_format_t::mcpservers_url,
        nullptr,
        "~/Library/Application Support/BoltAI/config.json",
        nullptr
    },
    {
        "Perplexity",
        mcp_cfg_format_t::mcpservers_url,
        nullptr,
        "~/Library/Application Support/Perplexity/mcp_config.json",
        nullptr
    },
#endif
};

static const std::string MCP_SERVER_NAME = OBFSTR("aida-ida-pro");

static std::string mcp_get_home_dir()
{
    qstring buf;
#ifdef _WIN32
    if (qgetenv("USERPROFILE", &buf) && !buf.empty())
        return std::string(buf.c_str());
    qstring drive, hpath;
    if (qgetenv("HOMEDRIVE", &drive) && qgetenv("HOMEPATH", &hpath))
        return std::string(drive.c_str()) + std::string(hpath.c_str());
#else
    if (qgetenv("HOME", &buf) && !buf.empty())
        return std::string(buf.c_str());
#endif
    return std::string();
}

static std::string mcp_get_appdata_dir()
{
#ifdef _WIN32
    qstring buf;
    if (qgetenv("APPDATA", &buf) && !buf.empty())
        return std::string(buf.c_str());
    return std::string();
#elif defined(__APPLE__)
    std::string home = mcp_get_home_dir();
    if (home.empty()) return std::string();
    return home + "/Library/Application Support";
#else
    std::string home = mcp_get_home_dir();
    if (home.empty()) return std::string();
    return home + "/.config";
#endif
}

static std::string mcp_normalize_separators(const std::string& path)
{
    std::string result = path;
#ifdef _WIN32
    for (auto& c : result)
    {
        if (c == '/')
            c = '\\';
    }
#endif
    return result;
}

static std::string mcp_expand_path(const char* path_template)
{
    if (!path_template || !*path_template)
        return std::string();

    std::string path(path_template);

    if (path.size() >= 1 && path[0] == '~')
    {
        std::string home = mcp_get_home_dir();
        if (home.empty())
            return std::string();
        if (path.size() >= 2 && (path[1] == '/' || path[1] == '\\'))
            path = home + path.substr(1);
        else if (path.size() == 1)
            path = home;
    }

    size_t pos = path.find("%APPDATA%");
    if (pos != std::string::npos)
    {
#ifdef _WIN32
        qstring appdata;
        if (!qgetenv("APPDATA", &appdata) || appdata.empty())
            return std::string();
        path.replace(pos, 9, appdata.c_str());
#else
        std::string appdata = mcp_get_appdata_dir();
        if (appdata.empty())
            return std::string();
        path.replace(pos, 9, appdata);
#endif
    }

    return mcp_normalize_separators(path);
}

static bool mcp_ensure_dir_recursive(const std::string& dir_path)
{
    if (dir_path.empty())
        return false;
    if (qisdir(dir_path.c_str()))
        return true;

    size_t sep = dir_path.find_last_of("/\\");
    if (sep != std::string::npos && sep > 0)
    {
        std::string parent = dir_path.substr(0, sep);
        if (!mcp_ensure_dir_recursive(parent))
            return false;
    }

    int rc = qmkdir(dir_path.c_str(), 0755);
    return rc == 0 || qisdir(dir_path.c_str());
}

static bool mcp_ensure_parent_dir(const std::string& file_path)
{
    size_t sep = file_path.find_last_of("/\\");
    if (sep == std::string::npos || sep == 0)
        return true;
    return mcp_ensure_dir_recursive(file_path.substr(0, sep));
}

static bool mcp_read_file_contents(const std::string& path, std::string& out)
{
    FILE* fp = qfopen(path.c_str(), "rb");
    if (!fp)
        return false;
    file_janitor_t fj(fp);
    uint64 size = qfsize(fp);
    if (size == 0 || size > 50ULL * 1024 * 1024)
        return false;
    out.resize(static_cast<size_t>(size));
    return qfread(fp, &out[0], out.size()) == static_cast<ssize_t>(out.size());
}

static bool mcp_write_file_contents(const std::string& path, const std::string& content)
{
    if (!mcp_ensure_parent_dir(path))
        return false;
    FILE* fp = qfopen(path.c_str(), "wb");
    if (!fp)
        return false;
    file_janitor_t fj(fp);
    return qfwrite(fp, content.c_str(), content.size()) == static_cast<ssize_t>(content.size());
}

static std::string mcp_strip_jsonc(const std::string& input)
{
    std::string result;
    result.reserve(input.size());

    bool in_string = false;
    bool in_line_comment = false;
    bool in_block_comment = false;

    for (size_t i = 0; i < input.size(); ++i)
    {
        char c = input[i];

        if (in_line_comment)
        {
            if (c == '\n')
            {
                in_line_comment = false;
                result += '\n';
            }
            continue;
        }

        if (in_block_comment)
        {
            if (c == '*' && i + 1 < input.size() && input[i + 1] == '/')
            {
                in_block_comment = false;
                ++i;
            }
            continue;
        }

        if (in_string)
        {
            result += c;
            if (c == '\\' && i + 1 < input.size())
                result += input[++i];
            else if (c == '"')
                in_string = false;
            continue;
        }

        if (c == '"')
        {
            in_string = true;
            result += c;
            continue;
        }

        if (c == '/' && i + 1 < input.size())
        {
            if (input[i + 1] == '/')
            {
                in_line_comment = true;
                ++i;
                continue;
            }
            if (input[i + 1] == '*')
            {
                in_block_comment = true;
                ++i;
                continue;
            }
        }

        if (c == ',')
        {
            size_t j = i + 1;
            while (j < input.size()
                && (input[j] == ' ' || input[j] == '\t'
                    || input[j] == '\n' || input[j] == '\r'))
                ++j;
            if (j < input.size() && (input[j] == '}' || input[j] == ']'))
                continue;
        }

        result += c;
    }

    return result;
}

static bool mcp_parse_json_file(const std::string& path, json& out, bool allow_jsonc = false)
{
    std::string raw;
    if (!mcp_read_file_contents(path, raw))
        return false;

    try
    {
        out = json::parse(raw);
        return true;
    }
    catch (const json::parse_error&)
    {
        if (!allow_jsonc)
            return false;
    }

    try
    {
        std::string stripped = mcp_strip_jsonc(raw);
        out = json::parse(stripped);
        return true;
    }
    catch (const json::parse_error&)
    {
        return false;
    }
}

static bool mcp_write_json_file(const std::string& path, const json& data)
{
    std::string content = json_dump_safe(data, 2);
    content += "\n";
    return mcp_write_file_contents(path, content);
}

static bool mcp_write_mcpservers_url(
    const std::string& path,
    const std::string& url,
    const char* url_key)
{
    json config;
    if (qfileexist(path.c_str()))
    {
        if (!mcp_parse_json_file(path, config, false))
            config = json::object();
    }
    if (!config.is_object())
        config = json::object();

    if (!config.contains("mcpServers") || !config["mcpServers"].is_object())
        config["mcpServers"] = json::object();

    config["mcpServers"][MCP_SERVER_NAME] = json::object();
    config["mcpServers"][MCP_SERVER_NAME][url_key] = url;

    return mcp_write_json_file(path, config);
}

static bool mcp_write_cline_config(const std::string& path, const std::string& url)
{
    json config;
    if (qfileexist(path.c_str()))
    {
        if (!mcp_parse_json_file(path, config, false))
            config = json::object();
    }
    if (!config.is_object())
        config = json::object();

    if (!config.contains("mcpServers") || !config["mcpServers"].is_object())
        config["mcpServers"] = json::object();

    json entry;
    entry["url"] = url;
    entry["disabled"] = false;
    entry["autoApprove"] = json::array();

    if (config["mcpServers"].contains(MCP_SERVER_NAME)
        && config["mcpServers"][MCP_SERVER_NAME].is_object()
        && config["mcpServers"][MCP_SERVER_NAME].contains("autoApprove"))
    {
        entry["autoApprove"] = config["mcpServers"][MCP_SERVER_NAME]["autoApprove"];
    }

    config["mcpServers"][MCP_SERVER_NAME] = entry;
    return mcp_write_json_file(path, config);
}

static bool mcp_write_vscode_settings(const std::string& path, const std::string& url)
{
    json config;
    if (qfileexist(path.c_str()))
    {
        if (!mcp_parse_json_file(path, config, true))
            config = json::object();
    }
    if (!config.is_object())
        config = json::object();

    if (!config.contains("mcp") || !config["mcp"].is_object())
        config["mcp"] = json::object();
    if (!config["mcp"].contains("servers") || !config["mcp"]["servers"].is_object())
        config["mcp"]["servers"] = json::object();

    json entry;
    entry[OBFSTR_C("type")] = "sse";
    entry["url"] = url;
    config["mcp"]["servers"][MCP_SERVER_NAME] = entry;

    return mcp_write_json_file(path, config);
}

static bool mcp_write_vscode_mcp_json(const std::string& path, const std::string& url)
{
    json config;
    if (qfileexist(path.c_str()))
    {
        if (!mcp_parse_json_file(path, config, true))
            config = json::object();
    }
    if (!config.is_object())
        config = json::object();

    if (!config.contains("servers") || !config["servers"].is_object())
        config["servers"] = json::object();

    json entry;
    entry[OBFSTR_C("type")] = "sse";
    entry["url"] = url;
    config["servers"][MCP_SERVER_NAME] = entry;

    return mcp_write_json_file(path, config);
}

static bool mcp_write_zed_settings(const std::string& path, const std::string& url)
{
    json config;
    if (qfileexist(path.c_str()))
    {
        if (!mcp_parse_json_file(path, config, true))
            config = json::object();
    }
    if (!config.is_object())
        config = json::object();

    if (!config.contains("context_servers") || !config["context_servers"].is_object())
        config["context_servers"] = json::object();

    json entry;
    entry["settings"] = json::object();
    entry["settings"]["url"] = url;
    config["context_servers"][MCP_SERVER_NAME] = entry;

    return mcp_write_json_file(path, config);
}

static bool mcp_write_codex_toml(const std::string& path, const std::string& url)
{
    std::string content;
    if (qfileexist(path.c_str()))
        mcp_read_file_contents(path, content);

    const std::string section_marker = OBFSTR("[mcp_servers.aida-ida-pro]");
    size_t section_pos = content.find(section_marker);

    if (section_pos != std::string::npos)
    {
        size_t section_end = content.find("\n[", section_pos + section_marker.size());
        if (section_end == std::string::npos)
            section_end = content.size();
        else
            section_end += 1;

        std::string new_section = section_marker + "\n"
            "type = \"sse\"\n"
            "url = \"" + url + "\"\n";

        content.replace(section_pos, section_end - section_pos, new_section);
    }
    else
    {
        if (!content.empty() && content.back() != '\n')
            content += "\n";
        content += "\n" + section_marker + "\n"
            "type = \"sse\"\n"
            "url = \"" + url + "\"\n";
    }

    return mcp_write_file_contents(path, content);
}

static bool mcp_write_claude_code_json(const std::string& path, const std::string& url)
{
    json config;
    if (qfileexist(path.c_str()))
    {
        if (!mcp_parse_json_file(path, config, false))
            config = json::object();
    }
    if (!config.is_object())
        config = json::object();

    if (!config.contains("mcpServers") || !config["mcpServers"].is_object())
        config["mcpServers"] = json::object();

    json entry;
    entry[OBFSTR_C("type")] = "sse";
    entry["url"] = url;
    config["mcpServers"][MCP_SERVER_NAME] = entry;

    return mcp_write_json_file(path, config);
}

static bool mcp_write_single_client(
    const mcp_client_def_t& def,
    const std::string& path,
    const std::string& http_url,
    const std::string& sse_url)
{
    switch (def.format)
    {
    case mcp_cfg_format_t::mcpservers_url:
        return mcp_write_mcpservers_url(path, sse_url, "url");

    case mcp_cfg_format_t::mcpservers_serverurl:
        return mcp_write_mcpservers_url(path, sse_url, "serverUrl");

    case mcp_cfg_format_t::vscode_mcp:
        return mcp_write_vscode_settings(path, sse_url);

    case mcp_cfg_format_t::vscode_mcp_json:
        return mcp_write_vscode_mcp_json(path, sse_url);

    case mcp_cfg_format_t::cline_mcp:
        return mcp_write_cline_config(path, sse_url);

    case mcp_cfg_format_t::zed_context:
        return mcp_write_zed_settings(path, http_url);

    case mcp_cfg_format_t::codex_toml:
        return mcp_write_codex_toml(path, sse_url);

    case mcp_cfg_format_t::claude_code_json:
        return mcp_write_claude_code_json(path, sse_url);
    }
    return false;
}

static void mcp_write_reference_config(
    int port,
    const std::string& port_str,
    const std::string& http_url,
    const std::string& sse_url)
{
    json config;
    config["_comment"] = OBFSTR("MCP Server - Auto-configured endpoints. All supported MCP clients have been configured automatically.");
    config["_version"] = AIDA_VERSION;
    config["_port"] = port;
    config["_endpoints"] = {
        {"streamable_http", http_url},
        {"legacy_sse", sse_url},
        {"health", "http://127.0.0.1:" + port_str + "/health"}
    };

    config["generic_http"] = {
        {OBFSTR_C("description"), "For any MCP client that supports Streamable HTTP or SSE transport"},
        {"streamable_http_url", http_url},
        {"sse_url", sse_url}
    };

    qstring config_file = get_user_idadir();
    config_file.append(OBFSTR_C("/aida_mcp_config.json"));

    try
    {
        std::string json_str = json_dump_safe(config, 2) + "\n";
        FILE* fp = qfopen(config_file.c_str(), "wb");
        if (fp)
        {
            file_janitor_t fj(fp);
            qfwrite(fp, json_str.c_str(), json_str.length());
        }
    }
    catch (...)
    {
        msg(OBFSTR_C("AiDA MCP: Warning - could not write reference config file.\n"));
    }
}

void mcp_server_t::write_mcp_client_configs() const
{
    if (!_running.load())
        return;

    std::string port_str = std::to_string(_port);
    std::string http_url = "http://127.0.0.1:" + port_str + "/mcp";
    std::string sse_url  = "http://127.0.0.1:" + port_str + "/sse";

    mcp_write_reference_config(_port, port_str, http_url, sse_url);

    std::set<std::string> written_paths;

    int configured_count = 0;
    int skipped_count = 0;
    int failed_count = 0;

    const size_t num_clients = sizeof(g_mcp_client_defs) / sizeof(g_mcp_client_defs[0]);
    for (size_t i = 0; i < num_clients; ++i)
    {
        const auto& def = g_mcp_client_defs[i];

        const char* path_template = nullptr;
#if defined(_WIN32)
        path_template = def.win_path;
#elif defined(__APPLE__)
        path_template = def.mac_path;
#else
        path_template = def.linux_path;
#endif

        if (!path_template || !*path_template)
        {
            ++skipped_count;
            continue;
        }

        std::string expanded = mcp_expand_path(path_template);
        if (expanded.empty())
        {
            ++skipped_count;
            continue;
        }

        if (written_paths.count(expanded))
            continue;

        if (expanded.find("globalStorage") != std::string::npos)
        {
            size_t sep = expanded.find_last_of("/\\");
            if (sep != std::string::npos)
            {
                std::string parent = expanded.substr(0, sep);
                if (!qisdir(parent.c_str()))
                {
                    ++skipped_count;
                    continue;
                }
            }
        }

        if (mcp_write_single_client(def, expanded, http_url, sse_url))
        {
            written_paths.insert(expanded);
            ++configured_count;
            msg(OBFSTR_C("AiDA MCP: [OK] %s -> %s\n"), def.name, expanded.c_str());
        }
        else
        {
            ++failed_count;
            msg(OBFSTR_C("AiDA MCP: [FAIL] %s -> %s\n"), def.name, expanded.c_str());
        }
    }

    qstring ref_file = get_user_idadir();
    ref_file.append("/aida_mcp_config.json");

    msg("\n");
    msg("============================================================\n");
    msg("  AiDA MCP Server - Auto-Configuration Summary\n");
    msg("============================================================\n");
    msg("  Streamable HTTP : %s\n", http_url.c_str());
    msg("  Legacy SSE      : %s\n", sse_url.c_str());
    msg("  Health Check    : http://127.0.0.1:%d/health\n", _port);
    msg("------------------------------------------------------------\n");
    msg("  Clients configured : %d\n", configured_count);
    msg("  Clients skipped    : %d (not installed or unavailable)\n", skipped_count);
    if (failed_count > 0)
        msg("  Clients failed     : %d\n", failed_count);
    msg("------------------------------------------------------------\n");
    msg("  All configured clients connect via HTTP/SSE directly.\n");
    msg("  No external bridge executable is required.\n");
    msg("------------------------------------------------------------\n");
    msg("  Reference config : %s\n", ref_file.c_str());
    msg("============================================================\n\n");
}
