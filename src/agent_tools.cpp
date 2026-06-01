#include "aida_pro.hpp"
#include "ida_utils.hpp"
#include "graphrag.hpp"
#include "analysis_db.hpp"
#include "anti_re.hpp"
#include "vuln/vuln_tools.hpp"
#include "vuln/verification_tools.hpp"
#include <allins.hpp>
#include <iomanip>
#include <loader.hpp>
#include <chrono>

using json = nlohmann::json;

namespace agent_tools
{

tool_result_t tool_result_t::ok(const std::string& msg, const json& data)
{
    tool_result_t r;
    r.success = true;
    r.output = sanitize_utf8(msg);
    r.data = data;
    sanitize_json_utf8_inplace(r.data);
    return r;
}

tool_result_t tool_result_t::error(const std::string& msg)
{
    tool_result_t r;
    r.success = false;
    r.output = sanitize_utf8(msg);
    return r;
}

ToolRegistry& ToolRegistry::instance()
{
    static ToolRegistry registry;
    return registry;
}

void ToolRegistry::register_tool(const tool_definition_t& tool)
{
    _tools[tool.name] = tool;
}

const tool_definition_t* ToolRegistry::get_tool(const std::string& name) const
{
    auto it = _tools.find(name);
    return (it != _tools.end()) ? &it->second : nullptr;
}

std::vector<std::string> ToolRegistry::get_tool_names() const
{
    std::vector<std::string> names;
    names.reserve(_tools.size());
    for (const auto& [name, _] : _tools)
        names.push_back(name);
    return names;
}

std::vector<const tool_definition_t*> ToolRegistry::get_tools_by_category(const std::string& category) const
{
    std::vector<const tool_definition_t*> result;
    for (const auto& [_, tool] : _tools)
    {
        if (tool.category == category)
            result.push_back(&tool);
    }
    return result;
}

std::vector<const tool_definition_t*> ToolRegistry::get_all_tools() const
{
    std::vector<const tool_definition_t*> result;
    result.reserve(_tools.size());

    auto meta_it = _tools.find("list_all_available_tools");
    if (meta_it != _tools.end())
        result.push_back(&meta_it->second);

    for (const auto& [name, tool] : _tools)
    {
        if (name != "list_all_available_tools")
            result.push_back(&tool);
    }
    return result;
}

json ToolRegistry::generate_tools_schema() const
{
    json tools_array = json::array();

    for (const auto& [_, tool] : _tools)
    {
        json tool_json;
        tool_json["name"] = tool.name;
        tool_json["category"] = tool.category;
        tool_json["description"] = tool.description;

        json params = json::object();
        json required_params = json::array();

        for (const auto& param : tool.parameters)
        {
            json param_json;
            param_json["type"] = param.type;
            param_json["description"] = param.description;
            if (!param.enum_values.empty())
                param_json["enum"] = param.enum_values;
            if (param.type == "array" && !param.items_schema.is_null())
                param_json["items"] = param.items_schema;
            else if (param.type == "array")
                param_json["items"] = json::object({{"type", "object"}});
            params[param.name] = param_json;

            if (param.required)
                required_params.push_back(param.name);
        }

        tool_json["parameters"] = {
            {"type", "object"},
            {"properties", params},
            {"required", required_params}
        };

        tools_array.push_back(tool_json);
    }

    return tools_array;
}

std::string ToolRegistry::generate_tools_description() const
{
    std::ostringstream ss;

    std::map<std::string, std::vector<const tool_definition_t*>> by_category;
    for (const auto& [_, tool] : _tools)
        by_category[tool.category].push_back(&tool);

    for (const auto& [category, tools] : by_category)
    {
        ss << "\n## " << category << " Tools\n\n";
        for (const auto* tool : tools)
        {
            ss << "### " << tool->name << "\n";
            ss << tool->description << "\n";
            ss << "Parameters:\n";
            for (const auto& param : tool->parameters)
            {
                ss << "  - `" << param.name << "` (" << param.type << ")";
                if (!param.required) ss << " [optional]";
                ss << ": " << param.description << "\n";
            }
            ss << "\n";
        }
    }

    return ss.str();
}

tool_result_t ToolRegistry::execute_tool(const std::string& name, const json& params)
{
    if (ida_utils::is_self_target_database())
        return tool_result_t::error(OBFSTR("Operation blocked."));

    const auto* tool = get_tool(name);
    if (!tool)
        return tool_result_t::error(OBFSTR("Unknown tool: ") + name);

    json sanitized_params = params.is_object() ? params : json::object();

    for (const auto& param : tool->parameters)
    {
        if (param.required && !sanitized_params.contains(param.name))
        {
            return tool_result_t::error(OBFSTR("Missing required parameter: ") + param.name);
        }

        if (sanitized_params.contains(param.name))
        {
            auto& val = sanitized_params[param.name];
            if (val.is_null())
            {
                if (param.type == "string")
                    val = "";
                else if (param.type == "number")
                    val = 0;
                else if (param.type == "boolean")
                    val = false;
                else if (param.type == "array")
                    val = json::array();
            }
            else if (param.type == "string" && val.is_number_integer())
            {
                std::ostringstream ss;
                ss << "0x" << std::hex << val.get<uint64_t>();
                val = ss.str();
            }
            else if (param.type == "string" && val.is_number())
            {
                val = std::to_string(val.get<double>());
            }
            else if (param.type == "number" && val.is_string())
            {
                std::string sv = val.get<std::string>();
                try {
                    if (sv.size() > 2 && sv[0] == '0' && (sv[1] == 'x' || sv[1] == 'X'))
                        val = static_cast<uint64_t>(std::stoull(sv, nullptr, 16));
                    else if (!sv.empty())
                        val = static_cast<uint64_t>(std::stoull(sv, nullptr, 0));
                    else
                        val = 0;
                } catch (...) { val = 0; }
            }
        }
    }

    try
    {
        return tool->handler(sanitized_params);
    }
    catch (const std::exception& e)
    {
        return tool_result_t::error(OBFSTR("Tool execution error: ") + e.what());
    }
}


namespace helpers
{

std::optional<ea_t> parse_address(const std::string& addr_str)
{
    if (addr_str.empty())
        return std::nullopt;

    try
    {
        size_t idx = 0;
        ea_t addr;
        if (addr_str.substr(0, 2) == "0x" || addr_str.substr(0, 2) == "0X")
            addr = std::stoull(addr_str, &idx, 16);
        else if (std::all_of(addr_str.begin(), addr_str.end(),
                            [](char c) { return std::isxdigit(static_cast<unsigned char>(c)) != 0; }))
            addr = std::stoull(addr_str, &idx, 16);
        else
            addr = std::stoull(addr_str, &idx, 0);

        if (idx == addr_str.length())
            return addr;
    }
    catch (...) {}

    ea_t ea = get_name_ea(BADADDR, addr_str.c_str());
    if (ea != BADADDR)
        return ea;

    return std::nullopt;
}

std::vector<ea_t> parse_addresses(const json& param)
{
    std::vector<ea_t> result;

    if (param.is_string())
    {
        std::string s = param.get<std::string>();
        std::istringstream iss(s);
        std::string token;
        while (std::getline(iss, token, ','))
        {
            token.erase(0, token.find_first_not_of(" \t"));
            size_t last = token.find_last_not_of(" \t");
            if (last == std::string::npos)
                continue;
            token.erase(last + 1);
            if (auto ea = parse_address(token))
                result.push_back(*ea);
        }
    }
    else if (param.is_array())
    {
        for (const auto& item : param)
        {
            if (item.is_string())
            {
                if (auto ea = parse_address(item.get<std::string>()))
                    result.push_back(*ea);
            }
            else if (item.is_number())
            {
                result.push_back(static_cast<ea_t>(item.get<uint64_t>()));
            }
        }
    }
    else if (param.is_number())
    {
        result.push_back(static_cast<ea_t>(param.get<uint64_t>()));
    }

    return result;
}

std::string get_pseudocode(ea_t ea)
{
    if (!init_hexrays_plugin())
        return "// Hex-Rays decompiler not available";

    func_t* pfn = get_func(ea);
    if (!pfn)
        return "// No function at address";

    if (!ida_utils::is_safely_decompilable(pfn))
        return "// Non-decompilable function (thunk/extern/tail)";

    try
    {
        cfuncptr_t cfunc = decompile_func(pfn, nullptr, DECOMP_NO_WAIT);
        if (!cfunc)
            return "// Decompilation failed";

        qstring code;
        qstring_printer_t printer(cfunc, code, false);
        cfunc->print_func(printer);
        return code.c_str();
    }
    catch (const vd_failure_t& e)
    {
        return std::string("// Decompilation error: ") + e.desc().c_str();
    }
    catch (...)
    {
        return "// Decompilation crashed (access violation) - skipped";
    }
}

std::string get_disassembly(ea_t start, ea_t end)
{
    if (end == BADADDR)
    {
        func_t* pfn = get_func(start);
        if (pfn)
            end = pfn->end_ea;
        else
            end = start + 0x100;
    }

    text_t text;
    gen_disasm_text(text, start, end, false);

    std::ostringstream ss;
    for (const auto& line : text)
    {
        qstring clean;
        tag_remove(&clean, line.line.c_str());
        ss << clean.c_str() << "\n";
    }
    return ss.str();
}

std::string format_address(ea_t ea)
{
    std::ostringstream ss;
    ss << "0x" << std::hex << std::uppercase << ea;
    return ss.str();
}

std::string get_name_or_address(ea_t ea)
{
    qstring name;
    if (get_name(&name, ea) > 0 && !name.empty())
        return name.c_str();
    return format_address(ea);
}

}

namespace function_tools
{

tool_result_t get_function(const json& params)
{
    auto addresses = helpers::parse_addresses(params["address"]);
    if (addresses.empty())
        return tool_result_t::error(OBFSTR("Invalid or no address provided"));

    json functions = json::array();

    for (ea_t ea : addresses)
    {
        func_t* pfn = get_func(ea);
        if (!pfn)
        {
            functions.push_back({
                {"address", helpers::format_address(ea)},
                {"error", "No function at this address"}
            });
            continue;
        }

        qstring func_name;
        get_func_name(&func_name, pfn->start_ea);

        json func_info;
        func_info["address"] = helpers::format_address(pfn->start_ea);
        func_info["end_address"] = helpers::format_address(pfn->end_ea);
        func_info["name"] = func_name.c_str();
        func_info["size"] = pfn->end_ea - pfn->start_ea;
        func_info["flags"] = pfn->flags;
        func_info["is_library"] = (pfn->flags & FUNC_LIB) != 0;
        func_info["is_thunk"] = (pfn->flags & FUNC_THUNK) != 0;
        func_info["does_return"] = pfn->does_return();

        tinfo_t tif;
        if (get_tinfo(&tif, pfn->start_ea))
        {
            qstring proto;
            tif.print(&proto);
            func_info["prototype"] = proto.c_str();
        }

        functions.push_back(func_info);
    }

    std::ostringstream ss;
    ss << "Found " << functions.size() << " function(s)";
    return tool_result_t::ok(ss.str(), functions);
}

tool_result_t list_functions(const json& params)
{
    int offset = params.value("offset", 0);
    int limit = params.value("limit", 100);
    std::string filter = params.value("filter", "");

    size_t total = get_func_qty();
    json functions = json::array();

    std::regex filter_regex;
    bool use_filter = !filter.empty();
    if (use_filter)
    {
        try { filter_regex = std::regex(filter, std::regex::icase); }
        catch (...) { return tool_result_t::error(OBFSTR("Invalid filter regex")); }
    }

    int count = 0;
    int skipped = 0;

    for (size_t i = 0; i < total && count < limit; i++)
    {
        func_t* pfn = getn_func(i);
        if (!pfn) continue;

        qstring name;
        get_func_name(&name, pfn->start_ea);

        if (use_filter && !std::regex_search(name.c_str(), filter_regex))
            continue;

        if (skipped < offset)
        {
            skipped++;
            continue;
        }

        functions.push_back({
            {"index", i},
            {"address", helpers::format_address(pfn->start_ea)},
            {"name", name.c_str()},
            {"size", pfn->end_ea - pfn->start_ea}
        });
        count++;
    }

    json result;
    result["functions"] = functions;
    result["total"] = total;
    result["offset"] = offset;
    result["limit"] = limit;
    result["returned"] = count;

    std::ostringstream ss;
    ss << "Listed " << count << " functions (total: " << total << ")";
    return tool_result_t::ok(ss.str(), result);
}

tool_result_t decompile_function(const json& params)
{
    auto ea_opt = helpers::parse_address(params["address"].get<std::string>());
    if (!ea_opt)
        return tool_result_t::error(OBFSTR("Invalid address"));

    func_t* pfn = get_func(*ea_opt);
    if (!pfn)
        return tool_result_t::error(OBFSTR("No function at address"));

    json result;
    result["address"] = helpers::format_address(pfn->start_ea);
    result["end_address"] = helpers::format_address(pfn->end_ea);
    result["size"] = pfn->end_ea - pfn->start_ea;

    qstring func_name;
    get_func_name(&func_name, pfn->start_ea);
    result["name"] = func_name.c_str();

    tinfo_t tif;
    if (get_tinfo(&tif, pfn->start_ea))
    {
        qstring proto;
        tif.print(&proto);
        result["prototype"] = proto.c_str();
    }

    if (!init_hexrays_plugin())
    {
        result["code"] = "// Hex-Rays decompiler not available";
        return tool_result_t::ok(OBFSTR("Decompilation complete (no Hex-Rays)"), result);
    }

    if (!ida_utils::is_safely_decompilable(pfn))
    {
        result["code"] = "// Non-decompilable function (thunk/extern/tail)";
        return tool_result_t::ok(OBFSTR("Function is not decompilable"), result);
    }

    try
    {
        cfuncptr_t cfunc = decompile_func(pfn, nullptr, DECOMP_NO_WAIT);
        if (!cfunc)
        {
            result["code"] = "// Decompilation failed";
            return tool_result_t::ok(OBFSTR("Decompilation failed"), result);
        }

        qstring code;
        qstring_printer_t printer(cfunc, code, false);
        cfunc->print_func(printer);
        result["code"] = code.c_str();

        lvars_t* lvars = cfunc->get_lvars();
        if (lvars && !lvars->empty())
        {
            json vars_arr = json::array();
            for (size_t i = 0; i < lvars->size(); i++)
            {
                const lvar_t& lv = (*lvars)[i];
                if (!lv.used())
                    continue;
                qstring tstr;
                lv.tif.print(&tstr);
                json v;
                v["name"] = lv.name.c_str();
                v["type"] = tstr.c_str();
                v["is_arg"] = lv.is_arg_var();
                vars_arr.push_back(v);
            }
            result["local_variables"] = vars_arr;
        }

        json strings = json::array();
        func_item_iterator_t fii;
        for (bool ok = fii.set(pfn); ok; ok = fii.next_addr())
        {
            ea_t item_ea = fii.current();
            xrefblk_t xb;
            for (bool xok = xb.first_from(item_ea, XREF_DATA); xok; xok = xb.next_from())
            {
                qstring str;
                if (get_strlit_contents(&str, xb.to, -1, STRTYPE_C) > 0)
                {
                    strings.push_back({
                        {"address", helpers::format_address(xb.to)},
                        {"value", str.c_str()}
                    });
                }
            }
        }
        if (!strings.empty())
            result["strings"] = strings;
    }
    catch (const vd_failure_t& e)
    {
        result["code"] = std::string("// Decompilation error: ") + e.desc().c_str();
    }

    return tool_result_t::ok(OBFSTR("Decompilation complete"), result);
}

tool_result_t disassemble_function(const json& params)
{
    auto ea_opt = helpers::parse_address(params["address"].get<std::string>());
    if (!ea_opt)
        return tool_result_t::error(OBFSTR("Invalid address"));

    func_t* pfn = get_func(*ea_opt);
    if (!pfn)
        return tool_result_t::error(OBFSTR("No function at address"));

    std::string disasm = helpers::get_disassembly(pfn->start_ea, pfn->end_ea);

    json result;
    result["address"] = helpers::format_address(pfn->start_ea);
    result["end_address"] = helpers::format_address(pfn->end_ea);
    result["disassembly"] = disasm;

    qstring func_name;
    get_func_name(&func_name, pfn->start_ea);
    result["name"] = func_name.c_str();
    result["size"] = pfn->end_ea - pfn->start_ea;

    result["frame_size"] = get_frame_size(pfn);
    result["local_vars_size"] = pfn->frsize;
    result["saved_regs_size"] = pfn->frregs;
    result["args_size"] = pfn->argsize;

    return tool_result_t::ok(OBFSTR("Disassembly complete"), result);
}

tool_result_t get_xrefs_to(const json& params)
{
    auto addresses = helpers::parse_addresses(params["address"]);
    if (addresses.empty())
        return tool_result_t::error(OBFSTR("Invalid or no address provided"));

    int limit = params.value("limit", 100);

    json all_xrefs = json::array();

    for (ea_t ea : addresses)
    {
        json xrefs_for_addr = json::array();
        int count = 0;

        xrefblk_t xb;
        for (bool ok = xb.first_to(ea, XREF_ALL); ok && count < limit; ok = xb.next_to())
        {
            json xref;
            xref["from"] = helpers::format_address(xb.from);
            xref["to"] = helpers::format_address(xb.to);
            xref["is_code"] = xb.iscode;
            xref["type"] = xb.type;
            xref["is_user"] = xb.user;

            xref["from_name"] = helpers::get_name_or_address(xb.from);

            xrefs_for_addr.push_back(xref);
            count++;
        }

        all_xrefs.push_back({
            {"target", helpers::format_address(ea)},
            {"xrefs", xrefs_for_addr},
            {"count", count}
        });
    }

    return tool_result_t::ok(OBFSTR("Cross-references retrieved"), all_xrefs);
}

tool_result_t get_xrefs_from(const json& params)
{
    auto addresses = helpers::parse_addresses(params["address"]);
    if (addresses.empty())
        return tool_result_t::error(OBFSTR("Invalid or no address provided"));

    int limit = params.value("limit", 100);

    json all_xrefs = json::array();

    for (ea_t ea : addresses)
    {
        json xrefs_for_addr = json::array();
        int count = 0;

        xrefblk_t xb;
        for (bool ok = xb.first_from(ea, XREF_ALL); ok && count < limit; ok = xb.next_from())
        {
            json xref;
            xref["from"] = helpers::format_address(xb.from);
            xref["to"] = helpers::format_address(xb.to);
            xref["is_code"] = xb.iscode;
            xref["type"] = xb.type;
            xref["is_user"] = xb.user;

            xref["to_name"] = helpers::get_name_or_address(xb.to);

            xrefs_for_addr.push_back(xref);
            count++;
        }

        all_xrefs.push_back({
            {"source", helpers::format_address(ea)},
            {"xrefs", xrefs_for_addr},
            {"count", count}
        });
    }

    return tool_result_t::ok(OBFSTR("Cross-references retrieved"), all_xrefs);
}

tool_result_t rename_function(const json& params)
{
    auto ea_opt = helpers::parse_address(params["address"].get<std::string>());
    if (!ea_opt)
        return tool_result_t::error(OBFSTR("Invalid address"));

    std::string new_name = params["new_name"].get<std::string>();
    if (new_name.empty())
        return tool_result_t::error(OBFSTR("New name cannot be empty"));

    func_t* pfn = get_func(*ea_opt);
    if (!pfn)
        return tool_result_t::error(OBFSTR("No function at address"));

    bool success = set_name(pfn->start_ea, new_name.c_str(), SN_FORCE | SN_NODUMMY);

    if (success)
    {

        auto& store = graphrag::GraphStore::instance();
        auto* node = store.get_node_by_address(
            aida_db::AnalysisDB::instance().get_binary_hash(),
            graphrag::node_type_t::FUNCTION, pfn->start_ea);
        if (node)
        {
            node->name = new_name;
            store.upsert_node(*node);
        }

        return tool_result_t::ok(OBFSTR("Function renamed to: ") + new_name);
    }
    else
        return tool_result_t::error(OBFSTR("Failed to rename function"));
}

tool_result_t define_function(const json& params)
{
    auto ea_opt = helpers::parse_address(params["address"].get<std::string>());
    if (!ea_opt)
        return tool_result_t::error(OBFSTR("Invalid address"));

    ea_t end_ea = BADADDR;
    if (params.contains("end"))
    {
        auto end_opt = helpers::parse_address(params["end"].get<std::string>());
        if (end_opt) end_ea = *end_opt;
    }

    bool success = add_func(*ea_opt, end_ea);

    if (success)
        return tool_result_t::ok(OBFSTR("Function defined at ") + helpers::format_address(*ea_opt));
    else
        return tool_result_t::error(OBFSTR("Failed to define function"));
}

tool_result_t get_stack_frame(const json& params)
{
    auto ea_opt = helpers::parse_address(params["address"].get<std::string>());
    if (!ea_opt)
        return tool_result_t::error(OBFSTR("Invalid address"));

    func_t* pfn = get_func(*ea_opt);
    if (!pfn)
        return tool_result_t::error(OBFSTR("No function at address"));

    tinfo_t frame_tif;
    if (!get_func_frame(&frame_tif, pfn))
        return tool_result_t::error(OBFSTR("No stack frame available"));

    udt_type_data_t udt;
    if (!frame_tif.get_udt_details(&udt))
        return tool_result_t::error(OBFSTR("Cannot get frame details"));

    json vars = json::array();
    for (size_t i = 0; i < udt.size(); i++)
    {
        const udm_t& member = udt[i];
        qstring type_str;
        member.type.print(&type_str);

        vars.push_back({
            {"name", member.name.c_str()},
            {"offset", member.offset / 8},
            {"size", member.size / 8},
            {"type", type_str.c_str()}
        });
    }

    json result;
    result["function"] = helpers::format_address(pfn->start_ea);
    result["frame_size"] = get_frame_size(pfn);
    result["local_vars_size"] = pfn->frsize;
    result["variables"] = vars;

    return tool_result_t::ok(OBFSTR("Stack frame retrieved"), result);
}

tool_result_t set_function_signature(const json& params)
{
    auto ea_opt = helpers::parse_address(params["address"].get<std::string>());
    if (!ea_opt)
        return tool_result_t::error(OBFSTR("Invalid address"));

    std::string signature = params["signature"].get<std::string>();

    tinfo_t tif;
    qstring name;
    if (!parse_decl(&tif, &name, nullptr, signature.c_str(), PT_SIL))
        return tool_result_t::error(OBFSTR("Failed to parse signature: ") + signature);

    if (!apply_tinfo(*ea_opt, tif, TINFO_DEFINITE))
        return tool_result_t::error(OBFSTR("Failed to apply type"));

    return tool_result_t::ok(OBFSTR("Function signature applied"));
}

tool_result_t build_call_graph(const json& params)
{
    auto ea_opt = helpers::parse_address(params["address"].get<std::string>());
    if (!ea_opt)
        return tool_result_t::error(OBFSTR("Invalid address"));

    int depth = params.value("depth", 3);
    if (depth < 0) depth = 0;
    if (depth > 16) depth = 16;

    constexpr size_t MAX_NODES = 4096;
    std::map<ea_t, json> nodes;
    std::set<std::pair<ea_t, ea_t>> edges;

    std::deque<std::pair<ea_t, int>> work;
    work.push_back({*ea_opt, 0});

    while (!work.empty() && nodes.size() < MAX_NODES)
    {
        auto [ea, current_depth] = work.front();
        work.pop_front();

        if (current_depth > depth) continue;
        if (nodes.count(ea)) continue;

        func_t* pfn = get_func(ea);
        if (!pfn) continue;

        qstring name;
        get_func_name(&name, pfn->start_ea);

        nodes[ea] = {
            {"address", helpers::format_address(ea)},
            {"name", name.c_str()},
            {"depth", current_depth}
        };

        if (current_depth >= depth) continue;

        func_item_iterator_t fii;
        for (bool ok = fii.set(pfn); ok; ok = fii.next_addr())
        {
            xrefblk_t xb;
            for (bool xok = xb.first_from(fii.current(), XREF_ALL); xok; xok = xb.next_from())
            {
                if (xb.iscode && (xb.type == fl_CN || xb.type == fl_CF))
                {
                    func_t* callee = get_func(xb.to);
                    if (callee)
                    {
                        edges.insert({ea, callee->start_ea});
                        if (!nodes.count(callee->start_ea))
                            work.push_back({callee->start_ea, current_depth + 1});
                    }
                }
            }
        }
    }

    json result;
    result["nodes"] = json::array();
    for (const auto& [_, node] : nodes)
        result["nodes"].push_back(node);

    result["edges"] = json::array();
    for (const auto& [from, to] : edges)
    {
        result["edges"].push_back({
            {"from", helpers::format_address(from)},
            {"to", helpers::format_address(to)}
        });
    }

    return tool_result_t::ok(OBFSTR("Call graph built"), result);
}

tool_result_t get_basic_blocks(const json& params)
{
    auto ea_opt = helpers::parse_address(params["address"].get<std::string>());
    if (!ea_opt)
        return tool_result_t::error(OBFSTR("Invalid address"));

    func_t* pfn = get_func(*ea_opt);
    if (!pfn)
        return tool_result_t::error(OBFSTR("No function at address"));

    qflow_chart_t fc;
    fc.create("", pfn, BADADDR, BADADDR, FC_RESERVED);

    json blocks = json::array();
    for (int i = 0; i < fc.size(); i++)
    {
        const qbasic_block_t& bb = fc.blocks[i];

        json successors = json::array();
        for (int j = 0; j < fc.nsucc(i); j++)
            successors.push_back(fc.succ(i, j));

        json predecessors = json::array();
        for (int j = 0; j < fc.npred(i); j++)
            predecessors.push_back(fc.pred(i, j));

        blocks.push_back({
            {"id", i},
            {"start", helpers::format_address(bb.start_ea)},
            {"end", helpers::format_address(bb.end_ea)},
            {"successors", successors},
            {"predecessors", predecessors}
        });
    }

    return tool_result_t::ok(OBFSTR("Basic blocks retrieved"), blocks);
}

void register_tools()
{
    auto& registry = ToolRegistry::instance();

    registry.register_tool({
        OBFSTR("get_function"),
        OBFSTR("function"),
        OBFSTR("Get function information by address or name. Auto-detects whether input is address or name."),
        {{OBFSTR("address"), OBFSTR("string"), OBFSTR("Address (0x...) or function name"), true}},
        get_function
    });

    registry.register_tool({
        OBFSTR("list_functions"),
        OBFSTR("function"),
        OBFSTR("List all functions in the binary (paginated). Optionally filter by regex pattern."),
        {
            {OBFSTR("offset"), OBFSTR("number"), OBFSTR("Starting offset for pagination"), false},
            {OBFSTR("limit"), OBFSTR("number"), OBFSTR("Maximum number of results (default 100)"), false},
            {OBFSTR("filter"), OBFSTR("string"), OBFSTR("Regex pattern to filter function names"), false}
        },
        list_functions
    });

    registry.register_tool({
        OBFSTR("decompile_function"),
        OBFSTR("function"),
        OBFSTR("Decompile a function at the given address using Hex-Rays."),
        {{OBFSTR("address"), OBFSTR("string"), OBFSTR("Function address to decompile"), true}},
        decompile_function,
        true
    });

    registry.register_tool({
        OBFSTR("disassemble_function"),
        OBFSTR("function"),
        OBFSTR("Get full disassembly of a function with details (args, stack frame, etc)."),
        {{OBFSTR("address"), OBFSTR("string"), OBFSTR("Function address"), true}},
        disassemble_function
    });

    registry.register_tool({
        OBFSTR("get_xrefs_to"),
        OBFSTR("function"),
        OBFSTR("Get all cross-references TO the specified address(es)."),
        {
            {OBFSTR("address"), OBFSTR("string"), OBFSTR("Target address(es) - single, comma-separated, or array"), true},
            {OBFSTR("limit"), OBFSTR("number"), OBFSTR("Maximum xrefs per address (default 100)"), false}
        },
        get_xrefs_to
    });

    registry.register_tool({
        OBFSTR("get_xrefs_from"),
        OBFSTR("function"),
        OBFSTR("Get all cross-references FROM the specified address(es)."),
        {
            {OBFSTR("address"), OBFSTR("string"), OBFSTR("Source address(es)"), true},
            {OBFSTR("limit"), OBFSTR("number"), OBFSTR("Maximum xrefs per address (default 100)"), false}
        },
        get_xrefs_from
    });

    registry.register_tool({
        OBFSTR("rename_function"),
        OBFSTR("function"),
        OBFSTR("Rename the function at the given address."),
        {
            {OBFSTR("address"), OBFSTR("string"), OBFSTR("Function address"), true},
            {OBFSTR("new_name"), OBFSTR("string"), OBFSTR("New function name (PascalCase recommended)"), true}
        },
        rename_function,
        false
    });

    registry.register_tool({
        OBFSTR("define_function"),
        OBFSTR("function"),
        OBFSTR("Define a function at the given address. IDA will auto-detect bounds if end not specified."),
        {
            {OBFSTR("address"), OBFSTR("string"), OBFSTR("Start address"), true},
            {OBFSTR("end"), OBFSTR("string"), OBFSTR("Optional end address"), false}
        },
        define_function,
        false
    });

    registry.register_tool({
        OBFSTR("get_stack_frame"),
        OBFSTR("function"),
        OBFSTR("Get stack frame variables for the function at the given address."),
        {{OBFSTR("address"), OBFSTR("string"), OBFSTR("Function address"), true}},
        get_stack_frame
    });

    registry.register_tool({
        OBFSTR("set_function_signature"),
        OBFSTR("function"),
        OBFSTR("Set/change the type signature of a function."),
        {
            {OBFSTR("address"), OBFSTR("string"), OBFSTR("Function address"), true},
            {OBFSTR("signature"), OBFSTR("string"), OBFSTR("C function prototype (e.g., 'int foo(char* a, int b)')"), true}
        },
        set_function_signature,
        false
    });

    registry.register_tool({
        OBFSTR("build_call_graph"),
        OBFSTR("function"),
        OBFSTR("Build a call graph from the root function with configurable depth."),
        {
            {OBFSTR("address"), OBFSTR("string"), OBFSTR("Root function address"), true},
            {OBFSTR("depth"), OBFSTR("number"), OBFSTR("Maximum recursion depth (default 3)"), false}
        },
        build_call_graph
    });

    registry.register_tool({
        OBFSTR("get_basic_blocks"),
        OBFSTR("function"),
        OBFSTR("Get basic blocks of a function with successors and predecessors."),
        {{OBFSTR("address"), OBFSTR("string"), OBFSTR("Function address"), true}},
        get_basic_blocks
    });

}

}

namespace memory_tools
{

tool_result_t read_bytes(const json& params)
{
    auto ea_opt = helpers::parse_address(params["address"].get<std::string>());
    if (!ea_opt)
        return tool_result_t::error(OBFSTR("Invalid address"));

    size_t size = params.value("size", 16);
    if (size > 4096)
        return tool_result_t::error(OBFSTR("Size too large (max 4096)"));

    if (!is_loaded(*ea_opt))
        return tool_result_t::error(OBFSTR("Address not mapped in database"));

    std::vector<uint8_t> buffer(size);
    ssize_t bytes_read = get_bytes(buffer.data(), size, *ea_opt);

    if (bytes_read < 0)
        return tool_result_t::error(OBFSTR("Failed to read bytes"));

    std::ostringstream hex_ss;
    for (ssize_t i = 0; i < bytes_read; i++)
    {
        if (i > 0) hex_ss << " ";
        hex_ss << std::hex << std::setw(2) << std::setfill('0') << (int)buffer[i];
    }

    json result;
    result["address"] = helpers::format_address(*ea_opt);
    result["size"] = bytes_read;
    result["hex"] = hex_ss.str();

    result["bytes"] = json::array();
    for (ssize_t i = 0; i < bytes_read; i++)
        result["bytes"].push_back(buffer[i]);

    return tool_result_t::ok(OBFSTR("Bytes read successfully"), result);
}

tool_result_t read_integer(const json& params)
{
    auto ea_opt = helpers::parse_address(params["address"].get<std::string>());
    if (!ea_opt)
        return tool_result_t::error(OBFSTR("Invalid address"));

    std::string type = params.value("type", "u64");

    if (!is_loaded(*ea_opt))
        return tool_result_t::error(OBFSTR("Address not mapped in database"));

    uint64_t value = 0;
    int64_t signed_value = 0;
    bool is_signed = type[0] == 'i';

    if (type == "i8" || type == "u8")
    {
        value = get_byte(*ea_opt);
        signed_value = (int8_t)value;
    }
    else if (type == "i16" || type == "u16" || type == "i16le" || type == "u16le")
    {
        value = get_word(*ea_opt);
        signed_value = (int16_t)value;
    }
    else if (type == "i32" || type == "u32" || type == "i32le" || type == "u32le")
    {
        value = get_dword(*ea_opt);
        signed_value = (int32_t)value;
    }
    else if (type == "i64" || type == "u64" || type == "i64le" || type == "u64le")
    {
        value = get_qword(*ea_opt);
        signed_value = (int64_t)value;
    }
    else
    {
        return tool_result_t::error(OBFSTR("Unknown type: ") + type);
    }

    json result;
    result["address"] = helpers::format_address(*ea_opt);
    result["type"] = type;
    result["unsigned_value"] = value;
    result["signed_value"] = signed_value;
    result["hex"] = helpers::format_address(value);

    return tool_result_t::ok(OBFSTR("Integer read successfully"), result);
}

tool_result_t read_string(const json& params)
{
    auto ea_opt = helpers::parse_address(params["address"].get<std::string>());
    if (!ea_opt)
        return tool_result_t::error(OBFSTR("Invalid address"));

    int max_len = params.value("max_length", 1024);

    if (!is_loaded(*ea_opt))
        return tool_result_t::error(OBFSTR("Address not mapped in database"));

    qstring str;
    if (get_strlit_contents(&str, *ea_opt, max_len, STRTYPE_C) <= 0)
        return tool_result_t::error(OBFSTR("No string at address or read failed"));

    json result;
    result["address"] = helpers::format_address(*ea_opt);
    result["value"] = str.c_str();
    result["length"] = str.length();

    return tool_result_t::ok(OBFSTR("String read successfully"), result);
}

tool_result_t read_global(const json& params)
{
    std::string name_or_addr = params["name"].get<std::string>();

    auto ea_opt = helpers::parse_address(name_or_addr);
    if (!ea_opt)
        return tool_result_t::error(OBFSTR("Invalid address or name"));

    if (!is_loaded(*ea_opt))
        return tool_result_t::error(OBFSTR("Address not mapped in database"));

    asize_t item_size = get_item_size(*ea_opt);

    json result;
    result["address"] = helpers::format_address(*ea_opt);
    result["name"] = helpers::get_name_or_address(*ea_opt);
    result["size"] = item_size;

    if (item_size <= 8)
    {
        uval_t value;
        if (get_data_value(&value, *ea_opt, item_size))
        {
            result["value"] = value;
            result["hex"] = helpers::format_address(value);
        }
    }

    return tool_result_t::ok(OBFSTR("Global read successfully"), result);
}

tool_result_t patch_bytes(const json& params)
{
    auto ea_opt = helpers::parse_address(params["address"].get<std::string>());
    if (!ea_opt)
        return tool_result_t::error(OBFSTR("Invalid address"));

    if (!is_loaded(*ea_opt))
        return tool_result_t::error(OBFSTR("Address not mapped in database"));

    std::string hex_bytes = params["bytes"].get<std::string>();

    std::vector<uint8_t> bytes;
    std::istringstream iss(hex_bytes);
    std::string token;

    hex_bytes.erase(std::remove(hex_bytes.begin(), hex_bytes.end(), ' '), hex_bytes.end());

    for (size_t i = 0; i + 1 < hex_bytes.length(); i += 2)
    {
        std::string byte_str = hex_bytes.substr(i, 2);
        try
        {
            bytes.push_back(static_cast<uint8_t>(std::stoul(byte_str, nullptr, 16)));
        }
        catch (...)
        {
            return tool_result_t::error(OBFSTR("Invalid hex byte: ") + byte_str);
        }
    }

    if (bytes.empty())
        return tool_result_t::error(OBFSTR("No bytes to patch"));

    for (size_t i = 0; i < bytes.size(); i++)
    {
        if (!is_loaded(*ea_opt + i))
            return tool_result_t::error(OBFSTR("Address out of range at offset ") + std::to_string(i));
        patch_byte(*ea_opt + i, bytes[i]);
    }

    json result;
    result["address"] = helpers::format_address(*ea_opt);
    result["size"] = bytes.size();

    return tool_result_t::ok(OBFSTR("Bytes patched successfully"), result);
}

tool_result_t make_code(const json& params)
{
    auto ea_opt = helpers::parse_address(params["address"].get<std::string>());
    if (!ea_opt)
        return tool_result_t::error(OBFSTR("Invalid address"));

    insn_t insn;
    if (decode_insn(&insn, *ea_opt) <= 0)
        return tool_result_t::error(OBFSTR("Failed to decode instruction"));

    if (create_insn(*ea_opt) == 0)
        return tool_result_t::error(OBFSTR("Failed to create instruction"));

    return tool_result_t::ok(OBFSTR("Code created at ") + helpers::format_address(*ea_opt));
}

tool_result_t make_data(const json& params)
{
    auto ea_opt = helpers::parse_address(params["address"].get<std::string>());
    if (!ea_opt)
        return tool_result_t::error(OBFSTR("Invalid address"));

    std::string type = params.value("type", "byte");

    bool ok = false;
    if (type == "word")       ok = create_word(*ea_opt, 2);
    else if (type == "dword") ok = create_dword(*ea_opt, 4);
    else if (type == "qword") ok = create_qword(*ea_opt, 8);
    else                       ok = create_byte(*ea_opt, 1);

    if (!ok)
        return tool_result_t::error(OBFSTR("Failed to create data"));

    return tool_result_t::ok(OBFSTR("Data created at ") + helpers::format_address(*ea_opt));
}

tool_result_t undefine(const json& params)
{
    auto ea_opt = helpers::parse_address(params["address"].get<std::string>());
    if (!ea_opt)
        return tool_result_t::error(OBFSTR("Invalid address"));

    asize_t size = params.value("size", 1);

    if (params.contains("end"))
    {
        auto end_opt = helpers::parse_address(params["end"].get<std::string>());
        if (end_opt)
            size = *end_opt - *ea_opt;
    }

    if (!del_items(*ea_opt, DELIT_SIMPLE, size))
        return tool_result_t::error(OBFSTR("Failed to undefine"));

    return tool_result_t::ok(OBFSTR("Undefined ") + std::to_string(size) + " bytes");
}

tool_result_t list_globals(const json& params)
{
    int offset = params.value("offset", 0);
    int limit = params.value("limit", 100);
    std::string filter = params.value("filter", "");

    std::regex filter_regex;
    bool use_filter = !filter.empty();
    if (use_filter)
    {
        try { filter_regex = std::regex(filter, std::regex::icase); }
        catch (...) { return tool_result_t::error(OBFSTR("Invalid filter regex")); }
    }

    json globals = json::array();
    int count = 0;
    int skipped = 0;

    for (size_t i = 0; i < get_nlist_size() && count < limit; i++)
    {
        ea_t ea = get_nlist_ea(i);

        if (get_func(ea))
            continue;

        const char* nname = get_nlist_name(i);
        qstring name = nname ? nname : "";

        if (use_filter && !std::regex_search(name.c_str(), filter_regex))
            continue;

        if (skipped < offset)
        {
            skipped++;
            continue;
        }

        globals.push_back({
            {"address", helpers::format_address(ea)},
            {"name", name.c_str()},
            {"size", get_item_size(ea)}
        });
        count++;
    }

    json result;
    result["globals"] = globals;
    result["returned"] = count;

    return tool_result_t::ok(OBFSTR("Globals listed"), result);
}

void register_tools()
{
    auto& registry = ToolRegistry::instance();

    registry.register_tool({
        OBFSTR("read_bytes"),
        OBFSTR("memory"),
        OBFSTR("Read raw bytes from the database at the specified address."),
        {
            {OBFSTR("address"), OBFSTR("string"), OBFSTR("Start address"), true},
            {OBFSTR("size"), OBFSTR("number"), OBFSTR("Number of bytes to read (max 4096, default 16)"), false}
        },
        read_bytes
    });

    registry.register_tool({
        OBFSTR("read_integer"),
        OBFSTR("memory"),
        OBFSTR("Read an integer value at address. Type can be i8/u8/i16/u16/i32/u32/i64/u64."),
        {
            {OBFSTR("address"), OBFSTR("string"), OBFSTR("Address to read"), true},
            {OBFSTR("type"), OBFSTR("string"), OBFSTR("Integer type (default u64)"), false, {OBFSTR("i8"), OBFSTR("u8"), OBFSTR("i16"), OBFSTR("u16"), OBFSTR("i32"), OBFSTR("u32"), OBFSTR("i64"), OBFSTR("u64")}}
        },
        read_integer
    });

    registry.register_tool({
        OBFSTR("read_string"),
        OBFSTR("memory"),
        OBFSTR("Read a null-terminated string at the specified address."),
        {
            {OBFSTR("address"), OBFSTR("string"), OBFSTR("String address"), true},
            {OBFSTR("max_length"), OBFSTR("number"), OBFSTR("Maximum string length (default 1024)"), false}
        },
        read_string
    });

    registry.register_tool({
        OBFSTR("read_global"),
        OBFSTR("memory"),
        OBFSTR("Read a global variable value by address or name."),
        {{OBFSTR("name"), OBFSTR("string"), OBFSTR("Address or name of the global variable"), true}},
        read_global
    });

    registry.register_tool({
        OBFSTR("patch_bytes"),
        OBFSTR("memory"),
        OBFSTR("Write bytes to the database at the specified address."),
        {
            {OBFSTR("address"), OBFSTR("string"), OBFSTR("Start address"), true},
            {OBFSTR("bytes"), OBFSTR("string"), OBFSTR("Hex bytes (e.g., '90 90 90' or '909090')"), true}
        },
        patch_bytes,
        false
    });

    registry.register_tool({
        OBFSTR("make_code"),
        OBFSTR("memory"),
        OBFSTR("Convert bytes at address to code (instruction)."),
        {{OBFSTR("address"), OBFSTR("string"), OBFSTR("Address to convert"), true}},
        make_code,
        false
    });

    registry.register_tool({
        OBFSTR("make_data"),
        OBFSTR("memory"),
        OBFSTR("Convert address to data of specified type."),
        {
            {OBFSTR("address"), OBFSTR("string"), OBFSTR("Address to convert"), true},
            {OBFSTR("type"), OBFSTR("string"), OBFSTR("Data type (byte, word, dword, qword)"), false, {OBFSTR("byte"), OBFSTR("word"), OBFSTR("dword"), OBFSTR("qword")}}
        },
        make_data,
        false
    });

    registry.register_tool({
        OBFSTR("undefine"),
        OBFSTR("memory"),
        OBFSTR("Undefine item(s) at address, converting back to raw bytes."),
        {
            {OBFSTR("address"), OBFSTR("string"), OBFSTR("Start address"), true},
            {OBFSTR("size"), OBFSTR("number"), OBFSTR("Number of bytes"), false},
            {OBFSTR("end"), OBFSTR("string"), OBFSTR("End address (alternative to size)"), false}
        },
        undefine,
        false
    });

    registry.register_tool({
        OBFSTR("list_globals"),
        OBFSTR("memory"),
        OBFSTR("List global variables (paginated, filtered by regex)."),
        {
            {OBFSTR("offset"), OBFSTR("number"), OBFSTR("Starting offset"), false},
            {OBFSTR("limit"), OBFSTR("number"), OBFSTR("Maximum results (default 100)"), false},
            {OBFSTR("filter"), OBFSTR("string"), OBFSTR("Regex filter for names"), false}
        },
        list_globals
    });

}

}

namespace comment_tools
{

tool_result_t set_comment(const json& params)
{
    auto ea_opt = helpers::parse_address(params["address"].get<std::string>());
    if (!ea_opt)
        return tool_result_t::error(OBFSTR("Invalid address"));

    std::string comment = params["comment"].get<std::string>();

    if (!set_cmt(*ea_opt, comment.c_str(), false))
        return tool_result_t::error(OBFSTR("Failed to set comment"));

    return tool_result_t::ok(OBFSTR("Comment set at ") + helpers::format_address(*ea_opt));
}

tool_result_t set_repeatable_comment(const json& params)
{
    auto ea_opt = helpers::parse_address(params["address"].get<std::string>());
    if (!ea_opt)
        return tool_result_t::error(OBFSTR("Invalid address"));

    std::string comment = params["comment"].get<std::string>();

    if (!set_cmt(*ea_opt, comment.c_str(), true))
        return tool_result_t::error(OBFSTR("Failed to set repeatable comment"));

    return tool_result_t::ok(OBFSTR("Repeatable comment set"));
}

tool_result_t set_function_comment(const json& params)
{
    auto ea_opt = helpers::parse_address(params["address"].get<std::string>());
    if (!ea_opt)
        return tool_result_t::error(OBFSTR("Invalid address"));

    func_t* pfn = get_func(*ea_opt);
    if (!pfn)
        return tool_result_t::error(OBFSTR("No function at address"));

    std::string comment = params["comment"].get<std::string>();
    bool repeatable = params.value("repeatable", false);

    if (!set_func_cmt(pfn, comment.c_str(), repeatable))
        return tool_result_t::error(OBFSTR("Failed to set function comment"));

    return tool_result_t::ok(OBFSTR("Function comment set"));
}

tool_result_t get_comment(const json& params)
{
    auto ea_opt = helpers::parse_address(params["address"].get<std::string>());
    if (!ea_opt)
        return tool_result_t::error(OBFSTR("Invalid address"));

    qstring regular_cmt, repeatable_cmt;
    get_cmt(&regular_cmt, *ea_opt, false);
    get_cmt(&repeatable_cmt, *ea_opt, true);

    json result;
    result["address"] = helpers::format_address(*ea_opt);
    result["comment"] = regular_cmt.c_str();
    result["repeatable_comment"] = repeatable_cmt.c_str();

    return tool_result_t::ok(OBFSTR("Comment retrieved"), result);
}

tool_result_t set_extra_comment(const json& params)
{
    auto ea_opt = helpers::parse_address(params["address"].get<std::string>());
    if (!ea_opt)
        return tool_result_t::error(OBFSTR("Invalid address"));

    std::string comment = params["comment"].get<std::string>();
    std::string position = params.value("position", "anterior");

    int line_idx = (position == "posterior") ? E_NEXT : E_PREV;

    update_extra_cmt(*ea_opt, line_idx, comment.c_str());

    return tool_result_t::ok(OBFSTR("Extra comment set"));
}

tool_result_t rename_variable(const json& params)
{
    auto ea_opt = helpers::parse_address(params["address"].get<std::string>());
    if (!ea_opt)
        return tool_result_t::error(OBFSTR("Invalid address"));

    std::string original_name = params["original_name"].get<std::string>();
    std::string new_name = params["new_name"].get<std::string>();

    if (!init_hexrays_plugin())
        return tool_result_t::error(OBFSTR("Hex-Rays not available"));

    func_t* pfn = get_func(*ea_opt);
    if (!pfn)
        return tool_result_t::error(OBFSTR("No function at address"));

    if (!ida_utils::is_safely_decompilable(pfn))
        return tool_result_t::error(OBFSTR("Function is not decompilable (thunk/extern/tail)"));

    try
    {
        cfuncptr_t cfunc = decompile(pfn);
        if (!cfunc)
            return tool_result_t::error(OBFSTR("Decompilation failed"));

        lvars_t* lvars = cfunc->get_lvars();
        if (!lvars)
            return tool_result_t::error(OBFSTR("No local variables"));

        for (size_t i = 0; i < lvars->size(); i++)
        {
            lvar_t& lvar = (*lvars)[i];
            if (lvar.name == original_name.c_str())
            {
                lvar_saved_info_t info;
                info.ll = lvar;
                info.name = new_name.c_str();
                if (modify_user_lvar_info(pfn->start_ea, MLI_NAME, info))
                    return tool_result_t::ok(OBFSTR("Variable renamed: ") + original_name + " -> " + new_name);
                else
                    return tool_result_t::error(OBFSTR("Failed to rename variable"));
            }
        }

        return tool_result_t::error(OBFSTR("Variable not found: ") + original_name);
    }
    catch (const vd_failure_t& e)
    {
        return tool_result_t::error(OBFSTR("Decompilation error: ") + std::string(e.desc().c_str()));
    }
}

void register_tools()
{
    auto& registry = ToolRegistry::instance();

    registry.register_tool({
        OBFSTR("set_comment"),
        OBFSTR("comment"),
        OBFSTR("Set a regular comment at the specified address (visible in disassembly)."),
        {
            {OBFSTR("address"), OBFSTR("string"), OBFSTR("Address"), true},
            {OBFSTR("comment"), OBFSTR("string"), OBFSTR("Comment text"), true}
        },
        set_comment,
        false
    });

    registry.register_tool({
        OBFSTR("set_repeatable_comment"),
        OBFSTR("comment"),
        OBFSTR("Set a repeatable comment (appears at all references to this address)."),
        {
            {OBFSTR("address"), OBFSTR("string"), OBFSTR("Address"), true},
            {OBFSTR("comment"), OBFSTR("string"), OBFSTR("Comment text"), true}
        },
        set_repeatable_comment,
        false
    });

    registry.register_tool({
        OBFSTR("set_function_comment"),
        OBFSTR("comment"),
        OBFSTR("Set a comment on the function header."),
        {
            {OBFSTR("address"), OBFSTR("string"), OBFSTR("Function address"), true},
            {OBFSTR("comment"), OBFSTR("string"), OBFSTR("Comment text"), true},
            {OBFSTR("repeatable"), OBFSTR("boolean"), OBFSTR("Make it repeatable (default false)"), false}
        },
        set_function_comment,
        false
    });

    registry.register_tool({
        OBFSTR("get_comment"),
        OBFSTR("comment"),
        OBFSTR("Get comments at the specified address."),
        {{OBFSTR("address"), OBFSTR("string"), OBFSTR("Address"), true}},
        get_comment
    });

    registry.register_tool({
        OBFSTR("set_extra_comment"),
        OBFSTR("comment"),
        OBFSTR("Set anterior (before) or posterior (after) comment lines."),
        {
            {OBFSTR("address"), OBFSTR("string"), OBFSTR("Address"), true},
            {OBFSTR("comment"), OBFSTR("string"), OBFSTR("Comment text"), true},
            {OBFSTR("position"), OBFSTR("string"), OBFSTR("anterior or posterior (default anterior)"), false, {OBFSTR("anterior"), OBFSTR("posterior")}}
        },
        set_extra_comment,
        false
    });

    registry.register_tool({
        OBFSTR("rename_variable"),
        OBFSTR("comment"),
        OBFSTR("Rename a local variable in the decompiled function."),
        {
            {OBFSTR("address"), OBFSTR("string"), OBFSTR("Function address"), true},
            {OBFSTR("original_name"), OBFSTR("string"), OBFSTR("Current variable name"), true},
            {OBFSTR("new_name"), OBFSTR("string"), OBFSTR("New variable name (camelCase recommended)"), true}
        },
        rename_variable,
        false
    });

}

}

namespace type_tools
{

tool_result_t declare_type(const json& params)
{
    std::string declaration = params["declaration"].get<std::string>();

    til_t* ti = get_idati();
    if (!ti)
        return tool_result_t::error(OBFSTR("Cannot get local type library"));

    int count = parse_decls(ti, declaration.c_str(), nullptr, HTI_DCL);
    if (count <= 0)
        return tool_result_t::error(OBFSTR("Failed to parse type declaration"));

    json result;
    result["types_added"] = count;
    return tool_result_t::ok(OBFSTR("Declared ") + std::to_string(count) + " type(s)", result);
}

tool_result_t apply_type(const json& params)
{
    auto ea_opt = helpers::parse_address(params["address"].get<std::string>());
    if (!ea_opt)
        return tool_result_t::error(OBFSTR("Invalid address"));

    std::string type_str = params["type"].get<std::string>();

    tinfo_t tif;
    qstring name;
    if (!parse_decl(&tif, &name, nullptr, type_str.c_str(), PT_SIL))
        return tool_result_t::error(OBFSTR("Failed to parse type: ") + type_str);

    if (!apply_tinfo(*ea_opt, tif, TINFO_DEFINITE))
        return tool_result_t::error(OBFSTR("Failed to apply type at address"));

    return tool_result_t::ok(OBFSTR("Type applied at ") + helpers::format_address(*ea_opt));
}

tool_result_t infer_type(const json& params)
{
    auto ea_opt = helpers::parse_address(params["address"].get<std::string>());
    if (!ea_opt)
        return tool_result_t::error(OBFSTR("Invalid address"));

    tinfo_t tif;
    int result_code = guess_tinfo(&tif, *ea_opt);

    if (result_code == GUESS_FUNC_FAILED)
        return tool_result_t::error(OBFSTR("Failed to infer type"));

    qstring type_str;
    tif.print(&type_str);

    json result;
    result["address"] = helpers::format_address(*ea_opt);
    result["type"] = type_str.c_str();
    result["confidence"] = (result_code == GUESS_FUNC_OK) ? "high" : "low";

    return tool_result_t::ok(OBFSTR("Type inferred"), result);
}

tool_result_t search_structs(const json& params)
{
    std::string pattern = params["pattern"].get<std::string>();
    int limit = params.value("limit", 50);

    std::regex filter_regex;
    try { filter_regex = std::regex(pattern, std::regex::icase); }
    catch (...) { return tool_result_t::error(OBFSTR("Invalid regex pattern")); }

    til_t* ti = get_idati();
    if (!ti)
        return tool_result_t::error(OBFSTR("Cannot get local type library"));

    json structs = json::array();
    uint32 count = get_ordinal_count(ti);

    for (uint32 i = 1; i <= count && (int)structs.size() < limit; i++)
    {
        const char* tname = get_numbered_type_name(ti, i);
        if (!tname)
            continue;

        if (!std::regex_search(tname, filter_regex))
            continue;

        tinfo_t tif;
        if (tif.get_numbered_type(ti, i))
        {
            qstring type_str;
            tif.print(&type_str);
            structs.push_back({
                {"ordinal", i},
                {"name", tname},
                {"type", type_str.c_str()},
                {"is_struct", tif.is_struct()},
                {"is_enum", tif.is_enum()},
                {"is_typedef", tif.is_typedef()},
                {"size", (size_t)tif.get_size()}
            });
        }
    }

    return tool_result_t::ok(OBFSTR("Found ") + std::to_string(structs.size()) + " matching types", structs);
}

tool_result_t get_struct(const json& params)
{
    std::string name = params["name"].get<std::string>();

    til_t* ti = get_idati();
    if (!ti)
        return tool_result_t::error(OBFSTR("Cannot get local type library"));

    int32 ordinal = get_type_ordinal(ti, name.c_str());
    if (ordinal <= 0)
        return tool_result_t::error(OBFSTR("Type not found: ") + name);

    tinfo_t tif;
    if (!tif.get_numbered_type(ti, ordinal))
        return tool_result_t::error(OBFSTR("Cannot load type"));

    json result;
    result["name"] = name;
    result["ordinal"] = ordinal;
    result["size"] = (size_t)tif.get_size();
    result["is_struct"] = tif.is_struct();
    result["is_union"] = tif.is_union();
    result["is_enum"] = tif.is_enum();

    if (tif.is_struct() || tif.is_union())
    {
        udt_type_data_t udt;
        if (tif.get_udt_details(&udt))
        {
            json members = json::array();
            for (size_t i = 0; i < udt.size(); i++)
            {
                const udm_t& m = udt[i];
                qstring mtype;
                m.type.print(&mtype);
                members.push_back({
                    {"name", m.name.c_str()},
                    {"offset", m.offset / 8},
                    {"size", m.size / 8},
                    {"type", mtype.c_str()}
                });
            }
            result["members"] = members;
        }
    }
    else if (tif.is_enum())
    {
        enum_type_data_t etd;
        if (tif.get_enum_details(&etd))
        {
            json members = json::array();
            for (size_t i = 0; i < etd.size(); i++)
            {
                members.push_back({
                    {"name", etd[i].name.c_str()},
                    {"value", (int64_t)etd[i].value}
                });
            }
            result["members"] = members;
        }
    }

    qstring printed;
    tif.print(&printed);
    result["declaration"] = printed.c_str();

    return tool_result_t::ok(OBFSTR("Type retrieved"), result);
}

tool_result_t create_struct(const json& params)
{
    std::string name = params["name"].get<std::string>();

    tinfo_t tif;
    udt_type_data_t udt;
    udt.taudt_bits |= TAUDT_UNALIGNED;

    if (params.contains("members") && params["members"].is_array())
    {
        for (const auto& mem : params["members"])
        {
            udm_t m;
            m.name = (mem.contains("name") && mem["name"].is_string()) ? mem["name"].get<std::string>().c_str() : "field";

            std::string type_str = (mem.contains("type") && mem["type"].is_string()) ? mem["type"].get<std::string>() : "int";
            tinfo_t mt;
            if (!parse_decl(&mt, nullptr, nullptr, (type_str + " x;").c_str(), PT_SIL | PT_VAR))
                mt = tinfo_t(BT_INT32);
            m.type = mt;
            m.size = mt.get_size() * 8;

            if (mem.contains("offset") && mem["offset"].is_number())
                m.offset = mem["offset"].get<uint64_t>() * 8;

            udt.push_back(m);
        }
    }

    tif.create_udt(udt, BTF_STRUCT);
    tif.set_named_type(get_idati(), name.c_str());

    return tool_result_t::ok(OBFSTR("Struct created: ") + name);
}

tool_result_t add_struct_member(const json& params)
{
    std::string struct_name = params["struct_name"].get<std::string>();
    std::string member_name = params["member_name"].get<std::string>();
    std::string type_str = params.value("type", "int");

    til_t* ti = get_idati();
    int32 ordinal = get_type_ordinal(ti, struct_name.c_str());
    if (ordinal <= 0)
        return tool_result_t::error(OBFSTR("Struct not found: ") + struct_name);

    tinfo_t tif;
    if (!tif.get_numbered_type(ti, ordinal))
        return tool_result_t::error(OBFSTR("Cannot load struct"));

    udt_type_data_t udt;
    if (!tif.get_udt_details(&udt))
        return tool_result_t::error(OBFSTR("Not a struct/union"));

    udm_t m;
    m.name = member_name.c_str();

    tinfo_t mt;
    if (!parse_decl(&mt, nullptr, nullptr, (type_str + " x;").c_str(), PT_SIL | PT_VAR))
        mt = tinfo_t(BT_INT32);
    m.type = mt;
    m.size = mt.get_size() * 8;

    if (params.contains("offset"))
        m.offset = params["offset"].get<uint64_t>() * 8;

    udt.push_back(m);

    tinfo_t new_tif;
    new_tif.create_udt(udt, BTF_STRUCT);
    new_tif.set_named_type(ti, struct_name.c_str(), NTF_REPLACE);

    return tool_result_t::ok(OBFSTR("Member added to ") + struct_name);
}

tool_result_t get_struct_field_xrefs(const json& params)
{
    std::string struct_name = params["struct_name"].get<std::string>();
    std::string field_name = params["field_name"].get<std::string>();
    int limit = params.value("limit", 100);

    til_t* ti = get_idati();
    int32 ordinal = get_type_ordinal(ti, struct_name.c_str());
    if (ordinal <= 0)
        return tool_result_t::error(OBFSTR("Struct not found: ") + struct_name);

    tinfo_t tif;
    if (!tif.get_numbered_type(ti, ordinal))
        return tool_result_t::error(OBFSTR("Cannot load struct"));

    udt_type_data_t udt;
    if (!tif.get_udt_details(&udt))
        return tool_result_t::error(OBFSTR("Not a struct/union"));

    uint64_t field_offset = 0;
    bool found = false;
    for (size_t i = 0; i < udt.size(); i++)
    {
        if (udt[i].name == field_name.c_str())
        {
            field_offset = udt[i].offset / 8;
            found = true;
            break;
        }
    }

    if (!found)
        return tool_result_t::error(OBFSTR("Field not found: ") + field_name);

    json result;
    result["struct"] = struct_name;
    result["field"] = field_name;
    result["field_offset"] = field_offset;
    result["note"] = "Use find_immediate or search to find accesses to this offset";

    return tool_result_t::ok(OBFSTR("Struct field info retrieved"), result);
}

tool_result_t create_stack_var(const json& params)
{
    auto ea_opt = helpers::parse_address(params["address"].get<std::string>());
    if (!ea_opt)
        return tool_result_t::error(OBFSTR("Invalid address"));

    func_t* pfn = get_func(*ea_opt);
    if (!pfn)
        return tool_result_t::error(OBFSTR("No function at address"));

    sval_t offset = params["offset"].get<int64_t>();
    std::string var_name = params["name"].get<std::string>();
    std::string type_str = params.value("type", "__int64");

    tinfo_t mt;
    if (!parse_decl(&mt, nullptr, nullptr, (type_str + " x;").c_str(), PT_SIL | PT_VAR))
        mt = tinfo_t(BT_INT64);

    if (!define_stkvar(pfn, var_name.c_str(), offset, mt))
        return tool_result_t::error(OBFSTR("Failed to create stack variable"));

    return tool_result_t::ok(OBFSTR("Stack variable created: ") + var_name);
}

tool_result_t delete_stack_var(const json& params)
{
    auto ea_opt = helpers::parse_address(params["address"].get<std::string>());
    if (!ea_opt)
        return tool_result_t::error(OBFSTR("Invalid address"));

    func_t* pfn = get_func(*ea_opt);
    if (!pfn)
        return tool_result_t::error(OBFSTR("No function at address"));

    std::string var_name = params["name"].get<std::string>();

    std::string py_code =
        "import ida_frame, ida_funcs, ida_struct\n"
        "pfn = ida_funcs.get_func(" + std::to_string(*ea_opt) + ")\n"
        "_aida_del_result = False\n"
        "if pfn:\n"
        "    frame = ida_frame.get_frame(pfn)\n"
        "    if frame:\n"
        "        for i in range(frame.memqty):\n"
        "            m = frame.get_member(i)\n"
        "            if m and ida_struct.get_member_name(m.id) == '" + var_name + "':\n"
        "                ida_struct.del_struc_member(frame, m.soff)\n"
        "                _aida_del_result = True\n"
        "                break\n";

    extlang_object_t python = find_extlang_by_name("python");
    if (!python)
        return tool_result_t::error(OBFSTR("Python not available for stack var deletion"));

    qstring errbuf;
    if (!python->eval_snippet(py_code.c_str(), &errbuf))
        return tool_result_t::error(OBFSTR("Python error: ") + std::string(errbuf.c_str()));

    idc_value_t rv;
    qstring eval_err;
    if (python->eval_expr(&rv, BADADDR, "_aida_del_result", &eval_err)
        && rv.is_integral() && (rv.vtype == VT_INT64 ? rv.i64 : rv.num) != 0)
        return tool_result_t::ok(OBFSTR("Stack variable deleted: ") + var_name);

    return tool_result_t::error(OBFSTR("Variable not found in stack frame: ") + var_name);
}

tool_result_t read_struct_field(const json& params)
{
    auto ea_opt = helpers::parse_address(params["address"].get<std::string>());
    if (!ea_opt)
        return tool_result_t::error(OBFSTR("Invalid address"));

    std::string struct_name = params["struct_name"].get<std::string>();
    std::string field_name = params["field_name"].get<std::string>();

    til_t* ti = get_idati();
    int32 ordinal = get_type_ordinal(ti, struct_name.c_str());
    if (ordinal <= 0)
        return tool_result_t::error(OBFSTR("Struct not found"));

    tinfo_t tif;
    if (!tif.get_numbered_type(ti, ordinal))
        return tool_result_t::error(OBFSTR("Cannot load struct"));

    udt_type_data_t udt;
    if (!tif.get_udt_details(&udt))
        return tool_result_t::error(OBFSTR("Not a struct"));

    for (size_t i = 0; i < udt.size(); i++)
    {
        if (udt[i].name == field_name.c_str())
        {
            ea_t field_ea = *ea_opt + udt[i].offset / 8;
            asize_t field_bytes = udt[i].size / 8;

            json result;
            result["address"] = helpers::format_address(*ea_opt);
            result["field_address"] = helpers::format_address(field_ea);
            result["field_name"] = field_name;
            result["field_offset"] = udt[i].offset / 8;
            result["field_size"] = field_bytes;

            if (field_bytes <= 8 && is_loaded(field_ea))
            {
                uval_t val;
                if (get_data_value(&val, field_ea, field_bytes))
                {
                    result["value"] = val;
                    result["hex"] = helpers::format_address(val);
                }
            }

            return tool_result_t::ok(OBFSTR("Field value read"), result);
        }
    }

    return tool_result_t::error(OBFSTR("Field not found: ") + field_name);
}

tool_result_t list_types(const json& params)
{
    int offset = params.value("offset", 0);
    int limit = params.value("limit", 100);
    std::string filter = params.value("filter", "");

    std::regex filter_regex;
    bool use_filter = !filter.empty();
    if (use_filter)
    {
        try { filter_regex = std::regex(filter, std::regex::icase); }
        catch (...) { return tool_result_t::error(OBFSTR("Invalid filter regex")); }
    }

    til_t* ti = get_idati();
    if (!ti)
        return tool_result_t::error(OBFSTR("No local type library"));

    json types = json::array();
    uint32 total = get_ordinal_count(ti);
    int skipped = 0;

    for (uint32 i = 1; i <= total && (int)types.size() < limit; i++)
    {
        const char* tname = get_numbered_type_name(ti, i);
        if (!tname)
            continue;

        if (use_filter && !std::regex_search(tname, filter_regex))
            continue;

        if (skipped < offset)
        {
            skipped++;
            continue;
        }

        tinfo_t tif;
        tif.get_numbered_type(ti, i);

        types.push_back({
            {"ordinal", i},
            {"name", tname},
            {"is_struct", tif.is_struct()},
            {"is_enum", tif.is_enum()},
            {"is_typedef", tif.is_typedef()},
            {"size", (size_t)tif.get_size()}
        });
    }

    json result;
    result["types"] = types;
    result["total"] = total;
    result["returned"] = types.size();

    return tool_result_t::ok(OBFSTR("Types listed"), result);
}

tool_result_t create_enum(const json& params)
{
    std::string name = params["name"].get<std::string>();
    if (name.empty())
        return tool_result_t::error(OBFSTR("Enum name is required"));

    tinfo_t tif;
    enum_type_data_t etd;

    if (params.contains("members") && params["members"].is_array())
    {
        for (const auto& mem : params["members"])
        {
            edm_t m;
            m.name = (mem.contains("name") && mem["name"].is_string()) ? mem["name"].get<std::string>().c_str() : "member";
            m.value = (mem.contains("value") && mem["value"].is_number()) ? mem["value"].get<int64_t>() : 0;
            etd.push_back(m);
        }
    }

    if (!tif.create_enum(etd))
        return tool_result_t::error(OBFSTR("Failed to construct enum tinfo for: ") + name);
    if (tif.set_named_type(get_idati(), name.c_str()) != TERR_OK)
        return tool_result_t::error(OBFSTR("Failed to register enum in type library: ") + name);

    return tool_result_t::ok(OBFSTR("Enum created: ") + name);
}

void register_tools()
{
    auto& registry = ToolRegistry::instance();

    registry.register_tool({OBFSTR("declare_type"), OBFSTR("type"),
        OBFSTR("Parse and declare C type(s) in the local type library."),
        {{OBFSTR("declaration"), OBFSTR("string"), OBFSTR("C type declaration (struct, enum, typedef, etc.)"), true}},
        declare_type, false});

    registry.register_tool({OBFSTR("apply_type"), OBFSTR("type"),
        OBFSTR("Apply a C type to a function, global, or address."),
        {{OBFSTR("address"), OBFSTR("string"), OBFSTR("Target address"), true},
         {OBFSTR("type"), OBFSTR("string"), OBFSTR("C type declaration (e.g., 'int __fastcall(void*, int)')"), true}},
        apply_type, false});

    registry.register_tool({OBFSTR("infer_type"), OBFSTR("type"),
        OBFSTR("Infer/guess the type at an address using Hex-Rays or heuristics."),
        {{OBFSTR("address"), OBFSTR("string"), OBFSTR("Address to analyze"), true}},
        infer_type});

    registry.register_tool({OBFSTR("search_structs"), OBFSTR("type"),
        OBFSTR("Search structures/types by name pattern (regex)."),
        {{OBFSTR("pattern"), OBFSTR("string"), OBFSTR("Regex pattern"), true},
         {OBFSTR("limit"), OBFSTR("number"), OBFSTR("Max results (default 50)"), false}},
        search_structs});

    registry.register_tool({OBFSTR("get_struct"), OBFSTR("type"),
        OBFSTR("Get detailed struct/type info including all members."),
        {{OBFSTR("name"), OBFSTR("string"), OBFSTR("Type name"), true}},
        get_struct});

    registry.register_tool({OBFSTR("create_struct"), OBFSTR("type"),
        OBFSTR("Create a new struct type."),
        {{OBFSTR("name"), OBFSTR("string"), OBFSTR("Struct name"), true},
         {OBFSTR("members"), OBFSTR("array"), OBFSTR("Array of {name, type, offset} objects"), false, {},
          json::object({
              {"type", "object"},
              {"properties", json::object({
                  {"name", json::object({{"type", "string"}, {"description", "Member name"}})},
                  {"type", json::object({{"type", "string"}, {"description", "C type (e.g., 'int', 'char*')"}})},
                  {"offset", json::object({{"type", "number"}, {"description", "Byte offset in struct"}})}
              })},
              {"required", json::array({"name"})}
          })
        }},
        create_struct, false});

    registry.register_tool({OBFSTR("add_struct_member"), OBFSTR("type"),
        OBFSTR("Add a member to an existing struct."),
        {{OBFSTR("struct_name"), OBFSTR("string"), OBFSTR("Struct name"), true},
         {OBFSTR("member_name"), OBFSTR("string"), OBFSTR("Member name"), true},
         {OBFSTR("type"), OBFSTR("string"), OBFSTR("Member C type (default 'int')"), false},
         {OBFSTR("offset"), OBFSTR("number"), OBFSTR("Byte offset in struct"), false}},
        add_struct_member, false});

    registry.register_tool({OBFSTR("get_struct_field_xrefs"), OBFSTR("type"),
        OBFSTR("Get cross-references to a specific struct field."),
        {{OBFSTR("struct_name"), OBFSTR("string"), OBFSTR("Struct name"), true},
         {OBFSTR("field_name"), OBFSTR("string"), OBFSTR("Field name"), true},
         {OBFSTR("limit"), OBFSTR("number"), OBFSTR("Max results"), false}},
        get_struct_field_xrefs});

    registry.register_tool({OBFSTR("create_stack_var"), OBFSTR("type"),
        OBFSTR("Create a stack variable in a function's frame."),
        {{OBFSTR("address"), OBFSTR("string"), OBFSTR("Function address"), true},
         {OBFSTR("offset"), OBFSTR("number"), OBFSTR("Stack offset"), true},
         {OBFSTR("name"), OBFSTR("string"), OBFSTR("Variable name"), true},
         {OBFSTR("type"), OBFSTR("string"), OBFSTR("C type (default '__int64')"), false}},
        create_stack_var, false});

    registry.register_tool({OBFSTR("delete_stack_var"), OBFSTR("type"),
        OBFSTR("Delete a stack variable by name."),
        {{OBFSTR("address"), OBFSTR("string"), OBFSTR("Function address"), true},
         {OBFSTR("name"), OBFSTR("string"), OBFSTR("Variable name to delete"), true}},
        delete_stack_var, false});

    registry.register_tool({OBFSTR("read_struct_field"), OBFSTR("type"),
        OBFSTR("Read the value of a struct field at a specific address."),
        {{OBFSTR("address"), OBFSTR("string"), OBFSTR("Base address of the struct instance"), true},
         {OBFSTR("struct_name"), OBFSTR("string"), OBFSTR("Struct type name"), true},
         {OBFSTR("field_name"), OBFSTR("string"), OBFSTR("Field name to read"), true}},
        read_struct_field});

    registry.register_tool({OBFSTR("list_types"), OBFSTR("type"),
        OBFSTR("List all types in the local type library (paginated, filtered)."),
        {{OBFSTR("offset"), OBFSTR("number"), OBFSTR("Starting offset"), false},
         {OBFSTR("limit"), OBFSTR("number"), OBFSTR("Max results (default 100)"), false},
         {OBFSTR("filter"), OBFSTR("string"), OBFSTR("Regex filter"), false}},
        list_types});

    registry.register_tool({OBFSTR("create_enum"), OBFSTR("type"),
        OBFSTR("Create a new enum type."),
        {{OBFSTR("name"), OBFSTR("string"), OBFSTR("Enum name"), true},
         {OBFSTR("members"), OBFSTR("array"), OBFSTR("Array of {name, value} objects"), false, {},
          json::object({
              {"type", "object"},
              {"properties", json::object({
                  {"name", json::object({{"type", "string"}, {"description", "Enum member name"}})},
                  {"value", json::object({{"type", "number"}, {"description", "Enum member value"}})}
              })},
              {"required", json::array({"name", "value"})}
          })
        }},
        create_enum, false});
}

}

namespace import_tools
{

struct import_data_t
{
    json imports;
    int limit;
    int count;
    std::string module_name;
    std::regex* filter;
};

static int idaapi import_enum_cb(ea_t ea, const char* name, uval_t ord, void* param)
{
    auto* data = static_cast<import_data_t*>(param);
    if (data->count >= data->limit)
        return 0;

    std::string import_name = name ? name : "";
    if (data->filter && !import_name.empty() && !std::regex_search(import_name, *data->filter))
        return 1;

    json entry;
    entry["address"] = helpers::format_address(ea);
    entry["name"] = import_name;
    entry["ordinal"] = ord;
    entry["module"] = data->module_name;
    data->imports.push_back(entry);
    data->count++;
    return 1;
}

tool_result_t list_imports(const json& params)
{
    int offset = params.value("offset", 0);
    int limit = params.value("limit", 200);
    std::string filter = params.value("filter", "");

    std::regex filter_regex;
    std::regex* filter_ptr = nullptr;
    if (!filter.empty())
    {
        try {
            filter_regex = std::regex(filter, std::regex::icase);
            filter_ptr = &filter_regex;
        }
        catch (...) { return tool_result_t::error(OBFSTR("Invalid filter regex")); }
    }

    json all_imports = json::array();
    uint module_count = get_import_module_qty();
    int total_count = 0;
    int skipped = 0;

    for (uint i = 0; i < module_count && total_count < limit; i++)
    {
        qstring mod_name;
        get_import_module_name(&mod_name, i);

        import_data_t data;
        data.imports = json::array();
        data.limit = limit - total_count;
        data.count = 0;
        data.module_name = mod_name.c_str();
        data.filter = filter_ptr;

        enum_import_names(i, import_enum_cb, &data);

        for (auto& imp : data.imports)
        {
            if (skipped < offset)
            {
                skipped++;
                continue;
            }
            all_imports.push_back(imp);
            total_count++;
        }
    }

    json result;
    result["imports"] = all_imports;
    result["module_count"] = module_count;
    result["returned"] = total_count;

    return tool_result_t::ok(OBFSTR("Listed ") + std::to_string(total_count) + " imports", result);
}

tool_result_t list_exports(const json& params)
{
    int offset = params.value("offset", 0);
    int limit = params.value("limit", 200);
    std::string filter = params.value("filter", "");

    std::regex filter_regex;
    bool use_filter = !filter.empty();
    if (use_filter)
    {
        try { filter_regex = std::regex(filter, std::regex::icase); }
        catch (...) { return tool_result_t::error(OBFSTR("Invalid filter regex")); }
    }

    json exports = json::array();
    size_t total = get_entry_qty();
    int count = 0;
    int skipped = 0;

    for (size_t i = 0; i < total && count < limit; i++)
    {
        uval_t ord = get_entry_ordinal(i);
        ea_t ea = get_entry(ord);
        if (ea == BADADDR)
            continue;

        qstring ename;
        get_entry_name(&ename, ord);

        if (use_filter && !std::regex_search(ename.c_str(), filter_regex))
            continue;

        if (skipped < offset)
        {
            skipped++;
            continue;
        }

        exports.push_back({
            {"address", helpers::format_address(ea)},
            {"name", ename.c_str()},
            {"ordinal", ord}
        });
        count++;
    }

    json result;
    result["exports"] = exports;
    result["total"] = total;
    result["returned"] = count;

    return tool_result_t::ok(OBFSTR("Listed ") + std::to_string(count) + " exports", result);
}

tool_result_t get_import(const json& params)
{
    std::string name_or_addr = params["name"].get<std::string>();

    auto ea_opt = helpers::parse_address(name_or_addr);
    if (!ea_opt)
        return tool_result_t::error(OBFSTR("Cannot resolve import"));

    qstring imp_name;
    if (get_name(&imp_name, *ea_opt) <= 0)
        return tool_result_t::error(OBFSTR("No name at address"));

    json result;
    result["address"] = helpers::format_address(*ea_opt);
    result["name"] = imp_name.c_str();

    xrefblk_t xb;
    json xrefs = json::array();
    int count = 0;
    for (bool ok = xb.first_to(*ea_opt, XREF_ALL); ok && count < 50; ok = xb.next_to())
    {
        xrefs.push_back({
            {"from", helpers::format_address(xb.from)},
            {"from_name", helpers::get_name_or_address(xb.from)}
        });
        count++;
    }
    result["references"] = xrefs;

    return tool_result_t::ok(OBFSTR("Import info retrieved"), result);
}

void register_tools()
{
    auto& registry = ToolRegistry::instance();

    registry.register_tool({OBFSTR("list_imports"), OBFSTR("import"),
        OBFSTR("List all imported symbols with module names (paginated, filtered)."),
        {{OBFSTR("offset"), OBFSTR("number"), OBFSTR("Start offset"), false},
         {OBFSTR("limit"), OBFSTR("number"), OBFSTR("Max results (default 200)"), false},
         {OBFSTR("filter"), OBFSTR("string"), OBFSTR("Regex filter for import names"), false}},
        list_imports});

    registry.register_tool({OBFSTR("list_exports"), OBFSTR("import"),
        OBFSTR("List all exported symbols (paginated, filtered)."),
        {{OBFSTR("offset"), OBFSTR("number"), OBFSTR("Start offset"), false},
         {OBFSTR("limit"), OBFSTR("number"), OBFSTR("Max results (default 200)"), false},
         {OBFSTR("filter"), OBFSTR("string"), OBFSTR("Regex filter"), false}},
        list_exports});

    registry.register_tool({OBFSTR("get_import"), OBFSTR("import"),
        OBFSTR("Get details about a specific import by name or address."),
        {{OBFSTR("name"), OBFSTR("string"), OBFSTR("Import name or address"), true}},
        get_import});
}

}

namespace search_tools
{

tool_result_t search_strings(const json& params)
{
    std::string pattern = params["pattern"].get<std::string>();
    int limit = params.value("limit", 100);
    int offset = params.value("offset", 0);


    {
        std::string hash = aida_db::AnalysisDB::instance().get_binary_hash();
        if (!hash.empty())
        {
            auto& store = graphrag::GraphStore::instance();
            auto stats = store.get_stats(hash);
            if (stats.nodes > 0)
            {
                graphrag::QueryEngine qe(store);
                json semantic_results = qe.search_semantic(hash, pattern, limit);
                if (!semantic_results.empty())
                {
                    return tool_result_t::ok(
                        OBFSTR("Binary is indexed Ã¢â‚¬â€ used semantic search (faster). Found ")
                        + std::to_string(semantic_results.size())
                        + OBFSTR(" results. Use search_semantic directly for best performance."),
                        semantic_results);
                }

            }
        }
    }

    std::regex filter_regex;
    try { filter_regex = std::regex(pattern, std::regex::icase); }
    catch (...) { return tool_result_t::error(OBFSTR("Invalid regex pattern")); }

    size_t total = get_strlist_qty();
    if (total == 0)
    {
        show_wait_box("NODELAY\nAiDA: Building string list...");
        build_strlist();
        hide_wait_box();
        total = get_strlist_qty();
    }

    json strings = json::array();
    int count = 0;
    int skipped = 0;

    show_wait_box("NODELAY\nAiDA: Searching strings (0 / %zu)...", total);

    for (size_t i = 0; i < total && count < limit; i++)
    {
        if (i % 500 == 0)
        {
            replace_wait_box("AiDA: Searching strings (%zu / %zu)...", i, total);
            if (user_cancelled())
                break;
        }

        string_info_t si;
        if (!get_strlist_item(&si, i))
            continue;

        qstring str;
        if (get_strlit_contents(&str, si.ea, si.length, si.type) <= 0)
            continue;

        if (!std::regex_search(str.c_str(), filter_regex))
            continue;

        if (skipped < offset)
        {
            skipped++;
            continue;
        }

        strings.push_back({
            {"address", helpers::format_address(si.ea)},
            {"value", str.c_str()},
            {"length", si.length},
            {"type", si.type}
        });
        count++;
    }

    hide_wait_box();

    json result;
    result["strings"] = strings;
    result["total_strings"] = total;
    result["returned"] = count;

    return tool_result_t::ok(OBFSTR("Found ") + std::to_string(count) + " matching strings", result);
}

tool_result_t find_bytes(const json& params)
{
    std::string pattern = params["pattern"].get<std::string>();
    int limit = params.value("limit", 20);

    ea_t start_ea = inf_get_min_ea();
    ea_t end_ea = inf_get_max_ea();

    if (params.contains("start"))
    {
        auto s = helpers::parse_address(params["start"].get<std::string>());
        if (s) start_ea = *s;
    }
    if (params.contains("end"))
    {
        auto e = helpers::parse_address(params["end"].get<std::string>());
        if (e) end_ea = *e;
    }

    compiled_binpat_vec_t binpat;
    qstring errbuf;
    if (!parse_binpat_str(&binpat, start_ea, pattern.c_str(), 16, PBSENC_DEF1BPU, &errbuf))
        return tool_result_t::error(OBFSTR("Invalid byte pattern: ") + std::string(errbuf.c_str()));

    json matches = json::array();
    ea_t current = start_ea;

    show_wait_box("NODELAY\nAiDA: Searching byte pattern...");

    for (int i = 0; i < limit; i++)
    {
        replace_wait_box("AiDA: Searching byte pattern (%d found)...", i);
        if (user_cancelled())
            break;

        ea_t found = bin_search(current, end_ea, binpat,
                                BIN_SEARCH_FORWARD);
        if (found == BADADDR)
            break;

        matches.push_back({
            {"address", helpers::format_address(found)},
            {"name", helpers::get_name_or_address(found)}
        });

        current = found + 1;
    }

    hide_wait_box();

    return tool_result_t::ok(OBFSTR("Found ") + std::to_string(matches.size()) + " matches", matches);
}

tool_result_t find_instructions(const json& params)
{
    std::string pattern = params["pattern"].get<std::string>();
    int limit = params.value("limit", 20);


    {
        std::string hash = aida_db::AnalysisDB::instance().get_binary_hash();
        if (!hash.empty())
        {
            auto& store = graphrag::GraphStore::instance();
            auto stats = store.get_stats(hash);
            if (stats.nodes > 0)
            {
                graphrag::QueryEngine qe(store);
                json semantic_results = qe.search_semantic(hash, pattern, limit);
                if (!semantic_results.empty())
                {
                    return tool_result_t::ok(
                        OBFSTR("Binary is indexed Ã¢â‚¬â€ used semantic search (faster). Found ")
                        + std::to_string(semantic_results.size())
                        + OBFSTR(" results. Use search_semantic directly for best performance."),
                        semantic_results);
                }

            }
        }
    }

    ea_t start_ea = inf_get_min_ea();
    ea_t end_ea = inf_get_max_ea();

    if (params.contains("start"))
    {
        auto s = helpers::parse_address(params["start"].get<std::string>());
        if (s) start_ea = *s;
    }

    json matches = json::array();
    ea_t ea = start_ea;

    show_wait_box("NODELAY\nAiDA: Searching instructions...");

    while (ea < end_ea && (int)matches.size() < limit)
    {
        replace_wait_box("AiDA: Searching instructions (%zu found)...", matches.size());
        if (user_cancelled())
            break;

        ea_t found = find_text(ea, 0, 0, pattern.c_str(),
                               SEARCH_DOWN | SEARCH_NEXT);
        if (found == BADADDR)
            break;

        insn_t insn;
        if (decode_insn(&insn, found) > 0)
        {
            qstring disasm_line;
            generate_disasm_line(&disasm_line, found, GENDSM_FORCE_CODE);
            qstring clean;
            tag_remove(&clean, disasm_line.c_str());

            matches.push_back({
                {"address", helpers::format_address(found)},
                {"disassembly", clean.c_str()},
                {"size", insn.size}
            });
        }

        ea = found + 1;
    }

    hide_wait_box();

    return tool_result_t::ok(OBFSTR("Found ") + std::to_string(matches.size()) + " instructions", matches);
}

tool_result_t find_immediate(const json& params)
{
    uint64_t value;
    if (params["value"].is_string())
    {
        auto ea_opt = helpers::parse_address(params["value"].get<std::string>());
        if (!ea_opt)
            return tool_result_t::error(OBFSTR("Invalid value"));
        value = *ea_opt;
    }
    else
    {
        value = params["value"].get<uint64_t>();
    }

    int limit = params.value("limit", 20);

    ea_t start_ea = inf_get_min_ea();
    if (params.contains("start"))
    {
        auto s = helpers::parse_address(params["start"].get<std::string>());
        if (s) start_ea = *s;
    }

    json matches = json::array();
    ea_t ea = start_ea;

    show_wait_box("NODELAY\nAiDA: Searching immediate values...");

    for (int i = 0; i < limit; i++)
    {
        replace_wait_box("AiDA: Searching immediate values (%d found)...", i);
        if (user_cancelled())
            break;

        int opnum = -1;
        ea_t found = find_imm(ea, SEARCH_DOWN | SEARCH_NEXT,
                              (uval_t)value, &opnum);
        if (found == BADADDR)
            break;

        qstring disasm_line;
        generate_disasm_line(&disasm_line, found, GENDSM_FORCE_CODE);
        qstring clean;
        tag_remove(&clean, disasm_line.c_str());

        matches.push_back({
            {"address", helpers::format_address(found)},
            {"operand", opnum},
            {"disassembly", clean.c_str()},
            {"function", helpers::get_name_or_address(found)}
        });

        ea = found + 1;
    }

    hide_wait_box();

    return tool_result_t::ok(OBFSTR("Found ") + std::to_string(matches.size()) + " occurrences", matches);
}

void register_tools()
{
    auto& registry = ToolRegistry::instance();

    registry.register_tool({OBFSTR("search_strings"), OBFSTR("search"),
        OBFSTR("Search strings with case-insensitive regex (paginated). "
               "Auto-redirects to semantic search when binary is indexed for faster results."),
        {{OBFSTR("pattern"), OBFSTR("string"), OBFSTR("Regex pattern to match"), true},
         {OBFSTR("offset"), OBFSTR("number"), OBFSTR("Pagination offset"), false},
         {OBFSTR("limit"), OBFSTR("number"), OBFSTR("Max results (default 100)"), false}},
        search_strings});

    registry.register_tool({OBFSTR("find_bytes"), OBFSTR("search"),
        OBFSTR("Find byte pattern(s) in binary. Supports wildcards with '??' (e.g., '48 8B ?? ?? 89')."),
        {{OBFSTR("pattern"), OBFSTR("string"), OBFSTR("Hex byte pattern (e.g., '48 8B ?? ??')"), true},
         {OBFSTR("start"), OBFSTR("string"), OBFSTR("Start address (optional)"), false},
         {OBFSTR("end"), OBFSTR("string"), OBFSTR("End address (optional)"), false},
         {OBFSTR("limit"), OBFSTR("number"), OBFSTR("Max results (default 20)"), false}},
        find_bytes});

    registry.register_tool({OBFSTR("find_instructions"), OBFSTR("search"),
        OBFSTR("Find instruction sequence(s) in code by text match. "
               "Auto-redirects to semantic search when binary is indexed for faster results. "
               "Prefer search_semantic directly for indexed binaries."),
        {{OBFSTR("pattern"), OBFSTR("string"), OBFSTR("Instruction text to search for"), true},
         {OBFSTR("start"), OBFSTR("string"), OBFSTR("Start address (optional)"), false},
         {OBFSTR("limit"), OBFSTR("number"), OBFSTR("Max results (default 20)"), false}},
        find_instructions});

    registry.register_tool({OBFSTR("find_immediate"), OBFSTR("search"),
        OBFSTR("Find immediate value occurrences in instructions."),
        {{OBFSTR("value"), OBFSTR("string"), OBFSTR("Immediate value (decimal or 0x hex)"), true},
         {OBFSTR("start"), OBFSTR("string"), OBFSTR("Start address (optional)"), false},
         {OBFSTR("limit"), OBFSTR("number"), OBFSTR("Max results (default 20)"), false}},
        find_immediate});

}

}


namespace segment_tools
{

static std::string format_segment_permissions(const segment_t& seg)
{
    std::string perms;
    if ((seg.perm & SEGPERM_READ) != 0)  perms += "R";
    if ((seg.perm & SEGPERM_WRITE) != 0) perms += "W";
    if ((seg.perm & SEGPERM_EXEC) != 0)  perms += "X";
    return perms;
}

static int segment_bitness_bits(const segment_t& seg)
{
    switch (seg.bitness)
    {
        case 0: return 16;
        case 1: return 32;
        default: return 64;
    }
}

static qstring get_safe_segment_name(const segment_t* seg)
{
    qstring name;
    if (get_visible_segm_name(&name, seg) <= 0 || name.empty())
        name = "<unnamed>";
    return name;
}

static qstring get_safe_segment_class(const segment_t* seg)
{
    qstring sclass;
    if (get_segm_class(&sclass, seg) <= 0 || sclass.empty())
        sclass = "unknown";
    return sclass;
}

static json build_segment_json(const segment_t* seg)
{
    qstring name = get_safe_segment_name(seg);
    qstring sclass = get_safe_segment_class(seg);

    return {
        {"index", get_segm_num(seg->start_ea)},
        {"name", name.c_str()},
        {"class", sclass.c_str()},
        {"start", helpers::format_address(seg->start_ea)},
        {"end", helpers::format_address(seg->end_ea)},
        {"size", seg->end_ea - seg->start_ea},
        {"permissions", format_segment_permissions(*seg)},
        {"bitness", segment_bitness_bits(*seg)},
        {"type", seg->type}
    };
}

tool_result_t list_segments(const json&)
{
    json segments = json::array();

    for (segment_t* seg = get_first_seg(); seg != nullptr; seg = get_next_seg(seg->start_ea))
    {
        if (seg->end_ea <= seg->start_ea)
            continue;

        segments.push_back(build_segment_json(seg));
    }

    return tool_result_t::ok(OBFSTR("Listed ") + std::to_string(segments.size()) + " segments", segments);
}

tool_result_t get_segment(const json& params)
{
    ea_t ea = BADADDR;

    if (params.contains("address"))
    {
        auto ea_opt = helpers::parse_address(params["address"].get<std::string>());
        if (ea_opt) ea = *ea_opt;
    }
    else if (params.contains("name"))
    {
        segment_t* seg = get_segm_by_name(params["name"].get<std::string>().c_str());
        if (seg) ea = seg->start_ea;
    }

    if (ea == BADADDR)
        return tool_result_t::error(OBFSTR("Segment not found"));

    segment_t* seg = getseg(ea);
    if (!seg)
        return tool_result_t::error(OBFSTR("No segment at address"));

    json result = build_segment_json(seg);
    result["alignment"] = seg->align;
    result["type"] = seg->type;

    return tool_result_t::ok(OBFSTR("Segment info retrieved"), result);
}

tool_result_t create_segment(const json& params)
{
    auto start_opt = helpers::parse_address(params["start"].get<std::string>());
    if (!start_opt)
        return tool_result_t::error(OBFSTR("Invalid start address"));

    auto end_opt = helpers::parse_address(params["end"].get<std::string>());
    if (!end_opt)
        return tool_result_t::error(OBFSTR("Invalid end address"));

    std::string name = params["name"].get<std::string>();
    std::string sclass = params.value("class", std::string("DATA"));

    if (*end_opt <= *start_opt)
        return tool_result_t::error(OBFSTR("End address must be greater than start address"));


    ea_t aligned_start = *start_opt & ~0xFULL;
    ea_t aligned_end   = (*end_opt + 0xF) & ~0xFULL;
    if (aligned_end <= aligned_start)
        aligned_end = aligned_start + 0x1000;


    if (getseg(aligned_start))
        return tool_result_t::error(OBFSTR("Segment already exists at ") + helpers::format_address(aligned_start));


    segment_t seg;
    seg.start_ea = aligned_start;
    seg.end_ea   = aligned_end;
    seg.bitness  = inf_is_64bit() ? 2 : (inf_is_32bit_exactly() ? 1 : 0);
    seg.align    = saRelByte;
    seg.comb     = scPub;
    seg.perm     = SEGPERM_READ | SEGPERM_WRITE;

    bool is_code = (sclass == "CODE");
    if (is_code)
    {
        seg.type = SEG_CODE;
        seg.perm |= SEGPERM_EXEC;
    }
    else
    {
        seg.type = SEG_DATA;
    }

    if (!add_segm_ex(&seg, name.c_str(), sclass.c_str(), ADDSEG_QUIET | ADDSEG_NOSREG))
        return tool_result_t::error(OBFSTR("Failed to create segment at ") +
                                    helpers::format_address(aligned_start) + OBFSTR("-") +
                                    helpers::format_address(aligned_end));

    json result;
    result["start"] = helpers::format_address(aligned_start);
    result["end"]   = helpers::format_address(aligned_end);
    result["name"]  = name;
    result["size"]  = aligned_end - aligned_start;
    result["bitness"] = seg.bitness == 2 ? 64 : (seg.bitness == 1 ? 32 : 16);

    return tool_result_t::ok(OBFSTR("Segment created: ") + name, result);
}

void register_tools()
{
    auto& registry = ToolRegistry::instance();

    registry.register_tool({OBFSTR("list_segments"), OBFSTR("segment"),
        OBFSTR("List all segments/sections in the binary."),
        {}, list_segments});

    registry.register_tool({OBFSTR("get_segment"), OBFSTR("segment"),
        OBFSTR("Get detailed info about a segment by address or name."),
        {{OBFSTR("address"), OBFSTR("string"), OBFSTR("Address within segment"), false},
         {OBFSTR("name"), OBFSTR("string"), OBFSTR("Segment name"), false}},
        get_segment});

    registry.register_tool({OBFSTR("create_segment"), OBFSTR("segment"),
        OBFSTR("Create a new segment with proper alignment. Automatically aligns addresses to paragraph "
               "boundaries and sets correct bitness (64/32/16) based on the current binary. "
               "Uses add_segm_ex for full control, avoiding 'bad segment start' errors with kernel addresses."),
        {{OBFSTR("start"), OBFSTR("string"), OBFSTR("Start address (will be aligned down to paragraph boundary)"), true},
         {OBFSTR("end"), OBFSTR("string"), OBFSTR("End address (will be aligned up to paragraph boundary)"), true},
         {OBFSTR("name"), OBFSTR("string"), OBFSTR("Segment name"), true},
         {OBFSTR("class"), OBFSTR("string"), OBFSTR("Segment class: CODE or DATA (default DATA)"), false}},
        create_segment, false});
}

}

namespace binary_tools
{

tool_result_t get_binary_info(const json&)
{
    json result;

    qstring procname = inf_get_procname();
    result["processor"] = procname.c_str();
    result["bitness"] = inf_get_app_bitness();
    result["is_64bit"] = inf_is_64bit();
    result["is_dll"] = inf_is_dll();
    result["is_big_endian"] = inf_is_be();
    result["file_type"] = (int)inf_get_filetype();
    result["min_ea"] = helpers::format_address(inf_get_min_ea());
    result["max_ea"] = helpers::format_address(inf_get_max_ea());

    result["function_count"] = (size_t)get_func_qty();
    result["segment_count"] = get_segm_qty();
    result["entry_count"] = (size_t)get_entry_qty();
    result["import_module_count"] = get_import_module_qty();

    return tool_result_t::ok(OBFSTR("Binary info retrieved"), result);
}

void register_tools()
{
    auto& registry = ToolRegistry::instance();

    registry.register_tool({OBFSTR("get_binary_info"), OBFSTR("binary"),
        OBFSTR("Get binary file metadata (processor, bitness, file type, etc)."),
        {}, get_binary_info});
}

}

namespace python_tools
{

tool_result_t execute_python(const json& params)
{
    std::string code = params["code"].get<std::string>();

    static const char b64_alphabet[] =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    std::string b64;
    b64.reserve(((code.size() + 2) / 3) * 4);
    for (size_t i = 0; i < code.size(); i += 3)
    {
        unsigned char c0 = static_cast<unsigned char>(code[i]);
        unsigned char c1 = (i + 1 < code.size()) ? static_cast<unsigned char>(code[i + 1]) : 0;
        unsigned char c2 = (i + 2 < code.size()) ? static_cast<unsigned char>(code[i + 2]) : 0;
        uint32_t v = (static_cast<uint32_t>(c0) << 16)
                   | (static_cast<uint32_t>(c1) << 8)
                   | static_cast<uint32_t>(c2);
        b64.push_back(b64_alphabet[(v >> 18) & 0x3F]);
        b64.push_back(b64_alphabet[(v >> 12) & 0x3F]);
        b64.push_back((i + 1 < code.size()) ? b64_alphabet[(v >> 6) & 0x3F] : '=');
        b64.push_back((i + 2 < code.size()) ? b64_alphabet[v & 0x3F] : '=');
    }

    std::string wrapper = R"PY(
import sys, io, json as _json, base64 as _b64
_aida_stdout = io.StringIO()
_aida_stderr = io.StringIO()
_aida_result = None
_aida_user_code = _b64.b64decode(")PY";
    wrapper += b64;
    wrapper += R"PY(").decode("utf-8")
try:
    _old_stdout, _old_stderr = sys.stdout, sys.stderr
    sys.stdout, sys.stderr = _aida_stdout, _aida_stderr
    try:
        _aida_result = eval(compile(_aida_user_code, "<aida>", "eval"))
    except SyntaxError:
        exec(compile(_aida_user_code, "<aida>", "exec"))
    sys.stdout, sys.stderr = _old_stdout, _old_stderr
except Exception as _e:
    sys.stdout, sys.stderr = _old_stdout, _old_stderr
    import traceback as _tb
    _aida_stderr.write(_tb.format_exc())
_aida_out = _json.dumps({
    "result": str(_aida_result) if _aida_result is not None else None,
    "stdout": _aida_stdout.getvalue(),
    "stderr": _aida_stderr.getvalue()
})
)PY";

    extlang_object_t python = find_extlang_by_name("python");
    if (!python)
        return tool_result_t::error(OBFSTR("Python interpreter not available in IDA"));

    qstring errbuf;
    bool ok = python->eval_snippet(wrapper.c_str(), &errbuf);

    if (!ok)
        return tool_result_t::error(OBFSTR("Python execution failed: ") + std::string(errbuf.c_str()));

    idc_value_t rv;
    qstring eval_err;
    if (python->eval_expr(&rv, BADADDR, "_aida_out", &eval_err))
    {
        try
        {
            std::string result_str = rv.c_str();
            json parsed = json::parse(result_str);
            return tool_result_t::ok(OBFSTR("Python executed successfully"), parsed);
        }
        catch (...) {}
    }

    return tool_result_t::ok(OBFSTR("Python executed (no structured output)"));
}

void register_tools()
{
    auto& registry = ToolRegistry::instance();

    registry.register_tool({OBFSTR("execute_python"), OBFSTR("python"),
        OBFSTR("Execute arbitrary Python code in IDA context. Returns dict with result/stdout/stderr. ") +
        OBFSTR("Supports Jupyter-style evaluation (expressions auto-return, statements exec)."),
        {{OBFSTR("code"), OBFSTR("string"), OBFSTR("Python code to execute"), true}},
        execute_python, false});
}

}


static void responsive_auto_wait(ea_t start, ea_t end, const char* status_msg)
{
    if (start != 0 || end != BADADDR)
        auto_mark_range(start, end, AU_FINAL);

    if (!auto_is_ok() && !user_cancelled())
        auto_wait_range(0, BADADDR);

    (void)status_msg;
}

namespace navigation_tools
{

tool_result_t jump_to_address(const json& params)
{
    auto ea_opt = helpers::parse_address(params["address"].get<std::string>());
    if (!ea_opt)
        return tool_result_t::error(OBFSTR("Invalid address"));

    bool ok = jumpto(*ea_opt);
    if (!ok)
        return tool_result_t::error(OBFSTR("Failed to navigate to ") + helpers::format_address(*ea_opt));

    return tool_result_t::ok(OBFSTR("Navigated to ") + helpers::format_address(*ea_opt));
}

tool_result_t get_current_address(const json&)
{
    ea_t ea = get_screen_ea();
    if (ea == BADADDR)
        return tool_result_t::error(OBFSTR("No current address available"));

    json data;
    data["address"] = helpers::format_address(ea);

    qstring name;
    if (get_name(&name, ea) > 0)
        data["name"] = std::string(name.c_str());

    func_t* fn = get_func(ea);
    if (fn)
    {
        data["function_start"] = helpers::format_address(fn->start_ea);
        qstring fname;
        if (get_func_name(&fname, fn->start_ea) > 0)
            data["function_name"] = std::string(fname.c_str());
        data["offset_in_function"] = helpers::format_address(ea - fn->start_ea);
    }

    segment_t* seg = getseg(ea);
    if (seg)
    {
        qstring segname;
        if (get_segm_name(&segname, seg) > 0)
            data["segment"] = std::string(segname.c_str());
    }

    return tool_result_t::ok(OBFSTR("Current address: ") + helpers::format_address(ea), data);
}

tool_result_t demangle_name(const json& params)
{
    std::string name = params["name"].get<std::string>();

    qstring demangled;
    int32 res = ::demangle_name(&demangled, name.c_str(), 0, DQT_FULL);

    if (res <= 0 || demangled.empty())
        return tool_result_t::error(OBFSTR("Could not demangle: ") + name);

    json data;
    data["mangled"] = name;
    data["demangled"] = std::string(demangled.c_str());

    return tool_result_t::ok(std::string(demangled.c_str()), data);
}

tool_result_t wait_for_analysis(const json&)
{
    show_wait_box("HIDECANCEL\nAiDA: Waiting for auto-analysis...");
    responsive_auto_wait(0, BADADDR, "Waiting for auto-analysis...");
    hide_wait_box();
    bool ok = auto_is_ok();

    if (!ok)
        return tool_result_t::error(OBFSTR("Analysis was cancelled by user"));

    return tool_result_t::ok(OBFSTR("Auto-analysis completed"));
}

tool_result_t delete_function(const json& params)
{
    auto ea_opt = helpers::parse_address(params["address"].get<std::string>());
    if (!ea_opt)
        return tool_result_t::error(OBFSTR("Invalid address"));

    func_t* fn = get_func(*ea_opt);
    if (!fn)
        return tool_result_t::error(OBFSTR("No function at ") + helpers::format_address(*ea_opt));

    qstring fname;
    get_func_name(&fname, fn->start_ea);
    ea_t start = fn->start_ea;

    bool ok = del_func(start);
    if (!ok)
        return tool_result_t::error(OBFSTR("Failed to delete function at ") + helpers::format_address(start));

    return tool_result_t::ok(OBFSTR("Deleted function ") + std::string(fname.c_str()) + " at " + helpers::format_address(start));
}

tool_result_t set_decompiler_comment(const json& params)
{
    auto ea_opt = helpers::parse_address(params["address"].get<std::string>());
    if (!ea_opt)
        return tool_result_t::error(OBFSTR("Invalid address"));

    std::string comment = params["comment"].get<std::string>();

    func_t* fn = get_func(*ea_opt);
    if (!fn)
        return tool_result_t::error(OBFSTR("No function at ") + helpers::format_address(*ea_opt));

    if (!ida_utils::is_safely_decompilable(fn))
        return tool_result_t::error(OBFSTR("Function is not decompilable (thunk/extern/tail)"));

    try
    {
        hexrays_failure_t hf;
        cfuncptr_t cfunc = decompile(fn, &hf);
        if (!cfunc)
            return tool_result_t::error(OBFSTR("Decompilation failed: ") + std::string(hf.desc().c_str()));

        treeloc_t loc;
        loc.ea = *ea_opt;
        loc.itp = ITP_SEMI;

        cfunc->set_user_cmt(loc, comment.c_str());
        cfunc->save_user_cmts();

        return tool_result_t::ok(OBFSTR("Decompiler comment set at ") + helpers::format_address(*ea_opt));
    }
    catch (const vd_failure_t& e)
    {
        return tool_result_t::error(OBFSTR("Decompilation failed: ") + std::string(e.desc().c_str()));
    }
    catch (...)
    {
        return tool_result_t::error(OBFSTR("Decompilation crashed for ") + helpers::format_address(*ea_opt));
    }
}

tool_result_t batch_rename(const json& params)
{
    auto renames = params["renames"];
    if (!renames.is_array())
        return tool_result_t::error(OBFSTR("'renames' must be an array of {address, name} objects"));

    int success_count = 0;
    int fail_count = 0;
    json results = json::array();

    for (const auto& item : renames)
    {
        if (!item.is_object() || !item.contains("address") || !item.contains("name"))
        {
            fail_count++;
            continue;
        }
        std::string addr_str = item["address"].is_string() ? item["address"].get<std::string>() : (item["address"].is_number() ? item["address"].dump() : "");
        std::string new_name = item["name"].is_string() ? item["name"].get<std::string>() : "";

        auto ea_opt = helpers::parse_address(addr_str);
        if (!ea_opt)
        {
            results.push_back({{"address", addr_str}, {"success", false}, {"error", "Invalid address"}});
            fail_count++;
            continue;
        }

        bool ok = set_name(*ea_opt, new_name.c_str(), SN_CHECK);
        if (ok)
        {
            results.push_back({{"address", addr_str}, {"success", true}, {"name", new_name}});
            success_count++;


            auto& store = graphrag::GraphStore::instance();
            auto* node = store.get_node_by_address(
                aida_db::AnalysisDB::instance().get_binary_hash(),
                graphrag::node_type_t::FUNCTION, *ea_opt);
            if (node)
            {
                node->name = new_name;
                store.upsert_node(*node);
            }
        }
        else
        {
            results.push_back({{"address", addr_str}, {"success", false}, {"error", "set_name failed"}});
            fail_count++;
        }
    }

    json data;
    data["results"] = results;
    data["success_count"] = success_count;
    data["fail_count"] = fail_count;

    return tool_result_t::ok(
        "Renamed " + std::to_string(success_count) + " items, " + std::to_string(fail_count) + " failures",
        data);
}

tool_result_t get_address_info(const json& params)
{
    auto ea_opt = helpers::parse_address(params["address"].get<std::string>());
    if (!ea_opt)
        return tool_result_t::error(OBFSTR("Invalid address"));

    ea_t ea = *ea_opt;
    json data;
    data["address"] = helpers::format_address(ea);

    qstring name;
    if (get_name(&name, ea) > 0)
        data["name"] = std::string(name.c_str());

    qstring demangled_name;
    if (name.size() > 0 && ::demangle_name(&demangled_name, name.c_str(), 0, DQT_FULL) > 0 && !demangled_name.empty())
        data["demangled"] = std::string(demangled_name.c_str());

    flags64_t f = get_flags(ea);
    data["is_code"] = is_code(f);
    data["is_data"] = is_data(f);
    data["is_head"] = is_head(f);
    data["is_tail"] = is_tail(f);
    data["has_name"] = has_name(f);
    data["has_xref"] = has_xref(f);

    qstring cmt;
    if (get_cmt(&cmt, ea, false) > 0)
        data["comment"] = std::string(cmt.c_str());

    qstring rcmt;
    if (get_cmt(&rcmt, ea, true) > 0)
        data["repeatable_comment"] = std::string(rcmt.c_str());

    func_t* fn = get_func(ea);
    if (fn)
    {
        qstring fname;
        get_func_name(&fname, fn->start_ea);
        data["function"] = std::string(fname.c_str());
        data["function_start"] = helpers::format_address(fn->start_ea);
        data["function_end"] = helpers::format_address(fn->end_ea);
    }

    segment_t* seg = getseg(ea);
    if (seg)
    {
        qstring segname;
        get_segm_name(&segname, seg);
        data["segment"] = std::string(segname.c_str());
        data["segment_start"] = helpers::format_address(seg->start_ea);
        data["segment_end"] = helpers::format_address(seg->end_ea);
    }

    tinfo_t ti;
    if (get_tinfo(&ti, ea))
    {
        qstring type_str;
        ti.print(&type_str);
        data["type"] = std::string(type_str.c_str());
    }

    return tool_result_t::ok(OBFSTR("Address info for ") + helpers::format_address(ea), data);
}

void register_tools()
{
    auto& registry = ToolRegistry::instance();

    registry.register_tool({OBFSTR("jump_to_address"), OBFSTR("navigation"),
        OBFSTR("Navigate IDA view to the specified address."),
        {{OBFSTR("address"), OBFSTR("string"), OBFSTR("Target address (hex or decimal)"), true}},
        jump_to_address});

    registry.register_tool({OBFSTR("get_current_address"), OBFSTR("navigation"),
        OBFSTR("Get the current cursor address in IDA with context (function, segment, name)."),
        {},
        get_current_address});

    registry.register_tool({OBFSTR("demangle_name"), OBFSTR("navigation"),
        OBFSTR("Demangle a C++ mangled symbol name."),
        {{OBFSTR("name"), OBFSTR("string"), OBFSTR("Mangled symbol name"), true}},
        demangle_name});

    registry.register_tool({OBFSTR("wait_for_analysis"), OBFSTR("navigation"),
        OBFSTR("Wait for IDA auto-analysis to complete before proceeding. Returns when all analysis queues are empty."),
        {},
        wait_for_analysis});

    registry.register_tool({OBFSTR("delete_function"), OBFSTR("navigation"),
        OBFSTR("Delete/remove a function definition at the given address."),
        {{OBFSTR("address"), OBFSTR("string"), OBFSTR("Address within the function to delete"), true}},
        delete_function, false});

    registry.register_tool({OBFSTR("set_decompiler_comment"), OBFSTR("navigation"),
        OBFSTR("Set a comment in the Hex-Rays decompiler pseudocode view at the specified address."),
        {{OBFSTR("address"), OBFSTR("string"), OBFSTR("Address to attach the decompiler comment"), true},
         {OBFSTR("comment"), OBFSTR("string"), OBFSTR("Comment text (empty to delete)"), true}},
        set_decompiler_comment, false});

    registry.register_tool({OBFSTR("batch_rename"), OBFSTR("navigation"),
        OBFSTR("Rename multiple addresses at once. Efficient for bulk renaming operations."),
        {{OBFSTR("renames"), OBFSTR("array"), OBFSTR("Array of objects with 'address' and 'name' fields"), true, {},
          json::object({
              {"type", "object"},
              {"properties", json::object({
                  {"address", json::object({{"type", "string"}, {"description", "Address in hex (e.g., '0x140001000')"}})},
                  {"name", json::object({{"type", "string"}, {"description", "New name for the address"}})}
              })},
              {"required", json::array({"address", "name"})}
          })
        }},
        batch_rename, false});

    registry.register_tool({OBFSTR("get_address_info"), OBFSTR("navigation"),
        OBFSTR("Get comprehensive information about a specific address: name, type, flags, comments, segment, function."),
        {{OBFSTR("address"), OBFSTR("string"), OBFSTR("Address to query"), true}},
        get_address_info});
}

}

namespace analysis_tools
{

tool_result_t detect_obfuscation_patterns(const json& params)
{
    auto addr = helpers::parse_address(params.value("address", std::string()));
    if (!addr)
        return tool_result_t::error(OBFSTR("Invalid address"));

    ea_t ea = *addr;
    func_t* pfn = get_func(ea);
    if (!pfn)
        return tool_result_t::error(OBFSTR("No function at ") + helpers::format_address(ea));

    size_t scan_size = params.value("scan_size", 0);
    ea_t scan_start = pfn->start_ea;
    ea_t scan_end   = pfn->end_ea;
    if (scan_size > 0)
        scan_end = std::min(scan_start + static_cast<ea_t>(scan_size), pfn->end_ea);

    json result;
    result["function"] = helpers::get_name_or_address(pfn->start_ea);
    result["start"]    = helpers::format_address(scan_start);
    result["end"]      = helpers::format_address(scan_end);

    json patterns = json::array();
    int opaque_predicates = 0;
    int dead_code_blocks  = 0;
    int junk_sequences    = 0;
    int indirect_jumps    = 0;
    int self_modifying    = 0;
    int stack_manip       = 0;

    ea_t cur = scan_start;
    ea_t prev_ea = BADADDR;
    int nop_run = 0;

    while (cur < scan_end && cur != BADADDR)
    {
        insn_t insn;
        int len = decode_insn(&insn, cur);
        if (len <= 0)
        {
            cur = next_head(cur, scan_end);
            if (cur == BADADDR) break;
            continue;
        }

        if (insn.itype == NN_nop)
        {
            ++nop_run;
            if (nop_run == 4)
            {
                ++junk_sequences;
                json p;
                p["type"]    = OBFSTR("nop_sled");
                p["address"] = helpers::format_address(cur - 3);
                p["note"]    = OBFSTR("4+ consecutive NOPs suggest junk insertion");
                patterns.push_back(std::move(p));
            }
        }
        else
        {
            nop_run = 0;
        }

        if (prev_ea != BADADDR && (insn.itype == NN_jz || insn.itype == NN_jnz ||
            insn.itype == NN_jbe || insn.itype == NN_ja))
        {
            insn_t prev_insn;
            if (decode_insn(&prev_insn, prev_ea) > 0)
            {
                bool is_opaque = false;
                if (prev_insn.itype == NN_xor && prev_insn.ops[0].type == o_reg &&
                    prev_insn.ops[1].type == o_reg && prev_insn.ops[0].reg == prev_insn.ops[1].reg)
                    is_opaque = true;
                if (prev_insn.itype == NN_test && prev_insn.ops[0].type == o_reg &&
                    prev_insn.ops[1].type == o_reg && prev_insn.ops[0].reg == prev_insn.ops[1].reg)
                    is_opaque = true;

                if (is_opaque)
                {
                    ++opaque_predicates;
                    json p;
                    p["type"]    = OBFSTR("opaque_predicate");
                    p["address"] = helpers::format_address(cur);
                    qstring dis;
                    generate_disasm_line(&dis, cur, GENDSM_FORCE_CODE);
                    tag_remove(&dis);
                    p["instruction"] = dis.c_str();
                    patterns.push_back(std::move(p));
                }
            }
        }

        if (insn.itype == NN_jmpni || insn.itype == NN_jmpfi)
        {
            ++indirect_jumps;
            json p;
            p["type"]    = OBFSTR("indirect_jump");
            p["address"] = helpers::format_address(cur);
            qstring dis;
            generate_disasm_line(&dis, cur, GENDSM_FORCE_CODE);
            tag_remove(&dis);
            p["instruction"] = dis.c_str();
            patterns.push_back(std::move(p));
        }

        if (insn.itype == NN_push && prev_ea != BADADDR)
        {
            ea_t next = cur + len;
            insn_t next_insn;
            if (next < scan_end && decode_insn(&next_insn, next) > 0 && next_insn.itype == NN_retn)
            {
                ++stack_manip;
                json p;
                p["type"]    = OBFSTR("push_ret_redirect");
                p["address"] = helpers::format_address(cur);
                p["note"]    = OBFSTR("push+ret pattern used as indirect jump (anti-disassembly)");
                patterns.push_back(std::move(p));
            }
        }

        prev_ea = cur;
        cur += len;
    }

    func_item_iterator_t fii(pfn);
    std::set<ea_t> reachable;
    for (bool ok = fii.first(); ok; ok = fii.next_head())
    {
        ea_t item = fii.current();
        xrefblk_t xb;
        bool has_incoming = false;
        if (item == pfn->start_ea)
            has_incoming = true;
        else
        {
            for (bool xok = xb.first_to(item, XREF_ALL); xok; xok = xb.next_to())
            {
                if (xb.iscode && func_contains(pfn, xb.from))
                {
                    has_incoming = true;
                    break;
                }
            }
        }
        if (!has_incoming)
        {
            ++dead_code_blocks;
            if (dead_code_blocks <= 10)
            {
                json p;
                p["type"]    = OBFSTR("dead_code");
                p["address"] = helpers::format_address(item);
                p["note"]    = OBFSTR("No incoming code xrefs within function - possibly dead/junk code");
                patterns.push_back(std::move(p));
            }
        }
    }

    result["patterns"]           = std::move(patterns);
    result["opaque_predicates"]  = opaque_predicates;
    result["dead_code_blocks"]   = dead_code_blocks;
    result["junk_sequences"]     = junk_sequences;
    result["indirect_jumps"]     = indirect_jumps;
    result["stack_manipulation"] = stack_manip;

    int score = 0;
    if (opaque_predicates > 0) score += std::min(opaque_predicates * 10, 25);
    if (dead_code_blocks > 2)  score += 15;
    if (junk_sequences > 0)    score += std::min(junk_sequences * 8, 20);
    if (indirect_jumps > 0)    score += std::min(indirect_jumps * 15, 25);
    if (stack_manip > 0)       score += 15;
    result["obfuscation_score_pct"] = std::min(score, 100);

    return tool_result_t::ok(OBFSTR("Obfuscation pattern detection complete"), result);
}

tool_result_t analyze_control_flow(const json& params)
{
    auto addr = helpers::parse_address(params.value("address", std::string()));
    if (!addr)
        return tool_result_t::error(OBFSTR("Invalid address"));

    ea_t ea = *addr;
    func_t* pfn = get_func(ea);
    if (!pfn)
        return tool_result_t::error(OBFSTR("No function at ") + helpers::format_address(ea));

    json result;
    result["function"] = helpers::get_name_or_address(pfn->start_ea);
    result["start"]    = helpers::format_address(pfn->start_ea);
    result["end"]      = helpers::format_address(pfn->end_ea);
    result["size"]     = pfn->end_ea - pfn->start_ea;

    json blocks = json::array();
    int block_count = 0;
    int edge_count  = 0;
    int back_edges  = 0;
    std::set<ea_t> block_starts;
    block_starts.insert(pfn->start_ea);

    func_item_iterator_t fii(pfn);
    for (bool ok = fii.first(); ok; ok = fii.next_head())
    {
        ea_t item = fii.current();
        insn_t insn;
        if (decode_insn(&insn, item) <= 0)
            continue;

        if (is_basic_block_end(insn, false))
        {
            ea_t fall = item + insn.size;
            if (fall < pfn->end_ea && func_contains(pfn, fall))
                block_starts.insert(fall);

            xrefblk_t xb;
            for (bool xok = xb.first_from(item, XREF_ALL); xok; xok = xb.next_from())
            {
                if (xb.iscode && func_contains(pfn, xb.to))
                    block_starts.insert(xb.to);
            }
        }
    }

    for (ea_t bs : block_starts)
    {
        ++block_count;
        ea_t block_end = pfn->end_ea;
        auto it = block_starts.upper_bound(bs);
        if (it != block_starts.end())
            block_end = *it;

        int insn_count = 0;
        ea_t last_insn = bs;
        for (ea_t a = bs; a < block_end && a != BADADDR;)
        {
            insn_t insn;
            int len = decode_insn(&insn, a);
            if (len <= 0) break;
            ++insn_count;
            last_insn = a;
            a += len;
        }

        json blk;
        blk["start"]       = helpers::format_address(bs);
        blk["end"]         = helpers::format_address(block_end);
        blk["instructions"] = insn_count;

        json successors = json::array();
        xrefblk_t xb;
        for (bool xok = xb.first_from(last_insn, XREF_ALL); xok; xok = xb.next_from())
        {
            if (xb.iscode && func_contains(pfn, xb.to))
            {
                ++edge_count;
                successors.push_back(helpers::format_address(xb.to));
                if (xb.to <= bs)
                    ++back_edges;
            }
        }

        ea_t fall = last_insn;
        insn_t last;
        if (decode_insn(&last, last_insn) > 0)
        {
            fall = last_insn + last.size;
            if (fall < pfn->end_ea && func_contains(pfn, fall) && !is_basic_block_end(last, true))
            {
                ++edge_count;
                successors.push_back(helpers::format_address(fall));
            }
        }
        blk["successors"] = std::move(successors);

        if (blocks.size() < 200)
            blocks.push_back(std::move(blk));
    }

    result["basic_blocks"]  = std::move(blocks);
    result["block_count"]   = block_count;
    result["edge_count"]    = edge_count;
    result["back_edges"]    = back_edges;

    int cyclomatic = edge_count - block_count + 2;
    if (cyclomatic < 1) cyclomatic = 1;
    result["cyclomatic_complexity"] = cyclomatic;

    return tool_result_t::ok(OBFSTR("Control flow analysis complete"), result);
}

tool_result_t get_function_complexity(const json& params)
{
    auto addr = helpers::parse_address(params.value("address", std::string()));
    if (!addr)
        return tool_result_t::error(OBFSTR("Invalid address"));

    ea_t ea = *addr;
    func_t* pfn = get_func(ea);
    if (!pfn)
        return tool_result_t::error(OBFSTR("No function at ") + helpers::format_address(ea));

    json result;
    qstring fname;
    get_func_name(&fname, pfn->start_ea);
    result["function"] = fname.c_str();
    result["start"]    = helpers::format_address(pfn->start_ea);
    result["size"]     = pfn->end_ea - pfn->start_ea;

    int total_insns = 0, call_count = 0, branch_count = 0, ret_count = 0;
    int arith_count = 0, mem_access = 0, string_ops = 0;
    std::set<ea_t> block_starts;
    block_starts.insert(pfn->start_ea);
    int edge_count = 0;

    func_item_iterator_t fii(pfn);
    for (bool ok = fii.first(); ok; ok = fii.next_head())
    {
        ea_t item = fii.current();
        insn_t insn;
        if (decode_insn(&insn, item) <= 0) continue;
        ++total_insns;

        if (insn.itype == NN_call || insn.itype == NN_callni || insn.itype == NN_callfi)
            ++call_count;
        if (insn.itype == NN_retn || insn.itype == NN_retf)
            ++ret_count;
        if (insn.itype >= NN_ja && insn.itype <= NN_jz)
            ++branch_count;
        if (insn.itype == NN_add || insn.itype == NN_sub || insn.itype == NN_imul ||
            insn.itype == NN_idiv || insn.itype == NN_mul || insn.itype == NN_div ||
            insn.itype == NN_shl || insn.itype == NN_shr || insn.itype == NN_sar)
            ++arith_count;
        if (insn.itype == NN_movs || insn.itype == NN_stos || insn.itype == NN_cmps ||
            insn.itype == NN_scas || insn.itype == NN_lods)
            ++string_ops;

        for (int oi = 0; oi < UA_MAXOP; ++oi)
        {
            if (insn.ops[oi].type == o_mem || insn.ops[oi].type == o_phrase ||
                insn.ops[oi].type == o_displ)
            {
                ++mem_access;
                break;
            }
        }

        if (is_basic_block_end(insn, false))
        {
            ea_t fall = item + insn.size;
            if (func_contains(pfn, fall)) { block_starts.insert(fall); ++edge_count; }
            xrefblk_t xb;
            for (bool xok = xb.first_from(item, XREF_ALL); xok; xok = xb.next_from())
            {
                if (xb.iscode && func_contains(pfn, xb.to))
                {
                    block_starts.insert(xb.to);
                    ++edge_count;
                }
            }
        }
    }

    int block_count = static_cast<int>(block_starts.size());
    int cyclomatic = edge_count - block_count + 2;
    if (cyclomatic < 1) cyclomatic = 1;

    result["instruction_count"]    = total_insns;
    result["basic_block_count"]    = block_count;
    result["edge_count"]           = edge_count;
    result["cyclomatic_complexity"] = cyclomatic;
    result["call_count"]           = call_count;
    result["branch_count"]         = branch_count;
    result["return_count"]         = ret_count;
    result["arithmetic_ops"]       = arith_count;
    result["memory_accesses"]      = mem_access;
    result["string_operations"]    = string_ops;

    std::set<uint16> unique_ops;
    std::set<uint64_t> unique_operands;
    func_item_iterator_t fii2(pfn);
    for (bool ok = fii2.first(); ok; ok = fii2.next_head())
    {
        insn_t insn;
        if (decode_insn(&insn, fii2.current()) <= 0) continue;
        unique_ops.insert(insn.itype);
        for (int oi = 0; oi < UA_MAXOP && insn.ops[oi].type != o_void; ++oi)
        {
            uint64_t key = (static_cast<uint64_t>(insn.ops[oi].type) << 48) |
                           (static_cast<uint64_t>(insn.ops[oi].reg) << 32) |
                           static_cast<uint64_t>(insn.ops[oi].value & 0xFFFFFFFF);
            unique_operands.insert(key);
        }
    }
    result["unique_operators"] = unique_ops.size();
    result["unique_operands"]  = unique_operands.size();

    std::string complexity_rating;
    if (cyclomatic <= 5)       complexity_rating = "simple";
    else if (cyclomatic <= 10) complexity_rating = "moderate";
    else if (cyclomatic <= 20) complexity_rating = "complex";
    else if (cyclomatic <= 50) complexity_rating = "very_complex";
    else                       complexity_rating = "extremely_complex";
    result["complexity_rating"] = complexity_rating;

    return tool_result_t::ok(OBFSTR("Function complexity analysis"), result);
}

tool_result_t analyze_string_decryption(const json& params)
{
    auto addr = helpers::parse_address(params.value("address", std::string()));
    if (!addr)
        return tool_result_t::error(OBFSTR("Invalid address"));

    ea_t ea = *addr;
    func_t* pfn = get_func(ea);
    if (!pfn)
        return tool_result_t::error(OBFSTR("No function at ") + helpers::format_address(ea));

    json result;
    result["function"] = helpers::get_name_or_address(pfn->start_ea);

    json candidates = json::array();
    int xor_loops = 0, byte_manip_chains = 0, stack_strings = 0;

    func_item_iterator_t fii(pfn);
    ea_t xor_chain_start = BADADDR;
    int xor_chain_len = 0;
    int mov_byte_chain = 0;
    ea_t mov_byte_start = BADADDR;

    for (bool ok = fii.first(); ok; ok = fii.next_head())
    {
        ea_t item = fii.current();
        insn_t insn;
        if (decode_insn(&insn, item) <= 0) continue;

        if (insn.itype == NN_xor)
        {
            bool self_xor = (insn.ops[0].type == o_reg && insn.ops[1].type == o_reg &&
                             insn.ops[0].reg == insn.ops[1].reg);
            if (!self_xor)
            {
                if (xor_chain_start == BADADDR) xor_chain_start = item;
                ++xor_chain_len;
            }
            else
            {
                if (xor_chain_len >= 2)
                {
                    ++xor_loops;
                    json c;
                    c["type"]    = OBFSTR("xor_decryption");
                    c["start"]   = helpers::format_address(xor_chain_start);
                    c["length"]  = xor_chain_len;
                    c["note"]    = OBFSTR("Consecutive XOR operations suggest string/data decryption");
                    candidates.push_back(std::move(c));
                }
                xor_chain_start = BADADDR;
                xor_chain_len = 0;
            }
        }
        else
        {
            if (xor_chain_len >= 2)
            {
                ++xor_loops;
                json c;
                c["type"]    = OBFSTR("xor_decryption");
                c["start"]   = helpers::format_address(xor_chain_start);
                c["length"]  = xor_chain_len;
                candidates.push_back(std::move(c));
            }
            xor_chain_start = BADADDR;
            xor_chain_len = 0;
        }

        if (insn.itype == NN_mov && insn.ops[0].type == o_displ &&
            insn.ops[1].type == o_imm && insn.ops[1].value >= 0x20 && insn.ops[1].value <= 0x7E)
        {
            if (mov_byte_start == BADADDR) mov_byte_start = item;
            ++mov_byte_chain;
        }
        else
        {
            if (mov_byte_chain >= 4)
            {
                ++stack_strings;
                json c;
                c["type"]    = OBFSTR("stack_string");
                c["start"]   = helpers::format_address(mov_byte_start);
                c["length"]  = mov_byte_chain;
                c["note"]    = OBFSTR("Sequential byte MOVs to stack - likely stack-constructed string");

                std::string reconstructed;
                ea_t scan = mov_byte_start;
                for (int i = 0; i < mov_byte_chain && scan < pfn->end_ea; ++i)
                {
                    insn_t si;
                    if (decode_insn(&si, scan) > 0 && si.itype == NN_mov &&
                        si.ops[1].type == o_imm && si.ops[1].value >= 0x20 && si.ops[1].value <= 0x7E)
                    {
                        reconstructed += static_cast<char>(si.ops[1].value);
                    }
                    scan = next_head(scan, pfn->end_ea);
                }
                if (!reconstructed.empty())
                    c["reconstructed"] = reconstructed;

                candidates.push_back(std::move(c));
            }
            mov_byte_chain = 0;
            mov_byte_start = BADADDR;
        }

        if (insn.itype == NN_call || insn.itype == NN_callni)
        {
            ea_t target = BADADDR;
            if (insn.ops[0].type == o_near || insn.ops[0].type == o_far)
                target = insn.ops[0].addr;
            if (target != BADADDR)
            {
                qstring tname;
                if (get_func_name(&tname, target) > 0)
                {
                    std::string name_lower(tname.c_str());
                    std::transform(name_lower.begin(), name_lower.end(), name_lower.begin(), ::tolower);
                    if (name_lower.find("decrypt") != std::string::npos ||
                        name_lower.find("decode") != std::string::npos ||
                        name_lower.find("deobfus") != std::string::npos ||
                        name_lower.find("unpack") != std::string::npos)
                    {
                        json c;
                        c["type"]      = OBFSTR("decrypt_call");
                        c["address"]   = helpers::format_address(item);
                        c["target"]    = tname.c_str();
                        candidates.push_back(std::move(c));
                    }
                }
            }
        }
    }

    result["candidates"]       = std::move(candidates);
    result["xor_patterns"]     = xor_loops;
    result["stack_strings"]    = stack_strings;

    return tool_result_t::ok(OBFSTR("String decryption analysis"), result);
}

tool_result_t analyze_indirect_calls(const json& params)
{
    auto addr = helpers::parse_address(params.value("address", std::string()));
    if (!addr)
        return tool_result_t::error(OBFSTR("Invalid address"));

    ea_t ea = *addr;
    func_t* pfn = get_func(ea);
    if (!pfn)
        return tool_result_t::error(OBFSTR("No function at ") + helpers::format_address(ea));

    json result;
    result["function"] = helpers::get_name_or_address(pfn->start_ea);

    json calls = json::array();
    int vtable_calls = 0, func_ptr_calls = 0, register_calls = 0;

    func_item_iterator_t fii(pfn);
    for (bool ok = fii.first(); ok; ok = fii.next_head())
    {
        ea_t item = fii.current();
        insn_t insn;
        if (decode_insn(&insn, item) <= 0) continue;

        bool is_indirect_call = (insn.itype == NN_callni || insn.itype == NN_callfi);
        bool is_indirect_jmp  = (insn.itype == NN_jmpni || insn.itype == NN_jmpfi);

        if (!is_indirect_call && !is_indirect_jmp) continue;

        json entry;
        entry["address"] = helpers::format_address(item);
        entry["type"]    = is_indirect_call ? "indirect_call" : "indirect_jump";

        qstring dis;
        generate_disasm_line(&dis, item, GENDSM_FORCE_CODE);
        tag_remove(&dis);
        entry["instruction"] = dis.c_str();

        if (insn.ops[0].type == o_displ)
        {
            ++vtable_calls;
            entry["classification"] = OBFSTR("vtable_call");
            entry["base_register"]  = static_cast<int>(insn.ops[0].reg);
            entry["offset"]         = static_cast<int64_t>(insn.ops[0].addr);
        }
        else if (insn.ops[0].type == o_mem)
        {
            ++func_ptr_calls;
            entry["classification"] = OBFSTR("function_pointer");
            entry["target_address"] = helpers::format_address(static_cast<ea_t>(insn.ops[0].addr));
            qstring tname;
            if (get_name(&tname, static_cast<ea_t>(insn.ops[0].addr)) > 0)
                entry["target_name"] = tname.c_str();
        }
        else if (insn.ops[0].type == o_reg)
        {
            ++register_calls;
            entry["classification"] = OBFSTR("register_call");
            entry["register"]       = static_cast<int>(insn.ops[0].reg);
        }
        else
        {
            entry["classification"] = OBFSTR("other");
        }

        json targets = json::array();
        xrefblk_t xb;
        for (bool xok = xb.first_from(item, XREF_FAR); xok; xok = xb.next_from())
        {
            if (xb.iscode)
            {
                json t;
                t["address"] = helpers::format_address(xb.to);
                qstring tname;
                if (get_func_name(&tname, xb.to) > 0)
                    t["name"] = tname.c_str();
                targets.push_back(std::move(t));
            }
        }
        if (!targets.empty())
            entry["resolved_targets"] = std::move(targets);

        calls.push_back(std::move(entry));
    }

    result["indirect_calls"]   = std::move(calls);
    result["vtable_calls"]     = vtable_calls;
    result["func_ptr_calls"]   = func_ptr_calls;
    result["register_calls"]   = register_calls;
    result["total"]            = vtable_calls + func_ptr_calls + register_calls;

    return tool_result_t::ok(OBFSTR("Indirect call analysis"), result);
}

tool_result_t find_crypto_constants(const json& params)
{
    auto addr = helpers::parse_address(params.value("address", std::string()));
    size_t scan_size = params.value("scan_size", 65536);
    if (scan_size > 1048576) scan_size = 1048576;

    ea_t start_ea;
    ea_t end_ea;

    if (addr)
    {
        start_ea = *addr;
        func_t* pfn = get_func(start_ea);
        if (pfn)
            end_ea = pfn->end_ea;
        else
            end_ea = start_ea + static_cast<ea_t>(scan_size);
    }
    else
    {
        start_ea = inf_get_min_ea();
        end_ea   = std::min(start_ea + static_cast<ea_t>(scan_size), inf_get_max_ea());
    }

    struct crypto_sig_t {
        const char* name;
        const char* algorithm;
        uint32_t    value;
    };
    static const crypto_sig_t signatures[] = {
        {"SHA-256 H0",     "SHA-256",    0x6A09E667},
        {"SHA-256 H1",     "SHA-256",    0xBB67AE85},
        {"SHA-256 H2",     "SHA-256",    0x3C6EF372},
        {"SHA-256 H3",     "SHA-256",    0xA54FF53A},
        {"SHA-256 K[0]",   "SHA-256",    0x428A2F98},
        {"SHA-256 K[1]",   "SHA-256",    0x71374491},
        {"MD5 T[1]",       "MD5",        0xD76AA478},
        {"MD5 T[2]",       "MD5",        0xE8C7B756},
        {"MD5 T[3]",       "MD5",        0x242070DB},
        {"MD5 init A",     "MD5",        0x67452301},
        {"MD5 init B",     "MD5",        0xEFCDAB89},
        {"MD5 init C",     "MD5",        0x98BADCFE},
        {"MD5 init D",     "MD5",        0x10325476},
        {"AES Te0[0]",     "AES",        0xC66363A5},
        {"AES Te0[1]",     "AES",        0xF87C7C84},
        {"AES Td0[0]",     "AES",        0x51F4A750},
        {"AES sbox[0..3]", "AES",        0x637C777B},
        {"CRC32 poly",     "CRC32",      0xEDB88320},
        {"CRC32 poly alt", "CRC32",      0x04C11DB7},
        {"Blowfish P[0]",  "Blowfish",   0x243F6A88},
        {"Blowfish P[1]",  "Blowfish",   0x85A308D3},
        {"SHA-1 K0",       "SHA-1",      0x5A827999},
        {"SHA-1 K1",       "SHA-1",      0x6ED9EBA1},
        {"SHA-1 K2",       "SHA-1",      0x8F1BBCDC},
        {"SHA-1 K3",       "SHA-1",      0xCA62C1D6},
        {"TEA delta",      "TEA/XTEA",   0x9E3779B9},
        {"RC5/RC6 P32",    "RC5/RC6",    0xB7E15163},
        {"RC5/RC6 Q32",    "RC5/RC6",    0x9E3779B9},
        {"ChaCha20",       "ChaCha20",   0x61707865},
        {"Salsa20",        "Salsa20",    0x61707865},
    };

    json found = json::array();
    std::set<std::string> found_algos;

    for (ea_t cur = start_ea; cur < end_ea && cur != BADADDR;)
    {
        insn_t insn;
        int len = decode_insn(&insn, cur);
        if (len <= 0)
        {
            cur = next_head(cur, end_ea);
            if (cur == BADADDR) break;
            continue;
        }

        for (int oi = 0; oi < UA_MAXOP && insn.ops[oi].type != o_void; ++oi)
        {
            if (insn.ops[oi].type != o_imm) continue;
            uint32_t val = static_cast<uint32_t>(insn.ops[oi].value);
            for (const auto& sig : signatures)
            {
                if (val == sig.value)
                {
                    json f;
                    f["address"]   = helpers::format_address(cur);
                    f["constant"]  = sig.name;
                    f["algorithm"] = sig.algorithm;
                    f["value"]     = helpers::format_address(static_cast<ea_t>(val));
                    qstring dis;
                    generate_disasm_line(&dis, cur, GENDSM_FORCE_CODE);
                    tag_remove(&dis);
                    f["instruction"] = dis.c_str();
                    found.push_back(std::move(f));
                    found_algos.insert(sig.algorithm);
                }
            }
        }
        cur += len;
    }

    for (ea_t cur = start_ea; cur + 4 <= end_ea; cur += 4)
    {
        if (!is_loaded(cur)) continue;
        uint32_t val = static_cast<uint32_t>(get_dword(cur));
        for (const auto& sig : signatures)
        {
            if (val == sig.value)
            {
                bool dup = false;
                for (const auto& f : found)
                {
                    if (f.value("address", "") == helpers::format_address(cur))
                    { dup = true; break; }
                }
                if (!dup)
                {
                    json f;
                    f["address"]   = helpers::format_address(cur);
                    f["constant"]  = sig.name;
                    f["algorithm"] = sig.algorithm;
                    f["value"]     = helpers::format_address(static_cast<ea_t>(val));
                    f["source"]    = OBFSTR("data");
                    found.push_back(std::move(f));
                    found_algos.insert(sig.algorithm);
                }
            }
        }
    }

    json result;
    result["scan_start"]  = helpers::format_address(start_ea);
    result["scan_end"]    = helpers::format_address(end_ea);
    result["matches"]     = std::move(found);
    result["match_count"] = found.size();

    json algos = json::array();
    for (const auto& a : found_algos)
        algos.push_back(a);
    result["algorithms_detected"] = std::move(algos);

    return tool_result_t::ok(OBFSTR("Crypto constant scan"), result);
}

tool_result_t analyze_data_flow(const json& params)
{
    auto addr = helpers::parse_address(params.value("address", std::string()));
    if (!addr)
        return tool_result_t::error(OBFSTR("Invalid address"));

    ea_t ea = *addr;
    func_t* pfn = get_func(ea);
    if (!pfn)
        return tool_result_t::error(OBFSTR("No function at ") + helpers::format_address(ea));

    int max_depth = params.value("max_depth", 32);
    if (max_depth < 1) max_depth = 1;
    if (max_depth > 256) max_depth = 256;

    json result;
    result["function"] = helpers::get_name_or_address(pfn->start_ea);
    result["start_address"] = helpers::format_address(ea);

    json defs = json::array();
    json uses = json::array();

    ea_t scan = ea;
    int steps = 0;
    std::set<ea_t> visited;
    while (scan >= pfn->start_ea && steps < max_depth)
    {
        if (visited.count(scan)) break;
        visited.insert(scan);
        insn_t insn;
        if (decode_insn(&insn, scan) <= 0) break;
        if (scan != ea)
        {
            bool is_def = (insn.itype == NN_mov || insn.itype == NN_lea ||
                insn.itype == NN_xor || insn.itype == NN_add || insn.itype == NN_sub ||
                insn.itype == NN_and || insn.itype == NN_or || insn.itype == NN_shl ||
                insn.itype == NN_shr || insn.itype == NN_imul || insn.itype == NN_movzx ||
                insn.itype == NN_movsx);
            if (is_def)
            {
                json d;
                d["address"] = helpers::format_address(scan);
                qstring dis;
                generate_disasm_line(&dis, scan, GENDSM_FORCE_CODE);
                tag_remove(&dis);
                d["instruction"] = dis.c_str();
                d["direction"] = OBFSTR("backward");
                d["distance"] = steps;
                defs.push_back(std::move(d));
            }
        }
        scan = prev_head(scan, pfn->start_ea);
        ++steps;
    }

    scan = ea; steps = 0; visited.clear();
    while (scan < pfn->end_ea && steps < max_depth)
    {
        if (visited.count(scan)) break;
        visited.insert(scan);
        insn_t insn;
        if (decode_insn(&insn, scan) <= 0) break;
        if (scan != ea)
        {
            json u;
            u["address"] = helpers::format_address(scan);
            qstring dis;
            generate_disasm_line(&dis, scan, GENDSM_FORCE_CODE);
            tag_remove(&dis);
            u["instruction"] = dis.c_str();
            u["direction"] = OBFSTR("forward");
            u["distance"] = steps;
            if (insn.itype == NN_call || insn.itype == NN_callni)
                u["usage_type"] = OBFSTR("call_argument");
            else if (insn.itype == NN_cmp || insn.itype == NN_test)
                u["usage_type"] = OBFSTR("comparison");
            else if (insn.itype == NN_mov && insn.ops[0].type == o_mem)
                u["usage_type"] = OBFSTR("store");
            else if (insn.itype == NN_push)
                u["usage_type"] = OBFSTR("push");
            else
                u["usage_type"] = OBFSTR("computation");
            uses.push_back(std::move(u));
        }
        scan = next_head(scan, pfn->end_ea);
        ++steps;
    }

    result["definitions"] = std::move(defs);
    result["uses"] = std::move(uses);
    result["pseudocode"] = helpers::get_pseudocode(pfn->start_ea);

    return tool_result_t::ok(OBFSTR("Data flow analysis"), result);
}

tool_result_t detect_anti_analysis(const json& params)
{
    auto addr = helpers::parse_address(params.value("address", std::string()));
    if (!addr)
        return tool_result_t::error(OBFSTR("Invalid address"));

    ea_t ea = *addr;
    func_t* pfn = get_func(ea);
    ea_t scan_start = pfn ? pfn->start_ea : ea;
    ea_t scan_end = pfn ? pfn->end_ea : ea + 4096;

    json result;
    if (pfn) result["function"] = helpers::get_name_or_address(pfn->start_ea);
    result["scan_start"] = helpers::format_address(scan_start);
    result["scan_end"] = helpers::format_address(scan_end);

    json detections = json::array();
    int anti_debug = 0, anti_vm = 0, anti_disasm = 0, timing_checks = 0;

    static const char* dbg_apis[] = {
        "IsDebuggerPresent", "CheckRemoteDebuggerPresent",
        "NtQueryInformationProcess", "NtSetInformationThread",
        "OutputDebugString", "GetTickCount", "QueryPerformanceCounter",
        "NtQuerySystemInformation", "DbgBreakPoint", "DbgUiRemoteBreakin",
        nullptr
    };
    static const char* vm_apis[] = {
        "GetSystemFirmwareTable", "EnumSystemFirmwareTable", nullptr
    };
    static const char* vm_strings[] = {
        "VMware", "VBox", "VBOX", "Virtual", "QEMU", "Xen",
        "vmtoolsd", "vmwaretray", "vboxservice", nullptr
    };

    auto check_insn = [&](ea_t item) {
        insn_t insn;
        if (decode_insn(&insn, item) <= 0) return;

        if (insn.itype == NN_call || insn.itype == NN_callni || insn.itype == NN_callfi)
        {
            ea_t target = BADADDR;
            if (insn.ops[0].type == o_near || insn.ops[0].type == o_far)
                target = insn.ops[0].addr;
            else if (insn.ops[0].type == o_mem)
                target = static_cast<ea_t>(insn.ops[0].addr);
            if (target != BADADDR)
            {
                qstring tname;
                if (get_name(&tname, target) > 0)
                {
                    for (int i = 0; dbg_apis[i]; ++i)
                    {
                        if (tname.find(dbg_apis[i]) != qstring::npos)
                        {
                            ++anti_debug;
                            json d; d["type"] = OBFSTR("anti_debug_api");
                            d["address"] = helpers::format_address(item);
                            d["api"] = tname.c_str();
                            detections.push_back(std::move(d)); break;
                        }
                    }
                    for (int i = 0; vm_apis[i]; ++i)
                    {
                        if (tname.find(vm_apis[i]) != qstring::npos)
                        {
                            ++anti_vm;
                            json d; d["type"] = OBFSTR("anti_vm_api");
                            d["address"] = helpers::format_address(item);
                            d["api"] = tname.c_str();
                            detections.push_back(std::move(d)); break;
                        }
                    }
                }
            }
        }
        if (insn.itype == NN_cpuid)
        {
            ++anti_vm;
            json d; d["type"] = OBFSTR("cpuid_check");
            d["address"] = helpers::format_address(item);
            d["note"] = OBFSTR("CPUID for VM/hypervisor detection");
            detections.push_back(std::move(d));
        }
        if (insn.itype == NN_rdtsc)
        {
            ++timing_checks;
            json d; d["type"] = OBFSTR("timing_check");
            d["address"] = helpers::format_address(item);
            d["note"] = OBFSTR("RDTSC timing-based anti-debug");
            detections.push_back(std::move(d));
        }
        if (insn.itype == NN_int && insn.ops[0].type == o_imm && insn.ops[0].value == 0x2D)
        {
            ++anti_debug;
            json d; d["type"] = OBFSTR("int2d_anti_debug");
            d["address"] = helpers::format_address(item);
            detections.push_back(std::move(d));
        }
        if (insn.itype == NN_int3)
        {
            ++anti_debug;
            json d; d["type"] = OBFSTR("int3_trap");
            d["address"] = helpers::format_address(item);
            detections.push_back(std::move(d));
        }
        if (insn.itype == NN_in)
        {
            ++anti_vm;
            json d; d["type"] = OBFSTR("port_io_check");
            d["address"] = helpers::format_address(item);
            d["note"] = OBFSTR("IN instruction for VMware backdoor");
            detections.push_back(std::move(d));
        }
    };

    if (pfn)
    {
        func_item_iterator_t fii(pfn);
        for (bool ok = fii.first(); ok; ok = fii.next_head())
            check_insn(fii.current());
    }
    else
    {
        for (ea_t cur = scan_start; cur < scan_end && cur != BADADDR;)
        {
            check_insn(cur);
            insn_t tmp;
            int len = decode_insn(&tmp, cur);
            cur = (len > 0) ? cur + len : next_head(cur, scan_end);
            if (cur == BADADDR) break;
        }
    }

    if (pfn)
    {
        func_item_iterator_t fii2(pfn);
        for (bool ok = fii2.first(); ok; ok = fii2.next_head())
        {
            xrefblk_t xb;
            for (bool xok = xb.first_from(fii2.current(), XREF_DATA); xok; xok = xb.next_from())
            {
                flags64_t f = get_flags(xb.to);
                if (!is_strlit(f)) continue;
                qstring s;
                if (get_strlit_contents(&s, xb.to, -1, get_str_type(xb.to)) <= 0) continue;
                for (int i = 0; vm_strings[i]; ++i)
                {
                    if (s.find(vm_strings[i]) != qstring::npos)
                    {
                        ++anti_vm;
                        json d; d["type"] = OBFSTR("anti_vm_string");
                        d["address"] = helpers::format_address(fii2.current());
                        d["string"] = s.c_str();
                        d["pattern"] = vm_strings[i];
                        detections.push_back(std::move(d)); break;
                    }
                }
            }
        }
    }

    result["detections"] = std::move(detections);
    result["anti_debug"] = anti_debug;
    result["anti_vm"] = anti_vm;
    result["anti_disasm"] = anti_disasm;
    result["timing_checks"] = timing_checks;

    int score = 0;
    if (anti_debug > 0) score += std::min(anti_debug * 15, 40);
    if (anti_vm > 0) score += std::min(anti_vm * 15, 30);
    if (timing_checks > 0) score += std::min(timing_checks * 15, 20);
    if (anti_disasm > 0) score += 10;
    result["anti_analysis_score_pct"] = std::min(score, 100);

    return tool_result_t::ok(OBFSTR("Anti-analysis detection"), result);
}


tool_result_t analyze_pe_headers(const json& params)
{
    ea_t base = get_imagebase();
    if (params.contains("address"))
    {
        auto a = helpers::parse_address(params.value("address", std::string()));
        if (a) base = *a;
    }

    std::uint16_t e_magic = is_loaded(base) ? get_word(base) : 0;
    if (e_magic != 0x5A4D)
        return tool_result_t::error(OBFSTR("Not a valid PE: missing MZ signature at ") + helpers::format_address(base));

    std::uint32_t pe_off = get_dword(base + 0x3C);
    ea_t pe_hdr = base + pe_off;
    if (!is_loaded(pe_hdr) || get_dword(pe_hdr) != 0x00004550)
        return tool_result_t::error(OBFSTR("Invalid PE signature at ") + helpers::format_address(pe_hdr));

    json result;
    result["image_base"] = helpers::format_address(base);


    ea_t coff = pe_hdr + 4;
    std::uint16_t machine       = get_word(coff);
    std::uint16_t num_sections  = get_word(coff + 2);
    std::uint32_t timestamp     = get_dword(coff + 4);
    std::uint16_t opt_size      = get_word(coff + 16);
    std::uint16_t characteristics = get_word(coff + 18);

    json coff_j;
    switch (machine)
    {
    case 0x8664: coff_j["machine"] = "AMD64"; break;
    case 0x14C:  coff_j["machine"] = "i386"; break;
    case 0xAA64: coff_j["machine"] = "ARM64"; break;
    default:     coff_j["machine"] = helpers::format_address(machine); break;
    }
    coff_j["num_sections"] = num_sections;
    coff_j["timestamp"]    = timestamp;

    std::vector<std::string> char_flags;
    if (characteristics & 0x0002) char_flags.push_back("EXECUTABLE_IMAGE");
    if (characteristics & 0x0020) char_flags.push_back("LARGE_ADDRESS_AWARE");
    if (characteristics & 0x2000) char_flags.push_back("DLL");
    coff_j["characteristics_flags"] = char_flags;
    result["coff_header"] = std::move(coff_j);


    ea_t opt = coff + 20;
    std::uint16_t magic = get_word(opt);
    bool is64 = (magic == 0x20B);
    result["pe_format"] = is64 ? "PE32+ (64-bit)" : "PE32 (32-bit)";

    json opt_j;
    opt_j["linker_version"] = std::to_string(get_byte(opt + 2)) + "." + std::to_string(get_byte(opt + 3));
    opt_j["entry_point"]    = helpers::format_address(base + get_dword(opt + 16));
    opt_j["section_alignment"] = get_dword(opt + 32);
    opt_j["file_alignment"]    = get_dword(opt + 36);

    std::uint64_t img_base_pe = is64
        ? static_cast<std::uint64_t>(get_qword(opt + 24))
        : static_cast<std::uint64_t>(get_dword(opt + 28));
    opt_j["image_base_pe"]    = helpers::format_address(static_cast<ea_t>(img_base_pe));
    opt_j["size_of_image"]    = get_dword(opt + 56);
    opt_j["size_of_headers"]  = get_dword(opt + 60);
    opt_j["checksum"]         = get_dword(opt + 64);
    opt_j["subsystem"]        = get_word(opt + 68);

    std::uint16_t dll_chars = get_word(opt + 70);
    std::vector<std::string> dll_flags;
    if (dll_chars & 0x0040) dll_flags.push_back("DYNAMIC_BASE (ASLR)");
    if (dll_chars & 0x0080) dll_flags.push_back("FORCE_INTEGRITY");
    if (dll_chars & 0x0100) dll_flags.push_back("NX_COMPAT (DEP)");
    if (dll_chars & 0x0400) dll_flags.push_back("NO_SEH");
    if (dll_chars & 0x4000) dll_flags.push_back("GUARD_CF");
    opt_j["dll_characteristics_flags"] = dll_flags;
    result["optional_header"] = std::move(opt_j);


    std::uint32_t num_dd;
    ea_t dd_base;
    if (is64) { num_dd = get_dword(opt + 108); dd_base = opt + 112; }
    else      { num_dd = get_dword(opt + 92);  dd_base = opt + 96;  }

    static const char* dd_names[] = {
        "Export","Import","Resource","Exception","Security",
        "Relocation","Debug","Architecture","GlobalPtr","TLS",
        "LoadConfig","BoundImport","IAT","DelayImport","CLR","Reserved"
    };

    json dirs = json::array();
    for (std::uint32_t i = 0; i < std::min(num_dd, 16u); ++i)
    {
        ea_t dd_ea = dd_base + i * 8;
        if (!is_loaded(dd_ea)) break;
        std::uint32_t rva  = get_dword(dd_ea);
        std::uint32_t sz   = get_dword(dd_ea + 4);
        if (rva == 0 && sz == 0) continue;

        json dd;
        dd["index"] = i;
        dd["name"]  = dd_names[i];
        dd["rva"]   = helpers::format_address(static_cast<ea_t>(rva));
        dd["va"]    = helpers::format_address(base + rva);
        dd["size"]  = sz;


        if (i == 0 && rva)
        {
            ea_t exp = base + rva;
            if (is_loaded(exp + 20))
            {
                dd["num_functions"] = get_dword(exp + 20);
                dd["num_names"]     = get_dword(exp + 24);
            }
        }
        else if (i == 3 && rva)
        {
            dd["runtime_function_count"] = sz / 12;
        }
        else if (i == 5 && rva)
        {
            ea_t cur = base + rva;
            ea_t rel_end = cur + sz;
            int blocks = 0;
            while (cur < rel_end)
            {
                if (!is_loaded(cur + 4)) break;
                std::uint32_t bsz = get_dword(cur + 4);
                if (bsz == 0) break;
                ++blocks;
                cur += bsz;
            }
            dd["relocation_blocks"] = blocks;
        }
        else if (i == 9 && rva)
        {
            ea_t tls = base + rva;
            json tls_j;
            ea_t cb_va;
            if (!is_loaded(tls))
            {
                tls_j["error"] = "TLS directory not loaded";
                cb_va = 0;
            }
            else if (is64)
            {
                tls_j["raw_data_start"]    = helpers::format_address(static_cast<ea_t>(get_qword(tls)));
                tls_j["raw_data_end"]      = helpers::format_address(static_cast<ea_t>(get_qword(tls + 8)));
                cb_va = static_cast<ea_t>(get_qword(tls + 24));
            }
            else
            {
                tls_j["raw_data_start"]    = helpers::format_address(get_dword(tls));
                tls_j["raw_data_end"]      = helpers::format_address(get_dword(tls + 4));
                cb_va = get_dword(tls + 12);
            }
            tls_j["callbacks_address"] = helpers::format_address(cb_va);

            json cbs = json::array();
            if (cb_va != 0 && is_loaded(cb_va))
            {
                for (int ci = 0; ci < 64; ++ci)
                {
                    std::uint64_t cb = is64 ? get_qword(cb_va + ci * 8) : get_dword(cb_va + ci * 4);
                    if (cb == 0) break;
                    json c;
                    c["address"] = helpers::format_address(static_cast<ea_t>(cb));
                    qstring nm;
                    if (get_name(&nm, static_cast<ea_t>(cb)) && !nm.empty())
                        c["name"] = nm.c_str();
                    cbs.push_back(std::move(c));
                }
            }
            tls_j["callbacks"]         = std::move(cbs);
            tls_j["callback_count"]    = tls_j["callbacks"].size();
            dd["tls_info"]             = std::move(tls_j);
        }
        else if (i == 10 && rva && is64)
        {
            ea_t lc = base + rva;
            json lc_j;
            if (is_loaded(lc + 88))
            {
                lc_j["security_cookie"]          = helpers::format_address(static_cast<ea_t>(get_qword(lc + 88)));
                lc_j["guard_cf_check_function"]  = helpers::format_address(static_cast<ea_t>(get_qword(lc + 112)));
                lc_j["guard_cf_function_table"]  = helpers::format_address(static_cast<ea_t>(get_qword(lc + 128)));
                lc_j["guard_cf_function_count"]  = static_cast<std::uint64_t>(get_qword(lc + 136));
            }
            dd["load_config"] = std::move(lc_j);
        }
        dirs.push_back(std::move(dd));
    }
    result["data_directories"] = std::move(dirs);


    ea_t sec_tbl = opt + opt_size;
    json secs = json::array();
    for (int si = 0; si < num_sections; ++si)
    {
        ea_t sec = sec_tbl + si * 40;
        if (!is_loaded(sec)) break;
        char sname[9] = {};
        for (int j = 0; j < 8; ++j)
            sname[j] = static_cast<char>(get_byte(sec + j));

        std::uint32_t vsize   = get_dword(sec + 8);
        std::uint32_t vrva    = get_dword(sec + 12);
        std::uint32_t rsize   = get_dword(sec + 16);
        std::uint32_t rptr    = get_dword(sec + 20);
        std::uint32_t chars   = get_dword(sec + 36);

        ea_t sec_va = base + vrva;
        std::uint32_t check_sz = std::min(vsize, 65536u);
        std::uint32_t freq[256] = {};
        std::uint32_t cnt = 0;
        for (std::uint32_t b = 0; b < check_sz; ++b)
        {
            if (is_loaded(sec_va + b))
            {
                freq[get_byte(sec_va + b)]++;
                ++cnt;
            }
        }
        double ent = 0.0;
        if (cnt > 0)
        {
            for (int k = 0; k < 256; ++k)
            {
                if (freq[k] == 0) continue;
                double p = static_cast<double>(freq[k]) / cnt;
                ent -= p * std::log2(p);
            }
        }

        json s;
        s["name"]            = sname;
        s["virtual_address"] = helpers::format_address(sec_va);
        s["virtual_size"]    = vsize;
        s["raw_size"]        = rsize;
        s["raw_offset"]      = rptr;
        s["entropy"]         = std::round(ent * 100.0) / 100.0;

        std::vector<std::string> fl;
        if (chars & 0x00000020) fl.push_back("CODE");
        if (chars & 0x00000040) fl.push_back("INITIALIZED_DATA");
        if (chars & 0x00000080) fl.push_back("UNINITIALIZED_DATA");
        if (chars & 0x02000000) fl.push_back("DISCARDABLE");
        if (chars & 0x20000000) fl.push_back("EXECUTE");
        if (chars & 0x40000000) fl.push_back("READ");
        if (chars & 0x80000000) fl.push_back("WRITE");
        s["flags"] = fl;

        if (ent > 7.0) s["classification"] = "likely_packed_or_encrypted";
        else if (ent > 6.5) s["classification"] = "high_entropy_suspicious";
        else if ((chars & 0x20000000) && (chars & 0x80000000)) s["classification"] = "rwx_suspicious";
        else s["classification"] = "normal";

        secs.push_back(std::move(s));
    }
    result["sections"] = std::move(secs);

    return tool_result_t::ok(OBFSTR("PE header analysis for ") + helpers::format_address(base), result);
}


tool_result_t analyze_entropy(const json& params)
{
    auto addr = helpers::parse_address(params.value("address", std::string()));
    if (!addr)
        return tool_result_t::error(OBFSTR("Invalid address"));

    std::uint32_t size    = params.value("size", 4096);
    if (size > 1048576) size = 1048576;
    std::uint32_t window  = params.value("window_size", 256);
    if (window < 32) window = 32;
    if (window > size) window = size;


    std::uint32_t freq[256] = {};
    std::uint32_t total = 0;
    for (std::uint32_t i = 0; i < size; ++i)
    {
        if (is_loaded(*addr + i)) { freq[get_byte(*addr + i)]++; ++total; }
    }
    double overall = 0.0;
    if (total > 0)
    {
        for (int k = 0; k < 256; ++k)
        {
            if (freq[k] == 0) continue;
            double p = static_cast<double>(freq[k]) / total;
            overall -= p * std::log2(p);
        }
    }


    json windows = json::array();
    std::uint32_t step = std::max(window / 2, 1u);
    double max_ent = 0.0, min_ent = 8.0;
    for (std::uint32_t off = 0; off + window <= size; off += step)
    {
        std::uint32_t wf[256] = {};
        std::uint32_t wc = 0;
        for (std::uint32_t b = 0; b < window; ++b)
        {
            if (is_loaded(*addr + off + b)) { wf[get_byte(*addr + off + b)]++; ++wc; }
        }
        double ent = 0.0;
        if (wc > 0)
        {
            for (int k = 0; k < 256; ++k)
            {
                if (wf[k] == 0) continue;
                double p = static_cast<double>(wf[k]) / wc;
                ent -= p * std::log2(p);
            }
        }
        if (ent > max_ent) max_ent = ent;
        if (ent < min_ent) min_ent = ent;

        json w;
        w["offset"]  = off;
        w["address"] = helpers::format_address(*addr + off);
        w["entropy"] = std::round(ent * 100.0) / 100.0;
        if (ent > 7.0) w["classification"] = "encrypted_or_compressed";
        else if (ent > 6.0) w["classification"] = "suspicious";
        else if (ent < 1.0) w["classification"] = "nearly_empty";
        else w["classification"] = "normal";
        windows.push_back(std::move(w));
    }

    json result;
    result["address"]             = helpers::format_address(*addr);
    result["size"]                = size;
    result["overall_entropy"]     = std::round(overall * 100.0) / 100.0;
    result["max_window_entropy"]  = std::round(max_ent * 100.0) / 100.0;
    result["min_window_entropy"]  = std::round(min_ent * 100.0) / 100.0;
    result["window_size"]         = window;
    result["windows"]             = std::move(windows);

    std::string verdict;
    if (overall > 7.5)      verdict = "almost_certainly_encrypted_or_compressed";
    else if (overall > 7.0) verdict = "likely_packed";
    else if (overall > 6.0) verdict = "suspicious_high_entropy";
    else                    verdict = "normal";
    result["verdict"] = verdict;

    return tool_result_t::ok(OBFSTR("Entropy: ") + std::to_string(overall) + OBFSTR(" bits/byte Ã¢â‚¬â€ ") + verdict, result);
}


tool_result_t detect_hooks(const json& params)
{
    auto addr_opt = helpers::parse_address(params.value("address", std::string()));
    std::uint32_t max_fn = params.value("max_functions", 500);
    if (max_fn > 10000) max_fn = 10000;

    segment_t* target_seg = addr_opt ? getseg(*addr_opt) : nullptr;
    int checked = 0;
    json hooks = json::array();

    for (std::size_t i = 0; i < get_func_qty() && checked < static_cast<int>(max_fn); ++i)
    {
        func_t* fn = getn_func(i);
        if (!fn) continue;
        if (target_seg && getseg(fn->start_ea) != target_seg) continue;
        ++checked;

        ea_t ea = fn->start_ea;
        if (!is_loaded(ea)) continue;
        std::uint8_t pr[16];
        for (int b = 0; b < 16; ++b) pr[b] = is_loaded(ea + b) ? static_cast<std::uint8_t>(get_byte(ea + b)) : 0;

        std::string hook_type;
        ea_t hook_target = BADADDR;

        if (pr[0] == 0xE9)
        {
            std::int32_t rel;
            std::memcpy(&rel, &pr[1], 4);
            hook_target = ea + 5 + rel;
            hook_type = "jmp_rel32";
        }
        else if (pr[0] == 0xFF && pr[1] == 0x25)
        {
            std::int32_t disp;
            std::memcpy(&disp, &pr[2], 4);
            ea_t ptr = ea + 6 + disp;
            hook_target = is_loaded(ptr) ? static_cast<ea_t>(get_qword(ptr)) : BADADDR;
            hook_type = "jmp_indirect_rip";
        }
        else if (pr[0] == 0x48 && pr[1] == 0xB8 && pr[10] == 0xFF && pr[11] == 0xE0)
        {
            std::memcpy(&hook_target, &pr[2], 8);
            hook_type = "mov_rax_jmp_rax";
        }
        else if (pr[0] == 0x68 && pr[5] == 0xC3)
        {
            std::uint32_t t;
            std::memcpy(&t, &pr[1], 4);
            hook_target = static_cast<ea_t>(t);
            hook_type = "push_ret";
        }
        else if (pr[0] == 0xCC)
        {
            hook_type = "int3_breakpoint";
        }

        if (hook_type.empty()) continue;

        json h;
        h["address"] = helpers::format_address(ea);
        qstring nm;
        if (get_name(&nm, ea) && !nm.empty()) h["name"] = nm.c_str();
        h["hook_type"] = hook_type;
        if (hook_target != BADADDR)
        {
            h["target"] = helpers::format_address(hook_target);
            segment_t* ts = getseg(hook_target);
            if (ts) { qstring sn; if (get_segm_name(&sn, ts) && !sn.empty()) h["target_segment"] = sn.c_str(); }
            qstring tn;
            if (get_name(&tn, hook_target) && !tn.empty()) h["target_name"] = tn.c_str();
        }

        std::ostringstream hex;
        for (int b = 0; b < 16; ++b)
        {
            if (b > 0) hex << " ";
            hex << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(pr[b]);
        }
        h["prologue_bytes"] = hex.str();
        hooks.push_back(std::move(h));
    }

    json result;
    result["functions_checked"] = checked;
    result["hooks_found"]       = hooks.size();
    result["hooks"]             = std::move(hooks);
    return tool_result_t::ok(OBFSTR("Hook detection: ") + std::to_string(result["hooks_found"].get<std::size_t>()) +
                             OBFSTR(" hooks in ") + std::to_string(checked) + OBFSTR(" functions"), result);
}


tool_result_t detect_direct_syscalls(const json& params)
{
    auto addr_opt = helpers::parse_address(params.value("address", std::string()));
    std::uint32_t scan_size = params.value("size", 0);

    json syscalls = json::array();

    auto scan = [&](ea_t start, ea_t end)
    {
        for (ea_t ea = start; ea + 10 < end; ++ea)
        {
            if (!is_loaded(ea)) continue;


            if (get_byte(ea) == 0x4C && get_byte(ea + 1) == 0x8B && get_byte(ea + 2) == 0xD1 &&
                get_byte(ea + 3) == 0xB8 && get_byte(ea + 8) == 0x0F && get_byte(ea + 9) == 0x05)
            {
                std::uint32_t num = get_dword(ea + 4);
                json sc;
                sc["address"]        = helpers::format_address(ea);
                sc["syscall_number"] = num;
                sc["syscall_hex"]    = helpers::format_address(static_cast<ea_t>(num));
                sc["pattern"]        = "mov_r10_rcx__mov_eax__syscall";

                func_t* fn = get_func(ea);
                if (fn) { qstring n; if (get_name(&n, fn->start_ea) && !n.empty()) sc["function"] = n.c_str(); }
                syscalls.push_back(std::move(sc));
                ea += 9;
            }

            else if (get_byte(ea) == 0xB8 && get_byte(ea + 5) == 0x0F && get_byte(ea + 6) == 0x05)
            {
                std::uint32_t num = get_dword(ea + 1);
                if (num > 0x1000) continue;
                json sc;
                sc["address"]        = helpers::format_address(ea);
                sc["syscall_number"] = num;
                sc["pattern"]        = "mov_eax__syscall";

                func_t* fn = get_func(ea);
                if (fn) { qstring n; if (get_name(&n, fn->start_ea) && !n.empty()) sc["function"] = n.c_str(); }
                syscalls.push_back(std::move(sc));
                ea += 6;
            }

            else if (get_byte(ea) == 0xCD && get_byte(ea + 1) == 0x2E)
            {
                if (ea >= start + 5 && is_loaded(ea - 5) && get_byte(ea - 5) == 0xB8)
                {
                    json sc;
                    sc["address"]        = helpers::format_address(ea - 5);
                    sc["syscall_number"] = get_dword(ea - 4);
                    sc["pattern"]        = "mov_eax__int2e";
                    syscalls.push_back(std::move(sc));
                }
            }
        }
    };

    if (addr_opt && scan_size > 0)
        scan(*addr_opt, *addr_opt + scan_size);
    else if (addr_opt)
    {
        segment_t* seg = getseg(*addr_opt);
        if (seg) scan(seg->start_ea, seg->end_ea);
        else     scan(*addr_opt, *addr_opt + 0x10000);
    }
    else
    {
        for (int i = 0; i < get_segm_qty(); ++i)
        {
            segment_t* seg = getnseg(i);
            if (!seg || seg->type != SEG_CODE) continue;
            scan(seg->start_ea, seg->end_ea);
        }
    }

    json result;
    result["syscalls_found"] = syscalls.size();
    result["syscalls"]       = std::move(syscalls);
    if (!result["syscalls"].empty())
        result["note"] = OBFSTR("Direct syscalls bypass IAT hooks and usermode API monitoring. "
                                "Common in anti-cheats, packers, and malware.");
    return tool_result_t::ok(OBFSTR("Direct syscall scan: ") + std::to_string(result["syscalls_found"].get<std::size_t>()) + OBFSTR(" found"), result);
}


tool_result_t resolve_api_hashes(const json& params)
{
    std::string algorithm = params.value("algorithm", "ror13");


    std::vector<std::uint32_t> targets;
    if (params.contains("hashes") && params["hashes"].is_array())
    {
        for (const auto& h : params["hashes"])
        {
            if (h.is_number()) targets.push_back(h.get<std::uint32_t>());
            else if (h.is_string()) { auto a = helpers::parse_address(h.get<std::string>()); if (a) targets.push_back(static_cast<std::uint32_t>(*a)); }
        }
    }
    else if (params.contains("hash"))
    {
        if (params["hash"].is_number()) targets.push_back(params["hash"].get<std::uint32_t>());
        else { auto a = helpers::parse_address(params.value("hash", std::string())); if (a) targets.push_back(static_cast<std::uint32_t>(*a)); }
    }
    if (targets.empty())
        return tool_result_t::error(OBFSTR("No hash values provided. Use 'hash' or 'hashes' parameter."));


    auto h_ror13 = [](const std::string& s) -> std::uint32_t {
        std::uint32_t h = 0;
        for (char c : s) h = ((h >> 13) | (h << 19)) + static_cast<std::uint8_t>(c);
        return h;
    };
    auto h_djb2 = [](const std::string& s) -> std::uint32_t {
        std::uint32_t h = 5381;
        for (char c : s) h = ((h << 5) + h) + static_cast<std::uint8_t>(c);
        return h;
    };
    auto h_crc32 = [](const std::string& s) -> std::uint32_t {
        std::uint32_t crc = 0xFFFFFFFF;
        for (char c : s) { crc ^= static_cast<std::uint8_t>(c); for (int i = 0; i < 8; ++i) crc = (crc >> 1) ^ (0xEDB88320 & (~((crc & 1) - 1))); }
        return ~crc;
    };
    auto h_fnv1a = [](const std::string& s) -> std::uint32_t {
        std::uint32_t h = 0x811C9DC5;
        for (char c : s) { h ^= static_cast<std::uint8_t>(c); h *= 0x01000193; }
        return h;
    };
    auto h_sdbm = [](const std::string& s) -> std::uint32_t {
        std::uint32_t h = 0;
        for (char c : s) h = static_cast<std::uint8_t>(c) + (h << 6) + (h << 16) - h;
        return h;
    };

    std::string algo_lc = algorithm;
    std::transform(algo_lc.begin(), algo_lc.end(), algo_lc.begin(), ::tolower);
    std::function<std::uint32_t(const std::string&)> hash_fn;
    if (algo_lc == "ror13")       hash_fn = h_ror13;
    else if (algo_lc == "djb2")   hash_fn = h_djb2;
    else if (algo_lc == "crc32")  hash_fn = h_crc32;
    else if (algo_lc == "fnv1a" || algo_lc == "fnv") hash_fn = h_fnv1a;
    else if (algo_lc == "sdbm")   hash_fn = h_sdbm;
    else return tool_result_t::error(OBFSTR("Unknown algorithm: ") + algorithm + OBFSTR(". Supported: ror13, djb2, crc32, fnv1a, sdbm"));


    std::vector<std::pair<std::string, std::string>> api_names;
    for (size_t i = 0; i < static_cast<size_t>(get_import_module_qty()); ++i)
    {
        qstring mod_name;
        get_import_module_name(&mod_name, static_cast<int>(i));
        std::string dll = mod_name.c_str();
        struct ctx_t { std::vector<std::pair<std::string, std::string>>* apis; std::string dll; };
        ctx_t ctx{&api_names, dll};
        enum_import_names(static_cast<int>(i), [](ea_t, const char* nm, uval_t, void* ud) -> int {
            auto* c = static_cast<ctx_t*>(ud);
            if (nm && nm[0]) c->apis->push_back({c->dll, nm});
            return 1;
        }, &ctx);
    }

    static const char* common[] = {
        "VirtualAlloc","VirtualAllocEx","VirtualFree","VirtualProtect","VirtualQuery",
        "ReadProcessMemory","WriteProcessMemory","OpenProcess","CreateRemoteThread",
        "NtAllocateVirtualMemory","NtReadVirtualMemory","NtWriteVirtualMemory",
        "NtProtectVirtualMemory","NtOpenProcess","NtQueryInformationProcess",
        "NtQuerySystemInformation","NtSetInformationThread","NtCreateThreadEx",
        "NtDeviceIoControlFile","NtClose","NtCreateFile","NtOpenFile",
        "NtMapViewOfSection","NtUnmapViewOfSection","NtQueryVirtualMemory",
        "GetProcAddress","LoadLibraryA","LoadLibraryW","LoadLibraryExA","LoadLibraryExW",
        "GetModuleHandleA","GetModuleHandleW","CreateFileA","CreateFileW",
        "ReadFile","WriteFile","CreateProcessA","CreateProcessW",
        "ExitProcess","TerminateProcess","IsDebuggerPresent","CheckRemoteDebuggerPresent",
        "GetTickCount","QueryPerformanceCounter","Sleep",
        "CreateThread","ResumeThread","SuspendThread","GetThreadContext","SetThreadContext",
        "WSAStartup","socket","connect","send","recv","closesocket",
        "RegOpenKeyExA","RegOpenKeyExW","RegQueryValueExA","RegSetValueExA",
        "CryptEncrypt","CryptDecrypt","BCryptOpenAlgorithmProvider","BCryptEncrypt","BCryptDecrypt",
        nullptr
    };
    for (int i = 0; common[i]; ++i) api_names.push_back({"common", common[i]});

    std::set<std::uint32_t> target_set(targets.begin(), targets.end());
    json resolved = json::array();
    std::set<std::uint32_t> found_set;

    bool try_dll = params.value("include_dll_name", false);

    for (const auto& [dll, api] : api_names)
    {
        std::uint32_t h = hash_fn(api);
        if (target_set.count(h))
        {
            json r; r["hash"] = helpers::format_address(static_cast<ea_t>(h)); r["api"] = api; r["dll"] = dll;
            found_set.insert(h);
            resolved.push_back(std::move(r));
        }
        if (try_dll)
        {
            std::string full = dll + "!" + api;
            h = hash_fn(full);
            if (target_set.count(h))
            {
                json r; r["hash"] = helpers::format_address(static_cast<ea_t>(h)); r["api"] = full; r["dll"] = dll;
                found_set.insert(h);
                resolved.push_back(std::move(r));
            }
        }
    }

    json result;
    result["algorithm"]        = algorithm;
    result["total_queried"]    = targets.size();
    result["resolved_count"]   = found_set.size();
    result["unresolved_count"] = targets.size() - found_set.size();
    result["resolved"]         = std::move(resolved);

    json unres = json::array();
    for (auto h : targets) { if (!found_set.count(h)) unres.push_back(helpers::format_address(static_cast<ea_t>(h))); }
    result["unresolved"] = std::move(unres);

    return tool_result_t::ok(OBFSTR("API hash resolution: ") + std::to_string(found_set.size()) +
                             "/" + std::to_string(targets.size()) + OBFSTR(" resolved"), result);
}


tool_result_t reconstruct_vtable(const json& params)
{
    auto addr = helpers::parse_address(params.value("address", std::string()));
    if (!addr)
        return tool_result_t::error(OBFSTR("Invalid VTABLE address"));

    std::uint32_t max_entries = params.value("max_entries", 200);
    if (max_entries > 1000) max_entries = 1000;

    bool is_64 = inf_is_64bit();
    std::size_t ptr_sz = is_64 ? 8 : 4;

    json entries = json::array();
    ea_t vt = *addr;


    json rtti;
    if (is_64 && is_loaded(vt - 8))
    {
        ea_t col_ptr = static_cast<ea_t>(get_qword(vt - 8));
        if (is_loaded(col_ptr))
        {
            std::uint32_t sig = get_dword(col_ptr);
            if (sig == 0 || sig == 1)
            {
                rtti["col_address"] = helpers::format_address(col_ptr);
                rtti["signature"]   = sig;
                if (sig == 1)
                {
                    std::int32_t td_off   = get_dword(col_ptr + 12);
                    std::int32_t chd_off  = get_dword(col_ptr + 16);
                    std::int32_t self_off = get_dword(col_ptr + 20);
                    std::uint64_t img_base = static_cast<std::uint64_t>(col_ptr) - self_off;

                    ea_t td = static_cast<ea_t>(img_base + td_off);
                    if (is_loaded(td + 16))
                    {
                        char tname[256] = {};
                        for (int i = 0; i < 255; ++i) { char c = static_cast<char>(get_byte(td + 16 + i)); if (!c) break; tname[i] = c; }
                        rtti["type_descriptor_name"] = tname;
                        qstring dem;
                        if (demangle_name(&dem, tname, 0) > 0 && !dem.empty())
                            rtti["demangled_class"] = dem.c_str();
                    }
                    ea_t chd = static_cast<ea_t>(img_base + chd_off);
                    if (is_loaded(chd)) rtti["num_base_classes"] = get_dword(chd + 8);
                }
            }
        }
    }

    for (std::uint32_t i = 0; i < max_entries; ++i)
    {
        ea_t entry_ea = vt + i * ptr_sz;
        if (!is_loaded(entry_ea)) break;
        ea_t fn_addr = is_64 ? static_cast<ea_t>(get_qword(entry_ea)) : get_dword(entry_ea);
        if (fn_addr == 0 || !is_loaded(fn_addr)) break;
        segment_t* fs = getseg(fn_addr);
        if (!fs || fs->type != SEG_CODE) break;

        json e;
        e["index"]   = i;
        e["offset"]  = helpers::format_address(static_cast<ea_t>(i * ptr_sz));
        e["address"] = helpers::format_address(fn_addr);

        func_t* fn = get_func(fn_addr);
        qstring nm;
        if (get_name(&nm, fn_addr) && !nm.empty())
        {
            e["name"] = nm.c_str();
            qstring dem;
            if (demangle_name(&dem, nm.c_str(), 0) > 0 && !dem.empty())
                e["demangled"] = dem.c_str();
        }
        if (fn) e["function_size"] = static_cast<std::uint64_t>(fn->size());
        entries.push_back(std::move(e));
    }

    json result;
    result["vtable_address"] = helpers::format_address(*addr);
    result["entry_count"]    = entries.size();
    result["pointer_size"]   = ptr_sz;
    result["entries"]        = std::move(entries);
    if (!rtti.empty()) result["rtti"] = std::move(rtti);

    return tool_result_t::ok(OBFSTR("VTABLE: ") + std::to_string(result["entry_count"].get<std::size_t>()) +
                             OBFSTR(" entries at ") + helpers::format_address(*addr), result);
}


tool_result_t classify_memory_pages(const json& params)
{
    auto addr_opt = helpers::parse_address(params.value("address", std::string()));
    ea_t start_ea = addr_opt ? *addr_opt : inf_get_min_ea();
    size_t total_size = params.value("size", (size_t)0);
    size_t page_size = params.value("page_size", (size_t)4096);
    if (page_size < 256) page_size = 256;

    segment_t* seg = getseg(start_ea);
    if (!seg && total_size == 0)
        return tool_result_t::error(OBFSTR("No segment at address and no size specified"));

    ea_t end_ea = (total_size > 0) ? (start_ea + total_size)
                                    : (seg ? seg->end_ea : (start_ea + 0x10000));

    json pages = json::array();
    int code_pages = 0, data_pages = 0, encrypted_pages = 0, padding_pages = 0, mixed_pages = 0;

    show_wait_box(OBFSTR("Classifying memory pages...").c_str());
    for (ea_t ea = start_ea; ea < end_ea; ea += page_size)
    {
        if (user_cancelled()) break;
        size_t sz = static_cast<size_t>(std::min((ea_t)page_size, end_ea - ea));

        std::vector<uint8_t> buf(sz);
        size_t loaded = 0;
        for (size_t i = 0; i < sz; ++i)
        {
            if (is_loaded(ea + i)) { buf[i] = get_byte(ea + i); ++loaded; }
        }

        if (loaded < sz / 2)
        {
            json pg;
            pg["address"] = helpers::format_address(ea);
            pg["class"]   = "unmapped";
            pg["loaded_ratio"] = static_cast<double>(loaded) / sz;
            pages.push_back(std::move(pg));
            continue;
        }


        int freq[256] = {};
        for (size_t i = 0; i < sz; ++i) freq[buf[i]]++;
        double entropy = 0.0;
        for (int i = 0; i < 256; ++i)
        {
            if (freq[i] == 0) continue;
            double p_val = static_cast<double>(freq[i]) / sz;
            entropy -= p_val * std::log2(p_val);
        }

        int max_freq = *std::max_element(freq, freq + 256);
        double uniformity = static_cast<double>(max_freq) / sz;


        int valid_insns = 0, total_bytes_decoded = 0;
        for (ea_t ip = ea; ip < ea + sz; )
        {
            insn_t insn;
            int insn_sz = decode_insn(&insn, ip);
            if (insn_sz > 0) { ++valid_insns; total_bytes_decoded += insn_sz; ip += insn_sz; }
            else { ip += 1; }
        }
        double insn_ratio = (sz > 0) ? static_cast<double>(total_bytes_decoded) / sz : 0.0;
        double zero_ratio = (sz > 0) ? static_cast<double>(freq[0]) / sz : 0.0;
        int printable = 0;
        for (int i = 0x20; i <= 0x7E; ++i) printable += freq[i];
        double string_ratio = (sz > 0) ? static_cast<double>(printable) / sz : 0.0;

        std::string classification;
        if (zero_ratio > 0.85)                              { classification = "padding"; ++padding_pages; }
        else if (uniformity > 0.7)                          { classification = "single_byte_encrypted"; ++encrypted_pages; }
        else if (entropy > 7.2 && insn_ratio < 0.3)        { classification = "encrypted_or_compressed"; ++encrypted_pages; }
        else if (entropy > 6.5 && insn_ratio < 0.5)        { classification = "obfuscated_code"; ++mixed_pages; }
        else if (insn_ratio > 0.75 && entropy < 6.5)       { classification = "code"; ++code_pages; }
        else if (string_ratio > 0.6)                        { classification = "string_data"; ++data_pages; }
        else if (insn_ratio < 0.3 && entropy < 5.0)        { classification = "structured_data"; ++data_pages; }
        else                                                { classification = "mixed"; ++mixed_pages; }

        json pg;
        pg["address"]       = helpers::format_address(ea);
        pg["size"]          = sz;
        pg["class"]         = classification;
        pg["entropy"]       = std::round(entropy * 100) / 100;
        pg["insn_ratio"]    = std::round(insn_ratio * 100) / 100;
        pg["zero_ratio"]    = std::round(zero_ratio * 100) / 100;
        pg["string_ratio"]  = std::round(string_ratio * 100) / 100;
        pg["valid_insns"]   = valid_insns;
        pages.push_back(std::move(pg));
    }
    hide_wait_box();

    json result;
    result["start"]       = helpers::format_address(start_ea);
    result["end"]         = helpers::format_address(end_ea);
    result["page_size"]   = page_size;
    result["total_pages"] = pages.size();
    result["summary"] = {{"code", code_pages}, {"data", data_pages}, {"encrypted", encrypted_pages},
                         {"padding", padding_pages}, {"mixed", mixed_pages}};
    result["pages"] = std::move(pages);

    return tool_result_t::ok(OBFSTR("Classified ") + std::to_string(result["total_pages"].get<std::size_t>()) +
                             OBFSTR(" pages: ") + std::to_string(code_pages) + OBFSTR(" code, ") +
                             std::to_string(encrypted_pages) + OBFSTR(" encrypted, ") +
                             std::to_string(data_pages) + OBFSTR(" data"), result);
}


tool_result_t detect_vm_handler_pattern(const json& params)
{
    auto addr = helpers::parse_address(params.value("address", std::string()));
    if (!addr)
        return tool_result_t::error(OBFSTR("Invalid address"));

    ea_t ea = *addr;
    size_t scan_size = params.value("scan_size", 4096);
    if (scan_size > 65536) scan_size = 65536;

    json result;
    result["scan_start"] = helpers::format_address(ea);

    json patterns = json::array();
    ea_t scan_end = ea + scan_size;
    ea_t cur = ea;

    int indirect_jumps = 0;
    int cmp_chains = 0;
    ea_t last_cmp = BADADDR;

    while (cur < scan_end && cur != BADADDR)
    {
        insn_t insn;
        int len = decode_insn(&insn, cur);
        if (len <= 0)
        {
            cur = next_head(cur, scan_end);
            if (cur == BADADDR) break;
            continue;
        }

        if (insn.itype == NN_jmpni || insn.itype == NN_jmpfi)
        {
            ++indirect_jumps;
            json p;
            p["type"] = OBFSTR("indirect_jump");
            p["address"] = helpers::format_address(cur);
            qstring dis;
            generate_disasm_line(&dis, cur, GENDSM_FORCE_CODE);
            tag_remove(&dis);
            p["instruction"] = dis.c_str();

            ea_t prev = prev_head(cur, ea);
            if (prev != BADADDR)
            {
                insn_t prev_insn;
                if (decode_insn(&prev_insn, prev) > 0)
                {
                    qstring prev_dis;
                    generate_disasm_line(&prev_dis, prev, GENDSM_FORCE_CODE);
                    tag_remove(&prev_dis);
                    p["preceding_instruction"] = prev_dis.c_str();
                }
            }
            patterns.push_back(std::move(p));
        }

        if (insn.itype == NN_cmp)
        {
            if (last_cmp != BADADDR && (cur - last_cmp) < 32)
                ++cmp_chains;
            last_cmp = cur;
        }

        if (insn.itype == NN_loop || insn.itype == NN_loopd ||
            insn.itype == NN_loopw || insn.itype == NN_loopne ||
            insn.itype == NN_loope)
        {
            json p;
            p["type"] = OBFSTR("loop_instruction");
            p["address"] = helpers::format_address(cur);
            qstring dis;
            generate_disasm_line(&dis, cur, GENDSM_FORCE_CODE);
            tag_remove(&dis);
            p["instruction"] = dis.c_str();
            patterns.push_back(std::move(p));
        }

        cur += len;
    }

    if (cmp_chains >= 3)
    {
        json p;
        p["type"] = OBFSTR("cmp_dispatch_chain");
        p["chain_length"] = cmp_chains;
        p["note"] = OBFSTR("Multiple sequential CMP instructions suggest opcode-based dispatch (VM handler table)");
        patterns.push_back(std::move(p));
    }

    result["patterns"] = std::move(patterns);
    result["indirect_jumps_found"] = indirect_jumps;
    result["cmp_chain_length"] = cmp_chains;
    result["scan_bytes"] = scan_size;

    int score = 0;
    if (indirect_jumps > 0) score += 30;
    if (cmp_chains >= 5) score += 30;
    if (cmp_chains >= 10) score += 20;
    if (indirect_jumps > 2) score += 20;
    result["vm_confidence_pct"] = std::min(score, 100);

    return tool_result_t::ok(OBFSTR("VM handler pattern detection"), result);
}

tool_result_t map_vm_handler_table(const json& params)
{
    auto table_addr = helpers::parse_address(params.value("table_address", std::string()));
    if (!table_addr)
        return tool_result_t::error(OBFSTR("Invalid table_address"));

    ea_t base = *table_addr;
    int entry_count = params.value("entry_count", 256);
    if (entry_count < 1) entry_count = 1;
    if (entry_count > 4096) entry_count = 4096;
    int entry_size = params.value("entry_size", 8);
    if (entry_size != 4 && entry_size != 8) entry_size = 8;

    json handlers = json::array();
    json result;
    result["table_base"] = helpers::format_address(base);
    result["entry_size"] = entry_size;

    for (int i = 0; i < entry_count; ++i)
    {
        ea_t slot = base + static_cast<ea_t>(i) * entry_size;
        ea_t target = BADADDR;

        if (!is_loaded(slot)) continue;
        if (entry_size == 8)
            target = get_qword(slot);
        else
            target = static_cast<ea_t>(get_dword(slot));

        if (target == 0 || target == BADADDR)
            continue;

        json entry;
        entry["index"] = i;
        entry["slot"] = helpers::format_address(slot);
        entry["target"] = helpers::format_address(target);

        qstring tname;
        if (get_func_name(&tname, target) > 0)
            entry["name"] = tname.c_str();

        func_t* pfn = get_func(target);
        if (pfn)
        {
            ea_t end = std::min(pfn->end_ea, target + 64);
            entry["disassembly"] = helpers::get_disassembly(target, end);
        }
        else
        {
            entry["disassembly"] = helpers::get_disassembly(target, target + 32);
        }

        handlers.push_back(std::move(entry));
    }

    size_t valid_count = handlers.size();
    result["handlers"] = std::move(handlers);
    result["valid_entries"] = valid_count;
    return tool_result_t::ok(OBFSTR("VM handler table map"), result);
}

void register_tools()
{
    auto& registry = ToolRegistry::instance();

    registry.register_tool({OBFSTR("detect_obfuscation_patterns"), OBFSTR("analysis"),
        OBFSTR("Scan a function for obfuscation patterns: opaque predicates, dead code, "
               "junk insertion, indirect jumps, push/ret redirects. Returns obfuscation score."),
        {{OBFSTR("address"), OBFSTR("string"), OBFSTR("Function address"), true},
         {OBFSTR("scan_size"), OBFSTR("number"), OBFSTR("Max bytes to scan (default: full function)"), false}},
        detect_obfuscation_patterns});

    registry.register_tool({OBFSTR("analyze_control_flow"), OBFSTR("analysis"),
        OBFSTR("Analyze function control flow: basic blocks, edges, back-edges, cyclomatic complexity."),
        {{OBFSTR("address"), OBFSTR("string"), OBFSTR("Function address"), true}},
        analyze_control_flow});

    registry.register_tool({OBFSTR("get_function_complexity"), OBFSTR("analysis"),
        OBFSTR("Compute complexity metrics: cyclomatic complexity, instruction counts, Halstead metrics."),
        {{OBFSTR("address"), OBFSTR("string"), OBFSTR("Function address"), true}},
        get_function_complexity});

    registry.register_tool({OBFSTR("analyze_string_decryption"), OBFSTR("analysis"),
        OBFSTR("Detect string decryption patterns: XOR loops, stack strings, decrypt calls."),
        {{OBFSTR("address"), OBFSTR("string"), OBFSTR("Function address"), true}},
        analyze_string_decryption});

    registry.register_tool({OBFSTR("analyze_indirect_calls"), OBFSTR("analysis"),
        OBFSTR("Find and classify indirect calls/jumps: vtable, function pointer, register calls."),
        {{OBFSTR("address"), OBFSTR("string"), OBFSTR("Function address"), true}},
        analyze_indirect_calls});

    registry.register_tool({OBFSTR("find_crypto_constants"), OBFSTR("analysis"),
        OBFSTR("Scan for well-known crypto constants (AES, SHA-256, MD5, CRC32, Blowfish, TEA, ChaCha20)."),
        {{OBFSTR("address"), OBFSTR("string"), OBFSTR("Start address (optional)"), false},
         {OBFSTR("scan_size"), OBFSTR("number"), OBFSTR("Bytes to scan (default 65536)"), false}},
        find_crypto_constants});

    registry.register_tool({OBFSTR("analyze_data_flow"), OBFSTR("analysis"),
        OBFSTR("Track data flow around an instruction: backward defs, forward uses, usage classification."),
        {{OBFSTR("address"), OBFSTR("string"), OBFSTR("Instruction address"), true},
         {OBFSTR("register"), OBFSTR("string"), OBFSTR("Register to track (optional)"), false},
         {OBFSTR("max_depth"), OBFSTR("number"), OBFSTR("Max scan depth per direction (default 32)"), false}},
        analyze_data_flow, false});

    registry.register_tool({OBFSTR("detect_anti_analysis"), OBFSTR("analysis"),
        OBFSTR("Detect anti-debug/anti-VM techniques: API calls, CPUID/RDTSC, INT traps, VM strings."),
        {{OBFSTR("address"), OBFSTR("string"), OBFSTR("Function or start address"), true}},
        detect_anti_analysis});

    registry.register_tool({OBFSTR("analyze_pe_headers"), OBFSTR("analysis"),
        OBFSTR("Deep PE header analysis: COFF/Optional headers, all 16 data directories, TLS callbacks, Load Config, sections with entropy/classification. Essential for packed/protected binary analysis."),
        {{OBFSTR("address"), OBFSTR("string"), OBFSTR("Override image base address (default: IDB image base)"), false}},
        analyze_pe_headers, true});

    registry.register_tool({OBFSTR("analyze_entropy"), OBFSTR("analysis"),
        OBFSTR("Compute Shannon entropy of a memory region using a sliding window. Identifies encrypted, compressed, or packed sections."),
        {{OBFSTR("address"), OBFSTR("string"), OBFSTR("Start address to analyze"), true},
         {OBFSTR("size"), OBFSTR("number"), OBFSTR("Size in bytes (default: 4096)"), false},
         {OBFSTR("window_size"), OBFSTR("number"), OBFSTR("Sliding window size (default: 256)"), false}},
        analyze_entropy, true});

    registry.register_tool({OBFSTR("detect_hooks"), OBFSTR("analysis"),
        OBFSTR("Scan function prologues for inline hooks: jmp rel32, jmp [rip+disp], mov rax/jmp rax, push/ret, int3. Finds anti-cheat and security product hooks."),
        {{OBFSTR("address"), OBFSTR("string"), OBFSTR("Limit scan to segment containing this address"), false},
         {OBFSTR("max_functions"), OBFSTR("number"), OBFSTR("Max functions to check (default: 500)"), false}},
        detect_hooks, true});

    registry.register_tool({OBFSTR("detect_direct_syscalls"), OBFSTR("analysis"),
        OBFSTR("Find direct NT syscall stubs (mov r10,rcx; mov eax,N; syscall/int2e). Common in anti-cheats and malware to bypass API hooks."),
        {{OBFSTR("address"), OBFSTR("string"), OBFSTR("Address or segment to scan"), false},
         {OBFSTR("size"), OBFSTR("number"), OBFSTR("Scan size in bytes (0 = full segment)"), false}},
        detect_direct_syscalls, true});

    registry.register_tool({OBFSTR("resolve_api_hashes"), OBFSTR("analysis"),
        OBFSTR("Resolve hashed API imports using ror13, djb2, crc32, fnv1a, or sdbm. Builds dictionary from IDB imports + common Windows APIs."),
        {{OBFSTR("hash"), OBFSTR("string"), OBFSTR("Single hash value to resolve"), false},
         {OBFSTR("hashes"), OBFSTR("array"), OBFSTR("Array of hash values to resolve"), false},
         {OBFSTR("algorithm"), OBFSTR("string"), OBFSTR("Hash algorithm: ror13, djb2, crc32, fnv1a, sdbm (default: ror13)"), false},
         {OBFSTR("include_dll_name"), OBFSTR("boolean"), OBFSTR("Also try DLL!API format (default: false)"), false}},
        resolve_api_hashes, true});

    registry.register_tool({OBFSTR("reconstruct_vtable"), OBFSTR("analysis"),
        OBFSTR("Reconstruct C++ virtual function table. Reads pointer array, validates code targets, extracts RTTI (COL, type descriptor, class hierarchy). Handles demangling."),
        {{OBFSTR("address"), OBFSTR("string"), OBFSTR("VTABLE start address"), true},
         {OBFSTR("max_entries"), OBFSTR("number"), OBFSTR("Max entries to read (default: 200)"), false}},
        reconstruct_vtable, true});

    registry.register_tool({OBFSTR("classify_memory_pages"), OBFSTR("analysis"),
        OBFSTR("Classify memory pages as code, data, encrypted/compressed, padding, string data, or obfuscated. "
               "Uses entropy, instruction decoding, zero-ratio and string-ratio heuristics per page. "
               "Essential for understanding packed binary layout and finding hidden code regions."),
        {{OBFSTR("address"), OBFSTR("string"), OBFSTR("Start address (default: segment start or image base)"), false},
         {OBFSTR("size"), OBFSTR("number"), OBFSTR("Total bytes to classify (default: full segment)"), false},
         {OBFSTR("page_size"), OBFSTR("number"), OBFSTR("Page granularity in bytes (default: 4096, min: 256)"), false}},
        classify_memory_pages, true});


    registry.register_tool({OBFSTR("detect_vm_handler_pattern"), OBFSTR("analysis"),
        OBFSTR("Scan a code region for virtualization patterns: indirect jump tables, CMP dispatch chains, "
               "loop instructions. Returns a VM confidence score and identified patterns. "
               "Use this to detect VMProtect/Themida/custom VM handlers."),
        {{OBFSTR("address"), OBFSTR("string"), OBFSTR("Start address to scan"), true},
         {OBFSTR("scan_size"), OBFSTR("number"), OBFSTR("Bytes to scan (default 4096, max 65536)"), false}},
        detect_vm_handler_pattern});

    registry.register_tool({OBFSTR("map_vm_handler_table"), OBFSTR("analysis"),
        OBFSTR("Read a VM handler/dispatch table from the IDB and resolve each entry to its "
               "target function. Returns handler addresses, names, and first instructions."),
        {{OBFSTR("table_address"), OBFSTR("string"), OBFSTR("Base address of the handler table"), true},
         {OBFSTR("entry_count"), OBFSTR("number"), OBFSTR("Number of entries to read (default 256, max 4096)"), false},
         {OBFSTR("entry_size"), OBFSTR("number"), OBFSTR("Size of each entry in bytes (4 or 8, default 8)"), false}},
        map_vm_handler_table});
}

}

namespace deobfuscation_tools
{

tool_result_t nop_junk_instructions(const json& params)
{
    auto addr = helpers::parse_address(params.value("address", std::string()));
    if (!addr)
        return tool_result_t::error(OBFSTR("Invalid address"));

    ea_t ea = *addr;
    func_t* pfn = get_func(ea);
    if (!pfn)
        return tool_result_t::error(OBFSTR("No function at ") + helpers::format_address(ea));

    bool aggressive = params.value("aggressive", false);
    int nop_threshold = params.value("nop_threshold", 3);
    if (nop_threshold < 2) nop_threshold = 2;
    if (nop_threshold > 16) nop_threshold = 16;

    json result;
    result["function"] = helpers::get_name_or_address(pfn->start_ea);
    result["start"]    = helpers::format_address(pfn->start_ea);
    result["end"]      = helpers::format_address(pfn->end_ea);

    int nops_patched = 0;
    int dead_blocks_nopped = 0;
    int junk_sequences_nopped = 0;
    json patches = json::array();

    std::set<ea_t> dead_starts;
    if (aggressive)
    {
        func_item_iterator_t fii(pfn);
        for (bool ok = fii.first(); ok; ok = fii.next_head())
        {
            ea_t item = fii.current();
            if (item == pfn->start_ea) continue;

            xrefblk_t xb;
            bool has_incoming = false;
            for (bool xok = xb.first_to(item, XREF_ALL); xok; xok = xb.next_to())
            {
                if (xb.iscode && func_contains(pfn, xb.from))
                {
                    has_incoming = true;
                    break;
                }
            }

            if (!has_incoming)
            {
                ea_t prev = prev_head(item, pfn->start_ea);
                if (prev != BADADDR)
                {
                    insn_t prev_insn;
                    if (decode_insn(&prev_insn, prev) > 0)
                    {
                        if (!is_basic_block_end(prev_insn, false))
                            has_incoming = true;
                    }
                }
            }

            if (!has_incoming)
                dead_starts.insert(item);
        }
    }

    ea_t cur = pfn->start_ea;
    while (cur < pfn->end_ea && cur != BADADDR)
    {
        insn_t insn;
        int len = decode_insn(&insn, cur);
        if (len <= 0)
        {
            cur = next_head(cur, pfn->end_ea);
            if (cur == BADADDR) break;
            continue;
        }

        if (insn.itype == NN_nop)
        {
            ea_t nop_start = cur;
            int nop_count = 0;
            ea_t scan = cur;
            while (scan < pfn->end_ea)
            {
                insn_t ns;
                int nlen = decode_insn(&ns, scan);
                if (nlen <= 0 || ns.itype != NN_nop) break;
                ++nop_count;
                scan += nlen;
            }

            if (nop_count >= nop_threshold)
            {
                ++junk_sequences_nopped;
                json p;
                p["type"]    = OBFSTR("nop_sled");
                p["address"] = helpers::format_address(nop_start);
                p["count"]   = nop_count;
                patches.push_back(std::move(p));
                cur = scan;
                continue;
            }
        }

        if (aggressive && dead_starts.count(cur))
        {
            ea_t block_end = pfn->end_ea;
            ea_t scan = cur;
            while (scan < pfn->end_ea)
            {
                insn_t di;
                int dlen = decode_insn(&di, scan);
                if (dlen <= 0) break;

                ea_t next = scan + dlen;
                if (next < pfn->end_ea && dead_starts.count(next) == 0)
                {
                    xrefblk_t xb;
                    bool has_incoming = false;
                    for (bool xok = xb.first_to(next, XREF_ALL); xok; xok = xb.next_to())
                    {
                        if (xb.iscode) { has_incoming = true; break; }
                    }
                    if (has_incoming)
                    {
                        block_end = next;
                        break;
                    }
                }

                if (is_basic_block_end(di, false))
                {
                    block_end = scan + dlen;
                    break;
                }
                scan += dlen;
            }

            int patched_count = 0;
            for (ea_t p = cur; p < block_end; ++p)
            {
                if (patch_byte(p, 0x90))
                    ++patched_count;
            }
            if (patched_count > 0)
            {
                ++dead_blocks_nopped;
                nops_patched += patched_count;
                json p;
                p["type"]    = OBFSTR("dead_code_nopped");
                p["address"] = helpers::format_address(cur);
                p["size"]    = patched_count;
                patches.push_back(std::move(p));
            }
            cur = block_end;
            continue;
        }

        cur += len;
    }

    if (nops_patched > 0)
        reanalyze_function(pfn);

    result["patches"]               = std::move(patches);
    result["nops_patched"]          = nops_patched;
    result["dead_blocks_nopped"]    = dead_blocks_nopped;
    result["junk_sequences_found"]  = junk_sequences_nopped;

    return tool_result_t::ok(OBFSTR("Junk instruction cleanup: ") + std::to_string(nops_patched) + " bytes NOPed", result);
}

tool_result_t resolve_opaque_predicates(const json& params)
{
    auto addr = helpers::parse_address(params.value("address", std::string()));
    if (!addr)
        return tool_result_t::error(OBFSTR("Invalid address"));

    ea_t ea = *addr;
    func_t* pfn = get_func(ea);
    if (!pfn)
        return tool_result_t::error(OBFSTR("No function at ") + helpers::format_address(ea));

    bool dry_run = params.value("dry_run", false);

    json result;
    result["function"] = helpers::get_name_or_address(pfn->start_ea);
    json resolved = json::array();
    int count = 0;

    ea_t cur = pfn->start_ea;
    ea_t prev_ea = BADADDR;

    while (cur < pfn->end_ea && cur != BADADDR)
    {
        insn_t insn;
        int len = decode_insn(&insn, cur);
        if (len <= 0)
        {
            cur = next_head(cur, pfn->end_ea);
            if (cur == BADADDR) break;
            continue;
        }

        if (prev_ea != BADADDR &&
            (insn.itype == NN_jz || insn.itype == NN_jnz ||
             insn.itype == NN_jbe || insn.itype == NN_ja ||
             insn.itype == NN_jl || insn.itype == NN_jge ||
             insn.itype == NN_jle || insn.itype == NN_jg))
        {
            insn_t prev_insn;
            if (decode_insn(&prev_insn, prev_ea) > 0)
            {
                bool is_always_zero = false;
                bool is_always_nonzero = false;

                if (prev_insn.itype == NN_xor &&
                    prev_insn.ops[0].type == o_reg &&
                    prev_insn.ops[1].type == o_reg &&
                    prev_insn.ops[0].reg == prev_insn.ops[1].reg)
                {
                    is_always_zero = true;
                }
                if (prev_insn.itype == NN_test &&
                    prev_insn.ops[0].type == o_reg &&
                    prev_insn.ops[1].type == o_reg &&
                    prev_insn.ops[0].reg == prev_insn.ops[1].reg)
                {
                    ea_t prev2 = prev_head(prev_ea, pfn->start_ea);
                    if (prev2 != BADADDR)
                    {
                        insn_t prev2_insn;
                        if (decode_insn(&prev2_insn, prev2) > 0 &&
                            prev2_insn.itype == NN_xor &&
                            prev2_insn.ops[0].type == o_reg &&
                            prev2_insn.ops[1].type == o_reg &&
                            prev2_insn.ops[0].reg == prev2_insn.ops[1].reg &&
                            prev2_insn.ops[0].reg == prev_insn.ops[0].reg)
                        {
                            is_always_zero = true;
                        }
                    }
                }

                if (is_always_zero || is_always_nonzero)
                {
                    json patch_entry;
                    patch_entry["address"] = helpers::format_address(cur);
                    qstring dis;
                    generate_disasm_line(&dis, cur, GENDSM_FORCE_CODE);
                    tag_remove(&dis);
                    patch_entry["original_insn"] = dis.c_str();

                    bool should_take_branch = false;
                    if (is_always_zero)
                    {
                        should_take_branch = (insn.itype == NN_jz || insn.itype == NN_jbe ||
                                              insn.itype == NN_jle || insn.itype == NN_jge);
                    }
                    else
                    {
                        should_take_branch = (insn.itype == NN_jnz || insn.itype == NN_ja ||
                                              insn.itype == NN_jg || insn.itype == NN_jl);
                    }

                    if (!dry_run)
                    {
                        if (should_take_branch)
                        {
                            if (insn.size == 2)
                            {
                                patch_byte(cur, 0xEB);
                                patch_entry["action"] = OBFSTR("converted_to_jmp_short");
                            }
                            else if (insn.size == 6)
                            {
                                patch_byte(cur, 0x90);
                                patch_byte(cur + 1, 0xE9);
                                patch_entry["action"] = OBFSTR("converted_to_jmp_near");
                            }
                            else
                            {
                                patch_entry["action"] = OBFSTR("skipped_unusual_size");
                            }
                        }
                        else
                        {
                            for (int i = 0; i < insn.size; ++i)
                                patch_byte(cur + i, 0x90);
                            patch_entry["action"] = OBFSTR("nopped_never_taken");
                        }
                    }
                    else
                    {
                        patch_entry["action"] = should_take_branch
                            ? OBFSTR("would_convert_to_jmp")
                            : OBFSTR("would_nop");
                    }

                    patch_entry["branch_decision"] = should_take_branch ? "always_taken" : "never_taken";
                    resolved.push_back(std::move(patch_entry));
                    ++count;
                }
            }
        }

        prev_ea = cur;
        cur += len;
    }

    if (!dry_run && count > 0)
        reanalyze_function(pfn);

    result["resolved"]  = std::move(resolved);
    result["count"]     = count;
    result["dry_run"]   = dry_run;

    return tool_result_t::ok(OBFSTR("Resolved ") + std::to_string(count) + " opaque predicates", result);
}

tool_result_t patch_anti_debug(const json& params)
{
    auto addr = helpers::parse_address(params.value("address", std::string()));
    if (!addr)
        return tool_result_t::error(OBFSTR("Invalid address"));

    ea_t ea = *addr;
    func_t* pfn = get_func(ea);
    ea_t scan_start = pfn ? pfn->start_ea : ea;
    ea_t scan_end   = pfn ? pfn->end_ea : ea + params.value("size", (size_t)4096);

    bool dry_run = params.value("dry_run", false);
    bool patch_api_calls = params.value("patch_api_calls", true);
    bool patch_int_traps = params.value("patch_int_traps", true);
    bool patch_timing    = params.value("patch_timing", true);

    static const char* anti_debug_apis[] = {
        "IsDebuggerPresent", "CheckRemoteDebuggerPresent",
        "NtQueryInformationProcess", "NtSetInformationThread",
        "OutputDebugString", "DbgBreakPoint", "DbgUiRemoteBreakin",
        "NtQuerySystemInformation",
        nullptr
    };

    json result;
    if (pfn) result["function"] = helpers::get_name_or_address(pfn->start_ea);
    json patches = json::array();
    int total_patched = 0;

    ea_t cur = scan_start;
    while (cur < scan_end && cur != BADADDR)
    {
        insn_t insn;
        int len = decode_insn(&insn, cur);
        if (len <= 0)
        {
            cur = next_head(cur, scan_end);
            if (cur == BADADDR) break;
            continue;
        }

        if (patch_api_calls && (insn.itype == NN_call || insn.itype == NN_callni || insn.itype == NN_callfi))
        {
            ea_t target = BADADDR;
            if (insn.ops[0].type == o_near || insn.ops[0].type == o_far)
                target = insn.ops[0].addr;
            else if (insn.ops[0].type == o_mem)
                target = static_cast<ea_t>(insn.ops[0].addr);

            if (target != BADADDR)
            {
                qstring tname;
                if (get_name(&tname, target) > 0)
                {
                    for (int i = 0; anti_debug_apis[i]; ++i)
                    {
                        if (tname.find(anti_debug_apis[i]) != qstring::npos)
                        {
                            json p;
                            p["type"]    = OBFSTR("anti_debug_call");
                            p["address"] = helpers::format_address(cur);
                            p["api"]     = tname.c_str();

                            if (!dry_run)
                            {
                                for (int b = 0; b < insn.size; ++b)
                                    patch_byte(cur + b, 0x90);
                                p["action"] = OBFSTR("nopped");
                                ++total_patched;

                                if (std::string(anti_debug_apis[i]) == "IsDebuggerPresent")
                                {
                                    if (insn.size >= 2)
                                    {
                                        patch_byte(cur, 0x31);
                                        patch_byte(cur + 1, 0xC0);
                                        for (int b = 2; b < insn.size; ++b)
                                            patch_byte(cur + b, 0x90);
                                        p["action"] = OBFSTR("replaced_with_xor_eax_eax");
                                    }
                                }
                            }
                            else
                            {
                                p["action"] = OBFSTR("would_nop");
                            }

                            patches.push_back(std::move(p));
                            break;
                        }
                    }
                }
            }
        }

        if (patch_int_traps && insn.itype == NN_int &&
            insn.ops[0].type == o_imm && insn.ops[0].value == 0x2D)
        {
            json p;
            p["type"]    = OBFSTR("int2d_trap");
            p["address"] = helpers::format_address(cur);
            if (!dry_run)
            {
                for (int b = 0; b < insn.size; ++b)
                    patch_byte(cur + b, 0x90);
                p["action"] = OBFSTR("nopped");
                ++total_patched;
            }
            else
            {
                p["action"] = OBFSTR("would_nop");
            }
            patches.push_back(std::move(p));
        }

        if (patch_int_traps && insn.itype == NN_int3)
        {
            json p;
            p["type"]    = OBFSTR("int3_trap");
            p["address"] = helpers::format_address(cur);
            if (!dry_run)
            {
                patch_byte(cur, 0x90);
                p["action"] = OBFSTR("nopped");
                ++total_patched;
            }
            else
            {
                p["action"] = OBFSTR("would_nop");
            }
            patches.push_back(std::move(p));
        }

        if (patch_timing && insn.itype == NN_rdtsc)
        {
            json p;
            p["type"]    = OBFSTR("rdtsc_timing");
            p["address"] = helpers::format_address(cur);
            if (!dry_run)
            {
                if (insn.size >= 2)
                {
                    patch_byte(cur, 0x31);
                    patch_byte(cur + 1, 0xC0);
                    p["action"] = OBFSTR("replaced_with_xor_eax");
                }
                ++total_patched;
            }
            else
            {
                p["action"] = OBFSTR("would_patch");
            }
            patches.push_back(std::move(p));
        }

        cur += len;
    }

    if (!dry_run && total_patched > 0 && pfn)
        reanalyze_function(pfn);

    result["patches"]       = std::move(patches);
    result["total_patched"] = total_patched;
    result["dry_run"]       = dry_run;

    return tool_result_t::ok(OBFSTR("Anti-debug patching: ") + std::to_string(total_patched) + " patches", result);
}

tool_result_t decode_strings_in_function(const json& params)
{
    auto addr = helpers::parse_address(params.value("address", std::string()));
    if (!addr)
        return tool_result_t::error(OBFSTR("Invalid address"));

    ea_t ea = *addr;
    func_t* pfn = get_func(ea);
    if (!pfn)
        return tool_result_t::error(OBFSTR("No function at ") + helpers::format_address(ea));

    bool add_comments = params.value("add_comments", true);

    json result;
    result["function"] = helpers::get_name_or_address(pfn->start_ea);
    json decoded_strings = json::array();

    ea_t cur = pfn->start_ea;
    ea_t stack_str_start = BADADDR;
    std::string stack_str_chars;
    int stack_str_count = 0;

    while (cur < pfn->end_ea && cur != BADADDR)
    {
        insn_t insn;
        int len = decode_insn(&insn, cur);
        if (len <= 0)
        {
            cur = next_head(cur, pfn->end_ea);
            if (cur == BADADDR) break;
            continue;
        }

        bool is_byte_mov = (insn.itype == NN_mov &&
                           insn.ops[0].type == o_displ &&
                           insn.ops[1].type == o_imm);

        if (is_byte_mov)
        {
            uint64_t val = insn.ops[1].value;
            if (val >= 0x20 && val <= 0x7E)
            {
                if (stack_str_start == BADADDR)
                    stack_str_start = cur;
                stack_str_chars += static_cast<char>(val);
                ++stack_str_count;
                cur += len;
                continue;
            }
        }

        if (insn.itype == NN_mov && insn.ops[0].type == o_displ && insn.ops[1].type == o_imm)
        {
            uint64_t val = insn.ops[1].value;
            std::string chunk;
            bool all_printable = true;
            int byte_count = 0;

            if (val > 0xFF && val <= 0xFFFFFFFF)
                byte_count = 4;
            else if (val > 0xFFFFFFFF)
                byte_count = 8;

            if (byte_count > 0)
            {
                for (int b = 0; b < byte_count; ++b)
                {
                    char c = static_cast<char>((val >> (b * 8)) & 0xFF);
                    if (c == 0) break;
                    if (c < 0x20 || c > 0x7E) { all_printable = false; break; }
                    chunk += c;
                }
                if (all_printable && chunk.size() >= 2)
                {
                    if (stack_str_start == BADADDR)
                        stack_str_start = cur;
                    stack_str_chars += chunk;
                    stack_str_count++;
                    cur += len;
                    continue;
                }
            }
        }

        if (stack_str_count >= 3 && !stack_str_chars.empty())
        {
            json s;
            s["type"]    = OBFSTR("stack_string");
            s["address"] = helpers::format_address(stack_str_start);
            s["decoded"] = stack_str_chars;
            s["length"]  = stack_str_chars.size();
            decoded_strings.push_back(std::move(s));

            if (add_comments)
                set_cmt(stack_str_start, (std::string("AiDA: Stack string: \"") + stack_str_chars + "\"").c_str(), false);
        }
        stack_str_start = BADADDR;
        stack_str_chars.clear();
        stack_str_count = 0;

        cur += len;
    }

    if (stack_str_count >= 3 && !stack_str_chars.empty())
    {
        json s;
        s["type"]    = OBFSTR("stack_string");
        s["address"] = helpers::format_address(stack_str_start);
        s["decoded"] = stack_str_chars;
        s["length"]  = stack_str_chars.size();
        decoded_strings.push_back(std::move(s));
        if (add_comments)
            set_cmt(stack_str_start, (std::string("AiDA: Stack string: \"") + stack_str_chars + "\"").c_str(), false);
    }

    func_item_iterator_t fii(pfn);
    for (bool ok = fii.first(); ok; ok = fii.next_head())
    {
        ea_t item = fii.current();
        insn_t insn;
        if (decode_insn(&insn, item) <= 0) continue;

        if (insn.itype == NN_xor && insn.ops[1].type == o_imm)
        {
            uint8_t xor_key = static_cast<uint8_t>(insn.ops[1].value & 0xFF);
            if (xor_key == 0) continue;

            xrefblk_t xb;
            for (bool xok = xb.first_from(item, XREF_DATA); xok; xok = xb.next_from())
            {
                ea_t data_ea = xb.to;
                if (!is_loaded(data_ea)) continue;

                std::string decoded;
                for (int i = 0; i < 256; ++i)
                {
                    if (!is_loaded(data_ea + i)) break;
                    uint8_t b = get_byte(data_ea + i);
                    char c = static_cast<char>(b ^ xor_key);
                    if (c == 0) break;
                    if (c < 0x20 || c > 0x7E) { decoded.clear(); break; }
                    decoded += c;
                }

                if (decoded.size() >= 4)
                {
                    json s;
                    s["type"]     = OBFSTR("xor_string");
                    s["address"]  = helpers::format_address(item);
                    s["data_at"]  = helpers::format_address(data_ea);
                    s["xor_key"]  = helpers::format_address(static_cast<ea_t>(xor_key));
                    s["decoded"]  = decoded;
                    s["length"]   = decoded.size();
                    decoded_strings.push_back(std::move(s));

                    if (add_comments)
                    {
                        set_cmt(item, (std::string("AiDA: XOR-decrypted string (key=0x") +
                                      helpers::format_address(static_cast<ea_t>(xor_key)).substr(2) +
                                      "): \"" + decoded + "\"").c_str(), false);
                    }
                }
            }
        }
    }

    int total_decoded = static_cast<int>(decoded_strings.size());
    result["decoded_strings"] = std::move(decoded_strings);
    result["total_decoded"]   = total_decoded;

    return tool_result_t::ok(OBFSTR("String decoding: ") + std::to_string(total_decoded) + " strings found", result);
}

tool_result_t rebuild_function(const json& params)
{
    auto addr = helpers::parse_address(params.value("address", std::string()));
    if (!addr)
        return tool_result_t::error(OBFSTR("Invalid address"));

    ea_t ea = *addr;
    func_t* pfn = get_func(ea);
    ea_t start = pfn ? pfn->start_ea : ea;
    ea_t end   = pfn ? pfn->end_ea : BADADDR;

    bool force_recreate = params.value("force_recreate", false);
    bool create_instructions = params.value("create_instructions", true);

    json result;
    result["original_start"] = helpers::format_address(start);
    if (end != BADADDR)
        result["original_end"] = helpers::format_address(end);

    int insns_created = 0;
    int errors = 0;

    if (force_recreate && pfn)
    {
        del_func(start);
        result["deleted_original"] = true;

        if (end != BADADDR)
            del_items(start, DELIT_SIMPLE, end - start);
    }

    if (create_instructions)
    {
        ea_t range_end = (end != BADADDR) ? end : start + 0x10000;
        ea_t cur = start;
        while (cur < range_end && cur != BADADDR)
        {
            int len = create_insn(cur);
            if (len > 0)
            {
                ++insns_created;
                cur += len;
            }
            else
            {
                ++errors;
                cur = next_addr(cur);
                if (cur == BADADDR) break;
            }
        }
    }

    bool func_created = add_func(start, BADADDR);
    pfn = get_func(start);

    if (pfn)
    {
        reanalyze_function(pfn);
        result["new_start"] = helpers::format_address(pfn->start_ea);
        result["new_end"]   = helpers::format_address(pfn->end_ea);
        result["new_size"]  = pfn->end_ea - pfn->start_ea;
    }

    if (end != BADADDR)
    {
        auto_mark_range(start, end, AU_FINAL);
        plan_range(start, end);


        responsive_auto_wait(start, end, "Rebuilding function analysis");
    }

    result["function_created"]   = func_created;
    result["instructions_created"] = insns_created;
    result["errors"]             = errors;

    return tool_result_t::ok(OBFSTR("Function rebuilt: ") + std::to_string(insns_created) + " instructions", result);
}

tool_result_t identify_protector(const json& params)
{
    size_t scan_size = params.value("scan_size", (size_t)0x100000);
    if (scan_size > 0x1000000) scan_size = 0x1000000;

    ea_t start = inf_get_min_ea();
    ea_t end   = std::min(start + static_cast<ea_t>(scan_size), inf_get_max_ea());

    json result;
    json detections = json::array();

    struct section_sig_t {
        const char* name;
        const char* protector;
    };
    static const section_sig_t section_sigs[] = {
        {".vmp",    "VMProtect"},
        {".vmp0",   "VMProtect"},
        {".vmp1",   "VMProtect"},
        {".vmp2",   "VMProtect"},
        {".vmprotect", "VMProtect"},
        {".themida", "Themida/WinLicense"},
        {".Themida", "Themida/WinLicense"},
        {"Themida",  "Themida/WinLicense"},
        {".upx",    "UPX"},
        {"UPX0",    "UPX"},
        {"UPX1",    "UPX"},
        {"UPX2",    "UPX"},
        {".aspack", "ASPack"},
        {".adata",  "ASPack"},
        {".nsp",    "NSPack"},
        {".enigma", "Enigma Protector"},
        {".perplex", "PECompact"},
        {".petite", "Petite"},
        {".yP",     "Y's Crypter"},
        {".sforce", "StarForce"},
        {"_winzip_", "WinZip SFX"},
        {".shrink", "Shrinker"},
        {".RLPack", "RLPack"},
        {".MaskPE", "MaskPE"},
        {".ndata",  "NSIS Installer"},
        {".rsrc",   ""},
        {nullptr,   nullptr}
    };

    for (int si = 0; si < get_segm_qty(); ++si)
    {
        segment_t* seg = getnseg(si);
        if (!seg) continue;

        qstring sname;
        get_segm_name(&sname, seg);

        for (int k = 0; section_sigs[k].name; ++k)
        {
            if (sname == section_sigs[k].name && section_sigs[k].protector[0] != '\0')
            {
                json d;
                d["type"]      = OBFSTR("section_name");
                d["section"]   = sname.c_str();
                d["protector"] = section_sigs[k].protector;
                d["start"]     = helpers::format_address(seg->start_ea);
                d["size"]      = seg->size();
                detections.push_back(std::move(d));
            }
        }
    }

    struct byte_sig_t {
        const char* protector;
        const char* description;
        const uint8_t* pattern;
        const uint8_t* mask;
        int length;
    };

    static const uint8_t vmp_push_call[] = { 0x68, 0x00, 0x00, 0x00, 0x00, 0xE8, 0x00, 0x00, 0x00, 0x00 };
    static const uint8_t vmp_push_mask[] = { 0xFF, 0x00, 0x00, 0x00, 0x00, 0xFF, 0x00, 0x00, 0x00, 0x00 };

    static const uint8_t themida_sig[] = { 0xB8, 0x00, 0x00, 0x00, 0x00, 0x60, 0x0F, 0x31 };
    static const uint8_t themida_mask[] = { 0xFF, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF };

    static const uint8_t upx_sig[] = { 0x60, 0xBE, 0x00, 0x00, 0x00, 0x00, 0x8D, 0xBE };
    static const uint8_t upx_mask[] = { 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF };

    static const byte_sig_t byte_sigs[] = {
        {"VMProtect", "VMProtect entry stub (push/call pattern)", vmp_push_call, vmp_push_mask, 10},
        {"Themida/WinLicense", "Themida stolen code entry", themida_sig, themida_mask, 8},
        {"UPX", "UPX decompression stub", upx_sig, upx_mask, 8},
    };

    ea_t ep = inf_get_start_ea();
    if (ep != BADADDR)
    {
        for (const auto& sig : byte_sigs)
        {
            for (ea_t scan = (ep > 0x100 ? ep - 0x100 : ep); scan < ep + 0x1000 && scan < end; ++scan)
            {
                if (!is_loaded(scan)) continue;
                bool match = true;
                for (int i = 0; i < sig.length; ++i)
                {
                    if (!is_loaded(scan + i)) { match = false; break; }
                    uint8_t b = get_byte(scan + i);
                    if ((b & sig.mask[i]) != (sig.pattern[i] & sig.mask[i]))
                    {
                        match = false;
                        break;
                    }
                }
                if (match)
                {
                    json d;
                    d["type"]        = OBFSTR("byte_signature");
                    d["address"]     = helpers::format_address(scan);
                    d["protector"]   = sig.protector;
                    d["description"] = sig.description;
                    detections.push_back(std::move(d));
                    break;
                }
            }
        }
    }

    static const char* protector_strings[] = {
        "VMProtect begin", "VMProtect end", "VMProtectSDK",
        "Themida", "WinLicense", "Oreans Technologies",
        "UPX!", "This program cannot be run",
        "ASProtect", "StarForce",
        "Enigma protector", "EXECryptor",
        ".NET Reactor", "ConfuserEx",
        "Obsidium", "PECompact",
        nullptr
    };

    for (int si = 0; si < get_segm_qty(); ++si)
    {
        segment_t* seg = getnseg(si);
        if (!seg) continue;

        qstring sname;
        get_segm_name(&sname, seg);
        if (sname != ".rdata" && sname != ".data" && sname != ".rsrc") continue;

        ea_t seg_end = std::min(seg->end_ea, seg->start_ea + static_cast<ea_t>(0x100000));
        for (ea_t scan = seg->start_ea; scan < seg_end; ++scan)
        {
            if (!is_loaded(scan)) continue;
            flags64_t f = get_flags(scan);
            if (!is_strlit(f)) continue;

            qstring s;
            if (get_strlit_contents(&s, scan, -1, get_str_type(scan)) <= 0) continue;

            for (int k = 0; protector_strings[k]; ++k)
            {
                if (s.find(protector_strings[k]) != qstring::npos)
                {
                    json d;
                    d["type"]      = OBFSTR("string_reference");
                    d["address"]   = helpers::format_address(scan);
                    d["string"]    = s.c_str();
                    d["protector"] = protector_strings[k];
                    detections.push_back(std::move(d));
                    break;
                }
            }
        }
    }

    json entropy_info = json::array();
    for (int si = 0; si < get_segm_qty(); ++si)
    {
        segment_t* seg = getnseg(si);
        if (!seg || seg->size() == 0) continue;

        qstring sname;
        get_segm_name(&sname, seg);

        size_t sample_size = std::min(static_cast<size_t>(seg->size()), static_cast<size_t>(4096));
        int freq[256] = {0};
        int valid_bytes = 0;

        for (size_t i = 0; i < sample_size; ++i)
        {
            ea_t addr = seg->start_ea + i;
            if (!is_loaded(addr)) continue;
            ++freq[get_byte(addr)];
            ++valid_bytes;
        }

        if (valid_bytes > 0)
        {
            double entropy = 0.0;
            for (int k = 0; k < 256; ++k)
            {
                if (freq[k] == 0) continue;
                double p = static_cast<double>(freq[k]) / valid_bytes;
                entropy -= p * std::log2(p);
            }

            json ei;
            ei["section"] = sname.c_str();
            ei["entropy"]  = entropy;
            ei["size"]     = seg->size();
            ei["verdict"]  = (entropy > 7.5) ? "packed/encrypted" :
                            (entropy > 6.5) ? "compressed/obfuscated" :
                            (entropy > 5.0) ? "normal_code" : "sparse_data";
            entropy_info.push_back(std::move(ei));

            if (entropy > 7.5)
            {
                json d;
                d["type"]      = OBFSTR("high_entropy");
                d["section"]   = sname.c_str();
                d["entropy"]   = entropy;
                d["note"]      = OBFSTR("High entropy suggests packed/encrypted section");
                detections.push_back(std::move(d));
            }
        }
    }

    result["detections"]   = std::move(detections);
    result["entropy"]      = std::move(entropy_info);
    result["detection_count"] = result["detections"].size();

    std::set<std::string> found_protectors;
    for (const auto& d : result["detections"])
    {
        if (d.contains("protector") && d["protector"].is_string())
            found_protectors.insert(d["protector"].get<std::string>());
    }

    json protectors = json::array();
    for (const auto& p : found_protectors)
        protectors.push_back(p);
    result["protectors_found"] = std::move(protectors);

    std::string summary = found_protectors.empty()
        ? "No known protectors detected"
        : "Detected: ";
    for (const auto& p : found_protectors)
        summary += p + ", ";
    if (!found_protectors.empty())
        summary = summary.substr(0, summary.size() - 2);

    return tool_result_t::ok(summary, result);
}

tool_result_t deobfuscate_control_flow(const json& params)
{
    auto addr = helpers::parse_address(params.value("address", std::string()));
    if (!addr)
        return tool_result_t::error(OBFSTR("Invalid address"));

    ea_t ea = *addr;
    func_t* pfn = get_func(ea);
    if (!pfn)
        return tool_result_t::error(OBFSTR("No function at ") + helpers::format_address(ea));

    json result;
    result["function"] = helpers::get_name_or_address(pfn->start_ea);
    result["start"]    = helpers::format_address(pfn->start_ea);
    result["end"]      = helpers::format_address(pfn->end_ea);

    std::map<ea_t, int> backedge_targets;
    std::set<ea_t> all_block_starts;
    all_block_starts.insert(pfn->start_ea);

    func_item_iterator_t fii(pfn);
    for (bool ok = fii.first(); ok; ok = fii.next_head())
    {
        ea_t item = fii.current();
        insn_t insn;
        if (decode_insn(&insn, item) <= 0) continue;

        if (is_basic_block_end(insn, false))
        {
            ea_t fall = item + insn.size;
            if (func_contains(pfn, fall))
                all_block_starts.insert(fall);

            xrefblk_t xb;
            for (bool xok = xb.first_from(item, XREF_ALL); xok; xok = xb.next_from())
            {
                if (xb.iscode && func_contains(pfn, xb.to))
                {
                    all_block_starts.insert(xb.to);
                    if (xb.to <= item)
                        backedge_targets[xb.to]++;
                }
            }
        }
    }

    ea_t dispatcher = BADADDR;
    int max_backedges = 0;
    for (const auto& [addr_target, count] : backedge_targets)
    {
        if (count > max_backedges)
        {
            max_backedges = count;
            dispatcher = addr_target;
        }
    }

    json cff_analysis;
    cff_analysis["block_count"]    = all_block_starts.size();
    cff_analysis["back_edge_targets"] = backedge_targets.size();

    bool is_cff = false;
    if (dispatcher != BADADDR && max_backedges >= 3 &&
        all_block_starts.size() >= 5)
    {
        is_cff = true;
        cff_analysis["dispatcher_address"] = helpers::format_address(dispatcher);
        cff_analysis["dispatcher_backedge_count"] = max_backedges;

        json state_var_info;
        ea_t disp_end = pfn->end_ea;
        auto it = all_block_starts.upper_bound(dispatcher);
        if (it != all_block_starts.end())
            disp_end = *it;

        for (ea_t dc = dispatcher; dc < disp_end && dc != BADADDR;)
        {
            insn_t dins;
            int dlen = decode_insn(&dins, dc);
            if (dlen <= 0) break;

            if (dins.itype == NN_cmp || dins.itype == NN_sub || dins.itype == NN_test)
            {
                qstring dis;
                generate_disasm_line(&dis, dc, GENDSM_FORCE_CODE);
                tag_remove(&dis);
                state_var_info["dispatcher_comparison"] = dis.c_str();
                state_var_info["comparison_address"]    = helpers::format_address(dc);

                if (dins.ops[0].type == o_reg)
                    state_var_info["state_register"] = static_cast<int>(dins.ops[0].reg);
                if (dins.ops[0].type == o_displ || dins.ops[0].type == o_mem)
                    state_var_info["state_memory"] = helpers::format_address(static_cast<ea_t>(dins.ops[0].addr));
                break;
            }
            dc += dlen;
        }
        cff_analysis["state_variable"] = state_var_info;

        json state_blocks = json::array();
        for (ea_t bs : all_block_starts)
        {
            ea_t block_end = pfn->end_ea;
            auto bit = all_block_starts.upper_bound(bs);
            if (bit != all_block_starts.end())
                block_end = *bit;

            ea_t last_insn = bs;
            for (ea_t a = bs; a < block_end;)
            {
                insn_t ti;
                int tlen = decode_insn(&ti, a);
                if (tlen <= 0) break;
                last_insn = a;
                a += tlen;
            }

            xrefblk_t xb;
            bool jumps_to_dispatcher = false;
            for (bool xok = xb.first_from(last_insn, XREF_ALL); xok; xok = xb.next_from())
            {
                if (xb.iscode && xb.to == dispatcher)
                {
                    jumps_to_dispatcher = true;
                    break;
                }
            }

            if (jumps_to_dispatcher && bs != dispatcher)
            {
                json sb;
                sb["start"] = helpers::format_address(bs);
                sb["end"]   = helpers::format_address(block_end);

                for (ea_t a = bs; a < block_end;)
                {
                    insn_t si;
                    int slen = decode_insn(&si, a);
                    if (slen <= 0) break;

                    if (si.itype == NN_mov && si.ops[1].type == o_imm)
                    {
                        if (si.ops[0].type == o_reg || si.ops[0].type == o_displ || si.ops[0].type == o_mem)
                        {
                            sb["next_state"] = static_cast<int64_t>(si.ops[1].value);
                            sb["state_assign_addr"] = helpers::format_address(a);
                        }
                    }
                    a += slen;
                }

                state_blocks.push_back(std::move(sb));
            }
        }

        cff_analysis["state_blocks"]      = std::move(state_blocks);
        cff_analysis["state_block_count"] = cff_analysis["state_blocks"].size();

        set_cmt(dispatcher, "AiDA: CFF Dispatcher block - state variable switch", false);
        for (const auto& sb : cff_analysis["state_blocks"])
        {
            auto sb_addr = helpers::parse_address(sb.value("start", std::string()));
            if (sb_addr)
            {
                std::string comment = "AiDA: CFF State block";
                if (sb.contains("next_state"))
                    comment += " ÃƒÆ’Ã‚Â¢ÃƒÂ¢Ã¢â€šÂ¬Ã‚Â ÃƒÂ¢Ã¢â€šÂ¬Ã¢â€žÂ¢ next_state=" + std::to_string(sb["next_state"].get<int64_t>());
                set_cmt(*sb_addr, comment.c_str(), false);
            }
        }
    }

    cff_analysis["is_control_flow_flattened"] = is_cff;
    result["cff_analysis"] = std::move(cff_analysis);

    std::string summary = is_cff
        ? "Control flow flattening detected and mapped (" + std::to_string(max_backedges) + " state blocks)"
        : "No control flow flattening pattern detected";

    return tool_result_t::ok(summary, result);
}

tool_result_t reconstruct_imports(const json& params)
{
    auto base_opt = helpers::parse_address(params.value("address", std::string()));
    ea_t base = base_opt ? *base_opt : inf_get_min_ea();
    size_t scan_size = params.value("scan_size", (size_t)0x100000);

    json result;
    result["base"] = helpers::format_address(base);

    uint import_count = get_import_module_qty();
    json known_imports = json::array();
    std::map<ea_t, std::string> import_map;

    for (uint i = 0; i < import_count; ++i)
    {
        qstring mod_name;
        get_import_module_name(&mod_name, i);

        struct enum_ctx_t {
            std::map<ea_t, std::string>* map;
            std::string module;
        };
        enum_ctx_t ctx;
        ctx.map = &import_map;
        ctx.module = mod_name.c_str();

        enum_import_names(i, [](ea_t ea, const char* name, uval_t , void* param) -> int {
            auto* c = static_cast<enum_ctx_t*>(param);
            if (name && name[0])
                (*c->map)[ea] = std::string(c->module) + "!" + name;
            return 1;
        }, &ctx);
    }

    json iat_entries = json::array();
    int resolved = 0;
    int unresolved = 0;

    for (int si = 0; si < get_segm_qty(); ++si)
    {
        segment_t* seg = getnseg(si);
        if (!seg) continue;

        qstring sname;
        get_segm_name(&sname, seg);

        bool is_iat = (sname == ".idata" || sname == ".rdata" || sname == "IAT");
        if (!is_iat) continue;

        for (ea_t ea = seg->start_ea; ea + 8 <= seg->end_ea; ea += 8)
        {
            if (!is_loaded(ea)) continue;

            uint64 val = get_qword(ea);
            if (val == 0 || val == BADADDR) continue;

            qstring target_name;
            if (get_name(&target_name, static_cast<ea_t>(val)) > 0 && !target_name.empty())
            {
                json ie;
                ie["iat_address"]   = helpers::format_address(ea);
                ie["target"]        = helpers::format_address(static_cast<ea_t>(val));
                ie["resolved_name"] = target_name.c_str();
                iat_entries.push_back(std::move(ie));
                ++resolved;
            }
            else
            {
                if (getseg(static_cast<ea_t>(val)))
                {
                    ++unresolved;
                    json ie;
                    ie["iat_address"] = helpers::format_address(ea);
                    ie["target"]      = helpers::format_address(static_cast<ea_t>(val));
                    ie["status"]      = OBFSTR("unresolved");
                    iat_entries.push_back(std::move(ie));
                }
            }
        }
    }

    int names_set = 0;

    for (auto& iat_entry : iat_entries)
    {
        if (iat_entry.value("status", "") != "unresolved") continue;
        auto target_opt = helpers::parse_address(iat_entry["target"].get<std::string>());
        if (!target_opt) continue;
        ea_t target_ea = *target_opt;


        auto it = import_map.find(target_ea);
        if (it != import_map.end())
        {
            iat_entry["resolved_name"] = it->second;
            iat_entry.erase("status");
            ++names_set;
            ++resolved; --unresolved;
            continue;
        }


        qstring found_name;
        if (get_name(&found_name, target_ea, GN_DEMANGLED) > 0 && !found_name.empty())
        {
            iat_entry["resolved_name"] = found_name.c_str();
            iat_entry.erase("status");
            set_name(target_ea, found_name.c_str(), SN_NOWARN | SN_NOCHECK);
            ++names_set;
            ++resolved; --unresolved;
            continue;
        }


        segment_t* target_seg = getseg(target_ea);
        if (target_seg)
        {
            qstring seg_name;
            get_segm_name(&seg_name, target_seg);

            if (target_seg->perm & SEGPERM_EXEC)
            {
                func_t* f = get_func(target_ea);
                if (!f)
                {
                    add_func(target_ea);
                    f = get_func(target_ea);
                }
                if (f)
                {
                    qstring fn;
                    if (get_func_name(&fn, target_ea) > 0 && !fn.empty())
                    {
                        auto iat_ea = helpers::parse_address(iat_entry["iat_address"].get<std::string>());
                        if (iat_ea)
                        {
                            std::string label = std::string("imp_") + fn.c_str();
                            set_name(*iat_ea, label.c_str(), SN_NOWARN | SN_NOCHECK);
                        }
                        iat_entry["resolved_name"] = fn.c_str();
                        iat_entry.erase("status");
                        ++names_set;
                        ++resolved; --unresolved;
                    }
                }
            }
        }
    }

    json call_thunks = json::array();
    for (const auto& iat_entry : iat_entries)
    {
        if (iat_entry.value("status", "") != "unresolved") continue;

        auto iat_ea = helpers::parse_address(iat_entry["iat_address"].get<std::string>());
        if (!iat_ea) continue;

        xrefblk_t xb;
        int ref_count = 0;
        for (bool xok = xb.first_to(*iat_ea, XREF_ALL); xok && ref_count < 50; xok = xb.next_to())
        {
            ++ref_count;
            insn_t insn;
            if (decode_insn(&insn, xb.from) > 0)
            {
                if (insn.itype == NN_call || insn.itype == NN_callni ||
                    insn.itype == NN_jmp || insn.itype == NN_jmpni)
                {
                    json ct;
                    ct["caller"]      = helpers::format_address(xb.from);
                    ct["iat_slot"]    = helpers::format_address(*iat_ea);
                    ct["target"]      = iat_entry["target"];
                    call_thunks.push_back(std::move(ct));
                }
            }
        }
    }

    result["import_modules"]       = import_count;
    result["known_imports"]        = import_map.size();
    result["iat_entries_found"]    = iat_entries.size();
    result["resolved_entries"]     = resolved;
    result["unresolved_entries"]   = unresolved;
    result["iat_entries"]          = std::move(iat_entries);
    result["call_thunks"]          = std::move(call_thunks);
    result["names_set"]            = names_set;

    return tool_result_t::ok(OBFSTR("Import reconstruction: ") + std::to_string(resolved) +
                             " resolved, " + std::to_string(unresolved) + " unresolved", result);
}

tool_result_t unpack_section(const json& params)
{
    auto addr = helpers::parse_address(params.value("address", std::string()));
    if (!addr)
        return tool_result_t::error(OBFSTR("Invalid address"));

    ea_t section_start = *addr;
    segment_t* seg = getseg(section_start);
    if (!seg)
        return tool_result_t::error(OBFSTR("No segment at ") + helpers::format_address(section_start));

    size_t section_size = params.value("size", static_cast<size_t>(seg->size()));
    if (section_size > static_cast<size_t>(seg->size()))
        section_size = static_cast<size_t>(seg->size());

    std::string method = params.value("method", "auto");
    std::string key_str = params.value("key", "");
    bool create_code = params.value("create_code", true);

    json result;
    result["section_start"]  = helpers::format_address(section_start);
    result["section_size"]   = section_size;
    result["method"]         = method;

    std::vector<uint8_t> xor_key;
    if (!key_str.empty())
    {
        std::string clean = key_str;
        clean.erase(std::remove(clean.begin(), clean.end(), ' '), clean.end());
        for (size_t i = 0; i + 1 < clean.size(); i += 2)
        {
            try { xor_key.push_back(static_cast<uint8_t>(std::stoul(clean.substr(i, 2), nullptr, 16))); }
            catch (...) {}
        }
    }

    if (method == "auto" && xor_key.empty())
    {
        int best_key = -1;
        int best_valid = 0;

        for (int k = 1; k < 256; ++k)
        {
            int valid_insns = 0;
            ea_t test_end = std::min(section_start + static_cast<ea_t>(256), section_start + static_cast<ea_t>(section_size));

            for (ea_t a = section_start; a < test_end; ++a)
            {
                if (!is_loaded(a)) continue;
                uint8_t orig = get_byte(a);
                uint8_t decoded = orig ^ static_cast<uint8_t>(k);

                if (decoded == 0x48 || decoded == 0x49 || decoded == 0x4C ||
                    decoded == 0x55 || decoded == 0x53 || decoded == 0x56 ||
                    decoded == 0x41 || decoded == 0x89 || decoded == 0x8B ||
                    decoded == 0xE8 || decoded == 0xE9 || decoded == 0xEB ||
                    decoded == 0xC3 || decoded == 0xCC || decoded == 0x90)
                {
                    ++valid_insns;
                }
            }

            if (valid_insns > best_valid)
            {
                best_valid = valid_insns;
                best_key = k;
            }
        }

        if (best_key > 0 && best_valid >= 20)
        {
            xor_key.push_back(static_cast<uint8_t>(best_key));
            method = "xor_single";
            result["detected_key"] = helpers::format_address(static_cast<ea_t>(best_key));
            result["key_confidence"] = best_valid;
        }
        else
        {
            return tool_result_t::error(OBFSTR("Auto-detection failed. Provide an explicit key or method."));
        }
    }
    else if (method == "auto" && !xor_key.empty())
    {
        method = (xor_key.size() == 1) ? "xor_single" : "xor_multi";
    }

    int bytes_patched = 0;
    show_wait_box("HIDECANCEL\nAiDA: Decrypting section (0x%zX bytes)...", section_size);

    if (method == "xor_single" || method == "xor_multi")
    {
        for (size_t i = 0; i < section_size; ++i)
        {
            ea_t cur_ea = section_start + i;
            if (!is_loaded(cur_ea)) continue;

            if (i % 0x10000 == 0)
                replace_wait_box("HIDECANCEL\nAiDA: Decrypting 0x%zX / 0x%zX...", i, section_size);

            uint8_t orig = get_byte(cur_ea);
            uint8_t key_byte = xor_key[i % xor_key.size()];
            uint8_t decrypted = orig ^ key_byte;

            if (decrypted != orig)
            {
                patch_byte(cur_ea, decrypted);
                ++bytes_patched;
            }
        }
    }
    else if (method == "xor_rolling")
    {
        uint8_t rolling = xor_key.empty() ? 0 : xor_key[0];
        for (size_t i = 0; i < section_size; ++i)
        {
            ea_t cur_ea = section_start + i;
            if (!is_loaded(cur_ea)) continue;

            uint8_t orig = get_byte(cur_ea);
            uint8_t decrypted = orig ^ rolling;
            rolling = orig;

            if (decrypted != orig)
            {
                patch_byte(cur_ea, decrypted);
                ++bytes_patched;
            }
        }
    }

    hide_wait_box();

    int insns_created = 0;
    if (create_code && (seg->perm & SEGPERM_EXEC))
    {
        show_wait_box("HIDECANCEL\nAiDA: Re-analyzing decrypted code...");

        del_items(section_start, DELIT_SIMPLE, static_cast<asize_t>(section_size));

        ea_t cur = section_start;
        ea_t code_end = section_start + static_cast<ea_t>(section_size);
        while (cur < code_end && cur != BADADDR)
        {
            int len = create_insn(cur);
            if (len > 0)
            {
                ++insns_created;
                cur += len;
            }
            else
            {
                cur = next_addr(cur);
                if (cur == BADADDR) break;
            }
        }

        auto_mark_range(section_start, code_end, AU_CODE);
        auto_mark_range(section_start, code_end, AU_FINAL);

        hide_wait_box();
    }

    result["bytes_patched"]      = bytes_patched;
    result["instructions_created"] = insns_created;
    result["method_used"]        = method;
    if (!xor_key.empty())
    {
        std::ostringstream ks;
        for (size_t i = 0; i < xor_key.size(); ++i)
        {
            if (i > 0) ks << " ";
            ks << std::hex << std::setw(2) << std::setfill('0') << (int)xor_key[i];
        }
        result["key_used"] = ks.str();
    }

    return tool_result_t::ok(OBFSTR("Section unpacked: ") + std::to_string(bytes_patched) +
                             " bytes decrypted, " + std::to_string(insns_created) + " instructions created", result);
}

tool_result_t full_deobfuscation_pass(const json& params)
{
    auto addr = helpers::parse_address(params.value("address", std::string()));
    if (!addr)
        return tool_result_t::error(OBFSTR("Invalid address"));

    ea_t ea = *addr;
    func_t* pfn = get_func(ea);
    if (!pfn)
        return tool_result_t::error(OBFSTR("No function at ") + helpers::format_address(ea));

    bool dry_run = params.value("dry_run", false);

    json result;
    result["function"] = helpers::get_name_or_address(pfn->start_ea);
    result["start"]    = helpers::format_address(pfn->start_ea);
    result["end"]      = helpers::format_address(pfn->end_ea);
    result["original_size"] = pfn->end_ea - pfn->start_ea;

    json steps = json::array();

    show_wait_box("HIDECANCEL\nAiDA: Full deobfuscation pass...");

    replace_wait_box("HIDECANCEL\nAiDA: Step 1/6 - Detecting obfuscation...");
    auto detect_result = analysis_tools::detect_obfuscation_patterns(
        json({{"address", helpers::format_address(ea)}}));
    steps.push_back({{"step", "detect_obfuscation"},
                     {"success", detect_result.success},
                     {"score", detect_result.data.value("obfuscation_score_pct", 0)}});

    int obf_score = detect_result.data.value("obfuscation_score_pct", 0);

    replace_wait_box("HIDECANCEL\nAiDA: Step 2/6 - Resolving opaque predicates...");
    auto opaque_result = resolve_opaque_predicates(
        json({{"address", helpers::format_address(ea)}, {"dry_run", dry_run}}));
    steps.push_back({{"step", "resolve_opaque_predicates"},
                     {"success", opaque_result.success},
                     {"count", opaque_result.data.value("count", 0)}});

    replace_wait_box("HIDECANCEL\nAiDA: Step 3/6 - Removing junk code...");
    auto junk_result = nop_junk_instructions(
        json({{"address", helpers::format_address(ea)},
              {"aggressive", obf_score >= 50}}));
    steps.push_back({{"step", "nop_junk"},
                     {"success", junk_result.success},
                     {"nops_patched", junk_result.data.value("nops_patched", 0)}});

    replace_wait_box("HIDECANCEL\nAiDA: Step 4/6 - Decoding strings...");
    auto strings_result = decode_strings_in_function(
        json({{"address", helpers::format_address(ea)}, {"add_comments", true}}));
    steps.push_back({{"step", "decode_strings"},
                     {"success", strings_result.success},
                     {"strings_found", strings_result.data.value("total_decoded", 0)}});

    replace_wait_box("HIDECANCEL\nAiDA: Step 5/6 - Analyzing control flow...");
    auto cff_result = deobfuscate_control_flow(
        json({{"address", helpers::format_address(ea)}}));
    steps.push_back({{"step", "deobfuscate_cff"},
                     {"success", cff_result.success},
                     {"is_cff", cff_result.data.contains("cff_analysis") ?
                          cff_result.data["cff_analysis"].value("is_control_flow_flattened", false) : false}});

    int total_changes = opaque_result.data.value("count", 0) +
                        junk_result.data.value("nops_patched", 0);
    if (!dry_run && total_changes > 0)
    {
        replace_wait_box("HIDECANCEL\nAiDA: Step 6/6 - Rebuilding function...");
        auto rebuild_result = rebuild_function(
            json({{"address", helpers::format_address(pfn->start_ea)},
                  {"force_recreate", true},
                  {"create_instructions", true}}));
        steps.push_back({{"step", "rebuild_function"},
                         {"success", rebuild_result.success},
                         {"instructions", rebuild_result.data.value("instructions_created", 0)}});
    }
    else
    {
        steps.push_back({{"step", "rebuild_function"},
                         {"success", true},
                         {"note", dry_run ? "Skipped (dry run)" : "Skipped (no patches applied)"}});
    }


    if (!dry_run && total_changes > 0)
        responsive_auto_wait(0, BADADDR, "Applying deobfuscation changes");

    hide_wait_box();

    if (!dry_run)
    {
        pfn = get_func(ea);
        if (pfn)
        {
            std::string pseudo = helpers::get_pseudocode(pfn->start_ea);
            if (!pseudo.empty() && pseudo.find("not available") == std::string::npos)
                result["deobfuscated_pseudocode"] = pseudo;
        }
    }

    result["steps"]         = std::move(steps);
    result["dry_run"]       = dry_run;
    result["total_changes"] = total_changes;

    if (!dry_run && total_changes > 0)
    {
        auto post_detect = analysis_tools::detect_obfuscation_patterns(
            json({{"address", helpers::format_address(ea)}}));
        int post_score = post_detect.data.value("obfuscation_score_pct", 0);
        result["pre_obfuscation_score"]  = obf_score;
        result["post_obfuscation_score"] = post_score;
        result["score_reduction"]        = obf_score - post_score;
    }

    return tool_result_t::ok(OBFSTR("Full deobfuscation pass complete: ") +
                             std::to_string(total_changes) + " changes", result);
}


tool_result_t devirtualize_function(const json& params)
{
    auto addr = helpers::parse_address(params.value("address", std::string()));
    if (!addr)
        return tool_result_t::error(OBFSTR("Invalid address"));

    ea_t ea = *addr;
    func_t* fn = get_func(ea);
    if (!fn)
        return tool_result_t::error(OBFSTR("No function at ") + helpers::format_address(ea));

    std::uint32_t max_handlers = params.value("max_handlers", 256);
    if (max_handlers > 4096) max_handlers = 4096;
    bool add_comments = params.value("add_comments", true);

    json result;
    result["function"] = helpers::format_address(fn->start_ea);
    result["function_size"] = static_cast<std::uint64_t>(fn->size());


    ea_t dispatch_addr = BADADDR;
    ea_t table_addr = BADADDR;
    int table_entry_size = 8;
    int indirect_jumps = 0;
    int cmp_count = 0;
    ea_t last_cmp = BADADDR;

    for (ea_t cur = fn->start_ea; cur < fn->end_ea && cur != BADADDR;)
    {
        insn_t insn;
        int len = decode_insn(&insn, cur);
        if (len <= 0) { cur = next_head(cur, fn->end_ea); if (cur == BADADDR) break; continue; }


        if (insn.itype == NN_cmp)
        {
            if (last_cmp != BADADDR && (cur - last_cmp) < 32) ++cmp_count;
            last_cmp = cur;
        }


        if (insn.itype == NN_jmpni || insn.itype == NN_jmpfi)
        {
            ++indirect_jumps;
            if (dispatch_addr == BADADDR) dispatch_addr = cur;

            for (int op = 0; op < UA_MAXOP; ++op)
            {
                if (insn.ops[op].type == o_displ || insn.ops[op].type == o_phrase)
                {
                    if (insn.ops[op].addr != 0) table_addr = insn.ops[op].addr;
                }
                if (insn.ops[op].type == o_mem)
                    table_addr = insn.ops[op].addr;
            }
        }
        cur += len;
    }

    result["dispatcher_address"]  = dispatch_addr != BADADDR ? helpers::format_address(dispatch_addr) : "not_found";
    result["indirect_jumps"]      = indirect_jumps;
    result["cmp_chain_length"]    = cmp_count;

    int score = 0;
    if (indirect_jumps > 0) score += 25;
    if (cmp_count >= 3) score += 25;
    if (cmp_count >= 8) score += 25;
    if (indirect_jumps > 2) score += 25;
    result["vm_confidence_pct"] = std::min(score, 100);

    if (score < 25)
    {
        result["conclusion"] = OBFSTR("Function does not appear to use VM-based obfuscation.");
        return tool_result_t::ok(OBFSTR("VM confidence too low: ") + std::to_string(score) + "%", result);
    }


    json handlers = json::array();
    if (table_addr != BADADDR)
    {
        result["handler_table"] = helpers::format_address(table_addr);
        bool is_64 = inf_is_64bit();
        table_entry_size = is_64 ? 8 : 4;

        for (std::uint32_t i = 0; i < max_handlers; ++i)
        {
            ea_t slot = table_addr + i * table_entry_size;
            if (!is_loaded(slot)) break;
            ea_t target = is_64 ? static_cast<ea_t>(get_qword(slot)) : get_dword(slot);
            if (target == 0 || target == BADADDR || !is_loaded(target)) break;
            segment_t* ts = getseg(target);
            if (!ts || ts->type != SEG_CODE) break;

            json h;
            h["opcode"] = i;
            h["address"] = helpers::format_address(target);

            qstring nm;
            if (get_name(&nm, target) && !nm.empty()) h["name"] = nm.c_str();


            func_t* hfn = get_func(target);
            ea_t hend = hfn ? hfn->end_ea : target + 64;
            int instr_count = 0;
            bool has_push = false, has_pop = false, has_add = false, has_sub = false;
            bool has_xor = false, has_and = false, has_or = false, has_shr = false, has_shl = false;
            bool has_cmp = false, has_call = false, has_jcc = false;
            bool reads_mem = false, writes_mem = false;

            for (ea_t ic = target; ic < hend && ic != BADADDR && instr_count < 128;)
            {
                insn_t hi;
                int hl = decode_insn(&hi, ic);
                if (hl <= 0) break;
                ++instr_count;
                if (hi.itype == NN_push || hi.itype == NN_pushf) has_push = true;
                if (hi.itype == NN_pop || hi.itype == NN_popf)   has_pop = true;
                if (hi.itype == NN_add || hi.itype == NN_adc)    has_add = true;
                if (hi.itype == NN_sub || hi.itype == NN_sbb)    has_sub = true;
                if (hi.itype == NN_xor)   has_xor = true;
                if (hi.itype == NN_and)    has_and = true;
                if (hi.itype == NN_or)     has_or = true;
                if (hi.itype == NN_shr || hi.itype == NN_sar) has_shr = true;
                if (hi.itype == NN_shl || hi.itype == NN_sal) has_shl = true;
                if (hi.itype == NN_cmp || hi.itype == NN_test) has_cmp = true;
                if (hi.itype == NN_call || hi.itype == NN_callni) has_call = true;
                if (hi.itype >= NN_ja && hi.itype <= NN_jz) has_jcc = true;
                for (int op = 0; op < UA_MAXOP && hi.ops[op].type != o_void; ++op)
                {
                    if (hi.ops[op].type == o_mem || hi.ops[op].type == o_displ || hi.ops[op].type == o_phrase)
                    {
                        if (op == 0) writes_mem = true; else reads_mem = true;
                    }
                }
                ic += hl;
            }

            std::string classification;
            if (has_push && !has_pop && !has_add && !has_sub && !has_xor) classification = "vm_push";
            else if (has_pop && !has_push && !has_add && !has_sub)         classification = "vm_pop";
            else if (has_add && !has_sub)                                   classification = "vm_add";
            else if (has_sub && !has_add)                                   classification = "vm_sub";
            else if (has_xor && !has_and && !has_or)                       classification = "vm_xor";
            else if (has_and)                                               classification = "vm_and";
            else if (has_or)                                                classification = "vm_or";
            else if (has_shr)                                               classification = "vm_shr";
            else if (has_shl)                                               classification = "vm_shl";
            else if (has_cmp && has_jcc)                                    classification = "vm_cmp_jcc";
            else if (has_call)                                              classification = "vm_call";
            else if (reads_mem && !writes_mem)                              classification = "vm_load";
            else if (writes_mem && !reads_mem)                              classification = "vm_store";
            else if (instr_count <= 3)                                      classification = "vm_nop";
            else                                                            classification = "vm_complex";

            h["classification"]  = classification;
            h["instruction_count"] = instr_count;

            if (add_comments)
            {
                std::string cmt = "VM handler " + std::to_string(i) + ": " + classification;
                set_cmt(target, cmt.c_str(), true);
            }

            handlers.push_back(std::move(h));
        }
    }

    result["handler_count"]           = handlers.size();
    result["handlers"]                = std::move(handlers);
    result["handler_table_entry_size"] = table_entry_size;


    json summary;
    std::map<std::string, int> class_counts;
    for (const auto& h : result["handlers"]) class_counts[h["classification"].get<std::string>()]++;
    summary["handler_classifications"] = class_counts;
    summary["has_arithmetic"]          = class_counts.count("vm_add") || class_counts.count("vm_sub");
    summary["has_logic"]               = class_counts.count("vm_xor") || class_counts.count("vm_and") || class_counts.count("vm_or");
    summary["has_memory"]              = class_counts.count("vm_load") || class_counts.count("vm_store") || class_counts.count("vm_push") || class_counts.count("vm_pop");
    summary["has_control_flow"]        = class_counts.count("vm_cmp_jcc") || class_counts.count("vm_call");
    result["summary"] = std::move(summary);

    return tool_result_t::ok(OBFSTR("VM devirtualization: ") + std::to_string(result["handler_count"].get<std::size_t>()) +
                             OBFSTR(" handlers classified"), result);
}

void register_tools()
{
    auto& registry = ToolRegistry::instance();

    registry.register_tool({OBFSTR("nop_junk_instructions"), OBFSTR("deobfuscation"),
        OBFSTR("NOP-out junk instructions in a function: dead code blocks without incoming xrefs, "
               "long NOP sleds, and unreachable code. Uses patch_byte to preserve originals. "
               "Set 'aggressive' to true to remove all unreachable code blocks."),
        {{OBFSTR("address"), OBFSTR("string"), OBFSTR("Function address"), true},
         {OBFSTR("aggressive"), OBFSTR("boolean"), OBFSTR("Aggressively NOP unreachable blocks (default false)"), false},
         {OBFSTR("nop_threshold"), OBFSTR("number"), OBFSTR("Min consecutive NOPs to report as sled (default 3)"), false}},
        nop_junk_instructions, false});

    registry.register_tool({OBFSTR("resolve_opaque_predicates"), OBFSTR("deobfuscation"),
        OBFSTR("Detect and resolve opaque predicates: xor reg,reg + conditional jump patterns. "
               "Converts always-taken branches to unconditional JMP and NOPs never-taken branches. "
               "Set dry_run=true to preview without patching."),
        {{OBFSTR("address"), OBFSTR("string"), OBFSTR("Function address"), true},
         {OBFSTR("dry_run"), OBFSTR("boolean"), OBFSTR("Preview changes without patching (default false)"), false}},
        resolve_opaque_predicates, false});

    registry.register_tool({OBFSTR("patch_anti_debug"), OBFSTR("deobfuscation"),
        OBFSTR("Detect and NOP-out anti-debugging techniques in a function: "
               "IsDebuggerPresent/CheckRemoteDebuggerPresent calls (replaced with xor eax,eax), "
               "NtQueryInformationProcess, INT 2D/INT 3 traps, and RDTSC timing checks."),
        {{OBFSTR("address"), OBFSTR("string"), OBFSTR("Function or start address"), true},
         {OBFSTR("dry_run"), OBFSTR("boolean"), OBFSTR("Preview without patching (default false)"), false},
         {OBFSTR("patch_api_calls"), OBFSTR("boolean"), OBFSTR("Patch anti-debug API calls (default true)"), false},
         {OBFSTR("patch_int_traps"), OBFSTR("boolean"), OBFSTR("Patch INT 2D/INT 3 traps (default true)"), false},
         {OBFSTR("patch_timing"), OBFSTR("boolean"), OBFSTR("Patch RDTSC timing checks (default true)"), false},
         {OBFSTR("size"), OBFSTR("number"), OBFSTR("Scan size if no function found (default 4096)"), false}},
        patch_anti_debug, false});

    registry.register_tool({OBFSTR("decode_strings_in_function"), OBFSTR("deobfuscation"),
        OBFSTR("Decode obfuscated strings in a function: stack-constructed strings (sequential byte MOVs), "
               "multi-byte immediate moves with packed ASCII, and XOR-encrypted data references. "
               "Automatically adds decoded string values as IDA comments."),
        {{OBFSTR("address"), OBFSTR("string"), OBFSTR("Function address"), true},
         {OBFSTR("add_comments"), OBFSTR("boolean"), OBFSTR("Add decoded values as IDA comments (default true)"), false}},
        decode_strings_in_function, false});

    registry.register_tool({OBFSTR("rebuild_function"), OBFSTR("deobfuscation"),
        OBFSTR("Re-analyze function boundaries after deobfuscation patches. "
               "Deletes the existing function, undefines bytes, recreates instructions, "
               "and rebuilds the function with auto-analysis. Use after patching."),
        {{OBFSTR("address"), OBFSTR("string"), OBFSTR("Function start address"), true},
         {OBFSTR("force_recreate"), OBFSTR("boolean"), OBFSTR("Delete and fully recreate (default false)"), false},
         {OBFSTR("create_instructions"), OBFSTR("boolean"), OBFSTR("Create instructions during rebuild (default true)"), false}},
        rebuild_function, false});

    registry.register_tool({OBFSTR("identify_protector"), OBFSTR("deobfuscation"),
        OBFSTR("Identify protection/packing schemes: VMProtect, Themida/WinLicense, UPX, ASPack, "
               "Enigma, PECompact, etc. Scans section names, byte signatures at entry point, "
               "string references, and calculates section entropy to detect packed/encrypted regions."),
        {{OBFSTR("scan_size"), OBFSTR("number"), OBFSTR("Bytes to scan (default 1MB, max 16MB)"), false}},
        identify_protector});

    registry.register_tool({OBFSTR("deobfuscate_control_flow"), OBFSTR("deobfuscation"),
        OBFSTR("Detect and map control flow flattening (CFF) in a function. "
               "Identifies: the dispatcher block (dominant back-edge target), "
               "state variable (comparison in dispatcher), state blocks (jump-back-to-dispatcher blocks), "
               "and state transitions. Annotates the structure with IDA comments."),
        {{OBFSTR("address"), OBFSTR("string"), OBFSTR("Function address"), true}},
        deobfuscate_control_flow});

    registry.register_tool({OBFSTR("reconstruct_imports"), OBFSTR("deobfuscation"),
        OBFSTR("Rebuild import table after unpacking. Scans IAT segments (.idata, .rdata) "
               "for pointer entries, resolves them against known imports, and identifies "
               "unresolved call thunks that need manual resolution."),
        {{OBFSTR("address"), OBFSTR("string"), OBFSTR("Base address (default min_ea)"), false},
         {OBFSTR("scan_size"), OBFSTR("number"), OBFSTR("Scan range in bytes (default 1MB)"), false}},
        reconstruct_imports, false});

    registry.register_tool({OBFSTR("unpack_section"), OBFSTR("deobfuscation"),
        OBFSTR("Decrypt/unpack a packed section directly in the IDB. Supports: "
               "single-byte XOR (auto-detects key), multi-byte XOR key, and rolling XOR. "
               "After decryption, optionally creates instructions and triggers re-analysis. "
               "Use identify_protector first to find packed sections."),
        {{OBFSTR("address"), OBFSTR("string"), OBFSTR("Section start address"), true},
         {OBFSTR("size"), OBFSTR("number"), OBFSTR("Bytes to decrypt (default: full segment)"), false},
         {OBFSTR("method"), OBFSTR("string"), OBFSTR("Decryption method: auto, xor_single, xor_multi, xor_rolling"), false,
          {OBFSTR("auto"), OBFSTR("xor_single"), OBFSTR("xor_multi"), OBFSTR("xor_rolling")}},
         {OBFSTR("key"), OBFSTR("string"), OBFSTR("XOR key as hex bytes (e.g. '4A' or '4A 5B 6C')"), false},
         {OBFSTR("create_code"), OBFSTR("boolean"), OBFSTR("Create instructions after decrypt (default true)"), false}},
        unpack_section, false});

    registry.register_tool({OBFSTR("full_deobfuscation_pass"), OBFSTR("deobfuscation"),
        OBFSTR("Complete automated deobfuscation pipeline for a function: "
               "(1) Detect obfuscation patterns and compute score, "
               "(2) Resolve opaque predicates, "
               "(3) NOP junk instructions, "
               "(4) Decode hidden strings and add comments, "
               "(5) Analyze control flow flattening, "
               "(6) Rebuild function with re-analysis. "
               "Produces before/after obfuscation scores and deobfuscated pseudocode."),
        {{OBFSTR("address"), OBFSTR("string"), OBFSTR("Function address"), true},
         {OBFSTR("dry_run"), OBFSTR("boolean"), OBFSTR("Preview all steps without patching (default false)"), false}},
        full_deobfuscation_pass, false});

    registry.register_tool({OBFSTR("devirtualize_function"), OBFSTR("deobfuscation"),
        OBFSTR("Analyze a VM-protected function: detect the dispatcher, locate the handler table, "
               "classify each VM handler (push/pop/add/sub/xor/and/or/shr/shl/cmp/call/load/store/nop). "
               "Produces a full handler map with semantic labels. Use on VMProtect/Themida virtualized code."),
        {{OBFSTR("address"), OBFSTR("string"), OBFSTR("Function address"), true},
         {OBFSTR("max_handlers"), OBFSTR("number"), OBFSTR("Max handler table entries (default: 256)"), false},
         {OBFSTR("add_comments"), OBFSTR("boolean"), OBFSTR("Add VM handler labels as IDA comments (default: true)"), false}},
        devirtualize_function});
}

}

static std::string get_current_binary_hash()
{
    return aida_db::AnalysisDB::instance().get_binary_hash();
}

namespace graphrag_tools
{

static bool is_graph_indexed()
{
    std::string hash = get_current_binary_hash();
    if (hash.empty()) return false;
    auto& store = graphrag::GraphStore::instance();
    auto stats = store.get_stats(hash);
    return stats.nodes > 0;
}

static tool_result_t not_indexed_error()
{
    return tool_result_t::error(OBFSTR("The binary is not indexed. "
        "The user must click the 'Index Binary' button in the AiDA panel before "
        "RAG tools can be used. Do NOT call any graphrag tools until the binary is indexed."));
}

tool_result_t get_semantic_analysis(const json& params)
{
    if (!is_graph_indexed()) return not_indexed_error();

    std::string addr_str = json_str(params, "address");
    auto addr = helpers::parse_address(addr_str);
    if (!addr) return tool_result_t::error(OBFSTR("Invalid address"));

    std::string hash = get_current_binary_hash();
    if (hash.empty()) return tool_result_t::error(OBFSTR("No binary loaded"));

    auto& store = graphrag::GraphStore::instance();
    graphrag::QueryEngine qe(store);
    json result = qe.get_semantic_analysis(hash, *addr);
    return tool_result_t::ok(OBFSTR("Semantic analysis for ") + addr_str, result);
}

tool_result_t search_semantic(const json& params)
{
    if (!is_graph_indexed()) return not_indexed_error();

    std::string query = json_str(params, "query");
    if (query.empty()) return tool_result_t::error(OBFSTR("Missing query parameter"));

    int limit = 10;
    if (params.contains("limit") && params["limit"].is_number())
        limit = params["limit"].get<int>();

    std::string hash = get_current_binary_hash();
    if (hash.empty()) return tool_result_t::error(OBFSTR("No binary loaded"));

    auto& store = graphrag::GraphStore::instance();
    graphrag::QueryEngine qe(store);
    json result = qe.search_semantic(hash, query, limit);
    return tool_result_t::ok(OBFSTR("Found ") + std::to_string(result.size()) + OBFSTR(" results"), result);
}

tool_result_t get_similar_functions(const json& params)
{
    if (!is_graph_indexed()) return not_indexed_error();

    std::string addr_str = json_str(params, "address");
    auto addr = helpers::parse_address(addr_str);
    if (!addr) return tool_result_t::error(OBFSTR("Invalid address"));

    int limit = 5;
    if (params.contains("limit") && params["limit"].is_number())
        limit = params["limit"].get<int>();

    std::string hash = get_current_binary_hash();
    if (hash.empty()) return tool_result_t::error(OBFSTR("No binary loaded"));

    auto& store = graphrag::GraphStore::instance();
    graphrag::QueryEngine qe(store);
    json result = qe.get_similar_functions(hash, *addr, limit);
    return tool_result_t::ok(OBFSTR("Found ") + std::to_string(result.size()) + OBFSTR(" similar functions"), result);
}

tool_result_t get_call_context(const json& params)
{
    if (!is_graph_indexed()) return not_indexed_error();

    std::string addr_str = json_str(params, "address");
    auto addr = helpers::parse_address(addr_str);
    if (!addr) return tool_result_t::error(OBFSTR("Invalid address"));

    int depth = 2;
    if (params.contains("depth") && params["depth"].is_number())
        depth = params["depth"].get<int>();

    std::string hash = get_current_binary_hash();
    if (hash.empty()) return tool_result_t::error(OBFSTR("No binary loaded"));

    auto& store = graphrag::GraphStore::instance();
    graphrag::QueryEngine qe(store);
    json result = qe.get_call_context(hash, *addr, depth);
    return tool_result_t::ok(OBFSTR("Call context for ") + addr_str, result);
}

tool_result_t get_taint_paths(const json& params)
{
    if (!is_graph_indexed()) return not_indexed_error();

    std::string addr_str = json_str(params, "address");
    auto addr = helpers::parse_address(addr_str);
    if (!addr) return tool_result_t::error(OBFSTR("Invalid address"));

    std::string hash = get_current_binary_hash();
    if (hash.empty()) return tool_result_t::error(OBFSTR("No binary loaded"));

    auto& store = graphrag::GraphStore::instance();
    graphrag::QueryEngine qe(store);
    json result = qe.get_taint_paths(hash, *addr);
    return tool_result_t::ok(OBFSTR("Taint paths for ") + addr_str, result);
}

tool_result_t get_community_info(const json& params)
{
    if (!is_graph_indexed()) return not_indexed_error();

    std::string addr_str = json_str(params, "address");
    auto addr = helpers::parse_address(addr_str);
    if (!addr) return tool_result_t::error(OBFSTR("Invalid address"));

    std::string hash = get_current_binary_hash();
    if (hash.empty()) return tool_result_t::error(OBFSTR("No binary loaded"));

    auto& store = graphrag::GraphStore::instance();
    graphrag::QueryEngine qe(store);
    json result = qe.get_community_info(hash, *addr);
    return tool_result_t::ok(OBFSTR("Community info for ") + addr_str, result);
}

tool_result_t run_security_analysis(const json& params)
{
    if (!is_graph_indexed()) return not_indexed_error();

    std::string hash = get_current_binary_hash();
    if (hash.empty()) return tool_result_t::error(OBFSTR("No binary loaded"));

    graphrag::ensure_full_binary_index(hash, [](int current, int total, const std::string& name) {
        if (current == 1 || (current % 100) == 0 || current == total)
            msg(OBFSTR_C("[AiDA GraphRAG] Preparing full graph %d/%d: %s\n"), current, total, name.c_str());
    });

    auto& store = graphrag::GraphStore::instance();
    auto nodes = store.get_nodes_by_type(hash, graphrag::node_type_t::FUNCTION);

    int risky = 0;
    json high_risk = json::array();
    json crypto_functions = json::array();
    std::map<std::string, int> vuln_type_counts;

    for (auto* n : nodes)
    {
        if (n->risk_level == "HIGH" || n->risk_level == "CRITICAL")
        {
            ++risky;
            if (high_risk.size() < 50)
            {
                high_risk.push_back({
                    {"name", n->name}, {"address", n->address},
                    {"risk_level", n->risk_level}, {"security_flags", n->security_flags}
                });
            }
        }

        if (!n->crypto_apis.empty() && crypto_functions.size() < 50)
        {
            crypto_functions.push_back({
                {"name", n->name}, {"address", n->address},
                {"crypto_apis", n->crypto_apis},
                {"activity_profile", n->activity_profile}
            });
        }

        for (auto& f : n->security_flags)
            if (f.find("_RISK") != std::string::npos)
                ++vuln_type_counts[f];
    }

    json data;
    data["total_functions"] = nodes.size();
    data["high_risk_count"] = risky;
    data["high_risk_functions"] = high_risk;
    data["crypto_functions_count"] = crypto_functions.size();
    data["crypto_functions"] = crypto_functions;
    data["vulnerability_types"] = vuln_type_counts;
    return tool_result_t::ok(OBFSTR("Security analysis: ") + std::to_string(risky)
        + OBFSTR(" high-risk functions, ") + std::to_string(crypto_functions.size())
        + OBFSTR(" crypto routines found"), data);
}

tool_result_t run_taint_analysis(const json& params)
{
    if (!is_graph_indexed()) return not_indexed_error();

    std::string hash = get_current_binary_hash();
    if (hash.empty()) return tool_result_t::error(OBFSTR("No binary loaded"));

    int max_paths = 20;
    if (params.contains("max_paths") && params["max_paths"].is_number())
        max_paths = params["max_paths"].get<int>();

    auto& store = graphrag::GraphStore::instance();
    graphrag::TaintAnalyzer analyzer(store);
    auto paths = analyzer.find_taint_paths(hash, max_paths, true);

    json data = json::array();
    for (auto& p : paths)
    {
        json pj;
        pj["source"] = p.source_name;
        pj["sink"] = p.sink_name;
        pj["path_length"] = p.path.size();
        pj["path"] = p.path_names;
        if (!p.source_apis.empty()) pj["source_apis"] = p.source_apis;
        if (!p.sink_apis.empty()) pj["sink_apis"] = p.sink_apis;
        if (!p.vulnerability_type.empty()) pj["vulnerability_type"] = p.vulnerability_type;
        data.push_back(pj);
    }

    graphrag::save_graph(hash);
    return tool_result_t::ok(OBFSTR("Found ") + std::to_string(paths.size()) + OBFSTR(" taint paths"), data);
}

tool_result_t detect_communities(const json& params)
{
    if (!is_graph_indexed()) return not_indexed_error();

    std::string hash = get_current_binary_hash();
    if (hash.empty()) return tool_result_t::error(OBFSTR("No binary loaded"));

    bool force = false;
    if (params.contains("force") && params["force"].is_boolean())
        force = params["force"].get<bool>();

    auto& store = graphrag::GraphStore::instance();
    graphrag::CommunityDetector detector(store);
    int count = detector.detect(hash, 2, 50, force);

    auto communities = store.get_communities(hash);
    json data = json::array();
    for (auto& c : communities)
    {
        data.push_back({
            {"id", c.id}, {"label", c.label},
            {"purpose", c.purpose}, {"size", c.member_ids.size()}
        });
    }

    graphrag::save_graph(hash);
    return tool_result_t::ok(OBFSTR("Detected ") + std::to_string(count) + OBFSTR(" communities"), data);
}

tool_result_t analyze_network_flow(const json& params)
{
    if (!is_graph_indexed()) return not_indexed_error();

    std::string hash = get_current_binary_hash();
    if (hash.empty()) return tool_result_t::error(OBFSTR("No binary loaded"));

    auto& store = graphrag::GraphStore::instance();
    graphrag::NetworkFlowAnalyzer analyzer(store);
    auto result = analyzer.analyze(hash);

    json data;
    data["send_functions"] = result.send_functions;
    data["recv_functions"] = result.recv_functions;
    data["send_edges_created"] = result.send_edges_created;
    data["recv_edges_created"] = result.recv_edges_created;


    json send_paths = json::array();
    for (auto& fp : result.send_paths)
    {
        json pj;
        pj["source"] = fp.source_name;
        pj["target"] = fp.target_name;
        pj["api"] = fp.api_name;
        pj["hops"] = fp.hop_count;
        pj["path_length"] = fp.path.size();
        send_paths.push_back(pj);
    }
    data["send_paths"] = send_paths;

    json recv_paths = json::array();
    for (auto& fp : result.recv_paths)
    {
        json pj;
        pj["source"] = fp.source_name;
        pj["target"] = fp.target_name;
        pj["api"] = fp.api_name;
        pj["hops"] = fp.hop_count;
        recv_paths.push_back(pj);
    }
    data["recv_paths"] = recv_paths;

    graphrag::save_graph(hash);
    return tool_result_t::ok(OBFSTR("Network flow: ") + std::to_string(result.send_functions.size())
        + OBFSTR(" send, ") + std::to_string(result.recv_functions.size()) + OBFSTR(" recv, ")
        + std::to_string(result.send_paths.size() + result.recv_paths.size()) + OBFSTR(" paths"), data);
}

tool_result_t index_function(const json& params)
{
    std::string addr_str = json_str(params, "address");
    auto addr = helpers::parse_address(addr_str);
    if (!addr) return tool_result_t::error(OBFSTR("Invalid address"));

    std::string hash = get_current_binary_hash();
    if (hash.empty()) return tool_result_t::error(OBFSTR("No binary loaded"));

    auto& store = graphrag::GraphStore::instance();
    graphrag::StructureExtractor extractor(store);
    auto* node = extractor.extract_function(*addr, hash);
    if (!node) return tool_result_t::error(OBFSTR("Failed to extract function"));


    auto& vs = graphrag::get_vector_store();
    std::string text = graphrag::build_embedding_text(*node);

    graphrag::EmbeddingClient ec;
    std::vector<float> vec;
    if (ec.is_available())
        vec = ec.embed_single(text);
    else
    {
        auto& lv = graphrag::get_local_vectorizer();
        if (lv.is_built())
            vec = lv.vectorize(text);
    }

    if (!vec.empty())
        vs.add(node->id, std::move(vec));

    graphrag::save_graph(hash);
    graphrag::save_vectors(hash);

    json data;
    data["function_name"] = node->name;
    data["address"] = node->address;
    data["node_id"] = node->id;
    data["has_embedding"] = vs.has(node->id);
    return tool_result_t::ok(OBFSTR("Indexed function: ") + node->name, data);
}

tool_result_t reindex_all(const json& params)
{
    std::string hash = get_current_binary_hash();
    if (hash.empty()) return tool_result_t::error(OBFSTR("No binary loaded"));

    bool reindexed = false;
    bool ok = graphrag::ensure_full_binary_index(hash, nullptr, &reindexed);
    if (!ok) return tool_result_t::error(OBFSTR("Index failed"));

    graphrag::save_graph(hash);
    graphrag::save_vectors(hash);

    auto& store = graphrag::GraphStore::instance();
    auto stats = store.get_stats(hash);
    auto& vs = graphrag::get_vector_store();

    json data;
    data["nodes"] = stats.nodes;
    data["edges"] = stats.edges;
    data["communities"] = stats.communities;
    data["vector_count"] = vs.size();
    data["reindexed"] = reindexed;
    return tool_result_t::ok(OBFSTR("Reindexed: ") + std::to_string(stats.nodes) + OBFSTR(" nodes, ")
        + std::to_string(vs.size()) + OBFSTR(" vectors"), data);
}

tool_result_t get_graph_stats(const json& params)
{
    std::string hash = get_current_binary_hash();
    if (hash.empty()) return tool_result_t::error(OBFSTR("No binary loaded"));

    auto& store = graphrag::GraphStore::instance();
    auto stats = store.get_stats(hash);
    auto& vs = graphrag::get_vector_store();
    auto& lv = graphrag::get_local_vectorizer();

    json data;
    data["nodes"] = stats.nodes;
    data["edges"] = stats.edges;
    data["communities"] = stats.communities;
    data["stale_nodes"] = stats.stale;
    data["binary_hash"] = hash;
    data["vector_count"] = vs.size();
    data["vector_dimensions"] = vs.dimensions();
    data["vectorizer_ready"] = lv.is_built();
    return tool_result_t::ok(OBFSTR("Graph: ") + std::to_string(stats.nodes) + OBFSTR(" nodes, ")
        + std::to_string(stats.edges) + OBFSTR(" edges, ")
        + std::to_string(vs.size()) + OBFSTR(" vectors"), data);
}

tool_result_t get_security_overview(const json& params)
{
    if (!is_graph_indexed()) return not_indexed_error();

    std::string hash = get_current_binary_hash();
    if (hash.empty()) return tool_result_t::error(OBFSTR("No binary loaded"));

    int limit = 50;
    if (params.contains("limit") && params["limit"].is_number())
        limit = params["limit"].get<int>();

    auto& store = graphrag::GraphStore::instance();
    graphrag::QueryEngine qe(store);
    json data = qe.get_security_analysis(hash, limit);
    return tool_result_t::ok(OBFSTR("Security overview: ") +
        std::to_string(data.value("total_functions", 0)) + OBFSTR(" functions analyzed"), data);
}

tool_result_t get_activity_analysis(const json& params)
{
    if (!is_graph_indexed()) return not_indexed_error();

    std::string hash = get_current_binary_hash();
    if (hash.empty()) return tool_result_t::error(OBFSTR("No binary loaded"));

    std::string filter;
    if (params.contains("activity_type") && params["activity_type"].is_string())
        filter = params["activity_type"].get<std::string>();

    auto& store = graphrag::GraphStore::instance();
    graphrag::QueryEngine qe(store);
    json data = qe.get_activity_analysis(hash, filter);
    return tool_result_t::ok(OBFSTR("Activity analysis complete"), data);
}

tool_result_t get_all_communities(const json& params)
{
    if (!is_graph_indexed()) return not_indexed_error();

    std::string hash = get_current_binary_hash();
    if (hash.empty()) return tool_result_t::error(OBFSTR("No binary loaded"));

    auto& store = graphrag::GraphStore::instance();
    graphrag::QueryEngine qe(store);
    json data = qe.get_all_communities(hash);
    return tool_result_t::ok(OBFSTR("Found ") +
        std::to_string(data.value("total_communities", 0)) + OBFSTR(" communities"), data);
}

void register_tools()
{
    auto& registry = ToolRegistry::instance();

    registry.register_tool({
        OBFSTR("get_semantic_analysis"), OBFSTR("graphrag"),
        OBFSTR("Get comprehensive semantic analysis of a function from the knowledge graph. "
               "Returns the function's summary, security flags, risk level, callers, callees, "
               "community membership, and decompiled code. Use this to understand what a "
               "function does and its relationships in the codebase."),
        {{OBFSTR("address"), OBFSTR("string"), OBFSTR("Function address"), true}},
        get_semantic_analysis, true});

    registry.register_tool({
        OBFSTR("search_semantic"), OBFSTR("graphrag"),
        OBFSTR("Search the knowledge graph using vector embeddings and keyword matching. "
               "Searches across function names, decompiled code, strings, URLs, IPs, domains, "
               "file paths, registry keys, API names, and security flags. MUCH FASTER than "
               "IDA search tools for indexed binaries. Use this FIRST when looking for strings, "
               "API usage, or code patterns in an indexed binary. Falls back to IDA search "
               "tools only if RAG returns no results."),
        {{OBFSTR("query"), OBFSTR("string"), OBFSTR("Search query: string literal, API name, IP, URL, domain, code pattern, or natural language"), true},
         {OBFSTR("limit"), OBFSTR("number"), OBFSTR("Maximum results (default 10)"), false}},
        search_semantic, true});

    registry.register_tool({
        OBFSTR("get_similar_functions"), OBFSTR("graphrag"),
        OBFSTR("Find functions similar to the given one using vector embedding cosine "
               "similarity. Compares function code, names, and security features in embedding "
               "space. Falls back to call-graph structural similarity if embeddings are "
               "unavailable. Useful for finding related functionality or duplicate code."),
        {{OBFSTR("address"), OBFSTR("string"), OBFSTR("Function address"), true},
         {OBFSTR("limit"), OBFSTR("number"), OBFSTR("Maximum results (default 5)"), false}},
        get_similar_functions, true});

    registry.register_tool({
        OBFSTR("get_call_context"), OBFSTR("graphrag"),
        OBFSTR("Get multi-level call context showing callers and callees of a function to "
               "the specified depth. Provides a tree view of the function's position in "
               "the call graph for understanding data flow and control flow."),
        {{OBFSTR("address"), OBFSTR("string"), OBFSTR("Function address"), true},
         {OBFSTR("depth"), OBFSTR("number"), OBFSTR("Depth of caller/callee tree (default 2)"), false}},
        get_call_context, true});

    registry.register_tool({
        OBFSTR("get_taint_paths_for_function"), OBFSTR("graphrag"),
        OBFSTR("Get taint analysis paths involving the specified function. Shows data flow "
               "from untrusted sources (recv, read, scanf) to dangerous sinks (strcpy, system, "
               "CreateProcess). Identifies potential vulnerability chains."),
        {{OBFSTR("address"), OBFSTR("string"), OBFSTR("Function address"), true}},
        get_taint_paths, true});

    registry.register_tool({
        OBFSTR("get_community_info"), OBFSTR("graphrag"),
        OBFSTR("Get information about the functional community (cluster) a function belongs to. "
               "Shows community purpose (network, crypto, file_io, etc.), all member functions, "
               "and the community label."),
        {{OBFSTR("address"), OBFSTR("string"), OBFSTR("Function address"), true}},
        get_community_info, true});

    registry.register_tool({
        OBFSTR("run_security_analysis"), OBFSTR("graphrag"),
        OBFSTR("Run security analysis across the entire knowledge graph. Identifies high-risk "
               "functions with dangerous API usage, buffer overflow risks, command injection "
               "vectors, and other vulnerabilities. Returns the riskiest functions."),
        {},
        run_security_analysis, true});

    registry.register_tool({
        OBFSTR("run_taint_analysis"), OBFSTR("graphrag"),
        OBFSTR("Run taint analysis to find data flow paths from untrusted input sources to "
               "dangerous sinks. Discovers potential vulnerability chains where user-controlled "
               "data reaches unsafe operations like strcpy, system, or CreateProcess."),
        {{OBFSTR("max_paths"), OBFSTR("number"), OBFSTR("Maximum taint paths to find (default 20)"), false}},
        run_taint_analysis, false});

    registry.register_tool({
        OBFSTR("detect_communities"), OBFSTR("graphrag"),
        OBFSTR("Detect functional communities (clusters) in the call graph using Label Propagation. "
               "Groups related functions by their calling patterns and infers the purpose of each "
               "community (network, crypto, file_io, process, init, gui, etc.)."),
        {{OBFSTR("force"), OBFSTR("boolean"), OBFSTR("Force re-detection even if communities exist (default false)"), false}},
        detect_communities, false});

    registry.register_tool({
        OBFSTR("analyze_network_flow"), OBFSTR("graphrag"),
        OBFSTR("Analyze network data flow patterns in the binary. Identifies functions that "
               "send and receive network data, creates flow edges, and maps the network "
               "communication architecture of the binary."),
        {},
        analyze_network_flow, false});

    registry.register_tool({
        OBFSTR("get_graph_stats"), OBFSTR("graphrag"),
        OBFSTR("Get statistics about the knowledge graph: total nodes, edges, communities, "
               "stale node count, and vector embedding count. Use to check index status."),
        {},
        get_graph_stats, true});

    registry.register_tool({
        OBFSTR("get_security_overview"), OBFSTR("graphrag"),
        OBFSTR("Get a comprehensive security overview of the entire binary from the knowledge "
               "graph. Returns risk distribution (critical/high/medium/low counts), security "
               "flag distribution across all functions, and the most dangerous functions with "
               "their specific vulnerabilities and activity profiles."),
        {{OBFSTR("limit"), OBFSTR("number"), OBFSTR("Maximum high-risk functions to return (default 50)"), false}},
        get_security_overview, true});

    registry.register_tool({
        OBFSTR("get_activity_analysis"), OBFSTR("graphrag"),
        OBFSTR("Analyze activity profiles of functions in the binary. Groups functions by "
               "their behavior: NETWORK_CLIENT, NETWORK_SERVER, FILE_RW, FILE_READER, "
               "FILE_WRITER, CRYPTO_CIPHER, CRYPTO_ENCRYPT, CRYPTO_DECRYPT, CRYPTO_HASH, "
               "PROCESS_INJECTOR, PROCESS_SPAWNER. Optionally filter to one activity type."),
        {{OBFSTR("activity_type"), OBFSTR("string"), OBFSTR("Optional: filter to specific activity type (e.g. 'NETWORK_CLIENT')"), false}},
        get_activity_analysis, true});

    registry.register_tool({
        OBFSTR("get_all_communities"), OBFSTR("graphrag"),
        OBFSTR("List all detected functional communities (clusters) in the binary. Returns "
               "each community's ID, label, detected purpose (network/crypto/file_io/process/"
               "registry/init/gui/etc.), member count, and member function details."),
        {},
        get_all_communities, true});
}

}


namespace aida_ida_batch_tools
{

static auto g_start_time = std::chrono::steady_clock::now();

static std::string trim_copy(std::string s)
{
    while (!s.empty() && std::isspace(static_cast<unsigned char>(s.front())))
        s.erase(s.begin());
    while (!s.empty() && std::isspace(static_cast<unsigned char>(s.back())))
        s.pop_back();
    return s;
}

static std::string value_to_string(const json& v)
{
    if (v.is_string())
        return v.get<std::string>();
    if (v.is_number_integer())
    {
        int64_t signed_value = v.get<int64_t>();
        if (signed_value < 0)
            return std::to_string(signed_value);
        std::ostringstream ss;
        ss << "0x" << std::hex << std::uppercase << static_cast<uint64_t>(signed_value);
        return ss.str();
    }
    if (v.is_number())
        return std::to_string(v.get<double>());
    return "";
}

static json normalize_list(const json& value)
{
    if (value.is_array())
        return value;
    if (value.is_object())
        return json::array({value});
    if (value.is_string())
    {
        std::string s = trim_copy(value.get<std::string>());
        if (!s.empty() && (s.front() == '[' || s.front() == '{'))
        {
            try
            {
                json parsed = json::parse(s);
                if (parsed.is_array())
                    return parsed;
                if (parsed.is_object())
                    return json::array({parsed});
            }
            catch (...) {}
        }
        json arr = json::array();
        std::istringstream iss(s);
        std::string part;
        while (std::getline(iss, part, ','))
        {
            part = trim_copy(part);
            if (!part.empty())
                arr.push_back(part);
        }
        if (arr.empty() && !s.empty())
            arr.push_back(s);
        return arr;
    }
    if (!value.is_null())
        return json::array({value});
    return json::array();
}

static json get_list_param(const json& params, const char* name, const char* alt = nullptr)
{
    if (params.contains(name))
        return normalize_list(params[name]);
    if (alt && params.contains(alt))
        return normalize_list(params[alt]);
    return json::array();
}

static std::string first_string_field(const json& item, std::initializer_list<const char*> names)
{
    if (!item.is_object())
        return value_to_string(item);
    for (const char* name : names)
    {
        if (item.contains(name))
            return value_to_string(item[name]);
    }
    return "";
}

static json make_page_params(const json& q, int default_limit)
{
    json p = json::object();
    p["offset"] = 0;
    p["limit"] = default_limit;
    if (q.is_object())
    {
        if (q.contains("offset")) p["offset"] = q["offset"];
        if (q.contains("limit")) p["limit"] = q["limit"];
        if (q.contains("count")) p["limit"] = q["count"];
        if (q.contains("filter")) p["filter"] = q["filter"];
        if (q.contains("name")) p["filter"] = q["name"];
        if (q.contains("pattern")) p["filter"] = q["pattern"];
        return p;
    }
    if (q.is_string())
    {
        std::string s = trim_copy(q.get<std::string>());
        if (!s.empty() && s != "*")
            p["filter"] = s;
    }
    return p;
}

static bool parse_int_type(const std::string& text, int& bytes, bool& sign, bool& big_endian, std::string& normalized)
{
    std::string s = text;
    std::transform(s.begin(), s.end(), s.begin(), [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    if (s.empty())
        s = "u64le";
    if (s == "byte") s = "u8le";
    if (s == "word") s = "u16le";
    if (s == "dword") s = "u32le";
    if (s == "qword") s = "u64le";
    if (s.size() < 2)
        return false;
    sign = s[0] == 'i';
    if (s[0] != 'i' && s[0] != 'u')
        return false;
    size_t pos = 1;
    int bits = 0;
    while (pos < s.size() && std::isdigit(static_cast<unsigned char>(s[pos])))
    {
        bits = bits * 10 + (s[pos] - '0');
        pos++;
    }
    if (bits != 8 && bits != 16 && bits != 32 && bits != 64)
        return false;
    std::string endian = s.substr(pos);
    if (endian.empty())
        endian = "le";
    if (endian != "le" && endian != "be")
        return false;
    bytes = bits / 8;
    big_endian = endian == "be";
    normalized = std::string(sign ? "i" : "u") + std::to_string(bits) + endian;
    return true;
}

static uint64_t read_raw_uint(ea_t ea, int bytes, bool big_endian)
{
    uint64_t value = 0;
    for (int i = 0; i < bytes; i++)
    {
        uint8_t b = static_cast<uint8_t>(get_byte(ea + i));
        if (big_endian)
            value = (value << 8) | b;
        else
            value |= static_cast<uint64_t>(b) << (i * 8);
    }
    return value;
}

static int64_t sign_extend_value(uint64_t value, int bytes)
{
    int bits = bytes * 8;
    if (bits >= 64)
        return static_cast<int64_t>(value);
    uint64_t mask = 1ULL << (bits - 1);
    uint64_t full = (1ULL << bits) - 1;
    value &= full;
    if ((value & mask) != 0)
        value |= ~full;
    return static_cast<int64_t>(value);
}

static std::string bytes_to_hex(uint64_t value, int bytes, bool big_endian)
{
    std::ostringstream ss;
    for (int i = 0; i < bytes; i++)
    {
        int index = big_endian ? (bytes - 1 - i) : i;
        if (i > 0)
            ss << " ";
        ss << std::hex << std::uppercase << std::setw(2) << std::setfill('0')
           << ((value >> (index * 8)) & 0xFF);
    }
    return ss.str();
}

static tool_result_t server_health(const json&)
{
    json data;
    qstring procname = inf_get_procname();
    auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(std::chrono::steady_clock::now() - g_start_time).count();
    data["status"] = "ok";
    data["server"] = "aida-ida-mcp";
    data["server_family"] = "aida-ida-mcp";
    data["processor"] = procname.c_str();
    data["bitness"] = inf_get_app_bitness();
    data["is_64bit"] = inf_is_64bit();
    data["auto_analysis_complete"] = auto_is_ok();
    data["hexrays_available"] = init_hexrays_plugin();
    data["uptime_seconds"] = elapsed;
    data["function_count"] = (size_t)get_func_qty();
    data["segment_count"] = get_segm_qty();
    return tool_result_t::ok(OBFSTR("IDA server is healthy"), data);
}

static tool_result_t server_warmup(const json& params)
{
    bool wait_analysis = params.value("wait_auto_analysis", params.value("wait", true));
    bool init_hexrays = params.value("init_hexrays", true);
    json data;
    if (wait_analysis)
        auto_wait_range(0, BADADDR);
    data["auto_analysis_complete"] = auto_is_ok();
    data["hexrays_available"] = init_hexrays ? init_hexrays_plugin() : false;
    data["function_count"] = (size_t)get_func_qty();
    return tool_result_t::ok(OBFSTR("IDA warmup complete"), data);
}

static tool_result_t decompile(const json& params)
{
    json p;
    if (params.contains("addr"))
        p["address"] = params["addr"];
    else
        p["address"] = params.value("address", "");
    return function_tools::decompile_function(p);
}

static tool_result_t disasm(const json& params)
{
    json p;
    if (params.contains("addr"))
        p["address"] = params["addr"];
    else
        p["address"] = params.value("address", "");
    return function_tools::disassemble_function(p);
}

static tool_result_t list_funcs(const json& params)
{
    return function_tools::list_functions(make_page_params(params.contains("query") ? params["query"] : params, 100));
}

static tool_result_t lookup_funcs(const json& params)
{
    json queries = get_list_param(params, "queries", "addrs");
    if (queries.empty() && params.contains("addr"))
        queries = json::array({params["addr"]});
    json out = json::array();
    for (const auto& q : queries)
    {
        json p;
        p["address"] = first_string_field(q, {"addr", "address", "name", "query"});
        auto r = function_tools::get_function(p);
        if (r.success)
            out.push_back(r.data);
        else
            out.push_back({{"query", p["address"]}, {"error", r.output}});
    }
    return tool_result_t::ok(OBFSTR("Function lookup complete"), out);
}

static tool_result_t func_query(const json& params)
{
    json queries = get_list_param(params, "queries", "query");
    if (queries.empty())
        queries.push_back(params);
    json results = json::array();
    for (const auto& q : queries)
    {
        json page = make_page_params(q, 100);
        auto r = function_tools::list_functions(page);
        if (r.success)
            results.push_back(r.data);
        else
            results.push_back({{"error", r.output}});
    }
    return tool_result_t::ok(OBFSTR("Function query complete"), results);
}

static tool_result_t imports(const json& params)
{
    json p;
    p["offset"] = params.value("offset", 0);
    p["limit"] = params.value("count", params.value("limit", 200));
    if (params.contains("filter"))
        p["filter"] = params["filter"];
    return import_tools::list_imports(p);
}

static tool_result_t imports_query(const json& params)
{
    json queries = get_list_param(params, "queries", "query");
    if (queries.empty())
        queries.push_back(params);
    json results = json::array();
    for (const auto& q : queries)
    {
        auto r = import_tools::list_imports(make_page_params(q, 200));
        results.push_back(r.success ? r.data : json{{"error", r.output}});
    }
    return tool_result_t::ok(OBFSTR("Import query complete"), results);
}

static tool_result_t list_globals_batch(const json& params)
{
    if (!params.contains("queries") && !params.contains("query"))
        return memory_tools::list_globals(params);
    json queries = get_list_param(params, "queries", "query");
    json results = json::array();
    for (const auto& q : queries)
    {
        auto r = memory_tools::list_globals(make_page_params(q, 100));
        results.push_back(r.success ? r.data : json{{"error", r.output}});
    }
    return tool_result_t::ok(OBFSTR("Global query complete"), results);
}

static tool_result_t entity_query(const json& params)
{
    json queries = get_list_param(params, "queries", "query");
    if (queries.empty())
        queries.push_back(params);
    json results = json::array();
    for (const auto& q : queries)
    {
        std::string kind = q.is_object() ? q.value("kind", q.value("type", "functions")) : "functions";
        std::transform(kind.begin(), kind.end(), kind.begin(), [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
        if (kind == "function" || kind == "functions" || kind == "func")
        {
            auto r = function_tools::list_functions(make_page_params(q, 100));
            results.push_back(r.success ? r.data : json{{"kind", kind}, {"error", r.output}});
        }
        else if (kind == "global" || kind == "globals" || kind == "data")
        {
            auto r = memory_tools::list_globals(make_page_params(q, 100));
            results.push_back(r.success ? r.data : json{{"kind", kind}, {"error", r.output}});
        }
        else if (kind == "import" || kind == "imports")
        {
            auto r = import_tools::list_imports(make_page_params(q, 200));
            results.push_back(r.success ? r.data : json{{"kind", kind}, {"error", r.output}});
        }
        else
        {
            results.push_back({{"kind", kind}, {"error", "Unsupported entity kind in static IDA plugin scope"}});
        }
    }
    return tool_result_t::ok(OBFSTR("Entity query complete"), results);
}

static tool_result_t xrefs_to(const json& params)
{
    json p;
    p["address"] = params.contains("addrs") ? params["addrs"] : params.value("addr", params.value("address", json()));
    p["limit"] = params.value("limit", params.value("count", 100));
    return function_tools::get_xrefs_to(p);
}

static tool_result_t xref_query(const json& params)
{
    json queries = get_list_param(params, "queries", "query");
    if (queries.empty())
        queries.push_back(params);
    json results = json::array();
    for (const auto& q : queries)
    {
        json p;
        p["address"] = first_string_field(q, {"addr", "address", "ea"});
        p["limit"] = q.is_object() ? q.value("limit", q.value("count", 100)) : 100;
        std::string direction = q.is_object() ? q.value("direction", q.value("dir", "to")) : "to";
        auto r = (direction == "from" || direction == "out" || direction == "outgoing")
            ? function_tools::get_xrefs_from(p)
            : function_tools::get_xrefs_to(p);
        results.push_back(r.success ? r.data : json{{"addr", p["address"]}, {"error", r.output}});
    }
    return tool_result_t::ok(OBFSTR("Xref query complete"), results);
}

static tool_result_t callees(const json& params)
{
    json addrs = get_list_param(params, "addrs", "addr");
    json results = json::array();
    for (const auto& a : addrs)
    {
        std::string addr = value_to_string(a);
        auto ea_opt = helpers::parse_address(addr);
        json item;
        item["addr"] = addr;
        item["callees"] = json::array();
        if (!ea_opt)
        {
            item["error"] = "Invalid address";
            results.push_back(item);
            continue;
        }
        func_t* pfn = get_func(*ea_opt);
        if (!pfn)
        {
            item["error"] = "No function at address";
            results.push_back(item);
            continue;
        }
        std::set<ea_t> seen;
        func_item_iterator_t fii;
        for (bool ok = fii.set(pfn); ok; ok = fii.next_addr())
        {
            xrefblk_t xb;
            for (bool xok = xb.first_from(fii.current(), XREF_ALL); xok; xok = xb.next_from())
            {
                if (!xb.iscode || (xb.type != fl_CN && xb.type != fl_CF))
                    continue;
                func_t* callee = get_func(xb.to);
                if (!callee || !seen.insert(callee->start_ea).second)
                    continue;
                qstring name;
                get_func_name(&name, callee->start_ea);
                item["callees"].push_back({{"addr", helpers::format_address(callee->start_ea)}, {"name", name.c_str()}});
            }
        }
        results.push_back(item);
    }
    return tool_result_t::ok(OBFSTR("Callees retrieved"), results);
}

static tool_result_t basic_blocks(const json& params)
{
    json addrs = get_list_param(params, "addrs", "addr");
    json results = json::array();
    for (const auto& a : addrs)
    {
        json p;
        p["address"] = value_to_string(a);
        auto r = function_tools::get_basic_blocks(p);
        results.push_back(r.success ? json{{"addr", p["address"]}, {"blocks", r.data}} : json{{"addr", p["address"]}, {"error", r.output}});
    }
    return tool_result_t::ok(OBFSTR("Basic blocks retrieved"), results);
}

static tool_result_t get_bytes_batch(const json& params)
{
    json regions = get_list_param(params, "regions", "items");
    json results = json::array();
    for (const auto& q : regions)
    {
        json p;
        if (q.is_string())
        {
            std::string s = q.get<std::string>();
            size_t colon = s.find(':');
            p["address"] = colon == std::string::npos ? s : s.substr(0, colon);
            p["size"] = colon == std::string::npos ? 16 : std::stoull(s.substr(colon + 1), nullptr, 0);
        }
        else
        {
            p["address"] = first_string_field(q, {"addr", "address"});
            p["size"] = q.value("size", q.value("count", 16));
        }
        auto r = memory_tools::read_bytes(p);
        results.push_back(r.success ? json{{"addr", p["address"]}, {"data", r.data.value("hex", "")}, {"bytes", r.data.value("bytes", json::array())}} : json{{"addr", p["address"]}, {"data", nullptr}, {"error", r.output}});
    }
    return tool_result_t::ok(OBFSTR("Bytes read"), results);
}

static tool_result_t get_int(const json& params)
{
    json queries = get_list_param(params, "queries", "items");
    json results = json::array();
    for (const auto& q : queries)
    {
        std::string addr = first_string_field(q, {"addr", "address"});
        std::string ty = q.is_object() ? q.value("ty", q.value("type", "u64le")) : "u64le";
        int bytes = 0;
        bool sign = false;
        bool be = false;
        std::string norm;
        auto ea_opt = helpers::parse_address(addr);
        if (!ea_opt || !parse_int_type(ty, bytes, sign, be, norm))
        {
            results.push_back({{"addr", addr}, {"ty", ty}, {"value", nullptr}, {"error", "Invalid address or integer type"}});
            continue;
        }
        if (!is_loaded(*ea_opt))
        {
            results.push_back({{"addr", addr}, {"ty", norm}, {"value", nullptr}, {"error", "Address not mapped in database"}});
            continue;
        }
        uint64_t raw = read_raw_uint(*ea_opt, bytes, be);
        results.push_back({{"addr", addr}, {"ty", norm}, {"value", sign ? json(sign_extend_value(raw, bytes)) : json(raw)}});
    }
    return tool_result_t::ok(OBFSTR("Integer read"), results);
}

static tool_result_t get_string(const json& params)
{
    json addrs = get_list_param(params, "addrs", "addr");
    json results = json::array();
    for (const auto& a : addrs)
    {
        json p;
        p["address"] = value_to_string(a);
        auto r = memory_tools::read_string(p);
        results.push_back(r.success ? json{{"addr", p["address"]}, {"value", r.data.value("value", "")}} : json{{"addr", p["address"]}, {"value", nullptr}, {"error", r.output}});
    }
    return tool_result_t::ok(OBFSTR("Strings read"), results);
}

static tool_result_t get_global_value(const json& params)
{
    json queries = get_list_param(params, "queries", "names");
    if (queries.empty() && params.contains("name"))
        queries.push_back(params["name"]);
    json results = json::array();
    for (const auto& q : queries)
    {
        std::string query = value_to_string(q);
        json p;
        p["name"] = query;
        auto r = memory_tools::read_global(p);
        if (!r.success)
            results.push_back({{"query", query}, {"value", nullptr}, {"error", r.output}});
        else if (r.data.contains("hex"))
            results.push_back({{"query", query}, {"value", r.data["hex"]}});
        else if (r.data.contains("value"))
            results.push_back({{"query", query}, {"value", r.data["value"]}});
        else
            results.push_back({{"query", query}, {"value", r.data.dump()}});
    }
    return tool_result_t::ok(OBFSTR("Global values read"), results);
}

static tool_result_t patch(const json& params)
{
    json patches = get_list_param(params, "patches", "items");
    json results = json::array();
    for (const auto& item : patches)
    {
        json p;
        p["address"] = first_string_field(item, {"addr", "address"});
        p["bytes"] = item.value("data", item.value("bytes", ""));
        auto r = memory_tools::patch_bytes(p);
        results.push_back(r.success ? json{{"addr", p["address"]}, {"size", r.data.value("size", 0)}} : json{{"addr", p["address"]}, {"size", 0}, {"error", r.output}});
    }
    return tool_result_t::ok(OBFSTR("Patch requests processed"), results);
}

static tool_result_t patch_asm(const json& params)
{
    json items = get_list_param(params, "items", "patches");
    if (items.empty() && params.contains("asm"))
        items.push_back(params);
    json results = json::array();
    for (const auto& item : items)
    {
        std::string addr = first_string_field(item, {"addr", "address"});
        std::string asm_text = item.value("asm", item.value("assembly", ""));
        auto ea_opt = helpers::parse_address(addr);
        if (!ea_opt || asm_text.empty())
        {
            results.push_back({{"addr", addr}, {"error", "Address and assembly are required"}});
            continue;
        }
        uchar bytes[64] = {};
        ssize_t n = processor_t::assemble(bytes, *ea_opt, 0, *ea_opt, inf_is_32bit_or_higher(), asm_text.c_str());
        if (n <= 0)
        {
            results.push_back({{"addr", addr}, {"asm", asm_text}, {"error", "Assembly failed"}});
            continue;
        }
        std::ostringstream hex;
        for (ssize_t i = 0; i < n; ++i)
        {
            if (i > 0)
                hex << " ";
            hex << std::hex << std::uppercase << std::setw(2) << std::setfill('0') << static_cast<int>(bytes[i]);
        }
        auto r = memory_tools::patch_bytes({{"address", addr}, {"bytes", hex.str()}});
        results.push_back(r.success ? json{{"addr", addr}, {"asm", asm_text}, {"bytes", hex.str()}} : json{{"addr", addr}, {"asm", asm_text}, {"error", r.output}});
    }
    return tool_result_t::ok(OBFSTR("Assembly patch requests processed"), results);
}

static tool_result_t put_int(const json& params)
{
    json items = get_list_param(params, "items", "queries");
    json results = json::array();
    for (const auto& item : items)
    {
        std::string addr = first_string_field(item, {"addr", "address"});
        std::string ty = item.value("ty", item.value("type", "u32le"));
        std::string value_text = value_to_string(item.contains("value") ? item["value"] : json());
        int bytes = 0;
        bool sign = false;
        bool be = false;
        std::string norm;
        if (!parse_int_type(ty, bytes, sign, be, norm))
        {
            results.push_back({{"addr", addr}, {"ty", ty}, {"value", value_text}, {"error", "Invalid integer type"}});
            continue;
        }
        uint64_t parsed = 0;
        try
        {
            if (!sign && !value_text.empty() && value_text[0] == '-')
                throw std::invalid_argument("negative unsigned integer");
            parsed = sign ? static_cast<uint64_t>(std::stoll(value_text, nullptr, 0)) : std::stoull(value_text, nullptr, 0);
        }
        catch (...)
        {
            results.push_back({{"addr", addr}, {"ty", norm}, {"value", value_text}, {"error", "Invalid integer value"}});
            continue;
        }
        json p;
        p["address"] = addr;
        p["bytes"] = bytes_to_hex(parsed, bytes, be);
        auto r = memory_tools::patch_bytes(p);
        results.push_back(r.success ? json{{"addr", addr}, {"ty", norm}, {"value", value_text}} : json{{"addr", addr}, {"ty", norm}, {"value", value_text}, {"error", r.output}});
    }
    return tool_result_t::ok(OBFSTR("Integer writes processed"), results);
}

static tool_result_t set_comments(const json& params)
{
    json items = get_list_param(params, "items", "comments");
    json results = json::array();
    for (const auto& item : items)
    {
        json p;
        p["address"] = first_string_field(item, {"addr", "address"});
        p["comment"] = item.value("comment", "");
        auto r = comment_tools::set_comment(p);
        if (r.success)
            navigation_tools::set_decompiler_comment(p);
        results.push_back(r.success ? json{{"addr", p["address"]}} : json{{"addr", p["address"]}, {"error", r.output}});
    }
    return tool_result_t::ok(OBFSTR("Comments processed"), results);
}

static tool_result_t append_comments(const json& params)
{
    json items = get_list_param(params, "items", "comments");
    json results = json::array();
    for (const auto& item : items)
    {
        std::string addr = first_string_field(item, {"addr", "address"});
        std::string text = item.value("comment", "");
        bool dedupe = item.value("dedupe", true);
        auto ea_opt = helpers::parse_address(addr);
        if (!ea_opt)
        {
            results.push_back({{"addr", addr}, {"error", "Invalid address"}});
            continue;
        }
        qstring current_q;
        get_cmt(&current_q, *ea_opt, false);
        std::string current = current_q.c_str();
        bool skipped = false;
        if (dedupe && !text.empty())
        {
            std::istringstream iss(current);
            std::string line;
            while (std::getline(iss, line))
            {
                if (trim_copy(line) == trim_copy(text))
                {
                    skipped = true;
                    break;
                }
            }
        }
        if (skipped)
        {
            results.push_back({{"addr", addr}, {"skipped", true}});
            continue;
        }
        std::string combined = current.empty() ? text : current + "\n" + text;
        json p;
        p["address"] = addr;
        p["comment"] = combined;
        auto r = comment_tools::set_comment(p);
        results.push_back(r.success ? json{{"addr", addr}, {"appended", true}} : json{{"addr", addr}, {"error", r.output}});
    }
    return tool_result_t::ok(OBFSTR("Append comments processed"), results);
}

static tool_result_t rename(const json& params)
{
    json result;
    int total = 0;
    int ok = 0;
    int failed = 0;
    auto handle_array = [&](const char* key, auto fn) {
        json arr = get_list_param(params, key);
        json out = json::array();
        for (const auto& item : arr)
        {
            total++;
            json r = fn(item);
            if (r.contains("error")) failed++; else ok++;
            out.push_back(r);
        }
        if (!arr.empty())
            result[key] = out;
    };
    handle_array("func", [](const json& item) {
        json p;
        p["address"] = first_string_field(item, {"addr", "func_addr", "func"});
        p["new_name"] = item.value("name", item.value("new", item.value("new_name", "")));
        auto r = function_tools::rename_function(p);
        return r.success ? json{{"addr", p["address"]}, {"name", p["new_name"]}} : json{{"addr", p["address"]}, {"name", p["new_name"]}, {"error", r.output}};
    });
    handle_array("data", [](const json& item) {
        std::string addr = first_string_field(item, {"addr", "address"});
        std::string name = item.value("name", item.value("new", item.value("new_name", "")));
        auto ea_opt = helpers::parse_address(addr.empty() ? item.value("old", "") : addr);
        if (!ea_opt || name.empty())
            return json{{"addr", addr}, {"name", name}, {"error", "Data rename requires addr/name"}};
        if (!set_name(*ea_opt, name.c_str(), SN_CHECK | SN_NODUMMY))
            return json{{"addr", helpers::format_address(*ea_opt)}, {"name", name}, {"error", "Rename failed"}};
        return json{{"addr", helpers::format_address(*ea_opt)}, {"name", name}};
    });
    handle_array("global", [](const json& item) {
        std::string addr = first_string_field(item, {"addr", "address", "old", "name"});
        std::string name = item.value("new", item.value("new_name", ""));
        if (name.empty() && item.contains("addr"))
            name = item.value("name", "");
        auto ea_opt = helpers::parse_address(addr);
        if (!ea_opt || name.empty())
            return json{{"addr", addr}, {"name", name}, {"error", "Global rename requires target/name"}};
        if (!set_name(*ea_opt, name.c_str(), SN_CHECK | SN_NODUMMY))
            return json{{"addr", helpers::format_address(*ea_opt)}, {"name", name}, {"error", "Rename failed"}};
        return json{{"addr", helpers::format_address(*ea_opt)}, {"name", name}};
    });
    handle_array("local", [](const json& item) {
        json p;
        p["address"] = first_string_field(item, {"func_addr", "func", "addr"});
        p["original_name"] = item.value("old", item.value("name", ""));
        p["new_name"] = item.value("new", item.value("new_name", ""));
        auto r = comment_tools::rename_variable(p);
        return r.success ? json{{"func_addr", p["address"]}, {"old", p["original_name"]}, {"new", p["new_name"]}} : json{{"func_addr", p["address"]}, {"old", p["original_name"]}, {"new", p["new_name"]}, {"error", r.output}};
    });
    if (params.contains("globals") && !result.contains("global"))
    {
        json copy = params;
        copy["global"] = params["globals"];
        return rename(copy);
    }
    result["summary"] = {{"total", total}, {"ok", ok}, {"failed", failed}, {"stopped", false}};
    return tool_result_t::ok(OBFSTR("Rename batch processed"), result);
}

static tool_result_t define_func(const json& params)
{
    json items = get_list_param(params, "items", "funcs");
    json results = json::array();
    for (const auto& item : items)
    {
        json p;
        p["address"] = first_string_field(item, {"addr", "address"});
        if (item.contains("end"))
            p["end"] = item["end"];
        auto r = function_tools::define_function(p);
        results.push_back(r.success ? json{{"addr", p["address"]}} : json{{"addr", p["address"]}, {"error", r.output}});
    }
    return tool_result_t::ok(OBFSTR("Function definitions processed"), results);
}

static tool_result_t define_code(const json& params)
{
    json items = get_list_param(params, "items", "addrs");
    json results = json::array();
    for (const auto& item : items)
    {
        json p;
        p["address"] = first_string_field(item, {"addr", "address"});
        auto r = memory_tools::make_code(p);
        results.push_back(r.success ? json{{"addr", p["address"]}} : json{{"addr", p["address"]}, {"error", r.output}});
    }
    return tool_result_t::ok(OBFSTR("Code definitions processed"), results);
}

static tool_result_t stack_frame(const json& params)
{
    json addrs = get_list_param(params, "addrs", "addr");
    json results = json::array();
    for (const auto& a : addrs)
    {
        json p;
        p["address"] = value_to_string(a);
        auto r = function_tools::get_stack_frame(p);
        results.push_back(r.success ? r.data : json{{"addr", p["address"]}, {"error", r.output}});
    }
    return tool_result_t::ok(OBFSTR("Stack frames retrieved"), results);
}

static tool_result_t declare_stack(const json& params)
{
    json items = get_list_param(params, "items", "vars");
    json results = json::array();
    for (const auto& item : items)
    {
        json p;
        p["address"] = first_string_field(item, {"func_addr", "func", "addr"});
        p["offset"] = item.value("offset", 0);
        p["name"] = item.value("name", "");
        p["type"] = item.value("ty", item.value("type", "__int64"));
        auto r = type_tools::create_stack_var(p);
        results.push_back(r.success ? json{{"func_addr", p["address"]}, {"name", p["name"]}} : json{{"func_addr", p["address"]}, {"name", p["name"]}, {"error", r.output}});
    }
    return tool_result_t::ok(OBFSTR("Stack declarations processed"), results);
}

static tool_result_t delete_stack(const json& params)
{
    json items = get_list_param(params, "items", "vars");
    json results = json::array();
    for (const auto& item : items)
    {
        json p;
        p["address"] = first_string_field(item, {"func_addr", "func", "addr"});
        p["name"] = item.value("name", "");
        auto r = type_tools::delete_stack_var(p);
        results.push_back(r.success ? json{{"func_addr", p["address"]}, {"name", p["name"]}} : json{{"func_addr", p["address"]}, {"name", p["name"]}, {"error", r.output}});
    }
    return tool_result_t::ok(OBFSTR("Stack deletes processed"), results);
}

static tool_result_t declare_type(const json& params)
{
    json decls = get_list_param(params, "decls", "declarations");
    if (decls.empty() && params.contains("declaration"))
        decls.push_back(params["declaration"]);
    json results = json::array();
    for (const auto& d : decls)
    {
        json p;
        p["declaration"] = value_to_string(d);
        auto r = type_tools::declare_type(p);
        results.push_back(r.success ? json{{"decl", p["declaration"]}} : json{{"decl", p["declaration"]}, {"error", r.output}});
    }
    return tool_result_t::ok(OBFSTR("Type declarations processed"), results);
}

static tool_result_t read_struct(const json& params)
{
    json queries = get_list_param(params, "queries", "items");
    json results = json::array();
    for (const auto& q : queries)
    {
        std::string addr = first_string_field(q, {"addr", "address"});
        std::string struct_name = q.value("struct", q.value("struct_name", q.value("type", "")));
        auto ea_opt = helpers::parse_address(addr);
        if (!ea_opt || struct_name.empty())
        {
            results.push_back({{"addr", addr}, {"struct", struct_name}, {"members", nullptr}, {"error", "Address and struct are required"}});
            continue;
        }
        til_t* ti = get_idati();
        int32 ordinal = get_type_ordinal(ti, struct_name.c_str());
        tinfo_t tif;
        udt_type_data_t udt;
        if (ordinal <= 0 || !tif.get_numbered_type(ti, ordinal) || !tif.get_udt_details(&udt))
        {
            results.push_back({{"addr", addr}, {"struct", struct_name}, {"members", nullptr}, {"error", "Struct not found"}});
            continue;
        }
        json members = json::array();
        for (size_t i = 0; i < udt.size(); i++)
        {
            const udm_t& m = udt[i];
            asize_t size = static_cast<asize_t>(std::max<uint64_t>(1, m.size / 8));
            ea_t field_ea = *ea_opt + m.offset / 8;
            qstring type_s;
            m.type.print(&type_s);
            json member;
            member["offset"] = helpers::format_address(m.offset / 8);
            member["type"] = type_s.c_str();
            member["name"] = m.name.c_str();
            member["size"] = size;
            if (size <= 8 && is_loaded(field_ea))
            {
                uval_t val = 0;
                if (get_data_value(&val, field_ea, size))
                    member["value"] = helpers::format_address(val);
            }
            members.push_back(member);
        }
        results.push_back({{"addr", addr}, {"struct", struct_name}, {"members", members}});
    }
    return tool_result_t::ok(OBFSTR("Struct reads processed"), results);
}

static tool_result_t search_structs_batch(const json& params)
{
    json p;
    p["pattern"] = params.value("filter", params.value("pattern", ".*"));
    p["limit"] = params.value("limit", 100);
    return type_tools::search_structs(p);
}

static tool_result_t type_query(const json& params)
{
    json queries = get_list_param(params, "queries", "query");
    if (queries.empty())
        queries.push_back(params);
    json results = json::array();
    for (const auto& q : queries)
    {
        auto r = type_tools::list_types(make_page_params(q, 100));
        std::string kind = q.is_object() ? q.value("kind", "any") : "any";
        results.push_back(r.success ? json{{"kind", kind}, {"data", r.data.value("types", json::array())}, {"total", r.data.value("total", 0)}, {"next_offset", nullptr}} : json{{"error", r.output}});
    }
    return tool_result_t::ok(OBFSTR("Type query complete"), results);
}

static tool_result_t set_type(const json& params)
{
    json edits = get_list_param(params, "edits", "items");
    json results = json::array();
    for (const auto& edit : edits)
    {
        std::string kind = edit.value("kind", "");
        std::string type_text = edit.value("ty", edit.value("type", edit.value("decl", edit.value("declaration", ""))));
        json p;
        p["address"] = first_string_field(edit, {"addr", "address", "name"});
        if (edit.contains("signature") || kind == "function")
        {
            p["signature"] = edit.value("signature", type_text);
            auto r = function_tools::set_function_signature(p);
            results.push_back(r.success ? json{{"edit", edit}, {"kind", "function"}, {"ok", true}} : json{{"edit", edit}, {"kind", "function"}, {"error", r.output}});
        }
        else
        {
            p["type"] = type_text;
            auto r = type_tools::apply_type(p);
            results.push_back(r.success ? json{{"edit", edit}, {"kind", "global"}, {"ok", true}} : json{{"edit", edit}, {"kind", "global"}, {"error", r.output}});
        }
    }
    return tool_result_t::ok(OBFSTR("Type edits processed"), results);
}

static tool_result_t infer_types(const json& params)
{
    json addrs = get_list_param(params, "addrs", "addr");
    json results = json::array();
    for (const auto& a : addrs)
    {
        json p;
        p["address"] = value_to_string(a);
        auto r = type_tools::infer_type(p);
        results.push_back(r.success ? json{{"addr", p["address"]}, {"inferred_type", r.data.value("type", "")}, {"method", "aida"}, {"confidence", r.data.value("confidence", "low")}} : json{{"addr", p["address"]}, {"inferred_type", nullptr}, {"confidence", "none"}, {"error", r.output}});
    }
    return tool_result_t::ok(OBFSTR("Type inference processed"), results);
}

static std::string address_param(const json& params)
{
    if (params.contains("addr")) return value_to_string(params["addr"]);
    if (params.contains("address")) return value_to_string(params["address"]);
    if (params.contains("ea")) return value_to_string(params["ea"]);
    if (params.contains("func")) return value_to_string(params["func"]);
    if (params.contains("function")) return value_to_string(params["function"]);
    if (params.contains("root")) return value_to_string(params["root"]);
    return "";
}

static tool_result_t idb_save(const json& params)
{
    std::string path = params.value("path", params.value("outfile", ""));
    uint32 flags = 0;
    if (params.value("backup", true))
        flags |= DBFL_BAK;
    if (params.value("compact", false))
        flags |= DBFL_COMP;
    bool ok = save_database(path.empty() ? nullptr : path.c_str(), flags);
    if (!ok)
        return tool_result_t::error(OBFSTR("Failed to save IDB"));
    json data;
    data["path"] = path.empty() ? "current" : path;
    data["backup"] = (flags & DBFL_BAK) != 0;
    data["compact"] = (flags & DBFL_COMP) != 0;
    return tool_result_t::ok(OBFSTR("IDB saved"), data);
}

static tool_result_t find_regex(const json& params)
{
    std::string pattern = params.value("pattern", params.value("regex", params.value("query", "")));
    int limit = params.value("limit", params.value("count", 50));
    if (pattern.empty())
        return tool_result_t::error(OBFSTR("Pattern is required"));
    json data;
    auto strings = search_tools::search_strings({{"pattern", pattern}, {"limit", limit}});
    auto insns = search_tools::find_instructions({{"pattern", pattern}, {"limit", limit}});
    data["strings"] = strings.success ? strings.data : json{{"error", strings.output}};
    data["instructions"] = insns.success ? insns.data : json{{"error", insns.output}};
    return tool_result_t::ok(OBFSTR("Regex search complete"), data);
}

static tool_result_t search_text(const json& params)
{
    std::string pattern = params.value("text", params.value("pattern", params.value("query", "")));
    int limit = params.value("limit", params.value("count", 100));
    if (pattern.empty())
        return tool_result_t::error(OBFSTR("Search text is required"));
    return search_tools::search_strings({{"pattern", pattern}, {"limit", limit}});
}

static tool_result_t export_funcs(const json& params)
{
    json p = make_page_params(params, 200);
    return import_tools::list_exports(p);
}

static tool_result_t callgraph(const json& params)
{
    json p;
    p["address"] = address_param(params);
    p["depth"] = params.value("depth", params.value("max_depth", 3));
    return function_tools::build_call_graph(p);
}

static tool_result_t func_profile(const json& params)
{
    std::string addr = address_param(params);
    if (addr.empty())
        return tool_result_t::error(OBFSTR("Address is required"));
    json data;
    auto fn = function_tools::get_function({{"address", addr}});
    auto complexity = analysis_tools::get_function_complexity({{"address", addr}});
    auto cfg = analysis_tools::analyze_control_flow({{"address", addr}});
    data["function"] = fn.success ? fn.data : json{{"error", fn.output}};
    data["complexity"] = complexity.success ? complexity.data : json{{"error", complexity.output}};
    data["control_flow"] = cfg.success ? cfg.data : json{{"error", cfg.output}};
    return tool_result_t::ok(OBFSTR("Function profile complete"), data);
}

static tool_result_t analyze_function_batch(const json& params)
{
    std::string addr = address_param(params);
    if (addr.empty())
        return tool_result_t::error(OBFSTR("Address is required"));
    json data;
    auto fn = function_tools::get_function({{"address", addr}});
    auto decomp = function_tools::decompile_function({{"address", addr}});
    auto disasm = function_tools::disassemble_function({{"address", addr}});
    auto to = function_tools::get_xrefs_to({{"address", addr}, {"limit", params.value("limit", 100)}});
    auto from = function_tools::get_xrefs_from({{"address", addr}, {"limit", params.value("limit", 100)}});
    auto blocks = function_tools::get_basic_blocks({{"address", addr}});
    auto profile = func_profile({{"addr", addr}});
    data["function"] = fn.success ? fn.data : json{{"error", fn.output}};
    data["decompilation"] = decomp.success ? decomp.data : json{{"error", decomp.output}};
    data["disassembly"] = disasm.success ? disasm.data : json{{"error", disasm.output}};
    data["xrefs_to"] = to.success ? to.data : json{{"error", to.output}};
    data["xrefs_from"] = from.success ? from.data : json{{"error", from.output}};
    data["basic_blocks"] = blocks.success ? blocks.data : json{{"error", blocks.output}};
    data["profile"] = profile.success ? profile.data : json{{"error", profile.output}};
    return tool_result_t::ok(OBFSTR("Function analysis complete"), data);
}

static tool_result_t analyze_batch(const json& params)
{
    json addrs = get_list_param(params, "addrs", "addresses");
    if (addrs.empty())
        addrs = get_list_param(params, "items", "functions");
    if (addrs.empty() && !address_param(params).empty())
        addrs.push_back(address_param(params));
    json results = json::array();
    for (const auto& item : addrs)
    {
        json p;
        p["addr"] = first_string_field(item, {"addr", "address", "ea", "func"});
        auto r = analyze_function_batch(p);
        results.push_back(r.success ? r.data : json{{"addr", p["addr"]}, {"error", r.output}});
    }
    return tool_result_t::ok(OBFSTR("Batch analysis complete"), results);
}

static tool_result_t analyze_component(const json& params)
{
    return analyze_batch(params);
}

static tool_result_t diff_before_after(const json& params)
{
    std::string addr = address_param(params);
    std::string action = params.value("action", params.value("operation", ""));
    json args = params.value("args", params.value("arguments", json::object()));
    if (addr.empty() || action.empty())
        return tool_result_t::error(OBFSTR("Address and action are required"));
    auto before = function_tools::decompile_function({{"address", addr}});
    agent_tools::tool_result_t applied = tool_result_t::error(OBFSTR("Unsupported action"));
    if (action == "rename_func" || action == "rename_function")
    {
        std::string name = args.value("name", args.value("new_name", ""));
        applied = function_tools::rename_function({{"address", addr}, {"new_name", name}});
    }
    else if (action == "set_comment")
    {
        std::string comment = args.value("comment", "");
        applied = comment_tools::set_comment({{"address", addr}, {"comment", comment}});
    }
    else if (action == "set_type")
    {
        std::string type_text = args.value("type", args.value("signature", ""));
        applied = function_tools::set_function_signature({{"address", addr}, {"signature", type_text}});
    }
    else if (action == "patch_bytes")
    {
        std::string bytes = args.value("bytes", args.value("data", ""));
        applied = memory_tools::patch_bytes({{"address", addr}, {"bytes", bytes}});
    }
    else if (action == "patch_asm")
    {
        std::string asm_text = args.value("asm", args.value("assembly", ""));
        applied = patch_asm({{"items", json::array({json::object({{"addr", addr}, {"asm", asm_text}})})}});
    }
    auto after = function_tools::decompile_function({{"address", addr}});
    json data;
    data["target"] = addr;
    data["action"] = action;
    data["before"] = before.success ? before.data : json{{"error", before.output}};
    data["applied"] = applied.success ? json{{"ok", true}, {"data", applied.data}, {"output", applied.output}} : json{{"ok", false}, {"error", applied.output}};
    data["after"] = after.success ? after.data : json{{"error", after.output}};
    return tool_result_t::ok(OBFSTR("Before/after diff action complete"), data);
}

static tool_result_t trace_data_flow(const json& params)
{
    json p;
    p["address"] = address_param(params);
    p["max_depth"] = params.value("max_depth", params.value("depth", 32));
    return analysis_tools::analyze_data_flow(p);
}

static tool_result_t xrefs_to_field(const json& params)
{
    json p;
    p["struct_name"] = params.value("struct_name", params.value("struct", params.value("type", "")));
    p["field_name"] = params.value("field_name", params.value("field", params.value("member", "")));
    p["limit"] = params.value("limit", 100);
    return type_tools::get_struct_field_xrefs(p);
}

static tool_result_t find_batch(const json& params)
{
    std::string kind = params.value("kind", params.value("type", "text"));
    std::transform(kind.begin(), kind.end(), kind.begin(), [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    if (kind == "bytes" || kind == "byte")
        return search_tools::find_bytes({{"pattern", params.value("pattern", params.value("query", ""))}, {"limit", params.value("limit", 20)}});
    if (kind == "instruction" || kind == "instructions" || kind == "insn")
        return search_tools::find_instructions({{"pattern", params.value("pattern", params.value("query", ""))}, {"limit", params.value("limit", 20)}});
    if (kind == "function" || kind == "functions")
        return function_tools::list_functions(make_page_params(params, 100));
    if (kind == "import" || kind == "imports")
        return import_tools::list_imports(make_page_params(params, 200));
    if (kind == "export" || kind == "exports")
        return import_tools::list_exports(make_page_params(params, 200));
    return search_text(params);
}

static tool_result_t insn_query(const json& params)
{
    json queries = get_list_param(params, "queries", "query");
    if (queries.empty())
        queries.push_back(params);
    json results = json::array();
    for (const auto& q : queries)
    {
        std::string pattern = first_string_field(q, {"pattern", "text", "query", "mnemonic"});
        int limit = q.is_object() ? q.value("limit", q.value("count", 20)) : 20;
        auto r = search_tools::find_instructions({{"pattern", pattern}, {"limit", limit}});
        results.push_back(r.success ? r.data : json{{"pattern", pattern}, {"error", r.output}});
    }
    return tool_result_t::ok(OBFSTR("Instruction query complete"), results);
}

static tool_result_t enum_upsert(const json& params)
{
    json items = get_list_param(params, "items", "enums");
    if (items.empty())
        items.push_back(params);
    json results = json::array();
    for (const auto& item : items)
    {
        json p;
        p["name"] = item.value("name", "");
        p["members"] = item.value("members", json::array());
        auto r = type_tools::create_enum(p);
        results.push_back(r.success ? json{{"name", p["name"]}, {"ok", true}} : json{{"name", p["name"]}, {"error", r.output}});
    }
    return tool_result_t::ok(OBFSTR("Enum upsert batch processed"), results);
}

static tool_result_t type_inspect(const json& params)
{
    std::string name = params.value("name", params.value("type", ""));
    if (!name.empty())
        return type_tools::get_struct({{"name", name}});
    return type_tools::list_types(make_page_params(params, 100));
}

static tool_result_t type_apply_batch(const json& params)
{
    return set_type(params);
}

static tool_result_t py_exec_file(const json& params)
{
    std::string path = params.value("path", params.value("file", ""));
    if (path.empty())
        return tool_result_t::error(OBFSTR("Path is required"));
    std::ifstream f(path, std::ios::binary);
    if (!f)
        return tool_result_t::error(OBFSTR("Failed to open Python file"));
    std::ostringstream ss;
    ss << f.rdbuf();
    std::string code = ss.str();
    if (code.size() > 1024 * 1024)
        return tool_result_t::error(OBFSTR("Python file too large"));
    return python_tools::execute_python({{"code", code}});
}

static tool_result_t survey_binary(const json& params)
{
    int count = params.value("count", params.value("limit", 50));
    json data;
    data["binary"] = binary_tools::get_binary_info(json::object()).data;
    data["functions"] = function_tools::list_functions({{"offset", 0}, {"limit", count}}).data;
    data["imports"] = import_tools::list_imports({{"offset", 0}, {"limit", count}}).data;
    data["globals"] = memory_tools::list_globals({{"offset", 0}, {"limit", count}}).data;
    return tool_result_t::ok(OBFSTR("Binary survey complete"), data);
}

static tool_result_t make_signature(const json& params)
{
    std::string addr = params.contains("addr") ? value_to_string(params["addr"]) : value_to_string(params.value("address", json()));
    int max_bytes = params.value("max_bytes", params.value("size", 64));
    if (max_bytes <= 0)
        max_bytes = 64;
    if (max_bytes > 512)
        max_bytes = 512;
    auto ea_opt = helpers::parse_address(addr);
    if (!ea_opt)
        return tool_result_t::error(OBFSTR("Invalid address"));
    func_t* pfn = get_func(*ea_opt);
    ea_t start = pfn ? pfn->start_ea : *ea_opt;
    ea_t end = pfn ? pfn->end_ea : start + max_bytes;
    size_t size = static_cast<size_t>(std::min<ea_t>(end - start, max_bytes));
    std::vector<uint8_t> buffer(size);
    ssize_t n = ::get_bytes(buffer.data(), size, start);
    if (n <= 0)
        return tool_result_t::error(OBFSTR("Failed to read bytes for signature"));
    std::ostringstream sig;
    for (ssize_t i = 0; i < n; i++)
    {
        if (i > 0)
            sig << " ";
        sig << std::hex << std::uppercase << std::setw(2) << std::setfill('0') << static_cast<int>(buffer[i]);
    }
    json data;
    data["addr"] = helpers::format_address(start);
    data["size"] = n;
    data["signature"] = sig.str();
    data["format"] = "ida_bytes";
    return tool_result_t::ok(OBFSTR("Signature generated"), data);
}

static tool_result_t make_signature_for_function(const json& params)
{
    return make_signature(params);
}

static tool_result_t py_eval(const json& params)
{
    json p;
    p["code"] = params.value("code", params.value("expr", ""));
    return python_tools::execute_python(p);
}

void register_tools()
{
    auto& registry = ToolRegistry::instance();
    registry.register_tool({OBFSTR("server_health"), OBFSTR("aida_ida_batch"), OBFSTR("Return IDA plugin health and static analysis state."), {}, server_health, true});
    registry.register_tool({OBFSTR("server_warmup"), OBFSTR("aida_ida_batch"), OBFSTR("Warm IDA analysis/decompiler state for AiDA clients."), {{OBFSTR("wait_auto_analysis"), OBFSTR("boolean"), OBFSTR("Wait for auto-analysis"), false}, {OBFSTR("init_hexrays"), OBFSTR("boolean"), OBFSTR("Initialize Hex-Rays"), false}}, server_warmup, true});
    registry.register_tool({OBFSTR("idb_save"), OBFSTR("aida_ida_batch"), OBFSTR("Save the current IDB."), {{OBFSTR("path"), OBFSTR("string"), OBFSTR("Optional output IDB path"), false}, {OBFSTR("backup"), OBFSTR("boolean"), OBFSTR("Create an IDB backup"), false}, {OBFSTR("compact"), OBFSTR("boolean"), OBFSTR("Compact database during save"), false}}, idb_save, false});
    registry.register_tool({OBFSTR("decompile"), OBFSTR("aida_ida_batch"), OBFSTR("AiDA alias for decompile_function."), {{OBFSTR("addr"), OBFSTR("string"), OBFSTR("Function address or name"), true}}, decompile, true});
    registry.register_tool({OBFSTR("disasm"), OBFSTR("aida_ida_batch"), OBFSTR("AiDA alias for disassemble_function."), {{OBFSTR("addr"), OBFSTR("string"), OBFSTR("Function address or name"), true}}, disasm, true});
    registry.register_tool({OBFSTR("list_funcs"), OBFSTR("aida_ida_batch"), OBFSTR("List functions using offset/count pagination."), {{OBFSTR("offset"), OBFSTR("number"), OBFSTR("Start offset"), false}, {OBFSTR("count"), OBFSTR("number"), OBFSTR("Result count"), false}, {OBFSTR("filter"), OBFSTR("string"), OBFSTR("Name filter"), false}}, list_funcs, true});
    registry.register_tool({OBFSTR("lookup_funcs"), OBFSTR("aida_ida_batch"), OBFSTR("Lookup functions by address or name."), {{OBFSTR("queries"), OBFSTR("array"), OBFSTR("Function lookup requests"), true}}, lookup_funcs, true});
    registry.register_tool({OBFSTR("func_query"), OBFSTR("aida_ida_batch"), OBFSTR("Batch function catalog query."), {{OBFSTR("queries"), OBFSTR("array"), OBFSTR("Function query requests"), true}}, func_query, true});
    registry.register_tool({OBFSTR("func_profile"), OBFSTR("aida_ida_batch"), OBFSTR("Return function metadata, complexity, and control-flow profile."), {{OBFSTR("addr"), OBFSTR("string"), OBFSTR("Function address or name"), true}}, func_profile, true});
    registry.register_tool({OBFSTR("analyze_function"), OBFSTR("aida_ida_batch"), OBFSTR("Return a composite function analysis package."), {{OBFSTR("addr"), OBFSTR("string"), OBFSTR("Function address or name"), true}, {OBFSTR("limit"), OBFSTR("number"), OBFSTR("Xref limit"), false}}, analyze_function_batch, true});
    registry.register_tool({OBFSTR("analyze_batch"), OBFSTR("aida_ida_batch"), OBFSTR("Analyze multiple functions."), {{OBFSTR("addrs"), OBFSTR("array"), OBFSTR("Function addresses"), true}}, analyze_batch, true});
    registry.register_tool({OBFSTR("analyze_component"), OBFSTR("aida_ida_batch"), OBFSTR("Analyze a component represented by a batch of functions."), {{OBFSTR("functions"), OBFSTR("array"), OBFSTR("Component function addresses"), true}}, analyze_component, true});
    registry.register_tool({OBFSTR("diff_before_after"), OBFSTR("aida_ida_batch"), OBFSTR("Apply a supported edit and return before/after decompilation data."), {{OBFSTR("addr"), OBFSTR("string"), OBFSTR("Function address or name"), true}, {OBFSTR("action"), OBFSTR("string"), OBFSTR("Edit action"), true}, {OBFSTR("args"), OBFSTR("object"), OBFSTR("Action arguments"), false}}, diff_before_after, false});
    registry.register_tool({OBFSTR("trace_data_flow"), OBFSTR("aida_ida_batch"), OBFSTR("Trace local data-flow around an address."), {{OBFSTR("addr"), OBFSTR("string"), OBFSTR("Instruction address"), true}, {OBFSTR("max_depth"), OBFSTR("number"), OBFSTR("Maximum scan depth"), false}}, trace_data_flow, true});
    registry.register_tool({OBFSTR("imports"), OBFSTR("aida_ida_batch"), OBFSTR("List imports using offset/count."), {{OBFSTR("offset"), OBFSTR("number"), OBFSTR("Start offset"), false}, {OBFSTR("count"), OBFSTR("number"), OBFSTR("Result count"), false}, {OBFSTR("filter"), OBFSTR("string"), OBFSTR("Name filter"), false}}, imports, true});
    registry.register_tool({OBFSTR("imports_query"), OBFSTR("aida_ida_batch"), OBFSTR("Batch import catalog query."), {{OBFSTR("queries"), OBFSTR("array"), OBFSTR("Import query requests"), true}}, imports_query, true});
    registry.register_tool({OBFSTR("export_funcs"), OBFSTR("aida_ida_batch"), OBFSTR("List exports using offset/count pagination."), {{OBFSTR("offset"), OBFSTR("number"), OBFSTR("Start offset"), false}, {OBFSTR("count"), OBFSTR("number"), OBFSTR("Result count"), false}, {OBFSTR("filter"), OBFSTR("string"), OBFSTR("Name filter"), false}}, export_funcs, true});
    registry.register_tool({OBFSTR("list_globals"), OBFSTR("memory"), OBFSTR("List globals with AiDA batch query shapes."), {{OBFSTR("offset"), OBFSTR("number"), OBFSTR("Start offset"), false}, {OBFSTR("limit"), OBFSTR("number"), OBFSTR("Max results"), false}, {OBFSTR("filter"), OBFSTR("string"), OBFSTR("Regex filter"), false}, {OBFSTR("queries"), OBFSTR("array"), OBFSTR("Batch query requests"), false}}, list_globals_batch, true});
    registry.register_tool({OBFSTR("entity_query"), OBFSTR("aida_ida_batch"), OBFSTR("Query function/global/import entity catalogs."), {{OBFSTR("queries"), OBFSTR("array"), OBFSTR("Entity query requests"), true}}, entity_query, true});
    registry.register_tool({OBFSTR("xrefs_to"), OBFSTR("aida_ida_batch"), OBFSTR("AiDA alias for get_xrefs_to."), {{OBFSTR("addrs"), OBFSTR("array"), OBFSTR("Target addresses"), true}, {OBFSTR("limit"), OBFSTR("number"), OBFSTR("Maximum xrefs"), false}}, xrefs_to, true});
    registry.register_tool({OBFSTR("xref_query"), OBFSTR("aida_ida_batch"), OBFSTR("Batch xref query with to/from direction."), {{OBFSTR("queries"), OBFSTR("array"), OBFSTR("Xref query requests"), true}}, xref_query, true});
    registry.register_tool({OBFSTR("xrefs_to_field"), OBFSTR("aida_ida_batch"), OBFSTR("Return information for a struct field and suggested offset search."), {{OBFSTR("struct_name"), OBFSTR("string"), OBFSTR("Struct name"), true}, {OBFSTR("field_name"), OBFSTR("string"), OBFSTR("Field name"), true}, {OBFSTR("limit"), OBFSTR("number"), OBFSTR("Maximum xrefs"), false}}, xrefs_to_field, true});
    registry.register_tool({OBFSTR("callees"), OBFSTR("aida_ida_batch"), OBFSTR("List callees for functions."), {{OBFSTR("addrs"), OBFSTR("array"), OBFSTR("Function addresses"), true}}, callees, true});
    registry.register_tool({OBFSTR("basic_blocks"), OBFSTR("aida_ida_batch"), OBFSTR("List basic blocks for functions."), {{OBFSTR("addrs"), OBFSTR("array"), OBFSTR("Function addresses"), true}}, basic_blocks, true});
    registry.register_tool({OBFSTR("callgraph"), OBFSTR("aida_ida_batch"), OBFSTR("Build a call graph from a root function."), {{OBFSTR("addr"), OBFSTR("string"), OBFSTR("Root function address"), true}, {OBFSTR("depth"), OBFSTR("number"), OBFSTR("Maximum depth"), false}}, callgraph, true});
    registry.register_tool({OBFSTR("find"), OBFSTR("aida_ida_batch"), OBFSTR("AiDA finder across text, bytes, instructions, functions, imports, and exports."), {{OBFSTR("kind"), OBFSTR("string"), OBFSTR("Result kind"), false}, {OBFSTR("pattern"), OBFSTR("string"), OBFSTR("Search pattern"), false}, {OBFSTR("limit"), OBFSTR("number"), OBFSTR("Maximum results"), false}}, find_batch, true});
    registry.register_tool({OBFSTR("find_regex"), OBFSTR("aida_ida_batch"), OBFSTR("Search strings and instructions by regex/text pattern."), {{OBFSTR("pattern"), OBFSTR("string"), OBFSTR("Regex pattern"), true}, {OBFSTR("limit"), OBFSTR("number"), OBFSTR("Maximum results per class"), false}}, find_regex, true});
    registry.register_tool({OBFSTR("search_text"), OBFSTR("aida_ida_batch"), OBFSTR("Search IDA string literals by text or regex."), {{OBFSTR("text"), OBFSTR("string"), OBFSTR("Search text"), true}, {OBFSTR("limit"), OBFSTR("number"), OBFSTR("Maximum results"), false}}, search_text, true});
    registry.register_tool({OBFSTR("insn_query"), OBFSTR("aida_ida_batch"), OBFSTR("Batch instruction text query."), {{OBFSTR("queries"), OBFSTR("array"), OBFSTR("Instruction query requests"), true}}, insn_query, true});
    registry.register_tool({OBFSTR("get_bytes"), OBFSTR("aida_ida_batch"), OBFSTR("Read byte regions using {addr,size} requests."), {{OBFSTR("regions"), OBFSTR("array"), OBFSTR("Memory regions"), true}}, get_bytes_batch, true});
    registry.register_tool({OBFSTR("get_int"), OBFSTR("aida_ida_batch"), OBFSTR("Read integers using {addr,ty} requests."), {{OBFSTR("queries"), OBFSTR("array"), OBFSTR("Integer read requests"), true}}, get_int, true});
    registry.register_tool({OBFSTR("get_string"), OBFSTR("aida_ida_batch"), OBFSTR("Read strings from addresses."), {{OBFSTR("addrs"), OBFSTR("array"), OBFSTR("String addresses"), true}}, get_string, true});
    registry.register_tool({OBFSTR("get_global_value"), OBFSTR("aida_ida_batch"), OBFSTR("Read global values by address or name."), {{OBFSTR("queries"), OBFSTR("array"), OBFSTR("Global value requests"), true}}, get_global_value, true});
    registry.register_tool({OBFSTR("patch"), OBFSTR("aida_ida_batch"), OBFSTR("Patch bytes using {addr,data} requests."), {{OBFSTR("patches"), OBFSTR("array"), OBFSTR("Patch requests"), true}}, patch, false});
    registry.register_tool({OBFSTR("patch_asm"), OBFSTR("aida_ida_batch"), OBFSTR("Assemble and patch instructions at addresses."), {{OBFSTR("items"), OBFSTR("array"), OBFSTR("Assembly patch requests"), false}, {OBFSTR("addr"), OBFSTR("string"), OBFSTR("Patch address"), false}, {OBFSTR("asm"), OBFSTR("string"), OBFSTR("Assembly instruction"), false}}, patch_asm, false});
    registry.register_tool({OBFSTR("put_int"), OBFSTR("aida_ida_batch"), OBFSTR("Patch integer values using {addr,ty,value} requests."), {{OBFSTR("items"), OBFSTR("array"), OBFSTR("Integer write requests"), true}}, put_int, false});
    registry.register_tool({OBFSTR("set_comments"), OBFSTR("aida_ida_batch"), OBFSTR("Set comments at addresses."), {{OBFSTR("items"), OBFSTR("array"), OBFSTR("Comment requests"), true}}, set_comments, false});
    registry.register_tool({OBFSTR("append_comments"), OBFSTR("aida_ida_batch"), OBFSTR("Append comments at addresses."), {{OBFSTR("items"), OBFSTR("array"), OBFSTR("Comment append requests"), true}}, append_comments, false});
    registry.register_tool({OBFSTR("rename"), OBFSTR("aida_ida_batch"), OBFSTR("Batch rename functions, globals, and locals."), {{OBFSTR("func"), OBFSTR("array"), OBFSTR("Function renames"), false}, {OBFSTR("data"), OBFSTR("array"), OBFSTR("Data renames"), false}, {OBFSTR("global"), OBFSTR("array"), OBFSTR("Global renames"), false}, {OBFSTR("local"), OBFSTR("array"), OBFSTR("Local renames"), false}}, rename, false});
    registry.register_tool({OBFSTR("define_func"), OBFSTR("aida_ida_batch"), OBFSTR("Define functions."), {{OBFSTR("items"), OBFSTR("array"), OBFSTR("Function definition requests"), true}}, define_func, false});
    registry.register_tool({OBFSTR("define_code"), OBFSTR("aida_ida_batch"), OBFSTR("Create code at addresses."), {{OBFSTR("items"), OBFSTR("array"), OBFSTR("Code definition requests"), true}}, define_code, false});
    registry.register_tool({OBFSTR("stack_frame"), OBFSTR("aida_ida_batch"), OBFSTR("Read function stack frames."), {{OBFSTR("addrs"), OBFSTR("array"), OBFSTR("Function addresses"), true}}, stack_frame, true});
    registry.register_tool({OBFSTR("declare_stack"), OBFSTR("aida_ida_batch"), OBFSTR("Declare stack variables."), {{OBFSTR("items"), OBFSTR("array"), OBFSTR("Stack variable declarations"), true}}, declare_stack, false});
    registry.register_tool({OBFSTR("delete_stack"), OBFSTR("aida_ida_batch"), OBFSTR("Delete stack variables."), {{OBFSTR("items"), OBFSTR("array"), OBFSTR("Stack variable deletes"), true}}, delete_stack, false});
    registry.register_tool({OBFSTR("declare_type"), OBFSTR("type"), OBFSTR("Declare C types with AiDA batch request shapes."), {{OBFSTR("decls"), OBFSTR("array"), OBFSTR("C type declarations"), false}, {OBFSTR("declaration"), OBFSTR("string"), OBFSTR("Single C type declaration"), false}}, declare_type, false});
    registry.register_tool({OBFSTR("enum_upsert"), OBFSTR("aida_ida_batch"), OBFSTR("Create enum types from AiDA batch requests."), {{OBFSTR("items"), OBFSTR("array"), OBFSTR("Enum definitions"), false}, {OBFSTR("name"), OBFSTR("string"), OBFSTR("Enum name"), false}, {OBFSTR("members"), OBFSTR("array"), OBFSTR("Enum members"), false}}, enum_upsert, false});
    registry.register_tool({OBFSTR("read_struct"), OBFSTR("aida_ida_batch"), OBFSTR("Read struct members at addresses."), {{OBFSTR("queries"), OBFSTR("array"), OBFSTR("Struct read requests"), true}}, read_struct, true});
    registry.register_tool({OBFSTR("search_structs"), OBFSTR("type"), OBFSTR("Search structs/types using filter or pattern."), {{OBFSTR("filter"), OBFSTR("string"), OBFSTR("Name filter"), false}, {OBFSTR("pattern"), OBFSTR("string"), OBFSTR("Regex pattern"), false}, {OBFSTR("limit"), OBFSTR("number"), OBFSTR("Max results"), false}}, search_structs_batch, true});
    registry.register_tool({OBFSTR("type_query"), OBFSTR("aida_ida_batch"), OBFSTR("Batch type catalog query."), {{OBFSTR("queries"), OBFSTR("array"), OBFSTR("Type query requests"), true}}, type_query, true});
    registry.register_tool({OBFSTR("type_inspect"), OBFSTR("aida_ida_batch"), OBFSTR("Inspect a named type or list local types."), {{OBFSTR("name"), OBFSTR("string"), OBFSTR("Type name"), false}, {OBFSTR("limit"), OBFSTR("number"), OBFSTR("Maximum list results"), false}}, type_inspect, true});
    registry.register_tool({OBFSTR("set_type"), OBFSTR("aida_ida_batch"), OBFSTR("Apply function/global types."), {{OBFSTR("edits"), OBFSTR("array"), OBFSTR("Type edit requests"), true}}, set_type, false});
    registry.register_tool({OBFSTR("type_apply_batch"), OBFSTR("aida_ida_batch"), OBFSTR("Apply multiple type edits."), {{OBFSTR("edits"), OBFSTR("array"), OBFSTR("Type edit requests"), true}}, type_apply_batch, false});
    registry.register_tool({OBFSTR("infer_types"), OBFSTR("aida_ida_batch"), OBFSTR("Infer types at addresses."), {{OBFSTR("addrs"), OBFSTR("array"), OBFSTR("Addresses"), true}}, infer_types, true});
    registry.register_tool({OBFSTR("survey_binary"), OBFSTR("aida_ida_batch"), OBFSTR("Return a compact binary survey."), {{OBFSTR("count"), OBFSTR("number"), OBFSTR("Sample count"), false}}, survey_binary, true});
    registry.register_tool({OBFSTR("make_signature"), OBFSTR("aida_ida_batch"), OBFSTR("Generate a byte-pattern signature for an address or function."), {{OBFSTR("addr"), OBFSTR("string"), OBFSTR("Address or function name"), true}, {OBFSTR("max_bytes"), OBFSTR("number"), OBFSTR("Maximum bytes"), false}}, make_signature, true});
    registry.register_tool({OBFSTR("make_signature_for_function"), OBFSTR("aida_ida_batch"), OBFSTR("Generate a byte-pattern signature for a function."), {{OBFSTR("addr"), OBFSTR("string"), OBFSTR("Function address or name"), true}, {OBFSTR("max_bytes"), OBFSTR("number"), OBFSTR("Maximum bytes"), false}}, make_signature_for_function, true});
    registry.register_tool({OBFSTR("py_eval"), OBFSTR("aida_ida_batch"), OBFSTR("Execute Python code in IDA context."), {{OBFSTR("code"), OBFSTR("string"), OBFSTR("Python code or expression"), false}, {OBFSTR("expr"), OBFSTR("string"), OBFSTR("Python expression"), false}}, py_eval, false});
    registry.register_tool({OBFSTR("py_exec_file"), OBFSTR("aida_ida_batch"), OBFSTR("Execute a Python file in IDA context."), {{OBFSTR("path"), OBFSTR("string"), OBFSTR("Python file path"), true}}, py_exec_file, false});
}

}


void initialize_all_tools()
{
    function_tools::register_tools();
    memory_tools::register_tools();
    comment_tools::register_tools();
    type_tools::register_tools();
    import_tools::register_tools();
    search_tools::register_tools();
    segment_tools::register_tools();
    binary_tools::register_tools();
    python_tools::register_tools();
    navigation_tools::register_tools();
    analysis_tools::register_tools();
    deobfuscation_tools::register_tools();
    graphrag_tools::register_tools();
    vuln_tools::register_tools();
    vuln_tools::register_advanced_tools();
    aida::vuln::verify::tools::register_verification_tools();
    aida_ida_batch_tools::register_tools();

    ToolRegistry::instance().register_tool({
        OBFSTR("list_all_available_tools"), OBFSTR("meta"),
        OBFSTR("Returns the complete list of all available IDA Pro tools with their ") +
        OBFSTR("names, categories, descriptions, and parameter schemas. Use this ") +
        OBFSTR("tool when asked what tools or capabilities are available."),
        {
            {OBFSTR("category"), OBFSTR("string"),
             OBFSTR("Optional: filter by category (function, memory, comment, type, ") +
               OBFSTR("import, search, segment, binary, python, navigation, analysis, deobfuscation, graphrag, vuln, vuln_advanced, vuln_verify, meta)"),
             false}
        },
        [](const json& params) -> tool_result_t {
            auto& registry = ToolRegistry::instance();
            std::string filter_category;
            if (params.contains("category") && params["category"].is_string())
                filter_category = params["category"].get<std::string>();

            auto selected = filter_category.empty()
                ? registry.get_all_tools()
                : registry.get_tools_by_category(filter_category);

            json tools_arr = json::array();
            for (const auto* tool : selected)
            {
                json tj;
                tj["name"]        = tool->name;
                tj["category"]    = tool->category;
                tj["description"] = tool->description;
                tj["read_only"]   = tool->read_only;

                json params_arr = json::array();
                for (const auto& p : tool->parameters)
                {
                    json pj;
                    pj["name"]        = p.name;
                    pj["type"]        = p.type;
                    pj["description"] = p.description;
                    pj["required"]    = p.required;
                    if (!p.enum_values.empty())
                        pj["enum"] = p.enum_values;
                    params_arr.push_back(pj);
                }
                tj["parameters"] = params_arr;
                tools_arr.push_back(tj);
            }

            std::string summary = OBFSTR("Found ") + std::to_string(tools_arr.size()) + OBFSTR(" tools");
            if (!filter_category.empty())
                summary += OBFSTR(" in category '") + filter_category + OBFSTR("'");
            return tool_result_t::ok(summary, tools_arr);
        },
        true
    });

    msg(OBFSTR_C("AiDA: Initialized %zu agent tools\n"), ToolRegistry::instance().get_tool_names().size());
}

}
