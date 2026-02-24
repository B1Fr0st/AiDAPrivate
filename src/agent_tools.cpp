#include "aida_pro.hpp"

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
    
    try
    {
        cfuncptr_t cfunc = decompile(pfn);
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

    try
    {
        cfuncptr_t cfunc = decompile(pfn);
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

tool_result_t get_callees(const json& params)
{
    auto ea_opt = helpers::parse_address(params["address"].get<std::string>());
    if (!ea_opt)
        return tool_result_t::error(OBFSTR("Invalid address"));
    
    func_t* pfn = get_func(*ea_opt);
    if (!pfn)
        return tool_result_t::error(OBFSTR("No function at address"));
    
    std::set<ea_t> callees;
    
    func_item_iterator_t fii;
    for (bool ok = fii.set(pfn); ok; ok = fii.next_addr())
    {
        ea_t item_ea = fii.current();
        xrefblk_t xb;
        for (bool xok = xb.first_from(item_ea, XREF_ALL); xok; xok = xb.next_from())
        {
            if (xb.iscode && (xb.type == fl_CN || xb.type == fl_CF))
            {
                func_t* callee = get_func(xb.to);
                if (callee)
                    callees.insert(callee->start_ea);
            }
        }
    }
    
    json result = json::array();
    for (ea_t callee_ea : callees)
    {
        qstring name;
        get_func_name(&name, callee_ea);
        result.push_back({
            {"address", helpers::format_address(callee_ea)},
            {"name", name.c_str()}
        });
    }
    
    std::ostringstream ss;
    ss << "Found " << result.size() << " callees";
    return tool_result_t::ok(ss.str(), result);
}

tool_result_t get_callers(const json& params)
{
    auto ea_opt = helpers::parse_address(params["address"].get<std::string>());
    if (!ea_opt)
        return tool_result_t::error(OBFSTR("Invalid address"));
    
    func_t* pfn = get_func(*ea_opt);
    if (!pfn)
        return tool_result_t::error(OBFSTR("No function at address"));
    
    std::set<ea_t> callers;
    
    xrefblk_t xb;
    for (bool ok = xb.first_to(pfn->start_ea, XREF_ALL); ok; ok = xb.next_to())
    {
        if (xb.iscode && (xb.type == fl_CN || xb.type == fl_CF))
        {
            func_t* caller = get_func(xb.from);
            if (caller)
                callers.insert(caller->start_ea);
        }
    }
    
    json result = json::array();
    for (ea_t caller_ea : callers)
    {
        qstring name;
        get_func_name(&name, caller_ea);
        result.push_back({
            {"address", helpers::format_address(caller_ea)},
            {"name", name.c_str()}
        });
    }
    
    std::ostringstream ss;
    ss << "Found " << result.size() << " callers";
    return tool_result_t::ok(ss.str(), result);
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
        return tool_result_t::ok(OBFSTR("Function renamed to: ") + new_name);
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

tool_result_t get_function_signature(const json& params)
{
    auto ea_opt = helpers::parse_address(params["address"].get<std::string>());
    if (!ea_opt)
        return tool_result_t::error(OBFSTR("Invalid address"));
    
    func_t* pfn = get_func(*ea_opt);
    if (!pfn)
        return tool_result_t::error(OBFSTR("No function at address"));
    
    tinfo_t tif;
    if (!get_tinfo(&tif, pfn->start_ea))
        return tool_result_t::error(OBFSTR("No type information available"));
    
    qstring proto;
    tif.print(&proto);
    
    json result;
    result["address"] = helpers::format_address(pfn->start_ea);
    result["signature"] = proto.c_str();
    
    func_type_data_t ftd;
    if (tif.get_func_details(&ftd))
    {
        json args = json::array();
        for (size_t i = 0; i < ftd.size(); i++)
        {
            const funcarg_t& arg = ftd[i];
            qstring arg_type;
            arg.type.print(&arg_type);
            args.push_back({
                {"name", arg.name.c_str()},
                {"type", arg_type.c_str()}
            });
        }
        result["arguments"] = args;
        
        qstring ret_type;
        ftd.rettype.print(&ret_type);
        result["return_type"] = ret_type.c_str();
    }
    
    return tool_result_t::ok(OBFSTR("Function signature retrieved"), result);
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

tool_result_t analyze_function(const json& params)
{
    auto ea_opt = helpers::parse_address(params["address"].get<std::string>());
    if (!ea_opt)
        return tool_result_t::error(OBFSTR("Invalid address"));
    
    func_t* pfn = get_func(*ea_opt);
    if (!pfn)
        return tool_result_t::error(OBFSTR("No function at address"));
    
    json result;
    
    qstring func_name;
    get_func_name(&func_name, pfn->start_ea);
    result["name"] = func_name.c_str();
    result["address"] = helpers::format_address(pfn->start_ea);
    result["end_address"] = helpers::format_address(pfn->end_ea);
    result["size"] = pfn->end_ea - pfn->start_ea;
    
    result["decompiled_code"] = helpers::get_pseudocode(pfn->start_ea);
    
    {
        auto callers_result = get_callers({{"address", helpers::format_address(pfn->start_ea)}});
        result["callers"] = callers_result.data;
        
        auto callees_result = get_callees({{"address", helpers::format_address(pfn->start_ea)}});
        result["callees"] = callees_result.data;
    }
    
    {
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
        result["strings"] = strings;
    }
    
    return tool_result_t::ok(OBFSTR("Comprehensive analysis complete"), result);
}

tool_result_t build_call_graph(const json& params)
{
    auto ea_opt = helpers::parse_address(params["address"].get<std::string>());
    if (!ea_opt)
        return tool_result_t::error(OBFSTR("Invalid address"));
    
    int depth = params.value("depth", 3);
    
    std::map<ea_t, json> nodes;
    std::set<std::pair<ea_t, ea_t>> edges;
    
    std::function<void(ea_t, int)> traverse;
    traverse = [&](ea_t ea, int current_depth) {
        if (current_depth > depth) return;
        if (nodes.count(ea)) return;
        
        func_t* pfn = get_func(ea);
        if (!pfn) return;
        
        qstring name;
        get_func_name(&name, pfn->start_ea);
        
        nodes[ea] = {
            {"address", helpers::format_address(ea)},
            {"name", name.c_str()},
            {"depth", current_depth}
        };
        
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
                        traverse(callee->start_ea, current_depth + 1);
                    }
                }
            }
        }
    };
    
    traverse(*ea_opt, 0);
    
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

tool_result_t export_function(const json& params)
{
    auto ea_opt = helpers::parse_address(params["address"].get<std::string>());
    if (!ea_opt)
        return tool_result_t::error(OBFSTR("Invalid address"));
    
    std::string format = params.value("format", "json");
    
    func_t* pfn = get_func(*ea_opt);
    if (!pfn)
        return tool_result_t::error(OBFSTR("No function at address"));
    
    json result;
    
    if (format == "json")
    {
        qstring name;
        get_func_name(&name, pfn->start_ea);
        result["name"] = name.c_str();
        result["address"] = helpers::format_address(pfn->start_ea);
        result["code"] = helpers::get_pseudocode(pfn->start_ea);
        result["disassembly"] = helpers::get_disassembly(pfn->start_ea, pfn->end_ea);
    }
    else if (format == "c_header")
    {
        tinfo_t tif;
        qstring proto;
        if (get_tinfo(&tif, pfn->start_ea))
            tif.print(&proto);
        result["header"] = proto.c_str();
    }
    else if (format == "prototype")
    {
        tinfo_t tif;
        qstring proto;
        if (get_tinfo(&tif, pfn->start_ea))
            tif.print(&proto);
        result["prototype"] = proto.c_str();
    }
    
    return tool_result_t::ok(OBFSTR("Function exported"), result);
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
        decompile_function
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
        OBFSTR("get_callees"),
        OBFSTR("function"),
        OBFSTR("Get all functions called by the function at the given address."),
        {{OBFSTR("address"), OBFSTR("string"), OBFSTR("Function address"), true}},
        get_callees
    });
    
    registry.register_tool({
        OBFSTR("get_callers"),
        OBFSTR("function"),
        OBFSTR("Get all functions that call the function at the given address."),
        {{OBFSTR("address"), OBFSTR("string"), OBFSTR("Function address"), true}},
        get_callers
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
        OBFSTR("get_function_signature"),
        OBFSTR("function"),
        OBFSTR("Get the type signature/prototype of a function."),
        {{OBFSTR("address"), OBFSTR("string"), OBFSTR("Function address"), true}},
        get_function_signature
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
        OBFSTR("analyze_function"),
        OBFSTR("function"),
        OBFSTR("Comprehensive function analysis: decompilation, xrefs, callers, callees, strings, etc."),
        {{OBFSTR("address"), OBFSTR("string"), OBFSTR("Function address"), true}},
        analyze_function
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
    
    registry.register_tool({
        OBFSTR("export_function"),
        OBFSTR("function"),
        OBFSTR("Export function in specified format (json, c_header, prototype)."),
        {
            {OBFSTR("address"), OBFSTR("string"), OBFSTR("Function address"), true},
            {OBFSTR("format"), OBFSTR("string"), OBFSTR("Export format"), false, {OBFSTR("json"), OBFSTR("c_header"), OBFSTR("prototype")}}
        },
        export_function
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
        if (!put_byte(*ea_opt + i, bytes[i]))
            return tool_result_t::error(OBFSTR("Failed to patch byte at offset ") + std::to_string(i));
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

tool_result_t convert_number(const json& params)
{
    std::string value_str = params["value"].get<std::string>();
    
    while (!value_str.empty() && std::isspace(static_cast<unsigned char>(value_str.front())))
        value_str.erase(value_str.begin());
    while (!value_str.empty() && std::isspace(static_cast<unsigned char>(value_str.back())))
        value_str.pop_back();
    
    if (value_str.empty())
        return tool_result_t::error(OBFSTR("Empty value string"));
    
    uint64_t value = 0;
    bool parsed = false;
    std::string input_base = "unknown";
    
    bool is_negative = (!value_str.empty() && value_str[0] == '-');
    if (is_negative)
    {
        try
        {
            size_t idx = 0;
            int64_t sval = std::stoll(value_str, &idx, 0);
            if (idx == value_str.length())
            {
                value = static_cast<uint64_t>(sval);
                parsed = true;
                input_base = "decimal";
            }
        }
        catch (...) {}
    }
    
    if (!parsed)
    {
        ea_t ea_val = 0;
        if (atoea(&ea_val, value_str.c_str()))
        {
            value = static_cast<uint64_t>(ea_val);
            parsed = true;
            
            if (value_str.size() > 2
                && value_str[0] == '0'
                && (value_str[1] == 'x' || value_str[1] == 'X'))
                input_base = "hexadecimal";
            else if (value_str.size() > 2
                     && value_str[0] == '0'
                     && (value_str[1] == 'b' || value_str[1] == 'B'))
                input_base = "binary";
            else if (value_str.size() > 1
                     && value_str[0] == '0'
                     && std::isdigit(static_cast<unsigned char>(value_str[1])))
                input_base = "octal";
            else
                input_base = "decimal";
        }
    }
    
    if (!parsed)
    {
        try
        {
            size_t idx = 0;
            if (value_str.size() > 2
                && value_str[0] == '0'
                && (value_str[1] == 'b' || value_str[1] == 'B'))
            {
                value = std::stoull(value_str.substr(2), &idx, 2);
                if (idx == value_str.length() - 2)
                {
                    parsed = true;
                    input_base = "binary";
                }
            }
            else
            {
                value = std::stoull(value_str, &idx, 0);
                if (idx == value_str.length())
                {
                    parsed = true;
                    if (value_str.size() > 2
                        && value_str[0] == '0'
                        && (value_str[1] == 'x' || value_str[1] == 'X'))
                        input_base = "hexadecimal";
                    else if (value_str.size() > 1 && value_str[0] == '0')
                        input_base = "octal";
                    else
                        input_base = "decimal";
                }
            }
        }
        catch (...) {}
    }
    
    if (!parsed)
        return tool_result_t::error(OBFSTR("Invalid number: ") + value_str);
    
    int min_bytes;
    if (value <= 0xFFULL)
        min_bytes = 1;
    else if (value <= 0xFFFFULL)
        min_bytes = 2;
    else if (value <= 0xFFFFFFFFULL)
        min_bytes = 4;
    else
        min_bytes = 8;
    
    int display_bytes = min_bytes;
    if (params.contains("size") && params["size"].is_number())
    {
        int requested = params["size"].get<int>();
        if (requested == 1 || requested == 2 || requested == 4 || requested == 8)
            display_bytes = std::max(requested, min_bytes);
    }
    
    json result;
    
    result["input"] = value_str;
    result["input_base"] = input_base;
    
    result["decimal"] = value;
    result["signed_decimal"] = static_cast<int64_t>(value);
    
    std::ostringstream hex_ss;
    hex_ss << "0x" << std::hex << std::uppercase << value;
    result["hex"] = hex_ss.str();
    
    std::ostringstream oct_ss;
    oct_ss << "0" << std::oct << value;
    result["octal"] = oct_ss.str();
    
    std::string binary;
    uint64_t temp = value;
    do {
        binary = static_cast<char>('0' + (temp & 1)) + binary;
        temp >>= 1;
    } while (temp);
    result["binary"] = "0b" + binary;
    
    result["min_size_bytes"] = min_bytes;
    
    auto format_bytes_le = [](uint64_t val, int num_bytes) -> std::string {
        std::ostringstream ss;
        for (int i = 0; i < num_bytes; i++)
        {
            if (i > 0) ss << " ";
            ss << std::hex << std::uppercase << std::setw(2) << std::setfill('0')
               << ((val >> (i * 8)) & 0xFF);
        }
        return ss.str();
    };
    
    auto format_bytes_be = [](uint64_t val, int num_bytes) -> std::string {
        std::ostringstream ss;
        for (int i = num_bytes - 1; i >= 0; i--)
        {
            if (i < num_bytes - 1) ss << " ";
            ss << std::hex << std::uppercase << std::setw(2) << std::setfill('0')
               << ((val >> (i * 8)) & 0xFF);
        }
        return ss.str();
    };
    
    result["bytes_le"] = format_bytes_le(value, display_bytes);
    result["bytes_be"] = format_bytes_be(value, display_bytes);
    
    if (min_bytes <= 1)
    {
        result["as_int8_le"] = format_bytes_le(value, 1);
        result["as_int8_signed"] = static_cast<int64_t>(extend_sign(value, 1, true));
    }
    if (min_bytes <= 2)
    {
        result["as_int16_le"] = format_bytes_le(value, 2);
        result["as_int16_be"] = format_bytes_be(value, 2);
        result["as_int16_signed"] = static_cast<int64_t>(extend_sign(value, 2, true));
    }
    if (min_bytes <= 4)
    {
        result["as_int32_le"] = format_bytes_le(value, 4);
        result["as_int32_be"] = format_bytes_be(value, 4);
        result["as_int32_signed"] = static_cast<int64_t>(extend_sign(value, 4, true));
    }
    result["as_int64_le"] = format_bytes_le(value, 8);
    result["as_int64_be"] = format_bytes_be(value, 8);
    result["as_int64_signed"] = static_cast<int64_t>(value);
    
    std::string ascii_le;
    for (int i = 0; i < display_bytes; i++)
    {
        char c = static_cast<char>((value >> (i * 8)) & 0xFF);
        if (c >= 32 && c < 127)
            ascii_le += c;
        else
            ascii_le += '.';
    }
    result["ascii"] = ascii_le;
    
    std::string ascii_be;
    for (int i = display_bytes - 1; i >= 0; i--)
    {
        char c = static_cast<char>((value >> (i * 8)) & 0xFF);
        if (c >= 32 && c < 127)
            ascii_be += c;
        else
            ascii_be += '.';
    }
    result["ascii_be"] = ascii_be;
    
    if (min_bytes <= 4)
    {
        uint32_t f_bits = static_cast<uint32_t>(value & 0xFFFFFFFF);
        float f;
        std::memcpy(&f, &f_bits, sizeof(float));
        if (std::isfinite(f))
            result["as_float"] = f;
    }
    
    {
        double d;
        std::memcpy(&d, &value, sizeof(double));
        if (std::isfinite(d))
            result["as_double"] = d;
    }
    
    return tool_result_t::ok(OBFSTR("Number converted"), result);
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
    
    registry.register_tool({
        OBFSTR("convert_number"),
        OBFSTR("memory"),
        OBFSTR("[MANDATORY for base conversions] Convert a number between bases and show byte/ASCII ") +
        OBFSTR("representation. You MUST use this tool for all hex-to-decimal conversions and for ") +
        OBFSTR("interpreting hex values as ASCII characters — NEVER do those manually. ") +
        OBFSTR("Returns: `input` (echo), `input_base` (detected base), `decimal` (unsigned), ") +
        OBFSTR("`signed_decimal` (int64 interpretation), `hex`, `octal`, `binary`, `bytes_le`, ") +
        OBFSTR("`bytes_be`, `ascii` (LE byte order), and `ascii_be` (BE / natural string order). ") +
        OBFSTR("`min_size_bytes` — the smallest standard integer width (1, 2, 4, or 8) that holds the value. ") +
        OBFSTR("Per-width fields: `as_int8_le`, `as_int16_le`/`as_int16_be`, `as_int32_le`/`as_int32_be`, ") +
        OBFSTR("`as_int64_le`/`as_int64_be` are provided for each applicable width. ") +
        OBFSTR("Signed fields: `as_int8_signed`, `as_int16_signed`, `as_int32_signed`, `as_int64_signed` ") +
        OBFSTR("give the signed decimal interpretation at each width (e.g. 0xFF → as_int8_signed = -1). ") +
        OBFSTR("IEEE 754 fields: `as_float` (when min_size_bytes <= 4) and `as_double` are provided ") +
        OBFSTR("when the bit pattern represents a finite float/double — useful for game RE values. ") +
        OBFSTR("CRITICAL: when decompiled code casts a local variable to (char*) and indexes beyond ") +
        OBFSTR("min_size_bytes, the extra bytes come from ADJACENT stack variables, NOT from zero-padding. ") +
        OBFSTR("Accepts a SINGLE numeric literal: decimal (e.g. '50463490'), hex (e.g. '0x426D416C'), ") +
        OBFSTR("binary (e.g. '0b1010'), octal (e.g. '0777'), or negative decimal (e.g. '-1'). ") +
        OBFSTR("Does NOT accept arithmetic expressions — compute sums first, then pass the result."),
        {
            {OBFSTR("value"), OBFSTR("string"), OBFSTR("Number to convert (decimal, 0x hex, 0b binary, 0 octal, or negative)"), true},
            {OBFSTR("size"), OBFSTR("number"), OBFSTR("Override byte width for bytes_le/bytes_be/ascii (1, 2, 4, or 8). ") +
                OBFSTR("If omitted, uses the minimum natural size for the value."), false}
        },
        convert_number
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

tool_result_t rename_address(const json& params)
{
    auto ea_opt = helpers::parse_address(params["address"].get<std::string>());
    if (!ea_opt)
        return tool_result_t::error(OBFSTR("Invalid address"));
    
    std::string new_name = params["new_name"].get<std::string>();
    
    if (!set_name(*ea_opt, new_name.c_str(), SN_FORCE | SN_NODUMMY))
        return tool_result_t::error(OBFSTR("Failed to rename"));
    
    return tool_result_t::ok(OBFSTR("Address renamed to: ") + new_name);
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
    
    registry.register_tool({
        OBFSTR("rename_address"),
        OBFSTR("comment"),
        OBFSTR("Rename any named location (function, global, label)."),
        {
            {OBFSTR("address"), OBFSTR("string"), OBFSTR("Address to rename"), true},
            {OBFSTR("new_name"), OBFSTR("string"), OBFSTR("New name"), true}
        },
        rename_address,
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
            
            if (field_bytes <= 8)
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

tool_result_t get_enum(const json& params)
{
    return get_struct(params);
}

tool_result_t create_enum(const json& params)
{
    std::string name = params["name"].get<std::string>();
    
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
    
    tif.create_enum(etd);
    tif.set_named_type(get_idati(), name.c_str());
    
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
    
    registry.register_tool({OBFSTR("get_enum"), OBFSTR("type"),
        OBFSTR("Get enum type details including all members/values."),
        {{OBFSTR("name"), OBFSTR("string"), OBFSTR("Enum name"), true}},
        get_enum});
    
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
    
    std::regex filter_regex;
    try { filter_regex = std::regex(pattern, std::regex::icase); }
    catch (...) { return tool_result_t::error(OBFSTR("Invalid regex pattern")); }
    
    size_t total = get_strlist_qty();
    if (total == 0)
    {
        show_wait_box("HIDECANCEL\nAiDA: Building string list...");
        build_strlist();
        hide_wait_box();
        total = get_strlist_qty();
    }
    
    json strings = json::array();
    int count = 0;
    int skipped = 0;
    
    show_wait_box("HIDECANCEL\nAiDA: Searching strings (0 / %zu)...", total);
    
    for (size_t i = 0; i < total && count < limit; i++)
    {
        if (i % 5000 == 0)
        {
            replace_wait_box("HIDECANCEL\nAiDA: Searching strings (%zu / %zu)...", i, total);
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
    
    show_wait_box("HIDECANCEL\nAiDA: Searching byte pattern...");
    
    for (int i = 0; i < limit; i++)
    {
        replace_wait_box("HIDECANCEL\nAiDA: Searching byte pattern (%d found)...", i);
        user_cancelled();
        
        ea_t found = bin_search(current, end_ea, binpat,
                                BIN_SEARCH_FORWARD | BIN_SEARCH_NOBREAK | BIN_SEARCH_NOSHOW);
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
    
    ea_t start_ea = inf_get_min_ea();
    ea_t end_ea = inf_get_max_ea();
    
    if (params.contains("start"))
    {
        auto s = helpers::parse_address(params["start"].get<std::string>());
        if (s) start_ea = *s;
    }
    
    json matches = json::array();
    ea_t ea = start_ea;
    
    show_wait_box("HIDECANCEL\nAiDA: Searching instructions...");
    
    while (ea < end_ea && (int)matches.size() < limit)
    {
        replace_wait_box("HIDECANCEL\nAiDA: Searching instructions (%zu found)...", matches.size());
        user_cancelled();
        
        ea_t found = find_text(ea, 0, 0, pattern.c_str(),
                               SEARCH_DOWN | SEARCH_NEXT | SEARCH_NOSHOW);
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
    
    show_wait_box("HIDECANCEL\nAiDA: Searching immediate values...");
    
    for (int i = 0; i < limit; i++)
    {
        replace_wait_box("HIDECANCEL\nAiDA: Searching immediate values (%d found)...", i);
        user_cancelled();
        
        int opnum = -1;
        ea_t found = find_imm(ea, SEARCH_DOWN | SEARCH_NEXT | SEARCH_NOSHOW,
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

tool_result_t search_text(const json& params)
{
    std::string text = params["text"].get<std::string>();
    int limit = params.value("limit", 20);
    bool case_sensitive = params.value("case_sensitive", false);
    
    ea_t start_ea = inf_get_min_ea();
    if (params.contains("start"))
    {
        auto s = helpers::parse_address(params["start"].get<std::string>());
        if (s) start_ea = *s;
    }
    
    int flags = SEARCH_DOWN | SEARCH_NEXT | SEARCH_NOSHOW;
    if (case_sensitive)
        flags |= SEARCH_CASE;
    
    json matches = json::array();
    ea_t ea = start_ea;
    
    show_wait_box("HIDECANCEL\nAiDA: Searching text...");
    
    for (int i = 0; i < limit; i++)
    {
        replace_wait_box("HIDECANCEL\nAiDA: Searching text (%d / %d)...", i + 1, limit);
        user_cancelled();
        
        ea_t found = find_text(ea, 0, 0, text.c_str(), flags);
        if (found == BADADDR)
            break;
        
        matches.push_back({
            {"address", helpers::format_address(found)},
            {"name", helpers::get_name_or_address(found)}
        });
        
        ea = found + 1;
    }
    
    hide_wait_box();
    
    return tool_result_t::ok(OBFSTR("Found ") + std::to_string(matches.size()) + " matches", matches);
}

tool_result_t advanced_search(const json& params)
{
    std::string search_type = params["type"].get<std::string>();
    json result;
    
    if (search_type == "immediate")
    {
        return find_immediate(params);
    }
    else if (search_type == "text")
    {
        json adapted = params;
        if (!adapted.contains("text") && adapted.contains("value"))
            adapted["text"] = adapted["value"];
        return search_text(adapted);
    }
    else if (search_type == "bytes")
    {
        json adapted = params;
        if (!adapted.contains("pattern") && adapted.contains("value"))
            adapted["pattern"] = adapted["value"];
        return find_bytes(adapted);
    }
    else if (search_type == "strings")
    {
        json adapted = params;
        if (!adapted.contains("pattern") && adapted.contains("value"))
            adapted["pattern"] = adapted["value"];
        return search_strings(adapted);
    }
    else if (search_type == "code_ref")
    {
        auto ea_opt = helpers::parse_address(params["value"].get<std::string>());
        if (!ea_opt)
            return tool_result_t::error(OBFSTR("Invalid address"));
        
        json xrefs = json::array();
        xrefblk_t xb;
        int count = 0;
        int limit = params.value("limit", 50);
        
        for (bool ok = xb.first_to(*ea_opt, XREF_ALL); ok && count < limit; ok = xb.next_to())
        {
            if (xb.iscode)
            {
                xrefs.push_back({
                    {"from", helpers::format_address(xb.from)},
                    {"type", xb.type},
                    {"name", helpers::get_name_or_address(xb.from)}
                });
                count++;
            }
        }
        return tool_result_t::ok(OBFSTR("Code references found"), xrefs);
    }
    else if (search_type == "data_ref")
    {
        auto ea_opt = helpers::parse_address(params["value"].get<std::string>());
        if (!ea_opt)
            return tool_result_t::error(OBFSTR("Invalid address"));
        
        json xrefs = json::array();
        xrefblk_t xb;
        int count = 0;
        int limit = params.value("limit", 50);
        
        for (bool ok = xb.first_to(*ea_opt, XREF_ALL); ok && count < limit; ok = xb.next_to())
        {
            if (!xb.iscode)
            {
                xrefs.push_back({
                    {"from", helpers::format_address(xb.from)},
                    {"type", xb.type},
                    {"name", helpers::get_name_or_address(xb.from)}
                });
                count++;
            }
        }
        return tool_result_t::ok(OBFSTR("Data references found"), xrefs);
    }
    
    return tool_result_t::error(OBFSTR("Unknown search type: ") + search_type);
}

void register_tools()
{
    auto& registry = ToolRegistry::instance();
    
    registry.register_tool({OBFSTR("search_strings"), OBFSTR("search"),
        OBFSTR("Search strings with case-insensitive regex (paginated)."),
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
        OBFSTR("Find instruction sequence(s) in code by text match."),
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
    
    registry.register_tool({OBFSTR("search_text"), OBFSTR("search"),
        OBFSTR("Search for text in disassembly listing."),
        {{OBFSTR("text"), OBFSTR("string"), OBFSTR("Text to search for"), true},
         {OBFSTR("start"), OBFSTR("string"), OBFSTR("Start address (optional)"), false},
         {OBFSTR("case_sensitive"), OBFSTR("boolean"), OBFSTR("Case-sensitive search (default false)"), false},
         {OBFSTR("limit"), OBFSTR("number"), OBFSTR("Max results (default 20)"), false}},
        search_text});
    
    registry.register_tool({OBFSTR("advanced_search"), OBFSTR("search"),
        OBFSTR("Advanced search: immediate values, strings, data/code references."),
        {{OBFSTR("type"), OBFSTR("string"), OBFSTR("Search type"), true, {OBFSTR("immediate"), OBFSTR("text"), OBFSTR("bytes"), OBFSTR("strings"), OBFSTR("code_ref"), OBFSTR("data_ref")}},
         {OBFSTR("value"), OBFSTR("string"), OBFSTR("Search value/pattern"), true},
         {OBFSTR("start"), OBFSTR("string"), OBFSTR("Start address (optional)"), false},
         {OBFSTR("limit"), OBFSTR("number"), OBFSTR("Max results (default 50)"), false}},
        advanced_search});
}

}

namespace debugger_tools
{

tool_result_t get_debugger_state(const json&)
{
    int state = get_process_state();
    
    json result;
    result["state"] = state;
    result["state_name"] = state == DSTATE_SUSP ? "suspended"
                         : state == DSTATE_NOTASK ? "no_process"
                         : state == DSTATE_RUN ? "running" : "unknown";
    result["has_debugger"] = dbg != nullptr;
    
    if (dbg != nullptr)
    {
        result["debugger_name"] = dbg->name;
    }
    
    return tool_result_t::ok(OBFSTR("Debugger state retrieved"), result);
}

tool_result_t start_process(const json& params)
{
    std::string path = params.value("path", "");
    std::string args = params.value("args", "");
    std::string sdir = params.value("sdir", "");
    
    int rc = ::start_process(
        path.empty() ? nullptr : path.c_str(),
        args.empty() ? nullptr : args.c_str(),
        sdir.empty() ? nullptr : sdir.c_str());
    
    if (rc < 0)
        return tool_result_t::error(OBFSTR("Cannot create process"));
    if (rc == 0)
        return tool_result_t::error(OBFSTR("Process start cancelled"));
    
    return tool_result_t::ok(OBFSTR("Process started"));
}

tool_result_t exit_process(const json&)
{
    if (!::exit_process())
        return tool_result_t::error(OBFSTR("Failed to exit process"));
    return tool_result_t::ok(OBFSTR("Process exit requested"));
}

tool_result_t attach_process(const json& params)
{
    pid_t pid = params.value("pid", (int)NO_PROCESS);
    int rc = ::attach_process(pid);
    
    if (rc < 0)
        return tool_result_t::error(OBFSTR("Cannot attach to process"));
    if (rc == 0)
        return tool_result_t::error(OBFSTR("Attach cancelled"));
    return tool_result_t::ok(OBFSTR("Attached to process"));
}

tool_result_t detach_process(const json&)
{
    if (!::detach_process())
        return tool_result_t::error(OBFSTR("Failed to detach"));
    return tool_result_t::ok(OBFSTR("Detached from process"));
}

tool_result_t continue_execution(const json&)
{
    if (!::continue_process())
        return tool_result_t::error(OBFSTR("Failed to continue execution"));
    return tool_result_t::ok(OBFSTR("Execution continued"));
}

tool_result_t run_to_address(const json& params)
{
    auto ea_opt = helpers::parse_address(params["address"].get<std::string>());
    if (!ea_opt)
        return tool_result_t::error(OBFSTR("Invalid address"));
    
    if (!::run_to(*ea_opt))
        return tool_result_t::error(OBFSTR("Failed to run to address"));
    return tool_result_t::ok(OBFSTR("Running to ") + helpers::format_address(*ea_opt));
}

tool_result_t step_into(const json&)
{
    if (!::step_into())
        return tool_result_t::error(OBFSTR("Failed to step into"));
    return tool_result_t::ok(OBFSTR("Stepped into"));
}

tool_result_t step_over(const json&)
{
    if (!::step_over())
        return tool_result_t::error(OBFSTR("Failed to step over"));
    return tool_result_t::ok(OBFSTR("Stepped over"));
}

tool_result_t step_out(const json&)
{
    if (!::step_until_ret())
        return tool_result_t::error(OBFSTR("Failed to step out"));
    return tool_result_t::ok(OBFSTR("Step until return"));
}

tool_result_t suspend(const json&)
{
    if (!::suspend_process())
        return tool_result_t::error(OBFSTR("Failed to suspend"));
    return tool_result_t::ok(OBFSTR("Process suspended"));
}

tool_result_t list_breakpoints(const json&)
{
    int count = get_bpt_qty();
    json bps = json::array();
    
    for (int i = 0; i < count; i++)
    {
        bpt_t bpt;
        if (getn_bpt(i, &bpt))
        {
            bps.push_back({
                {"address", helpers::format_address(bpt.ea)},
                {"size", bpt.size},
                {"type", bpt.type},
                {"enabled", (bpt.flags & BPT_ENABLED) != 0},
                {"name", helpers::get_name_or_address(bpt.ea)}
            });
        }
    }
    
    return tool_result_t::ok(OBFSTR("Found ") + std::to_string(count) + " breakpoints", bps);
}

tool_result_t add_breakpoint(const json& params)
{
    auto addresses = helpers::parse_addresses(params["address"]);
    if (addresses.empty())
        return tool_result_t::error(OBFSTR("No valid address"));
    
    json results = json::array();
    for (ea_t ea : addresses)
    {
        bool ok = ::add_bpt(ea, 0, BPT_DEFAULT);
        results.push_back({
            {"address", helpers::format_address(ea)},
            {"success", ok}
        });
    }
    
    return tool_result_t::ok(OBFSTR("Breakpoints processed"), results);
}

tool_result_t delete_breakpoint(const json& params)
{
    auto addresses = helpers::parse_addresses(params["address"]);
    if (addresses.empty())
        return tool_result_t::error(OBFSTR("No valid address"));
    
    json results = json::array();
    for (ea_t ea : addresses)
    {
        bool ok = ::del_bpt(ea);
        results.push_back({
            {"address", helpers::format_address(ea)},
            {"success", ok}
        });
    }
    
    return tool_result_t::ok(OBFSTR("Breakpoints deleted"), results);
}

tool_result_t toggle_breakpoint(const json& params)
{
    auto ea_opt = helpers::parse_address(params["address"].get<std::string>());
    if (!ea_opt)
        return tool_result_t::error(OBFSTR("Invalid address"));
    
    bool enable = params.value("enable", true);
    
    if (!::enable_bpt(*ea_opt, enable))
        return tool_result_t::error(OBFSTR("Failed to toggle breakpoint"));
    
    return tool_result_t::ok(std::string(enable ? "Enabled" : "Disabled") + " breakpoint at " + helpers::format_address(*ea_opt));
}

tool_result_t get_registers(const json& params)
{
    std::string mode = params.value("mode", "gp_current");
    
    if (get_process_state() != DSTATE_SUSP)
        return tool_result_t::error(OBFSTR("Process must be suspended to read registers"));
    
    json regs = json::array();
    
    if (dbg == nullptr)
        return tool_result_t::error(OBFSTR("No debugger loaded"));
    
    auto read_regs_for_thread = [&](thid_t tid, bool gp_only) {
        json thread_regs = json::object();
        thread_regs["thread_id"] = tid;
        json reg_values = json::array();
        
        for (int i = 0; i < dbg->nregisters; i++)
        {
            const register_info_t& ri = dbg->regs(i);
            
            if (gp_only && (ri.flags & (REGISTER_IP | REGISTER_SP | REGISTER_FP | REGISTER_ADDRESS)) == 0
                && ri.dtype != dt_qword && ri.dtype != dt_dword)
                continue;
            
            regval_t rv;
            if (get_reg_val(ri.name, &rv))
            {
                json reg;
                reg["name"] = ri.name;
                reg["value"] = helpers::format_address(rv.ival);
                reg["raw"] = rv.ival;
                reg_values.push_back(reg);
            }
        }
        
        thread_regs["registers"] = reg_values;
        return thread_regs;
    };
    
    if (mode == "all_current" || mode == "gp_current")
    {
        bool gp_only = (mode == "gp_current");
        thid_t tid = get_current_thread();
        json thread_regs = read_regs_for_thread(tid, gp_only);
        return tool_result_t::ok(OBFSTR("Registers read"), thread_regs);
    }
    else if (mode == "all_threads")
    {
        json all_threads = json::array();
        int thread_count = get_thread_qty();
        thid_t original = get_current_thread();
        
        for (int i = 0; i < thread_count; i++)
        {
            thid_t tid = getn_thread(i);
            select_thread(tid);
            all_threads.push_back(read_regs_for_thread(tid, false));
        }
        
        select_thread(original);
        return tool_result_t::ok(OBFSTR("All thread registers read"), all_threads);
    }
    else if (mode == "named")
    {
        if (!params.contains("names"))
            return tool_result_t::error(OBFSTR("Parameter 'names' required for named mode"));
        
        json result = json::array();
        for (const auto& name_val : params["names"])
        {
            if (!name_val.is_string()) continue;
            std::string rname = name_val.get<std::string>();
            regval_t rv;
            if (get_reg_val(rname.c_str(), &rv))
            {
                result.push_back({
                    {"name", rname},
                    {"value", helpers::format_address(rv.ival)},
                    {"raw", rv.ival}
                });
            }
            else
            {
                result.push_back({{"name", rname}, {"error", "cannot read"}});
            }
        }
        return tool_result_t::ok(OBFSTR("Named registers read"), result);
    }
    
    return tool_result_t::error(OBFSTR("Unknown mode: ") + mode);
}

tool_result_t set_register(const json& params)
{
    std::string name = params["name"].get<std::string>();
    uint64_t value = params["value"].get<uint64_t>();
    
    if (get_process_state() != DSTATE_SUSP)
        return tool_result_t::error(OBFSTR("Process must be suspended"));
    
    if (!::set_reg_val(name.c_str(), value))
        return tool_result_t::error(OBFSTR("Failed to set register: ") + name);
    
    return tool_result_t::ok(OBFSTR("Register ") + name + " set to " + helpers::format_address(value));
}

tool_result_t get_call_stack(const json& params)
{
    if (get_process_state() != DSTATE_SUSP)
        return tool_result_t::error(OBFSTR("Process must be suspended"));
    
    thid_t tid = get_current_thread();
    if (params.contains("thread_id"))
        tid = params["thread_id"].get<thid_t>();
    
    call_stack_t stack;
    if (!collect_stack_trace(tid, &stack))
        return tool_result_t::error(OBFSTR("Failed to collect stack trace"));
    
    json frames = json::array();
    for (size_t i = 0; i < stack.size(); i++)
    {
        const call_stack_info_t& frame = stack[i];
        
        json f;
        f["index"] = i;
        f["return_address"] = helpers::format_address(frame.callea);
        f["function_address"] = helpers::format_address(frame.funcea);
        f["frame_pointer"] = helpers::format_address(frame.fp);
        
        if (frame.funcok)
        {
            qstring fname;
            get_func_name(&fname, frame.funcea);
            f["function_name"] = fname.c_str();
        }
        
        segment_t* seg = getseg(frame.callea);
        if (seg)
        {
            qstring seg_name;
            get_segm_name(&seg_name, seg);
            f["module"] = seg_name.c_str();
        }
        
        frames.push_back(f);
    }
    
    return tool_result_t::ok(OBFSTR("Call stack collected"), frames);
}

tool_result_t read_memory(const json& params)
{
    auto ea_opt = helpers::parse_address(params["address"].get<std::string>());
    if (!ea_opt)
        return tool_result_t::error(OBFSTR("Invalid address"));
    
    size_t size = params.value("size", 256);
    if (size > 65536)
        return tool_result_t::error(OBFSTR("Size too large (max 65536)"));
    
    if (get_process_state() == DSTATE_NOTASK)
        return tool_result_t::error(OBFSTR("No process running"));
    
    std::vector<uint8_t> buffer(size);
    ssize_t bytes_read = ::read_dbg_memory(*ea_opt, buffer.data(), size);
    
    if (bytes_read <= 0)
        return tool_result_t::error(OBFSTR("Failed to read debugger memory"));
    
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
    
    return tool_result_t::ok(OBFSTR("Memory read"), result);
}

tool_result_t write_memory(const json& params)
{
    auto ea_opt = helpers::parse_address(params["address"].get<std::string>());
    if (!ea_opt)
        return tool_result_t::error(OBFSTR("Invalid address"));
    
    std::string hex_bytes = params["bytes"].get<std::string>();
    hex_bytes.erase(std::remove(hex_bytes.begin(), hex_bytes.end(), ' '), hex_bytes.end());
    
    std::vector<uint8_t> bytes;
    for (size_t i = 0; i + 1 < hex_bytes.length(); i += 2)
    {
        try { bytes.push_back(static_cast<uint8_t>(std::stoul(hex_bytes.substr(i, 2), nullptr, 16))); }
        catch (...) { return tool_result_t::error(OBFSTR("Invalid hex byte")); }
    }
    
    if (get_process_state() == DSTATE_NOTASK)
        return tool_result_t::error(OBFSTR("No process running"));
    
    ssize_t written = ::write_dbg_memory(*ea_opt, bytes.data(), bytes.size());
    if (written <= 0)
        return tool_result_t::error(OBFSTR("Failed to write debugger memory"));
    
    json result;
    result["address"] = helpers::format_address(*ea_opt);
    result["bytes_written"] = written;
    
    return tool_result_t::ok(OBFSTR("Memory written"), result);
}

tool_result_t get_threads(const json&)
{
    json threads = json::array();
    int count = get_thread_qty();
    thid_t current = get_current_thread();
    
    for (int i = 0; i < count; i++)
    {
        thid_t tid = getn_thread(i);
        const char* tname = getn_thread_name(i);
        
        threads.push_back({
            {"index", i},
            {"thread_id", tid},
            {"name", tname ? tname : ""},
            {"is_current", tid == current}
        });
    }
    
    return tool_result_t::ok(OBFSTR("Found ") + std::to_string(count) + " threads", threads);
}

tool_result_t select_thread(const json& params)
{
    thid_t tid = params["thread_id"].get<thid_t>();
    
    if (!::select_thread(tid))
        return tool_result_t::error(OBFSTR("Failed to select thread"));
    
    return tool_result_t::ok(OBFSTR("Thread selected: ") + std::to_string(tid));
}

tool_result_t get_modules(const json&)
{
    json modules = json::array();

    if (get_process_state() != DSTATE_NOTASK)
    {
        modinfo_t mi;
        bool ok = get_first_module(&mi);
        while (ok)
        {
            json m;
            m["name"]  = mi.name.c_str();
            m["base"]  = helpers::format_address(mi.base);
            m["size"]  = mi.size;
            m["rebase_to"] = helpers::format_address(mi.rebase_to);
            modules.push_back(m);
            ok = get_next_module(&mi);
        }
    }

    if (modules.empty())
    {
        int segcount = get_segm_qty();
        std::set<std::string> seen;
        for (int i = 0; i < segcount; i++)
        {
            segment_t* seg = getnseg(i);
            if (!seg) continue;
            qstring sn;
            get_segm_name(&sn, seg);
            std::string key(sn.c_str());
            if (seen.count(key)) continue;
            seen.insert(key);
            modules.push_back({
                {"name",  sn.c_str()},
                {"base",  helpers::format_address(seg->start_ea)},
                {"size",  seg->end_ea - seg->start_ea},
                {"rebase_to", helpers::format_address(BADADDR)}
            });
        }
    }

    return tool_result_t::ok(OBFSTR("Found ") + std::to_string(modules.size()) + " modules", modules);
}

tool_result_t wait_for_event(const json& params)
{
    int timeout = params.value("timeout", 1);
    bool silent = params.value("silent", true);

    int wfne = WFNE_SUSP | WFNE_CONT;
    if (silent) wfne |= WFNE_SILENT;
    if (params.value("any", false)) wfne = (wfne & ~WFNE_SUSP) | WFNE_ANY;
    if (params.value("nowait", false)) wfne |= WFNE_NOWAIT;

    dbg_event_code_t rc = wait_for_next_event(wfne, timeout);

    json result;
    result["code"] = (int)rc;
    if (rc == DEC_NOTASK)
        result["status"] = "no_process";
    else if (rc == DEC_ERROR)
        result["status"] = "error";
    else if (rc == DEC_TIMEOUT)
        result["status"] = "timeout";
    else
    {
        result["status"] = "event";
        result["event_id"] = (int)rc;
        const debug_event_t* ev = get_debug_event();
        if (ev)
        {
            result["pid"] = ev->pid;
            result["tid"] = ev->tid;
            result["ea"]  = helpers::format_address(ev->ea);
            result["handled"] = ev->handled;
            event_id_t eid = ev->eid();
            const char* eid_name = "unknown";
            switch (eid)
            {
                case NO_EVENT:          eid_name = "NO_EVENT"; break;
                case PROCESS_STARTED:   eid_name = "PROCESS_STARTED"; break;
                case PROCESS_EXITED:    eid_name = "PROCESS_EXITED"; break;
                case THREAD_STARTED:    eid_name = "THREAD_STARTED"; break;
                case THREAD_EXITED:     eid_name = "THREAD_EXITED"; break;
                case BREAKPOINT:        eid_name = "BREAKPOINT"; break;
                case STEP:              eid_name = "STEP"; break;
                case EXCEPTION:         eid_name = "EXCEPTION"; break;
                case LIB_LOADED:        eid_name = "LIB_LOADED"; break;
                case LIB_UNLOADED:      eid_name = "LIB_UNLOADED"; break;
                case INFORMATION:       eid_name = "INFORMATION"; break;
                case PROCESS_ATTACHED:  eid_name = "PROCESS_ATTACHED"; break;
                case PROCESS_DETACHED:  eid_name = "PROCESS_DETACHED"; break;
                case PROCESS_SUSPENDED: eid_name = "PROCESS_SUSPENDED"; break;
                case TRACE_FULL:        eid_name = "TRACE_FULL"; break;
                default: break;
            }
            result["event_name"] = eid_name;
        }
    }

    return tool_result_t::ok(OBFSTR("Wait completed"), result);
}

tool_result_t get_processes(const json&)
{
    procinfo_vec_t procs;
    ssize_t rc = ::get_processes(&procs);
    if (rc < 0)
        return tool_result_t::error(OBFSTR("Failed to enumerate processes"));

    json arr = json::array();
    for (const auto& pi : procs)
    {
        arr.push_back({
            {"pid", pi.pid},
            {"name", pi.name.c_str()}
        });
    }

    return tool_result_t::ok(OBFSTR("Found ") + std::to_string(arr.size()) + " processes", arr);
}

tool_result_t suspend_thread(const json& params)
{
    thid_t tid = params["thread_id"].get<thid_t>();

    if (!::suspend_thread(tid))
        return tool_result_t::error(OBFSTR("Failed to suspend thread ") + std::to_string(tid));

    return tool_result_t::ok(OBFSTR("Thread suspended: ") + std::to_string(tid));
}

tool_result_t resume_thread(const json& params)
{
    thid_t tid = params["thread_id"].get<thid_t>();

    if (!::resume_thread(tid))
        return tool_result_t::error(OBFSTR("Failed to resume thread ") + std::to_string(tid));

    return tool_result_t::ok(OBFSTR("Thread resumed: ") + std::to_string(tid));
}

tool_result_t get_memory_map(const json&)
{
    if (get_process_state() == DSTATE_NOTASK)
        return tool_result_t::error(OBFSTR("No process running"));

    meminfo_vec_t miv;
    get_dbg_memory_info(&miv);

    json arr = json::array();
    for (const auto& mi : miv)
    {
        json entry;
        entry["start"]   = helpers::format_address(mi.start_ea);
        entry["end"]     = helpers::format_address(mi.end_ea);
        entry["size"]    = mi.end_ea - mi.start_ea;
        entry["name"]    = mi.name.c_str();
        entry["sclass"]  = mi.sclass.c_str();
        entry["bitness"] = mi.bitness;

        std::string perms;
        if (mi.perm & 4) perms += "R";
        if (mi.perm & 2) perms += "W";
        if (mi.perm & 1) perms += "X";
        entry["perm"] = perms.empty() ? "---" : perms;

        arr.push_back(entry);
    }

    return tool_result_t::ok(OBFSTR("Memory map: ") + std::to_string(arr.size()) + " regions", arr);
}

tool_result_t get_exceptions(const json&)
{
    excvec_t* excs = retrieve_exceptions();
    if (!excs)
        return tool_result_t::error(OBFSTR("Failed to retrieve exceptions"));

    json arr = json::array();
    for (const auto& ei : *excs)
    {
        json e;
        e["code"] = ei.code;
        e["name"] = ei.name.c_str();
        e["desc"] = ei.desc.c_str();
        e["break_on"]  = (ei.flags & EXC_BREAK) != 0;
        e["handled"]   = (ei.flags & EXC_HANDLE) != 0;
        arr.push_back(e);
    }

    return tool_result_t::ok(OBFSTR("Found ") + std::to_string(arr.size()) + " exceptions", arr);
}

tool_result_t set_breakpoint_condition(const json& params)
{
    auto ea_opt = helpers::parse_address(params["address"].get<std::string>());
    if (!ea_opt)
        return tool_result_t::error(OBFSTR("Invalid address"));

    std::string condition = params.value("condition", "");

    bpt_t bpt;
    if (!get_bpt(*ea_opt, &bpt))
        return tool_result_t::error(OBFSTR("No breakpoint at ") + helpers::format_address(*ea_opt));

    bpt.cndbody = condition.c_str();
    if (!update_bpt(&bpt))
        return tool_result_t::error(OBFSTR("Failed to update breakpoint condition"));

    if (condition.empty())
        return tool_result_t::ok(OBFSTR("Condition cleared at ") + helpers::format_address(*ea_opt));

    return tool_result_t::ok(OBFSTR("Condition set at ") + helpers::format_address(*ea_opt));
}

tool_result_t add_hardware_breakpoint(const json& params)
{
    auto ea_opt = helpers::parse_address(params["address"].get<std::string>());
    if (!ea_opt)
        return tool_result_t::error(OBFSTR("Invalid address"));

    std::string type_str = params.value("type", "exec");
    int size = params.value("size", 1);

    bpttype_t bpt_type;
    if (type_str == "write")       bpt_type = BPT_WRITE;
    else if (type_str == "read")   bpt_type = BPT_READ;
    else if (type_str == "rdwr" || type_str == "access") bpt_type = BPT_RDWR;
    else if (type_str == "exec")   bpt_type = BPT_EXEC;
    else return tool_result_t::error(OBFSTR("Invalid type. Use: write, read, rdwr, exec"));

    if (!::add_bpt(*ea_opt, size, bpt_type))
        return tool_result_t::error(OBFSTR("Failed to add hardware breakpoint"));

    json result;
    result["address"] = helpers::format_address(*ea_opt);
    result["type"]    = type_str;
    result["size"]    = size;

    return tool_result_t::ok(OBFSTR("Hardware breakpoint added"), result);
}

tool_result_t enable_tracing(const json& params)
{
    std::string trace_type = params.value("type", "step");
    bool enable = params.value("enable", true);

    json result;
    result["type"]   = trace_type;
    result["enable"] = enable;

    if (trace_type == "step")
    {
        bool ok = enable_step_trace(enable ? 1 : 0);
        result["success"] = ok;
    }
    else if (trace_type == "instruction")
    {
        bool ok = enable_insn_trace(enable);
        result["success"] = ok;
    }
    else if (trace_type == "function")
    {
        bool ok = enable_func_trace(enable);
        result["success"] = ok;
    }
    else if (trace_type == "bblock")
    {
        bool ok = enable_bblk_trace(enable);
        result["success"] = ok;
    }
    else
    {
        return tool_result_t::error(OBFSTR("Invalid trace type. Use: step, instruction, function, bblock"));
    }

    return tool_result_t::ok(
        std::string(enable ? "Enabled" : "Disabled") + " " + trace_type + " tracing", result);
}

tool_result_t get_trace_events(const json& params)
{
    int count = get_tev_qty();
    int max_events = params.value("count", 100);
    int offset = params.value("offset", 0);

    if (count == 0)
        return tool_result_t::ok(OBFSTR("No trace events"), json::array());

    json arr = json::array();
    int end = std::min(count, offset + max_events);

    for (int i = offset; i < end; i++)
    {
        tev_info_t ti;
        if (!get_tev_info(i, &ti))
            continue;

        json ev;
        ev["index"]     = i;
        ev["thread_id"] = ti.tid;
        ev["address"]   = helpers::format_address(ti.ea);

        const char* type_name = "unknown";
        switch (ti.type)
        {
            case tev_none:  type_name = "none"; break;
            case tev_insn:  type_name = "instruction"; break;
            case tev_call:  type_name = "call"; break;
            case tev_ret:   type_name = "return"; break;
            case tev_bpt:   type_name = "breakpoint"; break;
            case tev_mem:   type_name = "memory"; break;
            case tev_event: type_name = "event"; break;
            default: break;
        }
        ev["type"] = type_name;

        if (ti.type == tev_call)
        {
            ea_t callee = get_call_tev_callee(i);
            if (callee != BADADDR)
            {
                ev["callee"] = helpers::format_address(callee);
                ev["callee_name"] = helpers::get_name_or_address(callee);
            }
        }
        else if (ti.type == tev_ret)
        {
            ea_t ret_addr = get_ret_tev_return(i);
            if (ret_addr != BADADDR)
                ev["return_to"] = helpers::format_address(ret_addr);
        }
        else if (ti.type == tev_bpt)
        {
            ea_t bpt_ea = get_bpt_tev_ea(i);
            if (bpt_ea != BADADDR)
                ev["bpt_address"] = helpers::format_address(bpt_ea);
        }

        qstring sym_name;
        if (get_func_name(&sym_name, ti.ea) && !sym_name.empty())
            ev["symbol"] = sym_name.c_str();

        arr.push_back(ev);
    }

    json result;
    result["total"]  = count;
    result["offset"] = offset;
    result["returned"] = (int)arr.size();
    result["events"] = arr;

    return tool_result_t::ok(OBFSTR("Trace events retrieved"), result);
}

tool_result_t get_trace_status(const json&)
{
    json result;
    result["step_trace"]        = is_step_trace_enabled();
    result["insn_trace"]        = is_insn_trace_enabled();
    result["func_trace"]        = is_func_trace_enabled();
    result["bblk_trace"]        = is_bblk_trace_enabled();
    result["trace_event_count"] = get_tev_qty();
    result["step_options"]      = get_step_trace_options();
    result["insn_options"]      = get_insn_trace_options();
    result["func_options"]      = get_func_trace_options();
    result["bblk_options"]      = get_bblk_trace_options();

    return tool_result_t::ok(OBFSTR("Trace status"), result);
}

tool_result_t clear_trace_events(const json&)
{
    clear_trace();
    return tool_result_t::ok(OBFSTR("Trace buffer cleared"));
}

tool_result_t set_trace_size_tool(const json& params)
{
    int size = params.value("size", 0);
    if (!set_trace_size(size))
        return tool_result_t::error(OBFSTR("Failed to set trace buffer size"));
    return tool_result_t::ok(OBFSTR("Trace buffer size set to ") + std::to_string(size));
}

tool_result_t set_debugger_options_tool(const json& params)
{
    uint options = 0;
    if (params.value("break_on_start", false))    options |= DOPT_START_BPT;
    if (params.value("break_on_entry", false))     options |= DOPT_ENTRY_BPT;
    if (params.value("break_on_thread", false))    options |= DOPT_THREAD_BPT;
    if (params.value("break_on_library", false))   options |= DOPT_LIB_BPT;
    if (params.value("break_on_info", false))      options |= DOPT_INFO_BPT;
    if (params.value("log_segments", false))       options |= DOPT_SEGM_MSGS;
    if (params.value("log_threads", false))        options |= DOPT_THREAD_MSGS;
    if (params.value("log_breakpoints", false))    options |= DOPT_BPT_MSGS;
    if (params.value("log_libraries", false))      options |= DOPT_LIB_MSGS;
    if (params.value("log_info", false))           options |= DOPT_INFO_MSGS;
    if (params.value("real_memory", false))        options |= DOPT_REAL_MEMORY;
    if (params.value("reconstruct_stack", false))  options |= DOPT_REDO_STACK;
    if (params.value("load_debug_info", false))    options |= DOPT_LOAD_DINFO;
    if (params.value("temp_hwbpt", false))         options |= DOPT_TEMP_HWBPT;
    if (params.value("fast_step", false))          options |= DOPT_FAST_STEP;
    if (params.value("disable_aslr", false))       options |= DOPT_DISABLE_ASLR;

    uint old_opts = set_debugger_options(options);

    json result;
    result["old_options"] = old_opts;
    result["new_options"] = options;

    return tool_result_t::ok(OBFSTR("Debugger options set"), result);
}

void register_tools()
{
    auto& registry = ToolRegistry::instance();
    
    registry.register_tool({OBFSTR("get_debugger_state"), OBFSTR("debugger"), OBFSTR("Get current debugger process state."),
        {}, get_debugger_state});
    
    registry.register_tool({OBFSTR("start_process"), OBFSTR("debugger"), OBFSTR("Start debugger process."),
        {{OBFSTR("path"), OBFSTR("string"), OBFSTR("Executable path (optional, uses IDB)"), false},
         {OBFSTR("args"), OBFSTR("string"), OBFSTR("Command line arguments"), false},
         {OBFSTR("sdir"), OBFSTR("string"), OBFSTR("Start directory"), false}},
        start_process, false});
    
    registry.register_tool({OBFSTR("exit_process"), OBFSTR("debugger"), OBFSTR("Exit/terminate debugger process."),
        {}, exit_process, false});
    
    registry.register_tool({OBFSTR("attach_process"), OBFSTR("debugger"), OBFSTR("Attach to a running process."),
        {{OBFSTR("pid"), OBFSTR("number"), OBFSTR("Process ID (optional, shows dialog if omitted)"), false}},
        attach_process, false});
    
    registry.register_tool({OBFSTR("detach_process"), OBFSTR("debugger"), OBFSTR("Detach from debugged process."),
        {}, detach_process, false});
    
    registry.register_tool({OBFSTR("continue_execution"), OBFSTR("debugger"), OBFSTR("Continue execution of debugged process."),
        {}, continue_execution, false});
    
    registry.register_tool({OBFSTR("run_to_address"), OBFSTR("debugger"), OBFSTR("Run until the specified address is reached."),
        {{OBFSTR("address"), OBFSTR("string"), OBFSTR("Target address"), true}},
        run_to_address, false});
    
    registry.register_tool({OBFSTR("step_into"), OBFSTR("debugger"), OBFSTR("Step into next instruction."),
        {}, step_into, false});
    
    registry.register_tool({OBFSTR("step_over"), OBFSTR("debugger"), OBFSTR("Step over next instruction (skip calls)."),
        {}, step_over, false});
    
    registry.register_tool({OBFSTR("step_out"), OBFSTR("debugger"), OBFSTR("Step out of current function (run until return)."),
        {}, step_out, false});
    
    registry.register_tool({OBFSTR("suspend"), OBFSTR("debugger"), OBFSTR("Suspend executing process."),
        {}, suspend, false});
    
    registry.register_tool({OBFSTR("list_breakpoints"), OBFSTR("debugger"), OBFSTR("List all breakpoints."),
        {}, list_breakpoints});
    
    registry.register_tool({OBFSTR("add_breakpoint"), OBFSTR("debugger"), OBFSTR("Add breakpoint(s) at address(es)."),
        {{OBFSTR("address"), OBFSTR("string"), OBFSTR("Address(es) - single, comma-separated, or array"), true}},
        add_breakpoint, false});
    
    registry.register_tool({OBFSTR("delete_breakpoint"), OBFSTR("debugger"), OBFSTR("Delete breakpoint(s) at address(es)."),
        {{OBFSTR("address"), OBFSTR("string"), OBFSTR("Address(es)"), true}},
        delete_breakpoint, false});
    
    registry.register_tool({OBFSTR("toggle_breakpoint"), OBFSTR("debugger"), OBFSTR("Enable/disable a breakpoint."),
        {{OBFSTR("address"), OBFSTR("string"), OBFSTR("Breakpoint address"), true},
         {OBFSTR("enable"), OBFSTR("boolean"), OBFSTR("Enable (true) or disable (false)"), false}},
        toggle_breakpoint, false});
    
    registry.register_tool({OBFSTR("get_registers"), OBFSTR("debugger"),
        OBFSTR("Read registers. Modes: gp_current, all_current, all_threads, named."),
        {{OBFSTR("mode"), OBFSTR("string"), OBFSTR("Mode"), false, {OBFSTR("gp_current"), OBFSTR("all_current"), OBFSTR("all_threads"), OBFSTR("named")}},
         {OBFSTR("names"), OBFSTR("array"), OBFSTR("Register names (for 'named' mode)"), false, {},
          json::object({{"type", "string"}})
        }},
        get_registers});
    
    registry.register_tool({OBFSTR("set_register"), OBFSTR("debugger"), OBFSTR("Set a register value."),
        {{OBFSTR("name"), OBFSTR("string"), OBFSTR("Register name"), true},
         {OBFSTR("value"), OBFSTR("number"), OBFSTR("Value to set"), true}},
        set_register, false});
    
    registry.register_tool({OBFSTR("get_call_stack"), OBFSTR("debugger"), OBFSTR("Get call stack with module/symbol info."),
        {{OBFSTR("thread_id"), OBFSTR("number"), OBFSTR("Thread ID (optional, current thread)"), false}},
        get_call_stack});
    
    registry.register_tool({OBFSTR("read_memory"), OBFSTR("debugger"), OBFSTR("Read memory from debugged process."),
        {{OBFSTR("address"), OBFSTR("string"), OBFSTR("Address"), true},
         {OBFSTR("size"), OBFSTR("number"), OBFSTR("Bytes to read (default 256, max 65536)"), false}},
        read_memory});
    
    registry.register_tool({OBFSTR("write_memory"), OBFSTR("debugger"), OBFSTR("Write memory to debugged process."),
        {{OBFSTR("address"), OBFSTR("string"), OBFSTR("Address"), true},
         {OBFSTR("bytes"), OBFSTR("string"), OBFSTR("Hex bytes (e.g., '90 90 90')"), true}},
        write_memory, false});
    
    registry.register_tool({OBFSTR("get_threads"), OBFSTR("debugger"), OBFSTR("List all threads with names."),
        {}, get_threads});
    
    registry.register_tool({OBFSTR("select_thread"), OBFSTR("debugger"), OBFSTR("Switch to a specific thread."),
        {{OBFSTR("thread_id"), OBFSTR("number"), OBFSTR("Thread ID"), true}},
        select_thread, false});
    
    registry.register_tool({OBFSTR("get_modules"), OBFSTR("debugger"), OBFSTR("List loaded modules using debugger module API (falls back to segments)."),
        {}, get_modules});

    registry.register_tool({OBFSTR("wait_for_event"), OBFSTR("debugger"),
        OBFSTR("Wait for next debugger event. Resumes and waits until suspended or timeout."),
        {{OBFSTR("timeout"), OBFSTR("number"), OBFSTR("Seconds to wait (-1=infinite, default 1)"), false},
         {OBFSTR("silent"), OBFSTR("boolean"), OBFSTR("Suppress modal dialogs (default true)"), false},
         {OBFSTR("any"), OBFSTR("boolean"), OBFSTR("Return first event even if non-suspending (default false)"), false},
         {OBFSTR("nowait"), OBFSTR("boolean"), OBFSTR("Return immediately (default false)"), false}},
        wait_for_event, false});

    registry.register_tool({OBFSTR("get_processes"), OBFSTR("debugger"),
        OBFSTR("Enumerate running processes available for attaching."),
        {}, get_processes});

    registry.register_tool({OBFSTR("suspend_thread"), OBFSTR("debugger"), OBFSTR("Suspend a specific thread."),
        {{OBFSTR("thread_id"), OBFSTR("number"), OBFSTR("Thread ID to suspend"), true}},
        suspend_thread, false});

    registry.register_tool({OBFSTR("resume_thread"), OBFSTR("debugger"), OBFSTR("Resume a specific suspended thread."),
        {{OBFSTR("thread_id"), OBFSTR("number"), OBFSTR("Thread ID to resume"), true}},
        resume_thread, false});

    registry.register_tool({OBFSTR("get_memory_map"), OBFSTR("debugger"),
        OBFSTR("Get full memory map of debugged process with permissions."),
        {}, get_memory_map});

    registry.register_tool({OBFSTR("get_exceptions"), OBFSTR("debugger"),
        OBFSTR("List all exception definitions with break/handle settings."),
        {}, get_exceptions});

    registry.register_tool({OBFSTR("set_breakpoint_condition"), OBFSTR("debugger"),
        OBFSTR("Set or clear a condition expression on an existing breakpoint."),
        {{OBFSTR("address"), OBFSTR("string"), OBFSTR("Breakpoint address"), true},
         {OBFSTR("condition"), OBFSTR("string"), OBFSTR("Condition expression (empty to clear)"), false}},
        set_breakpoint_condition, false});

    registry.register_tool({OBFSTR("add_hardware_breakpoint"), OBFSTR("debugger"),
        OBFSTR("Add a hardware breakpoint (write/read/access/exec watchpoint)."),
        {{OBFSTR("address"), OBFSTR("string"), OBFSTR("Address"), true},
         {OBFSTR("type"), OBFSTR("string"), OBFSTR("Type: write, read, rdwr, exec"), false,
          {OBFSTR("write"), OBFSTR("read"), OBFSTR("rdwr"), OBFSTR("exec")}},
         {OBFSTR("size"), OBFSTR("number"), OBFSTR("Watchpoint size in bytes (default 1)"), false}},
        add_hardware_breakpoint, false});

    registry.register_tool({OBFSTR("enable_tracing"), OBFSTR("debugger"),
        OBFSTR("Enable or disable tracing (step/instruction/function/bblock)."),
        {{OBFSTR("type"), OBFSTR("string"), OBFSTR("Trace type"), true,
          {OBFSTR("step"), OBFSTR("instruction"), OBFSTR("function"), OBFSTR("bblock")}},
         {OBFSTR("enable"), OBFSTR("boolean"), OBFSTR("Enable (true) or disable (false)"), false}},
        enable_tracing, false});

    registry.register_tool({OBFSTR("get_trace_events"), OBFSTR("debugger"),
        OBFSTR("Read trace events from the trace buffer with call/return/bpt details."),
        {{OBFSTR("count"), OBFSTR("number"), OBFSTR("Max events to return (default 100)"), false},
         {OBFSTR("offset"), OBFSTR("number"), OBFSTR("Start offset in trace buffer (default 0)"), false}},
        get_trace_events});

    registry.register_tool({OBFSTR("get_trace_status"), OBFSTR("debugger"),
        OBFSTR("Get current tracing status: which trace types are enabled and their options."),
        {}, get_trace_status});

    registry.register_tool({OBFSTR("clear_trace_events"), OBFSTR("debugger"),
        OBFSTR("Clear all events in the trace buffer."),
        {}, clear_trace_events, false});

    registry.register_tool({OBFSTR("set_trace_size"), OBFSTR("debugger"),
        OBFSTR("Set trace buffer size (0=unlimited circular buffer)."),
        {{OBFSTR("size"), OBFSTR("number"), OBFSTR("Buffer size (0=unlimited)"), true}},
        set_trace_size_tool, false});

    registry.register_tool({OBFSTR("set_debugger_options"), OBFSTR("debugger"),
        OBFSTR("Configure debugger options: break-on events, logging, ASLR, etc."),
        {{OBFSTR("break_on_start"), OBFSTR("boolean"), OBFSTR("Break on process start"), false},
         {OBFSTR("break_on_entry"), OBFSTR("boolean"), OBFSTR("Break on entry point"), false},
         {OBFSTR("break_on_thread"), OBFSTR("boolean"), OBFSTR("Break on thread start/exit"), false},
         {OBFSTR("break_on_library"), OBFSTR("boolean"), OBFSTR("Break on library load/unload"), false},
         {OBFSTR("log_segments"), OBFSTR("boolean"), OBFSTR("Log segment modifications"), false},
         {OBFSTR("log_threads"), OBFSTR("boolean"), OBFSTR("Log thread starts/exits"), false},
         {OBFSTR("log_breakpoints"), OBFSTR("boolean"), OBFSTR("Log breakpoints"), false},
         {OBFSTR("log_libraries"), OBFSTR("boolean"), OBFSTR("Log library loads/unloads"), false},
         {OBFSTR("load_debug_info"), OBFSTR("boolean"), OBFSTR("Auto-load debug files (PDB)"), false},
         {OBFSTR("disable_aslr"), OBFSTR("boolean"), OBFSTR("Disable ASLR"), false},
         {OBFSTR("fast_step"), OBFSTR("boolean"), OBFSTR("Fast single-stepping (skip memory refresh)"), false},
         {OBFSTR("reconstruct_stack"), OBFSTR("boolean"), OBFSTR("Reconstruct the stack"), false}},
        set_debugger_options_tool, false});
}

}

namespace segment_tools
{

tool_result_t list_segments(const json&)
{
    json segments = json::array();
    int count = get_segm_qty();
    
    for (int i = 0; i < count; i++)
    {
        segment_t* seg = getnseg(i);
        if (!seg)
            continue;
        
        qstring name, sclass;
        get_segm_name(&name, seg);
        get_segm_class(&sclass, seg);
        
        const char* perm_str = "";
        std::string perms;
        if (seg->perm & SEGPERM_READ)  perms += "R";
        if (seg->perm & SEGPERM_WRITE) perms += "W";
        if (seg->perm & SEGPERM_EXEC)  perms += "X";
        
        segments.push_back({
            {"index", i},
            {"name", name.c_str()},
            {"class", sclass.c_str()},
            {"start", helpers::format_address(seg->start_ea)},
            {"end", helpers::format_address(seg->end_ea)},
            {"size", seg->end_ea - seg->start_ea},
            {"permissions", perms},
            {"bitness", seg->bitness == 0 ? 16 : seg->bitness == 1 ? 32 : 64},
            {"type", seg->type}
        });
    }
    
    return tool_result_t::ok(OBFSTR("Listed ") + std::to_string(count) + " segments", segments);
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
    
    qstring name, sclass;
    get_segm_name(&name, seg);
    get_segm_class(&sclass, seg);
    
    std::string perms;
    if (seg->perm & SEGPERM_READ) perms += "R";
    if (seg->perm & SEGPERM_WRITE) perms += "W";
    if (seg->perm & SEGPERM_EXEC) perms += "X";
    
    json result;
    result["name"] = name.c_str();
    result["class"] = sclass.c_str();
    result["start"] = helpers::format_address(seg->start_ea);
    result["end"] = helpers::format_address(seg->end_ea);
    result["size"] = seg->end_ea - seg->start_ea;
    result["permissions"] = perms;
    result["bitness"] = seg->bitness == 0 ? 16 : seg->bitness == 1 ? 32 : 64;
    result["alignment"] = seg->align;
    result["type"] = seg->type;
    
    return tool_result_t::ok(OBFSTR("Segment info retrieved"), result);
}

tool_result_t create_segment(const json& params)
{
    return tool_result_t::error(OBFSTR("Segment creation requires careful setup — use execute_python tool for advanced segment manipulation"));
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
        OBFSTR("Create a new segment (delegates to Python for safety)."),
        {{OBFSTR("start"), OBFSTR("string"), OBFSTR("Start address"), true},
         {OBFSTR("end"), OBFSTR("string"), OBFSTR("End address"), true},
         {OBFSTR("name"), OBFSTR("string"), OBFSTR("Segment name"), true}},
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

tool_result_t get_idb_info(const json&)
{
    json result;
    
    result["binary_info"] = get_binary_info({}).data;
    
    if (get_strlist_qty() == 0)
        build_strlist();
    result["string_count"] = (size_t)get_strlist_qty();
    
    til_t* ti = get_idati();
    if (ti)
        result["local_type_count"] = get_ordinal_count(ti);
    
    result["named_count"] = (size_t)get_nlist_size();
    
    return tool_result_t::ok(OBFSTR("IDB info retrieved"), result);
}

void register_tools()
{
    auto& registry = ToolRegistry::instance();
    
    registry.register_tool({OBFSTR("get_binary_info"), OBFSTR("binary"),
        OBFSTR("Get binary file metadata (processor, bitness, file type, etc)."),
        {}, get_binary_info});
    
    registry.register_tool({OBFSTR("get_idb_info"), OBFSTR("binary"),
        OBFSTR("Get IDA database info (function count, types, strings, etc)."),
        {}, get_idb_info});
}

}

namespace python_tools
{

tool_result_t execute_python(const json& params)
{
    std::string code = params["code"].get<std::string>();
    
    std::string wrapper = R"PY(
import sys, io, json as _json
_aida_stdout = io.StringIO()
_aida_stderr = io.StringIO()
_aida_result = None
try:
    _old_stdout, _old_stderr = sys.stdout, sys.stderr
    sys.stdout, sys.stderr = _aida_stdout, _aida_stderr
    try:
        _aida_result = eval(compile("""
)PY";
    wrapper += code;
    wrapper += R"PY(
""", "<aida>", "eval"))
    except SyntaxError:
        exec(compile("""
)PY";
    wrapper += code;
    wrapper += R"PY(
""", "<aida>", "exec"))
    sys.stdout, sys.stderr = _old_stdout, _old_stderr
except Exception as _e:
    sys.stdout, sys.stderr = _old_stdout, _old_stderr
    _aida_stderr.write(str(_e))
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

namespace memory_tools
{

tool_result_t patch_instruction(const json& params)
{
    auto ea_opt = helpers::parse_address(params["address"].get<std::string>());
    if (!ea_opt)
        return tool_result_t::error(OBFSTR("Invalid address"));
    
    std::string assembly = params["assembly"].get<std::string>();
    
    std::string py_code = "import ida_idp, ida_bytes, idc\n"
        "ea = " + std::to_string(*ea_opt) + "\n"
        "ok, buf = ida_idp.assemble(ea, 0, ea, True, '" + assembly + "')\n"
        "_aida_patch_result = False\n"
        "_aida_patch_size = 0\n"
        "if ok and buf:\n"
        "    ida_bytes.patch_bytes(ea, bytes(buf))\n"
        "    _aida_patch_result = True\n"
        "    _aida_patch_size = len(buf)\n";
    
    extlang_object_t python = find_extlang_by_name("python");
    if (!python)
        return tool_result_t::error(OBFSTR("Python not available for assembly"));
    
    qstring errbuf;
    if (!python->eval_snippet(py_code.c_str(), &errbuf))
        return tool_result_t::error(OBFSTR("Assembly failed: ") + std::string(errbuf.c_str()));
    
    idc_value_t rv;
    qstring eval_err;
    if (python->eval_expr(&rv, BADADDR, "_aida_patch_result", &eval_err)
        && rv.is_integral() && (rv.vtype == VT_INT64 ? rv.i64 : rv.num) != 0)
    {
        idc_value_t sz;
        int patch_sz = 0;
        if (python->eval_expr(&sz, BADADDR, "_aida_patch_size", &eval_err) && sz.is_integral())
            patch_sz = (int)(sz.vtype == VT_INT64 ? sz.i64 : sz.num);
        
        json result;
        result["address"] = helpers::format_address(*ea_opt);
        result["bytes_patched"] = patch_sz;
        return tool_result_t::ok(OBFSTR("Instruction patched at ") + helpers::format_address(*ea_opt), result);
    }
    
    return tool_result_t::error(OBFSTR("Assembly failed: assembler could not encode '") + assembly + "' at " + helpers::format_address(*ea_opt));
}

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
    bool ok = auto_wait();

    if (!ok)
        return tool_result_t::error(OBFSTR("Analysis was cancelled by user"));

    return tool_result_t::ok(OBFSTR("Auto-analysis completed"));
}

tool_result_t get_entry_points(const json&)
{
    size_t qty = get_entry_qty();
    json entries = json::array();

    for (size_t i = 0; i < qty; i++)
    {
        uval_t ord = get_entry_ordinal(i);
        ea_t ea = get_entry(ord);
        if (ea == BADADDR)
            continue;

        json entry;
        entry["ordinal"] = ord;
        entry["address"] = helpers::format_address(ea);

        qstring name;
        if (get_entry_name(&name, ord) > 0)
            entry["name"] = std::string(name.c_str());

        qstring fwd;
        if (get_entry_forwarder(&fwd, ord) > 0 && !fwd.empty())
            entry["forwarder"] = std::string(fwd.c_str());

        entries.push_back(entry);
    }

    json data;
    data["count"] = qty;
    data["entries"] = entries;

    return tool_result_t::ok(OBFSTR("Found ") + std::to_string(qty) + " entry points", data);
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

    registry.register_tool({OBFSTR("get_entry_points"), OBFSTR("navigation"),
        OBFSTR("List all program entry points with their ordinals, addresses, and names."),
        {},
        get_entry_points});

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

void initialize_all_tools()
{
    function_tools::register_tools();
    memory_tools::register_tools();
    comment_tools::register_tools();
    type_tools::register_tools();
    import_tools::register_tools();
    search_tools::register_tools();
    debugger_tools::register_tools();
    segment_tools::register_tools();
    binary_tools::register_tools();
    python_tools::register_tools();
    navigation_tools::register_tools();
    
    ToolRegistry::instance().register_tool({
        OBFSTR("patch_instruction"), OBFSTR("memory"),
        OBFSTR("Patch assembly instruction at the given address."),
        {{OBFSTR("address"), OBFSTR("string"), OBFSTR("Address to patch"), true},
         {OBFSTR("assembly"), OBFSTR("string"), OBFSTR("Assembly instruction (e.g., 'nop', 'mov eax, 1')"), true}},
        memory_tools::patch_instruction,
        false
    });

    ToolRegistry::instance().register_tool({
        OBFSTR("list_all_available_tools"), OBFSTR("meta"),
        OBFSTR("Returns the complete list of all available IDA Pro tools with their ") +
        OBFSTR("names, categories, descriptions, and parameter schemas. Use this ") +
        OBFSTR("tool when asked what tools or capabilities are available."),
        {
            {OBFSTR("category"), OBFSTR("string"),
             OBFSTR("Optional: filter by category (function, memory, comment, type, ") +
             OBFSTR("import, search, debugger, segment, binary, python, navigation, meta)"),
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
        true  // read-only
    });

    msg(OBFSTR_C("AiDA: Initialized %zu agent tools\n"), ToolRegistry::instance().get_tool_names().size());
}

}