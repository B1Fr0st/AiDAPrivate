#include "aida_pro.hpp"
#include <allins.hpp>
#include <iomanip>
#include <loader.hpp>
#include "../driver/comm.h"

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

static std::string get_downloads_folder()
{
    char buf[MAX_PATH] = {};
    DWORD len = GetEnvironmentVariableA("USERPROFILE", buf, MAX_PATH);
    if (len > 0 && len < MAX_PATH)
        return std::string(buf, len) + "\\Downloads\\";
    return "C:\\Users\\Public\\Downloads\\";
}

// Recursively create all directories in the path leading to `file_path`.
// Uses only Win32 API (CreateDirectoryA) - no <shlobj.h> dependency.
static void ensure_parent_dir_exists(const std::string& file_path)
{
    std::string::size_type pos = 0;
    while ((pos = file_path.find_first_of("\\/", pos + 1)) != std::string::npos)
    {
        std::string dir = file_path.substr(0, pos);
        if (dir.size() == 2 && dir[1] == ':') { pos++; continue; } // skip "C:"
        CreateDirectoryA(dir.c_str(), nullptr);
    }
}

/// Non-blocking replacement for auto_wait().
/// Uses auto_make_step() to process analysis items one at a time, periodically
/// calling user_cancelled() and replace_wait_box() to pump the UI message queue.
///
/// IDA SDK auto.hpp (line ~249):
///   auto_make_step(ea1, ea2): "Analyze one address in the specified range
///     and return true. \return if processed anything."
///   auto_is_ok(): "Are all queues empty?" (line ~261)
/// IDA SDK kernwin.hpp (line ~6993):
///   HIDECANCEL: "user_cancelled() will always return false
///     (but can be called to refresh UI)"
///
static bool responsive_auto_wait(ea_t ea1, ea_t ea2, const char* step_label = nullptr)
{
    int step_count = 0;
    int idle_spins = 0;
    constexpr int UI_PUMP_INTERVAL = 2048;
    constexpr int MAX_IDLE_SPINS   = 128;

    while (!auto_is_ok())
    {
        bool did_work = auto_make_step(ea1, ea2);
        if (!did_work)
        {
            // Items may exist in queues outside our range, try globally
            did_work = auto_make_step(0, BADADDR);
            if (!did_work)
            {
                if (++idle_spins > MAX_IDLE_SPINS)
                    break;
                // Pump UI even when idle to prevent "(Not Responding)"
                user_cancelled();
                continue;
            }
        }
        idle_spins = 0;

        if (++step_count % UI_PUMP_INTERVAL == 0)
        {
            // Pump UI to avoid Windows marking IDA as "(Not Responding)"
            if (step_label)
                replace_wait_box("HIDECANCEL\nAiDA: %s (%dk steps...)",
                                 step_label, step_count / 1000);
            else
                user_cancelled();
        }
    }
    return true;
}

/// Non-blocking replacement for plan_and_wait().
/// Replicates the behaviour documented in IDA SDK auto.hpp (line ~228):
///   "Analyze the specified range. Try to create instructions where possible.
///    Make the final pass over the specified range if specified.
///    This function doesn't return until the range is analyzed."
///
/// We break this into:
///   1. plan_range()             — marks range as AU_USED  (auto.hpp line ~163)
///   2. auto_mark_range(AU_CODE) — marks for instruction creation (AU_CODE=20, line ~39)
///   3. responsive_auto_wait()   — drains queues while pumping UI
///   4. if final_pass: auto_mark_range(AU_FINAL) — final pass queue (AU_FINAL=200, line ~52)
///   5. responsive_auto_wait()   — drains final-pass queue while pumping UI
///
static int responsive_plan_and_wait(ea_t ea1, ea_t ea2, bool final_pass,
                                    const char* step_label)
{
    // Phase 1: queue for instruction creation + reanalysis
    auto_mark_range(ea1, ea2, AU_CODE);
    plan_range(ea1, ea2);
    responsive_auto_wait(ea1, ea2, step_label);

    // Phase 2: final pass if requested
    if (final_pass)
    {
        auto_mark_range(ea1, ea2, AU_FINAL);
        responsive_auto_wait(ea1, ea2, step_label);
    }

    return 1;
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
        OBFSTR("interpreting hex values as ASCII characters ÃƒÂ¢Ã¢â€šÂ¬Ã¢â‚¬Â NEVER do those manually. ") +
        OBFSTR("Returns: `input` (echo), `input_base` (detected base), `decimal` (unsigned), ") +
        OBFSTR("`signed_decimal` (int64 interpretation), `hex`, `octal`, `binary`, `bytes_le`, ") +
        OBFSTR("`bytes_be`, `ascii` (LE byte order), and `ascii_be` (BE / natural string order). ") +
        OBFSTR("`min_size_bytes` ÃƒÂ¢Ã¢â€šÂ¬Ã¢â‚¬Â the smallest standard integer width (1, 2, 4, or 8) that holds the value. ") +
        OBFSTR("Per-width fields: `as_int8_le`, `as_int16_le`/`as_int16_be`, `as_int32_le`/`as_int32_be`, ") +
        OBFSTR("`as_int64_le`/`as_int64_be` are provided for each applicable width. ") +
        OBFSTR("Signed fields: `as_int8_signed`, `as_int16_signed`, `as_int32_signed`, `as_int64_signed` ") +
        OBFSTR("give the signed decimal interpretation at each width (e.g. 0xFF ÃƒÂ¢Ã¢â‚¬Â Ã¢â‚¬â„¢ as_int8_signed = -1). ") +
        OBFSTR("IEEE 754 fields: `as_float` (when min_size_bytes <= 4) and `as_double` are provided ") +
        OBFSTR("when the bit pattern represents a finite float/double ÃƒÂ¢Ã¢â€šÂ¬Ã¢â‚¬Â useful for game RE values. ") +
        OBFSTR("CRITICAL: when decompiled code casts a local variable to (char*) and indexes beyond ") +
        OBFSTR("min_size_bytes, the extra bytes come from ADJACENT stack variables, NOT from zero-padding. ") +
        OBFSTR("Accepts a SINGLE numeric literal: decimal (e.g. '50463490'), hex (e.g. '0x426D416C'), ") +
        OBFSTR("binary (e.g. '0b1010'), octal (e.g. '0777'), or negative decimal (e.g. '-1'). ") +
        OBFSTR("Does NOT accept arithmetic expressions ÃƒÂ¢Ã¢â€šÂ¬Ã¢â‚¬Â compute sums first, then pass the result."),
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

tool_result_t get_debugger_event_log(const json& params)
{
    size_t count = params.value("count", 50);
    uint64_t since_ts = 0;
    if (params.contains("since_ms"))
        since_ts = params["since_ms"].get<uint64_t>();

    std::vector<dbg_event_record_t> events;
    if (since_ts > 0)
        events = g_dbg_event_log.since(since_ts);
    else
        events = g_dbg_event_log.snapshot(count);

    json arr = json::array();
    for (const auto& ev : events)
    {
        json j;
        j["timestamp_ms"] = ev.timestamp_ms;
        j["notification"]  = static_cast<int>(ev.notification);
        j["ea"]            = (ev.ea != BADADDR) ? helpers::format_address(ev.ea) : "";
        j["pid"]           = ev.pid;
        j["tid"]           = ev.tid;
        j["detail"]        = ev.detail;
        arr.push_back(std::move(j));
    }

    json result;
    result["events"]      = std::move(arr);
    result["total_logged"] = g_dbg_event_log.size();
    return tool_result_t::ok(OBFSTR("Debugger event log"), result);
}

tool_result_t clear_debugger_event_log(const json&)
{
    g_dbg_event_log.clear();
    return tool_result_t::ok(OBFSTR("Debugger event log cleared"));
}

tool_result_t analyze_breakpoint_context(const json& params)
{
    auto addr = helpers::parse_address(params.value("address", std::string()));
    if (!addr)
        return tool_result_t::error(OBFSTR("Invalid address"));

    ea_t ea = *addr;
    json ctx;

    regval_t rip_val, rsp_val, rax_val, rcx_val, rdx_val, r8_val, r9_val;
    json regs;
    struct { const char* name; regval_t* val; } reg_list[] = {
        {"RIP", &rip_val}, {"RSP", &rsp_val}, {"RAX", &rax_val},
        {"RCX", &rcx_val}, {"RDX", &rdx_val}, {"R8", &r8_val}, {"R9", &r9_val}
    };
    for (auto& r : reg_list)
    {
        if (get_reg_val(r.name, r.val))
            regs[r.name] = helpers::format_address(static_cast<ea_t>(r.val->ival));
    }
    ctx["registers"] = regs;

    func_t* pfn = get_func(ea);
    if (pfn)
    {
        ctx["function_code"] = helpers::get_pseudocode(pfn->start_ea);
        qstring fname;
        get_func_name(&fname, pfn->start_ea);
        ctx["function_name"] = fname.c_str();
        ctx["function_start"] = helpers::format_address(pfn->start_ea);
        ctx["offset_in_func"] = helpers::format_address(ea - pfn->start_ea);
    }

    ea_t dis_start = ea;
    for (int i = 0; i < 16 && dis_start > 0; ++i)
        dis_start = prev_head(dis_start, 0);
    ea_t dis_end = ea;
    for (int i = 0; i < 16; ++i)
        dis_end = next_head(dis_end, BADADDR);
    ctx["disassembly"] = helpers::get_disassembly(dis_start, dis_end);

    call_stack_t stack;
    if (collect_stack_trace(get_current_thread(), &stack))
    {
        json frames = json::array();
        for (size_t i = 0; i < stack.size() && i < 32; ++i)
        {
            json f;
            f["caller"] = helpers::format_address(stack[i].callea);
            f["callee"] = helpers::format_address(stack[i].funcea);
            qstring fn;
            if (get_func_name(&fn, stack[i].funcea) > 0)
                f["name"] = fn.c_str();
            frames.push_back(std::move(f));
        }
        ctx["call_stack"] = std::move(frames);
    }

    if (get_reg_val("RSP", &rsp_val))
    {
        ea_t rsp = static_cast<ea_t>(rsp_val.ival);
        std::vector<uint8_t> stack_bytes(256);
        ssize_t got = read_dbg_memory(rsp, stack_bytes.data(), 256);
        if (got > 0)
        {
            std::string hex;
            for (ssize_t i = 0; i < got; ++i)
            {
                char hb[4];
                qsnprintf(hb, sizeof(hb), "%02X ", stack_bytes[i]);
                hex += hb;
            }
            ctx["stack_memory"] = hex;
            ctx["stack_base"] = helpers::format_address(rsp);
        }
    }

    auto recent = g_dbg_event_log.snapshot(10);
    json events = json::array();
    for (const auto& ev : recent)
    {
        json j;
        j["detail"] = ev.detail;
        j["ea"] = (ev.ea != BADADDR) ? helpers::format_address(ev.ea) : "";
        events.push_back(std::move(j));
    }
    ctx["recent_events"] = std::move(events);
    ctx["breakpoint_address"] = helpers::format_address(ea);

    return tool_result_t::ok(OBFSTR("Breakpoint context analysis"), ctx);
}

tool_result_t trace_virtual_dispatch(const json& params)
{
    auto addr = helpers::parse_address(params.value("address", std::string()));
    if (!addr)
        return tool_result_t::error(OBFSTR("Invalid address ÃƒÂ¢Ã¢â€šÂ¬Ã¢â‚¬Â provide the address of the indirect call/jmp"));

    ea_t ea = *addr;
    int depth = params.value("depth", 3);
    if (depth < 1) depth = 1;
    if (depth > 16) depth = 16;

    json result;
    result["dispatch_site"] = helpers::format_address(ea);

    insn_t insn;
    if (decode_insn(&insn, ea) <= 0)
        return tool_result_t::error(OBFSTR("Failed to decode instruction at dispatch site"));

    qstring dis_text;
    generate_disasm_line(&dis_text, ea, GENDSM_FORCE_CODE);
    tag_remove(&dis_text);
    result["instruction"] = dis_text.c_str();

    bool dbg_active = is_debugger_on();
    json targets = json::array();

    if (dbg_active)
    {
        for (int i = 0; i < depth; ++i)
        {
            add_bpt(ea, 0, BPT_SOFT);
            enable_bpt(ea, true);

            continue_process();
            debug_event_t ev;
            int wfne = WFNE_SUSP | WFNE_SILENT;
            dbg_event_code_t gc = wait_for_next_event(wfne, 5000);

            if (gc == DEC_TIMEOUT)
            {
                del_bpt(ea);
                break;
            }

            regval_t rip;
            get_reg_val("RIP", &rip);
            ea_t current_ip = static_cast<ea_t>(rip.ival);

            request_step_into();
            run_requests();
            gc = wait_for_next_event(wfne, 3000);

            regval_t target_rip;
            get_reg_val("RIP", &target_rip);
            ea_t target = static_cast<ea_t>(target_rip.ival);

            json entry;
            entry["iteration"] = i + 1;
            entry["target"] = helpers::format_address(target);

            qstring tname;
            if (get_func_name(&tname, target) > 0)
                entry["target_name"] = tname.c_str();

            func_t* pfn = get_func(target);
            if (pfn)
                entry["target_code"] = helpers::get_pseudocode(pfn->start_ea);

            targets.push_back(std::move(entry));
        }
        del_bpt(ea);
    }
    else
    {
        xrefblk_t xb;
        for (bool ok = xb.first_from(ea, XREF_FAR); ok; ok = xb.next_from())
        {
            json entry;
            entry["target"] = helpers::format_address(xb.to);
            qstring tname;
            if (get_func_name(&tname, xb.to) > 0)
                entry["target_name"] = tname.c_str();
            targets.push_back(std::move(entry));
        }
        result["note"] = OBFSTR("Static analysis only ÃƒÂ¢Ã¢â€šÂ¬Ã¢â‚¬Â start debugger for dynamic dispatch tracing");
    }

    result["targets"] = std::move(targets);
    return tool_result_t::ok(OBFSTR("Virtual dispatch trace"), result);
}

tool_result_t snapshot_execution_state(const json& params)
{
    std::string label = params.value("label", std::string("snapshot"));

    json snap;
    snap["label"] = label;
    snap["timestamp_ms"] = static_cast<uint64_t>(
        std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::system_clock::now().time_since_epoch()).count());

    static const char* gp_regs[] = {
        "RAX", "RBX", "RCX", "RDX", "RSI", "RDI", "RBP", "RSP",
        "R8", "R9", "R10", "R11", "R12", "R13", "R14", "R15", "RIP", "EFLAGS"
    };
    json regs;
    for (const char* rn : gp_regs)
    {
        regval_t rv;
        if (get_reg_val(rn, &rv))
            regs[rn] = helpers::format_address(static_cast<ea_t>(rv.ival));
    }
    snap["registers"] = regs;

    regval_t rsp;
    if (get_reg_val("RSP", &rsp))
    {
        ea_t sp = static_cast<ea_t>(rsp.ival);
        std::vector<uint8_t> buf(512);
        ssize_t got = read_dbg_memory(sp, buf.data(), 512);
        if (got > 0)
        {
            std::string hex;
            for (ssize_t i = 0; i < got; ++i)
            {
                char hb[4];
                qsnprintf(hb, sizeof(hb), "%02X", buf[i]);
                hex += hb;
            }
            snap["stack_hex"] = hex;
            snap["stack_base"] = helpers::format_address(sp);
        }
    }

    regval_t rip;
    if (get_reg_val("RIP", &rip))
    {
        ea_t ip = static_cast<ea_t>(rip.ival);
        qstring dis;
        generate_disasm_line(&dis, ip, GENDSM_FORCE_CODE);
        tag_remove(&dis);
        snap["current_instruction"] = dis.c_str();
        snap["current_address"] = helpers::format_address(ip);
    }

    call_stack_t stack;
    if (collect_stack_trace(get_current_thread(), &stack))
    {
        json frames = json::array();
        for (size_t i = 0; i < stack.size() && i < 32; ++i)
        {
            json f;
            f["callea"] = helpers::format_address(stack[i].callea);
            f["funcea"] = helpers::format_address(stack[i].funcea);
            qstring fn;
            if (get_func_name(&fn, stack[i].funcea) > 0)
                f["name"] = fn.c_str();
            frames.push_back(std::move(f));
        }
        snap["call_stack"] = std::move(frames);
    }

    return tool_result_t::ok(OBFSTR("Execution state snapshot"), snap);
}

tool_result_t compare_execution_states(const json& params)
{
    if (!params.contains("state_a") || !params.contains("state_b"))
        return tool_result_t::error(OBFSTR("Provide 'state_a' and 'state_b' snapshot objects"));

    const json& a = params["state_a"];
    const json& b = params["state_b"];

    json diff;
    diff["label_a"] = a.value("label", "A");
    diff["label_b"] = b.value("label", "B");

    json reg_diffs = json::array();
    if (a.contains("registers") && b.contains("registers"))
    {
        const json& ra = a["registers"];
        const json& rb = b["registers"];
        for (auto it = ra.begin(); it != ra.end(); ++it)
        {
            std::string key = it.key();
            std::string va = it.value().get<std::string>();
            std::string vb = rb.value(key, std::string("N/A"));
            if (va != vb)
            {
                json d;
                d["register"] = key;
                d["value_a"] = va;
                d["value_b"] = vb;
                reg_diffs.push_back(std::move(d));
            }
        }
    }
    diff["register_diffs"] = std::move(reg_diffs);

    if (a.contains("stack_hex") && b.contains("stack_hex"))
    {
        std::string sa = a["stack_hex"].get<std::string>();
        std::string sb = b["stack_hex"].get<std::string>();
        size_t min_len = std::min(sa.size(), sb.size());
        int byte_diffs = 0;
        json stack_changes = json::array();
        for (size_t i = 0; i + 1 < min_len; i += 2)
        {
            if (sa[i] != sb[i] || sa[i+1] != sb[i+1])
            {
                ++byte_diffs;
                if (stack_changes.size() < 64)
                {
                    json c;
                    c["offset"] = i / 2;
                    c["byte_a"] = sa.substr(i, 2);
                    c["byte_b"] = sb.substr(i, 2);
                    stack_changes.push_back(std::move(c));
                }
            }
        }
        diff["stack_byte_diffs"] = byte_diffs;
        diff["stack_changes"] = std::move(stack_changes);
    }

    if (a.contains("call_stack") && b.contains("call_stack"))
    {
        diff["call_stack_a_depth"] = a["call_stack"].size();
        diff["call_stack_b_depth"] = b["call_stack"].size();
    }

    return tool_result_t::ok(OBFSTR("Execution state comparison"), diff);
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
    json dispatch_candidates = json::array();

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
    bool use_debugger = params.value("use_debugger", false);

    json handlers = json::array();
    json result;
    result["table_base"] = helpers::format_address(base);
    result["entry_size"] = entry_size;

    for (int i = 0; i < entry_count; ++i)
    {
        ea_t slot = base + static_cast<ea_t>(i) * entry_size;
        ea_t target = BADADDR;

        if (use_debugger && is_debugger_on())
        {
            if (entry_size == 8)
            {
                uint64_t val = 0;
                if (read_dbg_memory(slot, &val, 8) == 8)
                    target = static_cast<ea_t>(val);
            }
            else
            {
                uint32_t val = 0;
                if (read_dbg_memory(slot, &val, 4) == 4)
                    target = static_cast<ea_t>(val);
            }
        }
        else
        {
            if (entry_size == 8)
                target = get_qword(slot);
            else
                target = static_cast<ea_t>(get_dword(slot));
        }

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

    registry.register_tool({OBFSTR("get_debugger_event_log"), OBFSTR("debugger"),
        OBFSTR("Get recent debugger events captured by the HT_DBG hook (breakpoint hits, exceptions, process/thread events, step completions). "
               "Use 'count' to limit results or 'since_ms' to get events after a timestamp."),
        {{OBFSTR("count"), OBFSTR("number"), OBFSTR("Max events to return (default 50)"), false},
         {OBFSTR("since_ms"), OBFSTR("number"), OBFSTR("Return events after this epoch-ms timestamp"), false}},
        get_debugger_event_log});

    registry.register_tool({OBFSTR("clear_debugger_event_log"), OBFSTR("debugger"),
        OBFSTR("Clear all captured debugger events from the event log."),
        {}, clear_debugger_event_log, false});

    registry.register_tool({OBFSTR("analyze_breakpoint_context"), OBFSTR("debugger"),
        OBFSTR("Gather rich context at a breakpoint: registers, decompiled function, disassembly window, "
               "call stack, stack memory, and recent debugger events. Ideal for AI-assisted analysis of a stopped state."),
        {{OBFSTR("address"), OBFSTR("string"), OBFSTR("Breakpoint/current address"), true}},
        analyze_breakpoint_context});

    registry.register_tool({OBFSTR("trace_virtual_dispatch"), OBFSTR("debugger"),
        OBFSTR("Trace an indirect call/jump to discover its runtime targets. "
               "With debugger active: sets temp breakpoint, steps into the call N times, records each target. "
               "Without debugger: performs static xref analysis."),
        {{OBFSTR("address"), OBFSTR("string"), OBFSTR("Address of the indirect call/jmp instruction"), true},
         {OBFSTR("depth"), OBFSTR("number"), OBFSTR("Number of dispatch iterations to trace (default 3, max 16)"), false}},
        trace_virtual_dispatch, false});

    registry.register_tool({OBFSTR("snapshot_execution_state"), OBFSTR("debugger"),
        OBFSTR("Capture a full snapshot of the current execution state: all GP registers, stack memory, "
               "current instruction, and call stack. Label it for later comparison."),
        {{OBFSTR("label"), OBFSTR("string"), OBFSTR("Label for this snapshot (e.g., 'before_call', 'after_handler')"), false}},
        snapshot_execution_state});

    registry.register_tool({OBFSTR("compare_execution_states"), OBFSTR("debugger"),
        OBFSTR("Compare two execution state snapshots (from snapshot_execution_state) and report differences "
               "in registers, stack memory, and call stack depth."),
        {{OBFSTR("state_a"), OBFSTR("object"), OBFSTR("First snapshot object"), true},
         {OBFSTR("state_b"), OBFSTR("object"), OBFSTR("Second snapshot object"), true}},
        compare_execution_states});

    registry.register_tool({OBFSTR("detect_vm_handler_pattern"), OBFSTR("debugger"),
        OBFSTR("Scan a code region for virtualization patterns: indirect jump tables, CMP dispatch chains, "
               "loop instructions. Returns a VM confidence score and identified patterns. "
               "Use this to detect VMProtect/Themida/custom VM handlers."),
        {{OBFSTR("address"), OBFSTR("string"), OBFSTR("Start address to scan"), true},
         {OBFSTR("scan_size"), OBFSTR("number"), OBFSTR("Bytes to scan (default 4096, max 65536)"), false}},
        detect_vm_handler_pattern});

    registry.register_tool({OBFSTR("map_vm_handler_table"), OBFSTR("debugger"),
        OBFSTR("Read a VM handler/dispatch table from memory and resolve each entry to its target function. "
               "Returns handler addresses, names, and first instructions. "
               "Use 'use_debugger' to read from live process memory instead of IDB."),
        {{OBFSTR("table_address"), OBFSTR("string"), OBFSTR("Base address of the handler table"), true},
         {OBFSTR("entry_count"), OBFSTR("number"), OBFSTR("Number of entries to read (default 256, max 4096)"), false},
         {OBFSTR("entry_size"), OBFSTR("number"), OBFSTR("Size of each entry in bytes (4 or 8, default 8)"), false},
         {OBFSTR("use_debugger"), OBFSTR("boolean"), OBFSTR("Read from debugger memory instead of IDB (default false)"), false}},
        map_vm_handler_table});
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

    // Align start DOWN and end UP to page boundaries to avoid
    // IDA's "bad segment start" error. Per the IDA SDK segment.hpp:
    //   "if s.end_ea < s.start_ea, then fail."
    //   "if start==#BADADDR then start <- to_ea(para,0)."
    // The add_segm(para,...) form computes a base from 'para' which can
    // conflict with high kernel addresses. Using add_segm_ex() directly
    // with explicit start_ea/end_ea avoids this issue entirely.
    ea_t aligned_start = *start_opt & ~0xFULL;
    ea_t aligned_end   = (*end_opt + 0xF) & ~0xFULL;
    if (aligned_end <= aligned_start)
        aligned_end = aligned_start + 0x1000;

    // Check if segment already exists at this range
    if (getseg(aligned_start))
        return tool_result_t::error(OBFSTR("Segment already exists at ") + helpers::format_address(aligned_start));

    // Use add_segm_ex for full control over segment properties.
    // SDK segment.hpp add_segm_ex():
    //   "s->start_ea, s->end_ea: range of the segment"
    //   "s->bitness: 0=16bit, 1=32bit, 2=64bit"
    //   "ADDSEG_QUIET: silent mode, no 'Adding segment...' in messages"
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
    show_wait_box("HIDECANCEL\nAiDA: Waiting for auto-analysis...");
    responsive_auto_wait(0, BADADDR, "Waiting for auto-analysis...");
    hide_wait_box();
    bool ok = auto_is_ok();

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
        analyze_data_flow});

    registry.register_tool({OBFSTR("detect_anti_analysis"), OBFSTR("analysis"),
        OBFSTR("Detect anti-debug/anti-VM techniques: API calls, CPUID/RDTSC, INT traps, VM strings."),
        {{OBFSTR("address"), OBFSTR("string"), OBFSTR("Function or start address"), true}},
        detect_anti_analysis});
}

} // namespace analysis_tools

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
        show_wait_box("HIDECANCEL\nAiDA: Re-analyzing function...");
        responsive_auto_wait(start, end, "Re-analyzing function...");
        hide_wait_box();
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
                    comment += " Ã¢â€ â€™ next_state=" + std::to_string(sb["next_state"].get<int64_t>());
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

        enum_import_names(i, [](ea_t ea, const char* name, uval_t /*ord*/, void* param) -> int {
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
    for (size_t i = 0; i < import_map.size() && i < 10000; ++i)
    {
        // Already handled by the IDA loader for known imports
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

    hide_wait_box();

    if (!dry_run && total_changes > 0)
    {
        pfn = get_func(ea);
        if (pfn)
            reanalyze_function(pfn);
    }

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
}

} // namespace deobfuscation_tools

namespace driver_tools
{

tool_result_t driver_connect(const json& params)
{
    if (device->is_connected())
    {
        if (device->get_kernel_dtb() == 0)
            device->solve_kernel_dtb();
        return tool_result_t::ok(OBFSTR("Driver already connected"));
    }

    if (!device->connect())
        return tool_result_t::error(OBFSTR("Failed to connect to kernel driver. Ensure the driver is loaded and running."));

    device->solve_kernel_dtb();

    json result;
    result["connected"] = true;
    result["kernel_dtb"] = helpers::format_address(device->get_kernel_dtb());
    result["note"] = OBFSTR("Connected via obfuscated device path. Kernel DTB solved for full kernel memory access.");
    return tool_result_t::ok(OBFSTR("Kernel driver connected"), result);
}

tool_result_t driver_status(const json&)
{
    json result;
    result["connected"]    = device->is_connected();
    result["process_id"]   = device->get_process_id();
    result["base_address"] = helpers::format_address(device->get_base_address());
    result["dtb"]          = helpers::format_address(device->get_dtb());
    result["kernel_dtb"]   = helpers::format_address(device->get_kernel_dtb());
    result["has_process"]  = device->get_process_id() != 0;
    result["has_kernel"]   = device->get_kernel_dtb() != 0;

    if (device->is_connected() && device->get_process_id() != 0)
        result["heartbeat"] = device->send_heartbeat() ? "ok" : "failed";

    return tool_result_t::ok(OBFSTR("Driver status"), result);
}

tool_result_t driver_attach(const json& params)
{
    if (!device->is_connected())
    {
        if (!device->connect())
            return tool_result_t::error(OBFSTR("Cannot connect to kernel driver. Load the driver first."));
    }

    std::string process_name = params["process"].get<std::string>();

    std::uint32_t pid = device->find_process(process_name.c_str());
    if (pid == 0)
        return tool_result_t::error(OBFSTR("Process not found: ") + process_name);

    std::uint64_t base = device->find_image();
    if (base == 0)
        return tool_result_t::error(OBFSTR("Failed to locate image base for process: ") + process_name);

    device->solve_dtb();

    json result;
    result["process_name"] = process_name;
    result["process_id"]   = pid;
    result["base_address"] = helpers::format_address(base);
    result["dtb"]          = helpers::format_address(device->get_dtb());
    return tool_result_t::ok(OBFSTR("Attached to process: ") + process_name, result);
}

tool_result_t driver_read_memory(const json& params)
{
    if (!device->is_connected() || device->get_process_id() == 0)
        return tool_result_t::error(OBFSTR("Not attached. Call driver_connect then driver_attach first."));

    auto ea_opt = helpers::parse_address(params["address"].get<std::string>());
    if (!ea_opt)
        return tool_result_t::error(OBFSTR("Invalid address"));

    std::size_t size = params.value("size", 256);
    if (size > 65536)
        return tool_result_t::error(OBFSTR("Size too large (max 65536)"));

    std::vector<std::uint8_t> buffer(size);
    std::size_t bytes_read = device->read_raw(*ea_opt, buffer.data(), size);
    if (bytes_read == 0)
        return tool_result_t::error(OBFSTR("Kernel read failed at ") + helpers::format_address(*ea_opt));

    std::ostringstream hex_ss, ascii_ss;
    for (std::size_t i = 0; i < bytes_read; i++)
    {
        if (i > 0) hex_ss << " ";
        hex_ss << std::hex << std::setw(2) << std::setfill('0') << (int)buffer[i];
        char c = static_cast<char>(buffer[i]);
        ascii_ss << (c >= 32 && c < 127 ? c : '.');
    }

    json result;
    result["address"]       = helpers::format_address(*ea_opt);
    result["size_requested"] = size;
    result["size_read"]     = bytes_read;
    result["hex"]           = hex_ss.str();
    result["ascii"]         = ascii_ss.str();
    result["bytes"]         = json::array();
    for (std::size_t i = 0; i < bytes_read; i++)
        result["bytes"].push_back(buffer[i]);

    if (params.value("patch_idb", false))
    {
        for (std::size_t i = 0; i < bytes_read; i++)
            put_byte(*ea_opt + i, buffer[i]);
        result["patched_idb"] = true;
    }

    return tool_result_t::ok(OBFSTR("Kernel read: ") + std::to_string(bytes_read) + " bytes", result);
}

tool_result_t driver_write_memory(const json& params)
{
    if (!device->is_connected() || device->get_process_id() == 0)
        return tool_result_t::error(OBFSTR("Not attached. Call driver_connect then driver_attach first."));

    auto ea_opt = helpers::parse_address(params["address"].get<std::string>());
    if (!ea_opt)
        return tool_result_t::error(OBFSTR("Invalid address"));

    std::string hex_bytes = params["bytes"].get<std::string>();
    hex_bytes.erase(std::remove(hex_bytes.begin(), hex_bytes.end(), ' '), hex_bytes.end());

    std::vector<std::uint8_t> bytes;
    for (std::size_t i = 0; i + 1 < hex_bytes.length(); i += 2)
    {
        try { bytes.push_back(static_cast<std::uint8_t>(std::stoul(hex_bytes.substr(i, 2), nullptr, 16))); }
        catch (...) { return tool_result_t::error(OBFSTR("Invalid hex byte at offset ") + std::to_string(i)); }
    }
    if (bytes.empty())
        return tool_result_t::error(OBFSTR("No bytes to write"));

    std::size_t written = device->write_raw(*ea_opt, bytes.data(), bytes.size());
    if (written == 0)
        return tool_result_t::error(OBFSTR("Kernel write failed at ") + helpers::format_address(*ea_opt));

    json result;
    result["address"]       = helpers::format_address(*ea_opt);
    result["bytes_written"] = written;
    return tool_result_t::ok(OBFSTR("Kernel write: ") + std::to_string(written) + " bytes", result);
}

tool_result_t driver_dump_module(const json& params)
{
    if (!device->is_connected() || device->get_process_id() == 0)
        return tool_result_t::error(OBFSTR("Not attached. Call driver_connect then driver_attach first."));

    ea_t base = BADADDR;
    if (params.contains("address"))
    {
        auto a = helpers::parse_address(params["address"].get<std::string>());
        if (a) base = *a;
    }
    if (base == BADADDR || base == 0)
        base = static_cast<ea_t>(device->get_base_address());
    if (base == 0 || base == BADADDR)
        return tool_result_t::error(OBFSTR("Invalid module base. Provide 'address' or attach to a process first."));

    std::uint8_t pe_hdr[0x1000];
    std::size_t hdr_read = device->read_raw(base, pe_hdr, sizeof(pe_hdr));
    if (hdr_read < 0x200)
        return tool_result_t::error(OBFSTR("Failed to read PE header at ") + helpers::format_address(base));

    std::size_t module_size = 0;
    std::string module_name = "module";
    if (*(std::uint16_t*)pe_hdr == 0x5A4D)
    {
        std::uint32_t pe_off = *(std::uint32_t*)(pe_hdr + 0x3C);
        if (pe_off + 0x58 < sizeof(pe_hdr) && *(std::uint32_t*)(pe_hdr + pe_off) == 0x00004550)
        {
            std::uint16_t opt_magic = *(std::uint16_t*)(pe_hdr + pe_off + 0x18);
            if (opt_magic == 0x020B || opt_magic == 0x010B)
                module_size = *(std::uint32_t*)(pe_hdr + pe_off + 0x18 + 0x38);
        }
    }
    if (module_size == 0)
        module_size = params.value("size", (std::size_t)0x200000);
    if (module_size > 0x10000000)
        return tool_result_t::error(OBFSTR("Module size too large (>256MB): ") + std::to_string(module_size));

    std::vector<std::uint8_t> module_data(module_size, 0);
    // Use 64KB chunks instead of 4KB for significantly faster reads
    const std::size_t chunk = 0x10000;
    std::size_t total_read = 0;

    show_wait_box("HIDECANCEL\nAiDA: Dumping module via kernel (0 / 0x%zX)...", module_size);
    for (std::size_t off = 0; off < module_size; off += chunk)
    {
        if (off % 0x40000 == 0)
            replace_wait_box("HIDECANCEL\nAiDA: Kernel dump 0x%zX / 0x%zX (%.1f%%)...",
                             off, module_size, (off * 100.0) / module_size);
        std::size_t to_read = std::min(chunk, module_size - off);
        total_read += device->read_raw(base + off, module_data.data() + off, to_read);
    }
    hide_wait_box();

    // ALWAYS save to Downloads folder first, before any IDB patching.
    // This ensures the user has the raw dump file even if IDA stalls during patching.
    std::string output_path = params.value("output_path", std::string());
    if (output_path.empty())
    {
        output_path = get_downloads_folder() + "dumped_" + module_name + "_" +
                      helpers::format_address(base) + ".bin";
    }

    // Save dump to file IMMEDIATELY
    ensure_parent_dir_exists(output_path);
    {
        HANDLE hFile = CreateFileA(output_path.c_str(), GENERIC_WRITE, 0, nullptr,
                                   CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
        if (hFile != INVALID_HANDLE_VALUE)
        {
            DWORD written = 0;
            WriteFile(hFile, module_data.data(), static_cast<DWORD>(module_size), &written, nullptr);
            CloseHandle(hFile);
            msg(OBFSTR_C("AiDA: Dump saved to %s (%zu bytes)\n"), output_path.c_str(), module_size);
        }
        else
        {
            msg(OBFSTR_C("AiDA: WARNING - Failed to save dump file: %s (error %lu)\n"),
                output_path.c_str(), GetLastError());
        }
    }

    if (params.value("patch_idb", true))
    {
        // Use put_bytes() for bulk patching instead of per-byte put_byte().
        // SDK bytes.hpp put_bytes(): "Modify the specified number of bytes of the program."
        // This is orders of magnitude faster than individual put_byte() calls
        // and prevents IDA from freezing on large modules.
        show_wait_box("HIDECANCEL\nAiDA: Patching IDA database (bulk)...");

        // Patch segment by segment for correctness (only write to mapped areas)
        int seg_count = get_segm_qty();
        for (int si = 0; si < seg_count; ++si)
        {
            segment_t* seg = getnseg(si);
            if (!seg) continue;
            if (seg->start_ea >= base + module_size || seg->end_ea <= base) continue;

            ea_t patch_start = std::max(seg->start_ea, base);
            ea_t patch_end   = std::min(seg->end_ea, base + static_cast<ea_t>(module_size));
            std::size_t offset = static_cast<std::size_t>(patch_start - base);
            std::size_t length = static_cast<std::size_t>(patch_end - patch_start);

            if (offset < module_size && length > 0)
                put_bytes(patch_start, module_data.data() + offset, length);
        }

        hide_wait_box();
    }

    json result;
    result["base"]          = helpers::format_address(base);
    result["size"]          = module_size;
    result["bytes_read"]    = total_read;
    result["coverage_pct"]  = module_size ? (int)((total_read * 100) / module_size) : 0;
    result["saved_to"]      = output_path;
    if (params.value("patch_idb", true))
        result["patched_idb"] = true;
    result["can_load_in_ida"] = true;
    result["note"]          = OBFSTR(
        "Dump file saved to: ") + output_path + OBFSTR(". "
        "For best static analysis results, open this file in a NEW IDA Pro instance: "
        "File > Open > select the dumped file. Use manual load with image base ") +
        helpers::format_address(base) + OBFSTR(".");

    return tool_result_t::ok(OBFSTR("Module dumped: ") + std::to_string(total_read) + "/" +
                             std::to_string(module_size) + " bytes -> " + output_path, result);
}

tool_result_t driver_scan_pattern(const json& params)
{
    if (!device->is_connected() || device->get_process_id() == 0)
        return tool_result_t::error(OBFSTR("Not attached. Call driver_connect then driver_attach first."));

    std::string pattern_str = params["pattern"].get<std::string>();
    int limit = params.value("limit", 20);

    ea_t start_addr = static_cast<ea_t>(device->get_base_address());
    ea_t end_addr   = start_addr + (ea_t)params.value("size", (std::uint64_t)0x200000);
    if (params.contains("start"))
    {
        auto s = helpers::parse_address(params["start"].get<std::string>());
        if (s) start_addr = *s;
    }
    if (params.contains("end"))
    {
        auto e = helpers::parse_address(params["end"].get<std::string>());
        if (e) end_addr = *e;
    }

    std::vector<std::uint8_t> pat;
    std::vector<bool> mask;
    {
        std::istringstream iss(pattern_str);
        std::string tok;
        while (iss >> tok)
        {
            if (tok == "??" || tok == "?")
            {
                pat.push_back(0);
                mask.push_back(false);
            }
            else
            {
                try
                {
                    pat.push_back(static_cast<std::uint8_t>(std::stoul(tok, nullptr, 16)));
                    mask.push_back(true);
                }
                catch (...) { return tool_result_t::error(OBFSTR("Invalid pattern token: ") + tok); }
            }
        }
    }
    if (pat.empty())
        return tool_result_t::error(OBFSTR("Empty pattern"));

    json matches = json::array();
    const std::size_t chunk_sz = 0x10000;
    std::vector<std::uint8_t> chunk(chunk_sz + pat.size());

    show_wait_box("HIDECANCEL\nAiDA: Kernel pattern scan...");
    for (ea_t addr = start_addr; addr < end_addr && (int)matches.size() < limit; addr += chunk_sz)
    {
        replace_wait_box("HIDECANCEL\nAiDA: Kernel scan 0x%llX (%d found)...",
                         (unsigned long long)addr, (int)matches.size());
        std::size_t to_read = std::min((std::size_t)(end_addr - addr) + pat.size(), chunk_sz + pat.size());
        std::size_t got = device->read_raw(addr, chunk.data(), to_read);
        if (got < pat.size()) continue;

        for (std::size_t i = 0; i + pat.size() <= got && (int)matches.size() < limit; i++)
        {
            bool found = true;
            for (std::size_t j = 0; j < pat.size(); j++)
            {
                if (mask[j] && chunk[i + j] != pat[j]) { found = false; break; }
            }
            if (found)
            {
                ea_t m = addr + i;
                matches.push_back({{"address", helpers::format_address(m)},
                                   {"name", helpers::get_name_or_address(m)}});
            }
        }
    }
    hide_wait_box();

    return tool_result_t::ok(OBFSTR("Pattern scan: ") + std::to_string(matches.size()) + " matches", matches);
}

tool_result_t driver_read_string(const json& params)
{
    if (!device->is_connected() || device->get_process_id() == 0)
        return tool_result_t::error(OBFSTR("Not attached. Call driver_connect then driver_attach first."));

    auto ea_opt = helpers::parse_address(params["address"].get<std::string>());
    if (!ea_opt)
        return tool_result_t::error(OBFSTR("Invalid address"));

    std::size_t max_len = params.value("max_length", 512);
    std::string type    = params.value("type", "auto");

    std::vector<std::uint8_t> buf(max_len * 2 + 4, 0);
    std::size_t got = device->read_raw(*ea_opt, buf.data(), buf.size());
    if (got == 0)
        return tool_result_t::error(OBFSTR("Failed to read from ") + helpers::format_address(*ea_opt));

    json result;
    result["address"] = helpers::format_address(*ea_opt);

    bool try_ascii = (type == "auto" || type == "ascii");
    bool try_wide  = (type == "auto" || type == "wide");

    if (try_wide && got >= 2)
    {
        std::string narrow;
        for (std::size_t i = 0; i + 1 < got; i += 2)
        {
            std::uint16_t wc = buf[i] | ((std::uint16_t)buf[i + 1] << 8);
            if (wc == 0) break;
            narrow += (wc < 128 && wc >= 32) ? static_cast<char>(wc) : '?';
        }
        if (!narrow.empty())
        {
            result["wide_string"] = narrow;
            result["wide_length"] = narrow.length();
        }
    }

    if (try_ascii)
    {
        std::string ascii;
        for (std::size_t i = 0; i < got; i++)
        {
            if (buf[i] == 0) break;
            ascii += static_cast<char>(buf[i]);
        }
        result["string"]       = ascii;
        result["ascii_length"] = ascii.length();
    }

    return tool_result_t::ok(OBFSTR("String read via kernel"), result);
}

tool_result_t driver_read_pointer_chain(const json& params)
{
    if (!device->is_connected() || device->get_process_id() == 0)
        return tool_result_t::error(OBFSTR("Not attached. Call driver_connect then driver_attach first."));

    auto ea_opt = helpers::parse_address(params["address"].get<std::string>());
    if (!ea_opt)
        return tool_result_t::error(OBFSTR("Invalid address"));

    std::vector<std::int64_t> offsets;
    if (params.contains("offsets") && params["offsets"].is_array())
    {
        for (const auto& off : params["offsets"])
        {
            if (off.is_number_integer())
                offsets.push_back(off.get<std::int64_t>());
            else if (off.is_string())
            {
                auto o = helpers::parse_address(off.get<std::string>());
                if (o) offsets.push_back(static_cast<std::int64_t>(*o));
            }
        }
    }

    json chain = json::array();
    std::uint64_t current = *ea_opt;
    chain.push_back({{"step", 0}, {"address", helpers::format_address(current)}, {"type", "base"}});

    for (std::size_t i = 0; i < offsets.size(); i++)
    {
        std::uint64_t ptr = device->read<std::uint64_t>(current);
        if (ptr == 0)
        {
            chain.push_back({{"step", (int)(i + 1)}, {"error", "null pointer"}, {"offset", offsets[i]}});
            break;
        }
        std::uint64_t next = ptr + offsets[i];
        chain.push_back({{"step", (int)(i + 1)},
                         {"deref", helpers::format_address(ptr)},
                         {"offset", offsets[i]},
                         {"address", helpers::format_address(next)}});
        current = next;
    }

    std::uint64_t final_val = device->read<std::uint64_t>(current);

    json result;
    result["initial_address"]    = helpers::format_address(*ea_opt);
    result["final_address"]      = helpers::format_address(current);
    result["final_value"]        = helpers::format_address(final_val);
    result["final_value_decimal"] = final_val;
    result["chain"]              = chain;
    return tool_result_t::ok(OBFSTR("Pointer chain traversed"), result);
}

tool_result_t driver_enumerate_modules(const json&)
{
    if (!device->is_connected() || device->get_process_id() == 0)
        return tool_result_t::error(OBFSTR("Not attached. Call driver_connect then driver_attach first."));

    std::uint64_t base = device->get_base_address();
    if (base == 0)
        return tool_result_t::error(OBFSTR("No base address. Call driver_attach first."));

    std::uint8_t pe_hdr[0x1000];
    if (device->read_raw(base, pe_hdr, sizeof(pe_hdr)) < 0x200 || *(std::uint16_t*)pe_hdr != 0x5A4D)
        return tool_result_t::error(OBFSTR("Failed to read main PE header at ") + helpers::format_address(base));

    json modules = json::array();
    std::uint32_t pe_off = *(std::uint32_t*)(pe_hdr + 0x3C);

    std::uint32_t main_size = 0;
    {
        std::uint16_t mag = (pe_off + 0x58 < sizeof(pe_hdr)) ? *(std::uint16_t*)(pe_hdr + pe_off + 0x18) : 0;
        if (mag == 0x020B || mag == 0x010B)
            main_size = *(std::uint32_t*)(pe_hdr + pe_off + 0x18 + 0x38);
    }
    modules.push_back({{"name", "main_module"}, {"base", helpers::format_address(base)},
                       {"size", main_size}, {"is_main", true}});

    std::uint16_t opt_magic  = (pe_off + 0x1A < sizeof(pe_hdr)) ? *(std::uint16_t*)(pe_hdr + pe_off + 0x18) : 0;
    std::uint32_t import_rva = 0;
    if (opt_magic == 0x020B && pe_off + 0x90 < sizeof(pe_hdr))
        import_rva = *(std::uint32_t*)(pe_hdr + pe_off + 0x18 + 0x78);
    else if (opt_magic == 0x010B && pe_off + 0x80 < sizeof(pe_hdr))
        import_rva = *(std::uint32_t*)(pe_hdr + pe_off + 0x18 + 0x68);

    if (import_rva != 0)
    {
        std::uint8_t imp[20];
        for (std::uint32_t imp_off = 0; imp_off < 0x10000; imp_off += 20)
        {
            if (device->read_raw(base + import_rva + imp_off, imp, sizeof(imp)) < sizeof(imp)) break;
            bool zero = true;
            for (int k = 0; k < 20; k++) if (imp[k]) { zero = false; break; }
            if (zero) break;

            std::uint32_t name_rva = *(std::uint32_t*)(imp + 12);
            if (name_rva == 0) continue;

            char dll_name[260] = {0};
            if (device->read_raw(base + name_rva, dll_name, sizeof(dll_name) - 1) > 0 && dll_name[0])
                modules.push_back({{"name", std::string(dll_name)}, {"base", "runtime"}, {"is_import", true}});
        }
    }

    json result;
    result["modules"]       = modules;
    result["module_count"]  = modules.size();
    result["process_id"]    = device->get_process_id();
    result["note"]          = OBFSTR("Import-table enumeration. For full LDR list, walk PEB.Ldr via driver_read_pointer_chain.");
    return tool_result_t::ok(OBFSTR("Enumerated ") + std::to_string(modules.size()) + " modules", result);
}

struct post_dump_stats_t
{
    int initial_func_count   = 0;
    int exports_created      = 0;
    int entry_points_created = 0;
    int code_insns_created   = 0;
    int prologue_funcs_created = 0;
    int xref_funcs_created   = 0;
    int final_func_count     = 0;

    json to_json() const
    {
        json j;
        j["initial_functions"]    = initial_func_count;
        j["exports_created"]      = exports_created;
        j["entry_points_created"] = entry_points_created;
        j["code_insns_forced"]    = code_insns_created;
        j["prologue_funcs_found"] = prologue_funcs_created;
        j["xref_funcs_found"]     = xref_funcs_created;
        j["final_functions"]      = final_func_count;
        j["total_new_functions"]  = final_func_count - initial_func_count;
        return j;
    }
};

static void run_post_dump_analysis(
    std::uint64_t base_addr,
    std::size_t   dump_size,
    const std::uint8_t* pe_header,
    std::size_t   hdr_size,
    const std::uint8_t* image_data,
    std::size_t   image_len,
    bool          is_kernel,
    post_dump_stats_t& stats,
    json*         sections_arr = nullptr)
{
    ea_t range_start = static_cast<ea_t>(base_addr);
    ea_t range_end   = static_cast<ea_t>(base_addr + dump_size);

    if (hdr_size < 0x40 || pe_header[0] != 'M' || pe_header[1] != 'Z')
        return;
    std::uint32_t pe_off = *reinterpret_cast<const std::uint32_t*>(&pe_header[0x3C]);
    if (pe_off + 0x18 > hdr_size || pe_header[pe_off] != 'P' || pe_header[pe_off + 1] != 'E')
        return;

    std::uint16_t num_sections = *reinterpret_cast<const std::uint16_t*>(&pe_header[pe_off + 0x06]);
    std::uint16_t opt_size = *reinterpret_cast<const std::uint16_t*>(&pe_header[pe_off + 0x14]);
    std::uint32_t section_table_off = pe_off + 0x18 + opt_size;
    bool is_pe64 = (*reinterpret_cast<const std::uint16_t*>(&pe_header[pe_off + 0x18]) == 0x020B);

    for (ea_t fea = range_start; fea < range_end; fea = next_addr(fea))
    {
        func_t* fn = get_func(fea);
        if (fn && fn->start_ea == fea) ++stats.initial_func_count;
        if (fn) fea = fn->end_ea - 1;
    }

    replace_wait_box("HIDECANCEL\nAiDA: [1/6] Running initial auto-analysis...");
    plan_range(range_start, range_end);
    responsive_auto_wait(range_start, range_end, "[1/6] Running initial auto-analysis...");

    replace_wait_box("HIDECANCEL\nAiDA: [2/6] Parsing PE exports and entry points...");
    {
        if (pe_off + 24 + 20 <= hdr_size)
        {
            std::uint32_t entry_rva = *reinterpret_cast<const std::uint32_t*>(
                &pe_header[pe_off + 24 + 16]);
            if (entry_rva != 0)
            {
                ea_t entry_ea = static_cast<ea_t>(base_addr + entry_rva);
                if (is_loaded(entry_ea))
                {
                    create_insn(entry_ea);
                    if (!get_func(entry_ea) && add_func(entry_ea, BADADDR))
                        ++stats.entry_points_created;
                    const char* ep_name = is_kernel ? "DriverEntry" : "ModuleEntryPoint";
                    add_entry(0, entry_ea, ep_name, true, AEF_UTF8);
                    force_name(entry_ea, ep_name, SN_FORCE | SN_NODUMMY);
                }
            }
        }

        if (image_data && image_len > 0)
        {
            std::uint32_t dd_offset = pe_off + 24 + (is_pe64 ? 112 : 96);
            std::uint32_t export_dir_rva = 0, export_dir_size = 0;
            if (dd_offset + 8 <= hdr_size)
            {
                export_dir_rva  = *reinterpret_cast<const std::uint32_t*>(&pe_header[dd_offset]);
                export_dir_size = *reinterpret_cast<const std::uint32_t*>(&pe_header[dd_offset + 4]);
            }

            if (export_dir_rva != 0 && export_dir_size >= 40 && export_dir_rva < image_len)
            {
                const std::uint8_t* exp_dir = &image_data[export_dir_rva];
                std::uint32_t nf  = *reinterpret_cast<const std::uint32_t*>(exp_dir + 20);
                std::uint32_t nn  = *reinterpret_cast<const std::uint32_t*>(exp_dir + 24);
                std::uint32_t atr = *reinterpret_cast<const std::uint32_t*>(exp_dir + 28);
                std::uint32_t ntr = *reinterpret_cast<const std::uint32_t*>(exp_dir + 32);
                std::uint32_t ob  = *reinterpret_cast<const std::uint32_t*>(exp_dir + 16);
                std::uint32_t otr = *reinterpret_cast<const std::uint32_t*>(exp_dir + 36);

                std::map<std::uint32_t, std::string> ordinal_names;
                for (std::uint32_t n = 0; n < nn && n < 4096; ++n)
                {
                    if (ntr + n * 4 + 4 > image_len || otr + n * 2 + 2 > image_len) break;
                    std::uint32_t name_rva = *reinterpret_cast<const std::uint32_t*>(&image_data[ntr + n * 4]);
                    std::uint16_t oi = *reinterpret_cast<const std::uint16_t*>(&image_data[otr + n * 2]);
                    if (name_rva < image_len)
                    {
                        std::string en;
                        for (std::uint32_t c = name_rva; c < image_len && image_data[c]; ++c)
                            en += static_cast<char>(image_data[c]);
                        if (!en.empty()) ordinal_names[oi] = en;
                    }
                }

                for (std::uint32_t i = 0; i < nf && i < 4096; ++i)
                {
                    if (atr + i * 4 + 4 > image_len) break;
                    std::uint32_t fr = *reinterpret_cast<const std::uint32_t*>(&image_data[atr + i * 4]);
                    if (fr == 0 || fr >= image_len) continue;
                    ea_t fea = static_cast<ea_t>(base_addr + fr);
                    if (!is_loaded(fea)) continue;
                    create_insn(fea);
                    if (!get_func(fea) && add_func(fea, BADADDR))
                        ++stats.exports_created;
                    auto it = ordinal_names.find(i);
                    if (it != ordinal_names.end() && !it->second.empty())
                    {
                        force_name(fea, it->second.c_str(), SN_FORCE | SN_NODUMMY);
                        add_entry(ob + i, fea, it->second.c_str(), true, AEF_UTF8);
                    }
                }
            }
        }
    }

    replace_wait_box("HIDECANCEL\nAiDA: [3/6] Force-creating code in executable sections...");
    for (int s = 0; s < num_sections && section_table_off + (s + 1) * 40 <= hdr_size; s++)
    {
        const std::uint8_t* sec_hdr = &pe_header[section_table_off + s * 40];
        std::uint32_t sec_vsize = *reinterpret_cast<const std::uint32_t*>(sec_hdr + 8);
        std::uint32_t sec_vaddr = *reinterpret_cast<const std::uint32_t*>(sec_hdr + 12);
        std::uint32_t sec_chars = *reinterpret_cast<const std::uint32_t*>(sec_hdr + 36);
        if (!(sec_chars & 0x20000000)) continue;

        ea_t sec_start = static_cast<ea_t>(base_addr + sec_vaddr);
        ea_t sec_end   = sec_start + sec_vsize;

        double entropy = 0.0;
        {
            std::size_t sample_size = std::min<std::size_t>(sec_vsize, 4096);
            int freq[256] = {};
            std::size_t counted = 0;
            for (std::size_t b = 0; b < sample_size; ++b)
            {
                if (!is_loaded(sec_start + b)) continue;
                freq[get_byte(sec_start + b)]++;
                ++counted;
            }
            if (counted > 0)
            {
                for (int f = 0; f < 256; ++f)
                {
                    if (freq[f] == 0) continue;
                    double p = static_cast<double>(freq[f]) / static_cast<double>(counted);
                    entropy -= p * std::log2(p);
                }
            }
        }

        if (sections_arr)
        {
            char sn[9] = {};
            std::memcpy(sn, sec_hdr, 8);
            for (auto& si : *sections_arr)
            {
                if (si.value("name", "") == sn)
                {
                    si["entropy"] = entropy;
                    if (entropy > 7.5) si["skipped_high_entropy"] = true;
                }
            }
        }
        if (entropy > 7.5) continue;

        for (ea_t ea = sec_start; ea < sec_end; )
        {
            if (!is_loaded(ea)) { ea = next_addr(ea); if (ea == BADADDR || ea >= sec_end) break; continue; }
            flags64_t fl = get_flags(ea);
            if (is_code(fl))
            {
                insn_t existing;
                int ilen = decode_insn(&existing, ea);
                ea += (ilen > 0) ? ilen : 1;
                continue;
            }
            insn_t test;
            int len = decode_insn(&test, ea);
            if (len > 0 && get_byte(ea) != 0x00)
            {
                int created = create_insn(ea);
                if (created > 0) { ++stats.code_insns_created; ea += created; continue; }
            }
            ++ea;
        }
    }
    responsive_auto_wait(range_start, range_end, "[3/6] Force-creating code...");

    replace_wait_box("HIDECANCEL\nAiDA: [4/6] Scanning for function prologues...");
    {
        struct mini_sig_t { const uint8_t* bytes; const uint8_t* mask; int length; };
        static const uint8_t p1_b[]  = {0x55, 0x48, 0x89, 0xE5};
        static const uint8_t p1_m[]  = {0xFF, 0xFF, 0xFF, 0xFF};
        static const uint8_t p2_b[]  = {0x55, 0x48, 0x8B, 0xEC};
        static const uint8_t p2_m[]  = {0xFF, 0xFF, 0xFF, 0xFF};
        static const uint8_t p3_b[]  = {0x48, 0x83, 0xEC, 0x00};
        static const uint8_t p3_m[]  = {0xFF, 0xFF, 0xFF, 0x00};
        static const uint8_t p4_b[]  = {0x53, 0x48, 0x83, 0xEC, 0x00};
        static const uint8_t p4_m[]  = {0xFF, 0xFF, 0xFF, 0xFF, 0x00};
        static const uint8_t p5_b[]  = {0x48, 0x89, 0x4C, 0x24, 0x08};
        static const uint8_t p5_m[]  = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
        static const uint8_t p6_b[]  = {0x48, 0x89, 0x54, 0x24, 0x10};
        static const uint8_t p6_m[]  = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
        static const uint8_t p7_b[]  = {0x48, 0x89, 0x5C, 0x24, 0x00, 0x48, 0x89, 0x74, 0x24};
        static const uint8_t p7_m[]  = {0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0xFF, 0xFF, 0xFF, 0xFF};
        static const uint8_t p8_b[]  = {0x48, 0x89, 0x5C, 0x24, 0x00, 0x57, 0x48, 0x83, 0xEC};
        static const uint8_t p8_m[]  = {0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0xFF, 0xFF, 0xFF, 0xFF};
        static const uint8_t p9_b[]  = {0x40, 0x53, 0x48, 0x83, 0xEC};
        static const uint8_t p9_m[]  = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
        static const uint8_t p10_b[] = {0x40, 0x55, 0x48, 0x83, 0xEC};
        static const uint8_t p10_m[] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
        static const uint8_t p11_b[] = {0x40, 0x57, 0x48, 0x83, 0xEC};
        static const uint8_t p11_m[] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
        static const uint8_t p12_b[] = {0x48, 0x8B, 0xC4, 0x48, 0x89, 0x58};
        static const uint8_t p12_m[] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
        static const uint8_t p13_b[] = {0x48, 0x8B, 0xC4, 0x48, 0x83, 0xEC};
        static const uint8_t p13_m[] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
        static const uint8_t p14_b[] = {0x48, 0x8B, 0xC4, 0x48, 0x81, 0xEC};
        static const uint8_t p14_m[] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
        static const uint8_t p15_b[] = {0x4C, 0x8B, 0xDC, 0x49, 0x89};
        static const uint8_t p15_m[] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
        static const uint8_t p16_b[] = {0x41, 0x56, 0x41, 0x55};
        static const uint8_t p16_m[] = {0xFF, 0xFF, 0xFF, 0xFF};
        static const uint8_t p17_b[] = {0x57, 0x56, 0x53};
        static const uint8_t p17_m[] = {0xFF, 0xFF, 0xFF};
        static const uint8_t p18_b[] = {0x55, 0x48, 0x83, 0xEC, 0x00};
        static const uint8_t p18_m[] = {0xFF, 0xFF, 0xFF, 0xFF, 0x00};

        static const mini_sig_t prologues[] = {
            {p1_b,  p1_m,  4}, {p2_b,  p2_m,  4}, {p3_b,  p3_m,  4},
            {p4_b,  p4_m,  5}, {p5_b,  p5_m,  5}, {p6_b,  p6_m,  5},
            {p7_b,  p7_m,  9}, {p8_b,  p8_m,  9}, {p9_b,  p9_m,  5},
            {p10_b, p10_m, 5}, {p11_b, p11_m, 5}, {p12_b, p12_m, 6},
            {p13_b, p13_m, 6}, {p14_b, p14_m, 6}, {p15_b, p15_m, 5},
            {p16_b, p16_m, 4}, {p17_b, p17_m, 3}, {p18_b, p18_m, 5},
        };
        constexpr int NUM_PROBES = sizeof(prologues) / sizeof(prologues[0]);

        for (int s = 0; s < num_sections && section_table_off + (s + 1) * 40 <= hdr_size; s++)
        {
            const std::uint8_t* sec_hdr = &pe_header[section_table_off + s * 40];
            std::uint32_t sec_vsize = *reinterpret_cast<const std::uint32_t*>(sec_hdr + 8);
            std::uint32_t sec_vaddr = *reinterpret_cast<const std::uint32_t*>(sec_hdr + 12);
            std::uint32_t sec_chars = *reinterpret_cast<const std::uint32_t*>(sec_hdr + 36);
            if (!(sec_chars & 0x20000000)) continue;

            ea_t sec_start = static_cast<ea_t>(base_addr + sec_vaddr);
            ea_t sec_end   = sec_start + sec_vsize;

            for (ea_t ea = sec_start; ea < sec_end && stats.prologue_funcs_created < 50000; )
            {
                if (!is_loaded(ea)) { ea = next_addr(ea); if (ea == BADADDR || ea >= sec_end) break; continue; }
                func_t* efn = get_func(ea);
                if (efn) { ea = efn->end_ea; continue; }

                bool matched = false;
                for (int p = 0; p < NUM_PROBES && !matched; ++p)
                {
                    const auto& sig = prologues[p];
                    if (ea + sig.length > sec_end) continue;
                    bool sig_ok = true;
                    for (int b = 0; b < sig.length; ++b)
                    {
                        if (!is_loaded(ea + b)) { sig_ok = false; break; }
                        if ((get_byte(ea + b) & sig.mask[b]) != (sig.bytes[b] & sig.mask[b]))
                        { sig_ok = false; break; }
                    }
                    if (!sig_ok) continue;

                    insn_t chk;
                    int valid_count = 0;
                    ea_t check_ea = ea;
                    for (int ci = 0; ci < 8 && check_ea < sec_end; ++ci)
                    {
                        int clen = decode_insn(&chk, check_ea);
                        if (clen <= 0) break;
                        ++valid_count;
                        check_ea += clen;
                        if (chk.itype == NN_retn || chk.itype == NN_retf ||
                            chk.itype == NN_retnw || chk.itype == NN_retnd ||
                            chk.itype == NN_retnq) break;
                    }
                    if (valid_count < 3) continue;
                    matched = true;
                    create_insn(ea);
                    if (!get_func(ea) && add_func(ea, BADADDR))
                        ++stats.prologue_funcs_created;
                }
                if (!matched) ++ea;
                else { func_t* fn = get_func(ea); ea = fn ? fn->end_ea : (ea + 1); }
            }
        }
    }
    responsive_auto_wait(range_start, range_end, "[4/6] Scanning for prologues...");

    replace_wait_box("HIDECANCEL\nAiDA: [5/6] Creating functions from call targets...");
    {
        std::set<ea_t> call_targets;
        for (ea_t ea = range_start; ea < range_end; )
        {
            flags64_t fl = get_flags(ea);
            if (!is_code(fl)) { ea = next_addr(ea); if (ea == BADADDR || ea >= range_end) break; continue; }
            insn_t insn;
            int ilen = decode_insn(&insn, ea);
            if (ilen <= 0) { ++ea; continue; }
            if ((insn.itype == NN_call || insn.itype == NN_callfi || insn.itype == NN_callni)
                && insn.ops[0].type == o_near)
            {
                ea_t target = insn.ops[0].addr;
                if (target >= range_start && target < range_end &&
                    is_loaded(target) && !get_func(target))
                    call_targets.insert(target);
            }
            ea += ilen;
        }
        for (ea_t target : call_targets)
        {
            if (get_func(target)) continue;
            create_insn(target);
            if (add_func(target, BADADDR))
                ++stats.xref_funcs_created;
        }
    }

    replace_wait_box("HIDECANCEL\nAiDA: [6/6] Final analysis pass...");
    responsive_plan_and_wait(range_start, range_end, true, "[6/6] Final analysis pass...");

    for (ea_t fea = range_start; fea < range_end; fea = next_addr(fea))
    {
        func_t* fn = get_func(fea);
        if (fn && fn->start_ea == fea) ++stats.final_func_count;
        if (fn) fea = fn->end_ea - 1;
    }
}

tool_result_t driver_dump_to_idb(const json& params)
{
    if (!device->is_connected() || device->get_process_id() == 0)
        return tool_result_t::error(OBFSTR("Not attached. Call driver_connect then driver_attach first."));

    ea_t base = BADADDR;
    if (params.contains("address"))
    {
        auto a = helpers::parse_address(params["address"].get<std::string>());
        if (a) base = *a;
    }
    if (base == BADADDR || base == 0)
        base = static_cast<ea_t>(device->get_base_address());
    if (base == 0 || base == BADADDR)
        return tool_result_t::error(OBFSTR("Invalid base address"));

    std::uint8_t pe_hdr[0x1000];
    if (device->read_raw(base, pe_hdr, sizeof(pe_hdr)) < 0x200 || *(std::uint16_t*)pe_hdr != 0x5A4D)
        return tool_result_t::error(OBFSTR("Not a PE image at ") + helpers::format_address(base));

    std::uint32_t pe_off = *(std::uint32_t*)(pe_hdr + 0x3C);
    if (pe_off + 0x100 > sizeof(pe_hdr))
        return tool_result_t::error(OBFSTR("PE header offset out of range"));

    std::uint16_t sections_count = *(std::uint16_t*)(pe_hdr + pe_off + 0x06);
    std::uint16_t opt_size       = *(std::uint16_t*)(pe_hdr + pe_off + 0x14);
    std::uint32_t sec_table_off  = pe_off + 0x18 + opt_size;
    std::uint16_t opt_magic      = *(std::uint16_t*)(pe_hdr + pe_off + 0x18);
    std::uint32_t image_size     = 0;
    if (opt_magic == 0x020B || opt_magic == 0x010B)
        image_size = *(std::uint32_t*)(pe_hdr + pe_off + 0x18 + 0x38);
    if (image_size == 0) image_size = 0x1000000;

    int segs_created = 0;
    json segs_info = json::array();

    for (int si = 0; si < sections_count && si < 96; si++)
    {
        std::uint32_t soff = sec_table_off + si * 40;
        std::uint8_t sec[40] = {0};

        if (soff + 40 <= sizeof(pe_hdr))
            memcpy(sec, pe_hdr + soff, 40);
        else if (device->read_raw(base + soff, sec, sizeof(sec)) < sizeof(sec))
            break;

        char name[9] = {0};
        memcpy(name, sec, 8);
        std::uint32_t vsize  = *(std::uint32_t*)(sec + 8);
        std::uint32_t vrva   = *(std::uint32_t*)(sec + 12);
        std::uint32_t chars  = *(std::uint32_t*)(sec + 36);
        if (vsize == 0 || vrva == 0) continue;

        ea_t sec_start = base + vrva;
        ea_t sec_end   = sec_start + vsize;

        uchar perm = 0;
        if (chars & 0x40000000) perm |= SEGPERM_READ;
        if (chars & 0x80000000) perm |= SEGPERM_WRITE;
        if (chars & 0x20000000) perm |= SEGPERM_EXEC;

        bool created = false;
        if (!getseg(sec_start))
        {
            // Use add_segm_ex() instead of add_segm(0,...) per SDK segment.hpp:
            //   "add_segm_ex(): full control over segment properties"
            //   "ADDSEG_QUIET: silent mode"
            // This avoids "bad segment start" for high kernel addresses.
            segment_t new_seg;
            new_seg.start_ea = sec_start;
            new_seg.end_ea   = sec_end;
            new_seg.type     = (perm & SEGPERM_EXEC) ? SEG_CODE : SEG_DATA;
            new_seg.bitness  = (opt_magic == 0x020B) ? 2 : 1;
            new_seg.perm     = perm;
            new_seg.align    = saRelByte;
            new_seg.comb     = scPub;
            const char* sclass = (perm & SEGPERM_EXEC) ? "CODE" : "DATA";
            if (add_segm_ex(&new_seg, name, sclass, ADDSEG_QUIET | ADDSEG_NOSREG))
            {
                segment_t* seg = getseg(sec_start);
                if (seg) { seg->perm = perm; seg->update(); }
                segs_created++;
                created = true;
                segs_info.push_back({{"name", std::string(name)},
                                     {"start", helpers::format_address(sec_start)},
                                     {"size", vsize}});
            }
        }

        // Use put_bytes() for bulk write instead of per-byte put_byte().
        // SDK bytes.hpp put_bytes(): "Modify the specified number of bytes of the program."
        std::vector<std::uint8_t> sec_bytes(vsize, 0);
        std::size_t got = device->read_raw(sec_start, sec_bytes.data(), vsize);
        if (got > 0)
            put_bytes(sec_start, sec_bytes.data(), std::min(got, static_cast<std::size_t>(vsize)));
    }

    std::vector<std::uint8_t> full_image(image_size, 0);
    device->read_raw(base, full_image.data(), image_size);

    // Save dump to Downloads IMMEDIATELY, before analysis
    std::string output_path = get_downloads_folder() + "dumped_module_" +
                              helpers::format_address(base) + ".bin";
    ensure_parent_dir_exists(output_path);
    {
        HANDLE hFile = CreateFileA(output_path.c_str(), GENERIC_WRITE, 0, nullptr,
                                   CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
        if (hFile != INVALID_HANDLE_VALUE)
        {
            DWORD written = 0;
            WriteFile(hFile, full_image.data(), static_cast<DWORD>(image_size), &written, nullptr);
            CloseHandle(hFile);
            msg(OBFSTR_C("AiDA: Dump saved to %s (%u bytes)\n"), output_path.c_str(), image_size);
        }
    }

    post_dump_stats_t dump_stats;
    if (params.value("analyze", true))
    {
        show_wait_box("HIDECANCEL\nAiDA: Running post-dump analysis pipeline...");
        run_post_dump_analysis(
            static_cast<std::uint64_t>(base), image_size,
            pe_hdr, sizeof(pe_hdr),
            full_image.data(), full_image.size(),
            false,
            dump_stats,
            &segs_info);
        hide_wait_box();
    }

    json result;
    result["base"]             = helpers::format_address(base);
    result["image_size"]       = image_size;
    result["sections_created"] = segs_created;
    result["segments"]         = segs_info;
    result["saved_to"]         = output_path;
    result["can_load_in_ida"]  = true;
    result["post_dump_analysis"] = dump_stats.to_json();
    result["note"]             = OBFSTR(
        "Dump file saved to: ") + output_path + OBFSTR(". "
        "For best results, open this file in a NEW IDA Pro instance: "
        "File > Open > select the dumped file. Use manual load with image base ") +
        helpers::format_address(base) + OBFSTR(".");
    return tool_result_t::ok(
        OBFSTR("Dumped ") + std::to_string(segs_created) + " sections, " +
        std::to_string(dump_stats.final_func_count) + " functions recovered (was " +
        std::to_string(dump_stats.initial_func_count) + ") -> " + output_path, result);
}

tool_result_t driver_bypass_and_dump(const json& params)
{
    json steps = json::array();
    auto log = [&](const std::string& step, bool ok, const std::string& detail = "") {
        steps.push_back({{"step", step}, {"ok", ok}, {"detail", detail}});
    };

    if (!device->is_connected())
    {
        bool ok = device->connect();
        log("connect_driver", ok, ok ? "Connected to kernel driver" : "Failed");
        if (!ok)
        {
            json r; r["steps"] = steps;
            return tool_result_t::error(OBFSTR("Failed to connect to kernel driver. Is the driver loaded?"));
        }
    }
    else
        log("connect_driver", true, "Already connected");

    std::string process_name = params["process"].get<std::string>();
    std::uint32_t pid = device->find_process(process_name.c_str());
    log("find_process", pid != 0, "PID: " + (pid ? std::to_string(pid) : "not found"));
    if (pid == 0)
        return tool_result_t::error(OBFSTR("Process not found: ") + process_name);

    std::uint64_t base = device->find_image();
    log("find_image_base", base != 0, helpers::format_address(base));
    if (base == 0)
        return tool_result_t::error(OBFSTR("Failed to locate image base for ") + process_name);

    device->solve_dtb();
    std::uint64_t dtb = device->get_dtb();
    log("solve_dtb", dtb != 0, helpers::format_address(dtb));

    std::uint8_t pe_hdr[0x1000];
    std::size_t hdr_got = device->read_raw(base, pe_hdr, sizeof(pe_hdr));
    log("read_pe_header", hdr_got > 0x200, std::to_string(hdr_got) + " bytes");
    if (hdr_got < 0x200 || *(std::uint16_t*)pe_hdr != 0x5A4D)
        return tool_result_t::error(OBFSTR("Failed to read valid PE header at ") + helpers::format_address(base));

    std::uint32_t pe_off   = *(std::uint32_t*)(pe_hdr + 0x3C);
    std::uint16_t opt_mag  = (pe_off + 0x3A < sizeof(pe_hdr)) ? *(std::uint16_t*)(pe_hdr + pe_off + 0x18) : 0;
    std::uint32_t img_size = 0;
    if (opt_mag == 0x020B || opt_mag == 0x010B)
        img_size = *(std::uint32_t*)(pe_hdr + pe_off + 0x18 + 0x38);
    if (img_size == 0 || img_size > 0x10000000) img_size = 0x2000000;

    std::vector<std::uint8_t> img(img_size, 0);
    std::size_t total_read = 0;
    // Use 64KB chunks for faster reads instead of 4KB
    const std::size_t chunk = 0x10000;

    show_wait_box("HIDECANCEL\nAiDA: Bypassing & dumping %s (0x%X bytes)...", process_name.c_str(), img_size);
    for (std::size_t off = 0; off < img_size; off += chunk)
    {
        if (off % 0x100000 == 0)
            replace_wait_box("HIDECANCEL\nAiDA: Dumping %s (0x%zX / 0x%X, %.1f%%)...",
                             process_name.c_str(), off, img_size, (off * 100.0) / img_size);
        total_read += device->read_raw(base + off, img.data() + off,
                                       std::min(chunk, img_size - off));
    }
    hide_wait_box();
    log("dump_image", total_read > 0, std::to_string(total_read) + "/" + std::to_string(img_size) + " bytes");

    // Save dump to Downloads IMMEDIATELY before any IDB patching.
    // This ensures the user always gets the raw dump even if IDA stalls.
    std::string output_path = get_downloads_folder() + "dumped_" + process_name + "_" +
                              helpers::format_address(static_cast<ea_t>(base)) + ".bin";
    ensure_parent_dir_exists(output_path);
    {
        HANDLE hFile = CreateFileA(output_path.c_str(), GENERIC_WRITE, 0, nullptr,
                                   CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
        if (hFile != INVALID_HANDLE_VALUE)
        {
            DWORD written = 0;
            WriteFile(hFile, img.data(), static_cast<DWORD>(img_size), &written, nullptr);
            CloseHandle(hFile);
            msg(OBFSTR_C("AiDA: Dump saved to %s (%u bytes)\n"), output_path.c_str(), img_size);
        }
        log("save_to_disk", true, output_path);
    }

    // Use put_bytes() bulk API instead of per-byte put_byte() to avoid UI freeze.
    // SDK bytes.hpp put_bytes(): "Modify the specified number of bytes of the program."
    show_wait_box("HIDECANCEL\nAiDA: Patching IDA database (bulk)...");
    std::size_t patched = 0;
    int seg_count = get_segm_qty();
    for (int si = 0; si < seg_count; ++si)
    {
        segment_t* seg = getnseg(si);
        if (!seg) continue;
        if (seg->start_ea >= base + img_size || seg->end_ea <= base) continue;

        ea_t patch_start = std::max(seg->start_ea, static_cast<ea_t>(base));
        ea_t patch_end   = std::min(seg->end_ea, static_cast<ea_t>(base + img_size));
        std::size_t offset = static_cast<std::size_t>(patch_start - base);
        std::size_t length = static_cast<std::size_t>(patch_end - patch_start);

        if (offset < img_size && length > 0)
        {
            put_bytes(patch_start, img.data() + offset, length);
            patched += length;
        }
    }
    hide_wait_box();
    log("patch_idb", patched > 0, std::to_string(patched) + " bytes patched");

    bool hb = device->send_heartbeat();
    log("heartbeat", hb, hb ? "Session maintained" : "Failed (non-fatal)");

    post_dump_stats_t dump_stats;
    if (params.value("analyze", true))
    {
        show_wait_box("HIDECANCEL\nAiDA: Running post-dump analysis pipeline...");
        run_post_dump_analysis(
            static_cast<std::uint64_t>(base), img_size,
            pe_hdr, sizeof(pe_hdr),
            img.data(), img.size(),
            false,
            dump_stats);
        hide_wait_box();
        log("post_dump_analysis", dump_stats.final_func_count > dump_stats.initial_func_count,
            std::to_string(dump_stats.final_func_count) + " functions (was " +
            std::to_string(dump_stats.initial_func_count) + ")");
    }

    json result;
    result["process"]       = process_name;
    result["pid"]           = pid;
    result["base"]          = helpers::format_address(base);
    result["dtb"]           = helpers::format_address(dtb);
    result["image_size"]    = img_size;
    result["bytes_dumped"]  = total_read;
    result["coverage_pct"]  = total_read ? (int)((total_read * 100) / img_size) : 0;
    result["bytes_patched"] = patched;
    result["saved_to"]      = output_path;
    result["can_load_in_ida"] = true;
    result["steps"]         = steps;
    result["post_dump_analysis"] = dump_stats.to_json();
    result["note"]          = OBFSTR(
        "Dump file saved to: ") + output_path + OBFSTR(". "
        "For best static analysis, open this file in a NEW IDA Pro instance: "
        "File > Open > select the dumped file. Use manual load with image base ") +
        helpers::format_address(static_cast<ea_t>(base)) + OBFSTR(".");

    return tool_result_t::ok(OBFSTR("Bypass-and-dump complete for ") + process_name +
                             OBFSTR(": ") + std::to_string(total_read) + OBFSTR("/") +
                             std::to_string(img_size) + OBFSTR(" bytes, ") +
                             std::to_string(dump_stats.final_func_count) +
                             OBFSTR(" functions recovered -> ") + output_path, result);
}

static std::string resolve_nt_path_to_win32(const std::string& nt_path)
{
    std::string result = nt_path;
    std::replace(result.begin(), result.end(), '/', '\\');

    if (result.size() >= 12)
    {
        std::string prefix_lower = result.substr(0, 12);
        std::transform(prefix_lower.begin(), prefix_lower.end(), prefix_lower.begin(),
            [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
        if (prefix_lower == "\\systemroot\\")
        {
            char win_dir[MAX_PATH] = {};
            GetWindowsDirectoryA(win_dir, MAX_PATH);
            result = std::string(win_dir) + "\\" + result.substr(12);
        }
    }

    if (result.size() >= 4 && result.substr(0, 4) == "\\??\\")
        result = result.substr(4);

    return result;
}

struct sys_module_entry_t
{
    HANDLE   Section;
    PVOID    MappedBase;
    PVOID    ImageBase;
    ULONG    ImageSize;
    ULONG    Flags;
    USHORT   LoadOrderIndex;
    USHORT   InitOrderIndex;
    USHORT   LoadCount;
    USHORT   OffsetToFileName;
    UCHAR    FullPathName[256];
};

struct sys_module_info_t
{
    ULONG              NumberOfModules;
    sys_module_entry_t Modules[1];
};

typedef LONG(NTAPI* NtQuerySystemInformation_fn)(
    ULONG SystemInformationClass,
    PVOID SystemInformation,
    ULONG SystemInformationLength,
    PULONG ReturnLength);

static bool query_kernel_modules(
    std::vector<std::uint8_t>& out_buffer,
    sys_module_info_t*& out_info,
    std::string& error_msg)
{
    HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
    if (!ntdll)
    {
        error_msg = OBFSTR("Cannot resolve ntdll.dll");
        return false;
    }

    auto pNtQuerySystemInformation = reinterpret_cast<NtQuerySystemInformation_fn>(
        GetProcAddress(ntdll, "NtQuerySystemInformation"));
    if (!pNtQuerySystemInformation)
    {
        error_msg = OBFSTR("Cannot resolve NtQuerySystemInformation");
        return false;
    }

    constexpr ULONG SystemModuleInformation = 11;
    ULONG needed = 0;
    pNtQuerySystemInformation(SystemModuleInformation, nullptr, 0, &needed);
    if (needed == 0)
        needed = 256 * 1024;
    needed += 16384;

    out_buffer.resize(needed, 0);
    LONG status = pNtQuerySystemInformation(
        SystemModuleInformation, out_buffer.data(),
        static_cast<ULONG>(out_buffer.size()), &needed);

    if (status < 0)
    {
        error_msg = OBFSTR("NtQuerySystemInformation(SystemModuleInformation) failed: NTSTATUS 0x")
            + helpers::format_address(static_cast<ea_t>(static_cast<unsigned long>(status)));
        return false;
    }

    out_info = reinterpret_cast<sys_module_info_t*>(out_buffer.data());
    return true;
}

tool_result_t driver_enumerate_kernel_modules(const json& params)
{
    std::vector<std::uint8_t> buf;
    sys_module_info_t* info = nullptr;
    std::string err;
    if (!query_kernel_modules(buf, info, err))
        return tool_result_t::error(err);

    std::string filter;
    if (params.contains("filter") && params["filter"].is_string())
        filter = params["filter"].get<std::string>();

    int limit = params.value("limit", 500);

    json modules_arr = json::array();
    for (ULONG i = 0; i < info->NumberOfModules && static_cast<int>(modules_arr.size()) < limit; i++)
    {
        const auto& m = info->Modules[i];
        std::string full_path(reinterpret_cast<const char*>(m.FullPathName));
        std::string name(reinterpret_cast<const char*>(m.FullPathName + m.OffsetToFileName));

        if (!filter.empty())
        {
            std::string lower_name = name;
            std::string lower_filter = filter;
            std::transform(lower_name.begin(), lower_name.end(), lower_name.begin(),
                [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
            std::transform(lower_filter.begin(), lower_filter.end(), lower_filter.begin(),
                [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
            if (lower_name.find(lower_filter) == std::string::npos)
            {
                std::string lower_path = full_path;
                std::transform(lower_path.begin(), lower_path.end(), lower_path.begin(),
                    [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
                if (lower_path.find(lower_filter) == std::string::npos)
                    continue;
            }
        }

        std::string resolved_path = resolve_nt_path_to_win32(full_path);

        json entry;
        entry["name"]           = name;
        entry["nt_path"]        = full_path;
        entry["disk_path"]      = resolved_path;
        entry["base_address"]   = helpers::format_address(
            static_cast<ea_t>(reinterpret_cast<std::uintptr_t>(m.ImageBase)));
        entry["size"]           = m.ImageSize;
        entry["size_hex"]       = helpers::format_address(static_cast<ea_t>(m.ImageSize));
        entry["load_order"]     = m.LoadOrderIndex;
        modules_arr.push_back(entry);
    }

    json result;
    result["modules"]        = modules_arr;
    result["total_loaded"]   = info->NumberOfModules;
    result["returned"]       = modules_arr.size();

    return tool_result_t::ok(
        OBFSTR("Enumerated ") + std::to_string(modules_arr.size()) + OBFSTR(" kernel modules") +
        (filter.empty() ? "" : OBFSTR(" matching '") + filter + "'"), result);
}

tool_result_t driver_dump_kernel_module(const json& params)
{
    std::string module_name = params["module"].get<std::string>();
    std::string output_path = params.value("output_path", std::string());

    std::vector<std::uint8_t> buf;
    sys_module_info_t* info = nullptr;
    std::string err;
    if (!query_kernel_modules(buf, info, err))
        return tool_result_t::error(err);

    std::string found_name, found_nt_path;
    std::uintptr_t found_base = 0;
    ULONG found_size = 0;
    bool found = false;

    std::string lower_target = module_name;
    std::transform(lower_target.begin(), lower_target.end(), lower_target.begin(),
        [](unsigned char c) { return static_cast<char>(std::tolower(c)); });

    for (ULONG i = 0; i < info->NumberOfModules; i++)
    {
        const auto& m = info->Modules[i];
        std::string name(reinterpret_cast<const char*>(m.FullPathName + m.OffsetToFileName));
        std::string full_path(reinterpret_cast<const char*>(m.FullPathName));

        std::string lower_name = name;
        std::transform(lower_name.begin(), lower_name.end(), lower_name.begin(),
            [](unsigned char c) { return static_cast<char>(std::tolower(c)); });

        if (lower_name == lower_target || lower_name.find(lower_target) != std::string::npos)
        {
            found_name    = name;
            found_nt_path = full_path;
            found_base    = reinterpret_cast<std::uintptr_t>(m.ImageBase);
            found_size    = m.ImageSize;
            found = true;
            break;
        }
    }

    if (!found)
        return tool_result_t::error(
            OBFSTR("Kernel module not found: ") + module_name +
            OBFSTR(". Use driver_enumerate_kernel_modules with filter to list loaded drivers."));

    bool use_memory = params.value("from_memory", true);

    if (use_memory)
    {
        if (!device || !device->is_connected())
            return tool_result_t::error(
                OBFSTR("Driver not connected. Call driver_connect first for in-memory kernel dump."));

        if (device->get_kernel_dtb() == 0)
        {
            device->solve_kernel_dtb();
            if (device->get_kernel_dtb() == 0)
                return tool_result_t::error(
                    OBFSTR("Failed to solve kernel DTB (System process PID 4). "
                           "Cannot read kernel memory."));
        }

        if (output_path.empty())
        {
            output_path = get_downloads_folder() + "dumped_" + found_name;
        }

        std::uint64_t base_addr = static_cast<std::uint64_t>(found_base);
        std::uint32_t image_size = found_size;

        std::vector<std::uint8_t> header_buf(0x1000, 0);
        std::size_t header_read = device->read_kernel_raw(base_addr, header_buf.data(), 0x1000);
        if (header_read < 0x40 || header_buf[0] != 'M' || header_buf[1] != 'Z')
        {
            return tool_result_t::error(
                OBFSTR("Failed to read PE header at kernel base ") +
                helpers::format_address(static_cast<ea_t>(base_addr)) +
                OBFSTR(". Read ") + std::to_string(header_read) + OBFSTR(" bytes. "
                "MZ signature not found Ã¢â‚¬â€ module may be packed or encrypted in memory."));
        }

        std::uint32_t pe_off = *reinterpret_cast<std::uint32_t*>(&header_buf[0x3C]);
        if (pe_off + 0x18 > header_read || header_buf[pe_off] != 'P' || header_buf[pe_off + 1] != 'E')
        {
            return tool_result_t::error(
                OBFSTR("Invalid PE signature at offset 0x") +
                helpers::format_address(static_cast<ea_t>(pe_off)));
        }

        std::uint16_t machine = *reinterpret_cast<std::uint16_t*>(&header_buf[pe_off + 4]);
        std::uint16_t num_sections = *reinterpret_cast<std::uint16_t*>(&header_buf[pe_off + 6]);
        std::uint16_t opt_hdr_size = *reinterpret_cast<std::uint16_t*>(&header_buf[pe_off + 20]);
        std::uint32_t pe_image_size = *reinterpret_cast<std::uint32_t*>(&header_buf[pe_off + 24 + 56]);

        std::uint32_t dump_size = (pe_image_size > image_size) ? pe_image_size : image_size;
        if (dump_size == 0 || dump_size > 256 * 1024 * 1024)
        {
            return tool_result_t::error(
                OBFSTR("Invalid image size: ") + std::to_string(dump_size));
        }

        std::vector<std::uint8_t> dump_data(dump_size, 0);

        std::memcpy(dump_data.data(), header_buf.data(), std::min<std::size_t>(header_read, dump_size));

        show_wait_box("HIDECANCEL\nAiDA: Dumping kernel module %s from memory (0x%X bytes)...",
                      found_name.c_str(), dump_size);

        constexpr std::size_t CHUNK_SIZE = 0x10000;  // 64KB chunks for faster kernel reads
        std::size_t total_read = header_read;
        std::size_t readable_pages = 1;

        for (std::uint32_t offset = static_cast<std::uint32_t>(header_read);
             offset < dump_size; offset += CHUNK_SIZE)
        {
            std::size_t to_read = CHUNK_SIZE;
            if (offset + to_read > dump_size)
                to_read = dump_size - offset;

            std::size_t bytes_got = device->read_kernel_raw(
                base_addr + offset, dump_data.data() + offset, to_read);

            if (bytes_got > 0)
            {
                total_read += bytes_got;
                readable_pages++;
            }

            if (offset % 0x40000 == 0)
                replace_wait_box("HIDECANCEL\nAiDA: Dumping %s: 0x%X / 0x%X (%.1f%%)",
                                 found_name.c_str(), offset, dump_size,
                                 (offset * 100.0) / dump_size);
        }

        hide_wait_box();

        show_wait_box("HIDECANCEL\nAiDA: Writing memory dump to %s...", output_path.c_str());
        ensure_parent_dir_exists(output_path);

        HANDLE hOut = CreateFileA(
            output_path.c_str(), GENERIC_WRITE, 0, nullptr,
            CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);

        if (hOut == INVALID_HANDLE_VALUE)
        {
            hide_wait_box();
            return tool_result_t::error(
                OBFSTR("Failed to create output file: ") + output_path +
                OBFSTR(". Win32 error: ") + std::to_string(GetLastError()));
        }

        DWORD bytes_written = 0;
        WriteFile(hOut, dump_data.data(), static_cast<DWORD>(dump_size), &bytes_written, nullptr);
        CloseHandle(hOut);
        hide_wait_box();

        std::string pe_arch = "unknown";
        if (machine == 0x8664) pe_arch = "AMD64";
        else if (machine == 0x014C) pe_arch = "i386";
        else if (machine == 0xAA64) pe_arch = "ARM64";

        int coverage = dump_size ? static_cast<int>((total_read * 100) / dump_size) : 0;

        json result;
        result["module_name"]       = found_name;
        result["nt_path"]           = found_nt_path;
        result["kernel_base"]       = helpers::format_address(static_cast<ea_t>(found_base));
        result["kernel_size"]       = found_size;
        result["pe_image_size"]     = pe_image_size;
        result["dump_size"]         = dump_size;
        result["bytes_read"]        = total_read;
        result["readable_pages"]    = readable_pages;
        result["coverage_pct"]      = coverage;
        result["output_path"]       = output_path;
        result["valid_pe"]          = true;
        result["architecture"]      = pe_arch;
        result["num_sections"]      = num_sections;
        result["dump_source"]       = "kernel_memory";
        result["can_load_in_ida"]   = true;
        result["note"]              = OBFSTR(
            "LIVE MEMORY DUMP Ã¢â‚¬â€ contains runtime-decrypted code, devirtualized sections, "
            "and unpacked data as they exist in kernel memory. Open in IDA Pro: "
            "File > Open > select the dumped file > choose manual load with image base ") +
            helpers::format_address(static_cast<ea_t>(found_base)) +
            OBFSTR(". Some pages may be zero-filled if they were paged out.");

        return tool_result_t::ok(
            OBFSTR("Kernel module memory-dumped: ") + found_name + OBFSTR(" (") +
            std::to_string(total_read) + OBFSTR("/") + std::to_string(dump_size) +
            OBFSTR(" bytes, ") + std::to_string(coverage) + OBFSTR("% coverage) -> ") +
            output_path, result);
    }

    std::string disk_path = resolve_nt_path_to_win32(found_nt_path);

    if (output_path.empty())
    {
        output_path = get_downloads_folder() + "dumped_" + found_name;
    }

    HANDLE hFile = CreateFileA(
        disk_path.c_str(), GENERIC_READ,
        FILE_SHARE_READ | FILE_SHARE_DELETE, nullptr,
        OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);

    if (hFile == INVALID_HANDLE_VALUE)
    {
        hFile = CreateFileA(
            found_nt_path.c_str(), GENERIC_READ,
            FILE_SHARE_READ | FILE_SHARE_DELETE, nullptr,
            OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    }

    if (hFile == INVALID_HANDLE_VALUE)
    {
        DWORD last_err = GetLastError();
        return tool_result_t::error(
            OBFSTR("Cannot open driver file: ") + disk_path +
            OBFSTR(" (Win32 error: ") + std::to_string(last_err) +
            OBFSTR("). Connect the kernel driver and use from_memory=true for live dump."));
    }

    LARGE_INTEGER file_size_li;
    if (!GetFileSizeEx(hFile, &file_size_li) || file_size_li.QuadPart == 0)
    {
        CloseHandle(hFile);
        return tool_result_t::error(OBFSTR("Cannot determine file size for: ") + disk_path);
    }

    if (file_size_li.QuadPart > 256LL * 1024 * 1024)
    {
        CloseHandle(hFile);
        return tool_result_t::error(
            OBFSTR("Driver file exceeds 256 MB limit: ") +
            std::to_string(file_size_li.QuadPart) + OBFSTR(" bytes"));
    }

    std::size_t file_size = static_cast<std::size_t>(file_size_li.QuadPart);
    std::vector<std::uint8_t> file_data(file_size);

    show_wait_box("HIDECANCEL\nAiDA: Reading kernel module %s from disk (%zu bytes)...",
                  found_name.c_str(), file_size);

    DWORD total_read = 0;
    while (total_read < static_cast<DWORD>(file_size))
    {
        DWORD to_read = static_cast<DWORD>(
            std::min<std::size_t>(file_size - total_read, 0x100000));
        DWORD bytes_read = 0;
        if (!ReadFile(hFile, file_data.data() + total_read, to_read, &bytes_read, nullptr) || bytes_read == 0)
            break;
        total_read += bytes_read;
    }
    CloseHandle(hFile);
    hide_wait_box();

    if (total_read == 0)
        return tool_result_t::error(OBFSTR("Failed to read any bytes from: ") + disk_path);

    ensure_parent_dir_exists(output_path);
    HANDLE hOut = CreateFileA(
        output_path.c_str(), GENERIC_WRITE, 0, nullptr,
        CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);

    if (hOut == INVALID_HANDLE_VALUE)
    {
        return tool_result_t::error(
            OBFSTR("Failed to create output file: ") + output_path +
            OBFSTR(". Win32 error: ") + std::to_string(GetLastError()));
    }

    DWORD bytes_written = 0;
    WriteFile(hOut, file_data.data(), total_read, &bytes_written, nullptr);
    CloseHandle(hOut);

    bool is_valid_pe = false;
    std::string pe_arch = "unknown";
    if (file_data.size() >= 0x40 && file_data[0] == 'M' && file_data[1] == 'Z')
    {
        std::uint32_t pe_off = *reinterpret_cast<std::uint32_t*>(&file_data[0x3C]);
        if (pe_off + 6 < file_data.size() &&
            file_data[pe_off] == 'P' && file_data[pe_off + 1] == 'E' &&
            file_data[pe_off + 2] == 0 && file_data[pe_off + 3] == 0)
        {
            is_valid_pe = true;
            std::uint16_t machine = *reinterpret_cast<std::uint16_t*>(&file_data[pe_off + 4]);
            if (machine == 0x8664) pe_arch = "AMD64";
            else if (machine == 0x014C) pe_arch = "i386";
            else if (machine == 0xAA64) pe_arch = "ARM64";
        }
    }

    json result;
    result["module_name"]       = found_name;
    result["nt_path"]           = found_nt_path;
    result["disk_path"]         = disk_path;
    result["kernel_base"]       = helpers::format_address(static_cast<ea_t>(found_base));
    result["kernel_size"]       = found_size;
    result["file_size"]         = total_read;
    result["output_path"]       = output_path;
    result["valid_pe"]          = is_valid_pe;
    result["architecture"]      = pe_arch;
    result["dump_source"]       = "disk";
    result["can_load_in_ida"]   = is_valid_pe;
    result["note"]              = OBFSTR(
        "ON-DISK dump (not live memory). Contains static file contents only. "
        "For runtime-decrypted code, use from_memory=true with driver connected.");

    return tool_result_t::ok(
        OBFSTR("Kernel module disk-dumped: ") + found_name + OBFSTR(" (") +
        std::to_string(bytes_written) + OBFSTR(" bytes) -> ") + output_path, result);
}

tool_result_t driver_read_kernel_memory(const json& params)
{
    if (!device || !device->is_connected())
        return tool_result_t::error(OBFSTR("Driver not connected. Call driver_connect first."));

    if (device->get_kernel_dtb() == 0)
    {
        device->solve_kernel_dtb();
        if (device->get_kernel_dtb() == 0)
            return tool_result_t::error(OBFSTR("Failed to solve kernel DTB."));
    }

    std::string addr_str = params["address"].get<std::string>();
    auto addr_opt = helpers::parse_address(addr_str);
    if (!addr_opt.has_value())
        return tool_result_t::error(OBFSTR("Invalid address: ") + addr_str);

    std::uint64_t address = static_cast<std::uint64_t>(addr_opt.value());
    std::size_t size = params.value("size", 256);
    if (size > 65536) size = 65536;
    if (size == 0) size = 256;

    bool patch_idb = params.value("patch_idb", false);

    std::vector<std::uint8_t> buffer(size, 0);
    std::size_t bytes_read = device->read_kernel_raw(address, buffer.data(), size);

    if (bytes_read == 0)
        return tool_result_t::error(
            OBFSTR("Failed to read kernel memory at ") +
            helpers::format_address(static_cast<ea_t>(address)));

    std::ostringstream hex_dump;
    hex_dump << std::hex << std::setfill('0');
    for (std::size_t i = 0; i < bytes_read; i++)
    {
        if (i > 0 && (i % 16) == 0) hex_dump << "\n";
        else if (i > 0) hex_dump << " ";
        hex_dump << std::setw(2) << static_cast<int>(buffer[i]);
    }

    std::string ascii;
    ascii.reserve(bytes_read);
    for (std::size_t i = 0; i < bytes_read; i++)
        ascii += (buffer[i] >= 0x20 && buffer[i] < 0x7F) ? static_cast<char>(buffer[i]) : '.';

    std::size_t patched = 0;
    if (patch_idb)
    {
        ea_t ea = static_cast<ea_t>(address);
        for (std::size_t i = 0; i < bytes_read; i++)
        {
            if (is_mapped(ea + static_cast<ea_t>(i)))
            {
                patch_byte(ea + static_cast<ea_t>(i), buffer[i]);
                patched++;
            }
        }
    }

    json result;
    result["address"]       = helpers::format_address(static_cast<ea_t>(address));
    result["bytes_read"]    = bytes_read;
    result["requested"]     = size;
    result["hex"]           = hex_dump.str();
    result["ascii"]         = ascii;
    result["source"]        = "kernel_memory";
    result["kernel_dtb"]    = helpers::format_address(static_cast<ea_t>(device->get_kernel_dtb()));
    if (patch_idb)
        result["bytes_patched"] = patched;

    return tool_result_t::ok(
        OBFSTR("Read ") + std::to_string(bytes_read) + OBFSTR(" bytes from kernel address ") +
        helpers::format_address(static_cast<ea_t>(address)), result);
}

tool_result_t driver_write_kernel_memory(const json& params)
{
    if (!device || !device->is_connected())
        return tool_result_t::error(OBFSTR("Driver not connected. Call driver_connect first."));

    if (device->get_kernel_dtb() == 0)
    {
        device->solve_kernel_dtb();
        if (device->get_kernel_dtb() == 0)
            return tool_result_t::error(OBFSTR("Failed to solve kernel DTB."));
    }

    std::string addr_str = params["address"].get<std::string>();
    auto addr_opt = helpers::parse_address(addr_str);
    if (!addr_opt.has_value())
        return tool_result_t::error(OBFSTR("Invalid address: ") + addr_str);

    std::uint64_t address = static_cast<std::uint64_t>(addr_opt.value());

    std::string hex_bytes = params["bytes"].get<std::string>();
    std::vector<std::uint8_t> data;
    std::istringstream iss(hex_bytes);
    std::string byte_str;
    while (iss >> byte_str)
    {
        unsigned long val = std::strtoul(byte_str.c_str(), nullptr, 16);
        data.push_back(static_cast<std::uint8_t>(val));
    }

    if (data.empty())
        return tool_result_t::error(OBFSTR("No valid bytes to write."));

    if (data.size() > 4096)
        return tool_result_t::error(OBFSTR("Write size exceeds 4096 byte limit."));

    std::size_t written = device->write_kernel_raw(address, data.data(), data.size());

    json result;
    result["address"]       = helpers::format_address(static_cast<ea_t>(address));
    result["bytes_written"] = written;
    result["requested"]     = data.size();
    result["source"]        = "kernel_memory";

    if (written == 0)
        return tool_result_t::error(
            OBFSTR("Failed to write kernel memory at ") +
            helpers::format_address(static_cast<ea_t>(address)));

    return tool_result_t::ok(
        OBFSTR("Wrote ") + std::to_string(written) + OBFSTR(" bytes to kernel address ") +
        helpers::format_address(static_cast<ea_t>(address)), result);
}

tool_result_t driver_kernel_dump_module(const json& params)
{
    if (!device || !device->is_connected())
        return tool_result_t::error(OBFSTR("Driver not connected. Call driver_connect first."));

    if (device->get_kernel_dtb() == 0)
    {
        device->solve_kernel_dtb();
        if (device->get_kernel_dtb() == 0)
            return tool_result_t::error(OBFSTR("Failed to solve kernel DTB."));
    }

    std::string module_name = params["module"].get<std::string>();
    bool patch_idb = params.value("patch_idb", true);
    bool analyze = params.value("analyze", true);
    std::string output_path = params.value("output_path", std::string());

    std::vector<std::uint8_t> enum_buf;
    sys_module_info_t* info = nullptr;
    std::string err;
    if (!query_kernel_modules(enum_buf, info, err))
        return tool_result_t::error(err);

    std::string found_name;
    std::uintptr_t found_base = 0;
    ULONG found_size = 0;
    bool found = false;

    std::string lower_target = module_name;
    std::transform(lower_target.begin(), lower_target.end(), lower_target.begin(),
        [](unsigned char c) { return static_cast<char>(std::tolower(c)); });

    for (ULONG i = 0; i < info->NumberOfModules; i++)
    {
        const auto& m = info->Modules[i];
        std::string name(reinterpret_cast<const char*>(m.FullPathName + m.OffsetToFileName));
        std::string lower_name = name;
        std::transform(lower_name.begin(), lower_name.end(), lower_name.begin(),
            [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
        if (lower_name == lower_target || lower_name.find(lower_target) != std::string::npos)
        {
            found_name = name;
            found_base = reinterpret_cast<std::uintptr_t>(m.ImageBase);
            found_size = m.ImageSize;
            found = true;
            break;
        }
    }

    if (!found)
        return tool_result_t::error(OBFSTR("Kernel module not found: ") + module_name);

    std::uint64_t base_addr = static_cast<std::uint64_t>(found_base);

    std::vector<std::uint8_t> header(0x1000, 0);
    std::size_t hdr_read = device->read_kernel_raw(base_addr, header.data(), 0x1000);
    if (hdr_read < 0x40 || header[0] != 'M' || header[1] != 'Z')
        return tool_result_t::error(
            OBFSTR("Cannot read PE header at ") +
            helpers::format_address(static_cast<ea_t>(base_addr)));

    std::uint32_t pe_off = *reinterpret_cast<std::uint32_t*>(&header[0x3C]);
    if (pe_off + 0x18 > hdr_read || header[pe_off] != 'P' || header[pe_off + 1] != 'E')
        return tool_result_t::error(OBFSTR("Invalid PE signature."));

    std::uint16_t num_sections = *reinterpret_cast<std::uint16_t*>(&header[pe_off + 6]);
    std::uint16_t opt_hdr_size = *reinterpret_cast<std::uint16_t*>(&header[pe_off + 20]);
    std::uint32_t pe_image_size = *reinterpret_cast<std::uint32_t*>(&header[pe_off + 24 + 56]);
    std::uint32_t dump_size = (pe_image_size > found_size) ? pe_image_size : found_size;

    std::uint32_t section_table_off = pe_off + 24 + opt_hdr_size;

    show_wait_box("HIDECANCEL\nAiDA: Dumping kernel module %s to IDB (0x%X bytes, %d sections)...",
                  found_name.c_str(), dump_size, num_sections);

    std::vector<std::uint8_t> image(dump_size, 0);
    std::memcpy(image.data(), header.data(), std::min<std::size_t>(hdr_read, dump_size));

    std::size_t total_read = hdr_read;
    constexpr std::size_t K_CHUNK = 0x10000;  // 64KB chunks for faster kernel reads
    for (std::uint32_t offset = 0x1000; offset < dump_size; offset += K_CHUNK)
    {
        std::size_t to_read = K_CHUNK;
        if (offset + to_read > dump_size) to_read = dump_size - offset;

        std::size_t got = device->read_kernel_raw(base_addr + offset, image.data() + offset, to_read);
        if (got > 0) total_read += got;

        if (offset % 0x40000 == 0)
            replace_wait_box("HIDECANCEL\nAiDA: Dumping %s: 0x%X / 0x%X (%.1f%%)",
                             found_name.c_str(), offset, dump_size,
                             (offset * 100.0) / dump_size);
    }

    // Always save raw dump to Downloads for user to open in new IDA instance
    std::string saved_to = output_path;
    if (saved_to.empty())
        saved_to = get_downloads_folder() + "dumped_" + found_name;
    ensure_parent_dir_exists(saved_to);
    {
        HANDLE hSave = CreateFileA(
            saved_to.c_str(), GENERIC_WRITE, 0, nullptr,
            CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
        if (hSave == INVALID_HANDLE_VALUE)
        {
            hide_wait_box();
            return tool_result_t::error(
                OBFSTR("Failed to save dump file: ") + saved_to +
                OBFSTR(". Win32 error: ") + std::to_string(GetLastError()));
        }
        DWORD written = 0;
        WriteFile(hSave, image.data(), static_cast<DWORD>(dump_size), &written, nullptr);
        CloseHandle(hSave);
        msg(OBFSTR_C("AiDA: Dump saved to %s (%u bytes)\n"), saved_to.c_str(), dump_size);
    }

    std::size_t patched = 0;
    json sections_arr = json::array();
    post_dump_stats_t stats;

    if (patch_idb)
    {
        for (int s = 0; s < num_sections && section_table_off + (s + 1) * 40 <= hdr_read; s++)
        {
            const std::uint8_t* sec = &header[section_table_off + s * 40];
            char sec_name[9] = {};
            std::memcpy(sec_name, sec, 8);

            std::uint32_t virt_size = *reinterpret_cast<const std::uint32_t*>(sec + 8);
            std::uint32_t virt_addr = *reinterpret_cast<const std::uint32_t*>(sec + 12);
            std::uint32_t characteristics = *reinterpret_cast<const std::uint32_t*>(sec + 36);

            ea_t seg_start = static_cast<ea_t>(base_addr + virt_addr);
            ea_t seg_end   = seg_start + virt_size;

            segment_t* existing = getseg(seg_start);
            if (!existing)
            {
                segment_t seg;
                seg.start_ea = seg_start;
                seg.end_ea   = seg_end;
                seg.type     = (characteristics & 0x20000000) ? SEG_CODE : SEG_DATA;
                seg.bitness  = 2;
                seg.perm     = 0;
                if (characteristics & 0x20000000) seg.perm |= SEGPERM_EXEC;
                if (characteristics & 0x40000000) seg.perm |= SEGPERM_READ;
                if (characteristics & 0x80000000) seg.perm |= SEGPERM_WRITE;
                add_segm_ex(&seg, sec_name, nullptr, ADDSEG_QUIET | ADDSEG_NOSREG);
            }

            // Bulk write entire section data at once instead of per-byte patch_byte()
            std::uint32_t copy_len = virt_size;
            if (virt_addr + copy_len > dump_size)
                copy_len = dump_size - virt_addr;

            std::size_t sec_patched = 0;
            if (copy_len > 0 && is_mapped(seg_start))
            {
                put_bytes(seg_start, image.data() + virt_addr, copy_len);
                sec_patched = copy_len;
            }
            patched += sec_patched;

            json sec_info;
            sec_info["name"]            = sec_name;
            sec_info["virtual_address"] = helpers::format_address(static_cast<ea_t>(virt_addr));
            sec_info["virtual_size"]    = virt_size;
            sec_info["characteristics"] = helpers::format_address(static_cast<ea_t>(characteristics));
            sec_info["bytes_patched"]   = sec_patched;
            sections_arr.push_back(sec_info);
        }

        if (analyze)
        {
            run_post_dump_analysis(
                base_addr, dump_size,
                header.data(), hdr_read,
                image.data(), image.size(),
                true,
                stats,
                &sections_arr);
        }
    }

    hide_wait_box();

    int coverage = dump_size ? static_cast<int>((total_read * 100) / dump_size) : 0;

    json result;
    result["module_name"]       = found_name;
    result["kernel_base"]       = helpers::format_address(static_cast<ea_t>(found_base));
    result["image_size"]        = dump_size;
    result["bytes_read"]        = total_read;
    result["coverage_pct"]      = coverage;
    result["num_sections"]      = num_sections;
    result["sections"]          = sections_arr;
    result["bytes_patched"]     = patched;
    result["analyzed"]          = analyze && patch_idb;
    result["output_path"]       = saved_to;
    result["saved_to"]          = saved_to;
    result["can_load_in_ida"]   = true;
    result["note"]              = OBFSTR(
        "Kernel module dumped and saved to disk. Open in a NEW IDA Pro instance: "
        "File > Open > select the dumped file > choose manual load with image base ") +
        helpers::format_address(static_cast<ea_t>(found_base)) +
        OBFSTR(". Some pages may be zero-filled if they were paged out.");
    result["post_dump_analysis"] = stats.to_json();

    return tool_result_t::ok(
        OBFSTR("Kernel module ") + found_name +
        OBFSTR(" dumped to IDB: ") + std::to_string(total_read) + OBFSTR("/") +
        std::to_string(dump_size) + OBFSTR(" bytes, ") + std::to_string(patched) +
        OBFSTR(" bytes patched, ") + std::to_string(stats.final_func_count) +
        OBFSTR(" functions recovered (was ") + std::to_string(stats.initial_func_count) +
        OBFSTR(")"), result);
}

tool_result_t driver_allocate_memory(const json& params)
{
    if (!device->is_connected() || device->get_process_id() == 0)
        return tool_result_t::error(OBFSTR("Not attached. Call driver_connect then driver_attach first."));

    std::size_t size = 0;
    if (params.contains("size"))
    {
        if (params["size"].is_number())
            size = params["size"].get<std::size_t>();
        else if (params["size"].is_string())
        {
            auto addr = helpers::parse_address(params["size"].get<std::string>());
            if (addr) size = static_cast<std::size_t>(*addr);
        }
    }
    if (size == 0 || size > 0x1000000)
        return tool_result_t::error(OBFSTR("Invalid size. Must be 1 to 16777216 (16MB)."));

    std::uint64_t allocated = device->allocate_memory(size);
    if (allocated == 0)
        return tool_result_t::error(OBFSTR("Failed to allocate memory in target process."));

    json result;
    result["address"]    = helpers::format_address(static_cast<ea_t>(allocated));
    result["size"]       = size;
    result["protection"] = "PAGE_EXECUTE_READWRITE";
    result["process_id"] = device->get_process_id();
    return tool_result_t::ok(
        OBFSTR("Allocated ") + std::to_string(size) + OBFSTR(" bytes at ") +
        helpers::format_address(static_cast<ea_t>(allocated)), result);
}

tool_result_t driver_free_memory(const json& params)
{
    if (!device->is_connected() || device->get_process_id() == 0)
        return tool_result_t::error(OBFSTR("Not attached. Call driver_connect then driver_attach first."));

    auto addr_opt = helpers::parse_address(params["address"].get<std::string>());
    if (!addr_opt || *addr_opt == 0)
        return tool_result_t::error(OBFSTR("Invalid address."));

    std::uint64_t address = static_cast<std::uint64_t>(*addr_opt);
    bool ok = device->free_memory(address);

    json result;
    result["address"]    = helpers::format_address(*addr_opt);
    result["freed"]      = ok;
    result["process_id"] = device->get_process_id();
    if (ok)
        return tool_result_t::ok(OBFSTR("Memory freed at ") + helpers::format_address(*addr_opt), result);
    else
        return tool_result_t::error(OBFSTR("Failed to free memory at ") + helpers::format_address(*addr_opt));
}

tool_result_t driver_call_function(const json& params)
{
    if (!device->is_connected() || device->get_process_id() == 0)
        return tool_result_t::error(OBFSTR("Not attached. Call driver_connect then driver_attach first."));

    if (device->get_dtb() == 0)
    {
        device->solve_dtb();
        if (device->get_dtb() == 0)
            return tool_result_t::error(OBFSTR("Failed to solve DTB for target process."));
    }

    auto func_opt = helpers::parse_address(params["address"].get<std::string>());
    if (!func_opt || *func_opt == 0)
        return tool_result_t::error(OBFSTR("Invalid function address."));

    std::uint64_t func_addr = static_cast<std::uint64_t>(*func_opt);

    std::uint64_t args[4] = {0, 0, 0, 0};
    const char* arg_names[] = {"arg1", "arg2", "arg3", "arg4"};
    for (int i = 0; i < 4; ++i)
    {
        if (params.contains(arg_names[i]))
        {
            const auto& val = params[arg_names[i]];
            if (val.is_number())
                args[i] = val.get<std::uint64_t>();
            else if (val.is_string())
            {
                auto a = helpers::parse_address(val.get<std::string>());
                if (a) args[i] = static_cast<std::uint64_t>(*a);
            }
        }
    }

    std::uint64_t ret = device->call_function(func_addr, args[0], args[1], args[2], args[3]);

    json result;
    result["function"]   = helpers::format_address(static_cast<ea_t>(func_addr));
    result["arg1"]       = helpers::format_address(static_cast<ea_t>(args[0]));
    result["arg2"]       = helpers::format_address(static_cast<ea_t>(args[1]));
    result["arg3"]       = helpers::format_address(static_cast<ea_t>(args[2]));
    result["arg4"]       = helpers::format_address(static_cast<ea_t>(args[3]));
    result["return_value"] = helpers::format_address(static_cast<ea_t>(ret));
    result["return_decimal"] = ret;
    result["process_id"] = device->get_process_id();
    return tool_result_t::ok(
        OBFSTR("Function at ") + helpers::format_address(static_cast<ea_t>(func_addr)) +
        OBFSTR(" returned ") + helpers::format_address(static_cast<ea_t>(ret)), result);
}


void register_tools()
{
    auto& registry = ToolRegistry::instance();

    registry.register_tool({
        OBFSTR("driver_connect"), OBFSTR("driver"),
        OBFSTR("Connect to the AiDA kernel driver. Must be called before any other driver_ tools. "
               "Operates in the kernel to bypass all usermode anti-debugging and anti-RE protections."),
        {}, driver_connect, false});

    registry.register_tool({
        OBFSTR("driver_status"), OBFSTR("driver"),
        OBFSTR("Get kernel driver connection status: connected flag, attached process ID, "
               "image base address, DirectoryTableBase (DTB), and heartbeat result."),
        {}, driver_status, true});

    registry.register_tool({
        OBFSTR("driver_attach"), OBFSTR("driver"),
        OBFSTR("Attach the kernel driver to a running process by name. "
               "Finds the process, locates the image base, and solves the DTB for physical memory access. "
               "Bypasses all process isolation and memory protection."),
        {{OBFSTR("process"), OBFSTR("string"),
          OBFSTR("Target process executable name (e.g. 'target.exe'). Case-insensitive."), true}},
        driver_attach, false});

    registry.register_tool({
        OBFSTR("driver_read_memory"), OBFSTR("driver"),
        OBFSTR("Read raw bytes from the target process via kernel driver. "
               "Bypasses all memory protection, DEP, guard pages, and anti-read hooks. "
               "Optionally patches the bytes into the IDA database."),
        {{OBFSTR("address"), OBFSTR("string"), OBFSTR("Virtual address in target process"), true},
         {OBFSTR("size"), OBFSTR("number"), OBFSTR("Bytes to read (default 256, max 65536)"), false},
         {OBFSTR("patch_idb"), OBFSTR("boolean"), OBFSTR("Write read bytes to IDA database (default false)"), false}},
        driver_read_memory, false});

    registry.register_tool({
        OBFSTR("driver_write_memory"), OBFSTR("driver"),
        OBFSTR("Write bytes to the target process via kernel driver. "
               "Bypasses all memory protection including DEP, guard pages, and write protection."),
        {{OBFSTR("address"), OBFSTR("string"), OBFSTR("Virtual address in target process"), true},
         {OBFSTR("bytes"), OBFSTR("string"), OBFSTR("Hex bytes to write (e.g. '90 90 90')"), true}},
        driver_write_memory, false});

    registry.register_tool({
        OBFSTR("driver_dump_module"), OBFSTR("driver"),
        OBFSTR("Dump a complete PE module from the target process using kernel memory reads. "
               "Reads all sections page-by-page, handles packed/obfuscated sections. "
               "Optionally patches the dumped bytes into the IDA database."),
        {{OBFSTR("address"), OBFSTR("string"),
          OBFSTR("Module base address (default: attached process image base)"), false},
         {OBFSTR("size"), OBFSTR("number"), OBFSTR("Override image size in bytes (default: auto from PE header)"), false},
         {OBFSTR("output_path"), OBFSTR("string"), OBFSTR("Save dump to file path (e.g. 'C:\\\\dump.bin')"), false},
         {OBFSTR("patch_idb"), OBFSTR("boolean"), OBFSTR("Patch dumped bytes into IDA database (default true)"), false}},
        driver_dump_module, false});

    registry.register_tool({
        OBFSTR("driver_scan_pattern"), OBFSTR("driver"),
        OBFSTR("Scan target process memory for a byte pattern via kernel driver. "
               "Supports wildcard '??' bytes. Scans the attached module range by default."),
        {{OBFSTR("pattern"), OBFSTR("string"),
          OBFSTR("Hex byte pattern with '??' wildcards (e.g. '48 8B ?? ?? 89 ?? 00')"), true},
         {OBFSTR("start"), OBFSTR("string"), OBFSTR("Start address (default: image base)"), false},
         {OBFSTR("end"), OBFSTR("string"), OBFSTR("End address"), false},
         {OBFSTR("size"), OBFSTR("number"), OBFSTR("Scan size from start in bytes (default 0x200000)"), false},
         {OBFSTR("limit"), OBFSTR("number"), OBFSTR("Maximum matches to return (default 20)"), false}},
        driver_scan_pattern, false});

    registry.register_tool({
        OBFSTR("driver_read_string"), OBFSTR("driver"),
        OBFSTR("Read a null-terminated ASCII or UTF-16 string from target process memory via kernel driver."),
        {{OBFSTR("address"), OBFSTR("string"), OBFSTR("Address of the string in target process"), true},
         {OBFSTR("max_length"), OBFSTR("number"), OBFSTR("Maximum string character length (default 512)"), false},
         {OBFSTR("type"), OBFSTR("string"), OBFSTR("String encoding: auto, ascii, wide (default auto)"), false,
          {OBFSTR("auto"), OBFSTR("ascii"), OBFSTR("wide")}}},
        driver_read_string, false});

    registry.register_tool({
        OBFSTR("driver_read_pointer_chain"), OBFSTR("driver"),
        OBFSTR("Follow a chain of pointer dereferences through target process memory via kernel driver. "
               "Useful for traversing linked lists, object hierarchies, and obfuscated data structures."),
        {{OBFSTR("address"), OBFSTR("string"), OBFSTR("Starting virtual address"), true},
         {OBFSTR("offsets"), OBFSTR("array"),
          OBFSTR("Array of byte offsets to apply after each dereference (e.g. [0, 48, 24])"), false, {},
          json::object({{"type", "number"}})}},
        driver_read_pointer_chain, false});

    registry.register_tool({
        OBFSTR("driver_enumerate_modules"), OBFSTR("driver"),
        OBFSTR("Enumerate modules loaded in the target process via kernel memory reads. "
               "Reads the main PE import directory to discover all loaded DLL dependencies."),
        {}, driver_enumerate_modules, false});

    registry.register_tool({
        OBFSTR("driver_dump_to_idb"), OBFSTR("driver"),
        OBFSTR("Dump PE sections from target process into the IDA database. "
               "Creates IDA segments for each PE section, patches live bytes from process memory, "
               "and schedules auto-analysis. Use this to reconstruct packed or obfuscated binaries."),
        {{OBFSTR("address"), OBFSTR("string"),
          OBFSTR("Module base address (default: attached process image base)"), false},
         {OBFSTR("analyze"), OBFSTR("boolean"),
          OBFSTR("Run IDA auto-analysis after patching (default true)"), false}},
        driver_dump_to_idb, false});

    registry.register_tool({
        OBFSTR("driver_bypass_and_dump"), OBFSTR("driver"),
        OBFSTR("Complete kernel bypass workflow: connect driver Ã¢â€ â€™ find process Ã¢â€ â€™ solve DTB Ã¢â€ â€™ "
               "dump full image via physical memory Ã¢â€ â€™ patch IDA database. "
               "Handles VMProtect, Themida, custom packers, and any anti-debug target "
               "by reading directly from physical memory, bypassing all usermode defenses."),
        {{OBFSTR("process"), OBFSTR("string"),
          OBFSTR("Target process executable name (e.g. 'protected.exe')"), true}},
        driver_bypass_and_dump, false});

    registry.register_tool({
        OBFSTR("driver_enumerate_kernel_modules"), OBFSTR("driver"),
        OBFSTR("Enumerate ALL loaded kernel drivers and modules via NtQuerySystemInformation. "
               "Returns each driver's name, NT path, resolved disk path, kernel base address, "
               "and image size. Does NOT require the kernel driver to be connected Ã¢â‚¬â€ works "
               "purely from usermode. Use filter to search for a specific driver "
               "(e.g. filter='EasyAntiCheat' or filter='eac')."),
        {{OBFSTR("filter"), OBFSTR("string"),
          OBFSTR("Case-insensitive substring filter applied to module name and path (e.g. 'eac', 'ntfs')"), false},
         {OBFSTR("limit"), OBFSTR("number"),
          OBFSTR("Maximum number of modules to return (default 500)"), false}},
        driver_enumerate_kernel_modules, true});

    registry.register_tool({
        OBFSTR("driver_dump_kernel_module"), OBFSTR("driver"),
        OBFSTR("Dump a loaded kernel driver/module. By default dumps from LIVE KERNEL MEMORY "
               "using physical memory reads (requires driver connected). This captures runtime-decrypted, "
               "devirtualized, unpacked code as it exists in RAM. Set from_memory=false to fall back "
               "to reading the on-disk .sys file. "
               "Use this to dump ANY kernel driver: EasyAntiCheat (EAC), BattlEye, Vanguard, "
               "ntkrnlmp.exe, win32kfull.sys, etc. The dump file can be loaded in IDA Pro."),
        {{OBFSTR("module"), OBFSTR("string"),
          OBFSTR("Kernel module name or substring (e.g. 'EasyAntiCheat.sys', 'eac', 'ntoskrnl')"), true},
         {OBFSTR("output_path"), OBFSTR("string"),
          OBFSTR("Full file path to save the dump (e.g. 'C:\\\\dumps\\\\dumped_eac.sys'). "
                 "If omitted, saves to %%TEMP%%\\\\dumped_<module_name>"), false},
         {OBFSTR("from_memory"), OBFSTR("boolean"),
          OBFSTR("True (default) = dump live kernel memory via driver. "
                 "False = read on-disk file (no driver needed)."), false}},
        driver_dump_kernel_module, false});

    registry.register_tool({
        OBFSTR("driver_read_kernel_memory"), OBFSTR("driver"),
        OBFSTR("Read raw bytes from ANY kernel virtual address via physical memory translation. "
               "Requires driver connected. Solves System DTB automatically. "
               "Bypasses all kernel integrity checks, PatchGuard, and memory protections. "
               "Can read anticheat driver memory, ntoskrnl internals, SSDT, IDT, anything."),
        {{OBFSTR("address"), OBFSTR("string"),
          OBFSTR("Kernel virtual address to read (e.g. 'FFFFF80012345000')"), true},
         {OBFSTR("size"), OBFSTR("number"),
          OBFSTR("Bytes to read (default 256, max 65536)"), false},
         {OBFSTR("patch_idb"), OBFSTR("boolean"),
          OBFSTR("Patch read bytes into IDA database at the same address (default false)"), false}},
        driver_read_kernel_memory, false});

    registry.register_tool({
        OBFSTR("driver_write_kernel_memory"), OBFSTR("driver"),
        OBFSTR("Write raw bytes to ANY kernel virtual address via physical memory translation. "
               "Requires driver connected. Bypasses all memory protection, write-protection, "
               "PatchGuard, code integrity. WARNING: Writing to kernel memory can cause BSOD "
               "if done incorrectly. Use with extreme caution."),
        {{OBFSTR("address"), OBFSTR("string"),
          OBFSTR("Kernel virtual address to write (e.g. 'FFFFF80012345000')"), true},
         {OBFSTR("bytes"), OBFSTR("string"),
          OBFSTR("Hex bytes to write separated by spaces (e.g. '90 90 90 C3')"), true}},
        driver_write_kernel_memory, false});

    registry.register_tool({
        OBFSTR("driver_kernel_dump_module"), OBFSTR("driver"),
        OBFSTR("UNIVERSAL kernel module dump-and-analyze workflow. Finds module in kernel Ã¢â€ â€™ "
               "reads ALL sections from live kernel memory Ã¢â€ â€™ creates IDA segments Ã¢â€ â€™ "
               "patches runtime bytes Ã¢â€ â€™ runs FULL 6-step analysis pipeline: "
               "(1) initial auto-analysis, (2) PE export/entry point parsing with function creation, "
               "(3) linear sweep code creation across all executable sections (skips high-entropy "
               "VM bytecode sections automatically), (4) aggressive 18-pattern function prologue "
               "scanning with instruction validation, (5) CALL/JMP xref target function creation, "
               "(6) final analysis pass. Returns before/after function counts. "
               "Works on ANY kernel driver: EAC, BattlEye, Vanguard, ACE, ntkrnlmp.exe, etc. "
               "Optionally saves dump to file."),
        {{OBFSTR("module"), OBFSTR("string"),
          OBFSTR("Kernel module name or substring (e.g. 'EasyAntiCheat.sys', 'BEDaisy', 'vgk.sys')"), true},
         {OBFSTR("patch_idb"), OBFSTR("boolean"),
          OBFSTR("Create segments and patch bytes into IDA database (default true)"), false},
         {OBFSTR("analyze"), OBFSTR("boolean"),
          OBFSTR("Run full 6-step analysis pipeline after patching (default true)"), false},
         {OBFSTR("output_path"), OBFSTR("string"),
          OBFSTR("Optionally save raw dump to file (e.g. 'C:\\\\dumps\\\\eac_memory.sys')"), false}},
        driver_kernel_dump_module, false});

    registry.register_tool({
        OBFSTR("driver_allocate_memory"), OBFSTR("driver"),
        OBFSTR("Allocate RWX memory in the attached target process. "
               "Uses kernel-level ZwAllocateVirtualMemory with PAGE_EXECUTE_READWRITE. "
               "Max 16MB per allocation. Useful for injecting shellcode, writing strings "
               "for function arguments, or setting up data structures remotely. "
               "Requires driver connected and process attached."),
        {{OBFSTR("size"), OBFSTR("string"),
          OBFSTR("Number of bytes to allocate (max 16777216 = 16MB)"), true}},
        driver_allocate_memory, false});

    registry.register_tool({
        OBFSTR("driver_free_memory"), OBFSTR("driver"),
        OBFSTR("Free previously allocated memory in the attached target process. "
               "Uses kernel-level ZwFreeVirtualMemory with MEM_RELEASE. "
               "Requires driver connected and process attached."),
        {{OBFSTR("address"), OBFSTR("string"),
          OBFSTR("Address of the memory block to free (hex string like '0x...')"), true}},
        driver_free_memory, false});

    registry.register_tool({
        OBFSTR("driver_call_function"), OBFSTR("driver"),
        OBFSTR("Execute ANY function inside the attached target process via thread hijack. "
               "Suspends a target thread, redirects execution to injected shellcode that calls "
               "the specified function with up to 4 arguments, polls for completion, restores "
               "original thread context. Call stack is spoofed via JMP-RBX gadget. "
               "WARNING: Calling incorrect addresses or wrong arguments can crash the process. "
               "Common patterns: call LoadLibraryA to load DLLs, call LdrGetProcedureAddress "
               "to resolve exports, call VirtualProtect to change protections, call any "
               "game/anticheat function to observe behavior. "
               "Requires driver connected, process attached, DTB solved."),
        {{OBFSTR("address"), OBFSTR("string"),
          OBFSTR("Address of the function to call in the target process (hex)"), true},
         {OBFSTR("arg1"), OBFSTR("string"),
          OBFSTR("First argument (RCX). Hex address or integer. Default 0"), false},
         {OBFSTR("arg2"), OBFSTR("string"),
          OBFSTR("Second argument (RDX). Hex address or integer. Default 0"), false},
         {OBFSTR("arg3"), OBFSTR("string"),
          OBFSTR("Third argument (R8). Hex address or integer. Default 0"), false},
         {OBFSTR("arg4"), OBFSTR("string"),
          OBFSTR("Fourth argument (R9). Hex address or integer. Default 0"), false}},
        driver_call_function, false});
}

} // namespace driver_tools

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
    analysis_tools::register_tools();
    deobfuscation_tools::register_tools();
    driver_tools::register_tools();
    
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
             OBFSTR("import, search, debugger, segment, binary, python, navigation, analysis, meta)"),
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

