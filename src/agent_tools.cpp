#include "aida_pro.hpp"
#include "ida_utils.hpp"
#include "graphrag.hpp"
#include "analysis_db.hpp"
#include "anti_re.hpp"
#include "rlhf.hpp"
#include "subagents.hpp"
#include "emulation_engine.hpp"
#include <allins.hpp>
#include <iomanip>
#include <loader.hpp>
#include "../driver/comm.h"

using json = nlohmann::json;

namespace agent_tools
{
static tool_result_t execute_remote_subagent_tool(
    const std::string& name,
    const json& params,
    const subagents::instance_info_t& target)
{
    if (target.base_url.empty())
        return tool_result_t::error(OBFSTR("Remote sub-agent target is missing a transport URL."));

    httplib::Client client(target.base_url.c_str());
    client.set_connection_timeout(5);
    client.set_read_timeout(300);
    client.set_write_timeout(20);
    client.set_tcp_nodelay(true);
    client.set_keep_alive(true);
    client.set_decompress(true);
    client.set_compress(true);
    client.set_follow_location(true);

    json request_body = {
        {"name", name},
        {"arguments", params}
    };

    auto response = client.Post("/api/tools/call", json_dump_safe(request_body), "application/json");
    if (!response)
        return tool_result_t::error(OBFSTR("Failed to reach remote AiDA instance: ") + target.display_name);
    if (response->status < 200 || response->status >= 300)
        return tool_result_t::error(OBFSTR("Remote AiDA instance returned HTTP ") + std::to_string(response->status));

    json body;
    try
    {
        body = json::parse(response->body);
    }
    catch (const std::exception& e)
    {
        return tool_result_t::error(OBFSTR("Remote AiDA response parse error: ") + e.what());
    }

    const bool success = body.value("success", false);
    const std::string output = body.value("output", success ? std::string() : OBFSTR("Remote tool execution failed."));

    tool_result_t result = success ? tool_result_t::ok(output) : tool_result_t::error(output);
    if (body.contains("data"))
        result.data = body["data"];
    sanitize_json_utf8_inplace(result.data);
    return result;
}

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

    if (!subagents::can_execute_tool(name))
        return tool_result_t::error(OBFSTR("Tool is not available in the current sub-agent session: ") + name);

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

    if (!subagents::is_session_tool_name(name) && subagents::current_target_is_remote())
        return execute_remote_subagent_tool(name, sanitized_params, subagents::current_target_instance());

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


static void ensure_parent_dir_exists(const std::string& file_path)
{
    std::string::size_type pos = 0;
    while ((pos = file_path.find_first_of("\\/", pos + 1)) != std::string::npos)
    {
        std::string dir = file_path.substr(0, pos);
        if (dir.size() == 2 && dir[1] == ':') { pos++; continue; }
        CreateDirectoryA(dir.c_str(), nullptr);
    }
}


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

            did_work = auto_make_step(0, BADADDR);
            if (!did_work)
            {
                if (++idle_spins > MAX_IDLE_SPINS)
                    break;

                user_cancelled();
                continue;
            }
        }
        idle_spins = 0;

        if (++step_count % UI_PUMP_INTERVAL == 0)
        {

            if (step_label)
                replace_wait_box("HIDECANCEL\nAiDA: %s (%dk steps...)",
                                 step_label, step_count / 1000);
            else
                user_cancelled();
        }
    }
    return true;
}


static int responsive_plan_and_wait(ea_t ea1, ea_t ea2, bool final_pass,
                                    const char* step_label)
{

    auto_mark_range(ea1, ea2, AU_CODE);
    plan_range(ea1, ea2);
    responsive_auto_wait(ea1, ea2, step_label);


    if (final_pass)
    {
        auto_mark_range(ea1, ea2, AU_FINAL);
        responsive_auto_wait(ea1, ea2, step_label);
    }

    return 1;
}


struct pe_fix_result_t
{
    bool success = false;
    std::string error;
    int sections_fixed = 0;
    int iat_entries_restored = 0;
    int import_dlls_found = 0;
    bool entry_point_valid = false;
    bool entry_point_fixed = false;
    std::uint32_t original_ep_rva = 0;
    std::uint32_t fixed_ep_rva = 0;
    bool security_dir_cleared = false;
    bool debug_dir_cleared = false;
    bool checksum_cleared = false;
    bool file_alignment_fixed = false;
    bool is_pe64 = false;
    bool reloc_dir_cleared = false;
    bool relocs_stripped_flag_set = false;
    bool reloc_section_zeroed = false;
    bool tls_dir_cleared = false;
    bool loadconfig_dir_cleared = false;
    bool delay_import_dir_cleared = false;
    bool com_dir_cleared = false;
    bool is_dotnet = false;
    bool dotnet_com_preserved = false;
    bool dotnet_com_restored = false;
    bool imagebase_updated = false;
    std::uint64_t original_imagebase = 0;
    std::uint64_t updated_imagebase = 0;
    bool ep_prologue_scanned = false;
    std::vector<std::string> import_dll_names;
    bool extended_image = false;
    std::uint32_t original_size_of_image = 0;
    std::uint32_t updated_size_of_image = 0;
    bool vad_section_added = false;
    int vad_sections_added = 0;
};

static pe_fix_result_t fix_dumped_pe_image(
    std::vector<std::uint8_t>& image,
    std::uint64_t module_base)
{
    pe_fix_result_t result;

    if (image.size() < 0x100)
    {
        result.error = "Image too small for PE";
        return result;
    }


    if (image[0] != 'M' || image[1] != 'Z')
    {
        result.error = "Invalid MZ signature";
        return result;
    }

    std::uint32_t pe_off = *reinterpret_cast<std::uint32_t*>(&image[0x3C]);
    if (pe_off + 0x18 >= static_cast<std::uint32_t>(image.size()))
    {
        result.error = "PE header offset out of range";
        return result;
    }


    if (image[pe_off] != 'P' || image[pe_off + 1] != 'E' ||
        image[pe_off + 2] != 0   || image[pe_off + 3] != 0)
    {
        result.error = "Invalid PE signature";
        return result;
    }

    std::uint16_t num_sections  = *reinterpret_cast<std::uint16_t*>(&image[pe_off + 6]);
    std::uint16_t opt_hdr_size  = *reinterpret_cast<std::uint16_t*>(&image[pe_off + 20]);
    std::uint32_t opt_off       = pe_off + 24;

    if (opt_off + 2 >= static_cast<std::uint32_t>(image.size()))
    {
        result.error = "Optional header out of range";
        return result;
    }

    std::uint16_t opt_magic = *reinterpret_cast<std::uint16_t*>(&image[opt_off]);
    result.is_pe64 = (opt_magic == 0x020B);
    bool is_pe32   = (opt_magic == 0x010B);

    if (!result.is_pe64 && !is_pe32)
    {
        result.error = "Unknown PE optional header magic";
        return result;
    }

    std::uint32_t image_size_from_header = 0;
    if (opt_off + 60 <= static_cast<std::uint32_t>(image.size()))
        image_size_from_header = *reinterpret_cast<std::uint32_t*>(&image[opt_off + 56]);

    std::uint32_t section_table_off = pe_off + 24 + opt_hdr_size;


    std::uint32_t dd_base = result.is_pe64 ? (opt_off + 112) : (opt_off + 96);


    if (opt_off + 40 <= static_cast<std::uint32_t>(image.size()))
    {
        std::uint32_t sec_align = *reinterpret_cast<std::uint32_t*>(&image[opt_off + 32]);
        std::uint32_t fil_align = *reinterpret_cast<std::uint32_t*>(&image[opt_off + 36]);
        if (sec_align != 0 && fil_align != sec_align)
        {
            *reinterpret_cast<std::uint32_t*>(&image[opt_off + 36]) = sec_align;
            result.file_alignment_fixed = true;
        }
    }


    if (module_base != 0)
    {
        if (result.is_pe64)
        {
            if (opt_off + 32 <= static_cast<std::uint32_t>(image.size()))
            {
                result.original_imagebase = *reinterpret_cast<std::uint64_t*>(&image[opt_off + 24]);
                *reinterpret_cast<std::uint64_t*>(&image[opt_off + 24]) = module_base;
                result.updated_imagebase = module_base;
                result.imagebase_updated = (result.original_imagebase != module_base);
            }
        }
        else
        {
            if (opt_off + 32 <= static_cast<std::uint32_t>(image.size()))
            {
                result.original_imagebase = *reinterpret_cast<std::uint32_t*>(&image[opt_off + 28]);
                *reinterpret_cast<std::uint32_t*>(&image[opt_off + 28]) =
                    static_cast<std::uint32_t>(module_base);
                result.updated_imagebase = module_base;
                result.imagebase_updated = (result.original_imagebase != module_base);
            }
        }
    }


    for (int i = 0; i < num_sections && i < 96; i++)
    {
        std::uint32_t sec_off = section_table_off + i * 40;
        if (sec_off + 40 > static_cast<std::uint32_t>(image.size())) break;

        std::uint32_t virt_size = *reinterpret_cast<std::uint32_t*>(&image[sec_off + 8]);
        std::uint32_t virt_addr = *reinterpret_cast<std::uint32_t*>(&image[sec_off + 12]);
        std::uint32_t raw_size  = *reinterpret_cast<std::uint32_t*>(&image[sec_off + 16]);

        if (virt_addr == 0 || virt_size == 0) continue;


        *reinterpret_cast<std::uint32_t*>(&image[sec_off + 20]) = virt_addr;


        std::uint32_t new_raw = (virt_size > raw_size) ? virt_size : raw_size;
        if (virt_addr + new_raw > static_cast<std::uint32_t>(image.size()))
            new_raw = static_cast<std::uint32_t>(image.size()) - virt_addr;
        *reinterpret_cast<std::uint32_t*>(&image[sec_off + 16]) = new_raw;


        *reinterpret_cast<std::uint32_t*>(&image[sec_off + 24]) = 0;
        *reinterpret_cast<std::uint16_t*>(&image[sec_off + 32]) = 0;
        *reinterpret_cast<std::uint16_t*>(&image[sec_off + 34]) = 0;

        result.sections_fixed++;
    }


    if (opt_off + 68 <= static_cast<std::uint32_t>(image.size()))
    {
        *reinterpret_cast<std::uint32_t*>(&image[opt_off + 64]) = 0;
        result.checksum_cleared = true;
    }


    {
        std::uint32_t sec_dir_off = dd_base + 4 * 8;
        if (sec_dir_off + 8 <= static_cast<std::uint32_t>(image.size()))
        {
            std::uint32_t sec_rva = *reinterpret_cast<std::uint32_t*>(&image[sec_dir_off]);
            if (sec_rva != 0)
            {
                *reinterpret_cast<std::uint32_t*>(&image[sec_dir_off])     = 0;
                *reinterpret_cast<std::uint32_t*>(&image[sec_dir_off + 4]) = 0;
                result.security_dir_cleared = true;
            }
        }
    }


    {
        std::uint32_t dbg_dir_off = dd_base + 6 * 8;
        if (dbg_dir_off + 8 <= static_cast<std::uint32_t>(image.size()))
        {
            std::uint32_t dbg_rva = *reinterpret_cast<std::uint32_t*>(&image[dbg_dir_off]);
            if (dbg_rva != 0)
            {
                *reinterpret_cast<std::uint32_t*>(&image[dbg_dir_off])     = 0;
                *reinterpret_cast<std::uint32_t*>(&image[dbg_dir_off + 4]) = 0;
                result.debug_dir_cleared = true;
            }
        }
    }


    {
        std::uint32_t reloc_dir_off = dd_base + 5 * 8;
        if (reloc_dir_off + 8 <= static_cast<std::uint32_t>(image.size()))
        {
            std::uint32_t reloc_rva = *reinterpret_cast<std::uint32_t*>(&image[reloc_dir_off]);
            if (reloc_rva != 0)
            {
                *reinterpret_cast<std::uint32_t*>(&image[reloc_dir_off])     = 0;
                *reinterpret_cast<std::uint32_t*>(&image[reloc_dir_off + 4]) = 0;
                result.reloc_dir_cleared = true;
            }
        }
    }


    {
        std::uint32_t tls_dir_off = dd_base + 9 * 8;
        if (tls_dir_off + 8 <= static_cast<std::uint32_t>(image.size()))
        {
            std::uint32_t tls_rva = *reinterpret_cast<std::uint32_t*>(&image[tls_dir_off]);
            if (tls_rva != 0)
            {
                *reinterpret_cast<std::uint32_t*>(&image[tls_dir_off])     = 0;
                *reinterpret_cast<std::uint32_t*>(&image[tls_dir_off + 4]) = 0;
                result.tls_dir_cleared = true;
            }
        }
    }


    {
        std::uint32_t lc_dir_off = dd_base + 10 * 8;
        if (lc_dir_off + 8 <= static_cast<std::uint32_t>(image.size()))
        {
            std::uint32_t lc_rva = *reinterpret_cast<std::uint32_t*>(&image[lc_dir_off]);
            if (lc_rva != 0)
            {
                *reinterpret_cast<std::uint32_t*>(&image[lc_dir_off])     = 0;
                *reinterpret_cast<std::uint32_t*>(&image[lc_dir_off + 4]) = 0;
                result.loadconfig_dir_cleared = true;
            }
        }
    }


    {
        std::uint32_t di_dir_off = dd_base + 13 * 8;
        if (di_dir_off + 8 <= static_cast<std::uint32_t>(image.size()))
        {
            std::uint32_t di_rva = *reinterpret_cast<std::uint32_t*>(&image[di_dir_off]);
            if (di_rva != 0)
            {
                *reinterpret_cast<std::uint32_t*>(&image[di_dir_off])     = 0;
                *reinterpret_cast<std::uint32_t*>(&image[di_dir_off + 4]) = 0;
                result.delay_import_dir_cleared = true;
            }
        }
    }


    {
        std::uint32_t com_dir_off = dd_base + 14 * 8;


        bool dotnet_detected = false;
        std::uint32_t bsjb_rva = 0;
        {
            constexpr std::size_t SCAN_LIMIT = 0x800000;
            std::size_t scan_end = std::min(image.size(), SCAN_LIMIT);
            for (std::size_t i = 0x200; i + 4 <= scan_end; i++)
            {
                if (image[i] == 0x42 && image[i + 1] == 0x53 &&
                    image[i + 2] == 0x4A && image[i + 3] == 0x42)
                {
                    dotnet_detected = true;
                    bsjb_rva = static_cast<std::uint32_t>(i);
                    break;
                }
            }
        }

        result.is_dotnet = dotnet_detected;

        if (dotnet_detected)
        {
            if (com_dir_off + 8 <= static_cast<std::uint32_t>(image.size()))
            {
                std::uint32_t com_rva  = *reinterpret_cast<std::uint32_t*>(&image[com_dir_off]);
                std::uint32_t com_size = *reinterpret_cast<std::uint32_t*>(&image[com_dir_off + 4]);

                if (com_rva != 0 && com_rva < static_cast<std::uint32_t>(image.size()) && com_size >= 72)
                {
                    result.dotnet_com_preserved = true;
                }
                else if (bsjb_rva > 0)
                {

                    std::uint32_t metadata_rva = 0;
                    std::uint32_t metadata_size = 0;


                    if (bsjb_rva >= 16)
                    {
                        for (std::uint32_t scan = bsjb_rva - 16; scan > 0x200 && scan > bsjb_rva - 0x2000; scan--)
                        {
                            if (scan + 72 > static_cast<std::uint32_t>(image.size())) continue;

                            std::uint32_t cb = *reinterpret_cast<std::uint32_t*>(&image[scan]);
                            if (cb < 72 || cb > 0x1000) continue;

                            std::uint16_t major = *reinterpret_cast<std::uint16_t*>(&image[scan + 4]);
                            std::uint16_t minor = *reinterpret_cast<std::uint16_t*>(&image[scan + 6]);
                            if (major < 1 || major > 5) continue;
                            if (minor > 10) continue;

                            std::uint32_t meta_rva  = *reinterpret_cast<std::uint32_t*>(&image[scan + 8]);
                            std::uint32_t meta_size = *reinterpret_cast<std::uint32_t*>(&image[scan + 12]);

                            if (meta_rva > 0 && meta_rva < static_cast<std::uint32_t>(image.size()) &&
                                meta_size > 0 && meta_rva + meta_size <= static_cast<std::uint32_t>(image.size()))
                            {

                                if (meta_rva <= bsjb_rva && bsjb_rva < meta_rva + meta_size)
                                {
                                    *reinterpret_cast<std::uint32_t*>(&image[com_dir_off])     = scan;
                                    *reinterpret_cast<std::uint32_t*>(&image[com_dir_off + 4]) = cb;
                                    result.dotnet_com_restored = true;
                                    metadata_rva = meta_rva;
                                    metadata_size = meta_size;
                                    break;
                                }
                            }
                        }
                    }

                    if (!result.dotnet_com_restored)
                    {
                        result.dotnet_com_preserved = true;
                    }
                }
            }
        }
        else
        {
            if (com_dir_off + 8 <= static_cast<std::uint32_t>(image.size()))
            {
                std::uint32_t com_rva = *reinterpret_cast<std::uint32_t*>(&image[com_dir_off]);
                if (com_rva != 0)
                {
                    *reinterpret_cast<std::uint32_t*>(&image[com_dir_off])     = 0;
                    *reinterpret_cast<std::uint32_t*>(&image[com_dir_off + 4]) = 0;
                    result.com_dir_cleared = true;
                }
            }
        }
    }


    {
        std::uint32_t chars_off = pe_off + 18;
        if (chars_off + 2 <= static_cast<std::uint32_t>(image.size()))
        {
            std::uint16_t characteristics = *reinterpret_cast<std::uint16_t*>(&image[chars_off]);
            if (!(characteristics & 0x0001))
            {
                characteristics |= 0x0001;
                *reinterpret_cast<std::uint16_t*>(&image[chars_off]) = characteristics;
                result.relocs_stripped_flag_set = true;
            }
        }
    }


    for (int i = 0; i < num_sections && i < 96; i++)
    {
        std::uint32_t sec_off = section_table_off + i * 40;
        if (sec_off + 40 > static_cast<std::uint32_t>(image.size())) break;

        char sec_name[9] = {};
        std::memcpy(sec_name, &image[sec_off], 8);

        if (std::strcmp(sec_name, ".reloc") == 0)
        {
            std::uint32_t virt_addr = *reinterpret_cast<std::uint32_t*>(&image[sec_off + 12]);
            std::uint32_t raw_size  = *reinterpret_cast<std::uint32_t*>(&image[sec_off + 16]);

            if (virt_addr > 0 && virt_addr < static_cast<std::uint32_t>(image.size()))
            {
                std::uint32_t zero_end = virt_addr + raw_size;
                if (zero_end > static_cast<std::uint32_t>(image.size()))
                    zero_end = static_cast<std::uint32_t>(image.size());
                std::memset(&image[virt_addr], 0, zero_end - virt_addr);
                result.reloc_section_zeroed = true;
            }
            break;
        }
    }


    {
        std::uint32_t ep_rva = *reinterpret_cast<std::uint32_t*>(&image[opt_off + 16]);
        result.original_ep_rva = ep_rva;
        result.fixed_ep_rva    = ep_rva;

        bool ep_ok = false;


        if (ep_rva > 0 && ep_rva < static_cast<std::uint32_t>(image.size()))
        {
            for (int i = 0; i < num_sections && i < 96; i++)
            {
                std::uint32_t sec_off = section_table_off + i * 40;
                if (sec_off + 40 > static_cast<std::uint32_t>(image.size())) break;

                std::uint32_t va  = *reinterpret_cast<std::uint32_t*>(&image[sec_off + 12]);
                std::uint32_t vs  = *reinterpret_cast<std::uint32_t*>(&image[sec_off + 8]);
                std::uint32_t ch  = *reinterpret_cast<std::uint32_t*>(&image[sec_off + 36]);

                if (ep_rva >= va && ep_rva < va + vs && (ch & 0x20000000))
                {

                    if (image[ep_rva] != 0x00 && image[ep_rva] != 0xCC)
                        ep_ok = true;
                    break;
                }
            }
        }


        if (!ep_ok && (ep_rva == 0 || ep_rva >= static_cast<std::uint32_t>(image.size())))
        {
            if (dd_base + 8 <= static_cast<std::uint32_t>(image.size()))
            {
                std::uint32_t export_rva  = *reinterpret_cast<std::uint32_t*>(&image[dd_base]);
                std::uint32_t export_size = *reinterpret_cast<std::uint32_t*>(&image[dd_base + 4]);
                (void)export_size;

                if (export_rva != 0 && export_rva + 40 <= static_cast<std::uint32_t>(image.size()))
                {
                    std::uint32_t num_funcs   = *reinterpret_cast<std::uint32_t*>(&image[export_rva + 20]);
                    std::uint32_t num_names   = *reinterpret_cast<std::uint32_t*>(&image[export_rva + 24]);
                    std::uint32_t funcs_rva   = *reinterpret_cast<std::uint32_t*>(&image[export_rva + 28]);
                    std::uint32_t names_rva   = *reinterpret_cast<std::uint32_t*>(&image[export_rva + 32]);
                    std::uint32_t ords_rva    = *reinterpret_cast<std::uint32_t*>(&image[export_rva + 36]);
                    (void)num_funcs;

                    static const char* const entry_names[] = {
                        "DriverEntry", "GsDriverEntry", "DllMain",
                        "DllEntryPoint", "main", "wmain", "WinMain",
                        "wWinMain", "_DllMainCRTStartup", "mainCRTStartup"
                    };

                    for (std::uint32_t j = 0; j < num_names && j < 10000; j++)
                    {
                        if (names_rva + (j + 1) * 4 > static_cast<std::uint32_t>(image.size())) break;
                        std::uint32_t nrva = *reinterpret_cast<std::uint32_t*>(
                            &image[names_rva + j * 4]);
                        if (nrva == 0 || nrva >= static_cast<std::uint32_t>(image.size())) continue;

                        const char* exp_name = reinterpret_cast<const char*>(&image[nrva]);
                        bool matched = false;
                        for (auto en : entry_names)
                        {
                            if (std::strcmp(exp_name, en) == 0) { matched = true; break; }
                        }
                        if (!matched) continue;

                        if (ords_rva + (j + 1) * 2 > static_cast<std::uint32_t>(image.size())) break;
                        std::uint16_t ordinal = *reinterpret_cast<std::uint16_t*>(
                            &image[ords_rva + j * 2]);
                        if (funcs_rva + (ordinal + 1) * 4 > static_cast<std::uint32_t>(image.size())) break;
                        std::uint32_t frva = *reinterpret_cast<std::uint32_t*>(
                            &image[funcs_rva + ordinal * 4]);

                        if (frva > 0 && frva < static_cast<std::uint32_t>(image.size()))
                        {
                            *reinterpret_cast<std::uint32_t*>(&image[opt_off + 16]) = frva;
                            result.fixed_ep_rva      = frva;
                            result.entry_point_fixed = true;
                            ep_ok = true;
                        }
                        break;
                    }
                }
            }
        }


        if (!ep_ok && ep_rva > 0 && ep_rva < static_cast<std::uint32_t>(image.size()) &&
            (image[ep_rva] == 0x00 || image[ep_rva] == 0xCC))
        {


            static const struct { const std::uint8_t bytes[8]; int len; } prologues[] = {
                {{0x48, 0x89, 0x5C, 0x24},          4},
                {{0x48, 0x83, 0xEC},                 3},
                {{0x48, 0x8B, 0xC4},                 3},
                {{0x4C, 0x8B, 0xDC},                 3},
                {{0x48, 0x89, 0x4C, 0x24},           4},
                {{0x40, 0x55},                       2},
                {{0x40, 0x53},                       2},
                {{0x55, 0x48, 0x8B, 0xEC},           4},
                {{0x48, 0x81, 0xEC},                 3},
                {{0x48, 0x8D, 0x6C, 0x24},           4},
                {{0xE9},                             1},
                {{0x55, 0x8B, 0xEC},                 3},
            };

            bool found_prologue = false;
            for (int i = 0; i < num_sections && i < 96 && !found_prologue; i++)
            {
                std::uint32_t sec_off = section_table_off + i * 40;
                if (sec_off + 40 > static_cast<std::uint32_t>(image.size())) break;

                std::uint32_t va = *reinterpret_cast<std::uint32_t*>(&image[sec_off + 12]);
                std::uint32_t vs = *reinterpret_cast<std::uint32_t*>(&image[sec_off + 8]);
                std::uint32_t ch = *reinterpret_cast<std::uint32_t*>(&image[sec_off + 36]);

                if (!(ch & 0x20000000) || va == 0 || vs == 0) continue;

                std::uint32_t scan_end = va + vs;
                if (scan_end > static_cast<std::uint32_t>(image.size()))
                    scan_end = static_cast<std::uint32_t>(image.size());

                if (scan_end - va > 0x10000) scan_end = va + 0x10000;

                for (std::uint32_t off = va; off + 8 < scan_end; off++)
                {

                    if (image[off] == 0x00 || image[off] == 0xCC) continue;

                    for (const auto& p : prologues)
                    {
                        if (off + p.len > scan_end) continue;
                        if (std::memcmp(&image[off], p.bytes, p.len) == 0)
                        {
                            *reinterpret_cast<std::uint32_t*>(&image[opt_off + 16]) = off;
                            result.fixed_ep_rva      = off;
                            result.entry_point_fixed = true;
                            result.ep_prologue_scanned = true;
                            ep_ok = true;
                            found_prologue = true;
                            break;
                        }
                    }
                    if (found_prologue) break;
                }
            }


            if (!found_prologue)
            {
                for (int i = 0; i < num_sections && i < 96; i++)
                {
                    std::uint32_t sec_off = section_table_off + i * 40;
                    if (sec_off + 40 > static_cast<std::uint32_t>(image.size())) break;

                    std::uint32_t va = *reinterpret_cast<std::uint32_t*>(&image[sec_off + 12]);
                    std::uint32_t ch = *reinterpret_cast<std::uint32_t*>(&image[sec_off + 36]);

                    if ((ch & 0x20000000) && va > 0 && va < static_cast<std::uint32_t>(image.size()) &&
                        image[va] != 0x00)
                    {
                        *reinterpret_cast<std::uint32_t*>(&image[opt_off + 16]) = va;
                        result.fixed_ep_rva      = va;
                        result.entry_point_fixed = true;
                        ep_ok = true;
                        break;
                    }
                }
            }
        }

        result.entry_point_valid = ep_ok;
    }


    {
        std::uint32_t import_dir_off = dd_base + 1 * 8;
        if (import_dir_off + 8 <= static_cast<std::uint32_t>(image.size()))
        {
            std::uint32_t import_rva  = *reinterpret_cast<std::uint32_t*>(&image[import_dir_off]);
            std::uint32_t import_size = *reinterpret_cast<std::uint32_t*>(&image[import_dir_off + 4]);
            (void)import_size;

            if (import_rva != 0 && import_rva < static_cast<std::uint32_t>(image.size()))
            {
                std::uint32_t thunk_size = result.is_pe64 ? 8u : 4u;
                std::uint64_t ordinal_flag = result.is_pe64
                    ? 0x8000000000000000ULL : 0x80000000ULL;

                for (std::uint32_t imp_idx = 0; imp_idx < 0x2000; imp_idx++)
                {
                    std::uint32_t desc_off = import_rva + imp_idx * 20;
                    if (desc_off + 20 > static_cast<std::uint32_t>(image.size())) break;

                    std::uint32_t int_rva  = *reinterpret_cast<std::uint32_t*>(&image[desc_off]);
                    std::uint32_t name_rva = *reinterpret_cast<std::uint32_t*>(&image[desc_off + 12]);
                    std::uint32_t iat_rva  = *reinterpret_cast<std::uint32_t*>(&image[desc_off + 16]);


                    if (int_rva == 0 && name_rva == 0 && iat_rva == 0) break;
                    if (iat_rva == 0) continue;


                    if (name_rva > 0 && name_rva < static_cast<std::uint32_t>(image.size()))
                    {
                        std::string dll_name;
                        for (std::uint32_t k = name_rva;
                             k < static_cast<std::uint32_t>(image.size()) && image[k] != 0;
                             k++)
                        {
                            if (dll_name.size() >= 260) break;
                            dll_name += static_cast<char>(image[k]);
                        }
                        if (!dll_name.empty())
                            result.import_dll_names.push_back(dll_name);
                    }
                    result.import_dlls_found++;


                    *reinterpret_cast<std::uint32_t*>(&image[desc_off + 4]) = 0;

                    *reinterpret_cast<std::uint32_t*>(&image[desc_off + 8]) = static_cast<std::uint32_t>(-1);


                    if (int_rva == 0 || int_rva == iat_rva) continue;
                    if (int_rva >= static_cast<std::uint32_t>(image.size()) ||
                        iat_rva >= static_cast<std::uint32_t>(image.size())) continue;


                    bool int_valid = true;
                    int  thunk_count = 0;

                    for (int t = 0; t < 0x10000; t++)
                    {
                        std::uint32_t ie = int_rva + t * thunk_size;
                        if (ie + thunk_size > static_cast<std::uint32_t>(image.size()))
                        { int_valid = false; break; }

                        std::uint64_t tv = 0;
                        if (result.is_pe64)
                            tv = *reinterpret_cast<std::uint64_t*>(&image[ie]);
                        else
                            tv = *reinterpret_cast<std::uint32_t*>(&image[ie]);

                        if (tv == 0) break;

                        if (!(tv & ordinal_flag))
                        {

                            std::uint32_t nva = static_cast<std::uint32_t>(tv & 0x7FFFFFFF);
                            if (nva == 0 || nva + 3 >= static_cast<std::uint32_t>(image.size()))
                            { int_valid = false; break; }


                            bool printable = false;
                            for (int k = 2; k < 8 && nva + k < static_cast<std::uint32_t>(image.size()); k++)
                            {
                                char c = static_cast<char>(image[nva + k]);
                                if (c == 0) { printable = (k > 2); break; }
                                if (c >= 0x21 && c <= 0x7E) { printable = true; break; }
                            }
                            if (!printable) { int_valid = false; break; }
                        }
                        thunk_count++;
                    }


                    if (int_valid && thunk_count > 0)
                    {
                        for (int t = 0; t <= thunk_count; t++)
                        {
                            std::uint32_t src = int_rva + t * thunk_size;
                            std::uint32_t dst = iat_rva + t * thunk_size;
                            if (src + thunk_size > static_cast<std::uint32_t>(image.size()) ||
                                dst + thunk_size > static_cast<std::uint32_t>(image.size()))
                                break;
                            std::memcpy(&image[dst], &image[src], thunk_size);
                        }
                        result.iat_entries_restored += thunk_count;
                    }
                }
            }
        }
    }


    {
        std::uint32_t bound_off = dd_base + 11 * 8;
        if (bound_off + 8 <= static_cast<std::uint32_t>(image.size()))
        {
            std::uint32_t brva = *reinterpret_cast<std::uint32_t*>(&image[bound_off]);
            if (brva != 0)
            {
                *reinterpret_cast<std::uint32_t*>(&image[bound_off])     = 0;
                *reinterpret_cast<std::uint32_t*>(&image[bound_off + 4]) = 0;
            }
        }
    }


    result.original_size_of_image = image_size_from_header;

    std::uint32_t sec_align_val = 0x1000;
    if (opt_off + 36 <= static_cast<std::uint32_t>(image.size()))
    {
        std::uint32_t sa = *reinterpret_cast<std::uint32_t*>(&image[opt_off + 32]);
        if (sa >= 0x200 && sa <= 0x100000)
            sec_align_val = sa;
    }

    if (static_cast<std::uint32_t>(image.size()) > image_size_from_header)
    {
        result.extended_image = true;

        std::uint32_t last_sec_end = 0;
        for (int i = 0; i < num_sections && i < 96; i++)
        {
            std::uint32_t sec_off = section_table_off + i * 40;
            if (sec_off + 40 > static_cast<std::uint32_t>(image.size())) break;
            std::uint32_t va = *reinterpret_cast<std::uint32_t*>(&image[sec_off + 12]);
            std::uint32_t vs = *reinterpret_cast<std::uint32_t*>(&image[sec_off + 8]);
            std::uint32_t raw = *reinterpret_cast<std::uint32_t*>(&image[sec_off + 16]);
            std::uint32_t end = va + ((vs > raw) ? vs : raw);
            if (end > last_sec_end)
                last_sec_end = end;
        }

        std::uint32_t aligned_last = (last_sec_end + sec_align_val - 1) & ~(sec_align_val - 1);
        if (aligned_last < image_size_from_header)
            aligned_last = image_size_from_header;

        if (static_cast<std::uint32_t>(image.size()) > aligned_last)
        {
            std::uint16_t cur_num_sections = *reinterpret_cast<std::uint16_t*>(&image[pe_off + 6]);
            std::uint32_t cur_sec_table_off = pe_off + 24 + opt_hdr_size;

            std::uint32_t remaining_start = aligned_last;
            std::uint32_t remaining_total = static_cast<std::uint32_t>(image.size()) - remaining_start;

            constexpr std::uint32_t MAX_VAD_SECTION_SIZE = 0x40000000u;
            int vad_idx = 0;

            while (remaining_total > 0 && vad_idx < 16)
            {
                std::uint32_t chunk_size = remaining_total;
                if (chunk_size > MAX_VAD_SECTION_SIZE)
                    chunk_size = MAX_VAD_SECTION_SIZE;

                std::uint32_t chunk_aligned = (chunk_size + sec_align_val - 1) & ~(sec_align_val - 1);

                std::uint32_t new_sec_header_off = cur_sec_table_off + cur_num_sections * 40;
                if (new_sec_header_off + 40 > remaining_start &&
                    new_sec_header_off + 40 > static_cast<std::uint32_t>(image.size()))
                    break;

                if (new_sec_header_off + 40 > remaining_start)
                    break;

                char sec_name_buf[9] = {};
                if (vad_idx == 0)
                    std::memcpy(sec_name_buf, ".vad\0\0\0\0", 8);
                else
                    qsnprintf(sec_name_buf, sizeof(sec_name_buf), ".vad%d", vad_idx);

                std::memset(&image[new_sec_header_off], 0, 40);
                std::memcpy(&image[new_sec_header_off], sec_name_buf, 8);
                *reinterpret_cast<std::uint32_t*>(&image[new_sec_header_off + 8])  = chunk_aligned;
                *reinterpret_cast<std::uint32_t*>(&image[new_sec_header_off + 12]) = remaining_start;
                *reinterpret_cast<std::uint32_t*>(&image[new_sec_header_off + 16]) = chunk_aligned;
                *reinterpret_cast<std::uint32_t*>(&image[new_sec_header_off + 20]) = remaining_start;
                *reinterpret_cast<std::uint32_t*>(&image[new_sec_header_off + 36]) = 0xE0000060u;

                cur_num_sections++;
                result.vad_sections_added++;
                result.sections_fixed++;

                remaining_start += chunk_aligned;
                remaining_total = (remaining_start < static_cast<std::uint32_t>(image.size()))
                    ? static_cast<std::uint32_t>(image.size()) - remaining_start
                    : 0;
                vad_idx++;
            }

            *reinterpret_cast<std::uint16_t*>(&image[pe_off + 6]) = cur_num_sections;
            result.vad_section_added = (result.vad_sections_added > 0);
        }

        std::uint32_t new_soi = (static_cast<std::uint32_t>(image.size()) + sec_align_val - 1)
                                & ~(sec_align_val - 1);
        *reinterpret_cast<std::uint32_t*>(&image[opt_off + 56]) = new_soi;
        result.updated_size_of_image = new_soi;
    }
    else
    {
        result.updated_size_of_image = image_size_from_header;
    }


    result.success = true;
    return result;
}


static nlohmann::json pe_fix_to_json(const pe_fix_result_t& fix)
{
    auto fmt_rva = [](std::uint32_t v) -> std::string {
        std::ostringstream ss;
        ss << "0x" << std::hex << std::uppercase << v;
        return ss.str();
    };

    auto fmt_addr = [](std::uint64_t v) -> std::string {
        std::ostringstream ss;
        ss << "0x" << std::hex << std::uppercase << v;
        return ss.str();
    };

    nlohmann::json j;
    j["pe_fixed"]              = fix.success;
    j["sections_fixed"]        = fix.sections_fixed;
    j["iat_entries_restored"]  = fix.iat_entries_restored;
    j["import_dlls_found"]     = fix.import_dlls_found;
    j["entry_point_valid"]     = fix.entry_point_valid;
    j["entry_point_fixed"]     = fix.entry_point_fixed;
    if (fix.ep_prologue_scanned)
        j["ep_prologue_scanned"] = true;
    j["original_ep_rva"]       = fmt_rva(fix.original_ep_rva);
    j["fixed_ep_rva"]          = fmt_rva(fix.fixed_ep_rva);
    j["security_dir_cleared"]  = fix.security_dir_cleared;
    j["debug_dir_cleared"]     = fix.debug_dir_cleared;
    j["checksum_cleared"]      = fix.checksum_cleared;
    j["file_alignment_fixed"]  = fix.file_alignment_fixed;
    j["reloc_dir_cleared"]     = fix.reloc_dir_cleared;
    j["relocs_stripped"]       = fix.relocs_stripped_flag_set;
    if (fix.reloc_section_zeroed)
        j["reloc_section_zeroed"] = true;
    if (fix.tls_dir_cleared)
        j["tls_dir_cleared"]     = true;
    if (fix.loadconfig_dir_cleared)
        j["loadconfig_dir_cleared"] = true;
    if (fix.delay_import_dir_cleared)
        j["delay_import_dir_cleared"] = true;
    if (fix.com_dir_cleared)
        j["com_dir_cleared"]     = true;
    if (fix.is_dotnet)
    {
        j["is_dotnet"]           = true;
        if (fix.dotnet_com_preserved)
            j["dotnet_com_preserved"] = true;
        if (fix.dotnet_com_restored)
            j["dotnet_com_restored"]  = true;
    }
    if (fix.imagebase_updated)
    {
        j["imagebase_updated"]       = true;
        j["original_imagebase"]      = fmt_addr(fix.original_imagebase);
        j["updated_imagebase"]       = fmt_addr(fix.updated_imagebase);
    }
    if (!fix.import_dll_names.empty())
        j["import_dlls"]       = fix.import_dll_names;
    if (fix.extended_image)
    {
        j["extended_image"]         = true;
        j["original_size_of_image"] = fmt_rva(fix.original_size_of_image);
        j["updated_size_of_image"]  = fmt_rva(fix.updated_size_of_image);
        if (fix.vad_section_added)
            j["vad_sections_added"]  = fix.vad_sections_added;
    }
    if (!fix.error.empty())
        j["pe_fix_error"]      = fix.error;
    return j;
}


struct module_range_t
{
    std::string name;
    std::uint64_t base;
    std::uint64_t size;
};

struct iat_rebuild_result_t
{
    bool success = false;
    int imports_resolved = 0;
    int imports_failed = 0;
    int descriptors_rebuilt = 0;
    bool section_added = false;
    std::vector<std::string> resolved_dlls;
    std::string error;
};


static std::vector<module_range_t> enumerate_ldr_modules_for_iat(
    voyager::device_t* dev)
{
    std::vector<module_range_t> modules;

    if (!dev || !dev->is_connected() || dev->get_process_id() == 0)
        return modules;

    voyager::device_t::peb_info peb{};
    if (!dev->read_peb(peb) || peb.ldr_address == 0)
        return modules;


    std::uint64_t list_head = peb.ldr_address + 0x10;
    std::uint64_t first_entry = dev->read<std::uint64_t>(list_head);

    if (first_entry == 0 || first_entry == list_head)
        return modules;

    std::uint64_t current = first_entry;
    int max_iter = 1024;

    while (current != list_head && current != 0 && max_iter-- > 0)
    {


        module_range_t m;
        m.base = dev->read<std::uint64_t>(current + 0x30);
        m.size = static_cast<std::uint64_t>(dev->read<std::uint32_t>(current + 0x40));


        std::uint16_t name_len = dev->read<std::uint16_t>(current + 0x58);
        std::uint64_t name_ptr = dev->read<std::uint64_t>(current + 0x58 + 8);

        if (name_len > 0 && name_len < 520 && name_ptr != 0)
        {
            std::vector<std::uint8_t> raw(name_len, 0);
            dev->read_raw(name_ptr, raw.data(), name_len);
            m.name.reserve(name_len / 2);
            for (std::size_t i = 0; i + 1 < name_len; i += 2)
            {
                std::uint16_t wc = raw[i] | (static_cast<std::uint16_t>(raw[i + 1]) << 8);
                if (wc == 0) break;
                m.name += (wc < 128 && wc >= 32) ? static_cast<char>(wc) : '?';
            }
        }

        if (m.base != 0 && m.size != 0 && !m.name.empty())
            modules.push_back(m);

        std::uint64_t next = dev->read<std::uint64_t>(current);
        if (next == current) break;
        current = next;
    }

    return modules;
}


static std::vector<module_range_t> enumerate_kernel_modules_for_iat()
{
    std::vector<module_range_t> modules;

    struct km_entry_t
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

    struct km_info_t
    {
        ULONG       NumberOfModules;
        km_entry_t  Modules[1];
    };

    typedef LONG(NTAPI* NtQSI_fn)(ULONG, PVOID, ULONG, PULONG);

    HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
    if (!ntdll) return modules;

    auto pNtQSI = reinterpret_cast<NtQSI_fn>(
        GetProcAddress(ntdll, "NtQuerySystemInformation"));
    if (!pNtQSI) return modules;

    constexpr ULONG SysModInfo = 11;
    ULONG needed = 0;
    pNtQSI(SysModInfo, nullptr, 0, &needed);
    if (needed == 0) needed = 256 * 1024;
    needed += 16384;

    std::vector<std::uint8_t> buf(needed, 0);
    LONG status = pNtQSI(SysModInfo, buf.data(),
        static_cast<ULONG>(buf.size()), &needed);
    if (status < 0) return modules;

    auto* info = reinterpret_cast<km_info_t*>(buf.data());
    modules.reserve(info->NumberOfModules);
    for (ULONG i = 0; i < info->NumberOfModules; i++)
    {
        const auto& e = info->Modules[i];
        module_range_t mr;
        mr.name = std::string(reinterpret_cast<const char*>(
            e.FullPathName + e.OffsetToFileName));
        mr.base = reinterpret_cast<std::uintptr_t>(e.ImageBase);
        mr.size = e.ImageSize;
        modules.push_back(mr);
    }

    return modules;
}


static bool resolve_import_address(
    voyager::device_t* dev,
    const std::vector<module_range_t>& modules,
    std::uint64_t resolved_addr,
    bool is_kernel,
    std::string& out_dll,
    std::string& out_func,
    std::uint16_t& out_hint,
    bool& out_by_ordinal,
    std::uint16_t& out_ordinal)
{
    out_dll.clear();
    out_func.clear();
    out_hint = 0;
    out_ordinal = 0;
    out_by_ordinal = false;


    const module_range_t* target = nullptr;
    for (const auto& m : modules)
    {
        if (resolved_addr >= m.base && resolved_addr < m.base + m.size)
        {
            target = &m;
            break;
        }
    }
    if (!target) return false;

    out_dll = target->name;


    std::uint8_t pe_hdr[0x1000];
    std::size_t hdr_read = is_kernel
        ? dev->read_kernel_raw(target->base, pe_hdr, sizeof(pe_hdr))
        : dev->read_raw(target->base, pe_hdr, sizeof(pe_hdr));

    if (hdr_read < 0x100 || pe_hdr[0] != 'M' || pe_hdr[1] != 'Z')
        return false;

    std::uint32_t pe_off = *reinterpret_cast<std::uint32_t*>(&pe_hdr[0x3C]);
    if (pe_off + 0x18 >= hdr_read ||
        pe_hdr[pe_off] != 'P' || pe_hdr[pe_off + 1] != 'E')
        return false;

    std::uint16_t opt_magic = *reinterpret_cast<std::uint16_t*>(&pe_hdr[pe_off + 0x18]);
    bool pe64 = (opt_magic == 0x020B);

    std::uint32_t dd_off = pe_off + 0x18 + (pe64 ? 112 : 96);
    if (dd_off + 8 > hdr_read) return false;

    std::uint32_t export_rva  = *reinterpret_cast<std::uint32_t*>(&pe_hdr[dd_off]);
    if (export_rva == 0) return false;


    std::uint8_t edir[40];
    std::size_t er = is_kernel
        ? dev->read_kernel_raw(target->base + export_rva, edir, 40)
        : dev->read_raw(target->base + export_rva, edir, 40);
    if (er < 40) return false;

    std::uint32_t ordinal_base  = *reinterpret_cast<std::uint32_t*>(&edir[16]);
    std::uint32_t num_functions = *reinterpret_cast<std::uint32_t*>(&edir[20]);
    std::uint32_t num_names     = *reinterpret_cast<std::uint32_t*>(&edir[24]);
    std::uint32_t funcs_rva     = *reinterpret_cast<std::uint32_t*>(&edir[28]);
    std::uint32_t names_rva     = *reinterpret_cast<std::uint32_t*>(&edir[32]);
    std::uint32_t ords_rva      = *reinterpret_cast<std::uint32_t*>(&edir[36]);

    if (num_functions == 0 || num_functions > 200000) return false;


    std::size_t ft_bytes = num_functions * 4;
    if (ft_bytes > 0x200000) return false;
    std::vector<std::uint32_t> func_rvas(num_functions);

    std::size_t ft_read = is_kernel
        ? dev->read_kernel_raw(target->base + funcs_rva, func_rvas.data(), ft_bytes)
        : dev->read_raw(target->base + funcs_rva, func_rvas.data(), ft_bytes);
    if (ft_read < ft_bytes) return false;


    std::uint32_t target_rva = static_cast<std::uint32_t>(resolved_addr - target->base);
    std::uint32_t found_idx = UINT32_MAX;

    for (std::uint32_t i = 0; i < num_functions; i++)
    {
        if (func_rvas[i] == target_rva)
        {
            found_idx = i;
            break;
        }
    }
    if (found_idx == UINT32_MAX) return false;

    out_ordinal = static_cast<std::uint16_t>(found_idx + ordinal_base);

    if (num_names == 0)
    {
        out_by_ordinal = true;
        return true;
    }


    std::vector<std::uint16_t> ordinals(num_names);
    is_kernel
        ? dev->read_kernel_raw(target->base + ords_rva, ordinals.data(), num_names * 2)
        : dev->read_raw(target->base + ords_rva, ordinals.data(), num_names * 2);

    for (std::uint32_t ni = 0; ni < num_names; ni++)
    {
        if (ordinals[ni] == found_idx)
        {
            std::uint32_t name_rva = 0;
            is_kernel
                ? dev->read_kernel_raw(target->base + names_rva + ni * 4, &name_rva, 4)
                : dev->read_raw(target->base + names_rva + ni * 4, &name_rva, 4);

            if (name_rva != 0)
            {
                char nbuf[300] = {};
                is_kernel
                    ? dev->read_kernel_raw(target->base + name_rva, nbuf, sizeof(nbuf) - 1)
                    : dev->read_raw(target->base + name_rva, nbuf, sizeof(nbuf) - 1);

                out_func = nbuf;
                out_hint = static_cast<std::uint16_t>(ni);
                return true;
            }
        }
    }


    out_by_ordinal = true;
    return true;
}


static iat_rebuild_result_t reconstruct_iat_runtime(
    std::vector<std::uint8_t>& image,
    std::uint64_t module_base,
    voyager::device_t* dev,
    bool is_kernel)
{
    iat_rebuild_result_t result;

    if (!dev || !dev->is_connected())
    {
        result.error = "Device not connected";
        return result;
    }

    if (image.size() < 0x200)
    {
        result.error = "Image too small for PE";
        return result;
    }

    if (image[0] != 'M' || image[1] != 'Z')
    {
        result.error = "Invalid MZ signature";
        return result;
    }

    std::uint32_t pe_off = *reinterpret_cast<std::uint32_t*>(&image[0x3C]);
    if (pe_off + 0x18 >= static_cast<std::uint32_t>(image.size()) ||
        image[pe_off] != 'P' || image[pe_off + 1] != 'E')
    {
        result.error = "Invalid PE header";
        return result;
    }

    std::uint16_t num_sections = *reinterpret_cast<std::uint16_t*>(&image[pe_off + 6]);
    std::uint16_t opt_hdr_size = *reinterpret_cast<std::uint16_t*>(&image[pe_off + 20]);
    std::uint32_t opt_off      = pe_off + 24;
    std::uint16_t opt_magic    = *reinterpret_cast<std::uint16_t*>(&image[opt_off]);
    bool is_pe64 = (opt_magic == 0x020B);

    if (!is_pe64 && opt_magic != 0x010B)
    {
        result.error = "Unknown PE optional header magic";
        return result;
    }

    std::uint32_t section_alignment = *reinterpret_cast<std::uint32_t*>(&image[opt_off + 32]);
    if (section_alignment == 0) section_alignment = 0x1000;

    std::uint32_t dd_base = is_pe64 ? (opt_off + 112) : (opt_off + 96);
    std::uint32_t import_dir_off = dd_base + 1 * 8;
    if (import_dir_off + 8 > static_cast<std::uint32_t>(image.size()))
    {
        result.success = true;
        return result;
    }

    std::uint32_t import_rva = *reinterpret_cast<std::uint32_t*>(&image[import_dir_off]);
    if (import_rva == 0 || import_rva >= static_cast<std::uint32_t>(image.size()))
    {
        result.success = true;
        return result;
    }

    std::uint32_t thunk_size = is_pe64 ? 8u : 4u;
    std::uint64_t ordinal_flag = is_pe64 ? 0x8000000000000000ULL : 0x80000000ULL;


    std::vector<module_range_t> modules;
    if (is_kernel)
        modules = enumerate_kernel_modules_for_iat();
    else
        modules = enumerate_ldr_modules_for_iat(dev);

    if (modules.empty())
    {
        result.error = "No modules found for IAT resolution";
        return result;
    }


    struct thunk_info_t
    {
        std::uint64_t resolved_addr;
        std::string   func_name;
        std::uint16_t hint;
        std::uint16_t ordinal;
        bool by_ordinal;
        bool needs_fix;
        bool is_null;
    };

    struct descriptor_info_t
    {
        std::uint32_t desc_off;
        std::uint32_t iat_rva;
        std::string   dll_name;
        std::vector<thunk_info_t> thunks;
        bool needs_rebuild;
    };

    std::vector<descriptor_info_t> descriptors;

    for (std::uint32_t di = 0; di < 0x2000; di++)
    {
        std::uint32_t desc_off = import_rva + di * 20;
        if (desc_off + 20 > static_cast<std::uint32_t>(image.size())) break;

        std::uint32_t int_rva  = *reinterpret_cast<std::uint32_t*>(&image[desc_off]);
        std::uint32_t name_rva = *reinterpret_cast<std::uint32_t*>(&image[desc_off + 12]);
        std::uint32_t iat_rva  = *reinterpret_cast<std::uint32_t*>(&image[desc_off + 16]);

        if (int_rva == 0 && name_rva == 0 && iat_rva == 0) break;
        if (iat_rva == 0) continue;


        std::string dll_name;
        if (name_rva > 0 && name_rva < static_cast<std::uint32_t>(image.size()))
        {
            for (std::uint32_t k = name_rva;
                 k < static_cast<std::uint32_t>(image.size()) && image[k] != 0;
                 k++)
            {
                if (dll_name.size() >= 260) break;
                dll_name += static_cast<char>(image[k]);
            }
        }

        descriptor_info_t di_info;
        di_info.desc_off = desc_off;
        di_info.iat_rva  = iat_rva;
        di_info.dll_name = dll_name;
        di_info.needs_rebuild = false;

        for (int ti = 0; ti < 0x10000; ti++)
        {
            std::uint32_t iat_off = iat_rva + ti * thunk_size;
            if (iat_off + thunk_size > static_cast<std::uint32_t>(image.size())) break;

            std::uint64_t thunk_val = 0;
            if (is_pe64)
                thunk_val = *reinterpret_cast<std::uint64_t*>(&image[iat_off]);
            else
                thunk_val = *reinterpret_cast<std::uint32_t*>(&image[iat_off]);

            thunk_info_t ti_info;
            ti_info.resolved_addr = 0;
            ti_info.hint = 0;
            ti_info.ordinal = 0;
            ti_info.by_ordinal = false;
            ti_info.needs_fix = false;
            ti_info.is_null = false;

            if (thunk_val == 0)
            {
                ti_info.is_null = true;
                di_info.thunks.push_back(ti_info);
                break;
            }


            if (thunk_val & ordinal_flag)
            {
                di_info.thunks.push_back(ti_info);
                continue;
            }


            bool already_valid = false;
            if (thunk_val < static_cast<std::uint64_t>(image.size()) &&
                thunk_val + 3 < static_cast<std::uint64_t>(image.size()))
            {
                char c = static_cast<char>(image[static_cast<std::size_t>(thunk_val) + 2]);
                if (c >= 0x21 && c <= 0x7E)
                    already_valid = true;
            }

            if (already_valid)
            {
                di_info.thunks.push_back(ti_info);
                continue;
            }


            std::uint64_t live_addr = 0;
            if (is_kernel)
                dev->read_kernel_raw(module_base + iat_off, &live_addr, thunk_size);
            else
                dev->read_raw(module_base + iat_off, &live_addr, thunk_size);

            if (!is_pe64)
                live_addr &= 0xFFFFFFFF;


            if (live_addr == 0)
                live_addr = thunk_val;

            ti_info.resolved_addr = live_addr;
            ti_info.needs_fix = true;
            di_info.needs_rebuild = true;


            std::string mod, func;
            std::uint16_t hint = 0, ordinal = 0;
            bool by_ord = false;

            if (live_addr != 0 &&
                resolve_import_address(dev, modules, live_addr, is_kernel,
                                       mod, func, hint, by_ord, ordinal))
            {
                ti_info.func_name  = func;
                ti_info.hint       = hint;
                ti_info.ordinal    = ordinal;
                ti_info.by_ordinal = by_ord;
                result.imports_resolved++;
            }
            else
            {
                result.imports_failed++;
            }

            di_info.thunks.push_back(ti_info);
        }

        if (di_info.needs_rebuild)
            descriptors.push_back(di_info);
    }

    if (descriptors.empty())
    {
        result.success = true;
        return result;
    }


    std::uint32_t original_image_size = static_cast<std::uint32_t>(image.size());
    std::uint32_t new_section_rva =
        (original_image_size + section_alignment - 1) & ~(section_alignment - 1);


    std::size_t names_total = 0;
    for (const auto& desc : descriptors)
    {
        for (const auto& tk : desc.thunks)
        {
            if (tk.needs_fix && !tk.func_name.empty() && !tk.by_ordinal)
            {
                std::size_t entry = 2 + tk.func_name.size() + 1;
                if (entry & 1) entry++;
                names_total += entry;
            }
        }
    }

    std::size_t int_total = 0;
    for (const auto& desc : descriptors)
        int_total += (desc.thunks.size() + 1) * thunk_size;

    std::size_t new_data_raw = names_total + int_total;
    std::uint32_t new_section_vsize =
        (static_cast<std::uint32_t>(new_data_raw) + section_alignment - 1) & ~(section_alignment - 1);

    if (new_section_vsize == 0)
        new_section_vsize = section_alignment;


    image.resize(new_section_rva + new_section_vsize, 0);


    std::uint32_t sec_table_off = pe_off + 24 + opt_hdr_size;
    std::uint32_t new_sec_off   = sec_table_off + num_sections * 40;

    if (new_sec_off + 40 <= new_section_rva && new_sec_off + 40 <= static_cast<std::uint32_t>(image.size()))
    {
        std::memset(&image[new_sec_off], 0, 40);
        std::memcpy(&image[new_sec_off], ".aidat\0\0", 8);
        *reinterpret_cast<std::uint32_t*>(&image[new_sec_off + 8])  = new_section_vsize;
        *reinterpret_cast<std::uint32_t*>(&image[new_sec_off + 12]) = new_section_rva;
        *reinterpret_cast<std::uint32_t*>(&image[new_sec_off + 16]) = new_section_vsize;
        *reinterpret_cast<std::uint32_t*>(&image[new_sec_off + 20]) = new_section_rva;
        *reinterpret_cast<std::uint32_t*>(&image[new_sec_off + 36]) = 0xC0000040;

        *reinterpret_cast<std::uint16_t*>(&image[pe_off + 6]) =
            static_cast<std::uint16_t>(num_sections + 1);
        result.section_added = true;
    }


    *reinterpret_cast<std::uint32_t*>(&image[opt_off + 56]) = new_section_rva + new_section_vsize;


    struct name_loc_t { std::uint32_t rva; int desc_idx; int thunk_idx; };
    std::vector<name_loc_t> name_locs;

    std::uint32_t cursor = new_section_rva;

    for (int d = 0; d < static_cast<int>(descriptors.size()); d++)
    {
        for (int t = 0; t < static_cast<int>(descriptors[d].thunks.size()); t++)
        {
            const auto& tk = descriptors[d].thunks[t];
            if (!tk.needs_fix || tk.func_name.empty() || tk.by_ordinal)
                continue;

            std::uint32_t entry_rva = cursor;


            *reinterpret_cast<std::uint16_t*>(&image[cursor]) = tk.hint;
            cursor += 2;


            std::memcpy(&image[cursor], tk.func_name.c_str(), tk.func_name.size());
            cursor += static_cast<std::uint32_t>(tk.func_name.size());
            image[cursor++] = 0;


            if (cursor & 1) cursor++;

            name_locs.push_back({entry_rva, d, t});
        }
    }


    for (int d = 0; d < static_cast<int>(descriptors.size()); d++)
    {
        auto& desc = descriptors[d];
        std::uint32_t new_int_rva = cursor;


        if (desc.desc_off + 20 <= static_cast<std::uint32_t>(image.size()))
            *reinterpret_cast<std::uint32_t*>(&image[desc.desc_off]) = new_int_rva;

        for (int t = 0; t < static_cast<int>(desc.thunks.size()); t++)
        {
            const auto& tk = desc.thunks[t];
            std::uint64_t new_val = 0;

            if (tk.is_null)
            {
                new_val = 0;
            }
            else if (!tk.needs_fix)
            {

                std::uint32_t iat_off = desc.iat_rva + t * thunk_size;
                if (iat_off + thunk_size <= static_cast<std::uint32_t>(image.size()))
                {
                    if (is_pe64)
                        new_val = *reinterpret_cast<std::uint64_t*>(&image[iat_off]);
                    else
                        new_val = *reinterpret_cast<std::uint32_t*>(&image[iat_off]);
                }
            }
            else if (tk.by_ordinal)
            {
                new_val = ordinal_flag | tk.ordinal;
            }
            else if (!tk.func_name.empty())
            {

                for (const auto& nl : name_locs)
                {
                    if (nl.desc_idx == d && nl.thunk_idx == t)
                    {
                        new_val = nl.rva;
                        break;
                    }
                }
            }


            if (cursor + thunk_size <= static_cast<std::uint32_t>(image.size()))
            {
                if (is_pe64)
                    *reinterpret_cast<std::uint64_t*>(&image[cursor]) = new_val;
                else
                    *reinterpret_cast<std::uint32_t*>(&image[cursor]) =
                        static_cast<std::uint32_t>(new_val);
            }
            cursor += thunk_size;


            if (tk.needs_fix || tk.is_null)
            {
                std::uint32_t iat_off = desc.iat_rva + t * thunk_size;
                if (iat_off + thunk_size <= static_cast<std::uint32_t>(image.size()))
                {
                    if (is_pe64)
                        *reinterpret_cast<std::uint64_t*>(&image[iat_off]) = new_val;
                    else
                        *reinterpret_cast<std::uint32_t*>(&image[iat_off]) =
                            static_cast<std::uint32_t>(new_val);
                }
            }
        }


        if (cursor + thunk_size <= static_cast<std::uint32_t>(image.size()))
        {
            if (is_pe64)
                *reinterpret_cast<std::uint64_t*>(&image[cursor]) = 0;
            else
                *reinterpret_cast<std::uint32_t*>(&image[cursor]) = 0;
        }
        cursor += thunk_size;

        result.descriptors_rebuilt++;
        if (!desc.dll_name.empty())
        {
            bool already = false;
            for (const auto& rd : result.resolved_dlls)
                if (rd == desc.dll_name) { already = true; break; }
            if (!already)
                result.resolved_dlls.push_back(desc.dll_name);
        }
    }


    for (std::uint32_t di = 0; di < 0x2000; di++)
    {
        std::uint32_t desc_off = import_rva + di * 20;
        if (desc_off + 20 > static_cast<std::uint32_t>(image.size())) break;
        std::uint32_t v0 = *reinterpret_cast<std::uint32_t*>(&image[desc_off]);
        std::uint32_t v3 = *reinterpret_cast<std::uint32_t*>(&image[desc_off + 12]);
        std::uint32_t v4 = *reinterpret_cast<std::uint32_t*>(&image[desc_off + 16]);
        if (v0 == 0 && v3 == 0 && v4 == 0) break;
        *reinterpret_cast<std::uint32_t*>(&image[desc_off + 4]) = 0;
        *reinterpret_cast<std::uint32_t*>(&image[desc_off + 8]) = static_cast<std::uint32_t>(-1);
    }

    result.success = true;
    return result;
}


static nlohmann::json iat_rebuild_to_json(const iat_rebuild_result_t& r)
{
    nlohmann::json j;
    j["iat_runtime_rebuild"]  = r.success;
    j["imports_resolved"]     = r.imports_resolved;
    j["imports_failed"]       = r.imports_failed;
    j["descriptors_rebuilt"]  = r.descriptors_rebuilt;
    j["section_added"]        = r.section_added;
    if (!r.resolved_dlls.empty())
        j["resolved_import_dlls"] = r.resolved_dlls;
    if (!r.error.empty())
        j["iat_rebuild_error"]    = r.error;
    return j;
}


struct export_entry_info_t
{
    std::string   dll_name;
    std::string   func_name;
    std::uint16_t hint;
    std::uint16_t ordinal;
    bool          by_ordinal;
};


static std::unordered_map<std::uint64_t, export_entry_info_t> build_module_export_map(
    voyager::device_t* dev,
    const std::vector<module_range_t>& modules,
    bool is_kernel)
{
    std::unordered_map<std::uint64_t, export_entry_info_t> map;
    map.reserve(32768);

    for (const auto& m : modules)
    {
        std::uint8_t hdr[0x1000];
        std::size_t hdr_read = is_kernel
            ? dev->read_kernel_raw(m.base, hdr, sizeof(hdr))
            : dev->read_raw(m.base, hdr, sizeof(hdr));

        if (hdr_read < 0x100 || hdr[0] != 'M' || hdr[1] != 'Z')
            continue;

        std::uint32_t pe_off = *reinterpret_cast<std::uint32_t*>(&hdr[0x3C]);
        if (pe_off + 0x18 >= hdr_read) continue;
        if (hdr[pe_off] != 'P' || hdr[pe_off + 1] != 'E') continue;

        std::uint16_t opt_mag = *reinterpret_cast<std::uint16_t*>(&hdr[pe_off + 0x18]);
        bool pe64 = (opt_mag == 0x020B);
        std::uint32_t dd_off = pe_off + 0x18 + (pe64 ? 112 : 96);
        if (dd_off + 8 > hdr_read) continue;

        std::uint32_t export_rva  = *reinterpret_cast<std::uint32_t*>(&hdr[dd_off]);
        std::uint32_t export_size = *reinterpret_cast<std::uint32_t*>(&hdr[dd_off + 4]);
        if (export_rva == 0 || export_size == 0) continue;

        std::uint8_t edir[40];
        std::size_t er = is_kernel
            ? dev->read_kernel_raw(m.base + export_rva, edir, 40)
            : dev->read_raw(m.base + export_rva, edir, 40);
        if (er < 40) continue;

        std::uint32_t ordinal_base  = *reinterpret_cast<std::uint32_t*>(&edir[16]);
        std::uint32_t num_functions = *reinterpret_cast<std::uint32_t*>(&edir[20]);
        std::uint32_t num_names     = *reinterpret_cast<std::uint32_t*>(&edir[24]);
        std::uint32_t funcs_rva     = *reinterpret_cast<std::uint32_t*>(&edir[28]);
        std::uint32_t names_rva     = *reinterpret_cast<std::uint32_t*>(&edir[32]);
        std::uint32_t ords_rva      = *reinterpret_cast<std::uint32_t*>(&edir[36]);

        if (num_functions == 0 || num_functions > 200000) continue;

        std::size_t ft_bytes = static_cast<std::size_t>(num_functions) * 4;
        if (ft_bytes > 0x200000) continue;
        std::vector<std::uint32_t> func_rvas(num_functions);
        std::size_t ft_read = is_kernel
            ? dev->read_kernel_raw(m.base + funcs_rva, func_rvas.data(), ft_bytes)
            : dev->read_raw(m.base + funcs_rva, func_rvas.data(), ft_bytes);
        if (ft_read < ft_bytes) continue;

        std::unordered_map<std::uint32_t, std::pair<std::string, std::uint16_t>> ord_to_name;
        if (num_names > 0 && num_names <= 200000)
        {
            std::vector<std::uint16_t> ordinals(num_names);
            std::vector<std::uint32_t> name_rva_arr(num_names);
            is_kernel
                ? dev->read_kernel_raw(m.base + ords_rva, ordinals.data(), num_names * 2)
                : dev->read_raw(m.base + ords_rva, ordinals.data(), num_names * 2);
            is_kernel
                ? dev->read_kernel_raw(m.base + names_rva, name_rva_arr.data(), num_names * 4)
                : dev->read_raw(m.base + names_rva, name_rva_arr.data(), num_names * 4);

            for (std::uint32_t ni = 0; ni < num_names; ni++)
            {
                if (name_rva_arr[ni] == 0) continue;
                char nbuf[300] = {};
                is_kernel
                    ? dev->read_kernel_raw(m.base + name_rva_arr[ni], nbuf, sizeof(nbuf) - 1)
                    : dev->read_raw(m.base + name_rva_arr[ni], nbuf, sizeof(nbuf) - 1);
                if (nbuf[0] != 0)
                    ord_to_name[ordinals[ni]] = { std::string(nbuf), static_cast<std::uint16_t>(ni) };
            }
        }

        std::string dll_name = m.name;
        auto slash_pos = dll_name.find_last_of("\\/");
        if (slash_pos != std::string::npos)
            dll_name = dll_name.substr(slash_pos + 1);

        for (std::uint32_t i = 0; i < num_functions; i++)
        {
            if (func_rvas[i] == 0) continue;
            if (func_rvas[i] >= export_rva && func_rvas[i] < export_rva + export_size)
                continue;

            std::uint64_t addr = m.base + func_rvas[i];

            export_entry_info_t info;
            info.dll_name = dll_name;
            info.ordinal  = static_cast<std::uint16_t>(i + ordinal_base);

            auto nit = ord_to_name.find(i);
            if (nit != ord_to_name.end())
            {
                info.func_name  = nit->second.first;
                info.hint       = nit->second.second;
                info.by_ordinal = false;
            }
            else
            {
                info.by_ordinal = true;
                info.hint       = 0;
            }

            map.emplace(addr, std::move(info));
        }
    }

    return map;
}


static int patch_import_call_references(
    std::vector<std::uint8_t>& image,
    const std::unordered_map<std::uint32_t, std::uint32_t>& old_iat_to_new_iat,
    bool is_pe64)
{
    if (!is_pe64 || old_iat_to_new_iat.empty())
        return 0;

    if (image.size() < 0x200)
        return 0;

    std::uint32_t pe_off = *reinterpret_cast<std::uint32_t*>(&image[0x3C]);
    std::uint16_t num_sections = *reinterpret_cast<std::uint16_t*>(&image[pe_off + 6]);
    std::uint16_t opt_size     = *reinterpret_cast<std::uint16_t*>(&image[pe_off + 0x14]);
    std::uint32_t sec_table    = pe_off + 0x18 + opt_size;

    int patched = 0;

    for (int si = 0; si < num_sections && si < 96; si++)
    {
        std::uint32_t soff = sec_table + si * 40;
        if (soff + 40 > static_cast<std::uint32_t>(image.size())) break;

        std::uint32_t vrva  = *reinterpret_cast<std::uint32_t*>(&image[soff + 12]);
        std::uint32_t vsize = *reinterpret_cast<std::uint32_t*>(&image[soff + 8]);
        std::uint32_t chars = *reinterpret_cast<std::uint32_t*>(&image[soff + 36]);

        if (!(chars & 0x20000000)) continue;
        if (vrva == 0 || vsize == 0) continue;

        std::uint32_t scan_end = vrva + vsize;
        if (scan_end > static_cast<std::uint32_t>(image.size()))
            scan_end = static_cast<std::uint32_t>(image.size());

        for (std::uint32_t off = vrva; off + 6 < scan_end; off++)
        {
            bool is_call = (image[off] == 0xFF && image[off + 1] == 0x15);
            bool is_jmp  = (off + 7 < scan_end &&
                            image[off] == 0x48 && image[off + 1] == 0xFF && image[off + 2] == 0x25);


            bool is_mov_rip = (off + 7 < scan_end &&
                               (image[off] == 0x48 || image[off] == 0x4C) &&
                               image[off + 1] == 0x8B &&
                               (image[off + 2] & 0xC7) == 0x05);

            if (!is_call && !is_jmp && !is_mov_rip) continue;

            std::uint32_t disp_off = is_call ? (off + 2) : (off + 3);
            std::uint32_t inst_end = is_call ? (off + 6) : (off + 7);

            if (disp_off + 4 > static_cast<std::uint32_t>(image.size())) continue;

            std::int32_t disp = *reinterpret_cast<std::int32_t*>(&image[disp_off]);
            std::uint32_t target_rva = static_cast<std::uint32_t>(
                static_cast<std::int64_t>(inst_end) + disp);

            auto it = old_iat_to_new_iat.find(target_rva);
            if (it == old_iat_to_new_iat.end()) continue;

            std::int32_t new_disp = static_cast<std::int32_t>(
                static_cast<std::int64_t>(it->second) - static_cast<std::int64_t>(inst_end));
            *reinterpret_cast<std::int32_t*>(&image[disp_off]) = new_disp;
            patched++;
        }
    }

    return patched;
}


static iat_rebuild_result_t full_iat_scan_and_rebuild(
    std::vector<std::uint8_t>& image,
    std::uint64_t module_base,
    voyager::device_t* dev,
    bool is_kernel)
{
    iat_rebuild_result_t result;

    if (!dev || !dev->is_connected())
    {
        result.error = "Device not connected";
        return result;
    }

    if (image.size() < 0x200 || image[0] != 'M' || image[1] != 'Z')
    {
        result.error = "Invalid PE image";
        return result;
    }

    std::uint32_t pe_off = *reinterpret_cast<std::uint32_t*>(&image[0x3C]);
    if (pe_off + 0x18 >= static_cast<std::uint32_t>(image.size()) ||
        image[pe_off] != 'P' || image[pe_off + 1] != 'E')
    {
        result.error = "Invalid PE header";
        return result;
    }

    std::uint16_t num_sections = *reinterpret_cast<std::uint16_t*>(&image[pe_off + 6]);
    std::uint16_t opt_hdr_size = *reinterpret_cast<std::uint16_t*>(&image[pe_off + 20]);
    std::uint32_t opt_off      = pe_off + 24;
    std::uint16_t opt_magic    = *reinterpret_cast<std::uint16_t*>(&image[opt_off]);
    bool is_pe64 = (opt_magic == 0x020B);

    if (!is_pe64 && opt_magic != 0x010B)
    {
        result.error = "Unknown PE magic";
        return result;
    }

    std::uint32_t section_alignment = *reinterpret_cast<std::uint32_t*>(&image[opt_off + 32]);
    if (section_alignment == 0) section_alignment = 0x1000;

    std::uint32_t sec_table_off = pe_off + 24 + opt_hdr_size;
    std::uint32_t thunk_size    = is_pe64 ? 8u : 4u;
    std::uint32_t dd_base       = is_pe64 ? (opt_off + 112) : (opt_off + 96);

    std::vector<module_range_t> modules;
    if (is_kernel)
        modules = enumerate_kernel_modules_for_iat();
    else
        modules = enumerate_ldr_modules_for_iat(dev);

    if (modules.empty())
    {
        result.error = "No modules found for export map";
        return result;
    }

    msg(OBFSTR_C("AiDA: Building export address map from %zu modules...\n"), modules.size());
    auto export_map = build_module_export_map(dev, modules, is_kernel);

    if (export_map.empty())
    {
        result.error = "Export map empty — no module exports readable";
        return result;
    }

    msg(OBFSTR_C("AiDA: Export map built with %zu entries, scanning image for imports...\n"),
        export_map.size());

    struct found_import_t
    {
        std::uint32_t iat_offset;
        std::string   dll_name;
        std::string   func_name;
        std::uint16_t hint;
        std::uint16_t ordinal;
        bool          by_ordinal;
    };

    std::map<std::string, std::vector<found_import_t>> dll_imports;
    std::set<std::uint32_t> found_offsets;

    auto try_resolve = [&](std::uint32_t off, std::uint64_t val) -> bool
    {
        if (val == 0 || found_offsets.count(off))
            return false;

        auto it = export_map.find(val);
        if (it == export_map.end())
            return false;

        if (val >= module_base && val < module_base + static_cast<std::uint64_t>(image.size()))
            return false;

        const auto& info = it->second;
        found_offsets.insert(off);

        std::string dll_key = info.dll_name;
        for (auto& c : dll_key) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));

        found_import_t fi;
        fi.iat_offset  = off;
        fi.dll_name    = info.dll_name;
        fi.func_name   = info.func_name;
        fi.hint        = info.hint;
        fi.ordinal     = info.ordinal;
        fi.by_ordinal  = info.by_ordinal;
        dll_imports[dll_key].push_back(fi);
        return true;
    };

    for (int si = 0; si < num_sections && si < 96; si++)
    {
        std::uint32_t soff  = sec_table_off + si * 40;
        if (soff + 40 > static_cast<std::uint32_t>(image.size())) break;

        std::uint32_t vrva  = *reinterpret_cast<std::uint32_t*>(&image[soff + 12]);
        std::uint32_t vsize = *reinterpret_cast<std::uint32_t*>(&image[soff + 8]);
        std::uint32_t chars = *reinterpret_cast<std::uint32_t*>(&image[soff + 36]);

        if (vrva == 0 || vsize == 0) continue;
        if (chars & 0x20000000) continue;

        std::uint32_t scan_end = vrva + vsize;
        if (scan_end > static_cast<std::uint32_t>(image.size()))
            scan_end = static_cast<std::uint32_t>(image.size());

        for (std::uint32_t off = vrva; off + thunk_size <= scan_end; off += thunk_size)
        {
            std::uint64_t dump_val = 0;
            if (is_pe64)
                dump_val = *reinterpret_cast<std::uint64_t*>(&image[off]);
            else
                dump_val = *reinterpret_cast<std::uint32_t*>(&image[off]);

            if (dump_val == 0) continue;

            if (try_resolve(off, dump_val))
                continue;

            std::uint64_t live_val = 0;
            if (is_kernel)
                dev->read_kernel_raw(module_base + off, &live_val, thunk_size);
            else
                dev->read_raw(module_base + off, &live_val, thunk_size);
            if (!is_pe64)
                live_val &= 0xFFFFFFFF;

            if (live_val != 0 && live_val != dump_val)
                try_resolve(off, live_val);
        }
    }

    if (is_pe64)
    {
        for (int si = 0; si < num_sections && si < 96; si++)
        {
            std::uint32_t soff  = sec_table_off + si * 40;
            if (soff + 40 > static_cast<std::uint32_t>(image.size())) break;

            std::uint32_t vrva  = *reinterpret_cast<std::uint32_t*>(&image[soff + 12]);
            std::uint32_t vsize = *reinterpret_cast<std::uint32_t*>(&image[soff + 8]);
            std::uint32_t chars = *reinterpret_cast<std::uint32_t*>(&image[soff + 36]);

            if (!(chars & 0x20000000)) continue;
            if (vrva == 0 || vsize == 0) continue;

            std::uint32_t scan_end = vrva + vsize;
            if (scan_end > static_cast<std::uint32_t>(image.size()))
                scan_end = static_cast<std::uint32_t>(image.size());

            for (std::uint32_t off = vrva; off + 7 < scan_end; off++)
            {
                bool is_call = (image[off] == 0xFF && image[off + 1] == 0x15);
                bool is_jmp  = (off + 7 < scan_end &&
                                image[off] == 0x48 && image[off + 1] == 0xFF && image[off + 2] == 0x25);

                if (!is_call && !is_jmp) continue;

                std::uint32_t disp_off = is_call ? (off + 2) : (off + 3);
                std::uint32_t inst_end = is_call ? (off + 6) : (off + 7);
                if (disp_off + 4 > static_cast<std::uint32_t>(image.size())) continue;

                std::int32_t disp = *reinterpret_cast<std::int32_t*>(&image[disp_off]);
                std::int64_t target_rva64 = static_cast<std::int64_t>(inst_end) + disp;
                if (target_rva64 < 0 || target_rva64 + static_cast<std::int64_t>(thunk_size) >
                    static_cast<std::int64_t>(image.size()))
                    continue;

                std::uint32_t target_off = static_cast<std::uint32_t>(target_rva64);

                std::uint64_t slot_val = *reinterpret_cast<std::uint64_t*>(&image[target_off]);
                if (slot_val == 0) continue;

                if (!try_resolve(target_off, slot_val))
                {
                    std::uint64_t live_val = 0;
                    if (is_kernel)
                        dev->read_kernel_raw(module_base + target_off, &live_val, 8);
                    else
                        dev->read_raw(module_base + target_off, &live_val, 8);
                    if (live_val != 0 && live_val != slot_val)
                        try_resolve(target_off, live_val);
                }
            }
        }
    }

    int total_imports = 0;
    for (const auto& [k, v] : dll_imports)
        total_imports += static_cast<int>(v.size());

    if (total_imports == 0)
    {
        result.success = true;
        return result;
    }

    msg(OBFSTR_C("AiDA: Full IAT scan found %d imports across %zu DLLs\n"),
        total_imports, dll_imports.size());

    std::size_t descriptors_size = (dll_imports.size() + 1) * 20;
    std::size_t dll_names_size   = 0;
    std::size_t hint_names_size  = 0;
    std::size_t ilt_total        = 0;
    std::size_t iat_total        = 0;

    for (const auto& [dll_key, entries] : dll_imports)
    {
        if (entries.empty()) continue;
        dll_names_size += entries[0].dll_name.size() + 1;
        if (dll_names_size & 1) dll_names_size++;

        for (const auto& e : entries)
        {
            if (!e.by_ordinal && !e.func_name.empty())
            {
                std::size_t entry = 2 + e.func_name.size() + 1;
                if (entry & 1) entry++;
                hint_names_size += entry;
            }
        }

        ilt_total += (entries.size() + 1) * thunk_size;
        iat_total += (entries.size() + 1) * thunk_size;
    }

    std::size_t new_data_raw = descriptors_size + dll_names_size + hint_names_size + ilt_total + iat_total;

    std::uint32_t original_image_size = static_cast<std::uint32_t>(image.size());
    std::uint32_t new_section_rva =
        (original_image_size + section_alignment - 1) & ~(section_alignment - 1);
    std::uint32_t new_section_vsize =
        (static_cast<std::uint32_t>(new_data_raw) + section_alignment - 1) & ~(section_alignment - 1);
    if (new_section_vsize == 0) new_section_vsize = section_alignment;

    image.resize(new_section_rva + new_section_vsize, 0);

    std::uint32_t new_sec_hdr = sec_table_off + num_sections * 40;
    if (new_sec_hdr + 40 <= new_section_rva &&
        new_sec_hdr + 40 <= static_cast<std::uint32_t>(image.size()))
    {
        std::memset(&image[new_sec_hdr], 0, 40);
        std::memcpy(&image[new_sec_hdr], ".aidai\0\0", 8);
        *reinterpret_cast<std::uint32_t*>(&image[new_sec_hdr + 8])  = new_section_vsize;
        *reinterpret_cast<std::uint32_t*>(&image[new_sec_hdr + 12]) = new_section_rva;
        *reinterpret_cast<std::uint32_t*>(&image[new_sec_hdr + 16]) = new_section_vsize;
        *reinterpret_cast<std::uint32_t*>(&image[new_sec_hdr + 20]) = new_section_rva;
        *reinterpret_cast<std::uint32_t*>(&image[new_sec_hdr + 36]) = 0xC0000040;

        *reinterpret_cast<std::uint16_t*>(&image[pe_off + 6]) =
            static_cast<std::uint16_t>(num_sections + 1);
        result.section_added = true;
    }

    *reinterpret_cast<std::uint32_t*>(&image[opt_off + 56]) = new_section_rva + new_section_vsize;

    std::uint32_t cursor = new_section_rva;

    std::uint32_t descriptors_rva = cursor;
    std::uint32_t descriptors_end = cursor + static_cast<std::uint32_t>(descriptors_size);
    cursor = descriptors_end;

    struct dll_layout_t
    {
        std::string dll_key;
        std::uint32_t name_rva;
        std::uint32_t ilt_rva;
        std::uint32_t iat_rva;
        std::vector<std::uint32_t> hint_name_rvas;
        std::vector<bool> by_ordinal_flags;
        std::vector<std::uint16_t> ordinals;
    };
    std::vector<dll_layout_t> layouts;

    for (const auto& [dll_key, entries] : dll_imports)
    {
        if (entries.empty()) continue;
        dll_layout_t layout;
        layout.dll_key = dll_key;

        layout.name_rva = cursor;
        const std::string& dn = entries[0].dll_name;
        std::memcpy(&image[cursor], dn.c_str(), dn.size());
        cursor += static_cast<std::uint32_t>(dn.size());
        image[cursor++] = 0;
        if (cursor & 1) cursor++;

        for (const auto& e : entries)
        {
            layout.by_ordinal_flags.push_back(e.by_ordinal);
            layout.ordinals.push_back(e.ordinal);

            if (!e.by_ordinal && !e.func_name.empty())
            {
                std::uint32_t hn_rva = cursor;
                *reinterpret_cast<std::uint16_t*>(&image[cursor]) = e.hint;
                cursor += 2;
                std::memcpy(&image[cursor], e.func_name.c_str(), e.func_name.size());
                cursor += static_cast<std::uint32_t>(e.func_name.size());
                image[cursor++] = 0;
                if (cursor & 1) cursor++;
                layout.hint_name_rvas.push_back(hn_rva);
            }
            else
            {
                layout.hint_name_rvas.push_back(0);
            }
        }

        layouts.push_back(std::move(layout));
    }

    std::unordered_map<std::uint32_t, std::uint32_t> old_to_new_iat;

    int layout_idx = 0;
    for (auto& [dll_key, entries] : dll_imports)
    {
        if (entries.empty()) continue;
        auto& layout = layouts[layout_idx++];

        layout.ilt_rva = cursor;
        for (std::size_t i = 0; i < entries.size(); i++)
        {
            std::uint64_t val = 0;
            if (layout.by_ordinal_flags[i])
                val = (is_pe64 ? 0x8000000000000000ULL : 0x80000000ULL) | layout.ordinals[i];
            else
                val = layout.hint_name_rvas[i];

            if (is_pe64)
                *reinterpret_cast<std::uint64_t*>(&image[cursor]) = val;
            else
                *reinterpret_cast<std::uint32_t*>(&image[cursor]) = static_cast<std::uint32_t>(val);
            cursor += thunk_size;
        }
        if (is_pe64)
            *reinterpret_cast<std::uint64_t*>(&image[cursor]) = 0;
        else
            *reinterpret_cast<std::uint32_t*>(&image[cursor]) = 0;
        cursor += thunk_size;

        layout.iat_rva = cursor;
        for (std::size_t i = 0; i < entries.size(); i++)
        {
            std::uint64_t val = 0;
            if (layout.by_ordinal_flags[i])
                val = (is_pe64 ? 0x8000000000000000ULL : 0x80000000ULL) | layout.ordinals[i];
            else
                val = layout.hint_name_rvas[i];

            if (is_pe64)
                *reinterpret_cast<std::uint64_t*>(&image[cursor]) = val;
            else
                *reinterpret_cast<std::uint32_t*>(&image[cursor]) = static_cast<std::uint32_t>(val);

            old_to_new_iat[entries[i].iat_offset] = cursor;
            cursor += thunk_size;
        }
        if (is_pe64)
            *reinterpret_cast<std::uint64_t*>(&image[cursor]) = 0;
        else
            *reinterpret_cast<std::uint32_t*>(&image[cursor]) = 0;
        cursor += thunk_size;
    }

    layout_idx = 0;
    for (auto& [dll_key, entries] : dll_imports)
    {
        if (entries.empty()) continue;
        auto& layout = layouts[layout_idx];
        std::uint32_t desc_off = descriptors_rva + layout_idx * 20;

        *reinterpret_cast<std::uint32_t*>(&image[desc_off + 0])  = layout.ilt_rva;
        *reinterpret_cast<std::uint32_t*>(&image[desc_off + 4])  = 0;
        *reinterpret_cast<std::uint32_t*>(&image[desc_off + 8])  = static_cast<std::uint32_t>(-1);
        *reinterpret_cast<std::uint32_t*>(&image[desc_off + 12]) = layout.name_rva;
        *reinterpret_cast<std::uint32_t*>(&image[desc_off + 16]) = layout.iat_rva;

        layout_idx++;

        bool dll_already = false;
        for (const auto& rd : result.resolved_dlls)
            if (rd == entries[0].dll_name) { dll_already = true; break; }
        if (!dll_already)
            result.resolved_dlls.push_back(entries[0].dll_name);
    }

    std::uint32_t null_desc_off = descriptors_rva + layout_idx * 20;
    if (null_desc_off + 20 <= static_cast<std::uint32_t>(image.size()))
        std::memset(&image[null_desc_off], 0, 20);

    std::uint32_t import_dir_off = dd_base + 1 * 8;
    if (import_dir_off + 8 <= static_cast<std::uint32_t>(image.size()))
    {
        *reinterpret_cast<std::uint32_t*>(&image[import_dir_off])     = descriptors_rva;
        *reinterpret_cast<std::uint32_t*>(&image[import_dir_off + 4]) =
            static_cast<std::uint32_t>(descriptors_size);
    }

    for (auto& [dll_key, entries] : dll_imports)
    {
        for (const auto& e : entries)
        {
            std::uint32_t off = e.iat_offset;
            if (off + thunk_size > original_image_size) continue;

            auto new_it = old_to_new_iat.find(off);
            if (new_it == old_to_new_iat.end()) continue;

            std::uint32_t new_iat_off = new_it->second;
            if (new_iat_off + thunk_size > static_cast<std::uint32_t>(image.size())) continue;

            if (is_pe64)
            {
                std::uint64_t new_val = *reinterpret_cast<std::uint64_t*>(&image[new_iat_off]);
                *reinterpret_cast<std::uint64_t*>(&image[off]) = new_val;
            }
            else
            {
                std::uint32_t new_val = *reinterpret_cast<std::uint32_t*>(&image[new_iat_off]);
                *reinterpret_cast<std::uint32_t*>(&image[off]) = new_val;
            }
        }
    }

    int xrefs_patched = patch_import_call_references(image, old_to_new_iat, is_pe64);
    if (xrefs_patched > 0)
        msg(OBFSTR_C("AiDA: Patched %d import call/jmp cross-references to new IAT\n"), xrefs_patched);

    result.success = true;
    result.imports_resolved = total_imports;
    result.descriptors_rebuilt = static_cast<int>(dll_imports.size());

    msg(OBFSTR_C("AiDA: Full IAT rebuild complete — %d imports, %d DLLs, %d xrefs patched\n"),
        total_imports, static_cast<int>(dll_imports.size()), xrefs_patched);

    return result;
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

    std::uint16_t e_magic = get_word(base);
    if (e_magic != 0x5A4D)
        return tool_result_t::error(OBFSTR("Not a valid PE: missing MZ signature at ") + helpers::format_address(base));

    std::uint32_t pe_off = get_dword(base + 0x3C);
    ea_t pe_hdr = base + pe_off;
    if (get_dword(pe_hdr) != 0x00004550)
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
        std::uint32_t rva  = get_dword(dd_base + i * 8);
        std::uint32_t sz   = get_dword(dd_base + i * 8 + 4);
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
            dd["num_functions"] = get_dword(exp + 20);
            dd["num_names"]     = get_dword(exp + 24);
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
            if (is64)
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
            if (cb_va != 0)
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
            lc_j["security_cookie"]          = helpers::format_address(static_cast<ea_t>(get_qword(lc + 88)));
            lc_j["guard_cf_check_function"]  = helpers::format_address(static_cast<ea_t>(get_qword(lc + 112)));
            lc_j["guard_cf_function_table"]  = helpers::format_address(static_cast<ea_t>(get_qword(lc + 128)));
            lc_j["guard_cf_function_count"]  = static_cast<std::uint64_t>(get_qword(lc + 136));
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

    return tool_result_t::ok(OBFSTR("Entropy: ") + std::to_string(overall) + OBFSTR(" bits/byte — ") + verdict, result);
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
        std::uint8_t pr[16];
        for (int b = 0; b < 16; ++b) pr[b] = static_cast<std::uint8_t>(get_byte(ea + b));

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
            hook_target = static_cast<ea_t>(get_qword(ptr));
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
                if (ea >= start + 5 && get_byte(ea - 5) == 0xB8)
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
    for (int i = 0; i < get_import_module_qty(); ++i)
    {
        qstring mod_name;
        get_import_module_name(&mod_name, i);
        std::string dll = mod_name.c_str();
        struct ctx_t { std::vector<std::pair<std::string, std::string>>* apis; std::string dll; };
        ctx_t ctx{&api_names, dll};
        enum_import_names(i, [](ea_t, const char* nm, uval_t, void* ud) -> int {
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
    if (is_64)
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

namespace driver_tools
{

static std::string to_lower_ascii_copy(std::string value)
{
    std::transform(value.begin(), value.end(), value.begin(),
        [](unsigned char ch) { return static_cast<char>(std::tolower(ch)); });
    return value;
}

static bool is_ida_host_process_name(const std::string& process_name)
{
    const std::string lower = to_lower_ascii_copy(process_name);
    return lower.find("ida.exe") != std::string::npos
        || lower.find("ida64.exe") != std::string::npos
        || lower.find("idat.exe") != std::string::npos
        || lower.find("idat64.exe") != std::string::npos;
}

static std::string trim_ascii_copy(const std::string& text)
{
    const std::size_t first = text.find_first_not_of(" \t\r\n");
    if (first == std::string::npos)
        return {};
    const std::size_t last = text.find_last_not_of(" \t\r\n");
    return text.substr(first, last - first + 1);
}

static bool parse_u32_id_value(const json& value, std::uint32_t& out)
{
    if (value.is_number_unsigned())
    {
        const auto v = value.get<std::uint64_t>();
        if (v == 0 || v > 0xFFFFFFFFULL)
            return false;
        out = static_cast<std::uint32_t>(v);
        return true;
    }

    if (value.is_number_integer())
    {
        const auto v = value.get<std::int64_t>();
        if (v <= 0 || v > 0xFFFFFFFFLL)
            return false;
        out = static_cast<std::uint32_t>(v);
        return true;
    }

    if (!value.is_string())
        return false;

    std::string s = trim_ascii_copy(value.get<std::string>());
    if (s.empty())
        return false;

    try
    {
        std::size_t idx = 0;
        std::uint64_t parsed = 0;
        if (s.size() > 2 && s[0] == '0' && (s[1] == 'x' || s[1] == 'X'))
            parsed = std::stoull(s, &idx, 16);
        else
            parsed = std::stoull(s, &idx, 10);

        if (idx != s.size() || parsed == 0 || parsed > 0xFFFFFFFFULL)
            return false;

        out = static_cast<std::uint32_t>(parsed);
        return true;
    }
    catch (...)
    {
        return false;
    }
}

static bool parse_single_hex_byte_token(const std::string& raw_token, std::uint8_t& out)
{
    std::string token = trim_ascii_copy(raw_token);
    if (token.empty())
        return false;

    if (token.size() > 2 && token[0] == '0' && (token[1] == 'x' || token[1] == 'X'))
        token = token.substr(2);

    if (token.empty())
        return false;

    const bool all_hex = std::all_of(token.begin(), token.end(),
        [](unsigned char c) { return std::isxdigit(c) != 0; });
    const bool has_hex_alpha = std::any_of(token.begin(), token.end(),
        [](unsigned char c) { return std::isalpha(c) != 0; });

    if (all_hex)
    {
        try
        {
            std::uint64_t v16 = std::stoull(token, nullptr, 16);
            if (v16 <= 0xFFULL && (has_hex_alpha || token.size() <= 2))
            {
                out = static_cast<std::uint8_t>(v16);
                return true;
            }
        }
        catch (...) {}
    }

    const bool all_digits = std::all_of(token.begin(), token.end(),
        [](unsigned char c) { return std::isdigit(c) != 0; });
    if (all_digits)
    {
        try
        {
            std::uint64_t v10 = std::stoull(token, nullptr, 10);
            if (v10 <= 0xFFULL)
            {
                out = static_cast<std::uint8_t>(v10);
                return true;
            }
        }
        catch (...) {}
    }

    return false;
}

static bool parse_byte_sequence(const json& bytes_value, std::vector<std::uint8_t>& out, std::string& error)
{
    out.clear();

    if (bytes_value.is_array())
    {
        for (std::size_t i = 0; i < bytes_value.size(); ++i)
        {
            const auto& item = bytes_value[i];
            if (item.is_number_integer())
            {
                const auto v = item.get<std::int64_t>();
                if (v < 0 || v > 255)
                {
                    error = "Byte array value out of range at index " + std::to_string(i) + " (expected 0..255).";
                    return false;
                }
                out.push_back(static_cast<std::uint8_t>(v));
                continue;
            }

            if (item.is_number_unsigned())
            {
                const auto v = item.get<std::uint64_t>();
                if (v > 255)
                {
                    error = "Byte array value out of range at index " + std::to_string(i) + " (expected 0..255).";
                    return false;
                }
                out.push_back(static_cast<std::uint8_t>(v));
                continue;
            }

            if (item.is_string())
            {
                std::uint8_t b = 0;
                if (!parse_single_hex_byte_token(item.get<std::string>(), b))
                {
                    error = "Invalid byte token at index " + std::to_string(i) + ".";
                    return false;
                }
                out.push_back(b);
                continue;
            }

            error = "Unsupported bytes array element type at index " + std::to_string(i) + ".";
            return false;
        }

        if (out.empty())
            error = "No bytes were provided.";
        return !out.empty();
    }

    if (!bytes_value.is_string())
    {
        error = "'bytes' must be either a string or an array.";
        return false;
    }

    std::string text = trim_ascii_copy(bytes_value.get<std::string>());
    if (text.empty())
    {
        error = "No bytes were provided.";
        return false;
    }

    if (!text.empty() && text.front() == '[')
    {
        try
        {
            json parsed = json::parse(text);
            if (!parsed.is_array())
            {
                error = "String bytes payload starts with '[' but is not a valid array.";
                return false;
            }
            return parse_byte_sequence(parsed, out, error);
        }
        catch (...)
        {
            error = "Failed to parse bytes array string.";
            return false;
        }
    }

    std::string tokenized = text;
    std::replace(tokenized.begin(), tokenized.end(), ',', ' ');
    if (tokenized.find(' ') != std::string::npos || tokenized.find('\t') != std::string::npos ||
        tokenized.find('\n') != std::string::npos || tokenized.find('\r') != std::string::npos)
    {
        std::istringstream iss(tokenized);
        std::string token;
        std::size_t index = 0;
        while (iss >> token)
        {
            std::uint8_t b = 0;
            if (!parse_single_hex_byte_token(token, b))
            {
                error = "Invalid hex byte token '" + token + "' at position " + std::to_string(index) + ".";
                return false;
            }
            out.push_back(b);
            ++index;
        }
        if (out.empty())
            error = "No bytes were provided.";
        return !out.empty();
    }

    if (tokenized.size() > 2 && tokenized[0] == '0' && (tokenized[1] == 'x' || tokenized[1] == 'X'))
        tokenized = tokenized.substr(2);

    if (tokenized.size() % 2 != 0)
    {
        error = "Packed hex string must contain an even number of hex digits.";
        return false;
    }

    if (!std::all_of(tokenized.begin(), tokenized.end(),
        [](unsigned char c) { return std::isxdigit(c) != 0; }))
    {
        error = "Packed hex string contains non-hex characters.";
        return false;
    }

    for (std::size_t i = 0; i < tokenized.size(); i += 2)
    {
        const std::string byte_str = tokenized.substr(i, 2);
        out.push_back(static_cast<std::uint8_t>(std::stoul(byte_str, nullptr, 16)));
    }

    if (out.empty())
        error = "No bytes were provided.";

    return !out.empty();
}

static bool is_process_alive(std::uint32_t pid)
{
    if (pid == 0)
        return false;

    HANDLE h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    if (h == nullptr)
        return false;

    DWORD exit_code = 0;
    const bool ok = GetExitCodeProcess(h, &exit_code) != FALSE;
    CloseHandle(h);

    return ok && exit_code == STILL_ACTIVE;
}

static std::optional<tool_result_t> ensure_attached_process_context(const json& params)
{
    if (!device->is_connected())
        return tool_result_t::error(OBFSTR("Driver not connected. Call driver_connect first."));

    std::uint32_t requested_pid = 0;
    if (params.contains("process_id"))
    {
        if (!parse_u32_id_value(params["process_id"], requested_pid))
            return tool_result_t::error(OBFSTR("Invalid process_id. Expected a positive decimal PID or 0x-prefixed hex PID."));
    }
    else if (params.contains("pid"))
    {
        if (!parse_u32_id_value(params["pid"], requested_pid))
            return tool_result_t::error(OBFSTR("Invalid pid. Expected a positive decimal PID or 0x-prefixed hex PID."));
    }

    if (requested_pid != 0 && anti_re::is_self_target_pid(requested_pid))
        return tool_result_t::error(OBFSTR("Refusing to target the current IDA host PID."));

    const std::uint32_t current_pid = device->get_process_id();
    if (requested_pid != 0 && requested_pid != current_pid)
    {
        if (!is_process_alive(requested_pid))
            return tool_result_t::error(OBFSTR("process_id ") + std::to_string(requested_pid) + OBFSTR(" is not alive."));

        device->clear_process_context();
        device->set_process_id(requested_pid);
        (void)device->find_image();
        device->solve_dtb();

        if (device->get_dtb() == 0)
        {
            device->clear_process_context();
            return tool_result_t::error(OBFSTR("Failed to solve DTB for process_id ") + std::to_string(requested_pid) + OBFSTR(". Reattach by name with driver_attach."));
        }
    }

    if (device->get_process_id() == 0)
        return tool_result_t::error(OBFSTR("Not attached. Call driver_attach first or pass process_id."));

    if (!is_process_alive(device->get_process_id()))
    {
        const std::uint32_t dead_pid = device->get_process_id();
        device->clear_process_context();
        return tool_result_t::error(OBFSTR("Attached process PID ") + std::to_string(dead_pid) + OBFSTR(" is no longer alive. Call driver_attach again."));
    }

    if (device->get_dtb() == 0)
    {
        device->solve_dtb();
        if (device->get_dtb() == 0)
            return tool_result_t::error(OBFSTR("Failed to solve DTB for the attached process."));
    }

    return std::nullopt;
}

static std::optional<std::uint32_t> parse_tid_param(const json& params)
{
    if (!params.contains("tid"))
        return std::nullopt;

    std::uint32_t tid = 0;
    if (!parse_u32_id_value(params["tid"], tid) || tid == 0)
        return std::nullopt;
    return tid;
}

static bool is_probably_kernel_address(std::uint64_t address)
{
    return address >= 0xFFFF000000000000ULL;
}

static std::string read_remote_unicode_ascii(voyager::device_t* dev,
                                             std::uint64_t ptr,
                                             std::uint16_t byte_len,
                                             std::uint16_t max_len)
{
    if (dev == nullptr || ptr == 0 || byte_len == 0 || byte_len > max_len)
        return {};

    std::vector<std::uint8_t> raw(byte_len, 0);
    if (dev->read_raw(ptr, raw.data(), byte_len) == 0)
        return {};

    std::string text;
    text.reserve(byte_len / 2);
    for (std::size_t i = 0; i + 1 < raw.size(); i += 2)
    {
        const std::uint16_t wc = raw[i] | (static_cast<std::uint16_t>(raw[i + 1]) << 8);
        if (wc == 0)
            break;
        text += (wc >= 32 && wc < 128) ? static_cast<char>(wc) : '?';
    }

    return text;
}

static bool resolve_loaded_module_base(const std::string& query,
                                       std::uint64_t& out_base,
                                       std::string& out_name)
{
    out_base = 0;
    out_name.clear();

    if (!device || !device->is_connected() || device->get_process_id() == 0 || query.empty())
        return false;

    voyager::device_t::peb_info peb{};
    if (!device->read_peb(peb) || peb.ldr_address == 0)
        return false;

    const std::string needle = to_lower_ascii_copy(query);
    const std::uint64_t list_head = peb.ldr_address + 0x10;
    std::uint64_t current = device->read<std::uint64_t>(list_head);
    if (current == 0 || current == list_head)
        return false;

    auto basename_of_path = [](const std::string& path) {
        const std::size_t pos = path.find_last_of("\\/");
        return pos == std::string::npos ? path : path.substr(pos + 1);
    };

    std::uint64_t partial_base = 0;
    std::string partial_name;
    int max_iter = 1024;

    while (current != list_head && current != 0 && max_iter-- > 0)
    {
        const std::uint64_t base = device->read<std::uint64_t>(current + 0x30);
        const std::string module_name = read_remote_unicode_ascii(
            device.get(),
            device->read<std::uint64_t>(current + 0x60),
            device->read<std::uint16_t>(current + 0x58),
            520);
        const std::string module_path = read_remote_unicode_ascii(
            device.get(),
            device->read<std::uint64_t>(current + 0x50),
            device->read<std::uint16_t>(current + 0x48),
            1024);

        const std::string lower_name = to_lower_ascii_copy(module_name);
        const std::string lower_path = to_lower_ascii_copy(module_path);
        const std::string lower_file = to_lower_ascii_copy(basename_of_path(module_path));

        const bool exact_match = (lower_name == needle || lower_path == needle || lower_file == needle);
        const bool partial_match = !exact_match &&
            (lower_name.find(needle) != std::string::npos ||
             lower_path.find(needle) != std::string::npos ||
             lower_file.find(needle) != std::string::npos);

        if (base != 0 && exact_match)
        {
            out_base = base;
            out_name = module_name.empty() ? module_path : module_name;
            return true;
        }

        if (base != 0 && partial_match && partial_base == 0)
        {
            partial_base = base;
            partial_name = module_name.empty() ? module_path : module_name;
        }

        const std::uint64_t next = device->read<std::uint64_t>(current);
        if (next == current || next == 0)
            break;
        current = next;
    }

    if (partial_base != 0)
    {
        out_base = partial_base;
        out_name = partial_name;
        return true;
    }

    return false;
}

tool_result_t driver_connect(const json& params)
{
    if (device->is_connected())
    {
        bool cleared_self_target = false;
        if (anti_re::is_self_target_pid(device->get_process_id()))
        {
            device->clear_process_context();
            cleared_self_target = true;
        }

        if (device->get_kernel_dtb() == 0)
            device->solve_kernel_dtb();

        if (cleared_self_target)
        {
            json result;
            result["connected"] = true;
            result["process_id"] = device->get_process_id();
            result["kernel_dtb"] = helpers::format_address(device->get_kernel_dtb());
            return tool_result_t::ok(OBFSTR("Driver connected. Cleared stale IDA host attachment context."), result);
        }

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
    result["is_self_target"] = anti_re::is_self_target_pid(device->get_process_id());

    if (result["is_self_target"].get<bool>())
        result["warning"] = "Driver target is IDA host process. Call driver_unattach and driver_attach target.exe.";

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

    std::string process_name;
    if (params.contains("process") && params["process"].is_string())
        process_name = trim_ascii_copy(params["process"].get<std::string>());
    else if (params.contains("process_name") && params["process_name"].is_string())
        process_name = trim_ascii_copy(params["process_name"].get<std::string>());
    else if (params.contains("name") && params["name"].is_string())
        process_name = trim_ascii_copy(params["name"].get<std::string>());

    if (process_name.empty())
        return tool_result_t::error(OBFSTR("Missing process name. Use process='target.exe'. Aliases supported: process_name, name."));

    if (is_ida_host_process_name(process_name))
        return tool_result_t::error(OBFSTR("Refusing to attach kernel driver to IDA host process name."));

    std::uint32_t pid = device->find_process(process_name.c_str());
    if (pid == 0)
        return tool_result_t::error(OBFSTR("Process not found: ") + process_name);

    if (anti_re::is_self_target_pid(pid))
    {
        device->clear_process_context();
        return tool_result_t::error(OBFSTR("Refusing to attach kernel driver to current IDA host process PID."));
    }

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

tool_result_t driver_unattach(const json&)
{
    if (!device->is_connected())
        return tool_result_t::error(OBFSTR("Driver not connected. Call driver_connect first."));

    const std::uint32_t previous_pid = device->get_process_id();
    const std::uint64_t previous_base = device->get_base_address();
    const std::uint64_t previous_dtb = device->get_dtb();

    device->clear_process_context();

    json result;
    result["previous_process_id"] = previous_pid;
    result["previous_base_address"] = helpers::format_address(static_cast<ea_t>(previous_base));
    result["previous_dtb"] = helpers::format_address(static_cast<ea_t>(previous_dtb));
    result["connected"] = device->is_connected();
    result["process_id"] = device->get_process_id();
    result["base_address"] = helpers::format_address(device->get_base_address());
    result["dtb"] = helpers::format_address(device->get_dtb());
    result["kernel_dtb"] = helpers::format_address(device->get_kernel_dtb());

    if (previous_pid == 0)
        return tool_result_t::ok(OBFSTR("No process was attached. Driver connection remains active."), result);

    return tool_result_t::ok(OBFSTR("Detached from attached process context. Driver connection remains active."), result);
}

tool_result_t driver_read_memory(const json& params)
{
    if (auto ctx_err = ensure_attached_process_context(params))
        return *ctx_err;

    auto ea_opt = helpers::parse_address(params["address"].get<std::string>());
    if (!ea_opt)
        return tool_result_t::error(OBFSTR("Invalid address"));

    std::size_t size = params.value("size", 256);
    if (size > 65536)
        return tool_result_t::error(OBFSTR("Size too large (max 65536)"));

    anti_re::guard_driver_self_access(device->get_process_id(), *ea_opt, size);

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
    if (auto ctx_err = ensure_attached_process_context(params))
        return *ctx_err;

    auto ea_opt = helpers::parse_address(params["address"].get<std::string>());
    if (!ea_opt)
        return tool_result_t::error(OBFSTR("Invalid address"));

    anti_re::guard_driver_self_access(device->get_process_id(), *ea_opt, 1);

    std::vector<std::uint8_t> bytes;
    std::string parse_error;
    if (!parse_byte_sequence(params["bytes"], bytes, parse_error))
    {
        return tool_result_t::error(
            OBFSTR("Invalid bytes format. Use one of: 'DE AD BE EF', 'DEADBEEF', [222,173,190,239], ['DE','AD',...]. Detail: ") +
            parse_error);
    }

    std::size_t written = device->write_raw(*ea_opt, bytes.data(), bytes.size());
    if (written == 0)
        return tool_result_t::error(OBFSTR("Kernel write failed at ") + helpers::format_address(*ea_opt));

    json result;
    result["address"]       = helpers::format_address(*ea_opt);
    result["bytes_written"] = written;
    result["requested"]     = bytes.size();
    return tool_result_t::ok(OBFSTR("Kernel write: ") + std::to_string(written) + " bytes", result);
}


struct vad_dump_plan_t
{
    std::uint64_t module_base = 0;
    std::uint64_t pe_size_of_image = 0;
    std::uint64_t total_span = 0;
    std::uint64_t total_committed_bytes = 0;
    int committed_region_count = 0;
    bool used_vad = false;

    struct region_t
    {
        std::uint64_t offset;
        std::uint64_t size;
        std::uint32_t protect;
    };
    std::vector<region_t> regions;
};


static std::vector<voyager::detail::region_entry> enumerate_all_memory_regions_paginated(
    voyager::device_t* dev,
    std::uint64_t start,
    std::uint64_t end_addr,
    bool include_all)
{


    std::vector<voyager::detail::region_entry> all_regions;
    std::uint64_t current_start = start;
    constexpr int MAX_PAGINATION_ROUNDS = 256;

    for (int round = 0; round < MAX_PAGINATION_ROUNDS; round++)
    {
        if (current_start >= end_addr)
            break;

        auto batch = dev->enumerate_memory_regions(current_start, end_addr, include_all);
        if (batch.empty())
            break;

        std::uint64_t batch_max_end = 0;
        for (const auto& r : batch)
        {
            all_regions.push_back(r);
            std::uint64_t rend = r.base + r.size;
            if (rend > batch_max_end)
                batch_max_end = rend;
        }


        if (batch.size() < voyager::detail::MAX_ENUM_REGIONS)
            break;


        if (batch_max_end <= current_start)
            break;
        current_start = batch_max_end;
    }

    return all_regions;
}

static std::uint64_t get_ldr_module_size(voyager::device_t* dev, std::uint64_t module_base)
{


    struct ldr_module_info_t
    {
        std::uint64_t base = 0;
        std::uint64_t entry_point = 0;
        std::uint32_t size = 0;
        std::string name;
        std::string path;
    };

    auto to_lower_ascii = [](std::string value) {
        std::transform(value.begin(), value.end(), value.begin(),
            [](unsigned char ch) { return static_cast<char>(std::tolower(ch)); });
        return value;
    };

    auto read_remote_unicode_ascii = [](voyager::device_t* device,
                                        std::uint64_t ptr,
                                        std::uint16_t byte_len,
                                        std::uint16_t max_len) -> std::string {
        if (device == nullptr || ptr == 0 || byte_len == 0 || byte_len > max_len)
            return {};

        std::vector<std::uint8_t> raw(byte_len, 0);
        if (device->read_raw(ptr, raw.data(), byte_len) == 0)
            return {};

        std::string text;
        text.reserve(byte_len / 2);
        for (std::size_t i = 0; i + 1 < raw.size(); i += 2)
        {
            std::uint16_t wc = raw[i] | (static_cast<std::uint16_t>(raw[i + 1]) << 8);
            if (wc == 0)
                break;
            text += (wc < 128 && wc >= 32) ? static_cast<char>(wc) : '?';
        }
        return text;
    };

    auto visit_ldr_modules = [&](const std::function<bool(const ldr_module_info_t&)>& visitor) -> bool {
        if (!dev || !dev->is_connected() || dev->get_process_id() == 0)
            return false;

        voyager::device_t::peb_info peb{};
        if (!dev->read_peb(peb) || peb.ldr_address == 0)
            return false;

        std::uint64_t list_head = peb.ldr_address + 0x10;
        std::uint64_t first_entry = dev->read<std::uint64_t>(list_head);
        if (first_entry == 0 || first_entry == list_head)
            return false;

        std::uint64_t current = first_entry;
        int max_iter = 1024;

        while (current != list_head && current != 0 && max_iter-- > 0)
        {
            ldr_module_info_t info;
            info.base        = dev->read<std::uint64_t>(current + 0x30);
            info.entry_point = dev->read<std::uint64_t>(current + 0x38);
            info.size        = dev->read<std::uint32_t>(current + 0x40);
            info.path        = read_remote_unicode_ascii(
                dev,
                dev->read<std::uint64_t>(current + 0x50),
                dev->read<std::uint16_t>(current + 0x48),
                1024);
            info.name        = read_remote_unicode_ascii(
                dev,
                dev->read<std::uint64_t>(current + 0x60),
                dev->read<std::uint16_t>(current + 0x58),
                520);

            if (info.base != 0 && !info.name.empty() && visitor(info))
                return true;

            std::uint64_t next = dev->read<std::uint64_t>(current);
            if (next == current)
                break;
            current = next;
        }

        return true;
    };

    ldr_module_info_t found;
    bool matched = false;
    visit_ldr_modules([&](const ldr_module_info_t& info) {
        if (info.base != module_base)
            return false;
        found = info;
        matched = true;
        return true;
    });
    return matched ? static_cast<std::uint64_t>(found.size) : 0;
}

static void cleanup_exception_directory(
    std::vector<std::uint8_t>& image,
    bool is_pe64)
{


    if (image.size() < 0x200 || !is_pe64)
        return;

    std::uint32_t pe_off = *reinterpret_cast<std::uint32_t*>(&image[0x3C]);
    std::uint32_t opt_off = pe_off + 24;


    std::uint32_t dd_base = opt_off + 112;
    std::uint32_t exc_dir_off = dd_base + 3 * 8;
    if (exc_dir_off + 8 > static_cast<std::uint32_t>(image.size()))
        return;

    std::uint32_t exc_rva  = *reinterpret_cast<std::uint32_t*>(&image[exc_dir_off]);
    std::uint32_t exc_size = *reinterpret_cast<std::uint32_t*>(&image[exc_dir_off + 4]);

    if (exc_rva == 0 || exc_size == 0)
        return;
    if (exc_rva >= static_cast<std::uint32_t>(image.size()))
        return;


    constexpr std::uint32_t RTFUNC_SIZE = 12;
    std::uint32_t image_size = static_cast<std::uint32_t>(image.size());
    int cleaned = 0;

    for (std::uint32_t off = exc_rva; off + RTFUNC_SIZE <= exc_rva + exc_size && off + RTFUNC_SIZE <= image_size; off += RTFUNC_SIZE)
    {
        std::uint32_t begin_addr   = *reinterpret_cast<std::uint32_t*>(&image[off]);
        std::uint32_t end_addr     = *reinterpret_cast<std::uint32_t*>(&image[off + 4]);
        std::uint32_t unwind_addr  = *reinterpret_cast<std::uint32_t*>(&image[off + 8]);

        if (begin_addr == 0 && end_addr == 0 && unwind_addr == 0)
            continue;

        bool valid = true;


        if (begin_addr >= image_size || end_addr >= image_size)
            valid = false;
        if (begin_addr >= end_addr)
            valid = false;
        if (unwind_addr >= image_size)
            valid = false;


        if (valid && unwind_addr > 0 && unwind_addr < image_size)
        {
            std::uint8_t version = image[unwind_addr] & 0x07;
            if (version != 1 && version != 2)
                valid = false;
        }

        if (!valid)
        {
            std::memset(&image[off], 0, RTFUNC_SIZE);
            cleaned++;
        }
    }

    if (cleaned > 0)
        msg(OBFSTR_C("AiDA: Cleaned %d invalid runtime function entries from exception directory\n"), cleaned);
}


static std::string get_ldr_module_file_path(
    voyager::device_t* dev,
    std::uint64_t module_base)
{
    return {};
}


static int try_fill_from_disk_pe(
    std::vector<std::uint8_t>& image,
    const std::vector<std::size_t>& failed_offsets,
    const std::string& disk_path,
    nlohmann::json& steps_log)
{
    if (disk_path.empty() || failed_offsets.empty())
        return 0;

    HANDLE hFile = CreateFileA(disk_path.c_str(), GENERIC_READ,
        FILE_SHARE_READ | FILE_SHARE_DELETE, nullptr,
        OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (hFile == INVALID_HANDLE_VALUE)
        return 0;

    LARGE_INTEGER file_size_li;
    if (!GetFileSizeEx(hFile, &file_size_li) || file_size_li.QuadPart < 0x100)
    {
        CloseHandle(hFile);
        return 0;
    }


    std::vector<std::uint8_t> disk_hdr(std::min<std::size_t>(
        static_cast<std::size_t>(file_size_li.QuadPart), 0x1000), 0);
    DWORD hdr_read = 0;
    if (!ReadFile(hFile, disk_hdr.data(), static_cast<DWORD>(disk_hdr.size()), &hdr_read, nullptr) ||
        hdr_read < 0x100 || disk_hdr[0] != 'M' || disk_hdr[1] != 'Z')
    {
        CloseHandle(hFile);
        return 0;
    }

    std::uint32_t pe_off = *reinterpret_cast<std::uint32_t*>(&disk_hdr[0x3C]);
    if (pe_off + 0x18 >= hdr_read || disk_hdr[pe_off] != 'P' || disk_hdr[pe_off + 1] != 'E')
    {
        CloseHandle(hFile);
        return 0;
    }

    std::uint16_t num_sections = *reinterpret_cast<std::uint16_t*>(&disk_hdr[pe_off + 6]);
    std::uint16_t opt_size = *reinterpret_cast<std::uint16_t*>(&disk_hdr[pe_off + 0x14]);
    std::uint32_t sec_table = pe_off + 0x18 + opt_size;


    struct sec_map_t {
        std::uint32_t rva;
        std::uint32_t vsize;
        std::uint32_t raw_offset;
        std::uint32_t raw_size;
    };
    std::vector<sec_map_t> sec_map;
    for (int i = 0; i < num_sections && i < 96; i++)
    {
        std::uint32_t soff = sec_table + i * 40;
        if (soff + 40 > hdr_read) break;
        sec_map_t sm;
        sm.vsize      = *reinterpret_cast<std::uint32_t*>(&disk_hdr[soff + 8]);
        sm.rva        = *reinterpret_cast<std::uint32_t*>(&disk_hdr[soff + 12]);
        sm.raw_size   = *reinterpret_cast<std::uint32_t*>(&disk_hdr[soff + 16]);
        sm.raw_offset = *reinterpret_cast<std::uint32_t*>(&disk_hdr[soff + 20]);
        if (sm.rva > 0 && sm.raw_size > 0 && sm.raw_offset > 0)
            sec_map.push_back(sm);
    }

    constexpr std::size_t PAGE_SIZE = 0x1000;
    int recovered = 0;

    for (std::size_t pg_off : failed_offsets)
    {
        if (pg_off >= image.size()) continue;
        std::size_t pg_sz = std::min(PAGE_SIZE, image.size() - pg_off);


        bool has_data = false;
        for (std::size_t i = 0; i < pg_sz; i++)
        {
            if (image[pg_off + i] != 0) { has_data = true; break; }
        }
        if (has_data) continue;


        for (const auto& sm : sec_map)
        {
            if (pg_off >= sm.rva && pg_off < sm.rva + sm.vsize)
            {
                std::uint32_t offset_in_sec = static_cast<std::uint32_t>(pg_off - sm.rva);
                if (offset_in_sec < sm.raw_size)
                {
                    std::uint32_t file_offset = sm.raw_offset + offset_in_sec;
                    std::uint32_t copy_size = std::min<std::uint32_t>(
                        static_cast<std::uint32_t>(pg_sz),
                        sm.raw_size - offset_in_sec);

                    LARGE_INTEGER seek_pos;
                    seek_pos.QuadPart = file_offset;
                    if (SetFilePointerEx(hFile, seek_pos, nullptr, FILE_BEGIN))
                    {
                        DWORD rd = 0;
                        if (ReadFile(hFile, image.data() + pg_off, copy_size, &rd, nullptr) && rd > 0)
                            recovered++;
                    }
                }
                break;
            }
        }
    }

    CloseHandle(hFile);

    if (recovered > 0)
    {
        steps_log.push_back({{"step", "disk_fallback"}, {"ok", true},
            {"detail", std::to_string(recovered) + " pages recovered from on-disk PE: " + disk_path}});
        msg(OBFSTR_C("AiDA: Disk fallback recovered %d pages from %s\n"),
            recovered, disk_path.c_str());
    }

    return recovered;
}


static vad_dump_plan_t build_vad_dump_plan(
    voyager::device_t* dev,
    std::uint64_t module_base,
    std::uint64_t pe_size_of_image,
    nlohmann::json& steps_log)
{
    qnotused(dev);

    vad_dump_plan_t plan;
    plan.module_base = module_base;
    plan.pe_size_of_image = pe_size_of_image;
    plan.total_span = pe_size_of_image;

    if (plan.total_span == 0)
        plan.total_span = 0x1000;

    plan.regions.push_back({0, plan.total_span, 0});
    plan.total_committed_bytes = plan.total_span;
    plan.committed_region_count = 1;
    plan.used_vad = false;

    std::ostringstream detail_ss;
    detail_ss << "raw runtime snapshot over exact module span 0x"
              << std::hex << std::uppercase << plan.total_span
              << " (" << std::dec << (plan.total_span / (1024 * 1024)) << " MB)"
              << ", 1 region, no VAD expansion or reconstruction";

    steps_log.push_back({{"step", "module_range"}, {"ok", true}, {"detail", detail_ss.str()}});

    return plan;
}


static double calculate_page_entropy(const std::uint8_t* data, std::size_t size)
{
    if (size == 0) return 0.0;
    std::uint32_t freq[256] = {};
    for (std::size_t i = 0; i < size; i++)
        freq[data[i]]++;
    double entropy = 0.0;
    double inv_size = 1.0 / static_cast<double>(size);
    for (int i = 0; i < 256; i++)
    {
        if (freq[i] == 0) continue;
        double p = static_cast<double>(freq[i]) * inv_size;
        entropy -= p * std::log2(p);
    }
    return entropy;
}


struct protection_analysis_t
{
    bool is_packed = false;
    bool is_vmprotected = false;
    bool is_themida = false;
    bool is_upx = false;
    bool has_encrypted_sections = false;
    bool header_was_wiped = false;
    int zero_code_pages = 0;
    int high_entropy_pages = 0;
    int total_code_pages = 0;
    int encrypted_section_count = 0;
    double avg_code_entropy = 0.0;
    std::vector<std::string> detected_protections;
};


static protection_analysis_t analyze_module_protection(
    voyager::device_t* dev,
    std::uint64_t base,
    const std::uint8_t* pe_hdr,
    std::size_t hdr_read,
    bool has_valid_pe,
    bool header_wiped,
    std::uint32_t pe_off,
    std::uint16_t sections_count,
    std::uint32_t sec_table_off,
    std::uint32_t image_size,
    bool is_kernel,
    nlohmann::json& steps)
{
    protection_analysis_t result;
    result.header_was_wiped = header_wiped;

    if (header_wiped)
        result.detected_protections.push_back(OBFSTR("Header wiped (anti-dump/anti-cheat)"));

    if (!has_valid_pe || hdr_read < 0x200)
    {
        steps.push_back({{"step", "dynamic_analysis"}, {"ok", true},
            {"detail", "PE header invalid/wiped — skipping detailed analysis, will use aggressive dump strategy"}});
        return result;
    }

    for (int si = 0; si < sections_count && si < 96; si++)
    {
        std::uint32_t soff = sec_table_off + si * 40;
        if (soff + 40 > static_cast<std::uint32_t>(hdr_read)) break;

        char sec_name[9] = {};
        std::memcpy(sec_name, pe_hdr + soff, 8);

        if (std::strstr(sec_name, ".vmp") || std::strstr(sec_name, "VMPr") ||
            std::strstr(sec_name, ".VMP"))
        {
            result.is_vmprotected = true;
            result.is_packed = true;
            result.detected_protections.push_back(
                OBFSTR("VMProtect (section: ") + std::string(sec_name) + ")");
        }
        else if (std::strstr(sec_name, ".them") || std::strstr(sec_name, ".winl") ||
                 std::strcmp(sec_name, ".boot") == 0)
        {
            result.is_themida = true;
            result.is_packed = true;
            result.detected_protections.push_back(
                OBFSTR("Themida/WinLicense (section: ") + std::string(sec_name) + ")");
        }
        else if (std::strcmp(sec_name, "UPX0") == 0 || std::strcmp(sec_name, "UPX1") == 0 ||
                 std::strcmp(sec_name, "UPX2") == 0 || std::strcmp(sec_name, ".UPX0") == 0)
        {
            result.is_upx = true;
            result.is_packed = true;
            result.detected_protections.push_back(
                OBFSTR("UPX (section: ") + std::string(sec_name) + ")");
        }
    }

    double total_entropy = 0.0;
    int entropy_pages = 0;
    constexpr std::size_t ENTROPY_PAGE = 0x1000;

    for (int si = 0; si < sections_count && si < 96; si++)
    {
        std::uint32_t soff = sec_table_off + si * 40;
        if (soff + 40 > static_cast<std::uint32_t>(hdr_read)) break;

        std::uint32_t vsize = *reinterpret_cast<const std::uint32_t*>(pe_hdr + soff + 8);
        std::uint32_t vrva  = *reinterpret_cast<const std::uint32_t*>(pe_hdr + soff + 12);
        std::uint32_t chars = *reinterpret_cast<const std::uint32_t*>(pe_hdr + soff + 36);

        if (vsize == 0 || vrva == 0) continue;
        if (!(chars & 0x20) && !(chars & 0x20000000)) continue;

        std::uint32_t max_sample_pages = std::min<std::uint32_t>(vsize / static_cast<std::uint32_t>(ENTROPY_PAGE), 64);
        if (max_sample_pages == 0) max_sample_pages = 1;
        std::vector<std::uint8_t> page_buf(ENTROPY_PAGE);

        int sec_zero_pages = 0;
        int sec_high_entropy_pages = 0;
        int sec_total_pages = 0;

        for (std::uint32_t pi = 0; pi < max_sample_pages; pi++)
        {
            std::uint64_t pg_addr = base + vrva + pi * ENTROPY_PAGE;
            if (vrva + pi * ENTROPY_PAGE + ENTROPY_PAGE > image_size) break;

            std::memset(page_buf.data(), 0, ENTROPY_PAGE);
            std::size_t got = is_kernel
                ? dev->read_kernel_raw(pg_addr, page_buf.data(), ENTROPY_PAGE)
                : dev->read_raw(pg_addr, page_buf.data(), ENTROPY_PAGE);
            result.total_code_pages++;
            sec_total_pages++;

            if (got < ENTROPY_PAGE)
            {
                result.zero_code_pages++;
                sec_zero_pages++;
                continue;
            }

            bool is_empty = true;
            for (std::size_t i = 0; i < ENTROPY_PAGE; i++)
            {
                if (page_buf[i] != 0x00 && page_buf[i] != 0xCC)
                {
                    is_empty = false;
                    break;
                }
            }

            if (is_empty)
            {
                result.zero_code_pages++;
                sec_zero_pages++;
                continue;
            }

            double ent = calculate_page_entropy(page_buf.data(), ENTROPY_PAGE);
            total_entropy += ent;
            entropy_pages++;

            if (ent > 7.0)
            {
                result.high_entropy_pages++;
                sec_high_entropy_pages++;
            }
        }

        if (sec_total_pages > 0 &&
            (sec_zero_pages == sec_total_pages ||
             sec_high_entropy_pages > sec_total_pages / 2))
        {
            result.encrypted_section_count++;
        }
    }

    if (entropy_pages > 0)
        result.avg_code_entropy = total_entropy / entropy_pages;

    if (result.zero_code_pages > 0)
    {
        result.has_encrypted_sections = true;
        result.detected_protections.push_back(
            OBFSTR("Encrypted/guarded code sections (") + std::to_string(result.zero_code_pages) +
            "/" + std::to_string(result.total_code_pages) + OBFSTR(" pages empty)"));
    }

    if (result.high_entropy_pages > entropy_pages / 2 && entropy_pages > 4)
    {
        result.has_encrypted_sections = true;
        std::ostringstream ent_ss;
        ent_ss << std::fixed << std::setprecision(2) << result.avg_code_entropy;
        result.detected_protections.push_back(
            OBFSTR("High entropy code (") + std::to_string(result.high_entropy_pages) +
            "/" + std::to_string(entropy_pages) + OBFSTR(" pages >7.0 bits, avg=") +
            ent_ss.str() + ")");
    }

    std::string detail;
    if (result.detected_protections.empty())
    {
        std::ostringstream ent_ss;
        ent_ss << std::fixed << std::setprecision(2) << result.avg_code_entropy;
        detail = OBFSTR("No known protections detected, avg code entropy = ") + ent_ss.str();
    }
    else
    {
        detail = OBFSTR("Detected: ");
        for (std::size_t i = 0; i < result.detected_protections.size(); i++)
        {
            if (i > 0) detail += "; ";
            detail += result.detected_protections[i];
        }
    }

    steps.push_back({{"step", "dynamic_analysis"}, {"ok", true}, {"detail", detail}});
    msg(OBFSTR_C("AiDA: Pre-dump dynamic analysis — %s\n"), detail.c_str());

    return result;
}


static int force_decrypt_via_shellcode(
    voyager::device_t* dev,
    std::uint64_t base,
    const std::uint8_t* pe_hdr,
    std::size_t hdr_read,
    bool has_valid_pe,
    std::uint32_t pe_off,
    std::uint16_t sections_count,
    std::uint32_t sec_table_off,
    std::uint32_t image_size,
    nlohmann::json& steps)
{
    if (!dev || !dev->is_connected() || dev->get_process_id() == 0)
        return 0;


    struct page_range_t { std::uint64_t start; std::uint64_t end; };
    std::vector<page_range_t> code_ranges;

    if (has_valid_pe)
    {
        for (int si = 0; si < sections_count && si < 96; si++)
        {
            std::uint32_t soff = sec_table_off + si * 40;
            if (soff + 40 > static_cast<std::uint32_t>(hdr_read)) break;
            std::uint32_t vsize = *reinterpret_cast<const std::uint32_t*>(pe_hdr + soff + 8);
            std::uint32_t vrva  = *reinterpret_cast<const std::uint32_t*>(pe_hdr + soff + 12);
            std::uint32_t chars = *reinterpret_cast<const std::uint32_t*>(pe_hdr + soff + 36);
            if (vsize == 0 || vrva == 0) continue;

            if (chars & (0x20000000 | 0x00000020))
            {
                std::uint64_t sec_start = base + vrva;
                std::uint64_t sec_end = sec_start + std::min<std::uint64_t>(vsize,
                    (vrva < image_size) ? (image_size - vrva) : 0);
                if (sec_end > sec_start)
                    code_ranges.push_back({sec_start, sec_end});
            }
        }
    }
    else
    {

        code_ranges.push_back({base, base + image_size});
    }

    if (code_ranges.empty())
        return 0;


    constexpr std::uint32_t VMEM_COMMIT = 0x1000;
    constexpr std::uint32_t PROT_NOACCESS = 0x01;

    auto all_regions = enumerate_all_memory_regions_paginated(dev, base, base + image_size, true);

    std::vector<std::uint64_t> noaccess_pages;
    for (const auto& r : all_regions)
    {
        if (!(r.state & VMEM_COMMIT) || r.protect != PROT_NOACCESS)
            continue;


        for (const auto& cr : code_ranges)
        {
            std::uint64_t overlap_start = std::max(r.base, cr.start);
            std::uint64_t overlap_end = std::min(r.base + r.size, cr.end);
            if (overlap_start >= overlap_end) continue;


            for (std::uint64_t addr = overlap_start & ~0xFFFULL; addr < overlap_end; addr += 0x1000)
            {
                if (addr >= cr.start && addr < cr.end)
                    noaccess_pages.push_back(addr);
            }
        }
    }

    if (noaccess_pages.empty())
    {


        static const std::uint8_t touch_sc[] = {
            0x53,
            0x56,
            0x57,
            0x48, 0x89, 0xCB,
            0x48, 0x89, 0xD6,
            0x31, 0xFF,

            0x48, 0x39, 0xF7,
            0x7D, 0x0F,
            0x0F, 0xB6, 0x03,
            0x48, 0x81, 0xC3, 0x00, 0x10, 0x00, 0x00,
            0x48, 0xFF, 0xC7,
            0xEB, 0xEC,

            0x48, 0x89, 0xF8,
            0x5F,
            0x5E,
            0x5B,
            0xC3
        };

        std::uint64_t sc_mem = dev->allocate_memory(0x1000);
        if (sc_mem == 0) return 0;

        dev->write_raw(sc_mem, touch_sc, sizeof(touch_sc));

        int total_touched = 0;
        for (const auto& cr : code_ranges)
        {
            std::uint64_t page_count = (cr.end - cr.start + 0xFFF) / 0x1000;
            std::uint64_t ret = dev->call_function(sc_mem, cr.start, page_count, 0, 0);
            total_touched += static_cast<int>(ret);
        }

        dev->free_memory(sc_mem);

        if (total_touched > 0)
        {
            Sleep(100);
            steps.push_back({{"step", "decrypt_shellcode"}, {"ok", true},
                {"detail", std::to_string(total_touched) +
                    " code pages touched via usermode fault-trigger (no NOACCESS regions detected, full sweep)"}});
            msg(OBFSTR_C("AiDA: Shellcode touched %d code pages (full sweep, no NOACCESS pages found)\n"),
                total_touched);
        }
        return total_touched;
    }


    std::size_t addr_list_size = noaccess_pages.size() * sizeof(std::uint64_t);
    std::size_t alloc_size = 0x1000 + ((addr_list_size + 0xFFF) & ~0xFFFULL);
    if (alloc_size > 0x1000000) alloc_size = 0x1000000;

    std::uint64_t sc_mem = dev->allocate_memory(alloc_size);
    if (sc_mem == 0)
    {
        steps.push_back({{"step", "decrypt_shellcode"}, {"ok", false},
            {"detail", "Failed to allocate shellcode memory in target process"}});
        return 0;
    }


    static const std::uint8_t list_sc[] = {
        0x53,
        0x56,
        0x57,
        0x48, 0x89, 0xCB,
        0x48, 0x89, 0xD6,
        0x31, 0xFF,

        0x48, 0x39, 0xF7,
        0x7D, 0x0C,
        0x48, 0x8B, 0x0C, 0xFB,
        0x0F, 0xB6, 0x01,
        0x48, 0xFF, 0xC7,
        0xEB, 0xEF,

        0x48, 0x89, 0xF8,
        0x5F,
        0x5E,
        0x5B,
        0xC3
    };


    dev->write_raw(sc_mem, list_sc, sizeof(list_sc));


    std::uint64_t addr_list_base = sc_mem + 0x100;
    std::size_t max_entries = (alloc_size - 0x100) / sizeof(std::uint64_t);
    std::size_t entries = std::min(noaccess_pages.size(), max_entries);

    dev->write_raw(addr_list_base, noaccess_pages.data(),
        entries * sizeof(std::uint64_t));

    msg(OBFSTR_C("AiDA: Injecting decrypt shellcode — %zu NOACCESS code pages to trigger...\n"),
        entries);


    std::uint64_t ret = dev->call_function(sc_mem, addr_list_base, entries, 0, 0);

    dev->free_memory(sc_mem);

    int pages_decrypted = static_cast<int>(ret);

    if (pages_decrypted > 0)
        Sleep(100);

    steps.push_back({{"step", "decrypt_shellcode"}, {"ok", pages_decrypted > 0},
        {"detail", std::to_string(pages_decrypted) + "/" + std::to_string(entries) +
            " NOACCESS code pages triggered via usermode exception-based decryption"}});
    msg(OBFSTR_C("AiDA: Shellcode decryption complete — %d/%zu pages triggered\n"),
        pages_decrypted, entries);

    return pages_decrypted;
}


static int force_code_pages_in_memory(
    voyager::device_t* dev,
    std::uint64_t base,
    const std::uint8_t* pe_hdr,
    std::size_t hdr_read,
    bool has_valid_pe,
    std::uint32_t pe_off,
    std::uint16_t sections_count,
    std::uint32_t sec_table_off,
    std::uint32_t image_size,
    nlohmann::json& steps)
{
    if (!has_valid_pe || !dev || !dev->is_connected() || dev->get_process_id() == 0)
        return 0;

    auto modules = enumerate_ldr_modules_for_iat(dev);

    std::uint64_t kernel32_base = 0;
    for (const auto& m : modules)
    {
        std::string lower = m.name;
        std::transform(lower.begin(), lower.end(), lower.begin(),
            [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
        if (lower == "kernel32.dll")
        {
            kernel32_base = m.base;
            break;
        }
    }

    if (kernel32_base == 0)
    {
        steps.push_back({{"step", "force_page_in"}, {"ok", false},
            {"detail", "kernel32.dll not found in target — skipping active page forcing"}});
        return 0;
    }

    std::uint64_t vp_addr = dev->resolve_export(kernel32_base, "VirtualProtect");
    if (vp_addr == 0)
    {
        steps.push_back({{"step", "force_page_in"}, {"ok", false},
            {"detail", "Could not resolve VirtualProtect — skipping active page forcing"}});
        return 0;
    }

    std::uint64_t old_prot_buf = dev->allocate_memory(0x1000);
    if (old_prot_buf == 0)
    {
        steps.push_back({{"step", "force_page_in"}, {"ok", false},
            {"detail", "Could not allocate scratch buffer — skipping active page forcing"}});
        return 0;
    }

    int pages_forced = 0;
    constexpr std::uint32_t kPageExecReadWrite = 0x40;
    constexpr std::uint64_t VP_CHUNK = 0x10000;

    for (int si = 0; si < sections_count && si < 96; si++)
    {
        std::uint32_t soff = sec_table_off + si * 40;
        if (soff + 40 > static_cast<std::uint32_t>(hdr_read)) break;

        std::uint32_t vsize = *reinterpret_cast<const std::uint32_t*>(pe_hdr + soff + 8);
        std::uint32_t vrva  = *reinterpret_cast<const std::uint32_t*>(pe_hdr + soff + 12);
        std::uint32_t chars = *reinterpret_cast<const std::uint32_t*>(pe_hdr + soff + 36);

        if (vsize == 0 || vrva == 0 || !(chars & 0x20000000)) continue;

        std::uint64_t sec_addr = base + vrva;
        std::uint64_t sec_size = std::min<std::uint64_t>(vsize,
            (vrva < image_size) ? (image_size - vrva) : 0);
        if (sec_size == 0) continue;

        for (std::uint64_t off = 0; off < sec_size; off += VP_CHUNK)
        {
            std::uint64_t chunk_size = std::min(VP_CHUNK, sec_size - off);
            std::uint64_t ret = dev->call_function(vp_addr,
                sec_addr + off,
                chunk_size,
                kPageExecReadWrite,
                old_prot_buf);

            if (ret != 0)
                pages_forced += static_cast<int>(chunk_size / 0x1000);
        }
    }

    dev->free_memory(old_prot_buf);

    if (pages_forced > 0)
    {
        Sleep(150);

        steps.push_back({{"step", "force_page_in"}, {"ok", true},
            {"detail", std::to_string(pages_forced) +
                " code pages forced via VirtualProtect to trigger decryption/COW"}});
        msg(OBFSTR_C("AiDA: Forced %d code pages into memory via VirtualProtect\n"), pages_forced);
    }
    else
    {
        steps.push_back({{"step", "force_page_in"}, {"ok", false},
            {"detail", "VirtualProtect calls returned 0 — anti-cheat may have blocked protection changes"}});
    }

    return pages_forced;
}


tool_result_t driver_dump_module(const json& params)
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
            return tool_result_t::error(OBFSTR("Failed to connect to kernel driver. Is the driver loaded?"));
    }
    else
        log("connect_driver", true, "Already connected");

    if (params.contains("process"))
    {
        std::string process_name = params["process"].get<std::string>();
        if (is_ida_host_process_name(process_name))
            return tool_result_t::error(OBFSTR("Refusing to attach dump context to IDA host process name."));

        std::uint32_t pid = device->find_process(process_name.c_str());
        log("find_process", pid != 0, "PID: " + (pid ? std::to_string(pid) : "not found"));
        if (pid == 0)
            return tool_result_t::error(OBFSTR("Process not found: ") + process_name);

        if (anti_re::is_self_target_pid(pid))
        {
            device->clear_process_context();
            return tool_result_t::error(OBFSTR("Refusing to dump from current IDA host process PID."));
        }
    }

    if (device->get_process_id() == 0)
        return tool_result_t::error(OBFSTR("No process attached. Provide 'process' param or call driver_attach first."));

    if (device->get_dtb() == 0)
        device->solve_dtb();
    std::uint64_t dtb = device->get_dtb();
    log("solve_dtb", dtb != 0, helpers::format_address(dtb));

    struct resolved_module_t
    {
        std::uint64_t base = 0;
        std::uint64_t entry_point = 0;
        std::uint32_t size = 0;
        std::string name;
        std::string path;
    };

    auto to_lower_ascii = [](std::string value) {
        std::transform(value.begin(), value.end(), value.begin(),
            [](unsigned char ch) { return static_cast<char>(std::tolower(ch)); });
        return value;
    };

    auto basename_of_path = [](const std::string& path) {
        std::string::size_type pos = path.find_last_of("\\/");
        return pos == std::string::npos ? path : path.substr(pos + 1);
    };

    auto read_remote_unicode_ascii = [](voyager::device_t* dev,
                                        std::uint64_t ptr,
                                        std::uint16_t byte_len,
                                        std::uint16_t max_len) -> std::string {
        if (dev == nullptr || ptr == 0 || byte_len == 0 || byte_len > max_len)
            return {};

        std::vector<std::uint8_t> raw(byte_len, 0);
        if (dev->read_raw(ptr, raw.data(), byte_len) == 0)
            return {};

        std::string text;
        text.reserve(byte_len / 2);
        for (std::size_t i = 0; i + 1 < raw.size(); i += 2)
        {
            std::uint16_t wc = raw[i] | (static_cast<std::uint16_t>(raw[i + 1]) << 8);
            if (wc == 0)
                break;
            text += (wc < 128 && wc >= 32) ? static_cast<char>(wc) : '?';
        }
        return text;
    };

    auto visit_ldr_modules = [&](const std::function<bool(const resolved_module_t&)>& visitor) -> bool {
        voyager::device_t::peb_info peb{};
        if (!device->read_peb(peb) || peb.ldr_address == 0)
            return false;

        std::uint64_t list_head = peb.ldr_address + 0x10;
        std::uint64_t first_entry = device->read<std::uint64_t>(list_head);
        if (first_entry == 0 || first_entry == list_head)
            return false;

        std::uint64_t current = first_entry;
        int max_iter = 1024;

        while (current != list_head && current != 0 && max_iter-- > 0)
        {
            resolved_module_t info;
            info.base        = device->read<std::uint64_t>(current + 0x30);
            info.entry_point = device->read<std::uint64_t>(current + 0x38);
            info.size        = device->read<std::uint32_t>(current + 0x40);
            info.path        = read_remote_unicode_ascii(
                device.get(),
                device->read<std::uint64_t>(current + 0x50),
                device->read<std::uint16_t>(current + 0x48),
                1024);
            info.name        = read_remote_unicode_ascii(
                device.get(),
                device->read<std::uint64_t>(current + 0x60),
                device->read<std::uint16_t>(current + 0x58),
                520);

            if (info.base != 0 && !info.name.empty() && visitor(info))
                return true;

            std::uint64_t next = device->read<std::uint64_t>(current);
            if (next == current || next == 0)
                break;
            current = next;
        }

        return true;
    };

    auto find_ldr_module_by_base = [&](std::uint64_t module_base, resolved_module_t* out) {
        bool found = false;
        visit_ldr_modules([&](const resolved_module_t& info) {
            if (info.base != module_base)
                return false;
            if (out != nullptr)
                *out = info;
            found = true;
            return true;
        });
        return found;
    };

    auto find_ldr_module_by_query = [&](const std::string& query, resolved_module_t* out) {
        if (query.empty())
            return false;

        const std::string needle = to_lower_ascii(query);
        bool exact_found = false;
        bool partial_found = false;
        resolved_module_t exact_match;
        resolved_module_t partial_match;

        visit_ldr_modules([&](const resolved_module_t& info) {
            const std::string lower_name = to_lower_ascii(info.name);
            const std::string lower_path = to_lower_ascii(info.path);
            const std::string lower_file = to_lower_ascii(basename_of_path(info.path));
            const bool exact = lower_name == needle || lower_path == needle || lower_file == needle;
            const bool partial = !exact && (
                lower_name.find(needle) != std::string::npos ||
                lower_path.find(needle) != std::string::npos ||
                lower_file.find(needle) != std::string::npos);

            if (exact)
            {
                exact_match = info;
                exact_found = true;
                return true;
            }
            if (!partial_found && partial)
            {
                partial_match = info;
                partial_found = true;
            }
            return false;
        });

        if (exact_found)
        {
            if (out != nullptr)
                *out = exact_match;
            return true;
        }
        if (partial_found)
        {
            if (out != nullptr)
                *out = partial_match;
            return true;
        }
        return false;
    };

    const std::string module_query = params.value("module", std::string());
    if (params.contains("decrypt_timeout"))
        log("decrypt_timeout", true, "Ignored: raw runtime dump mode does not perform decrypt polling");

    ea_t base = BADADDR;
    if (params.contains("address"))
    {
        auto a = helpers::parse_address(params["address"].get<std::string>());
        if (a) base = *a;
    }

    resolved_module_t resolved_module;
    bool have_resolved_module = false;

    if ((base == BADADDR || base == 0) && !module_query.empty())
    {
        have_resolved_module = find_ldr_module_by_query(module_query, &resolved_module);
        if (!have_resolved_module)
            return tool_result_t::error(OBFSTR("Loaded module not found: ") + module_query);
        base = static_cast<ea_t>(resolved_module.base);
        log("resolve_module", true,
            resolved_module.name + " @ " + helpers::format_address(base));
    }

    if (base == BADADDR || base == 0)
    {
        std::uint64_t img_base = device->find_image();
        if (img_base == 0) img_base = device->get_base_address();
        base = static_cast<ea_t>(img_base);
    }
    if (base == 0 || base == BADADDR)
        return tool_result_t::error(OBFSTR("Invalid module base. Provide 'address' or attach to a process first."));

    anti_re::guard_driver_self_module(device->get_process_id(), static_cast<std::uint64_t>(base));

    if (!have_resolved_module)
        have_resolved_module = find_ldr_module_by_base(static_cast<std::uint64_t>(base), &resolved_module);

    log("find_image_base", true, helpers::format_address(base));

    bool header_wiped = false;
    bool has_valid_pe = false;
    std::uint8_t pe_hdr[0x1000];
    std::memset(pe_hdr, 0, sizeof(pe_hdr));
    std::size_t hdr_read = device->read_raw(base, pe_hdr, sizeof(pe_hdr));

    std::uint32_t pe_off = 0;
    std::uint16_t opt_magic      = 0x020B;
    std::uint16_t sections_count = 0;
    std::uint16_t opt_size       = 0;
    std::uint32_t sec_table_off  = 0;
    std::uint32_t pe_size_of_image = 0;

    if (hdr_read >= 0x200 && *(std::uint16_t*)pe_hdr == 0x5A4D)
    {
        pe_off = *(std::uint32_t*)(pe_hdr + 0x3C);
        if (pe_off + 0x100 <= sizeof(pe_hdr) && *(std::uint32_t*)(pe_hdr + pe_off) == 0x00004550)
        {
            has_valid_pe = true;
            opt_magic      = *(std::uint16_t*)(pe_hdr + pe_off + 0x18);
            sections_count = *(std::uint16_t*)(pe_hdr + pe_off + 0x06);
            opt_size       = *(std::uint16_t*)(pe_hdr + pe_off + 0x14);
            sec_table_off  = pe_off + 0x18 + opt_size;
            if (opt_magic == 0x020B || opt_magic == 0x010B)
                pe_size_of_image = *(std::uint32_t*)(pe_hdr + pe_off + 0x18 + 0x38);

            log("read_pe_header", true, std::to_string(hdr_read) + " bytes, " +
                std::to_string(sections_count) + " sections, SizeOfImage=0x" +
                helpers::format_address(static_cast<ea_t>(pe_size_of_image)));
        }
        else
        {
            header_wiped = true;
            log("read_pe_header", false, "MZ found but PE signature invalid/corrupt — will synthesize header after dump");
        }
    }
    else
    {
        header_wiped = true;
        msg(OBFSTR_C("AiDA: WARNING - MZ signature not found at base %s (read %zu bytes). "
            "Header likely wiped by anti-cheat. Will synthesize PE header after dump.\n"),
            helpers::format_address(base).c_str(), hdr_read);
        log("read_pe_header", false,
            "MZ signature wiped/missing — anti-cheat header erasure detected. Will synthesize after dump.");
    }

    std::uint64_t ldr_sz = 0;
    if (have_resolved_module && resolved_module.size > 0)
        ldr_sz = resolved_module.size;
    else
        ldr_sz = get_ldr_module_size(device.get(), base);

    if (params.contains("size"))
        pe_size_of_image = static_cast<std::uint32_t>(params.value("size", static_cast<std::size_t>(pe_size_of_image)));
    else if (ldr_sz > 0)
        pe_size_of_image = static_cast<std::uint32_t>(ldr_sz);
    else if (pe_size_of_image == 0)
        pe_size_of_image = 0x2000000;

    std::string module_name = have_resolved_module && !resolved_module.name.empty()
        ? resolved_module.name
        : params.value("process", std::string("module"));


    std::string module_disk_path = have_resolved_module && !resolved_module.path.empty()
        ? resolved_module.path
        : get_ldr_module_file_path(device.get(), base);
    if (!module_disk_path.empty())
        log("resolve_disk_path", true, module_disk_path);

    device->solve_dtb();
    if (device->get_dtb() == 0)
        return tool_result_t::error(OBFSTR("DTB solve failed before dump. Cannot read process memory."));

    protection_analysis_t protection = analyze_module_protection(
        device.get(), base, pe_hdr, hdr_read, has_valid_pe, header_wiped,
        pe_off, sections_count, sec_table_off, pe_size_of_image, false, steps);

    vad_dump_plan_t vad_plan = build_vad_dump_plan(device.get(), base, pe_size_of_image, steps);

    std::size_t module_size = static_cast<std::size_t>(vad_plan.total_span);
    if (module_size == 0)
        module_size = static_cast<std::size_t>(pe_size_of_image);
    if (module_size > 0x200000000ULL)
        return tool_result_t::error(OBFSTR("Module size too large (>8GB): ") + std::to_string(module_size));

    msg(OBFSTR_C("AiDA: Module dump plan — %d region, span 0x%zX (%zu MB), image size 0x%X (%u MB)\n"),
        vad_plan.committed_region_count, module_size, module_size / (1024 * 1024),
        pe_size_of_image, pe_size_of_image / (1024 * 1024));


    std::vector<std::uint32_t> suspended_tids;
    {
        auto threads = device->enumerate_threads();
        for (const auto& t : threads)
        {
            std::uint32_t prev = 0;
            if (device->suspend_thread(t.tid, &prev))
                suspended_tids.push_back(t.tid);
        }
        log("suspend_threads", !suspended_tids.empty(),
            std::to_string(suspended_tids.size()) + "/" + std::to_string(threads.size()) +
            " threads suspended for consistent snapshot");
        if (!suspended_tids.empty())
            msg(OBFSTR_C("AiDA: Suspended %zu/%zu threads for dump consistency\n"),
                suspended_tids.size(), threads.size());
    }


    struct thread_resume_guard_t {
        voyager::device_t* dev;
        std::vector<std::uint32_t>& tids;
        bool released = false;
        ~thread_resume_guard_t() { if (!released) resume(); }
        void resume() {
            for (std::uint32_t tid : tids) dev->resume_thread(tid);
            released = true;
        }
    } thread_guard{device.get(), suspended_tids};

    std::vector<std::uint8_t> module_data(module_size, 0);
    std::size_t total_read = 0;
    int failed_pages = 0;

    std::memcpy(module_data.data(), pe_hdr, std::min<std::size_t>(hdr_read, module_size));
    total_read = std::min<std::size_t>(hdr_read, module_size);

    show_wait_box("HIDECANCEL\nAiDA: Dumping %s via kernel — %d regions, 0x%zX bytes (%zu MB)...",
                  module_name.c_str(), vad_plan.committed_region_count, module_size,
                  module_size / (1024 * 1024));

    constexpr std::size_t DUMP_CHUNK = 0x10000;
    constexpr std::size_t DUMP_PAGE  = 0x1000;
    std::vector<std::size_t> failed_offsets;
    int region_idx = 0;


    struct code_section_range_t {
        std::size_t offset;
        std::size_t size;
    };
    std::vector<code_section_range_t> code_sections;
    if (has_valid_pe)
    {
        std::uint32_t fixed_pe_off = pe_off;
        std::uint16_t fixed_nsec = sections_count;
        std::uint32_t fixed_sec_table = sec_table_off;
        for (int si = 0; si < fixed_nsec && si < 96; si++)
        {
            std::uint32_t soff = fixed_sec_table + si * 40;
            if (soff + 40 > sizeof(pe_hdr)) break;
            std::uint32_t vsize = *(std::uint32_t*)(pe_hdr + soff + 8);
            std::uint32_t vrva  = *(std::uint32_t*)(pe_hdr + soff + 12);
            std::uint32_t chars = *(std::uint32_t*)(pe_hdr + soff + 36);
            if (vsize == 0 || vrva == 0) continue;
            if (chars & 0x20)
            {
                std::size_t sec_end = static_cast<std::size_t>(vrva) + vsize;
                if (sec_end > module_size) sec_end = module_size;
                if (vrva < module_size)
                    code_sections.push_back({static_cast<std::size_t>(vrva), sec_end - vrva});
            }
        }
    }

    for (const auto& region : vad_plan.regions)
    {
        region_idx++;
        if (region.offset >= module_size) continue;

        std::size_t read_size = static_cast<std::size_t>(
            std::min(region.size, static_cast<std::uint64_t>(module_size - region.offset)));

        std::size_t start_off = 0;
        if (region.offset == 0)
            start_off = std::min<std::size_t>(hdr_read, read_size);

        for (std::size_t chunk_off = start_off; chunk_off < read_size; chunk_off += DUMP_CHUNK)
        {
            std::size_t buf_offset = static_cast<std::size_t>(region.offset) + chunk_off;

            if (buf_offset % 0x400000 == 0)
                replace_wait_box("HIDECANCEL\nAiDA: Dumping %s — region %d/%d (0x%zX / 0x%zX, %.1f%%)...",
                                 module_name.c_str(), region_idx, vad_plan.committed_region_count,
                                 buf_offset, module_size, (buf_offset * 100.0) / module_size);

            std::size_t to_read = std::min(DUMP_CHUNK, read_size - chunk_off);
            std::size_t got = device->read_raw(base + buf_offset, module_data.data() + buf_offset, to_read);

            if (got >= to_read)
            {
                total_read += got;
                continue;
            }

            for (std::size_t pg = 0; pg < to_read; pg += DUMP_PAGE)
            {
                std::size_t pg_off = buf_offset + pg;
                if (pg_off >= module_size) break;
                std::size_t pg_sz  = std::min(DUMP_PAGE, module_size - pg_off);
                std::size_t pg_got = device->read_raw(
                    base + pg_off, module_data.data() + pg_off, pg_sz);
                if (pg_got > 0)
                    total_read += pg_got;
                else
                {
                    failed_pages++;
                    failed_offsets.push_back(pg_off);
                }
            }
        }
    }


    if (!failed_offsets.empty())
    {
        replace_wait_box("HIDECANCEL\nAiDA: Re-solving DTB and retrying %d failed pages...",
                         static_cast<int>(failed_offsets.size()));
        device->solve_dtb();

        int recovered = 0;
        for (std::size_t fo : failed_offsets)
        {
            if (fo >= module_size) continue;
            std::size_t pg_sz  = std::min(DUMP_PAGE, module_size - fo);
            std::size_t pg_got = device->read_raw(
                base + fo, module_data.data() + fo, pg_sz);
            if (pg_got > 0)
            {
                total_read += pg_got;
                recovered++;
            }
        }

        if (recovered > 0)
            msg(OBFSTR_C("AiDA: DTB re-solve recovered %d/%d failed pages\n"),
                recovered, static_cast<int>(failed_offsets.size()));

        failed_pages -= recovered;
    }


    hide_wait_box();

    log("dump_image", total_read > 0, std::to_string(total_read) + "/" + std::to_string(module_size) + " bytes" +
        (failed_pages > 0 ? (", " + std::to_string(failed_pages) + " pages unreadable") : ""));


    thread_guard.resume();
    log("resume_threads", true, std::to_string(suspended_tids.size()) + " threads resumed");


    std::string output_path = params.value("output_path", std::string());
    if (output_path.empty())
    {
        output_path = get_downloads_folder() + "dumped_" + module_name + "_" +
                      helpers::format_address(base) + ".bin";
    }
    ensure_parent_dir_exists(output_path);
    {
        HANDLE hFile = CreateFileA(output_path.c_str(), GENERIC_WRITE, 0, nullptr,
                                   CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
        if (hFile != INVALID_HANDLE_VALUE)
        {
            const std::uint8_t* write_ptr = module_data.data();
            std::size_t remaining = module_size;
            bool write_ok = true;

            while (remaining > 0)
            {
                DWORD chunk = static_cast<DWORD>(std::min<std::size_t>(remaining, 0x40000000ULL));
                DWORD written = 0;
                if (!WriteFile(hFile, write_ptr, chunk, &written, nullptr) || written != chunk)
                {
                    write_ok = false;
                    msg(OBFSTR_C("AiDA: WARNING - WriteFile failed at offset 0x%zX (error %lu)\n"),
                        module_size - remaining, GetLastError());
                    break;
                }
                write_ptr += written;
                remaining -= written;
            }

            CloseHandle(hFile);
            if (write_ok)
                msg(OBFSTR_C("AiDA: Dump saved to %s (%zu bytes, %zu MB)\n"),
                    output_path.c_str(), module_size, module_size / (1024 * 1024));
        }
        else
            msg(OBFSTR_C("AiDA: WARNING - Failed to save dump file: %s (error %lu)\n"),
                output_path.c_str(), GetLastError());
    }
    log("save_to_disk", true, output_path);

    bool patch_idb = params.value("patch_idb", true);
    std::size_t patched = 0;
    int segs_created = 0;
    json segs_info = json::array();

    if (patch_idb)
    {
        show_wait_box("HIDECANCEL\nAiDA: Creating IDB segments and patching bytes...");

        std::uint16_t fixed_sections_count = sections_count;
        std::uint32_t fixed_sec_table_off  = sec_table_off;
        if (has_valid_pe && module_size > 0x200)
        {
            std::uint32_t fixed_pe_off = *reinterpret_cast<std::uint32_t*>(module_data.data() + 0x3C);
            if (fixed_pe_off + 0x18 < module_size)
            {
                fixed_sections_count = *reinterpret_cast<std::uint16_t*>(module_data.data() + fixed_pe_off + 6);
                std::uint16_t fixed_opt_size = *reinterpret_cast<std::uint16_t*>(module_data.data() + fixed_pe_off + 0x14);
                fixed_sec_table_off = fixed_pe_off + 0x18 + fixed_opt_size;
            }
        }

        for (int si = 0; si < fixed_sections_count && si < 96; si++)
        {
            std::uint32_t soff = fixed_sec_table_off + si * 40;
            if (soff + 40 > module_size) break;

            const std::uint8_t* sec = module_data.data() + soff;

            char name[9] = {0};
            memcpy(name, sec, 8);
            std::uint32_t vsize = *(std::uint32_t*)(sec + 8);
            std::uint32_t vrva  = *(std::uint32_t*)(sec + 12);
            std::uint32_t chars = *(std::uint32_t*)(sec + 36);
            if (vsize == 0 || vrva == 0) continue;

            ea_t sec_start = base + vrva;
            ea_t sec_end   = sec_start + vsize;

            uchar perm = 0;
            if (chars & 0x40000000) perm |= SEGPERM_READ;
            if (chars & 0x80000000) perm |= SEGPERM_WRITE;
            if (chars & 0x20000000) perm |= SEGPERM_EXEC;

            if (!getseg(sec_start))
            {
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
                    segs_info.push_back({{"name", std::string(name)},
                                         {"start", helpers::format_address(sec_start)},
                                         {"size", vsize}});
                }
            }

            if (vrva < module_size && vsize > 0)
            {
                std::uint32_t copy_len = vsize;
                if (vrva + copy_len > module_size)
                    copy_len = static_cast<std::uint32_t>(module_size - vrva);
                if (copy_len > 0 && is_mapped(sec_start))
                {
                    put_bytes(sec_start, module_data.data() + vrva, copy_len);
                    patched += copy_len;
                }
            }
        }

        if (patched == 0 && module_size > 0)
        {
            if (!getseg(base))
            {
                segment_t raw_seg;
                raw_seg.start_ea = base;
                raw_seg.end_ea   = base + module_size;
                raw_seg.type     = SEG_NORM;
                raw_seg.bitness  = (opt_magic == 0x020B) ? 2 : 1;
                raw_seg.perm     = SEGPERM_READ | SEGPERM_WRITE | SEGPERM_EXEC;
                raw_seg.align    = saRelByte;
                raw_seg.comb     = scPub;

                const char* seg_name = module_name.empty() ? "runtime_dump" : module_name.c_str();
                if (add_segm_ex(&raw_seg, seg_name, "DATA", ADDSEG_QUIET | ADDSEG_NOSREG))
                {
                    segs_created++;
                    segs_info.push_back({{"name", std::string(seg_name)},
                                         {"start", helpers::format_address(base)},
                                         {"size", module_size}});
                }
            }

            if (is_mapped(base))
            {
                put_bytes(base, module_data.data(), module_size);
                patched = module_size;
            }
        }

        hide_wait_box();
        log("patch_idb", patched > 0, std::to_string(patched) + " bytes patched, " +
            std::to_string(segs_created) + " segments created");
    }

    bool hb = device->send_heartbeat();
    log("heartbeat", hb, hb ? "Session maintained" : "Failed (non-fatal)");

    json result;
    result["base"]            = helpers::format_address(base);
    result["module_name"]     = module_name;
    result["image_size"]      = module_size;
    result["pe_size_of_image"] = static_cast<std::size_t>(pe_size_of_image);
    result["bytes_dumped"]    = total_read;
    result["coverage_pct"]    = module_size ? (int)((total_read * 100) / module_size) : 0;
    result["saved_to"]        = output_path;
    result["can_load_in_ida"] = has_valid_pe && !header_wiped;
    result["raw_runtime_dump"] = true;
    result["post_processing_applied"] = false;
    result["header_valid"]    = has_valid_pe;
    result["header_wiped"]    = header_wiped;
    result["threads_suspended"]  = static_cast<int>(suspended_tids.size());
    if (!module_disk_path.empty())
        result["module_path"] = module_disk_path;
    if (!protection.detected_protections.empty())
    {
        result["protections_detected"] = protection.detected_protections;
        result["is_packed"] = protection.is_packed;
        if (protection.is_vmprotected) result["vmprotect"] = true;
        if (protection.is_themida) result["themida"] = true;
        if (protection.is_upx) result["upx"] = true;
    }
    if (protection.total_code_pages > 0)
    {
        json analysis;
        analysis["total_code_pages"] = protection.total_code_pages;
        analysis["zero_pages"] = protection.zero_code_pages;
        analysis["high_entropy_pages"] = protection.high_entropy_pages;
        analysis["avg_entropy"] = protection.avg_code_entropy;
        result["pre_dump_analysis"] = analysis;
    }
    result["steps"]           = steps;
    if (vad_plan.used_vad)
    {
        result["vad_regions"]          = vad_plan.committed_region_count;
        result["vad_committed_bytes"]  = vad_plan.total_committed_bytes;
        result["vad_extended"]         = (vad_plan.total_span > vad_plan.pe_size_of_image);
        if (vad_plan.total_span > vad_plan.pe_size_of_image)
            result["vad_extension_mb"] = (vad_plan.total_span - vad_plan.pe_size_of_image) / (1024 * 1024);
    }
    if (patch_idb)
    {
        result["patched_idb"]      = true;
        result["bytes_patched"]    = patched;
        result["sections_created"] = segs_created;
        if (!segs_info.empty())
            result["segments"] = segs_info;
    }
    result["note"] = std::string(
        OBFSTR("This dump preserves the module exactly as it existed in target memory. "
               "No decryption, devirtualization, header synthesis, IAT reconstruction, or disk fallback was applied. ")) +
        (header_wiped || !has_valid_pe
            ? OBFSTR("The in-memory image does not currently expose a clean PE header. "
                     "Open the saved file with manual load and set the image base to ") + helpers::format_address(base) + OBFSTR(".")
            : OBFSTR("Open the saved file in a new IDA Pro instance. If needed, use manual load with image base ") + helpers::format_address(base) + OBFSTR("."));

    return tool_result_t::ok(OBFSTR("Module dumped: ") + std::to_string(total_read) + "/" +
                             std::to_string(module_size) + " bytes -> " + output_path +
                             OBFSTR(". Open this file in a NEW IDA Pro instance for proper analysis."), result);
}

tool_result_t driver_scan_pattern(const json& params)
{
    if (!device->is_connected() || device->get_process_id() == 0)
        return tool_result_t::error(OBFSTR("Not attached. Call driver_connect then driver_attach first."));

    std::string pattern_str = params["pattern"].get<std::string>();

    int limit = 20;
    if (params.contains("limit")) {
        if (params["limit"].is_number())
            limit = params["limit"].get<int>();
        else if (params["limit"].is_string()) {
            try { limit = std::stoi(params["limit"].get<std::string>()); } catch (...) {}
        }
    }

    std::uint64_t scan_size = 0x200000;
    if (params.contains("size")) {
        if (params["size"].is_number())
            scan_size = params["size"].get<std::uint64_t>();
        else if (params["size"].is_string()) {
            auto sz = helpers::parse_address(params["size"].get<std::string>());
            if (sz) scan_size = *sz;
        }
    }

    ea_t start_addr = static_cast<ea_t>(device->get_base_address());
    ea_t end_addr   = start_addr + (ea_t)scan_size;
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

    anti_re::guard_driver_self_access(device->get_process_id(), start_addr, end_addr - start_addr);

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
    if (auto ctx_err = ensure_attached_process_context(params))
        return *ctx_err;

    auto ea_opt = helpers::parse_address(params["address"].get<std::string>());
    if (!ea_opt)
        return tool_result_t::error(OBFSTR("Invalid address"));

    std::size_t max_len = params.value("max_length", 512);
    std::string type    = params.value("type", "auto");

    anti_re::guard_driver_self_access(device->get_process_id(), *ea_opt, max_len * 2 + 4);

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
    if (auto ctx_err = ensure_attached_process_context(params))
        return *ctx_err;

    std::string base_address;
    if (params.contains("address") && params["address"].is_string())
        base_address = params["address"].get<std::string>();
    else if (params.contains("base_address") && params["base_address"].is_string())
        base_address = params["base_address"].get<std::string>();

    auto ea_opt = helpers::parse_address(base_address);
    if (!ea_opt)
        return tool_result_t::error(OBFSTR("Invalid address. Use address='0x...' (alias base_address is supported)."));

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

    anti_re::guard_driver_self_access(device->get_process_id(), *ea_opt, 8);

    json chain = json::array();
    std::uint64_t current = *ea_opt;
    chain.push_back({{"step", 0}, {"address", helpers::format_address(current)}, {"type", "base"}});

    for (std::size_t i = 0; i < offsets.size(); i++)
    {
        anti_re::guard_driver_self_access(device->get_process_id(), current, 8);
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

    if (device->get_dtb() == 0)
    {
        device->solve_dtb();
        if (device->get_dtb() == 0)
            return tool_result_t::error(OBFSTR("Failed to solve DTB. Cannot enumerate modules."));
    }

    voyager::device_t::peb_info peb{};
    if (!device->read_peb(peb) || peb.ldr_address == 0)
        return tool_result_t::error(OBFSTR("Failed to read PEB or PEB_LDR_DATA is null. "
            "Ensure the process is running and fully initialized."));


    std::uint64_t list_head = peb.ldr_address + 0x10;
    std::uint64_t first_entry = device->read<std::uint64_t>(list_head);

    if (first_entry == 0 || first_entry == list_head)
        return tool_result_t::error(OBFSTR("InLoadOrderModuleList is empty or unreadable."));

    json modules = json::array();
    std::uint64_t current = first_entry;
    int max_iter = 1024;
    std::uint64_t main_base = device->get_base_address();

    while (current != list_head && current != 0 && max_iter-- > 0)
    {


        std::uint64_t dll_base    = device->read<std::uint64_t>(current + 0x30);
        std::uint64_t entry_point = device->read<std::uint64_t>(current + 0x38);
        std::uint32_t size_of_img = device->read<std::uint32_t>(current + 0x40);


        std::uint16_t base_name_len = device->read<std::uint16_t>(current + 0x58);
        std::uint64_t base_name_ptr = device->read<std::uint64_t>(current + 0x60);

        std::string base_name;
        if (base_name_len > 0 && base_name_len < 520 && base_name_ptr != 0)
        {
            std::vector<std::uint8_t> raw(base_name_len, 0);
            device->read_raw(base_name_ptr, raw.data(), base_name_len);
            base_name.reserve(base_name_len / 2);
            for (std::size_t i = 0; i + 1 < base_name_len; i += 2)
            {
                std::uint16_t wc = raw[i] | (static_cast<std::uint16_t>(raw[i + 1]) << 8);
                if (wc == 0) break;
                base_name += (wc < 128 && wc >= 32) ? static_cast<char>(wc) : '?';
            }
        }


        std::uint16_t full_name_len = device->read<std::uint16_t>(current + 0x48);
        std::uint64_t full_name_ptr = device->read<std::uint64_t>(current + 0x50);

        std::string full_name;
        if (full_name_len > 0 && full_name_len < 1024 && full_name_ptr != 0)
        {
            std::vector<std::uint8_t> raw(full_name_len, 0);
            device->read_raw(full_name_ptr, raw.data(), full_name_len);
            full_name.reserve(full_name_len / 2);
            for (std::size_t i = 0; i + 1 < full_name_len; i += 2)
            {
                std::uint16_t wc = raw[i] | (static_cast<std::uint16_t>(raw[i + 1]) << 8);
                if (wc == 0) break;
                full_name += (wc < 128 && wc >= 32) ? static_cast<char>(wc) : '?';
            }
        }

        if (dll_base != 0 && !base_name.empty())
        {
            json entry;
            entry["name"]        = base_name;
            entry["base"]        = helpers::format_address(static_cast<ea_t>(dll_base));
            entry["size"]        = size_of_img;
            entry["size_hex"]    = helpers::format_address(static_cast<ea_t>(size_of_img));
            entry["entry_point"] = helpers::format_address(static_cast<ea_t>(entry_point));
            if (!full_name.empty())
                entry["path"]    = full_name;
            entry["is_main"]     = (dll_base == main_base);
            modules.push_back(entry);
        }

        std::uint64_t next = device->read<std::uint64_t>(current);
        if (next == current || next == 0) break;
        current = next;
    }

    json result;
    result["modules"]      = modules;
    result["module_count"] = modules.size();
    result["process_id"]   = device->get_process_id();
    result["peb_address"]  = helpers::format_address(static_cast<ea_t>(peb.peb_address));
    result["ldr_address"]  = helpers::format_address(static_cast<ea_t>(peb.ldr_address));
    result["image_base"]   = helpers::format_address(static_cast<ea_t>(main_base));
    return tool_result_t::ok(OBFSTR("Enumerated ") + std::to_string(modules.size()) +
        OBFSTR(" modules via PEB InLoadOrderModuleList"), result);
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
    bool use_memory = params.value("from_memory", true);
    bool patch_idb  = params.value("patch_idb", true);
    bool analyze    = params.value("analyze", true);

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

        json steps = json::array();
        auto log = [&](const std::string& step, bool ok, const std::string& detail) {
            steps.push_back({{"step", step}, {"ok", ok}, {"detail", detail}});
        };

        std::vector<std::uint8_t> header_buf(0x1000, 0);
        std::size_t header_read = device->read_kernel_raw(base_addr, header_buf.data(), 0x1000);

        bool has_valid_mz = (header_read >= 0x40 && header_buf[0] == 'M' && header_buf[1] == 'Z');
        bool has_valid_pe = false;
        bool header_wiped = false;

        std::uint16_t machine        = 0x8664;
        std::uint16_t num_sections   = 0;
        std::uint16_t opt_hdr_size   = 0;
        std::uint32_t pe_image_size  = 0;
        std::uint32_t pe_off         = 0;
        std::uint32_t section_table_off = 0;

        if (has_valid_mz)
        {
            pe_off = *reinterpret_cast<std::uint32_t*>(&header_buf[0x3C]);
            if (pe_off + 0x18 <= header_read &&
                header_buf[pe_off] == 'P' && header_buf[pe_off + 1] == 'E' &&
                header_buf[pe_off + 2] == 0 && header_buf[pe_off + 3] == 0)
            {
                has_valid_pe    = true;
                machine         = *reinterpret_cast<std::uint16_t*>(&header_buf[pe_off + 4]);
                num_sections    = *reinterpret_cast<std::uint16_t*>(&header_buf[pe_off + 6]);
                opt_hdr_size    = *reinterpret_cast<std::uint16_t*>(&header_buf[pe_off + 20]);
                pe_image_size   = *reinterpret_cast<std::uint32_t*>(&header_buf[pe_off + 24 + 56]);
                section_table_off = pe_off + 24 + opt_hdr_size;
            }

            log("read_header", true, has_valid_pe
                ? ("MZ+PE valid, " + std::to_string(num_sections) + " sections, SizeOfImage=0x" +
                   helpers::format_address(static_cast<ea_t>(pe_image_size)))
                : "MZ found but PE signature invalid/corrupt");
        }
        else
        {
            header_wiped = true;
            msg(OBFSTR_C("AiDA: WARNING - MZ signature not found at kernel base %s (read %zu bytes). "
                "Header likely wiped by anti-cheat. Using module info as source of truth.\n"),
                helpers::format_address(static_cast<ea_t>(base_addr)).c_str(), header_read);
            log("read_header", false,
                "MZ signature wiped/missing at base " +
                helpers::format_address(static_cast<ea_t>(base_addr)) +
                " - anti-cheat header erasure detected. Will synthesize PE header.");
        }


        protection_analysis_t kd_protection = analyze_module_protection(
            device.get(), base_addr, header_buf.data(), header_read,
            has_valid_pe, header_wiped, pe_off, num_sections,
            section_table_off, image_size, true, steps);

        if (kd_protection.is_packed || kd_protection.is_vmprotected ||
            kd_protection.is_themida)
        {
            msg(OBFSTR_C("AiDA: kernel module protection detected - VMProtect=%s Themida=%s Packed=%s "
                "encrypted_sections=%d high_entropy_pages=%d\n"),
                kd_protection.is_vmprotected ? "YES" : "no",
                kd_protection.is_themida ? "YES" : "no",
                kd_protection.is_packed ? "YES" : "no",
                kd_protection.encrypted_section_count,
                kd_protection.high_entropy_pages);
            log("protection_analysis", true,
                "Kernel module protections: VMProtect=" +
                std::string(kd_protection.is_vmprotected ? "YES" : "no") +
                " Themida=" + std::string(kd_protection.is_themida ? "YES" : "no") +
                " packed=" + std::string(kd_protection.is_packed ? "YES" : "no") +
                " encrypted_sections=" + std::to_string(kd_protection.encrypted_section_count) +
                " avg_entropy=" + std::to_string(kd_protection.avg_code_entropy));
        }

        std::uint32_t dump_size = image_size;
        if (has_valid_pe && pe_image_size > dump_size)
            dump_size = pe_image_size;
        if (dump_size == 0)
            dump_size = 0x100000;
        if (dump_size > 0x40000000u)
            return tool_result_t::error(OBFSTR("Image size exceeds 1GB limit: ") + std::to_string(dump_size));

        log("size_source", true,
            "Module info ImageSize=0x" + helpers::format_address(static_cast<ea_t>(image_size)) +
            (has_valid_pe ? (", PE SizeOfImage=0x" + helpers::format_address(static_cast<ea_t>(pe_image_size))) : "") +
            ", using dump_size=0x" + helpers::format_address(static_cast<ea_t>(dump_size)));

        constexpr std::uint32_t PROBE_CHUNK = 0x10000;
        constexpr int MAX_EMPTY_RUNS = 32;
        int empty_run = 0;
        std::uint32_t extended_end = dump_size;
        std::vector<std::uint8_t> probe_buf(PROBE_CHUNK, 0);
        std::uint64_t probe_limit = static_cast<std::uint64_t>(dump_size) * 4;
        if (probe_limit > 0x40000000ULL) probe_limit = 0x40000000ULL;

        for (std::uint64_t probe_off = dump_size; probe_off < probe_limit; probe_off += PROBE_CHUNK)
        {
            std::memset(probe_buf.data(), 0, PROBE_CHUNK);
            std::size_t probe_got = device->read_kernel_raw(
                base_addr + probe_off, probe_buf.data(), PROBE_CHUNK);
            if (probe_got == 0)
                break;

            bool all_zero = true;
            for (std::size_t i = 0; i < probe_got; i++)
            {
                if (probe_buf[i] != 0) { all_zero = false; break; }
            }

            if (all_zero)
            {
                empty_run++;
                if (empty_run >= MAX_EMPTY_RUNS) break;
            }
            else
            {
                empty_run = 0;
                extended_end = static_cast<std::uint32_t>(probe_off + PROBE_CHUNK);
            }
        }

        if (extended_end > dump_size)
        {
            msg(OBFSTR_C("AiDA: Extended kernel dump from 0x%X to 0x%X (+%u MB beyond base size)\n"),
                dump_size, extended_end, (extended_end - dump_size) / (1024 * 1024));
            log("probe_extend", true,
                "Extended dump by " + std::to_string((extended_end - dump_size) / (1024 * 1024)) +
                " MB via memory probing");
            dump_size = extended_end;
        }

        std::vector<std::uint8_t> dump_data(dump_size, 0);

        std::memcpy(dump_data.data(), header_buf.data(), std::min<std::size_t>(header_read, dump_size));

        show_wait_box("HIDECANCEL\nAiDA: Dumping kernel module %s from memory (0x%X bytes, %u MB)...",
                      found_name.c_str(), dump_size, dump_size / (1024 * 1024));

        constexpr std::size_t KD_CHUNK = 0x10000;
        constexpr std::size_t KD_PAGE  = 0x1000;
        std::size_t total_read = std::min<std::size_t>(header_read, dump_size);
        int kd_failed_pages = 0;
        std::vector<std::uint32_t> kd_failed_offsets;

        for (std::uint32_t offset = static_cast<std::uint32_t>(
                 std::min<std::size_t>(header_read, dump_size));
             offset < dump_size; offset += static_cast<std::uint32_t>(KD_CHUNK))
        {
            std::size_t to_read = KD_CHUNK;
            if (offset + to_read > dump_size)
                to_read = dump_size - offset;

            std::size_t bytes_got = device->read_kernel_raw(
                base_addr + offset, dump_data.data() + offset, to_read);

            if (bytes_got >= to_read)
            {
                total_read += bytes_got;
            }
            else
            {

                for (std::size_t pg = 0; pg < to_read; pg += KD_PAGE)
                {
                    std::size_t pg_sz  = std::min(KD_PAGE, to_read - pg);
                    std::size_t pg_got = device->read_kernel_raw(
                        base_addr + offset + pg,
                        dump_data.data() + offset + static_cast<std::uint32_t>(pg), pg_sz);
                    if (pg_got > 0)
                        total_read += pg_got;
                    else
                    {
                        kd_failed_pages++;
                        kd_failed_offsets.push_back(offset + static_cast<std::uint32_t>(pg));
                    }
                }
            }

            if (offset % 0x40000 == 0)
                replace_wait_box("HIDECANCEL\nAiDA: Dumping %s: 0x%X / 0x%X (%.1f%%)",
                                 found_name.c_str(), offset, dump_size,
                                 (offset * 100.0) / dump_size);
        }


        if (!kd_failed_offsets.empty())
        {
            replace_wait_box("HIDECANCEL\nAiDA: Re-solving kernel DTB and retrying %d pages...",
                             static_cast<int>(kd_failed_offsets.size()));
            device->solve_kernel_dtb();

            int kd_recovered = 0;
            for (std::uint32_t fo : kd_failed_offsets)
            {
                std::size_t pg_sz  = std::min(KD_PAGE, static_cast<std::size_t>(dump_size - fo));
                std::size_t pg_got = device->read_kernel_raw(
                    base_addr + fo, dump_data.data() + fo, pg_sz);
                if (pg_got > 0)
                {
                    total_read += pg_got;
                    kd_recovered++;
                }
            }

            if (kd_recovered > 0)
                msg(OBFSTR_C("AiDA: Kernel DTB re-solve recovered %d/%d failed pages\n"),
                    kd_recovered, static_cast<int>(kd_failed_offsets.size()));

            kd_failed_pages -= kd_recovered;
        }


        if (!kd_failed_offsets.empty())
        {
            std::string kd_disk_path = resolve_nt_path_to_win32(found_nt_path);
            if (!kd_disk_path.empty())
            {
                std::vector<std::size_t> kd_fail_sizes;
                kd_fail_sizes.reserve(kd_failed_offsets.size());
                for (std::uint32_t fo : kd_failed_offsets)
                    kd_fail_sizes.push_back(static_cast<std::size_t>(fo));

                int disk_recovered = try_fill_from_disk_pe(dump_data, kd_fail_sizes, kd_disk_path, steps);
                if (disk_recovered > 0)
                {
                    kd_failed_pages -= disk_recovered;
                    total_read += static_cast<std::size_t>(disk_recovered) * KD_PAGE;
                }
            }
        }

        hide_wait_box();

        log("dump_memory", total_read > 0,
            std::to_string(total_read) + "/" + std::to_string(dump_size) + " bytes" +
            (kd_failed_pages > 0 ? (", " + std::to_string(kd_failed_pages) + " pages unreadable (paged-out/shadow)") : ""));

        if (header_wiped || !has_valid_pe)
        {
            msg(OBFSTR_C("AiDA: Synthesizing PE header for headerless kernel dump...\n"));

            struct discovered_section_t {
                std::uint32_t rva;
                std::uint32_t size;
                bool is_executable;
                bool is_writable;
                bool has_data;
            };
            std::vector<discovered_section_t> discovered;

            constexpr std::uint32_t SCAN_GRANULARITY = 0x1000;
            std::uint32_t current_start = 0;
            bool in_section = false;
            bool sec_exec = false;
            bool sec_write = false;
            bool sec_has_data = false;

            for (std::uint32_t off = 0; off < dump_size; off += SCAN_GRANULARITY)
            {
                bool page_has_data = false;
                bool page_looks_code = false;
                std::uint32_t page_end = std::min(off + SCAN_GRANULARITY, dump_size);

                for (std::uint32_t i = off; i < page_end; i++)
                {
                    if (dump_data[i] != 0) { page_has_data = true; break; }
                }

                if (page_has_data && page_end - off >= 16)
                {
                    int code_heuristic = 0;
                    for (std::uint32_t i = off; i < page_end - 4; i += 64)
                    {
                        std::uint8_t b = dump_data[i];
                        if (b == 0xCC || b == 0xC3 || b == 0xC2 ||
                            b == 0xE8 || b == 0xE9 || b == 0xFF ||
                            b == 0x48 || b == 0x4C || b == 0x41 ||
                            b == 0x0F || b == 0x55 || b == 0x53)
                            code_heuristic++;
                    }
                    page_looks_code = (code_heuristic > 3);
                }

                if (page_has_data && !in_section)
                {
                    current_start = off;
                    in_section = true;
                    sec_exec = page_looks_code;
                    sec_write = !page_looks_code;
                    sec_has_data = true;
                }
                else if (page_has_data && in_section)
                {
                    if (page_looks_code) sec_exec = true;
                    sec_has_data = true;
                }
                else if (!page_has_data && in_section)
                {
                    std::uint32_t lookahead_end = std::min(off + 0x10000, dump_size);
                    bool resumes = false;
                    for (std::uint32_t la = off + SCAN_GRANULARITY; la < lookahead_end; la += SCAN_GRANULARITY)
                    {
                        for (std::uint32_t i = la; i < std::min(la + SCAN_GRANULARITY, dump_size); i++)
                        {
                            if (dump_data[i] != 0) { resumes = true; break; }
                        }
                        if (resumes) break;
                    }

                    if (!resumes)
                    {
                        discovered.push_back({current_start, off - current_start,
                                              sec_exec, sec_write, sec_has_data});
                        in_section = false;
                    }
                }
            }

            if (in_section)
            {
                discovered.push_back({current_start, dump_size - current_start,
                                      sec_exec, sec_write, sec_has_data});
            }

            if (discovered.empty())
            {
                discovered.push_back({0, dump_size, true, false, true});
            }

            int max_synth_sections = std::min<int>(static_cast<int>(discovered.size()), 16);
            std::uint32_t synth_pe_off = 0x80;
            std::uint32_t synth_opt_size = 0xF0;
            std::uint32_t synth_sec_table = synth_pe_off + 0x18 + synth_opt_size;
            std::uint32_t synth_header_end = synth_sec_table + max_synth_sections * 40;

            if (synth_header_end > 0x1000) synth_header_end = 0x1000;

            dump_data[0x00] = 'M'; dump_data[0x01] = 'Z';
            dump_data[0x02] = 0x90; dump_data[0x03] = 0x00;
            *reinterpret_cast<std::uint32_t*>(&dump_data[0x3C]) = synth_pe_off;

            dump_data[synth_pe_off + 0] = 'P';
            dump_data[synth_pe_off + 1] = 'E';
            dump_data[synth_pe_off + 2] = 0;
            dump_data[synth_pe_off + 3] = 0;

            *reinterpret_cast<std::uint16_t*>(&dump_data[synth_pe_off + 4]) = 0x8664;
            *reinterpret_cast<std::uint16_t*>(&dump_data[synth_pe_off + 6]) =
                static_cast<std::uint16_t>(max_synth_sections);

            std::uint16_t pe_characteristics = 0x0022;
            *reinterpret_cast<std::uint16_t*>(&dump_data[synth_pe_off + 0x16]) = pe_characteristics;

            *reinterpret_cast<std::uint16_t*>(&dump_data[synth_pe_off + 0x14]) = synth_opt_size;

            std::uint32_t opt_off = synth_pe_off + 0x18;
            *reinterpret_cast<std::uint16_t*>(&dump_data[opt_off + 0]) = 0x020B;
            *reinterpret_cast<std::uint32_t*>(&dump_data[opt_off + 0x38]) =
                (dump_size + 0xFFF) & ~0xFFFu;
            *reinterpret_cast<std::uint32_t*>(&dump_data[opt_off + 0x3C]) = 0x1000;
            *reinterpret_cast<std::uint64_t*>(&dump_data[opt_off + 0x18]) = base_addr;
            *reinterpret_cast<std::uint32_t*>(&dump_data[opt_off + 0x10]) =
                discovered.empty() ? 0x1000 : discovered[0].rva;
            *reinterpret_cast<std::uint16_t*>(&dump_data[opt_off + 0x44]) = 0x0A;
            *reinterpret_cast<std::uint32_t*>(&dump_data[opt_off + 0x6C]) = 0;

            for (int si = 0; si < max_synth_sections; si++)
            {
                const auto& ds = discovered[si];
                std::uint32_t sec_off = synth_sec_table + si * 40;
                if (sec_off + 40 > 0x1000) break;

                char sname[9] = {};
                if (ds.is_executable)
                    qsnprintf(sname, sizeof(sname), ".text%d", si);
                else
                    qsnprintf(sname, sizeof(sname), ".data%d", si);
                if (si == 0 && ds.is_executable) std::memcpy(sname, ".text\0\0\0", 8);
                if (si == 0 && !ds.is_executable) std::memcpy(sname, ".data\0\0\0", 8);

                std::memcpy(&dump_data[sec_off], sname, 8);
                *reinterpret_cast<std::uint32_t*>(&dump_data[sec_off + 8]) = ds.size;
                *reinterpret_cast<std::uint32_t*>(&dump_data[sec_off + 12]) = ds.rva;
                *reinterpret_cast<std::uint32_t*>(&dump_data[sec_off + 16]) = ds.size;
                *reinterpret_cast<std::uint32_t*>(&dump_data[sec_off + 20]) = ds.rva;

                std::uint32_t chars = 0x40000000u;
                if (ds.is_executable) chars |= 0x20000000u | 0x00000020u;
                if (ds.is_writable)   chars |= 0x80000000u;
                chars |= 0x00000040u;
                *reinterpret_cast<std::uint32_t*>(&dump_data[sec_off + 36]) = chars;
            }

            machine         = 0x8664;
            num_sections    = static_cast<std::uint16_t>(max_synth_sections);
            pe_off          = synth_pe_off;
            opt_hdr_size    = synth_opt_size;
            section_table_off = synth_sec_table;
            pe_image_size   = dump_size;
            has_valid_pe    = true;

            log("synthesize_header", true,
                "Built synthetic PE header with " + std::to_string(max_synth_sections) +
                " discovered sections from memory content analysis");
            msg(OBFSTR_C("AiDA: Synthesized PE header - %d sections discovered via memory scanning\n"),
                max_synth_sections);
        }


        pe_fix_result_t pe_fix = fix_dumped_pe_image(dump_data, base_addr);
        if (pe_fix.success)
        {
            msg(OBFSTR_C("AiDA: PE fixed - %d sections, %d IAT entries restored, EP %s\n"),
                pe_fix.sections_fixed, pe_fix.iat_entries_restored,
                pe_fix.entry_point_valid ? "valid" : "fallback");
            log("pe_fix", true, std::to_string(pe_fix.sections_fixed) + " sections, " +
                std::to_string(pe_fix.iat_entries_restored) + " IAT entries");
        }

        cleanup_exception_directory(dump_data, pe_fix.is_pe64 || (machine == 0x8664));
        log("exception_cleanup", true, "Invalid runtime function entries cleaned");

        {
            std::uint16_t kd_sec_count = num_sections;
            std::uint32_t kd_sec_table = section_table_off;
            if (pe_fix.success && dump_size > 0x200)
            {
                std::uint32_t fpo = *reinterpret_cast<std::uint32_t*>(dump_data.data() + 0x3C);
                if (fpo + 0x18 < dump_size)
                {
                    kd_sec_count = *reinterpret_cast<std::uint16_t*>(dump_data.data() + fpo + 6);
                    std::uint16_t fo = *reinterpret_cast<std::uint16_t*>(dump_data.data() + fpo + 0x14);
                    kd_sec_table = fpo + 0x18 + fo;
                }
            }

            int kd_nop_filled = 0;
            for (int si = 0; si < kd_sec_count && si < 96; si++)
            {
                std::uint32_t soff = kd_sec_table + si * 40;
                if (soff + 40 > dump_size) break;

                std::uint32_t vsize = *reinterpret_cast<std::uint32_t*>(dump_data.data() + soff + 8);
                std::uint32_t vrva  = *reinterpret_cast<std::uint32_t*>(dump_data.data() + soff + 12);
                std::uint32_t chars = *reinterpret_cast<std::uint32_t*>(dump_data.data() + soff + 36);

                if (vsize == 0 || vrva == 0 || !(chars & 0x20000000)) continue;

                for (std::uint32_t pg_off = vrva; pg_off < vrva + vsize; pg_off += 0x1000)
                {
                    if (pg_off >= dump_size) break;
                    std::uint32_t pg_sz = std::min<std::uint32_t>(0x1000, dump_size - pg_off);

                    bool is_all_zero = true;
                    for (std::uint32_t i = 0; i < pg_sz; i++)
                    {
                        if (dump_data[pg_off + i] != 0x00)
                        {
                            is_all_zero = false;
                            break;
                        }
                    }
                    if (is_all_zero)
                    {
                        std::memset(dump_data.data() + pg_off, 0x90, pg_sz);
                        kd_nop_filled++;
                    }
                }
            }

            if (kd_nop_filled > 0)
            {
                log("nop_fill", true, std::to_string(kd_nop_filled) +
                    " zero code pages NOP-filled to prevent IDA treating them as data");
                msg(OBFSTR_C("AiDA: NOP-filled %d zero code pages in kernel dump\n"), kd_nop_filled);
            }
        }

        iat_rebuild_result_t iat_rebuild = reconstruct_iat_runtime(dump_data, base_addr, device.get(), true);
        if (iat_rebuild.success && iat_rebuild.descriptors_rebuilt > 0)
        {
            msg(OBFSTR_C("AiDA: Kernel IAT reconstruction - %d imports resolved, %d failed, %d descriptors rebuilt\n"),
                iat_rebuild.imports_resolved, iat_rebuild.imports_failed, iat_rebuild.descriptors_rebuilt);
            log("iat_rebuild", true, std::to_string(iat_rebuild.imports_resolved) + " imports, " +
                std::to_string(iat_rebuild.descriptors_rebuilt) + " descriptors");
        }
        else if (!iat_rebuild.error.empty())
        {
            msg(OBFSTR_C("AiDA: Kernel IAT rebuild note: %s\n"), iat_rebuild.error.c_str());
            log("iat_rebuild", false, iat_rebuild.error);
        }

        if (iat_rebuild.descriptors_rebuilt == 0 || iat_rebuild.imports_resolved == 0)
        {
            msg(OBFSTR_C("AiDA: Standard kernel IAT rebuild found nothing — running full export-scan reconstruction...\n"));
            iat_rebuild_result_t scan_result = full_iat_scan_and_rebuild(dump_data, base_addr, device.get(), true);
            if (scan_result.success && scan_result.imports_resolved > 0)
            {
                iat_rebuild = scan_result;
                msg(OBFSTR_C("AiDA: Kernel full IAT scan — %d imports resolved, %d DLLs\n"),
                    scan_result.imports_resolved, scan_result.descriptors_rebuilt);
                log("iat_full_scan", true, std::to_string(scan_result.imports_resolved) +
                    " imports via full scan, " + std::to_string(scan_result.descriptors_rebuilt) + " DLLs");
            }
            else
            {
                msg(OBFSTR_C("AiDA: Kernel full IAT scan found no additional imports\n"));
                log("iat_full_scan", false, scan_result.error.empty() ? "No imports found" : scan_result.error);
            }
        }

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
        {
            const std::uint8_t* wp = dump_data.data();
            std::size_t rem = dump_size;
            bool wok = true;
            while (rem > 0 && wok)
            {
                DWORD chunk = static_cast<DWORD>(std::min<std::size_t>(rem, 0x40000000ULL));
                DWORD w = 0;
                if (!WriteFile(hOut, wp, chunk, &w, nullptr) || w != chunk)
                    wok = false;
                else { wp += w; rem -= w; bytes_written += w; }
            }
        }
        CloseHandle(hOut);
        hide_wait_box();
        msg(OBFSTR_C("AiDA: Dump saved to %s (%u bytes, %u MB)\n"),
            output_path.c_str(), dump_size, dump_size / (1024 * 1024));
        log("save_to_disk", true, output_path + " (" + std::to_string(dump_size) + " bytes)");

        std::size_t patched = 0;
        json sections_arr = json::array();

        if (patch_idb)
        {
            show_wait_box("HIDECANCEL\nAiDA: Creating IDB segments and patching bytes...");

            std::uint16_t final_num_sections = num_sections;
            std::uint32_t final_section_table_off = section_table_off;
            if (pe_fix.success && dump_size > 0x200)
            {
                std::uint32_t fpo = *reinterpret_cast<std::uint32_t*>(dump_data.data() + 0x3C);
                if (fpo + 0x18 < dump_size)
                {
                    final_num_sections = *reinterpret_cast<std::uint16_t*>(dump_data.data() + fpo + 6);
                    std::uint16_t fo = *reinterpret_cast<std::uint16_t*>(dump_data.data() + fpo + 0x14);
                    final_section_table_off = fpo + 0x18 + fo;
                }
            }

            for (int s = 0; s < final_num_sections && s < 96; s++)
            {
                std::uint32_t s_off = final_section_table_off + s * 40;
                if (s_off + 40 > dump_size) break;

                const std::uint8_t* sec = dump_data.data() + s_off;
                char sec_name[9] = {};
                std::memcpy(sec_name, sec, 8);

                std::uint32_t virt_size       = *reinterpret_cast<const std::uint32_t*>(sec + 8);
                std::uint32_t virt_addr       = *reinterpret_cast<const std::uint32_t*>(sec + 12);
                std::uint32_t sec_chars       = *reinterpret_cast<const std::uint32_t*>(sec + 36);

                if (virt_size == 0) continue;

                ea_t seg_start = static_cast<ea_t>(base_addr + virt_addr);
                ea_t seg_end   = seg_start + virt_size;

                if (!getseg(seg_start))
                {
                    segment_t seg;
                    seg.start_ea = seg_start;
                    seg.end_ea   = seg_end;
                    seg.type     = (sec_chars & 0x20000000) ? SEG_CODE : SEG_DATA;
                    seg.bitness  = 2;
                    seg.perm     = 0;
                    if (sec_chars & 0x20000000) seg.perm |= SEGPERM_EXEC;
                    if (sec_chars & 0x40000000) seg.perm |= SEGPERM_READ;
                    if (sec_chars & 0x80000000) seg.perm |= SEGPERM_WRITE;
                    add_segm_ex(&seg, sec_name, nullptr, ADDSEG_QUIET | ADDSEG_NOSREG);
                }

                std::uint32_t copy_len = virt_size;
                if (virt_addr + copy_len > dump_size) copy_len = dump_size - virt_addr;

                std::size_t sec_patched = 0;
                if (copy_len > 0 && is_mapped(seg_start))
                {
                    put_bytes(seg_start, dump_data.data() + virt_addr, copy_len);
                    sec_patched = copy_len;
                }
                patched += sec_patched;

                json sec_info;
                sec_info["name"]            = sec_name;
                sec_info["virtual_address"] = helpers::format_address(static_cast<ea_t>(virt_addr));
                sec_info["virtual_size"]    = virt_size;
                sec_info["characteristics"] = helpers::format_address(static_cast<ea_t>(sec_chars));
                sec_info["bytes_patched"]   = sec_patched;
                sections_arr.push_back(sec_info);
            }

            hide_wait_box();
            log("patch_idb", patched > 0, std::to_string(patched) + " bytes patched into IDB");
        }

        std::string pe_arch = "unknown";
        if (machine == 0x8664) pe_arch = "AMD64";
        else if (machine == 0x014C) pe_arch = "i386";
        else if (machine == 0xAA64) pe_arch = "ARM64";

        int coverage = dump_size ? static_cast<int>((total_read * 100) / dump_size) : 0;

        json result;
        result["module_name"]        = found_name;
        result["nt_path"]            = found_nt_path;
        result["kernel_base"]        = helpers::format_address(static_cast<ea_t>(found_base));
        result["image_size"]         = dump_size;
        result["module_info_size"]   = image_size;
        result["bytes_read"]         = total_read;
        result["coverage_pct"]       = coverage;
        result["output_path"]        = output_path;
        result["saved_to"]           = output_path;
        result["valid_pe"]           = has_valid_pe;
        result["header_wiped"]       = header_wiped;
        result["header_synthesized"] = header_wiped || !has_valid_mz;
        result["architecture"]       = pe_arch;
        result["num_sections"]       = static_cast<int>(num_sections);
        result["dump_source"]        = "kernel_memory";
        result["can_load_in_ida"]    = true;
        result["analyzed"]           = analyze && patch_idb;
        result["steps"]              = steps;
        if (kd_failed_pages > 0)
            result["unreadable_pages"] = kd_failed_pages;
        if (patch_idb)
        {
            result["bytes_patched"] = patched;
            result["sections"]      = sections_arr;
        }
        if (pe_fix.success)
            result["pe_fix"] = pe_fix_to_json(pe_fix);
        if (iat_rebuild.success && iat_rebuild.descriptors_rebuilt > 0)
            result["iat_rebuild"] = iat_rebuild_to_json(iat_rebuild);

        result["protections_detected"] = kd_protection.is_packed ||
            kd_protection.is_vmprotected || kd_protection.is_themida;
        result["vmprotect"]  = kd_protection.is_vmprotected;
        result["themida"]    = kd_protection.is_themida;
        result["upx"]        = kd_protection.is_upx;
        result["is_packed"]  = kd_protection.is_packed;
        {
            json pa;
            pa["total_code_pages"]    = kd_protection.total_code_pages;
            pa["zero_pages"]          = kd_protection.zero_code_pages;
            pa["high_entropy_pages"]  = kd_protection.high_entropy_pages;
            pa["avg_entropy"]         = kd_protection.avg_code_entropy;
            pa["encrypted_sections"]  = kd_protection.encrypted_section_count;

            result["pre_dump_analysis"] = pa;
        }

        std::string note_str;
        if (header_wiped)
            note_str = OBFSTR("WARNING: Original PE header was wiped by anti-cheat. "
                "A synthetic header has been constructed from memory analysis. "
                "Section boundaries are approximate. ");
        note_str += OBFSTR("Live kernel memory dump - contains runtime-decrypted code. "
            "Open this file in a NEW IDA Pro instance for proper analysis. ");
        if (kd_failed_pages > 0)
            note_str += std::to_string(kd_failed_pages) +
                OBFSTR(" pages were unreadable (paged-out, shadow-mapped, or EPT-protected). ");
        result["note"] = note_str;

        return tool_result_t::ok(
            OBFSTR("Kernel module dumped: ") + found_name + OBFSTR(" (") +
            std::to_string(total_read) + OBFSTR("/") + std::to_string(dump_size) +
            OBFSTR(" bytes, ") + std::to_string(coverage) + OBFSTR("% coverage") +
            (header_wiped ? OBFSTR(", header synthesized") : "") +
            OBFSTR(") -> ") + output_path +
            OBFSTR(". Open this file in a NEW IDA Pro instance for proper analysis."), result);
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
    if (!is_probably_kernel_address(address))
        return tool_result_t::error(OBFSTR("Address is not a canonical kernel virtual address. Use driver_read_memory for user-mode addresses."));

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

    if (!is_probably_kernel_address(address))
        return tool_result_t::error(OBFSTR("Address is not a canonical kernel virtual address. Use driver_write_memory for user-mode addresses."));

    std::vector<std::uint8_t> data;
    std::string parse_error;
    if (!parse_byte_sequence(params["bytes"], data, parse_error))
        return tool_result_t::error(OBFSTR("Invalid bytes format. ") + parse_error);

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

tool_result_t driver_allocate_memory(const json& params)
{
    if (auto ctx_err = ensure_attached_process_context(params))
        return *ctx_err;

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
    if (auto ctx_err = ensure_attached_process_context(params))
        return *ctx_err;

    auto addr_opt = helpers::parse_address(params["address"].get<std::string>());
    if (!addr_opt || *addr_opt == 0)
        return tool_result_t::error(OBFSTR("Invalid address."));

    std::uint64_t address = static_cast<std::uint64_t>(*addr_opt);

    voyager::device_t::memory_region_info before{};
    const bool query_before_free = device->query_memory(address, before);

    bool ok = device->free_memory(address);

    json result;
    result["address"]    = helpers::format_address(*addr_opt);
    result["freed"]      = ok;
    result["process_id"] = device->get_process_id();
    result["query_before_free"] = query_before_free;
    if (query_before_free)
    {
        result["region_base"] = helpers::format_address(static_cast<ea_t>(before.base));
        result["region_size"] = helpers::format_address(static_cast<ea_t>(before.size));
        result["region_protect"] = before.protect;
    }

    if (ok)
        return tool_result_t::ok(OBFSTR("Memory freed at ") + helpers::format_address(*addr_opt), result);
    else
        return tool_result_t::error(OBFSTR("Failed to free memory at ") + helpers::format_address(*addr_opt) +
            OBFSTR(". If the region was modified through kernel-space writes, verify address space consistency and attached PID."));
}

tool_result_t driver_call_function(const json& params)
{
    if (auto ctx_err = ensure_attached_process_context(params))
        return *ctx_err;

    auto func_opt = helpers::parse_address(params["address"].get<std::string>());
    if (!func_opt || *func_opt == 0)
        return tool_result_t::error(OBFSTR("Invalid function address."));

    std::uint64_t func_addr = static_cast<std::uint64_t>(*func_opt);

    anti_re::guard_driver_self_access(device->get_process_id(), func_addr, 1);

    const bool dry_run = params.value("dry_run", false);
    const bool unsafe_confirmed =
        params.value("confirm_unsafe", false) ||
        params.value("allow_unsafe", false) ||
        params.value("unsafe", false);

    if (dry_run)
    {
        json preview;
        preview["function"] = helpers::format_address(static_cast<ea_t>(func_addr));
        preview["process_id"] = device->get_process_id();
        preview["note"] = "Dry-run only. No remote execution performed.";
        return tool_result_t::ok(OBFSTR("driver_call_function dry-run completed."), preview);
    }

    if (!unsafe_confirmed)
    {
        return tool_result_t::error(
            OBFSTR("driver_call_function is high-risk and may crash the target process. "
                   "Re-run with confirm_unsafe=true (or allow_unsafe=true) to execute, "
                   "or dry_run=true to preview only."));
    }

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

    if (!is_process_alive(device->get_process_id()))
    {
        const std::uint32_t crashed_pid = device->get_process_id();
        device->clear_process_context();
        return tool_result_t::error(OBFSTR("Target process PID ") + std::to_string(crashed_pid) +
            OBFSTR(" terminated during driver_call_function. Process context was detached for safety."));
    }

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


tool_result_t driver_get_thread_context(const json& params)
{
    if (auto ctx_err = ensure_attached_process_context(params))
        return *ctx_err;

    const auto tid_opt = parse_tid_param(params);
    if (!tid_opt)
        return tool_result_t::error(OBFSTR("Thread ID (tid) is required and must be a decimal integer or 0x-prefixed hex."));
    const std::uint32_t tid = *tid_opt;

    voyager::device_t::thread_context ctx{};
    if (!device->get_thread_context(tid, ctx))
        return tool_result_t::error(OBFSTR("Failed to get thread context for TID ") + std::to_string(tid));

    json result;
    result["tid"] = tid;
    result["rax"] = helpers::format_address(static_cast<ea_t>(ctx.rax));
    result["rbx"] = helpers::format_address(static_cast<ea_t>(ctx.rbx));
    result["rcx"] = helpers::format_address(static_cast<ea_t>(ctx.rcx));
    result["rdx"] = helpers::format_address(static_cast<ea_t>(ctx.rdx));
    result["rsi"] = helpers::format_address(static_cast<ea_t>(ctx.rsi));
    result["rdi"] = helpers::format_address(static_cast<ea_t>(ctx.rdi));
    result["rbp"] = helpers::format_address(static_cast<ea_t>(ctx.rbp));
    result["rsp"] = helpers::format_address(static_cast<ea_t>(ctx.rsp));
    result["r8"]  = helpers::format_address(static_cast<ea_t>(ctx.r8));
    result["r9"]  = helpers::format_address(static_cast<ea_t>(ctx.r9));
    result["r10"] = helpers::format_address(static_cast<ea_t>(ctx.r10));
    result["r11"] = helpers::format_address(static_cast<ea_t>(ctx.r11));
    result["r12"] = helpers::format_address(static_cast<ea_t>(ctx.r12));
    result["r13"] = helpers::format_address(static_cast<ea_t>(ctx.r13));
    result["r14"] = helpers::format_address(static_cast<ea_t>(ctx.r14));
    result["r15"] = helpers::format_address(static_cast<ea_t>(ctx.r15));
    result["rip"] = helpers::format_address(static_cast<ea_t>(ctx.rip));
    result["rflags"] = helpers::format_address(static_cast<ea_t>(ctx.rflags));
    result["dr0"] = helpers::format_address(static_cast<ea_t>(ctx.dr0));
    result["dr1"] = helpers::format_address(static_cast<ea_t>(ctx.dr1));
    result["dr2"] = helpers::format_address(static_cast<ea_t>(ctx.dr2));
    result["dr3"] = helpers::format_address(static_cast<ea_t>(ctx.dr3));
    result["dr6"] = helpers::format_address(static_cast<ea_t>(ctx.dr6));
    result["dr7"] = helpers::format_address(static_cast<ea_t>(ctx.dr7));

    return tool_result_t::ok(OBFSTR("Thread context for TID ") + std::to_string(tid), result);
}

tool_result_t driver_set_thread_context(const json& params)
{
    if (auto ctx_err = ensure_attached_process_context(params))
        return *ctx_err;

    const auto tid_opt = parse_tid_param(params);
    if (!tid_opt)
        return tool_result_t::error(OBFSTR("Thread ID (tid) is required and must be a decimal integer or 0x-prefixed hex."));
    const std::uint32_t tid = *tid_opt;

    voyager::device_t::thread_context ctx{};
    std::uint64_t mask = 0;

    auto set_reg = [&](const char* name, std::uint64_t& reg, int bit) {
        if (params.contains(name)) {
            if (params[name].is_string())
                reg = helpers::parse_address(params[name].get<std::string>()).value_or(0);
            else
                reg = params[name].get<std::uint64_t>();
            mask |= (1ULL << bit);
        }
    };

    set_reg("rax", ctx.rax, 0);  set_reg("rbx", ctx.rbx, 1);
    set_reg("rcx", ctx.rcx, 2);  set_reg("rdx", ctx.rdx, 3);
    set_reg("rsi", ctx.rsi, 4);  set_reg("rdi", ctx.rdi, 5);
    set_reg("rbp", ctx.rbp, 6);  set_reg("rsp", ctx.rsp, 7);
    set_reg("r8",  ctx.r8,  8);  set_reg("r9",  ctx.r9,  9);
    set_reg("r10", ctx.r10, 10); set_reg("r11", ctx.r11, 11);
    set_reg("r12", ctx.r12, 12); set_reg("r13", ctx.r13, 13);
    set_reg("r14", ctx.r14, 14); set_reg("r15", ctx.r15, 15);
    set_reg("rip", ctx.rip, 16); set_reg("rflags", ctx.rflags, 17);
    set_reg("dr0", ctx.dr0, 18); set_reg("dr1", ctx.dr1, 19);
    set_reg("dr2", ctx.dr2, 20); set_reg("dr3", ctx.dr3, 21);
    set_reg("dr6", ctx.dr6, 22); set_reg("dr7", ctx.dr7, 23);

    if (mask == 0) return tool_result_t::error(OBFSTR("No registers specified to set"));

    if (!device->set_thread_context(tid, ctx, mask))
        return tool_result_t::error(OBFSTR("Failed to set thread context for TID ") + std::to_string(tid));

    json result;
    result["tid"] = tid;
    result["register_mask"] = helpers::format_address(static_cast<ea_t>(mask));
    return tool_result_t::ok(OBFSTR("Thread context updated for TID ") + std::to_string(tid), result);
}

tool_result_t driver_enumerate_threads(const json& params)
{
    (void)params;
    if (auto ctx_err = ensure_attached_process_context(params))
        return *ctx_err;

    auto threads = device->enumerate_threads();
    if (threads.empty())
        return tool_result_t::error(OBFSTR("No threads found or enumeration failed"));

    json result;
    result["process_id"] = device->get_process_id();
    result["thread_count"] = threads.size();
    json arr = json::array();
    for (const auto& t : threads) {
        json tj;
        tj["tid"] = t.tid;
        tj["state"] = t.state;
        if (t.rip) tj["rip"] = helpers::format_address(static_cast<ea_t>(t.rip));
        arr.push_back(tj);
    }
    result["threads"] = arr;
    return tool_result_t::ok(OBFSTR("Enumerated ") + std::to_string(threads.size()) + OBFSTR(" threads"), result);
}

tool_result_t driver_suspend_thread(const json& params)
{
    if (auto ctx_err = ensure_attached_process_context(params))
        return *ctx_err;

    const auto tid_opt = parse_tid_param(params);
    if (!tid_opt)
        return tool_result_t::error(OBFSTR("Thread ID (tid) is required and must be a decimal integer or 0x-prefixed hex."));
    const std::uint32_t tid = *tid_opt;

    std::uint32_t prev = 0;
    if (!device->suspend_thread(tid, &prev))
        return tool_result_t::error(OBFSTR("Failed to suspend thread ") + std::to_string(tid));

    json result;
    result["tid"] = tid;
    result["previous_suspend_count"] = prev;
    return tool_result_t::ok(OBFSTR("Thread ") + std::to_string(tid) + OBFSTR(" suspended"), result);
}

tool_result_t driver_resume_thread(const json& params)
{
    if (auto ctx_err = ensure_attached_process_context(params))
        return *ctx_err;

    const auto tid_opt = parse_tid_param(params);
    if (!tid_opt)
        return tool_result_t::error(OBFSTR("Thread ID (tid) is required and must be a decimal integer or 0x-prefixed hex."));
    const std::uint32_t tid = *tid_opt;

    std::uint32_t prev = 0;
    if (!device->resume_thread(tid, &prev))
        return tool_result_t::error(OBFSTR("Failed to resume thread ") + std::to_string(tid));

    json result;
    result["tid"] = tid;
    result["previous_suspend_count"] = prev;
    return tool_result_t::ok(OBFSTR("Thread ") + std::to_string(tid) + OBFSTR(" resumed"), result);
}

tool_result_t driver_query_memory(const json& params)
{
    if (auto ctx_err = ensure_attached_process_context(params))
        return *ctx_err;

    std::uint64_t address = 0;
    if (params.contains("address"))
        address = helpers::parse_address(params["address"].get<std::string>()).value_or(0);
    if (address == 0)
        address = device->get_base_address();

    anti_re::guard_driver_self_access(device->get_process_id(), address, 1);

    voyager::device_t::memory_region_info info{};
    if (!device->query_memory(address, info))
        return tool_result_t::error(OBFSTR("Failed to query memory at ") + helpers::format_address(static_cast<ea_t>(address)));

    auto prot_str = [](std::uint32_t p) -> std::string {
        std::string s;
        if (p & 0x10) s += "EXECUTE ";
        if (p & 0x20) s += "EXECUTE_READ ";
        if (p & 0x40) s += "EXECUTE_READWRITE ";
        if (p & 0x80) s += "EXECUTE_WRITECOPY ";
        if (p & 0x01) s += "NOACCESS ";
        if (p & 0x02) s += "READONLY ";
        if (p & 0x04) s += "READWRITE ";
        if (p & 0x08) s += "WRITECOPY ";
        if (p & 0x100) s += "GUARD ";
        if (p & 0x200) s += "NOCACHE ";
        if (s.empty()) s = "UNKNOWN";
        return s;
    };

    json result;
    result["address"] = helpers::format_address(static_cast<ea_t>(address));
    result["region_base"] = helpers::format_address(static_cast<ea_t>(info.base));
    result["region_size"] = helpers::format_address(static_cast<ea_t>(info.size));
    result["state"] = (info.state == 0x1000) ? "MEM_COMMIT" :
                      (info.state == 0x2000) ? "MEM_RESERVE" :
                      (info.state == 0x10000) ? "MEM_FREE" : std::to_string(info.state);
    result["protect"] = prot_str(info.protect);
    result["protect_raw"] = info.protect;
    result["type"] = (info.type == 0x20000) ? "MEM_PRIVATE" :
                     (info.type == 0x40000) ? "MEM_MAPPED" :
                     (info.type == 0x1000000) ? "MEM_IMAGE" : std::to_string(info.type);
    result["allocation_base"] = helpers::format_address(static_cast<ea_t>(info.allocation_base));
    result["allocation_protect"] = prot_str(info.allocation_protect);

    return tool_result_t::ok(OBFSTR("Memory region info"), result);
}

tool_result_t driver_protect_memory(const json& params)
{
    if (auto ctx_err = ensure_attached_process_context(params))
        return *ctx_err;

    std::uint64_t address = 0;
    if (params.contains("address"))
        address = helpers::parse_address(params["address"].get<std::string>()).value_or(0);
    if (address == 0)
        return tool_result_t::error(OBFSTR("Address is required"));

    std::uint64_t size = 0x1000;
    if (params.contains("size")) {
        if (params["size"].is_string())
            size = helpers::parse_address(params["size"].get<std::string>()).value_or(0x1000);
        else
            size = params["size"].get<std::uint64_t>();
    }

    anti_re::guard_driver_self_access(device->get_process_id(), address, size);

    std::uint32_t new_protect = 0x40;
    if (params.contains("protect")) {
        if (params["protect"].is_string())
            new_protect = static_cast<std::uint32_t>(helpers::parse_address(params["protect"].get<std::string>()).value_or(0x40));
        else
            new_protect = params["protect"].get<std::uint32_t>();
    }

    std::uint32_t old_protect = 0;
    if (!device->protect_memory(address, size, new_protect, &old_protect))
        return tool_result_t::error(OBFSTR("Failed to change protection at ") + helpers::format_address(static_cast<ea_t>(address)));

    json result;
    result["address"] = helpers::format_address(static_cast<ea_t>(address));
    result["size"] = helpers::format_address(static_cast<ea_t>(size));
    result["new_protect"] = new_protect;
    result["old_protect"] = old_protect;
    return tool_result_t::ok(OBFSTR("Memory protection changed"), result);
}

tool_result_t driver_enumerate_memory_regions(const json& params)
{
    if (auto ctx_err = ensure_attached_process_context(params))
        return *ctx_err;

    std::uint64_t start = 0;
    if (params.contains("start"))
        start = helpers::parse_address(params["start"].get<std::string>()).value_or(0);

    std::uint64_t end_addr = 0;
    if (params.contains("end"))
        end_addr = helpers::parse_address(params["end"].get<std::string>()).value_or(0);

    bool include_all = false;
    if (params.contains("include_all") && params["include_all"].is_boolean())
        include_all = params["include_all"].get<bool>();

    auto regions = device->enumerate_memory_regions(start, end_addr, include_all);
    if (regions.empty())
        return tool_result_t::error(OBFSTR("No memory regions found"));

    auto prot_str = [](std::uint32_t p) -> std::string {
        if (p & 0x40) return "ERW";
        if (p & 0x20) return "ER";
        if (p & 0x10) return "E";
        if (p & 0x04) return "RW";
        if (p & 0x02) return "R";
        if (p & 0x01) return "NA";
        return std::to_string(p);
    };

    json result;
    result["process_id"] = device->get_process_id();
    result["region_count"] = regions.size();
    json arr = json::array();
    for (const auto& r : regions) {
        json rj;
        rj["base"] = helpers::format_address(static_cast<ea_t>(r.base));
        rj["size"] = helpers::format_address(static_cast<ea_t>(r.size));
        rj["state"] = (r.state == 0x1000) ? "COMMIT" :
                      (r.state == 0x2000) ? "RESERVE" : "FREE";
        rj["protect"] = prot_str(r.protect);
        rj["type"] = (r.type == 0x20000) ? "PRIVATE" :
                     (r.type == 0x40000) ? "MAPPED" :
                     (r.type == 0x1000000) ? "IMAGE" : std::to_string(r.type);
        arr.push_back(rj);
    }
    result["regions"] = arr;
    return tool_result_t::ok(OBFSTR("Enumerated ") + std::to_string(regions.size()) + OBFSTR(" regions"), result);
}

tool_result_t driver_read_peb(const json& params)
{
    (void)params;
    if (auto ctx_err = ensure_attached_process_context(params))
        return *ctx_err;

    voyager::device_t::peb_info info{};
    if (!device->read_peb(info))
        return tool_result_t::error(OBFSTR("Failed to read PEB"));

    json result;
    result["peb_address"] = helpers::format_address(static_cast<ea_t>(info.peb_address));
    result["image_base"] = helpers::format_address(static_cast<ea_t>(info.image_base));
    result["being_debugged"] = info.being_debugged ? true : false;
    result["nt_global_flag"] = helpers::format_address(static_cast<ea_t>(info.nt_global_flag));
    result["ldr_address"] = helpers::format_address(static_cast<ea_t>(info.ldr_address));
    result["process_heap"] = helpers::format_address(static_cast<ea_t>(info.process_heap));
    result["number_of_heaps"] = info.number_of_heaps;
    result["max_heaps"] = info.max_heaps;
    result["process_heaps"] = helpers::format_address(static_cast<ea_t>(info.process_heaps));
    return tool_result_t::ok(OBFSTR("PEB info for PID ") + std::to_string(device->get_process_id()), result);
}

tool_result_t driver_spoof_debug_flags(const json& params)
{
    (void)params;
    if (auto ctx_err = ensure_attached_process_context(params))
        return *ctx_err;

    if (anti_re::is_self_target_pid(device->get_process_id()))
        return tool_result_t::error(OBFSTR("Refusing to spoof debug flags on the current IDA host process. Attach a non-IDA target first."));

    std::uint32_t flags = 0;
    if (!device->spoof_debug_flags(&flags))
        return tool_result_t::error(OBFSTR("Failed to spoof debug flags"));

    json result;
    result["process_id"] = device->get_process_id();
    result["cleared_debug_port"] = (flags & 1) != 0;
    result["cleared_being_debugged"] = (flags & 2) != 0;
    result["cleared_nt_global_flag"] = (flags & 4) != 0;
    return tool_result_t::ok(OBFSTR("Anti-debug flags cleared"), result);
}

tool_result_t driver_set_hw_breakpoint(const json& params)
{
    if (auto ctx_err = ensure_attached_process_context(params))
        return *ctx_err;

    const auto tid_opt = parse_tid_param(params);
    if (!tid_opt)
        return tool_result_t::error(OBFSTR("Thread ID (tid) is required and must be a decimal integer or 0x-prefixed hex."));
    const std::uint32_t tid = *tid_opt;

    std::uint64_t address = 0;
    if (params.contains("address"))
        address = helpers::parse_address(params["address"].get<std::string>()).value_or(0);
    if (address == 0) return tool_result_t::error(OBFSTR("Address is required"));

    anti_re::guard_driver_self_access(device->get_process_id(), address, 1);

    int index = 0;
    if (params.contains("index")) index = params["index"].get<int>();

    int type = 0;
    if (params.contains("type")) {
        std::string t = params["type"].get<std::string>();
        if (t == "write") type = 1;
        else if (t == "readwrite" || t == "rw") type = 3;
        else type = 0;
    }

    int size = 0;
    if (params.contains("size")) {
        int s = params["size"].get<int>();
        if (s == 2) size = 1;
        else if (s == 4) size = 3;
        else if (s == 8) size = 2;
        else size = 0;
    }

    if (!device->set_hardware_breakpoint(tid, index, address, type, size))
        return tool_result_t::error(OBFSTR("Failed to set hardware breakpoint"));

    json result;
    result["tid"] = tid;
    result["index"] = index;
    result["address"] = helpers::format_address(static_cast<ea_t>(address));
    result["type"] = (type == 0) ? "execute" : (type == 1) ? "write" : "readwrite";
    return tool_result_t::ok(OBFSTR("Hardware breakpoint set on DR") + std::to_string(index), result);
}

tool_result_t driver_clear_hw_breakpoint(const json& params)
{
    if (auto ctx_err = ensure_attached_process_context(params))
        return *ctx_err;

    const auto tid_opt = parse_tid_param(params);
    if (!tid_opt)
        return tool_result_t::error(OBFSTR("Thread ID (tid) is required and must be a decimal integer or 0x-prefixed hex."));
    const std::uint32_t tid = *tid_opt;

    int index = 0;
    if (params.contains("index")) index = params["index"].get<int>();

    if (!device->clear_hardware_breakpoint(tid, index))
        return tool_result_t::error(OBFSTR("Failed to clear hardware breakpoint"));

    json result;
    result["tid"] = tid;
    result["index"] = index;
    return tool_result_t::ok(OBFSTR("Hardware breakpoint cleared on DR") + std::to_string(index), result);
}

tool_result_t driver_resolve_export(const json& params)
{
    if (auto ctx_err = ensure_attached_process_context(params))
        return *ctx_err;

    std::string export_name;
    if (params.contains("name") && params["name"].is_string())
        export_name = trim_ascii_copy(params["name"].get<std::string>());
    else if (params.contains("export_name") && params["export_name"].is_string())
        export_name = trim_ascii_copy(params["export_name"].get<std::string>());

    if (export_name.empty())
        return tool_result_t::error(OBFSTR("Export name is required. Use name='GetTickCount' (alias export_name is supported)."));

    std::uint64_t module_base = 0;
    std::string resolved_module_name;
    std::string module_query;
    bool explicit_module_param = false;

    if (params.contains("module_base") && params["module_base"].is_string())
    {
        explicit_module_param = true;
        module_base = helpers::parse_address(params["module_base"].get<std::string>()).value_or(0);
    }

    if (module_base == 0 && params.contains("module"))
    {
        explicit_module_param = true;
        if (params["module"].is_string())
            module_query = trim_ascii_copy(params["module"].get<std::string>());
    }

    if (module_base == 0 && module_query.empty() && params.contains("module_name") && params["module_name"].is_string())
    {
        explicit_module_param = true;
        module_query = trim_ascii_copy(params["module_name"].get<std::string>());
    }

    if (module_base == 0 && !module_query.empty())
    {
        if (auto parsed = helpers::parse_address(module_query))
            module_base = static_cast<std::uint64_t>(*parsed);
        else if (!resolve_loaded_module_base(module_query, module_base, resolved_module_name))
            return tool_result_t::error(OBFSTR("Could not resolve module '") + module_query +
                OBFSTR("'. Provide module_base='0x...' or a loaded module name/path."));
    }

    if (module_base == 0)
        module_base = device->get_base_address();
    if (module_base == 0)
        return tool_result_t::error(OBFSTR("Module base required. Provide module_base or module/module_name."));

    anti_re::guard_driver_self_module(device->get_process_id(), module_base);

    std::uint64_t addr = device->resolve_export(module_base, export_name.c_str());
    if (addr == 0)
    {
        std::string detail = OBFSTR("Export '") + export_name + OBFSTR("' not found in module ") +
            helpers::format_address(static_cast<ea_t>(module_base));
        if (!module_query.empty())
            detail += OBFSTR(" (query: '") + module_query + OBFSTR("')");
        return tool_result_t::error(detail);
    }

    json result;
    result["export_name"] = export_name;
    result["module_base"] = helpers::format_address(static_cast<ea_t>(module_base));
    if (!module_query.empty())
        result["module_query"] = module_query;
    if (!resolved_module_name.empty())
        result["resolved_module_name"] = resolved_module_name;
    result["explicit_module_param"] = explicit_module_param;
    result["resolved_address"] = helpers::format_address(static_cast<ea_t>(addr));
    return tool_result_t::ok(OBFSTR("Export resolved: ") + export_name + OBFSTR(" -> ") + helpers::format_address(static_cast<ea_t>(addr)), result);
}

tool_result_t driver_virtual_to_physical(const json& params)
{
    if (!device->is_connected() || device->get_dtb() == 0)
        return tool_result_t::error(OBFSTR("Driver not connected or DTB not solved"));

    std::uint64_t vaddr = 0;
    if (params.contains("address"))
        vaddr = helpers::parse_address(params["address"].get<std::string>()).value_or(0);
    if (vaddr == 0) return tool_result_t::error(OBFSTR("Address is required"));

    anti_re::guard_driver_self_access(device->get_process_id(), vaddr, 1);

    std::uint64_t paddr = device->virtual_to_physical(vaddr);
    if (paddr == 0)
        return tool_result_t::error(OBFSTR("Translation failed for ") + helpers::format_address(static_cast<ea_t>(vaddr)));

    json result;
    result["virtual_address"] = helpers::format_address(static_cast<ea_t>(vaddr));
    result["physical_address"] = helpers::format_address(static_cast<ea_t>(paddr));
    return tool_result_t::ok(OBFSTR("Virtual -> Physical translation"), result);
}


DeferredActionManager& DeferredActionManager::instance()
{
    static DeferredActionManager mgr;
    return mgr;
}

DeferredActionManager::~DeferredActionManager()
{
    shutdown();
}

void DeferredActionManager::shutdown()
{
    _shutdown.store(true);
    std::lock_guard<std::mutex> lock(_mutex);
    for (auto& [id, action] : _actions)
    {
        auto st = action->status.load();
        if (st == deferred_status::pending || st == deferred_status::watching)
            action->status.store(deferred_status::cancelled);
    }
    for (auto& [id, thread] : _watchers)
    {
        if (thread.joinable())
            thread.join();
    }
    _watchers.clear();
}

int DeferredActionManager::register_action(std::unique_ptr<deferred_action_t> action)
{
    std::lock_guard<std::mutex> lock(_mutex);
    int id = _next_id++;
    action->id = id;
    action->created = std::chrono::steady_clock::now();
    action->status.store(deferred_status::pending);

    _actions[id] = std::move(action);

    _watchers[id] = std::thread(&DeferredActionManager::watcher_thread_func, this, id);

    return id;
}

bool DeferredActionManager::cancel_action(int id)
{
    std::lock_guard<std::mutex> lock(_mutex);
    auto it = _actions.find(id);
    if (it == _actions.end())
        return false;

    auto st = it->second->status.load();
    if (st == deferred_status::pending || st == deferred_status::watching)
    {
        it->second->status.store(deferred_status::cancelled);
        if (_watchers.count(id) && _watchers[id].joinable())
        {
            _mutex.unlock();
            _watchers[id].join();
            _mutex.lock();
        }
        return true;
    }
    return false;
}

const deferred_action_t* DeferredActionManager::get_action(int id) const
{
    std::lock_guard<std::mutex> lock(_mutex);
    auto it = _actions.find(id);
    return (it != _actions.end()) ? it->second.get() : nullptr;
}

std::vector<const deferred_action_t*> DeferredActionManager::get_all_actions() const
{
    std::lock_guard<std::mutex> lock(_mutex);
    std::vector<const deferred_action_t*> result;
    for (const auto& [id, action] : _actions)
        result.push_back(action.get());
    return result;
}

bool DeferredActionManager::poll_kernel_module_load(
    const std::string& target,
    std::uint64_t& out_base,
    std::uint32_t& out_size,
    std::string& out_name,
    std::string& out_path)
{
    HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
    if (!ntdll) return false;

    auto pNtQuerySystemInformation = reinterpret_cast<NtQuerySystemInformation_fn>(
        GetProcAddress(ntdll, "NtQuerySystemInformation"));
    if (!pNtQuerySystemInformation) return false;

    constexpr ULONG SystemModuleInformation = 11;
    ULONG needed = 0;
    pNtQuerySystemInformation(SystemModuleInformation, nullptr, 0, &needed);
    if (needed == 0) needed = 256 * 1024;
    needed += 16384;

    std::vector<std::uint8_t> buf(needed, 0);
    LONG status = pNtQuerySystemInformation(
        SystemModuleInformation, buf.data(),
        static_cast<ULONG>(buf.size()), &needed);
    if (status < 0) return false;

    auto* info = reinterpret_cast<sys_module_info_t*>(buf.data());

    std::string lower_target = target;
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
            out_base = reinterpret_cast<std::uintptr_t>(m.ImageBase);
            out_size = m.ImageSize;
            out_name = name;
            out_path = full_path;
            return true;
        }
    }
    return false;
}

bool DeferredActionManager::poll_process_start(
    const std::string& target,
    std::uint32_t& out_pid)
{
    const HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshot == INVALID_HANDLE_VALUE) return false;

    PROCESSENTRY32W entry{};
    entry.dwSize = sizeof(PROCESSENTRY32W);

    bool found = false;
    if (Process32FirstW(snapshot, &entry))
    {
        do {
            std::string exe_name;
            for (int i = 0; entry.szExeFile[i]; i++)
                exe_name.push_back(static_cast<char>(entry.szExeFile[i]));

            std::string lower_exe = exe_name;
            std::string lower_target = target;
            std::transform(lower_exe.begin(), lower_exe.end(), lower_exe.begin(),
                [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
            std::transform(lower_target.begin(), lower_target.end(), lower_target.begin(),
                [](unsigned char c) { return static_cast<char>(std::tolower(c)); });

            if (lower_exe == lower_target || lower_exe.find(lower_target) != std::string::npos)
            {
                out_pid = entry.th32ProcessID;
                found = true;
                break;
            }
        } while (Process32NextW(snapshot, &entry));
    }

    CloseHandle(snapshot);
    return found;
}

std::string DeferredActionManager::resolve_template(const std::string& value, const json& context)
{
    std::string result = value;

    auto replace_all = [&](const std::string& placeholder, const std::string& replacement) {
        size_t pos = 0;
        while ((pos = result.find(placeholder, pos)) != std::string::npos)
        {
            result.replace(pos, placeholder.size(), replacement);
            pos += replacement.size();
        }
    };

    if (context.contains("module_base"))
        replace_all("${module_base}", context["module_base"].get<std::string>());
    if (context.contains("module_size"))
        replace_all("${module_size}", context["module_size"].get<std::string>());
    if (context.contains("module_name"))
        replace_all("${module_name}", context["module_name"].get<std::string>());
    if (context.contains("pid"))
        replace_all("${pid}", context["pid"].get<std::string>());
    if (context.contains("base_address"))
        replace_all("${base_address}", context["base_address"].get<std::string>());


    static const std::regex offset_re("0x([0-9A-Fa-f]+)\\+0x([0-9A-Fa-f]+)");
    std::smatch match;
    if (std::regex_match(result, match, offset_re))
    {
        std::uint64_t base_val = std::stoull(match[1].str(), nullptr, 16);
        std::uint64_t offset_val = std::stoull(match[2].str(), nullptr, 16);
        std::ostringstream ss;
        ss << "0x" << std::hex << std::uppercase << (base_val + offset_val);
        result = ss.str();
    }

    return result;
}

json DeferredActionManager::resolve_params(const json& params, const json& context)
{
    if (params.is_string())
        return resolve_template(params.get<std::string>(), context);

    if (params.is_object())
    {
        json resolved = json::object();
        for (auto it = params.begin(); it != params.end(); ++it)
            resolved[it.key()] = resolve_params(it.value(), context);
        return resolved;
    }

    if (params.is_array())
    {
        json resolved = json::array();
        for (const auto& item : params)
            resolved.push_back(resolve_params(item, context));
        return resolved;
    }

    return params;
}

void DeferredActionManager::execute_deferred_tools(deferred_action_t& action, const json& context)
{


    struct deferred_exec_request_t : public exec_request_t
    {
        std::string tool_name;
        json params;
        tool_result_t tool_result;

        ssize_t idaapi execute() override
        {
            tool_result = ToolRegistry::instance().execute_tool(tool_name, params);
            return 0;
        }
    };

    for (const auto& tc : action.tool_calls)
    {
        json resolved_params = resolve_params(tc.params, context);
        deferred_action_result_t result;
        result.action_type = tc.tool_name;

        try
        {
            const auto* tool_def = ToolRegistry::instance().get_tool(tc.tool_name);
            int mff_flag = (tool_def && tool_def->read_only) ? MFF_READ : MFF_WRITE;

            deferred_exec_request_t req;
            req.tool_name = tc.tool_name;
            req.params = resolved_params;


            execute_sync(req, mff_flag);

            result.success = req.tool_result.success;
            result.message = req.tool_result.output;
            result.data = req.tool_result.data;
        }
        catch (const std::exception& e)
        {
            result.success = false;
            result.message = std::string("Exception: ") + e.what();
        }

        action.results.push_back(std::move(result));
    }
}

void DeferredActionManager::watcher_thread_func(int action_id)
{
    deferred_action_t* action = nullptr;
    {
        std::lock_guard<std::mutex> lock(_mutex);
        auto it = _actions.find(action_id);
        if (it == _actions.end()) return;
        action = it->second.get();
    }

    action->status.store(deferred_status::watching);

    auto start_time = std::chrono::steady_clock::now();
    auto timeout = std::chrono::seconds(action->timeout_seconds);
    auto poll_interval = std::chrono::milliseconds(action->poll_interval_ms);

    msg(OBFSTR_C("AiDA: Deferred action #%d watching for %s '%s' (timeout: %ds, poll: %dms)\n"),
        action->id, action->condition_type.c_str(), action->target_name.c_str(),
        action->timeout_seconds, action->poll_interval_ms);

    json trigger_context;

    while (!_shutdown.load())
    {
        auto st = action->status.load();
        if (st == deferred_status::cancelled)
        {
            msg(OBFSTR_C("AiDA: Deferred action #%d cancelled\n"), action->id);
            return;
        }


        auto elapsed = std::chrono::steady_clock::now() - start_time;
        if (elapsed >= timeout)
        {
            action->status.store(deferred_status::timed_out);
            action->error = OBFSTR("Timed out waiting for ") + action->condition_type +
                OBFSTR(": ") + action->target_name;
            msg(OBFSTR_C("AiDA: Deferred action #%d timed out after %ds\n"),
                action->id, action->timeout_seconds);
            return;
        }

        bool condition_met = false;

        if (action->condition_type == "kernel_module_load")
        {
            std::uint64_t base = 0;
            std::uint32_t size = 0;
            std::string name, path;
            if (poll_kernel_module_load(action->target_name, base, size, name, path))
            {
                condition_met = true;
                std::ostringstream base_ss, size_ss;
                base_ss << "0x" << std::hex << std::uppercase << base;
                size_ss << "0x" << std::hex << std::uppercase << size;

                trigger_context["module_base"] = base_ss.str();
                trigger_context["module_size"] = size_ss.str();
                trigger_context["module_name"] = name;
                trigger_context["module_path"] = path;

                action->trigger_info = trigger_context.dump();
            }
        }
        else if (action->condition_type == "process_start")
        {
            std::uint32_t pid = 0;
            if (poll_process_start(action->target_name, pid))
            {
                if (anti_re::is_self_target_pid(pid))
                {
                    action->error = "Refusing deferred process_start attach for IDA host PID.";
                    action->status.store(deferred_status::failed);
                    return;
                }

                condition_met = true;
                trigger_context["pid"] = std::to_string(pid);


                if (device && !device->is_connected())
                    device->connect();

                if (device && device->is_connected())
                {
                    device->clear_process_context();
                    device->set_process_id(pid);
                    std::uint64_t img_base = device->find_image();
                    device->solve_dtb();

                    std::ostringstream base_ss;
                    base_ss << "0x" << std::hex << std::uppercase << img_base;
                    trigger_context["base_address"] = base_ss.str();
                    trigger_context["pid"] = std::to_string(device->get_process_id());
                }

                action->trigger_info = trigger_context.dump();
            }
        }

        if (condition_met)
        {
            action->triggered_at = std::chrono::steady_clock::now();
            action->status.store(deferred_status::triggered);

            auto trigger_elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
                action->triggered_at - start_time).count();
            msg(OBFSTR_C("AiDA: Deferred action #%d TRIGGERED! %s '%s' detected after %lldms. "
                "Executing %zu queued tool call(s) IMMEDIATELY...\n"),
                action->id, action->condition_type.c_str(), action->target_name.c_str(),
                trigger_elapsed, action->tool_calls.size());


            execute_deferred_tools(*action, trigger_context);

            bool any_failed = false;
            for (const auto& r : action->results)
            {
                msg(OBFSTR_C("AiDA: Deferred action #%d - %s: %s — %s\n"),
                    action->id, r.action_type.c_str(),
                    r.success ? "OK" : "FAIL", r.message.c_str());
                if (!r.success) any_failed = true;
            }

            action->status.store(any_failed ? deferred_status::failed : deferred_status::completed);

            msg(OBFSTR_C("AiDA: Deferred action #%d %s. %zu/%zu actions succeeded.\n"),
                action->id,
                any_failed ? "completed with failures" : "completed successfully",
                std::count_if(action->results.begin(), action->results.end(),
                    [](const deferred_action_result_t& r) { return r.success; }),
                action->results.size());

            return;
        }

        std::this_thread::sleep_for(poll_interval);
    }
}


static std::string deferred_status_to_string(deferred_status s)
{
    switch (s)
    {
        case deferred_status::pending:    return "pending";
        case deferred_status::watching:   return "watching";
        case deferred_status::triggered:  return "triggered";
        case deferred_status::completed:  return "completed";
        case deferred_status::failed:     return "failed";
        case deferred_status::cancelled:  return "cancelled";
        case deferred_status::timed_out:  return "timed_out";
        default: return "unknown";
    }
}

tool_result_t driver_defer_action(const json& params)
{
    json normalized = params;

    if (!normalized.contains("actions") && normalized.contains("action"))
    {
        json one = json::object();
        one["tool"] = normalized["action"];
        one["params"] = normalized.contains("params") ? normalized["params"] : json::object();
        normalized["actions"] = json::array({one});
    }

    if (normalized.contains("actions") && normalized["actions"].is_array())
    {
        for (auto& act : normalized["actions"])
        {
            if (act.is_object() && !act.contains("tool") && act.contains("action"))
                act["tool"] = act["action"];
            if (act.is_object() && !act.contains("params"))
                act["params"] = json::object();
        }
    }

    std::string wait_for;
    if (normalized.contains("wait_for"))
    {
        if (!normalized["wait_for"].is_string())
            return tool_result_t::error(OBFSTR("'wait_for' must be a string enum: 'process_start' or 'kernel_module_load'."));
        wait_for = normalized["wait_for"].get<std::string>();
    }
    if (wait_for.empty())
        return tool_result_t::error(OBFSTR("'wait_for' is required: 'kernel_module_load' or 'process_start'."));

    if (wait_for != "kernel_module_load" && wait_for != "process_start")
        return tool_result_t::error(OBFSTR("Invalid 'wait_for'. Allowed values: 'kernel_module_load', 'process_start'."));

    std::string target;
    if (normalized.contains("target"))
    {
        if (!normalized["target"].is_string())
            return tool_result_t::error(OBFSTR("'target' must be a string (module or process name)."));
        target = normalized["target"].get<std::string>();
    }
    if (target.empty())
        return tool_result_t::error(OBFSTR("'target' is required: module or process name to watch for"));

    int timeout = normalized.value("timeout", 300);
    int poll_interval = normalized.value("poll_interval", 50);

    if (!normalized.contains("actions") || !normalized["actions"].is_array() || normalized["actions"].empty())
        return tool_result_t::error(OBFSTR("'actions' array is required with at least one tool call. Format: [{\"tool\":\"driver_read_memory\",\"params\":{...}}]."));

    auto action = std::make_unique<deferred_action_t>();
    action->condition_type = wait_for;
    action->target_name = target;
    action->timeout_seconds = timeout;
    action->poll_interval_ms = poll_interval;

    for (const auto& act : normalized["actions"])
    {
        if (!act.contains("tool") || !act["tool"].is_string())
            return tool_result_t::error(OBFSTR("Each action must have a string 'tool' field (full tool name, e.g. 'driver_read_memory')."));

        deferred_action_t::queued_tool_call_t tc;
        tc.tool_name = act["tool"].get<std::string>();
        tc.params = act.contains("params") ? act["params"] : json::object();


        if (!ToolRegistry::instance().get_tool(tc.tool_name))
            return tool_result_t::error(OBFSTR("Unknown tool: ") + tc.tool_name);

        action->tool_calls.push_back(std::move(tc));
    }


    bool already_met = false;
    if (wait_for == "kernel_module_load")
    {
        std::uint64_t base = 0;
        std::uint32_t size = 0;
        std::string name, path;
        auto& mgr = DeferredActionManager::instance();
        if (mgr.poll_kernel_module_load(target, base, size, name, path))
            already_met = true;
    }
    else if (wait_for == "process_start")
    {
        std::uint32_t pid = 0;
        auto& mgr = DeferredActionManager::instance();
        if (mgr.poll_process_start(target, pid))
            already_met = true;
    }

    const std::size_t queued_actions = action->tool_calls.size();
    int action_id = DeferredActionManager::instance().register_action(std::move(action));

    json result;
    result["action_id"] = action_id;
    result["condition"] = wait_for;
    result["target"] = target;
    result["timeout_seconds"] = timeout;
    result["poll_interval_ms"] = poll_interval;
    result["num_queued_actions"] = queued_actions;
    result["status"] = already_met ? "target_already_loaded_executing_now" : "watching";
    result["note"] = already_met
        ? OBFSTR("Target '") + target + OBFSTR("' is ALREADY loaded! Actions are being executed immediately.")
        : OBFSTR("Background watcher started. Actions will execute THE INSTANT '") + target +
          OBFSTR("' loads. Use driver_get_deferred_results with action_id=") +
          std::to_string(action_id) + OBFSTR(" to check results.");

    return tool_result_t::ok(
        already_met
            ? OBFSTR("Deferred action #") + std::to_string(action_id) + OBFSTR(" — target already loaded, executing immediately!")
            : OBFSTR("Deferred action #") + std::to_string(action_id) + OBFSTR(" registered — watching for '") + target + "'",
        result);
}

tool_result_t driver_list_deferred_actions(const json&)
{
    auto actions = DeferredActionManager::instance().get_all_actions();

    json arr = json::array();
    for (const auto* action : actions)
    {
        json entry;
        entry["id"] = action->id;
        entry["condition"] = action->condition_type;
        entry["target"] = action->target_name;
        entry["status"] = deferred_status_to_string(action->status.load());
        entry["num_actions"] = action->tool_calls.size();
        entry["timeout_seconds"] = action->timeout_seconds;

        if (!action->trigger_info.empty())
        {
            try { entry["trigger_info"] = json::parse(action->trigger_info); }
            catch (...) { entry["trigger_info"] = action->trigger_info; }
        }

        if (!action->error.empty())
            entry["error"] = action->error;

        entry["num_results"] = action->results.size();
        int succeeded = 0;
        for (const auto& r : action->results)
            if (r.success) succeeded++;
        entry["succeeded"] = succeeded;
        entry["failed"] = static_cast<int>(action->results.size()) - succeeded;

        arr.push_back(entry);
    }

    json result;
    result["actions"] = arr;
    result["total"] = arr.size();
    return tool_result_t::ok(
        OBFSTR("Found ") + std::to_string(arr.size()) + OBFSTR(" deferred action(s)"), result);
}

tool_result_t driver_cancel_deferred_action(const json& params)
{
    int id = 0;
    if (params.contains("action_id"))
    {
        if (params["action_id"].is_string())
            id = std::stoi(params["action_id"].get<std::string>());
        else
            id = params["action_id"].get<int>();
    }
    if (id == 0)
        return tool_result_t::error(OBFSTR("'action_id' is required"));

    if (DeferredActionManager::instance().cancel_action(id))
    {
        json result;
        result["action_id"] = id;
        result["status"] = "cancelled";
        return tool_result_t::ok(OBFSTR("Deferred action #") + std::to_string(id) + OBFSTR(" cancelled"), result);
    }

    return tool_result_t::error(OBFSTR("Cannot cancel action #") + std::to_string(id) +
        OBFSTR(" — not found or already completed/triggered"));
}

tool_result_t driver_get_deferred_results(const json& params)
{
    int id = 0;
    if (params.contains("action_id"))
    {
        if (params["action_id"].is_string())
            id = std::stoi(params["action_id"].get<std::string>());
        else
            id = params["action_id"].get<int>();
    }
    if (id == 0)
        return tool_result_t::error(OBFSTR("'action_id' is required"));

    const auto* action = DeferredActionManager::instance().get_action(id);
    if (!action)
        return tool_result_t::error(OBFSTR("Action #") + std::to_string(id) + OBFSTR(" not found"));

    json result;
    result["action_id"] = action->id;
    result["condition"] = action->condition_type;
    result["target"] = action->target_name;
    result["status"] = deferred_status_to_string(action->status.load());

    if (!action->trigger_info.empty())
    {
        try { result["trigger_info"] = json::parse(action->trigger_info); }
        catch (...) { result["trigger_info"] = action->trigger_info; }
    }

    if (!action->error.empty())
        result["error"] = action->error;

    json results_arr = json::array();
    for (const auto& r : action->results)
    {
        json rj;
        rj["tool"] = r.action_type;
        rj["success"] = r.success;
        rj["message"] = r.message;
        if (!r.data.is_null() && !r.data.empty())
            rj["data"] = r.data;
        results_arr.push_back(rj);
    }
    result["results"] = results_arr;

    int succeeded = 0;
    for (const auto& r : action->results)
        if (r.success) succeeded++;
    result["succeeded"] = succeeded;
    result["failed"] = static_cast<int>(action->results.size()) - succeeded;
    result["total_actions"] = action->tool_calls.size();

    std::string status_str = deferred_status_to_string(action->status.load());
    return tool_result_t::ok(
        OBFSTR("Deferred action #") + std::to_string(id) + OBFSTR(": ") + status_str, result);
}


static std::string format_recon_ip(const std::uint8_t* addr, std::uint32_t af) {
    char buf[64] = {};
    if (af == 23) {
        qsnprintf(buf, sizeof(buf), "%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x",
            addr[0], addr[1], addr[2], addr[3], addr[4], addr[5], addr[6], addr[7],
            addr[8], addr[9], addr[10], addr[11], addr[12], addr[13], addr[14], addr[15]);
    } else {
        qsnprintf(buf, sizeof(buf), "%u.%u.%u.%u", addr[0], addr[1], addr[2], addr[3]);
    }
    return buf;
}

static const char* tcp_state_str(std::uint32_t state) {
    static const char* names[] = {
        "CLOSED", "LISTEN", "SYN_SENT", "SYN_RCVD", "ESTABLISHED",
        "FIN_WAIT1", "FIN_WAIT2", "CLOSE_WAIT", "CLOSING", "LAST_ACK",
        "TIME_WAIT", "DELETE_TCB"
    };
    if (state < 12) return names[state];
    return "UNKNOWN";
}

static std::string reg_index_to_name(std::uint32_t idx) {
    static const char* names[] = {
        "rax", "rcx", "rdx", "rbx", "rsp", "rbp", "rsi", "rdi",
        "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15"
    };
    if (idx < 16) return names[idx];
    return "reg" + std::to_string(idx);
}

tool_result_t driver_enumerate_wfp_callouts(const json& params)
{
    if (!device->is_connected())
        return tool_result_t::error(OBFSTR("Driver not connected"));

    std::string filter;
    if (params.contains("filter_module"))
        filter = params["filter_module"].get<std::string>();

    auto callouts = device->enumerate_wfp_callouts(filter);
    if (callouts.empty())
        return tool_result_t::ok(OBFSTR("No WFP callouts found"), json::object());

    json result;
    result["count"] = callouts.size();
    json arr = json::array();
    for (const auto& c : callouts) {
        json entry;
        entry["callout_id"] = c.callout_id;
        entry["callout_key"] = c.callout_key_str;
        entry["applicable_layer"] = c.applicable_layer_str;
        entry["flags"] = c.flags;
        entry["owning_module"] = c.owning_module;
        if (c.classify_fn != 0)
            entry["classify_fn"] = helpers::format_address(static_cast<ea_t>(c.classify_fn));
        if (c.notify_fn != 0)
            entry["notify_fn"] = helpers::format_address(static_cast<ea_t>(c.notify_fn));
        if (c.flow_delete_fn != 0)
            entry["flow_delete_fn"] = helpers::format_address(static_cast<ea_t>(c.flow_delete_fn));
        if (c.owning_module_base != 0)
            entry["module_base"] = helpers::format_address(static_cast<ea_t>(c.owning_module_base));
        arr.push_back(std::move(entry));
    }
    result["callouts"] = std::move(arr);

    return tool_result_t::ok(
        OBFSTR("Found ") + std::to_string(callouts.size()) + OBFSTR(" WFP callout(s)"), result);
}

tool_result_t driver_get_socket_handles(const json& params)
{
    if (auto ctx_err = ensure_attached_process_context(params))
        return *ctx_err;

    std::uint32_t target_pid = 0;
    if (params.contains("target_pid"))
        target_pid = params["target_pid"].get<std::uint32_t>();

    auto sockets = device->get_socket_handles(target_pid);
    if (sockets.empty())
        return tool_result_t::ok(OBFSTR("No AFD socket handles found"), json::object());

    json result;
    result["count"] = sockets.size();
    json arr = json::array();
    for (const auto& s : sockets) {
        json entry;
        entry["handle"] = helpers::format_address(static_cast<ea_t>(s.handle_value));
        entry["afd_endpoint"] = helpers::format_address(static_cast<ea_t>(s.afd_endpoint_addr));
        entry["pid"] = s.pid;
        entry["protocol"] = (s.protocol == 6) ? "TCP" : (s.protocol == 17) ? "UDP" : std::to_string(s.protocol);
        entry["state"] = tcp_state_str(s.state);
        entry["address_family"] = (s.address_family == 2) ? "IPv4" : (s.address_family == 23) ? "IPv6" : "unknown";
        entry["local"] = format_recon_ip(s.local_addr, s.address_family) + ":" + std::to_string(s.local_port);
        entry["remote"] = format_recon_ip(s.remote_addr, s.address_family) + ":" + std::to_string(s.remote_port);
        arr.push_back(std::move(entry));
    }
    result["sockets"] = std::move(arr);

    return tool_result_t::ok(
        OBFSTR("Found ") + std::to_string(sockets.size()) + OBFSTR(" socket handle(s)"), result);
}

tool_result_t driver_sniff_network_buffers(const json& params)
{
    if (auto ctx_err = ensure_attached_process_context(params))
        return *ctx_err;


    if (params.contains("operation")) {
        std::string op = params["operation"].get<std::string>();

        if (op == "stop") {
            if (!device->sniff_net_buffers_stop())
                return tool_result_t::error(OBFSTR("Failed to stop sniff session"));
            return tool_result_t::ok(OBFSTR("Sniff session stopped"), json::object());
        }
        if (op == "get" || op == "results") {
            bool active = false;
            auto captures = device->sniff_net_buffers_get(active);

            json result;
            result["active"] = active;
            result["capture_count"] = captures.size();
            json arr = json::array();
            for (const auto& cap : captures) {
                json c;
                c["timestamp"] = cap.timestamp;
                c["thread_id"] = helpers::format_address(static_cast<ea_t>(cap.thread_id));
                c["size"] = cap.buffer.size();


                std::string hex;
                std::size_t show = (cap.buffer.size() < 256) ? cap.buffer.size() : 256;
                for (std::size_t i = 0; i < show; i++) {
                    char hb[4];
                    qsnprintf(hb, sizeof(hb), "%02X ", cap.buffer[i]);
                    hex += hb;
                    if ((i + 1) % 16 == 0) hex += "\n";
                }
                if (show < cap.buffer.size())
                    hex += "... (" + std::to_string(cap.buffer.size() - show) + " more)";
                c["hex_dump"] = hex;


                std::string ascii;
                for (std::size_t i = 0; i < show; i++) {
                    char ch = static_cast<char>(cap.buffer[i]);
                    ascii += (ch >= 0x20 && ch < 0x7F) ? ch : '.';
                }
                c["ascii"] = ascii;
                arr.push_back(std::move(c));
            }
            result["captures"] = std::move(arr);

            return tool_result_t::ok(
                std::to_string(captures.size()) + OBFSTR(" capture(s) retrieved"), result);
        }
    }


    std::uint64_t address = 0;
    if (params.contains("address"))
        address = helpers::parse_address(params["address"].get<std::string>()).value_or(0);
    if (address == 0)
        return tool_result_t::error(OBFSTR("Address of send/recv/encrypt function required"));


    auto reg_name_to_index = [](const std::string& name) -> std::uint32_t {
        static const std::pair<const char*, std::uint32_t> regs[] = {
            {"rax", 0}, {"rcx", 1}, {"rdx", 2}, {"rbx", 3},
            {"rsp", 4}, {"rbp", 5}, {"rsi", 6}, {"rdi", 7},
            {"r8", 8}, {"r9", 9}, {"r10", 10}, {"r11", 11},
            {"r12", 12}, {"r13", 13}, {"r14", 14}, {"r15", 15}
        };
        std::string lower = name;
        std::transform(lower.begin(), lower.end(), lower.begin(),
            [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
        for (const auto& [n, i] : regs)
            if (lower == n) return i;
        return 0;
    };

    std::uint32_t buf_reg = 1;
    if (params.contains("buffer_register"))
        buf_reg = reg_name_to_index(params["buffer_register"].get<std::string>());

    std::uint32_t size_reg = 2;
    if (params.contains("size_register"))
        size_reg = reg_name_to_index(params["size_register"].get<std::string>());

    std::uint32_t max_packets = params.value("max_packets", 1);
    if (max_packets > 16) max_packets = 16;

    std::uint32_t tid = 0;
    if (params.contains("tid"))
        tid = params["tid"].get<std::uint32_t>();

    std::uint32_t bp_index = params.value("bp_index", 0);
    if (bp_index > 3) bp_index = 0;

    if (!device->sniff_net_buffers_start(address, buf_reg, size_reg, max_packets, tid, bp_index))
        return tool_result_t::error(OBFSTR("Failed to start sniff session"));

    json result;
    result["status"] = "started";
    result["target_address"] = helpers::format_address(static_cast<ea_t>(address));
    result["buffer_register"] = reg_index_to_name(buf_reg);
    result["size_register"] = reg_index_to_name(size_reg);
    result["max_captures"] = max_packets;
    result["bp_index"] = bp_index;
    result["note"] = OBFSTR("Sniff session initialized. The HW breakpoint must be set separately via "
        "driver_set_hw_breakpoint on the target address. Then poll with operation='get' to retrieve captures. "
        "After each BP hit, read the buffer from memory using driver_read_memory at the register value, "
        "then call this tool with operation='store' to record it.");

    return tool_result_t::ok(OBFSTR("Sniff session started"), result);
}

tool_result_t driver_dump_tcpip_connections(const json& params)
{
    if (!device->is_connected())
        return tool_result_t::error(OBFSTR("Driver not connected"));

    std::uint32_t target_pid = 0;
    if (params.contains("target_pid"))
        target_pid = params["target_pid"].get<std::uint32_t>();

    std::uint32_t filter_proto = 0;
    if (params.contains("filter_protocol")) {
        auto& fp = params["filter_protocol"];
        if (fp.is_number()) {
            filter_proto = fp.get<std::uint32_t>();
        } else if (fp.is_string()) {
            std::string s = fp.get<std::string>();
            std::transform(s.begin(), s.end(), s.begin(),
                [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
            if (s == "tcp") filter_proto = 6;
            else if (s == "udp") filter_proto = 17;
        }
    }

    auto connections = device->dump_tcpip_connections(target_pid, filter_proto);
    if (connections.empty())
        return tool_result_t::ok(OBFSTR("No connections found"), json::object());

    json result;
    result["count"] = connections.size();
    if (target_pid != 0) result["filtered_pid"] = target_pid;


    std::uint32_t tcp_count = 0, udp_count = 0;
    json arr = json::array();
    for (const auto& c : connections) {
        json entry;
        entry["pid"] = c.pid;
        entry["protocol"] = (c.protocol == 6) ? "TCP" : (c.protocol == 17) ? "UDP" : std::to_string(c.protocol);
        entry["state"] = tcp_state_str(c.state);
        entry["local"] = format_recon_ip(c.local_addr, c.address_family) + ":" + std::to_string(c.local_port);
        entry["remote"] = format_recon_ip(c.remote_addr, c.address_family) + ":" + std::to_string(c.remote_port);
        entry["address_family"] = (c.address_family == 2) ? "IPv4" : "IPv6";

        if (c.create_time != 0)
            entry["create_time"] = c.create_time;
        if (c.tcb_address != 0)
            entry["tcb_address"] = helpers::format_address(static_cast<ea_t>(c.tcb_address));
        if (c.bytes_in != 0 || c.bytes_out != 0) {
            entry["bytes_in"] = c.bytes_in;
            entry["bytes_out"] = c.bytes_out;
        }

        if (c.protocol == 6) tcp_count++;
        else if (c.protocol == 17) udp_count++;

        arr.push_back(std::move(entry));
    }
    result["connections"] = std::move(arr);
    result["tcp_count"] = tcp_count;
    result["udp_count"] = udp_count;

    return tool_result_t::ok(
        OBFSTR("Kernel netstat: ") + std::to_string(connections.size()) +
        OBFSTR(" connection(s) (") + std::to_string(tcp_count) + OBFSTR(" TCP, ") +
        std::to_string(udp_count) + OBFSTR(" UDP)"), result);
}


static bool parse_ip_string(const std::string& ip, std::uint8_t* out16, std::uint32_t* af) {
    std::memset(out16, 0, 16);

    unsigned a, b, c, d;
    if (sscanf(ip.c_str(), "%u.%u.%u.%u", &a, &b, &c, &d) == 4 && a < 256 && b < 256 && c < 256 && d < 256) {
        out16[0] = static_cast<std::uint8_t>(a);
        out16[1] = static_cast<std::uint8_t>(b);
        out16[2] = static_cast<std::uint8_t>(c);
        out16[3] = static_cast<std::uint8_t>(d);
        if (af) *af = 2;
        return true;
    }

    if (ip.find(':') != std::string::npos) {
        if (af) *af = 23;

        unsigned vals[8] = {};
        int count = sscanf(ip.c_str(), "%x:%x:%x:%x:%x:%x:%x:%x",
            &vals[0], &vals[1], &vals[2], &vals[3], &vals[4], &vals[5], &vals[6], &vals[7]);
        for (int i = 0; i < count && i < 8; i++) {
            out16[i*2]   = static_cast<std::uint8_t>((vals[i] >> 8) & 0xFF);
            out16[i*2+1] = static_cast<std::uint8_t>(vals[i] & 0xFF);
        }
        return count > 0;
    }
    return false;
}

static std::string format_mac(const std::uint8_t* mac) {
    char buf[24];
    qsnprintf(buf, sizeof(buf), "%02X:%02X:%02X:%02X:%02X:%02X",
        mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
    return buf;
}

static std::uint32_t proto_from_param(const json& params, const char* key) {
    if (!params.contains(key)) return 0;
    auto& v = params[key];
    if (v.is_number()) return v.get<std::uint32_t>();
    if (v.is_string()) {
        std::string s = v.get<std::string>();
        std::transform(s.begin(), s.end(), s.begin(), [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
        if (s == "tcp") return 6;
        if (s == "udp") return 17;
    }
    return 0;
}

tool_result_t driver_inject_packet(const json& params)
{
    if (!device->is_connected())
        return tool_result_t::error(OBFSTR("Driver not connected"));

    std::uint32_t direction = 1;
    if (params.contains("direction")) {
        auto& d = params["direction"];
        if (d.is_number()) direction = d.get<std::uint32_t>();
        else if (d.is_string()) {
            std::string s = d.get<std::string>();
            if (s == "inbound" || s == "in") direction = 0;
        }
    }

    std::uint32_t protocol = proto_from_param(params, "protocol");
    if (protocol == 0) protocol = 6;

    std::uint8_t src_addr[16] = {}, dst_addr[16] = {};
    std::uint32_t af = 2;
    if (params.contains("src_addr")) parse_ip_string(params["src_addr"].get<std::string>(), src_addr, &af);
    if (params.contains("dst_addr")) parse_ip_string(params["dst_addr"].get<std::string>(), dst_addr, &af);

    std::uint32_t src_port = params.value("src_port", 0u);
    std::uint32_t dst_port = params.value("dst_port", 0u);
    std::uint32_t tcp_flags = params.value("tcp_flags", 0u);
    std::uint32_t tcp_seq = params.value("tcp_seq", 0u);
    std::uint32_t tcp_ack = params.value("tcp_ack", 0u);


    std::vector<std::uint8_t> payload_bytes;
    if (params.contains("payload")) {
        std::string error;
        if (!parse_byte_sequence(params["payload"], payload_bytes, error))
            return tool_result_t::error(OBFSTR("Invalid payload: ") + error);
    }
    if (payload_bytes.empty())
        return tool_result_t::error(OBFSTR("Payload is required"));

    bool ok = device->inject_packet(direction, protocol, af, src_port, dst_port,
                                     src_addr, dst_addr, payload_bytes.data(),
                                     static_cast<std::uint32_t>(payload_bytes.size()),
                                     tcp_flags, tcp_seq, tcp_ack);
    if (!ok) return tool_result_t::error(OBFSTR("Packet injection failed"));

    json result;
    result["direction"] = direction == 0 ? "inbound" : "outbound";
    result["protocol"] = protocol == 6 ? "TCP" : "UDP";
    result["payload_size"] = payload_bytes.size();
    result["dst_port"] = dst_port;
    return tool_result_t::ok(OBFSTR("Packet injected successfully"), result);
}

tool_result_t driver_modify_packet_rule(const json& params)
{
    if (!device->is_connected())
        return tool_result_t::error(OBFSTR("Driver not connected"));

    std::string operation = params.value("operation", "list");
    std::transform(operation.begin(), operation.end(), operation.begin(),
        [](unsigned char c) { return static_cast<char>(std::tolower(c)); });

    if (operation == "list") {
        auto rules = device->list_packet_mod_rules();
        json result;
        result["rule_count"] = rules.size();
        json arr = json::array();
        for (const auto& r : rules) {
            json e;
            e["rule_id"] = r.rule_id;
            e["direction"] = r.direction == 0 ? "in" : r.direction == 1 ? "out" : "both";
            e["protocol"] = r.protocol == 6 ? "TCP" : r.protocol == 17 ? "UDP" : "any";
            e["port"] = r.port;
            e["pid"] = r.pid;
            e["match_count"] = r.match_count;
            e["active"] = r.active != 0;
            arr.push_back(std::move(e));
        }
        result["rules"] = std::move(arr);
        return tool_result_t::ok(OBFSTR("Packet modification rules: ") + std::to_string(rules.size()), result);
    }

    std::uint32_t op_code = 0;
    if (operation == "add") op_code = 0;
    else if (operation == "remove") op_code = 1;
    else if (operation == "clear") op_code = 3;
    else return tool_result_t::error(OBFSTR("Unknown operation: ") + operation);

    std::uint32_t dir = 2;
    if (params.contains("direction")) {
        std::string ds = params["direction"].get<std::string>();
        if (ds == "in" || ds == "inbound") dir = 0;
        else if (ds == "out" || ds == "outbound") dir = 1;
    }

    std::uint32_t proto = proto_from_param(params, "protocol");
    std::uint32_t port = params.value("port", 0u);
    std::uint32_t pid = params.value("pid", 0u);

    std::vector<std::uint8_t> pattern_bytes, replace_bytes;
    if (params.contains("pattern")) {
        std::string err;
        if (!parse_byte_sequence(params["pattern"], pattern_bytes, err))
            return tool_result_t::error(OBFSTR("Invalid pattern: ") + err);
    }
    if (params.contains("replacement")) {
        std::string err;
        if (!parse_byte_sequence(params["replacement"], replace_bytes, err))
            return tool_result_t::error(OBFSTR("Invalid replacement: ") + err);
    }

    std::uint32_t rule_id = 0;
    if (op_code == 1 && params.contains("rule_id"))
        rule_id = params["rule_id"].get<std::uint32_t>();

    std::uint32_t out_id = 0;
    bool ok = device->packet_mod_rule_op(op_code, rule_id, dir, proto, port, pid,
                                          pattern_bytes.data(), static_cast<std::uint32_t>(pattern_bytes.size()),
                                          replace_bytes.data(), static_cast<std::uint32_t>(replace_bytes.size()),
                                          &out_id);
    if (!ok) return tool_result_t::error(OBFSTR("Packet mod rule operation failed"));

    json result;
    result["operation"] = operation;
    if (op_code == 0) result["rule_id"] = out_id;
    return tool_result_t::ok(OBFSTR("Packet mod rule ") + operation + OBFSTR(" success"), result);
}

tool_result_t driver_redirect_traffic(const json& params)
{
    if (!device->is_connected())
        return tool_result_t::error(OBFSTR("Driver not connected"));

    std::string operation = params.value("operation", "list");
    std::transform(operation.begin(), operation.end(), operation.begin(),
        [](unsigned char c) { return static_cast<char>(std::tolower(c)); });

    if (operation == "list") {
        auto rules = device->list_redirect_rules();
        json result;
        result["rule_count"] = rules.size();
        json arr = json::array();
        for (const auto& r : rules) {
            json e;
            e["rule_id"] = r.rule_id;
            e["protocol"] = r.protocol == 6 ? "TCP" : r.protocol == 17 ? "UDP" : "any";
            e["match_port"] = r.match_port;
            e["redirect_port"] = r.redirect_port;
            e["match_count"] = r.match_count;
            e["active"] = r.active != 0;
            arr.push_back(std::move(e));
        }
        result["rules"] = std::move(arr);
        return tool_result_t::ok(OBFSTR("Redirect rules: ") + std::to_string(rules.size()), result);
    }

    std::uint32_t op_code = 0;
    if (operation == "add") op_code = 0;
    else if (operation == "remove") op_code = 1;
    else if (operation == "clear") op_code = 3;
    else return tool_result_t::error(OBFSTR("Unknown operation: ") + operation);

    std::uint32_t proto = proto_from_param(params, "protocol");
    std::uint32_t rule_id = 0;
    if (op_code == 1 && params.contains("rule_id")) {
        rule_id = params["rule_id"].get<std::uint32_t>();
    }
    std::uint32_t match_port = params.value("match_port", 0u);
    std::uint32_t redirect_port = params.value("redirect_port", 0u);
    std::uint8_t match_addr[16] = {}, redir_addr[16] = {};
    std::uint32_t af = 2;
    if (params.contains("match_addr")) parse_ip_string(params["match_addr"].get<std::string>(), match_addr, &af);
    if (params.contains("redirect_addr")) parse_ip_string(params["redirect_addr"].get<std::string>(), redir_addr, &af);

    std::uint32_t out_id = 0;
    bool ok = device->traffic_redirect_op(op_code, rule_id, proto, match_port, match_addr,
                                           redirect_port, redir_addr, af, &out_id);
    if (!ok) return tool_result_t::error(OBFSTR("Redirect operation failed"));

    json result;
    result["operation"] = operation;
    if (op_code == 0) result["rule_id"] = out_id;
    return tool_result_t::ok(OBFSTR("Traffic redirect ") + operation + OBFSTR(" success"), result);
}

tool_result_t driver_reassemble_stream(const json& params)
{
    if (!device->is_connected())
        return tool_result_t::error(OBFSTR("Driver not connected"));

    std::string operation = params.value("operation", "list");
    std::transform(operation.begin(), operation.end(), operation.begin(),
        [](unsigned char c) { return static_cast<char>(std::tolower(c)); });

    std::uint32_t op_code = 3;
    if (operation == "start") op_code = 0;
    else if (operation == "stop") op_code = 1;
    else if (operation == "get" || operation == "get_data") op_code = 2;
    else if (operation == "list") op_code = 3;

    std::uint32_t src_port = params.value("src_port", 0u);
    std::uint32_t dst_port = params.value("dst_port", 0u);
    std::uint32_t pid = params.value("pid", 0u);
    std::uint8_t src_addr[16] = {}, dst_addr[16] = {};
    if (params.contains("src_addr")) parse_ip_string(params["src_addr"].get<std::string>(), src_addr, nullptr);
    if (params.contains("dst_addr")) parse_ip_string(params["dst_addr"].get<std::string>(), dst_addr, nullptr);

    std::vector<std::uint8_t> data;
    std::uint32_t packets = 0, truncated = 0;
    bool ok = device->stream_reassemble_op(op_code, src_port, dst_port, pid,
                                            src_addr, dst_addr, &data, &packets, &truncated);
    if (!ok) return tool_result_t::error(OBFSTR("Stream operation failed"));

    json result;
    result["operation"] = operation;
    result["total_packets"] = packets;
    if (truncated) result["truncated"] = true;
    if (!data.empty()) {
        result["stream_size"] = data.size();

        std::string hex;
        size_t preview = (data.size() > 256) ? 256 : data.size();
        for (size_t i = 0; i < preview; i++) {
            char buf[4];
            qsnprintf(buf, sizeof(buf), "%02X ", data[i]);
            hex += buf;
        }
        result["hex_preview"] = hex;

        std::string ascii;
        for (size_t i = 0; i < preview; i++)
            ascii += (data[i] >= 0x20 && data[i] < 0x7f) ? static_cast<char>(data[i]) : '.';
        result["ascii_preview"] = ascii;
    }

    return tool_result_t::ok(OBFSTR("Stream reassembly ") + operation + OBFSTR(": ") +
        std::to_string(data.size()) + OBFSTR(" bytes, ") + std::to_string(packets) + OBFSTR(" packets"), result);
}

tool_result_t driver_deep_inspect(const json& params)
{
    if (!device->is_connected())
        return tool_result_t::error(OBFSTR("Driver not connected"));

    std::uint32_t filter_pid = params.value("filter_pid", 0u);
    std::uint32_t filter_proto = proto_from_param(params, "filter_protocol");
    std::uint32_t filter_port = params.value("filter_port", 0u);
    std::uint32_t flags = 0;
    if (params.value("http_only", false)) flags |= 1;
    if (params.value("tls_only", false)) flags |= 2;
    if (params.value("dns_only", false)) flags |= 4;

    auto results = device->get_dpi_results(filter_pid, filter_proto, filter_port, flags);
    if (results.empty())
        return tool_result_t::ok(OBFSTR("No DPI results"), json::object());

    static const char* http_methods[] = {"NONE", "GET", "POST", "PUT", "DELETE", "HEAD", "OTHER"};
    json j;
    j["count"] = results.size();
    json arr = json::array();
    for (const auto& d : results) {
        json e;
        e["direction"] = d.direction == 0 ? "in" : "out";
        e["protocol"] = d.protocol == 6 ? "TCP" : d.protocol == 17 ? "UDP" : std::to_string(d.protocol);
        e["pid"] = d.pid;
        e["src"] = format_recon_ip(d.src_addr, d.af) + ":" + std::to_string(d.src_port);
        e["dst"] = format_recon_ip(d.dst_addr, d.af) + ":" + std::to_string(d.dst_port);
        e["payload_size"] = d.payload_size;
        if (d.is_http) {
            e["type"] = "HTTP";
            e["http_method"] = (d.http_method < 7) ? http_methods[d.http_method] : "?";
            if (!d.http_host.empty()) e["http_host"] = d.http_host;
            if (!d.http_path.empty()) e["http_path"] = d.http_path;
        }
        if (d.is_tls) {
            e["type"] = "TLS";
            char ver[16];
            qsnprintf(ver, sizeof(ver), "0x%04X", d.tls_version);
            e["tls_version"] = ver;
            if (!d.tls_sni.empty()) e["tls_sni"] = d.tls_sni;
            e["tls_content_type"] = d.tls_content_type;
        }
        if (d.is_dns) e["type"] = "DNS";
        if (d.tcp_flags != 0) {
            std::string fl;
            if (d.tcp_flags & 0x02) fl += "SYN ";
            if (d.tcp_flags & 0x10) fl += "ACK ";
            if (d.tcp_flags & 0x04) fl += "RST ";
            if (d.tcp_flags & 0x01) fl += "FIN ";
            if (d.tcp_flags & 0x08) fl += "PSH ";
            e["tcp_flags"] = fl;
        }
        arr.push_back(std::move(e));
    }
    j["packets"] = std::move(arr);

    return tool_result_t::ok(OBFSTR("Deep packet inspection: ") + std::to_string(results.size()) + OBFSTR(" packets"), j);
}

tool_result_t driver_intercept_hold(const json& params)
{
    if (!device->is_connected())
        return tool_result_t::error(OBFSTR("Driver not connected"));

    std::string operation = params.value("operation", "status");
    std::transform(operation.begin(), operation.end(), operation.begin(),
        [](unsigned char c) { return static_cast<char>(std::tolower(c)); });

    if (operation == "get" || operation == "get_held") {
        auto held = device->get_held_packets();
        json result;
        result["held_count"] = held.size();
        json arr = json::array();
        for (const auto& h : held) {
            json e;
            e["hold_id"] = h.hold_id;
            e["direction"] = h.direction == 0 ? "in" : "out";
            e["protocol"] = h.protocol == 6 ? "TCP" : "UDP";
            e["pid"] = h.pid;
            e["src"] = format_recon_ip(h.src_addr, h.af) + ":" + std::to_string(h.src_port);
            e["dst"] = format_recon_ip(h.dst_addr, h.af) + ":" + std::to_string(h.dst_port);
            e["payload_size"] = h.payload_size;
            if (!h.payload.empty()) {
                std::string hex;
                size_t preview = (h.payload.size() > 128) ? 128 : h.payload.size();
                for (size_t i = 0; i < preview; i++) {
                    char buf[4];
                    qsnprintf(buf, sizeof(buf), "%02X ", h.payload[i]);
                    hex += buf;
                }
                e["payload_hex_preview"] = hex;
            }
            arr.push_back(std::move(e));
        }
        result["packets"] = std::move(arr);
        return tool_result_t::ok(OBFSTR("Held packets: ") + std::to_string(held.size()), result);
    }

    std::uint32_t op_code;
    if (operation == "enable") op_code = 0;
    else if (operation == "disable") op_code = 1;
    else if (operation == "release") op_code = 3;
    else if (operation == "drop") op_code = 4;
    else if (operation == "modify" || operation == "modify_release") op_code = 5;
    else if (operation == "status") {
        std::uint32_t held_count = 0;
        bool active = false;
        device->intercept_op(2, 0, 0, 0, 0, nullptr, 0, &held_count, &active);
        json r;
        r["intercepting"] = active;
        r["held_count"] = held_count;
        return tool_result_t::ok(active ? OBFSTR("Intercept active") : OBFSTR("Intercept inactive"), r);
    }
    else return tool_result_t::error(OBFSTR("Unknown operation: ") + operation);

    std::uint32_t filter_pid = params.value("filter_pid", 0u);
    std::uint32_t filter_port = params.value("filter_port", 0u);
    std::uint32_t filter_proto = proto_from_param(params, "filter_protocol");
    std::uint64_t hold_id = params.value("hold_id", std::uint64_t(0));

    std::vector<std::uint8_t> mod_payload;
    if (op_code == 5 && params.contains("modify_payload")) {
        std::string err;
        if (!parse_byte_sequence(params["modify_payload"], mod_payload, err))
            return tool_result_t::error(OBFSTR("Invalid modify_payload: ") + err);
    }

    std::uint32_t held_count = 0;
    bool active = false;
    bool ok = device->intercept_op(op_code, filter_pid, filter_port, filter_proto, hold_id,
                                    mod_payload.empty() ? nullptr : mod_payload.data(),
                                    static_cast<std::uint32_t>(mod_payload.size()),
                                    &held_count, &active);
    if (!ok) return tool_result_t::error(OBFSTR("Intercept operation failed"));

    json result;
    result["operation"] = operation;
    result["intercepting"] = active;
    result["held_count"] = held_count;
    return tool_result_t::ok(OBFSTR("Intercept ") + operation + OBFSTR(" success"), result);
}

tool_result_t driver_kill_connection(const json& params)
{
    if (!device->is_connected())
        return tool_result_t::error(OBFSTR("Driver not connected"));

    std::uint8_t src_addr[16] = {}, dst_addr[16] = {};
    std::uint32_t af = 2;
    if (params.contains("src_addr")) parse_ip_string(params["src_addr"].get<std::string>(), src_addr, &af);
    if (params.contains("dst_addr")) parse_ip_string(params["dst_addr"].get<std::string>(), dst_addr, &af);

    std::uint32_t src_port = params.value("src_port", 0u);
    std::uint32_t dst_port = params.value("dst_port", 0u);
    std::uint32_t proto = proto_from_param(params, "protocol");
    if (proto == 0) proto = 6;
    std::uint32_t pid = params.value("pid", 0u);

    bool ok = device->kill_connection(proto, af, src_port, dst_port, src_addr, dst_addr, pid);
    if (!ok) return tool_result_t::error(OBFSTR("Connection kill failed"));

    json result;
    result["killed"] = true;
    result["src_port"] = src_port;
    result["dst_port"] = dst_port;
    return tool_result_t::ok(OBFSTR("TCP connection killed via RST injection"), result);
}

tool_result_t driver_spoof_dns(const json& params)
{
    if (!device->is_connected())
        return tool_result_t::error(OBFSTR("Driver not connected"));

    std::string operation = params.value("operation", "list");
    std::transform(operation.begin(), operation.end(), operation.begin(),
        [](unsigned char c) { return static_cast<char>(std::tolower(c)); });

    if (operation == "list") {
        auto rules = device->list_dns_spoof_rules();
        json result;
        result["rule_count"] = rules.size();
        json arr = json::array();
        for (const auto& r : rules) {
            json e;
            e["rule_id"] = r.rule_id;
            e["domain"] = r.domain;
            e["address_family"] = r.af == 2 ? "IPv4" : "IPv6";
            e["match_count"] = r.match_count;
            e["active"] = r.active != 0;
            e["ttl"] = r.ttl;
            arr.push_back(std::move(e));
        }
        result["rules"] = std::move(arr);
        return tool_result_t::ok(OBFSTR("DNS spoof rules: ") + std::to_string(rules.size()), result);
    }

    std::uint32_t op_code;
    if (operation == "add") op_code = 0;
    else if (operation == "remove") op_code = 1;
    else if (operation == "clear") op_code = 3;
    else return tool_result_t::error(OBFSTR("Unknown operation: ") + operation);

    std::uint32_t rule_id = 0;
    if (op_code == 1 && params.contains("rule_id")) {
        rule_id = params["rule_id"].get<std::uint32_t>();
    }

    std::string domain = params.value("domain", "");
    std::uint8_t spoof[16] = {};
    std::uint32_t af = 2;
    if (params.contains("spoof_addr")) parse_ip_string(params["spoof_addr"].get<std::string>(), spoof, &af);
    std::uint32_t ttl = params.value("ttl", 300u);

    std::uint32_t out_id = 0;
    bool ok = device->dns_spoof_op(op_code, rule_id, domain.c_str(), spoof, af, ttl, &out_id);
    if (!ok) return tool_result_t::error(OBFSTR("DNS spoof operation failed"));

    json result;
    result["operation"] = operation;
    if (op_code == 0) result["rule_id"] = out_id;
    return tool_result_t::ok(OBFSTR("DNS spoof ") + operation + OBFSTR(" success"), result);
}

tool_result_t driver_bandwidth_monitor(const json& params)
{
    if (!device->is_connected())
        return tool_result_t::error(OBFSTR("Driver not connected"));

    std::string operation = params.value("operation", "status");
    std::transform(operation.begin(), operation.end(), operation.begin(),
        [](unsigned char c) { return static_cast<char>(std::tolower(c)); });

    std::uint32_t op_code;
    if (operation == "start") op_code = 0;
    else if (operation == "stop") op_code = 1;
    else if (operation == "status" || operation == "get" || operation == "stats") op_code = 2;
    else if (operation == "reset") op_code = 3;
    else if (operation == "per_process") op_code = 4;
    else return tool_result_t::error(OBFSTR("Unknown operation: ") + operation);

    std::uint32_t filter_pid = params.value("filter_pid", 0u);

    if (op_code == 4) {
        auto procs = device->get_bw_per_process(filter_pid);
        json result;
        result["process_count"] = procs.size();
        json arr = json::array();
        for (const auto& p : procs) {
            json e;
            e["pid"] = p.pid;
            e["bytes_sent"] = p.bytes_sent;
            e["bytes_recv"] = p.bytes_recv;
            e["packets_sent"] = p.packets_sent;
            e["packets_recv"] = p.packets_recv;
            arr.push_back(std::move(e));
        }
        result["processes"] = std::move(arr);
        return tool_result_t::ok(OBFSTR("Per-process bandwidth: ") + std::to_string(procs.size()) + OBFSTR(" processes"), result);
    }

    voyager::device_t::bw_stats stats{};
    bool ok = device->bw_monitor_op(op_code, filter_pid, &stats);
    if (!ok) return tool_result_t::error(OBFSTR("Bandwidth monitor operation failed"));

    json result;
    result["operation"] = operation;
    result["monitoring_active"] = stats.active;
    result["total_bytes_sent"] = stats.total_bytes_sent;
    result["total_bytes_recv"] = stats.total_bytes_recv;
    result["total_packets_sent"] = stats.total_packets_sent;
    result["total_packets_recv"] = stats.total_packets_recv;
    result["bytes_per_second_in"] = stats.bps_in;
    result["bytes_per_second_out"] = stats.bps_out;
    return tool_result_t::ok(OBFSTR("Bandwidth monitor ") + operation, result);
}

tool_result_t driver_list_interfaces(const json& params)
{
    if (!device->is_connected())
        return tool_result_t::error(OBFSTR("Driver not connected"));

    auto ifaces = device->enumerate_interfaces();
    if (ifaces.empty())
        return tool_result_t::ok(OBFSTR("No network interfaces found"), json::object());

    json result;
    result["count"] = ifaces.size();
    json arr = json::array();
    for (const auto& iface : ifaces) {
        json e;
        e["index"] = iface.if_index;
        e["type"] = iface.if_type == 6 ? "Ethernet" : iface.if_type == 71 ? "WiFi" :
                    iface.if_type == 24 ? "Loopback" : std::to_string(iface.if_type);
        e["mtu"] = iface.mtu;
        e["status"] = iface.oper_status == 1 ? "Up" : "Down";
        e["speed_mbps"] = iface.speed / 1000000;
        e["mac"] = format_mac(iface.mac_addr);
        char ipv4[20];
        qsnprintf(ipv4, sizeof(ipv4), "%u.%u.%u.%u", iface.ipv4_addr[0], iface.ipv4_addr[1],
                  iface.ipv4_addr[2], iface.ipv4_addr[3]);
        e["ipv4"] = ipv4;
        if (!iface.name.empty()) e["name"] = iface.name;
        if (!iface.description.empty()) e["description"] = iface.description;
        e["in_bytes"] = iface.in_octets;
        e["out_bytes"] = iface.out_octets;
        arr.push_back(std::move(e));
    }
    result["interfaces"] = std::move(arr);

    return tool_result_t::ok(OBFSTR("Network interfaces: ") + std::to_string(ifaces.size()), result);
}

tool_result_t driver_export_pcap(const json& params)
{
    if (!device->is_connected())
        return tool_result_t::error(OBFSTR("Driver not connected"));

    std::uint32_t filter_pid = params.value("filter_pid", 0u);
    std::uint32_t filter_proto = proto_from_param(params, "filter_protocol");
    std::uint32_t max_packets = params.value("max_packets", 64u);

    voyager::device_t::pcap_export_result pcap{};
    bool ok = device->export_pcap(filter_pid, filter_proto, max_packets, &pcap);
    if (!ok) return tool_result_t::error(OBFSTR("PCAP export failed"));


    if (params.contains("output_path")) {
        std::string path = params["output_path"].get<std::string>();
        FILE* fp = qfopen(path.c_str(), "wb");
        if (fp) {
            qfwrite(fp, &pcap.header, sizeof(pcap.header));
            for (const auto& pkt : pcap.packets) {
                std::uint32_t hdr[4] = { pkt.ts_sec, pkt.ts_usec,
                    static_cast<std::uint32_t>(pkt.data.size()),
                    static_cast<std::uint32_t>(pkt.data.size()) };
                qfwrite(fp, hdr, sizeof(hdr));
                qfwrite(fp, pkt.data.data(), pkt.data.size());
            }
            qfclose(fp);
        }

        json result;
        result["output_path"] = path;
        result["packet_count"] = pcap.packets.size();
        return tool_result_t::ok(OBFSTR("PCAP saved: ") + std::to_string(pcap.packets.size()) +
            OBFSTR(" packets -> ") + path, result);
    }

    json result;
    result["packet_count"] = pcap.packets.size();
    result["link_type"] = pcap.header.network;
    json arr = json::array();
    for (const auto& pkt : pcap.packets) {
        json e;
        e["ts_sec"] = pkt.ts_sec;
        e["ts_usec"] = pkt.ts_usec;
        e["size"] = pkt.data.size();
        if (!pkt.data.empty()) {
            std::string hex;
            size_t preview = (pkt.data.size() > 64) ? 64 : pkt.data.size();
            for (size_t i = 0; i < preview; i++) {
                char buf[4];
                qsnprintf(buf, sizeof(buf), "%02X ", pkt.data[i]);
                hex += buf;
            }
            e["hex_preview"] = hex;
        }
        arr.push_back(std::move(e));
    }
    result["packets"] = std::move(arr);

    return tool_result_t::ok(OBFSTR("PCAP export: ") + std::to_string(pcap.packets.size()) + OBFSTR(" packets"), result);
}

tool_result_t driver_network_fingerprint(const json& params)
{
    if (!device->is_connected())
        return tool_result_t::error(OBFSTR("Driver not connected"));

    std::string operation = params.value("operation", "get");
    std::transform(operation.begin(), operation.end(), operation.begin(),
        [](unsigned char c) { return static_cast<char>(std::tolower(c)); });

    if (operation == "enable") {
        bool ok = device->fingerprint_op(0);
        return ok ? tool_result_t::ok(OBFSTR("Fingerprinting enabled"), json::object())
                  : tool_result_t::error(OBFSTR("Failed to enable fingerprinting"));
    }
    if (operation == "disable") {
        bool ok = device->fingerprint_op(1);
        return ok ? tool_result_t::ok(OBFSTR("Fingerprinting disabled"), json::object())
                  : tool_result_t::error(OBFSTR("Failed to disable fingerprinting"));
    }


    auto fps = device->get_fingerprints();
    if (fps.empty())
        return tool_result_t::ok(OBFSTR("No fingerprint results"), json::object());

    json result;
    result["count"] = fps.size();
    json arr = json::array();
    for (const auto& f : fps) {
        json e;
        e["remote"] = format_recon_ip(f.remote_addr, f.af);
        e["ttl"] = f.ttl;
        e["window_size"] = f.window_size;
        e["mss"] = f.mss;
        e["window_scale"] = f.window_scale;
        e["df_flag"] = f.df_flag != 0;
        e["sack"] = f.sack_permitted != 0;
        if (!f.os_guess.empty()) e["os_guess"] = f.os_guess;
        arr.push_back(std::move(e));
    }
    result["fingerprints"] = std::move(arr);

    return tool_result_t::ok(OBFSTR("Network fingerprints: ") + std::to_string(fps.size()) + OBFSTR(" hosts"), result);
}


tool_result_t driver_enum_kernel_callbacks(const json& params)
{
    if (!device->is_connected())
        return tool_result_t::error(OBFSTR("Driver not connected. Call driver_connect first."));
    if (device->get_kernel_dtb() == 0)
        return tool_result_t::error(OBFSTR("Kernel DTB not resolved. Call driver_connect first."));

    std::vector<std::uint8_t> mod_buf;
    sys_module_info_t* info = nullptr;
    std::string err;
    if (!query_kernel_modules(mod_buf, info, err))
        return tool_result_t::error(err);


    std::uint64_t ntos_base = 0;
    std::uint64_t ntos_size = 0;
    for (ULONG i = 0; i < info->NumberOfModules; ++i)
    {
        std::string path(reinterpret_cast<const char*>(info->Modules[i].FullPathName));
        std::string lower = path;
        std::transform(lower.begin(), lower.end(), lower.begin(), ::tolower);
        if (lower.find("ntoskrnl") != std::string::npos || lower.find("ntkrnlmp") != std::string::npos ||
            lower.find("ntkrnlpa") != std::string::npos || lower.find("ntkrpamp") != std::string::npos)
        {
            ntos_base = reinterpret_cast<std::uint64_t>(info->Modules[i].ImageBase);
            ntos_size = info->Modules[i].ImageSize;
            break;
        }
    }

    if (ntos_base == 0)
        return tool_result_t::error(OBFSTR("Could not locate ntoskrnl.exe base via NtQuerySystemInformation"));

    json result;
    result["ntoskrnl_base"] = helpers::format_address(static_cast<ea_t>(ntos_base));
    result["ntoskrnl_size"] = ntos_size;


    struct cb_type {
        const char* name;
        const char* export_name;
        int max_slots;
    };
    cb_type types[] = {
        {"PsSetCreateProcessNotifyRoutine", "PsSetCreateProcessNotifyRoutine", 64},
        {"PsSetCreateThreadNotifyRoutine",  "PsSetCreateThreadNotifyRoutine",  64},
        {"PsSetLoadImageNotifyRoutine",     "PsSetLoadImageNotifyRoutine",     64},
        {"CmRegisterCallback",              "CmRegisterCallbackEx",            64},
        {"ObRegisterCallbacks",             "ObRegisterCallbacks",             64},
    };

    json all_callbacks = json::array();
    for (const auto& t : types)
    {
        std::uint64_t fn_addr = device->resolve_export(ntos_base, t.export_name);
        if (fn_addr == 0) continue;

        json cb;
        cb["type"] = t.name;
        cb["registration_function"] = helpers::format_address(static_cast<ea_t>(fn_addr));


        std::uint8_t code[128] = {};
        device->read_kernel_raw(fn_addr, code, sizeof(code));

        json array_refs = json::array();
        for (int off = 0; off + 7 <= 128; ++off)
        {

            if ((code[off] == 0x48 || code[off] == 0x4C) &&
                code[off + 1] == 0x8D &&
                (code[off + 2] & 0xC7) == 0x05)
            {
                std::int32_t disp;
                std::memcpy(&disp, &code[off + 3], 4);
                std::uint64_t target = fn_addr + off + 7 + disp;

                if (is_probably_kernel_address(target))
                {
                    json ref;
                    ref["array_address"] = helpers::format_address(static_cast<ea_t>(target));
                    ref["instruction_offset"] = off;


                    json entries = json::array();
                    for (int slot = 0; slot < t.max_slots; ++slot)
                    {
                        std::uint64_t entry = 0;
                        device->read_kernel_raw(target + slot * 8, &entry, 8);
                        if (entry == 0) break;


                        std::uint64_t cb_body = entry & ~0xFULL;
                        if (!is_probably_kernel_address(cb_body)) continue;


                        std::uint64_t routine = 0;
                        device->read_kernel_raw(cb_body + 8, &routine, 8);

                        json e;
                        e["slot"]    = slot;
                        e["raw"]     = helpers::format_address(static_cast<ea_t>(entry));
                        e["block"]   = helpers::format_address(static_cast<ea_t>(cb_body));
                        e["routine"] = helpers::format_address(static_cast<ea_t>(routine));


                        if (is_probably_kernel_address(routine))
                        {
                            for (ULONG mi = 0; mi < info->NumberOfModules; ++mi)
                            {
                                std::uint64_t mb = reinterpret_cast<std::uint64_t>(info->Modules[mi].ImageBase);
                                std::uint64_t me = mb + info->Modules[mi].ImageSize;
                                if (routine >= mb && routine < me)
                                {
                                    std::string fp(reinterpret_cast<const char*>(info->Modules[mi].FullPathName));
                                    auto slash = fp.find_last_of("\\/");
                                    e["owner_module"] = (slash != std::string::npos) ? fp.substr(slash + 1) : fp;
                                    break;
                                }
                            }
                        }
                        entries.push_back(std::move(e));
                    }
                    ref["callbacks"] = std::move(entries);
                    ref["count"]     = ref["callbacks"].size();
                    array_refs.push_back(std::move(ref));
                }
            }
        }
        cb["arrays"] = std::move(array_refs);
        all_callbacks.push_back(std::move(cb));
    }

    result["callback_types"] = std::move(all_callbacks);
    result["note"] = OBFSTR("Kernel callbacks are used by anti-cheats (EAC/BattlEye/Vanguard) to monitor "
                            "process creation, thread creation, image loading, and registry access.");
    return tool_result_t::ok(OBFSTR("Kernel callback enumeration complete"), result);
}


tool_result_t driver_detect_integrity_checks(const json& params)
{
    if (!device->is_connected())
        return tool_result_t::error(OBFSTR("Driver not connected. Call driver_connect first."));
    if (device->get_kernel_dtb() == 0)
        return tool_result_t::error(OBFSTR("Kernel DTB not resolved. Call driver_connect first."));

    std::vector<std::uint8_t> mod_buf;
    sys_module_info_t* info = nullptr;
    std::string err;
    if (!query_kernel_modules(mod_buf, info, err))
        return tool_result_t::error(err);


    std::uint64_t ntos_base = 0;
    for (ULONG i = 0; i < info->NumberOfModules; ++i)
    {
        std::string path(reinterpret_cast<const char*>(info->Modules[i].FullPathName));
        std::string lower = path;
        std::transform(lower.begin(), lower.end(), lower.begin(), ::tolower);
        if (lower.find("ntoskrnl") != std::string::npos || lower.find("ntkrnlmp") != std::string::npos)
        {
            ntos_base = reinterpret_cast<std::uint64_t>(info->Modules[i].ImageBase);
            break;
        }
    }
    if (ntos_base == 0)
        return tool_result_t::error(OBFSTR("Could not locate ntoskrnl.exe base"));


    static const char* critical_exports[] = {
        "NtReadVirtualMemory", "NtWriteVirtualMemory", "NtOpenProcess",
        "NtAllocateVirtualMemory", "NtProtectVirtualMemory", "NtQueryVirtualMemory",
        "NtCreateThreadEx", "NtDeviceIoControlFile", "NtQuerySystemInformation",
        "NtSetInformationThread", "NtClose", "NtDuplicateObject",
        "MmCopyVirtualMemory", "KeStackAttachProcess", "KeUnstackDetachProcess",
        "PsLookupProcessByProcessId", "PsLookupThreadByThreadId",
        "ObOpenObjectByPointer", "MmProbeAndLockPages",
        nullptr
    };

    json hooks = json::array();
    json clean = json::array();
    int checked = 0;

    for (int fi = 0; critical_exports[fi]; ++fi)
    {
        std::uint64_t fn = device->resolve_export(ntos_base, critical_exports[fi]);
        if (fn == 0) continue;
        ++checked;


        std::uint8_t bytes[16] = {};
        device->read_kernel_raw(fn, bytes, 16);

        std::string hook_type;
        std::uint64_t hook_target = 0;


        if (bytes[0] == 0xE9)
        {
            std::int32_t rel;
            std::memcpy(&rel, &bytes[1], 4);
            hook_target = fn + 5 + rel;
            hook_type = "jmp_rel32";
        }
        else if (bytes[0] == 0xFF && bytes[1] == 0x25)
        {
            std::int32_t disp;
            std::memcpy(&disp, &bytes[2], 4);
            std::uint64_t ptr = fn + 6 + disp;
            device->read_kernel_raw(ptr, &hook_target, 8);
            hook_type = "jmp_indirect_rip";
        }
        else if (bytes[0] == 0x48 && bytes[1] == 0xB8 && bytes[10] == 0xFF && bytes[11] == 0xE0)
        {
            std::memcpy(&hook_target, &bytes[2], 8);
            hook_type = "mov_rax_jmp_rax";
        }
        else if (bytes[0] == 0xCC)
        {
            hook_type = "int3_breakpoint";
        }

        if (!hook_type.empty())
        {
            json h;
            h["function"] = critical_exports[fi];
            h["address"]  = helpers::format_address(static_cast<ea_t>(fn));
            h["hook_type"] = hook_type;
            if (hook_target != 0)
            {
                h["target"] = helpers::format_address(static_cast<ea_t>(hook_target));

                for (ULONG mi = 0; mi < info->NumberOfModules; ++mi)
                {
                    std::uint64_t mb = reinterpret_cast<std::uint64_t>(info->Modules[mi].ImageBase);
                    std::uint64_t me = mb + info->Modules[mi].ImageSize;
                    if (hook_target >= mb && hook_target < me)
                    {
                        std::string fp(reinterpret_cast<const char*>(info->Modules[mi].FullPathName));
                        auto slash = fp.find_last_of("\\/");
                        h["hook_owner"] = (slash != std::string::npos) ? fp.substr(slash + 1) : fp;
                        break;
                    }
                }
            }
            std::ostringstream hex;
            for (int b = 0; b < 16; ++b) { if (b) hex << " "; hex << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(bytes[b]); }
            h["prologue_bytes"] = hex.str();
            hooks.push_back(std::move(h));
        }
        else
        {
            json c;
            c["function"] = critical_exports[fi];
            c["address"]  = helpers::format_address(static_cast<ea_t>(fn));
            c["status"]   = "clean";
            clean.push_back(std::move(c));
        }
    }

    json result;
    result["ntoskrnl_base"]     = helpers::format_address(static_cast<ea_t>(ntos_base));
    result["functions_checked"] = checked;
    result["hooks_found"]       = hooks.size();
    result["hooked_functions"]  = std::move(hooks);
    result["clean_functions"]   = std::move(clean);
    result["note"] = OBFSTR("Kernel function hooks indicate anti-cheat monitoring. Hooked functions route through "
                            "the anti-cheat driver, which can block, log, or alter calls from target processes.");
    return tool_result_t::ok(OBFSTR("Kernel integrity: ") + std::to_string(result["hooks_found"].get<std::size_t>()) +
                             OBFSTR(" hooks in ") + std::to_string(checked) + OBFSTR(" functions"), result);
}


tool_result_t driver_detect_ssdt_hooks(const json& params)
{
    if (!device->is_connected())
        return tool_result_t::error(OBFSTR("Driver not connected. Call driver_connect first."));
    if (device->get_kernel_dtb() == 0)
        return tool_result_t::error(OBFSTR("Kernel DTB not resolved. Call driver_connect first."));

    std::vector<uint8_t> buf;
    sys_module_info_t* info = nullptr;
    std::string err;
    if (!query_kernel_modules(buf, info, err))
        return tool_result_t::error(OBFSTR("Failed to enumerate kernel modules: ") + err);

    std::uint64_t ntos_base = 0, ntos_size = 0;
    for (ULONG i = 0; i < info->NumberOfModules; ++i)
    {
        std::string fp(reinterpret_cast<const char*>(info->Modules[i].FullPathName));
        std::transform(fp.begin(), fp.end(), fp.begin(), ::tolower);
        if (fp.find("ntoskrnl") != std::string::npos || fp.find("ntkrnlmp") != std::string::npos ||
            fp.find("ntkrnlpa") != std::string::npos || fp.find("ntkrpamp") != std::string::npos)
        {
            ntos_base = reinterpret_cast<std::uint64_t>(info->Modules[i].ImageBase);
            ntos_size = info->Modules[i].ImageSize;
            break;
        }
    }
    if (ntos_base == 0)
        return tool_result_t::error(OBFSTR("Could not find ntoskrnl base address"));


    std::uint64_t ssdt_addr = device->resolve_export(ntos_base, "KeServiceDescriptorTable");
    if (ssdt_addr == 0)
        return tool_result_t::error(OBFSTR("Could not resolve KeServiceDescriptorTable export"));


    struct ssdt_entry_t {
        std::uint64_t service_table;
        std::uint64_t counter_table;
        std::uint32_t num_services;
        std::uint32_t _pad;
        std::uint64_t param_table;
    };
    ssdt_entry_t ssdt{};
    if (device->read_kernel_raw(ssdt_addr, &ssdt, sizeof(ssdt)) < sizeof(ssdt))
        return tool_result_t::error(OBFSTR("Failed to read SSDT structure"));

    if (ssdt.num_services == 0 || ssdt.num_services > 2048)
        return tool_result_t::error(OBFSTR("Invalid SSDT service count: ") + std::to_string(ssdt.num_services));
    if (!is_probably_kernel_address(ssdt.service_table))
        return tool_result_t::error(OBFSTR("ServiceTableBase is not a valid kernel address"));


    std::vector<std::int32_t> entries(ssdt.num_services);
    size_t read_sz = ssdt.num_services * sizeof(std::int32_t);
    if (device->read_kernel_raw(ssdt.service_table, entries.data(), read_sz) < read_sz)
        return tool_result_t::error(OBFSTR("Failed to read SSDT entries"));

    json hooked = json::array();
    json clean_count_json;
    int hooks_found = 0, clean_count = 0;
    std::uint64_t ntos_end = ntos_base + ntos_size;

    for (std::uint32_t i = 0; i < ssdt.num_services; ++i)
    {

        std::uint64_t fn = ssdt.service_table + (static_cast<std::uint64_t>(entries[i]) >> 4);

        bool inside_ntos = (fn >= ntos_base && fn < ntos_end);
        if (!inside_ntos)
        {
            json h;
            h["syscall_id"]    = i;
            h["address"]       = helpers::format_address(static_cast<ea_t>(fn));
            h["status"]        = "hooked";


            for (ULONG mi = 0; mi < info->NumberOfModules; ++mi)
            {
                std::uint64_t mb = reinterpret_cast<std::uint64_t>(info->Modules[mi].ImageBase);
                std::uint64_t me = mb + info->Modules[mi].ImageSize;
                if (fn >= mb && fn < me)
                {
                    std::string fp(reinterpret_cast<const char*>(info->Modules[mi].FullPathName));
                    auto slash = fp.find_last_of("\\/");
                    h["hook_owner"] = (slash != std::string::npos) ? fp.substr(slash + 1) : fp;
                    break;
                }
            }
            hooked.push_back(std::move(h));
            ++hooks_found;
        }
        else
        {
            ++clean_count;
        }
    }

    json result;
    result["ssdt_address"]      = helpers::format_address(static_cast<ea_t>(ssdt_addr));
    result["service_table"]     = helpers::format_address(static_cast<ea_t>(ssdt.service_table));
    result["total_services"]    = ssdt.num_services;
    result["hooks_found"]       = hooks_found;
    result["clean_services"]    = clean_count;
    result["ntoskrnl_range"]    = helpers::format_address(static_cast<ea_t>(ntos_base)) + " - " +
                                  helpers::format_address(static_cast<ea_t>(ntos_end));
    result["hooked_entries"]    = std::move(hooked);
    result["note"] = OBFSTR("SSDT hooks redirect syscalls to third-party kernel code. Anti-cheats commonly hook "
                            "NtReadVirtualMemory, NtWriteVirtualMemory, NtOpenProcess to intercept memory access.");

    return tool_result_t::ok(OBFSTR("SSDT: ") + std::to_string(hooks_found) + OBFSTR(" hooks in ") +
                             std::to_string(ssdt.num_services) + OBFSTR(" services"), result);
}


tool_result_t driver_enum_minifilters(const json& params)
{
    if (!device->is_connected())
        return tool_result_t::error(OBFSTR("Driver not connected. Call driver_connect first."));
    if (device->get_kernel_dtb() == 0)
        return tool_result_t::error(OBFSTR("Kernel DTB not resolved. Call driver_connect first."));

    std::vector<uint8_t> buf;
    sys_module_info_t* info = nullptr;
    std::string err;
    if (!query_kernel_modules(buf, info, err))
        return tool_result_t::error(OBFSTR("Failed to enumerate kernel modules: ") + err);


    std::uint64_t fltmgr_base = 0, fltmgr_size = 0;
    for (ULONG i = 0; i < info->NumberOfModules; ++i)
    {
        std::string fp(reinterpret_cast<const char*>(info->Modules[i].FullPathName));
        std::transform(fp.begin(), fp.end(), fp.begin(), ::tolower);
        if (fp.find("fltmgr.sys") != std::string::npos)
        {
            fltmgr_base = reinterpret_cast<std::uint64_t>(info->Modules[i].ImageBase);
            fltmgr_size = info->Modules[i].ImageSize;
            break;
        }
    }
    if (fltmgr_base == 0)
        return tool_result_t::error(OBFSTR("Filter Manager (fltmgr.sys) not found in loaded modules"));


    uint8_t pe_hdr[0x1000];
    device->read_kernel_raw(fltmgr_base, pe_hdr, sizeof(pe_hdr));

    std::uint32_t pe_off = *reinterpret_cast<std::uint32_t*>(&pe_hdr[0x3C]);
    if (pe_off + 0x18 + 0x70 > sizeof(pe_hdr))
        return tool_result_t::error(OBFSTR("Invalid fltmgr PE header"));

    std::uint16_t num_sections = *reinterpret_cast<std::uint16_t*>(&pe_hdr[pe_off + 6]);
    std::uint16_t opt_hdr_sz   = *reinterpret_cast<std::uint16_t*>(&pe_hdr[pe_off + 20]);
    std::uint32_t section_off  = pe_off + 24 + opt_hdr_sz;

    std::uint64_t data_rva = 0, data_size = 0;
    for (int s = 0; s < num_sections && (section_off + 40 <= sizeof(pe_hdr)); ++s, section_off += 40)
    {
        char name[9] = {};
        std::memcpy(name, &pe_hdr[section_off], 8);
        std::uint32_t vs = *reinterpret_cast<std::uint32_t*>(&pe_hdr[section_off + 8]);
        std::uint32_t va = *reinterpret_cast<std::uint32_t*>(&pe_hdr[section_off + 12]);
        if (std::string(name) == ".data")
        {
            data_rva  = va;
            data_size = vs;
            break;
        }
    }
    if (data_rva == 0)
        return tool_result_t::error(OBFSTR("Could not find fltmgr .data section"));


    std::uint64_t data_addr = fltmgr_base + data_rva;
    size_t scan_sz = static_cast<size_t>(std::min(data_size, std::uint64_t{0x20000}));
    std::vector<uint8_t> data_buf(scan_sz);
    device->read_kernel_raw(data_addr, data_buf.data(), scan_sz);


    json filters = json::array();
    std::set<std::uint64_t> visited;

    for (size_t off = 0; off + 16 <= scan_sz; off += 8)
    {
        std::uint64_t flink = *reinterpret_cast<std::uint64_t*>(&data_buf[off]);
        std::uint64_t blink = *reinterpret_cast<std::uint64_t*>(&data_buf[off + 8]);

        if (!is_probably_kernel_address(flink) || !is_probably_kernel_address(blink)) continue;

        std::uint64_t head = data_addr + off;
        if (flink == head) continue;
        if (visited.count(flink)) continue;


        std::uint64_t cur = flink;
        int walk_count = 0;
        bool valid_chain = true;
        std::vector<std::uint64_t> entries_found;

        while (cur != head && walk_count < 64)
        {
            if (!is_probably_kernel_address(cur)) { valid_chain = false; break; }
            entries_found.push_back(cur);
            visited.insert(cur);


            std::uint64_t next = 0;
            if (device->read_kernel_raw(cur, &next, 8) < 8) { valid_chain = false; break; }
            if (next == cur) { valid_chain = false; break; }
            cur = next;
            ++walk_count;
        }

        if (!valid_chain || entries_found.empty() || walk_count < 1) continue;


        for (auto& entry_addr : entries_found)
        {

            uint8_t block[0x200];
            if (device->read_kernel_raw(entry_addr, block, sizeof(block)) < sizeof(block)) continue;


            for (int noff : {0x28, 0x38, 0x48, 0x58, 0x68, 0x78})
            {
                if (noff + 16 > (int)sizeof(block)) break;
                std::uint16_t len     = *reinterpret_cast<std::uint16_t*>(&block[noff]);
                std::uint16_t max_len = *reinterpret_cast<std::uint16_t*>(&block[noff + 2]);
                std::uint64_t buf_ptr = *reinterpret_cast<std::uint64_t*>(&block[noff + 8]);

                if (len == 0 || len > 512 || max_len < len || !is_probably_kernel_address(buf_ptr)) continue;


                std::vector<wchar_t> name_buf(len / 2 + 1, 0);
                if (device->read_kernel_raw(buf_ptr, name_buf.data(), len) < len) continue;

                std::wstring wname(name_buf.data());
                if (wname.empty()) continue;


                bool looks_valid = true;
                for (auto wc : wname)
                {
                    if (wc == 0) break;
                    if (wc < 0x20 || wc > 0x7E) { looks_valid = false; break; }
                }
                if (!looks_valid) continue;

                std::string name_str(wname.begin(), wname.end());


                std::string altitude_str;
                if (noff + 0x20 + 16 <= (int)sizeof(block))
                {
                    std::uint16_t alen  = *reinterpret_cast<std::uint16_t*>(&block[noff + 0x10]);
                    std::uint64_t abuf  = *reinterpret_cast<std::uint64_t*>(&block[noff + 0x18]);
                    if (alen > 0 && alen <= 64 && is_probably_kernel_address(abuf))
                    {
                        std::vector<wchar_t> abuf_data(alen / 2 + 1, 0);
                        if (device->read_kernel_raw(abuf, abuf_data.data(), alen) >= alen)
                        {
                            std::wstring walt(abuf_data.data());
                            altitude_str = std::string(walt.begin(), walt.end());
                        }
                    }
                }

                json f;
                f["address"]  = helpers::format_address(static_cast<ea_t>(entry_addr));
                f["name"]     = name_str;
                if (!altitude_str.empty()) f["altitude"] = altitude_str;


                for (ULONG mi = 0; mi < info->NumberOfModules; ++mi)
                {
                    std::uint64_t mb = reinterpret_cast<std::uint64_t>(info->Modules[mi].ImageBase);
                    std::uint64_t me = mb + info->Modules[mi].ImageSize;

                    for (int poff = 0; poff + 8 <= (int)sizeof(block); poff += 8)
                    {
                        std::uint64_t ptr = *reinterpret_cast<std::uint64_t*>(&block[poff]);
                        if (ptr >= mb && ptr < me)
                        {
                            std::string mpth(reinterpret_cast<const char*>(info->Modules[mi].FullPathName));
                            auto slash = mpth.find_last_of("\\/");
                            f["owner_module"] = (slash != std::string::npos) ? mpth.substr(slash + 1) : mpth;
                            goto owner_found;
                        }
                    }
                }
                owner_found:


                bool dup = false;
                for (const auto& existing : filters)
                    if (existing["name"] == name_str) { dup = true; break; }
                if (!dup) filters.push_back(std::move(f));
                break;
            }
        }
    }

    json result;
    result["fltmgr_base"]     = helpers::format_address(static_cast<ea_t>(fltmgr_base));
    result["filter_count"]    = filters.size();
    result["filters"]         = std::move(filters);
    result["note"] = OBFSTR("Minifilter drivers intercept filesystem I/O. Anti-cheats use minifilters to monitor file access, "
                            "prevent dumps, and detect injection DLLs. Altitude determines callback priority order.");

    return tool_result_t::ok(OBFSTR("Minifilters: ") + std::to_string(result["filter_count"].get<std::size_t>()) +
                             OBFSTR(" registered filter drivers"), result);
}


tool_result_t driver_detect_etw_monitors(const json& params)
{
    if (!device->is_connected())
        return tool_result_t::error(OBFSTR("Driver not connected. Call driver_connect first."));
    if (device->get_kernel_dtb() == 0)
        return tool_result_t::error(OBFSTR("Kernel DTB not resolved. Call driver_connect first."));

    std::vector<uint8_t> buf;
    sys_module_info_t* info = nullptr;
    std::string err;
    if (!query_kernel_modules(buf, info, err))
        return tool_result_t::error(OBFSTR("Failed to enumerate kernel modules: ") + err);

    std::uint64_t ntos_base = 0, ntos_size = 0;
    for (ULONG i = 0; i < info->NumberOfModules; ++i)
    {
        std::string fp(reinterpret_cast<const char*>(info->Modules[i].FullPathName));
        std::transform(fp.begin(), fp.end(), fp.begin(), ::tolower);
        if (fp.find("ntoskrnl") != std::string::npos || fp.find("ntkrnlmp") != std::string::npos ||
            fp.find("ntkrnlpa") != std::string::npos || fp.find("ntkrpamp") != std::string::npos)
        {
            ntos_base = reinterpret_cast<std::uint64_t>(info->Modules[i].ImageBase);
            ntos_size = info->Modules[i].ImageSize;
            break;
        }
    }
    if (ntos_base == 0)
        return tool_result_t::error(OBFSTR("Could not find ntoskrnl base address"));


    std::uint64_t etw_threat_intel = device->resolve_export(ntos_base, "EtwThreatIntProvRegHandle");
    std::uint64_t etw_register     = device->resolve_export(ntos_base, "EtwRegister");

    json providers = json::array();


    if (etw_threat_intel != 0)
    {

        std::uint64_t reg_handle = 0;
        device->read_kernel_raw(etw_threat_intel, &reg_handle, 8);

        json ti;
        ti["name"]    = "Microsoft-Windows-Threat-Intelligence";
        ti["address"] = helpers::format_address(static_cast<ea_t>(etw_threat_intel));
        ti["status"]  = (reg_handle != 0) ? "active" : "inactive";
        ti["note"]    = OBFSTR("ETW-TI monitors process injection, executable memory allocation, and other "
                               "security-sensitive operations. Used by EDR and anti-cheat for real-time telemetry.");
        if (reg_handle != 0)
            ti["reg_handle"] = helpers::format_address(static_cast<ea_t>(reg_handle));
        providers.push_back(std::move(ti));
    }


    struct known_guid_t {
        const char* name;
        uint8_t bytes[16];
    };
    static const known_guid_t known_guids[] = {
        {"Microsoft-Windows-Kernel-Audit-API-Calls",
         {0xD6, 0x2C, 0xFB, 0x22, 0x7B, 0x0E, 0x2B, 0x42, 0xA0, 0xC7, 0x2F, 0xAD, 0x1F, 0xD0, 0xE7, 0x16}},
        {"Microsoft-Windows-Kernel-Process",
         {0x27, 0x09, 0xD0, 0xED, 0xC4, 0x9C, 0x65, 0x4E, 0xB9, 0x70, 0xC2, 0x56, 0x0F, 0xB5, 0xC2, 0x89}},
    };


    uint8_t pe_hdr[0x1000];
    device->read_kernel_raw(ntos_base, pe_hdr, sizeof(pe_hdr));
    std::uint32_t pe_off = *reinterpret_cast<std::uint32_t*>(&pe_hdr[0x3C]);
    std::uint16_t num_sections = *reinterpret_cast<std::uint16_t*>(&pe_hdr[pe_off + 6]);
    std::uint16_t opt_hdr_sz   = *reinterpret_cast<std::uint16_t*>(&pe_hdr[pe_off + 20]);
    std::uint32_t section_tbl  = pe_off + 24 + opt_hdr_sz;

    for (int s = 0; s < num_sections && (section_tbl + 40 <= sizeof(pe_hdr)); ++s, section_tbl += 40)
    {
        char sn[9] = {};
        std::memcpy(sn, &pe_hdr[section_tbl], 8);
        if (std::string(sn) != ".data" && std::string(sn) != ".rdata") continue;

        std::uint32_t vs = *reinterpret_cast<std::uint32_t*>(&pe_hdr[section_tbl + 8]);
        std::uint32_t va = *reinterpret_cast<std::uint32_t*>(&pe_hdr[section_tbl + 12]);
        std::uint64_t sec_addr = ntos_base + va;
        size_t sec_sz  = std::min(vs, (std::uint32_t)0x100000);

        std::vector<uint8_t> sec_data(sec_sz);
        device->read_kernel_raw(sec_addr, sec_data.data(), sec_sz);

        for (const auto& g : known_guids)
        {
            for (size_t off = 0; off + 16 <= sec_sz; ++off)
            {
                if (std::memcmp(&sec_data[off], g.bytes, 16) == 0)
                {
                    json prov;
                    prov["name"]    = g.name;
                    prov["address"] = helpers::format_address(static_cast<ea_t>(sec_addr + off));
                    prov["status"]  = "guid_found";
                    providers.push_back(std::move(prov));
                    break;
                }
            }
        }
    }


    json etw_modules = json::array();
    for (ULONG i = 0; i < info->NumberOfModules; ++i)
    {
        std::uint64_t mod_base = reinterpret_cast<std::uint64_t>(info->Modules[i].ImageBase);
        std::string fp(reinterpret_cast<const char*>(info->Modules[i].FullPathName));
        auto slash = fp.find_last_of("\\/");
        std::string mod_name = (slash != std::string::npos) ? fp.substr(slash + 1) : fp;

        std::transform(mod_name.begin(), mod_name.end(), mod_name.begin(), ::tolower);

        if (mod_name.find("ntoskrnl") != std::string::npos || mod_name.find("ntkrnl") != std::string::npos ||
            mod_name.find("hal.dll") != std::string::npos || mod_name.find("ci.dll") != std::string::npos ||
            mod_name.find("fltmgr") != std::string::npos || mod_name.find("nt.") != std::string::npos)
            continue;


        uint8_t mod_hdr[0x400];
        if (device->read_kernel_raw(mod_base, mod_hdr, sizeof(mod_hdr)) < 0x100) continue;
        if (mod_hdr[0] != 'M' || mod_hdr[1] != 'Z') continue;

        std::uint32_t mod_pe_off = *reinterpret_cast<std::uint32_t*>(&mod_hdr[0x3C]);
        if (mod_pe_off + 0x90 > sizeof(mod_hdr)) continue;


        uint8_t scan_buf[0x1000];
        device->read_kernel_raw(mod_base, scan_buf, sizeof(scan_buf));


        for (size_t off = 0; off + 11 < sizeof(scan_buf); ++off)
        {
            if (std::memcmp(&scan_buf[off], "EtwRegis", 8) == 0 ||
                std::memcmp(&scan_buf[off], "EtwWrite", 8) == 0 ||
                std::memcmp(&scan_buf[off], "EtwEventW", 9) == 0)
            {
                json em;
                em["module"]  = mod_name;
                em["address"] = helpers::format_address(static_cast<ea_t>(mod_base));
                em["etw_api_found"] = std::string(reinterpret_cast<const char*>(&scan_buf[off]),
                                                   std::min((size_t)32, sizeof(scan_buf) - off));

                auto& s = em["etw_api_found"].get_ref<std::string&>();
                auto nul = s.find('\0');
                if (nul != std::string::npos) s.resize(nul);
                etw_modules.push_back(std::move(em));
                break;
            }
        }
    }

    json result;
    result["ntoskrnl_base"]     = helpers::format_address(static_cast<ea_t>(ntos_base));
    result["etw_register"]      = (etw_register != 0) ? helpers::format_address(static_cast<ea_t>(etw_register)) : "not_found";
    result["threat_intel"]      = (etw_threat_intel != 0) ? helpers::format_address(static_cast<ea_t>(etw_threat_intel)) : "not_exported";
    result["providers"]         = std::move(providers);
    result["etw_consumer_modules"] = std::move(etw_modules);
    result["note"] = OBFSTR("ETW (Event Tracing for Windows) provides kernel-level telemetry. The Threat Intelligence "
                            "provider detects process injection, executable memory allocation, and suspicious API sequences. "
                            "Anti-cheats and EDRs subscribe to these events for real-time detection.");

    return tool_result_t::ok(OBFSTR("ETW monitors: ") + std::to_string(result["providers"].size()) +
                             OBFSTR(" providers, ") + std::to_string(result["etw_consumer_modules"].size()) +
                             OBFSTR(" consumer modules"), result);
}


tool_result_t driver_detect_hidden_modules(const json& params)
{
    if (!device->is_connected())
        return tool_result_t::error(OBFSTR("Driver not connected. Call driver_connect first."));
    if (device->get_process_id() == 0)
        return tool_result_t::error(OBFSTR("No target process attached. Call driver_attach first."));

    bool scan_kernel = params.value("kernel", false);

    json hidden = json::array();
    json legitimate = json::array();

    if (!scan_kernel)
    {


        voyager::device_t::peb_info peb{};
        if (!device->read_peb(peb))
            return tool_result_t::error(OBFSTR("Failed to read PEB"));


        auto regions = device->enumerate_memory_regions(0, 0x7FFFFFFFFFFF, false);


        std::set<std::uint64_t> peb_bases;


        std::uint64_t peb_addr = 0;


        auto modules = device->enumerate_memory_regions(0x10000, 0x7FFFFFFFFFFF, false);


        struct known_module_t {
            std::uint64_t base;
            std::uint64_t size;
            std::string name;
        };
        std::vector<known_module_t> known_modules;


        std::uint64_t ldr = 0;
        device->read_raw(peb.peb_address + 0x18, &ldr, 8);
        if (ldr != 0 && ldr < 0x7FFFFFFFFFFF)
        {

            std::uint64_t head = ldr + 0x10;
            std::uint64_t flink = 0;
            device->read_raw(head, &flink, 8);

            std::uint64_t cur = flink;
            int count = 0;
            while (cur != head && cur != 0 && count < 1024)
            {

                std::uint64_t dll_base = 0;
                std::uint32_t dll_size = 0;
                device->read_raw(cur + 0x30, &dll_base, 8);
                device->read_raw(cur + 0x40, &dll_size, 4);


                std::uint16_t name_len = 0;
                std::uint64_t name_buf = 0;
                device->read_raw(cur + 0x48, &name_len, 2);
                device->read_raw(cur + 0x48 + 8, &name_buf, 8);

                std::string name_str;
                if (name_len > 0 && name_len < 1024 && name_buf != 0)
                {
                    std::vector<wchar_t> wbuf(name_len / 2 + 1, 0);
                    device->read_raw(name_buf, wbuf.data(), name_len);
                    std::wstring wname(wbuf.data());
                    name_str = std::string(wname.begin(), wname.end());
                }

                if (dll_base != 0)
                {
                    known_modules.push_back({dll_base, dll_size, name_str});
                    peb_bases.insert(dll_base);
                }


                device->read_raw(cur, &cur, 8);
                ++count;
            }
        }


        for (const auto& reg : regions)
        {
            if (reg.size < 0x1000) continue;


            uint8_t mz[2] = {};
            device->read_raw(reg.base, mz, 2);
            if (mz[0] != 'M' || mz[1] != 'Z') continue;


            if (peb_bases.count(reg.base) == 0)
            {

                json h;
                h["address"] = helpers::format_address(static_cast<ea_t>(reg.base));
                h["size"]    = reg.size;
                h["status"]  = "hidden_pe";


                uint8_t pe_buf[0x400];
                if (device->read_raw(reg.base, pe_buf, sizeof(pe_buf)) >= 0x100)
                {
                    std::uint32_t pe_off2 = *reinterpret_cast<std::uint32_t*>(&pe_buf[0x3C]);
                    if (pe_off2 + 0x90 <= sizeof(pe_buf))
                    {

                        std::uint32_t export_rva = *reinterpret_cast<std::uint32_t*>(&pe_buf[pe_off2 + 0x88]);
                        if (export_rva > 0 && export_rva < 0x1000000)
                        {

                            uint8_t exp_dir[0x28];
                            if (device->read_raw(reg.base + export_rva, exp_dir, sizeof(exp_dir)) >= sizeof(exp_dir))
                            {
                                std::uint32_t name_rva = *reinterpret_cast<std::uint32_t*>(&exp_dir[0x0C]);
                                if (name_rva > 0 && name_rva < 0x1000000)
                                {
                                    char exp_name[128] = {};
                                    device->read_raw(reg.base + name_rva, exp_name, sizeof(exp_name) - 1);
                                    if (exp_name[0]) h["export_name"] = std::string(exp_name);
                                }
                            }
                        }

                        std::uint16_t chars = *reinterpret_cast<std::uint16_t*>(&pe_buf[pe_off2 + 0x16]);
                        h["is_dll"] = (chars & 0x2000) != 0;
                    }
                }

                hidden.push_back(std::move(h));
            }
            else
            {

                for (const auto& km : known_modules)
                {
                    if (km.base == reg.base)
                    {
                        json l;
                        l["address"] = helpers::format_address(static_cast<ea_t>(reg.base));
                        l["size"]    = km.size;
                        l["name"]    = km.name;
                        legitimate.push_back(std::move(l));
                        break;
                    }
                }
            }
        }
    }
    else
    {

        std::vector<uint8_t> mod_buf;
        sys_module_info_t* kinfo = nullptr;
        std::string kerr;
        if (!query_kernel_modules(mod_buf, kinfo, kerr))
            return tool_result_t::error(OBFSTR("Failed to enumerate kernel modules: ") + kerr);

        std::set<std::uint64_t> known_bases;
        for (ULONG i = 0; i < kinfo->NumberOfModules; ++i)
            known_bases.insert(reinterpret_cast<std::uint64_t>(kinfo->Modules[i].ImageBase));


        std::vector<std::pair<std::uint64_t, std::uint64_t>> scan_ranges;
        for (ULONG i = 0; i < kinfo->NumberOfModules; ++i)
        {
            std::uint64_t base = reinterpret_cast<std::uint64_t>(kinfo->Modules[i].ImageBase);
            std::uint64_t size = kinfo->Modules[i].ImageSize;

            if (base >= 0x10000)
                scan_ranges.push_back({base - 0x10000, base});
            scan_ranges.push_back({base + size, base + size + 0x10000});
        }

        int pages_scanned = 0;
        for (const auto& [start, end] : scan_ranges)
        {
            if (pages_scanned > 2048) break;
            for (std::uint64_t addr = start; addr < end; addr += 0x1000)
            {
                if (known_bases.count(addr)) continue;
                ++pages_scanned;

                uint8_t mz[2] = {};
                if (device->read_kernel_raw(addr, mz, 2) < 2) continue;
                if (mz[0] != 'M' || mz[1] != 'Z') continue;


                uint8_t pe_buf[0x400];
                if (device->read_kernel_raw(addr, pe_buf, sizeof(pe_buf)) < 0x100) continue;

                std::uint32_t pe_off2 = *reinterpret_cast<std::uint32_t*>(&pe_buf[0x3C]);
                if (pe_off2 > 0x300 || pe_off2 < 4) continue;
                if (pe_buf[pe_off2] != 'P' || pe_buf[pe_off2 + 1] != 'E') continue;

                json h;
                h["address"] = helpers::format_address(static_cast<ea_t>(addr));
                h["status"]  = "hidden_kernel_pe";
                h["mode"]    = "kernel";

                std::uint32_t img_size = *reinterpret_cast<std::uint32_t*>(&pe_buf[pe_off2 + 0x50]);
                h["image_size"] = img_size;


                std::uint32_t export_rva = *reinterpret_cast<std::uint32_t*>(&pe_buf[pe_off2 + 0x88]);
                if (export_rva > 0 && export_rva < img_size)
                {
                    uint8_t exp_dir[0x28];
                    if (device->read_kernel_raw(addr + export_rva, exp_dir, sizeof(exp_dir)) >= sizeof(exp_dir))
                    {
                        std::uint32_t name_rva = *reinterpret_cast<std::uint32_t*>(&exp_dir[0x0C]);
                        if (name_rva > 0 && name_rva < img_size)
                        {
                            char exp_name[128] = {};
                            device->read_kernel_raw(addr + name_rva, exp_name, sizeof(exp_name) - 1);
                            if (exp_name[0]) h["export_name"] = std::string(exp_name);
                        }
                    }
                }

                hidden.push_back(std::move(h));
            }
        }
    }

    json result;
    result["mode"]           = scan_kernel ? "kernel" : "usermode";
    result["hidden_count"]   = hidden.size();
    result["hidden_modules"] = std::move(hidden);
    if (!scan_kernel)
    {
        result["legitimate_count"]  = legitimate.size();
        result["legitimate_modules"] = std::move(legitimate);
    }
    result["note"] = OBFSTR("Hidden modules are PE images present in memory but not in the PEB module list (usermode) "
                            "or NtQuerySystemInformation module list (kernel). Common for manual-mapped DLLs, "
                            "anti-cheat drivers, and injected payloads.");

    return tool_result_t::ok(OBFSTR("Hidden modules: ") + std::to_string(result["hidden_count"].get<std::size_t>()) +
                             OBFSTR(" found"), result);
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
                    OBFSTR("Target process executable name (e.g. 'target.exe'). Case-insensitive. Aliases: process_name, name."), false},
                 {OBFSTR("process_name"), OBFSTR("string"),
                    OBFSTR("Alias of process."), false},
                 {OBFSTR("name"), OBFSTR("string"),
                    OBFSTR("Alias of process."), false}},
        driver_attach, false});

    registry.register_tool({
        OBFSTR("driver_unattach"), OBFSTR("driver"),
        OBFSTR("Clear the currently attached target process context without disconnecting the kernel driver. "
               "Resets attached PID, image base, process DTB, and temporary remote-call state. "
               "Use this before attaching to a different process to avoid stale context confusion."),
        {}, driver_unattach, false});

    registry.register_tool({
        OBFSTR("driver_read_memory"), OBFSTR("driver"),
        OBFSTR("Read raw bytes from the target process via kernel driver. "
               "Bypasses all memory protection, DEP, guard pages, and anti-read hooks. "
             "Optionally patches the bytes into the IDA database. "
             "Supports optional process_id override to avoid stale attach context."),
        {{OBFSTR("address"), OBFSTR("string"), OBFSTR("Virtual address in target process"), true},
         {OBFSTR("size"), OBFSTR("number"), OBFSTR("Bytes to read (default 256, max 65536)"), false},
          {OBFSTR("patch_idb"), OBFSTR("boolean"), OBFSTR("Write read bytes to IDA database (default false)"), false},
          {OBFSTR("process_id"), OBFSTR("number"), OBFSTR("Optional PID override. If different from attached PID, context is switched safely."), false}},
        driver_read_memory, false});

    registry.register_tool({
        OBFSTR("driver_write_memory"), OBFSTR("driver"),
        OBFSTR("Write bytes to the target process via kernel driver. "
             "Bypasses all memory protection including DEP, guard pages, and write protection. "
             "Accepted bytes formats: 'DE AD BE EF', 'DEADBEEF', [222,173,...], ['DE','AD',...]."),
        {{OBFSTR("address"), OBFSTR("string"), OBFSTR("Virtual address in target process"), true},
          {OBFSTR("bytes"), OBFSTR("string"), OBFSTR("Bytes payload in hex string or JSON array."), true},
          {OBFSTR("process_id"), OBFSTR("number"), OBFSTR("Optional PID override. If different from attached PID, context is switched safely."), false}},
        driver_write_memory, false});

    registry.register_tool({
        OBFSTR("driver_dump_module"), OBFSTR("driver"),
         OBFSTR("Dump a module from the target process using kernel memory reads. "
             "Captures the module exactly as it exists in runtime memory without decryption, "
             "devirtualization, header reconstruction, or import rebuilding. "
             "Can resolve a loaded sub-module by name or path via the 'module' parameter. "
             "Creates IDA segments and patches dumped bytes into the database. "
               "Can auto-connect to a process by name via the 'process' parameter."),
        {{OBFSTR("process"), OBFSTR("string"),
          OBFSTR("Target process name to auto-connect (e.g. 'game.exe'). "
                 "If omitted, uses currently attached process."), false},
          {OBFSTR("module"), OBFSTR("string"),
           OBFSTR("Loaded module name or full/partial path to dump (e.g. 'steam_api64.dll'). "
               "If omitted, dumps the main image unless 'address' is provided."), false},
         {OBFSTR("address"), OBFSTR("string"),
           OBFSTR("Explicit module base address (overrides automatic module resolution)"), false},
         {OBFSTR("size"), OBFSTR("number"), OBFSTR("Override image size in bytes (default: auto from PE header)"), false},
         {OBFSTR("output_path"), OBFSTR("string"), OBFSTR("Save dump to file path (e.g. 'C:\\\\dump.bin')"), false},
          {OBFSTR("patch_idb"), OBFSTR("boolean"), OBFSTR("Patch dumped runtime bytes into IDA database (default true)"), false}},
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
                    {OBFSTR("auto"), OBFSTR("ascii"), OBFSTR("wide")}},
                 {OBFSTR("process_id"), OBFSTR("number"), OBFSTR("Optional PID override."), false}},
        driver_read_string, false});

    registry.register_tool({
        OBFSTR("driver_read_pointer_chain"), OBFSTR("driver"),
        OBFSTR("Follow a chain of pointer dereferences through target process memory via kernel driver. "
               "Useful for traversing linked lists, object hierarchies, and obfuscated data structures."),
        {{OBFSTR("address"), OBFSTR("string"), OBFSTR("Starting virtual address"), false},
          {OBFSTR("base_address"), OBFSTR("string"), OBFSTR("Alias for address."), false},
         {OBFSTR("offsets"), OBFSTR("array"),
          OBFSTR("Array of byte offsets to apply after each dereference (e.g. [0, 48, 24])"), false, {},
           json::object({{"type", "number"}})},
          {OBFSTR("process_id"), OBFSTR("number"), OBFSTR("Optional PID override."), false}},
        driver_read_pointer_chain, false});

    registry.register_tool({
        OBFSTR("driver_enumerate_modules"), OBFSTR("driver"),
        OBFSTR("Enumerate ALL modules loaded in the attached process by walking the PEB LDR "
               "InLoadOrderModuleList. Returns each module's name, base address, size, entry point, "
               "full path, and whether it is the main executable. Requires driver_attach first."),
        {}, driver_enumerate_modules, false});

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
        driver_enumerate_kernel_modules, false});

    registry.register_tool({
        OBFSTR("driver_dump_kernel_module"), OBFSTR("driver"),
        OBFSTR("UNIVERSAL kernel module dump tool. By default dumps from LIVE KERNEL MEMORY "
               "using physical memory reads (requires driver connected). Captures runtime-decrypted, "
               "devirtualized, unpacked code as it exists in RAM. Set from_memory=false to fall back "
               "to reading the on-disk .sys file. "
               "When patch_idb=true, creates IDA segments for each PE section and patches live bytes. "
               "Use this to dump ANY kernel driver: EasyAntiCheat (EAC), BattlEye, Vanguard, "
               "ntkrnlmp.exe, win32kfull.sys, etc. The dump file can be loaded in IDA Pro."),
        {{OBFSTR("module"), OBFSTR("string"),
          OBFSTR("Kernel module name or substring (e.g. 'EasyAntiCheat.sys', 'eac', 'ntoskrnl')"), true},
         {OBFSTR("output_path"), OBFSTR("string"),
          OBFSTR("Full file path to save the dump (e.g. 'C:\\\\dumps\\\\dumped_eac.sys'). "
                 "If omitted, saves to %%TEMP%%\\\\dumped_<module_name>"), false},
         {OBFSTR("from_memory"), OBFSTR("boolean"),
          OBFSTR("True (default) = dump live kernel memory via driver. "
                 "False = read on-disk file (no driver needed)."), false},
         {OBFSTR("patch_idb"), OBFSTR("boolean"),
          OBFSTR("Create IDA segments and patch dumped bytes into the database (default true)"), false},
         {OBFSTR("analyze"), OBFSTR("boolean"),
          OBFSTR("Run analysis after patching (default true)"), false}},
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
                             "if done incorrectly. Use with extreme caution. User-mode addresses are rejected."),
        {{OBFSTR("address"), OBFSTR("string"),
          OBFSTR("Kernel virtual address to write (e.g. 'FFFFF80012345000')"), true},
         {OBFSTR("bytes"), OBFSTR("string"),
                    OBFSTR("Bytes payload in hex string or JSON array."), true}},
        driver_write_kernel_memory, false});


    registry.register_tool({
        OBFSTR("driver_allocate_memory"), OBFSTR("driver"),
        OBFSTR("Allocate RWX memory in the attached target process. "
               "Uses kernel-level ZwAllocateVirtualMemory with PAGE_EXECUTE_READWRITE. "
               "Max 16MB per allocation. Useful for injecting shellcode, writing strings "
               "for function arguments, or setting up data structures remotely. "
               "Requires driver connected and process attached."),
        {{OBFSTR("size"), OBFSTR("string"),
                    OBFSTR("Number of bytes to allocate (max 16777216 = 16MB)"), true},
                 {OBFSTR("process_id"), OBFSTR("number"), OBFSTR("Optional PID override."), false}},
        driver_allocate_memory, false});

    registry.register_tool({
        OBFSTR("driver_free_memory"), OBFSTR("driver"),
        OBFSTR("Free previously allocated memory in the attached target process. "
               "Uses kernel-level ZwFreeVirtualMemory with MEM_RELEASE. "
               "Requires driver connected and process attached."),
        {{OBFSTR("address"), OBFSTR("string"),
                    OBFSTR("Address of the memory block to free (hex string like '0x...')"), true},
                 {OBFSTR("process_id"), OBFSTR("number"), OBFSTR("Optional PID override."), false}},
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
                             "Requires driver connected, process attached, DTB solved. "
                             "For safety, execution requires confirm_unsafe=true unless dry_run=true."),
        {{OBFSTR("address"), OBFSTR("string"),
          OBFSTR("Address of the function to call in the target process (hex)"), true},
         {OBFSTR("arg1"), OBFSTR("string"),
          OBFSTR("First argument (RCX). Hex address or integer. Default 0"), false},
         {OBFSTR("arg2"), OBFSTR("string"),
          OBFSTR("Second argument (RDX). Hex address or integer. Default 0"), false},
         {OBFSTR("arg3"), OBFSTR("string"),
          OBFSTR("Third argument (R8). Hex address or integer. Default 0"), false},
         {OBFSTR("arg4"), OBFSTR("string"),
                    OBFSTR("Fourth argument (R9). Hex address or integer. Default 0"), false},
                 {OBFSTR("confirm_unsafe"), OBFSTR("boolean"), OBFSTR("Required for live execution. Must be true unless dry_run=true."), false},
         {OBFSTR("allow_unsafe"), OBFSTR("boolean"), OBFSTR("Alias of confirm_unsafe."), false},
         {OBFSTR("unsafe"), OBFSTR("boolean"), OBFSTR("Alias of confirm_unsafe."), false},
                 {OBFSTR("dry_run"), OBFSTR("boolean"), OBFSTR("Preview call metadata without executing."), false},
                 {OBFSTR("process_id"), OBFSTR("number"), OBFSTR("Optional PID override."), false}},
        driver_call_function, false});


    registry.register_tool({
        OBFSTR("driver_get_thread_context"), OBFSTR("driver"),
        OBFSTR("Get the full register state of a thread in the attached process via kernel PsGetContextThread. "
               "Returns all general purpose registers (RAX-R15), RIP, RFLAGS, and debug registers (DR0-DR7). "
               "Thread must exist in the attached process. Bypasses all anti-debug since it operates from kernel."),
        {{OBFSTR("tid"), OBFSTR("string"), OBFSTR("Thread ID. Decimal string recommended; 0x-prefixed hex supported."), true},
         {OBFSTR("process_id"), OBFSTR("number"), OBFSTR("Optional PID override."), false}},
        driver_get_thread_context, true});

    registry.register_tool({
        OBFSTR("driver_set_thread_context"), OBFSTR("driver"),
        OBFSTR("Set registers of a thread in the attached process via kernel PsSetContextThread. "
               "Only specified registers are modified; unspecified registers are untouched. "
               "Can set RIP to redirect execution, modify debug registers for HW breakpoints, "
               "change RSP, or any other register. Operates from kernel, bypasses all protection."),
        {{OBFSTR("tid"), OBFSTR("string"), OBFSTR("Thread ID. Decimal string recommended; 0x-prefixed hex supported."), true},
         {OBFSTR("rax"), OBFSTR("string"), OBFSTR("RAX value (hex)"), false},
         {OBFSTR("rbx"), OBFSTR("string"), OBFSTR("RBX value"), false},
         {OBFSTR("rcx"), OBFSTR("string"), OBFSTR("RCX value"), false},
         {OBFSTR("rdx"), OBFSTR("string"), OBFSTR("RDX value"), false},
         {OBFSTR("rsi"), OBFSTR("string"), OBFSTR("RSI value"), false},
         {OBFSTR("rdi"), OBFSTR("string"), OBFSTR("RDI value"), false},
         {OBFSTR("rbp"), OBFSTR("string"), OBFSTR("RBP value"), false},
         {OBFSTR("rsp"), OBFSTR("string"), OBFSTR("RSP value"), false},
         {OBFSTR("r8"), OBFSTR("string"), OBFSTR("R8 value"), false},
         {OBFSTR("r9"), OBFSTR("string"), OBFSTR("R9 value"), false},
         {OBFSTR("r10"), OBFSTR("string"), OBFSTR("R10 value"), false},
         {OBFSTR("r11"), OBFSTR("string"), OBFSTR("R11 value"), false},
         {OBFSTR("r12"), OBFSTR("string"), OBFSTR("R12 value"), false},
         {OBFSTR("r13"), OBFSTR("string"), OBFSTR("R13 value"), false},
         {OBFSTR("r14"), OBFSTR("string"), OBFSTR("R14 value"), false},
         {OBFSTR("r15"), OBFSTR("string"), OBFSTR("R15 value"), false},
         {OBFSTR("rip"), OBFSTR("string"), OBFSTR("RIP value"), false},
         {OBFSTR("rflags"), OBFSTR("string"), OBFSTR("RFLAGS value"), false},
         {OBFSTR("dr0"), OBFSTR("string"), OBFSTR("DR0 value"), false},
         {OBFSTR("dr1"), OBFSTR("string"), OBFSTR("DR1 value"), false},
         {OBFSTR("dr2"), OBFSTR("string"), OBFSTR("DR2 value"), false},
         {OBFSTR("dr3"), OBFSTR("string"), OBFSTR("DR3 value"), false},
         {OBFSTR("dr6"), OBFSTR("string"), OBFSTR("DR6 value"), false},
         {OBFSTR("dr7"), OBFSTR("string"), OBFSTR("DR7 value"), false},
         {OBFSTR("process_id"), OBFSTR("number"), OBFSTR("Optional PID override."), false}},
        driver_set_thread_context, false});

    registry.register_tool({
        OBFSTR("driver_enumerate_threads"), OBFSTR("driver"),
        OBFSTR("Enumerate all threads in the attached process via kernel PsGetNextProcessThread. "
               "Returns each thread's TID. Useful for finding threads to suspend, set breakpoints on, "
               "or inspect context of."),
        {{OBFSTR("process_id"), OBFSTR("number"), OBFSTR("Optional PID override."), false}}, driver_enumerate_threads, true});

    registry.register_tool({
        OBFSTR("driver_suspend_thread"), OBFSTR("driver"),
        OBFSTR("Suspend a thread in the attached process via kernel PsSuspendThread. "
               "Thread execution is paused until resumed. Returns previous suspend count."),
        {{OBFSTR("tid"), OBFSTR("string"), OBFSTR("Thread ID to suspend. Decimal string recommended; 0x-prefixed hex supported."), true},
         {OBFSTR("process_id"), OBFSTR("number"), OBFSTR("Optional PID override."), false}},
        driver_suspend_thread, false});

    registry.register_tool({
        OBFSTR("driver_resume_thread"), OBFSTR("driver"),
        OBFSTR("Resume a suspended thread in the attached process via kernel PsResumeThread. "
               "Returns previous suspend count. Thread resumes execution."),
        {{OBFSTR("tid"), OBFSTR("string"), OBFSTR("Thread ID to resume. Decimal string recommended; 0x-prefixed hex supported."), true},
         {OBFSTR("process_id"), OBFSTR("number"), OBFSTR("Optional PID override."), false}},
        driver_resume_thread, false});

    registry.register_tool({
        OBFSTR("driver_query_memory"), OBFSTR("driver"),
        OBFSTR("Query virtual memory region information at an address in the attached process. "
               "Uses kernel ZwQueryVirtualMemory. Returns region base, size, state (commit/reserve/free), "
               "protection (RWX flags), and type (private/mapped/image)."),
        {{OBFSTR("address"), OBFSTR("string"),
                    OBFSTR("Virtual address to query (default: image base)"), false},
                 {OBFSTR("process_id"), OBFSTR("number"), OBFSTR("Optional PID override."), false}},
        driver_query_memory, true});

    registry.register_tool({
        OBFSTR("driver_protect_memory"), OBFSTR("driver"),
        OBFSTR("Change virtual memory protection in the attached process via kernel ZwProtectVirtualMemory. "
               "Bypasses usermode hooks on VirtualProtect. Can set any protection including executable. "
               "Returns the old protection value."),
        {{OBFSTR("address"), OBFSTR("string"), OBFSTR("Virtual address"), true},
         {OBFSTR("size"), OBFSTR("string"), OBFSTR("Region size (default 0x1000)"), false},
         {OBFSTR("protect"), OBFSTR("string"),
          OBFSTR("New protection value: 0x40=PAGE_EXECUTE_READWRITE, 0x20=PAGE_EXECUTE_READ, "
             "0x04=PAGE_READWRITE, 0x02=PAGE_READONLY"), false},
         {OBFSTR("process_id"), OBFSTR("number"), OBFSTR("Optional PID override."), false}},
        driver_protect_memory, false});

    registry.register_tool({
        OBFSTR("driver_enumerate_memory_regions"), OBFSTR("driver"),
        OBFSTR("Walk the entire virtual address space of the attached process, enumerating all "
               "committed memory regions. Returns base, size, state, protection, and type for each. "
               "Useful for finding all executable regions, mapped images, private memory, etc."),
        {{OBFSTR("start"), OBFSTR("string"), OBFSTR("Start address (default 0)"), false},
         {OBFSTR("end"), OBFSTR("string"), OBFSTR("End address (default max user-mode)"), false},
         {OBFSTR("include_all"), OBFSTR("boolean"),
                    OBFSTR("Include free/reserved regions too (default false, only committed)"), false},
                 {OBFSTR("process_id"), OBFSTR("number"), OBFSTR("Optional PID override."), false}},
        driver_enumerate_memory_regions, true});

    registry.register_tool({
        OBFSTR("driver_read_peb"), OBFSTR("driver"),
        OBFSTR("Read the Process Environment Block (PEB) of the attached process via kernel. "
               "Returns PEB address, image base, BeingDebugged flag, NtGlobalFlag, "
               "loader data address, process heap, and heap info."),
        {{OBFSTR("process_id"), OBFSTR("number"), OBFSTR("Optional PID override."), false}}, driver_read_peb, true});

    registry.register_tool({
        OBFSTR("driver_spoof_debug_flags"), OBFSTR("driver"),
        OBFSTR("Clear ALL anti-debug indicators in the attached process from kernel space. "
               "Zeroes EPROCESS.DebugPort, PEB.BeingDebugged, clears PEB.NtGlobalFlag heap debug flags. "
               "Completely invisible to the target process. Call this before the target's anti-debug "
               "checks run to bypass IsDebuggerPresent, NtQueryInformationProcess, etc."),
        {{OBFSTR("process_id"), OBFSTR("number"), OBFSTR("Optional PID override."), false}}, driver_spoof_debug_flags, false});

    registry.register_tool({
        OBFSTR("driver_set_hw_breakpoint"), OBFSTR("driver"),
        OBFSTR("Set a hardware breakpoint on a thread in the attached process using debug registers. "
               "Uses DR0-DR3 (4 breakpoints max per thread). Operates via kernel PsSetContextThread "
               "so it's invisible to usermode anti-debug. Types: execute (break on execution), "
               "write (break on memory write), readwrite (break on read or write). "
               "After setting, the thread will trigger a SINGLE_STEP exception when the breakpoint fires."),
        {{OBFSTR("tid"), OBFSTR("string"), OBFSTR("Thread ID. Decimal string recommended; 0x-prefixed hex supported."), true},
         {OBFSTR("address"), OBFSTR("string"), OBFSTR("Address to break on"), true},
         {OBFSTR("index"), OBFSTR("number"),
          OBFSTR("Debug register index 0-3 (default 0). Each thread supports 4 HW breakpoints."), false},
         {OBFSTR("type"), OBFSTR("string"),
          OBFSTR("Breakpoint type: execute (default), write, readwrite"), false,
          {OBFSTR("execute"), OBFSTR("write"), OBFSTR("readwrite")}},
         {OBFSTR("size"), OBFSTR("number"),
                    OBFSTR("Watched region size in bytes: 1 (default), 2, 4, or 8"), false},
                 {OBFSTR("process_id"), OBFSTR("number"), OBFSTR("Optional PID override."), false}},
        driver_set_hw_breakpoint, false});

    registry.register_tool({
        OBFSTR("driver_clear_hw_breakpoint"), OBFSTR("driver"),
        OBFSTR("Clear a hardware breakpoint on a thread. Removes the address from the specified "
               "debug register and disables it in DR7."),
                {{OBFSTR("tid"), OBFSTR("string"), OBFSTR("Thread ID. Decimal string recommended; 0x-prefixed hex supported."), true},
         {OBFSTR("index"), OBFSTR("number"),
                    OBFSTR("Debug register index 0-3 to clear (default 0)"), false},
                 {OBFSTR("process_id"), OBFSTR("number"), OBFSTR("Optional PID override."), false}},
        driver_clear_hw_breakpoint, false});

    registry.register_tool({
        OBFSTR("driver_resolve_export"), OBFSTR("driver"),
        OBFSTR("Resolve an export function address from a PE module in the attached process. "
               "Walks the PE export directory via physical memory reads. Useful for finding API "
               "addresses without relying on import tables (which may be obfuscated by packers)."),
        {{OBFSTR("name"), OBFSTR("string"), OBFSTR("Export function name to resolve. Alias: export_name."), false},
          {OBFSTR("export_name"), OBFSTR("string"), OBFSTR("Alias for name."), false},
         {OBFSTR("module_base"), OBFSTR("string"),
           OBFSTR("Module base address (default: attached process image base)"), false},
          {OBFSTR("module"), OBFSTR("string"), OBFSTR("Module name/path or base address string. Alias: module_name."), false},
          {OBFSTR("module_name"), OBFSTR("string"), OBFSTR("Alias for module."), false},
          {OBFSTR("process_id"), OBFSTR("number"), OBFSTR("Optional PID override."), false}},
        driver_resolve_export, true});

    registry.register_tool({
        OBFSTR("driver_virtual_to_physical"), OBFSTR("driver"),
        OBFSTR("Translate a virtual address to its physical address using the process DTB. "
               "Performs a full 4-level page table walk (PML4->PDPT->PD->PT) in kernel."),
        {{OBFSTR("address"), OBFSTR("string"), OBFSTR("Virtual address to translate"), true}},
        driver_virtual_to_physical, true});


    registry.register_tool({
        OBFSTR("driver_defer_action"), OBFSTR("driver"),
        OBFSTR("PRE-SCHEDULE driver tool calls to execute THE INSTANT a kernel module loads "
               "or a process starts. This solves the critical timing problem: many drivers "
               "(EAC, BattlEye, Vanguard) wipe their IAT, decrypt code, or perform anti-RE "
               "operations during initialization. By the time you can manually react, the "
               "evidence is already destroyed. This tool lets you queue actions (read memory, "
               "set HW breakpoints, dump module, etc.) that fire IMMEDIATELY when the target "
               "appears — before its init routine runs. "
               "\n\nTemplate parameters in action params are resolved at trigger time:\n"
               "  ${module_base} — runtime kernel base address of the loaded module\n"
               "  ${module_size} — module image size\n"
               "  ${module_name} — resolved module filename\n"
               "  ${pid} — process ID (for process_start)\n"
               "  ${base_address} — process image base (for process_start)\n"
               "\nAddress arithmetic: '${module_base}+0x17C000' computes base+offset automatically.\n"
               "\nExample: to capture EAC's IAT before it's wiped:\n"
               "  wait_for='kernel_module_load', target='EasyAntiCheat_EOS.sys',\n"
               "  actions=[{tool:'driver_read_kernel_memory', params:{address:'${module_base}+0x17C000', size:64}}]"),
        {{OBFSTR("wait_for"), OBFSTR("string"),
          OBFSTR("Condition type: 'kernel_module_load' or 'process_start'"), true, {},
          {OBFSTR("kernel_module_load"), OBFSTR("process_start")}},
         {OBFSTR("target"), OBFSTR("string"),
          OBFSTR("Module or process name to watch for (case-insensitive substring match). "
                 "E.g. 'EasyAntiCheat_EOS.sys', 'BEService.exe'"), true},
         {OBFSTR("actions"), OBFSTR("array"),
          OBFSTR("Array of tool calls to execute when condition is met. "
                 "Each entry: {\"tool\": \"tool_name\", \"params\": {...}}. "
                 "Compatibility aliases accepted: top-level {action, params} and per-entry {action, params}. "
             "Params may use ${module_base}, ${module_size}, ${pid}, ${base_address} templates."), false, {},
          json::object({{"type", "object"},
                        {"properties", json::object({
                            {"tool", json::object({{"type", "string"}})},
                            {"action", json::object({{"type", "string"}})},
                            {"params", json::object({{"type", "object"}})}
                        })}
          })},
         {OBFSTR("timeout"), OBFSTR("number"),
          OBFSTR("Maximum seconds to wait for the condition (default 300 = 5 minutes)"), false},
         {OBFSTR("poll_interval"), OBFSTR("number"),
          OBFSTR("Milliseconds between condition checks (default 50ms). Lower = faster reaction "
                 "but more CPU. For IAT capture, use 10-25ms."), false}},
        driver_defer_action, false});

    registry.register_tool({
        OBFSTR("driver_list_deferred_actions"), OBFSTR("driver"),
        OBFSTR("List all registered deferred actions and their current status "
               "(pending, watching, triggered, completed, failed, cancelled, timed_out). "
               "Shows condition, target, number of queued actions, trigger info, and result counts."),
        {},
        driver_list_deferred_actions, false});

    registry.register_tool({
        OBFSTR("driver_cancel_deferred_action"), OBFSTR("driver"),
        OBFSTR("Cancel a pending/watching deferred action by its action_id. "
               "Only works if the action hasn't been triggered yet."),
        {{OBFSTR("action_id"), OBFSTR("number"),
          OBFSTR("The action ID returned by driver_defer_action"), true}},
        driver_cancel_deferred_action, false});

    registry.register_tool({
        OBFSTR("driver_get_deferred_results"), OBFSTR("driver"),
        OBFSTR("Get the detailed results of a deferred action after it has been triggered. "
               "Returns the trigger context (module base, PID, etc.), the status of each "
               "queued tool call (success/failure, output data), and timing information. "
               "Use this to retrieve data captured by pre-scheduled actions."),
        {{OBFSTR("action_id"), OBFSTR("number"),
          OBFSTR("The action ID returned by driver_defer_action"), true}},
        driver_get_deferred_results, false});


    registry.register_tool({
        OBFSTR("driver_enumerate_wfp_callouts"), OBFSTR("driver"),
        OBFSTR("Enumerate Windows Filtering Platform (WFP) callouts directly from kernel memory. "
               "Anti-cheats (EAC/BE/Vanguard), firewalls, and EDRs use WFP to intercept network traffic. "
               "Returns the owning driver/module name, the callout ID, the callout GUID, and the applicable "
               "WFP layer GUID, allowing the AI to immediately identify which drivers are inspecting network "
               "packets and at what layer. Use this to discover hidden network filters installed by anti-cheat "
               "or EDR software."),
        {{OBFSTR("filter_module"), OBFSTR("string"),
          OBFSTR("Optional: filter by driver/module name substring (e.g., 'EasyAntiCheat', 'vgk', 'BEDaisy')"), false}},
        driver_enumerate_wfp_callouts, true});

    registry.register_tool({
        OBFSTR("driver_get_socket_handles"), OBFSTR("driver"),
        OBFSTR("Walk the EPROCESS handle table of the attached process from kernel space, looking exclusively "
               "for socket objects (\\Device\\Afd). Extracts the local IP/Port, remote IP/Port, and protocol "
               "(TCP/UDP) directly from the kernel AFD endpoint structure. Completely bypasses user-mode "
               "rootkits or anti-cheats that hide their network connections from netstat/TCPView. "
               "Returns the raw handle value and kernel AFD_ENDPOINT address for further analysis."),
        {{OBFSTR("target_pid"), OBFSTR("number"),
          OBFSTR("Optional: PID to examine (default: attached process)"), false}},
        driver_get_socket_handles, true});

    registry.register_tool({
        OBFSTR("driver_sniff_network_buffers"), OBFSTR("driver"),
        OBFSTR("Manage a kernel-level network buffer sniff session that works with hardware breakpoints to "
               "capture plaintext network buffers in memory BEFORE encryption. Wireshark only sees encrypted "
               "payloads; this tool captures the data before it reaches ws2_32.dll!send, "
               "afd.sys!AfdFastIoDeviceControl, or a custom game/malware encryption function.\n\n"
               "Workflow:\n"
               "1. Call with address + buffer_register + size_register to START session\n"
               "2. Set HW breakpoint on the address via driver_set_hw_breakpoint\n"
               "3. When BP fires, read thread context, read buffer from memory, call with operation='store'\n"
               "4. Call with operation='get' to retrieve all captured buffers\n"
               "5. Call with operation='stop' when done\n\n"
               "This is a composite tool that coordinates with driver_set_hw_breakpoint and driver_read_memory."),
        {{OBFSTR("address"), OBFSTR("string"),
          OBFSTR("Address of the send/recv/encrypt function (for 'start' operation)"), false},
         {OBFSTR("buffer_register"), OBFSTR("string"),
          OBFSTR("Register containing the buffer pointer (e.g., 'rcx', 'rdx', 'r8')"), false},
         {OBFSTR("size_register"), OBFSTR("string"),
          OBFSTR("Register containing the buffer size (e.g., 'rdx', 'r8', 'r9')"), false},
         {OBFSTR("max_packets"), OBFSTR("number"),
          OBFSTR("Max captures before auto-stop (default 1, max 16)"), false},
         {OBFSTR("operation"), OBFSTR("string"),
          OBFSTR("'start' (default), 'stop', 'get'/'results'"), false, {},
          {OBFSTR("start"), OBFSTR("stop"), OBFSTR("get"), OBFSTR("results")}},
         {OBFSTR("tid"), OBFSTR("number"),
          OBFSTR("Thread ID for breakpoint (default: 0 = first thread)"), false},
         {OBFSTR("bp_index"), OBFSTR("number"),
          OBFSTR("Debug register index 0-3 (default: 0)"), false}},
        driver_sniff_network_buffers, false});

    registry.register_tool({
        OBFSTR("driver_dump_tcpip_connections"), OBFSTR("driver"),
        OBFSTR("Read the internal TCP/UDP connection tables directly from tcpip.sys/netio.sys memory via NSI. "
               "Functions as a 'kernel netstat' that cannot be lied to by user-mode hooks. "
               "Returns ALL active connections with states, process IDs, creation timestamps, and byte counters. "
               "Includes both established connections and listeners. "
               "Unlike the network_enumerate_connections tool, this uses direct kernel NSI enumeration "
               "(NsiEnumerateObjectsAllParameters) and includes TCP listeners and creation timestamps."),
        {{OBFSTR("target_pid"), OBFSTR("number"),
          OBFSTR("Optional: Only return connections for this PID (0 = all)"), false},
         {OBFSTR("filter_protocol"), OBFSTR("string"),
          OBFSTR("Optional: 'tcp', 'udp', or protocol number (0 = all)"), false}},
        driver_dump_tcpip_connections, true});


    registry.register_tool({
        OBFSTR("driver_inject_packet"), OBFSTR("driver"),
        OBFSTR("Inject a crafted raw network packet into the network stack via WFP injection APIs. "
               "Supports both inbound and outbound injection of TCP/UDP packets. "
               "Can spoof source addresses and ports. Useful for testing firewalls, triggering specific "
               "protocol handlers, and advanced network analysis."),
        {{OBFSTR("direction"), OBFSTR("string"), OBFSTR("'inbound'/'in' or 'outbound'/'out' (default out)"), false},
         {OBFSTR("protocol"), OBFSTR("string"), OBFSTR("'tcp' or 'udp' (default tcp)"), false},
         {OBFSTR("src_addr"), OBFSTR("string"), OBFSTR("Source IP address (e.g. '192.168.1.1')"), false},
         {OBFSTR("dst_addr"), OBFSTR("string"), OBFSTR("Destination IP address"), false},
         {OBFSTR("src_port"), OBFSTR("number"), OBFSTR("Source port"), false},
         {OBFSTR("dst_port"), OBFSTR("number"), OBFSTR("Destination port"), false},
         {OBFSTR("payload"), OBFSTR("string"), OBFSTR("Hex payload bytes (e.g. '48 45 4C 4C 4F')"), true},
         {OBFSTR("tcp_flags"), OBFSTR("number"), OBFSTR("TCP flags: SYN=2, ACK=16, RST=4, FIN=1, PSH=8"), false},
         {OBFSTR("tcp_seq"), OBFSTR("number"), OBFSTR("TCP sequence number"), false},
         {OBFSTR("tcp_ack"), OBFSTR("number"), OBFSTR("TCP acknowledgment number"), false}},
        driver_inject_packet, false});

    registry.register_tool({
        OBFSTR("driver_modify_packet_rule"), OBFSTR("driver"),
        OBFSTR("Manage kernel-level packet modification rules. Like Fiddler's AutoResponder but at the "
               "kernel level. Finds byte patterns in live network packets and replaces them in-place. "
               "Works on both TCP and UDP. Operations: add, remove, list, clear."),
        {{OBFSTR("operation"), OBFSTR("string"), OBFSTR("'add', 'remove', 'list', 'clear'"), false,
          {OBFSTR("add"), OBFSTR("remove"), OBFSTR("list"), OBFSTR("clear")}},
         {OBFSTR("direction"), OBFSTR("string"), OBFSTR("'in', 'out', or 'both' (default both)"), false},
         {OBFSTR("protocol"), OBFSTR("string"), OBFSTR("'tcp', 'udp', or 'any' (default any)"), false},
         {OBFSTR("port"), OBFSTR("number"), OBFSTR("Filter by port (0=any)"), false},
         {OBFSTR("pid"), OBFSTR("number"), OBFSTR("Filter by PID (0=any)"), false},
         {OBFSTR("pattern"), OBFSTR("string"), OBFSTR("Hex bytes to search for in packets"), false},
         {OBFSTR("replacement"), OBFSTR("string"), OBFSTR("Hex bytes to replace pattern with"), false},
         {OBFSTR("rule_id"), OBFSTR("number"), OBFSTR("Rule ID for remove operation"), false}},
        driver_modify_packet_rule, false});

    registry.register_tool({
        OBFSTR("driver_redirect_traffic"), OBFSTR("driver"),
        OBFSTR("Manage kernel-level traffic redirection rules. Redirects network connections matching "
               "protocol/port/address criteria to a different destination. Like mitmproxy's upstream "
               "proxy but at the kernel WFP layer. Operations: add, remove, list, clear."),
        {{OBFSTR("operation"), OBFSTR("string"), OBFSTR("'add', 'remove', 'list', 'clear'"), false,
          {OBFSTR("add"), OBFSTR("remove"), OBFSTR("list"), OBFSTR("clear")}},
         {OBFSTR("protocol"), OBFSTR("string"), OBFSTR("'tcp', 'udp', 'any'"), false},
         {OBFSTR("match_port"), OBFSTR("number"), OBFSTR("Original destination port to match"), false},
         {OBFSTR("match_addr"), OBFSTR("string"), OBFSTR("Original destination IP to match"), false},
         {OBFSTR("redirect_port"), OBFSTR("number"), OBFSTR("New destination port"), false},
         {OBFSTR("redirect_addr"), OBFSTR("string"), OBFSTR("New destination IP"), false}},
        driver_redirect_traffic, false});

    registry.register_tool({
        OBFSTR("driver_reassemble_stream"), OBFSTR("driver"),
        OBFSTR("TCP stream reassembly engine. Like Wireshark's 'Follow TCP Stream' but from the kernel. "
               "Tracks TCP connections and reassembles the byte stream in order. Supports up to 8 "
               "concurrent streams, 64KB each. Operations: start, stop, get_data, list."),
        {{OBFSTR("operation"), OBFSTR("string"), OBFSTR("'start', 'stop', 'get'/'get_data', 'list'"), false,
          {OBFSTR("start"), OBFSTR("stop"), OBFSTR("get"), OBFSTR("get_data"), OBFSTR("list")}},
         {OBFSTR("src_addr"), OBFSTR("string"), OBFSTR("Source IP of the connection to track"), false},
         {OBFSTR("dst_addr"), OBFSTR("string"), OBFSTR("Destination IP"), false},
         {OBFSTR("src_port"), OBFSTR("number"), OBFSTR("Source port"), false},
         {OBFSTR("dst_port"), OBFSTR("number"), OBFSTR("Destination port"), false},
         {OBFSTR("pid"), OBFSTR("number"), OBFSTR("Filter by PID"), false}},
        driver_reassemble_stream, false});

    registry.register_tool({
        OBFSTR("driver_deep_inspect"), OBFSTR("driver"),
        OBFSTR("Deep Packet Inspection engine. Analyzes live network traffic at the kernel level. "
               "Automatically detects and parses HTTP (method, host, path), TLS (version, SNI, content type), "
               "and DNS packets. Shows TCP flags, sequence numbers, and window sizes. "
               "Like Wireshark's protocol dissectors but running inside the kernel."),
        {{OBFSTR("filter_pid"), OBFSTR("number"), OBFSTR("Only show packets from this PID (0=all)"), false},
         {OBFSTR("filter_protocol"), OBFSTR("string"), OBFSTR("'tcp', 'udp', or number (0=all)"), false},
         {OBFSTR("filter_port"), OBFSTR("number"), OBFSTR("Only show packets on this port (0=all)"), false},
         {OBFSTR("http_only"), OBFSTR("boolean"), OBFSTR("Only show HTTP packets"), false},
         {OBFSTR("tls_only"), OBFSTR("boolean"), OBFSTR("Only show TLS packets"), false},
         {OBFSTR("dns_only"), OBFSTR("boolean"), OBFSTR("Only show DNS packets"), false}},
        driver_deep_inspect, true});

    registry.register_tool({
        OBFSTR("driver_intercept_hold"), OBFSTR("driver"),
        OBFSTR("Burp Suite-style intercept-and-hold at the kernel level. When enabled, matching packets "
               "are BLOCKED and held in a buffer. You can inspect them, then release (forward), drop, or "
               "modify-and-release each packet. Up to 32 packets can be held simultaneously. "
               "Operations: enable, disable, status, get/get_held, release, drop, modify/modify_release."),
        {{OBFSTR("operation"), OBFSTR("string"),
          OBFSTR("'enable', 'disable', 'status', 'get'/'get_held', 'release', 'drop', 'modify'/'modify_release'"), false,
          {OBFSTR("enable"), OBFSTR("disable"), OBFSTR("status"), OBFSTR("get"), OBFSTR("get_held"),
           OBFSTR("release"), OBFSTR("drop"), OBFSTR("modify"), OBFSTR("modify_release")}},
         {OBFSTR("filter_pid"), OBFSTR("number"), OBFSTR("PID filter for enable"), false},
         {OBFSTR("filter_port"), OBFSTR("number"), OBFSTR("Port filter for enable"), false},
         {OBFSTR("filter_protocol"), OBFSTR("string"), OBFSTR("Protocol filter for enable"), false},
         {OBFSTR("hold_id"), OBFSTR("number"), OBFSTR("Packet ID for release/drop/modify"), false},
         {OBFSTR("modify_payload"), OBFSTR("string"), OBFSTR("New hex payload for modify_release"), false}},
        driver_intercept_hold, false});

    registry.register_tool({
        OBFSTR("driver_kill_connection"), OBFSTR("driver"),
        OBFSTR("Kill a TCP connection by injecting a RST packet via the kernel WFP injection API. "
               "Instantly terminates the connection from the kernel level. Cannot be blocked by "
               "usermode firewalls or anti-cheat."),
        {{OBFSTR("src_addr"), OBFSTR("string"), OBFSTR("Source IP of the connection"), true},
         {OBFSTR("dst_addr"), OBFSTR("string"), OBFSTR("Destination IP"), true},
         {OBFSTR("src_port"), OBFSTR("number"), OBFSTR("Source port"), true},
         {OBFSTR("dst_port"), OBFSTR("number"), OBFSTR("Destination port"), true},
         {OBFSTR("protocol"), OBFSTR("string"), OBFSTR("'tcp' (default)"), false},
         {OBFSTR("pid"), OBFSTR("number"), OBFSTR("Optional PID filter"), false}},
        driver_kill_connection, false});

    registry.register_tool({
        OBFSTR("driver_spoof_dns"), OBFSTR("driver"),
        OBFSTR("Manage kernel-level DNS spoofing rules. When a DNS query matches a rule domain, "
               "a fake response with the configured IP is returned. Supports wildcard domains "
               "(e.g. '*.example.com'). Operations: add, remove, list, clear."),
        {{OBFSTR("operation"), OBFSTR("string"), OBFSTR("'add', 'remove', 'list', 'clear'"), false,
          {OBFSTR("add"), OBFSTR("remove"), OBFSTR("list"), OBFSTR("clear")}},
         {OBFSTR("domain"), OBFSTR("string"), OBFSTR("Domain to match (e.g. '*.evil.com')"), false},
         {OBFSTR("spoof_addr"), OBFSTR("string"), OBFSTR("Fake IP to return (e.g. '127.0.0.1')"), false},
         {OBFSTR("ttl"), OBFSTR("number"), OBFSTR("TTL for spoofed response (default 300)"), false}},
        driver_spoof_dns, false});

    registry.register_tool({
        OBFSTR("driver_bandwidth_monitor"), OBFSTR("driver"),
        OBFSTR("Per-process bandwidth monitoring from the kernel. Tracks bytes/packets sent and received "
               "for every process on the system with rate calculation. Like NetLimiter/GlassWire but "
               "from kernel WFP. Operations: start, stop, status/get, reset, per_process."),
        {{OBFSTR("operation"), OBFSTR("string"),
          OBFSTR("'start', 'stop', 'status'/'get', 'reset', 'per_process'"), false,
          {OBFSTR("start"), OBFSTR("stop"), OBFSTR("status"), OBFSTR("get"), OBFSTR("reset"), OBFSTR("per_process")}},
         {OBFSTR("filter_pid"), OBFSTR("number"), OBFSTR("Filter by PID (0=all)"), false}},
        driver_bandwidth_monitor, false});

    registry.register_tool({
        OBFSTR("driver_list_interfaces"), OBFSTR("driver"),
        OBFSTR("Enumerate all network interfaces from the kernel via GetIfTable2. Returns interface index, "
               "type (Ethernet/WiFi/Loopback), MTU, operational status, link speed, MAC address, "
               "IPv4 address, interface name, description, and byte counters."),
        {},
        driver_list_interfaces, true});

    registry.register_tool({
        OBFSTR("driver_export_pcap"), OBFSTR("driver"),
        OBFSTR("Export captured network packets in standard PCAP format that can be opened in Wireshark. "
               "Builds proper PCAP file headers (magic 0xa1b2c3d4, v2.4, LINKTYPE_RAW). "
               "Optionally saves directly to a .pcap file. Requires capture to be active first."),
        {{OBFSTR("filter_pid"), OBFSTR("number"), OBFSTR("Only export packets from this PID"), false},
         {OBFSTR("filter_protocol"), OBFSTR("string"), OBFSTR("'tcp', 'udp', or number"), false},
         {OBFSTR("max_packets"), OBFSTR("number"), OBFSTR("Maximum packets to export (default 64, max 256)"), false},
         {OBFSTR("output_path"), OBFSTR("string"),
          OBFSTR("Save to this file path (e.g. 'C:\\\\capture.pcap'). If omitted, returns data inline."), false}},
        driver_export_pcap, false});

    registry.register_tool({
        OBFSTR("driver_network_fingerprint"), OBFSTR("driver"),
        OBFSTR("Passive OS fingerprinting from TCP SYN packets (p0f-style). Analyzes TTL, TCP window size, "
               "MSS, window scale, SACK, and TCP options ordering to identify the remote operating system. "
               "Runs entirely in the kernel WFP layer. Operations: enable, disable, get."),
        {{OBFSTR("operation"), OBFSTR("string"), OBFSTR("'enable', 'disable', 'get' (default get)"), false,
          {OBFSTR("enable"), OBFSTR("disable"), OBFSTR("get")}}},
        driver_network_fingerprint, true});

    registry.register_tool({
        OBFSTR("driver_enum_kernel_callbacks"), OBFSTR("driver"),
        OBFSTR("Enumerate kernel notification callbacks: process creation (PsSetCreateProcessNotifyRoutine), "
               "thread creation (PsSetCreateThreadNotifyRoutine), image load (PsSetLoadImageNotifyRoutine), "
               "registry (CmRegisterCallbackEx), object (ObRegisterCallbacks). Identifies which driver module "
               "registered each callback. Essential for understanding anti-cheat monitoring."),
        {},
        driver_enum_kernel_callbacks, true});

    registry.register_tool({
        OBFSTR("driver_detect_integrity_checks"), OBFSTR("driver"),
        OBFSTR("Check critical ntoskrnl exports for inline hooks (jmp, mov rax + jmp, int3). "
               "Scans NtReadVirtualMemory, NtWriteVirtualMemory, NtOpenProcess, MmCopyVirtualMemory, "
               "KeStackAttachProcess, and 14 other critical functions. Identifies hook owner module. "
               "Reveals which kernel functions anti-cheats are monitoring."),
        {},
        driver_detect_integrity_checks, true});

    registry.register_tool({
        OBFSTR("driver_detect_ssdt_hooks"), OBFSTR("driver"),
        OBFSTR("Detect SSDT (System Service Descriptor Table) hooks. Reads KeServiceDescriptorTable, "
               "resolves all syscall function pointers, and identifies entries redirected outside ntoskrnl. "
               "Anti-cheats hook SSDT to intercept NtReadVirtualMemory, NtOpenProcess, etc. "
               "Returns hooked syscall IDs, target addresses, and hook owner modules."),
        {},
        driver_detect_ssdt_hooks, true});

    registry.register_tool({
        OBFSTR("driver_enum_minifilters"), OBFSTR("driver"),
        OBFSTR("Enumerate registered filesystem minifilter drivers via Filter Manager (fltmgr.sys). "
               "Minifilters intercept file I/O — anti-cheats use them to monitor file access, "
               "prevent memory dumps, and detect injection DLLs. Returns filter names, altitudes, and owner modules."),
        {},
        driver_enum_minifilters, true});

    registry.register_tool({
        OBFSTR("driver_detect_etw_monitors"), OBFSTR("driver"),
        OBFSTR("Detect active ETW (Event Tracing for Windows) monitoring. Checks if the Threat Intelligence "
               "provider is active (monitors process injection, executable memory allocation). "
               "Scans for known security ETW provider GUIDs and identifies kernel modules that import EtwRegister/EtwWrite."),
        {},
        driver_detect_etw_monitors, true});

    registry.register_tool({
        OBFSTR("driver_detect_hidden_modules"), OBFSTR("driver"),
        OBFSTR("Detect manually mapped or hidden PE modules not in the PEB module list (usermode) or "
               "NtQuerySystemInformation list (kernel). Scans memory for PE headers at non-listed addresses. "
               "Finds injected DLLs, manual-mapped anti-cheat drivers, and stealth payloads. "
               "Returns hidden module addresses, sizes, and export names when available."),
        {{OBFSTR("kernel"), OBFSTR("boolean"), OBFSTR("Scan kernel space instead of attached process (default: false)"), false}},
        driver_detect_hidden_modules, true});
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


namespace network_tools
{

using json = nlohmann::json;

static std::string format_ip(const std::uint8_t* addr, std::uint32_t af) {
    char buf[64] = {};
    if (af == 23) {
        qsnprintf(buf, sizeof(buf), "%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x",
            addr[0], addr[1], addr[2], addr[3], addr[4], addr[5], addr[6], addr[7],
            addr[8], addr[9], addr[10], addr[11], addr[12], addr[13], addr[14], addr[15]);
    } else {
        qsnprintf(buf, sizeof(buf), "%u.%u.%u.%u", addr[0], addr[1], addr[2], addr[3]);
    }
    return buf;
}

static bool parse_ipv4(const std::string& s, std::uint8_t* out) {
    unsigned a, b, c, d;
    if (sscanf(s.c_str(), "%u.%u.%u.%u", &a, &b, &c, &d) != 4) return false;
    if (a > 255 || b > 255 || c > 255 || d > 255) return false;
    out[0] = (std::uint8_t)a; out[1] = (std::uint8_t)b;
    out[2] = (std::uint8_t)c; out[3] = (std::uint8_t)d;
    return true;
}

static std::string protocol_name(std::uint32_t proto) {
    switch (proto) {
        case 6: return "TCP";
        case 17: return "UDP";
        case 1: return "ICMP";
        default: return std::to_string(proto);
    }
}

static std::string tcp_state_name(std::uint32_t state) {
    switch (state) {
        case 0: return "CLOSED";
        case 1: return "LISTEN";
        case 2: return "SYN_SENT";
        case 3: return "SYN_RCVD";
        case 4: return "ESTABLISHED";
        case 5: return "FIN_WAIT1";
        case 6: return "FIN_WAIT2";
        case 7: return "CLOSE_WAIT";
        case 8: return "CLOSING";
        case 9: return "LAST_ACK";
        case 10: return "TIME_WAIT";
        case 11: return "DELETE_TCB";
        default: return std::to_string(state);
    }
}

static std::string direction_name(std::uint32_t dir) {
    return dir == 0 ? "INBOUND" : "OUTBOUND";
}

static std::string hex_dump(const std::uint8_t* data, std::size_t len, std::size_t max_bytes = 256) {
    std::string result;
    std::size_t show = (len < max_bytes) ? len : max_bytes;
    for (std::size_t i = 0; i < show; i++) {
        char hex[4];
        qsnprintf(hex, sizeof(hex), "%02X ", data[i]);
        result += hex;
        if ((i + 1) % 16 == 0) result += "\n";
    }
    if (show < len) result += "... (" + std::to_string(len - show) + " more bytes)";
    return result;
}

static std::string extract_ascii(const std::uint8_t* data, std::size_t len, std::size_t max_chars = 512) {
    std::string result;
    std::size_t show = (len < max_chars) ? len : max_chars;
    for (std::size_t i = 0; i < show; i++) {
        result += (data[i] >= 0x20 && data[i] < 0x7F) ? (char)data[i] : '.';
    }
    return result;
}

tool_result_t network_enumerate_connections(const json& params)
{
    if (!device->is_connected())
        return tool_result_t::error(OBFSTR("Driver not connected. Call driver_connect first."));

    std::uint32_t filter_pid = 0, filter_protocol = 0;
    if (params.contains("pid") && params["pid"].is_number())
        filter_pid = params["pid"].get<std::uint32_t>();
    if (params.contains("protocol") && params["protocol"].is_string()) {
        std::string p = params["protocol"].get<std::string>();
        if (p == "tcp" || p == "TCP") filter_protocol = 6;
        else if (p == "udp" || p == "UDP") filter_protocol = 17;
    } else if (params.contains("protocol") && params["protocol"].is_number()) {
        filter_protocol = params["protocol"].get<std::uint32_t>();
    }

    auto conns = device->enumerate_connections(filter_pid, filter_protocol);

    json arr = json::array();
    for (const auto& c : conns) {
        json entry;
        entry["pid"] = c.pid;
        entry["protocol"] = protocol_name(c.protocol);
        entry["state"] = (c.protocol == 6) ? tcp_state_name(c.state) : "N/A";
        entry["local_address"] = format_ip(c.local_addr, c.address_family);
        entry["local_port"] = c.local_port;
        entry["remote_address"] = format_ip(c.remote_addr, c.address_family);
        entry["remote_port"] = c.remote_port;
        arr.push_back(entry);
    }

    return tool_result_t::ok(
        std::to_string(conns.size()) + OBFSTR(" active connections found"), arr);
}

tool_result_t network_start_capture(const json& params)
{
    if (!device->is_connected())
        return tool_result_t::error(OBFSTR("Driver not connected. Call driver_connect first."));

    std::uint32_t filter_pid = 0, filter_port = 0, filter_protocol = 0, max_payload = 1500;
    std::uint8_t filter_ip[16] = {};

    if (params.contains("pid") && params["pid"].is_number())
        filter_pid = params["pid"].get<std::uint32_t>();
    if (params.contains("port") && params["port"].is_number())
        filter_port = params["port"].get<std::uint32_t>();
    if (params.contains("protocol") && params["protocol"].is_string()) {
        std::string p = params["protocol"].get<std::string>();
        if (p == "tcp" || p == "TCP") filter_protocol = 6;
        else if (p == "udp" || p == "UDP") filter_protocol = 17;
    } else if (params.contains("protocol") && params["protocol"].is_number()) {
        filter_protocol = params["protocol"].get<std::uint32_t>();
    }
    if (params.contains("ip") && params["ip"].is_string()) {
        parse_ipv4(params["ip"].get<std::string>(), filter_ip);
    }
    if (params.contains("max_payload") && params["max_payload"].is_number())
        max_payload = params["max_payload"].get<std::uint32_t>();

    bool ok = device->start_capture(filter_pid, filter_port, filter_protocol,
        filter_ip, max_payload);

    if (!ok)
        return tool_result_t::error(OBFSTR("Failed to start packet capture. Network subsystem may not be ready."));

    json result;
    result["capture_active"] = true;
    if (filter_pid) result["filter_pid"] = filter_pid;
    if (filter_port) result["filter_port"] = filter_port;
    if (filter_protocol) result["filter_protocol"] = protocol_name(filter_protocol);
    if (params.contains("ip")) result["filter_ip"] = params["ip"];
    result["max_payload"] = max_payload;

    return tool_result_t::ok(OBFSTR("Packet capture started via kernel WFP callouts"), result);
}

tool_result_t network_stop_capture(const json&)
{
    if (!device->is_connected())
        return tool_result_t::error(OBFSTR("Driver not connected."));

    if (!device->stop_capture())
        return tool_result_t::error(OBFSTR("Failed to stop packet capture."));

    return tool_result_t::ok(OBFSTR("Packet capture stopped"));
}

tool_result_t network_get_packets(const json& params)
{
    if (!device->is_connected())
        return tool_result_t::error(OBFSTR("Driver not connected."));

    std::uint32_t max_packets = 32;
    if (params.contains("count") && params["count"].is_number())
        max_packets = params["count"].get<std::uint32_t>();
    if (max_packets > 32) max_packets = 32;

    auto packets = device->get_captured_packets(max_packets);

    json arr = json::array();
    for (const auto& p : packets) {
        json entry;
        entry["timestamp"] = p.timestamp;
        entry["pid"] = p.pid;
        entry["protocol"] = protocol_name(p.protocol);
        entry["direction"] = direction_name(p.direction);
        entry["local_address"] = format_ip(p.local_addr, p.address_family);
        entry["local_port"] = p.local_port;
        entry["remote_address"] = format_ip(p.remote_addr, p.address_family);
        entry["remote_port"] = p.remote_port;
        entry["payload_size"] = p.payload_size;
        if (!p.payload.empty()) {
            entry["hex_dump"] = hex_dump(p.payload.data(), p.payload.size());
            entry["ascii"] = extract_ascii(p.payload.data(), p.payload.size());
        }
        arr.push_back(entry);
    }

    return tool_result_t::ok(
        std::to_string(packets.size()) + OBFSTR(" packets retrieved"), arr);
}

tool_result_t network_analyze_packet(const json& params)
{
    if (!device->is_connected())
        return tool_result_t::error(OBFSTR("Driver not connected."));


    auto packets = device->get_captured_packets(1);
    if (packets.empty())
        return tool_result_t::error(OBFSTR("No packets available. Start capture first."));

    const auto& p = packets[0];
    json result;
    result["timestamp"] = p.timestamp;
    result["pid"] = p.pid;
    result["protocol"] = protocol_name(p.protocol);
    result["direction"] = direction_name(p.direction);
    result["src"] = format_ip(p.direction == 0 ? p.remote_addr : p.local_addr, p.address_family)
                    + ":" + std::to_string(p.direction == 0 ? p.remote_port : p.local_port);
    result["dst"] = format_ip(p.direction == 0 ? p.local_addr : p.remote_addr, p.address_family)
                    + ":" + std::to_string(p.direction == 0 ? p.local_port : p.remote_port);
    result["payload_size"] = p.payload_size;

    if (!p.payload.empty()) {
        result["hex_dump"] = hex_dump(p.payload.data(), p.payload.size(), 512);
        result["ascii_render"] = extract_ascii(p.payload.data(), p.payload.size());


        if (p.payload.size() >= 4) {
            std::string first4((const char*)p.payload.data(), std::min(p.payload.size(), (std::size_t)4));
            if (first4 == "GET " || first4 == "POST" || first4 == "HEAD" || first4 == "PUT " ||
                first4 == "DELE" || first4 == "HTTP") {
                result["detected_protocol"] = "HTTP";
                std::string http_text((const char*)p.payload.data(), p.payload.size());
                result["http_content"] = http_text;
            } else if (p.payload.size() >= 5 && p.payload[0] == 0x16 && p.payload[1] == 0x03) {
                result["detected_protocol"] = "TLS";
                std::uint8_t tls_ver_major = p.payload[1];
                std::uint8_t tls_ver_minor = p.payload[2];
                result["tls_version"] = std::to_string(tls_ver_major) + "." + std::to_string(tls_ver_minor);
                std::uint8_t content_type = p.payload[0];
                result["tls_content_type"] = content_type == 0x16 ? "Handshake" :
                    content_type == 0x17 ? "Application Data" :
                    content_type == 0x15 ? "Alert" : std::to_string(content_type);
            } else if (p.remote_port == 53 || p.local_port == 53) {
                result["detected_protocol"] = "DNS";
            }
        }
    }

    return tool_result_t::ok(OBFSTR("Packet analysis complete"), result);
}

tool_result_t network_dns_log(const json& params)
{
    if (!device->is_connected())
        return tool_result_t::error(OBFSTR("Driver not connected."));

    std::uint32_t filter_pid = 0;
    if (params.contains("pid") && params["pid"].is_number())
        filter_pid = params["pid"].get<std::uint32_t>();

    auto entries = device->get_dns_queries(filter_pid);

    json arr = json::array();
    for (const auto& e : entries) {
        json entry;
        entry["timestamp"] = e.timestamp;
        entry["pid"] = e.pid;
        entry["domain"] = e.domain;
        entry["query_type"] = e.query_type;
        entry["response_code"] = e.response_code;
        entry["ttl"] = e.ttl;

        bool has_addr = false;
        for (int i = 0; i < 16; i++) if (e.resolved_addr[i]) { has_addr = true; break; }
        if (has_addr) {
            entry["resolved_address"] = format_ip(e.resolved_addr, (e.query_type == 28) ? 23u : 2u);
        }


        switch (e.query_type) {
            case 1: entry["type_name"] = "A"; break;
            case 28: entry["type_name"] = "AAAA"; break;
            case 5: entry["type_name"] = "CNAME"; break;
            case 15: entry["type_name"] = "MX"; break;
            case 2: entry["type_name"] = "NS"; break;
            case 12: entry["type_name"] = "PTR"; break;
            case 16: entry["type_name"] = "TXT"; break;
            case 6: entry["type_name"] = "SOA"; break;
            case 33: entry["type_name"] = "SRV"; break;
            default: entry["type_name"] = "Type " + std::to_string(e.query_type); break;
        }

        arr.push_back(entry);
    }

    return tool_result_t::ok(
        std::to_string(entries.size()) + OBFSTR(" DNS entries retrieved"), arr);
}

tool_result_t network_add_filter(const json& params)
{
    if (!device->is_connected())
        return tool_result_t::error(OBFSTR("Driver not connected."));

    std::uint32_t action = 2;
    std::uint32_t direction = 2;
    std::uint32_t protocol = 0, pid = 0, port = 0;
    std::uint8_t ip_addr[16] = {}, ip_mask[16] = {};

    if (params.contains("action") && params["action"].is_string()) {
        std::string a = params["action"].get<std::string>();
        if (a == "allow") action = 0;
        else if (a == "block") action = 1;
        else if (a == "log") action = 2;
    }
    if (params.contains("direction") && params["direction"].is_string()) {
        std::string d = params["direction"].get<std::string>();
        if (d == "inbound" || d == "in") direction = 0;
        else if (d == "outbound" || d == "out") direction = 1;
        else if (d == "both") direction = 2;
    }
    if (params.contains("protocol") && params["protocol"].is_string()) {
        std::string p = params["protocol"].get<std::string>();
        if (p == "tcp" || p == "TCP") protocol = 6;
        else if (p == "udp" || p == "UDP") protocol = 17;
    } else if (params.contains("protocol") && params["protocol"].is_number()) {
        protocol = params["protocol"].get<std::uint32_t>();
    }
    if (params.contains("pid") && params["pid"].is_number())
        pid = params["pid"].get<std::uint32_t>();
    if (params.contains("port") && params["port"].is_number())
        port = params["port"].get<std::uint32_t>();
    if (params.contains("ip") && params["ip"].is_string()) {
        parse_ipv4(params["ip"].get<std::string>(), ip_addr);
        std::memset(ip_mask, 0xFF, 4);
    }

    std::uint32_t rule_id = 0;
    bool ok = device->add_filter_rule(action, direction, protocol, pid, port,
        ip_addr, ip_mask, &rule_id);

    if (!ok)
        return tool_result_t::error(OBFSTR("Failed to add filter rule. Rule table may be full."));

    json result;
    result["rule_id"] = rule_id;
    result["action"] = (action == 0) ? "allow" : (action == 1) ? "block" : "log";
    result["direction"] = (direction == 0) ? "inbound" : (direction == 1) ? "outbound" : "both";
    if (protocol) result["protocol"] = protocol_name(protocol);
    if (pid) result["pid"] = pid;
    if (port) result["port"] = port;
    if (params.contains("ip")) result["ip"] = params["ip"];

    return tool_result_t::ok(OBFSTR("Filter rule added (ID: ") + std::to_string(rule_id) + ")", result);
}

tool_result_t network_remove_filter(const json& params)
{
    if (!device->is_connected())
        return tool_result_t::error(OBFSTR("Driver not connected."));

    if (!params.contains("rule_id") || !params["rule_id"].is_number())
        return tool_result_t::error(OBFSTR("Missing required parameter: rule_id"));

    std::uint32_t rule_id = params["rule_id"].get<std::uint32_t>();
    if (!device->remove_filter_rule(rule_id))
        return tool_result_t::error(OBFSTR("Failed to remove filter rule ") + std::to_string(rule_id));

    return tool_result_t::ok(OBFSTR("Filter rule ") + std::to_string(rule_id) + OBFSTR(" removed"));
}

tool_result_t network_clear_filters(const json&)
{
    if (!device->is_connected())
        return tool_result_t::error(OBFSTR("Driver not connected."));

    if (!device->clear_filter_rules())
        return tool_result_t::error(OBFSTR("Failed to clear filter rules."));

    return tool_result_t::ok(OBFSTR("All filter rules cleared"));
}

tool_result_t network_stats(const json&)
{
    if (!device->is_connected())
        return tool_result_t::error(OBFSTR("Driver not connected."));

    voyager::device_t::network_stats stats{};
    if (!device->get_network_stats(stats))
        return tool_result_t::error(OBFSTR("Failed to get network stats."));

    json result;
    result["bytes_sent"] = stats.bytes_sent;
    result["bytes_received"] = stats.bytes_received;
    result["packets_sent"] = stats.packets_sent;
    result["packets_received"] = stats.packets_received;
    result["capture_active"] = stats.capture_active != 0;
    result["total_captured"] = stats.total_captured;
    result["total_dropped"] = stats.total_dropped;
    result["total_dns_logged"] = stats.total_dns_logged;
    result["active_filter_rules"] = stats.active_filter_rules;

    return tool_result_t::ok(OBFSTR("Network statistics"), result);
}

tool_result_t network_capture_status(const json&)
{
    if (!device->is_connected())
        return tool_result_t::error(OBFSTR("Driver not connected."));

    bool active = false;
    std::uint32_t captured = 0, dropped = 0;
    if (!device->get_capture_status(active, captured, dropped))
        return tool_result_t::error(OBFSTR("Failed to get capture status."));

    json result;
    result["capture_active"] = active;
    result["packets_captured"] = captured;
    result["packets_dropped"] = dropped;

    return tool_result_t::ok(active ? OBFSTR("Capture is active") : OBFSTR("Capture is stopped"), result);
}

tool_result_t network_block_ip(const json& params)
{
    if (!device->is_connected())
        return tool_result_t::error(OBFSTR("Driver not connected."));

    if (!params.contains("ip") || !params["ip"].is_string())
        return tool_result_t::error(OBFSTR("Missing required parameter: ip (e.g. '192.168.1.1')"));

    std::uint8_t ip[16] = {}, mask[16] = {};
    if (!parse_ipv4(params["ip"].get<std::string>(), ip))
        return tool_result_t::error(OBFSTR("Invalid IPv4 address"));

    std::memset(mask, 0xFF, 4);

    std::uint32_t direction = 2;
    if (params.contains("direction") && params["direction"].is_string()) {
        std::string d = params["direction"].get<std::string>();
        if (d == "inbound" || d == "in") direction = 0;
        else if (d == "outbound" || d == "out") direction = 1;
    }

    std::uint32_t rule_id = 0;
    if (!device->add_filter_rule(1, direction, 0, 0, 0, ip, mask, &rule_id))
        return tool_result_t::error(OBFSTR("Failed to add block rule"));

    json result;
    result["rule_id"] = rule_id;
    result["blocked_ip"] = params["ip"];
    result["direction"] = (direction == 0) ? "inbound" : (direction == 1) ? "outbound" : "both";
    return tool_result_t::ok(OBFSTR("IP blocked: ") + params["ip"].get<std::string>(), result);
}

tool_result_t network_block_port(const json& params)
{
    if (!device->is_connected())
        return tool_result_t::error(OBFSTR("Driver not connected."));

    if (!params.contains("port") || !params["port"].is_number())
        return tool_result_t::error(OBFSTR("Missing required parameter: port"));

    std::uint32_t port = params["port"].get<std::uint32_t>();
    std::uint32_t protocol = 0;
    if (params.contains("protocol") && params["protocol"].is_string()) {
        std::string p = params["protocol"].get<std::string>();
        if (p == "tcp" || p == "TCP") protocol = 6;
        else if (p == "udp" || p == "UDP") protocol = 17;
    }

    std::uint32_t rule_id = 0;
    if (!device->add_filter_rule(1, 2, protocol, 0, port, nullptr, nullptr, &rule_id))
        return tool_result_t::error(OBFSTR("Failed to add port block rule"));

    json result;
    result["rule_id"] = rule_id;
    result["blocked_port"] = port;
    if (protocol) result["protocol"] = protocol_name(protocol);
    return tool_result_t::ok(OBFSTR("Port blocked: ") + std::to_string(port), result);
}

tool_result_t network_block_process(const json& params)
{
    if (!device->is_connected())
        return tool_result_t::error(OBFSTR("Driver not connected."));

    if (!params.contains("pid") || !params["pid"].is_number())
        return tool_result_t::error(OBFSTR("Missing required parameter: pid"));

    std::uint32_t pid = params["pid"].get<std::uint32_t>();

    std::uint32_t rule_id = 0;
    if (!device->add_filter_rule(1, 2, 0, pid, 0, nullptr, nullptr, &rule_id))
        return tool_result_t::error(OBFSTR("Failed to add process block rule"));

    json result;
    result["rule_id"] = rule_id;
    result["blocked_pid"] = pid;
    return tool_result_t::ok(OBFSTR("All network traffic blocked for PID ") + std::to_string(pid), result);
}


struct parsed_http_msg_t {
    bool is_request = false;
    bool is_response = false;
    std::string method;
    std::string uri;
    std::string http_version;
    int status_code = 0;
    std::string reason_phrase;
    std::vector<std::pair<std::string, std::string>> headers;
    std::string body;
    bool body_truncated = false;
};

static bool try_parse_http_msg(const std::uint8_t* data, std::size_t len, parsed_http_msg_t& out) {
    if (len < 10) return false;
    std::size_t parse_len = (len > 16384) ? 16384 : len;
    std::string text(reinterpret_cast<const char*>(data), parse_len);

    auto crlf = text.find("\r\n");
    if (crlf == std::string::npos) return false;
    std::string first_line = text.substr(0, crlf);

    static const char* http_methods[] = {"GET","POST","PUT","DELETE","HEAD","OPTIONS","PATCH","CONNECT","TRACE"};
    for (const char* m : http_methods) {
        std::size_t mlen = std::strlen(m);
        if (first_line.size() > mlen + 1 && first_line.compare(0, mlen, m) == 0 && first_line[mlen] == ' ') {
            out.is_request = true;
            out.method = m;
            auto sp = first_line.rfind(' ');
            if (sp != std::string::npos && sp > mlen + 1) {
                out.uri = first_line.substr(mlen + 1, sp - mlen - 1);
                out.http_version = first_line.substr(sp + 1);
            } else {
                out.uri = first_line.substr(mlen + 1);
            }
            break;
        }
    }

    if (!out.is_request && first_line.size() > 12 && first_line.compare(0, 5, "HTTP/") == 0) {
        out.is_response = true;
        auto sp1 = first_line.find(' ');
        if (sp1 != std::string::npos) {
            out.http_version = first_line.substr(0, sp1);
            auto sp2 = first_line.find(' ', sp1 + 1);
            std::string code_str = (sp2 != std::string::npos) ? first_line.substr(sp1+1, sp2-sp1-1) : first_line.substr(sp1+1);
            out.status_code = std::atoi(code_str.c_str());
            if (sp2 != std::string::npos) out.reason_phrase = first_line.substr(sp2 + 1);
        }
    }

    if (!out.is_request && !out.is_response) return false;

    std::size_t pos = crlf + 2;
    while (pos < text.size()) {
        auto next = text.find("\r\n", pos);
        if (next == std::string::npos) break;
        if (next == pos) { pos += 2; break; }
        std::string line = text.substr(pos, next - pos);
        auto colon = line.find(':');
        if (colon != std::string::npos) {
            std::string name = line.substr(0, colon);
            std::string value = line.substr(colon + 1);
            while (!value.empty() && (value[0] == ' ' || value[0] == '\t')) value.erase(0, 1);
            out.headers.emplace_back(name, value);
        }
        pos = next + 2;
    }

    if (pos < parse_len) {
        std::size_t body_max = 4096;
        std::size_t avail = parse_len - pos;
        out.body = text.substr(pos, (avail < body_max) ? avail : body_max);
        out.body_truncated = (avail > body_max);
    }
    return true;
}

struct parsed_tls_info_t {
    std::uint8_t content_type = 0;
    std::uint16_t record_version = 0;
    std::uint8_t handshake_type = 0;
    std::uint16_t client_version = 0;
    std::string sni;
    std::vector<std::string> alpn_protocols;
    std::vector<std::uint16_t> cipher_suites;
    std::uint16_t selected_cipher = 0;
    bool is_http2 = false;
};

static std::string tls_cipher_name(std::uint16_t cs) {
    switch (cs) {
        case 0x1301: return "TLS_AES_128_GCM_SHA256";
        case 0x1302: return "TLS_AES_256_GCM_SHA384";
        case 0x1303: return "TLS_CHACHA20_POLY1305_SHA256";
        case 0xC02C: return "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384";
        case 0xC02B: return "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256";
        case 0xC030: return "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384";
        case 0xC02F: return "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256";
        case 0xCCA9: return "TLS_ECDHE_ECDSA_CHACHA20_POLY1305";
        case 0xCCA8: return "TLS_ECDHE_RSA_CHACHA20_POLY1305";
        case 0x009E: return "TLS_DHE_RSA_WITH_AES_128_GCM_SHA256";
        case 0x009F: return "TLS_DHE_RSA_WITH_AES_256_GCM_SHA384";
        case 0x002F: return "TLS_RSA_WITH_AES_128_CBC_SHA";
        case 0x0035: return "TLS_RSA_WITH_AES_256_CBC_SHA";
        case 0x00FF: return "RENEGOTIATION_INFO_SCSV";
        default: { char buf[16]; qsnprintf(buf, sizeof(buf), "0x%04X", cs); return buf; }
    }
}

static std::string tls_version_str(std::uint16_t ver) {
    switch (ver) {
        case 0x0300: return "SSL 3.0";
        case 0x0301: return "TLS 1.0";
        case 0x0302: return "TLS 1.1";
        case 0x0303: return "TLS 1.2";
        case 0x0304: return "TLS 1.3";
        default: { char buf[16]; qsnprintf(buf, sizeof(buf), "0x%04X", ver); return buf; }
    }
}

static std::string tls_content_type_str(std::uint8_t ct) {
    switch (ct) {
        case 20: return "ChangeCipherSpec";
        case 21: return "Alert";
        case 22: return "Handshake";
        case 23: return "ApplicationData";
        default: return std::to_string(ct);
    }
}

static std::string tls_handshake_type_str(std::uint8_t ht) {
    switch (ht) {
        case 1: return "ClientHello"; case 2: return "ServerHello";
        case 11: return "Certificate"; case 12: return "ServerKeyExchange";
        case 14: return "ServerHelloDone"; case 16: return "ClientKeyExchange";
        case 20: return "Finished";
        default: return "Type " + std::to_string(ht);
    }
}

static bool try_parse_tls_record(const std::uint8_t* data, std::size_t len, parsed_tls_info_t& out) {
    if (len < 5) return false;
    out.content_type = data[0];
    out.record_version = (static_cast<std::uint16_t>(data[1]) << 8) | data[2];
    if (out.content_type < 20 || out.content_type > 23) return false;
    if (data[1] != 0x03) return false;
    if (out.content_type != 22 || len < 9) return true;

    std::size_t off = 5;
    out.handshake_type = data[off];
    if (out.handshake_type != 1 && out.handshake_type != 2) return true;
    if (off + 6 >= len) return true;
    out.client_version = (static_cast<std::uint16_t>(data[off+4]) << 8) | data[off+5];

    std::size_t pos = off + 4 + 2 + 32;
    if (pos >= len) return true;
    std::uint8_t sid_len = data[pos++];
    pos += sid_len;
    if (pos >= len) return true;

    if (out.handshake_type == 1) {
        if (pos + 2 > len) return true;
        std::uint16_t cs_len = (static_cast<std::uint16_t>(data[pos]) << 8) | data[pos + 1];
        pos += 2;
        for (std::uint16_t i = 0; i + 1 < cs_len && pos + 1 < len; i += 2) {
            out.cipher_suites.push_back((static_cast<std::uint16_t>(data[pos]) << 8) | data[pos + 1]);
            pos += 2;
        }
        if (pos >= len) return true;
        std::uint8_t comp_len = data[pos++];
        pos += comp_len;
    } else {
        if (pos + 2 > len) return true;
        out.selected_cipher = (static_cast<std::uint16_t>(data[pos]) << 8) | data[pos + 1];
        pos += 3;
    }

    if (pos + 2 > len) return true;
    std::uint16_t ext_total = (static_cast<std::uint16_t>(data[pos]) << 8) | data[pos + 1];
    pos += 2;
    std::size_t ext_end = pos + ext_total;
    if (ext_end > len) ext_end = len;

    while (pos + 4 <= ext_end) {
        std::uint16_t ext_type = (static_cast<std::uint16_t>(data[pos]) << 8) | data[pos + 1];
        std::uint16_t ext_len = (static_cast<std::uint16_t>(data[pos + 2]) << 8) | data[pos + 3];
        pos += 4;
        if (pos + ext_len > ext_end) break;

        if (ext_type == 0 && ext_len >= 5) {
            std::size_t sp = pos + 2;
            if (sp < pos + ext_len && data[sp] == 0) {
                sp++;
                if (sp + 2 <= pos + ext_len) {
                    std::uint16_t nlen = (static_cast<std::uint16_t>(data[sp]) << 8) | data[sp+1];
                    sp += 2;
                    if (sp + nlen <= pos + ext_len)
                        out.sni.assign(reinterpret_cast<const char*>(&data[sp]), nlen);
                }
            }
        }
        if (ext_type == 16 && ext_len >= 2) {
            std::size_t ap = pos + 2;
            while (ap < pos + ext_len) {
                std::uint8_t plen = data[ap++];
                if (ap + plen > pos + ext_len) break;
                std::string proto(reinterpret_cast<const char*>(&data[ap]), plen);
                out.alpn_protocols.push_back(proto);
                if (proto == "h2") out.is_http2 = true;
                ap += plen;
            }
        }
        pos += ext_len;
    }
    return true;
}

static const char* http_method_id_name(std::uint32_t m) {
    switch (m) {
        case 1: return "GET"; case 2: return "POST"; case 3: return "PUT";
        case 4: return "DELETE"; case 5: return "HEAD"; case 6: return "OPTIONS";
        case 7: return "PATCH"; case 8: return "CONNECT"; case 9: return "TRACE";
        default: return "UNKNOWN";
    }
}

static std::vector<std::uint8_t> hex_string_to_bytes(const std::string& hex) {
    std::vector<std::uint8_t> out;
    std::string clean;
    for (char c : hex) {
        if (c != ' ' && c != ':' && c != '-') clean += c;
    }
    out.reserve(clean.size() / 2);
    for (std::size_t i = 0; i + 1 < clean.size(); i += 2) {
        auto nib = [](char c) -> int {
            if (c >= '0' && c <= '9') return c - '0';
            if (c >= 'a' && c <= 'f') return 10 + c - 'a';
            if (c >= 'A' && c <= 'F') return 10 + c - 'A';
            return -1;
        };
        int h = nib(clean[i]), l = nib(clean[i+1]);
        if (h >= 0 && l >= 0) out.push_back(static_cast<std::uint8_t>((h << 4) | l));
    }
    return out;
}

static std::string bytes_to_hex_string(const std::uint8_t* data, std::size_t len, std::size_t max_bytes = 512) {
    std::string result;
    std::size_t show = (len < max_bytes) ? len : max_bytes;
    for (std::size_t i = 0; i < show; i++) {
        char hex[4]; qsnprintf(hex, sizeof(hex), "%02X", data[i]);
        result += hex;
    }
    if (show < len) result += "...(" + std::to_string(len - show) + " more)";
    return result;
}

static std::string format_mac(const std::uint8_t* mac) {
    char buf[20];
    qsnprintf(buf, sizeof(buf), "%02X:%02X:%02X:%02X:%02X:%02X",
        mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
    return buf;
}

static std::string format_ipv4_bytes(const std::uint8_t* ip) {
    char buf[20];
    qsnprintf(buf, sizeof(buf), "%u.%u.%u.%u", ip[0], ip[1], ip[2], ip[3]);
    return buf;
}


tool_result_t network_deep_inspect(const json& params)
{
    if (!device->is_connected())
        return tool_result_t::error(OBFSTR("Driver not connected."));

    std::uint32_t filter_pid = 0, filter_protocol = 0, filter_port = 0;
    if (params.contains("pid") && params["pid"].is_number()) filter_pid = params["pid"].get<std::uint32_t>();
    if (params.contains("port") && params["port"].is_number()) filter_port = params["port"].get<std::uint32_t>();
    if (params.contains("protocol") && params["protocol"].is_string()) {
        std::string p = params["protocol"].get<std::string>();
        if (p == "tcp" || p == "TCP") filter_protocol = 6;
        else if (p == "udp" || p == "UDP") filter_protocol = 17;
    }

    auto results = device->get_dpi_results(filter_pid, filter_protocol, filter_port, 0);
    json arr = json::array();
    for (const auto& d : results) {
        json entry;
        entry["timestamp"] = d.timestamp;
        entry["direction"] = direction_name(d.direction);
        entry["protocol"] = protocol_name(d.protocol);
        entry["src"] = format_ip(d.src_addr, d.af) + ":" + std::to_string(d.src_port);
        entry["dst"] = format_ip(d.dst_addr, d.af) + ":" + std::to_string(d.dst_port);
        entry["pid"] = d.pid;
        entry["payload_size"] = d.payload_size;
        if (d.protocol == 6) {
            entry["tcp_flags"] = d.tcp_flags;
            entry["tcp_window"] = d.tcp_window;
        }
        if (d.is_http) {
            entry["app_protocol"] = "HTTP";
            entry["http_method"] = http_method_id_name(d.http_method);
            if (!d.http_host.empty()) entry["http_host"] = d.http_host;
            if (!d.http_path.empty()) entry["http_path"] = d.http_path;
        }
        if (d.is_tls) {
            entry["app_protocol"] = "TLS";
            entry["tls_version"] = tls_version_str(static_cast<std::uint16_t>(d.tls_version));
            entry["tls_content_type"] = tls_content_type_str(static_cast<std::uint8_t>(d.tls_content_type));
            if (!d.tls_sni.empty()) entry["tls_sni"] = d.tls_sni;
        }
        if (d.is_dns) entry["app_protocol"] = "DNS";
        arr.push_back(entry);
    }
    return tool_result_t::ok(std::to_string(results.size()) + OBFSTR(" DPI results"), arr);
}

tool_result_t network_follow_tcp_stream(const json& params)
{
    if (!device->is_connected())
        return tool_result_t::error(OBFSTR("Driver not connected."));
    if (!params.contains("operation") || !params["operation"].is_string())
        return tool_result_t::error(OBFSTR("Missing required parameter: operation ('start', 'stop', or 'get')"));

    std::string op = params["operation"].get<std::string>();
    std::uint32_t src_port = 0, dst_port = 0, pid = 0;
    if (params.contains("src_port") && params["src_port"].is_number()) src_port = params["src_port"].get<std::uint32_t>();
    if (params.contains("dst_port") && params["dst_port"].is_number()) dst_port = params["dst_port"].get<std::uint32_t>();
    if (params.contains("pid") && params["pid"].is_number()) pid = params["pid"].get<std::uint32_t>();

    if (op == "start") {
        bool ok = device->stream_reassemble_op(0, src_port, dst_port, pid, nullptr, nullptr, nullptr, nullptr, nullptr);
        if (!ok) return tool_result_t::error(OBFSTR("Failed to start stream reassembly. Max 8 concurrent streams."));
        json r; r["status"] = "started"; r["src_port"] = src_port; r["dst_port"] = dst_port;
        return tool_result_t::ok(OBFSTR("TCP stream reassembly started"), r);
    } else if (op == "stop") {
        bool ok = device->stream_reassemble_op(1, src_port, dst_port, pid, nullptr, nullptr, nullptr, nullptr, nullptr);
        if (!ok) return tool_result_t::error(OBFSTR("Failed to stop stream reassembly."));
        return tool_result_t::ok(OBFSTR("TCP stream reassembly stopped"));
    } else if (op == "get") {
        std::vector<std::uint8_t> stream_data;
        std::uint32_t total_packets = 0, truncated = 0;
        bool ok = device->stream_reassemble_op(2, src_port, dst_port, pid, nullptr, nullptr, &stream_data, &total_packets, &truncated);
        if (!ok) return tool_result_t::error(OBFSTR("Failed to get reassembled stream data."));
        json r;
        r["total_bytes"] = stream_data.size();
        r["total_packets"] = total_packets;
        r["truncated"] = truncated;
        if (!stream_data.empty()) {
            r["hex_dump"] = hex_dump(stream_data.data(), stream_data.size(), 1024);
            r["ascii"] = extract_ascii(stream_data.data(), stream_data.size(), 2048);
        }
        return tool_result_t::ok(std::to_string(stream_data.size()) + OBFSTR(" bytes reassembled"), r);
    }
    return tool_result_t::error(OBFSTR("Invalid operation. Use 'start', 'stop', or 'get'."));
}

tool_result_t network_parse_http(const json& params)
{
    if (!device->is_connected())
        return tool_result_t::error(OBFSTR("Driver not connected."));

    std::uint32_t max_pkts = 32;
    if (params.contains("count") && params["count"].is_number())
        max_pkts = params["count"].get<std::uint32_t>();
    if (max_pkts > 32) max_pkts = 32;

    auto packets = device->get_captured_packets(max_pkts);
    json arr = json::array();
    for (const auto& p : packets) {
        if (p.payload.empty()) continue;
        parsed_http_msg_t msg{};
        if (!try_parse_http_msg(p.payload.data(), p.payload.size(), msg)) continue;
        json entry;
        entry["direction"] = direction_name(p.direction);
        entry["pid"] = p.pid;
        entry["src"] = format_ip(p.direction == 0 ? p.remote_addr : p.local_addr, p.address_family)
            + ":" + std::to_string(p.direction == 0 ? p.remote_port : p.local_port);
        entry["dst"] = format_ip(p.direction == 0 ? p.local_addr : p.remote_addr, p.address_family)
            + ":" + std::to_string(p.direction == 0 ? p.local_port : p.remote_port);
        if (msg.is_request) {
            entry["type"] = "request";
            entry["method"] = msg.method;
            entry["uri"] = msg.uri;
            entry["version"] = msg.http_version;
        } else {
            entry["type"] = "response";
            entry["status_code"] = msg.status_code;
            entry["reason"] = msg.reason_phrase;
            entry["version"] = msg.http_version;
        }
        json hdrs = json::object();
        for (const auto& [name, value] : msg.headers)
            hdrs[name] = value;
        entry["headers"] = hdrs;
        if (!msg.body.empty()) {
            entry["body_preview"] = msg.body;
            entry["body_truncated"] = msg.body_truncated;
        }
        arr.push_back(entry);
    }

    if (arr.empty())
        return tool_result_t::ok(OBFSTR("No HTTP messages found in captured packets. Ensure capture is active and HTTP traffic is flowing."), arr);
    return tool_result_t::ok(std::to_string(arr.size()) + OBFSTR(" HTTP messages parsed"), arr);
}

tool_result_t network_parse_tls(const json& params)
{
    if (!device->is_connected())
        return tool_result_t::error(OBFSTR("Driver not connected."));

    std::uint32_t max_pkts = 32;
    if (params.contains("count") && params["count"].is_number())
        max_pkts = params["count"].get<std::uint32_t>();
    if (max_pkts > 32) max_pkts = 32;

    auto packets = device->get_captured_packets(max_pkts);
    json arr = json::array();
    for (const auto& p : packets) {
        if (p.payload.size() < 5) continue;
        parsed_tls_info_t tls{};
        if (!try_parse_tls_record(p.payload.data(), p.payload.size(), tls)) continue;
        json entry;
        entry["direction"] = direction_name(p.direction);
        entry["pid"] = p.pid;
        entry["src"] = format_ip(p.direction == 0 ? p.remote_addr : p.local_addr, p.address_family)
            + ":" + std::to_string(p.direction == 0 ? p.remote_port : p.local_port);
        entry["dst"] = format_ip(p.direction == 0 ? p.local_addr : p.remote_addr, p.address_family)
            + ":" + std::to_string(p.direction == 0 ? p.local_port : p.remote_port);
        entry["content_type"] = tls_content_type_str(tls.content_type);
        entry["record_version"] = tls_version_str(tls.record_version);
        if (tls.handshake_type != 0) {
            entry["handshake_type"] = tls_handshake_type_str(tls.handshake_type);
            entry["client_version"] = tls_version_str(tls.client_version);
        }
        if (!tls.sni.empty()) entry["sni"] = tls.sni;
        if (!tls.alpn_protocols.empty()) {
            json alpn = json::array();
            for (const auto& pr : tls.alpn_protocols) alpn.push_back(pr);
            entry["alpn"] = alpn;
            entry["http2"] = tls.is_http2;
        }
        if (!tls.cipher_suites.empty()) {
            json suites = json::array();
            for (auto cs : tls.cipher_suites) suites.push_back(tls_cipher_name(cs));
            entry["cipher_suites"] = suites;
            entry["cipher_count"] = tls.cipher_suites.size();
        }
        if (tls.selected_cipher != 0) entry["selected_cipher"] = tls_cipher_name(tls.selected_cipher);
        arr.push_back(entry);
    }

    if (arr.empty())
        return tool_result_t::ok(OBFSTR("No TLS records found in captured packets. Ensure capture is active and HTTPS traffic is flowing."), arr);
    return tool_result_t::ok(std::to_string(arr.size()) + OBFSTR(" TLS records parsed"), arr);
}

tool_result_t network_enumerate_wfp_callouts(const json& params)
{
    if (!device->is_connected())
        return tool_result_t::error(OBFSTR("Driver not connected."));

    std::string filter_module;
    if (params.contains("module") && params["module"].is_string())
        filter_module = params["module"].get<std::string>();

    auto callouts = device->enumerate_wfp_callouts(filter_module);
    json arr = json::array();
    for (const auto& c : callouts) {
        json entry;
        entry["callout_id"] = c.callout_id;
        entry["layer_id"] = c.layer_id;
        entry["owning_module"] = c.owning_module;
        entry["callout_key"] = c.callout_key_str;
        entry["applicable_layer"] = c.applicable_layer_str;
        char addr_buf[32]; qsnprintf(addr_buf, sizeof(addr_buf), "0x%llX", (unsigned long long)c.classify_fn);
        entry["classify_fn"] = addr_buf;
        qsnprintf(addr_buf, sizeof(addr_buf), "0x%llX", (unsigned long long)c.owning_module_base);
        entry["module_base"] = addr_buf;
        entry["flags"] = c.flags;
        arr.push_back(entry);
    }
    return tool_result_t::ok(std::to_string(callouts.size()) + OBFSTR(" WFP callouts found"), arr);
}

tool_result_t network_get_socket_handles(const json& params)
{
    if (!device->is_connected())
        return tool_result_t::error(OBFSTR("Driver not connected."));

    std::uint32_t target_pid = 0;
    if (params.contains("pid") && params["pid"].is_number())
        target_pid = params["pid"].get<std::uint32_t>();

    auto socks = device->get_socket_handles(target_pid);
    json arr = json::array();
    for (const auto& s : socks) {
        json entry;
        char buf[24]; qsnprintf(buf, sizeof(buf), "0x%llX", (unsigned long long)s.handle_value);
        entry["handle"] = buf;
        entry["pid"] = s.pid;
        entry["protocol"] = protocol_name(s.protocol);
        entry["state"] = (s.protocol == 6) ? tcp_state_name(s.state) : "N/A";
        entry["local"] = format_ip(s.local_addr, s.address_family) + ":" + std::to_string(s.local_port);
        entry["remote"] = format_ip(s.remote_addr, s.address_family) + ":" + std::to_string(s.remote_port);
        arr.push_back(entry);
    }
    return tool_result_t::ok(std::to_string(socks.size()) + OBFSTR(" socket handles found"), arr);
}

tool_result_t network_dump_tcpip(const json& params)
{
    if (!device->is_connected())
        return tool_result_t::error(OBFSTR("Driver not connected."));

    std::uint32_t target_pid = 0, filter_protocol = 0;
    if (params.contains("pid") && params["pid"].is_number()) target_pid = params["pid"].get<std::uint32_t>();
    if (params.contains("protocol") && params["protocol"].is_string()) {
        std::string p = params["protocol"].get<std::string>();
        if (p == "tcp" || p == "TCP") filter_protocol = 6;
        else if (p == "udp" || p == "UDP") filter_protocol = 17;
    }

    auto conns = device->dump_tcpip_connections(target_pid, filter_protocol);
    json arr = json::array();
    for (const auto& c : conns) {
        json entry;
        entry["pid"] = c.pid;
        entry["protocol"] = protocol_name(c.protocol);
        entry["state"] = (c.protocol == 6) ? tcp_state_name(c.state) : "N/A";
        entry["local"] = format_ip(c.local_addr, c.address_family) + ":" + std::to_string(c.local_port);
        entry["remote"] = format_ip(c.remote_addr, c.address_family) + ":" + std::to_string(c.remote_port);
        entry["bytes_in"] = c.bytes_in;
        entry["bytes_out"] = c.bytes_out;
        char buf[24]; qsnprintf(buf, sizeof(buf), "0x%llX", (unsigned long long)c.tcb_address);
        entry["tcb_address"] = buf;
        qsnprintf(buf, sizeof(buf), "0x%llX", (unsigned long long)c.owning_module_base);
        entry["module_base"] = buf;
        entry["create_time"] = c.create_time;
        arr.push_back(entry);
    }
    return tool_result_t::ok(std::to_string(conns.size()) + OBFSTR(" TCPIP connections dumped"), arr);
}

tool_result_t network_enumerate_interfaces(const json&)
{
    if (!device->is_connected())
        return tool_result_t::error(OBFSTR("Driver not connected."));

    auto ifaces = device->enumerate_interfaces();
    json arr = json::array();
    for (const auto& ifc : ifaces) {
        json entry;
        entry["index"] = ifc.if_index;
        entry["name"] = ifc.name;
        entry["description"] = ifc.description;
        entry["type"] = ifc.if_type;
        entry["mtu"] = ifc.mtu;
        entry["speed_mbps"] = ifc.speed / 1000000;
        entry["oper_status"] = (ifc.oper_status == 1) ? "Up" : (ifc.oper_status == 2) ? "Down" : std::to_string(ifc.oper_status);
        entry["mac"] = format_mac(ifc.mac_addr);
        entry["ipv4"] = format_ipv4_bytes(ifc.ipv4_addr);
        entry["ipv4_mask"] = format_ipv4_bytes(ifc.ipv4_mask);
        entry["in_bytes"] = ifc.in_octets;
        entry["out_bytes"] = ifc.out_octets;
        arr.push_back(entry);
    }
    return tool_result_t::ok(std::to_string(ifaces.size()) + OBFSTR(" network interfaces"), arr);
}

tool_result_t network_inject_packet(const json& params)
{
    if (!device->is_connected())
        return tool_result_t::error(OBFSTR("Driver not connected."));

    std::uint32_t direction = 1, protocol = 6, af = 2;
    std::uint32_t src_port = 0, dst_port = 0;
    std::uint8_t src_addr[16] = {}, dst_addr[16] = {};
    std::uint32_t tcp_flags = 0, tcp_seq = 0, tcp_ack = 0;

    if (params.contains("direction") && params["direction"].is_string()) {
        std::string d = params["direction"].get<std::string>();
        if (d == "inbound" || d == "in") direction = 0;
    }
    if (params.contains("protocol") && params["protocol"].is_string()) {
        std::string p = params["protocol"].get<std::string>();
        if (p == "udp" || p == "UDP") protocol = 17;
    }
    if (params.contains("src_port") && params["src_port"].is_number()) src_port = params["src_port"].get<std::uint32_t>();
    if (params.contains("dst_port") && params["dst_port"].is_number()) dst_port = params["dst_port"].get<std::uint32_t>();
    if (params.contains("src_ip") && params["src_ip"].is_string()) parse_ipv4(params["src_ip"].get<std::string>(), src_addr);
    if (params.contains("dst_ip") && params["dst_ip"].is_string()) parse_ipv4(params["dst_ip"].get<std::string>(), dst_addr);
    if (params.contains("tcp_flags") && params["tcp_flags"].is_number()) tcp_flags = params["tcp_flags"].get<std::uint32_t>();
    if (params.contains("tcp_seq") && params["tcp_seq"].is_number()) tcp_seq = params["tcp_seq"].get<std::uint32_t>();
    if (params.contains("tcp_ack") && params["tcp_ack"].is_number()) tcp_ack = params["tcp_ack"].get<std::uint32_t>();

    std::vector<std::uint8_t> payload;
    if (params.contains("payload_hex") && params["payload_hex"].is_string())
        payload = hex_string_to_bytes(params["payload_hex"].get<std::string>());
    else if (params.contains("payload_text") && params["payload_text"].is_string()) {
        std::string text = params["payload_text"].get<std::string>();
        payload.assign(text.begin(), text.end());
    }
    if (payload.empty())
        return tool_result_t::error(OBFSTR("Payload required. Provide 'payload_hex' or 'payload_text'."));

    bool ok = device->inject_packet(direction, protocol, af, src_port, dst_port,
        src_addr, dst_addr, payload.data(), static_cast<std::uint32_t>(payload.size()),
        tcp_flags, tcp_seq, tcp_ack);

    if (!ok) return tool_result_t::error(OBFSTR("Packet injection failed."));
    json r;
    r["direction"] = (direction == 0) ? "inbound" : "outbound";
    r["protocol"] = protocol_name(protocol);
    r["payload_size"] = payload.size();
    return tool_result_t::ok(OBFSTR("Packet injected successfully"), r);
}

tool_result_t network_modify_packet_rule(const json& params)
{
    if (!device->is_connected())
        return tool_result_t::error(OBFSTR("Driver not connected."));
    if (!params.contains("operation") || !params["operation"].is_string())
        return tool_result_t::error(OBFSTR("Missing required parameter: operation ('add', 'remove', or 'clear')"));

    std::string op = params["operation"].get<std::string>();
    if (op == "add") {
        std::uint32_t direction = 2, protocol = 0, port = 0, pid = 0;
        if (params.contains("direction") && params["direction"].is_string()) {
            std::string d = params["direction"].get<std::string>();
            if (d == "inbound" || d == "in") direction = 0;
            else if (d == "outbound" || d == "out") direction = 1;
        }
        if (params.contains("protocol") && params["protocol"].is_string()) {
            std::string p = params["protocol"].get<std::string>();
            if (p == "tcp" || p == "TCP") protocol = 6;
            else if (p == "udp" || p == "UDP") protocol = 17;
        }
        if (params.contains("port") && params["port"].is_number()) port = params["port"].get<std::uint32_t>();
        if (params.contains("pid") && params["pid"].is_number()) pid = params["pid"].get<std::uint32_t>();

        std::vector<std::uint8_t> pattern, replacement;
        if (params.contains("pattern_hex") && params["pattern_hex"].is_string())
            pattern = hex_string_to_bytes(params["pattern_hex"].get<std::string>());
        if (params.contains("replacement_hex") && params["replacement_hex"].is_string())
            replacement = hex_string_to_bytes(params["replacement_hex"].get<std::string>());
        if (params.contains("pattern_text") && params["pattern_text"].is_string()) {
            std::string t = params["pattern_text"].get<std::string>();
            pattern.assign(t.begin(), t.end());
        }
        if (params.contains("replacement_text") && params["replacement_text"].is_string()) {
            std::string t = params["replacement_text"].get<std::string>();
            replacement.assign(t.begin(), t.end());
        }
        if (pattern.empty())
            return tool_result_t::error(OBFSTR("Pattern required for 'add'. Provide 'pattern_hex' or 'pattern_text'."));

        std::uint32_t rule_id = 0;
        bool ok = device->packet_mod_rule_op(0, 0, direction, protocol, port, pid,
            pattern.data(), static_cast<std::uint32_t>(pattern.size()),
            replacement.empty() ? nullptr : replacement.data(), static_cast<std::uint32_t>(replacement.size()),
            &rule_id);
        if (!ok) return tool_result_t::error(OBFSTR("Failed to add modification rule. Max 32 rules."));
        json r; r["rule_id"] = rule_id;
        return tool_result_t::ok(OBFSTR("Packet modification rule added (ID: ") + std::to_string(rule_id) + ")", r);
    } else if (op == "remove") {
        if (!params.contains("rule_id") || !params["rule_id"].is_number())
            return tool_result_t::error(OBFSTR("Missing required parameter: rule_id"));
        std::uint32_t rule_id = params["rule_id"].get<std::uint32_t>();
        bool ok = device->packet_mod_rule_op(1, rule_id);
        if (!ok) return tool_result_t::error(OBFSTR("Failed to remove modification rule."));
        return tool_result_t::ok(OBFSTR("Modification rule ") + std::to_string(rule_id) + OBFSTR(" removed"));
    } else if (op == "clear") {
        bool ok = device->packet_mod_rule_op(3);
        if (!ok) return tool_result_t::error(OBFSTR("Failed to clear modification rules."));
        return tool_result_t::ok(OBFSTR("All packet modification rules cleared"));
    }
    return tool_result_t::error(OBFSTR("Invalid operation. Use 'add', 'remove', or 'clear'."));
}

tool_result_t network_list_mod_rules(const json&)
{
    if (!device->is_connected())
        return tool_result_t::error(OBFSTR("Driver not connected."));

    auto rules = device->list_packet_mod_rules();
    json arr = json::array();
    for (const auto& r : rules) {
        json entry;
        entry["rule_id"] = r.rule_id;
        entry["direction"] = (r.direction == 0) ? "inbound" : (r.direction == 1) ? "outbound" : "both";
        entry["protocol"] = protocol_name(r.protocol);
        entry["port"] = r.port;
        entry["pid"] = r.pid;
        entry["match_count"] = r.match_count;
        entry["active"] = r.active != 0;
        arr.push_back(entry);
    }
    return tool_result_t::ok(std::to_string(rules.size()) + OBFSTR(" packet modification rules"), arr);
}

tool_result_t network_redirect_traffic(const json& params)
{
    if (!device->is_connected())
        return tool_result_t::error(OBFSTR("Driver not connected."));
    if (!params.contains("operation") || !params["operation"].is_string())
        return tool_result_t::error(OBFSTR("Missing required parameter: operation ('add', 'remove', or 'clear')"));

    std::string op = params["operation"].get<std::string>();
    if (op == "add") {
        std::uint32_t protocol = 6, match_port = 0, redirect_port = 0, af = 2;
        std::uint8_t match_addr[16] = {}, redirect_addr[16] = {};
        if (params.contains("protocol") && params["protocol"].is_string()) {
            std::string p = params["protocol"].get<std::string>();
            if (p == "udp" || p == "UDP") protocol = 17;
        }
        if (params.contains("match_port") && params["match_port"].is_number()) match_port = params["match_port"].get<std::uint32_t>();
        if (params.contains("redirect_port") && params["redirect_port"].is_number()) redirect_port = params["redirect_port"].get<std::uint32_t>();
        if (params.contains("match_ip") && params["match_ip"].is_string()) parse_ipv4(params["match_ip"].get<std::string>(), match_addr);
        if (params.contains("redirect_ip") && params["redirect_ip"].is_string()) parse_ipv4(params["redirect_ip"].get<std::string>(), redirect_addr);

        std::uint32_t rule_id = 0;
        bool ok = device->traffic_redirect_op(0, 0, protocol, match_port, match_addr, redirect_port, redirect_addr, af, &rule_id);
        if (!ok) return tool_result_t::error(OBFSTR("Failed to add redirect rule. Max 16 rules."));
        json r; r["rule_id"] = rule_id;
        return tool_result_t::ok(OBFSTR("Traffic redirect rule added (ID: ") + std::to_string(rule_id) + ")", r);
    } else if (op == "remove") {
        if (!params.contains("rule_id") || !params["rule_id"].is_number())
            return tool_result_t::error(OBFSTR("Missing required parameter: rule_id"));
        std::uint32_t rule_id = params["rule_id"].get<std::uint32_t>();
        bool ok = device->traffic_redirect_op(1, rule_id);
        if (!ok) return tool_result_t::error(OBFSTR("Failed to remove redirect rule."));
        return tool_result_t::ok(OBFSTR("Redirect rule ") + std::to_string(rule_id) + OBFSTR(" removed"));
    } else if (op == "clear") {
        bool ok = device->traffic_redirect_op(3);
        if (!ok) return tool_result_t::error(OBFSTR("Failed to clear redirect rules."));
        return tool_result_t::ok(OBFSTR("All traffic redirect rules cleared"));
    }
    return tool_result_t::error(OBFSTR("Invalid operation. Use 'add', 'remove', or 'clear'."));
}

tool_result_t network_list_redirect_rules(const json&)
{
    if (!device->is_connected())
        return tool_result_t::error(OBFSTR("Driver not connected."));

    auto rules = device->list_redirect_rules();
    json arr = json::array();
    for (const auto& r : rules) {
        json entry;
        entry["rule_id"] = r.rule_id;
        entry["protocol"] = protocol_name(r.protocol);
        entry["match_port"] = r.match_port;
        entry["redirect_port"] = r.redirect_port;
        entry["match_count"] = r.match_count;
        entry["active"] = r.active != 0;
        arr.push_back(entry);
    }
    return tool_result_t::ok(std::to_string(rules.size()) + OBFSTR(" traffic redirect rules"), arr);
}

tool_result_t network_intercept(const json& params)
{
    if (!device->is_connected())
        return tool_result_t::error(OBFSTR("Driver not connected."));
    if (!params.contains("operation") || !params["operation"].is_string())
        return tool_result_t::error(OBFSTR("Missing required parameter: operation ('enable' or 'disable')"));

    std::string op = params["operation"].get<std::string>();
    if (op == "enable") {
        std::uint32_t filter_pid = 0, filter_port = 0, filter_protocol = 0;
        if (params.contains("pid") && params["pid"].is_number()) filter_pid = params["pid"].get<std::uint32_t>();
        if (params.contains("port") && params["port"].is_number()) filter_port = params["port"].get<std::uint32_t>();
        if (params.contains("protocol") && params["protocol"].is_string()) {
            std::string p = params["protocol"].get<std::string>();
            if (p == "tcp" || p == "TCP") filter_protocol = 6;
            else if (p == "udp" || p == "UDP") filter_protocol = 17;
        }
        std::uint32_t held_count = 0; bool active = false;
        bool ok = device->intercept_op(0, filter_pid, filter_port, filter_protocol, 0, nullptr, 0, &held_count, &active);
        if (!ok) return tool_result_t::error(OBFSTR("Failed to enable packet interception."));
        json r; r["active"] = active; r["held_count"] = held_count;
        return tool_result_t::ok(OBFSTR("Packet interception enabled. Matching packets will be held for inspection."), r);
    } else if (op == "disable") {
        bool ok = device->intercept_op(1, 0, 0, 0, 0, nullptr, 0, nullptr, nullptr);
        if (!ok) return tool_result_t::error(OBFSTR("Failed to disable packet interception."));
        return tool_result_t::ok(OBFSTR("Packet interception disabled. All held packets released."));
    }
    return tool_result_t::error(OBFSTR("Invalid operation. Use 'enable' or 'disable'."));
}

tool_result_t network_get_held_packets(const json&)
{
    if (!device->is_connected())
        return tool_result_t::error(OBFSTR("Driver not connected."));

    auto held = device->get_held_packets();
    json arr = json::array();
    for (const auto& h : held) {
        json entry;
        entry["hold_id"] = h.hold_id;
        entry["timestamp"] = h.timestamp;
        entry["direction"] = direction_name(h.direction);
        entry["protocol"] = protocol_name(h.protocol);
        entry["src"] = format_ip(h.src_addr, h.af) + ":" + std::to_string(h.src_port);
        entry["dst"] = format_ip(h.dst_addr, h.af) + ":" + std::to_string(h.dst_port);
        entry["pid"] = h.pid;
        entry["payload_size"] = h.payload_size;
        if (!h.payload.empty()) {
            entry["hex_dump"] = hex_dump(h.payload.data(), h.payload.size(), 512);
            entry["ascii"] = extract_ascii(h.payload.data(), h.payload.size());
        }
        arr.push_back(entry);
    }
    return tool_result_t::ok(std::to_string(held.size()) + OBFSTR(" packets held for inspection"), arr);
}

tool_result_t network_release_packet(const json& params)
{
    if (!device->is_connected())
        return tool_result_t::error(OBFSTR("Driver not connected."));
    if (!params.contains("hold_id") || !params["hold_id"].is_number())
        return tool_result_t::error(OBFSTR("Missing required parameter: hold_id"));

    std::uint64_t hold_id = params["hold_id"].get<std::uint64_t>();
    std::vector<std::uint8_t> modify_payload;
    std::uint32_t operation = 3;

    if (params.contains("action") && params["action"].is_string()) {
        std::string act = params["action"].get<std::string>();
        if (act == "drop") operation = 4;
        else if (act == "modify") operation = 5;
    }

    if (operation == 5) {
        if (params.contains("payload_hex") && params["payload_hex"].is_string())
            modify_payload = hex_string_to_bytes(params["payload_hex"].get<std::string>());
        else if (params.contains("payload_text") && params["payload_text"].is_string()) {
            std::string t = params["payload_text"].get<std::string>();
            modify_payload.assign(t.begin(), t.end());
        }
    }

    bool ok = device->intercept_op(operation, 0, 0, 0, hold_id,
        modify_payload.empty() ? nullptr : modify_payload.data(),
        static_cast<std::uint32_t>(modify_payload.size()), nullptr, nullptr);
    if (!ok) return tool_result_t::error(OBFSTR("Failed to release/process held packet."));

    std::string action_str = (operation == 4) ? "dropped" : (operation == 5) ? "modified and released" : "released";
    return tool_result_t::ok(OBFSTR("Packet ") + action_str);
}

tool_result_t network_kill_connection(const json& params)
{
    if (!device->is_connected())
        return tool_result_t::error(OBFSTR("Driver not connected."));

    std::uint32_t protocol = 6, af = 2, src_port = 0, dst_port = 0, pid = 0;
    std::uint8_t src_addr[16] = {}, dst_addr[16] = {};

    if (params.contains("protocol") && params["protocol"].is_string()) {
        std::string p = params["protocol"].get<std::string>();
        if (p == "udp" || p == "UDP") protocol = 17;
    }
    if (params.contains("src_port") && params["src_port"].is_number()) src_port = params["src_port"].get<std::uint32_t>();
    if (params.contains("dst_port") && params["dst_port"].is_number()) dst_port = params["dst_port"].get<std::uint32_t>();
    if (params.contains("src_ip") && params["src_ip"].is_string()) parse_ipv4(params["src_ip"].get<std::string>(), src_addr);
    if (params.contains("dst_ip") && params["dst_ip"].is_string()) parse_ipv4(params["dst_ip"].get<std::string>(), dst_addr);
    if (params.contains("pid") && params["pid"].is_number()) pid = params["pid"].get<std::uint32_t>();

    bool ok = device->kill_connection(protocol, af, src_port, dst_port, src_addr, dst_addr, pid);
    if (!ok) return tool_result_t::error(OBFSTR("Failed to kill connection. Tries socket close + RST injection."));
    return tool_result_t::ok(OBFSTR("Connection killed successfully"));
}

tool_result_t network_spoof_dns(const json& params)
{
    if (!device->is_connected())
        return tool_result_t::error(OBFSTR("Driver not connected."));
    if (!params.contains("operation") || !params["operation"].is_string())
        return tool_result_t::error(OBFSTR("Missing required parameter: operation ('add', 'remove', or 'clear')"));

    std::string op = params["operation"].get<std::string>();
    if (op == "add") {
        if (!params.contains("domain") || !params["domain"].is_string())
            return tool_result_t::error(OBFSTR("Missing required parameter: domain"));
        if (!params.contains("spoof_ip") || !params["spoof_ip"].is_string())
            return tool_result_t::error(OBFSTR("Missing required parameter: spoof_ip"));

        std::string domain = params["domain"].get<std::string>();
        std::uint8_t spoof_addr[16] = {};
        parse_ipv4(params["spoof_ip"].get<std::string>(), spoof_addr);
        std::uint32_t ttl = 300;
        if (params.contains("ttl") && params["ttl"].is_number()) ttl = params["ttl"].get<std::uint32_t>();

        std::uint32_t rule_id = 0;
        bool ok = device->dns_spoof_op(0, 0, domain.c_str(), spoof_addr, 2, ttl, &rule_id);
        if (!ok) return tool_result_t::error(OBFSTR("Failed to add DNS spoof rule. Max 32 rules."));
        json r; r["rule_id"] = rule_id; r["domain"] = domain;
        return tool_result_t::ok(OBFSTR("DNS spoof rule added: ") + domain + OBFSTR(" -> ") + params["spoof_ip"].get<std::string>(), r);
    } else if (op == "remove") {
        if (!params.contains("rule_id") || !params["rule_id"].is_number())
            return tool_result_t::error(OBFSTR("Missing required parameter: rule_id"));
        std::uint32_t rule_id = params["rule_id"].get<std::uint32_t>();
        bool ok = device->dns_spoof_op(1, rule_id, nullptr, nullptr, 2, 0, nullptr);
        if (!ok) return tool_result_t::error(OBFSTR("Failed to remove DNS spoof rule."));
        return tool_result_t::ok(OBFSTR("DNS spoof rule ") + std::to_string(rule_id) + OBFSTR(" removed"));
    } else if (op == "clear") {
        bool ok = device->dns_spoof_op(3, 0, nullptr, nullptr, 2, 0, nullptr);
        if (!ok) return tool_result_t::error(OBFSTR("Failed to clear DNS spoof rules."));
        return tool_result_t::ok(OBFSTR("All DNS spoof rules cleared"));
    }
    return tool_result_t::error(OBFSTR("Invalid operation. Use 'add', 'remove', or 'clear'."));
}

tool_result_t network_list_dns_spoof_rules(const json&)
{
    if (!device->is_connected())
        return tool_result_t::error(OBFSTR("Driver not connected."));

    auto rules = device->list_dns_spoof_rules();
    json arr = json::array();
    for (const auto& r : rules) {
        json entry;
        entry["rule_id"] = r.rule_id;
        entry["domain"] = r.domain;
        entry["ttl"] = r.ttl;
        entry["match_count"] = r.match_count;
        entry["active"] = r.active != 0;
        arr.push_back(entry);
    }
    return tool_result_t::ok(std::to_string(rules.size()) + OBFSTR(" DNS spoof rules"), arr);
}

tool_result_t network_bandwidth_monitor(const json& params)
{
    if (!device->is_connected())
        return tool_result_t::error(OBFSTR("Driver not connected."));
    if (!params.contains("operation") || !params["operation"].is_string())
        return tool_result_t::error(OBFSTR("Missing required parameter: operation ('start', 'stop', 'get', or 'reset')"));

    std::string op = params["operation"].get<std::string>();
    std::uint32_t filter_pid = 0;
    if (params.contains("pid") && params["pid"].is_number()) filter_pid = params["pid"].get<std::uint32_t>();

    if (op == "start") {
        bool ok = device->bw_monitor_op(0, filter_pid, nullptr);
        if (!ok) return tool_result_t::error(OBFSTR("Failed to start bandwidth monitoring."));
        return tool_result_t::ok(OBFSTR("Bandwidth monitoring started"));
    } else if (op == "stop") {
        bool ok = device->bw_monitor_op(1, 0, nullptr);
        if (!ok) return tool_result_t::error(OBFSTR("Failed to stop bandwidth monitoring."));
        return tool_result_t::ok(OBFSTR("Bandwidth monitoring stopped"));
    } else if (op == "get") {
        voyager::device_t::bw_stats stats{};
        bool ok = device->bw_monitor_op(2, filter_pid, &stats);
        if (!ok) return tool_result_t::error(OBFSTR("Failed to get bandwidth stats."));
        json r;
        r["active"] = stats.active;
        r["total_bytes_sent"] = stats.total_bytes_sent;
        r["total_bytes_recv"] = stats.total_bytes_recv;
        r["total_packets_sent"] = stats.total_packets_sent;
        r["total_packets_recv"] = stats.total_packets_recv;
        r["bps_in"] = stats.bps_in;
        r["bps_out"] = stats.bps_out;
        return tool_result_t::ok(OBFSTR("Bandwidth statistics"), r);
    } else if (op == "reset") {
        bool ok = device->bw_monitor_op(3, 0, nullptr);
        if (!ok) return tool_result_t::error(OBFSTR("Failed to reset bandwidth counters."));
        return tool_result_t::ok(OBFSTR("Bandwidth counters reset"));
    }
    return tool_result_t::error(OBFSTR("Invalid operation. Use 'start', 'stop', 'get', or 'reset'."));
}

tool_result_t network_bandwidth_per_process(const json& params)
{
    if (!device->is_connected())
        return tool_result_t::error(OBFSTR("Driver not connected."));

    std::uint32_t filter_pid = 0;
    if (params.contains("pid") && params["pid"].is_number()) filter_pid = params["pid"].get<std::uint32_t>();

    auto procs = device->get_bw_per_process(filter_pid);
    json arr = json::array();
    for (const auto& p : procs) {
        json entry;
        entry["pid"] = p.pid;
        entry["bytes_sent"] = p.bytes_sent;
        entry["bytes_recv"] = p.bytes_recv;
        entry["packets_sent"] = p.packets_sent;
        entry["packets_recv"] = p.packets_recv;
        entry["last_activity"] = p.last_activity;
        arr.push_back(entry);
    }
    return tool_result_t::ok(std::to_string(procs.size()) + OBFSTR(" processes with bandwidth data"), arr);
}

tool_result_t network_os_fingerprint(const json& params)
{
    if (!device->is_connected())
        return tool_result_t::error(OBFSTR("Driver not connected."));
    if (!params.contains("operation") || !params["operation"].is_string())
        return tool_result_t::error(OBFSTR("Missing required parameter: operation ('enable', 'disable', or 'get')"));

    std::string op = params["operation"].get<std::string>();
    if (op == "enable") {
        bool ok = device->fingerprint_op(0);
        if (!ok) return tool_result_t::error(OBFSTR("Failed to enable OS fingerprinting."));
        return tool_result_t::ok(OBFSTR("Passive OS fingerprinting enabled. Analyzing TCP SYN packets."));
    } else if (op == "disable") {
        bool ok = device->fingerprint_op(1);
        if (!ok) return tool_result_t::error(OBFSTR("Failed to disable OS fingerprinting."));
        return tool_result_t::ok(OBFSTR("OS fingerprinting disabled"));
    } else if (op == "get") {
        auto fps = device->get_fingerprints();
        json arr = json::array();
        for (const auto& f : fps) {
            json entry;
            entry["remote_ip"] = format_ip(f.remote_addr, f.af);
            entry["os_guess"] = f.os_guess;
            entry["ttl"] = f.ttl;
            entry["window_size"] = f.window_size;
            entry["mss"] = f.mss;
            entry["window_scale"] = f.window_scale;
            entry["df_flag"] = f.df_flag != 0;
            entry["sack_permitted"] = f.sack_permitted != 0;
            arr.push_back(entry);
        }
        return tool_result_t::ok(std::to_string(fps.size()) + OBFSTR(" OS fingerprints collected"), arr);
    }
    return tool_result_t::error(OBFSTR("Invalid operation. Use 'enable', 'disable', or 'get'."));
}

tool_result_t network_export_pcap(const json& params)
{
    if (!device->is_connected())
        return tool_result_t::error(OBFSTR("Driver not connected."));

    std::uint32_t filter_pid = 0, filter_protocol = 0, max_packets = 256;
    if (params.contains("pid") && params["pid"].is_number()) filter_pid = params["pid"].get<std::uint32_t>();
    if (params.contains("protocol") && params["protocol"].is_string()) {
        std::string p = params["protocol"].get<std::string>();
        if (p == "tcp" || p == "TCP") filter_protocol = 6;
        else if (p == "udp" || p == "UDP") filter_protocol = 17;
    }
    if (params.contains("max_packets") && params["max_packets"].is_number())
        max_packets = params["max_packets"].get<std::uint32_t>();
    if (max_packets > 256) max_packets = 256;

    voyager::device_t::pcap_export_result pcap{};
    bool ok = device->export_pcap(filter_pid, filter_protocol, max_packets, &pcap);
    if (!ok) return tool_result_t::error(OBFSTR("Failed to export PCAP data from driver."));

    std::string filename;
    if (params.contains("filename") && params["filename"].is_string())
        filename = params["filename"].get<std::string>();
    else
        filename = "aida_capture.pcap";

    std::string path = get_downloads_folder() + filename;
    ensure_parent_dir_exists(path);

    HANDLE hf = CreateFileA(path.c_str(), GENERIC_WRITE, 0, nullptr, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (hf == INVALID_HANDLE_VALUE)
        return tool_result_t::error(OBFSTR("Failed to create PCAP file: ") + path);

    DWORD written = 0;
    bool write_ok = true;
    if (!WriteFile(hf, &pcap.header, sizeof(pcap.header), &written, nullptr)) write_ok = false;

    struct { std::uint32_t ts_sec, ts_usec, incl_len, orig_len; } rec_hdr;
    for (const auto& pkt : pcap.packets) {
        if (!write_ok) break;
        rec_hdr.ts_sec = pkt.ts_sec;
        rec_hdr.ts_usec = pkt.ts_usec;
        rec_hdr.incl_len = static_cast<std::uint32_t>(pkt.data.size());
        rec_hdr.orig_len = static_cast<std::uint32_t>(pkt.data.size());
        if (!WriteFile(hf, &rec_hdr, sizeof(rec_hdr), &written, nullptr)) { write_ok = false; break; }
        if (!pkt.data.empty()) {
            if (!WriteFile(hf, pkt.data.data(), static_cast<DWORD>(pkt.data.size()), &written, nullptr))
                { write_ok = false; break; }
        }
    }
    CloseHandle(hf);

    if (!write_ok) return tool_result_t::error(OBFSTR("Failed to write PCAP file."));

    json r;
    r["file_path"] = path;
    r["packet_count"] = pcap.packets.size();
    return tool_result_t::ok(std::to_string(pcap.packets.size()) + OBFSTR(" packets exported to ") + path, r);
}

void register_tools()
{
    auto& registry = ToolRegistry::instance();

    registry.register_tool({
        OBFSTR("network_enumerate_connections"), OBFSTR("network"),
        OBFSTR("Enumerate all active TCP/UDP connections on the system via kernel driver. "
               "Returns PID, protocol, state, local/remote addresses and ports. "
               "Like netstat but kernel-level - invisible to usermode hooks. "
               "Optionally filter by PID or protocol."),
        {{OBFSTR("pid"), OBFSTR("number"), OBFSTR("Filter connections by process ID"), false},
         {OBFSTR("protocol"), OBFSTR("string"), OBFSTR("Filter by protocol: 'tcp' or 'udp'"), false}},
        network_enumerate_connections, true});

    registry.register_tool({
        OBFSTR("network_start_capture"), OBFSTR("network"),
        OBFSTR("Start kernel-level packet capture using WFP (Windows Filtering Platform) callouts. "
               "Captures all network traffic with process attribution. "
               "Like Wireshark but running in kernel space with PID-level visibility. "
               "Optionally filter by PID, port, protocol, or IP address."),
        {{OBFSTR("pid"), OBFSTR("number"), OBFSTR("Only capture traffic from this process"), false},
         {OBFSTR("port"), OBFSTR("number"), OBFSTR("Only capture traffic on this port"), false},
         {OBFSTR("protocol"), OBFSTR("string"), OBFSTR("Only capture 'tcp' or 'udp'"), false},
         {OBFSTR("ip"), OBFSTR("string"), OBFSTR("Only capture traffic to/from this IPv4 address"), false},
         {OBFSTR("max_payload"), OBFSTR("number"), OBFSTR("Max payload bytes per packet (default 1500)"), false}},
        network_start_capture, false});

    registry.register_tool({
        OBFSTR("network_stop_capture"), OBFSTR("network"),
        OBFSTR("Stop the active kernel packet capture session."),
        {},
        network_stop_capture, false});

    registry.register_tool({
        OBFSTR("network_get_packets"), OBFSTR("network"),
        OBFSTR("Retrieve captured network packets from the kernel ring buffer. "
               "Returns up to 32 packets per call with full headers, payload hex dump, "
               "ASCII render, PID, protocol, direction, and endpoint info. "
               "Packets are consumed (removed from buffer) after retrieval."),
        {{OBFSTR("count"), OBFSTR("number"), OBFSTR("Max packets to retrieve (1-32, default 32)"), false}},
        network_get_packets, true});

    registry.register_tool({
        OBFSTR("network_analyze_packet"), OBFSTR("network"),
        OBFSTR("Retrieve and deeply analyze a single captured packet. "
               "Auto-detects application protocol (HTTP, TLS, DNS), extracts headers, "
               "provides full hex dump and ASCII render. Like Fiddler's packet inspector."),
        {},
        network_analyze_packet, true});

    registry.register_tool({
        OBFSTR("network_dns_log"), OBFSTR("network"),
        OBFSTR("Retrieve captured DNS queries and responses from the kernel. "
               "Shows domain names, query types (A/AAAA/CNAME/MX/etc.), resolved IPs, "
               "TTLs, and owning PIDs. Requires capture to be active. "
               "Like a DNS sniffer with process attribution."),
        {{OBFSTR("pid"), OBFSTR("number"), OBFSTR("Filter DNS entries by process ID"), false}},
        network_dns_log, true});

    registry.register_tool({
        OBFSTR("network_add_filter"), OBFSTR("network"),
        OBFSTR("Add a kernel-level network filter rule. Can allow, block, or log traffic "
               "matching specified criteria. Rules are enforced in the WFP classify callback. "
               "Like a kernel firewall - operates below all usermode network stacks."),
        {{OBFSTR("action"), OBFSTR("string"), OBFSTR("Rule action: 'allow', 'block', or 'log' (default 'log')"), false},
         {OBFSTR("direction"), OBFSTR("string"), OBFSTR("'inbound', 'outbound', or 'both' (default 'both')"), false},
         {OBFSTR("protocol"), OBFSTR("string"), OBFSTR("'tcp', 'udp', or omit for all"), false},
         {OBFSTR("pid"), OBFSTR("number"), OBFSTR("Match only this process ID"), false},
         {OBFSTR("port"), OBFSTR("number"), OBFSTR("Match only this port"), false},
         {OBFSTR("ip"), OBFSTR("string"), OBFSTR("Match only this IPv4 address"), false}},
        network_add_filter, false});

    registry.register_tool({
        OBFSTR("network_remove_filter"), OBFSTR("network"),
        OBFSTR("Remove a previously added network filter rule by its ID."),
        {{OBFSTR("rule_id"), OBFSTR("number"), OBFSTR("The rule ID returned when the filter was added"), true}},
        network_remove_filter, false});

    registry.register_tool({
        OBFSTR("network_clear_filters"), OBFSTR("network"),
        OBFSTR("Remove all active network filter rules at once."),
        {},
        network_clear_filters, false});

    registry.register_tool({
        OBFSTR("network_stats"), OBFSTR("network"),
        OBFSTR("Get comprehensive kernel-level network statistics: total bytes/packets sent/received, "
               "capture status, total captured/dropped, DNS queries logged, and active filter rules."),
        {},
        network_stats, true});

    registry.register_tool({
        OBFSTR("network_capture_status"), OBFSTR("network"),
        OBFSTR("Check if packet capture is currently active and get capture counters."),
        {},
        network_capture_status, true});

    registry.register_tool({
        OBFSTR("network_block_ip"), OBFSTR("network"),
        OBFSTR("Quick shortcut to block all traffic to/from a specific IP address. "
               "Creates a kernel-level WFP block rule. Returns rule_id for later removal."),
        {{OBFSTR("ip"), OBFSTR("string"), OBFSTR("IPv4 address to block (e.g. '192.168.1.1')"), true},
         {OBFSTR("direction"), OBFSTR("string"), OBFSTR("'inbound', 'outbound', or 'both' (default 'both')"), false}},
        network_block_ip, false});

    registry.register_tool({
        OBFSTR("network_block_port"), OBFSTR("network"),
        OBFSTR("Quick shortcut to block all traffic on a specific port. "
               "Creates a kernel-level WFP block rule. Returns rule_id for later removal."),
        {{OBFSTR("port"), OBFSTR("number"), OBFSTR("Port number to block"), true},
         {OBFSTR("protocol"), OBFSTR("string"), OBFSTR("Optional: 'tcp' or 'udp' (default: both)"), false}},
        network_block_port, false});

    registry.register_tool({
        OBFSTR("network_block_process"), OBFSTR("network"),
        OBFSTR("Quick shortcut to block all network traffic for a specific process by PID. "
               "Creates a kernel-level WFP block rule. Returns rule_id for later removal."),
        {{OBFSTR("pid"), OBFSTR("number"), OBFSTR("Process ID to block"), true}},
        network_block_process, false});

    registry.register_tool({
        OBFSTR("network_deep_inspect"), OBFSTR("network"),
        OBFSTR("Deep packet inspection of captured traffic. Returns protocol-level analysis: HTTP method/host/path, "
               "TLS version/SNI/content type, DNS detection. Requires active capture (network_start_capture). "
               "Filter by pid, port, or protocol. Superior to basic packet view — identifies application-layer protocols."),
        {{OBFSTR("pid"), OBFSTR("number"), OBFSTR("Filter by process ID"), false},
         {OBFSTR("port"), OBFSTR("number"), OBFSTR("Filter by port number"), false},
         {OBFSTR("protocol"), OBFSTR("string"), OBFSTR("Filter: 'tcp' or 'udp'"), false}},
        network_deep_inspect, true});

    registry.register_tool({
        OBFSTR("network_follow_tcp_stream"), OBFSTR("network"),
        OBFSTR("TCP stream reassembly — equivalent to Wireshark 'Follow TCP Stream'. Reassembles TCP segments into "
               "complete application-layer data. Operations: 'start' begins tracking a flow, 'get' returns reassembled "
               "bytes (hex + ASCII), 'stop' ends tracking. Identify flows via src_port/dst_port. Max 8 concurrent streams."),
        {{OBFSTR("operation"), OBFSTR("string"), OBFSTR("'start', 'stop', or 'get'"), true},
         {OBFSTR("src_port"), OBFSTR("number"), OBFSTR("Source (client) port of the TCP flow"), false},
         {OBFSTR("dst_port"), OBFSTR("number"), OBFSTR("Destination (server) port of the TCP flow"), false},
         {OBFSTR("pid"), OBFSTR("number"), OBFSTR("Process ID filter"), false}},
        network_follow_tcp_stream, false});

    registry.register_tool({
        OBFSTR("network_parse_http"), OBFSTR("network"),
        OBFSTR("Parse HTTP request/response messages from captured packets. Extracts method, URI, status code, "
               "all headers (Host, Content-Type, User-Agent, Cookie, Authorization, etc.), and body preview. "
               "Equivalent to Wireshark HTTP dissector or HTTP Debugger request/response view. Requires active capture."),
        {{OBFSTR("count"), OBFSTR("number"), OBFSTR("Max packets to scan (default 32, max 32)"), false}},
        network_parse_http, true});

    registry.register_tool({
        OBFSTR("network_parse_tls"), OBFSTR("network"),
        OBFSTR("Parse TLS/SSL handshake details from captured packets. Extracts: record type, TLS version, "
               "handshake type (ClientHello/ServerHello), SNI (Server Name Indication), ALPN protocols (detects HTTP/2), "
               "cipher suites offered/selected. Equivalent to Wireshark TLS dissector. Requires active capture."),
        {{OBFSTR("count"), OBFSTR("number"), OBFSTR("Max packets to scan (default 32, max 32)"), false}},
        network_parse_tls, true});

    registry.register_tool({
        OBFSTR("network_enumerate_wfp_callouts"), OBFSTR("network"),
        OBFSTR("Enumerate all registered WFP (Windows Filtering Platform) callouts in the system. Shows callout ID, "
               "layer, owning module, classify/notify function addresses. Use to audit what other drivers/security "
               "products are hooking network traffic. Filter by module name."),
        {{OBFSTR("module"), OBFSTR("string"), OBFSTR("Filter by owning module name (case-insensitive substring)"), false}},
        network_enumerate_wfp_callouts, true});

    registry.register_tool({
        OBFSTR("network_get_socket_handles"), OBFSTR("network"),
        OBFSTR("Enumerate kernel socket handle objects for a process. Returns handle value, AFD endpoint address, "
               "protocol, state, local/remote address:port. Lower-level than netstat — works from kernel object tables."),
        {{OBFSTR("pid"), OBFSTR("number"), OBFSTR("Target process ID (0 = all processes)"), false}},
        network_get_socket_handles, true});

    registry.register_tool({
        OBFSTR("network_dump_tcpip"), OBFSTR("network"),
        OBFSTR("Deep kernel TCPIP stack connection dump. Returns TCB address, owning module, bytes in/out, "
               "create time, and full connection tuple. More detailed than netstat — reads kernel TCPIP internal structures."),
        {{OBFSTR("pid"), OBFSTR("number"), OBFSTR("Filter by process ID (0 = all)"), false},
         {OBFSTR("protocol"), OBFSTR("string"), OBFSTR("Filter: 'tcp' or 'udp'"), false}},
        network_dump_tcpip, true});

    registry.register_tool({
        OBFSTR("network_enumerate_interfaces"), OBFSTR("network"),
        OBFSTR("List all network interfaces with details: name, description, type, MTU, speed, operational status, "
               "MAC address, IPv4/IPv6 addresses, in/out byte counters. Equivalent to Wireshark's capture interface list."),
        {},
        network_enumerate_interfaces, true});

    registry.register_tool({
        OBFSTR("network_inject_packet"), OBFSTR("network"),
        OBFSTR("Inject a crafted packet into the network stack at the WFP transport layer. Specify direction, "
               "protocol, source/destination IP:port, payload (hex or text), and TCP flags/sequence numbers. "
               "Use for testing, replaying requests, or active response injection. Equivalent to Scapy packet crafting."),
        {{OBFSTR("direction"), OBFSTR("string"), OBFSTR("'inbound' or 'outbound' (default: outbound)"), false},
         {OBFSTR("protocol"), OBFSTR("string"), OBFSTR("'tcp' or 'udp' (default: tcp)"), false},
         {OBFSTR("src_ip"), OBFSTR("string"), OBFSTR("Source IP address"), false},
         {OBFSTR("dst_ip"), OBFSTR("string"), OBFSTR("Destination IP address"), false},
         {OBFSTR("src_port"), OBFSTR("number"), OBFSTR("Source port"), false},
         {OBFSTR("dst_port"), OBFSTR("number"), OBFSTR("Destination port"), false},
         {OBFSTR("payload_hex"), OBFSTR("string"), OBFSTR("Payload as hex string (e.g. '48656C6C6F')"), false},
         {OBFSTR("payload_text"), OBFSTR("string"), OBFSTR("Payload as ASCII text"), false},
         {OBFSTR("tcp_flags"), OBFSTR("number"), OBFSTR("TCP flags bitmask (SYN=2, ACK=16, RST=4, FIN=1, PSH=8)"), false},
         {OBFSTR("tcp_seq"), OBFSTR("number"), OBFSTR("TCP sequence number"), false},
         {OBFSTR("tcp_ack"), OBFSTR("number"), OBFSTR("TCP acknowledgment number"), false}},
        network_inject_packet, false});

    registry.register_tool({
        OBFSTR("network_modify_packet_rule"), OBFSTR("network"),
        OBFSTR("Manage real-time packet content modification rules. 'add' creates a rule that search-and-replaces "
               "byte patterns in matching packet payloads (like HTTP Debugger rewrite rules). 'remove' deletes a rule by ID. "
               "'clear' removes all rules. Patterns/replacements as hex or text. Filter by direction/protocol/port/pid. Max 32 rules."),
        {{OBFSTR("operation"), OBFSTR("string"), OBFSTR("'add', 'remove', or 'clear'"), true},
         {OBFSTR("direction"), OBFSTR("string"), OBFSTR("For add: 'inbound', 'outbound', or 'both' (default: both)"), false},
         {OBFSTR("protocol"), OBFSTR("string"), OBFSTR("For add: 'tcp' or 'udp'"), false},
         {OBFSTR("port"), OBFSTR("number"), OBFSTR("For add: port filter (0 = any)"), false},
         {OBFSTR("pid"), OBFSTR("number"), OBFSTR("For add: process ID filter (0 = any)"), false},
         {OBFSTR("pattern_hex"), OBFSTR("string"), OBFSTR("For add: byte pattern to find (hex)"), false},
         {OBFSTR("pattern_text"), OBFSTR("string"), OBFSTR("For add: text pattern to find"), false},
         {OBFSTR("replacement_hex"), OBFSTR("string"), OBFSTR("For add: replacement bytes (hex)"), false},
         {OBFSTR("replacement_text"), OBFSTR("string"), OBFSTR("For add: replacement text"), false},
         {OBFSTR("rule_id"), OBFSTR("number"), OBFSTR("For remove: rule ID to remove"), false}},
        network_modify_packet_rule, false});

    registry.register_tool({
        OBFSTR("network_list_mod_rules"), OBFSTR("network"),
        OBFSTR("List all active packet modification rules. Shows rule ID, direction, protocol, port/pid filters, "
               "match count, and active status."),
        {},
        network_list_mod_rules, true});

    registry.register_tool({
        OBFSTR("network_redirect_traffic"), OBFSTR("network"),
        OBFSTR("Manage kernel-level traffic redirect rules. 'add' redirects traffic matching IP:port to a different "
               "IP:port (transparent proxy). 'remove' deletes by rule ID. 'clear' removes all. Filter by protocol. "
               "Equivalent to iptables REDIRECT/DNAT but at WFP level. Max 16 rules."),
        {{OBFSTR("operation"), OBFSTR("string"), OBFSTR("'add', 'remove', or 'clear'"), true},
         {OBFSTR("protocol"), OBFSTR("string"), OBFSTR("For add: 'tcp' or 'udp' (default: tcp)"), false},
         {OBFSTR("match_port"), OBFSTR("number"), OBFSTR("For add: original destination port to match"), false},
         {OBFSTR("match_ip"), OBFSTR("string"), OBFSTR("For add: original destination IP to match"), false},
         {OBFSTR("redirect_port"), OBFSTR("number"), OBFSTR("For add: new destination port"), false},
         {OBFSTR("redirect_ip"), OBFSTR("string"), OBFSTR("For add: new destination IP"), false},
         {OBFSTR("rule_id"), OBFSTR("number"), OBFSTR("For remove: rule ID"), false}},
        network_redirect_traffic, false});

    registry.register_tool({
        OBFSTR("network_list_redirect_rules"), OBFSTR("network"),
        OBFSTR("List all active traffic redirect rules with match counts and status."),
        {},
        network_list_redirect_rules, true});

    registry.register_tool({
        OBFSTR("network_intercept"), OBFSTR("network"),
        OBFSTR("Enable/disable real-time packet interception and hold. When enabled, matching packets are "
               "held in a queue (like Fiddler breakpoints). Use network_get_held_packets to inspect them, then "
               "network_release_packet to release, drop, or modify-and-release each packet. Filter by pid/port/protocol."),
        {{OBFSTR("operation"), OBFSTR("string"), OBFSTR("'enable' or 'disable'"), true},
         {OBFSTR("pid"), OBFSTR("number"), OBFSTR("For enable: process ID filter (0 = all)"), false},
         {OBFSTR("port"), OBFSTR("number"), OBFSTR("For enable: port filter (0 = all)"), false},
         {OBFSTR("protocol"), OBFSTR("string"), OBFSTR("For enable: 'tcp' or 'udp'"), false}},
        network_intercept, false});

    registry.register_tool({
        OBFSTR("network_get_held_packets"), OBFSTR("network"),
        OBFSTR("Retrieve packets currently held by the interceptor. Returns hold_id, timestamp, direction, "
               "protocol, src/dst endpoints, pid, and payload (hex dump + ASCII). Use hold_id with "
               "network_release_packet to decide each packet's fate."),
        {},
        network_get_held_packets, true});

    registry.register_tool({
        OBFSTR("network_release_packet"), OBFSTR("network"),
        OBFSTR("Release a held packet from the interceptor. Actions: 'release' (forward as-is, default), "
               "'drop' (discard silently), 'modify' (replace payload then forward). For 'modify', provide "
               "new payload as hex or text. Like Fiddler's 'Run to Completion' / 'Drop' / 'Edit & Reissue'."),
        {{OBFSTR("hold_id"), OBFSTR("number"), OBFSTR("Held packet ID from network_get_held_packets"), true},
         {OBFSTR("action"), OBFSTR("string"), OBFSTR("'release', 'drop', or 'modify' (default: release)"), false},
         {OBFSTR("payload_hex"), OBFSTR("string"), OBFSTR("For modify: new payload as hex string"), false},
         {OBFSTR("payload_text"), OBFSTR("string"), OBFSTR("For modify: new payload as ASCII text"), false}},
        network_release_packet, false});

    registry.register_tool({
        OBFSTR("network_kill_connection"), OBFSTR("network"),
        OBFSTR("Forcefully terminate a network connection. Uses kernel-level socket close + TCP RST injection. "
               "Specify the connection by src/dst IP:port and/or PID. Like right-click 'Kill Connection' in TCPView."),
        {{OBFSTR("protocol"), OBFSTR("string"), OBFSTR("'tcp' or 'udp' (default: tcp)"), false},
         {OBFSTR("src_ip"), OBFSTR("string"), OBFSTR("Source (local) IP address"), false},
         {OBFSTR("dst_ip"), OBFSTR("string"), OBFSTR("Destination (remote) IP address"), false},
         {OBFSTR("src_port"), OBFSTR("number"), OBFSTR("Source (local) port"), false},
         {OBFSTR("dst_port"), OBFSTR("number"), OBFSTR("Destination (remote) port"), false},
         {OBFSTR("pid"), OBFSTR("number"), OBFSTR("Process ID owning the connection"), false}},
        network_kill_connection, false});

    registry.register_tool({
        OBFSTR("network_spoof_dns"), OBFSTR("network"),
        OBFSTR("Manage kernel-level DNS spoofing rules. 'add' creates a rule to intercept DNS queries for a domain "
               "and return a spoofed A/AAAA record. 'remove' deletes by rule ID. 'clear' removes all. Like a kernel "
               "hosts file — intercepts at the WFP layer before packets leave. Max 32 rules."),
        {{OBFSTR("operation"), OBFSTR("string"), OBFSTR("'add', 'remove', or 'clear'"), true},
         {OBFSTR("domain"), OBFSTR("string"), OBFSTR("For add: domain name to intercept (e.g. 'example.com')"), false},
         {OBFSTR("spoof_ip"), OBFSTR("string"), OBFSTR("For add: IP address to return in DNS response"), false},
         {OBFSTR("ttl"), OBFSTR("number"), OBFSTR("For add: TTL in seconds for spoofed response (default: 300)"), false},
         {OBFSTR("rule_id"), OBFSTR("number"), OBFSTR("For remove: rule ID"), false}},
        network_spoof_dns, false});

    registry.register_tool({
        OBFSTR("network_list_dns_spoof_rules"), OBFSTR("network"),
        OBFSTR("List all active DNS spoof rules with domain, spoof address, TTL, match counts, and status."),
        {},
        network_list_dns_spoof_rules, true});

    registry.register_tool({
        OBFSTR("network_bandwidth_monitor"), OBFSTR("network"),
        OBFSTR("Real-time bandwidth monitoring at the kernel level. 'start' begins tracking (optionally for a specific PID). "
               "'get' returns total bytes/packets sent/received plus current throughput (bps). 'stop' ends monitoring. "
               "'reset' zeroes all counters. Like Wireshark I/O graphs + NetLimiter bandwidth view."),
        {{OBFSTR("operation"), OBFSTR("string"), OBFSTR("'start', 'stop', 'get', or 'reset'"), true},
         {OBFSTR("pid"), OBFSTR("number"), OBFSTR("For start/get: filter by process ID (0 = all)"), false}},
        network_bandwidth_monitor, false});

    registry.register_tool({
        OBFSTR("network_bandwidth_per_process"), OBFSTR("network"),
        OBFSTR("Get per-process bandwidth usage breakdown. Shows bytes/packets sent/received and last activity "
               "timestamp for each process. Requires bandwidth monitoring to be active (network_bandwidth_monitor start)."),
        {{OBFSTR("pid"), OBFSTR("number"), OBFSTR("Filter by process ID (0 = all processes)"), false}},
        network_bandwidth_per_process, true});

    registry.register_tool({
        OBFSTR("network_os_fingerprint"), OBFSTR("network"),
        OBFSTR("Passive OS fingerprinting via TCP SYN packet analysis (p0f-style). 'enable' starts collecting "
               "fingerprints from incoming connections. 'get' returns results: remote IP, OS guess, TTL, window size, "
               "MSS, window scale, DF flag, SACK. 'disable' stops. Like p0f or Wireshark OS detection."),
        {{OBFSTR("operation"), OBFSTR("string"), OBFSTR("'enable', 'disable', or 'get'"), true}},
        network_os_fingerprint, false});

    registry.register_tool({
        OBFSTR("network_export_pcap"), OBFSTR("network"),
        OBFSTR("Export captured packets to a PCAP file that can be opened in Wireshark. Writes standard libpcap "
               "format with global header + packet records. Filter by pid/protocol. File saved to Downloads folder "
               "by default. Max 256 packets per export."),
        {{OBFSTR("pid"), OBFSTR("number"), OBFSTR("Filter by process ID"), false},
         {OBFSTR("protocol"), OBFSTR("string"), OBFSTR("Filter: 'tcp' or 'udp'"), false},
         {OBFSTR("max_packets"), OBFSTR("number"), OBFSTR("Max packets to export (default 256, max 256)"), false},
         {OBFSTR("filename"), OBFSTR("string"), OBFSTR("Output filename (default: 'aida_capture.pcap')"), false}},
        network_export_pcap, false});
}

}


namespace net_security_tools {

#ifdef __NT__

static std::string ns_bytes_to_hex(const std::uint8_t* data, std::size_t len) {
    std::string result;
    for (std::size_t i = 0; i < len; i++) {
        char hex[4]; qsnprintf(hex, sizeof(hex), "%02X", data[i]);
        result += hex;
    }
    return result;
}

static std::vector<std::uint8_t> ns_hex_to_bytes(const std::string& hex) {
    std::vector<std::uint8_t> out;
    std::string clean;
    for (char c : hex) {
        if (c != ' ' && c != ':' && c != '-') clean += c;
    }
    out.reserve(clean.size() / 2);
    for (std::size_t i = 0; i + 1 < clean.size(); i += 2) {
        auto nib = [](char c) -> int {
            if (c >= '0' && c <= '9') return c - '0';
            if (c >= 'a' && c <= 'f') return 10 + c - 'a';
            if (c >= 'A' && c <= 'F') return 10 + c - 'A';
            return -1;
        };
        int h = nib(clean[i]), l = nib(clean[i+1]);
        if (h >= 0 && l >= 0) out.push_back(static_cast<std::uint8_t>((h << 4) | l));
    }
    return out;
}

static std::string ns_get_downloads_folder() {
    char buf[MAX_PATH] = {};
    DWORD len = GetEnvironmentVariableA("USERPROFILE", buf, MAX_PATH);
    if (len > 0 && len < MAX_PATH)
        return std::string(buf, len) + "\\Downloads";
    return ".";
}

tool_result_t tls_extract_keys(const json& params) {
    if (!device || !device->is_connected())
        return tool_result_t::error(OBFSTR("Driver not connected"));

    net_security::tls_key_scan_config_t config;
    config.pid = params.value("pid", 0u);
    config.scan_schannel = params.value("scan_schannel", true);
    config.scan_openssl = params.value("scan_openssl", true);
    config.scan_nss = params.value("scan_nss", true);
    config.scan_boringssl = params.value("scan_boringssl", true);
    config.max_results = params.value("max_results", 64u);

    auto keys = net_security::TlsKeyExtractor::instance().extract_keys(config);
    json result;
    result["keys_found"] = keys.size();
    json arr = json::array();
    for (const auto& k : keys) {
        json kj;
        kj["label"] = k.label;
        kj["client_random"] = ns_bytes_to_hex(k.client_random.data(), k.client_random.size());
        kj["secret"] = ns_bytes_to_hex(k.secret.data(), k.secret.size());
        kj["tls_version"] = k.tls_version;
        kj["pid"] = k.pid;
        kj["library"] = k.library;
        kj["timestamp"] = k.timestamp;
        arr.push_back(kj);
    }
    result["keys"] = arr;
    return tool_result_t::ok(OBFSTR("Extracted ") + std::to_string(keys.size()) + OBFSTR(" TLS session keys"), result);
}

tool_result_t tls_start_keylog(const json& params) {
    net_security::keylog_config_t config;
    config.pid = params.value("pid", 0u);
    config.output_file = params.value("output_file", "");
    config.poll_interval_ms = params.value("poll_interval_ms", 2000u);
    config.append = params.value("append", true);

    if (config.output_file.empty()) {
        config.output_file = ns_get_downloads_folder() + "\\sslkeylog.txt";
    }

    if (net_security::TlsKeyExtractor::instance().start_keylog(config)) {
        json r;
        r["status"] = "started";
        r["output_file"] = config.output_file;
        r["poll_interval_ms"] = config.poll_interval_ms;
        return tool_result_t::ok(OBFSTR("TLS keylogging started -> ") + config.output_file, r);
    }
    return tool_result_t::error(OBFSTR("Keylogging already active or failed to start"));
}

tool_result_t tls_stop_keylog(const json&) {
    if (net_security::TlsKeyExtractor::instance().stop_keylog()) {
        json r;
        r["status"] = "stopped";
        return tool_result_t::ok(OBFSTR("TLS keylogging stopped"), r);
    }
    return tool_result_t::error(OBFSTR("No active keylogging session"));
}

tool_result_t tls_get_extracted_keys(const json&) {
    auto& ext = net_security::TlsKeyExtractor::instance();
    auto& seen = ext.get_seen_keys();

    json result;
    result["total_keys"] = seen.size();
    json arr = json::array();
    for (const auto& [key, val] : seen) {
        json kj;
        kj["label"] = val.label;
        kj["client_random"] = ns_bytes_to_hex(val.client_random.data(), val.client_random.size());
        kj["secret"] = ns_bytes_to_hex(val.secret.data(), val.secret.size());
        kj["library"] = val.library;
        kj["pid"] = val.pid;
        arr.push_back(kj);
    }
    result["keys"] = arr;
    return tool_result_t::ok(OBFSTR("Retrieved ") + std::to_string(seen.size()) + OBFSTR(" cached TLS keys"), result);
}

tool_result_t cert_inject(const json& params) {
    net_security::cert_injection_config_t config;
    config.cert_pem = params.value("cert_pem", "");
    config.store_name = params.value("store_name", "ROOT");
    config.system_wide = params.value("system_wide", false);

    if (params.contains("cert_der_hex") && params["cert_der_hex"].is_string()) {
        auto hex = params["cert_der_hex"].get<std::string>();
        config.cert_der = ns_hex_to_bytes(hex);
    }

    auto result = net_security::CertificateInjector::instance().inject_certificate(config);
    json r;
    r["success"] = result.success;
    r["thumbprint"] = result.thumbprint;
    r["subject_cn"] = result.subject_cn;
    r["store_name"] = result.store_name;
    r["method"] = result.method;
    if (result.success)
        return tool_result_t::ok(OBFSTR("Certificate injected: ") + result.subject_cn, r);
    return tool_result_t::error(OBFSTR("Certificate injection failed"));
}

tool_result_t cert_remove(const json& params) {
    std::string thumbprint = params.value("thumbprint", "");
    std::string store_name = params.value("store_name", "ROOT");
    if (thumbprint.empty())
        return tool_result_t::error(OBFSTR("thumbprint is required"));

    if (net_security::CertificateInjector::instance().remove_certificate(thumbprint, store_name)) {
        json r;
        r["removed"] = true;
        r["thumbprint"] = thumbprint;
        return tool_result_t::ok(OBFSTR("Certificate removed"), r);
    }
    return tool_result_t::error(OBFSTR("Failed to remove certificate"));
}

tool_result_t cert_generate_ca(const json& params) {
    std::string cn = params.value("cn", "AiDA Proxy CA");
    std::uint32_t days = params.value("validity_days", 3650u);

    std::vector<std::uint8_t> cert_der, key_der;
    if (net_security::CertificateInjector::instance().generate_ca_certificate(cn, days, cert_der, key_der)) {
        json r;
        r["success"] = true;
        r["cert_der_hex"] = ns_bytes_to_hex(cert_der.data(), cert_der.size());
        r["key_der_hex"] = ns_bytes_to_hex(key_der.data(), key_der.size());
        r["cert_size"] = cert_der.size();
        r["subject_cn"] = cn;
        r["validity_days"] = days;
        return tool_result_t::ok(OBFSTR("Generated CA certificate: ") + cn, r);
    }
    return tool_result_t::error(OBFSTR("Failed to generate CA certificate"));
}

tool_result_t cert_list(const json& params) {
    std::string store_name = params.value("store_name", "ROOT");
    auto certs = net_security::CertificateInjector::instance().list_certificates(store_name);

    json result;
    result["store_name"] = store_name;
    result["count"] = certs.size();
    json arr = json::array();
    for (const auto& c : certs) {
        json cj;
        cj["thumbprint"] = c.thumbprint;
        cj["subject"] = c.subject;
        cj["issuer"] = c.issuer;
        cj["not_before"] = c.not_before;
        cj["not_after"] = c.not_after;
        cj["is_ca"] = c.is_ca;
        arr.push_back(cj);
    }
    result["certificates"] = arr;
    return tool_result_t::ok(OBFSTR("Listed ") + std::to_string(certs.size()) + OBFSTR(" certificates"), result);
}

tool_result_t pin_bypass(const json& params) {
    if (!device || !device->is_connected())
        return tool_result_t::error(OBFSTR("Driver not connected"));

    net_security::pin_bypass_config_t config;
    config.pid = params.value("pid", 0u);
    std::string method = params.value("method", "all");
    if (method == "wintrust") config.method = net_security::pin_bypass_method::patch_wintrust;
    else if (method == "crypt32") config.method = net_security::pin_bypass_method::patch_crypt32;
    else if (method == "schannel") config.method = net_security::pin_bypass_method::patch_schannel;
    else if (method == "chrome") config.method = net_security::pin_bypass_method::patch_chrome_pins;
    else if (method == "dotnet") config.method = net_security::pin_bypass_method::patch_dotnet_callback;
    else config.method = net_security::pin_bypass_method::all;

    auto result = net_security::CertPinBypasser::instance().bypass_pins(config);
    json r;
    r["success"] = result.success;
    r["patches_applied"] = result.patches_applied;
    r["patches_failed"] = result.patches_failed;
    if (result.success)
        return tool_result_t::ok(OBFSTR("Pin bypass applied: ") + std::to_string(result.patches_applied.size()) + OBFSTR(" patches"), r);
    return tool_result_t::error(OBFSTR("Pin bypass failed for all methods"));
}

tool_result_t pin_bypass_revert(const json& params) {
    if (!device || !device->is_connected())
        return tool_result_t::error(OBFSTR("Driver not connected"));

    std::uint32_t pid = params.value("pid", 0u);
    if (pid == 0) pid = device->get_process_id();

    if (net_security::CertPinBypasser::instance().revert_bypass(pid)) {
        json r;
        r["reverted"] = true;
        r["pid"] = pid;
        return tool_result_t::ok(OBFSTR("Pin bypass reverted for PID ") + std::to_string(pid), r);
    }
    return tool_result_t::error(OBFSTR("No active bypass to revert for this PID"));
}

tool_result_t pin_bypass_status(const json& params) {
    std::uint32_t pid = params.value("pid", 0u);
    if (pid == 0 && device && device->is_connected()) pid = device->get_process_id();
    bool active = net_security::CertPinBypasser::instance().is_bypass_active(pid);
    json r;
    r["pid"] = pid;
    r["bypass_active"] = active;
    return tool_result_t::ok(active ? OBFSTR("Pin bypass is ACTIVE") : OBFSTR("No active pin bypass"), r);
}

tool_result_t quic_detect_connections(const json& params) {
    if (!device || !device->is_connected())
        return tool_result_t::error(OBFSTR("Driver not connected"));

    std::uint32_t pid = params.value("pid", 0u);
    auto conns = net_security::QuicAnalyzer::instance().detect_quic_connections(pid);

    json result;
    result["count"] = conns.size();
    json arr = json::array();
    for (const auto& c : conns) {
        json cj;
        cj["pid"] = c.pid;
        cj["src_port"] = c.src_port;
        cj["dst_port"] = c.dst_port;
        cj["dcid"] = ns_bytes_to_hex(c.dcid.data(), c.dcid.size());
        cj["scid"] = ns_bytes_to_hex(c.scid.data(), c.scid.size());
        cj["packets_sent"] = c.packets_sent;
        cj["packets_recv"] = c.packets_recv;
        cj["bytes_sent"] = c.bytes_sent;
        cj["bytes_recv"] = c.bytes_recv;
        cj["alpn"] = c.alpn;
        arr.push_back(cj);
    }
    result["connections"] = arr;
    return tool_result_t::ok(OBFSTR("Detected ") + std::to_string(conns.size()) + OBFSTR(" QUIC connections"), result);
}

tool_result_t quic_decrypt_initial(const json& params) {
    if (!params.contains("packet_hex"))
        return tool_result_t::error(OBFSTR("packet_hex is required"));

    auto pkt_bytes = ns_hex_to_bytes(params["packet_hex"].get<std::string>());
    if (pkt_bytes.empty())
        return tool_result_t::error(OBFSTR("Invalid packet hex data"));

    auto result = net_security::QuicAnalyzer::instance().decrypt_initial_packet(pkt_bytes.data(), pkt_bytes.size());
    json r;
    r["success"] = result.success;
    r["quic_version"] = result.quic_version;
    r["packet_type"] = result.packet_type;
    r["dcid"] = ns_bytes_to_hex(result.dcid.data(), result.dcid.size());
    r["scid"] = ns_bytes_to_hex(result.scid.data(), result.scid.size());
    if (result.success)
        return tool_result_t::ok(OBFSTR("QUIC Initial packet decoded"), r);
    return tool_result_t::error(OBFSTR("Failed to decode QUIC Initial packet"));
}

tool_result_t quic_extract_keys(const json& params) {
    if (!device || !device->is_connected())
        return tool_result_t::error(OBFSTR("Driver not connected"));

    std::uint32_t pid = params.value("pid", 0u);
    auto keys = net_security::QuicAnalyzer::instance().extract_quic_traffic_keys(pid);

    json result;
    result["keys_found"] = keys.size();
    json arr = json::array();
    for (const auto& k : keys) {
        json kj;
        kj["label"] = k.label;
        kj["client_random"] = ns_bytes_to_hex(k.client_random.data(), k.client_random.size());
        kj["secret"] = ns_bytes_to_hex(k.secret.data(), k.secret.size());
        kj["library"] = k.library;
        kj["pid"] = k.pid;
        arr.push_back(kj);
    }
    result["keys"] = arr;
    return tool_result_t::ok(OBFSTR("Extracted ") + std::to_string(keys.size()) + OBFSTR(" QUIC keys"), result);
}

tool_result_t dtls_detect_sessions(const json& params) {
    if (!device || !device->is_connected())
        return tool_result_t::error(OBFSTR("Driver not connected"));

    std::uint32_t pid = params.value("pid", 0u);
    auto sessions = net_security::DtlsAnalyzer::instance().detect_dtls_sessions(pid);

    json result;
    result["count"] = sessions.size();
    json arr = json::array();
    for (const auto& s : sessions) {
        json sj;
        sj["pid"] = s.pid;
        sj["src_port"] = s.src_port;
        sj["dst_port"] = s.dst_port;
        sj["dtls_version"] = s.dtls_version;
        sj["epoch"] = s.epoch;
        sj["state"] = s.state;
        sj["content_type"] = s.content_type;
        arr.push_back(sj);
    }
    result["sessions"] = arr;
    return tool_result_t::ok(OBFSTR("Detected ") + std::to_string(sessions.size()) + OBFSTR(" DTLS sessions"), result);
}

tool_result_t dtls_extract_keys(const json& params) {
    if (!device || !device->is_connected())
        return tool_result_t::error(OBFSTR("Driver not connected"));

    std::uint32_t pid = params.value("pid", 0u);
    auto keys = net_security::TlsKeyExtractor::instance().extract_dtls_keys(pid);

    json result;
    result["keys_found"] = keys.size();
    json arr = json::array();
    for (const auto& k : keys) {
        json kj;
        kj["dtls_version"] = k.dtls_version;
        kj["client_random"] = ns_bytes_to_hex(k.client_random.data(), k.client_random.size());
        kj["master_secret"] = ns_bytes_to_hex(k.master_secret.data(), k.master_secret.size());
        kj["library"] = k.library;
        kj["pid"] = k.pid;
        arr.push_back(kj);
    }
    result["keys"] = arr;
    return tool_result_t::ok(OBFSTR("Extracted ") + std::to_string(keys.size()) + OBFSTR(" DTLS keys"), result);
}

tool_result_t network_decrypt_capture(const json& params) {
    std::string pcap_path = params.value("pcap_path", "");
    std::string keylog_path = params.value("keylog_path", "");
    std::string display_filter = params.value("display_filter", "http2");

    if (pcap_path.empty())
        return tool_result_t::error(OBFSTR("pcap_path is required"));


    if (keylog_path.empty()) {
        char buf[MAX_PATH] = {};
        DWORD len = GetEnvironmentVariableA("SSLKEYLOGFILE", buf, MAX_PATH);
        if (len > 0 && len < MAX_PATH) keylog_path = std::string(buf, len);
    }
    if (keylog_path.empty())
        return tool_result_t::error(OBFSTR("keylog_path is required (or set SSLKEYLOGFILE environment variable)"));

    auto decrypt_result = net_security::TlsKeyExtractor::instance().decrypt_pcap_with_tshark(
        pcap_path, keylog_path, display_filter);

    json r;
    r["success"] = decrypt_result.success;
    r["pcap_file"] = decrypt_result.pcap_file_used;
    r["keylog_file"] = decrypt_result.keylog_file_used;
    r["total_packets"] = decrypt_result.total_packets;
    r["decrypted_packets"] = decrypt_result.decrypted_packets;

    if (!decrypt_result.error_message.empty())
        r["error"] = decrypt_result.error_message;

    json frames = json::array();
    for (const auto& f : decrypt_result.http2_frames) {
        json fj;
        if (!f.stream_id.empty()) fj["stream_id"] = f.stream_id;
        if (!f.method.empty()) fj["method"] = f.method;
        if (!f.url.empty()) fj["url"] = f.url;
        if (!f.authority.empty()) fj["authority"] = f.authority;
        if (!f.content_type.empty()) fj["content_type"] = f.content_type;
        if (f.status_code != 0) fj["status_code"] = f.status_code;
        if (!f.frame_type.empty()) fj["frame_type"] = f.frame_type;
        if (!f.headers.empty()) {
            json hdrs = json::object();
            for (const auto& [k, v] : f.headers) hdrs[k] = v;
            fj["headers"] = hdrs;
        }
        if (!f.body.empty()) fj["body"] = f.body;
        frames.push_back(fj);
    }
    r["http2_frames"] = frames;

    if (decrypt_result.success)
        return tool_result_t::ok(
            OBFSTR("Decrypted ") + std::to_string(decrypt_result.decrypted_packets) +
            OBFSTR(" packets, found ") + std::to_string(decrypt_result.http2_frames.size()) +
            OBFSTR(" HTTP/2 frames"), r);

    return tool_result_t::error(decrypt_result.error_message.empty() ?
        OBFSTR("Decryption failed - no matching packets found") : decrypt_result.error_message);
}

tool_result_t tls_ensure_keylogfile(const json& params) {
    std::string path = params.value("path", "");
    if (net_security::TlsKeyExtractor::instance().ensure_sslkeylogfile_env(path)) {
        char buf[MAX_PATH] = {};
        DWORD len = GetEnvironmentVariableA("SSLKEYLOGFILE", buf, MAX_PATH);
        json r;
        r["status"] = "configured";
        r["path"] = (len > 0) ? std::string(buf, len) : path;
        r["note"] = "SSLKEYLOGFILE set at user level. Newly started processes (browsers, VS Code, etc.) "
                    "will log TLS session keys to this file. Restart the target application for it to take effect.";
        return tool_result_t::ok(OBFSTR("SSLKEYLOGFILE configured"), r);
    }
    return tool_result_t::error(OBFSTR("Failed to set SSLKEYLOGFILE environment variable"));
}

tool_result_t autoresponder_add_rule(const json& params) {
    net_security::autoresponder_rule_t rule;
    rule.enabled = params.value("enabled", true);
    rule.priority = params.value("priority", 0);

    std::string mt = params.value("match_type", "prefix_url");
    if (mt == "exact_url") rule.match_type = net_security::autoresponder_match_type::exact_url;
    else if (mt == "prefix_url") rule.match_type = net_security::autoresponder_match_type::prefix_url;
    else if (mt == "regex_url") rule.match_type = net_security::autoresponder_match_type::regex_url;
    else if (mt == "method_and_url") rule.match_type = net_security::autoresponder_match_type::method_and_url;
    else if (mt == "header_contains") rule.match_type = net_security::autoresponder_match_type::header_contains;
    else if (mt == "body_contains") rule.match_type = net_security::autoresponder_match_type::body_contains;
    else if (mt == "sni_contains") rule.match_type = net_security::autoresponder_match_type::sni_contains;
    else rule.match_type = net_security::autoresponder_match_type::prefix_url;

    rule.match_pattern = params.value("match_pattern", "");
    rule.match_method = params.value("match_method", "");
    rule.status_code = params.value("status_code", 200u);
    rule.status_reason = params.value("status_reason", "");
    rule.response_body = params.value("response_body", "");
    rule.response_file_path = params.value("response_file_path", "");
    rule.latency_ms = params.value("latency_ms", 0u);
    rule.drop_request = params.value("drop_request", false);
    rule.passthrough = params.value("passthrough", false);

    if (params.contains("response_headers") && params["response_headers"].is_object()) {
        for (auto it = params["response_headers"].begin(); it != params["response_headers"].end(); ++it)
            rule.response_headers[it.key()] = it.value().get<std::string>();
    }

    std::uint32_t id = net_security::AutoResponder::instance().add_rule(rule);
    json r;
    r["rule_id"] = id;
    return tool_result_t::ok(OBFSTR("AutoResponder rule added with ID ") + std::to_string(id), r);
}

tool_result_t autoresponder_remove_rule(const json& params) {
    std::uint32_t rule_id = params.value("rule_id", 0u);
    if (net_security::AutoResponder::instance().remove_rule(rule_id)) {
        json r;
        r["removed"] = true;
        r["rule_id"] = rule_id;
        return tool_result_t::ok(OBFSTR("Rule removed"), r);
    }
    return tool_result_t::error(OBFSTR("Rule not found"));
}

tool_result_t autoresponder_list_rules(const json&) {
    auto rules = net_security::AutoResponder::instance().list_rules();
    json result;
    result["count"] = rules.size();
    json arr = json::array();
    for (const auto& rule : rules) {
        json rj;
        rj["rule_id"] = rule.rule_id;
        rj["enabled"] = rule.enabled;
        rj["priority"] = rule.priority;
        rj["match_pattern"] = rule.match_pattern;
        rj["match_method"] = rule.match_method;
        rj["status_code"] = rule.status_code;
        rj["match_count"] = rule.match_count;
        rj["drop_request"] = rule.drop_request;
        rj["passthrough"] = rule.passthrough;
        arr.push_back(rj);
    }
    result["rules"] = arr;
    return tool_result_t::ok(OBFSTR("Listed ") + std::to_string(rules.size()) + OBFSTR(" autoresponder rules"), result);
}

tool_result_t autoresponder_start(const json&) {
    if (net_security::AutoResponder::instance().start()) {
        json r;
        r["status"] = "started";
        return tool_result_t::ok(OBFSTR("AutoResponder started"), r);
    }
    return tool_result_t::error(OBFSTR("AutoResponder already running or failed"));
}

tool_result_t autoresponder_stop(const json&) {
    if (net_security::AutoResponder::instance().stop()) {
        json r;
        r["status"] = "stopped";
        return tool_result_t::ok(OBFSTR("AutoResponder stopped"), r);
    }
    return tool_result_t::error(OBFSTR("AutoResponder is not running"));
}

tool_result_t autoresponder_import_rules(const json& params) {
    std::string rules_json = params.value("rules_json", "");
    if (rules_json.empty())
        return tool_result_t::error(OBFSTR("rules_json is required"));

    if (net_security::AutoResponder::instance().import_rules(rules_json)) {
        auto count = net_security::AutoResponder::instance().list_rules().size();
        json r;
        r["imported"] = true;
        r["total_rules"] = count;
        return tool_result_t::ok(OBFSTR("Rules imported, total: ") + std::to_string(count), r);
    }
    return tool_result_t::error(OBFSTR("Failed to import rules - invalid JSON"));
}

tool_result_t autoresponder_export_rules(const json&) {
    std::string exported = net_security::AutoResponder::instance().export_rules();
    json r;
    r["rules_json"] = exported;
    return tool_result_t::ok(OBFSTR("AutoResponder rules exported"), r);
}

#else

tool_result_t tls_extract_keys(const json&) { return tool_result_t::error("Not supported on this platform"); }
tool_result_t tls_start_keylog(const json&) { return tool_result_t::error("Not supported on this platform"); }
tool_result_t tls_stop_keylog(const json&) { return tool_result_t::error("Not supported on this platform"); }
tool_result_t tls_get_extracted_keys(const json&) { return tool_result_t::error("Not supported on this platform"); }
tool_result_t cert_inject(const json&) { return tool_result_t::error("Not supported on this platform"); }
tool_result_t cert_remove(const json&) { return tool_result_t::error("Not supported on this platform"); }
tool_result_t cert_generate_ca(const json&) { return tool_result_t::error("Not supported on this platform"); }
tool_result_t cert_list(const json&) { return tool_result_t::error("Not supported on this platform"); }
tool_result_t pin_bypass(const json&) { return tool_result_t::error("Not supported on this platform"); }
tool_result_t pin_bypass_revert(const json&) { return tool_result_t::error("Not supported on this platform"); }
tool_result_t pin_bypass_status(const json&) { return tool_result_t::error("Not supported on this platform"); }
tool_result_t quic_detect_connections(const json&) { return tool_result_t::error("Not supported on this platform"); }
tool_result_t quic_decrypt_initial(const json&) { return tool_result_t::error("Not supported on this platform"); }
tool_result_t quic_extract_keys(const json&) { return tool_result_t::error("Not supported on this platform"); }
tool_result_t dtls_detect_sessions(const json&) { return tool_result_t::error("Not supported on this platform"); }
tool_result_t dtls_extract_keys(const json&) { return tool_result_t::error("Not supported on this platform"); }
tool_result_t autoresponder_add_rule(const json&) { return tool_result_t::error("Not supported on this platform"); }
tool_result_t autoresponder_remove_rule(const json&) { return tool_result_t::error("Not supported on this platform"); }
tool_result_t autoresponder_list_rules(const json&) { return tool_result_t::error("Not supported on this platform"); }
tool_result_t autoresponder_start(const json&) { return tool_result_t::error("Not supported on this platform"); }
tool_result_t autoresponder_stop(const json&) { return tool_result_t::error("Not supported on this platform"); }
tool_result_t autoresponder_import_rules(const json&) { return tool_result_t::error("Not supported on this platform"); }
tool_result_t autoresponder_export_rules(const json&) { return tool_result_t::error("Not supported on this platform"); }
tool_result_t network_decrypt_capture(const json&) { return tool_result_t::error("Not supported on this platform"); }
tool_result_t tls_ensure_keylogfile(const json&) { return tool_result_t::error("Not supported on this platform"); }
#endif

void register_tools() {
    auto& r = ToolRegistry::instance();

    r.register_tool({
        OBFSTR("tls_extract_keys"), OBFSTR("network_security"),
        OBFSTR("Extract TLS session keys from a target process by scanning memory for SChannel, OpenSSL, NSS, and BoringSSL key material. "
               "Returns CLIENT_RANDOM + master_secret pairs compatible with Wireshark SSLKEYLOGFILE format. "
               "Supports TLS 1.0-1.3. For TLS 1.3, also extracts handshake and traffic secrets."),
        {{OBFSTR("pid"), OBFSTR("number"), OBFSTR("Target process ID (0 = current attached process)"), false},
         {OBFSTR("scan_schannel"), OBFSTR("boolean"), OBFSTR("Scan for Windows SChannel keys (default: true)"), false},
         {OBFSTR("scan_openssl"), OBFSTR("boolean"), OBFSTR("Scan for OpenSSL keys (default: true)"), false},
         {OBFSTR("scan_nss"), OBFSTR("boolean"), OBFSTR("Scan for NSS/Firefox keys (default: true)"), false},
         {OBFSTR("scan_boringssl"), OBFSTR("boolean"), OBFSTR("Scan for BoringSSL/Chrome keys (default: true)"), false},
         {OBFSTR("max_results"), OBFSTR("number"), OBFSTR("Maximum keys to return (default: 64)"), false}},
        tls_extract_keys, true});

    r.register_tool({
        OBFSTR("tls_start_keylog"), OBFSTR("network_security"),
        OBFSTR("Start continuous TLS session key logging to a file (SSLKEYLOGFILE format). "
               "Periodically scans the target process for new keys and appends them. "
               "Output file can be loaded in Wireshark for live decryption."),
        {{OBFSTR("pid"), OBFSTR("number"), OBFSTR("Target process ID"), false},
         {OBFSTR("output_file"), OBFSTR("string"), OBFSTR("Output file path (default: Downloads/sslkeylog.txt)"), false},
         {OBFSTR("poll_interval_ms"), OBFSTR("number"), OBFSTR("Polling interval in ms (default: 2000)"), false},
         {OBFSTR("append"), OBFSTR("boolean"), OBFSTR("Append to existing file (default: true)"), false}},
        tls_start_keylog, false});

    r.register_tool({
        OBFSTR("tls_stop_keylog"), OBFSTR("network_security"),
        OBFSTR("Stop the active TLS session key logging thread."),
        {},
        tls_stop_keylog, false});

    r.register_tool({
        OBFSTR("tls_get_extracted_keys"), OBFSTR("network_security"),
        OBFSTR("Get all TLS session keys extracted so far from the cache. Keys persist across multiple scan operations."),
        {},
        tls_get_extracted_keys, true});

    r.register_tool({
        OBFSTR("cert_inject"), OBFSTR("network_security"),
        OBFSTR("Inject a certificate into the Windows certificate store. Supports PEM or DER format. "
               "Can inject into user or system stores (ROOT, CA, MY, etc.). "
               "Useful for MITM/proxy setups where a custom CA certificate needs to be trusted."),
        {{OBFSTR("cert_pem"), OBFSTR("string"), OBFSTR("PEM-encoded certificate string"), false},
         {OBFSTR("cert_der_hex"), OBFSTR("string"), OBFSTR("DER-encoded certificate as hex string"), false},
         {OBFSTR("store_name"), OBFSTR("string"), OBFSTR("Certificate store name (default: ROOT)"), false},
         {OBFSTR("system_wide"), OBFSTR("boolean"), OBFSTR("Install system-wide vs current user (default: false)"), false}},
        cert_inject, false});

    r.register_tool({
        OBFSTR("cert_remove"), OBFSTR("network_security"),
        OBFSTR("Remove a certificate from the Windows certificate store by its SHA-1 thumbprint."),
        {{OBFSTR("thumbprint"), OBFSTR("string"), OBFSTR("SHA-1 thumbprint of the certificate to remove"), true},
         {OBFSTR("store_name"), OBFSTR("string"), OBFSTR("Certificate store name (default: ROOT)"), false}},
        cert_remove, false});

    r.register_tool({
        OBFSTR("cert_generate_ca"), OBFSTR("network_security"),
        OBFSTR("Generate a self-signed CA certificate with a 2048-bit RSA key pair. "
               "Returns the certificate and private key in DER format (hex-encoded). "
               "The CA certificate can then be injected into the trust store for MITM purposes."),
        {{OBFSTR("cn"), OBFSTR("string"), OBFSTR("Common Name for the CA (default: 'AiDA Proxy CA')"), false},
         {OBFSTR("validity_days"), OBFSTR("number"), OBFSTR("Validity period in days (default: 3650)"), false}},
        cert_generate_ca, false});

    r.register_tool({
        OBFSTR("cert_list"), OBFSTR("network_security"),
        OBFSTR("List all certificates in a Windows certificate store. Shows subject, issuer, thumbprint, validity dates, and CA status."),
        {{OBFSTR("store_name"), OBFSTR("string"), OBFSTR("Store name: ROOT, CA, MY, TrustedPeople, etc. (default: ROOT)"), false}},
        cert_list, true});

    r.register_tool({
        OBFSTR("pin_bypass"), OBFSTR("network_security"),
        OBFSTR("Bypass certificate pinning in a target process by patching validation functions in memory. "
               "Supports WinVerifyTrust, CertVerifyCertificateChainPolicy (crypt32), SChannel validation, "
               "Chrome/Edge public key pins, and .NET certificate callbacks. Reverted on session end."),
        {{OBFSTR("pid"), OBFSTR("number"), OBFSTR("Target process ID (0 = current attached)"), false},
         {OBFSTR("method"), OBFSTR("string"), OBFSTR("Bypass method: 'all', 'wintrust', 'crypt32', 'schannel', 'chrome', 'dotnet' (default: all)"), false}},
        pin_bypass, false});

    r.register_tool({
        OBFSTR("pin_bypass_revert"), OBFSTR("network_security"),
        OBFSTR("Revert all certificate pinning bypass patches for a target process, restoring original function prologues."),
        {{OBFSTR("pid"), OBFSTR("number"), OBFSTR("Target process ID"), false}},
        pin_bypass_revert, false});

    r.register_tool({
        OBFSTR("pin_bypass_status"), OBFSTR("network_security"),
        OBFSTR("Check if certificate pin bypass is currently active for a process."),
        {{OBFSTR("pid"), OBFSTR("number"), OBFSTR("Target process ID (0 = current)"), false}},
        pin_bypass_status, true});

    r.register_tool({
        OBFSTR("quic_detect_connections"), OBFSTR("network_security"),
        OBFSTR("Detect active QUIC/HTTP3 connections by analyzing captured UDP packets for QUIC headers. "
               "Parses long and short QUIC headers, extracts connection IDs, and tracks packet counts."),
        {{OBFSTR("pid"), OBFSTR("number"), OBFSTR("Filter by process ID (0 = all)"), false}},
        quic_detect_connections, true});

    r.register_tool({
        OBFSTR("quic_decrypt_initial"), OBFSTR("network_security"),
        OBFSTR("Decrypt a QUIC Initial packet. Initial packets use deterministic key derivation from the "
               "Destination Connection ID, requiring no secret material. Parses header, extracts versions and CIDs."),
        {{OBFSTR("packet_hex"), OBFSTR("string"), OBFSTR("Raw QUIC packet data as hex string"), true}},
        quic_decrypt_initial, true});

    r.register_tool({
        OBFSTR("quic_extract_keys"), OBFSTR("network_security"),
        OBFSTR("Extract QUIC traffic encryption keys from a process. Scans for TLS 1.3 traffic secrets "
               "used by QUIC implementations (msquic, BoringSSL). Keys enable full QUIC payload decryption."),
        {{OBFSTR("pid"), OBFSTR("number"), OBFSTR("Target process ID"), false}},
        quic_extract_keys, true});

    r.register_tool({
        OBFSTR("dtls_detect_sessions"), OBFSTR("network_security"),
        OBFSTR("Detect active DTLS sessions by analyzing captured UDP packets for DTLS record headers. "
               "Identifies DTLS versions (1.0/1.2), handshake state, epochs, and sequence numbers."),
        {{OBFSTR("pid"), OBFSTR("number"), OBFSTR("Filter by process ID (0 = all)"), false}},
        dtls_detect_sessions, true});

    r.register_tool({
        OBFSTR("dtls_extract_keys"), OBFSTR("network_security"),
        OBFSTR("Extract DTLS session keys from a process. Scans memory for DTLS version markers adjacent to "
               "client_random and master_secret pairs. Supports DTLS 1.0 (0xFEFF) and DTLS 1.2 (0xFEFD)."),
        {{OBFSTR("pid"), OBFSTR("number"), OBFSTR("Target process ID"), false}},
        dtls_extract_keys, true});

    r.register_tool({
        OBFSTR("autoresponder_add_rule"), OBFSTR("network_security"),
        OBFSTR("Add an AutoResponder rule (similar to Fiddler's AutoResponder). Rules match intercepted HTTP requests "
               "by URL pattern, method, headers, or body content, and return custom responses. For HTTPS/TLS traffic, "
               "use match_type 'sni_contains' to match on the TLS Server Name Indication (domain). "
               "Supports exact, prefix, regex URL matching, SNI matching, custom status codes, headers, response bodies, and file-based responses."),
        {{OBFSTR("match_type"), OBFSTR("string"), OBFSTR("Match type: exact_url, prefix_url, regex_url, method_and_url, header_contains, body_contains, sni_contains (for HTTPS)"), false},
         {OBFSTR("match_pattern"), OBFSTR("string"), OBFSTR("Pattern to match against"), true},
         {OBFSTR("match_method"), OBFSTR("string"), OBFSTR("HTTP method filter (e.g., GET, POST)"), false},
         {OBFSTR("status_code"), OBFSTR("number"), OBFSTR("HTTP status code for the response (default: 200)"), false},
         {OBFSTR("status_reason"), OBFSTR("string"), OBFSTR("HTTP status reason phrase"), false},
         {OBFSTR("response_body"), OBFSTR("string"), OBFSTR("Response body content"), false},
         {OBFSTR("response_file_path"), OBFSTR("string"), OBFSTR("File path to serve as response body"), false},
         {OBFSTR("response_headers"), OBFSTR("object"), OBFSTR("Custom response headers as key-value pairs"), false},
         {OBFSTR("priority"), OBFSTR("number"), OBFSTR("Rule priority (lower = higher priority, default: 0)"), false},
         {OBFSTR("latency_ms"), OBFSTR("number"), OBFSTR("Artificial response latency in ms"), false},
         {OBFSTR("drop_request"), OBFSTR("boolean"), OBFSTR("Drop the request silently (default: false)"), false},
         {OBFSTR("passthrough"), OBFSTR("boolean"), OBFSTR("Let the request pass through unmodified (default: false)"), false},
         {OBFSTR("enabled"), OBFSTR("boolean"), OBFSTR("Enable the rule (default: true)"), false}},
        autoresponder_add_rule, false});

    r.register_tool({
        OBFSTR("autoresponder_remove_rule"), OBFSTR("network_security"),
        OBFSTR("Remove an AutoResponder rule by its ID."),
        {{OBFSTR("rule_id"), OBFSTR("number"), OBFSTR("Rule ID to remove"), true}},
        autoresponder_remove_rule, false});

    r.register_tool({
        OBFSTR("autoresponder_list_rules"), OBFSTR("network_security"),
        OBFSTR("List all AutoResponder rules with their match patterns, status codes, and hit counts."),
        {},
        autoresponder_list_rules, true});

    r.register_tool({
        OBFSTR("autoresponder_start"), OBFSTR("network_security"),
        OBFSTR("Start the AutoResponder engine. Automatically enables packet capture and interception. "
               "Monitors both HTTP (plaintext) and HTTPS (via TLS SNI extraction) traffic. "
               "Works on any network interface including WiFi. Use sni_contains rules for HTTPS domain blocking."),
        {},
        autoresponder_start, false});

    r.register_tool({
        OBFSTR("autoresponder_stop"), OBFSTR("network_security"),
        OBFSTR("Stop the AutoResponder engine."),
        {},
        autoresponder_stop, false});

    r.register_tool({
        OBFSTR("autoresponder_import_rules"), OBFSTR("network_security"),
        OBFSTR("Import AutoResponder rules from a JSON array string. Each rule object should have match_type, match_pattern, "
               "status_code, response_body, response_headers, and other fields."),
        {{OBFSTR("rules_json"), OBFSTR("string"), OBFSTR("JSON array of rule objects"), true}},
        autoresponder_import_rules, false});

    r.register_tool({
        OBFSTR("autoresponder_export_rules"), OBFSTR("network_security"),
        OBFSTR("Export all AutoResponder rules as a JSON array string. Can be saved and re-imported later."),
        {},
        autoresponder_export_rules, true});

    r.register_tool({
        OBFSTR("network_decrypt_capture"), OBFSTR("network_security"),
        OBFSTR("Decrypt a captured PCAP file using TLS session keys and return the decrypted HTTP/2 frames. "
               "Uses tshark (Wireshark CLI) with an SSLKEYLOGFILE to decrypt TLS traffic. "
               "Automatically reads the SSLKEYLOGFILE path from the environment if keylog_path is not specified. "
               "Returns decrypted HTTP/2 request/response headers, methods, URLs, and bodies. "
               "The target process must have been started with SSLKEYLOGFILE set for key logging to work."),
        {{OBFSTR("pcap_path"), OBFSTR("string"), OBFSTR("Path to the PCAP file to decrypt"), true},
         {OBFSTR("keylog_path"), OBFSTR("string"), OBFSTR("Path to the SSLKEYLOGFILE (auto-detected from env if empty)"), false},
         {OBFSTR("display_filter"), OBFSTR("string"), OBFSTR("Wireshark display filter (default: 'http2')"), false}},
        network_decrypt_capture, true});

    r.register_tool({
        OBFSTR("tls_ensure_keylogfile"), OBFSTR("network_security"),
        OBFSTR("Ensure the SSLKEYLOGFILE environment variable is set at the user level so that all newly launched "
               "Chromium-based browsers, VS Code, Electron apps, and other BoringSSL/OpenSSL applications "
               "will log TLS session keys to a file. The target application must be RESTARTED after this is set. "
               "Once set, use tls_extract_keys or network_decrypt_capture to read the logged keys and decrypt traffic."),
        {{OBFSTR("path"), OBFSTR("string"), OBFSTR("File path for the keylog file (default: %USERPROFILE%\\sslkeys.log)"), false}},
        tls_ensure_keylogfile, false});
}

}


namespace emulation_tools
{

#ifdef __NT__

tool_result_t disassemble_zydis(const json& params)
{
    auto addr = helpers::parse_address(params.value("address", std::string()));
    if (!addr)
        return tool_result_t::error(OBFSTR("Invalid address"));

    std::uint32_t size = params.value("size", 256);
    if (size > 65536)
        return tool_result_t::error(OBFSTR("Size too large (max 65536)"));

    std::uint32_t max_insns = params.value("max_instructions", 100);
    if (max_insns > 10000) max_insns = 10000;

    auto instructions = emulation::disassemble_idb_range(*addr, size, max_insns);
    if (instructions.empty())
        return tool_result_t::error(OBFSTR("No instructions decoded at ") + helpers::format_address(*addr));

    json result;
    result["address"] = helpers::format_address(*addr);
    result["count"]   = instructions.size();

    json arr = json::array();
    for (const auto& insn : instructions)
    {
        json e;
        e["address"]   = helpers::format_address(static_cast<ea_t>(insn.address));
        e["length"]    = insn.length;
        e["mnemonic"]  = insn.mnemonic;
        e["text"]      = insn.full_text;
        if (insn.is_branch) e["is_branch"] = true;
        if (insn.is_call)   e["is_call"]   = true;
        if (insn.is_ret)    e["is_ret"]    = true;
        if (insn.is_nop)    e["is_nop"]    = true;
        if (insn.is_privileged) e["is_privileged"] = true;
        arr.push_back(std::move(e));
    }
    result["instructions"] = std::move(arr);

    return tool_result_t::ok(OBFSTR("Zydis disassembly: ") + std::to_string(instructions.size()) +
                             OBFSTR(" instructions at ") + helpers::format_address(*addr), result);
}

tool_result_t driver_snapshot_and_emulate(const json& params)
{
    if (!device || !device->is_connected())
        return tool_result_t::error(OBFSTR("Driver not connected. Call driver_connect first."));

    if (device->get_process_id() == 0)
        return tool_result_t::error(OBFSTR("Not attached to a process. Call driver_attach first."));

    std::uint32_t pid = device->get_process_id();
    std::uint32_t tid = 0;

    if (params.contains("tid"))
    {
        auto tid_val = params["tid"];
        if (tid_val.is_number())
            tid = tid_val.get<std::uint32_t>();
        else if (tid_val.is_string())
        {
            std::string s = tid_val.get<std::string>();
            try { tid = static_cast<std::uint32_t>(std::stoull(s, nullptr, 0)); } catch (...) {}
        }
    }

    if (tid == 0)
    {
        auto threads = device->enumerate_threads();
        if (threads.empty())
            return tool_result_t::error(OBFSTR("No threads found in target process"));
        tid = threads[0].tid;
    }

    auto addr = helpers::parse_address(params.value("address", std::string()));
    if (!addr)
        return tool_result_t::error(OBFSTR("Invalid start address. Provide 'address' for emulation entry point."));

    emulation::emulation_config_t config;
    config.start_address     = *addr;
    config.max_instructions  = params.value("max_instructions", 50000);
    config.max_trace_entries  = params.value("max_trace_entries", 10000);
    config.record_mem_reads   = params.value("record_mem_reads", true);
    config.record_mem_writes  = params.value("record_mem_writes", true);
    config.record_registers   = params.value("record_registers", true);
    config.analyze_effective_ops = params.value("analyze_effective", true);
    config.timeout_us         = params.value("timeout_us", 10000000);

    if (config.max_instructions > 500000) config.max_instructions = 500000;
    if (config.max_trace_entries > 100000) config.max_trace_entries = 100000;

    if (params.contains("stop_address"))
    {
        auto stop = helpers::parse_address(params.value("stop_address", std::string()));
        if (stop) config.stop_address = *stop;
    }

    if (params.contains("breakpoints") && params["breakpoints"].is_array())
    {
        for (const auto& bp : params["breakpoints"])
        {
            auto bp_addr = helpers::parse_address(bp.is_string() ? bp.get<std::string>() : std::string());
            if (bp_addr) config.breakpoint_addresses.insert(*bp_addr);
        }
    }

    std::uint64_t snap_base = 0, snap_size = 0;
    if (params.contains("snapshot_base"))
    {
        auto sb = helpers::parse_address(params.value("snapshot_base", std::string()));
        if (sb) snap_base = *sb;
    }
    if (params.contains("snapshot_size"))
        snap_size = params.value("snapshot_size", 0);

    auto result = emulation::driver_snapshot_and_emulate(pid, tid, config, snap_base, snap_size);
    if (!result.success)
        return tool_result_t::error(OBFSTR("Emulation failed: ") + result.error);

    json out;
    out["start_address"]      = helpers::format_address(static_cast<ea_t>(result.start_address));
    out["end_address"]        = helpers::format_address(static_cast<ea_t>(result.end_address));
    out["total_instructions"] = result.total_instructions;
    out["junk_instructions"]  = result.junk_instruction_count;
    out["effective_instructions"] = result.total_instructions - result.junk_instruction_count;


    json deltas = json::array();
    for (const auto& d : result.reg_deltas)
    {
        json delta;
        delta["register"] = d.name;
        delta["before"]   = helpers::format_address(static_cast<ea_t>(d.before));
        delta["after"]    = helpers::format_address(static_cast<ea_t>(d.after));
        deltas.push_back(std::move(delta));
    }
    out["register_deltas"] = std::move(deltas);


    json writes = json::array();
    std::size_t write_limit = std::min<std::size_t>(result.mem_writes.size(), 128);
    for (std::size_t i = 0; i < write_limit; ++i)
    {
        const auto& w = result.mem_writes[i];
        json wr;
        wr["address"] = helpers::format_address(static_cast<ea_t>(w.address));
        wr["size"]    = w.size;
        wr["from_insn"] = helpers::format_address(static_cast<ea_t>(w.insn_address));
        std::ostringstream hex;
        for (std::size_t j = 0; j < std::min<std::size_t>(w.data.size(), 16); ++j)
        {
            if (j > 0) hex << " ";
            hex << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(w.data[j]);
        }
        wr["hex"] = hex.str();
        writes.push_back(std::move(wr));
    }
    out["memory_writes"] = std::move(writes);
    out["total_memory_writes"] = result.mem_writes.size();


    json eff_ops = json::array();
    for (const auto& op : result.effective_ops)
        eff_ops.push_back(op);
    out["effective_operations"] = std::move(eff_ops);


    constexpr std::size_t TRACE_EXCERPT = 50;
    json trace_arr = json::array();
    for (std::size_t i = 0; i < std::min(result.trace.size(), TRACE_EXCERPT); ++i)
    {
        const auto& t = result.trace[i];
        json te;
        te["address"] = helpers::format_address(static_cast<ea_t>(t.address));
        te["disasm"]  = t.disasm;
        trace_arr.push_back(std::move(te));
    }
    if (result.trace.size() > TRACE_EXCERPT * 2)
    {
        json gap;
        gap["note"] = "... " + std::to_string(result.trace.size() - TRACE_EXCERPT * 2) + " entries omitted ...";
        trace_arr.push_back(std::move(gap));
        for (std::size_t i = result.trace.size() - TRACE_EXCERPT; i < result.trace.size(); ++i)
        {
            const auto& t = result.trace[i];
            json te;
            te["address"] = helpers::format_address(static_cast<ea_t>(t.address));
            te["disasm"]  = t.disasm;
            trace_arr.push_back(std::move(te));
        }
    }
    out["trace_excerpt"] = std::move(trace_arr);

    if (!result.error.empty())
        out["note"] = result.error;

    return tool_result_t::ok(
        OBFSTR("Snapshot + emulation complete: ") + std::to_string(result.total_instructions) +
        OBFSTR(" insns traced (") + std::to_string(result.junk_instruction_count) + OBFSTR(" junk)"),
        out);
}

tool_result_t trace_execution_unicorn(const json& params)
{
    auto addr = helpers::parse_address(params.value("address", std::string()));
    if (!addr)
        return tool_result_t::error(OBFSTR("Invalid address. Provide the VM entry point address."));

    std::uint32_t size = params.value("size", 4096);
    if (size > 1024 * 1024) size = 1024 * 1024;

    std::uint32_t max_insns = params.value("max_instructions", 50000);
    if (max_insns > 500000) max_insns = 500000;


    std::vector<std::uint8_t> code(size);
    for (std::uint32_t i = 0; i < size; ++i)
        code[i] = static_cast<std::uint8_t>(get_byte(static_cast<ea_t>(*addr + i)));


    emulation::process_snapshot_t snapshot;
    snapshot.success = true;
    snapshot.rip = *addr;
    snapshot.rsp = 0x7FFE0000;
    snapshot.rflags = 0x202;


    emulation::memory_snapshot_region_t code_region;
    code_region.base = *addr & ~0xFFFULL;
    code_region.size = (static_cast<std::uint64_t>(size) + 0xFFF + (*addr & 0xFFF)) & ~0xFFFULL;
    code_region.data.resize(static_cast<std::size_t>(code_region.size), 0);
    std::memcpy(code_region.data.data() + (*addr - code_region.base), code.data(), size);
    snapshot.regions.push_back(std::move(code_region));


    emulation::memory_snapshot_region_t stack_region;
    stack_region.base = 0x7FFD0000;
    stack_region.size = 0x20000;
    stack_region.data.resize(0x20000, 0);
    snapshot.regions.push_back(std::move(stack_region));


    if (params.contains("rax")) { auto v = helpers::parse_address(params.value("rax", std::string())); if (v) snapshot.rax = *v; }
    if (params.contains("rbx")) { auto v = helpers::parse_address(params.value("rbx", std::string())); if (v) snapshot.rbx = *v; }
    if (params.contains("rcx")) { auto v = helpers::parse_address(params.value("rcx", std::string())); if (v) snapshot.rcx = *v; }
    if (params.contains("rdx")) { auto v = helpers::parse_address(params.value("rdx", std::string())); if (v) snapshot.rdx = *v; }
    if (params.contains("rsi")) { auto v = helpers::parse_address(params.value("rsi", std::string())); if (v) snapshot.rsi = *v; }
    if (params.contains("rdi")) { auto v = helpers::parse_address(params.value("rdi", std::string())); if (v) snapshot.rdi = *v; }

    emulation::emulation_config_t config;
    config.start_address     = *addr;
    config.max_instructions  = max_insns;
    config.max_trace_entries  = params.value("max_trace_entries", 10000);
    config.record_mem_reads   = params.value("record_mem_reads", true);
    config.record_mem_writes  = params.value("record_mem_writes", true);
    config.record_registers   = true;
    config.analyze_effective_ops = true;
    config.timeout_us         = params.value("timeout_us", 10000000);

    if (params.contains("stop_address"))
    {
        auto stop = helpers::parse_address(params.value("stop_address", std::string()));
        if (stop) config.stop_address = *stop;
    }

    auto result = emulation::emulate_from_snapshot(snapshot, config);
    if (!result.success)
        return tool_result_t::error(OBFSTR("Unicorn emulation failed: ") + result.error);

    json out;
    out["start_address"]      = helpers::format_address(static_cast<ea_t>(result.start_address));
    out["end_address"]        = helpers::format_address(static_cast<ea_t>(result.end_address));
    out["total_instructions"] = result.total_instructions;
    out["junk_instructions"]  = result.junk_instruction_count;
    out["effective_instructions"] = result.total_instructions - result.junk_instruction_count;

    json deltas = json::array();
    for (const auto& d : result.reg_deltas)
    {
        json delta;
        delta["register"] = d.name;
        delta["before"]   = helpers::format_address(static_cast<ea_t>(d.before));
        delta["after"]    = helpers::format_address(static_cast<ea_t>(d.after));
        deltas.push_back(std::move(delta));
    }
    out["register_deltas"] = std::move(deltas);

    json eff_ops = json::array();
    for (const auto& op : result.effective_ops)
        eff_ops.push_back(op);
    out["effective_operations"] = std::move(eff_ops);

    json writes = json::array();
    std::size_t write_limit = std::min<std::size_t>(result.mem_writes.size(), 128);
    for (std::size_t i = 0; i < write_limit; ++i)
    {
        const auto& w = result.mem_writes[i];
        json wr;
        wr["address"] = helpers::format_address(static_cast<ea_t>(w.address));
        wr["size"]    = w.size;
        writes.push_back(std::move(wr));
    }
    out["memory_writes"] = std::move(writes);

    constexpr std::size_t TRACE_EXCERPT = 50;
    json trace_arr = json::array();
    for (std::size_t i = 0; i < std::min(result.trace.size(), TRACE_EXCERPT); ++i)
    {
        const auto& t = result.trace[i];
        json te;
        te["address"] = helpers::format_address(static_cast<ea_t>(t.address));
        te["disasm"]  = t.disasm;
        trace_arr.push_back(std::move(te));
    }
    if (result.trace.size() > TRACE_EXCERPT * 2)
    {
        json gap;
        gap["note"] = "... " + std::to_string(result.trace.size() - TRACE_EXCERPT * 2) + " entries omitted ...";
        trace_arr.push_back(std::move(gap));
        for (std::size_t i = result.trace.size() - TRACE_EXCERPT; i < result.trace.size(); ++i)
        {
            const auto& t = result.trace[i];
            json te;
            te["address"] = helpers::format_address(static_cast<ea_t>(t.address));
            te["disasm"]  = t.disasm;
            trace_arr.push_back(std::move(te));
        }
    }
    out["trace_excerpt"] = std::move(trace_arr);

    return tool_result_t::ok(
        OBFSTR("IDB emulation: ") + std::to_string(result.total_instructions) +
        OBFSTR(" insns (") + std::to_string(result.junk_instruction_count) + OBFSTR(" junk)"), out);
}

tool_result_t analyze_vm_handler(const json& params)
{
    auto addr = helpers::parse_address(params.value("address", std::string()));
    if (!addr)
        return tool_result_t::error(OBFSTR("Invalid address. Provide the VM handler entry point."));

    std::uint32_t handler_size = params.value("size", 8192);
    if (handler_size > 1024 * 1024) handler_size = 1024 * 1024;

    std::uint32_t max_insns = params.value("max_instructions", 100000);
    if (max_insns > 500000) max_insns = 500000;


    auto disasm = emulation::disassemble_idb_range(*addr, handler_size, 10000);


    std::uint32_t nop_count = 0, branch_count = 0, call_count = 0, privileged_count = 0;
    std::uint32_t total_insns = static_cast<std::uint32_t>(disasm.size());
    std::set<std::uint64_t> branch_targets;
    std::uint64_t last_addr = *addr;

    for (const auto& insn : disasm)
    {
        if (insn.is_nop) ++nop_count;
        if (insn.is_branch) ++branch_count;
        if (insn.is_call) ++call_count;
        if (insn.is_privileged) ++privileged_count;
        last_addr = insn.address + insn.length;
    }


    std::vector<std::uint8_t> code(handler_size);
    for (std::uint32_t i = 0; i < handler_size; ++i)
        code[i] = static_cast<std::uint8_t>(get_byte(static_cast<ea_t>(*addr + i)));

    emulation::process_snapshot_t snapshot;
    snapshot.success = true;
    snapshot.rip = *addr;
    snapshot.rsp = 0x7FFE0000;
    snapshot.rflags = 0x202;


    if (params.contains("rax")) { auto v = helpers::parse_address(params.value("rax", std::string())); if (v) snapshot.rax = *v; }
    if (params.contains("rbx")) { auto v = helpers::parse_address(params.value("rbx", std::string())); if (v) snapshot.rbx = *v; }
    if (params.contains("rcx")) { auto v = helpers::parse_address(params.value("rcx", std::string())); if (v) snapshot.rcx = *v; }
    if (params.contains("rdx")) { auto v = helpers::parse_address(params.value("rdx", std::string())); if (v) snapshot.rdx = *v; }
    if (params.contains("rsi")) { auto v = helpers::parse_address(params.value("rsi", std::string())); if (v) snapshot.rsi = *v; }
    if (params.contains("rdi")) { auto v = helpers::parse_address(params.value("rdi", std::string())); if (v) snapshot.rdi = *v; }

    emulation::memory_snapshot_region_t code_region;
    code_region.base = *addr & ~0xFFFULL;
    code_region.size = (static_cast<std::uint64_t>(handler_size) + 0xFFF + (*addr & 0xFFF)) & ~0xFFFULL;
    code_region.data.resize(static_cast<std::size_t>(code_region.size), 0);
    std::memcpy(code_region.data.data() + (*addr - code_region.base), code.data(), handler_size);
    snapshot.regions.push_back(std::move(code_region));

    emulation::memory_snapshot_region_t stack_region;
    stack_region.base = 0x7FFD0000;
    stack_region.size = 0x20000;
    stack_region.data.resize(0x20000, 0);
    snapshot.regions.push_back(std::move(stack_region));

    emulation::emulation_config_t config;
    config.start_address         = *addr;
    config.max_instructions      = max_insns;
    config.max_trace_entries     = 50000;
    config.record_mem_reads      = true;
    config.record_mem_writes     = true;
    config.record_registers      = true;
    config.analyze_effective_ops = true;
    config.timeout_us            = params.value("timeout_us", 15000000);

    auto emu_result = emulation::emulate_from_snapshot(snapshot, config);

    json out;
    out["handler_address"]   = helpers::format_address(*addr);
    out["handler_size"]      = handler_size;


    json static_info;
    static_info["total_decoded"]     = total_insns;
    static_info["nop_instructions"]  = nop_count;
    static_info["branch_count"]      = branch_count;
    static_info["call_count"]        = call_count;
    static_info["privileged_count"]  = privileged_count;
    static_info["nop_ratio"]         = total_insns > 0
        ? static_cast<double>(nop_count) / total_insns : 0.0;
    out["static_analysis"] = std::move(static_info);


    if (emu_result.success)
    {
        auto analysis = emulation::analyze_vm_trace(emu_result);

        json emu_info;
        emu_info["total_executed"]       = analysis.total_instructions;
        emu_info["effective_instructions"] = analysis.effective_instructions;
        emu_info["junk_instructions"]    = analysis.junk_instructions;
        emu_info["junk_ratio"]           = analysis.total_instructions > 0
            ? static_cast<double>(analysis.junk_instructions) / analysis.total_instructions : 0.0;
        emu_info["summary"]              = analysis.summary;

        json deltas = json::array();
        for (const auto& d : analysis.net_reg_changes)
        {
            json delta;
            delta["register"] = d.name;
            delta["before"]   = helpers::format_address(static_cast<ea_t>(d.before));
            delta["after"]    = helpers::format_address(static_cast<ea_t>(d.after));
            deltas.push_back(std::move(delta));
        }
        emu_info["net_register_changes"] = std::move(deltas);

        json writes = json::array();
        std::size_t wlimit = std::min<std::size_t>(analysis.net_mem_writes.size(), 64);
        for (std::size_t i = 0; i < wlimit; ++i)
        {
            json wr;
            wr["address"] = helpers::format_address(static_cast<ea_t>(analysis.net_mem_writes[i].address));
            wr["size"]    = analysis.net_mem_writes[i].size;
            writes.push_back(std::move(wr));
        }
        emu_info["net_memory_writes"] = std::move(writes);

        json eff_ops = json::array();
        for (const auto& op : analysis.effective_ops)
            eff_ops.push_back(op);
        emu_info["effective_operations"] = std::move(eff_ops);

        out["emulation_analysis"] = std::move(emu_info);
    }
    else
    {
        out["emulation_error"] = emu_result.error;
    }


    double junk_ratio = emu_result.success && emu_result.total_instructions > 0
        ? static_cast<double>(emu_result.junk_instruction_count) / emu_result.total_instructions
        : 0.0;

    std::string classification;
    if (junk_ratio > 0.8)
        classification = "heavily_virtualized";
    else if (junk_ratio > 0.5)
        classification = "moderately_obfuscated";
    else if (nop_count > total_insns / 3)
        classification = "junk_padded";
    else
        classification = "normal";

    out["classification"] = classification;

    return tool_result_t::ok(
        OBFSTR("VM handler analysis at ") + helpers::format_address(*addr) +
        OBFSTR(": ") + classification, out);
}


tool_result_t emulate_multi_trace(const json& params)
{
    auto addr = helpers::parse_address(params.value("address", std::string()));
    if (!addr)
        return tool_result_t::error(OBFSTR("Invalid address"));

    if (!params.contains("inputs") || !params["inputs"].is_array() || params["inputs"].empty())
        return tool_result_t::error(OBFSTR("Provide 'inputs' array of register state objects [{rax:..., rbx:...}, ...]"));

    std::uint32_t size = params.value("size", 4096);
    if (size > 1024 * 1024) size = 1024 * 1024;
    std::uint32_t max_insns = params.value("max_instructions", 50000);
    if (max_insns > 500000) max_insns = 500000;


    std::vector<std::uint8_t> code(size);
    for (std::uint32_t i = 0; i < size; ++i)
        code[i] = static_cast<std::uint8_t>(get_byte(static_cast<ea_t>(*addr + i)));

    json traces = json::array();
    const auto& inputs = params["inputs"];

    for (std::size_t ti = 0; ti < inputs.size() && ti < 32; ++ti)
    {
        const json& inp = inputs[ti];

        emulation::process_snapshot_t snapshot;
        snapshot.success = true;
        snapshot.rip = *addr;
        snapshot.rsp = 0x7FFE0000;
        snapshot.rflags = 0x202;


        auto set_reg = [&](const char* name, std::uint64_t& reg)
        {
            if (inp.contains(name))
            {
                if (inp[name].is_number()) reg = inp[name].get<std::uint64_t>();
                else if (inp[name].is_string()) { auto v = helpers::parse_address(inp[name].get<std::string>()); if (v) reg = *v; }
            }
        };
        set_reg("rax", snapshot.rax); set_reg("rbx", snapshot.rbx);
        set_reg("rcx", snapshot.rcx); set_reg("rdx", snapshot.rdx);
        set_reg("rsi", snapshot.rsi); set_reg("rdi", snapshot.rdi);
        set_reg("r8", snapshot.r8);   set_reg("r9", snapshot.r9);


        emulation::memory_snapshot_region_t code_region;
        code_region.base = *addr & ~0xFFFULL;
        code_region.size = (static_cast<std::uint64_t>(size) + 0xFFF + (*addr & 0xFFF)) & ~0xFFFULL;
        code_region.data.resize(static_cast<std::size_t>(code_region.size), 0);
        std::memcpy(code_region.data.data() + (*addr - code_region.base), code.data(), size);
        snapshot.regions.push_back(std::move(code_region));


        emulation::memory_snapshot_region_t stack_region;
        stack_region.base = 0x7FFD0000;
        stack_region.size = 0x20000;
        stack_region.data.resize(0x20000, 0);
        snapshot.regions.push_back(std::move(stack_region));

        emulation::emulation_config_t config;
        config.start_address     = *addr;
        config.max_instructions  = max_insns;
        config.max_trace_entries  = 100;
        config.record_mem_reads   = false;
        config.record_mem_writes  = true;
        config.record_registers   = true;
        config.analyze_effective_ops = true;
        config.timeout_us         = params.value("timeout_us", 5000000);

        auto result = emulation::emulate_from_snapshot(snapshot, config);

        json trace;
        trace["input_index"] = ti;
        trace["input_regs"]  = inp;
        trace["success"]     = result.success;

        if (result.success)
        {
            trace["total_instructions"]     = result.total_instructions;
            trace["junk_instructions"]      = result.junk_instruction_count;
            trace["effective_instructions"] = result.total_instructions - result.junk_instruction_count;
            trace["end_address"]            = helpers::format_address(static_cast<ea_t>(result.end_address));

            json deltas = json::array();
            for (const auto& d : result.reg_deltas)
            {
                json delta;
                delta["register"] = d.name;
                delta["before"]   = helpers::format_address(static_cast<ea_t>(d.before));
                delta["after"]    = helpers::format_address(static_cast<ea_t>(d.after));
                deltas.push_back(std::move(delta));
            }
            trace["register_deltas"] = std::move(deltas);

            json eff = json::array();
            for (const auto& op : result.effective_ops) eff.push_back(op);
            trace["effective_operations"] = std::move(eff);

            json wrs = json::array();
            std::size_t wl = std::min<std::size_t>(result.mem_writes.size(), 32);
            for (std::size_t w = 0; w < wl; ++w)
            {
                json wr; wr["address"] = helpers::format_address(static_cast<ea_t>(result.mem_writes[w].address));
                wr["size"] = result.mem_writes[w].size; wrs.push_back(std::move(wr));
            }
            trace["memory_writes"] = std::move(wrs);
        }
        else
        {
            trace["error"] = result.error;
        }
        traces.push_back(std::move(trace));
    }


    json diff;
    if (traces.size() >= 2)
    {
        bool same_length = true;
        bool same_regs   = true;
        bool same_writes = true;
        std::uint32_t ref_insns = traces[0].value("total_instructions", 0);

        for (std::size_t i = 1; i < traces.size(); ++i)
        {
            if (traces[i].value("total_instructions", 0) != ref_insns) same_length = false;
            if (traces[i].value("register_deltas", json::array()) != traces[0].value("register_deltas", json::array())) same_regs = false;
            if (traces[i].value("memory_writes", json::array()) != traces[0].value("memory_writes", json::array())) same_writes = false;
        }
        diff["execution_length_consistent"] = same_length;
        diff["register_outputs_identical"]  = same_regs;
        diff["memory_writes_identical"]     = same_writes;

        if (same_regs && same_writes && same_length) diff["verdict"] = "constant_operation";
        else if (!same_regs && !same_writes) diff["verdict"] = "input_dependent_behavior";
        else if (!same_regs && same_writes)  diff["verdict"] = "register_transform_only";
        else                                 diff["verdict"] = "memory_behavior_varies";
    }

    json out;
    out["address"]      = helpers::format_address(*addr);
    out["trace_count"]  = traces.size();
    out["traces"]       = std::move(traces);
    if (!diff.empty()) out["differential_analysis"] = std::move(diff);

    return tool_result_t::ok(OBFSTR("Multi-trace: ") + std::to_string(out["trace_count"].get<std::size_t>()) +
                             OBFSTR(" traces at ") + helpers::format_address(*addr), out);
}


tool_result_t emulate_function(const json& params)
{
    auto addr = helpers::parse_address(params.value("address", std::string()));
    if (!addr)
        return tool_result_t::error(OBFSTR("Invalid address"));

    func_t* fn = get_func(*addr);
    std::uint32_t fn_size = fn ? static_cast<std::uint32_t>(fn->size()) : params.value("size", 4096);
    if (fn_size > 1024 * 1024) fn_size = 1024 * 1024;


    std::uint32_t map_size = std::max(fn_size * 2, 8192u);
    if (map_size > 1024 * 1024) map_size = 1024 * 1024;

    std::vector<std::uint8_t> code(map_size);
    for (std::uint32_t i = 0; i < map_size; ++i)
        code[i] = static_cast<std::uint8_t>(get_byte(static_cast<ea_t>(*addr + i)));


    constexpr std::uint64_t SENTINEL_RET = 0xDEAD000000000000ULL;
    constexpr std::uint64_t STACK_BASE   = 0x7FFD0000;
    constexpr std::uint64_t STACK_SIZE   = 0x20000;
    constexpr std::uint64_t STACK_TOP    = STACK_BASE + STACK_SIZE - 0x1000;

    emulation::process_snapshot_t snapshot;
    snapshot.success = true;
    snapshot.rip     = *addr;
    snapshot.rsp     = STACK_TOP;
    snapshot.rbp     = STACK_TOP + 0x100;
    snapshot.rflags  = 0x202;


    if (params.contains("rax")) { auto v = helpers::parse_address(params.value("rax", std::string())); if (v) snapshot.rax = *v; }
    if (params.contains("rbx")) { auto v = helpers::parse_address(params.value("rbx", std::string())); if (v) snapshot.rbx = *v; }
    if (params.contains("rcx")) { auto v = helpers::parse_address(params.value("rcx", std::string())); if (v) snapshot.rcx = *v; }
    if (params.contains("rdx")) { auto v = helpers::parse_address(params.value("rdx", std::string())); if (v) snapshot.rdx = *v; }
    if (params.contains("rsi")) { auto v = helpers::parse_address(params.value("rsi", std::string())); if (v) snapshot.rsi = *v; }
    if (params.contains("rdi")) { auto v = helpers::parse_address(params.value("rdi", std::string())); if (v) snapshot.rdi = *v; }
    if (params.contains("r8"))  { auto v = helpers::parse_address(params.value("r8", std::string()));  if (v) snapshot.r8  = *v; }
    if (params.contains("r9"))  { auto v = helpers::parse_address(params.value("r9", std::string()));  if (v) snapshot.r9  = *v; }


    emulation::memory_snapshot_region_t code_region;
    code_region.base = *addr & ~0xFFFULL;
    code_region.size = (static_cast<std::uint64_t>(map_size) + 0xFFF + (*addr & 0xFFF)) & ~0xFFFULL;
    code_region.data.resize(static_cast<std::size_t>(code_region.size), 0);
    std::memcpy(code_region.data.data() + (*addr - code_region.base), code.data(), map_size);
    snapshot.regions.push_back(std::move(code_region));


    emulation::memory_snapshot_region_t stack_region;
    stack_region.base = STACK_BASE;
    stack_region.size = STACK_SIZE;
    stack_region.data.resize(STACK_SIZE, 0);

    std::uint64_t sentinel = SENTINEL_RET;
    std::memcpy(stack_region.data.data() + (STACK_TOP - STACK_BASE), &sentinel, 8);
    snapshot.regions.push_back(std::move(stack_region));


    emulation::memory_snapshot_region_t sentinel_region;
    sentinel_region.base = SENTINEL_RET & ~0xFFFULL;
    sentinel_region.size = 0x1000;
    sentinel_region.data.resize(0x1000, 0xCC);
    snapshot.regions.push_back(std::move(sentinel_region));

    emulation::emulation_config_t config;
    config.start_address     = *addr;
    config.stop_address      = SENTINEL_RET;
    config.max_instructions  = params.value("max_instructions", 100000);
    config.max_trace_entries  = params.value("max_trace_entries", 10000);
    config.record_mem_reads   = params.value("record_mem_reads", true);
    config.record_mem_writes  = params.value("record_mem_writes", true);
    config.record_registers   = true;
    config.analyze_effective_ops = true;
    config.timeout_us         = params.value("timeout_us", 15000000);
    config.breakpoint_addresses.insert(SENTINEL_RET);

    auto result = emulation::emulate_from_snapshot(snapshot, config);

    json out;
    out["function_address"] = helpers::format_address(*addr);
    out["function_size"]    = fn_size;
    out["mapped_size"]      = map_size;
    out["success"]          = result.success;

    bool returned_normally = result.success &&
        (result.end_address == SENTINEL_RET || result.end_address == SENTINEL_RET + 1);
    out["returned_normally"] = returned_normally;

    if (result.success)
    {
        out["total_instructions"]     = result.total_instructions;
        out["junk_instructions"]      = result.junk_instruction_count;
        out["effective_instructions"] = result.total_instructions - result.junk_instruction_count;
        out["end_address"]            = helpers::format_address(static_cast<ea_t>(result.end_address));


        for (const auto& d : result.reg_deltas)
        {
            if (d.name == "rax")
            {
                out["return_value"] = helpers::format_address(static_cast<ea_t>(d.after));
                break;
            }
        }

        json deltas = json::array();
        for (const auto& d : result.reg_deltas)
        {
            json delta;
            delta["register"] = d.name;
            delta["before"]   = helpers::format_address(static_cast<ea_t>(d.before));
            delta["after"]    = helpers::format_address(static_cast<ea_t>(d.after));
            deltas.push_back(std::move(delta));
        }
        out["register_deltas"] = std::move(deltas);

        json eff = json::array();
        for (const auto& op : result.effective_ops) eff.push_back(op);
        out["effective_operations"] = std::move(eff);

        json writes = json::array();
        std::size_t wl = std::min<std::size_t>(result.mem_writes.size(), 128);
        for (std::size_t w = 0; w < wl; ++w)
        {
            json wr;
            wr["address"] = helpers::format_address(static_cast<ea_t>(result.mem_writes[w].address));
            wr["size"]    = result.mem_writes[w].size;
            writes.push_back(std::move(wr));
        }
        out["memory_writes"] = std::move(writes);


        constexpr std::size_t EX = 30;
        json trace_arr = json::array();
        for (std::size_t i = 0; i < std::min(result.trace.size(), EX); ++i)
        {
            json te; te["address"] = helpers::format_address(static_cast<ea_t>(result.trace[i].address));
            te["disasm"] = result.trace[i].disasm; trace_arr.push_back(std::move(te));
        }
        if (result.trace.size() > EX * 2)
        {
            trace_arr.push_back(json{{"note", "... " + std::to_string(result.trace.size() - EX * 2) + " instructions omitted ..."}});
            for (std::size_t i = result.trace.size() - EX; i < result.trace.size(); ++i)
            {
                json te; te["address"] = helpers::format_address(static_cast<ea_t>(result.trace[i].address));
                te["disasm"] = result.trace[i].disasm; trace_arr.push_back(std::move(te));
            }
        }
        out["trace_excerpt"] = std::move(trace_arr);
    }
    else
    {
        out["error"] = result.error;
    }

    return tool_result_t::ok(
        OBFSTR("Function emulation ") + helpers::format_address(*addr) +
        (returned_normally ? OBFSTR(": returned normally") : OBFSTR(": did not return")), out);
}

#else

tool_result_t disassemble_zydis(const json&)
{
    return tool_result_t::error(OBFSTR("Emulation engine requires Windows (NT kernel driver)."));
}

tool_result_t driver_snapshot_and_emulate(const json&)
{
    return tool_result_t::error(OBFSTR("Emulation engine requires Windows (NT kernel driver)."));
}

tool_result_t trace_execution_unicorn(const json&)
{
    return tool_result_t::error(OBFSTR("Emulation engine requires Windows (NT kernel driver)."));
}

tool_result_t analyze_vm_handler(const json&)
{
    return tool_result_t::error(OBFSTR("Emulation engine requires Windows (NT kernel driver)."));
}

tool_result_t emulate_multi_trace(const json&)
{
    return tool_result_t::error(OBFSTR("Emulation engine requires Windows (NT kernel driver)."));
}

tool_result_t emulate_function(const json&)
{
    return tool_result_t::error(OBFSTR("Emulation engine requires Windows (NT kernel driver)."));
}

#endif

void register_tools()
{
    auto& registry = ToolRegistry::instance();

    registry.register_tool({
        OBFSTR("disassemble_zydis"), OBFSTR("emulation"),
        OBFSTR("Disassemble bytes using the Zydis engine instead of IDA's built-in disassembler. "
               "Produces richer instruction metadata: branch/call/ret/nop/privileged classification, "
               "precise mnemonic parsing, and accurate instruction lengths. "
               "Works on any bytes in the IDB — useful for analyzing packed, encrypted, or "
               "dynamically-generated code that IDA may have failed to disassemble."),
        {{OBFSTR("address"), OBFSTR("string"), OBFSTR("Start address in the IDB"), true},
         {OBFSTR("size"), OBFSTR("number"), OBFSTR("Number of bytes to disassemble (default 256, max 65536)"), false},
         {OBFSTR("max_instructions"), OBFSTR("number"), OBFSTR("Maximum instructions to decode (default 100, max 10000)"), false}},
        disassemble_zydis, true});

    registry.register_tool({
        OBFSTR("driver_snapshot_and_emulate"), OBFSTR("emulation"),
        OBFSTR("Capture a live process snapshot via the kernel driver and emulate code offline in Unicorn. "
               "The driver silently reads physical memory pages and thread context without triggering "
               "any anti-debug or anti-tamper mechanisms. The captured state is loaded into Unicorn "
               "for offline x86-64 emulation with full instruction tracing. "
               "Produces: register deltas (before/after), memory writes, effective vs junk instruction "
               "classification, and an execution trace. "
               "Use this to analyze VM handlers, unpacking stubs, and obfuscated code in protected "
               "processes where the debugger would be detected. "
               "Requires: driver_connect + driver_attach first."),
        {{OBFSTR("address"), OBFSTR("string"), OBFSTR("Emulation start address (entry point of VM handler or code to trace)"), true},
         {OBFSTR("tid"), OBFSTR("number"), OBFSTR("Target thread ID (auto-selects first thread if omitted)"), false},
         {OBFSTR("max_instructions"), OBFSTR("number"), OBFSTR("Maximum instructions to emulate (default 50000)"), false},
         {OBFSTR("max_trace_entries"), OBFSTR("number"), OBFSTR("Maximum trace log entries (default 10000)"), false},
         {OBFSTR("stop_address"), OBFSTR("string"), OBFSTR("Address to stop emulation at (optional)"), false},
         {OBFSTR("breakpoints"), OBFSTR("array"), OBFSTR("Array of addresses to break at during emulation"), false,
          {}, {{"type", "string"}}},
         {OBFSTR("snapshot_base"), OBFSTR("string"), OBFSTR("Override snapshot region base address (auto if omitted)"), false},
         {OBFSTR("snapshot_size"), OBFSTR("number"), OBFSTR("Override snapshot region size in bytes (auto if omitted)"), false},
         {OBFSTR("record_mem_reads"), OBFSTR("boolean"), OBFSTR("Log all memory reads (default true)"), false},
         {OBFSTR("record_mem_writes"), OBFSTR("boolean"), OBFSTR("Log all memory writes (default true)"), false},
         {OBFSTR("analyze_effective"), OBFSTR("boolean"), OBFSTR("Classify junk vs effective instructions (default true)"), false},
         {OBFSTR("timeout_us"), OBFSTR("number"), OBFSTR("Emulation timeout in microseconds (default 10000000 = 10s)"), false}},
        driver_snapshot_and_emulate, false});

    registry.register_tool({
        OBFSTR("trace_execution_unicorn"), OBFSTR("emulation"),
        OBFSTR("Emulate code from the IDB offline using Unicorn — NO debugger or driver required. "
               "Reads bytes directly from the IDA database, maps them into a Unicorn x86-64 engine "
               "with a synthetic stack, and traces execution. Produces register deltas, memory writes, "
               "effective vs junk instruction classification, and an execution trace. "
               "Ideal for analyzing VM handlers, decryption loops, and obfuscated routines statically. "
               "You can set initial register values (rax, rbx, ...) to simulate specific VM opcodes."),
        {{OBFSTR("address"), OBFSTR("string"), OBFSTR("Start address to emulate from"), true},
         {OBFSTR("size"), OBFSTR("number"), OBFSTR("Bytes of code to map (default 4096, max 1MB)"), false},
         {OBFSTR("max_instructions"), OBFSTR("number"), OBFSTR("Maximum instructions to emulate (default 50000)"), false},
         {OBFSTR("max_trace_entries"), OBFSTR("number"), OBFSTR("Maximum trace log entries (default 10000)"), false},
         {OBFSTR("stop_address"), OBFSTR("string"), OBFSTR("Address to stop emulation at (optional)"), false},
         {OBFSTR("rax"), OBFSTR("string"), OBFSTR("Initial RAX value (hex)"), false},
         {OBFSTR("rbx"), OBFSTR("string"), OBFSTR("Initial RBX value (hex)"), false},
         {OBFSTR("rcx"), OBFSTR("string"), OBFSTR("Initial RCX value (hex)"), false},
         {OBFSTR("rdx"), OBFSTR("string"), OBFSTR("Initial RDX value (hex)"), false},
         {OBFSTR("rsi"), OBFSTR("string"), OBFSTR("Initial RSI value (hex)"), false},
         {OBFSTR("rdi"), OBFSTR("string"), OBFSTR("Initial RDI value (hex)"), false},
         {OBFSTR("record_mem_reads"), OBFSTR("boolean"), OBFSTR("Log memory reads (default true)"), false},
         {OBFSTR("record_mem_writes"), OBFSTR("boolean"), OBFSTR("Log memory writes (default true)"), false},
         {OBFSTR("timeout_us"), OBFSTR("number"), OBFSTR("Emulation timeout in microseconds (default 10s)"), false}},
        trace_execution_unicorn, true});

    registry.register_tool({
        OBFSTR("analyze_vm_handler"), OBFSTR("emulation"),
        OBFSTR("Combined static + dynamic analysis of a VM handler or obfuscated code block. "
               "Step 1: Zydis static disassembly with instruction classification. "
               "Step 2: Unicorn offline emulation to separate junk from effective operations. "
               "Produces: static instruction counts (nop/branch/call/privileged ratios), "
               "emulation results (register deltas, memory writes, effective ops), "
               "and an overall classification (heavily_virtualized / moderately_obfuscated / junk_padded / normal). "
               "Use this as a one-shot tool to understand what a VM handler actually computes, "
               "cutting through thousands of junk instructions to reveal the true logic."),
        {{OBFSTR("address"), OBFSTR("string"), OBFSTR("VM handler entry point address"), true},
         {OBFSTR("size"), OBFSTR("number"), OBFSTR("Handler size in bytes (default 8192)"), false},
         {OBFSTR("max_instructions"), OBFSTR("number"), OBFSTR("Max instructions for emulation (default 100000)"), false},
         {OBFSTR("rax"), OBFSTR("string"), OBFSTR("Initial RAX for emulation (hex)"), false},
         {OBFSTR("rbx"), OBFSTR("string"), OBFSTR("Initial RBX for emulation (hex)"), false},
         {OBFSTR("rcx"), OBFSTR("string"), OBFSTR("Initial RCX for emulation (hex)"), false},
         {OBFSTR("rdx"), OBFSTR("string"), OBFSTR("Initial RDX for emulation (hex)"), false},
         {OBFSTR("rsi"), OBFSTR("string"), OBFSTR("Initial RSI for emulation (hex)"), false},
         {OBFSTR("rdi"), OBFSTR("string"), OBFSTR("Initial RDI for emulation (hex)"), false},
         {OBFSTR("timeout_us"), OBFSTR("number"), OBFSTR("Emulation timeout in microseconds (default 15s)"), false}},
        analyze_vm_handler, true});

    registry.register_tool({
        OBFSTR("emulate_multi_trace"), OBFSTR("emulation"),
        OBFSTR("Run multiple emulation traces with different register inputs for differential analysis. "
               "Compare execution paths, register outputs, and memory writes across traces. "
               "Classifies behavior: constant_operation, register_transform_only, input_dependent_behavior, "
               "memory_behavior_varies. Use to understand VM handler semantics (e.g. verify that a handler "
               "is 'vm_add' by running with different inputs and confirming output = input_a + input_b)."),
        {{OBFSTR("address"), OBFSTR("string"), OBFSTR("Code address to emulate"), true},
         {OBFSTR("inputs"), OBFSTR("array"), OBFSTR("Array of register state objects, e.g. [{rax:\"0x10\",rbx:\"0x20\"}, {rax:\"0x30\",rbx:\"0x40\"}]"), true},
         {OBFSTR("size"), OBFSTR("number"), OBFSTR("Code size in bytes (default: 4096)"), false},
         {OBFSTR("max_instructions"), OBFSTR("number"), OBFSTR("Max instructions per trace (default: 50000)"), false},
         {OBFSTR("timeout_us"), OBFSTR("number"), OBFSTR("Timeout per trace in microseconds (default: 5s)"), false}},
        emulate_multi_trace, true});

    registry.register_tool({
        OBFSTR("emulate_function"), OBFSTR("emulation"),
        OBFSTR("Emulate a complete function from the IDB offline until it returns (RET). "
               "Sets up a synthetic stack with a sentinel return address to detect normal function return. "
               "Reports: return value (RAX), register deltas, memory writes, effective operations, "
               "and whether the function returned normally. "
               "Use to understand what a function computes without running it in a live process."),
        {{OBFSTR("address"), OBFSTR("string"), OBFSTR("Function entry point"), true},
         {OBFSTR("size"), OBFSTR("number"), OBFSTR("Override function size if no IDA function defined"), false},
         {OBFSTR("max_instructions"), OBFSTR("number"), OBFSTR("Max instructions (default: 100000)"), false},
         {OBFSTR("max_trace_entries"), OBFSTR("number"), OBFSTR("Max trace entries (default: 10000)"), false},
         {OBFSTR("rax"), OBFSTR("string"), OBFSTR("Initial RAX (hex)"), false},
         {OBFSTR("rbx"), OBFSTR("string"), OBFSTR("Initial RBX (hex)"), false},
         {OBFSTR("rcx"), OBFSTR("string"), OBFSTR("Initial RCX (hex)"), false},
         {OBFSTR("rdx"), OBFSTR("string"), OBFSTR("Initial RDX (hex)"), false},
         {OBFSTR("rsi"), OBFSTR("string"), OBFSTR("Initial RSI (hex)"), false},
         {OBFSTR("rdi"), OBFSTR("string"), OBFSTR("Initial RDI (hex)"), false},
         {OBFSTR("r8"), OBFSTR("string"), OBFSTR("Initial R8 (hex)"), false},
         {OBFSTR("r9"), OBFSTR("string"), OBFSTR("Initial R9 (hex)"), false},
         {OBFSTR("record_mem_reads"), OBFSTR("boolean"), OBFSTR("Log memory reads (default: true)"), false},
         {OBFSTR("record_mem_writes"), OBFSTR("boolean"), OBFSTR("Log memory writes (default: true)"), false},
         {OBFSTR("timeout_us"), OBFSTR("number"), OBFSTR("Timeout in microseconds (default: 15s)"), false}},
        emulate_function, true});
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
    analysis_tools::register_tools();
    deobfuscation_tools::register_tools();
    driver_tools::register_tools();
    graphrag_tools::register_tools();
    network_tools::register_tools();
    net_security_tools::register_tools();
    emulation_tools::register_tools();

    ToolRegistry::instance().register_tool({
        OBFSTR("sessions_spawn"), OBFSTR("session"),
        OBFSTR("Spawn a non-blocking background sub-agent run in an isolated session. The child announces its result back automatically to the requester session when it finishes. Use this for independent, slow, or research-heavy branches that can run in parallel."),
        {
            {OBFSTR("task"), OBFSTR("string"), OBFSTR("Required task for the child sub-agent."), true},
            {OBFSTR("label"), OBFSTR("string"), OBFSTR("Optional human-readable label for the child session."), false},
            {OBFSTR("targetInstance"), OBFSTR("string"), OBFSTR("Optional target instance id, input path, or display name. Leave empty to use the current IDA instance."), false},
            {OBFSTR("agentId"), OBFSTR("string"), OBFSTR("Optional agent id override. Defaults to the current AiDA agent."), false},
            {OBFSTR("model"), OBFSTR("string"), OBFSTR("Optional model override for the child run."), false},
            {OBFSTR("thinking"), OBFSTR("string"), OBFSTR("Optional thinking profile override: inherit, none, minimal, low, medium, high."), false},
            {OBFSTR("runTimeoutSeconds"), OBFSTR("number"), OBFSTR("Optional timeout for the child run in seconds."), false},
            {OBFSTR("thread"), OBFSTR("boolean"), OBFSTR("Reserved compatibility flag for thread-bound sessions."), false},
            {OBFSTR("mode"), OBFSTR("string"), OBFSTR("Optional mode: run or session."), false},
            {OBFSTR("cleanup"), OBFSTR("string"), OBFSTR("Optional cleanup mode: keep or delete."), false},
            {OBFSTR("sandbox"), OBFSTR("string"), OBFSTR("Optional sandbox policy: inherit or require."), false}
        },
        [](const json& params) -> tool_result_t {
            subagents::spawn_request_t request;
            request.task = params.value("task", "");
            request.label = params.value("label", "");


            if (params.contains("targetInstance"))
            {
                const auto& ti = params["targetInstance"];
                if (ti.is_string())
                    request.target_instance = ti.get<std::string>();
                else if (ti.is_object())
                    request.target_instance = json_str(ti, "instanceId",
                        json_str(ti, "inputPath",
                        json_str(ti, "displayName", "")));
            }

            request.agent_id = params.value("agentId", "");
            request.model = params.value("model", "");
            request.thinking = params.value("thinking", "");
            request.run_timeout_seconds = params.value("runTimeoutSeconds", 0);
            request.thread = params.value("thread", false);
            request.mode = params.value("mode", "run");
            request.cleanup = params.value("cleanup", "keep");
            request.sandbox = params.value("sandbox", "inherit");

            if (subagents::trim_copy(request.task).empty())
                return tool_result_t::error(OBFSTR("sessions_spawn requires a non-empty task."));

            json response = subagents::spawn(request);
            sanitize_json_utf8_inplace(response);
            if (json_str(response, "status") == "error")
                return tool_result_t::error(json_str(response, "message", OBFSTR("Failed to spawn sub-agent.")));

            return tool_result_t::ok(
                OBFSTR("Sub-agent accepted: ") + json_str(response, "childSessionKey", "unknown"),
                response);
        },
        false
    });

    ToolRegistry::instance().register_tool({
        OBFSTR("sessions_list"), OBFSTR("session"),
        OBFSTR("List visible sub-agent sessions for the current requester session, including status, depth, runtime, and token estimates."),
        {},
        [](const json&) -> tool_result_t {
            json response = subagents::list_visible_sessions();
            sanitize_json_utf8_inplace(response);
            return tool_result_t::ok(
                OBFSTR("Visible sub-agent sessions: ") + std::to_string(response.is_array() ? response.size() : 0),
                response);
        },
        true
    });

    ToolRegistry::instance().register_tool({
        OBFSTR("sessions_history"), OBFSTR("session"),
        OBFSTR("Read transcript history for a visible sub-agent session. Accepts either a session key or session id."),
        {
            {OBFSTR("session"), OBFSTR("string"), OBFSTR("Target session key or session id."), true},
            {OBFSTR("limit"), OBFSTR("number"), OBFSTR("Optional maximum number of history records to return."), false}
        },
        [](const json& params) -> tool_result_t {
            const std::string session = params.value("session", "");
            const size_t limit = static_cast<size_t>(params.value("limit", 200));
            json response = subagents::get_session_history(session, limit);
            sanitize_json_utf8_inplace(response);
            if (json_str(response, "status") == "error")
                return tool_result_t::error(json_str(response, "message", OBFSTR("Unable to read session history.")));
            return tool_result_t::ok(
                OBFSTR("Loaded sub-agent history for ") + session,
                response);
        },
        true
    });

    ToolRegistry::instance().register_tool({
        OBFSTR("sessions_send"), OBFSTR("session"),
        OBFSTR("Send a steering/update message to an active visible sub-agent session. The child consumes it on the next round."),
        {
            {OBFSTR("session"), OBFSTR("string"), OBFSTR("Target session key or session id."), true},
            {OBFSTR("message"), OBFSTR("string"), OBFSTR("Message to deliver to the child session."), true}
        },
        [](const json& params) -> tool_result_t {
            json response = subagents::send_message(
                params.value("session", ""),
                params.value("message", ""),
                false);
            sanitize_json_utf8_inplace(response);
            if (json_str(response, "status") == "error")
                return tool_result_t::error(json_str(response, "message", OBFSTR("Unable to send to sub-agent session.")));
            return tool_result_t::ok(
                OBFSTR("Message accepted for sub-agent session."),
                response);
        },
        false
    });

    ToolRegistry::instance().register_tool({
        OBFSTR("subagents"), OBFSTR("session"),
        OBFSTR("Inspect or control visible sub-agent runs. Operations: overview, list, info, log, kill, send, steer, instances. If operation is omitted, AiDA returns an overview with both visible sessions and available instances."),
        {
            {OBFSTR("operation"), OBFSTR("string"), OBFSTR("Optional. One of: overview, list, info, log, kill, send, steer, instances."), false},
            {OBFSTR("id"), OBFSTR("string"), OBFSTR("Target session id/key or 'all' for kill."), false},
            {OBFSTR("message"), OBFSTR("string"), OBFSTR("Message for send/steer operations."), false},
            {OBFSTR("limit"), OBFSTR("number"), OBFSTR("Optional log/history limit for info/log."), false}
        },
        [](const json& params) -> tool_result_t {
            std::string operation = ida_utils::qstring_tolower(params.value("operation", "").c_str()).c_str();
            const std::string id = params.value("id", "");
            const std::string message = params.value("message", "");
            const size_t limit = static_cast<size_t>(params.value("limit", 100));

            if (operation == "ls")
                operation = "list";
            else if (operation == "logs")
                operation = "log";
            else if (operation == "status")
                operation = id.empty() ? "list" : "info";
            else if (operation == "instance" || operation == "targets")
                operation = "instances";
            else if (operation.empty())
                operation = "overview";

            json response;
            if (operation == "overview")
            {
                response = {
                    {"sessions", subagents::list_visible_sessions()},
                    {"instances", subagents::list_available_instances()}
                };
                sanitize_json_utf8_inplace(response);
                return tool_result_t::ok(OBFSTR("Loaded sub-agent overview."), response);
            }
            if (operation == "list")
            {
                response = subagents::list_visible_sessions();
                sanitize_json_utf8_inplace(response);
                return tool_result_t::ok(
                    OBFSTR("Visible sub-agent sessions: ") + std::to_string(response.is_array() ? response.size() : 0),
                    response);
            }
            if (operation == "instances")
            {
                response = subagents::list_available_instances();
                sanitize_json_utf8_inplace(response);
                return tool_result_t::ok(
                    OBFSTR("Available AiDA instances: ") + std::to_string(response.is_array() ? response.size() : 0),
                    response);
            }
            if (operation == "info")
                response = subagents::get_session_info(id, 0, false);
            else if (operation == "log")
                response = subagents::get_session_info(id, limit, true);
            else if (operation == "kill")
                response = (id == "all") ? subagents::kill_all_visible(true) : subagents::kill(id, true);
            else if (operation == "send")
                response = subagents::send_message(id, message, false);
            else if (operation == "steer")
                response = subagents::send_message(id, message, true);
            else
                return tool_result_t::error(OBFSTR("Unsupported subagents operation."));

            sanitize_json_utf8_inplace(response);
            if (json_str(response, "status") == "error")
                return tool_result_t::error(json_str(response, "message", OBFSTR("Sub-agent operation failed.")));

            return tool_result_t::ok(
                OBFSTR("Sub-agent operation completed: ") + operation,
                response);
        },
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
               OBFSTR("import, search, debugger, segment, binary, python, navigation, analysis, session, meta)"),
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
