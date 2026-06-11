#include "offsets.hpp"

#include "artifact_store.hpp"

#include <algorithm>
#include <fstream>
#include <set>
#include <sstream>

namespace re::offsets
{
namespace
{
std::string make_aob_for_address(std::uint32_t pid, std::uint64_t va)
{
    std::vector<std::uint8_t> bytes;
    if (!read_bytes(pid, va, 32, bytes) || bytes.size() < 8)
        return {};
    return bytes_to_hex(bytes, bytes.size());
}

std::set<std::string> selected_offset_ids(const json& params)
{
    std::set<std::string> ids;
    if (params.contains("offset_id") && params["offset_id"].is_string())
        ids.insert(params["offset_id"].get<std::string>());
    if (params.contains("offset_ids") && params["offset_ids"].is_array())
    {
        for (const auto& id : params["offset_ids"])
        {
            if (id.is_string())
                ids.insert(id.get<std::string>());
        }
    }
    return ids;
}

bool module_matches_filter(const store::offset_record_t& record, const std::string& module_filter)
{
    if (module_filter.empty())
        return true;
    const std::string module = lower_ascii(record.module_name);
    const std::string filter = lower_ascii(module_filter);
    return module == filter || module.find(filter) != std::string::npos;
}

bool record_in_scope(const store::offset_record_t& record,
                     std::uint32_t pid,
                     const std::set<std::string>& selected_ids,
                     const std::string& module_filter,
                     std::string& reason)
{
    if (!selected_ids.empty() && selected_ids.count(record.id) == 0)
    {
        reason = "offset_id_not_selected";
        return false;
    }
    if (record.pid != 0 && pid != 0 && record.pid != pid)
    {
        reason = "process_id_mismatch";
        return false;
    }
    if (!module_matches_filter(record, module_filter))
    {
        reason = "module_filter_mismatch";
        return false;
    }
    return true;
}

json reverify_one(std::uint32_t pid, store::offset_record_t& record)
{
    json out = store::offset_to_json(record);
    out["previous_va"] = sa_format_address(record.va);
    bool live_valid = false;
    if (record.va != 0)
    {
        driver_bridge::memory_region_t region{};
        live_valid = query_region(pid, record.va, region) && is_readable(region);
        if (live_valid && !record.aob_pattern.empty())
        {
            std::vector<parsed_pattern_byte_t> pattern;
            if (parse_pattern(record.aob_pattern, pattern))
            {
                std::vector<std::uint8_t> bytes;
                live_valid = read_bytes(pid, record.va, pattern.size(), bytes) &&
                    bytes.size() >= pattern.size() &&
                    pattern_matches(bytes.data(), bytes.size(), pattern);
            }
        }
    }

    if (live_valid)
    {
        record.status = "valid";
        record.last_found_va = record.va;
        record.updated_ms = unix_time_ms();
        out["verification_status"] = "valid";
        out["current_va"] = sa_format_address(record.va);
        return out;
    }

    if (!record.aob_pattern.empty())
    {
        std::vector<parsed_pattern_byte_t> pattern;
        if (parse_pattern(record.aob_pattern, pattern))
        {
            auto matches = scan_pattern(pid, pattern, record.module_name, false, 2);
            if (matches.size() == 1)
            {
                const std::uint64_t found = matches.front();
                record.status = found == record.va ? "valid" : "shifted";
                record.last_found_va = found;
                record.updated_ms = unix_time_ms();
                out["verification_status"] = record.status;
                out["current_va"] = sa_format_address(record.va);
                out["found_va"] = sa_format_address(found);
                return out;
            }
            if (matches.size() > 1)
            {
                record.status = "ambiguous";
                record.updated_ms = unix_time_ms();
                out["verification_status"] = "ambiguous";
                out["match_count"] = matches.size();
                return out;
            }
        }
    }

    record.status = "broken";
    record.updated_ms = unix_time_ms();
    out["verification_status"] = "broken";
    return out;
}

tool_result_t record_offset(const json& params)
{
    if (!unsafe_confirmed(params))
        return unsafe_required("offsets_manage record");
    active_process_scope_t scope(params);
    if (!scope.ok())
        return tool_result_t::error(scope.error());
    const std::string name = string_param(params, "name");
    if (name.empty())
        return tool_result_t::error("'name' is required for record.");
    std::uint64_t va = 0;
    if (!parse_address_param(params, "va", va) || va == 0)
        return tool_result_t::error("'va' is required for record.");

    store::offset_record_t record;
    record.id = store::next_id("off");
    record.name = name;
    record.category = string_param(params, "category");
    record.notes = string_param(params, "notes");
    record.pid = scope.pid();
    record.va = va;
    record.status = "recorded";
    record.created_ms = unix_time_ms();
    record.updated_ms = record.created_ms;
    record.aob_pattern = string_param(params, "aob_pattern");
    record.rtti_path = string_param(params, "rtti_path");
    record.xref_context = string_param(params, "xref_context");
    if (record.aob_pattern.empty())
        record.aob_pattern = make_aob_for_address(scope.pid(), va);
    if (auto module = find_module_for_address(scope.pid(), va))
    {
        record.module_name = module->name;
        record.module_rva = va - module->base;
    }

    auto records = store::load_offsets();
    records.push_back(record);
    if (!store::save_offsets(records))
        return tool_result_t::error("Failed to save offsets database.");
    json result = store::offset_to_json(record);
    result["offset_id"] = record.id;
    return tool_result_t::ok("Offset recorded.", result);
}

tool_result_t list_offsets(const json& params)
{
    const bool verified_only = bool_param(params, "verified_only", false);
    const auto records = store::load_offsets();
    json arr = json::array();
    for (const auto& record : records)
    {
        if (verified_only && record.status != "valid")
            continue;
        arr.push_back(store::offset_to_json(record));
    }
    json result;
    result["offsets"] = std::move(arr);
    result["count"] = result["offsets"].size();
    return tool_result_t::ok(result);
}

tool_result_t reverify_offsets(const json& params, bool rebase)
{
    if (!unsafe_confirmed(params))
        return unsafe_required(rebase ? "offsets_manage rebase" : "offsets_manage reverify");
    active_process_scope_t scope(params);
    if (!scope.ok())
        return tool_result_t::error(scope.error());

    auto records = store::load_offsets();
    const std::set<std::string> selected_ids = selected_offset_ids(params);
    const std::string module_filter = string_param(params, "module_name");
    json valid = json::array();
    json broken = json::array();
    json shifted = json::array();
    json ambiguous = json::array();
    json skipped = json::array();
    for (auto& record : records)
    {
        std::string skip_reason;
        if (!record_in_scope(record, scope.pid(), selected_ids, module_filter, skip_reason))
        {
            json row = store::offset_to_json(record);
            row["skip_reason"] = skip_reason;
            skipped.push_back(std::move(row));
            continue;
        }
        json row = reverify_one(scope.pid(), record);
        const std::string status = row.value("verification_status", std::string());
        if (status == "valid")
            valid.push_back(row);
        else if (status == "shifted")
        {
            if (rebase)
            {
                record.va = record.last_found_va;
                if (auto module = find_module_for_address(scope.pid(), record.va))
                {
                    record.module_name = module->name;
                    record.module_rva = record.va - module->base;
                }
                row["rebased"] = true;
                row["current_va"] = sa_format_address(record.va);
                record.status = "valid";
                valid.push_back(row);
            }
            else
            {
                shifted.push_back(row);
            }
        }
        else if (status == "ambiguous")
            ambiguous.push_back(row);
        else
            broken.push_back(row);
    }
    if (!store::save_offsets(records))
        return tool_result_t::error("Failed to save updated offsets database.");
    json result;
    result["valid"] = std::move(valid);
    result["broken"] = std::move(broken);
    result["shifted"] = std::move(shifted);
    result["ambiguous"] = std::move(ambiguous);
    result["skipped"] = std::move(skipped);
    result["rebased"] = rebase;
    result["process_id"] = scope.pid();
    if (!module_filter.empty())
        result["module_name"] = module_filter;
    return tool_result_t::ok(result);
}

tool_result_t export_offsets(const json& params)
{
    if (!unsafe_confirmed(params))
        return unsafe_required("offsets_manage export");
    const std::string output_path = string_param(params, "output_path");
    if (output_path.empty())
        return tool_result_t::error("'output_path' is required for export.");
    const std::string ns = sanitize_identifier(string_param(params, "namespace_name", "Offsets"), "Offsets");
    const bool use_rva = bool_param(params, "use_rva", false);
    const auto records = store::load_offsets();
    ensure_parent_dir_exists(output_path);
    std::ofstream f(output_path, std::ios::binary | std::ios::trunc);
    if (!f.is_open())
        return tool_result_t::error("Failed to open output_path for writing.");
    f << "#pragma once\n\n";
    f << "#include <cstdint>\n\n";
    f << "namespace " << ns << "\n";
    f << "{\n";
    for (const auto& record : records)
    {
        const std::uint64_t value = use_rva && record.module_rva != 0 ? record.module_rva : record.va;
        f << "constexpr std::uintptr_t " << sanitize_identifier(record.name, "Offset") << " = 0x"
          << std::hex << std::uppercase << value << std::dec << "ull;\n";
    }
    f << "}\n";
    json result;
    result["output_path"] = output_path;
    result["count"] = records.size();
    result["use_rva"] = use_rva;
    return tool_result_t::ok("Offsets exported.", result);
}
}

tool_result_t manage(const json& params)
{
    const std::string action = compat_action_name(params);
    const json p = compat_action_payload(params);
    if (action == "record") return record_offset(p);
    if (action == "list") return list_offsets(p);
    if (action == "reverify") return reverify_offsets(p, false);
    if (action == "rebase") return reverify_offsets(p, true);
    if (action == "export") return export_offsets(p);
    return compat_unknown_action("offsets_manage", action);
}
}
