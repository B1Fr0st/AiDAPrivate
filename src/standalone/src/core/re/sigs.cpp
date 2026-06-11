#include "sigs.hpp"

#include "artifact_store.hpp"

#include <algorithm>
#include <fstream>
#include <sstream>

namespace re::sigs
{
namespace
{
std::int64_t signed_param(const json& params, const char* key, std::int64_t fallback, std::int64_t min_value, std::int64_t max_value)
{
    std::int64_t value = fallback;
    if (params.contains(key))
    {
        const auto& v = params[key];
        if (v.is_number_integer())
            value = v.get<std::int64_t>();
        else if (v.is_number_unsigned())
            value = static_cast<std::int64_t>(std::min<std::uint64_t>(v.get<std::uint64_t>(), static_cast<std::uint64_t>(max_value)));
        else if (v.is_string())
        {
            try
            {
                value = std::stoll(trim_ascii(v.get<std::string>()), nullptr, 0);
            }
            catch (...)
            {
                value = fallback;
            }
        }
    }
    if (value < min_value)
        value = min_value;
    if (value > max_value)
        value = max_value;
    return value;
}

std::string normalize_format(std::string format)
{
    format = lower_ascii(trim_ascii(format.empty() ? "json" : format));
    if (format == "cheatengine" || format == "cheat_engine")
        return "ce";
    if (format == "idc" || format == "pat")
        return "ida";
    if (format == "x64dbg-pattern" || format == "x64dbg_patterns")
        return "x64dbg";
    return format;
}

bool supported_format(const std::string& format)
{
    return format == "json" || format == "ida" || format == "x64dbg" || format == "ce";
}

std::vector<std::string> split_csv(std::string value)
{
    std::vector<std::string> out;
    std::size_t start = 0;
    for (std::size_t i = 0; i <= value.size(); ++i)
    {
        if (i == value.size() || value[i] == ',')
        {
            out.push_back(trim_ascii(value.substr(start, i - start)));
            start = i + 1;
        }
    }
    return out;
}

std::string strip_line(std::string line)
{
    line = trim_ascii(line);
    if (line.empty())
        return {};
    if (line.rfind("//", 0) == 0 || line[0] == ';' || line[0] == '#')
        return {};
    return line;
}

bool append_signature(std::vector<store::signature_record_t>& records,
                      const std::string& raw_name,
                      const std::string& pattern,
                      const std::string& module_hint,
                      const json& params)
{
    std::vector<parsed_pattern_byte_t> parsed;
    if (!parse_pattern(pattern, parsed))
        return false;
    store::signature_record_t sig;
    sig.id = store::next_id("sig");
    sig.name = sanitize_identifier(raw_name.empty() ? "sig_" + std::to_string(records.size() + 1) : raw_name, "Signature");
    sig.pattern = pattern;
    sig.module_hint = module_hint.empty() ? string_param(params, "module_hint") : module_hint;
    sig.category = string_param(params, "category");
    sig.notes = string_param(params, "notes");
    sig.offset_from_match = signed_param(params, "offset_from_match", 0, -0x7FFFFFFFLL, 0x7FFFFFFFLL);
    sig.created_ms = unix_time_ms();
    sig.updated_ms = sig.created_ms;
    sig.last_status = "new";
    records.push_back(std::move(sig));
    return true;
}

bool parse_ce_line(const std::string& line, std::vector<store::signature_record_t>& records, const json& params)
{
    const std::string lower = lower_ascii(line);
    const std::size_t fn = lower.find("aobscan");
    if (fn == std::string::npos)
        return false;
    const std::size_t open = line.find('(', fn);
    const std::size_t close = line.rfind(')');
    if (open == std::string::npos || close == std::string::npos || close <= open + 1)
        return false;
    const auto args = split_csv(line.substr(open + 1, close - open - 1));
    if (lower.find("aobscanmodule", fn) != std::string::npos)
    {
        if (args.size() < 3)
            return false;
        return append_signature(records, args[0], args[2], args[1], params);
    }
    if (args.size() < 2)
        return false;
    return append_signature(records, args[0], args[1], {}, params);
}

bool parse_text_pattern_line(const std::string& line,
                             const std::string& format,
                             std::vector<store::signature_record_t>& records,
                             const json& params)
{
    std::string name;
    std::string pattern;
    const std::size_t quote_a = line.find('"');
    const std::size_t quote_b = quote_a == std::string::npos ? std::string::npos : line.find('"', quote_a + 1);
    if (quote_a != std::string::npos && quote_b != std::string::npos)
    {
        name = trim_ascii(line.substr(0, quote_a));
        pattern = trim_ascii(line.substr(quote_a + 1, quote_b - quote_a - 1));
    }
    else
    {
        const std::size_t eq = line.find('=');
        const std::size_t colon = line.find(':');
        const std::size_t sep = eq == std::string::npos ? colon : (colon == std::string::npos ? eq : std::min(eq, colon));
        if (sep != std::string::npos)
        {
            name = trim_ascii(line.substr(0, sep));
            pattern = trim_ascii(line.substr(sep + 1));
        }
        else if (format == "x64dbg")
        {
            const std::size_t space = line.find(' ');
            if (space != std::string::npos && lower_ascii(line.substr(0, space)).find("find") != std::string::npos)
                pattern = trim_ascii(line.substr(space + 1));
            else
                pattern = line;
        }
        else
        {
            pattern = line;
        }
    }
    return append_signature(records, name, pattern, {}, params);
}

json scan_signature(std::uint32_t pid, store::signature_record_t& sig)
{
    json out = store::signature_to_json(sig);
    std::vector<parsed_pattern_byte_t> pattern;
    std::string err;
    if (!parse_pattern(sig.pattern, pattern, &err))
    {
        sig.last_status = "invalid";
        sig.last_match_count = 0;
        out["status"] = "invalid";
        out["error"] = err;
        return out;
    }
    auto matches = scan_pattern(pid, pattern, sig.module_hint, false, 128);
    sig.last_match_count = static_cast<std::uint32_t>(matches.size());
    if (matches.empty())
        sig.last_va = 0;
    else if (sig.offset_from_match < 0 && matches.front() < static_cast<std::uint64_t>(-sig.offset_from_match))
        sig.last_va = 0;
    else
        sig.last_va = sig.offset_from_match < 0
            ? matches.front() - static_cast<std::uint64_t>(-sig.offset_from_match)
            : matches.front() + static_cast<std::uint64_t>(sig.offset_from_match);
    if (matches.empty())
        sig.last_status = "not_found";
    else if (matches.size() == 1)
        sig.last_status = "found";
    else
        sig.last_status = "multiple";
    sig.updated_ms = unix_time_ms();
    out = store::signature_to_json(sig);
    out["status"] = sig.last_status;
    out["match_count"] = sig.last_match_count;
    out["va"] = sig.last_va ? json(sa_format_address(sig.last_va)) : json(nullptr);
    json match_arr = json::array();
    for (auto va : matches)
    {
        std::uint64_t adjusted = 0;
        if (sig.offset_from_match < 0)
        {
            if (va >= static_cast<std::uint64_t>(-sig.offset_from_match))
                adjusted = va - static_cast<std::uint64_t>(-sig.offset_from_match);
        }
        else
        {
            adjusted = va + static_cast<std::uint64_t>(sig.offset_from_match);
        }
        match_arr.push_back(adjusted ? json(sa_format_address(adjusted)) : json(nullptr));
    }
    out["matches"] = std::move(match_arr);
    return out;
}

tool_result_t save_signature(const json& params)
{
    if (!unsafe_confirmed(params))
        return unsafe_required("sigs_manage save");
    const std::string name = string_param(params, "name");
    const std::string pattern = string_param(params, "pattern");
    if (name.empty())
        return tool_result_t::error("'name' is required for save.");
    if (pattern.empty())
        return tool_result_t::error("'pattern' is required for save.");
    std::vector<parsed_pattern_byte_t> parsed;
    std::string err;
    if (!parse_pattern(pattern, parsed, &err))
        return tool_result_t::error("Invalid pattern: " + err);

    store::signature_record_t sig;
    sig.id = store::next_id("sig");
    sig.name = name;
    sig.pattern = pattern;
    sig.module_hint = string_param(params, "module_hint");
    sig.category = string_param(params, "category");
    sig.notes = string_param(params, "notes");
    sig.offset_from_match = signed_param(params, "offset_from_match", 0, -0x7FFFFFFFLL, 0x7FFFFFFFLL);
    sig.created_ms = unix_time_ms();
    sig.updated_ms = sig.created_ms;
    sig.last_status = "new";
    auto records = store::load_signatures();
    records.push_back(sig);
    if (!store::save_signatures(records))
        return tool_result_t::error("Failed to save signature database.");
    json result = store::signature_to_json(sig);
    return tool_result_t::ok("Signature saved.", result);
}

tool_result_t list_signatures(const json& params)
{
    const std::string category = lower_ascii(string_param(params, "category"));
    const std::string module_hint = lower_ascii(string_param(params, "module_hint"));
    json arr = json::array();
    for (const auto& sig : store::load_signatures())
    {
        if (!category.empty() && lower_ascii(sig.category) != category)
            continue;
        if (!module_hint.empty() && lower_ascii(sig.module_hint).find(module_hint) == std::string::npos)
            continue;
        arr.push_back(store::signature_to_json(sig));
    }
    json result;
    result["signatures"] = std::move(arr);
    result["count"] = result["signatures"].size();
    return tool_result_t::ok(result);
}

tool_result_t scan_all(const json& params)
{
    if (!unsafe_confirmed(params))
        return unsafe_required("sigs_manage scan_all");
    active_process_scope_t scope(params);
    if (!scope.ok())
        return tool_result_t::error(scope.error());
    auto records = store::load_signatures();
    json arr = json::array();
    for (auto& sig : records)
        arr.push_back(scan_signature(scope.pid(), sig));
    store::save_signatures(records);
    json result;
    result["process_id"] = scope.pid();
    result["results"] = std::move(arr);
    result["count"] = result["results"].size();
    return tool_result_t::ok(result);
}

void import_json_array(const json& arr, std::vector<store::signature_record_t>& records)
{
    for (const auto& item : arr)
    {
        store::signature_record_t sig = store::signature_from_json(item);
        if (sig.id.empty())
            sig.id = store::next_id("sig");
        if (sig.name.empty())
            sig.name = "sig_" + std::to_string(records.size() + 1);
        if (sig.pattern.empty())
            continue;
        std::vector<parsed_pattern_byte_t> parsed;
        if (!parse_pattern(sig.pattern, parsed))
            continue;
        if (sig.created_ms == 0)
            sig.created_ms = unix_time_ms();
        sig.updated_ms = unix_time_ms();
        records.push_back(std::move(sig));
    }
}

tool_result_t import_signatures(const json& params)
{
    if (!unsafe_confirmed(params))
        return unsafe_required("sigs_manage import");
    const std::string source = string_param(params, "source");
    if (source.empty())
        return tool_result_t::error("'source' is required for import.");
    std::string content = source;
    std::ifstream file(source, std::ios::binary);
    if (file.is_open())
    {
        std::ostringstream ss;
        ss << file.rdbuf();
        content = ss.str();
    }
    const std::string format = normalize_format(string_param(params, "format", "json"));
    if (!supported_format(format))
        return tool_result_t::error("Unsupported signature import format. Supported formats: json, ida, x64dbg, ce.");
    auto records = store::load_signatures();
    const std::size_t before = records.size();
    if (format == "json")
    {
        try
        {
            json root = json::parse(content);
            if (root.is_array())
                import_json_array(root, records);
            else if (root.contains("signatures") && root["signatures"].is_array())
                import_json_array(root["signatures"], records);
            else
                return tool_result_t::error("JSON import must be an array or contain signatures[].");
        }
        catch (...)
        {
            return tool_result_t::error("Failed to parse JSON signature import.");
        }
    }
    else
    {
        std::istringstream input(content);
        std::string line;
        while (std::getline(input, line))
        {
            line = strip_line(line);
            if (line.empty())
                continue;
            if (format == "ce")
                parse_ce_line(line, records, params);
            else
                parse_text_pattern_line(line, format, records, params);
        }
    }
    if (records.size() == before)
        return tool_result_t::error("No valid signatures were imported for the selected format.");
    if (!store::save_signatures(records))
        return tool_result_t::error("Failed to save imported signatures.");
    json result;
    result["imported"] = records.size() - before;
    result["total"] = records.size();
    return tool_result_t::ok("Signatures imported.", result);
}

tool_result_t export_signatures(const json& params)
{
    if (!unsafe_confirmed(params))
        return unsafe_required("sigs_manage export");
    const std::string output_path = string_param(params, "output_path");
    if (output_path.empty())
        return tool_result_t::error("'output_path' is required for export.");
    const std::string format = normalize_format(string_param(params, "format", "json"));
    if (!supported_format(format))
        return tool_result_t::error("Unsupported signature export format. Supported formats: json, ida, x64dbg, ce.");
    const std::string category = lower_ascii(string_param(params, "category"));
    auto records = store::load_signatures();
    std::vector<store::signature_record_t> filtered;
    for (const auto& sig : records)
    {
        if (!category.empty() && lower_ascii(sig.category) != category)
            continue;
        filtered.push_back(sig);
    }
    ensure_parent_dir_exists(output_path);
    std::ofstream f(output_path, std::ios::binary | std::ios::trunc);
    if (!f.is_open())
        return tool_result_t::error("Failed to open output_path for writing.");
    if (format == "json")
    {
        json root;
        root["version"] = 1;
        root["signatures"] = json::array();
        for (const auto& sig : filtered)
            root["signatures"].push_back(store::signature_to_json(sig));
        f << root.dump(2);
    }
    else if (format == "ida")
    {
        for (const auto& sig : filtered)
            f << sig.name << " = " << sig.pattern << "\n";
    }
    else if (format == "x64dbg")
    {
        for (const auto& sig : filtered)
            f << sig.name << ": " << sig.pattern << "\n";
    }
    else if (format == "ce")
    {
        for (const auto& sig : filtered)
        {
            if (!sig.module_hint.empty())
                f << "aobscanmodule(" << sig.name << "," << sig.module_hint << "," << sig.pattern << ")\n";
            else
                f << "aobscan(" << sig.name << "," << sig.pattern << ")\n";
        }
    }
    json result;
    result["output_path"] = output_path;
    result["format"] = format;
    result["count"] = filtered.size();
    return tool_result_t::ok("Signatures exported.", result);
}
}

tool_result_t manage(const json& params)
{
    const std::string action = compat_action_name(params);
    const json p = compat_action_payload(params);
    if (action == "save") return save_signature(p);
    if (action == "list") return list_signatures(p);
    if (action == "scan_all") return scan_all(p);
    if (action == "import") return import_signatures(p);
    if (action == "export") return export_signatures(p);
    return compat_unknown_action("sigs_manage", action);
}
}
