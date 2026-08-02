#include "sigs.hpp"

#include "artifact_store.hpp"
#include "../../helpers/diag_log.hpp"

#include "../analysis/flirt/flirt_engine.hpp"
#include "../analysis/flirt/flirt_signature_db.hpp"
#include "../analysis/flirt/static_recognition_service.hpp"
#include "../analysis/workspace/analysis_workspace.hpp"
#include "../analysis/workspace/workspace_registry.hpp"
#include "../infra/cancellation_watchdog.hpp"

#include <algorithm>
#include <atomic>
#include <chrono>
#include <fstream>
#include <sstream>

namespace re::sigs
{
namespace
{
std::uint64_t deadline_remaining_ms()
{
    const std::uint64_t deadline = mcp_standalone::current_call_deadline_ms();
    if (deadline == 0)
        return 0;
    const std::uint64_t now = GetTickCount64();
    return deadline > now ? deadline - now : 0;
}

bool sigs_call_cancelled(const char* phase, std::uint32_t pid, std::uint64_t started_ms)
{
    if (mcp_standalone::current_call_cancelled())
    {
        diag::log_tagged_fmt("sigs", "cancelled phase=%s pid=%u elapsed_ms=%llu diag_id=%s",
                             phase ? phase : "",
                             pid,
                             static_cast<unsigned long long>(GetTickCount64() - started_ms),
                             mcp_standalone::current_call_diag_id());
        return true;
    }
    const std::uint64_t deadline = mcp_standalone::current_call_deadline_ms();
    if (deadline != 0 && GetTickCount64() >= deadline)
    {
        diag::log_tagged_fmt("sigs", "deadline_reached phase=%s pid=%u elapsed_ms=%llu diag_id=%s",
                             phase ? phase : "",
                             pid,
                             static_cast<unsigned long long>(GetTickCount64() - started_ms),
                             mcp_standalone::current_call_diag_id());
        return true;
    }
    return false;
}

json sigs_cancel_detail(const char* action, std::uint32_t pid, std::uint64_t started_ms)
{
    return json{
        {"action", action ? action : ""},
        {"process_id", pid},
        {"elapsed_ms", GetTickCount64() - started_ms},
        {"deadline_remaining_ms", deadline_remaining_ms()},
        {"cancelled", mcp_standalone::current_call_cancelled()},
        {"diag_id", mcp_standalone::current_call_diag_id()}
    };
}

json sigs_guard_payload(const char* action, const json& params, std::uint64_t started_ms)
{
    json out;
    out["tool"] = "sigs_manage";
    out["action"] = action ? action : "";
    out["confirm_unsafe_required"] = true;
    out["confirm_unsafe_received"] = unsafe_confirmed(params);
    out["mutation"] = "none";
    out["persistence_mutation"] = false;
    out["file_write"] = false;
    out["security_guard_pass"] = true;
    out["safe_contract"] = "fail_closed_until_explicit_unsafe_confirmation";
    out["elapsed_ms"] = GetTickCount64() - started_ms;
    if (params.contains("name"))
        out["name"] = params["name"];
    if (params.contains("source"))
        out["source_present"] = true;
    if (params.contains("output_path"))
        out["output_path_present"] = true;
    return out;
}

tool_result_t sigs_guard_required(const char* action, const json& params, std::uint64_t started_ms)
{
    return tool_result_t::error(std::string(action ? action : "sigs_manage") + " requires confirm_unsafe=true or allow_unsafe=true.", sigs_guard_payload(action, params, started_ms));
}

struct sig_scan_stats_t
{
    std::uint64_t bytes_read = 0;
    std::uint64_t scan_bytes_requested = 0;
    std::size_t regions_scanned = 0;
    bool cancelled = false;
    bool deadline_hit = false;
};

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

std::vector<std::uint64_t> scan_pattern_range(std::uint32_t pid,
                                              const std::vector<parsed_pattern_byte_t>& pattern,
                                              std::uint64_t start,
                                              std::uint64_t size,
                                              std::size_t max_results,
                                              std::uint64_t started_ms,
                                              sig_scan_stats_t* stats)
{
    std::vector<std::uint64_t> results;
    if (stats)
        stats->scan_bytes_requested = size;
    if (pattern.empty() || start == 0 || size < pattern.size() || max_results == 0)
        return results;
    driver_bridge::memory_region_t region{};
    if (!query_region(pid, start, region) || !is_readable(region))
        return results;
    const std::uint64_t region_end = region.base + region.size;
    if (region_end <= start)
        return results;
    const std::uint64_t read_size64 = std::min<std::uint64_t>(size, region_end - start);
    if (read_size64 < pattern.size() || read_size64 > 64ull * 1024ull * 1024ull)
        return results;
    std::vector<std::uint8_t> bytes;
    if (!read_bytes(pid, start, static_cast<std::size_t>(read_size64), bytes) || bytes.size() < pattern.size())
        return results;
    if (stats)
    {
        stats->bytes_read = bytes.size();
        stats->regions_scanned = 1;
    }
    for (std::size_t i = 0; i + pattern.size() <= bytes.size(); ++i)
    {
        if ((i & 0xFFFu) == 0 && sigs_call_cancelled("scan_pattern_range", pid, started_ms))
        {
            if (stats)
            {
                stats->cancelled = mcp_standalone::current_call_cancelled();
                stats->deadline_hit = !stats->cancelled;
            }
            break;
        }
        if (!pattern_matches(bytes.data() + i, bytes.size() - i, pattern))
            continue;
        results.push_back(start + i);
        if (results.size() >= max_results)
            break;
    }
    return results;
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

json scan_signature(std::uint32_t pid, store::signature_record_t& sig, const json* params = nullptr)
{
    const std::uint64_t started_ms = GetTickCount64();
    json out = store::signature_to_json(sig);
    std::vector<parsed_pattern_byte_t> pattern;
    std::string err;
    if (!parse_pattern(sig.pattern, pattern, &err))
    {
        sig.last_status = "invalid";
        sig.last_match_count = 0;
        out["status"] = "invalid";
        out["error"] = err;
        out["elapsed_ms"] = GetTickCount64() - started_ms;
        diag::log_tagged_fmt("sigs",
                             "scan_signature pid=%u id=%s status=invalid error=%s elapsed_ms=%llu",
                             pid,
                             sig.id.c_str(),
                             err.c_str(),
                             static_cast<unsigned long long>(GetTickCount64() - started_ms));
        return out;
    }
    std::uint64_t scan_start = 0;
    std::uint64_t scan_size = 0;
    std::uint64_t scan_end = 0;
    if (params && (parse_address_param(*params, "scan_start_va", scan_start) || parse_address_param(*params, "start_va", scan_start) || parse_address_param(*params, "base_va", scan_start)))
    {
        if (!parse_address_param(*params, "scan_size", scan_size) && !parse_address_param(*params, "size", scan_size))
        {
            if (parse_address_param(*params, "scan_end_va", scan_end) || parse_address_param(*params, "end_va", scan_end))
                scan_size = scan_end > scan_start ? scan_end - scan_start : 0;
        }
    }
    sig_scan_stats_t scan_stats;
    auto matches = scan_start != 0 && scan_size != 0
        ? scan_pattern_range(pid, pattern, scan_start, scan_size, 128, started_ms, &scan_stats)
        : scan_pattern(pid, pattern, sig.module_hint, false, 128);
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
    if (scan_start != 0 && scan_size != 0)
    {
        out["scan_scope"] = {
            {"base_va", sa_format_address(scan_start)},
            {"size", scan_size},
            {"bounded", true}
        };
    }
    out["pattern_bytes"] = pattern.size();
    out["bounded_scan"] = scan_start != 0 && scan_size != 0;
    out["scan_bytes_requested"] = scan_stats.scan_bytes_requested;
    out["scan_bytes"] = scan_stats.bytes_read;
    out["regions_scanned"] = scan_stats.regions_scanned;
    out["deadline_hit"] = scan_stats.deadline_hit;
    out["cancelled"] = scan_stats.cancelled;
    out["elapsed_ms"] = GetTickCount64() - started_ms;
    diag::log_tagged_fmt("sigs",
                         "scan_signature pid=%u id=%s name=%s module_hint=%s pattern_bytes=%zu matches=%zu status=%s bounded=%d elapsed_ms=%llu",
                         pid,
                         sig.id.c_str(),
                         sig.name.c_str(),
                         sig.module_hint.c_str(),
                         pattern.size(),
                         matches.size(),
                         sig.last_status.c_str(),
                         scan_start != 0 && scan_size != 0 ? 1 : 0,
                         static_cast<unsigned long long>(GetTickCount64() - started_ms));
    return out;
}

tool_result_t save_signature(const json& params)
{
    const std::uint64_t started_ms = GetTickCount64();
    if (!unsafe_confirmed(params))
        return sigs_guard_required("save", params, started_ms);
    const std::string name = string_param(params, "name");
    const std::string pattern = string_param(params, "pattern");
    if (name.empty())
        return tool_result_t::error("'name' is required for save.");
    if (pattern.empty())
        return tool_result_t::error("'pattern' is required for save.");
    diag::log_tagged_fmt("sigs",
                         "save enter name=%s pattern_len=%zu module_hint=%s deadline_remaining_ms=%llu diag_id=%s",
                         name.c_str(),
                         pattern.size(),
                         string_param(params, "module_hint").c_str(),
                         static_cast<unsigned long long>(deadline_remaining_ms()),
                         mcp_standalone::current_call_diag_id());
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
    const std::size_t before_count = records.size();
    records.push_back(sig);
    const bool save_ok = store::save_signatures(records);
    diag::log_tagged_fmt("sigs",
                         "save store id=%s before=%zu after=%zu save_ok=%d elapsed_ms=%llu",
                         sig.id.c_str(),
                         before_count,
                         records.size(),
                         save_ok ? 1 : 0,
                         static_cast<unsigned long long>(GetTickCount64() - started_ms));
    if (!save_ok)
        return tool_result_t::error("Failed to save signature database.");
    json result = store::signature_to_json(sig);
    result["source_count_before"] = before_count;
    result["source_count_after"] = records.size();
    result["elapsed_ms"] = GetTickCount64() - started_ms;
    return tool_result_t::ok("Signature saved.", result);
}

tool_result_t list_signatures(const json& params)
{
    const std::uint64_t started_ms = GetTickCount64();
    const std::string category = lower_ascii(string_param(params, "category"));
    const std::string module_hint = lower_ascii(string_param(params, "module_hint"));
    json arr = json::array();
    const auto records = store::load_signatures();
    for (const auto& sig : records)
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
    result["source_count"] = records.size();
    result["elapsed_ms"] = GetTickCount64() - started_ms;
    diag::log_tagged_fmt("sigs",
                         "list exit source_count=%zu returned=%zu category=%s module_hint=%s elapsed_ms=%llu",
                         records.size(),
                         result["count"].get<std::size_t>(),
                         category.c_str(),
                         module_hint.c_str(),
                         static_cast<unsigned long long>(GetTickCount64() - started_ms));
    return tool_result_t::ok(result);
}

tool_result_t scan_all(const json& params)
{
    const std::uint64_t started_ms = GetTickCount64();
    if (!unsafe_confirmed(params))
        return sigs_guard_required("scan_all", params, started_ms);
    active_process_scope_t scope(params);
    if (!scope.ok())
        return tool_result_t::error(scope.error());
    auto records = store::load_signatures();
    diag::log_tagged_fmt("sigs",
                         "scan_all enter pid=%u records=%zu deadline_remaining_ms=%llu diag_id=%s",
                         scope.pid(),
                         records.size(),
                         static_cast<unsigned long long>(deadline_remaining_ms()),
                         mcp_standalone::current_call_diag_id());
    json arr = json::array();
    std::size_t scanned = 0;
    for (auto& sig : records)
    {
        if ((scanned & 0x03u) == 0 && sigs_call_cancelled("scan_all_loop", scope.pid(), started_ms))
            return tool_result_t::error("Signature scan cancelled.", sigs_cancel_detail("scan_all", scope.pid(), started_ms));
        arr.push_back(scan_signature(scope.pid(), sig, &params));
        ++scanned;
        if (sigs_call_cancelled("scan_all_after_signature", scope.pid(), started_ms))
        {
            json partial;
            partial["process_id"] = scope.pid();
            partial["results"] = arr;
            partial["count"] = arr.size();
            partial["source_count"] = records.size();
            partial["scanned"] = scanned;
            partial["elapsed_ms"] = GetTickCount64() - started_ms;
            const bool cancelled = mcp_standalone::current_call_cancelled();
            partial["cancelled"] = cancelled;
            partial["deadline_hit"] = !cancelled;
            partial["partial"] = true;
            return tool_result_t::error(cancelled ? "Signature scan cancelled." : "Signature scan deadline reached before all signatures completed.", partial);
        }
    }
    if (sigs_call_cancelled("scan_all_before_save", scope.pid(), started_ms))
    {
        json partial;
        partial["process_id"] = scope.pid();
        partial["results"] = arr;
        partial["count"] = arr.size();
        partial["source_count"] = records.size();
        partial["scanned"] = scanned;
        partial["elapsed_ms"] = GetTickCount64() - started_ms;
        const bool cancelled = mcp_standalone::current_call_cancelled();
        partial["cancelled"] = cancelled;
        partial["deadline_hit"] = !cancelled;
        partial["partial"] = true;
        return tool_result_t::error(cancelled ? "Signature scan cancelled before results were saved." : "Signature scan deadline reached before results were saved.", partial);
    }
    const bool save_ok = store::save_signatures(records);
    diag::log_tagged_fmt("sigs",
                         "scan_all store pid=%u scanned=%zu save_ok=%d elapsed_ms=%llu",
                         scope.pid(),
                         scanned,
                         save_ok ? 1 : 0,
                         static_cast<unsigned long long>(GetTickCount64() - started_ms));
    json result;
    result["process_id"] = scope.pid();
    result["results"] = std::move(arr);
    result["count"] = result["results"].size();
    result["source_count"] = records.size();
    result["save_ok"] = save_ok;
    result["elapsed_ms"] = GetTickCount64() - started_ms;
    if (!save_ok)
        return tool_result_t::error("Failed to save signature scan results.", result);
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
    const std::uint64_t started_ms = GetTickCount64();
    if (!unsafe_confirmed(params))
        return sigs_guard_required("import", params, started_ms);
    const std::string source = string_param(params, "source");
    if (source.empty())
        return tool_result_t::error("'source' is required for import.");
    std::string content = source;
    std::ifstream file(source, std::ios::binary);
    bool source_was_file = false;
    if (file.is_open())
    {
        std::ostringstream ss;
        ss << file.rdbuf();
        content = ss.str();
        source_was_file = true;
    }
    const std::string format = normalize_format(string_param(params, "format", "json"));
    if (!supported_format(format))
        return tool_result_t::error("Unsupported signature import format. Supported formats: json, ida, x64dbg, ce.");
    auto records = store::load_signatures();
    const std::size_t before = records.size();
    diag::log_tagged_fmt("sigs",
                         "import enter source_is_file=%d source_len=%zu content_len=%zu format=%s before=%zu deadline_remaining_ms=%llu diag_id=%s",
                         source_was_file ? 1 : 0,
                         source.size(),
                         content.size(),
                         format.c_str(),
                         before,
                         static_cast<unsigned long long>(deadline_remaining_ms()),
                         mcp_standalone::current_call_diag_id());
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
        std::size_t parsed_lines = 0;
        while (std::getline(input, line))
        {
            if ((parsed_lines & 0xFFu) == 0 && sigs_call_cancelled("import_parse_loop", 0, started_ms))
                return tool_result_t::error("Signature import cancelled.", sigs_cancel_detail("import", 0, started_ms));
            line = strip_line(line);
            if (line.empty())
                continue;
            if (format == "ce")
                parse_ce_line(line, records, params);
            else
                parse_text_pattern_line(line, format, records, params);
            ++parsed_lines;
        }
        diag::log_tagged_fmt("sigs",
                             "import parsed_text format=%s lines=%zu added=%zu elapsed_ms=%llu",
                             format.c_str(),
                             parsed_lines,
                             records.size() - before,
                             static_cast<unsigned long long>(GetTickCount64() - started_ms));
    }
    if (records.size() == before)
        return tool_result_t::error("No valid signatures were imported for the selected format.");
    const bool save_ok = store::save_signatures(records);
    diag::log_tagged_fmt("sigs",
                         "import store format=%s before=%zu after=%zu imported=%zu save_ok=%d elapsed_ms=%llu",
                         format.c_str(),
                         before,
                         records.size(),
                         records.size() - before,
                         save_ok ? 1 : 0,
                         static_cast<unsigned long long>(GetTickCount64() - started_ms));
    if (!save_ok)
        return tool_result_t::error("Failed to save imported signatures.");
    json result;
    result["imported"] = records.size() - before;
    result["total"] = records.size();
    result["format"] = format;
    result["source_was_file"] = source_was_file;
    result["content_bytes"] = content.size();
    result["elapsed_ms"] = GetTickCount64() - started_ms;
    return tool_result_t::ok("Signatures imported.", result);
}

tool_result_t export_signatures(const json& params)
{
    const std::uint64_t started_ms = GetTickCount64();
    if (!unsafe_confirmed(params))
        return sigs_guard_required("export", params, started_ms);
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
    diag::log_tagged_fmt("sigs",
                         "export enter output_path=%s format=%s source_count=%zu filtered=%zu category=%s deadline_remaining_ms=%llu diag_id=%s",
                         output_path.c_str(),
                         format.c_str(),
                         records.size(),
                         filtered.size(),
                         category.c_str(),
                         static_cast<unsigned long long>(deadline_remaining_ms()),
                         mcp_standalone::current_call_diag_id());
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
    f.flush();
    const std::streamoff bytes_written = f.tellp();
    json result;
    result["output_path"] = output_path;
    result["format"] = format;
    result["count"] = filtered.size();
    result["source_count"] = records.size();
    result["bytes_written"] = bytes_written >= 0 ? static_cast<std::uint64_t>(bytes_written) : 0;
    result["elapsed_ms"] = GetTickCount64() - started_ms;
    diag::log_tagged_fmt("sigs",
                         "export exit output_path=%s format=%s count=%zu bytes=%llu elapsed_ms=%llu",
                         output_path.c_str(),
                         format.c_str(),
                         filtered.size(),
                         static_cast<unsigned long long>(result["bytes_written"].get<std::uint64_t>()),
                         static_cast<unsigned long long>(GetTickCount64() - started_ms));
    return tool_result_t::ok("Signatures exported.", result);
}
struct static_section_view_t
{
    std::uint64_t virtual_address = 0;
    std::uint64_t virtual_size = 0;
    std::uint64_t file_offset = 0;
    std::uint64_t file_size = 0;
    std::uint32_t permissions = 0;
};

const static_section_view_t* static_find_section(const std::vector<static_section_view_t>& sections,
                                                 std::uint64_t rva)
{
    std::size_t lo = 0;
    std::size_t hi = sections.size();
    while (lo < hi)
    {
        const std::size_t mid = (lo + hi) / 2;
        if (sections[mid].virtual_address <= rva)
            lo = mid + 1;
        else
            hi = mid;
    }
    if (lo == 0)
        return nullptr;
    const static_section_view_t& section = sections[lo - 1];
    if (rva < section.virtual_address || rva - section.virtual_address >= section.virtual_size)
        return nullptr;
    return &section;
}

std::vector<static_section_view_t> static_sections_for(const aida::analysis::workspace_image_t& image)
{
    std::vector<static_section_view_t> sections;
    sections.reserve(image.sections.size());
    for (const auto& section : image.sections)
    {
        if (section.virtual_size == 0 || section.file_size == 0)
            continue;
        static_section_view_t view;
        view.virtual_address = section.virtual_address;
        view.virtual_size = section.virtual_size;
        view.file_offset = section.file_offset;
        view.file_size = section.file_size;
        view.permissions = section.permissions;
        sections.push_back(view);
    }
    std::sort(sections.begin(), sections.end(), [](const auto& lhs, const auto& rhs) {
        return lhs.virtual_address < rhs.virtual_address;
    });
    return sections;
}

tool_result_t scan_static(const json& params)
{
    const std::uint64_t started_ms = GetTickCount64();
    if (!unsafe_confirmed(params))
        return sigs_guard_required("scan_static", params, started_ms);
    using aida::analysis::workspace_registry;
    std::shared_ptr<aida::analysis::analysis_workspace_t> workspace;
    const std::string binary_id_text = lower_ascii(trim_ascii(string_param(params, "binary_id")));
    if (!binary_id_text.empty())
    {
        const auto id = aida::analysis::binary_id_t::from_hex(binary_id_text);
        if (!id)
            return tool_result_t::error("'binary_id' is not a valid 64-hex binary id.");
        workspace = workspace_registry().find_by_binary_id(*id);
    }
    else
    {
        const std::string target = trim_ascii(string_param(params, "target"));
        if (!target.empty())
        {
            auto exact = workspace_registry().find_by_exact_name_or_path(target);
            if (exact.size() == 1)
            {
                workspace = exact.front();
            }
            else
            {
                const std::string wanted = lower_ascii(target);
                for (const auto& candidate : workspace_registry().list())
                {
                    const auto& identity = candidate->identity();
                    const std::string name = lower_ascii(identity.bin_name());
                    const std::string path = lower_ascii(identity.normalized_source_path());
                    if ((!name.empty() && name.find(wanted) != std::string::npos) ||
                        (!path.empty() && path.find(wanted) != std::string::npos))
                    {
                        if (workspace)
                            return tool_result_t::error("'target' matched multiple workspaces.");
                        workspace = candidate;
                    }
                }
            }
        }
        else
        {
            workspace = workspace_registry().selected_for_ui();
        }
    }
    if (!workspace)
        return tool_result_t::error("scan_static could not resolve a workspace.");
    if (workspace->target_kind() != aida::analysis::target_kind_t::static_file)
        return tool_result_t::error("scan_static requires a static-file workspace.");
    const auto snapshot = workspace->snapshot();
    const auto image = workspace->normalized_image();
    const auto provider = workspace->provider_handle();
    if (!snapshot || !image || !provider)
        return tool_result_t::error("scan_static requires a published baseline snapshot.");
    aida::analysis::static_recognition::ensure_attached(workspace);
    const std::uint64_t max_results = numeric_param(params, "max_results", 128, 1, 65536);
    std::string mode = lower_ascii(trim_ascii(string_param(params, "mode", "functions")));
    if (mode != "sections")
        mode = "functions";
    diag::log_tagged_fmt("sigs",
                         "scan_static enter generation=%llu mode=%s max_results=%llu deadline_remaining_ms=%llu diag_id=%s",
                         static_cast<unsigned long long>(snapshot->generation),
                         mode.c_str(),
                         static_cast<unsigned long long>(max_results),
                         static_cast<unsigned long long>(deadline_remaining_ms()),
                         mcp_standalone::current_call_diag_id());
    const auto sections = static_sections_for(*image);
    json out;
    out["workspace"] = workspace->identity().bin_name();
    out["binary_id"] = snapshot->binary_id.to_hex();
    out["generation"] = snapshot->generation;
    out["mode"] = mode;
    out["function_count"] = snapshot->functions.size();

    const std::string source = lower_ascii(trim_ascii(string_param(params, "source")));
    if (source == "db")
    {
        if (mode == "sections")
            return tool_result_t::error("source='db' supports mode='functions' only.");
        const auto db = aida::analysis::flirt::flirt_signature_db_t::load_embedded();
        if (!db || db->empty())
        {
            out["status"] = "db_absent";
            out["matches"] = json::array();
            out["match_count"] = 0;
            out["elapsed_ms"] = GetTickCount64() - started_ms;
            diag::log_tagged_fmt("sigs", "scan_static db_absent elapsed_ms=%llu",
                                 static_cast<unsigned long long>(GetTickCount64() - started_ms));
            return tool_result_t::ok("FLIRT signature database is not embedded.", out);
        }
        aida::analysis::flirt::flirt_scan_request_t request;
        request.snapshot = snapshot.get();
        request.image = image.get();
        request.pe = snapshot->image.get();
        request.provider = provider;
        request.db = db.get();
        aida::analysis::cancellation_source_t scan_cancel;
        if (const std::uint64_t call_deadline_ms = mcp_standalone::current_call_deadline_ms();
            call_deadline_ms != 0)
        {
            const std::uint64_t now_ms = static_cast<std::uint64_t>(GetTickCount64());
            scan_cancel.set_deadline(std::chrono::steady_clock::now() +
                std::chrono::milliseconds(call_deadline_ms > now_ms ? call_deadline_ms - now_ms : 0));
        }
        aida::infra::cancellation_watchdog::watch_id_t scan_watch;
        if (std::atomic<bool>* const observed = mcp_standalone::current_cancel_token())
        {
            aida::infra::cancellation_watchdog::watch_descriptor_t watch;
            watch.external_flag = observed;
            watch.on_fire = [source_snapshot = scan_cancel]() mutable {
                source_snapshot.request_cancel();
            };
            scan_watch = aida::infra::cancellation_watchdog::register_watch(std::move(watch));
        }
        auto scanned = aida::analysis::flirt::flirt_scan(request, scan_cancel.token());
        if (scan_watch.valid())
            aida::infra::cancellation_watchdog::unregister_watch(scan_watch);
        if (!scanned)
            return tool_result_t::error("FLIRT static scan failed: " + scanned.error().message);
        const auto& scan = scanned.value();
        json matches = json::array();
        for (const auto& match : scan.matches)
        {
            if (matches.size() >= max_results)
                break;
            matches.push_back(json{
                {"rva", sa_format_address(match.rva)},
                {"name", match.name},
                {"tier", match.tier},
                {"confidence", match.confidence},
                {"is_noreturn", match.is_noreturn}
            });
        }
        out["status"] = scan.status == aida::analysis::flirt::k_flirt_status_completed ? "found" :
            scan.status == aida::analysis::flirt::k_flirt_status_cancelled ? "cancelled" : "error";
        out["matches"] = std::move(matches);
        out["match_count"] = scan.matches.size();
        out["functions_considered"] = scan.functions_considered;
        out["functions_skipped_thunk"] = scan.functions_skipped_thunk;
        out["functions_skipped_short"] = scan.functions_skipped_short;
        out["candidates_tested"] = scan.candidates_tested;
        out["ambiguous"] = scan.ambiguous;
        out["rejected_reloc"] = scan.rejected_reloc;
        out["db_entries"] = db->entry_count();
        out["db_toolset"] = db->toolset();
        out["cancelled"] = scan.status == aida::analysis::flirt::k_flirt_status_cancelled;
        out["elapsed_ms"] = GetTickCount64() - started_ms;
        diag::log_tagged_fmt("sigs",
                             "scan_static db exit status=%u matches=%zu elapsed_ms=%llu",
                             static_cast<unsigned int>(scan.status),
                             scan.matches.size(),
                             static_cast<unsigned long long>(GetTickCount64() - started_ms));
        return tool_result_t::ok(out);
    }

    std::string pattern_text = string_param(params, "pattern");
    std::string signature_name = string_param(params, "name");
    if (pattern_text.empty())
    {
        const std::string signature_id = string_param(params, "signature_id");
        if (signature_id.empty())
            return tool_result_t::error("scan_static requires 'pattern', 'signature_id', or source='db'.");
        const auto records = store::load_signatures();
        const auto found = std::find_if(records.begin(), records.end(), [&](const auto& record) {
            return record.id == signature_id;
        });
        if (found == records.end())
            return tool_result_t::error("'signature_id' did not match a stored signature.");
        pattern_text = found->pattern;
        if (signature_name.empty())
            signature_name = found->name;
    }
    std::vector<parsed_pattern_byte_t> pattern;
    std::string err;
    if (!parse_pattern(pattern_text, pattern, &err))
        return tool_result_t::error("Invalid pattern: " + err);
    if (pattern.empty() || pattern.size() > 64)
        return tool_result_t::error("scan_static pattern length must be within [1,64] bytes.");

    json match_arr = json::array();
    std::uint64_t bytes_scanned = 0;
    bool cancelled = false;
    bool deadline_hit = false;
    if (mode == "functions")
    {
        for (const auto& function : snapshot->functions)
        {
            if ((match_arr.size() & 0xFFu) == 0 && sigs_call_cancelled("scan_static_functions", 0, started_ms))
            {
                cancelled = mcp_standalone::current_call_cancelled();
                deadline_hit = !cancelled;
                break;
            }
            if (match_arr.size() >= max_results)
                break;
            const std::uint64_t rva = function.start.value;
            const auto* section = static_find_section(sections, rva);
            if (!section)
                continue;
            const std::uint64_t file_offset = section->file_offset + (rva - section->virtual_address);
            const std::uint64_t available = section->file_offset + section->file_size - file_offset;
            if (available < pattern.size())
                continue;
            auto leased = provider->lease(file_offset, pattern.size());
            if (!leased || leased.value().size() < pattern.size())
                continue;
            std::uint8_t buffer[64]{};
            leased.value().copy_to(buffer, pattern.size());
            bytes_scanned += pattern.size();
            if (!pattern_matches(buffer, pattern.size(), pattern))
                continue;
            match_arr.push_back(json{{"rva", sa_format_address(rva)},
                                     {"function_end_rva", sa_format_address(function.end.value)}});
        }
    }
    else
    {
        const std::uint64_t max_scan_bytes = numeric_param(params, "max_scan_bytes", 256ull << 20, 4096, 1ull << 31);
        for (const auto& section : sections)
        {
            if ((section.permissions & aida::analysis::image_permission_execute) == 0)
                continue;
            if (match_arr.size() >= max_results || bytes_scanned >= max_scan_bytes)
                break;
            std::uint64_t cursor = section.file_offset;
            const std::uint64_t section_end = section.file_offset + section.file_size;
            std::uint64_t section_rva_cursor = section.virtual_address;
            const std::uint64_t overlap = pattern.size() - 1;
            bool first_chunk = true;
            while (cursor < section_end && match_arr.size() < max_results && bytes_scanned < max_scan_bytes)
            {
                if (sigs_call_cancelled("scan_static_sections", 0, started_ms))
                {
                    cancelled = mcp_standalone::current_call_cancelled();
                    deadline_hit = !cancelled;
                    break;
                }
                const std::uint64_t chunk = (std::min<std::uint64_t>)(16ull << 20, section_end - cursor);
                if (!first_chunk && chunk <= overlap)
                    break;
                auto leased = provider->lease(cursor, chunk);
                if (!leased || leased.value().empty())
                    break;
                const std::size_t size = leased.value().size();
                std::vector<std::uint8_t> bytes(size);
                leased.value().copy_to(bytes.data(), size);
                for (std::size_t i = 0; i + pattern.size() <= bytes.size(); ++i)
                {
                    if ((i & 0xFFFu) == 0 && sigs_call_cancelled("scan_static_sections", 0, started_ms))
                    {
                        cancelled = mcp_standalone::current_call_cancelled();
                        deadline_hit = !cancelled;
                        break;
                    }
                    if (!pattern_matches(bytes.data() + i, bytes.size() - i, pattern))
                        continue;
                    match_arr.push_back(json{{"rva", sa_format_address(section_rva_cursor + i)}});
                    if (match_arr.size() >= max_results)
                        break;
                }
                if (cancelled || deadline_hit)
                    break;
                const std::uint64_t advance = size > overlap ? size - overlap : size;
                bytes_scanned += first_chunk ? size : advance;
                first_chunk = false;
                cursor += advance;
                section_rva_cursor += advance;
            }
            if (cancelled || deadline_hit)
                break;
        }
    }
    out["status"] = cancelled || deadline_hit ? "cancelled" : match_arr.empty() ? "not_found" : "found";
    out["name"] = signature_name;
    out["pattern_bytes"] = pattern.size();
    out["matches"] = std::move(match_arr);
    out["match_count"] = out["matches"].size();
    out["scan_bytes"] = bytes_scanned;
    out["cancelled"] = cancelled;
    out["deadline_hit"] = deadline_hit;
    out["elapsed_ms"] = GetTickCount64() - started_ms;
    diag::log_tagged_fmt("sigs",
                         "scan_static exit mode=%s pattern_bytes=%zu matches=%zu scan_bytes=%llu status=%s elapsed_ms=%llu",
                         mode.c_str(),
                         pattern.size(),
                         out["match_count"].get<std::size_t>(),
                         static_cast<unsigned long long>(bytes_scanned),
                         out["status"].get<std::string>().c_str(),
                         static_cast<unsigned long long>(GetTickCount64() - started_ms));
    return tool_result_t::ok(out);
}
}

tool_result_t manage(const json& params)
{
    const std::uint64_t started_ms = GetTickCount64();
    const std::string action = compat_action_name(params);
    const json p = compat_action_payload(params);
    diag::log_tagged_fmt("sigs",
                         "manage enter action=%s deadline_remaining_ms=%llu diag_id=%s",
                         action.c_str(),
                         static_cast<unsigned long long>(deadline_remaining_ms()),
                         mcp_standalone::current_call_diag_id());
    if (action == "save") return save_signature(p);
    if (action == "list") return list_signatures(p);
    if (action == "scan_all") return scan_all(p);
    if (action == "scan_static") return scan_static(p);
    if (action == "import") return import_signatures(p);
    if (action == "export") return export_signatures(p);
    diag::log_tagged_fmt("sigs",
                         "manage exit action=%s unknown=1 elapsed_ms=%llu",
                         action.c_str(),
                         static_cast<unsigned long long>(GetTickCount64() - started_ms));
    return compat_unknown_action("sigs_manage", action);
}
}
