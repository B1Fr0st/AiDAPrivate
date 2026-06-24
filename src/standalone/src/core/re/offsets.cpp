#include "offsets.hpp"

#include "artifact_store.hpp"
#include "../../helpers/diag_log.hpp"

#include <algorithm>
#include <cctype>
#include <fstream>
#include <map>
#include <optional>
#include <set>
#include <sstream>

namespace re::offsets
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

bool offsets_call_cancelled(const char* phase, std::uint32_t pid, std::uint64_t started_ms)
{
    if (mcp_standalone::current_call_cancelled())
    {
        diag::log_tagged_fmt("offsets", "cancelled phase=%s pid=%u elapsed_ms=%llu diag_id=%s",
                             phase ? phase : "",
                             pid,
                             static_cast<unsigned long long>(GetTickCount64() - started_ms),
                             mcp_standalone::current_call_diag_id());
        return true;
    }
    const std::uint64_t deadline = mcp_standalone::current_call_deadline_ms();
    if (deadline != 0 && GetTickCount64() >= deadline)
    {
        diag::log_tagged_fmt("offsets", "deadline_reached phase=%s pid=%u elapsed_ms=%llu diag_id=%s",
                             phase ? phase : "",
                             pid,
                             static_cast<unsigned long long>(GetTickCount64() - started_ms),
                             mcp_standalone::current_call_diag_id());
        return true;
    }
    return false;
}

json offsets_cancel_detail(const char* action, std::uint32_t pid, std::uint64_t started_ms)
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

tool_result_t offsets_guard_required(const char* action, const json& params, std::uint64_t started_ms)
{
    json out;
    out["tool"] = "offsets_manage";
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
    if (params.contains("offset_id"))
        out["offset_id"] = params["offset_id"];
    if (params.contains("output_path"))
        out["output_path_present"] = true;
    return tool_result_t::error(std::string(action ? action : "offsets_manage") + " requires confirm_unsafe=true or allow_unsafe=true.", out);
}

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

bool plausible_va(std::uint64_t va)
{
    return va >= 0x10000 && va < 0x0000800000000000ULL;
}

bool readable_va(std::uint32_t pid, std::uint64_t va)
{
    if (!plausible_va(va))
        return false;
    driver_bridge::memory_region_t region{};
    if (query_region(pid, va, region) && is_readable(region))
        return true;
    std::vector<std::uint8_t> probe;
    return read_bytes(pid, va, 1, probe) && !probe.empty();
}

bool pattern_at(std::uint32_t pid, std::uint64_t va, const std::vector<parsed_pattern_byte_t>& pattern)
{
    if (pattern.empty() || !plausible_va(va))
        return false;
    std::vector<std::uint8_t> bytes;
    return read_bytes(pid, va, pattern.size(), bytes) &&
        bytes.size() >= pattern.size() &&
        pattern_matches(bytes.data(), bytes.size(), pattern);
}

bool same_module_name(const std::string& a, const std::string& b)
{
    return !a.empty() && !b.empty() && lower_ascii(a) == lower_ascii(b);
}

struct offset_candidate_t
{
    std::uint64_t va = 0;
    int score = 0;
    bool readable = false;
    bool aob_match = false;
    bool accepted = false;
    bool module_match = false;
    std::set<std::string> sources;
};

void add_candidate(std::vector<offset_candidate_t>& candidates, std::uint64_t va, const std::string& source, int score)
{
    if (!plausible_va(va))
        return;
    for (auto& candidate : candidates)
    {
        if (candidate.va == va)
        {
            if (candidate.sources.insert(source).second)
                candidate.score += score;
            return;
        }
    }
    offset_candidate_t candidate;
    candidate.va = va;
    candidate.score = score;
    candidate.sources.insert(source);
    candidates.push_back(std::move(candidate));
}

void add_unique_address(std::vector<std::uint64_t>& out, std::uint64_t value)
{
    if (plausible_va(value) && std::find(out.begin(), out.end(), value) == out.end())
        out.push_back(value);
}

std::vector<std::uint64_t> addresses_from_text(const std::string& text)
{
    std::vector<std::uint64_t> out;
    for (std::size_t i = 0; i + 2 <= text.size(); ++i)
    {
        if (text[i] != '0' || (text[i + 1] != 'x' && text[i + 1] != 'X'))
            continue;
        std::size_t j = i + 2;
        std::uint64_t value = 0;
        std::size_t digits = 0;
        while (j < text.size() && std::isxdigit(static_cast<unsigned char>(text[j])) && digits < 16)
        {
            const char ch = text[j++];
            const std::uint64_t nibble = ch >= '0' && ch <= '9' ? static_cast<std::uint64_t>(ch - '0') :
                (ch >= 'a' && ch <= 'f' ? static_cast<std::uint64_t>(10 + ch - 'a') : static_cast<std::uint64_t>(10 + ch - 'A'));
            value = (value << 4) | nibble;
            ++digits;
        }
        if (digits != 0)
            add_unique_address(out, value);
        i = j;
    }
    return out;
}

bool json_key_is_addressish(const std::string& key)
{
    const std::string lower = lower_ascii(key);
    const bool va_key = lower == "va" ||
        (lower.size() >= 3 && lower.compare(lower.size() - 3, 3, "_va") == 0);
    return va_key ||
        lower.find("address") != std::string::npos ||
        lower.find("ptr") != std::string::npos;
}

void collect_json_addresses(const json& value, const std::string& key, std::vector<std::uint64_t>& out)
{
    if (value.is_object())
    {
        for (auto it = value.begin(); it != value.end(); ++it)
            collect_json_addresses(it.value(), it.key(), out);
        return;
    }
    if (value.is_array())
    {
        for (const auto& item : value)
            collect_json_addresses(item, key, out);
        return;
    }
    if (!json_key_is_addressish(key))
        return;
    std::uint64_t parsed = 0;
    if (parse_u64_value(value, parsed))
        add_unique_address(out, parsed);
}

std::vector<std::uint64_t> addresses_from_context(const std::string& text)
{
    std::vector<std::uint64_t> out = addresses_from_text(text);
    if (!text.empty())
    {
        json parsed = json::parse(text, nullptr, false);
        if (!parsed.is_discarded())
            collect_json_addresses(parsed, {}, out);
    }
    return out;
}

json address_array_json(const std::vector<std::uint64_t>& values)
{
    json out = json::array();
    for (auto value : values)
        out.push_back(sa_format_address(value));
    return out;
}

json candidate_sources_json(const offset_candidate_t& candidate)
{
    json out = json::array();
    for (const auto& source : candidate.sources)
        out.push_back(source);
    return out;
}

void evaluate_candidate(std::uint32_t pid,
                        const store::offset_record_t& record,
                        const std::vector<parsed_pattern_byte_t>& pattern,
                        offset_candidate_t& candidate)
{
    candidate.readable = readable_va(pid, candidate.va);
    candidate.aob_match = !pattern.empty() && pattern_at(pid, candidate.va, pattern);
    if (auto module = find_module_for_address(pid, candidate.va))
        candidate.module_match = same_module_name(module->name, record.module_name);
    if (candidate.readable)
        candidate.score += 10;
    if (candidate.module_match)
        candidate.score += 20;
    if (!pattern.empty())
    {
        if (candidate.aob_match)
            candidate.score += 200;
        else
            candidate.score -= 120;
    }
    candidate.accepted = candidate.readable && (pattern.empty() || candidate.aob_match);
}

json candidate_json(const offset_candidate_t& candidate)
{
    json row;
    row["va"] = sa_format_address(candidate.va);
    row["score"] = candidate.score;
    row["readable"] = candidate.readable;
    row["aob_match"] = candidate.aob_match;
    row["accepted"] = candidate.accepted;
    row["module_match"] = candidate.module_match;
    row["sources"] = candidate_sources_json(candidate);
    return row;
}

json fingerprint_for_record(std::uint32_t pid, const store::offset_record_t& record)
{
    json fingerprint;
    fingerprint["recorded_va"] = sa_format_address(record.va);
    fingerprint["module_name"] = record.module_name;
    fingerprint["module_rva"] = sa_format_address(record.module_rva);
    fingerprint["aob_pattern"] = record.aob_pattern;
    fingerprint["rtti_path"] = record.rtti_path;
    fingerprint["xref_context"] = record.xref_context;
    if (auto module = find_module_for_address(pid, record.va))
    {
        fingerprint["recorded_module_base"] = sa_format_address(module->base);
        fingerprint["recorded_module_size"] = module->size;
        fingerprint["recorded_module_path"] = module->path;
    }
    const auto rtti_addresses = addresses_from_context(record.rtti_path);
    const auto xref_addresses = addresses_from_context(record.xref_context);
    fingerprint["rtti_context_addresses"] = address_array_json(rtti_addresses);
    fingerprint["xref_context_addresses"] = address_array_json(xref_addresses);
    return fingerprint;
}

json reverify_one(std::uint32_t pid, store::offset_record_t& record, std::size_t max_aob_matches, std::uint64_t started_ms)
{
    json out = store::offset_to_json(record);
    out["previous_va"] = sa_format_address(record.va);
    out["phase"] = "candidate_seed";
    std::vector<parsed_pattern_byte_t> pattern;
    std::string pattern_error;
    const bool has_aob = !record.aob_pattern.empty();
    const bool valid_aob = !has_aob || parse_pattern(record.aob_pattern, pattern, &pattern_error);
    if (!valid_aob)
    {
        record.status = "broken";
        record.updated_ms = unix_time_ms();
        out["verification_status"] = "broken";
        out["aob_error"] = pattern_error;
        return out;
    }

    std::vector<offset_candidate_t> candidates;
    add_candidate(candidates, record.va, "persisted_va", 60);
    if (record.last_found_va != 0)
        add_candidate(candidates, record.last_found_va, "last_found_va", 50);
    if (!record.module_name.empty() && record.module_rva < 0x7FFFFFFF0000ull)
    {
        if (auto module = find_module_by_name(pid, record.module_name))
        {
            if (record.module_rva < module->size)
                add_candidate(candidates, module->base + record.module_rva, "module_rva_rebase", 110);
        }
    }
    std::size_t initial_candidate_count = candidates.size();
    auto fast_candidates = candidates;
    for (auto& candidate : fast_candidates)
        evaluate_candidate(pid, record, pattern, candidate);
    auto accepted_initial = std::find_if(fast_candidates.begin(), fast_candidates.end(), [](const offset_candidate_t& candidate) {
        return candidate.accepted;
    });
    const bool fast_path_hit = accepted_initial != fast_candidates.end();
    out["persisted_va_checked"] = record.va != 0;
    out["last_found_va_checked"] = record.last_found_va != 0;
    out["fast_path_checked"] = true;
    out["fast_path_hit"] = fast_path_hit;
    out["initial_candidate_count"] = initial_candidate_count;
    out["deadline_hit"] = false;
    out["cancelled"] = false;
    out["scan_bytes"] = nullptr;
    out["scan_bytes_available"] = false;
    out["aob_matches_considered"] = 0;
    out["aob_scan_skipped_fast_path"] = false;
    if (offsets_call_cancelled("reverify_one_after_fast_candidates", pid, started_ms))
    {
        out["verification_status"] = "partial";
        out["partial"] = true;
        out["deadline_hit"] = !mcp_standalone::current_call_cancelled();
        out["cancelled"] = mcp_standalone::current_call_cancelled();
        out["phase"] = "fast_candidate_evaluation";
        return out;
    }
    if (!pattern.empty())
    {
        if (fast_path_hit)
        {
            out["aob_match_count"] = 0;
            out["aob_scan_skipped_fast_path"] = true;
            out["phase"] = "fast_path_accepted";
        }
        else
        {
            out["phase"] = "saved_aob_scan";
            auto matches = scan_pattern(pid, pattern, record.module_name, false, max_aob_matches);
            for (auto found : matches)
                add_candidate(candidates, found, "saved_aob_scan", 120);
            out["aob_match_count"] = matches.size();
            out["aob_matches_considered"] = matches.size();
        }
    }
    const auto rtti_addresses = addresses_from_context(record.rtti_path);
    const auto xref_addresses = addresses_from_context(record.xref_context);
    for (auto va : rtti_addresses)
        add_candidate(candidates, va, "rtti_path_address", 45);
    for (auto va : xref_addresses)
        add_candidate(candidates, va, "xref_context_address", 45);
    if (record.fingerprint.is_object())
    {
        std::vector<std::uint64_t> fingerprint_addresses;
        collect_json_addresses(record.fingerprint, {}, fingerprint_addresses);
        for (auto va : fingerprint_addresses)
            add_candidate(candidates, va, "fingerprint_address", 25);
    }

    for (auto& candidate : candidates)
        evaluate_candidate(pid, record, pattern, candidate);
    std::stable_sort(candidates.begin(), candidates.end(), [](const offset_candidate_t& a, const offset_candidate_t& b) {
        if (a.accepted != b.accepted)
            return a.accepted;
        if (a.score != b.score)
            return a.score > b.score;
        if (a.aob_match != b.aob_match)
            return a.aob_match;
        return a.va < b.va;
    });
    json candidate_rows = json::array();
    for (const auto& candidate : candidates)
        candidate_rows.push_back(candidate_json(candidate));
    out["rediscovery_candidates"] = std::move(candidate_rows);
    out["rtti_context_addresses"] = address_array_json(rtti_addresses);
    out["xref_context_addresses"] = address_array_json(xref_addresses);
    out["candidate_count"] = candidates.size();

    auto accepted_end = std::find_if(candidates.begin(), candidates.end(), [](const offset_candidate_t& candidate) {
        return !candidate.accepted;
    });
    if (accepted_end == candidates.begin())
    {
        record.status = "broken";
        record.updated_ms = unix_time_ms();
        out["verification_status"] = "broken";
        out["rediscovery_method"] = "none";
        out["phase"] = "no_accepted_candidate";
        return out;
    }
    const offset_candidate_t& best = candidates.front();
    std::size_t tied = 0;
    for (auto it = candidates.begin(); it != accepted_end; ++it)
    {
        if (it->score == best.score)
            ++tied;
    }
    if (tied > 1)
    {
        record.status = "ambiguous";
        record.updated_ms = unix_time_ms();
        out["verification_status"] = "ambiguous";
        out["match_count"] = static_cast<std::uint64_t>(std::distance(candidates.begin(), accepted_end));
        out["top_score"] = best.score;
        out["phase"] = "ambiguous_candidate";
        return out;
    }

    record.last_found_va = best.va;
    record.updated_ms = unix_time_ms();
    record.status = best.va == record.va ? "valid" : "shifted";
    out["verification_status"] = record.status;
    out["current_va"] = sa_format_address(record.va);
    out["found_va"] = sa_format_address(best.va);
    out["confidence_score"] = best.score;
    out["rediscovery_method"] = candidate_sources_json(best);
    out["module_match"] = best.module_match;
    out["phase"] = fast_path_hit ? "fast_path_accepted" : "rediscovery_complete";
    return out;
}

void refresh_record_module(std::uint32_t pid, store::offset_record_t& record)
{
    if (auto module = find_module_for_address(pid, record.va))
    {
        record.module_name = module->name;
        record.module_rva = record.va - module->base;
    }
}

tool_result_t record_offset(const json& params)
{
    const std::uint64_t started_ms = GetTickCount64();
    if (!unsafe_confirmed(params))
        return offsets_guard_required("record", params, started_ms);
    active_process_scope_t scope(params);
    if (!scope.ok())
        return tool_result_t::error(scope.error());
    const std::string name = string_param(params, "name");
    if (name.empty())
        return tool_result_t::error("'name' is required for record.");
    std::uint64_t va = 0;
    if (!parse_address_param(params, "va", va) || va == 0)
        return tool_result_t::error("'va' is required for record.");
    diag::log_tagged_fmt("offsets",
                         "record enter pid=%u name=%s va=%s deadline_remaining_ms=%llu diag_id=%s",
                         scope.pid(),
                         name.c_str(),
                         sa_format_address(va).c_str(),
                         static_cast<unsigned long long>(deadline_remaining_ms()),
                         mcp_standalone::current_call_diag_id());

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
    diag::log_tagged_fmt("offsets",
                         "record fingerprint_begin pid=%u id=%s module=%s module_rva=%s aob_bytes=%zu elapsed_ms=%llu",
                         scope.pid(),
                         record.id.c_str(),
                         record.module_name.empty() ? "" : record.module_name.c_str(),
                         record.module_rva ? sa_format_address(record.module_rva).c_str() : "0x0",
                         record.aob_pattern.size(),
                         static_cast<unsigned long long>(GetTickCount64() - started_ms));
    if (offsets_call_cancelled("record_before_fingerprint", scope.pid(), started_ms))
        return tool_result_t::error("Offset record cancelled.", offsets_cancel_detail("record", scope.pid(), started_ms));
    record.fingerprint = fingerprint_for_record(scope.pid(), record);

    auto records = store::load_offsets();
    const std::size_t before_count = records.size();
    records.push_back(record);
    const bool save_ok = store::save_offsets(records);
    diag::log_tagged_fmt("offsets",
                         "record store pid=%u id=%s before=%zu after=%zu save_ok=%d elapsed_ms=%llu",
                         scope.pid(),
                         record.id.c_str(),
                         before_count,
                         records.size(),
                         save_ok ? 1 : 0,
                         static_cast<unsigned long long>(GetTickCount64() - started_ms));
    if (!save_ok)
        return tool_result_t::error("Failed to save offsets database.");
    json result = store::offset_to_json(record);
    result["offset_id"] = record.id;
    result["source_count_before"] = before_count;
    result["source_count_after"] = records.size();
    result["elapsed_ms"] = GetTickCount64() - started_ms;
    diag::log_tagged_fmt("offsets",
                         "record exit pid=%u id=%s ok=1 elapsed_ms=%llu",
                         scope.pid(),
                         record.id.c_str(),
                         static_cast<unsigned long long>(GetTickCount64() - started_ms));
    return tool_result_t::ok("Offset recorded.", result);
}

tool_result_t list_offsets(const json& params)
{
    const std::uint64_t started_ms = GetTickCount64();
    const bool verified_only = bool_param(params, "verified_only", false);
    const std::string category = lower_ascii(string_param(params, "category"));
    const auto records = store::load_offsets();
    json arr = json::array();
    for (const auto& record : records)
    {
        if (verified_only && record.status != "valid")
            continue;
        if (!category.empty() && lower_ascii(record.category) != category)
            continue;
        arr.push_back(store::offset_to_json(record));
    }
    json result;
    result["offsets"] = std::move(arr);
    result["count"] = result["offsets"].size();
    result["source_count"] = records.size();
    result["elapsed_ms"] = GetTickCount64() - started_ms;
    diag::log_tagged_fmt("offsets",
                         "list exit source_count=%zu returned=%zu verified_only=%d category=%s elapsed_ms=%llu",
                         records.size(),
                         result["count"].get<std::size_t>(),
                         verified_only ? 1 : 0,
                         category.c_str(),
                         static_cast<unsigned long long>(GetTickCount64() - started_ms));
    return tool_result_t::ok(result);
}

tool_result_t reverify_offsets(const json& params, bool rebase)
{
    const std::uint64_t started_ms = GetTickCount64();
    if (!unsafe_confirmed(params))
        return offsets_guard_required(rebase ? "rebase" : "reverify", params, started_ms);
    active_process_scope_t scope(params);
    if (!scope.ok())
        return tool_result_t::error(scope.error());

    auto records = store::load_offsets();
    const std::set<std::string> selected_ids = selected_offset_ids(params);
    const std::string module_filter = string_param(params, "module_name");
    const std::size_t max_aob_matches = static_cast<std::size_t>(numeric_param(params, "max_aob_matches", 64, 2, 512));
    diag::log_tagged_fmt("offsets",
                         "reverify enter pid=%u rebase=%d records=%zu selected=%zu module_filter=%s max_aob_matches=%zu deadline_remaining_ms=%llu diag_id=%s",
                         scope.pid(),
                         rebase ? 1 : 0,
                         records.size(),
                         selected_ids.size(),
                         module_filter.c_str(),
                         max_aob_matches,
                         static_cast<unsigned long long>(deadline_remaining_ms()),
                         mcp_standalone::current_call_diag_id());
    json valid = json::array();
    json broken = json::array();
    json shifted = json::array();
    json ambiguous = json::array();
    json skipped = json::array();
    std::size_t records_scanned = 0;
    std::size_t selected_count = 0;
    auto partial_payload = [&](const char* phase, json partial_row = json(nullptr)) {
        json detail = offsets_cancel_detail(rebase ? "rebase" : "reverify", scope.pid(), started_ms);
        detail["phase"] = phase ? phase : "";
        detail["valid"] = valid;
        detail["broken"] = broken;
        detail["shifted"] = shifted;
        detail["ambiguous"] = ambiguous;
        detail["skipped"] = skipped;
        detail["selected_count"] = selected_count;
        detail["record_count"] = records.size();
        detail["records_scanned"] = records_scanned;
        detail["partial"] = true;
        if (!partial_row.is_null())
            detail["partial_record"] = std::move(partial_row);
        return detail;
    };
    for (auto& record : records)
    {
        if (offsets_call_cancelled(rebase ? "rebase_loop" : "reverify_loop", scope.pid(), started_ms))
            return tool_result_t::error(rebase ? "Offset rebase cancelled." : "Offset reverify cancelled.", partial_payload("loop_entry"));
        std::string skip_reason;
        if (!record_in_scope(record, scope.pid(), selected_ids, module_filter, skip_reason))
        {
            json row = store::offset_to_json(record);
            row["skip_reason"] = skip_reason;
            skipped.push_back(std::move(row));
            continue;
        }
        ++selected_count;
        json row = reverify_one(scope.pid(), record, max_aob_matches, started_ms);
        ++records_scanned;
        const std::string status = row.value("verification_status", std::string());
        if (status == "partial")
            return tool_result_t::error(rebase ? "Offset rebase cancelled during record verification." : "Offset reverify cancelled during record verification.", partial_payload("record_verification", std::move(row)));
        if (status == "valid")
            valid.push_back(row);
        else if (status == "shifted")
        {
            if (rebase)
            {
                record.va = record.last_found_va;
                refresh_record_module(scope.pid(), record);
                record.fingerprint = fingerprint_for_record(scope.pid(), record);
                row["rebased"] = true;
                row["rebase_from_status"] = "shifted";
                row["verification_status"] = "valid";
                row["current_va"] = sa_format_address(record.va);
                row["module_name"] = record.module_name;
                row["module_rva"] = sa_format_address(record.module_rva);
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
    result["source_count"] = records.size();
    result["record_count"] = records.size();
    result["selected_count"] = selected_count;
    result["records_scanned"] = records_scanned;
    result["deadline_hit"] = false;
    result["cancelled"] = false;
    result["elapsed_ms"] = GetTickCount64() - started_ms;
    if (!module_filter.empty())
        result["module_name"] = module_filter;
    diag::log_tagged_fmt("offsets",
                         "reverify exit pid=%u rebase=%d valid=%zu broken=%zu shifted=%zu ambiguous=%zu skipped=%zu elapsed_ms=%llu",
                         scope.pid(),
                         rebase ? 1 : 0,
                         result["valid"].size(),
                         result["broken"].size(),
                         result["shifted"].size(),
                         result["ambiguous"].size(),
                         result["skipped"].size(),
                         static_cast<unsigned long long>(GetTickCount64() - started_ms));
    return tool_result_t::ok(result);
}

tool_result_t export_offsets(const json& params)
{
    const std::uint64_t started_ms = GetTickCount64();
    if (!unsafe_confirmed(params))
        return offsets_guard_required("export", params, started_ms);
    const std::string output_path = string_param(params, "output_path");
    if (output_path.empty())
        return tool_result_t::error("'output_path' is required for export.");
    const std::string ns = sanitize_identifier(string_param(params, "namespace_name", "Offsets"), "Offsets");
    const bool use_rva = bool_param(params, "use_rva", false);
    const bool verified_only = bool_param(params, "verified_only", false);
    const std::string category = lower_ascii(string_param(params, "category"));
    const std::string module_filter = string_param(params, "module_name");
    const std::set<std::string> selected_ids = selected_offset_ids(params);
    std::uint32_t pid = 0;
    parse_pid_param(params, pid);
    const auto records = store::load_offsets();
    diag::log_tagged_fmt("offsets",
                         "export enter pid=%u output_path=%s namespace=%s records=%zu use_rva=%d verified_only=%d category=%s module_filter=%s deadline_remaining_ms=%llu diag_id=%s",
                         pid,
                         output_path.c_str(),
                         ns.c_str(),
                         records.size(),
                         use_rva ? 1 : 0,
                         verified_only ? 1 : 0,
                         category.c_str(),
                         module_filter.c_str(),
                         static_cast<unsigned long long>(deadline_remaining_ms()),
                         mcp_standalone::current_call_diag_id());
    ensure_parent_dir_exists(output_path);
    std::ofstream f(output_path, std::ios::binary | std::ios::trunc);
    if (!f.is_open())
        return tool_result_t::error("Failed to open output_path for writing.");
    f << "#pragma once\n\n";
    f << "#include <cstdint>\n\n";
    f << "namespace " << ns << "\n";
    f << "{\n";
    std::set<std::string> used_identifiers;
    json exported = json::array();
    json skipped = json::array();
    for (const auto& record : records)
    {
        if (((exported.size() + skipped.size()) & 0x1Fu) == 0 && offsets_call_cancelled("export_loop", pid, started_ms))
            return tool_result_t::error("Offset export cancelled.", offsets_cancel_detail("export", pid, started_ms));
        std::string skip_reason;
        if (!record_in_scope(record, pid, selected_ids, module_filter, skip_reason))
        {
            json row = store::offset_to_json(record);
            row["skip_reason"] = skip_reason;
            skipped.push_back(std::move(row));
            continue;
        }
        if (verified_only && record.status != "valid")
        {
            json row = store::offset_to_json(record);
            row["skip_reason"] = "verified_only";
            skipped.push_back(std::move(row));
            continue;
        }
        if (!category.empty() && lower_ascii(record.category) != category)
        {
            json row = store::offset_to_json(record);
            row["skip_reason"] = "category_filter_mismatch";
            skipped.push_back(std::move(row));
            continue;
        }
        if (use_rva && record.module_name.empty() && record.module_rva == 0 && record.va != 0)
        {
            json row = store::offset_to_json(record);
            row["skip_reason"] = "rva_unavailable";
            skipped.push_back(std::move(row));
            continue;
        }
        const std::uint64_t value = use_rva ? record.module_rva : record.va;
        const std::string base_identifier = sanitize_identifier(record.name, "Offset");
        std::string identifier = base_identifier;
        for (std::size_t suffix = 2; used_identifiers.count(identifier) != 0; ++suffix)
            identifier = base_identifier + "_" + std::to_string(suffix);
        used_identifiers.insert(identifier);
        f << "constexpr std::uintptr_t " << identifier << " = 0x"
          << std::hex << std::uppercase << value << std::dec << "ull;\n";
        json row = store::offset_to_json(record);
        row["identifier"] = identifier;
        row["exported_value"] = sa_format_address(value);
        exported.push_back(std::move(row));
    }
    f << "}\n";
    f.flush();
    const std::streamoff bytes_written = f.tellp();
    json result;
    result["output_path"] = output_path;
    result["count"] = exported.size();
    result["source_count"] = records.size();
    result["skipped_count"] = skipped.size();
    result["use_rva"] = use_rva;
    result["bytes_written"] = bytes_written >= 0 ? static_cast<std::uint64_t>(bytes_written) : 0;
    result["elapsed_ms"] = GetTickCount64() - started_ms;
    result["exported"] = std::move(exported);
    result["skipped"] = std::move(skipped);
    diag::log_tagged_fmt("offsets",
                         "export exit pid=%u output_path=%s count=%zu skipped=%zu bytes=%llu elapsed_ms=%llu",
                         pid,
                         output_path.c_str(),
                         result["count"].get<std::size_t>(),
                         result["skipped_count"].get<std::size_t>(),
                         static_cast<unsigned long long>(result["bytes_written"].get<std::uint64_t>()),
                         static_cast<unsigned long long>(GetTickCount64() - started_ms));
    return tool_result_t::ok("Offsets exported.", result);
}
}

tool_result_t manage(const json& params)
{
    const std::uint64_t started_ms = GetTickCount64();
    const std::string action = compat_action_name(params);
    const json p = compat_action_payload(params);
    diag::log_tagged_fmt("offsets",
                         "manage enter action=%s deadline_remaining_ms=%llu diag_id=%s",
                         action.c_str(),
                         static_cast<unsigned long long>(deadline_remaining_ms()),
                         mcp_standalone::current_call_diag_id());
    if (action == "record") return record_offset(p);
    if (action == "list") return list_offsets(p);
    if (action == "reverify") return reverify_offsets(p, false);
    if (action == "rebase") return reverify_offsets(p, true);
    if (action == "export") return export_offsets(p);
    diag::log_tagged_fmt("offsets",
                         "manage exit action=%s unknown=1 elapsed_ms=%llu",
                         action.c_str(),
                         static_cast<unsigned long long>(GetTickCount64() - started_ms));
    return compat_unknown_action("offsets_manage", action);
}
}
