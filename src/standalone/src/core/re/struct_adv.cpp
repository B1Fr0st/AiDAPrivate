#include "struct_adv.hpp"

#include "artifact_store.hpp"
#include "../analysis/struct_recon_engine.hpp"
#include "../scanner/snapshot_diff.hpp"
#include "../../helpers/diag_log.hpp"

#include <algorithm>
#include <chrono>
#include <cmath>
#include <cstring>
#include <cstddef>
#include <limits>
#include <map>
#include <mutex>
#include <set>
#include <thread>

namespace re::struct_adv
{
namespace
{
json field_json(const struct_recon::struct_field_t& field)
{
    json out;
    out["name"] = field.name;
    out["offset"] = field.offset;
    out["size"] = field.size;
    out["type"] = struct_recon::field_type_name(field.type);
    out["confidence"] = field.type_confidence;
    out["array_count"] = field.array_count;
    json accesses = json::array();
    for (const auto& access : field.accesses)
    {
        json row;
        row["instruction_va"] = sa_format_address(access.instruction_addr);
        row["access_offset"] = access.access_offset;
        row["access_size"] = access.access_size;
        row["is_write"] = access.is_write;
        row["disasm"] = access.disasm_text;
        row["hit_count"] = access.hit_count;
        row["source"] = access.source.empty() ? "unknown" : access.source;
        row["thread_id"] = access.thread_id;
        row["sample_index"] = access.sample_index;
        row["capture_session_id"] = access.capture_session_id;
        row["initial_value_captured"] = access.initial_value_captured;
        if (access.initial_value_captured)
        {
            row["initial_value"] = access.initial_value;
            row["initial_hex"] = bytes_to_hex(access.initial_bytes, 16);
        }
        row["value_captured"] = access.value_captured;
        row["value_after_access"] = access.value_after_access;
        if (access.value_captured)
        {
            row["observed_value"] = access.observed_value;
            row["observed_hex"] = bytes_to_hex(access.observed_bytes, 16);
            row["observed_size"] = access.observed_bytes.size();
        }
        accesses.push_back(std::move(row));
    }
    out["accesses"] = std::move(accesses);
    return out;
}

std::string infer_scalar_type(const std::vector<std::uint8_t>& data)
{
    bool any_nonzero = false;
    for (auto b : data)
    {
        if (b != 0)
        {
            any_nonzero = true;
            break;
        }
    }
    if (!any_nonzero)
        return "zero";
    std::size_t printable = 0;
    for (auto b : data)
    {
        if ((b >= 0x20 && b <= 0x7E) || b == 0)
            ++printable;
    }
    if (data.size() >= 4 && printable * 4 >= data.size() * 3)
        return "char_buffer";
    if (data.size() >= 8)
    {
        std::uint64_t ptr = 0;
        std::memcpy(&ptr, data.data(), sizeof(ptr));
        if (ptr >= 0x10000 && ptr < 0x0000800000000000ULL)
            return "pointer";
        double d = 0.0;
        std::memcpy(&d, data.data(), sizeof(d));
        if (std::isfinite(d) && std::fabs(d) > 1e-12 && std::fabs(d) < 1e12)
            return "double";
    }
    if (data.size() >= 4)
    {
        float f = 0.0f;
        std::memcpy(&f, data.data(), sizeof(f));
        if (std::isfinite(f) && std::fabs(f) > 1e-6f && std::fabs(f) < 1e7f)
            return "float";
        return "uint32_t";
    }
    if (data.size() >= 2)
        return "uint16_t";
    return "uint8_t";
}

std::string infer_scalar_type_for_process(std::uint32_t pid, const std::vector<std::uint8_t>& data)
{
    if (data.size() >= 8)
    {
        std::uint64_t ptr = 0;
        std::memcpy(&ptr, data.data(), sizeof(ptr));
        driver_bridge::memory_region_t region{};
        if (ptr >= 0x10000 && ptr < 0x0000800000000000ULL && query_region(pid, ptr, region) && is_readable(region))
        {
            if (is_executable(region))
                return "code_pointer";
            return "pointer";
        }
    }
    return infer_scalar_type(data);
}

std::optional<snapshot_diff::snapshot_t> find_scanner_snapshot(const std::string& id)
{
    std::uint64_t numeric = 0;
    bool numeric_ok = false;
    try
    {
        numeric = std::stoull(id, nullptr, 0);
        numeric_ok = true;
    }
    catch (...)
    {
        numeric_ok = false;
    }
    std::lock_guard<std::mutex> lk(snapshot_diff::g_state.mutex);
    for (const auto& snap : snapshot_diff::g_state.snapshots)
    {
        if ((numeric_ok && snap.id == numeric) || snap.name == id)
            return snap;
    }
    return std::nullopt;
}

bool extract_snapshot_region(const snapshot_diff::snapshot_t& snap,
                             std::uint64_t base,
                             std::uint64_t size,
                             std::vector<std::uint8_t>& out)
{
    out.clear();
    for (const auto& region : snap.regions)
    {
        if (base < region.base)
            continue;
        const std::uint64_t rel = base - region.base;
        if (rel + size > region.data.size())
            continue;
        out.assign(region.data.begin() + static_cast<std::ptrdiff_t>(rel),
                   region.data.begin() + static_cast<std::ptrdiff_t>(rel + size));
        return true;
    }
    return false;
}

std::uint64_t read_le_scalar(const std::vector<std::uint8_t>& data, std::size_t offset, std::size_t size)
{
    std::uint64_t value = 0;
    if (offset >= data.size())
        return value;
    const std::size_t n = std::min<std::size_t>(size, std::min<std::size_t>(8, data.size() - offset));
    std::memcpy(&value, data.data() + offset, n);
    return value;
}

bool any_changed_in_range(const std::vector<std::uint8_t>& a,
                          const std::vector<std::uint8_t>& b,
                          std::size_t offset,
                          std::size_t size,
                          std::size_t& changed_count)
{
    changed_count = 0;
    const std::size_t limit = std::min(a.size(), b.size());
    if (offset >= limit)
        return false;
    const std::size_t end = std::min(limit, offset + size);
    for (std::size_t i = offset; i < end; ++i)
        if (a[i] != b[i])
            ++changed_count;
    return changed_count != 0;
}

void add_numeric_delta(json& row,
                       const std::vector<std::uint8_t>& a,
                       const std::vector<std::uint8_t>& b,
                       std::size_t offset,
                       std::size_t size)
{
    if (!(size == 1 || size == 2 || size == 4 || size == 8))
        return;
    const std::uint64_t before = read_le_scalar(a, offset, size);
    const std::uint64_t after = read_le_scalar(b, offset, size);
    row["numeric_delta_available"] = true;
    row["before_unsigned"] = before;
    row["after_unsigned"] = after;
    if (after >= before && after - before <= static_cast<std::uint64_t>(std::numeric_limits<std::int64_t>::max()))
    {
        row["delta"] = static_cast<std::int64_t>(after - before);
    }
    else if (before > after && before - after <= static_cast<std::uint64_t>(std::numeric_limits<std::int64_t>::max()))
    {
        row["delta"] = -static_cast<std::int64_t>(before - after);
    }
    else
    {
        row["delta_overflow"] = true;
    }
}

std::vector<struct_recon::struct_field_t> current_fields_for_base(std::uint64_t base)
{
    std::lock_guard<std::mutex> lk(struct_recon::g_state.mutex);
    if (!struct_recon::g_state.active || struct_recon::g_state.current.base_address != base)
        return {};
    return struct_recon::g_state.current.fields;
}

bool region_contains_address(const driver_bridge::memory_region_t& region, std::uint64_t address)
{
    if (address < region.base || region.size == 0)
        return false;
    return address - region.base < region.size;
}

double clamp_score(double score)
{
    if (score < 0.0)
        return 0.0;
    if (score > 0.99)
        return 0.99;
    return score;
}

struct access_pattern_sig_t
{
    std::uint64_t offset = 0;
    std::uint64_t rip = 0;
    int size = 0;
    bool write = false;

    bool operator<(const access_pattern_sig_t& other) const
    {
        if (offset != other.offset) return offset < other.offset;
        if (size != other.size) return size < other.size;
        if (write != other.write) return write < other.write;
        return rip < other.rip;
    }
};

json access_pattern_sig_json(const access_pattern_sig_t& sig)
{
    json row;
    row["offset"] = sig.offset;
    row["size"] = sig.size;
    row["is_write"] = sig.write;
    row["instruction_va"] = sa_format_address(sig.rip);
    return row;
}
}

tool_result_t observe(const json& params)
{
    const std::uint64_t started_ms = GetTickCount64();
    if (!unsafe_confirmed(params))
        return unsafe_required("struct_observe");
    active_process_scope_t scope(params);
    if (!scope.ok())
        return tool_result_t::error(scope.error());
    std::uint64_t base = 0;
    if (!parse_address_param(params, "base_va", base) || base == 0)
        return tool_result_t::error("'base_va' is required.");
    const int size = static_cast<int>(numeric_param(params, "size", 4096, 16, 65536));
    const int duration_sec = static_cast<int>(numeric_param(params, "duration_sec", 10, 1, 60));
    const std::uint64_t wait_budget_ms = numeric_param(params, "timeout_ms", static_cast<std::uint64_t>(duration_sec) * 1000ull + 2500ull, 500, 60000);
    diag::log_tagged_fmt("struct_adv",
                         "observe enter pid=%u base=%s size=%d duration_sec=%d wait_budget_ms=%llu monitoring=%d",
                         scope.pid(),
                         sa_format_address(base).c_str(),
                         size,
                         duration_sec,
                         static_cast<unsigned long long>(wait_budget_ms),
                         struct_recon::g_state.monitoring.load() ? 1 : 0);

    {
        std::lock_guard<std::mutex> lk(struct_recon::g_state.mutex);
        struct_recon::g_state.config.base_address = base;
        struct_recon::g_state.config.monitor_size = size;
        struct_recon::g_state.config.sample_count = std::max(1, duration_sec * 20);
    }
    diag::log_tagged_fmt("struct_adv",
                         "observe post_monitor pid=%u base=%s size=%d samples=%d elapsed_ms=%llu",
                         scope.pid(),
                         sa_format_address(base).c_str(),
                         size,
                         std::max(1, duration_sec * 20),
                         static_cast<unsigned long long>(GetTickCount64() - started_ms));
    struct_recon::monitor_with_hwbp(base, size, "observed_struct");
    const auto wait_start = GetTickCount64();
    while (struct_recon::g_state.monitoring.load() && GetTickCount64() - wait_start < wait_budget_ms)
        std::this_thread::sleep_for(std::chrono::milliseconds(50));
    const bool monitor_complete = !struct_recon::g_state.monitoring.load();
    if (!monitor_complete)
    {
        struct_recon::g_state.cancel.store(true);
        diag::log_tagged_fmt("struct_adv",
                             "observe wait_timeout pid=%u base=%s wait_ms=%llu budget_ms=%llu progress=%.3f",
                             scope.pid(),
                             sa_format_address(base).c_str(),
                             static_cast<unsigned long long>(GetTickCount64() - wait_start),
                             static_cast<unsigned long long>(wait_budget_ms),
                             static_cast<double>(struct_recon::g_state.progress.load()));
    }
    else
    {
        diag::log_tagged_fmt("struct_adv",
                             "observe wait_complete pid=%u base=%s wait_ms=%llu progress=%.3f",
                             scope.pid(),
                             sa_format_address(base).c_str(),
                             static_cast<unsigned long long>(GetTickCount64() - wait_start),
                             static_cast<double>(struct_recon::g_state.progress.load()));
    }

    struct_recon::reconstructed_struct_t snapshot;
    {
        std::lock_guard<std::mutex> lk(struct_recon::g_state.mutex);
        snapshot = struct_recon::g_state.current;
    }

    store::memory_snapshot_t mem_snap;
    mem_snap.id = store::next_id("structsnap");
    mem_snap.pid = scope.pid();
    mem_snap.base_va = base;
    mem_snap.size = static_cast<std::uint64_t>(size);
    mem_snap.created_ms = unix_time_ms();
    diag::log_tagged_fmt("struct_adv",
                         "observe snapshot_read_begin pid=%u base=%s size=%d elapsed_ms=%llu",
                         scope.pid(),
                         sa_format_address(base).c_str(),
                         size,
                         static_cast<unsigned long long>(GetTickCount64() - started_ms));
    const bool read_ok = read_bytes(scope.pid(), base, static_cast<std::size_t>(size), mem_snap.data);
    diag::log_tagged_fmt("struct_adv",
                         "observe snapshot_read_end pid=%u base=%s ok=%d bytes=%zu elapsed_ms=%llu",
                         scope.pid(),
                         sa_format_address(base).c_str(),
                         read_ok ? 1 : 0,
                         mem_snap.data.size(),
                         static_cast<unsigned long long>(GetTickCount64() - started_ms));
    store::add_memory_snapshot(mem_snap);

    json fields = json::array();
    std::size_t access_count = 0;
    std::size_t value_capture_count = 0;
    std::size_t initial_value_capture_count = 0;
    std::map<std::string, std::size_t> access_sources;
    for (const auto& field : snapshot.fields)
    {
        for (const auto& access : field.accesses)
        {
            ++access_count;
            ++access_sources[access.source.empty() ? std::string("unknown") : access.source];
            if (access.value_captured)
                ++value_capture_count;
            if (access.initial_value_captured)
                ++initial_value_capture_count;
        }
        fields.push_back(field_json(field));
    }
    json source_counts = json::object();
    for (const auto& [source, count] : access_sources)
        source_counts[source] = count;
    json result;
    result["struct_id"] = mem_snap.id;
    result["process_id"] = scope.pid();
    result["base_va"] = sa_format_address(base);
    result["size"] = size;
    result["duration_sec"] = duration_sec;
    result["wait_budget_ms"] = wait_budget_ms;
    result["elapsed_ms"] = GetTickCount64() - started_ms;
    result["monitor_complete"] = monitor_complete;
    result["inferred_fields"] = std::move(fields);
    result["field_count"] = result["inferred_fields"].size();
    result["access_evidence_count"] = access_count;
    result["initial_value_capture_count"] = initial_value_capture_count;
    result["value_capture_count"] = value_capture_count;
    result["access_value_evidence_available"] = value_capture_count != 0;
    result["access_sources"] = std::move(source_counts);
    result["snapshot_id"] = mem_snap.id;
    diag::log_tagged_fmt("struct_adv",
                         "observe exit pid=%u base=%s snapshot_id=%s fields=%zu monitor_complete=%d elapsed_ms=%llu",
                         scope.pid(),
                         sa_format_address(base).c_str(),
                         mem_snap.id.c_str(),
                         result["field_count"].get<std::size_t>(),
                         monitor_complete ? 1 : 0,
                         static_cast<unsigned long long>(GetTickCount64() - started_ms));
    return tool_result_t::ok(result);
}

tool_result_t correlate(const json& params)
{
    if (!params.contains("field_addresses") || !params["field_addresses"].is_array())
        return tool_result_t::error("'field_addresses' array is required.");
    struct field_t
    {
        std::string name;
        std::uint64_t va = 0;
    };
    std::vector<field_t> fields;
    for (const auto& item : params["field_addresses"])
    {
        field_t f;
        f.name = item.value("name", std::string("field"));
        if (item.contains("va"))
            parse_u64_value(item["va"], f.va);
        if (f.va != 0)
            fields.push_back(f);
    }
    if (fields.empty())
        return tool_result_t::error("field_addresses contains no valid addresses.");
    std::sort(fields.begin(), fields.end(), [](const field_t& a, const field_t& b) { return a.va < b.va; });
    const std::uint64_t min_va = fields.front().va;
    const std::uint64_t max_span = numeric_param(params, "max_span", 0x1000, 8, 0x100000);
    std::uint32_t pid = 0;
    const bool has_pid = parse_pid_param(params, pid);
    const std::uint64_t default_search = std::min<std::uint64_t>(max_span, 0x400);
    const std::uint64_t base_search_window = numeric_param(params, "base_search_window", default_search, 0, max_span);
    struct candidate_t
    {
        std::uint64_t base = 0;
        std::uint64_t alignment = 0;
        std::uint64_t span = 0;
        std::uint64_t leading_slack = 0;
        std::uint64_t alignment_cost = 0;
        double alignment_score = 0.0;
        double compact_score = 0.0;
        double leading_score = 0.0;
        double score = 0.0;
        bool readable_region = false;
        bool base_preview_read = false;
        std::string base_type;
        std::string base_preview_hex;
    };
    std::vector<candidate_t> candidates;
    std::set<std::uint64_t> seen_bases;
    for (std::uint64_t align : {8ull, 16ull, 32ull, 64ull})
    {
        const std::uint64_t step = align;
        for (std::uint64_t lead = 0; lead <= base_search_window && lead <= min_va; lead += step)
        {
            const std::uint64_t raw = min_va - lead;
            const std::uint64_t candidate = raw & ~(align - 1ull);
            if (candidate > min_va || seen_bases.count(candidate) != 0)
                continue;
            if (fields.back().va - candidate > max_span)
                continue;
            seen_bases.insert(candidate);
            std::uint64_t alignment_cost = 0;
            for (const auto& f : fields)
                alignment_cost += (f.va - candidate) % align;
            bool readable = false;
            if (has_pid)
            {
                driver_bridge::memory_region_t region{};
                readable = query_region(pid, candidate, region) &&
                           is_readable(region) &&
                           region_contains_address(region, fields.back().va);
            }
            candidate_t c;
            c.base = candidate;
            c.alignment = align;
            c.span = fields.back().va - candidate;
            c.leading_slack = min_va - candidate;
            c.alignment_cost = alignment_cost;
            c.readable_region = readable;
            if (has_pid && readable)
            {
                std::vector<std::uint8_t> base_preview;
                if (read_bytes(pid, candidate, 16, base_preview) && !base_preview.empty())
                {
                    c.base_preview_read = true;
                    c.base_type = infer_scalar_type_for_process(pid, base_preview);
                    c.base_preview_hex = bytes_to_hex(base_preview, 16);
                }
            }
            const double align_penalty = fields.empty() ? 0.0 : static_cast<double>(alignment_cost) / static_cast<double>(fields.size() * align);
            const double span_ratio = max_span ? static_cast<double>(c.span) / static_cast<double>(max_span) : 1.0;
            const double slack_ratio = max_span ? static_cast<double>(c.leading_slack) / static_cast<double>(max_span) : 1.0;
            c.alignment_score = 1.0 - std::min(1.0, align_penalty);
            c.compact_score = 1.0 - std::min(1.0, span_ratio);
            if (fields.size() < 2)
                c.leading_score = c.leading_slack == 0 ? 0.92 : 0.35;
            else if (c.leading_slack == 0)
                c.leading_score = 0.76;
            else if (c.leading_slack <= 0x100 && (c.leading_slack % align) == 0)
                c.leading_score = 0.88;
            else if (c.leading_slack <= 0x400)
                c.leading_score = 0.58;
            else
                c.leading_score = 0.30;
            c.score = 0.30 + c.alignment_score * 0.24 + c.compact_score * 0.12 + c.leading_score * 0.18;
            c.score -= std::min(0.08, slack_ratio * 0.08);
            if (has_pid)
                c.score += readable ? 0.10 : -0.08;
            if (c.base_type == "code_pointer")
                c.score += 0.11;
            else if (c.base_type == "pointer")
                c.score += 0.08;
            else if (c.base_type == "zero")
                c.score -= 0.03;
            c.score = clamp_score(c.score);
            candidates.push_back(c);
        }
    }
    if (candidates.empty())
    {
        candidate_t c;
        c.base = min_va;
        c.alignment = 1;
        c.span = fields.back().va - min_va;
        c.score = 0.5;
        candidates.push_back(c);
    }
    std::sort(candidates.begin(), candidates.end(), [](const candidate_t& a, const candidate_t& b) {
        if (a.score == b.score)
            return a.base > b.base;
        return a.score > b.score;
    });
    std::uint64_t best_base = candidates.front().base;
    json candidate_rows = json::array();
    for (const auto& c : candidates)
    {
        if (candidate_rows.size() >= 16)
            break;
        json row;
        row["base_va"] = sa_format_address(c.base);
        row["alignment"] = c.alignment;
        row["span"] = c.span;
        row["lowest_field_offset"] = c.leading_slack;
        row["alignment_cost"] = c.alignment_cost;
        row["score"] = c.score;
        row["readable_region"] = c.readable_region;
        row["base_preview_read"] = c.base_preview_read;
        if (c.base_preview_read)
        {
            row["base_type"] = c.base_type;
            row["base_preview_hex"] = c.base_preview_hex;
        }
        row["score_components"] = {
            {"alignment", c.alignment_score},
            {"compact", c.compact_score},
            {"leading_slack", c.leading_score}
        };
        candidate_rows.push_back(std::move(row));
    }
    json arr = json::array();
    for (const auto& f : fields)
    {
        json row;
        row["name"] = f.name;
        row["va"] = sa_format_address(f.va);
        row["offset"] = f.va - best_base;
        std::vector<std::uint8_t> preview;
        if (has_pid && read_bytes(pid, f.va, 16, preview) && !preview.empty())
        {
            row["type"] = infer_scalar_type_for_process(pid, preview);
            row["preview_hex"] = bytes_to_hex(preview, 16);
            row["preview_size"] = preview.size();
        }
        else
        {
            row["type"] = "unknown";
        }
        arr.push_back(std::move(row));
    }
    json result;
    result["base_va"] = sa_format_address(best_base);
    result["fields"] = std::move(arr);
    result["span"] = fields.back().va - best_base;
    result["candidate_bases"] = std::move(candidate_rows);
    result["candidate_count"] = candidates.size();
    result["base_search_window"] = base_search_window;
    result["selected_score"] = candidates.front().score;
    return tool_result_t::ok(result);
}

tool_result_t array_detect(const json& params)
{
    const std::uint64_t started_ms = GetTickCount64();
    active_process_scope_t scope(params);
    if (!scope.ok())
        return tool_result_t::error(scope.error());
    std::uint64_t base = 0;
    if (!parse_address_param(params, "base_va", base) || base == 0)
        return tool_result_t::error("'base_va' is required.");
    std::uint64_t suspected_size = 0;
    if (!params.contains("suspected_size") || !parse_u64_value(params["suspected_size"], suspected_size) || suspected_size == 0)
        return tool_result_t::error("'suspected_size' is required.");
    suspected_size = std::clamp<std::uint64_t>(suspected_size, 1, 0x100000);
    const std::size_t max_elements = static_cast<std::size_t>(numeric_param(params, "max_elements", 256, 2, 4096));
    const std::uint64_t timeout_ms = numeric_param(params, "timeout_ms", 2500, 100, 60000);
    bool deadline_hit = false;
    auto timed_out = [&]() -> bool {
        if (GetTickCount64() - started_ms < timeout_ms)
            return false;
        deadline_hit = true;
        return true;
    };
    diag::log_tagged_fmt("struct_adv",
                         "array_detect enter pid=%u base=%s element_size=%llu max_elements=%zu timeout_ms=%llu",
                         scope.pid(),
                         sa_format_address(base).c_str(),
                         static_cast<unsigned long long>(suspected_size),
                         max_elements,
                         static_cast<unsigned long long>(timeout_ms));
    std::vector<std::uint8_t> bulk;
    const std::uint64_t total_size64 = suspected_size > 0 && max_elements <= (std::numeric_limits<std::uint64_t>::max() / suspected_size) ?
        suspected_size * static_cast<std::uint64_t>(max_elements) : 0;
    bool bulk_ok = false;
    if (total_size64 != 0 && total_size64 <= 4ull * 1024ull * 1024ull)
    {
        diag::log_tagged_fmt("struct_adv",
                             "array_detect bulk_read_begin pid=%u base=%s bytes=%llu",
                             scope.pid(),
                             sa_format_address(base).c_str(),
                             static_cast<unsigned long long>(total_size64));
        bulk_ok = read_bytes(scope.pid(), base, static_cast<std::size_t>(total_size64), bulk) && bulk.size() >= suspected_size;
        diag::log_tagged_fmt("struct_adv",
                             "array_detect bulk_read_end pid=%u ok=%d bytes=%zu elapsed_ms=%llu",
                             scope.pid(),
                             bulk_ok ? 1 : 0,
                             bulk.size(),
                             static_cast<unsigned long long>(GetTickCount64() - started_ms));
    }
    auto read_element = [&](std::size_t index, std::vector<std::uint8_t>& out) -> bool {
        out.clear();
        const std::uint64_t offset64 = static_cast<std::uint64_t>(index) * suspected_size;
        if (bulk_ok && offset64 + suspected_size <= bulk.size())
        {
            const auto begin = bulk.begin() + static_cast<std::ptrdiff_t>(offset64);
            out.assign(begin, begin + static_cast<std::ptrdiff_t>(suspected_size));
            return true;
        }
        diag::log_tagged_fmt("struct_adv",
                             "array_detect element_read_begin pid=%u index=%zu va=%s size=%llu elapsed_ms=%llu",
                             scope.pid(),
                             index,
                             sa_format_address(base + offset64).c_str(),
                             static_cast<unsigned long long>(suspected_size),
                             static_cast<unsigned long long>(GetTickCount64() - started_ms));
        const bool ok = read_bytes(scope.pid(), base + offset64, static_cast<std::size_t>(suspected_size), out) && !out.empty();
        diag::log_tagged_fmt("struct_adv",
                             "array_detect element_read_end pid=%u index=%zu ok=%d bytes=%zu elapsed_ms=%llu",
                             scope.pid(),
                             index,
                             ok ? 1 : 0,
                             out.size(),
                             static_cast<unsigned long long>(GetTickCount64() - started_ms));
        return ok;
    };
    std::vector<std::uint8_t> first;
    if (!read_element(0, first) || first.empty())
        return tool_result_t::error("Failed to read first element.");
    const std::string first_type = infer_scalar_type(first);
    diag::log_tagged_fmt("struct_adv",
                         "array_detect first_type pid=%u type=%s bytes=%zu elapsed_ms=%llu",
                         scope.pid(),
                         first_type.c_str(),
                         first.size(),
                         static_cast<unsigned long long>(GetTickCount64() - started_ms));
    std::size_t similar = 1;
    std::map<std::string, std::size_t> type_counts;
    type_counts[first_type] = 1;
    std::size_t matching_prefix_bytes = 0;
    for (std::size_t i = 1; i < max_elements; ++i)
    {
        if (timed_out())
            break;
        std::vector<std::uint8_t> data;
        if (!read_element(i, data) || data.empty())
        {
            diag::log_tagged_fmt("struct_adv",
                                 "array_detect break_read_failed pid=%u index=%zu elapsed_ms=%llu",
                                 scope.pid(),
                                 i,
                                 static_cast<unsigned long long>(GetTickCount64() - started_ms));
            break;
        }
        const std::string type = infer_scalar_type(data);
        ++type_counts[type];
        diag::log_tagged_fmt("struct_adv",
                             "array_detect element_infer pid=%u index=%zu type=%s first_type=%s elapsed_ms=%llu",
                             scope.pid(),
                             i,
                             type.c_str(),
                             first_type.c_str(),
                             static_cast<unsigned long long>(GetTickCount64() - started_ms));
        for (std::size_t j = 0; j < data.size() && j < first.size(); ++j)
        {
            if (data[j] == first[j])
                ++matching_prefix_bytes;
            else
                break;
        }
        if (type == first_type)
            ++similar;
        else if (i > 8)
        {
            diag::log_tagged_fmt("struct_adv",
                                 "array_detect break_type_diverged pid=%u index=%zu type=%s first_type=%s similar=%zu elapsed_ms=%llu",
                                 scope.pid(),
                                 i,
                                 type.c_str(),
                                 first_type.c_str(),
                                 similar,
                                 static_cast<unsigned long long>(GetTickCount64() - started_ms));
            break;
        }
    }
    const std::size_t byte_type_similar = similar;
    bool access_pattern_available = false;
    std::size_t access_pattern_elements = 0;
    std::size_t access_pattern_similar = 0;
    double access_pattern_similarity = 0.0;
    json access_pattern_rows = json::array();
    {
        struct_recon::reconstructed_struct_t observed;
        std::vector<struct_recon::access_record_t> access_log;
        {
            std::lock_guard<std::mutex> lk(struct_recon::g_state.mutex);
            observed = struct_recon::g_state.current;
            access_log = struct_recon::g_state.access_log;
        }
        const std::uint64_t total_range = suspected_size > 0 && max_elements <= (std::numeric_limits<std::uint64_t>::max() / suspected_size) ?
            suspected_size * static_cast<std::uint64_t>(max_elements) : 0;
        if (observed.base_address != 0 && total_range != 0 && !access_log.empty())
        {
            std::vector<std::set<access_pattern_sig_t>> element_patterns(max_elements);
            for (const auto& access : access_log)
            {
                const std::uint64_t absolute = observed.base_address + access.access_offset;
                if (absolute < base || absolute >= base + total_range)
                    continue;
                const std::uint64_t rel = absolute - base;
                const std::size_t element = static_cast<std::size_t>(rel / suspected_size);
                if (element >= max_elements)
                    continue;
                access_pattern_sig_t sig;
                sig.offset = rel % suspected_size;
                sig.rip = access.instruction_addr;
                sig.size = access.access_size;
                sig.write = access.is_write;
                element_patterns[element].insert(sig);
            }
            std::size_t anchor_index = max_elements;
            for (std::size_t i = 0; i < element_patterns.size(); ++i)
            {
                if (!element_patterns[i].empty())
                {
                    anchor_index = i;
                    break;
                }
            }
            if (anchor_index < max_elements)
            {
                access_pattern_available = true;
                const auto& anchor = element_patterns[anchor_index];
                double total_similarity = 0.0;
                std::size_t comparable = 0;
                for (std::size_t i = anchor_index; i < element_patterns.size(); ++i)
                {
                    if (element_patterns[i].empty())
                        continue;
                    ++access_pattern_elements;
                    std::size_t intersection = 0;
                    for (auto off : element_patterns[i])
                        if (anchor.count(off) != 0)
                            ++intersection;
                    const std::size_t uni = anchor.size() + element_patterns[i].size() - intersection;
                    const double jaccard = uni == 0 ? 0.0 : static_cast<double>(intersection) / static_cast<double>(uni);
                    if (jaccard >= 0.5)
                        ++access_pattern_similar;
                    total_similarity += jaccard;
                    ++comparable;
                    if (access_pattern_rows.size() < 32)
                    {
                        json row;
                        row["element_index"] = i;
                        row["similarity"] = jaccard;
                        json signatures = json::array();
                        std::size_t reads = 0;
                        std::size_t writes = 0;
                        for (const auto& sig : element_patterns[i])
                        {
                            if (sig.write)
                                ++writes;
                            else
                                ++reads;
                            signatures.push_back(access_pattern_sig_json(sig));
                        }
                        row["read_signature_count"] = reads;
                        row["write_signature_count"] = writes;
                        row["access_signatures"] = std::move(signatures);
                        access_pattern_rows.push_back(std::move(row));
                    }
                }
                access_pattern_similarity = comparable == 0 ? 0.0 : total_similarity / static_cast<double>(comparable);
            }
        }
    }
    const bool access_pattern_decisive = access_pattern_available && access_pattern_elements >= 2;
    const double confidence = access_pattern_decisive ?
        std::min(0.99, 0.35 + access_pattern_similarity * 0.64) :
        std::min(0.99, static_cast<double>(byte_type_similar) / std::min(static_cast<double>(max_elements), 32.0));
    json type_histogram = json::object();
    for (const auto& [type, count] : type_counts)
        type_histogram[type] = count;
    json result;
    result["is_array"] = access_pattern_decisive ? access_pattern_similar >= 2 : byte_type_similar >= 3;
    result["element_count"] = access_pattern_decisive ? access_pattern_similar : byte_type_similar;
    result["element_size"] = suspected_size;
    result["confidence"] = confidence;
    result["similarity_backend"] = access_pattern_decisive ? "access_pattern" : "byte_type";
    result["access_pattern_available"] = access_pattern_available;
    result["access_pattern_decisive"] = access_pattern_decisive;
    result["access_pattern_element_count"] = access_pattern_elements;
    result["access_pattern_similar_count"] = access_pattern_similar;
    result["access_pattern_similarity"] = access_pattern_similarity;
    result["access_patterns"] = std::move(access_pattern_rows);
    result["first_element_type_hint"] = first_type;
    result["type_histogram"] = std::move(type_histogram);
    result["matching_prefix_bytes"] = matching_prefix_bytes;
    result["timeout_ms"] = timeout_ms;
    result["deadline_hit"] = deadline_hit;
    result["bulk_read"] = bulk_ok;
    result["elapsed_ms"] = GetTickCount64() - started_ms;
    diag::log_tagged_fmt("struct_adv",
                         "array_detect exit pid=%u is_array=%d similar=%zu confidence=%.3f deadline=%d bulk=%d elapsed_ms=%llu",
                         scope.pid(),
                         similar >= 3 ? 1 : 0,
                         similar,
                         confidence,
                         deadline_hit ? 1 : 0,
                         bulk_ok ? 1 : 0,
                         static_cast<unsigned long long>(GetTickCount64() - started_ms));
    return tool_result_t::ok(result);
}

tool_result_t compare_snapshots(const json& params)
{
    const auto started = std::chrono::steady_clock::now();
    const std::string a_id = string_param(params, "snapshot_a_id");
    const std::string b_id = string_param(params, "snapshot_b_id");
    if (a_id.empty() || b_id.empty())
        return tool_result_t::error("'snapshot_a_id' and 'snapshot_b_id' are required.");
    std::uint64_t base = 0;
    if (!parse_address_param(params, "base_va", base) || base == 0)
        return tool_result_t::error("'base_va' is required.");
    const std::uint64_t struct_size = numeric_param(params, "struct_size", 512, 1, 65536);

    std::vector<std::uint8_t> a_bytes;
    std::vector<std::uint8_t> b_bytes;
    store::memory_snapshot_t a_mem;
    store::memory_snapshot_t b_mem;
    bool found = false;
    std::uint32_t type_pid = 0;
    std::string snapshot_source;
    if (store::find_memory_snapshot(a_id, a_mem) && store::find_memory_snapshot(b_id, b_mem))
    {
        if (base >= a_mem.base_va && base + struct_size <= a_mem.base_va + a_mem.data.size() &&
            base >= b_mem.base_va && base + struct_size <= b_mem.base_va + b_mem.data.size())
        {
            const auto a_off = static_cast<std::ptrdiff_t>(base - a_mem.base_va);
            const auto b_off = static_cast<std::ptrdiff_t>(base - b_mem.base_va);
            a_bytes.assign(a_mem.data.begin() + a_off, a_mem.data.begin() + a_off + static_cast<std::ptrdiff_t>(struct_size));
            b_bytes.assign(b_mem.data.begin() + b_off, b_mem.data.begin() + b_off + static_cast<std::ptrdiff_t>(struct_size));
            found = true;
            type_pid = a_mem.pid == b_mem.pid ? a_mem.pid : 0;
            snapshot_source = "artifact_store";
        }
    }
    if (!found)
    {
        auto a_snap = find_scanner_snapshot(a_id);
        auto b_snap = find_scanner_snapshot(b_id);
        if (a_snap && b_snap) {
            found = extract_snapshot_region(*a_snap, base, struct_size, a_bytes) &&
                    extract_snapshot_region(*b_snap, base, struct_size, b_bytes);
            if (found)
                snapshot_source = "scanner_snapshot_diff";
        }
    }
    if (!found)
        return tool_result_t::error("Snapshots not found in RE artifact snapshots or scanner snapshot_diff store.");

    json changes = json::array();
    std::size_t total_changed_bytes = 0;
    bool change_rows_truncated = false;
    for (std::size_t i = 0; i < a_bytes.size() && i < b_bytes.size();)
    {
        if (a_bytes[i] == b_bytes[i])
        {
            ++i;
            continue;
        }
        const std::size_t start = i;
        while (i < a_bytes.size() && i < b_bytes.size() && a_bytes[i] != b_bytes[i] && i - start < 32)
            ++i;
        json row;
        row["offset"] = start;
        row["va"] = sa_format_address(base + start);
        row["size"] = i - start;
        std::vector<std::uint8_t> before(a_bytes.begin() + static_cast<std::ptrdiff_t>(start), a_bytes.begin() + static_cast<std::ptrdiff_t>(i));
        std::vector<std::uint8_t> after(b_bytes.begin() + static_cast<std::ptrdiff_t>(start), b_bytes.begin() + static_cast<std::ptrdiff_t>(i));
        row["before_hex"] = bytes_to_hex(before);
        row["after_hex"] = bytes_to_hex(after);
        row["before_type"] = type_pid != 0 ? infer_scalar_type_for_process(type_pid, before) : infer_scalar_type(before);
        row["after_type"] = type_pid != 0 ? infer_scalar_type_for_process(type_pid, after) : infer_scalar_type(after);
        if (i - start <= 8)
            add_numeric_delta(row, a_bytes, b_bytes, start, i - start);
        total_changed_bytes += i - start;
        if (changes.size() < 512)
            changes.push_back(std::move(row));
        else
            change_rows_truncated = true;
    }
    json field_summaries = json::array();
    std::string field_summary_source = "aligned_scalar_fallback";
    auto observed_fields = current_fields_for_base(base);
    if (!observed_fields.empty())
    {
        field_summary_source = "struct_recon_current_fields";
        for (const auto& field : observed_fields)
        {
            if (field.size <= 0 || field.offset >= struct_size)
                continue;
            const std::size_t offset = static_cast<std::size_t>(field.offset);
            const std::size_t size = static_cast<std::size_t>(std::min<std::uint64_t>(field.size, struct_size - field.offset));
            std::size_t changed_count = 0;
            if (!any_changed_in_range(a_bytes, b_bytes, offset, size, changed_count))
                continue;
            json row;
            row["name"] = field.name;
            row["offset"] = field.offset;
            row["va"] = sa_format_address(base + field.offset);
            row["size"] = size;
            row["type"] = struct_recon::field_type_name(field.type);
            row["changed_bytes"] = changed_count;
            std::vector<std::uint8_t> before(a_bytes.begin() + static_cast<std::ptrdiff_t>(offset), a_bytes.begin() + static_cast<std::ptrdiff_t>(offset + size));
            std::vector<std::uint8_t> after(b_bytes.begin() + static_cast<std::ptrdiff_t>(offset), b_bytes.begin() + static_cast<std::ptrdiff_t>(offset + size));
            row["before_hex"] = bytes_to_hex(before, 32);
            row["after_hex"] = bytes_to_hex(after, 32);
            add_numeric_delta(row, a_bytes, b_bytes, offset, size);
            field_summaries.push_back(std::move(row));
            if (field_summaries.size() >= 512)
                break;
        }
    }
    if (field_summaries.empty())
    {
        field_summary_source = "aligned_scalar_fallback";
        const std::size_t limit = std::min(a_bytes.size(), b_bytes.size());
        for (std::size_t offset = 0; offset < limit && field_summaries.size() < 512;)
        {
            if (a_bytes[offset] == b_bytes[offset])
            {
                ++offset;
                continue;
            }
            std::size_t size = 1;
            for (std::size_t candidate : {8ull, 4ull, 2ull})
            {
                if (offset % candidate == 0 && offset + candidate <= limit)
                {
                    std::size_t changed_count = 0;
                    if (any_changed_in_range(a_bytes, b_bytes, offset, candidate, changed_count))
                    {
                        size = candidate;
                        break;
                    }
                }
            }
            std::size_t changed_count = 0;
            any_changed_in_range(a_bytes, b_bytes, offset, size, changed_count);
            json row;
            char name_buf[32];
            std::snprintf(name_buf, sizeof(name_buf), "field_%03llX", static_cast<unsigned long long>(offset));
            row["name"] = name_buf;
            row["offset"] = offset;
            row["va"] = sa_format_address(base + offset);
            row["size"] = size;
            row["changed_bytes"] = changed_count;
            std::vector<std::uint8_t> before(a_bytes.begin() + static_cast<std::ptrdiff_t>(offset), a_bytes.begin() + static_cast<std::ptrdiff_t>(offset + size));
            std::vector<std::uint8_t> after(b_bytes.begin() + static_cast<std::ptrdiff_t>(offset), b_bytes.begin() + static_cast<std::ptrdiff_t>(offset + size));
            row["before_hex"] = bytes_to_hex(before, 32);
            row["after_hex"] = bytes_to_hex(after, 32);
            row["before_type"] = type_pid != 0 ? infer_scalar_type_for_process(type_pid, before) : infer_scalar_type(before);
            row["after_type"] = type_pid != 0 ? infer_scalar_type_for_process(type_pid, after) : infer_scalar_type(after);
            add_numeric_delta(row, a_bytes, b_bytes, offset, size);
            field_summaries.push_back(std::move(row));
            offset += size;
        }
    }
    json result;
    result["snapshot_a_id"] = a_id;
    result["snapshot_b_id"] = b_id;
    result["base_va"] = sa_format_address(base);
    result["struct_size"] = struct_size;
    result["bytes_compared"] = std::min(a_bytes.size(), b_bytes.size());
    result["snapshot_source"] = snapshot_source;
    result["changes"] = std::move(changes);
    result["change_count"] = result["changes"].size();
    result["change_rows_truncated"] = change_rows_truncated;
    result["changed_byte_count"] = total_changed_bytes;
    result["field_summaries"] = std::move(field_summaries);
    result["field_summary_count"] = result["field_summaries"].size();
    result["field_summary_source"] = field_summary_source;
    result["saw_mutation"] = result["change_count"].get<std::size_t>() > 0;
    result["snapshots_equal"] = result["change_count"].get<std::size_t>() == 0;
    result["functional_success"] = result["change_count"].get<std::size_t>() > 0;
    result["elapsed_ms"] = static_cast<std::uint64_t>(std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - started).count());
    result["evidence"] = {
        {"snapshot_a_id", a_id},
        {"snapshot_b_id", b_id},
        {"snapshot_source", snapshot_source},
        {"bytes_compared", result["bytes_compared"]},
        {"mutation_observed", result["functional_success"]},
        {"changed_byte_count", result["changed_byte_count"]},
        {"field_summary_source", field_summary_source}
    };
    if (result["change_count"].get<std::size_t>() == 0) {
        result["zero_change_reason"] = "snapshots were found and compared, but no byte differences were observed in the requested struct range";
        return tool_result_t::error("Struct snapshot comparison found zero changes; no mutation evidence was observed.", result);
    }
    return tool_result_t::ok(result);
}
}
