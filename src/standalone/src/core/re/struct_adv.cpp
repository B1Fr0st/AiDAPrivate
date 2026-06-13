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
    for (const auto& field : snapshot.fields)
        fields.push_back(field_json(field));
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
    std::uint64_t best_base = min_va;
    std::uint64_t best_cost = std::numeric_limits<std::uint64_t>::max();
    for (std::uint64_t align : {8ull, 16ull, 32ull})
    {
        const std::uint64_t candidate = min_va & ~(align - 1ull);
        if (fields.back().va - candidate > max_span)
            continue;
        std::uint64_t cost = 0;
        for (const auto& f : fields)
            cost += (f.va - candidate) % align;
        if (cost < best_cost)
        {
            best_cost = cost;
            best_base = candidate;
        }
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
    const double confidence = std::min(0.99, static_cast<double>(similar) / std::min(static_cast<double>(max_elements), 32.0));
    json type_histogram = json::object();
    for (const auto& [type, count] : type_counts)
        type_histogram[type] = count;
    json result;
    result["is_array"] = similar >= 3;
    result["element_count"] = similar;
    result["element_size"] = suspected_size;
    result["confidence"] = confidence;
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
        }
    }
    if (!found)
    {
        auto a_snap = find_scanner_snapshot(a_id);
        auto b_snap = find_scanner_snapshot(b_id);
        if (a_snap && b_snap)
            found = extract_snapshot_region(*a_snap, base, struct_size, a_bytes) &&
                    extract_snapshot_region(*b_snap, base, struct_size, b_bytes);
    }
    if (!found)
        return tool_result_t::error("Snapshots not found in RE artifact snapshots or scanner snapshot_diff store.");

    json changes = json::array();
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
        changes.push_back(std::move(row));
        if (changes.size() >= 512)
            break;
    }
    json result;
    result["snapshot_a_id"] = a_id;
    result["snapshot_b_id"] = b_id;
    result["base_va"] = sa_format_address(base);
    result["struct_size"] = struct_size;
    result["changes"] = std::move(changes);
    result["change_count"] = result["changes"].size();
    return tool_result_t::ok(result);
}
}
