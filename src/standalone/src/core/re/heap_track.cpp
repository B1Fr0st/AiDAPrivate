#include "heap_track.hpp"

#include "artifact_store.hpp"
#include "../infra/executor.hpp"
#include "../../helpers/diag_log.hpp"

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cstring>
#include <map>
#include <mutex>
#include <set>
#include <thread>
#include <utility>

namespace re::heap_track
{
namespace
{
constexpr const char* kHeapEventBackend = "kernel_context_hwbp_rtlallocateheap_return_poll";
constexpr const char* kHeapSnapshotBackend = "snapshot_diff";
constexpr const char* kHeapUnavailableBackend = "kernel_context_unavailable";

std::uint64_t deadline_remaining_ms()
{
    const std::uint64_t deadline = mcp_standalone::current_call_deadline_ms();
    if (deadline == 0)
        return 0;
    const std::uint64_t now = GetTickCount64();
    return deadline > now ? deadline - now : 0;
}

bool heap_call_cancelled(const char* phase, std::uint32_t pid, std::uint64_t started_ms)
{
    if (mcp_standalone::current_call_cancelled())
    {
        diag::log_tagged_fmt("heap_track", "cancelled phase=%s pid=%u elapsed_ms=%llu diag_id=%s",
                             phase ? phase : "",
                             pid,
                             static_cast<unsigned long long>(GetTickCount64() - started_ms),
                             mcp_standalone::current_call_diag_id());
        return true;
    }
    const std::uint64_t deadline = mcp_standalone::current_call_deadline_ms();
    if (deadline != 0 && GetTickCount64() >= deadline)
    {
        diag::log_tagged_fmt("heap_track", "deadline_reached phase=%s pid=%u elapsed_ms=%llu diag_id=%s",
                             phase ? phase : "",
                             pid,
                             static_cast<unsigned long long>(GetTickCount64() - started_ms),
                             mcp_standalone::current_call_diag_id());
        return true;
    }
    return false;
}

json heap_cancel_detail(const char* action, std::uint32_t pid, std::uint64_t started_ms)
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

bool session_event_active(const store::heap_session_t& session)
{
    return session.hw_slot >= 0 && !session.tids.empty();
}

const char* effective_backend(const store::heap_session_t& session)
{
    return session_event_active(session) ? kHeapEventBackend : kHeapUnavailableBackend;
}

bool capture_matches(const store::heap_session_t& session, const store::heap_capture_t& cap)
{
    if (cap.va == 0 || cap.size == 0)
        return false;
    if (session.min_size != 0 && cap.size < session.min_size)
        return false;
    if (session.max_size != 0 && cap.size > session.max_size)
        return false;
    if (session.alignment != 0 && (cap.va % session.alignment) != 0)
        return false;
    return true;
}

void add_capture(std::vector<store::heap_capture_t>& out,
                 const store::heap_session_t& session,
                 std::uint64_t va,
                 std::uint64_t size)
{
    store::heap_capture_t cap;
    cap.va = va;
    cap.size = size;
    cap.alignment = va == 0 ? 0 : (va & (~va + 1));
    cap.timestamp_ms = unix_time_ms();
    if (capture_matches(session, cap))
        out.push_back(std::move(cap));
}

bool append_focus_captures(store::heap_session_t& session, const json& params)
{
    std::uint64_t va = 0;
    if (!parse_address_param(params, "focus_va", va) && !parse_address_param(params, "capture_va", va) && !parse_address_param(params, "allocation_va", va))
        return false;
    std::uint64_t size = numeric_param(params, "focus_size", 0, 0, 0x7FFFFFFF);
    if (size == 0)
        size = numeric_param(params, "allocation_size", 0, 0, 0x7FFFFFFF);
    if (size == 0)
    {
        driver_bridge::memory_region_t region{};
        if (query_region(session.pid, va, region) && region.base + region.size > va)
            size = region.base + region.size - va;
    }
    const std::uint32_t count = static_cast<std::uint32_t>(numeric_param(params, "focus_count", 1, 1, 4096));
    std::uint64_t stride = numeric_param(params, "focus_stride", size, 0, 0x7FFFFFFF);
    if (stride == 0)
        stride = size;
    std::set<std::uint64_t> existing;
    for (const auto& cap : session.captures)
        existing.insert(cap.va);
    const std::size_t before = session.captures.size();
    for (std::uint32_t i = 0; i < count && session.captures.size() < session.max_captures; ++i)
    {
        const std::uint64_t current = va + static_cast<std::uint64_t>(i) * stride;
        if (current == 0 || existing.count(current) != 0)
            continue;
        driver_bridge::memory_region_t region{};
        if (!query_region(session.pid, current, region) || !is_readable(region))
            continue;
        existing.insert(current);
        add_capture(session.captures, session, current, size);
    }
    return session.captures.size() > before;
}

std::vector<store::heap_capture_t> sample_heap(std::uint32_t pid, const store::heap_session_t& session, std::size_t max_entries)
{
    const std::uint64_t sample_started_ms = GetTickCount64();
    std::vector<store::heap_capture_t> out;
    std::uint64_t sample_checks = 0;
    auto sample_cancelled = [&](const char* phase) -> bool {
        if (mcp_standalone::current_call_cancelled())
        {
            diag::log_tagged_fmt("heap_track",
                "sample_heap cancelled phase=%s pid=%u captured=%zu max=%zu elapsed_ms=%llu diag_id=%s",
                phase ? phase : "",
                pid,
                out.size(),
                max_entries,
                static_cast<unsigned long long>(GetTickCount64() - sample_started_ms),
                mcp_standalone::current_call_diag_id());
            return true;
        }
        const std::uint64_t deadline = mcp_standalone::current_call_deadline_ms();
        if (deadline != 0 && GetTickCount64() >= deadline)
        {
            diag::log_tagged_fmt("heap_track",
                "sample_heap deadline phase=%s pid=%u captured=%zu max=%zu elapsed_ms=%llu diag_id=%s",
                phase ? phase : "",
                pid,
                out.size(),
                max_entries,
                static_cast<unsigned long long>(GetTickCount64() - sample_started_ms),
                mcp_standalone::current_call_diag_id());
            return true;
        }
        return false;
    };
    driver_bridge::peb_info_t peb{};
    if (driver_bridge::read_peb_for(pid, peb) && peb.peb_address != 0)
    {
        std::uint32_t num_heaps = 0;
        std::uint64_t heaps_ptr = 0;
        read_u32(pid, peb.peb_address + 0xE8, num_heaps);
        read_u64(pid, peb.peb_address + 0xF0, heaps_ptr);
        if (num_heaps > 0 && num_heaps <= 256 && heaps_ptr != 0)
        {
            for (std::uint32_t h = 0; h < num_heaps && out.size() < max_entries; ++h)
            {
                if (sample_cancelled("heap_iter"))
                    return out;
                std::uint64_t heap_base = 0;
                if (!read_u64(pid, heaps_ptr + h * 8ull, heap_base) || heap_base == 0)
                    continue;
                const std::uint64_t seg_list_head = heap_base + 0x120;
                std::uint64_t seg_flink = 0;
                if (!read_u64(pid, seg_list_head, seg_flink))
                    continue;
                for (int seg_iter = 0; seg_flink != 0 && seg_flink != seg_list_head && seg_iter < 64 && out.size() < max_entries; ++seg_iter)
                {
                    if (sample_cancelled("segment_iter"))
                        return out;
                    const std::uint64_t segment_base = seg_flink - 0x18;
                    std::uint64_t first_entry = 0;
                    std::uint64_t last_entry = 0;
                    read_u64(pid, segment_base + 0x28, first_entry);
                    read_u64(pid, segment_base + 0x48, last_entry);
                    if (first_entry == 0 || last_entry <= first_entry || last_entry - first_entry > 512ull * 1024ull * 1024ull)
                    {
                        read_u64(pid, seg_flink, seg_flink);
                        continue;
                    }
                    std::uint64_t entry_addr = first_entry;
                    for (int entry_iter = 0; entry_addr != 0 && entry_addr < last_entry && entry_iter < 4096 && out.size() < max_entries; ++entry_iter)
                    {
                        if (((++sample_checks) & 0x3F) == 0 && sample_cancelled("entry_iter"))
                            return out;
                        std::uint16_t raw_size = 0;
                        std::vector<std::uint8_t> header;
                        if (!read_bytes(pid, entry_addr, 8, header) || header.size() < 8)
                            break;
                        std::memcpy(&raw_size, header.data(), sizeof(raw_size));
                        const std::uint8_t flags = header[2];
                        const std::uint64_t block_size = static_cast<std::uint64_t>(raw_size) * 16ull;
                        if (block_size == 0 || block_size > 64ull * 1024ull * 1024ull)
                            break;
                        const bool busy = (flags & 0x01) != 0;
                        const bool last = (flags & 0x10) != 0;
                        if (busy)
                            add_capture(out, session, entry_addr + 0x10, block_size > 0x10 ? block_size - 0x10 : block_size);
                        entry_addr += block_size;
                        if (last)
                            break;
                    }
                    read_u64(pid, seg_flink, seg_flink);
                }
            }
        }
    }

    if (out.empty())
    {
        std::size_t region_idx = 0;
        for (const auto& region : regions_for(pid, 8192))
        {
            if (out.size() >= max_entries)
                break;
            if (((region_idx++) & 0x3F) == 0 && sample_cancelled("region_iter"))
                return out;
            if (!is_readable(region) || region.type != MEM_PRIVATE || region.size < 16)
                continue;
            add_capture(out, session, region.base, region.size);
        }
    }
    if (out.size() > max_entries)
        out.resize(max_entries);
    return out;
}

json capture_json(const store::heap_session_t& session, const store::heap_capture_t& cap)
{
    json out;
    out["va"] = sa_format_address(cap.va);
    out["size"] = cap.size;
    out["allocation_size_estimate"] = cap.size;
    out["alignment"] = cap.alignment;
    out["timestamp_ms"] = cap.timestamp_ms;
    out["backend"] = effective_backend(session);
    driver_bridge::memory_region_t region{};
    if (query_region(session.pid, cap.va, region))
    {
        out["heap_membership"] = {
            {"committed", is_committed(region)},
            {"readable", is_readable(region)},
            {"writable", is_writable(region)},
            {"region_type", region.type},
            {"region_base", sa_format_address(region.base)},
            {"region_size", region.size}
        };
    }
    else
    {
        out["heap_membership"] = {
            {"committed", false},
            {"readable", false},
            {"writable", false},
            {"region_type", 0},
            {"region_base", nullptr},
            {"region_size", 0}
        };
    }
    json stack = json::array();
    for (auto va : cap.callstack)
        stack.push_back(sa_format_address(va));
    out["callstack"] = std::move(stack);
    return out;
}

json session_json(const store::heap_session_t& session)
{
    json out;
    out["session_id"] = session.id;
    out["process_id"] = session.pid;
    out["min_size"] = session.min_size;
    out["max_size"] = session.max_size;
    out["alignment"] = session.alignment;
    out["capture_callstack"] = session.capture_callstack;
    out["max_captures"] = session.max_captures;
    out["active"] = session.active;
    out["started_ms"] = session.started_ms;
    out["elapsed_ms"] = session.started_ms != 0 && unix_time_ms() >= session.started_ms ? unix_time_ms() - session.started_ms : 0;
    out["rtl_allocate_heap"] = session.rtl_allocate_heap ? json(sa_format_address(session.rtl_allocate_heap)) : json(nullptr);
    out["allocation_target"] = session.rtl_allocate_heap ? json(sa_format_address(session.rtl_allocate_heap)) : json(nullptr);
    out["hw_slot"] = session.hw_slot >= 0 ? json(session.hw_slot) : json(nullptr);
    out["thread_count"] = session.tids.size();
    out["armed_tids"] = session.tids;
    out["baseline_count"] = session.baseline.size();
    out["capture_count"] = session.captures.size();
    out["capture_queue_size"] = session.captures.size();
    out["positive_capture_count"] = session.captures.size();
    out["snapshot_capture_count"] = 0;
    out["event_capture_count"] = session_event_active(session) ? session.captures.size() : 0;
    out["saw_allocation_event"] = session_event_active(session) && !session.captures.empty();
    out["mutation_observed"] = !session.captures.empty();
    out["functional_success"] = !session.captures.empty();
    if (session.captures.empty())
        out["zero_capture_reason"] = session.active ? "heap tracking session is active but no kernel allocation captures have been observed yet" : "heap tracking session stopped with zero kernel allocation captures";
    out["backend"] = effective_backend(session);
    out["event_capture_active"] = session_event_active(session);
    out["event_backend_kind"] = kHeapEventBackend;
    out["snapshot_backend_kind"] = kHeapSnapshotBackend;
    out["event_backend_uses_debug_events"] = false;
    out["rtlallocateheap_inline_hook"] = false;
    out["kernel_context_polling"] = session_event_active(session);
    out["alignment_filter_active"] = session.alignment != 0;
    out["snapshot_diff_available"] = false;
    out["hwbp_evidence"] = {
        {"allocation_target", session.rtl_allocate_heap ? json(sa_format_address(session.rtl_allocate_heap)) : json(nullptr)},
        {"hw_slot", session.hw_slot >= 0 ? json(session.hw_slot) : json(nullptr)},
        {"armed_tids", session.tids},
        {"capture_queue_size", session.captures.size()},
        {"kernel_context_polling", session_event_active(session)}
    };
    return out;
}

json heap_session_lookup_error(const char* action, const std::string& id)
{
    auto sessions = store::list_heap_sessions(0);
    json active_ids = json::array();
    for (const auto& session : sessions)
        active_ids.push_back(session.id);
    diag::log_tagged_fmt("heap_track",
        "session_lookup action=%s requested_session_id='%s' found=0 active_count=%zu",
        action ? action : "",
        id.c_str(),
        sessions.size());
    return json{
        {"tool", "heap_track_manage"},
        {"action", action ? action : ""},
        {"session_id", id},
        {"validation_code", "heap_session_not_found"},
        {"active_session_count", sessions.size()},
        {"active_session_ids", active_ids}
    };
}

std::uint64_t resolve_rtl_allocate_heap(std::uint32_t pid)
{
    const std::uint64_t started_ms = GetTickCount64();
    const DWORD tid_at_entry = GetCurrentThreadId();
    diag::log_tagged_fmt("heap_track",
        "resolve_rtl_allocate_heap_enter pid=%u tid=%lu deadline_remaining_ms=%llu cancelled=%d diag_id=%s",
        pid,
        static_cast<unsigned long>(tid_at_entry),
        static_cast<unsigned long long>(deadline_remaining_ms()),
        mcp_standalone::current_call_cancelled() ? 1 : 0,
        mcp_standalone::current_call_diag_id());
    if (heap_call_cancelled("resolve_rtl_allocate_heap_enter", pid, started_ms))
        return 0;
    auto ntdll = find_module_by_name(pid, "ntdll.dll");
    if (!ntdll)
    {
        diag::log_tagged_fmt("heap_track",
            "resolve_rtl_allocate_heap_exit pid=%u tid=%lu va=0x0 elapsed_ms=%llu kernel_strict=0 gle=%lu reason=ntdll_not_found",
            pid,
            static_cast<unsigned long>(tid_at_entry),
            static_cast<unsigned long long>(GetTickCount64() - started_ms),
            static_cast<unsigned long>(GetLastError()));
        return 0;
    }
    if (heap_call_cancelled("resolve_rtl_allocate_heap_post_module", pid, started_ms))
        return 0;
    SetLastError(ERROR_SUCCESS);
    const std::uint64_t kernel_strict_started_ms = GetTickCount64();
    const std::uint64_t va = driver_bridge::resolve_export_for_kernel_strict(pid, ntdll->base, "RtlAllocateHeap");
    const DWORD gle = va != 0 ? ERROR_SUCCESS : GetLastError();
    diag::log_tagged_fmt("heap_track",
        "resolve_rtl_allocate_heap kernel_strict_result pid=%u tid=%lu va=0x%llX gle=%lu elapsed_ms=%llu module_base=0x%llX",
        pid,
        static_cast<unsigned long>(tid_at_entry),
        static_cast<unsigned long long>(va),
        static_cast<unsigned long>(gle),
        static_cast<unsigned long long>(GetTickCount64() - kernel_strict_started_ms),
        static_cast<unsigned long long>(ntdll->base));
    diag::log_tagged_fmt("heap_track",
        "resolve_rtl_allocate_heap_exit pid=%u tid=%lu va=0x%llX elapsed_ms=%llu kernel_strict=1 gle=%lu cancelled=%d deadline_remaining_ms=%llu",
        pid,
        static_cast<unsigned long>(tid_at_entry),
        static_cast<unsigned long long>(va),
        static_cast<unsigned long long>(GetTickCount64() - started_ms),
        static_cast<unsigned long>(gle),
        mcp_standalone::current_call_cancelled() ? 1 : 0,
        static_cast<unsigned long long>(deadline_remaining_ms()));
    return va;
}

std::size_t clear_session_breakpoints(const store::heap_session_t& session)
{
    if (session.hw_slot < 0 || session.hw_slot > 3)
        return 0;
    std::set<std::uint32_t> tids(session.tids.begin(), session.tids.end());
    std::size_t cleared = 0;
    for (auto tid : tids)
    {
        if (driver_bridge::clear_hardware_breakpoint(tid, session.hw_slot))
            ++cleared;
    }
    diag::log_tagged_fmt("heap_track",
        "breakpoint_clear session_id=%s pid=%u slot=%d tids=%zu cleared=%zu",
        session.id.c_str(),
        session.pid,
        session.hw_slot,
        tids.size(),
        cleared);
    return cleared;
}

std::optional<store::heap_session_t> event_session_for_pid(std::uint32_t pid)
{
    for (const auto& session : store::list_heap_sessions(pid))
    {
        if (session.active && session.hw_slot >= 0 && session.hw_slot <= 3 && session.rtl_allocate_heap != 0)
            return session;
    }
    return std::nullopt;
}

bool has_other_event_session(std::uint32_t pid, const std::string& except_id)
{
    for (const auto& session : store::list_heap_sessions(pid))
    {
        if (session.id != except_id && session.active && session.hw_slot >= 0 && session.rtl_allocate_heap != 0)
            return true;
    }
    return false;
}

std::vector<std::uint64_t> capture_callstack_addresses(std::uint32_t pid, const driver_bridge::thread_context_t& ctx, std::uint64_t return_address, bool enabled)
{
    std::vector<std::uint64_t> frames;
    if (!enabled)
        return frames;
    auto add_frame = [&](std::uint64_t address) {
        if (address == 0 || !find_module_for_address(pid, address))
            return;
        if (std::find(frames.begin(), frames.end(), address) == frames.end())
            frames.push_back(address);
    };
    add_frame(ctx.rip);
    add_frame(return_address);
    std::uint64_t rbp = ctx.rbp;
    for (int i = 0; i < 24 && rbp >= 0x10000; ++i)
    {
        std::uint64_t next_rbp = 0;
        std::uint64_t ret = 0;
        if (!read_u64(pid, rbp, next_rbp) || !read_u64(pid, rbp + 8, ret))
            break;
        add_frame(ret);
        if (next_rbp <= rbp)
            break;
        rbp = next_rbp;
    }
    if (frames.size() < 8)
    {
        std::vector<std::uint8_t> stack;
        if (read_bytes(pid, ctx.rsp, 0x200, stack))
        {
            const std::size_t aligned = stack.size() & ~static_cast<std::size_t>(7);
            for (std::size_t off = 0; off + 8 <= aligned && frames.size() < 32; off += 8)
            {
                std::uint64_t candidate = 0;
                std::memcpy(&candidate, stack.data() + off, sizeof(candidate));
                add_frame(candidate);
            }
        }
    }
    return frames;
}

struct pending_alloc_t
{
    std::uint64_t heap = 0;
    std::uint64_t flags = 0;
    std::uint64_t size = 0;
    std::uint64_t return_address = 0;
    std::uint64_t timestamp_ms = 0;
    std::vector<std::uint64_t> callstack;
};

struct heap_debug_state_t
{
    std::mutex mutex;
    std::map<std::uint32_t, pending_alloc_t> pending;
    std::atomic<bool> running{false};
    std::atomic<bool> polling{false};
    std::atomic<bool> attached{false};
    std::atomic<DWORD> error{0};
    std::atomic<std::uint32_t> pid{0};
};

heap_debug_state_t& heap_debug_state()
{
    static heap_debug_state_t state;
    return state;
}

void append_event_capture(store::heap_session_t session, const pending_alloc_t& pending, std::uint64_t allocation_va)
{
    store::heap_capture_t cap;
    cap.va = allocation_va;
    cap.size = pending.size;
    cap.alignment = allocation_va == 0 ? 0 : (allocation_va & (~allocation_va + 1));
    cap.timestamp_ms = unix_time_ms();
    cap.callstack = pending.callstack;
    if (!capture_matches(session, cap))
        return;
    session.captures.push_back(std::move(cap));
    while (session.captures.size() > session.max_captures)
        session.captures.erase(session.captures.begin());
    store::update_heap_session(session);
}

std::size_t arm_heap_existing_threads(std::uint32_t pid)
{
    auto session = event_session_for_pid(pid);
    if (!session) {
        diag::log_tagged_fmt("heap_track",
            "breakpoint_arm_existing_no_session pid=%u active_pid=%u",
            pid,
            driver_bridge::attached_pid());
        return 0;
    }
    const auto threads = threads_for(pid);
    std::size_t armed = 0;
    std::vector<std::uint32_t> armed_tids;
    auto dr_address = [](const driver_bridge::thread_context_t& ctx, int slot) -> std::uint64_t {
        switch (slot)
        {
        case 0: return ctx.dr0;
        case 1: return ctx.dr1;
        case 2: return ctx.dr2;
        case 3: return ctx.dr3;
        default: return 0;
        }
    };
    diag::log_tagged_fmt("heap_track",
        "breakpoint_arm_existing_begin pid=%u active_pid=%u session_id=%s thread_count=%zu slot=%d target=%s kernel=%d attached=%d status=%s last_error=%s",
        pid,
        driver_bridge::attached_pid(),
        session->id.c_str(),
        threads.size(),
        session->hw_slot,
        sa_format_address(session->rtl_allocate_heap).c_str(),
        driver_bridge::using_kernel_driver() ? 1 : 0,
        driver_bridge::attached_pid() == pid ? 1 : 0,
        driver_bridge::status().c_str(),
        driver_bridge::last_error().c_str());
    for (const auto& th : threads)
    {
        diag::log_tagged_fmt("heap_track",
            "breakpoint_arm_thread_begin pid=%u active_pid=%u session_id=%s tid=%u owner_pid=%u enum_state=%u priority=%d enum_rip=%s slot=%d target=%s",
            pid,
            driver_bridge::attached_pid(),
            session->id.c_str(),
            th.tid,
            th.owner_pid,
            th.state,
            th.priority,
            sa_format_address(th.rip).c_str(),
            session->hw_slot,
            sa_format_address(session->rtl_allocate_heap).c_str());
        if (th.tid == 0 || session->hw_slot < 0 || session->hw_slot > 3 || session->rtl_allocate_heap == 0) {
            diag::log_tagged_fmt("heap_track",
                "breakpoint_arm_thread_skip pid=%u session_id=%s tid=%u reason=invalid_candidate slot=%d target=%s owner_pid=%u",
                pid,
                session->id.c_str(),
                th.tid,
                session->hw_slot,
                sa_format_address(session->rtl_allocate_heap).c_str(),
                th.owner_pid);
            continue;
        }
        driver_bridge::thread_context_t before_ctx{};
        const bool before_ok = driver_bridge::get_thread_context(th.tid, before_ctx);
        const DWORD before_gle = before_ok ? ERROR_SUCCESS : GetLastError();
        const std::string before_status = driver_bridge::status();
        const std::string before_last_error = driver_bridge::last_error();
        diag::log_tagged_fmt("heap_track",
            "breakpoint_arm_thread_context_before pid=%u active_pid=%u session_id=%s tid=%u ok=%d gle=%lu rip=%s rsp=%s rflags=0x%llX dr0=%s dr1=%s dr2=%s dr3=%s dr6=0x%llX dr7=0x%llX status=%s last_error=%s",
            pid,
            driver_bridge::attached_pid(),
            session->id.c_str(),
            th.tid,
            before_ok ? 1 : 0,
            static_cast<unsigned long>(before_gle),
            sa_format_address(before_ctx.rip).c_str(),
            sa_format_address(before_ctx.rsp).c_str(),
            static_cast<unsigned long long>(before_ctx.rflags),
            sa_format_address(before_ctx.dr0).c_str(),
            sa_format_address(before_ctx.dr1).c_str(),
            sa_format_address(before_ctx.dr2).c_str(),
            sa_format_address(before_ctx.dr3).c_str(),
            static_cast<unsigned long long>(before_ctx.dr6),
            static_cast<unsigned long long>(before_ctx.dr7),
            before_status.c_str(),
            before_last_error.c_str());
        if (!before_ok) {
            diag::log_tagged_fmt("heap_track",
                "breakpoint_arm_thread_result pid=%u active_pid=%u session_id=%s tid=%u armed=0 reason=context_before_failed gle=%lu status=%s last_error=%s",
                pid,
                driver_bridge::attached_pid(),
                session->id.c_str(),
                th.tid,
                static_cast<unsigned long>(before_gle),
                before_status.c_str(),
                before_last_error.c_str());
            continue;
        }
        const bool set_ok = driver_bridge::set_hardware_breakpoint(th.tid, session->hw_slot, session->rtl_allocate_heap, 0, 0);
        const DWORD set_gle = set_ok ? ERROR_SUCCESS : GetLastError();
        const std::string set_status = driver_bridge::status();
        const std::string set_last_error = driver_bridge::last_error();
        diag::log_tagged_fmt("heap_track",
            "breakpoint_arm_thread_set pid=%u active_pid=%u session_id=%s tid=%u ok=%d gle=%lu slot=%d target=%s status=%s last_error=%s",
            pid,
            driver_bridge::attached_pid(),
            session->id.c_str(),
            th.tid,
            set_ok ? 1 : 0,
            static_cast<unsigned long>(set_gle),
            session->hw_slot,
            sa_format_address(session->rtl_allocate_heap).c_str(),
            set_status.c_str(),
            set_last_error.c_str());
        driver_bridge::thread_context_t after_ctx{};
        const bool after_ok = driver_bridge::get_thread_context(th.tid, after_ctx);
        const DWORD after_gle = after_ok ? ERROR_SUCCESS : GetLastError();
        const std::uint64_t after_dr = dr_address(after_ctx, session->hw_slot);
        const bool slot_enabled = after_ok && (after_ctx.dr7 & (1ull << static_cast<unsigned>(session->hw_slot * 2))) != 0;
        const bool verify_ok = set_ok && after_ok && after_dr == session->rtl_allocate_heap && slot_enabled;
        const char* result_reason = verify_ok ? "armed" : (!set_ok ? "set_hardware_breakpoint_failed" : (!after_ok ? "context_after_failed" : (after_dr != session->rtl_allocate_heap ? "verify_address_mismatch" : "verify_dr7_enable_missing")));
        diag::log_tagged_fmt("heap_track",
            "breakpoint_arm_thread_context_after pid=%u active_pid=%u session_id=%s tid=%u get_ok=%d get_gle=%lu set_ok=%d set_gle=%lu verify_ok=%d reason=%s rip=%s rsp=%s rflags=0x%llX dr0=%s dr1=%s dr2=%s dr3=%s dr6=0x%llX dr7=0x%llX verify_slot=%d verify_addr=%s target=%s slot_enabled=%d status=%s last_error=%s",
            pid,
            driver_bridge::attached_pid(),
            session->id.c_str(),
            th.tid,
            after_ok ? 1 : 0,
            static_cast<unsigned long>(after_gle),
            set_ok ? 1 : 0,
            static_cast<unsigned long>(set_gle),
            verify_ok ? 1 : 0,
            result_reason,
            sa_format_address(after_ctx.rip).c_str(),
            sa_format_address(after_ctx.rsp).c_str(),
            static_cast<unsigned long long>(after_ctx.rflags),
            sa_format_address(after_ctx.dr0).c_str(),
            sa_format_address(after_ctx.dr1).c_str(),
            sa_format_address(after_ctx.dr2).c_str(),
            sa_format_address(after_ctx.dr3).c_str(),
            static_cast<unsigned long long>(after_ctx.dr6),
            static_cast<unsigned long long>(after_ctx.dr7),
            session->hw_slot,
            sa_format_address(after_dr).c_str(),
            sa_format_address(session->rtl_allocate_heap).c_str(),
            slot_enabled ? 1 : 0,
            driver_bridge::status().c_str(),
            driver_bridge::last_error().c_str());
        if (verify_ok)
        {
            ++armed;
            if (std::find(armed_tids.begin(), armed_tids.end(), th.tid) == armed_tids.end())
                armed_tids.push_back(th.tid);
        }
    }
    if (!armed_tids.empty())
    {
        auto updated = *session;
        updated.tids = std::move(armed_tids);
        store::update_heap_session(updated);
    }
    diag::log_tagged_fmt("heap_track",
        "breakpoint_arm_existing pid=%u session_id=%s thread_count=%zu armed=%zu slot=%d target=%s",
        pid,
        session->id.c_str(),
        threads.size(),
        armed,
        session->hw_slot,
        sa_format_address(session->rtl_allocate_heap).c_str());
    return armed;
}

std::uint64_t context_dr_address(const driver_bridge::thread_context_t& ctx, int slot)
{
    switch (slot)
    {
    case 0: return ctx.dr0;
    case 1: return ctx.dr1;
    case 2: return ctx.dr2;
    case 3: return ctx.dr3;
    default: return 0;
    }
}

bool heap_context_reports_slot(const driver_bridge::thread_context_t& ctx, int slot, std::uint64_t expected)
{
    if (slot < 0 || slot > 3 || expected == 0)
        return false;
    const bool dr6_hit = (ctx.dr6 & (1ull << static_cast<unsigned>(slot))) != 0;
    const bool slot_matches = context_dr_address(ctx, slot) == expected;
    if (dr6_hit && slot_matches)
        return true;
    return slot_matches && ctx.rip == expected;
}

void remove_heap_thread(const store::heap_session_t& source_session, std::uint32_t tid)
{
    auto session = source_session;
    session.tids.erase(std::remove(session.tids.begin(), session.tids.end(), tid), session.tids.end());
    store::update_heap_session(session);
    auto& state = heap_debug_state();
    std::lock_guard<std::mutex> lock(state.mutex);
    state.pending.erase(tid);
}

bool handle_heap_single_step(std::uint32_t pid, std::uint32_t tid, const driver_bridge::thread_context_t& ctx)
{
    auto session_opt = event_session_for_pid(pid);
    if (!session_opt)
        return false;
    auto session = *session_opt;
    bool handled = false;
    auto& state = heap_debug_state();
    pending_alloc_t pending;
    bool had_pending = false;
    {
        std::lock_guard<std::mutex> lock(state.mutex);
        auto it = state.pending.find(tid);
        if (it != state.pending.end())
        {
            pending = it->second;
            had_pending = true;
        }
    }
    if (had_pending && heap_context_reports_slot(ctx, session.hw_slot, pending.return_address))
    {
        if (ctx.rax != 0)
            append_event_capture(session, pending, ctx.rax);
        {
            std::lock_guard<std::mutex> lock(state.mutex);
            state.pending.erase(tid);
        }
        driver_bridge::set_hardware_breakpoint(tid, session.hw_slot, session.rtl_allocate_heap, 0, 0);
        handled = true;
    }
    else if (heap_context_reports_slot(ctx, session.hw_slot, session.rtl_allocate_heap))
    {
        const std::uint64_t requested_size = ctx.r8;
        if (requested_size != 0 && (session.min_size == 0 || requested_size >= session.min_size) && (session.max_size == 0 || requested_size <= session.max_size))
        {
            std::uint64_t return_address = 0;
            if (read_u64(pid, ctx.rsp, return_address) && return_address != 0)
            {
                pending_alloc_t next;
                next.heap = ctx.rcx;
                next.flags = ctx.rdx;
                next.size = requested_size;
                next.return_address = return_address;
                next.timestamp_ms = unix_time_ms();
                next.callstack = capture_callstack_addresses(pid, ctx, return_address, session.capture_callstack);
                {
                    std::lock_guard<std::mutex> lock(state.mutex);
                    state.pending[tid] = std::move(next);
                }
                driver_bridge::set_hardware_breakpoint(tid, session.hw_slot, return_address, 0, 0);
            }
        }
        handled = true;
    }
    if (handled)
    {
        driver_bridge::thread_context_t next = ctx;
        next.rflags |= 0x10000ull;
        next.dr6 = 0;
        SetLastError(ERROR_SUCCESS);
        const bool set_ok = driver_bridge::set_thread_context(tid, next, (1ull << 17) | (1ull << 22));
        diag::log_tagged_fmt("heap_track",
            "kernel_context_hit_resume pid=%u tid=%u set_ok=%d gle=%lu rip=0x%llX dr6=0x%llX dr7=0x%llX",
            pid,
            tid,
            set_ok ? 1 : 0,
            static_cast<unsigned long>(set_ok ? ERROR_SUCCESS : GetLastError()),
            static_cast<unsigned long long>(ctx.rip),
            static_cast<unsigned long long>(ctx.dr6),
            static_cast<unsigned long long>(ctx.dr7));
    }
    return handled;
}

void poll_heap_thread_contexts(std::uint32_t pid)
{
    auto session = event_session_for_pid(pid);
    if (!session)
        return;
    std::vector<std::uint32_t> tids;
    for (const auto tid : session->tids)
    {
        if (tid != 0 && std::find(tids.begin(), tids.end(), tid) == tids.end())
            tids.push_back(tid);
    }
    for (const auto tid : tids)
    {
        driver_bridge::thread_context_t ctx{};
        SetLastError(ERROR_SUCCESS);
        if (!driver_bridge::get_thread_context(tid, ctx))
        {
            const DWORD gle = GetLastError();
            diag::log_tagged_fmt("heap_track",
                "kernel_context_poll_get_failed pid=%u tid=%u gle=%lu driver_error=%s",
                pid,
                tid,
                static_cast<unsigned long>(gle),
                driver_bridge::last_error().c_str());
            if (gle == ERROR_INVALID_PARAMETER || gle == ERROR_NOT_FOUND || gle == ERROR_INVALID_HANDLE)
                remove_heap_thread(*session, tid);
            continue;
        }
        handle_heap_single_step(pid, tid, ctx);
    }
}

void heap_debug_loop()
{
    auto& state = heap_debug_state();
    const std::uint32_t pid = state.pid.load(std::memory_order_acquire);
    if (pid == 0 || !driver_bridge::using_kernel_driver())
    {
        state.error.store(pid == 0 ? ERROR_INVALID_PARAMETER : ERROR_INVALID_HANDLE, std::memory_order_release);
        state.attached.store(false, std::memory_order_release);
        state.polling.store(false, std::memory_order_release);
        state.running.store(false, std::memory_order_release);
        diag::log_tagged_fmt("heap_track",
            "kernel_context_loop_exit_invalid pid=%u kernel=%d",
            pid,
            driver_bridge::using_kernel_driver() ? 1 : 0);
        return;
    }
    state.error.store(0, std::memory_order_release);
    state.attached.store(true, std::memory_order_release);
    diag::log_tagged_fmt("heap_track",
        "kernel_context_loop_entry pid=%u worker_tid=%lu active_pid=%u",
        pid,
        static_cast<unsigned long>(GetCurrentThreadId()),
        driver_bridge::attached_pid());
    arm_heap_existing_threads(pid);
    std::uint64_t poll_count = 0;
    while (state.polling.load(std::memory_order_acquire))
    {
        if (!driver_bridge::using_kernel_driver())
        {
            state.error.store(ERROR_INVALID_HANDLE, std::memory_order_release);
            state.polling.store(false, std::memory_order_release);
            break;
        }
        if (!event_session_for_pid(pid))
            break;
        if ((poll_count++ % 20) == 0)
            arm_heap_existing_threads(pid);
        poll_heap_thread_contexts(pid);
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }
    if (auto session = event_session_for_pid(pid))
        clear_session_breakpoints(*session);
    std::size_t pending_cleared = 0;
    {
        std::lock_guard<std::mutex> lock(state.mutex);
        pending_cleared = state.pending.size();
        state.pending.clear();
    }
    state.attached.store(false, std::memory_order_release);
    state.polling.store(false, std::memory_order_release);
    state.pid.store(0, std::memory_order_release);
    state.running.store(false, std::memory_order_release);
    diag::log_tagged_fmt("heap_track",
        "kernel_context_loop_exit pid=%u worker_tid=%lu polls=%llu pending_cleared=%zu",
        pid,
        static_cast<unsigned long>(GetCurrentThreadId()),
        static_cast<unsigned long long>(poll_count),
        pending_cleared);
}

bool start_heap_debug_loop(std::uint32_t pid, std::string& error)
{
    const std::uint64_t started_ms = GetTickCount64();
    auto& state = heap_debug_state();
    diag::log_tagged_fmt("heap_track",
        "kernel_context_start_loop enter pid=%u running=%d active_pid=%u deadline_remaining_ms=%llu diag_id=%s",
        pid,
        state.running.load(std::memory_order_acquire) ? 1 : 0,
        state.pid.load(std::memory_order_acquire),
        static_cast<unsigned long long>(deadline_remaining_ms()),
        mcp_standalone::current_call_diag_id());
    if (state.running.load(std::memory_order_acquire))
    {
        if (state.pid.load(std::memory_order_acquire) == pid && state.attached.load(std::memory_order_acquire))
        {
            const std::size_t armed = arm_heap_existing_threads(pid);
            diag::log_tagged_fmt("heap_track",
                "kernel_context_start_loop reuse pid=%u armed=%zu elapsed_ms=%llu",
                pid,
                armed,
                static_cast<unsigned long long>(GetTickCount64() - started_ms));
            return true;
        }
        error = "another heap kernel context consumer is already active";
        diag::log_tagged_fmt("heap_track",
            "kernel_context_start_loop busy pid=%u active_pid=%u elapsed_ms=%llu",
            pid,
            state.pid.load(std::memory_order_acquire),
            static_cast<unsigned long long>(GetTickCount64() - started_ms));
        return false;
    }
    state.pid.store(pid, std::memory_order_release);
    state.error.store(ERROR_IO_PENDING, std::memory_order_release);
    state.attached.store(false, std::memory_order_release);
    state.polling.store(true, std::memory_order_release);
    state.running.store(true, std::memory_order_release);
    aida::infra::executor::submission_t sub;
    sub.owner_subsystem = "re.heap_track";
    sub.label = "heap_track.debug_loop";
    sub.thread_class = "service_loop";
    sub.domain = aida::infra::executor::domain_t::service;
    sub.priority = 4;
    sub.target_pid = pid;
    sub.body = []() { heap_debug_loop(); };
    if (!aida::infra::executor::submit(std::move(sub)).submitted)
    {
        state.polling.store(false, std::memory_order_release);
        state.running.store(false, std::memory_order_release);
        error = "failed to schedule heap kernel context consumer";
        diag::log_tagged_fmt("heap_track",
            "kernel_context_start_loop post_failed pid=%u elapsed_ms=%llu",
            pid,
            static_cast<unsigned long long>(GetTickCount64() - started_ms));
        return false;
    }
    for (int i = 0; i < 80; ++i)
    {
        if (state.attached.load(std::memory_order_acquire))
        {
            diag::log_tagged_fmt("heap_track",
                "kernel_context_start_loop attached pid=%u waits=%d elapsed_ms=%llu",
                pid,
                i,
                static_cast<unsigned long long>(GetTickCount64() - started_ms));
            const std::uint64_t tids_wait_start = GetTickCount64();
            for (int j = 0; j < 80; ++j)
            {
                auto session = event_session_for_pid(pid);
                if (session && !session->tids.empty())
                {
                    diag::log_tagged_fmt("heap_track",
                        "kernel_context_start_loop tids_ready pid=%u tid_count=%zu tids_waits=%d tids_elapsed_ms=%llu total_elapsed_ms=%llu",
                        pid,
                        session->tids.size(),
                        j,
                        static_cast<unsigned long long>(GetTickCount64() - tids_wait_start),
                        static_cast<unsigned long long>(GetTickCount64() - started_ms));
                    return true;
                }
                if (!state.running.load(std::memory_order_acquire))
                    break;
                if (heap_call_cancelled("kernel_context_start_tids_wait", pid, started_ms))
                {
                    state.polling.store(false, std::memory_order_release);
                    break;
                }
                std::this_thread::sleep_for(std::chrono::milliseconds(25));
            }
            auto session = event_session_for_pid(pid);
            if (session && !session->tids.empty())
                return true;
            error = "heap kernel context attached but no threads armed within timeout";
            diag::log_tagged_fmt("heap_track",
                "kernel_context_start_loop tids_empty pid=%u tids_waits=%d tids_elapsed_ms=%llu total_elapsed_ms=%llu",
                pid,
                80,
                static_cast<unsigned long long>(GetTickCount64() - tids_wait_start),
                static_cast<unsigned long long>(GetTickCount64() - started_ms));
            state.polling.store(false, std::memory_order_release);
            return false;
        }
        if (!state.running.load(std::memory_order_acquire))
            break;
        if (heap_call_cancelled("kernel_context_start_wait", pid, started_ms))
        {
            state.polling.store(false, std::memory_order_release);
            break;
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(25));
    }
    const DWORD gle = state.error.load(std::memory_order_acquire);
    error = "heap kernel context consumer failed or timed out, error=" + std::to_string(static_cast<unsigned long>(gle));
    diag::log_tagged_fmt("heap_track",
        "kernel_context_start_loop failed pid=%u error=%lu running=%d attached=%d elapsed_ms=%llu",
        pid,
        static_cast<unsigned long>(gle),
        state.running.load(std::memory_order_acquire) ? 1 : 0,
        state.attached.load(std::memory_order_acquire) ? 1 : 0,
        static_cast<unsigned long long>(GetTickCount64() - started_ms));
    return false;
}

void stop_heap_debug_loop(std::uint32_t pid)
{
    const std::uint64_t started_ms = GetTickCount64();
    auto& state = heap_debug_state();
    if (state.pid.load(std::memory_order_acquire) != pid)
    {
        diag::log_tagged_fmt("heap_track",
            "kernel_context_stop_loop skip pid=%u active_pid=%u elapsed_ms=%llu",
            pid,
            state.pid.load(std::memory_order_acquire),
            static_cast<unsigned long long>(GetTickCount64() - started_ms));
        return;
    }
    state.polling.store(false, std::memory_order_release);
    for (int i = 0; i < 80 && state.running.load(std::memory_order_acquire); ++i)
    {
        if (heap_call_cancelled("kernel_context_stop_wait", pid, started_ms))
            break;
        std::this_thread::sleep_for(std::chrono::milliseconds(25));
    }
    diag::log_tagged_fmt("heap_track",
        "kernel_context_stop_loop exit pid=%u running=%d attached=%d elapsed_ms=%llu",
        pid,
        state.running.load(std::memory_order_acquire) ? 1 : 0,
        state.attached.load(std::memory_order_acquire) ? 1 : 0,
        static_cast<unsigned long long>(GetTickCount64() - started_ms));
}

std::string backend_param(const json& params)
{
    std::string backend = lower_ascii(string_param(params, "backend", string_param(params, "mode", "auto")));
    if (backend.empty())
        backend = "auto";
    return backend;
}

bool event_backend_required(const std::string& backend)
{
    return backend == "event" || backend == "events" || backend == "hwbp" || backend == "hw_bp" || backend == "hardware_breakpoint" || backend == "debug_events";
}

bool snapshot_backend_requested(const std::string& backend)
{
    return backend == "snapshot" || backend == "snapshot_diff" || backend == "diff" || backend == "polling";
}

json heap_backend_policy_json(std::uint32_t pid, const std::string& backend, std::uint64_t started_ms, std::uint64_t rtl_allocate_heap = 0, const std::string& failure = {})
{
    json out;
    out["process_id"] = pid;
    out["requested_backend"] = backend;
    out["allowed_backends"] = json::array({"auto", "event", "events", "hwbp", "hw_bp", "hardware_breakpoint", "debug_events"});
    out["disabled_backends"] = json::array({"snapshot", "snapshot_diff", "diff", "polling"});
    out["snapshot_diff_disabled"] = true;
    out["polling_disabled"] = true;
    out["kernel_only_policy"] = true;
    out["user_mode_fallback_allowed"] = false;
    out["snapshot_polling_fallback_allowed"] = false;
    out["capture_backend_required"] = kHeapEventBackend;
    out["snapshot_backend_kind"] = kHeapSnapshotBackend;
    out["policy_state"] = "fail_closed_kernel_event_only";
    out["mutation"] = "none";
    out["fail_closed"] = true;
    out["dependency_blocked"] = true;
    out["functional_success"] = false;
    out["safe_contract"] = "fail_closed_kernel_event_only";
    out["validation_code"] = failure.empty() ? "kernel_event_backend_unavailable" : failure;
    out["driver_connected"] = driver_bridge::using_kernel_driver();
    out["diag_id"] = mcp_standalone::current_call_diag_id();
    out["deadline_remaining_ms"] = deadline_remaining_ms();
    out["rtl_allocate_heap"] = rtl_allocate_heap ? json(sa_format_address(rtl_allocate_heap)) : json(nullptr);
    out["event_backend_available"] = rtl_allocate_heap != 0;
    if (!failure.empty())
        out["failure"] = failure;
    out["elapsed_ms"] = GetTickCount64() - started_ms;
    return out;
}

tool_result_t start_session(const json& params)
{
    const std::uint64_t started_ms = GetTickCount64();
    if (!unsafe_confirmed(params))
    {
        json guard = heap_backend_policy_json(0, backend_param(params), started_ms, 0, "confirm_unsafe_required");
        guard["tool"] = "heap_track_manage";
        guard["action"] = "start";
        guard["confirm_unsafe_required"] = true;
        guard["confirm_unsafe_received"] = unsafe_confirmed(params);
        return tool_result_t::error("heap_track_manage start requires confirm_unsafe=true or allow_unsafe=true.", guard);
    }
    active_process_scope_t scope(params);
    if (!scope.ok())
        return tool_result_t::error(scope.error());

    const std::string backend = backend_param(params);
    diag::log_tagged_fmt("heap_track",
        "start enter pid=%u caller_pid=%lu caller_tid=%lu requested_backend=%s deadline_remaining_ms=%llu diag_id=%s",
        scope.pid(),
        static_cast<unsigned long>(GetCurrentProcessId()),
        static_cast<unsigned long>(GetCurrentThreadId()),
        backend.c_str(),
        static_cast<unsigned long long>(deadline_remaining_ms()),
        mcp_standalone::current_call_diag_id());
    if (snapshot_backend_requested(backend))
    {
        const std::uint64_t rtl = resolve_rtl_allocate_heap(scope.pid());
        diag::log_tagged_fmt("heap_track",
            "start backend_policy pid=%u requested_backend=%s allowed=0 reason=snapshot_diff_disabled elapsed_ms=%llu",
            scope.pid(),
            backend.c_str(),
            static_cast<unsigned long long>(GetTickCount64() - started_ms));
        return tool_result_t::error("snapshot_diff/polling heap tracking is disabled by kernel-only stealth policy.", heap_backend_policy_json(scope.pid(), backend, started_ms, rtl, "requested_backend_disabled"));
    }
    if (backend != "auto" && !event_backend_required(backend))
        return tool_result_t::error("'backend' must be auto, event, hwbp, hardware_breakpoint, or debug_events.", heap_backend_policy_json(scope.pid(), backend, started_ms, 0, "unsupported_backend"));

    store::heap_session_t session;
    session.id = store::next_id("heap");
    session.pid = scope.pid();
    session.min_size = numeric_param(params, "min_size", 0, 0, 0x7FFFFFFF);
    session.max_size = numeric_param(params, "max_size", 0, 0, 0x7FFFFFFF);
    session.alignment = numeric_param(params, "alignment", 0, 0, 0x10000);
    session.capture_callstack = bool_param(params, "capture_callstack", true);
    session.max_captures = static_cast<std::uint32_t>(numeric_param(params, "max_captures", 256, 1, 10000));
    session.started_ms = unix_time_ms();
    diag::log_tagged_fmt("heap_track",
        "start resolve_pre pid=%u kernel_mode=%d driver_connected=%d deadline_remaining_ms=%llu diag_id=%s",
        scope.pid(),
        driver_bridge::using_kernel_driver() ? 1 : 0,
        driver_bridge::using_kernel_driver() ? 1 : 0,
        static_cast<unsigned long long>(deadline_remaining_ms()),
        mcp_standalone::current_call_diag_id());
    if (heap_call_cancelled("start_pre_resolve", scope.pid(), started_ms))
        return tool_result_t::error("Heap tracking start cancelled.", heap_cancel_detail("start", scope.pid(), started_ms));
    const std::uint64_t resolve_started_ms = GetTickCount64();
    session.rtl_allocate_heap = resolve_rtl_allocate_heap(scope.pid());
    diag::log_tagged_fmt("heap_track",
        "start resolve_rtlallocateheap pid=%u va=%s elapsed_ms=%llu cancelled=%d deadline_remaining_ms=%llu",
        scope.pid(),
        session.rtl_allocate_heap ? sa_format_address(session.rtl_allocate_heap).c_str() : "0x0",
        static_cast<unsigned long long>(GetTickCount64() - resolve_started_ms),
        mcp_standalone::current_call_cancelled() ? 1 : 0,
        static_cast<unsigned long long>(deadline_remaining_ms()));
    session.hw_slot = snapshot_backend_requested(backend) ? -1 : static_cast<int>(numeric_param(params, "hw_slot", 2, 0, 3));
    const bool skip_initial_snapshot = bool_param(params, "skip_initial_snapshot", false) || bool_param(params, "empty_baseline", false);
    if (heap_call_cancelled("start_pre_baseline", scope.pid(), started_ms))
        return tool_result_t::error("Heap tracking start cancelled.", heap_cancel_detail("start", scope.pid(), started_ms));
    const std::uint64_t baseline_started_ms = GetTickCount64();
    if (!skip_initial_snapshot)
        session.baseline = sample_heap(scope.pid(), session, session.max_captures);
    diag::log_tagged_fmt("heap_track",
        "start baseline pid=%u skipped=%d baseline_count=%zu elapsed_ms=%llu cancelled=%d",
        scope.pid(),
        skip_initial_snapshot ? 1 : 0,
        session.baseline.size(),
        static_cast<unsigned long long>(GetTickCount64() - baseline_started_ms),
        mcp_standalone::current_call_cancelled() ? 1 : 0);
    if (heap_call_cancelled("start_after_baseline", scope.pid(), started_ms))
        return tool_result_t::error("Heap tracking start cancelled.", heap_cancel_detail("start", scope.pid(), started_ms));

    const bool require_event = event_backend_required(backend);
    if (!snapshot_backend_requested(backend) && session.rtl_allocate_heap == 0)
    {
        return tool_result_t::error("RtlAllocateHeap could not be resolved; heap tracking is fail-closed under kernel-only stealth policy.", heap_backend_policy_json(scope.pid(), backend, started_ms, session.rtl_allocate_heap, "rtlallocateheap_unresolved"));
    }
    if (session.hw_slot >= 0 && has_other_event_session(scope.pid(), session.id))
    {
        return tool_result_t::error("Another heap event session is already active for this process; heap tracking will not downgrade to snapshot_diff.");
    }

    store::add_heap_session(session);
    diag::log_tagged_fmt("heap_track",
        "start store_add pid=%u session_id=%s hw_slot=%d baseline=%zu elapsed_ms=%llu",
        scope.pid(),
        session.id.c_str(),
        session.hw_slot,
        session.baseline.size(),
        static_cast<unsigned long long>(GetTickCount64() - started_ms));
    bool event_started = false;
    std::string event_error;
    if (session.hw_slot >= 0)
        event_started = start_heap_debug_loop(scope.pid(), event_error);
    diag::log_tagged_fmt("heap_track",
        "start event_backend pid=%u session_id=%s attempted=%d started=%d error=%s elapsed_ms=%llu",
        scope.pid(),
        session.id.c_str(),
        session.hw_slot >= 0 ? 1 : 0,
        event_started ? 1 : 0,
        event_error.empty() ? "" : event_error.c_str(),
        static_cast<unsigned long long>(GetTickCount64() - started_ms));
    if (session.hw_slot >= 0 && !event_started)
    {
        const std::size_t cleared = clear_session_breakpoints(session);
        const bool removed = store::remove_heap_session(session.id, nullptr);
        diag::log_tagged_fmt("heap_track",
            "start cleanup_event_failed pid=%u session_id=%s breakpoints_cleared=%zu removed=%d elapsed_ms=%llu",
            scope.pid(),
            session.id.c_str(),
            cleared,
            removed ? 1 : 0,
            static_cast<unsigned long long>(GetTickCount64() - started_ms));
        return tool_result_t::error("Heap event backend failed under kernel-only stealth policy: " + event_error, heap_backend_policy_json(scope.pid(), backend, started_ms, session.rtl_allocate_heap, event_error));
    }
    for (const auto& updated : store::list_heap_sessions(scope.pid()))
    {
        if (updated.id == session.id)
        {
            session = updated;
            break;
        }
    }
    if (event_started && session.tids.empty())
    {
        event_error = "RtlAllocateHeap breakpoint could not be armed on any target thread";
        stop_heap_debug_loop(scope.pid());
        const bool removed = store::remove_heap_session(session.id, nullptr);
        diag::log_tagged_fmt("heap_track",
            "start cleanup_no_threads pid=%u session_id=%s removed=%d elapsed_ms=%llu",
            scope.pid(),
            session.id.c_str(),
            removed ? 1 : 0,
            static_cast<unsigned long long>(GetTickCount64() - started_ms));
        return tool_result_t::error("Heap event backend failed under kernel-only stealth policy: " + event_error, heap_backend_policy_json(scope.pid(), backend, started_ms, session.rtl_allocate_heap, event_error));
    }
    json result = session_json(session);
    result["session_id"] = session.id;
    result["requested_backend"] = backend;
    result["capture_backend"] = kHeapEventBackend;
    result["fallback_reason"] = nullptr;
    result["event_backend_attempted"] = session.rtl_allocate_heap != 0;
    result["event_backend_required"] = require_event;
    result["snapshot_diff_selected"] = false;
    result["snapshot_polling_fallback_allowed"] = false;
    result["kernel_only_policy"] = true;
    result["dependency_blocked"] = false;
    result["fail_closed"] = false;
    result["stimulus_required"] = false;
    result["pre_stimulus"] = session.captures.empty();
    result["observation_state"] = session.captures.empty() ? "awaiting_stimulus_or_results_poll" : "captures_observed";
    result["functional_snapshot_evidence"] = false;
    result["functional_event_evidence"] = event_started && !session.captures.empty();
    result["evidence"] = {
        {"rtl_allocate_heap_resolved", session.rtl_allocate_heap != 0},
        {"debug_event_consumer", false},
        {"rtlallocateheap_inline_hook", false},
        {"event_backend_kind", kHeapEventBackend},
        {"snapshot_backend_kind", kHeapSnapshotBackend},
        {"auto_fallback_policy", "auto is kernel-event-only and fails closed; snapshot_diff is disabled"},
        {"kernel_context_consumer", event_started},
        {"return_value_capture", event_started},
        {"alignment_filter", session.alignment},
        {"capture_callstack", session.capture_callstack},
        {"snapshot_baseline_count", session.baseline.size()},
        {"snapshot_baseline_skipped", skip_initial_snapshot},
        {"snapshot_baseline_is_capture_backend", false},
        {"snapshot_baseline_role", "filter_only_not_functional_capture"},
        {"snapshot_polling_fallback_allowed", false},
        {"zero_capture_expected_on_start", session.captures.empty()}
    };
    result["elapsed_ms"] = GetTickCount64() - started_ms;
    diag::log_tagged_fmt("heap_track",
        "start exit pid=%u session_id=%s started=%d thread_count=%zu captures=%zu baseline=%zu elapsed_ms=%llu",
        scope.pid(),
        session.id.c_str(),
        event_started ? 1 : 0,
        session.tids.size(),
        session.captures.size(),
        session.baseline.size(),
        static_cast<unsigned long long>(GetTickCount64() - started_ms));
    return tool_result_t::ok("Heap tracking session started with kernel-context RtlAllocateHeap return polling.", result);
}

tool_result_t results_session(const json& params)
{
    const std::uint64_t started_ms = GetTickCount64();
    const std::string id = string_param(params, "session_id");
    if (id.empty())
        return tool_result_t::error("'session_id' is required for results.",
            json{{"tool", "heap_track_manage"}, {"action", "results"}, {"validation_code", "session_id_required"}});
    store::heap_session_t session;
    if (!store::find_heap_session(id, session))
        return tool_result_t::error("Unknown heap tracking session.", heap_session_lookup_error("results", id));
    diag::log_tagged_fmt("heap_track",
        "results enter session_id=%s pid=%u caller_pid=%lu caller_tid=%lu hw_slot=%d tids=%zu captures=%zu deadline_remaining_ms=%llu diag_id=%s",
        id.c_str(),
        session.pid,
        static_cast<unsigned long>(GetCurrentProcessId()),
        static_cast<unsigned long>(GetCurrentThreadId()),
        session.hw_slot,
        session.tids.size(),
        session.captures.size(),
        static_cast<unsigned long long>(deadline_remaining_ms()),
        mcp_standalone::current_call_diag_id());
    active_process_scope_t scope(session.pid);
    if (!scope.ok())
        return tool_result_t::error(scope.error());

    const bool focus_only = bool_param(params, "focus_only", false) || bool_param(params, "bounded_only", false);
    const std::uint64_t focus_started_ms = GetTickCount64();
    const bool focused = append_focus_captures(session, params);
    diag::log_tagged_fmt("heap_track",
        "results focus_capture session_id=%s focused=%d focus_only=%d elapsed_ms=%llu total_elapsed_ms=%llu",
        id.c_str(),
        focused ? 1 : 0,
        focus_only ? 1 : 0,
        static_cast<unsigned long long>(GetTickCount64() - focus_started_ms),
        static_cast<unsigned long long>(GetTickCount64() - started_ms));
    if (session.hw_slot < 0 || session.tids.empty())
    {
        json result = session_json(session);
        result["kernel_only_capture"] = true;
        result["snapshot_diff_checked"] = false;
        result["reason"] = "heap session has no active kernel HWBP/context backend";
        result["elapsed_ms"] = GetTickCount64() - started_ms;
        diag::log_tagged_fmt("heap_track",
            "results exit session_id=%s ok=0 reason=no_kernel_context hw_slot=%d tids=%zu elapsed_ms=%llu",
            id.c_str(),
            session.hw_slot,
            session.tids.size(),
            static_cast<unsigned long long>(GetTickCount64() - started_ms));
        return tool_result_t::error("Heap tracking session is not kernel-event-backed; snapshot_diff fallback is disabled.", result);
    }
    else
        store::find_heap_session(id, session);

    const std::size_t limit = static_cast<std::size_t>(numeric_param(params, "limit", 100, 1, 10000));
    json arr = json::array();
    const std::size_t n = std::min(limit, session.captures.size());
    for (std::size_t i = 0; i < n; ++i)
        arr.push_back(capture_json(session, session.captures[i]));
    json result = session_json(session);
    result["events"] = std::move(arr);
    result["returned"] = result["events"].size();
    result["functional_snapshot_evidence"] = false;
    result["functional_event_evidence"] = session_event_active(session) && session.captures.size() > 0;
    result["observation_complete"] = true;
    result["saw_allocation_or_mutation"] = session.captures.size() > 0;
    result["evidence"] = {
        {"backend", result["backend"]},
        {"event_backend_kind", kHeapEventBackend},
        {"snapshot_backend_kind", kHeapSnapshotBackend},
        {"debug_event_consumer", false},
        {"rtlallocateheap_inline_hook", false},
        {"kernel_context_polling", session_event_active(session)},
        {"snapshot_diff_baseline_count", 0},
        {"allocation_size_estimates", true},
        {"heap_membership_checked", true},
        {"synthetic_breakpoint_events", false},
        {"bounded_focus_capture", focused},
        {"bounded_focus_only", focus_only}
    };
    result["elapsed_ms"] = GetTickCount64() - started_ms;
    diag::log_tagged_fmt("heap_track",
        "results exit session_id=%s ok=%d returned=%zu captures=%zu focused=%d elapsed_ms=%llu",
        id.c_str(),
        session.captures.empty() ? 0 : 1,
        result["returned"].get<std::size_t>(),
        session.captures.size(),
        focused ? 1 : 0,
        static_cast<unsigned long long>(GetTickCount64() - started_ms));
    if (session.captures.empty())
        return tool_result_t::error("Heap tracking produced zero captures; no allocation or snapshot-diff mutation evidence was observed.", result);
    return tool_result_t::ok(result);
}

tool_result_t stop_session(const json& params)
{
    const std::uint64_t started_ms = GetTickCount64();
    if (!unsafe_confirmed(params))
        return unsafe_required("heap_track_manage stop");
    const std::string id = string_param(params, "session_id");
    if (id.empty())
        return tool_result_t::error("'session_id' is required for stop.",
            json{{"tool", "heap_track_manage"}, {"action", "stop"}, {"validation_code", "session_id_required"}});
    store::heap_session_t session;
    if (!store::find_heap_session(id, session))
        return tool_result_t::error("Unknown heap tracking session.", heap_session_lookup_error("stop", id));
    diag::log_tagged_fmt("heap_track",
        "stop enter session_id=%s pid=%u caller_pid=%lu caller_tid=%lu hw_slot=%d tids=%zu captures=%zu deadline_remaining_ms=%llu diag_id=%s",
        id.c_str(),
        session.pid,
        static_cast<unsigned long>(GetCurrentProcessId()),
        static_cast<unsigned long>(GetCurrentThreadId()),
        session.hw_slot,
        session.tids.size(),
        session.captures.size(),
        static_cast<unsigned long long>(deadline_remaining_ms()),
        mcp_standalone::current_call_diag_id());
    active_process_scope_t scope(session.pid);
    const bool focus_only = bool_param(params, "focus_only", false) || bool_param(params, "bounded_only", false);
    const bool focused = scope.ok() ? append_focus_captures(session, params) : false;
    if (scope.ok() && !(session.hw_slot < 0 || session.tids.empty()))
        store::find_heap_session(id, session);
    if (!store::remove_heap_session(id, &session))
        return tool_result_t::error("Unknown heap tracking session.", heap_session_lookup_error("stop_remove", id));
    std::size_t cleared = 0;
    if (scope.ok())
        cleared = clear_session_breakpoints(session);
    if (session.hw_slot >= 0)
        stop_heap_debug_loop(session.pid);
    session.active = false;
    json result = session_json(session);
    result["stopped"] = true;
    result["functional_snapshot_evidence"] = false;
    result["functional_event_evidence"] = session_event_active(session) && session.captures.size() > 0;
    result["observation_complete"] = true;
    result["saw_allocation_or_mutation"] = session.captures.size() > 0;
    result["evidence"] = {
        {"breakpoints_cleared", session.hw_slot >= 0},
        {"debug_event_consumer_stopped", false},
        {"rtlallocateheap_inline_hook", false},
        {"kernel_context_consumer_stopped", session.hw_slot >= 0},
        {"event_backend_kind", kHeapEventBackend},
        {"snapshot_backend_kind", kHeapSnapshotBackend},
        {"snapshot_diff_checked", false},
        {"bounded_focus_capture", focused},
        {"bounded_focus_only", focus_only}
    };
    result["breakpoints_cleared_count"] = cleared;
    result["stop_cleanup"] = {
        {"scope_ok", scope.ok()},
        {"breakpoints_clear_attempted", scope.ok()},
        {"breakpoints_cleared_count", cleared},
        {"kernel_context_stop_attempted", session.hw_slot >= 0},
        {"debug_loop_running_after_stop", heap_debug_state().running.load(std::memory_order_acquire)},
        {"armed_tids_before_stop", session.tids},
        {"capture_queue_size_at_stop", session.captures.size()}
    };
    result["elapsed_ms"] = GetTickCount64() - started_ms;
    diag::log_tagged_fmt("heap_track",
        "stop exit session_id=%s ok=%d captures=%zu focused=%d cleared=%zu scope_ok=%d elapsed_ms=%llu",
        id.c_str(),
        session.captures.empty() ? 0 : 1,
        session.captures.size(),
        focused ? 1 : 0,
        cleared,
        scope.ok() ? 1 : 0,
        static_cast<unsigned long long>(GetTickCount64() - started_ms));
    if (session.captures.empty())
        return tool_result_t::error("Heap tracking stopped with zero captures; no allocation or snapshot-diff mutation evidence was observed.", result);
    return tool_result_t::ok("Heap tracking session stopped.", result);
}
}

tool_result_t manage(const json& params)
{
    const std::uint64_t started_ms = GetTickCount64();
    const std::string action = compat_action_name(params);
    const json p = compat_action_payload(params);
    diag::log_tagged_fmt("heap_track",
        "manage enter action=%s pid=%lu tid=%lu deadline_remaining_ms=%llu diag_id=%s",
        action.c_str(),
        static_cast<unsigned long>(GetCurrentProcessId()),
        static_cast<unsigned long>(GetCurrentThreadId()),
        static_cast<unsigned long long>(deadline_remaining_ms()),
        mcp_standalone::current_call_diag_id());
    if (action == "start") return start_session(p);
    if (action == "results") return results_session(p);
    if (action == "stop") return stop_session(p);
    diag::log_tagged_fmt("heap_track",
        "manage exit action=%s pid=%lu tid=%lu unknown=1 elapsed_ms=%llu",
        action.c_str(),
        static_cast<unsigned long>(GetCurrentProcessId()),
        static_cast<unsigned long>(GetCurrentThreadId()),
        static_cast<unsigned long long>(GetTickCount64() - started_ms));
    return compat_unknown_action("heap_track_manage", action);
}
}
