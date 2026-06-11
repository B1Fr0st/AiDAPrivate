#include "heap_track.hpp"

#include "artifact_store.hpp"
#include "../infra/work_queue.hpp"

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cstring>
#include <map>
#include <mutex>
#include <set>
#include <thread>

namespace re::heap_track
{
namespace
{
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

std::vector<store::heap_capture_t> sample_heap(std::uint32_t pid, const store::heap_session_t& session, std::size_t max_entries)
{
    std::vector<store::heap_capture_t> out;
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
                std::uint64_t heap_base = 0;
                if (!read_u64(pid, heaps_ptr + h * 8ull, heap_base) || heap_base == 0)
                    continue;
                const std::uint64_t seg_list_head = heap_base + 0x120;
                std::uint64_t seg_flink = 0;
                if (!read_u64(pid, seg_list_head, seg_flink))
                    continue;
                for (int seg_iter = 0; seg_flink != 0 && seg_flink != seg_list_head && seg_iter < 64 && out.size() < max_entries; ++seg_iter)
                {
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
        for (const auto& region : regions_for(pid, 8192))
        {
            if (out.size() >= max_entries)
                break;
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
    out["backend"] = session.hw_slot >= 0 && !session.tids.empty() ? "rtlallocateheap_return_debug_event" : "snapshot_diff";
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
    out["rtl_allocate_heap"] = session.rtl_allocate_heap ? json(sa_format_address(session.rtl_allocate_heap)) : json(nullptr);
    out["hw_slot"] = session.hw_slot >= 0 ? json(session.hw_slot) : json(nullptr);
    out["thread_count"] = session.tids.size();
    out["baseline_count"] = session.baseline.size();
    out["capture_count"] = session.captures.size();
    out["backend"] = session.hw_slot >= 0 && !session.tids.empty() ? "rtlallocateheap_return_debug_event" : "snapshot_diff";
    out["event_capture_active"] = session.hw_slot >= 0 && !session.tids.empty();
    out["snapshot_diff_available"] = true;
    return out;
}

std::uint64_t resolve_rtl_allocate_heap(std::uint32_t pid)
{
    auto ntdll = find_module_by_name(pid, "ntdll.dll");
    if (!ntdll)
        return 0;
    active_process_scope_t scope(pid);
    if (!scope.ok())
        return 0;
    return driver_bridge::resolve_export(ntdll->base, "RtlAllocateHeap");
}

void clear_session_breakpoints(const store::heap_session_t& session)
{
    if (session.hw_slot < 0 || session.hw_slot > 3)
        return;
    std::set<std::uint32_t> tids(session.tids.begin(), session.tids.end());
    for (auto tid : tids)
        driver_bridge::clear_hardware_breakpoint(tid, session.hw_slot);
}

bool enable_debug_privilege()
{
    HANDLE token = nullptr;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &token))
        return false;
    LUID luid{};
    if (!LookupPrivilegeValueW(nullptr, SE_DEBUG_NAME, &luid))
    {
        CloseHandle(token);
        return false;
    }
    TOKEN_PRIVILEGES tp{};
    tp.PrivilegeCount = 1;
    tp.Privileges[0].Luid = luid;
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
    const BOOL ok = AdjustTokenPrivileges(token, FALSE, &tp, sizeof(tp), nullptr, nullptr);
    const DWORD gle = GetLastError();
    CloseHandle(token);
    return ok && gle == ERROR_SUCCESS;
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

std::vector<std::uint64_t> capture_callstack_addresses(std::uint32_t pid, const CONTEXT& ctx, std::uint64_t return_address, bool enabled)
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
    add_frame(static_cast<std::uint64_t>(ctx.Rip));
    add_frame(return_address);
    std::uint64_t rbp = static_cast<std::uint64_t>(ctx.Rbp);
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
        if (read_bytes(pid, static_cast<std::uint64_t>(ctx.Rsp), 0x200, stack))
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

void arm_heap_session_for_thread(const store::heap_session_t& source_session, std::uint32_t tid)
{
    if (tid == 0 || source_session.hw_slot < 0 || source_session.hw_slot > 3 || source_session.rtl_allocate_heap == 0)
        return;
    auto session = source_session;
    if (driver_bridge::set_hardware_breakpoint(tid, session.hw_slot, session.rtl_allocate_heap, 0, 0))
    {
        if (std::find(session.tids.begin(), session.tids.end(), tid) == session.tids.end())
        {
            session.tids.push_back(tid);
            store::update_heap_session(session);
        }
    }
}

void arm_heap_existing_threads(std::uint32_t pid)
{
    auto session = event_session_for_pid(pid);
    if (!session)
        return;
    for (const auto& th : threads_for(pid))
        arm_heap_session_for_thread(*session, th.tid);
}

void close_debug_event_handles(const DEBUG_EVENT& evt)
{
    switch (evt.dwDebugEventCode)
    {
    case CREATE_PROCESS_DEBUG_EVENT:
        if (evt.u.CreateProcessInfo.hFile) CloseHandle(evt.u.CreateProcessInfo.hFile);
        if (evt.u.CreateProcessInfo.hThread) CloseHandle(evt.u.CreateProcessInfo.hThread);
        if (evt.u.CreateProcessInfo.hProcess) CloseHandle(evt.u.CreateProcessInfo.hProcess);
        break;
    case CREATE_THREAD_DEBUG_EVENT:
        if (evt.u.CreateThread.hThread) CloseHandle(evt.u.CreateThread.hThread);
        break;
    case LOAD_DLL_DEBUG_EVENT:
        if (evt.u.LoadDll.hFile) CloseHandle(evt.u.LoadDll.hFile);
        break;
    default:
        break;
    }
}

bool handle_heap_single_step(std::uint32_t pid, const DEBUG_EVENT& evt)
{
    auto session_opt = event_session_for_pid(pid);
    if (!session_opt)
        return false;
    auto session = *session_opt;
    HANDLE thread = OpenThread(THREAD_GET_CONTEXT | THREAD_SET_CONTEXT, FALSE, evt.dwThreadId);
    if (!thread)
        return false;
    CONTEXT ctx{};
    ctx.ContextFlags = CONTEXT_INTEGER | CONTEXT_CONTROL | CONTEXT_DEBUG_REGISTERS;
    if (!GetThreadContext(thread, &ctx))
    {
        CloseHandle(thread);
        return false;
    }
    const std::uint64_t exception_address = reinterpret_cast<std::uint64_t>(evt.u.Exception.ExceptionRecord.ExceptionAddress);
    bool handled = false;
    auto& state = heap_debug_state();
    pending_alloc_t pending;
    bool had_pending = false;
    {
        std::lock_guard<std::mutex> lock(state.mutex);
        auto it = state.pending.find(evt.dwThreadId);
        if (it != state.pending.end())
        {
            pending = it->second;
            had_pending = true;
        }
    }
    if (had_pending && (pending.return_address == static_cast<std::uint64_t>(ctx.Rip) || pending.return_address == exception_address))
    {
        if (static_cast<std::uint64_t>(ctx.Rax) != 0)
            append_event_capture(session, pending, static_cast<std::uint64_t>(ctx.Rax));
        {
            std::lock_guard<std::mutex> lock(state.mutex);
            state.pending.erase(evt.dwThreadId);
        }
        driver_bridge::set_hardware_breakpoint(evt.dwThreadId, session.hw_slot, session.rtl_allocate_heap, 0, 0);
        handled = true;
    }
    else if (session.rtl_allocate_heap == static_cast<std::uint64_t>(ctx.Rip) || session.rtl_allocate_heap == exception_address)
    {
        const std::uint64_t requested_size = static_cast<std::uint64_t>(ctx.R8);
        if (requested_size != 0 && (session.min_size == 0 || requested_size >= session.min_size) && (session.max_size == 0 || requested_size <= session.max_size))
        {
            std::uint64_t return_address = 0;
            if (read_u64(pid, static_cast<std::uint64_t>(ctx.Rsp), return_address) && return_address != 0)
            {
                pending_alloc_t next;
                next.heap = static_cast<std::uint64_t>(ctx.Rcx);
                next.flags = static_cast<std::uint64_t>(ctx.Rdx);
                next.size = requested_size;
                next.return_address = return_address;
                next.timestamp_ms = unix_time_ms();
                next.callstack = capture_callstack_addresses(pid, ctx, return_address, session.capture_callstack);
                {
                    std::lock_guard<std::mutex> lock(state.mutex);
                    state.pending[evt.dwThreadId] = std::move(next);
                }
                driver_bridge::set_hardware_breakpoint(evt.dwThreadId, session.hw_slot, return_address, 0, 0);
            }
        }
        handled = true;
    }
    if (handled)
    {
        ctx.EFlags |= 0x10000;
        SetThreadContext(thread, &ctx);
    }
    CloseHandle(thread);
    return handled;
}

void heap_debug_loop()
{
    auto& state = heap_debug_state();
    const std::uint32_t pid = state.pid.load(std::memory_order_acquire);
    enable_debug_privilege();
    if (pid == 0 || !DebugActiveProcess(pid))
    {
        state.error.store(GetLastError(), std::memory_order_release);
        state.attached.store(false, std::memory_order_release);
        state.polling.store(false, std::memory_order_release);
        state.running.store(false, std::memory_order_release);
        return;
    }
    DebugSetProcessKillOnExit(FALSE);
    state.error.store(0, std::memory_order_release);
    state.attached.store(true, std::memory_order_release);
    arm_heap_existing_threads(pid);
    bool initial_break_pending = true;
    while (state.polling.load(std::memory_order_acquire))
    {
        if (!event_session_for_pid(pid))
            break;
        DEBUG_EVENT evt{};
        if (!WaitForDebugEvent(&evt, 100))
            continue;
        DWORD continue_status = DBG_CONTINUE;
        if (evt.dwDebugEventCode == EXCEPTION_DEBUG_EVENT)
        {
            const DWORD code = evt.u.Exception.ExceptionRecord.ExceptionCode;
            if (code == EXCEPTION_SINGLE_STEP)
            {
                if (!handle_heap_single_step(pid, evt))
                    continue_status = DBG_EXCEPTION_NOT_HANDLED;
            }
            else if (code == EXCEPTION_BREAKPOINT && evt.u.Exception.dwFirstChance != 0 && initial_break_pending)
            {
                initial_break_pending = false;
                continue_status = DBG_CONTINUE;
            }
            else
            {
                continue_status = DBG_EXCEPTION_NOT_HANDLED;
            }
        }
        else if (evt.dwDebugEventCode == CREATE_THREAD_DEBUG_EVENT)
        {
            auto session = event_session_for_pid(pid);
            if (session)
                arm_heap_session_for_thread(*session, evt.dwThreadId);
        }
        else if (evt.dwDebugEventCode == EXIT_THREAD_DEBUG_EVENT)
        {
            {
                std::lock_guard<std::mutex> lock(state.mutex);
                state.pending.erase(evt.dwThreadId);
            }
            auto session = event_session_for_pid(pid);
            if (session)
            {
                auto updated = *session;
                updated.tids.erase(std::remove(updated.tids.begin(), updated.tids.end(), evt.dwThreadId), updated.tids.end());
                store::update_heap_session(updated);
            }
        }
        else if (evt.dwDebugEventCode == EXIT_PROCESS_DEBUG_EVENT)
        {
            state.polling.store(false, std::memory_order_release);
        }
        close_debug_event_handles(evt);
        ContinueDebugEvent(evt.dwProcessId, evt.dwThreadId, continue_status);
    }
    if (auto session = event_session_for_pid(pid))
        clear_session_breakpoints(*session);
    {
        std::lock_guard<std::mutex> lock(state.mutex);
        state.pending.clear();
    }
    if (state.attached.exchange(false, std::memory_order_acq_rel))
        DebugActiveProcessStop(pid);
    state.polling.store(false, std::memory_order_release);
    state.pid.store(0, std::memory_order_release);
    state.running.store(false, std::memory_order_release);
}

bool start_heap_debug_loop(std::uint32_t pid, std::string& error)
{
    auto& state = heap_debug_state();
    if (state.running.load(std::memory_order_acquire))
    {
        if (state.pid.load(std::memory_order_acquire) == pid && state.attached.load(std::memory_order_acquire))
        {
            arm_heap_existing_threads(pid);
            return true;
        }
        error = "another heap debug-event consumer is already active";
        return false;
    }
    state.pid.store(pid, std::memory_order_release);
    state.error.store(ERROR_IO_PENDING, std::memory_order_release);
    state.attached.store(false, std::memory_order_release);
    state.polling.store(true, std::memory_order_release);
    state.running.store(true, std::memory_order_release);
    if (!work_queue::post_service([]() { heap_debug_loop(); }))
    {
        state.polling.store(false, std::memory_order_release);
        state.running.store(false, std::memory_order_release);
        error = "failed to schedule heap debug-event consumer";
        return false;
    }
    for (int i = 0; i < 80; ++i)
    {
        if (state.attached.load(std::memory_order_acquire))
            return true;
        if (!state.running.load(std::memory_order_acquire))
            break;
        std::this_thread::sleep_for(std::chrono::milliseconds(25));
    }
    const DWORD gle = state.error.load(std::memory_order_acquire);
    error = "DebugActiveProcess failed or timed out, error=" + std::to_string(static_cast<unsigned long>(gle));
    return false;
}

void stop_heap_debug_loop(std::uint32_t pid)
{
    auto& state = heap_debug_state();
    if (state.pid.load(std::memory_order_acquire) != pid)
        return;
    state.polling.store(false, std::memory_order_release);
    for (int i = 0; i < 80 && state.running.load(std::memory_order_acquire); ++i)
        std::this_thread::sleep_for(std::chrono::milliseconds(25));
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

void append_snapshot_diff(store::heap_session_t& session)
{
    auto now = sample_heap(session.pid, session, session.max_captures);
    std::map<std::uint64_t, std::uint64_t> baseline;
    for (const auto& cap : session.baseline)
        baseline[cap.va] = cap.size;
    std::set<std::uint64_t> existing;
    for (const auto& cap : session.captures)
        existing.insert(cap.va);
    for (const auto& cap : now)
    {
        if (session.captures.size() >= session.max_captures)
            break;
        const auto it = baseline.find(cap.va);
        if ((it == baseline.end() || it->second != cap.size) && existing.insert(cap.va).second)
            session.captures.push_back(cap);
    }
    store::update_heap_session(session);
}

tool_result_t start_session(const json& params)
{
    if (!unsafe_confirmed(params))
        return unsafe_required("heap_track_manage start");
    active_process_scope_t scope(params);
    if (!scope.ok())
        return tool_result_t::error(scope.error());

    const std::string backend = backend_param(params);
    if (backend != "auto" && !event_backend_required(backend) && !snapshot_backend_requested(backend))
        return tool_result_t::error("'backend' must be auto, snapshot_diff, polling, event, hwbp, hardware_breakpoint, or debug_events.");

    store::heap_session_t session;
    session.id = store::next_id("heap");
    session.pid = scope.pid();
    session.min_size = numeric_param(params, "min_size", 0, 0, 0x7FFFFFFF);
    session.max_size = numeric_param(params, "max_size", 0, 0, 0x7FFFFFFF);
    session.alignment = numeric_param(params, "alignment", 0, 0, 0x10000);
    session.capture_callstack = bool_param(params, "capture_callstack", true);
    session.max_captures = static_cast<std::uint32_t>(numeric_param(params, "max_captures", 256, 1, 10000));
    session.started_ms = unix_time_ms();
    session.rtl_allocate_heap = resolve_rtl_allocate_heap(scope.pid());
    session.hw_slot = snapshot_backend_requested(backend) ? -1 : static_cast<int>(numeric_param(params, "hw_slot", 2, 0, 3));
    session.baseline = sample_heap(scope.pid(), session, session.max_captures);

    const bool require_event = event_backend_required(backend);
    if (!snapshot_backend_requested(backend) && session.rtl_allocate_heap == 0)
    {
        if (require_event)
            return tool_result_t::error("RtlAllocateHeap could not be resolved; event backend was requested and will not downgrade silently.");
        session.hw_slot = -1;
    }
    if (session.hw_slot >= 0 && has_other_event_session(scope.pid(), session.id))
    {
        if (require_event)
            return tool_result_t::error("Another heap event session is already active for this process.");
        session.hw_slot = -1;
    }

    store::add_heap_session(session);
    bool event_started = false;
    std::string event_error;
    if (session.hw_slot >= 0)
        event_started = start_heap_debug_loop(scope.pid(), event_error);
    if (session.hw_slot >= 0 && !event_started)
    {
        clear_session_breakpoints(session);
        if (require_event)
        {
            store::remove_heap_session(session.id, nullptr);
            return tool_result_t::error("Heap event backend failed: " + event_error);
        }
        session.hw_slot = -1;
        session.tids.clear();
        store::update_heap_session(session);
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
        if (require_event)
        {
            store::remove_heap_session(session.id, nullptr);
            return tool_result_t::error("Heap event backend failed: " + event_error);
        }
        session.hw_slot = -1;
        store::update_heap_session(session);
        event_started = false;
    }
    json result = session_json(session);
    result["session_id"] = session.id;
    result["requested_backend"] = backend;
    result["capture_backend"] = event_started ? "rtlallocateheap_return_debug_event" : "snapshot_diff";
    result["fallback_reason"] = event_started ? json(nullptr) : json(event_error.empty() ? "snapshot_diff backend selected" : event_error);
    result["evidence"] = {
        {"rtl_allocate_heap_resolved", session.rtl_allocate_heap != 0},
        {"debug_event_consumer", event_started},
        {"return_value_capture", event_started},
        {"snapshot_baseline_count", session.baseline.size()}
    };
    return tool_result_t::ok(event_started ? "Heap tracking session started with RtlAllocateHeap return capture." : "Heap tracking session started in snapshot-diff mode.", result);
}

tool_result_t results_session(const json& params)
{
    const std::string id = string_param(params, "session_id");
    if (id.empty())
        return tool_result_t::error("'session_id' is required for results.");
    store::heap_session_t session;
    if (!store::find_heap_session(id, session))
        return tool_result_t::error("Unknown heap tracking session.");
    active_process_scope_t scope(session.pid);
    if (!scope.ok())
        return tool_result_t::error(scope.error());

    if (session.hw_slot < 0 || session.tids.empty())
        append_snapshot_diff(session);
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
    result["evidence"] = {
        {"backend", result["backend"]},
        {"snapshot_diff_baseline_count", session.baseline.size()},
        {"allocation_size_estimates", true},
        {"heap_membership_checked", true},
        {"synthetic_breakpoint_events", false}
    };
    return tool_result_t::ok(result);
}

tool_result_t stop_session(const json& params)
{
    if (!unsafe_confirmed(params))
        return unsafe_required("heap_track_manage stop");
    const std::string id = string_param(params, "session_id");
    if (id.empty())
        return tool_result_t::error("'session_id' is required for stop.");
    store::heap_session_t session;
    if (!store::remove_heap_session(id, &session))
        return tool_result_t::error("Unknown heap tracking session.");
    active_process_scope_t scope(session.pid);
    if (scope.ok())
        clear_session_breakpoints(session);
    if (session.hw_slot >= 0)
        stop_heap_debug_loop(session.pid);
    session.active = false;
    json result = session_json(session);
    result["stopped"] = true;
    result["evidence"] = {
        {"breakpoints_cleared", session.hw_slot >= 0},
        {"debug_event_consumer_stopped", session.hw_slot >= 0}
    };
    return tool_result_t::ok("Heap tracking session stopped.", result);
}
}

tool_result_t manage(const json& params)
{
    const std::string action = compat_action_name(params);
    const json p = compat_action_payload(params);
    if (action == "start") return start_session(p);
    if (action == "results") return results_session(p);
    if (action == "stop") return stop_session(p);
    return compat_unknown_action("heap_track_manage", action);
}
}
