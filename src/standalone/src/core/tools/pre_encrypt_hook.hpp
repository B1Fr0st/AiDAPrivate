#pragma once
#include <cstdint>
#include <string>
#include <vector>
#include <deque>
#include <mutex>
#include <atomic>
#include <thread>
#include <chrono>
#include <cstddef>
#include <windows.h>
#include "work_queue.hpp"
#include <algorithm>
#include <cctype>
#include <cstring>

#include "helpers/diag_log.hpp"
#include "standalone_driver.hpp"

namespace pre_encrypt_hook {

enum class buffer_kind_t : uint32_t {
    linear = 0,
    wsabuf_array = 1,
    sec_buffer_desc = 2
};

struct hook_target_t {
    std::string library_name;
    std::string function_name;
    uint64_t address = 0;
    uint32_t buffer_reg = 1;
    uint32_t size_reg = 2;
    bool active = false;
    uint32_t bp_index = 0;
    buffer_kind_t kind = buffer_kind_t::linear;
    std::vector<uint32_t> armed_tids;
};

struct plaintext_capture_t {
    uint64_t timestamp = 0;
    uint32_t tid = 0;
    std::string function_name;
    std::vector<uint8_t> buffer;
    uint64_t rip = 0;
    std::string module_name;
    uint64_t module_offset = 0;
};

struct state_t {
    std::vector<hook_target_t> targets;
    std::deque<plaintext_capture_t> captures;
    std::mutex mutex;
    std::atomic<bool> active{false};
    std::atomic<bool> polling{false};
    std::atomic<bool> debug_attached{false};
    std::atomic<bool> debug_loop_running{false};
    std::atomic<DWORD> debugger_error{0};
    std::atomic<DWORD> debug_loop_tid{0};
    size_t max_captures = 4096;
    uint32_t attached_pid = 0;
    std::vector<driver_bridge::module_info_t> cached_modules;
};

inline state_t g_state;

struct known_target_t {
    const char* module_pattern;
    const char* export_name;
    uint32_t buffer_reg;
    uint32_t size_reg;
    buffer_kind_t kind;
};

inline const known_target_t g_known_targets[] = {
    { "libssl",    "SSL_write",        1, 2, buffer_kind_t::linear },
    { "ssleay32",  "SSL_write",        1, 2, buffer_kind_t::linear },
    { "nss3",      "PR_Write",         1, 2, buffer_kind_t::linear },
    { "sspicli",   "EncryptMessage",   2, 0, buffer_kind_t::sec_buffer_desc },
    { "secur32",   "EncryptMessage",   2, 0, buffer_kind_t::sec_buffer_desc },
    { "ncrypt",    "SslEncryptPacket", 1, 2, buffer_kind_t::linear },
    { "ws2_32",    "send",             1, 2, buffer_kind_t::linear },
    { "ws2_32",    "WSASend",          1, 2, buffer_kind_t::wsabuf_array },
};

inline bool ci_contains(const std::string& haystack, const char* needle) {
    std::string lower_h = haystack;
    std::string lower_n = needle;
    std::transform(lower_h.begin(), lower_h.end(), lower_h.begin(),
        [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    std::transform(lower_n.begin(), lower_n.end(), lower_n.begin(),
        [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    return lower_h.find(lower_n) != std::string::npos;
}

inline uint64_t register_value(const CONTEXT& ctx, uint32_t reg_index) {
    switch (reg_index) {
    case 0: return static_cast<uint64_t>(ctx.Rcx);
    case 1: return static_cast<uint64_t>(ctx.Rdx);
    case 2: return static_cast<uint64_t>(ctx.R8);
    case 3: return static_cast<uint64_t>(ctx.R9);
    default: return 0;
    }
}

inline size_t bounded_capture_size(uint64_t requested_size) {
    constexpr size_t max_capture_bytes = 2048;
    if (requested_size == 0)
        return 0;
    if (requested_size > max_capture_bytes)
        return max_capture_bytes;
    return static_cast<size_t>(requested_size);
}

inline buffer_kind_t infer_kind_from_name(const std::string& name) {
    if (ci_contains(name, "WSASend"))
        return buffer_kind_t::wsabuf_array;
    if (ci_contains(name, "EncryptMessage"))
        return buffer_kind_t::sec_buffer_desc;
    return buffer_kind_t::linear;
}

inline void append_bounded(std::vector<uint8_t>& dst, const std::vector<uint8_t>& src) {
    constexpr size_t max_capture_bytes = 2048;
    if (dst.size() >= max_capture_bytes || src.empty())
        return;
    const size_t remaining = max_capture_bytes - dst.size();
    const size_t take = (std::min)(remaining, src.size());
    dst.insert(dst.end(), src.begin(), src.begin() + static_cast<ptrdiff_t>(take));
}

inline bool read_target_bytes(uint32_t pid, uint64_t address, size_t size, std::vector<uint8_t>& out) {
    out.clear();
    const size_t copy_size = bounded_capture_size(size);
    if (pid == 0 || address == 0 || copy_size == 0)
        return false;
    if (!driver_bridge::read_memory_for(pid, address, copy_size, out) || out.empty())
        return false;
    if (out.size() > copy_size)
        out.resize(copy_size);
    return true;
}

inline bool capture_linear(uint32_t pid, const CONTEXT& ctx, const hook_target_t& target, std::vector<uint8_t>& out) {
    const uint64_t buffer_address = register_value(ctx, target.buffer_reg);
    const uint64_t requested_size = register_value(ctx, target.size_reg);
    return read_target_bytes(pid, buffer_address, bounded_capture_size(requested_size), out);
}

inline bool capture_wsabuf_array(uint32_t pid, const CONTEXT& ctx, const hook_target_t& target, std::vector<uint8_t>& out) {
    struct remote_wsabuf_t {
        uint32_t len;
        uint32_t pad;
        uint64_t buf;
    };

    out.clear();
    const uint64_t array_address = register_value(ctx, target.buffer_reg);
    uint64_t count = register_value(ctx, target.size_reg);
    if (array_address == 0 || count == 0)
        return false;
    if (count > 16)
        count = 16;

    std::vector<uint8_t> raw;
    if (!driver_bridge::read_memory_for(pid, array_address, static_cast<size_t>(count) * sizeof(remote_wsabuf_t), raw))
        return false;
    if (raw.size() < sizeof(remote_wsabuf_t))
        return false;

    const size_t parsed = raw.size() / sizeof(remote_wsabuf_t);
    for (size_t i = 0; i < parsed; ++i) {
        remote_wsabuf_t entry{};
        std::memcpy(&entry, raw.data() + i * sizeof(remote_wsabuf_t), sizeof(entry));
        std::vector<uint8_t> chunk;
        if (read_target_bytes(pid, entry.buf, bounded_capture_size(entry.len), chunk))
            append_bounded(out, chunk);
    }
    return !out.empty();
}

inline bool capture_sec_buffer_desc(uint32_t pid, const CONTEXT& ctx, const hook_target_t& target, std::vector<uint8_t>& out) {
    struct remote_sec_buffer_desc_t {
        uint32_t ulVersion;
        uint32_t cBuffers;
        uint64_t pBuffers;
    };
    struct remote_sec_buffer_t {
        uint32_t cbBuffer;
        uint32_t BufferType;
        uint64_t pvBuffer;
    };

    out.clear();
    const uint64_t desc_address = register_value(ctx, target.buffer_reg);
    if (desc_address == 0)
        return false;

    std::vector<uint8_t> desc_raw;
    if (!driver_bridge::read_memory_for(pid, desc_address, sizeof(remote_sec_buffer_desc_t), desc_raw) ||
        desc_raw.size() < sizeof(remote_sec_buffer_desc_t))
        return false;

    remote_sec_buffer_desc_t desc{};
    std::memcpy(&desc, desc_raw.data(), sizeof(desc));
    if (desc.cBuffers == 0 || desc.pBuffers == 0)
        return false;
    if (desc.cBuffers > 16)
        desc.cBuffers = 16;

    std::vector<uint8_t> buffers_raw;
    if (!driver_bridge::read_memory_for(pid, desc.pBuffers, static_cast<size_t>(desc.cBuffers) * sizeof(remote_sec_buffer_t), buffers_raw))
        return false;
    if (buffers_raw.size() < sizeof(remote_sec_buffer_t))
        return false;

    const size_t parsed = buffers_raw.size() / sizeof(remote_sec_buffer_t);
    for (size_t i = 0; i < parsed; ++i) {
        remote_sec_buffer_t entry{};
        std::memcpy(&entry, buffers_raw.data() + i * sizeof(remote_sec_buffer_t), sizeof(entry));
        if ((entry.BufferType & 0xFFFFu) != 1u)
            continue;
        std::vector<uint8_t> chunk;
        if (read_target_bytes(pid, entry.pvBuffer, bounded_capture_size(entry.cbBuffer), chunk))
            append_bounded(out, chunk);
    }
    return !out.empty();
}

inline bool capture_target_buffer(uint32_t pid, const CONTEXT& ctx, const hook_target_t& target, std::vector<uint8_t>& out) {
    if (target.kind == buffer_kind_t::wsabuf_array)
        return capture_wsabuf_array(pid, ctx, target, out);
    if (target.kind == buffer_kind_t::sec_buffer_desc)
        return capture_sec_buffer_desc(pid, ctx, target, out);
    return capture_linear(pid, ctx, target, out);
}

inline std::string resolve_module_from_rip(uint64_t rip, uint64_t& offset_out) {
    offset_out = 0;
    for (const auto& mod : g_state.cached_modules) {
        if (rip >= mod.base && rip < mod.base + mod.size) {
            offset_out = rip - mod.base;
            return mod.name;
        }
    }
    return {};
}

inline void record_capture(uint32_t tid, const std::string& function_name,
                           std::vector<uint8_t>&& buffer, uint64_t rip) {
    if (buffer.empty())
        return;

    plaintext_capture_t cap;
    cap.timestamp = static_cast<uint64_t>(GetTickCount64());
    cap.tid = tid;
    cap.function_name = function_name;
    cap.buffer = std::move(buffer);
    cap.rip = rip;

    std::lock_guard<std::mutex> lock(g_state.mutex);
    uint64_t mod_offset = 0;
    cap.module_name = resolve_module_from_rip(cap.rip, mod_offset);
    cap.module_offset = mod_offset;
    g_state.captures.push_back(std::move(cap));

    while (g_state.captures.size() > g_state.max_captures)
        g_state.captures.pop_front();
}

inline std::vector<hook_target_t> targets_snapshot() {
    std::lock_guard<std::mutex> lock(g_state.mutex);
    std::vector<hook_target_t> result;
    for (const auto& target : g_state.targets) {
        if (target.active)
            result.push_back(target);
    }
    return result;
}

inline bool find_target_for_hit(uint64_t rip, uint64_t exception_address, hook_target_t& out) {
    auto targets = targets_snapshot();
    for (const auto& target : targets) {
        if (target.address == rip || target.address == exception_address) {
            out = target;
            return true;
        }
    }
    return false;
}

inline void mark_thread_armed(uint64_t address, uint32_t tid) {
    std::lock_guard<std::mutex> lock(g_state.mutex);
    for (auto& target : g_state.targets) {
        if (target.address != address)
            continue;
        if (std::find(target.armed_tids.begin(), target.armed_tids.end(), tid) == target.armed_tids.end())
            target.armed_tids.push_back(tid);
        return;
    }
}

inline void remove_thread_armed(uint32_t tid) {
    std::lock_guard<std::mutex> lock(g_state.mutex);
    for (auto& target : g_state.targets) {
        auto& tids = target.armed_tids;
        tids.erase(std::remove(tids.begin(), tids.end(), tid), tids.end());
    }
}

inline bool arm_breakpoints_for_thread(uint32_t tid) {
    if (tid == 0 || !driver_bridge::using_kernel_driver())
        return false;

    bool armed = false;
    auto targets = targets_snapshot();
    for (const auto& target : targets) {
        if (driver_bridge::set_hardware_breakpoint(tid, static_cast<int>(target.bp_index), target.address, 0, 0)) {
            mark_thread_armed(target.address, tid);
            armed = true;
        }
    }
    return armed;
}

inline uint32_t target_pid_snapshot() {
    std::lock_guard<std::mutex> lock(g_state.mutex);
    return g_state.attached_pid;
}

inline uint32_t arm_existing_threads() {
    const uint32_t pid = target_pid_snapshot();
    if (pid == 0)
        return 0;
    auto threads = driver_bridge::enumerate_threads_for(pid);
    uint32_t armed = 0;
    for (const auto& thread : threads) {
        if (arm_breakpoints_for_thread(thread.tid))
            ++armed;
    }
    return armed;
}

inline void clear_armed_breakpoints() {
    struct clear_request_t {
        uint32_t tid;
        uint32_t slot;
    };

    std::vector<clear_request_t> clear_requests;
    {
        std::lock_guard<std::mutex> lock(g_state.mutex);
        for (auto& target : g_state.targets) {
            for (uint32_t tid : target.armed_tids)
                clear_requests.push_back({tid, target.bp_index});
            target.armed_tids.clear();
        }
    }

    if (!driver_bridge::using_kernel_driver())
        return;

    for (const auto& req : clear_requests)
        driver_bridge::clear_hardware_breakpoint(req.tid, static_cast<int>(req.slot));
}

inline uint32_t armed_thread_count() {
    std::lock_guard<std::mutex> lock(g_state.mutex);
    uint32_t count = 0;
    for (const auto& target : g_state.targets)
        count += static_cast<uint32_t>(target.armed_tids.size());
    return count;
}

inline bool capture_breakpoint_hit(const DEBUG_EVENT& evt) {
    HANDLE thread_handle = OpenThread(THREAD_GET_CONTEXT | THREAD_SET_CONTEXT, FALSE, evt.dwThreadId);
    if (!thread_handle)
        return false;

    CONTEXT ctx{};
    ctx.ContextFlags = CONTEXT_INTEGER | CONTEXT_CONTROL | CONTEXT_DEBUG_REGISTERS;
    const BOOL got_context = GetThreadContext(thread_handle, &ctx);
    if (!got_context) {
        CloseHandle(thread_handle);
        return false;
    }

    const uint64_t exception_address = reinterpret_cast<uint64_t>(
        evt.u.Exception.ExceptionRecord.ExceptionAddress);

    hook_target_t target;
    if (!find_target_for_hit(static_cast<uint64_t>(ctx.Rip), exception_address, target)) {
        CloseHandle(thread_handle);
        return false;
    }

    uint32_t pid = 0;
    {
        std::lock_guard<std::mutex> lock(g_state.mutex);
        pid = g_state.attached_pid;
    }
    if (pid == 0) {
        CloseHandle(thread_handle);
        return false;
    }

    std::vector<uint8_t> buffer;
    if (!capture_target_buffer(pid, ctx, target, buffer)) {
        ctx.EFlags |= 0x10000;
        SetThreadContext(thread_handle, &ctx);
        CloseHandle(thread_handle);
        return true;
    }

    ctx.EFlags |= 0x10000;
    SetThreadContext(thread_handle, &ctx);
    CloseHandle(thread_handle);
    record_capture(evt.dwThreadId, target.function_name, std::move(buffer), static_cast<uint64_t>(ctx.Rip));
    return true;
}

inline void close_debug_event_handles(const DEBUG_EVENT& evt) {
    switch (evt.dwDebugEventCode) {
    case CREATE_PROCESS_DEBUG_EVENT:
        if (evt.u.CreateProcessInfo.hFile)
            CloseHandle(evt.u.CreateProcessInfo.hFile);
        if (evt.u.CreateProcessInfo.hThread)
            CloseHandle(evt.u.CreateProcessInfo.hThread);
        if (evt.u.CreateProcessInfo.hProcess)
            CloseHandle(evt.u.CreateProcessInfo.hProcess);
        break;
    case CREATE_THREAD_DEBUG_EVENT:
        if (evt.u.CreateThread.hThread)
            CloseHandle(evt.u.CreateThread.hThread);
        break;
    case LOAD_DLL_DEBUG_EVENT:
        if (evt.u.LoadDll.hFile)
            CloseHandle(evt.u.LoadDll.hFile);
        break;
    default:
        break;
    }
}

inline void debug_event_loop() {
    const DWORD tid = GetCurrentThreadId();
    const ULONGLONG start_ms = GetTickCount64();
    g_state.debug_loop_tid.store(tid, std::memory_order_release);
    uint32_t pid = 0;
    {
        std::lock_guard<std::mutex> lock(g_state.mutex);
        pid = g_state.attached_pid;
    }
    diag::log_tagged_fmt("pre_encrypt_hook",
        "debug_loop_enter pid=%u tid=%lu polling=%d attached=%d",
        pid,
        static_cast<unsigned long>(tid),
        g_state.polling.load() ? 1 : 0,
        g_state.debug_attached.load() ? 1 : 0);

    if (pid == 0 || !driver_bridge::using_kernel_driver()) {
        g_state.polling.store(false);
        g_state.debug_loop_running.store(false);
        g_state.active.store(false);
        g_state.debugger_error.store(ERROR_INVALID_PARAMETER);
        g_state.debug_loop_tid.store(0, std::memory_order_release);
        diag::log_tagged_fmt("pre_encrypt_hook",
            "debug_loop_exit_invalid pid=%u tid=%lu elapsed_ms=%llu driver=%d",
            pid,
            static_cast<unsigned long>(tid),
            static_cast<unsigned long long>(GetTickCount64() - start_ms),
            driver_bridge::using_kernel_driver() ? 1 : 0);
        return;
    }

    if (!DebugActiveProcess(pid)) {
        g_state.debugger_error.store(GetLastError());
        g_state.polling.store(false);
        g_state.debug_loop_running.store(false);
        g_state.active.store(false);
        g_state.debug_loop_tid.store(0, std::memory_order_release);
        diag::log_tagged_fmt("pre_encrypt_hook",
            "debug_loop_exit_attach_failed pid=%u tid=%lu elapsed_ms=%llu error=%lu",
            pid,
            static_cast<unsigned long>(tid),
            static_cast<unsigned long long>(GetTickCount64() - start_ms),
            static_cast<unsigned long>(g_state.debugger_error.load()));
        return;
    }

    DebugSetProcessKillOnExit(FALSE);
    g_state.debug_attached.store(true);
    g_state.debugger_error.store(0);
    arm_existing_threads();

    bool initial_break_pending = true;
    while (g_state.polling.load()) {
        DEBUG_EVENT evt{};
        if (!WaitForDebugEvent(&evt, 100))
            continue;

        DWORD continue_status = DBG_CONTINUE;
        if (evt.dwDebugEventCode == EXCEPTION_DEBUG_EVENT) {
            const DWORD code = evt.u.Exception.ExceptionRecord.ExceptionCode;
            if (code == EXCEPTION_SINGLE_STEP) {
                if (!capture_breakpoint_hit(evt))
                    continue_status = DBG_EXCEPTION_NOT_HANDLED;
            } else if (code == EXCEPTION_BREAKPOINT && evt.u.Exception.dwFirstChance != 0 && initial_break_pending) {
                initial_break_pending = false;
                continue_status = DBG_CONTINUE;
            } else {
                continue_status = DBG_EXCEPTION_NOT_HANDLED;
            }
        } else if (evt.dwDebugEventCode == CREATE_THREAD_DEBUG_EVENT) {
            arm_breakpoints_for_thread(evt.dwThreadId);
        } else if (evt.dwDebugEventCode == EXIT_THREAD_DEBUG_EVENT) {
            remove_thread_armed(evt.dwThreadId);
        } else if (evt.dwDebugEventCode == EXIT_PROCESS_DEBUG_EVENT) {
            g_state.active.store(false);
            g_state.polling.store(false);
        }

        close_debug_event_handles(evt);
        ContinueDebugEvent(evt.dwProcessId, evt.dwThreadId, continue_status);
    }

    clear_armed_breakpoints();
    if (g_state.debug_attached.exchange(false))
        DebugActiveProcessStop(pid);
    g_state.polling.store(false);
    g_state.debug_loop_running.store(false);
    g_state.debug_loop_tid.store(0, std::memory_order_release);
    diag::log_tagged_fmt("pre_encrypt_hook",
        "debug_loop_exit pid=%u tid=%lu elapsed_ms=%llu active=%d error=%lu",
        pid,
        static_cast<unsigned long>(tid),
        static_cast<unsigned long long>(GetTickCount64() - start_ms),
        g_state.active.load() ? 1 : 0,
        static_cast<unsigned long>(g_state.debugger_error.load()));
}

inline bool hook_address_with_kind(uint64_t address, const std::string& name,
                                   uint32_t buffer_reg, uint32_t size_reg,
                                   buffer_kind_t kind) {
    if (!driver_bridge::using_kernel_driver())
        return false;

    if (address == 0 || buffer_reg > 3 || size_reg > 3)
        return false;

    uint32_t attached_pid = driver_bridge::attached_pid();
    if (attached_pid == 0)
        return false;

    std::lock_guard<std::mutex> lock(g_state.mutex);
    if (g_state.attached_pid != 0 && g_state.attached_pid != attached_pid)
        return false;

    uint32_t bp_slot = 0;
    bool found_slot = false;
    for (uint32_t i = 0; i < 4; ++i) {
        bool used = false;
        for (const auto& t : g_state.targets) {
            if (t.active && t.bp_index == i) {
                used = true;
                break;
            }
        }
        if (!used) {
            bp_slot = i;
            found_slot = true;
            break;
        }
    }
    if (!found_slot)
        return false;

    for (const auto& t : g_state.targets) {
        if (t.active && t.address == address)
            return true;
    }

    hook_target_t target;
    target.library_name = {};
    target.function_name = name;
    target.address = address;
    target.buffer_reg = buffer_reg;
    target.size_reg = size_reg;
    target.active = true;
    target.bp_index = bp_slot;
    target.kind = kind;
    g_state.attached_pid = attached_pid;
    g_state.targets.push_back(std::move(target));
    g_state.active.store(true);

    return true;
}

inline bool hook_address(uint64_t address, const std::string& name,
                         uint32_t buffer_reg, uint32_t size_reg) {
    return hook_address_with_kind(address, name, buffer_reg, size_reg, infer_kind_from_name(name));
}

inline bool auto_hook(uint32_t pid) {
    if (!driver_bridge::using_kernel_driver())
        return false;

    if (!driver_bridge::is_loaded())
        return false;

    if (g_state.active.load()) {
        std::lock_guard<std::mutex> lock(g_state.mutex);
        if (g_state.attached_pid != 0 && g_state.attached_pid != pid)
            return false;
    }

    if (driver_bridge::attached_pid() != pid) {
        bool already_attached = false;
        const auto attached = driver_bridge::attached_pids();
        for (uint32_t attached_pid : attached) {
            if (attached_pid == pid) {
                already_attached = true;
                break;
            }
        }
        if (already_attached) {
            if (!driver_bridge::set_active_pid(pid))
                return false;
        } else if (!driver_bridge::attach(pid)) {
            return false;
        }
    }

    auto modules = driver_bridge::enumerate_modules();
    if (modules.empty())
        return false;

    {
        std::lock_guard<std::mutex> lock(g_state.mutex);
        g_state.cached_modules = modules;
        g_state.attached_pid = pid;
    }

    uint32_t hooked = 0;
    constexpr uint32_t max_hooks = 4;

    for (const auto& known : g_known_targets) {
        if (hooked >= max_hooks)
            break;

        for (const auto& mod : modules) {
            if (hooked >= max_hooks)
                break;

            if (!ci_contains(mod.name, known.module_pattern))
                continue;

            uint64_t func_addr = driver_bridge::resolve_export(mod.base, known.export_name);
            if (func_addr == 0)
                continue;

            std::string hook_name = mod.name + "!" + known.export_name;
            if (hook_address_with_kind(func_addr, hook_name, known.buffer_reg, known.size_reg, known.kind))
                ++hooked;
        }
    }

    return hooked > 0;
}

inline void unhook_all() {
    g_state.polling.store(false);
    const ULONGLONG wait_start = GetTickCount64();
    for (int i = 0; i < 120 && g_state.debug_loop_running.load(); ++i)
        std::this_thread::sleep_for(std::chrono::milliseconds(25));
    if (g_state.debug_loop_running.load()) {
        diag::log_tagged_fmt("pre_encrypt_hook", "debug_loop_join_timeout pid=%u attached=%d running=%d error=%lu",
            g_state.attached_pid,
            g_state.debug_attached.load() ? 1 : 0,
            g_state.debug_loop_running.load() ? 1 : 0,
            static_cast<unsigned long>(g_state.debugger_error.load()));
    }
    diag::log_tagged_fmt("pre_encrypt_hook",
        "unhook_wait_complete running=%d attached=%d waited_ms=%llu",
        g_state.debug_loop_running.load() ? 1 : 0,
        g_state.debug_attached.load() ? 1 : 0,
        static_cast<unsigned long long>(GetTickCount64() - wait_start));
    clear_armed_breakpoints();

    std::lock_guard<std::mutex> lock(g_state.mutex);

    for (auto& t : g_state.targets)
        t.active = false;
    g_state.targets.clear();
    g_state.active.store(false);
    g_state.attached_pid = 0;
    if (!g_state.polling.load() && !g_state.debug_attached.load())
        g_state.debug_loop_running.store(false);
}

inline bool start_polling() {
    if (!g_state.active.load())
        return false;

    if (g_state.debug_loop_running.load() && !g_state.debug_attached.load() && !g_state.polling.load())
        g_state.debug_loop_running.store(false);

    if (g_state.debug_loop_running.exchange(true)) {
        if (g_state.debug_attached.load())
            arm_existing_threads();
        return g_state.debug_attached.load();
    }

    g_state.polling.store(true);

    bool posted = false;
    try {
        posted = work_queue::post([]() { debug_event_loop(); });
    } catch (...) {
        posted = false;
    }
    if (!posted) {
        const auto qs = work_queue::stats();
        diag::log_tagged_fmt("pre_encrypt_hook",
            "debug_loop_post_failed cq_alive=%d cq_shutdown=%d cq_pending=%zu cq_active=%u cq_posted=%llu cq_rejected=%llu",
            qs.alive ? 1 : 0,
            qs.shutting_down ? 1 : 0,
            qs.pending,
            qs.active,
            static_cast<unsigned long long>(qs.posted),
            static_cast<unsigned long long>(qs.rejected));
        g_state.polling.store(false);
        g_state.debug_loop_running.store(false);
        g_state.debugger_error.store(ERROR_NOT_ENOUGH_MEMORY);
        return false;
    }
    const auto qs = work_queue::stats();
    diag::log_tagged_fmt("pre_encrypt_hook",
        "debug_loop_posted cq_alive=%d cq_shutdown=%d cq_pending=%zu cq_active=%u cq_started=%llu cq_finished=%llu",
        qs.alive ? 1 : 0,
        qs.shutting_down ? 1 : 0,
        qs.pending,
        qs.active,
        static_cast<unsigned long long>(qs.started),
        static_cast<unsigned long long>(qs.finished));

    for (int i = 0; i < 40; ++i) {
        if (g_state.debug_attached.load())
            return true;
        if (!g_state.debug_loop_running.load())
            return false;
        std::this_thread::sleep_for(std::chrono::milliseconds(25));
    }

    return g_state.debug_attached.load();
}

inline void stop_polling() {
    g_state.polling.store(false);
}

inline std::vector<plaintext_capture_t> get_captures(size_t max_count = 64) {
    std::lock_guard<std::mutex> lock(g_state.mutex);
    std::vector<plaintext_capture_t> result;

    size_t count = (std::min)(max_count, g_state.captures.size());
    auto it = g_state.captures.end();
    if (count <= g_state.captures.size())
        it = g_state.captures.end() - static_cast<ptrdiff_t>(count);
    else
        it = g_state.captures.begin();

    for (; it != g_state.captures.end(); ++it)
        result.push_back(*it);

    return result;
}

inline void clear_captures() {
    std::lock_guard<std::mutex> lock(g_state.mutex);
    g_state.captures.clear();
}

inline bool is_active() {
    return g_state.active.load();
}

}
