#define WIN32_LEAN_AND_MEAN
#include "standalone_driver.hpp"
#include "standalone_license.hpp"
#include "anti-tamper/orchestrator.hpp"
#include "driver_loader.hpp"
#include "toast_notification.hpp"
#include "arc/arc.h"
#include "comm.h"
#include "event_bus.hpp"
#include "work_queue.hpp"
#include "../mcp/mcp_standalone.hpp"
#include "../helpers/diag_log.hpp"

#include <windows.h>
#include <psapi.h>
#include <tlhelp32.h>
#include <intrin.h>

#include <algorithm>
#include <atomic>
#include <cstdarg>
#include <cctype>
#include <cstdio>
#include <cstring>
#include <iterator>
#include <memory>
#include <mutex>
#include <string>
#include <thread>
#include <unordered_map>
#include <vector>

#pragma comment(lib, "psapi.lib")

namespace
{
    driver_bridge::log_fn_t     g_log_fn;
    driver_bridge::confirm_fn_t g_confirm_fn;
    std::vector<driver_bridge::pre_detach_fn_t> g_pre_detach_hooks;
    std::mutex                  g_callback_mtx;

    std::mutex      g_state_mtx;
    HANDLE          g_process = nullptr;

    using arc_set_process_id_fn = void (*)(uint32_t);
    using arc_solve_dtb_fn = uint64_t (*)();
    using arc_get_dtb_fn = uint64_t (*)();
    using arc_find_image_fn = uint64_t (*)();
    using arc_set_base_address_fn = void (*)(uint64_t);

    struct arc_vtable_slots_t
    {
        arc_set_process_id_fn set_process_id = nullptr;
        arc_solve_dtb_fn solve_dtb = nullptr;
        arc_get_dtb_fn get_dtb = nullptr;
        arc_find_image_fn find_image = nullptr;
        arc_set_base_address_fn set_base_address = nullptr;
        DWORD exception_code = 0;
    };

    __declspec(noinline) arc_vtable_slots_t read_arc_vtable_slots_guarded(const arc_comm_vtable_t* table)
    {
        arc_vtable_slots_t slots{};
        if (!table)
            return slots;
        __try {
            slots.set_process_id = table->set_process_id;
            slots.solve_dtb = table->solve_dtb;
            slots.get_dtb = table->get_dtb;
            slots.find_image = table->find_image;
            slots.set_base_address = table->set_base_address;
        } __except(EXCEPTION_EXECUTE_HANDLER) {
            slots = {};
            slots.exception_code = GetExceptionCode();
        }
        return slots;
    }

    __declspec(noinline) DWORD call_arc_set_process_id_guarded(arc_set_process_id_fn fn, uint32_t pid)
    {
        DWORD seh_code = 0;
        __try {
            fn(pid);
        } __except(EXCEPTION_EXECUTE_HANDLER) {
            seh_code = GetExceptionCode();
        }
        return seh_code;
    }

    __declspec(noinline) uint64_t call_arc_u64_guarded(arc_solve_dtb_fn fn, DWORD* out_seh_code)
    {
        if (out_seh_code)
            *out_seh_code = 0;
        uint64_t result = 0;
        __try {
            result = fn();
        } __except(EXCEPTION_EXECUTE_HANDLER) {
            if (out_seh_code)
                *out_seh_code = GetExceptionCode();
            result = 0;
        }
        return result;
    }

    __declspec(noinline) uint64_t call_arc_get_dtb_guarded(arc_get_dtb_fn fn, DWORD* out_seh_code)
    {
        if (out_seh_code)
            *out_seh_code = 0;
        uint64_t result = 0;
        __try {
            result = fn();
        } __except(EXCEPTION_EXECUTE_HANDLER) {
            if (out_seh_code)
                *out_seh_code = GetExceptionCode();
            result = 0;
        }
        return result;
    }

    __declspec(noinline) uint64_t call_arc_find_image_guarded(arc_find_image_fn fn, DWORD* out_seh_code)
    {
        if (out_seh_code)
            *out_seh_code = 0;
        uint64_t result = 0;
        __try {
            result = fn();
        } __except(EXCEPTION_EXECUTE_HANDLER) {
            if (out_seh_code)
                *out_seh_code = GetExceptionCode();
            result = 0;
        }
        return result;
    }

    __declspec(noinline) DWORD call_arc_set_base_address_guarded(arc_set_base_address_fn fn, uint64_t base)
    {
        DWORD seh_code = 0;
        __try {
            fn(base);
        } __except(EXCEPTION_EXECUTE_HANDLER) {
            seh_code = GetExceptionCode();
        }
        return seh_code;
    }

    template <typename Fn>
    unsigned long long fn_bits(Fn fn)
    {
        return static_cast<unsigned long long>(reinterpret_cast<uintptr_t>(fn));
    }

    struct arc_attach_resolution_t
    {
        uint32_t pid = 0;
        ULONGLONG started_ms = 0;
        uint64_t dtb = 0;
        uint64_t image_base = 0;
        bool solved = false;
    };

    bool arc_bridge_attach_resolution(arc_attach_resolution_t& ctx)
    {
        return standalone_license::with_arc_comm_bridge(
            [](const arc_comm_vtable_t* table, void* user) -> bool {
                auto* c = static_cast<arc_attach_resolution_t*>(user);
                diag::log_tagged_critical_fmt("driver",
                    "attach_post_get_arc_vtable vtable=%p exc=0x%08lX elapsed_ms=%llu",
                    table,
                    0ul,
                    static_cast<unsigned long long>(GetTickCount64() - c->started_ms));
                const arc_vtable_slots_t arc_slots = read_arc_vtable_slots_guarded(table);
                diag::log_tagged_critical_fmt("driver",
                    "attach_arc_vtable_slots exc=0x%08lX set=0x%llX solve=0x%llX get=0x%llX image=0x%llX base=0x%llX",
                    static_cast<unsigned long>(arc_slots.exception_code),
                    fn_bits(arc_slots.set_process_id),
                    fn_bits(arc_slots.solve_dtb),
                    fn_bits(arc_slots.get_dtb),
                    fn_bits(arc_slots.find_image),
                    fn_bits(arc_slots.set_base_address));
                if (!arc_slots.set_process_id || !arc_slots.solve_dtb || !arc_slots.get_dtb ||
                    !arc_slots.find_image || !arc_slots.set_base_address || arc_slots.exception_code != 0)
                    return false;

                diag::log_tagged_critical("driver", "attach_arc_vtable_pre_set_process_id");
                const DWORD set_pid_exc = call_arc_set_process_id_guarded(arc_slots.set_process_id, c->pid);
                diag::log_tagged_critical_fmt("driver",
                    "attach_arc_vtable_post_set_process_id exc=0x%08lX",
                    static_cast<unsigned long>(set_pid_exc));
                diag::log_tagged_critical("driver", "attach_arc_vtable_pre_solve_dtb");
                DWORD solve_exc = 0;
                uint64_t dtb = (set_pid_exc == 0)
                    ? call_arc_u64_guarded(arc_slots.solve_dtb, &solve_exc)
                    : 0;
                diag::log_tagged_critical_fmt("driver",
                    "attach_arc_vtable_post_solve_dtb dtb=0x%llX exc=0x%08lX",
                    static_cast<unsigned long long>(dtb),
                    static_cast<unsigned long>(solve_exc));
                if (dtb == 0 && set_pid_exc == 0 && solve_exc == 0) {
                    DWORD get_exc = 0;
                    diag::log_tagged_critical("driver", "attach_arc_vtable_pre_get_dtb");
                    dtb = call_arc_get_dtb_guarded(arc_slots.get_dtb, &get_exc);
                    diag::log_tagged_critical_fmt("driver",
                        "attach_arc_vtable_post_get_dtb dtb=0x%llX exc=0x%08lX",
                        static_cast<unsigned long long>(dtb),
                        static_cast<unsigned long>(get_exc));
                }
                if (dtb == 0 || set_pid_exc != 0 || solve_exc != 0)
                    return false;

                c->dtb = dtb;
                c->solved = true;
                diag::log_tagged_critical("driver", "attach_arc_vtable_pre_find_image");
                DWORD find_exc = 0;
                const uint64_t image_base = call_arc_find_image_guarded(arc_slots.find_image, &find_exc);
                diag::log_tagged_critical_fmt("driver",
                    "attach_arc_vtable_post_find_image base=0x%llX exc=0x%08lX",
                    static_cast<unsigned long long>(image_base),
                    static_cast<unsigned long>(find_exc));
                if (image_base != 0 && find_exc == 0) {
                    c->image_base = image_base;
                    const DWORD base_exc = call_arc_set_base_address_guarded(arc_slots.set_base_address, image_base);
                    diag::log_tagged_critical_fmt("driver",
                        "attach_arc_vtable_post_set_base_address base=0x%llX exc=0x%08lX",
                        static_cast<unsigned long long>(image_base),
                        static_cast<unsigned long>(base_exc));
                }
                return true;
            },
            &ctx);
    }

    bool arc_bridge_set_process_id(uint32_t pid)
    {
        struct ctx_t { uint32_t pid; } ctx{pid};
        return standalone_license::with_arc_comm_bridge(
            [](const arc_comm_vtable_t* table, void* user) -> bool {
                auto* c = static_cast<ctx_t*>(user);
                if (!table->set_process_id)
                    return false;
                table->set_process_id(c->pid);
                return true;
            },
            &ctx);
    }

    uint64_t arc_bridge_solve_dtb(bool require_get_dtb)
    {
        struct ctx_t { bool require_get_dtb; uint64_t value; } ctx{require_get_dtb, 0};
        standalone_license::with_arc_comm_bridge(
            [](const arc_comm_vtable_t* table, void* user) -> bool {
                auto* c = static_cast<ctx_t*>(user);
                if (!table->solve_dtb || (c->require_get_dtb && !table->get_dtb))
                    return false;
                c->value = table->solve_dtb();
                return true;
            },
            &ctx);
        return ctx.value;
    }

    uint64_t arc_bridge_find_image()
    {
        struct ctx_t { uint64_t value; } ctx{};
        standalone_license::with_arc_comm_bridge(
            [](const arc_comm_vtable_t* table, void* user) -> bool {
                auto* c = static_cast<ctx_t*>(user);
                if (!table->find_image)
                    return false;
                c->value = table->find_image();
                return true;
            },
            &ctx);
        return ctx.value;
    }

    bool arc_bridge_set_base_address(uint64_t base)
    {
        struct ctx_t { uint64_t base; } ctx{base};
        return standalone_license::with_arc_comm_bridge(
            [](const arc_comm_vtable_t* table, void* user) -> bool {
                auto* c = static_cast<ctx_t*>(user);
                if (!table->set_base_address)
                    return false;
                table->set_base_address(c->base);
                return true;
            },
            &ctx);
    }

    uint32_t arc_bridge_find_process(const char* name)
    {
        if (!name || !*name)
            return 0;
        struct ctx_t { const char* name; uint32_t pid; } ctx{name, 0};
        standalone_license::with_arc_comm_bridge(
            [](const arc_comm_vtable_t* table, void* user) -> bool {
                auto* c = static_cast<ctx_t*>(user);
                if (!table->find_process)
                    return false;
                c->pid = table->find_process(c->name);
                return true;
            },
            &ctx);
        return ctx.pid;
    }

    bool arc_bridge_clear_process_context()
    {
        return standalone_license::with_arc_comm_bridge(
            [](const arc_comm_vtable_t* table, void*) -> bool {
                if (!table->clear_process_context)
                    return false;
                table->clear_process_context();
                return true;
            },
            nullptr);
    }

    size_t arc_bridge_read_raw(uint64_t address, void* buffer, size_t size, bool* invoked = nullptr)
    {
        if (invoked)
            *invoked = false;
        if (!buffer || size == 0)
            return 0;
        struct ctx_t { uint64_t address; void* buffer; size_t size; size_t bytes; bool invoked; } ctx{address, buffer, size, 0, false};
        standalone_license::with_arc_comm_bridge(
            [](const arc_comm_vtable_t* table, void* user) -> bool {
                auto* c = static_cast<ctx_t*>(user);
                if (!table->read_raw)
                    return false;
                c->invoked = true;
                c->bytes = table->read_raw(c->address, c->buffer, c->size);
                return true;
            },
            &ctx);
        if (invoked)
            *invoked = ctx.invoked;
        return ctx.bytes;
    }

    size_t arc_bridge_write_raw(uint64_t address, const void* buffer, size_t size)
    {
        if (!buffer || size == 0)
            return 0;
        struct ctx_t { uint64_t address; const void* buffer; size_t size; size_t bytes; } ctx{address, buffer, size, 0};
        standalone_license::with_arc_comm_bridge(
            [](const arc_comm_vtable_t* table, void* user) -> bool {
                auto* c = static_cast<ctx_t*>(user);
                if (!table->write_raw)
                    return false;
                c->bytes = table->write_raw(c->address, c->buffer, c->size);
                return true;
            },
            &ctx);
        return ctx.bytes;
    }

    bool arc_bridge_enumerate_threads(void (*callback)(const arc_comm_vtable_t::thread_info_t*, void*),
                                      void* callback_ctx,
                                      uint32_t* out_count)
    {
        if (out_count)
            *out_count = 0;
        if (!callback)
            return false;
        struct ctx_t {
            void (*callback)(const arc_comm_vtable_t::thread_info_t*, void*);
            void* callback_ctx;
            uint32_t count;
        } ctx{callback, callback_ctx, 0};
        bool ok = standalone_license::with_arc_comm_bridge(
            [](const arc_comm_vtable_t* table, void* user) -> bool {
                auto* c = static_cast<ctx_t*>(user);
                if (!table->enumerate_threads)
                    return false;
                c->count = table->enumerate_threads(c->callback, c->callback_ctx);
                return true;
            },
            &ctx);
        if (out_count)
            *out_count = ctx.count;
        return ok;
    }

    bool arc_bridge_enumerate_memory_regions(void (*callback)(const arc_comm_vtable_t::memory_region_info_t*, void*),
                                             void* callback_ctx,
                                             uint32_t* out_count)
    {
        if (out_count)
            *out_count = 0;
        if (!callback)
            return false;
        struct ctx_t {
            void (*callback)(const arc_comm_vtable_t::memory_region_info_t*, void*);
            void* callback_ctx;
            uint32_t count;
        } ctx{callback, callback_ctx, 0};
        bool ok = standalone_license::with_arc_comm_bridge(
            [](const arc_comm_vtable_t* table, void* user) -> bool {
                auto* c = static_cast<ctx_t*>(user);
                if (!table->enumerate_memory_regions)
                    return false;
                c->count = table->enumerate_memory_regions(c->callback, c->callback_ctx);
                return true;
            },
            &ctx);
        if (out_count)
            *out_count = ctx.count;
        return ok;
    }

    bool arc_bridge_query_memory(uint64_t address, arc_comm_vtable_t::memory_region_info_t* out)
    {
        if (!out)
            return false;
        struct ctx_t { uint64_t address; arc_comm_vtable_t::memory_region_info_t* out; bool result; } ctx{address, out, false};
        bool ok = standalone_license::with_arc_comm_bridge(
            [](const arc_comm_vtable_t* table, void* user) -> bool {
                auto* c = static_cast<ctx_t*>(user);
                if (!table->query_memory)
                    return false;
                c->result = table->query_memory(c->address, c->out);
                return true;
            },
            &ctx);
        return ok && ctx.result;
    }

    bool arc_bridge_remote_call(uint64_t function_address,
                                uint64_t arg1,
                                uint64_t arg2,
                                uint64_t arg3,
                                uint64_t arg4,
                                uint64_t& result)
    {
        struct ctx_t {
            uint64_t function_address;
            uint64_t arg1;
            uint64_t arg2;
            uint64_t arg3;
            uint64_t arg4;
            uint64_t result;
        } ctx{function_address, arg1, arg2, arg3, arg4, 0};
        bool ok = standalone_license::with_arc_comm_bridge(
            [](const arc_comm_vtable_t* table, void* user) -> bool {
                auto* c = static_cast<ctx_t*>(user);
                if (!table->remote_call)
                    return false;
                c->result = table->remote_call(c->function_address, c->arg1, c->arg2, c->arg3, c->arg4);
                return true;
            },
            &ctx);
        if (ok)
            result = ctx.result;
        return ok;
    }

    uint32_t        g_pid = 0;
    std::string     g_process_name;
    std::string     g_last_error;
    std::atomic<bool> g_last_error_present{false};
    bool            g_initialized = false;
    bool            g_kernel_mode = false;
    bool            g_has_vm_read = false;
    bool            g_kernel_attached = false;
    std::atomic_bool g_adbg_clear_process_dr_supported{ true };
    std::atomic_bool g_adbg_hide_all_threads_supported{ true };
    bool env_flag_enabled(const char* name)
    {
        if (!name || !*name)
            return false;
        char value[16] = {};
        DWORD n = GetEnvironmentVariableA(name, value, static_cast<DWORD>(sizeof(value)));
        if (n == 0)
            return false;
        if (n >= sizeof(value))
            return true;
        return value[0] != '\0' && !(value[0] == '0' && value[1] == '\0');
    }

    bool destructive_driver_action_suppressed()
    {
        if (anti_tamper::state::get().full_test_running.load(std::memory_order_acquire))
            return true;
        if (anti_tamper::state::full_test_suppression_active())
            return true;
        return env_flag_enabled("AIDA_FULL_TEST_RUNNING") ||
               env_flag_enabled("AIDA_DISABLE_DESTRUCTIVE_ENFORCEMENT");
    }

    bool driver_error_toast_suppressed()
    {
        if (anti_tamper::state::get().full_test_running.load(std::memory_order_acquire))
            return true;
        if (anti_tamper::state::full_test_suppression_active())
            return true;
        return env_flag_enabled("AIDA_FULL_TEST_RUNNING");
    }

    bool stale_session_error_toast_suppressed()
    {
        if (driver_error_toast_suppressed())
            return true;
        if (anti_tamper::state::get().violation_latched.load(std::memory_order_acquire))
            return true;
        if (anti_tamper::state::get().license_pending_activation.load(std::memory_order_acquire))
            return true;
        return !standalone_license::is_arc_loaded();
    }

    struct process_ctx_t {
        HANDLE      h_process = nullptr;
        bool        kernel_attached = false;
        bool        has_vm_read = false;
        std::string name;
        uint64_t    cached_image_base = 0;
        uint64_t    cached_dtb = 0;
        uint64_t    cached_kernel_dtb = 0;
    };

    std::unordered_map<uint32_t, process_ctx_t> g_processes;

    thread_local driver_bridge::remote_call_context_t g_remote_call_context_tls;
    thread_local bool g_remote_call_context_active_tls = false;

    const char* nonempty_cstr(const char* value, const char* fallback) noexcept
    {
        return value && value[0] ? value : fallback;
    }

    struct remote_call_snapshot_t
    {
        const char* label = "";
        const char* tool = "";
        const char* diag_id = "";
        uint32_t pid = 0;
        uint32_t timeout_ms = 0;
        uint64_t deadline_ms = 0;
        bool cancelled = false;
        bool require_deadline = false;
        bool context_active = false;
    };

    remote_call_snapshot_t capture_remote_call_snapshot() noexcept
    {
        remote_call_snapshot_t snapshot{};
        const driver_bridge::remote_call_context_t* ctx = g_remote_call_context_active_tls ? &g_remote_call_context_tls : nullptr;
        snapshot.context_active = ctx != nullptr;
        snapshot.label = ctx ? nonempty_cstr(ctx->label, "driver_bridge::call_function") : "driver_bridge::call_function";
        snapshot.tool = ctx ? nonempty_cstr(ctx->tool, mcp_standalone::current_call_tool_name()) : mcp_standalone::current_call_tool_name();
        snapshot.diag_id = ctx ? nonempty_cstr(ctx->diag_id, mcp_standalone::current_call_diag_id()) : mcp_standalone::current_call_diag_id();
        snapshot.pid = ctx && ctx->pid != 0 ? ctx->pid : driver_bridge::attached_pid();
        snapshot.timeout_ms = ctx ? ctx->timeout_ms : 0;
        snapshot.deadline_ms = ctx && ctx->deadline_ms != 0 ? ctx->deadline_ms : mcp_standalone::current_call_deadline_ms();
        snapshot.require_deadline = ctx ? ctx->require_deadline : false;
        snapshot.cancelled = mcp_standalone::current_call_cancelled() ||
            (ctx && ctx->cancel_token && ctx->cancel_token->load(std::memory_order_acquire));
        snapshot.label = nonempty_cstr(snapshot.label, "");
        snapshot.tool = nonempty_cstr(snapshot.tool, "");
        snapshot.diag_id = nonempty_cstr(snapshot.diag_id, "");
        return snapshot;
    }

    uint64_t deadline_remaining_ms(uint64_t deadline_ms, ULONGLONG now) noexcept
    {
        if (deadline_ms == 0 || now >= deadline_ms)
            return 0;
        return deadline_ms - now;
    }

    void release_ctx_handle(process_ctx_t& ctx)
    {
        if (ctx.h_process) {
            CloseHandle(ctx.h_process);
            ctx.h_process = nullptr;
        }
    }

    struct handle_closer
    {
        void operator()(HANDLE h) const
        {
            if (h && h != INVALID_HANDLE_VALUE)
                CloseHandle(h);
        }
    };

    using unique_handle = std::unique_ptr<std::remove_pointer_t<HANDLE>, handle_closer>;

    unique_handle make_handle(HANDLE h)
    {
        return unique_handle((h && h != INVALID_HANDLE_VALUE) ? h : nullptr);
    }

    void logf(const char* fmt, ...)
    {
        char buf[1024];
        va_list ap;
        va_start(ap, fmt);
        vsnprintf(buf, sizeof(buf), fmt, ap);
        va_end(ap);

        OutputDebugStringA(buf);
        std::lock_guard<std::mutex> lk(g_callback_mtx);
        if (g_log_fn)
            g_log_fn(buf);
    }

    void driver_critical_fmt(const char* fmt, ...)
    {
        char buf[2048] = {};
        va_list ap;
        va_start(ap, fmt);
        _vsnprintf_s(buf, sizeof(buf), _TRUNCATE, fmt, ap);
        va_end(ap);
        auto starts_with = [](const char* text, const char* prefix) -> bool {
            return text && prefix && std::strncmp(text, prefix, std::strlen(prefix)) == 0;
        };
        const bool routine_kernel_probe =
            starts_with(buf, "kernel_anti_debug_query_pre ") ||
            starts_with(buf, "kernel_anti_debug_clear_dr_pre ") ||
            starts_with(buf, "kernel_anti_debug_clear_process_dr_pre ") ||
            starts_with(buf, "kernel_anti_debug_scan_debuggers_pre ") ||
            starts_with(buf, "kernel_anti_debug_query_post ok=1 ") ||
            starts_with(buf, "kernel_anti_debug_clear_dr_post ok=1 ") ||
            starts_with(buf, "kernel_anti_debug_clear_process_dr_post ok=1 ") ||
            starts_with(buf, "kernel_anti_debug_scan_debuggers_post ok=1 ");
        if (routine_kernel_probe)
            anti_tamper::webhook::write_log("driver", buf);
        else
            anti_tamper::webhook::write_log_critical("driver", buf);
    }

    std::vector<driver_bridge::thread_info_t> enumerate_threads_usermode_snapshot(uint32_t pid)
    {
        std::vector<driver_bridge::thread_info_t> result;
        if (pid == 0)
            return result;
        auto snapshot = make_handle(CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0));
        if (!snapshot)
            return result;
        THREADENTRY32 te = {};
        te.dwSize = sizeof(te);
        if (Thread32First(snapshot.get(), &te)) {
            do {
                if (te.th32OwnerProcessID == pid) {
                    driver_bridge::thread_info_t t;
                    t.tid = te.th32ThreadID;
                    t.owner_pid = pid;
                    t.priority = te.tpBasePri;
                    t.state = 0;
                    t.rip = 0;
                    result.push_back(t);
                }
            } while (Thread32Next(snapshot.get(), &te));
        }
        std::sort(result.begin(), result.end(), [](const driver_bridge::thread_info_t& a, const driver_bridge::thread_info_t& b) {
            return a.tid < b.tid;
        });
        return result;
    }

    uint64_t driver_fnv1a64(const void* data, size_t len)
    {
        if (!data)
            return 0;
        const auto* p = static_cast<const uint8_t*>(data);
        uint64_t h = 14695981039346656037ULL;
        for (size_t i = 0; i < len; ++i) {
            h ^= static_cast<uint64_t>(p[i]);
            h *= 1099511628211ULL;
        }
        return h;
    }

    void set_last_error_locked(const std::string& text, bool allow_toast = true)
    {
        g_last_error = text;
        g_last_error_present.store(!text.empty(), std::memory_order_release);
        if (!text.empty()) {
            logf("AiDA Standalone: %s\n", text.c_str());
            if (!allow_toast || driver_error_toast_suppressed()) {
                diag::log_tagged_critical_fmt("driver", "driver_error_toast_suppressed text_len=%zu allow_toast=%d full_test_latch=%d env_full_test=%d",
                    text.size(),
                    allow_toast ? 1 : 0,
                    anti_tamper::state::get().full_test_running.load(std::memory_order_acquire) ? 1 : 0,
                    env_flag_enabled("AIDA_FULL_TEST_RUNNING") ? 1 : 0);
            } else {
                toast_notification::push(text, toast_notification::toast_type_t::error);
            }
        }
    }

    void clear_last_error_locked_after_success(const char* source)
    {
        if (!g_last_error.empty()) {
            diag::log_tagged_fmt("driver",
                "last_error_clear_after_success source=%s stale=\"%s\"",
                source ? source : "<null>",
                g_last_error.c_str());
        }
        set_last_error_locked({});
    }

    void clear_last_error_after_success(const char* source)
    {
        if (!g_last_error_present.load(std::memory_order_acquire))
            return;
        std::lock_guard<std::mutex> lk(g_state_mtx);
        clear_last_error_locked_after_success(source);
    }

    void require_kernel_fail(const char* func_name)
    {
        logf("AiDA Standalone: %s requires kernel driver.\n", func_name);
        if (driver_error_toast_suppressed()) {
            diag::log_tagged_critical_fmt("driver", "driver_kernel_required_toast_suppressed func=%s full_test_latch=%d env_full_test=%d",
                func_name ? func_name : "<null>",
                anti_tamper::state::get().full_test_running.load(std::memory_order_acquire) ? 1 : 0,
                env_flag_enabled("AIDA_FULL_TEST_RUNNING") ? 1 : 0);
        } else {
            toast_notification::push(std::string(func_name) + " requires kernel driver",
                                      toast_notification::toast_type_t::error);
        }
    }

    std::atomic<bool> g_driver_watchdog_started{false};
    std::atomic<bool> g_driver_watchdog_stop{false};
    std::atomic<uint64_t> g_driver_watchdog_epoch{0};
    std::atomic<int>  g_driver_consecutive_fail{0};
    std::atomic<uint64_t> g_driver_watchdog_last_ok_tick{0};

    constexpr int    kDriverWatchdogPeriodMs       = 4000;
    constexpr int    kDriverWatchdogFailThreshold  = 8;
    constexpr uint64_t kDriverWatchdogStaleSessionMinAgeMs = 45000;
    constexpr int    kDriverWatchdogRecoveryProbeCount = 2;
    constexpr DWORD  kDriverWatchdogRecoveryProbeDelayMs = 250;
    constexpr DWORD  kDriverFastFailCode           = 0xBEA7DEADu;

    [[noreturn]] void driver_fast_fail(const char* phase, DWORD err)
    {
        char buf[768];
        DWORD hb_err     = device ? device->get_last_heartbeat_error() : 0u;
        DWORD hb_bytes   = device ? device->get_last_heartbeat_bytes_returned() : 0u;
        std::uint64_t hb_resp = device ? device->get_last_heartbeat_response() : 0ull;
        std::uint32_t hb_ioctl = device ? device->get_last_heartbeat_ioctl_code() : 0u;
        std::uint32_t hb_magic = device ? device->get_last_heartbeat_magic() : 0u;
        std::uint32_t hb_base = device ? device->get_last_heartbeat_base() : 0u;
        std::uint32_t hb_key_hash = device ? device->get_last_heartbeat_key_hash() : 0u;
        std::uint32_t hb_ioctl_seed_hash = device ? device->get_last_heartbeat_ioctl_seed_hash() : 0u;
        std::uint32_t hb_inst_server_seed = device ? device->get_last_heartbeat_server_seed_present() : 0u;
        std::uint32_t hb_inst_ioctl_seed = device ? device->get_last_heartbeat_ioctl_seed_present() : 0u;
        std::uint32_t hb_global_server_seed = device ? device->get_last_heartbeat_global_server_seed_present() : 0u;
        std::uint32_t hb_global_ioctl_seed = device ? device->get_last_heartbeat_global_ioctl_seed_present() : 0u;
        std::uint32_t hb_offset = device ? device->get_last_heartbeat_offset() : 0u;
        BOOL hb_dioctl   = device ? device->get_last_heartbeat_dioctl_result() : FALSE;
        _snprintf_s(buf, sizeof(buf), _TRUNCATE,
            "DRIVER_REQUIRED phase=%s err=0x%08X "
            "hb_err=%lu hb_bytes=%lu hb_resp=0x%016llX "
            "hb_ioctl=0x%08X hb_magic=0x%08X hb_dioctl=%d "
            "hb_base=0x%04X hb_offset=%u key_hash=0x%08X ioctl_seed_hash=0x%08X "
            "inst_seed=%u/%u global_seed=%u/%u last_ok_ms=%llu",
            phase ? phase : "?", err,
            (unsigned long)hb_err, (unsigned long)hb_bytes,
            (unsigned long long)hb_resp,
            hb_ioctl, hb_magic, hb_dioctl ? 1 : 0,
            hb_base, hb_offset, hb_key_hash, hb_ioctl_seed_hash,
            hb_inst_server_seed, hb_inst_ioctl_seed,
            hb_global_server_seed, hb_global_ioctl_seed,
            static_cast<unsigned long long>(g_driver_watchdog_last_ok_tick.load(std::memory_order_acquire)));
        const std::string loader_error = driver_loader::last_error();
        diag::log_tagged_critical("driver", buf);
        diag::log_tagged_critical_fmt("driver", "loader_last_error=\"%s\"",
            loader_error.empty() ? "<empty>" : loader_error.c_str());

        char crash[2048];
        _snprintf_s(crash, sizeof(crash), _TRUNCATE,
            "FASTFAIL: code=0x%08X phase=%s err=0x%08X tid=%lu\r\n"
            "Reason=Kernel driver is required, but the loader did not produce a connectable device.\r\n"
            "DriverLoaderLastError=%s\r\n"
            "HeartbeatError=%lu HeartbeatBytes=%lu HeartbeatResponse=0x%016llX\r\n"
            "HeartbeatIoctl=0x%08X HeartbeatMagic=0x%08X HeartbeatDeviceIoctl=%d\r\n"
            "HeartbeatBase=0x%04X HeartbeatOffset=%u HeartbeatKeyHash=0x%08X HeartbeatIoctlSeedHash=0x%08X\r\n"
            "HeartbeatInstanceSeeds=%u/%u HeartbeatGlobalSeeds=%u/%u WatchdogLastOkMs=%llu\r\n"
            "KernelDriverLogExpected=%s\r\n",
            kDriverFastFailCode,
            phase ? phase : "?",
            err,
            GetCurrentThreadId(),
            loader_error.empty() ? "<empty>" : loader_error.c_str(),
            (unsigned long)hb_err,
            (unsigned long)hb_bytes,
            (unsigned long long)hb_resp,
            hb_ioctl,
            hb_magic,
            hb_dioctl ? 1 : 0,
            hb_base,
            hb_offset,
            hb_key_hash,
            hb_ioctl_seed_hash,
            hb_inst_server_seed,
            hb_inst_ioctl_seed,
            hb_global_server_seed,
            hb_global_ioctl_seed,
            static_cast<unsigned long long>(g_driver_watchdog_last_ok_tick.load(std::memory_order_acquire)),
            (err == ERROR_FILE_NOT_FOUND || err == ERROR_PATH_NOT_FOUND) ? "no, DriverEntry likely did not run" : "unknown");
        diag::write_crash_log(crash, false);
        diag::log_tagged_critical("driver", "ABOUT_TO_FASTFAIL_0xBEA7DEAD");
        OutputDebugStringA(buf);
        anti_tamper::webhook::send_debug_log("driver", buf, true);
        Sleep(50);
        __fastfail(kDriverFastFailCode);
    }

    bool driver_startup_fail_closed(const char* phase, DWORD err)
    {
        char buf[1024];
        DWORD hb_err     = device ? device->get_last_heartbeat_error() : 0u;
        DWORD hb_bytes   = device ? device->get_last_heartbeat_bytes_returned() : 0u;
        std::uint64_t hb_resp = device ? device->get_last_heartbeat_response() : 0ull;
        std::uint32_t hb_ioctl = device ? device->get_last_heartbeat_ioctl_code() : 0u;
        std::uint32_t hb_magic = device ? device->get_last_heartbeat_magic() : 0u;
        std::uint32_t hb_base = device ? device->get_last_heartbeat_base() : 0u;
        std::uint32_t hb_key_hash = device ? device->get_last_heartbeat_key_hash() : 0u;
        std::uint32_t hb_ioctl_seed_hash = device ? device->get_last_heartbeat_ioctl_seed_hash() : 0u;
        std::uint32_t hb_inst_server_seed = device ? device->get_last_heartbeat_server_seed_present() : 0u;
        std::uint32_t hb_inst_ioctl_seed = device ? device->get_last_heartbeat_ioctl_seed_present() : 0u;
        std::uint32_t hb_global_server_seed = device ? device->get_last_heartbeat_global_server_seed_present() : 0u;
        std::uint32_t hb_global_ioctl_seed = device ? device->get_last_heartbeat_global_ioctl_seed_present() : 0u;
        std::uint32_t hb_offset = device ? device->get_last_heartbeat_offset() : 0u;
        BOOL hb_dioctl = device ? device->get_last_heartbeat_dioctl_result() : FALSE;
        const std::string loader_error = driver_loader::last_error();
        _snprintf_s(buf, sizeof(buf), _TRUNCATE,
            "DRIVER_REQUIRED_FAIL_CLOSED phase=%s err=0x%08X "
            "hb_err=%lu hb_bytes=%lu hb_resp=0x%016llX "
            "hb_ioctl=0x%08X hb_magic=0x%08X hb_dioctl=%d "
            "hb_base=0x%04X hb_offset=%u key_hash=0x%08X ioctl_seed_hash=0x%08X "
            "inst_seed=%u/%u global_seed=%u/%u loader=\"%s\"",
            phase ? phase : "?",
            err,
            (unsigned long)hb_err,
            (unsigned long)hb_bytes,
            (unsigned long long)hb_resp,
            hb_ioctl,
            hb_magic,
            hb_dioctl ? 1 : 0,
            hb_base,
            hb_offset,
            hb_key_hash,
            hb_ioctl_seed_hash,
            hb_inst_server_seed,
            hb_inst_ioctl_seed,
            hb_global_server_seed,
            hb_global_ioctl_seed,
            loader_error.empty() ? "<empty>" : loader_error.c_str());

        diag::log_tagged_critical("driver", buf);
        anti_tamper::webhook::send_debug_log("driver", buf, true);

        char crash[2048];
        _snprintf_s(crash, sizeof(crash), _TRUNCATE,
            "FAIL_CLOSED: phase=%s err=0x%08X tid=%lu\r\n"
            "Reason=Kernel driver is required, but the loader did not produce a connectable device. AiDA remains locked without crashing.\r\n"
            "DriverLoaderLastError=%s\r\n"
            "HeartbeatError=%lu HeartbeatBytes=%lu HeartbeatResponse=0x%016llX\r\n"
            "HeartbeatIoctl=0x%08X HeartbeatMagic=0x%08X HeartbeatDeviceIoctl=%d\r\n"
            "HeartbeatBase=0x%04X HeartbeatOffset=%u HeartbeatKeyHash=0x%08X HeartbeatIoctlSeedHash=0x%08X\r\n"
            "HeartbeatInstanceSeeds=%u/%u HeartbeatGlobalSeeds=%u/%u WatchdogLastOkMs=%llu\r\n",
            phase ? phase : "?",
            err,
            GetCurrentThreadId(),
            loader_error.empty() ? "<empty>" : loader_error.c_str(),
            (unsigned long)hb_err,
            (unsigned long)hb_bytes,
            (unsigned long long)hb_resp,
            hb_ioctl,
            hb_magic,
            hb_dioctl ? 1 : 0,
            hb_base,
            hb_offset,
            hb_key_hash,
            hb_ioctl_seed_hash,
            hb_inst_server_seed,
            hb_inst_ioctl_seed,
            hb_global_server_seed,
            hb_global_ioctl_seed,
            static_cast<unsigned long long>(g_driver_watchdog_last_ok_tick.load(std::memory_order_acquire)));
        diag::write_crash_log(crash, false);

        std::string ui_error = "Kernel driver is required and could not be started.";
        if (!loader_error.empty())
            ui_error += " " + loader_error;
        set_last_error_locked(ui_error);
        return false;
    }

    void driver_watchdog_thread(uint64_t epoch)
    {
        diag::log_tagged_critical("driver", "watchdog_thread_entry");
        uint64_t hb_iter = 0;
        while (!g_driver_watchdog_stop.load(std::memory_order_acquire) &&
               g_driver_watchdog_epoch.load(std::memory_order_acquire) == epoch) {
            Sleep(kDriverWatchdogPeriodMs);
            if (g_driver_watchdog_stop.load(std::memory_order_acquire) ||
                g_driver_watchdog_epoch.load(std::memory_order_acquire) != epoch) {
                break;
            }
            ++hb_iter;
            bool connected = (device && device->is_connected());
            bool ok = false;
            if (connected) {
                ok = device->send_heartbeat();
            }
            diag::log_tagged_critical_fmt("driver",
                "heartbeat iter=%llu connected=%d ok=%d hb_err=%lu hb_bytes=%lu hb_resp=0x%016llX hb_ioctl=0x%08X hb_magic=0x%08X hb_dioctl=%d hb_base=0x%04X hb_offset=%u key_hash=0x%08X ioctl_seed_hash=0x%08X inst_seed=%u/%u global_seed=%u/%u last_ok_ms=%llu",
                (unsigned long long)hb_iter,
                connected ? 1 : 0,
                ok ? 1 : 0,
                device ? (unsigned long)device->get_last_heartbeat_error() : 0ul,
                device ? (unsigned long)device->get_last_heartbeat_bytes_returned() : 0ul,
                device ? (unsigned long long)device->get_last_heartbeat_response() : 0ull,
                device ? (unsigned int)device->get_last_heartbeat_ioctl_code() : 0u,
                device ? (unsigned int)device->get_last_heartbeat_magic() : 0u,
                (device && device->get_last_heartbeat_dioctl_result()) ? 1 : 0,
                device ? (unsigned int)device->get_last_heartbeat_base() : 0u,
                device ? (unsigned int)device->get_last_heartbeat_offset() : 0u,
                device ? (unsigned int)device->get_last_heartbeat_key_hash() : 0u,
                device ? (unsigned int)device->get_last_heartbeat_ioctl_seed_hash() : 0u,
                device ? (unsigned int)device->get_last_heartbeat_server_seed_present() : 0u,
                device ? (unsigned int)device->get_last_heartbeat_ioctl_seed_present() : 0u,
                device ? (unsigned int)device->get_last_heartbeat_global_server_seed_present() : 0u,
                device ? (unsigned int)device->get_last_heartbeat_global_ioctl_seed_present() : 0u,
                static_cast<unsigned long long>(g_driver_watchdog_last_ok_tick.load(std::memory_order_acquire)));
            if (ok) {
                g_driver_watchdog_last_ok_tick.store(GetTickCount64(), std::memory_order_release);
                g_driver_consecutive_fail.store(0, std::memory_order_release);
                continue;
            }
            int n = g_driver_consecutive_fail.fetch_add(1, std::memory_order_acq_rel) + 1;
            char dbg[256];
            _snprintf_s(dbg, sizeof(dbg), _TRUNCATE,
                "watchdog_heartbeat_fail consecutive=%d hb_err=%lu hb_bytes=%lu",
                n,
                device ? (unsigned long)device->get_last_heartbeat_error() : 0ul,
                device ? (unsigned long)device->get_last_heartbeat_bytes_returned() : 0ul);
            diag::log_tagged_critical("driver", dbg);
            if (n >= kDriverWatchdogFailThreshold) {
                const uint64_t last_ok = g_driver_watchdog_last_ok_tick.load(std::memory_order_acquire);
                if (connected && last_ok != 0) {
                    const uint64_t now_tick = static_cast<uint64_t>(GetTickCount64());
                    const uint64_t last_ok_age = now_tick >= last_ok ? now_tick - last_ok : 0;
                    if (last_ok_age < kDriverWatchdogStaleSessionMinAgeMs) {
                        diag::log_tagged_critical_fmt("driver",
                            "watchdog_stale_session_defer consecutive=%d last_ok_age_ms=%llu min_age_ms=%llu hb_err=%lu hb_ioctl=0x%08X hb_base=0x%04X key_hash=0x%08X inst_seed=%u/%u global_seed=%u/%u",
                            n,
                            static_cast<unsigned long long>(last_ok_age),
                            static_cast<unsigned long long>(kDriverWatchdogStaleSessionMinAgeMs),
                            device ? (unsigned long)device->get_last_heartbeat_error() : 0ul,
                            device ? (unsigned int)device->get_last_heartbeat_ioctl_code() : 0u,
                            device ? (unsigned int)device->get_last_heartbeat_base() : 0u,
                            device ? (unsigned int)device->get_last_heartbeat_key_hash() : 0u,
                            device ? (unsigned int)device->get_last_heartbeat_server_seed_present() : 0u,
                            device ? (unsigned int)device->get_last_heartbeat_ioctl_seed_present() : 0u,
                            device ? (unsigned int)device->get_last_heartbeat_global_server_seed_present() : 0u,
                            device ? (unsigned int)device->get_last_heartbeat_global_ioctl_seed_present() : 0u);
                        g_driver_consecutive_fail.store(kDriverWatchdogFailThreshold - 1, std::memory_order_release);
                        continue;
                    }
                    bool recovered = false;
                    for (int probe = 1; probe <= kDriverWatchdogRecoveryProbeCount; ++probe) {
                        if (g_driver_watchdog_stop.load(std::memory_order_acquire) ||
                            g_driver_watchdog_epoch.load(std::memory_order_acquire) != epoch)
                            break;
                        Sleep(kDriverWatchdogRecoveryProbeDelayMs);
                        const bool probe_connected = (device && device->is_connected());
                        const bool probe_ok = probe_connected && device->send_heartbeat();
                        diag::log_tagged_critical_fmt("driver",
                            "watchdog_recovery_probe probe=%d max=%d connected=%d ok=%d last_ok_age_ms=%llu hb_err=%lu hb_bytes=%lu hb_ioctl=0x%08X hb_base=0x%04X key_hash=0x%08X inst_seed=%u/%u global_seed=%u/%u",
                            probe,
                            kDriverWatchdogRecoveryProbeCount,
                            probe_connected ? 1 : 0,
                            probe_ok ? 1 : 0,
                            static_cast<unsigned long long>(last_ok_age),
                            device ? (unsigned long)device->get_last_heartbeat_error() : 0ul,
                            device ? (unsigned long)device->get_last_heartbeat_bytes_returned() : 0ul,
                            device ? (unsigned int)device->get_last_heartbeat_ioctl_code() : 0u,
                            device ? (unsigned int)device->get_last_heartbeat_base() : 0u,
                            device ? (unsigned int)device->get_last_heartbeat_key_hash() : 0u,
                            device ? (unsigned int)device->get_last_heartbeat_server_seed_present() : 0u,
                            device ? (unsigned int)device->get_last_heartbeat_ioctl_seed_present() : 0u,
                            device ? (unsigned int)device->get_last_heartbeat_global_server_seed_present() : 0u,
                            device ? (unsigned int)device->get_last_heartbeat_global_ioctl_seed_present() : 0u);
                        if (probe_ok) {
                            g_driver_watchdog_last_ok_tick.store(GetTickCount64(), std::memory_order_release);
                            g_driver_consecutive_fail.store(0, std::memory_order_release);
                            recovered = true;
                            break;
                        }
                    }
                    if (recovered)
                        continue;
                    diag::log_tagged_critical_fmt("driver",
                        "watchdog_stale_session_invalidate consecutive=%d last_ok_age_ms=%llu hb_err=%lu hb_ioctl=0x%08X hb_base=0x%04X key_hash=0x%08X inst_seed=%u/%u global_seed=%u/%u",
                        n,
                        static_cast<unsigned long long>(GetTickCount64() - last_ok),
                        device ? (unsigned long)device->get_last_heartbeat_error() : 0ul,
                        device ? (unsigned int)device->get_last_heartbeat_ioctl_code() : 0u,
                        device ? (unsigned int)device->get_last_heartbeat_base() : 0u,
                        device ? (unsigned int)device->get_last_heartbeat_key_hash() : 0u,
                        device ? (unsigned int)device->get_last_heartbeat_server_seed_present() : 0u,
                        device ? (unsigned int)device->get_last_heartbeat_ioctl_seed_present() : 0u,
                        device ? (unsigned int)device->get_last_heartbeat_global_server_seed_present() : 0u,
                        device ? (unsigned int)device->get_last_heartbeat_global_ioctl_seed_present() : 0u);
                    g_driver_consecutive_fail.store(kDriverWatchdogFailThreshold, std::memory_order_release);
                    driver_bridge::invalidate_kernel_session("watchdog_heartbeat_fail");
                    break;
                }
                driver_fast_fail("watchdog", 0xBEA70000u | (device ? device->get_last_heartbeat_error() & 0xFFFFu : 0u));
            }
        }
        if (g_driver_watchdog_epoch.load(std::memory_order_acquire) == epoch)
            g_driver_watchdog_started.store(false, std::memory_order_release);
        diag::log_tagged_critical("driver", "watchdog_thread_exit");
    }

    void start_driver_watchdog_locked()
    {
        const uint64_t started = static_cast<uint64_t>(GetTickCount64());
        driver_critical_fmt("driver_watchdog_post_pre pid=%lu tid=%lu tick=%llu",
            GetCurrentProcessId(),
            GetCurrentThreadId(),
            static_cast<unsigned long long>(started));
        g_driver_watchdog_stop.store(false, std::memory_order_release);
        const uint64_t epoch = g_driver_watchdog_epoch.load(std::memory_order_acquire);
        bool expected = false;
        if (!g_driver_watchdog_started.compare_exchange_strong(expected, true)) {
            driver_critical_fmt("driver_watchdog_post_skip reason=already_started elapsed_ms=%llu",
                static_cast<unsigned long long>(static_cast<uint64_t>(GetTickCount64()) - started));
            return;
        }
        bool posted = work_queue::post_service_labeled("driver_watchdog", [epoch]() {
            driver_critical_fmt("driver_watchdog_thread_entry pid=%lu tid=%lu tick=%llu",
                GetCurrentProcessId(),
                GetCurrentThreadId(),
                static_cast<unsigned long long>(GetTickCount64()));
            driver_watchdog_thread(epoch);
            driver_critical_fmt("driver_watchdog_thread_exit pid=%lu tid=%lu tick=%llu",
                GetCurrentProcessId(),
                GetCurrentThreadId(),
                static_cast<unsigned long long>(GetTickCount64()));
        });
        driver_critical_fmt("driver_watchdog_post_post posted=%d elapsed_ms=%llu",
            posted ? 1 : 0,
            static_cast<unsigned long long>(static_cast<uint64_t>(GetTickCount64()) - started));
        if (!posted) {
            g_driver_watchdog_started.store(false, std::memory_order_release);
            diag::log_tagged("driver", "watchdog_post_failed");
        }
    }

    std::atomic<bool> g_event_poller_started{false};
    std::atomic<bool> g_event_poller_stop{false};
    std::atomic<uint64_t> g_event_poller_epoch{0};
    std::atomic<bool> g_kernel_reconnect_queued{false};
    std::atomic<uint64_t> g_tctx_kernel_bypass_until_ms{0};
    std::atomic<uint32_t> g_tctx_kernel_failures{0};
    constexpr DWORD kKernelReconnectInitialDelayMs = 750;
    constexpr DWORD kKernelReconnectRetryDelayMs = 2000;
    constexpr int kKernelReconnectMaxAttempts = 3;

    struct runtime_auth_snapshot_t
    {
        bool valid = false;
        bool arc_loaded = false;
        bool arc_loading = false;
        bool arc_transfer = false;
        bool arc_exports = false;
        bool pending_activation = true;
        bool violation_latched = false;
        bool activation_hardening = false;
        bool driver_hardening = false;
        std::string missing_exports;
        std::string violation_reason;
        std::string latch_source;
    };

    struct kernel_session_snapshot_t
    {
        bool initialized = false;
        bool kernel_mode = false;
        bool connected = false;
        bool has_vm_read = false;
        bool kernel_attached = false;
        bool watchdog_started = false;
        bool watchdog_stop = false;
        uint32_t active_pid = 0;
        size_t attached_count = 0;
        uint64_t watchdog_last_ok = 0;
        int consecutive_fail = 0;
        DWORD hb_err = 0;
        DWORD hb_bytes = 0;
        uint32_t hb_ioctl = 0;
        uint32_t hb_base = 0;
        uint32_t hb_key_hash = 0;
    };

    runtime_auth_snapshot_t capture_runtime_auth_snapshot()
    {
        runtime_auth_snapshot_t snap{};
        auto& rt = anti_tamper::state::get();
        snap.pending_activation = rt.license_pending_activation.load(std::memory_order_acquire);
        snap.violation_latched = rt.violation_latched.load(std::memory_order_acquire);
        snap.activation_hardening = rt.activation_hardening_done.load(std::memory_order_acquire);
        snap.driver_hardening = rt.driver_hardening_done.load(std::memory_order_acquire);
        {
            std::lock_guard<std::mutex> lk(rt.mtx);
            snap.violation_reason = rt.violation_reason;
        }
        snap.latch_source = anti_tamper::runtime_integrity_latch_source_snapshot();
        snap.arc_loaded = standalone_license::is_arc_loaded();
        snap.arc_loading = standalone_license::is_arc_download_in_progress();
        snap.arc_transfer = standalone_license::is_arc_transfer_in_progress();
        snap.valid = standalone_license::is_valid();
        if (snap.arc_loaded)
            snap.arc_exports = standalone_license::validate_arc_required_exports(snap.missing_exports);
        else
            snap.missing_exports = "arc_not_loaded";
        return snap;
    }

    bool authenticated_runtime_preserved_for_kernel_transition(const runtime_auth_snapshot_t& snap)
    {
        return snap.valid &&
               snap.arc_loaded &&
               snap.arc_exports &&
               snap.activation_hardening &&
               !snap.pending_activation &&
               !snap.violation_latched;
    }

    kernel_session_snapshot_t capture_kernel_session_snapshot_locked()
    {
        kernel_session_snapshot_t snap{};
        snap.initialized = g_initialized;
        snap.kernel_mode = g_kernel_mode;
        snap.connected = device && device->is_connected();
        snap.has_vm_read = g_has_vm_read;
        snap.kernel_attached = g_kernel_attached;
        snap.watchdog_started = g_driver_watchdog_started.load(std::memory_order_acquire);
        snap.watchdog_stop = g_driver_watchdog_stop.load(std::memory_order_acquire);
        snap.active_pid = g_pid;
        snap.attached_count = g_processes.size();
        snap.watchdog_last_ok = g_driver_watchdog_last_ok_tick.load(std::memory_order_acquire);
        snap.consecutive_fail = g_driver_consecutive_fail.load(std::memory_order_acquire);
        snap.hb_err = device ? device->get_last_heartbeat_error() : 0u;
        snap.hb_bytes = device ? device->get_last_heartbeat_bytes_returned() : 0u;
        snap.hb_ioctl = device ? device->get_last_heartbeat_ioctl_code() : 0u;
        snap.hb_base = device ? device->get_last_heartbeat_base() : 0u;
        snap.hb_key_hash = device ? device->get_last_heartbeat_key_hash() : 0u;
        return snap;
    }

    void log_auth_kernel_transition(const char* phase,
                                    const char* reason,
                                    bool preserve_activation,
                                    const runtime_auth_snapshot_t& before_auth,
                                    const runtime_auth_snapshot_t& after_auth,
                                    const kernel_session_snapshot_t& before_kernel,
                                    const kernel_session_snapshot_t& after_kernel)
    {
        driver_critical_fmt(
            "auth_kernel_transition phase=%s reason=%s preserve_activation=%d "
            "auth_valid=%d->%d arc=%d->%d loading=%d->%d transfer=%d->%d exports=%d->%d pending=%d->%d violation=%d->%d activation_hardening=%d->%d driver_hardening=%d->%d missing_before='%.160s' missing_after='%.160s' violation_reason_before='%.160s' violation_reason_after='%.160s' latch_source_before='%.512s' latch_source_after='%.512s' "
            "kernel_initialized=%d->%d kernel_mode=%d->%d connected=%d->%d vm_read=%d->%d kernel_attached=%d->%d pid=%u->%u attached=%llu->%llu watchdog_started=%d->%d watchdog_stop=%d->%d watchdog_last_ok=%llu->%llu consecutive_fail=%d->%d hb_err=%lu->%lu hb_bytes=%lu->%lu hb_ioctl=0x%08X->0x%08X hb_base=0x%04X->0x%04X key_hash=0x%08X->0x%08X",
            phase ? phase : "<null>",
            reason ? reason : "<null>",
            preserve_activation ? 1 : 0,
            before_auth.valid ? 1 : 0,
            after_auth.valid ? 1 : 0,
            before_auth.arc_loaded ? 1 : 0,
            after_auth.arc_loaded ? 1 : 0,
            before_auth.arc_loading ? 1 : 0,
            after_auth.arc_loading ? 1 : 0,
            before_auth.arc_transfer ? 1 : 0,
            after_auth.arc_transfer ? 1 : 0,
            before_auth.arc_exports ? 1 : 0,
            after_auth.arc_exports ? 1 : 0,
            before_auth.pending_activation ? 1 : 0,
            after_auth.pending_activation ? 1 : 0,
            before_auth.violation_latched ? 1 : 0,
            after_auth.violation_latched ? 1 : 0,
            before_auth.activation_hardening ? 1 : 0,
            after_auth.activation_hardening ? 1 : 0,
            before_auth.driver_hardening ? 1 : 0,
            after_auth.driver_hardening ? 1 : 0,
            before_auth.missing_exports.c_str(),
            after_auth.missing_exports.c_str(),
            before_auth.violation_reason.c_str(),
            after_auth.violation_reason.c_str(),
            before_auth.latch_source.c_str(),
            after_auth.latch_source.c_str(),
            before_kernel.initialized ? 1 : 0,
            after_kernel.initialized ? 1 : 0,
            before_kernel.kernel_mode ? 1 : 0,
            after_kernel.kernel_mode ? 1 : 0,
            before_kernel.connected ? 1 : 0,
            after_kernel.connected ? 1 : 0,
            before_kernel.has_vm_read ? 1 : 0,
            after_kernel.has_vm_read ? 1 : 0,
            before_kernel.kernel_attached ? 1 : 0,
            after_kernel.kernel_attached ? 1 : 0,
            before_kernel.active_pid,
            after_kernel.active_pid,
            static_cast<unsigned long long>(before_kernel.attached_count),
            static_cast<unsigned long long>(after_kernel.attached_count),
            before_kernel.watchdog_started ? 1 : 0,
            after_kernel.watchdog_started ? 1 : 0,
            before_kernel.watchdog_stop ? 1 : 0,
            after_kernel.watchdog_stop ? 1 : 0,
            static_cast<unsigned long long>(before_kernel.watchdog_last_ok),
            static_cast<unsigned long long>(after_kernel.watchdog_last_ok),
            before_kernel.consecutive_fail,
            after_kernel.consecutive_fail,
            static_cast<unsigned long>(before_kernel.hb_err),
            static_cast<unsigned long>(after_kernel.hb_err),
            static_cast<unsigned long>(before_kernel.hb_bytes),
            static_cast<unsigned long>(after_kernel.hb_bytes),
            before_kernel.hb_ioctl,
            after_kernel.hb_ioctl,
            before_kernel.hb_base,
            after_kernel.hb_base,
            before_kernel.hb_key_hash,
            after_kernel.hb_key_hash);
    }

    void reset_kernel_transition_hardening_locked(bool preserve_activation)
    {
        auto& rt = anti_tamper::state::get();
        rt.driver_hardening_done.store(false, std::memory_order_release);
        if (!preserve_activation)
            rt.activation_hardening_done.store(false, std::memory_order_release);
    }

    void schedule_kernel_reconnect_after_stale(const char* reason, const runtime_auth_snapshot_t& stale_auth)
    {
        if (!authenticated_runtime_preserved_for_kernel_transition(stale_auth)) {
            driver_critical_fmt("kernel_reconnect_skip reason=%s auth_valid=%d arc=%d exports=%d pending=%d violation=%d activation_hardening=%d",
                reason ? reason : "<null>",
                stale_auth.valid ? 1 : 0,
                stale_auth.arc_loaded ? 1 : 0,
                stale_auth.arc_exports ? 1 : 0,
                stale_auth.pending_activation ? 1 : 0,
                stale_auth.violation_latched ? 1 : 0,
                stale_auth.activation_hardening ? 1 : 0);
            return;
        }

        bool expected = false;
        if (!g_kernel_reconnect_queued.compare_exchange_strong(expected, true, std::memory_order_acq_rel)) {
            driver_critical_fmt("kernel_reconnect_skip reason=%s already_queued=1", reason ? reason : "<null>");
            return;
        }

        const std::string reason_text = (reason && *reason) ? reason : "kernel_stale";
        bool posted = work_queue::post_service_labeled("kernel_reconnect_after_stale", [reason_text]() {
            Sleep(kKernelReconnectInitialDelayMs);
            for (int attempt = 1; attempt <= kKernelReconnectMaxAttempts; ++attempt) {
                runtime_auth_snapshot_t auth = capture_runtime_auth_snapshot();
                if (!authenticated_runtime_preserved_for_kernel_transition(auth)) {
                    driver_critical_fmt("kernel_reconnect_abort reason=%s attempt=%d auth_valid=%d arc=%d exports=%d pending=%d violation=%d activation_hardening=%d missing='%.160s'",
                        reason_text.c_str(),
                        attempt,
                        auth.valid ? 1 : 0,
                        auth.arc_loaded ? 1 : 0,
                        auth.arc_exports ? 1 : 0,
                        auth.pending_activation ? 1 : 0,
                        auth.violation_latched ? 1 : 0,
                        auth.activation_hardening ? 1 : 0,
                        auth.missing_exports.c_str());
                    break;
                }

                driver_critical_fmt("kernel_reconnect_attempt reason=%s attempt=%d max=%d",
                    reason_text.c_str(),
                    attempt,
                    kKernelReconnectMaxAttempts);
                const bool loaded = driver_bridge::load_kernel_driver();
                std::string unavailable_reason;
                const bool available = loaded && driver_bridge::kernel_session_available(&unavailable_reason);
                driver_critical_fmt("kernel_reconnect_result reason=%s attempt=%d loaded=%d available=%d unavailable='%.160s'",
                    reason_text.c_str(),
                    attempt,
                    loaded ? 1 : 0,
                    available ? 1 : 0,
                    unavailable_reason.c_str());
                if (loaded) {
                    auto& rt = anti_tamper::state::get();
                    if (rt.initialized.load(std::memory_order_acquire) &&
                        !rt.driver_hardening_done.load(std::memory_order_acquire) &&
                        !rt.violation_latched.load(std::memory_order_acquire))
                    {
                        const bool at_ok = anti_tamper::initialize();
                        driver_critical_fmt("kernel_reconnect_antitamper_retry reason=%s attempt=%d ok=%d driver_hardening=%d violation=%d",
                            reason_text.c_str(),
                            attempt,
                            at_ok ? 1 : 0,
                            rt.driver_hardening_done.load(std::memory_order_acquire) ? 1 : 0,
                            rt.violation_latched.load(std::memory_order_acquire) ? 1 : 0);
                    }
                    break;
                }
                if (attempt < kKernelReconnectMaxAttempts)
                    Sleep(kKernelReconnectRetryDelayMs);
            }
            g_kernel_reconnect_queued.store(false, std::memory_order_release);
        });

        driver_critical_fmt("kernel_reconnect_post reason=%s posted=%d", reason_text.c_str(), posted ? 1 : 0);
        if (!posted)
            g_kernel_reconnect_queued.store(false, std::memory_order_release);
    }
    struct tctx_kernel_failure_key_t
    {
        uint32_t pid = 0;
        uint32_t tid = 0;
        DWORD status = ERROR_SUCCESS;
        std::string op;
    };
    struct tctx_kernel_failure_state_t
    {
        tctx_kernel_failure_key_t active_key;
        tctx_kernel_failure_key_t last_stable_key;
        bool have_active_key = false;
        bool have_last_stable_key = false;
        uint32_t active_repeats = 0;
        uint32_t distinct_stable_failures = 0;
        uint64_t first_seen_ms = 0;
        uint64_t last_seen_ms = 0;
    };
    std::mutex g_tctx_kernel_failure_mtx;
    tctx_kernel_failure_state_t g_tctx_kernel_failure_state;
    constexpr uint64_t kTctxKernelBypassMs = 120000;
    constexpr uint64_t kTctxSlowFailureMs = 250;
    constexpr uint64_t kTctxFailureEvidenceWindowMs = 30000;
    constexpr uint32_t kTctxStableFailureRepeats = 2;
    constexpr uint32_t kTctxDistinctStableFailuresBeforeBypass = 2;

    bool tctx_kernel_bypass_active()
    {
        const uint64_t until = g_tctx_kernel_bypass_until_ms.load(std::memory_order_acquire);
        return until != 0 && static_cast<uint64_t>(GetTickCount64()) < until;
    }

    void note_tctx_kernel_success()
    {
        g_tctx_kernel_failures.store(0, std::memory_order_release);
        std::lock_guard<std::mutex> lk(g_tctx_kernel_failure_mtx);
        g_tctx_kernel_failure_state = {};
    }

    bool same_tctx_failure_key(const tctx_kernel_failure_key_t& a, const tctx_kernel_failure_key_t& b)
    {
        return a.pid == b.pid && a.tid == b.tid && a.status == b.status && a.op == b.op;
    }

    void arm_tctx_kernel_bypass(const char* op, uint32_t pid, uint32_t tid, DWORD gle, uint64_t elapsed_ms, uint32_t failures, uint32_t key_repeats, uint32_t distinct_stable_failures, const char* reason)
    {
        const uint64_t now = static_cast<uint64_t>(GetTickCount64());
        const uint64_t previous = g_tctx_kernel_bypass_until_ms.exchange(0, std::memory_order_acq_rel);
        diag::log_tagged_fmt("driver",
            "tctx_kernel_bypass_rejected op=%s pid=%u tid=%u gle=%lu elapsed_ms=%llu failures=%u key_repeats=%u distinct_stable_failures=%u previous_remaining_ms=%llu reason=%s fail_closed=1",
            op ? op : "tctx",
            pid,
            tid,
            static_cast<unsigned long>(gle),
            static_cast<unsigned long long>(elapsed_ms),
            failures,
            key_repeats,
            distinct_stable_failures,
            previous > now ? static_cast<unsigned long long>(previous - now) : 0ULL,
            reason ? reason : "unspecified");
    }

    void note_tctx_kernel_failure(const char* op, uint32_t pid, uint32_t tid, DWORD gle, uint64_t elapsed_ms)
    {
        const uint32_t failures = g_tctx_kernel_failures.fetch_add(1, std::memory_order_acq_rel) + 1;
        const bool proven_unavailable = gle == ERROR_PROC_NOT_FOUND || gle == ERROR_INVALID_FUNCTION || gle == ERROR_CALL_NOT_IMPLEMENTED;
        if (proven_unavailable) {
            arm_tctx_kernel_bypass(op, pid, tid, gle, elapsed_ms, failures, failures, failures, "driver_path_unavailable");
            return;
        }

        bool should_arm = false;
        uint32_t key_repeats = 0;
        uint32_t distinct_stable_failures = 0;
        bool stable_evidence = false;
        const uint64_t now = static_cast<uint64_t>(GetTickCount64());
        {
            std::lock_guard<std::mutex> lk(g_tctx_kernel_failure_mtx);
            tctx_kernel_failure_state_t& state = g_tctx_kernel_failure_state;
            if (state.last_seen_ms != 0 && now >= state.last_seen_ms &&
                (now - state.last_seen_ms) > kTctxFailureEvidenceWindowMs) {
                state = {};
            }
            tctx_kernel_failure_key_t key{};
            key.pid = pid;
            key.tid = tid;
            key.status = gle;
            key.op = op ? op : "tctx";
            if (!state.have_active_key || !same_tctx_failure_key(state.active_key, key)) {
                state.active_key = key;
                state.have_active_key = true;
                state.active_repeats = 1;
                if (state.first_seen_ms == 0)
                    state.first_seen_ms = now;
            } else {
                state.active_repeats++;
            }
            state.last_seen_ms = now;
            key_repeats = state.active_repeats;
            stable_evidence = key_repeats >= kTctxStableFailureRepeats || elapsed_ms >= kTctxSlowFailureMs;
            if (stable_evidence &&
                (!state.have_last_stable_key || !same_tctx_failure_key(state.last_stable_key, key))) {
                state.last_stable_key = key;
                state.have_last_stable_key = true;
                state.distinct_stable_failures++;
            }
            distinct_stable_failures = state.distinct_stable_failures;
            should_arm = distinct_stable_failures >= kTctxDistinctStableFailuresBeforeBypass;
        }
        diag::log_tagged_fmt("driver",
            "tctx_kernel_failure_scoped op=%s pid=%u tid=%u gle=%lu elapsed_ms=%llu failures=%u key_repeats=%u stable_evidence=%d distinct_stable_failures=%u arm_global=%d",
            op ? op : "tctx",
            pid,
            tid,
            static_cast<unsigned long>(gle),
            static_cast<unsigned long long>(elapsed_ms),
            failures,
            key_repeats,
            stable_evidence ? 1 : 0,
            distinct_stable_failures,
            should_arm ? 1 : 0);
        if (should_arm) {
            arm_tctx_kernel_bypass(op, pid, tid, gle, elapsed_ms, failures, key_repeats, distinct_stable_failures, "distinct_stable_thread_context_failures");
        }
    }
    constexpr int kEventPollerPeriodMs = 250;
    constexpr size_t kEventPollerDrainBatch = 64;

    std::string utf8_from_wstring(const std::wstring& w)
    {
        if (w.empty()) return {};
        int needed = WideCharToMultiByte(CP_UTF8, 0, w.c_str(),
            static_cast<int>(w.size()), nullptr, 0, nullptr, nullptr);
        if (needed <= 0) return {};
        std::string out(static_cast<size_t>(needed), '\0');
        WideCharToMultiByte(CP_UTF8, 0, w.c_str(),
            static_cast<int>(w.size()), out.data(), needed, nullptr, nullptr);
        return out;
    }

    std::string extract_basename_utf8(const std::string& path)
    {
        if (path.empty()) return {};
        size_t slash = path.find_last_of("\\/");
        if (slash == std::string::npos) return path;
        return path.substr(slash + 1);
    }

    void publish_drained_event(const driver_bridge::debug_event_t& evt)
    {
        switch (evt.type) {
            case driver_bridge::debug_event_type_e::image_loaded: {
                aida::events::dll_loaded_t payload{};
                payload.process_id = evt.process_id;
                payload.thread_id = evt.thread_id;
                payload.image_base = evt.image_base;
                payload.image_size = evt.image_size;
                payload.timestamp = evt.timestamp;
                payload.flags = evt.flags;
                payload.image_path = evt.image_path;
                payload.image_name = evt.image_name;
                aida::events::publish(aida::events::event_dll_loaded, payload);
                break;
            }
            case driver_bridge::debug_event_type_e::process_created: {
                aida::events::process_created_t payload{};
                payload.process_id = evt.process_id;
                payload.timestamp = evt.timestamp;
                payload.image_path = evt.image_path;
                payload.image_name = evt.image_name;
                aida::events::publish(aida::events::event_process_created, payload);
                break;
            }
            case driver_bridge::debug_event_type_e::process_exited: {
                aida::events::process_exited_t payload{};
                payload.process_id = evt.process_id;
                payload.timestamp = evt.timestamp;
                aida::events::publish(aida::events::event_process_exited, payload);
                break;
            }
            case driver_bridge::debug_event_type_e::invalid:
            default:
                break;
        }
    }

    void event_poller_thread(uint64_t epoch)
    {
        diag::log_tagged("driver", "event_poller_thread_entry");
        while (!g_event_poller_stop.load(std::memory_order_acquire) &&
               g_event_poller_epoch.load(std::memory_order_acquire) == epoch) {
            Sleep(kEventPollerPeriodMs);
            if (g_event_poller_stop.load(std::memory_order_acquire) ||
                g_event_poller_epoch.load(std::memory_order_acquire) != epoch)
                break;

            bool kernel_active = false;
            uint32_t pid_filter = 0;
            {
                std::lock_guard<std::mutex> lk(g_state_mtx);
                kernel_active = g_kernel_mode && device && device->is_connected();
                pid_filter = g_pid;
            }
            if (!kernel_active || pid_filter == 0)
                continue;

            std::vector<driver_bridge::debug_event_t> events;
            driver_bridge::debug_event_stats_t stats{};
            if (!driver_bridge::drain_debug_events(events, kEventPollerDrainBatch, &stats))
                continue;

            if (stats.returned_count == 0 && stats.dropped_since_last_drain == 0)
                continue;

            if (stats.returned_count > 0 || stats.dropped_since_last_drain > 0) {
                aida::events::debug_events_drained_t payload{};
                payload.returned_count = stats.returned_count;
                payload.dropped_since_last_drain = stats.dropped_since_last_drain;
                payload.total_dropped = stats.total_dropped;
                payload.total_published = stats.total_published;
                aida::events::publish(aida::events::event_debug_events_drained, payload);
            }

            for (auto& evt : events) {
                publish_drained_event(evt);
            }
        }
        if (g_event_poller_epoch.load(std::memory_order_acquire) == epoch)
            g_event_poller_started.store(false, std::memory_order_release);
        diag::log_tagged("driver", "event_poller_thread_exit");
    }

    void start_event_poller_locked()
    {
        const uint64_t started = static_cast<uint64_t>(GetTickCount64());
        driver_critical_fmt("event_poller_post_pre pid=%lu tid=%lu tick=%llu",
            GetCurrentProcessId(),
            GetCurrentThreadId(),
            static_cast<unsigned long long>(started));
        g_event_poller_stop.store(false, std::memory_order_release);
        const uint64_t epoch = g_event_poller_epoch.load(std::memory_order_acquire);
        bool expected = false;
        if (!g_event_poller_started.compare_exchange_strong(expected, true)) {
            driver_critical_fmt("event_poller_post_skip reason=already_started elapsed_ms=%llu",
                static_cast<unsigned long long>(static_cast<uint64_t>(GetTickCount64()) - started));
            return;
        }
        bool posted = work_queue::post_service_labeled("driver_event_poller", [epoch]() {
            driver_critical_fmt("event_poller_thread_entry pid=%lu tid=%lu tick=%llu",
                GetCurrentProcessId(),
                GetCurrentThreadId(),
                static_cast<unsigned long long>(GetTickCount64()));
            event_poller_thread(epoch);
            driver_critical_fmt("event_poller_thread_exit pid=%lu tid=%lu tick=%llu",
                GetCurrentProcessId(),
                GetCurrentThreadId(),
                static_cast<unsigned long long>(GetTickCount64()));
        });
        driver_critical_fmt("event_poller_post_post posted=%d elapsed_ms=%llu",
            posted ? 1 : 0,
            static_cast<unsigned long long>(static_cast<uint64_t>(GetTickCount64()) - started));
        if (!posted) {
            g_event_poller_started.store(false, std::memory_order_release);
            diag::log_tagged("driver", "event_poller_post_failed");
        }
    }

    std::string utf8_from_wide(const wchar_t* text)
    {
        if (!text || !*text)
            return {};
        char narrow[MAX_PATH * 2] = {};
        WideCharToMultiByte(CP_UTF8, 0, text, -1, narrow, sizeof(narrow), nullptr, nullptr);
        return narrow;
    }

    bool refresh_process_name_locked()
    {
        g_process_name.clear();
        if (!g_process)
            return false;

        wchar_t path[MAX_PATH] = {};
        DWORD len = static_cast<DWORD>(std::size(path));
        if (QueryFullProcessImageNameW(g_process, 0, path, &len) && len > 0) {
            std::wstring full(path, path + len);
            auto slash = full.find_last_of(L"\\/");
            g_process_name = utf8_from_wide(slash == std::wstring::npos ? full.c_str() : full.c_str() + slash + 1);
            return true;
        }
        return false;
    }

    std::string process_name_from_pid(uint32_t pid)
    {
        auto snapshot = make_handle(CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0));
        if (!snapshot)
            return {};

        PROCESSENTRY32W pe = {};
        pe.dwSize = sizeof(pe);
        if (!Process32FirstW(snapshot.get(), &pe))
            return {};

        do {
            if (pe.th32ProcessID == pid)
                return utf8_from_wide(pe.szExeFile);
        } while (Process32NextW(snapshot.get(), &pe));

        return {};
    }

    void close_process_handle_locked()
    {
        if (g_process) {
            CloseHandle(g_process);
            g_process = nullptr;
        }
    }

    std::string to_lower_copy(std::string text)
    {
        std::transform(text.begin(), text.end(), text.begin(), [](unsigned char c) {
            return static_cast<char>(std::tolower(c));
        });
        return text;
    }
}

namespace driver_bridge
{
    bool refresh_kernel_context_locked(uint32_t pid, process_ctx_t& ctx);

    scoped_remote_call_context_t::scoped_remote_call_context_t(const remote_call_context_t& context)
        : previous_(g_remote_call_context_tls)
        , previous_active_(g_remote_call_context_active_tls)
        , active_(true)
    {
        g_remote_call_context_tls = context;
        g_remote_call_context_active_tls = true;
    }

    scoped_remote_call_context_t::~scoped_remote_call_context_t()
    {
        if (!active_)
            return;
        if (previous_active_) {
            g_remote_call_context_tls = previous_;
            g_remote_call_context_active_tls = true;
        } else {
            g_remote_call_context_tls = {};
            g_remote_call_context_active_tls = false;
        }
        active_ = false;
    }

    const char* current_remote_call_label() noexcept
    {
        return capture_remote_call_snapshot().label;
    }

    const char* current_remote_call_tool_name() noexcept
    {
        return capture_remote_call_snapshot().tool;
    }

    const char* current_remote_call_diag_id() noexcept
    {
        return capture_remote_call_snapshot().diag_id;
    }

    uint32_t current_remote_call_pid() noexcept
    {
        return capture_remote_call_snapshot().pid;
    }

    uint32_t current_remote_call_timeout_ms() noexcept
    {
        return capture_remote_call_snapshot().timeout_ms;
    }

    uint64_t current_remote_call_deadline_ms() noexcept
    {
        return capture_remote_call_snapshot().deadline_ms;
    }

    bool current_remote_call_cancelled() noexcept
    {
        return capture_remote_call_snapshot().cancelled;
    }

    void set_log_callback(log_fn_t fn)
    {
        std::lock_guard<std::mutex> lk(g_callback_mtx);
        g_log_fn = std::move(fn);
    }

    void set_confirm_callback(confirm_fn_t fn)
    {
        std::lock_guard<std::mutex> lk(g_callback_mtx);
        g_confirm_fn = std::move(fn);
    }

    void add_pre_detach_callback(pre_detach_fn_t fn)
    {
        std::lock_guard<std::mutex> lk(g_callback_mtx);
        g_pre_detach_hooks.push_back(std::move(fn));
    }

    void debug_log(const char* fmt, ...)
    {
        char buf[1024];
        va_list ap;
        va_start(ap, fmt);
        vsnprintf(buf, sizeof(buf), fmt, ap);
        va_end(ap);
        logf("%s", buf);
    }

    void invalidate_kernel_session(const char* reason)
    {
        const runtime_auth_snapshot_t before_auth = capture_runtime_auth_snapshot();
        const bool preserve_activation = authenticated_runtime_preserved_for_kernel_transition(before_auth);
        kernel_session_snapshot_t before_kernel{};
        kernel_session_snapshot_t after_kernel{};
        {
            std::lock_guard<std::mutex> lk(g_state_mtx);
            before_kernel = capture_kernel_session_snapshot_locked();
            diag::log_tagged_critical_fmt("driver",
                "invalidate_kernel_session reason=%s initialized=%d kernel=%d connected=%d preserve_activation=%d auth_valid=%d arc=%d exports=%d pending=%d violation=%d activation_hardening=%d driver_hardening=%d",
                reason ? reason : "<null>",
                g_initialized ? 1 : 0,
                g_kernel_mode ? 1 : 0,
                (device && device->is_connected()) ? 1 : 0,
                preserve_activation ? 1 : 0,
                before_auth.valid ? 1 : 0,
                before_auth.arc_loaded ? 1 : 0,
                before_auth.arc_exports ? 1 : 0,
                before_auth.pending_activation ? 1 : 0,
                before_auth.violation_latched ? 1 : 0,
                before_auth.activation_hardening ? 1 : 0,
                before_auth.driver_hardening ? 1 : 0);
            reset_kernel_transition_hardening_locked(preserve_activation);
            g_kernel_mode = false;
            g_initialized = false;
            g_has_vm_read = false;
            g_kernel_attached = false;
            g_pid = 0;
            g_process_name.clear();
            g_driver_watchdog_stop.store(true, std::memory_order_release);
            g_event_poller_stop.store(true, std::memory_order_release);
            g_driver_watchdog_epoch.fetch_add(1, std::memory_order_acq_rel);
            g_event_poller_epoch.fetch_add(1, std::memory_order_acq_rel);
            g_driver_watchdog_started.store(false, std::memory_order_release);
            g_event_poller_started.store(false, std::memory_order_release);
            g_driver_consecutive_fail.store(0, std::memory_order_release);
            g_driver_watchdog_last_ok_tick.store(0, std::memory_order_release);
            close_process_handle_locked();
            for (auto& kv : g_processes)
                release_ctx_handle(kv.second);
            g_processes.clear();
            if (device)
                device->disconnect();
            const bool suppress_toast = stale_session_error_toast_suppressed();
            const bool allow_toast = !suppress_toast && !preserve_activation;
            diag::log_tagged_critical_fmt("driver",
                "stale_session_toast_policy reason=%s suppress=%d allow_toast=%d violation_latched=%d pending_activation=%d arc_loaded=%d preserve_activation=%d",
                reason ? reason : "<null>",
                suppress_toast ? 1 : 0,
                allow_toast ? 1 : 0,
                anti_tamper::state::get().violation_latched.load(std::memory_order_acquire) ? 1 : 0,
                anti_tamper::state::get().license_pending_activation.load(std::memory_order_acquire) ? 1 : 0,
                standalone_license::is_arc_loaded() ? 1 : 0,
                preserve_activation ? 1 : 0);
            set_last_error_locked(
                preserve_activation
                    ? "Kernel driver session became stale; AiDA kept the authenticated IDE session active and degraded driver-backed capabilities while reconnecting."
                    : "Kernel driver session became stale during activation; AiDA did not treat this as tampering.",
                allow_toast);
            after_kernel = capture_kernel_session_snapshot_locked();
        }
        const runtime_auth_snapshot_t after_auth = capture_runtime_auth_snapshot();
        log_auth_kernel_transition("invalidate_kernel_session",
            reason,
            preserve_activation,
            before_auth,
            after_auth,
            before_kernel,
            after_kernel);
        schedule_kernel_reconnect_after_stale(reason, after_auth);
    }

    void shutdown(const char* reason)
    {
        const char* reason_text = (reason && *reason) ? reason : "shutdown";
        const uint64_t started = static_cast<uint64_t>(GetTickCount64());
        const runtime_auth_snapshot_t before_auth = capture_runtime_auth_snapshot();
        kernel_session_snapshot_t before_kernel{};
        kernel_session_snapshot_t after_kernel{};
        bool kernel_mode = false;
        bool connected = false;
        uint32_t active_pid = 0;
        size_t attached_count = 0;
        {
            std::lock_guard<std::mutex> lk(g_state_mtx);
            before_kernel = capture_kernel_session_snapshot_locked();
            kernel_mode = g_kernel_mode;
            connected = device && device->is_connected();
            active_pid = g_pid;
            attached_count = g_processes.size();
            driver_critical_fmt(
                "shutdown_begin reason=%s initialized=%d kernel=%d connected=%d active_pid=%u attached=%llu watchdog_started=%d watchdog_stop=%d event_started=%d event_stop=%d tid=%lu",
                reason_text,
                g_initialized ? 1 : 0,
                kernel_mode ? 1 : 0,
                connected ? 1 : 0,
                active_pid,
                static_cast<unsigned long long>(attached_count),
                g_driver_watchdog_started.load(std::memory_order_acquire) ? 1 : 0,
                g_driver_watchdog_stop.load(std::memory_order_acquire) ? 1 : 0,
                g_event_poller_started.load(std::memory_order_acquire) ? 1 : 0,
                g_event_poller_stop.load(std::memory_order_acquire) ? 1 : 0,
                GetCurrentThreadId());
            g_driver_watchdog_stop.store(true, std::memory_order_release);
            g_event_poller_stop.store(true, std::memory_order_release);
            g_driver_watchdog_epoch.fetch_add(1, std::memory_order_acq_rel);
            g_event_poller_epoch.fetch_add(1, std::memory_order_acq_rel);
            g_driver_watchdog_started.store(false, std::memory_order_release);
            g_event_poller_started.store(false, std::memory_order_release);
            g_driver_consecutive_fail.store(0, std::memory_order_release);
            g_driver_watchdog_last_ok_tick.store(0, std::memory_order_release);
        }

        bool self_unregistered = false;
        DWORD self_unregister_error = ERROR_SUCCESS;
        if (kernel_mode && connected)
        {
            SetLastError(ERROR_SUCCESS);
            self_unregistered = unregister_self_dll_protection();
            self_unregister_error = self_unregistered ? ERROR_SUCCESS : GetLastError();
            driver_critical_fmt(
                "shutdown_unregister_self_dll_protection ok=%d err=%lu elapsed_ms=%llu",
                self_unregistered ? 1 : 0,
                static_cast<unsigned long>(self_unregister_error),
                static_cast<unsigned long long>(static_cast<uint64_t>(GetTickCount64()) - started));
        }
        else
        {
            driver_critical_fmt(
                "shutdown_unregister_self_dll_protection skipped kernel=%d connected=%d elapsed_ms=%llu",
                kernel_mode ? 1 : 0,
                connected ? 1 : 0,
                static_cast<unsigned long long>(static_cast<uint64_t>(GetTickCount64()) - started));
        }

        {
            std::lock_guard<std::mutex> lk(g_state_mtx);
            bool clear_context_ok = true;
            if (g_kernel_mode && device && device->is_connected())
            {
                clear_context_ok = arc_bridge_clear_process_context();
                if (!clear_context_ok)
                    device->clear_process_context();
            }
            close_process_handle_locked();
            for (auto& kv : g_processes)
                release_ctx_handle(kv.second);
            g_processes.clear();
            g_pid = 0;
            g_process_name.clear();
            g_has_vm_read = false;
            g_kernel_attached = false;
            g_kernel_mode = false;
            g_initialized = false;
            anti_tamper::state::get().driver_hardening_done.store(false, std::memory_order_release);
            anti_tamper::state::get().activation_hardening_done.store(false, std::memory_order_release);
            bool disconnect_attempted = device != nullptr;
            bool disconnect_connected_before = device && device->is_connected();
            if (device)
                device->disconnect();
            bool disconnect_connected_after = device && device->is_connected();
            set_last_error_locked({});
            after_kernel = capture_kernel_session_snapshot_locked();
            driver_critical_fmt(
                "shutdown_done reason=%s self_unreg=%d self_unreg_err=%lu clear_context_ok=%d disconnect_attempted=%d connected_before=%d connected_after=%d elapsed_ms=%llu tid=%lu",
                reason_text,
                self_unregistered ? 1 : 0,
                static_cast<unsigned long>(self_unregister_error),
                clear_context_ok ? 1 : 0,
                disconnect_attempted ? 1 : 0,
                disconnect_connected_before ? 1 : 0,
                disconnect_connected_after ? 1 : 0,
                static_cast<unsigned long long>(static_cast<uint64_t>(GetTickCount64()) - started),
                GetCurrentThreadId());
        }
        const runtime_auth_snapshot_t after_auth = capture_runtime_auth_snapshot();
        log_auth_kernel_transition("shutdown",
            reason_text,
            false,
            before_auth,
            after_auth,
            before_kernel,
            after_kernel);
    }

    bool initialize()
    {
        const uint64_t started = static_cast<uint64_t>(GetTickCount64());
        const runtime_auth_snapshot_t before_auth = capture_runtime_auth_snapshot();
        const bool preserve_activation = authenticated_runtime_preserved_for_kernel_transition(before_auth);
        driver_critical_fmt("initialize_enter pid=%lu tid=%lu tick=%llu",
            GetCurrentProcessId(),
            GetCurrentThreadId(),
            static_cast<unsigned long long>(started));
        std::lock_guard<std::mutex> lk(g_state_mtx);
        kernel_session_snapshot_t before_kernel = capture_kernel_session_snapshot_locked();
        driver_critical_fmt("initialize_state initialized=%d kernel=%d elapsed_ms=%llu",
            g_initialized ? 1 : 0,
            g_kernel_mode ? 1 : 0,
            static_cast<unsigned long long>(static_cast<uint64_t>(GetTickCount64()) - started));
        if (g_initialized)
        {
            driver_critical_fmt("initialize_exit reason=already_initialized kernel=%d elapsed_ms=%llu",
                g_kernel_mode ? 1 : 0,
                static_cast<unsigned long long>(static_cast<uint64_t>(GetTickCount64()) - started));
            return true;
        }

        g_kernel_mode = false;
        reset_kernel_transition_hardening_locked(preserve_activation);
        g_adbg_clear_process_dr_supported.store(true, std::memory_order_release);
        g_adbg_hide_all_threads_supported.store(true, std::memory_order_release);
        g_driver_watchdog_last_ok_tick.store(0, std::memory_order_release);
        clear_last_error_locked_after_success("initialize_reset");
        kernel_session_snapshot_t after_reset_kernel = capture_kernel_session_snapshot_locked();
        runtime_auth_snapshot_t after_reset_auth = capture_runtime_auth_snapshot();
        log_auth_kernel_transition("initialize_reset",
            "initialize",
            preserve_activation,
            before_auth,
            after_reset_auth,
            before_kernel,
            after_reset_kernel);

        driver_critical_fmt("initialize_connect_existing_pre device=%d elapsed_ms=%llu",
            device ? 1 : 0,
            static_cast<unsigned long long>(static_cast<uint64_t>(GetTickCount64()) - started));
        if (device && device->connect()) {
            driver_critical_fmt("initialize_connect_existing_post ok=1 elapsed_ms=%llu hb_err=%lu hb_bytes=%lu",
                static_cast<unsigned long long>(static_cast<uint64_t>(GetTickCount64()) - started),
                static_cast<unsigned long>(device->get_last_heartbeat_error()),
                static_cast<unsigned long>(device->get_last_heartbeat_bytes_returned()));
            diag::log_tagged_fmt("driver", "connected to existing driver instance, skipping mapper");
            driver_loader::mark_already_loaded();
            g_kernel_mode = true;
            g_initialized = true;
            logf("AiDA Standalone: Connected to already-loaded driver (reuse, no remap).\n");
            start_driver_watchdog_locked();
            start_event_poller_locked();
            kernel_session_snapshot_t after_kernel = capture_kernel_session_snapshot_locked();
            runtime_auth_snapshot_t after_auth = capture_runtime_auth_snapshot();
            log_auth_kernel_transition("initialize_connect_existing",
                "initialize",
                preserve_activation,
                before_auth,
                after_auth,
                before_kernel,
                after_kernel);
            driver_critical_fmt("initialize_exit reason=existing_driver ok=1 kernel=1 elapsed_ms=%llu",
                static_cast<unsigned long long>(static_cast<uint64_t>(GetTickCount64()) - started));
            return true;
        }
        DWORD existing_connect_err = device ? device->get_last_connect_error() : GetLastError();
        BOOL existing_hb_ioctl = device ? device->get_last_heartbeat_dioctl_result() : FALSE;
        DWORD existing_hb_bytes = device ? device->get_last_heartbeat_bytes_returned() : 0u;
        DWORD existing_hb_err = device ? device->get_last_heartbeat_error() : 0u;
        driver_critical_fmt("initialize_connect_existing_post ok=0 err=%lu hb_ioctl=%d hb_err=%lu hb_bytes=%lu elapsed_ms=%llu",
            static_cast<unsigned long>(existing_connect_err),
            existing_hb_ioctl ? 1 : 0,
            static_cast<unsigned long>(existing_hb_err),
            static_cast<unsigned long>(existing_hb_bytes),
            static_cast<unsigned long long>(static_cast<uint64_t>(GetTickCount64()) - started));

        const bool existing_driver_unreachable =
            ((existing_connect_err & 0xFFFF0000u) == 0xBEA70000u) ||
            existing_hb_ioctl ||
            existing_hb_bytes != 0 ||
            existing_connect_err == 433u ||
            existing_connect_err == ERROR_ACCESS_DENIED;
        if (device && existing_driver_unreachable) {
            for (int attempt = 1; attempt <= 3; ++attempt) {
                Sleep(300);
                driver_critical_fmt("initialize_existing_driver_retry_pre attempt=%d err=%lu hb_ioctl=%d hb_err=%lu hb_bytes=%lu elapsed_ms=%llu",
                    attempt,
                    static_cast<unsigned long>(device->get_last_connect_error()),
                    device->get_last_heartbeat_dioctl_result() ? 1 : 0,
                    static_cast<unsigned long>(device->get_last_heartbeat_error()),
                    static_cast<unsigned long>(device->get_last_heartbeat_bytes_returned()),
                    static_cast<unsigned long long>(static_cast<uint64_t>(GetTickCount64()) - started));
                if (device->connect()) {
                    driver_critical_fmt("initialize_existing_driver_retry_post attempt=%d ok=1 elapsed_ms=%llu hb_err=%lu hb_bytes=%lu",
                        attempt,
                        static_cast<unsigned long long>(static_cast<uint64_t>(GetTickCount64()) - started),
                        static_cast<unsigned long>(device->get_last_heartbeat_error()),
                        static_cast<unsigned long>(device->get_last_heartbeat_bytes_returned()));
                    diag::log_tagged_fmt("driver", "connected to existing driver instance after guarded retry, skipping mapper");
                    driver_loader::mark_already_loaded();
                    g_kernel_mode = true;
                    g_initialized = true;
                    logf("AiDA Standalone: Connected to already-loaded driver after guarded retry.\n");
                    start_driver_watchdog_locked();
                    start_event_poller_locked();
                    kernel_session_snapshot_t after_kernel = capture_kernel_session_snapshot_locked();
                    runtime_auth_snapshot_t after_auth = capture_runtime_auth_snapshot();
                    log_auth_kernel_transition("initialize_existing_driver_retry",
                        "initialize",
                        preserve_activation,
                        before_auth,
                        after_auth,
                        before_kernel,
                        after_kernel);
                    driver_critical_fmt("initialize_exit reason=existing_driver_retry ok=1 kernel=1 elapsed_ms=%llu",
                        static_cast<unsigned long long>(static_cast<uint64_t>(GetTickCount64()) - started));
                    return true;
                }
                driver_critical_fmt("initialize_existing_driver_retry_post attempt=%d ok=0 err=%lu hb_ioctl=%d hb_err=%lu hb_bytes=%lu elapsed_ms=%llu",
                    attempt,
                    static_cast<unsigned long>(device->get_last_connect_error()),
                    device->get_last_heartbeat_dioctl_result() ? 1 : 0,
                    static_cast<unsigned long>(device->get_last_heartbeat_error()),
                    static_cast<unsigned long>(device->get_last_heartbeat_bytes_returned()),
                    static_cast<unsigned long long>(static_cast<uint64_t>(GetTickCount64()) - started));
            }
            DWORD guarded_err = device->get_last_connect_error();
            driver_critical_fmt("initialize_exit reason=existing_driver_unreachable_no_remap err=%lu hb_ioctl=%d hb_err=%lu hb_bytes=%lu elapsed_ms=%llu",
                static_cast<unsigned long>(guarded_err),
                device->get_last_heartbeat_dioctl_result() ? 1 : 0,
                static_cast<unsigned long>(device->get_last_heartbeat_error()),
                static_cast<unsigned long>(device->get_last_heartbeat_bytes_returned()),
                static_cast<unsigned long long>(static_cast<uint64_t>(GetTickCount64()) - started));
            return driver_startup_fail_closed("initialize_existing_driver_unreachable_no_remap", guarded_err);
        }

        driver_critical_fmt("initialize_loader_pre elapsed_ms=%llu",
            static_cast<unsigned long long>(static_cast<uint64_t>(GetTickCount64()) - started));
        bool loader_ok = driver_loader::initialize_and_load();
        const std::string loader_error_after_load = driver_loader::last_error();
        driver_critical_fmt("initialize_loader_post ok=%d elapsed_ms=%llu loader_error_hash=0x%016llX",
            loader_ok ? 1 : 0,
            static_cast<unsigned long long>(static_cast<uint64_t>(GetTickCount64()) - started),
            static_cast<unsigned long long>(driver_fnv1a64(loader_error_after_load.data(), loader_error_after_load.size())));
        diag::log_tagged_fmt("driver", "loader_initialize_result=%d", loader_ok ? 1 : 0);
        if (!loader_ok) {
            const std::string loader_error = loader_error_after_load;
            diag::log_tagged_critical_fmt("driver", "loader_last_error=\"%s\"",
                loader_error.empty() ? "<empty>" : loader_error.c_str());
            driver_critical_fmt("initialize_loader_failed_connect_retry_pre elapsed_ms=%llu",
                static_cast<unsigned long long>(static_cast<uint64_t>(GetTickCount64()) - started));
            if (device && device->connect()) {
                driver_critical_fmt("initialize_loader_failed_connect_retry_post ok=1 elapsed_ms=%llu hb_err=%lu hb_bytes=%lu",
                    static_cast<unsigned long long>(static_cast<uint64_t>(GetTickCount64()) - started),
                    static_cast<unsigned long>(device->get_last_heartbeat_error()),
                    static_cast<unsigned long>(device->get_last_heartbeat_bytes_returned()));
                diag::log_tagged_fmt("driver", "loader_failed_but_driver_connect_ok");
                driver_loader::mark_already_loaded();
                g_kernel_mode = true;
                g_initialized = true;
                g_adbg_clear_process_dr_supported.store(true, std::memory_order_release);
                g_adbg_hide_all_threads_supported.store(true, std::memory_order_release);
                logf("AiDA Standalone: Mapper reported failure after load, but kernel driver backend is reachable.\n");
                start_driver_watchdog_locked();
                start_event_poller_locked();
                kernel_session_snapshot_t after_kernel = capture_kernel_session_snapshot_locked();
                runtime_auth_snapshot_t after_auth = capture_runtime_auth_snapshot();
                log_auth_kernel_transition("initialize_loader_failed_connect_retry",
                    "initialize_loader",
                    preserve_activation,
                    before_auth,
                    after_auth,
                    before_kernel,
                    after_kernel);
                driver_critical_fmt("initialize_exit reason=loader_failed_but_connect_ok ok=1 kernel=1 elapsed_ms=%llu",
                    static_cast<unsigned long long>(static_cast<uint64_t>(GetTickCount64()) - started));
                return true;
            }
            driver_critical_fmt("initialize_loader_failed_connect_retry_post ok=0 err=%lu elapsed_ms=%llu",
                static_cast<unsigned long>(device ? device->get_last_connect_error() : GetLastError()),
                static_cast<unsigned long long>(static_cast<uint64_t>(GetTickCount64()) - started));
            return driver_startup_fail_closed("initialize_loader", ERROR_BAD_DRIVER);
        }

        driver_critical_fmt("initialize_connect_after_loader_pre elapsed_ms=%llu",
            static_cast<unsigned long long>(static_cast<uint64_t>(GetTickCount64()) - started));
        if (device && device->connect()) {
            driver_critical_fmt("initialize_connect_after_loader_post ok=1 elapsed_ms=%llu hb_err=%lu hb_bytes=%lu",
                static_cast<unsigned long long>(static_cast<uint64_t>(GetTickCount64()) - started),
                static_cast<unsigned long>(device->get_last_heartbeat_error()),
            static_cast<unsigned long>(device->get_last_heartbeat_bytes_returned()));
            g_kernel_mode = true;
            g_initialized = true;
            g_adbg_clear_process_dr_supported.store(true, std::memory_order_release);
            g_adbg_hide_all_threads_supported.store(true, std::memory_order_release);
            logf("AiDA Standalone: Live inspection bridge initialized with kernel driver backend.\n");
            start_driver_watchdog_locked();
            start_event_poller_locked();
            kernel_session_snapshot_t after_kernel = capture_kernel_session_snapshot_locked();
            runtime_auth_snapshot_t after_auth = capture_runtime_auth_snapshot();
            log_auth_kernel_transition("initialize_connect_after_loader",
                "initialize",
                preserve_activation,
                before_auth,
                after_auth,
                before_kernel,
                after_kernel);
            driver_critical_fmt("initialize_exit reason=loaded_connect_ok ok=1 kernel=1 elapsed_ms=%llu",
                static_cast<unsigned long long>(static_cast<uint64_t>(GetTickCount64()) - started));
            return true;
        }

        DWORD err = device ? device->get_last_connect_error() : 0xFFFFFFFFu;
        driver_critical_fmt("initialize_connect_after_loader_post ok=0 err=%lu elapsed_ms=%llu",
            static_cast<unsigned long>(err),
            static_cast<unsigned long long>(static_cast<uint64_t>(GetTickCount64()) - started));
        if (device) {
            logf("AiDA Standalone: Kernel driver connection failed (error 0x%08X).\n", err);
        }

        driver_critical_fmt("initialize_exit reason=connect_failed err=%lu elapsed_ms=%llu",
            static_cast<unsigned long>(err),
            static_cast<unsigned long long>(static_cast<uint64_t>(GetTickCount64()) - started));
        return driver_startup_fail_closed("initialize", err);
    }

    bool load_kernel_driver()
    {
        const runtime_auth_snapshot_t before_auth = capture_runtime_auth_snapshot();
        const bool preserve_activation = authenticated_runtime_preserved_for_kernel_transition(before_auth);
        std::lock_guard<std::mutex> lk(g_state_mtx);
        kernel_session_snapshot_t before_kernel = capture_kernel_session_snapshot_locked();
        if (g_kernel_mode && device && device->is_connected())
            return true;

        if (device && device->connect()) {
            driver_loader::mark_already_loaded();
            reset_kernel_transition_hardening_locked(preserve_activation);
            g_kernel_mode = true;
            g_initialized = true;
            g_adbg_clear_process_dr_supported.store(true, std::memory_order_release);
            g_adbg_hide_all_threads_supported.store(true, std::memory_order_release);
            g_driver_watchdog_last_ok_tick.store(0, std::memory_order_release);
            start_driver_watchdog_locked();
            start_event_poller_locked();
            kernel_session_snapshot_t after_kernel = capture_kernel_session_snapshot_locked();
            runtime_auth_snapshot_t after_auth = capture_runtime_auth_snapshot();
            log_auth_kernel_transition("load_kernel_driver_connect_existing",
                "load_kernel_driver",
                preserve_activation,
                before_auth,
                after_auth,
                before_kernel,
                after_kernel);
            return true;
        }

        if (device) {
            DWORD existing_connect_err = device->get_last_connect_error();
            const bool existing_driver_unreachable =
                ((existing_connect_err & 0xFFFF0000u) == 0xBEA70000u) ||
                device->get_last_heartbeat_dioctl_result() ||
                device->get_last_heartbeat_bytes_returned() != 0 ||
                existing_connect_err == 433u ||
                existing_connect_err == ERROR_ACCESS_DENIED;
            if (existing_driver_unreachable) {
                for (int attempt = 1; attempt <= 3; ++attempt) {
                    Sleep(300);
                    driver_critical_fmt("load_kernel_driver_existing_retry_pre attempt=%d err=%lu hb_ioctl=%d hb_err=%lu hb_bytes=%lu",
                        attempt,
                        static_cast<unsigned long>(device->get_last_connect_error()),
                        device->get_last_heartbeat_dioctl_result() ? 1 : 0,
                        static_cast<unsigned long>(device->get_last_heartbeat_error()),
                        static_cast<unsigned long>(device->get_last_heartbeat_bytes_returned()));
                    if (device->connect()) {
                        driver_loader::mark_already_loaded();
                        reset_kernel_transition_hardening_locked(preserve_activation);
                        g_kernel_mode = true;
                        g_initialized = true;
                        g_adbg_clear_process_dr_supported.store(true, std::memory_order_release);
                        g_adbg_hide_all_threads_supported.store(true, std::memory_order_release);
                        g_driver_watchdog_last_ok_tick.store(0, std::memory_order_release);
                        start_driver_watchdog_locked();
                        start_event_poller_locked();
                        kernel_session_snapshot_t after_kernel = capture_kernel_session_snapshot_locked();
                        runtime_auth_snapshot_t after_auth = capture_runtime_auth_snapshot();
                        log_auth_kernel_transition("load_kernel_driver_existing_retry",
                            "load_kernel_driver",
                            preserve_activation,
                            before_auth,
                            after_auth,
                            before_kernel,
                            after_kernel);
                        driver_critical_fmt("load_kernel_driver_existing_retry_post attempt=%d ok=1 hb_err=%lu hb_bytes=%lu",
                            attempt,
                            static_cast<unsigned long>(device->get_last_heartbeat_error()),
                            static_cast<unsigned long>(device->get_last_heartbeat_bytes_returned()));
                        return true;
                    }
                    driver_critical_fmt("load_kernel_driver_existing_retry_post attempt=%d ok=0 err=%lu hb_ioctl=%d hb_err=%lu hb_bytes=%lu",
                        attempt,
                        static_cast<unsigned long>(device->get_last_connect_error()),
                        device->get_last_heartbeat_dioctl_result() ? 1 : 0,
                        static_cast<unsigned long>(device->get_last_heartbeat_error()),
                        static_cast<unsigned long>(device->get_last_heartbeat_bytes_returned()));
                }
                DWORD guarded_err = device->get_last_connect_error();
                driver_critical_fmt("load_kernel_driver_no_remap_existing_unreachable err=%lu hb_ioctl=%d hb_err=%lu hb_bytes=%lu",
                    static_cast<unsigned long>(guarded_err),
                    device->get_last_heartbeat_dioctl_result() ? 1 : 0,
                    static_cast<unsigned long>(device->get_last_heartbeat_error()),
                    static_cast<unsigned long>(device->get_last_heartbeat_bytes_returned()));
                return driver_startup_fail_closed("load_kernel_driver_existing_unreachable_no_remap", guarded_err);
            }
        }

        bool loader_ok = driver_loader::initialize_and_load();
        diag::log_tagged_fmt("driver", "load_kernel_driver loader_initialize_result=%d", loader_ok ? 1 : 0);
        if (!loader_ok) {
            const std::string loader_error = driver_loader::last_error();
            diag::log_tagged_critical_fmt("driver", "load_kernel_driver loader_last_error=\"%s\"",
                loader_error.empty() ? "<empty>" : loader_error.c_str());
        }

        if (!device || !device->connect()) {
            DWORD err = device ? device->get_last_connect_error() : 0xFFFFFFFFu;
            char buf[256];
            if (err == 0xFFFFFFFFu) {
                snprintf(buf, sizeof(buf), "Failed to connect to the kernel driver (device object is null).");
            } else if ((err & 0xFFFF0000u) == 0xBEA70000u) {
                snprintf(buf, sizeof(buf),
                    "Driver device opened but heartbeat failed (0x%08X). "
                    "Stale session or IOCTL mismatch — try rebooting.",
                    err);
            } else if (err == ERROR_FILE_NOT_FOUND || err == ERROR_PATH_NOT_FOUND) {
                snprintf(buf, sizeof(buf),
                    "Driver device not found (error %lu). "
                    "The kernel driver may not be loaded.",
                    (unsigned long)err);
            } else if (err == ERROR_ACCESS_DENIED) {
                snprintf(buf, sizeof(buf),
                    "Access denied opening driver device. "
                    "Run AiDA as Administrator.");
            } else {
                snprintf(buf, sizeof(buf),
                    "Failed to connect to the kernel driver (error 0x%08X).",
                    err);
            }
            set_last_error_locked(buf);
            logf("AiDA Standalone: %s\n", buf);
            return false;
        }

        reset_kernel_transition_hardening_locked(preserve_activation);
        g_kernel_mode = true;
        g_initialized = true;
        g_adbg_clear_process_dr_supported.store(true, std::memory_order_release);
        g_adbg_hide_all_threads_supported.store(true, std::memory_order_release);
        g_driver_watchdog_last_ok_tick.store(0, std::memory_order_release);
        clear_last_error_locked_after_success("load_kernel_driver");
        logf("AiDA Standalone: Kernel driver backend is active.\n");
        start_driver_watchdog_locked();
        start_event_poller_locked();
        kernel_session_snapshot_t after_kernel = capture_kernel_session_snapshot_locked();
        runtime_auth_snapshot_t after_auth = capture_runtime_auth_snapshot();
        log_auth_kernel_transition("load_kernel_driver_connect_after_loader",
            "load_kernel_driver",
            preserve_activation,
            before_auth,
            after_auth,
            before_kernel,
            after_kernel);
        return true;
    }

    bool is_loaded()
    {
        std::lock_guard<std::mutex> lk(g_state_mtx);
        return g_initialized;
    }

    bool using_kernel_driver()
    {
        std::lock_guard<std::mutex> lk(g_state_mtx);
        return g_kernel_mode && device && device->is_connected();
    }

    bool kernel_session_available(std::string* reason)
    {
        bool initialized = false;
        bool kernel_mode = false;
        bool connected = false;
        std::string last_error_copy;
        {
            std::lock_guard<std::mutex> lk(g_state_mtx);
            initialized = g_initialized;
            kernel_mode = g_kernel_mode;
            connected = device && device->is_connected();
            last_error_copy = g_last_error;
        }

        auto set_reason = [&](const char* value) {
            if (reason)
                *reason = value ? value : "kernel_session_unavailable";
        };

        if (!initialized) {
            set_reason("kernel_session_not_initialized");
            driver_critical_fmt("kernel_session_available ok=0 reason=kernel_session_not_initialized kernel=%d connected=%d last_error='%.160s'",
                kernel_mode ? 1 : 0,
                connected ? 1 : 0,
                last_error_copy.c_str());
            return false;
        }
        if (!kernel_mode) {
            set_reason("kernel_driver_degraded");
            driver_critical_fmt("kernel_session_available ok=0 reason=kernel_driver_degraded initialized=%d connected=%d last_error='%.160s'",
                initialized ? 1 : 0,
                connected ? 1 : 0,
                last_error_copy.c_str());
            return false;
        }
        if (!connected) {
            set_reason("kernel_device_disconnected");
            driver_critical_fmt("kernel_session_available ok=0 reason=kernel_device_disconnected initialized=%d kernel=%d last_error='%.160s'",
                initialized ? 1 : 0,
                kernel_mode ? 1 : 0,
                last_error_copy.c_str());
            return false;
        }

        auto& rt = anti_tamper::state::get();
        if (rt.violation_latched.load(std::memory_order_acquire)) {
            set_reason("runtime_integrity_violation_latched");
            std::string latch_source = anti_tamper::runtime_integrity_latch_source_snapshot();
            std::string violation_reason;
            {
                std::lock_guard<std::mutex> lk(rt.mtx);
                violation_reason = rt.violation_reason;
            }
            driver_critical_fmt("kernel_session_available ok=0 reason=runtime_integrity_violation_latched violation_reason='%.160s' latch_source='%.512s'",
                violation_reason.c_str(),
                latch_source.c_str());
            return false;
        }
        if (rt.initialized.load(std::memory_order_acquire) &&
            !rt.driver_hardening_done.load(std::memory_order_acquire))
        {
            set_reason("driver_hardening_not_finalized");
            driver_critical_fmt("kernel_session_available ok=0 reason=driver_hardening_not_finalized initialized=%d kernel=%d connected=%d activation_hardening=%d",
                initialized ? 1 : 0,
                kernel_mode ? 1 : 0,
                connected ? 1 : 0,
                rt.activation_hardening_done.load(std::memory_order_acquire) ? 1 : 0);
            return false;
        }

        if (reason)
            reason->clear();
        return true;
    }

    bool can_read_memory()
    {
        std::lock_guard<std::mutex> lk(g_state_mtx);
        return g_pid != 0 && g_kernel_attached && g_kernel_mode && device && device->is_connected();
    }

    bool attach(uint32_t pid)
    {
        diag::log_tagged_critical_fmt("driver", "attach_enter pid=%u tid=%lu", pid, GetCurrentThreadId());

        if (pid == static_cast<uint32_t>(GetCurrentProcessId())) {
            diag::log_tagged_critical("driver", "attach_REJECTED_self_pid");
            return false;
        }

        {
            diag::log_tagged_critical("driver", "attach_pre_inline_gate_check");
            uint64_t gt = standalone_license::inline_gate_check(
                standalone_license::gate_driver_attach);
            diag::log_tagged_critical_fmt("driver", "attach_post_inline_gate_check token=0x%llX",
                (unsigned long long)gt);
            if (standalone_license::verify_gate_token(
                    standalone_license::gate_driver_attach, gt) < 0.5) {
                diag::log_tagged_critical("driver", "attach_REJECTED_gate_check_failed");
                return false;
            }
            diag::log_tagged_critical("driver", "attach_post_verify_gate_token");
        }

        diag::log_tagged_critical("driver", "attach_pre_state_mtx_lock");
        std::lock_guard<std::mutex> lk(g_state_mtx);
        diag::log_tagged_critical("driver", "attach_post_state_mtx_lock");

        constexpr DWORD access = PROCESS_QUERY_LIMITED_INFORMATION;
        diag::log_tagged_critical_fmt("driver", "attach_pre_OpenProcess access=0x%X pid=%u", access, pid);
        unique_handle process(OpenProcess(access, FALSE, pid));
        diag::log_tagged_critical_fmt("driver", "attach_post_OpenProcess handle=%p gle=%lu",
            process.get(), process ? 0UL : GetLastError());
        if (!process) {
            set_last_error_locked("OpenProcess query failed for PID " + std::to_string(pid) +
                                  " (error " + std::to_string(GetLastError()) + ")");
            return false;
        }

        bool kernel_ok = g_kernel_mode && device && device->is_connected();
        diag::log_tagged_critical_fmt("driver", "attach_kernel_check kernel_mode=%d device=%p connected=%d kernel_ok=%d",
            g_kernel_mode ? 1 : 0, device.get(),
            (device && device->is_connected()) ? 1 : 0,
            kernel_ok ? 1 : 0);
        if (!kernel_ok) {
            require_kernel_fail("attach");
            set_last_error_locked("attach requires WhosWho kernel driver for PID " + std::to_string(pid));
            return false;
        }

        close_process_handle_locked();
        g_process = process.release();
        g_pid = pid;
        g_has_vm_read = false;
        g_kernel_attached = false;
        if (!refresh_process_name_locked())
            g_process_name = process_name_from_pid(pid);

        {
            auto it = g_processes.find(pid);
            if (it != g_processes.end()) {
                release_ctx_handle(it->second);
                g_processes.erase(it);
            }
        }

        diag::log_tagged_critical("driver", "attach_pre_set_process_id");
        device->set_process_id(pid);
        diag::log_tagged_critical("driver", "attach_post_set_process_id");

        const ULONGLONG arc_bridge_t0 = GetTickCount64();
        diag::log_tagged_critical("driver", "attach_pre_get_arc_vtable");
        arc_attach_resolution_t arc_attach_ctx{};
        arc_attach_ctx.pid = pid;
        arc_attach_ctx.started_ms = arc_bridge_t0;
        const bool arc_bridge_ok = arc_bridge_attach_resolution(arc_attach_ctx);
        diag::log_tagged_critical_fmt("driver",
            "attach_arc_vtable_wrapper_result ok=%d solved=%d dtb=0x%llX image=0x%llX elapsed_ms=%llu",
            arc_bridge_ok ? 1 : 0,
            arc_attach_ctx.solved ? 1 : 0,
            static_cast<unsigned long long>(arc_attach_ctx.dtb),
            static_cast<unsigned long long>(arc_attach_ctx.image_base),
            static_cast<unsigned long long>(GetTickCount64() - arc_bridge_t0));
        bool vtable_solved = arc_bridge_ok && arc_attach_ctx.solved;
        if (vtable_solved) {
            diag::log_tagged_critical("driver", "attach_pre_device_solve_dtb_after_vtable");
            device->solve_dtb();
            diag::log_tagged_critical("driver", "attach_post_device_solve_dtb_after_vtable");
            if (arc_attach_ctx.image_base != 0)
                device->set_base_address(arc_attach_ctx.image_base);
        }

        if (!vtable_solved) {
            diag::log_tagged_critical("driver", "attach_pre_device_solve_dtb_fallback");
            device->solve_dtb();
            diag::log_tagged_critical_fmt("driver", "attach_post_device_solve_dtb_fallback dtb=0x%llX",
                (unsigned long long)device->get_dtb());
            if (device->get_dtb() == 0) {
                diag::log_tagged_critical_fmt("driver",
                    "attach_device_solve_dtb_zero connected=%d hb_err=%lu hb_bytes=%lu hb_ioctl=0x%08X hb_magic=0x%08X hb_dioctl=%d",
                    device->is_connected() ? 1 : 0,
                    static_cast<unsigned long>(device->get_last_heartbeat_error()),
                    static_cast<unsigned long>(device->get_last_heartbeat_bytes_returned()),
                    device->get_last_heartbeat_ioctl_code(),
                    device->get_last_heartbeat_magic(),
                    device->get_last_heartbeat_dioctl_result() ? 1 : 0);
                set_last_error_locked("WhosWho failed to resolve DTB for PID " + std::to_string(pid));
                return false;
            }
            diag::log_tagged_critical("driver", "attach_pre_device_find_image_fallback");
            const auto image_base = device->find_image();
            diag::log_tagged_critical_fmt("driver", "attach_post_device_find_image_fallback base=0x%llX",
                (unsigned long long)image_base);
            if (image_base != 0)
                device->set_base_address(image_base);
        }

        g_kernel_attached = true;
        diag::log_tagged_critical("driver", "attach_pre_solve_kernel_dtb");
        device->solve_kernel_dtb();
        diag::log_tagged_critical_fmt("driver", "attach_post_solve_kernel_dtb kdtb=0x%llX",
            (unsigned long long)device->get_kernel_dtb());
        if (device->get_kernel_dtb() != 0) {
            logf("AiDA Standalone: Kernel DTB solved: 0x%llX\n",
                 static_cast<unsigned long long>(device->get_kernel_dtb()));
        }

        clear_last_error_locked_after_success("attach");
        logf("AiDA Standalone: Attached to PID %u (%s) via kernel driver. DTB=0x%llX\n",
             g_pid, g_process_name.empty() ? "unknown" : g_process_name.c_str(),
             static_cast<unsigned long long>(device->get_dtb()));

        process_ctx_t ctx;
        ctx.h_process = nullptr;
        ctx.kernel_attached = g_kernel_attached;
        ctx.has_vm_read = false;
        ctx.name = g_process_name;
        diag::log_tagged_critical("driver", "attach_pre_ctx_cached_find_image");
        ctx.cached_image_base = device->find_image();
        diag::log_tagged_critical_fmt("driver", "attach_post_ctx_cached_find_image base=0x%llX",
            static_cast<unsigned long long>(ctx.cached_image_base));
        ctx.cached_dtb = device->get_dtb();
        ctx.cached_kernel_dtb = device->get_kernel_dtb();
        g_processes[pid] = std::move(ctx);

        diag::log_tagged_critical_fmt("driver", "attach_exit_ok pid=%u kernel_ok=1 has_vm_read=0", pid);
        return true;
    }

    bool attach_by_name(const std::string& process_name)
    {
        uint32_t kernel_pid = 0;
        {
            std::lock_guard<std::mutex> lk(g_state_mtx);
            if (g_kernel_mode && device && device->is_connected()) {
                kernel_pid = arc_bridge_find_process(process_name.c_str());
                if (kernel_pid == 0)
                    kernel_pid = device->find_process(process_name.c_str());
            }
        }
        if (kernel_pid != 0)
            return attach(kernel_pid);

        auto lowered = to_lower_copy(process_name);
        for (const auto& proc : enumerate_processes()) {
            if (to_lower_copy(proc.name) == lowered)
                return attach(proc.pid);
        }

        std::lock_guard<std::mutex> lk(g_state_mtx);
        set_last_error_locked("Process not found: " + process_name);
        return false;
    }

    void detach()
    {


        {
            std::lock_guard<std::mutex> lk(g_callback_mtx);
            for (auto& hook : g_pre_detach_hooks) {
                if (hook) hook();
            }
        }

        std::lock_guard<std::mutex> lk(g_state_mtx);
        uint32_t prev_pid = g_pid;
        close_process_handle_locked();
        g_pid = 0;
        g_process_name.clear();
        g_has_vm_read = false;
        g_kernel_attached = false;
        if (g_kernel_mode && device && device->is_connected()) {
            if (!arc_bridge_clear_process_context())
                device->clear_process_context();
        }
        if (prev_pid != 0) {
            auto it = g_processes.find(prev_pid);
            if (it != g_processes.end()) {
                release_ctx_handle(it->second);
                g_processes.erase(it);
            }
        }
        clear_last_error_locked_after_success("detach");
    }

    bool attach_additional(uint32_t pid)
    {
        if (pid == 0)
            return false;
        if (pid == static_cast<uint32_t>(GetCurrentProcessId()))
            return false;

        std::lock_guard<std::mutex> lk(g_state_mtx);
        if (g_processes.find(pid) != g_processes.end()) {
            clear_last_error_locked_after_success("attach_additional_existing");
            return true;
        }

        if (!g_kernel_mode || !device || !device->is_connected()) {
            require_kernel_fail("attach_additional");
            set_last_error_locked("attach_additional requires WhosWho kernel driver for PID " + std::to_string(pid));
            return false;
        }

        constexpr DWORD access = PROCESS_QUERY_LIMITED_INFORMATION;
        unique_handle process(OpenProcess(access, FALSE, pid));
        if (!process) {
            set_last_error_locked("OpenProcess query failed for PID " + std::to_string(pid) +
                                  " (error " + std::to_string(GetLastError()) + ")");
            return false;
        }

        process_ctx_t ctx;
        ctx.h_process = process.release();
        ctx.has_vm_read = false;
        ctx.kernel_attached = false;
        ctx.name = process_name_from_pid(pid);
        ctx.cached_image_base = 0;
        ctx.cached_dtb = 0;
        ctx.cached_kernel_dtb = 0;
        if (!refresh_kernel_context_locked(pid, ctx)) {
            release_ctx_handle(ctx);
            set_last_error_locked("WhosWho failed to attach additional PID " + std::to_string(pid));
            return false;
        }
        g_processes[pid] = std::move(ctx);

        diag::log_tagged_fmt("driver", "attach_additional_ok pid=%u kernel_attached=1 has_vm_read=0", pid);
        clear_last_error_locked_after_success("attach_additional");
        return true;
    }

    bool refresh_kernel_context_locked(uint32_t pid, process_ctx_t& ctx)
    {
        if (!g_kernel_mode || !device || !device->is_connected()) {
            ctx.kernel_attached = false;
            return false;
        }

        arc_bridge_set_process_id(pid);
        device->set_process_id(pid);

        uint64_t arc_dtb = arc_bridge_solve_dtb(false);

        device->solve_dtb();
        if (device->get_dtb() == 0 && arc_dtb != 0)
            device->set_dtb(arc_dtb);
        if (device->get_dtb() == 0 && ctx.cached_dtb != 0)
            device->set_dtb(ctx.cached_dtb);
        if (device->get_dtb() == 0) {
            ctx.kernel_attached = false;
            return false;
        }

        ctx.kernel_attached = true;
        ctx.cached_dtb = device->get_dtb();

        if (ctx.cached_image_base == 0) {
            uint64_t image_base = arc_bridge_find_image();
            if (image_base == 0)
                image_base = device->find_image();
            ctx.cached_image_base = image_base;
        }
        if (ctx.cached_image_base != 0) {
            device->set_base_address(ctx.cached_image_base);
            arc_bridge_set_base_address(ctx.cached_image_base);
        }

        if (ctx.cached_kernel_dtb != 0) {
            device->set_kernel_dtb(ctx.cached_kernel_dtb);
        } else {
            device->solve_kernel_dtb();
            ctx.cached_kernel_dtb = device->get_kernel_dtb();
        }
        return true;
    }

    bool set_active_pid(uint32_t pid)
    {
        if (pid == 0)
            return false;

        std::lock_guard<std::mutex> lk(g_state_mtx);
        if (g_pid == pid) {
            auto it = g_processes.find(pid);
            process_ctx_t transient;
            process_ctx_t& ctx = (it != g_processes.end()) ? it->second : transient;
            if (g_kernel_mode && device && device->is_connected()) {
                g_kernel_attached = refresh_kernel_context_locked(pid, ctx);
            }
            diag::log_tagged_fmt("driver", "set_active_pid_same pid=%u kernel_attached=%d dtb=0x%llX cached_dtb=0x%llX",
                pid,
                g_kernel_attached ? 1 : 0,
                static_cast<unsigned long long>((device && device->is_connected()) ? device->get_dtb() : 0),
                static_cast<unsigned long long>(ctx.cached_dtb));
            clear_last_error_locked_after_success("set_active_pid_same");
            return true;
        }

        auto it = g_processes.find(pid);
        if (it == g_processes.end()) {
            set_last_error_locked("set_active_pid: pid " + std::to_string(pid) + " not in attached set");
            return false;
        }
        process_ctx_t& target = it->second;

        if (g_pid != 0) {
            auto cur_it = g_processes.find(g_pid);
            if (cur_it != g_processes.end()) {
                cur_it->second.kernel_attached = g_kernel_attached;
                cur_it->second.has_vm_read = g_has_vm_read;
                cur_it->second.name = g_process_name;
                if (g_kernel_attached && device) {
                    cur_it->second.cached_image_base = device->find_image();
                    cur_it->second.cached_dtb = device->get_dtb();
                    cur_it->second.cached_kernel_dtb = device->get_kernel_dtb();
                }
                if (cur_it->second.h_process == nullptr && g_process != nullptr) {
                    cur_it->second.h_process = g_process;
                    g_process = nullptr;
                }
            }
        }

        close_process_handle_locked();
        g_pid = pid;
        g_process_name = target.name;
        g_has_vm_read = target.has_vm_read;
        g_kernel_attached = target.kernel_attached;
        g_process = target.h_process;
        target.h_process = nullptr;

        bool kernel_mode = g_kernel_mode && device && device->is_connected();
        if (kernel_mode) {
            g_kernel_attached = refresh_kernel_context_locked(pid, target);
        }
        diag::log_tagged_fmt("driver", "set_active_pid_ok pid=%u kernel_attached=%d dtb=0x%llX cached_dtb=0x%llX",
            pid,
            g_kernel_attached ? 1 : 0,
            static_cast<unsigned long long>((device && device->is_connected()) ? device->get_dtb() : 0),
            static_cast<unsigned long long>(target.cached_dtb));
        clear_last_error_locked_after_success("set_active_pid");
        return true;
    }

    bool detach_one(uint32_t pid)
    {
        if (pid == 0)
            return false;

        std::lock_guard<std::mutex> lk(g_state_mtx);
        auto it = g_processes.find(pid);
        if (it == g_processes.end())
            return false;

        if (g_pid == pid) {
            close_process_handle_locked();
            g_pid = 0;
            g_process_name.clear();
            g_has_vm_read = false;
            g_kernel_attached = false;
            if (g_kernel_mode && device && device->is_connected()) {
                if (!arc_bridge_clear_process_context())
                    device->clear_process_context();
            }
        } else {
            release_ctx_handle(it->second);
        }
        g_processes.erase(it);
        diag::log_tagged_fmt("driver", "detach_one_ok pid=%u", pid);
        return true;
    }

    bool clear_active_pid()
    {
        std::lock_guard<std::mutex> lk(g_state_mtx);
        if (g_pid == 0) {
            clear_last_error_locked_after_success("clear_active_pid_noop");
            return true;
        }
        auto it = g_processes.find(g_pid);
        if (it != g_processes.end()) {
            if (it->second.h_process == nullptr && g_process != nullptr) {
                it->second.h_process = g_process;
                g_process = nullptr;
            }
            it->second.kernel_attached = g_kernel_attached;
            it->second.has_vm_read = g_has_vm_read;
            it->second.name = g_process_name;
            if (g_kernel_attached && device) {
                it->second.cached_image_base = device->find_image();
                it->second.cached_dtb = device->get_dtb();
                it->second.cached_kernel_dtb = device->get_kernel_dtb();
            }
        }
        close_process_handle_locked();
        g_pid = 0;
        g_process_name.clear();
        g_has_vm_read = false;
        g_kernel_attached = false;
        if (g_kernel_mode && device && device->is_connected()) {
            if (!arc_bridge_clear_process_context())
                device->clear_process_context();
        }
        clear_last_error_locked_after_success("clear_active_pid");
        return true;
    }

    std::vector<uint32_t> attached_pids()
    {
        std::vector<uint32_t> out;
        std::lock_guard<std::mutex> lk(g_state_mtx);
        out.reserve(g_processes.size());
        for (const auto& kv : g_processes)
            out.push_back(kv.first);
        return out;
    }

    std::string status()
    {
        std::lock_guard<std::mutex> lk(g_state_mtx);
        if (!g_initialized)
            return "Live inspection bridge: not initialized";
        const bool kernel_active = g_kernel_mode && device && device->is_connected();
        if (g_pid == 0) {
            return kernel_active
                ? "Live inspection bridge: kernel backend ready (no process attached)"
                : "Live inspection bridge: kernel driver required (not loaded)";
        }

        char buf[256];
        snprintf(buf, sizeof(buf), "Live inspection bridge: %s attached to PID %u (%s)",
                 kernel_active ? "kernel backend" : "kernel driver required (not loaded)",
                 g_pid, g_process_name.empty() ? "unknown" : g_process_name.c_str());
        return buf;
    }

    std::string last_error()
    {
        std::lock_guard<std::mutex> lk(g_state_mtx);
        return g_last_error;
    }

    uint32_t attached_pid()
    {
        std::lock_guard<std::mutex> lk(g_state_mtx);
        return g_pid;
    }

    bool attached_process_alive(uint32_t* exit_code_out)
    {
        uint32_t pid = 0;
        DWORD exit_code = 0;
        bool got_exit_code = false;

        {
            std::lock_guard<std::mutex> lk(g_state_mtx);
            pid = g_pid;
            if (pid == 0) {
                if (exit_code_out) *exit_code_out = 0;
                return false;
            }
            if (g_process && GetExitCodeProcess(g_process, &exit_code)) {
                got_exit_code = true;
            }
        }

        if (!got_exit_code) {
            auto proc = make_handle(OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid));
            if (!proc) {
                const DWORD err = GetLastError();
                if (exit_code_out) *exit_code_out = err;
                diag::log_tagged_fmt("driver",
                    "attached_process_alive open_failed pid=%u err=%lu",
                    pid, static_cast<unsigned long>(err));
                return err == ERROR_ACCESS_DENIED;
            }
            if (!GetExitCodeProcess(proc.get(), &exit_code)) {
                const DWORD err = GetLastError();
                if (exit_code_out) *exit_code_out = err;
                diag::log_tagged_fmt("driver",
                    "attached_process_alive get_exit_failed pid=%u err=%lu",
                    pid, static_cast<unsigned long>(err));
                return false;
            }
        }

        if (exit_code_out) *exit_code_out = static_cast<uint32_t>(exit_code);
        return exit_code == STILL_ACTIVE;
    }

    std::string attached_process_name()
    {
        std::lock_guard<std::mutex> lk(g_state_mtx);
        return g_process_name;
    }

    struct enum_main_window_ctx {
        DWORD pid;
        HWND  result;
    };

    static BOOL CALLBACK find_main_window_cb(HWND hwnd, LPARAM lParam)
    {
        auto* ctx = reinterpret_cast<enum_main_window_ctx*>(lParam);
        DWORD wnd_pid = 0;
        GetWindowThreadProcessId(hwnd, &wnd_pid);
        if (wnd_pid != ctx->pid) return TRUE;
        if (GetWindow(hwnd, GW_OWNER)) return TRUE;
        if (!IsWindowVisible(hwnd)) return TRUE;
        ctx->result = hwnd;
        return FALSE;
    }

    static std::string get_window_title(DWORD pid)
    {
        enum_main_window_ctx ctx{pid, nullptr};
        EnumWindows(find_main_window_cb, reinterpret_cast<LPARAM>(&ctx));
        if (!ctx.result) return {};
        wchar_t buf[256] = {};
        if (!GetWindowTextW(ctx.result, buf, 256)) return {};
        return utf8_from_wide(buf);
    }

    std::vector<process_info_t> enumerate_processes()
    {
        std::vector<process_info_t> result;

        auto snapshot = make_handle(CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0));
        if (!snapshot)
            return result;

        PROCESSENTRY32W pe = {};
        pe.dwSize = sizeof(pe);
        if (!Process32FirstW(snapshot.get(), &pe))
            return result;

        DWORD self_pid = GetCurrentProcessId();

        do {
            if (pe.th32ProcessID == 0 || pe.th32ProcessID == 4)
                continue;
            if (pe.th32ProcessID == self_pid)
                continue;

            process_info_t proc;
            proc.pid  = pe.th32ProcessID;
            proc.name = utf8_from_wide(pe.szExeFile);

            auto hProc = make_handle(OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pe.th32ProcessID));
            if (hProc) {
                wchar_t path_buf[MAX_PATH] = {};
                DWORD path_len = static_cast<DWORD>(std::size(path_buf));
                if (QueryFullProcessImageNameW(hProc.get(), 0, path_buf, &path_len) && path_len > 0)
                    proc.path = utf8_from_wide(path_buf);
            }

            proc.window_title = get_window_title(pe.th32ProcessID);

            result.push_back(std::move(proc));
        } while (Process32NextW(snapshot.get(), &pe));

        std::sort(result.begin(), result.end(), [](const process_info_t& a, const process_info_t& b) {
            if (!a.window_title.empty() && b.window_title.empty()) return true;
            if (a.window_title.empty() && !b.window_title.empty()) return false;
            return a.pid < b.pid;
        });
        return result;
    }

    static std::vector<module_info_t> enumerate_modules_usermode(uint32_t pid, HANDLE process)
    {
        const ULONGLONG t0 = GetTickCount64();
        std::vector<module_info_t> result;

        SetLastError(ERROR_SUCCESS);
        HANDLE raw_snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid);
        DWORD snapshot_error = raw_snapshot == INVALID_HANDLE_VALUE ? GetLastError() : ERROR_SUCCESS;
        diag::log_tagged_critical_fmt("driver",
            "enumerate_modules_usermode_toolhelp_snapshot pid=%u process=%p handle=%p gle=%lu elapsed_ms=%llu",
            pid,
            process,
            raw_snapshot == INVALID_HANDLE_VALUE ? nullptr : raw_snapshot,
            static_cast<unsigned long>(snapshot_error),
            static_cast<unsigned long long>(GetTickCount64() - t0));
        auto snapshot = make_handle(raw_snapshot);
        if (!snapshot)
            return result;

        MODULEENTRY32W me = {};
        me.dwSize = sizeof(me);
        SetLastError(ERROR_SUCCESS);
        BOOL first_ok = Module32FirstW(snapshot.get(), &me);
        DWORD first_error = first_ok ? ERROR_SUCCESS : GetLastError();
        if (first_ok) {
            do {
                module_info_t mod;
                mod.base = reinterpret_cast<uint64_t>(me.modBaseAddr);
                mod.size = me.modBaseSize;
                mod.name = utf8_from_wide(me.szModule);
                mod.path = utf8_from_wide(me.szExePath);
                result.push_back(std::move(mod));
            } while (Module32NextW(snapshot.get(), &me));
        }

        std::sort(result.begin(), result.end(), [](const module_info_t& a, const module_info_t& b) {
            return a.base < b.base;
        });
        diag::log_tagged_critical_fmt("driver",
            "enumerate_modules_usermode_toolhelp_result pid=%u first_ok=%d first_gle=%lu count=%llu elapsed_ms=%llu",
            pid,
            first_ok ? 1 : 0,
            static_cast<unsigned long>(first_error),
            static_cast<unsigned long long>(result.size()),
            static_cast<unsigned long long>(GetTickCount64() - t0));
        return result;
    }

    std::vector<module_info_t> enumerate_modules()
    {
        const ULONGLONG t0 = GetTickCount64();
        diag::log_tagged_critical_fmt("driver", "enumerate_modules_enter tid=%lu", GetCurrentThreadId());
        std::vector<module_info_t> result;
        const uint32_t pid = attached_pid();
        if (!pid) {
            diag::log_tagged_critical("driver", "enumerate_modules_no_pid");
            return result;
        }

        HANDLE process = nullptr;
        {
            std::lock_guard<std::mutex> lk(g_state_mtx);
            process = g_process;
        }

        if (process) {
            diag::log_tagged_critical_fmt("driver", "enumerate_modules_pre_usermode pid=%u handle=%p", pid, process);
            result = enumerate_modules_usermode(pid, process);
            diag::log_tagged_critical_fmt("driver", "enumerate_modules_post_usermode count=%llu", (unsigned long long)result.size());
        }

        if (!result.empty()) {
            logf("AiDA Standalone: enumerate_modules: resolved %zu modules via user-mode snapshot for PID %u.\n",
                 result.size(), pid);
            diag::log_tagged_critical_fmt("driver", "enumerate_modules_exit_ok count=%llu", (unsigned long long)result.size());
            return result;
        }

        bool kernel_mode = false;
        {
            std::lock_guard<std::mutex> lk(g_state_mtx);
            kernel_mode = g_kernel_mode && device && device->is_connected();
        }

        if (!kernel_mode) {
            logf("AiDA Standalone: enumerate_modules: no modules resolved for PID %u.\n", pid);
            diag::log_tagged_critical_fmt("driver",
                "enumerate_modules_kernel_unavailable pid=%u elapsed_ms=%llu",
                pid,
                static_cast<unsigned long long>(GetTickCount64() - t0));
            return result;
        }

        voyager::device_t::peb_info peb{};
        const ULONGLONG peb_start = GetTickCount64();
        bool peb_ok = device->read_peb(peb);
        diag::log_tagged_critical_fmt("driver",
            "enumerate_modules_kernel_peb pid=%u ok=%d peb=0x%llX image=0x%llX ldr=0x%llX elapsed_ms=%llu",
            pid,
            peb_ok ? 1 : 0,
            static_cast<unsigned long long>(peb.peb_address),
            static_cast<unsigned long long>(peb.image_base),
            static_cast<unsigned long long>(peb.ldr_address),
            static_cast<unsigned long long>(GetTickCount64() - peb_start));
        if (!peb_ok || peb.ldr_address == 0) {
            logf("AiDA Standalone: enumerate_modules: failed to read PEB/LDR for PID %u.\n", pid);
            return result;
        }

        const uint64_t list_head = peb.ldr_address + 0x10;
        uint64_t current = device->read<uint64_t>(list_head);
        diag::log_tagged_critical_fmt("driver",
            "enumerate_modules_kernel_ldr_head pid=%u list_head=0x%llX first=0x%llX",
            pid,
            static_cast<unsigned long long>(list_head),
            static_cast<unsigned long long>(current));
        if (current == 0 || current == list_head) {
            logf("AiDA Standalone: enumerate_modules: LDR list empty for PID %u.\n", pid);
            diag::log_tagged_critical_fmt("driver",
                "enumerate_modules_kernel_ldr_empty pid=%u list_head=0x%llX first=0x%llX",
                pid,
                static_cast<unsigned long long>(list_head),
                static_cast<unsigned long long>(current));
            return result;
        }

        int max_iter = 1024;
        while (current != list_head && current != 0 && max_iter-- > 0) {
            const uint64_t dll_base = device->read<uint64_t>(current + 0x30);
            const uint32_t size_of_image = device->read<uint32_t>(current + 0x40);

            const uint16_t full_name_len = device->read<uint16_t>(current + 0x48);
            const uint64_t full_name_ptr = device->read<uint64_t>(current + 0x50);
            const uint16_t base_name_len = device->read<uint16_t>(current + 0x58);
            const uint64_t base_name_ptr = device->read<uint64_t>(current + 0x60);

            std::string base_name;
            if (base_name_ptr != 0 && base_name_len > 0 && base_name_len <= 520) {
                std::vector<uint8_t> raw(base_name_len, 0);
                if (device->read_raw(base_name_ptr, raw.data(), base_name_len) > 0) {
                    base_name.reserve(base_name_len / 2);
                    for (size_t i = 0; i + 1 < raw.size(); i += 2) {
                        uint16_t wc = raw[i] | (static_cast<uint16_t>(raw[i + 1]) << 8);
                        if (wc == 0) break;
                        base_name += (wc >= 32 && wc < 128) ? static_cast<char>(wc) : '?';
                    }
                }
            }

            std::string full_path;
            if (full_name_ptr != 0 && full_name_len > 0 && full_name_len <= 1024) {
                std::vector<uint8_t> raw(full_name_len, 0);
                if (device->read_raw(full_name_ptr, raw.data(), full_name_len) > 0) {
                    full_path.reserve(full_name_len / 2);
                    for (size_t i = 0; i + 1 < raw.size(); i += 2) {
                        uint16_t wc = raw[i] | (static_cast<uint16_t>(raw[i + 1]) << 8);
                        if (wc == 0) break;
                        full_path += (wc >= 32 && wc < 128) ? static_cast<char>(wc) : '?';
                    }
                }
            }

            if (dll_base != 0 && !base_name.empty()) {
                module_info_t mod;
                mod.base = dll_base;
                mod.size = size_of_image;
                mod.name = std::move(base_name);
                mod.path = std::move(full_path);
                result.push_back(std::move(mod));
            }

            const uint64_t next = device->read<uint64_t>(current);
            if (next == current || next == 0)
                break;
            current = next;
        }

        std::sort(result.begin(), result.end(), [](const module_info_t& a, const module_info_t& b) {
            return a.base < b.base;
        });

        logf("AiDA Standalone: enumerate_modules: resolved %zu modules via kernel LDR walk for PID %u.\n",
             result.size(), pid);
        diag::log_tagged_critical_fmt("driver",
            "enumerate_modules_kernel_ldr_result pid=%u count=%llu final_current=0x%llX elapsed_ms=%llu",
            pid,
            static_cast<unsigned long long>(result.size()),
            static_cast<unsigned long long>(current),
            static_cast<unsigned long long>(GetTickCount64() - t0));
        return result;
    }

    std::vector<thread_info_t> enumerate_threads()
    {
        std::vector<thread_info_t> result;
        const uint32_t pid = attached_pid();
        if (!pid)
            return result;

        bool kernel_mode = false;
        {
            std::lock_guard<std::mutex> lk(g_state_mtx);
            kernel_mode = g_kernel_mode && device && device->is_connected();
        }

        if (!kernel_mode) {
            result = enumerate_threads_usermode_snapshot(pid);
            logf("AiDA Standalone: enumerate_threads: resolved %zu threads via user-mode snapshot for PID %u.\n",
                 result.size(), pid);
            if (result.empty()) {
                uint32_t exit_code = 0;
                if (!attached_process_alive(&exit_code)) {
                    diag::log_tagged_fmt("driver",
                        "enumerate_threads_dead_target_user pid=%u exit_code_or_err=0x%08X; detaching stale target",
                        pid, exit_code);
                    detach();
                }
            }
            return result;
        }

        {
            struct enum_ctx { std::vector<thread_info_t>* out; uint32_t pid; };
            enum_ctx ctx{&result, pid};
            uint32_t arc_count = 0;
            const bool arc_ok = arc_bridge_enumerate_threads(
                [](const arc_comm_vtable_t::thread_info_t* info, void* user) {
                    auto* c = static_cast<enum_ctx*>(user);
                    thread_info_t t;
                    t.tid = info->tid;
                    t.owner_pid = c->pid;
                    t.priority = 0;
                    t.state = info->state;
                    t.rip = info->rip;
                    c->out->push_back(t);
                },
                &ctx,
                &arc_count);
            if (arc_ok) {
                diag::log_tagged_fmt("driver",
                    "enumerate_threads_arc_bridge pid=%u count=%u result=%zu",
                    pid,
                    arc_count,
                    result.size());
            } else {
                auto kernel_threads = device->enumerate_threads();
                result.reserve(kernel_threads.size());
                for (const auto& kt : kernel_threads) {
                    thread_info_t t;
                    t.tid = kt.tid;
                    t.owner_pid = pid;
                    t.priority = 0;
                    t.state = kt.state;
                    t.rip = kt.rip;
                    result.push_back(t);
                }
            }
        }

        std::sort(result.begin(), result.end(), [](const thread_info_t& a, const thread_info_t& b) {
            return a.tid < b.tid;
        });

        logf("AiDA Standalone: enumerate_threads: resolved %zu threads via kernel IOCTL for PID %u.\n",
             result.size(), pid);
        if (result.empty()) {
            result = enumerate_threads_usermode_snapshot(pid);
            diag::log_tagged_fmt("driver",
                "enumerate_threads_kernel_empty_usermode_fallback pid=%u count=%zu",
                pid,
                result.size());
        }
        if (result.empty()) {
            uint32_t exit_code = 0;
            if (!attached_process_alive(&exit_code)) {
                diag::log_tagged_fmt("driver",
                    "enumerate_threads_dead_target_kernel pid=%u exit_code_or_err=0x%08X; detaching stale target",
                    pid, exit_code);
                detach();
            }
        }
        return result;
    }

    std::vector<memory_region_t> enumerate_memory_regions(size_t max_regions)
    {
        std::vector<memory_region_t> result;
        HANDLE process = nullptr;
        bool kernel_mode = false;
        bool kernel_attached = false;
        uint32_t pid = 0;
        {
            std::lock_guard<std::mutex> lk(g_state_mtx);
            process = g_process;
            kernel_mode = g_kernel_mode && device && device->is_connected();
            kernel_attached = g_kernel_attached;
            pid = g_pid;
        }

        if (kernel_mode) {
            {
                struct enum_ctx { std::vector<memory_region_t>* out; size_t max; };
                uint32_t arc_count = 0;
                uint32_t retry_count = 0;
                bool arc_ok = false;
                auto run_arc_enum = [&](const char* phase) {
                    result.clear();
                    arc_count = 0;
                    enum_ctx ctx{&result, max_regions};
                    const bool ok = arc_bridge_enumerate_memory_regions(
                        [](const arc_comm_vtable_t::memory_region_info_t* info, void* user) {
                            auto* c = static_cast<enum_ctx*>(user);
                            if (c->out->size() >= c->max) return;
                            memory_region_t region;
                            region.base    = info->base;
                            region.size    = info->size;
                            region.state   = info->state;
                            region.protect = info->protect;
                            region.type    = info->type;
                            c->out->push_back(region);
                        },
                        &ctx,
                        &arc_count);
                    diag::log_tagged_fmt("driver",
                        "enumerate_memory_regions_arc_bridge phase=%s pid=%u max=%zu arc_ok=%d arc_count=%u result=%zu kernel_attached=%d dtb=0x%llX",
                        phase,
                        pid,
                        max_regions,
                        ok ? 1 : 0,
                        arc_count,
                        result.size(),
                        kernel_attached ? 1 : 0,
                        static_cast<unsigned long long>((device && device->is_connected()) ? device->get_dtb() : 0));
                    return ok;
                };
                auto run_direct_enum = [&](const char* reason, DWORD& gle_out, size_t& raw_count_out) {
                    result.clear();
                    raw_count_out = 0;
                    gle_out = ERROR_SUCCESS;
                    if (!device) {
                        gle_out = ERROR_DEVICE_NOT_CONNECTED;
                        SetLastError(gle_out);
                        return;
                    }
                    SetLastError(ERROR_SUCCESS);
                    const auto regions = device->enumerate_memory_regions(0, 0, false);
                    gle_out = GetLastError();
                    raw_count_out = regions.size();
                    for (const auto& src : regions) {
                        memory_region_t region;
                        region.base = src.base;
                        region.size = src.size;
                        region.state = src.state;
                        region.protect = src.protect;
                        region.type = src.type;
                        result.push_back(region);
                        if (result.size() >= max_regions)
                            break;
                    }
                    diag::log_tagged_fmt("driver",
                        "enumerate_memory_regions_direct reason=%s pid=%u max=%zu raw_count=%zu copied=%zu gle=%lu kernel_attached=%d dtb=0x%llX",
                        reason,
                        pid,
                        max_regions,
                        raw_count_out,
                        result.size(),
                        static_cast<unsigned long>(gle_out),
                        kernel_attached ? 1 : 0,
                        static_cast<unsigned long long>((device && device->is_connected()) ? device->get_dtb() : 0));
                };
                arc_ok = run_arc_enum("initial");
                while (arc_ok && result.empty() && pid != 0 && max_regions != 0 && retry_count < 2) {
                    ++retry_count;
                    Sleep(35);
                    char phase[32];
                    std::snprintf(phase, sizeof(phase), "retry%u", retry_count);
                    arc_ok = run_arc_enum(phase);
                }
                DWORD fallback_gle = ERROR_SUCCESS;
                size_t fallback_raw_count = 0;
                bool used_fallback = false;
                if (!arc_ok || (pid != 0 && max_regions != 0 && result.empty())) {
                    used_fallback = true;
                    run_direct_enum(arc_ok ? "arc_zero_regions" : "arc_failed", fallback_gle, fallback_raw_count);
                }
                diag::log_tagged_fmt("driver",
                    "enumerate_memory_regions_summary pid=%u max=%zu arc_ok=%d arc_count=%u retries=%u used_fallback=%d fallback_raw_count=%zu fallback_result=%zu fallback_gle=%lu final_count=%zu",
                    pid,
                    max_regions,
                    arc_ok ? 1 : 0,
                    arc_count,
                    retry_count,
                    used_fallback ? 1 : 0,
                    fallback_raw_count,
                    used_fallback ? result.size() : 0,
                    static_cast<unsigned long>(fallback_gle),
                    result.size());
            }
            return result;
        }

        if (process) {
            MEMORY_BASIC_INFORMATION mbi{};
            uint64_t addr = 0;
            while (result.size() < max_regions &&
                   VirtualQueryEx(process, reinterpret_cast<LPCVOID>(static_cast<uintptr_t>(addr)), &mbi, sizeof(mbi)) == sizeof(mbi)) {
                memory_region_t region;
                region.base    = reinterpret_cast<uint64_t>(mbi.BaseAddress);
                region.size    = mbi.RegionSize;
                region.state   = mbi.State;
                region.protect = mbi.Protect;
                region.type    = mbi.Type;
                result.push_back(region);
                uint64_t next = reinterpret_cast<uint64_t>(mbi.BaseAddress) + mbi.RegionSize;
                if (next <= addr) break;
                addr = next;
            }
        }

        return result;
    }

    bool query_memory(uint64_t address, memory_region_t& region)
    {
        HANDLE process = nullptr;
        bool kernel_mode = false;
        {
            std::lock_guard<std::mutex> lk(g_state_mtx);
            process = g_process;
            kernel_mode = g_kernel_mode && device && device->is_connected();
        }

        if (kernel_mode) {
            arc_comm_vtable_t::memory_region_info_t arc_info{};
            if (arc_bridge_query_memory(address, &arc_info)) {
                region.base    = arc_info.base;
                region.size    = arc_info.size;
                region.state   = arc_info.state;
                region.protect = arc_info.protect;
                region.type    = arc_info.type;
                return true;
            } else {
                voyager::device_t::memory_region_info info = {};
                if (!device->query_memory(address, info))
                    return false;
                region.base = info.base;
                region.size = info.size;
                region.state = info.state;
                region.protect = info.protect;
                region.type = info.type;
                return true;
            }
        }

        if (process) {
            MEMORY_BASIC_INFORMATION mbi{};
            if (VirtualQueryEx(process, reinterpret_cast<LPCVOID>(static_cast<uintptr_t>(address)),
                               &mbi, sizeof(mbi)) == sizeof(mbi)) {
                region.base    = reinterpret_cast<uint64_t>(mbi.BaseAddress);
                region.size    = mbi.RegionSize;
                region.state   = mbi.State;
                region.protect = mbi.Protect;
                region.type    = mbi.Type;
                return true;
            }
        }

        return false;
    }

    bool read_memory(uint64_t address, size_t size, std::vector<uint8_t>& out)
    {

        {
            uint64_t tok = anti_tamper::run_inline_check(anti_tamper::CHECK_CODE_INTEGRITY);
            standalone_license::fold_integrity_token(tok);
        }

        {
            uint64_t gt = standalone_license::inline_gate_check(
                standalone_license::gate_driver_read_mem);
            if (standalone_license::verify_gate_token(
                    standalone_license::gate_driver_read_mem, gt) < 0.5) {
                out.clear();
                return false;
            }
        }

        out.clear();
        bool kernel_mode = false;
        bool kernel_attached = false;
        {
            std::lock_guard<std::mutex> lk(g_state_mtx);
            kernel_mode = g_kernel_mode && device && device->is_connected();
            kernel_attached = g_kernel_attached;
        }
        if (size == 0)
            return false;

        if (!kernel_mode || !kernel_attached) {
            diag::log_tagged_fmt("driver",
                "read_memory_kernel_required addr=0x%llX sz=%llu kernel=%d attached=%d",
                static_cast<unsigned long long>(address),
                static_cast<unsigned long long>(size),
                kernel_mode ? 1 : 0,
                kernel_attached ? 1 : 0);
            require_kernel_fail("read_memory");
            return false;
        }

        out.resize(size);
        size_t bytes_read = 0;
        bool arc_read_invoked = false;
        bytes_read = arc_bridge_read_raw(address, out.data(), size, &arc_read_invoked);

        if (bytes_read == 0 && device && device->get_dtb() != 0) {
            bytes_read = device->read_raw(address, out.data(), size);
        }

        {
            static int s_read_log_count = 0;
            if (s_read_log_count < 50) {
                s_read_log_count++;
                logf("read_memory: addr=0x%llX sz=%llu kernel=%d vtable=%d dtb=0x%llX bytes=%llu\n",
                    (unsigned long long)address, (unsigned long long)size,
                    kernel_mode ? 1 : 0,
                    arc_read_invoked ? 1 : 0,
                    device ? (unsigned long long)device->get_dtb() : 0ULL,
                    (unsigned long long)bytes_read);
            }
        }

        if (bytes_read == 0) {
            bool re_resolved = false;
            {
                std::lock_guard<std::mutex> lk(g_state_mtx);
                if (device) {
                    device->solve_dtb();
                    re_resolved = (device->get_dtb() != 0);
                }
                if (!re_resolved) {
                    uint64_t new_dtb = arc_bridge_solve_dtb(true);
                    re_resolved = (new_dtb != 0);
                }
            }

            if (re_resolved) {
                std::memset(out.data(), 0, size);
                bytes_read = arc_bridge_read_raw(address, out.data(), size);
                if (bytes_read == 0 && device) {
                    bytes_read = device->read_raw(address, out.data(), size);
                }
            }
        }

        if (bytes_read > 0) {
            out.resize(bytes_read);
            clear_last_error_after_success("read_memory_kernel");
            return true;
        }

        out.clear();
        diag::log_tagged_fmt("driver",
            "read_memory_kernel_failed addr=0x%llX sz=%llu dtb=0x%llX",
            static_cast<unsigned long long>(address),
            static_cast<unsigned long long>(size),
            static_cast<unsigned long long>(device ? device->get_dtb() : 0));
        return false;
    }

    bool write_memory(uint64_t address, const std::vector<uint8_t>& data)
    {
        {
            uint64_t gt = standalone_license::inline_gate_check(
                standalone_license::gate_driver_read_mem);
            if (standalone_license::verify_gate_token(
                    standalone_license::gate_driver_read_mem, gt) < 0.5) {
                return false;
            }
        }

        if (data.empty())
            return false;

        constexpr size_t kVerifyLimit = 4096;
        bool kernel_mode = false;
        bool kernel_attached = false;
        {
            std::lock_guard<std::mutex> lk(g_state_mtx);
            kernel_mode = g_kernel_mode && device && device->is_connected();
            kernel_attached = g_kernel_attached;
        }

        if (!kernel_mode || !kernel_attached) {
            diag::log_tagged_fmt("driver",
                "write_memory_kernel_required addr=0x%llX sz=%llu kernel=%d attached=%d",
                static_cast<unsigned long long>(address),
                static_cast<unsigned long long>(data.size()),
                kernel_mode ? 1 : 0,
                kernel_attached ? 1 : 0);
            require_kernel_fail("write_memory");
            return false;
        }

        auto first_mismatch = [](const std::vector<uint8_t>& expected, const std::vector<uint8_t>& actual) -> size_t {
            const size_t n = std::min(expected.size(), actual.size());
            for (size_t i = 0; i < n; ++i) {
                if (expected[i] != actual[i])
                    return i;
            }
            return n;
        };

        size_t bytes_written = arc_bridge_write_raw(address, data.data(), data.size());

        if (bytes_written != data.size() && device && device->get_dtb() != 0) {
            const size_t direct_written = device->write_raw(address, data.data(), data.size());
            if (direct_written > bytes_written)
                bytes_written = direct_written;
        }

        if (bytes_written != data.size()) {
            bool re_resolved = false;
            {
                std::lock_guard<std::mutex> lk(g_state_mtx);
                if (device) {
                    device->solve_dtb();
                    re_resolved = (device->get_dtb() != 0);
                }
                if (!re_resolved) {
                    uint64_t new_dtb = arc_bridge_solve_dtb(true);
                    re_resolved = (new_dtb != 0);
                }
            }

            if (re_resolved) {
                const size_t retry_written = arc_bridge_write_raw(address, data.data(), data.size());
                if (retry_written > bytes_written)
                    bytes_written = retry_written;
                if (bytes_written != data.size() && device) {
                    const size_t retry_direct_written = device->write_raw(address, data.data(), data.size());
                    if (retry_direct_written > bytes_written)
                        bytes_written = retry_direct_written;
                }
            }
        }

        if (bytes_written == data.size()) {
            if (data.size() > kVerifyLimit) {
                clear_last_error_after_success("write_memory_kernel");
                return true;
            }
            std::vector<uint8_t> bridge_verify;
            bool bridge_read_ok = read_memory(address, data.size(), bridge_verify);
            bool bridge_match = bridge_read_ok &&
                bridge_verify.size() == data.size() &&
                std::equal(data.begin(), data.end(), bridge_verify.begin());
            if (bridge_match) {
                clear_last_error_after_success("write_memory_kernel_verified");
                return true;
            }
            const size_t mismatch = first_mismatch(data, bridge_verify);
            const uint8_t expected = mismatch < data.size() ? data[mismatch] : 0;
            const uint8_t actual = mismatch < bridge_verify.size() ? bridge_verify[mismatch] : 0;
            diag::log_tagged_fmt("driver",
                "write_memory kernel verify_mismatch addr=0x%llX sz=%llu bridge_read=%d bridge_bytes=%llu mismatch=%llu expected=0x%02X actual=0x%02X",
                static_cast<unsigned long long>(address),
                static_cast<unsigned long long>(data.size()),
                bridge_read_ok ? 1 : 0,
                static_cast<unsigned long long>(bridge_verify.size()),
                static_cast<unsigned long long>(mismatch),
                static_cast<unsigned>(expected),
                static_cast<unsigned>(actual));
            return false;
        }

        if (bytes_written > 0) {
            diag::log_tagged_fmt("driver",
                "write_memory kernel partial addr=0x%llX sz=%llu bytes=%llu",
                static_cast<unsigned long long>(address),
                static_cast<unsigned long long>(data.size()),
                static_cast<unsigned long long>(bytes_written));
        } else {
            diag::log_tagged_fmt("driver",
                "write_memory kernel failed addr=0x%llX sz=%llu dtb=0x%llX",
                static_cast<unsigned long long>(address),
                static_cast<unsigned long long>(data.size()),
                static_cast<unsigned long long>(device ? device->get_dtb() : 0));
        }

        return false;
    }

    bool read_string(uint64_t address, size_t max_length, std::string& out)
    {
        out.clear();
        if (max_length == 0)
            return false;

        std::vector<uint8_t> bytes;
        if (!read_memory(address, max_length, bytes))
            return false;

        for (uint8_t b : bytes) {
            if (b == 0)
                break;
            out.push_back(static_cast<char>(b));
        }
        return !out.empty();
    }

}

namespace driver_bridge_pid_call
{
    std::recursive_mutex g_call_mtx;

    inline bool pid_is_alive(uint32_t pid, uint32_t* exit_code_out)
    {
        if (pid == 0) {
            if (exit_code_out) *exit_code_out = 0;
            return false;
        }
        auto proc = make_handle(OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid));
        if (!proc) {
            const DWORD err = GetLastError();
            if (exit_code_out) *exit_code_out = err;
            return err == ERROR_ACCESS_DENIED;
        }
        DWORD exit_code = 0;
        if (!GetExitCodeProcess(proc.get(), &exit_code)) {
            const DWORD err = GetLastError();
            if (exit_code_out) *exit_code_out = err;
            return false;
        }
        if (exit_code_out) *exit_code_out = static_cast<uint32_t>(exit_code);
        return exit_code == STILL_ACTIVE;
    }

    struct pid_scope_t
    {
        bool     ok = false;
        bool     swapped = false;
        uint32_t prev_pid = 0;
        uint32_t target_pid = 0;
        std::unique_lock<std::recursive_mutex> lk;

        pid_scope_t() = default;
        pid_scope_t(const pid_scope_t&) = delete;
        pid_scope_t& operator=(const pid_scope_t&) = delete;

        ~pid_scope_t()
        {
            if (!ok) return;
            if (!swapped) return;
            const DWORD restore_start = GetTickCount();
            const uint32_t active_before = driver_bridge::attached_pid();
            uint32_t active_exit = 0;
            const bool active_alive = active_before != 0 && pid_is_alive(active_before, &active_exit);
            if (active_before != target_pid && active_before != 0 && active_alive) {
                diag::log_tagged_fmt("driver_bridge",
                    "pid_scope_exit_restore_skip target=%u previous=%u active_before=%u active_alive=%d active_exit=0x%08X status=%s last_error=%s elapsed_ms=%lu",
                    target_pid,
                    prev_pid,
                    active_before,
                    active_alive ? 1 : 0,
                    active_exit,
                    driver_bridge::status().c_str(),
                    driver_bridge::last_error().c_str(),
                    static_cast<unsigned long>(GetTickCount() - restore_start));
                return;
            }
            uint32_t selected_pid = 0;
            uint32_t previous_exit = 0;
            bool previous_alive = false;
            bool previous_known = false;
            bool restored = false;
            const char* method = "none";
            if (prev_pid != 0 && prev_pid != target_pid) {
                previous_alive = pid_is_alive(prev_pid, &previous_exit);
                const auto pids = driver_bridge::attached_pids();
                for (auto pid : pids) {
                    if (pid == prev_pid) {
                        previous_known = true;
                        break;
                    }
                }
                if (!previous_known && previous_alive)
                    previous_known = driver_bridge::attach_additional(prev_pid);
                if (previous_known && previous_alive) {
                    method = "previous";
                    restored = driver_bridge::set_active_pid(prev_pid);
                    if (restored)
                        selected_pid = prev_pid;
                }
            }
            if (!restored) {
                const auto pids = driver_bridge::attached_pids();
                for (auto pid : pids) {
                    if (pid == 0 || pid == target_pid)
                        continue;
                    uint32_t exit_code = 0;
                    if (!pid_is_alive(pid, &exit_code))
                        continue;
                    method = "fallback_live_attached";
                    restored = driver_bridge::set_active_pid(pid);
                    if (restored) {
                        selected_pid = pid;
                        break;
                    }
                }
            }
            if (!restored) {
                method = prev_pid == 0 ? "clear_no_previous" : "clear_no_live_restore";
                (void)driver_bridge::clear_active_pid();
            }
            diag::log_tagged_fmt("driver_bridge",
                "pid_scope_exit_restore target=%u previous=%u active_before=%u previous_known=%d previous_alive=%d previous_exit=0x%08X method=%s restored=%d selected=%u active_after=%u status=%s last_error=%s elapsed_ms=%lu",
                target_pid,
                prev_pid,
                active_before,
                previous_known ? 1 : 0,
                previous_alive ? 1 : 0,
                previous_exit,
                method,
                restored ? 1 : 0,
                selected_pid,
                driver_bridge::attached_pid(),
                driver_bridge::status().c_str(),
                driver_bridge::last_error().c_str(),
                static_cast<unsigned long>(GetTickCount() - restore_start));
        }
    };

    inline bool enter(pid_scope_t& scope, uint32_t pid)
    {
        if (pid == 0)
            return false;
        scope.lk = std::unique_lock<std::recursive_mutex>(g_call_mtx);
        scope.prev_pid = driver_bridge::attached_pid();
        scope.target_pid = pid;
        uint32_t exit_code = 0;
        if (!pid_is_alive(pid, &exit_code)) {
            diag::log_tagged_fmt("driver_bridge",
                "pid_scope_enter_dead_target pid=%u exit_code_or_err=0x%08X",
                pid, exit_code);
            (void)driver_bridge::detach_one(pid);
            return false;
        }
        if (scope.prev_pid == pid) {
            scope.ok = true;
            scope.swapped = false;
            return true;
        }
        const auto pids = driver_bridge::attached_pids();
        bool in_map = false;
        for (auto p : pids) { if (p == pid) { in_map = true; break; } }
        if (!in_map) {
            if (!driver_bridge::attach_additional(pid))
                return false;
        }
        if (!driver_bridge::set_active_pid(pid))
            return false;
        scope.ok = true;
        scope.swapped = true;
        return true;
    }
}

namespace driver_bridge
{
    bool read_memory_for(uint32_t pid, uint64_t address, size_t size, std::vector<uint8_t>& out)
    {
        driver_bridge_pid_call::pid_scope_t scope;
        if (!driver_bridge_pid_call::enter(scope, pid)) {
            const std::string err = last_error();
            diag::log_tagged_fmt("driver_bridge",
                "read_memory_for pid=%u addr=0x%llX size=%zu enter_failed active_pid=%u status=%s last_error=%s gle=%lu",
                pid,
                static_cast<unsigned long long>(address),
                size,
                attached_pid(),
                status().c_str(),
                err.empty() ? "(empty)" : err.c_str(),
                static_cast<unsigned long>(GetLastError()));
            return false;
        }
        bool ok = read_memory(address, size, out);
        diag::log_tagged_fmt("driver_bridge",
            "read_memory_for pid=%u addr=0x%llX size=%zu ok=%d bytes=%zu",
            pid, static_cast<unsigned long long>(address), size, ok ? 1 : 0, out.size());
        return ok;
    }

    bool write_memory_for(uint32_t pid, uint64_t address, const std::vector<uint8_t>& data)
    {
        driver_bridge_pid_call::pid_scope_t scope;
        if (!driver_bridge_pid_call::enter(scope, pid)) {
            diag::log_tagged_fmt("driver_bridge",
                "write_memory_for pid=%u addr=0x%llX size=%zu enter_failed",
                pid, static_cast<unsigned long long>(address), data.size());
            return false;
        }
        bool ok = write_memory(address, data);
        diag::log_tagged_fmt("driver_bridge",
            "write_memory_for pid=%u addr=0x%llX size=%zu ok=%d",
            pid, static_cast<unsigned long long>(address), data.size(), ok ? 1 : 0);
        return ok;
    }

    bool query_memory_for(uint32_t pid, uint64_t address, memory_region_t& region)
    {
        driver_bridge_pid_call::pid_scope_t scope;
        if (!driver_bridge_pid_call::enter(scope, pid))
            return false;
        return query_memory(address, region);
    }

    bool protect_memory_for(uint32_t pid, uint64_t address, uint64_t size,
                            uint32_t new_protect, uint32_t* old_protect)
    {
        driver_bridge_pid_call::pid_scope_t scope;
        if (!driver_bridge_pid_call::enter(scope, pid))
            return false;
        return protect_memory(address, size, new_protect, old_protect);
    }

    std::vector<module_info_t> enumerate_modules_for(uint32_t pid)
    {
        const ULONGLONG t0 = GetTickCount64();
        driver_bridge_pid_call::pid_scope_t scope;
        if (!driver_bridge_pid_call::enter(scope, pid)) {
            diag::log_tagged_critical_fmt("driver",
                "enumerate_modules_for_enter_failed requested_pid=%u active_pid=%u status=%s last_error=%s elapsed_ms=%llu",
                pid,
                attached_pid(),
                status().c_str(),
                last_error().c_str(),
                static_cast<unsigned long long>(GetTickCount64() - t0));
            return {};
        }
        auto result = enumerate_modules();
        diag::log_tagged_critical_fmt("driver",
            "enumerate_modules_for_exit requested_pid=%u active_pid=%u count=%llu status=%s last_error=%s elapsed_ms=%llu",
            pid,
            attached_pid(),
            static_cast<unsigned long long>(result.size()),
            status().c_str(),
            last_error().c_str(),
            static_cast<unsigned long long>(GetTickCount64() - t0));
        return result;
    }

    std::vector<thread_info_t> enumerate_threads_for(uint32_t pid)
    {
        driver_bridge_pid_call::pid_scope_t scope;
        if (!driver_bridge_pid_call::enter(scope, pid))
            return {};
        return enumerate_threads();
    }

    std::vector<memory_region_t> enumerate_memory_regions_for(uint32_t pid, size_t max_regions)
    {
        driver_bridge_pid_call::pid_scope_t scope;
        if (!driver_bridge_pid_call::enter(scope, pid))
            return {};
        return enumerate_memory_regions(max_regions);
    }

    bool read_peb_for(uint32_t pid, peb_info_t& out)
    {
        driver_bridge_pid_call::pid_scope_t scope;
        if (!driver_bridge_pid_call::enter(scope, pid))
            return false;
        return read_peb(out);
    }

    uint64_t resolve_export_for(uint32_t pid, uint64_t module_base, const char* export_name)
    {
        const ULONGLONG t0 = GetTickCount64();
        driver_bridge_pid_call::pid_scope_t scope;
        if (!driver_bridge_pid_call::enter(scope, pid)) {
            diag::log_tagged_fmt("driver_bridge",
                "resolve_export_for_enter_failed pid=%u active_pid=%u module=0x%llX export=%s status=%s last_error=%s elapsed_ms=%llu",
                pid,
                attached_pid(),
                static_cast<unsigned long long>(module_base),
                export_name ? export_name : "(null)",
                status().c_str(),
                last_error().c_str(),
                static_cast<unsigned long long>(GetTickCount64() - t0));
            return 0;
        }
        const uint32_t active = attached_pid();
        const uint64_t resolved = resolve_export(module_base, export_name);
        diag::log_tagged_fmt("driver_bridge",
            "resolve_export_for pid=%u active_pid=%u module=0x%llX export=%s result=0x%llX elapsed_ms=%llu",
            pid,
            active,
            static_cast<unsigned long long>(module_base),
            export_name ? export_name : "(null)",
            static_cast<unsigned long long>(resolved),
            static_cast<unsigned long long>(GetTickCount64() - t0));
        return resolved;
    }

    uint64_t allocate_memory_for(uint32_t pid, size_t size)
    {
        const ULONGLONG t0 = GetTickCount64();
        if (size == 0) {
            diag::log_tagged_fmt("driver_bridge",
                "allocate_memory_for_reject pid=%u size=%zu reason=zero elapsed_ms=%llu",
                pid,
                size,
                static_cast<unsigned long long>(GetTickCount64() - t0));
            return 0;
        }
        driver_bridge_pid_call::pid_scope_t scope;
        if (!driver_bridge_pid_call::enter(scope, pid)) {
            diag::log_tagged_fmt("driver_bridge",
                "allocate_memory_for_enter_failed pid=%u active_pid=%u size=%zu status=%s last_error=%s elapsed_ms=%llu",
                pid,
                attached_pid(),
                size,
                status().c_str(),
                last_error().c_str(),
                static_cast<unsigned long long>(GetTickCount64() - t0));
            return 0;
        }
        const uint32_t active = attached_pid();
        const uint64_t remote = allocate_memory(size);
        diag::log_tagged_fmt("driver_bridge",
            "allocate_memory_for pid=%u active_pid=%u size=%zu result=0x%llX elapsed_ms=%llu",
            pid,
            active,
            size,
            static_cast<unsigned long long>(remote),
            static_cast<unsigned long long>(GetTickCount64() - t0));
        return remote;
    }

    bool free_memory_for(uint32_t pid, uint64_t address)
    {
        const ULONGLONG t0 = GetTickCount64();
        if (address == 0) {
            diag::log_tagged_fmt("driver_bridge",
                "free_memory_for_reject pid=%u addr=0x%llX reason=zero elapsed_ms=%llu",
                pid,
                static_cast<unsigned long long>(address),
                static_cast<unsigned long long>(GetTickCount64() - t0));
            return false;
        }
        driver_bridge_pid_call::pid_scope_t scope;
        if (!driver_bridge_pid_call::enter(scope, pid)) {
            diag::log_tagged_fmt("driver_bridge",
                "free_memory_for_enter_failed pid=%u active_pid=%u addr=0x%llX status=%s last_error=%s elapsed_ms=%llu",
                pid,
                attached_pid(),
                static_cast<unsigned long long>(address),
                status().c_str(),
                last_error().c_str(),
                static_cast<unsigned long long>(GetTickCount64() - t0));
            SetLastError(ERROR_INVALID_HANDLE);
            return false;
        }
        const uint32_t active = attached_pid();
        const bool ok = free_memory(address);
        diag::log_tagged_fmt("driver_bridge",
            "free_memory_for pid=%u active_pid=%u addr=0x%llX ok=%d elapsed_ms=%llu",
            pid,
            active,
            static_cast<unsigned long long>(address),
            ok ? 1 : 0,
            static_cast<unsigned long long>(GetTickCount64() - t0));
        return ok;
    }


    bool read_kernel_memory(uint64_t address, size_t size, std::vector<uint8_t>& out)
    {
        out.clear();
        if (size == 0)
            return false;

        bool kernel_mode = false;
        uint64_t current_dtb = 0;
        uint64_t current_kernel_dtb = 0;
        uint32_t current_pid = 0;
        {
            std::lock_guard<std::mutex> lk(g_state_mtx);
            kernel_mode = g_kernel_mode && device && device->is_connected();
            current_pid = g_pid;
            if (device) {
                current_dtb = device->get_dtb();
                current_kernel_dtb = device->get_kernel_dtb();
            }
        }
        if (!kernel_mode) {
            require_kernel_fail("read_kernel_memory");
            return false;
        }

        out.resize(size);
        const size_t bytes_read = device->read_kernel_raw(address, out.data(), size);
        if (bytes_read == 0) {
            static std::atomic<int> s_kernel_read_fail_logs{0};
            const int log_index = s_kernel_read_fail_logs.fetch_add(1);
            if (log_index < 160) {
                diag::log_tagged_fmt("driver_bridge",
                    "read_kernel_memory_failed addr=0x%llX size=%llu pid=%u dtb=0x%llX kdtb=0x%llX connected=%d",
                    static_cast<unsigned long long>(address),
                    static_cast<unsigned long long>(size),
                    current_pid,
                    static_cast<unsigned long long>(current_dtb),
                    static_cast<unsigned long long>(current_kernel_dtb),
                    device && device->is_connected() ? 1 : 0);
            }
            out.clear();
            return false;
        }
        out.resize(bytes_read);
        clear_last_error_after_success("read_kernel_memory");
        return true;
    }

    bool write_kernel_memory(uint64_t address, const std::vector<uint8_t>& data)
    {
        if (data.empty())
            return false;

        bool kernel_mode = false;
        {
            std::lock_guard<std::mutex> lk(g_state_mtx);
            kernel_mode = g_kernel_mode && device && device->is_connected();
        }
        if (!kernel_mode) {
            require_kernel_fail("write_kernel_memory");
            return false;
        }

        const size_t bytes_written = device->write_kernel_raw(address, data.data(), data.size());
        return bytes_written > 0;
    }


    uint64_t allocate_memory(size_t size)
    {
        if (size == 0)
            return 0;

        bool kernel_mode = false;
        bool kernel_attached = false;
        {
            std::lock_guard<std::mutex> lk(g_state_mtx);
            kernel_mode = g_kernel_mode && device && device->is_connected();
            kernel_attached = g_kernel_attached;
        }

        if (!kernel_mode || !kernel_attached) {
            diag::log_tagged_fmt("driver",
                "allocate_memory_kernel_required sz=%llu kernel=%d attached=%d",
                static_cast<unsigned long long>(size),
                kernel_mode ? 1 : 0,
                kernel_attached ? 1 : 0);
            require_kernel_fail("allocate_memory");
            return 0;
        }

        const uint64_t remote = device->allocate_memory(size);
        diag::log_tagged_fmt("driver",
            "allocate_memory kernel sz=%llu addr=0x%llX",
            static_cast<unsigned long long>(size),
            static_cast<unsigned long long>(remote));
        if (remote != 0)
            clear_last_error_after_success("allocate_memory_kernel");
        return remote;
    }

    bool free_memory(uint64_t address)
    {
        if (address == 0)
            return false;

        bool kernel_mode = false;
        bool kernel_attached = false;
        {
            std::lock_guard<std::mutex> lk(g_state_mtx);
            kernel_mode = g_kernel_mode && device && device->is_connected();
            kernel_attached = g_kernel_attached;
        }

        if (!kernel_mode || !kernel_attached) {
            diag::log_tagged_fmt("driver",
                "free_memory_kernel_required addr=0x%llX kernel=%d attached=%d",
                static_cast<unsigned long long>(address),
                kernel_mode ? 1 : 0,
                kernel_attached ? 1 : 0);
            require_kernel_fail("free_memory");
            return false;
        }

        const bool ok = device->free_memory(address);
        diag::log_tagged_fmt("driver",
            "free_memory kernel addr=0x%llX ok=%d",
            static_cast<unsigned long long>(address), ok ? 1 : 0);
        if (ok)
            clear_last_error_after_success("free_memory_kernel");
        return ok;
    }

    bool protect_memory(uint64_t address, uint64_t size, uint32_t new_protect, uint32_t* old_protect)
    {
        bool kernel_mode = false;
        bool kernel_attached = false;
        {
            std::lock_guard<std::mutex> lk(g_state_mtx);
            kernel_mode = g_kernel_mode && device && device->is_connected();
            kernel_attached = g_kernel_attached;
        }

        if (!kernel_mode || !kernel_attached || size == 0) {
            diag::log_tagged_fmt("driver",
                "protect_memory_kernel_required addr=0x%llX sz=0x%llX protect=0x%X kernel=%d attached=%d",
                static_cast<unsigned long long>(address),
                static_cast<unsigned long long>(size),
                new_protect,
                kernel_mode ? 1 : 0,
                kernel_attached ? 1 : 0);
            require_kernel_fail("protect_memory");
            return false;
        }

        const bool ok = device->protect_memory(address, size, new_protect, old_protect);
        diag::log_tagged_fmt("driver",
            "protect_memory kernel addr=0x%llX sz=0x%llX protect=0x%X ok=%d",
            static_cast<unsigned long long>(address),
            static_cast<unsigned long long>(size),
            new_protect, ok ? 1 : 0);
        if (ok)
            clear_last_error_after_success("protect_memory_kernel");
        return ok;
    }


    bool get_thread_context(uint32_t tid, thread_context_t& ctx)
    {
        bool kernel_mode = false;
        bool kernel_attached = false;
        {
            std::lock_guard<std::mutex> lk(g_state_mtx);
            kernel_mode = g_kernel_mode && device && device->is_connected();
            kernel_attached = g_kernel_attached;
        }
        if (!kernel_mode || !kernel_attached) {
            diag::log_tagged_fmt("driver",
                "get_thread_context_kernel_required tid=%u kernel=%d attached=%d bypass=%d",
                tid,
                kernel_mode ? 1 : 0,
                kernel_attached ? 1 : 0,
                tctx_kernel_bypass_active() ? 1 : 0);
            require_kernel_fail("get_thread_context");
            return false;
        }

        voyager::device_t::thread_context kctx{};
        const uint64_t kernel_t0 = static_cast<uint64_t>(GetTickCount64());
        if (!device->get_thread_context(tid, kctx)) {
            DWORD gle = GetLastError();
            const uint64_t elapsed_ms = static_cast<uint64_t>(GetTickCount64()) - kernel_t0;
            const uint32_t pid = attached_pid();
            note_tctx_kernel_failure("get_thread_context", pid, tid, gle, elapsed_ms);
            diag::log_tagged_fmt("driver",
                "get_thread_context_kernel_failed tid=%u gle=%lu attached_pid=%u elapsed_ms=%llu fail_closed=1",
                tid,
                gle,
                pid,
                static_cast<unsigned long long>(elapsed_ms));
            SetLastError(gle);
            return false;
        }
        note_tctx_kernel_success();

        ctx.rax = kctx.rax;  ctx.rbx = kctx.rbx;  ctx.rcx = kctx.rcx;  ctx.rdx = kctx.rdx;
        ctx.rsi = kctx.rsi;  ctx.rdi = kctx.rdi;  ctx.rbp = kctx.rbp;  ctx.rsp = kctx.rsp;
        ctx.r8  = kctx.r8;   ctx.r9  = kctx.r9;   ctx.r10 = kctx.r10;  ctx.r11 = kctx.r11;
        ctx.r12 = kctx.r12;  ctx.r13 = kctx.r13;  ctx.r14 = kctx.r14;  ctx.r15 = kctx.r15;
        ctx.rip = kctx.rip;  ctx.rflags = kctx.rflags;
        ctx.cs  = kctx.cs;   ctx.ss  = kctx.ss;
        ctx.dr0 = kctx.dr0;  ctx.dr1 = kctx.dr1;  ctx.dr2 = kctx.dr2;  ctx.dr3 = kctx.dr3;
        ctx.dr6 = kctx.dr6;  ctx.dr7 = kctx.dr7;
        if (ctx.rip == 0 || ctx.rsp == 0 || ctx.rflags == 0) {
            diag::log_tagged_fmt("driver",
                "get_thread_context_REJECTED_ZERO tid=%u rip=0x%llX rsp=0x%llX rflags=0x%llX fail_closed=1",
                tid,
                static_cast<unsigned long long>(ctx.rip),
                static_cast<unsigned long long>(ctx.rsp),
                static_cast<unsigned long long>(ctx.rflags));
            SetLastError(ERROR_INVALID_DATA);
            return false;
        }
        diag::log_tagged_fmt("driver",
            "get_thread_context_kernel_ok tid=%u rip=0x%llX rsp=0x%llX dr7=0x%llX",
            tid,
            static_cast<unsigned long long>(ctx.rip),
            static_cast<unsigned long long>(ctx.rsp),
            static_cast<unsigned long long>(ctx.dr7));
        return true;
    }

    bool set_thread_context(uint32_t tid, const thread_context_t& ctx, uint64_t register_mask)
    {
        bool kernel_mode = false;
        bool kernel_attached = false;
        {
            std::lock_guard<std::mutex> lk(g_state_mtx);
            kernel_mode = g_kernel_mode && device && device->is_connected();
            kernel_attached = g_kernel_attached;
        }
        if (!kernel_mode || !kernel_attached) {
            diag::log_tagged_fmt("driver",
                "set_thread_context_kernel_required tid=%u mask=0x%llX kernel=%d attached=%d bypass=%d",
                tid,
                static_cast<unsigned long long>(register_mask),
                kernel_mode ? 1 : 0,
                kernel_attached ? 1 : 0,
                tctx_kernel_bypass_active() ? 1 : 0);
            require_kernel_fail("set_thread_context");
            return false;
        }

        voyager::device_t::thread_context kctx{};
        kctx.rax = ctx.rax;  kctx.rbx = ctx.rbx;  kctx.rcx = ctx.rcx;  kctx.rdx = ctx.rdx;
        kctx.rsi = ctx.rsi;  kctx.rdi = ctx.rdi;  kctx.rbp = ctx.rbp;  kctx.rsp = ctx.rsp;
        kctx.r8  = ctx.r8;   kctx.r9  = ctx.r9;   kctx.r10 = ctx.r10;  kctx.r11 = ctx.r11;
        kctx.r12 = ctx.r12;  kctx.r13 = ctx.r13;  kctx.r14 = ctx.r14;  kctx.r15 = ctx.r15;
        kctx.rip = ctx.rip;  kctx.rflags = ctx.rflags;
        kctx.cs  = ctx.cs;   kctx.ss  = ctx.ss;
        kctx.dr0 = ctx.dr0;  kctx.dr1 = ctx.dr1;  kctx.dr2 = ctx.dr2;  kctx.dr3 = ctx.dr3;
        kctx.dr6 = ctx.dr6;  kctx.dr7 = ctx.dr7;
        const uint64_t kernel_t0 = static_cast<uint64_t>(GetTickCount64());
        bool ok = device->set_thread_context(tid, kctx, register_mask);
        if (!ok) {
            DWORD gle = GetLastError();
            const uint64_t elapsed_ms = static_cast<uint64_t>(GetTickCount64()) - kernel_t0;
            const uint32_t pid = attached_pid();
            note_tctx_kernel_failure("set_thread_context", pid, tid, gle, elapsed_ms);
            diag::log_tagged_fmt("driver",
                "set_thread_context_KERNEL_FAILED tid=%u mask=0x%llX rip=0x%llX rsp=0x%llX attached_pid=%u kernel_mode=%d gle=%lu elapsed_ms=%llu fail_closed=1",
                tid,
                static_cast<unsigned long long>(register_mask),
                static_cast<unsigned long long>(ctx.rip),
                static_cast<unsigned long long>(ctx.rsp),
                pid,
                kernel_mode ? 1 : 0,
                gle,
                static_cast<unsigned long long>(elapsed_ms));
            SetLastError(gle);
        } else {
            note_tctx_kernel_success();
            diag::log_tagged_fmt("driver",
                "set_thread_context_kernel_ok tid=%u mask=0x%llX rip=0x%llX rsp=0x%llX dr7=0x%llX",
                tid,
                static_cast<unsigned long long>(register_mask),
                static_cast<unsigned long long>(ctx.rip),
                static_cast<unsigned long long>(ctx.rsp),
                static_cast<unsigned long long>(ctx.dr7));
        }
        return ok;
    }

    bool suspend_thread(uint32_t tid, uint32_t* prev_count)
    {
        bool kernel_mode = false;
        bool kernel_attached = false;
        {
            std::lock_guard<std::mutex> lk(g_state_mtx);
            kernel_mode = g_kernel_mode && device && device->is_connected();
            kernel_attached = g_kernel_attached;
        }
        if (!kernel_mode || !kernel_attached) {
            diag::log_tagged_fmt("driver",
                "suspend_thread_kernel_required tid=%u kernel=%d attached=%d",
                tid,
                kernel_mode ? 1 : 0,
                kernel_attached ? 1 : 0);
            require_kernel_fail("suspend_thread");
            return false;
        }

        bool ok = device->suspend_thread(tid, prev_count);
        if (!ok) {
            DWORD gle = GetLastError();
            diag::log_tagged_fmt("driver",
                "suspend_thread_kernel_failed tid=%u gle=%lu fail_closed=1",
                tid,
                gle);
            SetLastError(gle);
        }
        return ok;
    }

    bool resume_thread(uint32_t tid, uint32_t* prev_count)
    {
        bool kernel_mode = false;
        bool kernel_attached = false;
        {
            std::lock_guard<std::mutex> lk(g_state_mtx);
            kernel_mode = g_kernel_mode && device && device->is_connected();
            kernel_attached = g_kernel_attached;
        }
        if (!kernel_mode || !kernel_attached) {
            diag::log_tagged_fmt("driver",
                "resume_thread_kernel_required tid=%u kernel=%d attached=%d",
                tid,
                kernel_mode ? 1 : 0,
                kernel_attached ? 1 : 0);
            require_kernel_fail("resume_thread");
            return false;
        }

        bool ok = device->resume_thread(tid, prev_count);
        if (!ok) {
            DWORD gle = GetLastError();
            diag::log_tagged_fmt("driver",
                "resume_thread_kernel_failed tid=%u gle=%lu fail_closed=1",
                tid,
                gle);
            SetLastError(gle);
        }
        return ok;
    }

    bool query_thread_information(uint32_t tid, uint32_t info_class, void* buffer, uint32_t buffer_size, uint32_t* return_length)
    {
        if (return_length != nullptr)
            *return_length = 0;
        if (tid == 0 || buffer == nullptr || buffer_size == 0)
            return false;
        if (info_class != 0)
            return false;

        bool kernel_mode = false;
        bool kernel_attached = false;
        {
            std::lock_guard<std::mutex> lk(g_state_mtx);
            kernel_mode = g_kernel_mode && device && device->is_connected();
            kernel_attached = g_kernel_attached;
        }
        if (!kernel_mode || !kernel_attached) {
            diag::log_tagged_fmt("driver",
                "query_thread_information_kernel_required tid=%u class=%u size=%u kernel=%d attached=%d",
                tid,
                info_class,
                buffer_size,
                kernel_mode ? 1 : 0,
                kernel_attached ? 1 : 0);
            require_kernel_fail("query_thread_information");
            return false;
        }

        voyager::detail::thread_query_information_request info{};
        if (!device->query_thread_basic_information(tid, info)) {
            diag::log_tagged_fmt("driver",
                "query_thread_information_kernel_failed tid=%u status=0x%08X",
                tid,
                info.status);
            SetLastError(ERROR_GEN_FAILURE);
            return false;
        }

        struct teb_basic_t {
            long      exit_status;
            void*     teb_base;
            void*     unique_process;
            void*     unique_thread;
            uintptr_t affinity_mask;
            long      priority;
            long      base_priority;
        };
        if (buffer_size < sizeof(teb_basic_t)) {
            SetLastError(ERROR_INSUFFICIENT_BUFFER);
            return false;
        }
        teb_basic_t out{};
        out.exit_status = static_cast<long>(info.exit_status);
        out.teb_base = reinterpret_cast<void*>(static_cast<uintptr_t>(info.teb_base));
        out.unique_process = reinterpret_cast<void*>(static_cast<uintptr_t>(info.client_process));
        out.unique_thread = reinterpret_cast<void*>(static_cast<uintptr_t>(info.client_thread));
        out.affinity_mask = static_cast<uintptr_t>(info.affinity_mask);
        out.priority = static_cast<long>(info.priority);
        out.base_priority = static_cast<long>(info.base_priority);
        std::memcpy(buffer, &out, sizeof(out));
        if (return_length != nullptr)
            *return_length = sizeof(out);
        clear_last_error_after_success("query_thread_information_kernel");
        return true;
    }

    bool terminate_thread(uint32_t tid, uint32_t exit_status)
    {
        if (tid == 0)
            return false;
        bool kernel_mode = false;
        bool kernel_attached = false;
        {
            std::lock_guard<std::mutex> lk(g_state_mtx);
            kernel_mode = g_kernel_mode && device && device->is_connected();
            kernel_attached = g_kernel_attached;
        }
        if (!kernel_mode || !kernel_attached) {
            diag::log_tagged_fmt("driver",
                "terminate_thread_kernel_required tid=%u exit=0x%08X kernel=%d attached=%d",
                tid,
                exit_status,
                kernel_mode ? 1 : 0,
                kernel_attached ? 1 : 0);
            require_kernel_fail("terminate_thread");
            return false;
        }
        const bool ok = device->terminate_thread(tid, exit_status);
        diag::log_tagged_fmt("driver",
            "terminate_thread_kernel tid=%u exit=0x%08X ok=%d",
            tid,
            exit_status,
            ok ? 1 : 0);
        if (ok)
            clear_last_error_after_success("terminate_thread_kernel");
        return ok;
    }

    bool close_process_handle(uint32_t pid, uint64_t handle_value)
    {
        if (pid == 0 || handle_value == 0)
            return false;
        bool kernel_mode = false;
        {
            std::lock_guard<std::mutex> lk(g_state_mtx);
            kernel_mode = g_kernel_mode && device && device->is_connected();
        }
        if (!kernel_mode) {
            diag::log_tagged_fmt("driver",
                "close_process_handle_kernel_required pid=%u handle=0x%llX kernel=%d",
                pid,
                static_cast<unsigned long long>(handle_value),
                kernel_mode ? 1 : 0);
            require_kernel_fail("close_process_handle");
            return false;
        }
        const bool ok = device->close_process_handle(pid, handle_value);
        diag::log_tagged_fmt("driver",
            "close_process_handle_kernel pid=%u handle=0x%llX ok=%d",
            pid,
            static_cast<unsigned long long>(handle_value),
            ok ? 1 : 0);
        if (ok)
            clear_last_error_after_success("close_process_handle_kernel");
        return ok;
    }


    bool read_peb(peb_info_t& out)
    {
        bool kernel_mode = false;
        {
            std::lock_guard<std::mutex> lk(g_state_mtx);
            kernel_mode = g_kernel_mode && device && device->is_connected();
        }
        if (!kernel_mode) {
            require_kernel_fail("read_peb");
            return false;
        }

        voyager::device_t::peb_info kpeb{};
        if (!device->read_peb(kpeb))
            return false;

        out.peb_address     = kpeb.peb_address;
        out.image_base      = kpeb.image_base;
        out.being_debugged  = kpeb.being_debugged;
        out.nt_global_flag  = kpeb.nt_global_flag;
        out.ldr_address     = kpeb.ldr_address;
        out.process_heap    = kpeb.process_heap;
        out.number_of_heaps = kpeb.number_of_heaps;
        out.max_heaps       = kpeb.max_heaps;
        out.process_heaps   = kpeb.process_heaps;
        return true;
    }

    bool usermode_module_base(uint64_t module_base)
    {
        return module_base != 0 && module_base < 0x0000800000000000ULL;
    }

    bool read_process_exact(uint64_t address, void* buffer, size_t size)
    {
        if (address == 0 || !buffer || size == 0)
            return false;
        std::vector<uint8_t> bytes;
        if (!read_memory(address, size, bytes) || bytes.size() < size)
            return false;
        std::memcpy(buffer, bytes.data(), size);
        return true;
    }

    std::string read_process_c_string(uint64_t address, size_t max_len)
    {
        if (address == 0 || max_len == 0 || max_len > 4096)
            return {};
        std::vector<uint8_t> bytes;
        if (!read_memory(address, max_len, bytes) || bytes.empty())
            return {};
        std::string out;
        out.reserve((std::min<size_t>)(bytes.size(), max_len));
        for (uint8_t b : bytes) {
            if (b == 0)
                break;
            if (b < 0x20 || b > 0x7E)
                return {};
            out.push_back(static_cast<char>(b));
            if (out.size() >= max_len)
                break;
        }
        return out;
    }

    uint64_t resolve_export_usermode_pe(uint64_t module_base, const char* export_name, uint32_t* ordinal_out)
    {
        if (!usermode_module_base(module_base) || !export_name || !*export_name)
            return 0;

        IMAGE_DOS_HEADER dos{};
        if (!read_process_exact(module_base, &dos, sizeof(dos)) || dos.e_magic != IMAGE_DOS_SIGNATURE)
            return 0;
        if (dos.e_lfanew <= 0 || dos.e_lfanew > 0x100000)
            return 0;

        const uint64_t nt_va = module_base + static_cast<uint32_t>(dos.e_lfanew);
        DWORD sig = 0;
        if (!read_process_exact(nt_va, &sig, sizeof(sig)) || sig != IMAGE_NT_SIGNATURE)
            return 0;

        IMAGE_FILE_HEADER fh{};
        if (!read_process_exact(nt_va + sizeof(DWORD), &fh, sizeof(fh)))
            return 0;
        if (fh.NumberOfSections == 0 || fh.NumberOfSections > 128)
            return 0;

        const uint64_t opt_va = nt_va + sizeof(DWORD) + sizeof(IMAGE_FILE_HEADER);
        WORD magic = 0;
        if (!read_process_exact(opt_va, &magic, sizeof(magic)))
            return 0;

        DWORD export_rva = 0;
        DWORD export_size = 0;
        if (magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC) {
            IMAGE_OPTIONAL_HEADER64 opt{};
            if (!read_process_exact(opt_va, &opt, sizeof(opt)))
                return 0;
            if (IMAGE_DIRECTORY_ENTRY_EXPORT >= opt.NumberOfRvaAndSizes)
                return 0;
            export_rva = opt.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
            export_size = opt.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size;
        } else if (magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC) {
            IMAGE_OPTIONAL_HEADER32 opt{};
            if (!read_process_exact(opt_va, &opt, sizeof(opt)))
                return 0;
            if (IMAGE_DIRECTORY_ENTRY_EXPORT >= opt.NumberOfRvaAndSizes)
                return 0;
            export_rva = opt.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
            export_size = opt.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size;
        } else {
            return 0;
        }

        if (export_rva == 0 || export_size < sizeof(IMAGE_EXPORT_DIRECTORY))
            return 0;

        IMAGE_EXPORT_DIRECTORY exp{};
        if (!read_process_exact(module_base + export_rva, &exp, sizeof(exp)))
            return 0;
        if (exp.NumberOfNames == 0 || exp.NumberOfFunctions == 0 ||
            exp.AddressOfNames == 0 || exp.AddressOfNameOrdinals == 0 || exp.AddressOfFunctions == 0)
            return 0;

        const DWORD name_count = (std::min<DWORD>)(exp.NumberOfNames, 65536u);
        for (DWORD i = 0; i < name_count; ++i) {
            DWORD name_rva = 0;
            WORD ordinal_index = 0;
            if (!read_process_exact(module_base + exp.AddressOfNames + static_cast<uint64_t>(i) * sizeof(DWORD),
                                    &name_rva, sizeof(name_rva)) || name_rva == 0)
                continue;
            if (!read_process_exact(module_base + exp.AddressOfNameOrdinals + static_cast<uint64_t>(i) * sizeof(WORD),
                                    &ordinal_index, sizeof(ordinal_index)))
                continue;
            if (ordinal_index >= exp.NumberOfFunctions)
                continue;
            const std::string candidate = read_process_c_string(module_base + name_rva, 512);
            if (candidate != export_name)
                continue;

            DWORD func_rva = 0;
            if (!read_process_exact(module_base + exp.AddressOfFunctions + static_cast<uint64_t>(ordinal_index) * sizeof(DWORD),
                                    &func_rva, sizeof(func_rva)) || func_rva == 0)
                return 0;
            if (func_rva >= export_rva && func_rva < export_rva + export_size)
                return 0;
            if (ordinal_out)
                *ordinal_out = exp.Base + ordinal_index;
            return module_base + func_rva;
        }

        return 0;
    }

    uint64_t resolve_export(uint64_t module_base, const char* export_name)
    {
        if (module_base == 0 || !export_name || !*export_name)
            return 0;

        bool kernel_mode = false;
        {
            std::lock_guard<std::mutex> lk(g_state_mtx);
            kernel_mode = g_kernel_mode && device && device->is_connected();
        }
        if (!kernel_mode) {
            uint32_t ordinal = 0;
            const uint64_t fallback = resolve_export_usermode_pe(module_base, export_name, &ordinal);
            if (fallback != 0)
                return fallback;
            require_kernel_fail("resolve_export");
            return 0;
        }

        const uint64_t resolved = device->resolve_export(module_base, export_name);
        if (resolved != 0)
            return resolved;
        if (!usermode_module_base(module_base))
            return 0;

        uint32_t ordinal = 0;
        const uint64_t fallback = resolve_export_usermode_pe(module_base, export_name, &ordinal);
        static std::atomic<int> s_export_fallback_logs{0};
        const int log_index = s_export_fallback_logs.fetch_add(1);
        if (log_index < 160) {
            diag::log_tagged_fmt("driver_bridge",
                "resolve_export_user_fallback module=0x%llX export=%s result=0x%llX ordinal=%u kernel_mode=%d",
                static_cast<unsigned long long>(module_base),
                export_name,
                static_cast<unsigned long long>(fallback),
                ordinal,
                kernel_mode ? 1 : 0);
        }
        return fallback;
    }

    uint64_t virtual_to_physical(uint64_t virtual_address)
    {
        if (virtual_address == 0)
            return 0;

        bool kernel_mode = false;
        {
            std::lock_guard<std::mutex> lk(g_state_mtx);
            kernel_mode = g_kernel_mode && device && device->is_connected();
        }
        if (!kernel_mode) {
            require_kernel_fail("virtual_to_physical");
            return 0;
        }

        return device->virtual_to_physical(virtual_address);
    }


    std::vector<net_connection_info_t> enumerate_connections(uint32_t filter_pid, uint32_t filter_protocol)
    {
        const ULONGLONG t0 = GetTickCount64();
        std::vector<net_connection_info_t> result;

        bool kernel_mode = false;
        {
            std::lock_guard<std::mutex> lk(g_state_mtx);
            kernel_mode = g_kernel_mode && device && device->is_connected();
        }
        if (!kernel_mode) {
            require_kernel_fail("enumerate_connections");
            return result;
        }

        diag::log_tagged_fmt("driver_bridge_net",
            "enumerate_connections ENTER filter_pid=%u filter_protocol=%u",
            filter_pid, filter_protocol);
        auto raw = device->enumerate_connections(filter_pid, filter_protocol);
        result.reserve(raw.size());
        for (const auto& src : raw) {
            net_connection_info_t c;
            c.pid            = src.pid;
            c.protocol       = src.protocol;
            c.state          = src.state;
            c.local_port     = src.local_port;
            c.remote_port    = src.remote_port;
            c.address_family = src.address_family;
            std::memcpy(c.local_addr,  src.local_addr,  sizeof(c.local_addr));
            std::memcpy(c.remote_addr, src.remote_addr, sizeof(c.remote_addr));
            std::memcpy(c.process_path, src.process_path, sizeof(c.process_path));
            result.push_back(c);
        }
        diag::log_tagged_fmt("driver_bridge_net",
            "enumerate_connections EXIT filter_pid=%u filter_protocol=%u raw=%zu mapped=%zu elapsed_ms=%llu",
            filter_pid, filter_protocol, raw.size(), result.size(),
            static_cast<unsigned long long>(GetTickCount64() - t0));
        return result;
    }


    bool start_capture(uint32_t filter_pid, uint32_t filter_port, uint32_t filter_protocol, const uint8_t* filter_ip, uint32_t max_payload)
    {
        bool kernel_mode = false;
        {
            std::lock_guard<std::mutex> lk(g_state_mtx);
            kernel_mode = g_kernel_mode && device && device->is_connected();
        }
        logf("start_capture: kernel_mode=%d pid=%u port=%u proto=%u\n", kernel_mode ? 1 : 0, filter_pid, filter_port, filter_protocol);
        if (!kernel_mode) {
            require_kernel_fail("start_capture");
            return false;
        }

        bool result = device->start_capture(filter_pid, filter_port, filter_protocol, filter_ip, max_payload);
        logf("start_capture: device->start_capture returned %d\n", result ? 1 : 0);
        return result;
    }

    bool stop_capture()
    {
        const ULONGLONG t0 = GetTickCount64();
        bool kernel_mode = false;
        {
            std::lock_guard<std::mutex> lk(g_state_mtx);
            kernel_mode = g_kernel_mode && device && device->is_connected();
        }
        if (!kernel_mode) {
            require_kernel_fail("stop_capture");
            return false;
        }

        bool ok = device->stop_capture();
        DWORD gle = ok ? 0 : GetLastError();
        diag::log_tagged_fmt("driver_bridge_net",
            "stop_capture EXIT ok=%d gle=%lu elapsed_ms=%llu",
            ok ? 1 : 0,
            static_cast<unsigned long>(gle),
            static_cast<unsigned long long>(GetTickCount64() - t0));
        return ok;
    }

    bool get_capture_status(bool& active, uint32_t& captured, uint32_t& dropped)
    {
        const ULONGLONG t0 = GetTickCount64();
        bool kernel_mode = false;
        {
            std::lock_guard<std::mutex> lk(g_state_mtx);
            kernel_mode = g_kernel_mode && device && device->is_connected();
        }
        if (!kernel_mode) {
            diag::log_tagged("driver_bridge_net", "get_capture_status ABORT kernel_mode=false");
            return false;
        }

        bool ok = device->get_capture_status(active, captured, dropped);
        DWORD gle = ok ? 0 : GetLastError();
        diag::log_tagged_fmt("driver_bridge_net",
            "get_capture_status EXIT ok=%d active=%d captured=%u dropped=%u gle=%lu elapsed_ms=%llu",
            ok ? 1 : 0,
            active ? 1 : 0,
            captured,
            dropped,
            static_cast<unsigned long>(gle),
            static_cast<unsigned long long>(GetTickCount64() - t0));
        return ok;
    }

    std::vector<captured_packet_t> get_captured_packets(uint32_t max_packets)
    {
        std::vector<captured_packet_t> result;

        bool kernel_mode = false;
        {
            std::lock_guard<std::mutex> lk(g_state_mtx);
            kernel_mode = g_kernel_mode && device && device->is_connected();
        }
        if (!kernel_mode) {
            logf("get_captured_packets: kernel_mode=false, returning empty\n");
            return result;
        }

        auto raw = device->get_captured_packets(max_packets);
        logf("get_captured_packets: got %zu raw packets\n", raw.size());
        diag::log_tagged_fmt("driver_bridge_net",
            "get_captured_packets EXIT max=%u raw=%zu kernel_mode=1",
            max_packets,
            raw.size());
        result.reserve(raw.size());
        for (auto& src : raw) {
            captured_packet_t pkt;
            pkt.timestamp      = src.timestamp;
            pkt.pid            = src.pid;
            pkt.protocol       = src.protocol;
            pkt.direction      = src.direction;
            pkt.payload_size   = src.payload_size;
            pkt.local_port     = src.local_port;
            pkt.remote_port    = src.remote_port;
            pkt.address_family = src.address_family;
            std::memcpy(pkt.local_addr,  src.local_addr,  sizeof(pkt.local_addr));
            std::memcpy(pkt.remote_addr, src.remote_addr, sizeof(pkt.remote_addr));
            pkt.payload = std::move(src.payload);
            result.push_back(std::move(pkt));
        }
        return result;
    }


    std::vector<dns_entry_t> get_dns_queries(uint32_t filter_pid)
    {
        std::vector<dns_entry_t> result;

        bool kernel_mode = false;
        {
            std::lock_guard<std::mutex> lk(g_state_mtx);
            kernel_mode = g_kernel_mode && device && device->is_connected();
        }
        if (!kernel_mode) {
            logf("get_dns_queries: kernel_mode=false, returning empty\n");
            return result;
        }

        auto raw = device->get_dns_queries(filter_pid);
        logf("get_dns_queries: got %zu raw entries (filter_pid=%u)\n", raw.size(), filter_pid);
        result.reserve(raw.size());
        for (auto& src : raw) {
            dns_entry_t entry;
            entry.timestamp     = src.timestamp;
            entry.pid           = src.pid;
            entry.query_type    = src.query_type;
            entry.domain        = std::move(src.domain);
            std::memcpy(entry.resolved_addr, src.resolved_addr, sizeof(entry.resolved_addr));
            entry.response_code = src.response_code;
            entry.ttl           = src.ttl;
            result.push_back(std::move(entry));
        }
        return result;
    }


    bool add_filter_rule(uint32_t action, uint32_t direction, uint32_t protocol, uint32_t pid, uint32_t port, const uint8_t* ip_addr, const uint8_t* ip_mask, uint32_t* out_rule_id)
    {
        bool kernel_mode = false;
        {
            std::lock_guard<std::mutex> lk(g_state_mtx);
            kernel_mode = g_kernel_mode && device && device->is_connected();
        }
        if (!kernel_mode) {
            require_kernel_fail("add_filter_rule");
            return false;
        }

        return device->add_filter_rule(action, direction, protocol, pid, port, ip_addr, ip_mask, out_rule_id);
    }

    bool remove_filter_rule(uint32_t rule_id)
    {
        bool kernel_mode = false;
        {
            std::lock_guard<std::mutex> lk(g_state_mtx);
            kernel_mode = g_kernel_mode && device && device->is_connected();
        }
        if (!kernel_mode) {
            require_kernel_fail("remove_filter_rule");
            return false;
        }

        return device->remove_filter_rule(rule_id);
    }

    bool clear_filter_rules()
    {
        bool kernel_mode = false;
        {
            std::lock_guard<std::mutex> lk(g_state_mtx);
            kernel_mode = g_kernel_mode && device && device->is_connected();
        }
        if (!kernel_mode) {
            require_kernel_fail("clear_filter_rules");
            return false;
        }

        return device->clear_filter_rules();
    }


    bool get_network_stats(network_stats_t& stats)
    {
        bool kernel_mode = false;
        {
            std::lock_guard<std::mutex> lk(g_state_mtx);
            kernel_mode = g_kernel_mode && device && device->is_connected();
        }
        if (!kernel_mode)
            return false;

        voyager::device_t::network_stats ks{};
        if (!device->get_network_stats(ks))
            return false;

        stats.bytes_sent          = ks.bytes_sent;
        stats.bytes_received      = ks.bytes_received;
        stats.packets_sent        = ks.packets_sent;
        stats.packets_received    = ks.packets_received;
        stats.active_connections  = ks.active_connections;
        stats.capture_active      = ks.capture_active;
        stats.total_captured      = ks.total_captured;
        stats.total_dropped       = ks.total_dropped;
        stats.total_dns_logged    = ks.total_dns_logged;
        stats.active_filter_rules = ks.active_filter_rules;
        return true;
    }

    bool bw_monitor_op(uint32_t operation, uint32_t filter_pid, bw_stats_t* out_stats)
    {
        const ULONGLONG t0 = GetTickCount64();
        bool kernel_mode = false;
        {
            std::lock_guard<std::mutex> lk(g_state_mtx);
            kernel_mode = g_kernel_mode && device && device->is_connected();
        }
        if (!kernel_mode) {
            require_kernel_fail("bw_monitor_op");
            return false;
        }

        voyager::device_t::bw_stats raw{};
        bool ok = device->bw_monitor_op(operation, filter_pid, out_stats ? &raw : nullptr);
        DWORD gle = ok ? 0 : GetLastError();
        if (ok && out_stats) {
            out_stats->total_bytes_sent    = raw.total_bytes_sent;
            out_stats->total_bytes_recv    = raw.total_bytes_recv;
            out_stats->total_packets_sent  = raw.total_packets_sent;
            out_stats->total_packets_recv  = raw.total_packets_recv;
            out_stats->bps_in              = raw.bps_in;
            out_stats->bps_out             = raw.bps_out;
            out_stats->active              = raw.active;
        }
        diag::log_tagged_fmt("driver_bridge_net",
            "bw_monitor_op EXIT op=%u filter_pid=%u ok=%d active=%d sent=%llu recv=%llu pkts_sent=%llu pkts_recv=%llu gle=%lu elapsed_ms=%llu",
            operation,
            filter_pid,
            ok ? 1 : 0,
            raw.active ? 1 : 0,
            static_cast<unsigned long long>(raw.total_bytes_sent),
            static_cast<unsigned long long>(raw.total_bytes_recv),
            static_cast<unsigned long long>(raw.total_packets_sent),
            static_cast<unsigned long long>(raw.total_packets_recv),
            static_cast<unsigned long>(gle),
            static_cast<unsigned long long>(GetTickCount64() - t0));
        return ok;
    }

    std::vector<bw_process_info_t> get_bw_per_process(uint32_t filter_pid)
    {
        std::vector<bw_process_info_t> result;

        bool kernel_mode = false;
        {
            std::lock_guard<std::mutex> lk(g_state_mtx);
            kernel_mode = g_kernel_mode && device && device->is_connected();
        }
        if (!kernel_mode)
            return result;

        auto raw = device->get_bw_per_process(filter_pid);
        diag::log_tagged_fmt("driver_bridge_net",
            "get_bw_per_process EXIT filter_pid=%u raw=%zu",
            filter_pid,
            raw.size());
        result.reserve(raw.size());
        for (const auto& src : raw) {
            bw_process_info_t bw;
            bw.pid           = src.pid;
            bw.bytes_sent    = src.bytes_sent;
            bw.bytes_recv    = src.bytes_recv;
            bw.packets_sent  = src.packets_sent;
            bw.packets_recv  = src.packets_recv;
            bw.last_activity = src.last_activity;
            result.push_back(bw);
        }
        return result;
    }


    uint64_t call_function(uint64_t function_address, uint64_t arg1, uint64_t arg2, uint64_t arg3, uint64_t arg4)
    {
        const ULONGLONG call_start = GetTickCount64();
        const remote_call_snapshot_t call_ctx = capture_remote_call_snapshot();
        const uint32_t active_at_entry = attached_pid();
        diag::log_tagged_fmt("driver",
            "call_function_entry label=%s tool=%s diag_id=%s pid=%u active_pid=%u fn=0x%llX arg1=0x%llX arg2=0x%llX arg3=0x%llX arg4=0x%llX timeout_ms=%u deadline_ms=%llu deadline_remaining_ms=%llu cancelled=%d require_deadline=%d context=%d",
            call_ctx.label,
            call_ctx.tool,
            call_ctx.diag_id,
            call_ctx.pid,
            active_at_entry,
            static_cast<unsigned long long>(function_address),
            static_cast<unsigned long long>(arg1),
            static_cast<unsigned long long>(arg2),
            static_cast<unsigned long long>(arg3),
            static_cast<unsigned long long>(arg4),
            call_ctx.timeout_ms,
            static_cast<unsigned long long>(call_ctx.deadline_ms),
            static_cast<unsigned long long>(deadline_remaining_ms(call_ctx.deadline_ms, call_start)),
            call_ctx.cancelled ? 1 : 0,
            call_ctx.require_deadline ? 1 : 0,
            call_ctx.context_active ? 1 : 0);
        if (function_address == 0) {
            SetLastError(ERROR_INVALID_PARAMETER);
            diag::log_tagged_fmt("driver",
                "call_function_reject label=%s tool=%s diag_id=%s pid=%u active_pid=%u fn=0x%llX reason=invalid_function elapsed_ms=%llu gle=%lu status=%s last_error=%s",
                call_ctx.label,
                call_ctx.tool,
                call_ctx.diag_id,
                call_ctx.pid,
                attached_pid(),
                static_cast<unsigned long long>(function_address),
                static_cast<unsigned long long>(GetTickCount64() - call_start),
                static_cast<unsigned long>(GetLastError()),
                status().c_str(),
                last_error().c_str());
            return 0;
        }
        if (call_ctx.require_deadline && call_ctx.deadline_ms == 0) {
            SetLastError(ERROR_TIMEOUT);
            diag::log_tagged_fmt("driver",
                "call_function_reject label=%s tool=%s diag_id=%s pid=%u active_pid=%u fn=0x%llX reason=missing_required_deadline timeout_ms=%u elapsed_ms=%llu gle=%lu status=%s last_error=%s",
                call_ctx.label,
                call_ctx.tool,
                call_ctx.diag_id,
                call_ctx.pid,
                attached_pid(),
                static_cast<unsigned long long>(function_address),
                call_ctx.timeout_ms,
                static_cast<unsigned long long>(GetTickCount64() - call_start),
                static_cast<unsigned long>(GetLastError()),
                status().c_str(),
                last_error().c_str());
            return 0;
        }
        if (call_ctx.cancelled || (call_ctx.deadline_ms != 0 && call_start >= call_ctx.deadline_ms)) {
            SetLastError(call_ctx.cancelled ? ERROR_CANCELLED : ERROR_TIMEOUT);
            diag::log_tagged_fmt("driver",
                "call_function_deadline_preempt label=%s tool=%s diag_id=%s pid=%u active_pid=%u fn=0x%llX cancelled=%d timeout_ms=%u deadline_ms=%llu elapsed_ms=%llu gle=%lu status=%s last_error=%s",
                call_ctx.label,
                call_ctx.tool,
                call_ctx.diag_id,
                call_ctx.pid,
                attached_pid(),
                static_cast<unsigned long long>(function_address),
                call_ctx.cancelled ? 1 : 0,
                call_ctx.timeout_ms,
                static_cast<unsigned long long>(call_ctx.deadline_ms),
                static_cast<unsigned long long>(GetTickCount64() - call_start),
                static_cast<unsigned long>(GetLastError()),
                status().c_str(),
                last_error().c_str());
            return 0;
        }

        bool kernel_mode = false;
        {
            std::lock_guard<std::mutex> lk(g_state_mtx);
            kernel_mode = g_kernel_mode && device && device->is_connected();
        }
        if (!kernel_mode) {
            require_kernel_fail("call_function");
            diag::log_tagged_fmt("driver",
                "call_function_kernel_unavailable label=%s tool=%s diag_id=%s pid=%u active_pid=%u fn=0x%llX timeout_ms=%u deadline_ms=%llu elapsed_ms=%llu gle=%lu status=%s last_error=%s",
                call_ctx.label,
                call_ctx.tool,
                call_ctx.diag_id,
                call_ctx.pid,
                attached_pid(),
                static_cast<unsigned long long>(function_address),
                call_ctx.timeout_ms,
                static_cast<unsigned long long>(call_ctx.deadline_ms),
                static_cast<unsigned long long>(GetTickCount64() - call_start),
                static_cast<unsigned long>(GetLastError()),
                status().c_str(),
                last_error().c_str());
            return 0;
        }

        uint64_t arc_result = 0;
        diag::log_tagged_fmt("driver",
            "call_function_arc_begin label=%s tool=%s diag_id=%s pid=%u active_pid=%u fn=0x%llX cancelled=%d timeout_ms=%u deadline_ms=%llu deadline_remaining_ms=%llu elapsed_ms=%llu",
            call_ctx.label,
            call_ctx.tool,
            call_ctx.diag_id,
            call_ctx.pid,
            attached_pid(),
            static_cast<unsigned long long>(function_address),
            current_remote_call_cancelled() ? 1 : 0,
            call_ctx.timeout_ms,
            static_cast<unsigned long long>(call_ctx.deadline_ms),
            static_cast<unsigned long long>(deadline_remaining_ms(call_ctx.deadline_ms, GetTickCount64())),
            static_cast<unsigned long long>(GetTickCount64() - call_start));
        if (arc_bridge_remote_call(function_address, arg1, arg2, arg3, arg4, arc_result)) {
            const ULONGLONG arc_end = GetTickCount64();
            const remote_call_snapshot_t done_ctx = capture_remote_call_snapshot();
            const bool late_completion = call_ctx.deadline_ms != 0 && arc_end >= call_ctx.deadline_ms;
            const bool cancelled_after = done_ctx.cancelled;
            diag::log_tagged_fmt("driver",
                "call_function_arc_done label=%s tool=%s diag_id=%s pid=%u active_pid=%u fn=0x%llX result=0x%llX ok=1 gle=%lu cancelled=%d timeout_ms=%u deadline_ms=%llu deadline_expired_after=%d late_completion=%d lower_uninterruptible=%d elapsed_ms=%llu status=%s last_error=%s",
                call_ctx.label,
                call_ctx.tool,
                call_ctx.diag_id,
                call_ctx.pid,
                attached_pid(),
                static_cast<unsigned long long>(function_address),
                static_cast<unsigned long long>(arc_result),
                static_cast<unsigned long>(late_completion ? ERROR_TIMEOUT : (cancelled_after ? ERROR_CANCELLED : ERROR_SUCCESS)),
                cancelled_after ? 1 : 0,
                call_ctx.timeout_ms,
                static_cast<unsigned long long>(call_ctx.deadline_ms),
                late_completion ? 1 : 0,
                late_completion ? 1 : 0,
                late_completion ? 1 : 0,
                static_cast<unsigned long long>(arc_end - call_start),
                status().c_str(),
                last_error().c_str());
            if (late_completion || cancelled_after) {
                SetLastError(cancelled_after ? ERROR_CANCELLED : ERROR_TIMEOUT);
                return 0;
            }
            return arc_result;
        }
        const DWORD arc_gle = GetLastError();
        diag::log_tagged_fmt("driver",
            "call_function_arc_done label=%s tool=%s diag_id=%s pid=%u active_pid=%u fn=0x%llX ok=0 gle=%lu cancelled=%d timeout_ms=%u deadline_ms=%llu deadline_remaining_ms=%llu elapsed_ms=%llu status=%s last_error=%s",
            call_ctx.label,
            call_ctx.tool,
            call_ctx.diag_id,
            call_ctx.pid,
            attached_pid(),
            static_cast<unsigned long long>(function_address),
            static_cast<unsigned long>(arc_gle),
            current_remote_call_cancelled() ? 1 : 0,
            call_ctx.timeout_ms,
            static_cast<unsigned long long>(call_ctx.deadline_ms),
            static_cast<unsigned long long>(deadline_remaining_ms(call_ctx.deadline_ms, GetTickCount64())),
            static_cast<unsigned long long>(GetTickCount64() - call_start),
            status().c_str(),
            last_error().c_str());
        if (current_remote_call_cancelled() || (call_ctx.deadline_ms != 0 && GetTickCount64() >= call_ctx.deadline_ms)) {
            const bool cancelled = current_remote_call_cancelled();
            SetLastError(cancelled ? ERROR_CANCELLED : ERROR_TIMEOUT);
            diag::log_tagged_fmt("driver",
                "call_function_deadline_before_device label=%s tool=%s diag_id=%s pid=%u active_pid=%u fn=0x%llX cancelled=%d timeout_ms=%u deadline_ms=%llu elapsed_ms=%llu gle=%lu status=%s last_error=%s",
                call_ctx.label,
                call_ctx.tool,
                call_ctx.diag_id,
                call_ctx.pid,
                attached_pid(),
                static_cast<unsigned long long>(function_address),
                cancelled ? 1 : 0,
                call_ctx.timeout_ms,
                static_cast<unsigned long long>(call_ctx.deadline_ms),
                static_cast<unsigned long long>(GetTickCount64() - call_start),
                static_cast<unsigned long>(GetLastError()),
                status().c_str(),
                last_error().c_str());
            return 0;
        }

        diag::log_tagged_fmt("driver",
            "call_function_device_wait_begin label=%s tool=%s diag_id=%s pid=%u active_pid=%u fn=0x%llX cancelled=%d timeout_ms=%u deadline_ms=%llu deadline_remaining_ms=%llu elapsed_ms=%llu",
            call_ctx.label,
            call_ctx.tool,
            call_ctx.diag_id,
            call_ctx.pid,
            attached_pid(),
            static_cast<unsigned long long>(function_address),
            current_remote_call_cancelled() ? 1 : 0,
            call_ctx.timeout_ms,
            static_cast<unsigned long long>(call_ctx.deadline_ms),
            static_cast<unsigned long long>(deadline_remaining_ms(call_ctx.deadline_ms, GetTickCount64())),
            static_cast<unsigned long long>(GetTickCount64() - call_start));
        const uint64_t result = device->call_function(function_address, arg1, arg2, arg3, arg4);
        const DWORD gle = result != 0 ? ERROR_SUCCESS : GetLastError();
        const ULONGLONG call_end = GetTickCount64();
        const remote_call_snapshot_t done_ctx = capture_remote_call_snapshot();
        const bool late_completion = call_ctx.deadline_ms != 0 && call_end >= call_ctx.deadline_ms;
        const bool cancelled_after = done_ctx.cancelled;
        diag::log_tagged_fmt("driver",
            "call_function_device_wait_done label=%s tool=%s diag_id=%s pid=%u active_pid=%u fn=0x%llX result=0x%llX ok=%d gle=%lu cancelled=%d timeout_ms=%u deadline_ms=%llu deadline_expired_after=%d late_completion=%d lower_uninterruptible=%d elapsed_ms=%llu status=%s last_error=%s",
            call_ctx.label,
            call_ctx.tool,
            call_ctx.diag_id,
            call_ctx.pid,
            attached_pid(),
            static_cast<unsigned long long>(function_address),
            static_cast<unsigned long long>(result),
            result != 0 ? 1 : 0,
            static_cast<unsigned long>(late_completion ? ERROR_TIMEOUT : (cancelled_after ? ERROR_CANCELLED : gle)),
            cancelled_after ? 1 : 0,
            call_ctx.timeout_ms,
            static_cast<unsigned long long>(call_ctx.deadline_ms),
            late_completion ? 1 : 0,
            late_completion ? 1 : 0,
            late_completion ? 1 : 0,
            static_cast<unsigned long long>(call_end - call_start),
            status().c_str(),
            last_error().c_str());
        if (late_completion || cancelled_after) {
            SetLastError(cancelled_after ? ERROR_CANCELLED : ERROR_TIMEOUT);
            return 0;
        }
        if (result == 0)
            SetLastError(gle);
        return result;
    }

    uint64_t find_gadget(const char* pattern, size_t pattern_size)
    {
        if (!pattern || pattern_size == 0)
            return 0;

        bool kernel_mode = false;
        {
            std::lock_guard<std::mutex> lk(g_state_mtx);
            kernel_mode = g_kernel_mode && device && device->is_connected();
        }
        if (!kernel_mode) {
            require_kernel_fail("find_gadget");
            return 0;
        }

        return device->find_gadget(pattern, pattern_size);
    }

    bool set_hardware_breakpoint(uint32_t tid, int index, uint64_t address, int type, int size)
    {
        bool kernel_mode = false;
        bool kernel_attached = false;
        {
            std::lock_guard<std::mutex> lk(g_state_mtx);
            kernel_mode = g_kernel_mode && device && device->is_connected();
            kernel_attached = g_kernel_attached;
        }
        if (!kernel_mode || !kernel_attached) {
            diag::log_tagged_fmt("driver",
                "set_hardware_breakpoint_kernel_required tid=%u index=%d addr=0x%llX type=%d size=%d kernel=%d attached=%d bypass=%d",
                tid,
                index,
                static_cast<unsigned long long>(address),
                type,
                size,
                kernel_mode ? 1 : 0,
                kernel_attached ? 1 : 0,
                tctx_kernel_bypass_active() ? 1 : 0);
            require_kernel_fail("set_hardware_breakpoint");
            return false;
        }

        const uint64_t kernel_t0 = static_cast<uint64_t>(GetTickCount64());
        bool ok = device->set_hardware_breakpoint(tid, index, address, type, size);
        if (!ok) {
            DWORD gle = GetLastError();
            const uint64_t elapsed_ms = static_cast<uint64_t>(GetTickCount64()) - kernel_t0;
            const uint32_t pid = attached_pid();
            note_tctx_kernel_failure("set_hardware_breakpoint", pid, tid, gle, elapsed_ms);
            diag::log_tagged_fmt("driver",
                "set_hardware_breakpoint_kernel_failed pid=%u tid=%u index=%d addr=0x%llX type=%d size=%d gle=%lu elapsed_ms=%llu fail_closed=1",
                pid,
                tid,
                index,
                static_cast<unsigned long long>(address),
                type,
                size,
                gle,
                static_cast<unsigned long long>(elapsed_ms));
            SetLastError(gle);
        } else {
            note_tctx_kernel_success();
        }
        return ok;
    }

    bool clear_hardware_breakpoint(uint32_t tid, int index)
    {
        bool kernel_mode = false;
        bool kernel_attached = false;
        {
            std::lock_guard<std::mutex> lk(g_state_mtx);
            kernel_mode = g_kernel_mode && device && device->is_connected();
            kernel_attached = g_kernel_attached;
        }
        if (!kernel_mode || !kernel_attached) {
            diag::log_tagged_fmt("driver",
                "clear_hardware_breakpoint_kernel_required tid=%u index=%d kernel=%d attached=%d bypass=%d",
                tid,
                index,
                kernel_mode ? 1 : 0,
                kernel_attached ? 1 : 0,
                tctx_kernel_bypass_active() ? 1 : 0);
            require_kernel_fail("clear_hardware_breakpoint");
            return false;
        }

        const uint64_t kernel_t0 = static_cast<uint64_t>(GetTickCount64());
        bool ok = device->clear_hardware_breakpoint(tid, index);
        if (!ok) {
            DWORD gle = GetLastError();
            const uint64_t elapsed_ms = static_cast<uint64_t>(GetTickCount64()) - kernel_t0;
            const uint32_t pid = attached_pid();
            note_tctx_kernel_failure("clear_hardware_breakpoint", pid, tid, gle, elapsed_ms);
            diag::log_tagged_fmt("driver",
                "clear_hardware_breakpoint_kernel_failed pid=%u tid=%u index=%d gle=%lu elapsed_ms=%llu fail_closed=1",
                pid,
                tid,
                index,
                gle,
                static_cast<unsigned long long>(elapsed_ms));
            SetLastError(gle);
        } else {
            note_tctx_kernel_success();
        }
        return ok;
    }

    bool spoof_debug_flags(uint32_t* result_flags)
    {
        bool kernel_mode = false;
        {
            std::lock_guard<std::mutex> lk(g_state_mtx);
            kernel_mode = g_kernel_mode && device && device->is_connected();
        }
        if (!kernel_mode) {
            require_kernel_fail("spoof_debug_flags");
            return false;
        }

        return device->spoof_debug_flags(result_flags);
    }

    bool refresh_heartbeat()
    {
        bool kernel_mode = false;
        {
            std::lock_guard<std::mutex> lk(g_state_mtx);
            kernel_mode = g_kernel_mode && device && device->is_connected();
        }
        if (!kernel_mode)
            return false;

        return device->refresh_heartbeat();
    }

    static dynamic_ioctl_state_t sentinel_dynamic_ioctl_preflight_state()
    {
        dynamic_ioctl_state_t out{};
        std::lock_guard<std::mutex> lk(g_state_mtx);
        out.loaded = g_initialized;
        out.kernel = g_kernel_mode;
        out.connected = device && device->is_connected();
        if (device)
        {
            device->sync_dynamic_security_state();
            out.instance_server_seed = device->has_server_seed() ? 1u : 0u;
            out.instance_ioctl_seed = device->has_server_ioctl_seed() ? 1u : 0u;
            out.global_server_seed = dynamic_key::g_server_seed != 0 ? 1u : 0u;
            out.global_ioctl_seed = ioctl_codes::g_server_ioctl_seed != 0 ? 1u : 0u;
            out.ioctl_seed_hash = device->get_server_ioctl_seed_hash();
            out.heartbeat_ioctl_seed_hash = device->get_last_heartbeat_ioctl_seed_hash();
        }
        out.ready = out.connected && out.kernel &&
            out.instance_server_seed != 0 &&
            out.instance_ioctl_seed != 0 &&
            out.global_server_seed != 0 &&
            out.global_ioctl_seed != 0;
        return out;
    }

    static bool sentinel_dynamic_ioctl_ready_preflight(const char* op, ULONGLONG start, dynamic_ioctl_state_t* out_state = nullptr)
    {
        dynamic_ioctl_state_t dyn = sentinel_dynamic_ioctl_preflight_state();
        if (out_state)
            *out_state = dyn;
        if (dyn.ready)
            return true;
        SetLastError(ERROR_NOT_READY);
        diag::log_tagged_fmt("driver",
            "preauth_skipped_dynamic_ioctl_not_ready phase=driver_bridge_sentinel op=%s loaded=%d kernel=%d connected=%d inst_seed=%u/%u global_seed=%u/%u ioctl_seed_hash=0x%08X hb_ioctl_seed_hash=0x%08X elapsed_ms=%llu",
            op && *op ? op : "unknown",
            dyn.loaded ? 1 : 0,
            dyn.kernel ? 1 : 0,
            dyn.connected ? 1 : 0,
            dyn.instance_server_seed,
            dyn.instance_ioctl_seed,
            dyn.global_server_seed,
            dyn.global_ioctl_seed,
            dyn.ioctl_seed_hash,
            dyn.heartbeat_ioctl_seed_hash,
            static_cast<unsigned long long>(GetTickCount64() - start));
        return false;
    }

    bool sentinel_bridge_ready()
    {
        const ULONGLONG start = GetTickCount64();
        bool kernel_mode = false;
        bool initialized = false;
        bool kernel_flag = false;
        bool connected = false;
        {
            std::lock_guard<std::mutex> lk(g_state_mtx);
            initialized = g_initialized;
            kernel_flag = g_kernel_mode;
            connected = device && device->is_connected();
            kernel_mode = kernel_flag && connected;
        }
        if (!kernel_mode) {
            diag::log_tagged_fmt("driver",
                "sentinel_bridge_ready_preflight_failed initialized=%d kernel=%d connected=%d elapsed_ms=%llu",
                initialized ? 1 : 0,
                kernel_flag ? 1 : 0,
                connected ? 1 : 0,
                static_cast<unsigned long long>(GetTickCount64() - start));
            return false;
        }

        dynamic_ioctl_state_t dyn{};
        if (!sentinel_dynamic_ioctl_ready_preflight("sentinel_bridge_ready", start, &dyn)) {
            diag::log_tagged_fmt("driver",
                "sentinel_bridge_ready_result heartbeat_ok=0 heartbeat_gle=%lu heartbeat_ms=0 ready=0 ready_gle=%lu ready_ms=0 total_ms=%llu dyn_ready=%d",
                static_cast<unsigned long>(ERROR_NOT_READY),
                static_cast<unsigned long>(ERROR_NOT_READY),
                static_cast<unsigned long long>(GetTickCount64() - start),
                dyn.ready ? 1 : 0);
            return false;
        }

        SetLastError(ERROR_SUCCESS);
        const ULONGLONG hb_start = GetTickCount64();
        bool hb_ok = device->refresh_heartbeat();
        DWORD hb_gle = hb_ok ? ERROR_SUCCESS : GetLastError();
        const ULONGLONG ready_start = GetTickCount64();
        bool ready = device->sentinel_bridge_ready();
        DWORD ready_gle = ready ? ERROR_SUCCESS : GetLastError();
        diag::log_tagged_fmt("driver",
            "sentinel_bridge_ready_result heartbeat_ok=%d heartbeat_gle=%lu heartbeat_ms=%llu ready=%d ready_gle=%lu ready_ms=%llu total_ms=%llu",
            hb_ok ? 1 : 0,
            static_cast<unsigned long>(hb_gle),
            static_cast<unsigned long long>(ready_start - hb_start),
            ready ? 1 : 0,
            static_cast<unsigned long>(ready_gle),
            static_cast<unsigned long long>(GetTickCount64() - ready_start),
            static_cast<unsigned long long>(GetTickCount64() - start));
        SetLastError(ready ? ERROR_SUCCESS : ready_gle);
        return ready;
    }

    uint64_t sentinel_ready_since_tsc()
    {
        const ULONGLONG start = GetTickCount64();
        bool kernel_mode = false;
        {
            std::lock_guard<std::mutex> lk(g_state_mtx);
            kernel_mode = g_kernel_mode && device && device->is_connected();
        }
        if (!kernel_mode)
            return 0;

        if (!sentinel_dynamic_ioctl_ready_preflight("sentinel_ready_since_tsc", start))
            return 0;

        if (!device->refresh_heartbeat()) {
            DWORD gle = GetLastError();
            diag::log_tagged_fmt("driver",
                "sentinel_ready_since_tsc_heartbeat_failed gle=%lu elapsed_ms=%llu",
                static_cast<unsigned long>(gle),
                static_cast<unsigned long long>(GetTickCount64() - start));
            SetLastError(gle);
            return 0;
        }
        return device->sentinel_ready_since_tsc();
    }

    dynamic_ioctl_state_t dynamic_ioctl_state()
    {
        dynamic_ioctl_state_t out{};
        std::lock_guard<std::mutex> lk(g_state_mtx);
        out.loaded = g_initialized;
        out.kernel = g_kernel_mode;
        out.connected = device && device->is_connected();
        if (device)
        {
            device->sync_dynamic_security_state();
            out.instance_server_seed = device->has_server_seed() ? 1u : 0u;
            out.instance_ioctl_seed = device->has_server_ioctl_seed() ? 1u : 0u;
            out.global_server_seed = dynamic_key::g_server_seed != 0 ? 1u : 0u;
            out.global_ioctl_seed = ioctl_codes::g_server_ioctl_seed != 0 ? 1u : 0u;
            out.ioctl_seed_hash = device->get_server_ioctl_seed_hash();
            out.heartbeat_ioctl_seed_hash = device->get_last_heartbeat_ioctl_seed_hash();
        }
        out.ready = out.connected && out.kernel &&
            out.instance_server_seed != 0 &&
            out.instance_ioctl_seed != 0 &&
            out.global_server_seed != 0 &&
            out.global_ioctl_seed != 0;
        return out;
    }

    bool dynamic_ioctls_ready()
    {
        return dynamic_ioctl_state().ready;
    }

    bool register_dll_protection(uint64_t module_base, uint64_t text_va, uint32_t text_size,
                                 uint64_t expected_hash, uint32_t check_interval_ms)
    {
        const uint64_t started = static_cast<uint64_t>(GetTickCount64());
        bool kernel_mode = false;
        {
            std::lock_guard<std::mutex> lk(g_state_mtx);
            kernel_mode = g_kernel_mode && device && device->is_connected();
        }
        driver_critical_fmt(
            "register_dll_protection_pre kernel=%d pid=%lu tid=%lu module=0x%llX text=0x%llX size=0x%X hash=0x%016llX interval=%u tick=%llu",
            kernel_mode ? 1 : 0,
            GetCurrentProcessId(),
            GetCurrentThreadId(),
            static_cast<unsigned long long>(module_base),
            static_cast<unsigned long long>(text_va),
            text_size,
            static_cast<unsigned long long>(expected_hash),
            check_interval_ms,
            static_cast<unsigned long long>(started));
        if (!kernel_mode) {
            require_kernel_fail("register_dll_protection");
            driver_critical_fmt("register_dll_protection_post ok=0 err=%lu reason=no_kernel elapsed_ms=%llu",
                static_cast<unsigned long>(GetLastError()),
                static_cast<unsigned long long>(static_cast<uint64_t>(GetTickCount64()) - started));
            return false;
        }

        SetLastError(ERROR_SUCCESS);
        bool ok = device->register_dll_protection(module_base, text_va, text_size,
                                                  expected_hash, check_interval_ms);
        DWORD err = ok ? ERROR_SUCCESS : GetLastError();
        driver_critical_fmt("register_dll_protection_post ok=%d err=%lu elapsed_ms=%llu",
            ok ? 1 : 0,
            static_cast<unsigned long>(err),
            static_cast<unsigned long long>(static_cast<uint64_t>(GetTickCount64()) - started));
        return ok;
    }

    bool register_self_dll_protection(uint64_t module_base, uint64_t text_va, uint32_t text_size,
                                      uint64_t expected_hash, uint32_t check_interval_ms)
    {
        const uint32_t self_pid = static_cast<uint32_t>(GetCurrentProcessId());
        const uint64_t started = static_cast<uint64_t>(GetTickCount64());
        std::lock_guard<std::mutex> lk(g_state_mtx);
        bool kernel_mode = g_kernel_mode && device && device->is_connected();
        if (!kernel_mode) {
            require_kernel_fail("register_self_dll_protection");
            driver_critical_fmt("register_self_dll_protection_post ok=0 err=%lu reason=no_kernel elapsed_ms=%llu",
                static_cast<unsigned long>(GetLastError()),
                static_cast<unsigned long long>(static_cast<uint64_t>(GetTickCount64()) - started));
            return false;
        }

        if (anti_tamper::state::get().violation_latched.load(std::memory_order_acquire)) {
            SetLastError(ERROR_ACCESS_DENIED);
            driver_critical_fmt("register_self_dll_protection_post ok=0 err=%lu reason=violation_latched elapsed_ms=%llu",
                static_cast<unsigned long>(GetLastError()),
                static_cast<unsigned long long>(static_cast<uint64_t>(GetTickCount64()) - started));
            return false;
        }

        const uint32_t saved_pid = device->get_process_id();
        const uint64_t saved_base = device->get_base_address();
        const uint64_t saved_dtb = device->get_dtb();

        device->set_process_id(self_pid);
        device->solve_dtb();
        uint64_t self_dtb = device->get_dtb();
        driver_critical_fmt(
            "register_self_dll_protection_dtb pid=%u dtb=0x%llX saved_pid=%u saved_dtb=0x%llX elapsed_ms=%llu",
            self_pid,
            static_cast<unsigned long long>(self_dtb),
            saved_pid,
            static_cast<unsigned long long>(saved_dtb),
            static_cast<unsigned long long>(static_cast<uint64_t>(GetTickCount64()) - started));

        SetLastError(ERROR_SUCCESS);
        bool ok = device->register_dll_protection_for_pid(self_pid,
                                                          module_base, text_va, text_size,
                                                          expected_hash, check_interval_ms);
        DWORD err = ok ? ERROR_SUCCESS : GetLastError();

        device->set_process_id(saved_pid);
        device->set_base_address(saved_base);
        device->set_dtb(saved_dtb);

        SetLastError(err);
        driver_critical_fmt("register_self_dll_protection_post ok=%d err=%lu dtb=0x%llX elapsed_ms=%llu",
            ok ? 1 : 0,
            static_cast<unsigned long>(err),
            static_cast<unsigned long long>(self_dtb),
            static_cast<unsigned long long>(static_cast<uint64_t>(GetTickCount64()) - started));
        return ok;
    }

    bool query_dll_protection(dll_protect_status_t& out)
    {
        bool kernel_mode = false;
        {
            std::lock_guard<std::mutex> lk(g_state_mtx);
            kernel_mode = g_kernel_mode && device && device->is_connected();
        }
        if (!kernel_mode) {
            require_kernel_fail("query_dll_protection");
            return false;
        }

        voyager::device_t::dll_protect_status raw{};
        if (!device->query_dll_protection(raw))
            return false;

        out.status         = raw.status;
        out.current_hash   = raw.current_hash;
        out.expected_hash  = raw.expected_hash;
        out.last_check_tsc = raw.last_check_tsc;
        return true;
    }

    bool unregister_dll_protection()
    {
        bool kernel_mode = false;
        {
            std::lock_guard<std::mutex> lk(g_state_mtx);
            kernel_mode = g_kernel_mode && device && device->is_connected();
        }
        if (!kernel_mode) {
            require_kernel_fail("unregister_dll_protection");
            return false;
        }

        return device->unregister_dll_protection();
    }

    bool unregister_self_dll_protection(uint64_t module_base)
    {
        bool kernel_mode = false;
        {
            std::lock_guard<std::mutex> lk(g_state_mtx);
            kernel_mode = g_kernel_mode && device && device->is_connected();
        }
        if (!kernel_mode) {
            require_kernel_fail("unregister_self_dll_protection");
            return false;
        }

        return device->unregister_dll_protection_for_pid(static_cast<uint32_t>(GetCurrentProcessId()), module_base);
    }

    bool trigger_kernel_bsod(uint32_t reason_code, uint64_t evidence_hash)
    {
        if (destructive_driver_action_suppressed()) {
            uint64_t full_test_suppression_remaining = 0;
            anti_tamper::state::full_test_suppression_active(&full_test_suppression_remaining);
            diag::log_tagged_critical_fmt("driver",
                "trigger_kernel_bsod_SUPPRESSED reason=0x%08X evidence=0x%016llX full_test_latch=%d post_full_test_ms=%llu env_full_test=%d env_disable=%d",
                reason_code,
                static_cast<unsigned long long>(evidence_hash),
                anti_tamper::state::get().full_test_running.load(std::memory_order_acquire) ? 1 : 0,
                static_cast<unsigned long long>(full_test_suppression_remaining),
                env_flag_enabled("AIDA_FULL_TEST_RUNNING") ? 1 : 0,
                env_flag_enabled("AIDA_DISABLE_DESTRUCTIVE_ENFORCEMENT") ? 1 : 0);
            return false;
        }

        bool kernel_mode = false;
        {
            std::lock_guard<std::mutex> lk(g_state_mtx);
            kernel_mode = g_kernel_mode && device && device->is_connected();
        }
        if (!kernel_mode)
            return false;


        return device->trigger_kernel_bsod(reason_code, evidence_hash);
    }

    bool latch_targeting_from_usermode(uint32_t reason)
    {
        bool kernel_mode = false;
        {
            std::lock_guard<std::mutex> lk(g_state_mtx);
            kernel_mode = g_kernel_mode && device && device->is_connected();
        }
        if (!kernel_mode)
            return false;

        return device->latch_targeting_from_usermode(reason);
    }

    bool tier_a_driver_present_query(bool* out_present, uint32_t* out_mask, uint64_t* out_first_base)
    {
        const uint64_t started = static_cast<uint64_t>(GetTickCount64());
        if (out_present) *out_present = false;
        if (out_mask) *out_mask = 0;
        if (out_first_base) *out_first_base = 0;

        bool kernel_mode = false;
        {
            std::lock_guard<std::mutex> lk(g_state_mtx);
            kernel_mode = g_kernel_mode && device && device->is_connected();
        }
        driver_critical_fmt("tier_a_driver_present_query_pre kernel=%d pid=%lu tid=%lu tick=%llu",
            kernel_mode ? 1 : 0,
            GetCurrentProcessId(),
            GetCurrentThreadId(),
            static_cast<unsigned long long>(started));
        if (!kernel_mode) {
            driver_critical_fmt("tier_a_driver_present_query_post ok=0 err=%lu reason=no_kernel elapsed_ms=%llu",
                static_cast<unsigned long>(GetLastError()),
                static_cast<unsigned long long>(static_cast<uint64_t>(GetTickCount64()) - started));
            return false;
        }

        bool present = false;
        uint32_t mask = 0;
        uint64_t base = 0;
        SetLastError(ERROR_SUCCESS);
        bool ok = device->tier_a_driver_present_query(present, &mask, &base);
        DWORD err = ok ? ERROR_SUCCESS : GetLastError();
        driver_critical_fmt("tier_a_driver_present_query_post ok=%d err=%lu present=%d mask=0x%08X first_base=0x%llX elapsed_ms=%llu",
            ok ? 1 : 0,
            static_cast<unsigned long>(err),
            present ? 1 : 0,
            mask,
            static_cast<unsigned long long>(base),
            static_cast<unsigned long long>(static_cast<uint64_t>(GetTickCount64()) - started));
        if (!ok)
            return false;

        if (out_present) *out_present = present;
        if (out_mask) *out_mask = mask;
        if (out_first_base) *out_first_base = base;
        return true;
    }

    bool tier_a_driver_present()
    {
        bool present = false;
        if (!tier_a_driver_present_query(&present, nullptr, nullptr))
            return false;
        return present;
    }

    bool canary_register(void* va, size_t size)
    {
        const uint64_t started = static_cast<uint64_t>(GetTickCount64());
        bool kernel_mode = false;
        {
            std::lock_guard<std::mutex> lk(g_state_mtx);
            kernel_mode = g_kernel_mode && device && device->is_connected();
        }
        driver_critical_fmt("canary_register_bridge_pre kernel=%d pid=%lu tid=%lu va=0x%llX size=0x%llX tick=%llu",
            kernel_mode ? 1 : 0,
            GetCurrentProcessId(),
            GetCurrentThreadId(),
            static_cast<unsigned long long>(reinterpret_cast<uintptr_t>(va)),
            static_cast<unsigned long long>(size),
            static_cast<unsigned long long>(started));
        if (!kernel_mode) {
            diag::log_tagged_fmt("driver", "canary_register_skip kernel_mode=0 va=%p size=%llu",
                va,
                static_cast<unsigned long long>(size));
            driver_critical_fmt("canary_register_bridge_post ok=0 err=%lu reason=no_kernel elapsed_ms=%llu",
                static_cast<unsigned long>(GetLastError()),
                static_cast<unsigned long long>(static_cast<uint64_t>(GetTickCount64()) - started));
            return false;
        }

        diag::log_tagged_fmt("driver", "canary_register_pre va=%p size=%llu",
            va,
            static_cast<unsigned long long>(size));
        SetLastError(ERROR_SUCCESS);
        bool registered = device->canary_register(reinterpret_cast<uint64_t>(va),
                                                  static_cast<uint64_t>(size));
        DWORD err = registered ? ERROR_SUCCESS : GetLastError();
        diag::log_tagged_fmt("driver", "canary_register_post va=%p size=%llu registered=%d",
            va,
            static_cast<unsigned long long>(size),
            registered ? 1 : 0);
        driver_critical_fmt("canary_register_bridge_post ok=%d err=%lu elapsed_ms=%llu",
            registered ? 1 : 0,
            static_cast<unsigned long>(err),
            static_cast<unsigned long long>(static_cast<uint64_t>(GetTickCount64()) - started));
        return registered;
    }

    bool re_confirmed_usermode_bsod(const re_evidence_blob_t& evidence)
    {
        bool kernel_mode = false;
        {
            std::lock_guard<std::mutex> lk(g_state_mtx);
            kernel_mode = g_kernel_mode && device && device->is_connected();
        }
        if (!kernel_mode) return false;

        voyager::detail::re_evidence_blob_t raw{};
        raw.magic = evidence.magic;
        raw.version = evidence.version;
        raw.signal_family = evidence.signal_family;
        raw.signal_id = evidence.signal_id;
        raw.score = evidence.score;
        raw.pid = evidence.pid;
        raw.reserved0 = evidence.reserved0;
        raw.caller_image_hash = evidence.caller_image_hash;
        raw.signals_bitmap_hash = evidence.signals_bitmap_hash;
        raw.timestamp = evidence.timestamp;

        return device->re_confirmed_usermode_bsod(raw);
    }

    bool kernel_anti_debug_query(anti_debug_result_t& out)
    {
        const uint64_t started = static_cast<uint64_t>(GetTickCount64());
        bool kernel_mode = false;
        {
            std::lock_guard<std::mutex> lk(g_state_mtx);
            kernel_mode = g_kernel_mode && device && device->is_connected();
        }
        driver_critical_fmt("kernel_anti_debug_query_pre kernel=%d pid=%lu tid=%lu tick=%llu",
            kernel_mode ? 1 : 0,
            GetCurrentProcessId(),
            GetCurrentThreadId(),
            static_cast<unsigned long long>(started));
        if (!kernel_mode) {
            driver_critical_fmt("kernel_anti_debug_query_post ok=0 err=%lu reason=no_kernel elapsed_ms=%llu",
                static_cast<unsigned long>(GetLastError()),
                static_cast<unsigned long long>(static_cast<uint64_t>(GetTickCount64()) - started));
            return false;
        }

        voyager::device_t::anti_debug_result raw{};
        SetLastError(ERROR_SUCCESS);
        if (!device->kernel_anti_debug_query(raw))
        {
            DWORD err = GetLastError();
            driver_critical_fmt("kernel_anti_debug_query_post ok=0 err=%lu elapsed_ms=%llu",
                static_cast<unsigned long>(err),
                static_cast<unsigned long long>(static_cast<uint64_t>(GetTickCount64()) - started));
            return false;
        }

        out.result_flags = raw.result_flags;
        out.detected_debugger_pid = raw.detected_debugger_pid;
        out.dr_clear_count = raw.dr_clear_count;
        driver_critical_fmt("kernel_anti_debug_query_post ok=1 flags=0x%08X debugger_pid=%llu dr_clear=%llu elapsed_ms=%llu",
            out.result_flags,
            static_cast<unsigned long long>(out.detected_debugger_pid),
            static_cast<unsigned long long>(out.dr_clear_count),
            static_cast<unsigned long long>(static_cast<uint64_t>(GetTickCount64()) - started));
        return true;
    }

    bool kernel_anti_debug_clear_dr(uint64_t* out_clear_count)
    {
        const uint64_t started = static_cast<uint64_t>(GetTickCount64());
        bool kernel_mode = false;
        {
            std::lock_guard<std::mutex> lk(g_state_mtx);
            kernel_mode = g_kernel_mode && device && device->is_connected();
        }
        driver_critical_fmt("kernel_anti_debug_clear_dr_pre kernel=%d pid=%lu tid=%lu out=%d tick=%llu",
            kernel_mode ? 1 : 0,
            GetCurrentProcessId(),
            GetCurrentThreadId(),
            out_clear_count ? 1 : 0,
            static_cast<unsigned long long>(started));
        if (!kernel_mode) {
            driver_critical_fmt("kernel_anti_debug_clear_dr_post ok=0 err=%lu reason=no_kernel elapsed_ms=%llu",
                static_cast<unsigned long>(GetLastError()),
                static_cast<unsigned long long>(static_cast<uint64_t>(GetTickCount64()) - started));
            return false;
        }

        SetLastError(ERROR_SUCCESS);
        bool ok = device->kernel_anti_debug_clear_dr(out_clear_count);
        DWORD err = ok ? ERROR_SUCCESS : GetLastError();
        driver_critical_fmt("kernel_anti_debug_clear_dr_post ok=%d err=%lu clear_count=%llu elapsed_ms=%llu",
            ok ? 1 : 0,
            static_cast<unsigned long>(err),
            static_cast<unsigned long long>(out_clear_count ? *out_clear_count : 0),
            static_cast<unsigned long long>(static_cast<uint64_t>(GetTickCount64()) - started));
        if (!ok) SetLastError(err);
        return ok;
    }

    bool kernel_anti_debug_clear_process_dr(uint32_t pid, uint64_t* out_clear_count)
    {
        const uint64_t started = static_cast<uint64_t>(GetTickCount64());
        driver_critical_fmt("kernel_anti_debug_clear_process_dr_pre pid=%u caller_pid=%lu tid=%lu out=%d tick=%llu",
            pid,
            GetCurrentProcessId(),
            GetCurrentThreadId(),
            out_clear_count ? 1 : 0,
            static_cast<unsigned long long>(started));

        bool kernel_mode = false;
        {
            std::lock_guard<std::mutex> lk(g_state_mtx);
            kernel_mode = g_kernel_mode && device && device->is_connected();
        }
        if (!kernel_mode) {
            driver_critical_fmt("kernel_anti_debug_clear_process_dr_post ok=0 err=%lu reason=no_kernel elapsed_ms=%llu",
                static_cast<unsigned long>(GetLastError()),
                static_cast<unsigned long long>(static_cast<uint64_t>(GetTickCount64()) - started));
            return false;
        }

        SetLastError(ERROR_SUCCESS);
        bool ok = device->kernel_anti_debug_clear_process_dr(pid, out_clear_count);
        DWORD err = ok ? ERROR_SUCCESS : GetLastError();
        driver_critical_fmt("kernel_anti_debug_clear_process_dr_post ok=%d err=%lu clear_count=%llu elapsed_ms=%llu",
            ok ? 1 : 0,
            static_cast<unsigned long>(err),
            static_cast<unsigned long long>(out_clear_count ? *out_clear_count : 0),
            static_cast<unsigned long long>(static_cast<uint64_t>(GetTickCount64()) - started));
        if (!ok) SetLastError(err);
        return ok;
    }

    bool kernel_anti_debug_scan_debuggers(uint64_t* out_debugger_pid)
    {
        const uint64_t started = static_cast<uint64_t>(GetTickCount64());
        bool kernel_mode = false;
        {
            std::lock_guard<std::mutex> lk(g_state_mtx);
            kernel_mode = g_kernel_mode && device && device->is_connected();
        }
        driver_critical_fmt("kernel_anti_debug_scan_debuggers_pre kernel=%d pid=%lu tid=%lu out=%d tick=%llu",
            kernel_mode ? 1 : 0,
            GetCurrentProcessId(),
            GetCurrentThreadId(),
            out_debugger_pid ? 1 : 0,
            static_cast<unsigned long long>(started));
        if (!kernel_mode) {
            driver_critical_fmt("kernel_anti_debug_scan_debuggers_post ok=0 err=%lu reason=no_kernel elapsed_ms=%llu",
                static_cast<unsigned long>(GetLastError()),
                static_cast<unsigned long long>(static_cast<uint64_t>(GetTickCount64()) - started));
            return false;
        }

        SetLastError(ERROR_SUCCESS);
        bool ok = device->kernel_anti_debug_scan_debuggers(out_debugger_pid);
        DWORD err = ok ? ERROR_SUCCESS : GetLastError();
        if (!ok)
        {
            diag::log_tagged_fmt("driver",
                "adbg_scan_debuggers_failed err=%lu",
                static_cast<unsigned long>(err));
            SetLastError(err);
        }
        driver_critical_fmt("kernel_anti_debug_scan_debuggers_post ok=%d err=%lu debugger_pid=%llu elapsed_ms=%llu",
            ok ? 1 : 0,
            static_cast<unsigned long>(err),
            static_cast<unsigned long long>(out_debugger_pid ? *out_debugger_pid : 0),
            static_cast<unsigned long long>(static_cast<uint64_t>(GetTickCount64()) - started));
        if (!ok) SetLastError(err);
        return ok;
    }

    bool kernel_anti_debug_hide_thread(uint32_t pid, uint32_t tid)
    {
        const uint64_t started = static_cast<uint64_t>(GetTickCount64());
        bool kernel_mode = false;
        {
            std::lock_guard<std::mutex> lk(g_state_mtx);
            kernel_mode = g_kernel_mode && device && device->is_connected();
        }
        driver_critical_fmt("kernel_anti_debug_hide_thread_pre kernel=%d pid=%u tid_target=%u caller_pid=%lu caller_tid=%lu tick=%llu",
            kernel_mode ? 1 : 0,
            pid,
            tid,
            GetCurrentProcessId(),
            GetCurrentThreadId(),
            static_cast<unsigned long long>(started));
        if (!kernel_mode) {
            driver_critical_fmt("kernel_anti_debug_hide_thread_post ok=0 err=%lu reason=no_kernel elapsed_ms=%llu",
                static_cast<unsigned long>(GetLastError()),
                static_cast<unsigned long long>(static_cast<uint64_t>(GetTickCount64()) - started));
            return false;
        }

        SetLastError(ERROR_SUCCESS);
        bool ok = device->kernel_anti_debug_hide_thread(pid, tid);
        DWORD err = ok ? ERROR_SUCCESS : GetLastError();
        driver_critical_fmt("kernel_anti_debug_hide_thread_post ok=%d err=%lu elapsed_ms=%llu",
            ok ? 1 : 0,
            static_cast<unsigned long>(err),
            static_cast<unsigned long long>(static_cast<uint64_t>(GetTickCount64()) - started));
        return ok;
    }

    bool kernel_anti_debug_hide_all_threads(uint32_t pid)
    {
        const uint64_t started = static_cast<uint64_t>(GetTickCount64());
        driver_critical_fmt("kernel_anti_debug_hide_all_threads_pre pid=%u caller_pid=%lu caller_tid=%lu tick=%llu",
            pid,
            GetCurrentProcessId(),
            GetCurrentThreadId(),
            static_cast<unsigned long long>(started));

        bool kernel_mode = false;
        {
            std::lock_guard<std::mutex> lk(g_state_mtx);
            kernel_mode = g_kernel_mode && device && device->is_connected();
        }
        if (!kernel_mode) {
            driver_critical_fmt("kernel_anti_debug_hide_all_threads_post ok=0 err=%lu reason=no_kernel elapsed_ms=%llu",
                static_cast<unsigned long>(GetLastError()),
                static_cast<unsigned long long>(static_cast<uint64_t>(GetTickCount64()) - started));
            return false;
        }

        SetLastError(ERROR_SUCCESS);
        bool ok = device->kernel_anti_debug_hide_all_threads(pid);
        DWORD err = ok ? ERROR_SUCCESS : GetLastError();
        driver_critical_fmt("kernel_anti_debug_hide_all_threads_post ok=%d err=%lu elapsed_ms=%llu",
            ok ? 1 : 0,
            static_cast<unsigned long>(err),
            static_cast<unsigned long long>(static_cast<uint64_t>(GetTickCount64()) - started));
        if (!ok) SetLastError(err);
        return ok;
    }

    bool kernel_anti_debug_install_instrumentation(uint32_t pid, void* callback)
    {
        bool kernel_mode = false;
        {
            std::lock_guard<std::mutex> lk(g_state_mtx);
            kernel_mode = g_kernel_mode && device && device->is_connected();
        }
        if (!kernel_mode) return false;

        return device->kernel_anti_debug_install_instrumentation(pid, callback);
    }

    bool kernel_anti_debug_remove_instrumentation(uint32_t pid)
    {
        bool kernel_mode = false;
        {
            std::lock_guard<std::mutex> lk(g_state_mtx);
            kernel_mode = g_kernel_mode && device && device->is_connected();
        }
        if (!kernel_mode) return false;

        return device->kernel_anti_debug_remove_instrumentation(pid);
    }

    bool kernel_anti_dump_full(uint32_t pid)
    {
        const uint64_t started = static_cast<uint64_t>(GetTickCount64());
        bool kernel_mode = false;
        {
            std::lock_guard<std::mutex> lk(g_state_mtx);
            kernel_mode = g_kernel_mode && device && device->is_connected();
        }
        driver_critical_fmt("kernel_anti_dump_full_pre kernel=%d pid=%u caller_pid=%lu caller_tid=%lu tick=%llu",
            kernel_mode ? 1 : 0,
            pid,
            GetCurrentProcessId(),
            GetCurrentThreadId(),
            static_cast<unsigned long long>(started));
        if (!kernel_mode) {
            driver_critical_fmt("kernel_anti_dump_full_post ok=0 err=%lu reason=no_kernel elapsed_ms=%llu",
                static_cast<unsigned long>(GetLastError()),
                static_cast<unsigned long long>(static_cast<uint64_t>(GetTickCount64()) - started));
            return false;
        }

        SetLastError(ERROR_SUCCESS);
        bool ok = device->kernel_anti_dump_full(pid);
        DWORD err = ok ? ERROR_SUCCESS : GetLastError();
        driver_critical_fmt("kernel_anti_dump_full_post ok=%d err=%lu elapsed_ms=%llu",
            ok ? 1 : 0,
            static_cast<unsigned long>(err),
            static_cast<unsigned long long>(static_cast<uint64_t>(GetTickCount64()) - started));
        return ok;
    }

    bool kernel_anti_dump_register_filter(uint32_t pid)
    {
        bool kernel_mode = false;
        {
            std::lock_guard<std::mutex> lk(g_state_mtx);
            kernel_mode = g_kernel_mode && device && device->is_connected();
        }
        if (!kernel_mode) return false;

        return device->kernel_anti_dump_register_filter(pid);
    }

    bool kernel_anti_dump_hide_threads(uint32_t pid)
    {
        bool kernel_mode = false;
        {
            std::lock_guard<std::mutex> lk(g_state_mtx);
            kernel_mode = g_kernel_mode && device && device->is_connected();
        }
        if (!kernel_mode) return false;

        return device->kernel_anti_dump_hide_threads(pid);
    }

    bool kernel_anti_dump_erase_headers(uint32_t pid)
    {
        bool kernel_mode = false;
        {
            std::lock_guard<std::mutex> lk(g_state_mtx);
            kernel_mode = g_kernel_mode && device && device->is_connected();
        }
        if (!kernel_mode) return false;

        return device->kernel_anti_dump_erase_headers(pid);
    }

    bool kernel_anti_dump_query(anti_dump_result_t& out)
    {
        bool kernel_mode = false;
        {
            std::lock_guard<std::mutex> lk(g_state_mtx);
            kernel_mode = g_kernel_mode && device && device->is_connected();
        }
        if (!kernel_mode) return false;

        voyager::device_t::anti_dump_result raw{};
        if (!device->kernel_anti_dump_query(raw))
            return false;

        out.blocks_count = raw.blocks_count;
        return true;
    }

    bool kernel_anti_dump_permit_pid(uint32_t pid)
    {
        bool kernel_mode = false;
        {
            std::lock_guard<std::mutex> lk(g_state_mtx);
            kernel_mode = g_kernel_mode && device && device->is_connected();
        }
        if (!kernel_mode) return false;
        return device->kernel_anti_dump_permit_pid(pid);
    }

    bool kernel_anti_dump_unpermit_pid(uint32_t pid)
    {
        bool kernel_mode = false;
        {
            std::lock_guard<std::mutex> lk(g_state_mtx);
            kernel_mode = g_kernel_mode && device && device->is_connected();
        }
        if (!kernel_mode) return false;
        return device->kernel_anti_dump_unpermit_pid(pid);
    }

    bool kernel_anti_dump_stop_continuous()
    {
        bool kernel_mode = false;
        {
            std::lock_guard<std::mutex> lk(g_state_mtx);
            kernel_mode = g_kernel_mode && device && device->is_connected();
        }
        if (!kernel_mode) return false;
        return device->kernel_anti_dump_stop_continuous();
    }

    bool kernel_anti_dump_start_continuous(uint32_t pid)
    {
        const uint64_t started = static_cast<uint64_t>(GetTickCount64());
        bool kernel_mode = false;
        {
            std::lock_guard<std::mutex> lk(g_state_mtx);
            kernel_mode = g_kernel_mode && device && device->is_connected();
        }
        driver_critical_fmt("kernel_anti_dump_start_continuous_pre kernel=%d pid=%u caller_pid=%lu caller_tid=%lu tick=%llu",
            kernel_mode ? 1 : 0,
            pid,
            GetCurrentProcessId(),
            GetCurrentThreadId(),
            static_cast<unsigned long long>(started));
        if (!kernel_mode) {
            driver_critical_fmt("kernel_anti_dump_start_continuous_post ok=0 err=%lu reason=no_kernel elapsed_ms=%llu",
                static_cast<unsigned long>(GetLastError()),
                static_cast<unsigned long long>(static_cast<uint64_t>(GetTickCount64()) - started));
            return false;
        }
        SetLastError(ERROR_SUCCESS);
        bool ok = device->kernel_anti_dump_start_continuous(pid);
        DWORD err = ok ? ERROR_SUCCESS : GetLastError();
        driver_critical_fmt("kernel_anti_dump_start_continuous_post ok=%d err=%lu elapsed_ms=%llu",
            ok ? 1 : 0,
            static_cast<unsigned long>(err),
            static_cast<unsigned long long>(static_cast<uint64_t>(GetTickCount64()) - started));
        return ok;
    }

    bool malware_safe_protect_pid(uint32_t pid, uint32_t flags, uint64_t* out_denials)
    {
        bool kernel_mode = false;
        {
            std::lock_guard<std::mutex> lk(g_state_mtx);
            kernel_mode = g_kernel_mode && device && device->is_connected();
        }
        if (!kernel_mode) {
            diag::log_tagged_fmt("driver",
                "malware_safe_protect_pid skip_kernel_mode pid=%u flags=0x%08X",
                pid, flags);
            return false;
        }
        bool ok = device->protect_sandbox_pid(pid, flags, out_denials);
        diag::log_tagged_fmt("driver",
            "malware_safe_protect_pid pid=%u flags=0x%08X ok=%d",
            pid, flags, ok ? 1 : 0);
        return ok;
    }

    bool malware_safe_unprotect_pid(uint32_t pid, uint64_t* out_denials)
    {
        bool kernel_mode = false;
        {
            std::lock_guard<std::mutex> lk(g_state_mtx);
            kernel_mode = g_kernel_mode && device && device->is_connected();
        }
        if (!kernel_mode) return false;
        bool ok = device->unprotect_sandbox_pid(pid, out_denials);
        diag::log_tagged_fmt("driver",
            "malware_safe_unprotect_pid pid=%u ok=%d",
            pid, ok ? 1 : 0);
        return ok;
    }

    bool malware_safe_net_log(uint32_t pid, bool enable)
    {
        bool kernel_mode = false;
        {
            std::lock_guard<std::mutex> lk(g_state_mtx);
            kernel_mode = g_kernel_mode && device && device->is_connected();
        }
        if (!kernel_mode) return false;
        bool ok = device->net_log_register_pid(pid, enable);
        diag::log_tagged_fmt("driver",
            "malware_safe_net_log pid=%u enable=%d ok=%d",
            pid, enable ? 1 : 0, ok ? 1 : 0);
        return ok;
    }

    bool malware_safe_pull_packets(uint32_t pid, uint32_t max_records,
                                   std::vector<packet_record_t>& out,
                                   uint64_t* out_dropped)
    {
        out.clear();
        if (out_dropped) *out_dropped = 0;
        bool kernel_mode = false;
        {
            std::lock_guard<std::mutex> lk(g_state_mtx);
            kernel_mode = g_kernel_mode && device && device->is_connected();
        }
        if (!kernel_mode) {
            diag::log_tagged_fmt("driver",
                "malware_safe_pull_packets skip_kernel_mode pid=%u max=%u",
                pid, max_records);
            return false;
        }
        std::vector<voyager::detail::net_packet_record> raw;
        uint64_t dropped = 0;
        bool ok = device->malware_safe_pull_packets(pid, max_records, raw, &dropped);
        if (out_dropped) *out_dropped = dropped;
        if (!ok) {
            diag::log_tagged_fmt("driver",
                "malware_safe_pull_packets FAILED pid=%u max=%u",
                pid, max_records);
            return false;
        }
        out.reserve(raw.size());
        for (const auto& r : raw) {
            packet_record_t pr{};
            pr.timestamp = r.timestamp;
            pr.tcp_seq = r.tcp_seq;
            pr.pid = r.pid;
            pr.payload_len = r.payload_len;
            pr.flags = r.flags;
            pr.local_port = r.local_port;
            pr.remote_port = r.remote_port;
            pr.address_family = r.address_family;
            pr.protocol = r.protocol;
            pr.direction = r.direction;
            for (int i = 0; i < 16; ++i) pr.local_addr[i] = r.local_addr[i];
            for (int i = 0; i < 16; ++i) pr.remote_addr[i] = r.remote_addr[i];
            for (int i = 0; i < 256; ++i) pr.payload[i] = r.payload[i];
            out.push_back(pr);
        }
        diag::log_tagged_fmt("driver",
            "malware_safe_pull_packets pid=%u max=%u returned=%zu dropped_since=%llu",
            pid, max_records, out.size(), (unsigned long long)dropped);
        return true;
    }

    bool relay_server_token(uint32_t token_hash, uint64_t server_nonce)
    {
        bool kernel_mode = false;
        {
            std::lock_guard<std::mutex> lk(g_state_mtx);
            kernel_mode = g_kernel_mode && device && device->is_connected();
        }
        if (!kernel_mode) return false;

        return device->relay_server_token(token_hash, server_nonce);
    }

    bool relay_server_token_v2(uint32_t token_hash, uint64_t server_nonce, uint64_t* out_driver_proof)
    {
        bool kernel_mode = false;
        bool initialized = false;
        bool kernel_flag = false;
        bool connected = false;
        {
            std::lock_guard<std::mutex> lk(g_state_mtx);
            initialized = g_initialized;
            kernel_flag = g_kernel_mode;
            connected = device && device->is_connected();
            kernel_mode = kernel_flag && connected;
        }
        if (!kernel_mode) {
            SetLastError(ERROR_DEVICE_NOT_CONNECTED);
            diag::log_tagged_fmt("driver",
                "relay_server_token_v2_preflight_failed initialized=%d kernel_mode=%d connected=%d token_set=%d nonce_set=%d",
                initialized ? 1 : 0,
                kernel_flag ? 1 : 0,
                connected ? 1 : 0,
                token_hash != 0 ? 1 : 0,
                server_nonce != 0 ? 1 : 0);
            return false;
        }

        SetLastError(ERROR_SUCCESS);
        const ULONGLONG start = GetTickCount64();
        bool ok = device->relay_server_token_v2(token_hash, server_nonce, out_driver_proof);
        DWORD gle = ok ? ERROR_SUCCESS : GetLastError();
        diag::log_tagged_fmt("driver",
            "relay_server_token_v2_result ok=%d gle=%lu proof=%d elapsed_ms=%llu",
            ok ? 1 : 0,
            static_cast<unsigned long>(gle),
            (out_driver_proof && *out_driver_proof != 0) ? 1 : 0,
            static_cast<unsigned long long>(GetTickCount64() - start));
        SetLastError(gle);
        return ok;
    }

    bool traffic_redirect_op(uint32_t operation, uint32_t rule_id, uint32_t protocol,
                             uint32_t match_port, const uint8_t* match_addr,
                             uint32_t redirect_port, const uint8_t* redirect_addr,
                             uint32_t af, uint32_t* out_rule_id, uint32_t exclude_pid)
    {
        const ULONGLONG t0 = GetTickCount64();
        bool kernel_mode = false;
        {
            std::lock_guard<std::mutex> lk(g_state_mtx);
            kernel_mode = g_kernel_mode && device && device->is_connected();
        }
        if (!kernel_mode) {
            require_kernel_fail("traffic_redirect_op");
            return false;
        }

        diag::log_tagged_fmt("driver_bridge_net",
            "traffic_redirect_op ENTER op=%u rule_id=%u proto=%u match_port=%u redir_port=%u af=%u exclude_pid=%u match=%02X.%02X.%02X.%02X redir=%02X.%02X.%02X.%02X",
            operation, rule_id, protocol, match_port, redirect_port, af, exclude_pid,
            match_addr ? match_addr[0] : 0, match_addr ? match_addr[1] : 0,
            match_addr ? match_addr[2] : 0, match_addr ? match_addr[3] : 0,
            redirect_addr ? redirect_addr[0] : 0, redirect_addr ? redirect_addr[1] : 0,
            redirect_addr ? redirect_addr[2] : 0, redirect_addr ? redirect_addr[3] : 0);
        bool ok = device->traffic_redirect_op(operation, rule_id, protocol, match_port, match_addr,
                                              redirect_port, redirect_addr, af, out_rule_id, exclude_pid);
        DWORD gle = ok ? 0 : GetLastError();
        diag::log_tagged_fmt("driver_bridge_net",
            "traffic_redirect_op EXIT op=%u ok=%d out_rule_id=%u gle=%lu elapsed_ms=%llu",
            operation, ok ? 1 : 0, out_rule_id ? *out_rule_id : 0,
            static_cast<unsigned long>(gle),
            static_cast<unsigned long long>(GetTickCount64() - t0));
        return ok;
    }

    bool inject_packet(uint32_t direction, uint32_t protocol, uint32_t af,
                       uint32_t src_port, uint32_t dst_port,
                       const uint8_t* src_addr, const uint8_t* dst_addr,
                       const uint8_t* payload, uint32_t payload_size,
                       uint32_t tcp_flags, uint32_t tcp_seq, uint32_t tcp_ack)
    {
        bool kernel_mode = false;
        {
            std::lock_guard<std::mutex> lk(g_state_mtx);
            kernel_mode = g_kernel_mode && device && device->is_connected();
        }
        if (!kernel_mode) {
            require_kernel_fail("inject_packet");
            return false;
        }

        return device->inject_packet(direction, protocol, af, src_port, dst_port,
                                     src_addr, dst_addr, payload, payload_size,
                                     tcp_flags, tcp_seq, tcp_ack);
    }

    bool kill_connection(uint32_t protocol, uint32_t af,
                         uint32_t src_port, uint32_t dst_port,
                         const uint8_t* src_addr, const uint8_t* dst_addr,
                         uint32_t pid)
    {
        bool kernel_mode = false;
        {
            std::lock_guard<std::mutex> lk(g_state_mtx);
            kernel_mode = g_kernel_mode && device && device->is_connected();
        }
        if (!kernel_mode) {
            require_kernel_fail("kill_connection");
            return false;
        }

        return device->kill_connection(protocol, af, src_port, dst_port, src_addr, dst_addr, pid);
    }

    bool intercept_op(uint32_t operation, uint32_t filter_pid, uint32_t filter_port,
                      uint32_t filter_protocol, uint64_t hold_id,
                      const uint8_t* modify_payload, uint32_t modify_size,
                      uint32_t* out_held_count, bool* out_active)
    {
        const ULONGLONG t0 = GetTickCount64();
        bool kernel_mode = false;
        {
            std::lock_guard<std::mutex> lk(g_state_mtx);
            kernel_mode = g_kernel_mode && device && device->is_connected();
        }
        if (!kernel_mode) {
            require_kernel_fail("intercept_op");
            SetLastError(ERROR_INVALID_HANDLE);
            diag::log_tagged_fmt("driver_bridge_net",
                "intercept_op EXIT op=%u pid=%u port=%u proto=%u hold_id=%llu ok=0 preserved_gle=%lu attached_pid=%u kernel_mode=0 status=%s driver_error=%s elapsed_ms=%llu",
                operation,
                filter_pid,
                filter_port,
                filter_protocol,
                static_cast<unsigned long long>(hold_id),
                static_cast<unsigned long>(ERROR_INVALID_HANDLE),
                attached_pid(),
                status().c_str(),
                last_error().c_str(),
                static_cast<unsigned long long>(GetTickCount64() - t0));
            return false;
        }

        diag::log_tagged_fmt("driver_bridge_net",
            "intercept_op ENTER op=%u pid=%u port=%u proto=%u hold_id=%llu modify_size=%u attached_pid=%u kernel_mode=%d status=%s",
            operation, filter_pid, filter_port, filter_protocol,
            static_cast<unsigned long long>(hold_id), modify_size,
            attached_pid(), kernel_mode ? 1 : 0, status().c_str());
        SetLastError(ERROR_SUCCESS);
        bool ok = device->intercept_op(operation, filter_pid, filter_port, filter_protocol,
                                       hold_id, modify_payload, modify_size,
                                       out_held_count, out_active);
        DWORD gle = GetLastError();
        if (!ok && gle == ERROR_SUCCESS)
            gle = ERROR_GEN_FAILURE;
        diag::log_tagged_fmt("driver_bridge_net",
            "intercept_op EXIT op=%u pid=%u port=%u proto=%u hold_id=%llu ok=%d held_count=%u active=%d preserved_gle=%lu attached_pid=%u kernel_mode=%d status=%s driver_error=%s elapsed_ms=%llu",
            operation, filter_pid, filter_port, filter_protocol,
            static_cast<unsigned long long>(hold_id),
            ok ? 1 : 0,
            out_held_count ? *out_held_count : 0,
            out_active && *out_active ? 1 : 0,
            static_cast<unsigned long>(ok ? ERROR_SUCCESS : gle),
            attached_pid(),
            kernel_mode ? 1 : 0,
            status().c_str(),
            last_error().c_str(),
            static_cast<unsigned long long>(GetTickCount64() - t0));
        SetLastError(ok ? ERROR_SUCCESS : gle);
        return ok;
    }

    bool dns_spoof_op(uint32_t operation, uint32_t rule_id, const char* domain,
                      const uint8_t* spoof_addr, uint32_t af,
                      uint32_t ttl, uint32_t* out_rule_id)
    {
        const ULONGLONG t0 = GetTickCount64();
        bool kernel_mode = false;
        {
            std::lock_guard<std::mutex> lk(g_state_mtx);
            kernel_mode = g_kernel_mode && device && device->is_connected();
        }
        if (!kernel_mode) {
            require_kernel_fail("dns_spoof_op");
            return false;
        }

        diag::log_tagged_fmt("driver_bridge_net",
            "dns_spoof_op ENTER op=%u rule_id=%u domain=\"%.96s\" af=%u ttl=%u spoof=%02X.%02X.%02X.%02X",
            operation, rule_id, domain ? domain : "", af, ttl,
            spoof_addr ? spoof_addr[0] : 0, spoof_addr ? spoof_addr[1] : 0,
            spoof_addr ? spoof_addr[2] : 0, spoof_addr ? spoof_addr[3] : 0);
        bool ok = device->dns_spoof_op(operation, rule_id, domain, spoof_addr, af, ttl, out_rule_id);
        DWORD gle = ok ? 0 : GetLastError();
        diag::log_tagged_fmt("driver_bridge_net",
            "dns_spoof_op EXIT op=%u ok=%d out_rule_id=%u gle=%lu elapsed_ms=%llu",
            operation, ok ? 1 : 0, out_rule_id ? *out_rule_id : 0,
            static_cast<unsigned long>(gle),
            static_cast<unsigned long long>(GetTickCount64() - t0));
        return ok;
    }

    bool packet_mod_rule_op(uint32_t operation, uint32_t rule_id,
                            uint32_t direction, uint32_t protocol,
                            uint32_t port, uint32_t pid,
                            const uint8_t* pattern, uint32_t pattern_size,
                            const uint8_t* replacement, uint32_t replace_size,
                            uint32_t* out_rule_id)
    {
        const ULONGLONG t0 = GetTickCount64();
        bool kernel_mode = false;
        {
            std::lock_guard<std::mutex> lk(g_state_mtx);
            kernel_mode = g_kernel_mode && device && device->is_connected();
        }
        if (!kernel_mode) {
            require_kernel_fail("packet_mod_rule_op");
            return false;
        }

        diag::log_tagged_fmt("driver_bridge_net",
            "packet_mod_rule_op ENTER op=%u rule_id=%u dir=%u proto=%u port=%u pid=%u pattern_size=%u replace_size=%u",
            operation, rule_id, direction, protocol, port, pid, pattern_size, replace_size);
        bool ok = device->packet_mod_rule_op(operation, rule_id, direction, protocol,
                                             port, pid, pattern, pattern_size,
                                             replacement, replace_size, out_rule_id);
        DWORD gle = ok ? 0 : GetLastError();
        diag::log_tagged_fmt("driver_bridge_net",
            "packet_mod_rule_op EXIT op=%u ok=%d out_rule_id=%u gle=%lu elapsed_ms=%llu",
            operation, ok ? 1 : 0, out_rule_id ? *out_rule_id : 0,
            static_cast<unsigned long>(gle),
            static_cast<unsigned long long>(GetTickCount64() - t0));
        return ok;
    }

    bool stream_reassemble_op(uint32_t operation, uint32_t src_port, uint32_t dst_port,
                              uint32_t pid, const uint8_t* src_addr,
                              const uint8_t* dst_addr,
                              std::vector<uint8_t>* out_data,
                              uint32_t* out_packets, uint32_t* out_truncated)
    {
        const ULONGLONG t0 = GetTickCount64();
        bool kernel_mode = false;
        {
            std::lock_guard<std::mutex> lk(g_state_mtx);
            kernel_mode = g_kernel_mode && device && device->is_connected();
        }
        if (!kernel_mode) {
            require_kernel_fail("stream_reassemble_op");
            return false;
        }

        diag::log_tagged_fmt("driver_bridge_net",
            "stream_reassemble_op ENTER op=%u src_port=%u dst_port=%u pid=%u src=%02X.%02X.%02X.%02X dst=%02X.%02X.%02X.%02X",
            operation, src_port, dst_port, pid,
            src_addr ? src_addr[0] : 0, src_addr ? src_addr[1] : 0,
            src_addr ? src_addr[2] : 0, src_addr ? src_addr[3] : 0,
            dst_addr ? dst_addr[0] : 0, dst_addr ? dst_addr[1] : 0,
            dst_addr ? dst_addr[2] : 0, dst_addr ? dst_addr[3] : 0);
        bool ok = device->stream_reassemble_op(operation, src_port, dst_port, pid,
                                               src_addr, dst_addr, out_data,
                                               out_packets, out_truncated);
        DWORD gle = ok ? 0 : GetLastError();
        diag::log_tagged_fmt("driver_bridge_net",
            "stream_reassemble_op EXIT op=%u ok=%d data_size=%zu packets=%u truncated=%u gle=%lu elapsed_ms=%llu",
            operation, ok ? 1 : 0, out_data ? out_data->size() : 0,
            out_packets ? *out_packets : 0, out_truncated ? *out_truncated : 0,
            static_cast<unsigned long>(gle),
            static_cast<unsigned long long>(GetTickCount64() - t0));
        return ok;
    }

    bool sniff_net_buffers_start(uint64_t address, uint32_t buf_reg, uint32_t size_reg,
                                 uint32_t max_captures, uint32_t tid, uint32_t bp_index)
    {
        bool kernel_mode = false;
        {
            std::lock_guard<std::mutex> lk(g_state_mtx);
            kernel_mode = g_kernel_mode && device && device->is_connected();
        }
        if (!kernel_mode) {
            require_kernel_fail("sniff_net_buffers_start");
            return false;
        }

        return device->sniff_net_buffers_start(address, buf_reg, size_reg, max_captures, tid, bp_index);
    }

    bool sniff_net_buffers_stop()
    {
        bool kernel_mode = false;
        {
            std::lock_guard<std::mutex> lk(g_state_mtx);
            kernel_mode = g_kernel_mode && device && device->is_connected();
        }
        if (!kernel_mode) {
            require_kernel_fail("sniff_net_buffers_stop");
            return false;
        }

        return device->sniff_net_buffers_stop();
    }

    std::vector<sniff_result_t> sniff_net_buffers_get(bool& active)
    {
        bool kernel_mode = false;
        {
            std::lock_guard<std::mutex> lk(g_state_mtx);
            kernel_mode = g_kernel_mode && device && device->is_connected();
        }
        if (!kernel_mode) {
            active = false;
            return {};
        }

        auto raw = device->sniff_net_buffers_get(active);
        std::vector<sniff_result_t> out;
        out.reserve(raw.size());
        for (auto& r : raw) {
            sniff_result_t sr;
            sr.timestamp = r.timestamp;
            sr.thread_id = r.thread_id;
            sr.buffer    = std::move(r.buffer);
            out.push_back(std::move(sr));
        }
        return out;
    }

    std::vector<dpi_result_t> get_dpi_results(uint32_t filter_pid, uint32_t filter_protocol, uint32_t filter_port, uint32_t flags)
    {
        std::vector<dpi_result_t> result;
        bool kernel_mode = false;
        {
            std::lock_guard<std::mutex> lk(g_state_mtx);
            kernel_mode = g_kernel_mode && device && device->is_connected();
        }
        if (!kernel_mode) {
            diag::log_tagged_fmt("driver_bridge_net",
                "get_dpi_results ABORT kernel_mode=false filter_pid=%u proto=%u port=%u flags=0x%X",
                filter_pid, filter_protocol, filter_port, flags);
            return result;
        }

        auto raw = device->get_dpi_results(filter_pid, filter_protocol, filter_port, flags);
        diag::log_tagged_fmt("driver_bridge_net",
            "get_dpi_results EXIT filter_pid=%u proto=%u port=%u flags=0x%X raw=%zu",
            filter_pid, filter_protocol, filter_port, flags, raw.size());
        result.reserve(raw.size());
        for (const auto& src : raw) {
            dpi_result_t d;
            d.timestamp      = src.timestamp;
            d.direction      = src.direction;
            d.protocol       = src.protocol;
            d.src_port       = src.src_port;
            d.dst_port       = src.dst_port;
            d.pid            = src.pid;
            d.payload_size   = src.payload_size;
            d.af             = src.af;
            std::memcpy(d.src_addr, src.src_addr, 16);
            std::memcpy(d.dst_addr, src.dst_addr, 16);
            d.tcp_flags      = src.tcp_flags;
            d.tcp_window     = src.tcp_window;
            d.is_http        = src.is_http;
            d.is_tls         = src.is_tls;
            d.is_dns         = src.is_dns;
            d.http_method    = src.http_method;
            d.tls_version    = src.tls_version;
            d.tls_content_type = src.tls_content_type;
            d.http_host      = src.http_host;
            d.http_path      = src.http_path;
            d.tls_sni        = src.tls_sni;
            result.push_back(std::move(d));
        }
        return result;
    }

    std::vector<wfp_callout_info_t> enumerate_wfp_callouts(const std::string& filter_module)
    {
        std::vector<wfp_callout_info_t> result;
        bool kernel_mode = false;
        {
            std::lock_guard<std::mutex> lk(g_state_mtx);
            kernel_mode = g_kernel_mode && device && device->is_connected();
        }
        if (!kernel_mode) return result;

        auto raw = device->enumerate_wfp_callouts(filter_module);
        result.reserve(raw.size());
        for (const auto& src : raw) {
            wfp_callout_info_t c;
            c.classify_fn          = src.classify_fn;
            c.notify_fn            = src.notify_fn;
            c.flow_delete_fn       = src.flow_delete_fn;
            c.owning_module_base   = src.owning_module_base;
            c.filter_id            = src.filter_id;
            c.callout_id           = src.callout_id;
            c.layer_id             = src.layer_id;
            c.flags                = src.flags;
            c.entry_type           = src.entry_type;
            c.action_type          = src.action_type;
            c.provider_present     = src.provider_present;
            c.aida_match_reason    = src.aida_match_reason;
            c.callout_key_str      = src.callout_key_str;
            c.applicable_layer_str = src.applicable_layer_str;
            c.sublayer_key_str     = src.sublayer_key_str;
            c.owning_module        = src.owning_module;
            result.push_back(std::move(c));
        }
        return result;
    }

    std::vector<socket_info_t> get_socket_handles(uint32_t target_pid)
    {
        std::vector<socket_info_t> result;
        bool kernel_mode = false;
        {
            std::lock_guard<std::mutex> lk(g_state_mtx);
            kernel_mode = g_kernel_mode && device && device->is_connected();
        }
        if (!kernel_mode) return result;

        auto raw = device->get_socket_handles(target_pid);
        result.reserve(raw.size());
        for (const auto& src : raw) {
            socket_info_t s;
            s.handle_value     = src.handle_value;
            s.afd_endpoint_addr = src.afd_endpoint_addr;
            s.pid              = src.pid;
            s.protocol         = src.protocol;
            s.state            = src.state;
            s.local_port       = src.local_port;
            s.remote_port      = src.remote_port;
            s.address_family   = src.address_family;
            std::memcpy(s.local_addr, src.local_addr, 16);
            std::memcpy(s.remote_addr, src.remote_addr, 16);
            result.push_back(s);
        }
        return result;
    }

    std::vector<tcpip_connection_t> dump_tcpip_connections(uint32_t target_pid, uint32_t filter_protocol)
    {
        std::vector<tcpip_connection_t> result;
        bool kernel_mode = false;
        {
            std::lock_guard<std::mutex> lk(g_state_mtx);
            kernel_mode = g_kernel_mode && device && device->is_connected();
        }
        if (!kernel_mode) return result;

        auto raw = device->dump_tcpip_connections(target_pid, filter_protocol);
        result.reserve(raw.size());
        for (const auto& src : raw) {
            tcpip_connection_t c;
            c.tcb_address        = src.tcb_address;
            c.owning_module_base = src.owning_module_base;
            c.pid                = src.pid;
            c.protocol           = src.protocol;
            c.state              = src.state;
            c.local_port         = src.local_port;
            c.remote_port        = src.remote_port;
            c.address_family     = src.address_family;
            std::memcpy(c.local_addr, src.local_addr, 16);
            std::memcpy(c.remote_addr, src.remote_addr, 16);
            c.create_time        = src.create_time;
            c.bytes_in           = src.bytes_in;
            c.bytes_out          = src.bytes_out;
            result.push_back(c);
        }
        return result;
    }

    std::vector<net_iface_info_t> enumerate_interfaces()
    {
        std::vector<net_iface_info_t> result;
        bool kernel_mode = false;
        {
            std::lock_guard<std::mutex> lk(g_state_mtx);
            kernel_mode = g_kernel_mode && device && device->is_connected();
        }
        if (!kernel_mode) return result;

        auto raw = device->enumerate_interfaces();
        result.reserve(raw.size());
        for (const auto& src : raw) {
            net_iface_info_t ifc;
            ifc.if_index    = src.if_index;
            ifc.if_type     = src.if_type;
            ifc.mtu         = src.mtu;
            ifc.oper_status = src.oper_status;
            ifc.speed       = src.speed;
            std::memcpy(ifc.mac_addr, src.mac_addr, 6);
            std::memcpy(ifc.ipv4_addr, src.ipv4_addr, 4);
            std::memcpy(ifc.ipv4_mask, src.ipv4_mask, 4);
            std::memcpy(ifc.ipv6_addr, src.ipv6_addr, 16);
            ifc.name        = src.name;
            ifc.description = src.description;
            ifc.in_octets   = src.in_octets;
            ifc.out_octets  = src.out_octets;
            result.push_back(std::move(ifc));
        }
        return result;
    }

    std::vector<held_packet_info_t> get_held_packets()
    {
        std::vector<held_packet_info_t> result;
        bool kernel_mode = false;
        {
            std::lock_guard<std::mutex> lk(g_state_mtx);
            kernel_mode = g_kernel_mode && device && device->is_connected();
        }
        if (!kernel_mode) {
            diag::log_tagged("driver_bridge_net", "get_held_packets ABORT kernel_mode=false");
            return result;
        }

        auto raw = device->get_held_packets();
        diag::log_tagged_fmt("driver_bridge_net",
            "get_held_packets EXIT raw=%zu",
            raw.size());
        result.reserve(raw.size());
        for (auto& src : raw) {
            held_packet_info_t h;
            h.hold_id      = src.hold_id;
            h.timestamp    = src.timestamp;
            h.direction    = src.direction;
            h.protocol     = src.protocol;
            h.src_port     = src.src_port;
            h.dst_port     = src.dst_port;
            h.pid          = src.pid;
            h.payload_size = src.payload_size;
            h.af           = src.af;
            std::memcpy(h.src_addr, src.src_addr, 16);
            std::memcpy(h.dst_addr, src.dst_addr, 16);
            h.payload      = std::move(src.payload);
            result.push_back(std::move(h));
        }
        return result;
    }

    std::vector<mod_rule_info_t> list_packet_mod_rules()
    {
        std::vector<mod_rule_info_t> result;
        bool kernel_mode = false;
        {
            std::lock_guard<std::mutex> lk(g_state_mtx);
            kernel_mode = g_kernel_mode && device && device->is_connected();
        }
        if (!kernel_mode) {
            diag::log_tagged("driver_bridge_net", "list_packet_mod_rules ABORT kernel_mode=false");
            return result;
        }

        auto raw = device->list_packet_mod_rules();
        diag::log_tagged_fmt("driver_bridge_net",
            "list_packet_mod_rules EXIT raw=%zu",
            raw.size());
        result.reserve(raw.size());
        for (const auto& src : raw) {
            mod_rule_info_t r;
            r.rule_id     = src.rule_id;
            r.direction   = src.direction;
            r.protocol    = src.protocol;
            r.port        = src.port;
            r.pid         = src.pid;
            r.match_count = src.match_count;
            r.active      = src.active;
            result.push_back(r);
        }
        return result;
    }

    std::vector<redirect_rule_info_t> list_redirect_rules()
    {
        std::vector<redirect_rule_info_t> result;
        bool kernel_mode = false;
        {
            std::lock_guard<std::mutex> lk(g_state_mtx);
            kernel_mode = g_kernel_mode && device && device->is_connected();
        }
        if (!kernel_mode) {
            diag::log_tagged("driver_bridge_net", "list_redirect_rules ABORT kernel_mode=false");
            return result;
        }

        auto raw = device->list_redirect_rules();
        diag::log_tagged_fmt("driver_bridge_net",
            "list_redirect_rules EXIT raw=%zu",
            raw.size());
        result.reserve(raw.size());
        for (const auto& src : raw) {
            redirect_rule_info_t r;
            r.rule_id       = src.rule_id;
            r.protocol      = src.protocol;
            r.match_port    = src.match_port;
            r.redirect_port = src.redirect_port;
            r.af            = src.af;
            r.match_count   = src.match_count;
            r.active        = src.active;
            result.push_back(r);
        }
        return result;
    }

    std::vector<dns_spoof_info_t> list_dns_spoof_rules()
    {
        std::vector<dns_spoof_info_t> result;
        bool kernel_mode = false;
        {
            std::lock_guard<std::mutex> lk(g_state_mtx);
            kernel_mode = g_kernel_mode && device && device->is_connected();
        }
        if (!kernel_mode) {
            diag::log_tagged("driver_bridge_net", "list_dns_spoof_rules ABORT kernel_mode=false");
            return result;
        }

        auto raw = device->list_dns_spoof_rules();
        diag::log_tagged_fmt("driver_bridge_net",
            "list_dns_spoof_rules EXIT raw=%zu",
            raw.size());
        result.reserve(raw.size());
        for (const auto& src : raw) {
            dns_spoof_info_t r;
            r.rule_id     = src.rule_id;
            r.domain      = src.domain;
            r.af          = src.af;
            r.match_count = src.match_count;
            r.active      = src.active;
            r.ttl         = src.ttl;
            result.push_back(std::move(r));
        }
        return result;
    }

    bool fingerprint_op(uint32_t operation)
    {
        const ULONGLONG t0 = GetTickCount64();
        bool kernel_mode = false;
        {
            std::lock_guard<std::mutex> lk(g_state_mtx);
            kernel_mode = g_kernel_mode && device && device->is_connected();
        }
        if (!kernel_mode) {
            require_kernel_fail("fingerprint_op");
            return false;
        }
        bool ok = device->fingerprint_op(operation);
        DWORD gle = ok ? 0 : GetLastError();
        diag::log_tagged_fmt("driver_bridge_net",
            "fingerprint_op EXIT op=%u ok=%d gle=%lu elapsed_ms=%llu",
            operation,
            ok ? 1 : 0,
            static_cast<unsigned long>(gle),
            static_cast<unsigned long long>(GetTickCount64() - t0));
        return ok;
    }

    std::vector<fingerprint_info_t> get_fingerprints()
    {
        std::vector<fingerprint_info_t> result;
        bool kernel_mode = false;
        {
            std::lock_guard<std::mutex> lk(g_state_mtx);
            kernel_mode = g_kernel_mode && device && device->is_connected();
        }
        if (!kernel_mode) {
            diag::log_tagged("driver_bridge_net", "get_fingerprints ABORT kernel_mode=false");
            return result;
        }

        auto raw = device->get_fingerprints();
        diag::log_tagged_fmt("driver_bridge_net",
            "get_fingerprints EXIT raw=%zu",
            raw.size());
        result.reserve(raw.size());
        for (const auto& src : raw) {
            fingerprint_info_t f;
            std::memcpy(f.remote_addr, src.remote_addr, 16);
            f.af             = src.af;
            f.ttl            = src.ttl;
            f.window_size    = src.window_size;
            f.mss            = src.mss;
            f.window_scale   = src.window_scale;
            f.df_flag        = src.df_flag;
            f.sack_permitted = src.sack_permitted;
            f.nop_count      = src.nop_count;
            f.os_guess       = src.os_guess;
            result.push_back(std::move(f));
        }
        return result;
    }

    bool export_pcap(uint32_t filter_pid, uint32_t filter_protocol, uint32_t max_packets, pcap_export_result_t* out)
    {
        bool kernel_mode = false;
        {
            std::lock_guard<std::mutex> lk(g_state_mtx);
            kernel_mode = g_kernel_mode && device && device->is_connected();
        }
        if (!kernel_mode) {
            require_kernel_fail("export_pcap");
            return false;
        }

        voyager::device_t::pcap_export_result raw{};
        bool ok = device->export_pcap(filter_pid, filter_protocol, max_packets, out ? &raw : nullptr);
        if (ok && out) {
            out->header.magic_number  = raw.header.magic_number;
            out->header.version_major = raw.header.version_major;
            out->header.version_minor = raw.header.version_minor;
            out->header.thiszone      = raw.header.thiszone;
            out->header.sigfigs       = raw.header.sigfigs;
            out->header.snaplen       = raw.header.snaplen;
            out->header.network       = raw.header.network;
            out->packets.reserve(raw.packets.size());
            for (auto& src : raw.packets) {
                pcap_packet_t p;
                p.ts_sec  = src.ts_sec;
                p.ts_usec = src.ts_usec;
                p.data    = std::move(src.data);
                out->packets.push_back(std::move(p));
            }
        }
        return ok;
    }

    bool run_kernel_hv_detection(hv_kernel_detect_result_t& result) {
        const uint64_t started = static_cast<uint64_t>(GetTickCount64());
        bool kernel_mode = false;
        bool connected_snapshot = false;
        voyager::device_t* local_device = nullptr;
        driver_critical_fmt("run_kernel_hv_detection_state_lock_pre pid=%lu tid=%lu tick=%llu",
            GetCurrentProcessId(),
            GetCurrentThreadId(),
            static_cast<unsigned long long>(started));
        {
            std::lock_guard<std::mutex> lk(g_state_mtx);
            local_device = device.get();
            connected_snapshot = local_device && local_device->is_connected();
            kernel_mode = g_kernel_mode && connected_snapshot;
        }
        driver_critical_fmt("run_kernel_hv_detection_state_lock_post kernel=%d connected=%d device=%p elapsed_ms=%llu",
            kernel_mode ? 1 : 0,
            connected_snapshot ? 1 : 0,
            local_device,
            static_cast<unsigned long long>(static_cast<uint64_t>(GetTickCount64()) - started));
        if (!kernel_mode) {
            driver_critical_fmt("run_kernel_hv_detection_post ok=0 err=%lu reason=no_kernel pid=%lu tid=%lu elapsed_ms=%llu",
                static_cast<unsigned long>(GetLastError()),
                GetCurrentProcessId(),
                GetCurrentThreadId(),
                static_cast<unsigned long long>(static_cast<uint64_t>(GetTickCount64()) - started));
            return false;
        }

        driver_critical_fmt("run_kernel_hv_detection_pre pid=%lu tid=%lu tick=%llu",
            GetCurrentProcessId(),
            GetCurrentThreadId(),
            static_cast<unsigned long long>(started));
        voyager::detail::hv_detect_result raw{};
        SetLastError(ERROR_SUCCESS);
        driver_critical_fmt("run_kernel_hv_detection_device_call_pre device=%p connected_snapshot=%d elapsed_ms=%llu",
            local_device,
            connected_snapshot ? 1 : 0,
            static_cast<unsigned long long>(static_cast<uint64_t>(GetTickCount64()) - started));
        bool ok = local_device->run_hv_detect(raw);
        DWORD err = ok ? ERROR_SUCCESS : GetLastError();
        if (ok) {
            result.sidt_lock_prefix    = raw.sidt_lock_prefix;
            result.sidt_invalid_pf     = raw.sidt_invalid_pf;
            result.sidt_tlb_only       = raw.sidt_tlb_only;
            result.sidt_timing         = raw.sidt_timing;
            result.sidt_compat_mode    = raw.sidt_compat_mode;
            result.sidt_noncanonical_gp = raw.sidt_noncanonical_gp;
            result.sidt_noncanonical_ss = raw.sidt_noncanonical_ss;
            result.sidt_cpl3_umip_off  = raw.sidt_cpl3_umip_off;
            result.sidt_cpl3_umip_on   = raw.sidt_cpl3_umip_on;
            result.lidt_lock_prefix    = raw.lidt_lock_prefix;
            result.lidt_invalid_pf     = raw.lidt_invalid_pf;
            result.lidt_tlb_only       = raw.lidt_tlb_only;
            result.lidt_timing         = raw.lidt_timing;
            result.lidt_noncanonical_gp = raw.lidt_noncanonical_gp;
            result.lidt_noncanonical_ss = raw.lidt_noncanonical_ss;
            result.lidt_cpl3_gp        = raw.lidt_cpl3_gp;
            result.ve_trigger          = raw.ve_trigger;
            result.ve_lbr_stack        = raw.ve_lbr_stack;
            result.ve_xsetbv_gp        = raw.ve_xsetbv_gp;
            result.ve_cr4_vmxe         = raw.ve_cr4_vmxe;
            result.vmf_cpuid_vendor    = raw.vmf_cpuid_vendor;
            result.vmf_hyperv_guest    = raw.vmf_hyperv_guest;
            result.vmf_smbios_vm       = raw.vmf_smbios_vm;
            result.vmf_acpi_vm         = raw.vmf_acpi_vm;
            result.vmf_pci_vm          = raw.vmf_pci_vm;
            result.vmf_disk_vm         = raw.vmf_disk_vm;
            result.vmf_mac_vm          = raw.vmf_mac_vm;
            result.vmf_registry_vm     = raw.vmf_registry_vm;
            result.total_run           = raw.total_run;
            result.total_failed        = raw.total_failed;
            result.ms_hv_root          = raw.ms_hv_root;
            result.is_virtual_machine  = raw.is_virtual_machine;
            std::memcpy(result.vm_vendor_name, raw.vm_vendor_name, sizeof(result.vm_vendor_name));
            std::memcpy(result.measurements_hmac, raw.measurements_hmac, sizeof(result.measurements_hmac));
        }
        driver_critical_fmt("run_kernel_hv_detection_post ok=%d err=%lu cpuid=%u hyperv_guest=%u smbios=%u acpi=%u pci=%u disk=%u mac=%u registry=%u total_run=%u total_failed=%u hmac_hash=0x%016llX elapsed_ms=%llu",
            ok ? 1 : 0,
            static_cast<unsigned long>(err),
            static_cast<unsigned>(raw.vmf_cpuid_vendor),
            static_cast<unsigned>(raw.vmf_hyperv_guest),
            static_cast<unsigned>(raw.vmf_smbios_vm),
            static_cast<unsigned>(raw.vmf_acpi_vm),
            static_cast<unsigned>(raw.vmf_pci_vm),
            static_cast<unsigned>(raw.vmf_disk_vm),
            static_cast<unsigned>(raw.vmf_mac_vm),
            static_cast<unsigned>(raw.vmf_registry_vm),
            static_cast<unsigned>(raw.total_run),
            static_cast<unsigned>(raw.total_failed),
            static_cast<unsigned long long>(driver_fnv1a64(raw.measurements_hmac, sizeof(raw.measurements_hmac))),
            static_cast<unsigned long long>(static_cast<uint64_t>(GetTickCount64()) - started));
        return ok;
    }

    bool drain_debug_events(std::vector<debug_event_t>& out,
                            size_t max_events,
                            debug_event_stats_t* out_stats)
    {
        out.clear();
        if (out_stats) *out_stats = debug_event_stats_t{};

        bool kernel_mode = false;
        {
            std::lock_guard<std::mutex> lk(g_state_mtx);
            kernel_mode = g_kernel_mode && device && device->is_connected();
        }
        if (!kernel_mode) return false;

        std::vector<voyager::device_t::debug_event_record> raw;
        voyager::device_t::debug_event_drain_stats raw_stats{};
        if (!device->drain_debug_events(raw, max_events, &raw_stats))
            return false;

        if (out_stats) {
            out_stats->returned_count = raw_stats.returned_count;
            out_stats->dropped_since_last_drain = raw_stats.dropped_since_last_drain;
            out_stats->total_dropped = raw_stats.total_dropped;
            out_stats->total_published = raw_stats.total_published;
        }

        out.reserve(raw.size());
        for (auto& src : raw) {
            debug_event_t dst;
            dst.type       = static_cast<debug_event_type_e>(static_cast<uint32_t>(src.type));
            dst.process_id = src.process_id;
            dst.thread_id  = src.thread_id;
            dst.flags      = src.flags;
            dst.timestamp  = src.timestamp;
            dst.image_base = src.image_base;
            dst.image_size = src.image_size;
            dst.image_path_wide = std::move(src.image_path);
            dst.image_path = utf8_from_wstring(dst.image_path_wide);
            dst.image_name = extract_basename_utf8(dst.image_path);
            out.push_back(std::move(dst));
        }
        return true;
    }
}
