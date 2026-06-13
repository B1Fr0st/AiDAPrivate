#include "test_all_debugger.h"
#include "test_all_features.hpp"

#include "../debugger/debugger_engine.hpp"
#include "../debugger/debugger_view.hpp"
#include "../debugger/seh_view.hpp"
#include "../debugger/module_view.hpp"
#include "../../helpers/diag_log.hpp"

#include <Windows.h>
#include <atomic>
#include <chrono>
#include <cstdio>
#include <cstring>
#include <string>
#include <vector>

namespace test_all_features {

namespace {

static void format_timestamp(char* out, std::size_t cap) {
    SYSTEMTIME st;
    GetLocalTime(&st);
    std::snprintf(out, cap, "%04u-%02u-%02u %02u:%02u:%02u.%03u",
        static_cast<unsigned>(st.wYear),
        static_cast<unsigned>(st.wMonth),
        static_cast<unsigned>(st.wDay),
        static_cast<unsigned>(st.wHour),
        static_cast<unsigned>(st.wMinute),
        static_cast<unsigned>(st.wSecond),
        static_cast<unsigned>(st.wMilliseconds));
}

static void write_log_file(HANDLE hf, const std::string& line) {
    test_all_features::write_full_test_log_line(hf, line.data(), line.size());
}

static void log_msg(HANDLE hf, const char* tag, const char* fmt, ...) {
    char ts[40];
    format_timestamp(ts, sizeof(ts));

    char detail[1024];
    va_list ap;
    va_start(ap, fmt);
    _vsnprintf_s(detail, sizeof(detail), _TRUNCATE, fmt, ap);
    va_end(ap);

    char line[1200];
    _snprintf_s(line, sizeof(line), _TRUNCATE, "[%s] [%s] %s\n", ts, tag, detail);
    std::string s(line);

    write_log_file(hf, s);
    test_all_features::mirror_full_test_log_line(tag, detail, s.c_str());
}

static uint64_t get_ntdll_fn(const char* name) {
    HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
    if (!ntdll) return 0;
    FARPROC fn = GetProcAddress(ntdll, name);
    return static_cast<uint64_t>(reinterpret_cast<uintptr_t>(fn));
}

static uint64_t alloc_target_bp_region(size_t size = 64) {
    uint64_t addr = driver_bridge::allocate_memory(size);
    if (addr == 0) return 0;
    std::vector<uint8_t> code(size, 0x90);
    code.back() = 0xC3;
    driver_bridge::write_memory(addr, code);
    uint32_t old_protect = 0;
    if (!driver_bridge::protect_memory(addr, size, PAGE_EXECUTE_READWRITE, &old_protect)) {
        diag::log_tagged_fmt("test_dbg_detail", "alloc_target_bp_region protect_memory failed addr=0x%llX size=%zu",
            (unsigned long long)addr, size);
    }
    return addr;
}

static bool require_attached_live_target(HANDLE hf, const char* tag, std::atomic<int>& failed) {
    uint32_t pid = driver_bridge::attached_pid();
    if (pid == 0) {
        log_msg(hf, tag, "FAIL -- no active attached PID");
        failed.fetch_add(1);
        return false;
    }
    uint32_t exit_code = 0;
    if (!driver_bridge::attached_process_alive(&exit_code)) {
        log_msg(hf, tag, "FAIL -- attached PID %u is not alive (exit_code_or_error=0x%08X)",
            (unsigned)pid, (unsigned)exit_code);
        failed.fetch_add(1);
        return false;
    }
    return true;
}

static std::vector<uint32_t> attached_target_tids() {
    std::vector<uint32_t> result;
    const uint32_t pid = driver_bridge::attached_pid();
    if (pid == 0)
        return result;

    const uint32_t active = debugger_engine::g_state.active_tid;
    auto threads = driver_bridge::enumerate_threads();
    auto add_tid = [&](uint32_t tid) {
        if (tid == 0)
            return;
        for (uint32_t existing : result) {
            if (existing == tid)
                return;
        }
        result.push_back(tid);
    };
    if (active != 0) {
        for (const auto& t : threads) {
            if (t.owner_pid == pid && t.tid == active) {
                add_tid(active);
                break;
            }
        }
    }
    for (const auto& t : threads) {
        if (t.owner_pid == pid)
            add_tid(t.tid);
    }
    return result;
}

static std::vector<uint32_t> bounded_hardware_breakpoint_tids(std::size_t limit) {
    std::vector<uint32_t> result;
    auto candidates = attached_target_tids();
    for (uint32_t tid : candidates) {
        if (tid == 0)
            continue;
        bool seen = false;
        for (uint32_t existing : result) {
            if (existing == tid) {
                seen = true;
                break;
            }
        }
        if (!seen)
            result.push_back(tid);
        if (result.size() >= limit)
            break;
    }
    return result;
}

static bool select_hardware_breakpoint_tid(HANDLE hf, const char* tag, uint32_t& tid, driver_bridge::thread_context_t* out_ctx) {
    auto candidates = attached_target_tids();
    for (uint32_t candidate : candidates) {
        driver_bridge::thread_context_t ctx{};
        if (!driver_bridge::get_thread_context(candidate, ctx) || ctx.rip == 0 || ctx.rsp == 0)
            continue;
        tid = candidate;
        debugger_engine::g_state.active_tid = candidate;
        if (out_ctx)
            *out_ctx = ctx;
        log_msg(hf, tag, "selected hardware breakpoint thread tid=%u rip=0x%llX rsp=0x%llX dr7=0x%llX candidates=%zu",
            static_cast<unsigned>(candidate),
            static_cast<unsigned long long>(ctx.rip),
            static_cast<unsigned long long>(ctx.rsp),
            static_cast<unsigned long long>(ctx.dr7),
            candidates.size());
        return true;
    }
    log_msg(hf, tag, "FAIL -- no contextable target thread available for hardware breakpoint test (candidates=%zu)", candidates.size());
    return false;
}

struct controlled_step_fixture_t {
    uint32_t tid = 0;
    uint32_t original_suspend_count = 0;
    uint64_t code = 0;
    uint64_t stack = 0;
    uint64_t rsp = 0;
    uint64_t expected_rip = 0;
    driver_bridge::thread_context_t before{};
    bool context_valid = false;
    bool context_entered = false;
};

static bool restore_context_and_suspend_count(uint32_t tid,
                                              const driver_bridge::thread_context_t& ctx,
                                              uint32_t desired_suspend_count) {
    if (tid == 0)
        return false;
    uint32_t prev = 0;
    if (!driver_bridge::suspend_thread(tid, &prev))
        return false;
    uint32_t current = prev < 0xFFFFFFFFu ? prev + 1 : prev;
    bool ctx_ok = driver_bridge::set_thread_context(tid, ctx, ~0ULL);
    bool depth_ok = true;
    for (int guard = 0; current > desired_suspend_count && guard < 64; ++guard) {
        uint32_t resume_prev = 0;
        if (!driver_bridge::resume_thread(tid, &resume_prev)) {
            depth_ok = false;
            break;
        }
        current = resume_prev > 0 ? resume_prev - 1 : 0;
    }
    return ctx_ok && depth_ok && current == desired_suspend_count;
}

static bool cleanup_controlled_step_fixture(controlled_step_fixture_t& fx,
                                            bool* restored,
                                            bool* freed_code,
                                            bool* freed_stack) {
    bool restore_ok = true;
    bool code_ok = true;
    bool stack_ok = true;

    if (fx.context_valid && fx.tid != 0)
        restore_ok = restore_context_and_suspend_count(fx.tid, fx.before, fx.original_suspend_count);

    if (fx.code != 0 && (!fx.context_entered || restore_ok)) {
        code_ok = driver_bridge::free_memory(fx.code);
        fx.code = 0;
    }
    if (fx.stack != 0 && (!fx.context_entered || restore_ok)) {
        stack_ok = driver_bridge::free_memory(fx.stack);
        fx.stack = 0;
    }

    if (restored) *restored = restore_ok;
    if (freed_code) *freed_code = code_ok;
    if (freed_stack) *freed_stack = stack_ok;
    return restore_ok && code_ok && stack_ok;
}

static bool prepare_controlled_step_fixture(HANDLE hf,
                                            const char* tag,
                                            controlled_step_fixture_t& fx,
                                            const std::vector<uint8_t>& code_bytes,
                                            bool use_stack_return) {
    auto candidates = attached_target_tids();
    if (candidates.empty()) {
        log_msg(hf, tag, "FAIL -- no live target thread available for controlled step fixture");
        return false;
    }

    std::string last_detail = "none";
    for (uint32_t tid : candidates) {
        controlled_step_fixture_t trial;
        trial.tid = tid;
        debugger_engine::g_state.active_tid = trial.tid;
        if (!driver_bridge::suspend_thread(trial.tid, &trial.original_suspend_count)) {
            char detail[96];
            std::snprintf(detail, sizeof(detail), "suspend tid=%u failed", trial.tid);
            last_detail = detail;
            log_msg(hf, tag, "INFO -- controlled step fixture candidate rejected: %s", last_detail.c_str());
            continue;
        }

        if (!driver_bridge::get_thread_context(trial.tid, trial.before) || trial.before.rip == 0 || trial.before.rsp == 0) {
            driver_bridge::resume_thread(trial.tid);
            char detail[128];
            std::snprintf(detail, sizeof(detail), "context tid=%u rip=0x%llX rsp=0x%llX failed",
                trial.tid,
                (unsigned long long)trial.before.rip,
                (unsigned long long)trial.before.rsp);
            last_detail = detail;
            log_msg(hf, tag, "INFO -- controlled step fixture candidate rejected: %s", last_detail.c_str());
            continue;
        }
        trial.context_valid = true;

        trial.code = driver_bridge::allocate_memory(64);
        if (use_stack_return)
            trial.stack = driver_bridge::allocate_memory(0x1000);

        bool ok = trial.code != 0 && (!use_stack_return || trial.stack != 0);
        if (ok) {
            std::vector<uint8_t> code(64, 0x90);
            for (size_t i = 0; i < code_bytes.size() && i < code.size(); ++i)
                code[i] = code_bytes[i];
            ok = driver_bridge::write_memory(trial.code, code);
        }
        if (ok) {
            uint32_t old_protect = 0;
            ok = driver_bridge::protect_memory(trial.code, 64, PAGE_EXECUTE_READWRITE, &old_protect);
        }
        if (ok && use_stack_return) {
            trial.expected_rip = trial.code + 0x10;
            trial.rsp = trial.stack + 0x800;
            std::vector<uint8_t> stack_bytes(8, 0);
            std::memcpy(stack_bytes.data(), &trial.expected_rip, sizeof(trial.expected_rip));
            ok = driver_bridge::write_memory(trial.rsp, stack_bytes);
        } else if (ok) {
            trial.expected_rip = trial.code + 1;
        }

        driver_bridge::thread_context_t entry_ctx{};
        if (ok) {
            entry_ctx = trial.before;
            entry_ctx.rip = trial.code;
            if (use_stack_return)
                entry_ctx.rsp = trial.rsp;
            entry_ctx.rflags &= ~0x100ULL;
            ok = driver_bridge::set_thread_context(trial.tid, entry_ctx, ~0ULL);
            trial.context_entered = ok;
        }
        if (ok) {
            auto verify_ctx = entry_ctx;
            verify_ctx.rip = trial.expected_rip;
            if (use_stack_return)
                verify_ctx.rsp = trial.rsp + 8;
            bool verify_set = driver_bridge::set_thread_context(trial.tid, verify_ctx, ~0ULL);
            bool restore_entry = verify_set && driver_bridge::set_thread_context(trial.tid, entry_ctx, ~0ULL);
            ok = verify_set && restore_entry;
        }

        if (!ok) {
            uint64_t failed_code = trial.code;
            uint64_t failed_stack = trial.stack;
            bool restored = false;
            bool freed_code = false;
            bool freed_stack = false;
            cleanup_controlled_step_fixture(trial, &restored, &freed_code, &freed_stack);
            char detail[220];
            std::snprintf(detail, sizeof(detail),
                "build tid=%u code=0x%llX stack=0x%llX restored=%d free_code=%d free_stack=%d failed",
                tid,
                (unsigned long long)failed_code,
                (unsigned long long)failed_stack,
                (int)restored,
                (int)freed_code,
                (int)freed_stack);
            last_detail = detail;
            log_msg(hf, tag, "INFO -- controlled step fixture candidate rejected: %s", last_detail.c_str());
            continue;
        }

        fx = trial;
        log_msg(hf, tag, "INFO -- controlled step fixture tid=%u entry=0x%llX expected=0x%llX stack=0x%llX original_suspend=%u candidates=%zu",
            fx.tid,
            (unsigned long long)fx.code,
            (unsigned long long)fx.expected_rip,
            (unsigned long long)fx.rsp,
            (unsigned)fx.original_suspend_count,
            candidates.size());
        return true;
    }

    log_msg(hf, tag, "FAIL -- could not build controlled step fixture across %zu candidate thread(s); last=%s",
        candidates.size(),
        last_detail.c_str());
    return false;
}

static void scrub_target_hardware_breakpoints(HANDLE hf, const char* reason) {
    debugger_engine::clear_all_breakpoints();

    const uint32_t pid = driver_bridge::attached_pid();
    auto tids = bounded_hardware_breakpoint_tids(2);
    int target_threads = 0;
    int clear_ok = 0;
    int clear_fail = 0;

    for (uint32_t tid : tids) {
        ++target_threads;
        for (int slot = 0; slot < 4; ++slot) {
            if (driver_bridge::clear_hardware_breakpoint(tid, slot))
                ++clear_ok;
            else
                ++clear_fail;
        }
    }

    Sleep(10);
    log_msg(hf, "dbg_hwclr",
        "scrub reason=%s pid=%u target_threads=%d clear_ok=%d clear_fail=%d",
        reason ? reason : "unspecified",
        static_cast<unsigned>(pid),
        target_threads,
        clear_ok,
        clear_fail);
}

static bool verify_target_hardware_breakpoints_cleared(HANDLE hf, const char* reason) {
    const uint32_t pid = driver_bridge::attached_pid();
    auto tids = bounded_hardware_breakpoint_tids(2);
    int target_threads = 0;
    int context_ok = 0;
    int context_fail = 0;
    int enabled_residual = 0;

    for (uint32_t tid : tids) {
        ++target_threads;
        driver_bridge::thread_context_t ctx{};
        if (!driver_bridge::get_thread_context(tid, ctx)) {
            ++context_fail;
            continue;
        }
        ++context_ok;
        if ((ctx.dr7 & 0xFFULL) != 0) {
            ++enabled_residual;
            log_msg(hf, "dbg_hwclr",
                "RESIDUAL -- reason=%s tid=%u dr0=0x%llX dr1=0x%llX dr2=0x%llX dr3=0x%llX dr6=0x%llX dr7=0x%llX",
                reason ? reason : "unspecified",
                static_cast<unsigned>(tid),
                static_cast<unsigned long long>(ctx.dr0),
                static_cast<unsigned long long>(ctx.dr1),
                static_cast<unsigned long long>(ctx.dr2),
                static_cast<unsigned long long>(ctx.dr3),
                static_cast<unsigned long long>(ctx.dr6),
                static_cast<unsigned long long>(ctx.dr7));
        }
    }

    log_msg(hf, "dbg_hwclr",
        "verify reason=%s pid=%u target_threads=%d context_ok=%d context_fail=%d enabled_residual=%d",
        reason ? reason : "unspecified",
        static_cast<unsigned>(pid),
        target_threads,
        context_ok,
        context_fail,
        enabled_residual);
    return enabled_residual == 0;
}

static void test_add_remove_hw_bp_common(HANDLE hf,
                                         std::atomic<int>& passed,
                                         std::atomic<int>& failed,
                                         const char* tag,
                                         const char* label,
                                         debugger_engine::bp_type_t type,
                                         const char* type_name,
                                         int size,
                                         const char* bp_name) {
    log_msg(hf, tag, "START -- %s", label);
    auto t0 = std::chrono::steady_clock::now();

    scrub_target_hardware_breakpoints(hf, tag);

    uint32_t selected_tid = 0;
    driver_bridge::thread_context_t selected_before{};
    if (!select_hardware_breakpoint_tid(hf, tag, selected_tid, &selected_before)) {
        failed.fetch_add(1);
        return;
    }

    uint64_t addr = alloc_target_bp_region(64);
    if (addr == 0) {
        log_msg(hf, tag, "FAIL -- alloc_target_bp_region returned 0 (no driver attach?)");
        failed.fetch_add(1);
        return;
    }

    diag::log_tagged_fmt("test_dbg_detail", "%s inputs: private_target_addr=0x%llX type=%s size=%d pid=%u",
        tag,
        (unsigned long long)addr,
        type_name ? type_name : "?",
        size,
        (unsigned)driver_bridge::attached_pid());

    int idx = debugger_engine::add_breakpoint(addr, type, bp_name ? bp_name : "test_hw_bp", "", size);
    int hw_slot = -1;
    if (idx >= 0) {
        std::lock_guard<std::mutex> lk(debugger_engine::g_state.bp_mutex);
        if (idx < static_cast<int>(debugger_engine::g_state.breakpoints.size()))
            hw_slot = debugger_engine::g_state.breakpoints[static_cast<std::size_t>(idx)].hw_slot;
    }
    driver_bridge::thread_context_t armed_ctx{};
    bool armed_ctx_ok = selected_tid != 0 && driver_bridge::get_thread_context(selected_tid, armed_ctx);
    bool armed = armed_ctx_ok && hw_slot >= 0 && hw_slot < 4 && ((armed_ctx.dr7 & (1ULL << (hw_slot * 2))) != 0);
    bool removed = false;
    if (idx >= 0)
        removed = debugger_engine::remove_breakpoint(idx);

    driver_bridge::thread_context_t clear_ctx{};
    bool clear_ctx_ok = selected_tid != 0 && driver_bridge::get_thread_context(selected_tid, clear_ctx);
    bool regs_clear = clear_ctx_ok && (hw_slot < 0 || (clear_ctx.dr7 & (1ULL << (hw_slot * 2))) == 0);
    if (!regs_clear)
        scrub_target_hardware_breakpoints(hf, tag);
    bool freed = driver_bridge::free_memory(addr);

    diag::log_tagged_fmt("test_dbg_detail",
        "%s result: private_target_addr=0x%llX selected_tid=%u add_breakpoint=>idx=%d hw_slot=%d armed=>%d remove_breakpoint=>%d regs_clear=>%d free=>%d before_dr7=0x%llX armed_dr7=0x%llX clear_dr7=0x%llX",
        tag,
        (unsigned long long)addr,
        static_cast<unsigned>(selected_tid),
        idx,
        hw_slot,
        (int)armed,
        (int)removed,
        (int)regs_clear,
        (int)freed,
        static_cast<unsigned long long>(selected_before.dr7),
        static_cast<unsigned long long>(armed_ctx.dr7),
        static_cast<unsigned long long>(clear_ctx.dr7));

    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - t0).count();
    if (idx >= 0 && hw_slot >= 0 && armed && removed && regs_clear && freed) {
        log_msg(hf, tag, "PASS -- %s idx=%d slot=%d tid=%u armed and removed ok (elapsed %lld ms)",
            label, idx, hw_slot, static_cast<unsigned>(selected_tid), (long long)ms);
        passed.fetch_add(1);
    } else {
        log_msg(hf, tag, "FAIL -- idx=%d hw_slot=%d armed=%d armed_ctx=%d removed=%d clear_ctx=%d regs_clear=%d free=%d (elapsed %lld ms)",
            idx, hw_slot, (int)armed, (int)armed_ctx_ok, (int)removed, (int)clear_ctx_ok, (int)regs_clear, (int)freed, (long long)ms);
        failed.fetch_add(1);
    }
}

static void test_add_remove_software_bp(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
    log_msg(hf, "dbg_bp", "START -- add and remove software breakpoint");
    auto t0 = std::chrono::steady_clock::now();

    uint64_t addr = alloc_target_bp_region();
    if (addr == 0) {
        log_msg(hf, "dbg_bp", "FAIL -- alloc_target_bp_region returned 0 (no driver attach?)");
        failed.fetch_add(1); return;
    }
    diag::log_tagged_fmt("test_dbg_detail", "dbg_bp inputs: addr=0x%llX type=software size=1 pid=%u",
        (unsigned long long)addr, (unsigned)driver_bridge::attached_pid());

    int idx = debugger_engine::add_breakpoint(addr, debugger_engine::bp_type_t::software, "test_sw_bp", "", 1);
    bool removed = debugger_engine::remove_breakpoint(idx);
    driver_bridge::free_memory(addr);
    diag::log_tagged_fmt("test_dbg_detail", "dbg_bp result: add_breakpoint=>idx=%d remove_breakpoint=>%d", idx, (int)removed);

    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - t0).count();
    if (idx >= 0 && removed) {
        log_msg(hf, "dbg_bp", "PASS -- sw bp idx=%d, removed ok (elapsed %lld ms)", idx, (long long)ms);
        passed.fetch_add(1);
    } else {
        log_msg(hf, "dbg_bp", "FAIL -- idx=%d (<0 means add failed) removed=%d (elapsed %lld ms)", idx, (int)removed, (long long)ms);
        failed.fetch_add(1);
    }
}

static void test_add_remove_hw_execute_bp(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
    test_add_remove_hw_bp_common(hf, passed, failed,
        "dbg_hwx",
        "hardware execute breakpoint on private target memory",
        debugger_engine::bp_type_t::hardware_execute,
        "hardware_execute",
        1,
        "test_hwx_bp");
}

static void test_add_remove_hw_write_bp(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
    test_add_remove_hw_bp_common(hf, passed, failed,
        "dbg_hww",
        "hardware write breakpoint on private target memory",
        debugger_engine::bp_type_t::hardware_write,
        "hardware_write",
        4,
        "test_hww_bp");
}

static void test_add_remove_hw_read_bp(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
    test_add_remove_hw_bp_common(hf, passed, failed,
        "dbg_hwr",
        "hardware read breakpoint on private target memory",
        debugger_engine::bp_type_t::hardware_read,
        "hardware_read",
        4,
        "test_hwr_bp");
}

static void test_toggle_breakpoint(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
    log_msg(hf, "dbg_tog", "START -- toggle breakpoint on/off");
    auto t0 = std::chrono::steady_clock::now();

    uint64_t addr = alloc_target_bp_region();
    if (addr == 0) { log_msg(hf, "dbg_tog", "FAIL -- alloc_target_bp_region returned 0 (no driver attach?)"); failed.fetch_add(1); return; }
    diag::log_tagged_fmt("test_dbg_detail", "dbg_tog inputs: addr=0x%llX type=software size=1 pid=%u",
        (unsigned long long)addr, (unsigned)driver_bridge::attached_pid());

    int idx = debugger_engine::add_breakpoint(addr, debugger_engine::bp_type_t::software, "test_toggle_bp", "", 1);
    bool t1_ok = debugger_engine::toggle_breakpoint(idx);
    bool t2_ok = debugger_engine::toggle_breakpoint(idx);
    debugger_engine::remove_breakpoint(idx);
    driver_bridge::free_memory(addr);
    diag::log_tagged_fmt("test_dbg_detail", "dbg_tog result: idx=%d toggle1=>%d toggle2=>%d", idx, (int)t1_ok, (int)t2_ok);

    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - t0).count();
    if (idx >= 0 && t1_ok && t2_ok) {
        log_msg(hf, "dbg_tog", "PASS -- toggled twice ok (elapsed %lld ms)", (long long)ms);
        passed.fetch_add(1);
    } else {
        log_msg(hf, "dbg_tog", "FAIL -- idx=%d t1=%d t2=%d (elapsed %lld ms)", idx, t1_ok, t2_ok, (long long)ms);
        failed.fetch_add(1);
    }
}

static void test_set_breakpoint_condition(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
    log_msg(hf, "dbg_cond", "START -- set breakpoint condition");
    auto t0 = std::chrono::steady_clock::now();

    uint64_t addr = alloc_target_bp_region();
    if (addr == 0) { log_msg(hf, "dbg_cond", "FAIL -- alloc_target_bp_region returned 0 (no driver attach?)"); failed.fetch_add(1); return; }
    diag::log_tagged_fmt("test_dbg_detail", "dbg_cond inputs: addr=0x%llX condition='rax == 0' pid=%u",
        (unsigned long long)addr, (unsigned)driver_bridge::attached_pid());

    int idx = debugger_engine::add_breakpoint(addr, debugger_engine::bp_type_t::software, "test_cond_bp", "", 1);
    bool ok = debugger_engine::set_breakpoint_condition(idx, "rax == 0");
    debugger_engine::remove_breakpoint(idx);
    driver_bridge::free_memory(addr);
    diag::log_tagged_fmt("test_dbg_detail", "dbg_cond result: idx=%d set_breakpoint_condition=>%d", idx, (int)ok);

    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - t0).count();
    if (idx >= 0 && ok) {
        log_msg(hf, "dbg_cond", "PASS -- condition set ok (elapsed %lld ms)", (long long)ms);
        passed.fetch_add(1);
    } else {
        log_msg(hf, "dbg_cond", "FAIL -- idx=%d set=%d (elapsed %lld ms)", idx, ok, (long long)ms);
        failed.fetch_add(1);
    }
}

static void test_set_breakpoint_log(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
    log_msg(hf, "dbg_log", "START -- set breakpoint log message");
    auto t0 = std::chrono::steady_clock::now();

    uint64_t addr = alloc_target_bp_region();
    if (addr == 0) { log_msg(hf, "dbg_log", "FAIL -- alloc_target_bp_region returned 0 (no driver attach?)"); failed.fetch_add(1); return; }
    diag::log_tagged_fmt("test_dbg_detail", "dbg_log inputs: addr=0x%llX log_text='hit bp' auto_continue=1 pid=%u",
        (unsigned long long)addr, (unsigned)driver_bridge::attached_pid());

    int idx = debugger_engine::add_breakpoint(addr, debugger_engine::bp_type_t::software, "test_log_bp", "", 1);
    bool ok = debugger_engine::set_breakpoint_log(idx, "hit bp", true);
    debugger_engine::remove_breakpoint(idx);
    driver_bridge::free_memory(addr);
    diag::log_tagged_fmt("test_dbg_detail", "dbg_log result: idx=%d set_breakpoint_log=>%d", idx, (int)ok);

    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - t0).count();
    if (idx >= 0 && ok) {
        log_msg(hf, "dbg_log", "PASS -- log message set ok, auto_continue=true (elapsed %lld ms)", (long long)ms);
        passed.fetch_add(1);
    } else {
        log_msg(hf, "dbg_log", "FAIL -- idx=%d set=%d (elapsed %lld ms)", idx, ok, (long long)ms);
        failed.fetch_add(1);
    }
}

static void test_snapshot_breakpoints(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
    log_msg(hf, "dbg_snap", "START -- snapshot all breakpoints");
    auto t0 = std::chrono::steady_clock::now();

    uint64_t addr = alloc_target_bp_region();
    if (addr == 0) { log_msg(hf, "dbg_snap", "FAIL -- alloc_target_bp_region returned 0 (no driver attach?)"); failed.fetch_add(1); return; }
    diag::log_tagged_fmt("test_dbg_detail", "dbg_snap inputs: addr=0x%llX type=software size=1 pid=%u",
        (unsigned long long)addr, (unsigned)driver_bridge::attached_pid());

    int idx = debugger_engine::add_breakpoint(addr, debugger_engine::bp_type_t::software, "test_snap_bp", "", 1);
    auto bps = debugger_engine::snapshot_breakpoints();
    bool found = false;
    for (const auto& bp : bps) {
        if (bp.address == addr) { found = true; break; }
    }
    debugger_engine::remove_breakpoint(idx);
    driver_bridge::free_memory(addr);
    diag::log_tagged_fmt("test_dbg_detail", "dbg_snap result: idx=%d snapshot_size=%zu found_added=%d", idx, bps.size(), (int)found);

    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - t0).count();
    if (idx >= 0 && !bps.empty() && found) {
        log_msg(hf, "dbg_snap", "PASS -- snapshot returned %zu breakpoints, added bp present (elapsed %lld ms)", bps.size(), (long long)ms);
        passed.fetch_add(1);
    } else {
        log_msg(hf, "dbg_snap", "FAIL -- idx=%d snapshot_size=%zu added_bp_found=%d (snapshot must contain the just-added bp) (elapsed %lld ms)",
            idx, bps.size(), (int)found, (long long)ms);
        failed.fetch_add(1);
    }
}

static void test_clear_all_breakpoints(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
    log_msg(hf, "dbg_clr", "START -- clear all breakpoints");
    auto t0 = std::chrono::steady_clock::now();

    uint64_t a1 = alloc_target_bp_region();
    uint64_t a2 = alloc_target_bp_region();
    if (a1 == 0 || a2 == 0) {
        if (a1) driver_bridge::free_memory(a1);
        if (a2) driver_bridge::free_memory(a2);
        log_msg(hf, "dbg_clr", "FAIL -- alloc_target_bp_region returned 0 (no driver attach?)"); failed.fetch_add(1); return;
    }
    diag::log_tagged_fmt("test_dbg_detail", "dbg_clr inputs: addr1=0x%llX addr2=0x%llX pid=%u",
        (unsigned long long)a1, (unsigned long long)a2, (unsigned)driver_bridge::attached_pid());

    debugger_engine::add_breakpoint(a1, debugger_engine::bp_type_t::software, "test_clr1", "", 1);
    debugger_engine::add_breakpoint(a2, debugger_engine::bp_type_t::software, "test_clr2", "", 1);
    debugger_engine::clear_all_breakpoints();
    auto bps = debugger_engine::snapshot_breakpoints();
    driver_bridge::free_memory(a1);
    driver_bridge::free_memory(a2);
    diag::log_tagged_fmt("test_dbg_detail", "dbg_clr result: snapshot_size_after_clear=%zu", bps.size());

    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - t0).count();
    if (bps.empty()) {
        log_msg(hf, "dbg_clr", "PASS -- all breakpoints cleared (elapsed %lld ms)", (long long)ms);
        passed.fetch_add(1);
    } else {
        log_msg(hf, "dbg_clr", "FAIL -- %zu breakpoints remain after clear (elapsed %lld ms)", bps.size(), (long long)ms);
        failed.fetch_add(1);
    }
}

static void test_get_registers(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
    log_msg(hf, "dbg_reg", "START -- get registers");
    auto t0 = std::chrono::steady_clock::now();

    diag::log_tagged_fmt("test_dbg_detail", "dbg_reg inputs: get_registers() driver_loaded=%d attached_pid=%u",
        (int)driver_bridge::is_loaded(), (unsigned)driver_bridge::attached_pid());

    auto regs = debugger_engine::get_registers();
    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - t0).count();

    diag::log_tagged_fmt("test_dbg_detail",
        "dbg_reg result: rip=0x%llX rsp=0x%llX rbp=0x%llX cs=0x%llX ss=0x%llX rflags=0x%llX",
        (unsigned long long)regs.rip, (unsigned long long)regs.rsp, (unsigned long long)regs.rbp,
        (unsigned long long)regs.cs, (unsigned long long)regs.ss, (unsigned long long)regs.rflags);

    if (regs.rip != 0 && regs.rsp != 0) {
        log_msg(hf, "dbg_reg", "PASS -- rax=0x%llX rbx=0x%llX rcx=0x%llX rdx=0x%llX rip=0x%llX rsp=0x%llX rflags=0x%llX (elapsed %lld ms)",
            (unsigned long long)regs.rax, (unsigned long long)regs.rbx,
            (unsigned long long)regs.rcx, (unsigned long long)regs.rdx,
            (unsigned long long)regs.rip, (unsigned long long)regs.rsp,
            (unsigned long long)regs.rflags, (long long)ms);
        passed.fetch_add(1);
    } else {
        log_msg(hf, "dbg_reg", "FAIL -- live thread cannot have rip=0x%llX rsp=0x%llX (both must be non-zero); engine returned empty regs (not attached or context read failed) (elapsed %lld ms)",
            (unsigned long long)regs.rip, (unsigned long long)regs.rsp, (long long)ms);
        failed.fetch_add(1);
    }
}

static void test_cached_registers(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
    log_msg(hf, "dbg_creg", "START -- get cached registers");
    auto t0 = std::chrono::steady_clock::now();

    diag::log_tagged_fmt("test_dbg_detail", "dbg_creg inputs: request_refresh(0) then cached_registers() driver_loaded=%d attached_pid=%u",
        (int)driver_bridge::is_loaded(), (unsigned)driver_bridge::attached_pid());

    debugger_engine::request_refresh(0);
    Sleep(300);
    auto regs = debugger_engine::cached_registers();
    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - t0).count();

    diag::log_tagged_fmt("test_dbg_detail", "dbg_creg result: cached rip=0x%llX rsp=0x%llX rax=0x%llX",
        (unsigned long long)regs.rip, (unsigned long long)regs.rsp, (unsigned long long)regs.rax);

    if (regs.rip != 0 && regs.rsp != 0) {
        log_msg(hf, "dbg_creg", "PASS -- cached rax=0x%llX rsp=0x%llX rip=0x%llX (elapsed %lld ms)",
            (unsigned long long)regs.rax, (unsigned long long)regs.rsp,
            (unsigned long long)regs.rip, (long long)ms);
        passed.fetch_add(1);
    } else {
        log_msg(hf, "dbg_creg", "FAIL -- cache not populated after refresh: rip=0x%llX rsp=0x%llX (both must be non-zero for a live thread) (elapsed %lld ms)",
            (unsigned long long)regs.rip, (unsigned long long)regs.rsp, (long long)ms);
        failed.fetch_add(1);
    }
}

static void test_get_call_stack(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
    log_msg(hf, "dbg_stk", "START -- get call stack");
    auto t0 = std::chrono::steady_clock::now();

    diag::log_tagged_fmt("test_dbg_detail", "dbg_stk inputs: get_call_stack() driver_loaded=%d attached_pid=%u",
        (int)driver_bridge::is_loaded(), (unsigned)driver_bridge::attached_pid());

    auto frames = debugger_engine::get_call_stack();
    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - t0).count();

    uint64_t top_addr = frames.empty() ? 0 : frames.front().address;
    diag::log_tagged_fmt("test_dbg_detail", "dbg_stk result: frame_count=%zu top_addr=0x%llX",
        frames.size(), (unsigned long long)top_addr);
    for (size_t i = 0; i < frames.size() && i < 8; ++i) {
        log_msg(hf, "dbg_stk", "  frame[%zu]: addr=0x%llX ret=0x%llX module=%s func=%s",
            i, (unsigned long long)frames[i].address, (unsigned long long)frames[i].return_addr,
            frames[i].module_name.c_str(), frames[i].function_name.c_str());
    }

    if (!frames.empty() && top_addr != 0) {
        log_msg(hf, "dbg_stk", "PASS -- %zu stack frames, top addr=0x%llX (elapsed %lld ms)",
            frames.size(), (unsigned long long)top_addr, (long long)ms);
        passed.fetch_add(1);
    } else {
        log_msg(hf, "dbg_stk", "FAIL -- call stack empty (frames=%zu top_addr=0x%llX); a live thread always yields >=1 frame at RIP (elapsed %lld ms)",
            frames.size(), (unsigned long long)top_addr, (long long)ms);
        failed.fetch_add(1);
    }
}

static void test_get_memory_map(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
    log_msg(hf, "dbg_mmap", "START -- get memory map");
    auto t0 = std::chrono::steady_clock::now();

    diag::log_tagged_fmt("test_dbg_detail", "dbg_mmap inputs: get_memory_map() driver_loaded=%d attached_pid=%u",
        (int)driver_bridge::is_loaded(), (unsigned)driver_bridge::attached_pid());

    auto regions = debugger_engine::get_memory_map();
    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - t0).count();

    size_t exec_count = 0;
    for (auto& r : regions) {
        uint32_t prot = r.protect & 0xFF;
        if (prot == 0x10 || prot == 0x20 || prot == 0x40 || prot == 0x80) exec_count++;
    }
    diag::log_tagged_fmt("test_dbg_detail", "dbg_mmap result: region_count=%zu exec_count=%zu", regions.size(), exec_count);

    if (!regions.empty()) {
        log_msg(hf, "dbg_mmap", "PASS -- %zu regions total, %zu executable (elapsed %lld ms)",
            regions.size(), exec_count, (long long)ms);
        passed.fetch_add(1);
    } else {
        log_msg(hf, "dbg_mmap", "FAIL -- memory map empty (0 regions); an attached live process always has mapped regions (elapsed %lld ms)", (long long)ms);
        failed.fetch_add(1);
    }
}

static void test_get_thread_list(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
    log_msg(hf, "dbg_thr", "START -- get thread list");
    auto t0 = std::chrono::steady_clock::now();

    diag::log_tagged_fmt("test_dbg_detail", "dbg_thr inputs: request_thread_refresh(0) then cached_thread_list() driver_loaded=%d attached_pid=%u",
        (int)driver_bridge::is_loaded(), (unsigned)driver_bridge::attached_pid());

    debugger_engine::request_thread_refresh(0);
    Sleep(300);
    auto threads = debugger_engine::cached_thread_list();
    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - t0).count();

    diag::log_tagged_fmt("test_dbg_detail", "dbg_thr result: thread_count=%zu", threads.size());
    for (size_t i = 0; i < threads.size() && i < 10; ++i) {
        log_msg(hf, "dbg_thr", "  thread[%zu]: tid=%u pid=%u priority=%d state=%u rip=0x%llX",
            i, threads[i].tid, threads[i].owner_pid, threads[i].priority,
            threads[i].state, (unsigned long long)threads[i].rip);
    }

    if (!threads.empty()) {
        log_msg(hf, "dbg_thr", "PASS -- %zu threads (elapsed %lld ms)", threads.size(), (long long)ms);
        passed.fetch_add(1);
    } else {
        log_msg(hf, "dbg_thr", "FAIL -- thread list empty (0 threads); every process has >=1 thread (elapsed %lld ms)", (long long)ms);
        failed.fetch_add(1);
    }
}

static void test_add_remove_watch(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
    log_msg(hf, "dbg_wat", "START -- add and remove watch expression");
    auto t0 = std::chrono::steady_clock::now();

    diag::log_tagged_fmt("test_dbg_detail", "dbg_wat inputs: add_watch('rax') then remove_watch");
    int idx = debugger_engine::add_watch("rax");
    bool removed = debugger_engine::remove_watch(idx);
    diag::log_tagged_fmt("test_dbg_detail", "dbg_wat result: add_watch=>idx=%d remove_watch=>%d", idx, (int)removed);

    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - t0).count();
    if (idx >= 0 && removed) {
        log_msg(hf, "dbg_wat", "PASS -- watch idx=%d, removed ok (elapsed %lld ms)", idx, (long long)ms);
        passed.fetch_add(1);
    } else {
        log_msg(hf, "dbg_wat", "FAIL -- idx=%d (<0 means add failed) removed=%d (elapsed %lld ms)", idx, (int)removed, (long long)ms);
        failed.fetch_add(1);
    }
}

static void test_refresh_watches(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
    log_msg(hf, "dbg_wrfr", "START -- refresh watches");
    auto t0 = std::chrono::steady_clock::now();

    diag::log_tagged_fmt("test_dbg_detail", "dbg_wrfr inputs: add_watch('rsp') refresh_watches() driver_loaded=%d attached_pid=%u",
        (int)driver_bridge::is_loaded(), (unsigned)driver_bridge::attached_pid());

    int idx = debugger_engine::add_watch("rsp");
    debugger_engine::refresh_watches();

    auto watches = debugger_engine::snapshot_watches();
    bool evaluated = false;
    std::string value;
    std::string error;
    for (const auto& w : watches) {
        if (w.expression == "rsp") {
            evaluated = w.valid && !w.value.empty() && w.error.empty();
            value = w.value;
            error = w.error;
            break;
        }
    }
    debugger_engine::remove_watch(idx);
    diag::log_tagged_fmt("test_dbg_detail", "dbg_wrfr result: idx=%d valid_value='%s' error='%s'",
        idx, value.c_str(), error.c_str());

    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - t0).count();
    if (idx >= 0 && evaluated) {
        log_msg(hf, "dbg_wrfr", "PASS -- 'rsp' watch evaluated to \"%s\" (elapsed %lld ms)", value.c_str(), (long long)ms);
        passed.fetch_add(1);
    } else {
        log_msg(hf, "dbg_wrfr", "FAIL -- idx=%d watch not evaluated value=\"%s\" error=\"%s\" (rsp must resolve on a live target) (elapsed %lld ms)",
            idx, value.c_str(), error.c_str(), (long long)ms);
        failed.fetch_add(1);
    }
}

static void test_snapshot_watches(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
    log_msg(hf, "dbg_wsn", "START -- snapshot watches");
    auto t0 = std::chrono::steady_clock::now();

    diag::log_tagged_fmt("test_dbg_detail", "dbg_wsn inputs: add_watch('rbp') then snapshot_watches()");
    int idx = debugger_engine::add_watch("rbp");
    auto watches = debugger_engine::snapshot_watches();
    bool found = false;
    for (const auto& w : watches) {
        if (w.expression == "rbp") { found = true; break; }
    }
    debugger_engine::remove_watch(idx);
    diag::log_tagged_fmt("test_dbg_detail", "dbg_wsn result: idx=%d snapshot_size=%zu found_added=%d", idx, watches.size(), (int)found);

    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - t0).count();
    if (idx >= 0 && !watches.empty() && found) {
        log_msg(hf, "dbg_wsn", "PASS -- snapshot returned %zu watches, added watch present (elapsed %lld ms)", watches.size(), (long long)ms);
        passed.fetch_add(1);
    } else {
        log_msg(hf, "dbg_wsn", "FAIL -- idx=%d snapshot_size=%zu added_watch_found=%d (snapshot must contain the just-added watch) (elapsed %lld ms)",
            idx, watches.size(), (int)found, (long long)ms);
        failed.fetch_add(1);
    }
}

static void test_start_stop_trace(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
    log_msg(hf, "dbg_trc", "START -- start and stop trace");
    auto t0 = std::chrono::steady_clock::now();

    debugger_engine::stop_trace();
    diag::log_tagged_fmt("test_dbg_detail", "dbg_trc inputs: start_trace(1000) then stop_trace()");

    bool started = debugger_engine::start_trace(1000);
    bool tracing_active = debugger_engine::g_state.tracing.load();
    bool stopped = debugger_engine::stop_trace();
    bool tracing_cleared = !debugger_engine::g_state.tracing.load();
    diag::log_tagged_fmt("test_dbg_detail", "dbg_trc result: start=>%d tracing_active=%d stop=>%d tracing_cleared=%d",
        (int)started, (int)tracing_active, (int)stopped, (int)tracing_cleared);

    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - t0).count();
    if (started && tracing_active && stopped && tracing_cleared) {
        log_msg(hf, "dbg_trc", "PASS -- start=%d (tracing flag set) stop=%d (flag cleared) (elapsed %lld ms)",
            (int)started, (int)stopped, (long long)ms);
        passed.fetch_add(1);
    } else {
        log_msg(hf, "dbg_trc", "FAIL -- start=%d tracing_active=%d stop=%d tracing_cleared=%d (start must set tracing, stop must clear it) (elapsed %lld ms)",
            (int)started, (int)tracing_active, (int)stopped, (int)tracing_cleared, (long long)ms);
        failed.fetch_add(1);
    }
}

static void test_set_get_comment(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
    log_msg(hf, "dbg_cmt", "START -- set and get comment at address");
    auto t0 = std::chrono::steady_clock::now();

    uint64_t addr = get_ntdll_fn("NtClose");
    if (addr == 0) { log_msg(hf, "dbg_cmt", "FAIL -- NtClose not found"); failed.fetch_add(1); return; }
    diag::log_tagged_fmt("test_dbg_detail", "dbg_cmt inputs: addr=0x%llX set_comment='test_comment_12345'", (unsigned long long)addr);

    debugger_engine::set_comment(addr, "test_comment_12345");
    std::string got = debugger_engine::get_comment(addr);
    debugger_engine::set_comment(addr, "");
    diag::log_tagged_fmt("test_dbg_detail", "dbg_cmt result: get_comment=>'%s'", got.c_str());

    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - t0).count();
    if (got == "test_comment_12345") {
        log_msg(hf, "dbg_cmt", "PASS -- comment round-trip ok: \"%s\" (elapsed %lld ms)", got.c_str(), (long long)ms);
        passed.fetch_add(1);
    } else {
        log_msg(hf, "dbg_cmt", "FAIL -- expected \"test_comment_12345\" got \"%s\" (elapsed %lld ms)", got.c_str(), (long long)ms);
        failed.fetch_add(1);
    }
}

static void test_set_get_label(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
    log_msg(hf, "dbg_lbl", "START -- set and get label at address");
    auto t0 = std::chrono::steady_clock::now();

    uint64_t addr = get_ntdll_fn("NtClose");
    if (addr == 0) { log_msg(hf, "dbg_lbl", "FAIL -- NtClose not found"); failed.fetch_add(1); return; }
    diag::log_tagged_fmt("test_dbg_detail", "dbg_lbl inputs: addr=0x%llX set_label='test_label_67890'", (unsigned long long)addr);

    debugger_engine::set_label(addr, "test_label_67890");
    std::string got = debugger_engine::get_label(addr);
    debugger_engine::set_label(addr, "");
    diag::log_tagged_fmt("test_dbg_detail", "dbg_lbl result: get_label=>'%s'", got.c_str());

    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - t0).count();
    if (got == "test_label_67890") {
        log_msg(hf, "dbg_lbl", "PASS -- label round-trip ok: \"%s\" (elapsed %lld ms)", got.c_str(), (long long)ms);
        passed.fetch_add(1);
    } else {
        log_msg(hf, "dbg_lbl", "FAIL -- expected \"test_label_67890\" got \"%s\" (elapsed %lld ms)", got.c_str(), (long long)ms);
        failed.fetch_add(1);
    }
}

static void test_toggle_bookmark(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
    log_msg(hf, "dbg_bkm", "START -- toggle bookmark");
    auto t0 = std::chrono::steady_clock::now();

    uint64_t addr = get_ntdll_fn("NtClose");
    if (addr == 0) { log_msg(hf, "dbg_bkm", "FAIL -- NtClose not found"); failed.fetch_add(1); return; }
    diag::log_tagged_fmt("test_dbg_detail", "dbg_bkm inputs: addr=0x%llX toggle on then off", (unsigned long long)addr);

    auto bookmark_present = [&](uint64_t a) -> bool {
        std::lock_guard<std::mutex> lk(debugger_engine::g_state.anno_mutex);
        for (uint64_t b : debugger_engine::g_state.bookmarks) {
            if (b == a) return true;
        }
        return false;
    };

    bool before = bookmark_present(addr);
    debugger_engine::toggle_bookmark(addr);
    bool after_on = bookmark_present(addr);
    debugger_engine::toggle_bookmark(addr);
    bool after_off = bookmark_present(addr);
    diag::log_tagged_fmt("test_dbg_detail", "dbg_bkm result: before=%d after_on=%d after_off=%d",
        (int)before, (int)after_on, (int)after_off);

    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - t0).count();
    if (after_on != before && after_off == before) {
        log_msg(hf, "dbg_bkm", "PASS -- bookmark toggled on (present=%d) then off (present=%d) (elapsed %lld ms)",
            (int)after_on, (int)after_off, (long long)ms);
        passed.fetch_add(1);
    } else {
        log_msg(hf, "dbg_bkm", "FAIL -- toggle did not flip state: before=%d after_on=%d after_off=%d (elapsed %lld ms)",
            (int)before, (int)after_on, (int)after_off, (long long)ms);
        failed.fetch_add(1);
    }
}

static void test_enumerate_handles(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
    log_msg(hf, "dbg_hdl", "START -- enumerate handles");
    auto t0 = std::chrono::steady_clock::now();

    diag::log_tagged_fmt("test_dbg_detail", "dbg_hdl inputs: enumerate_handles() driver_loaded=%d attached_pid=%u",
        (int)driver_bridge::is_loaded(), (unsigned)driver_bridge::attached_pid());

    debugger_engine::enumerate_handles();

    auto& state = debugger_engine::g_state;
    size_t count = 0;
    {
        std::lock_guard<std::mutex> lk(state.handle_mutex);
        count = state.handles.size();
    }
    diag::log_tagged_fmt("test_dbg_detail", "dbg_hdl result: handle_count=%zu", count);

    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - t0).count();
    if (count != 0) {
        log_msg(hf, "dbg_hdl", "PASS -- enumerated %zu handles (elapsed %lld ms)", count, (long long)ms);
        passed.fetch_add(1);
    } else {
        log_msg(hf, "dbg_hdl", "FAIL -- 0 handles enumerated; every attached process has open handles (not attached or query failed) (elapsed %lld ms)", (long long)ms);
        failed.fetch_add(1);
    }
}

static void test_find_strings(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
    log_msg(hf, "dbg_str", "START -- find strings (min_length=4)");
    auto t0 = std::chrono::steady_clock::now();

    diag::log_tagged_fmt("test_dbg_detail", "dbg_str inputs: find_strings_async(min_length=4) driver_loaded=%d attached_pid=%u",
        (int)driver_bridge::is_loaded(), (unsigned)driver_bridge::attached_pid());

    debugger_engine::find_strings_async(4);

    for (int i = 0; i < 150; ++i) {
        if (!debugger_engine::g_state.strings_scanning.load(std::memory_order_acquire))
            break;
        Sleep(100);
    }

    auto& state = debugger_engine::g_state;
    if (state.strings_scanning.load(std::memory_order_acquire)) {
        debugger_engine::request_strings_cancel();
        for (int i = 0; i < 50; ++i) {
            if (!state.strings_scanning.load(std::memory_order_acquire))
                break;
            Sleep(100);
        }
    }

    size_t count = 0;
    {
        std::lock_guard<std::mutex> lk(state.strings_mutex);
        count = state.strings.size();
    }
    uint64_t pages = state.strings_pages_scanned.load();
    diag::log_tagged_fmt("test_dbg_detail", "dbg_str result: string_count=%zu pages_scanned=%llu", count, (unsigned long long)pages);

    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - t0).count();
    if (count != 0) {
        log_msg(hf, "dbg_str", "PASS -- found %zu strings across %llu pages (elapsed %lld ms)", count, (unsigned long long)pages, (long long)ms);
        passed.fetch_add(1);
    } else {
        log_msg(hf, "dbg_str", "FAIL -- 0 strings found (pages_scanned=%llu); an attached process with mapped modules contains ASCII/wide strings (elapsed %lld ms)",
            (unsigned long long)pages, (long long)ms);
        failed.fetch_add(1);
    }
}

static void test_format_flags(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
    log_msg(hf, "dbg_fmt", "START -- format rflags");
    auto t0 = std::chrono::steady_clock::now();

    uint64_t test_flags = 0x246;
    diag::log_tagged_fmt("test_dbg_detail", "dbg_fmt inputs: format_flags(0x%llX)", (unsigned long long)test_flags);
    std::string formatted = debugger_engine::format_flags(test_flags);
    diag::log_tagged_fmt("test_dbg_detail", "dbg_fmt result: '%s'", formatted.c_str());

    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - t0).count();
    if (!formatted.empty()) {
        log_msg(hf, "dbg_fmt", "PASS -- flags 0x%llX => \"%s\" (elapsed %lld ms)",
            (unsigned long long)test_flags, formatted.c_str(), (long long)ms);
        passed.fetch_add(1);
    } else {
        log_msg(hf, "dbg_fmt", "FAIL -- format_flags returned empty (elapsed %lld ms)", (long long)ms);
        failed.fetch_add(1);
    }
}

static void test_format_protect(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
    log_msg(hf, "dbg_prt", "START -- format memory protection");
    auto t0 = std::chrono::steady_clock::now();

    diag::log_tagged_fmt("test_dbg_detail", "dbg_prt inputs: format_protect(EXECUTE_READWRITE, READONLY, READWRITE)");
    std::string p1 = debugger_engine::format_protect(PAGE_EXECUTE_READWRITE);
    std::string p2 = debugger_engine::format_protect(PAGE_READONLY);
    std::string p3 = debugger_engine::format_protect(PAGE_READWRITE);
    diag::log_tagged_fmt("test_dbg_detail", "dbg_prt result: p1='%s' p2='%s' p3='%s'", p1.c_str(), p2.c_str(), p3.c_str());

    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - t0).count();
    if (!p1.empty() && !p2.empty() && !p3.empty()) {
        log_msg(hf, "dbg_prt", "PASS -- ERW=\"%s\" R=\"%s\" RW=\"%s\" (elapsed %lld ms)",
            p1.c_str(), p2.c_str(), p3.c_str(), (long long)ms);
        passed.fetch_add(1);
    } else {
        log_msg(hf, "dbg_prt", "FAIL -- format_protect returned empty (elapsed %lld ms)", (long long)ms);
        failed.fetch_add(1);
    }
}

static void test_request_refresh(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
    log_msg(hf, "dbg_rfr", "START -- request refresh operations");
    auto t0 = std::chrono::steady_clock::now();

    diag::log_tagged_fmt("test_dbg_detail", "dbg_rfr inputs: request_refresh(0)+request_thread_refresh(0) driver_loaded=%d attached_pid=%u",
        (int)driver_bridge::is_loaded(), (unsigned)driver_bridge::attached_pid());

    debugger_engine::request_refresh(0);
    debugger_engine::request_thread_refresh(0);
    Sleep(400);

    auto regs = debugger_engine::cached_registers();
    auto threads = debugger_engine::cached_thread_list();
    diag::log_tagged_fmt("test_dbg_detail", "dbg_rfr result: cached rip=0x%llX rsp=0x%llX thread_count=%zu",
        (unsigned long long)regs.rip, (unsigned long long)regs.rsp, threads.size());

    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - t0).count();
    if (regs.rip != 0 && regs.rsp != 0 && !threads.empty()) {
        log_msg(hf, "dbg_rfr", "PASS -- refresh populated caches: rip=0x%llX rsp=0x%llX threads=%zu (elapsed %lld ms)",
            (unsigned long long)regs.rip, (unsigned long long)regs.rsp, threads.size(), (long long)ms);
        passed.fetch_add(1);
    } else {
        log_msg(hf, "dbg_rfr", "FAIL -- caches not populated after refresh: rip=0x%llX rsp=0x%llX threads=%zu (elapsed %lld ms)",
            (unsigned long long)regs.rip, (unsigned long long)regs.rsp, threads.size(), (long long)ms);
        failed.fetch_add(1);
    }
}

static void test_get_disasm_window(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
    log_msg(hf, "dbg_dasm", "START -- get disasm window");
    auto t0 = std::chrono::steady_clock::now();

    uint64_t addr = get_ntdll_fn("NtClose");
    if (addr == 0) { log_msg(hf, "dbg_dasm", "FAIL -- NtClose not found"); failed.fetch_add(1); return; }
    diag::log_tagged_fmt("test_dbg_detail", "dbg_dasm inputs: request_disasm_refresh(addr=0x%llX, max_age=0) driver_loaded=%d attached_pid=%u",
        (unsigned long long)addr, (int)driver_bridge::is_loaded(), (unsigned)driver_bridge::attached_pid());

    debugger_engine::request_disasm_refresh(addr, 0);
    Sleep(300);

    uint64_t base_out = 0;
    auto bytes = debugger_engine::cached_disasm_window(base_out);
    diag::log_tagged_fmt("test_dbg_detail", "dbg_dasm result: byte_count=%zu base=0x%llX", bytes.size(), (unsigned long long)base_out);

    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - t0).count();
    if (!bytes.empty() && base_out != 0) {
        log_msg(hf, "dbg_dasm", "PASS -- disasm window %zu bytes at base 0x%llX (elapsed %lld ms)",
            bytes.size(), (unsigned long long)base_out, (long long)ms);
        passed.fetch_add(1);
    } else {
        log_msg(hf, "dbg_dasm", "FAIL -- disasm window empty: bytes=%zu base=0x%llX (target read returned no code) (elapsed %lld ms)",
            bytes.size(), (unsigned long long)base_out, (long long)ms);
        failed.fetch_add(1);
    }
}

static void test_get_stack_bytes(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
    log_msg(hf, "dbg_stkb", "START -- get stack bytes");
    auto t0 = std::chrono::steady_clock::now();

    auto regs = debugger_engine::get_registers();
    diag::log_tagged_fmt("test_dbg_detail", "dbg_stkb inputs: rsp=0x%llX request_stack_refresh(rsp, 256, 0) attached_pid=%u",
        (unsigned long long)regs.rsp, (unsigned)driver_bridge::attached_pid());

    if (regs.rsp == 0) {
        auto ms0 = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - t0).count();
        log_msg(hf, "dbg_stkb", "FAIL -- rsp is 0; cannot read stack of a live thread (not attached) (elapsed %lld ms)", (long long)ms0);
        failed.fetch_add(1);
        return;
    }

    debugger_engine::request_stack_refresh(regs.rsp, 256, 0);
    Sleep(300);

    uint64_t addr_out = 0;
    auto bytes = debugger_engine::cached_stack_bytes(addr_out);
    diag::log_tagged_fmt("test_dbg_detail", "dbg_stkb result: byte_count=%zu addr=0x%llX", bytes.size(), (unsigned long long)addr_out);

    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - t0).count();
    if (!bytes.empty() && addr_out != 0) {
        log_msg(hf, "dbg_stkb", "PASS -- stack %zu bytes at addr 0x%llX (elapsed %lld ms)",
            bytes.size(), (unsigned long long)addr_out, (long long)ms);
        passed.fetch_add(1);
    } else {
        log_msg(hf, "dbg_stkb", "FAIL -- stack read empty: bytes=%zu addr=0x%llX (rsp=0x%llX) (elapsed %lld ms)",
            bytes.size(), (unsigned long long)addr_out, (unsigned long long)regs.rsp, (long long)ms);
        failed.fetch_add(1);
    }
}

static void test_last_error(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
    log_msg(hf, "dbg_err", "START -- last_error() accessor");
    auto t0 = std::chrono::steady_clock::now();

    diag::log_tagged_fmt("test_dbg_detail", "dbg_err inputs: last_error() driver_loaded=%d attached_pid=%u",
        (int)driver_bridge::is_loaded(), (unsigned)driver_bridge::attached_pid());

    const std::string& err = debugger_engine::last_error();
    diag::log_tagged_fmt("test_dbg_detail", "dbg_err result: last_error='%s'", err.empty() ? "(empty)" : err.c_str());

    bool has_fatal = (err.find("not attached") != std::string::npos)
                  || (err.find("must be non-zero") != std::string::npos)
                  || (err.find("<read error>") != std::string::npos);

    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - t0).count();
    if (!has_fatal) {
        log_msg(hf, "dbg_err", "PASS -- last_error=\"%s\" (no fatal engine error pending) (elapsed %lld ms)",
            err.empty() ? "(empty)" : err.c_str(), (long long)ms);
        passed.fetch_add(1);
    } else {
        log_msg(hf, "dbg_err", "FAIL -- engine has fatal error pending: last_error=\"%s\" (elapsed %lld ms)",
            err.c_str(), (long long)ms);
        failed.fetch_add(1);
    }
}

static void test_memory_access_bp(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
    log_msg(hf, "dbg_ma", "START -- add and remove memory_access breakpoint");
    auto t0 = std::chrono::steady_clock::now();

    uint64_t addr = alloc_target_bp_region();
    if (addr == 0) { log_msg(hf, "dbg_ma", "FAIL -- alloc_target_bp_region returned 0 (no driver attach?)"); failed.fetch_add(1); return; }
    diag::log_tagged_fmt("test_dbg_detail", "dbg_ma inputs: private_target_addr=0x%llX type=memory_access size=4 pid=%u",
        (unsigned long long)addr, (unsigned)driver_bridge::attached_pid());

    int idx = debugger_engine::add_breakpoint(addr, debugger_engine::bp_type_t::memory_access, "test_ma_bp", "", 4);
    bool removed = idx >= 0 && debugger_engine::remove_breakpoint(idx);
    bool freed = driver_bridge::free_memory(addr);
    diag::log_tagged_fmt("test_dbg_detail", "dbg_ma result: add_breakpoint=>idx=%d remove_breakpoint=>%d free=>%d", idx, (int)removed, (int)freed);

    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - t0).count();
    if (idx >= 0 && removed) {
        log_msg(hf, "dbg_ma", "PASS -- memory_access bp idx=%d, removed ok (elapsed %lld ms)", idx, (long long)ms);
        passed.fetch_add(1);
    } else {
        log_msg(hf, "dbg_ma", "FAIL -- idx=%d (<0 means add failed) removed=%d (elapsed %lld ms)", idx, (int)removed, (long long)ms);
        failed.fetch_add(1);
    }
}

static void test_multiple_breakpoints(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
    log_msg(hf, "dbg_mbp", "START -- add multiple breakpoints, verify count, clear subset");
    auto t0 = std::chrono::steady_clock::now();

    debugger_engine::clear_all_breakpoints();

    uint64_t a1 = alloc_target_bp_region();
    uint64_t a2 = alloc_target_bp_region();
    uint64_t a3 = alloc_target_bp_region();
    uint64_t a4 = alloc_target_bp_region();
    if (a1 == 0 || a2 == 0 || a3 == 0 || a4 == 0) {
        if (a1) driver_bridge::free_memory(a1);
        if (a2) driver_bridge::free_memory(a2);
        if (a3) driver_bridge::free_memory(a3);
        if (a4) driver_bridge::free_memory(a4);
        log_msg(hf, "dbg_mbp", "FAIL -- alloc_target_bp_region returned 0 (no driver attach?)");
        failed.fetch_add(1);
        return;
    }

    diag::log_tagged_fmt("test_dbg_detail", "dbg_mbp inputs: a1=0x%llX a2=0x%llX a3=0x%llX a4=0x%llX",
        (unsigned long long)a1, (unsigned long long)a2, (unsigned long long)a3, (unsigned long long)a4);

    int i1 = debugger_engine::add_breakpoint(a1, debugger_engine::bp_type_t::software, "mbp_1", "", 1);
    int i2 = debugger_engine::add_breakpoint(a2, debugger_engine::bp_type_t::software, "mbp_2", "", 1);
    int i3 = debugger_engine::add_breakpoint(a3, debugger_engine::bp_type_t::software, "mbp_3", "", 1);
    int i4 = debugger_engine::add_breakpoint(a4, debugger_engine::bp_type_t::software, "mbp_4", "", 1);

    auto snap1 = debugger_engine::snapshot_breakpoints();
    size_t count_before = snap1.size();

    debugger_engine::remove_breakpoint(i2);
    debugger_engine::remove_breakpoint(i3);

    auto snap2 = debugger_engine::snapshot_breakpoints();
    size_t count_after = snap2.size();
    diag::log_tagged_fmt("test_dbg_detail", "dbg_mbp result: idx=[%d,%d,%d,%d] count_before=%zu count_after=%zu",
        i1, i2, i3, i4, count_before, count_after);

    debugger_engine::remove_breakpoint(i1);
    debugger_engine::remove_breakpoint(i4);
    driver_bridge::free_memory(a1);
    driver_bridge::free_memory(a2);
    driver_bridge::free_memory(a3);
    driver_bridge::free_memory(a4);

    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - t0).count();
    if (i1 >= 0 && i2 >= 0 && i3 >= 0 && i4 >= 0 && count_before >= 4 && count_after == count_before - 2) {
        log_msg(hf, "dbg_mbp", "PASS -- 4 bps added (count=%zu), removed 2 (count=%zu) (elapsed %lld ms)",
            count_before, count_after, (long long)ms);
        passed.fetch_add(1);
    } else {
        log_msg(hf, "dbg_mbp", "FAIL -- before=%zu after=%zu (elapsed %lld ms)",
            count_before, count_after, (long long)ms);
        failed.fetch_add(1);
    }
}

static void test_hw_bp_size_1(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
    test_add_remove_hw_bp_common(hf, passed, failed,
        "dbg_hw1",
        "1-byte hardware write breakpoint on private target memory",
        debugger_engine::bp_type_t::hardware_write,
        "hardware_write",
        1,
        "hw_s1");
}

static void test_hw_bp_size_2(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
    test_add_remove_hw_bp_common(hf, passed, failed,
        "dbg_hw2",
        "2-byte hardware write breakpoint on private target memory",
        debugger_engine::bp_type_t::hardware_write,
        "hardware_write",
        2,
        "hw_s2");
}

static void test_hw_bp_size_8(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
    test_add_remove_hw_bp_common(hf, passed, failed,
        "dbg_hw8",
        "8-byte hardware write breakpoint on private target memory",
        debugger_engine::bp_type_t::hardware_write,
        "hardware_write",
        8,
        "hw_s8");
}

static void test_set_register(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
    log_msg(hf, "dbg_sreg", "START -- set_register API call");
    auto t0 = std::chrono::steady_clock::now();

    const uint64_t test_val = 0x41414141ULL;
    auto before = debugger_engine::get_registers();
    diag::log_tagged_fmt("test_dbg_detail", "dbg_sreg inputs: set_register('rax', 0x%llX) before_rax=0x%llX attached_pid=%u",
        (unsigned long long)test_val, (unsigned long long)before.rax, (unsigned)driver_bridge::attached_pid());

    bool ok = debugger_engine::set_register("rax", test_val);
    std::string err = debugger_engine::last_error();
    diag::log_tagged_fmt("test_dbg_detail", "dbg_sreg result: set_register=>%d last_error='%s' (return value is the authoritative kernel set_thread_context confirmation)",
        (int)ok, err.c_str());

    if (ok) {
        debugger_engine::set_register("rax", before.rax);
    }

    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - t0).count();
    if (ok) {
        log_msg(hf, "dbg_sreg", "PASS -- set_register(rax, 0x%llX) succeeded (kernel set_thread_context confirmed), original 0x%llX restored (elapsed %lld ms)",
            (unsigned long long)test_val, (unsigned long long)before.rax, (long long)ms);
        passed.fetch_add(1);
    } else {
        log_msg(hf, "dbg_sreg", "FAIL -- set_register returned 0; last_error=\"%s\" (not attached or kernel context write failed) (elapsed %lld ms)",
            err.empty() ? "(none)" : err.c_str(), (long long)ms);
        failed.fetch_add(1);
    }
}

static void test_step_into(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
    log_msg(hf, "dbg_si", "START -- step_into controlled nop fixture");
    auto t0 = std::chrono::steady_clock::now();

    if (!require_attached_live_target(hf, "dbg_si", failed))
        return;

    controlled_step_fixture_t fixture;
    std::vector<uint8_t> code{0x90, 0x90, 0x90, 0xC3};
    if (!prepare_controlled_step_fixture(hf, "dbg_si", fixture, code, false)) {
        failed.fetch_add(1);
        return;
    }

    auto before = debugger_engine::get_registers();
    diag::log_tagged_fmt("test_dbg_detail", "dbg_si inputs: step_into() before_rip=0x%llX expected=0x%llX attached_pid=%u tid=%u",
        (unsigned long long)before.rip,
        (unsigned long long)fixture.expected_rip,
        (unsigned)driver_bridge::attached_pid(),
        (unsigned)fixture.tid);

    bool ok = debugger_engine::step_into();
    auto after = debugger_engine::get_registers();
    std::string err = debugger_engine::last_error();
    bool restored = false;
    bool freed_code = false;
    bool freed_stack = false;
    cleanup_controlled_step_fixture(fixture, &restored, &freed_code, &freed_stack);
    diag::log_tagged_fmt("test_dbg_detail", "dbg_si result: step_into=>%d before_rip=0x%llX after_rip=0x%llX expected=0x%llX restored=%d free_code=%d last_error='%s'",
        (int)ok,
        (unsigned long long)before.rip,
        (unsigned long long)after.rip,
        (unsigned long long)fixture.expected_rip,
        (int)restored,
        (int)freed_code,
        err.c_str());

    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - t0).count();
    if (ok && after.rip == fixture.expected_rip && restored && freed_code && ms <= 5000) {
        log_msg(hf, "dbg_si", "PASS -- step_into advanced controlled rip 0x%llX -> 0x%llX and restored context (elapsed %lld ms)",
            (unsigned long long)before.rip,
            (unsigned long long)after.rip,
            (long long)ms);
        passed.fetch_add(1);
    } else {
        log_msg(hf, "dbg_si", "FAIL -- step_into returned %d (after_rip=0x%llX expected=0x%llX restored=%d free_code=%d); last_error=\"%s\" (elapsed %lld ms)",
            (int)ok,
            (unsigned long long)after.rip,
            (unsigned long long)fixture.expected_rip,
            (int)restored,
            (int)freed_code,
            err.empty() ? "(none)" : err.c_str(),
            (long long)ms);
        failed.fetch_add(1);
    }
}

static void test_step_over(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
    log_msg(hf, "dbg_so", "START -- step_over controlled nop fixture");
    auto t0 = std::chrono::steady_clock::now();

    if (!require_attached_live_target(hf, "dbg_so", failed))
        return;

    controlled_step_fixture_t fixture;
    std::vector<uint8_t> code{0x90, 0x90, 0x90, 0xC3};
    if (!prepare_controlled_step_fixture(hf, "dbg_so", fixture, code, false)) {
        failed.fetch_add(1);
        return;
    }

    auto before = debugger_engine::get_registers();
    diag::log_tagged_fmt("test_dbg_detail", "dbg_so inputs: step_over() before_rip=0x%llX expected=0x%llX attached_pid=%u tid=%u",
        (unsigned long long)before.rip,
        (unsigned long long)fixture.expected_rip,
        (unsigned)driver_bridge::attached_pid(),
        (unsigned)fixture.tid);

    bool ok = debugger_engine::step_over();
    auto after = debugger_engine::get_registers();
    std::string err = debugger_engine::last_error();
    bool restored = false;
    bool freed_code = false;
    bool freed_stack = false;
    cleanup_controlled_step_fixture(fixture, &restored, &freed_code, &freed_stack);
    diag::log_tagged_fmt("test_dbg_detail", "dbg_so result: step_over=>%d before_rip=0x%llX after_rip=0x%llX expected=0x%llX restored=%d free_code=%d last_error='%s'",
        (int)ok,
        (unsigned long long)before.rip,
        (unsigned long long)after.rip,
        (unsigned long long)fixture.expected_rip,
        (int)restored,
        (int)freed_code,
        err.c_str());

    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - t0).count();
    if (ok && after.rip == fixture.expected_rip && restored && freed_code && ms <= 5000) {
        log_msg(hf, "dbg_so", "PASS -- step_over advanced controlled rip 0x%llX -> 0x%llX and restored context (elapsed %lld ms)",
            (unsigned long long)before.rip,
            (unsigned long long)after.rip,
            (long long)ms);
        passed.fetch_add(1);
    } else {
        log_msg(hf, "dbg_so", "FAIL -- step_over returned %d (after_rip=0x%llX expected=0x%llX restored=%d free_code=%d); last_error=\"%s\" (elapsed %lld ms)",
            (int)ok,
            (unsigned long long)after.rip,
            (unsigned long long)fixture.expected_rip,
            (int)restored,
            (int)freed_code,
            err.empty() ? "(none)" : err.c_str(),
            (long long)ms);
        failed.fetch_add(1);
    }
}

static void test_step_out(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
    log_msg(hf, "dbg_sout", "START -- step_out controlled return fixture");
    auto t0 = std::chrono::steady_clock::now();

    if (!require_attached_live_target(hf, "dbg_sout", failed))
        return;

    controlled_step_fixture_t fixture;
    std::vector<uint8_t> code{0xC3, 0x90, 0x90, 0x90};
    if (!prepare_controlled_step_fixture(hf, "dbg_sout", fixture, code, true)) {
        failed.fetch_add(1);
        return;
    }

    auto before = debugger_engine::get_registers();
    diag::log_tagged_fmt("test_dbg_detail", "dbg_sout inputs: step_out() before_rip=0x%llX before_rsp=0x%llX expected=0x%llX attached_pid=%u tid=%u",
        (unsigned long long)before.rip,
        (unsigned long long)before.rsp,
        (unsigned long long)fixture.expected_rip,
        (unsigned)driver_bridge::attached_pid(),
        (unsigned)fixture.tid);

    bool ok = debugger_engine::step_out();
    auto after = debugger_engine::get_registers();
    std::string err = debugger_engine::last_error();
    bool restored = false;
    bool freed_code = false;
    bool freed_stack = false;
    cleanup_controlled_step_fixture(fixture, &restored, &freed_code, &freed_stack);
    diag::log_tagged_fmt("test_dbg_detail", "dbg_sout result: step_out=>%d after_rip=0x%llX after_rsp=0x%llX expected=0x%llX restored=%d free_code=%d free_stack=%d last_error='%s'",
        (int)ok,
        (unsigned long long)after.rip,
        (unsigned long long)after.rsp,
        (unsigned long long)fixture.expected_rip,
        (int)restored,
        (int)freed_code,
        (int)freed_stack,
        err.c_str());

    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - t0).count();
    if (ok && after.rip == fixture.expected_rip && restored && freed_code && freed_stack && ms <= 5000) {
        log_msg(hf, "dbg_sout", "PASS -- step_out reached controlled return 0x%llX and restored context (elapsed %lld ms)",
            (unsigned long long)after.rip,
            (long long)ms);
        passed.fetch_add(1);
    } else {
        log_msg(hf, "dbg_sout", "FAIL -- step_out returned %d (after_rip=0x%llX expected=0x%llX restored=%d free_code=%d free_stack=%d); last_error=\"%s\" (elapsed %lld ms)",
            (int)ok,
            (unsigned long long)after.rip,
            (unsigned long long)fixture.expected_rip,
            (int)restored,
            (int)freed_code,
            (int)freed_stack,
            err.empty() ? "(none)" : err.c_str(),
            (long long)ms);
        failed.fetch_add(1);
    }
}

static void test_run_target(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
    log_msg(hf, "dbg_run", "START -- run_target resumes target threads");
    auto t0 = std::chrono::steady_clock::now();

    diag::log_tagged_fmt("test_dbg_detail", "dbg_run inputs: run_target() driver_loaded=%d attached_pid=%u",
        (int)driver_bridge::is_loaded(), (unsigned)driver_bridge::attached_pid());

    bool ok = debugger_engine::run_target();
    std::string err = debugger_engine::last_error();
    diag::log_tagged_fmt("test_dbg_detail", "dbg_run result: run_target=>%d status=%d last_error='%s'",
        (int)ok, (int)debugger_engine::g_state.status.load(), err.c_str());

    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - t0).count();
    if (ok) {
        log_msg(hf, "dbg_run", "PASS -- run_target resumed target threads (elapsed %lld ms)", (long long)ms);
        passed.fetch_add(1);
    } else {
        log_msg(hf, "dbg_run", "FAIL -- run_target returned 0; last_error=\"%s\" (not attached) (elapsed %lld ms)",
            err.empty() ? "(none)" : err.c_str(), (long long)ms);
        failed.fetch_add(1);
    }
}

static void test_pause_target(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
    log_msg(hf, "dbg_pause", "START -- pause_target suspends target threads");
    auto t0 = std::chrono::steady_clock::now();

    diag::log_tagged_fmt("test_dbg_detail", "dbg_pause inputs: pause_target() driver_loaded=%d attached_pid=%u",
        (int)driver_bridge::is_loaded(), (unsigned)driver_bridge::attached_pid());

    bool ok = debugger_engine::pause_target();
    std::string err = debugger_engine::last_error();
    diag::log_tagged_fmt("test_dbg_detail", "dbg_pause result: pause_target=>%d status=%d last_error='%s'",
        (int)ok, (int)debugger_engine::g_state.status.load(), err.c_str());

    debugger_engine::run_target();

    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - t0).count();
    if (ok) {
        log_msg(hf, "dbg_pause", "PASS -- pause_target suspended target threads (elapsed %lld ms)", (long long)ms);
        passed.fetch_add(1);
    } else {
        log_msg(hf, "dbg_pause", "FAIL -- pause_target returned 0; last_error=\"%s\" (not attached) (elapsed %lld ms)",
            err.empty() ? "(none)" : err.c_str(), (long long)ms);
        failed.fetch_add(1);
    }
}

static void test_multiple_watches(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
    log_msg(hf, "dbg_mw", "START -- add multiple watch expressions");
    auto t0 = std::chrono::steady_clock::now();

    diag::log_tagged_fmt("test_dbg_detail", "dbg_mw inputs: add_watch x5 ('rax','rbx','rcx + rdx','rsp - 0x100','[rsp]')");
    int w1 = debugger_engine::add_watch("rax");
    int w2 = debugger_engine::add_watch("rbx");
    int w3 = debugger_engine::add_watch("rcx + rdx");
    int w4 = debugger_engine::add_watch("rsp - 0x100");
    int w5 = debugger_engine::add_watch("[rsp]");

    auto snap = debugger_engine::snapshot_watches();
    size_t count = snap.size();
    diag::log_tagged_fmt("test_dbg_detail", "dbg_mw result: idx=[%d,%d,%d,%d,%d] snapshot_size=%zu", w1, w2, w3, w4, w5, count);

    debugger_engine::remove_watch(w1);
    debugger_engine::remove_watch(w2);
    debugger_engine::remove_watch(w3);
    debugger_engine::remove_watch(w4);
    debugger_engine::remove_watch(w5);

    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - t0).count();
    if (w1 >= 0 && w2 >= 0 && w3 >= 0 && w4 >= 0 && w5 >= 0 && count >= 5) {
        log_msg(hf, "dbg_mw", "PASS -- 5 watches added, snapshot has %zu entries (elapsed %lld ms)",
            count, (long long)ms);
        passed.fetch_add(1);
    } else {
        log_msg(hf, "dbg_mw", "FAIL -- w1=%d w2=%d w3=%d w4=%d w5=%d count=%zu (elapsed %lld ms)",
            w1, w2, w3, w4, w5, count, (long long)ms);
        failed.fetch_add(1);
    }
}

static void test_trace_with_depth(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
    log_msg(hf, "dbg_trd", "START -- start trace with different max_instructions values");
    auto t0 = std::chrono::steady_clock::now();

    debugger_engine::stop_trace();
    diag::log_tagged_fmt("test_dbg_detail", "dbg_trd inputs: start_trace depths {100, 10000, 50000}, each paired with stop_trace");

    bool s1 = debugger_engine::start_trace(100);
    debugger_engine::stop_trace();

    bool s2 = debugger_engine::start_trace(10000);
    debugger_engine::stop_trace();

    bool s3 = debugger_engine::start_trace(50000);
    debugger_engine::stop_trace();
    diag::log_tagged_fmt("test_dbg_detail", "dbg_trd result: start_trace depth100=>%d depth10000=>%d depth50000=>%d",
        (int)s1, (int)s2, (int)s3);

    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - t0).count();
    if (s1 && s2 && s3) {
        log_msg(hf, "dbg_trd", "PASS -- trace depth 100=%d 10000=%d 50000=%d (all started) (elapsed %lld ms)",
            (int)s1, (int)s2, (int)s3, (long long)ms);
        passed.fetch_add(1);
    } else {
        log_msg(hf, "dbg_trd", "FAIL -- start_trace failed for one or more depths: 100=%d 10000=%d 50000=%d (elapsed %lld ms)",
            (int)s1, (int)s2, (int)s3, (long long)ms);
        failed.fetch_add(1);
    }
}

static void test_trace_result_inspection(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
    log_msg(hf, "dbg_tri", "START -- trace result buffer inspection");
    auto t0 = std::chrono::steady_clock::now();

    debugger_engine::stop_trace();
    diag::log_tagged_fmt("test_dbg_detail", "dbg_tri inputs: start_trace(500) then inspect g_state.trace_log");

    bool started = debugger_engine::start_trace(500);
    Sleep(100);
    bool stopped = debugger_engine::stop_trace();

    auto& state = debugger_engine::g_state;
    size_t trace_count = 0;
    {
        std::lock_guard<std::mutex> lk(state.trace_mutex);
        trace_count = state.trace_log.size();
    }
    diag::log_tagged_fmt("test_dbg_detail", "dbg_tri result: start=>%d stop=>%d trace_log_size=%zu",
        (int)started, (int)stopped, trace_count);

    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - t0).count();
    if (started && stopped) {
        log_msg(hf, "dbg_tri", "PASS -- trace engaged and buffer accessible: %zu records (0 expected without stepping) (elapsed %lld ms)",
            trace_count, (long long)ms);
        passed.fetch_add(1);
    } else {
        log_msg(hf, "dbg_tri", "FAIL -- trace control failed: start=%d stop=%d (elapsed %lld ms)",
            (int)started, (int)stopped, (long long)ms);
        failed.fetch_add(1);
    }
}

static void test_comment_multiple_addresses(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
    log_msg(hf, "dbg_cmt2", "START -- set/get comments at multiple addresses");
    auto t0 = std::chrono::steady_clock::now();

    uint64_t a1 = get_ntdll_fn("NtClose");
    uint64_t a2 = get_ntdll_fn("NtOpenFile");
    uint64_t a3 = get_ntdll_fn("NtCreateFile");
    if (a1 == 0 || a2 == 0 || a3 == 0) {
        log_msg(hf, "dbg_cmt2", "FAIL -- ntdll functions not found");
        failed.fetch_add(1);
        return;
    }

    diag::log_tagged_fmt("test_dbg_detail", "dbg_cmt2 inputs: a1=0x%llX a2=0x%llX a3=0x%llX",
        (unsigned long long)a1, (unsigned long long)a2, (unsigned long long)a3);

    debugger_engine::set_comment(a1, "comment_alpha");
    debugger_engine::set_comment(a2, "comment_beta");
    debugger_engine::set_comment(a3, "comment_gamma");

    std::string c1 = debugger_engine::get_comment(a1);
    std::string c2 = debugger_engine::get_comment(a2);
    std::string c3 = debugger_engine::get_comment(a3);

    debugger_engine::set_comment(a1, "");
    debugger_engine::set_comment(a2, "");
    debugger_engine::set_comment(a3, "");
    diag::log_tagged_fmt("test_dbg_detail", "dbg_cmt2 result: c1='%s' c2='%s' c3='%s'", c1.c_str(), c2.c_str(), c3.c_str());

    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - t0).count();
    if (c1 == "comment_alpha" && c2 == "comment_beta" && c3 == "comment_gamma") {
        log_msg(hf, "dbg_cmt2", "PASS -- 3 comments set/get round-trip ok (elapsed %lld ms)", (long long)ms);
        passed.fetch_add(1);
    } else {
        log_msg(hf, "dbg_cmt2", "FAIL -- c1=\"%s\" c2=\"%s\" c3=\"%s\" (elapsed %lld ms)",
            c1.c_str(), c2.c_str(), c3.c_str(), (long long)ms);
        failed.fetch_add(1);
    }
}

static void test_label_multiple_addresses(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
    log_msg(hf, "dbg_lbl2", "START -- set/get labels at multiple addresses");
    auto t0 = std::chrono::steady_clock::now();

    uint64_t a1 = get_ntdll_fn("NtClose");
    uint64_t a2 = get_ntdll_fn("NtOpenFile");
    if (a1 == 0 || a2 == 0) {
        log_msg(hf, "dbg_lbl2", "FAIL -- ntdll functions not found");
        failed.fetch_add(1);
        return;
    }

    diag::log_tagged_fmt("test_dbg_detail", "dbg_lbl2 inputs: a1=0x%llX a2=0x%llX", (unsigned long long)a1, (unsigned long long)a2);

    debugger_engine::set_label(a1, "label_first");
    debugger_engine::set_label(a2, "label_second");

    std::string l1 = debugger_engine::get_label(a1);
    std::string l2 = debugger_engine::get_label(a2);

    debugger_engine::set_label(a1, "");
    debugger_engine::set_label(a2, "");
    diag::log_tagged_fmt("test_dbg_detail", "dbg_lbl2 result: l1='%s' l2='%s'", l1.c_str(), l2.c_str());

    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - t0).count();
    if (l1 == "label_first" && l2 == "label_second") {
        log_msg(hf, "dbg_lbl2", "PASS -- 2 labels set/get round-trip ok (elapsed %lld ms)", (long long)ms);
        passed.fetch_add(1);
    } else {
        log_msg(hf, "dbg_lbl2", "FAIL -- l1=\"%s\" l2=\"%s\" (elapsed %lld ms)", l1.c_str(), l2.c_str(), (long long)ms);
        failed.fetch_add(1);
    }
}

static void test_label_lookup_by_name(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
    log_msg(hf, "dbg_llkp", "START -- set label, look up by address, verify name");
    auto t0 = std::chrono::steady_clock::now();

    uint64_t addr = get_ntdll_fn("NtReadFile");
    if (addr == 0) { log_msg(hf, "dbg_llkp", "FAIL -- NtReadFile not found"); failed.fetch_add(1); return; }
    diag::log_tagged_fmt("test_dbg_detail", "dbg_llkp inputs: addr=0x%llX set_label='label_lookup_test_xyzzy'", (unsigned long long)addr);

    debugger_engine::set_label(addr, "label_lookup_test_xyzzy");
    std::string got = debugger_engine::get_label(addr);
    debugger_engine::set_label(addr, "");
    diag::log_tagged_fmt("test_dbg_detail", "dbg_llkp result: get_label=>'%s'", got.c_str());

    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - t0).count();
    if (got == "label_lookup_test_xyzzy") {
        log_msg(hf, "dbg_llkp", "PASS -- label resolved ok (elapsed %lld ms)", (long long)ms);
        passed.fetch_add(1);
    } else {
        log_msg(hf, "dbg_llkp", "FAIL -- expected \"label_lookup_test_xyzzy\" got \"%s\" (elapsed %lld ms)",
            got.c_str(), (long long)ms);
        failed.fetch_add(1);
    }
}

static void test_bookmark_listing(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
    log_msg(hf, "dbg_bklst", "START -- add several bookmarks, list them");
    auto t0 = std::chrono::steady_clock::now();

    uint64_t a1 = get_ntdll_fn("NtClose");
    uint64_t a2 = get_ntdll_fn("NtOpenFile");
    uint64_t a3 = get_ntdll_fn("NtCreateFile");
    if (a1 == 0 || a2 == 0 || a3 == 0) {
        log_msg(hf, "dbg_bklst", "FAIL -- ntdll functions not found");
        failed.fetch_add(1);
        return;
    }

    diag::log_tagged_fmt("test_dbg_detail", "dbg_bklst inputs: toggle_bookmark a1=0x%llX a2=0x%llX a3=0x%llX",
        (unsigned long long)a1, (unsigned long long)a2, (unsigned long long)a3);

    debugger_engine::toggle_bookmark(a1);
    debugger_engine::toggle_bookmark(a2);
    debugger_engine::toggle_bookmark(a3);

    size_t count = 0;
    {
        std::lock_guard<std::mutex> lk(debugger_engine::g_state.anno_mutex);
        count = debugger_engine::g_state.bookmarks.size();
    }

    debugger_engine::toggle_bookmark(a1);
    debugger_engine::toggle_bookmark(a2);
    debugger_engine::toggle_bookmark(a3);
    diag::log_tagged_fmt("test_dbg_detail", "dbg_bklst result: bookmark_count_after_3=%zu", count);

    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - t0).count();
    if (count >= 3) {
        log_msg(hf, "dbg_bklst", "PASS -- %zu bookmarks after adding 3 (elapsed %lld ms)", count, (long long)ms);
        passed.fetch_add(1);
    } else {
        log_msg(hf, "dbg_bklst", "FAIL -- expected >= 3 bookmarks, got %zu (elapsed %lld ms)", count, (long long)ms);
        failed.fetch_add(1);
    }
}

static void test_memory_map_executable_filter(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
    log_msg(hf, "dbg_mmex", "START -- memory map filter executable regions");
    auto t0 = std::chrono::steady_clock::now();

    diag::log_tagged_fmt("test_dbg_detail", "dbg_mmex inputs: get_memory_map() attached_pid=%u", (unsigned)driver_bridge::attached_pid());

    auto regions = debugger_engine::get_memory_map();
    size_t exec_count = 0;
    size_t write_count = 0;
    size_t guard_count = 0;
    for (auto& r : regions) {
        uint32_t prot = r.protect;
        if (prot == 0x10 || prot == 0x20 || prot == 0x40 || prot == 0x80) exec_count++;
        if (prot == 0x04 || prot == 0x08 || prot == 0x40 || prot == 0x80) write_count++;
        if (prot & 0x100) guard_count++;
    }
    diag::log_tagged_fmt("test_dbg_detail", "dbg_mmex result: region_count=%zu exec=%zu writable=%zu guard=%zu",
        regions.size(), exec_count, write_count, guard_count);

    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - t0).count();
    if (!regions.empty() && exec_count != 0) {
        log_msg(hf, "dbg_mmex", "PASS -- %zu regions: exec=%zu writable=%zu guard=%zu (elapsed %lld ms)",
            regions.size(), exec_count, write_count, guard_count, (long long)ms);
        passed.fetch_add(1);
    } else {
        log_msg(hf, "dbg_mmex", "FAIL -- memory map invalid: regions=%zu exec=%zu (an attached process always has mapped + executable regions) (elapsed %lld ms)",
            regions.size(), exec_count, (long long)ms);
        failed.fetch_add(1);
    }
}

static void test_format_protect_guard(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
    log_msg(hf, "dbg_fpg", "START -- format_protect with GUARD pages");
    auto t0 = std::chrono::steady_clock::now();

    diag::log_tagged_fmt("test_dbg_detail", "dbg_fpg inputs: format_protect(EXECUTE_READ, NOACCESS, GUARD|READWRITE, WRITECOPY)");
    std::string p1 = debugger_engine::format_protect(PAGE_EXECUTE_READ);
    std::string p2 = debugger_engine::format_protect(PAGE_NOACCESS);
    std::string p3 = debugger_engine::format_protect(PAGE_GUARD | PAGE_READWRITE);
    std::string p4 = debugger_engine::format_protect(PAGE_WRITECOPY);
    diag::log_tagged_fmt("test_dbg_detail", "dbg_fpg result: p1='%s' p2='%s' p3='%s' p4='%s'",
        p1.c_str(), p2.c_str(), p3.c_str(), p4.c_str());

    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - t0).count();
    if (!p1.empty() && !p2.empty() && !p3.empty() && !p4.empty()) {
        log_msg(hf, "dbg_fpg", "PASS -- ER=\"%s\" NA=\"%s\" G|RW=\"%s\" WC=\"%s\" (elapsed %lld ms)",
            p1.c_str(), p2.c_str(), p3.c_str(), p4.c_str(), (long long)ms);
        passed.fetch_add(1);
    } else {
        log_msg(hf, "dbg_fpg", "FAIL -- format_protect returned empty: p1=\"%s\" p2=\"%s\" p3=\"%s\" p4=\"%s\" (elapsed %lld ms)",
            p1.c_str(), p2.c_str(), p3.c_str(), p4.c_str(), (long long)ms);
        failed.fetch_add(1);
    }
}

static void test_format_flags_zero(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
    log_msg(hf, "dbg_ff0", "START -- format_flags with zero and various flag combos");
    auto t0 = std::chrono::steady_clock::now();

    diag::log_tagged_fmt("test_dbg_detail", "dbg_ff0 inputs: format_flags(0x0, 0x202, 0x246, 0x297)");
    std::string f0 = debugger_engine::format_flags(0);
    std::string f1 = debugger_engine::format_flags(0x202);
    std::string f2 = debugger_engine::format_flags(0x246);
    std::string f3 = debugger_engine::format_flags(0x297);
    diag::log_tagged_fmt("test_dbg_detail", "dbg_ff0 result: f0='%s' f1='%s' f2='%s' f3='%s'",
        f0.c_str(), f1.c_str(), f2.c_str(), f3.c_str());

    bool f1_has_if = f1.find("IF") != std::string::npos;
    bool f2_has_zf = f2.find("ZF") != std::string::npos;
    bool f3_has_cf = f3.find("CF") != std::string::npos;

    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - t0).count();
    if (f0.empty() && !f1.empty() && !f2.empty() && !f3.empty() && f1_has_if && f2_has_zf && f3_has_cf) {
        log_msg(hf, "dbg_ff0", "PASS -- 0x0=\"%s\" 0x202=\"%s\" 0x246=\"%s\" 0x297=\"%s\" (elapsed %lld ms)",
            f0.c_str(), f1.c_str(), f2.c_str(), f3.c_str(), (long long)ms);
        passed.fetch_add(1);
    } else {
        log_msg(hf, "dbg_ff0", "FAIL -- format_flags wrong: 0x0=\"%s\"(want empty) 0x202=\"%s\"(want IF) 0x246=\"%s\"(want ZF) 0x297=\"%s\"(want CF) (elapsed %lld ms)",
            f0.c_str(), f1.c_str(), f2.c_str(), f3.c_str(), (long long)ms);
        failed.fetch_add(1);
    }
}

static void test_format_segment_registers(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
    log_msg(hf, "dbg_seg", "START -- read segment registers CS/DS/SS/ES/FS/GS");
    auto t0 = std::chrono::steady_clock::now();

    diag::log_tagged_fmt("test_dbg_detail", "dbg_seg inputs: get_registers() (cs/ss populated from kernel thread context) attached_pid=%u",
        (unsigned)driver_bridge::attached_pid());
    auto regs = debugger_engine::get_registers();
    diag::log_tagged_fmt("test_dbg_detail", "dbg_seg result: cs=0x%llX ss=0x%llX (ds/es/fs/gs not provided by driver context)",
        (unsigned long long)regs.cs, (unsigned long long)regs.ss);

    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - t0).count();
    if (regs.cs != 0 && regs.ss != 0) {
        log_msg(hf, "dbg_seg", "PASS -- cs=0x%llX ds=0x%llX ss=0x%llX es=0x%llX fs=0x%llX gs=0x%llX (elapsed %lld ms)",
            (unsigned long long)regs.cs, (unsigned long long)regs.ds, (unsigned long long)regs.ss,
            (unsigned long long)regs.es, (unsigned long long)regs.fs, (unsigned long long)regs.gs,
            (long long)ms);
        passed.fetch_add(1);
    } else {
        log_msg(hf, "dbg_seg", "FAIL -- segment regs all zero: cs=0x%llX ss=0x%llX (a live x64 user thread always has non-zero cs and ss; engine returned empty regs) (elapsed %lld ms)",
            (unsigned long long)regs.cs, (unsigned long long)regs.ss, (long long)ms);
        failed.fetch_add(1);
    }
}

static void test_debug_registers(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
    log_msg(hf, "dbg_dreg", "START -- read debug registers DR0-DR3, DR6, DR7");
    auto t0 = std::chrono::steady_clock::now();

    diag::log_tagged_fmt("test_dbg_detail", "dbg_dreg inputs: get_registers() (DR0-DR3/DR6/DR7) attached_pid=%u",
        (unsigned)driver_bridge::attached_pid());
    auto regs = debugger_engine::get_registers();
    diag::log_tagged_fmt("test_dbg_detail", "dbg_dreg result: rip=0x%llX dr0=0x%llX dr1=0x%llX dr2=0x%llX dr3=0x%llX dr6=0x%llX dr7=0x%llX",
        (unsigned long long)regs.rip, (unsigned long long)regs.dr0, (unsigned long long)regs.dr1, (unsigned long long)regs.dr2,
        (unsigned long long)regs.dr3, (unsigned long long)regs.dr6, (unsigned long long)regs.dr7);

    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - t0).count();
    if (regs.rip != 0 && regs.rsp != 0) {
        log_msg(hf, "dbg_dreg", "PASS -- debug-register read succeeded: dr0=0x%llX dr1=0x%llX dr2=0x%llX dr3=0x%llX dr6=0x%llX dr7=0x%llX (elapsed %lld ms)",
            (unsigned long long)regs.dr0, (unsigned long long)regs.dr1, (unsigned long long)regs.dr2,
            (unsigned long long)regs.dr3, (unsigned long long)regs.dr6, (unsigned long long)regs.dr7,
            (long long)ms);
        passed.fetch_add(1);
    } else {
        log_msg(hf, "dbg_dreg", "FAIL -- debug-register read failed: thread context not read (rip=0x%llX rsp=0x%llX must be non-zero) (elapsed %lld ms)",
            (unsigned long long)regs.rip, (unsigned long long)regs.rsp, (long long)ms);
        failed.fetch_add(1);
    }
}

static void test_request_dump_refresh(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
    log_msg(hf, "dbg_dump", "START -- request dump refresh and read cached bytes");
    auto t0 = std::chrono::steady_clock::now();

    uint64_t addr = get_ntdll_fn("NtClose");
    if (addr == 0) { log_msg(hf, "dbg_dump", "FAIL -- NtClose not found"); failed.fetch_add(1); return; }
    diag::log_tagged_fmt("test_dbg_detail", "dbg_dump inputs: request_dump_refresh(addr=0x%llX, bytes=128, max_age=0) attached_pid=%u",
        (unsigned long long)addr, (unsigned)driver_bridge::attached_pid());

    debugger_engine::request_dump_refresh(addr, 128, 0);

    uint64_t addr_out = 0;
    size_t size_out = 0;
    std::vector<uint8_t> bytes;
    bool in_flight = false;
    for (int poll = 0; poll < 60; ++poll) {
        bytes = debugger_engine::cached_dump_bytes(addr_out, size_out);
        in_flight = debugger_engine::dump_refresh_in_flight();
        diag::log_tagged_fmt("test_dbg_detail", "dbg_dump poll=%d byte_count=%zu addr=0x%llX requested_size=%zu in_flight=%d attached_pid=%u driver_status=%s driver_error=%s",
            poll,
            bytes.size(),
            (unsigned long long)addr_out,
            size_out,
            in_flight ? 1 : 0,
            (unsigned)driver_bridge::attached_pid(),
            driver_bridge::status().c_str(),
            driver_bridge::last_error().c_str());
        if (!bytes.empty() && addr_out != 0)
            break;
        if (!in_flight && poll > 0)
            break;
        Sleep(50);
    }

    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - t0).count();
    if (!bytes.empty() && addr_out != 0) {
        log_msg(hf, "dbg_dump", "PASS -- dump %zu bytes at 0x%llX size=%zu (elapsed %lld ms)",
            bytes.size(), (unsigned long long)addr_out, size_out, (long long)ms);
        passed.fetch_add(1);
    } else {
        log_msg(hf, "dbg_dump", "FAIL -- dump read empty: bytes=%zu addr=0x%llX in_flight=%d status=%s last_error=%s (target memory read returned no data) (elapsed %lld ms)",
            bytes.size(), (unsigned long long)addr_out, in_flight ? 1 : 0, driver_bridge::status().c_str(), driver_bridge::last_error().c_str(), (long long)ms);
        failed.fetch_add(1);
    }
}

static void test_invalidate_cache(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
    log_msg(hf, "dbg_inv", "START -- invalidate_cache resets timestamps");
    auto t0 = std::chrono::steady_clock::now();

    diag::log_tagged_fmt("test_dbg_detail", "dbg_inv inputs: invalidate_cache()");
    debugger_engine::invalidate_cache();

    uint64_t lr = debugger_engine::g_state.last_refresh_ms.load();
    uint64_t lt = debugger_engine::g_state.last_thread_refresh_ms.load();
    uint64_t ls = debugger_engine::g_state.last_stack_refresh_ms.load();
    uint64_t ld = debugger_engine::g_state.last_dump_refresh_ms.load();
    uint64_t lda = debugger_engine::g_state.last_disasm_refresh_ms.load();
    diag::log_tagged_fmt("test_dbg_detail", "dbg_inv result: last_refresh=%llu thread=%llu stack=%llu dump=%llu disasm=%llu",
        (unsigned long long)lr, (unsigned long long)lt, (unsigned long long)ls, (unsigned long long)ld, (unsigned long long)lda);

    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - t0).count();
    if (lr == 0 && lt == 0 && ls == 0 && ld == 0 && lda == 0) {
        log_msg(hf, "dbg_inv", "PASS -- all cache timestamps zeroed (elapsed %lld ms)", (long long)ms);
        passed.fetch_add(1);
    } else {
        log_msg(hf, "dbg_inv", "FAIL -- timestamps not zero: r=%llu t=%llu s=%llu d=%llu da=%llu (elapsed %lld ms)",
            (unsigned long long)lr, (unsigned long long)lt, (unsigned long long)ls,
            (unsigned long long)ld, (unsigned long long)lda, (long long)ms);
        failed.fetch_add(1);
    }
}

static void test_signal_trap(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
    log_msg(hf, "dbg_trap", "START -- signal_trap and wait_for_trap");
    auto t0 = std::chrono::steady_clock::now();

    uint64_t trap_addr = 0xDEADCAFE00000001ULL;
    diag::log_tagged_fmt("test_dbg_detail", "dbg_trap inputs: signal_trap(0x%llX) then wait_for_trap(0x%llX, 1000ms)",
        (unsigned long long)trap_addr, (unsigned long long)trap_addr);
    debugger_engine::signal_trap(trap_addr);
    bool caught = debugger_engine::wait_for_trap(trap_addr, 1000);
    diag::log_tagged_fmt("test_dbg_detail", "dbg_trap result: wait_for_trap=>%d", (int)caught);

    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - t0).count();
    if (caught) {
        log_msg(hf, "dbg_trap", "PASS -- trap signaled and caught at 0x%llX (elapsed %lld ms)",
            (unsigned long long)trap_addr, (long long)ms);
        passed.fetch_add(1);
    } else {
        log_msg(hf, "dbg_trap", "FAIL -- wait_for_trap returned false (elapsed %lld ms)", (long long)ms);
        failed.fetch_add(1);
    }
}

static void test_pop_log_messages(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
    log_msg(hf, "dbg_poplog", "START -- pop_log_messages and log_message_count");
    auto t0 = std::chrono::steady_clock::now();

    diag::log_tagged_fmt("test_dbg_detail", "dbg_poplog inputs: log_message_count() then pop_log_messages() then re-count");
    size_t before_count = debugger_engine::log_message_count();
    auto msgs = debugger_engine::pop_log_messages();
    size_t after_count = debugger_engine::log_message_count();
    diag::log_tagged_fmt("test_dbg_detail", "dbg_poplog result: before_count=%zu popped=%zu after_count=%zu",
        before_count, msgs.size(), after_count);

    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - t0).count();
    if (msgs.size() == before_count && after_count == 0) {
        log_msg(hf, "dbg_poplog", "PASS -- popped %zu of %zu messages, buffer drained to 0 (elapsed %lld ms)",
            msgs.size(), before_count, (long long)ms);
        passed.fetch_add(1);
    } else {
        log_msg(hf, "dbg_poplog", "FAIL -- pop inconsistent: before=%zu popped=%zu after=%zu (pop must drain buffer and return all entries) (elapsed %lld ms)",
            before_count, msgs.size(), after_count, (long long)ms);
        failed.fetch_add(1);
    }
}

static void test_restore_breakpoints_and_watches(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
    log_msg(hf, "dbg_rest", "START -- restore_breakpoints_and_watches round-trip");
    auto t0 = std::chrono::steady_clock::now();

    debugger_engine::clear_breakpoints_and_watches();

    uint64_t addr = alloc_target_bp_region();
    if (addr == 0) { log_msg(hf, "dbg_rest", "FAIL -- alloc_target_bp_region returned 0 (no driver attach?)"); failed.fetch_add(1); return; }

    diag::log_tagged_fmt("test_dbg_detail", "dbg_rest inputs: addr=0x%llX add 1 bp + 1 watch, snapshot, clear, restore", (unsigned long long)addr);
    debugger_engine::add_breakpoint(addr, debugger_engine::bp_type_t::software, "restore_test", "", 1);
    debugger_engine::add_watch("rax + rbx");

    auto bps = debugger_engine::snapshot_breakpoints();
    auto ws = debugger_engine::snapshot_watches();

    debugger_engine::clear_breakpoints_and_watches();
    auto empty_bps = debugger_engine::snapshot_breakpoints();
    auto empty_ws = debugger_engine::snapshot_watches();

    debugger_engine::restore_breakpoints_and_watches(bps, ws);
    auto restored_bps = debugger_engine::snapshot_breakpoints();
    auto restored_ws = debugger_engine::snapshot_watches();

    debugger_engine::clear_breakpoints_and_watches();
    driver_bridge::free_memory(addr);
    diag::log_tagged_fmt("test_dbg_detail", "dbg_rest result: orig_bps=%zu orig_ws=%zu after_clear_bps=%zu after_clear_ws=%zu restored_bps=%zu restored_ws=%zu",
        bps.size(), ws.size(), empty_bps.size(), empty_ws.size(), restored_bps.size(), restored_ws.size());

    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - t0).count();
    if (!bps.empty() && !ws.empty() && empty_bps.empty() && empty_ws.empty() && restored_bps.size() == bps.size() && restored_ws.size() == ws.size()) {
        log_msg(hf, "dbg_rest", "PASS -- clear then restore verified: bps=%zu ws=%zu (elapsed %lld ms)",
            restored_bps.size(), restored_ws.size(), (long long)ms);
        passed.fetch_add(1);
    } else {
        log_msg(hf, "dbg_rest", "FAIL -- restore mismatch: orig_bps=%zu orig_ws=%zu after_clear(bps=%zu ws=%zu, expect 0/0) restored(bps=%zu ws=%zu, expect %zu/%zu) (elapsed %lld ms)",
            bps.size(), ws.size(), empty_bps.size(), empty_ws.size(), restored_bps.size(), restored_ws.size(), bps.size(), ws.size(), (long long)ms);
        failed.fetch_add(1);
    }
}

static void test_clear_breakpoints_and_watches(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
    log_msg(hf, "dbg_cbw", "START -- clear_breakpoints_and_watches");
    auto t0 = std::chrono::steady_clock::now();

    uint64_t addr = alloc_target_bp_region();
    if (addr == 0) { log_msg(hf, "dbg_cbw", "FAIL -- alloc_target_bp_region returned 0 (no driver attach?)"); failed.fetch_add(1); return; }
    diag::log_tagged_fmt("test_dbg_detail", "dbg_cbw inputs: addr=0x%llX add 1 bp + 1 watch then clear_breakpoints_and_watches()", (unsigned long long)addr);

    debugger_engine::add_breakpoint(addr, debugger_engine::bp_type_t::software, "cbw_bp", "", 1);
    debugger_engine::add_watch("rip");
    debugger_engine::clear_breakpoints_and_watches();

    auto bps = debugger_engine::snapshot_breakpoints();
    auto ws = debugger_engine::snapshot_watches();
    driver_bridge::free_memory(addr);
    diag::log_tagged_fmt("test_dbg_detail", "dbg_cbw result: bps_after_clear=%zu ws_after_clear=%zu", bps.size(), ws.size());

    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - t0).count();
    if (bps.empty() && ws.empty()) {
        log_msg(hf, "dbg_cbw", "PASS -- both breakpoints and watches cleared (elapsed %lld ms)", (long long)ms);
        passed.fetch_add(1);
    } else {
        log_msg(hf, "dbg_cbw", "FAIL -- bps=%zu ws=%zu (elapsed %lld ms)", bps.size(), ws.size(), (long long)ms);
        failed.fetch_add(1);
    }
}

static void test_disasm_refresh_ntcreatefile(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
    log_msg(hf, "dbg_dasm2", "START -- disasm refresh at NtCreateFile");
    auto t0 = std::chrono::steady_clock::now();

    uint64_t addr = get_ntdll_fn("NtCreateFile");
    if (addr == 0) { log_msg(hf, "dbg_dasm2", "FAIL -- NtCreateFile not found"); failed.fetch_add(1); return; }
    diag::log_tagged_fmt("test_dbg_detail", "dbg_dasm2 inputs: request_disasm_refresh(addr=0x%llX, max_age=0) attached_pid=%u",
        (unsigned long long)addr, (unsigned)driver_bridge::attached_pid());

    debugger_engine::request_disasm_refresh(addr, 0);
    Sleep(300);

    uint64_t base_out = 0;
    auto bytes = debugger_engine::cached_disasm_window(base_out);
    diag::log_tagged_fmt("test_dbg_detail", "dbg_dasm2 result: byte_count=%zu base=0x%llX", bytes.size(), (unsigned long long)base_out);

    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - t0).count();
    if (!bytes.empty() && base_out != 0) {
        log_msg(hf, "dbg_dasm2", "PASS -- NtCreateFile disasm %zu bytes at base 0x%llX (elapsed %lld ms)",
            bytes.size(), (unsigned long long)base_out, (long long)ms);
        passed.fetch_add(1);
    } else {
        log_msg(hf, "dbg_dasm2", "FAIL -- NtCreateFile disasm empty: bytes=%zu base=0x%llX (elapsed %lld ms)",
            bytes.size(), (unsigned long long)base_out, (long long)ms);
        failed.fetch_add(1);
    }
}

static void test_disasm_refresh_ntopenfile(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
    log_msg(hf, "dbg_dasm3", "START -- disasm refresh at NtOpenFile");
    auto t0 = std::chrono::steady_clock::now();

    uint64_t addr = get_ntdll_fn("NtOpenFile");
    if (addr == 0) { log_msg(hf, "dbg_dasm3", "FAIL -- NtOpenFile not found"); failed.fetch_add(1); return; }
    diag::log_tagged_fmt("test_dbg_detail", "dbg_dasm3 inputs: request_disasm_refresh(addr=0x%llX, max_age=0) attached_pid=%u",
        (unsigned long long)addr, (unsigned)driver_bridge::attached_pid());

    debugger_engine::request_disasm_refresh(addr, 0);
    Sleep(300);

    uint64_t base_out = 0;
    auto bytes = debugger_engine::cached_disasm_window(base_out);
    diag::log_tagged_fmt("test_dbg_detail", "dbg_dasm3 result: byte_count=%zu base=0x%llX", bytes.size(), (unsigned long long)base_out);

    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - t0).count();
    if (!bytes.empty() && base_out != 0) {
        log_msg(hf, "dbg_dasm3", "PASS -- NtOpenFile disasm %zu bytes at base 0x%llX (elapsed %lld ms)",
            bytes.size(), (unsigned long long)base_out, (long long)ms);
        passed.fetch_add(1);
    } else {
        log_msg(hf, "dbg_dasm3", "FAIL -- NtOpenFile disasm empty: bytes=%zu base=0x%llX (elapsed %lld ms)",
            bytes.size(), (unsigned long long)base_out, (long long)ms);
        failed.fetch_add(1);
    }
}

static void test_handle_type_distribution(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
    log_msg(hf, "dbg_htyp", "START -- enumerate handles and check type distribution");
    auto t0 = std::chrono::steady_clock::now();

    auto& state = debugger_engine::g_state;
    size_t pre_total = 0;
    {
        std::lock_guard<std::mutex> lk(state.handle_mutex);
        pre_total = state.handles.size();
    }
    diag::log_tagged_fmt("test_dbg_detail", "dbg_htyp inputs: cached_handles=%zu attached_pid=%u", pre_total, (unsigned)driver_bridge::attached_pid());
    if (pre_total == 0) {
        debugger_engine::enumerate_handles();
    }

    size_t total = 0;
    size_t unique_types = 0;
    {
        std::lock_guard<std::mutex> lk(state.handle_mutex);
        total = state.handles.size();
        std::vector<uint32_t> seen_types;
        for (const auto& h : state.handles) {
            bool found = false;
            for (uint32_t t : seen_types) {
                if (t == h.type_index) { found = true; break; }
            }
            if (!found) seen_types.push_back(h.type_index);
        }
        unique_types = seen_types.size();
    }
    diag::log_tagged_fmt("test_dbg_detail", "dbg_htyp result: handle_count=%zu unique_types=%zu", total, unique_types);

    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - t0).count();
    if (total != 0 && unique_types != 0) {
        log_msg(hf, "dbg_htyp", "PASS -- %zu handles, %zu unique type indices (elapsed %lld ms)",
            total, unique_types, (long long)ms);
        passed.fetch_add(1);
    } else {
        log_msg(hf, "dbg_htyp", "FAIL -- handle enumeration empty: handles=%zu unique_types=%zu (every attached process has open handles) (elapsed %lld ms)",
            total, unique_types, (long long)ms);
        failed.fetch_add(1);
    }
}

static void test_strings_cancel(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
    log_msg(hf, "dbg_strc", "START -- start string search, cancel mid-way");
    auto t0 = std::chrono::steady_clock::now();

    diag::log_tagged_fmt("test_dbg_detail", "dbg_strc inputs: find_strings_async(4) then request_strings_cancel() attached_pid=%u",
        (unsigned)driver_bridge::attached_pid());
    debugger_engine::find_strings_async(4);
    Sleep(200);
    debugger_engine::request_strings_cancel();

    for (int i = 0; i < 30; ++i) {
        if (!debugger_engine::g_state.strings_scanning.load()) break;
        Sleep(100);
    }

    bool cancelled = !debugger_engine::g_state.strings_scanning.load();
    diag::log_tagged_fmt("test_dbg_detail", "dbg_strc result: strings_scanning=%d cancelled=%d",
        (int)debugger_engine::g_state.strings_scanning.load(), (int)cancelled);

    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - t0).count();
    if (cancelled) {
        log_msg(hf, "dbg_strc", "PASS -- string search cancelled (elapsed %lld ms)", (long long)ms);
        passed.fetch_add(1);
    } else {
        log_msg(hf, "dbg_strc", "FAIL -- string search still running after cancel (elapsed %lld ms)", (long long)ms);
        failed.fetch_add(1);
    }
}

static void test_dbg_status(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
    log_msg(hf, "dbg_stat", "START -- g_state.status check");
    auto t0 = std::chrono::steady_clock::now();

    diag::log_tagged_fmt("test_dbg_detail", "dbg_stat inputs: g_state.status.load() attached_pid=%u", (unsigned)driver_bridge::attached_pid());
    auto status = debugger_engine::g_state.status.load();
    const char* status_str = "unknown";
    bool valid = true;
    switch (status) {
        case debugger_engine::dbg_status_t::idle: status_str = "idle"; break;
        case debugger_engine::dbg_status_t::running: status_str = "running"; break;
        case debugger_engine::dbg_status_t::paused: status_str = "paused"; break;
        case debugger_engine::dbg_status_t::stepping: status_str = "stepping"; break;
        case debugger_engine::dbg_status_t::terminated: status_str = "terminated"; valid = false; break;
    }
    diag::log_tagged_fmt("test_dbg_detail", "dbg_stat result: status=%s(%d)", status_str, (int)status);

    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - t0).count();
    if (valid) {
        log_msg(hf, "dbg_stat", "PASS -- debugger status=%s (elapsed %lld ms)", status_str, (long long)ms);
        passed.fetch_add(1);
    } else {
        log_msg(hf, "dbg_stat", "FAIL -- debugger status=terminated; the attached target is dead (elapsed %lld ms)", (long long)ms);
        failed.fetch_add(1);
    }
}

static void test_run_to_address(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
    log_msg(hf, "dbg_rta", "START -- run_to_address API exists");
    auto t0 = std::chrono::steady_clock::now();

    uint64_t addr = alloc_target_bp_region();
    if (addr == 0) { log_msg(hf, "dbg_rta", "FAIL -- alloc_target_bp_region returned 0 (no driver attach?)"); failed.fetch_add(1); return; }
    diag::log_tagged_fmt("test_dbg_detail", "dbg_rta inputs: run_to_address(addr=0x%llX, wait=false, timeout=100ms) attached_pid=%u",
        (unsigned long long)addr, (unsigned)driver_bridge::attached_pid());

    bool ok = debugger_engine::run_to_address(addr, false, 100);
    std::string err = debugger_engine::last_error();
    Sleep(150);
    uint32_t exit_code = 0;
    const bool alive_after_resume = driver_bridge::attached_process_alive(&exit_code);
    debugger_engine::clear_all_breakpoints();
    driver_bridge::free_memory(addr);
    diag::log_tagged_fmt("test_dbg_detail", "dbg_rta result: run_to_address=>%d alive_after_resume=%d exit_code_or_error=0x%08X last_error='%s' (armed bp cleared/byte restored)",
        (int)ok, (int)alive_after_resume, (unsigned)exit_code, err.c_str());

    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - t0).count();
    if (ok && alive_after_resume) {
        log_msg(hf, "dbg_rta", "PASS -- run_to_address armed one-shot bp at 0x%llX and resumed target (elapsed %lld ms)",
            (unsigned long long)addr, (long long)ms);
        passed.fetch_add(1);
    } else if (ok) {
        log_msg(hf, "dbg_rta", "FAIL -- run_to_address resumed target but the target exited or detached immediately (exit_code_or_error=0x%08X) (elapsed %lld ms)",
            (unsigned)exit_code, (long long)ms);
        failed.fetch_add(1);
    } else {
        log_msg(hf, "dbg_rta", "FAIL -- run_to_address returned 0; last_error=\"%s\" (not attached or memory read/write failed) (elapsed %lld ms)",
            err.empty() ? "(none)" : err.c_str(), (long long)ms);
        failed.fetch_add(1);
    }
}

static void test_one_shot_bp(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
    log_msg(hf, "dbg_1shot", "START -- add breakpoint with bp_state one_shot via toggle");
    auto t0 = std::chrono::steady_clock::now();

    uint64_t addr = alloc_target_bp_region();
    if (addr == 0) { log_msg(hf, "dbg_1shot", "FAIL -- alloc_target_bp_region returned 0 (no driver attach?)"); failed.fetch_add(1); return; }
    diag::log_tagged_fmt("test_dbg_detail", "dbg_1shot inputs: addr=0x%llX add software bp then toggle pid=%u",
        (unsigned long long)addr, (unsigned)driver_bridge::attached_pid());

    int idx = debugger_engine::add_breakpoint(addr, debugger_engine::bp_type_t::software, "one_shot_test", "", 1);
    debugger_engine::toggle_breakpoint(idx);

    auto snap = debugger_engine::snapshot_breakpoints();
    bool found = false;
    for (const auto& bp : snap) {
        if (bp.address == addr) { found = true; break; }
    }

    debugger_engine::remove_breakpoint(idx);
    driver_bridge::free_memory(addr);
    diag::log_tagged_fmt("test_dbg_detail", "dbg_1shot result: idx=%d found_in_snapshot=%d snapshot_size=%zu", idx, (int)found, snap.size());

    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - t0).count();
    if (idx >= 0 && found) {
        log_msg(hf, "dbg_1shot", "PASS -- one-shot bp exists in snapshot (elapsed %lld ms)", (long long)ms);
        passed.fetch_add(1);
    } else {
        log_msg(hf, "dbg_1shot", "FAIL -- idx=%d found=%d (elapsed %lld ms)", idx, (int)found, (long long)ms);
        failed.fetch_add(1);
    }
}

static void test_seh_view_refresh(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
    log_msg(hf, "seh_ref", "START -- seh_view::refresh() trigger and wait");
    auto t0 = std::chrono::steady_clock::now();

    if (!require_attached_live_target(hf, "seh_ref", failed))
        return;

    log_msg(hf, "seh_ref", "driver_loaded=%d attached_pid=%u",
        (int)driver_bridge::is_loaded(),
        (unsigned)driver_bridge::attached_pid());
    diag::log_tagged_fmt("test_dbg_detail", "seh_ref inputs: seh_view::refresh() driver_loaded=%d attached_pid=%u active_tid=%u",
        (int)driver_bridge::is_loaded(), (unsigned)driver_bridge::attached_pid(),
        (unsigned)debugger_engine::g_state.active_tid);

    seh_view::refresh();

    int waited_ms = 0;
    while (seh_view::g_ui.refreshing.load(std::memory_order_acquire) && waited_ms < 3000) {
        Sleep(50);
        waited_ms += 50;
    }

    bool still_refreshing = seh_view::g_ui.refreshing.load(std::memory_order_acquire);
    size_t chain_depth = 0;
    {
        std::lock_guard<std::mutex> lk(seh_view::g_ui.mutex);
        chain_depth = seh_view::g_ui.entries.size();
    }
    diag::log_tagged_fmt("test_dbg_detail", "seh_ref result: still_refreshing=%d chain_depth=%zu waited_ms=%d (empty chain expected on x64)",
        (int)still_refreshing, chain_depth, waited_ms);

    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - t0).count();
    log_msg(hf, "seh_ref", "refresh completed: still_refreshing=%d chain_depth=%zu waited_ms=%d (elapsed %lld ms)",
        (int)still_refreshing, chain_depth, waited_ms, (long long)ms);

    if (!still_refreshing) {
        log_msg(hf, "seh_ref", "PASS -- seh_view refresh completed without hang, chain_depth=%zu (x64 targets commonly have no linked SEH chain) (elapsed %lld ms)",
            chain_depth, (long long)ms);
        passed.fetch_add(1);
    } else {
        log_msg(hf, "seh_ref", "FAIL -- seh_view refresh still running after 3s timeout (worker hung) (elapsed %lld ms)", (long long)ms);
        failed.fetch_add(1);
    }
}

static void test_seh_view_entries(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
    log_msg(hf, "seh_ent", "START -- seh_view entry inspection");
    auto t0 = std::chrono::steady_clock::now();

    if (!require_attached_live_target(hf, "seh_ent", failed))
        return;

    std::vector<seh_view::seh_entry_t> snapshot;
    {
        std::lock_guard<std::mutex> lk(seh_view::g_ui.mutex);
        snapshot = seh_view::g_ui.entries;
    }

    log_msg(hf, "seh_ent", "chain_depth=%zu", snapshot.size());
    diag::log_tagged_fmt("test_dbg_detail", "seh_ent inputs: inspect seh_view::g_ui.entries chain_depth=%zu", snapshot.size());

    size_t valid_entries = 0;
    for (size_t i = 0; i < snapshot.size() && i < 16; ++i) {
        const auto& e = snapshot[i];
        log_msg(hf, "seh_ent", "  [%zu] frame=0x%016llX handler=0x%016llX module=%s name=%s",
            i,
            (unsigned long long)e.frame_addr,
            (unsigned long long)e.handler_addr,
            e.module_name.c_str(),
            e.handler_name.c_str());
    }
    for (const auto& e : snapshot) {
        if (e.frame_addr != 0 && e.handler_addr != 0) valid_entries++;
    }
    diag::log_tagged_fmt("test_dbg_detail", "seh_ent result: chain_depth=%zu valid_entries=%zu", snapshot.size(), valid_entries);

    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - t0).count();
    if (snapshot.empty() || valid_entries > 0) {
        log_msg(hf, "seh_ent", "PASS -- SEH chain readable: depth=%zu valid_entries=%zu malformed_tail=%zu (empty/tail-truncated chain acceptable on x64) (elapsed %lld ms)",
            snapshot.size(), valid_entries, snapshot.size() - valid_entries, (long long)ms);
        passed.fetch_add(1);
    } else {
        log_msg(hf, "seh_ent", "FAIL -- SEH chain has no valid entries out of %zu (elapsed %lld ms)",
            snapshot.size(), (long long)ms);
        failed.fetch_add(1);
    }
}

static void test_module_view_refresh(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
    log_msg(hf, "mod_ref", "START -- module_view::refresh() trigger and wait");
    auto t0 = std::chrono::steady_clock::now();

    log_msg(hf, "mod_ref", "driver_loaded=%d attached_pid=%u",
        (int)driver_bridge::is_loaded(),
        (unsigned)driver_bridge::attached_pid());
    diag::log_tagged_fmt("test_dbg_detail", "mod_ref inputs: module_view::refresh() driver_loaded=%d attached_pid=%u",
        (int)driver_bridge::is_loaded(), (unsigned)driver_bridge::attached_pid());

    module_view::refresh();

    int waited_ms = 0;
    while (module_view::g_ui.loading.load(std::memory_order_acquire) && waited_ms < 5000) {
        Sleep(50);
        waited_ms += 50;
    }

    bool still_loading = module_view::g_ui.loading.load(std::memory_order_acquire);
    size_t module_count = 0;
    {
        std::lock_guard<std::mutex> lk(module_view::g_ui.modules_mutex);
        module_count = module_view::g_ui.modules.size();
    }
    diag::log_tagged_fmt("test_dbg_detail", "mod_ref result: still_loading=%d module_count=%zu waited_ms=%d",
        (int)still_loading, module_count, waited_ms);

    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - t0).count();
    log_msg(hf, "mod_ref", "refresh result: still_loading=%d module_count=%zu waited_ms=%d (elapsed %lld ms)",
        (int)still_loading, module_count, waited_ms, (long long)ms);

    if (!still_loading && module_count > 0) {
        log_msg(hf, "mod_ref", "PASS -- module_view refresh completed: %zu modules found (elapsed %lld ms)",
            module_count, (long long)ms);
        passed.fetch_add(1);
    } else if (still_loading) {
        log_msg(hf, "mod_ref", "FAIL -- module_view refresh still loading after 5s timeout (worker hung) (elapsed %lld ms)", (long long)ms);
        failed.fetch_add(1);
    } else {
        log_msg(hf, "mod_ref", "FAIL -- module_view refresh returned 0 modules; an attached process always has loaded modules (image + ntdll) (elapsed %lld ms)", (long long)ms);
        failed.fetch_add(1);
    }
}

static void test_module_view_entries(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
    log_msg(hf, "mod_ent", "START -- module_view entry inspection");
    auto t0 = std::chrono::steady_clock::now();

    std::vector<driver_bridge::module_info_t> snapshot;
    {
        std::lock_guard<std::mutex> lk(module_view::g_ui.modules_mutex);
        snapshot = module_view::g_ui.modules;
    }

    log_msg(hf, "mod_ent", "total_modules=%zu", snapshot.size());
    diag::log_tagged_fmt("test_dbg_detail", "mod_ent inputs: inspect module_view::g_ui.modules total=%zu", snapshot.size());

    for (size_t i = 0; i < snapshot.size() && i < 32; ++i) {
        const auto& m = snapshot[i];
        log_msg(hf, "mod_ent", "  [%zu] name=%s base=0x%016llX size=0x%llX",
            i,
            m.name.c_str(),
            (unsigned long long)m.base,
            (unsigned long long)m.size);
    }

    if (snapshot.size() > 32) {
        log_msg(hf, "mod_ent", "  ... and %zu more modules (truncated for log brevity)",
            snapshot.size() - 32);
    }

    size_t valid_modules = 0;
    for (const auto& m : snapshot) {
        if (m.base != 0 && m.size != 0) valid_modules++;
    }
    diag::log_tagged_fmt("test_dbg_detail", "mod_ent result: total_modules=%zu valid_modules=%zu", snapshot.size(), valid_modules);

    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - t0).count();
    if (!snapshot.empty() && valid_modules == snapshot.size()) {
        log_msg(hf, "mod_ent", "PASS -- module entry inspection complete: %zu modules, all with valid base+size (elapsed %lld ms)",
            snapshot.size(), (long long)ms);
        passed.fetch_add(1);
    } else if (snapshot.empty()) {
        log_msg(hf, "mod_ent", "FAIL -- 0 modules; an attached process always has loaded modules (run module_view_refresh first) (elapsed %lld ms)", (long long)ms);
        failed.fetch_add(1);
    } else {
        log_msg(hf, "mod_ent", "FAIL -- %zu of %zu modules have base==0 or size==0 (elapsed %lld ms)",
            snapshot.size() - valid_modules, snapshot.size(), (long long)ms);
        failed.fetch_add(1);
    }
}

static void select_debugger_tab(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed,
                                const char* tag, debugger_view::sub_tab_t value) {
    diag::log_tagged_fmt("test_dbg_detail", "%s inputs: set active_tab=%d", tag, static_cast<int>(value));
    const bool visible = debugger_view::is_visible_sub_tab(value);
    debugger_view::g_ui.active_tab = value;
    auto read_back = debugger_view::g_ui.active_tab;
    diag::log_tagged_fmt("test_dbg_detail", "%s result: active_tab read_back=%d visible=%d visible_count=%d enum_count=%d",
        tag,
        static_cast<int>(read_back),
        visible ? 1 : 0,
        debugger_view::visible_sub_tab_count(),
        static_cast<int>(debugger_view::sub_tab_t::COUNT));
    if (read_back == value && visible && debugger_view::visible_sub_tab_count() == static_cast<int>(debugger_view::sub_tab_t::COUNT)) {
        log_msg(hf, tag, "PASS -- active_tab selected and visible (%d)", static_cast<int>(value));
        passed.fetch_add(1);
    } else {
        log_msg(hf, tag, "FAIL -- active_tab visibility contract failed: set %d, read back %d, visible=%d, visible_count=%d, enum_count=%d",
            static_cast<int>(value),
            static_cast<int>(read_back),
            visible ? 1 : 0,
            debugger_view::visible_sub_tab_count(),
            static_cast<int>(debugger_view::sub_tab_t::COUNT));
        failed.fetch_add(1);
    }
}

static void test_dbg_tab_cpu(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
    select_debugger_tab(hf, passed, failed, "dbg_tab.cpu", debugger_view::sub_tab_t::cpu);
}
static void test_dbg_tab_breakpoints(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
    select_debugger_tab(hf, passed, failed, "dbg_tab.breakpoints", debugger_view::sub_tab_t::breakpoints);
}
static void test_dbg_tab_memory_map(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
    select_debugger_tab(hf, passed, failed, "dbg_tab.memory_map", debugger_view::sub_tab_t::memory_map);
}
static void test_dbg_tab_call_stack(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
    select_debugger_tab(hf, passed, failed, "dbg_tab.call_stack", debugger_view::sub_tab_t::call_stack);
}
static void test_dbg_tab_threads(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
    select_debugger_tab(hf, passed, failed, "dbg_tab.threads", debugger_view::sub_tab_t::threads);
}
static void test_dbg_tab_watches(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
    select_debugger_tab(hf, passed, failed, "dbg_tab.watches", debugger_view::sub_tab_t::watches);
}
static void test_dbg_tab_handles(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
    select_debugger_tab(hf, passed, failed, "dbg_tab.handles", debugger_view::sub_tab_t::handles);
}
static void test_dbg_tab_trace_log(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
    select_debugger_tab(hf, passed, failed, "dbg_tab.trace_log", debugger_view::sub_tab_t::trace_log);
}
static void test_dbg_tab_strings(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
    select_debugger_tab(hf, passed, failed, "dbg_tab.strings", debugger_view::sub_tab_t::strings);
}
static void test_dbg_tab_bookmarks(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
    select_debugger_tab(hf, passed, failed, "dbg_tab.bookmarks", debugger_view::sub_tab_t::bookmarks);
}
static void test_dbg_tab_modules(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
    select_debugger_tab(hf, passed, failed, "dbg_tab.modules", debugger_view::sub_tab_t::modules);
}
static void test_dbg_tab_patches(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
    select_debugger_tab(hf, passed, failed, "dbg_tab.patches", debugger_view::sub_tab_t::patches);
}
static void test_dbg_tab_seh_chain(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
    select_debugger_tab(hf, passed, failed, "dbg_tab.seh_chain", debugger_view::sub_tab_t::seh_chain);
}
static void test_dbg_tab_cfg(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
    select_debugger_tab(hf, passed, failed, "dbg_tab.cfg", debugger_view::sub_tab_t::cfg);
}

}

void phase_debugger_tests(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped, bool(*cancelled)()) {
    log_msg(hf, "debugger", "=== BEGIN debugger engine tests (83 tests) ===");

    struct test_entry_t {
        const char* name;
        void (*fn)(HANDLE, std::atomic<int>&, std::atomic<int>&);
    };

    static const test_entry_t tests[] = {
        { "add_remove_software_bp",            test_add_remove_software_bp            },
        { "add_remove_hw_execute_bp",          test_add_remove_hw_execute_bp          },
        { "add_remove_hw_write_bp",            test_add_remove_hw_write_bp            },
        { "add_remove_hw_read_bp",             test_add_remove_hw_read_bp             },
        { "memory_access_bp",                  test_memory_access_bp                  },
        { "toggle_breakpoint",                 test_toggle_breakpoint                 },
        { "set_breakpoint_condition",          test_set_breakpoint_condition           },
        { "set_breakpoint_log",                test_set_breakpoint_log                },
        { "snapshot_breakpoints",              test_snapshot_breakpoints               },
        { "clear_all_breakpoints",             test_clear_all_breakpoints             },
        { "multiple_breakpoints",              test_multiple_breakpoints              },
        { "hw_bp_size_1",                      test_hw_bp_size_1                      },
        { "hw_bp_size_2",                      test_hw_bp_size_2                      },
        { "hw_bp_size_8",                      test_hw_bp_size_8                      },
        { "one_shot_bp",                       test_one_shot_bp                       },
        { "get_registers",                     test_get_registers                     },
        { "cached_registers",                  test_cached_registers                  },
        { "set_register",                      test_set_register                      },
        { "format_segment_registers",          test_format_segment_registers          },
        { "debug_registers",                   test_debug_registers                   },
        { "get_call_stack",                    test_get_call_stack                    },
        { "get_memory_map",                    test_get_memory_map                    },
        { "memory_map_executable_filter",      test_memory_map_executable_filter      },
        { "get_thread_list",                   test_get_thread_list                   },
        { "add_remove_watch",                  test_add_remove_watch                  },
        { "refresh_watches",                   test_refresh_watches                   },
        { "snapshot_watches",                  test_snapshot_watches                  },
        { "multiple_watches",                  test_multiple_watches                  },
        { "start_stop_trace",                  test_start_stop_trace                  },
        { "trace_with_depth",                  test_trace_with_depth                  },
        { "trace_result_inspection",           test_trace_result_inspection           },
        { "set_get_comment",                   test_set_get_comment                   },
        { "comment_multiple_addresses",        test_comment_multiple_addresses        },
        { "set_get_label",                     test_set_get_label                     },
        { "label_multiple_addresses",          test_label_multiple_addresses          },
        { "label_lookup_by_name",              test_label_lookup_by_name              },
        { "toggle_bookmark",                   test_toggle_bookmark                   },
        { "bookmark_listing",                  test_bookmark_listing                  },
        { "enumerate_handles",                 test_enumerate_handles                 },
        { "handle_type_distribution",          test_handle_type_distribution          },
        { "find_strings",                      test_find_strings                      },
        { "strings_cancel",                    test_strings_cancel                    },
        { "format_flags",                      test_format_flags                      },
        { "format_flags_zero",                 test_format_flags_zero                 },
        { "format_protect",                    test_format_protect                    },
        { "format_protect_guard",              test_format_protect_guard              },
        { "request_refresh",                   test_request_refresh                   },
        { "get_disasm_window",                 test_get_disasm_window                 },
        { "disasm_refresh_ntcreatefile",        test_disasm_refresh_ntcreatefile       },
        { "disasm_refresh_ntopenfile",          test_disasm_refresh_ntopenfile         },
        { "get_stack_bytes",                   test_get_stack_bytes                   },
        { "request_dump_refresh",              test_request_dump_refresh              },
        { "invalidate_cache",                  test_invalidate_cache                  },
        { "signal_trap",                       test_signal_trap                       },
        { "pop_log_messages",                  test_pop_log_messages                  },
        { "last_error",                        test_last_error                        },
        { "dbg_status",                        test_dbg_status                        },
        { "step_into",                         test_step_into                         },
        { "step_over",                         test_step_over                         },
        { "step_out",                          test_step_out                          },
        { "run_target",                        test_run_target                        },
        { "pause_target",                      test_pause_target                      },
        { "run_to_address",                    test_run_to_address                    },
        { "restore_breakpoints_and_watches",   test_restore_breakpoints_and_watches   },
        { "clear_breakpoints_and_watches",     test_clear_breakpoints_and_watches     },
        { "seh_view_refresh",                  test_seh_view_refresh                  },
        { "seh_view_entries",                  test_seh_view_entries                  },
        { "module_view_refresh",               test_module_view_refresh               },
        { "module_view_entries",               test_module_view_entries               },

        { "dbg_tab_cpu",                       test_dbg_tab_cpu                       },
        { "dbg_tab_breakpoints",               test_dbg_tab_breakpoints               },
        { "dbg_tab_memory_map",                test_dbg_tab_memory_map                },
        { "dbg_tab_call_stack",                test_dbg_tab_call_stack                },
        { "dbg_tab_threads",                   test_dbg_tab_threads                   },
        { "dbg_tab_watches",                   test_dbg_tab_watches                   },
        { "dbg_tab_handles",                   test_dbg_tab_handles                   },
        { "dbg_tab_trace_log",                 test_dbg_tab_trace_log                 },
        { "dbg_tab_strings",                   test_dbg_tab_strings                   },
        { "dbg_tab_bookmarks",                 test_dbg_tab_bookmarks                 },
        { "dbg_tab_modules",                   test_dbg_tab_modules                   },
        { "dbg_tab_patches",                   test_dbg_tab_patches                   },
        { "dbg_tab_seh_chain",                 test_dbg_tab_seh_chain                 },
        { "dbg_tab_cfg",                       test_dbg_tab_cfg                       },
    };

    int total = static_cast<int>(sizeof(tests) / sizeof(tests[0]));
    for (int i = 0; i < total; ++i) {
        if (cancelled && cancelled()) {
            int remaining = total - i;
            skipped.fetch_add(remaining);
            log_msg(hf, "debugger", "cancelled -- skipping %d remaining tests", remaining);
            break;
        }

        log_msg(hf, "debugger", "[%d/%d] %s", i + 1, total, tests[i].name);
        char progress[160];
        std::snprintf(progress, sizeof(progress), "debugger [%d/%d] %s", i + 1, total, tests[i].name);
        set_progress_step(progress);
        __try {
            tests[i].fn(hf, passed, failed);
        }
        __except (EXCEPTION_EXECUTE_HANDLER) {
            DWORD code = GetExceptionCode();
            log_msg(hf, "debugger", "FAIL -- %s threw SEH exception 0x%08X",
                tests[i].name, code);
            if (code == 0x80000004UL) {
                scrub_target_hardware_breakpoints(hf, "STATUS_SINGLE_STEP exception handler");
            }
            failed.fetch_add(1);
        }
    }

    set_progress_step("debugger complete");
    log_msg(hf, "debugger", "=== END debugger engine tests ===");
}

}
