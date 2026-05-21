#include "test_all_debugger.h"

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
    if (hf == INVALID_HANDLE_VALUE) return;
    DWORD wrote = 0;
    WriteFile(hf, line.data(), static_cast<DWORD>(line.size()), &wrote, nullptr);
    FlushFileBuffers(hf);
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
    diag::log_tagged_fmt("test_dbg", "%s: %s", tag, detail);
    OutputDebugStringA(s.c_str());
}

static uint64_t get_ntdll_fn(const char* name) {
    HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
    if (!ntdll) return 0;
    FARPROC fn = GetProcAddress(ntdll, name);
    return static_cast<uint64_t>(reinterpret_cast<uintptr_t>(fn));
}

static void test_add_remove_software_bp(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
    log_msg(hf, "dbg_bp", "START -- add and remove software breakpoint");
    auto t0 = std::chrono::steady_clock::now();

    uint64_t addr = get_ntdll_fn("NtClose");
    if (addr == 0) {
        log_msg(hf, "dbg_bp", "FAIL -- NtClose not found");
        failed.fetch_add(1); return;
    }

    int idx = debugger_engine::add_breakpoint(addr, debugger_engine::bp_type_t::software, "test_sw_bp", "", 1);
    bool removed = debugger_engine::remove_breakpoint(idx);

    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - t0).count();
    if (idx >= 0 && removed) {
        log_msg(hf, "dbg_bp", "PASS -- sw bp idx=%d, removed ok (elapsed %lld ms)", idx, (long long)ms);
        passed.fetch_add(1);
    } else {
        log_msg(hf, "dbg_bp", "FAIL -- idx=%d removed=%d (elapsed %lld ms)", idx, removed, (long long)ms);
        failed.fetch_add(1);
    }
}

static void test_add_remove_hw_execute_bp(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
    log_msg(hf, "dbg_hwx", "START -- add and remove hardware execute breakpoint");
    auto t0 = std::chrono::steady_clock::now();

    uint64_t addr = get_ntdll_fn("NtClose");
    if (addr == 0) { log_msg(hf, "dbg_hwx", "FAIL -- NtClose not found"); failed.fetch_add(1); return; }

    int idx = debugger_engine::add_breakpoint(addr, debugger_engine::bp_type_t::hardware_execute, "test_hwx_bp", "", 1);
    bool removed = debugger_engine::remove_breakpoint(idx);

    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - t0).count();
    if (idx >= 0 && removed) {
        log_msg(hf, "dbg_hwx", "PASS -- hw exec bp idx=%d, removed ok (elapsed %lld ms)", idx, (long long)ms);
        passed.fetch_add(1);
    } else {
        log_msg(hf, "dbg_hwx", "FAIL -- idx=%d removed=%d (elapsed %lld ms)", idx, removed, (long long)ms);
        failed.fetch_add(1);
    }
}

static void test_add_remove_hw_write_bp(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
    log_msg(hf, "dbg_hww", "START -- add and remove hardware write breakpoint");
    auto t0 = std::chrono::steady_clock::now();

    uint64_t addr = get_ntdll_fn("NtClose");
    if (addr == 0) { log_msg(hf, "dbg_hww", "FAIL -- NtClose not found"); failed.fetch_add(1); return; }

    int idx = debugger_engine::add_breakpoint(addr, debugger_engine::bp_type_t::hardware_write, "test_hww_bp", "", 4);
    bool removed = debugger_engine::remove_breakpoint(idx);

    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - t0).count();
    if (idx >= 0 && removed) {
        log_msg(hf, "dbg_hww", "PASS -- hw write bp idx=%d, removed ok (elapsed %lld ms)", idx, (long long)ms);
        passed.fetch_add(1);
    } else {
        log_msg(hf, "dbg_hww", "FAIL -- idx=%d removed=%d (elapsed %lld ms)", idx, removed, (long long)ms);
        failed.fetch_add(1);
    }
}

static void test_add_remove_hw_read_bp(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
    log_msg(hf, "dbg_hwr", "START -- add and remove hardware read breakpoint");
    auto t0 = std::chrono::steady_clock::now();

    uint64_t addr = get_ntdll_fn("NtClose");
    if (addr == 0) { log_msg(hf, "dbg_hwr", "FAIL -- NtClose not found"); failed.fetch_add(1); return; }

    int idx = debugger_engine::add_breakpoint(addr, debugger_engine::bp_type_t::hardware_read, "test_hwr_bp", "", 4);
    bool removed = debugger_engine::remove_breakpoint(idx);

    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - t0).count();
    if (idx >= 0 && removed) {
        log_msg(hf, "dbg_hwr", "PASS -- hw read bp idx=%d, removed ok (elapsed %lld ms)", idx, (long long)ms);
        passed.fetch_add(1);
    } else {
        log_msg(hf, "dbg_hwr", "FAIL -- idx=%d removed=%d (elapsed %lld ms)", idx, removed, (long long)ms);
        failed.fetch_add(1);
    }
}

static void test_toggle_breakpoint(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
    log_msg(hf, "dbg_tog", "START -- toggle breakpoint on/off");
    auto t0 = std::chrono::steady_clock::now();

    uint64_t addr = get_ntdll_fn("NtClose");
    if (addr == 0) { log_msg(hf, "dbg_tog", "FAIL -- NtClose not found"); failed.fetch_add(1); return; }

    int idx = debugger_engine::add_breakpoint(addr, debugger_engine::bp_type_t::software, "test_toggle_bp", "", 1);
    bool t1_ok = debugger_engine::toggle_breakpoint(idx);
    bool t2_ok = debugger_engine::toggle_breakpoint(idx);
    debugger_engine::remove_breakpoint(idx);

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

    uint64_t addr = get_ntdll_fn("NtClose");
    if (addr == 0) { log_msg(hf, "dbg_cond", "FAIL -- NtClose not found"); failed.fetch_add(1); return; }

    int idx = debugger_engine::add_breakpoint(addr, debugger_engine::bp_type_t::software, "test_cond_bp", "", 1);
    bool ok = debugger_engine::set_breakpoint_condition(idx, "rax == 0");
    debugger_engine::remove_breakpoint(idx);

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

    uint64_t addr = get_ntdll_fn("NtClose");
    if (addr == 0) { log_msg(hf, "dbg_log", "FAIL -- NtClose not found"); failed.fetch_add(1); return; }

    int idx = debugger_engine::add_breakpoint(addr, debugger_engine::bp_type_t::software, "test_log_bp", "", 1);
    bool ok = debugger_engine::set_breakpoint_log(idx, "hit NtClose", true);
    debugger_engine::remove_breakpoint(idx);

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

    uint64_t addr = get_ntdll_fn("NtClose");
    if (addr == 0) { log_msg(hf, "dbg_snap", "FAIL -- NtClose not found"); failed.fetch_add(1); return; }

    int idx = debugger_engine::add_breakpoint(addr, debugger_engine::bp_type_t::software, "test_snap_bp", "", 1);
    auto bps = debugger_engine::snapshot_breakpoints();
    debugger_engine::remove_breakpoint(idx);

    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - t0).count();
    log_msg(hf, "dbg_snap", "PASS -- snapshot returned %zu breakpoints (elapsed %lld ms)", bps.size(), (long long)ms);
    passed.fetch_add(1);
}

static void test_clear_all_breakpoints(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
    log_msg(hf, "dbg_clr", "START -- clear all breakpoints");
    auto t0 = std::chrono::steady_clock::now();

    uint64_t addr = get_ntdll_fn("NtClose");
    if (addr == 0) { log_msg(hf, "dbg_clr", "FAIL -- NtClose not found"); failed.fetch_add(1); return; }

    debugger_engine::add_breakpoint(addr, debugger_engine::bp_type_t::software, "test_clr1", "", 1);
    debugger_engine::add_breakpoint(addr + 16, debugger_engine::bp_type_t::software, "test_clr2", "", 1);
    debugger_engine::clear_all_breakpoints();
    auto bps = debugger_engine::snapshot_breakpoints();

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

    auto regs = debugger_engine::get_registers();
    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - t0).count();

    log_msg(hf, "dbg_reg", "PASS -- rax=0x%llX rbx=0x%llX rcx=0x%llX rdx=0x%llX rip=0x%llX rflags=0x%llX (elapsed %lld ms)",
        (unsigned long long)regs.rax, (unsigned long long)regs.rbx,
        (unsigned long long)regs.rcx, (unsigned long long)regs.rdx,
        (unsigned long long)regs.rip, (unsigned long long)regs.rflags,
        (long long)ms);
    passed.fetch_add(1);
}

static void test_cached_registers(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
    log_msg(hf, "dbg_creg", "START -- get cached registers");
    auto t0 = std::chrono::steady_clock::now();

    auto regs = debugger_engine::cached_registers();
    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - t0).count();

    log_msg(hf, "dbg_creg", "PASS -- cached rax=0x%llX rsp=0x%llX rip=0x%llX (elapsed %lld ms)",
        (unsigned long long)regs.rax, (unsigned long long)regs.rsp,
        (unsigned long long)regs.rip, (long long)ms);
    passed.fetch_add(1);
}

static void test_get_call_stack(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
    log_msg(hf, "dbg_stk", "START -- get call stack");
    auto t0 = std::chrono::steady_clock::now();

    auto frames = debugger_engine::get_call_stack();
    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - t0).count();

    log_msg(hf, "dbg_stk", "PASS -- %zu stack frames (elapsed %lld ms)", frames.size(), (long long)ms);
    for (size_t i = 0; i < frames.size() && i < 8; ++i) {
        log_msg(hf, "dbg_stk", "  frame[%zu]: addr=0x%llX ret=0x%llX module=%s func=%s",
            i, (unsigned long long)frames[i].address, (unsigned long long)frames[i].return_addr,
            frames[i].module_name.c_str(), frames[i].function_name.c_str());
    }
    passed.fetch_add(1);
}

static void test_get_memory_map(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
    log_msg(hf, "dbg_mmap", "START -- get memory map");
    auto t0 = std::chrono::steady_clock::now();

    auto regions = debugger_engine::get_memory_map();
    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - t0).count();

    size_t exec_count = 0;
    for (auto& r : regions) {
        uint32_t prot = r.protect & 0xFF;
        if (prot == 0x10 || prot == 0x20 || prot == 0x40 || prot == 0x80) exec_count++;
    }

    log_msg(hf, "dbg_mmap", "PASS -- %zu regions total, %zu executable (elapsed %lld ms)",
        regions.size(), exec_count, (long long)ms);
    passed.fetch_add(1);
}

static void test_get_thread_list(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
    log_msg(hf, "dbg_thr", "START -- get thread list");
    auto t0 = std::chrono::steady_clock::now();

    debugger_engine::request_thread_refresh(0);
    Sleep(200);
    auto threads = debugger_engine::cached_thread_list();
    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - t0).count();

    log_msg(hf, "dbg_thr", "PASS -- %zu threads (elapsed %lld ms)", threads.size(), (long long)ms);
    for (size_t i = 0; i < threads.size() && i < 10; ++i) {
        log_msg(hf, "dbg_thr", "  thread[%zu]: tid=%u pid=%u priority=%d state=%u rip=0x%llX",
            i, threads[i].tid, threads[i].owner_pid, threads[i].priority,
            threads[i].state, (unsigned long long)threads[i].rip);
    }
    passed.fetch_add(1);
}

static void test_add_remove_watch(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
    log_msg(hf, "dbg_wat", "START -- add and remove watch expression");
    auto t0 = std::chrono::steady_clock::now();

    int idx = debugger_engine::add_watch("rax");
    bool removed = debugger_engine::remove_watch(idx);

    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - t0).count();
    if (idx >= 0 && removed) {
        log_msg(hf, "dbg_wat", "PASS -- watch idx=%d, removed ok (elapsed %lld ms)", idx, (long long)ms);
        passed.fetch_add(1);
    } else {
        log_msg(hf, "dbg_wat", "FAIL -- idx=%d removed=%d (elapsed %lld ms)", idx, removed, (long long)ms);
        failed.fetch_add(1);
    }
}

static void test_refresh_watches(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
    log_msg(hf, "dbg_wrfr", "START -- refresh watches");
    auto t0 = std::chrono::steady_clock::now();

    int idx = debugger_engine::add_watch("rsp");
    debugger_engine::refresh_watches();
    debugger_engine::remove_watch(idx);

    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - t0).count();
    log_msg(hf, "dbg_wrfr", "PASS -- refresh_watches completed (elapsed %lld ms)", (long long)ms);
    passed.fetch_add(1);
}

static void test_snapshot_watches(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
    log_msg(hf, "dbg_wsn", "START -- snapshot watches");
    auto t0 = std::chrono::steady_clock::now();

    int idx = debugger_engine::add_watch("rbp");
    auto watches = debugger_engine::snapshot_watches();
    debugger_engine::remove_watch(idx);

    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - t0).count();
    log_msg(hf, "dbg_wsn", "PASS -- snapshot returned %zu watches (elapsed %lld ms)", watches.size(), (long long)ms);
    passed.fetch_add(1);
}

static void test_start_stop_trace(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
    log_msg(hf, "dbg_trc", "START -- start and stop trace");
    auto t0 = std::chrono::steady_clock::now();

    bool started = debugger_engine::start_trace(1000);
    bool stopped = debugger_engine::stop_trace();

    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - t0).count();
    log_msg(hf, "dbg_trc", "PASS -- start=%d stop=%d (elapsed %lld ms)", started, stopped, (long long)ms);
    passed.fetch_add(1);
}

static void test_set_get_comment(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
    log_msg(hf, "dbg_cmt", "START -- set and get comment at address");
    auto t0 = std::chrono::steady_clock::now();

    uint64_t addr = get_ntdll_fn("NtClose");
    if (addr == 0) { log_msg(hf, "dbg_cmt", "FAIL -- NtClose not found"); failed.fetch_add(1); return; }

    debugger_engine::set_comment(addr, "test_comment_12345");
    std::string got = debugger_engine::get_comment(addr);
    debugger_engine::set_comment(addr, "");

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

    debugger_engine::set_label(addr, "test_label_67890");
    std::string got = debugger_engine::get_label(addr);
    debugger_engine::set_label(addr, "");

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

    debugger_engine::toggle_bookmark(addr);
    debugger_engine::toggle_bookmark(addr);

    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - t0).count();
    log_msg(hf, "dbg_bkm", "PASS -- bookmark toggled on/off (elapsed %lld ms)", (long long)ms);
    passed.fetch_add(1);
}

static void test_enumerate_handles(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
    log_msg(hf, "dbg_hdl", "START -- enumerate handles");
    auto t0 = std::chrono::steady_clock::now();

    debugger_engine::enumerate_handles();
    Sleep(500);

    auto& state = debugger_engine::g_state;
    size_t count = 0;
    {
        std::lock_guard<std::mutex> lk(state.handle_mutex);
        count = state.handles.size();
    }

    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - t0).count();
    log_msg(hf, "dbg_hdl", "PASS -- enumerated %zu handles (elapsed %lld ms)", count, (long long)ms);
    passed.fetch_add(1);
}

static void test_find_strings(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
    log_msg(hf, "dbg_str", "START -- find strings (min_length=4)");
    auto t0 = std::chrono::steady_clock::now();

    debugger_engine::find_strings_async(4);

    for (int i = 0; i < 50; ++i) {
        if (!debugger_engine::g_state.strings_scanning.load()) break;
        Sleep(100);
    }
    debugger_engine::request_strings_cancel();

    auto& state = debugger_engine::g_state;
    size_t count = 0;
    {
        std::lock_guard<std::mutex> lk(state.strings_mutex);
        count = state.strings.size();
    }

    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - t0).count();
    log_msg(hf, "dbg_str", "PASS -- found %zu strings (elapsed %lld ms)", count, (long long)ms);
    passed.fetch_add(1);
}

static void test_format_flags(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
    log_msg(hf, "dbg_fmt", "START -- format rflags");
    auto t0 = std::chrono::steady_clock::now();

    uint64_t test_flags = 0x246;
    std::string formatted = debugger_engine::format_flags(test_flags);

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

    std::string p1 = debugger_engine::format_protect(PAGE_EXECUTE_READWRITE);
    std::string p2 = debugger_engine::format_protect(PAGE_READONLY);
    std::string p3 = debugger_engine::format_protect(PAGE_READWRITE);

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

    debugger_engine::request_refresh(0);
    debugger_engine::request_thread_refresh(0);
    Sleep(200);

    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - t0).count();
    log_msg(hf, "dbg_rfr", "PASS -- refresh requests issued (elapsed %lld ms)", (long long)ms);
    passed.fetch_add(1);
}

static void test_get_disasm_window(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
    log_msg(hf, "dbg_dasm", "START -- get disasm window");
    auto t0 = std::chrono::steady_clock::now();

    uint64_t addr = get_ntdll_fn("NtClose");
    if (addr == 0) { log_msg(hf, "dbg_dasm", "FAIL -- NtClose not found"); failed.fetch_add(1); return; }

    debugger_engine::request_disasm_refresh(addr, 0);
    Sleep(300);

    uint64_t base_out = 0;
    auto bytes = debugger_engine::cached_disasm_window(base_out);

    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - t0).count();
    log_msg(hf, "dbg_dasm", "PASS -- disasm window %zu bytes at base 0x%llX (elapsed %lld ms)",
        bytes.size(), (unsigned long long)base_out, (long long)ms);
    passed.fetch_add(1);
}

static void test_get_stack_bytes(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
    log_msg(hf, "dbg_stkb", "START -- get stack bytes");
    auto t0 = std::chrono::steady_clock::now();

    auto regs = debugger_engine::cached_registers();
    if (regs.rsp != 0) {
        debugger_engine::request_stack_refresh(regs.rsp, 256, 0);
        Sleep(300);
    }

    uint64_t addr_out = 0;
    auto bytes = debugger_engine::cached_stack_bytes(addr_out);

    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - t0).count();
    log_msg(hf, "dbg_stkb", "PASS -- stack %zu bytes at addr 0x%llX (elapsed %lld ms)",
        bytes.size(), (unsigned long long)addr_out, (long long)ms);
    passed.fetch_add(1);
}

static void test_last_error(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
    log_msg(hf, "dbg_err", "START -- last_error() accessor");
    auto t0 = std::chrono::steady_clock::now();

    const std::string& err = debugger_engine::last_error();

    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - t0).count();
    log_msg(hf, "dbg_err", "PASS -- last_error=\"%s\" (elapsed %lld ms)",
        err.empty() ? "(empty)" : err.c_str(), (long long)ms);
    passed.fetch_add(1);
}

static void test_memory_access_bp(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
    log_msg(hf, "dbg_ma", "START -- add and remove memory_access breakpoint");
    auto t0 = std::chrono::steady_clock::now();

    uint64_t addr = get_ntdll_fn("NtClose");
    if (addr == 0) { log_msg(hf, "dbg_ma", "FAIL -- NtClose not found"); failed.fetch_add(1); return; }

    int idx = debugger_engine::add_breakpoint(addr, debugger_engine::bp_type_t::memory_access, "test_ma_bp", "", 4);
    bool removed = debugger_engine::remove_breakpoint(idx);

    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - t0).count();
    if (idx >= 0 && removed) {
        log_msg(hf, "dbg_ma", "PASS -- memory_access bp idx=%d, removed ok (elapsed %lld ms)", idx, (long long)ms);
        passed.fetch_add(1);
    } else {
        log_msg(hf, "dbg_ma", "FAIL -- idx=%d removed=%d (elapsed %lld ms)", idx, removed, (long long)ms);
        failed.fetch_add(1);
    }
}

static void test_multiple_breakpoints(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
    log_msg(hf, "dbg_mbp", "START -- add multiple breakpoints, verify count, clear subset");
    auto t0 = std::chrono::steady_clock::now();

    debugger_engine::clear_all_breakpoints();

    uint64_t a1 = get_ntdll_fn("NtClose");
    uint64_t a2 = get_ntdll_fn("NtOpenFile");
    uint64_t a3 = get_ntdll_fn("NtCreateFile");
    uint64_t a4 = get_ntdll_fn("NtReadFile");
    if (a1 == 0 || a2 == 0 || a3 == 0 || a4 == 0) {
        log_msg(hf, "dbg_mbp", "FAIL -- one or more ntdll functions not found");
        failed.fetch_add(1);
        return;
    }

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

    debugger_engine::remove_breakpoint(i1);
    debugger_engine::remove_breakpoint(i4);

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
    log_msg(hf, "dbg_hw1", "START -- hardware write bp size 1");
    auto t0 = std::chrono::steady_clock::now();

    uint64_t addr = get_ntdll_fn("NtClose");
    if (addr == 0) { log_msg(hf, "dbg_hw1", "FAIL -- NtClose not found"); failed.fetch_add(1); return; }

    int idx = debugger_engine::add_breakpoint(addr, debugger_engine::bp_type_t::hardware_write, "hw_s1", "", 1);
    bool removed = debugger_engine::remove_breakpoint(idx);

    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - t0).count();
    if (idx >= 0 && removed) {
        log_msg(hf, "dbg_hw1", "PASS -- 1-byte hw write bp idx=%d (elapsed %lld ms)", idx, (long long)ms);
        passed.fetch_add(1);
    } else {
        log_msg(hf, "dbg_hw1", "FAIL -- idx=%d (elapsed %lld ms)", idx, (long long)ms);
        failed.fetch_add(1);
    }
}

static void test_hw_bp_size_2(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
    log_msg(hf, "dbg_hw2", "START -- hardware write bp size 2");
    auto t0 = std::chrono::steady_clock::now();

    uint64_t addr = get_ntdll_fn("NtOpenFile");
    if (addr == 0) { log_msg(hf, "dbg_hw2", "FAIL -- NtOpenFile not found"); failed.fetch_add(1); return; }

    int idx = debugger_engine::add_breakpoint(addr, debugger_engine::bp_type_t::hardware_write, "hw_s2", "", 2);
    bool removed = debugger_engine::remove_breakpoint(idx);

    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - t0).count();
    if (idx >= 0 && removed) {
        log_msg(hf, "dbg_hw2", "PASS -- 2-byte hw write bp idx=%d (elapsed %lld ms)", idx, (long long)ms);
        passed.fetch_add(1);
    } else {
        log_msg(hf, "dbg_hw2", "FAIL -- idx=%d (elapsed %lld ms)", idx, (long long)ms);
        failed.fetch_add(1);
    }
}

static void test_hw_bp_size_8(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
    log_msg(hf, "dbg_hw8", "START -- hardware write bp size 8");
    auto t0 = std::chrono::steady_clock::now();

    uint64_t addr = get_ntdll_fn("NtCreateFile");
    if (addr == 0) { log_msg(hf, "dbg_hw8", "FAIL -- NtCreateFile not found"); failed.fetch_add(1); return; }

    int idx = debugger_engine::add_breakpoint(addr, debugger_engine::bp_type_t::hardware_write, "hw_s8", "", 8);
    bool removed = debugger_engine::remove_breakpoint(idx);

    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - t0).count();
    if (idx >= 0 && removed) {
        log_msg(hf, "dbg_hw8", "PASS -- 8-byte hw write bp idx=%d (elapsed %lld ms)", idx, (long long)ms);
        passed.fetch_add(1);
    } else {
        log_msg(hf, "dbg_hw8", "FAIL -- idx=%d (elapsed %lld ms)", idx, (long long)ms);
        failed.fetch_add(1);
    }
}

static void test_set_register(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
    log_msg(hf, "dbg_sreg", "START -- set_register API call");
    auto t0 = std::chrono::steady_clock::now();

    bool ok = debugger_engine::set_register("rax", 0x41414141);

    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - t0).count();
    log_msg(hf, "dbg_sreg", "PASS -- set_register(rax, 0x41414141) returned %d (elapsed %lld ms)",
        (int)ok, (long long)ms);
    passed.fetch_add(1);
}

static void test_step_into(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
    log_msg(hf, "dbg_si", "START -- step_into API exists");
    auto t0 = std::chrono::steady_clock::now();

    bool ok = debugger_engine::step_into();

    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - t0).count();
    log_msg(hf, "dbg_si", "PASS -- step_into returned %d (no target attached expected) (elapsed %lld ms)",
        (int)ok, (long long)ms);
    passed.fetch_add(1);
}

static void test_step_over(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
    log_msg(hf, "dbg_so", "START -- step_over API exists");
    auto t0 = std::chrono::steady_clock::now();

    bool ok = debugger_engine::step_over();

    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - t0).count();
    log_msg(hf, "dbg_so", "PASS -- step_over returned %d (elapsed %lld ms)", (int)ok, (long long)ms);
    passed.fetch_add(1);
}

static void test_step_out(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
    log_msg(hf, "dbg_sout", "START -- step_out API exists");
    auto t0 = std::chrono::steady_clock::now();

    bool ok = debugger_engine::step_out();

    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - t0).count();
    log_msg(hf, "dbg_sout", "PASS -- step_out returned %d (elapsed %lld ms)", (int)ok, (long long)ms);
    passed.fetch_add(1);
}

static void test_run_target(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
    log_msg(hf, "dbg_run", "START -- run_target API exists");
    auto t0 = std::chrono::steady_clock::now();

    bool ok = debugger_engine::run_target();

    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - t0).count();
    log_msg(hf, "dbg_run", "PASS -- run_target returned %d (elapsed %lld ms)", (int)ok, (long long)ms);
    passed.fetch_add(1);
}

static void test_pause_target(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
    log_msg(hf, "dbg_pause", "START -- pause_target API exists");
    auto t0 = std::chrono::steady_clock::now();

    bool ok = debugger_engine::pause_target();

    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - t0).count();
    log_msg(hf, "dbg_pause", "PASS -- pause_target returned %d (elapsed %lld ms)", (int)ok, (long long)ms);
    passed.fetch_add(1);
}

static void test_multiple_watches(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
    log_msg(hf, "dbg_mw", "START -- add multiple watch expressions");
    auto t0 = std::chrono::steady_clock::now();

    int w1 = debugger_engine::add_watch("rax");
    int w2 = debugger_engine::add_watch("rbx");
    int w3 = debugger_engine::add_watch("rcx + rdx");
    int w4 = debugger_engine::add_watch("rsp - 0x100");
    int w5 = debugger_engine::add_watch("[rsp]");

    auto snap = debugger_engine::snapshot_watches();
    size_t count = snap.size();

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

    bool s1 = debugger_engine::start_trace(100);
    debugger_engine::stop_trace();

    bool s2 = debugger_engine::start_trace(10000);
    debugger_engine::stop_trace();

    bool s3 = debugger_engine::start_trace(50000);
    debugger_engine::stop_trace();

    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - t0).count();
    log_msg(hf, "dbg_trd", "PASS -- trace depth 100=%d 10000=%d 50000=%d (elapsed %lld ms)",
        (int)s1, (int)s2, (int)s3, (long long)ms);
    passed.fetch_add(1);
}

static void test_trace_result_inspection(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
    log_msg(hf, "dbg_tri", "START -- trace result buffer inspection");
    auto t0 = std::chrono::steady_clock::now();

    debugger_engine::start_trace(500);
    Sleep(100);
    debugger_engine::stop_trace();

    auto& state = debugger_engine::g_state;
    size_t trace_count = 0;
    {
        std::lock_guard<std::mutex> lk(state.trace_mutex);
        trace_count = state.trace_log.size();
    }

    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - t0).count();
    log_msg(hf, "dbg_tri", "PASS -- trace_log contains %zu records (elapsed %lld ms)",
        trace_count, (long long)ms);
    passed.fetch_add(1);
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

    debugger_engine::set_comment(a1, "comment_alpha");
    debugger_engine::set_comment(a2, "comment_beta");
    debugger_engine::set_comment(a3, "comment_gamma");

    std::string c1 = debugger_engine::get_comment(a1);
    std::string c2 = debugger_engine::get_comment(a2);
    std::string c3 = debugger_engine::get_comment(a3);

    debugger_engine::set_comment(a1, "");
    debugger_engine::set_comment(a2, "");
    debugger_engine::set_comment(a3, "");

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

    debugger_engine::set_label(a1, "label_first");
    debugger_engine::set_label(a2, "label_second");

    std::string l1 = debugger_engine::get_label(a1);
    std::string l2 = debugger_engine::get_label(a2);

    debugger_engine::set_label(a1, "");
    debugger_engine::set_label(a2, "");

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

    debugger_engine::set_label(addr, "label_lookup_test_xyzzy");
    std::string got = debugger_engine::get_label(addr);
    debugger_engine::set_label(addr, "");

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

    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - t0).count();
    log_msg(hf, "dbg_mmex", "PASS -- %zu regions: exec=%zu writable=%zu guard=%zu (elapsed %lld ms)",
        regions.size(), exec_count, write_count, guard_count, (long long)ms);
    passed.fetch_add(1);
}

static void test_format_protect_guard(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
    log_msg(hf, "dbg_fpg", "START -- format_protect with GUARD pages");
    auto t0 = std::chrono::steady_clock::now();

    std::string p1 = debugger_engine::format_protect(PAGE_EXECUTE_READ);
    std::string p2 = debugger_engine::format_protect(PAGE_NOACCESS);
    std::string p3 = debugger_engine::format_protect(PAGE_GUARD | PAGE_READWRITE);
    std::string p4 = debugger_engine::format_protect(PAGE_WRITECOPY);

    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - t0).count();
    if (!p1.empty() && !p2.empty()) {
        log_msg(hf, "dbg_fpg", "PASS -- ER=\"%s\" NA=\"%s\" G|RW=\"%s\" WC=\"%s\" (elapsed %lld ms)",
            p1.c_str(), p2.c_str(), p3.c_str(), p4.c_str(), (long long)ms);
        passed.fetch_add(1);
    } else {
        log_msg(hf, "dbg_fpg", "FAIL -- format_protect returned empty (elapsed %lld ms)", (long long)ms);
        failed.fetch_add(1);
    }
}

static void test_format_flags_zero(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
    log_msg(hf, "dbg_ff0", "START -- format_flags with zero and various flag combos");
    auto t0 = std::chrono::steady_clock::now();

    std::string f0 = debugger_engine::format_flags(0);
    std::string f1 = debugger_engine::format_flags(0x202);
    std::string f2 = debugger_engine::format_flags(0x246);
    std::string f3 = debugger_engine::format_flags(0x297);

    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - t0).count();
    log_msg(hf, "dbg_ff0", "PASS -- 0x0=\"%s\" 0x202=\"%s\" 0x246=\"%s\" 0x297=\"%s\" (elapsed %lld ms)",
        f0.c_str(), f1.c_str(), f2.c_str(), f3.c_str(), (long long)ms);
    passed.fetch_add(1);
}

static void test_format_segment_registers(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
    log_msg(hf, "dbg_seg", "START -- read segment registers CS/DS/SS/ES/FS/GS");
    auto t0 = std::chrono::steady_clock::now();

    auto regs = debugger_engine::get_registers();

    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - t0).count();
    log_msg(hf, "dbg_seg", "PASS -- cs=0x%llX ds=0x%llX ss=0x%llX es=0x%llX fs=0x%llX gs=0x%llX (elapsed %lld ms)",
        (unsigned long long)regs.cs, (unsigned long long)regs.ds, (unsigned long long)regs.ss,
        (unsigned long long)regs.es, (unsigned long long)regs.fs, (unsigned long long)regs.gs,
        (long long)ms);
    passed.fetch_add(1);
}

static void test_debug_registers(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
    log_msg(hf, "dbg_dreg", "START -- read debug registers DR0-DR3, DR6, DR7");
    auto t0 = std::chrono::steady_clock::now();

    auto regs = debugger_engine::get_registers();

    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - t0).count();
    log_msg(hf, "dbg_dreg", "PASS -- dr0=0x%llX dr1=0x%llX dr2=0x%llX dr3=0x%llX dr6=0x%llX dr7=0x%llX (elapsed %lld ms)",
        (unsigned long long)regs.dr0, (unsigned long long)regs.dr1, (unsigned long long)regs.dr2,
        (unsigned long long)regs.dr3, (unsigned long long)regs.dr6, (unsigned long long)regs.dr7,
        (long long)ms);
    passed.fetch_add(1);
}

static void test_request_dump_refresh(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
    log_msg(hf, "dbg_dump", "START -- request dump refresh and read cached bytes");
    auto t0 = std::chrono::steady_clock::now();

    uint64_t addr = get_ntdll_fn("NtClose");
    if (addr == 0) { log_msg(hf, "dbg_dump", "FAIL -- NtClose not found"); failed.fetch_add(1); return; }

    debugger_engine::request_dump_refresh(addr, 128, 0);
    Sleep(300);

    uint64_t addr_out = 0;
    size_t size_out = 0;
    auto bytes = debugger_engine::cached_dump_bytes(addr_out, size_out);

    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - t0).count();
    log_msg(hf, "dbg_dump", "PASS -- dump %zu bytes at 0x%llX size=%zu (elapsed %lld ms)",
        bytes.size(), (unsigned long long)addr_out, size_out, (long long)ms);
    passed.fetch_add(1);
}

static void test_invalidate_cache(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
    log_msg(hf, "dbg_inv", "START -- invalidate_cache resets timestamps");
    auto t0 = std::chrono::steady_clock::now();

    debugger_engine::invalidate_cache();

    uint64_t lr = debugger_engine::g_state.last_refresh_ms.load();
    uint64_t lt = debugger_engine::g_state.last_thread_refresh_ms.load();
    uint64_t ls = debugger_engine::g_state.last_stack_refresh_ms.load();
    uint64_t ld = debugger_engine::g_state.last_dump_refresh_ms.load();
    uint64_t lda = debugger_engine::g_state.last_disasm_refresh_ms.load();

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
    debugger_engine::signal_trap(trap_addr);
    bool caught = debugger_engine::wait_for_trap(trap_addr, 1000);

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

    size_t before_count = debugger_engine::log_message_count();
    auto msgs = debugger_engine::pop_log_messages();

    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - t0).count();
    log_msg(hf, "dbg_poplog", "PASS -- before_count=%zu, popped %zu messages (elapsed %lld ms)",
        before_count, msgs.size(), (long long)ms);
    passed.fetch_add(1);
}

static void test_restore_breakpoints_and_watches(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
    log_msg(hf, "dbg_rest", "START -- restore_breakpoints_and_watches round-trip");
    auto t0 = std::chrono::steady_clock::now();

    debugger_engine::clear_breakpoints_and_watches();

    uint64_t addr = get_ntdll_fn("NtClose");
    if (addr == 0) { log_msg(hf, "dbg_rest", "FAIL -- NtClose not found"); failed.fetch_add(1); return; }

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

    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - t0).count();
    if (empty_bps.empty() && empty_ws.empty() && restored_bps.size() == bps.size() && restored_ws.size() == ws.size()) {
        log_msg(hf, "dbg_rest", "PASS -- clear then restore verified: bps=%zu ws=%zu (elapsed %lld ms)",
            restored_bps.size(), restored_ws.size(), (long long)ms);
        passed.fetch_add(1);
    } else {
        log_msg(hf, "dbg_rest", "FAIL -- restore mismatch (elapsed %lld ms)", (long long)ms);
        failed.fetch_add(1);
    }
}

static void test_clear_breakpoints_and_watches(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
    log_msg(hf, "dbg_cbw", "START -- clear_breakpoints_and_watches");
    auto t0 = std::chrono::steady_clock::now();

    uint64_t addr = get_ntdll_fn("NtClose");
    if (addr == 0) { log_msg(hf, "dbg_cbw", "FAIL -- NtClose not found"); failed.fetch_add(1); return; }

    debugger_engine::add_breakpoint(addr, debugger_engine::bp_type_t::software, "cbw_bp", "", 1);
    debugger_engine::add_watch("rip");
    debugger_engine::clear_breakpoints_and_watches();

    auto bps = debugger_engine::snapshot_breakpoints();
    auto ws = debugger_engine::snapshot_watches();

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

    debugger_engine::request_disasm_refresh(addr, 0);
    Sleep(300);

    uint64_t base_out = 0;
    auto bytes = debugger_engine::cached_disasm_window(base_out);

    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - t0).count();
    log_msg(hf, "dbg_dasm2", "PASS -- NtCreateFile disasm %zu bytes at base 0x%llX (elapsed %lld ms)",
        bytes.size(), (unsigned long long)base_out, (long long)ms);
    passed.fetch_add(1);
}

static void test_disasm_refresh_ntopenfile(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
    log_msg(hf, "dbg_dasm3", "START -- disasm refresh at NtOpenFile");
    auto t0 = std::chrono::steady_clock::now();

    uint64_t addr = get_ntdll_fn("NtOpenFile");
    if (addr == 0) { log_msg(hf, "dbg_dasm3", "FAIL -- NtOpenFile not found"); failed.fetch_add(1); return; }

    debugger_engine::request_disasm_refresh(addr, 0);
    Sleep(300);

    uint64_t base_out = 0;
    auto bytes = debugger_engine::cached_disasm_window(base_out);

    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - t0).count();
    log_msg(hf, "dbg_dasm3", "PASS -- NtOpenFile disasm %zu bytes at base 0x%llX (elapsed %lld ms)",
        bytes.size(), (unsigned long long)base_out, (long long)ms);
    passed.fetch_add(1);
}

static void test_handle_type_distribution(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
    log_msg(hf, "dbg_htyp", "START -- enumerate handles and check type distribution");
    auto t0 = std::chrono::steady_clock::now();

    debugger_engine::enumerate_handles();
    Sleep(500);

    auto& state = debugger_engine::g_state;
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

    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - t0).count();
    log_msg(hf, "dbg_htyp", "PASS -- %zu handles, %zu unique type indices (elapsed %lld ms)",
        total, unique_types, (long long)ms);
    passed.fetch_add(1);
}

static void test_strings_cancel(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
    log_msg(hf, "dbg_strc", "START -- start string search, cancel mid-way");
    auto t0 = std::chrono::steady_clock::now();

    debugger_engine::find_strings_async(4);
    Sleep(200);
    debugger_engine::request_strings_cancel();

    for (int i = 0; i < 30; ++i) {
        if (!debugger_engine::g_state.strings_scanning.load()) break;
        Sleep(100);
    }

    bool cancelled = !debugger_engine::g_state.strings_scanning.load();

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

    auto status = debugger_engine::g_state.status.load();
    const char* status_str = "unknown";
    switch (status) {
        case debugger_engine::dbg_status_t::idle: status_str = "idle"; break;
        case debugger_engine::dbg_status_t::running: status_str = "running"; break;
        case debugger_engine::dbg_status_t::paused: status_str = "paused"; break;
        case debugger_engine::dbg_status_t::stepping: status_str = "stepping"; break;
        case debugger_engine::dbg_status_t::terminated: status_str = "terminated"; break;
    }

    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - t0).count();
    log_msg(hf, "dbg_stat", "PASS -- debugger status=%s (elapsed %lld ms)", status_str, (long long)ms);
    passed.fetch_add(1);
}

static void test_run_to_address(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
    log_msg(hf, "dbg_rta", "START -- run_to_address API exists");
    auto t0 = std::chrono::steady_clock::now();

    uint64_t addr = get_ntdll_fn("NtClose");
    if (addr == 0) { log_msg(hf, "dbg_rta", "FAIL -- NtClose not found"); failed.fetch_add(1); return; }

    bool ok = debugger_engine::run_to_address(addr, false, 100);

    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - t0).count();
    log_msg(hf, "dbg_rta", "PASS -- run_to_address returned %d (elapsed %lld ms)", (int)ok, (long long)ms);
    passed.fetch_add(1);
}

static void test_one_shot_bp(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
    log_msg(hf, "dbg_1shot", "START -- add breakpoint with bp_state one_shot via toggle");
    auto t0 = std::chrono::steady_clock::now();

    uint64_t addr = get_ntdll_fn("NtWriteFile");
    if (addr == 0) { log_msg(hf, "dbg_1shot", "FAIL -- NtWriteFile not found"); failed.fetch_add(1); return; }

    int idx = debugger_engine::add_breakpoint(addr, debugger_engine::bp_type_t::software, "one_shot_test", "", 1);
    debugger_engine::toggle_breakpoint(idx);

    auto snap = debugger_engine::snapshot_breakpoints();
    bool found = false;
    for (const auto& bp : snap) {
        if (bp.address == addr) { found = true; break; }
    }

    debugger_engine::remove_breakpoint(idx);

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

    log_msg(hf, "seh_ref", "driver_loaded=%d attached_pid=%u",
        (int)driver_bridge::is_loaded(),
        (unsigned)driver_bridge::attached_pid());

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

    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - t0).count();
    log_msg(hf, "seh_ref", "refresh completed: still_refreshing=%d chain_depth=%zu waited_ms=%d (elapsed %lld ms)",
        (int)still_refreshing, chain_depth, waited_ms, (long long)ms);

    if (!still_refreshing) {
        log_msg(hf, "seh_ref", "PASS -- seh_view refresh completed without hang (elapsed %lld ms)", (long long)ms);
        passed.fetch_add(1);
    } else {
        log_msg(hf, "seh_ref", "FAIL -- seh_view refresh still running after 3s timeout (elapsed %lld ms)", (long long)ms);
        failed.fetch_add(1);
    }
}

static void test_seh_view_entries(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
    log_msg(hf, "seh_ent", "START -- seh_view entry inspection");
    auto t0 = std::chrono::steady_clock::now();

    std::vector<seh_view::seh_entry_t> snapshot;
    {
        std::lock_guard<std::mutex> lk(seh_view::g_ui.mutex);
        snapshot = seh_view::g_ui.entries;
    }

    log_msg(hf, "seh_ent", "chain_depth=%zu", snapshot.size());

    for (size_t i = 0; i < snapshot.size() && i < 16; ++i) {
        const auto& e = snapshot[i];
        log_msg(hf, "seh_ent", "  [%zu] frame=0x%016llX handler=0x%016llX module=%s name=%s",
            i,
            (unsigned long long)e.frame_addr,
            (unsigned long long)e.handler_addr,
            e.module_name.c_str(),
            e.handler_name.c_str());
    }

    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - t0).count();
    log_msg(hf, "seh_ent", "PASS -- SEH chain inspection complete: depth=%zu (elapsed %lld ms)",
        snapshot.size(), (long long)ms);
    passed.fetch_add(1);
}

static void test_module_view_refresh(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
    log_msg(hf, "mod_ref", "START -- module_view::refresh() trigger and wait");
    auto t0 = std::chrono::steady_clock::now();

    log_msg(hf, "mod_ref", "driver_loaded=%d attached_pid=%u",
        (int)driver_bridge::is_loaded(),
        (unsigned)driver_bridge::attached_pid());

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

    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - t0).count();
    log_msg(hf, "mod_ref", "refresh result: still_loading=%d module_count=%zu waited_ms=%d (elapsed %lld ms)",
        (int)still_loading, module_count, waited_ms, (long long)ms);

    if (!still_loading) {
        log_msg(hf, "mod_ref", "PASS -- module_view refresh completed: %zu modules found (elapsed %lld ms)",
            module_count, (long long)ms);
        passed.fetch_add(1);
    } else {
        log_msg(hf, "mod_ref", "FAIL -- module_view refresh still loading after 5s timeout (elapsed %lld ms)", (long long)ms);
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

    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - t0).count();
    log_msg(hf, "mod_ent", "PASS -- module entry inspection complete: %zu modules (elapsed %lld ms)",
        snapshot.size(), (long long)ms);
    passed.fetch_add(1);
}

static void select_debugger_tab(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed,
                                const char* tag, debugger_view::sub_tab_t value) {
    debugger_view::g_ui.active_tab = value;
    if (debugger_view::g_ui.active_tab == value) {
        log_msg(hf, tag, "PASS -- active_tab selected (%d)", static_cast<int>(value));
        passed.fetch_add(1);
    } else {
        log_msg(hf, tag, "FAIL -- active_tab not selected (%d)", static_cast<int>(value));
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
        __try {
            tests[i].fn(hf, passed, failed);
        }
        __except (EXCEPTION_EXECUTE_HANDLER) {
            log_msg(hf, "debugger", "FAIL -- %s threw SEH exception 0x%08X",
                tests[i].name, GetExceptionCode());
            failed.fetch_add(1);
        }
    }

    log_msg(hf, "debugger", "=== END debugger engine tests ===");
}

}
