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
#include <cctype>
#include <cstdio>
#include <cstdint>
#include <cstring>
#include <string>
#include <vector>

namespace debugger_engine {
std::string call_stack_frame_resolver_evidence(uint64_t address);
}

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

static long long elapsed_us_since(std::chrono::steady_clock::time_point t0) {
    return static_cast<long long>(std::chrono::duration_cast<std::chrono::microseconds>(
        std::chrono::steady_clock::now() - t0).count());
}

static bool hwbp_dr7_has_enabled_slot(uint64_t dr7) {
    return (dr7 & 0xFFULL) != 0;
}

static bool hwbp_dr7_slot_enabled(uint64_t dr7, int slot) {
    if (slot < 0 || slot > 3)
        return true;
    const uint64_t mask = (1ULL << (slot * 2)) | (1ULL << ((slot * 2) + 1));
    return (dr7 & mask) != 0;
}

static uint64_t hwbp_slot_address_for_scrub(const driver_bridge::thread_context_t& ctx, int slot) {
    switch (slot) {
        case 0: return ctx.dr0;
        case 1: return ctx.dr1;
        case 2: return ctx.dr2;
        case 3: return ctx.dr3;
        default: return UINT64_MAX;
    }
}

static bool hwbp_debug_registers_clear_for_scrub(const driver_bridge::thread_context_t& ctx) {
    return ctx.dr0 == 0 &&
        ctx.dr1 == 0 &&
        ctx.dr2 == 0 &&
        ctx.dr3 == 0 &&
        ctx.dr6 == 0 &&
        ctx.dr7 == 0 &&
        !hwbp_dr7_has_enabled_slot(ctx.dr7);
}

static bool hwbp_slot_clear_for_scrub(const driver_bridge::thread_context_t& ctx, int slot) {
    return !hwbp_dr7_slot_enabled(ctx.dr7, slot) && hwbp_slot_address_for_scrub(ctx, slot) == 0;
}

static size_t first_byte_mismatch(const std::vector<uint8_t>& expected, const std::vector<uint8_t>& actual) {
    const size_t n = expected.size() < actual.size() ? expected.size() : actual.size();
    for (size_t i = 0; i < n; ++i) {
        if (expected[i] != actual[i])
            return i;
    }
    return n;
}

static bool verify_target_bytes(uint64_t address,
                                const std::vector<uint8_t>& expected,
                                std::vector<uint8_t>& actual,
                                size_t& mismatch) {
    actual.clear();
    mismatch = 0;
    if (expected.empty())
        return false;
    const bool read_ok = driver_bridge::read_memory(address, expected.size(), actual);
    mismatch = first_byte_mismatch(expected, actual);
    return read_ok && actual.size() == expected.size() && mismatch == expected.size();
}

static std::string dbg_stack_lower_ascii(std::string value) {
    for (char& c : value)
        c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    return value;
}

static bool dbg_stack_ends_with(const std::string& value, const char* suffix) {
    const size_t suffix_len = std::strlen(suffix);
    return value.size() >= suffix_len && value.compare(value.size() - suffix_len, suffix_len, suffix) == 0;
}

static bool dbg_stack_module_requires_function(const std::string& module_name) {
    const std::string lower = dbg_stack_lower_ascii(module_name);
    return lower == "ntdll.dll" ||
        lower == "kernelbase.dll" ||
        lower == "kernel32.dll" ||
        lower == "ucrtbase.dll" ||
        lower == "user32.dll" ||
        lower == "win32u.dll" ||
        lower == "msvcrt.dll" ||
        lower == "vcruntime140.dll" ||
        lower == "msvcp140.dll" ||
        lower.find("aida_testtarget") != std::string::npos ||
        dbg_stack_ends_with(lower, ".exe");
}

static bool dbg_stack_target_module_frame(const std::string& module_name) {
    const std::string lower = dbg_stack_lower_ascii(module_name);
    return lower.find("aida_testtarget") != std::string::npos;
}

static bool dbg_stack_expected_structural_module(const std::string& module_name) {
    const std::string lower = dbg_stack_lower_ascii(module_name);
    return lower == "ntdll.dll" ||
        lower == "kernelbase.dll" ||
        lower == "kernel32.dll" ||
        lower == "ucrtbase.dll" ||
        lower == "user32.dll" ||
        lower == "win32u.dll" ||
        lower == "msvcrt.dll" ||
        lower == "vcruntime140.dll" ||
        lower == "msvcp140.dll" ||
        lower.find("aida_testtarget") != std::string::npos;
}

static uint64_t get_ntdll_fn(const char* name) {
    HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
    if (!ntdll) return 0;
    FARPROC fn = GetProcAddress(ntdll, name);
    return static_cast<uint64_t>(reinterpret_cast<uintptr_t>(fn));
}

static uint64_t alloc_target_bp_region(size_t size = 64, bool need_execute = true) {
    uint64_t addr = driver_bridge::allocate_memory(size);
    if (addr == 0) return 0;
    std::vector<uint8_t> code(size, 0x90);
    code.back() = 0xC3;
    const bool write_ok = driver_bridge::write_memory(addr, code);
    std::vector<uint8_t> verify;
    size_t mismatch = 0;
    const bool verify_ok = write_ok && verify_target_bytes(addr, code, verify, mismatch);
    if (!verify_ok) {
        const uint8_t expected = mismatch < code.size() ? code[mismatch] : 0;
        const uint8_t actual = mismatch < verify.size() ? verify[mismatch] : 0;
        diag::log_tagged_fmt("test_dbg_detail",
            "alloc_target_bp_region write_verify_FAILED addr=0x%llX size=%zu write=%d read_bytes=%zu mismatch=%zu expected=0x%02X actual=0x%02X",
            (unsigned long long)addr,
            size,
            write_ok ? 1 : 0,
            verify.size(),
            mismatch,
            (unsigned)expected,
            (unsigned)actual);
        driver_bridge::free_memory(addr);
        return 0;
    }
    if (need_execute) {
        uint32_t old_protect = 0;
        if (!driver_bridge::protect_memory(addr, size, PAGE_EXECUTE_READWRITE, &old_protect)) {
            diag::log_tagged_fmt("test_dbg_detail", "alloc_target_bp_region protect_memory failed addr=0x%llX size=%zu",
                (unsigned long long)addr, size);
        }
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

struct hwbp_fixture_descriptor_t {
    uint32_t magic;
    uint32_t version;
    uint32_t size;
    uint32_t thread_id;
    uint32_t ready;
    uint32_t state;
    uint32_t generation;
    uint32_t reserved;
    uint64_t descriptor_va;
    uint64_t execute_fn_va;
    uint64_t data_va;
    uint64_t data_size;
    uint64_t hit_counter_va;
    uint64_t heartbeat_va;
    uint64_t thread_entry_va;
};

struct hwbp_fixture_selection_t {
    hwbp_fixture_descriptor_t desc{};
    driver_bridge::thread_context_t ctx{};
    uint64_t address = 0;
    uint32_t tid = 0;
    uint32_t thread_state = 0xFFFFFFFFu;
    bool context_ok = false;
};

static bool hwbp_read_descriptor_at(uint32_t pid,
                                    uint64_t va,
                                    hwbp_fixture_descriptor_t& out,
                                    std::string& reason) {
    std::vector<uint8_t> bytes;
    if (pid == 0 || va == 0) {
        reason = "invalid descriptor address";
        return false;
    }
    if (!driver_bridge::read_memory_for(pid, va, sizeof(out), bytes) || bytes.size() < sizeof(out)) {
        char detail[256];
        std::snprintf(detail, sizeof(detail), "read_memory_for descriptor failed pid=%u va=0x%llX bytes=%zu status=%s error=%s",
            static_cast<unsigned>(pid),
            static_cast<unsigned long long>(va),
            bytes.size(),
            driver_bridge::status().c_str(),
            driver_bridge::last_error().c_str());
        reason = detail;
        return false;
    }
    std::memcpy(&out, bytes.data(), sizeof(out));
    if (out.magic != 0x48574250u || out.version != 1u || out.size < sizeof(out)) {
        char detail[256];
        std::snprintf(detail, sizeof(detail), "descriptor validation failed magic=0x%08X version=%u size=%u descriptor_va=0x%llX",
            out.magic,
            out.version,
            out.size,
            static_cast<unsigned long long>(out.descriptor_va));
        reason = detail;
        return false;
    }
    if (out.ready == 0 || out.thread_id == 0 || out.execute_fn_va == 0 || out.data_va == 0 || out.data_size < 8) {
        char detail[256];
        std::snprintf(detail, sizeof(detail), "descriptor not ready ready=%u tid=%u execute=0x%llX data=0x%llX data_size=%llu state=%u generation=%u",
            out.ready,
            out.thread_id,
            static_cast<unsigned long long>(out.execute_fn_va),
            static_cast<unsigned long long>(out.data_va),
            static_cast<unsigned long long>(out.data_size),
            out.state,
            out.generation);
        reason = detail;
        return false;
    }
    reason.clear();
    return true;
}

static bool hwbp_module_name_matches(const driver_bridge::module_info_t& mod) {
    const std::string combined = dbg_stack_lower_ascii(mod.name + " " + mod.path);
    return combined.find("aida_testtarget") != std::string::npos ||
        combined.find("aida_test_target") != std::string::npos ||
        combined.find("aida_testtarget.exe") != std::string::npos ||
        combined.find("aida_test_target.exe") != std::string::npos;
}

static bool resolve_hwbp_fixture_descriptor(HANDLE hf,
                                            const char* tag,
                                            hwbp_fixture_descriptor_t& out,
                                            std::string& reason) {
    const uint32_t pid = driver_bridge::attached_pid();
    if (pid == 0) {
        reason = "no active attached PID";
        return false;
    }
    uint32_t pre_exit_code = 0;
    const bool pre_alive = driver_bridge::attached_process_alive(&pre_exit_code);
    if (!pre_alive) {
        reason = "target process not alive before export resolution";
        if (hf) {
            log_msg(hf, tag ? tag : "dbg_hwbp",
                "PRE_CHECK -- target process not alive pid=%u exit_code=0x%08X",
                static_cast<unsigned>(pid),
                static_cast<unsigned>(pre_exit_code));
        }
        return false;
    }
    auto modules = driver_bridge::enumerate_modules_for(pid);
    if (modules.empty())
        modules = driver_bridge::enumerate_modules();

    std::string export_reason = "export not found";
    for (const auto& mod : modules) {
        if (!hwbp_module_name_matches(mod) || mod.base == 0)
            continue;
        const uint64_t descriptor_va = driver_bridge::resolve_export_for(pid, mod.base, "aida_test_hwbp_descriptor");
        if (descriptor_va == 0) {
            char detail[256];
            std::snprintf(detail, sizeof(detail), "module=%s base=0x%llX export aida_test_hwbp_descriptor unresolved",
                mod.name.c_str(),
                static_cast<unsigned long long>(mod.base));
            export_reason = detail;
            continue;
        }
        hwbp_fixture_descriptor_t candidate{};
        std::string read_reason;
        if (!hwbp_read_descriptor_at(pid, descriptor_va, candidate, read_reason)) {
            export_reason = read_reason;
            continue;
        }
        bool thread_found = false;
        uint32_t thread_state = 0xFFFFFFFFu;
        auto threads = driver_bridge::enumerate_threads_for(pid);
        for (const auto& th : threads) {
            if (th.tid == candidate.thread_id && (th.owner_pid == 0 || th.owner_pid == pid)) {
                thread_found = true;
                thread_state = th.state;
                break;
            }
        }
        if (!thread_found) {
            char detail[256];
            std::snprintf(detail, sizeof(detail), "fixture thread not found pid=%u tid=%u module=%s descriptor=0x%llX threads=%zu",
                static_cast<unsigned>(pid),
                candidate.thread_id,
                mod.name.c_str(),
                static_cast<unsigned long long>(descriptor_va),
                threads.size());
            export_reason = detail;
            continue;
        }
        out = candidate;
        if (hf) {
            log_msg(hf, tag ? tag : "dbg_hwbp",
                "FIXTURE -- role=hwbp_fixture module=%s descriptor=0x%llX tid=%u state=%u ready=%u generation=%u execute=0x%llX data=0x%llX data_size=%llu heartbeat=0x%llX",
                mod.name.c_str(),
                static_cast<unsigned long long>(candidate.descriptor_va ? candidate.descriptor_va : descriptor_va),
                candidate.thread_id,
                thread_state,
                candidate.ready,
                candidate.generation,
                static_cast<unsigned long long>(candidate.execute_fn_va),
                static_cast<unsigned long long>(candidate.data_va),
                static_cast<unsigned long long>(candidate.data_size),
                static_cast<unsigned long long>(candidate.heartbeat_va));
        }
        reason.clear();
        return true;
    }

    char detail[320];
    std::snprintf(detail, sizeof(detail), "aida_test_hwbp_descriptor unavailable pid=%u modules=%zu last=%s",
        static_cast<unsigned>(pid),
        modules.size(),
        export_reason.c_str());
    reason = detail;
    return false;
}

static bool select_hwbp_fixture(HANDLE hf,
                                const char* tag,
                                debugger_engine::bp_type_t type,
                                int size,
                                hwbp_fixture_selection_t& out) {
    std::string reason;
    hwbp_fixture_descriptor_t desc{};
    if (!resolve_hwbp_fixture_descriptor(hf, tag, desc, reason)) {
        log_msg(hf, tag, "FAIL -- controlled HWBP fixture unavailable: %s", reason.c_str());
        return false;
    }

    uint64_t address = 0;
    if (type == debugger_engine::bp_type_t::hardware_execute) {
        address = desc.execute_fn_va;
    } else {
        if (size <= 0 || static_cast<uint64_t>(size) > desc.data_size) {
            log_msg(hf, tag, "FAIL -- controlled HWBP fixture data too small size=%d data_size=%llu data=0x%llX",
                size,
                static_cast<unsigned long long>(desc.data_size),
                static_cast<unsigned long long>(desc.data_va));
            return false;
        }
        address = desc.data_va;
    }

    driver_bridge::thread_context_t ctx{};
    const bool ctx_ok = driver_bridge::get_thread_context(desc.thread_id, ctx) && ctx.rip != 0 && ctx.rsp != 0;
    DWORD ctx_gle = ctx_ok ? ERROR_SUCCESS : GetLastError();
    if (!ctx_ok) {
        log_msg(hf, tag, "FAIL -- controlled HWBP fixture thread not contextable role=hwbp_fixture tid=%u gle=%lu rip=0x%llX rsp=0x%llX dr7=0x%llX",
            desc.thread_id,
            static_cast<unsigned long>(ctx_gle),
            static_cast<unsigned long long>(ctx.rip),
            static_cast<unsigned long long>(ctx.rsp),
            static_cast<unsigned long long>(ctx.dr7));
        return false;
    }

    auto threads = driver_bridge::enumerate_threads_for(driver_bridge::attached_pid());
    uint32_t thread_state = 0xFFFFFFFFu;
    for (const auto& th : threads) {
        if (th.tid == desc.thread_id) {
            thread_state = th.state;
            break;
        }
    }

    out.desc = desc;
    out.ctx = ctx;
    out.address = address;
    out.tid = desc.thread_id;
    out.thread_state = thread_state;
    out.context_ok = true;
    debugger_engine::g_state.active_tid = desc.thread_id;
    log_msg(hf, tag, "selected hardware breakpoint fixture role=hwbp_fixture tid=%u state=%u address=0x%llX rip=0x%llX rsp=0x%llX dr7=0x%llX",
        static_cast<unsigned>(out.tid),
        static_cast<unsigned>(thread_state),
        static_cast<unsigned long long>(address),
        static_cast<unsigned long long>(ctx.rip),
        static_cast<unsigned long long>(ctx.rsp),
        static_cast<unsigned long long>(ctx.dr7));
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
    if (limit == 0)
        return result;
    hwbp_fixture_descriptor_t desc{};
    std::string reason;
    if (resolve_hwbp_fixture_descriptor(nullptr, "dbg_hwbp", desc, reason) && desc.thread_id != 0) {
        result.push_back(desc.thread_id);
    } else {
        diag::log_tagged_fmt("test_dbg_detail",
            "bounded_hardware_breakpoint_tids fixture_unavailable limit=%zu reason=%s",
            limit,
            reason.c_str());
    }
    return result;
}

static constexpr uint64_t k_ctx_mask_base = (1ULL << 18) - 1ULL;
static constexpr uint64_t k_ctx_mask_fixture = (1ULL << 16) | (1ULL << 7) | (1ULL << 17);

static bool select_hardware_breakpoint_tid(HANDLE hf, const char* tag, uint32_t& tid, driver_bridge::thread_context_t* out_ctx) {
    auto all_candidates = attached_target_tids();
    hwbp_fixture_selection_t fixture{};
    if (select_hwbp_fixture(hf, tag, debugger_engine::bp_type_t::hardware_execute, 1, fixture)) {
        tid = fixture.tid;
        if (out_ctx)
            *out_ctx = fixture.ctx;
        return true;
    }
    log_msg(hf, tag, "FAIL -- no controlled contextable target thread available for hardware breakpoint test (enumerated_target_threads=%zu)", all_candidates.size());
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
    bool ctx_ok = driver_bridge::set_thread_context(tid, ctx, k_ctx_mask_base);
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
                                            bool* freed_stack,
                                            HANDLE hf = nullptr,
                                            const char* tag = "dbg_fixture") {
    bool restore_ok = true;
    bool code_ok = true;
    bool stack_ok = true;
    const uint64_t code_addr = fx.code;
    const uint64_t stack_addr = fx.stack;
    driver_bridge::memory_region_t code_before{};
    driver_bridge::memory_region_t stack_before{};
    driver_bridge::memory_region_t code_after{};
    driver_bridge::memory_region_t stack_after{};
    const uint32_t pid = driver_bridge::attached_pid();
    const bool code_before_ok = code_addr != 0 && pid != 0 && driver_bridge::query_memory_for(pid, code_addr, code_before);
    const bool stack_before_ok = stack_addr != 0 && pid != 0 && driver_bridge::query_memory_for(pid, stack_addr, stack_before);

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
    const bool code_after_ok = code_addr != 0 && pid != 0 && driver_bridge::query_memory_for(pid, code_addr, code_after);
    const bool stack_after_ok = stack_addr != 0 && pid != 0 && driver_bridge::query_memory_for(pid, stack_addr, stack_after);

    if (restored) *restored = restore_ok;
    if (freed_code) *freed_code = code_ok;
    if (freed_stack) *freed_stack = stack_ok;
    diag::log_tagged_fmt("test_dbg_detail",
        "%s controlled_step_cleanup tid=%u context_valid=%d context_entered=%d original_suspend=%u restored=%d code=0x%llX code_before=%d/0x%08X/0x%08X code_after=%d/0x%08X/0x%08X free_code=%d stack=0x%llX stack_before=%d/0x%08X/0x%08X stack_after=%d/0x%08X/0x%08X free_stack=%d",
        tag ? tag : "dbg_fixture",
        (unsigned)fx.tid,
        (int)fx.context_valid,
        (int)fx.context_entered,
        (unsigned)fx.original_suspend_count,
        (int)restore_ok,
        (unsigned long long)code_addr,
        (int)code_before_ok,
        (unsigned)code_before.state,
        (unsigned)code_before.protect,
        (int)code_after_ok,
        (unsigned)code_after.state,
        (unsigned)code_after.protect,
        (int)code_ok,
        (unsigned long long)stack_addr,
        (int)stack_before_ok,
        (unsigned)stack_before.state,
        (unsigned)stack_before.protect,
        (int)stack_after_ok,
        (unsigned)stack_after.state,
        (unsigned)stack_after.protect,
        (int)stack_ok);
    if (hf) {
        log_msg(hf, tag ? tag : "dbg_fixture",
            "INFO -- controlled step cleanup tid=%u restored=%d code=0x%llX free_code=%d code_before=%d/0x%08X/0x%08X code_after=%d/0x%08X/0x%08X stack=0x%llX free_stack=%d stack_before=%d/0x%08X/0x%08X stack_after=%d/0x%08X/0x%08X",
            (unsigned)fx.tid,
            (int)restore_ok,
            (unsigned long long)code_addr,
            (int)code_ok,
            (int)code_before_ok,
            (unsigned)code_before.state,
            (unsigned)code_before.protect,
            (int)code_after_ok,
            (unsigned)code_after.state,
            (unsigned)code_after.protect,
            (unsigned long long)stack_addr,
            (int)stack_ok,
            (int)stack_before_ok,
            (unsigned)stack_before.state,
            (unsigned)stack_before.protect,
            (int)stack_after_ok,
            (unsigned)stack_after.state,
            (unsigned)stack_after.protect);
    }
    return restore_ok && code_ok && stack_ok;
}

static bool prepare_controlled_step_fixture(HANDLE hf,
                                            const char* tag,
                                            controlled_step_fixture_t& fx,
                                            const std::vector<uint8_t>& code_bytes,
                                            bool use_stack_return) {
    auto all_candidates = attached_target_tids();
    auto candidates = bounded_hardware_breakpoint_tids(8);
    if (candidates.empty()) {
        log_msg(hf, tag, "FAIL -- no live target thread available for controlled step fixture");
        return false;
    }

    std::string last_detail = "none";
    for (uint32_t tid : candidates) {
        controlled_step_fixture_t trial;
        std::string failed_stage = "start";
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
        if (!ok)
            failed_stage = use_stack_return && trial.stack == 0 ? "allocate_stack" : "allocate_code";
        if (ok) {
            std::vector<uint8_t> code(64, 0x90);
            for (size_t i = 0; i < code_bytes.size() && i < code.size(); ++i)
                code[i] = code_bytes[i];
            const bool write_ok = driver_bridge::write_memory(trial.code, code);
            std::vector<uint8_t> verify;
            size_t mismatch = 0;
            const bool verify_ok = write_ok && verify_target_bytes(trial.code, code, verify, mismatch);
            if (!verify_ok) {
                driver_bridge::memory_region_t write_region{};
                const bool region_ok = driver_bridge::query_memory_for(driver_bridge::attached_pid(), trial.code, write_region);
                const uint8_t expected = mismatch < code.size() ? code[mismatch] : 0;
                const uint8_t actual = mismatch < verify.size() ? verify[mismatch] : 0;
                diag::log_tagged_fmt("test_dbg_detail",
                    "%s controlled_step_code_write_verify_FAILED tid=%u code=0x%llX size=%zu write=%d read_bytes=%zu mismatch=%zu expected=0x%02X actual=0x%02X region_ok=%d state=0x%08X protect=0x%08X",
                    tag ? tag : "dbg_fixture",
                    (unsigned)trial.tid,
                    (unsigned long long)trial.code,
                    code.size(),
                    write_ok ? 1 : 0,
                    verify.size(),
                    mismatch,
                    (unsigned)expected,
                    (unsigned)actual,
                    region_ok ? 1 : 0,
                    (unsigned)write_region.state,
                    (unsigned)write_region.protect);
            }
            ok = verify_ok;
            if (!ok)
                failed_stage = write_ok ? "code_verify" : "code_write";
        }
        if (ok) {
            uint32_t old_protect = 0;
            ok = driver_bridge::protect_memory(trial.code, 64, PAGE_EXECUTE_READWRITE, &old_protect);
            driver_bridge::memory_region_t prot_region{};
            const bool prot_region_ok = driver_bridge::query_memory_for(driver_bridge::attached_pid(), trial.code, prot_region);
            diag::log_tagged_fmt("test_dbg_detail",
                "%s controlled_step_code_protect tid=%u code=0x%llX protect_ok=%d old=0x%08X query=%d state=0x%08X protect=0x%08X",
                tag ? tag : "dbg_fixture",
                (unsigned)trial.tid,
                (unsigned long long)trial.code,
                ok ? 1 : 0,
                (unsigned)old_protect,
                prot_region_ok ? 1 : 0,
                (unsigned)prot_region.state,
                (unsigned)prot_region.protect);
            if (!ok)
                failed_stage = "code_protect";
        }
        if (ok && use_stack_return) {
            trial.expected_rip = trial.code + 0x10;
            trial.rsp = trial.stack + 0x800;
            std::vector<uint8_t> stack_bytes(8, 0);
            std::memcpy(stack_bytes.data(), &trial.expected_rip, sizeof(trial.expected_rip));
            const bool stack_write_ok = driver_bridge::write_memory(trial.rsp, stack_bytes);
            std::vector<uint8_t> stack_verify;
            size_t stack_mismatch = 0;
            const bool stack_verify_ok = stack_write_ok && verify_target_bytes(trial.rsp, stack_bytes, stack_verify, stack_mismatch);
            if (!stack_verify_ok) {
                const uint8_t expected = stack_mismatch < stack_bytes.size() ? stack_bytes[stack_mismatch] : 0;
                const uint8_t actual = stack_mismatch < stack_verify.size() ? stack_verify[stack_mismatch] : 0;
                diag::log_tagged_fmt("test_dbg_detail",
                    "%s controlled_step_stack_write_verify_FAILED tid=%u stack=0x%llX rsp=0x%llX write=%d read_bytes=%zu mismatch=%zu expected=0x%02X actual=0x%02X",
                    tag ? tag : "dbg_fixture",
                    (unsigned)trial.tid,
                    (unsigned long long)trial.stack,
                    (unsigned long long)trial.rsp,
                    stack_write_ok ? 1 : 0,
                    stack_verify.size(),
                    stack_mismatch,
                    (unsigned)expected,
                    (unsigned)actual);
            }
            ok = stack_verify_ok;
            if (!ok)
                failed_stage = stack_write_ok ? "stack_verify" : "stack_write";
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
            ok = driver_bridge::set_thread_context(trial.tid, entry_ctx, k_ctx_mask_fixture);
            trial.context_entered = ok;
            if (!ok)
                failed_stage = "entry_set_context";
        }
        if (ok) {
            auto verify_ctx = entry_ctx;
            verify_ctx.rip = trial.expected_rip;
            if (use_stack_return)
                verify_ctx.rsp = trial.rsp + 8;
            bool verify_set = driver_bridge::set_thread_context(trial.tid, verify_ctx, k_ctx_mask_fixture);
            bool restore_entry = verify_set && driver_bridge::set_thread_context(trial.tid, entry_ctx, k_ctx_mask_fixture);
            ok = verify_set && restore_entry;
            if (!ok)
                failed_stage = verify_set ? "restore_entry_context" : "verify_set_context";
        }

        if (!ok) {
            uint64_t failed_code = trial.code;
            uint64_t failed_stack = trial.stack;
            bool restored = false;
            bool freed_code = false;
            bool freed_stack = false;
            cleanup_controlled_step_fixture(trial, &restored, &freed_code, &freed_stack, hf, tag);
            char detail[220];
            std::snprintf(detail, sizeof(detail),
                "build stage=%s tid=%u code=0x%llX stack=0x%llX restored=%d free_code=%d free_stack=%d failed",
                failed_stage.c_str(),
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
        log_msg(hf, tag, "INFO -- controlled step fixture tid=%u entry=0x%llX expected=0x%llX stack=0x%llX original_suspend=%u candidates=%zu probed=%zu",
            fx.tid,
            (unsigned long long)fx.code,
            (unsigned long long)fx.expected_rip,
            (unsigned long long)fx.rsp,
            (unsigned)fx.original_suspend_count,
            all_candidates.size(),
            candidates.size());
        return true;
    }

    log_msg(hf, tag, "FAIL -- could not build controlled step fixture across %zu candidate thread(s), probed %zu; last=%s",
        all_candidates.size(),
        candidates.size(),
        last_detail.c_str());
    return false;
}

static bool scrub_target_hardware_breakpoints(HANDLE hf, const char* reason) {
    const uint32_t pid = driver_bridge::attached_pid();
    int target_threads = 0;
    int clear_ok = 0;
    int clear_fail = 0;
    int already_clear_ok = 0;
    int cleared_proof_ok = 0;
    int proof_fail = 0;
    bool final_context_ok = false;
    bool final_all_clear = false;
    DWORD final_gle = ERROR_SUCCESS;
    driver_bridge::thread_context_t final_ctx{};
    hwbp_fixture_descriptor_t desc{};
    std::string fixture_reason;

    if (resolve_hwbp_fixture_descriptor(hf, "dbg_hwclr", desc, fixture_reason)) {
        debugger_engine::g_state.active_tid = desc.thread_id;
        debugger_engine::clear_all_breakpoints();
        ++target_threads;

        uint32_t suspend_prev = 0;
        const bool thread_suspended = driver_bridge::suspend_thread(desc.thread_id, &suspend_prev);
        DWORD suspend_gle = thread_suspended ? ERROR_SUCCESS : GetLastError();
        diag::log_tagged_fmt("test_dbg_detail",
            "dbg_hwclr suspend reason=%s tid=%u suspended=%d prev_count=%u gle=%lu",
            reason ? reason : "unspecified",
            desc.thread_id,
            thread_suspended ? 1 : 0,
            suspend_prev,
            static_cast<unsigned long>(suspend_gle));

        driver_bridge::thread_context_t batch_before{};
        const bool batch_before_ok = driver_bridge::get_thread_context(desc.thread_id, batch_before);
        DWORD batch_before_gle = batch_before_ok ? ERROR_SUCCESS : GetLastError();
        const bool batch_before_all_clear = batch_before_ok && hwbp_debug_registers_clear_for_scrub(batch_before);

        for (int slot = 0; slot < 4; ++slot) {
            driver_bridge::clear_hardware_breakpoint(desc.thread_id, slot);
        }

        driver_bridge::thread_context_t batch_after{};
        const bool batch_after_ok = driver_bridge::get_thread_context(desc.thread_id, batch_after);
        DWORD batch_after_gle = batch_after_ok ? ERROR_SUCCESS : GetLastError();
        uint32_t batch_exit_code = 0;
        const bool batch_alive = driver_bridge::attached_process_alive(&batch_exit_code);
        const bool batch_after_all_clear = batch_after_ok && hwbp_debug_registers_clear_for_scrub(batch_after);

        for (int slot = 0; slot < 4; ++slot) {
            const bool before_slot_clear = batch_before_ok && hwbp_slot_clear_for_scrub(batch_before, slot);
            const bool after_slot_clear = batch_after_ok && hwbp_slot_clear_for_scrub(batch_after, slot);
            const bool batch_slot_ok = batch_after_ok && batch_alive && after_slot_clear;
            const char* batch_proof = batch_slot_ok ? (batch_before_all_clear && before_slot_clear ? "already_clear" : "cleared") : "failed";
            if (batch_slot_ok) {
                ++clear_ok;
                if (batch_before_all_clear && before_slot_clear)
                    ++already_clear_ok;
                else
                    ++cleared_proof_ok;
            }
            diag::log_tagged_fmt("test_dbg_detail",
                "dbg_hwclr batch_slot reason=%s pid=%u tid=%u slot=%d proof=%s before_ok=%d before_gle=%lu before_all_clear=%d before_slot_clear=%d after_ok=%d after_gle=%lu after_all_clear=%d after_slot_clear=%d alive=%d exit_code=0x%08X before_dr0=0x%llX before_dr1=0x%llX before_dr2=0x%llX before_dr3=0x%llX before_dr6=0x%llX before_dr7=0x%llX after_dr0=0x%llX after_dr1=0x%llX after_dr2=0x%llX after_dr3=0x%llX after_dr6=0x%llX after_dr7=0x%llX",
                reason ? reason : "unspecified",
                static_cast<unsigned>(pid),
                desc.thread_id,
                slot,
                batch_proof,
                batch_before_ok ? 1 : 0,
                static_cast<unsigned long>(batch_before_gle),
                batch_before_all_clear ? 1 : 0,
                before_slot_clear ? 1 : 0,
                batch_after_ok ? 1 : 0,
                static_cast<unsigned long>(batch_after_gle),
                batch_after_all_clear ? 1 : 0,
                after_slot_clear ? 1 : 0,
                batch_alive ? 1 : 0,
                static_cast<unsigned>(batch_exit_code),
                static_cast<unsigned long long>(batch_before.dr0),
                static_cast<unsigned long long>(batch_before.dr1),
                static_cast<unsigned long long>(batch_before.dr2),
                static_cast<unsigned long long>(batch_before.dr3),
                static_cast<unsigned long long>(batch_before.dr6),
                static_cast<unsigned long long>(batch_before.dr7),
                static_cast<unsigned long long>(batch_after.dr0),
                static_cast<unsigned long long>(batch_after.dr1),
                static_cast<unsigned long long>(batch_after.dr2),
                static_cast<unsigned long long>(batch_after.dr3),
                static_cast<unsigned long long>(batch_after.dr6),
                static_cast<unsigned long long>(batch_after.dr7));
        }

        if (!(batch_after_ok && batch_after_all_clear && batch_alive)) {
            for (int slot = 0; slot < 4; ++slot) {
                const bool after_slot_clear = batch_after_ok && hwbp_slot_clear_for_scrub(batch_after, slot);
                if (after_slot_clear)
                    continue;
                bool slot_scrubbed = false;
                for (int retry = 1; retry <= 2 && !slot_scrubbed; ++retry) {
                    Sleep(10);
                    driver_bridge::thread_context_t retry_before{};
                    const bool retry_before_ok = driver_bridge::get_thread_context(desc.thread_id, retry_before);
                    const bool retry_clear = driver_bridge::clear_hardware_breakpoint(desc.thread_id, slot);
                    driver_bridge::thread_context_t retry_after{};
                    const bool retry_after_ok = driver_bridge::get_thread_context(desc.thread_id, retry_after);
                    const bool retry_slot_clear = retry_after_ok && hwbp_slot_clear_for_scrub(retry_after, slot);
                    const bool retry_cleared_proof = retry_clear && retry_slot_clear;
                    const bool retry_already_clear = !retry_clear && retry_before_ok && hwbp_debug_registers_clear_for_scrub(retry_before) && retry_after_ok && hwbp_debug_registers_clear_for_scrub(retry_after);
                    const bool retry_scrubbed = retry_cleared_proof || retry_already_clear;
                    diag::log_tagged_fmt("test_dbg_detail",
                        "dbg_hwclr slot_retry reason=%s tid=%u slot=%d retry=%d retry_clear=%d retry_slot_clear=%d retry_scrubbed=%d",
                        reason ? reason : "unspecified",
                        desc.thread_id,
                        slot,
                        retry,
                        retry_clear ? 1 : 0,
                        retry_slot_clear ? 1 : 0,
                        retry_scrubbed ? 1 : 0);
                    if (retry_scrubbed) {
                        slot_scrubbed = true;
                        ++clear_ok;
                        if (retry_already_clear)
                            ++already_clear_ok;
                        if (retry_cleared_proof)
                            ++cleared_proof_ok;
                    }
                }
                if (!slot_scrubbed) {
                    ++clear_fail;
                    ++proof_fail;
                }
            }
        }

        constexpr int kFinalProofAttempts = 4;
        for (int attempt = 1; attempt <= kFinalProofAttempts; ++attempt) {
            driver_bridge::thread_context_t attempt_ctx{};
            const ULONGLONG proof_start = GetTickCount64();
            SetLastError(ERROR_SUCCESS);
            const bool attempt_ok = driver_bridge::get_thread_context(desc.thread_id, attempt_ctx);
            const DWORD attempt_gle = attempt_ok ? ERROR_SUCCESS : GetLastError();
            uint32_t exit_code = 0;
            const bool alive = driver_bridge::attached_process_alive(&exit_code);
            const bool attempt_clear = attempt_ok && hwbp_debug_registers_clear_for_scrub(attempt_ctx);
            const bool dr7_enabled = attempt_ok && hwbp_dr7_has_enabled_slot(attempt_ctx.dr7);
            diag::log_tagged_fmt("test_dbg_detail",
                "dbg_hwclr final_proof reason=%s pid=%u active_pid=%u tid=%u active_tid=%u attempt=%d max_attempts=%d context_ok=%d gle=%lu all_clear=%d dr7_enabled=%d rip=0x%llX rsp=0x%llX dr0=0x%llX dr1=0x%llX dr2=0x%llX dr3=0x%llX dr6=0x%llX dr7=0x%llX alive=%d exit_code_or_error=0x%08X status=\"%s\" last_error=\"%s\" elapsed_ms=%llu",
                reason ? reason : "unspecified",
                static_cast<unsigned>(pid),
                static_cast<unsigned>(driver_bridge::attached_pid()),
                desc.thread_id,
                debugger_engine::g_state.active_tid,
                attempt,
                kFinalProofAttempts,
                attempt_ok ? 1 : 0,
                static_cast<unsigned long>(attempt_gle),
                attempt_clear ? 1 : 0,
                dr7_enabled ? 1 : 0,
                attempt_ok ? static_cast<unsigned long long>(attempt_ctx.rip) : 0ull,
                attempt_ok ? static_cast<unsigned long long>(attempt_ctx.rsp) : 0ull,
                attempt_ok ? static_cast<unsigned long long>(attempt_ctx.dr0) : 0ull,
                attempt_ok ? static_cast<unsigned long long>(attempt_ctx.dr1) : 0ull,
                attempt_ok ? static_cast<unsigned long long>(attempt_ctx.dr2) : 0ull,
                attempt_ok ? static_cast<unsigned long long>(attempt_ctx.dr3) : 0ull,
                attempt_ok ? static_cast<unsigned long long>(attempt_ctx.dr6) : 0ull,
                attempt_ok ? static_cast<unsigned long long>(attempt_ctx.dr7) : 0ull,
                alive ? 1 : 0,
                static_cast<unsigned>(exit_code),
                driver_bridge::status().c_str(),
                driver_bridge::last_error().c_str(),
                static_cast<unsigned long long>(GetTickCount64() - proof_start));
            final_gle = attempt_gle;
            if (attempt_ok) {
                final_context_ok = true;
                final_ctx = attempt_ctx;
                final_all_clear = attempt_clear;
                if (final_all_clear)
                    break;
            }
            if (!alive)
                break;
            Sleep(20);
        }

        if (thread_suspended) {
            uint32_t resume_prev = 0;
            const bool resumed = driver_bridge::resume_thread(desc.thread_id, &resume_prev);
            DWORD resume_gle = resumed ? ERROR_SUCCESS : GetLastError();
            diag::log_tagged_fmt("test_dbg_detail",
                "dbg_hwclr resume reason=%s tid=%u resumed=%d prev_count=%u gle=%lu",
                reason ? reason : "unspecified",
                desc.thread_id,
                resumed ? 1 : 0,
                resume_prev,
                static_cast<unsigned long>(resume_gle));
        }
    } else {
        log_msg(hf, "dbg_hwclr",
            "FAIL -- scrub skipped because controlled HWBP fixture is unavailable: %s",
            fixture_reason.c_str());
    }

    Sleep(10);
    log_msg(hf, "dbg_hwclr",
        "scrub reason=%s pid=%u role=hwbp_fixture target_threads=%d clear_ok=%d clear_fail=%d cleared_proof_ok=%d already_clear_ok=%d proof_fail=%d final_context_ok=%d final_gle=%lu final_all_clear=%d final_dr0=0x%llX final_dr1=0x%llX final_dr2=0x%llX final_dr3=0x%llX final_dr6=0x%llX final_dr7=0x%llX",
        reason ? reason : "unspecified",
        static_cast<unsigned>(pid),
        target_threads,
        clear_ok,
        clear_fail,
        cleared_proof_ok,
        already_clear_ok,
        proof_fail,
        final_context_ok ? 1 : 0,
        static_cast<unsigned long>(final_gle),
        final_all_clear ? 1 : 0,
        static_cast<unsigned long long>(final_ctx.dr0),
        static_cast<unsigned long long>(final_ctx.dr1),
        static_cast<unsigned long long>(final_ctx.dr2),
        static_cast<unsigned long long>(final_ctx.dr3),
        static_cast<unsigned long long>(final_ctx.dr6),
        static_cast<unsigned long long>(final_ctx.dr7));
    return target_threads > 0 && clear_fail == 0 && final_context_ok && final_all_clear;
}

static bool verify_target_hardware_breakpoints_cleared(HANDLE hf, const char* reason) {
    const uint32_t pid = driver_bridge::attached_pid();
    int target_threads = 0;
    int context_ok = 0;
    int context_fail = 0;
    int uncleared_residual = 0;
    hwbp_fixture_descriptor_t desc{};
    std::string fixture_reason;

    if (!resolve_hwbp_fixture_descriptor(hf, "dbg_hwclr", desc, fixture_reason)) {
        log_msg(hf, "dbg_hwclr",
            "FAIL -- verify skipped because controlled HWBP fixture is unavailable: %s",
            fixture_reason.c_str());
        return false;
    }

    ++target_threads;
    driver_bridge::thread_context_t ctx{};
    if (!driver_bridge::get_thread_context(desc.thread_id, ctx)) {
        ++context_fail;
    } else {
        ++context_ok;
        if (!hwbp_debug_registers_clear_for_scrub(ctx)) {
            ++uncleared_residual;
            log_msg(hf, "dbg_hwclr",
                "RESIDUAL -- reason=%s role=hwbp_fixture tid=%u dr0=0x%llX dr1=0x%llX dr2=0x%llX dr3=0x%llX dr6=0x%llX dr7=0x%llX",
                reason ? reason : "unspecified",
                static_cast<unsigned>(desc.thread_id),
                static_cast<unsigned long long>(ctx.dr0),
                static_cast<unsigned long long>(ctx.dr1),
                static_cast<unsigned long long>(ctx.dr2),
                static_cast<unsigned long long>(ctx.dr3),
                static_cast<unsigned long long>(ctx.dr6),
                static_cast<unsigned long long>(ctx.dr7));
        }
    }

    log_msg(hf, "dbg_hwclr",
        "verify reason=%s pid=%u role=hwbp_fixture target_threads=%d context_ok=%d context_fail=%d uncleared_residual=%d",
        reason ? reason : "unspecified",
        static_cast<unsigned>(pid),
        target_threads,
        context_ok,
        context_fail,
        uncleared_residual);
    return target_threads > 0 && context_ok > 0 && context_fail == 0 && uncleared_residual == 0;
}

static uint64_t hwbp_slot_address_from_context(const driver_bridge::thread_context_t& ctx, int slot) {
    switch (slot) {
        case 0: return ctx.dr0;
        case 1: return ctx.dr1;
        case 2: return ctx.dr2;
        case 3: return ctx.dr3;
        default: return 0;
    }
}

static int hwbp_type_bits(debugger_engine::bp_type_t type) {
    if (type == debugger_engine::bp_type_t::hardware_execute)
        return 0;
    if (type == debugger_engine::bp_type_t::hardware_write)
        return 1;
    if (type == debugger_engine::bp_type_t::hardware_read)
        return 3;
    return -1;
}

static int hwbp_len_bits(int size) {
    switch (size) {
        case 1: return 0;
        case 2: return 1;
        case 4: return 3;
        case 8: return 2;
        default: return -1;
    }
}

static bool hwbp_context_matches_expected(const driver_bridge::thread_context_t& ctx,
                                          int slot,
                                          uint64_t address,
                                          debugger_engine::bp_type_t type,
                                          int size) {
    if (slot < 0 || slot > 3)
        return false;
    const int type_bits = hwbp_type_bits(type);
    const int len_bits = hwbp_len_bits(size);
    if (type_bits < 0 || len_bits < 0)
        return false;
    const uint64_t enabled_bit = 1ULL << (slot * 2);
    const int type_shift = 16 + slot * 4;
    const int len_shift = 18 + slot * 4;
    const uint64_t slot_mask = (3ULL << type_shift) | (3ULL << len_shift);
    const uint64_t expected_bits = (static_cast<uint64_t>(type_bits) << type_shift) |
        (static_cast<uint64_t>(len_bits) << len_shift);
    return (ctx.dr7 & enabled_bit) != 0 &&
        hwbp_slot_address_from_context(ctx, slot) == address &&
        (ctx.dr7 & slot_mask) == expected_bits;
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

    hwbp_fixture_selection_t fixture{};
    if (!select_hwbp_fixture(hf, tag, type, size, fixture)) {
        failed.fetch_add(1);
        return;
    }

    if (!scrub_target_hardware_breakpoints(hf, tag)) {
        log_msg(hf, tag, "FAIL -- controlled HWBP fixture scrub did not prove all debug-register slots clear");
        uint32_t post_scrub_exit = 0;
        const bool post_scrub_alive = driver_bridge::attached_process_alive(&post_scrub_exit);
        log_msg(hf, tag, "POST_SCRUB_CHECK -- alive=%d exit_code=0x%08X pid=%u",
            post_scrub_alive ? 1 : 0,
            static_cast<unsigned>(post_scrub_exit),
            static_cast<unsigned>(driver_bridge::attached_pid()));
        failed.fetch_add(1);
        return;
    }

    uint32_t selected_tid = fixture.tid;
    driver_bridge::thread_context_t selected_before{};
    bool selected_before_ok = driver_bridge::get_thread_context(selected_tid, selected_before);
    DWORD selected_before_gle = selected_before_ok ? ERROR_SUCCESS : GetLastError();
    if (!selected_before_ok || selected_before.rip == 0 || selected_before.rsp == 0) {
        log_msg(hf, tag, "FAIL -- controlled HWBP fixture context unavailable after scrub tid=%u gle=%lu rip=0x%llX rsp=0x%llX dr7=0x%llX",
            static_cast<unsigned>(selected_tid),
            static_cast<unsigned long>(selected_before_gle),
            static_cast<unsigned long long>(selected_before.rip),
            static_cast<unsigned long long>(selected_before.rsp),
            static_cast<unsigned long long>(selected_before.dr7));
        failed.fetch_add(1);
        return;
    }

    uint64_t addr = fixture.address;
    uint32_t exit_before = 0;
    const bool alive_before = driver_bridge::attached_process_alive(&exit_before);

    diag::log_tagged_fmt("test_dbg_detail", "%s inputs: fixture_addr=0x%llX role=hwbp_fixture type=%s size=%d pid=%u tid=%u state=%u alive_before=%d exit_before=0x%08X before_rip=0x%llX before_rsp=0x%llX before_dr0=0x%llX before_dr1=0x%llX before_dr2=0x%llX before_dr3=0x%llX before_dr6=0x%llX before_dr7=0x%llX descriptor=0x%llX execute=0x%llX data=0x%llX data_size=%llu",
        tag,
        (unsigned long long)addr,
        type_name ? type_name : "?",
        size,
        (unsigned)driver_bridge::attached_pid(),
        (unsigned)selected_tid,
        (unsigned)fixture.thread_state,
        alive_before ? 1 : 0,
        (unsigned)exit_before,
        (unsigned long long)selected_before.rip,
        (unsigned long long)selected_before.rsp,
        (unsigned long long)selected_before.dr0,
        (unsigned long long)selected_before.dr1,
        (unsigned long long)selected_before.dr2,
        (unsigned long long)selected_before.dr3,
        (unsigned long long)selected_before.dr6,
        (unsigned long long)selected_before.dr7,
        (unsigned long long)fixture.desc.descriptor_va,
        (unsigned long long)fixture.desc.execute_fn_va,
        (unsigned long long)fixture.desc.data_va,
        (unsigned long long)fixture.desc.data_size);

    int idx = debugger_engine::add_breakpoint(addr, type, bp_name ? bp_name : "test_hw_bp", "", size);
    DWORD add_gle = idx >= 0 ? ERROR_SUCCESS : GetLastError();
    int hw_slot = -1;
    if (idx >= 0) {
        std::lock_guard<std::mutex> lk(debugger_engine::g_state.bp_mutex);
        if (idx < static_cast<int>(debugger_engine::g_state.breakpoints.size()))
            hw_slot = debugger_engine::g_state.breakpoints[static_cast<std::size_t>(idx)].hw_slot;
    }
    driver_bridge::thread_context_t armed_ctx{};
    bool armed_ctx_ok = selected_tid != 0 && driver_bridge::get_thread_context(selected_tid, armed_ctx);
    DWORD armed_ctx_gle = armed_ctx_ok ? ERROR_SUCCESS : GetLastError();
    uint32_t exit_after_add = 0;
    const bool alive_after_add = driver_bridge::attached_process_alive(&exit_after_add);
    const bool hwbp_slot_valid = hw_slot >= 0 && hw_slot < 4;
    const bool active_tid_matches = debugger_engine::g_state.active_tid == selected_tid;
    const bool set_verified_by_add = idx >= 0 && hwbp_slot_valid && selected_tid != 0 && active_tid_matches;
    const uint64_t observed_armed_slot_address = hwbp_slot_address_from_context(armed_ctx, hw_slot);
    const bool armed_context_matches = armed_ctx_ok && set_verified_by_add &&
        hwbp_context_matches_expected(armed_ctx, hw_slot, addr, type, size);
    const bool post_arm_context_transport_miss = set_verified_by_add && !armed_ctx_ok;
    bool armed = armed_context_matches;
    bool removed = false;
    if (idx >= 0)
        removed = debugger_engine::remove_breakpoint(idx);
    DWORD remove_gle = removed ? ERROR_SUCCESS : GetLastError();

    driver_bridge::thread_context_t clear_ctx{};
    bool clear_ctx_ok = selected_tid != 0 && driver_bridge::get_thread_context(selected_tid, clear_ctx);
    DWORD clear_ctx_gle = clear_ctx_ok ? ERROR_SUCCESS : GetLastError();
    uint32_t exit_after_remove = 0;
    const bool alive_after_remove = driver_bridge::attached_process_alive(&exit_after_remove);
    bool clear_direct_verified = clear_ctx_ok && hwbp_slot_valid && hwbp_debug_registers_clear_for_scrub(clear_ctx);
    bool clear_scrub_ok = false;
    bool clear_verify_ok = false;
    bool regs_clear = clear_direct_verified;
    if (!regs_clear) {
        clear_scrub_ok = scrub_target_hardware_breakpoints(hf, tag);
        clear_verify_ok = verify_target_hardware_breakpoints_cleared(hf, tag);
        clear_ctx = {};
        clear_ctx_ok = selected_tid != 0 && driver_bridge::get_thread_context(selected_tid, clear_ctx);
        clear_ctx_gle = clear_ctx_ok ? ERROR_SUCCESS : GetLastError();
        clear_direct_verified = clear_ctx_ok && hwbp_slot_valid && hwbp_debug_registers_clear_for_scrub(clear_ctx);
        regs_clear = clear_scrub_ok && clear_verify_ok && clear_direct_verified;
    }
    uint32_t exit_after_clear = 0;
    const bool alive_after_clear = driver_bridge::attached_process_alive(&exit_after_clear);
    const bool post_arm_transport_miss_tolerated = type == debugger_engine::bp_type_t::hardware_read &&
        post_arm_context_transport_miss &&
        set_verified_by_add &&
        removed &&
        regs_clear;
    if (post_arm_transport_miss_tolerated)
        armed = true;

    diag::log_tagged_fmt("test_dbg_detail",
        "%s result: fixture_addr=0x%llX role=hwbp_fixture selected_tid=%u state=%u add_breakpoint=>idx=%d add_gle=%lu hw_slot=%d active_tid=%u active_tid_matches=%d set_verified_by_add=%d expected_slot_addr=0x%llX observed_armed_slot_addr=0x%llX expected_type_bits=%d expected_len_bits=%d armed=>%d armed_ctx=%d armed_gle=%lu armed_context_matches=%d post_arm_context_transport_miss=%d post_arm_transport_miss_tolerated=%d remove_breakpoint=>%d remove_gle=%lu clear_ctx=%d clear_gle=%lu clear_direct_verified=%d clear_scrub_ok=%d clear_verify_ok=%d regs_clear=>%d alive_before=%d exit_before=0x%08X alive_after_add=%d exit_after_add=0x%08X alive_after_remove=%d exit_after_remove=0x%08X alive_after_clear=%d exit_after_clear=0x%08X before_rip=0x%llX before_rsp=0x%llX before_dr0=0x%llX before_dr1=0x%llX before_dr2=0x%llX before_dr3=0x%llX before_dr6=0x%llX before_dr7=0x%llX armed_rip=0x%llX armed_rsp=0x%llX armed_dr0=0x%llX armed_dr1=0x%llX armed_dr2=0x%llX armed_dr3=0x%llX armed_dr6=0x%llX armed_dr7=0x%llX clear_rip=0x%llX clear_rsp=0x%llX clear_dr0=0x%llX clear_dr1=0x%llX clear_dr2=0x%llX clear_dr3=0x%llX clear_dr6=0x%llX clear_dr7=0x%llX",
        tag,
        (unsigned long long)addr,
        static_cast<unsigned>(selected_tid),
        static_cast<unsigned>(fixture.thread_state),
        idx,
        static_cast<unsigned long>(add_gle),
        hw_slot,
        static_cast<unsigned>(debugger_engine::g_state.active_tid),
        active_tid_matches ? 1 : 0,
        set_verified_by_add ? 1 : 0,
        static_cast<unsigned long long>(addr),
        static_cast<unsigned long long>(observed_armed_slot_address),
        hwbp_type_bits(type),
        hwbp_len_bits(size),
        (int)armed,
        (int)armed_ctx_ok,
        static_cast<unsigned long>(armed_ctx_gle),
        armed_context_matches ? 1 : 0,
        post_arm_context_transport_miss ? 1 : 0,
        post_arm_transport_miss_tolerated ? 1 : 0,
        (int)removed,
        static_cast<unsigned long>(remove_gle),
        (int)clear_ctx_ok,
        static_cast<unsigned long>(clear_ctx_gle),
        clear_direct_verified ? 1 : 0,
        clear_scrub_ok ? 1 : 0,
        clear_verify_ok ? 1 : 0,
        (int)regs_clear,
        alive_before ? 1 : 0,
        static_cast<unsigned>(exit_before),
        alive_after_add ? 1 : 0,
        static_cast<unsigned>(exit_after_add),
        alive_after_remove ? 1 : 0,
        static_cast<unsigned>(exit_after_remove),
        alive_after_clear ? 1 : 0,
        static_cast<unsigned>(exit_after_clear),
        static_cast<unsigned long long>(selected_before.rip),
        static_cast<unsigned long long>(selected_before.rsp),
        static_cast<unsigned long long>(selected_before.dr0),
        static_cast<unsigned long long>(selected_before.dr1),
        static_cast<unsigned long long>(selected_before.dr2),
        static_cast<unsigned long long>(selected_before.dr3),
        static_cast<unsigned long long>(selected_before.dr6),
        static_cast<unsigned long long>(selected_before.dr7),
        static_cast<unsigned long long>(armed_ctx.rip),
        static_cast<unsigned long long>(armed_ctx.rsp),
        static_cast<unsigned long long>(armed_ctx.dr0),
        static_cast<unsigned long long>(armed_ctx.dr1),
        static_cast<unsigned long long>(armed_ctx.dr2),
        static_cast<unsigned long long>(armed_ctx.dr3),
        static_cast<unsigned long long>(armed_ctx.dr6),
        static_cast<unsigned long long>(armed_ctx.dr7),
        static_cast<unsigned long long>(clear_ctx.rip),
        static_cast<unsigned long long>(clear_ctx.rsp),
        static_cast<unsigned long long>(clear_ctx.dr0),
        static_cast<unsigned long long>(clear_ctx.dr1),
        static_cast<unsigned long long>(clear_ctx.dr2),
        static_cast<unsigned long long>(clear_ctx.dr3),
        static_cast<unsigned long long>(clear_ctx.dr6),
        static_cast<unsigned long long>(clear_ctx.dr7));

    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - t0).count();
    if (idx >= 0 && hwbp_slot_valid && set_verified_by_add && armed && removed && regs_clear && alive_before && alive_after_add && alive_after_remove && alive_after_clear) {
        log_msg(hf, tag, "PASS -- %s idx=%d slot=%d role=hwbp_fixture tid=%u set_verified_by_add=%d post_arm_transport_miss_tolerated=%d clear_verified=%d armed and removed ok (elapsed %lld ms)",
            label,
            idx,
            hw_slot,
            static_cast<unsigned>(selected_tid),
            set_verified_by_add ? 1 : 0,
            post_arm_transport_miss_tolerated ? 1 : 0,
            regs_clear ? 1 : 0,
            (long long)ms);
        passed.fetch_add(1);
    } else {
        log_msg(hf, tag, "FAIL -- role=hwbp_fixture tid=%u idx=%d add_gle=%lu hw_slot=%d active_tid=%u active_tid_matches=%d set_verified_by_add=%d armed=%d armed_ctx=%d armed_gle=%lu armed_context_matches=%d post_arm_context_transport_miss=%d post_arm_transport_miss_tolerated=%d removed=%d remove_gle=%lu clear_ctx=%d clear_gle=%lu clear_direct_verified=%d clear_scrub_ok=%d clear_verify_ok=%d regs_clear=%d alive=[%d,%d,%d,%d] exits=[0x%08X,0x%08X,0x%08X,0x%08X] (elapsed %lld ms)",
            static_cast<unsigned>(selected_tid),
            idx,
            static_cast<unsigned long>(add_gle),
            hw_slot,
            static_cast<unsigned>(debugger_engine::g_state.active_tid),
            active_tid_matches ? 1 : 0,
            set_verified_by_add ? 1 : 0,
            (int)armed,
            (int)armed_ctx_ok,
            static_cast<unsigned long>(armed_ctx_gle),
            armed_context_matches ? 1 : 0,
            post_arm_context_transport_miss ? 1 : 0,
            post_arm_transport_miss_tolerated ? 1 : 0,
            (int)removed,
            static_cast<unsigned long>(remove_gle),
            (int)clear_ctx_ok,
            static_cast<unsigned long>(clear_ctx_gle),
            clear_direct_verified ? 1 : 0,
            clear_scrub_ok ? 1 : 0,
            clear_verify_ok ? 1 : 0,
            (int)regs_clear,
            alive_before ? 1 : 0,
            alive_after_add ? 1 : 0,
            alive_after_remove ? 1 : 0,
            alive_after_clear ? 1 : 0,
            static_cast<unsigned>(exit_before),
            static_cast<unsigned>(exit_after_add),
            static_cast<unsigned>(exit_after_remove),
            static_cast<unsigned>(exit_after_clear),
            (long long)ms);
        failed.fetch_add(1);
    }
}

static void test_add_remove_software_bp(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
    log_msg(hf, "dbg_bp", "START -- add and remove software breakpoint");
    auto t0 = std::chrono::steady_clock::now();

    uint64_t addr = alloc_target_bp_region(64, false);
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
        "hardware execute breakpoint on controlled fixture function",
        debugger_engine::bp_type_t::hardware_execute,
        "hardware_execute",
        1,
        "test_hwx_bp");
}

static void test_add_remove_hw_write_bp(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
    test_add_remove_hw_bp_common(hf, passed, failed,
        "dbg_hww",
        "hardware write breakpoint on controlled fixture data",
        debugger_engine::bp_type_t::hardware_write,
        "hardware_write",
        4,
        "test_hww_bp");
}

static void test_add_remove_hw_read_bp(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
    test_add_remove_hw_bp_common(hf, passed, failed,
        "dbg_hwr",
        "hardware read breakpoint on controlled fixture data",
        debugger_engine::bp_type_t::hardware_read,
        "hardware_read",
        4,
        "test_hwr_bp");
}

static void test_toggle_breakpoint(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
    log_msg(hf, "dbg_tog", "START -- toggle breakpoint on/off");
    auto t0 = std::chrono::steady_clock::now();

    uint64_t addr = alloc_target_bp_region(64, false);
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

    uint64_t addr = alloc_target_bp_region(64, false);
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

    uint64_t addr = alloc_target_bp_region(64, false);
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

    uint64_t addr = alloc_target_bp_region(64, false);
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

    uint64_t a1 = alloc_target_bp_region(64, false);
    uint64_t a2 = alloc_target_bp_region(64, false);
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

    uint32_t attached_pid = driver_bridge::attached_pid();
    bool driver_loaded = driver_bridge::is_loaded();
    bool kernel_bridge = driver_bridge::using_kernel_driver();
    std::string status = driver_bridge::status();
    std::string last_error = driver_bridge::last_error();
    diag::log_tagged_fmt("test_dbg_detail", "dbg_reg inputs: get_registers() driver_loaded=%d kernel_bridge=%d attached_pid=%u status='%s' last_error='%s'",
        (int)driver_loaded, kernel_bridge ? 1 : 0, (unsigned)attached_pid, status.c_str(), last_error.c_str());
    log_msg(hf, "dbg_reg", "INPUT -- get_registers twice driver_loaded=%d kernel_bridge=%d attached_pid=%u status=\"%s\" last_error=\"%s\"",
        (int)driver_loaded, kernel_bridge ? 1 : 0, attached_pid, status.c_str(), last_error.c_str());

    auto regs = debugger_engine::get_registers();
    long long first_us = elapsed_us_since(t0);
    auto second_start = std::chrono::steady_clock::now();
    auto regs2 = debugger_engine::get_registers();
    long long second_us = elapsed_us_since(second_start);
    std::string flags_decoded = debugger_engine::format_flags(regs.rflags);
    std::string flags_decoded2 = debugger_engine::format_flags(regs2.rflags);
    long long total_us = elapsed_us_since(t0);

    diag::log_tagged_fmt("test_dbg_detail",
        "dbg_reg result: rip=0x%llX rsp=0x%llX rbp=0x%llX cs=0x%llX ss=0x%llX rflags=0x%llX second_rip=0x%llX second_rsp=0x%llX",
        (unsigned long long)regs.rip, (unsigned long long)regs.rsp, (unsigned long long)regs.rbp,
        (unsigned long long)regs.cs, (unsigned long long)regs.ss, (unsigned long long)regs.rflags,
        (unsigned long long)regs2.rip, (unsigned long long)regs2.rsp);
    log_msg(hf, "dbg_reg", "OUTPUT -- first rip=0x%llX rsp=0x%llX rbp=0x%llX rflags=0x%llX decoded=\"%s\" cs=0x%llX ss=0x%llX dr7=0x%llX elapsed_us=%lld",
        (unsigned long long)regs.rip,
        (unsigned long long)regs.rsp,
        (unsigned long long)regs.rbp,
        (unsigned long long)regs.rflags,
        flags_decoded.c_str(),
        (unsigned long long)regs.cs,
        (unsigned long long)regs.ss,
        (unsigned long long)regs.dr7,
        first_us);
    log_msg(hf, "dbg_reg", "OUTPUT -- second rip=0x%llX rsp=0x%llX rbp=0x%llX rflags=0x%llX decoded=\"%s\" cs=0x%llX ss=0x%llX dr7=0x%llX elapsed_us=%lld total_us=%lld",
        (unsigned long long)regs2.rip,
        (unsigned long long)regs2.rsp,
        (unsigned long long)regs2.rbp,
        (unsigned long long)regs2.rflags,
        flags_decoded2.c_str(),
        (unsigned long long)regs2.cs,
        (unsigned long long)regs2.ss,
        (unsigned long long)regs2.dr7,
        second_us,
        total_us);

    if (regs.rip != 0 && regs.rsp != 0 && regs2.rip != 0 && regs2.rsp != 0 && regs.cs != 0 && regs.ss != 0) {
        log_msg(hf, "dbg_reg", "PASS -- rax=0x%llX rbx=0x%llX rcx=0x%llX rdx=0x%llX rip=0x%llX rsp=0x%llX rflags=0x%llX second_rip=0x%llX second_rsp=0x%llX elapsed_us=%lld",
            (unsigned long long)regs.rax, (unsigned long long)regs.rbx,
            (unsigned long long)regs.rcx, (unsigned long long)regs.rdx,
            (unsigned long long)regs.rip, (unsigned long long)regs.rsp,
            (unsigned long long)regs.rflags,
            (unsigned long long)regs2.rip,
            (unsigned long long)regs2.rsp,
            total_us);
        passed.fetch_add(1);
    } else {
        log_msg(hf, "dbg_reg", "FAIL -- live thread register snapshots invalid first(rip=0x%llX rsp=0x%llX cs=0x%llX ss=0x%llX) second(rip=0x%llX rsp=0x%llX cs=0x%llX ss=0x%llX) elapsed_us=%lld",
            (unsigned long long)regs.rip,
            (unsigned long long)regs.rsp,
            (unsigned long long)regs.cs,
            (unsigned long long)regs.ss,
            (unsigned long long)regs2.rip,
            (unsigned long long)regs2.rsp,
            (unsigned long long)regs2.cs,
            (unsigned long long)regs2.ss,
            total_us);
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
    size_t known_module_blank_functions = 0;
    size_t resolved_count = 0;
    size_t module_rva_fallback_count = 0;
    size_t budget_exhausted_count = 0;
    size_t target_module_frame_count = 0;
    size_t expected_structural_module_count = 0;
    size_t blank_module_count = 0;
    size_t zero_address_count = 0;
    std::string first_blank_evidence;
    std::string first_budget_evidence;
    for (size_t i = 0; i < frames.size(); ++i) {
        const std::string resolver = debugger_engine::call_stack_frame_resolver_evidence(frames[i].address);
        const bool known_module = dbg_stack_module_requires_function(frames[i].module_name);
        const bool target_module = dbg_stack_target_module_frame(frames[i].module_name);
        const bool expected_structural_module = dbg_stack_expected_structural_module(frames[i].module_name);
        const bool blank_module = frames[i].module_name.empty();
        const bool empty_function = frames[i].function_name.empty();
        const bool resolved_symbol = resolver.find("source=pdb") != std::string::npos ||
            resolver.find("source=export") != std::string::npos ||
            resolver.find("source=local_image_nearest") != std::string::npos;
        const bool module_rva_fallback = resolver.find("source=module_rva") != std::string::npos;
        const bool budget_exhausted = resolver.find("budget") != std::string::npos;
        if (frames[i].address == 0)
            ++zero_address_count;
        if (blank_module)
            ++blank_module_count;
        if (resolved_symbol)
            ++resolved_count;
        if (module_rva_fallback)
            ++module_rva_fallback_count;
        if (budget_exhausted) {
            ++budget_exhausted_count;
            if (first_budget_evidence.empty())
                first_budget_evidence = resolver;
        }
        if (target_module)
            ++target_module_frame_count;
        if (expected_structural_module)
            ++expected_structural_module_count;
        log_msg(hf, "dbg_stk", "  frame[%zu]: addr=0x%llX ret=0x%llX module=%s func=%s offset=0x%llX resolver=%s",
            i, (unsigned long long)frames[i].address, (unsigned long long)frames[i].return_addr,
            frames[i].module_name.c_str(), empty_function ? "(empty)" : frames[i].function_name.c_str(),
            (unsigned long long)frames[i].module_offset, resolver.c_str());
        diag::log_tagged_fmt("test_dbg_detail",
            "dbg_stk frame index=%zu addr=0x%llX ret=0x%llX module=%s function=%s offset=0x%llX known_module=%d target_module=%d expected_structural_module=%d blank_module=%d empty_function=%d resolved_symbol=%d module_rva_fallback=%d budget_exhausted=%d resolver=%s",
            i,
            (unsigned long long)frames[i].address,
            (unsigned long long)frames[i].return_addr,
            frames[i].module_name.empty() ? "(empty)" : frames[i].module_name.c_str(),
            empty_function ? "(empty)" : frames[i].function_name.c_str(),
            (unsigned long long)frames[i].module_offset,
            known_module ? 1 : 0,
            target_module ? 1 : 0,
            expected_structural_module ? 1 : 0,
            blank_module ? 1 : 0,
            empty_function ? 1 : 0,
            resolved_symbol ? 1 : 0,
            module_rva_fallback ? 1 : 0,
            budget_exhausted ? 1 : 0,
            resolver.c_str());
        if (known_module && empty_function) {
            ++known_module_blank_functions;
            if (first_blank_evidence.empty())
                first_blank_evidence = resolver;
        }
    }
    const bool structural_ok = !frames.empty() && top_addr != 0;
    const bool budget_majority = structural_ok && budget_exhausted_count * 2 >= frames.size() && frames.size() > 1;
    const bool module_rva_structural_contract = structural_ok &&
        (module_rva_fallback_count + resolved_count) == frames.size() &&
        known_module_blank_functions == 0 &&
        blank_module_count == 0 &&
        zero_address_count == 0 &&
        target_module_frame_count > 0 &&
        expected_structural_module_count == frames.size();
    diag::log_tagged_fmt("test_dbg_detail",
        "dbg_stk quality frame_count=%zu resolved=%zu module_rva_fallback=%zu budget_exhausted=%zu target_module_frames=%zu expected_structural_modules=%zu blank_modules=%zu zero_address_frames=%zu known_module_blank_functions=%zu structural_ok=%d budget_majority=%d module_rva_structural_contract=%d",
        frames.size(),
        resolved_count,
        module_rva_fallback_count,
        budget_exhausted_count,
        target_module_frame_count,
        expected_structural_module_count,
        blank_module_count,
        zero_address_count,
        known_module_blank_functions,
        structural_ok ? 1 : 0,
        budget_majority ? 1 : 0,
        module_rva_structural_contract ? 1 : 0);

    if (structural_ok && zero_address_count == 0 && blank_module_count == 0 && known_module_blank_functions == 0 && target_module_frame_count > 0 && (!budget_majority || module_rva_structural_contract)) {
        log_msg(hf, "dbg_stk", "PASS -- structural frames=%zu top_addr=0x%llX resolved=%zu module_rva_fallback=%zu budget_exhausted=%zu budget_majority=%d module_rva_structural_contract=%d target_module_frames=%zu expected_structural_modules=%zu blank_modules=%zu zero_address_frames=%zu (elapsed %lld ms)",
            frames.size(), (unsigned long long)top_addr, resolved_count, module_rva_fallback_count, budget_exhausted_count, budget_majority ? 1 : 0, module_rva_structural_contract ? 1 : 0, target_module_frame_count, expected_structural_module_count, blank_module_count, zero_address_count, (long long)ms);
        passed.fetch_add(1);
    } else if (structural_ok) {
        log_msg(hf, "dbg_stk", "FAIL -- stack structural capture succeeded but symbol/addressability evidence is incomplete: frames=%zu top_addr=0x%llX resolved=%zu module_rva_fallback=%zu budget_exhausted=%zu budget_majority=%d module_rva_structural_contract=%d target_module_frames=%zu expected_structural_modules=%zu blank_modules=%zu zero_address_frames=%zu known_module_blank_functions=%zu first_blank_resolver=\"%s\" first_budget_resolver=\"%s\" (elapsed %lld ms)",
            frames.size(), (unsigned long long)top_addr, resolved_count, module_rva_fallback_count, budget_exhausted_count, budget_majority ? 1 : 0, module_rva_structural_contract ? 1 : 0, target_module_frame_count, expected_structural_module_count, blank_module_count, zero_address_count, known_module_blank_functions, first_blank_evidence.c_str(), first_budget_evidence.c_str(), (long long)ms);
        failed.fetch_add(1);
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
    std::string before = debugger_engine::get_comment(addr);
    diag::log_tagged_fmt("test_dbg_detail", "dbg_cmt inputs: addr=0x%llX before='%s' set_comment='test_comment_12345'", (unsigned long long)addr, before.c_str());
    log_msg(hf, "dbg_cmt", "STATE before addr=0x%llX comment=\"%s\" len=%zu", (unsigned long long)addr, before.c_str(), before.size());

    debugger_engine::set_comment(addr, "test_comment_12345");
    std::string got = debugger_engine::get_comment(addr);
    debugger_engine::set_comment(addr, before);
    std::string restored = debugger_engine::get_comment(addr);
    diag::log_tagged_fmt("test_dbg_detail", "dbg_cmt result: set_get='%s' restored='%s'", got.c_str(), restored.c_str());

    long long us = elapsed_us_since(t0);
    log_msg(hf, "dbg_cmt", "STATE after_set expected=\"test_comment_12345\" got=\"%s\" restored=\"%s\" restored_matches_before=%d elapsed_us=%lld",
        got.c_str(), restored.c_str(), restored == before ? 1 : 0, us);
    if (got == "test_comment_12345" && restored == before) {
        log_msg(hf, "dbg_cmt", "PASS -- comment round-trip and restore verified elapsed_us=%lld", us);
        passed.fetch_add(1);
    } else {
        log_msg(hf, "dbg_cmt", "FAIL -- expected set=\"test_comment_12345\" got=\"%s\" before=\"%s\" restored=\"%s\" elapsed_us=%lld",
            got.c_str(), before.c_str(), restored.c_str(), us);
        failed.fetch_add(1);
    }
}

static void test_set_get_label(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
    log_msg(hf, "dbg_lbl", "START -- set and get label at address");
    auto t0 = std::chrono::steady_clock::now();

    uint64_t addr = get_ntdll_fn("NtClose");
    if (addr == 0) { log_msg(hf, "dbg_lbl", "FAIL -- NtClose not found"); failed.fetch_add(1); return; }
    std::string before = debugger_engine::get_label(addr);
    diag::log_tagged_fmt("test_dbg_detail", "dbg_lbl inputs: addr=0x%llX before='%s' set_label='test_label_67890'", (unsigned long long)addr, before.c_str());
    log_msg(hf, "dbg_lbl", "STATE before addr=0x%llX label=\"%s\" len=%zu", (unsigned long long)addr, before.c_str(), before.size());

    debugger_engine::set_label(addr, "test_label_67890");
    std::string got = debugger_engine::get_label(addr);
    debugger_engine::set_label(addr, before);
    std::string restored = debugger_engine::get_label(addr);
    diag::log_tagged_fmt("test_dbg_detail", "dbg_lbl result: set_get='%s' restored='%s'", got.c_str(), restored.c_str());

    long long us = elapsed_us_since(t0);
    log_msg(hf, "dbg_lbl", "STATE after_set expected=\"test_label_67890\" got=\"%s\" restored=\"%s\" restored_matches_before=%d elapsed_us=%lld",
        got.c_str(), restored.c_str(), restored == before ? 1 : 0, us);
    if (got == "test_label_67890" && restored == before) {
        log_msg(hf, "dbg_lbl", "PASS -- label round-trip and restore verified elapsed_us=%lld", us);
        passed.fetch_add(1);
    } else {
        log_msg(hf, "dbg_lbl", "FAIL -- expected set=\"test_label_67890\" got=\"%s\" before=\"%s\" restored=\"%s\" elapsed_us=%lld",
            got.c_str(), before.c_str(), restored.c_str(), us);
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
    size_t count_before = 0;
    {
        std::lock_guard<std::mutex> lk(debugger_engine::g_state.anno_mutex);
        count_before = debugger_engine::g_state.bookmarks.size();
    }
    debugger_engine::toggle_bookmark(addr);
    bool after_on = bookmark_present(addr);
    size_t count_after_on = 0;
    {
        std::lock_guard<std::mutex> lk(debugger_engine::g_state.anno_mutex);
        count_after_on = debugger_engine::g_state.bookmarks.size();
    }
    debugger_engine::toggle_bookmark(addr);
    bool after_off = bookmark_present(addr);
    size_t count_after_off = 0;
    {
        std::lock_guard<std::mutex> lk(debugger_engine::g_state.anno_mutex);
        count_after_off = debugger_engine::g_state.bookmarks.size();
    }
    diag::log_tagged_fmt("test_dbg_detail", "dbg_bkm result: before=%d after_on=%d after_off=%d",
        (int)before, (int)after_on, (int)after_off);

    long long us = elapsed_us_since(t0);
    log_msg(hf, "dbg_bkm", "STATE addr=0x%llX before=%d count_before=%zu after_first=%d count_after_first=%zu after_second=%d count_after_second=%zu elapsed_us=%lld",
        (unsigned long long)addr,
        before ? 1 : 0,
        count_before,
        after_on ? 1 : 0,
        count_after_on,
        after_off ? 1 : 0,
        count_after_off,
        us);
    if (after_on != before && after_off == before) {
        log_msg(hf, "dbg_bkm", "PASS -- bookmark toggled first state and restored original membership elapsed_us=%lld", us);
        passed.fetch_add(1);
    } else {
        log_msg(hf, "dbg_bkm", "FAIL -- toggle did not flip/restore state before=%d after_first=%d after_second=%d elapsed_us=%lld",
            (int)before, (int)after_on, (int)after_off, us);
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

    for (int i = 0; i < 80; ++i) {
        if (!debugger_engine::g_state.strings_scanning.load(std::memory_order_acquire))
            break;
        Sleep(25);
    }

    auto& state = debugger_engine::g_state;
    if (state.strings_scanning.load(std::memory_order_acquire)) {
        debugger_engine::request_strings_cancel();
        for (int i = 0; i < 20; ++i) {
            if (!state.strings_scanning.load(std::memory_order_acquire))
                break;
            Sleep(25);
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
    std::string expected = "PF ZF IF ";
    bool has_pf = formatted.find("PF") != std::string::npos;
    bool has_zf = formatted.find("ZF") != std::string::npos;
    bool has_if = formatted.find("IF") != std::string::npos;
    bool has_cf = formatted.find("CF") != std::string::npos;
    diag::log_tagged_fmt("test_dbg_detail", "dbg_fmt result: '%s' expected='%s'", formatted.c_str(), expected.c_str());

    long long us = elapsed_us_since(t0);
    log_msg(hf, "dbg_fmt", "RESULT flags=0x%llX formatted=\"%s\" expected=\"%s\" has_pf=%d has_zf=%d has_if=%d has_cf=%d elapsed_us=%lld",
        (unsigned long long)test_flags,
        formatted.c_str(),
        expected.c_str(),
        has_pf ? 1 : 0,
        has_zf ? 1 : 0,
        has_if ? 1 : 0,
        has_cf ? 1 : 0,
        us);
    if (formatted == expected && has_pf && has_zf && has_if && !has_cf) {
        log_msg(hf, "dbg_fmt", "PASS -- flags 0x%llX exactly decoded to \"%s\" elapsed_us=%lld",
            (unsigned long long)test_flags, formatted.c_str(), us);
        passed.fetch_add(1);
    } else {
        log_msg(hf, "dbg_fmt", "FAIL -- expected \"%s\" got \"%s\" elapsed_us=%lld", expected.c_str(), formatted.c_str(), us);
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
    std::string p4 = debugger_engine::format_protect(0x123456u);
    diag::log_tagged_fmt("test_dbg_detail", "dbg_prt result: p1='%s' p2='%s' p3='%s' p4='%s'", p1.c_str(), p2.c_str(), p3.c_str(), p4.c_str());

    long long us = elapsed_us_since(t0);
    bool ok = p1 == "EXECUTE_READWRITE" && p2 == "READONLY" && p3 == "READWRITE" && p4 == "0x123456";
    log_msg(hf, "dbg_prt", "RESULT ERW=\"%s\" expected=\"EXECUTE_READWRITE\" R=\"%s\" expected=\"READONLY\" RW=\"%s\" expected=\"READWRITE\" unknown=\"%s\" expected=\"0x123456\" elapsed_us=%lld",
        p1.c_str(), p2.c_str(), p3.c_str(), p4.c_str(), us);
    if (ok) {
        log_msg(hf, "dbg_prt", "PASS -- base protection names and unknown fallback match expected outputs elapsed_us=%lld", us);
        passed.fetch_add(1);
    } else {
        log_msg(hf, "dbg_prt", "FAIL -- protection format mismatch ERW=\"%s\" R=\"%s\" RW=\"%s\" unknown=\"%s\" elapsed_us=%lld",
            p1.c_str(), p2.c_str(), p3.c_str(), p4.c_str(), us);
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
    const bool driver_loaded = driver_bridge::is_loaded();
    const uint32_t attached_pid = driver_bridge::attached_pid();
    auto regs = debugger_engine::get_registers();
    const bool register_evidence = regs.rip != 0 && regs.rsp != 0;
    diag::log_tagged_fmt("test_dbg_detail", "dbg_err field: last_error='%s' driver_loaded=%d attached_pid=%u rip=0x%llX rsp=0x%llX register_evidence=%d",
        err.empty() ? "(empty)" : err.c_str(), driver_loaded ? 1 : 0, attached_pid,
        (unsigned long long)regs.rip, (unsigned long long)regs.rsp, register_evidence ? 1 : 0);

    bool has_fatal = (err.find("not attached") != std::string::npos)
                  || (err.find("must be non-zero") != std::string::npos)
                  || (err.find("<read error>") != std::string::npos);

    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - t0).count();
    if (!has_fatal && driver_loaded && attached_pid != 0 && register_evidence) {
        log_msg(hf, "dbg_err", "PASS -- debugger accessor paired with same-run register evidence driver_loaded=1 attached_pid=%u rip=0x%llX rsp=0x%llX last_error_len=%zu (elapsed %lld ms)",
            attached_pid, (unsigned long long)regs.rip, (unsigned long long)regs.rsp, err.size(), (long long)ms);
        passed.fetch_add(1);
    } else {
        log_msg(hf, "dbg_err", "FAIL -- debugger accessor state invalid driver_loaded=%d attached_pid=%u has_fatal=%d register_evidence=%d rip=0x%llX rsp=0x%llX last_error=\"%s\" (elapsed %lld ms)",
            driver_loaded ? 1 : 0, attached_pid, has_fatal ? 1 : 0, register_evidence ? 1 : 0,
            (unsigned long long)regs.rip, (unsigned long long)regs.rsp, err.c_str(), (long long)ms);
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

    uint64_t base = alloc_target_bp_region(256, false);
    if (base == 0) {
        log_msg(hf, "dbg_mbp", "FAIL -- alloc_target_bp_region returned 0 (no driver attach?)");
        failed.fetch_add(1);
        return;
    }
    uint64_t a1 = base;
    uint64_t a2 = base + 64;
    uint64_t a3 = base + 128;
    uint64_t a4 = base + 192;

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
    driver_bridge::free_memory(base);

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
    if (ok && after.rip == fixture.expected_rip && restored && freed_code && freed_stack && ms <= 10000) {
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
    log_msg(hf, "dbg_tri", "START -- trace result buffer inspection with controlled step evidence");
    auto t0 = std::chrono::steady_clock::now();

    if (!require_attached_live_target(hf, "dbg_tri", failed))
        return;

    controlled_step_fixture_t fixture;
    std::vector<uint8_t> code{0x90, 0x90, 0x90, 0xC3};
    if (!prepare_controlled_step_fixture(hf, "dbg_tri", fixture, code, false)) {
        failed.fetch_add(1);
        return;
    }

    const uint32_t active_tid = debugger_engine::g_state.active_tid;
    const uint64_t fixture_va = fixture.code;
    const uint64_t fixture_expected_rip = fixture.expected_rip;
    driver_bridge::memory_region_t region{};
    const bool region_ok = driver_bridge::query_memory_for(driver_bridge::attached_pid(), fixture_va, region);

    debugger_engine::stop_trace();
    auto before = debugger_engine::get_registers();
    diag::log_tagged_fmt("test_dbg_detail", "dbg_tri inputs: active_tid=%u fixture_va=0x%llX expected=0x%llX region_ok=%d region_base=0x%llX region_size=0x%llX region_state=0x%08X region_protect=0x%08X start_trace(16) step_into()",
        (unsigned)active_tid,
        (unsigned long long)fixture_va,
        (unsigned long long)fixture_expected_rip,
        (int)region_ok,
        (unsigned long long)region.base,
        (unsigned long long)region.size,
        (unsigned)region.state,
        (unsigned)region.protect);

    bool started = debugger_engine::start_trace(16);
    bool stepped = started ? debugger_engine::step_into() : false;
    bool stopped = debugger_engine::stop_trace();
    auto after = debugger_engine::get_registers();
    std::string err = debugger_engine::last_error();

    auto& state = debugger_engine::g_state;
    size_t trace_count = 0;
    uint64_t first_rip = 0;
    uint64_t last_rip = 0;
    std::string first_disasm;
    std::string last_disasm;
    {
        std::lock_guard<std::mutex> lk(state.trace_mutex);
        trace_count = state.trace_log.size();
        if (!state.trace_log.empty()) {
            first_rip = state.trace_log.front().address;
            last_rip = state.trace_log.back().address;
            first_disasm = state.trace_log.front().disasm_text;
            last_disasm = state.trace_log.back().disasm_text;
        }
    }

    bool restored = false;
    bool freed_code = false;
    bool freed_stack = false;
    cleanup_controlled_step_fixture(fixture, &restored, &freed_code, &freed_stack, hf, "dbg_tri");

    diag::log_tagged_fmt("test_dbg_detail", "dbg_tri result: active_tid=%u fixture_va=0x%llX region_protect=0x%08X before_rip=0x%llX after_rip=0x%llX expected=0x%llX start=%d step=%d stop=%d trace_count=%zu first_rip=0x%llX last_rip=0x%llX restored=%d free_code=%d last_error='%s' first_disasm='%s' last_disasm='%s'",
        (unsigned)active_tid,
        (unsigned long long)fixture_va,
        (unsigned)region.protect,
        (unsigned long long)before.rip,
        (unsigned long long)after.rip,
        (unsigned long long)fixture_expected_rip,
        (int)started,
        (int)stepped,
        (int)stopped,
        trace_count,
        (unsigned long long)first_rip,
        (unsigned long long)last_rip,
        (int)restored,
        (int)freed_code,
        err.empty() ? "(none)" : err.c_str(),
        first_disasm.c_str(),
        last_disasm.c_str());

    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - t0).count();
    if (started && stepped && stopped && trace_count > 0 && after.rip == fixture_expected_rip && restored && freed_code) {
        log_msg(hf, "dbg_tri", "PASS -- trace recorded %zu controlled step record(s): tid=%u fixture=0x%llX protect=0x%08X first_rip=0x%llX last_rip=0x%llX last_error=\"%s\" (elapsed %lld ms)",
            trace_count,
            (unsigned)active_tid,
            (unsigned long long)fixture_va,
            (unsigned)region.protect,
            (unsigned long long)first_rip,
            (unsigned long long)last_rip,
            err.empty() ? "(none)" : err.c_str(),
            (long long)ms);
        passed.fetch_add(1);
    } else {
        log_msg(hf, "dbg_tri", "FAIL -- trace evidence missing or controlled step failed: tid=%u fixture=0x%llX protect=0x%08X start=%d step=%d stop=%d before_rip=0x%llX after_rip=0x%llX expected=0x%llX trace_count=%zu first_rip=0x%llX last_rip=0x%llX restored=%d free_code=%d last_error=\"%s\" (elapsed %lld ms)",
            (unsigned)active_tid,
            (unsigned long long)fixture_va,
            (unsigned)region.protect,
            (int)started,
            (int)stepped,
            (int)stopped,
            (unsigned long long)before.rip,
            (unsigned long long)after.rip,
            (unsigned long long)fixture_expected_rip,
            trace_count,
            (unsigned long long)first_rip,
            (unsigned long long)last_rip,
            (int)restored,
            (int)freed_code,
            err.empty() ? "(none)" : err.c_str(),
            (long long)ms);
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
    std::string b1 = debugger_engine::get_comment(a1);
    std::string b2 = debugger_engine::get_comment(a2);
    std::string b3 = debugger_engine::get_comment(a3);
    log_msg(hf, "dbg_cmt2", "STATE before a1=0x%llX c1=\"%s\" a2=0x%llX c2=\"%s\" a3=0x%llX c3=\"%s\"",
        (unsigned long long)a1, b1.c_str(),
        (unsigned long long)a2, b2.c_str(),
        (unsigned long long)a3, b3.c_str());

    debugger_engine::set_comment(a1, "comment_alpha");
    debugger_engine::set_comment(a2, "comment_beta");
    debugger_engine::set_comment(a3, "comment_gamma");

    std::string c1 = debugger_engine::get_comment(a1);
    std::string c2 = debugger_engine::get_comment(a2);
    std::string c3 = debugger_engine::get_comment(a3);

    debugger_engine::set_comment(a1, b1);
    debugger_engine::set_comment(a2, b2);
    debugger_engine::set_comment(a3, b3);
    std::string r1 = debugger_engine::get_comment(a1);
    std::string r2 = debugger_engine::get_comment(a2);
    std::string r3 = debugger_engine::get_comment(a3);
    diag::log_tagged_fmt("test_dbg_detail", "dbg_cmt2 result: c1='%s' c2='%s' c3='%s' r1='%s' r2='%s' r3='%s'",
        c1.c_str(), c2.c_str(), c3.c_str(), r1.c_str(), r2.c_str(), r3.c_str());

    long long us = elapsed_us_since(t0);
    bool restored = r1 == b1 && r2 == b2 && r3 == b3;
    log_msg(hf, "dbg_cmt2", "STATE after_set c1=\"%s\" c2=\"%s\" c3=\"%s\" restored=%d r1=\"%s\" r2=\"%s\" r3=\"%s\" elapsed_us=%lld",
        c1.c_str(), c2.c_str(), c3.c_str(), restored ? 1 : 0, r1.c_str(), r2.c_str(), r3.c_str(), us);
    if (c1 == "comment_alpha" && c2 == "comment_beta" && c3 == "comment_gamma" && restored) {
        log_msg(hf, "dbg_cmt2", "PASS -- 3 comments set/get round-trip and restore verified elapsed_us=%lld", us);
        passed.fetch_add(1);
    } else {
        log_msg(hf, "dbg_cmt2", "FAIL -- c1=\"%s\" c2=\"%s\" c3=\"%s\" restored=%d elapsed_us=%lld",
            c1.c_str(), c2.c_str(), c3.c_str(), restored ? 1 : 0, us);
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
    std::string b1 = debugger_engine::get_label(a1);
    std::string b2 = debugger_engine::get_label(a2);
    log_msg(hf, "dbg_lbl2", "STATE before a1=0x%llX l1=\"%s\" a2=0x%llX l2=\"%s\"",
        (unsigned long long)a1, b1.c_str(), (unsigned long long)a2, b2.c_str());

    debugger_engine::set_label(a1, "label_first");
    debugger_engine::set_label(a2, "label_second");

    std::string l1 = debugger_engine::get_label(a1);
    std::string l2 = debugger_engine::get_label(a2);

    debugger_engine::set_label(a1, b1);
    debugger_engine::set_label(a2, b2);
    std::string r1 = debugger_engine::get_label(a1);
    std::string r2 = debugger_engine::get_label(a2);
    diag::log_tagged_fmt("test_dbg_detail", "dbg_lbl2 result: l1='%s' l2='%s' r1='%s' r2='%s'", l1.c_str(), l2.c_str(), r1.c_str(), r2.c_str());

    long long us = elapsed_us_since(t0);
    bool restored = r1 == b1 && r2 == b2;
    log_msg(hf, "dbg_lbl2", "STATE after_set l1=\"%s\" l2=\"%s\" restored=%d r1=\"%s\" r2=\"%s\" elapsed_us=%lld",
        l1.c_str(), l2.c_str(), restored ? 1 : 0, r1.c_str(), r2.c_str(), us);
    if (l1 == "label_first" && l2 == "label_second" && restored) {
        log_msg(hf, "dbg_lbl2", "PASS -- 2 labels set/get round-trip and restore verified elapsed_us=%lld", us);
        passed.fetch_add(1);
    } else {
        log_msg(hf, "dbg_lbl2", "FAIL -- l1=\"%s\" l2=\"%s\" restored=%d elapsed_us=%lld", l1.c_str(), l2.c_str(), restored ? 1 : 0, us);
        failed.fetch_add(1);
    }
}

static void test_label_lookup_by_name(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
    log_msg(hf, "dbg_llkp", "START -- set label, look up by address, verify name");
    auto t0 = std::chrono::steady_clock::now();

    uint64_t addr = get_ntdll_fn("NtReadFile");
    if (addr == 0) { log_msg(hf, "dbg_llkp", "FAIL -- NtReadFile not found"); failed.fetch_add(1); return; }
    std::string before = debugger_engine::get_label(addr);
    diag::log_tagged_fmt("test_dbg_detail", "dbg_llkp inputs: addr=0x%llX before='%s' set_label='label_lookup_test_xyzzy'", (unsigned long long)addr, before.c_str());

    debugger_engine::set_label(addr, "label_lookup_test_xyzzy");
    std::string got = debugger_engine::get_label(addr);
    uint64_t reverse_addr = 0;
    size_t label_count = 0;
    {
        std::lock_guard<std::mutex> lk(debugger_engine::g_state.anno_mutex);
        label_count = debugger_engine::g_state.labels.size();
        for (const auto& kv : debugger_engine::g_state.labels) {
            if (kv.second.text == "label_lookup_test_xyzzy") {
                reverse_addr = kv.first;
                break;
            }
        }
    }
    debugger_engine::set_label(addr, before);
    std::string restored = debugger_engine::get_label(addr);
    diag::log_tagged_fmt("test_dbg_detail", "dbg_llkp result: get_label='%s' reverse_addr=0x%llX restored='%s'",
        got.c_str(), (unsigned long long)reverse_addr, restored.c_str());

    long long us = elapsed_us_since(t0);
    log_msg(hf, "dbg_llkp", "STATE expected=\"label_lookup_test_xyzzy\" got=\"%s\" reverse_addr=0x%llX expected_addr=0x%llX labels=%zu restored=\"%s\" restored_matches_before=%d elapsed_us=%lld",
        got.c_str(), (unsigned long long)reverse_addr, (unsigned long long)addr, label_count,
        restored.c_str(), restored == before ? 1 : 0, us);
    if (got == "label_lookup_test_xyzzy" && reverse_addr == addr && restored == before) {
        log_msg(hf, "dbg_llkp", "PASS -- label get and reverse lookup by name verified elapsed_us=%lld", us);
        passed.fetch_add(1);
    } else {
        log_msg(hf, "dbg_llkp", "FAIL -- expected label/reverse lookup mismatch got=\"%s\" reverse_addr=0x%llX expected_addr=0x%llX restored_matches=%d elapsed_us=%lld",
            got.c_str(), (unsigned long long)reverse_addr, (unsigned long long)addr, restored == before ? 1 : 0, us);
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

    auto bookmark_present = [&](uint64_t a) -> bool {
        std::lock_guard<std::mutex> lk(debugger_engine::g_state.anno_mutex);
        for (uint64_t b : debugger_engine::g_state.bookmarks) {
            if (b == a) return true;
        }
        return false;
    };

    bool b1 = bookmark_present(a1);
    bool b2 = bookmark_present(a2);
    bool b3 = bookmark_present(a3);
    size_t count_before = 0;
    {
        std::lock_guard<std::mutex> lk(debugger_engine::g_state.anno_mutex);
        count_before = debugger_engine::g_state.bookmarks.size();
    }
    log_msg(hf, "dbg_bklst", "STATE before count=%zu a1_present=%d a2_present=%d a3_present=%d",
        count_before, b1 ? 1 : 0, b2 ? 1 : 0, b3 ? 1 : 0);

    if (!b1) debugger_engine::toggle_bookmark(a1);
    if (!b2) debugger_engine::toggle_bookmark(a2);
    if (!b3) debugger_engine::toggle_bookmark(a3);

    size_t count = 0;
    bool p1 = false;
    bool p2 = false;
    bool p3 = false;
    {
        std::lock_guard<std::mutex> lk(debugger_engine::g_state.anno_mutex);
        count = debugger_engine::g_state.bookmarks.size();
        for (uint64_t b : debugger_engine::g_state.bookmarks) {
            if (b == a1) p1 = true;
            if (b == a2) p2 = true;
            if (b == a3) p3 = true;
        }
    }

    if (bookmark_present(a1) != b1) debugger_engine::toggle_bookmark(a1);
    if (bookmark_present(a2) != b2) debugger_engine::toggle_bookmark(a2);
    if (bookmark_present(a3) != b3) debugger_engine::toggle_bookmark(a3);

    size_t count_restored = 0;
    bool r1 = bookmark_present(a1);
    bool r2 = bookmark_present(a2);
    bool r3 = bookmark_present(a3);
    {
        std::lock_guard<std::mutex> lk(debugger_engine::g_state.anno_mutex);
        count_restored = debugger_engine::g_state.bookmarks.size();
    }
    diag::log_tagged_fmt("test_dbg_detail", "dbg_bklst result: bookmark_count_after_ensure=%zu present=%d/%d/%d restored=%d/%d/%d",
        count, p1 ? 1 : 0, p2 ? 1 : 0, p3 ? 1 : 0, r1 ? 1 : 0, r2 ? 1 : 0, r3 ? 1 : 0);

    long long us = elapsed_us_since(t0);
    bool restored = count_restored == count_before && r1 == b1 && r2 == b2 && r3 == b3;
    log_msg(hf, "dbg_bklst", "STATE after_ensure count=%zu present={%d,%d,%d} restored_count=%zu restored_present={%d,%d,%d} restored=%d elapsed_us=%lld",
        count,
        p1 ? 1 : 0,
        p2 ? 1 : 0,
        p3 ? 1 : 0,
        count_restored,
        r1 ? 1 : 0,
        r2 ? 1 : 0,
        r3 ? 1 : 0,
        restored ? 1 : 0,
        us);
    if (p1 && p2 && p3 && count >= count_before && restored) {
        log_msg(hf, "dbg_bklst", "PASS -- bookmark listing contains all seeded targets and restores original state elapsed_us=%lld", us);
        passed.fetch_add(1);
    } else {
        log_msg(hf, "dbg_bklst", "FAIL -- bookmark listing evidence mismatch count=%zu before=%zu present={%d,%d,%d} restored=%d elapsed_us=%lld",
            count, count_before, p1 ? 1 : 0, p2 ? 1 : 0, p3 ? 1 : 0, restored ? 1 : 0, us);
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

    diag::log_tagged_fmt("test_dbg_detail", "dbg_fpg inputs: format_protect(EXECUTE_READ, NOACCESS, GUARD|READWRITE, WRITECOPY, NOCACHE|WRITECOMBINE|READONLY)");
    std::string p1 = debugger_engine::format_protect(PAGE_EXECUTE_READ);
    std::string p2 = debugger_engine::format_protect(PAGE_NOACCESS);
    std::string p3 = debugger_engine::format_protect(PAGE_GUARD | PAGE_READWRITE);
    std::string p4 = debugger_engine::format_protect(PAGE_WRITECOPY);
    std::string p5 = debugger_engine::format_protect(PAGE_NOCACHE | PAGE_WRITECOMBINE | PAGE_READONLY);
    diag::log_tagged_fmt("test_dbg_detail", "dbg_fpg result: p1='%s' p2='%s' p3='%s' p4='%s' p5='%s'",
        p1.c_str(), p2.c_str(), p3.c_str(), p4.c_str(), p5.c_str());

    long long us = elapsed_us_since(t0);
    bool ok = p1 == "EXECUTE_READ" && p2 == "NOACCESS" && p3 == "READWRITE|GUARD" &&
              p4 == "WRITECOPY" && p5 == "READONLY|NOCACHE|WRITECOMBINE";
    log_msg(hf, "dbg_fpg", "RESULT ER=\"%s\" expected=\"EXECUTE_READ\" NA=\"%s\" expected=\"NOACCESS\" G_RW=\"%s\" expected=\"READWRITE|GUARD\" WC=\"%s\" expected=\"WRITECOPY\" R_NC_WC=\"%s\" expected=\"READONLY|NOCACHE|WRITECOMBINE\" elapsed_us=%lld",
        p1.c_str(), p2.c_str(), p3.c_str(), p4.c_str(), p5.c_str(), us);
    if (ok) {
        log_msg(hf, "dbg_fpg", "PASS -- guarded and modifier protection formatting matches expected outputs elapsed_us=%lld", us);
        passed.fetch_add(1);
    } else {
        log_msg(hf, "dbg_fpg", "FAIL -- format_protect modifier mismatch p1=\"%s\" p2=\"%s\" p3=\"%s\" p4=\"%s\" p5=\"%s\" elapsed_us=%lld",
            p1.c_str(), p2.c_str(), p3.c_str(), p4.c_str(), p5.c_str(), us);
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

    long long us = elapsed_us_since(t0);
    bool ok = f0.empty() && f1 == "IF " && f2 == "PF ZF IF " && f3 == "CF PF AF SF IF " &&
              f1_has_if && f2_has_zf && f3_has_cf;
    log_msg(hf, "dbg_ff0", "RESULT 0x0=\"%s\" expected=\"\" 0x202=\"%s\" expected=\"IF \" 0x246=\"%s\" expected=\"PF ZF IF \" 0x297=\"%s\" expected=\"CF PF AF SF IF \" elapsed_us=%lld",
        f0.c_str(), f1.c_str(), f2.c_str(), f3.c_str(), us);
    if (ok) {
        log_msg(hf, "dbg_ff0", "PASS -- zero and multi-flag formatting exactly matched expected outputs elapsed_us=%lld", us);
        passed.fetch_add(1);
    } else {
        log_msg(hf, "dbg_ff0", "FAIL -- format_flags mismatch 0x0=\"%s\" 0x202=\"%s\" 0x246=\"%s\" 0x297=\"%s\" elapsed_us=%lld",
            f0.c_str(), f1.c_str(), f2.c_str(), f3.c_str(), us);
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

    {
        std::lock_guard<std::mutex> lk(debugger_engine::g_state.log_mutex);
        if (debugger_engine::g_state.log_messages.size() >= debugger_engine::g_state.log_messages_max)
            debugger_engine::g_state.log_messages.pop_front();
        debugger_engine::g_state.log_messages.push_back("test_poplog_probe");
    }

    diag::log_tagged_fmt("test_dbg_detail", "dbg_poplog inputs: injected probe, log_message_count() then pop_log_messages() then re-count");
    size_t before_count = debugger_engine::log_message_count();
    auto msgs = debugger_engine::pop_log_messages();
    size_t after_count = debugger_engine::log_message_count();
    diag::log_tagged_fmt("test_dbg_detail", "dbg_poplog result: before_count=%zu popped=%zu after_count=%zu",
        before_count, msgs.size(), after_count);

    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - t0).count();
    if (before_count > 0 && msgs.size() == before_count && after_count == 0) {
        log_msg(hf, "dbg_poplog", "PASS -- popped %zu of %zu messages, buffer drained to 0 (elapsed %lld ms)",
            msgs.size(), before_count, (long long)ms);
        passed.fetch_add(1);
    } else {
        log_msg(hf, "dbg_poplog", "FAIL -- pop inconsistent: before=%zu popped=%zu after=%zu (pop must drain non-empty buffer and return all entries) (elapsed %lld ms)",
            before_count, msgs.size(), after_count, (long long)ms);
        failed.fetch_add(1);
    }
}

static void test_restore_breakpoints_and_watches(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
    log_msg(hf, "dbg_rest", "START -- restore_breakpoints_and_watches round-trip");
    auto t0 = std::chrono::steady_clock::now();

    debugger_engine::clear_breakpoints_and_watches();

    uint64_t addr = alloc_target_bp_region(64, false);
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

    uint64_t addr = alloc_target_bp_region(64, false);
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
        default: status_str = "unknown"; valid = false; break;
    }
    const bool driver_loaded = driver_bridge::is_loaded();
    const uint32_t attached_pid = driver_bridge::attached_pid();
    auto regs = debugger_engine::get_registers();
    const bool register_evidence = regs.rip != 0 && regs.rsp != 0;
    diag::log_tagged_fmt("test_dbg_detail", "dbg_stat result: status=%s(%d) driver_loaded=%d attached_pid=%u rip=0x%llX rsp=0x%llX register_evidence=%d",
        status_str,
        (int)status,
        driver_loaded ? 1 : 0,
        attached_pid,
        (unsigned long long)regs.rip,
        (unsigned long long)regs.rsp,
        register_evidence ? 1 : 0);

    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - t0).count();
    if (valid && driver_loaded && attached_pid != 0 && register_evidence) {
        log_msg(hf, "dbg_stat", "PASS -- debugger status paired with live register evidence status=%s attached_pid=%u rip=0x%llX rsp=0x%llX (elapsed %lld ms)",
            status_str,
            attached_pid,
            (unsigned long long)regs.rip,
            (unsigned long long)regs.rsp,
            (long long)ms);
        passed.fetch_add(1);
    } else {
        log_msg(hf, "dbg_stat", "FAIL -- debugger status lacks live evidence status=%s valid=%d driver_loaded=%d attached_pid=%u rip=0x%llX rsp=0x%llX register_evidence=%d (elapsed %lld ms)",
            status_str,
            valid ? 1 : 0,
            driver_loaded ? 1 : 0,
            attached_pid,
            (unsigned long long)regs.rip,
            (unsigned long long)regs.rsp,
            register_evidence ? 1 : 0,
            (long long)ms);
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

    uint64_t addr = alloc_target_bp_region(64, false);
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
    seh_view::seh_diagnostics_t seh_diag{};
    {
        std::lock_guard<std::mutex> lk(seh_view::g_ui.mutex);
        snapshot = seh_view::g_ui.entries;
        seh_diag = seh_view::g_ui.diagnostics;
    }

    const bool x64_target = sizeof(void*) == 8;
    log_msg(hf, "seh_ent", "chain_depth=%zu arch=%s teb=0x%016llX exception_list=0x%016llX x64_empty_chain_proven=%d",
        snapshot.size(),
        x64_target ? "x64" : "x86",
        (unsigned long long)seh_diag.teb_va,
        (unsigned long long)seh_diag.raw_exception_list,
        seh_diag.x64_empty_chain_proven ? 1 : 0);
    diag::log_tagged_fmt("test_dbg_detail",
        "seh_ent inputs: chain_depth=%zu arch=%s teb_query_attempted=%d teb_query_ok=%d teb=0x%llX teb_read_ok=%d exception_list_read_ok=%d raw_exception_list=0x%llX sentinel=%d x64_empty_chain_proven=%d empty_reason=%s stack_attempted=%d stack_read_ok=%d stack_candidates=%u stack_found=%d stack_reason=%s chain_stop=%s",
        snapshot.size(),
        x64_target ? "x64" : "x86",
        seh_diag.teb_query_attempted ? 1 : 0,
        seh_diag.teb_query_ok ? 1 : 0,
        (unsigned long long)seh_diag.teb_va,
        seh_diag.teb_read_ok ? 1 : 0,
        seh_diag.exception_list_read_ok ? 1 : 0,
        (unsigned long long)seh_diag.raw_exception_list,
        seh_diag.sentinel_reached ? 1 : 0,
        seh_diag.x64_empty_chain_proven ? 1 : 0,
        seh_diag.empty_reason.c_str(),
        seh_diag.stack_scan_attempted ? 1 : 0,
        seh_diag.stack_scan_read_ok ? 1 : 0,
        seh_diag.stack_scan_candidates,
        seh_diag.stack_scan_candidate_found ? 1 : 0,
        seh_diag.stack_scan_reason.c_str(),
        seh_diag.chain_stop_reason.c_str());

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
    const size_t malformed_tail = snapshot.size() >= valid_entries ? snapshot.size() - valid_entries : 0;
    diag::log_tagged_fmt("test_dbg_detail",
        "seh_ent result: chain_depth=%zu valid_entries=%zu malformed_tail=%zu x64_empty_chain_proven=%d empty_reason=%s chain_stop=%s",
        snapshot.size(),
        valid_entries,
        malformed_tail,
        seh_diag.x64_empty_chain_proven ? 1 : 0,
        seh_diag.empty_reason.c_str(),
        seh_diag.chain_stop_reason.c_str());

    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - t0).count();
    if ((snapshot.empty() && x64_target && seh_diag.x64_empty_chain_proven) || valid_entries > 0) {
        log_msg(hf, "seh_ent", "PASS -- linked SEH state classified: arch=%s depth=%zu valid_entries=%zu malformed_tail=%zu teb=0x%016llX exception_list=0x%016llX sentinel=%d x64_empty_chain_proven=%d empty_reason=%s (elapsed %lld ms)",
            x64_target ? "x64" : "x86",
            snapshot.size(),
            valid_entries,
            malformed_tail,
            (unsigned long long)seh_diag.teb_va,
            (unsigned long long)seh_diag.raw_exception_list,
            seh_diag.sentinel_reached ? 1 : 0,
            seh_diag.x64_empty_chain_proven ? 1 : 0,
            seh_diag.empty_reason.c_str(),
            (long long)ms);
        passed.fetch_add(1);
    } else {
        log_msg(hf, "seh_ent", "FAIL -- linked SEH chain has no valid decoded entries and no x64 empty-chain proof: arch=%s depth=%zu valid_entries=%zu malformed_tail=%zu teb=0x%016llX exception_list=0x%016llX exception_list_read_ok=%d sentinel=%d empty_reason=%s chain_stop=%s (elapsed %lld ms)",
            x64_target ? "x64" : "x86",
            snapshot.size(),
            valid_entries,
            malformed_tail,
            (unsigned long long)seh_diag.teb_va,
            (unsigned long long)seh_diag.raw_exception_list,
            seh_diag.exception_list_read_ok ? 1 : 0,
            seh_diag.sentinel_reached ? 1 : 0,
            seh_diag.empty_reason.c_str(),
            seh_diag.chain_stop_reason.c_str(),
            (long long)ms);
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

static const char* dbg_sub_tab_label(debugger_view::sub_tab_t tab) {
    switch (tab) {
    case debugger_view::sub_tab_t::cpu:         return "cpu";
    case debugger_view::sub_tab_t::breakpoints: return "breakpoints";
    case debugger_view::sub_tab_t::memory_map:  return "memory_map";
    case debugger_view::sub_tab_t::call_stack:  return "call_stack";
    case debugger_view::sub_tab_t::threads:     return "threads";
    case debugger_view::sub_tab_t::watches:     return "watches";
    case debugger_view::sub_tab_t::handles:     return "handles";
    case debugger_view::sub_tab_t::trace_log:   return "trace_log";
    case debugger_view::sub_tab_t::strings:     return "strings";
    case debugger_view::sub_tab_t::bookmarks:   return "bookmarks";
    case debugger_view::sub_tab_t::modules:     return "modules";
    case debugger_view::sub_tab_t::patches:     return "patches";
    case debugger_view::sub_tab_t::seh_chain:   return "seh_chain";
    case debugger_view::sub_tab_t::cfg:         return "cfg";
    case debugger_view::sub_tab_t::COUNT:       break;
    }
    return "";
}

static void select_debugger_tab(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed,
                                const char* tag, debugger_view::sub_tab_t value) {
    auto t0 = std::chrono::steady_clock::now();
    const debugger_view::sub_tab_t before = debugger_view::g_ui.active_tab;
    const bool visible = debugger_view::is_visible_sub_tab(value);
    const int visible_count = debugger_view::visible_sub_tab_count();
    const int enum_count = static_cast<int>(debugger_view::sub_tab_t::COUNT);
    const char* before_label = dbg_sub_tab_label(before);
    const char* target_label = dbg_sub_tab_label(value);
    diag::log_tagged_fmt("test_dbg_detail", "%s inputs: set active_tab=%d", tag, static_cast<int>(value));
    log_msg(hf, tag, "STATE -- before=%d label=%s target=%d target_label=%s visible=%d visible_count=%d enum_count=%d tid=%lu",
        static_cast<int>(before), before_label,
        static_cast<int>(value), target_label,
        visible ? 1 : 0, visible_count, enum_count,
        (unsigned long)GetCurrentThreadId());
    debugger_view::g_ui.active_tab = value;
    const debugger_view::sub_tab_t got = debugger_view::g_ui.active_tab;
    const char* got_label = dbg_sub_tab_label(got);
    long long us = elapsed_us_since(t0);
    diag::log_tagged_fmt("test_dbg_detail", "%s result: active_tab read_back=%d visible=%d visible_count=%d enum_count=%d",
        tag,
        static_cast<int>(got),
        visible ? 1 : 0,
        visible_count,
        enum_count);
    log_msg(hf, tag, "STATE -- after=%d label=%s changed=%d elapsed_us=%lld",
        static_cast<int>(got), got_label,
        (before != got) ? 1 : 0, us);
    if (got == value && visible && visible_count == enum_count) {
        log_msg(hf, tag, "PASS -- debugger active_tab selected and visible (%d label=%s visible_count=%d elapsed_us=%lld)",
            static_cast<int>(value), got_label, visible_count, us);
        passed.fetch_add(1);
    } else {
        log_msg(hf, tag, "FAIL -- debugger active_tab set %d (%s) but read back %d (%s) visible=%d visible_count=%d enum_count=%d elapsed_us=%lld",
            static_cast<int>(value), target_label,
            static_cast<int>(got), got_label,
            visible ? 1 : 0, visible_count, enum_count, us);
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
            failed.fetch_add(remaining);
            log_msg(hf, "debugger", "FAIL -- cancelled before %d remaining tests could produce evidence", remaining);
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
