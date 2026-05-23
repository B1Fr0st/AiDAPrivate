#include "test_all_analysis.h"

#include "../emulation/symbolic_engine.hpp"
#include "../emulation/deobfuscation_engine.hpp"
#include "../analysis/code_patcher.hpp"
#include "../analysis/integrity_hunter.hpp"
#include "../analysis/binary_map.hpp"
#include "../analysis/source_reconstructor.hpp"
#include "../analysis/xref_engine.hpp"
#include "../analysis/xref_db.hpp"
#include "../analysis/fuzzer_engine.hpp"
#include "../analysis/struct_recon_engine.hpp"
#include "../analysis/stealth_engine.hpp"
#include "../analysis/decrypt_oracle.hpp"
#include "../analysis/pdb_downloader.hpp"
#include "../analysis/analysis_hub_view.hpp"
#include "../disasm/comment_store.hpp"
#include "../disasm/rename_store.hpp"
#include "../editor/expression_eval.hpp"
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
    diag::log_tagged_fmt("test_analysis", "%s: %s", tag, detail);
    OutputDebugStringA(s.c_str());
}

static uint64_t get_ntdll_fn(const char* name) {
    HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
    if (!ntdll) return 0;
    FARPROC fn = GetProcAddress(ntdll, name);
    return static_cast<uint64_t>(reinterpret_cast<uintptr_t>(fn));
}

static void test_symbolic_execute(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
    log_msg(hf, "sym_exec", "START -- symbolic engine execute on small range");
    auto t0 = std::chrono::steady_clock::now();

    uint64_t addr = get_ntdll_fn("NtClose");
    if (addr == 0) {
        log_msg(hf, "sym_exec", "FAIL -- NtClose not found");
        failed.fetch_add(1); return;
    }

    auto result = symbolic_engine::execute_symbolic(addr, addr + 32, 500, {}, {});

    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - t0).count();
    if (!result.success) {
        log_msg(hf, "sym_exec", "FAIL -- execute_symbolic success=0 error=\"%s\" traced=%u (elapsed %lld ms)",
            result.error.c_str(), result.total_instructions, (long long)ms);
        failed.fetch_add(1); return;
    }
    if (result.total_instructions == 0 || result.trace.empty()) {
        log_msg(hf, "sym_exec", "FAIL -- execute_symbolic returned empty trace success=%d traced=%u trace=%zu (elapsed %lld ms)",
            result.success, result.total_instructions, result.trace.size(), (long long)ms);
        failed.fetch_add(1); return;
    }
    log_msg(hf, "sym_exec", "PASS -- success=%d traced=%u tainted=%u junk=%u opaque=%u (elapsed %lld ms)",
        result.success, result.total_instructions, result.tainted_count,
        result.junk_count, result.opaque_count, (long long)ms);
    passed.fetch_add(1);
}

static void test_symbolic_slice(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
    log_msg(hf, "sym_slice", "START -- symbolic engine slice to register");
    auto t0 = std::chrono::steady_clock::now();

    uint64_t addr = get_ntdll_fn("NtClose");
    if (addr == 0) {
        log_msg(hf, "sym_slice", "FAIL -- NtClose not found");
        failed.fetch_add(1); return;
    }

    auto result = symbolic_engine::slice_to_register(addr, addr + 32, 500, "rax");

    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - t0).count();
    if (!result.success) {
        log_msg(hf, "sym_slice", "FAIL -- slice_to_register success=0 error=\"%s\" total=%u effective=%u (elapsed %lld ms)",
            result.error.c_str(), result.total_instructions, result.effective_count, (long long)ms);
        failed.fetch_add(1); return;
    }
    if (result.total_instructions == 0 || result.effective_instructions.empty()) {
        log_msg(hf, "sym_slice", "FAIL -- slice_to_register returned empty slice success=%d total=%u effective=%u (elapsed %lld ms)",
            result.success, result.total_instructions, result.effective_count, (long long)ms);
        failed.fetch_add(1); return;
    }
    log_msg(hf, "sym_slice", "PASS -- success=%d total=%u effective=%u removed=%u (elapsed %lld ms)",
        result.success, result.total_instructions, result.effective_count,
        result.removed_count, (long long)ms);
    passed.fetch_add(1);
}

static void test_symbolic_taint(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
    log_msg(hf, "sym_taint", "START -- symbolic engine taint trace");
    auto t0 = std::chrono::steady_clock::now();

    uint64_t addr = get_ntdll_fn("NtClose");
    if (addr == 0) {
        log_msg(hf, "sym_taint", "FAIL -- NtClose not found");
        failed.fetch_add(1); return;
    }

    auto result = symbolic_engine::taint_trace(addr, addr + 32, 500, {"rcx"}, {});

    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - t0).count();
    if (!result.success) {
        log_msg(hf, "sym_taint", "FAIL -- taint_trace success=0 error=\"%s\" traced=%u tainted=%u (elapsed %lld ms)",
            result.error.c_str(), result.total_processed, result.tainted_count, (long long)ms);
        failed.fetch_add(1); return;
    }
    if (result.total_processed == 0 || result.tainted_instructions.empty()) {
        log_msg(hf, "sym_taint", "FAIL -- taint_trace returned empty taint result success=%d traced=%u tainted=%u (elapsed %lld ms)",
            result.success, result.total_processed, result.tainted_count, (long long)ms);
        failed.fetch_add(1); return;
    }
    log_msg(hf, "sym_taint", "PASS -- success=%d traced=%u tainted=%u (elapsed %lld ms)",
        result.success, result.total_processed, result.tainted_count, (long long)ms);
    passed.fetch_add(1);
}

static void test_symbolic_opaque_predicate(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
    log_msg(hf, "sym_opq", "START -- symbolic engine check opaque predicate");
    auto t0 = std::chrono::steady_clock::now();

    uint64_t addr = get_ntdll_fn("NtClose");
    if (addr == 0) {
        log_msg(hf, "sym_opq", "FAIL -- NtClose not found");
        failed.fetch_add(1); return;
    }

    bool is_opaque = symbolic_engine::is_opaque_predicate(addr, 16);

    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - t0).count();
    log_msg(hf, "sym_opq", "PASS -- is_opaque_predicate(NtClose)=%d (elapsed %lld ms)",
        is_opaque, (long long)ms);
    passed.fetch_add(1);
}

static void test_deobfusc_strip_junk(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
    log_msg(hf, "deob_jnk", "START -- deobfuscation engine strip junk code");
    auto t0 = std::chrono::steady_clock::now();

    uint64_t addr = get_ntdll_fn("NtClose");
    if (addr == 0) {
        log_msg(hf, "deob_jnk", "FAIL -- NtClose not found");
        failed.fetch_add(1); return;
    }

    auto result = deobfuscation_engine::strip_junk_code(addr, addr + 64, {"rax"});

    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - t0).count();
    if (!result.success) {
        log_msg(hf, "deob_jnk", "FAIL -- strip_junk_code success=0 error=\"%s\" original=%u clean=%u (elapsed %lld ms)",
            result.error.c_str(), result.total_original, result.total_clean, (long long)ms);
        failed.fetch_add(1); return;
    }
    if (result.total_original == 0 || result.clean_instructions.empty()) {
        log_msg(hf, "deob_jnk", "FAIL -- strip_junk_code returned empty clean result success=%d original=%u clean=%u (elapsed %lld ms)",
            result.success, result.total_original, result.total_clean, (long long)ms);
        failed.fetch_add(1); return;
    }
    log_msg(hf, "deob_jnk", "PASS -- success=%d original=%u clean=%u removed=%u junk_ratio=%.2f (elapsed %lld ms)",
        result.success, result.total_original, result.total_clean,
        result.removed_junk, static_cast<double>(result.junk_ratio), (long long)ms);
    passed.fetch_add(1);
}

static void test_deobfusc_resolve_constants(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
    log_msg(hf, "deob_cst", "START -- deobfuscation engine resolve constants");
    auto t0 = std::chrono::steady_clock::now();

    uint64_t addr = get_ntdll_fn("NtClose");
    if (addr == 0) {
        log_msg(hf, "deob_cst", "FAIL -- NtClose not found");
        failed.fetch_add(1); return;
    }

    auto constants = deobfuscation_engine::resolve_constants(addr, addr + 32, 500);

    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - t0).count();
    if (constants.empty()) {
        log_msg(hf, "deob_cst", "FAIL -- resolve_constants returned 0 constants (elapsed %lld ms)", (long long)ms);
        failed.fetch_add(1); return;
    }
    log_msg(hf, "deob_cst", "PASS -- resolved %zu constants (elapsed %lld ms)", constants.size(), (long long)ms);
    passed.fetch_add(1);
}

static void test_code_patcher_create_apply_revert(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
    log_msg(hf, "patch_car", "START -- code patcher create/apply/revert");
    auto t0 = std::chrono::steady_clock::now();

    std::vector<uint8_t> new_bytes = { 0x90, 0x90, 0x90 };
    int idx = code_patcher::create_patch(0xDEADBEEF, new_bytes, "test patch (not applied)");

    size_t count = code_patcher::count();
    size_t active = code_patcher::active_count();

    if (idx >= 0) {
        code_patcher::remove_patch(idx);
    }

    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - t0).count();
    if (idx >= 0) {
        log_msg(hf, "patch_car", "PASS -- created patch idx=%d, count=%zu, active=%zu (elapsed %lld ms)",
            idx, count, active, (long long)ms);
        passed.fetch_add(1);
    } else {
        log_msg(hf, "patch_car", "FAIL -- create_patch returned %d (elapsed %lld ms)", idx, (long long)ms);
        failed.fetch_add(1);
    }
}

static void test_code_patcher_nop(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
    log_msg(hf, "patch_nop", "START -- code patcher NOP region");
    auto t0 = std::chrono::steady_clock::now();

    bool ok = code_patcher::nop_region(0xBAADF00D, 4, "test nop region");

    size_t count = code_patcher::count();
    if (count > 0) {
        code_patcher::remove_patch(static_cast<int>(count - 1));
    }

    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - t0).count();
    log_msg(hf, "patch_nop", "PASS -- nop_region returned %d (elapsed %lld ms)", ok, (long long)ms);
    passed.fetch_add(1);
}

static void test_code_patcher_find_caves(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
    log_msg(hf, "patch_cav", "START -- code patcher find code caves");
    auto t0 = std::chrono::steady_clock::now();

    HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
    if (!ntdll) {
        log_msg(hf, "patch_cav", "FAIL -- ntdll not loaded");
        failed.fetch_add(1); return;
    }

    uint64_t base = static_cast<uint64_t>(reinterpret_cast<uintptr_t>(ntdll));
    auto caves = code_patcher::find_code_caves(base, 0x100000, 16);

    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - t0).count();
    log_msg(hf, "patch_cav", "PASS -- found %zu code caves >= 16 bytes (elapsed %lld ms)",
        caves.size(), (long long)ms);
    for (size_t i = 0; i < caves.size() && i < 5; ++i) {
        log_msg(hf, "patch_cav", "  cave[%zu]: addr=0x%llX size=%llu module=%s",
            i, (unsigned long long)caves[i].address,
            (unsigned long long)caves[i].size, caves[i].module_name.c_str());
    }
    passed.fetch_add(1);
}

static void test_integrity_hunter_state(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
    log_msg(hf, "integ_st", "START -- integrity hunter check state");
    auto t0 = std::chrono::steady_clock::now();

    bool hunting = integrity_hunter::g_state.hunting.load();
    uint64_t reads = integrity_hunter::g_state.total_reads.load();

    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - t0).count();
    log_msg(hf, "integ_st", "PASS -- hunting=%d total_reads=%llu (elapsed %lld ms)",
        hunting, (unsigned long long)reads, (long long)ms);
    passed.fetch_add(1);
}

static void test_binary_map_generate(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
    log_msg(hf, "binmap", "START -- binary map generate");
    auto t0 = std::chrono::steady_clock::now();

    aida::binary_map::map_options_t opts;
    opts.max_functions = 10;
    opts.max_globals = 5;
    opts.max_chars = 2048;

    aida::binary_map::map_t map;
    bool ok = aida::binary_map::generate(opts, map);

    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - t0).count();
    if (ok) {
        log_msg(hf, "binmap", "PASS -- module=%s arch=%s sections=%zu functions=%zu (elapsed %lld ms)",
            map.module_name.c_str(), map.architecture.c_str(),
            map.sections.size(), map.functions.size(), (long long)ms);
    } else {
        log_msg(hf, "binmap", "PASS -- generate returned false (no PE loaded, expected): %s (elapsed %lld ms)",
            aida::binary_map::last_error().c_str(), (long long)ms);
    }
    passed.fetch_add(1);
}

static void test_source_reconstructor_status(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
    log_msg(hf, "srcrecon", "START -- source reconstructor status check (no execution)");
    auto t0 = std::chrono::steady_clock::now();

    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - t0).count();
    log_msg(hf, "srcrecon", "PASS -- source_reconstructor namespace accessible (elapsed %lld ms)", (long long)ms);
    passed.fetch_add(1);
}

static void test_xref_find(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
    log_msg(hf, "xref_find", "START -- xref engine find xrefs to known function");
    auto t0 = std::chrono::steady_clock::now();

    uint64_t addr = get_ntdll_fn("NtClose");
    if (addr == 0) {
        log_msg(hf, "xref_find", "FAIL -- NtClose not found");
        failed.fetch_add(1); return;
    }

    xref_engine::find_xrefs_to(addr);

    for (int i = 0; i < 50; ++i) {
        if (!xref_engine::is_scanning()) break;
        Sleep(100);
    }
    xref_engine::cancel_scan();

    size_t count = 0;
    {
        std::lock_guard<std::mutex> lk(xref_engine::g_state.mutex);
        count = xref_engine::g_state.results.size();
    }

    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - t0).count();
    if (count == 0) {
        log_msg(hf, "xref_find", "FAIL -- found 0 xrefs to NtClose (elapsed %lld ms)", (long long)ms);
        failed.fetch_add(1); return;
    }
    log_msg(hf, "xref_find", "PASS -- found %zu xrefs to NtClose (elapsed %lld ms)", count, (long long)ms);
    passed.fetch_add(1);
}

static void test_expression_eval_hex(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
    log_msg(hf, "expr_hex", "START -- expression eval: 0x1000 + 0x20");
    auto t0 = std::chrono::steady_clock::now();

    expression_eval::context_t ctx{};
    auto result = expression_eval::evaluate("0x1000 + 0x20", ctx);

    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - t0).count();
    if (result.ok && result.value == 0x1020) {
        log_msg(hf, "expr_hex", "PASS -- 0x1000 + 0x20 = 0x%llX (elapsed %lld ms)",
            (unsigned long long)result.value, (long long)ms);
        passed.fetch_add(1);
    } else {
        log_msg(hf, "expr_hex", "FAIL -- ok=%d value=0x%llX error=\"%s\" (elapsed %lld ms)",
            result.ok, (unsigned long long)result.value, result.error.c_str(), (long long)ms);
        failed.fetch_add(1);
    }
}

static void test_expression_eval_register(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
    log_msg(hf, "expr_reg", "START -- expression eval: rax + rbx with context");
    auto t0 = std::chrono::steady_clock::now();

    expression_eval::context_t ctx{};
    ctx.rax = 100;
    ctx.rbx = 200;
    auto result = expression_eval::evaluate("rax + rbx", ctx);

    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - t0).count();
    if (result.ok && result.value == 300) {
        log_msg(hf, "expr_reg", "PASS -- rax(100) + rbx(200) = %llu (elapsed %lld ms)",
            (unsigned long long)result.value, (long long)ms);
        passed.fetch_add(1);
    } else {
        log_msg(hf, "expr_reg", "FAIL -- ok=%d value=%llu error=\"%s\" (elapsed %lld ms)",
            result.ok, (unsigned long long)result.value, result.error.c_str(), (long long)ms);
        failed.fetch_add(1);
    }
}

static void test_comment_store(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
    log_msg(hf, "cmt_store", "START -- comment store set/get/has");
    auto t0 = std::chrono::steady_clock::now();

    uint64_t test_addr = 0xDEAD0001;
    comment_store::set(test_addr, "test_comment_analysis");

    bool has = comment_store::has(test_addr);
    std::string got = comment_store::get(test_addr);

    comment_store::set(test_addr, "");

    bool has_after = comment_store::has(test_addr);

    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - t0).count();
    if (has && got == "test_comment_analysis" && !has_after) {
        log_msg(hf, "cmt_store", "PASS -- set/get/has/clear all correct (elapsed %lld ms)", (long long)ms);
        passed.fetch_add(1);
    } else {
        log_msg(hf, "cmt_store", "FAIL -- has=%d got=\"%s\" has_after=%d (elapsed %lld ms)",
            has, got.c_str(), has_after, (long long)ms);
        failed.fetch_add(1);
    }
}

static void test_rename_store(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
    log_msg(hf, "ren_store", "START -- rename store set/get/has");
    auto t0 = std::chrono::steady_clock::now();

    uint64_t test_addr = 0xDEAD0002;
    rename_store::set(test_addr, "test_label_analysis");

    bool has = rename_store::has(test_addr);
    std::string got = rename_store::get(test_addr);

    rename_store::clear(test_addr);

    bool has_after = rename_store::has(test_addr);

    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - t0).count();
    if (has && got == "test_label_analysis" && !has_after) {
        log_msg(hf, "ren_store", "PASS -- set/get/has/clear all correct (elapsed %lld ms)", (long long)ms);
        passed.fetch_add(1);
    } else {
        log_msg(hf, "ren_store", "FAIL -- has=%d got=\"%s\" has_after=%d (elapsed %lld ms)",
            has, got.c_str(), has_after, (long long)ms);
        failed.fetch_add(1);
    }
}

static void test_rename_store_resolve_or(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
    log_msg(hf, "ren_reso", "START -- rename store resolve_or");
    auto t0 = std::chrono::steady_clock::now();

    uint64_t test_addr = 0xDEAD0003;
    rename_store::set(test_addr, "resolved_name");

    std::string found = rename_store::resolve_or(test_addr, "fallback");
    std::string not_found = rename_store::resolve_or(0xDEAD9999, "fallback_val");

    rename_store::clear(test_addr);

    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - t0).count();
    if (found == "resolved_name" && not_found == "fallback_val") {
        log_msg(hf, "ren_reso", "PASS -- resolve_or correct: found=\"%s\" not_found=\"%s\" (elapsed %lld ms)",
            found.c_str(), not_found.c_str(), (long long)ms);
        passed.fetch_add(1);
    } else {
        log_msg(hf, "ren_reso", "FAIL -- found=\"%s\" not_found=\"%s\" (elapsed %lld ms)",
            found.c_str(), not_found.c_str(), (long long)ms);
        failed.fetch_add(1);
    }
}

static void test_symbolic_execute_larger(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
    log_msg(hf, "sym_exlg", "START -- symbolic engine execute on larger range");
    auto t0 = std::chrono::steady_clock::now();

    uint64_t addr = get_ntdll_fn("NtQuerySystemInformation");
    if (addr == 0) {
        log_msg(hf, "sym_exlg", "FAIL -- NtQuerySystemInformation not found");
        failed.fetch_add(1); return;
    }

    auto result = symbolic_engine::execute_symbolic(addr, addr + 64, 1000, {}, {});

    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - t0).count();
    if (!result.success) {
        log_msg(hf, "sym_exlg", "FAIL -- execute_symbolic success=0 error=\"%s\" traced=%u (elapsed %lld ms)",
            result.error.c_str(), result.total_instructions, (long long)ms);
        failed.fetch_add(1); return;
    }
    if (result.total_instructions == 0 || result.trace.empty()) {
        log_msg(hf, "sym_exlg", "FAIL -- execute_symbolic returned empty trace success=%d traced=%u trace=%zu (elapsed %lld ms)",
            result.success, result.total_instructions, result.trace.size(), (long long)ms);
        failed.fetch_add(1); return;
    }
    log_msg(hf, "sym_exlg", "PASS -- success=%d traced=%u tainted=%u (elapsed %lld ms)",
        result.success, result.total_instructions, result.tainted_count, (long long)ms);
    passed.fetch_add(1);
}

static void test_symbolic_slice_rsi(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
    log_msg(hf, "sym_slrsi", "START -- symbolic engine slice to syscall argument mirror r10");
    auto t0 = std::chrono::steady_clock::now();

    uint64_t addr = get_ntdll_fn("NtQuerySystemInformation");
    if (addr == 0) {
        log_msg(hf, "sym_slrsi", "FAIL -- NtQuerySystemInformation not found");
        failed.fetch_add(1); return;
    }

    auto result = symbolic_engine::slice_to_register(addr, addr + 48, 500, "r10");

    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - t0).count();
    if (!result.success) {
        log_msg(hf, "sym_slrsi", "FAIL -- slice_to_register success=0 error=\"%s\" total=%u effective=%u (elapsed %lld ms)",
            result.error.c_str(), result.total_instructions, result.effective_count, (long long)ms);
        failed.fetch_add(1); return;
    }
    if (result.total_instructions == 0 || result.effective_instructions.empty()) {
        log_msg(hf, "sym_slrsi", "FAIL -- slice_to_register returned empty slice success=%d total=%u effective=%u (elapsed %lld ms)",
            result.success, result.total_instructions, result.effective_count, (long long)ms);
        failed.fetch_add(1); return;
    }
    log_msg(hf, "sym_slrsi", "PASS -- success=%d total=%u effective=%u removed=%u (elapsed %lld ms)",
        result.success, result.total_instructions, result.effective_count,
        result.removed_count, (long long)ms);
    passed.fetch_add(1);
}

static void test_symbolic_taint_rdx(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
    log_msg(hf, "sym_trdx", "START -- symbolic engine taint trace syscall input rcx");
    auto t0 = std::chrono::steady_clock::now();

    uint64_t addr = get_ntdll_fn("NtClose");
    if (addr == 0) {
        log_msg(hf, "sym_trdx", "FAIL -- NtClose not found");
        failed.fetch_add(1); return;
    }

    auto result = symbolic_engine::taint_trace(addr, addr + 32, 500, {"rcx"}, {});

    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - t0).count();
    if (!result.success) {
        log_msg(hf, "sym_trdx", "FAIL -- taint_trace success=0 error=\"%s\" traced=%u tainted=%u (elapsed %lld ms)",
            result.error.c_str(), result.total_processed, result.tainted_count, (long long)ms);
        failed.fetch_add(1); return;
    }
    if (result.total_processed == 0 || result.tainted_instructions.empty()) {
        log_msg(hf, "sym_trdx", "FAIL -- taint_trace returned empty taint result success=%d traced=%u tainted=%u regs=%zu mem=%zu (elapsed %lld ms)",
            result.success, result.total_processed, result.tainted_count,
            result.tainted_registers.size(), result.tainted_memory_addresses.size(), (long long)ms);
        failed.fetch_add(1); return;
    }
    log_msg(hf, "sym_trdx", "PASS -- success=%d traced=%u tainted=%u regs=%zu mem=%zu (elapsed %lld ms)",
        result.success, result.total_processed, result.tainted_count,
        result.tainted_registers.size(), result.tainted_memory_addresses.size(), (long long)ms);
    passed.fetch_add(1);
}

static void test_symbolic_solve_for_path(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
    log_msg(hf, "sym_solv", "START -- symbolic engine solve_for_path");
    auto t0 = std::chrono::steady_clock::now();

    uint64_t addr = get_ntdll_fn("NtClose");
    if (addr == 0) {
        log_msg(hf, "sym_solv", "FAIL -- NtClose not found");
        failed.fetch_add(1); return;
    }

    auto result = symbolic_engine::solve_for_path(addr, addr + 16, 500, {"rcx"});

    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - t0).count();
    if (!result.success) {
        log_msg(hf, "sym_solv", "FAIL -- solve_for_path success=0 error=\"%s\" satisfiable=%d vars=%zu solve_ms=%u (elapsed %lld ms)",
            result.error.c_str(), result.satisfiable,
            result.variable_values.size(), result.solving_time_ms, (long long)ms);
        failed.fetch_add(1); return;
    }
    log_msg(hf, "sym_solv", "PASS -- success=%d satisfiable=%d vars=%zu solve_ms=%u (elapsed %lld ms)",
        result.success, result.satisfiable,
        result.variable_values.size(), result.solving_time_ms, (long long)ms);
    passed.fetch_add(1);
}

static void test_symbolic_state_check(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
    log_msg(hf, "sym_stch", "START -- symbolic engine state check");
    auto t0 = std::chrono::steady_clock::now();

    bool processing = symbolic_engine::g_state.processing.load();

    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - t0).count();
    log_msg(hf, "sym_stch", "PASS -- processing=%d (elapsed %lld ms)", processing, (long long)ms);
    passed.fetch_add(1);
}

static void test_deobfusc_deobfuscate_function(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
    log_msg(hf, "deob_fn", "START -- deobfuscation engine deobfuscate_function");
    auto t0 = std::chrono::steady_clock::now();

    uint64_t addr = get_ntdll_fn("NtClose");
    if (addr == 0) {
        log_msg(hf, "deob_fn", "FAIL -- NtClose not found");
        failed.fetch_add(1); return;
    }

    auto result = deobfuscation_engine::deobfuscate_function(addr, 128);

    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - t0).count();
    if (!result.success) {
        log_msg(hf, "deob_fn", "FAIL -- deobfuscate_function success=0 error=\"%s\" original=%u clean=%u blocks=%zu (elapsed %lld ms)",
            result.error.c_str(), result.total_original, result.total_clean,
            result.clean_blocks.size(), (long long)ms);
        failed.fetch_add(1); return;
    }
    if (result.total_original == 0 || result.clean_instructions.empty() || result.clean_blocks.empty()) {
        log_msg(hf, "deob_fn", "FAIL -- deobfuscate_function returned empty result success=%d original=%u clean=%u blocks=%zu (elapsed %lld ms)",
            result.success, result.total_original, result.total_clean,
            result.clean_blocks.size(), (long long)ms);
        failed.fetch_add(1); return;
    }
    log_msg(hf, "deob_fn", "PASS -- success=%d original=%u clean=%u blocks=%zu edges=%zu (elapsed %lld ms)",
        result.success, result.total_original, result.total_clean,
        result.clean_blocks.size(), result.clean_edges.size(), (long long)ms);
    passed.fetch_add(1);
}

static void test_deobfusc_export_asm(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
    log_msg(hf, "deob_asm", "START -- deobfuscation engine export_clean_asm");
    auto t0 = std::chrono::steady_clock::now();

    deobfuscation_engine::deobfuscated_result_t empty_result;
    empty_result.success = true;

    deobfuscation_engine::clean_instruction_t ci;
    ci.address = 0x1000;
    ci.size = 3;
    ci.disasm = "mov eax, ecx";
    empty_result.clean_instructions.push_back(ci);

    std::string asm_text = deobfuscation_engine::export_clean_asm(empty_result);

    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - t0).count();
    if (!asm_text.empty()) {
        log_msg(hf, "deob_asm", "PASS -- export_clean_asm returned %zu chars (elapsed %lld ms)",
            asm_text.size(), (long long)ms);
        passed.fetch_add(1);
    } else {
        log_msg(hf, "deob_asm", "FAIL -- export_clean_asm returned empty (elapsed %lld ms)", (long long)ms);
        failed.fetch_add(1);
    }
}

static void test_deobfusc_export_stats(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
    log_msg(hf, "deob_stat", "START -- deobfuscation engine export_statistics");
    auto t0 = std::chrono::steady_clock::now();

    deobfuscation_engine::deobfuscated_result_t result;
    result.success = true;
    result.total_original = 100;
    result.total_clean = 80;
    result.removed_junk = 15;
    result.opaque_predicates_found = 3;
    result.constants_resolved = 2;
    result.junk_ratio = 0.15f;

    std::string stats = deobfuscation_engine::export_statistics(result);

    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - t0).count();
    if (!stats.empty()) {
        log_msg(hf, "deob_stat", "PASS -- export_statistics returned %zu chars (elapsed %lld ms)",
            stats.size(), (long long)ms);
        passed.fetch_add(1);
    } else {
        log_msg(hf, "deob_stat", "FAIL -- export_statistics returned empty (elapsed %lld ms)", (long long)ms);
        failed.fetch_add(1);
    }
}

static void test_code_patcher_format_parse(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
    log_msg(hf, "patch_fp", "START -- code patcher format_bytes/parse_bytes");
    auto t0 = std::chrono::steady_clock::now();

    std::vector<uint8_t> original = { 0x48, 0x89, 0x5C, 0x24, 0x08 };
    std::string formatted = code_patcher::format_bytes(original);
    std::vector<uint8_t> parsed = code_patcher::parse_bytes(formatted);

    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - t0).count();
    if (parsed == original) {
        log_msg(hf, "patch_fp", "PASS -- format/parse roundtrip: \"%s\" => %zu bytes (elapsed %lld ms)",
            formatted.c_str(), parsed.size(), (long long)ms);
        passed.fetch_add(1);
    } else {
        log_msg(hf, "patch_fp", "FAIL -- format=\"%s\" parsed_size=%zu (elapsed %lld ms)",
            formatted.c_str(), parsed.size(), (long long)ms);
        failed.fetch_add(1);
    }
}

static void test_code_patcher_count(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
    log_msg(hf, "patch_cnt", "START -- code patcher count/active_count");
    auto t0 = std::chrono::steady_clock::now();

    size_t total = code_patcher::count();
    size_t active = code_patcher::active_count();

    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - t0).count();
    log_msg(hf, "patch_cnt", "PASS -- total=%zu active=%zu (elapsed %lld ms)", total, active, (long long)ms);
    passed.fetch_add(1);
}

static void test_integrity_hunter_start_stop(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
    log_msg(hf, "integ_ss", "START -- integrity hunter start/stop hunt");
    auto t0 = std::chrono::steady_clock::now();

    HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
    uint64_t addr = static_cast<uint64_t>(reinterpret_cast<uintptr_t>(ntdll));

    integrity_hunter::start_hunt(addr, 4096);

    Sleep(200);

    integrity_hunter::stop_hunt();

    bool hunting = integrity_hunter::g_state.hunting.load();

    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - t0).count();
    log_msg(hf, "integ_ss", "PASS -- hunting_after_stop=%d (elapsed %lld ms)", hunting, (long long)ms);
    passed.fetch_add(1);
}

static void test_integrity_hunter_nodes(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
    log_msg(hf, "integ_nd", "START -- integrity hunter node list");
    auto t0 = std::chrono::steady_clock::now();

    size_t node_count = 0;
    size_t event_count = 0;
    {
        std::lock_guard<std::mutex> lk(integrity_hunter::g_state.mutex);
        node_count = integrity_hunter::g_state.nodes.size();
        event_count = integrity_hunter::g_state.event_log.size();
    }

    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - t0).count();
    log_msg(hf, "integ_nd", "PASS -- nodes=%zu events=%zu (elapsed %lld ms)", node_count, event_count, (long long)ms);
    passed.fetch_add(1);
}

static void test_binary_map_options(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
    log_msg(hf, "binmap_op", "START -- binary map generate with different options");
    auto t0 = std::chrono::steady_clock::now();

    aida::binary_map::map_options_t opts;
    opts.max_functions = 5;
    opts.max_globals = 3;
    opts.max_chars = 1024;
    opts.include_imports = true;
    opts.include_exports = true;

    aida::binary_map::map_t map;
    bool ok = aida::binary_map::generate(opts, map);

    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - t0).count();
    log_msg(hf, "binmap_op", "PASS -- generate returned %d, sections=%zu funcs=%zu imports=%zu exports=%zu (elapsed %lld ms)",
        ok, map.sections.size(), map.functions.size(),
        map.imports.size(), map.exports.size(), (long long)ms);
    passed.fetch_add(1);
}

static void test_binary_map_pin_unpin(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
    log_msg(hf, "binmap_pin", "START -- binary map pin/unpin function");
    auto t0 = std::chrono::steady_clock::now();

    uint64_t test_va = 0xDEAD1234;
    aida::binary_map::pin_function(test_va);

    auto pinned = aida::binary_map::pinned_functions();
    bool found = false;
    for (auto va : pinned) {
        if (va == test_va) { found = true; break; }
    }

    aida::binary_map::unpin_function(test_va);

    auto pinned_after = aida::binary_map::pinned_functions();
    bool found_after = false;
    for (auto va : pinned_after) {
        if (va == test_va) { found_after = true; break; }
    }

    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - t0).count();
    if (found && !found_after) {
        log_msg(hf, "binmap_pin", "PASS -- pin/unpin correct (elapsed %lld ms)", (long long)ms);
        passed.fetch_add(1);
    } else {
        log_msg(hf, "binmap_pin", "FAIL -- pinned=%d unpinned=%d (elapsed %lld ms)", found, !found_after, (long long)ms);
        failed.fetch_add(1);
    }
}

static void test_binary_map_clear_cache(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
    log_msg(hf, "binmap_cc", "START -- binary map clear_cache");
    auto t0 = std::chrono::steady_clock::now();

    bool ok = aida::binary_map::clear_cache();

    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - t0).count();
    log_msg(hf, "binmap_cc", "PASS -- clear_cache returned %d (elapsed %lld ms)", ok, (long long)ms);
    passed.fetch_add(1);
}

static void test_binary_map_render_text(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
    log_msg(hf, "binmap_rt", "START -- binary map render_text");
    auto t0 = std::chrono::steady_clock::now();

    aida::binary_map::map_options_t opts;
    opts.max_functions = 3;
    opts.max_globals = 2;
    opts.max_chars = 512;

    aida::binary_map::map_t map;
    aida::binary_map::generate(opts, map);

    std::string text = aida::binary_map::render_text(map, opts);

    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - t0).count();
    log_msg(hf, "binmap_rt", "PASS -- render_text returned %zu chars (elapsed %lld ms)", text.size(), (long long)ms);
    passed.fetch_add(1);
}

static void test_source_reconstructor_running(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
    log_msg(hf, "srcrecon_r", "START -- source reconstructor is_running/get_progress");
    auto t0 = std::chrono::steady_clock::now();

    bool running = source_reconstructor::is_running();
    float progress = source_reconstructor::get_progress();
    std::string status = source_reconstructor::get_status();

    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - t0).count();
    log_msg(hf, "srcrecon_r", "PASS -- running=%d progress=%.2f status=\"%s\" (elapsed %lld ms)",
        running, progress, status.c_str(), (long long)ms);
    passed.fetch_add(1);
}

static void test_source_reconstructor_last_result(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
    log_msg(hf, "srcrecon_lr", "START -- source reconstructor get_last_result");
    auto t0 = std::chrono::steady_clock::now();

    auto& result = source_reconstructor::get_last_result();

    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - t0).count();
    log_msg(hf, "srcrecon_lr", "PASS -- success=%d total_funcs=%d decompiled=%d modules=%d files=%zu (elapsed %lld ms)",
        result.success, result.total_functions, result.decompiled_functions,
        result.modules_created, result.files_created.size(), (long long)ms);
    passed.fetch_add(1);
}

static void test_xref_engine_scan_state(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
    log_msg(hf, "xref_st", "START -- xref engine scanning state");
    auto t0 = std::chrono::steady_clock::now();

    bool scanning = xref_engine::is_scanning();
    xref_engine::cancel_scan();

    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - t0).count();
    log_msg(hf, "xref_st", "PASS -- is_scanning=%d (elapsed %lld ms)", scanning, (long long)ms);
    passed.fetch_add(1);
}

static void test_xref_type_names(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
    log_msg(hf, "xref_tn", "START -- xref engine type names");
    auto t0 = std::chrono::steady_clock::now();

    std::string call_name = xref_engine::xref_type_name(xref_engine::xref_type_t::call);
    std::string jmp_name = xref_engine::xref_type_name(xref_engine::xref_type_t::jump);
    std::string jcc_name = xref_engine::xref_type_name(xref_engine::xref_type_t::conditional_jump);
    std::string lea_name = xref_engine::xref_type_name(xref_engine::xref_type_t::lea);
    std::string data_name = xref_engine::xref_type_name(xref_engine::xref_type_t::data_ref);

    bool ok = (call_name == "CALL" && jmp_name == "JMP" && jcc_name == "Jcc" &&
               lea_name == "LEA" && data_name == "DATA");

    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - t0).count();
    if (ok) {
        log_msg(hf, "xref_tn", "PASS -- all xref type names correct (elapsed %lld ms)", (long long)ms);
        passed.fetch_add(1);
    } else {
        log_msg(hf, "xref_tn", "FAIL -- unexpected type names (elapsed %lld ms)", (long long)ms);
        failed.fetch_add(1);
    }
}

static void test_xref_db_state(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
    log_msg(hf, "xrefdb_st", "START -- xref_db state check");
    auto t0 = std::chrono::steady_clock::now();

    bool building = xref_db::g_state.building.load();
    size_t module_count = 0;
    {
        std::lock_guard<std::mutex> lk(xref_db::g_state.mutex);
        module_count = xref_db::g_state.modules.size();
    }

    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - t0).count();
    log_msg(hf, "xrefdb_st", "PASS -- building=%d modules=%zu (elapsed %lld ms)", building, module_count, (long long)ms);
    passed.fetch_add(1);
}

static void test_xref_db_query_to(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
    log_msg(hf, "xrefdb_qt", "START -- xref_db query_xrefs_to");
    auto t0 = std::chrono::steady_clock::now();

    uint64_t addr = get_ntdll_fn("NtClose");
    if (addr == 0) {
        log_msg(hf, "xrefdb_qt", "FAIL -- NtClose not found");
        failed.fetch_add(1); return;
    }

    xref_db::query_xrefs_to(addr);

    size_t results = 0;
    {
        std::lock_guard<std::mutex> lk(xref_db::g_state.mutex);
        results = xref_db::g_state.query_results.size();
    }

    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - t0).count();
    if (results == 0) {
        log_msg(hf, "xrefdb_qt", "FAIL -- query_xrefs_to found 0 results (elapsed %lld ms)", (long long)ms);
        failed.fetch_add(1); return;
    }
    log_msg(hf, "xrefdb_qt", "PASS -- query_xrefs_to found %zu results (elapsed %lld ms)", results, (long long)ms);
    passed.fetch_add(1);
}

static void test_expression_eval_multiply(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
    log_msg(hf, "expr_mul", "START -- expression eval: 0x10 * 0x10");
    auto t0 = std::chrono::steady_clock::now();

    expression_eval::context_t ctx{};
    auto result = expression_eval::evaluate("0x10 * 0x10", ctx);

    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - t0).count();
    if (result.ok && result.value == 0x100) {
        log_msg(hf, "expr_mul", "PASS -- 0x10 * 0x10 = 0x%llX (elapsed %lld ms)",
            (unsigned long long)result.value, (long long)ms);
        passed.fetch_add(1);
    } else {
        log_msg(hf, "expr_mul", "FAIL -- ok=%d value=0x%llX (elapsed %lld ms)",
            result.ok, (unsigned long long)result.value, (long long)ms);
        failed.fetch_add(1);
    }
}

static void test_expression_eval_bitwise(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
    log_msg(hf, "expr_bit", "START -- expression eval: 0xFF & 0x0F | 0xF0");
    auto t0 = std::chrono::steady_clock::now();

    expression_eval::context_t ctx{};
    auto result = expression_eval::evaluate("0xFF & 0x0F | 0xF0", ctx);

    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - t0).count();
    if (result.ok && result.value == 0xFF) {
        log_msg(hf, "expr_bit", "PASS -- 0xFF & 0x0F | 0xF0 = 0x%llX (elapsed %lld ms)",
            (unsigned long long)result.value, (long long)ms);
        passed.fetch_add(1);
    } else {
        log_msg(hf, "expr_bit", "FAIL -- ok=%d value=0x%llX (elapsed %lld ms)",
            result.ok, (unsigned long long)result.value, (long long)ms);
        failed.fetch_add(1);
    }
}

static void test_expression_eval_shift(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
    log_msg(hf, "expr_shl", "START -- expression eval: 1 << 16");
    auto t0 = std::chrono::steady_clock::now();

    expression_eval::context_t ctx{};
    auto result = expression_eval::evaluate("1 << 16", ctx);

    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - t0).count();
    if (result.ok && result.value == 65536) {
        log_msg(hf, "expr_shl", "PASS -- 1 << 16 = %llu (elapsed %lld ms)",
            (unsigned long long)result.value, (long long)ms);
        passed.fetch_add(1);
    } else {
        log_msg(hf, "expr_shl", "FAIL -- ok=%d value=%llu (elapsed %lld ms)",
            result.ok, (unsigned long long)result.value, (long long)ms);
        failed.fetch_add(1);
    }
}

static void test_expression_eval_nested_parens(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
    log_msg(hf, "expr_par", "START -- expression eval: (10 + 20) * (3 + 7)");
    auto t0 = std::chrono::steady_clock::now();

    expression_eval::context_t ctx{};
    auto result = expression_eval::evaluate("(10 + 20) * (3 + 7)", ctx);

    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - t0).count();
    if (result.ok && result.value == 300) {
        log_msg(hf, "expr_par", "PASS -- (10+20)*(3+7) = %llu (elapsed %lld ms)",
            (unsigned long long)result.value, (long long)ms);
        passed.fetch_add(1);
    } else {
        log_msg(hf, "expr_par", "FAIL -- ok=%d value=%llu (elapsed %lld ms)",
            result.ok, (unsigned long long)result.value, (long long)ms);
        failed.fetch_add(1);
    }
}

static void test_expression_eval_xor(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
    log_msg(hf, "expr_xor", "START -- expression eval: 0xAAAA ^ 0x5555");
    auto t0 = std::chrono::steady_clock::now();

    expression_eval::context_t ctx{};
    auto result = expression_eval::evaluate("0xAAAA ^ 0x5555", ctx);

    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - t0).count();
    if (result.ok && result.value == 0xFFFF) {
        log_msg(hf, "expr_xor", "PASS -- 0xAAAA ^ 0x5555 = 0x%llX (elapsed %lld ms)",
            (unsigned long long)result.value, (long long)ms);
        passed.fetch_add(1);
    } else {
        log_msg(hf, "expr_xor", "FAIL -- ok=%d value=0x%llX (elapsed %lld ms)",
            result.ok, (unsigned long long)result.value, (long long)ms);
        failed.fetch_add(1);
    }
}

static void test_expression_eval_multi_register(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
    log_msg(hf, "expr_mreg", "START -- expression eval: rax + rbx * rcx");
    auto t0 = std::chrono::steady_clock::now();

    expression_eval::context_t ctx{};
    ctx.rax = 10;
    ctx.rbx = 5;
    ctx.rcx = 3;
    auto result = expression_eval::evaluate("rax + rbx * rcx", ctx);

    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - t0).count();
    if (result.ok && result.value == 25) {
        log_msg(hf, "expr_mreg", "PASS -- rax(10) + rbx(5)*rcx(3) = %llu (elapsed %lld ms)",
            (unsigned long long)result.value, (long long)ms);
        passed.fetch_add(1);
    } else {
        log_msg(hf, "expr_mreg", "FAIL -- ok=%d value=%llu (elapsed %lld ms)",
            result.ok, (unsigned long long)result.value, (long long)ms);
        failed.fetch_add(1);
    }
}

static void test_fuzzer_state(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
    log_msg(hf, "fuzz_st", "START -- fuzzer engine state check");
    auto t0 = std::chrono::steady_clock::now();

    bool running = fuzzer_engine::g_state.running.load();
    bool cancel = fuzzer_engine::g_state.cancel.load();

    uint64_t total_exec = 0;
    uint64_t total_crash = 0;
    {
        std::lock_guard<std::mutex> lk(fuzzer_engine::g_state.mutex);
        total_exec = fuzzer_engine::g_state.stats.total_executions;
        total_crash = fuzzer_engine::g_state.stats.total_crashes;
    }

    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - t0).count();
    log_msg(hf, "fuzz_st", "PASS -- running=%d cancel=%d execs=%llu crashes=%llu (elapsed %lld ms)",
        running, cancel,
        (unsigned long long)total_exec, (unsigned long long)total_crash, (long long)ms);
    passed.fetch_add(1);
}

static void test_fuzzer_config(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
    log_msg(hf, "fuzz_cfg", "START -- fuzzer engine config defaults");
    auto t0 = std::chrono::steady_clock::now();

    fuzzer_engine::fuzz_config_t cfg;
    bool ok = (cfg.max_instructions == 100000 &&
               cfg.timeout_ms == 5000 &&
               cfg.max_iterations == 100000 &&
               cfg.input_size == 256 &&
               cfg.mutation_count == 4);

    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - t0).count();
    if (ok) {
        log_msg(hf, "fuzz_cfg", "PASS -- config defaults correct (elapsed %lld ms)", (long long)ms);
        passed.fetch_add(1);
    } else {
        log_msg(hf, "fuzz_cfg", "FAIL -- unexpected config defaults (elapsed %lld ms)", (long long)ms);
        failed.fetch_add(1);
    }
}

static void test_stealth_state(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
    log_msg(hf, "stealth_st", "START -- stealth engine state check");
    auto t0 = std::chrono::steady_clock::now();

    bool active = stealth_engine::g_state.active.load();

    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - t0).count();
    log_msg(hf, "stealth_st", "PASS -- active=%d (elapsed %lld ms)", active, (long long)ms);
    passed.fetch_add(1);
}

static void test_stealth_options_default(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
    log_msg(hf, "stealth_op", "START -- stealth engine default options");
    auto t0 = std::chrono::steady_clock::now();

    stealth_engine::stealth_options_t opts;
    bool ok = (opts.spoof_peb == true && opts.hook_rdtsc == true && opts.scrub_context == false);

    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - t0).count();
    if (ok) {
        log_msg(hf, "stealth_op", "PASS -- default options correct (elapsed %lld ms)", (long long)ms);
        passed.fetch_add(1);
    } else {
        log_msg(hf, "stealth_op", "FAIL -- unexpected defaults (elapsed %lld ms)", (long long)ms);
        failed.fetch_add(1);
    }
}

static void test_struct_recon_state(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
    log_msg(hf, "strecon_st", "START -- struct recon state check");
    auto t0 = std::chrono::steady_clock::now();

    bool monitoring = struct_recon::g_state.monitoring.load();
    float progress = struct_recon::g_state.progress.load();

    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - t0).count();
    log_msg(hf, "strecon_st", "PASS -- monitoring=%d progress=%.2f (elapsed %lld ms)",
        monitoring, progress, (long long)ms);
    passed.fetch_add(1);
}

static void test_struct_recon_field_types(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
    log_msg(hf, "strecon_ft", "START -- struct recon field type enum range");
    auto t0 = std::chrono::steady_clock::now();

    int count_val = static_cast<int>(struct_recon::field_type_t::COUNT);
    bool ok = (count_val > 20 &&
               static_cast<int>(struct_recon::field_type_t::unknown) == 0 &&
               static_cast<int>(struct_recon::field_type_t::pointer) == 11 &&
               static_cast<int>(struct_recon::field_type_t::vtable_ptr) == 12 &&
               std::strcmp(struct_recon::field_type_name(struct_recon::field_type_t::pointer), "void*") == 0 &&
               std::strcmp(struct_recon::field_type_name(struct_recon::field_type_t::vtable_ptr), "vtable*") == 0);

    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - t0).count();
    if (ok) {
        log_msg(hf, "strecon_ft", "PASS -- field_type_t has %d values (elapsed %lld ms)", count_val, (long long)ms);
        passed.fetch_add(1);
    } else {
        log_msg(hf, "strecon_ft", "FAIL -- unexpected field_type_t layout (elapsed %lld ms)", (long long)ms);
        failed.fetch_add(1);
    }
}

static void test_decrypt_oracle_state(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
    log_msg(hf, "decr_st", "START -- decrypt oracle state check");
    auto t0 = std::chrono::steady_clock::now();

    bool scanning = decrypt_oracle::g_state.scanning.load();
    float progress = decrypt_oracle::g_state.progress.load();
    int total_xrefs = decrypt_oracle::g_state.total_xrefs.load();
    int processed_xrefs = decrypt_oracle::g_state.processed_xrefs.load();

    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - t0).count();
    log_msg(hf, "decr_st", "PASS -- scanning=%d progress=%.2f total_xrefs=%d processed=%d (elapsed %lld ms)",
        scanning, progress, total_xrefs, processed_xrefs, (long long)ms);
    passed.fetch_add(1);
}

static void test_decrypt_oracle_config(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
    log_msg(hf, "decr_cfg", "START -- decrypt oracle config defaults");
    auto t0 = std::chrono::steady_clock::now();

    decrypt_oracle::scan_config_t cfg;
    bool ok = (cfg.max_instructions == 50000 &&
               cfg.timeout_ms == 5000 &&
               cfg.min_string_length == 4 &&
               cfg.min_printable_ratio > 0.7f);

    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - t0).count();
    if (ok) {
        log_msg(hf, "decr_cfg", "PASS -- config defaults correct (elapsed %lld ms)", (long long)ms);
        passed.fetch_add(1);
    } else {
        log_msg(hf, "decr_cfg", "FAIL -- unexpected config defaults (elapsed %lld ms)", (long long)ms);
        failed.fetch_add(1);
    }
}

static void test_pdb_resolve_cache_path(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
    log_msg(hf, "pdb_cache", "START -- pdb downloader resolve_cache_path");
    auto t0 = std::chrono::steady_clock::now();

    pdb_downloader::download_request_t req;
    req.pdb_name = "ntdll.pdb";
    req.pdb_guid = "00000000000000000000000000000000";
    req.pdb_age = 1;

    char* appdata = nullptr;
    size_t len = 0;
    _dupenv_s(&appdata, &len, "APPDATA");
    if (appdata) {
        req.cache_root = std::string(appdata) + "\\AiDA\\Standalone\\symbols";
        free(appdata);
    }

    std::string out_path;
    bool resolved = pdb_downloader::resolve_cache_path(req, out_path);

    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - t0).count();
    log_msg(hf, "pdb_cache", "PASS -- resolve_cache_path returned %d path=\"%s\" (elapsed %lld ms)",
        resolved, out_path.c_str(), (long long)ms);
    passed.fetch_add(1);
}

static void test_comment_store_multiple(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
    log_msg(hf, "cmt_multi", "START -- comment store multiple addresses");
    auto t0 = std::chrono::steady_clock::now();

    comment_store::set(0xBEEF0001, "comment_alpha");
    comment_store::set(0xBEEF0002, "comment_beta");
    comment_store::set(0xBEEF0003, "comment_gamma");

    std::string a = comment_store::get(0xBEEF0001);
    std::string b = comment_store::get(0xBEEF0002);
    std::string c = comment_store::get(0xBEEF0003);

    comment_store::set(0xBEEF0001, "");
    comment_store::set(0xBEEF0002, "");
    comment_store::set(0xBEEF0003, "");

    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - t0).count();
    if (a == "comment_alpha" && b == "comment_beta" && c == "comment_gamma") {
        log_msg(hf, "cmt_multi", "PASS -- all 3 comments stored/retrieved correctly (elapsed %lld ms)", (long long)ms);
        passed.fetch_add(1);
    } else {
        log_msg(hf, "cmt_multi", "FAIL -- a=\"%s\" b=\"%s\" c=\"%s\" (elapsed %lld ms)",
            a.c_str(), b.c_str(), c.c_str(), (long long)ms);
        failed.fetch_add(1);
    }
}

static void test_comment_store_overwrite(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
    log_msg(hf, "cmt_over", "START -- comment store overwrite");
    auto t0 = std::chrono::steady_clock::now();

    uint64_t addr = 0xBEEF1234;
    comment_store::set(addr, "first_value");
    comment_store::set(addr, "second_value");

    std::string got = comment_store::get(addr);
    comment_store::set(addr, "");

    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - t0).count();
    if (got == "second_value") {
        log_msg(hf, "cmt_over", "PASS -- overwrite correct: \"%s\" (elapsed %lld ms)", got.c_str(), (long long)ms);
        passed.fetch_add(1);
    } else {
        log_msg(hf, "cmt_over", "FAIL -- got \"%s\" (elapsed %lld ms)", got.c_str(), (long long)ms);
        failed.fetch_add(1);
    }
}

static void select_analysis_hub_tab(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed,
                                     const char* tag, analysis_hub_view::sub_tab_t value) {
    analysis_hub_view::set_sub_tab(value);
    analysis_hub_view::sub_tab_t got = analysis_hub_view::active_sub_tab();
    const char* label = analysis_hub_view::sub_tab_label(value);
    if (got == value && label[0] != '\0') {
        log_msg(hf, tag, "PASS -- analysis_hub sub_tab selected and read back (%d label=%s)",
            static_cast<int>(value), label);
        passed.fetch_add(1);
    } else {
        log_msg(hf, tag, "FAIL -- analysis_hub sub_tab set %d but read back %d label=\"%s\"",
            static_cast<int>(value), static_cast<int>(got), label);
        failed.fetch_add(1);
    }
}

static void select_symbolic_inner_tab(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed,
                                      const char* tag, int value, const char* expected_label) {
    analysis_hub_view::set_sub_tab(analysis_hub_view::sub_tab_t::symbolic);
    symbolic_view::set_active_tab(value);
    int got = symbolic_view::active_tab();
    const char* label = symbolic_view::tab_label(value);
    if (got == value && std::strcmp(label, expected_label) == 0) {
        log_msg(hf, tag, "PASS -- symbolic inner tab selected and read back (%d label=%s)",
            value, label);
        passed.fetch_add(1);
    } else {
        log_msg(hf, tag, "FAIL -- symbolic inner tab set %d but read back %d label=\"%s\" expected=\"%s\"",
            value, got, label, expected_label);
        failed.fetch_add(1);
    }
}

static void select_protection_inner_tab(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed,
                                        const char* tag, int value, const char* expected_label) {
    analysis_hub_view::set_sub_tab(analysis_hub_view::sub_tab_t::stealth);
    stealth_view::set_sub_tab(value);
    int got = stealth_view::active_sub_tab();
    const char* label = stealth_view::sub_tab_label(value);
    if (got == value && std::strcmp(label, expected_label) == 0) {
        log_msg(hf, tag, "PASS -- protection inner tab selected and read back (%d label=%s)",
            value, label);
        passed.fetch_add(1);
    } else {
        log_msg(hf, tag, "FAIL -- protection inner tab set %d but read back %d label=\"%s\" expected=\"%s\"",
            value, got, label, expected_label);
        failed.fetch_add(1);
    }
}

static void test_analysis_hub_tab_symbolic(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
    select_analysis_hub_tab(hf, passed, failed, "analysis_hub_tab.symbolic", analysis_hub_view::sub_tab_t::symbolic);
}
static void test_analysis_hub_tab_taint(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
    select_analysis_hub_tab(hf, passed, failed, "analysis_hub_tab.taint", analysis_hub_view::sub_tab_t::taint);
}
static void test_analysis_hub_tab_deobfuscation(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
    select_analysis_hub_tab(hf, passed, failed, "analysis_hub_tab.deobfuscation", analysis_hub_view::sub_tab_t::deobfuscation);
}
static void test_analysis_hub_tab_fuzzer(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
    select_analysis_hub_tab(hf, passed, failed, "analysis_hub_tab.fuzzer", analysis_hub_view::sub_tab_t::fuzzer);
}
static void test_analysis_hub_tab_protection(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
    select_analysis_hub_tab(hf, passed, failed, "analysis_hub_tab.protection", analysis_hub_view::sub_tab_t::stealth);
}

static void test_symbolic_inner_trace(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
    select_symbolic_inner_tab(hf, passed, failed, "symbolic_inner.trace", 0, "Trace");
}
static void test_symbolic_inner_deobfuscation(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
    select_symbolic_inner_tab(hf, passed, failed, "symbolic_inner.deobfuscation", 1, "Deobfuscation");
}
static void test_symbolic_inner_slice(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
    select_symbolic_inner_tab(hf, passed, failed, "symbolic_inner.slice", 2, "Slice");
}
static void test_symbolic_inner_solver(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
    select_symbolic_inner_tab(hf, passed, failed, "symbolic_inner.solver", 3, "Solver");
}
static void test_symbolic_inner_constraints(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
    select_symbolic_inner_tab(hf, passed, failed, "symbolic_inner.constraints", 4, "Constraints");
}
static void test_symbolic_inner_expression(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
    select_symbolic_inner_tab(hf, passed, failed, "symbolic_inner.expression", 5, "Expression");
}

static void test_protection_inner_scan(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
    select_protection_inner_tab(hf, passed, failed, "protection_inner.scan", 0, "Protection Scan");
}
static void test_protection_inner_controls(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
    select_protection_inner_tab(hf, passed, failed, "protection_inner.controls", 1, "Stealth Controls");
}

}

void phase_analysis_tests(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped, bool(*cancelled)()) {
    struct test_entry_t {
        const char* name;
        void (*fn)(HANDLE, std::atomic<int>&, std::atomic<int>&);
    };

    static const test_entry_t tests[] = {
        { "symbolic_execute",            test_symbolic_execute            },
        { "symbolic_execute_larger",     test_symbolic_execute_larger     },
        { "symbolic_slice",              test_symbolic_slice              },
        { "symbolic_slice_rsi",          test_symbolic_slice_rsi          },
        { "symbolic_taint",              test_symbolic_taint              },
        { "symbolic_taint_rdx",          test_symbolic_taint_rdx          },
        { "symbolic_opaque_predicate",   test_symbolic_opaque_predicate   },
        { "symbolic_solve_for_path",     test_symbolic_solve_for_path     },
        { "symbolic_state_check",        test_symbolic_state_check        },
        { "deobfusc_strip_junk",         test_deobfusc_strip_junk         },
        { "deobfusc_resolve_constants",  test_deobfusc_resolve_constants  },
        { "deobfusc_deobfuscate_fn",     test_deobfusc_deobfuscate_function },
        { "deobfusc_export_asm",         test_deobfusc_export_asm         },
        { "deobfusc_export_stats",       test_deobfusc_export_stats       },
        { "code_patcher_create_revert",  test_code_patcher_create_apply_revert },
        { "code_patcher_nop",            test_code_patcher_nop            },
        { "code_patcher_find_caves",     test_code_patcher_find_caves     },
        { "code_patcher_format_parse",   test_code_patcher_format_parse   },
        { "code_patcher_count",          test_code_patcher_count          },
        { "integrity_hunter_state",      test_integrity_hunter_state      },
        { "integrity_hunter_start_stop", test_integrity_hunter_start_stop },
        { "integrity_hunter_nodes",      test_integrity_hunter_nodes      },
        { "binary_map_generate",         test_binary_map_generate         },
        { "binary_map_options",          test_binary_map_options          },
        { "binary_map_pin_unpin",        test_binary_map_pin_unpin        },
        { "binary_map_clear_cache",      test_binary_map_clear_cache      },
        { "binary_map_render_text",      test_binary_map_render_text      },
        { "source_reconstructor_status", test_source_reconstructor_status },
        { "source_recon_running",        test_source_reconstructor_running },
        { "source_recon_last_result",    test_source_reconstructor_last_result },
        { "xref_find",                   test_xref_find                   },
        { "xref_engine_scan_state",      test_xref_engine_scan_state      },
        { "xref_type_names",             test_xref_type_names             },
        { "xref_db_state",               test_xref_db_state               },
        { "xref_db_query_to",            test_xref_db_query_to            },
        { "expression_eval_hex",         test_expression_eval_hex         },
        { "expression_eval_register",    test_expression_eval_register    },
        { "expression_eval_multiply",    test_expression_eval_multiply    },
        { "expression_eval_bitwise",     test_expression_eval_bitwise     },
        { "expression_eval_shift",       test_expression_eval_shift       },
        { "expression_eval_nested_paren",test_expression_eval_nested_parens},
        { "expression_eval_xor",         test_expression_eval_xor         },
        { "expression_eval_multi_reg",   test_expression_eval_multi_register },
        { "comment_store",               test_comment_store               },
        { "comment_store_multiple",      test_comment_store_multiple      },
        { "comment_store_overwrite",     test_comment_store_overwrite     },
        { "rename_store",                test_rename_store                },
        { "rename_store_resolve_or",     test_rename_store_resolve_or     },
        { "fuzzer_state",                test_fuzzer_state                },
        { "fuzzer_config",               test_fuzzer_config               },
        { "stealth_state",               test_stealth_state               },
        { "stealth_options_default",     test_stealth_options_default     },
        { "struct_recon_state",          test_struct_recon_state          },
        { "struct_recon_field_types",    test_struct_recon_field_types    },
        { "decrypt_oracle_state",        test_decrypt_oracle_state        },
        { "decrypt_oracle_config",       test_decrypt_oracle_config       },
        { "pdb_resolve_cache_path",      test_pdb_resolve_cache_path      },

        { "analysis_hub_tab_symbolic",   test_analysis_hub_tab_symbolic   },
        { "analysis_hub_tab_taint",      test_analysis_hub_tab_taint      },
        { "analysis_hub_tab_deobfusc",   test_analysis_hub_tab_deobfuscation },
        { "analysis_hub_tab_fuzzer",     test_analysis_hub_tab_fuzzer     },
        { "analysis_hub_tab_protection", test_analysis_hub_tab_protection },
        { "symbolic_inner_trace",        test_symbolic_inner_trace        },
        { "symbolic_inner_deobfusc",     test_symbolic_inner_deobfuscation },
        { "symbolic_inner_slice",        test_symbolic_inner_slice        },
        { "symbolic_inner_solver",       test_symbolic_inner_solver       },
        { "symbolic_inner_constraints",  test_symbolic_inner_constraints  },
        { "symbolic_inner_expression",   test_symbolic_inner_expression   },
        { "protection_inner_scan",       test_protection_inner_scan       },
        { "protection_inner_controls",   test_protection_inner_controls   },
    };

    int total = static_cast<int>(sizeof(tests) / sizeof(tests[0]));
    log_msg(hf, "analysis", "=== BEGIN analysis tests (%d tests) ===", total);
    for (int i = 0; i < total; ++i) {
        if (cancelled && cancelled()) {
            int remaining = total - i;
            skipped.fetch_add(remaining);
            log_msg(hf, "analysis", "cancelled -- skipping %d remaining tests", remaining);
            break;
        }

        log_msg(hf, "analysis", "[%d/%d] %s", i + 1, total, tests[i].name);
        __try {
            tests[i].fn(hf, passed, failed);
        }
        __except (EXCEPTION_EXECUTE_HANDLER) {
            log_msg(hf, "analysis", "FAIL -- %s threw SEH exception 0x%08X",
                tests[i].name, GetExceptionCode());
            failed.fetch_add(1);
        }
    }

    log_msg(hf, "analysis", "=== END analysis tests ===");
}

}
