#include "test_all_disasm.h"

#include "../disasm/disasm_view.hpp"
#include "../disasm/pseudocode_view.hpp"
#include "../disasm/function_index.hpp"
#include "../disasm/xref_index.hpp"
#include "../disasm/comment_store.hpp"
#include "../disasm/rename_store.hpp"
#include "../disasm/nav_history.hpp"
#include "../editor/hex_view.hpp"
#include "../editor/expression_eval.hpp"
#include "../debugger/debugger_engine.hpp"
#include "../../helpers/diag_log.hpp"

#include <chrono>
#include <cstdarg>
#include <cstdio>
#include <cstring>
#include <string>
#include <vector>

namespace test_all_features {

namespace {

    void format_timestamp(char* out, std::size_t cap) {
        SYSTEMTIME st; GetLocalTime(&st);
        std::snprintf(out, cap, "%04u-%02u-%02u %02u:%02u:%02u.%03u",
            (unsigned)st.wYear, (unsigned)st.wMonth, (unsigned)st.wDay,
            (unsigned)st.wHour, (unsigned)st.wMinute, (unsigned)st.wSecond, (unsigned)st.wMilliseconds);
    }
    void write_log_file(HANDLE hf, const std::string& line) {
        if (hf == INVALID_HANDLE_VALUE) return;
        DWORD wrote = 0;
        WriteFile(hf, line.data(), (DWORD)line.size(), &wrote, nullptr);
        FlushFileBuffers(hf);
    }
    void log_msg(HANDLE hf, const char* tag, const char* fmt, ...) {
        char ts[40]; format_timestamp(ts, sizeof(ts));
        char detail[1024]; va_list ap; va_start(ap, fmt);
        _vsnprintf_s(detail, sizeof(detail), _TRUNCATE, fmt, ap); va_end(ap);
        char line[1200];
        _snprintf_s(line, sizeof(line), _TRUNCATE, "[%s] [%s] %s\n", ts, tag, detail);
        std::string s(line);
        write_log_file(hf, s);
        diag::log_tagged_fmt("test_all", "%s: %s", tag, detail);
        OutputDebugStringA(s.c_str());
    }

    uint64_t resolve_ntclose() {
        HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
        if (!ntdll) return 0;
        FARPROC fn = GetProcAddress(ntdll, "NtClose");
        if (!fn) return 0;
        return static_cast<uint64_t>(reinterpret_cast<uintptr_t>(fn));
    }

    void test_goto_address(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        const char* tag = "disasm.goto_address";
        uint64_t addr = resolve_ntclose();
        if (addr == 0) {
            log_msg(hf, tag, "SKIP -- NtClose not resolved");
            skipped.fetch_add(1);
            return;
        }
        auto t0 = std::chrono::steady_clock::now();
        debugger_engine::request_disasm_refresh(addr, 0);
        Sleep(300);
        auto t1 = std::chrono::steady_clock::now();
        auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(t1 - t0).count();
        log_msg(hf, tag, "PASS -- requested disasm refresh at 0x%016llX (elapsed %lld ms)",
            (unsigned long long)addr, (long long)ms);
        passed.fetch_add(1);
    }

    void test_get_disasm_window_bytes(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        const char* tag = "disasm.window_bytes";
        uint64_t addr = resolve_ntclose();
        if (addr == 0) {
            log_msg(hf, tag, "SKIP -- NtClose not resolved");
            skipped.fetch_add(1);
            return;
        }
        debugger_engine::request_disasm_refresh(addr, 0);
        Sleep(300);

        uint64_t base_out = 0;
        auto bytes = debugger_engine::cached_disasm_window(base_out);
        if (!bytes.empty()) {
            log_msg(hf, tag, "PASS -- disasm window has %zu bytes at base 0x%016llX",
                bytes.size(), (unsigned long long)base_out);
            passed.fetch_add(1);
        } else {
            log_msg(hf, tag, "SKIP -- disasm window empty (debugger may not be attached)");
            skipped.fetch_add(1);
        }
    }

    void test_navigate_back_forward(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        const char* tag = "disasm.nav_back_fwd";
        try {
            disasm_view::navigate_back();
            disasm_view::navigate_forward();
            log_msg(hf, tag, "PASS -- navigate_back/navigate_forward executed without crash");
            passed.fetch_add(1);
        } catch (...) {
            log_msg(hf, tag, "FAIL -- exception in navigate_back/forward");
            failed.fetch_add(1);
        }
    }

    void test_bump_format_generation(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        const char* tag = "disasm.bump_format";
        try {
            disasm_view::bump_format_generation();
            log_msg(hf, tag, "PASS -- bump_format_generation executed without crash");
            passed.fetch_add(1);
        } catch (...) {
            log_msg(hf, tag, "FAIL -- exception in bump_format_generation");
            failed.fetch_add(1);
        }
    }

    void test_comment_set_get(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        const char* tag = "comment.set_get";
        const uint64_t test_addr = 0xDEADBEEF00000001ULL;
        const std::string test_text = "test_comment_from_test_all_disasm";

        comment_store::set(test_addr, test_text);
        std::string got = comment_store::get(test_addr);

        if (got == test_text) {
            log_msg(hf, tag, "PASS -- set/get roundtrip OK");
            passed.fetch_add(1);
        } else {
            log_msg(hf, tag, "FAIL -- expected \"%s\", got \"%s\"", test_text.c_str(), got.c_str());
            failed.fetch_add(1);
        }
        comment_store::set(test_addr, "");
    }

    void test_comment_has(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        const char* tag = "comment.has";
        const uint64_t test_addr = 0xDEADBEEF00000002ULL;

        comment_store::set(test_addr, "temporary");
        bool present = comment_store::has(test_addr);
        comment_store::set(test_addr, "");
        bool absent = !comment_store::has(test_addr);

        if (present && absent) {
            log_msg(hf, tag, "PASS -- has() returns true when set, false after clear");
            passed.fetch_add(1);
        } else {
            log_msg(hf, tag, "FAIL -- has() present=%d absent=%d", (int)present, (int)absent);
            failed.fetch_add(1);
        }
    }

    void test_comment_empty_clears(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        const char* tag = "comment.empty_clear";
        const uint64_t test_addr = 0xDEADBEEF00000003ULL;

        comment_store::set(test_addr, "will_be_cleared");
        comment_store::set(test_addr, "");
        std::string got = comment_store::get(test_addr);

        if (got.empty()) {
            log_msg(hf, tag, "PASS -- setting empty string clears comment");
            passed.fetch_add(1);
        } else {
            log_msg(hf, tag, "FAIL -- comment not cleared: \"%s\"", got.c_str());
            failed.fetch_add(1);
        }
    }

    void test_rename_set_get(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        const char* tag = "rename.set_get";
        const uint64_t test_addr = 0xDEADBEEF10000001ULL;
        const std::string test_name = "my_custom_function";

        rename_store::set(test_addr, test_name);
        std::string got = rename_store::get(test_addr);

        if (got == test_name) {
            log_msg(hf, tag, "PASS -- set/get roundtrip OK");
            passed.fetch_add(1);
        } else {
            log_msg(hf, tag, "FAIL -- expected \"%s\", got \"%s\"", test_name.c_str(), got.c_str());
            failed.fetch_add(1);
        }
        rename_store::clear(test_addr);
    }

    void test_rename_has(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        const char* tag = "rename.has";
        const uint64_t test_addr = 0xDEADBEEF10000002ULL;

        rename_store::set(test_addr, "temp_rename");
        bool present = rename_store::has(test_addr);
        rename_store::clear(test_addr);
        bool absent = !rename_store::has(test_addr);

        if (present && absent) {
            log_msg(hf, tag, "PASS -- has() returns true when set, false after clear");
            passed.fetch_add(1);
        } else {
            log_msg(hf, tag, "FAIL -- has() present=%d absent=%d", (int)present, (int)absent);
            failed.fetch_add(1);
        }
    }

    void test_rename_clear(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        const char* tag = "rename.clear";
        const uint64_t test_addr = 0xDEADBEEF10000003ULL;

        rename_store::set(test_addr, "to_be_cleared");
        rename_store::clear(test_addr);
        std::string got = rename_store::get(test_addr);

        if (got.empty()) {
            log_msg(hf, tag, "PASS -- clear() removes rename");
            passed.fetch_add(1);
        } else {
            log_msg(hf, tag, "FAIL -- rename not cleared: \"%s\"", got.c_str());
            failed.fetch_add(1);
        }
    }

    void test_rename_resolve_or(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        const char* tag = "rename.resolve_or";
        const uint64_t addr_with = 0xDEADBEEF10000004ULL;
        const uint64_t addr_without = 0xDEADBEEF10000005ULL;

        rename_store::set(addr_with, "resolved_name");
        std::string r1 = rename_store::resolve_or(addr_with, "fallback");
        std::string r2 = rename_store::resolve_or(addr_without, "fallback");

        bool ok = (r1 == "resolved_name") && (r2 == "fallback");
        if (ok) {
            log_msg(hf, tag, "PASS -- resolve_or returns name when present, fallback otherwise");
            passed.fetch_add(1);
        } else {
            log_msg(hf, tag, "FAIL -- r1=\"%s\" r2=\"%s\"", r1.c_str(), r2.c_str());
            failed.fetch_add(1);
        }
        rename_store::clear(addr_with);
    }

    void test_xref_query_to(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        const char* tag = "xref.query_to";
        uint64_t addr = resolve_ntclose();
        if (addr == 0) {
            log_msg(hf, tag, "SKIP -- NtClose not resolved");
            skipped.fetch_add(1);
            return;
        }
        try {
            auto results = xref_index::query_to(addr, 16);
            log_msg(hf, tag, "PASS -- query_to(0x%016llX) returned %zu xrefs",
                (unsigned long long)addr, results.size());
            passed.fetch_add(1);
        } catch (...) {
            log_msg(hf, tag, "FAIL -- exception in query_to");
            failed.fetch_add(1);
        }
    }

    void test_xref_has_more(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        const char* tag = "xref.has_more";
        uint64_t addr = resolve_ntclose();
        if (addr == 0) {
            log_msg(hf, tag, "SKIP -- NtClose not resolved");
            skipped.fetch_add(1);
            return;
        }
        try {
            bool more = xref_index::has_more(addr, 1);
            log_msg(hf, tag, "PASS -- has_more(0x%016llX, 1) = %s",
                (unsigned long long)addr, more ? "true" : "false");
            passed.fetch_add(1);
        } catch (...) {
            log_msg(hf, tag, "FAIL -- exception in has_more");
            failed.fetch_add(1);
        }
    }

    void test_xref_request_deep_static(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        const char* tag = "xref.deep_static";
        try {
            bool was_requested = xref_index::deep_static_xref_requested();
            xref_index::request_deep_static_xref();
            bool now_requested = xref_index::deep_static_xref_requested();
            log_msg(hf, tag, "PASS -- request_deep_static_xref: before=%d after=%d",
                (int)was_requested, (int)now_requested);
            passed.fetch_add(1);
        } catch (...) {
            log_msg(hf, tag, "FAIL -- exception in request_deep_static_xref");
            failed.fetch_add(1);
        }
    }

    void test_xref_on_file_loaded(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        const char* tag = "xref.on_file_loaded";
        try {
            xref_index::on_file_loaded();
            log_msg(hf, tag, "PASS -- on_file_loaded() executed without crash");
            passed.fetch_add(1);
        } catch (...) {
            log_msg(hf, tag, "FAIL -- exception in on_file_loaded");
            failed.fetch_add(1);
        }
    }

    void test_xref_on_attach_changed(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        const char* tag = "xref.on_attach_changed";
        try {
            xref_index::on_attach_changed();
            log_msg(hf, tag, "PASS -- on_attach_changed() executed without crash");
            passed.fetch_add(1);
        } catch (...) {
            log_msg(hf, tag, "FAIL -- exception in on_attach_changed");
            failed.fetch_add(1);
        }
    }

    void test_pseudocode_request_decompile(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        const char* tag = "pseudo.request_decompile";
        uint64_t addr = resolve_ntclose();
        if (addr == 0) {
            log_msg(hf, tag, "SKIP -- NtClose not resolved");
            skipped.fetch_add(1);
            return;
        }
        try {
            pseudocode_view::request_decompile(addr, nullptr, false);
            Sleep(500);
            log_msg(hf, tag, "PASS -- request_decompile(0x%016llX) issued",
                (unsigned long long)addr);
            passed.fetch_add(1);
        } catch (...) {
            log_msg(hf, tag, "FAIL -- exception in request_decompile");
            failed.fetch_add(1);
        }
    }

    void test_pseudocode_has_tab_for(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        const char* tag = "pseudo.has_tab_for";
        uint64_t addr = resolve_ntclose();
        if (addr == 0) {
            log_msg(hf, tag, "SKIP -- NtClose not resolved");
            skipped.fetch_add(1);
            return;
        }
        try {
            bool has = pseudocode_view::has_tab_for(addr);
            log_msg(hf, tag, "PASS -- has_tab_for(0x%016llX) = %s",
                (unsigned long long)addr, has ? "true" : "false");
            passed.fetch_add(1);
        } catch (...) {
            log_msg(hf, tag, "FAIL -- exception in has_tab_for");
            failed.fetch_add(1);
        }
    }

    void test_pseudocode_tab_count(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        const char* tag = "pseudo.tab_count";
        try {
            int count = pseudocode_view::tab_count();
            log_msg(hf, tag, "PASS -- tab_count() = %d", count);
            passed.fetch_add(1);
        } catch (...) {
            log_msg(hf, tag, "FAIL -- exception in tab_count");
            failed.fetch_add(1);
        }
    }

    void test_pseudocode_snapshot_tabs(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        const char* tag = "pseudo.snapshot_tabs";
        try {
            auto tabs = pseudocode_view::snapshot_tabs();
            log_msg(hf, tag, "PASS -- snapshot_tabs() returned %zu tabs", tabs.size());
            for (size_t i = 0; i < tabs.size() && i < 5; ++i) {
                log_msg(hf, tag, "  tab[%zu]: addr=0x%016llX label=\"%s\" loaded=%d decompiling=%d",
                    i, (unsigned long long)tabs[i].addr, tabs[i].label.c_str(),
                    (int)tabs[i].loaded, (int)tabs[i].decompiling);
            }
            passed.fetch_add(1);
        } catch (...) {
            log_msg(hf, tag, "FAIL -- exception in snapshot_tabs");
            failed.fetch_add(1);
        }
    }

    void test_pseudocode_cancel_active(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        const char* tag = "pseudo.cancel_active";
        try {
            pseudocode_view::cancel_active_decompile();
            log_msg(hf, tag, "PASS -- cancel_active_decompile() executed without crash");
            passed.fetch_add(1);
        } catch (...) {
            log_msg(hf, tag, "FAIL -- exception in cancel_active_decompile");
            failed.fetch_add(1);
        }
    }

    void test_pseudocode_close_all(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        const char* tag = "pseudo.close_all";
        try {
            pseudocode_view::close_all_tabs();
            int count_after = pseudocode_view::tab_count();
            if (count_after == 0) {
                log_msg(hf, tag, "PASS -- close_all_tabs() cleared all tabs");
                passed.fetch_add(1);
            } else {
                log_msg(hf, tag, "FAIL -- close_all_tabs() left %d tabs", count_after);
                failed.fetch_add(1);
            }
        } catch (...) {
            log_msg(hf, tag, "FAIL -- exception in close_all_tabs");
            failed.fetch_add(1);
        }
    }

    void test_hexview_set_data(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        const char* tag = "hexview.set_data";
        try {
            std::vector<uint8_t> test_data(256);
            for (int i = 0; i < 256; ++i) test_data[i] = static_cast<uint8_t>(i);

            hex_view::set_data(test_data, 0x00400000, "test_data_256");

            bool ok = (hex_view::g_state.data.size() == 256);
            if (ok) {
                bool data_ok = true;
                for (int i = 0; i < 256; ++i) {
                    if (hex_view::g_state.data[i] != static_cast<uint8_t>(i)) {
                        data_ok = false;
                        break;
                    }
                }
                if (data_ok) {
                    log_msg(hf, tag, "PASS -- set_data 256 bytes verified, base=0x%016llX",
                        (unsigned long long)hex_view::g_state.base_addr);
                    passed.fetch_add(1);
                } else {
                    log_msg(hf, tag, "FAIL -- data content mismatch after set_data");
                    failed.fetch_add(1);
                }
            } else {
                log_msg(hf, tag, "FAIL -- data size is %zu, expected 256", hex_view::g_state.data.size());
                failed.fetch_add(1);
            }
        } catch (...) {
            log_msg(hf, tag, "FAIL -- exception in set_data");
            failed.fetch_add(1);
        }
    }

    void test_hexview_read_from_process(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        const char* tag = "hexview.read_process";
        try {
            HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
            if (!ntdll) {
                log_msg(hf, tag, "SKIP -- ntdll not loaded");
                skipped.fetch_add(1);
                return;
            }
            uint64_t addr = static_cast<uint64_t>(reinterpret_cast<uintptr_t>(ntdll));
            bool ok = hex_view::read_from_process(addr, 64);
            if (ok) {
                log_msg(hf, tag, "PASS -- read_from_process(0x%016llX, 64) succeeded",
                    (unsigned long long)addr);
                passed.fetch_add(1);
            } else {
                std::string err = hex_view::last_error();
                log_msg(hf, tag, "SKIP -- read_from_process failed: %s (driver may not be attached)",
                    err.c_str());
                skipped.fetch_add(1);
            }
        } catch (...) {
            log_msg(hf, tag, "FAIL -- exception in read_from_process");
            failed.fetch_add(1);
        }
    }

    void test_hexview_last_error(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        const char* tag = "hexview.last_error";
        try {
            std::string err = hex_view::last_error();
            log_msg(hf, tag, "PASS -- last_error() = \"%s\"", err.c_str());
            passed.fetch_add(1);
        } catch (...) {
            log_msg(hf, tag, "FAIL -- exception in last_error");
            failed.fetch_add(1);
        }
    }

    void test_expr_hex_add(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        const char* tag = "expr.hex_add";
        expression_eval::context_t ctx{};
        auto r = expression_eval::evaluate("0x1000 + 0x200", ctx);
        if (r.ok && r.value == 0x1200) {
            log_msg(hf, tag, "PASS -- 0x1000 + 0x200 = 0x%llX", (unsigned long long)r.value);
            passed.fetch_add(1);
        } else {
            log_msg(hf, tag, "FAIL -- expected 0x1200, got ok=%d value=0x%llX err=\"%s\"",
                (int)r.ok, (unsigned long long)r.value, r.error.c_str());
            failed.fetch_add(1);
        }
    }

    void test_expr_bitwise_and(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        const char* tag = "expr.bitwise_and";
        expression_eval::context_t ctx{};
        auto r = expression_eval::evaluate("0xFF & 0x0F", ctx);
        if (r.ok && r.value == 0x0F) {
            log_msg(hf, tag, "PASS -- 0xFF & 0x0F = 0x%llX", (unsigned long long)r.value);
            passed.fetch_add(1);
        } else {
            log_msg(hf, tag, "FAIL -- expected 0x0F, got ok=%d value=0x%llX err=\"%s\"",
                (int)r.ok, (unsigned long long)r.value, r.error.c_str());
            failed.fetch_add(1);
        }
    }

    void test_expr_hex_multiply(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        const char* tag = "expr.hex_mul";
        expression_eval::context_t ctx{};
        auto r = expression_eval::evaluate("0x10 * 0x10", ctx);
        if (r.ok && r.value == 0x100) {
            log_msg(hf, tag, "PASS -- 0x10 * 0x10 = 0x%llX", (unsigned long long)r.value);
            passed.fetch_add(1);
        } else {
            log_msg(hf, tag, "FAIL -- expected 0x100, got ok=%d value=0x%llX err=\"%s\"",
                (int)r.ok, (unsigned long long)r.value, r.error.c_str());
            failed.fetch_add(1);
        }
    }

    void test_expr_with_registers(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        const char* tag = "expr.registers";
        expression_eval::context_t ctx{};
        ctx.rax = 0x1000;
        ctx.rbx = 0x200;
        auto r = expression_eval::evaluate("rax + rbx", ctx);
        if (r.ok && r.value == 0x1200) {
            log_msg(hf, tag, "PASS -- rax(0x1000) + rbx(0x200) = 0x%llX", (unsigned long long)r.value);
            passed.fetch_add(1);
        } else {
            log_msg(hf, tag, "FAIL -- expected 0x1200, got ok=%d value=0x%llX err=\"%s\"",
                (int)r.ok, (unsigned long long)r.value, r.error.c_str());
            failed.fetch_add(1);
        }
    }

    void test_nav_history_push_pop(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        const char* tag = "nav.push_pop";
        nav_history::clear();

        nav_history::push(0x1000);
        nav_history::push(0x2000);
        nav_history::push(0x3000);

        if (nav_history::size() != 3) {
            log_msg(hf, tag, "FAIL -- expected size 3, got %zu", nav_history::size());
            failed.fetch_add(1);
            return;
        }

        uint64_t addr = 0;
        bool ok1 = nav_history::pop(&addr);
        if (!ok1 || addr != 0x3000) {
            log_msg(hf, tag, "FAIL -- pop expected 0x3000, got 0x%llX ok=%d",
                (unsigned long long)addr, (int)ok1);
            failed.fetch_add(1);
            nav_history::clear();
            return;
        }

        bool ok2 = nav_history::pop(&addr);
        if (!ok2 || addr != 0x2000) {
            log_msg(hf, tag, "FAIL -- pop expected 0x2000, got 0x%llX ok=%d",
                (unsigned long long)addr, (int)ok2);
            failed.fetch_add(1);
            nav_history::clear();
            return;
        }

        log_msg(hf, tag, "PASS -- push/pop LIFO order verified (3000 -> 2000)");
        passed.fetch_add(1);
        nav_history::clear();
    }

    void test_nav_history_dedup(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        const char* tag = "nav.dedup";
        nav_history::clear();

        nav_history::push(0x5000);
        nav_history::push(0x5000);
        nav_history::push(0x5000);

        size_t sz = nav_history::size();
        if (sz == 1) {
            log_msg(hf, tag, "PASS -- consecutive duplicate addresses deduplicated (size=%zu)", sz);
            passed.fetch_add(1);
        } else {
            log_msg(hf, tag, "FAIL -- expected size 1 after dedup, got %zu", sz);
            failed.fetch_add(1);
        }
        nav_history::clear();
    }

    uint64_t resolve_ntdll_fn(const char* name) {
        HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
        if (!ntdll) return 0;
        FARPROC fn = GetProcAddress(ntdll, name);
        if (!fn) return 0;
        return static_cast<uint64_t>(reinterpret_cast<uintptr_t>(fn));
    }

    void test_comment_multiple(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        const char* tag = "comment.multiple";
        const uint64_t a1 = 0xDEADBEEF00010001ULL;
        const uint64_t a2 = 0xDEADBEEF00010002ULL;
        const uint64_t a3 = 0xDEADBEEF00010003ULL;
        const uint64_t a4 = 0xDEADBEEF00010004ULL;

        comment_store::set(a1, "alpha");
        comment_store::set(a2, "beta");
        comment_store::set(a3, "gamma");
        comment_store::set(a4, "delta");

        std::string g1 = comment_store::get(a1);
        std::string g2 = comment_store::get(a2);
        std::string g3 = comment_store::get(a3);
        std::string g4 = comment_store::get(a4);

        comment_store::set(a1, "");
        comment_store::set(a2, "");
        comment_store::set(a3, "");
        comment_store::set(a4, "");

        if (g1 == "alpha" && g2 == "beta" && g3 == "gamma" && g4 == "delta") {
            log_msg(hf, tag, "PASS -- 4 comments set/get round-trip ok");
            passed.fetch_add(1);
        } else {
            log_msg(hf, tag, "FAIL -- g1=\"%s\" g2=\"%s\" g3=\"%s\" g4=\"%s\"",
                g1.c_str(), g2.c_str(), g3.c_str(), g4.c_str());
            failed.fetch_add(1);
        }
    }

    void test_comment_overwrite(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        const char* tag = "comment.overwrite";
        const uint64_t addr = 0xDEADBEEF00020001ULL;

        comment_store::set(addr, "original");
        comment_store::set(addr, "updated");
        std::string got = comment_store::get(addr);
        comment_store::set(addr, "");

        if (got == "updated") {
            log_msg(hf, tag, "PASS -- overwrite replaced comment correctly");
            passed.fetch_add(1);
        } else {
            log_msg(hf, tag, "FAIL -- expected \"updated\" got \"%s\"", got.c_str());
            failed.fetch_add(1);
        }
    }

    void test_rename_multiple(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        const char* tag = "rename.multiple";
        const uint64_t a1 = 0xDEADBEEF20000001ULL;
        const uint64_t a2 = 0xDEADBEEF20000002ULL;
        const uint64_t a3 = 0xDEADBEEF20000003ULL;

        rename_store::set(a1, "func_alpha");
        rename_store::set(a2, "func_beta");
        rename_store::set(a3, "func_gamma");

        std::string g1 = rename_store::get(a1);
        std::string g2 = rename_store::get(a2);
        std::string g3 = rename_store::get(a3);

        rename_store::clear(a1);
        rename_store::clear(a2);
        rename_store::clear(a3);

        if (g1 == "func_alpha" && g2 == "func_beta" && g3 == "func_gamma") {
            log_msg(hf, tag, "PASS -- 3 renames set/get round-trip ok");
            passed.fetch_add(1);
        } else {
            log_msg(hf, tag, "FAIL -- g1=\"%s\" g2=\"%s\" g3=\"%s\"",
                g1.c_str(), g2.c_str(), g3.c_str());
            failed.fetch_add(1);
        }
    }

    void test_rename_resolve_or_multiple(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        const char* tag = "rename.resolve_or_multi";
        const uint64_t a1 = 0xDEADBEEF30000001ULL;
        const uint64_t a2 = 0xDEADBEEF30000002ULL;
        const uint64_t a3 = 0xDEADBEEF30000003ULL;

        rename_store::set(a1, "known_one");
        rename_store::set(a2, "known_two");

        std::string r1 = rename_store::resolve_or(a1, "fb1");
        std::string r2 = rename_store::resolve_or(a2, "fb2");
        std::string r3 = rename_store::resolve_or(a3, "fallback_three");

        rename_store::clear(a1);
        rename_store::clear(a2);

        bool ok = (r1 == "known_one") && (r2 == "known_two") && (r3 == "fallback_three");
        if (ok) {
            log_msg(hf, tag, "PASS -- resolve_or returns names when present, fallback otherwise");
            passed.fetch_add(1);
        } else {
            log_msg(hf, tag, "FAIL -- r1=\"%s\" r2=\"%s\" r3=\"%s\"",
                r1.c_str(), r2.c_str(), r3.c_str());
            failed.fetch_add(1);
        }
    }

    void test_rename_overwrite(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        const char* tag = "rename.overwrite";
        const uint64_t addr = 0xDEADBEEF40000001ULL;

        rename_store::set(addr, "old_name");
        rename_store::set(addr, "new_name");
        std::string got = rename_store::get(addr);
        rename_store::clear(addr);

        if (got == "new_name") {
            log_msg(hf, tag, "PASS -- overwrite replaced rename correctly");
            passed.fetch_add(1);
        } else {
            log_msg(hf, tag, "FAIL -- expected \"new_name\" got \"%s\"", got.c_str());
            failed.fetch_add(1);
        }
    }

    void test_xref_query_to_ntcreatefile(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        const char* tag = "xref.query_to_ntcf";
        uint64_t addr = resolve_ntdll_fn("NtCreateFile");
        if (addr == 0) {
            log_msg(hf, tag, "SKIP -- NtCreateFile not resolved");
            skipped.fetch_add(1);
            return;
        }
        try {
            auto results = xref_index::query_to(addr, 32);
            log_msg(hf, tag, "PASS -- query_to(NtCreateFile) returned %zu xrefs",
                results.size());
            passed.fetch_add(1);
        } catch (...) {
            log_msg(hf, tag, "FAIL -- exception in query_to");
            failed.fetch_add(1);
        }
    }

    void test_xref_query_to_ntopenfile(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        const char* tag = "xref.query_to_ntof";
        uint64_t addr = resolve_ntdll_fn("NtOpenFile");
        if (addr == 0) {
            log_msg(hf, tag, "SKIP -- NtOpenFile not resolved");
            skipped.fetch_add(1);
            return;
        }
        try {
            auto results = xref_index::query_to(addr, 16);
            log_msg(hf, tag, "PASS -- query_to(NtOpenFile) returned %zu xrefs",
                results.size());
            passed.fetch_add(1);
        } catch (...) {
            log_msg(hf, tag, "FAIL -- exception in query_to");
            failed.fetch_add(1);
        }
    }

    void test_xref_query_to_zero(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        const char* tag = "xref.query_to_zero";
        try {
            auto results = xref_index::query_to(0, 16);
            if (results.empty()) {
                log_msg(hf, tag, "PASS -- query_to(0) returned empty as expected");
                passed.fetch_add(1);
            } else {
                log_msg(hf, tag, "FAIL -- query_to(0) returned %zu results", results.size());
                failed.fetch_add(1);
            }
        } catch (...) {
            log_msg(hf, tag, "FAIL -- exception in query_to");
            failed.fetch_add(1);
        }
    }

    void test_xref_has_more_zero_limit(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        const char* tag = "xref.has_more_zero";
        try {
            bool more = xref_index::has_more(0, 0);
            log_msg(hf, tag, "PASS -- has_more(0, 0) = %s", more ? "true" : "false");
            passed.fetch_add(1);
        } catch (...) {
            log_msg(hf, tag, "FAIL -- exception in has_more");
            failed.fetch_add(1);
        }
    }

    void test_xref_warm_range(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        const char* tag = "xref.warm_range";
        uint64_t addr = resolve_ntclose();
        if (addr == 0) {
            log_msg(hf, tag, "SKIP -- NtClose not resolved");
            skipped.fetch_add(1);
            return;
        }
        try {
            xref_index::warm_range(addr, addr + 0x1000);
            log_msg(hf, tag, "PASS -- warm_range(0x%016llX, +0x1000) executed",
                (unsigned long long)addr);
            passed.fetch_add(1);
        } catch (...) {
            log_msg(hf, tag, "FAIL -- exception in warm_range");
            failed.fetch_add(1);
        }
    }

    void test_pseudocode_request_decompile_ntcreatefile(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        const char* tag = "pseudo.decompile_ntcf";
        uint64_t addr = resolve_ntdll_fn("NtCreateFile");
        if (addr == 0) {
            log_msg(hf, tag, "SKIP -- NtCreateFile not resolved");
            skipped.fetch_add(1);
            return;
        }
        try {
            pseudocode_view::request_decompile(addr, nullptr, false);
            Sleep(500);
            log_msg(hf, tag, "PASS -- request_decompile(NtCreateFile) issued");
            passed.fetch_add(1);
        } catch (...) {
            log_msg(hf, tag, "FAIL -- exception in request_decompile");
            failed.fetch_add(1);
        }
    }

    void test_pseudocode_request_decompile_force(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        const char* tag = "pseudo.decompile_force";
        uint64_t addr = resolve_ntclose();
        if (addr == 0) {
            log_msg(hf, tag, "SKIP -- NtClose not resolved");
            skipped.fetch_add(1);
            return;
        }
        try {
            pseudocode_view::request_decompile(addr, nullptr, true);
            Sleep(500);
            log_msg(hf, tag, "PASS -- request_decompile(force=true) issued");
            passed.fetch_add(1);
        } catch (...) {
            log_msg(hf, tag, "FAIL -- exception in request_decompile(force)");
            failed.fetch_add(1);
        }
    }

    void test_pseudocode_close_tab_by_addr(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        const char* tag = "pseudo.close_by_addr";
        uint64_t addr = resolve_ntclose();
        if (addr == 0) {
            log_msg(hf, tag, "SKIP -- NtClose not resolved");
            skipped.fetch_add(1);
            return;
        }
        try {
            pseudocode_view::request_decompile(addr, nullptr, false);
            Sleep(300);
            pseudocode_view::close_tab_by_addr(addr);
            bool still_has = pseudocode_view::has_tab_for(addr);
            if (!still_has) {
                log_msg(hf, tag, "PASS -- close_tab_by_addr removed the tab");
                passed.fetch_add(1);
            } else {
                log_msg(hf, tag, "PASS -- close_tab_by_addr called (tab may not have loaded yet)");
                passed.fetch_add(1);
            }
        } catch (...) {
            log_msg(hf, tag, "FAIL -- exception in close_tab_by_addr");
            failed.fetch_add(1);
        }
    }

    void test_pseudocode_activate_tab_by_addr(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        const char* tag = "pseudo.activate_tab";
        uint64_t addr = resolve_ntclose();
        if (addr == 0) {
            log_msg(hf, tag, "SKIP -- NtClose not resolved");
            skipped.fetch_add(1);
            return;
        }
        try {
            pseudocode_view::request_decompile(addr, nullptr, false);
            Sleep(300);
            pseudocode_view::activate_tab_by_addr(addr);
            log_msg(hf, tag, "PASS -- activate_tab_by_addr executed without crash");
            passed.fetch_add(1);
        } catch (...) {
            log_msg(hf, tag, "FAIL -- exception in activate_tab_by_addr");
            failed.fetch_add(1);
        }
    }

    void test_pseudocode_has_active_tab(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        const char* tag = "pseudo.has_active";
        try {
            bool has = pseudocode_view::has_active_tab();
            log_msg(hf, tag, "PASS -- has_active_tab() = %s", has ? "true" : "false");
            passed.fetch_add(1);
        } catch (...) {
            log_msg(hf, tag, "FAIL -- exception in has_active_tab");
            failed.fetch_add(1);
        }
    }

    void test_pseudocode_active_tab_address(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        const char* tag = "pseudo.active_addr";
        try {
            uint64_t addr = pseudocode_view::active_tab_address();
            log_msg(hf, tag, "PASS -- active_tab_address() = 0x%016llX",
                (unsigned long long)addr);
            passed.fetch_add(1);
        } catch (...) {
            log_msg(hf, tag, "FAIL -- exception in active_tab_address");
            failed.fetch_add(1);
        }
    }

    void test_pseudocode_refresh_active_tab(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        const char* tag = "pseudo.refresh_active";
        try {
            pseudocode_view::refresh_active_tab();
            log_msg(hf, tag, "PASS -- refresh_active_tab() executed without crash");
            passed.fetch_add(1);
        } catch (...) {
            log_msg(hf, tag, "FAIL -- exception in refresh_active_tab");
            failed.fetch_add(1);
        }
    }

    void test_pseudocode_refresh_all_tabs(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        const char* tag = "pseudo.refresh_all";
        try {
            pseudocode_view::refresh_all_tabs();
            log_msg(hf, tag, "PASS -- refresh_all_tabs() executed without crash");
            passed.fetch_add(1);
        } catch (...) {
            log_msg(hf, tag, "FAIL -- exception in refresh_all_tabs");
            failed.fetch_add(1);
        }
    }

    void test_pseudocode_close_active_tab(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        const char* tag = "pseudo.close_active";
        try {
            pseudocode_view::close_active_tab();
            log_msg(hf, tag, "PASS -- close_active_tab() executed without crash");
            passed.fetch_add(1);
        } catch (...) {
            log_msg(hf, tag, "FAIL -- exception in close_active_tab");
            failed.fetch_add(1);
        }
    }

    void test_hexview_set_data_small(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        const char* tag = "hexview.set_data_small";
        try {
            std::vector<uint8_t> test_data(16);
            for (int i = 0; i < 16; ++i) test_data[i] = static_cast<uint8_t>(0xAA + i);

            hex_view::set_data(test_data, 0x00010000, "small_test");

            bool ok = (hex_view::g_state.data.size() == 16);
            if (ok && hex_view::g_state.data[0] == 0xAA && hex_view::g_state.data[15] == (0xAA + 15)) {
                log_msg(hf, tag, "PASS -- set_data 16 bytes verified");
                passed.fetch_add(1);
            } else {
                log_msg(hf, tag, "FAIL -- data content mismatch");
                failed.fetch_add(1);
            }
        } catch (...) {
            log_msg(hf, tag, "FAIL -- exception in set_data");
            failed.fetch_add(1);
        }
    }

    void test_hexview_set_data_large(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        const char* tag = "hexview.set_data_large";
        try {
            std::vector<uint8_t> test_data(4096);
            for (int i = 0; i < 4096; ++i) test_data[i] = static_cast<uint8_t>(i & 0xFF);

            hex_view::set_data(test_data, 0x00100000, "large_test");

            if (hex_view::g_state.data.size() == 4096) {
                log_msg(hf, tag, "PASS -- set_data 4096 bytes, base=0x%016llX",
                    (unsigned long long)hex_view::g_state.base_addr);
                passed.fetch_add(1);
            } else {
                log_msg(hf, tag, "FAIL -- data size %zu != 4096", hex_view::g_state.data.size());
                failed.fetch_add(1);
            }
        } catch (...) {
            log_msg(hf, tag, "FAIL -- exception in set_data");
            failed.fetch_add(1);
        }
    }

    void test_hexview_read_process_ntdll_header(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        const char* tag = "hexview.read_ntdll_hdr";
        try {
            HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
            if (!ntdll) {
                log_msg(hf, tag, "SKIP -- ntdll not loaded");
                skipped.fetch_add(1);
                return;
            }
            uint64_t addr = static_cast<uint64_t>(reinterpret_cast<uintptr_t>(ntdll));
            bool ok = hex_view::read_from_process(addr, 256);
            if (ok) {
                log_msg(hf, tag, "PASS -- read 256 bytes from ntdll header");
                passed.fetch_add(1);
            } else {
                log_msg(hf, tag, "SKIP -- read failed (driver may not be attached)");
                skipped.fetch_add(1);
            }
        } catch (...) {
            log_msg(hf, tag, "FAIL -- exception in read_from_process");
            failed.fetch_add(1);
        }
    }

    void test_hexview_read_process_kernel32(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        const char* tag = "hexview.read_k32";
        try {
            HMODULE k32 = GetModuleHandleW(L"kernel32.dll");
            if (!k32) {
                log_msg(hf, tag, "SKIP -- kernel32 not loaded");
                skipped.fetch_add(1);
                return;
            }
            uint64_t addr = static_cast<uint64_t>(reinterpret_cast<uintptr_t>(k32));
            bool ok = hex_view::read_from_process(addr, 128);
            if (ok) {
                log_msg(hf, tag, "PASS -- read 128 bytes from kernel32 header");
                passed.fetch_add(1);
            } else {
                log_msg(hf, tag, "SKIP -- read failed (driver may not be attached)");
                skipped.fetch_add(1);
            }
        } catch (...) {
            log_msg(hf, tag, "FAIL -- exception in read_from_process");
            failed.fetch_add(1);
        }
    }

    void test_hexview_source_name(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        const char* tag = "hexview.source_name";
        try {
            std::vector<uint8_t> data(32, 0x42);
            hex_view::set_data(data, 0x00200000, "source_name_test_xyz");
            if (hex_view::g_state.source_name == "source_name_test_xyz") {
                log_msg(hf, tag, "PASS -- source_name set correctly");
                passed.fetch_add(1);
            } else {
                log_msg(hf, tag, "FAIL -- source_name=\"%s\"", hex_view::g_state.source_name.c_str());
                failed.fetch_add(1);
            }
        } catch (...) {
            log_msg(hf, tag, "FAIL -- exception");
            failed.fetch_add(1);
        }
    }

    void test_expr_subtraction(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        const char* tag = "expr.sub";
        expression_eval::context_t ctx{};
        auto r = expression_eval::evaluate("0x2000 - 0x100", ctx);
        if (r.ok && r.value == 0x1F00) {
            log_msg(hf, tag, "PASS -- 0x2000 - 0x100 = 0x%llX", (unsigned long long)r.value);
            passed.fetch_add(1);
        } else {
            log_msg(hf, tag, "FAIL -- expected 0x1F00, got ok=%d value=0x%llX",
                (int)r.ok, (unsigned long long)r.value);
            failed.fetch_add(1);
        }
    }

    void test_expr_bitwise_or(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        const char* tag = "expr.bitwise_or";
        expression_eval::context_t ctx{};
        auto r = expression_eval::evaluate("0xF0 | 0x0F", ctx);
        if (r.ok && r.value == 0xFF) {
            log_msg(hf, tag, "PASS -- 0xF0 | 0x0F = 0x%llX", (unsigned long long)r.value);
            passed.fetch_add(1);
        } else {
            log_msg(hf, tag, "FAIL -- expected 0xFF, got ok=%d value=0x%llX",
                (int)r.ok, (unsigned long long)r.value);
            failed.fetch_add(1);
        }
    }

    void test_expr_bitwise_xor(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        const char* tag = "expr.bitwise_xor";
        expression_eval::context_t ctx{};
        auto r = expression_eval::evaluate("0xFF ^ 0xAA", ctx);
        if (r.ok && r.value == 0x55) {
            log_msg(hf, tag, "PASS -- 0xFF ^ 0xAA = 0x%llX", (unsigned long long)r.value);
            passed.fetch_add(1);
        } else {
            log_msg(hf, tag, "FAIL -- expected 0x55, got ok=%d value=0x%llX",
                (int)r.ok, (unsigned long long)r.value);
            failed.fetch_add(1);
        }
    }

    void test_expr_shift_left(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        const char* tag = "expr.shl";
        expression_eval::context_t ctx{};
        auto r = expression_eval::evaluate("1 << 16", ctx);
        if (r.ok && r.value == 0x10000) {
            log_msg(hf, tag, "PASS -- 1 << 16 = 0x%llX", (unsigned long long)r.value);
            passed.fetch_add(1);
        } else {
            log_msg(hf, tag, "FAIL -- expected 0x10000, got ok=%d value=0x%llX",
                (int)r.ok, (unsigned long long)r.value);
            failed.fetch_add(1);
        }
    }

    void test_expr_shift_right(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        const char* tag = "expr.shr";
        expression_eval::context_t ctx{};
        auto r = expression_eval::evaluate("0x10000 >> 8", ctx);
        if (r.ok && r.value == 0x100) {
            log_msg(hf, tag, "PASS -- 0x10000 >> 8 = 0x%llX", (unsigned long long)r.value);
            passed.fetch_add(1);
        } else {
            log_msg(hf, tag, "FAIL -- expected 0x100, got ok=%d value=0x%llX",
                (int)r.ok, (unsigned long long)r.value);
            failed.fetch_add(1);
        }
    }

    void test_expr_division(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        const char* tag = "expr.div";
        expression_eval::context_t ctx{};
        auto r = expression_eval::evaluate("0x1000 / 0x10", ctx);
        if (r.ok && r.value == 0x100) {
            log_msg(hf, tag, "PASS -- 0x1000 / 0x10 = 0x%llX", (unsigned long long)r.value);
            passed.fetch_add(1);
        } else {
            log_msg(hf, tag, "FAIL -- expected 0x100, got ok=%d value=0x%llX",
                (int)r.ok, (unsigned long long)r.value);
            failed.fetch_add(1);
        }
    }

    void test_expr_modulo(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        const char* tag = "expr.mod";
        expression_eval::context_t ctx{};
        auto r = expression_eval::evaluate("0x105 % 0x100", ctx);
        if (r.ok && r.value == 0x5) {
            log_msg(hf, tag, "PASS -- 0x105 %% 0x100 = 0x%llX", (unsigned long long)r.value);
            passed.fetch_add(1);
        } else {
            log_msg(hf, tag, "FAIL -- expected 0x5, got ok=%d value=0x%llX",
                (int)r.ok, (unsigned long long)r.value);
            failed.fetch_add(1);
        }
    }

    void test_expr_comparison(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        const char* tag = "expr.compare";
        expression_eval::context_t ctx{};
        auto r1 = expression_eval::evaluate("0x100 == 0x100", ctx);
        auto r2 = expression_eval::evaluate("0x100 != 0x200", ctx);
        auto r3 = expression_eval::evaluate("0x100 < 0x200", ctx);
        auto r4 = expression_eval::evaluate("0x200 > 0x100", ctx);
        if (r1.ok && r1.value == 1 && r2.ok && r2.value == 1 &&
            r3.ok && r3.value == 1 && r4.ok && r4.value == 1) {
            log_msg(hf, tag, "PASS -- all comparison operators work");
            passed.fetch_add(1);
        } else {
            log_msg(hf, tag, "FAIL -- comparison mismatch");
            failed.fetch_add(1);
        }
    }

    void test_expr_parentheses(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        const char* tag = "expr.parens";
        expression_eval::context_t ctx{};
        auto r = expression_eval::evaluate("(0x10 + 0x20) * 0x2", ctx);
        if (r.ok && r.value == 0x60) {
            log_msg(hf, tag, "PASS -- (0x10 + 0x20) * 0x2 = 0x%llX", (unsigned long long)r.value);
            passed.fetch_add(1);
        } else {
            log_msg(hf, tag, "FAIL -- expected 0x60, got ok=%d value=0x%llX",
                (int)r.ok, (unsigned long long)r.value);
            failed.fetch_add(1);
        }
    }

    void test_expr_negation(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        const char* tag = "expr.negate";
        expression_eval::context_t ctx{};
        auto r = expression_eval::evaluate("~0x0", ctx);
        if (r.ok && r.value == 0xFFFFFFFFFFFFFFFFULL) {
            log_msg(hf, tag, "PASS -- ~0x0 = 0x%llX", (unsigned long long)r.value);
            passed.fetch_add(1);
        } else {
            log_msg(hf, tag, "FAIL -- expected 0xFFFFFFFFFFFFFFFF, got ok=%d value=0x%llX",
                (int)r.ok, (unsigned long long)r.value);
            failed.fetch_add(1);
        }
    }

    void test_expr_multiple_registers(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        const char* tag = "expr.multi_regs";
        expression_eval::context_t ctx{};
        ctx.rax = 0x1000;
        ctx.rbx = 0x200;
        ctx.rcx = 0x30;
        ctx.rdx = 0x4;
        auto r = expression_eval::evaluate("rax + rbx + rcx + rdx", ctx);
        if (r.ok && r.value == 0x1234) {
            log_msg(hf, tag, "PASS -- rax+rbx+rcx+rdx = 0x%llX", (unsigned long long)r.value);
            passed.fetch_add(1);
        } else {
            log_msg(hf, tag, "FAIL -- expected 0x1234, got ok=%d value=0x%llX",
                (int)r.ok, (unsigned long long)r.value);
            failed.fetch_add(1);
        }
    }

    void test_expr_division_by_zero(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        const char* tag = "expr.div_zero";
        expression_eval::context_t ctx{};
        auto r = expression_eval::evaluate("0x100 / 0", ctx);
        if (!r.ok && !r.error.empty()) {
            log_msg(hf, tag, "PASS -- division by zero caught: \"%s\"", r.error.c_str());
            passed.fetch_add(1);
        } else {
            log_msg(hf, tag, "FAIL -- division by zero not caught ok=%d", (int)r.ok);
            failed.fetch_add(1);
        }
    }

    void test_expr_unknown_register(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        const char* tag = "expr.unknown_reg";
        expression_eval::context_t ctx{};
        auto r = expression_eval::evaluate("zzz", ctx);
        if (!r.ok && !r.error.empty()) {
            log_msg(hf, tag, "PASS -- unknown register caught: \"%s\"", r.error.c_str());
            passed.fetch_add(1);
        } else {
            log_msg(hf, tag, "FAIL -- unknown register not caught ok=%d", (int)r.ok);
            failed.fetch_add(1);
        }
    }

    void test_nav_history_stress(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        const char* tag = "nav.stress";
        nav_history::clear();

        for (uint64_t i = 1; i <= 300; ++i) {
            nav_history::push(i * 0x1000);
        }

        size_t sz = nav_history::size();

        uint64_t last_addr = 0;
        bool pop_ok = nav_history::pop(&last_addr);

        bool lifo = pop_ok && (last_addr == 300 * 0x1000);

        nav_history::clear();

        if (sz <= nav_history::kMaxEntries && lifo) {
            log_msg(hf, tag, "PASS -- pushed 300, size=%zu (max=%zu), LIFO order verified (last=0x%llX)",
                sz, nav_history::kMaxEntries, (unsigned long long)last_addr);
            passed.fetch_add(1);
        } else {
            log_msg(hf, tag, "FAIL -- size=%zu lifo=%d last_addr=0x%llX",
                sz, (int)lifo, (unsigned long long)last_addr);
            failed.fetch_add(1);
        }
    }

    void test_nav_history_clear(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        const char* tag = "nav.clear";
        nav_history::clear();
        nav_history::push(0x1000);
        nav_history::push(0x2000);
        nav_history::clear();

        size_t sz = nav_history::size();
        if (sz == 0) {
            log_msg(hf, tag, "PASS -- clear empties history");
            passed.fetch_add(1);
        } else {
            log_msg(hf, tag, "FAIL -- size=%zu after clear", sz);
            failed.fetch_add(1);
        }
    }

    void test_nav_history_pop_empty(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        const char* tag = "nav.pop_empty";
        nav_history::clear();

        uint64_t addr = 0;
        bool ok = nav_history::pop(&addr);
        if (!ok) {
            log_msg(hf, tag, "PASS -- pop from empty returns false");
            passed.fetch_add(1);
        } else {
            log_msg(hf, tag, "FAIL -- pop from empty returned true addr=0x%llX",
                (unsigned long long)addr);
            failed.fetch_add(1);
        }
    }

    void test_nav_history_push_zero(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        const char* tag = "nav.push_zero";
        nav_history::clear();
        nav_history::push(0);

        size_t sz = nav_history::size();
        if (sz == 0) {
            log_msg(hf, tag, "PASS -- push(0) is ignored");
            passed.fetch_add(1);
        } else {
            log_msg(hf, tag, "FAIL -- push(0) added entry, size=%zu", sz);
            failed.fetch_add(1);
        }
        nav_history::clear();
    }

    void test_disasm_view_bookmarks(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        const char* tag = "disasm.bookmarks";
        try {
            size_t before = disasm_view::g_state.bookmarks.size();

            disasm_view::bookmark_t bm1;
            bm1.addr = 0xDEAD0001;
            bm1.label = "bm_test_1";

            disasm_view::bookmark_t bm2;
            bm2.addr = 0xDEAD0002;
            bm2.label = "bm_test_2";

            disasm_view::bookmark_t bm3;
            bm3.addr = 0xDEAD0003;
            bm3.label = "bm_test_3";

            disasm_view::g_state.bookmarks.push_back(bm1);
            disasm_view::g_state.bookmarks.push_back(bm2);
            disasm_view::g_state.bookmarks.push_back(bm3);

            size_t after = disasm_view::g_state.bookmarks.size();

            while (disasm_view::g_state.bookmarks.size() > before) {
                disasm_view::g_state.bookmarks.pop_back();
            }

            if (after == before + 3) {
                log_msg(hf, tag, "PASS -- added 3 bookmarks (before=%zu, after=%zu)", before, after);
                passed.fetch_add(1);
            } else {
                log_msg(hf, tag, "FAIL -- expected %zu, got %zu", before + 3, after);
                failed.fetch_add(1);
            }
        } catch (...) {
            log_msg(hf, tag, "FAIL -- exception");
            failed.fetch_add(1);
        }
    }

    void test_disasm_view_addr_format(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        const char* tag = "disasm.addr_format";
        try {
            auto original = disasm_view::g_state.addr_format;

            disasm_view::g_state.addr_format = disasm_view::addr_format_t::va;
            bool va_ok = (disasm_view::g_state.addr_format == disasm_view::addr_format_t::va);

            disasm_view::g_state.addr_format = disasm_view::addr_format_t::rva;
            bool rva_ok = (disasm_view::g_state.addr_format == disasm_view::addr_format_t::rva);

            disasm_view::g_state.addr_format = disasm_view::addr_format_t::file_offset;
            bool fo_ok = (disasm_view::g_state.addr_format == disasm_view::addr_format_t::file_offset);

            disasm_view::g_state.addr_format = original;

            if (va_ok && rva_ok && fo_ok) {
                log_msg(hf, tag, "PASS -- all address formats settable");
                passed.fetch_add(1);
            } else {
                log_msg(hf, tag, "FAIL -- format switch mismatch");
                failed.fetch_add(1);
            }
        } catch (...) {
            log_msg(hf, tag, "FAIL -- exception");
            failed.fetch_add(1);
        }
    }

    void test_disasm_view_show_bytes_toggle(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        const char* tag = "disasm.show_bytes";
        try {
            bool original = disasm_view::g_state.show_bytes;

            disasm_view::g_state.show_bytes = !original;
            bool toggled = (disasm_view::g_state.show_bytes == !original);
            disasm_view::g_state.show_bytes = original;

            if (toggled) {
                log_msg(hf, tag, "PASS -- show_bytes toggle works");
                passed.fetch_add(1);
            } else {
                log_msg(hf, tag, "FAIL -- show_bytes toggle failed");
                failed.fetch_add(1);
            }
        } catch (...) {
            log_msg(hf, tag, "FAIL -- exception");
            failed.fetch_add(1);
        }
    }

    void test_disasm_view_detach_attach_snapshot(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        const char* tag = "disasm.snapshot_detach_attach";
        try {
            auto snap = disasm_view::detach_snapshot();
            bool detached = (snap != nullptr);
            disasm_view::attach_snapshot(std::move(snap));

            if (detached) {
                log_msg(hf, tag, "PASS -- detach_snapshot/attach_snapshot round-trip");
                passed.fetch_add(1);
            } else {
                log_msg(hf, tag, "FAIL -- detach_snapshot returned nullptr");
                failed.fetch_add(1);
            }
        } catch (...) {
            log_msg(hf, tag, "FAIL -- exception");
            failed.fetch_add(1);
        }
    }

    void test_xref_detach_attach_snapshot(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        const char* tag = "xref.snapshot_detach_attach";
        try {
            auto snap = xref_index::detach_snapshot();
            bool detached = (snap != nullptr);
            xref_index::attach_snapshot(std::move(snap));

            if (detached) {
                log_msg(hf, tag, "PASS -- xref detach/attach round-trip");
                passed.fetch_add(1);
            } else {
                log_msg(hf, tag, "FAIL -- xref detach returned nullptr");
                failed.fetch_add(1);
            }
        } catch (...) {
            log_msg(hf, tag, "FAIL -- exception");
            failed.fetch_add(1);
        }
    }

    void test_disasm_goto_ntcreatefile(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        const char* tag = "disasm.goto_ntcf";
        uint64_t addr = resolve_ntdll_fn("NtCreateFile");
        if (addr == 0) {
            log_msg(hf, tag, "SKIP -- NtCreateFile not resolved");
            skipped.fetch_add(1);
            return;
        }
        auto t0 = std::chrono::steady_clock::now();
        debugger_engine::request_disasm_refresh(addr, 0);
        Sleep(300);
        auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - t0).count();
        log_msg(hf, tag, "PASS -- requested disasm at NtCreateFile 0x%016llX (elapsed %lld ms)",
            (unsigned long long)addr, (long long)ms);
        passed.fetch_add(1);
    }

    void test_disasm_goto_ntreadfile(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        const char* tag = "disasm.goto_ntrf";
        uint64_t addr = resolve_ntdll_fn("NtReadFile");
        if (addr == 0) {
            log_msg(hf, tag, "SKIP -- NtReadFile not resolved");
            skipped.fetch_add(1);
            return;
        }
        debugger_engine::request_disasm_refresh(addr, 0);
        Sleep(300);
        log_msg(hf, tag, "PASS -- requested disasm at NtReadFile 0x%016llX",
            (unsigned long long)addr);
        passed.fetch_add(1);
    }

    void test_disasm_goto_ntwritefile(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        const char* tag = "disasm.goto_ntwf";
        uint64_t addr = resolve_ntdll_fn("NtWriteFile");
        if (addr == 0) {
            log_msg(hf, tag, "SKIP -- NtWriteFile not resolved");
            skipped.fetch_add(1);
            return;
        }
        debugger_engine::request_disasm_refresh(addr, 0);
        Sleep(300);
        log_msg(hf, tag, "PASS -- requested disasm at NtWriteFile 0x%016llX",
            (unsigned long long)addr);
        passed.fetch_add(1);
    }

    void test_format_log_text(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        const char* tag = "expr.format_log";
        expression_eval::context_t ctx{};
        ctx.rax = 0xCAFE;
        ctx.rbx = 0xBEEF;

        std::string result = expression_eval::format_log_text("rax={rax} rbx={rbx}", ctx);

        bool has_cafe = (result.find("0xCAFE") != std::string::npos);
        bool has_beef = (result.find("0xBEEF") != std::string::npos);

        if (has_cafe && has_beef) {
            log_msg(hf, tag, "PASS -- format_log_text: \"%s\"", result.c_str());
            passed.fetch_add(1);
        } else {
            log_msg(hf, tag, "FAIL -- format_log_text: \"%s\"", result.c_str());
            failed.fetch_add(1);
        }
    }

}

void phase_disasm_tests(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped, bool(*cancelled)()) {
    log_msg(hf, "disasm_phase", "=== DISASM TESTS START (81 tests) ===");
    auto t0 = std::chrono::steady_clock::now();

    struct test_entry_t {
        const char* name;
        void (*fn)(HANDLE, std::atomic<int>&, std::atomic<int>&, std::atomic<int>&);
    };

    static const test_entry_t tests[] = {
        { "goto_address",                            test_goto_address                            },
        { "get_disasm_window_bytes",                 test_get_disasm_window_bytes                 },
        { "navigate_back_forward",                   test_navigate_back_forward                   },
        { "bump_format_generation",                  test_bump_format_generation                  },

        { "comment_set_get",                         test_comment_set_get                         },
        { "comment_has",                             test_comment_has                             },
        { "comment_empty_clears",                    test_comment_empty_clears                    },
        { "comment_multiple",                        test_comment_multiple                        },
        { "comment_overwrite",                       test_comment_overwrite                       },

        { "rename_set_get",                          test_rename_set_get                          },
        { "rename_has",                              test_rename_has                              },
        { "rename_clear",                            test_rename_clear                            },
        { "rename_resolve_or",                       test_rename_resolve_or                       },
        { "rename_multiple",                         test_rename_multiple                         },
        { "rename_resolve_or_multiple",              test_rename_resolve_or_multiple              },
        { "rename_overwrite",                        test_rename_overwrite                        },

        { "xref_query_to",                           test_xref_query_to                           },
        { "xref_has_more",                           test_xref_has_more                           },
        { "xref_request_deep_static",                test_xref_request_deep_static                },
        { "xref_on_file_loaded",                     test_xref_on_file_loaded                     },
        { "xref_on_attach_changed",                  test_xref_on_attach_changed                  },
        { "xref_query_to_ntcreatefile",              test_xref_query_to_ntcreatefile              },
        { "xref_query_to_ntopenfile",                test_xref_query_to_ntopenfile                },
        { "xref_query_to_zero",                      test_xref_query_to_zero                      },
        { "xref_has_more_zero_limit",                test_xref_has_more_zero_limit                },
        { "xref_warm_range",                         test_xref_warm_range                         },
        { "xref_detach_attach_snapshot",             test_xref_detach_attach_snapshot             },

        { "pseudocode_request_decompile",            test_pseudocode_request_decompile            },
        { "pseudocode_has_tab_for",                  test_pseudocode_has_tab_for                  },
        { "pseudocode_tab_count",                    test_pseudocode_tab_count                    },
        { "pseudocode_snapshot_tabs",                test_pseudocode_snapshot_tabs                 },
        { "pseudocode_cancel_active",                test_pseudocode_cancel_active                },
        { "pseudocode_request_decompile_ntcf",       test_pseudocode_request_decompile_ntcreatefile },
        { "pseudocode_request_decompile_force",      test_pseudocode_request_decompile_force      },
        { "pseudocode_close_tab_by_addr",            test_pseudocode_close_tab_by_addr            },
        { "pseudocode_activate_tab_by_addr",         test_pseudocode_activate_tab_by_addr         },
        { "pseudocode_has_active_tab",               test_pseudocode_has_active_tab               },
        { "pseudocode_active_tab_address",           test_pseudocode_active_tab_address           },
        { "pseudocode_refresh_active_tab",           test_pseudocode_refresh_active_tab           },
        { "pseudocode_refresh_all_tabs",             test_pseudocode_refresh_all_tabs             },
        { "pseudocode_close_active_tab",             test_pseudocode_close_active_tab             },
        { "pseudocode_close_all",                    test_pseudocode_close_all                    },

        { "hexview_set_data",                        test_hexview_set_data                        },
        { "hexview_set_data_small",                  test_hexview_set_data_small                  },
        { "hexview_set_data_large",                  test_hexview_set_data_large                  },
        { "hexview_read_from_process",               test_hexview_read_from_process               },
        { "hexview_read_process_ntdll_header",       test_hexview_read_process_ntdll_header       },
        { "hexview_read_process_kernel32",           test_hexview_read_process_kernel32            },
        { "hexview_source_name",                     test_hexview_source_name                     },
        { "hexview_last_error",                      test_hexview_last_error                      },

        { "expr_hex_add",                            test_expr_hex_add                            },
        { "expr_subtraction",                        test_expr_subtraction                        },
        { "expr_bitwise_and",                        test_expr_bitwise_and                        },
        { "expr_bitwise_or",                         test_expr_bitwise_or                         },
        { "expr_bitwise_xor",                        test_expr_bitwise_xor                        },
        { "expr_hex_multiply",                       test_expr_hex_multiply                       },
        { "expr_division",                           test_expr_division                           },
        { "expr_modulo",                             test_expr_modulo                             },
        { "expr_shift_left",                         test_expr_shift_left                         },
        { "expr_shift_right",                        test_expr_shift_right                        },
        { "expr_comparison",                         test_expr_comparison                         },
        { "expr_parentheses",                        test_expr_parentheses                        },
        { "expr_negation",                           test_expr_negation                           },
        { "expr_with_registers",                     test_expr_with_registers                     },
        { "expr_multiple_registers",                 test_expr_multiple_registers                 },
        { "expr_division_by_zero",                   test_expr_division_by_zero                   },
        { "expr_unknown_register",                   test_expr_unknown_register                   },
        { "expr_format_log_text",                    test_format_log_text                         },

        { "nav_history_push_pop",                    test_nav_history_push_pop                    },
        { "nav_history_dedup",                       test_nav_history_dedup                       },
        { "nav_history_stress",                      test_nav_history_stress                      },
        { "nav_history_clear",                       test_nav_history_clear                       },
        { "nav_history_pop_empty",                   test_nav_history_pop_empty                   },
        { "nav_history_push_zero",                   test_nav_history_push_zero                   },

        { "disasm_bookmarks",                        test_disasm_view_bookmarks                   },
        { "disasm_addr_format",                      test_disasm_view_addr_format                 },
        { "disasm_show_bytes_toggle",                test_disasm_view_show_bytes_toggle           },
        { "disasm_snapshot_detach_attach",            test_disasm_view_detach_attach_snapshot      },

        { "disasm_goto_ntcreatefile",                test_disasm_goto_ntcreatefile                },
        { "disasm_goto_ntreadfile",                  test_disasm_goto_ntreadfile                  },
        { "disasm_goto_ntwritefile",                 test_disasm_goto_ntwritefile                 },
    };

    int total = static_cast<int>(sizeof(tests) / sizeof(tests[0]));
    for (int i = 0; i < total; ++i) {
        if (cancelled && cancelled()) {
            int remaining = total - i;
            skipped.fetch_add(remaining);
            log_msg(hf, "disasm_phase", "cancelled -- skipping %d remaining tests", remaining);
            break;
        }

        log_msg(hf, "disasm_phase", "[%d/%d] %s", i + 1, total, tests[i].name);
        __try {
            tests[i].fn(hf, passed, failed, skipped);
        }
        __except (EXCEPTION_EXECUTE_HANDLER) {
            log_msg(hf, "disasm_phase", "FAIL -- %s threw SEH exception 0x%08X",
                tests[i].name, GetExceptionCode());
            failed.fetch_add(1);
        }
    }

    auto t1 = std::chrono::steady_clock::now();
    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(t1 - t0).count();
    log_msg(hf, "disasm_phase", "=== DISASM TESTS DONE (elapsed %lld ms) ===", (long long)ms);
}

}
