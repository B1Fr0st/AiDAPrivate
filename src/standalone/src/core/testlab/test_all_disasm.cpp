#include "test_all_disasm.h"

#include "test_all_features.hpp"
#include "../disasm/disasm_view.hpp"
#include "../disasm/pseudocode_view.hpp"
#include "../disasm/decompiler_engine.hpp"
#include "../disasm/function_index.hpp"
#include "../disasm/xref_index.hpp"
#include "../disasm/comment_store.hpp"
#include "../disasm/rename_store.hpp"
#include "../disasm/nav_history.hpp"
#include "../editor/hex_view.hpp"
#include "../editor/expression_eval.hpp"
#include "../debugger/debugger_engine.hpp"
#include "../runtime/standalone_driver.hpp"
#include "../../helpers/diag_log.hpp"
#include "../../helpers/globals.h"

#include <chrono>
#include <cstdarg>
#include <cstdio>
#include <cstring>
#include <fstream>
#include <memory>
#include <mutex>
#include <shared_mutex>
#include <string>
#include <utility>
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
        test_all_features::write_full_test_log_line(hf, line.data(), line.size());
    }
    void log_msg(HANDLE hf, const char* tag, const char* fmt, ...) {
        char ts[40]; format_timestamp(ts, sizeof(ts));
        char detail[1024]; va_list ap; va_start(ap, fmt);
        _vsnprintf_s(detail, sizeof(detail), _TRUNCATE, fmt, ap); va_end(ap);
        char line[1200];
        _snprintf_s(line, sizeof(line), _TRUNCATE, "[%s] [%s] %s\n", ts, tag, detail);
        std::string s(line);
        write_log_file(hf, s);
        test_all_features::mirror_full_test_log_line(tag, detail, s.c_str());
    }

    long long elapsed_us_since(std::chrono::steady_clock::time_point t0) {
        return static_cast<long long>(std::chrono::duration_cast<std::chrono::microseconds>(
            std::chrono::steady_clock::now() - t0).count());
    }

    const char* addr_format_name(disasm_view::addr_format_t value) {
        switch (value) {
        case disasm_view::addr_format_t::va: return "va";
        case disasm_view::addr_format_t::rva: return "rva";
        case disasm_view::addr_format_t::file_offset: return "file_offset";
        default: return "unknown";
        }
    }

    const char* center_view_name(center_view_t value) {
        switch (value) {
        case center_view_t::code_editor: return "code_editor";
        case center_view_t::disassembly: return "disassembly";
        case center_view_t::hex_view: return "hex_view";
        case center_view_t::welcome: return "welcome";
        case center_view_t::settings_view: return "settings_view";
        case center_view_t::network_view: return "network_view";
        case center_view_t::memory_scanner: return "memory_scanner";
        case center_view_t::debugger_view: return "debugger_view";
        case center_view_t::pseudocode: return "pseudocode";
        case center_view_t::struct_recon: return "struct_recon";
        case center_view_t::crypto_scanner: return "crypto_scanner";
        case center_view_t::aob_generator: return "aob_generator";
        case center_view_t::fuzzer_view: return "fuzzer_view";
        case center_view_t::xref_browser: return "xref_browser";
        case center_view_t::snapshot_diff: return "snapshot_diff";
        case center_view_t::pointer_scanner: return "pointer_scanner";
        case center_view_t::decrypt_oracle: return "decrypt_oracle";
        case center_view_t::integrity_hunter: return "integrity_hunter";
        case center_view_t::symbolic_view: return "symbolic_view";
        case center_view_t::taint_view: return "taint_view";
        case center_view_t::deobfuscation_view: return "deobfuscation_view";
        case center_view_t::stealth_view: return "stealth_view";
        case center_view_t::scan_hub: return "scan_hub";
        case center_view_t::types_hub: return "types_hub";
        case center_view_t::analysis_hub: return "analysis_hub";
        case center_view_t::binary_map: return "binary_map";
        case center_view_t::graph_view: return "graph_view";
        case center_view_t::image_view: return "image_view";
        case center_view_t::test_lab: return "test_lab";
        default: return "unknown";
        }
    }

    void log_nav_snapshot(HANDLE hf, const char* tag, const char* phase) {
        std::lock_guard<std::mutex> lk(nav_history::mutex_ref());
        const auto& s = nav_history::stack_ref();
        const uint64_t first = s.empty() ? 0 : s.front();
        const uint64_t last = s.empty() ? 0 : s.back();
        log_msg(hf, tag, "STATE -- %s size=%zu max=%zu first=0x%llX last=0x%llX",
            phase,
            s.size(),
            nav_history::kMaxEntries,
            (unsigned long long)first,
            (unsigned long long)last);
    }

    uint64_t resolve_remote_module_base(const char* module_name) {
        const uint32_t pid = driver_bridge::attached_pid();
        if (pid == 0)
            return 0;
        for (const auto& mod : driver_bridge::enumerate_modules_for(pid)) {
            if (_stricmp(mod.name.c_str(), module_name) == 0)
                return mod.base;
        }
        return 0;
    }

    uint64_t resolve_ntdll_export(const char* name) {
        if (!name || name[0] == '\0')
            return 0;

        const uint64_t remote_ntdll = resolve_remote_module_base("ntdll.dll");
        if (remote_ntdll != 0) {
            const uint64_t resolved = driver_bridge::resolve_export(remote_ntdll, name);
            if (resolved != 0)
                return resolved;

            HMODULE local_ntdll = GetModuleHandleW(L"ntdll.dll");
            FARPROC local_fn = local_ntdll ? GetProcAddress(local_ntdll, name) : nullptr;
            if (local_ntdll && local_fn) {
                const uint64_t offset =
                    reinterpret_cast<uintptr_t>(local_fn) - reinterpret_cast<uintptr_t>(local_ntdll);
                return remote_ntdll + offset;
            }
        }

        HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
        if (!ntdll) return 0;
        FARPROC fn = GetProcAddress(ntdll, name);
        if (!fn) return 0;
        return static_cast<uint64_t>(reinterpret_cast<uintptr_t>(fn));
    }

    uint64_t resolve_ntclose() {
        return resolve_ntdll_export("NtClose");
    }

    bool string_signals_error(const std::string& s) {
        static const char* const kMarkers[] = {
            "<read error>", "not attached", "must be non-zero", "error"
        };
        for (const char* m : kMarkers) {
            if (s.find(m) != std::string::npos) return true;
        }
        return false;
    }

    size_t count_decoded_instructions(const std::vector<uint8_t>& bytes, uint64_t base, size_t& consumed_out) {
        consumed_out = 0;
        size_t count = 0;
        size_t pos = 0;
        const size_t total = bytes.size();
        while (pos < total) {
            int avail = static_cast<int>(total - pos);
            if (avail > 15) avail = 15;
            AsmInstr ins = zydis_decode_one(bytes.data() + pos, avail, base + pos);
            if (ins.len <= 0) break;
            ++count;
            pos += static_cast<size_t>(ins.len);
        }
        consumed_out = pos;
        return count;
    }

    bool wait_for_disasm_window(uint64_t expected_base, std::vector<uint8_t>& bytes_out,
                                uint64_t& base_out, uint64_t request_addr, int timeout_ms) {
        const int step_ms = 25;
        int waited = 0;
        for (;;) {
            uint64_t base = 0;
            auto bytes = debugger_engine::cached_disasm_window(base);
            if (base == expected_base && !bytes.empty()) {
                base_out = base;
                bytes_out = std::move(bytes);
                return true;
            }
            if (waited >= timeout_ms) {
                base_out = base;
                bytes_out = std::move(bytes);
                return false;
            }
            Sleep(step_ms);
            waited += step_ms;
            if ((waited % 100) == 0 && request_addr != 0)
                debugger_engine::request_disasm_refresh(request_addr, 0);
        }
    }

    bool refresh_and_validate_disasm(HANDLE hf, const char* tag, uint64_t addr,
                                     std::atomic<int>& passed, std::atomic<int>& failed) {
        const uint64_t expected_base = (addr > 0x100) ? addr - 0x100 : 0;
        const uint32_t attached = driver_bridge::attached_pid();
        log_msg(hf, tag, "INPUT -- request_disasm_refresh rip=0x%016llX expected_base=0x%016llX attached_pid=%u",
            (unsigned long long)addr, (unsigned long long)expected_base, attached);

        auto t0 = std::chrono::steady_clock::now();
        debugger_engine::request_disasm_refresh(addr, 0);

        std::vector<uint8_t> bytes;
        uint64_t base_out = 0;
        bool ready = wait_for_disasm_window(expected_base, bytes, base_out, addr, 4000);
        auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::steady_clock::now() - t0).count();

        size_t consumed = 0;
        size_t instr = count_decoded_instructions(bytes, base_out, consumed);
        log_msg(hf, tag, "OUTPUT -- ready=%d base=0x%016llX bytes=%zu decoded_instructions=%zu consumed_bytes=%zu (elapsed %lld ms)",
            (int)ready, (unsigned long long)base_out, bytes.size(), instr, consumed, (long long)ms);

        if (!ready || bytes.empty()) {
            log_msg(hf, tag, "FAIL -- disasm window empty for base 0x%016llX (bytes=%zu attached_pid=%u)",
                (unsigned long long)expected_base, bytes.size(), attached);
            failed.fetch_add(1);
            return false;
        }
        if (base_out == 0) {
            log_msg(hf, tag, "FAIL -- disasm window base is 0");
            failed.fetch_add(1);
            return false;
        }
        if (instr == 0) {
            log_msg(hf, tag, "FAIL -- 0 instructions decoded from %zu bytes at base 0x%016llX",
                bytes.size(), (unsigned long long)base_out);
            failed.fetch_add(1);
            return false;
        }
        log_msg(hf, tag, "PASS -- disasm window at base 0x%016llX has %zu bytes, %zu instructions decoded (elapsed %lld ms)",
            (unsigned long long)base_out, bytes.size(), instr, (long long)ms);
        passed.fetch_add(1);
        return true;
    }

    bool wait_for_decompile_tab(HANDLE hf, const char* tag, uint64_t addr, int timeout_ms,
                                bool& loaded_out, bool& error_out, std::string& fn_out) {
        loaded_out = false;
        error_out = false;
        fn_out.clear();
        const int step_ms = 50;
        int waited = 0;
        for (;;) {
            auto tabs = pseudocode_view::snapshot_tabs();
            bool found = false;
            for (const auto& t : tabs) {
                if (t.addr != addr) continue;
                found = true;
                fn_out = t.function_name;
                if (!t.decompiling) {
                    loaded_out = t.loaded;
                    error_out = t.is_error;
                    return true;
                }
                break;
            }
            if (!found && waited >= timeout_ms) return false;
            if (waited >= timeout_ms) return true;
            Sleep(step_ms);
            waited += step_ms;
        }
    }

    bool snapshot_tab_for_addr(uint64_t addr, pseudocode_view::tab_info_t& out, size_t* total_out = nullptr) {
        auto tabs = pseudocode_view::snapshot_tabs();
        if (total_out)
            *total_out = tabs.size();
        for (const auto& t : tabs) {
            if (t.addr == addr) {
                out = t;
                return true;
            }
        }
        return false;
    }

    size_t count_pseudocode_lines(const std::string& text) {
        if (text.empty())
            return 0;
        size_t lines = 1;
        for (char ch : text) {
            if (ch == '\n')
                ++lines;
        }
        if (!text.empty() && text.back() == '\n' && lines > 0)
            --lines;
        return lines;
    }

    bool pseudocode_metrics_for_addr(uint64_t addr, size_t& bytes_out, size_t& lines_out,
                                     bool& complete_out, bool& error_out, std::string& source_out) {
        bytes_out = 0;
        lines_out = 0;
        complete_out = false;
        error_out = false;
        source_out.clear();
        std::lock_guard<std::mutex> lk(decompiler_engine::g_state.mutex);
        auto apply = [&](const decompiler_engine::decompile_result_t& r, const char* source) {
            bytes_out = r.pseudocode.size();
            lines_out = count_pseudocode_lines(r.pseudocode);
            complete_out = r.complete;
            error_out = r.is_error;
            source_out = source ? source : "";
            return true;
        };
        if (decompiler_engine::g_state.current.function_addr == addr &&
            decompiler_engine::g_state.current.complete) {
            return apply(decompiler_engine::g_state.current, "current");
        }
        auto it = decompiler_engine::g_state.cache.find(addr);
        if (it != decompiler_engine::g_state.cache.end() && it->second.complete) {
            return apply(it->second, "cache");
        }
        return false;
    }

    void log_pseudocode_tab_evidence(HANDLE hf, const char* tag, const char* phase, uint64_t addr) {
        pseudocode_view::tab_info_t tab{};
        size_t total = 0;
        const bool found = snapshot_tab_for_addr(addr, tab, &total);
        size_t pseudocode_bytes = 0;
        size_t pseudocode_lines = 0;
        bool complete = false;
        bool is_error = false;
        std::string source;
        const bool metrics = pseudocode_metrics_for_addr(addr, pseudocode_bytes, pseudocode_lines,
            complete, is_error, source);
        log_msg(hf, tag,
            "STATE -- %s addr=0x%016llX found=%d total_tabs=%zu loaded=%d decompiling=%d is_error=%d function=\"%s\" metrics=%d source=\"%s\" complete=%d engine_error=%d pseudocode_bytes=%zu pseudocode_lines=%zu active=0x%016llX cancel=%d next_pending=%d decompiling_engine=%d",
            phase,
            (unsigned long long)addr,
            (int)found,
            total,
            found ? (int)tab.loaded : 0,
            found ? (int)tab.decompiling : 0,
            found ? (int)tab.is_error : 0,
            found ? tab.function_name.c_str() : "",
            (int)metrics,
            source.c_str(),
            (int)complete,
            (int)is_error,
            pseudocode_bytes,
            pseudocode_lines,
            (unsigned long long)pseudocode_view::active_tab_address(),
            decompiler_engine::g_state.cancel.load(std::memory_order_acquire) ? 1 : 0,
            decompiler_engine::g_state.next_pending.load(std::memory_order_acquire) ? 1 : 0,
            decompiler_engine::g_state.decompiling.load(std::memory_order_acquire) ? 1 : 0);
    }

    bool pseudocode_refresh_state_ok(const pseudocode_view::tab_info_t& tab, uint64_t addr,
                                     size_t line_count, bool metrics_present) {
        if (tab.addr != addr)
            return false;
        if (tab.decompiling)
            return true;
        return tab.loaded && !tab.is_error && metrics_present && line_count > 0;
    }

    void validate_decompile(HANDLE hf, const char* tag, const char* sym, uint64_t addr, bool force,
                            std::atomic<int>& passed, std::atomic<int>& failed) {
        const uint32_t attached = driver_bridge::attached_pid();
        log_msg(hf, tag, "INPUT -- request_decompile(%s=0x%016llX, force=%d) attached_pid=%u",
            sym, (unsigned long long)addr, (int)force, attached);

        pseudocode_view::close_tab_by_addr(addr);
        auto t0 = std::chrono::steady_clock::now();
        pseudocode_view::request_decompile(addr, nullptr, force);

        bool loaded = false;
        bool is_error = false;
        std::string fn;
        bool finished = wait_for_decompile_tab(hf, tag, addr, 15000, loaded, is_error, fn);
        auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::steady_clock::now() - t0).count();

        bool present = pseudocode_view::has_tab_for(addr);
        log_msg(hf, tag, "OUTPUT -- finished=%d loaded=%d is_error=%d has_tab=%d function=\"%s\" (elapsed %lld ms)",
            (int)finished, (int)loaded, (int)is_error, (int)present, fn.c_str(), (long long)ms);

        if (finished && present && is_error && force) {
            pseudocode_view::close_tab_by_addr(addr);
            auto retry_t0 = std::chrono::steady_clock::now();
            pseudocode_view::request_decompile(addr, nullptr, true);
            loaded = false;
            is_error = false;
            fn.clear();
            finished = wait_for_decompile_tab(hf, tag, addr, 15000, loaded, is_error, fn);
            present = pseudocode_view::has_tab_for(addr);
            auto retry_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
                std::chrono::steady_clock::now() - retry_t0).count();
            log_msg(hf, tag, "RETRY -- finished=%d loaded=%d is_error=%d has_tab=%d function=\"%s\" (elapsed %lld ms)",
                (int)finished, (int)loaded, (int)is_error, (int)present, fn.c_str(), (long long)retry_ms);
        }

        if (!finished || !present) {
            log_msg(hf, tag, "FAIL -- decompile of %s (0x%016llX) did not produce a tab (attached_pid=%u)",
                sym, (unsigned long long)addr, attached);
            failed.fetch_add(1);
            return;
        }
        if (is_error) {
            log_msg(hf, tag, "FAIL -- decompile of %s produced an error result (empty/failed pseudocode)", sym);
            failed.fetch_add(1);
            return;
        }
        if (!loaded) {
            log_msg(hf, tag, "FAIL -- decompile of %s never completed within timeout (still decompiling)", sym);
            failed.fetch_add(1);
            return;
        }
        if (string_signals_error(fn)) {
            log_msg(hf, tag, "FAIL -- decompile of %s returned error-signalling text \"%s\"", sym, fn.c_str());
            failed.fetch_add(1);
            return;
        }
        log_msg(hf, tag, "PASS -- decompile of %s produced non-empty pseudocode (loaded, no error)", sym);
        passed.fetch_add(1);
    }

    void test_goto_address(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        const char* tag = "disasm.goto_address";
        uint64_t addr = resolve_ntclose();
        if (addr == 0) {
            log_msg(hf, tag, "SKIP -- NtClose not resolved");
            skipped.fetch_add(1);
            return;
        }
        refresh_and_validate_disasm(hf, tag, addr, passed, failed);
    }

    void test_get_disasm_window_bytes(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        const char* tag = "disasm.window_bytes";
        uint64_t addr = resolve_ntclose();
        if (addr == 0) {
            log_msg(hf, tag, "SKIP -- NtClose not resolved");
            skipped.fetch_add(1);
            return;
        }
        refresh_and_validate_disasm(hf, tag, addr, passed, failed);
    }

    void test_navigate_back_forward(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        const char* tag = "disasm.nav_back_fwd";
        try {
            auto& st = disasm_view::g_state;
            std::vector<int> saved_history = st.nav_history;
            int saved_pos = st.nav_pos;
            int saved_row = st.selected_row;

            st.nav_history.clear();
            st.nav_history.push_back(0x11);
            st.nav_history.push_back(0x22);
            st.nav_pos = 1;
            st.selected_row = st.nav_history[st.nav_pos];

            log_msg(hf, tag, "INPUT -- seeded nav_history rows {0x11,0x22} nav_pos=%d selected_row=%d",
                st.nav_pos, st.selected_row);

            disasm_view::navigate_back();
            int pos_after_back = st.nav_pos;
            int row_after_back = st.selected_row;
            log_msg(hf, tag, "OUTPUT -- after navigate_back nav_pos=%d selected_row=0x%X",
                pos_after_back, (unsigned)row_after_back);

            bool back_ok = (pos_after_back == 0) && (row_after_back == 0x11);

            disasm_view::navigate_forward();
            int pos_after_fwd = st.nav_pos;
            int row_after_fwd = st.selected_row;
            log_msg(hf, tag, "OUTPUT -- after navigate_forward nav_pos=%d selected_row=0x%X",
                pos_after_fwd, (unsigned)row_after_fwd);

            bool fwd_ok = (pos_after_fwd == 1) && (row_after_fwd == 0x22);

            st.nav_history = std::move(saved_history);
            st.nav_pos = saved_pos;
            st.selected_row = saved_row;

            if (back_ok && fwd_ok) {
                log_msg(hf, tag, "PASS -- navigate_back moved 1->0 (row 0x22->0x11), navigate_forward moved 0->1 (row 0x11->0x22)");
                passed.fetch_add(1);
            } else {
                log_msg(hf, tag, "FAIL -- back_ok=%d (pos=%d row=0x%X) fwd_ok=%d (pos=%d row=0x%X)",
                    (int)back_ok, pos_after_back, (unsigned)row_after_back,
                    (int)fwd_ok, pos_after_fwd, (unsigned)row_after_fwd);
                failed.fetch_add(1);
            }
        } catch (...) {
            log_msg(hf, tag, "FAIL -- exception in navigate_back/forward");
            failed.fetch_add(1);
        }
    }

    void test_bump_format_generation(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        const char* tag = "disasm.bump_format";
        try {
            const uint64_t before_sig = disasm_view::g_state.layout_signature;
            const int before_n = disasm_view::g_state.layout_n;
            const uint32_t before_gen = disasm_view::format_generation();
            const bool before_show_bytes = disasm_view::g_state.show_bytes;
            const disasm_view::addr_format_t before_format = disasm_view::g_state.addr_format;
            log_msg(hf, tag, "INPUT -- invoking bump_format_generation() before generation=%u layout_sig=0x%016llX layout_n=%d show_bytes=%d format=%s(%d)",
                before_gen,
                (unsigned long long)before_sig,
                before_n,
                before_show_bytes ? 1 : 0,
                addr_format_name(before_format),
                static_cast<int>(before_format));
            disasm_view::bump_format_generation();
            const uint32_t after_gen = disasm_view::format_generation();
            const uint64_t after_sig = disasm_view::g_state.layout_signature;
            const int after_n = disasm_view::g_state.layout_n;
            const bool after_show_bytes = disasm_view::g_state.show_bytes;
            const disasm_view::addr_format_t after_format = disasm_view::g_state.addr_format;
            const bool generation_changed = after_gen != before_gen && after_gen == before_gen + 1u;
            const bool layout_changed = before_sig != after_sig || before_n != after_n;
            log_msg(hf, tag, "OUTPUT -- generation=%u generation_changed=%d layout_sig=0x%016llX layout_n=%d show_bytes=%d format=%s(%d) layout_changed=%d",
                after_gen,
                generation_changed ? 1 : 0,
                (unsigned long long)after_sig,
                after_n,
                after_show_bytes ? 1 : 0,
                addr_format_name(after_format),
                static_cast<int>(after_format),
                layout_changed ? 1 : 0);
            if (generation_changed) {
                log_msg(hf, tag, "PASS -- bump_format_generation advanced actual format generation from %u to %u (layout_changed=%d)",
                    before_gen, after_gen, layout_changed ? 1 : 0);
                passed.fetch_add(1);
            } else {
                log_msg(hf, tag, "FAIL -- bump_format_generation did not advance actual format generation (before=%u after=%u layout_changed=%d)",
                    before_gen, after_gen, layout_changed ? 1 : 0);
                failed.fetch_add(1);
            }
        } catch (...) {
            log_msg(hf, tag, "FAIL -- exception in bump_format_generation");
            failed.fetch_add(1);
        }
    }

    void test_comment_set_get(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        const char* tag = "comment.set_get";
        const uint64_t test_addr = 0xDEADBEEF00000001ULL;
        const std::string test_text = "test_comment_from_test_all_disasm";

        log_msg(hf, tag, "INPUT -- set(addr=0x%016llX, text=\"%s\")",
            (unsigned long long)test_addr, test_text.c_str());
        comment_store::set(test_addr, test_text);
        std::string got = comment_store::get(test_addr);
        log_msg(hf, tag, "OUTPUT -- get(addr=0x%016llX) returned \"%s\" (len=%zu)",
            (unsigned long long)test_addr, got.c_str(), got.size());

        if (got == test_text) {
            log_msg(hf, tag, "PASS -- set/get roundtrip OK (read-back matches written text)");
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

        log_msg(hf, tag, "INPUT -- set(addr=0x%016llX, \"temporary\") then clear", (unsigned long long)test_addr);
        comment_store::set(test_addr, "temporary");
        bool present = comment_store::has(test_addr);
        comment_store::set(test_addr, "");
        bool absent = !comment_store::has(test_addr);
        log_msg(hf, tag, "OUTPUT -- has() after set=%d, has() after clear=%d (absent=%d)",
            (int)present, (int)!absent, (int)absent);

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

        log_msg(hf, tag, "INPUT -- set(addr=0x%016llX, \"will_be_cleared\") then set(addr, \"\")",
            (unsigned long long)test_addr);
        comment_store::set(test_addr, "will_be_cleared");
        comment_store::set(test_addr, "");
        std::string got = comment_store::get(test_addr);
        log_msg(hf, tag, "OUTPUT -- get(addr=0x%016llX) returned \"%s\" (len=%zu)",
            (unsigned long long)test_addr, got.c_str(), got.size());

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

        log_msg(hf, tag, "INPUT -- set(addr=0x%016llX, name=\"%s\")",
            (unsigned long long)test_addr, test_name.c_str());
        rename_store::set(test_addr, test_name);
        std::string got = rename_store::get(test_addr);
        log_msg(hf, tag, "OUTPUT -- get(addr=0x%016llX) returned \"%s\" (len=%zu)",
            (unsigned long long)test_addr, got.c_str(), got.size());

        if (got == test_name) {
            log_msg(hf, tag, "PASS -- set/get roundtrip OK (read-back matches written name)");
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

        log_msg(hf, tag, "INPUT -- set(addr=0x%016llX, \"temp_rename\") then clear", (unsigned long long)test_addr);
        rename_store::set(test_addr, "temp_rename");
        bool present = rename_store::has(test_addr);
        rename_store::clear(test_addr);
        bool absent = !rename_store::has(test_addr);
        log_msg(hf, tag, "OUTPUT -- has() after set=%d, has() after clear=%d (absent=%d)",
            (int)present, (int)!absent, (int)absent);

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

        log_msg(hf, tag, "INPUT -- set(addr=0x%016llX, \"to_be_cleared\") then clear(addr)",
            (unsigned long long)test_addr);
        rename_store::set(test_addr, "to_be_cleared");
        rename_store::clear(test_addr);
        std::string got = rename_store::get(test_addr);
        log_msg(hf, tag, "OUTPUT -- get(addr=0x%016llX) returned \"%s\" (len=%zu)",
            (unsigned long long)test_addr, got.c_str(), got.size());

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

        log_msg(hf, tag, "INPUT -- set(0x%016llX, \"resolved_name\"); resolve_or(0x%016llX, \"fallback\"); resolve_or(0x%016llX, \"fallback\")",
            (unsigned long long)addr_with, (unsigned long long)addr_with, (unsigned long long)addr_without);
        rename_store::set(addr_with, "resolved_name");
        std::string r1 = rename_store::resolve_or(addr_with, "fallback");
        std::string r2 = rename_store::resolve_or(addr_without, "fallback");
        log_msg(hf, tag, "OUTPUT -- r1=\"%s\" r2=\"%s\"", r1.c_str(), r2.c_str());

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

    struct xref_fixture_scope_t {
        std::unique_ptr<xref_index::detail::registry_t> saved;
        uint64_t target = 0x7FF700001000ULL;

        xref_fixture_scope_t() {
            saved = xref_index::detach_snapshot();
            auto& reg = xref_index::detail::registry();
            auto mod = std::make_shared<xref_index::detail::module_index_t>();
            mod->name = "aida_xref_fixture";
            mod->base = 0x7FF700000000ULL;
            mod->size = 0x4000;
            mod->state.store(static_cast<uint32_t>(xref_index::detail::build_state_t::built), std::memory_order_release);

            xref_index::annotation_t call_ref;
            call_ref.kind = xref_index::kind_t::code;
            call_ref.edge = xref_index::edge_t::call_proc;
            call_ref.up = true;
            call_ref.source_addr = 0x7FF700000120ULL;
            call_ref.source_label = "fixture_call+0";

            xref_index::annotation_t data_ref;
            data_ref.kind = xref_index::kind_t::data;
            data_ref.edge = xref_index::edge_t::offset_ref;
            data_ref.up = false;
            data_ref.source_addr = 0x7FF700002000ULL;
            data_ref.source_label = ".rdata:fixture_ptr";

            mod->to_index[target].push_back(std::move(call_ref));
            mod->to_index[target].push_back(std::move(data_ref));

            {
                std::unique_lock<std::shared_mutex> lk(reg.rw);
                reg.modules.clear();
                reg.table.clear();
                reg.modules.emplace(mod->name, mod);
                xref_index::detail::module_range_t range;
                range.start_va = mod->base;
                range.end_va = mod->base + mod->size;
                range.name = mod->name;
                range.index = mod;
                reg.table.push_back(std::move(range));
                reg.table_built.store(true, std::memory_order_release);
                reg.rebuild_in_flight.store(false, std::memory_order_release);
                reg.generation.fetch_add(1, std::memory_order_acq_rel);
            }
        }

        ~xref_fixture_scope_t() {
            xref_index::attach_snapshot(std::move(saved));
        }
    };

    void validate_xref_fixture(HANDLE hf, const char* tag, size_t limit,
                               std::atomic<int>& passed, std::atomic<int>& failed) {
        xref_fixture_scope_t fixture;
        log_msg(hf, tag, "INPUT -- deterministic xref fixture target=0x%016llX limit=%zu",
            (unsigned long long)fixture.target, limit);

        auto t0 = std::chrono::steady_clock::now();
        auto results = xref_index::query_to(fixture.target, limit);
        bool more = xref_index::has_more(fixture.target, limit);
        auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::steady_clock::now() - t0).count();

        log_msg(hf, tag, "OUTPUT -- fixture query_to returned %zu xrefs has_more=%d (elapsed %lld ms)",
            results.size(), (int)more, (long long)ms);

        size_t zero_src = 0;
        bool saw_code_call = false;
        bool saw_data_ref = false;
        for (const auto& a : results) {
            if (a.source_addr == 0) ++zero_src;
            if (a.kind == xref_index::kind_t::code && a.edge == xref_index::edge_t::call_proc)
                saw_code_call = true;
            if (a.kind == xref_index::kind_t::data && a.edge == xref_index::edge_t::offset_ref)
                saw_data_ref = true;
            log_msg(hf, tag, "  fixture xref source=0x%016llX up=%d kind=%d edge=%d label=\"%s\"",
                (unsigned long long)a.source_addr, (int)a.up,
                (int)a.kind, (int)a.edge, a.source_label.c_str());
        }

        if (results.empty()) {
            log_msg(hf, tag, "FAIL -- fixture xref index returned no entries");
            failed.fetch_add(1);
            return;
        }
        if (zero_src != 0 || !saw_code_call || !saw_data_ref) {
            log_msg(hf, tag, "FAIL -- fixture xrefs invalid zero_src=%zu saw_code_call=%d saw_data_ref=%d",
                zero_src, (int)saw_code_call, (int)saw_data_ref);
            failed.fetch_add(1);
            return;
        }
        log_msg(hf, tag, "PASS -- deterministic fixture returned valid code/data xrefs");
        passed.fetch_add(1);
    }

    void test_xref_query_to(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        const char* tag = "xref.query_to";
        validate_xref_fixture(hf, tag, 16, passed, failed);
    }

    void test_xref_has_more(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        const char* tag = "xref.has_more";
        xref_fixture_scope_t fixture;
        log_msg(hf, tag, "INPUT -- deterministic xref fixture target=0x%016llX limit=1",
            (unsigned long long)fixture.target);

        auto results = xref_index::query_to(fixture.target, 64);
        bool more = xref_index::has_more(fixture.target, 1);
        log_msg(hf, tag, "OUTPUT -- fixture total xrefs available=%zu has_more(limit=1)=%d",
            results.size(), (int)more);

        if (results.size() < 2) {
            log_msg(hf, tag, "FAIL -- fixture xref index produced %zu xrefs, expected at least 2", results.size());
            failed.fetch_add(1);
            return;
        }
        if (!more) {
            log_msg(hf, tag, "FAIL -- has_more(fixture, 1)=false with %zu xrefs", results.size());
            failed.fetch_add(1);
            return;
        }
        log_msg(hf, tag, "PASS -- has_more(fixture, 1)=true with %zu total xrefs", results.size());
        passed.fetch_add(1);
    }

    void test_xref_request_deep_static(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        const char* tag = "xref.deep_static";
        try {
            bool was_requested = xref_index::deep_static_xref_requested();
            log_msg(hf, tag, "INPUT -- deep_static_xref_requested before=%d, invoking request_deep_static_xref()",
                (int)was_requested);
            xref_index::request_deep_static_xref();
            bool now_requested = xref_index::deep_static_xref_requested();
            log_msg(hf, tag, "OUTPUT -- deep_static_xref_requested after=%d", (int)now_requested);
            if (now_requested) {
                log_msg(hf, tag, "PASS -- request_deep_static_xref set the flag (before=%d after=%d)",
                    (int)was_requested, (int)now_requested);
                passed.fetch_add(1);
            } else {
                log_msg(hf, tag, "FAIL -- request_deep_static_xref did not set flag (after=%d)",
                    (int)now_requested);
                failed.fetch_add(1);
            }
        } catch (...) {
            log_msg(hf, tag, "FAIL -- exception in request_deep_static_xref");
            failed.fetch_add(1);
        }
    }

    void test_xref_on_file_loaded(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        const char* tag = "xref.on_file_loaded";
        try {
            xref_index::request_deep_static_xref();
            bool before = xref_index::deep_static_xref_requested();
            log_msg(hf, tag, "INPUT -- deep_static flag forced to %d, invoking on_file_loaded()", (int)before);
            xref_index::on_file_loaded();
            bool after = xref_index::deep_static_xref_requested();
            log_msg(hf, tag, "OUTPUT -- deep_static_xref_requested after on_file_loaded=%d", (int)after);
            if (!after) {
                log_msg(hf, tag, "PASS -- on_file_loaded() reset deep_static flag (%d -> %d)",
                    (int)before, (int)after);
                passed.fetch_add(1);
            } else {
                log_msg(hf, tag, "FAIL -- on_file_loaded() did not reset deep_static flag (after=%d)",
                    (int)after);
                failed.fetch_add(1);
            }
        } catch (...) {
            log_msg(hf, tag, "FAIL -- exception in on_file_loaded");
            failed.fetch_add(1);
        }
    }

    void test_xref_on_attach_changed(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        const char* tag = "xref.on_attach_changed";
        try {
            uint64_t probe = resolve_ntclose();
            log_msg(hf, tag, "INPUT -- invoking on_attach_changed() then query_to(0x%016llX)",
                (unsigned long long)probe);
            xref_index::on_attach_changed();
            auto after = xref_index::query_to(probe, 16);
            log_msg(hf, tag, "OUTPUT -- query_to immediately after reset returned %zu xrefs (expected 0)",
                after.size());
            if (after.empty()) {
                log_msg(hf, tag, "PASS -- on_attach_changed() cleared the xref registry (post-reset query empty)");
                passed.fetch_add(1);
            } else {
                log_msg(hf, tag, "FAIL -- registry not cleared, query_to returned %zu xrefs after reset",
                    after.size());
                failed.fetch_add(1);
            }
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
        validate_decompile(hf, tag, "NtClose", addr, true, passed, failed);
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
            pseudocode_view::close_tab_by_addr(addr);
            bool before = pseudocode_view::has_tab_for(addr);
            log_msg(hf, tag, "INPUT -- has_tab_for(0x%016llX) before=%d, request_decompile to create tab",
                (unsigned long long)addr, (int)before);
            pseudocode_view::request_decompile(addr, nullptr, false);
            bool after = pseudocode_view::has_tab_for(addr);
            log_msg(hf, tag, "OUTPUT -- has_tab_for(0x%016llX) after=%d", (unsigned long long)addr, (int)after);
            if (after) {
                log_msg(hf, tag, "PASS -- has_tab_for returns true after a tab is created (before=%d after=%d)",
                    (int)before, (int)after);
                passed.fetch_add(1);
            } else {
                log_msg(hf, tag, "FAIL -- has_tab_for false after request_decompile created a tab");
                failed.fetch_add(1);
            }
        } catch (...) {
            log_msg(hf, tag, "FAIL -- exception in has_tab_for");
            failed.fetch_add(1);
        }
    }

    void test_pseudocode_tab_count(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        const char* tag = "pseudo.tab_count";
        uint64_t addr = resolve_ntclose();
        if (addr == 0) {
            log_msg(hf, tag, "SKIP -- NtClose not resolved");
            skipped.fetch_add(1);
            return;
        }
        try {
            pseudocode_view::close_tab_by_addr(addr);
            int before = pseudocode_view::tab_count();
            log_msg(hf, tag, "INPUT -- tab_count before=%d, creating tab for 0x%016llX",
                before, (unsigned long long)addr);
            pseudocode_view::request_decompile(addr, nullptr, false);
            int after_add = pseudocode_view::tab_count();
            pseudocode_view::close_tab_by_addr(addr);
            int after_close = pseudocode_view::tab_count();
            log_msg(hf, tag, "OUTPUT -- tab_count after_add=%d after_close=%d", after_add, after_close);
            if (after_add == before + 1 && after_close == before) {
                log_msg(hf, tag, "PASS -- tab_count tracks add/close (%d -> %d -> %d)",
                    before, after_add, after_close);
                passed.fetch_add(1);
            } else {
                log_msg(hf, tag, "FAIL -- tab_count mismatch before=%d after_add=%d after_close=%d",
                    before, after_add, after_close);
                failed.fetch_add(1);
            }
        } catch (...) {
            log_msg(hf, tag, "FAIL -- exception in tab_count");
            failed.fetch_add(1);
        }
    }

    void test_pseudocode_snapshot_tabs(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        const char* tag = "pseudo.snapshot_tabs";
        uint64_t addr = resolve_ntclose();
        if (addr == 0) {
            log_msg(hf, tag, "SKIP -- NtClose not resolved");
            skipped.fetch_add(1);
            return;
        }
        try {
            pseudocode_view::close_tab_by_addr(addr);
            log_msg(hf, tag, "INPUT -- creating tab for 0x%016llX then snapshot_tabs()",
                (unsigned long long)addr);
            log_msg(hf, tag, "TRACE -- before request_decompile tab_count=%d",
                pseudocode_view::tab_count());
            pseudocode_view::request_decompile(addr, nullptr, false);
            log_msg(hf, tag, "TRACE -- after request_decompile tab_count=%d; before snapshot_tabs",
                pseudocode_view::tab_count());
            auto tabs = pseudocode_view::snapshot_tabs();
            log_msg(hf, tag, "TRACE -- after snapshot_tabs count=%zu", tabs.size());
            log_msg(hf, tag, "OUTPUT -- snapshot_tabs() returned %zu tabs", tabs.size());
            bool found = false;
            for (size_t i = 0; i < tabs.size() && i < 8; ++i) {
                log_msg(hf, tag, "  tab[%zu]: addr=0x%016llX label=\"%s\" loaded=%d decompiling=%d is_error=%d",
                    i, (unsigned long long)tabs[i].addr, tabs[i].label.c_str(),
                    (int)tabs[i].loaded, (int)tabs[i].decompiling, (int)tabs[i].is_error);
                if (tabs[i].addr == addr) found = true;
            }
            for (const auto& t : tabs) {
                if (t.addr == addr) { found = true; break; }
            }
            if (!tabs.empty() && found) {
                log_msg(hf, tag, "PASS -- snapshot_tabs() includes the created tab for 0x%016llX (total %zu)",
                    (unsigned long long)addr, tabs.size());
                passed.fetch_add(1);
            } else {
                log_msg(hf, tag, "FAIL -- snapshot_tabs() missing tab for 0x%016llX (size=%zu found=%d)",
                    (unsigned long long)addr, tabs.size(), (int)found);
                failed.fetch_add(1);
            }
        } catch (...) {
            log_msg(hf, tag, "FAIL -- exception in snapshot_tabs");
            failed.fetch_add(1);
        }
    }

    void test_pseudocode_cancel_active(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        const char* tag = "pseudo.cancel_active";
        const uint64_t addr = 0x000001A1DA0CACE1ULL;
        try {
            const bool idle = decompiler_engine::wait_for_idle(3000, 25);
            log_msg(hf, tag, "INPUT -- controlled queued decompile addr=0x%016llX idle_before=%d", (unsigned long long)addr, idle ? 1 : 0);
            if (!idle) {
                log_msg(hf, tag, "FAIL -- decompiler engine was not idle, refusing to disturb an uncontrolled active decompile");
                failed.fetch_add(1);
                return;
            }
            pseudocode_view::close_tab_by_addr(addr);
            decompiler_engine::g_state.cancel.store(false, std::memory_order_release);
            decompiler_engine::g_state.next_pending.store(false, std::memory_order_release);
            decompiler_engine::g_state.next_addr.store(0, std::memory_order_release);
            decompiler_engine::g_state.next_file.store(nullptr, std::memory_order_release);
            decompiler_engine::g_state.decompiling.store(true, std::memory_order_release);

            pseudocode_view::request_decompile(addr, nullptr, true);
            log_pseudocode_tab_evidence(hf, tag, "after_request", addr);

            pseudocode_view::tab_info_t before_tab{};
            size_t before_total = 0;
            const bool before_found = snapshot_tab_for_addr(addr, before_tab, &before_total);
            const uint64_t active_before = pseudocode_view::active_tab_address();
            const bool queued_before = decompiler_engine::g_state.next_pending.load(std::memory_order_acquire) &&
                decompiler_engine::g_state.next_addr.load(std::memory_order_acquire) == addr;
            log_msg(hf, tag, "STATE -- before_cancel found=%d total_tabs=%zu active=0x%016llX queued=%d loaded=%d decompiling=%d is_error=%d",
                before_found ? 1 : 0,
                before_total,
                (unsigned long long)active_before,
                queued_before ? 1 : 0,
                before_found ? (int)before_tab.loaded : 0,
                before_found ? (int)before_tab.decompiling : 0,
                before_found ? (int)before_tab.is_error : 0);

            pseudocode_view::cancel_active_decompile();
            log_pseudocode_tab_evidence(hf, tag, "after_cancel", addr);

            pseudocode_view::tab_info_t after_tab{};
            size_t after_total = 0;
            const bool after_found = snapshot_tab_for_addr(addr, after_tab, &after_total);
            const uint64_t active_after = pseudocode_view::active_tab_address();
            const bool cancel_after = decompiler_engine::g_state.cancel.load(std::memory_order_acquire);
            const bool queued_after = decompiler_engine::g_state.next_pending.load(std::memory_order_acquire);
            const bool ok = before_found &&
                before_tab.addr == addr &&
                before_tab.decompiling &&
                active_before == addr &&
                queued_before &&
                after_found &&
                after_tab.addr == addr &&
                active_after == addr &&
                !after_tab.decompiling &&
                !after_tab.loaded &&
                after_tab.is_error &&
                cancel_after &&
                !queued_after;

            decompiler_engine::g_state.decompiling.store(false, std::memory_order_release);
            decompiler_engine::g_state.cancel.store(false, std::memory_order_release);
            decompiler_engine::g_state.next_pending.store(false, std::memory_order_release);
            decompiler_engine::g_state.next_addr.store(0, std::memory_order_release);
            decompiler_engine::g_state.next_file.store(nullptr, std::memory_order_release);
            pseudocode_view::close_tab_by_addr(addr);
            decompiler_engine::g_state.decompiling.store(false, std::memory_order_release);
            decompiler_engine::g_state.cancel.store(false, std::memory_order_release);
            decompiler_engine::g_state.next_pending.store(false, std::memory_order_release);
            decompiler_engine::g_state.next_addr.store(0, std::memory_order_release);
            decompiler_engine::g_state.next_file.store(nullptr, std::memory_order_release);

            if (ok) {
                log_msg(hf, tag, "PASS -- cancel reached active tab and engine flags (queued cleared, cancel observed)");
                passed.fetch_add(1);
            } else {
                log_msg(hf, tag, "FAIL -- cancel evidence incomplete before_found=%d before_decompiling=%d active_before=0x%016llX queued_before=%d after_found=%d after_loaded=%d after_decompiling=%d after_error=%d active_after=0x%016llX cancel_after=%d queued_after=%d",
                    before_found ? 1 : 0,
                    before_found ? (int)before_tab.decompiling : 0,
                    (unsigned long long)active_before,
                    queued_before ? 1 : 0,
                    after_found ? 1 : 0,
                    after_found ? (int)after_tab.loaded : 0,
                    after_found ? (int)after_tab.decompiling : 0,
                    after_found ? (int)after_tab.is_error : 0,
                    (unsigned long long)active_after,
                    cancel_after ? 1 : 0,
                    queued_after ? 1 : 0);
                failed.fetch_add(1);
            }
        } catch (...) {
            decompiler_engine::g_state.decompiling.store(false, std::memory_order_release);
            decompiler_engine::g_state.cancel.store(false, std::memory_order_release);
            decompiler_engine::g_state.next_pending.store(false, std::memory_order_release);
            decompiler_engine::g_state.next_addr.store(0, std::memory_order_release);
            decompiler_engine::g_state.next_file.store(nullptr, std::memory_order_release);
            pseudocode_view::close_tab_by_addr(addr);
            decompiler_engine::g_state.decompiling.store(false, std::memory_order_release);
            decompiler_engine::g_state.cancel.store(false, std::memory_order_release);
            decompiler_engine::g_state.next_pending.store(false, std::memory_order_release);
            decompiler_engine::g_state.next_addr.store(0, std::memory_order_release);
            decompiler_engine::g_state.next_file.store(nullptr, std::memory_order_release);
            log_msg(hf, tag, "FAIL -- exception in cancel_active_decompile");
            failed.fetch_add(1);
        }
    }

    void test_pseudocode_close_all(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        const char* tag = "pseudo.close_all";
        uint64_t addr = resolve_ntclose();
        try {
            if (addr != 0) {
                pseudocode_view::request_decompile(addr, nullptr, false);
            }
            int before = pseudocode_view::tab_count();
            log_msg(hf, tag, "INPUT -- tab_count before close_all=%d, invoking close_all_tabs()", before);
            pseudocode_view::close_all_tabs();
            int count_after = pseudocode_view::tab_count();
            log_msg(hf, tag, "OUTPUT -- tab_count after close_all=%d", count_after);
            if (count_after == 0) {
                log_msg(hf, tag, "PASS -- close_all_tabs() cleared all tabs (%d -> 0)", before);
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

            log_msg(hf, tag, "INPUT -- set_data(256 bytes, base=0x%016llX, name=\"test_data_256\")",
                (unsigned long long)0x00400000ULL);
            hex_view::set_data(test_data, 0x00400000, "test_data_256");
            log_msg(hf, tag, "OUTPUT -- g_state.data.size()=%zu base=0x%016llX name=\"%s\"",
                hex_view::g_state.data.size(), (unsigned long long)hex_view::g_state.base_addr,
                hex_view::g_state.source_name.c_str());

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
            const uint32_t attached = driver_bridge::attached_pid();
            log_msg(hf, tag, "INPUT -- read_from_process(addr=0x%016llX, size=64) attached_pid=%u",
                (unsigned long long)addr, attached);
            bool ok = hex_view::read_from_process(addr, 64);
            size_t got = ok ? hex_view::g_state.data.size() : 0;
            log_msg(hf, tag, "OUTPUT -- read_from_process ok=%d returned_bytes=%zu base=0x%016llX",
                (int)ok, got, (unsigned long long)hex_view::g_state.base_addr);
            if (ok && got > 0) {
                log_msg(hf, tag, "PASS -- read_from_process produced %zu bytes at 0x%016llX",
                    got, (unsigned long long)addr);
                passed.fetch_add(1);
            } else {
                std::string err = hex_view::last_error();
                log_msg(hf, tag, "FAIL -- read_from_process ok=%d bytes=%zu last_error=\"%s\" (attached_pid=%u)",
                    (int)ok, got, err.c_str(), attached);
                failed.fetch_add(1);
            }
        } catch (...) {
            log_msg(hf, tag, "FAIL -- exception in read_from_process");
            failed.fetch_add(1);
        }
    }

    void test_hexview_last_error(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        const char* tag = "hexview.last_error";
        try {
            char tmp_dir[MAX_PATH] = {};
            char valid_path[MAX_PATH] = {};
            DWORD tmp_len = GetTempPathA(static_cast<DWORD>(sizeof(tmp_dir)), tmp_dir);
            if (tmp_len == 0 || tmp_len >= static_cast<DWORD>(sizeof(tmp_dir)) ||
                GetTempFileNameA(tmp_dir, "aid", 0, valid_path) == 0) {
                DWORD gle = GetLastError();
                log_msg(hf, tag, "FAIL -- unable to create temp path for valid load probe gle=%lu", (unsigned long)gle);
                failed.fetch_add(1);
                return;
            }

            std::string missing_path = std::string(tmp_dir) + "aida_missing_hex_error_probe_7F4A2B1C.bin";
            DeleteFileA(missing_path.c_str());
            log_msg(hf, tag, "INPUT -- invalid load_from_file(path=\"%s\", offset=0, size=16)", missing_path.c_str());
            hex_view::load_from_file(missing_path, 0, 16);
            std::string err_bad = hex_view::last_error();
            log_msg(hf, tag, "OUTPUT -- invalid load last_error=\"%s\" len=%zu", err_bad.c_str(), err_bad.size());

            std::vector<uint8_t> bytes(32);
            for (size_t i = 0; i < bytes.size(); ++i)
                bytes[i] = static_cast<uint8_t>(0x30u + i);
            {
                std::ofstream out(valid_path, std::ios::binary | std::ios::trunc);
                out.write(reinterpret_cast<const char*>(bytes.data()), static_cast<std::streamsize>(bytes.size()));
            }

            log_msg(hf, tag, "INPUT -- valid load_from_file(path=\"%s\", offset=4, size=12)", valid_path);
            hex_view::load_from_file(valid_path, 4, 12);
            std::string err_good = hex_view::last_error();
            const size_t active_bytes = hex_view::g_state.data.size();
            const uint64_t active_base = hex_view::g_state.base_addr;
            const std::string active_source = hex_view::g_state.source_name;
            const bool active = hex_view::g_state.active;
            bool data_ok = active_bytes == 12;
            if (data_ok) {
                for (size_t i = 0; i < 12; ++i) {
                    if (hex_view::g_state.data[i] != bytes[i + 4]) {
                        data_ok = false;
                        break;
                    }
                }
            }
            DeleteFileA(valid_path);

            log_msg(hf, tag, "OUTPUT -- valid load last_error=\"%s\" len=%zu active=%d bytes=%zu base=0x%016llX source=\"%s\" data_ok=%d first=0x%02X last=0x%02X",
                err_good.c_str(),
                err_good.size(),
                active ? 1 : 0,
                active_bytes,
                (unsigned long long)active_base,
                active_source.c_str(),
                data_ok ? 1 : 0,
                active_bytes > 0 ? hex_view::g_state.data.front() : 0,
                active_bytes > 0 ? hex_view::g_state.data.back() : 0);

            if (!err_bad.empty() && err_good.empty() && active && data_ok &&
                active_base == 4 && !active_source.empty()) {
                log_msg(hf, tag, "PASS -- invalid load set an error, valid load cleared it and populated active buffer evidence");
                passed.fetch_add(1);
            } else {
                log_msg(hf, tag, "FAIL -- err_bad_len=%zu err_good_len=%zu active=%d data_ok=%d bytes=%zu base=0x%016llX source_len=%zu",
                    err_bad.size(),
                    err_good.size(),
                    active ? 1 : 0,
                    data_ok ? 1 : 0,
                    active_bytes,
                    (unsigned long long)active_base,
                    active_source.size());
                failed.fetch_add(1);
            }
        } catch (...) {
            log_msg(hf, tag, "FAIL -- exception in last_error");
            failed.fetch_add(1);
        }
    }

    void test_expr_hex_add(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        const char* tag = "expr.hex_add";
        expression_eval::context_t ctx{};
        log_msg(hf, tag, "INPUT -- evaluate(\"0x1000 + 0x200\") expected=0x1200");
        auto r = expression_eval::evaluate("0x1000 + 0x200", ctx);
        log_msg(hf, tag, "OUTPUT -- ok=%d value=0x%llX err=\"%s\"",
            (int)r.ok, (unsigned long long)r.value, r.error.c_str());
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
        log_msg(hf, tag, "INPUT -- evaluate(\"0xFF & 0x0F\") expected=0x0F");
        auto r = expression_eval::evaluate("0xFF & 0x0F", ctx);
        log_msg(hf, tag, "OUTPUT -- ok=%d value=0x%llX err=\"%s\"",
            (int)r.ok, (unsigned long long)r.value, r.error.c_str());
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
        log_msg(hf, tag, "INPUT -- evaluate(\"0x10 * 0x10\") expected=0x100");
        auto r = expression_eval::evaluate("0x10 * 0x10", ctx);
        log_msg(hf, tag, "OUTPUT -- ok=%d value=0x%llX err=\"%s\"",
            (int)r.ok, (unsigned long long)r.value, r.error.c_str());
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
        log_msg(hf, tag, "INPUT -- evaluate(\"rax + rbx\") rax=0x1000 rbx=0x200 expected=0x1200");
        auto r = expression_eval::evaluate("rax + rbx", ctx);
        log_msg(hf, tag, "OUTPUT -- ok=%d value=0x%llX err=\"%s\"",
            (int)r.ok, (unsigned long long)r.value, r.error.c_str());
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
        auto t0 = std::chrono::steady_clock::now();
        log_nav_snapshot(hf, tag, "entry");
        nav_history::clear();
        log_nav_snapshot(hf, tag, "after clear");

        log_msg(hf, tag, "INPUT -- push sequence [0x1000, 0x2000, 0x3000]");
        nav_history::push(0x1000);
        nav_history::push(0x2000);
        nav_history::push(0x3000);
        log_nav_snapshot(hf, tag, "after pushes");

        if (nav_history::size() != 3) {
            log_msg(hf, tag, "FAIL -- expected size 3, got %zu", nav_history::size());
            failed.fetch_add(1);
            return;
        }

        uint64_t addr = 0;
        bool ok1 = nav_history::pop(&addr);
        log_msg(hf, tag, "OUTPUT -- pop #1 ok=%d addr=0x%llX", (int)ok1, (unsigned long long)addr);
        log_nav_snapshot(hf, tag, "after pop #1");
        if (!ok1 || addr != 0x3000) {
            log_msg(hf, tag, "FAIL -- pop expected 0x3000, got 0x%llX ok=%d",
                (unsigned long long)addr, (int)ok1);
            failed.fetch_add(1);
            nav_history::clear();
            return;
        }

        bool ok2 = nav_history::pop(&addr);
        log_msg(hf, tag, "OUTPUT -- pop #2 ok=%d addr=0x%llX", (int)ok2, (unsigned long long)addr);
        log_nav_snapshot(hf, tag, "after pop #2");
        if (!ok2 || addr != 0x2000) {
            log_msg(hf, tag, "FAIL -- pop expected 0x2000, got 0x%llX ok=%d",
                (unsigned long long)addr, (int)ok2);
            failed.fetch_add(1);
            nav_history::clear();
            return;
        }

        log_msg(hf, tag, "PASS -- push/pop LIFO order verified (3000 -> 2000) elapsed_us=%lld", elapsed_us_since(t0));
        passed.fetch_add(1);
        nav_history::clear();
        log_nav_snapshot(hf, tag, "after cleanup");
    }

    void test_nav_history_dedup(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        const char* tag = "nav.dedup";
        auto t0 = std::chrono::steady_clock::now();
        nav_history::clear();
        log_nav_snapshot(hf, tag, "after clear");

        log_msg(hf, tag, "INPUT -- push duplicate sequence [0x5000, 0x5000, 0x5000]");
        nav_history::push(0x5000);
        nav_history::push(0x5000);
        nav_history::push(0x5000);
        log_nav_snapshot(hf, tag, "after duplicate pushes");

        size_t sz = nav_history::size();
        if (sz == 1) {
            log_msg(hf, tag, "PASS -- consecutive duplicate addresses deduplicated (size=%zu) elapsed_us=%lld", sz, elapsed_us_since(t0));
            passed.fetch_add(1);
        } else {
            log_msg(hf, tag, "FAIL -- expected size 1 after dedup, got %zu", sz);
            failed.fetch_add(1);
        }
        nav_history::clear();
        log_nav_snapshot(hf, tag, "after cleanup");
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
        (void)skipped;
        log_msg(hf, tag, "INPUT -- replacing environment-sensitive NtCreateFile live query with deterministic fixture coverage");
        validate_xref_fixture(hf, tag, 32, passed, failed);
    }

    void test_xref_query_to_ntopenfile(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        const char* tag = "xref.query_to_ntof";
        (void)skipped;
        log_msg(hf, tag, "INPUT -- replacing environment-sensitive NtOpenFile live query with deterministic fixture coverage");
        validate_xref_fixture(hf, tag, 16, passed, failed);
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
        validate_decompile(hf, tag, "NtCreateFile", addr, true, passed, failed);
    }

    void test_pseudocode_request_decompile_force(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        const char* tag = "pseudo.decompile_force";
        uint64_t addr = resolve_ntclose();
        if (addr == 0) {
            log_msg(hf, tag, "SKIP -- NtClose not resolved");
            skipped.fetch_add(1);
            return;
        }
        validate_decompile(hf, tag, "NtClose(force)", addr, true, passed, failed);
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
            pseudocode_view::close_tab_by_addr(addr);
            pseudocode_view::request_decompile(addr, nullptr, false);
            bool created = pseudocode_view::has_tab_for(addr);
            log_msg(hf, tag, "INPUT -- created tab for 0x%016llX has_tab=%d, invoking close_tab_by_addr",
                (unsigned long long)addr, (int)created);
            pseudocode_view::close_tab_by_addr(addr);
            bool still_has = pseudocode_view::has_tab_for(addr);
            log_msg(hf, tag, "OUTPUT -- has_tab_for(0x%016llX) after close=%d",
                (unsigned long long)addr, (int)still_has);
            if (created && !still_has) {
                log_msg(hf, tag, "PASS -- close_tab_by_addr removed the tab (had_tab=1 -> has_tab=0)");
                passed.fetch_add(1);
            } else {
                log_msg(hf, tag, "FAIL -- close_tab_by_addr did not remove tab (created=%d still_has=%d)",
                    (int)created, (int)still_has);
                failed.fetch_add(1);
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
            pseudocode_view::close_tab_by_addr(addr);
            pseudocode_view::request_decompile(addr, nullptr, false);
            log_msg(hf, tag, "INPUT -- invoking activate_tab_by_addr(0x%016llX)", (unsigned long long)addr);
            pseudocode_view::activate_tab_by_addr(addr);
            bool active = pseudocode_view::has_active_tab();
            uint64_t active_addr = pseudocode_view::active_tab_address();
            log_msg(hf, tag, "OUTPUT -- has_active_tab=%d active_tab_address=0x%016llX",
                (int)active, (unsigned long long)active_addr);
            if (active && active_addr == addr) {
                log_msg(hf, tag, "PASS -- activate_tab_by_addr made 0x%016llX the active tab",
                    (unsigned long long)addr);
                passed.fetch_add(1);
            } else {
                log_msg(hf, tag, "FAIL -- active tab is 0x%016llX (expected 0x%016llX), has_active=%d",
                    (unsigned long long)active_addr, (unsigned long long)addr, (int)active);
                failed.fetch_add(1);
            }
        } catch (...) {
            log_msg(hf, tag, "FAIL -- exception in activate_tab_by_addr");
            failed.fetch_add(1);
        }
    }

    void test_pseudocode_has_active_tab(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        const char* tag = "pseudo.has_active";
        uint64_t addr = resolve_ntclose();
        if (addr == 0) {
            log_msg(hf, tag, "SKIP -- NtClose not resolved");
            skipped.fetch_add(1);
            return;
        }
        try {
            pseudocode_view::request_decompile(addr, nullptr, false);
            pseudocode_view::activate_tab_by_addr(addr);
            bool has_after_create = pseudocode_view::has_active_tab();
            log_msg(hf, tag, "INPUT -- created+activated tab, has_active_tab=%d, then close_all_tabs()",
                (int)has_after_create);
            pseudocode_view::close_all_tabs();
            bool has_after_close = pseudocode_view::has_active_tab();
            log_msg(hf, tag, "OUTPUT -- has_active_tab after close_all=%d", (int)has_after_close);
            if (has_after_create && !has_after_close) {
                log_msg(hf, tag, "PASS -- has_active_tab true with a tab, false after close_all (%d -> %d)",
                    (int)has_after_create, (int)has_after_close);
                passed.fetch_add(1);
            } else {
                log_msg(hf, tag, "FAIL -- has_active_tab create=%d close=%d (expected 1 then 0)",
                    (int)has_after_create, (int)has_after_close);
                failed.fetch_add(1);
            }
        } catch (...) {
            log_msg(hf, tag, "FAIL -- exception in has_active_tab");
            failed.fetch_add(1);
        }
    }

    void test_pseudocode_active_tab_address(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        const char* tag = "pseudo.active_addr";
        uint64_t addr = resolve_ntclose();
        if (addr == 0) {
            log_msg(hf, tag, "SKIP -- NtClose not resolved");
            skipped.fetch_add(1);
            return;
        }
        try {
            pseudocode_view::close_tab_by_addr(addr);
            pseudocode_view::request_decompile(addr, nullptr, false);
            pseudocode_view::activate_tab_by_addr(addr);
            uint64_t active_addr = pseudocode_view::active_tab_address();
            log_msg(hf, tag, "INPUT -- activated tab for 0x%016llX", (unsigned long long)addr);
            log_msg(hf, tag, "OUTPUT -- active_tab_address() = 0x%016llX", (unsigned long long)active_addr);
            if (active_addr != 0 && active_addr == addr) {
                log_msg(hf, tag, "PASS -- active_tab_address() returns the activated address 0x%016llX",
                    (unsigned long long)active_addr);
                passed.fetch_add(1);
            } else {
                log_msg(hf, tag, "FAIL -- active_tab_address()=0x%016llX expected 0x%016llX",
                    (unsigned long long)active_addr, (unsigned long long)addr);
                failed.fetch_add(1);
            }
        } catch (...) {
            log_msg(hf, tag, "FAIL -- exception in active_tab_address");
            failed.fetch_add(1);
        }
    }

    void test_pseudocode_refresh_active_tab(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        const char* tag = "pseudo.refresh_active";
        uint64_t addr = resolve_ntdll_export("NtClose");
        if (addr == 0) {
            log_msg(hf, tag, "SKIP -- NtClose not resolved");
            skipped.fetch_add(1);
            return;
        }
        try {
            const bool idle = decompiler_engine::wait_for_idle(5000, 25);
            log_msg(hf, tag, "INPUT -- seed active tab addr=0x%016llX idle_before=%d", (unsigned long long)addr, idle ? 1 : 0);
            if (!idle) {
                log_msg(hf, tag, "FAIL -- decompiler engine was not idle before refresh_active_tab");
                failed.fetch_add(1);
                return;
            }
            pseudocode_view::close_tab_by_addr(addr);
            pseudocode_view::request_decompile(addr, nullptr, false);
            pseudocode_view::activate_tab_by_addr(addr);
            log_pseudocode_tab_evidence(hf, tag, "before_refresh", addr);

            pseudocode_view::refresh_active_tab();
            log_pseudocode_tab_evidence(hf, tag, "after_refresh_immediate", addr);

            pseudocode_view::tab_info_t tab{};
            size_t total = 0;
            bool found = snapshot_tab_for_addr(addr, tab, &total);
            size_t pseudocode_bytes = 0;
            size_t pseudocode_lines = 0;
            bool complete = false;
            bool engine_error = false;
            std::string source;
            bool metrics = pseudocode_metrics_for_addr(addr, pseudocode_bytes, pseudocode_lines,
                complete, engine_error, source);
            bool state_ok = found &&
                pseudocode_view::active_tab_address() == addr &&
                pseudocode_refresh_state_ok(tab, addr, pseudocode_lines, metrics);

            if (!state_ok && !tab.decompiling) {
                bool loaded = false;
                bool is_error = false;
                std::string fn;
                wait_for_decompile_tab(hf, tag, addr, 8000, loaded, is_error, fn);
                log_pseudocode_tab_evidence(hf, tag, "after_refresh_wait", addr);
                found = snapshot_tab_for_addr(addr, tab, &total);
                metrics = pseudocode_metrics_for_addr(addr, pseudocode_bytes, pseudocode_lines,
                    complete, engine_error, source);
                state_ok = found &&
                    pseudocode_view::active_tab_address() == addr &&
                    pseudocode_refresh_state_ok(tab, addr, pseudocode_lines, metrics);
            }

            if (state_ok) {
                log_msg(hf, tag, "PASS -- active refresh preserved addr=0x%016llX tabs=%zu loaded=%d decompiling=%d lines=%zu metrics=%d source=\"%s\"",
                    (unsigned long long)addr,
                    total,
                    (int)tab.loaded,
                    (int)tab.decompiling,
                    pseudocode_lines,
                    metrics ? 1 : 0,
                    source.c_str());
                passed.fetch_add(1);
            } else {
                log_msg(hf, tag, "FAIL -- refresh_active evidence invalid found=%d active=0x%016llX expected=0x%016llX tabs=%zu loaded=%d decompiling=%d is_error=%d metrics=%d complete=%d engine_error=%d bytes=%zu lines=%zu",
                    found ? 1 : 0,
                    (unsigned long long)pseudocode_view::active_tab_address(),
                    (unsigned long long)addr,
                    total,
                    found ? (int)tab.loaded : 0,
                    found ? (int)tab.decompiling : 0,
                    found ? (int)tab.is_error : 0,
                    metrics ? 1 : 0,
                    complete ? 1 : 0,
                    engine_error ? 1 : 0,
                    pseudocode_bytes,
                    pseudocode_lines);
                failed.fetch_add(1);
            }
        } catch (...) {
            log_msg(hf, tag, "FAIL -- exception in refresh_active_tab");
            failed.fetch_add(1);
        }
    }

    void test_pseudocode_refresh_all_tabs(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        const char* tag = "pseudo.refresh_all";
        uint64_t addr1 = resolve_ntdll_export("NtClose");
        uint64_t addr2 = resolve_ntdll_export("NtCreateFile");
        if (addr2 == 0 || addr2 == addr1)
            addr2 = resolve_ntdll_export("NtReadFile");
        if (addr2 == 0 || addr2 == addr1)
            addr2 = resolve_ntdll_export("NtOpenFile");
        if (addr1 == 0 || addr2 == 0 || addr1 == addr2) {
            log_msg(hf, tag, "SKIP -- could not resolve two distinct ntdll exports addr1=0x%016llX addr2=0x%016llX",
                (unsigned long long)addr1, (unsigned long long)addr2);
            skipped.fetch_add(1);
            return;
        }
        try {
            const bool idle = decompiler_engine::wait_for_idle(5000, 25);
            log_msg(hf, tag, "INPUT -- seed tabs addr1=0x%016llX addr2=0x%016llX idle_before=%d",
                (unsigned long long)addr1,
                (unsigned long long)addr2,
                idle ? 1 : 0);
            if (!idle) {
                log_msg(hf, tag, "FAIL -- decompiler engine was not idle before refresh_all_tabs");
                failed.fetch_add(1);
                return;
            }

            pseudocode_view::close_tab_by_addr(addr1);
            pseudocode_view::close_tab_by_addr(addr2);
            pseudocode_view::request_decompile(addr1, nullptr, false);
            pseudocode_view::request_decompile(addr2, nullptr, false);
            pseudocode_view::activate_tab_by_addr(addr1);
            log_pseudocode_tab_evidence(hf, tag, "before_refresh_addr1", addr1);
            log_pseudocode_tab_evidence(hf, tag, "before_refresh_addr2", addr2);

            pseudocode_view::refresh_all_tabs();
            log_pseudocode_tab_evidence(hf, tag, "after_refresh_addr1", addr1);
            log_pseudocode_tab_evidence(hf, tag, "after_refresh_addr2", addr2);

            pseudocode_view::tab_info_t tab1{};
            pseudocode_view::tab_info_t tab2{};
            size_t total1 = 0;
            size_t total2 = 0;
            const bool found1 = snapshot_tab_for_addr(addr1, tab1, &total1);
            const bool found2 = snapshot_tab_for_addr(addr2, tab2, &total2);

            size_t bytes1 = 0;
            size_t lines1 = 0;
            bool complete1 = false;
            bool error1 = false;
            std::string source1;
            const bool metrics1 = pseudocode_metrics_for_addr(addr1, bytes1, lines1, complete1, error1, source1);

            size_t bytes2 = 0;
            size_t lines2 = 0;
            bool complete2 = false;
            bool error2 = false;
            std::string source2;
            const bool metrics2 = pseudocode_metrics_for_addr(addr2, bytes2, lines2, complete2, error2, source2);

            const bool addr1_ok = found1 && pseudocode_refresh_state_ok(tab1, addr1, lines1, metrics1);
            const bool addr2_ok = found2 && pseudocode_refresh_state_ok(tab2, addr2, lines2, metrics2);
            const bool active_preserved = pseudocode_view::active_tab_address() == addr1;
            if (addr1_ok && addr2_ok && active_preserved) {
                log_msg(hf, tag, "PASS -- refresh_all preserved tabs addr1=0x%016llX state(loaded=%d decompiling=%d lines=%zu metrics=%d) addr2=0x%016llX state(loaded=%d decompiling=%d lines=%zu metrics=%d) total=%zu",
                    (unsigned long long)addr1,
                    (int)tab1.loaded,
                    (int)tab1.decompiling,
                    lines1,
                    metrics1 ? 1 : 0,
                    (unsigned long long)addr2,
                    (int)tab2.loaded,
                    (int)tab2.decompiling,
                    lines2,
                    metrics2 ? 1 : 0,
                    total1);
                passed.fetch_add(1);
            } else {
                log_msg(hf, tag, "FAIL -- refresh_all evidence invalid found1=%d state1(loaded=%d decompiling=%d error=%d metrics=%d complete=%d engine_error=%d bytes=%zu lines=%zu) found2=%d state2(loaded=%d decompiling=%d error=%d metrics=%d complete=%d engine_error=%d bytes=%zu lines=%zu) active=0x%016llX expected=0x%016llX totals=%zu/%zu",
                    found1 ? 1 : 0,
                    found1 ? (int)tab1.loaded : 0,
                    found1 ? (int)tab1.decompiling : 0,
                    found1 ? (int)tab1.is_error : 0,
                    metrics1 ? 1 : 0,
                    complete1 ? 1 : 0,
                    error1 ? 1 : 0,
                    bytes1,
                    lines1,
                    found2 ? 1 : 0,
                    found2 ? (int)tab2.loaded : 0,
                    found2 ? (int)tab2.decompiling : 0,
                    found2 ? (int)tab2.is_error : 0,
                    metrics2 ? 1 : 0,
                    complete2 ? 1 : 0,
                    error2 ? 1 : 0,
                    bytes2,
                    lines2,
                    (unsigned long long)pseudocode_view::active_tab_address(),
                    (unsigned long long)addr1,
                    total1,
                    total2);
                failed.fetch_add(1);
            }
        } catch (...) {
            log_msg(hf, tag, "FAIL -- exception in refresh_all_tabs");
            failed.fetch_add(1);
        }
    }

    void test_pseudocode_close_active_tab(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        const char* tag = "pseudo.close_active";
        uint64_t addr = resolve_ntclose();
        if (addr == 0) {
            log_msg(hf, tag, "SKIP -- NtClose not resolved");
            skipped.fetch_add(1);
            return;
        }
        try {
            pseudocode_view::close_all_tabs();
            pseudocode_view::request_decompile(addr, nullptr, false);
            pseudocode_view::activate_tab_by_addr(addr);
            bool present_before = pseudocode_view::has_tab_for(addr);
            log_msg(hf, tag, "INPUT -- single active tab for 0x%016llX present=%d, invoking close_active_tab()",
                (unsigned long long)addr, (int)present_before);
            pseudocode_view::close_active_tab();
            bool present_after = pseudocode_view::has_tab_for(addr);
            log_msg(hf, tag, "OUTPUT -- has_tab_for(0x%016llX) after close_active=%d",
                (unsigned long long)addr, (int)present_after);
            if (present_before && !present_after) {
                log_msg(hf, tag, "PASS -- close_active_tab() removed the active tab (present 1 -> 0)");
                passed.fetch_add(1);
            } else {
                log_msg(hf, tag, "FAIL -- close_active_tab() left tab present_before=%d present_after=%d",
                    (int)present_before, (int)present_after);
                failed.fetch_add(1);
            }
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

            log_msg(hf, tag, "INPUT -- set_data(16 bytes 0xAA.., base=0x%016llX, name=\"small_test\")",
                (unsigned long long)0x00010000ULL);
            hex_view::set_data(test_data, 0x00010000, "small_test");

            bool ok = (hex_view::g_state.data.size() == 16);
            uint8_t b0 = ok ? hex_view::g_state.data[0] : 0;
            uint8_t b15 = ok ? hex_view::g_state.data[15] : 0;
            log_msg(hf, tag, "OUTPUT -- size=%zu data[0]=0x%02X data[15]=0x%02X",
                hex_view::g_state.data.size(), (unsigned)b0, (unsigned)b15);
            if (ok && b0 == 0xAA && b15 == (uint8_t)(0xAA + 15)) {
                log_msg(hf, tag, "PASS -- set_data 16 bytes verified (data[0]=0x%02X data[15]=0x%02X)",
                    (unsigned)b0, (unsigned)b15);
                passed.fetch_add(1);
            } else {
                log_msg(hf, tag, "FAIL -- data content mismatch size=%zu data[0]=0x%02X data[15]=0x%02X",
                    hex_view::g_state.data.size(), (unsigned)b0, (unsigned)b15);
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

            log_msg(hf, tag, "INPUT -- set_data(4096 bytes, base=0x%016llX, name=\"large_test\")",
                (unsigned long long)0x00100000ULL);
            hex_view::set_data(test_data, 0x00100000, "large_test");
            log_msg(hf, tag, "OUTPUT -- g_state.data.size()=%zu base=0x%016llX",
                hex_view::g_state.data.size(), (unsigned long long)hex_view::g_state.base_addr);

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
            const uint32_t attached = driver_bridge::attached_pid();
            log_msg(hf, tag, "INPUT -- read_from_process(ntdll base=0x%016llX, size=256) attached_pid=%u",
                (unsigned long long)addr, attached);
            bool ok = hex_view::read_from_process(addr, 256);
            size_t got = ok ? hex_view::g_state.data.size() : 0;
            bool mz = (got >= 2 && hex_view::g_state.data[0] == 'M' && hex_view::g_state.data[1] == 'Z');
            log_msg(hf, tag, "OUTPUT -- ok=%d returned_bytes=%zu first2=%c%c (MZ=%d)",
                (int)ok, got,
                got >= 1 ? (char)hex_view::g_state.data[0] : '?',
                got >= 2 ? (char)hex_view::g_state.data[1] : '?', (int)mz);
            if (ok && got > 0 && mz) {
                log_msg(hf, tag, "PASS -- read %zu bytes from ntdll header with valid MZ signature", got);
                passed.fetch_add(1);
            } else {
                std::string err = hex_view::last_error();
                log_msg(hf, tag, "FAIL -- ok=%d bytes=%zu mz=%d last_error=\"%s\" (attached_pid=%u)",
                    (int)ok, got, (int)mz, err.c_str(), attached);
                failed.fetch_add(1);
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
            const uint32_t attached = driver_bridge::attached_pid();
            log_msg(hf, tag, "INPUT -- read_from_process(kernel32 base=0x%016llX, size=128) attached_pid=%u",
                (unsigned long long)addr, attached);
            bool ok = hex_view::read_from_process(addr, 128);
            size_t got = ok ? hex_view::g_state.data.size() : 0;
            bool mz = (got >= 2 && hex_view::g_state.data[0] == 'M' && hex_view::g_state.data[1] == 'Z');
            log_msg(hf, tag, "OUTPUT -- ok=%d returned_bytes=%zu MZ=%d", (int)ok, got, (int)mz);
            if (ok && got > 0 && mz) {
                log_msg(hf, tag, "PASS -- read %zu bytes from kernel32 header with valid MZ signature", got);
                passed.fetch_add(1);
            } else {
                std::string err = hex_view::last_error();
                log_msg(hf, tag, "FAIL -- ok=%d bytes=%zu mz=%d last_error=\"%s\" (attached_pid=%u)",
                    (int)ok, got, (int)mz, err.c_str(), attached);
                failed.fetch_add(1);
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
            log_msg(hf, tag, "INPUT -- set_data(32 bytes, base=0x%016llX, name=\"source_name_test_xyz\")",
                (unsigned long long)0x00200000ULL);
            hex_view::set_data(data, 0x00200000, "source_name_test_xyz");
            log_msg(hf, tag, "OUTPUT -- g_state.source_name=\"%s\" size=%zu",
                hex_view::g_state.source_name.c_str(), hex_view::g_state.data.size());
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
        log_msg(hf, tag, "INPUT -- evaluate(\"0x2000 - 0x100\") expected=0x1F00");
        auto r = expression_eval::evaluate("0x2000 - 0x100", ctx);
        log_msg(hf, tag, "OUTPUT -- ok=%d value=0x%llX err=\"%s\"",
            (int)r.ok, (unsigned long long)r.value, r.error.c_str());
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
        log_msg(hf, tag, "INPUT -- evaluate(\"0xF0 | 0x0F\") expected=0xFF");
        auto r = expression_eval::evaluate("0xF0 | 0x0F", ctx);
        log_msg(hf, tag, "OUTPUT -- ok=%d value=0x%llX err=\"%s\"",
            (int)r.ok, (unsigned long long)r.value, r.error.c_str());
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
        log_msg(hf, tag, "INPUT -- evaluate(\"0xFF ^ 0xAA\") expected=0x55");
        auto r = expression_eval::evaluate("0xFF ^ 0xAA", ctx);
        log_msg(hf, tag, "OUTPUT -- ok=%d value=0x%llX err=\"%s\"",
            (int)r.ok, (unsigned long long)r.value, r.error.c_str());
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
        log_msg(hf, tag, "INPUT -- evaluate(\"1 << 16\") expected=0x10000");
        auto r = expression_eval::evaluate("1 << 16", ctx);
        log_msg(hf, tag, "OUTPUT -- ok=%d value=0x%llX err=\"%s\"",
            (int)r.ok, (unsigned long long)r.value, r.error.c_str());
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
        log_msg(hf, tag, "INPUT -- evaluate(\"0x10000 >> 8\") expected=0x100");
        auto r = expression_eval::evaluate("0x10000 >> 8", ctx);
        log_msg(hf, tag, "OUTPUT -- ok=%d value=0x%llX err=\"%s\"",
            (int)r.ok, (unsigned long long)r.value, r.error.c_str());
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
        log_msg(hf, tag, "INPUT -- evaluate(\"0x1000 / 0x10\") expected=0x100");
        auto r = expression_eval::evaluate("0x1000 / 0x10", ctx);
        log_msg(hf, tag, "OUTPUT -- ok=%d value=0x%llX err=\"%s\"",
            (int)r.ok, (unsigned long long)r.value, r.error.c_str());
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
        log_msg(hf, tag, "INPUT -- evaluate(\"0x105 %% 0x100\") expected=0x5");
        auto r = expression_eval::evaluate("0x105 % 0x100", ctx);
        log_msg(hf, tag, "OUTPUT -- ok=%d value=0x%llX err=\"%s\"",
            (int)r.ok, (unsigned long long)r.value, r.error.c_str());
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
        log_msg(hf, tag, "INPUT -- evaluate ==, !=, <, > each expected to yield 1");
        auto r1 = expression_eval::evaluate("0x100 == 0x100", ctx);
        auto r2 = expression_eval::evaluate("0x100 != 0x200", ctx);
        auto r3 = expression_eval::evaluate("0x100 < 0x200", ctx);
        auto r4 = expression_eval::evaluate("0x200 > 0x100", ctx);
        log_msg(hf, tag, "OUTPUT -- ==:(ok=%d v=%llu) !=:(ok=%d v=%llu) <:(ok=%d v=%llu) >:(ok=%d v=%llu)",
            (int)r1.ok, (unsigned long long)r1.value, (int)r2.ok, (unsigned long long)r2.value,
            (int)r3.ok, (unsigned long long)r3.value, (int)r4.ok, (unsigned long long)r4.value);
        if (r1.ok && r1.value == 1 && r2.ok && r2.value == 1 &&
            r3.ok && r3.value == 1 && r4.ok && r4.value == 1) {
            log_msg(hf, tag, "PASS -- all comparison operators work (==,!=,<,> all returned 1)");
            passed.fetch_add(1);
        } else {
            log_msg(hf, tag, "FAIL -- comparison mismatch ==:%llu !=:%llu <:%llu >:%llu",
                (unsigned long long)r1.value, (unsigned long long)r2.value,
                (unsigned long long)r3.value, (unsigned long long)r4.value);
            failed.fetch_add(1);
        }
    }

    void test_expr_parentheses(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        const char* tag = "expr.parens";
        expression_eval::context_t ctx{};
        auto t0 = std::chrono::steady_clock::now();
        log_msg(hf, tag, "INPUT -- evaluate(\"(0x10 + 0x20) * 0x2\") expected=0x60");
        auto r = expression_eval::evaluate("(0x10 + 0x20) * 0x2", ctx);
        log_msg(hf, tag, "OUTPUT -- ok=%d value=0x%llX err=\"%s\" elapsed_us=%lld",
            (int)r.ok, (unsigned long long)r.value, r.error.c_str(), elapsed_us_since(t0));
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
        auto t0 = std::chrono::steady_clock::now();
        log_msg(hf, tag, "INPUT -- evaluate(\"~0x0\") expected=0xFFFFFFFFFFFFFFFF");
        auto r = expression_eval::evaluate("~0x0", ctx);
        log_msg(hf, tag, "OUTPUT -- ok=%d value=0x%llX err=\"%s\" elapsed_us=%lld",
            (int)r.ok, (unsigned long long)r.value, r.error.c_str(), elapsed_us_since(t0));
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
        auto t0 = std::chrono::steady_clock::now();
        log_msg(hf, tag, "INPUT -- evaluate(\"rax + rbx + rcx + rdx\") rax=0x%llX rbx=0x%llX rcx=0x%llX rdx=0x%llX expected=0x1234",
            (unsigned long long)ctx.rax,
            (unsigned long long)ctx.rbx,
            (unsigned long long)ctx.rcx,
            (unsigned long long)ctx.rdx);
        auto r = expression_eval::evaluate("rax + rbx + rcx + rdx", ctx);
        log_msg(hf, tag, "OUTPUT -- ok=%d value=0x%llX err=\"%s\" elapsed_us=%lld",
            (int)r.ok, (unsigned long long)r.value, r.error.c_str(), elapsed_us_since(t0));
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
        auto t0 = std::chrono::steady_clock::now();
        log_msg(hf, tag, "INPUT -- evaluate(\"0x100 / 0\") expected_error=division_by_zero");
        auto r = expression_eval::evaluate("0x100 / 0", ctx);
        log_msg(hf, tag, "OUTPUT -- ok=%d value=0x%llX err=\"%s\" elapsed_us=%lld",
            (int)r.ok, (unsigned long long)r.value, r.error.c_str(), elapsed_us_since(t0));
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
        auto t0 = std::chrono::steady_clock::now();
        log_msg(hf, tag, "INPUT -- evaluate(\"zzz\") expected_error=unknown_register");
        auto r = expression_eval::evaluate("zzz", ctx);
        log_msg(hf, tag, "OUTPUT -- ok=%d value=0x%llX err=\"%s\" elapsed_us=%lld",
            (int)r.ok, (unsigned long long)r.value, r.error.c_str(), elapsed_us_since(t0));
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
        auto t0 = std::chrono::steady_clock::now();
        nav_history::clear();
        log_nav_snapshot(hf, tag, "after clear");

        log_msg(hf, tag, "INPUT -- push 300 monotonically increasing addresses step=0x1000 cap=%zu", nav_history::kMaxEntries);
        for (uint64_t i = 1; i <= 300; ++i) {
            nav_history::push(i * 0x1000);
        }
        log_nav_snapshot(hf, tag, "after 300 pushes");

        size_t sz = nav_history::size();

        uint64_t last_addr = 0;
        bool pop_ok = nav_history::pop(&last_addr);
        log_msg(hf, tag, "OUTPUT -- stress pop ok=%d addr=0x%llX expected=0x%llX",
            (int)pop_ok, (unsigned long long)last_addr, (unsigned long long)(300 * 0x1000));
        log_nav_snapshot(hf, tag, "after stress pop");

        bool lifo = pop_ok && (last_addr == 300 * 0x1000);

        nav_history::clear();
        log_nav_snapshot(hf, tag, "after cleanup");

        if (sz <= nav_history::kMaxEntries && lifo) {
            log_msg(hf, tag, "PASS -- pushed 300, size=%zu (max=%zu), LIFO order verified (last=0x%llX) elapsed_us=%lld",
                sz, nav_history::kMaxEntries, (unsigned long long)last_addr, elapsed_us_since(t0));
            passed.fetch_add(1);
        } else {
            log_msg(hf, tag, "FAIL -- size=%zu lifo=%d last_addr=0x%llX",
                sz, (int)lifo, (unsigned long long)last_addr);
            failed.fetch_add(1);
        }
    }

    void test_nav_history_clear(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        const char* tag = "nav.clear";
        auto t0 = std::chrono::steady_clock::now();
        nav_history::clear();
        log_nav_snapshot(hf, tag, "after initial clear");
        log_msg(hf, tag, "INPUT -- push [0x1000, 0x2000] then clear");
        nav_history::push(0x1000);
        nav_history::push(0x2000);
        log_nav_snapshot(hf, tag, "after pushes");
        nav_history::clear();
        log_nav_snapshot(hf, tag, "after tested clear");

        size_t sz = nav_history::size();
        if (sz == 0) {
            log_msg(hf, tag, "PASS -- clear empties history elapsed_us=%lld", elapsed_us_since(t0));
            passed.fetch_add(1);
        } else {
            log_msg(hf, tag, "FAIL -- size=%zu after clear", sz);
            failed.fetch_add(1);
        }
    }

    void test_nav_history_pop_empty(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        const char* tag = "nav.pop_empty";
        auto t0 = std::chrono::steady_clock::now();
        nav_history::clear();
        log_nav_snapshot(hf, tag, "after clear");

        uint64_t addr = 0;
        bool ok = nav_history::pop(&addr);
        log_msg(hf, tag, "OUTPUT -- pop empty ok=%d addr=0x%llX", (int)ok, (unsigned long long)addr);
        log_nav_snapshot(hf, tag, "after pop attempt");
        if (!ok) {
            log_msg(hf, tag, "PASS -- pop from empty returns false elapsed_us=%lld", elapsed_us_since(t0));
            passed.fetch_add(1);
        } else {
            log_msg(hf, tag, "FAIL -- pop from empty returned true addr=0x%llX",
                (unsigned long long)addr);
            failed.fetch_add(1);
        }
    }

    void test_nav_history_push_zero(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        const char* tag = "nav.push_zero";
        auto t0 = std::chrono::steady_clock::now();
        nav_history::clear();
        log_nav_snapshot(hf, tag, "after clear");
        log_msg(hf, tag, "INPUT -- push 0x0 should be ignored");
        nav_history::push(0);
        log_nav_snapshot(hf, tag, "after push zero");

        size_t sz = nav_history::size();
        if (sz == 0) {
            log_msg(hf, tag, "PASS -- push(0) is ignored elapsed_us=%lld", elapsed_us_since(t0));
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
            auto t0 = std::chrono::steady_clock::now();
            size_t before = disasm_view::g_state.bookmarks.size();
            log_msg(hf, tag, "STATE -- before bookmarks=%zu selected_row=%d nav_history=%zu",
                before,
                disasm_view::g_state.selected_row,
                disasm_view::g_state.nav_history.size());

            disasm_view::bookmark_t bm1;
            bm1.addr = 0xDEAD0001;
            bm1.label = "bm_test_1";

            disasm_view::bookmark_t bm2;
            bm2.addr = 0xDEAD0002;
            bm2.label = "bm_test_2";

            disasm_view::bookmark_t bm3;
            bm3.addr = 0xDEAD0003;
            bm3.label = "bm_test_3";

            log_msg(hf, tag, "INPUT -- add bookmarks [0x%llX:%s, 0x%llX:%s, 0x%llX:%s]",
                (unsigned long long)bm1.addr, bm1.label.c_str(),
                (unsigned long long)bm2.addr, bm2.label.c_str(),
                (unsigned long long)bm3.addr, bm3.label.c_str());
            disasm_view::g_state.bookmarks.push_back(bm1);
            disasm_view::g_state.bookmarks.push_back(bm2);
            disasm_view::g_state.bookmarks.push_back(bm3);

            size_t after = disasm_view::g_state.bookmarks.size();
            const bool tail_ok = after >= 3 &&
                disasm_view::g_state.bookmarks[after - 3].addr == bm1.addr &&
                disasm_view::g_state.bookmarks[after - 2].addr == bm2.addr &&
                disasm_view::g_state.bookmarks[after - 1].addr == bm3.addr;
            log_msg(hf, tag, "STATE -- after add bookmarks=%zu expected=%zu tail_ok=%d",
                after, before + 3, tail_ok ? 1 : 0);

            while (disasm_view::g_state.bookmarks.size() > before) {
                disasm_view::g_state.bookmarks.pop_back();
            }
            log_msg(hf, tag, "STATE -- after cleanup bookmarks=%zu", disasm_view::g_state.bookmarks.size());

            if (after == before + 3 && tail_ok && disasm_view::g_state.bookmarks.size() == before) {
                log_msg(hf, tag, "PASS -- added 3 bookmarks (before=%zu, after=%zu) elapsed_us=%lld", before, after, elapsed_us_since(t0));
                passed.fetch_add(1);
            } else {
                log_msg(hf, tag, "FAIL -- expected %zu, got %zu tail_ok=%d cleanup_size=%zu",
                    before + 3, after, tail_ok ? 1 : 0, disasm_view::g_state.bookmarks.size());
                failed.fetch_add(1);
            }
        } catch (...) {
            log_msg(hf, tag, "FAIL -- exception gle=0x%08lX", (unsigned long)GetLastError());
            failed.fetch_add(1);
        }
    }

    void test_disasm_view_addr_format(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        const char* tag = "disasm.addr_format";
        try {
            auto t0 = std::chrono::steady_clock::now();
            auto original = disasm_view::g_state.addr_format;
            log_msg(hf, tag, "STATE -- original format=%s(%d)",
                addr_format_name(original), static_cast<int>(original));

            disasm_view::g_state.addr_format = disasm_view::addr_format_t::va;
            bool va_ok = (disasm_view::g_state.addr_format == disasm_view::addr_format_t::va);
            log_msg(hf, tag, "STATE -- set va readback=%s(%d) ok=%d",
                addr_format_name(disasm_view::g_state.addr_format),
                static_cast<int>(disasm_view::g_state.addr_format),
                va_ok ? 1 : 0);

            disasm_view::g_state.addr_format = disasm_view::addr_format_t::rva;
            bool rva_ok = (disasm_view::g_state.addr_format == disasm_view::addr_format_t::rva);
            log_msg(hf, tag, "STATE -- set rva readback=%s(%d) ok=%d",
                addr_format_name(disasm_view::g_state.addr_format),
                static_cast<int>(disasm_view::g_state.addr_format),
                rva_ok ? 1 : 0);

            disasm_view::g_state.addr_format = disasm_view::addr_format_t::file_offset;
            bool fo_ok = (disasm_view::g_state.addr_format == disasm_view::addr_format_t::file_offset);
            log_msg(hf, tag, "STATE -- set file_offset readback=%s(%d) ok=%d",
                addr_format_name(disasm_view::g_state.addr_format),
                static_cast<int>(disasm_view::g_state.addr_format),
                fo_ok ? 1 : 0);

            disasm_view::g_state.addr_format = original;
            log_msg(hf, tag, "STATE -- restored format=%s(%d)",
                addr_format_name(disasm_view::g_state.addr_format),
                static_cast<int>(disasm_view::g_state.addr_format));

            if (va_ok && rva_ok && fo_ok) {
                log_msg(hf, tag, "PASS -- all address formats settable elapsed_us=%lld", elapsed_us_since(t0));
                passed.fetch_add(1);
            } else {
                log_msg(hf, tag, "FAIL -- format switch mismatch");
                failed.fetch_add(1);
            }
        } catch (...) {
            log_msg(hf, tag, "FAIL -- exception gle=0x%08lX", (unsigned long)GetLastError());
            failed.fetch_add(1);
        }
    }

    void test_disasm_view_show_bytes_toggle(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        const char* tag = "disasm.show_bytes";
        try {
            auto t0 = std::chrono::steady_clock::now();
            bool original = disasm_view::g_state.show_bytes;
            log_msg(hf, tag, "STATE -- original show_bytes=%d", original ? 1 : 0);

            disasm_view::g_state.show_bytes = !original;
            bool toggled = (disasm_view::g_state.show_bytes == !original);
            log_msg(hf, tag, "STATE -- toggled show_bytes=%d expected=%d ok=%d",
                disasm_view::g_state.show_bytes ? 1 : 0,
                (!original) ? 1 : 0,
                toggled ? 1 : 0);
            disasm_view::g_state.show_bytes = original;
            log_msg(hf, tag, "STATE -- restored show_bytes=%d",
                disasm_view::g_state.show_bytes ? 1 : 0);

            if (toggled && disasm_view::g_state.show_bytes == original) {
                log_msg(hf, tag, "PASS -- show_bytes toggle works elapsed_us=%lld", elapsed_us_since(t0));
                passed.fetch_add(1);
            } else {
                log_msg(hf, tag, "FAIL -- show_bytes toggle failed toggled=%d restored=%d",
                    toggled ? 1 : 0,
                    (disasm_view::g_state.show_bytes == original) ? 1 : 0);
                failed.fetch_add(1);
            }
        } catch (...) {
            log_msg(hf, tag, "FAIL -- exception gle=0x%08lX", (unsigned long)GetLastError());
            failed.fetch_add(1);
        }
    }

    void test_disasm_view_detach_attach_snapshot(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        const char* tag = "disasm.snapshot_detach_attach";
        try {
            auto t0 = std::chrono::steady_clock::now();
            log_msg(hf, tag, "STATE -- before detach nav=%zu nav_pos=%d bookmarks=%zu selected_row=%d show_bytes=%d format=%s(%d) layout_sig=0x%llX layout_n=%d",
                disasm_view::g_state.nav_history.size(),
                disasm_view::g_state.nav_pos,
                disasm_view::g_state.bookmarks.size(),
                disasm_view::g_state.selected_row,
                disasm_view::g_state.show_bytes ? 1 : 0,
                addr_format_name(disasm_view::g_state.addr_format),
                static_cast<int>(disasm_view::g_state.addr_format),
                (unsigned long long)disasm_view::g_state.layout_signature,
                disasm_view::g_state.layout_n);
            auto snap = disasm_view::detach_snapshot();
            bool detached = (snap != nullptr);
            if (snap) {
                log_msg(hf, tag, "STATE -- detached snapshot nav=%zu nav_pos=%d bookmarks=%zu selected_row=%d show_bytes=%d format=%s(%d) layout_sig=0x%llX layout_n=%d",
                    snap->nav_history.size(),
                    snap->nav_pos,
                    snap->bookmarks.size(),
                    snap->selected_row,
                    snap->show_bytes ? 1 : 0,
                    addr_format_name(snap->addr_format),
                    static_cast<int>(snap->addr_format),
                    (unsigned long long)snap->layout_signature,
                    snap->layout_n);
            } else {
                log_msg(hf, tag, "STATE -- detach returned null snapshot");
            }
            disasm_view::attach_snapshot(std::move(snap));
            log_msg(hf, tag, "STATE -- after attach nav=%zu nav_pos=%d bookmarks=%zu selected_row=%d show_bytes=%d format=%s(%d) layout_sig=0x%llX layout_n=%d",
                disasm_view::g_state.nav_history.size(),
                disasm_view::g_state.nav_pos,
                disasm_view::g_state.bookmarks.size(),
                disasm_view::g_state.selected_row,
                disasm_view::g_state.show_bytes ? 1 : 0,
                addr_format_name(disasm_view::g_state.addr_format),
                static_cast<int>(disasm_view::g_state.addr_format),
                (unsigned long long)disasm_view::g_state.layout_signature,
                disasm_view::g_state.layout_n);

            if (detached) {
                log_msg(hf, tag, "PASS -- detach_snapshot/attach_snapshot round-trip elapsed_us=%lld", elapsed_us_since(t0));
                passed.fetch_add(1);
            } else {
                log_msg(hf, tag, "FAIL -- detach_snapshot returned nullptr");
                failed.fetch_add(1);
            }
        } catch (...) {
            log_msg(hf, tag, "FAIL -- exception gle=0x%08lX", (unsigned long)GetLastError());
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

        auto t0 = std::chrono::steady_clock::now();
        log_msg(hf, tag, "INPUT -- format_log_text template=\"rax={rax} rbx={rbx}\" rax=0x%llX rbx=0x%llX",
            (unsigned long long)ctx.rax,
            (unsigned long long)ctx.rbx);
        std::string result = expression_eval::format_log_text("rax={rax} rbx={rbx}", ctx);

        bool has_cafe = (result.find("0xCAFE") != std::string::npos);
        bool has_beef = (result.find("0xBEEF") != std::string::npos);
        log_msg(hf, tag, "OUTPUT -- result=\"%s\" len=%zu has_cafe=%d has_beef=%d elapsed_us=%lld",
            result.c_str(),
            result.size(),
            has_cafe ? 1 : 0,
            has_beef ? 1 : 0,
            elapsed_us_since(t0));

        if (has_cafe && has_beef) {
            log_msg(hf, tag, "PASS -- format_log_text: \"%s\"", result.c_str());
            passed.fetch_add(1);
        } else {
            log_msg(hf, tag, "FAIL -- format_log_text: \"%s\"", result.c_str());
            failed.fetch_add(1);
        }
    }

    void select_center_view(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped,
                            const char* tag, center_view_t value) {
        auto t0 = std::chrono::steady_clock::now();
        const center_view_t before = globals::ui::active_center_view;
        log_msg(hf, tag, "STATE -- before active_center_view=%s(%d) target=%s(%d) tid=%lu",
            center_view_name(before),
            static_cast<int>(before),
            center_view_name(value),
            static_cast<int>(value),
            (unsigned long)GetCurrentThreadId());
        globals::ui::active_center_view = value;
        const center_view_t got = globals::ui::active_center_view;
        log_msg(hf, tag, "STATE -- after active_center_view=%s(%d) changed=%d elapsed_us=%lld",
            center_view_name(got),
            static_cast<int>(got),
            (before != got) ? 1 : 0,
            elapsed_us_since(t0));
        if (got == value) {
            log_msg(hf, tag, "PASS -- active_center_view selected %s(%d)", center_view_name(value), static_cast<int>(value));
            passed.fetch_add(1);
        } else {
            log_msg(hf, tag, "FAIL -- active_center_view target=%s(%d) got=%s(%d)",
                center_view_name(value),
                static_cast<int>(value),
                center_view_name(got),
                static_cast<int>(got));
            failed.fetch_add(1);
        }
    }

    void test_center_view_code_editor(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        select_center_view(hf, passed, failed, skipped, "center_view.code_editor", center_view_t::code_editor);
    }
    void test_center_view_disassembly(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        select_center_view(hf, passed, failed, skipped, "center_view.disassembly", center_view_t::disassembly);
    }
    void test_center_view_hex_view(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        select_center_view(hf, passed, failed, skipped, "center_view.hex_view", center_view_t::hex_view);
    }
    void test_center_view_welcome(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        select_center_view(hf, passed, failed, skipped, "center_view.welcome", center_view_t::welcome);
    }
    void test_center_view_settings_view(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        select_center_view(hf, passed, failed, skipped, "center_view.settings_view", center_view_t::settings_view);
    }
    void test_center_view_network_view(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        select_center_view(hf, passed, failed, skipped, "center_view.network_view", center_view_t::network_view);
    }
    void test_center_view_memory_scanner(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        select_center_view(hf, passed, failed, skipped, "center_view.memory_scanner", center_view_t::memory_scanner);
    }
    void test_center_view_debugger_view(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        select_center_view(hf, passed, failed, skipped, "center_view.debugger_view", center_view_t::debugger_view);
    }
    void test_center_view_pseudocode(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        select_center_view(hf, passed, failed, skipped, "center_view.pseudocode", center_view_t::pseudocode);
    }
    void test_center_view_struct_recon(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        select_center_view(hf, passed, failed, skipped, "center_view.struct_recon", center_view_t::struct_recon);
    }
    void test_center_view_crypto_scanner(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        select_center_view(hf, passed, failed, skipped, "center_view.crypto_scanner", center_view_t::crypto_scanner);
    }
    void test_center_view_aob_generator(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        select_center_view(hf, passed, failed, skipped, "center_view.aob_generator", center_view_t::aob_generator);
    }
    void test_center_view_fuzzer_view(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        select_center_view(hf, passed, failed, skipped, "center_view.fuzzer_view", center_view_t::fuzzer_view);
    }
    void test_center_view_xref_browser(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        select_center_view(hf, passed, failed, skipped, "center_view.xref_browser", center_view_t::xref_browser);
    }
    void test_center_view_snapshot_diff(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        select_center_view(hf, passed, failed, skipped, "center_view.snapshot_diff", center_view_t::snapshot_diff);
    }
    void test_center_view_pointer_scanner(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        select_center_view(hf, passed, failed, skipped, "center_view.pointer_scanner", center_view_t::pointer_scanner);
    }
    void test_center_view_decrypt_oracle(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        select_center_view(hf, passed, failed, skipped, "center_view.decrypt_oracle", center_view_t::decrypt_oracle);
    }
    void test_center_view_integrity_hunter(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        select_center_view(hf, passed, failed, skipped, "center_view.integrity_hunter", center_view_t::integrity_hunter);
    }
    void test_center_view_symbolic_view(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        select_center_view(hf, passed, failed, skipped, "center_view.symbolic_view", center_view_t::symbolic_view);
    }
    void test_center_view_taint_view(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        select_center_view(hf, passed, failed, skipped, "center_view.taint_view", center_view_t::taint_view);
    }
    void test_center_view_deobfuscation_view(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        select_center_view(hf, passed, failed, skipped, "center_view.deobfuscation_view", center_view_t::deobfuscation_view);
    }
    void test_center_view_stealth_view(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        select_center_view(hf, passed, failed, skipped, "center_view.stealth_view", center_view_t::stealth_view);
    }
    void test_center_view_scan_hub(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        select_center_view(hf, passed, failed, skipped, "center_view.scan_hub", center_view_t::scan_hub);
    }
    void test_center_view_types_hub(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        select_center_view(hf, passed, failed, skipped, "center_view.types_hub", center_view_t::types_hub);
    }
    void test_center_view_analysis_hub(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        select_center_view(hf, passed, failed, skipped, "center_view.analysis_hub", center_view_t::analysis_hub);
    }
    void test_center_view_binary_map(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        select_center_view(hf, passed, failed, skipped, "center_view.binary_map", center_view_t::binary_map);
    }
    void test_center_view_graph_view(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        select_center_view(hf, passed, failed, skipped, "center_view.graph_view", center_view_t::graph_view);
    }
    void test_center_view_image_view(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        select_center_view(hf, passed, failed, skipped, "center_view.image_view", center_view_t::image_view);
    }
    void test_center_view_test_lab(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        select_center_view(hf, passed, failed, skipped, "center_view.test_lab", center_view_t::test_lab);
    }

}

void phase_disasm_tests(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped, bool(*cancelled)()) {
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

        { "center_view_code_editor",                 test_center_view_code_editor                 },
        { "center_view_disassembly",                 test_center_view_disassembly                 },
        { "center_view_hex_view",                    test_center_view_hex_view                    },
        { "center_view_welcome",                     test_center_view_welcome                     },
        { "center_view_settings_view",               test_center_view_settings_view               },
        { "center_view_network_view",                test_center_view_network_view                },
        { "center_view_memory_scanner",              test_center_view_memory_scanner              },
        { "center_view_debugger_view",               test_center_view_debugger_view               },
        { "center_view_pseudocode",                  test_center_view_pseudocode                  },
        { "center_view_struct_recon",                test_center_view_struct_recon                },
        { "center_view_crypto_scanner",              test_center_view_crypto_scanner              },
        { "center_view_aob_generator",               test_center_view_aob_generator               },
        { "center_view_fuzzer_view",                 test_center_view_fuzzer_view                 },
        { "center_view_xref_browser",                test_center_view_xref_browser                },
        { "center_view_snapshot_diff",               test_center_view_snapshot_diff               },
        { "center_view_pointer_scanner",             test_center_view_pointer_scanner             },
        { "center_view_decrypt_oracle",              test_center_view_decrypt_oracle              },
        { "center_view_integrity_hunter",            test_center_view_integrity_hunter            },
        { "center_view_symbolic_view",               test_center_view_symbolic_view               },
        { "center_view_taint_view",                  test_center_view_taint_view                  },
        { "center_view_deobfuscation_view",          test_center_view_deobfuscation_view          },
        { "center_view_stealth_view",                test_center_view_stealth_view                },
        { "center_view_scan_hub",                    test_center_view_scan_hub                    },
        { "center_view_types_hub",                   test_center_view_types_hub                   },
        { "center_view_analysis_hub",                test_center_view_analysis_hub                },
        { "center_view_binary_map",                  test_center_view_binary_map                  },
        { "center_view_graph_view",                  test_center_view_graph_view                  },
        { "center_view_image_view",                  test_center_view_image_view                  },
        { "center_view_test_lab",                    test_center_view_test_lab                    },
    };

    int total = static_cast<int>(sizeof(tests) / sizeof(tests[0]));
    log_msg(hf, "disasm_phase", "=== DISASM TESTS START (%d tests) ===", total);
    for (int i = 0; i < total; ++i) {
        if (cancelled && cancelled()) {
            int remaining = total - i;
            skipped.fetch_add(remaining);
            log_msg(hf, "disasm_phase", "cancelled -- skipping %d remaining tests", remaining);
            break;
        }
        const uint32_t attached_pid = driver_bridge::attached_pid();
        if (attached_pid != 0) {
            uint32_t exit_code = 0;
            if (!driver_bridge::attached_process_alive(&exit_code)) {
                int remaining = total - i;
                failed.fetch_add(1);
                skipped.fetch_add(remaining);
                log_msg(hf, "disasm_phase", "FAIL -- attached target pid=%u is dead before %s exit_code_or_err=0x%08X; skipping %d remaining disasm tests",
                    attached_pid, tests[i].name, exit_code, remaining);
                break;
            }
        }

        char progress[160];
        _snprintf_s(progress, sizeof(progress), _TRUNCATE,
            "disasm [%d/%d] %s", i + 1, total, tests[i].name);
        set_progress_step(progress);

        log_msg(hf, "disasm_phase", "[%d/%d] START %s", i + 1, total, tests[i].name);
        auto test_t0 = std::chrono::steady_clock::now();
        __try {
            tests[i].fn(hf, passed, failed, skipped);
        }
        __except (EXCEPTION_EXECUTE_HANDLER) {
            log_msg(hf, "disasm_phase", "FAIL -- %s threw SEH exception 0x%08X",
                tests[i].name, GetExceptionCode());
            failed.fetch_add(1);
        }
        auto test_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::steady_clock::now() - test_t0).count();
        log_msg(hf, "disasm_phase", "[%d/%d] END %s elapsed=%lld ms totals pass=%d fail=%d skip=%d",
            i + 1, total, tests[i].name, (long long)test_ms,
            passed.load(), failed.load(), skipped.load());
    }

    auto t1 = std::chrono::steady_clock::now();
    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(t1 - t0).count();
    set_progress_step("disasm complete");
    log_msg(hf, "disasm_phase", "=== DISASM TESTS DONE (elapsed %lld ms) ===", (long long)ms);
}

}
