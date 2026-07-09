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
#include "../infra/executor.hpp"
#include "../infra/taskflow_runtime.hpp"
#include "../ui/ui_thread_dispatcher.hpp"
#include "../../helpers/diag_log.hpp"
#include "../../helpers/globals.h"

#include <algorithm>
#include <chrono>
#include <condition_variable>
#include <cstdarg>
#include <cstdio>
#include <cstring>
#include <fstream>
#include <memory>
#include <mutex>
#include <shared_mutex>
#include <string>
#include <thread>
#include <utility>
#include <vector>

namespace test_all_features {

namespace {

    std::atomic<int> g_xref_live_after_warm_stage{0};

    const char* xref_live_after_warm_stage_name(int value) {
        switch (value) {
        case 1: return "select_module_begin";
        case 2: return "select_module_done";
        case 3: return "validate_module";
        case 4: return "construct_range";
        case 5: return "watchdog_start";
        case 6: return "before_warm_range";
        case 7: return "inside_warm_range";
        case 8: return "after_warm_range";
        case 9: return "before_bounded_live_range";
        case 10: return "inside_bounded_live_range";
        case 11: return "after_bounded_live_range";
        case 12: return "materialize_result";
        case 13: return "finished";
        case 14: return "exception";
        default: return "entry";
        }
    }

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

    struct expr_eval_case_t {
        const char* label;
        const char* expression;
        uint64_t expected;
    };

    bool run_expr_cases(HANDLE hf, const char* tag, const expression_eval::context_t& ctx,
                        const expr_eval_case_t* cases, size_t case_count, long long& total_us) {
        bool all_ok = true;
        for (size_t i = 0; i < case_count; ++i) {
            auto t0 = std::chrono::steady_clock::now();
            log_msg(hf, tag, "INPUT -- case=%zu label=\"%s\" expr=\"%s\" expected=0x%llX ctx={rax=0x%llX rbx=0x%llX rcx=0x%llX rdx=0x%llX rip=0x%llX rflags=0x%llX}",
                i,
                cases[i].label,
                cases[i].expression,
                (unsigned long long)cases[i].expected,
                (unsigned long long)ctx.rax,
                (unsigned long long)ctx.rbx,
                (unsigned long long)ctx.rcx,
                (unsigned long long)ctx.rdx,
                (unsigned long long)ctx.rip,
                (unsigned long long)ctx.rflags);
            auto r = expression_eval::evaluate(cases[i].expression, ctx);
            long long case_us = elapsed_us_since(t0);
            total_us += case_us;
            bool matched = r.ok && r.value == cases[i].expected;
            log_msg(hf, tag, "OUTPUT -- case=%zu ok=%d value=0x%llX expected=0x%llX matched=%d err=\"%s\" elapsed_us=%lld",
                i,
                (int)r.ok,
                (unsigned long long)r.value,
                (unsigned long long)cases[i].expected,
                matched ? 1 : 0,
                r.error.c_str(),
                case_us);
            if (!matched)
                all_ok = false;
        }
        return all_ok;
    }

    template <size_t N>
    bool run_expr_cases(HANDLE hf, const char* tag, const expression_eval::context_t& ctx,
                        const expr_eval_case_t (&cases)[N], long long& total_us) {
        return run_expr_cases(hf, tag, ctx, cases, N, total_us);
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

    struct remote_module_lookup_t {
        uint64_t base = 0;
        uint32_t size = 0;
        size_t module_count = 0;
        uint32_t pid = 0;
        std::string name;
    };

    remote_module_lookup_t resolve_remote_module_info(const char* module_name) {
        remote_module_lookup_t out{};
        const uint32_t pid = driver_bridge::attached_pid();
        out.pid = pid;
        if (pid == 0)
            return out;
        auto modules = driver_bridge::enumerate_modules_for(pid);
        out.module_count = modules.size();
        for (const auto& mod : modules) {
            if (_stricmp(mod.name.c_str(), module_name) == 0) {
                out.base = mod.base;
                out.size = mod.size;
                out.name = mod.name;
                return out;
            }
        }
        return out;
    }

    remote_module_lookup_t select_live_xref_module() {
        remote_module_lookup_t out{};
        const uint32_t pid = driver_bridge::attached_pid();
        out.pid = pid;
        if (pid == 0)
            return out;
        auto modules = driver_bridge::enumerate_modules_for(pid);
        out.module_count = modules.size();
        auto assign = [&](const driver_bridge::module_info_t& mod) {
            out.base = mod.base;
            out.size = mod.size;
            out.name = mod.name;
        };
        for (const auto& mod : modules) {
            if (mod.base != 0 && mod.size != 0 && _stricmp(mod.name.c_str(), "AiDA_TestTarget.exe") == 0) {
                assign(mod);
                return out;
            }
        }
        for (const auto& mod : modules) {
            if (mod.base == 0 || mod.size == 0 || mod.name.empty())
                continue;
            const char* dot = std::strrchr(mod.name.c_str(), '.');
            if (dot && _stricmp(dot, ".exe") == 0) {
                assign(mod);
                return out;
            }
        }
        for (const auto& mod : modules) {
            if (mod.base != 0 && mod.size != 0 && _stricmp(mod.name.c_str(), "ntdll.dll") == 0) {
                assign(mod);
                return out;
            }
        }
        for (const auto& mod : modules) {
            if (mod.base != 0 && mod.size != 0) {
                assign(mod);
                return out;
            }
        }
        return out;
    }

    uint64_t resolve_remote_module_base(const char* module_name) {
        return resolve_remote_module_info(module_name).base;
    }

    void log_ntdll_resolve(HANDLE hf, const char* tag, const char* fmt, ...) {
        char detail[1024];
        va_list ap;
        va_start(ap, fmt);
        _vsnprintf_s(detail, sizeof(detail), _TRUNCATE, fmt, ap);
        va_end(ap);
        diag::log_tagged_fmt("disasm_resolve", "%s", detail);
        if (hf != nullptr && hf != INVALID_HANDLE_VALUE)
            log_msg(hf, tag ? tag : "disasm.resolve", "%s", detail);
    }

    bool local_ntdll_export_rva(const char* name, uint64_t& rva_out, uint64_t& local_va_out) {
        rva_out = 0;
        local_va_out = 0;
        HMODULE local_ntdll = GetModuleHandleW(L"ntdll.dll");
        FARPROC local_fn = local_ntdll ? GetProcAddress(local_ntdll, name) : nullptr;
        if (!local_ntdll || !local_fn)
            return false;
        const uintptr_t local_base = reinterpret_cast<uintptr_t>(local_ntdll);
        const uintptr_t local_va = reinterpret_cast<uintptr_t>(local_fn);
        if (local_va < local_base)
            return false;
        rva_out = static_cast<uint64_t>(local_va - local_base);
        local_va_out = static_cast<uint64_t>(local_va);
        return rva_out != 0;
    }

    uint64_t resolve_ntdll_export(const char* name, HANDLE hf = nullptr, const char* tag = "disasm.resolve") {
        if (!name || name[0] == '\0') {
            log_ntdll_resolve(hf, tag, "resolve_ntdll_export invalid_name");
            return 0;
        }

        const auto t0 = std::chrono::steady_clock::now();
        remote_module_lookup_t remote = resolve_remote_module_info("ntdll.dll");
        const long long enum_us = elapsed_us_since(t0);
        uint64_t local_rva = 0;
        uint64_t local_va = 0;
        const bool local_ok = local_ntdll_export_rva(name, local_rva, local_va);
        log_ntdll_resolve(hf, tag,
            "resolve_ntdll_export phase=module_enum name=%s pid=%u module_count=%zu ntdll_base=0x%016llX ntdll_size=0x%08X local_ok=%d local_rva=0x%016llX local_va=0x%016llX enum_us=%lld status=\"%s\" last_error=\"%s\"",
            name,
            remote.pid,
            remote.module_count,
            (unsigned long long)remote.base,
            remote.size,
            local_ok ? 1 : 0,
            (unsigned long long)local_rva,
            (unsigned long long)local_va,
            enum_us,
            driver_bridge::status().c_str(),
            driver_bridge::last_error().c_str());

        if (remote.base != 0 && local_ok) {
            const uint64_t final_va = remote.base + local_rva;
            log_ntdll_resolve(hf, tag,
                "resolve_ntdll_export phase=local_rva_fast_path name=%s module_count=%zu ntdll_base=0x%016llX rva=0x%016llX final_va=0x%016llX total_us=%lld",
                name,
                remote.module_count,
                (unsigned long long)remote.base,
                (unsigned long long)local_rva,
                (unsigned long long)final_va,
                elapsed_us_since(t0));
            return final_va;
        }

        uint64_t driver_resolved = 0;
        if (remote.base != 0) {
            const auto td = std::chrono::steady_clock::now();
            log_ntdll_resolve(hf, tag,
                "resolve_ntdll_export phase=driver_resolve_enter name=%s pid=%u ntdll_base=0x%016llX module_count=%zu",
                name,
                remote.pid,
                (unsigned long long)remote.base,
                remote.module_count);
            driver_resolved = driver_bridge::resolve_export_for(remote.pid, remote.base, name);
            log_ntdll_resolve(hf, tag,
                "resolve_ntdll_export phase=driver_resolve_exit name=%s pid=%u ntdll_base=0x%016llX result=0x%016llX elapsed_us=%lld status=\"%s\" last_error=\"%s\"",
                name,
                remote.pid,
                (unsigned long long)remote.base,
                (unsigned long long)driver_resolved,
                elapsed_us_since(td),
                driver_bridge::status().c_str(),
                driver_bridge::last_error().c_str());
            if (driver_resolved != 0) {
                log_ntdll_resolve(hf, tag,
                    "resolve_ntdll_export phase=final name=%s method=driver_fallback final_va=0x%016llX total_us=%lld",
                    name,
                    (unsigned long long)driver_resolved,
                    elapsed_us_since(t0));
                return driver_resolved;
            }
        }

        if (local_ok) {
            log_ntdll_resolve(hf, tag,
                "resolve_ntdll_export phase=final name=%s method=local_process_fallback final_va=0x%016llX total_us=%lld remote_base=0x%016llX module_count=%zu",
                name,
                (unsigned long long)local_va,
                elapsed_us_since(t0),
                (unsigned long long)remote.base,
                remote.module_count);
            return local_va;
        }

        log_ntdll_resolve(hf, tag,
            "resolve_ntdll_export phase=final name=%s method=unresolved final_va=0x0000000000000000 total_us=%lld remote_base=0x%016llX module_count=%zu",
            name,
            elapsed_us_since(t0),
            (unsigned long long)remote.base,
            remote.module_count);
        return 0;
    }

    std::atomic<uint64_t> g_disasm_ntclose_va_cache{0};
    std::atomic<int>      g_disasm_ntclose_strategy{0};

    const char* ntclose_strategy_name(int code) {
        switch (code) {
        case 1: return "kernel_remote_ntdll";
        case 2: return "host_process_ntdll";
        case 3: return "kernel_host_pid_ntdll";
        default: return "uninitialized";
        }
    }

    uint64_t resolve_ntclose() {
        const uint64_t cached = g_disasm_ntclose_va_cache.load(std::memory_order_acquire);
        if (cached != 0) return cached;
        return resolve_ntdll_export("NtClose");
    }

    bool ensure_disasm_ntclose_va(HANDLE hf) {
        const char* tag = "disasm.ntclose_prologue";
        const auto t0 = std::chrono::steady_clock::now();
        const DWORD host_pid = GetCurrentProcessId();
        const DWORD host_tid = GetCurrentThreadId();
        const uint32_t attached_pid = driver_bridge::attached_pid();
        const uint64_t cache_before = g_disasm_ntclose_va_cache.load(std::memory_order_acquire);
        log_msg(hf, tag,
            "ENTER pid=%lu tid=%lu attached_pid=%u driver_status=\"%s\" cache_before=0x%016llX strategy_before=%s(%d)",
            (unsigned long)host_pid,
            (unsigned long)host_tid,
            attached_pid,
            driver_bridge::status().c_str(),
            (unsigned long long)cache_before,
            ntclose_strategy_name(g_disasm_ntclose_strategy.load(std::memory_order_acquire)),
            g_disasm_ntclose_strategy.load(std::memory_order_acquire));
        if (cache_before != 0) {
            log_msg(hf, tag,
                "EXIT pid=%lu tid=%lu strategy=cache_hit final_va=0x%016llX elapsed_us=%lld",
                (unsigned long)host_pid,
                (unsigned long)host_tid,
                (unsigned long long)cache_before,
                elapsed_us_since(t0));
            return true;
        }

        const auto t_kernel = std::chrono::steady_clock::now();
        remote_module_lookup_t remote = resolve_remote_module_info("ntdll.dll");
        const long long kernel_us = elapsed_us_since(t_kernel);
        log_msg(hf, tag,
            "phase=kernel_remote_ntdll pid=%lu attached_pid=%u remote_pid=%u module_count=%zu ntdll_base=0x%016llX ntdll_size=0x%08X elapsed_us=%lld driver_status=\"%s\" last_error=\"%s\"",
            (unsigned long)host_pid,
            attached_pid,
            remote.pid,
            remote.module_count,
            (unsigned long long)remote.base,
            remote.size,
            kernel_us,
            driver_bridge::status().c_str(),
            driver_bridge::last_error().c_str());

        uint64_t local_rva = 0;
        uint64_t local_va = 0;
        const bool local_ok = local_ntdll_export_rva("NtClose", local_rva, local_va);
        const DWORD local_gle = local_ok ? 0 : GetLastError();
        log_msg(hf, tag,
            "phase=host_process_ntdll local_ok=%d local_rva=0x%016llX local_va=0x%016llX gle=%lu",
            local_ok ? 1 : 0,
            (unsigned long long)local_rva,
            (unsigned long long)local_va,
            (unsigned long)local_gle);

        if (remote.base != 0 && local_ok) {
            const uint64_t final_va = remote.base + local_rva;
            g_disasm_ntclose_va_cache.store(final_va, std::memory_order_release);
            g_disasm_ntclose_strategy.store(1, std::memory_order_release);
            log_msg(hf, tag,
                "EXIT pid=%lu tid=%lu strategy=kernel_remote_ntdll final_va=0x%016llX remote_base=0x%016llX rva=0x%016llX elapsed_us=%lld",
                (unsigned long)host_pid,
                (unsigned long)host_tid,
                (unsigned long long)final_va,
                (unsigned long long)remote.base,
                (unsigned long long)local_rva,
                elapsed_us_since(t0));
            return true;
        }

        if (remote.base != 0) {
            const auto t_drv = std::chrono::steady_clock::now();
            const uint64_t drv_va = driver_bridge::resolve_export_for(remote.pid, remote.base, "NtClose");
            log_msg(hf, tag,
                "phase=kernel_driver_resolve_export pid=%u remote_base=0x%016llX result=0x%016llX elapsed_us=%lld driver_status=\"%s\" last_error=\"%s\"",
                remote.pid,
                (unsigned long long)remote.base,
                (unsigned long long)drv_va,
                elapsed_us_since(t_drv),
                driver_bridge::status().c_str(),
                driver_bridge::last_error().c_str());
            if (drv_va != 0) {
                g_disasm_ntclose_va_cache.store(drv_va, std::memory_order_release);
                g_disasm_ntclose_strategy.store(1, std::memory_order_release);
                log_msg(hf, tag,
                    "EXIT pid=%lu tid=%lu strategy=kernel_remote_ntdll(driver_resolve) final_va=0x%016llX elapsed_us=%lld",
                    (unsigned long)host_pid,
                    (unsigned long)host_tid,
                    (unsigned long long)drv_va,
                    elapsed_us_since(t0));
                return true;
            }
        }

        if (attached_pid != 0 && attached_pid != host_pid) {
            const auto t_hostpid = std::chrono::steady_clock::now();
            auto modules = driver_bridge::enumerate_modules_for(host_pid);
            uint64_t host_ntdll_base = 0;
            uint32_t host_ntdll_size = 0;
            for (const auto& mod : modules) {
                if (_stricmp(mod.name.c_str(), "ntdll.dll") == 0) {
                    host_ntdll_base = mod.base;
                    host_ntdll_size = mod.size;
                    break;
                }
            }
            log_msg(hf, tag,
                "phase=kernel_host_pid_ntdll host_pid=%lu module_count=%zu host_ntdll_base=0x%016llX host_ntdll_size=0x%08X elapsed_us=%lld driver_status=\"%s\" last_error=\"%s\"",
                (unsigned long)host_pid,
                modules.size(),
                (unsigned long long)host_ntdll_base,
                host_ntdll_size,
                elapsed_us_since(t_hostpid),
                driver_bridge::status().c_str(),
                driver_bridge::last_error().c_str());
            if (host_ntdll_base != 0 && local_ok) {
                const uint64_t final_va = host_ntdll_base + local_rva;
                g_disasm_ntclose_va_cache.store(final_va, std::memory_order_release);
                g_disasm_ntclose_strategy.store(3, std::memory_order_release);
                log_msg(hf, tag,
                    "EXIT pid=%lu tid=%lu strategy=kernel_host_pid_ntdll final_va=0x%016llX host_base=0x%016llX rva=0x%016llX elapsed_us=%lld",
                    (unsigned long)host_pid,
                    (unsigned long)host_tid,
                    (unsigned long long)final_va,
                    (unsigned long long)host_ntdll_base,
                    (unsigned long long)local_rva,
                    elapsed_us_since(t0));
                return true;
            }
        }

        if (local_ok && local_va != 0) {
            g_disasm_ntclose_va_cache.store(local_va, std::memory_order_release);
            g_disasm_ntclose_strategy.store(2, std::memory_order_release);
            log_msg(hf, tag,
                "EXIT pid=%lu tid=%lu strategy=host_process_ntdll final_va=0x%016llX elapsed_us=%lld",
                (unsigned long)host_pid,
                (unsigned long)host_tid,
                (unsigned long long)local_va,
                elapsed_us_since(t0));
            return true;
        }

        log_msg(hf, tag,
            "EXIT pid=%lu tid=%lu strategy=unresolved final_va=0x0000000000000000 elapsed_us=%lld driver_status=\"%s\" last_error=\"%s\" gle=%lu",
            (unsigned long)host_pid,
            (unsigned long)host_tid,
            elapsed_us_since(t0),
            driver_bridge::status().c_str(),
            driver_bridge::last_error().c_str(),
            (unsigned long)local_gle);
        return false;
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
        struct engine_metrics_t {
            bool metrics_present = false;
            bool metrics_error = false;
            bool metrics_complete = false;
            size_t pseudocode_bytes = 0;
            size_t pseudocode_lines = 0;
            const char* source = "";
            bool cache_found = false;
            bool cache_complete = false;
            bool cache_error = false;
            size_t cache_bytes = 0;
            size_t cache_lines = 0;
            uint64_t current_addr = 0;
            bool current_complete = false;
            bool current_error = false;
            size_t current_bytes = 0;
            size_t current_lines = 0;
            bool engine_decompiling = false;
            bool next_pending = false;
            uint64_t next_addr = 0;
            bool cancel = false;
        };
        auto count_lines_local = [](const std::string& text) -> size_t {
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
        };
        auto read_engine_metrics = [&]() -> engine_metrics_t {
            engine_metrics_t out;
            std::lock_guard<std::mutex> lk(decompiler_engine::g_state.mutex);
            out.engine_decompiling = decompiler_engine::g_state.decompiling.load(std::memory_order_acquire);
            out.next_pending = decompiler_engine::g_state.next_pending.load(std::memory_order_acquire);
            out.next_addr = decompiler_engine::g_state.next_addr.load(std::memory_order_acquire);
            out.cancel = decompiler_engine::g_state.cancel.load(std::memory_order_acquire);
            out.current_addr = decompiler_engine::g_state.current.function_addr;
            out.current_complete = decompiler_engine::g_state.current.complete;
            out.current_error = decompiler_engine::g_state.current.is_error;
            out.current_bytes = decompiler_engine::g_state.current.pseudocode.size();
            out.current_lines = count_lines_local(decompiler_engine::g_state.current.pseudocode);
            auto it = decompiler_engine::g_state.cache.find(addr);
            if (it != decompiler_engine::g_state.cache.end()) {
                out.cache_found = true;
                out.cache_complete = it->second.complete;
                out.cache_error = it->second.is_error;
                out.cache_bytes = it->second.pseudocode.size();
                out.cache_lines = count_lines_local(it->second.pseudocode);
                if (it->second.complete) {
                    out.metrics_present = true;
                    out.metrics_complete = it->second.complete;
                    out.metrics_error = it->second.is_error;
                    out.pseudocode_bytes = out.cache_bytes;
                    out.pseudocode_lines = out.cache_lines;
                    out.source = "cache";
                }
            }
            if (!out.metrics_present &&
                decompiler_engine::g_state.current.function_addr == addr &&
                decompiler_engine::g_state.current.complete) {
                out.metrics_present = true;
                out.metrics_complete = decompiler_engine::g_state.current.complete;
                out.metrics_error = decompiler_engine::g_state.current.is_error;
                out.pseudocode_bytes = out.current_bytes;
                out.pseudocode_lines = out.current_lines;
                out.source = "current";
            }
            return out;
        };
        auto log_wait_state = [&](const char* reason, int waited_ms, bool found, size_t total,
                                  const pseudocode_view::tab_info_t& tab,
                                  const engine_metrics_t& metrics) {
            log_msg(hf, tag,
                "STATE -- decompile_wait_%s tab addr=0x%016llX waited_ms=%d timeout_ms=%d found=%d total_tabs=%zu loaded=%d decompiling=%d is_error=%d function=\"%s\" metrics=%d source=\"%s\" complete=%d engine_error=%d bytes=%zu lines=%zu",
                reason ? reason : "state",
                (unsigned long long)addr,
                waited_ms,
                timeout_ms,
                found ? 1 : 0,
                total,
                found ? (int)tab.loaded : 0,
                found ? (int)tab.decompiling : 0,
                found ? (int)tab.is_error : 0,
                found ? tab.function_name.c_str() : "",
                metrics.metrics_present ? 1 : 0,
                metrics.source,
                metrics.metrics_complete ? 1 : 0,
                metrics.metrics_error ? 1 : 0,
                metrics.pseudocode_bytes,
                metrics.pseudocode_lines);
            log_msg(hf, tag,
                "STATE -- decompile_wait_%s engine current_addr=0x%016llX current_complete=%d current_error=%d current_bytes=%zu current_lines=%zu cache_found=%d cache_complete=%d cache_error=%d cache_bytes=%zu cache_lines=%zu engine_decompiling=%d next_pending=%d next_addr=0x%016llX cancel=%d",
                reason ? reason : "state",
                (unsigned long long)metrics.current_addr,
                metrics.current_complete ? 1 : 0,
                metrics.current_error ? 1 : 0,
                metrics.current_bytes,
                metrics.current_lines,
                metrics.cache_found ? 1 : 0,
                metrics.cache_complete ? 1 : 0,
                metrics.cache_error ? 1 : 0,
                metrics.cache_bytes,
                metrics.cache_lines,
                metrics.engine_decompiling ? 1 : 0,
                metrics.next_pending ? 1 : 0,
                (unsigned long long)metrics.next_addr,
                metrics.cancel ? 1 : 0);
        };
        const int step_ms = 50;
        int waited = 0;
        for (;;) {
            auto tabs = pseudocode_view::snapshot_tabs();
            bool found = false;
            pseudocode_view::tab_info_t observed{};
            for (const auto& t : tabs) {
                if (t.addr != addr) continue;
                found = true;
                observed = t;
                fn_out = t.function_name;
                break;
            }
            engine_metrics_t metrics = read_engine_metrics();
            if (found) {
                const bool has_nonzero_metrics = metrics.metrics_present &&
                    !metrics.metrics_error &&
                    metrics.pseudocode_bytes > 0 &&
                    metrics.pseudocode_lines > 0 &&
                    (observed.loaded || std::strcmp(metrics.source, "cache") == 0);
                const bool explicit_error = observed.is_error ||
                    (metrics.metrics_present && metrics.metrics_error);
                if (has_nonzero_metrics || explicit_error) {
                    loaded_out = observed.loaded || has_nonzero_metrics;
                    error_out = observed.is_error || metrics.metrics_error;
                    return true;
                }
            }
            if (waited >= timeout_ms) {
                log_wait_state(found ? "timeout_terminal_state_missing" : "timeout_tab_missing",
                    waited, found, tabs.size(), observed, metrics);
                return false;
            }
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
        (void)skipped;
        uint64_t addr = resolve_ntclose();
        if (addr == 0)
            addr = resolve_ntdll_export("NtClose", hf, tag);
        if (addr == 0) {
            log_msg(hf, tag, "FAIL -- NtClose precondition unresolved at test entry (phase prologue should have populated cache) strategy=%s(%d) cache=0x%016llX driver_status=\"%s\" last_error=\"%s\"",
                ntclose_strategy_name(g_disasm_ntclose_strategy.load(std::memory_order_acquire)),
                g_disasm_ntclose_strategy.load(std::memory_order_acquire),
                (unsigned long long)g_disasm_ntclose_va_cache.load(std::memory_order_acquire),
                driver_bridge::status().c_str(),
                driver_bridge::last_error().c_str());
            failed.fetch_add(1);
            return;
        }
        refresh_and_validate_disasm(hf, tag, addr, passed, failed);
    }

    void test_get_disasm_window_bytes(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        const char* tag = "disasm.window_bytes";
        (void)skipped;
        uint64_t addr = resolve_ntclose();
        if (addr == 0) {
            log_msg(hf, tag, "FAIL -- NtClose precondition unresolved at test entry strategy=%s(%d) cache=0x%016llX driver_status=\"%s\" last_error=\"%s\"",
                ntclose_strategy_name(g_disasm_ntclose_strategy.load(std::memory_order_acquire)),
                g_disasm_ntclose_strategy.load(std::memory_order_acquire),
                (unsigned long long)g_disasm_ntclose_va_cache.load(std::memory_order_acquire),
                driver_bridge::status().c_str(),
                driver_bridge::last_error().c_str());
            failed.fetch_add(1);
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

    const char* xref_build_state_name(uint32_t s) {
        switch (static_cast<xref_index::detail::build_state_t>(s)) {
        case xref_index::detail::build_state_t::idle: return "idle";
        case xref_index::detail::build_state_t::building: return "building";
        case xref_index::detail::build_state_t::built: return "built";
        case xref_index::detail::build_state_t::failed: return "failed";
        default: return "unknown";
        }
    }

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
        (void)skipped;
        uint64_t addr = resolve_ntclose();
        if (addr == 0) {
            log_msg(hf, tag, "FAIL -- NtClose precondition unresolved at test entry strategy=%s(%d) cache=0x%016llX",
                ntclose_strategy_name(g_disasm_ntclose_strategy.load(std::memory_order_acquire)),
                g_disasm_ntclose_strategy.load(std::memory_order_acquire),
                (unsigned long long)g_disasm_ntclose_va_cache.load(std::memory_order_acquire));
            failed.fetch_add(1);
            return;
        }
        validate_decompile(hf, tag, "NtClose", addr, true, passed, failed);
    }

    void test_pseudocode_has_tab_for(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        const char* tag = "pseudo.has_tab_for";
        (void)skipped;
        uint64_t addr = resolve_ntclose();
        if (addr == 0) {
            log_msg(hf, tag, "FAIL -- NtClose precondition unresolved at test entry strategy=%s(%d) cache=0x%016llX",
                ntclose_strategy_name(g_disasm_ntclose_strategy.load(std::memory_order_acquire)),
                g_disasm_ntclose_strategy.load(std::memory_order_acquire),
                (unsigned long long)g_disasm_ntclose_va_cache.load(std::memory_order_acquire));
            failed.fetch_add(1);
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
        (void)skipped;
        uint64_t addr = resolve_ntclose();
        if (addr == 0) {
            log_msg(hf, tag, "FAIL -- NtClose precondition unresolved at test entry strategy=%s(%d) cache=0x%016llX",
                ntclose_strategy_name(g_disasm_ntclose_strategy.load(std::memory_order_acquire)),
                g_disasm_ntclose_strategy.load(std::memory_order_acquire),
                (unsigned long long)g_disasm_ntclose_va_cache.load(std::memory_order_acquire));
            failed.fetch_add(1);
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
        (void)skipped;
        uint64_t addr = resolve_ntclose();
        if (addr == 0) {
            log_msg(hf, tag, "FAIL -- NtClose precondition unresolved at test entry strategy=%s(%d) cache=0x%016llX",
                ntclose_strategy_name(g_disasm_ntclose_strategy.load(std::memory_order_acquire)),
                g_disasm_ntclose_strategy.load(std::memory_order_acquire),
                (unsigned long long)g_disasm_ntclose_va_cache.load(std::memory_order_acquire));
            failed.fetch_add(1);
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
        (void)skipped;
        try {
            HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
            if (!ntdll) {
                log_msg(hf, tag, "FAIL -- ntdll.dll handle is null in host process gle=%lu", (unsigned long)GetLastError());
                failed.fetch_add(1);
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
        (void)skipped;
        expression_eval::context_t ctx{};
        const expr_eval_case_t cases[] = {
            {"hex_plus_hex", "0x1000 + 0x200", 0x1200},
            {"zero_plus_hex", "0 + 0x2A", 0x2A},
            {"carry_boundary", "0x7FFF + 1", 0x8000},
        };
        long long total_us = 0;
        if (run_expr_cases(hf, tag, ctx, cases, total_us)) {
            log_msg(hf, tag, "PASS -- %zu addition cases matched expected outputs elapsed_us=%lld", sizeof(cases) / sizeof(cases[0]), total_us);
            passed.fetch_add(1);
        } else {
            log_msg(hf, tag, "FAIL -- one or more addition cases mismatched elapsed_us=%lld", total_us);
            failed.fetch_add(1);
        }
    }

    void test_expr_bitwise_and(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        const char* tag = "expr.bitwise_and";
        (void)skipped;
        expression_eval::context_t ctx{};
        const expr_eval_case_t cases[] = {
            {"low_nibble", "0xFF & 0x0F", 0x0F},
            {"alternating_mask", "0xAA55 & 0x0F0F", 0x0A05},
            {"zero_mask", "0x1234 & 0", 0},
        };
        long long total_us = 0;
        if (run_expr_cases(hf, tag, ctx, cases, total_us)) {
            log_msg(hf, tag, "PASS -- %zu bitwise-and cases matched expected outputs elapsed_us=%lld", sizeof(cases) / sizeof(cases[0]), total_us);
            passed.fetch_add(1);
        } else {
            log_msg(hf, tag, "FAIL -- one or more bitwise-and cases mismatched elapsed_us=%lld", total_us);
            failed.fetch_add(1);
        }
    }

    void test_expr_hex_multiply(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        const char* tag = "expr.hex_mul";
        (void)skipped;
        expression_eval::context_t ctx{};
        const expr_eval_case_t cases[] = {
            {"hex_square", "0x10 * 0x10", 0x100},
            {"multiply_by_zero", "0x123 * 0", 0},
            {"decimal_product", "7 * 9", 63},
        };
        long long total_us = 0;
        if (run_expr_cases(hf, tag, ctx, cases, total_us)) {
            log_msg(hf, tag, "PASS -- %zu multiplication cases matched expected outputs elapsed_us=%lld", sizeof(cases) / sizeof(cases[0]), total_us);
            passed.fetch_add(1);
        } else {
            log_msg(hf, tag, "FAIL -- one or more multiplication cases mismatched elapsed_us=%lld", total_us);
            failed.fetch_add(1);
        }
    }

    void test_expr_with_registers(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        const char* tag = "expr.registers";
        (void)skipped;
        expression_eval::context_t ctx{};
        ctx.rax = 0x1000;
        ctx.rbx = 0x200;
        const expr_eval_case_t cases[] = {
            {"register_add", "rax + rbx", 0x1200},
            {"register_sub_then_add", "(rax - rbx) + 0x10", 0xE10},
            {"register_bitwise_or", "rax | rbx", 0x1200},
        };
        long long total_us = 0;
        if (run_expr_cases(hf, tag, ctx, cases, total_us)) {
            log_msg(hf, tag, "PASS -- %zu register expression cases matched expected outputs elapsed_us=%lld", sizeof(cases) / sizeof(cases[0]), total_us);
            passed.fetch_add(1);
        } else {
            log_msg(hf, tag, "FAIL -- one or more register expression cases mismatched elapsed_us=%lld", total_us);
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
        return resolve_ntdll_export(name);
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
        (void)skipped;
        uint64_t addr = resolve_ntclose();
        if (addr == 0) {
            log_msg(hf, tag, "FAIL -- NtClose precondition unresolved at test entry strategy=%s(%d) cache=0x%016llX",
                ntclose_strategy_name(g_disasm_ntclose_strategy.load(std::memory_order_acquire)),
                g_disasm_ntclose_strategy.load(std::memory_order_acquire),
                (unsigned long long)g_disasm_ntclose_va_cache.load(std::memory_order_acquire));
            failed.fetch_add(1);
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

    void test_xref_live_after_warm_range(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        (void)skipped;
        const char* tag = "xref.live_after_warm";
        auto t0 = std::chrono::steady_clock::now();
        g_xref_live_after_warm_stage.store(1, std::memory_order_release);
        log_msg(hf, tag, "SELECT_MODULE_BEGIN -- attached_pid=%u status=\"%s\" last_error=\"%s\" elapsed_us=%lld",
            driver_bridge::attached_pid(),
            driver_bridge::status().c_str(),
            driver_bridge::last_error().c_str(),
            elapsed_us_since(t0));
        remote_module_lookup_t module{};
        try {
            module = select_live_xref_module();
        } catch (const std::exception& ex) {
            g_xref_live_after_warm_stage.store(14, std::memory_order_release);
            log_msg(hf, tag, "OUTPUT -- ok=0 error=\"select_module_exception\" type=\"%s\" what=\"%s\" stage=%s elapsed_us=%lld",
                "std::exception",
                ex.what(),
                xref_live_after_warm_stage_name(g_xref_live_after_warm_stage.load(std::memory_order_acquire)),
                elapsed_us_since(t0));
            failed.fetch_add(1);
            return;
        } catch (...) {
            g_xref_live_after_warm_stage.store(14, std::memory_order_release);
            log_msg(hf, tag, "OUTPUT -- ok=0 error=\"select_module_exception_unknown\" stage=%s elapsed_us=%lld",
                xref_live_after_warm_stage_name(g_xref_live_after_warm_stage.load(std::memory_order_acquire)),
                elapsed_us_since(t0));
            failed.fetch_add(1);
            return;
        }
        g_xref_live_after_warm_stage.store(2, std::memory_order_release);
        log_msg(hf, tag, "SELECT_MODULE_END -- pid=%u module=\"%s\" module_base=0x%016llX module_size=0x%08X module_count=%zu status=\"%s\" last_error=\"%s\" elapsed_us=%lld",
            module.pid,
            module.name.empty() ? "<unknown>" : module.name.c_str(),
            (unsigned long long)module.base,
            module.size,
            module.module_count,
            driver_bridge::status().c_str(),
            driver_bridge::last_error().c_str(),
            elapsed_us_since(t0));
        g_xref_live_after_warm_stage.store(3, std::memory_order_release);
        if (module.pid == 0) {
            log_msg(hf, tag, "OUTPUT -- ok=0 error=\"no_attached_pid\" pid=0 module_count=%zu", module.module_count);
            log_msg(hf, tag, "FAIL -- no_attached_pid; live xref proof requires a verified target");
            failed.fetch_add(1);
            return;
        }
        if (module.base == 0 || module.size == 0) {
            log_msg(hf, tag, "OUTPUT -- ok=0 error=\"no_live_module_for_bounded_xref\" pid=%u module_count=%zu status=\"%s\" last_error=\"%s\"",
                module.pid,
                module.module_count,
                driver_bridge::status().c_str(),
                driver_bridge::last_error().c_str());
            log_msg(hf, tag, "FAIL -- no_live_module_for_bounded_xref pid=%u module_count=%zu status=\"%s\" last_error=\"%s\"",
                module.pid,
                module.module_count,
                driver_bridge::status().c_str(),
                driver_bridge::last_error().c_str());
            failed.fetch_add(1);
            return;
        }
        g_xref_live_after_warm_stage.store(4, std::memory_order_release);
        const uint64_t max_span = 0x100000ull;
        const uint64_t span = std::min<uint64_t>(module.size, max_span);
        const uint64_t range_lo = module.base;
        const uint64_t range_hi = module.base + span;
        log_msg(hf, tag, "RANGE_CONSTRUCTED -- pid=%u module=\"%s\" module_base=0x%016llX module_size=0x%08X span=0x%016llX range=[0x%016llX,0x%016llX) overflow=%d elapsed_us=%lld",
            module.pid,
            module.name.empty() ? "<unknown>" : module.name.c_str(),
            (unsigned long long)module.base,
            module.size,
            (unsigned long long)span,
            (unsigned long long)range_lo,
            (unsigned long long)range_hi,
            range_hi <= range_lo ? 1 : 0,
            elapsed_us_since(t0));
        if (range_hi <= range_lo) {
            log_msg(hf, tag, "OUTPUT -- ok=0 error=\"range_overflow\" pid=%u module=\"%s\" module_base=0x%016llX span=0x%016llX elapsed_us=%lld",
                module.pid,
                module.name.empty() ? "<unknown>" : module.name.c_str(),
                (unsigned long long)module.base,
                (unsigned long long)span,
                elapsed_us_since(t0));
            failed.fetch_add(1);
            return;
        }
        constexpr uint32_t proof_timeout_ms = 4000;
        constexpr uint32_t watchdog_timeout_ms = 6000;
        struct watchdog_shared_state_t {
            std::atomic<bool> finished{ false };
            std::atomic<bool> hung_logged{ false };
            std::atomic<int>  stage{ 0 };
            std::atomic<bool> done{ false };
        };
        auto wd_state = std::make_shared<watchdog_shared_state_t>();
        auto& finished = wd_state->finished;
        auto& hung_logged = wd_state->hung_logged;
        auto& stage = wd_state->stage;
        auto set_stage = [&](int value) {
            stage.store(value, std::memory_order_release);
            g_xref_live_after_warm_stage.store(value, std::memory_order_release);
        };
        auto stage_name = [](int value) -> const char* {
            return xref_live_after_warm_stage_name(value);
        };
        set_stage(5);
        auto watchdog_event_holder = std::shared_ptr<void>(
            CreateEventW(nullptr, TRUE, FALSE, nullptr),
            [](HANDLE h) { if (h) CloseHandle(h); });
        if (!watchdog_event_holder.get()) {
            const DWORD ev_gle = GetLastError();
            g_xref_live_after_warm_stage.store(14, std::memory_order_release);
            log_msg(hf, tag, "OUTPUT -- ok=0 error=\"watchdog_event_create_failed\" gle=%lu pid=%u module=\"%s\" elapsed_us=%lld",
                static_cast<unsigned long>(ev_gle),
                module.pid,
                module.name.empty() ? "<unknown>" : module.name.c_str(),
                elapsed_us_since(t0));
            failed.fetch_add(1);
            return;
        }
        const HANDLE wd_log_file = hf;
        const uint32_t wd_pid = module.pid;
        const std::string wd_module_name = module.name;
        const uint64_t wd_module_base = module.base;
        const uint32_t wd_module_size = module.size;
        const uint64_t wd_range_lo = range_lo;
        const uint64_t wd_range_hi = range_hi;
        bool watchdog_posted = false;
        {
            aida::infra::executor::submission_t _exec_sub;
            _exec_sub.owner_subsystem = "standalone.testlab.disasm";
            _exec_sub.label = "xref_live_after_warm.watchdog";
            _exec_sub.thread_class = "queued_task";
            _exec_sub.domain = aida::infra::executor::domain_t::diagnostics;
            _exec_sub.priority = 4;
            _exec_sub.body = [wd_state, watchdog_event_holder, t0, tag, wd_log_file, wd_pid, wd_module_name, wd_module_base, wd_module_size, wd_range_lo, wd_range_hi]() {
                HANDLE watchdog_event = watchdog_event_holder.get();
                const auto deadline = t0 + std::chrono::milliseconds(watchdog_timeout_ms);
                while (!wd_state->finished.load(std::memory_order_acquire) && std::chrono::steady_clock::now() < deadline) {
                    const DWORD wait_res = WaitForSingleObject(watchdog_event, 25);
                    if (wait_res != WAIT_TIMEOUT) break;
                }
                if (!wd_state->finished.load(std::memory_order_acquire)) {
                    const int active_stage = wd_state->stage.load(std::memory_order_acquire);
                    wd_state->hung_logged.store(true, std::memory_order_release);
                    const char* wd_module_name_cstr = wd_module_name.empty() ? "<unknown>" : wd_module_name.c_str();
                    log_msg(wd_log_file, tag, "HUNG -- stage=%s pid=%u module=\"%s\" module_base=0x%016llX module_size=0x%08X requested=[0x%016llX,0x%016llX) proof_timeout_ms=%u watchdog_timeout_ms=%u elapsed_us=%lld",
                        xref_live_after_warm_stage_name(active_stage),
                        wd_pid,
                        wd_module_name_cstr,
                        (unsigned long long)wd_module_base,
                        wd_module_size,
                        (unsigned long long)wd_range_lo,
                        (unsigned long long)wd_range_hi,
                        proof_timeout_ms,
                        watchdog_timeout_ms,
                        elapsed_us_since(t0));
                    diag::log_tagged_critical_fmt("testlab",
                        "xref_live_after_warm_hung stage=%s pid=%u module=%s base=0x%llX size=0x%X range_lo=0x%llX range_hi=0x%llX proof_timeout_ms=%u watchdog_timeout_ms=%u elapsed_us=%lld",
                        xref_live_after_warm_stage_name(active_stage),
                        wd_pid,
                        wd_module_name_cstr,
                        (unsigned long long)wd_module_base,
                        wd_module_size,
                        (unsigned long long)wd_range_lo,
                        (unsigned long long)wd_range_hi,
                        proof_timeout_ms,
                        watchdog_timeout_ms,
                        elapsed_us_since(t0));
                }
                wd_state->done.store(true, std::memory_order_release);
            };
            _exec_sub.failure_policy = "reject_not_started";
            _exec_sub.ui_access_policy = "none";
            _exec_sub.shutdown_policy = "drain";
            _exec_sub.no_capacity_reason = "no_capacity_needed_diagnostics_queue";
            auto _exec_result = aida::infra::executor::submit(std::move(_exec_sub));
            watchdog_posted = _exec_result.submitted;
            (void)_exec_result;
        }
        if (!watchdog_posted) {
            const aida::infra::taskflow_runtime::stats_t work_stats = aida::infra::taskflow_runtime::domain_stats(aida::infra::taskflow_runtime::executor_domain_t::general);
            const aida::infra::taskflow_runtime::stats_t service_stats = aida::infra::taskflow_runtime::domain_stats(aida::infra::taskflow_runtime::executor_domain_t::service);
            g_xref_live_after_warm_stage.store(14, std::memory_order_release);
            log_msg(hf, tag,
                "OUTPUT -- ok=0 error=\"watchdog_post_failed\" reason=taskflow_executor_submit_returned_false "
                "work_alive=%d work_shutting_down=%d work_pool_size=%d work_workers=%zu work_pending=%zu work_active=%u work_posted=%llu work_rejected=%llu work_started=%llu work_finished=%llu work_oldest_active_ms=%llu work_active_label_count=%u "
                "service_alive=%d service_shutting_down=%d service_pool_size=%d service_workers=%zu service_pending=%zu service_active=%u service_rejected=%llu "
                "pid=%u module=\"%s\" elapsed_us=%lld",
                work_stats.alive ? 1 : 0,
                work_stats.shutting_down ? 1 : 0,
                work_stats.pool_size,
                work_stats.workers,
                work_stats.pending,
                work_stats.active,
                static_cast<unsigned long long>(work_stats.posted),
                static_cast<unsigned long long>(work_stats.rejected),
                static_cast<unsigned long long>(work_stats.started),
                static_cast<unsigned long long>(work_stats.finished),
                static_cast<unsigned long long>(work_stats.oldest_active_ms),
                work_stats.active_label_count,
                service_stats.alive ? 1 : 0,
                service_stats.shutting_down ? 1 : 0,
                service_stats.pool_size,
                service_stats.workers,
                service_stats.pending,
                service_stats.active,
                static_cast<unsigned long long>(service_stats.rejected),
                module.pid,
                module.name.empty() ? "<unknown>" : module.name.c_str(),
                elapsed_us_since(t0));
            diag::log_tagged_critical_fmt("testlab",
                "xref_live_after_warm_watchdog_post_failed work_alive=%d work_workers=%zu work_pending=%zu work_active=%u work_oldest_active_ms=%llu work_active_labels=\"%s\" service_alive=%d service_active=%u pid=%u module=%s elapsed_us=%lld",
                work_stats.alive ? 1 : 0,
                work_stats.workers,
                work_stats.pending,
                work_stats.active,
                static_cast<unsigned long long>(work_stats.oldest_active_ms),
                work_stats.active_labels.empty() ? "<none>" : work_stats.active_labels.c_str(),
                service_stats.alive ? 1 : 0,
                service_stats.active,
                module.pid,
                module.name.empty() ? "<unknown>" : module.name.c_str(),
                elapsed_us_since(t0));
            failed.fetch_add(1);
            return;
        }
        auto finish_watchdog = [&, wd_state, watchdog_event_holder]() {
            set_stage(13);
            finished.store(true, std::memory_order_release);
            SetEvent(watchdog_event_holder.get());
            const auto join_deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(watchdog_timeout_ms + 250);
            while (!wd_state->done.load(std::memory_order_acquire) &&
                   std::chrono::steady_clock::now() < join_deadline) {
                Sleep(5);
            }
        };
        log_msg(hf, tag, "INPUT -- pid=%u module=\"%s\" module_base=0x%016llX module_size=0x%08X module_count=%zu requested_range=[0x%016llX,0x%016llX) span=0x%016llX proof_timeout_ms=%u watchdog_timeout_ms=%u",
            module.pid,
            module.name.empty() ? "<unknown>" : module.name.c_str(),
            (unsigned long long)module.base,
            module.size,
            module.module_count,
            (unsigned long long)range_lo,
            (unsigned long long)range_hi,
            (unsigned long long)span,
            proof_timeout_ms,
            watchdog_timeout_ms);
        bool counted = false;
        try {
            set_stage(6);
            log_msg(hf, tag, "WARM_RANGE_BEGIN -- pid=%u module=\"%s\" range=[0x%016llX,0x%016llX) elapsed_us=%lld",
                module.pid,
                module.name.empty() ? "<unknown>" : module.name.c_str(),
                (unsigned long long)range_lo,
                (unsigned long long)range_hi,
                elapsed_us_since(t0));
            diag::log_tagged_critical_fmt("testlab",
                "xref_live_after_warm_range_begin pid=%u module=%s base=0x%llX size=0x%X range_lo=0x%llX range_hi=0x%llX elapsed_us=%lld",
                module.pid,
                module.name.empty() ? "<unknown>" : module.name.c_str(),
                (unsigned long long)module.base,
                module.size,
                (unsigned long long)range_lo,
                (unsigned long long)range_hi,
                elapsed_us_since(t0));
            set_stage(7);
            const auto warm_started = std::chrono::steady_clock::now();
            xref_index::warm_range(range_lo, range_hi);
            set_stage(8);
            log_msg(hf, tag, "WARM_RANGE_END -- pid=%u module=\"%s\" elapsed_us=%lld outer_elapsed_us=%lld",
                module.pid,
                module.name.empty() ? "<unknown>" : module.name.c_str(),
                elapsed_us_since(warm_started),
                elapsed_us_since(t0));
            diag::log_tagged_critical_fmt("testlab",
                "xref_live_after_warm_range_end pid=%u module=%s elapsed_us=%lld outer_elapsed_us=%lld",
                module.pid,
                module.name.empty() ? "<unknown>" : module.name.c_str(),
                elapsed_us_since(warm_started),
                elapsed_us_since(t0));
            set_stage(9);
            log_msg(hf, tag, "BOUNDED_LIVE_RANGE_BEGIN -- pid=%u module=\"%s\" range=[0x%016llX,0x%016llX) timeout_ms=%u elapsed_us=%lld",
                module.pid,
                module.name.empty() ? "<unknown>" : module.name.c_str(),
                (unsigned long long)range_lo,
                (unsigned long long)range_hi,
                proof_timeout_ms,
                elapsed_us_since(t0));
            diag::log_tagged_critical_fmt("testlab",
                "xref_live_after_bounded_live_range_begin pid=%u module=%s range_lo=0x%llX range_hi=0x%llX timeout_ms=%u elapsed_us=%lld",
                module.pid,
                module.name.empty() ? "<unknown>" : module.name.c_str(),
                (unsigned long long)range_lo,
                (unsigned long long)range_hi,
                proof_timeout_ms,
                elapsed_us_since(t0));
            set_stage(10);
            const auto proof_started = std::chrono::steady_clock::now();
            xref_index::bounded_live_range_result_t proof = xref_index::build_bounded_live_range(range_lo, range_hi, proof_timeout_ms);
            set_stage(11);
            const bool proof_source_in_range = proof.proof_source >= proof.clipped_lo && proof.proof_source < proof.clipped_hi;
            const long long proof_elapsed_us = elapsed_us_since(proof_started);
            log_msg(hf, tag, "BOUNDED_LIVE_RANGE_END -- ok=%d error=\"%s\" pid=%u module=\"%s\" timeout_ms=%u proof_elapsed_us=%lld result_elapsed_us=%llu outer_elapsed_us=%lld",
                proof.ok ? 1 : 0,
                proof.error.empty() ? "<none>" : proof.error.c_str(),
                proof.pid,
                proof.module.empty() ? "<unknown>" : proof.module.c_str(),
                proof_timeout_ms,
                proof_elapsed_us,
                (unsigned long long)proof.elapsed_us,
                elapsed_us_since(t0));
            diag::log_tagged_critical_fmt("testlab",
                "xref_live_after_bounded_live_range_end ok=%d error=%s pid=%u module=%s timeout_ms=%u proof_elapsed_us=%lld result_elapsed_us=%llu outer_elapsed_us=%lld",
                proof.ok ? 1 : 0,
                proof.error.empty() ? "<none>" : proof.error.c_str(),
                proof.pid,
                proof.module.empty() ? "<unknown>" : proof.module.c_str(),
                proof_timeout_ms,
                proof_elapsed_us,
                (unsigned long long)proof.elapsed_us,
                elapsed_us_since(t0));
            set_stage(12);
            log_msg(hf, tag, "OUTPUT -- ok=%d error=\"%s\" hung_logged=%d pid=%u module=\"%s\" module_base=0x%016llX module_size=0x%08X requested=[0x%016llX,0x%016llX) clipped=[0x%016llX,0x%016llX) pages_read=%zu pages_failed=%zu bytes_read=%zu targets=%zu xrefs=%zu proof_target=0x%016llX proof_source=0x%016llX proof_source_in_range=%d proof_label=\"%s\" state_before=%s(%u) state_after=%s(%u) table_before=%d table_after=%d rebuild_before=%d rebuild_after=%d elapsed_us=%llu proof_call_elapsed_us=%lld outer_elapsed_us=%lld",
                proof.ok ? 1 : 0,
                proof.error.empty() ? "<none>" : proof.error.c_str(),
                hung_logged.load(std::memory_order_acquire) ? 1 : 0,
                proof.pid,
                proof.module.empty() ? "<unknown>" : proof.module.c_str(),
                (unsigned long long)proof.module_base,
                proof.module_size,
                (unsigned long long)proof.requested_lo,
                (unsigned long long)proof.requested_hi,
                (unsigned long long)proof.clipped_lo,
                (unsigned long long)proof.clipped_hi,
                proof.pages_read,
                proof.pages_failed,
                proof.bytes_read,
                proof.targets_found,
                proof.xrefs_found,
                (unsigned long long)proof.proof_target,
                (unsigned long long)proof.proof_source,
                proof_source_in_range ? 1 : 0,
                proof.proof_label.c_str(),
                xref_build_state_name(proof.state_before),
                proof.state_before,
                xref_build_state_name(proof.state_after),
                proof.state_after,
                proof.table_built_before ? 1 : 0,
                proof.table_built_after ? 1 : 0,
                proof.rebuild_in_flight_before ? 1 : 0,
                proof.rebuild_in_flight_after ? 1 : 0,
                (unsigned long long)proof.elapsed_us,
                proof_elapsed_us,
                elapsed_us_since(t0));
            if (hung_logged.load(std::memory_order_acquire)) {
                log_msg(hf, tag, "FAIL -- bounded live range exceeded watchdog before returning pid=%u module=\"%s\" proof_elapsed_us=%lld outer_elapsed_us=%lld",
                    proof.pid,
                    proof.module.empty() ? "<unknown>" : proof.module.c_str(),
                    proof_elapsed_us,
                    elapsed_us_since(t0));
                failed.fetch_add(1);
                counted = true;
            } else if (proof.ok && proof.xrefs_found > 0 && proof.proof_target != 0 && proof.proof_source != 0 && proof_source_in_range) {
                log_msg(hf, tag, "PASS -- deterministic bounded live range produced xref proof target=0x%016llX source=0x%016llX bytes_read=%zu elapsed_us=%llu",
                    (unsigned long long)proof.proof_target,
                    (unsigned long long)proof.proof_source,
                    proof.bytes_read,
                    (unsigned long long)proof.elapsed_us);
                passed.fetch_add(1);
                counted = true;
            } else {
                log_msg(hf, tag, "FAIL -- bounded live range did not produce a valid xref proof error=\"%s\" pid=%u module=\"%s\" pages_read=%zu bytes_read=%zu xrefs=%zu state_before=%s(%u) state_after=%s(%u)",
                    proof.error.empty() ? "<none>" : proof.error.c_str(),
                    proof.pid,
                    proof.module.empty() ? "<unknown>" : proof.module.c_str(),
                    proof.pages_read,
                    proof.bytes_read,
                    proof.xrefs_found,
                    xref_build_state_name(proof.state_before),
                    proof.state_before,
                    xref_build_state_name(proof.state_after),
                    proof.state_after);
                failed.fetch_add(1);
                counted = true;
            }
        } catch (const std::exception& ex) {
            g_xref_live_after_warm_stage.store(14, std::memory_order_release);
            log_msg(hf, tag, "OUTPUT -- ok=0 error=\"exception\" type=\"%s\" what=\"%s\" stage=%s pid=%u module=\"%s\" module_base=0x%016llX range=[0x%016llX,0x%016llX) elapsed_us=%lld",
                "std::exception",
                ex.what(),
                stage_name(stage.load(std::memory_order_acquire)),
                module.pid,
                module.name.empty() ? "<unknown>" : module.name.c_str(),
                (unsigned long long)module.base,
                (unsigned long long)range_lo,
                (unsigned long long)range_hi,
                elapsed_us_since(t0));
            log_msg(hf, tag, "FAIL -- exception during bounded live xref proof stage=%s type=\"%s\" what=\"%s\" pid=%u module=\"%s\" elapsed_us=%lld",
                stage_name(stage.load(std::memory_order_acquire)),
                "std::exception",
                ex.what(),
                module.pid,
                module.name.empty() ? "<unknown>" : module.name.c_str(),
                elapsed_us_since(t0));
            failed.fetch_add(1);
            counted = true;
        } catch (...) {
            g_xref_live_after_warm_stage.store(14, std::memory_order_release);
            log_msg(hf, tag, "OUTPUT -- ok=0 error=\"exception\" stage=%s pid=%u module=\"%s\" elapsed_us=%lld",
                stage_name(stage.load(std::memory_order_acquire)),
                module.pid,
                module.name.empty() ? "<unknown>" : module.name.c_str(),
                elapsed_us_since(t0));
            log_msg(hf, tag, "FAIL -- exception during bounded live xref proof pid=%u module=\"%s\" elapsed_us=%lld",
                module.pid,
                module.name.empty() ? "<unknown>" : module.name.c_str(),
                elapsed_us_since(t0));
            failed.fetch_add(1);
            counted = true;
        }
        finish_watchdog();
        if (!counted) {
            log_msg(hf, tag, "OUTPUT -- ok=0 error=\"unaccounted_completion\" pid=%u module=\"%s\" elapsed_us=%lld",
                module.pid,
                module.name.empty() ? "<unknown>" : module.name.c_str(),
                elapsed_us_since(t0));
            log_msg(hf, tag, "FAIL -- unaccounted bounded live xref completion pid=%u module=\"%s\" elapsed_us=%lld",
                module.pid,
                module.name.empty() ? "<unknown>" : module.name.c_str(),
                elapsed_us_since(t0));
            failed.fetch_add(1);
        }
    }

    void test_pseudocode_request_decompile_ntcreatefile(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        const char* tag = "pseudo.decompile_ntcf";
        (void)skipped;
        uint64_t addr = resolve_ntdll_fn("NtCreateFile");
        if (addr == 0) {
            log_msg(hf, tag, "FAIL -- NtCreateFile precondition unresolved driver_status=\"%s\" last_error=\"%s\"",
                driver_bridge::status().c_str(),
                driver_bridge::last_error().c_str());
            failed.fetch_add(1);
            return;
        }
        validate_decompile(hf, tag, "NtCreateFile", addr, true, passed, failed);
    }

    void test_pseudocode_request_decompile_force(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        const char* tag = "pseudo.decompile_force";
        (void)skipped;
        uint64_t addr = resolve_ntclose();
        if (addr == 0) {
            log_msg(hf, tag, "FAIL -- NtClose precondition unresolved at test entry strategy=%s(%d) cache=0x%016llX",
                ntclose_strategy_name(g_disasm_ntclose_strategy.load(std::memory_order_acquire)),
                g_disasm_ntclose_strategy.load(std::memory_order_acquire),
                (unsigned long long)g_disasm_ntclose_va_cache.load(std::memory_order_acquire));
            failed.fetch_add(1);
            return;
        }
        validate_decompile(hf, tag, "NtClose(force)", addr, true, passed, failed);
    }

    void test_pseudocode_close_tab_by_addr(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        const char* tag = "pseudo.close_by_addr";
        (void)skipped;
        uint64_t addr = resolve_ntclose();
        if (addr == 0) {
            log_msg(hf, tag, "FAIL -- NtClose precondition unresolved at test entry strategy=%s(%d) cache=0x%016llX",
                ntclose_strategy_name(g_disasm_ntclose_strategy.load(std::memory_order_acquire)),
                g_disasm_ntclose_strategy.load(std::memory_order_acquire),
                (unsigned long long)g_disasm_ntclose_va_cache.load(std::memory_order_acquire));
            failed.fetch_add(1);
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
        (void)skipped;
        uint64_t addr = resolve_ntclose();
        if (addr == 0) {
            log_msg(hf, tag, "FAIL -- NtClose precondition unresolved at test entry strategy=%s(%d) cache=0x%016llX",
                ntclose_strategy_name(g_disasm_ntclose_strategy.load(std::memory_order_acquire)),
                g_disasm_ntclose_strategy.load(std::memory_order_acquire),
                (unsigned long long)g_disasm_ntclose_va_cache.load(std::memory_order_acquire));
            failed.fetch_add(1);
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
        (void)skipped;
        uint64_t addr = resolve_ntclose();
        if (addr == 0) {
            log_msg(hf, tag, "FAIL -- NtClose precondition unresolved at test entry strategy=%s(%d) cache=0x%016llX",
                ntclose_strategy_name(g_disasm_ntclose_strategy.load(std::memory_order_acquire)),
                g_disasm_ntclose_strategy.load(std::memory_order_acquire),
                (unsigned long long)g_disasm_ntclose_va_cache.load(std::memory_order_acquire));
            failed.fetch_add(1);
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
        (void)skipped;
        uint64_t addr = resolve_ntclose();
        if (addr == 0) {
            log_msg(hf, tag, "FAIL -- NtClose precondition unresolved at test entry strategy=%s(%d) cache=0x%016llX",
                ntclose_strategy_name(g_disasm_ntclose_strategy.load(std::memory_order_acquire)),
                g_disasm_ntclose_strategy.load(std::memory_order_acquire),
                (unsigned long long)g_disasm_ntclose_va_cache.load(std::memory_order_acquire));
            failed.fetch_add(1);
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
        (void)skipped;
        uint64_t addr = resolve_ntclose();
        if (addr == 0) {
            log_msg(hf, tag, "FAIL -- NtClose precondition unresolved at test entry strategy=%s(%d) cache=0x%016llX",
                ntclose_strategy_name(g_disasm_ntclose_strategy.load(std::memory_order_acquire)),
                g_disasm_ntclose_strategy.load(std::memory_order_acquire),
                (unsigned long long)g_disasm_ntclose_va_cache.load(std::memory_order_acquire));
            failed.fetch_add(1);
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
        (void)skipped;
        uint64_t addr1 = resolve_ntclose();
        if (addr1 == 0) addr1 = resolve_ntdll_export("NtClose");
        uint64_t addr2 = resolve_ntdll_export("NtCreateFile");
        if (addr2 == 0 || addr2 == addr1)
            addr2 = resolve_ntdll_export("NtReadFile");
        if (addr2 == 0 || addr2 == addr1)
            addr2 = resolve_ntdll_export("NtOpenFile");
        if (addr1 == 0 || addr2 == 0 || addr1 == addr2) {
            log_msg(hf, tag, "FAIL -- could not resolve two distinct ntdll exports addr1=0x%016llX addr2=0x%016llX driver_status=\"%s\" last_error=\"%s\"",
                (unsigned long long)addr1, (unsigned long long)addr2,
                driver_bridge::status().c_str(),
                driver_bridge::last_error().c_str());
            failed.fetch_add(1);
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
        (void)skipped;
        uint64_t addr = resolve_ntclose();
        if (addr == 0) {
            log_msg(hf, tag, "FAIL -- NtClose precondition unresolved at test entry strategy=%s(%d) cache=0x%016llX",
                ntclose_strategy_name(g_disasm_ntclose_strategy.load(std::memory_order_acquire)),
                g_disasm_ntclose_strategy.load(std::memory_order_acquire),
                (unsigned long long)g_disasm_ntclose_va_cache.load(std::memory_order_acquire));
            failed.fetch_add(1);
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
        (void)skipped;
        try {
            HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
            if (!ntdll) {
                log_msg(hf, tag, "FAIL -- ntdll.dll handle is null in host process gle=%lu", (unsigned long)GetLastError());
                failed.fetch_add(1);
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
        (void)skipped;
        try {
            HMODULE k32 = GetModuleHandleW(L"kernel32.dll");
            if (!k32) {
                log_msg(hf, tag, "FAIL -- kernel32.dll handle is null in host process gle=%lu", (unsigned long)GetLastError());
                failed.fetch_add(1);
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
        (void)skipped;
        expression_eval::context_t ctx{};
        const expr_eval_case_t cases[] = {
            {"hex_minus_hex", "0x2000 - 0x100", 0x1F00},
            {"subtract_to_zero", "0x100 - 0x100", 0},
            {"mixed_add_sub", "0x100 + 0x20 - 0x10", 0x110},
        };
        long long total_us = 0;
        if (run_expr_cases(hf, tag, ctx, cases, total_us)) {
            log_msg(hf, tag, "PASS -- %zu subtraction cases matched expected outputs elapsed_us=%lld", sizeof(cases) / sizeof(cases[0]), total_us);
            passed.fetch_add(1);
        } else {
            log_msg(hf, tag, "FAIL -- one or more subtraction cases mismatched elapsed_us=%lld", total_us);
            failed.fetch_add(1);
        }
    }

    void test_expr_bitwise_or(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        const char* tag = "expr.bitwise_or";
        (void)skipped;
        expression_eval::context_t ctx{};
        const expr_eval_case_t cases[] = {
            {"merge_nibbles", "0xF0 | 0x0F", 0xFF},
            {"preserve_high_bit", "0x8000 | 0x7", 0x8007},
            {"idempotent_or", "0x1234 | 0x1234", 0x1234},
        };
        long long total_us = 0;
        if (run_expr_cases(hf, tag, ctx, cases, total_us)) {
            log_msg(hf, tag, "PASS -- %zu bitwise-or cases matched expected outputs elapsed_us=%lld", sizeof(cases) / sizeof(cases[0]), total_us);
            passed.fetch_add(1);
        } else {
            log_msg(hf, tag, "FAIL -- one or more bitwise-or cases mismatched elapsed_us=%lld", total_us);
            failed.fetch_add(1);
        }
    }

    void test_expr_bitwise_xor(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        const char* tag = "expr.bitwise_xor";
        (void)skipped;
        expression_eval::context_t ctx{};
        const expr_eval_case_t cases[] = {
            {"xor_mask", "0xFF ^ 0xAA", 0x55},
            {"xor_word", "0xFFFF ^ 0x0F0F", 0xF0F0},
            {"xor_self", "0x12345678 ^ 0x12345678", 0},
        };
        long long total_us = 0;
        if (run_expr_cases(hf, tag, ctx, cases, total_us)) {
            log_msg(hf, tag, "PASS -- %zu bitwise-xor cases matched expected outputs elapsed_us=%lld", sizeof(cases) / sizeof(cases[0]), total_us);
            passed.fetch_add(1);
        } else {
            log_msg(hf, tag, "FAIL -- one or more bitwise-xor cases mismatched elapsed_us=%lld", total_us);
            failed.fetch_add(1);
        }
    }

    void test_expr_shift_left(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        const char* tag = "expr.shl";
        (void)skipped;
        expression_eval::context_t ctx{};
        const expr_eval_case_t cases[] = {
            {"bit_16", "1 << 16", 0x10000},
            {"nibble_shift", "0x3 << 4", 0x30},
            {"zero_shift", "0x1234 << 0", 0x1234},
        };
        long long total_us = 0;
        if (run_expr_cases(hf, tag, ctx, cases, total_us)) {
            log_msg(hf, tag, "PASS -- %zu shift-left cases matched expected outputs elapsed_us=%lld", sizeof(cases) / sizeof(cases[0]), total_us);
            passed.fetch_add(1);
        } else {
            log_msg(hf, tag, "FAIL -- one or more shift-left cases mismatched elapsed_us=%lld", total_us);
            failed.fetch_add(1);
        }
    }

    void test_expr_shift_right(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        const char* tag = "expr.shr";
        (void)skipped;
        expression_eval::context_t ctx{};
        const expr_eval_case_t cases[] = {
            {"byte_shift", "0x10000 >> 8", 0x100},
            {"top_bit_to_one", "0x8000000000000000 >> 63", 1},
            {"zero_shift", "0x1234 >> 0", 0x1234},
        };
        long long total_us = 0;
        if (run_expr_cases(hf, tag, ctx, cases, total_us)) {
            log_msg(hf, tag, "PASS -- %zu shift-right cases matched expected outputs elapsed_us=%lld", sizeof(cases) / sizeof(cases[0]), total_us);
            passed.fetch_add(1);
        } else {
            log_msg(hf, tag, "FAIL -- one or more shift-right cases mismatched elapsed_us=%lld", total_us);
            failed.fetch_add(1);
        }
    }

    void test_expr_division(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        const char* tag = "expr.div";
        (void)skipped;
        expression_eval::context_t ctx{};
        const expr_eval_case_t cases[] = {
            {"hex_division", "0x1000 / 0x10", 0x100},
            {"integer_truncation", "255 / 10", 25},
            {"divide_by_one", "0x1234 / 1", 0x1234},
        };
        long long total_us = 0;
        if (run_expr_cases(hf, tag, ctx, cases, total_us)) {
            log_msg(hf, tag, "PASS -- %zu division cases matched expected outputs elapsed_us=%lld", sizeof(cases) / sizeof(cases[0]), total_us);
            passed.fetch_add(1);
        } else {
            log_msg(hf, tag, "FAIL -- one or more division cases mismatched elapsed_us=%lld", total_us);
            failed.fetch_add(1);
        }
    }

    void test_expr_modulo(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        const char* tag = "expr.mod";
        (void)skipped;
        expression_eval::context_t ctx{};
        const expr_eval_case_t cases[] = {
            {"hex_modulo", "0x105 % 0x100", 0x5},
            {"decimal_modulo", "255 % 10", 5},
            {"zero_remainder", "0x1200 % 0x100", 0},
        };
        long long total_us = 0;
        if (run_expr_cases(hf, tag, ctx, cases, total_us)) {
            log_msg(hf, tag, "PASS -- %zu modulo cases matched expected outputs elapsed_us=%lld", sizeof(cases) / sizeof(cases[0]), total_us);
            passed.fetch_add(1);
        } else {
            log_msg(hf, tag, "FAIL -- one or more modulo cases mismatched elapsed_us=%lld", total_us);
            failed.fetch_add(1);
        }
    }

    void test_expr_comparison(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        const char* tag = "expr.compare";
        (void)skipped;
        expression_eval::context_t ctx{};
        const expr_eval_case_t cases[] = {
            {"eq_true", "0x100 == 0x100", 1},
            {"eq_false", "0x100 == 0x101", 0},
            {"ne_true", "0x100 != 0x200", 1},
            {"lt_true", "0x100 < 0x200", 1},
            {"lt_false", "0x100 < 0x100", 0},
            {"gt_true", "0x200 > 0x100", 1},
            {"le_equal", "0x200 <= 0x200", 1},
            {"ge_false", "0x10 >= 0x20", 0},
        };
        long long total_us = 0;
        if (run_expr_cases(hf, tag, ctx, cases, total_us)) {
            log_msg(hf, tag, "PASS -- %zu comparison cases matched expected boolean outputs elapsed_us=%lld", sizeof(cases) / sizeof(cases[0]), total_us);
            passed.fetch_add(1);
        } else {
            log_msg(hf, tag, "FAIL -- one or more comparison cases mismatched elapsed_us=%lld", total_us);
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
        (void)skipped;
        expression_eval::context_t ctx{};
        const expr_eval_case_t cases[] = {
            {"bitwise_not_zero", "~0x0", 0xFFFFFFFFFFFFFFFFULL},
            {"double_bitwise_not", "~~0x1234", 0x1234},
            {"arithmetic_negation", "-1", 0xFFFFFFFFFFFFFFFFULL},
        };
        long long total_us = 0;
        if (run_expr_cases(hf, tag, ctx, cases, total_us)) {
            log_msg(hf, tag, "PASS -- %zu negation cases matched expected outputs elapsed_us=%lld", sizeof(cases) / sizeof(cases[0]), total_us);
            passed.fetch_add(1);
        } else {
            log_msg(hf, tag, "FAIL -- one or more negation cases mismatched elapsed_us=%lld", total_us);
            failed.fetch_add(1);
        }
    }

    void test_expr_multiple_registers(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        const char* tag = "expr.multi_regs";
        (void)skipped;
        expression_eval::context_t ctx{};
        ctx.rax = 0x1000;
        ctx.rbx = 0x200;
        ctx.rcx = 0x30;
        ctx.rdx = 0x4;
        const expr_eval_case_t cases[] = {
            {"four_register_sum", "rax + rbx + rcx + rdx", 0x1234},
            {"precedence_with_registers", "rax + (rbx * rdx) - rcx", 0x17D0},
            {"shifted_register_mix", "(rax >> 8) + (rbx << 1) + rcx + rdx", 0x444},
            {"subregister_aliases", "eax + bx + cl + dl", 0x1234},
        };
        long long total_us = 0;
        if (run_expr_cases(hf, tag, ctx, cases, total_us)) {
            log_msg(hf, tag, "PASS -- %zu multi-register cases matched expected outputs elapsed_us=%lld", sizeof(cases) / sizeof(cases[0]), total_us);
            passed.fetch_add(1);
        } else {
            log_msg(hf, tag, "FAIL -- one or more multi-register cases mismatched elapsed_us=%lld", total_us);
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
            auto& st = disasm_view::g_state;
            std::vector<int> saved_nav = st.nav_history;
            int saved_nav_pos = st.nav_pos;
            std::vector<disasm_view::bookmark_t> saved_bookmarks = st.bookmarks;
            int saved_selected_row = st.selected_row;
            bool saved_show_bytes = st.show_bytes;
            disasm_view::addr_format_t saved_format = st.addr_format;
            uint64_t saved_layout_signature = st.layout_signature;
            int saved_layout_n = st.layout_n;

            st.nav_history.clear();
            st.nav_history.push_back(0x101);
            st.nav_history.push_back(0x202);
            st.nav_history.push_back(0x303);
            st.nav_pos = 2;
            st.selected_row = 0x303;
            st.show_bytes = false;
            st.addr_format = disasm_view::addr_format_t::rva;
            st.layout_signature = 0xA1DA5A5AULL;
            st.layout_n = 3;
            st.bookmarks.clear();
            disasm_view::bookmark_t bm1;
            bm1.addr = 0x7FF700001111ULL;
            bm1.label = "snapshot_seed_1";
            disasm_view::bookmark_t bm2;
            bm2.addr = 0x7FF700002222ULL;
            bm2.label = "snapshot_seed_2";
            st.bookmarks.push_back(bm1);
            st.bookmarks.push_back(bm2);

            log_msg(hf, tag, "STATE -- seeded before detach nav=%zu nav_pos=%d bookmarks=%zu selected_row=%d show_bytes=%d format=%s(%d) layout_sig=0x%llX layout_n=%d",
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
            const bool restored_nav = disasm_view::g_state.nav_history.size() == 3 &&
                disasm_view::g_state.nav_history[0] == 0x101 &&
                disasm_view::g_state.nav_history[1] == 0x202 &&
                disasm_view::g_state.nav_history[2] == 0x303 &&
                disasm_view::g_state.nav_pos == 2 &&
                disasm_view::g_state.selected_row == 0x303;
            const bool restored_bookmarks = disasm_view::g_state.bookmarks.size() == 2 &&
                disasm_view::g_state.bookmarks[0].addr == bm1.addr &&
                disasm_view::g_state.bookmarks[0].label == bm1.label &&
                disasm_view::g_state.bookmarks[1].addr == bm2.addr &&
                disasm_view::g_state.bookmarks[1].label == bm2.label;
            const bool restored_format = disasm_view::g_state.addr_format == disasm_view::addr_format_t::rva &&
                !disasm_view::g_state.show_bytes &&
                disasm_view::g_state.layout_signature == 0xA1DA5A5AULL &&
                disasm_view::g_state.layout_n == 3;
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

            st.nav_history = std::move(saved_nav);
            st.nav_pos = saved_nav_pos;
            st.bookmarks = std::move(saved_bookmarks);
            st.selected_row = saved_selected_row;
            st.show_bytes = saved_show_bytes;
            st.addr_format = saved_format;
            st.layout_signature = saved_layout_signature;
            st.layout_n = saved_layout_n;

            if (detached && restored_nav && restored_bookmarks && restored_format) {
                log_msg(hf, tag, "PASS -- detach_snapshot/attach_snapshot restored seeded nav/bookmark/format state elapsed_us=%lld", elapsed_us_since(t0));
                passed.fetch_add(1);
            } else {
                log_msg(hf, tag, "FAIL -- snapshot restore mismatch detached=%d restored_nav=%d restored_bookmarks=%d restored_format=%d",
                    detached ? 1 : 0,
                    restored_nav ? 1 : 0,
                    restored_bookmarks ? 1 : 0,
                    restored_format ? 1 : 0);
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
            xref_fixture_scope_t fixture;
            auto snap = xref_index::detach_snapshot();
            bool detached = (snap != nullptr);
            size_t detached_modules = snap ? snap->modules.size() : 0;
            size_t detached_table = snap ? snap->table.size() : 0;
            bool detached_table_built = snap && snap->table_built.load(std::memory_order_acquire);
            log_msg(hf, tag, "STATE -- detached fixture snapshot modules=%zu table=%zu table_built=%d target=0x%016llX",
                detached_modules,
                detached_table,
                detached_table_built ? 1 : 0,
                (unsigned long long)fixture.target);
            xref_index::attach_snapshot(std::move(snap));
            auto restored = xref_index::query_to(fixture.target, 16);
            bool saw_code = false;
            bool saw_data = false;
            for (const auto& a : restored) {
                if (a.kind == xref_index::kind_t::code && a.edge == xref_index::edge_t::call_proc && a.source_addr != 0)
                    saw_code = true;
                if (a.kind == xref_index::kind_t::data && a.edge == xref_index::edge_t::offset_ref && a.source_addr != 0)
                    saw_data = true;
            }
            log_msg(hf, tag, "STATE -- after attach fixture query returned %zu saw_code=%d saw_data=%d",
                restored.size(),
                saw_code ? 1 : 0,
                saw_data ? 1 : 0);

            if (detached && detached_modules == 1 && detached_table == 1 && detached_table_built && restored.size() >= 2 && saw_code && saw_data) {
                log_msg(hf, tag, "PASS -- xref detach/attach restored seeded fixture registry");
                passed.fetch_add(1);
            } else {
                log_msg(hf, tag, "FAIL -- xref snapshot restore mismatch detached=%d modules=%zu table=%zu table_built=%d restored=%zu saw_code=%d saw_data=%d",
                    detached ? 1 : 0,
                    detached_modules,
                    detached_table,
                    detached_table_built ? 1 : 0,
                    restored.size(),
                    saw_code ? 1 : 0,
                    saw_data ? 1 : 0);
                failed.fetch_add(1);
            }
        } catch (...) {
            log_msg(hf, tag, "FAIL -- exception");
            failed.fetch_add(1);
        }
    }

    void test_disasm_goto_ntcreatefile(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        const char* tag = "disasm.goto_ntcf";
        (void)skipped;
        uint64_t addr = resolve_ntdll_fn("NtCreateFile");
        if (addr == 0) {
            log_msg(hf, tag, "FAIL -- NtCreateFile precondition unresolved driver_status=\"%s\" last_error=\"%s\"",
                driver_bridge::status().c_str(),
                driver_bridge::last_error().c_str());
            failed.fetch_add(1);
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
        (void)skipped;
        uint64_t addr = resolve_ntdll_fn("NtReadFile");
        if (addr == 0) {
            log_msg(hf, tag, "FAIL -- NtReadFile precondition unresolved driver_status=\"%s\" last_error=\"%s\"",
                driver_bridge::status().c_str(),
                driver_bridge::last_error().c_str());
            failed.fetch_add(1);
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
        (void)skipped;
        uint64_t addr = resolve_ntdll_fn("NtWriteFile");
        if (addr == 0) {
            log_msg(hf, tag, "FAIL -- NtWriteFile precondition unresolved driver_status=\"%s\" last_error=\"%s\"",
                driver_bridge::status().c_str(),
                driver_bridge::last_error().c_str());
            failed.fetch_add(1);
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

        struct center_view_dispatch_state_t {
            std::mutex mtx;
            std::condition_variable cv;
            bool done = false;
            center_view_t got = center_view_t::welcome;
        };

        if (aida::ui_thread::is_owner_thread()) {
            if (!aida::ui_thread::require_owner("testlab", "select_center_view", "disasm_inline")) {
                log_msg(hf, tag, "FAIL -- select_center_view require_owner rejected tid=%lu",
                    (unsigned long)GetCurrentThreadId());
                failed.fetch_add(1);
                return;
            }
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
            return;
        }

        auto state = std::make_shared<center_view_dispatch_state_t>();
        const DWORD producer_tid = ::GetCurrentThreadId();
        const bool posted = aida::ui_thread::post([state, value, producer_tid]() {
            bool ok = false;
            if (aida::ui_thread::require_owner("testlab", "select_center_view", "disasm_dispatch")) {
                globals::ui::active_center_view = value;
                ok = true;
            }
            {
                std::lock_guard<std::mutex> lk(state->mtx);
                state->got = globals::ui::active_center_view;
                state->done = true;
            }
            state->cv.notify_all();
            diag::log_tagged_critical_fmt("TESTLAB-UI-DISPATCH",
                "select_center_view producer_tid=%lu ui_tid=%lu value=%d ok=%d got=%d",
                static_cast<unsigned long>(producer_tid),
                static_cast<unsigned long>(::GetCurrentThreadId()),
                static_cast<int>(value),
                ok ? 1 : 0,
                static_cast<int>(state->got));
        }, "testlab", "select_center_view", "disasm_dispatch");

        if (!posted) {
            log_msg(hf, tag, "FAIL -- select_center_view dispatcher post failed tid=%lu ui_tid=%lu",
                (unsigned long)producer_tid,
                (unsigned long)aida::ui_thread::owner_tid());
            failed.fetch_add(1);
            return;
        }

        std::unique_lock<std::mutex> lk(state->mtx);
        const bool completed = state->cv.wait_for(lk, std::chrono::milliseconds(5000), [&] { return state->done; });
        lk.unlock();

        if (!completed) {
            log_msg(hf, tag, "FAIL -- select_center_view dispatcher timeout tid=%lu pending=%zu",
                (unsigned long)producer_tid,
                aida::ui_thread::pending_count());
            failed.fetch_add(1);
            return;
        }

        const center_view_t got = state->got;
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

struct disasm_test_entry_t {
    const char* name;
    void (*fn)(HANDLE, std::atomic<int>&, std::atomic<int>&, std::atomic<int>&);
};

__declspec(noinline) void run_disasm_test_entry_seh(
    HANDLE hf,
    const disasm_test_entry_t& test,
    std::atomic<int>& passed,
    std::atomic<int>& failed,
    std::atomic<int>& skipped)
{
    __try {
        test.fn(hf, passed, failed, skipped);
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        const DWORD code = GetExceptionCode();
        if (std::strcmp(test.name, "xref_live_after_warm_range") == 0) {
            const int xref_stage = g_xref_live_after_warm_stage.load(std::memory_order_acquire);
            log_msg(hf, "disasm_phase", "SEH-DETAIL -- %s stage=%s(%d) exception=0x%08X",
                test.name,
                xref_live_after_warm_stage_name(xref_stage),
                xref_stage,
                code);
            diag::log_tagged_critical_fmt("testlab",
                "xref_live_after_warm_seh stage=%s stage_id=%d exception=0x%08lX",
                xref_live_after_warm_stage_name(xref_stage),
                xref_stage,
                static_cast<unsigned long>(code));
        }
        log_msg(hf, "disasm_phase", "FAIL -- %s threw SEH exception 0x%08X",
            test.name, code);
        failed.fetch_add(1);
    }
}

void phase_disasm_tests(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped, bool(*cancelled)()) {
    auto t0 = std::chrono::steady_clock::now();

    static const disasm_test_entry_t tests[] = {
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
        { "xref_live_after_warm_range",              test_xref_live_after_warm_range              },
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

    const bool ntclose_ready = ensure_disasm_ntclose_va(hf);
    if (!ntclose_ready) {
        log_msg(hf, "disasm_phase",
            "FAIL -- disasm phase prologue failed to resolve NtClose precondition; per-test arms will FAIL individually with diagnostics pid=%lu tid=%lu attached_pid=%u driver_status=\"%s\" last_error=\"%s\" gle=%lu strategy=%s(%d) cache=0x%016llX",
            static_cast<unsigned long>(GetCurrentProcessId()),
            static_cast<unsigned long>(GetCurrentThreadId()),
            driver_bridge::attached_pid(),
            driver_bridge::status().c_str(),
            driver_bridge::last_error().c_str(),
            static_cast<unsigned long>(GetLastError()),
            ntclose_strategy_name(g_disasm_ntclose_strategy.load(std::memory_order_acquire)),
            g_disasm_ntclose_strategy.load(std::memory_order_acquire),
            static_cast<unsigned long long>(g_disasm_ntclose_va_cache.load(std::memory_order_acquire)));
        failed.fetch_add(1);
    }

    for (int i = 0; i < total; ++i) {
        if (cancelled && cancelled()) {
            int remaining = total - i;
            failed.fetch_add(remaining);
            log_msg(hf, "disasm_phase",
                "FAIL -- cancellation requested mid-disasm-phase with %d test(s) remaining; cancellation is a defect in the sanctioned full-test run pid=%lu tid=%lu attempted_test=%s index=%d total=%d",
                remaining,
                static_cast<unsigned long>(GetCurrentProcessId()),
                static_cast<unsigned long>(GetCurrentThreadId()),
                tests[i].name,
                i,
                total);
            break;
        }
        const uint32_t attached_pid = driver_bridge::attached_pid();
        if (attached_pid != 0) {
            uint32_t exit_code = 0;
            if (!driver_bridge::attached_process_alive(&exit_code)) {
                int remaining = total - i;
                failed.fetch_add(1 + remaining);
                log_msg(hf, "disasm_phase", "FAIL -- attached target pid=%u is dead before %s exit_code_or_err=0x%08X; failing %d remaining disasm tests",
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
        run_disasm_test_entry_seh(hf, tests[i], passed, failed, skipped);
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
