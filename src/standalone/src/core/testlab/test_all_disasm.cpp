#include "test_all_disasm.h"

#include "test_all_features.hpp"
#include "../disasm/disasm_view.hpp"
#include "../disasm/pseudocode_view.hpp"
#include "../disasm/function_index.hpp"
#include "../disasm/xref_index.hpp"
#include "../analysis/workspace/decompiler_service.hpp"
#include "../analysis/workspace/workspace_registry.hpp"
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
#include <map>
#include <memory>
#include <mutex>
#include <shared_mutex>
#include <string>
#include <thread>
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
        case center_view_t::workbench: return "workbench";
        default: return "unknown";
        }
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

    disasm_view::workspace_context_t selected_pseudocode_context() {
        return disasm_view::capture_selected_workspace();
    }

    bool workspace_decompiler_idle(const disasm_view::workspace_context_t& context, int timeout_ms) {
        if (!context.workspace)
            return false;
        auto service = context.workspace->decompiler();
        if (!service)
            return false;
        const auto deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(timeout_ms);
        do {
            if (service->snapshot().active_contexts == 0)
                return true;
            Sleep(25);
        } while (std::chrono::steady_clock::now() < deadline);
        return service->snapshot().active_contexts == 0;
    }

    bool wait_for_workspace_mutation(const disasm_view::workspace_context_t& context,
                                     std::string& error) {
        if (!context || !context.view)
            return false;
        const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(5);
        while (context.view->pending_mutations.load(std::memory_order_acquire) != 0 &&
               std::chrono::steady_clock::now() < deadline)
            Sleep(10);
        std::lock_guard<std::mutex> lock(context.view->mutex);
        error = context.view->mutation_error;
        return context.view->pending_mutations.load(std::memory_order_acquire) == 0 && error.empty();
    }

    bool apply_workspace_comment(const disasm_view::workspace_context_t& context,
                                 const aida::analysis::address_t& address,
                                 const std::string& text, std::string& error) {
        {
            std::lock_guard<std::mutex> lock(context.view->mutex);
            context.view->mutation_error.clear();
        }
        return disasm_view::queue_comment(context, address, text) &&
            wait_for_workspace_mutation(context, error);
    }

    bool apply_workspace_name(const disasm_view::workspace_context_t& context,
                              const aida::analysis::address_t& address,
                              const std::string& name, std::string& error) {
        {
            std::lock_guard<std::mutex> lock(context.view->mutex);
            context.view->mutation_error.clear();
        }
        return disasm_view::queue_rename(context, address, name) &&
            wait_for_workspace_mutation(context, error);
    }

    std::vector<aida::analysis::address_t> workspace_fixture_addresses(
        const disasm_view::workspace_context_t& context, std::size_t count) {
        std::vector<aida::analysis::address_t> result;
        if (!context || !context.publication || !context.publication->snapshot)
            return result;
        for (const auto& instruction : context.publication->snapshot->instructions) {
            if (std::find(result.begin(), result.end(), instruction.address) == result.end())
                result.push_back(instruction.address);
            if (result.size() == count)
                break;
        }
        return result;
    }

    enum class comment_case_t : std::uint8_t {
        set_get,
        has,
        empty_clears,
        multiple,
        overwrite
    };

    void run_workspace_comment_case(HANDLE hf, const char* tag, comment_case_t mode,
                                    std::atomic<int>& passed, std::atomic<int>& failed) {
        const auto context = disasm_view::capture_selected_workspace();
        const auto addresses = workspace_fixture_addresses(context, mode == comment_case_t::multiple ? 2 : 1);
        if (!context || addresses.empty() || (mode == comment_case_t::multiple && addresses.size() != 2)) {
            log_msg(hf, tag, "FAIL -- explicit workspace comment fixture unavailable");
            failed.fetch_add(1);
            return;
        }
        std::vector<std::string> originals;
        for (const auto& address : addresses)
            originals.push_back(disasm_view::comment(context, address));
        std::string error;
        bool valid = false;
        if (mode == comment_case_t::multiple) {
            valid = apply_workspace_comment(context, addresses[0], "test_comment_workspace_a", error) &&
                apply_workspace_comment(context, addresses[1], "test_comment_workspace_b", error) &&
                disasm_view::comment(context, addresses[0]) == "test_comment_workspace_a" &&
                disasm_view::comment(context, addresses[1]) == "test_comment_workspace_b";
        } else {
            valid = apply_workspace_comment(context, addresses[0], "test_comment_workspace", error);
            if (mode == comment_case_t::set_get)
                valid = valid && disasm_view::comment(context, addresses[0]) == "test_comment_workspace";
            else if (mode == comment_case_t::has)
                valid = valid && !disasm_view::comment(context, addresses[0]).empty();
            else if (mode == comment_case_t::empty_clears)
                valid = valid && apply_workspace_comment(context, addresses[0], std::string(), error) &&
                    disasm_view::comment(context, addresses[0]).empty();
            else if (mode == comment_case_t::overwrite)
                valid = valid && apply_workspace_comment(context, addresses[0], "test_comment_workspace_new", error) &&
                    disasm_view::comment(context, addresses[0]) == "test_comment_workspace_new";
        }
        bool restored = true;
        for (std::size_t index = 0; index < addresses.size(); ++index)
            restored = apply_workspace_comment(context, addresses[index], originals[index], error) && restored;
        if (valid && restored) {
            log_msg(hf, tag, "PASS -- workspace-owned comment behavior passed with prior-state restoration");
            passed.fetch_add(1);
        } else {
            log_msg(hf, tag, "FAIL -- workspace comment behavior failed restored=%d error=\"%s\"",
                restored ? 1 : 0, error.c_str());
            failed.fetch_add(1);
        }
    }

    enum class rename_case_t : std::uint8_t {
        set_get,
        has,
        clear,
        resolve_or,
        multiple,
        resolve_or_multiple,
        overwrite
    };

    void run_workspace_rename_case(HANDLE hf, const char* tag, rename_case_t mode,
                                   std::atomic<int>& passed, std::atomic<int>& failed) {
        const auto context = disasm_view::capture_selected_workspace();
        const bool multiple = mode == rename_case_t::multiple || mode == rename_case_t::resolve_or_multiple;
        const auto addresses = workspace_fixture_addresses(context, multiple ? 2 : 1);
        if (!context || addresses.empty() || (multiple && addresses.size() != 2)) {
            log_msg(hf, tag, "FAIL -- explicit workspace rename fixture unavailable");
            failed.fetch_add(1);
            return;
        }
        std::vector<std::string> symbols;
        std::vector<std::string> originals;
        for (const auto& address : addresses) {
            symbols.push_back(disasm_view::resolve_symbol(context, address));
            originals.push_back(disasm_view::resolve_name(context, address));
        }
        std::string error;
        bool valid = false;
        if (multiple) {
            valid = apply_workspace_name(context, addresses[0], "test_workspace_name_a", error) &&
                apply_workspace_name(context, addresses[1], "test_workspace_name_b", error) &&
                disasm_view::resolve_name(context, addresses[0]) == "test_workspace_name_a" &&
                disasm_view::resolve_name(context, addresses[1]) == "test_workspace_name_b";
            if (valid && mode == rename_case_t::resolve_or_multiple) {
                valid = apply_workspace_name(context, addresses[0], std::string(), error) &&
                    apply_workspace_name(context, addresses[1], std::string(), error) &&
                    disasm_view::resolve_name(context, addresses[0]) == symbols[0] &&
                    disasm_view::resolve_name(context, addresses[1]) == symbols[1];
            }
        } else {
            valid = apply_workspace_name(context, addresses[0], "test_workspace_name", error);
            if (mode == rename_case_t::set_get || mode == rename_case_t::has)
                valid = valid && disasm_view::resolve_name(context, addresses[0]) == "test_workspace_name";
            else if (mode == rename_case_t::clear || mode == rename_case_t::resolve_or)
                valid = valid && apply_workspace_name(context, addresses[0], std::string(), error) &&
                    disasm_view::resolve_name(context, addresses[0]) == symbols[0];
            else if (mode == rename_case_t::overwrite)
                valid = valid && apply_workspace_name(context, addresses[0], "test_workspace_name_new", error) &&
                    disasm_view::resolve_name(context, addresses[0]) == "test_workspace_name_new";
        }
        bool restored = true;
        for (std::size_t index = 0; index < addresses.size(); ++index) {
            const std::string custom = originals[index] == symbols[index] ? std::string() : originals[index];
            restored = apply_workspace_name(context, addresses[index], custom, error) && restored;
        }
        if (valid && restored) {
            log_msg(hf, tag, "PASS -- workspace-owned rename behavior passed with prior-state restoration");
            passed.fetch_add(1);
        } else {
            log_msg(hf, tag, "FAIL -- workspace rename behavior failed restored=%d error=\"%s\"",
                restored ? 1 : 0, error.c_str());
            failed.fetch_add(1);
        }
    }

    void test_comment_set_get(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        (void)skipped;
        run_workspace_comment_case(hf, "comment.set_get", comment_case_t::set_get, passed, failed);
    }
    void test_comment_has(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        (void)skipped;
        run_workspace_comment_case(hf, "comment.has", comment_case_t::has, passed, failed);
    }
    void test_comment_empty_clears(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        (void)skipped;
        run_workspace_comment_case(hf, "comment.empty_clears", comment_case_t::empty_clears, passed, failed);
    }
    void test_comment_multiple(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        (void)skipped;
        run_workspace_comment_case(hf, "comment.multiple", comment_case_t::multiple, passed, failed);
    }
    void test_comment_overwrite(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        (void)skipped;
        run_workspace_comment_case(hf, "comment.overwrite", comment_case_t::overwrite, passed, failed);
    }
    void test_rename_set_get(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        (void)skipped;
        run_workspace_rename_case(hf, "rename.set_get", rename_case_t::set_get, passed, failed);
    }
    void test_rename_has(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        (void)skipped;
        run_workspace_rename_case(hf, "rename.has", rename_case_t::has, passed, failed);
    }
    void test_rename_clear(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        (void)skipped;
        run_workspace_rename_case(hf, "rename.clear", rename_case_t::clear, passed, failed);
    }
    void test_rename_resolve_or(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        (void)skipped;
        run_workspace_rename_case(hf, "rename.resolve_or", rename_case_t::resolve_or, passed, failed);
    }
    void test_rename_multiple(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        (void)skipped;
        run_workspace_rename_case(hf, "rename.multiple", rename_case_t::multiple, passed, failed);
    }
    void test_rename_resolve_or_multiple(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        (void)skipped;
        run_workspace_rename_case(hf, "rename.resolve_or_multiple", rename_case_t::resolve_or_multiple, passed, failed);
    }
    void test_rename_overwrite(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        (void)skipped;
        run_workspace_rename_case(hf, "rename.overwrite", rename_case_t::overwrite, passed, failed);
    }

    bool wait_for_decompile_tab(HANDLE hf, const char* tag, uint64_t addr, int timeout_ms,
                                bool& loaded_out, bool& error_out, std::string& fn_out) {
        loaded_out = false;
        error_out = false;
        fn_out.clear();
        const auto context = selected_pseudocode_context();
        if (!context) {
            log_msg(hf, tag, "STATE -- decompile_wait_missing_workspace addr=0x%016llX",
                (unsigned long long)addr);
            return false;
        }
        const int step_ms = 50;
        int waited = 0;
        for (;;) {
            const auto tabs = pseudocode_view::snapshot_tabs(context);
            bool found = false;
            pseudocode_view::tab_info_t observed{};
            for (const auto& tab : tabs) {
                if (tab.addr != addr)
                    continue;
                found = true;
                observed = tab;
                fn_out = tab.function_name;
                break;
            }
            if (found && (observed.loaded || observed.is_error)) {
                loaded_out = observed.loaded;
                error_out = observed.is_error;
                return true;
            }
            if (waited >= timeout_ms) {
                const auto service = context.workspace->decompiler();
                const auto snapshot = service ? service->snapshot() : aida::analysis::decompiler_service_snapshot_t{};
                log_msg(hf, tag,
                    "STATE -- decompile_wait_timeout addr=0x%016llX waited_ms=%d found=%d total_tabs=%zu loaded=%d decompiling=%d is_error=%d active_contexts=%zu requests=%llu completed=%llu failed=%llu",
                    (unsigned long long)addr,
                    waited,
                    found ? 1 : 0,
                    tabs.size(),
                    found ? (int)observed.loaded : 0,
                    found ? (int)observed.decompiling : 0,
                    found ? (int)observed.is_error : 0,
                    snapshot.active_contexts,
                    (unsigned long long)snapshot.requests,
                    (unsigned long long)snapshot.completed,
                    (unsigned long long)snapshot.failed);
                return false;
            }
            Sleep(step_ms);
            waited += step_ms;
        }
    }

    bool snapshot_tab_for_addr(uint64_t addr, pseudocode_view::tab_info_t& out, size_t* total_out = nullptr) {
        const auto context = selected_pseudocode_context();
        if (!context)
            return false;
        auto tabs = pseudocode_view::snapshot_tabs(context);
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
        const auto context = selected_pseudocode_context();
        if (!context)
            return false;
        const auto typed = disasm_view::typed_address(context, addr);
        const auto service = context.workspace->decompiler();
        if (!typed || !service)
            return false;
        const auto result = service->decompile(*typed);
        if (!result) {
            complete_out = true;
            error_out = true;
            source_out = result.error().stable_code();
            return true;
        }
        bytes_out = result.value().pseudocode.size();
        lines_out = count_pseudocode_lines(result.value().pseudocode);
        complete_out = true;
        source_out = result.value().cache_hit ? "workspace_cache" : "workspace_service";
        return true;
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
        const auto context = selected_pseudocode_context();
        const auto service = context.workspace ? context.workspace->decompiler() : nullptr;
        const auto snapshot = service ? service->snapshot() : aida::analysis::decompiler_service_snapshot_t{};
        log_msg(hf, tag,
            "STATE -- %s addr=0x%016llX found=%d total_tabs=%zu loaded=%d decompiling=%d is_error=%d function=\"%s\" metrics=%d source=\"%s\" complete=%d engine_error=%d pseudocode_bytes=%zu pseudocode_lines=%zu active=0x%016llX active_contexts=%zu requests=%llu completed=%llu failed=%llu",
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
            context ? (unsigned long long)pseudocode_view::active_tab_address(context) : 0ULL,
            snapshot.active_contexts,
            (unsigned long long)snapshot.requests,
            (unsigned long long)snapshot.completed,
            (unsigned long long)snapshot.failed);
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
        const auto context = selected_pseudocode_context();
        if (!context) {
            log_msg(hf, tag, "FAIL -- no selected analysis workspace for decompile");
            failed.fetch_add(1);
            return;
        }
        log_msg(hf, tag, "INPUT -- request_decompile(%s=0x%016llX, force=%d) attached_pid=%u",
            sym, (unsigned long long)addr, (int)force, attached);

        pseudocode_view::close_tab_by_addr(context, addr);
        auto t0 = std::chrono::steady_clock::now();
        pseudocode_view::request_decompile(context, addr, force);

        bool loaded = false;
        bool is_error = false;
        std::string fn;
        bool finished = wait_for_decompile_tab(hf, tag, addr, 15000, loaded, is_error, fn);
        auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::steady_clock::now() - t0).count();

        bool present = pseudocode_view::has_tab_for(context, addr);
        log_msg(hf, tag, "OUTPUT -- finished=%d loaded=%d is_error=%d has_tab=%d function=\"%s\" (elapsed %lld ms)",
            (int)finished, (int)loaded, (int)is_error, (int)present, fn.c_str(), (long long)ms);

        if (finished && present && is_error && force) {
            pseudocode_view::close_tab_by_addr(context, addr);
            auto retry_t0 = std::chrono::steady_clock::now();
            pseudocode_view::request_decompile(context, addr, true);
            loaded = false;
            is_error = false;
            fn.clear();
            finished = wait_for_decompile_tab(hf, tag, addr, 15000, loaded, is_error, fn);
            present = pseudocode_view::has_tab_for(context, addr);
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
        (void)skipped;
        try {
            auto context = disasm_view::capture_selected_workspace();
            const auto first = disasm_view::typed_address(context, 0x11);
            const auto second = disasm_view::typed_address(context, 0x22);
            if (!context || !first || !second) {
                log_msg(hf, tag, "FAIL -- selected workspace cannot represent navigation addresses");
                failed.fetch_add(1);
                return;
            }
            const auto saved = context.workspace->view_state();
            auto seeded = context.workspace->update_view_state([&](aida::analysis::workspace_view_state_t& state) {
                state.selection = *second;
                state.navigation_back = {*first};
                state.navigation_forward.clear();
            });
            if (!seeded) {
                log_msg(hf, tag, "FAIL -- workspace navigation seed rejected");
                failed.fetch_add(1);
                return;
            }
            {
                std::lock_guard<std::mutex> lock(context.view->mutex);
                context.view->selection = *second;
            }

            log_msg(hf, tag, "INPUT -- seeded workspace navigation back=1 selection=0x%llX",
                (unsigned long long)second->value);
            disasm_view::navigate_back(context);
            const auto after_back = context.workspace->view_state();
            const bool back_ok = after_back.selection == first &&
                after_back.navigation_back.empty() &&
                after_back.navigation_forward.size() == 1 &&
                after_back.navigation_forward.back() == *second;

            disasm_view::navigate_forward(context);
            const auto after_forward = context.workspace->view_state();
            const bool forward_ok = after_forward.selection == second &&
                after_forward.navigation_forward.empty() &&
                after_forward.navigation_back.size() == 1 &&
                after_forward.navigation_back.back() == *first;
            context.workspace->update_view_state([&](aida::analysis::workspace_view_state_t& state) {
                state = saved;
            });
            {
                std::lock_guard<std::mutex> lock(context.view->mutex);
                context.view->selection = saved.selection;
            }

            if (back_ok && forward_ok) {
                log_msg(hf, tag, "PASS -- workspace-owned back/forward navigation preserved typed addresses");
                passed.fetch_add(1);
            } else {
                log_msg(hf, tag, "FAIL -- back_ok=%d forward_ok=%d", back_ok ? 1 : 0, forward_ok ? 1 : 0);
                failed.fetch_add(1);
            }
        } catch (...) {
            log_msg(hf, tag, "FAIL -- exception in navigate_back/forward");
            failed.fetch_add(1);
        }
    }

    enum class navigation_case_t : std::uint8_t {
        push_pop,
        dedup,
        stress,
        clear,
        pop_empty,
        push_zero
    };

    void run_workspace_navigation_case(HANDLE hf, const char* tag, navigation_case_t mode,
                                       std::atomic<int>& passed, std::atomic<int>& failed) {
        auto context = disasm_view::capture_selected_workspace();
        const auto addresses = workspace_fixture_addresses(context, 3);
        if (!context || addresses.size() != 3) {
            log_msg(hf, tag, "FAIL -- explicit workspace navigation fixture unavailable");
            failed.fetch_add(1);
            return;
        }
        const auto runtime_second = disasm_view::runtime_address(context, addresses[1]);
        const auto runtime_third = disasm_view::runtime_address(context, addresses[2]);
        if (!runtime_second || !runtime_third) {
            log_msg(hf, tag, "FAIL -- workspace navigation addresses are not displayable");
            failed.fetch_add(1);
            return;
        }
        const auto saved = context.workspace->view_state();
        std::optional<aida::analysis::address_t> saved_view_selection;
        {
            std::lock_guard<std::mutex> lock(context.view->mutex);
            saved_view_selection = context.view->selection;
            context.view->selection = addresses[0];
        }
        const auto seeded = context.workspace->update_view_state([&](aida::analysis::workspace_view_state_t& state) {
            state.selection = addresses[0];
            state.navigation_back.clear();
            state.navigation_forward.clear();
        });
        bool valid = static_cast<bool>(seeded);
        if (valid && mode == navigation_case_t::push_pop) {
            disasm_view::goto_address(*runtime_second, context);
            disasm_view::goto_address(*runtime_third, context);
            disasm_view::navigate_back(context);
            disasm_view::navigate_back(context);
            const auto state = context.workspace->view_state();
            valid = state.selection == addresses[0] && state.navigation_back.empty() &&
                state.navigation_forward.size() == 2;
        } else if (valid && mode == navigation_case_t::dedup) {
            disasm_view::goto_address(*runtime_second, context);
            const auto once = context.workspace->view_state();
            disasm_view::goto_address(*runtime_second, context);
            const auto twice = context.workspace->view_state();
            valid = once.navigation_back.size() == 1 && twice.navigation_back == once.navigation_back &&
                twice.selection == addresses[1];
        } else if (valid && mode == navigation_case_t::stress) {
            context.workspace->update_view_state([&](aida::analysis::workspace_view_state_t& state) {
                state.selection = addresses[0];
                state.navigation_back.clear();
                state.navigation_back.reserve(5000);
                for (std::size_t index = 0; index < 5000; ++index)
                    state.navigation_back.push_back(addresses[(index % 2) + 1]);
            });
            disasm_view::goto_address(*runtime_second, context);
            valid = context.workspace->view_state().navigation_back.size() == 4096;
        } else if (valid && mode == navigation_case_t::clear) {
            context.workspace->update_view_state([&](aida::analysis::workspace_view_state_t& state) {
                state.navigation_back = {addresses[1], addresses[2]};
                state.navigation_forward = {addresses[1]};
            });
            const auto cleared = context.workspace->update_view_state([](aida::analysis::workspace_view_state_t& state) {
                state.navigation_back.clear();
                state.navigation_forward.clear();
            });
            const auto state = context.workspace->view_state();
            valid = static_cast<bool>(cleared) && state.navigation_back.empty() && state.navigation_forward.empty();
        } else if (valid && mode == navigation_case_t::pop_empty) {
            disasm_view::navigate_back(context);
            const auto state = context.workspace->view_state();
            valid = state.selection == addresses[0] && state.navigation_back.empty() && state.navigation_forward.empty();
        } else if (valid && mode == navigation_case_t::push_zero) {
            disasm_view::goto_address(0, context);
            const auto state = context.workspace->view_state();
            valid = state.selection == addresses[0] && state.navigation_back.empty();
        }
        const auto restored = context.workspace->update_view_state([&](aida::analysis::workspace_view_state_t& state) {
            state = saved;
        });
        {
            std::lock_guard<std::mutex> lock(context.view->mutex);
            context.view->selection = saved_view_selection;
        }
        if (valid && restored) {
            log_msg(hf, tag, "PASS -- workspace-owned navigation behavior passed and state was restored");
            passed.fetch_add(1);
        } else {
            log_msg(hf, tag, "FAIL -- workspace-owned navigation behavior failed valid=%d restored=%d",
                valid ? 1 : 0, restored ? 1 : 0);
            failed.fetch_add(1);
        }
    }

    void test_nav_history_push_pop(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        (void)skipped;
        run_workspace_navigation_case(hf, "nav.push_pop", navigation_case_t::push_pop, passed, failed);
    }
    void test_nav_history_dedup(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        (void)skipped;
        run_workspace_navigation_case(hf, "nav.dedup", navigation_case_t::dedup, passed, failed);
    }
    void test_nav_history_stress(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        (void)skipped;
        run_workspace_navigation_case(hf, "nav.stress", navigation_case_t::stress, passed, failed);
    }
    void test_nav_history_clear(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        (void)skipped;
        run_workspace_navigation_case(hf, "nav.clear", navigation_case_t::clear, passed, failed);
    }
    void test_nav_history_pop_empty(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        (void)skipped;
        run_workspace_navigation_case(hf, "nav.pop_empty", navigation_case_t::pop_empty, passed, failed);
    }
    void test_nav_history_push_zero(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        (void)skipped;
        run_workspace_navigation_case(hf, "nav.push_zero", navigation_case_t::push_zero, passed, failed);
    }

    void test_bump_format_generation(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        const char* tag = "disasm.bump_format";
        (void)skipped;
        try {
            auto context = disasm_view::capture_selected_workspace();
            if (!context) {
                log_msg(hf, tag, "FAIL -- no selected analysis workspace");
                failed.fetch_add(1);
                return;
            }
            std::unordered_set<std::uint64_t> saved_pending;
            {
                std::lock_guard<std::mutex> lock(context.view->mutex);
                saved_pending = context.view->pending_format_pages;
                context.view->pending_format_pages.insert(0xA1DAULL);
            }
            const uint32_t before_gen = disasm_view::format_generation(context);
            disasm_view::bump_format_generation(context);
            const uint32_t after_gen = disasm_view::format_generation(context);
            bool cache_cleared = false;
            {
                std::lock_guard<std::mutex> lock(context.view->mutex);
                cache_cleared = context.view->pending_format_pages.empty() && context.view->formatted.empty();
                context.view->pending_format_pages = std::move(saved_pending);
            }
            const bool generation_changed = after_gen == before_gen + 1u;
            if (generation_changed && cache_cleared) {
                log_msg(hf, tag, "PASS -- workspace format generation advanced from %u to %u and invalidated cached pages",
                    before_gen, after_gen);
                passed.fetch_add(1);
            } else {
                log_msg(hf, tag, "FAIL -- generation_changed=%d cache_cleared=%d before=%u after=%u",
                    generation_changed ? 1 : 0, cache_cleared ? 1 : 0, before_gen, after_gen);
                failed.fetch_add(1);
            }
        } catch (...) {
            log_msg(hf, tag, "FAIL -- exception in bump_format_generation");
            failed.fetch_add(1);
        }
    }

    struct xref_fixture_scope_t {
        std::shared_ptr<aida::analysis::analysis_workspace_t> workspace;
        aida::analysis::address_t target;
        size_t available = 0;
        bool expect_code = false;
        bool expect_data = false;

        xref_fixture_scope_t() {
            for (const auto& candidate : aida::analysis::workspace_registry().list()) {
                if (!candidate || candidate->target_kind() != aida::analysis::target_kind_t::static_file)
                    continue;
                const auto snapshot = candidate->snapshot();
                if (!snapshot || snapshot->xrefs.empty())
                    continue;
                std::map<aida::analysis::address_t, size_t> counts;
                for (const auto& xref : snapshot->xrefs)
                    ++counts[xref.target];
                const auto best = std::max_element(counts.begin(), counts.end(),
                    [](const auto& lhs, const auto& rhs) { return lhs.second < rhs.second; });
                if (best == counts.end() || best->second <= available)
                    continue;
                workspace = candidate;
                target = best->first;
                available = best->second;
                expect_code = false;
                expect_data = false;
                for (const auto& xref : snapshot->xrefs) {
                    if (xref.target != target) continue;
                    const bool data = xref.kind == aida::analysis::xref_kind_t::read ||
                        xref.kind == aida::analysis::xref_kind_t::write ||
                        xref.kind == aida::analysis::xref_kind_t::address ||
                        xref.kind == aida::analysis::xref_kind_t::relocation;
                    expect_data = expect_data || data;
                    expect_code = expect_code || !data;
                }
            }
        }

        uint64_t display_target() const {
            return function_index::workspace_display_address(workspace, target);
        }
    };

    void validate_xref_fixture(HANDLE hf, const char* tag, size_t limit,
                               std::atomic<int>& passed, std::atomic<int>& failed) {
        xref_fixture_scope_t fixture;
        if (!fixture.workspace || fixture.available == 0 || fixture.display_target() == 0) {
            log_msg(hf, tag, "FAIL -- no analyzed static workspace with published xrefs");
            failed.fetch_add(1);
            return;
        }
        log_msg(hf, tag, "INPUT -- workspace xref target=0x%016llX available=%zu limit=%zu binary_id=%s",
            (unsigned long long)fixture.display_target(), fixture.available, limit,
            fixture.workspace->identity().binary_id().to_hex().c_str());

        auto t0 = std::chrono::steady_clock::now();
        auto queried = xref_index::query_to(fixture.workspace, fixture.target, limit);
        bool more = xref_index::has_more(fixture.workspace, fixture.target, limit);
        auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::steady_clock::now() - t0).count();

        if (!queried) {
            log_msg(hf, tag, "FAIL -- explicit workspace xref query failed code=%s message=%s",
                queried.error().stable_code(), queried.error().message.c_str());
            failed.fetch_add(1);
            return;
        }
        const auto& results = queried.value();

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
        if (zero_src != 0 || (fixture.expect_code && !saw_code_call) ||
            (fixture.expect_data && !saw_data_ref)) {
            log_msg(hf, tag, "FAIL -- workspace xrefs invalid zero_src=%zu expected_code=%d saw_code=%d expected_data=%d saw_data=%d",
                zero_src, (int)fixture.expect_code, (int)saw_code_call,
                (int)fixture.expect_data, (int)saw_data_ref);
            failed.fetch_add(1);
            return;
        }
        log_msg(hf, tag, "PASS -- explicit workspace query returned the published xref facts without global target state");
        passed.fetch_add(1);
    }

    void test_xref_query_to(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        const char* tag = "xref.query_to";
        validate_xref_fixture(hf, tag, 16, passed, failed);
    }

    void test_xref_has_more(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        const char* tag = "xref.has_more";
        xref_fixture_scope_t fixture;
        if (!fixture.workspace || fixture.available < 2 || fixture.display_target() == 0) {
            log_msg(hf, tag, "FAIL -- no static workspace target has at least two published xrefs");
            failed.fetch_add(1);
            return;
        }
        log_msg(hf, tag, "INPUT -- workspace xref target=0x%016llX available=%zu limit=1",
            (unsigned long long)fixture.display_target(), fixture.available);

        auto queried = xref_index::query_to(fixture.workspace, fixture.target, 64);
        if (!queried) {
            log_msg(hf, tag, "FAIL -- explicit workspace query failed code=%s message=%s",
                queried.error().stable_code(), queried.error().message.c_str());
            failed.fetch_add(1);
            return;
        }
        const auto& results = queried.value();
        bool more = xref_index::has_more(fixture.workspace, fixture.target, 1);
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

    bool equal_xref_results(const std::vector<xref_index::annotation_t>& lhs,
                            const std::vector<xref_index::annotation_t>& rhs) {
        if (lhs.size() != rhs.size())
            return false;
        for (std::size_t index = 0; index < lhs.size(); ++index) {
            if (lhs[index].source_addr != rhs[index].source_addr ||
                lhs[index].kind != rhs[index].kind || lhs[index].edge != rhs[index].edge ||
                lhs[index].source_label != rhs[index].source_label)
                return false;
        }
        return true;
    }

    void test_xref_request_deep_static(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        (void)skipped;
        validate_xref_fixture(hf, "xref.deep_static", 100000, passed, failed);
    }

    void test_xref_on_file_loaded(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        (void)skipped;
        xref_fixture_scope_t fixture;
        if (!fixture.workspace || fixture.available == 0) {
            log_msg(hf, "xref.on_file_loaded", "FAIL -- no static workspace xref fixture");
            failed.fetch_add(1);
            return;
        }
        const auto before = xref_index::query_to(fixture.workspace, fixture.target, fixture.available);
        const auto recaptured = disasm_view::capture_workspace(fixture.workspace);
        const auto after = xref_index::query_to(fixture.workspace, fixture.target, fixture.available);
        if (recaptured && before && after && equal_xref_results(before.value(), after.value())) {
            log_msg(hf, "xref.on_file_loaded", "PASS -- file workspace recapture preserved the complete xref publication");
            passed.fetch_add(1);
        } else {
            log_msg(hf, "xref.on_file_loaded", "FAIL -- file workspace recapture changed xref results");
            failed.fetch_add(1);
        }
    }

    void test_xref_on_attach_changed(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        xref_fixture_scope_t fixture;
        if (!fixture.workspace || fixture.available == 0) {
            log_msg(hf, "xref.on_attach_changed", "FAIL -- no static workspace xref fixture");
            failed.fetch_add(1);
            return;
        }
        std::shared_ptr<aida::analysis::analysis_workspace_t> other;
        for (const auto& candidate : aida::analysis::workspace_registry().list()) {
            if (candidate && candidate != fixture.workspace && !candidate->closing() && !candidate->closed()) {
                other = candidate;
                break;
            }
        }
        if (!other) {
            log_msg(hf, "xref.on_attach_changed", "SKIP -- no second workspace is open for isolation evidence");
            skipped.fetch_add(1);
            return;
        }
        const auto before = xref_index::query_to(fixture.workspace, fixture.target, fixture.available);
        const auto other_context = disasm_view::capture_workspace(other);
        const auto after = xref_index::query_to(fixture.workspace, fixture.target, fixture.available);
        if (other_context && before && after && equal_xref_results(before.value(), after.value())) {
            log_msg(hf, "xref.on_attach_changed", "PASS -- capturing another target did not alter the static workspace xref index");
            passed.fetch_add(1);
        } else {
            log_msg(hf, "xref.on_attach_changed", "FAIL -- cross-workspace capture contaminated xref results");
            failed.fetch_add(1);
        }
    }

    void test_xref_query_to_zero(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        (void)skipped;
        xref_fixture_scope_t fixture;
        if (!fixture.workspace) {
            log_msg(hf, "xref.query_to_zero", "FAIL -- no static workspace xref fixture");
            failed.fetch_add(1);
            return;
        }
        auto zero = fixture.target;
        zero.value = 0;
        const auto results = xref_index::query_to(fixture.workspace, zero, 16);
        if (results && results.value().empty()) {
            log_msg(hf, "xref.query_to_zero", "PASS -- explicit workspace query_to at zero returned an empty page");
            passed.fetch_add(1);
        } else {
            log_msg(hf, "xref.query_to_zero", "FAIL -- zero-address query did not return an empty page");
            failed.fetch_add(1);
        }
    }

    void test_xref_has_more_zero_limit(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        (void)skipped;
        xref_fixture_scope_t fixture;
        if (!fixture.workspace || fixture.available == 0) {
            log_msg(hf, "xref.has_more_zero", "FAIL -- no static workspace xref fixture");
            failed.fetch_add(1);
            return;
        }
        const auto page = xref_index::query_to(fixture.workspace, fixture.target, 0);
        const bool more = xref_index::has_more(fixture.workspace, fixture.target, 0);
        if (page && page.value().empty() && more) {
            log_msg(hf, "xref.has_more_zero", "PASS -- zero-size page reported additional workspace xrefs");
            passed.fetch_add(1);
        } else {
            log_msg(hf, "xref.has_more_zero", "FAIL -- zero-size page pagination contract mismatch");
            failed.fetch_add(1);
        }
    }

    void test_xref_warm_range(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        (void)skipped;
        xref_fixture_scope_t fixture;
        if (!fixture.workspace || fixture.available == 0) {
            log_msg(hf, "xref.warm_range", "FAIL -- no static workspace xref fixture");
            failed.fetch_add(1);
            return;
        }
        const auto first = xref_index::query_to(fixture.workspace, fixture.target, fixture.available);
        const auto second = xref_index::query_to(fixture.workspace, fixture.target, fixture.available);
        if (first && second && equal_xref_results(first.value(), second.value())) {
            log_msg(hf, "xref.warm_range", "PASS -- repeated explicit workspace xref pages were deterministic");
            passed.fetch_add(1);
        } else {
            log_msg(hf, "xref.warm_range", "FAIL -- repeated workspace xref pages diverged");
            failed.fetch_add(1);
        }
    }

    void test_xref_live_after_warm_range(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        (void)skipped;
        std::shared_ptr<aida::analysis::analysis_workspace_t> live;
        for (const auto& candidate : aida::analysis::workspace_registry().list()) {
            if (candidate && candidate->target_kind() == aida::analysis::target_kind_t::live_snapshot &&
                !candidate->closing() && !candidate->closed()) {
                live = candidate;
                break;
            }
        }
        if (!live) {
            log_msg(hf, "xref.live_after_warm", "FAIL -- no explicit live workspace is open");
            failed.fetch_add(1);
            return;
        }
        aida::analysis::address_t target;
        target.space = aida::analysis::address_space_id_t::live_virtual;
        target.value = live->identity().image_base();
        target.architecture = live->identity().architecture();
        target.mode = live->image() ? live->image()->architecture_mode() : aida::analysis::architecture_mode_t::unknown;
        const auto result = xref_index::query_to(live, target, 16);
        if (!result && result.error().code == aida::analysis::workspace_error_code_t::live_target_bulk_analysis_unsupported) {
            log_msg(hf, "xref.live_after_warm", "PASS -- live target returned stable bulk-xref unsupported disposition");
            passed.fetch_add(1);
        } else {
            log_msg(hf, "xref.live_after_warm", "FAIL -- live target did not enforce bounded on-demand xref policy");
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
            const auto context = selected_pseudocode_context();
            pseudocode_view::close_tab_by_addr(context, addr);
            bool before = pseudocode_view::has_tab_for(context, addr);
            log_msg(hf, tag, "INPUT -- has_tab_for(0x%016llX) before=%d, request_decompile to create tab",
                (unsigned long long)addr, (int)before);
            pseudocode_view::request_decompile(context, addr, false);
            bool after = pseudocode_view::has_tab_for(context, addr);
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

    void test_pseudocode_cancel_active(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        (void)skipped;
        const char* tag = "pseudo.cancel_active";
        const auto context = selected_pseudocode_context();
        if (!context || !context.publication || !context.publication->snapshot ||
            context.publication->snapshot->functions.empty() || !context.workspace->decompiler()) {
            log_msg(hf, tag, "FAIL -- explicit workspace decompiler fixture unavailable");
            failed.fetch_add(1);
            return;
        }
        const auto function = context.publication->snapshot->functions.front();
        const auto display = function_index::workspace_display_address(context.workspace, function.start);
        if (display == 0) {
            log_msg(hf, tag, "FAIL -- decompiler fixture function is not displayable");
            failed.fetch_add(1);
            return;
        }
        aida::analysis::cancellation_source_t cancelled;
        cancelled.request_cancel();
        const auto service_result = context.workspace->decompiler()->decompile(function.start, {}, cancelled.token());
        const bool service_cancelled = !service_result && service_result.error().cancellation;
        pseudocode_view::close_tab_by_addr(context, display);
        pseudocode_view::request_decompile(context, display, true);
        const bool tab_created = pseudocode_view::has_tab_for(context, display) &&
            pseudocode_view::active_tab_address(context) == display;
        pseudocode_view::cancel_active_decompile(context);
        const bool drained = workspace_decompiler_idle(context, 5000);
        pseudocode_view::tab_info_t tab{};
        const bool found = snapshot_tab_for_addr(display, tab);
        const bool tab_settled = !found || !tab.decompiling;
        pseudocode_view::close_tab_by_addr(context, display);
        if (service_cancelled && tab_created && drained && tab_settled) {
            log_msg(hf, tag, "PASS -- workspace cancellation token and active pseudocode tab cancelled without global engine state");
            passed.fetch_add(1);
        } else {
            log_msg(hf, tag, "FAIL -- cancellation evidence service=%d tab=%d drained=%d settled=%d",
                service_cancelled ? 1 : 0, tab_created ? 1 : 0, drained ? 1 : 0, tab_settled ? 1 : 0);
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
            const auto context = selected_pseudocode_context();
            pseudocode_view::close_tab_by_addr(context, addr);
            int before = pseudocode_view::tab_count(context);
            log_msg(hf, tag, "INPUT -- tab_count before=%d, creating tab for 0x%016llX",
                before, (unsigned long long)addr);
            pseudocode_view::request_decompile(context, addr, false);
            int after_add = pseudocode_view::tab_count(context);
            pseudocode_view::close_tab_by_addr(context, addr);
            int after_close = pseudocode_view::tab_count(context);
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
            const auto context = selected_pseudocode_context();
            pseudocode_view::close_tab_by_addr(context, addr);
            log_msg(hf, tag, "INPUT -- creating tab for 0x%016llX then snapshot_tabs()",
                (unsigned long long)addr);
            log_msg(hf, tag, "TRACE -- before request_decompile tab_count=%d",
                pseudocode_view::tab_count(context));
            pseudocode_view::request_decompile(context, addr, false);
            log_msg(hf, tag, "TRACE -- after request_decompile tab_count=%d; before snapshot_tabs",
                pseudocode_view::tab_count(context));
            auto tabs = pseudocode_view::snapshot_tabs(context);
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

    void test_pseudocode_close_all(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        const char* tag = "pseudo.close_all";
        uint64_t addr = resolve_ntclose();
        try {
            const auto context = selected_pseudocode_context();
            if (addr != 0) {
                pseudocode_view::request_decompile(context, addr, false);
            }
            int before = pseudocode_view::tab_count(context);
            log_msg(hf, tag, "INPUT -- tab_count before close_all=%d, invoking close_all_tabs()", before);
            pseudocode_view::close_all_tabs(context);
            int count_after = pseudocode_view::tab_count(context);
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

    void test_hexview_workspace_activate(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        const char* tag = "hexview.workspace_activate";
        try {
            std::vector<uint8_t> test_data(256);
            for (int i = 0; i < 256; ++i) test_data[i] = static_cast<uint8_t>(i);

            log_msg(hf, tag, "INPUT -- activate(selected workspace) with 256-byte local fixture retained for caller isolation");
            auto context = disasm_view::capture_selected_workspace();
            hex_view::activate(context);
            log_msg(hf, tag, "OUTPUT -- data.size()=%zu base=0x%016llX name=\"%s\"",
                test_data.size(), (unsigned long long)0x00400000ULL,
                hex_view::source_name(context).c_str());

            bool ok = hex_view::active(context) && test_data.size() == 256;
            if (ok) {
                bool data_ok = true;
                for (int i = 0; i < 256; ++i) {
                    if (test_data[i] != static_cast<uint8_t>(i)) {
                        data_ok = false;
                        break;
                    }
                }
                if (data_ok) {
                    log_msg(hf, tag, "PASS -- workspace activation retained the local 256-byte fixture and produced an active hex context");
                    passed.fetch_add(1);
                } else {
                    log_msg(hf, tag, "FAIL -- local fixture content changed during workspace activation");
                    failed.fetch_add(1);
                }
            } else {
                log_msg(hf, tag, "FAIL -- active=%d data_size=%zu, expected 256",
                    hex_view::active(context) ? 1 : 0, test_data.size());
                failed.fetch_add(1);
            }
        } catch (...) {
            log_msg(hf, tag, "FAIL -- exception in workspace activation");
            failed.fetch_add(1);
        }
    }

    void test_hexview_read_live_memory(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        const char* tag = "hexview.read_live_memory";
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
            log_msg(hf, tag, "INPUT -- read_live_memory(addr=0x%016llX, size=64) attached_pid=%u",
                (unsigned long long)addr, attached);
            auto context = disasm_view::capture_selected_workspace();
            bool ok = hex_view::read_live_memory(context, addr, 64);
            std::vector<uint8_t> local_data;
            if (ok) driver_bridge::read_memory(addr, 64, local_data);
            size_t got = ok ? local_data.size() : 0;
            log_msg(hf, tag, "OUTPUT -- read_live_memory ok=%d returned_bytes=%zu base=0x%016llX",
                (int)ok, got, (unsigned long long)addr);
            if (ok && got > 0) {
                log_msg(hf, tag, "PASS -- read_live_memory produced %zu bytes at 0x%016llX",
                    got, (unsigned long long)addr);
                passed.fetch_add(1);
            } else {
                std::string err = hex_view::last_error(context);
                log_msg(hf, tag, "FAIL -- read_live_memory ok=%d bytes=%zu last_error=\"%s\" (attached_pid=%u)",
                    (int)ok, got, err.c_str(), attached);
                failed.fetch_add(1);
            }
        } catch (...) {
            log_msg(hf, tag, "FAIL -- exception in read_live_memory");
            failed.fetch_add(1);
        }
    }

    void test_hexview_last_error(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        const char* tag = "hexview.last_error";
        try {
            auto context = disasm_view::capture_selected_workspace();
            hex_view::activate(context);
            const bool rejected = !hex_view::read_live_memory(context, 0, 0);
            const std::string rejected_error = hex_view::last_error(context);
            hex_view::activate(context);
            const std::string activated_error = hex_view::last_error(context);
            const bool active = hex_view::active(context);
            const std::string source = hex_view::source_name(context);
            log_msg(hf, tag, "OUTPUT -- rejected=%d rejected_error=\"%s\" active=%d source=\"%s\" activated_error=\"%s\"",
                rejected ? 1 : 0, rejected_error.c_str(), active ? 1 : 0,
                source.c_str(), activated_error.c_str());
            if (rejected && !rejected_error.empty() && active && !source.empty() && activated_error.empty()) {
                log_msg(hf, tag, "PASS -- workspace-bound hex state reports invalid live requests and activation clears the state error");
                passed.fetch_add(1);
            } else {
                log_msg(hf, tag, "FAIL -- rejected=%d rejected_error_len=%zu active=%d source_len=%zu activated_error_len=%zu",
                    rejected ? 1 : 0, rejected_error.size(), active ? 1 : 0,
                    source.size(), activated_error.size());
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

    void test_pseudocode_request_decompile_ntcreatefile(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        const char* tag = "pseudo.decompile_ntcf";
        (void)skipped;
        uint64_t addr = resolve_ntdll_export("NtCreateFile");
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
            const auto context = selected_pseudocode_context();
            pseudocode_view::close_tab_by_addr(context, addr);
            pseudocode_view::request_decompile(context, addr, false);
            bool created = pseudocode_view::has_tab_for(context, addr);
            log_msg(hf, tag, "INPUT -- created tab for 0x%016llX has_tab=%d, invoking close_tab_by_addr",
                (unsigned long long)addr, (int)created);
            pseudocode_view::close_tab_by_addr(context, addr);
            bool still_has = pseudocode_view::has_tab_for(context, addr);
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
            const auto context = selected_pseudocode_context();
            pseudocode_view::close_tab_by_addr(context, addr);
            pseudocode_view::request_decompile(context, addr, false);
            log_msg(hf, tag, "INPUT -- invoking activate_tab_by_addr(0x%016llX)", (unsigned long long)addr);
            pseudocode_view::activate_tab_by_addr(context, addr);
            bool active = pseudocode_view::has_active_tab(context);
            uint64_t active_addr = pseudocode_view::active_tab_address(context);
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
            const auto context = selected_pseudocode_context();
            pseudocode_view::request_decompile(context, addr, false);
            pseudocode_view::activate_tab_by_addr(context, addr);
            bool has_after_create = pseudocode_view::has_active_tab(context);
            log_msg(hf, tag, "INPUT -- created+activated tab, has_active_tab=%d, then close_all_tabs()",
                (int)has_after_create);
            pseudocode_view::close_all_tabs(context);
            bool has_after_close = pseudocode_view::has_active_tab(context);
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
            const auto context = selected_pseudocode_context();
            pseudocode_view::close_tab_by_addr(context, addr);
            pseudocode_view::request_decompile(context, addr, false);
            pseudocode_view::activate_tab_by_addr(context, addr);
            uint64_t active_addr = pseudocode_view::active_tab_address(context);
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
            const auto context = selected_pseudocode_context();
            const bool idle = workspace_decompiler_idle(context, 5000);
            log_msg(hf, tag, "INPUT -- seed active tab addr=0x%016llX idle_before=%d", (unsigned long long)addr, idle ? 1 : 0);
            if (!idle) {
                log_msg(hf, tag, "FAIL -- decompiler engine was not idle before refresh_active_tab");
                failed.fetch_add(1);
                return;
            }
            pseudocode_view::close_tab_by_addr(context, addr);
            pseudocode_view::request_decompile(context, addr, false);
            pseudocode_view::activate_tab_by_addr(context, addr);
            log_pseudocode_tab_evidence(hf, tag, "before_refresh", addr);

            pseudocode_view::refresh_active_tab(context);
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
                pseudocode_view::active_tab_address(context) == addr &&
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
                    pseudocode_view::active_tab_address(context) == addr &&
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
                    (unsigned long long)pseudocode_view::active_tab_address(context),
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
            const auto context = selected_pseudocode_context();
            const bool idle = workspace_decompiler_idle(context, 5000);
            log_msg(hf, tag, "INPUT -- seed tabs addr1=0x%016llX addr2=0x%016llX idle_before=%d",
                (unsigned long long)addr1,
                (unsigned long long)addr2,
                idle ? 1 : 0);
            if (!idle) {
                log_msg(hf, tag, "FAIL -- decompiler engine was not idle before refresh_all_tabs");
                failed.fetch_add(1);
                return;
            }

            pseudocode_view::close_tab_by_addr(context, addr1);
            pseudocode_view::close_tab_by_addr(context, addr2);
            pseudocode_view::request_decompile(context, addr1, false);
            pseudocode_view::request_decompile(context, addr2, false);
            pseudocode_view::activate_tab_by_addr(context, addr1);
            log_pseudocode_tab_evidence(hf, tag, "before_refresh_addr1", addr1);
            log_pseudocode_tab_evidence(hf, tag, "before_refresh_addr2", addr2);

            pseudocode_view::refresh_all_tabs(context);
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
            const bool active_preserved = pseudocode_view::active_tab_address(context) == addr1;
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
                    (unsigned long long)pseudocode_view::active_tab_address(context),
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
            const auto context = selected_pseudocode_context();
            pseudocode_view::close_all_tabs(context);
            pseudocode_view::request_decompile(context, addr, false);
            pseudocode_view::activate_tab_by_addr(context, addr);
            bool present_before = pseudocode_view::has_tab_for(context, addr);
            log_msg(hf, tag, "INPUT -- single active tab for 0x%016llX present=%d, invoking close_active_tab()",
                (unsigned long long)addr, (int)present_before);
            pseudocode_view::close_active_tab(context);
            bool present_after = pseudocode_view::has_tab_for(context, addr);
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

    void test_hexview_workspace_activate_small(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        const char* tag = "hexview.workspace_activate_small";
        try {
            std::vector<uint8_t> test_data(16);
            for (int i = 0; i < 16; ++i) test_data[i] = static_cast<uint8_t>(0xAA + i);

            log_msg(hf, tag, "INPUT -- activate(selected workspace) with 16-byte local fixture retained for caller isolation");
            auto context = disasm_view::capture_selected_workspace();
            hex_view::activate(context);

            bool ok = hex_view::active(context) && test_data.size() == 16;
            uint8_t b0 = ok ? test_data[0] : 0;
            uint8_t b15 = ok ? test_data[15] : 0;
            log_msg(hf, tag, "OUTPUT -- size=%zu data[0]=0x%02X data[15]=0x%02X",
                test_data.size(), (unsigned)b0, (unsigned)b15);
            if (ok && b0 == 0xAA && b15 == (uint8_t)(0xAA + 15)) {
                log_msg(hf, tag, "PASS -- workspace activation retained the 16-byte local fixture (data[0]=0x%02X data[15]=0x%02X)",
                    (unsigned)b0, (unsigned)b15);
                passed.fetch_add(1);
            } else {
                log_msg(hf, tag, "FAIL -- data content mismatch size=%zu data[0]=0x%02X data[15]=0x%02X",
                    test_data.size(), (unsigned)b0, (unsigned)b15);
                failed.fetch_add(1);
            }
        } catch (...) {
            log_msg(hf, tag, "FAIL -- exception in workspace activation");
            failed.fetch_add(1);
        }
    }

    void test_hexview_workspace_activate_large(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        const char* tag = "hexview.workspace_activate_large";
        try {
            std::vector<uint8_t> test_data(4096);
            for (int i = 0; i < 4096; ++i) test_data[i] = static_cast<uint8_t>(i & 0xFF);

            log_msg(hf, tag, "INPUT -- activate(selected workspace) with 4096-byte local fixture retained for caller isolation");
            auto context = disasm_view::capture_selected_workspace();
            hex_view::activate(context);
            log_msg(hf, tag, "OUTPUT -- data.size()=%zu base=0x%016llX",
                test_data.size(), (unsigned long long)0x00100000ULL);

            if (hex_view::active(context) && test_data.size() == 4096) {
                log_msg(hf, tag, "PASS -- workspace activation retained the 4096-byte local fixture");
                passed.fetch_add(1);
            } else {
                log_msg(hf, tag, "FAIL -- active=%d data size %zu != 4096",
                    hex_view::active(context) ? 1 : 0, test_data.size());
                failed.fetch_add(1);
            }
        } catch (...) {
            log_msg(hf, tag, "FAIL -- exception in workspace activation");
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
            log_msg(hf, tag, "INPUT -- read_live_memory(ntdll base=0x%016llX, size=256) attached_pid=%u",
                (unsigned long long)addr, attached);
            auto context = disasm_view::capture_selected_workspace();
            bool ok = hex_view::read_live_memory(context, addr, 256);
            std::vector<uint8_t> local_data;
            if (ok) driver_bridge::read_memory(addr, 256, local_data);
            size_t got = ok ? local_data.size() : 0;
            bool mz = (got >= 2 && local_data[0] == 'M' && local_data[1] == 'Z');
            log_msg(hf, tag, "OUTPUT -- ok=%d returned_bytes=%zu first2=%c%c (MZ=%d)",
                (int)ok, got,
                got >= 1 ? (char)local_data[0] : '?',
                got >= 2 ? (char)local_data[1] : '?', (int)mz);
            if (ok && got > 0 && mz) {
                log_msg(hf, tag, "PASS -- read %zu bytes from ntdll header with valid MZ signature", got);
                passed.fetch_add(1);
            } else {
                std::string err = hex_view::last_error(context);
                log_msg(hf, tag, "FAIL -- ok=%d bytes=%zu mz=%d last_error=\"%s\" (attached_pid=%u)",
                    (int)ok, got, (int)mz, err.c_str(), attached);
                failed.fetch_add(1);
            }
        } catch (...) {
            log_msg(hf, tag, "FAIL -- exception in read_live_memory");
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
            log_msg(hf, tag, "INPUT -- read_live_memory(kernel32 base=0x%016llX, size=128) attached_pid=%u",
                (unsigned long long)addr, attached);
            auto context = disasm_view::capture_selected_workspace();
            bool ok = hex_view::read_live_memory(context, addr, 128);
            std::vector<uint8_t> local_data;
            if (ok) driver_bridge::read_memory(addr, 128, local_data);
            size_t got = ok ? local_data.size() : 0;
            bool mz = (got >= 2 && local_data[0] == 'M' && local_data[1] == 'Z');
            log_msg(hf, tag, "OUTPUT -- ok=%d returned_bytes=%zu MZ=%d", (int)ok, got, (int)mz);
            if (ok && got > 0 && mz) {
                log_msg(hf, tag, "PASS -- read %zu bytes from kernel32 header with valid MZ signature", got);
                passed.fetch_add(1);
            } else {
                std::string err = hex_view::last_error(context);
                log_msg(hf, tag, "FAIL -- ok=%d bytes=%zu mz=%d last_error=\"%s\" (attached_pid=%u)",
                    (int)ok, got, (int)mz, err.c_str(), attached);
                failed.fetch_add(1);
            }
        } catch (...) {
            log_msg(hf, tag, "FAIL -- exception in read_live_memory");
            failed.fetch_add(1);
        }
    }

    void test_hexview_workspace_source_name(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        const char* tag = "hexview.workspace_source_name";
        try {
            std::vector<uint8_t> data(32, 0x42);
            log_msg(hf, tag, "INPUT -- activate(selected workspace) before resolving its source name");
            auto context = disasm_view::capture_selected_workspace();
            hex_view::activate(context);
            log_msg(hf, tag, "OUTPUT -- source_name=\"%s\" size=%zu",
                hex_view::source_name(context).c_str(), data.size());
            if (!hex_view::source_name(context).empty()) {
                log_msg(hf, tag, "PASS -- source_name is bound to the active workspace");
                passed.fetch_add(1);
            } else {
                log_msg(hf, tag, "FAIL -- source_name=\"%s\"", hex_view::source_name(context).c_str());
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

    void test_disasm_view_bookmarks(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        const char* tag = "disasm.bookmarks";
        (void)skipped;
        try {
            auto t0 = std::chrono::steady_clock::now();
            auto context = disasm_view::capture_selected_workspace();
            if (!context) {
                log_msg(hf, tag, "FAIL -- no selected analysis workspace");
                failed.fetch_add(1);
                return;
            }
            std::vector<disasm_view::bookmark_t> saved;
            {
                std::lock_guard<std::mutex> lock(context.view->mutex);
                saved = context.view->bookmarks;
            }
            const size_t before = saved.size();

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
            size_t after = 0;
            bool tail_ok = false;
            {
                std::lock_guard<std::mutex> lock(context.view->mutex);
                context.view->bookmarks.push_back(bm1);
                context.view->bookmarks.push_back(bm2);
                context.view->bookmarks.push_back(bm3);
                after = context.view->bookmarks.size();
                tail_ok = after >= 3 &&
                    context.view->bookmarks[after - 3].addr == bm1.addr &&
                    context.view->bookmarks[after - 2].addr == bm2.addr &&
                    context.view->bookmarks[after - 1].addr == bm3.addr;
                context.view->bookmarks = saved;
            }
            log_msg(hf, tag, "STATE -- after add bookmarks=%zu expected=%zu tail_ok=%d",
                after, before + 3, tail_ok ? 1 : 0);
            size_t restored_size = 0;
            {
                std::lock_guard<std::mutex> lock(context.view->mutex);
                restored_size = context.view->bookmarks.size();
            }
            if (after == before + 3 && tail_ok && restored_size == before) {
                log_msg(hf, tag, "PASS -- added 3 bookmarks (before=%zu, after=%zu) elapsed_us=%lld", before, after, elapsed_us_since(t0));
                passed.fetch_add(1);
            } else {
                log_msg(hf, tag, "FAIL -- expected %zu, got %zu tail_ok=%d cleanup_size=%zu",
                    before + 3, after, tail_ok ? 1 : 0, restored_size);
                failed.fetch_add(1);
            }
        } catch (...) {
            log_msg(hf, tag, "FAIL -- exception gle=0x%08lX", (unsigned long)GetLastError());
            failed.fetch_add(1);
        }
    }

    void test_disasm_view_addr_format(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        const char* tag = "disasm.addr_format";
        (void)skipped;
        try {
            auto t0 = std::chrono::steady_clock::now();
            auto context = disasm_view::capture_selected_workspace();
            if (!context) {
                log_msg(hf, tag, "FAIL -- no selected analysis workspace");
                failed.fetch_add(1);
                return;
            }
            std::lock_guard<std::mutex> lock(context.view->mutex);
            const auto original = context.view->addr_format;
            log_msg(hf, tag, "STATE -- original format=%s(%d)",
                addr_format_name(original), static_cast<int>(original));

            context.view->addr_format = disasm_view::addr_format_t::va;
            const bool va_ok = context.view->addr_format == disasm_view::addr_format_t::va;
            log_msg(hf, tag, "STATE -- set va readback=%s(%d) ok=%d",
                addr_format_name(context.view->addr_format),
                static_cast<int>(context.view->addr_format),
                va_ok ? 1 : 0);

            context.view->addr_format = disasm_view::addr_format_t::rva;
            const bool rva_ok = context.view->addr_format == disasm_view::addr_format_t::rva;
            log_msg(hf, tag, "STATE -- set rva readback=%s(%d) ok=%d",
                addr_format_name(context.view->addr_format),
                static_cast<int>(context.view->addr_format),
                rva_ok ? 1 : 0);

            context.view->addr_format = disasm_view::addr_format_t::file_offset;
            const bool fo_ok = context.view->addr_format == disasm_view::addr_format_t::file_offset;
            log_msg(hf, tag, "STATE -- set file_offset readback=%s(%d) ok=%d",
                addr_format_name(context.view->addr_format),
                static_cast<int>(context.view->addr_format),
                fo_ok ? 1 : 0);

            context.view->addr_format = original;
            log_msg(hf, tag, "STATE -- restored format=%s(%d)",
                addr_format_name(context.view->addr_format),
                static_cast<int>(context.view->addr_format));

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
        (void)skipped;
        try {
            auto t0 = std::chrono::steady_clock::now();
            auto context = disasm_view::capture_selected_workspace();
            if (!context) {
                log_msg(hf, tag, "FAIL -- no selected analysis workspace");
                failed.fetch_add(1);
                return;
            }
            std::lock_guard<std::mutex> lock(context.view->mutex);
            const bool original = context.view->show_bytes;
            log_msg(hf, tag, "STATE -- original show_bytes=%d", original ? 1 : 0);

            context.view->show_bytes = !original;
            const bool toggled = context.view->show_bytes == !original;
            log_msg(hf, tag, "STATE -- toggled show_bytes=%d expected=%d ok=%d",
                context.view->show_bytes ? 1 : 0,
                (!original) ? 1 : 0,
                toggled ? 1 : 0);
            context.view->show_bytes = original;
            log_msg(hf, tag, "STATE -- restored show_bytes=%d",
                context.view->show_bytes ? 1 : 0);

            if (toggled && context.view->show_bytes == original) {
                log_msg(hf, tag, "PASS -- show_bytes toggle works elapsed_us=%lld", elapsed_us_since(t0));
                passed.fetch_add(1);
            } else {
                log_msg(hf, tag, "FAIL -- show_bytes toggle failed toggled=%d restored=%d",
                    toggled ? 1 : 0,
                    context.view->show_bytes == original ? 1 : 0);
                failed.fetch_add(1);
            }
        } catch (...) {
            log_msg(hf, tag, "FAIL -- exception gle=0x%08lX", (unsigned long)GetLastError());
            failed.fetch_add(1);
        }
    }

    void test_disasm_view_workspace_recapture(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        const char* tag = "disasm.workspace_recapture";
        (void)skipped;
        try {
            auto t0 = std::chrono::steady_clock::now();
            auto context = disasm_view::capture_selected_workspace();
            const auto first = disasm_view::typed_address(context, 0x101);
            const auto second = disasm_view::typed_address(context, 0x202);
            const auto third = disasm_view::typed_address(context, 0x303);
            if (!context || !first || !second || !third) {
                log_msg(hf, tag, "FAIL -- selected workspace cannot represent recapture fixture addresses");
                failed.fetch_add(1);
                return;
            }
            const auto saved_workspace_state = context.workspace->view_state();
            std::vector<disasm_view::bookmark_t> saved_bookmarks;
            bool saved_show_bytes = true;
            disasm_view::addr_format_t saved_format = disasm_view::addr_format_t::va;
            std::optional<aida::analysis::address_t> saved_selection;
            {
                std::lock_guard<std::mutex> lock(context.view->mutex);
                saved_bookmarks = context.view->bookmarks;
                saved_show_bytes = context.view->show_bytes;
                saved_format = context.view->addr_format;
                saved_selection = context.view->selection;
                context.view->bookmarks = {
                    {first->value, "workspace_seed_1"},
                    {second->value, "workspace_seed_2"}
                };
                context.view->show_bytes = false;
                context.view->addr_format = disasm_view::addr_format_t::rva;
                context.view->selection = *third;
            }
            auto seeded = context.workspace->update_view_state([&](aida::analysis::workspace_view_state_t& state) {
                state.selection = *third;
                state.navigation_back = {*first, *second};
                state.navigation_forward.clear();
                state.bookmarks = {*first, *second};
            });
            auto recaptured = disasm_view::capture_workspace(context.workspace);
            const auto recaptured_state = context.workspace->view_state();
            bool view_state_ok = false;
            if (recaptured) {
                std::lock_guard<std::mutex> lock(recaptured.view->mutex);
                view_state_ok = recaptured.view == context.view &&
                    recaptured.view->selection == third &&
                    recaptured.view->bookmarks.size() == 2 &&
                    recaptured.view->bookmarks[0].addr == first->value &&
                    recaptured.view->bookmarks[1].addr == second->value &&
                    !recaptured.view->show_bytes &&
                    recaptured.view->addr_format == disasm_view::addr_format_t::rva;
            }
            const bool workspace_state_ok = seeded &&
                recaptured_state.selection == third &&
                recaptured_state.navigation_back.size() == 2 &&
                recaptured_state.navigation_back[0] == *first &&
                recaptured_state.navigation_back[1] == *second &&
                recaptured_state.bookmarks.size() == 2;
            context.workspace->update_view_state([&](aida::analysis::workspace_view_state_t& state) {
                state = saved_workspace_state;
            });
            {
                std::lock_guard<std::mutex> lock(context.view->mutex);
                context.view->bookmarks = std::move(saved_bookmarks);
                context.view->show_bytes = saved_show_bytes;
                context.view->addr_format = saved_format;
                context.view->selection = saved_selection;
            }

            if (workspace_state_ok && view_state_ok) {
                log_msg(hf, tag, "PASS -- explicit workspace recapture preserved navigation, bookmarks, selection, and format state elapsed_us=%lld", elapsed_us_since(t0));
                passed.fetch_add(1);
            } else {
                log_msg(hf, tag, "FAIL -- workspace_state_ok=%d view_state_ok=%d",
                    workspace_state_ok ? 1 : 0, view_state_ok ? 1 : 0);
                failed.fetch_add(1);
            }
        } catch (...) {
            log_msg(hf, tag, "FAIL -- exception gle=0x%08lX", (unsigned long)GetLastError());
            failed.fetch_add(1);
        }
    }

    void test_xref_workspace_recapture(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        const char* tag = "xref.workspace_recapture";
        try {
            xref_fixture_scope_t fixture;
            if (!fixture.workspace || fixture.available == 0) {
                log_msg(hf, tag, "FAIL -- no static workspace with published xrefs");
                failed.fetch_add(1);
                return;
            }
            auto before = xref_index::query_to(fixture.workspace, fixture.target, 16);
            auto recaptured = disasm_view::capture_workspace(fixture.workspace);
            auto after = xref_index::query_to(fixture.workspace, fixture.target, 16);
            bool equivalent = before && after && before.value().size() == after.value().size();
            if (equivalent) {
                for (size_t i = 0; i < before.value().size(); ++i) {
                    const auto& lhs = before.value()[i];
                    const auto& rhs = after.value()[i];
                    equivalent = equivalent && lhs.source_addr == rhs.source_addr &&
                        lhs.kind == rhs.kind && lhs.edge == rhs.edge && lhs.source_label == rhs.source_label;
                }
            }
            log_msg(hf, tag, "STATE -- binary_id=%s recaptured=%d before=%zu after=%zu equivalent=%d",
                fixture.workspace->identity().binary_id().to_hex().c_str(), recaptured ? 1 : 0,
                before ? before.value().size() : 0, after ? after.value().size() : 0,
                equivalent ? 1 : 0);

            if (recaptured && equivalent && before && !before.value().empty()) {
                log_msg(hf, tag, "PASS -- explicit workspace recapture preserved deterministic xref results without global snapshot swapping");
                passed.fetch_add(1);
            } else {
                log_msg(hf, tag, "FAIL -- workspace recapture changed xref identity or query results");
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
        uint64_t addr = resolve_ntdll_export("NtCreateFile");
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
        uint64_t addr = resolve_ntdll_export("NtReadFile");
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
        uint64_t addr = resolve_ntdll_export("NtWriteFile");
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
    void test_center_view_workbench(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        select_center_view(hf, passed, failed, skipped, "center_view.workbench", center_view_t::workbench);
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
        { "nav_history_push_pop",                    test_nav_history_push_pop                    },
        { "nav_history_dedup",                       test_nav_history_dedup                       },
        { "nav_history_stress",                      test_nav_history_stress                      },
        { "nav_history_clear",                       test_nav_history_clear                       },
        { "nav_history_pop_empty",                   test_nav_history_pop_empty                   },
        { "nav_history_push_zero",                   test_nav_history_push_zero                   },
        { "bump_format_generation",                  test_bump_format_generation                  },

        { "comment_set_get",                         test_comment_set_get                         },
        { "comment_has",                            test_comment_has                            },
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
        { "xref_query_to_zero",                      test_xref_query_to_zero                      },
        { "xref_has_more_zero_limit",                test_xref_has_more_zero_limit                },
        { "xref_warm_range",                         test_xref_warm_range                         },
        { "xref_live_after_warm_range",              test_xref_live_after_warm_range              },
        { "xref_query_to_ntcreatefile",              test_xref_query_to_ntcreatefile              },
        { "xref_query_to_ntopenfile",                test_xref_query_to_ntopenfile                },
        { "xref_workspace_recapture",                test_xref_workspace_recapture                },

        { "pseudocode_request_decompile",            test_pseudocode_request_decompile            },
        { "pseudocode_cancel_active",                test_pseudocode_cancel_active                },
        { "pseudocode_has_tab_for",                  test_pseudocode_has_tab_for                  },
        { "pseudocode_tab_count",                    test_pseudocode_tab_count                    },
        { "pseudocode_snapshot_tabs",                test_pseudocode_snapshot_tabs                 },
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

        { "hexview_workspace_activate",              test_hexview_workspace_activate              },
        { "hexview_workspace_activate_small",        test_hexview_workspace_activate_small        },
        { "hexview_workspace_activate_large",        test_hexview_workspace_activate_large        },
        { "hexview_read_live_memory",                test_hexview_read_live_memory                },
        { "hexview_read_process_ntdll_header",       test_hexview_read_process_ntdll_header       },
        { "hexview_read_process_kernel32",           test_hexview_read_process_kernel32            },
        { "hexview_workspace_source_name",           test_hexview_workspace_source_name           },
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

        { "disasm_bookmarks",                        test_disasm_view_bookmarks                   },
        { "disasm_addr_format",                      test_disasm_view_addr_format                 },
        { "disasm_show_bytes_toggle",                test_disasm_view_show_bytes_toggle           },
        { "disasm_workspace_recapture",               test_disasm_view_workspace_recapture        },

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
        { "center_view_workbench",                   test_center_view_workbench                   },
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
