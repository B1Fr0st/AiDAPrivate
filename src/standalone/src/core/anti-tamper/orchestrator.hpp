#pragma once

#include "../runtime/standalone_anti_ai.hpp"

#include <windows.h>
#include <psapi.h>
#include <bcrypt.h>
#include <nmmintrin.h>

#include <cstdint>
#include <cstdio>
#include <cstring>
#include <atomic>
#include <mutex>
#include <string>
#include <thread>
#include <chrono>
#include <exception>
#include <functional>
#include <memory>

#include "webhook.hpp"
#include "state.hpp"
#include "enforcement.hpp"
#include "../../helpers/diag_log.hpp"
#include "integrity.hpp"
#include "anti_debug.hpp"
#include "anti_vm.hpp"
#include "anti_hook.hpp"
#include "anti_emulation.hpp"
#include "anti_dump.hpp"
#include "virtualizer.hpp"
#include "code_encrypt.hpp"
#include "metamorphic.hpp"
#include "vm_jit.hpp"
#include "cloakwork.hpp"
#include "ai_deception.hpp"
#include "token_chain.hpp"
#include "syscall.hpp"
#include "packer.hpp"
#include "cff.hpp"
#include "call_obfuscation.hpp"
#include "decoy_call_graph.hpp"
#include "nanomites.hpp"
#include "binary_protocol.hpp"
#include "server_pages.hpp"
#include "vm_compiler.hpp"
#include "stolen_bytes.hpp"
#include "vm_nested.hpp"
#include "standalone_anti_dump.hpp"
#include "re_detection_engine.hpp"
#include "ghost_veh.hpp"
#include "key_pipeline.hpp"

#include "obfuscation.hpp"
#include "standalone_license.hpp"
#include "../infra/work_queue.hpp"
#include "../arc/arc.h"
#include "../runtime/loader_header_invariant.hpp"
#include "../runtime/reason_ids.hpp"
#include "dr_check.hpp"

#pragma comment(lib, "bcrypt.lib")

namespace anti_tamper {

static constexpr uint32_t ATP_VIRTUALIZED    = 1u << 0;
static constexpr uint32_t ATP_STOLEN_BYTES   = 1u << 1;
static constexpr uint32_t ATP_NANOMITE       = 1u << 2;
static constexpr uint32_t ATP_CALL_OBF       = 1u << 3;
static constexpr uint32_t ATP_CODE_ENCRYPT   = 1u << 4;
static constexpr uint32_t ATP_DECOY          = 1u << 5;
static constexpr uint32_t ATP_PACKED         = 1u << 6;
static constexpr uint32_t ATP_JIT            = 1u << 7;
static constexpr uint32_t ATP_VM_NESTED      = 1u << 8;

inline uint32_t resolve_export_rva(const char* name)
{
    if (!name) return 0u;
    HMODULE h = GetModuleHandleW(nullptr);
    if (!h) return 0u;
    FARPROC p = GetProcAddress(h, name);
    if (!p) return 0u;
    uint64_t base = reinterpret_cast<uint64_t>(h);
    uint64_t addr = reinterpret_cast<uint64_t>(p);
    if (addr < base) return 0u;
    uint64_t rva = addr - base;
    if (rva >= 0x80000000ULL) return 0u;
    return static_cast<uint32_t>(rva);
}

inline uint64_t resolve_rolling_key_for(uint32_t rva)
{
    uint64_t k0 = 0, k1 = 0;
    integrity::get_session_keys(k0, k1);
    uint8_t ikm[24];
    memcpy(ikm, &k0, 8);
    memcpy(ikm + 8, &k1, 8);
    uint64_t rva_u64 = static_cast<uint64_t>(rva);
    memcpy(ikm + 16, &rva_u64, 8);
    uint8_t prk[32];
    virtualizer::detail::hmac_sha256(state::g_vm_master_key, 32, ikm, 24, prk);
    static const uint8_t info[16] = {
        'a','i','d','a','_','o','r','c','h',
        '_','i','n','n','e','r','k'
    };
    uint8_t okm[16];
    virtualizer::detail::hkdf_expand_sha256(prk, info, 16, okm, 16);
    uint64_t out_lo = 0, out_hi = 0;
    memcpy(&out_lo, okm, 8);
    memcpy(&out_hi, okm + 8, 8);
    SecureZeroMemory(prk, 32);
    SecureZeroMemory(okm, 16);
    SecureZeroMemory(ikm, 24);
    return out_lo ^ _rotl64(out_hi, 23);
}

inline bool extract_inner_bytecode_by_rva(uint32_t rva, std::vector<uint8_t>& out)
{
    out.clear();
    HMODULE h = GetModuleHandleW(nullptr);
    if (!h) return false;
    uint64_t va = reinterpret_cast<uint64_t>(h) + static_cast<uint64_t>(rva);
    auto& ps = virtualizer::protection::get_state();
    for (uint32_t i = 0; i < ps.count; ++i)
    {
        const auto& e = ps.entries[i];
        if (!e.active) continue;
        if (e.original_addr != va) continue;
        if (e.bytecode.empty()) continue;
        if (e.bytecode.size() > vm_nested::MAX_INNER_BYTECODE_BYTES) return false;
        out = e.bytecode;
        return true;
    }
    return false;
}

inline std::unordered_map<uint32_t, vm_nested::wrap_result_t>& nested_map()
{
    static std::unordered_map<uint32_t, vm_nested::wrap_result_t> m;
    return m;
}

inline uint32_t vm_nested_count()
{
    return static_cast<uint32_t>(nested_map().size());
}

inline uint32_t apply_vm_nested_tags()
{
    auto& rt = state::get();
    uint32_t applied = 0;

    static const char* const kCriticalNames[] = {
        "arc_validate_tool_exec_v2",
        "arc_heartbeat",
        "arc_init",
        "arc_get_comm_bridge",
        "arc_verify_watermark_trailer"
    };

    static const char* const kCriticalNamesOptional[] = {
        "arc_validate_tool_exec_v2",
        "arc_verify_watermark_trailer"
    };

    rt.vm_nested_rvas.clear();
    for (const char* name : kCriticalNames)
    {
        uint32_t rva = resolve_export_rva(name);
        if (rva == 0u)
        {
            bool is_optional = false;
            for (const char* opt : kCriticalNamesOptional)
            {
                if (std::strcmp(name, opt) == 0) { is_optional = true; break; }
            }

            if (!is_optional)
                webhook::write_log("init", (std::string("vm_nested_arc_export_deferred:") + name).c_str());
            continue;
        }
        rt.vm_nested_rvas.push_back(rva);
    }

    for (uint32_t rva : rt.vm_nested_rvas)
    {
        std::vector<uint8_t> inner_bc;
        if (!extract_inner_bytecode_by_rva(rva, inner_bc))
        {
            char dbg[96];
            _snprintf_s(dbg, sizeof(dbg), _TRUNCATE,
                "vm_nested_no_inner_bytecode rva=0x%X", rva);
            webhook::write_log("init", dbg);
            continue;
        }
        if (!vm_nested::is_eligible(inner_bc.size()))
        {
            char dbg[96];
            _snprintf_s(dbg, sizeof(dbg), _TRUNCATE,
                "vm_nested_ineligible rva=0x%X size=%zu", rva, inner_bc.size());
            webhook::write_log("init", dbg);
            continue;
        }

        uint32_t outer_rva = rva | 0x80000000u;
        uint64_t inner_key = resolve_rolling_key_for(rva);

        auto wrapped = vm_nested::wrap_critical(
            inner_bc, state::g_vm_master_key, rva, outer_rva, inner_key);

        if (!wrapped.ok)
        {
            char dbg[128];
            _snprintf_s(dbg, sizeof(dbg), _TRUNCATE,
                "vm_nested_wrap_fail rva=0x%X err=%s", rva, vm_nested::last_error());
            webhook::write_log("init", dbg);
            continue;
        }

        nested_map()[rva] = std::move(wrapped);
        rt.atp_flags[rva] |= ATP_VM_NESTED;
        ++applied;
    }

    char dbg[64];
    _snprintf_s(dbg, sizeof(dbg), _TRUNCATE,
        "vm_nested_applied=%u", applied);
    webhook::write_log("init", dbg);
    return applied;
}

inline uint64_t guard_now_ms()
{
    return static_cast<uint64_t>(GetTickCount64());
}

inline uint64_t driver_crc_text_hash_seh(const void* data, size_t len, bool& ok)
{
    ok = false;
    uint64_t h1 = 0xFFFFFFFFULL;
    uint64_t h2 = 0x85EBCA6BULL;
    const auto* p = static_cast<const uint8_t*>(data);
    __try
    {
        size_t aligned_end = len & ~7ULL;
        for (size_t i = 0; i < aligned_end; i += 8)
        {
            uint64_t block = 0;
            memcpy(&block, p + i, sizeof(block));
            h1 = _mm_crc32_u64(h1, block);
            h2 = _mm_crc32_u64(h2, block ^ 0xA5A5A5A5A5A5A5A5ULL);
        }
        for (size_t i = aligned_end; i < len; ++i)
        {
            h1 = _mm_crc32_u8(static_cast<uint32_t>(h1), p[i]);
            h2 = _mm_crc32_u8(static_cast<uint32_t>(h2), p[i] ^ 0xA5u);
        }
        ok = true;
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        ok = false;
        h1 = 0;
        h2 = 0;
    }
    return (h1 & 0xFFFFFFFFULL) | ((h2 & 0xFFFFFFFFULL) << 32);
}

inline bool kernel_adbg_thread_walk_optional_error(DWORD err)
{
    return err == ERROR_NOT_SUPPORTED || err == ERROR_INVALID_FUNCTION;
}

inline std::atomic<bool> g_kernel_clear_process_dr_unsupported{false};
inline std::atomic<bool> g_kernel_hide_all_threads_unsupported{false};

struct seh_capture_t
{
    DWORD code = 0;
    void* address = nullptr;
    DWORD flags = 0;
    DWORD parameters = 0;
    ULONG_PTR info[EXCEPTION_MAXIMUM_PARAMETERS] = {};
};

static int capture_seh_exception(EXCEPTION_POINTERS* ep, seh_capture_t* out)
{
    if (out && ep && ep->ExceptionRecord)
    {
        out->code = ep->ExceptionRecord->ExceptionCode;
        out->address = ep->ExceptionRecord->ExceptionAddress;
        out->flags = ep->ExceptionRecord->ExceptionFlags;
        out->parameters = ep->ExceptionRecord->NumberParameters;
        const DWORD count = out->parameters < EXCEPTION_MAXIMUM_PARAMETERS ? out->parameters : EXCEPTION_MAXIMUM_PARAMETERS;
        for (DWORD i = 0; i < count; ++i)
            out->info[i] = ep->ExceptionRecord->ExceptionInformation[i];
    }
    return EXCEPTION_EXECUTE_HANDLER;
}

__declspec(noinline) static DWORD seh_canary_register(void* canary,
                                                      SIZE_T size,
                                                      BOOL* out_registered,
                                                      DWORD* out_error,
                                                      seh_capture_t* out_exception)
{
    if (out_registered)
        *out_registered = FALSE;
    if (out_error)
        *out_error = ERROR_SUCCESS;
    if (out_exception)
        *out_exception = {};
    __try
    {
        SetLastError(ERROR_SUCCESS);
        const bool registered = driver_bridge::canary_register(canary, size);
        const DWORD err = registered ? ERROR_SUCCESS : GetLastError();
        if (out_registered)
            *out_registered = registered ? TRUE : FALSE;
        if (out_error)
            *out_error = err;
    }
    __except (capture_seh_exception(GetExceptionInformation(), out_exception))
    {
        const DWORD code = out_exception ? out_exception->code : GetExceptionCode();
        if (out_error)
            *out_error = GetLastError() != ERROR_SUCCESS ? GetLastError() : ERROR_UNHANDLED_EXCEPTION;
        return code;
    }
    return 0;
}

inline bool kernel_adbg_hard_flags_present(uint32_t flags)
{
    constexpr uint32_t kHardFlags = 0x00000001u | 0x00000008u;
    return (flags & kHardFlags) != 0;
}

inline void kernel_debugger_scan_process_names_for_log(DWORD pid, std::string& image, std::string& path)
{
    image = "?";
    path = "?";
    if (pid == 0)
        return;
    HANDLE process = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    if (!process)
        return;
    std::vector<wchar_t> buffer(32768);
    DWORD size = static_cast<DWORD>(buffer.size());
    if (QueryFullProcessImageNameW(process, 0, buffer.data(), &size) && size > 0 && size < buffer.size())
    {
        std::wstring lower = standalone_anti_ai::detail::lower_copy(std::wstring(buffer.data(), size));
        path = standalone_anti_ai::detail::wide_to_utf8_lossy(lower);
        image = standalone_anti_ai::detail::wide_to_utf8_lossy(std::wstring(standalone_anti_ai::detail::basename_ptr(lower.c_str())));
    }
    CloseHandle(process);
}

inline bool kernel_debugger_scan_confirmed_for_enforcement(const char* phase,
                                                           const char* source,
                                                           uint64_t scan_pid)
{
    const DWORD pid32 = scan_pid <= 0xFFFFFFFFULL ? static_cast<DWORD>(scan_pid) : 0;
    std::string image;
    std::string path;
    kernel_debugger_scan_process_names_for_log(pid32, image, path);
    driver_bridge::anti_debug_result_t query{};
    SetLastError(ERROR_SUCCESS);
    const uint64_t started = GetTickCount64();
    const bool query_ok = driver_bridge::kernel_anti_debug_query(query);
    const DWORD query_err = query_ok ? ERROR_SUCCESS : GetLastError();
    const bool confirmed = query_ok &&
        (kernel_adbg_hard_flags_present(query.result_flags) || query.detected_debugger_pid != 0);
    webhook::write_log_critical_fmt(
        phase ? phase : "guard",
        "kernel_debugger_scan_evaluation source=%s scan_pid=%llu scan_image=%s scan_path='%s' query_ok=%d query_err=%lu query_flags=0x%08X query_pid=%llu confirmed=%d elapsed_ms=%llu",
        source ? source : "unknown",
        static_cast<unsigned long long>(scan_pid),
        image.c_str(),
        path.c_str(),
        query_ok ? 1 : 0,
        static_cast<unsigned long>(query_err),
        query.result_flags,
        static_cast<unsigned long long>(query.detected_debugger_pid),
        confirmed ? 1 : 0,
        static_cast<unsigned long long>(GetTickCount64() - started));
    return confirmed;
}

inline uint64_t run_inline_check(check_class_t which, uint64_t proof_hash = 0)
{
    return token_chain::run_inline_check(which, proof_hash);
}

#ifdef AIDA_STANDALONE
inline bool vm_protect_function(void* func, size_t func_len)
{
    uint64_t base_addr = reinterpret_cast<uint64_t>(func);
    uint64_t seed = __rdtsc() ^ base_addr ^ GetCurrentProcessId();

    uint64_t k0 = 0, k1 = 0;
    integrity::get_session_keys(k0, k1);
    uint64_t master_key = k0 ^ k1 ^ 0x9E3779B97F4A7C15ULL;
    auto* pool = virtualizer::pool_manager::get_or_create(base_addr, master_key);
    if (!pool) return false;

    virtualizer::detail::vm_state_t tmp_vm;
    virtualizer::detail::init_vm(tmp_vm, seed, pool);

    auto lifted = vm_compiler::x86_lifter::compile_function(
        static_cast<const uint8_t*>(func), func_len,
        base_addr, seed ^ 0x6A09E667F3BCC908ULL, tmp_vm.opcode_map, pool);

    virtualizer::detail::destroy_vm(tmp_vm);

    if (lifted.bytecode.empty()) return false;

    return virtualizer::protection::protect_function(
        func, func_len, lifted.bytecode, seed);
}
#endif

inline bool start_monitors();
inline bool verify_integrity_clean_after_worker_degrade(const char* phase);

inline const char* ai_tool_posture_reason(const standalone_anti_ai::combined::threat_report_t& report)
{
    using namespace standalone_anti_ai;
    if ((report.high_risk_mask & (category_foreign_write_handle | category_foreign_vm_operation | category_foreign_create_thread)) != 0)
        return "ai_tool_posture_foreign_handle";
    if ((report.high_risk_mask & category_targets_aida) != 0)
        return "ai_tool_posture_targeting_aida";
    if ((report.high_risk_mask & (category_re_tool | category_debugger_tool | category_dump_tool)) != 0)
        return "ai_tool_posture_re_tool";
    if ((report.high_risk_mask & category_memory_scanner) != 0)
        return "ai_tool_posture_memory_scanner";
    if ((report.high_risk_mask & category_offensive_mcp_tool) != 0)
        return "ai_tool_posture_mcp_offensive_tools";
    if ((report.high_risk_mask & (category_mcp_pipe | category_mcp_process | category_mcp_port | category_mcp_command_server)) != 0)
        return "ai_tool_posture_mcp_bridge";
    return "ai_tool_posture_untrusted";
}

inline bool ai_tool_posture_full_test_observed_only(uint32_t high_risk_mask)
{
    using namespace standalone_anti_ai;
    constexpr uint32_t observed_mask =
        category_mcp_pipe |
        category_mcp_process |
        category_mcp_port |
        category_mcp_command_server |
        category_local_llm |
        category_ai_coding_tool |
        category_clipboard_monitor |
        category_foreign_write_handle |
        category_foreign_vm_operation |
        category_foreign_create_thread |
        category_targets_aida;
    return high_risk_mask != 0 && (high_risk_mask & ~observed_mask) == 0;
}

inline bool ai_tool_posture_post_full_test_tail_observed_only(uint32_t high_risk_mask)
{
    using namespace standalone_anti_ai;
    constexpr uint32_t observed_mask =
        category_mcp_pipe |
        category_mcp_process |
        category_mcp_port |
        category_mcp_command_server |
        category_local_llm |
        category_ai_coding_tool |
        category_clipboard_monitor |
        category_foreign_write_handle |
        category_foreign_vm_operation;
    return high_risk_mask != 0 && (high_risk_mask & ~observed_mask) == 0;
}

inline bool ai_tool_posture_unconfirmed_core_system_foreign_handle(const standalone_anti_ai::combined::threat_report_t& report)
{
    using namespace standalone_anti_ai;
    constexpr uint32_t foreign_mutating_mask =
        category_foreign_write_handle |
        category_foreign_vm_operation |
        category_foreign_create_thread;
    constexpr uint32_t correlated_mask =
        category_mcp_pipe |
        category_mcp_process |
        category_mcp_port |
        category_mcp_command_server |
        category_local_llm |
        category_ai_coding_tool |
        category_clipboard_monitor |
        foreign_mutating_mask;
    if ((report.high_risk_mask & foreign_mutating_mask) == 0)
        return false;
    if ((report.high_risk_mask & ~correlated_mask) != 0)
        return false;
    if (!report.first_handle_owner_core_system || report.first_handle_owner_query_ok)
        return false;
    if (report.first_handle_owner_tool || report.first_handle_owner_targets_aida ||
        report.handle_owner_tool || report.tool_targets_aida)
        return false;
    return true;
}

inline bool ai_tool_posture_full_test_tail_active(uint64_t* expired_ms = nullptr, uint64_t* tail_remaining_ms = nullptr)
{
    constexpr uint64_t kTailMs = 30ULL * 60ULL * 1000ULL;
    const uint64_t until = state::get().full_test_suppression_until_ms.load(std::memory_order_acquire);
    const uint64_t now = state::monotonic_ms();
    if (expired_ms)
        *expired_ms = 0;
    if (tail_remaining_ms)
        *tail_remaining_ms = 0;
    if (until == 0 || now < until)
        return false;
    const uint64_t expired = now - until;
    if (expired > kTailMs)
        return false;
    if (expired_ms)
        *expired_ms = expired;
    if (tail_remaining_ms)
        *tail_remaining_ms = kTailMs - expired;
    return true;
}

inline void log_ai_tool_posture_handle_detail(
    const char* log_tag,
    const char* phase_name,
    const standalone_anti_ai::combined::threat_report_t& report,
    bool full_test_active,
    bool post_full_test_suppressed,
    uint64_t post_full_test_ms,
    bool post_full_test_tail,
    uint64_t post_full_test_expired_ms,
    uint64_t post_full_test_tail_ms)
{
    if (!report.handle_to_us_detected && !report.trusted_system_handle_ignored &&
        !report.fileless_bootstrap_parent_handle_ignored)
        return;
    if (report.fileless_bootstrap_parent_handle_ignored)
    {
        webhook::write_log_critical_fmt(log_tag,
            "ai_tool_posture_fileless_parent_handle_ignored_detail phase=%s ignored=%u access=0x%08lX owner_pid=%lu owner_hash=0x%016llX owner_image=%s owner_path=%s full_test_active=%d post_full_test_active=%d post_full_test_ms=%llu post_full_test_tail=%d post_full_test_expired_ms=%llu post_full_test_tail_ms=%llu",
            phase_name,
            report.fileless_bootstrap_parent_handle_ignored_count,
            static_cast<unsigned long>(report.fileless_bootstrap_parent_handle_access_mask),
            static_cast<unsigned long>(report.fileless_bootstrap_parent_handle_owner_pid),
            static_cast<unsigned long long>(report.fileless_bootstrap_parent_handle_owner_hash),
            report.fileless_bootstrap_parent_handle_owner_image.empty() ? "<empty>" : report.fileless_bootstrap_parent_handle_owner_image.c_str(),
            report.fileless_bootstrap_parent_handle_owner_path.empty() ? "<empty>" : report.fileless_bootstrap_parent_handle_owner_path.c_str(),
            full_test_active ? 1 : 0,
            post_full_test_suppressed ? 1 : 0,
            static_cast<unsigned long long>(post_full_test_ms),
            post_full_test_tail ? 1 : 0,
            static_cast<unsigned long long>(post_full_test_expired_ms),
            static_cast<unsigned long long>(post_full_test_tail_ms));
    }
    if (!report.handle_to_us_detected && !report.trusted_system_handle_ignored)
        return;
    webhook::write_log_critical_fmt(log_tag,
        "ai_tool_posture_handle_detail phase=%s handle_any=%d observed_handles=%u access=0x%08lX first_owner_pid=%lu first_handle=0x%016llX first_access=0x%08lX first_owner_hash=0x%016llX first_owner_image=%s first_owner_path=%s first_query_ok=%d first_core_system=%d first_owner_tool=%d first_owner_mcp=%d first_owner_ai=%d first_owner_memory=%d first_owner_re=%d first_owner_debugger=%d first_owner_dump=%d first_owner_targets_aida=%d trusted_system_ignored=%u trusted_system_access=0x%08lX trusted_system_hash=0x%016llX full_test_active=%d post_full_test_active=%d post_full_test_ms=%llu post_full_test_tail=%d post_full_test_expired_ms=%llu post_full_test_tail_ms=%llu",
        phase_name,
        report.handle_to_us_detected ? 1 : 0,
        report.observed_handle_count,
        static_cast<unsigned long>(report.handle_access_mask),
        static_cast<unsigned long>(report.first_handle_owner_pid),
        static_cast<unsigned long long>(report.first_handle_value),
        static_cast<unsigned long>(report.first_handle_access_mask),
        static_cast<unsigned long long>(report.first_handle_owner_hash),
        report.first_handle_owner_image.empty() ? "<empty>" : report.first_handle_owner_image.c_str(),
        report.first_handle_owner_path.empty() ? "<empty>" : report.first_handle_owner_path.c_str(),
        report.first_handle_owner_query_ok ? 1 : 0,
        report.first_handle_owner_core_system ? 1 : 0,
        report.first_handle_owner_tool ? 1 : 0,
        report.first_handle_owner_mcp ? 1 : 0,
        report.first_handle_owner_ai ? 1 : 0,
        report.first_handle_owner_memory ? 1 : 0,
        report.first_handle_owner_re ? 1 : 0,
        report.first_handle_owner_debugger ? 1 : 0,
        report.first_handle_owner_dump ? 1 : 0,
        report.first_handle_owner_targets_aida ? 1 : 0,
        report.trusted_system_handle_ignored_count,
        static_cast<unsigned long>(report.trusted_system_handle_access_mask),
        static_cast<unsigned long long>(report.trusted_system_handle_owner_hash),
        full_test_active ? 1 : 0,
        post_full_test_suppressed ? 1 : 0,
        static_cast<unsigned long long>(post_full_test_ms),
        post_full_test_tail ? 1 : 0,
        static_cast<unsigned long long>(post_full_test_expired_ms),
        static_cast<unsigned long long>(post_full_test_tail_ms));
}

inline bool enforce_ai_tool_posture(const char* phase, bool runtime)
{
    auto& rt = state::get();
    const char* phase_name = phase ? phase : "unknown";
    const char* log_tag = runtime ? "guard" : "init";
    static std::atomic<uint64_t> s_last_runtime_scan_ms{0};
    if (runtime)
    {
        uint64_t now_ms = static_cast<uint64_t>(GetTickCount64());
        uint64_t last_ms = s_last_runtime_scan_ms.load(std::memory_order_relaxed);
        if (last_ms != 0 && now_ms - last_ms < 5000ULL)
            return true;
        s_last_runtime_scan_ms.store(now_ms, std::memory_order_relaxed);
    }
    uint64_t pre_post_full_test_ms = 0;
    uint64_t pre_post_full_test_expired_ms = 0;
    uint64_t pre_post_full_test_tail_ms = 0;
    const bool pre_full_test_active = rt.full_test_running.load(std::memory_order_acquire);
    const bool pre_post_full_test_suppressed =
        anti_tamper::state::full_test_suppression_active(&pre_post_full_test_ms);
    const bool pre_post_full_test_tail =
        ai_tool_posture_full_test_tail_active(&pre_post_full_test_expired_ms, &pre_post_full_test_tail_ms);
    uint64_t scan_tick = GetTickCount64();
    webhook::write_log_critical_fmt(log_tag,
        "ai_tool_posture_scan_pre phase=%s pid=%lu tid=%lu tick=%llu runtime=%d full_test=%u post_full_test_active=%d post_full_test_ms=%llu post_full_test_tail=%d post_full_test_expired_ms=%llu post_full_test_tail_ms=%llu",
        phase_name,
        GetCurrentProcessId(),
        GetCurrentThreadId(),
        static_cast<unsigned long long>(scan_tick),
        runtime ? 1 : 0,
        pre_full_test_active ? 1u : 0u,
        pre_post_full_test_suppressed ? 1 : 0,
        static_cast<unsigned long long>(pre_post_full_test_ms),
        pre_post_full_test_tail ? 1 : 0,
        static_cast<unsigned long long>(pre_post_full_test_expired_ms),
        static_cast<unsigned long long>(pre_post_full_test_tail_ms));
    auto report = standalone_anti_ai::full_scan();
    webhook::write_log_critical_fmt(log_tag,
        "ai_tool_posture_scan_post phase=%s category_mask=0x%08X high_risk_mask=0x%08X high_risk_count=%u evidence_count=%u evidence_hash=0x%016llX summary_hash=0x%016llX elapsed_ms=%llu summary=%s",
        phase_name,
        report.category_mask,
        report.high_risk_mask,
        report.high_risk_count,
        report.evidence_count,
        static_cast<unsigned long long>(report.evidence_hash),
        static_cast<unsigned long long>(report.summary_hash),
        static_cast<unsigned long long>(GetTickCount64() - scan_tick),
        report.summary.c_str());
    uint64_t full_test_suppression_remaining = 0;
    uint64_t full_test_suppression_expired_ms = 0;
    uint64_t full_test_tail_remaining_ms = 0;
    const bool full_test_active = rt.full_test_running.load(std::memory_order_acquire);
    const bool post_full_test_suppressed =
        anti_tamper::state::full_test_suppression_active(&full_test_suppression_remaining);
    const bool post_full_test_tail =
        ai_tool_posture_full_test_tail_active(&full_test_suppression_expired_ms, &full_test_tail_remaining_ms);
    log_ai_tool_posture_handle_detail(
        log_tag,
        phase_name,
        report,
        full_test_active,
        post_full_test_suppressed,
        full_test_suppression_remaining,
        post_full_test_tail,
        full_test_suppression_expired_ms,
        full_test_tail_remaining_ms);
    if (!report.confirmed_high_risk())
        return true;
    if (ai_tool_posture_unconfirmed_core_system_foreign_handle(report))
    {
        webhook::write_log_critical_fmt(log_tag,
            "ai_tool_posture_unconfirmed_core_system_foreign_handle phase=%s category_mask=0x%08X high_risk_mask=0x%08X high_risk_count=%u summary_hash=0x%016llX handle_any=%d observed_handles=%u first_owner_pid=%lu first_owner_image=%s first_owner_path=%s first_access=0x%08lX first_owner_hash=0x%016llX first_query_ok=%d first_core_system=%d first_owner_tool=%d first_owner_targets_aida=%d summary=%s",
            phase_name,
            report.category_mask,
            report.high_risk_mask,
            report.high_risk_count,
            static_cast<unsigned long long>(report.summary_hash),
            report.handle_to_us_detected ? 1 : 0,
            report.observed_handle_count,
            static_cast<unsigned long>(report.first_handle_owner_pid),
            report.first_handle_owner_image.empty() ? "<empty>" : report.first_handle_owner_image.c_str(),
            report.first_handle_owner_path.empty() ? "<empty>" : report.first_handle_owner_path.c_str(),
            static_cast<unsigned long>(report.first_handle_access_mask),
            static_cast<unsigned long long>(report.first_handle_owner_hash),
            report.first_handle_owner_query_ok ? 1 : 0,
            report.first_handle_owner_core_system ? 1 : 0,
            report.first_handle_owner_tool ? 1 : 0,
            report.first_handle_owner_targets_aida ? 1 : 0,
            report.summary.c_str());
        return true;
    }
    if ((full_test_active || post_full_test_suppressed) &&
        ai_tool_posture_full_test_observed_only(report.high_risk_mask))
    {
        webhook::write_log_critical_fmt(log_tag,
            "ai_tool_posture_full_test_observed phase=%s category_mask=0x%08X high_risk_mask=0x%08X high_risk_count=%u summary_hash=0x%016llX full_test_active=%d post_full_test_ms=%llu handle_any=%d observed_handles=%u first_owner_pid=%lu first_access=0x%08lX first_owner_hash=0x%016llX first_owner_tool=%d first_owner_targets_aida=%d",
            phase_name,
            report.category_mask,
            report.high_risk_mask,
            report.high_risk_count,
            static_cast<unsigned long long>(report.summary_hash),
            full_test_active ? 1 : 0,
            static_cast<unsigned long long>(full_test_suppression_remaining),
            report.handle_to_us_detected ? 1 : 0,
            report.observed_handle_count,
            static_cast<unsigned long>(report.first_handle_owner_pid),
            static_cast<unsigned long>(report.first_handle_access_mask),
            static_cast<unsigned long long>(report.first_handle_owner_hash),
            report.first_handle_owner_tool ? 1 : 0,
            report.first_handle_owner_targets_aida ? 1 : 0);
        return true;
    }
    if (post_full_test_tail &&
        ai_tool_posture_post_full_test_tail_observed_only(report.high_risk_mask))
    {
        webhook::write_log_critical_fmt(log_tag,
            "ai_tool_posture_post_full_test_tail_observed phase=%s category_mask=0x%08X high_risk_mask=0x%08X high_risk_count=%u summary_hash=0x%016llX post_full_test_expired_ms=%llu post_full_test_tail_ms=%llu handle_any=%d observed_handles=%u first_owner_pid=%lu first_access=0x%08lX first_owner_hash=0x%016llX first_owner_tool=%d first_owner_targets_aida=%d trusted_system_ignored=%u",
            phase_name,
            report.category_mask,
            report.high_risk_mask,
            report.high_risk_count,
            static_cast<unsigned long long>(report.summary_hash),
            static_cast<unsigned long long>(full_test_suppression_expired_ms),
            static_cast<unsigned long long>(full_test_tail_remaining_ms),
            report.handle_to_us_detected ? 1 : 0,
            report.observed_handle_count,
            static_cast<unsigned long>(report.first_handle_owner_pid),
            static_cast<unsigned long>(report.first_handle_access_mask),
            static_cast<unsigned long long>(report.first_handle_owner_hash),
            report.first_handle_owner_tool ? 1 : 0,
            report.first_handle_owner_targets_aida ? 1 : 0,
            report.trusted_system_handle_ignored_count);
        return true;
    }
    char detail[1024];
    _snprintf_s(detail, sizeof(detail), _TRUNCATE,
        "phase=%s category_mask=0x%08X high_risk_mask=0x%08X high_risk_count=%u evidence_count=%u evidence_hash=0x%016llX summary_hash=0x%016llX full_test_active=%d post_full_test_active=%d post_full_test_ms=%llu post_full_test_tail=%d post_full_test_expired_ms=%llu handle_any=%d observed_handles=%u first_owner_pid=%lu first_owner_image=%s first_owner_path=%s first_access=0x%08lX first_owner_hash=0x%016llX first_query_ok=%d first_core_system=%d first_owner_tool=%d first_owner_targets_aida=%d summary=%s",
        phase_name,
        report.category_mask,
        report.high_risk_mask,
        report.high_risk_count,
        report.evidence_count,
        static_cast<unsigned long long>(report.evidence_hash),
        static_cast<unsigned long long>(report.summary_hash),
        full_test_active ? 1 : 0,
        post_full_test_suppressed ? 1 : 0,
        static_cast<unsigned long long>(full_test_suppression_remaining),
        post_full_test_tail ? 1 : 0,
        static_cast<unsigned long long>(full_test_suppression_expired_ms),
        report.handle_to_us_detected ? 1 : 0,
        report.observed_handle_count,
        static_cast<unsigned long>(report.first_handle_owner_pid),
        report.first_handle_owner_image.empty() ? "<empty>" : report.first_handle_owner_image.c_str(),
        report.first_handle_owner_path.empty() ? "<empty>" : report.first_handle_owner_path.c_str(),
        static_cast<unsigned long>(report.first_handle_access_mask),
        static_cast<unsigned long long>(report.first_handle_owner_hash),
        report.first_handle_owner_query_ok ? 1 : 0,
        report.first_handle_owner_core_system ? 1 : 0,
        report.first_handle_owner_tool ? 1 : 0,
        report.first_handle_owner_targets_aida ? 1 : 0,
        report.summary.c_str());
    const char* reason = ai_tool_posture_reason(report);
    webhook::write_log_critical_fmt(log_tag,
        "ai_tool_posture_enforcing reason=%s %s",
        reason,
        detail);
    webhook::send_debug_log(log_tag, detail, true);
    enforce_violation_id(aida::reason_ids::reason_id_from_string(reason), detail);
    return false;
}

inline bool ensure_driver_hardening(const char* phase)
{
    auto& rt = state::get();
    const char* phase_name = phase ? phase : "unknown";
    if (rt.driver_hardening_done.load(std::memory_order_acquire))
    {
        webhook::write_log_critical_fmt("init",
            "driver_hardening_already_done phase=%s",
            phase_name);
        return true;
    }
    if (rt.violation_latched.load(std::memory_order_acquire))
    {
        std::string reason;
        {
            std::lock_guard<std::mutex> lk(rt.mtx);
            reason = rt.violation_reason;
        }
        webhook::write_log_critical_fmt("init",
            "driver_hardening_blocked_violation_latched phase=%s reason=%.96s pid=%lu tid=%lu initialized=%d driver_hardening=%d",
            phase_name,
            reason.empty() ? "unknown" : reason.c_str(),
            GetCurrentProcessId(),
            GetCurrentThreadId(),
            rt.initialized.load(std::memory_order_acquire) ? 1 : 0,
            rt.driver_hardening_done.load(std::memory_order_acquire) ? 1 : 0);
        return false;
    }
    if (!driver_bridge::is_loaded() || !driver_bridge::using_kernel_driver())
    {
        webhook::write_log_critical_fmt("init",
            "driver_hardening_driver_unavailable phase=%s loaded=%d kernel=%d",
            phase_name,
            driver_bridge::is_loaded() ? 1 : 0,
            driver_bridge::using_kernel_driver() ? 1 : 0);
        return false;
    }
    driver_bridge::dynamic_ioctl_state_t dyn = driver_bridge::dynamic_ioctl_state();
    if (!dyn.ready)
    {
        const bool runtime_authorized = standalone_license::is_valid() || standalone_license::is_arc_loaded();
        webhook::write_log_critical_fmt("init",
            "driver_hardening_deferred_dynamic_ioctl_not_ready phase=%s runtime_authorized=%d loaded=%d kernel=%d connected=%d inst_seed=%u/%u global_seed=%u/%u ioctl_seed_hash=0x%08X hb_ioctl_seed_hash=0x%08X",
            phase_name,
            runtime_authorized ? 1 : 0,
            dyn.loaded ? 1 : 0,
            dyn.kernel ? 1 : 0,
            dyn.connected ? 1 : 0,
            dyn.instance_server_seed,
            dyn.instance_ioctl_seed,
            dyn.global_server_seed,
            dyn.global_ioctl_seed,
            dyn.ioctl_seed_hash,
            dyn.heartbeat_ioctl_seed_hash);
        if (!runtime_authorized)
            return true;
        webhook::send_debug_log("init", "driver_hardening_dynamic_ioctl_not_ready_after_auth", true);
        enforce_violation_id(aida::reason_ids::reason_id_from_string("driver_hardening_dynamic_ioctl_not_ready_after_auth"), "driver_hardening_dynamic_ioctl_not_ready_after_auth");
        return false;
    }

    struct driver_hardening_scope_t
    {
        state::runtime_t& rt;
        const char* phase;
        uint64_t started;

        ~driver_hardening_scope_t()
        {
            const uint64_t elapsed = state::monotonic_ms() >= started ? state::monotonic_ms() - started : 0;
            rt.driver_hardening_active.store(false, std::memory_order_release);
            webhook::write_log_critical_fmt("init",
                "driver_hardening_active_end phase=%s elapsed_ms=%llu violation_latched=%d",
                phase ? phase : "unknown",
                static_cast<unsigned long long>(elapsed),
                rt.violation_latched.load(std::memory_order_acquire) ? 1 : 0);
        }
    };
    const uint64_t hardening_started = state::monotonic_ms();
    rt.driver_hardening_started_ms.store(hardening_started, std::memory_order_release);
    rt.driver_hardening_active.store(true, std::memory_order_release);
    webhook::write_log_critical_fmt("init",
        "driver_hardening_active_begin phase=%s pid=%lu tid=%lu tick=%llu",
        phase_name,
        GetCurrentProcessId(),
        GetCurrentThreadId(),
        static_cast<unsigned long long>(hardening_started));
    driver_hardening_scope_t hardening_scope{rt, phase_name, hardening_started};

    if (rt.code_snap.module_base == 0 || rt.code_snap.text_base == 0 ||
        rt.code_snap.text_size == 0 || rt.code_snap.text_hash == 0)
    {
        uint64_t snap_tick = GetTickCount64();
        webhook::write_log_critical_fmt("init",
            "driver_hardening_snapshot_pre phase=%s pid=%lu tid=%lu tick=%llu",
            phase_name,
            GetCurrentProcessId(),
            GetCurrentThreadId(),
            static_cast<unsigned long long>(snap_tick));
        bool snap_ok = integrity::snapshot_code(rt.code_snap);
        webhook::write_log_critical_fmt("init",
            "driver_hardening_snapshot_post phase=%s ok=%d elapsed_ms=%llu base=0x%llX text=0x%llX size=0x%X hash=0x%016llX",
            phase_name,
            snap_ok ? 1 : 0,
            static_cast<unsigned long long>(GetTickCount64() - snap_tick),
            static_cast<unsigned long long>(rt.code_snap.module_base),
            static_cast<unsigned long long>(rt.code_snap.text_base),
            rt.code_snap.text_size,
            static_cast<unsigned long long>(rt.code_snap.text_hash));
        if (!snap_ok || rt.code_snap.module_base == 0 || rt.code_snap.text_base == 0 ||
            rt.code_snap.text_size == 0 || rt.code_snap.text_hash == 0)
        {
            webhook::send_debug_log("init", "driver_hardening_snapshot_failed", true);
            enforce_violation_id(aida::reason_ids::reason_id_from_string("driver_hardening_snapshot_failed"), "driver_hardening_snapshot_failed");
            return false;
        }
    }

    {
        uint64_t snap_tick = GetTickCount64();
        uint64_t prior_base = rt.code_snap.text_base;
        uint32_t prior_size = rt.code_snap.text_size;
        uint64_t prior_hash = rt.code_snap.text_hash;
        webhook::write_log_critical_fmt("init",
            "driver_hardening_preregister_snapshot_pre phase=%s pid=%lu tid=%lu tick=%llu prior_hash=0x%016llX",
            phase_name,
            GetCurrentProcessId(),
            GetCurrentThreadId(),
            static_cast<unsigned long long>(snap_tick),
            static_cast<unsigned long long>(prior_hash));
        state::code_snapshot_t refreshed_snap = rt.code_snap;
        bool snap_ok = integrity::snapshot_code(refreshed_snap);
        const bool snap_changed =
            refreshed_snap.text_base != prior_base ||
            refreshed_snap.text_size != prior_size ||
            refreshed_snap.text_hash != prior_hash;
        webhook::write_log_critical_fmt("init",
            "driver_hardening_preregister_snapshot_post phase=%s ok=%d elapsed_ms=%llu base=0x%llX text=0x%llX size=0x%X app_hash=0x%016llX prior_hash=0x%016llX changed=%d",
            phase_name,
            snap_ok ? 1 : 0,
            static_cast<unsigned long long>(GetTickCount64() - snap_tick),
            static_cast<unsigned long long>(refreshed_snap.module_base),
            static_cast<unsigned long long>(refreshed_snap.text_base),
            refreshed_snap.text_size,
            static_cast<unsigned long long>(refreshed_snap.text_hash),
            static_cast<unsigned long long>(prior_hash),
            snap_changed ? 1 : 0);
        if (!snap_ok || refreshed_snap.module_base == 0 || refreshed_snap.text_base == 0 ||
            refreshed_snap.text_size == 0 || refreshed_snap.text_hash == 0)
        {
            webhook::send_debug_log("init", "driver_hardening_preregister_snapshot_failed", true);
            enforce_violation_id(aida::reason_ids::reason_id_from_string("driver_hardening_preregister_snapshot_failed"), "driver_hardening_preregister_snapshot_failed");
            return false;
        }
        if (snap_changed || rt.block_chain.empty())
        {
            uint64_t chain_tick = GetTickCount64();
            std::vector<state::block_hash_t> refreshed_chain;
            bool chain_ok = integrity::build_block_chain(refreshed_snap, refreshed_chain);
            webhook::write_log_critical_fmt("init",
                "driver_hardening_preregister_block_chain_refresh_post phase=%s ok=%d changed=%d blocks=%zu elapsed_ms=%llu",
                phase_name,
                chain_ok ? 1 : 0,
                snap_changed ? 1 : 0,
                refreshed_chain.size(),
                static_cast<unsigned long long>(GetTickCount64() - chain_tick));
            if (!chain_ok)
            {
                webhook::send_debug_log("init", "driver_hardening_preregister_block_chain_refresh_failed", true);
                enforce_violation_id(aida::reason_ids::reason_id_from_string("driver_hardening_preregister_block_chain_refresh_failed"), "driver_hardening_preregister_block_chain_refresh_failed");
                return false;
            }
            std::lock_guard<std::mutex> lk(rt.mtx);
            rt.code_snap = refreshed_snap;
            rt.block_chain.swap(refreshed_chain);
        }
        else
        {
            std::lock_guard<std::mutex> lk(rt.mtx);
            rt.code_snap = refreshed_snap;
        }
    }

    if (rt.violation_latched.load(std::memory_order_acquire))
    {
        webhook::write_log_critical_fmt("init",
            "driver_hardening_skip_dprt_register_violation_latched phase=%s stage=pre_hash pid=%lu tid=%lu",
            phase_name,
            GetCurrentProcessId(),
            GetCurrentThreadId());
        return false;
    }

    bool driver_hash_ok = false;
    uint64_t driver_expected_hash = driver_crc_text_hash_seh(
        reinterpret_cast<const void*>(rt.code_snap.text_base),
        rt.code_snap.text_size,
        driver_hash_ok);
    webhook::write_log_critical_fmt("init",
        "driver_hardening_driver_hash phase=%s ok=%d app_hash=0x%016llX driver_hash=0x%016llX text=0x%llX size=0x%X",
        phase_name,
        driver_hash_ok ? 1 : 0,
        static_cast<unsigned long long>(rt.code_snap.text_hash),
        static_cast<unsigned long long>(driver_expected_hash),
        static_cast<unsigned long long>(rt.code_snap.text_base),
        rt.code_snap.text_size);
    if (!driver_hash_ok || driver_expected_hash == 0)
    {
        webhook::send_debug_log("init", "driver_hardening_driver_hash_failed", true);
        enforce_violation_id(aida::reason_ids::reason_id_from_string("driver_hardening_driver_hash_failed"), "driver_hardening_driver_hash_failed");
        return false;
    }

    if (rt.violation_latched.load(std::memory_order_acquire))
    {
        webhook::write_log_critical_fmt("init",
            "driver_hardening_skip_dprt_register_violation_latched phase=%s stage=pre_register pid=%lu tid=%lu hash=0x%016llX app_hash=0x%016llX",
            phase_name,
            GetCurrentProcessId(),
            GetCurrentThreadId(),
            static_cast<unsigned long long>(driver_expected_hash),
            static_cast<unsigned long long>(rt.code_snap.text_hash));
        return false;
    }

    webhook::write_log_critical_fmt("init",
        "driver_bridge_register_self_dll_protection_pre phase=%s pid=%lu tid=%lu base=0x%llX text=0x%llX size=0x%X hash=0x%016llX app_hash=0x%016llX hash_algo=driver_crc32c",
        phase_name,
        GetCurrentProcessId(),
        GetCurrentThreadId(),
        static_cast<unsigned long long>(rt.code_snap.module_base),
        static_cast<unsigned long long>(rt.code_snap.text_base),
        rt.code_snap.text_size,
        static_cast<unsigned long long>(driver_expected_hash),
        static_cast<unsigned long long>(rt.code_snap.text_hash));
    SetLastError(ERROR_SUCCESS);
    uint64_t dll_protect_tick = GetTickCount64();
    bool dll_protect_ok = driver_bridge::register_self_dll_protection(
        rt.code_snap.module_base,
        rt.code_snap.text_base,
        rt.code_snap.text_size,
        driver_expected_hash,
        2000
    );
    DWORD dll_protect_err = dll_protect_ok ? ERROR_SUCCESS : GetLastError();
    webhook::write_log_critical_fmt("init",
        "driver_bridge_register_self_dll_protection_post phase=%s ok=%d err=%lu elapsed_ms=%llu",
        phase_name,
        dll_protect_ok ? 1 : 0,
        static_cast<unsigned long>(dll_protect_err),
        static_cast<unsigned long long>(GetTickCount64() - dll_protect_tick));
    if (!dll_protect_ok && dll_protect_err != ERROR_ALREADY_EXISTS && dll_protect_err != 183ul)
    {
        char detail[256];
        _snprintf_s(detail, sizeof(detail), _TRUNCATE,
            "driver_bridge_register_self_dll_protection_failed phase=%s err=%lu base=0x%llX text=0x%llX size=0x%X hash=0x%016llX app_hash=0x%016llX",
            phase_name,
            static_cast<unsigned long>(dll_protect_err),
            static_cast<unsigned long long>(rt.code_snap.module_base),
            static_cast<unsigned long long>(rt.code_snap.text_base),
            rt.code_snap.text_size,
            static_cast<unsigned long long>(driver_expected_hash),
            static_cast<unsigned long long>(rt.code_snap.text_hash));
        webhook::send_debug_log("init", detail, true);
        enforce_violation_id(aida::reason_ids::reason_id_from_string("driver_bridge_register_dll_protection_failed"), detail);
        return false;
    }
    if (!dll_protect_ok)
        webhook::write_log("init", "driver_bridge_register_self_dll_protection_already_registered");
    webhook::write_log("init", "driver_bridge_ok");

    uint32_t self_pid = GetCurrentProcessId();

    SetLastError(ERROR_SUCCESS);
    uint64_t clear_dr_tick = GetTickCount64();
    webhook::write_log_critical_fmt("init", "kernel_clear_dr_pre phase=%s pid=%lu tid=%lu tick=%llu", phase_name, static_cast<unsigned long>(self_pid), GetCurrentThreadId(), static_cast<unsigned long long>(clear_dr_tick));
    bool clear_dr_ok = driver_bridge::kernel_anti_debug_clear_dr();
    DWORD clear_dr_err = clear_dr_ok ? ERROR_SUCCESS : GetLastError();
    webhook::write_log_critical_fmt("init",
        "kernel_clear_dr_post phase=%s ok=%d err=%lu elapsed_ms=%llu",
        phase_name,
        clear_dr_ok ? 1 : 0,
        static_cast<unsigned long>(clear_dr_err),
        static_cast<unsigned long long>(GetTickCount64() - clear_dr_tick));
    SetLastError(ERROR_SUCCESS);
    uint64_t clear_proc_tick = GetTickCount64();
    webhook::write_log_critical_fmt("init", "kernel_clear_process_dr_pre phase=%s pid=%lu tid=%lu tick=%llu", phase_name, static_cast<unsigned long>(self_pid), GetCurrentThreadId(), static_cast<unsigned long long>(clear_proc_tick));
    bool clear_proc_ok = driver_bridge::kernel_anti_debug_clear_process_dr(self_pid);
    DWORD clear_proc_err = clear_proc_ok ? ERROR_SUCCESS : GetLastError();
    webhook::write_log_critical_fmt("init",
        "kernel_clear_process_dr_post phase=%s ok=%d err=%lu elapsed_ms=%llu",
        phase_name,
        clear_proc_ok ? 1 : 0,
        static_cast<unsigned long>(clear_proc_err),
        static_cast<unsigned long long>(GetTickCount64() - clear_proc_tick));
    bool clear_proc_required = clear_proc_ok || !kernel_adbg_thread_walk_optional_error(clear_proc_err);
    SetLastError(ERROR_SUCCESS);
    uint64_t hide_threads_tick = GetTickCount64();
    webhook::write_log_critical_fmt("init", "kernel_hide_all_threads_pre phase=%s pid=%lu tid=%lu tick=%llu", phase_name, static_cast<unsigned long>(self_pid), GetCurrentThreadId(), static_cast<unsigned long long>(hide_threads_tick));
    bool hide_threads_ok = driver_bridge::kernel_anti_debug_hide_all_threads(self_pid);
    DWORD hide_threads_err = hide_threads_ok ? ERROR_SUCCESS : GetLastError();
    webhook::write_log_critical_fmt("init",
        "kernel_hide_all_threads_post phase=%s ok=%d err=%lu elapsed_ms=%llu",
        phase_name,
        hide_threads_ok ? 1 : 0,
        static_cast<unsigned long>(hide_threads_err),
        static_cast<unsigned long long>(GetTickCount64() - hide_threads_tick));
    bool hide_threads_required = hide_threads_ok || !kernel_adbg_thread_walk_optional_error(hide_threads_err);
    if (!clear_proc_ok && !clear_proc_required)
    {
        g_kernel_clear_process_dr_unsupported.store(true, std::memory_order_release);
        webhook::write_log_critical_fmt("init",
            "kernel_clear_process_dr_optional_unsupported phase=%s err=%lu pid=%lu",
            phase_name,
            static_cast<unsigned long>(clear_proc_err),
            static_cast<unsigned long>(self_pid));
    }
    if (!hide_threads_ok && !hide_threads_required)
    {
        g_kernel_hide_all_threads_unsupported.store(true, std::memory_order_release);
        webhook::write_log_critical_fmt("init",
            "kernel_hide_all_threads_optional_unsupported phase=%s err=%lu pid=%lu",
            phase_name,
            static_cast<unsigned long>(hide_threads_err),
            static_cast<unsigned long>(self_pid));
    }
    bool kernel_adbg_ok = clear_dr_ok && (clear_proc_ok || !clear_proc_required) &&
        (hide_threads_ok || !hide_threads_required);
    {
        char dbg[384];
        _snprintf_s(dbg, sizeof(dbg), _TRUNCATE,
            "kernel_anti_debug_ops phase=%s clear_dr=%d err=%lu clear_process_dr=%d err=%lu clear_process_required=%d hide_all_threads=%d err=%lu hide_required=%d pid=%lu",
            phase_name,
            clear_dr_ok ? 1 : 0,
            static_cast<unsigned long>(clear_dr_err),
            clear_proc_ok ? 1 : 0,
            static_cast<unsigned long>(clear_proc_err),
            clear_proc_required ? 1 : 0,
            hide_threads_ok ? 1 : 0,
            static_cast<unsigned long>(hide_threads_err),
            hide_threads_required ? 1 : 0,
            static_cast<unsigned long>(self_pid));
        webhook::write_log("init", dbg);
    }
    if (!kernel_adbg_ok)
    {
        webhook::send_debug_log("init", "kernel_anti_debug_required_op_failed", true);
        enforce_violation_id(aida::reason_ids::reason_id_kernel_debugger_at_startup, "kernel_anti_debug_required_op_failed");
        return false;
    }
    webhook::write_log("init", "kernel_anti_debug_ok");

    uint64_t debugger_pid = 0;
    SetLastError(ERROR_SUCCESS);
    uint64_t scan_tick = GetTickCount64();
    webhook::write_log_critical_fmt("init", "kernel_debugger_scan_pre phase=%s pid=%lu tid=%lu tick=%llu", phase_name, static_cast<unsigned long>(self_pid), GetCurrentThreadId(), static_cast<unsigned long long>(scan_tick));
    bool scan_ok = driver_bridge::kernel_anti_debug_scan_debuggers(&debugger_pid);
    DWORD scan_err = scan_ok ? ERROR_SUCCESS : GetLastError();
    webhook::write_log_critical_fmt("init",
        "kernel_debugger_scan_post phase=%s ok=%d err=%lu debugger_pid=%llu elapsed_ms=%llu",
        phase_name,
        scan_ok ? 1 : 0,
        static_cast<unsigned long>(scan_err),
        static_cast<unsigned long long>(debugger_pid),
        static_cast<unsigned long long>(GetTickCount64() - scan_tick));
    {
        char dbg[160];
        _snprintf_s(dbg, sizeof(dbg), _TRUNCATE,
            "kernel_debugger_scan_result phase=%s ok=%d err=%lu debugger_pid=%llu",
            phase_name,
            scan_ok ? 1 : 0,
            static_cast<unsigned long>(scan_err),
            static_cast<unsigned long long>(debugger_pid));
        webhook::write_log("init", dbg);
    }
    if (!scan_ok)
    {
        webhook::send_debug_log("init", "kernel_debugger_scan_required_op_failed", true);
        enforce_violation_id(aida::reason_ids::reason_id_kernel_debugger_at_startup, "kernel_debugger_scan_required_op_failed");
        return false;
    }
    if (debugger_pid != 0)
    {
        if (kernel_debugger_scan_confirmed_for_enforcement("init", "startup_scan", debugger_pid))
        {
            webhook::send_debug_log("init", "kernel_debugger_detected_pid_" + std::to_string(debugger_pid), true);
            enforce_violation_id(aida::reason_ids::reason_id_kernel_debugger_at_startup);
            return false;
        }
        webhook::write_log_critical_fmt("init",
            "kernel_debugger_scan_unconfirmed_global_tool_ignored phase=%s debugger_pid=%llu",
            phase_name,
            static_cast<unsigned long long>(debugger_pid));
    }
    webhook::write_log("init", "kernel_debugger_scan_ok");

    rt.driver_hardening_done.store(true, std::memory_order_release);
    webhook::write_log_critical_fmt("init",
        "driver_hardening_done phase=%s pid=%lu",
        phase_name,
        static_cast<unsigned long>(self_pid));
    return true;
}

inline bool initialize()
{
    webhook::write_log("init", "initialize_ENTRY before state::get");
    static std::mutex s_initialize_mtx;
    std::lock_guard<std::mutex> init_lk(s_initialize_mtx);
    auto& rt = state::get();
    webhook::write_log("init", "initialize_state_get_OK");

    if (rt.initialized.load(std::memory_order_acquire)) {
        if (driver_bridge::is_loaded() && driver_bridge::using_kernel_driver() &&
            !rt.driver_hardening_done.load(std::memory_order_acquire))
        {
            webhook::write_log("init", "initialize_already_initialized_driver_hardening_retry");
            return ensure_driver_hardening("initialize_retry");
        }
        webhook::write_log("init", "initialize_already_initialized_returning_true");
        return true;
    }
    webhook::write_log("init", "initialize_not_yet_initialized");

    uint64_t kat_tick = GetTickCount64();
    webhook::write_log_critical_fmt("init",
        "ensure_kat_passed_pre pid=%lu tid=%lu tick=%llu",
        GetCurrentProcessId(),
        GetCurrentThreadId(),
        static_cast<unsigned long long>(kat_tick));
    webhook::write_log("init", "calling_ensure_kat_passed");
    bool kat_ok = key_pipeline::ensure_kat_passed();
    webhook::write_log_critical_fmt("init",
        "ensure_kat_passed_post ok=%d elapsed_ms=%llu",
        kat_ok ? 1 : 0,
        static_cast<unsigned long long>(GetTickCount64() - kat_tick));
    if (!kat_ok)
    {
        webhook::write_log("init", "ensure_kat_passed_returned_FALSE_about_to_fastfail");
        webhook::send_debug_log("init", "crypto_kat_failed", true);
        __fastfail(0xA1DA0CA7u);
    }
    webhook::write_log("init", "crypto_kat_ok");

    uint64_t syscall_tick = GetTickCount64();
    webhook::write_log_critical_fmt("init",
        "syscall_initialize_pre pid=%lu tid=%lu tick=%llu",
        GetCurrentProcessId(),
        GetCurrentThreadId(),
        static_cast<unsigned long long>(syscall_tick));
    bool syscall_ok = syscall::initialize();
    webhook::write_log_critical_fmt("init",
        "syscall_initialize_post ok=%d elapsed_ms=%llu",
        syscall_ok ? 1 : 0,
        static_cast<unsigned long long>(GetTickCount64() - syscall_tick));
    if (!syscall_ok)
    {
        webhook::send_debug_log("init", "syscall_initialize_failed", true);
        enforce_violation_id(aida::reason_ids::reason_id_from_string("syscall_initialize_failed"), "syscall_initialize_failed");
        return false;
    }
    webhook::write_log("init", "syscall_ok");

    if (driver_bridge::is_loaded() && driver_bridge::using_kernel_driver())
    {
        bool tier_a_present = false;
        uint32_t tier_a_mask = 0;
        uint64_t tier_a_base = 0;
        uint64_t tier_tick = GetTickCount64();
        webhook::write_log_critical_fmt("init",
            "tier_a_driver_present_query_pre pid=%lu tid=%lu tick=%llu",
            GetCurrentProcessId(),
            GetCurrentThreadId(),
            static_cast<unsigned long long>(tier_tick));
        SetLastError(ERROR_SUCCESS);
        bool tier_a_ok = driver_bridge::tier_a_driver_present_query(&tier_a_present, &tier_a_mask, &tier_a_base);
        DWORD tier_a_err = tier_a_ok ? ERROR_SUCCESS : GetLastError();
        webhook::write_log_critical_fmt("init",
            "tier_a_driver_present_query_post ok=%d err=%lu present=%d mask=0x%08X first_base=0x%llX elapsed_ms=%llu",
            tier_a_ok ? 1 : 0,
            static_cast<unsigned long>(tier_a_err),
            tier_a_present ? 1 : 0,
            tier_a_mask,
            static_cast<unsigned long long>(tier_a_base),
            static_cast<unsigned long long>(GetTickCount64() - tier_tick));
        if (tier_a_ok && tier_a_present)
        {
            webhook::send_debug_log("init", "tier_a_driver_present_startup", true);
            std::wstring msg = WOBFSTR(L"AiDA cannot start because a kernel-mode analysis driver is loaded. Unload it and try again.");
            std::wstring title = WOBFSTR(L"AiDA");
            MessageBoxW(nullptr, msg.c_str(), title.c_str(),
                MB_OK | MB_ICONERROR | MB_SYSTEMMODAL | MB_TOPMOST);
            ExitProcess(1);
        }

        uint64_t canary_alloc_tick = GetTickCount64();
        webhook::write_log_critical_fmt("init",
            "canary_alloc_pre pid=%lu tid=%lu tick=%llu size=0x%X alloc=0x%lX protect=0x%lX",
            GetCurrentProcessId(),
            GetCurrentThreadId(),
            static_cast<unsigned long long>(canary_alloc_tick),
            4096u,
            static_cast<unsigned long>(MEM_COMMIT | MEM_RESERVE),
            static_cast<unsigned long>(PAGE_READWRITE));
        SetLastError(ERROR_SUCCESS);
        void* canary = VirtualAlloc(nullptr, 4096, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        DWORD canary_alloc_error = canary ? ERROR_SUCCESS : GetLastError();
        MEMORY_BASIC_INFORMATION canary_alloc_mbi{};
        SIZE_T canary_alloc_vq = canary ? VirtualQuery(canary, &canary_alloc_mbi, sizeof(canary_alloc_mbi)) : 0;
        {
            char dbg[640];
            std::snprintf(dbg, sizeof(dbg),
                "canary_alloc_result va=%p gle=%lu elapsed_ms=%llu vq=%llu mbi_base=0x%llX alloc_base=0x%llX region=0x%llX state=0x%lX protect=0x%lX type=0x%lX",
                canary,
                static_cast<unsigned long>(canary_alloc_error),
                static_cast<unsigned long long>(GetTickCount64() - canary_alloc_tick),
                static_cast<unsigned long long>(canary_alloc_vq),
                static_cast<unsigned long long>(reinterpret_cast<uintptr_t>(canary_alloc_mbi.BaseAddress)),
                static_cast<unsigned long long>(reinterpret_cast<uintptr_t>(canary_alloc_mbi.AllocationBase)),
                static_cast<unsigned long long>(canary_alloc_mbi.RegionSize),
                static_cast<unsigned long>(canary_alloc_mbi.State),
                static_cast<unsigned long>(canary_alloc_mbi.Protect),
                static_cast<unsigned long>(canary_alloc_mbi.Type));
            webhook::write_log("init", dbg);
        }
        if (canary != nullptr)
        {
            auto* canary_bytes = static_cast<unsigned char*>(canary);
            ULONGLONG canary_seed = GetTickCount64()
                ^ static_cast<ULONGLONG>(reinterpret_cast<ULONG_PTR>(canary))
                ^ (static_cast<ULONGLONG>(GetCurrentProcessId()) << 32);
            ULONGLONG initial_canary_seed = canary_seed;
            for (size_t index = 0; index < 4096; ++index)
            {
                canary_seed = canary_seed * 2862933555777941757ULL + 3037000493ULL;
                canary_bytes[index] = static_cast<unsigned char>(canary_seed >> 33);
            }

            uint64_t canary_lock_tick = GetTickCount64();
            webhook::write_log_critical_fmt("init",
                "canary_lock_pre pid=%lu tid=%lu tick=%llu va=%p size=0x%X",
                GetCurrentProcessId(),
                GetCurrentThreadId(),
                static_cast<unsigned long long>(canary_lock_tick),
                canary,
                4096u);
            SetLastError(ERROR_SUCCESS);
            BOOL lock_ok = VirtualLock(canary, 4096);
            DWORD lock_error = lock_ok ? 0 : GetLastError();
            webhook::write_log_critical_fmt("init",
                "canary_lock_post ok=%d err=%lu elapsed_ms=%llu va=%p size=0x%X",
                lock_ok ? 1 : 0,
                static_cast<unsigned long>(lock_error),
                static_cast<unsigned long long>(GetTickCount64() - canary_lock_tick),
                canary,
                4096u);
            bool register_ok = false;
            DWORD register_error = lock_ok ? ERROR_SUCCESS : lock_error;
            DWORD register_seh = 0;
            seh_capture_t register_exception{};
            if (lock_ok)
            {
                uint64_t canary_register_tick = GetTickCount64();
                webhook::write_log_critical_fmt("init",
                    "canary_register_pre pid=%lu tid=%lu tick=%llu va=%p size=0x%X",
                    GetCurrentProcessId(),
                    GetCurrentThreadId(),
                    static_cast<unsigned long long>(canary_register_tick),
                    canary,
                    4096u);
                BOOL register_bool = FALSE;
                register_seh = seh_canary_register(canary,
                    4096,
                    &register_bool,
                    &register_error,
                    &register_exception);
                register_ok = register_seh == 0 && register_bool != FALSE;
                webhook::write_log_critical_fmt("init",
                    "canary_register_post ok=%d err=%lu seh=0x%08lX elapsed_ms=%llu va=%p size=0x%X",
                    register_ok ? 1 : 0,
                    static_cast<unsigned long>(register_error),
                    static_cast<unsigned long>(register_seh),
                    static_cast<unsigned long long>(GetTickCount64() - canary_register_tick),
                    canary,
                    4096u);
                if (register_seh != 0)
                {
                    webhook::write_log_critical_fmt("init",
                        "canary_register_seh code=0x%08lX addr=%p flags=0x%08lX params=%lu p0=0x%llX p1=0x%llX p2=0x%llX p3=0x%llX err=%lu va=%p size=0x%X pid=%lu tid=%lu",
                        static_cast<unsigned long>(register_seh),
                        register_exception.address,
                        static_cast<unsigned long>(register_exception.flags),
                        static_cast<unsigned long>(register_exception.parameters),
                        static_cast<unsigned long long>(register_exception.info[0]),
                        static_cast<unsigned long long>(register_exception.info[1]),
                        static_cast<unsigned long long>(register_exception.info[2]),
                        static_cast<unsigned long long>(register_exception.info[3]),
                        static_cast<unsigned long>(register_error),
                        canary,
                        4096u,
                        static_cast<unsigned long>(GetCurrentProcessId()),
                        static_cast<unsigned long>(GetCurrentThreadId()));
                }
            }
            {
                char dbg[256];
                std::snprintf(dbg, sizeof(dbg), "canary_stage va=%p pid=%lu seed=0x%llx lock=%d lock_err=%lu register=%d register_err=%lu register_seh=0x%08lx",
                    canary,
                    GetCurrentProcessId(),
                    static_cast<unsigned long long>(initial_canary_seed),
                    lock_ok ? 1 : 0,
                    lock_error,
                    register_ok ? 1 : 0,
                    register_error,
                    static_cast<unsigned long>(register_seh));
                webhook::write_log("init", dbg);
            }

            if (lock_ok && register_ok)
            {
                DWORD old_protect = 0;
                MEMORY_BASIC_INFORMATION before_mbi{};
                SIZE_T before_vq = VirtualQuery(canary, &before_mbi, sizeof(before_mbi));
                uint64_t protect_tick = GetTickCount64();
                webhook::write_log_critical_fmt("init",
                    "canary_virtualprotect_pre pid=%lu tid=%lu tick=%llu va=%p size=0x%X new=0x%lX vq=%llu mbi_base=0x%llX alloc_base=0x%llX region=0x%llX state=0x%lX protect=0x%lX type=0x%lX",
                    GetCurrentProcessId(),
                    GetCurrentThreadId(),
                    static_cast<unsigned long long>(protect_tick),
                    canary,
                    4096u,
                    static_cast<unsigned long>(PAGE_NOACCESS),
                    static_cast<unsigned long long>(before_vq),
                    static_cast<unsigned long long>(reinterpret_cast<uintptr_t>(before_mbi.BaseAddress)),
                    static_cast<unsigned long long>(reinterpret_cast<uintptr_t>(before_mbi.AllocationBase)),
                    static_cast<unsigned long long>(before_mbi.RegionSize),
                    static_cast<unsigned long>(before_mbi.State),
                    static_cast<unsigned long>(before_mbi.Protect),
                    static_cast<unsigned long>(before_mbi.Type));
                SetLastError(ERROR_SUCCESS);
                BOOL protect_ok = VirtualProtect(canary, 4096, PAGE_NOACCESS, &old_protect);
                DWORD protect_error = protect_ok ? ERROR_SUCCESS : GetLastError();
                MEMORY_BASIC_INFORMATION after_mbi{};
                SIZE_T after_vq = VirtualQuery(canary, &after_mbi, sizeof(after_mbi));
                webhook::write_log_critical_fmt("init",
                    "canary_virtualprotect_post ok=%d err=%lu elapsed_ms=%llu va=%p size=0x%X old=0x%lX after_vq=%llu after_base=0x%llX after_alloc=0x%llX after_region=0x%llX after_state=0x%lX after_protect=0x%lX after_type=0x%lX",
                    protect_ok ? 1 : 0,
                    static_cast<unsigned long>(protect_error),
                    static_cast<unsigned long long>(GetTickCount64() - protect_tick),
                    canary,
                    4096u,
                    static_cast<unsigned long>(old_protect),
                    static_cast<unsigned long long>(after_vq),
                    static_cast<unsigned long long>(reinterpret_cast<uintptr_t>(after_mbi.BaseAddress)),
                    static_cast<unsigned long long>(reinterpret_cast<uintptr_t>(after_mbi.AllocationBase)),
                    static_cast<unsigned long long>(after_mbi.RegionSize),
                    static_cast<unsigned long>(after_mbi.State),
                    static_cast<unsigned long>(after_mbi.Protect),
                    static_cast<unsigned long>(after_mbi.Type));
                {
                    char dbg[224];
                    std::snprintf(dbg, sizeof(dbg), "canary_protect va=%p protect=%d old=0x%lx err=%lu",
                        canary,
                        protect_ok ? 1 : 0,
                        old_protect,
                        static_cast<unsigned long>(protect_error));
                    webhook::write_log("init", dbg);
                }
                rt.canary_page = canary;
            }
            else if (lock_ok && register_seh != 0)
            {
                MEMORY_BASIC_INFORMATION retained_mbi{};
                SIZE_T retained_vq = VirtualQuery(canary, &retained_mbi, sizeof(retained_mbi));
                rt.canary_page = canary;
                webhook::write_log_critical_fmt("init",
                    "canary_register_seh_page_retained va=%p size=0x%X err=%lu seh=0x%08lX vq=%llu mbi_base=0x%llX alloc_base=0x%llX region=0x%llX state=0x%lX protect=0x%lX type=0x%lX",
                    canary,
                    4096u,
                    static_cast<unsigned long>(register_error),
                    static_cast<unsigned long>(register_seh),
                    static_cast<unsigned long long>(retained_vq),
                    static_cast<unsigned long long>(reinterpret_cast<uintptr_t>(retained_mbi.BaseAddress)),
                    static_cast<unsigned long long>(reinterpret_cast<uintptr_t>(retained_mbi.AllocationBase)),
                    static_cast<unsigned long long>(retained_mbi.RegionSize),
                    static_cast<unsigned long>(retained_mbi.State),
                    static_cast<unsigned long>(retained_mbi.Protect),
                    static_cast<unsigned long>(retained_mbi.Type));
            }
            else
            {
                webhook::write_log_critical_fmt("init",
                    "canary_cleanup_after_failed_stage va=%p lock_ok=%d register_ok=%d lock_err=%lu register_err=%lu register_seh=0x%08lX",
                    canary,
                    lock_ok ? 1 : 0,
                    register_ok ? 1 : 0,
                    static_cast<unsigned long>(lock_error),
                    static_cast<unsigned long>(register_error),
                    static_cast<unsigned long>(register_seh));
                SetLastError(ERROR_SUCCESS);
                BOOL unlock_ok = VirtualUnlock(canary, 4096);
                DWORD unlock_err = unlock_ok ? ERROR_SUCCESS : GetLastError();
                webhook::write_log_critical_fmt("init",
                    "canary_virtualunlock_post ok=%d err=%lu va=%p size=0x%X",
                    unlock_ok ? 1 : 0,
                    static_cast<unsigned long>(unlock_err),
                    canary,
                    4096u);
                SecureZeroMemory(canary, 4096);
                SetLastError(ERROR_SUCCESS);
                BOOL free_ok = VirtualFree(canary, 0, MEM_RELEASE);
                DWORD free_err = free_ok ? ERROR_SUCCESS : GetLastError();
                webhook::write_log_critical_fmt("init",
                    "canary_virtualfree_post ok=%d err=%lu va=%p",
                    free_ok ? 1 : 0,
                    static_cast<unsigned long>(free_err),
                    canary);
            }
        }
    }

    uint64_t snapshot_code_tick = GetTickCount64();
    webhook::write_log_critical_fmt("init",
        "snapshot_code_call_pre pid=%lu tid=%lu tick=%llu base=0x%llX size=0x%X hash=0x%016llX module_base=0x%llX module_end=0x%llX",
        GetCurrentProcessId(),
        GetCurrentThreadId(),
        static_cast<unsigned long long>(snapshot_code_tick),
        static_cast<unsigned long long>(rt.code_snap.text_base),
        rt.code_snap.text_size,
        static_cast<unsigned long long>(rt.code_snap.text_hash),
        static_cast<unsigned long long>(rt.code_snap.module_base),
        static_cast<unsigned long long>(rt.code_snap.module_end));
    bool snapshot_code_ok = integrity::snapshot_code(rt.code_snap);
    webhook::write_log_critical_fmt("init",
        "snapshot_code_call_post ok=%d elapsed_ms=%llu base=0x%llX size=0x%X hash=0x%016llX module_base=0x%llX module_end=0x%llX",
        snapshot_code_ok ? 1 : 0,
        static_cast<unsigned long long>(GetTickCount64() - snapshot_code_tick),
        static_cast<unsigned long long>(rt.code_snap.text_base),
        rt.code_snap.text_size,
        static_cast<unsigned long long>(rt.code_snap.text_hash),
        static_cast<unsigned long long>(rt.code_snap.module_base),
        static_cast<unsigned long long>(rt.code_snap.module_end));
    if (!snapshot_code_ok)
    {
        webhook::write_log_critical("init", "snapshot_code_failed");
        enforce_violation_id(aida::reason_ids::reason_id_from_string("snapshot_code_failed"), "snapshot_code_failed");
        return false;
    }
    webhook::write_log_critical_fmt("init",
        "snapshot_code_gate_passed pid=%lu tid=%lu base=0x%llX size=0x%X hash=0x%016llX",
        GetCurrentProcessId(),
        GetCurrentThreadId(),
        static_cast<unsigned long long>(rt.code_snap.text_base),
        rt.code_snap.text_size,
        static_cast<unsigned long long>(rt.code_snap.text_hash));
    webhook::write_log_critical("init", "snapshot_code_ok_log_pre");
    webhook::write_log("init", "snapshot_code_ok");
    webhook::write_log_critical("init", "snapshot_code_ok_log_post");

    uint64_t snapshot_iat_tick = GetTickCount64();
    webhook::write_log_critical_fmt("init",
        "snapshot_iat_call_pre pid=%lu tid=%lu tick=%llu prior_entries=%zu base=0x%llX module_end=0x%llX",
        GetCurrentProcessId(),
        GetCurrentThreadId(),
        static_cast<unsigned long long>(snapshot_iat_tick),
        rt.iat_snap.size(),
        static_cast<unsigned long long>(rt.code_snap.module_base),
        static_cast<unsigned long long>(rt.code_snap.module_end));
    integrity::snapshot_iat(rt.iat_snap);
    webhook::write_log_critical_fmt("init",
        "snapshot_iat_call_post entries=%zu elapsed_ms=%llu",
        rt.iat_snap.size(),
        static_cast<unsigned long long>(GetTickCount64() - snapshot_iat_tick));
    webhook::write_log_critical("init", "snapshot_iat_ok_log_pre");
    webhook::write_log("init", "snapshot_iat_ok");
    webhook::write_log_critical("init", "snapshot_iat_ok_log_post");

    uint64_t block_chain_tick = GetTickCount64();
    webhook::write_log_critical_fmt("init",
        "block_chain_build_pre pid=%lu tid=%lu tick=%llu prior_blocks=%zu base=0x%llX size=0x%X",
        GetCurrentProcessId(),
        GetCurrentThreadId(),
        static_cast<unsigned long long>(block_chain_tick),
        rt.block_chain.size(),
        static_cast<unsigned long long>(rt.code_snap.text_base),
        rt.code_snap.text_size);
    bool block_chain_ok = integrity::build_block_chain(rt.code_snap, rt.block_chain);
    webhook::write_log_critical_fmt("init",
        "block_chain_build_post ok=%d blocks=%zu elapsed_ms=%llu",
        block_chain_ok ? 1 : 0,
        rt.block_chain.size(),
        static_cast<unsigned long long>(GetTickCount64() - block_chain_tick));
    if (!block_chain_ok)
    {
        webhook::write_log_critical("init", "block_chain_build_failed");
        enforce_violation_id(aida::reason_ids::reason_id_from_string("block_chain_build_failed"), "block_chain_build_failed");
        return false;
    }
    webhook::write_log_critical("init", "block_chain_ok_log_pre");
    webhook::write_log("init", "block_chain_ok");
    webhook::write_log_critical("init", "block_chain_ok_log_post");

    uint64_t token_chain_tick = GetTickCount64();
    webhook::write_log_critical_fmt("init",
        "token_chain_initialize_pre pid=%lu tid=%lu tick=%llu",
        GetCurrentProcessId(),
        GetCurrentThreadId(),
        static_cast<unsigned long long>(token_chain_tick));
    token_chain::initialize_keys();
    webhook::write_log_critical_fmt("init",
        "token_chain_initialize_post elapsed_ms=%llu",
        static_cast<unsigned long long>(GetTickCount64() - token_chain_tick));
    {
        uint32_t pf = ai_deception::phase::cached_phase_flags();
        webhook::write_log_critical_fmt("init", "token_chain_phase_flags flags=0x%X", pf);
        if (pf & 0x20u)
        {
            webhook::write_log_critical("init", "rdtsc_entangle_enable_pre");
            token_chain::enable_rdtsc_entangle(true);
            webhook::write_log("init", "rdtsc_entangle_enabled");
            webhook::write_log_critical("init", "rdtsc_entangle_enable_post");
        }
    }
    webhook::write_log_critical("init", "token_chain_ok_log_pre");
    webhook::write_log("init", "token_chain_ok");
    webhook::write_log_critical("init", "token_chain_ok_log_post");

    {
        uint64_t anti_debug_tick = GetTickCount64();
        webhook::write_log_critical_fmt("init",
            "anti_debug_scan_pre pid=%lu tid=%lu tick=%llu module_base=0x%llX module_end=0x%llX",
            GetCurrentProcessId(),
            GetCurrentThreadId(),
            static_cast<unsigned long long>(anti_debug_tick),
            static_cast<unsigned long long>(rt.code_snap.module_base),
            static_cast<unsigned long long>(rt.code_snap.module_end));
        auto dbg = anti_debug::full_scan(rt.code_snap.module_base, rt.code_snap.module_end);
        webhook::write_log_critical_fmt("init",
            "anti_debug_scan_post detected=%d elapsed_ms=%llu summary_len=%zu",
            dbg.any_detected() ? 1 : 0,
            static_cast<unsigned long long>(GetTickCount64() - anti_debug_tick),
            dbg.summary.size());
        if (dbg.any_detected())
        {
            webhook::send_debug_log("init", "debugger_at_startup: " + dbg.summary, true);
            enforce_violation_id(aida::reason_ids::reason_id_debugger_at_startup, dbg.summary);
            return false;
        }
    }
    webhook::write_log_critical("init", "anti_debug_ok_log_pre");
    webhook::write_log("init", "anti_debug_ok");
    webhook::write_log_critical("init", "anti_debug_ok_log_post");

    {
        uint64_t anti_hook_tick = GetTickCount64();
        webhook::write_log_critical_fmt("init",
            "anti_hook_scan_pre pid=%lu tid=%lu tick=%llu iat_entries=%zu",
            GetCurrentProcessId(),
            GetCurrentThreadId(),
            static_cast<unsigned long long>(anti_hook_tick),
            rt.iat_snap.size());
        auto hook = anti_hook::full_scan(rt.iat_snap);
        webhook::write_log_critical_fmt("init",
            "anti_hook_scan_post detected=%d elapsed_ms=%llu summary_len=%zu",
            hook.any_detected() ? 1 : 0,
            static_cast<unsigned long long>(GetTickCount64() - anti_hook_tick),
            hook.summary.size());
        if (hook.any_detected())
        {
            webhook::send_debug_log("init", "hook_at_startup: " + hook.summary, true);
            enforce_violation_id(aida::reason_ids::reason_id_hook_at_startup, hook.summary);
            return false;
        }
    }
    webhook::write_log_critical("init", "anti_hook_ok_log_pre");
    webhook::write_log("init", "anti_hook_ok");
    webhook::write_log_critical("init", "anti_hook_ok_log_post");

    if (!enforce_ai_tool_posture("startup", false))
        return false;
    webhook::write_log_critical("init", "ai_tool_posture_ok_log_pre");
    webhook::write_log("init", "ai_tool_posture_ok");
    webhook::write_log_critical("init", "ai_tool_posture_ok_log_post");

    {
        uint64_t anti_vm_tick = GetTickCount64();
        webhook::write_log_critical_fmt("init",
            "anti_vm_scan_pre pid=%lu tid=%lu tick=%llu",
            GetCurrentProcessId(),
            GetCurrentThreadId(),
            static_cast<unsigned long long>(anti_vm_tick));
        auto vm = anti_vm::full_scan();
        webhook::write_log_critical_fmt("init",
            "anti_vm_scan_post detected=%d trust_failure=%d kernel_ok=%d kernel_deferred=%d kernel_err=%lu elapsed_ms=%llu summary_len=%zu",
            vm.any_detected() ? 1 : 0,
            vm.kernel_hv_trust_failure() ? 1 : 0,
            vm.kernel_query_ok ? 1 : 0,
            vm.kernel_hv_deferred ? 1 : 0,
            static_cast<unsigned long>(vm.kernel_hv_error),
            static_cast<unsigned long long>(GetTickCount64() - anti_vm_tick),
            vm.summary.size());
        if (vm.kernel_hv_trust_failure())
        {
            webhook::send_debug_log("init", "kernel_hv_detection_untrusted: " + vm.summary, true);
            enforce_violation_id(aida::reason_ids::reason_id_from_string("kernel_hv_detection_untrusted"), vm.summary);
            return false;
        }
        if (vm.any_detected())
        {
            webhook::send_debug_log("init", "vm_at_startup: " + vm.summary, true);
            enforce_violation_id(aida::reason_ids::reason_id_vm_at_startup, vm.summary);
            return false;
        }
    }
    webhook::write_log_critical("init", "anti_vm_ok_log_pre");
    webhook::write_log("init", "anti_vm_ok");
    webhook::write_log_critical("init", "anti_vm_ok_log_post");

    uint64_t virtualizer_tick = GetTickCount64();
    webhook::write_log_critical_fmt("init",
        "virtualizer_initialize_pre pid=%lu tid=%lu tick=%llu text_base=0x%llX text_size=0x%X text_hash=0x%016llX",
        GetCurrentProcessId(),
        GetCurrentThreadId(),
        static_cast<unsigned long long>(virtualizer_tick),
        static_cast<unsigned long long>(rt.code_snap.text_base),
        rt.code_snap.text_size,
        static_cast<unsigned long long>(rt.code_snap.text_hash));
    virtualizer::initialize(
        rt.code_snap.text_base,
        rt.code_snap.text_size,
        rt.code_snap.text_hash);
    webhook::write_log_critical_fmt("init",
        "virtualizer_initialize_post elapsed_ms=%llu",
        static_cast<unsigned long long>(GetTickCount64() - virtualizer_tick));
    webhook::write_log_critical("init", "virtualizer_ok_log_pre");
    webhook::write_log("init", "virtualizer_ok");
    webhook::write_log_critical("init", "virtualizer_ok_log_post");

    {
        uint64_t vm_nested_tick = GetTickCount64();
        webhook::write_log_critical_fmt("init",
            "vm_nested_tags_pre pid=%lu tid=%lu tick=%llu",
            GetCurrentProcessId(),
            GetCurrentThreadId(),
            static_cast<unsigned long long>(vm_nested_tick));
        uint32_t nested_applied = apply_vm_nested_tags();
        char dbg[64];
        _snprintf_s(dbg, sizeof(dbg), _TRUNCATE,
            "vm_nested_tags_applied=%u", nested_applied);
        webhook::write_log("init", dbg);
        webhook::write_log_critical_fmt("init",
            "vm_nested_tags_post applied=%u elapsed_ms=%llu",
            nested_applied,
            static_cast<unsigned long long>(GetTickCount64() - vm_nested_tick));
    }

    uint64_t ghost_tick = GetTickCount64();
    webhook::write_log_critical_fmt("init",
        "ghost_veh_initialize_pre pid=%lu tid=%lu tick=%llu",
        GetCurrentProcessId(),
        GetCurrentThreadId(),
        static_cast<unsigned long long>(ghost_tick));
    ghost_veh::initialize();
    webhook::write_log_critical_fmt("init",
        "ghost_veh_initialize_post active=%d flags=0x%X elapsed_ms=%llu",
        ghost_veh::is_active() ? 1 : 0,
        ghost_veh::get_flags(),
        static_cast<unsigned long long>(GetTickCount64() - ghost_tick));
    {
        char dbg[64];
        _snprintf_s(dbg, sizeof(dbg), _TRUNCATE,
            "ghost_veh_active=%d flags=0x%x",
            ghost_veh::is_active() ? 1 : 0, ghost_veh::get_flags());
        webhook::write_log("init", dbg);
    }

    uint64_t code_encrypt_tick = GetTickCount64();
    webhook::write_log_critical_fmt("init",
        "code_encrypt_initialize_pre pid=%lu tid=%lu tick=%llu text_hash=0x%016llX",
        GetCurrentProcessId(),
        GetCurrentThreadId(),
        static_cast<unsigned long long>(code_encrypt_tick),
        static_cast<unsigned long long>(rt.code_snap.text_hash));
    code_encrypt::initialize(rt.code_snap.text_hash);
    webhook::write_log_critical_fmt("init",
        "code_encrypt_initialize_post elapsed_ms=%llu",
        static_cast<unsigned long long>(GetTickCount64() - code_encrypt_tick));
    webhook::write_log_critical("init", "code_encrypt_ok_log_pre");
    webhook::write_log("init", "code_encrypt_ok");
    webhook::write_log_critical("init", "code_encrypt_ok_log_post");

    uint64_t metamorphic_tick = GetTickCount64();
    webhook::write_log_critical_fmt("init",
        "metamorphic_initialize_pre pid=%lu tid=%lu tick=%llu",
        GetCurrentProcessId(),
        GetCurrentThreadId(),
        static_cast<unsigned long long>(metamorphic_tick));
    metamorphic::initialize();
    webhook::write_log_critical_fmt("init",
        "metamorphic_initialize_post elapsed_ms=%llu",
        static_cast<unsigned long long>(GetTickCount64() - metamorphic_tick));
    webhook::write_log_critical("init", "metamorphic_ok_log_pre");
    webhook::write_log("init", "metamorphic_ok");
    webhook::write_log_critical("init", "metamorphic_ok_log_post");

    uint64_t cloakwork_tick = GetTickCount64();
    webhook::write_log_critical_fmt("init",
        "cloakwork_initialize_pre pid=%lu tid=%lu tick=%llu text_hash=0x%016llX",
        GetCurrentProcessId(),
        GetCurrentThreadId(),
        static_cast<unsigned long long>(cloakwork_tick),
        static_cast<unsigned long long>(rt.code_snap.text_hash));
    cloakwork::initialize(rt.code_snap.text_hash);
    webhook::write_log_critical_fmt("init",
        "cloakwork_initialize_post elapsed_ms=%llu",
        static_cast<unsigned long long>(GetTickCount64() - cloakwork_tick));
    webhook::write_log_critical("init", "cloakwork_ok_log_pre");
    webhook::write_log("init", "cloakwork_ok");
    webhook::write_log_critical("init", "cloakwork_ok_log_post");

    uint64_t ai_deception_tick = GetTickCount64();
    webhook::write_log_critical_fmt("init",
        "ai_deception_initialize_pre pid=%lu tid=%lu tick=%llu",
        GetCurrentProcessId(),
        GetCurrentThreadId(),
        static_cast<unsigned long long>(ai_deception_tick));
    ai_deception::initialize();
    webhook::write_log_critical_fmt("init",
        "ai_deception_initialize_post elapsed_ms=%llu",
        static_cast<unsigned long long>(GetTickCount64() - ai_deception_tick));
    webhook::write_log_critical("init", "ai_deception_ok_log_pre");
    webhook::write_log("init", "ai_deception_ok");
    webhook::write_log_critical("init", "ai_deception_ok_log_post");

    uint64_t call_obfuscation_tick = GetTickCount64();
    webhook::write_log_critical_fmt("init",
        "call_obfuscation_initialize_pre pid=%lu tid=%lu tick=%llu text_hash=0x%016llX",
        GetCurrentProcessId(),
        GetCurrentThreadId(),
        static_cast<unsigned long long>(call_obfuscation_tick),
        static_cast<unsigned long long>(rt.code_snap.text_hash));
    call_obfuscation::initialize(rt.code_snap.text_hash);
    webhook::write_log_critical_fmt("init",
        "call_obfuscation_initialize_post elapsed_ms=%llu",
        static_cast<unsigned long long>(GetTickCount64() - call_obfuscation_tick));
    webhook::write_log_critical("init", "call_obfuscation_ok_log_pre");
    webhook::write_log("init", "call_obfuscation_ok");
    webhook::write_log_critical("init", "call_obfuscation_ok_log_post");

    uint64_t decoy_tick = GetTickCount64();
    webhook::write_log_critical_fmt("init",
        "decoy_initialize_pre pid=%lu tid=%lu tick=%llu",
        GetCurrentProcessId(),
        GetCurrentThreadId(),
        static_cast<unsigned long long>(decoy_tick));
    decoy::initialize();
    webhook::write_log_critical_fmt("init",
        "decoy_initialize_post elapsed_ms=%llu",
        static_cast<unsigned long long>(GetTickCount64() - decoy_tick));
    webhook::write_log_critical("init", "decoy_call_graph_ok_log_pre");
    webhook::write_log("init", "decoy_call_graph_ok");
    webhook::write_log_critical("init", "decoy_call_graph_ok_log_post");


    {
        packer::build_protection_status_t packer_status{};
        webhook::write_log_critical_fmt("init",
            "packer_verify_call_enter pid=%lu tid=%lu tick=%llu",
            GetCurrentProcessId(),
            GetCurrentThreadId(),
            static_cast<unsigned long long>(GetTickCount64()));
        const bool packer_ok = packer::verify_build_protection(packer_status);
        {
            char dbg[2048];
            _snprintf_s(dbg, sizeof(dbg), _TRUNCATE,
                "packer_verify_call_result ok=%d packed=%d version=%d sections=%u imports=%u strings=%u resources=%u aux=%d aux_off=0x%X aux_size=%u aux_err=%u sec_rva=0x%X sec_size=0x%X scan=0x%X hdr_off=0x%X phase=0x%X stolen=%u dseal=%d dthunk=%d disk=%d verifier_main=%d stage=%u gle=%u exc=0x%X live_mz=0x%X live_lfanew=0x%X live_nt=0x%X live_secs=%u live_img=0x%X live_scanned=%u disk_mz=0x%X disk_lfanew=0x%X disk_nt=0x%X disk_secs=%u disk_img=0x%X disk_path_len=%u disk_path_hash=0x%llX disk_file=%llu disk_candidates=%u disk_scanned=%u last_sec=%u last_raw=0x%X last_raw_size=0x%X last_off=0x%X",
                packer_ok ? 1 : 0,
                packer_status.packed_found ? 1 : 0,
                packer_status.packed_version_ok ? 1 : 0,
                packer_status.section_count,
                packer_status.import_count,
                packer_status.string_fixup_count,
                packer_status.resource_fixup_count,
                packer_status.aux_found ? 1 : 0,
                packer_status.aux_offset,
                packer_status.aux_size,
                packer_status.aux_probe_error,
                packer_status.packed_section_rva,
                packer_status.packed_section_size,
                packer_status.header_scan_size,
                packer_status.packed_header_offset,
                packer_status.phase_flags,
                packer_status.stolen_block_count,
                packer_status.dseal_found ? 1 : 0,
                packer_status.dthunk_found ? 1 : 0,
                packer_status.disk_backed ? 1 : 0,
                packer_status.verifier_module_is_process_image ? 1 : 0,
                packer_status.failure_stage,
                packer_status.last_error,
                packer_status.exception_code,
                packer_status.live_dos_magic,
                packer_status.live_e_lfanew,
                packer_status.live_nt_signature,
                packer_status.live_section_count,
                packer_status.live_image_size,
                packer_status.live_sections_scanned,
                packer_status.disk_dos_magic,
                packer_status.disk_e_lfanew,
                packer_status.disk_nt_signature,
                packer_status.disk_section_count,
                packer_status.disk_image_size,
                packer_status.disk_path_len,
                static_cast<unsigned long long>(packer_status.disk_path_hash),
                static_cast<unsigned long long>(packer_status.disk_file_size),
                packer_status.disk_candidate_count,
                packer_status.disk_sections_scanned,
                packer_status.last_section_index,
                packer_status.last_raw_ptr,
                packer_status.last_raw_size,
                packer_status.last_scan_offset);
            webhook::write_log("init", dbg);
        }
        if (!packer_ok)
        {
            char dbg[2048];
            _snprintf_s(dbg, sizeof(dbg), _TRUNCATE,
                "packer_build_protection_required_failed packed=%d version=%d sections=%u imports=%u strings=%u resources=%u aux=%d aux_off=0x%X aux_size=%u aux_err=%u sec_rva=0x%X sec_size=0x%X scan=0x%X hdr_off=0x%X phase=0x%X stolen=%u dseal=%d dthunk=%d disk=%d verifier_main=%d stage=%u gle=%u exc=0x%X live_mz=0x%X live_lfanew=0x%X live_nt=0x%X live_secs=%u live_img=0x%X live_scanned=%u disk_mz=0x%X disk_lfanew=0x%X disk_nt=0x%X disk_secs=%u disk_img=0x%X disk_path_len=%u disk_path_hash=0x%llX disk_file=%llu disk_candidates=%u disk_scanned=%u last_sec=%u last_raw=0x%X last_raw_size=0x%X last_off=0x%X",
                packer_status.packed_found ? 1 : 0,
                packer_status.packed_version_ok ? 1 : 0,
                packer_status.section_count,
                packer_status.import_count,
                packer_status.string_fixup_count,
                packer_status.resource_fixup_count,
                packer_status.aux_found ? 1 : 0,
                packer_status.aux_offset,
                packer_status.aux_size,
                packer_status.aux_probe_error,
                packer_status.packed_section_rva,
                packer_status.packed_section_size,
                packer_status.header_scan_size,
                packer_status.packed_header_offset,
                packer_status.phase_flags,
                packer_status.stolen_block_count,
                packer_status.dseal_found ? 1 : 0,
                packer_status.dthunk_found ? 1 : 0,
                packer_status.disk_backed ? 1 : 0,
                packer_status.verifier_module_is_process_image ? 1 : 0,
                packer_status.failure_stage,
                packer_status.last_error,
                packer_status.exception_code,
                packer_status.live_dos_magic,
                packer_status.live_e_lfanew,
                packer_status.live_nt_signature,
                packer_status.live_section_count,
                packer_status.live_image_size,
                packer_status.live_sections_scanned,
                packer_status.disk_dos_magic,
                packer_status.disk_e_lfanew,
                packer_status.disk_nt_signature,
                packer_status.disk_section_count,
                packer_status.disk_image_size,
                packer_status.disk_path_len,
                static_cast<unsigned long long>(packer_status.disk_path_hash),
                static_cast<unsigned long long>(packer_status.disk_file_size),
                packer_status.disk_candidate_count,
                packer_status.disk_sections_scanned,
                packer_status.last_section_index,
                packer_status.last_raw_ptr,
                packer_status.last_raw_size,
                packer_status.last_scan_offset);
            webhook::send_debug_log("init", dbg, true);
            enforce_violation_id(aida::reason_ids::reason_id_unpack_timing_anomaly, dbg);
            return false;
        }
        char dbg[2048];
        _snprintf_s(dbg, sizeof(dbg), _TRUNCATE,
            "packer_build_protection_ok sections=%u imports=%u strings=%u resources=%u aux=%d aux_off=0x%X aux_size=%u sec_rva=0x%X sec_size=0x%X scan=0x%X hdr_off=0x%X phase=0x%X stolen=%u dseal=%d dthunk=%d disk=%d verifier_main=%d stage=%u gle=%u exc=0x%X live_secs=%u disk_secs=%u disk_candidates=%u disk_file=%llu",
            packer_status.section_count,
            packer_status.import_count,
            packer_status.string_fixup_count,
            packer_status.resource_fixup_count,
            packer_status.aux_found ? 1 : 0,
            packer_status.aux_offset,
            packer_status.aux_size,
            packer_status.packed_section_rva,
            packer_status.packed_section_size,
            packer_status.header_scan_size,
            packer_status.packed_header_offset,
            packer_status.phase_flags,
            packer_status.stolen_block_count,
            packer_status.dseal_found ? 1 : 0,
            packer_status.dthunk_found ? 1 : 0,
            packer_status.disk_backed ? 1 : 0,
            packer_status.verifier_module_is_process_image ? 1 : 0,
            packer_status.failure_stage,
            packer_status.last_error,
            packer_status.exception_code,
            packer_status.live_section_count,
            packer_status.disk_section_count,
            packer_status.disk_candidate_count,
            static_cast<unsigned long long>(packer_status.disk_file_size));
        webhook::write_log("init", dbg);
    }

    uint64_t nanomites_tick = GetTickCount64();
    webhook::write_log_critical_fmt("init",
        "nanomites_initialize_pre pid=%lu tid=%lu tick=%llu",
        GetCurrentProcessId(),
        GetCurrentThreadId(),
        static_cast<unsigned long long>(nanomites_tick));
    bool nanomites_ok = nanomites::initialize();
    webhook::write_log_critical_fmt("init",
        "nanomites_initialize_post ok=%d elapsed_ms=%llu refresher_running=%d refresher_degraded=%d refresher_error=%u",
        nanomites_ok ? 1 : 0,
        static_cast<unsigned long long>(GetTickCount64() - nanomites_tick),
        nanomites::refresher_running() ? 1 : 0,
        nanomites::refresher_degraded() ? 1 : 0,
        nanomites::refresher_start_error());
    if (!nanomites_ok)
    {
        webhook::send_debug_log("init", "nanomites_initialize_failed", true);
        enforce_violation_id(aida::reason_ids::reason_id_nanomite_table_tamper, "nanomites_initialize_failed");
        return false;
    }
    {
        char dbg[192];
        _snprintf_s(dbg, sizeof(dbg), _TRUNCATE,
            "nanomites_ok refresher_running=%d refresher_degraded=%d refresher_error=%u",
            nanomites::refresher_running() ? 1 : 0,
            nanomites::refresher_degraded() ? 1 : 0,
            nanomites::refresher_start_error());
        webhook::write_log("init", dbg);
    }

    uint64_t binary_protocol_tick = GetTickCount64();
    webhook::write_log_critical_fmt("init",
        "binary_protocol_initialize_pre pid=%lu tid=%lu tick=%llu",
        GetCurrentProcessId(),
        GetCurrentThreadId(),
        static_cast<unsigned long long>(binary_protocol_tick));
    bool binary_protocol_ok = binary_protocol::initialize_with_baked_pin();
    webhook::write_log_critical_fmt("init",
        "binary_protocol_initialize_post ok=%d elapsed_ms=%llu",
        binary_protocol_ok ? 1 : 0,
        static_cast<unsigned long long>(GetTickCount64() - binary_protocol_tick));
    if (binary_protocol_ok)
        webhook::write_log("init", "binary_protocol_pin_ok");
    else
    {
        webhook::write_log("init", "binary_protocol_pin_fail");
        enforce_violation_id(aida::reason_ids::reason_id_from_string("binary_protocol_pin_fail"), "binary_protocol_pin_fail");
        return false;
    }

    uint64_t server_pages_tick = GetTickCount64();
    webhook::write_log_critical_fmt("init",
        "server_pages_initialize_pre pid=%lu tid=%lu tick=%llu",
        GetCurrentProcessId(),
        GetCurrentThreadId(),
        static_cast<unsigned long long>(server_pages_tick));
    server_pages::initialize();
    webhook::write_log_critical_fmt("init",
        "server_pages_initialize_post elapsed_ms=%llu",
        static_cast<unsigned long long>(GetTickCount64() - server_pages_tick));
    webhook::write_log("init", "server_pages_ok");

#if defined(AIDA_DEEP_STEAL)
    if (stolen_bytes::initialize())
    {
        webhook::write_log("init", "stolen_bytes_init_ok");
        if (stolen_bytes::initialize_basic_blocks())
        {
            webhook::write_log("init", "stolen_bb_init_ok");
            uint32_t stolen = stolen_bytes::auto_steal_from_self(8);
            char dbg[64];
            _snprintf_s(dbg, sizeof(dbg), _TRUNCATE, "deep_steal_count=%u", stolen);
            webhook::write_log("init", dbg);
        }
        else
        {
            webhook::write_log("init", "stolen_bb_init_fail");
        }
    }
    else
    {
        webhook::write_log("init", "stolen_bytes_init_fail");
    }
#endif

    if (driver_bridge::is_loaded() && driver_bridge::using_kernel_driver())
    {
        if (!ensure_driver_hardening("initialize"))
            return false;
    }
    else
    {
        webhook::write_log("init", "driver_bridge_skipped");
    }

    webhook::write_log_critical_fmt("init",
        "hide_thread_pre pid=%lu tid=%lu",
        GetCurrentProcessId(),
        GetCurrentThreadId());
    anti_debug::hide_thread_from_debugger(GetCurrentThread());
    webhook::write_log_critical("init", "hide_thread_post");
    webhook::write_log("init", "hide_thread_ok");

    webhook::write_log_critical("init", "tpm_attest_state_pre");
    if (anti_tamper::tpm_attest::is_available())
    {
        anti_tamper::tpm_attest::ensure_counter_defined(anti_tamper::tpm_attest::TPM_NV_INDEX_AIDA_COUNTER);
        webhook::write_log("init", "tpm_attest_ready");
    }
    else
    {
        webhook::write_log("init", anti_tamper::tpm_attest::last_error());
    }

    {
        uint64_t resnap_tick = GetTickCount64();
        webhook::write_log_critical_fmt("init",
            "code_snapshot_resnap_pre_periodic_start pid=%lu tid=%lu tick=%llu prior_base=0x%llX prior_size=0x%X prior_hash=0x%016llX",
            GetCurrentProcessId(),
            GetCurrentThreadId(),
            static_cast<unsigned long long>(resnap_tick),
            static_cast<unsigned long long>(rt.code_snap.text_base),
            rt.code_snap.text_size,
            static_cast<unsigned long long>(rt.code_snap.text_hash));
        bool resnap_ok = integrity::snapshot_code(rt.code_snap);
        webhook::write_log_critical_fmt("init",
            "code_snapshot_resnap_snapshot_post ok=%d elapsed_ms=%llu base=0x%llX size=0x%X hash=0x%016llX",
            resnap_ok ? 1 : 0,
            static_cast<unsigned long long>(GetTickCount64() - resnap_tick),
            static_cast<unsigned long long>(rt.code_snap.text_base),
            rt.code_snap.text_size,
            static_cast<unsigned long long>(rt.code_snap.text_hash));
        if (resnap_ok) {
            uint64_t resnap_chain_tick = GetTickCount64();
            bool resnap_chain_ok = integrity::build_block_chain(rt.code_snap, rt.block_chain);
            webhook::write_log_critical_fmt("init",
                "code_snapshot_resnap_block_chain_post ok=%d blocks=%zu elapsed_ms=%llu total_elapsed_ms=%llu",
                resnap_chain_ok ? 1 : 0,
                rt.block_chain.size(),
                static_cast<unsigned long long>(GetTickCount64() - resnap_chain_tick),
                static_cast<unsigned long long>(GetTickCount64() - resnap_tick));
            if (!resnap_chain_ok)
            {
                webhook::write_log_critical("init", "code_snapshot_resnap_block_chain_FAILED");
                enforce_violation_id(aida::reason_ids::reason_id_from_string("code_snapshot_resnap_block_chain_failed"), "code_snapshot_resnap_block_chain_failed");
                return false;
            }
            webhook::write_log("init", "code_snapshot_resnap_ok");
        } else {
            webhook::write_log_critical("init", "code_snapshot_resnap_FAILED");
            enforce_violation_id(aida::reason_ids::reason_id_from_string("code_snapshot_resnap_failed"), "code_snapshot_resnap_failed");
            return false;
        }
    }

    uint64_t periodic_tick = GetTickCount64();
    webhook::write_log_critical_fmt("init",
        "periodic_integrity_start_pre pid=%lu tid=%lu tick=%llu",
        GetCurrentProcessId(),
        GetCurrentThreadId(),
        static_cast<unsigned long long>(periodic_tick));
    bool periodic_started = integrity::periodic::start();
    webhook::write_log_critical_fmt("init",
        "periodic_integrity_start_post ok=%d elapsed_ms=%llu",
        periodic_started ? 1 : 0,
        static_cast<unsigned long long>(GetTickCount64() - periodic_tick));
    if (!periodic_started)
    {
        webhook::write_log_critical("init", "periodic_integrity_start_degraded");
        uint32_t mismatch_page = 0;
        bool eager_ok = integrity::verify_full_text_eager(&mismatch_page);
        integrity::block_chain_verify_result_t bc_detail{};
        bool block_ok = integrity::verify_block_chain(rt.code_snap, rt.block_chain, &bc_detail);
        if (!eager_ok)
        {
            char detail[160];
            _snprintf_s(detail, sizeof(detail), _TRUNCATE,
                "periodic_start_degraded_eager_mismatch page=%u",
                mismatch_page);
            webhook::send_debug_log("init", detail, true);
            enforce_violation_id(aida::reason_ids::reason_id_page_mac_periodic_mismatch, detail);
            return false;
        }
        if (!block_ok)
        {
            char detail[256];
            _snprintf_s(detail, sizeof(detail), _TRUNCATE,
                "periodic_start_degraded_block_chain_fail idx=%u/%u base=0x%llX size=%u expected=0x%llX actual=0x%llX prev=0x%llX layout=%u",
                bc_detail.block_index,
                bc_detail.chain_count,
                static_cast<unsigned long long>(bc_detail.block_base),
                bc_detail.block_size,
                static_cast<unsigned long long>(bc_detail.expected_hash),
                static_cast<unsigned long long>(bc_detail.actual_hash),
                static_cast<unsigned long long>(bc_detail.prev_hash),
                bc_detail.layout_mismatch ? 1u : 0u);
            webhook::send_debug_log("init", detail, true);
            enforce_violation_id(aida::reason_ids::reason_id_block_chain_runtime, detail);
            return false;
        }
        integrity::clear_periodic_violation_flag();
        webhook::write_log_critical("init", "periodic_integrity_degraded_verified");
    }
    else
    {
        webhook::write_log("init", "periodic_integrity_started");
    }

    try
    {
        uint64_t monitors_tick = GetTickCount64();
        webhook::write_log_critical_fmt("init",
            "start_monitors_entering pid=%lu tid=%lu tick=%llu",
            GetCurrentProcessId(),
            GetCurrentThreadId(),
            static_cast<unsigned long long>(monitors_tick));
        bool monitors_ok = start_monitors();
        webhook::write_log_critical_fmt("init",
            "start_monitors_post ok=%d elapsed_ms=%llu monitors_running=%d watchdog_running=%d",
            monitors_ok ? 1 : 0,
            static_cast<unsigned long long>(GetTickCount64() - monitors_tick),
            rt.monitors_running.load(std::memory_order_acquire) ? 1 : 0,
            rt.watchdog_running.load(std::memory_order_acquire) ? 1 : 0);
        if (!monitors_ok)
        {
            webhook::write_log_critical("init", "start_monitors_degraded");
            if (!verify_integrity_clean_after_worker_degrade("start_monitors"))
                return false;
            webhook::write_log_critical("init", "start_monitors_degraded_verified");
        }
        else
        {
            webhook::write_log("init", "monitors_started_ok");
        }
    }
    catch (const std::exception& ex)
    {
        webhook::write_log("init", (std::string("start_monitors_exception: ") + ex.what()).c_str());
        if (!verify_integrity_clean_after_worker_degrade("start_monitors_exception"))
            return false;
        webhook::write_log_critical("init", "start_monitors_exception_degraded_verified");
    }
    catch (...)
    {
        webhook::write_log("init", "start_monitors_unknown_exception");
        if (!verify_integrity_clean_after_worker_degrade("start_monitors_unknown_exception"))
            return false;
        webhook::write_log_critical("init", "start_monitors_unknown_exception_degraded_verified");
    }

    try
    {
        uint64_t re_detect_tick = GetTickCount64();
        webhook::write_log_critical_fmt("init",
            "re_detect_entering pid=%lu tid=%lu tick=%llu",
            GetCurrentProcessId(),
            GetCurrentThreadId(),
            static_cast<unsigned long long>(re_detect_tick));
        re_detect::initialize();
        webhook::write_log_critical_fmt("init",
            "re_detect_initialize_post elapsed_ms=%llu",
            static_cast<unsigned long long>(GetTickCount64() - re_detect_tick));
        webhook::write_log("init", "re_detect_engine_ok");
    }
    catch (const std::exception& ex)
    {
        webhook::write_log("init", (std::string("re_detect_exception: ") + ex.what()).c_str());
        enforce_violation_id(aida::reason_ids::reason_id_re_detected, ex.what());
        return false;
    }
    catch (...)
    {
        webhook::write_log("init", "re_detect_unknown_exception");
        enforce_violation_id(aida::reason_ids::reason_id_re_detected, "re_detect_unknown_exception");
        return false;
    }


    webhook::write_log_critical("init", "initialized_store_pre");
    rt.initialized.store(true, std::memory_order_release);
    webhook::write_log_critical("init", "initialized_store_post");
    webhook::write_log("init", "initialized_ok");

    webhook::write_log("init", "deferred_anti_dump_until_arc_loaded");

    return true;
}

__declspec(noinline) static bool finalize_call_anti_dump_init_cpp()
{
    try { return anti_dump::initialize(); }
    catch (const std::exception& ex) {
        webhook::write_log_critical_fmt("init",
            "anti_dump_init_cpp_exception what=%.160s", ex.what());
    }
    catch (...) {
        webhook::write_log_critical("init", "anti_dump_init_unknown_cpp_exception");
    }
    return false;
}

__declspec(noinline) static int finalize_anti_dump_init_exception_filter(EXCEPTION_POINTERS* ep)
{
    const DWORD code = (ep && ep->ExceptionRecord) ? ep->ExceptionRecord->ExceptionCode : 0;
    if (code == STATUS_SINGLE_STEP)
    {
        const bool consumed = anti_dump::read_intercept::consume_pending_single_step(ep, "anti_dump_init_seh");
        if (ep && ep->ContextRecord)
            ep->ContextRecord->EFlags &= ~0x100u;
        webhook::write_log_critical_fmt("init",
            "anti_dump_init_SEH_single_step_continued consumed=%d addr=0x%016llX rip=0x%016llX tid=%lu",
            consumed ? 1 : 0,
            static_cast<unsigned long long>((ep && ep->ExceptionRecord) ? reinterpret_cast<uintptr_t>(ep->ExceptionRecord->ExceptionAddress) : 0),
            static_cast<unsigned long long>((ep && ep->ContextRecord) ? ep->ContextRecord->Rip : 0),
            GetCurrentThreadId());
        return EXCEPTION_CONTINUE_EXECUTION;
    }
    webhook::write_log_critical_fmt("init",
        "anti_dump_init_SEH code=0x%08X addr=0x%016llX rip=0x%016llX tid=%lu",
        code,
        static_cast<unsigned long long>((ep && ep->ExceptionRecord) ? reinterpret_cast<uintptr_t>(ep->ExceptionRecord->ExceptionAddress) : 0),
        static_cast<unsigned long long>((ep && ep->ContextRecord) ? ep->ContextRecord->Rip : 0),
        GetCurrentThreadId());
    return EXCEPTION_EXECUTE_HANDLER;
}

__declspec(noinline) static bool finalize_call_anti_dump_init_seh()
{
    bool ok = false;
    __try { ok = finalize_call_anti_dump_init_cpp(); }
    __except (finalize_anti_dump_init_exception_filter(GetExceptionInformation())) {
        ok = false;
    }
    return ok;
}

__declspec(noinline) static bool finalize_call_standalone_anti_dump_init_cpp()
{
    try { return standalone_anti_dump::initialize(); }
    catch (const std::exception& ex) {
        webhook::write_log_critical_fmt("init",
            "standalone_anti_dump_init_cpp_exception what=%.160s", ex.what());
    }
    catch (...) {
        webhook::write_log_critical("init", "standalone_anti_dump_init_unknown_cpp_exception");
    }
    return false;
}

__declspec(noinline) static bool finalize_call_standalone_anti_dump_init_seh()
{
    bool ok = false;
    __try { ok = finalize_call_standalone_anti_dump_init_cpp(); }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        webhook::write_log_critical_fmt("init",
            "standalone_anti_dump_init_SEH code=0x%08X", GetExceptionCode());
        ok = false;
    }
    return ok;
}

__declspec(noinline) static bool finalize_call_anti_dump_seal_seh()
{
    bool ok = true;
    __try { anti_dump::seal_handles(); }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        webhook::write_log_critical_fmt("init",
            "anti_dump_seal_SEH code=0x%08X", GetExceptionCode());
        ok = false;
    }
    return ok;
}

__declspec(noinline) static bool finalize_call_standalone_anti_dump_seal_seh()
{
    bool ok = true;
    __try { standalone_anti_dump::seal_handles(); }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        webhook::write_log_critical_fmt("init",
            "standalone_anti_dump_seal_SEH code=0x%08X", GetExceptionCode());
        ok = false;
    }
    return ok;
}

inline bool finalize_thread_creation_probe(const char* phase)
{
    struct probe_state_t
    {
        HANDLE event_handle = nullptr;
        std::atomic<bool> ran{false};
        ~probe_state_t()
        {
            if (event_handle)
                CloseHandle(event_handle);
        }
    };

    std::shared_ptr<probe_state_t> state;
    try
    {
        state = std::make_shared<probe_state_t>();
    }
    catch (const std::exception& ex)
    {
        webhook::write_log_critical_fmt("init",
            "%s_worker_probe_alloc_exception what=%.160s", phase, ex.what());
        return false;
    }
    catch (...)
    {
        webhook::write_log_critical_fmt("init", "%s_worker_probe_alloc_unknown_exception", phase);
        return false;
    }
    state->event_handle = CreateEventW(nullptr, TRUE, FALSE, nullptr);
    if (!state->event_handle)
    {
        webhook::write_log_critical_fmt("init", "%s_worker_probe_event_fail err=%lu", phase, GetLastError());
        return false;
    }

    bool posted = false;
    try
    {
        posted = work_queue::post([state]() {
                state->ran.store(true, std::memory_order_release);
                SetEvent(state->event_handle);
            });
    }
    catch (const std::exception& ex)
    {
        webhook::write_log_critical_fmt("init", "%s_worker_probe_post_exception what=%.160s", phase, ex.what());
        posted = false;
    }
    catch (...)
    {
        webhook::write_log_critical_fmt("init", "%s_worker_probe_post_unknown_exception", phase);
        posted = false;
    }

    if (!posted)
    {
        webhook::write_log_critical_fmt("init", "%s_worker_probe_post_fail", phase);
        return false;
    }

    DWORD wait_result = WaitForSingleObject(state->event_handle, 2000);
    bool ok = wait_result == WAIT_OBJECT_0 && state->ran.load(std::memory_order_acquire);
    webhook::write_log_critical_fmt("init", "%s_worker_probe_%s wait=0x%08lX",
        phase, ok ? "PASS" : "FAIL", wait_result);
    return ok;
}

inline bool verify_integrity_clean_after_worker_degrade(const char* phase)
{
    auto& rt = state::get();
    uint32_t mismatch_page = 0;
    bool eager_ok = integrity::verify_full_text_eager(&mismatch_page);
    integrity::block_chain_verify_result_t bc_detail{};
    bool block_ok = integrity::verify_block_chain(rt.code_snap, rt.block_chain, &bc_detail);
    webhook::write_log_critical_fmt("init",
        "%s_worker_degrade_integrity_check eager=%d page=%u block=%d idx=%u/%u layout=%u",
        phase,
        eager_ok ? 1 : 0,
        mismatch_page,
        block_ok ? 1 : 0,
        bc_detail.block_index,
        bc_detail.chain_count,
        bc_detail.layout_mismatch ? 1u : 0u);
    if (!eager_ok)
    {
        char detail[160];
        _snprintf_s(detail, sizeof(detail), _TRUNCATE,
            "%s_worker_degrade_eager_mismatch page=%u",
            phase,
            mismatch_page);
        webhook::send_debug_log("init", detail, true);
        enforce_violation_id(aida::reason_ids::reason_id_page_mac_periodic_mismatch, detail);
        return false;
    }
    if (!block_ok)
    {
        char detail[256];
        _snprintf_s(detail, sizeof(detail), _TRUNCATE,
            "%s_worker_degrade_block_chain_fail idx=%u/%u base=0x%llX size=%u expected=0x%llX actual=0x%llX prev=0x%llX layout=%u",
            phase,
            bc_detail.block_index,
            bc_detail.chain_count,
            static_cast<unsigned long long>(bc_detail.block_base),
            bc_detail.block_size,
            static_cast<unsigned long long>(bc_detail.expected_hash),
            static_cast<unsigned long long>(bc_detail.actual_hash),
            static_cast<unsigned long long>(bc_detail.prev_hash),
            bc_detail.layout_mismatch ? 1u : 0u);
        webhook::send_debug_log("init", detail, true);
        enforce_violation_id(aida::reason_ids::reason_id_block_chain_runtime, detail);
        return false;
    }
    integrity::clear_periodic_violation_flag();
    webhook::write_log_critical_fmt("init", "%s_worker_degrade_verified_clean", phase);
    return true;
}

__declspec(noinline) static bool finalize_call_kernel_anti_dump_seh(uint32_t self_pid)
{
    bool ok = false;
    uint64_t tick = GetTickCount64();
    webhook::write_log_critical_fmt("init",
        "kernel_anti_dump_full_pre pid=%u tid=%lu tick=%llu",
        self_pid,
        GetCurrentThreadId(),
        static_cast<unsigned long long>(tick));
    __try {
        SetLastError(ERROR_SUCCESS);
        ok = driver_bridge::kernel_anti_dump_full(self_pid);
        DWORD err = ok ? ERROR_SUCCESS : GetLastError();
        webhook::write_log_critical_fmt("init",
            "kernel_anti_dump_full_post ok=%d err=%lu elapsed_ms=%llu",
            ok ? 1 : 0,
            static_cast<unsigned long>(err),
            static_cast<unsigned long long>(GetTickCount64() - tick));
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        webhook::write_log_critical_fmt("init",
            "kernel_anti_dump_full_SEH code=0x%08X elapsed_ms=%llu",
            GetExceptionCode(),
            static_cast<unsigned long long>(GetTickCount64() - tick));
        ok = false;
    }
    return ok;
}

__declspec(noinline) static bool finalize_call_kernel_anti_dump_start_continuous_seh(uint32_t self_pid)
{
    bool ok = false;
    uint64_t tick = GetTickCount64();
    webhook::write_log_critical_fmt("init",
        "kernel_anti_dump_start_continuous_pre pid=%u tid=%lu tick=%llu",
        self_pid,
        GetCurrentThreadId(),
        static_cast<unsigned long long>(tick));
    __try {
        SetLastError(ERROR_SUCCESS);
        ok = driver_bridge::kernel_anti_dump_start_continuous(self_pid);
        DWORD err = ok ? ERROR_SUCCESS : GetLastError();
        webhook::write_log_critical_fmt("init",
            "kernel_anti_dump_start_continuous_result=%d pid=%u err=%lu elapsed_ms=%llu",
            ok ? 1 : 0,
            self_pid,
            static_cast<unsigned long>(err),
            static_cast<unsigned long long>(GetTickCount64() - tick));
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        webhook::write_log_critical_fmt("init",
            "kernel_anti_dump_start_continuous_SEH code=0x%08X elapsed_ms=%llu",
            GetExceptionCode(),
            static_cast<unsigned long long>(GetTickCount64() - tick));
        ok = false;
    }
    return ok;
}

__declspec(noinline) static bool finalize_call_hide_module_seh()
{
    bool ok = true;
    __try { anti_dump::hide_module(); }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        webhook::write_log_critical_fmt("init",
            "hide_module_SEH code=0x%08X", GetExceptionCode());
        ok = false;
    }
    return ok;
}

static bool finalize_post_resnap_inner()
{
    auto& rt = state::get();
    auto& pt = integrity::detail::page_table();

    {
        std::lock_guard<std::mutex> lk(pt.mtx);
        webhook::write_log_critical_fmt("init",
            "post_finalize_integrity_resnap_pre snapshot_base=0x%llX snapshot_size=0x%X snapshot_hash=0x%016llX module_base=0x%llX module_end=0x%llX block_count=%zu pt_base=0x%llX pt_size=0x%X pt_entries=%zu pt_epoch=%llu initialized=%d monitors=%d activation_done=%d",
            static_cast<unsigned long long>(rt.code_snap.text_base),
            rt.code_snap.text_size,
            static_cast<unsigned long long>(rt.code_snap.text_hash),
            static_cast<unsigned long long>(rt.code_snap.module_base),
            static_cast<unsigned long long>(rt.code_snap.module_end),
            rt.block_chain.size(),
            static_cast<unsigned long long>(pt.base),
            pt.size,
            pt.entries.size(),
            static_cast<unsigned long long>(pt.key_epoch.load(std::memory_order_acquire)),
            rt.initialized.load(std::memory_order_acquire) ? 1 : 0,
            rt.monitors_running.load(std::memory_order_acquire) ? 1 : 0,
            rt.activation_hardening_done.load(std::memory_order_acquire) ? 1 : 0);
    }

    if (rt.code_snap.text_base == 0 || rt.code_snap.text_size == 0)
    {
        webhook::write_log_critical("init",
            "post_finalize_integrity_resnap_missing_baseline_recover_enter");
        bool snapshot_ok = integrity::snapshot_code(rt.code_snap);
        bool chain_ok = snapshot_ok && integrity::build_block_chain(rt.code_snap, rt.block_chain);
        webhook::write_log_critical_fmt("init",
            "post_finalize_integrity_resnap_missing_baseline_recover_result snapshot=%d chain=%d base=0x%llX size=0x%X hash=0x%016llX module_base=0x%llX module_end=0x%llX blocks=%zu",
            snapshot_ok ? 1 : 0,
            chain_ok ? 1 : 0,
            static_cast<unsigned long long>(rt.code_snap.text_base),
            rt.code_snap.text_size,
            static_cast<unsigned long long>(rt.code_snap.text_hash),
            static_cast<unsigned long long>(rt.code_snap.module_base),
            static_cast<unsigned long long>(rt.code_snap.module_end),
            rt.block_chain.size());
        if (!snapshot_ok || !chain_ok)
            return false;
    }
    else if (rt.block_chain.empty())
    {
        bool chain_ok = integrity::build_block_chain(rt.code_snap, rt.block_chain);
        webhook::write_log_critical_fmt("init",
            "post_finalize_integrity_resnap_block_chain_recover_result chain=%d base=0x%llX size=0x%X hash=0x%016llX blocks=%zu",
            chain_ok ? 1 : 0,
            static_cast<unsigned long long>(rt.code_snap.text_base),
            rt.code_snap.text_size,
            static_cast<unsigned long long>(rt.code_snap.text_hash),
            rt.block_chain.size());
        if (!chain_ok)
            return false;
    }

    bool ok = false;
    size_t pages = 0;
    uint64_t old_base = 0;
    uint32_t old_size = 0;
    size_t old_entries = 0;
    uint64_t old_epoch = 0;
    uint64_t new_epoch = 0;
    {
        std::lock_guard<std::mutex> lk(pt.mtx);
        old_base = pt.base;
        old_size = pt.size;
        old_entries = pt.entries.size();
        old_epoch = pt.key_epoch.load(std::memory_order_acquire);
        ok = integrity::detail::rebuild_page_table_locked(
            pt, rt.code_snap.text_base, rt.code_snap.text_size);
        pages = pt.entries.size();
        new_epoch = pt.key_epoch.load(std::memory_order_acquire);
    }

    if (ok)
    {
        integrity::clear_periodic_violation_flag();
        webhook::write_log_critical_fmt("init",
            "post_finalize_integrity_resnap_ok old_base=0x%llX old_size=0x%X old_pages=%zu old_epoch=%llu base=0x%llX size=0x%X pages=%zu epoch=%llu hash=0x%016llX blocks=%zu module_base=0x%llX module_end=0x%llX",
            static_cast<unsigned long long>(old_base),
            old_size,
            old_entries,
            static_cast<unsigned long long>(old_epoch),
            static_cast<unsigned long long>(rt.code_snap.text_base),
            rt.code_snap.text_size,
            pages,
            static_cast<unsigned long long>(new_epoch),
            static_cast<unsigned long long>(rt.code_snap.text_hash),
            rt.block_chain.size(),
            static_cast<unsigned long long>(rt.code_snap.module_base),
            static_cast<unsigned long long>(rt.code_snap.module_end));
    }
    else
    {
        webhook::write_log_critical_fmt("init",
            "post_finalize_integrity_resnap_FAILED old_base=0x%llX old_size=0x%X old_pages=%zu old_epoch=%llu base=0x%llX size=0x%X hash=0x%016llX blocks=%zu",
            static_cast<unsigned long long>(old_base),
            old_size,
            old_entries,
            static_cast<unsigned long long>(old_epoch),
            static_cast<unsigned long long>(rt.code_snap.text_base),
            rt.code_snap.text_size,
            static_cast<unsigned long long>(rt.code_snap.text_hash),
            rt.block_chain.size());
    }
    return ok;
}

__declspec(noinline) static bool finalize_post_resnap_seh()
{
    bool ok = false;
    __try { ok = finalize_post_resnap_inner(); }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        webhook::write_log_critical_fmt("init",
            "post_finalize_integrity_resnap_SEH code=0x%08X",
            GetExceptionCode());
        ok = false;
    }
    return ok;
}

static bool finalize_ensure_integrity_baseline_inner(const char* phase)
{
    auto& rt = state::get();
    auto& pt = integrity::detail::page_table();

    {
        std::lock_guard<std::mutex> lk(pt.mtx);
        webhook::write_log_critical_fmt("init",
            "%s_integrity_baseline_pre snapshot_base=0x%llX snapshot_size=0x%X snapshot_hash=0x%016llX module_base=0x%llX module_end=0x%llX blocks=%zu pt_base=0x%llX pt_size=0x%X pt_entries=%zu pt_epoch=%llu initialized=%d monitors=%d",
            phase,
            static_cast<unsigned long long>(rt.code_snap.text_base),
            rt.code_snap.text_size,
            static_cast<unsigned long long>(rt.code_snap.text_hash),
            static_cast<unsigned long long>(rt.code_snap.module_base),
            static_cast<unsigned long long>(rt.code_snap.module_end),
            rt.block_chain.size(),
            static_cast<unsigned long long>(pt.base),
            pt.size,
            pt.entries.size(),
            static_cast<unsigned long long>(pt.key_epoch.load(std::memory_order_acquire)),
            rt.initialized.load(std::memory_order_acquire) ? 1 : 0,
            rt.monitors_running.load(std::memory_order_acquire) ? 1 : 0);
    }

    bool snapshot_ok = true;
    if (rt.code_snap.text_base == 0 || rt.code_snap.text_size == 0 || rt.code_snap.text_hash == 0)
        snapshot_ok = integrity::snapshot_code(rt.code_snap);

    bool chain_ok = snapshot_ok && !rt.block_chain.empty();
    if (snapshot_ok && !chain_ok)
        chain_ok = integrity::build_block_chain(rt.code_snap, rt.block_chain);

    size_t pages = 0;
    uint64_t pt_base = 0;
    uint32_t pt_size = 0;
    uint64_t pt_epoch = 0;
    {
        std::lock_guard<std::mutex> lk(pt.mtx);
        pages = pt.entries.size();
        pt_base = pt.base;
        pt_size = pt.size;
        pt_epoch = pt.key_epoch.load(std::memory_order_acquire);
    }

    webhook::write_log_critical_fmt("init",
        "%s_integrity_baseline_result snapshot=%d chain=%d snapshot_base=0x%llX snapshot_size=0x%X snapshot_hash=0x%016llX module_base=0x%llX module_end=0x%llX blocks=%zu pt_base=0x%llX pt_size=0x%X pt_entries=%zu pt_epoch=%llu",
        phase,
        snapshot_ok ? 1 : 0,
        chain_ok ? 1 : 0,
        static_cast<unsigned long long>(rt.code_snap.text_base),
        rt.code_snap.text_size,
        static_cast<unsigned long long>(rt.code_snap.text_hash),
        static_cast<unsigned long long>(rt.code_snap.module_base),
        static_cast<unsigned long long>(rt.code_snap.module_end),
        rt.block_chain.size(),
        static_cast<unsigned long long>(pt_base),
        pt_size,
        pages,
        static_cast<unsigned long long>(pt_epoch));

    return snapshot_ok && chain_ok &&
        rt.code_snap.text_base != 0 &&
        rt.code_snap.text_size != 0 &&
        rt.code_snap.text_hash != 0;
}

__declspec(noinline) static bool finalize_ensure_integrity_baseline_seh(const char* phase)
{
    bool ok = false;
    __try { ok = finalize_ensure_integrity_baseline_inner(phase); }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        webhook::write_log_critical_fmt("init",
            "%s_integrity_baseline_SEH code=0x%08X",
            phase,
            GetExceptionCode());
        ok = false;
    }
    return ok;
}

inline bool finalize_after_activation()
{
    auto& rt = state::get();
    if (rt.activation_hardening_done.load(std::memory_order_acquire))
    {
        webhook::write_log_critical("init", "finalize_after_activation_already_done");
        return true;
    }

    webhook::write_log_critical("init", "finalize_after_activation_entering");
    auto loader_header_snapshot = aida::runtime::loader_header_invariant::capture("finalize_after_activation_entering", "init");

    {
        std::string missing_exports;
        if (!standalone_license::validate_arc_required_exports(missing_exports))
        {
            webhook::send_debug_log("init", "arc_required_exports_missing: " + missing_exports, true);
            enforce_violation_id(aida::reason_ids::reason_id_arc_required, missing_exports);
            return false;
        }
        webhook::write_log_critical("init", "arc_required_exports_ok");
    }

    if (!finalize_ensure_integrity_baseline_seh("pre_anti_dump"))
    {
        webhook::write_log_critical("init", "pre_anti_dump_integrity_baseline_failed");
        enforce_violation_id(aida::reason_ids::reason_id_from_string("pre_anti_dump_integrity_baseline_failed"), "pre_anti_dump_integrity_baseline_failed");
        return false;
    }

    try
    {
        webhook::write_log_critical("init", "anti_dump_entering");
        if (!finalize_call_anti_dump_init_seh())
        {
            webhook::write_log_critical("init", "anti_dump_init_failed");
            enforce_violation_id(aida::reason_ids::reason_id_from_string("anti_dump_init_failed"), "anti_dump_init_failed");
            return false;
        }
        aida::runtime::loader_header_invariant::ensure("post_anti_dump_init", "init");
        webhook::write_log_critical("init", "anti_dump_ok");
    }
    catch (const std::exception& ex)
    {
        webhook::write_log_critical("init", (std::string("anti_dump_exception: ") + ex.what()).c_str());
        enforce_violation_id(aida::reason_ids::reason_id_from_string("anti_dump_init_exception"), ex.what());
        return false;
    }
    catch (...)
    {
        webhook::write_log_critical("init", "anti_dump_unknown_exception");
        enforce_violation_id(aida::reason_ids::reason_id_from_string("anti_dump_init_exception"), "unknown");
        return false;
    }

    try
    {
        webhook::write_log_critical("init", "standalone_anti_dump_entering");
        if (!finalize_call_standalone_anti_dump_init_seh())
        {
            webhook::write_log_critical("init", "standalone_anti_dump_init_failed");
            enforce_violation_id(aida::reason_ids::reason_id_from_string("standalone_anti_dump_init_failed"), "standalone_anti_dump_init_failed");
            return false;
        }
        aida::runtime::loader_header_invariant::ensure("post_standalone_anti_dump_init", "init");
        webhook::write_log_critical("init", "standalone_anti_dump_ok");
    }
    catch (const std::exception& ex)
    {
        webhook::write_log_critical("init", (std::string("standalone_anti_dump_exception: ") + ex.what()).c_str());
        enforce_violation_id(aida::reason_ids::reason_id_from_string("standalone_anti_dump_init_exception"), ex.what());
        return false;
    }
    catch (...)
    {
        webhook::write_log_critical("init", "standalone_anti_dump_unknown_exception");
        enforce_violation_id(aida::reason_ids::reason_id_from_string("standalone_anti_dump_init_exception"), "unknown");
        return false;
    }

    if (driver_bridge::is_loaded() && driver_bridge::using_kernel_driver())
    {
        uint32_t self_pid = GetCurrentProcessId();
        webhook::write_log_critical("init", "kernel_anti_dump_entering");
        if (!finalize_call_kernel_anti_dump_seh(self_pid))
        {
            webhook::write_log_critical("init", "kernel_anti_dump_failed");
            enforce_violation_id(aida::reason_ids::reason_id_from_string("kernel_anti_dump_failed"), "kernel_anti_dump_failed");
            return false;
        }
        aida::runtime::loader_header_invariant::ensure("post_kernel_anti_dump_full", "init");
        webhook::write_log_critical("init", "kernel_anti_dump_ok");

        webhook::write_log_critical("init", "kernel_anti_dump_start_continuous_entering");
        if (!finalize_call_kernel_anti_dump_start_continuous_seh(self_pid))
        {
            webhook::write_log_critical("init", "kernel_anti_dump_start_continuous_failed");
            enforce_violation_id(aida::reason_ids::reason_id_from_string("kernel_anti_dump_start_continuous_failed"), "kernel_anti_dump_start_continuous_failed");
            return false;
        }
        aida::runtime::loader_header_invariant::ensure("post_kernel_anti_dump_continuous", "init");
        webhook::write_log_critical("init", "kernel_anti_dump_start_continuous_ok");
    }

    bool seal_worker_usable = finalize_thread_creation_probe("pre_seal");
    if (seal_worker_usable)
    {
        webhook::write_log_critical("init", "anti_dump_seal_handles_entering");
        if (!finalize_call_anti_dump_seal_seh())
        {
            webhook::write_log_critical("init", "anti_dump_seal_handles_failed");
            enforce_violation_id(aida::reason_ids::reason_id_from_string("anti_dump_seal_failed"), "anti_dump_seal_failed");
            return false;
        }
        if (!finalize_thread_creation_probe("post_anti_dump_seal"))
        {
            webhook::write_log_critical("init", "post_anti_dump_seal_worker_degraded");
            if (!verify_integrity_clean_after_worker_degrade("post_anti_dump_seal"))
                return false;
            seal_worker_usable = false;
        }
        webhook::write_log_critical("init", "seal_handles_ok");

        if (seal_worker_usable)
        {
            webhook::write_log_critical("init", "standalone_anti_dump_seal_handles_entering");
            if (!finalize_call_standalone_anti_dump_seal_seh())
            {
                webhook::write_log_critical("init", "standalone_anti_dump_seal_handles_failed");
                enforce_violation_id(aida::reason_ids::reason_id_from_string("standalone_anti_dump_seal_failed"), "standalone_anti_dump_seal_failed");
                return false;
            }
            if (!finalize_thread_creation_probe("post_standalone_seal"))
            {
                webhook::write_log_critical("init", "post_standalone_seal_worker_degraded");
                if (!verify_integrity_clean_after_worker_degrade("post_standalone_seal"))
                    return false;
                seal_worker_usable = false;
            }
            webhook::write_log_critical("init", "standalone_seal_handles_ok");
        }
    }
    else
    {
        webhook::write_log_critical("init", "seal_handles_degraded_worker_queue_unavailable");
        if (!verify_integrity_clean_after_worker_degrade("pre_seal"))
            return false;
    }


    if (seal_worker_usable && !finalize_thread_creation_probe("post_seal_worker"))
    {
        webhook::write_log_critical("init", "post_seal_worker_degraded");
        if (!verify_integrity_clean_after_worker_degrade("post_seal_worker"))
            return false;
        seal_worker_usable = false;
    }

    if (!seal_worker_usable)
        webhook::write_log_critical("init", "seal_worker_probes_degraded_verified");

    webhook::write_log_critical("init", "hide_module_entering");
    if (!finalize_call_hide_module_seh())
    {
        webhook::write_log_critical("init", "hide_module_failed");
        enforce_violation_id(aida::reason_ids::reason_id_from_string("hide_module_failed"), "hide_module_failed");
        return false;
    }
    webhook::write_log_critical("init", "hide_peb_ok");
    aida::runtime::loader_header_invariant::ensure("post_hide_module", "init");

    webhook::write_log_critical("init", "post_finalize_integrity_resnap_entering");
    if (!finalize_post_resnap_seh())
    {
        webhook::write_log_critical("init", "post_finalize_integrity_resnap_failed");
        enforce_violation_id(aida::reason_ids::reason_id_from_string("post_finalize_integrity_resnap_failed"), "post_finalize_integrity_resnap_failed");
        return false;
    }

    rt.activation_hardening_done.store(true, std::memory_order_release);
    aida::runtime::loader_header_invariant::ensure("finalize_after_activation_done", "init");
    (void)loader_header_snapshot;
    webhook::write_log_critical("init", "finalize_after_activation_done");
    return true;
}

inline bool guard()
{
    static bool s_first_guard = true;
    if (s_first_guard) {
        webhook::write_log("guard", "first_guard_entry");
        s_first_guard = false;
    }

    auto& rt = state::get();

    CFF_BEGIN(guard_cff)
    CFF_STATE(guard_cff, 0)
    {
        if (rt.violation_latched.load(std::memory_order_acquire))
        {
            CFF_EXIT(guard_cff);
        }
        if (ghost_veh::is_active() && !ghost_veh::verify_detour())
        {
            webhook::send_debug_log("guard", "ghost_veh_unhooked", true);
            enforce_violation_id(aida::reason_ids::reason_id_ghost_veh_unhooked, "");
            CFF_EXIT(guard_cff);
        }
        CFF_GOTO(guard_cff, 1);
    }
    CFF_STATE(guard_cff, 1)
    {
        bool chain_stale = token_chain::is_chain_stale();
        if (chain_stale)
        {
            webhook::send_debug_log("guard", "chain_stale", true);
            enforce_violation_id(aida::reason_ids::reason_id_integrity_chain_stale);
            CFF_EXIT(guard_cff);
        }
        CFF_GOTO(guard_cff, 2);
    }
    CFF_STATE(guard_cff, 2)
    {
        bool unpack_ok = packer::verify_unpack_timing();
        if (!unpack_ok)
        {
            webhook::send_debug_log("guard", "unpack_timing_anomaly", true);
            enforce_violation_id(aida::reason_ids::reason_id_unpack_timing_anomaly);
            CFF_EXIT(guard_cff);
        }
        CFF_GOTO(guard_cff, 3);
    }
    CFF_STATE(guard_cff, 3)
    {
        DECOY_CALL_INTEGRATED(g3);
        auto dbg = anti_debug::full_scan(rt.code_snap.module_base, rt.code_snap.module_end);
        if (dbg.any_detected())
        {
            webhook::send_debug_log("guard", "debugger_detected: " + dbg.summary, true);
            enforce_violation_id(aida::reason_ids::reason_id_debugger_runtime, dbg.summary);
            CFF_EXIT(guard_cff);
        }
        if (!enforce_ai_tool_posture("runtime", true))
        {
            CFF_EXIT(guard_cff);
        }
        CFF_GOTO(guard_cff, 4);
    }
    CFF_STATE(guard_cff, 4)
    {
        uint64_t anti_hook_tick = GetTickCount64();
        webhook::write_log_critical_fmt("guard",
            "anti_hook_runtime_pre verify_counter=%u iat_entries=%zu full_test=%u",
            rt.verify_counter,
            rt.iat_snap.size(),
            rt.full_test_running.load(std::memory_order_acquire) ? 1u : 0u);
        auto hook = anti_hook::full_scan(rt.iat_snap);
        webhook::write_log_critical_fmt("guard",
            "anti_hook_runtime_post detected=%d elapsed_ms=%llu iat=%d ntdll=%d k32=%d syscall=%d eat=%d prologue=%d disk=%d veh=%d dr=%d redir=%d summary=%s",
            hook.any_detected() ? 1 : 0,
            static_cast<unsigned long long>(GetTickCount64() - anti_hook_tick),
            hook.iat_modified ? 1 : 0,
            hook.ntdll_inline_hooked ? 1 : 0,
            hook.kernel32_inline_hooked ? 1 : 0,
            hook.syscall_stubs_modified ? 1 : 0,
            hook.eat_hooked ? 1 : 0,
            hook.prologue_hash_mismatch ? 1 : 0,
            hook.disk_image_mismatch ? 1 : 0,
            hook.veh_chain_tampered ? 1 : 0,
            hook.dr_in_text_range ? 1 : 0,
            hook.dispatch_table_redirected ? 1 : 0,
            hook.summary.c_str());
        if (hook.any_detected())
        {
            const bool syscall_only =
                hook.syscall_stubs_modified &&
                !hook.iat_modified &&
                !hook.ntdll_inline_hooked &&
                !hook.kernel32_inline_hooked &&
                !hook.eat_hooked &&
                !hook.prologue_hash_mismatch &&
                !hook.disk_image_mismatch &&
                !hook.veh_chain_tampered &&
                !hook.dr_in_text_range &&
                !hook.dispatch_table_redirected;
            if (rt.full_test_running.load(std::memory_order_acquire) && syscall_only)
            {
                webhook::write_log_critical_fmt("guard",
                    "anti_hook_runtime_full_test_syscall_only_observed iat=%d ntdll=%d k32=%d syscall=%d eat=%d prologue=%d disk=%d veh=%d dr=%d redir=%d summary=%s",
                    hook.iat_modified ? 1 : 0,
                    hook.ntdll_inline_hooked ? 1 : 0,
                    hook.kernel32_inline_hooked ? 1 : 0,
                    hook.syscall_stubs_modified ? 1 : 0,
                    hook.eat_hooked ? 1 : 0,
                    hook.prologue_hash_mismatch ? 1 : 0,
                    hook.disk_image_mismatch ? 1 : 0,
                    hook.veh_chain_tampered ? 1 : 0,
                    hook.dr_in_text_range ? 1 : 0,
                    hook.dispatch_table_redirected ? 1 : 0,
                    hook.summary.c_str());
                CFF_GOTO(guard_cff, 5);
            }
            webhook::send_debug_log("guard", "hook_detected: " + hook.summary, true);
            enforce_violation_id(aida::reason_ids::reason_id_hook_runtime, hook.summary);
            CFF_EXIT(guard_cff);
        }
        CFF_GOTO(guard_cff, 5);
    }
    CFF_STATE(guard_cff, 5)
    {
        DECOY_CRYPTO_INTEGRATED(g5);
        bool self_hash_ok = integrity::verify_self_hash();
        if (!self_hash_ok)
        {
            webhook::send_debug_log("guard", "code_integrity_fail", true);
            enforce_violation_id(aida::reason_ids::reason_id_code_integrity_runtime);
            CFF_EXIT(guard_cff);
        }
        if (integrity::periodic_violation_latched())
        {
            static std::atomic<uint32_t> s_periodic_consecutive_fail_count{0};
            static std::atomic<uint64_t> s_periodic_first_fail_qpc{0};
            constexpr uint32_t kRequiredConsecutiveFailures = 3;

            uint64_t epoch_at_attempt1 = integrity::detail::page_table().key_epoch.load(std::memory_order_acquire);
            uint64_t pt_size_at_attempt1 = static_cast<uint64_t>(integrity::detail::page_table().size);
            size_t entries_at_attempt1 = integrity::detail::page_table().entries.size();
            uint64_t last_rot_at_attempt1 = integrity::detail::page_table().last_rotation_qpc.load(std::memory_order_acquire);
            uint64_t now_ms = static_cast<uint64_t>(GetTickCount64());
            uint64_t ms_since_last_rotation = (now_ms >= last_rot_at_attempt1)
                ? (now_ms - last_rot_at_attempt1) : 0;

            webhook::write_log_critical_fmt("guard",
                "periodic_violation_attempt1_eager_verify_pre epoch=%llu pt_size=0x%llX entries=%zu ms_since_rotation=%llu",
                static_cast<unsigned long long>(epoch_at_attempt1),
                static_cast<unsigned long long>(pt_size_at_attempt1),
                entries_at_attempt1,
                static_cast<unsigned long long>(ms_since_last_rotation));

            uint32_t mismatch_page1 = 0;
            bool attempt1_ok = integrity::verify_full_text_eager(&mismatch_page1);
            webhook::write_log_critical_fmt("guard",
                "periodic_violation_attempt1_result ok=%d epoch=%llu page=%u",
                attempt1_ok ? 1 : 0,
                static_cast<unsigned long long>(epoch_at_attempt1),
                mismatch_page1);
            if (attempt1_ok)
            {
                webhook::write_log_critical("guard", "periodic_violation_FALSE_POSITIVE_cleared");
                s_periodic_consecutive_fail_count.store(0, std::memory_order_release);
                s_periodic_first_fail_qpc.store(0, std::memory_order_release);
                integrity::clear_periodic_violation_flag();
                CFF_GOTO(guard_cff, 6);
            }
            Sleep(250);
            uint64_t epoch_at_attempt2 = integrity::detail::page_table().key_epoch.load(std::memory_order_acquire);
            uint32_t mismatch_page2 = 0;
            bool attempt2_ok = integrity::verify_full_text_eager(&mismatch_page2);
            webhook::write_log_critical_fmt("guard",
                "periodic_violation_attempt2_result ok=%d epoch1=%llu epoch2=%llu page=%u",
                attempt2_ok ? 1 : 0,
                static_cast<unsigned long long>(epoch_at_attempt1),
                static_cast<unsigned long long>(epoch_at_attempt2),
                mismatch_page2);
            if (attempt2_ok && epoch_at_attempt1 != epoch_at_attempt2)
            {
                webhook::write_log_critical("guard", "periodic_violation_FALSE_POSITIVE_rotation_race_cleared");
                s_periodic_consecutive_fail_count.store(0, std::memory_order_release);
                s_periodic_first_fail_qpc.store(0, std::memory_order_release);
                integrity::clear_periodic_violation_flag();
                CFF_GOTO(guard_cff, 6);
            }
            if (attempt2_ok)
            {
                webhook::write_log_critical("guard", "periodic_violation_attempt2_ok_clearing_flag");
                s_periodic_consecutive_fail_count.store(0, std::memory_order_release);
                s_periodic_first_fail_qpc.store(0, std::memory_order_release);
                integrity::clear_periodic_violation_flag();
                CFF_GOTO(guard_cff, 6);
            }

            uint32_t prior_count = s_periodic_consecutive_fail_count.fetch_add(1, std::memory_order_acq_rel);
            uint32_t fail_count = prior_count + 1;
            if (prior_count == 0)
                s_periodic_first_fail_qpc.store(now_ms, std::memory_order_release);
            uint64_t first_fail_at = s_periodic_first_fail_qpc.load(std::memory_order_acquire);
            uint64_t span_ms = (first_fail_at != 0 && now_ms >= first_fail_at)
                ? (now_ms - first_fail_at) : 0;

            if (fail_count < kRequiredConsecutiveFailures)
            {
                webhook::write_log_critical_fmt("guard",
                    "periodic_violation_DEFERRED count=%u/%u span_ms=%llu page=%u epoch=%llu",
                    fail_count,
                    kRequiredConsecutiveFailures,
                    static_cast<unsigned long long>(span_ms),
                    mismatch_page2,
                    static_cast<unsigned long long>(epoch_at_attempt2));
                CFF_EXIT(guard_cff);
            }

            webhook::write_log_critical_fmt("guard",
                "periodic_violation_CONFIRMED_enforcing count=%u span_ms=%llu page=%u epoch=%llu",
                fail_count,
                static_cast<unsigned long long>(span_ms),
                mismatch_page2,
                static_cast<unsigned long long>(epoch_at_attempt2));
            char detail[160];
            _snprintf_s(detail, sizeof(detail), _TRUNCATE,
                "page_mac_periodic_mismatch page=%u count=%u span_ms=%llu",
                mismatch_page2,
                fail_count,
                static_cast<unsigned long long>(span_ms));
            webhook::send_debug_log("guard", detail, true);
            enforce_violation_id(aida::reason_ids::reason_id_page_mac_periodic_mismatch, detail);
            CFF_EXIT(guard_cff);
        }
        CFF_GOTO(guard_cff, 6);
    }
    CFF_STATE(guard_cff, 6)
    {
        if (rt.driver_hardening_active.load(std::memory_order_acquire))
        {
            const uint64_t started = rt.driver_hardening_started_ms.load(std::memory_order_acquire);
            const uint64_t now = state::monotonic_ms();
            const uint64_t active_ms = started != 0 && now >= started ? now - started : 0;
            webhook::write_log_critical_fmt("guard",
                "block_chain_skip_driver_hardening_active active_ms=%llu verify_counter=%u",
                static_cast<unsigned long long>(active_ms),
                rt.verify_counter);
            CFF_GOTO(guard_cff, 7);
        }
        integrity::block_chain_verify_result_t bc_detail{};
        bool bc_ok = false;
        {
            std::lock_guard<std::mutex> lk(rt.mtx);
            bc_ok = integrity::verify_block_chain(rt.code_snap, rt.block_chain, &bc_detail);
        }
        if (!bc_ok)
        {
            char detail[256];
            _snprintf_s(detail, sizeof(detail), _TRUNCATE,
                "block_chain_fail idx=%u/%u base=0x%llX size=%u expected=0x%llX actual=0x%llX prev=0x%llX layout=%u full_test=%u",
                bc_detail.block_index,
                bc_detail.chain_count,
                static_cast<unsigned long long>(bc_detail.block_base),
                bc_detail.block_size,
                static_cast<unsigned long long>(bc_detail.expected_hash),
                static_cast<unsigned long long>(bc_detail.actual_hash),
                static_cast<unsigned long long>(bc_detail.prev_hash),
                bc_detail.layout_mismatch ? 1u : 0u,
                rt.full_test_running.load(std::memory_order_acquire) ? 1u : 0u);
            webhook::write_log_critical_fmt("guard", "%s", detail);
            Sleep(50);
            integrity::block_chain_verify_result_t retry_detail{};
            bool retry_ok = false;
            {
                std::lock_guard<std::mutex> lk(rt.mtx);
                retry_ok = integrity::verify_block_chain(rt.code_snap, rt.block_chain, &retry_detail);
            }
            if (retry_ok)
            {
                webhook::write_log_critical_fmt("guard", "block_chain_retry_recovered idx=%u", bc_detail.block_index);
                CFF_GOTO(guard_cff, 7);
            }
            if (rt.driver_hardening_active.load(std::memory_order_acquire))
            {
                const uint64_t started = rt.driver_hardening_started_ms.load(std::memory_order_acquire);
                const uint64_t now = state::monotonic_ms();
                const uint64_t active_ms = started != 0 && now >= started ? now - started : 0;
                webhook::write_log_critical_fmt("guard",
                    "block_chain_retry_deferred_driver_hardening_active idx=%u retry_idx=%u active_ms=%llu",
                    bc_detail.block_index,
                    retry_detail.block_index,
                    static_cast<unsigned long long>(active_ms));
                CFF_GOTO(guard_cff, 7);
            }
            uint32_t eager_page = 0;
            const bool self_ok = integrity::verify_self_hash();
            const bool eager_ok = integrity::verify_full_text_eager(&eager_page);
            bool rebuild_ok = false;
            if (self_ok && eager_ok)
            {
                std::lock_guard<std::mutex> lk(rt.mtx);
                rebuild_ok = integrity::build_block_chain(rt.code_snap, rt.block_chain);
            }
            if (rebuild_ok)
            {
                webhook::write_log_critical_fmt("guard",
                    "block_chain_resnap_recovered idx=%u page=%u full_test=%u",
                    bc_detail.block_index,
                    eager_page,
                    rt.full_test_running.load(std::memory_order_acquire) ? 1u : 0u);
                CFF_GOTO(guard_cff, 7);
            }
            webhook::write_log_critical_fmt("guard",
                "block_chain_confirmed self=%u eager=%u page=%u retry_idx=%u full_test=%u",
                self_ok ? 1u : 0u,
                eager_ok ? 1u : 0u,
                eager_page,
                retry_detail.block_index,
                rt.full_test_running.load(std::memory_order_acquire) ? 1u : 0u);
            webhook::send_debug_log("guard", detail, true);
            enforce_violation_id(aida::reason_ids::reason_id_block_chain_runtime, detail);
            CFF_EXIT(guard_cff);
        }
        CFF_GOTO(guard_cff, 7);
    }
    CFF_STATE(guard_cff, 7)
    {
        DECOY_CALL_INTEGRATED(g7);
        bool call_obf_ok = call_obfuscation::verify_table_integrity();
        if (!call_obf_ok)
        {
            webhook::send_debug_log("guard", "call_obfuscation_tamper", true);
            enforce_violation_id(aida::reason_ids::reason_id_call_obfuscation_tamper);
            CFF_EXIT(guard_cff);
        }


        call_obfuscation::re_encrypt_all();

        bool nano_ok = nanomites::verify_table_integrity();
        if (!nano_ok)
        {
            webhook::send_debug_log("guard", "nanomite_table_tamper", true);
            enforce_violation_id(aida::reason_ids::reason_id_nanomite_table_tamper);
            CFF_EXIT(guard_cff);
        }
        nanomites::rotate_keys();

#if defined(AIDA_DEEP_STEAL)
        bool bb_ok = stolen_bytes::verify_basic_blocks();
        if (!bb_ok)
        {
            webhook::send_debug_log("guard", "stolen_basic_block_tamper", true);
            enforce_violation_id(aida::reason_ids::reason_id_stolen_basic_block_tamper);
            CFF_EXIT(guard_cff);
        }
#endif

        CFF_GOTO(guard_cff, 8);
    }
    CFF_STATE(guard_cff, 8)
    {
        bool drv_loaded = driver_bridge::is_loaded();
        bool drv_kernel = drv_loaded && driver_bridge::using_kernel_driver();
        if (drv_kernel)
        {
            driver_bridge::dynamic_ioctl_state_t dyn = driver_bridge::dynamic_ioctl_state();
            if (!dyn.ready)
            {
                const bool runtime_authorized = standalone_license::is_valid() || standalone_license::is_arc_loaded();
                webhook::write_log_critical_fmt("guard",
                    "kernel_anti_debug_runtime_deferred_dynamic_ioctl_not_ready runtime_authorized=%d loaded=%d kernel=%d connected=%d inst_seed=%u/%u global_seed=%u/%u ioctl_seed_hash=0x%08X hb_ioctl_seed_hash=0x%08X",
                    runtime_authorized ? 1 : 0,
                    dyn.loaded ? 1 : 0,
                    dyn.kernel ? 1 : 0,
                    dyn.connected ? 1 : 0,
                    dyn.instance_server_seed,
                    dyn.instance_ioctl_seed,
                    dyn.global_server_seed,
                    dyn.global_ioctl_seed,
                    dyn.ioctl_seed_hash,
                    dyn.heartbeat_ioctl_seed_hash);
                if (runtime_authorized)
                {
                    webhook::send_debug_log("guard", "kernel_anti_debug_dynamic_ioctl_not_ready_after_auth", true);
                    enforce_violation_id(aida::reason_ids::reason_id_kernel_debugger_runtime, "kernel_anti_debug_dynamic_ioctl_not_ready_after_auth");
                    CFF_EXIT(guard_cff);
                }
            }
            else
            {
                const bool runtime_authorized = standalone_license::is_valid() || standalone_license::is_arc_loaded();
                const bool activation_pending = rt.license_pending_activation.load(std::memory_order_acquire);

                SetLastError(ERROR_SUCCESS);
                if (!driver_bridge::kernel_anti_debug_clear_dr())
                {
                    DWORD clear_dr_err = GetLastError();
                    webhook::write_log_critical_fmt("guard",
                        "kernel_clear_dr_runtime_result ok=0 err=%lu activation_pending=%d runtime_authorized=%d",
                        static_cast<unsigned long>(clear_dr_err),
                        activation_pending ? 1 : 0,
                        runtime_authorized ? 1 : 0);
                    if (activation_pending && !runtime_authorized)
                    {
                        webhook::write_log("guard", "kernel_clear_dr_runtime_deferred_activation_pending");
                        CFF_GOTO(guard_cff, 9);
                    }
                    webhook::send_debug_log("guard", "kernel_clear_dr_runtime_failed", true);
                    enforce_violation_id(aida::reason_ids::reason_id_kernel_debugger_runtime, "kernel_clear_dr_runtime_failed");
                    CFF_EXIT(guard_cff);
                }

                uint64_t debugger_pid = 0;
                SetLastError(ERROR_SUCCESS);
                if (!driver_bridge::kernel_anti_debug_scan_debuggers(&debugger_pid))
                {
                    DWORD scan_err = GetLastError();
                    webhook::write_log_critical_fmt("guard",
                        "kernel_debugger_scan_runtime_result ok=0 err=%lu activation_pending=%d runtime_authorized=%d",
                        static_cast<unsigned long>(scan_err),
                        activation_pending ? 1 : 0,
                        runtime_authorized ? 1 : 0);
                    if (activation_pending && !runtime_authorized)
                    {
                        webhook::write_log("guard", "kernel_debugger_scan_runtime_deferred_activation_pending");
                        CFF_GOTO(guard_cff, 9);
                    }
                    webhook::send_debug_log("guard", "kernel_debugger_scan_runtime_failed", true);
                    enforce_violation_id(aida::reason_ids::reason_id_kernel_debugger_runtime, "kernel_debugger_scan_runtime_failed");
                    CFF_EXIT(guard_cff);
                }
                if (debugger_pid != 0)
                {
                    if (kernel_debugger_scan_confirmed_for_enforcement("guard", "runtime_scan", debugger_pid))
                    {
                        webhook::send_debug_log("guard", "kernel_debugger_runtime_" + std::to_string(debugger_pid), true);
                        enforce_violation_id(aida::reason_ids::reason_id_kernel_debugger_runtime);
                        CFF_EXIT(guard_cff);
                    }
                    webhook::write_log_critical_fmt("guard",
                        "kernel_debugger_runtime_unconfirmed_global_tool_ignored debugger_pid=%llu",
                        static_cast<unsigned long long>(debugger_pid));
                }

                if (g_kernel_clear_process_dr_unsupported.load(std::memory_order_acquire))
                {
                    webhook::write_log("guard", "kernel_clear_process_dr_runtime_skipped_unsupported");
                }
                else
                {
                    SetLastError(ERROR_SUCCESS);
                    bool clear_proc_runtime_ok = driver_bridge::kernel_anti_debug_clear_process_dr(GetCurrentProcessId());
                    DWORD clear_proc_runtime_err = clear_proc_runtime_ok ? ERROR_SUCCESS : GetLastError();
                    bool clear_proc_runtime_required = clear_proc_runtime_ok || !kernel_adbg_thread_walk_optional_error(clear_proc_runtime_err);
                    webhook::write_log_critical_fmt("guard",
                        "kernel_clear_process_dr_runtime_result ok=%d err=%lu required=%d pid=%lu",
                        clear_proc_runtime_ok ? 1 : 0,
                        static_cast<unsigned long>(clear_proc_runtime_err),
                        clear_proc_runtime_required ? 1 : 0,
                        static_cast<unsigned long>(GetCurrentProcessId()));
                    if (!clear_proc_runtime_ok && clear_proc_runtime_required)
                    {
                        webhook::send_debug_log("guard", "kernel_clear_process_dr_runtime_failed", true);
                        enforce_violation_id(aida::reason_ids::reason_id_kernel_debugger_runtime, "kernel_clear_process_dr_runtime_failed");
                        CFF_EXIT(guard_cff);
                    }
                    if (!clear_proc_runtime_ok)
                    {
                        g_kernel_clear_process_dr_unsupported.store(true, std::memory_order_release);
                        webhook::write_log("guard", "kernel_clear_process_dr_runtime_degraded_unsupported");
                    }
                }
            }
        }

        server_pages::evict_expired();

        virtualizer::protection::reencrypt_live_bytecode();

        {
            uint64_t nonce_hash = standalone_license::get_server_nonce_hash();
            if (nonce_hash != 0 && nonce_hash != rt.last_server_nonce_hash)
            {
                virtualizer::reseed_from_server(nonce_hash);
                rt.last_server_nonce_hash = nonce_hash;
            }
        }
        CFF_GOTO(guard_cff, 9);
    }
    CFF_STATE(guard_cff, 9)
    {
        bool lic_valid = standalone_license::is_valid();
        if (!lic_valid)
        {
            if (!rt.license_pending_activation.load(std::memory_order_acquire))
            {
                std::string err = standalone_license::last_error();
                webhook::send_debug_log("guard", "license_invalid: " + err, true);
                enforce_violation_id(aida::reason_ids::reason_id_license_killed, err);
                CFF_EXIT(guard_cff);
            }
            webhook::write_log("guard", "license_pending_activation_wait");
            CFF_EXIT(guard_cff);
        }

        {
            uint64_t activation_completed_at = standalone_license::activation_completed_at();
            if (activation_completed_at != 0
                && !standalone_license::is_arc_loaded()
                && !standalone_license::is_arc_download_in_progress())
            {
                constexpr uint64_t kArcRequiredGraceMs = 10000;
                uint64_t now_ms = guard_now_ms();
                if ((now_ms - activation_completed_at) > kArcRequiredGraceMs)
                {
                    webhook::send_debug_log("guard", "arc_missing_after_activation", true);
                    enforce_violation_id(aida::reason_ids::reason_id_arc_required, "arc_missing_after_activation");
                    CFF_EXIT(guard_cff);
                }
            }
        }

        if (driver_bridge::is_loaded() && driver_bridge::using_kernel_driver())
        {
            driver_bridge::dynamic_ioctl_state_t dyn = driver_bridge::dynamic_ioctl_state();
            if (!dyn.ready)
            {
                webhook::write_log_critical_fmt("guard",
                    "kernel_anti_debug_query_dynamic_ioctl_not_ready_after_auth loaded=%d kernel=%d connected=%d inst_seed=%u/%u global_seed=%u/%u ioctl_seed_hash=0x%08X hb_ioctl_seed_hash=0x%08X",
                    dyn.loaded ? 1 : 0,
                    dyn.kernel ? 1 : 0,
                    dyn.connected ? 1 : 0,
                    dyn.instance_server_seed,
                    dyn.instance_ioctl_seed,
                    dyn.global_server_seed,
                    dyn.global_ioctl_seed,
                    dyn.ioctl_seed_hash,
                    dyn.heartbeat_ioctl_seed_hash);
                webhook::send_debug_log("guard", "kernel_anti_debug_query_dynamic_ioctl_not_ready_after_auth", true);
                enforce_violation_id(aida::reason_ids::reason_id_kernel_debugger_runtime, "kernel_anti_debug_query_dynamic_ioctl_not_ready_after_auth");
                CFF_EXIT(guard_cff);
            }
            else
            {
                driver_bridge::anti_debug_result_t adbg_result{};
                if (driver_bridge::kernel_anti_debug_query(adbg_result) &&
                    adbg_result.result_flags != 0)
                {
                    auto& rt = state::get();
                    char kflag_buf[32];
                    _snprintf_s(kflag_buf, sizeof(kflag_buf), _TRUNCATE,
                        "kernel_detection_flags_0x%x", adbg_result.result_flags);
                    webhook::send_debug_log("guard", kflag_buf, true);

                    char flag_dbg[128];
                    _snprintf_s(flag_dbg, sizeof(flag_dbg), _TRUNCATE,
                        "guard_kernel_flags flags=0x%x last=0x%x persist=%u",
                        adbg_result.result_flags, rt.last_kernel_flags, rt.kernel_flag_persist_count);
                    webhook::write_log("guard", flag_dbg);

                    constexpr uint32_t kSoftFlags =
                        0x00000002u |
                        0x00000010u |
                        0x00000040u;

                    constexpr uint64_t kKernelDetectionSettleGraceMs = 3000;

                    const uint32_t flags = adbg_result.result_flags;
                    const bool hard_hit  = kernel_adbg_hard_flags_present(flags);
                    const bool two_soft  = (flags & kSoftFlags) != 0 &&
                                           ((flags & kSoftFlags) & ((flags & kSoftFlags) - 1)) != 0;

                    uint64_t sentinel_ready_since_tsc = driver_bridge::sentinel_ready_since_tsc();
                    uint64_t now_ms = guard_now_ms();
                    if (sentinel_ready_since_tsc != 0 &&
                        sentinel_ready_since_tsc != rt.last_sentinel_ready_since_tsc)
                    {
                        rt.last_sentinel_ready_since_tsc = sentinel_ready_since_tsc;
                        rt.kernel_flags_settle_start_ms = now_ms;
                        rt.last_kernel_flags = 0;
                        rt.kernel_flag_persist_count = 0;
                        webhook::write_log("guard", "kernel_flag_settle_started");
                    }

                    const bool settle_active =
                        driver_bridge::sentinel_bridge_ready() &&
                        rt.last_sentinel_ready_since_tsc != 0 &&
                        (now_ms - rt.kernel_flags_settle_start_ms) < kKernelDetectionSettleGraceMs;

                    if (flags == rt.last_kernel_flags && flags != 0) {
                        rt.kernel_flag_persist_count++;
                    } else {
                        rt.last_kernel_flags = flags;
                        rt.kernel_flag_persist_count = 1;
                    }

                    const bool persist_hit = (rt.kernel_flag_persist_count >= 3);

                    if (settle_active)
                    {
                        char settle_flag_buf[32];
                        _snprintf_s(settle_flag_buf, sizeof(settle_flag_buf), _TRUNCATE,
                            "0x%x", flags);
                        webhook::send_debug_log("sentinel_settle_flags", settle_flag_buf, true);
                        char settle_dbg[128];
                        _snprintf_s(settle_dbg, sizeof(settle_dbg), _TRUNCATE,
                            "kernel_flag_settle_active flags=0x%x persist=%u",
                            flags, rt.kernel_flag_persist_count);
                        webhook::write_log("guard", settle_dbg);
                        CFF_GOTO(guard_cff, 10);
                    }

                    if (hard_hit || two_soft || persist_hit)
                    {
                        char extra_buf[16];
                        _snprintf_s(extra_buf, sizeof(extra_buf), _TRUNCATE, "0x%x", flags);
                        enforce_violation_id(aida::reason_ids::reason_id_kernel_detection_active, extra_buf);
                        CFF_EXIT(guard_cff);
                    }
                }
                else
                {
                    auto& rt = state::get();
                    rt.last_kernel_flags = 0;
                    rt.kernel_flag_persist_count = 0;
                }
            }
        }
        CFF_GOTO(guard_cff, 10);
    }
    CFF_STATE(guard_cff, 10)
    {
        CFF_GOTO(guard_cff, 11);
    }
    CFF_STATE(guard_cff, 11)
    {
        MEMORY_BASIC_INFORMATION mbi{};
        uint64_t addr = rt.code_snap.text_base;
        const uint64_t end = rt.code_snap.text_base + rt.code_snap.text_size;
        bool page_ok = true;
        DWORD failed_prot = 0;
        uint64_t failed_addr = 0;

        while (addr < end && page_ok)
        {
            if (VirtualQuery(reinterpret_cast<LPCVOID>(addr), &mbi, sizeof(mbi)) == 0)
            {
                page_ok = false;
                failed_addr = addr;
                break;
            }
            constexpr DWORD writable = PAGE_EXECUTE_READWRITE | PAGE_READWRITE
                | PAGE_EXECUTE_WRITECOPY | PAGE_WRITECOPY;
            if (mbi.Protect & writable) {
                page_ok = false;
                failed_prot = mbi.Protect;
                failed_addr = reinterpret_cast<uint64_t>(mbi.BaseAddress);
            }
            addr = reinterpret_cast<uint64_t>(mbi.BaseAddress) + mbi.RegionSize;
        }

        if (!page_ok)
        {
            char detail[256];
            _snprintf_s(detail, sizeof(detail), _TRUNCATE,
                "writable_code_page prot=0x%X addr=0x%llX", failed_prot, failed_addr);
            webhook::send_debug_log("guard", detail, true);
            enforce_violation_id(aida::reason_ids::reason_id_writable_code_page);
            CFF_EXIT(guard_cff);
        }
        CFF_EXIT(guard_cff);
    }
    CFF_END(guard_cff)

    ++rt.verify_counter;

    return !rt.violation_latched.load(std::memory_order_acquire);
}

namespace watchdog_detail {

inline uint64_t now_ms()
{
    return static_cast<uint64_t>(GetTickCount64());
}

inline uint64_t fast_check_peb()
{
    uint64_t score = 0;
    if (anti_debug::check_being_debugged()) score |= 0x1ull;
    if (anti_debug::check_nt_global_flag()) score |= 0x2ull;
    if (anti_debug::check_heap_flags()) score |= 0x4ull;
    if (anti_debug::check_is_debugger_present()) score |= 0x8ull;
    return score;
}

inline uint64_t fast_check_dr()
{
    return anti_debug::check_hw_breakpoints_local() ? 0x10ull : 0ull;
}

inline uint64_t fast_check_guard_pages()
{
    auto& rt = state::get();
    if (rt.code_snap.text_base == 0 || rt.code_snap.text_size == 0) return 0;

    MEMORY_BASIC_INFORMATION mbi{};
    uint64_t addr = rt.code_snap.text_base;
    const uint64_t end = rt.code_snap.text_base + rt.code_snap.text_size;
    constexpr DWORD writable = PAGE_EXECUTE_READWRITE | PAGE_READWRITE
        | PAGE_EXECUTE_WRITECOPY | PAGE_WRITECOPY;

    while (addr < end)
    {
        if (VirtualQuery(reinterpret_cast<LPCVOID>(addr), &mbi, sizeof(mbi)) == 0)
            return 0x40ull;
        if (mbi.Protect & writable)
            return 0x80ull;
        addr = reinterpret_cast<uint64_t>(mbi.BaseAddress) + mbi.RegionSize;
    }
    return 0;
}

inline uint64_t fast_check_iat()
{
    auto& rt = state::get();
    if (rt.iat_snap.empty()) return 0;
    return integrity::verify_iat(rt.iat_snap) ? 0 : 0x100ull;
}

inline uint64_t fast_check_vm_synthetic()
{
    return anti_vm::synthetic_vm_trip_active() ? 0x200ull : 0ull;
}

inline uint64_t worker_compute_score()
{
    uint64_t s = 0;
    s |= fast_check_peb();
    s |= fast_check_dr();
    s |= fast_check_guard_pages();
    s |= fast_check_iat();
    s |= fast_check_vm_synthetic();
    return s;
}

inline BCRYPT_ALG_HANDLE get_hmac_alg()
{
    thread_local BCRYPT_ALG_HANDLE h = nullptr;
    if (!h)
    {
        if (BCryptOpenAlgorithmProvider(&h, BCRYPT_SHA256_ALGORITHM, nullptr,
                                        BCRYPT_ALG_HANDLE_HMAC_FLAG) != 0)
        {
            h = nullptr;
        }
    }
    return h;
}

inline bool hmac_sha256(const uint8_t* key, uint32_t key_len,
                       const uint8_t* data, uint32_t data_len,
                       uint8_t out[32])
{
    BCRYPT_ALG_HANDLE alg = get_hmac_alg();
    if (!alg) return false;
    BCRYPT_HASH_HANDLE hash = nullptr;
    bool ok = false;
    if (BCryptCreateHash(alg, &hash, nullptr, 0,
                         const_cast<PUCHAR>(key), key_len, 0) == 0)
    {
        if (BCryptHashData(hash, const_cast<PUCHAR>(data), data_len, 0) == 0)
            ok = (BCryptFinishHash(hash, out, 32, 0) == 0);
        BCryptDestroyHash(hash);
    }
    return ok;
}

inline uint64_t fold_witness(uint64_t prev_chain, uint64_t score, uint64_t worker_id,
                             uint64_t epoch, const uint8_t key[32])
{
    uint8_t input[32] = {};
    std::memcpy(input + 0, &prev_chain, 8);
    std::memcpy(input + 8, &score, 8);
    std::memcpy(input + 16, &worker_id, 8);
    std::memcpy(input + 24, &epoch, 8);
    uint8_t mac[32] = {};
    if (!hmac_sha256(key, 32, input, sizeof(input), mac))
        return prev_chain ^ (score * 0x9E3779B97F4A7C15ULL);
    uint64_t out = 0;
    std::memcpy(&out, mac, 8);
    return out;
}

inline const uint8_t* witness_key()
{
    static uint8_t s_key[32] = {};
    static std::once_flag s_once;
    std::call_once(s_once, []() {
        const char salt_str[] = "aida.watchdog.witness.key.v1";
        if (!key_pipeline::derive("aida.watchdog.witness",
                                  reinterpret_cast<const uint8_t*>(salt_str),
                                  sizeof(salt_str) - 1,
                                  s_key, 32))
        {
            uint64_t k0 = 0, k1 = 0;
            integrity::get_session_keys(k0, k1);
            std::memcpy(s_key + 0, &k0, 8);
            std::memcpy(s_key + 8, &k1, 8);
            uint64_t mix = 0xC2B2AE3D27D4EB4FULL ^ static_cast<uint64_t>(GetCurrentProcessId());
            std::memcpy(s_key + 16, &mix, 8);
            mix ^= __rdtsc();
            std::memcpy(s_key + 24, &mix, 8);
        }
    });
    return s_key;
}

inline void worker_loop(int worker_id, std::atomic<uint64_t>& tick_atomic,
                        std::atomic<uint64_t>& chain_atomic)
{
    auto& rt = state::get();
    SetThreadPriority(GetCurrentThread(), THREAD_PRIORITY_ABOVE_NORMAL);
    tick_atomic.store(now_ms(), std::memory_order_release);
    uint64_t epoch = 0;
    while (rt.monitors_running.load() && !rt.violation_latched.load())
    {
        ++epoch;
        uint64_t score = worker_compute_score();
        uint64_t prev = chain_atomic.load(std::memory_order_acquire);
        uint64_t folded = fold_witness(prev, score, static_cast<uint64_t>(worker_id),
                                       epoch, witness_key());
        chain_atomic.store(folded, std::memory_order_release);
        tick_atomic.store(now_ms(), std::memory_order_release);

        if (score != 0)
        {
            char dbg[128];
            _snprintf_s(dbg, sizeof(dbg), _TRUNCATE,
                "worker%d_score=0x%llX epoch=%llu", worker_id,
                static_cast<unsigned long long>(score),
                static_cast<unsigned long long>(epoch));
            webhook::send_debug_log("watchdog_worker", dbg, true);
            enforce_violation_id(aida::reason_ids::reason_id_watchdog_worker_anomaly, dbg);
            return;
        }

        Sleep(75);
    }
}

inline bool reattest()
{
    auto& rt = state::get();
    auto hb = standalone_license::arc_heartbeat();
    if (hb.valid && hb.proof_token != 0)
    {
        rt.reattest_last_proof_token.store(hb.proof_token, std::memory_order_release);
        rt.reattest_last_success_ms.store(now_ms(), std::memory_order_release);
        rt.reattest_first_failure_ms.store(0, std::memory_order_release);
        return true;
    }
    return false;
}

inline void watchdog_loop()
{
    auto& rt = state::get();
    HANDLE self_thread = GetCurrentThread();
    SetThreadPriority(self_thread, THREAD_PRIORITY_HIGHEST);

    constexpr uint64_t kReattestPeriodMs = 5ull * 60ull * 1000ull;
    constexpr uint64_t kReattestGraceMs = 30ull * 1000ull;
    constexpr uint64_t kWorkerStallMs = 3000ull;
    constexpr uint32_t kRequiredConsecutiveStalls = 4;
    uint32_t s_consecutive_stalls = 0;
    uint64_t s_first_stall_ms = 0;

    uint64_t last_reattest_attempt_ms = now_ms();
    uint64_t startup_grace_until = now_ms() + 8000ull;

    rt.watchdog_last_tick_ms.store(now_ms(), std::memory_order_release);

    while (rt.monitors_running.load() && !rt.violation_latched.load())
    {
        uint64_t cur = now_ms();
        rt.watchdog_last_tick_ms.store(cur, std::memory_order_release);

        if (cur > startup_grace_until)
        {
            uint64_t ta = rt.worker_a_last_tick_ms.load(std::memory_order_acquire);
            uint64_t tb = rt.worker_b_last_tick_ms.load(std::memory_order_acquire);
            uint64_t tc = rt.worker_c_last_tick_ms.load(std::memory_order_acquire);

            uint64_t da = (ta == 0) ? 0 : (cur - ta);
            uint64_t db = (tb == 0) ? 0 : (cur - tb);
            uint64_t dc = (tc == 0) ? 0 : (cur - tc);

            int stalled = 0;
            if (ta != 0 && da > kWorkerStallMs) ++stalled;
            if (tb != 0 && db > kWorkerStallMs) ++stalled;
            if (tc != 0 && dc > kWorkerStallMs) ++stalled;

            if (stalled >= 2)
            {
                if (s_consecutive_stalls == 0)
                    s_first_stall_ms = cur;
                ++s_consecutive_stalls;
                if (s_consecutive_stalls >= kRequiredConsecutiveStalls)
                {
                    uint64_t span = (s_first_stall_ms != 0 && cur >= s_first_stall_ms)
                        ? (cur - s_first_stall_ms) : 0;
                    char dbg[224];
                    _snprintf_s(dbg, sizeof(dbg), _TRUNCATE,
                        "watchdog_workers_stalled da=%llu db=%llu dc=%llu count=%u span_ms=%llu",
                        static_cast<unsigned long long>(da),
                        static_cast<unsigned long long>(db),
                        static_cast<unsigned long long>(dc),
                        s_consecutive_stalls,
                        static_cast<unsigned long long>(span));
                    webhook::send_debug_log("watchdog_stall", dbg, true);
                    enforce_violation_id(aida::reason_ids::reason_id_watchdog_workers_stalled, dbg);
                    return;
                }
                webhook::write_log_critical_fmt("watchdog",
                    "watchdog_stall_DEFERRED da=%llu db=%llu dc=%llu count=%u/%u",
                    static_cast<unsigned long long>(da),
                    static_cast<unsigned long long>(db),
                    static_cast<unsigned long long>(dc),
                    s_consecutive_stalls,
                    kRequiredConsecutiveStalls);
            }
            else
            {
                if (s_consecutive_stalls != 0)
                {
                    webhook::write_log_critical_fmt("watchdog",
                        "watchdog_stall_RECOVERED prior_count=%u da=%llu db=%llu dc=%llu",
                        s_consecutive_stalls,
                        static_cast<unsigned long long>(da),
                        static_cast<unsigned long long>(db),
                        static_cast<unsigned long long>(dc));
                }
                s_consecutive_stalls = 0;
                s_first_stall_ms = 0;
            }
        }

        if (rt.initialized.load() &&
            !rt.license_pending_activation.load() &&
            standalone_license::is_arc_loaded())
        {
            uint64_t since_last_attempt = cur - last_reattest_attempt_ms;
            if (since_last_attempt >= kReattestPeriodMs)
            {
                last_reattest_attempt_ms = cur;
                bool ok = reattest();
                char dbg[96];
                _snprintf_s(dbg, sizeof(dbg), _TRUNCATE,
                    "watchdog_reattest ok=%d at_ms=%llu", ok ? 1 : 0,
                    static_cast<unsigned long long>(cur));
                webhook::write_log("watchdog", dbg);
                if (!ok)
                {
                    uint64_t first_fail = rt.reattest_first_failure_ms.load(std::memory_order_acquire);
                    if (first_fail == 0)
                    {
                        rt.reattest_first_failure_ms.store(cur, std::memory_order_release);
                    }
                    else if ((cur - first_fail) > kReattestGraceMs)
                    {
                        webhook::send_debug_log("watchdog", "reattest_grace_exceeded", true);
                        enforce_violation_id(aida::reason_ids::reason_id_reattest_failure, "5min_re_attestation_failed");
                        return;
                    }
                }
            }
        }

        Sleep(50);
    }
}

inline void monitor_loop()
{
    auto& rt = state::get();
    Sleep(5000);
    diag::log_tagged_critical("monitor", "thread_started");
    uint64_t iter = 0;
    while (rt.monitors_running.load() && !rt.violation_latched.load())
    {
        ++iter;
        if ((iter % 4ULL) == 0ULL) {
            diag::log_tagged_critical_fmt("monitor", "iter=%llu pre_guard latched=%d",
                (unsigned long long)iter, rt.violation_latched.load() ? 1 : 0);
        }
        try
        {
            guard();
            enforcement_tick();
        }
        catch (const std::exception& ex)
        {
            char ebuf[256];
            _snprintf_s(ebuf, sizeof(ebuf), _TRUNCATE,
                "monitor_loop_EXCEPTION iter=%llu what=%s", iter, ex.what());
            diag::log_tagged_critical("monitor", ebuf);
        }
        catch (...)
        {
            char ebuf[128];
            _snprintf_s(ebuf, sizeof(ebuf), _TRUNCATE,
                "monitor_loop_UNKNOWN_EXCEPTION iter=%llu", iter);
            diag::log_tagged_critical("monitor", ebuf);
        }
        if ((iter % 4ULL) == 0ULL) {
            diag::log_tagged_critical_fmt("monitor", "iter=%llu post_guard latched=%d",
                (unsigned long long)iter, rt.violation_latched.load() ? 1 : 0);
        }
        Sleep(500);
    }
    char dbg[128];
    _snprintf_s(dbg, sizeof(dbg), _TRUNCATE,
        "thread_exiting monitors_running=%d violation_latched=%d iter=%llu",
        rt.monitors_running.load() ? 1 : 0, rt.violation_latched.load() ? 1 : 0, iter);
    webhook::write_log("monitor", dbg);
}

}

inline bool post_monitor_task(const char* ok_tag, const char* fail_tag, std::function<void()> task)
{
    uint64_t tick = GetTickCount64();
    webhook::write_log_critical_fmt("init",
        "post_monitor_task_pre ok_tag=%s fail_tag=%s pid=%lu tid=%lu tick=%llu",
        ok_tag ? ok_tag : "<null>",
        fail_tag ? fail_tag : "<null>",
        GetCurrentProcessId(),
        GetCurrentThreadId(),
        static_cast<unsigned long long>(tick));
    try
    {
        bool posted = work_queue::post(std::move(task));
        webhook::write_log_critical_fmt("init",
            "post_monitor_task_post ok_tag=%s fail_tag=%s posted=%d elapsed_ms=%llu",
            ok_tag ? ok_tag : "<null>",
            fail_tag ? fail_tag : "<null>",
            posted ? 1 : 0,
            static_cast<unsigned long long>(GetTickCount64() - tick));
        webhook::write_log("init", posted ? ok_tag : fail_tag);
        return posted;
    }
    catch (const std::exception& ex)
    {
        webhook::write_log_critical_fmt("init", "%s_exception elapsed_ms=%llu what=%.160s",
            fail_tag ? fail_tag : "<null>",
            static_cast<unsigned long long>(GetTickCount64() - tick),
            ex.what());
        return false;
    }
    catch (...)
    {
        webhook::write_log_critical_fmt("init", "%s_unknown_exception elapsed_ms=%llu",
            fail_tag ? fail_tag : "<null>",
            static_cast<unsigned long long>(GetTickCount64() - tick));
        return false;
    }
}

inline bool start_monitors()
{
    auto& rt = state::get();
    if (rt.monitors_running.exchange(true))
    {
        webhook::write_log_critical_fmt("init",
            "watchdog_workers_already_running pid=%lu tid=%lu tick=%llu",
            GetCurrentProcessId(),
            GetCurrentThreadId(),
            static_cast<unsigned long long>(GetTickCount64()));
        return true;
    }

    rt.watchdog_running.store(true, std::memory_order_release);
    uint64_t tick = GetTickCount64();
    webhook::write_log_critical_fmt("init",
        "watchdog_workers_start_pre pid=%lu tid=%lu tick=%llu",
        GetCurrentProcessId(),
        GetCurrentThreadId(),
        static_cast<unsigned long long>(tick));

    bool posted = true;
    bool monitor_posted = post_monitor_task(
        "watchdog_monitor_post_ok",
        "watchdog_monitor_post_fail",
        watchdog_detail::monitor_loop);
    posted = monitor_posted && posted;

    bool worker_a_posted = post_monitor_task(
        "watchdog_worker_a_post_ok",
        "watchdog_worker_a_post_fail",
        []() {
            auto& rt = state::get();
            watchdog_detail::worker_loop(0,
                rt.worker_a_last_tick_ms, rt.witness_chain_a);
            webhook::write_log("watchdog_worker_a", "exiting");
        });
    posted = worker_a_posted && posted;

    bool worker_b_posted = post_monitor_task(
        "watchdog_worker_b_post_ok",
        "watchdog_worker_b_post_fail",
        []() {
            auto& rt = state::get();
            watchdog_detail::worker_loop(1,
                rt.worker_b_last_tick_ms, rt.witness_chain_b);
            webhook::write_log("watchdog_worker_b", "exiting");
        });
    posted = worker_b_posted && posted;

    bool worker_c_posted = post_monitor_task(
        "watchdog_worker_c_post_ok",
        "watchdog_worker_c_post_fail",
        []() {
            auto& rt = state::get();
            watchdog_detail::worker_loop(2,
                rt.worker_c_last_tick_ms, rt.witness_chain_c);
            webhook::write_log("watchdog_worker_c", "exiting");
        });
    posted = worker_c_posted && posted;

    bool watchdog_posted = post_monitor_task(
        "watchdog_post_ok",
        "watchdog_post_fail",
        []() {
            watchdog_detail::watchdog_loop();
            auto& rt = state::get();
            rt.watchdog_running.store(false, std::memory_order_release);
            webhook::write_log("watchdog", "exiting");
        });
    posted = watchdog_posted && posted;

    if (posted)
    {
        webhook::write_log_critical_fmt("init",
            "watchdog_workers_started monitor=%d a=%d b=%d c=%d watchdog=%d elapsed_ms=%llu",
            monitor_posted ? 1 : 0,
            worker_a_posted ? 1 : 0,
            worker_b_posted ? 1 : 0,
            worker_c_posted ? 1 : 0,
            watchdog_posted ? 1 : 0,
            static_cast<unsigned long long>(GetTickCount64() - tick));
        return true;
    }

    webhook::write_log_critical_fmt("init",
        "watchdog_worker_start_failed monitor=%d a=%d b=%d c=%d watchdog=%d elapsed_ms=%llu",
        monitor_posted ? 1 : 0,
        worker_a_posted ? 1 : 0,
        worker_b_posted ? 1 : 0,
        worker_c_posted ? 1 : 0,
        watchdog_posted ? 1 : 0,
        static_cast<unsigned long long>(GetTickCount64() - tick));
    rt.monitors_running.store(false, std::memory_order_release);
    rt.watchdog_running.store(false, std::memory_order_release);
    return false;
}

inline void shutdown()
{
    auto& rt = state::get();
    rt.monitors_running.store(false);
    integrity::periodic::stop();
    re_detect::shutdown();
    standalone_anti_dump::shutdown();
    server_pages::shutdown();
    nanomites::shutdown();
    ai_deception::shutdown();
    code_encrypt::shutdown();
    packer::shutdown();
    anti_dump::shutdown();
    syscall::shutdown();
}

}
