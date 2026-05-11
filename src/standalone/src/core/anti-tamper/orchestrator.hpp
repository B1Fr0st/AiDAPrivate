#pragma once

#include <windows.h>
#include <psapi.h>
#include <bcrypt.h>

#include <cstdint>
#include <cstdio>
#include <mutex>
#include <string>
#include <thread>
#include <chrono>

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
#include "../arc/arc.h"

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
        "arc_validate_tool_exec",
        "arc_heartbeat",
        "arc_init",
        "arc_download_page",
        "arc_get_comm_bridge"
    };

    rt.vm_nested_rvas.clear();
    for (const char* name : kCriticalNames)
    {
        uint32_t rva = resolve_export_rva(name);
        if (rva == 0u)
        {
            std::string err = std::string("vm_nested_skip_export_missing:") + name;
            webhook::write_log("init", err.c_str());
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

inline void start_monitors();

inline bool initialize()
{
    webhook::write_log("init", "initialize_ENTRY before state::get");
    auto& rt = state::get();
    webhook::write_log("init", "initialize_state_get_OK before lock_guard");
    std::lock_guard<std::mutex> lk(rt.mtx);
    webhook::write_log("init", "initialize_lock_acquired");

    if (rt.initialized.load()) {
        webhook::write_log("init", "initialize_already_initialized_returning_true");
        return true;
    }
    webhook::write_log("init", "initialize_not_yet_initialized");

    webhook::write_log("init", "calling_ensure_kat_passed");
    if (!key_pipeline::ensure_kat_passed())
    {
        webhook::write_log("init", "ensure_kat_passed_returned_FALSE_about_to_fastfail");
        webhook::send_debug_log("init", "crypto_kat_failed", true);
        __fastfail(0xA1DA0CA7u);
    }
    webhook::write_log("init", "crypto_kat_ok");

    syscall::initialize();
    webhook::write_log("init", "syscall_ok");

    if (driver_bridge::is_loaded() && driver_bridge::using_kernel_driver())
    {
        bool tier_a_present = false;
        if (driver_bridge::tier_a_driver_present_query(&tier_a_present, nullptr, nullptr)
            && tier_a_present)
        {
            webhook::send_debug_log("init", "tier_a_driver_present_startup", true);
            std::wstring msg = WOBFSTR(L"AiDA cannot start because a kernel-mode analysis driver is loaded. Unload it and try again.");
            std::wstring title = WOBFSTR(L"AiDA");
            MessageBoxW(nullptr, msg.c_str(), title.c_str(),
                MB_OK | MB_ICONERROR | MB_SYSTEMMODAL | MB_TOPMOST);
            ExitProcess(1);
        }

        void* canary = VirtualAlloc(nullptr, 4096, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        {
            char dbg[192];
            std::snprintf(dbg, sizeof(dbg), "canary_alloc_result va=%p gle=%lu", canary, canary ? 0ul : GetLastError());
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

            BOOL lock_ok = VirtualLock(canary, 4096);
            DWORD lock_error = lock_ok ? 0 : GetLastError();
            bool register_ok = false;
            if (lock_ok)
                register_ok = driver_bridge::canary_register(canary, 4096);
            DWORD register_error = register_ok ? 0 : GetLastError();
            {
                char dbg[256];
                std::snprintf(dbg, sizeof(dbg), "canary_stage va=%p pid=%lu seed=0x%llx lock=%d lock_err=%lu register=%d register_err=%lu",
                    canary,
                    GetCurrentProcessId(),
                    static_cast<unsigned long long>(initial_canary_seed),
                    lock_ok ? 1 : 0,
                    lock_error,
                    register_ok ? 1 : 0,
                    register_error);
                webhook::write_log("init", dbg);
            }

            if (lock_ok && register_ok)
            {
                DWORD old_protect = 0;
                BOOL protect_ok = VirtualProtect(canary, 4096, PAGE_NOACCESS, &old_protect);
                {
                    char dbg[224];
                    std::snprintf(dbg, sizeof(dbg), "canary_protect va=%p protect=%d old=0x%lx err=%lu",
                        canary,
                        protect_ok ? 1 : 0,
                        old_protect,
                        protect_ok ? 0ul : GetLastError());
                    webhook::write_log("init", dbg);
                }
                rt.canary_page = canary;
            }
            else
            {
                webhook::write_log("init", "canary_cleanup_after_failed_stage");
                VirtualUnlock(canary, 4096);
                SecureZeroMemory(canary, 4096);
                VirtualFree(canary, 0, MEM_RELEASE);
            }
        }
    }

    if (!integrity::snapshot_code(rt.code_snap))
        return false;
    webhook::write_log("init", "snapshot_code_ok");

    integrity::snapshot_iat(rt.iat_snap);
    webhook::write_log("init", "snapshot_iat_ok");

    integrity::build_block_chain(rt.code_snap, rt.block_chain);
    webhook::write_log("init", "block_chain_ok");

    token_chain::initialize_keys();
    {
        uint32_t pf = ai_deception::phase::cached_phase_flags();
        if (pf & 0x20u)
        {
            token_chain::enable_rdtsc_entangle(true);
            webhook::write_log("init", "rdtsc_entangle_enabled");
        }
    }
    webhook::write_log("init", "token_chain_ok");

    {
        auto dbg = anti_debug::full_scan(rt.code_snap.module_base, rt.code_snap.module_end);
        if (dbg.any_detected())
        {
            webhook::send_debug_log("init", "debugger_at_startup: " + dbg.summary, true);
            enforce_violation("debugger_at_startup", dbg.summary);
            return false;
        }
    }
    webhook::write_log("init", "anti_debug_ok");

    {
        auto hook = anti_hook::full_scan(rt.iat_snap);
        if (hook.any_detected())
        {
            webhook::send_debug_log("init", "hook_at_startup: " + hook.summary, true);
            enforce_violation("hook_at_startup", hook.summary);
            return false;
        }
    }
    webhook::write_log("init", "anti_hook_ok");

#if !defined(AIDA_TEST_VMWARE_BYPASS)
    {
        auto vm = anti_vm::full_scan();
        if (vm.any_detected())
        {
            webhook::send_debug_log("init", "vm_at_startup: " + vm.summary, true);
            enforce_violation("vm_at_startup", vm.summary);
            return false;
        }
    }
    webhook::write_log("init", "anti_vm_ok");
#else
    webhook::write_log("init", "anti_vm_SKIPPED_vmware_bypass");
#endif

    virtualizer::initialize(
        rt.code_snap.text_base,
        rt.code_snap.text_size,
        rt.code_snap.text_hash);
    webhook::write_log("init", "virtualizer_ok");

    {
        uint32_t nested_applied = apply_vm_nested_tags();
        char dbg[64];
        _snprintf_s(dbg, sizeof(dbg), _TRUNCATE,
            "vm_nested_tags_applied=%u", nested_applied);
        webhook::write_log("init", dbg);
    }

    ghost_veh::initialize();
    {
        char dbg[64];
        _snprintf_s(dbg, sizeof(dbg), _TRUNCATE,
            "ghost_veh_active=%d flags=0x%x",
            ghost_veh::is_active() ? 1 : 0, ghost_veh::get_flags());
        webhook::write_log("init", dbg);
    }

    code_encrypt::initialize(rt.code_snap.text_hash);
    webhook::write_log("init", "code_encrypt_ok");

    metamorphic::initialize();
    webhook::write_log("init", "metamorphic_ok");

    cloakwork::initialize(rt.code_snap.text_hash);
    webhook::write_log("init", "cloakwork_ok");

    ai_deception::initialize();
    webhook::write_log("init", "ai_deception_ok");

    call_obfuscation::initialize(rt.code_snap.text_hash);
    webhook::write_log("init", "call_obfuscation_ok");

    decoy::initialize();
    webhook::write_log("init", "decoy_call_graph_ok");


    webhook::write_log("init", "packer_encrypt_SKIPPED_no_autodecrypt");


    webhook::write_log("init", "packer_imports_SKIPPED_breaks_crt");

    nanomites::initialize();
    webhook::write_log("init", "nanomites_ok");

    if (binary_protocol::initialize_with_baked_pin())
        webhook::write_log("init", "binary_protocol_pin_ok");
    else
        webhook::write_log("init", "binary_protocol_pin_fail");

    server_pages::initialize();
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
        webhook::write_log("init", "driver_bridge_registering");
        driver_bridge::register_dll_protection(
            rt.code_snap.module_base,
            rt.code_snap.text_base,
            rt.code_snap.text_size,
            rt.code_snap.text_hash,
            2000
        );
        webhook::write_log("init", "driver_bridge_ok");

        uint32_t self_pid = GetCurrentProcessId();

        driver_bridge::kernel_anti_debug_clear_dr();
        driver_bridge::kernel_anti_debug_clear_process_dr(self_pid);
        driver_bridge::kernel_anti_debug_hide_all_threads(self_pid);
        webhook::write_log("init", "kernel_anti_debug_ok");


#if !defined(AIDA_TEST_VMWARE_BYPASS)
        uint64_t debugger_pid = 0;
        driver_bridge::kernel_anti_debug_scan_debuggers(&debugger_pid);
        if (debugger_pid != 0)
        {
            webhook::send_debug_log("init", "kernel_debugger_detected_pid_" + std::to_string(debugger_pid), true);
            enforce_violation("kernel_debugger_at_startup");
            return false;
        }
        webhook::write_log("init", "kernel_debugger_scan_ok");
#else
        webhook::write_log("init", "kernel_debugger_scan_SKIPPED_vmware_bypass");
#endif
    }
    else
    {
        webhook::write_log("init", "driver_bridge_skipped");
    }

    anti_debug::hide_thread_from_debugger(GetCurrentThread());
    webhook::write_log("init", "hide_thread_ok");

    rt.initialized.store(true);
    webhook::write_log("init", "initialized_ok");

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
        webhook::write_log("init", "code_snapshot_resnap_pre_periodic_start");
        if (integrity::snapshot_code(rt.code_snap)) {
            integrity::build_block_chain(rt.code_snap, rt.block_chain);
            webhook::write_log("init", "code_snapshot_resnap_ok");
        } else {
            webhook::write_log("init", "code_snapshot_resnap_FAILED");
        }
    }

    integrity::periodic::start();
    webhook::write_log("init", "periodic_integrity_started");

    try
    {
        webhook::write_log("init", "start_monitors_entering");
        start_monitors();
        webhook::write_log("init", "monitors_started_ok");
    }
    catch (const std::exception& ex)
    {
        webhook::write_log("init", (std::string("start_monitors_exception: ") + ex.what()).c_str());
    }
    catch (...)
    {
        webhook::write_log("init", "start_monitors_unknown_exception");
    }

    try
    {
        webhook::write_log("init", "re_detect_entering");
        re_detect::initialize();
        webhook::write_log("init", "re_detect_engine_ok");
    }
    catch (const std::exception& ex)
    {
        webhook::write_log("init", (std::string("re_detect_exception: ") + ex.what()).c_str());
    }
    catch (...)
    {
        webhook::write_log("init", "re_detect_unknown_exception");
    }


    webhook::write_log("init", "deferred_anti_dump_until_arc_loaded");

    return true;
}

__declspec(noinline) static void finalize_call_anti_dump_init_seh()
{
    __try { anti_dump::initialize(); }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        webhook::write_log_critical_fmt("init",
            "anti_dump_init_SEH code=0x%08X", GetExceptionCode());
    }
}

__declspec(noinline) static void finalize_call_standalone_anti_dump_init_seh()
{
    __try { standalone_anti_dump::initialize(); }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        webhook::write_log_critical_fmt("init",
            "standalone_anti_dump_init_SEH code=0x%08X", GetExceptionCode());
    }
}

__declspec(noinline) static void finalize_call_anti_dump_seal_seh()
{
    __try { anti_dump::seal_handles(); }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        webhook::write_log_critical_fmt("init",
            "anti_dump_seal_SEH code=0x%08X", GetExceptionCode());
    }
}

__declspec(noinline) static void finalize_call_standalone_anti_dump_seal_seh()
{
    __try { standalone_anti_dump::seal_handles(); }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        webhook::write_log_critical_fmt("init",
            "standalone_anti_dump_seal_SEH code=0x%08X", GetExceptionCode());
    }
}

__declspec(noinline) static void finalize_call_kernel_anti_dump_seh(uint32_t self_pid)
{
    __try { driver_bridge::kernel_anti_dump_full(self_pid); }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        webhook::write_log_critical_fmt("init",
            "kernel_anti_dump_full_SEH code=0x%08X", GetExceptionCode());
    }
}

__declspec(noinline) static void finalize_call_hide_module_seh()
{
    __try { anti_dump::hide_module(); }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        webhook::write_log_critical_fmt("init",
            "hide_module_SEH code=0x%08X", GetExceptionCode());
    }
}

static bool finalize_post_resnap_inner()
{
    auto& rt = state::get();
    if (rt.code_snap.text_base == 0 || rt.code_snap.text_size == 0)
    {
        webhook::write_log_critical("init",
            "post_finalize_integrity_resnap_skip_no_baseline");
        return false;
    }

    auto& pt = integrity::detail::page_table();
    bool ok = false;
    size_t pages = 0;
    {
        std::lock_guard<std::mutex> lk(pt.mtx);
        ok = integrity::detail::rebuild_page_table_locked(
            pt, rt.code_snap.text_base, rt.code_snap.text_size);
        pages = pt.entries.size();
    }

    if (ok)
    {
        integrity::clear_periodic_violation_flag();
        webhook::write_log_critical_fmt("init",
            "post_finalize_integrity_resnap_ok base=0x%llX size=0x%X pages=%zu",
            static_cast<unsigned long long>(rt.code_snap.text_base),
            rt.code_snap.text_size,
            pages);
    }
    else
    {
        webhook::write_log_critical("init",
            "post_finalize_integrity_resnap_FAILED");
    }
    return ok;
}

__declspec(noinline) static void finalize_post_resnap_seh()
{
    __try { finalize_post_resnap_inner(); }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        webhook::write_log_critical_fmt("init",
            "post_finalize_integrity_resnap_SEH code=0x%08X",
            GetExceptionCode());
    }
}

inline bool finalize_after_activation()
{
    auto& rt = state::get();
    if (rt.activation_hardening_done.exchange(true, std::memory_order_acq_rel))
    {
        webhook::write_log_critical("init", "finalize_after_activation_already_done");
        return true;
    }

    webhook::write_log_critical("init", "finalize_after_activation_entering");

    try
    {
        webhook::write_log_critical("init", "anti_dump_entering");
        finalize_call_anti_dump_init_seh();
        webhook::write_log_critical("init", "anti_dump_ok");
    }
    catch (const std::exception& ex)
    {
        webhook::write_log_critical("init", (std::string("anti_dump_exception: ") + ex.what()).c_str());
    }
    catch (...)
    {
        webhook::write_log_critical("init", "anti_dump_unknown_exception");
    }

    try
    {
        webhook::write_log_critical("init", "standalone_anti_dump_entering");
        finalize_call_standalone_anti_dump_init_seh();
        webhook::write_log_critical("init", "standalone_anti_dump_ok");
    }
    catch (const std::exception& ex)
    {
        webhook::write_log_critical("init", (std::string("standalone_anti_dump_exception: ") + ex.what()).c_str());
    }
    catch (...)
    {
        webhook::write_log_critical("init", "standalone_anti_dump_unknown_exception");
    }

    if (driver_bridge::is_loaded() && driver_bridge::using_kernel_driver())
    {
        uint32_t self_pid = GetCurrentProcessId();
        webhook::write_log_critical("init", "kernel_anti_dump_entering");
        finalize_call_kernel_anti_dump_seh(self_pid);
        webhook::write_log_critical("init", "kernel_anti_dump_ok");
    }

    webhook::write_log_critical("init", "anti_dump_seal_handles_entering");
    finalize_call_anti_dump_seal_seh();
    webhook::write_log_critical("init", "seal_handles_ok");

    webhook::write_log_critical("init", "standalone_anti_dump_seal_handles_entering");
    finalize_call_standalone_anti_dump_seal_seh();
    webhook::write_log_critical("init", "standalone_seal_handles_ok");


    try
    {
        std::atomic<bool> test_done{false};
        std::thread([&test_done]() { test_done.store(true); }).join();
        webhook::write_log_critical("init", test_done.load()
            ? "post_seal_thread_test_PASS"
            : "post_seal_thread_test_FAIL_no_exec");
    }
    catch (const std::exception& ex)
    {
        char buf[256];
        _snprintf_s(buf, sizeof(buf), _TRUNCATE,
            "post_seal_thread_test_FAIL: %s", ex.what());
        webhook::write_log_critical("init", buf);
    }
    catch (...)
    {
        webhook::write_log_critical("init", "post_seal_thread_test_FAIL_unknown");
    }

    webhook::write_log_critical("init", "hide_module_entering");
    finalize_call_hide_module_seh();
    webhook::write_log_critical("init", "hide_peb_ok");

    webhook::write_log_critical("init", "post_finalize_integrity_resnap_entering");
    finalize_post_resnap_seh();

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
            enforce_violation("ghost_veh_unhooked", "");
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
            enforce_violation("integrity_chain_stale");
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
            enforce_violation("unpack_timing_anomaly");
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
            enforce_violation("debugger_runtime", dbg.summary);
            CFF_EXIT(guard_cff);
        }
        CFF_GOTO(guard_cff, 4);
    }
    CFF_STATE(guard_cff, 4)
    {
#if !defined(AIDA_TEST_VMWARE_BYPASS)
        auto hook = anti_hook::full_scan(rt.iat_snap);
        if (hook.any_detected())
        {
            webhook::send_debug_log("guard", "hook_detected: " + hook.summary, true);
            enforce_violation("hook_runtime", hook.summary);
            CFF_EXIT(guard_cff);
        }
#endif
        CFF_GOTO(guard_cff, 5);
    }
    CFF_STATE(guard_cff, 5)
    {
        DECOY_CRYPTO_INTEGRATED(g5);
        bool self_hash_ok = integrity::verify_self_hash();
        if (!self_hash_ok)
        {
            webhook::send_debug_log("guard", "code_integrity_fail", true);
            enforce_violation("code_integrity_runtime");
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
            enforce_violation("page_mac_periodic_mismatch", detail);
            CFF_EXIT(guard_cff);
        }
        CFF_GOTO(guard_cff, 6);
    }
    CFF_STATE(guard_cff, 6)
    {
        bool bc_ok = integrity::verify_block_chain(rt.code_snap, rt.block_chain);
        if (!bc_ok)
        {
            webhook::send_debug_log("guard", "block_chain_fail", true);
            enforce_violation("block_chain_runtime");
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
            enforce_violation("call_obfuscation_tamper");
            CFF_EXIT(guard_cff);
        }


        call_obfuscation::re_encrypt_all();

        bool nano_ok = nanomites::verify_table_integrity();
        if (!nano_ok)
        {
            webhook::send_debug_log("guard", "nanomite_table_tamper", true);
            enforce_violation("nanomite_table_tamper");
            CFF_EXIT(guard_cff);
        }
        nanomites::rotate_keys();

#if defined(AIDA_DEEP_STEAL)
        bool bb_ok = stolen_bytes::verify_basic_blocks();
        if (!bb_ok)
        {
            webhook::send_debug_log("guard", "stolen_basic_block_tamper", true);
            enforce_violation("stolen_basic_block_tamper");
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
            driver_bridge::kernel_anti_debug_clear_dr();

#if !defined(AIDA_TEST_VMWARE_BYPASS)
            uint64_t debugger_pid = 0;
            driver_bridge::kernel_anti_debug_scan_debuggers(&debugger_pid);
            if (debugger_pid != 0)
            {
                webhook::send_debug_log("guard", "kernel_debugger_runtime_" + std::to_string(debugger_pid), true);
                enforce_violation("kernel_debugger_runtime");
                CFF_EXIT(guard_cff);
            }
#endif

            driver_bridge::kernel_anti_debug_clear_process_dr(GetCurrentProcessId());
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
                enforce_violation("license_killed", err);
                CFF_EXIT(guard_cff);
            }
            webhook::write_log("guard", "license_pending_activation_skip");
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
                    enforce_violation("arc_required", "arc_missing_after_activation");
                    CFF_EXIT(guard_cff);
                }
            }
        }

        if (driver_bridge::is_loaded() && driver_bridge::using_kernel_driver())
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

                constexpr uint32_t kHardFlags =
                    0x00000001u |
                    0x00000008u;

                constexpr uint32_t kSoftFlags =
                    0x00000002u |
                    0x00000010u |
                    0x00000040u;

                constexpr uint64_t kKernelDetectionSettleGraceMs = 3000;

                const uint32_t flags = adbg_result.result_flags;
                const bool hard_hit  = (flags & kHardFlags) != 0;
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
                    enforce_violation("kernel_detection_active", extra_buf);
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
            enforce_violation("writable_code_page");
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
            enforce_violation("watchdog_worker_anomaly", dbg);
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
                    enforce_violation("watchdog_workers_stalled", dbg);
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
                        enforce_violation("reattest_failure", "5min_re_attestation_failed");
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

inline void start_monitors()
{
    auto& rt = state::get();
    if (rt.monitors_running.exchange(true))
        return;

    rt.watchdog_running.store(true, std::memory_order_release);

    try
    {
        std::thread(watchdog_detail::monitor_loop).detach();

        std::thread([]() {
            auto& rt = state::get();
            watchdog_detail::worker_loop(0,
                rt.worker_a_last_tick_ms, rt.witness_chain_a);
            webhook::write_log("watchdog_worker_a", "exiting");
        }).detach();

        std::thread([]() {
            auto& rt = state::get();
            watchdog_detail::worker_loop(1,
                rt.worker_b_last_tick_ms, rt.witness_chain_b);
            webhook::write_log("watchdog_worker_b", "exiting");
        }).detach();

        std::thread([]() {
            auto& rt = state::get();
            watchdog_detail::worker_loop(2,
                rt.worker_c_last_tick_ms, rt.witness_chain_c);
            webhook::write_log("watchdog_worker_c", "exiting");
        }).detach();

        std::thread([]() {
            watchdog_detail::watchdog_loop();
            auto& rt = state::get();
            rt.watchdog_running.store(false, std::memory_order_release);
            webhook::write_log("watchdog", "exiting");
        }).detach();

        webhook::write_log("init", "watchdog_threads_started");
    }
    catch (const std::exception& ex)
    {
        char buf[256];
        _snprintf_s(buf, sizeof(buf), _TRUNCATE, "monitor_thread_exception: %s", ex.what());
        webhook::write_log("init", buf);
        rt.monitors_running.store(false);
        rt.watchdog_running.store(false);
    }
    catch (...)
    {
        webhook::write_log("init", "monitor_thread_failed_unknown");
        rt.monitors_running.store(false);
        rt.watchdog_running.store(false);
    }
}

inline void shutdown()
{
    auto& rt = state::get();
    rt.monitors_running.store(false);
    integrity::periodic::stop();
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
