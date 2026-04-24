#pragma once

#include <windows.h>
#include <psapi.h>

#include <cstdint>
#include <mutex>
#include <string>
#include <thread>

#include "webhook.hpp"
#include "state.hpp"
#include "enforcement.hpp"
#include "integrity.hpp"
#include "anti_debug.hpp"
#include "anti_vm.hpp"
#include "anti_hook.hpp"
#include "anti_emulation.hpp"
#include "anti_dump.hpp"
#include "virtualizer.hpp"
#include "code_encrypt.hpp"
#include "metamorphic.hpp"
#include "cloakwork.hpp"
#include "ai_deception.hpp"
#include "token_chain.hpp"
#include "syscall.hpp"
#include "packer.hpp"
#include "cff.hpp"
#include "call_obfuscation.hpp"
#include "decoy_call_graph.hpp"
#include "nanomites.hpp"
#include "server_pages.hpp"
#include "vm_compiler.hpp"
#include "stolen_bytes.hpp"
#include "../standalone_anti_dump.hpp"
#include "re_detection_engine.hpp"
#include "ghost_veh.hpp"

#include "../../../obfuscation.hpp"

namespace anti_tamper {

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

    virtualizer::detail::vm_state_t tmp_vm;
    virtualizer::detail::init_vm(tmp_vm, seed);

    auto lifted = vm_compiler::x86_lifter::compile_function(
        static_cast<const uint8_t*>(func), func_len,
        base_addr, seed ^ 0x6A09E667F3BCC908ULL, tmp_vm.opcode_map);

    virtualizer::detail::destroy_vm(tmp_vm);

    if (lifted.bytecode.empty()) return false;

    return virtualizer::protection::protect_function(
        func, func_len, lifted.bytecode, seed);
}
#endif

inline void start_monitors();

inline bool initialize()
{
    auto& rt = state::get();
    std::lock_guard<std::mutex> lk(rt.mtx);

    if (rt.initialized.load()) return true;

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

        void* canary = VirtualAlloc(nullptr, 4096, MEM_COMMIT | MEM_RESERVE, PAGE_NOACCESS);
        if (canary != nullptr)
        {
            rt.canary_page = canary;
            driver_bridge::canary_register(canary, 4096);
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

    anti_vm::full_scan();
    webhook::write_log("init", "anti_vm_ok");

    virtualizer::initialize(
        rt.code_snap.text_base,
        rt.code_snap.text_size,
        rt.code_snap.text_hash);
    webhook::write_log("init", "virtualizer_ok");

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


        uint64_t debugger_pid = 0;
        driver_bridge::kernel_anti_debug_scan_debuggers(&debugger_pid);
        if (debugger_pid != 0)
        {
            webhook::send_debug_log("init", "kernel_debugger_detected_pid_" + std::to_string(debugger_pid), true);
            enforce_violation("kernel_debugger_at_startup");
            return false;
        }
        webhook::write_log("init", "kernel_debugger_scan_ok");
    }
    else
    {
        webhook::write_log("init", "driver_bridge_skipped");
    }

    anti_debug::hide_thread_from_debugger(GetCurrentThread());
    webhook::write_log("init", "hide_thread_ok");

    rt.initialized.store(true);
    webhook::write_log("init", "initialized_ok");


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


    try
    {
        webhook::write_log("init", "anti_dump_entering");
        anti_dump::initialize();
        webhook::write_log("init", "anti_dump_ok");
    }
    catch (const std::exception& ex)
    {
        webhook::write_log("init", (std::string("anti_dump_exception: ") + ex.what()).c_str());
    }
    catch (...)
    {
        webhook::write_log("init", "anti_dump_unknown_exception");
    }

    try
    {
        webhook::write_log("init", "standalone_anti_dump_entering");
        standalone_anti_dump::initialize();
        webhook::write_log("init", "standalone_anti_dump_ok");
    }
    catch (const std::exception& ex)
    {
        webhook::write_log("init", (std::string("standalone_anti_dump_exception: ") + ex.what()).c_str());
    }
    catch (...)
    {
        webhook::write_log("init", "standalone_anti_dump_unknown_exception");
    }


    if (driver_bridge::is_loaded() && driver_bridge::using_kernel_driver())
    {
        uint32_t self_pid = GetCurrentProcessId();
        driver_bridge::kernel_anti_dump_full(self_pid);
        webhook::write_log("init", "kernel_anti_dump_ok");
    }

    anti_dump::seal_handles();
    webhook::write_log("init", "seal_handles_ok");

    standalone_anti_dump::seal_handles();
    webhook::write_log("init", "standalone_seal_handles_ok");


    try
    {
        std::atomic<bool> test_done{false};
        std::thread([&test_done]() { test_done.store(true); }).join();
        webhook::write_log("init", test_done.load()
            ? "post_seal_thread_test_PASS"
            : "post_seal_thread_test_FAIL_no_exec");
    }
    catch (const std::exception& ex)
    {
        char buf[256];
        _snprintf_s(buf, sizeof(buf), _TRUNCATE,
            "post_seal_thread_test_FAIL: %s", ex.what());
        webhook::write_log("init", buf);
    }
    catch (...)
    {
        webhook::write_log("init", "post_seal_thread_test_FAIL_unknown");
    }

    anti_dump::hide_module();
    webhook::write_log("init", "hide_peb_ok");

    return true;
}

inline bool guard()
{
    static bool s_first_guard = true;
    static uint64_t s_guard_call_count = 0;
    ++s_guard_call_count;
    if (s_first_guard) {
        webhook::write_log("guard", "first_guard_entry");
        s_first_guard = false;
    }

    auto& rt = state::get();

    CFF_BEGIN(guard_cff)
    CFF_STATE(guard_cff, 0)
    {
        if (s_guard_call_count <= 3 || (s_guard_call_count % 5) == 0) {
            char dbg[128];
            _snprintf_s(dbg, sizeof(dbg), _TRUNCATE, "guard_iter=%llu state=0 violation_latched=%d",
                s_guard_call_count, rt.violation_latched.load() ? 1 : 0);
            webhook::write_log("guard", dbg);
        }
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
        if (s_guard_call_count <= 3) {
            char dbg[128];
            _snprintf_s(dbg, sizeof(dbg), _TRUNCATE, "guard_iter=%llu state=1 chain_stale=%d",
                s_guard_call_count, chain_stale ? 1 : 0);
            webhook::write_log("guard", dbg);
        }
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
        if (s_guard_call_count <= 3) {
            char dbg[128];
            _snprintf_s(dbg, sizeof(dbg), _TRUNCATE, "guard_iter=%llu state=2 unpack_timing_ok=%d",
                s_guard_call_count, unpack_ok ? 1 : 0);
            webhook::write_log("guard", dbg);
        }
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
        {
            char dbg_buf[256];
            _snprintf_s(dbg_buf, sizeof(dbg_buf), _TRUNCATE,
                "guard_iter=%llu state=3 anti_debug_any=%d summary=%s",
                s_guard_call_count, dbg.any_detected() ? 1 : 0,
                dbg.summary.empty() ? "none" : dbg.summary.c_str());
            webhook::write_log("guard", dbg_buf);
        }
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
        if (s_guard_call_count <= 3) {
            char dbg[128];
            _snprintf_s(dbg, sizeof(dbg), _TRUNCATE,
                "guard_iter=%llu state=4 iat_snap_size=%zu entering_hook_scan",
                s_guard_call_count, rt.iat_snap.size());
            webhook::write_log("guard", dbg);
        }
        auto hook = anti_hook::full_scan(rt.iat_snap);
        if (s_guard_call_count <= 3) {
            char dbg[256];
            _snprintf_s(dbg, sizeof(dbg), _TRUNCATE,
                "guard_iter=%llu state=4 hook_any=%d iat=%d ntdll=%d k32=%d syscall=%d eat=%d summary=%s",
                s_guard_call_count, hook.any_detected() ? 1 : 0,
                hook.iat_modified ? 1 : 0, hook.ntdll_inline_hooked ? 1 : 0,
                hook.kernel32_inline_hooked ? 1 : 0, hook.syscall_stubs_modified ? 1 : 0,
                hook.eat_hooked ? 1 : 0,
                hook.summary.empty() ? "none" : hook.summary.c_str());
            webhook::write_log("guard", dbg);
        }
        if (hook.any_detected())
        {
            webhook::send_debug_log("guard", "hook_detected: " + hook.summary, true);
            enforce_violation("hook_runtime", hook.summary);
            CFF_EXIT(guard_cff);
        }
        CFF_GOTO(guard_cff, 5);
    }
    CFF_STATE(guard_cff, 5)
    {
        DECOY_CRYPTO_INTEGRATED(g5);
        bool self_hash_ok = integrity::verify_self_hash();
        if (s_guard_call_count <= 3) {
            char dbg[128];
            _snprintf_s(dbg, sizeof(dbg), _TRUNCATE,
                "guard_iter=%llu state=5 self_hash_ok=%d",
                s_guard_call_count, self_hash_ok ? 1 : 0);
            webhook::write_log("guard", dbg);
        }
        if (!self_hash_ok)
        {
            webhook::send_debug_log("guard", "code_integrity_fail", true);
            enforce_violation("code_integrity_runtime");
            CFF_EXIT(guard_cff);
        }
        CFF_GOTO(guard_cff, 6);
    }
    CFF_STATE(guard_cff, 6)
    {
        bool bc_ok = integrity::verify_block_chain(rt.code_snap, rt.block_chain);
        if (s_guard_call_count <= 3) {
            char dbg[128];
            _snprintf_s(dbg, sizeof(dbg), _TRUNCATE,
                "guard_iter=%llu state=6 block_chain_ok=%d",
                s_guard_call_count, bc_ok ? 1 : 0);
            webhook::write_log("guard", dbg);
        }
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
        if (s_guard_call_count <= 3) {
            char dbg[128];
            _snprintf_s(dbg, sizeof(dbg), _TRUNCATE,
                "guard_iter=%llu state=7 call_obf_ok=%d",
                s_guard_call_count, call_obf_ok ? 1 : 0);
            webhook::write_log("guard", dbg);
        }
        if (!call_obf_ok)
        {
            webhook::send_debug_log("guard", "call_obfuscation_tamper", true);
            enforce_violation("call_obfuscation_tamper");
            CFF_EXIT(guard_cff);
        }


        call_obfuscation::re_encrypt_all();

        bool nano_ok = nanomites::verify_table_integrity();
        if (s_guard_call_count <= 3) {
            char dbg[128];
            _snprintf_s(dbg, sizeof(dbg), _TRUNCATE,
                "guard_iter=%llu state=7 nanomite_ok=%d",
                s_guard_call_count, nano_ok ? 1 : 0);
            webhook::write_log("guard", dbg);
        }
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
        if (s_guard_call_count <= 3) {
            char dbg[128];
            _snprintf_s(dbg, sizeof(dbg), _TRUNCATE,
                "guard_iter=%llu state=8 drv_loaded=%d drv_kernel=%d",
                s_guard_call_count, drv_loaded ? 1 : 0, drv_kernel ? 1 : 0);
            webhook::write_log("guard", dbg);
        }
        if (drv_kernel)
        {
            driver_bridge::kernel_anti_debug_clear_dr();

            uint64_t debugger_pid = 0;
            driver_bridge::kernel_anti_debug_scan_debuggers(&debugger_pid);
            if (debugger_pid != 0)
            {
                webhook::send_debug_log("guard", "kernel_debugger_runtime_" + std::to_string(debugger_pid), true);
                enforce_violation("kernel_debugger_runtime");
                CFF_EXIT(guard_cff);
            }

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
        {
            char dbg[256];
            _snprintf_s(dbg, sizeof(dbg), _TRUNCATE,
                "guard_iter=%llu state=9 license_valid=%d",
                s_guard_call_count, lic_valid ? 1 : 0);
            webhook::write_log("guard", dbg);
        }
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
            if (activation_completed_at != 0 && !standalone_license::is_arc_loaded())
            {
                constexpr uint64_t kArcRequiredGraceMs = 60000;
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
        {
            char dbg[256];
            _snprintf_s(dbg, sizeof(dbg), _TRUNCATE,
                "page_scan_ok iter=%llu text_base=0x%llX text_size=0x%X",
                s_guard_call_count, rt.code_snap.text_base, (unsigned)rt.code_snap.text_size);
            webhook::write_log("guard", dbg);
        }
        CFF_EXIT(guard_cff);
    }
    CFF_END(guard_cff)

    ++rt.verify_counter;

    return !rt.violation_latched.load(std::memory_order_acquire);
}

inline void start_monitors()
{
    auto& rt = state::get();
    if (rt.monitors_running.exchange(true))
        return;

    try
    {
        std::thread([]() {
            Sleep(5000);
            webhook::write_log("monitor", "thread_started");
            auto& rt = state::get();
            uint64_t iter = 0;
            while (rt.monitors_running.load() && !rt.violation_latched.load())
            {
                ++iter;
                try
                {
                    {
                        char dbg[128];
                        _snprintf_s(dbg, sizeof(dbg), _TRUNCATE,
                            "monitor_loop iter=%llu verify_counter=%u violation=%d",
                            iter, rt.verify_counter, rt.violation_latched.load() ? 1 : 0);
                        webhook::write_log("monitor", dbg);
                    }
                    bool guard_result = guard();
                    {
                        char dbg[128];
                        _snprintf_s(dbg, sizeof(dbg), _TRUNCATE,
                            "guard_returned=%d iter=%llu verify_counter=%u",
                            guard_result ? 1 : 0, iter, rt.verify_counter);
                        webhook::write_log("monitor", dbg);
                    }
                    enforcement_tick();
                }
                catch (const std::exception& ex)
                {
                    char ebuf[256];
                    _snprintf_s(ebuf, sizeof(ebuf), _TRUNCATE,
                        "monitor_loop_EXCEPTION iter=%llu what=%s", iter, ex.what());
                    webhook::write_log("monitor", ebuf);
                }
                catch (...)
                {
                    char ebuf[128];
                    _snprintf_s(ebuf, sizeof(ebuf), _TRUNCATE,
                        "monitor_loop_UNKNOWN_EXCEPTION iter=%llu", iter);
                    webhook::write_log("monitor", ebuf);
                }
                Sleep(500);
            }
            char dbg[128];
            _snprintf_s(dbg, sizeof(dbg), _TRUNCATE,
                "thread_exiting monitors_running=%d violation_latched=%d iter=%llu",
                rt.monitors_running.load() ? 1 : 0, rt.violation_latched.load() ? 1 : 0, iter);
            webhook::write_log("monitor", dbg);
        }).detach();
    }
    catch (const std::exception& ex)
    {
        char buf[256];
        _snprintf_s(buf, sizeof(buf), _TRUNCATE, "monitor_thread_exception: %s", ex.what());
        webhook::write_log("init", buf);
        rt.monitors_running.store(false);
    }
    catch (...)
    {
        webhook::write_log("init", "monitor_thread_failed_unknown");
        rt.monitors_running.store(false);
    }
}

inline void shutdown()
{
    auto& rt = state::get();
    rt.monitors_running.store(false);
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
