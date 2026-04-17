#pragma once

#include <windows.h>

#include <cstdint>
#include <mutex>
#include <string>

#include "webhook.hpp"
#include "state.hpp"
#include "enforcement.hpp"
#include "integrity.hpp"
#include "anti_debug.hpp"
#include "anti_vm.hpp"
#include "anti_hook.hpp"
#include "anti_emulation.hpp"
#include "anti_dump.hpp"
#include "anti_ai.hpp"
#include "process_scan.hpp"
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

namespace anti_tamper {

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

inline bool initialize()
{
    auto& rt = state::get();
    std::lock_guard<std::mutex> lk(rt.mtx);

    if (rt.initialized.load()) return true;

    syscall::initialize();
    webhook::write_log("init", "syscall_ok");

    if (!integrity::snapshot_code(rt.code_snap))
        return false;
    webhook::write_log("init", "snapshot_code_ok");

    integrity::snapshot_iat(rt.iat_snap);
    webhook::write_log("init", "snapshot_iat_ok");

    integrity::build_block_chain(rt.code_snap, rt.block_chain);
    webhook::write_log("init", "block_chain_ok");

    token_chain::initialize_keys();
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

    code_encrypt::initialize(rt.code_snap.text_hash);
    webhook::write_log("init", "code_encrypt_ok");

    anti_dump::initialize();
    webhook::write_log("init", "anti_dump_ok");

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

    packer::encrypt_sections(rt.code_snap.text_hash ^ __rdtsc());
    webhook::write_log("init", "packer_encrypt_ok");

    packer::obfuscate_imports(static_cast<uint32_t>(rt.code_snap.text_hash));
    webhook::write_log("init", "packer_imports_ok");

    nanomites::initialize();
    webhook::write_log("init", "nanomites_ok");

    server_pages::initialize();
    webhook::write_log("init", "server_pages_ok");

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

        driver_bridge::kernel_anti_dump_full(self_pid);
        webhook::write_log("init", "kernel_anti_dump_ok");

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

    return true;
}

inline bool guard()
{
    auto& rt = state::get();

    CFF_BEGIN(guard_cff)
    CFF_STATE(guard_cff, 0)
    {
        if (rt.violation_latched.load(std::memory_order_acquire))
        {
            CFF_EXIT(guard_cff);
        }
        CFF_GOTO(guard_cff, 1);
    }
    CFF_STATE(guard_cff, 1)
    {
        if (token_chain::is_chain_stale())
        {
            webhook::send_debug_log("guard", "chain_stale", true);
            enforce_violation("integrity_chain_stale");
            CFF_EXIT(guard_cff);
        }
        CFF_GOTO(guard_cff, 2);
    }
    CFF_STATE(guard_cff, 2)
    {
        if (!packer::verify_unpack_timing())
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
        auto hook = anti_hook::full_scan(rt.iat_snap);
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
        if (!integrity::verify_self_hash())
        {
            webhook::send_debug_log("guard", "code_integrity_fail", true);
            enforce_violation("code_integrity_runtime");
            CFF_EXIT(guard_cff);
        }
        CFF_GOTO(guard_cff, 6);
    }
    CFF_STATE(guard_cff, 6)
    {
        if (!integrity::verify_block_chain(rt.code_snap, rt.block_chain))
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
        if (!call_obfuscation::verify_table_integrity())
        {
            webhook::send_debug_log("guard", "call_obfuscation_tamper", true);
            enforce_violation("call_obfuscation_tamper");
            CFF_EXIT(guard_cff);
        }


        call_obfuscation::re_encrypt_all();


        if (!nanomites::verify_table_integrity())
        {
            webhook::send_debug_log("guard", "nanomite_table_tamper", true);
            enforce_violation("nanomite_table_tamper");
            CFF_EXIT(guard_cff);
        }
        nanomites::rotate_keys();

        CFF_GOTO(guard_cff, 8);
    }
    CFF_STATE(guard_cff, 8)
    {
        if (driver_bridge::is_loaded() && driver_bridge::using_kernel_driver())
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
        if (!standalone_license::is_valid())
        {
            std::string err = standalone_license::last_error();
            webhook::send_debug_log("guard", "license_invalid: " + err, true);
            enforce_violation("license_killed", err);
            CFF_EXIT(guard_cff);
        }

        if (driver_bridge::is_loaded() && driver_bridge::using_kernel_driver())
        {
            driver_bridge::anti_debug_result_t adbg_result{};
            if (driver_bridge::kernel_anti_debug_query(adbg_result) &&
                adbg_result.result_flags != 0)
            {
                webhook::send_debug_log("guard",
                    "kernel_detection_flags_0x" + std::to_string(adbg_result.result_flags), true);
                enforce_violation("kernel_detection_active");
                CFF_EXIT(guard_cff);
            }
        }
    }
    CFF_END(guard_cff)

    return !rt.violation_latched.load(std::memory_order_acquire);
}

inline void shutdown()
{
    server_pages::shutdown();
    nanomites::shutdown();
    ai_deception::shutdown();
    code_encrypt::shutdown();
    packer::shutdown();
    anti_dump::shutdown();
    syscall::shutdown();
}

}
