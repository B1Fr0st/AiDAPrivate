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

namespace anti_tamper {

inline uint64_t run_inline_check(check_class_t which, uint64_t proof_hash = 0)
{
    return token_chain::run_inline_check(which, proof_hash);
}

inline bool initialize()
{
    auto& rt = state::get();
    std::lock_guard<std::mutex> lk(rt.mtx);

    if (rt.initialized.load()) return true;

    syscall::initialize();

    if (!integrity::snapshot_code(rt.code_snap))
        return false;

    integrity::snapshot_iat(rt.iat_snap);

    integrity::build_block_chain(rt.code_snap, rt.block_chain);

    token_chain::initialize_keys();

    {
        auto dbg = anti_debug::full_scan(rt.code_snap.module_base, rt.code_snap.module_end);
        if (dbg.any_detected())
        {
            webhook::send_debug_log("init", "debugger_at_startup: " + dbg.summary, true);
            enforce_violation("debugger_at_startup", dbg.summary);
            return false;
        }
    }

    {
        auto hook = anti_hook::full_scan(rt.iat_snap);
        if (hook.any_detected())
        {
            webhook::send_debug_log("init", "hook_at_startup: " + hook.summary, true);
            enforce_violation("hook_at_startup", hook.summary);
            return false;
        }
    }

    anti_vm::full_scan();

    virtualizer::initialize(
        rt.code_snap.text_base,
        rt.code_snap.text_size,
        rt.code_snap.text_hash);

    code_encrypt::initialize(rt.code_snap.text_hash);

    anti_dump::initialize();

    metamorphic::initialize();

    cloakwork::initialize(rt.code_snap.text_hash);

    ai_deception::initialize();

    // Packer: encrypt sections + obfuscate imports
    packer::encrypt_sections(rt.code_snap.text_hash ^ __rdtsc());
    packer::obfuscate_imports(static_cast<uint32_t>(rt.code_snap.text_hash));

    if (driver_bridge::is_loaded() && driver_bridge::using_kernel_driver())
    {
        driver_bridge::register_dll_protection(
            rt.code_snap.module_base,
            rt.code_snap.text_base,
            rt.code_snap.text_size,
            rt.code_snap.text_hash,
            2000
        );
    }

    anti_debug::hide_thread_from_debugger(GetCurrentThread());

    rt.initialized.store(true);

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
    }
    CFF_END(guard_cff)

    return !rt.violation_latched.load(std::memory_order_acquire);
}

inline void shutdown()
{
    ai_deception::shutdown();
    code_encrypt::shutdown();
    packer::shutdown();
    anti_dump::shutdown();
    syscall::shutdown();
}

}
