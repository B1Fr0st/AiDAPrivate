#pragma once

#include <windows.h>

#include <cstdint>
#include <string>

#include "state.hpp"
#include "webhook.hpp"
#include "syscall.hpp"
#include "../standalone_license.hpp"
#include "../standalone_driver.hpp"

namespace anti_tamper {

namespace enforcement_detail {

    inline __declspec(noinline) void kill_path_kernel()
    {
        if (driver_bridge::is_loaded() && driver_bridge::using_kernel_driver())
        {
            auto& rt = state::get();
            driver_bridge::trigger_kernel_bsod(
                0x0002u,
                rt.code_snap.text_hash
            );
        }
    }

    inline __declspec(noinline) void kill_path_hard_error()
    {
        if (syscall::is_initialized())
        {
            BOOLEAN wasEnabled = FALSE;
            syscall::RtlAdjustPrivilege()(19, TRUE, FALSE, &wasEnabled);

            ULONG response = 0;
            syscall::NtRaiseHardError()(
                static_cast<NTSTATUS>(0xC0000420),
                0, 0, nullptr, 6, &response);
        }
    }

    inline __declspec(noinline) void kill_path_fastfail()
    {
        __fastfail(FAST_FAIL_FATAL_APP_EXIT);
    }

    inline __declspec(noinline) void kill_path_corrupt_stack()
    {
        volatile uint64_t* rsp;
        #if defined(_MSC_VER)
            rsp = reinterpret_cast<volatile uint64_t*>(_AddressOfReturnAddress());
        #endif
        if (rsp)
            *rsp ^= 0xDEADC0DEULL;
    }

    inline __declspec(noinline) void execute_all_kill_paths()
    {
        kill_path_kernel();
        kill_path_hard_error();
        kill_path_corrupt_stack();
        kill_path_fastfail();
    }

}

inline void enforce_violation(const char* reason, const std::string& extra = "")
{
    auto& rt = state::get();

    if (rt.violation_latched.exchange(true))
        return;

    {
        std::lock_guard<std::mutex> lk(rt.mtx);
        rt.violation_reason = reason ? reason : "anti_tamper";
    }

    webhook::send_violation_alert(reason ? reason : "anti_tamper", extra);

    standalone_license::shutdown();

    enforcement_detail::execute_all_kill_paths();
}

inline void enforcement_tick()
{
}

}
