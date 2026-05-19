#pragma once

#include <windows.h>
#include <bcrypt.h>

#include <atomic>
#include <cstdint>
#include <cstring>
#include <mutex>
#include <string>

#include "../runtime/reason_ids.hpp"
#include "webhook.hpp"

#pragma comment(lib, "bcrypt.lib")

namespace anti_tamper {

void enforce_violation_id(uint64_t reason_id, const std::string& extra);

namespace dr_check {

namespace detail {

    using nt_get_context_thread_fn = LONG(NTAPI*)(HANDLE, PCONTEXT);

    inline nt_get_context_thread_fn& resolved_fn()
    {
        static nt_get_context_thread_fn f = nullptr;
        return f;
    }

    inline std::once_flag& resolve_once_flag()
    {
        static std::once_flag o;
        return o;
    }

    inline void resolve_fn_once()
    {
        std::call_once(resolve_once_flag(), []() {
            HMODULE nt = GetModuleHandleW(L"ntdll.dll");
            if (!nt)
                return;
            FARPROC p = GetProcAddress(nt, "NtGetContextThread");
            resolved_fn() = reinterpret_cast<nt_get_context_thread_fn>(p);
        });
    }

    inline std::atomic<uint32_t>& gate_counter_for_slot(uint32_t slot_id)
    {
        constexpr uint32_t kSlotMax = 64;
        static std::atomic<uint32_t> slots[kSlotMax]{};
        return slots[slot_id % kSlotMax];
    }

    inline std::atomic<uint32_t>& gate_threshold_for_slot(uint32_t slot_id)
    {
        constexpr uint32_t kSlotMax = 64;
        static std::atomic<uint32_t> slots[kSlotMax]{};
        return slots[slot_id % kSlotMax];
    }

    inline uint32_t random_cadence()
    {
        uint32_t v = 0;
        NTSTATUS s = BCryptGenRandom(nullptr,
            reinterpret_cast<PUCHAR>(&v), sizeof(v),
            BCRYPT_USE_SYSTEM_PREFERRED_RNG);
        if (s != 0)
        {
            return 17u;
        }
        return (v & 0x1Fu) + 8u;
    }

}

inline bool any_hw_breakpoint_set()
{
    detail::resolve_fn_once();
    auto fn = detail::resolved_fn();
    if (!fn) return false;

    CONTEXT ctx{};
    ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
    LONG status = fn(GetCurrentThread(), &ctx);
    if (status < 0) return false;

    if ((ctx.Dr0 | ctx.Dr1 | ctx.Dr2 | ctx.Dr3) != 0)
        return true;
    if ((ctx.Dr7 & 0xFFu) != 0)
        return true;
    return false;
}

inline void on_gate_call_random_check(uint32_t slot_id)
{
    auto& counter = detail::gate_counter_for_slot(slot_id);
    auto& threshold = detail::gate_threshold_for_slot(slot_id);

    uint32_t t = threshold.load(std::memory_order_acquire);
    if (t == 0)
    {
        t = detail::random_cadence();
        threshold.store(t, std::memory_order_release);
    }

    uint32_t prev = counter.fetch_add(1, std::memory_order_acq_rel);
    if (prev + 1 < t)
        return;

    counter.store(0, std::memory_order_release);
    threshold.store(detail::random_cadence(), std::memory_order_release);

    if (!any_hw_breakpoint_set())
        return;

    char buf[96];
    _snprintf_s(buf, sizeof(buf), _TRUNCATE,
        "dr_check_slot=%u id=0x%016llX",
        slot_id,
        static_cast<unsigned long long>(
            aida::reason_ids::reason_id_hardware_breakpoint_in_code));
    webhook::write_log_critical("dr_check", buf);

    std::string slot_buf("slot=");
    char num[16];
    _snprintf_s(num, sizeof(num), _TRUNCATE, "%u", slot_id);
    slot_buf += num;
    anti_tamper::enforce_violation_id(
        aida::reason_ids::reason_id_hardware_breakpoint_in_code,
        slot_buf);
}

}
}
