#pragma once

#include <windows.h>
#include <bcrypt.h>

#include <cstdint>
#include <string>
#include <thread>
#include <atomic>
#include <chrono>

#include "state.hpp"
#include "webhook.hpp"
#include "syscall.hpp"
#include "obfuscation_macros.hpp"
#include "standalone_license.hpp"
#include "standalone_driver.hpp"
#include "../../helpers/diag_log.hpp"
#include "../../../../../libs/cpp-httplib/httplib.h"
#include "../../../../../libs/nlohmann/json.hpp"

#ifndef NT_SUCCESS
#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)
#endif

namespace anti_tamper {

namespace enforcement_detail {


    inline std::string get_payload_host()
    {
#ifdef AIDA_LOCAL_LICENSE_SERVER
        return "http://localhost:3001";
#else
        return "https://aidapro.net";
#endif
    }


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
        diag::log_tagged_critical("enforce", "kill_path_fastfail ABOUT_TO_FASTFAIL_FATAL_APP_EXIT");
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

    inline __declspec(noinline) void clear_process_critical_flags()
    {
        using NtSetInformationProcess_t = NTSTATUS(NTAPI*)(HANDLE, ULONG, PVOID, ULONG);
        auto pSet = reinterpret_cast<NtSetInformationProcess_t>(
            GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtSetInformationProcess"));
        if (!pSet) return;
        ULONG zero = 0;
        pSet(GetCurrentProcess(), 0x1D, &zero, sizeof(zero));
        pSet(GetCurrentProcess(), 0x3D, &zero, sizeof(zero));
    }

    inline __declspec(noinline) void execute_all_kill_paths()
    {
        webhook::write_log("enforce", "EXECUTING_ALL_KILL_PATHS");
        clear_process_critical_flags();
        kill_path_kernel();
        kill_path_hard_error();
        kill_path_corrupt_stack();
        kill_path_fastfail();
    }


    inline std::atomic<int> g_corruption_round{0};

    inline uint64_t corruption_prng(uint64_t& seed)
    {
        seed ^= seed >> 12;
        seed ^= seed << 25;
        seed ^= seed >> 27;
        return seed * 0x2545F4914F6CDD1DULL;
    }

    inline void silent_corrupt_text(int round)
    {
        HMODULE hMod = GetModuleHandleA(nullptr);
        if (!hMod) {
            webhook::write_log("enforce", "corrupt_text: no module handle");
            return;
        }

        auto* dos = reinterpret_cast<IMAGE_DOS_HEADER*>(hMod);
        if (dos->e_magic != IMAGE_DOS_SIGNATURE) {
            webhook::write_log("enforce", "corrupt_text: dos magic mismatch (expected after anti_dump)");
            return;
        }

        auto* nt = reinterpret_cast<IMAGE_NT_HEADERS64*>(
            reinterpret_cast<uint8_t*>(hMod) + dos->e_lfanew);
        if (nt->Signature != IMAGE_NT_SIGNATURE) {
            webhook::write_log("enforce", "corrupt_text: nt sig mismatch (expected after anti_dump)");
            return;
        }

        auto* sec = IMAGE_FIRST_SECTION(nt);
        uint8_t* text_base = nullptr;
        uint32_t text_size = 0;

        for (WORD i = 0; i < nt->FileHeader.NumberOfSections; ++i) {
            if (sec[i].Characteristics & IMAGE_SCN_MEM_EXECUTE) {
                text_base = reinterpret_cast<uint8_t*>(hMod) + sec[i].VirtualAddress;
                text_size = sec[i].Misc.VirtualSize;
                break;
            }
        }

        if (!text_base || text_size < 256) return;

        DWORD old_prot = 0;

        uint64_t seed = __rdtsc() ^ (static_cast<uint64_t>(round) << 32);

        switch (round) {
        case 1: {
            VirtualProtect(text_base, text_size, PAGE_EXECUTE_READWRITE, &old_prot);
            for (int i = 0; i < 16; ++i) {
                uint32_t offset = static_cast<uint32_t>(corruption_prng(seed) % (text_size - 1));
                text_base[offset] ^= static_cast<uint8_t>(corruption_prng(seed));
            }
            VirtualProtect(text_base, text_size, old_prot, &old_prot);
            break;
        }
        case 2: {
            VirtualProtect(text_base, text_size, PAGE_EXECUTE_READWRITE, &old_prot);
            for (int i = 0; i < 256; ++i) {
                uint32_t offset = static_cast<uint32_t>(corruption_prng(seed) % (text_size - 1));
                text_base[offset] = static_cast<uint8_t>(corruption_prng(seed));
            }
            auto* rdata_sec = IMAGE_FIRST_SECTION(nt);
            for (WORD i = 0; i < nt->FileHeader.NumberOfSections; ++i) {
                if (rdata_sec[i].Name[1] == 'r' && rdata_sec[i].Name[2] == 'd') {
                    uint8_t* rdata = reinterpret_cast<uint8_t*>(hMod) + rdata_sec[i].VirtualAddress;
                    uint32_t rdata_size = rdata_sec[i].Misc.VirtualSize;
                    DWORD rp = 0;
                    VirtualProtect(rdata, rdata_size, PAGE_READWRITE, &rp);
                    for (int j = 0; j < 64; ++j) {
                        uint32_t off = static_cast<uint32_t>(corruption_prng(seed) % (rdata_size - 1));
                        rdata[off] ^= static_cast<uint8_t>(corruption_prng(seed));
                    }
                    VirtualProtect(rdata, rdata_size, rp, &rp);
                    break;
                }
            }
            VirtualProtect(text_base, text_size, old_prot, &old_prot);
            break;
        }
        case 3: {
            VirtualProtect(text_base, text_size, PAGE_EXECUTE_READWRITE, &old_prot);
            uint32_t page_count = text_size / 4096;
            for (uint32_t p = 0; p < page_count; ++p) {
                if ((corruption_prng(seed) & 3) == 0) {
                    uint8_t* page = text_base + p * 4096;
                    for (int b = 0; b < 4096; ++b)
                        page[b] = static_cast<uint8_t>(corruption_prng(seed));
                }
            }
            VirtualProtect(text_base, text_size, old_prot, &old_prot);
            break;
        }
        }
    }

    static void violation_post_impl(int round)
    {
        try {
            std::string host = get_payload_host();
            httplib::Client cli(host);
            cli.set_address_family(AF_INET);
            cli.set_connection_timeout(5);
            cli.set_read_timeout(5);
            cli.enable_server_certificate_verification(true);

            nlohmann::json body;
            body["session_token"] = standalone_license::get_session_token();
            body["corruption_round"] = round;
            body["tsc"] = __rdtsc();

            std::string body_str = body.dump();
            cli.Post("/api/license/violation", body_str, "application/json");
        } catch (...) {}
    }

    __declspec(noinline) static DWORD seh_violation_post(int round)
    {
        __try {
            violation_post_impl(round);
            return 0;
        } __except (EXCEPTION_EXECUTE_HANDLER) {
            return GetExceptionCode();
        }
    }

    inline void graduated_enforcement()
    {
        int round = g_corruption_round.fetch_add(1) + 1;

        {
            char dbg[128];
            _snprintf_s(dbg, sizeof(dbg), _TRUNCATE,
                "graduated_enforcement round=%d", round);
            webhook::write_log("enforce", dbg);
        }

        if (round == 1) {
            DWORD seh_post = seh_violation_post(round);
            if (seh_post != 0) {
                char dbg[64];
                _snprintf_s(dbg, sizeof(dbg), _TRUNCATE, "violation_post_seh=0x%08X", seh_post);
                webhook::write_log("enforce", dbg);
            }
        } else if (round <= 3) {
            silent_corrupt_text(round);

            DWORD seh_post = seh_violation_post(round);
            if (seh_post != 0) {
                char dbg[64];
                _snprintf_s(dbg, sizeof(dbg), _TRUNCATE, "violation_post_seh=0x%08X", seh_post);
                webhook::write_log("enforce", dbg);
            }

            if (round == 3) {
                execute_all_kill_paths();
            }
        } else {
            execute_all_kill_paths();
        }
    }

}

inline void enforce_violation(const char* reason, const std::string& extra = "")
{
    auto& rt = state::get();

    {
        char enforce_dbg[512];
        _snprintf_s(enforce_dbg, sizeof(enforce_dbg), _TRUNCATE,
            "ENFORCE_VIOLATION reason=%s extra=%s already_latched=%d",
            reason ? reason : "null",
            extra.empty() ? "none" : extra.c_str(),
            rt.violation_latched.load() ? 1 : 0);
        diag::log_tagged_critical("enforce", enforce_dbg);
    }

    OBFUSCATE_JUNK(ev_pre);

    if (rt.violation_latched.exchange(true)) {
        diag::log_tagged_critical("enforce", "already_latched_returning");
        return;
    }

    diag::log_tagged_critical("enforce", "ev_cff_state_0_entering_set_reason");
    CFF_BEGIN(ev_cff)
    CFF_STATE(ev_cff, 0)
    {
        {
            std::lock_guard<std::mutex> lk(rt.mtx);
            rt.violation_reason = reason ? reason : "anti_tamper";
        }
        diag::log_tagged_critical("enforce", "ev_cff_state_0_done_goto_1");
        CFF_GOTO(ev_cff, 1);
    }
    CFF_STATE(ev_cff, 1)
    {
        diag::log_tagged_critical("enforce", "ev_cff_state_1_calling_send_violation_alert");
        OBFUSCATE_JUNK(ev_wh);
        webhook::send_violation_alert(reason ? reason : "anti_tamper", extra);
        diag::log_tagged_critical("enforce", "ev_cff_state_1_done_goto_2");
        CFF_GOTO(ev_cff, 2);
    }
    CFF_STATE(ev_cff, 2)
    {
        diag::log_tagged_critical("enforce", "ev_cff_state_2_calling_license_shutdown");
        standalone_license::shutdown();
        diag::log_tagged_critical("enforce", "ev_cff_state_2_done_goto_3");
        CFF_GOTO(ev_cff, 3);
    }
    CFF_STATE(ev_cff, 3)
    {
        diag::log_tagged_critical("enforce", "ev_cff_state_3_calling_graduated_enforcement");
        OBFUSCATE_JUNK(ev_grad);
        enforcement_detail::graduated_enforcement();
        diag::log_tagged_critical("enforce", "ev_cff_state_3_returned_from_graduated");
    }
    CFF_END(ev_cff)
    diag::log_tagged_critical("enforce", "enforce_violation_returning_normally");
}

namespace enforcement {

    inline int64_t now_ms()
    {
        FILETIME ft;
        GetSystemTimeAsFileTime(&ft);
        ULARGE_INTEGER ui;
        ui.LowPart  = ft.dwLowDateTime;
        ui.HighPart = ft.dwHighDateTime;
        return static_cast<int64_t>(ui.QuadPart / 10000ULL);
    }

    inline int64_t degrade_delay_ms()
    {
        char buf[32] = {};
        DWORD n = GetEnvironmentVariableA("AIDA_DECOY_DEGRADE_MS", buf, 31);
        if (n > 0 && n < 31)
        {
            int64_t v = _atoi64(buf);
            if (v > 0 && v < 24LL * 3600LL * 1000LL)
                return v;
        }
        return 10LL * 60LL * 1000LL;
    }

    inline void degrade_mode()
    {
        auto& rt = state::get();
        bool was = rt.decoy_degrade_active.exchange(true);
        if (was) return;

        webhook::write_log("decoy", "degrade_mode_active");

        rt.license_pending_activation.store(true, std::memory_order_release);
        rt.activation_hardening_done.store(false, std::memory_order_release);
    }

    inline bool is_degraded()
    {
        return state::get().decoy_degrade_active.load(std::memory_order_acquire);
    }

    inline void trip_honeypot_silent()
    {
        auto& rt = state::get();
        bool was = rt.decoy_honeypot_tripped.exchange(true);
        rt.decoy_honeypot_count.fetch_add(1, std::memory_order_relaxed);
        if (was) return;
        rt.decoy_honeypot_trip_ms.store(now_ms(), std::memory_order_release);
        webhook::write_log("decoy", "honeypot_tripped_silent");
    }

    inline void poll_decoy_degrade()
    {
        auto& rt = state::get();
        if (!rt.decoy_honeypot_tripped.load(std::memory_order_acquire))
            return;
        if (rt.decoy_degrade_active.load(std::memory_order_acquire))
            return;
        int64_t trip = rt.decoy_honeypot_trip_ms.load(std::memory_order_acquire);
        if (trip == 0) return;
        int64_t elapsed = now_ms() - trip;
        if (elapsed >= degrade_delay_ms())
            degrade_mode();
    }

}

inline void enforcement_tick()
{
    auto& rt = state::get();

    enforcement::poll_decoy_degrade();

    if (!rt.violation_latched.load())
        return;

    int current_round = enforcement_detail::g_corruption_round.load();
    if (current_round > 0 && current_round < 3) {
        enforcement_detail::graduated_enforcement();
    }
}

}
