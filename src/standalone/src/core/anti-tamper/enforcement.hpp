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
#include "../standalone_license.hpp"
#include "../standalone_driver.hpp"
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
        webhook::write_log("enforce", "kill_path_fastfail");
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

                cli.Post("/api/license/violation", body.dump(), "application/json");
            } catch (...) {}
        } else if (round <= 3) {
            silent_corrupt_text(round);

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

                cli.Post("/api/license/violation", body.dump(), "application/json");
            } catch (...) {}

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
        webhook::write_log("enforce", enforce_dbg);
    }

    OBFUSCATE_JUNK(ev_pre);

    if (rt.violation_latched.exchange(true))
        return;

    CFF_BEGIN(ev_cff)
    CFF_STATE(ev_cff, 0)
    {
        {
            std::lock_guard<std::mutex> lk(rt.mtx);
            rt.violation_reason = reason ? reason : "anti_tamper";
        }
        CFF_GOTO(ev_cff, 1);
    }
    CFF_STATE(ev_cff, 1)
    {
        OBFUSCATE_JUNK(ev_wh);
        webhook::send_violation_alert(reason ? reason : "anti_tamper", extra);
        CFF_GOTO(ev_cff, 2);
    }
    CFF_STATE(ev_cff, 2)
    {
        standalone_license::shutdown();
        CFF_GOTO(ev_cff, 3);
    }
    CFF_STATE(ev_cff, 3)
    {
        OBFUSCATE_JUNK(ev_grad);
        enforcement_detail::graduated_enforcement();
    }
    CFF_END(ev_cff)
}

inline void enforcement_tick()
{
    auto& rt = state::get();
    if (!rt.violation_latched.load())
        return;

    int current_round = enforcement_detail::g_corruption_round.load();
    if (current_round > 0 && current_round < 3) {
        enforcement_detail::graduated_enforcement();
    }
}

}
