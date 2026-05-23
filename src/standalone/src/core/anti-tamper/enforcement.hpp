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
#include "integrity.hpp"
#include "standalone_license.hpp"
#include "standalone_driver.hpp"
#include "../runtime/reason_ids.hpp"
#include "../../helpers/diag_log.hpp"
#include "../../../../../libs/cpp-httplib/httplib.h"
#include "../../../../../libs/nlohmann/json.hpp"

#ifndef NT_SUCCESS
#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)
#endif

namespace anti_tamper {

inline uint32_t get_tamper_response_level()
{
    static std::atomic<int32_t> s_cached{-1};
    int32_t cur = s_cached.load(std::memory_order_acquire);
    if (cur >= 0) return static_cast<uint32_t>(cur);

    constexpr uint32_t kAuxMagic   = 0x4D585541u;
    constexpr uint32_t kAuxVersion = 0x00030000u;
    constexpr size_t   kAuxSize    = 176;
    constexpr size_t   kTamperLevelOffsetInAux = 12;

    HMODULE h = GetModuleHandleW(nullptr);
    if (!h)
    {
        s_cached.store(2, std::memory_order_release);
        return 2u;
    }
    uint8_t* base = reinterpret_cast<uint8_t*>(h);
    IMAGE_DOS_HEADER dos{};
    std::memcpy(&dos, base, sizeof(dos));
    if (dos.e_magic != IMAGE_DOS_SIGNATURE)
    {
        s_cached.store(2, std::memory_order_release);
        return 2u;
    }
    IMAGE_NT_HEADERS nt{};
    std::memcpy(&nt, base + dos.e_lfanew, sizeof(nt));
    if (nt.Signature != IMAGE_NT_SIGNATURE)
    {
        s_cached.store(2, std::memory_order_release);
        return 2u;
    }

    IMAGE_SECTION_HEADER* sec = reinterpret_cast<IMAGE_SECTION_HEADER*>(
        base + dos.e_lfanew + sizeof(DWORD) + sizeof(IMAGE_FILE_HEADER)
             + nt.FileHeader.SizeOfOptionalHeader);

    for (unsigned i = 0; i < nt.FileHeader.NumberOfSections; ++i, ++sec)
    {
        uint8_t* p = base + sec->VirtualAddress;
        size_t sz = sec->Misc.VirtualSize;
        if (sz < kAuxSize || sz > 0x02000000u) continue;

        for (size_t j = 0; j + kAuxSize <= sz; j += 4)
        {
            uint32_t mg = 0, ver = 0, lvl = 0;
            std::memcpy(&mg,  p + j,     4);
            if (mg != kAuxMagic) continue;
            std::memcpy(&ver, p + j + 4, 4);
            if (ver != kAuxVersion) continue;
            std::memcpy(&lvl, p + j + kTamperLevelOffsetInAux, 4);
            if (lvl < 1u || lvl > 4u) lvl = 2u;
            s_cached.store(static_cast<int32_t>(lvl), std::memory_order_release);
            return lvl;
        }
    }

    s_cached.store(2, std::memory_order_release);
    return 2u;
}

namespace enforcement_detail {


    inline std::string get_payload_host()
    {
#ifdef AIDA_LOCAL_LICENSE_SERVER
        return "http://localhost:3001";
#else
        return "https://aidapro.net";
#endif
    }

    inline bool env_flag_enabled(const char* name)
    {
        if (!name || !*name)
            return false;
        char value[16] = {};
        DWORD n = GetEnvironmentVariableA(name, value, static_cast<DWORD>(sizeof(value)));
        if (n == 0)
            return false;
        if (n >= sizeof(value))
            return true;
        return value[0] != '\0' && !(value[0] == '0' && value[1] == '\0');
    }

    inline bool destructive_enforcement_suppressed()
    {
#ifdef NDEBUG
        return false;
#else
        return env_flag_enabled("AIDA_FULL_TEST_RUNNING") ||
               env_flag_enabled("AIDA_DISABLE_DESTRUCTIVE_ENFORCEMENT");
#endif
    }

    inline void log_destructive_enforcement_suppressed(const char* path, uint64_t reason_id = 0)
    {
        char msg[192];
        _snprintf_s(msg, sizeof(msg), _TRUNCATE,
            "DESTRUCTIVE_ENFORCEMENT_SUPPRESSED path=%s reason_id=0x%016llX env_full_test=%d env_disable=%d",
            path ? path : "?",
            static_cast<unsigned long long>(reason_id),
            env_flag_enabled("AIDA_FULL_TEST_RUNNING") ? 1 : 0,
            env_flag_enabled("AIDA_DISABLE_DESTRUCTIVE_ENFORCEMENT") ? 1 : 0);
        diag::log_tagged_critical("enforce", msg);
        webhook::write_log("enforce", msg);
    }


    inline __declspec(noinline) void kill_path_kernel()
    {
        if (destructive_enforcement_suppressed()) {
            log_destructive_enforcement_suppressed("kill_path_kernel");
            return;
        }
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
        if (destructive_enforcement_suppressed()) {
            log_destructive_enforcement_suppressed("kill_path_hard_error");
            return;
        }
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
        if (destructive_enforcement_suppressed()) {
            log_destructive_enforcement_suppressed("kill_path_fastfail");
            return;
        }
        diag::log_tagged_critical("enforce", "kill_path_fastfail ABOUT_TO_FASTFAIL_FATAL_APP_EXIT");
        __fastfail(FAST_FAIL_FATAL_APP_EXIT);
    }

    inline __declspec(noinline) void kill_path_corrupt_stack()
    {
        if (destructive_enforcement_suppressed()) {
            log_destructive_enforcement_suppressed("kill_path_corrupt_stack");
            return;
        }
        volatile uint64_t* rsp;
        #if defined(_MSC_VER)
            rsp = reinterpret_cast<volatile uint64_t*>(_AddressOfReturnAddress());
        #endif
        if (rsp)
            *rsp ^= 0xDEADC0DEULL;
    }

    inline __declspec(noinline) void arm_bugcheck_on_exit()
    {
        using NtSetInformationProcess_t = NTSTATUS(NTAPI*)(HANDLE, ULONG, PVOID, ULONG);
        auto pSet = reinterpret_cast<NtSetInformationProcess_t>(
            GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtSetInformationProcess"));
        if (!pSet) return;
        ULONG one = 1;
        pSet(GetCurrentProcess(), 0x1D, &one, sizeof(one));
    }

    inline __declspec(noinline) void execute_all_kill_paths()
    {
        if (destructive_enforcement_suppressed()) {
            log_destructive_enforcement_suppressed("execute_all_kill_paths");
            return;
        }
        webhook::write_log("enforce", "EXECUTING_ALL_KILL_PATHS");
        arm_bugcheck_on_exit();
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

    struct section_layout_t
    {
        uint8_t* text_base = nullptr;
        uint32_t text_size = 0;
        uint8_t* rdata_base = nullptr;
        uint32_t rdata_size = 0;
        bool valid = false;
    };

    inline section_layout_t locate_sections()
    {
        section_layout_t out{};
        HMODULE hMod = GetModuleHandleA(nullptr);
        if (!hMod) return out;
        auto* dos = reinterpret_cast<IMAGE_DOS_HEADER*>(hMod);
        if (dos->e_magic != IMAGE_DOS_SIGNATURE) return out;
        auto* nt = reinterpret_cast<IMAGE_NT_HEADERS64*>(
            reinterpret_cast<uint8_t*>(hMod) + dos->e_lfanew);
        if (nt->Signature != IMAGE_NT_SIGNATURE) return out;

        auto* sec = IMAGE_FIRST_SECTION(nt);
        for (WORD i = 0; i < nt->FileHeader.NumberOfSections; ++i)
        {
            if (!out.text_base && (sec[i].Characteristics & IMAGE_SCN_MEM_EXECUTE))
            {
                out.text_base = reinterpret_cast<uint8_t*>(hMod) + sec[i].VirtualAddress;
                out.text_size = sec[i].Misc.VirtualSize;
            }
            if (!out.rdata_base &&
                sec[i].Name[0] == '.' && sec[i].Name[1] == 'r' &&
                sec[i].Name[2] == 'd' && sec[i].Name[3] == 'a')
            {
                out.rdata_base = reinterpret_cast<uint8_t*>(hMod) + sec[i].VirtualAddress;
                out.rdata_size = sec[i].Misc.VirtualSize;
            }
        }
        out.valid = (out.text_base != nullptr && out.text_size >= 4096);
        return out;
    }

    inline uint8_t pick_random_page(uint32_t section_size, uint64_t& seed)
    {
        if (section_size < 4096) return 0;
        uint32_t page_count = section_size / 4096u;
        if (page_count == 0) return 0;
        if (page_count > 254u) page_count = 254u;
        uint32_t pick = static_cast<uint32_t>(corruption_prng(seed) % page_count);
        return static_cast<uint8_t>(pick);
    }

    inline void corrupt_page_bytes_exec(uint8_t* section_base,
                                        uint32_t section_size,
                                        uint8_t page_index,
                                        uint32_t n_bytes,
                                        uint64_t& seed)
    {
        uint32_t offset = static_cast<uint32_t>(page_index) * 4096u;
        if (offset >= section_size) return;
        uint32_t page_size = 4096u;
        if (offset + page_size > section_size) page_size = section_size - offset;
        uint8_t* page_addr = section_base + offset;

        DWORD old_prot = 0;
        if (!VirtualProtect(page_addr, page_size, PAGE_EXECUTE_READWRITE, &old_prot))
            return;

        for (uint32_t i = 0; i < n_bytes; ++i)
        {
            uint32_t boff = static_cast<uint32_t>(corruption_prng(seed) % page_size);
            volatile uint8_t* p = page_addr + boff;
            *p = static_cast<uint8_t>(*p ^ 0x66u);
        }

        VirtualProtect(page_addr, page_size, old_prot, &old_prot);
        FlushInstructionCache(GetCurrentProcess(), page_addr, page_size);
    }

    inline void corrupt_page_bytes_data(uint8_t* section_base,
                                        uint32_t section_size,
                                        uint8_t page_index,
                                        uint32_t n_bytes,
                                        uint64_t& seed)
    {
        uint32_t offset = static_cast<uint32_t>(page_index) * 4096u;
        if (offset >= section_size) return;
        uint32_t page_size = 4096u;
        if (offset + page_size > section_size) page_size = section_size - offset;
        uint8_t* page_addr = section_base + offset;

        DWORD old_prot = 0;
        if (!VirtualProtect(page_addr, page_size, PAGE_READWRITE, &old_prot))
            return;

        for (uint32_t i = 0; i < n_bytes; ++i)
        {
            uint32_t boff = static_cast<uint32_t>(corruption_prng(seed) % page_size);
            volatile uint8_t* p = page_addr + boff;
            *p = static_cast<uint8_t>(*p ^ 0x66u);
        }

        VirtualProtect(page_addr, page_size, old_prot, &old_prot);
    }

    inline void silent_corrupt_text_surgical(int round, uint64_t reason_id)
    {
        section_layout_t lay = locate_sections();
        if (!lay.valid)
        {
            webhook::write_log("enforce", "corrupt_surgical: no module layout (expected after anti_dump)");
            return;
        }

        uint64_t seed = __rdtsc()
            ^ (static_cast<uint64_t>(round) << 32)
            ^ reason_id
            ^ static_cast<uint64_t>(GetCurrentProcessId());

        uint8_t corruption_pages[16] = {0};
        size_t corruption_count = 0;

        auto add_corruption_text_page = [&](uint8_t p)
        {
            if (corruption_count < 16)
                corruption_pages[corruption_count++] = p;
        };

        if (round <= 1)
        {
            uint8_t pt = pick_random_page(lay.text_size, seed);
            add_corruption_text_page(pt);
            integrity::set_expected_corruption_mask(corruption_pages, corruption_count);
            corrupt_page_bytes_exec(lay.text_base, lay.text_size, pt, 16, seed);
            if (lay.rdata_base && lay.rdata_size >= 4096)
            {
                uint8_t pr = pick_random_page(lay.rdata_size, seed);
                corrupt_page_bytes_data(lay.rdata_base, lay.rdata_size, pr, 16, seed);
            }
        }
        else if (round == 2)
        {
            uint8_t pt1 = pick_random_page(lay.text_size, seed);
            uint8_t pt2 = pick_random_page(lay.text_size, seed);
            add_corruption_text_page(pt1);
            if (pt2 != pt1) add_corruption_text_page(pt2);
            integrity::set_expected_corruption_mask(corruption_pages, corruption_count);
            corrupt_page_bytes_exec(lay.text_base, lay.text_size, pt1, 128, seed);
            if (pt2 != pt1)
                corrupt_page_bytes_exec(lay.text_base, lay.text_size, pt2, 128, seed);
            if (lay.rdata_base && lay.rdata_size >= 4096)
            {
                uint8_t pr = pick_random_page(lay.rdata_size, seed);
                corrupt_page_bytes_data(lay.rdata_base, lay.rdata_size, pr, 64, seed);
            }
        }
        else
        {
            uint32_t page_count = lay.text_size / 4096u;
            if (page_count > 254u) page_count = 254u;
            for (uint32_t p = 0; p < page_count && corruption_count < 16; ++p)
            {
                if ((corruption_prng(seed) & 3u) == 0u)
                    add_corruption_text_page(static_cast<uint8_t>(p));
            }
            if (corruption_count == 0)
                add_corruption_text_page(pick_random_page(lay.text_size, seed));
            integrity::set_expected_corruption_mask(corruption_pages, corruption_count);
            for (size_t i = 0; i < corruption_count; ++i)
            {
                corrupt_page_bytes_exec(lay.text_base, lay.text_size,
                                        corruption_pages[i], 256, seed);
            }
        }

        integrity::clear_expected_corruption_mask(corruption_pages, corruption_count);
    }

    inline void silent_corrupt_text(int round)
    {
        silent_corrupt_text_surgical(round, 0);
    }

    static void violation_post_impl(int round, uint64_t reason_id)
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
            body["reason_id_hex"] = ([reason_id]() {
                char tmp[20];
                _snprintf_s(tmp, sizeof(tmp), _TRUNCATE,
                    "0x%016llX", static_cast<unsigned long long>(reason_id));
                return std::string(tmp);
            })();

            std::string body_str = body.dump();
            cli.Post("/api/license/violation", body_str, "application/json");
        } catch (...) {}
    }

    __declspec(noinline) static DWORD seh_violation_post(int round, uint64_t reason_id)
    {
        __try {
            violation_post_impl(round, reason_id);
            return 0;
        } __except (EXCEPTION_EXECUTE_HANDLER) {
            return GetExceptionCode();
        }
    }

    __declspec(noinline) static void seh_graduated_enforcement_round_impl(int round,
                                                                          uint64_t reason_id,
                                                                          uint32_t level)
    {
        if (round == 1)
        {
            silent_corrupt_text_surgical(1, reason_id);
            if (level >= 4)
                execute_all_kill_paths();
        }
        else if (round == 2)
        {
            silent_corrupt_text_surgical(2, reason_id);
            if (level >= 3)
                execute_all_kill_paths();
        }
        else if (round == 3)
        {
            silent_corrupt_text_surgical(3, reason_id);
            execute_all_kill_paths();
        }
        else
        {
            execute_all_kill_paths();
        }
    }

    __declspec(noinline) static void seh_graduated_enforcement_round(int round,
                                                                     uint64_t reason_id,
                                                                     uint32_t level)
    {
        __try {
            seh_graduated_enforcement_round_impl(round, reason_id, level);
        } __except (EXCEPTION_EXECUTE_HANDLER) {
            char dbg[80];
            _snprintf_s(dbg, sizeof(dbg), _TRUNCATE,
                "graduated_round_SEH code=0x%08X round=%d",
                GetExceptionCode(), round);
            webhook::write_log("enforce", dbg);
        }
    }

    inline void graduated_enforcement(uint64_t reason_id = 0)
    {
        if (destructive_enforcement_suppressed()) {
            log_destructive_enforcement_suppressed("graduated_enforcement", reason_id);
            return;
        }
        int round = g_corruption_round.fetch_add(1) + 1;
        uint32_t level = anti_tamper::get_tamper_response_level();
        if (level == 0) level = 2;

        {
            char dbg[160];
            _snprintf_s(dbg, sizeof(dbg), _TRUNCATE,
                "graduated_enforcement round=%d level=%u reason_id=0x%016llX",
                round, level,
                static_cast<unsigned long long>(reason_id));
            webhook::write_log("enforce", dbg);
        }

        seh_graduated_enforcement_round(round, reason_id, level);

        DWORD seh_post = seh_violation_post(round, reason_id);
        if (seh_post != 0) {
            char dbg[64];
            _snprintf_s(dbg, sizeof(dbg), _TRUNCATE, "violation_post_seh=0x%08X", seh_post);
            webhook::write_log("enforce", dbg);
        }
    }

}

inline void enforce_violation_id(uint64_t reason_id, const std::string& extra = "")
{
    auto& rt = state::get();

    char reason_short[9] = {};
    aida::reason_ids::reason_id_to_short_string(reason_id, reason_short);

    {
        char enforce_dbg[512];
        _snprintf_s(enforce_dbg, sizeof(enforce_dbg), _TRUNCATE,
            "ENFORCE_VIOLATION_ID reason_id=0x%016llX short=%s extra=%s already_latched=%d",
            static_cast<unsigned long long>(reason_id),
            reason_short,
            extra.empty() ? "none" : extra.c_str(),
            rt.violation_latched.load() ? 1 : 0);
        diag::log_tagged_critical("enforce", enforce_dbg);
    }

    OBFUSCATE_JUNK(ev_pre);

    if (rt.violation_latched.exchange(true)) {
        diag::log_tagged_critical("enforce", "already_latched_returning");
        return;
    }

    if (enforcement_detail::destructive_enforcement_suppressed()) {
        {
            std::lock_guard<std::mutex> lk(rt.mtx);
            rt.violation_reason = std::string("rid_") + reason_short + "_suppressed";
        }
        enforcement_detail::log_destructive_enforcement_suppressed(
            extra.empty() ? "enforce_violation_id" : extra.c_str(),
            reason_id);
        diag::log_tagged_critical("enforce", "enforce_violation_id_suppressed_returning_before_alert_shutdown");
        return;
    }

    diag::log_tagged_critical("enforce", "ev_cff_state_0_entering_set_reason");
    CFF_BEGIN(ev_cff)
    CFF_STATE(ev_cff, 0)
    {
        {
            std::lock_guard<std::mutex> lk(rt.mtx);
            rt.violation_reason = std::string("rid_") + reason_short;
        }
        diag::log_tagged_critical("enforce", "ev_cff_state_0_done_goto_1");
        CFF_GOTO(ev_cff, 1);
    }
    CFF_STATE(ev_cff, 1)
    {
        diag::log_tagged_critical("enforce", "ev_cff_state_1_calling_send_violation_alert");
        OBFUSCATE_JUNK(ev_wh);
        webhook::send_violation_alert_id(reason_id, extra);
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
        enforcement_detail::graduated_enforcement(reason_id);
        diag::log_tagged_critical("enforce", "ev_cff_state_3_returned_from_graduated");
    }
    CFF_END(ev_cff)
    diag::log_tagged_critical("enforce", "enforce_violation_returning_normally");
}

inline void enforce_violation(const char* reason, const std::string& extra = "")
{
    uint64_t rid = aida::reason_ids::reason_id_from_string(reason);
    enforce_violation_id(rid, extra);
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
        enforcement_detail::graduated_enforcement(0);
    }
}

}
