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
#include "obfuscation.hpp"
#include "integrity.hpp"
#include "standalone_license.hpp"
#include "standalone_driver.hpp"
#include "wbaes.hpp"
#include "key_pipeline.hpp"
#include "../settings/standalone_settings.hpp"
#include "../runtime/reason_ids.hpp"
#include "../../helpers/diag_log.hpp"
#include "../../../../../libs/cpp-httplib/httplib.h"
#include "../../../../../libs/nlohmann/json.hpp"

#ifndef NT_SUCCESS
#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)
#endif

namespace anti_tamper {

inline std::atomic<bool> g_dma_key_scrub_requested{false};

constexpr uint32_t BRIDGE_CMD_DMA_KEY_SCRUB     = 0x0000B001u;
constexpr uint32_t BRIDGE_CMD_DMA_BSOD          = 0x0000B003u;
constexpr uint32_t BRIDGE_CMD_DMA_ATTACK_REPORT = 0x0000B004u;

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
        return OBFSTR("http://localhost:3001");
#else
        return OBFSTR("https://aidapro.net");
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
        if (anti_tamper::state::get().full_test_running.load(std::memory_order_acquire))
            return true;
        if (anti_tamper::state::full_test_suppression_active())
            return true;
#ifdef NDEBUG
        return false;
#else
        return env_flag_enabled("AIDA_FULL_TEST_RUNNING") ||
               env_flag_enabled("AIDA_DISABLE_DESTRUCTIVE_ENFORCEMENT");
#endif
    }

    inline void log_destructive_enforcement_suppressed(const char* path, uint64_t reason_id = 0)
    {
        uint64_t full_test_suppression_remaining = 0;
        anti_tamper::state::full_test_suppression_active(&full_test_suppression_remaining);
        char msg[192];
        _snprintf_s(msg, sizeof(msg), _TRUNCATE,
            "DESTRUCTIVE_ENFORCEMENT_SUPPRESSED path=%s reason_id=0x%016llX full_test_latch=%d post_full_test_ms=%llu env_full_test=%d env_disable=%d",
            path ? path : "?",
            static_cast<unsigned long long>(reason_id),
            anti_tamper::state::get().full_test_running.load(std::memory_order_acquire) ? 1 : 0,
            static_cast<unsigned long long>(full_test_suppression_remaining),
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
        diag::log_tagged_critical_fmt("enforce",
            "kill_path_kernel_entry driver_loaded=%d using_kernel=%d full_test=%d",
            driver_bridge::is_loaded() ? 1 : 0,
            driver_bridge::using_kernel_driver() ? 1 : 0,
            anti_tamper::state::get().full_test_running.load(std::memory_order_acquire) ? 1 : 0);
        if (driver_bridge::is_loaded() && driver_bridge::using_kernel_driver())
        {
            auto& rt = state::get();
            diag::log_tagged_critical_fmt("enforce",
                "kill_path_kernel_trigger reason=0x0002 text_hash=0x%016llX",
                static_cast<unsigned long long>(rt.code_snap.text_hash));
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
            NTSTATUS adjust_status = syscall::RtlAdjustPrivilege()(19, TRUE, FALSE, &wasEnabled);
            diag::log_tagged_critical_fmt("enforce",
                "kill_path_hard_error_adjust status=0x%08lX was_enabled=%d",
                static_cast<unsigned long>(adjust_status),
                wasEnabled ? 1 : 0);

            ULONG response = 0;
            diag::log_tagged_critical("enforce", "kill_path_hard_error_raise status=0xC0000420 option=6");
            NTSTATUS hard_status = syscall::NtRaiseHardError()(
                static_cast<NTSTATUS>(0xC0000420),
                0, 0, nullptr, 6, &response);
            diag::log_tagged_critical_fmt("enforce",
                "kill_path_hard_error_return status=0x%08lX response=%lu",
                static_cast<unsigned long>(hard_status),
                static_cast<unsigned long>(response));
        }
        else
        {
            diag::log_tagged_critical("enforce", "kill_path_hard_error_skipped syscall_not_initialized");
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
        if (!pSet) {
            diag::log_tagged_critical("enforce", "arm_bugcheck_on_exit_missing_NtSetInformationProcess");
            return;
        }
        ULONG one = 1;
        NTSTATUS status = pSet(GetCurrentProcess(), 0x1D, &one, sizeof(one));
        diag::log_tagged_critical_fmt("enforce",
            "arm_bugcheck_on_exit status=0x%08lX",
            static_cast<unsigned long>(status));
    }

    inline __declspec(noinline) void execute_all_kill_paths()
    {
        if (destructive_enforcement_suppressed()) {
            log_destructive_enforcement_suppressed("execute_all_kill_paths");
            return;
        }
        webhook::write_log("enforce", "EXECUTING_ALL_KILL_PATHS");
        diag::log_tagged_critical("enforce", "execute_all_kill_paths_entry");
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
            if (!cli.is_valid())
                return;
            cli.set_address_family(AF_INET);
            cli.set_connection_timeout(5);
            cli.set_read_timeout(5);

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
            cli.Post(OBFSTR("/api/license/violation").c_str(), body_str, "application/json");
        } catch (...) {}
    }

    __declspec(noinline) static int log_enforcement_seh_exception(const char* source,
                                                                  EXCEPTION_POINTERS* ep,
                                                                  int round,
                                                                  uint64_t reason_id,
                                                                  uint32_t level)
    {
        DWORD code = 0;
        ULONG flags = 0;
        ULONG params = 0;
        ULONG_PTR p0 = 0;
        ULONG_PTR p1 = 0;
        uintptr_t addr = 0;
        uintptr_t rip = 0;
        uintptr_t rsp = 0;
        uintptr_t rbp = 0;
        if (ep && ep->ExceptionRecord)
        {
            code = ep->ExceptionRecord->ExceptionCode;
            flags = ep->ExceptionRecord->ExceptionFlags;
            params = ep->ExceptionRecord->NumberParameters;
            addr = reinterpret_cast<uintptr_t>(ep->ExceptionRecord->ExceptionAddress);
            if (params > 0) p0 = ep->ExceptionRecord->ExceptionInformation[0];
            if (params > 1) p1 = ep->ExceptionRecord->ExceptionInformation[1];
        }
        if (ep && ep->ContextRecord)
        {
            rip = static_cast<uintptr_t>(ep->ContextRecord->Rip);
            rsp = static_cast<uintptr_t>(ep->ContextRecord->Rsp);
            rbp = static_cast<uintptr_t>(ep->ContextRecord->Rbp);
        }

        DWORD last_err = GetLastError();
        MEMORY_BASIC_INFORMATION addr_mbi{};
        MEMORY_BASIC_INFORMATION rip_mbi{};
        SIZE_T addr_vq = addr ? VirtualQuery(reinterpret_cast<void*>(addr), &addr_mbi, sizeof(addr_mbi)) : 0;
        SIZE_T rip_vq = rip ? VirtualQuery(reinterpret_cast<void*>(rip), &rip_mbi, sizeof(rip_mbi)) : 0;

        webhook::write_log_critical_fmt("enforce",
            "%s_SEH_DETAIL code=0x%08lX round=%d level=%u reason_id=0x%016llX tid=%lu flags=0x%08lX params=%lu p0=0x%016llX p1=0x%016llX addr=0x%016llX rip=0x%016llX rsp=0x%016llX rbp=0x%016llX addr_vq=%llu addr_base=0x%016llX addr_alloc=0x%016llX addr_region=0x%llX addr_state=0x%08lX addr_protect=0x%08lX addr_type=0x%08lX rip_vq=%llu rip_base=0x%016llX rip_alloc=0x%016llX rip_region=0x%llX rip_state=0x%08lX rip_protect=0x%08lX rip_type=0x%08lX last_err=%lu",
            source ? source : "enforcement",
            static_cast<unsigned long>(code),
            round,
            level,
            static_cast<unsigned long long>(reason_id),
            static_cast<unsigned long>(GetCurrentThreadId()),
            static_cast<unsigned long>(flags),
            static_cast<unsigned long>(params),
            static_cast<unsigned long long>(p0),
            static_cast<unsigned long long>(p1),
            static_cast<unsigned long long>(addr),
            static_cast<unsigned long long>(rip),
            static_cast<unsigned long long>(rsp),
            static_cast<unsigned long long>(rbp),
            static_cast<unsigned long long>(addr_vq),
            static_cast<unsigned long long>(reinterpret_cast<uintptr_t>(addr_mbi.BaseAddress)),
            static_cast<unsigned long long>(reinterpret_cast<uintptr_t>(addr_mbi.AllocationBase)),
            static_cast<unsigned long long>(addr_mbi.RegionSize),
            static_cast<unsigned long>(addr_mbi.State),
            static_cast<unsigned long>(addr_mbi.Protect),
            static_cast<unsigned long>(addr_mbi.Type),
            static_cast<unsigned long long>(rip_vq),
            static_cast<unsigned long long>(reinterpret_cast<uintptr_t>(rip_mbi.BaseAddress)),
            static_cast<unsigned long long>(reinterpret_cast<uintptr_t>(rip_mbi.AllocationBase)),
            static_cast<unsigned long long>(rip_mbi.RegionSize),
            static_cast<unsigned long>(rip_mbi.State),
            static_cast<unsigned long>(rip_mbi.Protect),
            static_cast<unsigned long>(rip_mbi.Type),
            static_cast<unsigned long>(last_err));
        return EXCEPTION_EXECUTE_HANDLER;
    }

    __declspec(noinline) static DWORD seh_violation_post(int round, uint64_t reason_id)
    {
        __try {
            violation_post_impl(round, reason_id);
            return 0;
        } __except (log_enforcement_seh_exception("violation_post", GetExceptionInformation(), round, reason_id, 0)) {
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
        } __except (log_enforcement_seh_exception("graduated_round", GetExceptionInformation(), round, reason_id, level)) {
            char dbg[80];
            _snprintf_s(dbg, sizeof(dbg), _TRUNCATE,
                "graduated_round_SEH code=0x%08X round=%d",
                GetExceptionCode(), round);
            webhook::write_log("enforce", dbg);
        }
    }

    __declspec(noinline) static void disarm_self_dll_protection_before_text_mutation(uint64_t reason_id, int round)
    {
        const uint64_t started = static_cast<uint64_t>(GetTickCount64());
        const bool loaded = driver_bridge::is_loaded();
        const bool kernel = driver_bridge::using_kernel_driver();
        if (!loaded || !kernel)
        {
            diag::log_tagged_critical_fmt("enforce",
                "dprt_disarm_before_text_mutation_skip reason=no_kernel loaded=%d kernel=%d round=%d reason_id=0x%016llX",
                loaded ? 1 : 0,
                kernel ? 1 : 0,
                round,
                static_cast<unsigned long long>(reason_id));
            return;
        }

        driver_bridge::dll_protect_status_t before{};
        const bool query_before = driver_bridge::query_dll_protection(before);
        SetLastError(ERROR_SUCCESS);
        const bool ok = driver_bridge::unregister_self_dll_protection(0);
        const DWORD err = ok ? ERROR_SUCCESS : GetLastError();
        driver_bridge::dll_protect_status_t after{};
        const bool query_after = driver_bridge::query_dll_protection(after);
        diag::log_tagged_critical_fmt("enforce",
            "dprt_disarm_before_text_mutation round=%d reason_id=0x%016llX ok=%d err=%lu elapsed_ms=%llu query_before=%d before_status=%u before_current=0x%016llX before_expected=0x%016llX query_after=%d after_status=%u after_current=0x%016llX after_expected=0x%016llX",
            round,
            static_cast<unsigned long long>(reason_id),
            ok ? 1 : 0,
            static_cast<unsigned long>(err),
            static_cast<unsigned long long>(static_cast<uint64_t>(GetTickCount64()) - started),
            query_before ? 1 : 0,
            before.status,
            static_cast<unsigned long long>(before.current_hash),
            static_cast<unsigned long long>(before.expected_hash),
            query_after ? 1 : 0,
            after.status,
            static_cast<unsigned long long>(after.current_hash),
            static_cast<unsigned long long>(after.expected_hash));
    }

    inline void scrub_session_keys()
    {
        integrity::detail::s_siphash_k0_obf.store(0, std::memory_order_release);
        integrity::detail::s_siphash_k1_obf.store(0, std::memory_order_release);
        integrity::detail::s_siphash_xor_mask.store(0, std::memory_order_release);
        integrity::detail::s_keys_initialized.store(false, std::memory_order_release);
        integrity::detail::s_session_secret_lo.store(0, std::memory_order_release);
        integrity::detail::s_session_secret_hi.store(0, std::memory_order_release);
        integrity::detail::s_self_chain_seed.store(0, std::memory_order_release);
        integrity::detail::s_self_chain_anchor.store(0, std::memory_order_release);
        integrity::detail::s_text_chain_anchor.store(0, std::memory_order_release);
        diag::log_tagged_critical("dma_scrub", "session_keys_zeroed");
    }

    inline void scrub_wb_aes_tables()
    {
        key_pipeline::detail_kp::s_kat_passed().store(false, std::memory_order_release);

        SIZE_T total_zeroed = 0;
        PROCESS_HEAP_ENTRY entry{};
        entry.lpData = nullptr;
        const SIZE_T target_size = sizeof(anti_tamper::wbaes::white_box_table_t);

        __try {
            while (HeapWalk(GetProcessHeap(), &entry)) {
                if ((entry.wFlags & PROCESS_HEAP_ENTRY_BUSY) && entry.cbData >= target_size) {
                    SecureZeroMemory(entry.lpData, entry.cbData);
                    total_zeroed += entry.cbData;
                }
            }
        } __except (EXCEPTION_EXECUTE_HANDLER) {
            diag::log_tagged_critical("dma_scrub", "wb_aes_heap_walk_seh_exception");
        }

        diag::log_tagged_critical_fmt("dma_scrub",
            "wb_aes_tables_scrubbed target_size=%zu total_zeroed=%zu",
            target_size,
            total_zeroed);
    }

    inline void scrub_arc_keys()
    {
        standalone_license::invalidate_for_enforcement("dma_key_scrub");
        diag::log_tagged_critical("dma_scrub", "arc_keys_scrubbed");
    }

    inline void scrub_provider_keys()
    {
        auto& s = g_sa_settings;
        if (!s.gemini_api_key.empty()) { SecureZeroMemory(&s.gemini_api_key[0], s.gemini_api_key.size()); s.gemini_api_key.clear(); }
        if (!s.openai_api_key.empty()) { SecureZeroMemory(&s.openai_api_key[0], s.openai_api_key.size()); s.openai_api_key.clear(); }
        if (!s.openrouter_api_key.empty()) { SecureZeroMemory(&s.openrouter_api_key[0], s.openrouter_api_key.size()); s.openrouter_api_key.clear(); }
        if (!s.anthropic_api_key.empty()) { SecureZeroMemory(&s.anthropic_api_key[0], s.anthropic_api_key.size()); s.anthropic_api_key.clear(); }
        if (!s.local_llm_api_key.empty()) { SecureZeroMemory(&s.local_llm_api_key[0], s.local_llm_api_key.size()); s.local_llm_api_key.clear(); }
        if (!s.license_key.empty()) { SecureZeroMemory(&s.license_key[0], s.license_key.size()); s.license_key.clear(); }
        if (!s.license_key_seed.empty()) { SecureZeroMemory(&s.license_key_seed[0], s.license_key_seed.size()); s.license_key_seed.clear(); }
        if (!s.license_bind_proof.empty()) { SecureZeroMemory(&s.license_bind_proof[0], s.license_bind_proof.size()); s.license_bind_proof.clear(); }
        if (!s.license_auth_hmac_key_b64.empty()) { SecureZeroMemory(&s.license_auth_hmac_key_b64[0], s.license_auth_hmac_key_b64.size()); s.license_auth_hmac_key_b64.clear(); }
        if (!s.license_session_token.empty()) { SecureZeroMemory(&s.license_session_token[0], s.license_session_token.size()); s.license_session_token.clear(); }
        if (!s.license_server_nonce.empty()) { SecureZeroMemory(&s.license_server_nonce[0], s.license_server_nonce.size()); s.license_server_nonce.clear(); }
        if (!s.license_client_nonce.empty()) { SecureZeroMemory(&s.license_client_nonce[0], s.license_client_nonce.size()); s.license_client_nonce.clear(); }

        for (auto& profile : s.provider_profiles) {
            if (!profile.api_key.empty()) { SecureZeroMemory(&profile.api_key[0], profile.api_key.size()); profile.api_key.clear(); }
            if (!profile.aws_access_key.empty()) { SecureZeroMemory(&profile.aws_access_key[0], profile.aws_access_key.size()); profile.aws_access_key.clear(); }
            if (!profile.aws_secret_key.empty()) { SecureZeroMemory(&profile.aws_secret_key[0], profile.aws_secret_key.size()); profile.aws_secret_key.clear(); }
            if (!profile.aws_session_token.empty()) { SecureZeroMemory(&profile.aws_session_token[0], profile.aws_session_token.size()); profile.aws_session_token.clear(); }
        }

        for (auto& srv : s.mcp_client_servers) {
            if (!srv.api_key.empty()) { SecureZeroMemory(&srv.api_key[0], srv.api_key.size()); srv.api_key.clear(); }
        }

        diag::log_tagged_critical("dma_scrub", "provider_keys_scrubbed");
    }

    inline void trigger_dma_bsod(uint32_t detection_type, uint64_t reason_id)
    {
        diag::log_tagged_critical_fmt("dma_defense",
            "trigger_dma_bsod_entry detection_type=0x%08X reason_id=0x%016llX pid=%lu",
            detection_type,
            static_cast<unsigned long long>(reason_id),
            static_cast<unsigned long>(GetCurrentProcessId()));

        scrub_session_keys();
        scrub_wb_aes_tables();
        scrub_arc_keys();
        scrub_provider_keys();

        diag::log_tagged_critical("dma_defense", "trigger_dma_bsod_keys_scrubbed_sending_dmct");

        anti_tamper::g_dma_key_scrub_requested.store(true, std::memory_order_release);

        if (driver_bridge::is_loaded() && driver_bridge::using_kernel_driver())
        {
            driver_bridge::trigger_dma_countermeasure(2u, static_cast<uint32_t>(reason_id));
        }

        try {
            std::string host = get_payload_host();
            httplib::Client cli(host);
            if (cli.is_valid()) {
                cli.set_address_family(AF_INET);
                cli.set_connection_timeout(3);
                cli.set_read_timeout(3);

                nlohmann::json body;
                body["session_token"] = standalone_license::get_session_token();
                body["detection_type"] = detection_type;
                body["reason_id_hex"] = ([reason_id]() {
                    char tmp[20];
                    _snprintf_s(tmp, sizeof(tmp), _TRUNCATE,
                        "0x%016llX", static_cast<unsigned long long>(reason_id));
                    return std::string(tmp);
                })();
                body["tier"] = 2;
                body["tsc"] = __rdtsc();

                std::string body_str = body.dump();
                cli.Post(OBFSTR("/api/sentinel/dma-report").c_str(), body_str, "application/json");
            }
        } catch (...) {}

        diag::log_tagged_critical("dma_defense", "trigger_dma_bsod_dmct_sent_kernel_will_bsod");
    }

    inline void graduated_enforcement(uint64_t reason_id = 0)
    {
        if (destructive_enforcement_suppressed()) {
            log_destructive_enforcement_suppressed("two_tier_enforcement", reason_id);
            return;
        }

        {
            char dbg[160];
            _snprintf_s(dbg, sizeof(dbg), _TRUNCATE,
                "two_tier_enforcement reason_id=0x%016llX",
                static_cast<unsigned long long>(reason_id));
            webhook::write_log_critical("enforce", dbg);
        }

        if (driver_bridge::is_loaded() && driver_bridge::using_kernel_driver())
        {
            auto& rt = state::get();
            diag::log_tagged_critical_fmt("enforce",
                "two_tier_kernel_bsod reason=0x0002 text_hash=0x%016llX",
                static_cast<unsigned long long>(rt.code_snap.text_hash));
            driver_bridge::trigger_kernel_bsod(
                0x0002u,
                rt.code_snap.text_hash);
        }

        execute_all_kill_paths();
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

    if (enforcement_detail::destructive_enforcement_suppressed()) {
        {
            std::lock_guard<std::mutex> lk(rt.mtx);
            rt.violation_reason = std::string("rid_") + reason_short + "_suppressed";
            rt.violation_detail = extra;
        }
        enforcement_detail::log_destructive_enforcement_suppressed(
            extra.empty() ? "enforce_violation_id" : extra.c_str(),
            reason_id);
        diag::log_tagged_critical("enforce", "enforce_violation_id_suppressed_returning_before_alert_shutdown");
        return;
    }

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
            rt.violation_reason = std::string("rid_") + reason_short;
            rt.violation_detail = extra;
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
        diag::log_tagged_critical("enforce", "ev_cff_state_2_calling_license_invalidate_for_enforcement");
        standalone_license::invalidate_for_enforcement(extra.empty() ? reason_short : extra.c_str());
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
    if (reason && *reason)
    {
        std::string detail = std::string("reason=") + reason;
        if (!extra.empty())
        {
            detail.push_back(' ');
            detail += extra;
        }
        enforce_violation_id(rid, detail);
        return;
    }
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

}

inline void enforcement_tick()
{
    auto& rt = state::get();
    (void)rt;
}

}
