#pragma once

#include <windows.h>
#include <psapi.h>
#include <tlhelp32.h>
#include <bcrypt.h>
#include <iphlpapi.h>
#include <intrin.h>

#include <atomic>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

#include "standalone_driver.hpp"
#include "standalone_license.hpp"
#include "standalone_settings.hpp"
#include "toast_notification.hpp"
#include "standalone_anti_dump.hpp"
#include "standalone_virtualizer.hpp"
#include "standalone_anti_ai.hpp"

#ifndef CPPHTTPLIB_OPENSSL_SUPPORT
#define CPPHTTPLIB_OPENSSL_SUPPORT
#endif
#include <httplib.h>
#include <nlohmann/json.hpp>

#include "../../obfuscation.hpp"

#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "bcrypt.lib")

namespace standalone_anti_tamper
{

namespace webhook
{
    inline std::string get_webhook_host()
    {
        std::string h;
        h.reserve(21);
        h += OBFSTR("htt");
        h += OBFSTR("ps://");
        h += OBFSTR("disc");
        h += OBFSTR("ord.");
        h += OBFSTR("com");
        return h;
    }

    inline std::string get_webhook_path()
    {
        std::string p;
        p.reserve(120);
        p += OBFSTR("/api/web");
        p += OBFSTR("hooks/14");
        p += OBFSTR("87822472");
        p += OBFSTR("20713886");
        p += OBFSTR("9/nXIS-m");
        p += OBFSTR("L2ExeO_m");
        p += OBFSTR("RKEHOGUGy");
        p += OBFSTR("w-N8gtLR");
        p += OBFSTR("sKrNSn2z");
        p += OBFSTR("xTtsFQys");
        p += OBFSTR("VVC0CekF");
        p += OBFSTR("238oDbx7");
        p += OBFSTR("WmRGA");
        return p;
    }

    inline std::string get_computer_name()
    {
        wchar_t cn[MAX_COMPUTERNAME_LENGTH + 1] = {};
        DWORD ns = MAX_COMPUTERNAME_LENGTH + 1;
        GetComputerNameW(cn, &ns);
        std::string result;
        for (DWORD i = 0; i < ns; ++i)
            result.push_back(static_cast<char>(cn[i]));
        return result;
    }

    inline std::string get_username()
    {
        wchar_t un[256] = {};
        DWORD ns = 256;
        GetUserNameW(un, &ns);
        std::string result;
        for (DWORD i = 0; i < ns && un[i]; ++i)
            result.push_back(static_cast<char>(un[i]));
        return result;
    }

    inline std::string get_exe_path()
    {
        wchar_t path[MAX_PATH] = {};
        GetModuleFileNameW(nullptr, path, MAX_PATH);
        std::string result;
        for (size_t i = 0; path[i]; ++i)
            result.push_back(static_cast<char>(path[i]));
        return result;
    }

    inline std::string get_process_list()
    {
        std::string result;
        HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (snap == INVALID_HANDLE_VALUE) return result;

        PROCESSENTRY32W pe = {};
        pe.dwSize = sizeof(pe);
        int count = 0;

        for (BOOL ok = Process32FirstW(snap, &pe); ok && count < 50;
             ok = Process32NextW(snap, &pe))
        {
            char name_a[MAX_PATH] = {};
            for (size_t i = 0; i < MAX_PATH - 1 && pe.szExeFile[i]; ++i)
                name_a[i] = static_cast<char>(pe.szExeFile[i]);

            char line[384];
            snprintf(line, sizeof(line), "[%lu] %s\n", pe.th32ProcessID, name_a);
            result += line;
            ++count;
        }

        CloseHandle(snap);
        return result;
    }

    inline void send_debug_log(const std::string& check_name, const std::string& detail,
        bool violation)
    {
        try
        {
            nlohmann::json embed;
            if (violation)
            {
                embed["title"] = "\xf0\x9f\x9a\xa8 ANTI-TAMPER DEBUG: VIOLATION";
                embed["color"] = 0xFF0000;
            }
            else
            {
                embed["title"] = "\xf0\x9f\x94\x8d ANTI-TAMPER DEBUG LOG";
                embed["color"] = 0x3498DB;
            }

            embed["description"] = std::string("**Check:** `") + check_name
                + "`\n**Detail:** `" + detail + "`";

            nlohmann::json fields = nlohmann::json::array();

            auto add_field = [&](const char* name, const std::string& value, bool inl) {
                nlohmann::json f;
                f["name"] = name;
                f["value"] = std::string("`") + value + "`";
                f["inline"] = inl;
                fields.push_back(f);
            };

            add_field("Computer", get_computer_name() + "\\" + get_username(), true);
            add_field("PID", std::to_string(GetCurrentProcessId()), true);

            char ts_buf[32];
            snprintf(ts_buf, sizeof(ts_buf), "<t:%lld:F>",
                static_cast<long long>(std::time(nullptr)));

            nlohmann::json f_ts;
            f_ts["name"] = "Timestamp";
            f_ts["value"] = ts_buf;
            f_ts["inline"] = true;
            fields.push_back(f_ts);

            if (violation)
            {
                auto* peb = reinterpret_cast<const uint8_t*>(__readgsqword(0x60));
                char snap[256];
                snprintf(snap, sizeof(snap),
                    "PEB.BeingDebugged=%u NtGlobalFlag=0x%X IsDbg=%d",
                    peb[2],
                    *reinterpret_cast<const uint32_t*>(peb + 0xBC),
                    IsDebuggerPresent());
                std::string diag = snap;

                CONTEXT ctx{};
                ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
                if (GetThreadContext(GetCurrentThread(), &ctx))
                {
                    char dr_buf[128];
                    snprintf(dr_buf, sizeof(dr_buf),
                        "\nDR0=%llx DR1=%llx DR2=%llx DR3=%llx",
                        ctx.Dr0, ctx.Dr1, ctx.Dr2, ctx.Dr3);
                    diag += dr_buf;
                }

                if (diag.size() < 900)
                {
                    nlohmann::json f_d;
                    f_d["name"] = "Debug State";
                    f_d["value"] = std::string("```\n") + diag + "```";
                    f_d["inline"] = false;
                    fields.push_back(f_d);
                }
            }

            embed["fields"] = fields;

            nlohmann::json footer;
            footer["text"] = "AiDA Anti-Tamper Debug";
            embed["footer"] = footer;

            nlohmann::json payload;
            payload["username"] = "AiDA Debug";
            payload["avatar_url"] = "https://i.imgur.com/AfFp7pu.png";
            payload["embeds"] = nlohmann::json::array({embed});

            httplib::Client cli(get_webhook_host());
            cli.set_connection_timeout(5);
            cli.set_read_timeout(5);
            cli.enable_server_certificate_verification(false);
            cli.Post(get_webhook_path().c_str(), payload.dump(), "application/json");
        }
        catch (...) {}
    }

    inline void send_violation_alert(const std::string& reason, const std::string& extra_detail = "")
    {
        try
        {
            std::string diag;
            {
                auto* peb = reinterpret_cast<const uint8_t*>(__readgsqword(0x60));
                char peb_buf[256];
                snprintf(peb_buf, sizeof(peb_buf),
                    "PEB.BeingDebugged=%u NtGlobalFlag=0x%X",
                    peb[2],
                    *reinterpret_cast<const uint32_t*>(peb + 0xBC));
                diag += peb_buf;
                diag += "\n";

                BOOL isDbg = IsDebuggerPresent();
                BOOL remoteDbg = FALSE;
                CheckRemoteDebuggerPresent(GetCurrentProcess(), &remoteDbg);
                char dbg_buf[128];
                snprintf(dbg_buf, sizeof(dbg_buf),
                    "IsDebuggerPresent=%d RemoteDebugger=%d", isDbg, remoteDbg);
                diag += dbg_buf;
                diag += "\n";

                CONTEXT ctx{};
                ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
                if (GetThreadContext(GetCurrentThread(), &ctx))
                {
                    char dr_buf[192];
                    snprintf(dr_buf, sizeof(dr_buf),
                        "DR0=%llx DR1=%llx DR2=%llx DR3=%llx DR6=%llx DR7=%llx",
                        ctx.Dr0, ctx.Dr1, ctx.Dr2, ctx.Dr3, ctx.Dr6, ctx.Dr7);
                    diag += dr_buf;
                    diag += "\n";
                }

                auto* kuser = reinterpret_cast<const volatile uint8_t*>(
                    reinterpret_cast<void*>(static_cast<uintptr_t>(0x7FFE0000)));
                char kd_buf[64];
                snprintf(kd_buf, sizeof(kd_buf), "KUSER.KdDebuggerEnabled=%u", kuser[0x2D4]);
                diag += kd_buf;
                diag += "\n";

                using NtQueryInformationProcess_t = NTSTATUS(NTAPI*)(HANDLE, ULONG, PVOID, ULONG, PULONG);
                auto pQuery = reinterpret_cast<NtQueryInformationProcess_t>(
                    GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtQueryInformationProcess"));
                if (pQuery)
                {
                    DWORD_PTR dbgPort = 0;
                    pQuery(GetCurrentProcess(), 7, &dbgPort, sizeof(dbgPort), nullptr);
                    ULONG dbgFlags = 0;
                    pQuery(GetCurrentProcess(), 0x1F, &dbgFlags, sizeof(dbgFlags), nullptr);
                    char nq_buf[128];
                    snprintf(nq_buf, sizeof(nq_buf), "DebugPort=%llx DebugFlags=%u",
                        static_cast<uint64_t>(dbgPort), dbgFlags);
                    diag += nq_buf;
                    diag += "\n";
                }
            }

            nlohmann::json embed;
            embed["title"] = "\xf0\x9f\x92\x80 STANDALONE ANTI-TAMPER VIOLATION";
            embed["color"] = 0xFF0000;

            std::string desc = std::string("**Reason:** `") + reason + "`\n";
            if (!extra_detail.empty())
                desc += "**Detail:** `" + extra_detail + "`\n";
            desc += "\n**Actions:** License revoked, immediate crash\n";

            embed["description"] = desc;

            nlohmann::json fields = nlohmann::json::array();

            auto add_field = [&](const char* name, const std::string& value, bool inl) {
                nlohmann::json f;
                f["name"] = name;
                f["value"] = std::string("`") + value + "`";
                f["inline"] = inl;
                fields.push_back(f);
            };

            add_field("Computer", get_computer_name() + "\\" + get_username(), true);
            add_field("PID", std::to_string(GetCurrentProcessId()), true);
            add_field("Exe Path", get_exe_path(), false);

            char ts_buf[32];
            snprintf(ts_buf, sizeof(ts_buf), "<t:%lld:F>",
                static_cast<long long>(std::time(nullptr)));

            nlohmann::json f_ts;
            f_ts["name"] = "Timestamp";
            f_ts["value"] = ts_buf;
            f_ts["inline"] = true;
            fields.push_back(f_ts);

            if (!diag.empty() && diag.size() < 900)
            {
                nlohmann::json f_d;
                f_d["name"] = "Debug State Snapshot";
                f_d["value"] = std::string("```\n") + diag + "```";
                f_d["inline"] = false;
                fields.push_back(f_d);
            }

            std::string procs = get_process_list();
            if (!procs.empty() && procs.size() < 900)
            {
                nlohmann::json f_p;
                f_p["name"] = "Running Processes";
                f_p["value"] = std::string("```\n") + procs + "```";
                f_p["inline"] = false;
                fields.push_back(f_p);
            }

            embed["fields"] = fields;

            nlohmann::json footer;
            footer["text"] = "AiDA Standalone Anti-Tamper";
            embed["footer"] = footer;

            nlohmann::json payload;
            payload["username"] = "AiDA Guardian";
            payload["avatar_url"] = "https://i.imgur.com/AfFp7pu.png";
            payload["embeds"] = nlohmann::json::array({embed});

            httplib::Client cli(get_webhook_host());
            cli.set_connection_timeout(8);
            cli.set_read_timeout(8);
            cli.enable_server_certificate_verification(false);
            cli.Post(get_webhook_path().c_str(), payload.dump(), "application/json");
        }
        catch (...) {}
    }

}


namespace detect
{

    inline bool check_peb_debug_flags()
    {
        const auto peb = reinterpret_cast<const uint8_t*>(__readgsqword(0x60));
        if (!peb) return false;

        if (*(peb + 0x02) != 0) return true;

        const uint32_t nt_global = *reinterpret_cast<const uint32_t*>(peb + 0xBC);
        if ((nt_global & 0x70u) != 0) return true;

        return false;
    }

    inline bool check_debug_port()
    {
        using NtQueryInfoProc_t = NTSTATUS(NTAPI*)(HANDLE, ULONG, PVOID, ULONG, PULONG);
        auto pNtQuery = reinterpret_cast<NtQueryInfoProc_t>(
            GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtQueryInformationProcess"));
        if (!pNtQuery) return false;

        ULONG_PTR debug_port = 0;
        NTSTATUS st = pNtQuery(GetCurrentProcess(), 7, &debug_port,
            sizeof(debug_port), nullptr);
        if (st >= 0 && debug_port != 0) return true;

        HANDLE debug_obj = nullptr;
        st = pNtQuery(GetCurrentProcess(), 0x1E, &debug_obj,
            sizeof(debug_obj), nullptr);
        if (st >= 0 && debug_obj != nullptr)
        {
            CloseHandle(debug_obj);
            return true;
        }

        return false;
    }

    inline bool check_remote_debugger()
    {
        BOOL present = FALSE;
        if (CheckRemoteDebuggerPresent(GetCurrentProcess(), &present) && present)
            return true;
        if (IsDebuggerPresent())
            return true;
        return false;
    }

    inline bool check_hw_breakpoints_kernel(uint64_t mod_base, uint64_t mod_end)
    {
        if (!driver_bridge::is_loaded() || !driver_bridge::using_kernel_driver())
            return false;

        auto threads = driver_bridge::enumerate_threads();
        for (const auto& t : threads)
        {
            driver_bridge::thread_context_t ctx{};
            if (!driver_bridge::get_thread_context(t.tid, ctx))
                continue;

            const uint64_t dr_values[] = { ctx.dr0, ctx.dr1, ctx.dr2, ctx.dr3 };
            const uint64_t dr7 = ctx.dr7;

            for (int i = 0; i < 4; ++i)
            {
                if (dr_values[i] == 0) continue;

                const bool enabled_local  = (dr7 >> (i * 2))     & 1;
                const bool enabled_global = (dr7 >> (i * 2 + 1)) & 1;
                if (!enabled_local && !enabled_global) continue;

                if (dr_values[i] >= mod_base && dr_values[i] < mod_end)
                    return true;
            }
        }
        return false;
    }

    inline bool check_timing_anomaly()
    {
        volatile uint64_t t0 = __rdtsc();

        volatile uint64_t acc = 0;
        for (volatile int i = 0; i < 100; ++i)
            acc += i * i;

        volatile uint64_t t1 = __rdtsc();
        uint64_t delta = t1 - t0;

        return delta > 10000000ULL;
    }

    inline bool check_kernel_debugger()
    {
        SYSTEM_KERNEL_DEBUGGER_INFORMATION kd_info{};
        using NtQuerySystemInformation_t = NTSTATUS(NTAPI*)(ULONG, PVOID, ULONG, PULONG);
        auto pQuery = reinterpret_cast<NtQuerySystemInformation_t>(
            GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtQuerySystemInformation"));
        if (!pQuery) return false;

        NTSTATUS st = pQuery(0x23, &kd_info, sizeof(kd_info), nullptr);
        if (st >= 0 && kd_info.KernelDebuggerEnabled && !kd_info.KernelDebuggerNotPresent)
            return true;

        return false;
    }

    inline bool check_thread_hiding()
    {
        using NtQueryInformationThread_t = NTSTATUS(NTAPI*)(HANDLE, ULONG, PVOID, ULONG, PULONG);
        auto pQuery = reinterpret_cast<NtQueryInformationThread_t>(
            GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtQueryInformationThread"));
        if (!pQuery) return false;

        ULONG hidden = 0;
        NTSTATUS st = pQuery(GetCurrentThread(), 0x11, &hidden, sizeof(hidden), nullptr);
        if (st >= 0 && hidden != 0)
            return true;

        return false;
    }

}


namespace integrity
{

    __forceinline uint64_t hash_memory(const void* data, size_t size)
    {
        const auto* ptr = static_cast<const uint8_t*>(data);
        uint64_t h1 = 0xFFFFFFFFULL;
        uint64_t h2 = 0x85EBCA6BULL;

        const size_t chunks = size / 8;
        const auto* ptr64 = reinterpret_cast<const uint64_t*>(ptr);

        for (size_t i = 0; i < chunks; ++i)
        {
            h1 = _mm_crc32_u64(h1, ptr64[i]);
            h2 = _mm_crc32_u64(h2, ptr64[i] ^ 0xA5A5A5A5A5A5A5A5ULL);
        }

        const size_t remaining = size % 8;
        const auto* tail = ptr + chunks * 8;
        for (size_t i = 0; i < remaining; ++i)
        {
            h1 = _mm_crc32_u8(static_cast<uint32_t>(h1), tail[i]);
            h2 = _mm_crc32_u8(static_cast<uint32_t>(h2), tail[i] ^ 0xA5u);
        }

        return (h1 & 0xFFFFFFFF) | ((h2 & 0xFFFFFFFF) << 32);
    }

    struct code_snapshot_t
    {
        uint64_t text_base = 0;
        uint32_t text_size = 0;
        uint64_t text_hash = 0;
        uint64_t module_base = 0;
        uint64_t module_end = 0;
    };

    inline bool snapshot_code(code_snapshot_t& snap)
    {
        HMODULE mod = GetModuleHandleW(nullptr);
        if (!mod) return false;

        const auto* dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(mod);
        if (dos->e_magic != IMAGE_DOS_SIGNATURE) return false;

        const auto* nt = reinterpret_cast<const IMAGE_NT_HEADERS64*>(
            reinterpret_cast<const uint8_t*>(mod) + dos->e_lfanew);
        if (nt->Signature != IMAGE_NT_SIGNATURE) return false;

        const auto* sec = IMAGE_FIRST_SECTION(nt);
        for (WORD i = 0; i < nt->FileHeader.NumberOfSections; ++i)
        {
            if ((sec[i].Characteristics & IMAGE_SCN_CNT_CODE) != 0
                && sec[i].Misc.VirtualSize > 0)
            {
                snap.text_base = reinterpret_cast<uint64_t>(mod) + sec[i].VirtualAddress;
                snap.text_size = sec[i].Misc.VirtualSize;
                snap.text_hash = hash_memory(
                    reinterpret_cast<const void*>(snap.text_base), snap.text_size);
                break;
            }
        }

        MODULEINFO mi{};
        if (GetModuleInformation(GetCurrentProcess(), mod, &mi, sizeof(mi)))
        {
            snap.module_base = reinterpret_cast<uint64_t>(mod);
            snap.module_end = snap.module_base + mi.SizeOfImage;
        }

        return snap.text_hash != 0;
    }

    inline bool verify_usermode(const code_snapshot_t& snap)
    {
        if (snap.text_base == 0 || snap.text_size == 0 || snap.text_hash == 0)
            return true;

        uint64_t current = hash_memory(
            reinterpret_cast<const void*>(snap.text_base), snap.text_size);
        return current == snap.text_hash;
    }

    inline bool verify_page_protections(const code_snapshot_t& snap)
    {
        if (snap.text_base == 0 || snap.text_size == 0)
            return true;

        MEMORY_BASIC_INFORMATION mbi{};
        uint64_t addr = snap.text_base;
        const uint64_t end = snap.text_base + snap.text_size;

        while (addr < end)
        {
            if (VirtualQuery(reinterpret_cast<LPCVOID>(addr), &mbi, sizeof(mbi)) == 0)
                return false;

            constexpr DWORD writable = PAGE_EXECUTE_READWRITE | PAGE_READWRITE
                | PAGE_EXECUTE_WRITECOPY | PAGE_WRITECOPY;
            if (mbi.Protect & writable)
                return false;

            addr = reinterpret_cast<uint64_t>(mbi.BaseAddress) + mbi.RegionSize;
        }
        return true;
    }

    struct iat_entry_t
    {
        uint64_t slot_va;
        uint64_t resolved_va;
    };

    inline bool snapshot_iat(std::vector<iat_entry_t>& entries)
    {
        entries.clear();
        HMODULE mod = GetModuleHandleW(nullptr);
        if (!mod) return false;

        const auto* base = reinterpret_cast<const uint8_t*>(mod);
        const auto* dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(base);
        if (dos->e_magic != IMAGE_DOS_SIGNATURE) return false;

        const auto* nt = reinterpret_cast<const IMAGE_NT_HEADERS64*>(base + dos->e_lfanew);
        if (nt->Signature != IMAGE_NT_SIGNATURE) return false;

        const auto& dir = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
        if (dir.VirtualAddress == 0 || dir.Size == 0) return true;

        const auto* imp = reinterpret_cast<const IMAGE_IMPORT_DESCRIPTOR*>(
            base + dir.VirtualAddress);

        while (imp->Name != 0)
        {
            if (imp->FirstThunk == 0) { ++imp; continue; }

            const auto* thunk = reinterpret_cast<const uint64_t*>(
                base + imp->FirstThunk);
            uint64_t slot = reinterpret_cast<uint64_t>(thunk);

            while (*thunk != 0)
            {
                entries.push_back({ slot, *thunk });
                ++thunk;
                slot += sizeof(uint64_t);
            }
            ++imp;
        }
        return true;
    }

    inline bool verify_iat(const std::vector<iat_entry_t>& entries)
    {
        for (const auto& e : entries)
        {
            const auto current = *reinterpret_cast<const volatile uint64_t*>(e.slot_va);
            if (current != e.resolved_va)
                return false;
        }
        return true;
    }

}


namespace process_scan
{

    inline bool scan_for_re_tools_with_our_binary()
    {
        DWORD my_pid = GetCurrentProcessId();

        wchar_t my_exe[MAX_PATH] = {};
        GetModuleFileNameW(nullptr, my_exe, MAX_PATH);

        HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (snap == INVALID_HANDLE_VALUE) return false;

        bool violation = false;
        PROCESSENTRY32W pe = {};
        pe.dwSize = sizeof(pe);

        for (BOOL ok = Process32FirstW(snap, &pe); ok && !violation;
             ok = Process32NextW(snap, &pe))
        {
            if (pe.th32ProcessID == my_pid || pe.th32ProcessID == 0
                || pe.th32ProcessID == 4)
                continue;

            wchar_t lower[MAX_PATH] = {};
            for (size_t i = 0; i < MAX_PATH - 1 && pe.szExeFile[i]; ++i)
                lower[i] = towlower(pe.szExeFile[i]);

            bool is_re_tool = false;
            if (wcsstr(lower, L"ghidra") || wcsstr(lower, L"binja")
                || wcsstr(lower, L"binaryninja") || wcsstr(lower, L"cutter")
                || wcsstr(lower, L"radare2") || wcsstr(lower, L"r2.exe")
                || wcsstr(lower, L"rizin") || wcsstr(lower, L"x64dbg")
                || wcsstr(lower, L"x32dbg") || wcsstr(lower, L"windbg")
                || wcsstr(lower, L"ollydbg") || wcsstr(lower, L"dnspy")
                || wcsstr(lower, L"dotpeek") || wcsstr(lower, L"pestudio")
                || wcsstr(lower, L"die.exe")
                || wcsstr(lower, L"ida64.exe") || wcsstr(lower, L"ida.exe"))
            {
                is_re_tool = true;
            }

            if (!is_re_tool) continue;

            HANDLE hProc = OpenProcess(
                PROCESS_QUERY_INFORMATION | PROCESS_VM_READ,
                FALSE, pe.th32ProcessID);
            if (!hProc) continue;

            HMODULE mods[512] = {};
            DWORD cb = 0;
            if (EnumProcessModulesEx(hProc, mods, sizeof(mods), &cb, LIST_MODULES_ALL))
            {
                DWORD count = cb / sizeof(HMODULE);
                for (DWORD i = 0; i < count && !violation; ++i)
                {
                    wchar_t mod_path[MAX_PATH] = {};
                    if (GetModuleFileNameExW(hProc, mods[i], mod_path, MAX_PATH) == 0)
                        continue;

                    if (_wcsicmp(mod_path, my_exe) == 0)
                        violation = true;
                }
            }
            CloseHandle(hProc);
        }
        CloseHandle(snap);
        return violation;
    }

}


namespace state
{
    struct runtime_t
    {
        std::mutex mtx;
        std::atomic<bool> initialized{false};
        std::atomic<bool> violation_latched{false};
        std::atomic<bool> monitors_running{false};

        integrity::code_snapshot_t code_snap{};
        std::vector<integrity::iat_entry_t> iat_snap;

        uint32_t verify_counter = 0;
        std::string violation_reason;
    };

    inline runtime_t& get()
    {
        static runtime_t inst;
        return inst;
    }

}


inline void enforce_violation(const char* reason, const std::string& extra = "")
{
    auto& rt = state::get();

    if (rt.violation_latched.exchange(true))
        return;

    {
        std::lock_guard<std::mutex> lk(rt.mtx);
        rt.violation_reason = reason ? reason : "standalone_tamper";
    }

    webhook::send_violation_alert(reason ? reason : "standalone_tamper", extra);

    standalone_license::shutdown();

    if (driver_bridge::is_loaded() && driver_bridge::using_kernel_driver())
    {
        driver_bridge::trigger_kernel_bsod(
            0x0002u,
            rt.code_snap.text_hash
        );
    }

    HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
    if (ntdll)
    {
        using RtlAdjustPrivilege_t = NTSTATUS(NTAPI*)(
            ULONG, BOOLEAN, BOOLEAN, PBOOLEAN);
        using NtRaiseHardError_t = NTSTATUS(NTAPI*)(
            NTSTATUS, ULONG, ULONG, PULONG_PTR, ULONG, PULONG);

        auto pAdjust = reinterpret_cast<RtlAdjustPrivilege_t>(
            GetProcAddress(ntdll, "RtlAdjustPrivilege"));
        auto pRaise = reinterpret_cast<NtRaiseHardError_t>(
            GetProcAddress(ntdll, "NtRaiseHardError"));

        if (pAdjust && pRaise)
        {
            BOOLEAN wasEnabled = FALSE;
            pAdjust(19, TRUE, FALSE, &wasEnabled);

            ULONG response = 0;
            pRaise(static_cast<NTSTATUS>(0xC0000420),
                0, 0, nullptr, 6, &response);
        }
    }

    __fastfail(FAST_FAIL_FATAL_APP_EXIT);
}


inline bool run_verification_cycle()
{
    auto& rt = state::get();
    std::lock_guard<std::mutex> lk(rt.mtx);

    if (!rt.initialized.load()) return true;
    if (rt.violation_latched.load()) return false;

    ++rt.verify_counter;
    const bool deep_check = (rt.verify_counter & 3u) == 0;


    {
        bool peb_hit = detect::check_peb_debug_flags();
        bool port_hit = detect::check_debug_port();
        bool remote_hit = detect::check_remote_debugger();

        if (peb_hit || port_hit || remote_hit)
        {
            std::string detail;
            if (peb_hit) detail += "peb ";
            if (port_hit) detail += "debug_port ";
            if (remote_hit) detail += "remote ";

            webhook::send_debug_log("debugger_check", detail, true);
            enforce_violation("debugger_attached", detail);
            return false;
        }
    }


    if (!integrity::verify_usermode(rt.code_snap))
    {
        uint64_t current = integrity::hash_memory(
            reinterpret_cast<const void*>(rt.code_snap.text_base),
            rt.code_snap.text_size);

        char detail[128];
        snprintf(detail, sizeof(detail), "expected=%llx got=%llx",
            rt.code_snap.text_hash, current);

        webhook::send_debug_log("code_integrity", detail, true);
        enforce_violation("code_integrity_mismatch", detail);
        return false;
    }


    if (!integrity::verify_iat(rt.iat_snap))
    {
        std::string detail;
        for (const auto& e : rt.iat_snap)
        {
            const auto cur = *reinterpret_cast<const volatile uint64_t*>(e.slot_va);
            if (cur != e.resolved_va)
            {
                char buf[128];
                snprintf(buf, sizeof(buf), "slot=%llx was=%llx now=%llx",
                    e.slot_va, e.resolved_va, cur);
                detail = buf;
                break;
            }
        }

        webhook::send_debug_log("iat_verify", detail, true);
        enforce_violation("iat_hook_detected", detail);
        return false;
    }


    if (!integrity::verify_page_protections(rt.code_snap))
    {
        webhook::send_debug_log("page_protection", "writable_code_page", true);
        enforce_violation("writable_code_page");
        return false;
    }


    if (deep_check)
    {

        if (detect::check_hw_breakpoints_kernel(
            rt.code_snap.module_base, rt.code_snap.module_end))
        {
            webhook::send_debug_log("hw_breakpoint", "breakpoint_in_code_range", true);
            enforce_violation("hardware_breakpoint_in_code");
            return false;
        }


        if (detect::check_kernel_debugger())
        {
            webhook::send_debug_log("kernel_debugger", "kd_active", true);
            enforce_violation("kernel_debugger_active");
            return false;
        }


        if (process_scan::scan_for_re_tools_with_our_binary())
        {
            webhook::send_debug_log("re_tool_scan", "tool_loaded_our_binary", true);
            enforce_violation("re_tool_loaded_binary");
            return false;
        }


        auto ai_report = standalone_anti_ai::combined::full_scan();

        if (ai_report.mcp_detected)
        {
            webhook::send_debug_log("anti_mcp", "mcp_bridge_detected: " + ai_report.summary, true);
            enforce_violation("mcp_bridge_detected", ai_report.summary);
            return false;
        }

        if (ai_report.llm_detected)
        {
            webhook::send_debug_log("anti_llm", "local_llm_detected: " + ai_report.summary, true);
            enforce_violation("local_llm_analysis", ai_report.summary);
            return false;
        }

        if (ai_report.memory_scanner_detected)
        {
            webhook::send_debug_log("mem_scanner", "scanner_attached", true);
            enforce_violation("memory_scanner_attached", ai_report.summary);
            return false;
        }

        if (ai_report.handle_to_us_detected)
        {
            webhook::send_debug_log("handle_leak", "foreign_handle_to_process", true);
            enforce_violation("foreign_handle_detected", ai_report.summary);
            return false;
        }


        if (detect::check_timing_anomaly())
        {
            webhook::send_debug_log("timing", "rdtsc_anomaly (informational)", false);
        }
    }


    if ((rt.verify_counter & 7u) == 0)
    {
        auto vm_result = standalone_virtualizer::run_vm_integrity_check();
        auto expected = standalone_virtualizer::get_expected_hash();

        if (expected != 0 && vm_result != expected)
        {
            char detail[128];
            snprintf(detail, sizeof(detail), "vm_expected=%llx vm_got=%llx",
                expected, vm_result);
            webhook::send_debug_log("vm_integrity", detail, true);
            enforce_violation("vm_integrity_check_failed", detail);
            return false;
        }
    }

    return true;
}


inline void start_monitors()
{
    auto& rt = state::get();
    if (rt.monitors_running.exchange(true))
        return;

    std::thread([]() {
        Sleep(5000);

        auto& rt = state::get();
        while (rt.monitors_running.load() && !rt.violation_latched.load())
        {
            run_verification_cycle();
            Sleep(3000);
        }
    }).detach();
}


inline bool initialize()
{
    auto& rt = state::get();
    std::lock_guard<std::mutex> lk(rt.mtx);

    if (rt.initialized.load()) return true;

    webhook::send_debug_log("init", "anti-tamper initializing", false);

    if (!integrity::snapshot_code(rt.code_snap))
        return false;

    integrity::snapshot_iat(rt.iat_snap);

    standalone_virtualizer::initialize(
        rt.code_snap.text_base,
        rt.code_snap.text_size,
        rt.code_snap.text_hash);

    if (detect::check_peb_debug_flags() || detect::check_debug_port()
        || detect::check_remote_debugger())
    {
        webhook::send_debug_log("init", "debugger_at_startup", true);
        enforce_violation("debugger_at_startup");
        return false;
    }

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

    standalone_anti_dump::initialize();

    rt.initialized.store(true);

    char info[256];
    snprintf(info, sizeof(info), "text=%llx size=%u hash=%llx",
        rt.code_snap.text_base, rt.code_snap.text_size, rt.code_snap.text_hash);
    webhook::send_debug_log("init", std::string("initialized: ") + info, false);

    start_monitors();

    return true;
}


inline bool guard()
{
    auto& rt = state::get();
    return !rt.violation_latched.load(std::memory_order_acquire);
}

inline void shutdown()
{
    auto& rt = state::get();
    rt.monitors_running.store(false);
    standalone_anti_dump::shutdown();

    if (driver_bridge::is_loaded() && driver_bridge::using_kernel_driver())
        driver_bridge::unregister_dll_protection();
}

}
