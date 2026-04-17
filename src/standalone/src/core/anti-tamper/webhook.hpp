#pragma once

#include <windows.h>
#include <psapi.h>
#include <tlhelp32.h>
#include <intrin.h>

#include <atomic>
#include <chrono>
#include <cstdint>
#include <ctime>
#include <mutex>
#include <string>
#include <vector>

#include "../../../obfuscation.hpp"
#include "../../../../../libs/cpp-httplib/httplib.h"
#include "../../../../../libs/nlohmann/json.hpp"

namespace anti_tamper {
namespace webhook {

namespace detail {

    inline const char* log_path()
    {
        static char s_path[MAX_PATH] = {};
        static std::once_flag s_once;
        std::call_once(s_once, [](){
            DWORD ret = GetModuleFileNameA(nullptr, s_path, MAX_PATH);
            if (ret == 0 || ret >= MAX_PATH)
            {
                strcpy_s(s_path, "aida_debug.log");
                return;
            }
            char* last = strrchr(s_path, '\\');
            if (last)
                *(last + 1) = '\0';
            else
                s_path[0] = '\0';
            strcat_s(s_path, "aida_debug.log");
        });
        return s_path;
    }

    inline std::mutex& log_mtx()
    {
        static std::mutex m;
        return m;
    }
}

inline void write_log(const char* tag, const char* detail)
{
    std::lock_guard<std::mutex> lk(detail::log_mtx());
    const char* path = detail::log_path();

    HANDLE hf = CreateFileA(path, GENERIC_WRITE, FILE_SHARE_READ, nullptr,
        OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (hf == INVALID_HANDLE_VALUE) return;
    SetFilePointer(hf, 0, nullptr, FILE_END);

    SYSTEMTIME st{};
    GetLocalTime(&st);
    char line[1024];
    int len = _snprintf_s(line, sizeof(line), _TRUNCATE,
        "[%02d:%02d:%02d.%03d] [%s] %s\r\n",
        st.wHour, st.wMinute, st.wSecond, st.wMilliseconds,
        tag, detail);
    if (len > 0) {
        DWORD written;
        WriteFile(hf, line, static_cast<DWORD>(len), &written, nullptr);
    }
    CloseHandle(hf);
}

namespace detail {

    inline std::mutex& rate_mtx()
    {
        static std::mutex m;
        return m;
    }

    inline std::atomic<int>& debug_count()
    {
        static std::atomic<int> c{0};
        return c;
    }

    inline std::atomic<int64_t>& debug_window_start()
    {
        static std::atomic<int64_t> t{0};
        return t;
    }

    inline int64_t now_ms()
    {
        return std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::steady_clock::now().time_since_epoch()).count();
    }

    inline bool rate_check_debug()
    {
        int64_t now = now_ms();
        int64_t window = debug_window_start().load();
        if (now - window > 10000)
        {
            debug_window_start().store(now);
            debug_count().store(1);
            return true;
        }
        int count = debug_count().fetch_add(1);
        return count < 5;
    }

}

inline std::string get_webhook_host()
{
    return OBFSTR("https://discord.com");
}

inline std::string get_webhook_path()
{
    std::string p;
    p += OBFSTR("/api/webhooks/");
    p += OBFSTR("1487822472207138869");
    p += OBFSTR("/");
    p += OBFSTR("nXIS-mL2ExeO_mRKEHOGUGyw-N8gtLRsKrNSn2zxTtsFQysVVC0CekF238oDbx7WmRGA");
    return p;
}

inline std::string get_computer_name()
{
    char buf[MAX_COMPUTERNAME_LENGTH + 1] = {};
    DWORD sz = sizeof(buf);
    GetComputerNameA(buf, &sz);
    return buf;
}

inline std::string get_username()
{
    char buf[256] = {};
    DWORD sz = sizeof(buf);
    GetUserNameA(buf, &sz);
    return buf;
}

inline std::string get_exe_path()
{
    char buf[MAX_PATH] = {};
    GetModuleFileNameA(nullptr, buf, MAX_PATH);
    return buf;
}

inline std::string get_process_list()
{
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) return "";

    std::string result;
    PROCESSENTRY32W pe = {};
    pe.dwSize = sizeof(pe);

    int count = 0;
    for (BOOL ok = Process32FirstW(snap, &pe); ok && count < 40;
         ok = Process32NextW(snap, &pe))
    {
        if (pe.th32ProcessID == 0 || pe.th32ProcessID == 4) continue;

        char narrow[MAX_PATH] = {};
        WideCharToMultiByte(CP_UTF8, 0, pe.szExeFile, -1, narrow, MAX_PATH, nullptr, nullptr);
        result += "[";
        result += std::to_string(pe.th32ProcessID);
        result += "] ";
        result += narrow;
        result += "\n";
        ++count;
    }

    CloseHandle(snap);
    return result;
}

inline std::string collect_debug_state()
{
    std::string diag;

    auto* peb = reinterpret_cast<const uint8_t*>(__readgsqword(0x60));
    char peb_buf[256];
    snprintf(peb_buf, sizeof(peb_buf),
        "PEB.BeingDebugged=%u NtGlobalFlag=0x%X HeapFlags=0x%X HeapForceFlags=0x%X",
        peb[2],
        *reinterpret_cast<const uint32_t*>(peb + 0xBC),
        0u, 0u);
    diag += peb_buf;
    diag += "\n";

    BOOL isDbg = FALSE;
    IsDebuggerPresent() ? (isDbg = TRUE) : (isDbg = FALSE);
    isDbg = IsDebuggerPresent();

    BOOL remoteDbg = FALSE;
    CheckRemoteDebuggerPresent(GetCurrentProcess(), &remoteDbg);

    char dbg_buf[128];
    snprintf(dbg_buf, sizeof(dbg_buf),
        "IsDebuggerPresent=%d RemoteDebugger=%d",
        isDbg, remoteDbg);
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

    HMODULE mod = GetModuleHandleW(nullptr);
    if (mod)
    {
        MODULEINFO mi{};
        GetModuleInformation(GetCurrentProcess(), mod, &mi, sizeof(mi));
        char mod_buf[128];
        snprintf(mod_buf, sizeof(mod_buf),
            "ModuleBase=%llx ImageSize=%u",
            reinterpret_cast<uint64_t>(mod), mi.SizeOfImage);
        diag += mod_buf;
        diag += "\n";
    }

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
        snprintf(nq_buf, sizeof(nq_buf),
            "DebugPort=%llx DebugFlags=%u",
            static_cast<uint64_t>(dbgPort), dbgFlags);
        diag += nq_buf;
        diag += "\n";
    }

    return diag;
}

inline void send_debug_log(const char* check_name, const std::string& detail, bool is_violation)
{
    if (!is_violation && !detail::rate_check_debug())
        return;

    try
    {
        nlohmann::json embed;
        embed["title"] = is_violation
            ? std::string("\xe2\x9a\xa0\xef\xb8\x8f VIOLATION: ") + check_name
            : std::string("\xf0\x9f\x94\x8d CHECK: ") + check_name;
        embed["color"] = is_violation ? 0xFF0000 : 0x3498DB;

        std::string desc;
        desc += "**Module:** `anti_tamper`\n";
        desc += std::string("**Check:** `") + check_name + "`\n";
        if (!detail.empty())
            desc += std::string("**Detail:** `") + detail + "`\n";

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

        char ts_buf[32];
        snprintf(ts_buf, sizeof(ts_buf), "<t:%lld:F>",
            static_cast<long long>(std::time(nullptr)));

        nlohmann::json f_ts;
        f_ts["name"] = "Timestamp";
        f_ts["value"] = ts_buf;
        f_ts["inline"] = true;
        fields.push_back(f_ts);

        if (is_violation)
        {
            std::string diag = collect_debug_state();
            if (!diag.empty() && diag.size() < 900)
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
        payload["username"] = "AiDA Guardian";
        payload["avatar_url"] = "https://i.imgur.com/AfFp7pu.png";
        payload["embeds"] = nlohmann::json::array({embed});

        httplib::Client cli(get_webhook_host());
        cli.set_connection_timeout(5);
        cli.set_read_timeout(5);
        cli.enable_server_certificate_verification(true);
        cli.Post(get_webhook_path().c_str(), payload.dump(), "application/json");
    }
    catch (...) {}
}

inline void send_violation_alert(const char* reason, const std::string& extra_detail)
{
    try
    {
        std::string diag = collect_debug_state();
        std::string procs = get_process_list();

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
        cli.enable_server_certificate_verification(true);
        cli.Post(get_webhook_path().c_str(), payload.dump(), "application/json");
    }
    catch (...) {}
}

}
}
