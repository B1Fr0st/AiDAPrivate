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
#include "../../../../../libs/nlohmann/json.hpp"
#include "../../../../../src/shared/telemetry/telemetry_client.hpp"

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

inline std::string collect_debug_state()
{
    std::string diag;

    auto* peb = reinterpret_cast<const uint8_t*>(__readgsqword(0x60));
    char peb_buf[256];
    snprintf(peb_buf, sizeof(peb_buf),
        "PEB.BeingDebugged=%u NtGlobalFlag=0x%X",
        peb[2],
        *reinterpret_cast<const uint32_t*>(peb + 0xBC));
    diag += peb_buf;
    diag += "\n";

    BOOL isDbg = FALSE;
    CheckRemoteDebuggerPresent(GetCurrentProcess(), &isDbg);
    diag += "IsRemoteDebuggerPresent=";
    diag += (isDbg ? "true" : "false");
    diag += "\n";

    return diag;
}

inline void send_debug_log(const char* check_name, const std::string& detail, bool is_violation)
{
    if (!is_violation && !detail::rate_check_debug())
        return;

    write_log(check_name ? check_name : "check", detail.c_str());

    try
    {
        nlohmann::json payload;
        payload["check"] = check_name ? check_name : "unknown";
        payload["detail"] = detail;
        payload["computer"] = get_computer_name();
        payload["user"] = get_username();
        payload["pid"] = GetCurrentProcessId();
        if (is_violation) {
            payload["debug_state"] = collect_debug_state();
        }

        aida::telemetry::event_t ev;
        ev.type = is_violation ? "violation" : "check";
        ev.severity = is_violation ? aida::telemetry::severity_t::critical
                                   : aida::telemetry::severity_t::info;
        ev.payload_json = payload.dump();
        aida::telemetry::instance().enqueue(ev);
    }
    catch (...) {}
}

inline void send_violation_alert(const char* reason, const std::string& extra_detail)
{
    write_log("violation", (std::string(reason ? reason : "") + " " + extra_detail).c_str());

    try
    {
        nlohmann::json payload;
        payload["reason"] = reason ? reason : "unknown";
        payload["detail"] = extra_detail;
        payload["computer"] = get_computer_name();
        payload["user"] = get_username();
        payload["pid"] = GetCurrentProcessId();
        payload["exe"] = get_exe_path();
        payload["debug_state"] = collect_debug_state();

        aida::telemetry::event_t ev;
        ev.type = "violation_alert";
        ev.severity = aida::telemetry::severity_t::critical;
        ev.payload_json = payload.dump();
        aida::telemetry::instance().enqueue(ev);
        aida::telemetry::instance().flush_blocking();
    }
    catch (...) {}
}

inline void post_critical_then_enforce(const char* reason,
                                       const std::string& extra_detail,
                                       uint32_t signal_mask)
{
    try
    {
        nlohmann::json payload;
        payload["reason"] = reason ? reason : "unknown";
        payload["detail"] = extra_detail;
        payload["signal_mask"] = signal_mask;
        payload["computer"] = get_computer_name();
        payload["user"] = get_username();
        payload["pid"] = GetCurrentProcessId();
        payload["exe"] = get_exe_path();
        payload["debug_state"] = collect_debug_state();
        payload["critical"] = true;

        aida::telemetry::event_t ev;
        ev.type = "critical_webhook";
        ev.severity = aida::telemetry::severity_t::critical;
        ev.payload_json = payload.dump();
        aida::telemetry::instance().enqueue(ev);
        aida::telemetry::instance().flush_blocking();
    }
    catch (...) {}
    write_log("critical_webhook",
        (std::string(reason ? reason : "") + " " + extra_detail).c_str());
}

}
}
