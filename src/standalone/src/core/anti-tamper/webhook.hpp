#pragma once

#include <windows.h>
#include <psapi.h>
#include <tlhelp32.h>
#include <intrin.h>

#include <atomic>
#include <chrono>
#include <cstdarg>
#include <cstdint>
#include <ctime>
#include <mutex>
#include <string>
#include <vector>

#include "../runtime/manual_map_tls.hpp"
#include "../../helpers/diag_log.hpp"
#include "../../../../../libs/nlohmann/json.hpp"
#include "../../../../../src/shared/telemetry/telemetry_client.hpp"

namespace anti_tamper {
namespace webhook {

namespace detail {

    inline const char* log_path()
    {
        static char s_path[MAX_PATH] = {};
        static bool s_init = false;
        if (!s_init)
        {
            if (!diag::build_log_path("aida_debug.log", s_path, sizeof(s_path)))
                s_path[0] = '\0';
            s_init = true;
        }
        return s_path;
    }

    inline std::recursive_mutex& log_mtx()
    {
        static std::recursive_mutex m;
        return m;
    }

    inline bool& log_reentry()
    {
        static thread_local bool active = false;
        return active;
    }

    struct log_scope
    {
        bool entered;

        log_scope() : entered(false)
        {
            bool& active = log_reentry();
            if (!active)
            {
                active = true;
                entered = true;
            }
        }

        ~log_scope()
        {
            if (entered)
                log_reentry() = false;
        }

        explicit operator bool() const
        {
            return entered;
        }
    };

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

namespace detail {

    inline HANDLE& log_handle()
    {
        static HANDLE h = INVALID_HANDLE_VALUE;
        return h;
    }

}

inline void write_log(const char* tag, const char* detail)
{
    aida::manual_map_tls::ensure_current_thread();
    detail::log_scope scope;
    if (!scope) return;

    try
    {
        std::lock_guard<std::recursive_mutex> lk(detail::log_mtx());
        HANDLE& hf = detail::log_handle();
        if (hf == INVALID_HANDLE_VALUE)
        {
            const char* path = detail::log_path();
            if (!path || !*path) return;
            hf = CreateFileA(path, FILE_APPEND_DATA | SYNCHRONIZE,
                FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr,
                OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
            if (hf == INVALID_HANDLE_VALUE) return;
        }

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

            char dbg_line[1100];
            _snprintf_s(dbg_line, sizeof(dbg_line), _TRUNCATE,
                "[AIDA][%02d:%02d:%02d.%03d] [%s] %s",
                st.wHour, st.wMinute, st.wSecond, st.wMilliseconds,
                tag, detail);
            OutputDebugStringA(dbg_line);
        }
    }
    catch (...) {}
}

inline void write_log_critical(const char* tag, const char* detail)
{
    aida::manual_map_tls::ensure_current_thread();
    detail::log_scope scope;
    if (!scope) return;

    try
    {
        std::lock_guard<std::recursive_mutex> lk(detail::log_mtx());
        const char* path = detail::log_path();
        if (!path || !*path) return;
        HANDLE hf = CreateFileA(path,
            FILE_APPEND_DATA | SYNCHRONIZE,
            FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr,
            OPEN_ALWAYS,
            FILE_ATTRIBUTE_NORMAL | FILE_FLAG_WRITE_THROUGH,
            nullptr);
        if (hf == INVALID_HANDLE_VALUE) return;

        SYSTEMTIME st{};
        GetLocalTime(&st);
        char line[2048];
        int len = _snprintf_s(line, sizeof(line), _TRUNCATE,
            "[%02d:%02d:%02d.%03d] [%s] %s\r\n",
            st.wHour, st.wMinute, st.wSecond, st.wMilliseconds,
            tag, detail);
        if (len > 0) {
            DWORD written;
            WriteFile(hf, line, static_cast<DWORD>(len), &written, nullptr);
            FlushFileBuffers(hf);

            char dbg_line[2100];
            _snprintf_s(dbg_line, sizeof(dbg_line), _TRUNCATE,
                "[AIDA-CRIT][%02d:%02d:%02d.%03d] [%s] %s",
                st.wHour, st.wMinute, st.wSecond, st.wMilliseconds,
                tag, detail);
            OutputDebugStringA(dbg_line);
        }
        CloseHandle(hf);
    }
    catch (...) {}
}

inline void write_log_critical_fmt(const char* tag, const char* fmt, ...)
{
    aida::manual_map_tls::ensure_current_thread();
    char buf[2048];
    va_list ap;
    va_start(ap, fmt);
    _vsnprintf_s(buf, sizeof(buf), _TRUNCATE, fmt, ap);
    va_end(ap);
    write_log_critical(tag, buf);
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
        const bool flushed = aida::telemetry::instance().flush_blocking();
        write_log_critical_fmt("violation",
            "violation_alert_flush_result kind=reason flushed=%d detail_len=%zu",
            flushed ? 1 : 0,
            extra_detail.size());
    }
    catch (...) {
        write_log_critical("violation", "violation_alert_flush_exception kind=reason");
    }
}

inline void send_violation_alert_id(uint64_t reason_id, const std::string& extra_detail)
{
    char idbuf[20];
    _snprintf_s(idbuf, sizeof(idbuf), _TRUNCATE,
        "0x%016llX", static_cast<unsigned long long>(reason_id));
    write_log("violation", (std::string(idbuf) + " " + extra_detail).c_str());

    try
    {
        nlohmann::json payload;
        payload["reason_id_hex"] = idbuf;
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
        const bool flushed = aida::telemetry::instance().flush_blocking();
        write_log_critical_fmt("violation",
            "violation_alert_flush_result kind=reason_id flushed=%d detail_len=%zu",
            flushed ? 1 : 0,
            extra_detail.size());
    }
    catch (...) {
        write_log_critical("violation", "violation_alert_flush_exception kind=reason_id");
    }
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
        const bool flushed = aida::telemetry::instance().flush_blocking();
        write_log_critical_fmt("critical_webhook",
            "critical_webhook_flush_result flushed=%d detail_len=%zu signal_mask=0x%08X",
            flushed ? 1 : 0,
            extra_detail.size(),
            signal_mask);
    }
    catch (...) {
        write_log_critical("critical_webhook", "critical_webhook_flush_exception");
    }
    write_log("critical_webhook",
        (std::string(reason ? reason : "") + " " + extra_detail).c_str());
}

}
}
