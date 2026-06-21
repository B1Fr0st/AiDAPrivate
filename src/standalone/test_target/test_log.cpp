#define AIDA_TARGET_LOG_NO_MACROS
#include "test_log.h"

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif

#include <Windows.h>
#include <cstdio>
#include <cstring>
#include <mutex>
#include <string>

namespace {
    std::mutex g_log_mutex;
    HANDLE g_log_file = INVALID_HANDLE_VALUE;
    thread_local std::string g_pending_log_line;

    void format_timestamp(char* out, std::size_t cap)
    {
        SYSTEMTIME st{};
        GetLocalTime(&st);
        _snprintf_s(out, cap, _TRUNCATE, "%04u-%02u-%02u %02u:%02u:%02u.%03u",
            static_cast<unsigned>(st.wYear), static_cast<unsigned>(st.wMonth), static_cast<unsigned>(st.wDay),
            static_cast<unsigned>(st.wHour), static_cast<unsigned>(st.wMinute), static_cast<unsigned>(st.wSecond),
            static_cast<unsigned>(st.wMilliseconds));
    }

    void write_file_locked(const char* text, std::size_t len)
    {
        if (g_log_file == INVALID_HANDLE_VALUE || !text || len == 0)
            return;
        DWORD wrote = 0;
        BOOL ok = WriteFile(g_log_file, text, static_cast<DWORD>(len), &wrote, nullptr);
        if (!ok || wrote != static_cast<DWORD>(len)) {
            char dbg[384];
            _snprintf_s(dbg, sizeof(dbg), _TRUNCATE,
                "[AIDA-TEST-TARGET] log write failed ok=%d requested=%zu wrote=%lu err=%lu\n",
                ok ? 1 : 0, len, static_cast<unsigned long>(wrote), GetLastError());
            OutputDebugStringA(dbg);
        }
        FlushFileBuffers(g_log_file);
    }

    void append_prefixed_line_locked(std::string& out, const char* text, std::size_t len)
    {
        char ts[40];
        format_timestamp(ts, sizeof(ts));

        char prefix[160];
        int n = _snprintf_s(prefix, sizeof(prefix), _TRUNCATE,
            "[%s] [target pid=%lu tid=%lu] ",
            ts,
            static_cast<unsigned long>(GetCurrentProcessId()),
            static_cast<unsigned long>(GetCurrentThreadId()));
        if (n > 0)
            out.append(prefix, static_cast<std::size_t>(n));
        if (text && len > 0)
            out.append(text, len);
        out.push_back('\n');
    }

    void write_target_text_locked(const char* text, std::size_t len)
    {
        if (g_log_file == INVALID_HANDLE_VALUE || !text || len == 0)
            return;

        std::string out;
        out.reserve(len + 256);

        std::size_t pos = 0;
        while (pos < len) {
            std::size_t end = pos;
            while (end < len && text[end] != '\r' && text[end] != '\n')
                ++end;

            g_pending_log_line.append(text + pos, end - pos);

            if (end == len) {
                break;
            }

            append_prefixed_line_locked(out, g_pending_log_line.data(), g_pending_log_line.size());
            g_pending_log_line.clear();

            if (text[end] == '\r' && end + 1 < len && text[end + 1] == '\n')
                pos = end + 2;
            else
                pos = end + 1;
        }

        if (!out.empty())
            write_file_locked(out.data(), out.size());
    }

    void flush_pending_target_text_locked()
    {
        if (g_pending_log_line.empty())
            return;

        std::string out;
        append_prefixed_line_locked(out, g_pending_log_line.data(), g_pending_log_line.size());
        g_pending_log_line.clear();
        write_file_locked(out.data(), out.size());
    }

    void write_target_log_open_line_locked(const char* path, bool ok, DWORD err)
    {
        char line[512];
        char ts[40];
        format_timestamp(ts, sizeof(ts));
        int n = _snprintf_s(line, sizeof(line), _TRUNCATE,
            "[%s] [target-log] open path=\"%s\" ok=%d err=%lu pid=%lu tid=%lu\n",
            ts,
            path ? path : "", ok ? 1 : 0, static_cast<unsigned long>(err),
            static_cast<unsigned long>(GetCurrentProcessId()),
            static_cast<unsigned long>(GetCurrentThreadId()));
        if (n > 0) {
            fputs(line, stdout);
            fflush(stdout);
            OutputDebugStringA(line);
            if (g_log_file != INVALID_HANDLE_VALUE)
                write_file_locked(line, static_cast<std::size_t>(n));
        }
    }
}

void aida_target_log_set_file(const char* path)
{
    std::lock_guard<std::mutex> lk(g_log_mutex);
    if (g_log_file != INVALID_HANDLE_VALUE) {
        CloseHandle(g_log_file);
        g_log_file = INVALID_HANDLE_VALUE;
    }
    if (!path || !*path)
        return;
    g_log_file = CreateFileA(path, FILE_APPEND_DATA, FILE_SHARE_READ | FILE_SHARE_WRITE,
        nullptr, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (g_log_file != INVALID_HANDLE_VALUE) {
        write_target_log_open_line_locked(path, true, 0);
        return;
    }

    DWORD primary_err = GetLastError();
    write_target_log_open_line_locked(path, false, primary_err);
}

void aida_target_log_close()
{
    std::lock_guard<std::mutex> lk(g_log_mutex);
    if (g_log_file != INVALID_HANDLE_VALUE) {
        flush_pending_target_text_locked();
        CloseHandle(g_log_file);
        g_log_file = INVALID_HANDLE_VALUE;
    }
}

int aida_target_vprintf(const char* fmt, va_list ap)
{
    if (!fmt)
        return 0;

    va_list console_ap;
    va_copy(console_ap, ap);
    const int rc = vprintf(fmt, console_ap);
    va_end(console_ap);
    fflush(stdout);

    va_list count_ap;
    va_copy(count_ap, ap);
    int needed = _vscprintf(fmt, count_ap);
    va_end(count_ap);
    if (needed <= 0)
        return rc;

    std::string line;
    line.resize(static_cast<std::size_t>(needed) + 1u);
    va_list file_ap;
    va_copy(file_ap, ap);
    vsnprintf(line.data(), line.size(), fmt, file_ap);
    va_end(file_ap);

    std::lock_guard<std::mutex> lk(g_log_mutex);
    write_target_text_locked(line.data(), static_cast<std::size_t>(needed));
    return rc;
}

int aida_target_printf(const char* fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    int rc = aida_target_vprintf(fmt, ap);
    va_end(ap);
    return rc;
}
