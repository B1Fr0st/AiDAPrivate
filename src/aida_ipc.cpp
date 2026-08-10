#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif

#include "aida_ipc.hpp"

#include <windows.h>

#include <cstdarg>
#include <cstdio>
#include <cstring>

namespace
{
    bool diag_log_path(char* out, size_t cap)
    {
        if (!out || cap == 0)
            return false;
        char temp[MAX_PATH] = {};
        DWORD len = GetTempPathA(static_cast<DWORD>(sizeof(temp)), temp);
        if (len == 0 || len >= sizeof(temp))
            return false;
        char dir[MAX_PATH] = {};
        if (_snprintf_s(dir, sizeof(dir), _TRUNCATE, "%sAiDA", temp) < 0)
            return false;
        if (!CreateDirectoryA(dir, nullptr))
        {
            DWORD gle = GetLastError();
            if (gle != ERROR_ALREADY_EXISTS)
                return false;
        }
        return _snprintf_s(out, cap, _TRUNCATE, "%s\\aida_ida_plugin.log", dir) >= 0;
    }

    void diag_write_raw(const char* line)
    {
        if (!line || !*line)
            return;
        char path[MAX_PATH] = {};
        if (!diag_log_path(path, sizeof(path)))
            return;
        HANDLE file = CreateFileA(path,
                                  FILE_APPEND_DATA,
                                  FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                                  nullptr,
                                  OPEN_ALWAYS,
                                  FILE_ATTRIBUTE_NORMAL,
                                  nullptr);
        if (file == INVALID_HANDLE_VALUE)
            return;
        DWORD written = 0;
        DWORD len = static_cast<DWORD>(std::strlen(line));
        WriteFile(file, line, len, &written, nullptr);
        FlushFileBuffers(file);
        CloseHandle(file);
        OutputDebugStringA(line);
    }

    void diag_log_vfmt(const char* fmt, va_list args)
    {
        char body[3072] = {};
        _vsnprintf_s(body, sizeof(body), _TRUNCATE, fmt, args);

        SYSTEMTIME st = {};
        GetLocalTime(&st);
        char line[4096] = {};
        _snprintf_s(line,
                    sizeof(line),
                    _TRUNCATE,
                    "[%04u-%02u-%02u %02u:%02u:%02u.%03u] [ida_ipc] pid=%lu tid=%lu tick=%llu %s\r\n",
                    static_cast<unsigned>(st.wYear),
                    static_cast<unsigned>(st.wMonth),
                    static_cast<unsigned>(st.wDay),
                    static_cast<unsigned>(st.wHour),
                    static_cast<unsigned>(st.wMinute),
                    static_cast<unsigned>(st.wSecond),
                    static_cast<unsigned>(st.wMilliseconds),
                    GetCurrentProcessId(),
                    GetCurrentThreadId(),
                    static_cast<unsigned long long>(GetTickCount64()),
                    body);
        diag_write_raw(line);
    }

    void diag_log_fmt(const char* fmt, ...)
    {
        va_list args;
        va_start(args, fmt);
        diag_log_vfmt(fmt, args);
        va_end(args);
    }

    void diag_flush_log()
    {
        char path[MAX_PATH] = {};
        if (!diag_log_path(path, sizeof(path)))
            return;
        HANDLE file = CreateFileA(path,
                                  FILE_APPEND_DATA,
                                  FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                                  nullptr,
                                  OPEN_ALWAYS,
                                  FILE_ATTRIBUTE_NORMAL,
                                  nullptr);
        if (file == INVALID_HANDLE_VALUE)
            return;
        FlushFileBuffers(file);
        CloseHandle(file);
    }
}

namespace aida_ipc
{
    void trace_breadcrumb(const char* fmt, ...)
    {
        const DWORD calling_tid = GetCurrentThreadId();
        const ULONGLONG entry_tick = GetTickCount64();
        char body[3072] = {};
        va_list args;
        va_start(args, fmt);
        _vsnprintf_s(body, sizeof(body), _TRUNCATE, fmt, args);
        va_end(args);
        diag_log_fmt("[BREADCRUMB] calling_tid=%lu entry_tick=%llu body=%s",
                     calling_tid,
                     static_cast<unsigned long long>(entry_tick),
                     body);
        diag_flush_log();
    }

    void log_plugin_startup(const char* phase, const char* detail)
    {
        const DWORD calling_tid = GetCurrentThreadId();
        const ULONGLONG entry_tick = GetTickCount64();
        diag_log_fmt("[PLUGIN_STARTUP] phase=%s detail=%s calling_tid=%lu entry_tick=%llu pid=%lu",
                     phase ? phase : "<null>",
                     detail ? detail : "<null>",
                     calling_tid,
                     static_cast<unsigned long long>(entry_tick),
                     GetCurrentProcessId());
        diag_flush_log();
    }
}
