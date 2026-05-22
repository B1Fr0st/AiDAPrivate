#pragma once

#ifndef NOMINMAX
#define NOMINMAX
#endif
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif

#include <windows.h>
#include <cstdarg>
#include <cstdio>
#include <cstring>

namespace diag {

inline const char* resolve_log_dir()
{
    static char s_cached[MAX_PATH] = {};
    static bool s_ready = false;
    if (s_ready) return s_cached;
    DWORD ret = GetModuleFileNameA(nullptr, s_cached, MAX_PATH);
    if (ret == 0 || ret >= MAX_PATH) {
        s_cached[0] = '\0';
    } else {
        char* last = std::strrchr(s_cached, '\\');
        if (last) *(last + 1) = '\0';
        else s_cached[0] = '\0';
    }
    s_ready = true;
    return s_cached;
}

inline void log_tagged(const char* tag, const char* msg)
{
    char path[MAX_PATH];
    _snprintf_s(path, sizeof(path), _TRUNCATE, "%saida_debug.log", resolve_log_dir());
    HANDLE hf = CreateFileA(path, FILE_APPEND_DATA | SYNCHRONIZE, FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr,
        OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (hf == INVALID_HANDLE_VALUE) return;
    SYSTEMTIME st{};
    GetLocalTime(&st);
    char line[4096];
    int len = _snprintf_s(line, sizeof(line), _TRUNCATE,
        "[%02d:%02d:%02d.%03d] [%s] %s\r\n",
        st.wHour, st.wMinute, st.wSecond, st.wMilliseconds,
        tag ? tag : "diag", msg ? msg : "");
    if (len > 0) {
        DWORD written = 0;
        WriteFile(hf, line, static_cast<DWORD>(len), &written, nullptr);
    }
    CloseHandle(hf);
}

inline void log_tagged_fmt(const char* tag, const char* fmt, ...)
{
    char buf[2048];
    va_list ap;
    va_start(ap, fmt);
    _vsnprintf_s(buf, sizeof(buf), _TRUNCATE, fmt, ap);
    va_end(ap);
    log_tagged(tag, buf);
}

inline void log_tagged_critical(const char* tag, const char* msg)
{
    char path[MAX_PATH];
    _snprintf_s(path, sizeof(path), _TRUNCATE, "%saida_debug.log", resolve_log_dir());
    HANDLE hf = CreateFileA(path,
        FILE_APPEND_DATA | SYNCHRONIZE,
        FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr,
        OPEN_ALWAYS,
        FILE_ATTRIBUTE_NORMAL | FILE_FLAG_WRITE_THROUGH,
        nullptr);
    if (hf == INVALID_HANDLE_VALUE) return;
    SYSTEMTIME st{};
    GetLocalTime(&st);
    char line[4096];
    int len = _snprintf_s(line, sizeof(line), _TRUNCATE,
        "[%02d:%02d:%02d.%03d] [%s] %s\r\n",
        st.wHour, st.wMinute, st.wSecond, st.wMilliseconds,
        tag ? tag : "diag", msg ? msg : "");
    if (len > 0) {
        DWORD written = 0;
        WriteFile(hf, line, static_cast<DWORD>(len), &written, nullptr);
        FlushFileBuffers(hf);
    }
    CloseHandle(hf);
}

inline void log_tagged_critical_fmt(const char* tag, const char* fmt, ...)
{
    char buf[2048];
    va_list ap;
    va_start(ap, fmt);
    _vsnprintf_s(buf, sizeof(buf), _TRUNCATE, fmt, ap);
    va_end(ap);
    log_tagged_critical(tag, buf);
}

inline bool write_crash_log(const char* msg, bool append = false)
{
    char path[MAX_PATH];
    _snprintf_s(path, sizeof(path), _TRUNCATE, "%saida_crash.log", resolve_log_dir());

    HANDLE hf = CreateFileA(path,
        append ? (FILE_APPEND_DATA | SYNCHRONIZE) : (GENERIC_WRITE | SYNCHRONIZE),
        FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr,
        append ? OPEN_ALWAYS : CREATE_ALWAYS,
        FILE_ATTRIBUTE_NORMAL | FILE_FLAG_WRITE_THROUGH,
        nullptr);
    if (hf == INVALID_HANDLE_VALUE) return false;

    if (append)
        SetFilePointer(hf, 0, nullptr, FILE_END);

    DWORD written = 0;
    if (msg && msg[0] != '\0') {
        WriteFile(hf, msg, static_cast<DWORD>(std::strlen(msg)), &written, nullptr);
        const size_t len = std::strlen(msg);
        if (len < 2 || msg[len - 2] != '\r' || msg[len - 1] != '\n') {
            DWORD newline_written = 0;
            WriteFile(hf, "\r\n", 2, &newline_written, nullptr);
        }
    }
    FlushFileBuffers(hf);
    CloseHandle(hf);
    return true;
}

}
