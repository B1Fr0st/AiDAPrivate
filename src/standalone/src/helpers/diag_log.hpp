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

inline bool ensure_dir_exists(const char* dir)
{
    if (!dir || dir[0] == '\0') return false;
    DWORD attr = GetFileAttributesA(dir);
    if (attr != INVALID_FILE_ATTRIBUTES && (attr & FILE_ATTRIBUTE_DIRECTORY)) return true;
    if (CreateDirectoryA(dir, nullptr)) return true;
    return GetLastError() == ERROR_ALREADY_EXISTS;
}

inline bool resolve_local_log_dir(char* out, size_t out_size)
{
    if (!out || out_size == 0) return false;
    out[0] = '\0';
    char base[MAX_PATH] = {};
    DWORD n = GetEnvironmentVariableA("LOCALAPPDATA", base, MAX_PATH);
    if (n == 0 || n >= MAX_PATH) return false;
    char root[MAX_PATH] = {};
    _snprintf_s(root, sizeof(root), _TRUNCATE, "%s\\AiDA", base);
    if (!ensure_dir_exists(root)) return false;
    _snprintf_s(out, out_size, _TRUNCATE, "%s\\logs", root);
    return ensure_dir_exists(out);
}

inline bool resolve_temp_log_dir(char* out, size_t out_size)
{
    if (!out || out_size == 0) return false;
    out[0] = '\0';
    char base[MAX_PATH] = {};
    DWORD n = GetTempPathA(MAX_PATH, base);
    if (n == 0 || n >= MAX_PATH) return false;
    _snprintf_s(out, out_size, _TRUNCATE, "%sAiDA", base);
    return ensure_dir_exists(out);
}

inline HANDLE open_log_handle(const char* file_name, DWORD desired_access, DWORD creation, DWORD flags)
{
    constexpr DWORD share = FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE;
    char path[MAX_PATH] = {};
    const char* exe_dir = resolve_log_dir();
    if (exe_dir && exe_dir[0] != '\0') {
        _snprintf_s(path, sizeof(path), _TRUNCATE, "%s%s", exe_dir, file_name);
        HANDLE hf = CreateFileA(path, desired_access, share, nullptr, creation, flags, nullptr);
        if (hf != INVALID_HANDLE_VALUE) return hf;
    }

    char dir[MAX_PATH] = {};
    if (resolve_local_log_dir(dir, sizeof(dir))) {
        _snprintf_s(path, sizeof(path), _TRUNCATE, "%s\\%s", dir, file_name);
        HANDLE hf = CreateFileA(path, desired_access, share, nullptr, creation, flags, nullptr);
        if (hf != INVALID_HANDLE_VALUE) return hf;
    }

    if (resolve_temp_log_dir(dir, sizeof(dir))) {
        _snprintf_s(path, sizeof(path), _TRUNCATE, "%s\\%s", dir, file_name);
        HANDLE hf = CreateFileA(path, desired_access, share, nullptr, creation, flags, nullptr);
        if (hf != INVALID_HANDLE_VALUE) return hf;
    }

    return CreateFileA(file_name, desired_access, share, nullptr, creation, flags, nullptr);
}

inline void write_tagged_line(HANDLE hf, const char* tag, const char* msg, bool flush)
{
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
        if (flush) FlushFileBuffers(hf);
    }
}

inline void log_tagged(const char* tag, const char* msg)
{
    HANDLE hf = open_log_handle("aida_debug.log", FILE_APPEND_DATA | SYNCHRONIZE,
        OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL);
    if (hf == INVALID_HANDLE_VALUE) return;
    write_tagged_line(hf, tag, msg, false);
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
    HANDLE hf = open_log_handle("aida_debug.log", FILE_APPEND_DATA | SYNCHRONIZE,
        OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL | FILE_FLAG_WRITE_THROUGH);
    if (hf == INVALID_HANDLE_VALUE) return;
    write_tagged_line(hf, tag, msg, true);
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
    HANDLE hf = open_log_handle("aida_crash.log",
        append ? (FILE_APPEND_DATA | SYNCHRONIZE) : (GENERIC_WRITE | SYNCHRONIZE),
        append ? OPEN_ALWAYS : CREATE_ALWAYS,
        FILE_ATTRIBUTE_NORMAL | FILE_FLAG_WRITE_THROUGH);
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
