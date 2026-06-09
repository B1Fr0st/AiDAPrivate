#pragma once

#ifndef NOMINMAX
#define NOMINMAX
#endif
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif

#include <windows.h>
#include <atomic>
#include <cstdarg>
#include <cstdio>
#include <cstring>
#include <cstdint>
#include <mutex>
#include <cstdlib>

#include "../core/runtime/manual_map_tls.hpp"

#if defined(_M_X64)
#include <intrin.h>
#endif

namespace diag {

inline bool ensure_dir_exists(const char* dir);

inline bool append_trailing_slash(char* path, size_t path_size)
{
    if (!path || path_size == 0) return false;
    size_t len = std::strlen(path);
    if (len == 0 || len + 1 >= path_size) return false;
    if (path[len - 1] != '\\' && path[len - 1] != '/') {
        path[len++] = '\\';
        path[len] = '\0';
    }
    return true;
}

inline bool copy_log_dir(char* out, size_t out_size, const char* dir)
{
    if (!out || out_size == 0 || !dir || dir[0] == '\0') return false;
    _snprintf_s(out, out_size, _TRUNCATE, "%s", dir);
    if (out[out_size - 1] != '\0') out[out_size - 1] = '\0';
    return append_trailing_slash(out, out_size);
}

inline bool env_value_present(const char* name, char* out, DWORD out_size)
{
    if (out && out_size)
        out[0] = '\0';
    if (!name || !out || out_size == 0)
        return false;
    DWORD n = GetEnvironmentVariableA(name, out, out_size);
    return n > 0 && n < out_size;
}

inline bool env_flag_enabled(const char* name)
{
    char value[16] = {};
    if (!env_value_present(name, value, static_cast<DWORD>(sizeof(value)))) return false;
    return !(value[0] == '0' && (value[1] == '\0' || value[1] == ' ' || value[1] == '\t'));
}

inline char* cached_log_path()
{
    static char path[MAX_PATH] = {};
    return path;
}

inline char* cached_log_source()
{
    static char source[48] = {};
    return source;
}

inline bool& cached_log_fileless()
{
    static bool value = false;
    return value;
}

inline void remember_log_source(const char* source, bool fileless)
{
    _snprintf_s(cached_log_source(), 48, _TRUNCATE, "%s", source ? source : "unknown");
    cached_log_fileless() = fileless;
}

inline void remember_log_path(const char* path)
{
    _snprintf_s(cached_log_path(), MAX_PATH, _TRUNCATE, "%s", path ? path : "");
}

inline bool is_debug_log_name(const char* file_name)
{
    return file_name &&
        (std::strcmp(file_name, "aida_debug.log") == 0 ||
         std::strcmp(file_name, "aida_debug_fileless.log") == 0);
}

inline const char* effective_log_file_name(const char* file_name)
{
    char fileless_path[MAX_PATH] = {};
    if (is_debug_log_name(file_name) &&
        (env_flag_enabled("AIDA_FILELESS_LAUNCH") ||
         env_value_present("AIDA_FILELESS_DEBUG_LOG_PATH", fileless_path, static_cast<DWORD>(sizeof(fileless_path))))) {
        return "aida_debug_fileless.log";
    }
    return file_name;
}

inline bool resolve_env_log_path(const char* env_name, char* out, size_t out_size)
{
    if (!out || out_size == 0) return false;
    out[0] = '\0';
    char path[MAX_PATH] = {};
    DWORD n = GetEnvironmentVariableA(env_name, path, static_cast<DWORD>(sizeof(path)));
    if (n == 0 || n >= sizeof(path)) return false;
    const char* slash = std::strrchr(path, '\\');
    const char* fslash = std::strrchr(path, '/');
    const char* last = slash && fslash ? (slash > fslash ? slash : fslash) : (slash ? slash : fslash);
    if (!last || last == path) return false;
    char dir[MAX_PATH] = {};
    size_t dir_len = static_cast<size_t>(last - path);
    if (dir_len == 0 || dir_len >= sizeof(dir)) return false;
    std::memcpy(dir, path, dir_len);
    dir[dir_len] = '\0';
    if (!ensure_dir_exists(dir)) return false;
    _snprintf_s(out, out_size, _TRUNCATE, "%s", path);
    return out[0] != '\0';
}

inline bool resolve_env_log_dir(const char* env_name, char* out, size_t out_size)
{
    if (!out || out_size == 0) return false;
    char dir[MAX_PATH] = {};
    DWORD n = GetEnvironmentVariableA(env_name, dir, static_cast<DWORD>(sizeof(dir)));
    if (n == 0 || n >= sizeof(dir)) return false;
    if (!ensure_dir_exists(dir)) return false;
    return copy_log_dir(out, out_size, dir);
}

inline bool resolve_desktop_log_dir(char* out, size_t out_size)
{
    if (!out || out_size == 0) return false;
    char desktop[MAX_PATH] = {};
    DWORD n = GetEnvironmentVariableA("AIDA_FILELESS_DEBUG_LOG_PATH", desktop, static_cast<DWORD>(sizeof(desktop)));
    if (n > 0 && n < sizeof(desktop)) {
        char* last = std::strrchr(desktop, '\\');
        if (last) {
            *last = '\0';
            if (ensure_dir_exists(desktop))
                return copy_log_dir(out, out_size, desktop);
        }
    }
    n = GetEnvironmentVariableA("AIDA_FILELESS_LOG_DIR", desktop, static_cast<DWORD>(sizeof(desktop)));
    if (n > 0 && n < sizeof(desktop) && ensure_dir_exists(desktop))
        return copy_log_dir(out, out_size, desktop);
    char user[MAX_PATH] = {};
    n = GetEnvironmentVariableA("USERPROFILE", user, static_cast<DWORD>(sizeof(user)));
    if (n == 0 || n >= sizeof(user)) return false;
    _snprintf_s(desktop, sizeof(desktop), _TRUNCATE, "%s\\Desktop", user);
    if (!ensure_dir_exists(desktop)) return false;
    return copy_log_dir(out, out_size, desktop);
}

inline bool resolve_module_log_dir(char* out, size_t out_size)
{
    if (!out || out_size == 0) return false;
    char module[MAX_PATH] = {};
    DWORD ret = GetModuleFileNameA(nullptr, module, MAX_PATH);
    if (ret == 0 || ret >= MAX_PATH) {
        return false;
    }
    char* last = std::strrchr(module, '\\');
    if (last) *(last + 1) = '\0';
    else module[0] = '\0';
    return copy_log_dir(out, out_size, module);
}

inline const char* resolve_log_dir()
{
    static char s_cached[MAX_PATH] = {};
    static bool s_ready = false;
    if (s_ready) return s_cached;
    char debug_env[MAX_PATH] = {};
    bool fileless = env_flag_enabled("AIDA_FILELESS_LAUNCH");
    bool has_debug_env = env_value_present("AIDA_FILELESS_DEBUG_LOG_PATH", debug_env, static_cast<DWORD>(sizeof(debug_env)));
    if (has_debug_env) fileless = true;
    if (fileless && resolve_desktop_log_dir(s_cached, sizeof(s_cached))) {
        remember_log_source(has_debug_env ? "fileless_debug_env" : "fileless_desktop", true);
        s_ready = true;
        return s_cached;
    }
    if (!fileless && resolve_module_log_dir(s_cached, sizeof(s_cached))) {
        remember_log_source("exe_dir", false);
        s_ready = true;
        return s_cached;
    }
    if (fileless && resolve_env_log_dir("AIDA_FILELESS_LOG_DIR", s_cached, sizeof(s_cached))) {
        remember_log_source("fileless_env_dir", true);
        s_ready = true;
        return s_cached;
    }
    s_cached[0] = '\0';
    remember_log_source(fileless ? "fileless_unresolved" : "unresolved", fileless);
    s_ready = true;
    return s_cached;
}

inline bool build_log_path(const char* file_name, char* out, size_t out_size)
{
    if (!file_name || !out || out_size == 0) return false;
    out[0] = '\0';
    char fileless_path_env[MAX_PATH] = {};
    const bool fileless = env_flag_enabled("AIDA_FILELESS_LAUNCH") ||
        env_value_present("AIDA_FILELESS_DEBUG_LOG_PATH", fileless_path_env, static_cast<DWORD>(sizeof(fileless_path_env)));
    if (fileless &&
        is_debug_log_name(file_name) &&
        resolve_env_log_path("AIDA_FILELESS_DEBUG_LOG_PATH", out, out_size)) {
        return true;
    }
    file_name = effective_log_file_name(file_name);
    const char* dir = resolve_log_dir();
    if (!dir || dir[0] == '\0') return false;
    _snprintf_s(out, out_size, _TRUNCATE, "%s%s", dir, file_name);
    return out[0] != '\0';
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
    char fileless_path_env[MAX_PATH] = {};
    const bool fileless = env_flag_enabled("AIDA_FILELESS_LAUNCH") ||
        env_value_present("AIDA_FILELESS_DEBUG_LOG_PATH", fileless_path_env, static_cast<DWORD>(sizeof(fileless_path_env)));
    file_name = effective_log_file_name(file_name);
    if (fileless &&
        is_debug_log_name(file_name) &&
        resolve_env_log_path("AIDA_FILELESS_DEBUG_LOG_PATH", path, sizeof(path))) {
        HANDLE hf = CreateFileA(path, desired_access, share, nullptr, creation, flags, nullptr);
        if (hf != INVALID_HANDLE_VALUE) {
            remember_log_source("fileless_debug_env", true);
            remember_log_path(path);
            return hf;
        }
    }
    const char* exe_dir = resolve_log_dir();
    if (exe_dir && exe_dir[0] != '\0') {
        _snprintf_s(path, sizeof(path), _TRUNCATE, "%s%s", exe_dir, file_name);
        HANDLE hf = CreateFileA(path, desired_access, share, nullptr, creation, flags, nullptr);
        if (hf != INVALID_HANDLE_VALUE) {
            remember_log_path(path);
            return hf;
        }
    }

    char dir[MAX_PATH] = {};
    if (resolve_local_log_dir(dir, sizeof(dir))) {
        _snprintf_s(path, sizeof(path), _TRUNCATE, "%s\\%s", dir, file_name);
        HANDLE hf = CreateFileA(path, desired_access, share, nullptr, creation, flags, nullptr);
        if (hf != INVALID_HANDLE_VALUE) {
            remember_log_source(fileless ? "fileless_localappdata" : "localappdata", fileless);
            remember_log_path(path);
            return hf;
        }
    }

    if (resolve_temp_log_dir(dir, sizeof(dir))) {
        _snprintf_s(path, sizeof(path), _TRUNCATE, "%s\\%s", dir, file_name);
        HANDLE hf = CreateFileA(path, desired_access, share, nullptr, creation, flags, nullptr);
        if (hf != INVALID_HANDLE_VALUE) {
            remember_log_source(fileless ? "fileless_temp" : "temp", fileless);
            remember_log_path(path);
            return hf;
        }
    }

    HANDLE hf = CreateFileA(file_name, desired_access, share, nullptr, creation, flags, nullptr);
    if (hf != INVALID_HANDLE_VALUE) {
        remember_log_source(fileless ? "fileless_cwd" : "cwd", fileless);
        remember_log_path(file_name);
    }
    return hf;
}

inline std::mutex& log_file_mutex()
{
    static std::mutex m;
    return m;
}

inline HANDLE& cached_log_handle()
{
    static HANDLE hf = INVALID_HANDLE_VALUE;
    return hf;
}

inline std::uint64_t& cached_log_last_flush_ms()
{
    static std::uint64_t v = 0;
    return v;
}

inline std::uint32_t& cached_log_bytes_since_flush()
{
    static std::uint32_t v = 0;
    return v;
}

inline HANDLE get_cached_log_handle()
{
    HANDLE& hf = cached_log_handle();
    if (hf == INVALID_HANDLE_VALUE) {
        hf = open_log_handle("aida_debug.log", FILE_APPEND_DATA | SYNCHRONIZE,
            OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL);
    }
    return hf;
}

inline void coalesced_flush_log(HANDLE hf, DWORD bytes_written, bool force)
{
    if (hf == INVALID_HANDLE_VALUE)
        return;

    auto& last_flush = cached_log_last_flush_ms();
    auto& bytes_pending = cached_log_bytes_since_flush();
    const std::uint64_t now = static_cast<std::uint64_t>(GetTickCount64());
    bytes_pending += bytes_written;
    if (force || bytes_pending >= 65536u || last_flush == 0 || now - last_flush >= 1000u) {
        FlushFileBuffers(hf);
        last_flush = now;
        bytes_pending = 0;
    }
}

inline DWORD write_tagged_line(HANDLE hf, const char* tag, const char* msg)
{
    if (hf == INVALID_HANDLE_VALUE) return 0;
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
        return written;
    }
    return 0;
}

inline void write_log_path_decision_once(HANDLE hf)
{
    static std::atomic<bool> written{ false };
    bool expected = false;
    if (hf == INVALID_HANDLE_VALUE ||
        !written.compare_exchange_strong(expected, true, std::memory_order_acq_rel))
        return;

    char module[MAX_PATH] = {};
    char cwd[MAX_PATH] = {};
    char debug_env[MAX_PATH] = {};
    char bootstrap_env[MAX_PATH] = {};
    char image_base_env[64] = {};
    char image_size_env[64] = {};
    char entry_rva_env[64] = {};
    GetModuleFileNameA(nullptr, module, static_cast<DWORD>(sizeof(module)));
    GetCurrentDirectoryA(static_cast<DWORD>(sizeof(cwd)), cwd);
    env_value_present("AIDA_FILELESS_DEBUG_LOG_PATH", debug_env, static_cast<DWORD>(sizeof(debug_env)));
    env_value_present("AIDA_FILELESS_BOOTSTRAP_LOG_PATH", bootstrap_env, static_cast<DWORD>(sizeof(bootstrap_env)));
    env_value_present("AIDA_FILELESS_IMAGE_BASE", image_base_env, static_cast<DWORD>(sizeof(image_base_env)));
    env_value_present("AIDA_FILELESS_IMAGE_SIZE", image_size_env, static_cast<DWORD>(sizeof(image_size_env)));
    env_value_present("AIDA_FILELESS_ENTRY_RVA", entry_rva_env, static_cast<DWORD>(sizeof(entry_rva_env)));

    std::uintptr_t teb = 0;
    std::uintptr_t peb = 0;
    std::uintptr_t tls_vector = 0;
#if defined(_M_X64)
    teb = static_cast<std::uintptr_t>(__readgsqword(0x30));
    peb = static_cast<std::uintptr_t>(__readgsqword(0x60));
    tls_vector = static_cast<std::uintptr_t>(__readgsqword(0x58));
#endif

    char msg[2048] = {};
    _snprintf_s(msg, sizeof(msg), _TRUNCATE,
        "log_path_decision fileless=%d source=%s path=%s pid=%lu tid=%lu module=%s cwd=%s teb=0x%016llX peb=0x%016llX tls_vector=0x%016llX fileless_debug_env=%s bootstrap_log=%s image_base_env=%s image_size_env=%s entry_rva_env=%s no_disk_write=%d",
        cached_log_fileless() ? 1 : 0,
        cached_log_source(),
        cached_log_path(),
        GetCurrentProcessId(),
        GetCurrentThreadId(),
        module,
        cwd,
        static_cast<unsigned long long>(teb),
        static_cast<unsigned long long>(peb),
        static_cast<unsigned long long>(tls_vector),
        debug_env,
        bootstrap_env,
        image_base_env,
        image_size_env,
        entry_rva_env,
        env_flag_enabled("AIDA_FILELESS_NO_DISK_WRITE") ? 1 : 0);
    DWORD bytes = write_tagged_line(hf, "diag", msg);
    coalesced_flush_log(hf, bytes, true);
}

inline void log_tagged(const char* tag, const char* msg)
{
    aida::manual_map_tls::ensure_current_thread();
    std::lock_guard<std::mutex> lk(log_file_mutex());
    HANDLE hf = get_cached_log_handle();
    if (hf == INVALID_HANDLE_VALUE) return;
    write_log_path_decision_once(hf);
    DWORD written = write_tagged_line(hf, tag, msg);
    coalesced_flush_log(hf, written, false);
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
    aida::manual_map_tls::ensure_current_thread();
    std::lock_guard<std::mutex> lk(log_file_mutex());
    HANDLE hf = get_cached_log_handle();
    if (hf == INVALID_HANDLE_VALUE) return;
    write_log_path_decision_once(hf);
    DWORD written = write_tagged_line(hf, tag, msg);
    coalesced_flush_log(hf, written, true);
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
    aida::manual_map_tls::ensure_current_thread();
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
