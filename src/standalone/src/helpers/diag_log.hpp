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
#include <deque>
#include <string>
#include <utility>
#include <process.h>

#include "../core/runtime/manual_map_tls.hpp"

#if defined(_M_X64)
#include <intrin.h>
#endif

namespace diag {

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

inline void remember_log_source(const char* source)
{
    _snprintf_s(cached_log_source(), 48, _TRUNCATE, "%s", source ? source : "unknown");
}

inline void remember_log_path(const char* path)
{
    _snprintf_s(cached_log_path(), MAX_PATH, _TRUNCATE, "%s", path ? path : "");
}

inline bool is_debug_log_name(const char* file_name)
{
    return file_name && std::strcmp(file_name, "aida_debug.log") == 0;
}

inline const char* effective_log_file_name(const char* file_name)
{
    return file_name;
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
    if (resolve_module_log_dir(s_cached, sizeof(s_cached))) {
        remember_log_source("exe_dir");
        s_ready = true;
        return s_cached;
    }
    s_cached[0] = '\0';
    remember_log_source("unresolved");
    s_ready = true;
    return s_cached;
}

inline bool build_log_path(const char* file_name, char* out, size_t out_size)
{
    if (!file_name || !out || out_size == 0) return false;
    out[0] = '\0';
    file_name = effective_log_file_name(file_name);
    const char* dir = resolve_log_dir();
    if (!dir || dir[0] == '\0') return false;
    _snprintf_s(out, out_size, _TRUNCATE, "%s%s", dir, file_name);
    return out[0] != '\0';
}

inline void archive_existing_debug_log_once(const char* file_name, const char* path)
{
    if (!is_debug_log_name(file_name) || !path || path[0] == '\0')
        return;
    if (env_flag_enabled("AIDA_DISABLE_LOG_ARCHIVE"))
        return;

    DWORD attr = GetFileAttributesA(path);
    if (attr == INVALID_FILE_ATTRIBUTES || (attr & FILE_ATTRIBUTE_DIRECTORY))
        return;

    HANDLE existing = CreateFileA(path, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (existing == INVALID_HANDLE_VALUE)
        return;

    LARGE_INTEGER size{};
    const BOOL sized = GetFileSizeEx(existing, &size);
    CloseHandle(existing);
    if (!sized || size.QuadPart <= 0)
        return;

    static std::atomic<bool> archived{ false };
    bool expected = false;
    if (!archived.compare_exchange_strong(expected, true, std::memory_order_acq_rel))
        return;

    char archive[MAX_PATH] = {};
    _snprintf_s(archive, sizeof(archive), _TRUNCATE, "%s.previous", path);
    if (archive[0] == '\0')
        return;

    DeleteFileA(archive);
    CopyFileA(path, archive, FALSE);
}

inline HANDLE open_log_handle(const char* file_name, DWORD desired_access, DWORD creation, DWORD flags)
{
    constexpr DWORD share = FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE;
    char path[MAX_PATH] = {};
    file_name = effective_log_file_name(file_name);
    const char* exe_dir = resolve_log_dir();
    if (exe_dir && exe_dir[0] != '\0') {
        _snprintf_s(path, sizeof(path), _TRUNCATE, "%s%s", exe_dir, file_name);
        archive_existing_debug_log_once(file_name, path);
        HANDLE hf = CreateFileA(path, desired_access, share, nullptr, creation, flags, nullptr);
        if (hf != INVALID_HANDLE_VALUE) {
            remember_log_path(path);
            return hf;
        }
    }
    return INVALID_HANDLE_VALUE;
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

inline bool format_tagged_line(char* line, size_t line_size, DWORD* len_out, const char* tag, const char* msg)
{
    if (!line || line_size == 0)
        return false;
    if (len_out)
        *len_out = 0;
    SYSTEMTIME st{};
    GetLocalTime(&st);
    int len = _snprintf_s(line, line_size, _TRUNCATE,
        "[%02d:%02d:%02d.%03d] [%s] %s\r\n",
        st.wHour, st.wMinute, st.wSecond, st.wMilliseconds,
        tag ? tag : "diag", msg ? msg : "");
    if (len <= 0)
        return false;
    if (len_out)
        *len_out = static_cast<DWORD>(len);
    return true;
}

inline DWORD write_tagged_line(HANDLE hf, const char* tag, const char* msg)
{
    if (hf == INVALID_HANDLE_VALUE) return 0;
    char line[4096];
    DWORD len = 0;
    if (!format_tagged_line(line, sizeof(line), &len, tag, msg))
        return 0;
    DWORD written = 0;
    WriteFile(hf, line, len, &written, nullptr);
    return written;
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
    GetModuleFileNameA(nullptr, module, static_cast<DWORD>(sizeof(module)));
    GetCurrentDirectoryA(static_cast<DWORD>(sizeof(cwd)), cwd);

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
        "log_path_decision source=%s path=%s pid=%lu tid=%lu module=%s cwd=%s teb=0x%016llX peb=0x%016llX tls_vector=0x%016llX",
        cached_log_source(),
        cached_log_path(),
        GetCurrentProcessId(),
        GetCurrentThreadId(),
        module,
        cwd,
        static_cast<unsigned long long>(teb),
        static_cast<unsigned long long>(peb),
        static_cast<unsigned long long>(tls_vector));
    DWORD bytes = write_tagged_line(hf, "diag", msg);
    coalesced_flush_log(hf, bytes, true);
}

struct async_log_item_t
{
    std::string line;
    bool force;
};

inline std::mutex& async_log_mutex()
{
    static std::mutex m;
    return m;
}

inline std::deque<async_log_item_t>& async_log_queue()
{
    static std::deque<async_log_item_t> q;
    return q;
}

inline HANDLE& async_log_event()
{
    static HANDLE h = nullptr;
    return h;
}

inline HANDLE& async_log_thread()
{
    static HANDLE h = nullptr;
    return h;
}

inline std::atomic<bool>& async_log_started()
{
    static std::atomic<bool> v{ false };
    return v;
}

inline std::atomic<bool>& async_log_start_failed()
{
    static std::atomic<bool> v{ false };
    return v;
}

inline std::atomic<bool>& async_log_shutdown_requested()
{
    static std::atomic<bool> v{ false };
    return v;
}

inline unsigned __stdcall async_log_thread_main(void*)
{
    aida::manual_map_tls::ensure_current_thread();
    SetThreadPriority(GetCurrentThread(), THREAD_PRIORITY_BELOW_NORMAL);
    for (;;) {
        HANDLE ev = async_log_event();
        if (ev)
            WaitForSingleObject(ev, 250);

        std::deque<async_log_item_t> batch;
        {
            std::lock_guard<std::mutex> lk(async_log_mutex());
            batch.swap(async_log_queue());
        }

        if (!batch.empty()) {
            std::lock_guard<std::mutex> lk(log_file_mutex());
            HANDLE hf = get_cached_log_handle();
            if (hf != INVALID_HANDLE_VALUE) {
                write_log_path_decision_once(hf);
                DWORD batch_bytes = 0;
                bool force_flush = false;
                for (const auto& item : batch) {
                    DWORD written = 0;
                    if (!item.line.empty())
                        WriteFile(hf, item.line.data(), static_cast<DWORD>(item.line.size()), &written, nullptr);
                    batch_bytes += written;
                    force_flush = force_flush || item.force;
                }
                coalesced_flush_log(hf, batch_bytes, force_flush);
            }
        }

        if (async_log_shutdown_requested().load(std::memory_order_acquire)) {
            std::lock_guard<std::mutex> lk(async_log_mutex());
            if (async_log_queue().empty())
                break;
        }
    }
    {
        std::lock_guard<std::mutex> lk(log_file_mutex());
        HANDLE hf = cached_log_handle();
        if (hf != INVALID_HANDLE_VALUE)
            FlushFileBuffers(hf);
    }
    return 0;
}

inline bool ensure_async_log_thread()
{
    if (async_log_started().load(std::memory_order_acquire))
        return true;
    if (async_log_start_failed().load(std::memory_order_acquire))
        return false;
    static std::mutex start_mutex;
    std::lock_guard<std::mutex> lk(start_mutex);
    if (async_log_started().load(std::memory_order_acquire))
        return true;
    if (async_log_start_failed().load(std::memory_order_acquire))
        return false;
    HANDLE ev = CreateEventA(nullptr, FALSE, FALSE, nullptr);
    if (!ev) {
        async_log_start_failed().store(true, std::memory_order_release);
        return false;
    }
    unsigned tid = 0;
    uintptr_t th = _beginthreadex(nullptr, 0, async_log_thread_main, nullptr, 0, &tid);
    if (!th) {
        CloseHandle(ev);
        async_log_start_failed().store(true, std::memory_order_release);
        return false;
    }
    async_log_event() = ev;
    async_log_thread() = reinterpret_cast<HANDLE>(th);
    async_log_started().store(true, std::memory_order_release);
    return true;
}

inline bool sync_critical_tag(const char* tag)
{
    return tag &&
        (std::strcmp(tag, "veh_crash") == 0 ||
         std::strcmp(tag, "exception") == 0);
}

inline void log_tagged_direct(const char* tag, const char* msg, bool force)
{
    aida::manual_map_tls::ensure_current_thread();
    std::lock_guard<std::mutex> lk(log_file_mutex());
    HANDLE hf = get_cached_log_handle();
    if (hf == INVALID_HANDLE_VALUE) return;
    write_log_path_decision_once(hf);
    DWORD written = write_tagged_line(hf, tag, msg);
    coalesced_flush_log(hf, written, force);
}

inline void log_tagged_async_or_direct(const char* tag, const char* msg, bool force)
{
    aida::manual_map_tls::ensure_current_thread();
    if (force && sync_critical_tag(tag)) {
        log_tagged_direct(tag, msg, true);
        return;
    }
    char line[4096];
    DWORD len = 0;
    if (!format_tagged_line(line, sizeof(line), &len, tag, msg))
        return;
    if (!ensure_async_log_thread()) {
        log_tagged_direct(tag, msg, force);
        return;
    }
    {
        std::lock_guard<std::mutex> lk(async_log_mutex());
        async_log_queue().push_back(async_log_item_t{ std::string(line, line + len), force });
    }
    HANDLE ev = async_log_event();
    if (ev)
        SetEvent(ev);
}

inline void flush_async_logs(DWORD timeout_ms = 5000)
{
    if (!async_log_started().load(std::memory_order_acquire))
        return;
    async_log_shutdown_requested().store(true, std::memory_order_release);
    HANDLE ev = async_log_event();
    if (ev)
        SetEvent(ev);
    HANDLE th = async_log_thread();
    if (th)
        WaitForSingleObject(th, timeout_ms);
}

inline void log_tagged(const char* tag, const char* msg)
{
    log_tagged_async_or_direct(tag, msg, false);
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
    log_tagged_async_or_direct(tag, msg, true);
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
