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
#include <vector>
#include <process.h>

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

inline std::atomic<std::uint64_t>& async_log_force_flushes();
inline std::atomic<std::uint64_t>& async_log_normal_flushes();
inline std::atomic<std::uint64_t>& async_log_flush_elapsed_ms_total();
inline std::atomic<std::uint64_t>& async_log_flush_elapsed_ms_max();
inline std::atomic<std::uint64_t>& async_log_flush_failures();
inline std::atomic<std::uint64_t>& async_log_last_flush_error();
inline void async_log_update_max(std::atomic<std::uint64_t>& slot, std::uint64_t value);

inline void coalesced_flush_log(HANDLE hf, DWORD bytes_written, bool force)
{
    if (hf == INVALID_HANDLE_VALUE)
        return;

    auto& last_flush = cached_log_last_flush_ms();
    auto& bytes_pending = cached_log_bytes_since_flush();
    const std::uint64_t now = static_cast<std::uint64_t>(GetTickCount64());
    bytes_pending += bytes_written;
    if (force || bytes_pending >= 65536u || last_flush == 0 || now - last_flush >= 1000u) {
        const std::uint64_t flush_start = static_cast<std::uint64_t>(GetTickCount64());
        const BOOL flushed = FlushFileBuffers(hf);
        const DWORD flush_gle = flushed ? 0 : GetLastError();
        const std::uint64_t flush_elapsed = static_cast<std::uint64_t>(GetTickCount64()) - flush_start;
        if (force)
            async_log_force_flushes().fetch_add(1, std::memory_order_acq_rel);
        else
            async_log_normal_flushes().fetch_add(1, std::memory_order_acq_rel);
        async_log_flush_elapsed_ms_total().fetch_add(flush_elapsed, std::memory_order_acq_rel);
        async_log_update_max(async_log_flush_elapsed_ms_max(), flush_elapsed);
        if (!flushed) {
            async_log_flush_failures().fetch_add(1, std::memory_order_acq_rel);
            async_log_last_flush_error().store(flush_gle, std::memory_order_release);
        }
        last_flush = static_cast<std::uint64_t>(GetTickCount64());
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

struct async_log_stats_t
{
    std::uint64_t queued_items = 0;
    std::uint64_t queued_bytes = 0;
    std::uint64_t written_items = 0;
    std::uint64_t written_bytes = 0;
    std::uint64_t direct_items = 0;
    std::uint64_t direct_bytes = 0;
    std::uint64_t batches = 0;
    std::uint64_t batch_items = 0;
    std::uint64_t max_batch_items = 0;
    std::uint64_t force_batches = 0;
    std::uint64_t force_flushes = 0;
    std::uint64_t normal_flushes = 0;
    std::uint64_t flush_elapsed_ms_total = 0;
    std::uint64_t flush_elapsed_ms_max = 0;
    std::uint64_t flush_failures = 0;
    std::uint64_t last_flush_error = 0;
    std::uint64_t max_queue_depth = 0;
    std::uint64_t queue_depth = 0;
    std::uint64_t bytes_pending_flush = 0;
    std::uint64_t tag_metric_events = 0;
    std::uint64_t tag_metric_bytes = 0;
    std::uint64_t tag_metric_forced = 0;
    std::uint64_t coalesced_success_events = 0;
    std::uint64_t coalesced_success_bytes = 0;
    std::uint64_t coalesced_success_summaries = 0;
    std::uint64_t coalesced_success_force_downgrades = 0;
    std::string top_tags;
    bool queue_lock_busy = false;
    bool file_lock_busy = false;
    bool started = false;
    bool start_failed = false;
    bool shutdown_requested = false;
};

struct tag_metric_t
{
    char tag[32] = {};
    std::uint64_t events = 0;
    std::uint64_t bytes = 0;
    std::uint64_t forced = 0;
    std::uint64_t suppressed = 0;
};

struct coalesced_success_bucket_t
{
    char tag[32] = {};
    char key[80] = {};
    char last_msg[640] = {};
    std::uint64_t first_ms = 0;
    std::uint64_t last_event_ms = 0;
    std::uint64_t last_emit_ms = 0;
    std::uint64_t total_events = 0;
    std::uint64_t total_bytes = 0;
    std::uint64_t suppressed_events = 0;
    std::uint64_t suppressed_bytes = 0;
    std::uint64_t force_downgrades = 0;
};

struct pending_coalesced_summary_t
{
    char tag[32] = {};
    std::string msg;
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

inline std::atomic<std::uint64_t>& async_log_queued_items()
{
    static std::atomic<std::uint64_t> v{ 0 };
    return v;
}

inline std::atomic<std::uint64_t>& async_log_queued_bytes()
{
    static std::atomic<std::uint64_t> v{ 0 };
    return v;
}

inline std::atomic<std::uint64_t>& async_log_written_items()
{
    static std::atomic<std::uint64_t> v{ 0 };
    return v;
}

inline std::atomic<std::uint64_t>& async_log_written_bytes()
{
    static std::atomic<std::uint64_t> v{ 0 };
    return v;
}

inline std::atomic<std::uint64_t>& async_log_direct_items()
{
    static std::atomic<std::uint64_t> v{ 0 };
    return v;
}

inline std::atomic<std::uint64_t>& async_log_direct_bytes()
{
    static std::atomic<std::uint64_t> v{ 0 };
    return v;
}

inline std::atomic<std::uint64_t>& async_log_batches()
{
    static std::atomic<std::uint64_t> v{ 0 };
    return v;
}

inline std::atomic<std::uint64_t>& async_log_batch_items()
{
    static std::atomic<std::uint64_t> v{ 0 };
    return v;
}

inline std::atomic<std::uint64_t>& async_log_max_batch_items()
{
    static std::atomic<std::uint64_t> v{ 0 };
    return v;
}

inline std::atomic<std::uint64_t>& async_log_force_batches()
{
    static std::atomic<std::uint64_t> v{ 0 };
    return v;
}

inline std::atomic<std::uint64_t>& async_log_force_flushes()
{
    static std::atomic<std::uint64_t> v{ 0 };
    return v;
}

inline std::atomic<std::uint64_t>& async_log_normal_flushes()
{
    static std::atomic<std::uint64_t> v{ 0 };
    return v;
}

inline std::atomic<std::uint64_t>& async_log_flush_elapsed_ms_total()
{
    static std::atomic<std::uint64_t> v{ 0 };
    return v;
}

inline std::atomic<std::uint64_t>& async_log_flush_elapsed_ms_max()
{
    static std::atomic<std::uint64_t> v{ 0 };
    return v;
}

inline std::atomic<std::uint64_t>& async_log_flush_failures()
{
    static std::atomic<std::uint64_t> v{ 0 };
    return v;
}

inline std::atomic<std::uint64_t>& async_log_last_flush_error()
{
    static std::atomic<std::uint64_t> v{ 0 };
    return v;
}

inline std::atomic<std::uint64_t>& async_log_max_queue_depth()
{
    static std::atomic<std::uint64_t> v{ 0 };
    return v;
}

inline std::atomic<std::uint64_t>& async_log_tag_metric_events()
{
    static std::atomic<std::uint64_t> v{ 0 };
    return v;
}

inline std::atomic<std::uint64_t>& async_log_tag_metric_bytes()
{
    static std::atomic<std::uint64_t> v{ 0 };
    return v;
}

inline std::atomic<std::uint64_t>& async_log_tag_metric_forced()
{
    static std::atomic<std::uint64_t> v{ 0 };
    return v;
}

inline std::atomic<std::uint64_t>& async_log_coalesced_success_events()
{
    static std::atomic<std::uint64_t> v{ 0 };
    return v;
}

inline std::atomic<std::uint64_t>& async_log_coalesced_success_bytes()
{
    static std::atomic<std::uint64_t> v{ 0 };
    return v;
}

inline std::atomic<std::uint64_t>& async_log_coalesced_success_summaries()
{
    static std::atomic<std::uint64_t> v{ 0 };
    return v;
}

inline std::atomic<std::uint64_t>& async_log_coalesced_force_downgrades()
{
    static std::atomic<std::uint64_t> v{ 0 };
    return v;
}

inline std::mutex& async_log_tag_metric_mutex()
{
    static std::mutex m;
    return m;
}

inline std::vector<tag_metric_t>& async_log_tag_metrics()
{
    static std::vector<tag_metric_t> v;
    return v;
}

inline std::mutex& async_log_coalesced_mutex()
{
    static std::mutex m;
    return m;
}

inline std::vector<coalesced_success_bucket_t>& async_log_coalesced_buckets()
{
    static std::vector<coalesced_success_bucket_t> v;
    return v;
}

inline void async_log_update_max(std::atomic<std::uint64_t>& slot, std::uint64_t value)
{
    std::uint64_t current = slot.load(std::memory_order_acquire);
    while (value > current && !slot.compare_exchange_weak(current, value, std::memory_order_acq_rel, std::memory_order_acquire)) {
    }
}

inline bool starts_with_literal(const char* s, const char* prefix)
{
    if (!s || !prefix)
        return false;
    while (*prefix) {
        if (*s++ != *prefix++)
            return false;
    }
    return true;
}

inline bool contains_literal(const char* s, const char* needle)
{
    return s && needle && std::strstr(s, needle) != nullptr;
}

inline bool log_message_has_failure_shape(const char* msg)
{
    return contains_literal(msg, "failed") ||
        contains_literal(msg, "fail") ||
        contains_literal(msg, "FAIL") ||
        contains_literal(msg, "ABORT") ||
        contains_literal(msg, "reject") ||
        contains_literal(msg, "REJECT") ||
        contains_literal(msg, "invalid") ||
        contains_literal(msg, "timeout") ||
        contains_literal(msg, "stale") ||
        contains_literal(msg, "denied") ||
        contains_literal(msg, "exception") ||
        contains_literal(msg, "seh") ||
        contains_literal(msg, "tamper") ||
        contains_literal(msg, "security") ||
        contains_literal(msg, "kill") ||
        contains_literal(msg, "mismatch") ||
        contains_literal(msg, "corrupt") ||
        contains_literal(msg, "zero");
}

inline bool expected_success_log_key(const char* tag, const char* msg, char* key, size_t key_size)
{
    if (!tag || !msg || !key || key_size == 0)
        return false;
    key[0] = '\0';
    const bool comm_tag = std::strcmp(tag, "comm") == 0;
    const bool driver_tag = std::strcmp(tag, "driver") == 0;
    if (!comm_tag && !driver_tag)
        return false;
    if (log_message_has_failure_shape(msg))
        return false;
    const char* selected = nullptr;
    if (driver_tag && starts_with_literal(msg, "get_thread_context_kernel_ok "))
        selected = "driver.get_thread_context_kernel_ok";
    else if (comm_tag && starts_with_literal(msg, "phys_transfer_read_begin "))
        selected = "comm.phys_transfer_read_begin";
    else if (comm_tag && starts_with_literal(msg, "phys_transfer_read_chunk ") && contains_literal(msg, "sent=1 gle=0"))
        selected = "comm.phys_transfer_read_chunk_ok";
    else if (comm_tag && starts_with_literal(msg, "phys_transfer_read_done ") && contains_literal(msg, "complete=1"))
        selected = "comm.phys_transfer_read_done_ok";
    else if (comm_tag && starts_with_literal(msg, "TCTX get final_ok "))
        selected = "comm.tctx_get_final_ok";
    else if (comm_tag && starts_with_literal(msg, "TCTX get initial ") && contains_literal(msg, "ok=1") && contains_literal(msg, "sane=1"))
        selected = "comm.tctx_get_initial_ok";
    else if (comm_tag && starts_with_literal(msg, "send_request_in_lock_shared_acquired "))
        selected = "comm.send_request_shared_acquired";
    if (!selected)
        return false;
    _snprintf_s(key, key_size, _TRUNCATE, "%s", selected);
    return key[0] != '\0';
}

inline void record_tag_metric(const char* tag, std::uint64_t bytes, bool force, bool suppressed)
{
    async_log_tag_metric_events().fetch_add(1, std::memory_order_acq_rel);
    async_log_tag_metric_bytes().fetch_add(bytes, std::memory_order_acq_rel);
    if (force)
        async_log_tag_metric_forced().fetch_add(1, std::memory_order_acq_rel);
    std::lock_guard<std::mutex> lk(async_log_tag_metric_mutex());
    auto& metrics = async_log_tag_metrics();
    tag_metric_t* slot = nullptr;
    for (auto& item : metrics) {
        if (std::strcmp(item.tag, tag ? tag : "diag") == 0) {
            slot = &item;
            break;
        }
    }
    if (!slot) {
        if (metrics.size() < 48) {
            tag_metric_t item;
            _snprintf_s(item.tag, sizeof(item.tag), _TRUNCATE, "%s", tag ? tag : "diag");
            metrics.push_back(item);
            slot = &metrics.back();
        } else {
            slot = &metrics.front();
            for (auto& item : metrics) {
                if (item.events < slot->events)
                    slot = &item;
            }
            _snprintf_s(slot->tag, sizeof(slot->tag), _TRUNCATE, "%s", tag ? tag : "diag");
            slot->events = 0;
            slot->bytes = 0;
            slot->forced = 0;
            slot->suppressed = 0;
        }
    }
    ++slot->events;
    slot->bytes += bytes;
    if (force)
        ++slot->forced;
    if (suppressed)
        ++slot->suppressed;
}

inline std::string format_top_tag_metrics()
{
    tag_metric_t top[5] = {};
    std::size_t top_count = 0;
    {
        std::lock_guard<std::mutex> lk(async_log_tag_metric_mutex());
        for (const auto& item : async_log_tag_metrics()) {
            std::size_t pos = top_count;
            while (pos > 0 && item.events > top[pos - 1].events)
                --pos;
            if (pos >= 5)
                continue;
            if (top_count < 5)
                ++top_count;
            for (std::size_t j = top_count - 1; j > pos; --j)
                top[j] = top[j - 1];
            top[pos] = item;
        }
    }
    char out[900] = {};
    std::size_t used = 0;
    for (std::size_t i = 0; i < top_count; ++i) {
        char item[180] = {};
        _snprintf_s(item, sizeof(item), _TRUNCATE,
            "%s%s:events=%llu:bytes=%llu:forced=%llu:suppressed=%llu",
            i == 0 ? "" : ";",
            top[i].tag[0] ? top[i].tag : "<empty>",
            static_cast<unsigned long long>(top[i].events),
            static_cast<unsigned long long>(top[i].bytes),
            static_cast<unsigned long long>(top[i].forced),
            static_cast<unsigned long long>(top[i].suppressed));
        const std::size_t item_len = std::strlen(item);
        if (used + item_len + 1 >= sizeof(out))
            break;
        std::memcpy(out + used, item, item_len);
        used += item_len;
        out[used] = '\0';
    }
    return out[0] ? std::string(out) : std::string("<none>");
}

inline bool collect_coalesced_success_summaries(std::vector<pending_coalesced_summary_t>& out, bool force_all)
{
    const std::uint64_t now_ms = static_cast<std::uint64_t>(GetTickCount64());
    std::lock_guard<std::mutex> lk(async_log_coalesced_mutex());
    for (auto& bucket : async_log_coalesced_buckets()) {
        if (bucket.suppressed_events == 0)
            continue;
        const bool due = force_all || bucket.last_emit_ms == 0 || now_ms - bucket.last_emit_ms >= 5000ULL || bucket.suppressed_events >= 512ULL;
        if (!due)
            continue;
        pending_coalesced_summary_t summary;
        _snprintf_s(summary.tag, sizeof(summary.tag), _TRUNCATE, "%s", bucket.tag[0] ? bucket.tag : "diag");
        char msg[1400] = {};
        _snprintf_s(msg, sizeof(msg), _TRUNCATE,
            "expected_success_summary key=%s total=%llu suppressed=%llu suppressed_bytes=%llu total_bytes=%llu interval_ms=%llu force_downgraded=%llu last={%.620s}",
            bucket.key[0] ? bucket.key : "<empty>",
            static_cast<unsigned long long>(bucket.total_events),
            static_cast<unsigned long long>(bucket.suppressed_events),
            static_cast<unsigned long long>(bucket.suppressed_bytes),
            static_cast<unsigned long long>(bucket.total_bytes),
            static_cast<unsigned long long>(bucket.last_event_ms >= bucket.last_emit_ms ? bucket.last_event_ms - bucket.last_emit_ms : 0ULL),
            static_cast<unsigned long long>(bucket.force_downgrades),
            bucket.last_msg[0] ? bucket.last_msg : "<empty>");
        summary.msg = msg;
        out.push_back(std::move(summary));
        bucket.suppressed_events = 0;
        bucket.suppressed_bytes = 0;
        bucket.last_emit_ms = now_ms;
        async_log_coalesced_success_summaries().fetch_add(1, std::memory_order_acq_rel);
    }
    return !out.empty();
}

inline bool coalesce_expected_success_log(const char* tag, const char* msg, std::uint64_t bytes, bool force, bool& effective_force, char* summary, size_t summary_size)
{
    effective_force = force;
    if (summary && summary_size != 0)
        summary[0] = '\0';
    char key[80] = {};
    if (!expected_success_log_key(tag, msg, key, sizeof(key)))
        return false;
    if (force) {
        effective_force = false;
        async_log_coalesced_force_downgrades().fetch_add(1, std::memory_order_acq_rel);
    }
    async_log_coalesced_success_events().fetch_add(1, std::memory_order_acq_rel);
    async_log_coalesced_success_bytes().fetch_add(bytes, std::memory_order_acq_rel);
    const std::uint64_t now_ms = static_cast<std::uint64_t>(GetTickCount64());
    std::lock_guard<std::mutex> lk(async_log_coalesced_mutex());
    auto& buckets = async_log_coalesced_buckets();
    coalesced_success_bucket_t* bucket = nullptr;
    for (auto& item : buckets) {
        if (std::strcmp(item.key, key) == 0 && std::strcmp(item.tag, tag ? tag : "diag") == 0) {
            bucket = &item;
            break;
        }
    }
    if (!bucket) {
        if (buckets.size() < 32) {
            coalesced_success_bucket_t item;
            _snprintf_s(item.tag, sizeof(item.tag), _TRUNCATE, "%s", tag ? tag : "diag");
            _snprintf_s(item.key, sizeof(item.key), _TRUNCATE, "%s", key);
            buckets.push_back(item);
            bucket = &buckets.back();
        } else {
            bucket = &buckets.front();
            for (auto& item : buckets) {
                if (item.total_events < bucket->total_events)
                    bucket = &item;
            }
            _snprintf_s(bucket->tag, sizeof(bucket->tag), _TRUNCATE, "%s", tag ? tag : "diag");
            _snprintf_s(bucket->key, sizeof(bucket->key), _TRUNCATE, "%s", key);
            bucket->first_ms = 0;
            bucket->last_event_ms = 0;
            bucket->last_emit_ms = 0;
            bucket->total_events = 0;
            bucket->total_bytes = 0;
            bucket->suppressed_events = 0;
            bucket->suppressed_bytes = 0;
            bucket->force_downgrades = 0;
            bucket->last_msg[0] = '\0';
        }
    }
    if (bucket->total_events == 0) {
        bucket->first_ms = now_ms;
        bucket->last_emit_ms = now_ms;
        bucket->last_event_ms = now_ms;
        bucket->total_events = 1;
        bucket->total_bytes = bytes;
        if (force)
            bucket->force_downgrades = 1;
        _snprintf_s(bucket->last_msg, sizeof(bucket->last_msg), _TRUNCATE, "%s", msg ? msg : "");
        return false;
    }
    ++bucket->total_events;
    bucket->total_bytes += bytes;
    ++bucket->suppressed_events;
    bucket->suppressed_bytes += bytes;
    bucket->last_event_ms = now_ms;
    if (force)
        ++bucket->force_downgrades;
    _snprintf_s(bucket->last_msg, sizeof(bucket->last_msg), _TRUNCATE, "%s", msg ? msg : "");
    const bool due = now_ms - bucket->last_emit_ms >= 5000ULL || bucket->suppressed_events >= 512ULL;
    if (!due)
        return true;
    if (summary && summary_size != 0) {
        _snprintf_s(summary, summary_size, _TRUNCATE,
            "expected_success_summary key=%s total=%llu suppressed=%llu suppressed_bytes=%llu total_bytes=%llu interval_ms=%llu force_downgraded=%llu last={%.620s}",
            bucket->key,
            static_cast<unsigned long long>(bucket->total_events),
            static_cast<unsigned long long>(bucket->suppressed_events),
            static_cast<unsigned long long>(bucket->suppressed_bytes),
            static_cast<unsigned long long>(bucket->total_bytes),
            static_cast<unsigned long long>(now_ms - bucket->last_emit_ms),
            static_cast<unsigned long long>(bucket->force_downgrades),
            bucket->last_msg);
    }
    bucket->suppressed_events = 0;
    bucket->suppressed_bytes = 0;
    bucket->last_emit_ms = now_ms;
    async_log_coalesced_success_summaries().fetch_add(1, std::memory_order_acq_rel);
    return false;
}

inline async_log_stats_t async_log_stats()
{
    async_log_stats_t s;
    s.queued_items = async_log_queued_items().load(std::memory_order_acquire);
    s.queued_bytes = async_log_queued_bytes().load(std::memory_order_acquire);
    s.written_items = async_log_written_items().load(std::memory_order_acquire);
    s.written_bytes = async_log_written_bytes().load(std::memory_order_acquire);
    s.direct_items = async_log_direct_items().load(std::memory_order_acquire);
    s.direct_bytes = async_log_direct_bytes().load(std::memory_order_acquire);
    s.batches = async_log_batches().load(std::memory_order_acquire);
    s.batch_items = async_log_batch_items().load(std::memory_order_acquire);
    s.max_batch_items = async_log_max_batch_items().load(std::memory_order_acquire);
    s.force_batches = async_log_force_batches().load(std::memory_order_acquire);
    s.force_flushes = async_log_force_flushes().load(std::memory_order_acquire);
    s.normal_flushes = async_log_normal_flushes().load(std::memory_order_acquire);
    s.flush_elapsed_ms_total = async_log_flush_elapsed_ms_total().load(std::memory_order_acquire);
    s.flush_elapsed_ms_max = async_log_flush_elapsed_ms_max().load(std::memory_order_acquire);
    s.flush_failures = async_log_flush_failures().load(std::memory_order_acquire);
    s.last_flush_error = async_log_last_flush_error().load(std::memory_order_acquire);
    s.max_queue_depth = async_log_max_queue_depth().load(std::memory_order_acquire);
    s.tag_metric_events = async_log_tag_metric_events().load(std::memory_order_acquire);
    s.tag_metric_bytes = async_log_tag_metric_bytes().load(std::memory_order_acquire);
    s.tag_metric_forced = async_log_tag_metric_forced().load(std::memory_order_acquire);
    s.coalesced_success_events = async_log_coalesced_success_events().load(std::memory_order_acquire);
    s.coalesced_success_bytes = async_log_coalesced_success_bytes().load(std::memory_order_acquire);
    s.coalesced_success_summaries = async_log_coalesced_success_summaries().load(std::memory_order_acquire);
    s.coalesced_success_force_downgrades = async_log_coalesced_force_downgrades().load(std::memory_order_acquire);
    s.top_tags = format_top_tag_metrics();
    s.started = async_log_started().load(std::memory_order_acquire);
    s.start_failed = async_log_start_failed().load(std::memory_order_acquire);
    s.shutdown_requested = async_log_shutdown_requested().load(std::memory_order_acquire);
    {
        std::unique_lock<std::mutex> lk(async_log_mutex(), std::try_to_lock);
        if (lk.owns_lock())
            s.queue_depth = async_log_queue().size();
        else
            s.queue_lock_busy = true;
    }
    {
        std::unique_lock<std::mutex> lk(log_file_mutex(), std::try_to_lock);
        if (lk.owns_lock())
            s.bytes_pending_flush = cached_log_bytes_since_flush();
        else
            s.file_lock_busy = true;
    }
    return s;
}

inline unsigned __stdcall async_log_thread_main(void*)
{
    SetThreadPriority(GetCurrentThread(), THREAD_PRIORITY_BELOW_NORMAL);
    std::uint64_t last_metric_summary_ms = 0;
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
                async_log_batches().fetch_add(1, std::memory_order_acq_rel);
                async_log_batch_items().fetch_add(static_cast<std::uint64_t>(batch.size()), std::memory_order_acq_rel);
                async_log_update_max(async_log_max_batch_items(), static_cast<std::uint64_t>(batch.size()));
                for (const auto& item : batch) {
                    DWORD written = 0;
                    if (!item.line.empty())
                        WriteFile(hf, item.line.data(), static_cast<DWORD>(item.line.size()), &written, nullptr);
                    batch_bytes += written;
                    force_flush = force_flush || item.force;
                }
                async_log_written_items().fetch_add(static_cast<std::uint64_t>(batch.size()), std::memory_order_acq_rel);
                async_log_written_bytes().fetch_add(static_cast<std::uint64_t>(batch_bytes), std::memory_order_acq_rel);
                if (force_flush)
                    async_log_force_batches().fetch_add(1, std::memory_order_acq_rel);
                coalesced_flush_log(hf, batch_bytes, force_flush);
            }
        }

        std::vector<pending_coalesced_summary_t> summaries;
        const bool shutdown_now = async_log_shutdown_requested().load(std::memory_order_acquire);
        collect_coalesced_success_summaries(summaries, shutdown_now);
        const std::uint64_t now_ms = static_cast<std::uint64_t>(GetTickCount64());
        const bool metric_due = last_metric_summary_ms == 0 || now_ms - last_metric_summary_ms >= 10000ULL || shutdown_now;
        if (!summaries.empty() || metric_due) {
            std::lock_guard<std::mutex> lk(log_file_mutex());
            HANDLE hf = get_cached_log_handle();
            if (hf != INVALID_HANDLE_VALUE) {
                write_log_path_decision_once(hf);
                DWORD summary_bytes = 0;
                std::uint64_t summary_items = 0;
                for (const auto& summary : summaries) {
                    summary_bytes += write_tagged_line(hf, summary.tag[0] ? summary.tag : "diag", summary.msg.c_str());
                    ++summary_items;
                }
                if (metric_due) {
                    char msg[1400] = {};
                    const std::string top_tags = format_top_tag_metrics();
                    std::size_t queue_depth_snapshot = 0;
                    {
                        std::unique_lock<std::mutex> qlk(async_log_mutex(), std::try_to_lock);
                        if (qlk.owns_lock())
                            queue_depth_snapshot = async_log_queue().size();
                    }
                    _snprintf_s(msg, sizeof(msg), _TRUNCATE,
                        "logger_summary queued=%llu queued_bytes=%llu written=%llu written_bytes=%llu direct=%llu direct_bytes=%llu queue_depth=%zu max_queue_depth=%llu batches=%llu batch_items=%llu max_batch=%llu force_batches=%llu force_flushes=%llu normal_flushes=%llu flush_ms_total=%llu flush_ms_max=%llu flush_failures=%llu last_flush_error=%llu pending_flush_bytes=%llu coalesced_success=%llu coalesced_bytes=%llu coalesced_summaries=%llu force_downgraded=%llu top_tags={%.900s}",
                        static_cast<unsigned long long>(async_log_queued_items().load(std::memory_order_acquire)),
                        static_cast<unsigned long long>(async_log_queued_bytes().load(std::memory_order_acquire)),
                        static_cast<unsigned long long>(async_log_written_items().load(std::memory_order_acquire)),
                        static_cast<unsigned long long>(async_log_written_bytes().load(std::memory_order_acquire)),
                        static_cast<unsigned long long>(async_log_direct_items().load(std::memory_order_acquire)),
                        static_cast<unsigned long long>(async_log_direct_bytes().load(std::memory_order_acquire)),
                        queue_depth_snapshot,
                        static_cast<unsigned long long>(async_log_max_queue_depth().load(std::memory_order_acquire)),
                        static_cast<unsigned long long>(async_log_batches().load(std::memory_order_acquire)),
                        static_cast<unsigned long long>(async_log_batch_items().load(std::memory_order_acquire)),
                        static_cast<unsigned long long>(async_log_max_batch_items().load(std::memory_order_acquire)),
                        static_cast<unsigned long long>(async_log_force_batches().load(std::memory_order_acquire)),
                        static_cast<unsigned long long>(async_log_force_flushes().load(std::memory_order_acquire)),
                        static_cast<unsigned long long>(async_log_normal_flushes().load(std::memory_order_acquire)),
                        static_cast<unsigned long long>(async_log_flush_elapsed_ms_total().load(std::memory_order_acquire)),
                        static_cast<unsigned long long>(async_log_flush_elapsed_ms_max().load(std::memory_order_acquire)),
                        static_cast<unsigned long long>(async_log_flush_failures().load(std::memory_order_acquire)),
                        static_cast<unsigned long long>(async_log_last_flush_error().load(std::memory_order_acquire)),
                        static_cast<unsigned long long>(cached_log_bytes_since_flush()),
                        static_cast<unsigned long long>(async_log_coalesced_success_events().load(std::memory_order_acquire)),
                        static_cast<unsigned long long>(async_log_coalesced_success_bytes().load(std::memory_order_acquire)),
                        static_cast<unsigned long long>(async_log_coalesced_success_summaries().load(std::memory_order_acquire)),
                        static_cast<unsigned long long>(async_log_coalesced_force_downgrades().load(std::memory_order_acquire)),
                        top_tags.c_str());
                    summary_bytes += write_tagged_line(hf, "diag", msg);
                    ++summary_items;
                    last_metric_summary_ms = now_ms;
                }
                if (summary_items != 0) {
                    async_log_written_items().fetch_add(summary_items, std::memory_order_acq_rel);
                    async_log_written_bytes().fetch_add(static_cast<std::uint64_t>(summary_bytes), std::memory_order_acq_rel);
                    coalesced_flush_log(hf, summary_bytes, false);
                }
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
    std::lock_guard<std::mutex> lk(log_file_mutex());
    HANDLE hf = get_cached_log_handle();
    if (hf == INVALID_HANDLE_VALUE) return;
    write_log_path_decision_once(hf);
    DWORD written = write_tagged_line(hf, tag, msg);
    record_tag_metric(tag, static_cast<std::uint64_t>(written), force, false);
    async_log_direct_items().fetch_add(1, std::memory_order_acq_rel);
    async_log_direct_bytes().fetch_add(static_cast<std::uint64_t>(written), std::memory_order_acq_rel);
    coalesced_flush_log(hf, written, force);
}

inline void log_tagged_async_or_direct(const char* tag, const char* msg, bool force)
{
    if (force && sync_critical_tag(tag)) {
        log_tagged_direct(tag, msg, true);
        return;
    }
    bool effective_force = force;
    char summary_msg[1400] = {};
    const char* effective_msg = msg;
    const std::uint64_t msg_bytes = msg ? static_cast<std::uint64_t>(std::strlen(msg)) : 0ULL;
    const bool suppressed = coalesce_expected_success_log(tag, msg, msg_bytes, force, effective_force, summary_msg, sizeof(summary_msg));
    if (suppressed) {
        record_tag_metric(tag, msg_bytes, effective_force, true);
        return;
    }
    if (summary_msg[0])
        effective_msg = summary_msg;
    char line[4096];
    DWORD len = 0;
    if (!format_tagged_line(line, sizeof(line), &len, tag, effective_msg))
        return;
    if (!ensure_async_log_thread()) {
        log_tagged_direct(tag, effective_msg, effective_force);
        return;
    }
    std::size_t queue_depth = 0;
    {
        std::lock_guard<std::mutex> lk(async_log_mutex());
        async_log_queue().push_back(async_log_item_t{ std::string(line, line + len), effective_force });
        queue_depth = async_log_queue().size();
    }
    record_tag_metric(tag, static_cast<std::uint64_t>(len), effective_force, false);
    async_log_queued_items().fetch_add(1, std::memory_order_acq_rel);
    async_log_queued_bytes().fetch_add(static_cast<std::uint64_t>(len), std::memory_order_acq_rel);
    async_log_update_max(async_log_max_queue_depth(), static_cast<std::uint64_t>(queue_depth));
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
