#include "KernelDebugCapture.h"

#include <ntifs.h>
#include <ntstrsafe.h>

namespace dbg_capture {

    static constexpr ULONG kRingSize = 0x100000;
    static constexpr ULONG kMaxMessageLen = 768;
    static constexpr ULONG kFlushIntervalMs = 200;
    static constexpr ULONG kMaxIdleFlushIntervalMs = 5000;
    static constexpr ULONG kPoolTag = 'gbDA';

    static UCHAR* g_ring = nullptr;
    static UCHAR* g_flush_buffer = nullptr;
    static volatile ULONG g_write_pos = 0;
    static volatile ULONG g_read_pos = 0;
    static volatile LONG g_initialized = 0;
    static volatile LONG g_stop = 0;
    static KSPIN_LOCK g_lock;
    static KEVENT g_wake_event;
    static PETHREAD g_drain_thread = nullptr;
    static volatile UINT64 g_drain_thread_tid = 0;

    static const wchar_t* const kLogPath = L"\\??\\C:\\Users\\Public\\Desktop\\aida_kernel.log";

    static BOOLEAN is_hex_digit_char(char c)
    {
        return (c >= '0' && c <= '9') ||
               (c >= 'a' && c <= 'f') ||
               (c >= 'A' && c <= 'F');
    }

    static BOOLEAN token_matches(const char* text, const char* token)
    {
        while (*token) {
            if (*text++ != *token++) return FALSE;
        }
        return TRUE;
    }

    static SIZE_T token_length(const char* token)
    {
        SIZE_T len = 0;
        while (token[len]) ++len;
        return len;
    }

    static void redact_labeled_hex_values(char* text)
    {
        static const char* const labels[] = {
            "session_key=0x", "session=0x", "g_session=0x",
            "magic=0x", "expected=0x", "received=0x",
            "existing=0x", "new=0x", "hb_key=0x",
            "key=0x", "proof=0x", "nonce=0x",
            "token=0x", "challenge=0x", "response=0x",
            "raw_cmd=0x", "raw_param=0x", "enc_cmd=0x", "enc_param=0x"
        };

        for (char* p = text; p && *p; ++p) {
            for (ULONG i = 0; i < RTL_NUMBER_OF(labels); ++i) {
                if (!token_matches(p, labels[i])) continue;
                char* v = p + token_length(labels[i]);
                while (*v && is_hex_digit_char(*v)) {
                    *v++ = 'x';
                }
                break;
            }
        }
    }

    static void redact_long_hex_runs(char* text)
    {
        char* p = text;
        while (p && *p) {
            char* start = p;
            ULONG hex_count = 0;
            while (*p && (is_hex_digit_char(*p) || *p == '`')) {
                if (is_hex_digit_char(*p)) ++hex_count;
                ++p;
            }
            if (hex_count >= 12) {
                for (char* q = start; q < p; ++q) {
                    if (is_hex_digit_char(*q)) *q = 'x';
                }
            }
            if (p == start) ++p;
        }
    }

    static void scrub_message(char* text)
    {
        if (!text) return;
        redact_labeled_hex_values(text);
        redact_long_hex_runs(text);
    }

    static void copy_into_ring_locked(const char* data, ULONG len)
    {
        ULONG wpos = g_write_pos;
        ULONG rpos = g_read_pos;
        ULONG used = wpos - rpos;
        if (used > kRingSize) {
            g_read_pos = wpos - kRingSize;
            rpos = g_read_pos;
            used = kRingSize;
        }

        ULONG free_bytes = kRingSize - used;
        if (free_bytes < len) {
            ULONG to_drop = len - free_bytes;
            g_read_pos = rpos + to_drop;
        }

        ULONG offset = wpos % kRingSize;
        ULONG first_chunk = kRingSize - offset;
        if (first_chunk > len) first_chunk = len;
        RtlCopyMemory(g_ring + offset, data, first_chunk);
        if (first_chunk < len) {
            RtlCopyMemory(g_ring, data + first_chunk, len - first_chunk);
        }
        g_write_pos = wpos + len;
    }

    static void push_raw(const char* data, ULONG len)
    {
        if (g_drain_thread && PsGetCurrentThread() == g_drain_thread) return;
        if (!g_ring || len == 0) return;
        if (len > kMaxMessageLen) len = kMaxMessageLen;

        char ts[40];
        size_t ts_len = 0;
        LARGE_INTEGER sys_time, local_time;
        TIME_FIELDS tf = {};
        KeQuerySystemTime(&sys_time);
        ExSystemTimeToLocalTime(&sys_time, &local_time);
        RtlTimeToTimeFields(&local_time, &tf);
        NTSTATUS sf = RtlStringCbPrintfA(ts, sizeof(ts),
            "[%04u-%02u-%02u %02u:%02u:%02u.%03u] ",
            (ULONG)tf.Year, (ULONG)tf.Month, (ULONG)tf.Day,
            (ULONG)tf.Hour, (ULONG)tf.Minute, (ULONG)tf.Second,
            (ULONG)tf.Milliseconds);
        if (!NT_SUCCESS(sf) || !NT_SUCCESS(RtlStringCbLengthA(ts, sizeof(ts), &ts_len))) {
            ts_len = 0;
        }

        KIRQL old_irql;
        KeAcquireSpinLock(&g_lock, &old_irql);
        if (ts_len > 0) copy_into_ring_locked(ts, (ULONG)ts_len);
        copy_into_ring_locked(data, len);
        KeReleaseSpinLock(&g_lock, old_irql);

        KeSetEvent(&g_wake_event, 0, FALSE);
    }

    void write_formatted(const char* fmt, ...)
    {
        if (!_InterlockedCompareExchange(&g_initialized, 0, 0)) return;

        char buf[kMaxMessageLen];
        va_list ap;
        va_start(ap, fmt);
        NTSTATUS s = RtlStringCbVPrintfA(buf, sizeof(buf), fmt, ap);
        va_end(ap);
        if (!NT_SUCCESS(s) && s != STATUS_BUFFER_OVERFLOW) return;

        size_t out_len = 0;
        if (!NT_SUCCESS(RtlStringCbLengthA(buf, sizeof(buf), &out_len))) return;
        scrub_message(buf);
        push_raw(buf, static_cast<ULONG>(out_len));
    }

    struct flush_result_t
    {
        ULONG bytes;
        NTSTATUS create_status;
        NTSTATUS write_status;
        ULONG elapsed_us;
    };

    static ULONG elapsed_us(LARGE_INTEGER start, LARGE_INTEGER end, LARGE_INTEGER freq)
    {
        if (freq.QuadPart <= 0 || end.QuadPart < start.QuadPart) return 0;
        ULONGLONG delta = static_cast<ULONGLONG>(end.QuadPart - start.QuadPart);
        return static_cast<ULONG>((delta * 1000000ULL) / static_cast<ULONGLONG>(freq.QuadPart));
    }

    static BOOLEAN should_log_empty(UINT64 empty_count)
    {
        if (empty_count <= 4) return TRUE;
        if (empty_count == 8 || empty_count == 16 || empty_count == 32) return TRUE;
        return (empty_count % 64) == 0;
    }

    static BOOLEAN should_log_flush(const flush_result_t& flush, UINT64 flush_count)
    {
        if (!NT_SUCCESS(flush.create_status) || !NT_SUCCESS(flush.write_status)) return TRUE;
        if (flush.elapsed_us >= 5000) return TRUE;
        if (flush_count <= 4) return TRUE;
        if (flush_count == 8 || flush_count == 16 || flush_count == 32) return TRUE;
        return (flush_count % 64) == 0;
    }

    static const char* wait_reason(NTSTATUS status, BOOLEAN stopping)
    {
        if (stopping) return "stop";
        if (status == STATUS_SUCCESS) return "event";
        if (status == STATUS_TIMEOUT) return "timeout";
        return "status";
    }

    static flush_result_t flush_to_file()
    {
        flush_result_t result = {};
        result.create_status = STATUS_SUCCESS;
        result.write_status = STATUS_SUCCESS;
        if (!g_ring || !g_flush_buffer) return result;
        if (KeGetCurrentIrql() != PASSIVE_LEVEL) return result;

        LARGE_INTEGER freq;
        LARGE_INTEGER start = KeQueryPerformanceCounter(&freq);

        ULONG snapshot_len = 0;

        KIRQL old_irql;
        KeAcquireSpinLock(&g_lock, &old_irql);
        ULONG wpos = g_write_pos;
        ULONG rpos = g_read_pos;
        ULONG used = wpos - rpos;
        if (used == 0) {
            KeReleaseSpinLock(&g_lock, old_irql);
            return result;
        }
        if (used > kRingSize) {
            rpos = wpos - kRingSize;
            used = kRingSize;
        }
        ULONG offset = rpos % kRingSize;
        ULONG first_chunk = kRingSize - offset;
        if (first_chunk > used) first_chunk = used;
        RtlCopyMemory(g_flush_buffer, g_ring + offset, first_chunk);
        if (first_chunk < used) {
            RtlCopyMemory(g_flush_buffer + first_chunk, g_ring, used - first_chunk);
        }
        g_read_pos = rpos + used;
        snapshot_len = used;
        KeReleaseSpinLock(&g_lock, old_irql);
        result.bytes = snapshot_len;

        UNICODE_STRING path;
        RtlInitUnicodeString(&path, kLogPath);

        OBJECT_ATTRIBUTES oa;
        InitializeObjectAttributes(&oa, &path,
            OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE, NULL, NULL);

        HANDLE hFile = nullptr;
        IO_STATUS_BLOCK iosb = {};
        NTSTATUS st = ZwCreateFile(
            &hFile,
            FILE_APPEND_DATA | SYNCHRONIZE,
            &oa,
            &iosb,
            NULL,
            FILE_ATTRIBUTE_NORMAL,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            FILE_OPEN_IF,
            FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT,
            NULL, 0);
        result.create_status = st;

        if (NT_SUCCESS(st) && hFile) {
            LARGE_INTEGER offset_li;
            offset_li.HighPart = -1;
            offset_li.LowPart = FILE_WRITE_TO_END_OF_FILE;
            result.write_status = ZwWriteFile(hFile, NULL, NULL, NULL, &iosb,
                g_flush_buffer, snapshot_len, &offset_li, NULL);
            ZwClose(hFile);
        }
        LARGE_INTEGER end = KeQueryPerformanceCounter(nullptr);
        result.elapsed_us = elapsed_us(start, end, freq);
        return result;
    }

    static void write_immediate_raw(const char* data, ULONG len)
    {
        if (!data || len == 0 || KeGetCurrentIrql() != PASSIVE_LEVEL) return;

        UNICODE_STRING path;
        RtlInitUnicodeString(&path, kLogPath);

        OBJECT_ATTRIBUTES oa;
        InitializeObjectAttributes(&oa, &path,
            OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE, NULL, NULL);

        HANDLE hFile = nullptr;
        IO_STATUS_BLOCK iosb = {};
        NTSTATUS st = ZwCreateFile(
            &hFile,
            FILE_APPEND_DATA | SYNCHRONIZE,
            &oa,
            &iosb,
            NULL,
            FILE_ATTRIBUTE_NORMAL,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            FILE_OPEN_IF,
            FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT,
            NULL, 0);

        if (NT_SUCCESS(st) && hFile) {
            LARGE_INTEGER offset_li;
            offset_li.HighPart = -1;
            offset_li.LowPart = FILE_WRITE_TO_END_OF_FILE;
            ZwWriteFile(hFile, NULL, NULL, NULL, &iosb,
                const_cast<char*>(data), len, &offset_li, NULL);
            ZwClose(hFile);
        }
    }

    void write_immediate_formatted(const char* fmt, ...)
    {
        if (!fmt) return;

        char buf[kMaxMessageLen];
        va_list ap;
        va_start(ap, fmt);
        NTSTATUS s = RtlStringCbVPrintfA(buf, sizeof(buf), fmt, ap);
        va_end(ap);
        if (!NT_SUCCESS(s) && s != STATUS_BUFFER_OVERFLOW) return;

        size_t out_len = 0;
        if (!NT_SUCCESS(RtlStringCbLengthA(buf, sizeof(buf), &out_len))) return;
        scrub_message(buf);
        write_immediate_raw(buf, static_cast<ULONG>(out_len));
    }

    static VOID NTAPI drain_thread_routine(PVOID context)
    {
        UNREFERENCED_PARAMETER(context);

        UINT64 tid = reinterpret_cast<UINT64>(PsGetCurrentThreadId());
        _InterlockedExchange64(reinterpret_cast<volatile LONG64*>(&g_drain_thread_tid),
            static_cast<LONG64>(tid));
        ULONG wait_ms = kFlushIntervalMs;
        UINT64 empty_count = 0;
        UINT64 total_bytes = 0;
        UINT64 total_flush_us = 0;
        UINT64 flush_count = 0;
        UINT64 suppressed_flush_count = 0;
        UINT64 suppressed_flush_bytes = 0;
        UINT64 suppressed_flush_us = 0;

        write_immediate_formatted("[WW] dbg_capture::drain_thread_start tid=%llu wait_ms=%lu max_wait_ms=%lu\n",
            static_cast<unsigned long long>(tid),
            wait_ms,
            kMaxIdleFlushIntervalMs);

        for (;;) {
            LARGE_INTEGER timeout;
            timeout.QuadPart = -(static_cast<LONGLONG>(wait_ms) * 10000LL);
            NTSTATUS wait_status = KeWaitForSingleObject(&g_wake_event, Executive, KernelMode, FALSE, &timeout);
            BOOLEAN stopping = _InterlockedCompareExchange(&g_stop, 0, 0) ? TRUE : FALSE;
            if (stopping) break;

            flush_result_t flush = flush_to_file();
            if (flush.bytes != 0) {
                total_bytes += flush.bytes;
                total_flush_us += flush.elapsed_us;
                ++flush_count;
                empty_count = 0;
                wait_ms = kFlushIntervalMs;
                if (should_log_flush(flush, flush_count)) {
                    write_immediate_formatted("[WW] dbg_capture::drain_thread_flush tid=%llu wait_status=0x%08lx wake=%s bytes=%lu total_bytes=%llu flush_us=%lu total_flush_us=%llu flush_count=%llu suppressed_flushes=%llu suppressed_bytes=%llu suppressed_flush_us=%llu create=0x%08lx write=0x%08lx next_wait_ms=%lu\n",
                        static_cast<unsigned long long>(tid),
                        static_cast<ULONG>(wait_status),
                        wait_reason(wait_status, FALSE),
                        flush.bytes,
                        static_cast<unsigned long long>(total_bytes),
                        flush.elapsed_us,
                        static_cast<unsigned long long>(total_flush_us),
                        static_cast<unsigned long long>(flush_count),
                        static_cast<unsigned long long>(suppressed_flush_count),
                        static_cast<unsigned long long>(suppressed_flush_bytes),
                        static_cast<unsigned long long>(suppressed_flush_us),
                        static_cast<ULONG>(flush.create_status),
                        static_cast<ULONG>(flush.write_status),
                        wait_ms);
                    suppressed_flush_count = 0;
                    suppressed_flush_bytes = 0;
                    suppressed_flush_us = 0;
                } else {
                    ++suppressed_flush_count;
                    suppressed_flush_bytes += flush.bytes;
                    suppressed_flush_us += flush.elapsed_us;
                }
            } else {
                ++empty_count;
                ULONG previous_wait = wait_ms;
                if (wait_ms < kMaxIdleFlushIntervalMs) {
                    wait_ms *= 2;
                    if (wait_ms > kMaxIdleFlushIntervalMs)
                        wait_ms = kMaxIdleFlushIntervalMs;
                }
                if (should_log_empty(empty_count)) {
                    write_immediate_formatted("[WW] dbg_capture::drain_thread_idle tid=%llu wait_status=0x%08lx wake=%s empty_count=%llu wait_ms=%lu next_wait_ms=%lu total_bytes=%llu total_flush_us=%llu flush_count=%llu\n",
                        static_cast<unsigned long long>(tid),
                        static_cast<ULONG>(wait_status),
                        wait_reason(wait_status, FALSE),
                        static_cast<unsigned long long>(empty_count),
                        previous_wait,
                        wait_ms,
                        static_cast<unsigned long long>(total_bytes),
                        static_cast<unsigned long long>(total_flush_us),
                        static_cast<unsigned long long>(flush_count));
                }
            }
        }

        flush_result_t final_flush = flush_to_file();
        total_bytes += final_flush.bytes;
        total_flush_us += final_flush.elapsed_us;
        if (final_flush.bytes != 0)
            ++flush_count;
        write_immediate_formatted("[WW] dbg_capture::drain_thread_exit tid=%llu final_bytes=%lu total_bytes=%llu empty_count=%llu total_flush_us=%llu flush_count=%llu suppressed_flushes=%llu suppressed_bytes=%llu suppressed_flush_us=%llu create=0x%08lx write=0x%08lx\n",
            static_cast<unsigned long long>(tid),
            final_flush.bytes,
            static_cast<unsigned long long>(total_bytes),
            static_cast<unsigned long long>(empty_count),
            static_cast<unsigned long long>(total_flush_us),
            static_cast<unsigned long long>(flush_count),
            static_cast<unsigned long long>(suppressed_flush_count),
            static_cast<unsigned long long>(suppressed_flush_bytes),
            static_cast<unsigned long long>(suppressed_flush_us),
            static_cast<ULONG>(final_flush.create_status),
            static_cast<ULONG>(final_flush.write_status));
        PsTerminateSystemThread(STATUS_SUCCESS);
    }

    NTSTATUS initialize()
    {
        if (_InterlockedCompareExchange(&g_initialized, 0, 0)) return STATUS_SUCCESS;

        g_ring = static_cast<UCHAR*>(
            ExAllocatePool2(POOL_FLAG_NON_PAGED, kRingSize, kPoolTag));
        if (!g_ring) return STATUS_INSUFFICIENT_RESOURCES;

        g_flush_buffer = static_cast<UCHAR*>(
            ExAllocatePool2(POOL_FLAG_NON_PAGED, kRingSize, kPoolTag));
        if (!g_flush_buffer) {
            ExFreePoolWithTag(g_ring, kPoolTag);
            g_ring = nullptr;
            return STATUS_INSUFFICIENT_RESOURCES;
        }

        KeInitializeSpinLock(&g_lock);
        KeInitializeEvent(&g_wake_event, SynchronizationEvent, FALSE);
        g_write_pos = 0;
        g_read_pos = 0;
        g_stop = 0;

        _InterlockedExchange(&g_initialized, 1);

        HANDLE thread_handle = nullptr;
        OBJECT_ATTRIBUTES oa;
        InitializeObjectAttributes(&oa, NULL, OBJ_KERNEL_HANDLE, NULL, NULL);
        NTSTATUS st = PsCreateSystemThread(
            &thread_handle,
            THREAD_ALL_ACCESS,
            &oa,
            NULL,
            NULL,
            drain_thread_routine,
            NULL);
        if (!NT_SUCCESS(st)) {
            ExFreePoolWithTag(g_ring, kPoolTag);
            g_ring = nullptr;
            ExFreePoolWithTag(g_flush_buffer, kPoolTag);
            g_flush_buffer = nullptr;
            _InterlockedExchange(&g_initialized, 0);
            return st;
        }

        ObReferenceObjectByHandle(
            thread_handle,
            THREAD_ALL_ACCESS,
            NULL,
            KernelMode,
            reinterpret_cast<PVOID*>(&g_drain_thread),
            NULL);
        ZwClose(thread_handle);

        return STATUS_SUCCESS;
    }
}
