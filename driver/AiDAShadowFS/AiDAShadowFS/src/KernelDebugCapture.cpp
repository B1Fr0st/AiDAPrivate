#include "KernelDebugCapture.h"

#include <fltKernel.h>
#include <ntstrsafe.h>

namespace dbg_capture {

    static constexpr ULONG kRingSize = 0x100000;
    static constexpr ULONG kMaxMessageLen = 768;
    static constexpr ULONG kFlushIntervalMs = 200;
    static constexpr ULONG kPoolTag = 'gbDA';

    static UCHAR* g_ring = nullptr;
    static volatile ULONG g_write_pos = 0;
    static volatile ULONG g_read_pos = 0;
    static volatile LONG g_initialized = 0;
    static volatile LONG g_stop = 0;
    static KSPIN_LOCK g_lock;
    static KEVENT g_wake_event;
    static PETHREAD g_drain_thread = nullptr;

    static const wchar_t* const kLogPath = L"\\??\\C:\\Users\\Public\\Desktop\\aida_kernel.log";

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

    void write_raw(const char* data, ULONG len)
    {
        if (!_InterlockedCompareExchange(&g_initialized, 0, 0)) return;
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

    static void flush_to_file()
    {
        ULONG snapshot_len = 0;

        KIRQL old_irql;
        KeAcquireSpinLock(&g_lock, &old_irql);
        ULONG wpos = g_write_pos;
        ULONG rpos = g_read_pos;
        ULONG used = wpos - rpos;
        if (used == 0) {
            KeReleaseSpinLock(&g_lock, old_irql);
            return;
        }
        if (used > kRingSize) used = kRingSize;
        snapshot_len = used;
        KeReleaseSpinLock(&g_lock, old_irql);

        UCHAR* snapshot = static_cast<UCHAR*>(
            ExAllocatePool2(POOL_FLAG_PAGED, snapshot_len, kPoolTag));
        if (!snapshot) return;

        KeAcquireSpinLock(&g_lock, &old_irql);
        wpos = g_write_pos;
        rpos = g_read_pos;
        ULONG now_used = wpos - rpos;
        if (now_used == 0) {
            KeReleaseSpinLock(&g_lock, old_irql);
            ExFreePoolWithTag(snapshot, kPoolTag);
            return;
        }
        if (now_used > snapshot_len) now_used = snapshot_len;

        ULONG offset = rpos % kRingSize;
        ULONG first_chunk = kRingSize - offset;
        if (first_chunk > now_used) first_chunk = now_used;
        RtlCopyMemory(snapshot, g_ring + offset, first_chunk);
        if (first_chunk < now_used) {
            RtlCopyMemory(snapshot + first_chunk, g_ring, now_used - first_chunk);
        }
        g_read_pos = rpos + now_used;
        snapshot_len = now_used;
        KeReleaseSpinLock(&g_lock, old_irql);

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
                snapshot, snapshot_len, &offset_li, NULL);
            ZwClose(hFile);
        }

        ExFreePoolWithTag(snapshot, kPoolTag);
    }

    static VOID NTAPI drain_thread_routine(PVOID context)
    {
        UNREFERENCED_PARAMETER(context);

        LARGE_INTEGER timeout;
        timeout.QuadPart = -(static_cast<LONGLONG>(kFlushIntervalMs) * 10000LL);

        for (;;) {
            KeWaitForSingleObject(&g_wake_event, Executive, KernelMode, FALSE, &timeout);
            if (_InterlockedCompareExchange(&g_stop, 0, 0)) break;
            flush_to_file();
        }

        flush_to_file();
        PsTerminateSystemThread(STATUS_SUCCESS);
    }

    NTSTATUS initialize()
    {
        if (_InterlockedCompareExchange(&g_initialized, 0, 0)) return STATUS_SUCCESS;

        g_ring = static_cast<UCHAR*>(
            ExAllocatePool2(POOL_FLAG_NON_PAGED, kRingSize, kPoolTag));
        if (!g_ring) return STATUS_INSUFFICIENT_RESOURCES;

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
