#pragma once

#include <ntddk.h>
#include "KernelCrypto.h"

namespace witness_key
{
    constexpr ULONG KW_SIZE = 32;
    constexpr ULONG KW_PAGE_SIZE = 4096;
    constexpr ULONG KW_POOL_TAG = 'kwSn';
    constexpr ULONG KW_MASK_ROTATE_INTERVAL_MS = 10000;

    struct kw_storage_t
    {
        UINT8* page;
        UINT8  mask[KW_SIZE];
        KSPIN_LOCK lock;
        KTIMER rotate_timer;
        KDPC   rotate_dpc;
        BOOLEAN valid;
    };

    inline kw_storage_t g_kw = {};
    inline WORK_QUEUE_ITEM g_rotate_work_item = {};
    inline KEVENT g_rotate_work_done = {};
    inline volatile LONG   g_rotate_active = 0;
    inline volatile LONG   g_rotate_work_queued = 0;
    inline volatile LONG   g_rotate_work_running = 0;
    inline volatile LONG   g_rotate_sync_initialized = 0;

    __forceinline void ensure_rotate_sync_initialized()
    {
        if (_InterlockedCompareExchange(&g_rotate_sync_initialized, 1, 0) == 0)
            KeInitializeEvent(&g_rotate_work_done, NotificationEvent, TRUE);
    }

    static VOID NTAPI rotate_work_item_callback(PVOID)
    {
        _InterlockedExchange(&g_rotate_work_running, 1);

        UINT8 new_mask[KW_SIZE] = {};
        UINT8 old_mask[KW_SIZE] = {};
        UINT8* decoy_buf = static_cast<UINT8*>(
            ExAllocatePool2(POOL_FLAG_NON_PAGED, KW_PAGE_SIZE - KW_SIZE, 'dwSn'));

        if (decoy_buf)
        {
            kernel_crypto::gen_random(new_mask, KW_SIZE);
            kernel_crypto::gen_random(decoy_buf, KW_PAGE_SIZE - KW_SIZE);
        }

        if (decoy_buf && _InterlockedCompareExchange(&g_rotate_active, 1, 1) == 1)
        {
            KIRQL old_irql;
            KeAcquireSpinLock(&g_kw.lock, &old_irql);

            if (_InterlockedCompareExchange(&g_rotate_active, 1, 1) == 1 &&
                g_kw.valid && g_kw.page)
            {
                RtlCopyMemory(old_mask, g_kw.mask, KW_SIZE);
                for (ULONG i = 0; i < KW_SIZE; ++i)
                    g_kw.page[i] = (g_kw.page[i] ^ old_mask[i]) ^ new_mask[i];

                RtlCopyMemory(g_kw.mask, new_mask, KW_SIZE);
                RtlCopyMemory(g_kw.page + KW_SIZE, decoy_buf, KW_PAGE_SIZE - KW_SIZE);
            }

            KeReleaseSpinLock(&g_kw.lock, old_irql);
        }

        if (decoy_buf)
        {
            RtlSecureZeroMemory(decoy_buf, KW_PAGE_SIZE - KW_SIZE);
            ExFreePoolWithTag(decoy_buf, 'dwSn');
        }

        RtlSecureZeroMemory(new_mask, sizeof(new_mask));
        RtlSecureZeroMemory(old_mask, sizeof(old_mask));
        _InterlockedExchange(&g_rotate_work_running, 0);
        _InterlockedExchange(&g_rotate_work_queued, 0);
        KeSetEvent(&g_rotate_work_done, IO_NO_INCREMENT, FALSE);
    }

    __forceinline void rotate_mask_dpc(KDPC*, PVOID, PVOID, PVOID)
    {
        if (_InterlockedCompareExchange(&g_rotate_active, 1, 1) != 1)
            return;
        ensure_rotate_sync_initialized();
        if (_InterlockedCompareExchange(&g_rotate_work_queued, 1, 0) == 0) {
            KeClearEvent(&g_rotate_work_done);
            ExInitializeWorkItem(&g_rotate_work_item, rotate_work_item_callback, nullptr);
            if (_ExQueueWorkItem)
                _ExQueueWorkItem(&g_rotate_work_item, DelayedWorkQueue);
            else
                ExQueueWorkItem(&g_rotate_work_item, DelayedWorkQueue);
        }

        if (_InterlockedCompareExchange(&g_rotate_active, 1, 1) == 1) {
            LARGE_INTEGER due;
            due.QuadPart = -static_cast<LONGLONG>(KW_MASK_ROTATE_INTERVAL_MS) * 10000LL;
            KeSetTimer(&g_kw.rotate_timer, due, &g_kw.rotate_dpc);
        }
    }

    __forceinline BOOLEAN init()
    {
        g_kw.page = static_cast<UINT8*>(
            ExAllocatePool2(POOL_FLAG_NON_PAGED, KW_PAGE_SIZE, KW_POOL_TAG));
        if (!g_kw.page) return FALSE;

        kernel_crypto::gen_random(g_kw.page, KW_PAGE_SIZE);
        kernel_crypto::gen_random(g_kw.mask, KW_SIZE);

        KeInitializeSpinLock(&g_kw.lock);
        ensure_rotate_sync_initialized();
        _InterlockedExchange(&g_rotate_active, 1);
        _InterlockedExchange(&g_rotate_work_queued, 0);
        _InterlockedExchange(&g_rotate_work_running, 0);
        KeSetEvent(&g_rotate_work_done, IO_NO_INCREMENT, FALSE);
        g_kw.valid = FALSE;

        KeInitializeTimer(&g_kw.rotate_timer);
        KeInitializeDpc(&g_kw.rotate_dpc, rotate_mask_dpc, nullptr);

        LARGE_INTEGER due;
        due.QuadPart = -static_cast<LONGLONG>(KW_MASK_ROTATE_INTERVAL_MS) * 10000LL;
        KeSetTimer(&g_kw.rotate_timer, due, &g_kw.rotate_dpc);

        return TRUE;
    }

    __forceinline BOOLEAN store_kw(const UINT8 kw[KW_SIZE])
    {
        KIRQL old_irql;
        KeAcquireSpinLock(&g_kw.lock, &old_irql);

        for (ULONG i = 0; i < KW_SIZE; ++i)
            g_kw.page[i] = kw[i] ^ g_kw.mask[i];

        g_kw.valid = TRUE;
        KeReleaseSpinLock(&g_kw.lock, old_irql);
        return TRUE;
    }

    __forceinline BOOLEAN read_kw(UINT8 kw_out[KW_SIZE])
    {
        KIRQL old_irql;
        KeAcquireSpinLock(&g_kw.lock, &old_irql);

        if (!g_kw.valid) {
            KeReleaseSpinLock(&g_kw.lock, old_irql);
            return FALSE;
        }

        for (ULONG i = 0; i < KW_SIZE; ++i)
            kw_out[i] = g_kw.page[i] ^ g_kw.mask[i];

        KeReleaseSpinLock(&g_kw.lock, old_irql);
        return TRUE;
    }

    __forceinline BOOLEAN derive_subkey(const char* label, UINT8 subkey_out[KW_SIZE])
    {
        UINT8 kw[KW_SIZE];
        if (!read_kw(kw)) return FALSE;

        UINT8 data[KW_SIZE + 64] = {};
        RtlCopyMemory(data, kw, KW_SIZE);
        SIZE_T label_len = 0;
        while (label[label_len] && label_len < 63) ++label_len;
        RtlCopyMemory(data + KW_SIZE, label, label_len);

        NTSTATUS st = kernel_crypto::hmac_sha256(
            kw, KW_SIZE,
            reinterpret_cast<const UINT8*>(label), static_cast<ULONG>(label_len),
            subkey_out);

        RtlSecureZeroMemory(kw, KW_SIZE);
        return NT_SUCCESS(st);
    }

    __forceinline void shutdown()
    {
        _InterlockedExchange(&g_rotate_active, 0);
        KeCancelTimer(&g_kw.rotate_timer);
        if (_KeFlushQueuedDpcs)
            _KeFlushQueuedDpcs();
        ensure_rotate_sync_initialized();
        if (KeGetCurrentIrql() == PASSIVE_LEVEL &&
            (_InterlockedCompareExchange(&g_rotate_work_queued, 0, 0) != 0 ||
             _InterlockedCompareExchange(&g_rotate_work_running, 0, 0) != 0)) {
            LARGE_INTEGER timeout;
            timeout.QuadPart = -50'000'000LL;
            KeWaitForSingleObject(&g_rotate_work_done, Executive, KernelMode, FALSE, &timeout);
        }

        if (g_kw.page)
        {
            RtlSecureZeroMemory(g_kw.page, KW_PAGE_SIZE);
            ExFreePoolWithTag(g_kw.page, KW_POOL_TAG);
            g_kw.page = nullptr;
        }
        RtlSecureZeroMemory(g_kw.mask, KW_SIZE);
        g_kw.valid = FALSE;
    }
}
