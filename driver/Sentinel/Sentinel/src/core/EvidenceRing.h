#pragma once
#include <ntddk.h>
#include <core/Heartbeat.h>

namespace evidence {

    constexpr ULONG POOL_TAG      = 'vEiA';
    constexpr ULONG RING_BYTES    = 16u * 1024u;
    constexpr ULONG SLOT_BYTES    = sizeof(heartbeat::RE_EVIDENCE_BLOB);
    constexpr ULONG SLOT_COUNT    = RING_BYTES / SLOT_BYTES;

    struct ring_t {
        KSPIN_LOCK lock;
        ULONG      head;
        ULONG      count;
        ULONG      total_written;
        ULONG      _pad;
        heartbeat::RE_EVIDENCE_BLOB slots[SLOT_COUNT];
    };

    inline ring_t* g_ring = nullptr;

    __forceinline BOOLEAN init() {
        SN_LOG("evidence::init: g_ring=%p", g_ring);
        if (g_ring) return TRUE;
        SIZE_T sz = sizeof(ring_t);
        g_ring = static_cast<ring_t*>(
            ExAllocatePool2(POOL_FLAG_NON_PAGED, sz, POOL_TAG));
        if (!g_ring) {
            SN_LOG("evidence::init: FAIL - ExAllocatePool2 returned NULL (size=0x%llx)", (UINT64)sz);
            return FALSE;
        }
        RtlZeroMemory(g_ring, sz);
        KeInitializeSpinLock(&g_ring->lock);
        SN_LOG("evidence::init: SUCCESS ring=%p", g_ring);
        return TRUE;
    }

    __forceinline void shutdown() {
        if (g_ring) {
            RtlSecureZeroMemory(g_ring, sizeof(ring_t));
            ExFreePoolWithTag(g_ring, POOL_TAG);
            g_ring = nullptr;
        }
    }

    __forceinline BOOLEAN write(const heartbeat::RE_EVIDENCE_BLOB& blob) {
        if (!g_ring) return FALSE;

        KIRQL old;
        KeAcquireSpinLock(&g_ring->lock, &old);

        ULONG idx = g_ring->head;
        g_ring->slots[idx] = blob;
        g_ring->slots[idx].magic = heartbeat::RE_EVIDENCE_MAGIC;
        if (g_ring->slots[idx].version == 0)
            g_ring->slots[idx].version = heartbeat::RE_EVIDENCE_VERSION;
        if (g_ring->slots[idx].timestamp == 0)
            g_ring->slots[idx].timestamp = __rdtsc();

        g_ring->head = (idx + 1) % SLOT_COUNT;
        if (g_ring->count < SLOT_COUNT) g_ring->count++;
        g_ring->total_written++;

        KeReleaseSpinLock(&g_ring->lock, old);
        return TRUE;
    }

    __forceinline BOOLEAN write_signal(UINT32 family, UINT32 signal_id, UINT32 score,
                                       UINT32 pid, UINT64 caller_hash, UINT64 bitmap_hash) {
        heartbeat::RE_EVIDENCE_BLOB b = {};
        b.magic               = heartbeat::RE_EVIDENCE_MAGIC;
        b.version             = heartbeat::RE_EVIDENCE_VERSION;
        b.signal_family       = family;
        b.signal_id           = signal_id;
        b.score               = score;
        b.pid                 = pid;
        b.caller_image_hash   = caller_hash;
        b.signals_bitmap_hash = bitmap_hash;
        b.timestamp           = __rdtsc();
        return write(b);
    }

    __forceinline ULONG snapshot(heartbeat::RE_EVIDENCE_BLOB* out, ULONG max_slots) {
        if (!g_ring || !out || max_slots == 0) return 0;

        KIRQL old;
        KeAcquireSpinLock(&g_ring->lock, &old);

        ULONG avail = g_ring->count;
        ULONG copy  = avail < max_slots ? avail : max_slots;
        ULONG start = (g_ring->head + SLOT_COUNT - avail) % SLOT_COUNT;
        for (ULONG i = 0; i < copy; i++) {
            out[i] = g_ring->slots[(start + i) % SLOT_COUNT];
        }

        KeReleaseSpinLock(&g_ring->lock, old);
        return copy;
    }
}
