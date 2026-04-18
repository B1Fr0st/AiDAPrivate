#pragma once
#include <ntddk.h>

namespace driver_load_audit {

    constexpr ULONG POOL_TAG  = 'aLiA';
    constexpr ULONG RING_SIZE = 64;

    struct record_t {
        UINT64 name_hash;
        UINT64 image_base;
        UINT32 image_size;
        UINT32 hostile_tier;
        UINT64 timestamp;
    };

    struct ring_t {
        KSPIN_LOCK lock;
        ULONG      head;
        ULONG      count;
        ULONG      _pad;
        record_t   records[RING_SIZE];
    };

    inline ring_t* g_ring = nullptr;

    __forceinline BOOLEAN init() {
        SN_LOG("driver_load_audit::init: g_ring=%p", g_ring);
        if (g_ring) return TRUE;
        g_ring = static_cast<ring_t*>(
            ExAllocatePool2(POOL_FLAG_NON_PAGED, sizeof(ring_t), POOL_TAG));
        if (!g_ring) {
            SN_LOG("driver_load_audit::init: FAIL - ExAllocatePool2 returned NULL");
            return FALSE;
        }
        RtlZeroMemory(g_ring, sizeof(ring_t));
        KeInitializeSpinLock(&g_ring->lock);
        SN_LOG("driver_load_audit::init: SUCCESS ring=%p", g_ring);
        return TRUE;
    }

    __forceinline void shutdown() {
        if (g_ring) {
            RtlSecureZeroMemory(g_ring, sizeof(ring_t));
            ExFreePoolWithTag(g_ring, POOL_TAG);
            g_ring = nullptr;
        }
    }

    __forceinline void record(UINT64 name_hash, UINT64 image_base,
                              UINT32 image_size, UINT32 hostile_tier) {
        if (!g_ring) return;

        KIRQL old;
        KeAcquireSpinLock(&g_ring->lock, &old);

        ULONG idx = g_ring->head;
        g_ring->records[idx].name_hash    = name_hash;
        g_ring->records[idx].image_base   = image_base;
        g_ring->records[idx].image_size   = image_size;
        g_ring->records[idx].hostile_tier = hostile_tier;
        g_ring->records[idx].timestamp    = __rdtsc();
        g_ring->head = (idx + 1) % RING_SIZE;
        if (g_ring->count < RING_SIZE) g_ring->count++;

        KeReleaseSpinLock(&g_ring->lock, old);
    }

    __forceinline BOOLEAN was_hostile_load_near(UINT64 window_tsc, UINT32 min_tier = 1) {
        if (!g_ring) return FALSE;
        UINT64 now = __rdtsc();

        KIRQL old;
        KeAcquireSpinLock(&g_ring->lock, &old);

        BOOLEAN found = FALSE;
        ULONG cnt = g_ring->count;
        ULONG start = (g_ring->head + RING_SIZE - cnt) % RING_SIZE;
        for (ULONG i = 0; i < cnt; i++) {
            const record_t& r = g_ring->records[(start + i) % RING_SIZE];
            if (r.hostile_tier < min_tier) continue;
            if (now - r.timestamp <= window_tsc) {
                found = TRUE;
                break;
            }
        }

        KeReleaseSpinLock(&g_ring->lock, old);
        return found;
    }

    __forceinline ULONG snapshot(record_t* out, ULONG max_slots) {
        if (!g_ring || !out || max_slots == 0) return 0;

        KIRQL old;
        KeAcquireSpinLock(&g_ring->lock, &old);

        ULONG cnt = g_ring->count;
        ULONG copy = cnt < max_slots ? cnt : max_slots;
        ULONG start = (g_ring->head + RING_SIZE - cnt) % RING_SIZE;
        for (ULONG i = 0; i < copy; i++) {
            out[i] = g_ring->records[(start + i) % RING_SIZE];
        }

        KeReleaseSpinLock(&g_ring->lock, old);
        return copy;
    }
}
