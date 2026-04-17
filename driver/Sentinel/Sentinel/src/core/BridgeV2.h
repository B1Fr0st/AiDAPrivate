#pragma once

#include <ntddk.h>
#include "KernelCrypto.h"

namespace bridge_v2
{
    constexpr ULONG  BRIDGE_V2_VERSION = 2;
    constexpr ULONG  REPLAY_WINDOW = 64;
    constexpr ULONG  BRIDGE_POOL_TAG = 'br2S';

    struct bridge_v2_t
    {
        volatile UINT32  version;
        volatile UINT64  counter;
        volatile UINT64  whoswho_tsc;
        volatile UINT64  sentinel_tsc;
        volatile UINT64  sentinel_cmd_enc;
        volatile UINT64  sentinel_cmd_param_enc;
        volatile UINT64  sentinel_challenge_enc;
        volatile UINT64  whoswho_response;
        volatile UINT64  challenge_issued_tsc;
        volatile UINT8   mac[32];
    };

    inline bridge_v2_t* g_bridge_v2 = nullptr;
    inline UINT8         g_bridge_key[32] = {};
    inline UINT64        g_last_counter = 0;
    inline KSPIN_LOCK    g_bridge_lock = {};

    __forceinline BOOLEAN init_bridge(const UINT8 kw_subkey[32])
    {
        g_bridge_v2 = static_cast<bridge_v2_t*>(
            ExAllocatePool2(POOL_FLAG_NON_PAGED, sizeof(bridge_v2_t), BRIDGE_POOL_TAG));
        if (!g_bridge_v2) return FALSE;

        RtlZeroMemory(g_bridge_v2, sizeof(bridge_v2_t));
        g_bridge_v2->version = BRIDGE_V2_VERSION;
        g_bridge_v2->counter = 0;

        RtlCopyMemory(g_bridge_key, kw_subkey, 32);
        KeInitializeSpinLock(&g_bridge_lock);
        g_last_counter = 0;

        return TRUE;
    }

    __forceinline void compute_mac(const bridge_v2_t* b, const UINT8 key[32], UINT8 mac_out[32])
    {
        UINT8 data[sizeof(bridge_v2_t) - 32] = {};
        RtlCopyMemory(data, b, sizeof(data));
        kernel_crypto::hmac_sha256(key, 32, data, sizeof(data), mac_out);
    }

    __forceinline BOOLEAN send_command(UINT64 cmd, UINT64 param)
    {
        if (!g_bridge_v2) return FALSE;

        KIRQL old_irql;
        KeAcquireSpinLock(&g_bridge_lock, &old_irql);

        g_bridge_v2->counter++;
        g_bridge_v2->sentinel_tsc = __rdtsc();
        g_bridge_v2->sentinel_cmd_enc = cmd;
        g_bridge_v2->sentinel_cmd_param_enc = param;

        compute_mac(g_bridge_v2, g_bridge_key, const_cast<UINT8*>(g_bridge_v2->mac));

        KeReleaseSpinLock(&g_bridge_lock, old_irql);
        return TRUE;
    }

    __forceinline BOOLEAN verify_response()
    {
        if (!g_bridge_v2) return FALSE;

        KIRQL old_irql;
        KeAcquireSpinLock(&g_bridge_lock, &old_irql);

        UINT8 expected_mac[32];
        compute_mac(g_bridge_v2, g_bridge_key, expected_mac);

        BOOLEAN mac_ok = (RtlCompareMemory(
            expected_mac, const_cast<UINT8*>(g_bridge_v2->mac), 32) == 32);

        UINT64 counter = g_bridge_v2->counter;
        BOOLEAN replay_ok = (counter > g_last_counter ||
                             counter - g_last_counter < REPLAY_WINDOW);
        if (mac_ok && replay_ok)
            g_last_counter = counter;

        KeReleaseSpinLock(&g_bridge_lock, old_irql);
        return mac_ok && replay_ok;
    }

    __forceinline PVOID get_bridge_address()
    {
        return g_bridge_v2;
    }

    __forceinline void shutdown()
    {
        if (g_bridge_v2)
        {
            RtlSecureZeroMemory(g_bridge_v2, sizeof(bridge_v2_t));
            ExFreePoolWithTag(g_bridge_v2, BRIDGE_POOL_TAG);
            g_bridge_v2 = nullptr;
        }
        RtlSecureZeroMemory(g_bridge_key, sizeof(g_bridge_key));
    }
}
