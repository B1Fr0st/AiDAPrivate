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
        volatile UINT8   peer_code_hash[32];
        volatile UINT64  peer_code_hash_tsc;
        volatile UINT32  peer_code_hash_valid;
        volatile UINT8   mac[32];
    };

    inline bridge_v2_t* g_bridge_v2 = nullptr;
    inline UINT8         g_bridge_key[32] = {};
    inline UINT64        g_last_counter = 0;
    inline KSPIN_LOCK    g_bridge_lock = {};

    __forceinline BOOLEAN init_bridge(const UINT8 kw_subkey[32])
    {
        SN_LOG("bridge_v2::init_bridge: allocating bridge_v2_t size=0x%lx key_present=%u existing=%p irql=%lu",
            (ULONG)sizeof(bridge_v2_t),
            kw_subkey ? 1u : 0u,
            g_bridge_v2,
            static_cast<ULONG>(KeGetCurrentIrql()));
        g_bridge_v2 = static_cast<bridge_v2_t*>(
            ExAllocatePool2(POOL_FLAG_NON_PAGED, sizeof(bridge_v2_t), BRIDGE_POOL_TAG));
        if (!g_bridge_v2) {
            SN_LOG("bridge_v2::init_bridge: FAIL - ExAllocatePool2 returned NULL");
            return FALSE;
        }

        RtlZeroMemory(g_bridge_v2, sizeof(bridge_v2_t));
        g_bridge_v2->version = BRIDGE_V2_VERSION;
        g_bridge_v2->counter = 0;

        RtlCopyMemory(g_bridge_key, kw_subkey, 32);
        KeInitializeSpinLock(&g_bridge_lock);
        g_last_counter = 0;

        SN_LOG("bridge_v2::init_bridge: SUCCESS bridge=%p version=%u counter=%llu key_present=%u",
            g_bridge_v2,
            g_bridge_v2->version,
            static_cast<unsigned long long>(g_bridge_v2->counter),
            g_bridge_key[0] || g_bridge_key[1] || g_bridge_key[2] || g_bridge_key[3] ? 1u : 0u);
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
        if (!g_bridge_v2) {
            SN_LOG("bridge_v2::send_command: reject reason=no_bridge cmd=%llu param_present=%u",
                static_cast<unsigned long long>(cmd),
                param != 0 ? 1u : 0u);
            return FALSE;
        }

        KIRQL old_irql;
        KeAcquireSpinLock(&g_bridge_lock, &old_irql);

        g_bridge_v2->counter++;
        g_bridge_v2->sentinel_tsc = __rdtsc();
        g_bridge_v2->sentinel_cmd_enc = cmd;
        g_bridge_v2->sentinel_cmd_param_enc = param;

        compute_mac(g_bridge_v2, g_bridge_key, const_cast<UINT8*>(g_bridge_v2->mac));

        KeReleaseSpinLock(&g_bridge_lock, old_irql);
        SN_LOG("bridge_v2::send_command: ok bridge=%p cmd=%llu param_present=%u counter=%llu sentinel_tsc=%llu irql_before=%lu",
            g_bridge_v2,
            static_cast<unsigned long long>(cmd),
            param != 0 ? 1u : 0u,
            static_cast<unsigned long long>(g_bridge_v2->counter),
            static_cast<unsigned long long>(g_bridge_v2->sentinel_tsc),
            static_cast<ULONG>(old_irql));
        return TRUE;
    }

    __forceinline BOOLEAN publish_peer_code_hash(const UINT8 hash[32])
    {
        if (!g_bridge_v2 || !hash) {
            SN_LOG("bridge_v2::publish_peer_code_hash: reject bridge=%p hash_present=%u",
                g_bridge_v2,
                hash ? 1u : 0u);
            return FALSE;
        }

        KIRQL old_irql;
        KeAcquireSpinLock(&g_bridge_lock, &old_irql);

        for (ULONG i = 0; i < 32; ++i) {
            const_cast<UINT8*>(g_bridge_v2->peer_code_hash)[i] = hash[i];
        }
        g_bridge_v2->peer_code_hash_tsc = __rdtsc();
        g_bridge_v2->peer_code_hash_valid = 1;
        g_bridge_v2->counter++;
        g_bridge_v2->sentinel_tsc = __rdtsc();

        compute_mac(g_bridge_v2, g_bridge_key, const_cast<UINT8*>(g_bridge_v2->mac));

        KeReleaseSpinLock(&g_bridge_lock, old_irql);
        SN_LOG("bridge_v2::publish_peer_code_hash: ok bridge=%p counter=%llu hash_valid=%u hash_tsc=%llu irql_before=%lu",
            g_bridge_v2,
            static_cast<unsigned long long>(g_bridge_v2->counter),
            g_bridge_v2->peer_code_hash_valid ? 1u : 0u,
            static_cast<unsigned long long>(g_bridge_v2->peer_code_hash_tsc),
            static_cast<ULONG>(old_irql));
        return TRUE;
    }

    __forceinline BOOLEAN verify_response()
    {
        if (!g_bridge_v2) {
            SN_LOG("bridge_v2::verify_response: reject reason=no_bridge");
            return FALSE;
        }

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
        SN_LOG("bridge_v2::verify_response: bridge=%p mac_ok=%u replay_ok=%u counter=%llu last_counter=%llu whoswho_tsc=%llu sentinel_tsc=%llu irql_before=%lu",
            g_bridge_v2,
            mac_ok ? 1u : 0u,
            replay_ok ? 1u : 0u,
            static_cast<unsigned long long>(counter),
            static_cast<unsigned long long>(g_last_counter),
            static_cast<unsigned long long>(g_bridge_v2->whoswho_tsc),
            static_cast<unsigned long long>(g_bridge_v2->sentinel_tsc),
            static_cast<ULONG>(old_irql));
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
            SN_LOG("bridge_v2::shutdown bridge=%p counter=%llu whoswho_tsc=%llu sentinel_tsc=%llu",
                g_bridge_v2,
                static_cast<unsigned long long>(g_bridge_v2->counter),
                static_cast<unsigned long long>(g_bridge_v2->whoswho_tsc),
                static_cast<unsigned long long>(g_bridge_v2->sentinel_tsc));
            RtlSecureZeroMemory(g_bridge_v2, sizeof(bridge_v2_t));
            ExFreePoolWithTag(g_bridge_v2, BRIDGE_POOL_TAG);
            g_bridge_v2 = nullptr;
        }
        RtlSecureZeroMemory(g_bridge_key, sizeof(g_bridge_key));
    }
}
