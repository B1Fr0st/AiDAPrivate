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

    __forceinline ULONG bridge_read_kuser_u32(ULONG offset)
    {
        ULONG value = 0;
        __try {
            volatile ULONG* ptr = reinterpret_cast<volatile ULONG*>(0xFFFFF78000000000ULL + offset);
            value = *ptr;
        } __except (EXCEPTION_EXECUTE_HANDLER) {
            value = 0;
        }
        return value;
    }

    __forceinline UINT64 bridge_diag_hash(const UINT8* data, SIZE_T size)
    {
        UINT64 hash = 1469598103934665603ULL;
        if (!data || size == 0)
            return hash;
        for (SIZE_T i = 0; i < size; ++i) {
            hash ^= data[i];
            hash *= 1099511628211ULL;
        }
        return hash;
    }

    __forceinline void compute_mac(const bridge_v2_t* b, const UINT8 key[32], UINT8 mac_out[32])
    {
        UINT8 data[sizeof(bridge_v2_t) - 32] = {};
        RtlCopyMemory(data, b, sizeof(data));
        kernel_crypto::hmac_sha256(key, 32, data, sizeof(data), mac_out);
    }

    __forceinline BOOLEAN init_bridge(const UINT8 kw_subkey[32])
    {
        SN_LOG("bridge_v2::init_bridge: enter size=0x%lx key_present=%u key_hash=0x%llx existing=%p irql=%lu cpu=%lu pid=%llu tid=%llu build=%lu offsets version=0x%lx counter=0x%lx whoswho_tsc=0x%lx sentinel_tsc=0x%lx mac=0x%lx last_counter=%llu",
            (ULONG)sizeof(bridge_v2_t),
            kw_subkey ? 1u : 0u,
            static_cast<unsigned long long>(bridge_diag_hash(kw_subkey, kw_subkey ? 32 : 0)),
            g_bridge_v2,
            static_cast<ULONG>(KeGetCurrentIrql()),
            KeGetCurrentProcessorNumber(),
            static_cast<unsigned long long>(reinterpret_cast<ULONG_PTR>(PsGetCurrentProcessId())),
            static_cast<unsigned long long>(reinterpret_cast<ULONG_PTR>(PsGetCurrentThreadId())),
            bridge_read_kuser_u32(0x260) & 0xFFFFu,
            static_cast<ULONG>(FIELD_OFFSET(bridge_v2_t, version)),
            static_cast<ULONG>(FIELD_OFFSET(bridge_v2_t, counter)),
            static_cast<ULONG>(FIELD_OFFSET(bridge_v2_t, whoswho_tsc)),
            static_cast<ULONG>(FIELD_OFFSET(bridge_v2_t, sentinel_tsc)),
            static_cast<ULONG>(FIELD_OFFSET(bridge_v2_t, mac)),
            static_cast<unsigned long long>(g_last_counter));
        g_bridge_v2 = static_cast<bridge_v2_t*>(
            ExAllocatePool2(POOL_FLAG_NON_PAGED, sizeof(bridge_v2_t), BRIDGE_POOL_TAG));
        if (!g_bridge_v2) {
            SN_LOG("bridge_v2::init_bridge: FAIL reason=alloc_null size=0x%lx key_hash=0x%llx irql=%lu",
                (ULONG)sizeof(bridge_v2_t),
                static_cast<unsigned long long>(bridge_diag_hash(kw_subkey, kw_subkey ? 32 : 0)),
                static_cast<ULONG>(KeGetCurrentIrql()));
            return FALSE;
        }

        RtlZeroMemory(g_bridge_v2, sizeof(bridge_v2_t));
        g_bridge_v2->version = BRIDGE_V2_VERSION;
        g_bridge_v2->counter = 0;

        RtlCopyMemory(g_bridge_key, kw_subkey, 32);
        KeInitializeSpinLock(&g_bridge_lock);
        g_last_counter = 0;

        UINT8 init_mac[32] = {};
        compute_mac(g_bridge_v2, g_bridge_key, init_mac);
        RtlCopyMemory(const_cast<UINT8*>(g_bridge_v2->mac), init_mac, sizeof(init_mac));
        SN_LOG("bridge_v2::init_bridge: SUCCESS bridge=%p version=%u counter=%llu key_present=%u key_hash=0x%llx mac_hash=0x%llx whoswho_tsc=%llu sentinel_tsc=%llu last_counter=%llu pool_tag=0x%08lx",
            g_bridge_v2,
            g_bridge_v2->version,
            static_cast<unsigned long long>(g_bridge_v2->counter),
            g_bridge_key[0] || g_bridge_key[1] || g_bridge_key[2] || g_bridge_key[3] ? 1u : 0u,
            static_cast<unsigned long long>(bridge_diag_hash(g_bridge_key, sizeof(g_bridge_key))),
            static_cast<unsigned long long>(bridge_diag_hash(init_mac, sizeof(init_mac))),
            static_cast<unsigned long long>(g_bridge_v2->whoswho_tsc),
            static_cast<unsigned long long>(g_bridge_v2->sentinel_tsc),
            static_cast<unsigned long long>(g_last_counter),
            BRIDGE_POOL_TAG);
        RtlSecureZeroMemory(init_mac, sizeof(init_mac));
        return TRUE;
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
        UINT64 mac_hash = bridge_diag_hash(const_cast<UINT8*>(g_bridge_v2->mac), 32);
        UINT64 key_hash = bridge_diag_hash(g_bridge_key, sizeof(g_bridge_key));
        UINT64 counter = g_bridge_v2->counter;
        UINT64 sentinel_tsc = g_bridge_v2->sentinel_tsc;
        UINT64 whoswho_tsc = g_bridge_v2->whoswho_tsc;

        KeReleaseSpinLock(&g_bridge_lock, old_irql);
        SN_LOG("bridge_v2::send_command: ok bridge=%p cmd=%llu param_present=%u counter=%llu whoswho_tsc=%llu sentinel_tsc=%llu key_hash=0x%llx mac_hash=0x%llx irql_before=%lu cpu=%lu",
            g_bridge_v2,
            static_cast<unsigned long long>(cmd),
            param != 0 ? 1u : 0u,
            static_cast<unsigned long long>(counter),
            static_cast<unsigned long long>(whoswho_tsc),
            static_cast<unsigned long long>(sentinel_tsc),
            static_cast<unsigned long long>(key_hash),
            static_cast<unsigned long long>(mac_hash),
            static_cast<ULONG>(old_irql),
            KeGetCurrentProcessorNumber());
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
        UINT64 mac_hash = bridge_diag_hash(const_cast<UINT8*>(g_bridge_v2->mac), 32);
        UINT64 peer_hash_fold = bridge_diag_hash(hash, 32);
        UINT64 key_hash = bridge_diag_hash(g_bridge_key, sizeof(g_bridge_key));
        UINT64 counter = g_bridge_v2->counter;
        UINT64 peer_tsc = g_bridge_v2->peer_code_hash_tsc;
        UINT64 sentinel_tsc = g_bridge_v2->sentinel_tsc;

        KeReleaseSpinLock(&g_bridge_lock, old_irql);
        SN_LOG("bridge_v2::publish_peer_code_hash: ok bridge=%p counter=%llu hash_valid=%u peer_hash_fold=0x%llx hash_tsc=%llu sentinel_tsc=%llu key_hash=0x%llx mac_hash=0x%llx irql_before=%lu cpu=%lu",
            g_bridge_v2,
            static_cast<unsigned long long>(counter),
            g_bridge_v2->peer_code_hash_valid ? 1u : 0u,
            static_cast<unsigned long long>(peer_hash_fold),
            static_cast<unsigned long long>(peer_tsc),
            static_cast<unsigned long long>(sentinel_tsc),
            static_cast<unsigned long long>(key_hash),
            static_cast<unsigned long long>(mac_hash),
            static_cast<ULONG>(old_irql),
            KeGetCurrentProcessorNumber());
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
        UINT64 expected_mac_hash = bridge_diag_hash(expected_mac, sizeof(expected_mac));
        UINT64 actual_mac_hash = bridge_diag_hash(const_cast<UINT8*>(g_bridge_v2->mac), 32);
        UINT64 key_hash = bridge_diag_hash(g_bridge_key, sizeof(g_bridge_key));

        UINT64 counter = g_bridge_v2->counter;
        BOOLEAN replay_ok = (counter > g_last_counter ||
                             counter - g_last_counter < REPLAY_WINDOW);
        if (mac_ok && replay_ok)
            g_last_counter = counter;
        UINT64 last_counter = g_last_counter;
        UINT64 whoswho_tsc = g_bridge_v2->whoswho_tsc;
        UINT64 sentinel_tsc = g_bridge_v2->sentinel_tsc;

        KeReleaseSpinLock(&g_bridge_lock, old_irql);
        SN_LOG("bridge_v2::verify_response: bridge=%p mac_ok=%u replay_ok=%u counter=%llu last_counter=%llu whoswho_tsc=%llu sentinel_tsc=%llu key_hash=0x%llx expected_mac_hash=0x%llx actual_mac_hash=0x%llx irql_before=%lu cpu=%lu",
            g_bridge_v2,
            mac_ok ? 1u : 0u,
            replay_ok ? 1u : 0u,
            static_cast<unsigned long long>(counter),
            static_cast<unsigned long long>(last_counter),
            static_cast<unsigned long long>(whoswho_tsc),
            static_cast<unsigned long long>(sentinel_tsc),
            static_cast<unsigned long long>(key_hash),
            static_cast<unsigned long long>(expected_mac_hash),
            static_cast<unsigned long long>(actual_mac_hash),
            static_cast<ULONG>(old_irql),
            KeGetCurrentProcessorNumber());
        RtlSecureZeroMemory(expected_mac, sizeof(expected_mac));
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
            SN_LOG("bridge_v2::shutdown bridge=%p counter=%llu whoswho_tsc=%llu sentinel_tsc=%llu last_counter=%llu key_hash=0x%llx mac_hash=0x%llx irql=%lu cpu=%lu",
                g_bridge_v2,
                static_cast<unsigned long long>(g_bridge_v2->counter),
                static_cast<unsigned long long>(g_bridge_v2->whoswho_tsc),
                static_cast<unsigned long long>(g_bridge_v2->sentinel_tsc),
                static_cast<unsigned long long>(g_last_counter),
                static_cast<unsigned long long>(bridge_diag_hash(g_bridge_key, sizeof(g_bridge_key))),
                static_cast<unsigned long long>(bridge_diag_hash(const_cast<UINT8*>(g_bridge_v2->mac), 32)),
                static_cast<ULONG>(KeGetCurrentIrql()),
                KeGetCurrentProcessorNumber());
            RtlSecureZeroMemory(g_bridge_v2, sizeof(bridge_v2_t));
            ExFreePoolWithTag(g_bridge_v2, BRIDGE_POOL_TAG);
            g_bridge_v2 = nullptr;
        }
        RtlSecureZeroMemory(g_bridge_key, sizeof(g_bridge_key));
    }
}
