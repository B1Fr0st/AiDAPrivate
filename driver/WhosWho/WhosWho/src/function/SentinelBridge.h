#pragma once


namespace sentinel_bridge {


    constexpr ULONG BRIDGE_MAGIC   = 0x57484F53;
    constexpr ULONG BRIDGE_VERSION = 1;


    constexpr ULONG BUGCHECK_SENTINEL_ABSENT = 0xDEAD5E10;

    constexpr ULONG BRIDGE_CMD_NONE             = 0;
    constexpr ULONG BRIDGE_CMD_DEBUGGER_FOUND   = 1;
    constexpr ULONG BRIDGE_CMD_DUMP_TOOL_FOUND  = 2;
    constexpr ULONG BRIDGE_CMD_INTEGRITY_FAIL   = 3;
    constexpr ULONG BRIDGE_CMD_CALLBACK_REMOVED = 4;
    constexpr ULONG BRIDGE_CMD_ETW_REACTIVATED  = 5;
    constexpr ULONG BRIDGE_CMD_RE_EVIDENCE      = 6;
    constexpr ULONG BRIDGE_CMD_SET_PROTECTED_PID= 7;
    constexpr ULONG BRIDGE_CMD_PRE_BSOD_INTENT  = 8;
    constexpr ULONG BRIDGE_CMD_HEARTBEAT_STALL  = 9;
    constexpr ULONG BRIDGE_CMD_INJECTED_DLL     = 10;

    constexpr ULONG RE_REASON_GENERIC       = 0x0000DEEEu;
    constexpr ULONG RE_REASON_DEBUG_ATTACH  = 0x0000DBDBu;
    constexpr ULONG RE_REASON_DR_SET        = 0x0000D7D7u;
    constexpr ULONG RE_REASON_FOREIGN_HND   = 0x0000AD7Du;
    constexpr ULONG RE_REASON_INJECTED_DLL  = 0x0000114Du;
    constexpr ULONG RE_REASON_WATCHDOG_STALL= 0x0000DEDDu;

    struct bridge_t {
        volatile ULONG   magic;
        volatile ULONG   version;
        volatile PVOID   code_base;
        volatile ULONG   code_size;
        volatile LONG64  whoswho_tsc;
        volatile LONG64  sentinel_tsc;
        volatile ULONG   sentinel_cmd;
        volatile ULONG   sentinel_cmd_param;
        volatile UINT64  sentinel_challenge;
        volatile UINT64  whoswho_response;
        volatile UINT64  challenge_issued_tsc;
    };

    // V2 bridge: adds crypto nonce + HMAC integrity for shared memory validation
    constexpr ULONG BRIDGE_VERSION_2 = 2;

    struct bridge_v2_t {
        bridge_t          v1;              // backward-compatible base
        volatile UINT64   crypto_nonce;    // random per-session; rotated on heartbeat
        volatile UINT8    hmac[32];        // HMAC-SHA256(bridge_key, v1 fields || nonce)
        volatile UINT64   nonce_tsc;       // TSC at last nonce rotation
        volatile UINT32   hmac_valid;      // 1 if hmac was validated last tick
        volatile UINT32   _pad;
    };


    inline bridge_v2_t g_bridge_v2 = {
        {   // v1
            BRIDGE_MAGIC,
            BRIDGE_VERSION_2,
            nullptr,
            0,
            0,
            0,
            BRIDGE_CMD_NONE,
            0,
            0,
            0,
            0
        },
        0,       // crypto_nonce
        {0},     // hmac
        0,       // nonce_tsc
        0,       // hmac_valid
        0        // _pad
    };

    // Alias for code still using g_bridge directly
    inline bridge_t& g_bridge = g_bridge_v2.v1;

    constexpr UINT64 CHALLENGE_HMAC_KEY = 0x7A3F1D9E5BC82A46ULL;

    inline volatile UINT64 g_bridge_crypt_key = 0;

    __forceinline UINT64 derive_bridge_key() {
        int cpu[4] = {};
        __cpuid(cpu, 1);
        UINT64 k = static_cast<UINT64>(cpu[0]) ^ (static_cast<UINT64>(cpu[2]) << 32);
        __cpuid(cpu, 0x80000001);
        k ^= static_cast<UINT64>(cpu[0]) ^ (static_cast<UINT64>(cpu[3]) << 16);
        k ^= k >> 33;
        k *= 0xFF51AFD7ED558CCDULL;
        k ^= k >> 33;
        k *= 0xC4CEB9FE1A85EC53ULL;
        k ^= k >> 33;
        return k;
    }

    __forceinline void bridge_encrypt_cmd(ULONG& cmd, ULONG& param) {
        UINT64 key = g_bridge_crypt_key;
        cmd   ^= static_cast<ULONG>(key & 0xFFFFFFFF);
        param ^= static_cast<ULONG>(key >> 32);
    }

    __forceinline void bridge_decrypt_cmd(ULONG raw_cmd, ULONG raw_param,
                                          ULONG& cmd, ULONG& param) {
        UINT64 key = g_bridge_crypt_key;
        cmd   = raw_cmd   ^ static_cast<ULONG>(key & 0xFFFFFFFF);
        param = raw_param ^ static_cast<ULONG>(key >> 32);
    }

    __forceinline void bridge_encrypt_challenge(UINT64& challenge) {
        challenge ^= _rotr64(g_bridge_crypt_key, 17);
    }

    __forceinline void bridge_decrypt_challenge(UINT64 raw, UINT64& challenge) {
        challenge = raw ^ _rotr64(g_bridge_crypt_key, 17);
    }


    constexpr LONG WATCHDOG_PERIOD_MS    = 10000;
    constexpr LONG GRACE_PERIOD_MS       = 90000;
    constexpr LONG SENTINEL_TIMEOUT_MS   = 60000;

    inline KTIMER  g_watchdog_timer  = {};
    inline KDPC    g_watchdog_dpc    = {};
    inline volatile LONG64  g_last_seen_sentinel_tsc = 0;
    inline volatile LONG    g_stale_streak           = 0;
    inline volatile LONG64  g_watchdog_start_qpc     = 0;
    inline volatile LONG    g_watchdog_active        = 0;


    __forceinline UINT64 compute_challenge_response(UINT64 challenge) {
        UINT64 h = challenge ^ CHALLENGE_HMAC_KEY;
        h ^= h >> 33;
        h *= 0xFF51AFD7ED558CCDULL;
        h ^= h >> 33;
        h *= 0xC4CEB9FE1A85EC53ULL;
        h ^= h >> 33;
        return h;
    }

    // V2: rotate bridge nonce and recompute HMAC over v1 fields
    __forceinline void rotate_bridge_nonce() {
        UINT64 tsc = __rdtsc();
        UINT64 nonce = tsc ^ _rotl64(g_bridge_crypt_key, 23) ^ 0xA5A5A5A5A5A5A5A5ULL;
        nonce *= 0xFF51AFD7ED558CCDULL;
        nonce ^= nonce >> 33;

        _InterlockedExchange64(
            reinterpret_cast<volatile LONG64*>(&g_bridge_v2.crypto_nonce),
            static_cast<LONG64>(nonce));
        _InterlockedExchange64(
            reinterpret_cast<volatile LONG64*>(&g_bridge_v2.nonce_tsc),
            static_cast<LONG64>(tsc));

        // Compute soft HMAC: mix critical v1 fields with nonce
        // Full BCrypt HMAC unavailable at DISPATCH_LEVEL; use keyed mix
        UINT8 hmac_data[32];
        UINT64 h0 = g_bridge.magic ^ nonce;
        h0 *= 0xC4CEB9FE1A85EC53ULL; h0 ^= h0 >> 33;
        UINT64 h1 = static_cast<UINT64>(g_bridge.whoswho_tsc) ^ _rotl64(nonce, 17);
        h1 *= 0xFF51AFD7ED558CCDULL; h1 ^= h1 >> 33;
        UINT64 h2 = static_cast<UINT64>(g_bridge.sentinel_tsc) ^ _rotl64(nonce, 31);
        h2 *= 0xC4CEB9FE1A85EC53ULL; h2 ^= h2 >> 33;
        UINT64 h3 = g_bridge.sentinel_challenge ^ _rotl64(nonce, 7) ^ g_bridge_crypt_key;
        h3 *= 0xFF51AFD7ED558CCDULL; h3 ^= h3 >> 33;

        RtlCopyMemory(hmac_data,      &h0, 8);
        RtlCopyMemory(hmac_data + 8,  &h1, 8);
        RtlCopyMemory(hmac_data + 16, &h2, 8);
        RtlCopyMemory(hmac_data + 24, &h3, 8);
        RtlCopyMemory((PVOID)g_bridge_v2.hmac, hmac_data, 32);

        _InterlockedExchange(
            reinterpret_cast<volatile LONG*>(&g_bridge_v2.hmac_valid), 1);
    }

    // V2: verify HMAC integrity of bridge shared memory
    __forceinline BOOLEAN verify_bridge_hmac() {
        UINT64 nonce = g_bridge_v2.crypto_nonce;
        if (nonce == 0) return FALSE;

        UINT8 expected[32];
        UINT64 h0 = g_bridge.magic ^ nonce;
        h0 *= 0xC4CEB9FE1A85EC53ULL; h0 ^= h0 >> 33;
        UINT64 h1 = static_cast<UINT64>(g_bridge.whoswho_tsc) ^ _rotl64(nonce, 17);
        h1 *= 0xFF51AFD7ED558CCDULL; h1 ^= h1 >> 33;
        UINT64 h2 = static_cast<UINT64>(g_bridge.sentinel_tsc) ^ _rotl64(nonce, 31);
        h2 *= 0xC4CEB9FE1A85EC53ULL; h2 ^= h2 >> 33;
        UINT64 h3 = g_bridge.sentinel_challenge ^ _rotl64(nonce, 7) ^ g_bridge_crypt_key;
        h3 *= 0xFF51AFD7ED558CCDULL; h3 ^= h3 >> 33;

        RtlCopyMemory(expected,      &h0, 8);
        RtlCopyMemory(expected + 8,  &h1, 8);
        RtlCopyMemory(expected + 16, &h2, 8);
        RtlCopyMemory(expected + 24, &h3, 8);

        // Constant-time compare
        volatile UINT8 diff = 0;
        for (int i = 0; i < 32; i++)
            diff |= expected[i] ^ g_bridge_v2.hmac[i];

        return (diff == 0) ? TRUE : FALSE;
    }

    __forceinline void tick() {
        LONG64 tsc = static_cast<LONG64>(__rdtsc());
        _InterlockedExchange64(&g_bridge.whoswho_tsc, tsc);

        UINT64 raw_challenge = g_bridge.sentinel_challenge;
        UINT64 challenge = 0;
        bridge_decrypt_challenge(raw_challenge, challenge);
        if (challenge != 0 && g_bridge.whoswho_response == 0) {
            UINT64 response = compute_challenge_response(challenge);
            InterlockedExchange64(
                reinterpret_cast<volatile LONG64*>(&g_bridge.whoswho_response),
                static_cast<LONG64>(response));
        }

        // V2: rotate nonce and recompute bridge HMAC each tick
        rotate_bridge_nonce();

        WW_LOG("tick: wrote whoswho_tsc=%lld", tsc);
    }

    inline VOID NTAPI watchdog_dpc_callback(
        PKDPC  ,
        PVOID  ,
        PVOID  ,
        PVOID  )
    {
        if (!_InterlockedCompareExchange(&g_watchdog_active, 0, 0)) {
            WW_LOG("watchdog_dpc: NOT active, returning");
            return;
        }

        tick();

        constexpr LONG64 TSC_PER_MS_LOW = 2000000LL;
        constexpr LONG64 GRACE_TSC      = static_cast<LONG64>(GRACE_PERIOD_MS) * TSC_PER_MS_LOW;

        LONG64 now_tsc  = static_cast<LONG64>(__rdtsc());
        LONG64 start    = _InterlockedCompareExchange64(&g_watchdog_start_qpc, 0, 0);
        LONG64 elapsed  = now_tsc - start;

        WW_LOG("watchdog_dpc: now_tsc=%lld start=%lld elapsed=%lld grace_tsc=%lld",
            now_tsc, start, elapsed, GRACE_TSC);

        if (elapsed < GRACE_TSC) {
            WW_LOG("watchdog_dpc: still in grace period (%lld < %lld), skipping",
                elapsed, GRACE_TSC);
            return;
        }

        LONG64 current_sentinel_tsc = _InterlockedCompareExchange64(
            &g_bridge.sentinel_tsc, 0, 0);

        LONG64 last = _InterlockedCompareExchange64(
            &g_last_seen_sentinel_tsc, 0, 0);

        WW_LOG("watchdog_dpc: sentinel_tsc=%lld last_seen=%lld bridge_addr=%p",
            current_sentinel_tsc, last, &g_bridge);

        if (current_sentinel_tsc != last) {
            _InterlockedExchange64(&g_last_seen_sentinel_tsc, current_sentinel_tsc);
            _InterlockedExchange(&g_stale_streak, 0);
            WW_LOG("watchdog_dpc: Sentinel ALIVE, tsc changed from %lld to %lld",
                last, current_sentinel_tsc);

            ULONG raw_cmd = _InterlockedExchange((volatile LONG*)&g_bridge.sentinel_cmd, BRIDGE_CMD_NONE);
            ULONG raw_param = _InterlockedExchange((volatile LONG*)&g_bridge.sentinel_cmd_param, 0);
            ULONG cmd = 0, param = 0;
            bridge_decrypt_cmd(raw_cmd, raw_param, cmd, param);
            if (cmd != BRIDGE_CMD_NONE) {
                WW_LOG("watchdog_dpc: Sentinel command=%lu param=0x%lx", cmd, param);

                if (cmd == BRIDGE_CMD_DEBUGGER_FOUND || cmd == BRIDGE_CMD_DUMP_TOOL_FOUND ||
                    cmd == BRIDGE_CMD_INTEGRITY_FAIL || cmd == BRIDGE_CMD_CALLBACK_REMOVED) {
                    if (_KeBugCheckEx) {
                        _KeBugCheckEx(0xDEAD0002u, cmd, param, 0, 0);
                    }
                }
            }

            return;
        }

        LONG streak = _InterlockedIncrement(&g_stale_streak);

        constexpr LONG STALE_THRESHOLD = SENTINEL_TIMEOUT_MS / WATCHDOG_PERIOD_MS;

        WW_LOG("watchdog_dpc: Sentinel STALE! streak=%ld threshold=%ld sentinel_tsc=%lld last_seen=%lld",
            streak, STALE_THRESHOLD, current_sentinel_tsc, last);

        if (streak >= STALE_THRESHOLD) {
            WW_LOG("watchdog_dpc: BUGCHECK! streak=%ld >= threshold=%ld, sentinel_tsc=%lld, last=%lld, elapsed=%lld",
                streak, STALE_THRESHOLD, current_sentinel_tsc, last, elapsed);
            if (_KeBugCheckEx) {
                _KeBugCheckEx(
                    BUGCHECK_SENTINEL_ABSENT,
                    static_cast<ULONG_PTR>(last),
                    static_cast<ULONG_PTR>(current_sentinel_tsc),
                    static_cast<ULONG_PTR>(elapsed),
                    static_cast<ULONG_PTR>(streak));
            }
        }
    }


    __forceinline void init(PVOID text_base, ULONG text_size) {
        g_bridge_crypt_key = derive_bridge_key();
        g_bridge.code_base = text_base;
        g_bridge.code_size = text_size;
        WW_LOG("bridge::init: code_base=%p code_size=0x%lx bridge_addr=%p magic=0x%lx version=%lu",
            text_base, text_size, &g_bridge, g_bridge.magic, g_bridge.version);
    }


    __forceinline void start_watchdog() {
        if (_InterlockedCompareExchange(&g_watchdog_active, 1, 0) != 0) {
            WW_LOG("start_watchdog: already active, skipping");
            return;
        }

        _InterlockedExchange64(&g_watchdog_start_qpc, static_cast<LONG64>(__rdtsc()));

        LONG64 initial_sentinel_tsc = _InterlockedCompareExchange64(&g_bridge.sentinel_tsc, 0, 0);
        _InterlockedExchange64(&g_last_seen_sentinel_tsc, initial_sentinel_tsc);

        _InterlockedExchange(&g_stale_streak, 0);

        _KeInitializeTimerEx(&g_watchdog_timer, SynchronizationTimer);
        _KeInitializeDpc(&g_watchdog_dpc, watchdog_dpc_callback, nullptr);

        LARGE_INTEGER due_time;
        due_time.QuadPart = -static_cast<LONGLONG>(WATCHDOG_PERIOD_MS) * 10000LL;

        _KeSetTimerEx(&g_watchdog_timer, due_time, WATCHDOG_PERIOD_MS, &g_watchdog_dpc);

        WW_LOG("start_watchdog: armed, period=%ldms grace=%ldms timeout=%ldms initial_sentinel_tsc=%lld bridge=%p",
            WATCHDOG_PERIOD_MS, GRACE_PERIOD_MS, SENTINEL_TIMEOUT_MS,
            initial_sentinel_tsc, &g_bridge);
    }
}
