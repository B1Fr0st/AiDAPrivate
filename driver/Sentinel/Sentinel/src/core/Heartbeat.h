#pragma once
#include <imports/Defs.h>

// Declared in DriverEntry.cpp — global scope
extern volatile PVOID  g_target_driver_base;
extern volatile PVOID  g_target_driver_object;
extern volatile ULONG  g_target_driver_size;
extern PDRIVER_OBJECT  g_sentinel_driver_object;


namespace heartbeat {


    struct sentinel_bridge_t {
        volatile ULONG  magic;
        volatile ULONG  version;
        volatile PVOID  code_base;
        volatile ULONG  code_size;
        volatile LONG64 whoswho_tsc;
        volatile LONG64 sentinel_tsc;
        volatile ULONG  sentinel_cmd;
        volatile ULONG  sentinel_cmd_param;
        volatile UINT64 sentinel_challenge;
        volatile UINT64 whoswho_response;
        volatile UINT64 challenge_issued_tsc;
    };


    constexpr ULONG  BRIDGE_MAGIC = 0x57484F53;
    constexpr ULONG  BRIDGE_VERSION = 2;

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
    constexpr ULONG BRIDGE_CMD_HOSTILE_DRIVER    = 11;
    constexpr ULONG BRIDGE_CMD_HOSTILE_DEVICE    = 12;
    constexpr ULONG BRIDGE_CMD_KD_ENABLED        = 13;
    constexpr ULONG BRIDGE_CMD_DMA_CANARY_HIT    = 14;
    constexpr ULONG BRIDGE_CMD_EVIDENCE_READY    = 15;
    constexpr ULONG BRIDGE_CMD_TIER_A_PRE_LOADED = 16;
    constexpr ULONG BRIDGE_CMD_RE_CONFIRMED_USERMODE  = 17;
    constexpr ULONG BRIDGE_CMD_SENTINEL_THREAD_INJECT = 18;

    constexpr ULONG BRIDGE_CMD_TIER_A_DRIVER_PRESENT = BRIDGE_CMD_HOSTILE_DRIVER;
    constexpr ULONG BRIDGE_CMD_KDBG_TRANSITION       = BRIDGE_CMD_KD_ENABLED;
    constexpr ULONG BRIDGE_CMD_CANARY_FOREIGN_PT     = BRIDGE_CMD_DMA_CANARY_HIT;
    constexpr ULONG BRIDGE_CMD_DEVICE_OBJECT_HIT     = BRIDGE_CMD_HOSTILE_DEVICE;

    constexpr ULONG BUGCHECK_RE_USERMODE_CONFIRMED = 0xDEAD0002u;
    constexpr ULONG BUGCHECK_HOSTILE_DRIVER_LOAD   = 0xDEAD5E40u;
    constexpr ULONG BUGCHECK_HOSTILE_DEVICE_OBJECT = 0xDEAD5E41u;
    constexpr ULONG BUGCHECK_KD_ENABLED_POST_INIT  = 0xDEAD5E42u;
    constexpr ULONG BUGCHECK_DMA_CANARY_HIT        = 0xDEAD5E43u;
    constexpr ULONG BUGCHECK_SENTINEL_THREAD_INJECT= 0xDEAD5E44u;
    constexpr ULONG BUGCHECK_TARGET_FILE_SCANNED   = 0xDEAD7A60u;
    constexpr ULONG BUGCHECK_DEBUG_BY_RE_TOOL      = 0xDEAD7A62u;
    constexpr ULONG BUGCHECK_KD_TARGETING_US       = 0xDEAD7A63u;
    constexpr ULONG BUGCHECK_TIER_A_DRIVER_LOADED  = BUGCHECK_HOSTILE_DRIVER_LOAD;
    constexpr ULONG BUGCHECK_CANARY_FOREIGN_PT     = BUGCHECK_DMA_CANARY_HIT;
    constexpr ULONG BUGCHECK_KDBG_ENABLED_POSTINIT = BUGCHECK_KD_ENABLED_POST_INIT;

    constexpr UINT32 EVIDENCE_FAMILY_SIDECHANNEL = 0x01;
    constexpr UINT32 EVIDENCE_FAMILY_DEBUG       = 0x02;
    constexpr UINT32 EVIDENCE_FAMILY_DR          = 0x04;
    constexpr UINT32 EVIDENCE_FAMILY_HANDLE      = 0x08;
    constexpr UINT32 EVIDENCE_FAMILY_INTEGRITY   = 0x10;
    constexpr UINT32 EVIDENCE_FAMILY_DMA         = 0x20;
    constexpr UINT32 EVIDENCE_FAMILY_INJECTION   = 0x40;
    constexpr UINT32 EVIDENCE_FAMILY_TARGET      = 0x80;
    constexpr UINT32 EVIDENCE_FAMILY_KD          = 0x100;

    struct RE_EVIDENCE_BLOB {
        UINT64 magic;
        UINT32 version;
        UINT32 signal_family;
        UINT32 signal_id;
        UINT32 score;
        UINT32 pid;
        UINT32 reserved0;
        UINT64 caller_image_hash;
        UINT64 signals_bitmap_hash;
        UINT64 timestamp;
    };
    static_assert(sizeof(RE_EVIDENCE_BLOB) == 56, "RE_EVIDENCE_BLOB must be 56 bytes");
    constexpr UINT64 RE_EVIDENCE_MAGIC = 0x5645444149414941ULL;
    constexpr UINT32 RE_EVIDENCE_VERSION = 1;

    constexpr ULONG RE_REASON_GENERIC           = 0x0000DEEEu;
    constexpr ULONG RE_REASON_DEBUG_ATTACH      = 0x0000DBDBu;
    constexpr ULONG RE_REASON_DR_SET            = 0x0000D7D7u;
    constexpr ULONG RE_REASON_FOREIGN_HND       = 0x0000AD7Du;
    constexpr ULONG RE_REASON_INJECTED_DLL      = 0x0000114Du;
    constexpr ULONG RE_REASON_WATCHDOG_STALL    = 0x0000DEDDu;
    constexpr ULONG RE_REASON_PARENT_RE_TOOL    = 0x0000BA7Eu;
    constexpr ULONG RE_REASON_VAD_MAPPED_IN_RE  = 0x0000DA7Au;
    constexpr ULONG RE_REASON_TEXT_WRITABLE     = 0x0000D7ECu;
    constexpr ULONG RE_REASON_HOSTILE_DRIVER          = 0x00005E40u;
    constexpr ULONG RE_REASON_HOSTILE_DEVICE          = 0x00005E41u;
    constexpr ULONG RE_REASON_KD_ENABLED              = 0x00005E42u;
    constexpr ULONG RE_REASON_DMA_CANARY              = 0x00005E43u;
    constexpr ULONG RE_REASON_TARGET_FILE_OPENED      = 0x00007A60u;
    constexpr ULONG RE_REASON_TARGET_SECTION_MAPPED   = 0x00007A61u;
    constexpr ULONG RE_REASON_DEBUG_BY_RE_TOOL        = 0x00007A62u;
    constexpr ULONG RE_REASON_KD_TARGETING_US         = 0x00007A63u;
    constexpr ULONG RE_REASON_SIDECHANNEL_CORROBORATED = 0x0000AE03u;


    constexpr UINT64 HEARTBEAT_TIMEOUT_TSC = 60ULL * 3000000000ULL;
    constexpr UINT64 CHALLENGE_TIMEOUT_TSC = 30ULL * 3000000000ULL;
    constexpr UINT64 CHALLENGE_HMAC_KEY    = 0x7A3F1D9E5BC82A46ULL;

    inline volatile UINT64 g_bridge_crypt_key = 0;

    __forceinline void derive_bridge_key_from_whoswho(PVOID whoswho_base) {
        (void)whoswho_base;
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
        g_bridge_crypt_key = k;
    }

    __forceinline void bridge_encrypt_cmd(ULONG& cmd, ULONG& param) {
        UINT64 key = g_bridge_crypt_key;
        cmd   ^= static_cast<ULONG>(key & 0xFFFFFFFF);
        param ^= static_cast<ULONG>(key >> 32);
    }

    __forceinline void bridge_encrypt_challenge(UINT64& challenge) {
        challenge ^= _rotr64(g_bridge_crypt_key, 17);
    }

    inline volatile sentinel_bridge_t* g_bridge = nullptr;
    inline volatile UINT64             g_last_whoswho_tsc = 0;
    inline volatile UINT64             g_last_check_tsc = 0;
    inline volatile LONG               g_initialized = 0;
    inline volatile LONG               g_first_heartbeat_seen = 0;
    inline volatile ULONG              g_quorum_fail_mask = 0;
    inline volatile UINT64             g_quorum_fail_tsc = 0;

    constexpr ULONG QUORUM_FAIL_STALE   = 0x1;
    constexpr ULONG QUORUM_FAIL_CHALL   = 0x2;
    constexpr ULONG QUORUM_FAIL_MODULE  = 0x4;
    constexpr UINT64 QUORUM_WINDOW_TSC  = 90ULL * 3000000000ULL;

    __forceinline ULONG popcount32(ULONG v) {
        ULONG c = 0;
        while (v) {
            v &= (v - 1);
            c++;
        }
        return c;
    }

    __forceinline bool register_quorum_failure(ULONG bit, ULONG_PTR a, ULONG_PTR b, ULONG_PTR c) {
        UINT64 now = __rdtsc();
        UINT64 last = g_quorum_fail_tsc;
        ULONG mask = g_quorum_fail_mask;

        if (last == 0 || (now - last) > QUORUM_WINDOW_TSC) {
            mask = 0;
        }

        mask |= bit;
        g_quorum_fail_mask = mask;
        g_quorum_fail_tsc = now;

        ULONG failures = popcount32(mask);
        SN_LOG("heartbeat::quorum: bit=0x%lx mask=0x%lx failures=%lu", bit, mask, failures);

        if (failures >= 2) {
            if (_KeBugCheckEx) {
                _KeBugCheckEx(0xDEAD5E08, mask, a, b, c);
            }
            return false;
        }
        return true;
    }


    __forceinline bool locate_bridge(PVOID whoswho_base, ULONG whoswho_size) {

        SN_LOG("locate_bridge: whoswho_base=%p whoswho_size=0x%lx", whoswho_base, whoswho_size);

        if (!whoswho_base || whoswho_size == 0) {
            SN_LOG("locate_bridge: FAIL - null base or zero size");
            return false;
        }

        if (!_MmIsAddressValid(whoswho_base)) {
            SN_LOG("locate_bridge: FAIL - whoswho_base %p not valid", whoswho_base);
            return false;
        }

        PIMAGE_DOS_HEADER dos = static_cast<PIMAGE_DOS_HEADER>(whoswho_base);
        if (dos->e_magic != IMAGE_DOS_SIGNATURE) {
            SN_LOG("locate_bridge: FAIL - bad DOS sig at %p (got 0x%x)", whoswho_base, dos->e_magic);
            return false;
        }

        PIMAGE_NT_HEADERS64 nt = reinterpret_cast<PIMAGE_NT_HEADERS64>(
            static_cast<UCHAR*>(whoswho_base) + dos->e_lfanew);
        if (!_MmIsAddressValid(nt) || nt->Signature != IMAGE_NT_SIGNATURE) {
            SN_LOG("locate_bridge: FAIL - bad NT headers at %p", nt);
            return false;
        }

        PIMAGE_SECTION_HEADER sections = IMAGE_FIRST_SECTION(nt);
        SN_LOG("locate_bridge: PE valid, %u sections", nt->FileHeader.NumberOfSections);

        for (USHORT i = 0; i < nt->FileHeader.NumberOfSections; i++) {
            UCHAR* section_base = static_cast<UCHAR*>(whoswho_base) + sections[i].VirtualAddress;
            ULONG section_size = sections[i].Misc.VirtualSize;

            SN_LOG("locate_bridge: section[%u] name=%.8s base=%p size=0x%lx",
                i, sections[i].Name, section_base, section_size);

            if (section_size < sizeof(sentinel_bridge_t)) {
                SN_LOG("locate_bridge: section[%u] too small for bridge (%lu < %llu)",
                    i, section_size, (ULONGLONG)sizeof(sentinel_bridge_t));
                continue;
            }

            __try {
                ULONG magic_hits = 0;
                for (ULONG offset = 0; offset <= section_size - sizeof(sentinel_bridge_t); offset += 4) {
                    if (!_MmIsAddressValid(section_base + offset))
                        continue;

                    volatile UINT32* magic_ptr = reinterpret_cast<volatile UINT32*>(section_base + offset);
                    if (!_MmIsAddressValid(reinterpret_cast<PVOID>(const_cast<UINT32*>(magic_ptr))))
                        continue;

                    if (*magic_ptr != BRIDGE_MAGIC)
                        continue;

                    magic_hits++;
                    SN_LOG("locate_bridge: MAGIC hit at section[%u]+0x%lx (addr=%p)", i, offset, magic_ptr);

                    volatile UINT32* version_ptr = magic_ptr + 1;
                    if (!_MmIsAddressValid(reinterpret_cast<PVOID>(const_cast<UINT32*>(version_ptr)))) {
                        SN_LOG("locate_bridge: version_ptr %p not valid", version_ptr);
                        continue;
                    }

                    if (*version_ptr != BRIDGE_VERSION) {
                        SN_LOG("locate_bridge: version mismatch: got %u expected %u", *version_ptr, BRIDGE_VERSION);
                        continue;
                    }

                    volatile sentinel_bridge_t* bridge =
                        reinterpret_cast<volatile sentinel_bridge_t*>(section_base + offset);

                    if (!_MmIsAddressValid(reinterpret_cast<PVOID>(const_cast<sentinel_bridge_t*>(bridge)))) {
                        SN_LOG("locate_bridge: bridge struct at %p not valid", bridge);
                        continue;
                    }

                    PVOID cb = bridge->code_base;
                    ULONG cs = bridge->code_size;

                    SN_LOG("locate_bridge: candidate bridge at %p code_base=%p code_size=0x%lx whoswho_tsc=%lld sentinel_tsc=%lld",
                        bridge, cb, cs, bridge->whoswho_tsc, bridge->sentinel_tsc);

                    if (reinterpret_cast<ULONG_PTR>(cb) > 0xFFFF800000000000ULL &&
                        cs > 0 && cs < 10 * 1024 * 1024) {
                        g_bridge = bridge;
                        g_last_whoswho_tsc = static_cast<UINT64>(bridge->whoswho_tsc);
                        g_last_check_tsc = __rdtsc();
                        SN_LOG("locate_bridge: SUCCESS - bridge=%p tsc_now=%llu", bridge, g_last_check_tsc);
                        return true;
                    } else {
                        SN_LOG("locate_bridge: REJECTED bridge - code_base=%p code_size=0x%lx out of range", cb, cs);
                    }
                }
                if (magic_hits == 0) {
                    SN_LOG("locate_bridge: section[%u] no magic hits", i);
                }
            } __except (EXCEPTION_EXECUTE_HANDLER) {
                SN_LOG("locate_bridge: EXCEPTION in section[%u]", i);
                continue;
            }
        }

        SN_LOG("locate_bridge: FAIL - bridge not found in any section");
        return false;
    }

    __forceinline bool init(PVOID whoswho_base, ULONG whoswho_size) {
        SN_LOG("heartbeat::init: whoswho_base=%p whoswho_size=0x%lx", whoswho_base, whoswho_size);

        if (!whoswho_base || whoswho_size == 0) {
            SN_LOG("heartbeat::init: FAIL - null base or zero size");
            return false;
        }

        derive_bridge_key_from_whoswho(whoswho_base);

        if (!locate_bridge(whoswho_base, whoswho_size)) {
            SN_LOG("heartbeat::init: FAIL - locate_bridge returned false");
            return false;
        }

        _InterlockedExchange(&g_initialized, 1);
        SN_LOG("heartbeat::init: SUCCESS - g_initialized=1 g_bridge=%p", g_bridge);
        return true;
    }


    __forceinline bool update_and_check() {
        if (!_InterlockedCompareExchange(&g_initialized, 1, 1)) {
            SN_LOG("heartbeat::update_and_check: not initialized, skip");
            return true;
        }

        if (!g_bridge || !_MmIsAddressValid(reinterpret_cast<PVOID>(
                const_cast<sentinel_bridge_t*>(g_bridge)))) {
            SN_LOG("heartbeat::update_and_check: bridge %p invalid or NULL", g_bridge);
            return true;
        }

        __try {
            LONG64 now_tsc = static_cast<LONG64>(__rdtsc());
            InterlockedExchange64(
                const_cast<volatile LONG64*>(&g_bridge->sentinel_tsc), now_tsc);

            SN_LOG("heartbeat::update_and_check: wrote sentinel_tsc=%lld to bridge %p", now_tsc, g_bridge);

            UINT64 current_whoswho_tsc = static_cast<UINT64>(g_bridge->whoswho_tsc);
            UINT64 now_check = __rdtsc();

            if (!_InterlockedCompareExchange(&g_first_heartbeat_seen, 0, 0)) {
                if (current_whoswho_tsc != 0) {
                    _InterlockedExchange(&g_first_heartbeat_seen, 1);
                    g_last_whoswho_tsc = current_whoswho_tsc;
                    g_last_check_tsc = now_check;
                    SN_LOG("heartbeat::update_and_check: first WW heartbeat seen, whoswho_tsc=%llu", current_whoswho_tsc);
                } else {
                    SN_LOG("heartbeat::update_and_check: waiting for first WW heartbeat (whoswho_tsc=0)");
                }
                return true;
            }

            if (current_whoswho_tsc != g_last_whoswho_tsc) {
                SN_LOG("heartbeat::update_and_check: WW alive, tsc changed %llu -> %llu",
                    g_last_whoswho_tsc, current_whoswho_tsc);
                g_last_whoswho_tsc = current_whoswho_tsc;
                g_last_check_tsc = now_check;
                return true;
            }

            UINT64 elapsed = now_check - g_last_check_tsc;

            SN_LOG("heartbeat::update_and_check: WW STALE whoswho_tsc=%llu elapsed=%llu timeout=%llu",
                current_whoswho_tsc, elapsed, HEARTBEAT_TIMEOUT_TSC);

            if (elapsed > HEARTBEAT_TIMEOUT_TSC) {
                SN_LOG("heartbeat::update_and_check: TIMEOUT EXCEEDED - quorum fail STALE");
                return register_quorum_failure(
                    QUORUM_FAIL_STALE,
                    static_cast<ULONG_PTR>(g_last_whoswho_tsc),
                    static_cast<ULONG_PTR>(now_check),
                    static_cast<ULONG_PTR>(elapsed));
            }
        } __except (EXCEPTION_EXECUTE_HANDLER) {
            SN_LOG("heartbeat::update_and_check: EXCEPTION");
            return true;
        }

        return true;
    }

    __forceinline void send_command(ULONG cmd, ULONG param = 0) {
        if (!_InterlockedCompareExchange(&g_initialized, 1, 1))
            return;
        if (!g_bridge || !_MmIsAddressValid(reinterpret_cast<PVOID>(
                const_cast<sentinel_bridge_t*>(g_bridge))))
            return;

        __try {
            ULONG enc_cmd = cmd;
            ULONG enc_param = param;
            bridge_encrypt_cmd(enc_cmd, enc_param);
            _InterlockedExchange((volatile LONG*)&g_bridge->sentinel_cmd_param, (LONG)enc_param);
            _InterlockedExchange((volatile LONG*)&g_bridge->sentinel_cmd, (LONG)enc_cmd);
            SN_LOG("heartbeat::send_command: cmd=%lu param=0x%lx", cmd, param);
        } __except (EXCEPTION_EXECUTE_HANDLER) {
            SN_LOG("heartbeat::send_command: EXCEPTION");
        }
    }

    __forceinline UINT64 compute_expected_response(UINT64 challenge) {
        UINT64 h = challenge ^ CHALLENGE_HMAC_KEY;
        h ^= h >> 33;
        h *= 0xFF51AFD7ED558CCDULL;
        h ^= h >> 33;
        h *= 0xC4CEB9FE1A85EC53ULL;
        h ^= h >> 33;
        return h;
    }

    __forceinline void issue_challenge() {
        if (!_InterlockedCompareExchange(&g_initialized, 1, 1))
            return;
        if (!g_bridge || !_MmIsAddressValid(reinterpret_cast<PVOID>(
                const_cast<sentinel_bridge_t*>(g_bridge))))
            return;

        __try {
            UINT64 challenge = __rdtsc() ^ (static_cast<UINT64>(__rdtsc()) << 17);
            challenge |= 1;
            UINT64 enc_challenge = challenge;
            bridge_encrypt_challenge(enc_challenge);
            InterlockedExchange64(
                const_cast<volatile LONG64*>(reinterpret_cast<volatile LONG64*>(
                    &g_bridge->whoswho_response)),
                0);
            InterlockedExchange64(
                const_cast<volatile LONG64*>(reinterpret_cast<volatile LONG64*>(
                    &g_bridge->challenge_issued_tsc)),
                static_cast<LONG64>(__rdtsc()));
            InterlockedExchange64(
                const_cast<volatile LONG64*>(reinterpret_cast<volatile LONG64*>(
                    &g_bridge->sentinel_challenge)),
                static_cast<LONG64>(enc_challenge));
            SN_LOG("heartbeat::issue_challenge: challenge=0x%llx", challenge);
        } __except (EXCEPTION_EXECUTE_HANDLER) {
            SN_LOG("heartbeat::issue_challenge: EXCEPTION");
        }
    }

    inline volatile LONG g_challenge_failures = 0;
    constexpr LONG CHALLENGE_FAILURE_THRESHOLD = 3;

    __forceinline bool verify_challenge_response() {
        if (!_InterlockedCompareExchange(&g_initialized, 1, 1))
            return true;
        if (!g_bridge || !_MmIsAddressValid(reinterpret_cast<PVOID>(
                const_cast<sentinel_bridge_t*>(g_bridge))))
            return true;

        __try {
            UINT64 enc_challenge = static_cast<UINT64>(g_bridge->sentinel_challenge);
            if (enc_challenge == 0)
                return true;

            UINT64 issued_tsc = static_cast<UINT64>(g_bridge->challenge_issued_tsc);
            UINT64 now = __rdtsc();
            if (now - issued_tsc < 10ULL * 3000000000ULL)
                return true;

            UINT64 challenge = enc_challenge;
            bridge_encrypt_challenge(challenge);

            UINT64 response = static_cast<UINT64>(g_bridge->whoswho_response);
            UINT64 expected = compute_expected_response(challenge);

            if (response == expected) {
                _InterlockedExchange(&g_challenge_failures, 0);
                InterlockedExchange64(
                    const_cast<volatile LONG64*>(reinterpret_cast<volatile LONG64*>(
                        &g_bridge->sentinel_challenge)),
                    0);
                SN_LOG("heartbeat::verify_challenge: PASS");
                return true;
            }

            if (now - issued_tsc > CHALLENGE_TIMEOUT_TSC) {
                LONG fails = _InterlockedIncrement(&g_challenge_failures);
                SN_LOG("heartbeat::verify_challenge: TIMEOUT fails=%ld response=0x%llx expected=0x%llx",
                    fails, response, expected);

                if (fails >= CHALLENGE_FAILURE_THRESHOLD) {
                    SN_LOG("heartbeat::verify_challenge: quorum fail CHALLENGE failures=%ld", fails);
                    return register_quorum_failure(
                        QUORUM_FAIL_CHALL,
                        static_cast<ULONG_PTR>(challenge),
                        static_cast<ULONG_PTR>(response),
                        static_cast<ULONG_PTR>(fails));
                }

                InterlockedExchange64(
                    const_cast<volatile LONG64*>(reinterpret_cast<volatile LONG64*>(
                        &g_bridge->sentinel_challenge)),
                    0);
            }
        } __except (EXCEPTION_EXECUTE_HANDLER) {
            SN_LOG("heartbeat::verify_challenge: EXCEPTION");
        }
        return true;
    }

    __forceinline bool verify_module_presence() {
        if (!g_target_driver_base || !g_sentinel_driver_object)
            return true;

        if (!_MmIsAddressValid(g_sentinel_driver_object) ||
            !g_sentinel_driver_object->DriverSection ||
            !_MmIsAddressValid(g_sentinel_driver_object->DriverSection))
            return true;

        PLDR_DATA_TABLE_ENTRY sentinel_ldr = static_cast<PLDR_DATA_TABLE_ENTRY>(
            g_sentinel_driver_object->DriverSection);
        PLIST_ENTRY list_head = &sentinel_ldr->InLoadOrderModuleList;

        __try {
            PLIST_ENTRY entry = list_head->Flink;
            ULONG safety = 512;

            while (entry && entry != list_head && safety-- > 0) {
                if (!_MmIsAddressValid(entry))
                    break;

                PLDR_DATA_TABLE_ENTRY mod = CONTAINING_RECORD(
                    entry, LDR_DATA_TABLE_ENTRY, InLoadOrderModuleList);

                if (_MmIsAddressValid(mod) && mod->DllBase == (PVOID)g_target_driver_base)
                    return true;

                entry = entry->Flink;
            }
        } __except (EXCEPTION_EXECUTE_HANDLER) {
            return true;
        }

        SN_LOG("heartbeat::verify_module_presence: target module %p NOT FOUND in module list",
            (PVOID)g_target_driver_base);

        if (g_target_driver_base && g_target_driver_size) {
            if (locate_bridge((PVOID)g_target_driver_base, g_target_driver_size)) {
                SN_LOG("heartbeat::verify_module_presence: bridge re-discovered in target module");
                return true;
            }
        }

        if (!register_quorum_failure(
            QUORUM_FAIL_MODULE,
            reinterpret_cast<ULONG_PTR>(g_target_driver_base),
            static_cast<ULONG_PTR>(g_target_driver_size),
            0)) {
            return false;
        }
        return false;
    }
}
