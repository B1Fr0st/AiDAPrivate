#pragma once
#include "KernelCrypto.h"


namespace sentinel_bridge {


    constexpr ULONG BRIDGE_MAGIC   = 0x57484F53;
    constexpr ULONG BRIDGE_VERSION = 1;


    constexpr ULONG BUGCHECK_SENTINEL_ABSENT = 0xDEAD5E10;

    constexpr ULONG BUGCHECK_RE_USERMODE_CONFIRMED = 0xDEAD0002u;
    constexpr ULONG BUGCHECK_HOSTILE_DRIVER_LOAD   = 0xDEAD5E40u;
    constexpr ULONG BUGCHECK_HOSTILE_DEVICE_OBJECT = 0xDEAD5E41u;
    constexpr ULONG BUGCHECK_KD_ENABLED_POST_INIT  = 0xDEAD5E42u;
    constexpr ULONG BUGCHECK_RE_TARGETING_CONFIRMED = 0xDEADDEADu;
    constexpr ULONG BUGCHECK_DMA_CANARY_HIT        = 0xDEAD5E43u;
    constexpr ULONG BUGCHECK_SENTINEL_THREAD_INJECT= 0xDEAD5E44u;
    constexpr ULONG BUGCHECK_TARGET_FILE_SCANNED   = 0xDEAD7A60u;
    constexpr ULONG BUGCHECK_DEBUG_BY_RE_TOOL      = 0xDEAD7A62u;
    constexpr ULONG BUGCHECK_KD_TARGETING_US       = 0xDEAD7A63u;
    constexpr ULONG BUGCHECK_IOMMU_DISABLED        = 0xDEAD7A70u;

    constexpr ULONG BUGCHECK_TIER_A_DRIVER_LOADED  = BUGCHECK_HOSTILE_DRIVER_LOAD;
    constexpr ULONG BUGCHECK_CANARY_FOREIGN_PT     = BUGCHECK_DMA_CANARY_HIT;
    constexpr ULONG BUGCHECK_KDBG_ENABLED_POSTINIT = BUGCHECK_KD_ENABLED_POST_INIT;

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
    constexpr ULONG BRIDGE_CMD_RE_CONFIRMED_USERMODE = 17;
    constexpr ULONG BRIDGE_CMD_SENTINEL_THREAD_INJECT = 18;
    constexpr ULONG BRIDGE_CMD_LATCH_TARGETING        = 19;

    constexpr ULONG BRIDGE_CMD_DMA_KEY_SCRUB        = 0x0000B001u;
    constexpr ULONG BRIDGE_CMD_DMA_BSOD             = 0x0000B003u;
    constexpr ULONG BRIDGE_CMD_DMA_ATTACK_REPORT    = 0x0000B004u;

    constexpr ULONG BRIDGE_CMD_HONEYPOT_CANARY_PATCH     = 0x0000C001u;
    constexpr ULONG BRIDGE_CMD_HONEYPOT_STRING_ACCESS    = 0x0000C002u;
    constexpr ULONG BRIDGE_CMD_REGISTER_HONEYPOT_PID     = 0x0000C003u;
    constexpr ULONG BRIDGE_CMD_REGISTER_HONEYPOT_GUARD   = 0x0000C004u;

    constexpr ULONG BRIDGE_CMD_UPDATE_CE_HASHES          = 0x0000D001u;

    constexpr ULONG BUGCHECK_HONEYPOT_STRING_ACCESS = 0xA1DA0001u;
    constexpr ULONG BUGCHECK_HONEYPOT_CANARY_PATCH  = 0xA1DA0002u;

    inline volatile HANDLE g_aida_pid = nullptr;
    inline PVOID g_honeypot_guard_page_base = nullptr;
    inline SIZE_T g_honeypot_guard_page_size = 0;

    inline const wchar_t* g_av_allowlist[] = {
        L"MsMpEng.exe",
        L"MpCopyAccelerator.exe",
        L"NisSrv.exe",
        L"SearchIndexer.exe",
        L"SearchProtocolHandler.exe",
        L"TiWorker.exe",
        L"CompatTelRunner.exe",
        L"WerFault.exe",
    };
    constexpr SIZE_T g_av_allowlist_count = sizeof(g_av_allowlist) / sizeof(g_av_allowlist[0]);

    __forceinline BOOLEAN is_av_allowlisted_process(HANDLE pid)
    {
        PEPROCESS process = NULL;
        NTSTATUS status = PsLookupProcessByProcessId(pid, &process);
        if (!NT_SUCCESS(status) || process == NULL)
            return FALSE;

        PUNICODE_STRING image_name = NULL;
        SeQueryInformationProcess(process, ProcessImageFileName, &image_name);

        BOOLEAN allowed = FALSE;
        if (image_name != NULL && image_name->Buffer != NULL) {
            PWSTR filename = image_name->Buffer;
            USHORT char_count = image_name->Length / sizeof(WCHAR);
            for (SHORT i = char_count - 1; i >= 0; --i) {
                if (image_name->Buffer[i] == L'\\') {
                    filename = &image_name->Buffer[i + 1];
                    break;
                }
            }

            UNICODE_STRING fname_u;
            RtlInitUnicodeString(&fname_u, filename);

            for (SIZE_T i = 0; i < g_av_allowlist_count; ++i) {
                UNICODE_STRING allowlist_u;
                RtlInitUnicodeString(&allowlist_u, g_av_allowlist[i]);
                if (RtlEqualUnicodeString(&fname_u, &allowlist_u, TRUE)) {
                    allowed = TRUE;
                    break;
                }
            }
            ExFreePool(image_name);
        }
        ObDereferenceObject(process);
        return allowed;
    }

    __forceinline VOID handle_honeypot_guard_page_access(
        UINT64 rip, UINT64 accessed_addr)
    {
        HANDLE accessing_pid = PsGetCurrentProcessId();

        if (accessing_pid == g_aida_pid) {
            WW_LOG("honeypot_guard: internal access rip=0x%llx addr=0x%llx pid=%p (allowed)",
                rip, accessed_addr, accessing_pid);
            return;
        }

        if (is_av_allowlisted_process(accessing_pid)) {
            WW_LOG("honeypot_guard: av_allowlisted access rip=0x%llx addr=0x%llx pid=%p (allowed)",
                rip, accessed_addr, accessing_pid);
            return;
        }

        WW_LOG("honeypot_guard: EXTERNAL access rip=0x%llx addr=0x%llx pid=%p -> BUGCHECK 0x%lx",
            rip, accessed_addr, accessing_pid, BUGCHECK_HONEYPOT_STRING_ACCESS);
        if (_KeBugCheckEx)
            _KeBugCheckEx(BUGCHECK_HONEYPOT_STRING_ACCESS,
                (ULONG_PTR)rip, (ULONG_PTR)accessed_addr,
                (ULONG_PTR)accessing_pid, 0);
    }

    constexpr ULONG BRIDGE_CMD_TIER_A_DRIVER_PRESENT = BRIDGE_CMD_HOSTILE_DRIVER;
    constexpr ULONG BRIDGE_CMD_KDBG_TRANSITION       = BRIDGE_CMD_KD_ENABLED;
    constexpr ULONG BRIDGE_CMD_CANARY_FOREIGN_PT     = BRIDGE_CMD_DMA_CANARY_HIT;
    constexpr ULONG BRIDGE_CMD_DEVICE_OBJECT_HIT     = BRIDGE_CMD_HOSTILE_DEVICE;

    constexpr ULONG RE_REASON_GENERIC       = 0x0000DEEEu;
    constexpr ULONG RE_REASON_DEBUG_ATTACH  = 0x0000DBDBu;
    constexpr ULONG RE_REASON_DR_SET        = 0x0000D7D7u;
    constexpr ULONG RE_REASON_FOREIGN_HND   = 0x0000AD7Du;
    constexpr ULONG RE_REASON_INJECTED_DLL  = 0x0000114Du;
    constexpr ULONG RE_REASON_WATCHDOG_STALL= 0x0000DEDDu;
    constexpr ULONG RE_REASON_PARENT_RE_TOOL   = 0x0000BA7Eu;
    constexpr ULONG RE_REASON_VAD_MAPPED_IN_RE = 0x0000DA7Au;
    constexpr ULONG RE_REASON_TEXT_WRITABLE    = 0x0000D7ECu;
    constexpr ULONG RE_REASON_HOSTILE_DRIVER          = 0x00005E40u;
    constexpr ULONG RE_REASON_HOSTILE_DEVICE          = 0x00005E41u;
    constexpr ULONG RE_REASON_KD_ENABLED              = 0x00005E42u;
    constexpr ULONG RE_REASON_DMA_CANARY              = 0x00005E43u;
    constexpr ULONG RE_REASON_TARGET_FILE_OPENED      = 0x00007A60u;
    constexpr ULONG RE_REASON_TARGET_SECTION_MAPPED   = 0x00007A61u;
    constexpr ULONG RE_REASON_DEBUG_BY_RE_TOOL        = 0x00007A62u;
    constexpr ULONG RE_REASON_KD_TARGETING_US         = 0x00007A63u;
    constexpr ULONG RE_REASON_OB_WRITE                 = 0x0000AB01u;
    constexpr ULONG RE_REASON_OB_CREATE_THREAD         = 0x0000AB02u;
    constexpr ULONG RE_REASON_OB_SUSPEND               = 0x0000AB03u;
    constexpr ULONG RE_REASON_DEBUG_PORT_TRAP           = 0x0000AB04u;
    constexpr ULONG RE_REASON_DR_ON_TEXT               = RE_REASON_DR_SET;
    constexpr ULONG RE_REASON_SIDECHANNEL_CORROBORATED = 0x0000AE03u;
    constexpr ULONG RE_REASON_SELF_ANALYSIS_ATTEMPT    = 0x0000AE40u;

    constexpr ULONG RE_REASON_DMA_IOMMU_BYPASS      = 0x00005E44u;
    constexpr ULONG RE_REASON_DMA_UNKNOWN_PCIE      = 0x00005E45u;
    constexpr ULONG RE_REASON_DMA_EPT_HOOK          = 0x00005E46u;
    constexpr ULONG RE_REASON_DMA_PTE_TAMPER        = 0x00005E47u;
    constexpr ULONG RE_REASON_DMA_KEY_SCRUB         = 0x00005E48u;

    constexpr UINT32 EVIDENCE_FAMILY_SIDECHANNEL = 0x01u;
    constexpr UINT32 EVIDENCE_FAMILY_DEBUG       = 0x02u;
    constexpr UINT32 EVIDENCE_FAMILY_DR          = 0x04u;
    constexpr UINT32 EVIDENCE_FAMILY_HANDLE      = 0x08u;
    constexpr UINT32 EVIDENCE_FAMILY_INTEGRITY   = 0x10u;
    constexpr UINT32 EVIDENCE_FAMILY_DMA         = 0x20u;
    constexpr UINT32 EVIDENCE_FAMILY_INJECTION   = 0x40u;
    constexpr UINT32 EVIDENCE_FAMILY_TARGET      = 0x80u;
    constexpr UINT32 EVIDENCE_FAMILY_KD          = 0x100u;

    constexpr UINT32 EVIDENCE_FAMILY_DMA_IOMMU    = 0x44u;
    constexpr UINT32 EVIDENCE_FAMILY_DMA_PCIE     = 0x45u;
    constexpr UINT32 EVIDENCE_FAMILY_DMA_EPT      = 0x46u;
    constexpr UINT32 EVIDENCE_FAMILY_DMA_PTE      = 0x47u;

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
        volatile UINT64  challenge_counter;
        volatile UINT8   challenge_tag[16];
        volatile LONG64  protected_pid;
        volatile UINT8   sentinel_dispatch_hook_detected;
        UINT8            _pad_dh[7];
        volatile UINT64  sentinel_dispatch_hook_target;
        volatile UINT8   sentinel_hostile_drivers;
        volatile UINT8   sentinel_modified_callbacks;
        UINT8            _pad_cb[6];
        volatile UINT64  whoswho_challenge;
        volatile UINT64  sentinel_response;
        volatile UINT8   expected_watermark[16];
        volatile UINT8   actual_watermark[16];
        volatile UINT8   watermark_verified;
        volatile UINT32  watermark_rva;
        UINT8            _pad_wm[3];
        volatile UINT8   ce_driver_hash_data[32 * 32];
        volatile UINT32  ce_driver_hash_count;
        UINT8            _pad_ce[4];
    };


    constexpr ULONG BRIDGE_VERSION_2 = 2;

    struct bridge_v2_t {
        bridge_t          v1;
        volatile UINT64   crypto_nonce;
        volatile UINT8    hmac[32];
        volatile UINT64   nonce_tsc;
        volatile UINT32   hmac_valid;
        volatile UINT32   _pad;
    };


    inline bridge_v2_t g_bridge_v2 = {
        {
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
            0,
            0,
            {0},
            0,
            0,
            {0},
            0,
            0,
            {0},
            0,
            0,
            0,
            {0},
            {0},
            0,
            0,
            {0},
            {0},
            0,
            {0}
        },
        0,
        {0},
        0,
        0,
        0
    };


    inline bridge_t& g_bridge = g_bridge_v2.v1;

    inline volatile UINT64 g_bridge_crypt_key = 0;
    inline UINT8 g_challenge_aes_key[kernel_crypto::AES256_KEY_SIZE]    = {};
    inline UINT8 g_challenge_hmac_key[kernel_crypto::SHA256_DIGEST_SIZE] = {};
    inline volatile LONG g_challenge_keys_valid = 0;
    inline volatile LONG64 g_last_seen_challenge_counter = 0;

    __forceinline void log_watchdog_bugcheck_intent(const char* path,
                                                    ULONG code,
                                                    ULONG cmd,
                                                    ULONG param,
                                                    ULONG raw_cmd,
                                                    ULONG raw_param,
                                                    LONG64 sentinel_tsc,
                                                    LONG64 last_tsc,
                                                    LONG64 elapsed)
    {
        WW_LOG("watchdog_dpc: BUGCHECK_INTENT path=%s code=0x%lx cmd=%lu param=0x%lx raw_cmd=0x%lx raw_param=0x%lx bridge=%p sentinel_tsc=%lld last=%lld elapsed=%lld",
            path ? path : "unknown",
            code,
            cmd,
            param,
            raw_cmd,
            raw_param,
            &g_bridge,
            sentinel_tsc,
            last_tsc,
            elapsed);
    }

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

    __forceinline void derive_challenge_subkeys() {
        UINT8 root[kernel_crypto::AES256_KEY_SIZE];
        UINT64 root_seed[4];
        root_seed[0] = g_bridge_crypt_key;
        root_seed[1] = g_bridge_crypt_key ^ 0x9E3779B97F4A7C15ULL;
        root_seed[2] = g_bridge_crypt_key * 0xBF58476D1CE4E5B9ULL;
        root_seed[3] = g_bridge_crypt_key ^ 0x94D049BB133111EBULL;
        RtlCopyMemory(root, root_seed, sizeof(root));

        const UINT8 aes_label[]  = { 'a','i','d','a','-','b','r','i','d','g','e','-','a','e','s' };
        const UINT8 hmac_label[] = { 'a','i','d','a','-','b','r','i','d','g','e','-','m','a','c' };

        kernel_crypto::sw_hkdf_sha256(
            nullptr, 0,
            root, sizeof(root),
            aes_label, sizeof(aes_label),
            g_challenge_aes_key, kernel_crypto::AES256_KEY_SIZE);
        kernel_crypto::sw_hkdf_sha256(
            nullptr, 0,
            root, sizeof(root),
            hmac_label, sizeof(hmac_label),
            g_challenge_hmac_key, kernel_crypto::SHA256_DIGEST_SIZE);

        RtlSecureZeroMemory(root, sizeof(root));
        RtlSecureZeroMemory(root_seed, sizeof(root_seed));
        _InterlockedExchange(&g_challenge_keys_valid, 1);
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

    __forceinline void build_challenge_nonce(UINT64 counter, UINT8 nonce_out[kernel_crypto::GCM_NONCE_SIZE]) {
        for (ULONG i = 0; i < kernel_crypto::GCM_NONCE_SIZE; ++i) nonce_out[i] = 0;
        for (ULONG i = 0; i < 8; ++i)
            nonce_out[i] = static_cast<UINT8>((counter >> (i * 8)) & 0xFFu);
        nonce_out[8]  = 0xA1u;
        nonce_out[9]  = 0xDAu;
        nonce_out[10] = 0xB7u;
        nonce_out[11] = 0x53u;
    }

    __forceinline BOOLEAN bridge_decrypt_challenge_gcm(
        UINT64 ciphertext_in,
        UINT64 counter,
        const UINT8 tag_in[kernel_crypto::GCM_TAG_SIZE],
        UINT64& plaintext_out)
    {
        if (_InterlockedCompareExchange(&g_challenge_keys_valid, 0, 0) == 0)
            return FALSE;

        UINT8 nonce[kernel_crypto::GCM_NONCE_SIZE];
        build_challenge_nonce(counter, nonce);

        UINT8 aad[16];
        RtlCopyMemory(aad + 0, &counter, 8);
        UINT64 magic = 0x57484F535F47434DULL;
        RtlCopyMemory(aad + 8, &magic, 8);

        UINT8 ct[8];
        RtlCopyMemory(ct, &ciphertext_in, 8);

        UINT8 pt[8];
        BOOLEAN ok = kernel_crypto::sw_aes256_gcm_decrypt(
            g_challenge_aes_key, nonce,
            aad, sizeof(aad),
            ct, 8,
            tag_in,
            pt);
        if (ok) {
            RtlCopyMemory(&plaintext_out, pt, 8);
        }
        RtlSecureZeroMemory(nonce, sizeof(nonce));
        RtlSecureZeroMemory(pt,    sizeof(pt));
        RtlSecureZeroMemory(ct,    sizeof(ct));
        return ok;
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
        UINT8 mac[kernel_crypto::SHA256_DIGEST_SIZE];
        UINT8 in[8];
        RtlCopyMemory(in, &challenge, 8);
        kernel_crypto::sw_hmac_sha256(
            g_challenge_hmac_key, kernel_crypto::SHA256_DIGEST_SIZE,
            in, 8,
            mac);
        UINT64 result;
        RtlCopyMemory(&result, mac, 8);
        RtlSecureZeroMemory(mac, sizeof(mac));
        RtlSecureZeroMemory(in,  sizeof(in));
        return result;
    }

    inline volatile UINT64 g_reverse_challenge_value       = 0;
    inline volatile UINT64 g_reverse_challenge_issued_tsc  = 0;
    inline volatile LONG64 g_last_verified_reverse_challenge = 0;
    inline volatile LONG   g_reverse_challenge_failures    = 0;

    __forceinline void compute_reverse_challenge() {
        if (_InterlockedCompareExchange(&g_challenge_keys_valid, 0, 0) == 0)
            return;

        UINT64 existing_challenge = static_cast<UINT64>(
            _InterlockedCompareExchange64(
                reinterpret_cast<volatile LONG64*>(&g_bridge.whoswho_challenge), 0, 0));
        if (existing_challenge != 0)
            return;

        UINT64 challenge = __rdtsc() ^ (static_cast<UINT64>(__rdtsc()) << 17);
        challenge |= 1;

        _InterlockedExchange64(
            reinterpret_cast<volatile LONG64*>(&g_bridge.sentinel_response), 0);
        _InterlockedExchange64(
            reinterpret_cast<volatile LONG64*>(&g_bridge.whoswho_challenge),
            static_cast<LONG64>(challenge));

        g_reverse_challenge_value = challenge;
        g_reverse_challenge_issued_tsc = __rdtsc();

        WW_LOG("compute_reverse_challenge: issued challenge=0x%llx", challenge);
    }

    __forceinline BOOLEAN verify_sentinel_response() {
        UINT64 challenge = static_cast<UINT64>(
            _InterlockedCompareExchange64(
                reinterpret_cast<volatile LONG64*>(&g_bridge.whoswho_challenge), 0, 0));
        if (challenge == 0)
            return TRUE;

        UINT64 response = static_cast<UINT64>(
            _InterlockedCompareExchange64(
                reinterpret_cast<volatile LONG64*>(&g_bridge.sentinel_response), 0, 0));
        if (response == 0) {
            UINT64 issued_tsc = g_reverse_challenge_issued_tsc;
            UINT64 now = __rdtsc();
            if (now - issued_tsc > 30ULL * 3000000000ULL) {
                WW_LOG("verify_sentinel_response: TIMEOUT challenge=0x%llx no response",
                    challenge);
                return FALSE;
            }
            return TRUE;
        }

        UINT64 expected = compute_challenge_response(challenge);
        if (response != expected) {
            WW_LOG("verify_sentinel_response: FAIL challenge=0x%llx response=0x%llx expected=0x%llx",
                challenge, response, expected);
            _InterlockedExchange64(
                reinterpret_cast<volatile LONG64*>(&g_bridge.whoswho_challenge), 0);
            _InterlockedExchange64(
                reinterpret_cast<volatile LONG64*>(&g_bridge.sentinel_response), 0);
            return FALSE;
        }

        _InterlockedExchange64(&g_last_verified_reverse_challenge,
            static_cast<LONG64>(challenge));
        _InterlockedExchange64(
            reinterpret_cast<volatile LONG64*>(&g_bridge.whoswho_challenge), 0);
        _InterlockedExchange64(
            reinterpret_cast<volatile LONG64*>(&g_bridge.sentinel_response), 0);
        g_reverse_challenge_value = 0;

        WW_LOG("verify_sentinel_response: PASS challenge=0x%llx", challenge);
        return TRUE;
    }

    namespace evidence_accumulator {
        constexpr ULONG MAX_ENTRIES = 32;
        constexpr UINT64 WINDOW_TSC = 60ULL * 3000000000ULL;
        constexpr ULONG REQUIRED_FAMILIES = 3;

        struct entry_t {
            ULONG reason;
            UINT32 family;
            UINT64 tsc;
        };

        inline entry_t g_entries[MAX_ENTRIES] = {};
        inline volatile LONG g_entry_count = 0;

        __forceinline UINT32 classify_family(ULONG reason) {
            if (reason == RE_REASON_SELF_ANALYSIS_ATTEMPT) return EVIDENCE_FAMILY_TARGET;
            if (reason >= 0xAE00 && reason <= 0xAEFF) return EVIDENCE_FAMILY_SIDECHANNEL;
            if (reason == RE_REASON_TARGET_FILE_OPENED)    return EVIDENCE_FAMILY_TARGET;
            if (reason == RE_REASON_TARGET_SECTION_MAPPED) return EVIDENCE_FAMILY_TARGET;
            if (reason == RE_REASON_DEBUG_BY_RE_TOOL)      return EVIDENCE_FAMILY_DEBUG;
            if (reason == RE_REASON_KD_TARGETING_US)       return EVIDENCE_FAMILY_KD;
            if (reason == RE_REASON_DEBUG_ATTACH)          return EVIDENCE_FAMILY_DEBUG;
            if (reason == RE_REASON_DR_SET)                return EVIDENCE_FAMILY_DR;
            if (reason == RE_REASON_FOREIGN_HND)           return EVIDENCE_FAMILY_HANDLE;
            if (reason == RE_REASON_INJECTED_DLL)          return EVIDENCE_FAMILY_INJECTION;
            if (reason == RE_REASON_TEXT_WRITABLE)          return EVIDENCE_FAMILY_INTEGRITY;
            if (reason == RE_REASON_WATCHDOG_STALL)        return EVIDENCE_FAMILY_SIDECHANNEL;
            if (reason == RE_REASON_PARENT_RE_TOOL)        return EVIDENCE_FAMILY_TARGET;
            if (reason == RE_REASON_VAD_MAPPED_IN_RE)      return EVIDENCE_FAMILY_TARGET;
            if (reason == RE_REASON_DMA_CANARY)            return EVIDENCE_FAMILY_DMA;
            if (reason == RE_REASON_DMA_IOMMU_BYPASS)      return EVIDENCE_FAMILY_DMA;
            if (reason == RE_REASON_DMA_UNKNOWN_PCIE)      return EVIDENCE_FAMILY_DMA;
            if (reason == RE_REASON_DMA_EPT_HOOK)          return EVIDENCE_FAMILY_DMA;
            if (reason == RE_REASON_DMA_PTE_TAMPER)        return EVIDENCE_FAMILY_DMA;
            if (reason == RE_REASON_DMA_KEY_SCRUB)         return EVIDENCE_FAMILY_DMA;
            if (reason == RE_REASON_KD_ENABLED)            return EVIDENCE_FAMILY_KD;
            return 0;
        }

        __forceinline bool is_direct_bsod_reason(ULONG reason) {
            return reason == RE_REASON_DEBUG_BY_RE_TOOL
                || reason == RE_REASON_DMA_CANARY
                || reason == RE_REASON_SELF_ANALYSIS_ATTEMPT;
        }

        __forceinline ULONG popcount32(UINT32 v) {
            ULONG c = 0;
            while (v) { v &= (v - 1); c++; }
            return c;
        }

        __forceinline UINT32 active_family_mask() {
            UINT64 now = __rdtsc();
            UINT32 families_present = 0;
            LONG count = _InterlockedCompareExchange(&g_entry_count, 0, 0);

            for (LONG i = 0; i < count && i < MAX_ENTRIES; i++) {
                if ((now - g_entries[i].tsc) > WINDOW_TSC)
                    continue;
                families_present |= g_entries[i].family;
            }

            return families_present;
        }

        __forceinline void add_evidence(ULONG reason) {
            UINT64 now = __rdtsc();
            UINT32 family = classify_family(reason);

            LONG count = _InterlockedCompareExchange(&g_entry_count, 0, 0);
            for (LONG i = 0; i < count && i < MAX_ENTRIES; i++) {
                if (g_entries[i].reason == reason) {
                    UINT32 active = active_family_mask();
                    UINT32 non_sc = active & ~EVIDENCE_FAMILY_SIDECHANNEL;
                    WW_LOG("evidence_accumulator: duplicate reason=0x%lx family=0x%lx active=0x%lx non_sc=0x%lx quorum=%lu/%lu decision=observe",
                        reason,
                        family,
                        active,
                        non_sc,
                        popcount32(active),
                        REQUIRED_FAMILIES);
                    return;
                }
            }

            LONG idx = _InterlockedIncrement(&g_entry_count) - 1;
            if (idx >= MAX_ENTRIES) {
                _InterlockedDecrement(&g_entry_count);
                WW_LOG("evidence_accumulator: full reason=0x%lx family=0x%lx decision=observe", reason, family);
                return;
            }

            g_entries[idx].reason = reason;
            g_entries[idx].family = family;
            g_entries[idx].tsc = now;
            UINT32 active = active_family_mask();
            UINT32 non_sc = active & ~EVIDENCE_FAMILY_SIDECHANNEL;
            ULONG family_count = popcount32(active);
            WW_LOG("evidence_accumulator: add reason=0x%lx family=0x%lx active=0x%lx non_sc=0x%lx quorum=%lu/%lu sidechannel_only=%d decision=%s",
                reason,
                family,
                active,
                non_sc,
                family_count,
                REQUIRED_FAMILIES,
                non_sc == 0 ? 1 : 0,
                (non_sc != 0 && family_count >= REQUIRED_FAMILIES) ? "deny" : "observe");
        }

        __forceinline bool should_bugcheck() {
            UINT32 families_present = active_family_mask();
            UINT32 non_sc = families_present & ~EVIDENCE_FAMILY_SIDECHANNEL;
            if (non_sc == 0)
                return false;

            ULONG family_count = popcount32(families_present);
            return family_count >= REQUIRED_FAMILIES;
        }
    }


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


        volatile UINT8 diff = 0;
        for (int i = 0; i < 32; i++)
            diff |= expected[i] ^ g_bridge_v2.hmac[i];

        return (diff == 0) ? TRUE : FALSE;
    }

    __forceinline void tick() {
        LONG64 tsc = static_cast<LONG64>(__rdtsc());
        _InterlockedExchange64(&g_bridge.whoswho_tsc, tsc);

        UINT64 raw_challenge = g_bridge.sentinel_challenge;
        UINT64 issued_counter = static_cast<UINT64>(g_bridge.challenge_counter);
        UINT64 last_seen = static_cast<UINT64>(_InterlockedCompareExchange64(
            &g_last_seen_challenge_counter, 0, 0));
        BOOLEAN challenge_seen = raw_challenge != 0 ? TRUE : FALSE;
        BOOLEAN challenge_candidate = FALSE;
        BOOLEAN challenge_response_written = FALSE;
        BOOLEAN challenge_decrypt_failed = FALSE;

        if (raw_challenge != 0 &&
            issued_counter > last_seen &&
            g_bridge.whoswho_response == 0 &&
            _InterlockedCompareExchange(&g_challenge_keys_valid, 0, 0) != 0)
        {
            challenge_candidate = TRUE;
            UINT8 tag[kernel_crypto::GCM_TAG_SIZE];
            for (ULONG i = 0; i < kernel_crypto::GCM_TAG_SIZE; ++i)
                tag[i] = g_bridge.challenge_tag[i];

            UINT64 plaintext = 0;
            BOOLEAN ok = bridge_decrypt_challenge_gcm(raw_challenge, issued_counter, tag, plaintext);
            RtlSecureZeroMemory(tag, sizeof(tag));

            if (ok && plaintext != 0) {
                UINT64 response = compute_challenge_response(plaintext);
                InterlockedExchange64(
                    reinterpret_cast<volatile LONG64*>(&g_bridge.whoswho_response),
                    static_cast<LONG64>(response));
                _InterlockedExchange64(
                    &g_last_seen_challenge_counter,
                    static_cast<LONG64>(issued_counter));
                challenge_response_written = TRUE;
            } else {
                challenge_decrypt_failed = TRUE;
            }
        }


        compute_reverse_challenge();
        if (!verify_sentinel_response()) {
            LONG fails = _InterlockedIncrement(&g_reverse_challenge_failures);
            WW_LOG("tick: reverse challenge FAILED fails=%ld challenge=0x%llx response=0x%llx -> BUGCHECK 0xDEAD5E08",
                fails,
                static_cast<unsigned long long>(g_reverse_challenge_value),
                static_cast<unsigned long long>(g_bridge.sentinel_response));
            if (_KeBugCheckEx)
                _KeBugCheckEx(0xDEAD5E08,
                    static_cast<ULONG_PTR>(g_reverse_challenge_value),
                    static_cast<ULONG_PTR>(g_bridge.sentinel_response),
                    static_cast<ULONG_PTR>(g_bridge.whoswho_challenge),
                    2);
        }

        rotate_bridge_nonce();

        if (challenge_response_written || challenge_decrypt_failed) {
            WW_LOG("tick: challenge whoswho_tsc=%lld sentinel_tsc=%lld challenge=%u candidate=%u response=%u decrypt_failed=%u counter=%llu last_seen=%llu bridge=%p keys_valid=%ld hmac_valid=%u",
                tsc,
                g_bridge.sentinel_tsc,
                challenge_seen ? 1u : 0u,
                challenge_candidate ? 1u : 0u,
                challenge_response_written ? 1u : 0u,
                challenge_decrypt_failed ? 1u : 0u,
                issued_counter,
                last_seen,
                &g_bridge,
                _InterlockedCompareExchange(&g_challenge_keys_valid, 0, 0),
                g_bridge_v2.hmac_valid ? 1u : 0u);
        }
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

        if (elapsed < GRACE_TSC) {
            ULONG queued_raw_cmd = static_cast<ULONG>(_InterlockedCompareExchange(
                reinterpret_cast<volatile LONG*>(&g_bridge.sentinel_cmd), 0, 0));
            ULONG queued_raw_param = static_cast<ULONG>(_InterlockedCompareExchange(
                reinterpret_cast<volatile LONG*>(&g_bridge.sentinel_cmd_param), 0, 0));
            if (queued_raw_cmd != 0) {
                ULONG queued_cmd = 0;
                ULONG queued_param = 0;
                bridge_decrypt_cmd(queued_raw_cmd, queued_raw_param, queued_cmd, queued_param);
                WW_LOG("watchdog_dpc: grace queued command raw_cmd=0x%lx raw_param=0x%lx cmd=%lu param=0x%lx key=0x%llx",
                    queued_raw_cmd,
                    queued_raw_param,
                    queued_cmd,
                    queued_param,
                    static_cast<unsigned long long>(g_bridge_crypt_key));
            }
            return;
        }

        LONG64 current_sentinel_tsc = _InterlockedCompareExchange64(
            &g_bridge.sentinel_tsc, 0, 0);

        LONG64 last = _InterlockedCompareExchange64(
            &g_last_seen_sentinel_tsc, 0, 0);

        if (current_sentinel_tsc != last) {
            _InterlockedExchange64(&g_last_seen_sentinel_tsc, current_sentinel_tsc);
            _InterlockedExchange(&g_stale_streak, 0);

            ULONG raw_cmd = _InterlockedExchange((volatile LONG*)&g_bridge.sentinel_cmd, BRIDGE_CMD_NONE);
            ULONG raw_param = _InterlockedExchange((volatile LONG*)&g_bridge.sentinel_cmd_param, 0);
            if (raw_cmd != 0) {
                ULONG cmd = 0, param = 0;
                bridge_decrypt_cmd(raw_cmd, raw_param, cmd, param);
                WW_LOG("watchdog_dpc: raw command raw_cmd=0x%lx raw_param=0x%lx cmd=%lu param=0x%lx key=0x%llx",
                    raw_cmd,
                    raw_param,
                    cmd,
                    param,
                    static_cast<unsigned long long>(g_bridge_crypt_key));
                if (cmd != BRIDGE_CMD_NONE) {
                    WW_LOG("watchdog_dpc: Sentinel command=%lu param=0x%lx", cmd, param);

                    if (cmd == BRIDGE_CMD_DMA_CANARY_HIT) {
                        WW_LOG("watchdog_dpc: BUGCHECK_DMA_CANARY_HIT code=0x%lx cmd=%lu param_pid=%lu raw_cmd=0x%lx raw_param=0x%lx bridge=%p sentinel_tsc=%lld last=%lld elapsed=%lld",
                            BUGCHECK_DMA_CANARY_HIT,
                            cmd,
                            param,
                            raw_cmd,
                            raw_param,
                            &g_bridge,
                            current_sentinel_tsc,
                            last,
                            elapsed);
                        log_watchdog_bugcheck_intent("dma_canary",
                            BUGCHECK_DMA_CANARY_HIT,
                            cmd,
                            param,
                            raw_cmd,
                            raw_param,
                            current_sentinel_tsc,
                            last,
                            elapsed);
                        if (_KeBugCheckEx)
                            _KeBugCheckEx(BUGCHECK_DMA_CANARY_HIT, cmd, param, 0, 0);
                    }
                    else if (cmd == BRIDGE_CMD_INTEGRITY_FAIL) {
                        log_watchdog_bugcheck_intent("integrity_fail",
                            BUGCHECK_RE_USERMODE_CONFIRMED,
                            cmd,
                            param,
                            raw_cmd,
                            raw_param,
                            current_sentinel_tsc,
                            last,
                            elapsed);
                        if (_KeBugCheckEx)
                            _KeBugCheckEx(BUGCHECK_RE_USERMODE_CONFIRMED, cmd, param, 0, 0);
                    }
                    else if (cmd == BRIDGE_CMD_RE_EVIDENCE) {
                        WW_LOG("watchdog_dpc: RE_EVIDENCE reason=0x%lx -> accumulator", param);
                        evidence_accumulator::add_evidence(param);

                        if (evidence_accumulator::is_direct_bsod_reason(param)) {
                            WW_LOG("watchdog_dpc: direct BSOD reason=0x%lx", param);
                            log_watchdog_bugcheck_intent("re_evidence_direct",
                                BUGCHECK_RE_USERMODE_CONFIRMED,
                                cmd,
                                param,
                                raw_cmd,
                                raw_param,
                                current_sentinel_tsc,
                                last,
                                elapsed);
                            if (_KeBugCheckEx)
                                _KeBugCheckEx(BUGCHECK_RE_USERMODE_CONFIRMED, cmd, param, 0, 0);
                        }
                        else if (evidence_accumulator::should_bugcheck()) {
                            WW_LOG("watchdog_dpc: accumulator quorum met, BSOD");
                            log_watchdog_bugcheck_intent("re_evidence_quorum",
                                BUGCHECK_RE_USERMODE_CONFIRMED,
                                cmd,
                                param,
                                raw_cmd,
                                raw_param,
                                current_sentinel_tsc,
                                last,
                                elapsed);
                            if (_KeBugCheckEx)
                                _KeBugCheckEx(BUGCHECK_RE_USERMODE_CONFIRMED, cmd, param, 0, 0);
                        }
                    }
                    else if (cmd == BRIDGE_CMD_DEBUGGER_FOUND || cmd == BRIDGE_CMD_DUMP_TOOL_FOUND ||
                             cmd == BRIDGE_CMD_CALLBACK_REMOVED) {
                        log_watchdog_bugcheck_intent("debug_dump_callback",
                            BUGCHECK_RE_USERMODE_CONFIRMED,
                            cmd,
                            param,
                            raw_cmd,
                            raw_param,
                            current_sentinel_tsc,
                            last,
                            elapsed);
                        if (_KeBugCheckEx)
                            _KeBugCheckEx(BUGCHECK_RE_USERMODE_CONFIRMED, cmd, param, 0, 0);
                    }
                    else if (cmd == BRIDGE_CMD_HONEYPOT_CANARY_PATCH) {
                        WW_LOG("watchdog_dpc: HONEYPOT_CANARY_PATCH decoy_id=%lu -> BUGCHECK 0x%lx",
                            param, BUGCHECK_HONEYPOT_CANARY_PATCH);
                        log_watchdog_bugcheck_intent("honeypot_canary_patch",
                            BUGCHECK_HONEYPOT_CANARY_PATCH,
                            cmd, param, raw_cmd, raw_param,
                            current_sentinel_tsc, last, elapsed);
                        if (_KeBugCheckEx)
                            _KeBugCheckEx(BUGCHECK_HONEYPOT_CANARY_PATCH,
                                (ULONG_PTR)param, 0, 0, 0);
                    }
                    else if (cmd == BRIDGE_CMD_HONEYPOT_STRING_ACCESS) {
                        WW_LOG("watchdog_dpc: HONEYPOT_STRING_ACCESS -> BUGCHECK 0x%lx",
                            BUGCHECK_HONEYPOT_STRING_ACCESS);
                        log_watchdog_bugcheck_intent("honeypot_string_access",
                            BUGCHECK_HONEYPOT_STRING_ACCESS,
                            cmd, param, raw_cmd, raw_param,
                            current_sentinel_tsc, last, elapsed);
                        if (_KeBugCheckEx)
                            _KeBugCheckEx(BUGCHECK_HONEYPOT_STRING_ACCESS,
                                (ULONG_PTR)param, 0, 0, 0);
                    }
                    else if (cmd == BRIDGE_CMD_REGISTER_HONEYPOT_PID) {
                        g_aida_pid = (HANDLE)(ULONG_PTR)param;
                        WW_LOG("watchdog_dpc: REGISTER_HONEYPOT_PID pid=%p", g_aida_pid);
                    }
                    else if (cmd == BRIDGE_CMD_REGISTER_HONEYPOT_GUARD) {
                        WW_LOG("watchdog_dpc: REGISTER_HONEYPOT_GUARD param=0x%lx", param);
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
            WW_LOG("watchdog_dpc: sentinel_absent_nonfatal streak=%ld >= threshold=%ld, sentinel_tsc=%lld, last=%lld, elapsed=%lld",
                streak, STALE_THRESHOLD, current_sentinel_tsc, last, elapsed);
            _InterlockedExchange(&g_stale_streak, STALE_THRESHOLD);
        }
    }


    __forceinline void init(PVOID text_base, ULONG text_size) {
        g_bridge_crypt_key = derive_bridge_key();
        derive_challenge_subkeys();
        g_bridge.code_base = text_base;
        g_bridge.code_size = text_size;
        WW_LOG("bridge::init: code_base=%p code_end=%p code_size=0x%lx bridge_addr=%p bridge_v2=%p magic=0x%lx version=%lu expected_version=%lu key_present=%u challenge_keys_valid=%ld whoswho_tsc=%lld sentinel_tsc=%lld hmac_valid=%u",
            text_base,
            text_base ? static_cast<UCHAR*>(text_base) + text_size : nullptr,
            text_size,
            &g_bridge,
            &g_bridge_v2,
            g_bridge.magic,
            g_bridge.version,
            BRIDGE_VERSION_2,
            g_bridge_crypt_key != 0 ? 1u : 0u,
            _InterlockedCompareExchange(&g_challenge_keys_valid, 0, 0),
            g_bridge.whoswho_tsc,
            g_bridge.sentinel_tsc,
            g_bridge_v2.hmac_valid ? 1u : 0u);
    }


    __forceinline void start_watchdog() {
        if (_InterlockedCompareExchange(&g_watchdog_active, 1, 0) != 0) {
            WW_LOG("start_watchdog: already active, skipping");
            return;
        }

        WW_LOG("sentinel_bridge::discovery_model whoswho_sentinel_device_probe=0 whoswho_sentinel_object_probe=0 reason=shared_bridge_waits_for_sentinel_tsc bridge=%p version=%lu magic=0x%lx",
            &g_bridge,
            g_bridge.version,
            g_bridge.magic);

        _InterlockedExchange64(&g_watchdog_start_qpc, static_cast<LONG64>(__rdtsc()));

        LONG64 initial_sentinel_tsc = _InterlockedCompareExchange64(&g_bridge.sentinel_tsc, 0, 0);
        _InterlockedExchange64(&g_last_seen_sentinel_tsc, initial_sentinel_tsc);

        _InterlockedExchange(&g_stale_streak, 0);

        _KeInitializeTimerEx(&g_watchdog_timer, SynchronizationTimer);
        _KeInitializeDpc(&g_watchdog_dpc, watchdog_dpc_callback, nullptr);

        LARGE_INTEGER due_time;
        due_time.QuadPart = -static_cast<LONGLONG>(WATCHDOG_PERIOD_MS) * 10000LL;

        BOOLEAN timer_was_set = _KeSetTimerEx(&g_watchdog_timer, due_time, WATCHDOG_PERIOD_MS, &g_watchdog_dpc);

        WW_LOG("start_watchdog: armed, period=%ldms grace=%ldms timeout=%ldms initial_sentinel_tsc=%lld bridge=%p timer_was_set=%u active=%ld whoswho_tsc=%lld hmac_valid=%u",
            WATCHDOG_PERIOD_MS, GRACE_PERIOD_MS, SENTINEL_TIMEOUT_MS,
            initial_sentinel_tsc,
            &g_bridge,
            timer_was_set ? 1u : 0u,
            _InterlockedCompareExchange(&g_watchdog_active, 0, 0),
            g_bridge.whoswho_tsc,
            g_bridge_v2.hmac_valid ? 1u : 0u);
    }

    constexpr ULONG EVIDENCE_BLOB_MAGIC = 0x45564944u;
    constexpr ULONG EVIDENCE_BLOB_SIZE  = 512;
    constexpr ULONG EVIDENCE_BLOB_TAG   = 'DivE';

    struct evidence_blob_t {
        volatile ULONG   magic;
        volatile ULONG   version;
        volatile ULONG   signal_family;
        volatile ULONG   signal_id;
        volatile ULONG   score;
        volatile ULONG   source_pid;
        volatile ULONG64 caller_image_hash;
        volatile ULONG64 signals_bitmap;
        volatile ULONG64 evidence_siphash;
        volatile LARGE_INTEGER timestamp;
        volatile LONG    seq;
        volatile ULONG   _pad;
        UCHAR            aux[EVIDENCE_BLOB_SIZE - 64];
    };
    static_assert(sizeof(evidence_blob_t) == EVIDENCE_BLOB_SIZE, "evidence_blob_t size mismatch");

    inline evidence_blob_t* g_evidence_blob = nullptr;
    inline ULONG_PTR        g_evidence_blob_offset = 0;

    __forceinline NTSTATUS allocate_evidence_blob() {
        if (g_evidence_blob) return STATUS_SUCCESS;
        PVOID p = ExAllocatePool2(POOL_FLAG_NON_PAGED, EVIDENCE_BLOB_SIZE, EVIDENCE_BLOB_TAG);
        if (!p) return STATUS_INSUFFICIENT_RESOURCES;
        auto* b = static_cast<evidence_blob_t*>(p);
        b->magic = EVIDENCE_BLOB_MAGIC;
        b->version = 1;
        g_evidence_blob = b;
        ULONG_PTR bridge_base = reinterpret_cast<ULONG_PTR>(&g_bridge);
        ULONG_PTR blob_addr   = reinterpret_cast<ULONG_PTR>(b);
        g_evidence_blob_offset = (blob_addr >= bridge_base) ? (blob_addr - bridge_base) : (bridge_base - blob_addr);
        return STATUS_SUCCESS;
    }

    __forceinline void free_evidence_blob() {
        if (!g_evidence_blob) return;
        ExFreePoolWithTag(g_evidence_blob, EVIDENCE_BLOB_TAG);
        g_evidence_blob = nullptr;
        g_evidence_blob_offset = 0;
    }

    __forceinline void populate_evidence_blob(
        ULONG family, ULONG signal_id, ULONG score, ULONG pid,
        ULONG64 image_hash, ULONG64 bitmap, ULONG64 siphash)
    {
        evidence_blob_t* b = g_evidence_blob;
        if (!b) return;
        _InterlockedIncrement(&b->seq);
        b->signal_family     = family;
        b->signal_id         = signal_id;
        b->score             = score;
        b->source_pid        = pid;
        b->caller_image_hash = image_hash;
        b->signals_bitmap    = bitmap;
        b->evidence_siphash  = siphash;
        LARGE_INTEGER now;
        KeQuerySystemTime(&now);
        b->timestamp.QuadPart = now.QuadPart;
        KeMemoryBarrier();
        b->magic             = EVIDENCE_BLOB_MAGIC;
    }
}
