#pragma once
#include <imports/Defs.h>
#include <core/KernelCrypto.h>


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
        volatile UINT64 challenge_counter;
        volatile UINT8  challenge_tag[16];
        volatile LONG64 protected_pid;
        volatile UINT8  dispatch_hook_detected;
        UINT8           _pad_dh[7];
        volatile UINT64 dispatch_hook_target;
        volatile UINT8  hostile_drivers;
        volatile UINT8  modified_callbacks;
        UINT8           _pad_cb[6];
        volatile UINT64 whoswho_challenge;
        volatile UINT64 sentinel_response;
        volatile UINT8  expected_watermark[16];
        volatile UINT8  actual_watermark[16];
        volatile UINT8  watermark_verified;
        volatile UINT32 watermark_rva;
        UINT8           _pad_wm[3];
        volatile UINT8  ce_driver_hash_data[32 * 32];
        volatile UINT32 ce_driver_hash_count;
        UINT8           _pad_ce[4];
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

    constexpr ULONG BRIDGE_CMD_DMA_KEY_SCRUB        = 0x0000B001u;
    constexpr ULONG BRIDGE_CMD_DMA_BSOD             = 0x0000B003u;
    constexpr ULONG BRIDGE_CMD_DMA_ATTACK_REPORT    = 0x0000B004u;

    constexpr ULONG BRIDGE_CMD_UPDATE_CE_HASHES     = 0x0000D001u;

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

    constexpr ULONG BUGCHECK_DMA_ATTACK             = 0xA1DA0008u;

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

    inline volatile UINT64 g_bridge_crypt_key = 0;
    inline UINT8 g_challenge_aes_key[kernel_crypto::AES256_KEY_SIZE]    = {};
    inline UINT8 g_challenge_hmac_key[kernel_crypto::SHA256_DIGEST_SIZE] = {};
    inline volatile LONG g_challenge_keys_valid = 0;
    inline volatile LONG64 g_last_seen_challenge_counter = 0;
    inline volatile LONG64 g_issued_challenge_counter    = 0;

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
        derive_challenge_subkeys();
    }

    __forceinline void bridge_encrypt_cmd(ULONG& cmd, ULONG& param) {
        UINT64 key = g_bridge_crypt_key;
        cmd   ^= static_cast<ULONG>(key & 0xFFFFFFFF);
        param ^= static_cast<ULONG>(key >> 32);
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

    __forceinline BOOLEAN bridge_encrypt_challenge_gcm(
        UINT64 plaintext_challenge,
        UINT64 counter,
        UINT64& ciphertext_out,
        UINT8  tag_out[kernel_crypto::GCM_TAG_SIZE])
    {
        if (_InterlockedCompareExchange(&g_challenge_keys_valid, 0, 0) == 0)
            return FALSE;

        UINT8 nonce[kernel_crypto::GCM_NONCE_SIZE];
        build_challenge_nonce(counter, nonce);

        UINT8 aad[16];
        RtlCopyMemory(aad + 0, &counter, 8);
        UINT64 magic = 0x57484F535F47434DULL;
        RtlCopyMemory(aad + 8, &magic, 8);

        UINT8 pt[8];
        RtlCopyMemory(pt, &plaintext_challenge, 8);

        UINT8 ct[8];
        NTSTATUS enc_st = kernel_crypto::bcrypt_aes256_gcm_encrypt(
            g_challenge_aes_key, nonce,
            aad, sizeof(aad),
            pt, 8,
            ct,
            tag_out);
        if (!NT_SUCCESS(enc_st)) {
            RtlSecureZeroMemory(nonce, sizeof(nonce));
            RtlSecureZeroMemory(pt,    sizeof(pt));
            RtlSecureZeroMemory(ct,    sizeof(ct));
            return FALSE;
        }

        RtlCopyMemory(&ciphertext_out, ct, 8);
        RtlSecureZeroMemory(nonce, sizeof(nonce));
        RtlSecureZeroMemory(pt,    sizeof(pt));
        RtlSecureZeroMemory(ct,    sizeof(ct));
        return TRUE;
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
        NTSTATUS dec_st = kernel_crypto::bcrypt_aes256_gcm_decrypt(
            g_challenge_aes_key, nonce,
            aad, sizeof(aad),
            ct, 8,
            tag_in,
            pt);
        BOOLEAN ok = NT_SUCCESS(dec_st) ? TRUE : FALSE;

        if (ok) {
            RtlCopyMemory(&plaintext_out, pt, 8);
        }
        RtlSecureZeroMemory(nonce, sizeof(nonce));
        RtlSecureZeroMemory(pt,    sizeof(pt));
        RtlSecureZeroMemory(ct,    sizeof(ct));
        return ok;
    }

    inline volatile sentinel_bridge_t* g_bridge = nullptr;

    __forceinline HANDLE get_bridge_protected_pid() {
        if (g_bridge) {
            __try {
                if (_MmIsAddressValid(reinterpret_cast<PVOID>(
                        const_cast<sentinel_bridge_t*>(g_bridge)))) {
                    LONG64 bridge_pid = g_bridge->protected_pid;
                    if (bridge_pid != 0) {
                        return reinterpret_cast<HANDLE>(bridge_pid);
                    }
                }
            } __except (EXCEPTION_EXECUTE_HANDLER) {}
        }
        return nullptr;
    }

    inline volatile UINT64             g_last_whoswho_tsc = 0;
    inline volatile UINT64             g_last_check_tsc = 0;
    inline volatile LONG               g_initialized = 0;
    inline volatile LONG               g_first_heartbeat_seen = 0;
    inline volatile ULONG              g_quorum_fail_mask = 0;
    inline volatile UINT64             g_quorum_fail_tsc = 0;

    inline volatile LONG               g_dma_tier1_refused = 0;
    inline volatile LONG               g_dma_tier2_bsod_armed = 0;
    inline volatile LONG               g_dma_canary_count = 0;
    inline volatile LONG               g_dma_canary_hits = 0;
    inline volatile LONG               g_dma_pcie_unknown_count = 0;
    inline volatile LONG               g_dma_ept_anomaly = 0;

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

    __forceinline ULONG elapsed_us_from_qpc(const LARGE_INTEGER& start, const LARGE_INTEGER& freq) {
        LARGE_INTEGER now = KeQueryPerformanceCounter(nullptr);
        if (freq.QuadPart <= 0 || now.QuadPart < start.QuadPart)
            return 0;
        return static_cast<ULONG>(((now.QuadPart - start.QuadPart) * 1000000ULL) / static_cast<ULONGLONG>(freq.QuadPart));
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

        LARGE_INTEGER freq = {};
        LARGE_INTEGER start = KeQueryPerformanceCounter(&freq);

        SN_LOG("locate_bridge: whoswho_base=%p whoswho_end=%p whoswho_size=0x%lx irql=%lu pid=%llu tid=%llu",
            whoswho_base,
            whoswho_base ? static_cast<UCHAR*>(whoswho_base) + whoswho_size : nullptr,
            whoswho_size,
            static_cast<ULONG>(KeGetCurrentIrql()),
            static_cast<unsigned long long>(reinterpret_cast<ULONG_PTR>(PsGetCurrentProcessId())),
            static_cast<unsigned long long>(reinterpret_cast<ULONG_PTR>(PsGetCurrentThreadId())));

        if (!whoswho_base || whoswho_size == 0) {
            SN_LOG("locate_bridge: FAIL - null base or zero size elapsed_us=%lu", elapsed_us_from_qpc(start, freq));
            return false;
        }

        if (!_MmIsAddressValid(whoswho_base)) {
            SN_LOG("locate_bridge: FAIL - whoswho_base %p not valid elapsed_us=%lu", whoswho_base, elapsed_us_from_qpc(start, freq));
            return false;
        }

        PIMAGE_DOS_HEADER dos = static_cast<PIMAGE_DOS_HEADER>(whoswho_base);
        if (dos->e_magic != IMAGE_DOS_SIGNATURE) {
            SN_LOG("locate_bridge: FAIL - bad DOS sig at %p (got 0x%x) elapsed_us=%lu", whoswho_base, dos->e_magic, elapsed_us_from_qpc(start, freq));
            return false;
        }

        PIMAGE_NT_HEADERS64 nt = reinterpret_cast<PIMAGE_NT_HEADERS64>(
            static_cast<UCHAR*>(whoswho_base) + dos->e_lfanew);
        if (!_MmIsAddressValid(nt) || nt->Signature != IMAGE_NT_SIGNATURE) {
            SN_LOG("locate_bridge: FAIL - bad NT headers at %p valid=%u elapsed_us=%lu",
                nt,
                _MmIsAddressValid(nt) ? 1u : 0u,
                elapsed_us_from_qpc(start, freq));
            return false;
        }

        PIMAGE_SECTION_HEADER sections = IMAGE_FIRST_SECTION(nt);
        SN_LOG("locate_bridge: PE valid, %u sections", nt->FileHeader.NumberOfSections);
        ULONG total_magic_hits = 0;
        ULONG scanned_sections = 0;
        ULONG scanned_bytes = 0;

        for (USHORT i = 0; i < nt->FileHeader.NumberOfSections; i++) {
            UCHAR* section_base = static_cast<UCHAR*>(whoswho_base) + sections[i].VirtualAddress;
            ULONG section_size = sections[i].Misc.VirtualSize;
            ++scanned_sections;
            scanned_bytes += section_size;

            SN_LOG("locate_bridge: section[%u] name=%.8s base=%p end=%p rva=0x%lx size=0x%lx",
                i,
                sections[i].Name,
                section_base,
                section_base + section_size,
                sections[i].VirtualAddress,
                section_size);

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
                    total_magic_hits++;
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
                        SN_LOG("locate_bridge: SUCCESS bridge=%p tsc_now=%llu whoswho_tsc=%llu sentinel_tsc=%llu challenge_counter=%llu sections=%lu magic_hits=%lu scanned_bytes=0x%lx elapsed_us=%lu",
                            bridge,
                            g_last_check_tsc,
                            static_cast<unsigned long long>(bridge->whoswho_tsc),
                            static_cast<unsigned long long>(bridge->sentinel_tsc),
                            static_cast<unsigned long long>(bridge->challenge_counter),
                            scanned_sections,
                            total_magic_hits,
                            scanned_bytes,
                            elapsed_us_from_qpc(start, freq));
                        return true;
                    } else {
                        SN_LOG("locate_bridge: REJECTED bridge - code_base=%p code_size=0x%lx out of range", cb, cs);
                    }
                }
                if (magic_hits == 0) {
                    SN_LOG("locate_bridge: section[%u] no magic hits", i);
                }
            } __except (EXCEPTION_EXECUTE_HANDLER) {
                SN_LOG("locate_bridge: EXCEPTION in section[%u] code=0x%08lx elapsed_us=%lu",
                    i,
                    GetExceptionCode(),
                    elapsed_us_from_qpc(start, freq));
                continue;
            }
        }

        SN_LOG("locate_bridge: FAIL - bridge not found sections=%lu magic_hits=%lu scanned_bytes=0x%lx elapsed_us=%lu",
            scanned_sections,
            total_magic_hits,
            scanned_bytes,
            elapsed_us_from_qpc(start, freq));
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
                g_last_whoswho_tsc = current_whoswho_tsc;
                g_last_check_tsc = now_check;
                return true;
            }

            UINT64 elapsed = now_check - g_last_check_tsc;

            if (elapsed > HEARTBEAT_TIMEOUT_TSC) {
                SN_LOG("heartbeat::update_and_check: WW STALE whoswho_tsc=%llu elapsed=%llu timeout=%llu",
                    current_whoswho_tsc, elapsed, HEARTBEAT_TIMEOUT_TSC);
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

    __forceinline void issue_challenge() {
        if (!_InterlockedCompareExchange(&g_initialized, 1, 1))
            return;
        if (!g_bridge || !_MmIsAddressValid(reinterpret_cast<PVOID>(
                const_cast<sentinel_bridge_t*>(g_bridge))))
            return;
        if (_InterlockedCompareExchange(&g_challenge_keys_valid, 0, 0) == 0)
            return;

        __try {
            UINT64 challenge = __rdtsc() ^ (static_cast<UINT64>(__rdtsc()) << 17);
            challenge |= 1;

            UINT64 counter = static_cast<UINT64>(_InterlockedIncrement64(&g_issued_challenge_counter));

            UINT64 ciphertext = 0;
            UINT8  tag[kernel_crypto::GCM_TAG_SIZE];
            if (!bridge_encrypt_challenge_gcm(challenge, counter, ciphertext, tag)) {
                return;
            }

            InterlockedExchange64(
                const_cast<volatile LONG64*>(reinterpret_cast<volatile LONG64*>(
                    &g_bridge->whoswho_response)),
                0);
            InterlockedExchange64(
                const_cast<volatile LONG64*>(reinterpret_cast<volatile LONG64*>(
                    &g_bridge->challenge_issued_tsc)),
                static_cast<LONG64>(__rdtsc()));
            for (ULONG i = 0; i < kernel_crypto::GCM_TAG_SIZE; ++i) {
                g_bridge->challenge_tag[i] = tag[i];
            }
            InterlockedExchange64(
                const_cast<volatile LONG64*>(reinterpret_cast<volatile LONG64*>(
                    &g_bridge->challenge_counter)),
                static_cast<LONG64>(counter));
            InterlockedExchange64(
                const_cast<volatile LONG64*>(reinterpret_cast<volatile LONG64*>(
                    &g_bridge->sentinel_challenge)),
                static_cast<LONG64>(ciphertext));
            SN_LOG("heartbeat::issue_challenge: challenge=0x%llx counter=%llu", challenge, counter);
            RtlSecureZeroMemory(tag, sizeof(tag));
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
        if (_InterlockedCompareExchange(&g_challenge_keys_valid, 0, 0) == 0)
            return true;

        __try {
            UINT64 enc_challenge = static_cast<UINT64>(g_bridge->sentinel_challenge);
            if (enc_challenge == 0)
                return true;

            UINT64 issued_tsc = static_cast<UINT64>(g_bridge->challenge_issued_tsc);
            UINT64 now = __rdtsc();
            if (now - issued_tsc < 10ULL * 3000000000ULL)
                return true;

            UINT64 counter = static_cast<UINT64>(g_bridge->challenge_counter);
            UINT8 tag[kernel_crypto::GCM_TAG_SIZE];
            for (ULONG i = 0; i < kernel_crypto::GCM_TAG_SIZE; ++i)
                tag[i] = g_bridge->challenge_tag[i];

            UINT64 challenge = 0;
            BOOLEAN dec_ok = bridge_decrypt_challenge_gcm(enc_challenge, counter, tag, challenge);
            RtlSecureZeroMemory(tag, sizeof(tag));
            if (!dec_ok) {
                LONG fails = _InterlockedIncrement(&g_challenge_failures);
                SN_LOG("heartbeat::verify_challenge: GCM_TAG_FAIL fails=%ld", fails);
                if (fails >= CHALLENGE_FAILURE_THRESHOLD) {
                    return register_quorum_failure(
                        QUORUM_FAIL_CHALL,
                        static_cast<ULONG_PTR>(counter),
                        static_cast<ULONG_PTR>(enc_challenge),
                        static_cast<ULONG_PTR>(fails));
                }
                InterlockedExchange64(
                    const_cast<volatile LONG64*>(reinterpret_cast<volatile LONG64*>(
                        &g_bridge->sentinel_challenge)),
                    0);
                return true;
            }

            UINT64 response = static_cast<UINT64>(g_bridge->whoswho_response);
            UINT64 expected = compute_expected_response(challenge);

            if (response == expected) {
                _InterlockedExchange(&g_challenge_failures, 0);
                InterlockedExchange64(
                    const_cast<volatile LONG64*>(reinterpret_cast<volatile LONG64*>(
                        &g_bridge->sentinel_challenge)),
                    0);
                SN_LOG("heartbeat::verify_challenge: PASS counter=%llu", counter);
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

    inline volatile UINT64 g_reverse_response_written_tsc = 0;

    __forceinline void process_reverse_challenge() {
        if (!_InterlockedCompareExchange(&g_initialized, 1, 1))
            return;
        if (!g_bridge || !_MmIsAddressValid(reinterpret_cast<PVOID>(
                const_cast<sentinel_bridge_t*>(g_bridge))))
            return;
        if (_InterlockedCompareExchange(&g_challenge_keys_valid, 0, 0) == 0) {
            SN_LOG("heartbeat::process_reverse_challenge: keys not valid -> BUGCHECK 0xDEAD5E08");
            if (_KeBugCheckEx)
                _KeBugCheckEx(0xDEAD5E08, 0, 0, 0, 3);
            return;
        }

        __try {
            UINT64 reverse_challenge = static_cast<UINT64>(g_bridge->whoswho_challenge);
            if (reverse_challenge == 0) {
                g_reverse_response_written_tsc = 0;
                return;
            }

            UINT64 current_response = static_cast<UINT64>(g_bridge->sentinel_response);
            if (current_response == 0) {
                UINT64 response = compute_expected_response(reverse_challenge);
                InterlockedExchange64(
                    const_cast<volatile LONG64*>(reinterpret_cast<volatile LONG64*>(
                        &g_bridge->sentinel_response)),
                    static_cast<LONG64>(response));
                g_reverse_response_written_tsc = __rdtsc();
                SN_LOG("heartbeat::process_reverse_challenge: challenge=0x%llx response=0x%llx",
                    reverse_challenge, response);
                return;
            }

            UINT64 written_tsc = g_reverse_response_written_tsc;
            if (written_tsc != 0) {
                UINT64 now = __rdtsc();
                if (now - written_tsc > 30ULL * 3000000000ULL) {
                    SN_LOG("heartbeat::process_reverse_challenge: STALE challenge=0x%llx response=0x%llx elapsed=%llu -> BUGCHECK 0xDEAD5E08",
                        reverse_challenge, current_response, now - written_tsc);
                    if (_KeBugCheckEx)
                        _KeBugCheckEx(0xDEAD5E08,
                            static_cast<ULONG_PTR>(reverse_challenge),
                            static_cast<ULONG_PTR>(current_response),
                            static_cast<ULONG_PTR>(now - written_tsc),
                            1);
                }
            }
        } __except (EXCEPTION_EXECUTE_HANDLER) {
            SN_LOG("heartbeat::process_reverse_challenge: EXCEPTION -> BUGCHECK 0xDEAD5E08");
            if (_KeBugCheckEx)
                _KeBugCheckEx(0xDEAD5E08, 0, 0, 0, 4);
        }
    }

    __forceinline bool verify_module_presence() {
        if (!g_target_driver_base || !g_sentinel_driver_object) {
            SN_LOG("heartbeat::verify_module_presence: skip target_base=%p sentinel_driver=%p",
                (PVOID)g_target_driver_base,
                g_sentinel_driver_object);
            return true;
        }

        if (!_MmIsAddressValid(g_sentinel_driver_object) ||
            !g_sentinel_driver_object->DriverSection ||
            !_MmIsAddressValid(g_sentinel_driver_object->DriverSection)) {
            SN_LOG("heartbeat::verify_module_presence: skip invalid_sentinel_object driver=%p section=%p",
                g_sentinel_driver_object,
                g_sentinel_driver_object ? g_sentinel_driver_object->DriverSection : nullptr);
            return true;
        }

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

                if (_MmIsAddressValid(mod) && mod->DllBase == (PVOID)g_target_driver_base) {
                    SN_LOG("heartbeat::verify_module_presence: target present entry=%p base=%p size=0x%lx",
                        mod,
                        mod->DllBase,
                        mod->SizeOfImage);
                    return true;
                }

                entry = entry->Flink;
            }
        } __except (EXCEPTION_EXECUTE_HANDLER) {
            SN_LOG("heartbeat::verify_module_presence: exception code=0x%08lx target=%p",
                GetExceptionCode(),
                (PVOID)g_target_driver_base);
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
