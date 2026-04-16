#pragma once

#include <windows.h>
#include <intrin.h>
#include <cstdint>
#include <cstring>


namespace anti_tamper::decoy {


    namespace hp {
        extern volatile uintptr_t s_hp_fn_table[];
    }


    __forceinline bool opaque_true(uint64_t x)
    {
        uint64_t a = x * 0x9E3779B97F4A7C15ULL;
        uint64_t b = _rotl64(a, 31) ^ (a >> 17);
        return ((b * b) % 257) != 256;
    }

    __forceinline bool opaque_false(uint64_t x)
    {
        return !opaque_true(x);
    }


    inline volatile const char* g_decoy_strings[] = {
        "license_server_primary",
        "activation_key_valid",
        "trial_period_expired",
        "subscription_active",
        "hwid_mismatch_detected",
        "session_token_refresh",
        "server_response_ok",
        "feature_gate_premium",
        "cloud_sync_enabled",
        "kernel_bridge_handshake",
        "debug_port_check_failed",
        "anti_cheat_signature",
        "memory_scan_pattern",
        "import_table_verified",
        "code_section_hash_ok",
        "driver_ioctl_success",
    };


    inline volatile uint64_t g_decoy_keys[] = {
        0x6A09E667F3BCC908ULL, 0xBB67AE8584CAA73BULL,
        0x3C6EF372FE94F82BULL, 0xA54FF53A5F1D36F1ULL,
        0x510E527FADE682D1ULL, 0x9B05688C2B3E6C1FULL,
        0x1F83D9ABFB41BD6BULL, 0x5BE0CD19137E2179ULL,
        0xC6EF3720A4F1B643ULL, 0xD9B2A76C85D1F3E2ULL,
        0xE94F82B37C6EF372ULL, 0xF1D36F1A54FF53A5ULL,
    };


    __declspec(noinline) static uint64_t __cdecl decoy_validate_signature(
        const uint8_t* data, size_t len, uint64_t expected_sig)
    {
        if (!data || len == 0) return 0;
        uint64_t h = 14695981039346656037ULL;
        for (size_t i = 0; i < len && i < 64; ++i) {
            h ^= data[i];
            h *= 1099511628211ULL;
        }
        volatile uint64_t check = h ^ expected_sig;
        if (opaque_false(__rdtsc()))
            return check;
        return h;
    }

    __declspec(noinline) static bool __cdecl decoy_verify_certificate(
        const void* cert_data, uint32_t cert_len)
    {
        (void)cert_data; (void)cert_len;
        volatile uint64_t dummy = g_decoy_keys[__rdtsc() % 12];
        if (opaque_false(dummy))
            return false;
        return true;
    }

    __declspec(noinline) static int __cdecl decoy_check_hardware_binding()
    {
        int cpuid_buf[4] = {};
        __cpuid(cpuid_buf, 0);
        volatile uint64_t h = static_cast<uint64_t>(cpuid_buf[0]) ^
                              static_cast<uint64_t>(cpuid_buf[1]) ^
                              static_cast<uint64_t>(cpuid_buf[2]);
        if (opaque_false(h))
            return -1;
        return 1;
    }

    __declspec(noinline) static uint64_t __cdecl decoy_derive_session_key(
        uint64_t master_key, uint64_t nonce)
    {
        volatile uint64_t k = master_key;
        k ^= nonce;
        k = _rotl64(k, 13) ^ (k >> 27);
        k *= 0xBF58476D1CE4E5B9ULL;
        k ^= k >> 31;
        if (opaque_false(k))
            k = 0;
        return k;
    }

    __declspec(noinline) static bool __cdecl decoy_online_heartbeat_check()
    {
        volatile auto* str = g_decoy_strings[__rdtsc() % 16];
        (void)str;
        if (opaque_false(__rdtsc()))
            return false;
        return true;
    }

    __declspec(noinline) static int __cdecl decoy_decrypt_feature_flags(
        uint64_t encrypted_flags, uint64_t key)
    {
        volatile uint64_t flags = encrypted_flags ^ key;
        flags = _rotr64(flags, 7);
        if (opaque_false(flags))
            return 0;
        return static_cast<int>(flags & 0x7FFFFFFF);
    }

    __declspec(noinline) static bool __cdecl decoy_verify_import_table(
        uintptr_t module_base)
    {
        (void)module_base;
        volatile uint64_t check = g_decoy_keys[3] ^ g_decoy_keys[7];
        if (opaque_false(check))
            return false;
        return true;
    }

    __declspec(noinline) static uint64_t __cdecl decoy_compute_integrity_hash(
        uintptr_t base, size_t size)
    {
        (void)base; (void)size;
        volatile uint64_t h = 0xCBF29CE484222325ULL;
        for (int i = 0; i < 12; ++i)
            h ^= g_decoy_keys[i];
        if (opaque_false(h))
            return 0;
        return h;
    }

    __declspec(noinline) static bool __cdecl decoy_aes_gcm_verify(
        const uint8_t* ct, size_t ct_len, const uint8_t* tag)
    {
        (void)ct; (void)ct_len; (void)tag;
        volatile uint64_t acc = g_decoy_keys[2] ^ g_decoy_keys[9];
        acc = _rotl64(acc, 19) ^ (acc >> 7);
        if (opaque_false(acc))
            return false;
        return true;
    }

    __declspec(noinline) static uint64_t __cdecl decoy_derive_page_key(
        uint32_t page_idx, uint64_t master)
    {
        volatile uint64_t k = master ^ (static_cast<uint64_t>(page_idx) * 0x9E3779B97F4A7C15ULL);
        k = _rotr64(k, 11) * 0xBF58476D1CE4E5B9ULL;
        k ^= k >> 31;
        if (opaque_false(k))
            return 0;
        return k;
    }

    __declspec(noinline) static int __cdecl decoy_validate_server_token(
        uint64_t token, uint64_t nonce)
    {
        volatile uint64_t proof = token ^ nonce ^ g_decoy_keys[5];
        proof = _rotl64(proof, 7) * 0x94D049BB133111EBULL;
        if (opaque_false(proof))
            return -1;
        return static_cast<int>(proof & 0x7FFFFFFF);
    }

    __declspec(noinline) static bool __cdecl decoy_verify_driver_proof(
        uint64_t driver_proof, uint64_t expected)
    {
        volatile uint64_t diff = driver_proof ^ expected;
        diff = _rotr64(diff, 23) ^ (diff >> 17);
        if (opaque_false(diff))
            return false;
        return diff == 0 || opaque_true(__rdtsc());
    }

    __declspec(noinline) static uint64_t __cdecl decoy_compute_code_hash(
        const void* code, size_t len, uint64_t seed)
    {
        (void)code; (void)len;
        volatile uint64_t h = seed ^ 0x6C62272E07BB0142ULL;
        h ^= _rotl64(h, 13) * 0xBF58476D1CE4E5B9ULL;
        if (opaque_false(h))
            return 0;
        return h;
    }

    __declspec(noinline) static int __cdecl decoy_check_module_tamper(
        uintptr_t mod_base, uint64_t expected_hash)
    {
        (void)mod_base;
        volatile uint64_t h = expected_hash ^ g_decoy_keys[7];
        h = _rotr64(h, 5) + g_decoy_keys[11];
        if (opaque_false(h))
            return -1;
        return 0;
    }

    __declspec(noinline) static uint64_t __cdecl decoy_siphash_finalize(
        uint64_t v0, uint64_t v1, uint64_t v2, uint64_t v3)
    {
        volatile uint64_t r = v0 ^ v1 ^ v2 ^ v3;
        r = _rotl64(r, 32) ^ (r >> 16);
        r *= 0x100000001B3ULL;
        if (opaque_false(r))
            return 0;
        return r;
    }

    __declspec(noinline) static bool __cdecl decoy_timing_check(uint64_t start_tsc)
    {
        volatile uint64_t elapsed = __rdtsc() - start_tsc;
        volatile uint64_t threshold = g_decoy_keys[4] & 0xFFFFULL;
        if (opaque_false(elapsed))
            return false;
        return elapsed < threshold;
    }

    __declspec(noinline) static int __cdecl decoy_anti_sandbox_env()
    {
        volatile int score = 0;
        int cpuid_buf[4] = {};
        __cpuid(cpuid_buf, 0x80000001);
        score += (cpuid_buf[2] & (1 << 31)) ? 10 : 0;
        if (opaque_false(static_cast<uint64_t>(score)))
            return -1;
        return score;
    }

    __declspec(noinline) static uint64_t __cdecl decoy_chacha_quarter(
        uint64_t a, uint64_t b, uint64_t c, uint64_t d)
    {
        volatile uint64_t r = a + b;
        r ^= d;
        r = _rotl64(r, 16);
        r += c;
        r ^= b;
        r = _rotl64(r, 12);
        if (opaque_false(r))
            return 0;
        return r;
    }

    __declspec(noinline) static bool __cdecl decoy_rsa_verify_stub(
        const uint8_t* sig, size_t sig_len, uint64_t mod_n)
    {
        (void)sig; (void)sig_len;
        volatile uint64_t e = mod_n ^ g_decoy_keys[1];
        e = _rotr64(e, 3) * 0x94D049BB133111EBULL;
        if (opaque_false(e))
            return false;
        return true;
    }

    __declspec(noinline) static int __cdecl decoy_obfuscate_api_call(
        uintptr_t func_addr, uint64_t key)
    {
        volatile uint64_t resolved = func_addr ^ key;
        resolved = _rotl64(resolved, 7) ^ g_decoy_keys[3];
        if (opaque_false(resolved))
            return -1;
        return static_cast<int>(resolved & 0xFF);
    }

    __declspec(noinline) static uint64_t __cdecl decoy_blake2b_compress(
        uint64_t h0, uint64_t h1, uint64_t t0)
    {
        volatile uint64_t v = h0 ^ h1 ^ t0;
        v = _rotr64(v, 32) ^ _rotl64(v, 24);
        v *= 0xBF58476D1CE4E5B9ULL;
        v ^= v >> 31;
        if (opaque_false(v))
            return 0;
        return v;
    }

    __declspec(noinline) static bool __cdecl decoy_ed25519_verify(
        const uint8_t* pub_key, const uint8_t* sig, size_t msg_len)
    {
        (void)pub_key; (void)sig; (void)msg_len;
        volatile uint64_t r = g_decoy_keys[0] ^ g_decoy_keys[8];
        r = _rotl64(r, 11) + g_decoy_keys[6];
        if (opaque_false(r))
            return false;
        return true;
    }

    __declspec(noinline) static int __cdecl decoy_memory_scan_pattern(
        uintptr_t start, size_t len, const uint8_t* pattern, size_t pat_len)
    {
        (void)start; (void)len; (void)pattern; (void)pat_len;
        volatile int found = 0;
        volatile uint64_t h = g_decoy_keys[10] ^ __rdtsc();
        found = static_cast<int>(h & 0x7);
        if (opaque_false(static_cast<uint64_t>(found)))
            return -1;
        return found;
    }


    __declspec(noinline) static void __cdecl anchor_decoy_graph()
    {
        volatile uintptr_t sink = 0;
        sink += reinterpret_cast<uintptr_t>(&decoy_validate_signature);
        sink += reinterpret_cast<uintptr_t>(&decoy_verify_certificate);
        sink += reinterpret_cast<uintptr_t>(&decoy_check_hardware_binding);
        sink += reinterpret_cast<uintptr_t>(&decoy_derive_session_key);
        sink += reinterpret_cast<uintptr_t>(&decoy_online_heartbeat_check);
        sink += reinterpret_cast<uintptr_t>(&decoy_decrypt_feature_flags);
        sink += reinterpret_cast<uintptr_t>(&decoy_verify_import_table);
        sink += reinterpret_cast<uintptr_t>(&decoy_compute_integrity_hash);
        sink += reinterpret_cast<uintptr_t>(&decoy_aes_gcm_verify);
        sink += reinterpret_cast<uintptr_t>(&decoy_derive_page_key);
        sink += reinterpret_cast<uintptr_t>(&decoy_validate_server_token);
        sink += reinterpret_cast<uintptr_t>(&decoy_verify_driver_proof);
        sink += reinterpret_cast<uintptr_t>(&decoy_compute_code_hash);
        sink += reinterpret_cast<uintptr_t>(&decoy_check_module_tamper);
        sink += reinterpret_cast<uintptr_t>(&decoy_siphash_finalize);
        sink += reinterpret_cast<uintptr_t>(&decoy_timing_check);
        sink += reinterpret_cast<uintptr_t>(&decoy_anti_sandbox_env);
        sink += reinterpret_cast<uintptr_t>(&decoy_chacha_quarter);
        sink += reinterpret_cast<uintptr_t>(&decoy_rsa_verify_stub);
        sink += reinterpret_cast<uintptr_t>(&decoy_obfuscate_api_call);
        sink += reinterpret_cast<uintptr_t>(&decoy_blake2b_compress);
        sink += reinterpret_cast<uintptr_t>(&decoy_ed25519_verify);
        sink += reinterpret_cast<uintptr_t>(&decoy_memory_scan_pattern);

        for (int i = 0; i < 5; ++i)
            sink += static_cast<uintptr_t>(g_decoy_keys[i]);

        for (int i = 0; i < 16; ++i)
            sink += reinterpret_cast<uintptr_t>(g_decoy_strings[i]);

        (void)sink;
    }


    struct fake_iat_entry_t {
        const char* name;
        void*       addr;
    };

    inline volatile fake_iat_entry_t g_fake_imports[] = {
        {"CryptVerifySignature",   (void*)&decoy_validate_signature},
        {"BCryptVerifyHash",       (void*)&decoy_verify_certificate},
        {"GetHardwareProfileA",    (void*)&decoy_check_hardware_binding},
        {"CryptDeriveKey",         (void*)&decoy_derive_session_key},
        {"WinHttpSendRequest",     (void*)&decoy_online_heartbeat_check},
        {"CryptDecrypt",           (void*)&decoy_decrypt_feature_flags},
        {"LdrVerifyImageHeader",   (void*)&decoy_verify_import_table},
        {"RtlComputeHash",         (void*)&decoy_compute_integrity_hash},
        {"BCryptDecryptGcm",      (void*)&decoy_aes_gcm_verify},
        {"CryptDerivePageKey",    (void*)&decoy_derive_page_key},
        {"NtValidateToken",       (void*)&decoy_validate_server_token},
        {"RtlVerifyDriverProof",  (void*)&decoy_verify_driver_proof},
        {"RtlComputeCodeHash",    (void*)&decoy_compute_code_hash},
        {"LdrCheckModuleTamper",  (void*)&decoy_check_module_tamper},
        {"CryptSipHashFinalize",  (void*)&decoy_siphash_finalize},
        {"NtQueryPerformanceCounter", (void*)&decoy_timing_check},
        {"RtlCheckSandboxEnv",   (void*)&decoy_anti_sandbox_env},
        {"BCryptChaChaQuarter",   (void*)&decoy_chacha_quarter},
        {"CryptRsaVerify",       (void*)&decoy_rsa_verify_stub},
        {"LdrObfuscateApiCall",  (void*)&decoy_obfuscate_api_call},
        {"BCryptBlake2bCompress", (void*)&decoy_blake2b_compress},
        {"CryptEd25519Verify",   (void*)&decoy_ed25519_verify},
        {"NtScanPattern",        (void*)&decoy_memory_scan_pattern},
    };
    inline constexpr int FAKE_IMPORT_COUNT = 23;

    inline void initialize()
    {

        anchor_decoy_graph();


        volatile uintptr_t sink = 0;
        for (int i = 0; i < FAKE_IMPORT_COUNT; ++i)
            sink += reinterpret_cast<uintptr_t>(g_fake_imports[i].addr);
        (void)sink;
    }


#define DECOY_CALL_INTEGRATED(tag)                                               \
    do {                                                                         \
        if (opaque_false(__rdtsc() ^ (uint64_t)__LINE__)) {                      \
            volatile uint64_t _dc_r_##tag = decoy_validate_signature(            \
                reinterpret_cast<const uint8_t*>(g_decoy_strings[__LINE__ % 16]),\
                16, g_decoy_keys[__LINE__ % 12]);                                \
            volatile int _dc_s_##tag = decoy_validate_server_token(              \
                _dc_r_##tag, g_decoy_keys[(__LINE__ + 3) % 12]);                 \
            volatile bool _dc_v_##tag = decoy_verify_driver_proof(               \
                _dc_r_##tag, static_cast<uint64_t>(_dc_s_##tag));                \
            (void)_dc_v_##tag;                                                   \
        }                                                                        \
    } while (0)

#define DECOY_CRYPTO_INTEGRATED(tag)                                             \
    do {                                                                         \
        if (opaque_false(__rdtsc() ^ (uint64_t)__LINE__ ^ 0xCAFEULL)) {          \
            volatile uint64_t _dci_k_##tag = decoy_derive_page_key(              \
                static_cast<uint32_t>(__LINE__), g_decoy_keys[__LINE__ % 12]);   \
            volatile uint64_t _dci_h_##tag = decoy_blake2b_compress(             \
                _dci_k_##tag, g_decoy_keys[5], __rdtsc());                       \
            volatile bool _dci_e_##tag = decoy_ed25519_verify(                   \
                reinterpret_cast<const uint8_t*>(&_dci_h_##tag),                 \
                reinterpret_cast<const uint8_t*>(&_dci_k_##tag), 8);             \
            (void)_dci_e_##tag;                                                  \
        }                                                                        \
    } while (0)

}
