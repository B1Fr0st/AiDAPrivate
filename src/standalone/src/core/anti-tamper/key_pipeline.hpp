#pragma once

#include <windows.h>
#include <intrin.h>

#include <atomic>
#include <cstdint>
#include <cstring>
#include <mutex>
#include <string>

#include <openssl/evp.h>
#include <openssl/kdf.h>
#include <openssl/core_names.h>
#include <openssl/params.h>
#include <openssl/rand.h>

#include "arc_build_seed.hpp"
#include "wbaes.hpp"
#include "wb_crypto.hpp"
#include "../../helpers/diag_log.hpp"

namespace anti_tamper {
namespace key_pipeline {

namespace detail_kp {

    inline void kat_dbg_log(const char* msg)
    {
        char path[MAX_PATH] = {};
        if (!diag::build_log_path("aida_debug.log", path, sizeof(path)))
            return;
        HANDLE hf = CreateFileA(path, FILE_APPEND_DATA | SYNCHRONIZE,
            FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr,
            OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
        if (hf == INVALID_HANDLE_VALUE) return;
        SYSTEMTIME st{};
        GetLocalTime(&st);
        char line[512];
        int len = _snprintf_s(line, sizeof(line), _TRUNCATE,
            "[%02d:%02d:%02d.%03d] [kat] %s\r\n",
            st.wHour, st.wMinute, st.wSecond, st.wMilliseconds,
            msg ? msg : "");
        if (len > 0) {
            DWORD written = 0;
            WriteFile(hf, line, static_cast<DWORD>(len), &written, nullptr);
            FlushFileBuffers(hf);
        }
        CloseHandle(hf);
    }

    inline std::string& s_last_error_storage()
    {
        static std::string s;
        return s;
    }

    inline void set_last_error(const char* m)
    {
        if (m) s_last_error_storage().assign(m);
        else s_last_error_storage().clear();
    }

    inline std::atomic<bool>& s_kat_passed()
    {
        static std::atomic<bool> v{false};
        return v;
    }

    inline std::once_flag& s_kat_once()
    {
        static std::once_flag f;
        return f;
    }

    inline void hkdf_sha512_internal(const uint8_t* ikm, size_t ikm_len,
                                     const uint8_t* salt, size_t salt_len,
                                     const uint8_t* info, size_t info_len,
                                     uint8_t* out, size_t out_len,
                                     bool& ok)
    {
        ok = false;
        EVP_KDF* kdf = EVP_KDF_fetch(nullptr, "HKDF", nullptr);
        if (!kdf) return;
        EVP_KDF_CTX* ctx = EVP_KDF_CTX_new(kdf);
        EVP_KDF_free(kdf);
        if (!ctx) return;

        OSSL_PARAM params[5];
        int idx = 0;
        char digest_name[] = "SHA512";
        params[idx++] = OSSL_PARAM_construct_utf8_string(OSSL_KDF_PARAM_DIGEST, digest_name, 0);
        params[idx++] = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_KEY,
            const_cast<uint8_t*>(ikm), ikm_len);
        if (salt && salt_len > 0)
        {
            params[idx++] = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_SALT,
                const_cast<uint8_t*>(salt), salt_len);
        }
        if (info && info_len > 0)
        {
            params[idx++] = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_INFO,
                const_cast<uint8_t*>(info), info_len);
        }
        params[idx] = OSSL_PARAM_construct_end();

        if (EVP_KDF_derive(ctx, out, out_len, params) > 0)
            ok = true;

        EVP_KDF_CTX_free(ctx);
    }

    inline void hmac_sha256_internal(const uint8_t* key, size_t key_len,
                                     const uint8_t* data, size_t data_len,
                                     uint8_t out[32], bool& ok)
    {
        ok = false;
        EVP_MAC* mac = EVP_MAC_fetch(nullptr, "HMAC", nullptr);
        if (!mac) return;
        EVP_MAC_CTX* ctx = EVP_MAC_CTX_new(mac);
        EVP_MAC_free(mac);
        if (!ctx) return;

        char digest_name[] = "SHA256";
        OSSL_PARAM params[2];
        params[0] = OSSL_PARAM_construct_utf8_string(OSSL_MAC_PARAM_DIGEST, digest_name, 0);
        params[1] = OSSL_PARAM_construct_end();

        if (EVP_MAC_init(ctx, key, key_len, params) <= 0)
        {
            EVP_MAC_CTX_free(ctx);
            return;
        }
        if (EVP_MAC_update(ctx, data, data_len) <= 0)
        {
            EVP_MAC_CTX_free(ctx);
            return;
        }
        size_t outlen = 32;
        if (EVP_MAC_final(ctx, out, &outlen, 32) > 0 && outlen == 32)
            ok = true;

        EVP_MAC_CTX_free(ctx);
    }

    inline bool ct_equal(const uint8_t* a, const uint8_t* b, size_t n)
    {
        uint8_t r = 0;
        for (size_t i = 0; i < n; ++i) r |= static_cast<uint8_t>(a[i] ^ b[i]);
        return r == 0;
    }

    inline bool run_kat()
    {
        kat_dbg_log("run_kat: ENTRY");
        {
            const uint8_t ikm[22] = {
                0x0b,0x0b,0x0b,0x0b,0x0b,0x0b,0x0b,0x0b,
                0x0b,0x0b,0x0b,0x0b,0x0b,0x0b,0x0b,0x0b,
                0x0b,0x0b,0x0b,0x0b,0x0b,0x0b
            };
            const uint8_t salt[13] = {
                0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,
                0x08,0x09,0x0a,0x0b,0x0c
            };
            const uint8_t info[10] = {
                0xf0,0xf1,0xf2,0xf3,0xf4,0xf5,0xf6,0xf7,0xf8,0xf9
            };
            const uint8_t expected[42] = {
                0x83,0x23,0x90,0x08,0x6c,0xda,0x71,0xfb,
                0x47,0x62,0x5b,0xb5,0xce,0xb1,0x68,0xe4,
                0xc8,0xe2,0x6a,0x1a,0x16,0xed,0x34,0xd9,
                0xfc,0x7f,0xe9,0x2c,0x14,0x81,0x57,0x93,
                0x38,0xda,0x36,0x2c,0xb8,0xd9,0xf9,0x25,
                0xd7,0xcb
            };
            uint8_t out[42] = {};
            bool ok = false;
            kat_dbg_log("run_kat: HKDF-SHA512 calling");
            hkdf_sha512_internal(ikm, sizeof(ikm), salt, sizeof(salt),
                                 info, sizeof(info), out, sizeof(out), ok);
            kat_dbg_log(ok ? "run_kat: HKDF-SHA512 call returned ok=true" : "run_kat: HKDF-SHA512 call returned ok=FALSE");
            if (!ok) { set_last_error("kat_hkdf_sha512_call_failed"); kat_dbg_log("run_kat: FAIL kat_hkdf_sha512_call_failed"); return false; }
            if (!ct_equal(out, expected, sizeof(expected)))
            {
                set_last_error("kat_hkdf_sha512_mismatch");
                char buf[256];
                _snprintf_s(buf, sizeof(buf), _TRUNCATE,
                    "run_kat: FAIL kat_hkdf_sha512_mismatch first8=%02X%02X%02X%02X%02X%02X%02X%02X expected_first8=%02X%02X%02X%02X%02X%02X%02X%02X",
                    out[0],out[1],out[2],out[3],out[4],out[5],out[6],out[7],
                    expected[0],expected[1],expected[2],expected[3],expected[4],expected[5],expected[6],expected[7]);
                kat_dbg_log(buf);
                return false;
            }
            kat_dbg_log("run_kat: HKDF-SHA512 PASS");
        }

        {
            const uint8_t key[20] = {
                0x0b,0x0b,0x0b,0x0b,0x0b,0x0b,0x0b,0x0b,
                0x0b,0x0b,0x0b,0x0b,0x0b,0x0b,0x0b,0x0b,
                0x0b,0x0b,0x0b,0x0b
            };
            const uint8_t data[8] = { 'H','i',' ','T','h','e','r','e' };
            const uint8_t expected[32] = {
                0xb0,0x34,0x4c,0x61,0xd8,0xdb,0x38,0x53,
                0x5c,0xa8,0xaf,0xce,0xaf,0x0b,0xf1,0x2b,
                0x88,0x1d,0xc2,0x00,0xc9,0x83,0x3d,0xa7,
                0x26,0xe9,0x37,0x6c,0x2e,0x32,0xcf,0xf7
            };
            uint8_t out[32] = {};
            bool ok = false;
            kat_dbg_log("run_kat: HMAC-SHA256 calling");
            hmac_sha256_internal(key, sizeof(key), data, sizeof(data), out, ok);
            kat_dbg_log(ok ? "run_kat: HMAC-SHA256 call returned ok=true" : "run_kat: HMAC-SHA256 call returned ok=FALSE");
            if (!ok) { set_last_error("kat_hmac_sha256_call_failed"); kat_dbg_log("run_kat: FAIL kat_hmac_sha256_call_failed"); return false; }
            if (!ct_equal(out, expected, 32))
            {
                set_last_error("kat_hmac_sha256_mismatch");
                char buf[256];
                _snprintf_s(buf, sizeof(buf), _TRUNCATE,
                    "run_kat: FAIL kat_hmac_sha256_mismatch first8=%02X%02X%02X%02X%02X%02X%02X%02X expected_first8=%02X%02X%02X%02X%02X%02X%02X%02X",
                    out[0],out[1],out[2],out[3],out[4],out[5],out[6],out[7],
                    expected[0],expected[1],expected[2],expected[3],expected[4],expected[5],expected[6],expected[7]);
                kat_dbg_log(buf);
                return false;
            }
            kat_dbg_log("run_kat: HMAC-SHA256 PASS");
        }

        {
            kat_dbg_log("run_kat: WB-AES init calling");
            if (!wbaes::initialize_tables())
            {
                set_last_error("kat_wbaes_init_failed");
                kat_dbg_log("run_kat: FAIL kat_wbaes_init_failed");
                return false;
            }
            kat_dbg_log("run_kat: WB-AES init PASS");

            kat_dbg_log("run_kat: WB-AES test vector calling");
            if (!wbaes::verify_test_vector())
            {
                set_last_error("kat_wbaes_test_vector_failed");
                kat_dbg_log("run_kat: FAIL kat_wbaes_test_vector_failed");
                return false;
            }
            kat_dbg_log("run_kat: WB-AES test vector PASS");

            kat_dbg_log("run_kat: WB-AES table hash calling");
            if (!wbaes::verify_table_hash())
            {
                set_last_error("kat_wbaes_table_hash_failed");
                kat_dbg_log("run_kat: FAIL kat_wbaes_table_hash_failed");
                return false;
            }
            kat_dbg_log("run_kat: WB-AES table hash PASS");
        }

        {
            kat_dbg_log("run_kat: WB-GCM round-trip KAT calling");

            bool tv_all_zeros = true;
            for (int i = 0; i < 32; ++i)
            {
                if (wbaes::kWbaesTestVector[i] != 0)
                {
                    tv_all_zeros = false;
                    break;
                }
            }

            if (tv_all_zeros)
            {
                kat_dbg_log("run_kat: WB-GCM KAT skipped (dev mode, all-zeros test vector)");
            }
            else
            {
                uint8_t gcm_nonce[12] = {0};
                uint8_t gcm_pt[16];
                uint8_t gcm_ct[16];
                uint8_t gcm_tag[16];
                uint8_t gcm_dec[16];

                std::memcpy(gcm_pt, wbaes::kWbaesTestVector, 16);

                bool gcm_enc_ok = wb_crypto::gcm_encrypt(
                    gcm_pt, 16, nullptr, 0, gcm_nonce, gcm_ct, gcm_tag);
                if (!gcm_enc_ok)
                {
                    set_last_error("kat_wb_gcm_encrypt_failed");
                    kat_dbg_log("run_kat: FAIL kat_wb_gcm_encrypt_failed");
                    SecureZeroMemory(gcm_pt, sizeof(gcm_pt));
                    SecureZeroMemory(gcm_ct, sizeof(gcm_ct));
                    SecureZeroMemory(gcm_tag, sizeof(gcm_tag));
                    SecureZeroMemory(gcm_dec, sizeof(gcm_dec));
                    return false;
                }

                bool gcm_dec_ok = wb_crypto::gcm_decrypt(
                    gcm_ct, 16, nullptr, 0, gcm_nonce, gcm_tag, gcm_dec);
                if (!gcm_dec_ok)
                {
                    set_last_error("kat_wb_gcm_decrypt_failed");
                    kat_dbg_log("run_kat: FAIL kat_wb_gcm_decrypt_failed");
                    SecureZeroMemory(gcm_pt, sizeof(gcm_pt));
                    SecureZeroMemory(gcm_ct, sizeof(gcm_ct));
                    SecureZeroMemory(gcm_tag, sizeof(gcm_tag));
                    SecureZeroMemory(gcm_dec, sizeof(gcm_dec));
                    return false;
                }

                if (!ct_equal(gcm_pt, gcm_dec, 16))
                {
                    set_last_error("kat_wb_gcm_roundtrip_mismatch");
                    kat_dbg_log("run_kat: FAIL kat_wb_gcm_roundtrip_mismatch");
                    SecureZeroMemory(gcm_pt, sizeof(gcm_pt));
                    SecureZeroMemory(gcm_ct, sizeof(gcm_ct));
                    SecureZeroMemory(gcm_tag, sizeof(gcm_tag));
                    SecureZeroMemory(gcm_dec, sizeof(gcm_dec));
                    return false;
                }

                SecureZeroMemory(gcm_pt, sizeof(gcm_pt));
                SecureZeroMemory(gcm_ct, sizeof(gcm_ct));
                SecureZeroMemory(gcm_tag, sizeof(gcm_tag));
                SecureZeroMemory(gcm_dec, sizeof(gcm_dec));
                kat_dbg_log("run_kat: WB-GCM round-trip KAT PASS");
            }
        }

        kat_dbg_log("run_kat: ALL PASS, returning true");
        return true;
    }

}

inline const char* last_error()
{
    return detail_kp::s_last_error_storage().c_str();
}

inline bool ensure_kat_passed()
{
    detail_kp::kat_dbg_log("ensure_kat_passed: ENTRY");
    std::call_once(detail_kp::s_kat_once(), []() {
        detail_kp::kat_dbg_log("ensure_kat_passed: call_once callback ENTRY");
        bool ok = detail_kp::run_kat();
        detail_kp::kat_dbg_log(ok ? "ensure_kat_passed: run_kat returned TRUE" : "ensure_kat_passed: run_kat returned FALSE");
        detail_kp::s_kat_passed().store(ok, std::memory_order_release);
        if (!ok) {
            char buf[256];
            _snprintf_s(buf, sizeof(buf), _TRUNCATE,
                "ensure_kat_passed: ABOUT TO __fastfail(0xA1DA0CA7) last_error=%s",
                detail_kp::s_last_error_storage().c_str());
            detail_kp::kat_dbg_log(buf);
            __fastfail(0xA1DA0CA7u);
        }
        detail_kp::kat_dbg_log("ensure_kat_passed: call_once callback DONE");
    });
    bool result = detail_kp::s_kat_passed().load(std::memory_order_acquire);
    detail_kp::kat_dbg_log(result ? "ensure_kat_passed: returning TRUE" : "ensure_kat_passed: returning FALSE");
    return result;
}

inline bool derive(const char* domain,
                   const uint8_t* salt, size_t salt_len,
                   uint8_t* out, size_t out_len)
{
    if (!domain || !out || out_len == 0)
    {
        detail_kp::set_last_error("derive_invalid_args");
        return false;
    }
    if (!ensure_kat_passed())
    {
        detail_kp::set_last_error("derive_kat_not_passed");
        return false;
    }

    uint8_t seed[32];
    arc_internal::arc_build_seed_bytes(seed);

    size_t domain_len = std::strlen(domain);
    if (domain_len == 0 || domain_len > 128)
    {
        detail_kp::set_last_error("derive_invalid_domain");
        SecureZeroMemory(seed, sizeof(seed));
        return false;
    }

    bool ok = false;
    detail_kp::hkdf_sha512_internal(
        seed, sizeof(seed),
        salt, salt_len,
        reinterpret_cast<const uint8_t*>(domain), domain_len,
        out, out_len, ok);

    SecureZeroMemory(seed, sizeof(seed));

    if (!ok)
    {
        detail_kp::set_last_error("derive_hkdf_failed");
        return false;
    }
    detail_kp::set_last_error(nullptr);
    return true;
}

inline bool derive_with_info(const char* domain,
                             const uint8_t* salt, size_t salt_len,
                             const uint8_t* extra_info, size_t extra_info_len,
                             uint8_t* out, size_t out_len)
{
    if (!domain || !out || out_len == 0)
    {
        detail_kp::set_last_error("derive_with_info_invalid_args");
        return false;
    }
    if (!ensure_kat_passed())
    {
        detail_kp::set_last_error("derive_with_info_kat_not_passed");
        return false;
    }

    uint8_t seed[32];
    arc_internal::arc_build_seed_bytes(seed);

    size_t domain_len = std::strlen(domain);
    if (domain_len == 0 || domain_len > 128)
    {
        detail_kp::set_last_error("derive_with_info_invalid_domain");
        SecureZeroMemory(seed, sizeof(seed));
        return false;
    }
    size_t info_total = domain_len + 1 + extra_info_len;
    if (info_total > 4096)
    {
        detail_kp::set_last_error("derive_with_info_info_too_large");
        SecureZeroMemory(seed, sizeof(seed));
        return false;
    }

    uint8_t info_stack[256];
    uint8_t* info_buf = info_stack;
    bool heap_alloc = false;
    if (info_total > sizeof(info_stack))
    {
        info_buf = static_cast<uint8_t*>(HeapAlloc(GetProcessHeap(), 0, info_total));
        if (!info_buf)
        {
            detail_kp::set_last_error("derive_with_info_alloc_failed");
            SecureZeroMemory(seed, sizeof(seed));
            return false;
        }
        heap_alloc = true;
    }

    std::memcpy(info_buf, domain, domain_len);
    info_buf[domain_len] = 0x00;
    if (extra_info && extra_info_len > 0)
        std::memcpy(info_buf + domain_len + 1, extra_info, extra_info_len);

    bool ok = false;
    detail_kp::hkdf_sha512_internal(
        seed, sizeof(seed),
        salt, salt_len,
        info_buf, info_total,
        out, out_len, ok);

    SecureZeroMemory(seed, sizeof(seed));
    SecureZeroMemory(info_buf, info_total);
    if (heap_alloc) HeapFree(GetProcessHeap(), 0, info_buf);

    if (!ok)
    {
        detail_kp::set_last_error("derive_with_info_hkdf_failed");
        return false;
    }
    detail_kp::set_last_error(nullptr);
    return true;
}

inline void build_commitment(uint8_t out[32])
{
    arc_internal::arc_build_commitment_bytes(out);
}

inline bool encrypt_with_wbaes_precomputed(
    const uint8_t iv[16],
    const uint8_t* pt, size_t pt_len,
    uint8_t* ct)
{
    if (!iv || (pt_len > 0 && (!pt || !ct)))
    {
        detail_kp::set_last_error("encrypt_with_wbaes_precomputed_invalid_args");
        return false;
    }
    if (!ensure_kat_passed())
    {
        detail_kp::set_last_error("encrypt_with_wbaes_precomputed_kat_not_passed");
        return false;
    }

    bool ok = wb_crypto::ctr_crypt(pt, ct, pt_len, iv);
    if (!ok)
    {
        detail_kp::set_last_error("encrypt_with_wbaes_precomputed_ctr_failed");
        return false;
    }

    detail_kp::set_last_error(nullptr);
    return true;
}

inline bool encrypt_with_wbaes_gcm(
    const uint8_t* pt, size_t pt_len,
    const uint8_t* aad, size_t aad_len,
    const uint8_t nonce[12],
    uint8_t* ct, uint8_t tag[16])
{
    if (!nonce || (pt_len > 0 && (!pt || !ct)))
    {
        detail_kp::set_last_error("encrypt_with_wbaes_gcm_invalid_args");
        return false;
    }
    if (!ensure_kat_passed())
    {
        detail_kp::set_last_error("encrypt_with_wbaes_gcm_kat_not_passed");
        return false;
    }

    bool ok = wb_crypto::gcm_encrypt(pt, pt_len, aad, aad_len, nonce, ct, tag);
    if (!ok)
    {
        detail_kp::set_last_error("encrypt_with_wbaes_gcm_failed");
        return false;
    }

    detail_kp::set_last_error(nullptr);
    return true;
}

inline bool decrypt_with_wbaes_gcm(
    const uint8_t* ct, size_t ct_len,
    const uint8_t* aad, size_t aad_len,
    const uint8_t nonce[12],
    const uint8_t tag[16],
    uint8_t* pt)
{
    if (!nonce || !tag || (ct_len > 0 && (!ct || !pt)))
    {
        detail_kp::set_last_error("decrypt_with_wbaes_gcm_invalid_args");
        return false;
    }
    if (!ensure_kat_passed())
    {
        detail_kp::set_last_error("decrypt_with_wbaes_gcm_kat_not_passed");
        return false;
    }

    bool ok = wb_crypto::gcm_decrypt(ct, ct_len, aad, aad_len, nonce, tag, pt);
    if (!ok)
    {
        detail_kp::set_last_error("decrypt_with_wbaes_gcm_failed");
        return false;
    }

    detail_kp::set_last_error(nullptr);
    return true;
}

}
}
