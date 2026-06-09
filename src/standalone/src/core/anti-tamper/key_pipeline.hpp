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
#include "../../helpers/diag_log.hpp"

namespace anti_tamper {
namespace key_pipeline {

namespace detail_kp {

    inline void kat_dbg_log(const char* msg)
    {
        char path[MAX_PATH] = {};
        if (!diag::build_log_path("aida_debug.log", path, sizeof(path))) {
            std::strcpy(path, "aida_debug.log");
        }
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

    inline void aes_gcm_encrypt_internal(const uint8_t key[32], const uint8_t iv[12],
                                         const uint8_t* aad, size_t aad_len,
                                         const uint8_t* pt, size_t pt_len,
                                         uint8_t* ct, uint8_t tag[16],
                                         bool& ok)
    {
        ok = false;
        EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
        if (!ctx) return;

        do {
            if (EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr) != 1) break;
            if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, 12, nullptr) != 1) break;
            if (EVP_EncryptInit_ex(ctx, nullptr, nullptr, key, iv) != 1) break;

            int outlen = 0;
            if (aad && aad_len > 0)
            {
                if (EVP_EncryptUpdate(ctx, nullptr, &outlen, aad, static_cast<int>(aad_len)) != 1) break;
            }
            if (pt && pt_len > 0)
            {
                if (EVP_EncryptUpdate(ctx, ct, &outlen, pt, static_cast<int>(pt_len)) != 1) break;
            }
            int finlen = 0;
            if (EVP_EncryptFinal_ex(ctx, ct ? ct + outlen : nullptr, &finlen) != 1) break;
            if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, tag) != 1) break;

            ok = true;
        } while (false);

        EVP_CIPHER_CTX_free(ctx);
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
            const uint8_t key[32] = {
                0xfe,0xff,0xe9,0x92,0x86,0x65,0x73,0x1c,
                0x6d,0x6a,0x8f,0x94,0x67,0x30,0x83,0x08,
                0xfe,0xff,0xe9,0x92,0x86,0x65,0x73,0x1c,
                0x6d,0x6a,0x8f,0x94,0x67,0x30,0x83,0x08
            };
            const uint8_t iv[12] = {
                0xca,0xfe,0xba,0xbe,0xfa,0xce,0xdb,0xad,
                0xde,0xca,0xf8,0x88
            };
            const uint8_t aad[20] = {
                0xfe,0xed,0xfa,0xce,0xde,0xad,0xbe,0xef,
                0xfe,0xed,0xfa,0xce,0xde,0xad,0xbe,0xef,
                0xab,0xad,0xda,0xd2
            };
            const uint8_t pt[60] = {
                0xd9,0x31,0x32,0x25,0xf8,0x84,0x06,0xe5,
                0xa5,0x59,0x09,0xc5,0xaf,0xf5,0x26,0x9a,
                0x86,0xa7,0xa9,0x53,0x15,0x34,0xf7,0xda,
                0x2e,0x4c,0x30,0x3d,0x8a,0x31,0x8a,0x72,
                0x1c,0x3c,0x0c,0x95,0x95,0x68,0x09,0x53,
                0x2f,0xcf,0x0e,0x24,0x49,0xa6,0xb5,0x25,
                0xb1,0x6a,0xed,0xf5,0xaa,0x0d,0xe6,0x57,
                0xba,0x63,0x7b,0x39
            };
            const uint8_t expected_ct[60] = {
                0x52,0x2d,0xc1,0xf0,0x99,0x56,0x7d,0x07,
                0xf4,0x7f,0x37,0xa3,0x2a,0x84,0x42,0x7d,
                0x64,0x3a,0x8c,0xdc,0xbf,0xe5,0xc0,0xc9,
                0x75,0x98,0xa2,0xbd,0x25,0x55,0xd1,0xaa,
                0x8c,0xb0,0x8e,0x48,0x59,0x0d,0xbb,0x3d,
                0xa7,0xb0,0x8b,0x10,0x56,0x82,0x88,0x38,
                0xc5,0xf6,0x1e,0x63,0x93,0xba,0x7a,0x0a,
                0xbc,0xc9,0xf6,0x62
            };
            const uint8_t expected_tag[16] = {
                0x76,0xfc,0x6e,0xce,0x0f,0x4e,0x17,0x68,
                0xcd,0xdf,0x88,0x53,0xbb,0x2d,0x55,0x1b
            };
            uint8_t ct[60] = {};
            uint8_t tag[16] = {};
            bool ok = false;
            kat_dbg_log("run_kat: AES-GCM calling");
            aes_gcm_encrypt_internal(key, iv, aad, sizeof(aad), pt, sizeof(pt),
                                     ct, tag, ok);
            kat_dbg_log(ok ? "run_kat: AES-GCM call returned ok=true" : "run_kat: AES-GCM call returned ok=FALSE");
            if (!ok) { set_last_error("kat_aes_gcm_call_failed"); kat_dbg_log("run_kat: FAIL kat_aes_gcm_call_failed"); return false; }
            if (!ct_equal(ct, expected_ct, sizeof(expected_ct)))
            {
                set_last_error("kat_aes_gcm_ct_mismatch");
                char buf[256];
                _snprintf_s(buf, sizeof(buf), _TRUNCATE,
                    "run_kat: FAIL kat_aes_gcm_ct_mismatch first8=%02X%02X%02X%02X%02X%02X%02X%02X expected_first8=%02X%02X%02X%02X%02X%02X%02X%02X",
                    ct[0],ct[1],ct[2],ct[3],ct[4],ct[5],ct[6],ct[7],
                    expected_ct[0],expected_ct[1],expected_ct[2],expected_ct[3],expected_ct[4],expected_ct[5],expected_ct[6],expected_ct[7]);
                kat_dbg_log(buf);
                return false;
            }
            if (!ct_equal(tag, expected_tag, sizeof(expected_tag)))
            {
                set_last_error("kat_aes_gcm_tag_mismatch");
                char buf[256];
                _snprintf_s(buf, sizeof(buf), _TRUNCATE,
                    "run_kat: FAIL kat_aes_gcm_tag_mismatch tag=%02X%02X%02X%02X%02X%02X%02X%02X expected_tag=%02X%02X%02X%02X%02X%02X%02X%02X",
                    tag[0],tag[1],tag[2],tag[3],tag[4],tag[5],tag[6],tag[7],
                    expected_tag[0],expected_tag[1],expected_tag[2],expected_tag[3],expected_tag[4],expected_tag[5],expected_tag[6],expected_tag[7]);
                kat_dbg_log(buf);
                return false;
            }
            kat_dbg_log("run_kat: AES-GCM PASS");
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

inline bool encrypt_with_wbaes(const char* domain,
                                const uint8_t* salt, size_t salt_len,
                                const uint8_t iv[16],
                                const uint8_t* pt, size_t pt_len,
                                uint8_t* ct)
{
    if (!domain || !iv || (pt_len > 0 && (!pt || !ct)))
    {
        detail_kp::set_last_error("encrypt_with_wbaes_invalid_args");
        return false;
    }
    if (!ensure_kat_passed())
    {
        detail_kp::set_last_error("encrypt_with_wbaes_kat_not_passed");
        return false;
    }

    uint8_t key[16];
    if (!derive(domain, salt, salt_len, key, sizeof(key)))
    {
        SecureZeroMemory(key, sizeof(key));
        detail_kp::set_last_error("encrypt_with_wbaes_derive_failed");
        return false;
    }

    uint8_t seed_bytes[32];
    arc_internal::arc_build_seed_bytes(seed_bytes);
    uint64_t seed_low = 0;
    std::memcpy(&seed_low, seed_bytes, sizeof(seed_low));
    SecureZeroMemory(seed_bytes, sizeof(seed_bytes));

    uint64_t entropy_seed = static_cast<uint64_t>(__rdtsc()) ^ seed_low;

    wbaes::white_box_table_t* tbl = static_cast<wbaes::white_box_table_t*>(
        HeapAlloc(GetProcessHeap(), 0, sizeof(wbaes::white_box_table_t)));
    if (!tbl)
    {
        SecureZeroMemory(key, sizeof(key));
        detail_kp::set_last_error("encrypt_with_wbaes_alloc_failed");
        return false;
    }

    bool generated = wbaes::generate_tables(key, entropy_seed, *tbl);
    SecureZeroMemory(key, sizeof(key));
    if (!generated)
    {
        SecureZeroMemory(tbl, sizeof(wbaes::white_box_table_t));
        HeapFree(GetProcessHeap(), 0, tbl);
        detail_kp::set_last_error("encrypt_with_wbaes_generate_failed");
        return false;
    }

    bool encrypted = wbaes::encrypt_ctr(*tbl, iv, pt, ct, pt_len);

    SecureZeroMemory(tbl, sizeof(wbaes::white_box_table_t));
    HeapFree(GetProcessHeap(), 0, tbl);

    if (!encrypted)
    {
        detail_kp::set_last_error("encrypt_with_wbaes_ctr_failed");
        return false;
    }

    detail_kp::set_last_error(nullptr);
    return true;
}

}
}
