#pragma once

#include "wbaes.hpp"

namespace anti_tamper {
namespace wb_crypto {

inline bool ctr_crypt(const uint8_t* in, uint8_t* out, size_t len,
                      const uint8_t iv[16])
{
    return wbaes::ctr_crypt(in, out, len, iv);
}

inline bool gcm_encrypt(const uint8_t* plaintext, size_t pt_len,
                        const uint8_t* aad, size_t aad_len,
                        const uint8_t nonce[12],
                        uint8_t* ciphertext,
                        uint8_t tag[16])
{
    if (wbaes::is_fallback_mode())
    {
        uint8_t ver_key[16];
        wbaes::get_verification_key(ver_key);
        bool ok = wbaes::bcrypt_aes128_gcm_encrypt(
            plaintext, pt_len, aad, aad_len, ver_key, nonce, ciphertext, tag);
        SecureZeroMemory(ver_key, sizeof(ver_key));
        return ok;
    }
    return wbaes::gcm_encrypt(plaintext, pt_len, aad, aad_len, nonce, ciphertext, tag);
}

inline bool gcm_decrypt(const uint8_t* ciphertext, size_t ct_len,
                        const uint8_t* aad, size_t aad_len,
                        const uint8_t nonce[12],
                        const uint8_t tag[16],
                        uint8_t* plaintext)
{
    if (wbaes::is_fallback_mode())
    {
        uint8_t ver_key[16];
        wbaes::get_verification_key(ver_key);
        bool ok = wbaes::bcrypt_aes128_gcm_decrypt(
            ciphertext, ct_len, aad, aad_len, ver_key, nonce, tag, plaintext);
        SecureZeroMemory(ver_key, sizeof(ver_key));
        return ok;
    }
    return wbaes::gcm_decrypt(ciphertext, ct_len, aad, aad_len, nonce, tag, plaintext);
}

inline bool initialize()
{
    if (!wbaes::initialize_tables()) return false;
    if (!wbaes::verify_test_vector()) return false;
    if (!wbaes::verify_table_hash()) return false;
    return true;
}

inline bool periodic_verify()
{
    return wbaes::verify_table_hash();
}

inline void get_table_hash(uint8_t out[32])
{
    wbaes::get_table_hash(out);
}

inline bool is_fallback_active()
{
    return wbaes::is_fallback_mode();
}

inline void set_fallback(bool mode)
{
    wbaes::set_fallback_mode(mode);
}

inline void set_fallback_token(const uint8_t token[64])
{
    wbaes::set_fallback_token(token);
}

}
}
