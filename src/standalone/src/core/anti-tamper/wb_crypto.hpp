#pragma once

#include "wbaes.hpp"
#include "blake3.hpp"

#include <vector>

namespace anti_tamper {
namespace wb_crypto {

namespace detail_wbc {

constexpr uint8_t kGhashHalfA = 0xC0;
constexpr uint8_t kGhashHalfB = 0x21;
constexpr uint8_t kIpad = 0x36;
constexpr uint8_t kOpad = 0x5C;
constexpr int kHmacBlockSize = 64;

__forceinline void gf_mul(
    const uint8_t x[16], const uint8_t y[16], uint8_t z_out[16])
{
    uint8_t z[16] = {0};
    uint8_t v[16];
    std::memcpy(v, y, 16);
    uint8_t reduction = static_cast<uint8_t>(kGhashHalfA | kGhashHalfB);

    for (int i = 0; i < 128; ++i)
    {
        uint8_t bit = static_cast<uint8_t>(
            (x[i >> 3] >> (7 - (i & 7))) & 1);
        if (bit)
        {
            for (int j = 0; j < 16; ++j)
                z[j] ^= v[j];
        }
        uint8_t lsb = static_cast<uint8_t>(v[15] & 1);
        for (int j = 15; j > 0; --j)
        {
            v[j] = static_cast<uint8_t>(
                (v[j] >> 1) | ((v[j - 1] & 1) << 7));
        }
        v[0] >>= 1;
        if (lsb) v[0] ^= reduction;
    }
    std::memcpy(z_out, z, 16);
    SecureZeroMemory(z, sizeof(z));
    SecureZeroMemory(v, sizeof(v));
}

__forceinline void ghash_update(
    const uint8_t H[16], const uint8_t* data, size_t len,
    uint8_t y[16])
{
    size_t full = len / 16;
    for (size_t i = 0; i < full; ++i)
    {
        for (int j = 0; j < 16; ++j)
            y[j] ^= data[i * 16 + j];
        uint8_t t[16];
        gf_mul(y, H, t);
        std::memcpy(y, t, 16);
        SecureZeroMemory(t, sizeof(t));
    }
    size_t rem = len % 16;
    if (rem)
    {
        uint8_t last[16] = {0};
        for (size_t j = 0; j < rem; ++j)
            last[j] = data[full * 16 + j];
        for (int j = 0; j < 16; ++j)
            y[j] ^= last[j];
        uint8_t t[16];
        gf_mul(y, H, t);
        std::memcpy(y, t, 16);
        SecureZeroMemory(t, sizeof(t));
        SecureZeroMemory(last, sizeof(last));
    }
}

__forceinline void inc32(uint8_t ctr[16])
{
    uint32_t c = (static_cast<uint32_t>(ctr[12]) << 24) |
                 (static_cast<uint32_t>(ctr[13]) << 16) |
                 (static_cast<uint32_t>(ctr[14]) << 8)  |
                 (static_cast<uint32_t>(ctr[15]));
    c += 1;
    ctr[12] = static_cast<uint8_t>(c >> 24);
    ctr[13] = static_cast<uint8_t>(c >> 16);
    ctr[14] = static_cast<uint8_t>(c >> 8);
    ctr[15] = static_cast<uint8_t>(c);
}

}

inline bool ctr_crypt(const uint8_t* in, uint8_t* out, size_t len,
                      const uint8_t iv[16])
{
    if (!iv) return false;
    if (len > 0 && (!in || !out)) return false;

    if (wbaes::is_fallback_mode())
    {
        uint8_t ver_key[16];
        wbaes::get_verification_key(ver_key);
        bool ok = wbaes::bcrypt_aes128_ctr(in, out, len, ver_key, iv);
        SecureZeroMemory(ver_key, sizeof(ver_key));
        return ok;
    }

    const auto& tbl = wbaes::get_tables();
    uint8_t counter[16];
    std::memcpy(counter, iv, 16);
    uint8_t ks[16];
    size_t off = 0;
    while (off < len)
    {
        wbaes::encrypt_block(tbl, counter, ks);
        for (int i = 15; i >= 0; --i)
        {
            if (++counter[i] != 0) break;
        }
        size_t bl = (len - off > 16) ? 16 : (len - off);
        for (size_t i = 0; i < bl; ++i)
            out[off + i] = static_cast<uint8_t>(in[off + i] ^ ks[i]);
        off += bl;
    }
    SecureZeroMemory(counter, sizeof(counter));
    SecureZeroMemory(ks, sizeof(ks));
    return true;
}

inline bool gcm_encrypt(const uint8_t* plaintext, size_t pt_len,
                        const uint8_t* aad, size_t aad_len,
                        const uint8_t nonce[12],
                        uint8_t* ciphertext,
                        uint8_t tag[16])
{
    if (!nonce) return false;
    if (pt_len > 0 && (!plaintext || !ciphertext)) return false;

    if (wbaes::is_fallback_mode())
    {
        uint8_t ver_key[16];
        wbaes::get_verification_key(ver_key);
        bool ok = wbaes::bcrypt_aes128_gcm_encrypt(
            plaintext, pt_len, aad, aad_len,
            ver_key, nonce, ciphertext, tag);
        SecureZeroMemory(ver_key, sizeof(ver_key));
        return ok;
    }

    const auto& tbl = wbaes::get_tables();

    uint8_t H[16] = {0};
    uint8_t zero[16] = {0};
    wbaes::encrypt_block(tbl, zero, H);

    uint8_t j0[16] = {0};
    std::memcpy(j0, nonce, 12);
    j0[15] = 1;

    uint8_t ctr[16];
    std::memcpy(ctr, j0, 16);
    detail_wbc::inc32(ctr);

    size_t full = pt_len / 16;
    size_t rem = pt_len % 16;
    for (size_t i = 0; i < full; ++i)
    {
        uint8_t ks[16];
        wbaes::encrypt_block(tbl, ctr, ks);
        for (int j = 0; j < 16; ++j)
            ciphertext[i * 16 + j] =
                static_cast<uint8_t>(plaintext[i * 16 + j] ^ ks[j]);
        detail_wbc::inc32(ctr);
        SecureZeroMemory(ks, sizeof(ks));
    }
    if (rem)
    {
        uint8_t ks[16];
        wbaes::encrypt_block(tbl, ctr, ks);
        for (size_t j = 0; j < rem; ++j)
            ciphertext[full * 16 + j] =
                static_cast<uint8_t>(plaintext[full * 16 + j] ^ ks[j]);
        SecureZeroMemory(ks, sizeof(ks));
    }

    uint8_t y[16] = {0};
    if (aad && aad_len > 0)
        detail_wbc::ghash_update(H, aad, aad_len, y);
    if (pt_len > 0)
        detail_wbc::ghash_update(H, ciphertext, pt_len, y);

    uint8_t len_blk[16] = {0};
    uint64_t aad_bits = static_cast<uint64_t>(aad_len) * 8;
    uint64_t ct_bits  = static_cast<uint64_t>(pt_len) * 8;
    for (int i = 7; i >= 0; --i)
        len_blk[7 - i] = static_cast<uint8_t>(aad_bits >> (i * 8));
    for (int i = 7; i >= 0; --i)
        len_blk[15 - i] = static_cast<uint8_t>(ct_bits >> (i * 8));
    for (int j = 0; j < 16; ++j)
        y[j] ^= len_blk[j];

    uint8_t ghash_tag[16];
    detail_wbc::gf_mul(y, H, ghash_tag);

    uint8_t ej0[16];
    wbaes::encrypt_block(tbl, j0, ej0);
    for (int j = 0; j < 16; ++j)
        tag[j] = static_cast<uint8_t>(ghash_tag[j] ^ ej0[j]);

    SecureZeroMemory(H, sizeof(H));
    SecureZeroMemory(j0, sizeof(j0));
    SecureZeroMemory(ctr, sizeof(ctr));
    SecureZeroMemory(y, sizeof(y));
    SecureZeroMemory(ghash_tag, sizeof(ghash_tag));
    SecureZeroMemory(ej0, sizeof(ej0));
    SecureZeroMemory(len_blk, sizeof(len_blk));
    return true;
}

inline bool gcm_decrypt(const uint8_t* ciphertext, size_t ct_len,
                        const uint8_t* aad, size_t aad_len,
                        const uint8_t nonce[12],
                        const uint8_t tag[16],
                        uint8_t* plaintext)
{
    if (!nonce || !tag) return false;
    if (ct_len > 0 && (!ciphertext || !plaintext)) return false;

    if (wbaes::is_fallback_mode())
    {
        uint8_t ver_key[16];
        wbaes::get_verification_key(ver_key);
        bool ok = wbaes::bcrypt_aes128_gcm_decrypt(
            ciphertext, ct_len, aad, aad_len,
            ver_key, nonce, tag, plaintext);
        SecureZeroMemory(ver_key, sizeof(ver_key));
        return ok;
    }

    const auto& tbl = wbaes::get_tables();

    uint8_t H[16] = {0};
    uint8_t zero[16] = {0};
    wbaes::encrypt_block(tbl, zero, H);

    uint8_t j0[16] = {0};
    std::memcpy(j0, nonce, 12);
    j0[15] = 1;

    uint8_t y[16] = {0};
    if (aad && aad_len > 0)
        detail_wbc::ghash_update(H, aad, aad_len, y);
    if (ct_len > 0)
        detail_wbc::ghash_update(H, ciphertext, ct_len, y);

    uint8_t len_blk[16] = {0};
    uint64_t aad_bits = static_cast<uint64_t>(aad_len) * 8;
    uint64_t ct_bits  = static_cast<uint64_t>(ct_len) * 8;
    for (int i = 7; i >= 0; --i)
        len_blk[7 - i] = static_cast<uint8_t>(aad_bits >> (i * 8));
    for (int i = 7; i >= 0; --i)
        len_blk[15 - i] = static_cast<uint8_t>(ct_bits >> (i * 8));
    for (int j = 0; j < 16; ++j)
        y[j] ^= len_blk[j];

    uint8_t ghash_tag[16];
    detail_wbc::gf_mul(y, H, ghash_tag);

    uint8_t ej0[16];
    wbaes::encrypt_block(tbl, j0, ej0);
    uint8_t expected_tag[16];
    for (int j = 0; j < 16; ++j)
        expected_tag[j] = static_cast<uint8_t>(ghash_tag[j] ^ ej0[j]);

    volatile uint8_t diff = 0;
    for (int j = 0; j < 16; ++j)
        diff |= static_cast<uint8_t>(expected_tag[j] ^ tag[j]);

    if (diff != 0)
    {
        SecureZeroMemory(H, sizeof(H));
        SecureZeroMemory(j0, sizeof(j0));
        SecureZeroMemory(y, sizeof(y));
        SecureZeroMemory(ghash_tag, sizeof(ghash_tag));
        SecureZeroMemory(ej0, sizeof(ej0));
        SecureZeroMemory(expected_tag, sizeof(expected_tag));
        SecureZeroMemory(len_blk, sizeof(len_blk));
        return false;
    }

    uint8_t ctr[16];
    std::memcpy(ctr, j0, 16);
    detail_wbc::inc32(ctr);

    size_t full = ct_len / 16;
    size_t rem = ct_len % 16;
    for (size_t i = 0; i < full; ++i)
    {
        uint8_t ks[16];
        wbaes::encrypt_block(tbl, ctr, ks);
        for (int j = 0; j < 16; ++j)
            plaintext[i * 16 + j] =
                static_cast<uint8_t>(ciphertext[i * 16 + j] ^ ks[j]);
        detail_wbc::inc32(ctr);
        SecureZeroMemory(ks, sizeof(ks));
    }
    if (rem)
    {
        uint8_t ks[16];
        wbaes::encrypt_block(tbl, ctr, ks);
        for (size_t j = 0; j < rem; ++j)
            plaintext[full * 16 + j] =
                static_cast<uint8_t>(ciphertext[full * 16 + j] ^ ks[j]);
        SecureZeroMemory(ks, sizeof(ks));
    }

    SecureZeroMemory(H, sizeof(H));
    SecureZeroMemory(j0, sizeof(j0));
    SecureZeroMemory(ctr, sizeof(ctr));
    SecureZeroMemory(y, sizeof(y));
    SecureZeroMemory(ghash_tag, sizeof(ghash_tag));
    SecureZeroMemory(ej0, sizeof(ej0));
    SecureZeroMemory(expected_tag, sizeof(expected_tag));
    SecureZeroMemory(len_blk, sizeof(len_blk));
    return true;
}

inline void hmac(const uint8_t* data, size_t len, uint8_t out[32])
{
    uint8_t key[32];
    wbaes::get_table_hash(key);

    uint8_t key_block[kHmacBlockSize] = {0};
    std::memcpy(key_block, key, 32);

    uint8_t ipad_key[kHmacBlockSize];
    uint8_t opad_key[kHmacBlockSize];
    for (int i = 0; i < kHmacBlockSize; ++i)
    {
        ipad_key[i] = static_cast<uint8_t>(
            key_block[i] ^ detail_wbc::kIpad);
        opad_key[i] = static_cast<uint8_t>(
            key_block[i] ^ detail_wbc::kOpad);
    }

    std::vector<uint8_t> inner_buf(
        static_cast<size_t>(kHmacBlockSize) + len);
    std::memcpy(inner_buf.data(), ipad_key, kHmacBlockSize);
    if (len > 0 && data)
        std::memcpy(inner_buf.data() + kHmacBlockSize, data, len);

    uint8_t inner_hash[32];
    blake3::hash(inner_buf.data(), inner_buf.size(), inner_hash);

    uint8_t outer_buf[kHmacBlockSize + 32];
    std::memcpy(outer_buf, opad_key, kHmacBlockSize);
    std::memcpy(outer_buf + kHmacBlockSize, inner_hash, 32);

    blake3::hash(outer_buf, sizeof(outer_buf), out);

    SecureZeroMemory(key, sizeof(key));
    SecureZeroMemory(key_block, sizeof(key_block));
    SecureZeroMemory(ipad_key, sizeof(ipad_key));
    SecureZeroMemory(opad_key, sizeof(opad_key));
    SecureZeroMemory(inner_hash, sizeof(inner_hash));
    SecureZeroMemory(outer_buf, sizeof(outer_buf));
    std::fill(inner_buf.begin(), inner_buf.end(),
              static_cast<uint8_t>(0));
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
