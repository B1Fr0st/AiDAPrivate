#pragma once

#ifndef NOMINMAX
#define NOMINMAX
#endif
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif

#include <windows.h>
#include <intrin.h>
#include <bcrypt.h>

#include <atomic>
#include <cstdint>
#include <cstddef>
#include <cstring>
#include <mutex>
#include <string>

#include "blake3.hpp"

#pragma comment(lib, "bcrypt.lib")

namespace anti_tamper {
namespace wbaes {

namespace detail_wb {

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

constexpr uint8_t kGhashHalfA = 0xC0;
constexpr uint8_t kGhashHalfB = 0x21;

__forceinline int sr_source_col(int target_col, int row)
{
    return (target_col + row) & 3;
}

__forceinline int sr_source_index(int target_col, int row)
{
    return sr_source_col(target_col, row) * 4 + row;
}

}

struct white_box_table_t {
    uint8_t  t_boxes[10][16][256];
    uint32_t mb_tables[9][16][256];
    uint8_t  ext_in[16];
    uint8_t  ext_out[16];
    uint8_t  table_id[16];
    uint8_t  t_xor_keys[10][16][32];
    uint8_t  mb_xor_keys[9][16][32];
};

struct white_box_table_masked_t {
    uint8_t  t_boxes_s1[10][16][256];
    uint8_t  t_boxes_s2[10][16][256];
    uint32_t mb_tables_s1[9][16][256];
    uint32_t mb_tables_s2[9][16][256];
    uint8_t  ext_in[16];
    uint8_t  ext_out[16];
    uint8_t  table_id[16];
    uint8_t  input_masks[10][16];
    uint8_t  output_masks[10][16];
    uint8_t  t_xor_keys_s1[10][16][32];
    uint8_t  t_xor_keys_s2[10][16][32];
    uint8_t  mb_xor_keys_s1[9][16][32];
    uint8_t  mb_xor_keys_s2[9][16][32];
};

#include "wbaes_generated_tables.hpp"

namespace detail_wb {

__forceinline uint8_t t_box_lookup(
    const white_box_table_t& tbl,
    int round, int pos, uint8_t input)
{
    uint8_t encoded = tbl.t_boxes[round][pos][input];
    return static_cast<uint8_t>(encoded ^ tbl.t_xor_keys[round][pos][0]);
}

__forceinline uint32_t mb_table_lookup(
    const white_box_table_t& tbl,
    int round, int pos, uint8_t input)
{
    uint32_t encoded = tbl.mb_tables[round][pos][input];
    uint32_t key;
    std::memcpy(&key, tbl.mb_xor_keys[round][pos], 4);
    return encoded ^ key;
}

constexpr int k_col_order[9][4] = {
    {0, 1, 2, 3}, {0, 1, 2, 3}, {0, 1, 2, 3},
    {0, 1, 2, 3}, {0, 1, 2, 3}, {0, 1, 2, 3},
    {0, 1, 2, 3}, {0, 1, 2, 3}, {0, 1, 2, 3},
};

__forceinline uint8_t t_box_lookup_s1(
    const white_box_table_masked_t& tbl,
    int round, int pos, uint8_t input)
{
    uint8_t encoded = tbl.t_boxes_s1[round][pos][input];
    return static_cast<uint8_t>(encoded ^ tbl.t_xor_keys_s1[round][pos][0]);
}

__forceinline uint8_t t_box_lookup_s2(
    const white_box_table_masked_t& tbl,
    int round, int pos, uint8_t input)
{
    uint8_t encoded = tbl.t_boxes_s2[round][pos][input];
    return static_cast<uint8_t>(encoded ^ tbl.t_xor_keys_s2[round][pos][0]);
}

__forceinline uint32_t mb_table_lookup_s1(
    const white_box_table_masked_t& tbl,
    int round, int pos, uint8_t input)
{
    uint32_t encoded = tbl.mb_tables_s1[round][pos][input];
    uint32_t key;
    std::memcpy(&key, tbl.mb_xor_keys_s1[round][pos], 4);
    return encoded ^ key;
}

__forceinline uint32_t mb_table_lookup_s2(
    const white_box_table_masked_t& tbl,
    int round, int pos, uint8_t input)
{
    uint32_t encoded = tbl.mb_tables_s2[round][pos][input];
    uint32_t key;
    std::memcpy(&key, tbl.mb_xor_keys_s2[round][pos], 4);
    return encoded ^ key;
}

__forceinline void gcm_gf_mul_wb(
    const uint8_t x[16], const uint8_t y[16], uint8_t z_out[16],
    uint8_t half_a, uint8_t half_b)
{
    uint8_t z[16] = {0};
    uint8_t v[16];
    std::memcpy(v, y, 16);
    uint8_t reduction = static_cast<uint8_t>(half_a | half_b);

    for (int i = 0; i < 128; ++i)
    {
        uint8_t bit = static_cast<uint8_t>((x[i >> 3] >> (7 - (i & 7))) & 1);
        if (bit)
        {
            for (int j = 0; j < 16; ++j)
                z[j] ^= v[j];
        }
        uint8_t lsb = static_cast<uint8_t>(v[15] & 1);
        for (int j = 15; j > 0; --j)
        {
            v[j] = static_cast<uint8_t>((v[j] >> 1) | ((v[j - 1] & 1) << 7));
        }
        v[0] >>= 1;
        if (lsb) v[0] ^= reduction;
    }
    std::memcpy(z_out, z, 16);
    SecureZeroMemory(z, sizeof(z));
    SecureZeroMemory(v, sizeof(v));
}

__forceinline void ghash_update_wb(
    const uint8_t H[16], const uint8_t* data, size_t len,
    uint8_t y[16], uint8_t half_a, uint8_t half_b)
{
    size_t full = len / 16;
    for (size_t i = 0; i < full; ++i)
    {
        for (int j = 0; j < 16; ++j)
            y[j] ^= data[i * 16 + j];
        uint8_t t[16];
        gcm_gf_mul_wb(y, H, t, half_a, half_b);
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
        gcm_gf_mul_wb(y, H, t, half_a, half_b);
        std::memcpy(y, t, 16);
        SecureZeroMemory(t, sizeof(t));
        SecureZeroMemory(last, sizeof(last));
    }
}

__forceinline void gcm_inc32_wb(uint8_t ctr[16])
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

inline std::atomic<bool>& s_fallback_mode()
{
    static std::atomic<bool> v{false};
    return v;
}

inline uint8_t (&s_fallback_token())[64]
{
    static uint8_t t[64] = {};
    return t;
}

inline std::mutex& s_fallback_mtx()
{
    static std::mutex m;
    return m;
}

inline uint8_t (&s_table_hash())[32]
{
    static uint8_t h[32] = {};
    return h;
}

inline std::atomic<bool>& s_tables_ready()
{
    static std::atomic<bool> v{false};
    return v;
}

inline std::once_flag& s_init_once()
{
    static std::once_flag f;
    return f;
}

}

inline const char* last_error()
{
    return detail_wb::s_last_error_storage().c_str();
}

inline void encrypt_block(
    const white_box_table_t& tbl,
    const uint8_t in[16], uint8_t out[16])
{
    uint8_t state[16];
    for (int i = 0; i < 16; ++i)
        state[i] = static_cast<uint8_t>(in[i] ^ tbl.ext_in[i]);

    for (int r = 0; r < 9; ++r)
    {
        uint8_t next[16];
        for (int c = 0; c < 4; ++c)
        {
            uint32_t col = 0;
            for (int i = 0; i < 4; ++i)
            {
                int src_idx = detail_wb::sr_source_index(c, i);
                int pos = c * 4 + i;
                col ^= detail_wb::mb_table_lookup(tbl, r, pos, state[src_idx]);
            }
            next[c * 4 + 0] = static_cast<uint8_t>((col >> 24) & 0xFFu);
            next[c * 4 + 1] = static_cast<uint8_t>((col >> 16) & 0xFFu);
            next[c * 4 + 2] = static_cast<uint8_t>((col >> 8) & 0xFFu);
            next[c * 4 + 3] = static_cast<uint8_t>(col & 0xFFu);
        }
        std::memcpy(state, next, 16);
        SecureZeroMemory(next, sizeof(next));
    }

    for (int c = 0; c < 4; ++c)
    {
        for (int i = 0; i < 4; ++i)
        {
            int src_idx = detail_wb::sr_source_index(c, i);
            int pos = c * 4 + i;
            out[pos] = detail_wb::t_box_lookup(tbl, 9, pos, state[src_idx]);
        }
    }

    SecureZeroMemory(state, sizeof(state));
}

inline void encrypt_block_masked(
    const white_box_table_masked_t& tbl,
    const uint8_t in[16], uint8_t out[16])
{
    uint8_t state[16];
    for (int i = 0; i < 16; ++i)
        state[i] = static_cast<uint8_t>(in[i] ^ tbl.ext_in[i]);

    for (int r = 0; r < 9; ++r)
    {
        uint8_t next[16];
        for (int col_idx = 0; col_idx < 4; ++col_idx)
        {
            int c = detail_wb::k_col_order[r][col_idx];
            uint32_t col = 0;
            for (int i = 0; i < 4; ++i)
            {
                int src_idx = detail_wb::sr_source_index(c, i);
                int pos = c * 4 + i;
                uint8_t masked_idx = static_cast<uint8_t>(
                    state[src_idx] ^ tbl.input_masks[r][src_idx]);

                col ^= detail_wb::mb_table_lookup_s1(tbl, r, pos, masked_idx);
                col ^= detail_wb::mb_table_lookup_s2(tbl, r, pos, masked_idx);

                volatile uint32_t dummy1 =
                    tbl.mb_tables_s1[r][pos][static_cast<uint8_t>(masked_idx ^ 0x5Au)];
                volatile uint32_t dummy2 =
                    tbl.mb_tables_s2[r][pos][static_cast<uint8_t>(masked_idx ^ 0xA5u)];
                (void)dummy1;
                (void)dummy2;
            }
            next[c * 4 + 0] = static_cast<uint8_t>((col >> 24) & 0xFFu);
            next[c * 4 + 1] = static_cast<uint8_t>((col >> 16) & 0xFFu);
            next[c * 4 + 2] = static_cast<uint8_t>((col >> 8) & 0xFFu);
            next[c * 4 + 3] = static_cast<uint8_t>(col & 0xFFu);
        }
        std::memcpy(state, next, 16);
        SecureZeroMemory(next, sizeof(next));
    }

    for (int c = 0; c < 4; ++c)
    {
        for (int i = 0; i < 4; ++i)
        {
            int src_idx = detail_wb::sr_source_index(c, i);
            int pos = c * 4 + i;
            uint8_t masked_idx = static_cast<uint8_t>(
                state[src_idx] ^ tbl.input_masks[9][src_idx]);

            uint8_t s1_val = detail_wb::t_box_lookup_s1(tbl, 9, pos, masked_idx);
            uint8_t s2_val = detail_wb::t_box_lookup_s2(tbl, 9, pos, masked_idx);
            out[pos] = static_cast<uint8_t>(s1_val ^ s2_val ^ tbl.ext_out[pos]);

            volatile uint8_t dummy1 =
                tbl.t_boxes_s1[9][pos][static_cast<uint8_t>(masked_idx ^ 0x5Au)];
            volatile uint8_t dummy2 =
                tbl.t_boxes_s2[9][pos][static_cast<uint8_t>(masked_idx ^ 0xA5u)];
            (void)dummy1;
            (void)dummy2;
        }
    }

    SecureZeroMemory(state, sizeof(state));
}

inline bool encrypt_ctr(
    const white_box_table_t& tbl,
    const uint8_t iv[16],
    const uint8_t* in, uint8_t* out, size_t len)
{
    if (len > 0 && (!in || !out))
    {
        detail_wb::set_last_error("encrypt_ctr_invalid_args");
        return false;
    }
    if (!iv)
    {
        detail_wb::set_last_error("encrypt_ctr_invalid_iv");
        return false;
    }

    uint8_t counter[16];
    std::memcpy(counter, iv, 16);
    uint8_t ks[16];
    size_t off = 0;
    while (off < len)
    {
        encrypt_block(tbl, counter, ks);
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
    detail_wb::set_last_error(nullptr);
    return true;
}

inline bool gcm_encrypt(
    const uint8_t* plaintext, size_t pt_len,
    const uint8_t* aad, size_t aad_len,
    const uint8_t nonce[12],
    uint8_t* ciphertext,
    uint8_t tag[16])
{
    if (!nonce) return false;
    if (pt_len > 0 && (!plaintext || !ciphertext)) return false;

    const auto& tbl = get_tables();

    uint8_t H[16] = {0};
    uint8_t zero[16] = {0};
    encrypt_block(tbl, zero, H);

    uint8_t j0[16] = {0};
    std::memcpy(j0, nonce, 12);
    j0[15] = 1;

    uint8_t ctr[16];
    std::memcpy(ctr, j0, 16);
    detail_wb::gcm_inc32_wb(ctr);

    size_t full = pt_len / 16;
    size_t rem = pt_len % 16;
    for (size_t i = 0; i < full; ++i)
    {
        uint8_t ks[16];
        encrypt_block(tbl, ctr, ks);
        for (int j = 0; j < 16; ++j)
            ciphertext[i * 16 + j] = static_cast<uint8_t>(plaintext[i * 16 + j] ^ ks[j]);
        detail_wb::gcm_inc32_wb(ctr);
        SecureZeroMemory(ks, sizeof(ks));
    }
    if (rem)
    {
        uint8_t ks[16];
        encrypt_block(tbl, ctr, ks);
        for (size_t j = 0; j < rem; ++j)
            ciphertext[full * 16 + j] = static_cast<uint8_t>(plaintext[full * 16 + j] ^ ks[j]);
        SecureZeroMemory(ks, sizeof(ks));
    }

    uint8_t y[16] = {0};
    if (aad && aad_len > 0)
        detail_wb::ghash_update_wb(H, aad, aad_len, y, detail_wb::kGhashHalfA, detail_wb::kGhashHalfB);
    if (pt_len > 0)
        detail_wb::ghash_update_wb(H, ciphertext, pt_len, y, detail_wb::kGhashHalfA, detail_wb::kGhashHalfB);

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
    detail_wb::gcm_gf_mul_wb(y, H, ghash_tag, detail_wb::kGhashHalfA, detail_wb::kGhashHalfB);

    uint8_t ej0[16];
    encrypt_block(tbl, j0, ej0);
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

inline bool gcm_decrypt(
    const uint8_t* ciphertext, size_t ct_len,
    const uint8_t* aad, size_t aad_len,
    const uint8_t nonce[12],
    const uint8_t tag[16],
    uint8_t* plaintext)
{
    if (!nonce || !tag) return false;
    if (ct_len > 0 && (!ciphertext || !plaintext)) return false;

    const auto& tbl = get_tables();

    uint8_t H[16] = {0};
    uint8_t zero[16] = {0};
    encrypt_block(tbl, zero, H);

    uint8_t j0[16] = {0};
    std::memcpy(j0, nonce, 12);
    j0[15] = 1;

    uint8_t y[16] = {0};
    if (aad && aad_len > 0)
        detail_wb::ghash_update_wb(H, aad, aad_len, y, detail_wb::kGhashHalfA, detail_wb::kGhashHalfB);
    if (ct_len > 0)
        detail_wb::ghash_update_wb(H, ciphertext, ct_len, y, detail_wb::kGhashHalfA, detail_wb::kGhashHalfB);

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
    detail_wb::gcm_gf_mul_wb(y, H, ghash_tag, detail_wb::kGhashHalfA, detail_wb::kGhashHalfB);

    uint8_t ej0[16];
    encrypt_block(tbl, j0, ej0);
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
        detail_wb::set_last_error("gcm_decrypt_tag_mismatch");
        return false;
    }

    uint8_t ctr[16];
    std::memcpy(ctr, j0, 16);
    detail_wb::gcm_inc32_wb(ctr);

    size_t full = ct_len / 16;
    size_t rem = ct_len % 16;
    for (size_t i = 0; i < full; ++i)
    {
        uint8_t ks[16];
        encrypt_block(tbl, ctr, ks);
        for (int j = 0; j < 16; ++j)
            plaintext[i * 16 + j] = static_cast<uint8_t>(ciphertext[i * 16 + j] ^ ks[j]);
        detail_wb::gcm_inc32_wb(ctr);
        SecureZeroMemory(ks, sizeof(ks));
    }
    if (rem)
    {
        uint8_t ks[16];
        encrypt_block(tbl, ctr, ks);
        for (size_t j = 0; j < rem; ++j)
            plaintext[full * 16 + j] = static_cast<uint8_t>(ciphertext[full * 16 + j] ^ ks[j]);
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

inline void compute_table_hash(const white_box_table_t& tbl, uint8_t out[32])
{
    blake3::hash(reinterpret_cast<const uint8_t*>(&tbl), sizeof(white_box_table_t), out);
}

inline bool is_fallback_mode()
{
    return detail_wb::s_fallback_mode().load(std::memory_order_acquire);
}

inline void set_fallback_mode(bool mode)
{
    detail_wb::s_fallback_mode().store(mode, std::memory_order_release);
}

inline void set_fallback_token(const uint8_t token[64])
{
    std::lock_guard<std::mutex> lk(detail_wb::s_fallback_mtx());
    std::memcpy(detail_wb::s_fallback_token(), token, 64);
}

inline void get_fallback_token(uint8_t token[64])
{
    std::lock_guard<std::mutex> lk(detail_wb::s_fallback_mtx());
    std::memcpy(token, detail_wb::s_fallback_token(), 64);
}

inline void get_table_hash(uint8_t out[32])
{
    std::memcpy(out, detail_wb::s_table_hash(), 32);
}

inline bool bcrypt_aes128_ecb(
    const uint8_t in[16], const uint8_t key[16], uint8_t out[16])
{
    BCRYPT_ALG_HANDLE hAlg = nullptr;
    BCRYPT_KEY_HANDLE hKey = nullptr;
    NTSTATUS st = BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_AES_ALGORITHM, nullptr, 0);
    if (!BCRYPT_SUCCESS(st) || !hAlg) return false;

    st = BCryptSetProperty(hAlg, BCRYPT_CHAINING_MODE,
        reinterpret_cast<PUCHAR>(const_cast<wchar_t*>(BCRYPT_CHAIN_MODE_ECB)),
        static_cast<ULONG>(wcslen(BCRYPT_CHAIN_MODE_ECB) * sizeof(wchar_t) + sizeof(wchar_t)), 0);
    if (!BCRYPT_SUCCESS(st))
    {
        BCryptCloseAlgorithmProvider(hAlg, 0);
        return false;
    }

    st = BCryptGenerateSymmetricKey(hAlg, &hKey, nullptr, 0,
        const_cast<PUCHAR>(key), 16, 0);
    if (!BCRYPT_SUCCESS(st) || !hKey)
    {
        BCryptCloseAlgorithmProvider(hAlg, 0);
        return false;
    }

    ULONG bytes_done = 0;
    st = BCryptEncrypt(hKey,
        const_cast<PUCHAR>(in), 16,
        nullptr, nullptr, 0,
        out, 16, &bytes_done, 0);

    BCryptDestroyKey(hKey);
    BCryptCloseAlgorithmProvider(hAlg, 0);

    return BCRYPT_SUCCESS(st) && bytes_done == 16;
}

inline bool bcrypt_aes128_ctr(
    const uint8_t* in, uint8_t* out, size_t len,
    const uint8_t key[16], const uint8_t iv[16])
{
    if (len == 0) return true;
    if (!in || !out || !key || !iv) return false;

    uint8_t counter[16];
    std::memcpy(counter, iv, 16);

    size_t off = 0;
    while (off < len)
    {
        uint8_t ks[16];
        if (!bcrypt_aes128_ecb(counter, key, ks))
        {
            SecureZeroMemory(counter, sizeof(counter));
            return false;
        }
        for (int i = 15; i >= 0; --i)
        {
            if (++counter[i] != 0) break;
        }
        size_t bl = (len - off > 16) ? 16 : (len - off);
        for (size_t i = 0; i < bl; ++i)
            out[off + i] = static_cast<uint8_t>(in[off + i] ^ ks[i]);
        off += bl;
        SecureZeroMemory(ks, sizeof(ks));
    }
    SecureZeroMemory(counter, sizeof(counter));
    return true;
}

inline bool bcrypt_aes128_gcm_encrypt(
    const uint8_t* plaintext, size_t pt_len,
    const uint8_t* aad, size_t aad_len,
    const uint8_t key[16], const uint8_t nonce[12],
    uint8_t* ciphertext, uint8_t tag[16])
{
    BCRYPT_ALG_HANDLE hAlg = nullptr;
    BCRYPT_KEY_HANDLE hKey = nullptr;

    NTSTATUS st = BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_AES_ALGORITHM, nullptr, 0);
    if (!BCRYPT_SUCCESS(st)) return false;

    st = BCryptSetProperty(hAlg, BCRYPT_CHAINING_MODE,
        reinterpret_cast<PUCHAR>(const_cast<wchar_t*>(BCRYPT_CHAIN_MODE_GCM)),
        static_cast<ULONG>(wcslen(BCRYPT_CHAIN_MODE_GCM) * sizeof(wchar_t) + sizeof(wchar_t)), 0);
    if (!BCRYPT_SUCCESS(st))
    {
        BCryptCloseAlgorithmProvider(hAlg, 0);
        return false;
    }

    st = BCryptGenerateSymmetricKey(hAlg, &hKey, nullptr, 0,
        const_cast<PUCHAR>(key), 16, 0);
    if (!BCRYPT_SUCCESS(st) || !hKey)
    {
        BCryptCloseAlgorithmProvider(hAlg, 0);
        return false;
    }

    BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO info;
    BCRYPT_INIT_AUTH_MODE_INFO(info);
    info.pbNonce = const_cast<PUCHAR>(nonce);
    info.cbNonce = 12;
    info.pbAuthData = aad ? const_cast<PUCHAR>(aad) : nullptr;
    info.cbAuthData = static_cast<ULONG>(aad_len);
    info.pbTag = tag;
    info.cbTag = 16;

    ULONG bytes_done = 0;
    st = BCryptEncrypt(hKey,
        const_cast<PUCHAR>(plaintext), static_cast<ULONG>(pt_len),
        &info, nullptr, 0,
        ciphertext, static_cast<ULONG>(pt_len), &bytes_done, 0);

    BCryptDestroyKey(hKey);
    BCryptCloseAlgorithmProvider(hAlg, 0);
    return BCRYPT_SUCCESS(st);
}

inline bool bcrypt_aes128_gcm_decrypt(
    const uint8_t* ciphertext, size_t ct_len,
    const uint8_t* aad, size_t aad_len,
    const uint8_t key[16], const uint8_t nonce[12],
    const uint8_t tag[16], uint8_t* plaintext)
{
    BCRYPT_ALG_HANDLE hAlg = nullptr;
    BCRYPT_KEY_HANDLE hKey = nullptr;

    NTSTATUS st = BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_AES_ALGORITHM, nullptr, 0);
    if (!BCRYPT_SUCCESS(st)) return false;

    st = BCryptSetProperty(hAlg, BCRYPT_CHAINING_MODE,
        reinterpret_cast<PUCHAR>(const_cast<wchar_t*>(BCRYPT_CHAIN_MODE_GCM)),
        static_cast<ULONG>(wcslen(BCRYPT_CHAIN_MODE_GCM) * sizeof(wchar_t) + sizeof(wchar_t)), 0);
    if (!BCRYPT_SUCCESS(st))
    {
        BCryptCloseAlgorithmProvider(hAlg, 0);
        return false;
    }

    st = BCryptGenerateSymmetricKey(hAlg, &hKey, nullptr, 0,
        const_cast<PUCHAR>(key), 16, 0);
    if (!BCRYPT_SUCCESS(st) || !hKey)
    {
        BCryptCloseAlgorithmProvider(hAlg, 0);
        return false;
    }

    BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO info;
    BCRYPT_INIT_AUTH_MODE_INFO(info);
    info.pbNonce = const_cast<PUCHAR>(nonce);
    info.cbNonce = 12;
    info.pbAuthData = aad ? const_cast<PUCHAR>(aad) : nullptr;
    info.cbAuthData = static_cast<ULONG>(aad_len);
    info.pbTag = const_cast<PUCHAR>(tag);
    info.cbTag = 16;

    ULONG bytes_done = 0;
    st = BCryptDecrypt(hKey,
        const_cast<PUCHAR>(ciphertext), static_cast<ULONG>(ct_len),
        &info, nullptr, 0,
        plaintext, static_cast<ULONG>(ct_len), &bytes_done, 0);

    BCryptDestroyKey(hKey);
    BCryptCloseAlgorithmProvider(hAlg, 0);
    return BCRYPT_SUCCESS(st);
}

inline void get_verification_key(uint8_t key[16])
{
    for (int i = 0; i < 16; ++i)
        key[i] = static_cast<uint8_t>(kWbaesVerificationKeyObf[i] ^ kWbaesVerificationKeyXor[i]);
}

inline bool initialize_tables()
{
    if (detail_wb::s_tables_ready().load(std::memory_order_acquire))
        return true;

    bool success = false;
    std::call_once(detail_wb::s_init_once(), [&]() {
        std::memcpy(detail_wb::s_table_hash(), kWbaesTableHash, 32);
        detail_wb::s_tables_ready().store(true, std::memory_order_release);
        success = true;
    });

    return success;
}

inline const white_box_table_t& get_tables()
{
    if (!detail_wb::s_tables_ready().load(std::memory_order_acquire))
        initialize_tables();
    return kWbaesTables;
}

inline const white_box_table_masked_t& get_tables_masked()
{
    if (!detail_wb::s_tables_ready().load(std::memory_order_acquire))
        initialize_tables();
    return kWbaesTablesMasked;
}

inline bool verify_test_vector()
{
    const auto& tbl = get_tables();

    uint8_t result[16];
    encrypt_block(tbl, kWbaesTestVector, result);

    volatile uint8_t diff = 0;
    for (int i = 0; i < 16; ++i)
        diff |= static_cast<uint8_t>(result[i] ^ kWbaesTestVector[16 + i]);

    SecureZeroMemory(result, sizeof(result));

    if (diff != 0)
    {
        detail_wb::set_last_error("test_vector_mismatch");
        return false;
    }
    return true;
}

inline bool verify_table_hash()
{
    const auto& tbl = get_tables();

    uint8_t computed[32];
    compute_table_hash(tbl, computed);

    volatile uint8_t diff = 0;
    for (int i = 0; i < 32; ++i)
        diff |= static_cast<uint8_t>(computed[i] ^ kWbaesTableHash[i]);

    SecureZeroMemory(computed, sizeof(computed));

    if (diff != 0)
    {
        detail_wb::set_last_error("table_hash_mismatch");
        set_fallback_mode(true);
        return false;
    }
    return true;
}

inline bool ctr_crypt(
    const uint8_t* in, uint8_t* out, size_t len,
    const uint8_t iv[16])
{
    if (!iv) return false;
    if (len > 0 && (!in || !out)) return false;

    if (is_fallback_mode())
    {
        uint8_t ver_key[16];
        get_verification_key(ver_key);
        bool ok = bcrypt_aes128_ctr(in, out, len, ver_key, iv);
        SecureZeroMemory(ver_key, sizeof(ver_key));
        return ok;
    }

    const auto& tbl = get_tables();
    return encrypt_ctr(tbl, iv, in, out, len);
}

struct wbaes_challenge_t {
    uint8_t challenge_plaintext[16];
    uint8_t expected_ciphertext[16];
    uint8_t build_id[16];
    uint8_t fallback_mode;
    uint8_t fallback_token[64];
    uint8_t reserved[15];
};

inline bool compute_challenge_response(
    const uint8_t challenge[16],
    uint8_t response[16],
    bool& used_fallback)
{
    if (!challenge || !response) return false;

    if (is_fallback_mode())
    {
        used_fallback = true;
        uint8_t ver_key[16];
        get_verification_key(ver_key);
        bool ok = bcrypt_aes128_ecb(challenge, ver_key, response);
        SecureZeroMemory(ver_key, sizeof(ver_key));
        return ok;
    }

    used_fallback = false;
    const auto& tbl = get_tables();
    encrypt_block(tbl, challenge, response);
    return true;
}

inline void build_challenge_packet(
    const uint8_t challenge[16],
    wbaes_challenge_t& out_pkt)
{
    std::memcpy(out_pkt.challenge_plaintext, challenge, 16);

    bool used_fallback = false;
    compute_challenge_response(challenge, out_pkt.expected_ciphertext, used_fallback);

    out_pkt.fallback_mode = used_fallback ? 1 : 0;

    if (used_fallback)
        get_fallback_token(out_pkt.fallback_token);
    else
        std::memset(out_pkt.fallback_token, 0, 64);

    std::memcpy(out_pkt.build_id, kWbaesBuildId, 16);
    std::memset(out_pkt.reserved, 0, sizeof(out_pkt.reserved));
}

inline void shutdown_tables()
{
    detail_wb::s_tables_ready().store(false, std::memory_order_release);
    set_fallback_mode(false);
    SecureZeroMemory(detail_wb::s_table_hash(), 32);
}

}
}
