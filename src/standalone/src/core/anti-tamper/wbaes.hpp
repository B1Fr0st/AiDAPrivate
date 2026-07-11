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
#include "arc_build_seed.hpp"

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

__forceinline uint8_t gf_mul(uint8_t a, uint8_t b)
{
    uint8_t p = 0;
    for (int i = 0; i < 8; ++i)
    {
        if (b & 1u) p ^= a;
        uint8_t hi = a & 0x80u;
        a = static_cast<uint8_t>(a << 1);
        if (hi) a ^= 0x1Bu;
        b >>= 1;
    }
    return p;
}

__forceinline uint8_t gf_inv(uint8_t a)
{
    if (a == 0) return 0;
    for (int b = 1; b < 256; ++b)
    {
        if (gf_mul(static_cast<uint8_t>(a), static_cast<uint8_t>(b)) == 1)
            return static_cast<uint8_t>(b);
    }
    return 0;
}

__forceinline uint8_t sbox_entry(uint8_t input)
{
    uint8_t inv = gf_inv(input);
    uint8_t result = 0;
    for (int i = 0; i < 8; ++i)
    {
        uint8_t bit = static_cast<uint8_t>(
            ((inv >> i) & 1u) ^
            ((inv >> ((i + 4) % 8)) & 1u) ^
            ((inv >> ((i + 5) % 8)) & 1u) ^
            ((inv >> ((i + 6) % 8)) & 1u) ^
            ((inv >> ((i + 7) % 8)) & 1u) ^
            ((0x63u >> i) & 1u));
        result |= static_cast<uint8_t>(bit << i);
    }
    return result;
}

__forceinline uint8_t compute_rcon(int i)
{
    if (i == 0) return 0;
    uint8_t r = 1;
    for (int j = 1; j < i; ++j)
    {
        uint8_t hi = r & 0x80u;
        r = static_cast<uint8_t>(r << 1);
        if (hi) r ^= 0x1Bu;
    }
    return r;
}

__forceinline void compute_sbox(uint8_t out[256])
{
    for (int i = 0; i < 256; ++i)
        out[i] = sbox_entry(static_cast<uint8_t>(i));
}

__forceinline void compute_rcon_table(uint8_t out[11])
{
    for (int i = 0; i < 11; ++i)
        out[i] = compute_rcon(i);
}

__forceinline uint32_t sub_word_runtime(uint32_t w, const uint8_t sbox[256])
{
    return (static_cast<uint32_t>(sbox[(w >> 24) & 0xFFu]) << 24) |
           (static_cast<uint32_t>(sbox[(w >> 16) & 0xFFu]) << 16) |
           (static_cast<uint32_t>(sbox[(w >> 8) & 0xFFu]) << 8) |
            static_cast<uint32_t>(sbox[w & 0xFFu]);
}

__forceinline uint32_t rot_word(uint32_t w)
{
    return (w << 8) | (w >> 24);
}

__forceinline void key_expansion_128_runtime(
    const uint8_t key[16], uint32_t rk[44],
    const uint8_t sbox[256], const uint8_t rcon[11])
{
    for (int i = 0; i < 4; ++i)
    {
        rk[i] = (static_cast<uint32_t>(key[4 * i]) << 24) |
                (static_cast<uint32_t>(key[4 * i + 1]) << 16) |
                (static_cast<uint32_t>(key[4 * i + 2]) << 8) |
                 static_cast<uint32_t>(key[4 * i + 3]);
    }
    for (int i = 4; i < 44; ++i)
    {
        uint32_t t = rk[i - 1];
        if ((i % 4) == 0)
            t = sub_word_runtime(rot_word(t), sbox) ^
                (static_cast<uint32_t>(rcon[i / 4]) << 24);
        rk[i] = rk[i - 4] ^ t;
    }
}

__forceinline uint8_t gf_mul2(uint8_t a)
{
    return static_cast<uint8_t>((a << 1) ^ (((a >> 7) & 1u) * 0x1Bu));
}

__forceinline uint8_t gf_mul3(uint8_t a)
{
    return static_cast<uint8_t>(gf_mul2(a) ^ a);
}

__forceinline uint32_t mc_word_for_row(uint8_t v, int row)
{
    uint8_t b2 = gf_mul2(v);
    uint8_t b3 = gf_mul3(v);
    uint8_t r0, r1, r2, r3;
    if (row == 0) { r0 = b2; r1 = v;  r2 = v;  r3 = b3; }
    else if (row == 1) { r0 = b3; r1 = b2; r2 = v;  r3 = v;  }
    else if (row == 2) { r0 = v;  r1 = b3; r2 = b2; r3 = v;  }
    else               { r0 = v;  r1 = v;  r2 = b3; r3 = b2; }
    return (static_cast<uint32_t>(r0) << 24) |
           (static_cast<uint32_t>(r1) << 16) |
           (static_cast<uint32_t>(r2) << 8) |
            static_cast<uint32_t>(r3);
}

__forceinline int sr_source_col(int target_col, int row)
{
    return (target_col + row) & 3;
}

__forceinline int sr_source_index(int target_col, int row)
{
    return sr_source_col(target_col, row) * 4 + row;
}

struct prng_t {
    uint8_t key[32];
    uint64_t counter;

    void init(const uint8_t seed[32])
    {
        uint8_t input[48];
        std::memcpy(input, seed, 32);
        static const uint8_t label[16] = {
            'W','B','A','E','S','-','P','R','N','G','-','K','E','Y','V','2'
        };
        std::memcpy(input + 32, label, 16);
        blake3::hash(input, 48, key);
        counter = 0;
        SecureZeroMemory(input, sizeof(input));
    }

    void emit(uint8_t* out, size_t n)
    {
        size_t produced = 0;
        while (produced < n)
        {
            uint8_t blk[40];
            std::memcpy(blk, key, 32);
            std::memcpy(blk + 32, &counter, 8);
            uint8_t hash[32];
            blake3::hash(blk, 40, hash);
            size_t take = (n - produced > 32) ? 32 : (n - produced);
            std::memcpy(out + produced, hash, take);
            produced += take;
            ++counter;
            SecureZeroMemory(blk, sizeof(blk));
            SecureZeroMemory(hash, sizeof(hash));
        }
    }

    uint8_t next_byte()
    {
        uint8_t b;
        emit(&b, 1);
        return b;
    }

    void next_bytes(uint8_t* out, size_t n)
    {
        emit(out, n);
    }

    void wipe()
    {
        SecureZeroMemory(key, sizeof(key));
        SecureZeroMemory(&counter, sizeof(counter));
    }
};

__forceinline void blake3_compress_custom(
    uint32_t out[16],
    const uint32_t chaining[8],
    const uint32_t block_words[16],
    uint32_t counter,
    uint32_t block_len,
    uint32_t flags,
    const uint32_t iv[8])
{
    uint32_t state[16];
    std::memcpy(state, chaining, 32);
    std::memcpy(state + 8, iv, 32);
    state[12] ^= counter;
    state[13] ^= 0;
    state[14] ^= block_len;
    state[15] ^= flags;

    uint32_t m[16];
    std::memcpy(m, block_words, 64);

    for (int round = 0; round < 7; ++round)
    {
        const uint8_t* s = blake3::kMsgSchedule[round];
        blake3::g_round(state[0], state[4], state[8],  state[12], m[s[0]],  m[s[1]]);
        blake3::g_round(state[1], state[5], state[9],  state[13], m[s[2]],  m[s[3]]);
        blake3::g_round(state[2], state[6], state[10], state[14], m[s[4]],  m[s[5]]);
        blake3::g_round(state[3], state[7], state[11], state[15], m[s[6]],  m[s[7]]);
        blake3::g_round(state[0], state[5], state[10], state[15], m[s[8]],  m[s[9]]);
        blake3::g_round(state[1], state[6], state[11], state[12], m[s[10]], m[s[11]]);
        blake3::g_round(state[2], state[7], state[8],  state[13], m[s[12]], m[s[13]]);
        blake3::g_round(state[3], state[4], state[9],  state[14], m[s[14]], m[s[15]]);
    }

    for (int i = 0; i < 8; ++i)
    {
        out[i]     = state[i]     ^ state[i + 8];
        out[i + 8] = chaining[i]  ^ state[i + 8];
    }
}

__forceinline void blake3_hash_custom(
    const void* data, size_t len,
    const uint32_t iv[8],
    uint8_t out[32])
{
    const auto* input = static_cast<const uint8_t*>(data);
    const uint32_t flags = 0;

    if (len <= static_cast<size_t>(blake3::kChunkSize))
    {
        blake3::chunk_state_t cs;
        blake3::chunk_state_init(cs, iv, flags);
        blake3::chunk_state_update(cs, input, len);
        uint32_t cv[8];
        blake3::chunk_state_finalize(cs, cv);

        uint8_t block[blake3::kBlockSize];
        std::memcpy(block, cs.block, cs.block_len);
        std::memset(block + cs.block_len, 0, blake3::kBlockSize - cs.block_len);

        uint32_t words[16];
        for (int i = 0; i < 16; ++i)
            std::memcpy(&words[i], block + i * 4, 4);

        uint32_t out16[16];
        uint32_t chunk_flags = cs.flags | blake3::chunk_start_flag(cs) |
                               blake3::kFlags_ChunkEnd | blake3::kFlags_Root;
        blake3_compress_custom(out16, cv, words,
            static_cast<uint32_t>(cs.chunk_counter),
            static_cast<uint32_t>(cs.block_len), chunk_flags, iv);

        for (int i = 0; i < 8; ++i)
        {
            out[i * 4]     = static_cast<uint8_t>((out16[i] >> 24) & 0xFFu);
            out[i * 4 + 1] = static_cast<uint8_t>((out16[i] >> 16) & 0xFFu);
            out[i * 4 + 2] = static_cast<uint8_t>((out16[i] >> 8) & 0xFFu);
            out[i * 4 + 3] = static_cast<uint8_t>(out16[i] & 0xFFu);
        }
        return;
    }

    size_t chunks_remaining = (len + blake3::kChunkSize - 1) / blake3::kChunkSize;
    blake3::chunk_state_t cs;
    blake3::chunk_state_init(cs, iv, flags);
    size_t pos = 0;

    while (chunks_remaining > 1)
    {
        size_t take = blake3::kChunkSize - blake3::chunk_state_len(cs);
        if (take > len - pos) take = len - pos;

        blake3::chunk_state_update(cs, input + pos, take);
        pos += take;

        if (blake3::chunk_state_len(cs) == static_cast<size_t>(blake3::kChunkSize))
        {
            uint32_t cv[8];
            blake3::chunk_state_finalize(cs, cv);
            blake3::chunk_state_init(cs, iv, flags);
            std::memcpy(cs.cv, cv, 32);
            cs.chunk_counter += 1;
            chunks_remaining -= 1;
        }
    }

    blake3::chunk_state_update(cs, input + pos, len - pos);
    uint32_t final_cv[8];
    blake3::chunk_state_finalize(cs, final_cv);

    uint8_t block[blake3::kBlockSize];
    std::memcpy(block, cs.block, cs.block_len);
    std::memset(block + cs.block_len, 0, blake3::kBlockSize - cs.block_len);

    uint32_t words[16];
    for (int i = 0; i < 16; ++i)
        std::memcpy(&words[i], block + i * 4, 4);

    uint32_t out16[16];
    uint32_t chunk_flags = cs.flags | blake3::chunk_start_flag(cs) |
                           blake3::kFlags_ChunkEnd | blake3::kFlags_Root;
    blake3_compress_custom(out16, final_cv, words,
        static_cast<uint32_t>(cs.chunk_counter),
        static_cast<uint32_t>(cs.block_len), chunk_flags, iv);

    for (int i = 0; i < 8; ++i)
    {
        out[i * 4]     = static_cast<uint8_t>((out16[i] >> 24) & 0xFFu);
        out[i * 4 + 1] = static_cast<uint8_t>((out16[i] >> 16) & 0xFFu);
        out[i * 4 + 2] = static_cast<uint8_t>((out16[i] >> 8) & 0xFFu);
        out[i * 4 + 3] = static_cast<uint8_t>(out16[i] & 0xFFu);
    }
}

__forceinline void derive_blake3_iv(const uint8_t seed[32], uint32_t iv[8])
{
    std::memcpy(iv, seed, 32);
    for (int i = 0; i < 8; ++i)
    {
        iv[i] ^= 0x9E3779B9u;
        iv[i] = (iv[i] << 13) | (iv[i] >> 19);
        iv[i] *= 0x85EBCA6Bu;
        iv[i] ^= iv[(i + 3) & 7];
        iv[i] = (iv[i] << 17) | (iv[i] >> 15);
        iv[i] *= 0xC2B2AE35u;
    }
}

__forceinline void derive_wbaes_key(const uint8_t seed[32], uint8_t key[16])
{
    uint8_t okm[64];
    uint8_t input[40];
    std::memcpy(input, seed, 32);
    static const uint8_t label[8] = {'W','B','K','E','Y','V','2','\0'};
    std::memcpy(input + 32, label, 8);
    blake3::hash(input, 40, okm);
    std::memcpy(key, okm, 16);
    SecureZeroMemory(okm, sizeof(okm));
    SecureZeroMemory(input, sizeof(input));
}

__forceinline void derive_verification_key(const uint8_t seed[32], uint8_t key[16])
{
    uint8_t okm[64];
    uint8_t input[40];
    std::memcpy(input, seed, 32);
    static const uint8_t label[8] = {'W','B','V','K','E','Y','V','2'};
    std::memcpy(input + 32, label, 8);
    blake3::hash(input, 40, okm);
    std::memcpy(key, okm, 16);
    SecureZeroMemory(okm, sizeof(okm));
    SecureZeroMemory(input, sizeof(input));
}

}

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
    int      col_order[9][4];
    uint8_t  ghash_half_a;
    uint8_t  ghash_half_b;
    uint32_t blake3_iv[8];
    uint8_t  expected_hash[32];
    uint8_t  test_plaintext[16];
    uint8_t  test_ciphertext[16];
    uint8_t  build_id[16];
    uint8_t  verification_key_obf[16];
    uint8_t  verification_key_xor[16];
    bool     initialized;
};

using white_box_table_t = white_box_table_masked_t;

namespace detail_wb {

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

__forceinline void generate_tables_masked(
    const uint8_t key[16],
    const uint8_t seed[32],
    white_box_table_masked_t& out)
{
    SecureZeroMemory(&out, sizeof(out));

    uint8_t sbox[256];
    uint8_t rcon[11];
    compute_sbox(sbox);
    compute_rcon_table(rcon);

    uint32_t round_keys[44];
    key_expansion_128_runtime(key, round_keys, sbox, rcon);

    uint8_t key_bytes[16 * 11];
    for (int r = 0; r < 11; ++r)
    {
        for (int c = 0; c < 4; ++c)
        {
            key_bytes[r * 16 + c * 4 + 0] = static_cast<uint8_t>((round_keys[r * 4 + c] >> 24) & 0xFFu);
            key_bytes[r * 16 + c * 4 + 1] = static_cast<uint8_t>((round_keys[r * 4 + c] >> 16) & 0xFFu);
            key_bytes[r * 16 + c * 4 + 2] = static_cast<uint8_t>((round_keys[r * 4 + c] >> 8) & 0xFFu);
            key_bytes[r * 16 + c * 4 + 3] = static_cast<uint8_t>(round_keys[r * 4 + c] & 0xFFu);
        }
    }

    prng_t rng;
    rng.init(seed);

    rng.emit(out.ext_in, 16);
    rng.emit(out.ext_out, 16);
    rng.emit(out.table_id, 16);

    for (int r = 0; r < 10; ++r)
        for (int c = 0; c < 4; ++c)
        {
            uint8_t mask = rng.next_byte();
            out.input_masks[r][c * 4 + 0] = mask;
            out.input_masks[r][c * 4 + 1] = mask;
            out.input_masks[r][c * 4 + 2] = mask;
            out.input_masks[r][c * 4 + 3] = mask;

            out.output_masks[r][c * 4 + 0] = rng.next_byte();
            out.output_masks[r][c * 4 + 1] = rng.next_byte();
            out.output_masks[r][c * 4 + 2] = rng.next_byte();
            out.output_masks[r][c * 4 + 3] = rng.next_byte();
        }

    uint8_t mb_masks[9][4][4];
    for (int r = 0; r < 9; ++r)
        for (int c = 0; c < 4; ++c)
            for (int i = 0; i < 4; ++i)
                mb_masks[r][c][i] = rng.next_byte();

    for (int r = 0; r < 10; ++r)
        for (int pos = 0; pos < 16; ++pos)
        {
            rng.emit(out.t_xor_keys_s1[r][pos], 32);
            rng.emit(out.t_xor_keys_s2[r][pos], 32);
        }
    for (int r = 0; r < 9; ++r)
        for (int pos = 0; pos < 16; ++pos)
        {
            rng.emit(out.mb_xor_keys_s1[r][pos], 32);
            rng.emit(out.mb_xor_keys_s2[r][pos], 32);
        }

    for (int r = 0; r < 10; ++r)
    {
        for (int c = 0; c < 4; ++c)
        {
            for (int i = 0; i < 4; ++i)
            {
                int target_col = c;
                int row = i;
                int src_idx = sr_source_index(target_col, row);
                int pos = c * 4 + i;

                uint8_t input_decode = 0;
                if (r == 0)
                {
                    input_decode = out.ext_in[src_idx];
                }
                else
                {
                    int src_col = sr_source_col(target_col, row);
                    input_decode = mb_masks[r - 1][src_col][row];
                }

                uint8_t kbyte = key_bytes[r * 16 + src_idx];
                uint8_t out_decode = 0;
                if (r == 9)
                {
                    out_decode = static_cast<uint8_t>(
                        key_bytes[10 * 16 + c * 4 + i] ^ out.ext_out[c * 4 + i]);
                }

                uint8_t m_in = out.input_masks[r][pos];
                uint8_t m_out = out.output_masks[r][pos];

                for (int b = 0; b < 256; ++b)
                {
                    uint8_t actual = static_cast<uint8_t>(b ^ m_in);
                    uint8_t after_decode = static_cast<uint8_t>(actual ^ input_decode);
                    uint8_t after_key = static_cast<uint8_t>(after_decode ^ kbyte);
                    uint8_t after_sbox = sbox[after_key];
                    uint8_t t_val = static_cast<uint8_t>(after_sbox ^ out_decode);

                    uint8_t o1 = rng.next_byte();
                    uint8_t o2 = static_cast<uint8_t>(t_val ^ o1);

                    out.t_boxes_s1[r][pos][b] = static_cast<uint8_t>(o1 ^ out.t_xor_keys_s1[r][pos][0]);
                    out.t_boxes_s2[r][pos][b] = static_cast<uint8_t>(o2 ^ out.t_xor_keys_s2[r][pos][0]);
                }

                if (r < 9)
                {
                    for (int b = 0; b < 256; ++b)
                    {
                        uint8_t actual = static_cast<uint8_t>(b ^ m_in);
                        uint8_t t_val = static_cast<uint8_t>(
                            sbox[static_cast<uint8_t>(actual ^ input_decode ^ kbyte)] ^ out_decode);
                        uint32_t mc_word = mc_word_for_row(t_val, i);

                        uint32_t col_mask = 0;
                        if (i == 0)
                        {
                            col_mask =
                                (static_cast<uint32_t>(mb_masks[r][c][0]) << 24) |
                                (static_cast<uint32_t>(mb_masks[r][c][1]) << 16) |
                                (static_cast<uint32_t>(mb_masks[r][c][2]) << 8) |
                                 static_cast<uint32_t>(mb_masks[r][c][3]);
                            mc_word ^= col_mask;
                        }

                        uint32_t mb_mask_out =
                            (static_cast<uint32_t>(out.output_masks[r][c * 4 + 0]) << 24) |
                            (static_cast<uint32_t>(out.output_masks[r][c * 4 + 1]) << 16) |
                            (static_cast<uint32_t>(out.output_masks[r][c * 4 + 2]) << 8) |
                             static_cast<uint32_t>(out.output_masks[r][c * 4 + 3]);

                        uint32_t share1_val = mc_word ^ mb_mask_out;
                        uint32_t share2_val = mb_mask_out;

                        uint32_t xor_key1;
                        std::memcpy(&xor_key1, out.mb_xor_keys_s1[r][pos], 4);
                        uint32_t xor_key2;
                        std::memcpy(&xor_key2, out.mb_xor_keys_s2[r][pos], 4);

                        out.mb_tables_s1[r][pos][b] = share1_val ^ xor_key1;
                        out.mb_tables_s2[r][pos][b] = share2_val ^ xor_key2;
                    }
                }
            }
        }
    }

    for (int r = 0; r < 9; ++r)
    {
        int order[4] = {0, 1, 2, 3};
        for (int i = 3; i > 0; --i)
        {
            int j = rng.next_byte() % (i + 1);
            int tmp = order[i];
            order[i] = order[j];
            order[j] = tmp;
        }
        for (int c = 0; c < 4; ++c)
            out.col_order[r][c] = order[c];
    }

    derive_blake3_iv(seed, out.blake3_iv);

    out.ghash_half_a = kGhashHalfA;
    out.ghash_half_b = kGhashHalfB;

    uint8_t ver_key[16];
    derive_verification_key(seed, ver_key);

    for (int i = 0; i < 16; ++i)
    {
        out.verification_key_xor[i] = rng.next_byte();
        out.verification_key_obf[i] = static_cast<uint8_t>(ver_key[i] ^ out.verification_key_xor[i]);
    }
    SecureZeroMemory(ver_key, sizeof(ver_key));

    uint8_t build_id_input[48];
    std::memcpy(build_id_input, seed, 32);
    static const uint8_t bid_label[16] = {
        'W','B','B','U','I','L','D','I','D','V','2','\0','\0','\0','\0','\0'
    };
    std::memcpy(build_id_input + 32, bid_label, 16);
    blake3::hash(build_id_input, 48, out.build_id);
    SecureZeroMemory(build_id_input, sizeof(build_id_input));

    static const uint8_t test_pt[16] = {
        0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
        0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00
    };
    std::memcpy(out.test_plaintext, test_pt, 16);

    SecureZeroMemory(round_keys, sizeof(round_keys));
    SecureZeroMemory(key_bytes, sizeof(key_bytes));
    SecureZeroMemory(mb_masks, sizeof(mb_masks));
    SecureZeroMemory(sbox, sizeof(sbox));
    SecureZeroMemory(rcon, sizeof(rcon));
    rng.wipe();
}

}

inline const char* last_error()
{
    return detail_wb::s_last_error_storage().c_str();
}

inline void encrypt_block_masked(
    const white_box_table_masked_t& tbl,
    const uint8_t in[16], uint8_t out[16])
{
    uint8_t state1[16], state2[16];
    for (int i = 0; i < 16; ++i)
    {
        state1[i] = static_cast<uint8_t>(in[i] ^ tbl.ext_in[i]);
        state2[i] = tbl.input_masks[0][i];
        state1[i] = static_cast<uint8_t>(state1[i] ^ state2[i]);
    }

    for (int r = 0; r < 9; ++r)
    {
        uint8_t next1[16], next2[16];
        for (int co = 0; co < 4; ++co)
        {
            int c = tbl.col_order[r][co];
            uint32_t col1 = 0, col2 = 0;
            for (int i = 0; i < 4; ++i)
            {
                int src_idx = detail_wb::sr_source_index(c, i);
                int pos = c * 4 + i;

                col1 ^= detail_wb::mb_table_lookup_s1(tbl, r, pos, state1[src_idx]);
                col2 ^= detail_wb::mb_table_lookup_s2(tbl, r, pos, state2[src_idx]);

                volatile uint8_t dummy1 = tbl.t_boxes_s1[r][pos ^ 0x05][state1[src_idx ^ 0x0A]];
                volatile uint8_t dummy2 = tbl.t_boxes_s2[r][pos ^ 0x0A][state2[src_idx ^ 0x05]];
                (void)dummy1;
                (void)dummy2;
            }

            uint32_t combined = col1 ^ col2;
            uint8_t new_mask = tbl.input_masks[r + 1][c * 4];
            next1[c * 4 + 0] = static_cast<uint8_t>((combined >> 24) & 0xFFu) ^ new_mask;
            next1[c * 4 + 1] = static_cast<uint8_t>((combined >> 16) & 0xFFu) ^ new_mask;
            next1[c * 4 + 2] = static_cast<uint8_t>((combined >> 8) & 0xFFu) ^ new_mask;
            next1[c * 4 + 3] = static_cast<uint8_t>(combined & 0xFFu) ^ new_mask;
            next2[c * 4 + 0] = new_mask;
            next2[c * 4 + 1] = new_mask;
            next2[c * 4 + 2] = new_mask;
            next2[c * 4 + 3] = new_mask;
        }
        std::memcpy(state1, next1, 16);
        std::memcpy(state2, next2, 16);
        SecureZeroMemory(next1, sizeof(next1));
        SecureZeroMemory(next2, sizeof(next2));
    }

    uint8_t final_state[16];
    for (int c = 0; c < 4; ++c)
    {
        for (int i = 0; i < 4; ++i)
        {
            int src_idx = detail_wb::sr_source_index(c, i);
            int pos = c * 4 + i;

            uint8_t v1 = detail_wb::t_box_lookup_s1(tbl, 9, pos, state1[src_idx]);
            uint8_t v2 = detail_wb::t_box_lookup_s2(tbl, 9, pos, state2[src_idx]);

            volatile uint8_t dummy = tbl.t_boxes_s1[9][pos ^ 0x05][state2[src_idx ^ 0x0A]];
            (void)dummy;

            final_state[pos] = static_cast<uint8_t>((v1 ^ v2) ^ tbl.ext_out[pos]);
        }
    }
    std::memcpy(out, final_state, 16);
    SecureZeroMemory(state1, sizeof(state1));
    SecureZeroMemory(state2, sizeof(state2));
    SecureZeroMemory(final_state, sizeof(final_state));
}

inline bool encrypt_ctr_masked(
    const white_box_table_masked_t& tbl,
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
        encrypt_block_masked(tbl, counter, ks);
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

inline const white_box_table_masked_t& get_tables();
inline bool initialize_tables();
inline bool is_fallback_mode();
inline void get_verification_key(uint8_t key[16]);

namespace detail_wb {

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
    encrypt_block_masked(tbl, zero, H);

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
        encrypt_block_masked(tbl, ctr, ks);
        for (int j = 0; j < 16; ++j)
            ciphertext[i * 16 + j] = static_cast<uint8_t>(plaintext[i * 16 + j] ^ ks[j]);
        detail_wb::gcm_inc32_wb(ctr);
        SecureZeroMemory(ks, sizeof(ks));
    }
    if (rem)
    {
        uint8_t ks[16];
        encrypt_block_masked(tbl, ctr, ks);
        for (size_t j = 0; j < rem; ++j)
            ciphertext[full * 16 + j] = static_cast<uint8_t>(plaintext[full * 16 + j] ^ ks[j]);
        SecureZeroMemory(ks, sizeof(ks));
    }

    uint8_t y[16] = {0};
    if (aad && aad_len > 0)
        detail_wb::ghash_update_wb(H, aad, aad_len, y, tbl.ghash_half_a, tbl.ghash_half_b);
    if (pt_len > 0)
        detail_wb::ghash_update_wb(H, ciphertext, pt_len, y, tbl.ghash_half_a, tbl.ghash_half_b);

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
    detail_wb::gcm_gf_mul_wb(y, H, ghash_tag, tbl.ghash_half_a, tbl.ghash_half_b);

    uint8_t ej0[16];
    encrypt_block_masked(tbl, j0, ej0);
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
    encrypt_block_masked(tbl, zero, H);

    uint8_t j0[16] = {0};
    std::memcpy(j0, nonce, 12);
    j0[15] = 1;

    uint8_t y[16] = {0};
    if (aad && aad_len > 0)
        detail_wb::ghash_update_wb(H, aad, aad_len, y, tbl.ghash_half_a, tbl.ghash_half_b);
    if (ct_len > 0)
        detail_wb::ghash_update_wb(H, ciphertext, ct_len, y, tbl.ghash_half_a, tbl.ghash_half_b);

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
    detail_wb::gcm_gf_mul_wb(y, H, ghash_tag, tbl.ghash_half_a, tbl.ghash_half_b);

    uint8_t ej0[16];
    encrypt_block_masked(tbl, j0, ej0);
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
        encrypt_block_masked(tbl, ctr, ks);
        for (int j = 0; j < 16; ++j)
            plaintext[i * 16 + j] = static_cast<uint8_t>(ciphertext[i * 16 + j] ^ ks[j]);
        detail_wb::gcm_inc32_wb(ctr);
        SecureZeroMemory(ks, sizeof(ks));
    }
    if (rem)
    {
        uint8_t ks[16];
        encrypt_block_masked(tbl, ctr, ks);
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

inline void compute_table_hash(const white_box_table_masked_t& tbl, uint8_t out[32])
{
    constexpr size_t kTableDataSize = offsetof(white_box_table_masked_t, blake3_iv);
    detail_wb::blake3_hash_custom(&tbl, kTableDataSize, tbl.blake3_iv, out);
}

namespace detail_wb {

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

inline white_box_table_masked_t*& s_global_tables()
{
    static white_box_table_masked_t* p = nullptr;
    return p;
}

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
    const auto& tbl = *detail_wb::s_global_tables();
    for (int i = 0; i < 16; ++i)
        key[i] = static_cast<uint8_t>(tbl.verification_key_obf[i] ^ tbl.verification_key_xor[i]);
}

inline bool initialize_tables()
{
    if (detail_wb::s_tables_ready().load(std::memory_order_acquire))
        return true;

    bool success = false;
    std::call_once(detail_wb::s_init_once(), [&]() {
        auto* tbl = static_cast<white_box_table_masked_t*>(
            HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY,
                      sizeof(white_box_table_masked_t)));
        if (!tbl)
        {
            detail_wb::set_last_error("init_tables_alloc_failed");
            return;
        }

        uint8_t seed[32];
        arc_internal::arc_build_seed_bytes(seed);

        uint8_t wbaes_key[16];
        detail_wb::derive_wbaes_key(seed, wbaes_key);

        detail_wb::generate_tables_masked(wbaes_key, seed, *tbl);

        SecureZeroMemory(wbaes_key, sizeof(wbaes_key));

        encrypt_block_masked(*tbl, tbl->test_plaintext, tbl->test_ciphertext);

        compute_table_hash(*tbl, tbl->expected_hash);

        std::memcpy(detail_wb::s_table_hash(), tbl->expected_hash, 32);

        tbl->initialized = true;
        detail_wb::s_global_tables() = tbl;
        detail_wb::s_tables_ready().store(true, std::memory_order_release);
        success = true;

        SecureZeroMemory(seed, sizeof(seed));
    });

    return success;
}

inline const white_box_table_masked_t& get_tables()
{
    if (!detail_wb::s_tables_ready().load(std::memory_order_acquire))
        initialize_tables();
    return *detail_wb::s_global_tables();
}

inline bool verify_test_vector()
{
    const auto& tbl = get_tables();

    uint8_t result[16];
    encrypt_block_masked(tbl, tbl.test_plaintext, result);

    volatile uint8_t diff = 0;
    for (int i = 0; i < 16; ++i)
        diff |= static_cast<uint8_t>(result[i] ^ tbl.test_ciphertext[i]);

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
        diff |= static_cast<uint8_t>(computed[i] ^ tbl.expected_hash[i]);

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
    return encrypt_ctr_masked(tbl, iv, in, out, len);
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
    encrypt_block_masked(tbl, challenge, response);
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

    const auto& tbl = get_tables();
    std::memcpy(out_pkt.build_id, tbl.build_id, 16);
    std::memset(out_pkt.reserved, 0, sizeof(out_pkt.reserved));
}

inline void shutdown_tables()
{
    auto* tbl = detail_wb::s_global_tables();
    if (tbl)
    {
        SecureZeroMemory(tbl, sizeof(white_box_table_masked_t));
        HeapFree(GetProcessHeap(), 0, tbl);
        detail_wb::s_global_tables() = nullptr;
    }
    detail_wb::s_tables_ready().store(false, std::memory_order_release);
    set_fallback_mode(false);
}

}
}
