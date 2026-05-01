#pragma once

#ifndef NOMINMAX
#define NOMINMAX
#endif
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif

#include <windows.h>
#include <intrin.h>

#include <atomic>
#include <cstdint>
#include <cstddef>
#include <cstring>
#include <string>

namespace anti_tamper {
namespace wbaes {

struct white_box_table_t {
    uint8_t  t_boxes[10][16][256];
    uint32_t mb_tables[9][16][256];
    uint8_t  ext_in[16];
    uint8_t  ext_out[16];
    uint8_t  table_id[16];
};

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

static constexpr uint8_t k_sbox[256] = {
    0x63,0x7C,0x77,0x7B,0xF2,0x6B,0x6F,0xC5,0x30,0x01,0x67,0x2B,0xFE,0xD7,0xAB,0x76,
    0xCA,0x82,0xC9,0x7D,0xFA,0x59,0x47,0xF0,0xAD,0xD4,0xA2,0xAF,0x9C,0xA4,0x72,0xC0,
    0xB7,0xFD,0x93,0x26,0x36,0x3F,0xF7,0xCC,0x34,0xA5,0xE5,0xF1,0x71,0xD8,0x31,0x15,
    0x04,0xC7,0x23,0xC3,0x18,0x96,0x05,0x9A,0x07,0x12,0x80,0xE2,0xEB,0x27,0xB2,0x75,
    0x09,0x83,0x2C,0x1A,0x1B,0x6E,0x5A,0xA0,0x52,0x3B,0xD6,0xB3,0x29,0xE3,0x2F,0x84,
    0x53,0xD1,0x00,0xED,0x20,0xFC,0xB1,0x5B,0x6A,0xCB,0xBE,0x39,0x4A,0x4C,0x58,0xCF,
    0xD0,0xEF,0xAA,0xFB,0x43,0x4D,0x33,0x85,0x45,0xF9,0x02,0x7F,0x50,0x3C,0x9F,0xA8,
    0x51,0xA3,0x40,0x8F,0x92,0x9D,0x38,0xF5,0xBC,0xB6,0xDA,0x21,0x10,0xFF,0xF3,0xD2,
    0xCD,0x0C,0x13,0xEC,0x5F,0x97,0x44,0x17,0xC4,0xA7,0x7E,0x3D,0x64,0x5D,0x19,0x73,
    0x60,0x81,0x4F,0xDC,0x22,0x2A,0x90,0x88,0x46,0xEE,0xB8,0x14,0xDE,0x5E,0x0B,0xDB,
    0xE0,0x32,0x3A,0x0A,0x49,0x06,0x24,0x5C,0xC2,0xD3,0xAC,0x62,0x91,0x95,0xE4,0x79,
    0xE7,0xC8,0x37,0x6D,0x8D,0xD5,0x4E,0xA9,0x6C,0x56,0xF4,0xEA,0x65,0x7A,0xAE,0x08,
    0xBA,0x78,0x25,0x2E,0x1C,0xA6,0xB4,0xC6,0xE8,0xDD,0x74,0x1F,0x4B,0xBD,0x8B,0x8A,
    0x70,0x3E,0xB5,0x66,0x48,0x03,0xF6,0x0E,0x61,0x35,0x57,0xB9,0x86,0xC1,0x1D,0x9E,
    0xE1,0xF8,0x98,0x11,0x69,0xD9,0x8E,0x94,0x9B,0x1E,0x87,0xE9,0xCE,0x55,0x28,0xDF,
    0x8C,0xA1,0x89,0x0D,0xBF,0xE6,0x42,0x68,0x41,0x99,0x2D,0x0F,0xB0,0x54,0xBB,0x16
};

static constexpr uint8_t k_rcon[11] = {
    0x00, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36
};

inline uint32_t sub_word(uint32_t w)
{
    return (static_cast<uint32_t>(k_sbox[(w >> 24) & 0xFFu]) << 24) |
           (static_cast<uint32_t>(k_sbox[(w >> 16) & 0xFFu]) << 16) |
           (static_cast<uint32_t>(k_sbox[(w >> 8) & 0xFFu]) << 8) |
            static_cast<uint32_t>(k_sbox[w & 0xFFu]);
}

inline uint32_t rot_word(uint32_t w)
{
    return (w << 8) | (w >> 24);
}

inline void key_expansion_128(const uint8_t key[16], uint32_t rk[44])
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
            t = sub_word(rot_word(t)) ^ (static_cast<uint32_t>(k_rcon[i / 4]) << 24);
        rk[i] = rk[i - 4] ^ t;
    }
}

inline uint8_t gf_mul2(uint8_t a)
{
    return static_cast<uint8_t>((a << 1) ^ (((a >> 7) & 1u) * 0x1Bu));
}

inline uint8_t gf_mul3(uint8_t a)
{
    return static_cast<uint8_t>(gf_mul2(a) ^ a);
}

inline uint32_t mc_word_for_row(uint8_t v, int row)
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

inline uint32_t rotr32(uint32_t x, unsigned n)
{
    return (x >> n) | (x << (32 - n));
}

inline void sha256_compress(uint32_t H[8], const uint8_t block[64])
{
    static constexpr uint32_t K[64] = {
        0x428a2f98u,0x71374491u,0xb5c0fbcfu,0xe9b5dba5u,0x3956c25bu,0x59f111f1u,0x923f82a4u,0xab1c5ed5u,
        0xd807aa98u,0x12835b01u,0x243185beu,0x550c7dc3u,0x72be5d74u,0x80deb1feu,0x9bdc06a7u,0xc19bf174u,
        0xe49b69c1u,0xefbe4786u,0x0fc19dc6u,0x240ca1ccu,0x2de92c6fu,0x4a7484aau,0x5cb0a9dcu,0x76f988dau,
        0x983e5152u,0xa831c66du,0xb00327c8u,0xbf597fc7u,0xc6e00bf3u,0xd5a79147u,0x06ca6351u,0x14292967u,
        0x27b70a85u,0x2e1b2138u,0x4d2c6dfcu,0x53380d13u,0x650a7354u,0x766a0abbu,0x81c2c92eu,0x92722c85u,
        0xa2bfe8a1u,0xa81a664bu,0xc24b8b70u,0xc76c51a3u,0xd192e819u,0xd6990624u,0xf40e3585u,0x106aa070u,
        0x19a4c116u,0x1e376c08u,0x2748774cu,0x34b0bcb5u,0x391c0cb3u,0x4ed8aa4au,0x5b9cca4fu,0x682e6ff3u,
        0x748f82eeu,0x78a5636fu,0x84c87814u,0x8cc70208u,0x90befffau,0xa4506cebu,0xbef9a3f7u,0xc67178f2u
    };
    uint32_t W[64];
    for (int i = 0; i < 16; ++i)
    {
        W[i] = (static_cast<uint32_t>(block[4 * i]) << 24) |
               (static_cast<uint32_t>(block[4 * i + 1]) << 16) |
               (static_cast<uint32_t>(block[4 * i + 2]) << 8) |
                static_cast<uint32_t>(block[4 * i + 3]);
    }
    for (int i = 16; i < 64; ++i)
    {
        uint32_t s0 = rotr32(W[i - 15], 7) ^ rotr32(W[i - 15], 18) ^ (W[i - 15] >> 3);
        uint32_t s1 = rotr32(W[i - 2], 17) ^ rotr32(W[i - 2], 19) ^ (W[i - 2] >> 10);
        W[i] = W[i - 16] + s0 + W[i - 7] + s1;
    }
    uint32_t a = H[0], b = H[1], c = H[2], d = H[3];
    uint32_t e = H[4], f = H[5], g = H[6], h = H[7];
    for (int i = 0; i < 64; ++i)
    {
        uint32_t S1 = rotr32(e, 6) ^ rotr32(e, 11) ^ rotr32(e, 25);
        uint32_t ch = (e & f) ^ (~e & g);
        uint32_t t1 = h + S1 + ch + K[i] + W[i];
        uint32_t S0 = rotr32(a, 2) ^ rotr32(a, 13) ^ rotr32(a, 22);
        uint32_t mj = (a & b) ^ (a & c) ^ (b & c);
        uint32_t t2 = S0 + mj;
        h = g; g = f; f = e; e = d + t1; d = c; c = b; b = a; a = t1 + t2;
    }
    H[0] += a; H[1] += b; H[2] += c; H[3] += d;
    H[4] += e; H[5] += f; H[6] += g; H[7] += h;
}

inline void sha256(const uint8_t* data, size_t len, uint8_t out[32])
{
    uint32_t H[8] = {
        0x6a09e667u, 0xbb67ae85u, 0x3c6ef372u, 0xa54ff53au,
        0x510e527fu, 0x9b05688cu, 0x1f83d9abu, 0x5be0cd19u
    };
    uint64_t bitlen = static_cast<uint64_t>(len) * 8ull;
    size_t off = 0;
    while (len - off >= 64)
    {
        sha256_compress(H, data + off);
        off += 64;
    }
    uint8_t block[64];
    size_t rem = len - off;
    if (rem > 0) std::memcpy(block, data + off, rem);
    block[rem] = 0x80;
    if (rem + 1 > 56)
    {
        std::memset(block + rem + 1, 0, 64 - rem - 1);
        sha256_compress(H, block);
        std::memset(block, 0, 56);
    }
    else
    {
        std::memset(block + rem + 1, 0, 56 - rem - 1);
    }
    for (int i = 0; i < 8; ++i)
        block[56 + i] = static_cast<uint8_t>((bitlen >> (56 - 8 * i)) & 0xFFull);
    sha256_compress(H, block);
    for (int i = 0; i < 8; ++i)
    {
        out[4 * i]     = static_cast<uint8_t>((H[i] >> 24) & 0xFFu);
        out[4 * i + 1] = static_cast<uint8_t>((H[i] >> 16) & 0xFFu);
        out[4 * i + 2] = static_cast<uint8_t>((H[i] >> 8) & 0xFFu);
        out[4 * i + 3] = static_cast<uint8_t>(H[i] & 0xFFu);
    }
}

inline void hmac_sha256(const uint8_t* key, size_t key_len,
                         const uint8_t* data, size_t data_len,
                         uint8_t out[32])
{
    uint8_t k[64];
    if (key_len > 64)
    {
        sha256(key, key_len, k);
        std::memset(k + 32, 0, 32);
    }
    else
    {
        if (key_len > 0) std::memcpy(k, key, key_len);
        std::memset(k + key_len, 0, 64 - key_len);
    }
    uint8_t ipad[64];
    uint8_t opad[64];
    for (int i = 0; i < 64; ++i)
    {
        ipad[i] = static_cast<uint8_t>(k[i] ^ 0x36u);
        opad[i] = static_cast<uint8_t>(k[i] ^ 0x5Cu);
    }
    uint8_t* inner_buf = static_cast<uint8_t*>(HeapAlloc(GetProcessHeap(), 0, 64 + data_len));
    if (!inner_buf)
    {
        std::memset(out, 0, 32);
        SecureZeroMemory(k, 64);
        SecureZeroMemory(ipad, 64);
        SecureZeroMemory(opad, 64);
        return;
    }
    std::memcpy(inner_buf, ipad, 64);
    if (data_len > 0) std::memcpy(inner_buf + 64, data, data_len);
    uint8_t inner_hash[32];
    sha256(inner_buf, 64 + data_len, inner_hash);
    SecureZeroMemory(inner_buf, 64 + data_len);
    HeapFree(GetProcessHeap(), 0, inner_buf);

    uint8_t outer[96];
    std::memcpy(outer, opad, 64);
    std::memcpy(outer + 64, inner_hash, 32);
    sha256(outer, 96, out);

    SecureZeroMemory(k, 64);
    SecureZeroMemory(ipad, 64);
    SecureZeroMemory(opad, 64);
    SecureZeroMemory(inner_hash, 32);
    SecureZeroMemory(outer, 96);
}

struct prng_t {
    uint8_t state[32];
    uint64_t counter;

    void init(const uint8_t key[16], uint64_t seed)
    {
        uint8_t ikm[24];
        std::memcpy(ikm, key, 16);
        ikm[16] = static_cast<uint8_t>(seed & 0xFFu);
        ikm[17] = static_cast<uint8_t>((seed >> 8) & 0xFFu);
        ikm[18] = static_cast<uint8_t>((seed >> 16) & 0xFFu);
        ikm[19] = static_cast<uint8_t>((seed >> 24) & 0xFFu);
        ikm[20] = static_cast<uint8_t>((seed >> 32) & 0xFFu);
        ikm[21] = static_cast<uint8_t>((seed >> 40) & 0xFFu);
        ikm[22] = static_cast<uint8_t>((seed >> 48) & 0xFFu);
        ikm[23] = static_cast<uint8_t>((seed >> 56) & 0xFFu);
        static const uint8_t label[18] = { 'A','i','D','A','-','W','B','A','E','S','-','S','E','E','D','-','V','1' };
        hmac_sha256(label, sizeof(label), ikm, sizeof(ikm), state);
        counter = 0;
        SecureZeroMemory(ikm, sizeof(ikm));
    }

    void emit(uint8_t* out, size_t n)
    {
        size_t produced = 0;
        while (produced < n)
        {
            uint8_t blk[40];
            std::memcpy(blk, state, 32);
            blk[32] = static_cast<uint8_t>(counter & 0xFFu);
            blk[33] = static_cast<uint8_t>((counter >> 8) & 0xFFu);
            blk[34] = static_cast<uint8_t>((counter >> 16) & 0xFFu);
            blk[35] = static_cast<uint8_t>((counter >> 24) & 0xFFu);
            blk[36] = static_cast<uint8_t>((counter >> 32) & 0xFFu);
            blk[37] = static_cast<uint8_t>((counter >> 40) & 0xFFu);
            blk[38] = static_cast<uint8_t>((counter >> 48) & 0xFFu);
            blk[39] = static_cast<uint8_t>((counter >> 56) & 0xFFu);
            uint8_t hash[32];
            static const uint8_t label[14] = { 'A','i','D','A','-','W','B','A','E','S','-','G','E','N' };
            hmac_sha256(label, sizeof(label), blk, sizeof(blk), hash);
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
};

inline int sr_source_col(int target_col, int row)
{
    return (target_col + row) & 3;
}

inline int sr_source_index(int target_col, int row)
{
    return sr_source_col(target_col, row) * 4 + row;
}

}

inline const char* last_error()
{
    return detail_wb::s_last_error_storage().c_str();
}

inline bool generate_tables(const uint8_t key[16], uint64_t entropy_seed, white_box_table_t& out)
{
    if (!key)
    {
        detail_wb::set_last_error("generate_tables_invalid_key");
        return false;
    }

    SecureZeroMemory(&out, sizeof(out));

    uint32_t round_keys[44];
    detail_wb::key_expansion_128(key, round_keys);

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

    detail_wb::prng_t rng;
    rng.init(key, entropy_seed);

    rng.emit(out.ext_in, 16);
    rng.emit(out.ext_out, 16);
    rng.emit(out.table_id, 16);

    uint8_t mb_masks[9][4][4];
    for (int r = 0; r < 9; ++r)
    {
        for (int c = 0; c < 4; ++c)
            for (int i = 0; i < 4; ++i)
                mb_masks[r][c][i] = rng.next_byte();
    }

    for (int r = 0; r < 10; ++r)
    {
        for (int c = 0; c < 4; ++c)
        {
            for (int i = 0; i < 4; ++i)
            {
                int target_col = c;
                int row = i;
                int src_idx = detail_wb::sr_source_index(target_col, row);

                uint8_t input_decode = 0;
                if (r == 0)
                {
                    input_decode = out.ext_in[src_idx];
                }
                else
                {
                    int src_col = detail_wb::sr_source_col(target_col, row);
                    input_decode = mb_masks[r - 1][src_col][row];
                }

                uint8_t kbyte = key_bytes[r * 16 + src_idx];
                uint8_t out_decode = 0;
                if (r == 9)
                {
                    out_decode = static_cast<uint8_t>(key_bytes[10 * 16 + c * 4 + i] ^ out.ext_out[c * 4 + i]);
                }

                for (int b = 0; b < 256; ++b)
                {
                    uint8_t input_byte = static_cast<uint8_t>(b);
                    uint8_t after_decode = static_cast<uint8_t>(input_byte ^ input_decode);
                    uint8_t after_key = static_cast<uint8_t>(after_decode ^ kbyte);
                    uint8_t after_sbox = detail_wb::k_sbox[after_key];
                    uint8_t final_byte = static_cast<uint8_t>(after_sbox ^ out_decode);
                    out.t_boxes[r][c * 4 + i][b] = final_byte;
                }
            }
        }
    }

    for (int r = 0; r < 9; ++r)
    {
        for (int c = 0; c < 4; ++c)
        {
            for (int i = 0; i < 4; ++i)
            {
                for (int b = 0; b < 256; ++b)
                {
                    uint8_t sbox_out = out.t_boxes[r][c * 4 + i][b];
                    uint32_t mc_word = detail_wb::mc_word_for_row(sbox_out, i);
                    if (i == 0)
                    {
                        uint32_t mask_word =
                            (static_cast<uint32_t>(mb_masks[r][c][0]) << 24) |
                            (static_cast<uint32_t>(mb_masks[r][c][1]) << 16) |
                            (static_cast<uint32_t>(mb_masks[r][c][2]) << 8) |
                             static_cast<uint32_t>(mb_masks[r][c][3]);
                        mc_word ^= mask_word;
                    }
                    out.mb_tables[r][c * 4 + i][b] = mc_word;
                }
            }
        }
    }

    SecureZeroMemory(round_keys, sizeof(round_keys));
    SecureZeroMemory(key_bytes, sizeof(key_bytes));
    SecureZeroMemory(mb_masks, sizeof(mb_masks));
    SecureZeroMemory(&rng, sizeof(rng));

    detail_wb::set_last_error(nullptr);
    return true;
}

inline void encrypt_block(const white_box_table_t& tbl, const uint8_t in[16], uint8_t out[16])
{
    uint8_t state[16];
    for (int i = 0; i < 16; ++i)
        state[i] = static_cast<uint8_t>(in[i] ^ tbl.ext_in[i]);

    for (int r = 0; r < 9; ++r)
    {
        uint8_t next_state[16];
        for (int c = 0; c < 4; ++c)
        {
            uint32_t col_word = 0;
            for (int i = 0; i < 4; ++i)
            {
                int src_idx = detail_wb::sr_source_index(c, i);
                uint8_t b = state[src_idx];
                col_word ^= tbl.mb_tables[r][c * 4 + i][b];
            }
            next_state[c * 4 + 0] = static_cast<uint8_t>((col_word >> 24) & 0xFFu);
            next_state[c * 4 + 1] = static_cast<uint8_t>((col_word >> 16) & 0xFFu);
            next_state[c * 4 + 2] = static_cast<uint8_t>((col_word >> 8) & 0xFFu);
            next_state[c * 4 + 3] = static_cast<uint8_t>(col_word & 0xFFu);
        }
        std::memcpy(state, next_state, 16);
        SecureZeroMemory(next_state, sizeof(next_state));
    }

    {
        uint8_t final_state[16];
        for (int c = 0; c < 4; ++c)
        {
            for (int i = 0; i < 4; ++i)
            {
                int src_idx = detail_wb::sr_source_index(c, i);
                uint8_t b = state[src_idx];
                final_state[c * 4 + i] = tbl.t_boxes[9][c * 4 + i][b];
            }
        }
        std::memcpy(state, final_state, 16);
        SecureZeroMemory(final_state, sizeof(final_state));
    }

    for (int i = 0; i < 16; ++i)
        out[i] = static_cast<uint8_t>(state[i] ^ tbl.ext_out[i]);

    SecureZeroMemory(state, sizeof(state));
}

inline bool encrypt_ctr(const white_box_table_t& tbl, const uint8_t iv[16],
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

}
}
