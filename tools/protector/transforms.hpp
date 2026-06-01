#pragma once
#ifndef NOMINMAX
#define NOMINMAX
#endif
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <bcrypt.h>
#include <intrin.h>
#include <immintrin.h>
#include "pe_file.hpp"
#include "llm_poison.hpp"
#include <vector>
#include <string>
#include <cstring>
#include <cstdint>
#include <cstddef>
#include <cstdio>
#include <array>
#include <algorithm>

#pragma comment(lib, "bcrypt.lib")
#pragma comment(lib, "advapi32.lib")

namespace protector {

inline namespace crc32c_detail {

constexpr std::array<uint32_t, 256> crc32c_build_table() {
    std::array<uint32_t, 256> t{};
    for (uint32_t i = 0; i < 256; ++i) {
        uint32_t c = i;
        for (int k = 0; k < 8; ++k) {
            c = (c & 1u) ? (0x82F63B78u ^ (c >> 1)) : (c >> 1);
        }
        t[i] = c;
    }
    return t;
}

constexpr std::array<uint32_t, 256> kCrc32cTable = crc32c_build_table();

inline uint32_t crc32c_update(uint32_t crc, const uint8_t* data, size_t len) {
#if defined(__SSE4_2__) || defined(_M_X64)
    uint64_t c = ~static_cast<uint64_t>(crc) & 0xFFFFFFFFull;
    while (len >= 8) {
        uint64_t v;
        std::memcpy(&v, data, 8);
        c = _mm_crc32_u64(c, v);
        data += 8;
        len -= 8;
    }
    uint32_t c32 = static_cast<uint32_t>(c);
    while (len > 0) {
        c32 = _mm_crc32_u8(c32, *data);
        ++data;
        --len;
    }
    return ~c32;
#else
    uint32_t c = ~crc;
    for (size_t i = 0; i < len; ++i) {
        c = kCrc32cTable[(c ^ data[i]) & 0xFF] ^ (c >> 8);
    }
    return ~c;
#endif
}

inline uint32_t crc32c(const uint8_t* data, size_t len) {
    return crc32c_update(0, data, len);
}

inline uint64_t fnv1a64(const uint8_t* d, size_t n) {
    uint64_t h = 0xcbf29ce484222325ULL;
    for (size_t i = 0; i < n; ++i) {
        h ^= static_cast<uint64_t>(d[i]);
        h *= 0x100000001b3ULL;
    }
    return h;
}

}

namespace sha256_detail {

inline uint32_t rotr32(uint32_t x, unsigned n) {
    return (x >> n) | (x << (32 - n));
}

inline void sha256_compress(uint32_t H[8], const uint8_t block[64]) {
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
    for (int i = 0; i < 16; ++i) {
        W[i] = (static_cast<uint32_t>(block[4 * i]) << 24) |
               (static_cast<uint32_t>(block[4 * i + 1]) << 16) |
               (static_cast<uint32_t>(block[4 * i + 2]) << 8) |
                static_cast<uint32_t>(block[4 * i + 3]);
    }
    for (int i = 16; i < 64; ++i) {
        uint32_t s0 = rotr32(W[i - 15], 7) ^ rotr32(W[i - 15], 18) ^ (W[i - 15] >> 3);
        uint32_t s1 = rotr32(W[i - 2], 17) ^ rotr32(W[i - 2], 19) ^ (W[i - 2] >> 10);
        W[i] = W[i - 16] + s0 + W[i - 7] + s1;
    }
    uint32_t a = H[0], b = H[1], c = H[2], d = H[3];
    uint32_t e = H[4], f = H[5], g = H[6], h = H[7];
    for (int i = 0; i < 64; ++i) {
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

inline void sha256(const uint8_t* data, size_t len, uint8_t out[32]) {
    uint32_t H[8] = {
        0x6a09e667u, 0xbb67ae85u, 0x3c6ef372u, 0xa54ff53au,
        0x510e527fu, 0x9b05688cu, 0x1f83d9abu, 0x5be0cd19u
    };
    uint64_t bitlen = static_cast<uint64_t>(len) * 8ull;
    size_t off = 0;
    while (len - off >= 64) {
        sha256_compress(H, data + off);
        off += 64;
    }
    uint8_t block[64];
    size_t rem = len - off;
    if (rem > 0) {
        std::memcpy(block, data + off, rem);
    }
    block[rem] = 0x80;
    if (rem + 1 > 56) {
        std::memset(block + rem + 1, 0, 64 - rem - 1);
        sha256_compress(H, block);
        std::memset(block, 0, 56);
    } else {
        std::memset(block + rem + 1, 0, 56 - rem - 1);
    }
    for (int i = 0; i < 8; ++i) {
        block[56 + i] = static_cast<uint8_t>((bitlen >> (56 - 8 * i)) & 0xFFull);
    }
    sha256_compress(H, block);
    for (int i = 0; i < 8; ++i) {
        out[4 * i]     = static_cast<uint8_t>((H[i] >> 24) & 0xFFu);
        out[4 * i + 1] = static_cast<uint8_t>((H[i] >> 16) & 0xFFu);
        out[4 * i + 2] = static_cast<uint8_t>((H[i] >> 8) & 0xFFu);
        out[4 * i + 3] = static_cast<uint8_t>(H[i] & 0xFFu);
    }
}

inline void hmac_sha256(const uint8_t* key, size_t key_len,
                         const uint8_t* data, size_t data_len,
                         uint8_t out[32]) {
    uint8_t k[64];
    if (key_len > 64) {
        sha256(key, key_len, k);
        std::memset(k + 32, 0, 32);
    } else {
        if (key_len > 0) {
            std::memcpy(k, key, key_len);
        }
        std::memset(k + key_len, 0, 64 - key_len);
    }
    uint8_t ipad[64];
    uint8_t opad[64];
    for (int i = 0; i < 64; ++i) {
        ipad[i] = k[i] ^ 0x36u;
        opad[i] = k[i] ^ 0x5Cu;
    }
    std::vector<uint8_t> inner(64 + data_len);
    std::memcpy(inner.data(), ipad, 64);
    if (data_len > 0) {
        std::memcpy(inner.data() + 64, data, data_len);
    }
    uint8_t inner_hash[32];
    sha256(inner.data(), inner.size(), inner_hash);
    uint8_t outer[96];
    std::memcpy(outer, opad, 64);
    std::memcpy(outer + 64, inner_hash, 32);
    sha256(outer, 96, out);
}

inline void hkdf_extract(const uint8_t* salt, size_t salt_len,
                          const uint8_t* ikm, size_t ikm_len,
                          uint8_t prk[32]) {
    static const uint8_t zero_salt[32] = { 0 };
    if (salt_len == 0) {
        hmac_sha256(zero_salt, 32, ikm, ikm_len, prk);
    } else {
        hmac_sha256(salt, salt_len, ikm, ikm_len, prk);
    }
}

inline void hkdf_expand(const uint8_t prk[32],
                         const uint8_t* info, size_t info_len,
                         uint8_t* out, size_t out_len) {
    uint8_t t[32];
    size_t t_len = 0;
    size_t produced = 0;
    uint8_t counter = 1;
    while (produced < out_len) {
        std::vector<uint8_t> m;
        m.reserve(t_len + info_len + 1);
        if (t_len > 0) {
            m.insert(m.end(), t, t + t_len);
        }
        if (info_len > 0) {
            m.insert(m.end(), info, info + info_len);
        }
        m.push_back(counter);
        hmac_sha256(prk, 32, m.data(), m.size(), t);
        t_len = 32;
        size_t copy = (std::min)(out_len - produced, static_cast<size_t>(32));
        std::memcpy(out + produced, t, copy);
        produced += copy;
        ++counter;
    }
}

inline void hkdf_sha256(const uint8_t* ikm, size_t ikm_len,
                         const uint8_t* salt, size_t salt_len,
                         const uint8_t* info, size_t info_len,
                         uint8_t* out, size_t out_len) {
    uint8_t prk[32];
    hkdf_extract(salt, salt_len, ikm, ikm_len, prk);
    hkdf_expand(prk, info, info_len, out, out_len);
}

}

namespace aes_detail {

static constexpr uint8_t kSbox[256] = {
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

static constexpr uint8_t kRcon[11] = {
    0x00, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36
};

inline uint32_t sub_word(uint32_t w) {
    return (static_cast<uint32_t>(kSbox[(w >> 24) & 0xFFu]) << 24) |
           (static_cast<uint32_t>(kSbox[(w >> 16) & 0xFFu]) << 16) |
           (static_cast<uint32_t>(kSbox[(w >> 8) & 0xFFu]) << 8) |
            static_cast<uint32_t>(kSbox[w & 0xFFu]);
}

inline uint32_t rot_word(uint32_t w) {
    return (w << 8) | (w >> 24);
}

inline void key_expansion(const uint8_t* key, int nk, int nr, uint32_t* rk) {
    int total = 4 * (nr + 1);
    for (int i = 0; i < nk; ++i) {
        rk[i] = (static_cast<uint32_t>(key[4 * i]) << 24) |
                (static_cast<uint32_t>(key[4 * i + 1]) << 16) |
                (static_cast<uint32_t>(key[4 * i + 2]) << 8) |
                 static_cast<uint32_t>(key[4 * i + 3]);
    }
    for (int i = nk; i < total; ++i) {
        uint32_t t = rk[i - 1];
        if (i % nk == 0) {
            t = sub_word(rot_word(t)) ^ (static_cast<uint32_t>(kRcon[i / nk]) << 24);
        } else if (nk > 6 && (i % nk) == 4) {
            t = sub_word(t);
        }
        rk[i] = rk[i - nk] ^ t;
    }
}

inline uint8_t gf_mul2(uint8_t a) {
    return static_cast<uint8_t>((a << 1) ^ (((a >> 7) & 1u) * 0x1Bu));
}

inline uint8_t gf_mul3(uint8_t a) {
    return static_cast<uint8_t>(gf_mul2(a) ^ a);
}

inline void encrypt_block(const uint8_t in[16], uint8_t out[16], const uint32_t* rk, int nr) {
    uint8_t s[4][4];
    for (int r = 0; r < 4; ++r) {
        for (int c = 0; c < 4; ++c) {
            s[r][c] = in[r + 4 * c];
        }
    }
    for (int c = 0; c < 4; ++c) {
        uint32_t k = rk[c];
        s[0][c] ^= static_cast<uint8_t>((k >> 24) & 0xFFu);
        s[1][c] ^= static_cast<uint8_t>((k >> 16) & 0xFFu);
        s[2][c] ^= static_cast<uint8_t>((k >> 8) & 0xFFu);
        s[3][c] ^= static_cast<uint8_t>(k & 0xFFu);
    }
    for (int round = 1; round <= nr; ++round) {
        for (int r = 0; r < 4; ++r) {
            for (int c = 0; c < 4; ++c) {
                s[r][c] = kSbox[s[r][c]];
            }
        }
        uint8_t t;
        t = s[1][0]; s[1][0] = s[1][1]; s[1][1] = s[1][2]; s[1][2] = s[1][3]; s[1][3] = t;
        t = s[2][0]; s[2][0] = s[2][2]; s[2][2] = t;
        t = s[2][1]; s[2][1] = s[2][3]; s[2][3] = t;
        t = s[3][3]; s[3][3] = s[3][2]; s[3][2] = s[3][1]; s[3][1] = s[3][0]; s[3][0] = t;
        if (round < nr) {
            for (int c = 0; c < 4; ++c) {
                uint8_t s0 = s[0][c], s1 = s[1][c], s2 = s[2][c], s3 = s[3][c];
                s[0][c] = static_cast<uint8_t>(gf_mul2(s0) ^ gf_mul3(s1) ^ s2 ^ s3);
                s[1][c] = static_cast<uint8_t>(s0 ^ gf_mul2(s1) ^ gf_mul3(s2) ^ s3);
                s[2][c] = static_cast<uint8_t>(s0 ^ s1 ^ gf_mul2(s2) ^ gf_mul3(s3));
                s[3][c] = static_cast<uint8_t>(gf_mul3(s0) ^ s1 ^ s2 ^ gf_mul2(s3));
            }
        }
        const uint32_t* krk = &rk[round * 4];
        for (int c = 0; c < 4; ++c) {
            s[0][c] ^= static_cast<uint8_t>((krk[c] >> 24) & 0xFFu);
            s[1][c] ^= static_cast<uint8_t>((krk[c] >> 16) & 0xFFu);
            s[2][c] ^= static_cast<uint8_t>((krk[c] >> 8) & 0xFFu);
            s[3][c] ^= static_cast<uint8_t>(krk[c] & 0xFFu);
        }
    }
    for (int r = 0; r < 4; ++r) {
        for (int c = 0; c < 4; ++c) {
            out[r + 4 * c] = s[r][c];
        }
    }
}

inline void aes128_ecb_encrypt(const uint8_t key[16], const uint8_t in[16], uint8_t out[16]) {
    uint32_t rk[44];
    key_expansion(key, 4, 10, rk);
    encrypt_block(in, out, rk, 10);
}

inline void aes256_ctr(const uint8_t key[32], const uint8_t iv[16],
                        const uint8_t* in, uint8_t* out, size_t len) {
    uint32_t rk[60];
    key_expansion(key, 8, 14, rk);
    uint8_t counter[16];
    std::memcpy(counter, iv, 16);
    uint8_t ks[16];
    size_t off = 0;
    while (off < len) {
        encrypt_block(counter, ks, rk, 14);
        for (int i = 15; i >= 0; --i) {
            if (++counter[i] != 0) {
                break;
            }
        }
        size_t bl = (std::min)(static_cast<size_t>(16), len - off);
        for (size_t i = 0; i < bl; ++i) {
            out[off + i] = static_cast<uint8_t>(in[off + i] ^ ks[i]);
        }
        off += bl;
    }
}

inline void aes128_ctr(const uint8_t key[16], const uint8_t iv[16],
                        const uint8_t* in, uint8_t* out, size_t len) {
    uint32_t rk[44];
    key_expansion(key, 4, 10, rk);
    uint8_t counter[16];
    std::memcpy(counter, iv, 16);
    uint8_t ks[16];
    size_t off = 0;
    while (off < len) {
        encrypt_block(counter, ks, rk, 10);
        for (int i = 15; i >= 0; --i) {
            if (++counter[i] != 0) {
                break;
            }
        }
        size_t bl = (std::min)(static_cast<size_t>(16), len - off);
        for (size_t i = 0; i < bl; ++i) {
            out[off + i] = static_cast<uint8_t>(in[off + i] ^ ks[i]);
        }
        off += bl;
    }
}

inline void compute_inner_master(const uint8_t outer[32], uint8_t inner[32]) {
    uint32_t crc = crc32c(outer, 32);
    uint8_t key16[16];
    for (int i = 0; i < 4; ++i) {
        key16[4 * i]     = static_cast<uint8_t>(crc & 0xFFu);
        key16[4 * i + 1] = static_cast<uint8_t>((crc >> 8) & 0xFFu);
        key16[4 * i + 2] = static_cast<uint8_t>((crc >> 16) & 0xFFu);
        key16[4 * i + 3] = static_cast<uint8_t>((crc >> 24) & 0xFFu);
    }
    uint32_t rk[44];
    key_expansion(key16, 4, 10, rk);
    for (int i = 0; i < 8; ++i) {
        inner[4 * i]     = static_cast<uint8_t>((rk[i] >> 24) & 0xFFu);
        inner[4 * i + 1] = static_cast<uint8_t>((rk[i] >> 16) & 0xFFu);
        inner[4 * i + 2] = static_cast<uint8_t>((rk[i] >> 8) & 0xFFu);
        inner[4 * i + 3] = static_cast<uint8_t>(rk[i] & 0xFFu);
    }
}

struct wbaes_table_t {
    uint8_t  t_boxes[10][16][256];
    uint32_t mb_tables[9][16][256];
    uint8_t  ext_in[16];
    uint8_t  ext_out[16];
};

inline uint32_t wbaes_mc_word_for_row(uint8_t v, int row) {
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

inline int wbaes_sr_source_col(int target_col, int row) {
    return (target_col + row) & 3;
}

inline int wbaes_sr_source_index(int target_col, int row) {
    return wbaes_sr_source_col(target_col, row) * 4 + row;
}

inline void wbaes_emit_random(const uint8_t key[16], uint64_t seed, uint64_t counter,
                               uint8_t* out, size_t n) {
    static const uint8_t k_label[14] = { 'A','i','D','A','-','W','B','A','E','S','-','G','E','N' };
    static const uint8_t k_seed_label[18] = { 'A','i','D','A','-','W','B','A','E','S','-','S','E','E','D','-','V','1' };
    size_t produced = 0;
    uint64_t local_counter = counter;
    uint8_t prk[32];
    uint8_t ikm[24];
    std::memcpy(ikm, key, 16);
    for (int j = 0; j < 8; ++j) {
        ikm[16 + j] = static_cast<uint8_t>((seed >> (j * 8)) & 0xFFu);
    }
    sha256_detail::hmac_sha256(k_seed_label, sizeof(k_seed_label), ikm, sizeof(ikm), prk);
    while (produced < n) {
        uint8_t blk[40];
        std::memcpy(blk, prk, 32);
        for (int j = 0; j < 8; ++j) {
            blk[32 + j] = static_cast<uint8_t>((local_counter >> (j * 8)) & 0xFFu);
        }
        uint8_t hash[32];
        sha256_detail::hmac_sha256(k_label, sizeof(k_label), blk, sizeof(blk), hash);
        size_t take = (n - produced > 32) ? 32 : (n - produced);
        std::memcpy(out + produced, hash, take);
        produced += take;
        ++local_counter;
        SecureZeroMemory(blk, sizeof(blk));
        SecureZeroMemory(hash, sizeof(hash));
    }
    SecureZeroMemory(prk, sizeof(prk));
    SecureZeroMemory(ikm, sizeof(ikm));
}

inline bool wbaes_generate_tables(const uint8_t key[16], uint64_t entropy_seed, wbaes_table_t& out) {
    if (!key) return false;
    SecureZeroMemory(&out, sizeof(out));

    uint32_t round_keys[44];
    key_expansion(key, 4, 10, round_keys);

    uint8_t key_bytes[16 * 11];
    for (int r = 0; r < 11; ++r) {
        for (int c = 0; c < 4; ++c) {
            key_bytes[r * 16 + c * 4 + 0] = static_cast<uint8_t>((round_keys[r * 4 + c] >> 24) & 0xFFu);
            key_bytes[r * 16 + c * 4 + 1] = static_cast<uint8_t>((round_keys[r * 4 + c] >> 16) & 0xFFu);
            key_bytes[r * 16 + c * 4 + 2] = static_cast<uint8_t>((round_keys[r * 4 + c] >> 8) & 0xFFu);
            key_bytes[r * 16 + c * 4 + 3] = static_cast<uint8_t>(round_keys[r * 4 + c] & 0xFFu);
        }
    }

    uint8_t random_pool[16 + 16 + 16 + 9 * 4 * 4];
    wbaes_emit_random(key, entropy_seed, 0, random_pool, sizeof(random_pool));

    std::memcpy(out.ext_in, random_pool, 16);
    std::memcpy(out.ext_out, random_pool + 16, 16);
    uint8_t mb_masks[9][4][4];
    std::memcpy(mb_masks, random_pool + 48, 9 * 4 * 4);
    SecureZeroMemory(random_pool, sizeof(random_pool));

    for (int r = 0; r < 10; ++r) {
        for (int c = 0; c < 4; ++c) {
            for (int i = 0; i < 4; ++i) {
                int target_col = c;
                int row = i;
                int src_idx = wbaes_sr_source_index(target_col, row);

                uint8_t input_decode = 0;
                if (r == 0) {
                    input_decode = out.ext_in[src_idx];
                } else {
                    int src_col = wbaes_sr_source_col(target_col, row);
                    input_decode = mb_masks[r - 1][src_col][row];
                }

                uint8_t kbyte = key_bytes[r * 16 + src_idx];
                uint8_t out_decode = 0;
                if (r == 9) {
                    out_decode = static_cast<uint8_t>(key_bytes[10 * 16 + c * 4 + i] ^ out.ext_out[c * 4 + i]);
                }

                for (int b = 0; b < 256; ++b) {
                    uint8_t input_byte = static_cast<uint8_t>(b);
                    uint8_t after_decode = static_cast<uint8_t>(input_byte ^ input_decode);
                    uint8_t after_key = static_cast<uint8_t>(after_decode ^ kbyte);
                    uint8_t after_sbox = kSbox[after_key];
                    uint8_t final_byte = static_cast<uint8_t>(after_sbox ^ out_decode);
                    out.t_boxes[r][c * 4 + i][b] = final_byte;
                }
            }
        }
    }

    for (int r = 0; r < 9; ++r) {
        for (int c = 0; c < 4; ++c) {
            for (int i = 0; i < 4; ++i) {
                for (int b = 0; b < 256; ++b) {
                    uint8_t sbox_out = out.t_boxes[r][c * 4 + i][b];
                    uint32_t mc_word = wbaes_mc_word_for_row(sbox_out, i);
                    if (i == 0) {
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
    return true;
}

inline void wbaes_encrypt_block(const wbaes_table_t& tbl, const uint8_t in[16], uint8_t out[16]) {
    uint8_t state[16];
    for (int i = 0; i < 16; ++i) {
        state[i] = static_cast<uint8_t>(in[i] ^ tbl.ext_in[i]);
    }
    for (int r = 0; r < 9; ++r) {
        uint8_t next_state[16];
        for (int c = 0; c < 4; ++c) {
            uint32_t col_word = 0;
            for (int i = 0; i < 4; ++i) {
                int src_idx = wbaes_sr_source_index(c, i);
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
        for (int c = 0; c < 4; ++c) {
            for (int i = 0; i < 4; ++i) {
                int src_idx = wbaes_sr_source_index(c, i);
                uint8_t b = state[src_idx];
                final_state[c * 4 + i] = tbl.t_boxes[9][c * 4 + i][b];
            }
        }
        std::memcpy(state, final_state, 16);
        SecureZeroMemory(final_state, sizeof(final_state));
    }
    for (int i = 0; i < 16; ++i) {
        out[i] = static_cast<uint8_t>(state[i] ^ tbl.ext_out[i]);
    }
    SecureZeroMemory(state, sizeof(state));
}

inline void wbaes_encrypt_ctr(const wbaes_table_t& tbl, const uint8_t iv[16],
                               const uint8_t* in, uint8_t* out, size_t len) {
    uint8_t counter[16];
    std::memcpy(counter, iv, 16);
    uint8_t ks[16];
    size_t off = 0;
    while (off < len) {
        wbaes_encrypt_block(tbl, counter, ks);
        for (int i = 15; i >= 0; --i) {
            if (++counter[i] != 0) break;
        }
        size_t bl = (std::min)(static_cast<size_t>(16), len - off);
        for (size_t i = 0; i < bl; ++i) {
            out[off + i] = static_cast<uint8_t>(in[off + i] ^ ks[i]);
        }
        off += bl;
    }
    SecureZeroMemory(counter, sizeof(counter));
    SecureZeroMemory(ks, sizeof(ks));
}

inline bool wbaes_encrypt_section_buffer(const uint8_t key[16], const uint8_t iv[16],
                                          const uint8_t* in, uint8_t* out, size_t len) {
    if (!key || !iv) return false;
    if (len > 0 && (!in || !out)) return false;

    wbaes_table_t* tbl = static_cast<wbaes_table_t*>(
        HeapAlloc(GetProcessHeap(), 0, sizeof(wbaes_table_t)));
    if (!tbl) return false;

    uint64_t entropy_seed = static_cast<uint64_t>(__rdtsc());
    if (!wbaes_generate_tables(key, entropy_seed, *tbl)) {
        SecureZeroMemory(tbl, sizeof(wbaes_table_t));
        HeapFree(GetProcessHeap(), 0, tbl);
        return false;
    }
    wbaes_encrypt_ctr(*tbl, iv, in, out, len);
    SecureZeroMemory(tbl, sizeof(wbaes_table_t));
    HeapFree(GetProcessHeap(), 0, tbl);
    return true;
}

}

namespace chacha_detail {

inline uint32_t rotl32(uint32_t a, unsigned b) {
    return (a << b) | (a >> (32 - b));
}

inline void quarter_round(uint32_t& a, uint32_t& b, uint32_t& c, uint32_t& d) {
    a += b; d ^= a; d = rotl32(d, 16);
    c += d; b ^= c; b = rotl32(b, 12);
    a += b; d ^= a; d = rotl32(d, 8);
    c += d; b ^= c; b = rotl32(b, 7);
}

inline void block(const uint32_t state[16], uint8_t out[64]) {
    uint32_t x[16];
    std::memcpy(x, state, 64);
    for (int i = 0; i < 10; ++i) {
        quarter_round(x[0], x[4], x[8], x[12]);
        quarter_round(x[1], x[5], x[9], x[13]);
        quarter_round(x[2], x[6], x[10], x[14]);
        quarter_round(x[3], x[7], x[11], x[15]);
        quarter_round(x[0], x[5], x[10], x[15]);
        quarter_round(x[1], x[6], x[11], x[12]);
        quarter_round(x[2], x[7], x[8], x[13]);
        quarter_round(x[3], x[4], x[9], x[14]);
    }
    for (int i = 0; i < 16; ++i) {
        uint32_t v = x[i] + state[i];
        out[4 * i]     = static_cast<uint8_t>(v & 0xFFu);
        out[4 * i + 1] = static_cast<uint8_t>((v >> 8) & 0xFFu);
        out[4 * i + 2] = static_cast<uint8_t>((v >> 16) & 0xFFu);
        out[4 * i + 3] = static_cast<uint8_t>((v >> 24) & 0xFFu);
    }
}

struct chacha20_drbg {
    uint32_t state[16];
    uint8_t buf[64];
    size_t buf_pos;

    void init(const uint8_t seed[32]) {
        state[0] = 0x61707865u;
        state[1] = 0x3320646eu;
        state[2] = 0x79622d32u;
        state[3] = 0x6b206574u;
        for (int i = 0; i < 8; ++i) {
            state[4 + i] = static_cast<uint32_t>(seed[4 * i]) |
                           (static_cast<uint32_t>(seed[4 * i + 1]) << 8) |
                           (static_cast<uint32_t>(seed[4 * i + 2]) << 16) |
                           (static_cast<uint32_t>(seed[4 * i + 3]) << 24);
        }
        state[12] = 0;
        state[13] = 0;
        state[14] = 0;
        state[15] = 0;
        buf_pos = 64;
        std::memset(buf, 0, 64);
    }

    void get(uint8_t* out, size_t n) {
        while (n > 0) {
            if (buf_pos >= 64) {
                block(state, buf);
                ++state[12];
                if (state[12] == 0) {
                    ++state[13];
                }
                buf_pos = 0;
            }
            size_t take = (std::min)(n, static_cast<size_t>(64) - buf_pos);
            std::memcpy(out, buf + buf_pos, take);
            buf_pos += take;
            out += take;
            n -= take;
        }
    }
};

inline void chacha20_xor(const uint8_t key[32], const uint8_t nonce[12],
                          const uint8_t* in, uint8_t* out, size_t len) {
    uint32_t state[16];
    state[0] = 0x61707865u;
    state[1] = 0x3320646eu;
    state[2] = 0x79622d32u;
    state[3] = 0x6b206574u;
    for (int i = 0; i < 8; ++i) {
        state[4 + i] = static_cast<uint32_t>(key[4 * i]) |
                       (static_cast<uint32_t>(key[4 * i + 1]) << 8) |
                       (static_cast<uint32_t>(key[4 * i + 2]) << 16) |
                       (static_cast<uint32_t>(key[4 * i + 3]) << 24);
    }
    state[12] = 1u;
    for (int i = 0; i < 3; ++i) {
        state[13 + i] = static_cast<uint32_t>(nonce[4 * i]) |
                        (static_cast<uint32_t>(nonce[4 * i + 1]) << 8) |
                        (static_cast<uint32_t>(nonce[4 * i + 2]) << 16) |
                        (static_cast<uint32_t>(nonce[4 * i + 3]) << 24);
    }
    uint8_t ks[64];
    size_t off = 0;
    while (off < len) {
        block(state, ks);
        ++state[12];
        size_t bl = (std::min)(static_cast<size_t>(64), len - off);
        for (size_t i = 0; i < bl; ++i) {
            out[off + i] = static_cast<uint8_t>(in[off + i] ^ ks[i]);
        }
        off += bl;
    }
}

}

namespace xtea_detail {

inline void block_encrypt(const uint32_t key[4], uint32_t v[2]) {
    uint32_t v0 = v[0];
    uint32_t v1 = v[1];
    uint32_t sum = 0;
    constexpr uint32_t delta = 0x9E3779B9u;
    for (int i = 0; i < 64; ++i) {
        v0 += (((v1 << 4) ^ (v1 >> 5)) + v1) ^ (sum + key[sum & 3u]);
        sum += delta;
        v1 += (((v0 << 4) ^ (v0 >> 5)) + v0) ^ (sum + key[(sum >> 11) & 3u]);
    }
    v[0] = v0;
    v[1] = v1;
}

inline void key_to_words(const uint8_t key[16], uint32_t out[4]) {
    for (int i = 0; i < 4; ++i) {
        out[i] = static_cast<uint32_t>(key[4 * i]) |
                 (static_cast<uint32_t>(key[4 * i + 1]) << 8) |
                 (static_cast<uint32_t>(key[4 * i + 2]) << 16) |
                 (static_cast<uint32_t>(key[4 * i + 3]) << 24);
    }
}

inline void increment_counter_le(uint8_t ctr[8]) {
    for (int i = 0; i < 8; ++i) {
        if (++ctr[i] != 0) {
            break;
        }
    }
}

inline void counter_to_words(const uint8_t ctr[8], uint32_t out[2]) {
    out[0] = static_cast<uint32_t>(ctr[0]) |
             (static_cast<uint32_t>(ctr[1]) << 8) |
             (static_cast<uint32_t>(ctr[2]) << 16) |
             (static_cast<uint32_t>(ctr[3]) << 24);
    out[1] = static_cast<uint32_t>(ctr[4]) |
             (static_cast<uint32_t>(ctr[5]) << 8) |
             (static_cast<uint32_t>(ctr[6]) << 16) |
             (static_cast<uint32_t>(ctr[7]) << 24);
}

inline void words_to_bytes(const uint32_t v[2], uint8_t out[8]) {
    out[0] = static_cast<uint8_t>(v[0] & 0xFFu);
    out[1] = static_cast<uint8_t>((v[0] >> 8) & 0xFFu);
    out[2] = static_cast<uint8_t>((v[0] >> 16) & 0xFFu);
    out[3] = static_cast<uint8_t>((v[0] >> 24) & 0xFFu);
    out[4] = static_cast<uint8_t>(v[1] & 0xFFu);
    out[5] = static_cast<uint8_t>((v[1] >> 8) & 0xFFu);
    out[6] = static_cast<uint8_t>((v[1] >> 16) & 0xFFu);
    out[7] = static_cast<uint8_t>((v[1] >> 24) & 0xFFu);
}

}

inline void xtea_ctr(const uint8_t key[16], const uint8_t iv[8],
                      const uint8_t* in, uint8_t* out, size_t len) {
    uint32_t kw[4];
    xtea_detail::key_to_words(key, kw);
    uint8_t counter[8];
    std::memcpy(counter, iv, 8);
    uint8_t ks[8];
    size_t off = 0;
    while (off < len) {
        uint32_t cw[2];
        xtea_detail::counter_to_words(counter, cw);
        xtea_detail::block_encrypt(kw, cw);
        xtea_detail::words_to_bytes(cw, ks);
        xtea_detail::increment_counter_le(counter);
        size_t bl = (std::min)(static_cast<size_t>(8), len - off);
        for (size_t i = 0; i < bl; ++i) {
            out[off + i] = static_cast<uint8_t>(in[off + i] ^ ks[i]);
        }
        off += bl;
    }
}

namespace matryoshka_detail {

inline void compute_hwid_anchor(uint8_t out[32]) {
    static constexpr char kAnchor[] = "aida-build-hwid-anchor-v1";
    sha256_detail::sha256(reinterpret_cast<const uint8_t*>(kAnchor),
                           sizeof(kAnchor) - 1u, out);
}

inline void compute_tpm_anchor(uint8_t out[32]) {
    static constexpr char kAnchor[] = "aida-build-tpm-anchor-v1";
    sha256_detail::sha256(reinterpret_cast<const uint8_t*>(kAnchor),
                           sizeof(kAnchor) - 1u, out);
}

inline void compute_server_anchor(uint8_t out[32]) {
    static constexpr char kAnchor[] = "aida-build-srv-heartbeat-anchor-v1";
    sha256_detail::sha256(reinterpret_cast<const uint8_t*>(kAnchor),
                           sizeof(kAnchor) - 1u, out);
}

inline void derive_layer1_key(const uint8_t hwid[32], const uint8_t build_seed[32],
                               uint32_t section_rva, uint32_t section_index,
                               uint8_t out_key[16]) {
    uint8_t ikm[64];
    std::memcpy(ikm, hwid, 32);
    std::memcpy(ikm + 32, build_seed, 32);
    uint8_t info[64];
    static constexpr char kInfo[] = "matryoshka-l1-hwid";
    std::memcpy(info, kInfo, sizeof(kInfo) - 1u);
    size_t info_len = sizeof(kInfo) - 1u;
    info[info_len + 0] = static_cast<uint8_t>(section_rva & 0xFFu);
    info[info_len + 1] = static_cast<uint8_t>((section_rva >> 8) & 0xFFu);
    info[info_len + 2] = static_cast<uint8_t>((section_rva >> 16) & 0xFFu);
    info[info_len + 3] = static_cast<uint8_t>((section_rva >> 24) & 0xFFu);
    info[info_len + 4] = static_cast<uint8_t>(section_index & 0xFFu);
    info[info_len + 5] = static_cast<uint8_t>((section_index >> 8) & 0xFFu);
    info[info_len + 6] = static_cast<uint8_t>((section_index >> 16) & 0xFFu);
    info[info_len + 7] = static_cast<uint8_t>((section_index >> 24) & 0xFFu);
    sha256_detail::hkdf_sha256(ikm, 64, nullptr, 0, info, info_len + 8u, out_key, 16);
}

inline void derive_layer2_key(const uint8_t tpm[32], const uint8_t build_seed[32],
                               uint32_t section_rva, uint32_t section_index,
                               uint8_t out_key[32]) {
    uint8_t ikm[64];
    std::memcpy(ikm, tpm, 32);
    std::memcpy(ikm + 32, build_seed, 32);
    uint8_t info[64];
    static constexpr char kInfo[] = "matryoshka-l2-tpm";
    std::memcpy(info, kInfo, sizeof(kInfo) - 1u);
    size_t info_len = sizeof(kInfo) - 1u;
    info[info_len + 0] = static_cast<uint8_t>(section_rva & 0xFFu);
    info[info_len + 1] = static_cast<uint8_t>((section_rva >> 8) & 0xFFu);
    info[info_len + 2] = static_cast<uint8_t>((section_rva >> 16) & 0xFFu);
    info[info_len + 3] = static_cast<uint8_t>((section_rva >> 24) & 0xFFu);
    info[info_len + 4] = static_cast<uint8_t>(section_index & 0xFFu);
    info[info_len + 5] = static_cast<uint8_t>((section_index >> 8) & 0xFFu);
    info[info_len + 6] = static_cast<uint8_t>((section_index >> 16) & 0xFFu);
    info[info_len + 7] = static_cast<uint8_t>((section_index >> 24) & 0xFFu);
    sha256_detail::hkdf_sha256(ikm, 64, nullptr, 0, info, info_len + 8u, out_key, 32);
}

inline void derive_layer3_key(const uint8_t srv[32], const uint8_t build_seed[32],
                               uint32_t section_rva, uint32_t section_index,
                               uint8_t out_key[16]) {
    uint8_t ikm[64];
    std::memcpy(ikm, srv, 32);
    std::memcpy(ikm + 32, build_seed, 32);
    uint8_t info[64];
    static constexpr char kInfo[] = "matryoshka-l3-srv";
    std::memcpy(info, kInfo, sizeof(kInfo) - 1u);
    size_t info_len = sizeof(kInfo) - 1u;
    info[info_len + 0] = static_cast<uint8_t>(section_rva & 0xFFu);
    info[info_len + 1] = static_cast<uint8_t>((section_rva >> 8) & 0xFFu);
    info[info_len + 2] = static_cast<uint8_t>((section_rva >> 16) & 0xFFu);
    info[info_len + 3] = static_cast<uint8_t>((section_rva >> 24) & 0xFFu);
    info[info_len + 4] = static_cast<uint8_t>(section_index & 0xFFu);
    info[info_len + 5] = static_cast<uint8_t>((section_index >> 8) & 0xFFu);
    info[info_len + 6] = static_cast<uint8_t>((section_index >> 16) & 0xFFu);
    info[info_len + 7] = static_cast<uint8_t>((section_index >> 24) & 0xFFu);
    sha256_detail::hkdf_sha256(ikm, 64, nullptr, 0, info, info_len + 8u, out_key, 16);
}

inline void derive_build_seed_from_master(const uint8_t master[32], uint8_t out[32]) {
    uint8_t info[] = { 'a','i','d','a','-','m','a','t','r','y','o','s','h','k','a','-','b','u','i','l','d','-','s','e','e','d','-','v','1' };
    sha256_detail::hkdf_sha256(master, 32, nullptr, 0, info, sizeof(info), out, 32);
}

}

namespace lzss_detail {

static constexpr size_t kWindowSize = 4095;
static constexpr size_t kMinMatch = 3;
static constexpr size_t kMaxMatch = 18;
static constexpr size_t kHashSize = 16384;

inline uint32_t hash3(const uint8_t* p) {
    return ((static_cast<uint32_t>(p[0]) << 5) ^
            (static_cast<uint32_t>(p[1]) << 3) ^
             static_cast<uint32_t>(p[2])) & (kHashSize - 1);
}

}

inline std::vector<uint8_t> lz_compress(const uint8_t* data, size_t len) {
    if (len == 0) {
        return {};
    }
    std::vector<uint8_t> output;
    output.reserve(len + len / 8 + 64);

    std::vector<int32_t> hash_table(lzss_detail::kHashSize, -1);
    std::vector<int32_t> chain(len, -1);

    size_t pos = 0;
    while (pos < len) {
        size_t flag_pos = output.size();
        output.push_back(0);
        uint8_t flags = 0;

        for (int bit = 7; bit >= 0 && pos < len; --bit) {
            size_t best_len = 0;
            size_t best_off = 0;

            if (pos + lzss_detail::kMinMatch <= len) {
                uint32_t h = lzss_detail::hash3(data + pos);
                int32_t candidate = hash_table[h];

                int search_depth = 64;
                while (candidate >= 0 && search_depth-- > 0) {
                    size_t off = pos - static_cast<size_t>(candidate);
                    if (off > lzss_detail::kWindowSize) {
                        break;
                    }
                    if (data[candidate] == data[pos]) {
                        size_t ml = 0;
                        size_t max_ml = (std::min)(lzss_detail::kMaxMatch, len - pos);
                        while (ml < max_ml && data[static_cast<size_t>(candidate) + ml] == data[pos + ml]) {
                            ++ml;
                        }
                        if (ml >= lzss_detail::kMinMatch && ml > best_len) {
                            best_len = ml;
                            best_off = off;
                            if (ml == lzss_detail::kMaxMatch) {
                                break;
                            }
                        }
                    }
                    candidate = chain[static_cast<size_t>(candidate)];
                }

                chain[pos] = hash_table[h];
                hash_table[h] = static_cast<int32_t>(pos);
            }

            if (best_len >= lzss_detail::kMinMatch) {
                flags = static_cast<uint8_t>(flags | (1u << bit));
                uint8_t b0 = static_cast<uint8_t>(((best_off >> 8) & 0x0Fu) |
                                                   (((best_len - lzss_detail::kMinMatch) & 0x0Fu) << 4));
                uint8_t b1 = static_cast<uint8_t>(best_off & 0xFFu);
                output.push_back(b0);
                output.push_back(b1);

                for (size_t k = 1; k < best_len; ++k) {
                    if (pos + k < len && pos + k + lzss_detail::kMinMatch <= len) {
                        uint32_t hk = lzss_detail::hash3(data + pos + k);
                        chain[pos + k] = hash_table[hk];
                        hash_table[hk] = static_cast<int32_t>(pos + k);
                    }
                }
                pos += best_len;
            } else {
                output.push_back(data[pos]);
                ++pos;
            }
        }
        output[flag_pos] = flags;
    }

    return output;
}

inline std::vector<uint8_t> lz_decompress(const uint8_t* data, size_t compressed_len, size_t original_len) {
    std::vector<uint8_t> output(original_len);
    size_t src = 0;
    size_t dst = 0;

    while (dst < original_len && src < compressed_len) {
        uint8_t flags = data[src++];
        for (int bit = 7; bit >= 0 && dst < original_len && src < compressed_len; --bit) {
            if (flags & (1u << bit)) {
                if (src + 1 >= compressed_len) {
                    break;
                }
                uint8_t b0 = data[src++];
                uint8_t b1 = data[src++];
                size_t match_len = ((b0 >> 4) & 0x0Fu) + lzss_detail::kMinMatch;
                size_t match_off = (static_cast<size_t>(b0 & 0x0Fu) << 8) | b1;
                if (match_off == 0 || match_off > dst) {
                    break;
                }
                for (size_t k = 0; k < match_len && dst < original_len; ++k) {
                    output[dst] = output[dst - match_off];
                    ++dst;
                }
            } else {
                output[dst++] = data[src++];
            }
        }
    }
    return output;
}

namespace siphash_detail {

inline uint64_t rotl64(uint64_t x, unsigned n) {
    return (x << n) | (x >> (64u - n));
}

inline uint64_t siphash_2_4_raw(const uint8_t* data, size_t len, uint64_t k0, uint64_t k1) {
    uint64_t v0 = k0 ^ 0x736F6D6570736575ULL;
    uint64_t v1 = k1 ^ 0x646F72616E646F6DULL;
    uint64_t v2 = k0 ^ 0x6C7967656E657261ULL;
    uint64_t v3 = k1 ^ 0x7465646279746573ULL;

    auto sip = [&]() {
        v0 += v1; v1 = rotl64(v1, 13); v1 ^= v0; v0 = rotl64(v0, 32);
        v2 += v3; v3 = rotl64(v3, 16); v3 ^= v2;
        v0 += v3; v3 = rotl64(v3, 21); v3 ^= v0;
        v2 += v1; v1 = rotl64(v1, 17); v1 ^= v2; v2 = rotl64(v2, 32);
    };

    size_t blocks = len / 8u;
    for (size_t i = 0; i < blocks; ++i) {
        uint64_t m;
        std::memcpy(&m, data + i * 8u, 8u);
        v3 ^= m;
        sip(); sip();
        v0 ^= m;
    }

    uint64_t last = static_cast<uint64_t>(len & 0xFFu) << 56;
    const uint8_t* tail = data + blocks * 8u;
    switch (len & 7u) {
        case 7: last |= static_cast<uint64_t>(tail[6]) << 48; [[fallthrough]];
        case 6: last |= static_cast<uint64_t>(tail[5]) << 40; [[fallthrough]];
        case 5: last |= static_cast<uint64_t>(tail[4]) << 32; [[fallthrough]];
        case 4: last |= static_cast<uint64_t>(tail[3]) << 24; [[fallthrough]];
        case 3: last |= static_cast<uint64_t>(tail[2]) << 16; [[fallthrough]];
        case 2: last |= static_cast<uint64_t>(tail[1]) << 8;  [[fallthrough]];
        case 1: last |= static_cast<uint64_t>(tail[0]);       break;
        case 0: break;
    }

    v3 ^= last;
    sip(); sip();
    v0 ^= last;

    v2 ^= 0xFFu;
    sip(); sip(); sip(); sip();

    return v0 ^ v1 ^ v2 ^ v3;
}

}

inline uint64_t siphash_2_4(const uint8_t* data, size_t len, uint64_t k0, uint64_t k1) {
    return siphash_detail::siphash_2_4_raw(data, len, k0, k1);
}

inline uint64_t siphash_3u64(uint64_t key, uint64_t d0, uint64_t d1) {
    uint8_t buf[16];
    std::memcpy(buf, &d0, 8);
    std::memcpy(buf + 8, &d1, 8);
    return siphash_detail::siphash_2_4_raw(buf, 16, key, key ^ 0xA5A5A5A5A5A5A5A5ULL);
}

inline void derive_section_key(const uint8_t master[32],
                                uint32_t section_rva,
                                uint32_t section_index,
                                uint8_t out_key[32],
                                uint8_t out_iv[16]) {
    uint64_t m0, m1, m2, m3;
    std::memcpy(&m0, master + 0, 8);
    std::memcpy(&m1, master + 8, 8);
    std::memcpy(&m2, master + 16, 8);
    std::memcpy(&m3, master + 24, 8);

    uint64_t rva64 = static_cast<uint64_t>(section_rva);
    uint64_t idx64 = static_cast<uint64_t>(section_index);

    uint64_t k0 = siphash_3u64(m0, rva64, idx64);
    uint64_t k1 = siphash_3u64(m1, rva64 ^ k0, idx64);
    uint64_t k2 = siphash_3u64(m2, k0 ^ k1, idx64);
    uint64_t k3 = siphash_3u64(m3, k1 ^ k2, idx64);

    std::memcpy(out_key + 0, &k0, 8);
    std::memcpy(out_key + 8, &k1, 8);
    std::memcpy(out_key + 16, &k2, 8);
    std::memcpy(out_key + 24, &k3, 8);

    uint64_t n0 = siphash_3u64(0xDEADC0DEDEADC0DEULL, k0 ^ k3, k1 ^ k2);
    uint64_t n1 = siphash_3u64(0xCAFEBABECAFEBABEULL, k2 ^ k0, k3 ^ k1);
    std::memcpy(out_iv + 0, &n0, 8);
    std::memcpy(out_iv + 8, &n1, 8);
}

inline void derive_pe_mask(uint32_t timestamp, uint32_t size_of_code, uint8_t out_pe_mask[32]) {
    uint64_t h = siphash_3u64(0x4149444150524F54ULL,
                               static_cast<uint64_t>(timestamp),
                               static_cast<uint64_t>(size_of_code));
    for (unsigned i = 0; i < 4u; ++i) {
        unsigned n = i * 17u;
        uint64_t rot = (n == 0u) ? h : ((h << n) | (h >> (64u - n)));
        std::memcpy(out_pe_mask + i * 8u, &rot, 8u);
    }
}

inline void obfuscate_master_key_with_mask(const uint8_t master[32],
                                            const uint8_t mask[32],
                                            uint32_t timestamp,
                                            uint32_t size_of_code,
                                            uint8_t out_obfuscated[32]) {
    uint8_t pe_mask[32];
    derive_pe_mask(timestamp, size_of_code, pe_mask);
    for (int i = 0; i < 32; ++i) {
        out_obfuscated[i] = static_cast<uint8_t>(master[i] ^ mask[i] ^ pe_mask[i]);
    }
}

inline void obfuscate_master_key(const uint8_t master[32],
                                  uint32_t timestamp,
                                  uint32_t size_of_code,
                                  uint8_t out_obfuscated[32],
                                  uint8_t out_mask[32]) {
    (void)BCryptGenRandom(nullptr, out_mask, 32u, BCRYPT_USE_SYSTEM_PREFERRED_RNG);
    obfuscate_master_key_with_mask(master, out_mask, timestamp, size_of_code, out_obfuscated);
}

enum class section_skip_reason_t : uint32_t {
    NONE = 0,
    RELOC = 1,
    RSRC = 2,
    NO_DATA = 3
};

inline bool should_skip_section(const pe_file::section_t& s,
                                 uint32_t reloc_rva,
                                 uint32_t rsrc_rva,
                                 section_skip_reason_t& out) {
    if (reloc_rva != 0u && s.virtual_address == reloc_rva) {
        out = section_skip_reason_t::RELOC;
        return true;
    }
    if (rsrc_rva != 0u && s.virtual_address == rsrc_rva) {
        out = section_skip_reason_t::RSRC;
        return true;
    }
    if (s.data.empty()) {
        out = section_skip_reason_t::NO_DATA;
        return true;
    }
    out = section_skip_reason_t::NONE;
    return false;
}

struct packed_header_t {
    uint32_t magic;
    uint32_t version;
    uint32_t section_count;
    uint32_t import_count;
    uint32_t string_fixup_count;
    uint32_t resource_fixup_count;
    uint32_t section_table_offset;
    uint32_t import_table_offset;
    uint32_t string_table_offset;
    uint32_t resource_table_offset;
    uint32_t master_key_offset;
    uint32_t stub_code_offset;
    uint32_t master_key_pe_timestamp;
    uint32_t master_key_pe_size_of_code;
    uint32_t bind_flags;
    uint32_t aux_offset;
    uint32_t aux_size;
    uint8_t  bind_salt[16];
    uint32_t reserved[3];
};

static_assert(sizeof(packed_header_t) == 96, "packed_header_t must be 96 bytes");

constexpr uint32_t kBindFlagCpuid = 0x1u;

constexpr uint32_t kAuxMagic   = 0x4D585541u;
constexpr uint32_t kAuxVersion = 0x00030000u;

#pragma pack(push, 1)
struct aux_block_t {
    uint32_t magic;
    uint32_t version;
    uint32_t spread_seed;
    uint32_t tamper_response_level;
    uint32_t bind_flags;
    uint32_t reserved0;
    uint8_t  watermark[16];
    uint8_t  watermark_hash[32];
    uint8_t  fingerprint_hash[32];
    uint8_t  bind_salt[16];
    uint32_t phase_flags;
    uint32_t stolen_block_count;
    uint32_t stolen_block_table_rva;
    uint32_t stolen_block_table_size;
    uint64_t rdtsc_entangle_seed;
    uint64_t polymorphic_build_nonce;
    uint32_t stub_signature_tag;
    uint32_t ghost_veh_flags;
    uint8_t  spki_pins[2][32];
    char     primary_host[64];
    char     secondary_host[64];
    uint32_t pin_reserved[4];
};
#pragma pack(pop)

static_assert(sizeof(aux_block_t) == 368, "aux_block_t must be 368 bytes");
static_assert(offsetof(aux_block_t, phase_flags) == 120, "phase_flags offset must remain 120");
static_assert(offsetof(aux_block_t, spki_pins) == 160, "spki_pins offset must be 160");
static_assert(offsetof(aux_block_t, primary_host) == 224, "primary_host offset must be 224");
static_assert(offsetof(aux_block_t, secondary_host) == 288, "secondary_host offset must be 288");
static_assert(offsetof(aux_block_t, pin_reserved) == 352, "pin_reserved offset must be 352");

struct section_descriptor_t {
    uint32_t original_rva;
    uint32_t original_virtual_size;
    uint32_t original_characteristics;
    uint32_t blob_offset;
    uint32_t compressed_size;
    uint32_t encrypted_size;
    uint32_t original_crc32;
    uint32_t reserved;
    uint8_t  layer1_iv[16];
    uint8_t  layer2_nonce[12];
    uint8_t  layer3_iv[8];
    uint32_t layers_applied;
};

static_assert(sizeof(section_descriptor_t) == 72, "section_descriptor_t must be 72 bytes");

constexpr uint32_t kPackedMagic    = 0x41504B44u;
constexpr uint32_t kPackedVersion  = 0x00030000u;
constexpr uint32_t kPackedVersionLegacy = 0x00020000u;

constexpr uint16_t kImportFlagByOrdinal   = 0x1u;
constexpr uint16_t kImportFlagDelayLoaded = 0x2u;

struct import_hash_entry_t {
    uint64_t dll_hash;
    uint64_t func_hash;
    uint32_t iat_rva;
    uint16_t ordinal;
    uint16_t flags;
};

static_assert(sizeof(import_hash_entry_t) == 24, "import_hash_entry_t must be 24 bytes");

struct string_fixup_t {
    uint32_t rva;
    uint32_t length;
    uint8_t  xor_key;
    uint8_t  is_wide;
    uint16_t reserved;
};

static_assert(sizeof(string_fixup_t) == 12, "string_fixup_t must be 12 bytes");

#pragma pack(push, 1)
struct resource_fixup_t {
    uint32_t rva;
    uint32_t size;
    uint64_t rolling_key;
};
#pragma pack(pop)

static_assert(sizeof(resource_fixup_t) == 16, "resource_fixup_t must be 16 bytes");

struct packed_section_blob_t {
    uint32_t original_rva;
    uint32_t original_virtual_size;
    uint32_t original_characteristics;
    uint32_t section_index;
    uint32_t compressed_size;
    uint32_t encrypted_size;
    uint32_t original_crc32;
    uint8_t  layer1_iv[16];
    uint8_t  layer2_nonce[12];
    uint8_t  layer3_iv[8];
    uint32_t layers_applied;
    std::vector<uint8_t> data;
};

struct import_hash_table_t {
    std::vector<import_hash_entry_t> entries;
    std::vector<uint8_t> dll_name_pool;
    std::vector<uint8_t> serialized;
    bool     present;
    uint32_t entry_count;
    uint32_t dll_pool_crc;
};

struct string_fixup_table_t {
    std::vector<string_fixup_t> entries;
    uint32_t entry_count;
    std::vector<uint8_t> serialized;
};

struct resource_fixup_table_t {
    std::vector<resource_fixup_t> entries;
    uint32_t entry_count;
    std::vector<uint8_t> serialized;
};

struct packed_section_layout_t {
    uint32_t header_offset;
    uint32_t section_table_offset;
    uint32_t import_table_offset;
    uint32_t string_table_offset;
    uint32_t resource_table_offset;
    uint32_t blob_data_offset;
    uint32_t master_key_offset;
    uint32_t aux_offset;
    uint32_t stub_offset;
    uint32_t tls_stub_offset;
    uint32_t total_size;
};

struct transform_result_t {
    bool        success;
    std::string error;
    uint32_t    original_entry_point;
    uint32_t    packed_section_rva;
    packed_section_layout_t layout;
    uint8_t     obfuscated_master_key[32];
    uint8_t     key_obfuscation_mask[32];
    uint32_t    master_key_pe_timestamp;
    uint32_t    master_key_pe_size_of_code;
    uint32_t    reserved_main_stub_size;
    uint32_t    reserved_tls_stub_size;
    uint64_t    seed_used;
    uint32_t    bind_flags;
    uint8_t     bind_salt[16];
    uint32_t    aux_size;
    uint32_t    watermark_spread_seed;
    uint8_t     watermark_hash[32];
    uint8_t     fingerprint_hash[32];
    import_hash_table_t    imports;
    string_fixup_table_t   strings;
    resource_fixup_table_t resources;
};

constexpr uint32_t kReservedMainStubSize = 0xC000u;
constexpr uint32_t kReservedTlsStubSize = 0x200u;

struct protect_options_t {
    uint64_t seed = 0;
    bool seed_provided = false;
    bool verbose = false;
    bool strip_rich = true;
    bool strip_debug = true;
    bool encrypt_imports = true;
    bool encrypt_strings = true;
    bool encrypt_resources = true;
    bool pack_sections = true;
    bool mangle_headers = true;
    bool randomize_section_names = true;
    bool embed_watermark = false;
    bool bind_machine = false;
    bool polymorphic_stub = false;
    bool merge_sections = false;
    bool flatten_entropy = false;
    bool deep_steal = false;
    bool ghost_veh = false;
    bool rdtsc_entangle = false;
    bool opaque_predicates = false;
    bool ast_poison = false;
    bool symexec_bombs = false;
    bool llm_poison = false;
    bool jit = false;
    uint32_t tamper_response_level = 0;
    uint8_t  license_hash[16] = {0};
    uint32_t matryoshka_layers = 3u;
    uint8_t  spki_pin_primary[32]   = {0};
    uint8_t  spki_pin_secondary[32] = {0};
    char     primary_host[64]   = {0};
    char     secondary_host[64] = {0};
    bool     spki_pin_primary_provided   = false;
    bool     spki_pin_secondary_provided = false;
    bool     primary_host_provided   = false;
    bool     secondary_host_provided = false;
};

struct section_skip_list {
    static bool name_equals(const char name[8], const char* target) {
        char buf[8] = { 0 };
        for (size_t i = 0; i < 8 && target[i] != '\0'; ++i) {
            buf[i] = target[i];
        }
        return std::memcmp(name, buf, 8) == 0;
    }

    static bool is_skipped(const char name[8]) {
        return name_equals(name, ".reloc")
            || name_equals(name, ".rsrc")
            || name_equals(name, ".gehi")
            || name_equals(name, ".epheme")
            || name_equals(name, ".rdiag")
            || name_equals(name, ".dseal")
            || name_equals(name, ".dthunk")
            || name_equals(name, ".licbind")
            || name_equals(name, ".feat")
            || name_equals(name, ".aidashr");
    }
};

struct import_build_result_t {};

inline uint64_t derive_import_key(const uint8_t master[32]) {
    return siphash_2_4(master, 32, 0x494D504F5254434Eull, 0x494D504F5254434Eull);
}

inline uint64_t derive_string_key(const uint8_t master[32]) {
    return siphash_2_4(master, 32, 0x5354524B45595A31ull, 0x5354524B45595A31ull);
}

inline uint64_t derive_resource_key(const uint8_t master[32]) {
    return siphash_2_4(master, 32, 0x5253525F4B455931ull, 0x5253525F4B455931ull);
}

namespace phase2_detail {

inline std::string to_upper(const std::string& s) {
    std::string r(s);
    for (auto& c : r) {
        if (c >= 'a' && c <= 'z') {
            c = static_cast<char>(c - 32);
        }
    }
    return r;
}

}

inline import_hash_table_t destroy_imports(pe_file::pe_image_t& pe, const uint8_t master[32]) {
    import_hash_table_t out{};
    std::vector<import_hash_entry_t> entries;
    std::vector<std::string> dll_upper;
    std::vector<uint32_t> dll_offsets;
    std::vector<uint8_t> pool;

    auto ensure_dll = [&](const std::string& dll) -> uint32_t {
        std::string u = phase2_detail::to_upper(dll);
        for (size_t i = 0; i < dll_upper.size(); ++i) {
            if (dll_upper[i] == u) {
                return dll_offsets[i];
            }
        }
        uint32_t off = static_cast<uint32_t>(pool.size());
        for (char c : u) {
            pool.push_back(static_cast<uint8_t>(c));
        }
        pool.push_back(0u);
        dll_upper.push_back(u);
        dll_offsets.push_back(off);
        return off;
    };

    auto hash_dll = [](const std::string& dll) -> uint64_t {
        std::string u = phase2_detail::to_upper(dll);
        return u.empty() ? 0ULL : fnv1a64(reinterpret_cast<const uint8_t*>(u.data()), u.size());
    };

    if (pe.data_directories[IMAGE_DIRECTORY_ENTRY_IMPORT].rva != 0u) {
        uint32_t desc_rva = pe.data_directories[IMAGE_DIRECTORY_ENTRY_IMPORT].rva;
        for (;;) {
            uint8_t* dp = pe.rva_ptr(desc_rva);
            if (!dp) {
                break;
            }
            IMAGE_IMPORT_DESCRIPTOR desc{};
            std::memcpy(&desc, dp, sizeof(desc));
            if (desc.Name == 0u && desc.FirstThunk == 0u) {
                std::memset(dp, 0, sizeof(desc));
                break;
            }
            std::string dllname;
            if (uint8_t* np = pe.rva_ptr(desc.Name)) {
                dllname = reinterpret_cast<const char*>(np);
            }
            (void)ensure_dll(dllname);
            uint64_t dh = hash_dll(dllname);
            uint32_t ilt = (desc.OriginalFirstThunk != 0u) ? desc.OriginalFirstThunk : desc.FirstThunk;
            uint32_t iat = desc.FirstThunk;

            for (uint32_t idx = 0; ; ++idx) {
                uint8_t* tp = pe.rva_ptr(ilt + idx * 8u);
                if (!tp) {
                    break;
                }
                uint64_t tv = 0;
                std::memcpy(&tv, tp, 8);
                if (tv == 0ull) {
                    break;
                }
                import_hash_entry_t ent{};
                ent.dll_hash = dh;
                ent.iat_rva = iat + idx * 8u;
                ent.flags = 0u;
                if (tv & (1ull << 63)) {
                    ent.ordinal = static_cast<uint16_t>(tv & 0xFFFFu);
                    uint16_t ord_le = ent.ordinal;
                    ent.func_hash = fnv1a64(reinterpret_cast<const uint8_t*>(&ord_le), 2);
                    ent.flags |= kImportFlagByOrdinal;
                } else {
                    uint32_t hint_rva = static_cast<uint32_t>(tv & 0x7FFFFFFFull);
                    if (uint8_t* hp = pe.rva_ptr(hint_rva)) {
                        uint16_t hint = 0;
                        std::memcpy(&hint, hp, 2);
                        ent.ordinal = hint;
                        const char* fn = reinterpret_cast<const char*>(hp + 2);
                        size_t flen = std::strlen(fn);
                        ent.func_hash = flen > 0
                            ? fnv1a64(reinterpret_cast<const uint8_t*>(fn), flen)
                            : 0ULL;
                        hp[0] = 0;
                        hp[1] = 0;
                        uint8_t* q = hp + 2;
                        while (*q != 0u) {
                            *q = 0u;
                            ++q;
                        }
                    }
                }
                entries.push_back(ent);
                std::memset(tp, 0, 8);
                if (uint8_t* itp = pe.rva_ptr(iat + idx * 8u); itp != nullptr && iat != ilt) {
                    std::memset(itp, 0, 8);
                }
            }
            if (iat != ilt) {
                for (uint32_t idx = 0; ; ++idx) {
                    uint8_t* tp = pe.rva_ptr(iat + idx * 8u);
                    if (!tp) {
                        break;
                    }
                    uint64_t tv = 0;
                    std::memcpy(&tv, tp, 8);
                    if (tv == 0ull) {
                        break;
                    }
                    std::memset(tp, 0, 8);
                }
            } else {
                for (uint32_t idx = 0; ; ++idx) {
                    uint8_t* tp = pe.rva_ptr(iat + idx * 8u);
                    if (!tp) {
                        break;
                    }
                    uint64_t tv = 0;
                    std::memcpy(&tv, tp, 8);
                    if (tv == 0ull) {
                        break;
                    }
                    std::memset(tp, 0, 8);
                }
            }
            if (uint8_t* np = pe.rva_ptr(desc.Name)) {
                while (*np != 0u) {
                    *np = 0u;
                    ++np;
                }
            }
            std::memset(dp, 0, sizeof(desc));
            desc_rva += sizeof(IMAGE_IMPORT_DESCRIPTOR);
        }
    }

    if (pe.data_directories[IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT].rva != 0u) {
        uint32_t desc_rva = pe.data_directories[IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT].rva;
        for (;;) {
            const uint8_t* dp = pe.rva_ptr(desc_rva);
            if (!dp) {
                break;
            }
            uint32_t name_rva = 0, iat = 0, int_rva = 0;
            std::memcpy(&name_rva, dp + 4, 4);
            std::memcpy(&iat, dp + 12, 4);
            std::memcpy(&int_rva, dp + 16, 4);
            if (name_rva == 0u && iat == 0u) {
                break;
            }
            std::string dllname;
            if (const uint8_t* np = pe.rva_ptr(name_rva)) {
                dllname = reinterpret_cast<const char*>(np);
            }
            (void)ensure_dll(dllname);
            uint64_t dh = hash_dll(dllname);
            uint32_t walk_rva = (int_rva != 0u) ? int_rva : iat;
            for (uint32_t idx = 0; ; ++idx) {
                const uint8_t* tp = pe.rva_ptr(walk_rva + idx * 8u);
                if (!tp) {
                    break;
                }
                uint64_t tv = 0;
                std::memcpy(&tv, tp, 8);
                if (tv == 0ull) {
                    break;
                }
                import_hash_entry_t ent{};
                ent.dll_hash = dh;
                ent.iat_rva = iat + idx * 8u;
                ent.flags = kImportFlagDelayLoaded;
                if (tv & (1ull << 63)) {
                    ent.ordinal = static_cast<uint16_t>(tv & 0xFFFFu);
                    uint16_t ord_le = ent.ordinal;
                    ent.func_hash = fnv1a64(reinterpret_cast<const uint8_t*>(&ord_le), 2);
                    ent.flags |= kImportFlagByOrdinal;
                } else {
                    uint32_t hint_rva = static_cast<uint32_t>(tv & 0x7FFFFFFFull);
                    if (const uint8_t* hp = pe.rva_ptr(hint_rva)) {
                        uint16_t hint = 0;
                        std::memcpy(&hint, hp, 2);
                        ent.ordinal = hint;
                        const char* fn = reinterpret_cast<const char*>(hp + 2);
                        size_t flen = std::strlen(fn);
                        ent.func_hash = flen > 0
                            ? fnv1a64(reinterpret_cast<const uint8_t*>(fn), flen)
                            : 0ULL;
                    }
                }
                entries.push_back(ent);
            }
            desc_rva += 32u;
        }
    }

    uint32_t pool_crc = pool.empty() ? 0u : crc32c(pool.data(), pool.size());

    uint64_t key64 = derive_import_key(master);
    uint8_t kb[8];
    std::memcpy(kb, &key64, 8);
    std::vector<uint8_t> scrambled(pool.size());
    for (size_t i = 0; i < pool.size(); ++i) {
        scrambled[i] = static_cast<uint8_t>(pool[i] ^ kb[i & 7u]);
    }

    std::sort(entries.begin(), entries.end(),
              [](const import_hash_entry_t& a, const import_hash_entry_t& b) {
        if (a.dll_hash != b.dll_hash) {
            return a.dll_hash < b.dll_hash;
        }
        return a.func_hash < b.func_hash;
    });

    uint32_t count = static_cast<uint32_t>(entries.size());
    uint32_t pool_size = static_cast<uint32_t>(scrambled.size());
    uint32_t total = 4u + count * 24u + 4u + pool_size;

    std::vector<uint8_t> ser(total, 0);
    uint32_t cursor = 0;
    std::memcpy(ser.data() + cursor, &count, 4);
    cursor += 4u;
    if (count > 0) {
        std::memcpy(ser.data() + cursor, entries.data(), count * 24u);
        cursor += count * 24u;
    }
    std::memcpy(ser.data() + cursor, &pool_size, 4);
    cursor += 4u;
    if (pool_size > 0) {
        std::memcpy(ser.data() + cursor, scrambled.data(), pool_size);
    }

    out.present = (count > 0) || (pool_size > 0);
    out.entry_count = count;
    out.dll_pool_crc = pool_crc;
    out.entries = std::move(entries);
    out.dll_name_pool = std::move(scrambled);
    out.serialized = std::move(ser);

    pe.data_directories[IMAGE_DIRECTORY_ENTRY_IMPORT].rva = 0;
    pe.data_directories[IMAGE_DIRECTORY_ENTRY_IMPORT].size = 0;
    pe.optional_header.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress = 0;
    pe.optional_header.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size = 0;
    pe.data_directories[IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT].rva = 0;
    pe.data_directories[IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT].size = 0;
    pe.optional_header.DataDirectory[IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT].VirtualAddress = 0;
    pe.optional_header.DataDirectory[IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT].Size = 0;
    pe.imports.clear();

    return out;
}

namespace phase3_detail {

inline bool is_string_skipped_section(const char name[8]) {
    static const char* skip[] = { ".rsrc", ".reloc", ".pdata", ".xdata", ".idata", ".tls" };
    for (const char* t : skip) {
        char buf[8] = { 0 };
        for (size_t i = 0; i < 8 && t[i] != '\0'; ++i) {
            buf[i] = t[i];
        }
        if (std::memcmp(name, buf, 8) == 0) {
            return true;
        }
    }
    return false;
}

struct range_t {
    uint32_t offset;
    uint32_t length;
    uint8_t  is_wide;
};

}

struct preserve_string_range_t {
    uint32_t rva;
    uint32_t length;
};

inline std::vector<preserve_string_range_t> collect_loader_string_ranges(const pe_file::pe_image_t& pe, bool include_imports) {
    std::vector<preserve_string_range_t> ranges;
    auto add_range = [&](uint32_t rva, uint32_t length) {
        if (rva == 0u || length == 0u) {
            return;
        }
        ranges.push_back({rva, length});
    };
    auto add_string = [&](uint32_t rva) {
        if (rva == 0u) {
            return;
        }
        const uint8_t* p = pe.rva_ptr(rva);
        if (!p) {
            return;
        }
        size_t len = std::strlen(reinterpret_cast<const char*>(p));
        if (len == 0u) {
            return;
        }
        add_range(rva, static_cast<uint32_t>(len + 1u));
    };

    if (include_imports && pe.data_directories[IMAGE_DIRECTORY_ENTRY_IMPORT].rva != 0u) {
        uint32_t desc_rva = pe.data_directories[IMAGE_DIRECTORY_ENTRY_IMPORT].rva;
        for (;;) {
            const uint8_t* dp = pe.rva_ptr(desc_rva);
            if (!dp) {
                break;
            }
            IMAGE_IMPORT_DESCRIPTOR desc{};
            std::memcpy(&desc, dp, sizeof(desc));
            if (desc.Name == 0u && desc.FirstThunk == 0u) {
                break;
            }
            add_string(desc.Name);
            uint32_t ilt = (desc.OriginalFirstThunk != 0u) ? desc.OriginalFirstThunk : desc.FirstThunk;
            for (uint32_t idx = 0; ; ++idx) {
                const uint8_t* tp = pe.rva_ptr(ilt + idx * 8u);
                if (!tp) {
                    break;
                }
                uint64_t tv = 0;
                std::memcpy(&tv, tp, 8);
                if (tv == 0ull) {
                    break;
                }
                if ((tv & (1ull << 63)) == 0ull) {
                    uint32_t hint_rva = static_cast<uint32_t>(tv & 0x7FFFFFFFu);
                    const uint8_t* hp = pe.rva_ptr(hint_rva);
                    if (hp) {
                        const char* fn = reinterpret_cast<const char*>(hp + 2);
                        size_t len = std::strlen(fn);
                        if (len > 0u) {
                            add_range(hint_rva, static_cast<uint32_t>(2u + len + 1u));
                        }
                    }
                }
            }
            desc_rva += static_cast<uint32_t>(sizeof(IMAGE_IMPORT_DESCRIPTOR));
        }
    }

    if (include_imports && pe.data_directories[IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT].rva != 0u) {
        uint32_t desc_rva = pe.data_directories[IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT].rva;
        for (;;) {
            const uint8_t* dp = pe.rva_ptr(desc_rva);
            if (!dp) {
                break;
            }
            uint32_t name_rva = 0, iat = 0, int_rva = 0;
            std::memcpy(&name_rva, dp + 4, 4);
            std::memcpy(&iat, dp + 12, 4);
            std::memcpy(&int_rva, dp + 16, 4);
            if (name_rva == 0u && iat == 0u) {
                break;
            }
            add_string(name_rva);
            uint32_t walk_rva = (int_rva != 0u) ? int_rva : iat;
            for (uint32_t idx = 0; ; ++idx) {
                const uint8_t* tp = pe.rva_ptr(walk_rva + idx * 8u);
                if (!tp) {
                    break;
                }
                uint64_t tv = 0;
                std::memcpy(&tv, tp, 8);
                if (tv == 0ull) {
                    break;
                }
                if ((tv & (1ull << 63)) == 0ull) {
                    uint32_t hint_rva = static_cast<uint32_t>(tv & 0x7FFFFFFFu);
                    const uint8_t* hp = pe.rva_ptr(hint_rva);
                    if (hp) {
                        const char* fn = reinterpret_cast<const char*>(hp + 2);
                        size_t len = std::strlen(fn);
                        if (len > 0u) {
                            add_range(hint_rva, static_cast<uint32_t>(2u + len + 1u));
                        }
                    }
                }
            }
            desc_rva += 32u;
        }
    }

    {
        uint32_t exp_rva = pe.data_directories[IMAGE_DIRECTORY_ENTRY_EXPORT].rva;
        uint32_t exp_size = pe.data_directories[IMAGE_DIRECTORY_ENTRY_EXPORT].size;
        if (exp_rva != 0u && exp_size != 0u) {
            const uint8_t* dir_ptr = pe.rva_ptr(exp_rva);
            if (dir_ptr) {
                IMAGE_EXPORT_DIRECTORY ed{};
                std::memcpy(&ed, dir_ptr, sizeof(ed));
                add_string(ed.Name);
                if (ed.AddressOfNames != 0u && ed.NumberOfNames != 0u) {
                    const uint8_t* names_ptr = pe.rva_ptr(ed.AddressOfNames);
                    if (names_ptr) {
                        for (uint32_t i = 0; i < ed.NumberOfNames; ++i) {
                            uint32_t name_rva = 0;
                            std::memcpy(&name_rva, names_ptr + i * 4u, 4);
                            add_string(name_rva);
                        }
                    }
                }
                if (ed.AddressOfFunctions != 0u && ed.NumberOfFunctions != 0u) {
                    const uint8_t* funcs_ptr = pe.rva_ptr(ed.AddressOfFunctions);
                    if (funcs_ptr) {
                        uint32_t exp_end = exp_rva + exp_size;
                        for (uint32_t i = 0; i < ed.NumberOfFunctions; ++i) {
                            uint32_t func_rva = 0;
                            std::memcpy(&func_rva, funcs_ptr + i * 4u, 4);
                            if (func_rva >= exp_rva && func_rva < exp_end) {
                                add_string(func_rva);
                            }
                        }
                    }
                }
            }
        }
    }

    return ranges;
}

inline string_fixup_table_t encrypt_strings(pe_file::pe_image_t& pe, const uint8_t master[32], const std::vector<preserve_string_range_t>& preserve_ranges) {
    string_fixup_table_t out{};
    uint64_t base_key = derive_string_key(master);
    uint8_t base_xor = static_cast<uint8_t>(base_key & 0xFFull);

    std::vector<string_fixup_t> fixups;

    for (auto& sec : pe.sections) {
        if ((sec.characteristics & IMAGE_SCN_CNT_INITIALIZED_DATA) == 0u) {
            continue;
        }
        if (section_skip_list::is_skipped(sec.name)) {
            continue;
        }
        if (phase3_detail::is_string_skipped_section(sec.name)) {
            continue;
        }
        if (sec.data.empty()) {
            continue;
        }

        std::vector<phase3_detail::range_t> hits;
        size_t n = sec.data.size();
        const uint8_t* d = sec.data.data();

        size_t i = 0;
        while (i < n) {
            size_t start = i;
            while (i < n && d[i] >= 0x20u && d[i] <= 0x7Eu) {
                ++i;
            }
            if (i > start && i < n && d[i] == 0u) {
                size_t ascii_len = i - start;
                size_t total = ascii_len + 1u;
                if (ascii_len >= 6u && ascii_len <= 4096u) {
                    phase3_detail::range_t r{};
                    r.offset = static_cast<uint32_t>(start);
                    r.length = static_cast<uint32_t>(total);
                    r.is_wide = 0u;
                    hits.push_back(r);
                }
                ++i;
            } else if (i == start) {
                ++i;
            }
        }

        for (size_t j = 0; j + 1 < n; j += 2) {
            if ((j & 1u) != 0u) {
                continue;
            }
            size_t start = j;
            size_t k = j;
            while (k + 1 < n && d[k + 1] == 0u && d[k] >= 0x20u && d[k] <= 0x7Eu) {
                k += 2;
            }
            size_t wchars = (k - start) / 2u;
            if (wchars > 0u && k + 1 < n && d[k] == 0u && d[k + 1] == 0u) {
                size_t total_bytes = wchars * 2u + 2u;
                if (wchars >= 6u && wchars <= 4096u) {
                    phase3_detail::range_t r{};
                    r.offset = static_cast<uint32_t>(start);
                    r.length = static_cast<uint32_t>(total_bytes);
                    r.is_wide = 1u;
                    hits.push_back(r);
                }
                j = k;
            }
        }

        std::sort(hits.begin(), hits.end(),
                  [](const phase3_detail::range_t& a, const phase3_detail::range_t& b) {
            if (a.offset != b.offset) {
                return a.offset < b.offset;
            }
            return a.length > b.length;
        });

        std::vector<phase3_detail::range_t> dedup;
        uint32_t covered_end = 0u;
        for (const auto& h : hits) {
            if (h.offset >= covered_end) {
                dedup.push_back(h);
                covered_end = h.offset + h.length;
            }
        }

        for (const auto& h : dedup) {
            uint32_t rva = sec.virtual_address + h.offset;
            uint32_t s_end = rva + h.length;
            bool overlaps_preserve = false;
            for (const auto& pr : preserve_ranges) {
                uint32_t pr_end = pr.rva + pr.length;
                if (pr.rva < s_end && pr_end > rva) {
                    overlaps_preserve = true;
                    break;
                }
            }
            if (overlaps_preserve) {
                continue;
            }
            uint8_t rva_low = static_cast<uint8_t>(rva & 0xFFu);
            uint8_t* p = sec.data.data() + h.offset;
            for (uint32_t k = 0; k < h.length; ++k) {
                uint8_t kb = static_cast<uint8_t>(base_xor ^ static_cast<uint8_t>((k * 0x9Eu) & 0xFFu) ^ rva_low);
                p[k] = static_cast<uint8_t>(p[k] ^ kb);
            }
            string_fixup_t sf{};
            sf.rva = rva;
            sf.length = h.length;
            sf.xor_key = base_xor;
            sf.is_wide = h.is_wide;
            sf.reserved = 0u;
            fixups.push_back(sf);
        }
    }

    uint32_t count = static_cast<uint32_t>(fixups.size());
    out.entry_count = count;
    uint32_t total = 4u + count * 12u;
    out.serialized.assign(total, 0);
    std::memcpy(out.serialized.data(), &count, 4);
    if (count > 0) {
        for (uint32_t i2 = 0; i2 < count; ++i2) {
            std::memcpy(out.serialized.data() + 4u + i2 * 12u, &fixups[i2], 12u);
        }
    }
    out.entries = std::move(fixups);
    return out;
}

namespace phase4_detail {

inline bool is_plaintext_type(uint32_t type_id) {
    switch (type_id) {
        case 1u:  return true;
        case 3u:  return true;
        case 6u:  return true;
        case 9u:  return true;
        case 12u: return true;
        case 14u: return true;
        case 16u: return true;
        case 24u: return true;
        default:  return false;
    }
}

}

inline resource_fixup_table_t encrypt_resources(pe_file::pe_image_t& pe, const uint8_t master[32]) {
    resource_fixup_table_t out{};
    uint64_t base_key = derive_resource_key(master);

    std::vector<resource_fixup_t> fixups;

    for (const auto& r : pe.resources) {
        if (r.type_is_string) {
            continue;
        }
        if (r.type_id != 10u) {
            continue;
        }
        if (r.size == 0u) {
            continue;
        }
        uint8_t* d = pe.rva_ptr(r.data_rva);
        if (!d) {
            continue;
        }
        uint64_t rolling_key = siphash_3u64(base_key,
                                             static_cast<uint64_t>(r.data_rva),
                                             static_cast<uint64_t>(r.size));
        uint32_t n_chunks = r.size / 8u;
        for (uint32_t i = 0; i < n_chunks; ++i) {
            uint64_t ki = rolling_key + static_cast<uint64_t>(i) * 0x9E3779B97F4A7C15ull;
            uint64_t v = 0;
            std::memcpy(&v, d + i * 8u, 8);
            v ^= ki;
            std::memcpy(d + i * 8u, &v, 8);
        }
        uint32_t tail_start = n_chunks * 8u;
        uint32_t tail = r.size - tail_start;
        if (tail > 0u) {
            uint64_t ki = rolling_key + static_cast<uint64_t>(n_chunks) * 0x9E3779B97F4A7C15ull;
            uint8_t kb[8];
            std::memcpy(kb, &ki, 8);
            for (uint32_t j = 0; j < tail; ++j) {
                d[tail_start + j] = static_cast<uint8_t>(d[tail_start + j] ^ kb[j]);
            }
        }
        resource_fixup_t rf{};
        rf.rva = r.data_rva;
        rf.size = r.size;
        rf.rolling_key = rolling_key;
        fixups.push_back(rf);
    }

    uint32_t count = static_cast<uint32_t>(fixups.size());
    out.entry_count = count;
    uint32_t total = 4u + count * static_cast<uint32_t>(sizeof(resource_fixup_t));
    out.serialized.assign(total, 0);
    std::memcpy(out.serialized.data(), &count, 4);
    if (count > 0) {
        std::memcpy(out.serialized.data() + 4u, fixups.data(), count * sizeof(resource_fixup_t));
    }
    out.entries = std::move(fixups);
    return out;
}

struct rng_state_t {
    uint64_t s;

    uint64_t next_u64() {
        s += 0x9E3779B97F4A7C15ull;
        uint64_t z = s;
        z = (z ^ (z >> 30)) * 0xBF58476D1CE4E5B9ull;
        z = (z ^ (z >> 27)) * 0x94D049BB133111EBull;
        return z ^ (z >> 31);
    }

    void next_bytes(uint8_t* out, size_t n) {
        while (n > 0) {
            uint64_t v = next_u64();
            size_t c = n < 8u ? n : 8u;
            std::memcpy(out, &v, c);
            out += c;
            n -= c;
        }
    }

    uint32_t next_u32_in_range(uint32_t lo, uint32_t hi) {
        if (hi <= lo) {
            return lo;
        }
        uint64_t r = next_u64();
        uint64_t span = static_cast<uint64_t>(hi) - static_cast<uint64_t>(lo) + 1ull;
        return lo + static_cast<uint32_t>(r % span);
    }
};

inline rng_state_t make_rng(uint64_t seed) {
    rng_state_t r{};
    r.s = seed;
    (void)r.next_u64();
    return r;
}

inline void strip_rich_header(pe_file::pe_image_t& pe) {
    if (!pe.has_rich_header) {
        return;
    }
    if (pe.rich_offset + pe.rich_size <= pe.dos_stub.size()) {
        std::memset(pe.dos_stub.data() + pe.rich_offset, 0, pe.rich_size);
    }
    pe.has_rich_header = false;
    pe.rich_offset = 0;
    pe.rich_size = 0;
}

inline void strip_debug_directory(pe_file::pe_image_t& pe) {
    uint32_t dbg_rva = pe.data_directories[IMAGE_DIRECTORY_ENTRY_DEBUG].rva;
    uint32_t dbg_size = pe.data_directories[IMAGE_DIRECTORY_ENTRY_DEBUG].size;
    if (dbg_rva != 0u && dbg_size != 0u) {
        uint32_t count = dbg_size / static_cast<uint32_t>(sizeof(IMAGE_DEBUG_DIRECTORY));
        for (uint32_t i = 0; i < count; ++i) {
            uint8_t* dp = pe.rva_ptr(dbg_rva + i * static_cast<uint32_t>(sizeof(IMAGE_DEBUG_DIRECTORY)));
            if (!dp) {
                break;
            }
            IMAGE_DEBUG_DIRECTORY dd{};
            std::memcpy(&dd, dp, sizeof(dd));
            if (dd.PointerToRawData != 0u && dd.SizeOfData != 0u) {
                for (auto& sec : pe.sections) {
                    if (dd.AddressOfRawData >= sec.virtual_address &&
                        dd.AddressOfRawData < sec.virtual_address + static_cast<uint32_t>(sec.data.size())) {
                        uint32_t off = dd.AddressOfRawData - sec.virtual_address;
                        uint32_t z = dd.SizeOfData;
                        if (off + z <= sec.data.size()) {
                            std::memset(sec.data.data() + off, 0, z);
                        }
                        break;
                    }
                }
            }
            std::memset(dp, 0, sizeof(dd));
        }
    }
    pe.data_directories[IMAGE_DIRECTORY_ENTRY_DEBUG].rva = 0;
    pe.data_directories[IMAGE_DIRECTORY_ENTRY_DEBUG].size = 0;
    pe.optional_header.DataDirectory[IMAGE_DIRECTORY_ENTRY_DEBUG].VirtualAddress = 0;
    pe.optional_header.DataDirectory[IMAGE_DIRECTORY_ENTRY_DEBUG].Size = 0;
}

inline void mangle_header(pe_file::pe_image_t& pe, rng_state_t& rng) {
    strip_rich_header(pe);
    strip_debug_directory(pe);
    pe.file_header.TimeDateStamp = rng.next_u32_in_range(1546300800u, 1735689600u);
    pe.optional_header.CheckSum = 0;
    pe.optional_header.MajorLinkerVersion = static_cast<BYTE>(rng.next_u32_in_range(10u, 14u));
    pe.optional_header.MinorLinkerVersion = static_cast<BYTE>(rng.next_u32_in_range(0u, 40u));
    pe.optional_header.LoaderFlags = 0;
    pe.optional_header.Win32VersionValue = 0;
    pe.data_directories[IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT].rva = 0;
    pe.data_directories[IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT].size = 0;
    pe.optional_header.DataDirectory[IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT].VirtualAddress = 0;
    pe.optional_header.DataDirectory[IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT].Size = 0;
}

inline void randomize_section_names(pe_file::pe_image_t& pe, rng_state_t& rng) {
    static const char kB64[64] = {
        'A','B','C','D','E','F','G','H','I','J','K','L','M','N','O','P',
        'Q','R','S','T','U','V','W','X','Y','Z','a','b','c','d','e','f',
        'g','h','i','j','k','l','m','n','o','p','q','r','s','t','u','v',
        'w','x','y','z','0','1','2','3','4','5','6','7','8','9','-','_'
    };
    for (auto& sec : pe.sections) {
        if (section_skip_list::name_equals(sec.name, ".rsrc") ||
            section_skip_list::name_equals(sec.name, ".reloc") ||
            section_skip_list::name_equals(sec.name, ".packed") ||
            section_skip_list::name_equals(sec.name, ".dseal") ||
            section_skip_list::name_equals(sec.name, ".dthunk") ||
            section_skip_list::name_equals(sec.name, ".licbind") ||
            section_skip_list::name_equals(sec.name, ".feat") ||
            section_skip_list::name_equals(sec.name, ".aidashr")) {
            continue;
        }
        char nn[8] = { 0 };
        nn[0] = '.';
        for (int k = 0; k < 5; ++k) {
            uint32_t idx = rng.next_u32_in_range(0u, 63u);
            nn[1 + k] = kB64[idx];
        }
        nn[6] = 0;
        nn[7] = 0;
        std::memcpy(sec.name, nn, 8);
    }
}

namespace rng_detail {

struct rng_source {
    bool seeded;
    chacha_detail::chacha20_drbg drbg;

    void init(const uint8_t* seed) {
        if (seed != nullptr) {
            seeded = true;
            drbg.init(seed);
        } else {
            seeded = false;
        }
    }

    void get(uint8_t* out, size_t n) {
        if (seeded) {
            drbg.get(out, n);
        } else {
            (void)BCryptGenRandom(nullptr, out, static_cast<ULONG>(n), BCRYPT_USE_SYSTEM_PREFERRED_RNG);
        }
    }
};

inline void init_from_u64_seed(rng_source& rs, uint64_t seed, bool seed_provided) {
    if (seed_provided) {
        uint8_t seed32[32];
        rng_state_t s = make_rng(seed);
        s.next_bytes(seed32, 32);
        rs.init(seed32);
    } else {
        rs.init(nullptr);
    }
}

}

inline std::vector<packed_section_blob_t> pack_sections(pe_file::pe_image_t& pe,
                                                         const uint8_t master[32],
                                                         uint32_t exception_rva,
                                                         uint32_t exception_size,
                                                         const std::vector<uint32_t>& keep_intact_section_rvas,
                                                         uint32_t matryoshka_layers) {
    std::vector<packed_section_blob_t> blobs;

    uint32_t reloc_rva = pe.data_directories[IMAGE_DIRECTORY_ENTRY_BASERELOC].rva;
    uint32_t rsrc_rva  = pe.data_directories[IMAGE_DIRECTORY_ENTRY_RESOURCE].rva;

    uint8_t hwid_anchor[32];
    uint8_t tpm_anchor[32];
    uint8_t srv_anchor[32];
    uint8_t build_seed[32];
    matryoshka_detail::compute_hwid_anchor(hwid_anchor);
    matryoshka_detail::compute_tpm_anchor(tpm_anchor);
    matryoshka_detail::compute_server_anchor(srv_anchor);
    matryoshka_detail::derive_build_seed_from_master(master, build_seed);

    for (uint32_t i = 0; i < static_cast<uint32_t>(pe.sections.size()); ++i) {
        auto& sec = pe.sections[i];
        section_skip_reason_t reason = section_skip_reason_t::NONE;
        if (should_skip_section(sec, reloc_rva, rsrc_rva, reason)) {
            continue;
        }
        if (section_skip_list::is_skipped(sec.name)) {
            continue;
        }
        bool keep_intact_hit = false;
        for (uint32_t kva : keep_intact_section_rvas) {
            if (kva != 0u && sec.virtual_address == kva) {
                keep_intact_hit = true;
                break;
            }
        }
        if (keep_intact_hit) {
            continue;
        }
        if (exception_rva != 0u && exception_size != 0u) {
            const uint32_t sec_end = sec.virtual_address + sec.virtual_size;
            const uint32_t exc_end = exception_rva + exception_size;
            if (exception_rva < sec_end && exc_end > sec.virtual_address) {
                continue;
            }
        }

        uint32_t plain_crc = crc32c(sec.data.data(), sec.data.size());

        std::vector<uint8_t> compressed = lz_compress(sec.data.data(), sec.data.size());
        if (compressed.empty()) {
            continue;
        }

        packed_section_blob_t pb{};
        pb.original_rva = sec.virtual_address;
        pb.original_virtual_size = sec.virtual_size;
        pb.original_characteristics = sec.characteristics;
        pb.section_index = i;
        pb.compressed_size = static_cast<uint32_t>(compressed.size());
        pb.original_crc32 = plain_crc;

        uint32_t applied = (matryoshka_layers >= 3u) ? 3u : 1u;
        pb.layers_applied = applied;

        if (applied >= 3u) {
            uint8_t l1_key[16];
            uint8_t l2_key[32];
            uint8_t l3_key[16];
            matryoshka_detail::derive_layer1_key(hwid_anchor, build_seed, sec.virtual_address, i, l1_key);
            matryoshka_detail::derive_layer2_key(tpm_anchor, build_seed, sec.virtual_address, i, l2_key);
            matryoshka_detail::derive_layer3_key(srv_anchor, build_seed, sec.virtual_address, i, l3_key);

            uint8_t l1_iv[16] = {0};
            uint8_t l2_nonce[12] = {0};
            uint8_t l3_iv[8] = {0};
            BCryptGenRandom(nullptr, l1_iv, 16, BCRYPT_USE_SYSTEM_PREFERRED_RNG);
            BCryptGenRandom(nullptr, l2_nonce, 12, BCRYPT_USE_SYSTEM_PREFERRED_RNG);
            BCryptGenRandom(nullptr, l3_iv, 8, BCRYPT_USE_SYSTEM_PREFERRED_RNG);
            std::memcpy(pb.layer1_iv, l1_iv, 16);
            std::memcpy(pb.layer2_nonce, l2_nonce, 12);
            std::memcpy(pb.layer3_iv, l3_iv, 8);

            std::vector<uint8_t> layer1(compressed.size());
            aes_detail::aes128_ctr(l1_key, l1_iv, compressed.data(), layer1.data(), compressed.size());

            std::vector<uint8_t> layer2(layer1.size());
            chacha_detail::chacha20_xor(l2_key, l2_nonce, layer1.data(), layer2.data(), layer1.size());

            std::vector<uint8_t> layer3(layer2.size());
            xtea_ctr(l3_key, l3_iv, layer2.data(), layer3.data(), layer2.size());

            pb.encrypted_size = static_cast<uint32_t>(layer3.size());
            pb.data = std::move(layer3);
        } else {
            uint8_t section_key[32];
            uint8_t iv[16];
            derive_section_key(master, sec.virtual_address, i, section_key, iv);

            std::vector<uint8_t> encrypted(compressed.size());
            aes_detail::aes256_ctr(section_key, iv, compressed.data(), encrypted.data(), compressed.size());

            std::memset(pb.layer1_iv, 0, 16);
            std::memset(pb.layer2_nonce, 0, 12);
            std::memset(pb.layer3_iv, 0, 8);
            pb.encrypted_size = static_cast<uint32_t>(encrypted.size());
            pb.data = std::move(encrypted);
        }

        blobs.push_back(std::move(pb));
    }

    return blobs;
}

inline packed_section_layout_t build_packed_section(pe_file::pe_image_t& pe,
                                                     const uint8_t obfuscated_master_key[32],
                                                     const uint8_t key_obfuscation_mask[32],
                                                     uint32_t master_key_pe_timestamp,
                                                     uint32_t master_key_pe_size_of_code,
                                                     const std::vector<packed_section_blob_t>& blobs,
                                                     const import_hash_table_t& imports,
                                                     const string_fixup_table_t& strings,
                                                     const resource_fixup_table_t& resources,
                                                     const std::vector<uint8_t>& stub_code,
                                                     const std::vector<uint8_t>& tls_stub_code,
                                                     uint32_t bind_flags,
                                                     const uint8_t bind_salt[16],
                                                     const aux_block_t& aux,
                                                     rng_detail::rng_source& rng) {
    packed_section_layout_t layout{};

    uint32_t section_count = static_cast<uint32_t>(blobs.size());
    uint32_t section_table_bytes = section_count * static_cast<uint32_t>(sizeof(section_descriptor_t));

    uint32_t cursor = static_cast<uint32_t>(sizeof(packed_header_t));
    layout.header_offset = 0u;
    layout.section_table_offset = cursor;
    cursor += section_table_bytes;

    layout.blob_data_offset = cursor;
    std::vector<uint32_t> blob_offsets(blobs.size(), 0u);
    for (size_t i = 0; i < blobs.size(); ++i) {
        blob_offsets[i] = cursor;
        cursor += blobs[i].encrypted_size;
    }

    layout.import_table_offset = imports.present ? cursor : 0u;
    cursor += static_cast<uint32_t>(imports.serialized.size());

    layout.string_table_offset = strings.serialized.empty() ? 0u : cursor;
    cursor += static_cast<uint32_t>(strings.serialized.size());

    layout.resource_table_offset = resources.serialized.empty() ? 0u : cursor;
    cursor += static_cast<uint32_t>(resources.serialized.size());

    layout.master_key_offset = cursor;
    cursor += 64u;

    layout.aux_offset = cursor;
    cursor += static_cast<uint32_t>(sizeof(aux_block_t));

    layout.tls_stub_offset = tls_stub_code.empty() ? 0u : cursor;
    cursor += static_cast<uint32_t>(tls_stub_code.size());

    layout.stub_offset = stub_code.empty() ? 0u : cursor;
    cursor += static_cast<uint32_t>(stub_code.size());

    layout.total_size = cursor;

    std::vector<uint8_t> buf(layout.total_size, 0);

    packed_header_t hdr{};
    hdr.magic = kPackedMagic;
    hdr.version = kPackedVersion;
    hdr.section_count = section_count;
    hdr.import_count = imports.entry_count;
    hdr.string_fixup_count = strings.entry_count;
    hdr.resource_fixup_count = resources.entry_count;
    hdr.section_table_offset = layout.section_table_offset;
    hdr.import_table_offset = layout.import_table_offset;
    hdr.string_table_offset = layout.string_table_offset;
    hdr.resource_table_offset = layout.resource_table_offset;
    hdr.master_key_offset = layout.master_key_offset;
    hdr.stub_code_offset = layout.stub_offset;
    hdr.master_key_pe_timestamp = master_key_pe_timestamp;
    hdr.master_key_pe_size_of_code = master_key_pe_size_of_code;
    hdr.bind_flags = bind_flags;
    hdr.aux_offset = layout.aux_offset;
    hdr.aux_size = static_cast<uint32_t>(sizeof(aux_block_t));
    std::memcpy(hdr.bind_salt, bind_salt, 16);
    std::memcpy(buf.data(), &hdr, sizeof(hdr));

    for (size_t i = 0; i < blobs.size(); ++i) {
        section_descriptor_t d{};
        d.original_rva = blobs[i].original_rva;
        d.original_virtual_size = blobs[i].original_virtual_size;
        d.original_characteristics = blobs[i].original_characteristics;
        d.blob_offset = blob_offsets[i];
        d.compressed_size = blobs[i].compressed_size;
        d.encrypted_size = blobs[i].encrypted_size;
        d.original_crc32 = blobs[i].original_crc32;
        d.reserved = blobs[i].section_index;
        std::memcpy(d.layer1_iv, blobs[i].layer1_iv, 16);
        std::memcpy(d.layer2_nonce, blobs[i].layer2_nonce, 12);
        std::memcpy(d.layer3_iv, blobs[i].layer3_iv, 8);
        d.layers_applied = blobs[i].layers_applied;
        std::memcpy(buf.data() + layout.section_table_offset + i * sizeof(d), &d, sizeof(d));

        if (!blobs[i].data.empty()) {
            std::memcpy(buf.data() + blob_offsets[i], blobs[i].data.data(), blobs[i].data.size());
        }
    }

    if (imports.present && !imports.serialized.empty()) {
        std::memcpy(buf.data() + layout.import_table_offset,
                    imports.serialized.data(), imports.serialized.size());
    }
    if (!strings.serialized.empty()) {
        std::memcpy(buf.data() + layout.string_table_offset,
                    strings.serialized.data(), strings.serialized.size());
    }
    if (!resources.serialized.empty()) {
        std::memcpy(buf.data() + layout.resource_table_offset,
                    resources.serialized.data(), resources.serialized.size());
    }

    std::memcpy(buf.data() + layout.master_key_offset, obfuscated_master_key, 32);
    std::memcpy(buf.data() + layout.master_key_offset + 32u, key_obfuscation_mask, 32);

    std::memcpy(buf.data() + layout.aux_offset, &aux, sizeof(aux));

    if (!tls_stub_code.empty()) {
        std::memcpy(buf.data() + layout.tls_stub_offset,
                    tls_stub_code.data(), tls_stub_code.size());
    }
    if (!stub_code.empty()) {
        std::memcpy(buf.data() + layout.stub_offset,
                    stub_code.data(), stub_code.size());
    }

    (void)rng;
    char packed_name[8] = { '.', 'p', 'a', 'c', 'k', 'e', 'd', 0 };

    uint32_t packed_chars = IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE | IMAGE_SCN_MEM_EXECUTE
                            | IMAGE_SCN_CNT_CODE | IMAGE_SCN_CNT_INITIALIZED_DATA;
    pe_file::add_section(pe, packed_name, packed_chars, buf);

    layout.header_offset = 0u;
    return layout;
}

inline void finalize_headers(pe_file::pe_image_t& pe) {
    pe_file::recalculate_headers(pe);
}

inline void apply_machine_binding_xor(uint8_t master[32], const uint8_t salt[16], uint32_t fp) {
    for (int i = 0; i < 4; ++i) {
        uint64_t k0 = 0;
        uint64_t k1 = 0;
        std::memcpy(&k0, salt + 0, 8);
        std::memcpy(&k1, salt + 8, 8);
        k0 ^= static_cast<uint64_t>(fp);
        k1 ^= static_cast<uint64_t>(i) * 0x9E3779B97F4A7C15ull;
        uint8_t blk[8] = {0};
        blk[0] = static_cast<uint8_t>(i);
        uint64_t h = siphash_2_4(blk, 8, k0, k1);
        for (int j = 0; j < 8; ++j) {
            master[i * 8 + j] ^= static_cast<uint8_t>(h >> (j * 8));
        }
    }
}

inline uint32_t collect_cpuid_fingerprint() {
    int regs[4] = {0, 0, 0, 0};
    __cpuid(regs, 1);
    return static_cast<uint32_t>(regs[0]);
}

namespace noise_sections {

inline const std::vector<uint8_t>& get_pool() {
    static const std::vector<uint8_t> pool = [](){
        std::vector<uint8_t> p;
        p.reserve(2048);
        static const char* kStrs[] = {
            "GetProcAddress", "kernel32.dll", "ntdll.dll", "user32.dll",
            "LoadLibraryA", "LoadLibraryW", "FreeLibrary", "VirtualAlloc",
            "VirtualProtect", "VirtualFree", "ExitProcess", "MessageBoxA",
            "CreateFileA", "ReadFile", "WriteFile", "CloseHandle",
            "HeapAlloc", "HeapFree", "GetLastError", "SetLastError",
            "Sleep", "GetModuleHandleA", "GetCommandLineA", "GetEnvironmentStringsW",
            "RSDS", "Microsoft Visual C++ Runtime Library",
            "D:\\\\build\\\\src\\\\main.c", "D:\\\\build\\\\src\\\\util.c",
            "Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod ",
            "tempor incididunt ut labore et dolore magna aliqua. Ut enim ad minim veniam, ",
            "quis nostrud exercitation ullamco laboris nisi ut aliquip ex ea commodo. ",
            "Duis aute irure dolor in reprehenderit in voluptate velit esse cillum. "
        };
        static const uint8_t kBigrams[64][2] = {
            {'t','h'},{'h','e'},{'i','n'},{'e','r'},{'a','n'},{'r','e'},{'o','n'},{'a','t'},
            {'e','n'},{'n','d'},{'t','i'},{'e','s'},{'o','r'},{'t','e'},{'o','f'},{'e','d'},
            {'i','s'},{'i','t'},{'a','l'},{'a','r'},{'s','t'},{'t','o'},{'n','t'},{'n','g'},
            {'s','e'},{'h','a'},{'a','s'},{'o','u'},{'i','o'},{'l','e'},{'v','e'},{'c','o'},
            {'m','e'},{'d','e'},{'h','i'},{'r','i'},{'r','o'},{'i','c'},{'n','e'},{'e','a'},
            {'r','a'},{'r','o'},{'l','i'},{'l','l'},{'c','h'},{'e','l'},{'n','a'},{'u','r'},
            {'w','a'},{'s','h'},{'n','o'},{'i','l'},{'d','i'},{'f','o'},{'o','m'},{'c','e'},
            {'t','a'},{'e','c'},{'a','m'},{'i','g'},{'n','i'},{'i','r'},{'o','l'},{'l','o'}
        };
        for (const char* s : kStrs) {
            size_t k = 0;
            while (s[k] != 0 && p.size() < 1024) {
                p.push_back(static_cast<uint8_t>(s[k]));
                ++k;
            }
            if (p.size() < 1024) {
                p.push_back(0x20);
            }
        }
        size_t bi = 0;
        while (p.size() < 2048) {
            p.push_back(kBigrams[bi & 63][0]);
            p.push_back(kBigrams[bi & 63][1]);
            if ((bi & 7u) == 7u) { p.push_back(0x20); }
            if ((bi & 31u) == 31u) { p.push_back(0x0A); }
            ++bi;
        }
        p.resize(2048);
        return p;
    }();
    return pool;
}

inline std::vector<uint8_t> generate_structured_noise(size_t target_size,
                                                      uint32_t target_entropy_milli,
                                                      uint64_t seed) {
    std::vector<uint8_t> out;
    if (target_size == 0) {
        return out;
    }
    out.reserve(target_size);
    const auto& pool = get_pool();

    chacha_detail::chacha20_drbg drbg;
    uint8_t seed32[32] = {0};
    for (int i = 0; i < 4; ++i) {
        uint64_t w = seed ^ (0x9E3779B97F4A7C15ULL * static_cast<uint64_t>(i + 1));
        std::memcpy(seed32 + i * 8, &w, 8);
    }
    drbg.init(seed32);

    uint32_t ratio = 160u;
    int tune_remaining = 4;
    const size_t kChunk = 4096;
    size_t pool_pos = 0;

    while (out.size() < target_size) {
        size_t chunk_n = (std::min)(kChunk, target_size - out.size());
        for (size_t i = 0; i < chunk_n; ++i) {
            uint8_t rnd;
            drbg.get(&rnd, 1);
            if (rnd < static_cast<uint8_t>(ratio)) {
                out.push_back(pool[pool_pos % pool.size()]);
                ++pool_pos;
                if ((pool_pos & 0xFu) == 0u) {
                    uint8_t skip;
                    drbg.get(&skip, 1);
                    pool_pos += static_cast<size_t>(skip & 0x0Fu);
                }
            } else {
                uint8_t b;
                drbg.get(&b, 1);
                out.push_back(b);
            }
        }
        if (tune_remaining > 0) {
            uint32_t cur = pe_file::compute_section_entropy_fixed(out.data(), out.size());
            if (cur > target_entropy_milli + 100u) {
                if (ratio < 240u) { ratio += 20u; }
            } else if (cur + 100u < target_entropy_milli) {
                if (ratio > 30u) { ratio -= 20u; }
            } else {
                tune_remaining = 1;
            }
            --tune_remaining;
        }
    }

    return out;
}

}

namespace ast_poison_detail {

inline uint64_t splitmix(uint64_t& s) {
    s += 0x9E3779B97F4A7C15ull;
    uint64_t z = s;
    z = (z ^ (z >> 30)) * 0xBF58476D1CE4E5B9ull;
    z = (z ^ (z >> 27)) * 0x94D049BB133111EBull;
    return z ^ (z >> 31);
}

inline void push_u16(std::vector<uint8_t>& v, uint16_t x) {
    v.push_back(static_cast<uint8_t>(x & 0xFFu));
    v.push_back(static_cast<uint8_t>((x >> 8) & 0xFFu));
}

inline void push_u32(std::vector<uint8_t>& v, uint32_t x) {
    for (int i = 0; i < 4; ++i) { v.push_back(static_cast<uint8_t>((x >> (8 * i)) & 0xFFu)); }
}

inline void push_u64(std::vector<uint8_t>& v, uint64_t x) {
    for (int i = 0; i < 8; ++i) { v.push_back(static_cast<uint8_t>((x >> (8 * i)) & 0xFFu)); }
}

inline void pad_record(std::vector<uint8_t>& v, size_t record_start) {
    while (((v.size() - record_start) & 3u) != 0u) {
        v.push_back(static_cast<uint8_t>(0xF1u + ((v.size() - record_start) & 3u)));
    }
}

inline void build_codeview_blob(std::vector<uint8_t>& out, uint64_t seed) {
    uint64_t st = seed ^ 0xA57C0DE70150AECDull;
    const uint32_t kRsdsMagic = 0x53445352u;
    push_u32(out, kRsdsMagic);
    for (int i = 0; i < 16; ++i) { out.push_back(static_cast<uint8_t>(splitmix(st) & 0xFFu)); }
    push_u32(out, static_cast<uint32_t>(splitmix(st) & 0x7FFFFFFFu));
    const char pdb_name[] = "aida_private_types.pdb";
    for (size_t i = 0; i < sizeof(pdb_name); ++i) { out.push_back(static_cast<uint8_t>(pdb_name[i])); }
    while ((out.size() & 3u) != 0u) { out.push_back(0); }

    push_u32(out, 0x00000004u);

    const uint32_t kRingCount = 8192u;
    uint32_t first_type_index = 0x1000u;

    for (uint32_t n = 0; n < kRingCount; ++n) {
        size_t rec_start = out.size();
        push_u16(out, 0);
        push_u16(out, 0x1203u);
        uint32_t ref_target = first_type_index + ((n + 1u) % kRingCount);
        push_u16(out, static_cast<uint16_t>(0x1503u));
        push_u16(out, static_cast<uint16_t>(0x0200u));
        push_u32(out, ref_target);
        push_u32(out, ref_target ^ 0xDEADBEEFu);
        push_u16(out, static_cast<uint16_t>(splitmix(st) & 0xFFFFu));
        push_u16(out, 0x8000u);
        pad_record(out, rec_start);
        uint16_t len = static_cast<uint16_t>(out.size() - rec_start - 2u);
        out[rec_start]     = static_cast<uint8_t>(len & 0xFFu);
        out[rec_start + 1] = static_cast<uint8_t>((len >> 8) & 0xFFu);
    }

    for (uint32_t n = 0; n < kRingCount; ++n) {
        size_t rec_start = out.size();
        push_u16(out, 0);
        push_u16(out, 0x1504u);
        uint32_t field_ref = first_type_index + ((n + 1u) % kRingCount);
        uint32_t derived_ref = first_type_index + ((n + 2u) % kRingCount);
        uint32_t vshape_ref = first_type_index + ((n + 3u) % kRingCount);
        push_u16(out, static_cast<uint16_t>((n & 0x7FFFu) | 0x8000u));
        push_u16(out, 0x0200u);
        push_u32(out, field_ref);
        push_u32(out, derived_ref);
        push_u32(out, vshape_ref);
        push_u16(out, 0x8004u);
        push_u32(out, static_cast<uint32_t>(splitmix(st) & 0xFFFFFFFFu));
        char name[24];
        for (int i = 0; i < 20; ++i) {
            uint64_t x = splitmix(st);
            name[i] = static_cast<char>(((x & 0x1Fu) + static_cast<uint64_t>('A')));
        }
        name[20] = '\0';
        name[21] = '\0';
        name[22] = '\0';
        name[23] = '\0';
        for (int i = 0; i < 21; ++i) { out.push_back(static_cast<uint8_t>(name[i])); }
        pad_record(out, rec_start);
        uint16_t len = static_cast<uint16_t>(out.size() - rec_start - 2u);
        out[rec_start]     = static_cast<uint8_t>(len & 0xFFu);
        out[rec_start + 1] = static_cast<uint8_t>((len >> 8) & 0xFFu);
    }

    for (uint32_t n = 0; n < 256u; ++n) {
        size_t rec_start = out.size();
        push_u16(out, 0);
        push_u16(out, 0x1001u);
        uint32_t self_ref = first_type_index + (kRingCount * 2u) + n;
        push_u32(out, self_ref);
        push_u16(out, 0x000Fu);
        pad_record(out, rec_start);
        uint16_t len = static_cast<uint16_t>(out.size() - rec_start - 2u);
        out[rec_start]     = static_cast<uint8_t>(len & 0xFFu);
        out[rec_start + 1] = static_cast<uint8_t>((len >> 8) & 0xFFu);
    }
}

inline void build_dwarf_blob(std::vector<uint8_t>& out, uint64_t seed) {
    uint64_t st = seed ^ 0xDEAD0DBBF0015A7Eull;
    push_u32(out, 0xFFFFFFFFu);
    push_u64(out, 0xFFFFFFFFFFFFFFF0ull);
    size_t header_mark = out.size();
    push_u16(out, 0x0004u);
    push_u64(out, 0x0ull);
    out.push_back(0x08u);

    const uint32_t kCircularDies = 1024u;
    for (uint32_t i = 0; i < kCircularDies; ++i) {
        size_t die_off = out.size();
        out.push_back(0x02u);
        push_u32(out, static_cast<uint32_t>(die_off & 0xFFFFFFFFu));
        out.push_back(0x47u);
        push_u32(out, static_cast<uint32_t>(die_off & 0xFFFFFFFFu));
        out.push_back(0x03u);
        char nm[9];
        for (int j = 0; j < 8; ++j) {
            uint64_t x = splitmix(st);
            nm[j] = static_cast<char>(((x & 0x1Fu) + static_cast<uint64_t>('A')));
        }
        nm[8] = '\0';
        for (int j = 0; j < 9; ++j) { out.push_back(static_cast<uint8_t>(nm[j])); }
    }

    out.push_back(0x00u);
    out.push_back(0x00u);
    out.push_back(0x00u);
    out.push_back(0x00u);
    (void)header_mark;
}

}

inline void inject_ast_poison(pe_file::pe_image_t& pe, uint64_t seed) {
    std::vector<uint8_t> blob;
    blob.resize(sizeof(IMAGE_DEBUG_DIRECTORY), 0);
    uint32_t cv_off = static_cast<uint32_t>(blob.size());
    ast_poison_detail::build_codeview_blob(blob, seed);
    uint32_t cv_size = static_cast<uint32_t>(blob.size() - cv_off);
    ast_poison_detail::build_dwarf_blob(blob, seed ^ 0xB1AC0DE11DEA7EFFull);

    while (blob.size() < 0x18000u) {
        uint64_t pad_seed = seed ^ (static_cast<uint64_t>(blob.size()) * 0x9E37u);
        uint64_t z = pad_seed;
        z = (z ^ (z >> 30)) * 0xBF58476D1CE4E5B9ull;
        z = (z ^ (z >> 27)) * 0x94D049BB133111EBull;
        z = z ^ (z >> 31);
        for (int i = 0; i < 8 && blob.size() < 0x18000u; ++i) {
            blob.push_back(static_cast<uint8_t>((z >> (8 * i)) & 0xFFu));
        }
    }

    char sec_name[8] = { '.','g','e','h','i',0,0,0 };
    pe_file::section_t& sec = pe_file::add_section(
        pe, sec_name,
        IMAGE_SCN_MEM_READ | IMAGE_SCN_CNT_INITIALIZED_DATA,
        blob);

    IMAGE_DEBUG_DIRECTORY dd{};
    dd.Characteristics = 0;
    dd.TimeDateStamp = 0;
    dd.MajorVersion = 0;
    dd.MinorVersion = 0;
    dd.Type = IMAGE_DEBUG_TYPE_CODEVIEW;
    dd.SizeOfData = cv_size;
    dd.AddressOfRawData = sec.virtual_address + cv_off;
    dd.PointerToRawData = 0;
    std::memcpy(sec.data.data(), &dd, sizeof(dd));

    pe.data_directories[IMAGE_DIRECTORY_ENTRY_DEBUG].rva = sec.virtual_address;
    pe.data_directories[IMAGE_DIRECTORY_ENTRY_DEBUG].size = static_cast<uint32_t>(sizeof(IMAGE_DEBUG_DIRECTORY));
    pe.optional_header.DataDirectory[IMAGE_DIRECTORY_ENTRY_DEBUG].VirtualAddress = sec.virtual_address;
    pe.optional_header.DataDirectory[IMAGE_DIRECTORY_ENTRY_DEBUG].Size = static_cast<uint32_t>(sizeof(IMAGE_DEBUG_DIRECTORY));
}

inline void fixup_ast_poison_debug_pointer(pe_file::pe_image_t& pe) {
    uint32_t dbg_rva = pe.data_directories[IMAGE_DIRECTORY_ENTRY_DEBUG].rva;
    if (dbg_rva == 0u) { return; }
    pe_file::section_t* sec = pe.section_from_rva(dbg_rva);
    if (sec == nullptr) { return; }
    if (std::memcmp(sec->name, ".gehi", 5) != 0) { return; }
    uint32_t off = dbg_rva - sec->virtual_address;
    if (off + sizeof(IMAGE_DEBUG_DIRECTORY) > sec->data.size()) { return; }
    IMAGE_DEBUG_DIRECTORY dd{};
    std::memcpy(&dd, sec->data.data() + off, sizeof(dd));
    if (sec->raw_offset != 0u && dd.AddressOfRawData >= sec->virtual_address) {
        dd.PointerToRawData = sec->raw_offset + (dd.AddressOfRawData - sec->virtual_address);
        std::memcpy(sec->data.data() + off, &dd, sizeof(dd));
    }
}

namespace symexec_bomb_detail {

inline void emit_mov_rax_imm64(std::vector<uint8_t>& code, uint64_t imm) {
    code.push_back(0x48u);
    code.push_back(0xB8u);
    for (int i = 0; i < 8; ++i) { code.push_back(static_cast<uint8_t>((imm >> (8 * i)) & 0xFFu)); }
}

inline void emit_mov_rbx_imm64(std::vector<uint8_t>& code, uint64_t imm) {
    code.push_back(0x48u);
    code.push_back(0xBBu);
    for (int i = 0; i < 8; ++i) { code.push_back(static_cast<uint8_t>((imm >> (8 * i)) & 0xFFu)); }
}

inline void emit_mov_rcx_imm64(std::vector<uint8_t>& code, uint64_t imm) {
    code.push_back(0x48u);
    code.push_back(0xB9u);
    for (int i = 0; i < 8; ++i) { code.push_back(static_cast<uint8_t>((imm >> (8 * i)) & 0xFFu)); }
}

inline void emit_mov_rdx_imm64(std::vector<uint8_t>& code, uint64_t imm) {
    code.push_back(0x48u);
    code.push_back(0xBAu);
    for (int i = 0; i < 8; ++i) { code.push_back(static_cast<uint8_t>((imm >> (8 * i)) & 0xFFu)); }
}

inline void emit_push_regs(std::vector<uint8_t>& code) {
    code.push_back(0x53u);
    code.push_back(0x51u);
    code.push_back(0x52u);
    code.push_back(0x56u);
    code.push_back(0x57u);
}

inline void emit_pop_regs(std::vector<uint8_t>& code) {
    code.push_back(0x5Fu);
    code.push_back(0x5Eu);
    code.push_back(0x5Au);
    code.push_back(0x59u);
    code.push_back(0x5Bu);
}

inline uint64_t splitmix(uint64_t& s) {
    s += 0x9E3779B97F4A7C15ull;
    uint64_t z = s;
    z = (z ^ (z >> 30)) * 0xBF58476D1CE4E5B9ull;
    z = (z ^ (z >> 27)) * 0x94D049BB133111EBull;
    return z ^ (z >> 31);
}

inline void emit_opaque_always_false_prologue(std::vector<uint8_t>& code, uint64_t& st, size_t& body_patch_offset) {
    uint64_t a = splitmix(st) | 1ull;
    uint64_t b = a;
    emit_mov_rax_imm64(code, a);
    emit_mov_rbx_imm64(code, b);
    code.push_back(0x48u); code.push_back(0x31u); code.push_back(0xD8u);
    code.push_back(0x48u); code.push_back(0x83u); code.push_back(0xE0u); code.push_back(0x01u);
    code.push_back(0x48u); code.push_back(0x0Fu); code.push_back(0xAFu); code.push_back(0xC0u);
    code.push_back(0x48u); code.push_back(0x83u); code.push_back(0xE0u); code.push_back(0x01u);
    code.push_back(0x0Fu); code.push_back(0x85u);
    body_patch_offset = code.size();
    code.push_back(0x00u); code.push_back(0x00u); code.push_back(0x00u); code.push_back(0x00u);
}

inline void emit_sha_round_inline(std::vector<uint8_t>& code, uint32_t k_const, uint64_t& st) {
    code.push_back(0x48u); code.push_back(0x31u); code.push_back(0xC0u);
    code.push_back(0x48u); code.push_back(0xB8u);
    uint64_t imm = static_cast<uint64_t>(k_const) | (splitmix(st) & 0xFFFFFFFF00000000ull);
    for (int i = 0; i < 8; ++i) { code.push_back(static_cast<uint8_t>((imm >> (8 * i)) & 0xFFu)); }
    code.push_back(0x48u); code.push_back(0x31u); code.push_back(0xD8u);
    code.push_back(0x48u); code.push_back(0xC1u); code.push_back(0xC8u);
    code.push_back(static_cast<uint8_t>(0x07u + (k_const & 0x17u)));
    code.push_back(0x48u); code.push_back(0x01u); code.push_back(0xD8u);
    code.push_back(0x48u); code.push_back(0x29u); code.push_back(0xC8u);
    code.push_back(0x48u); code.push_back(0xF7u); code.push_back(0xD0u);
    code.push_back(0x48u); code.push_back(0x21u); code.push_back(0xD8u);
    code.push_back(0x48u); code.push_back(0x09u); code.push_back(0xCBu);
}

inline void emit_sha_body(std::vector<uint8_t>& code, uint64_t& st) {
    static const uint32_t kSha256K[64] = {
        0x428a2f98u,0x71374491u,0xb5c0fbcfu,0xe9b5dba5u,0x3956c25bu,0x59f111f1u,0x923f82a4u,0xab1c5ed5u,
        0xd807aa98u,0x12835b01u,0x243185beu,0x550c7dc3u,0x72be5d74u,0x80deb1feu,0x9bdc06a7u,0xc19bf174u,
        0xe49b69c1u,0xefbe4786u,0x0fc19dc6u,0x240ca1ccu,0x2de92c6fu,0x4a7484aau,0x5cb0a9dcu,0x76f988dau,
        0x983e5152u,0xa831c66du,0xb00327c8u,0xbf597fc7u,0xc6e00bf3u,0xd5a79147u,0x06ca6351u,0x14292967u,
        0x27b70a85u,0x2e1b2138u,0x4d2c6dfcu,0x53380d13u,0x650a7354u,0x766a0abbu,0x81c2c92eu,0x92722c85u,
        0xa2bfe8a1u,0xa81a664bu,0xc24b8b70u,0xc76c51a3u,0xd192e819u,0xd6990624u,0xf40e3585u,0x106aa070u,
        0x19a4c116u,0x1e376c08u,0x2748774cu,0x34b0bcb5u,0x391c0cb3u,0x4ed8aa4au,0x5b9cca4fu,0x682e6ff3u,
        0x748f82eeu,0x78a5636fu,0x84c87814u,0x8cc70208u,0x90befffau,0xa4506cebu,0xbef9a3f7u,0xc67178f2u
    };
    emit_mov_rcx_imm64(code, 1024ull);
    size_t loop_head = code.size();
    for (int i = 0; i < 64; ++i) {
        emit_sha_round_inline(code, kSha256K[i], st);
    }
    code.push_back(0x48u); code.push_back(0xFFu); code.push_back(0xC9u);
    code.push_back(0x75u);
    int64_t rel = static_cast<int64_t>(loop_head) - static_cast<int64_t>(code.size() + 1);
    if (rel < -128 || rel > 127) {
        code.pop_back();
        code.push_back(0x0Fu); code.push_back(0x85u);
        int32_t rel32 = static_cast<int32_t>(static_cast<int64_t>(loop_head) - static_cast<int64_t>(code.size() + 4));
        for (int i = 0; i < 4; ++i) { code.push_back(static_cast<uint8_t>((rel32 >> (8 * i)) & 0xFFu)); }
    } else {
        code.push_back(static_cast<uint8_t>(static_cast<int8_t>(rel)));
    }
}

inline uint32_t shannon_entropy_milli(const uint8_t* data, size_t len) {
    if (len == 0) { return 0; }
    uint64_t hist[256] = {0};
    for (size_t i = 0; i < len; ++i) { ++hist[data[i]]; }
    double ent = 0.0;
    double dl = static_cast<double>(len);
    for (int i = 0; i < 256; ++i) {
        if (hist[i] == 0) { continue; }
        double p = static_cast<double>(hist[i]) / dl;
        ent -= p * (std::log(p) / std::log(2.0));
    }
    double milli = ent * 1000.0;
    if (milli < 0.0) { milli = 0.0; }
    if (milli > 8000.0) { milli = 8000.0; }
    return static_cast<uint32_t>(milli);
}

}

inline uint32_t inject_symexec_bombs(pe_file::pe_image_t& pe, uint64_t seed) {
    std::vector<uint8_t> code;
    uint64_t st = seed ^ 0x5E7EC0BB1E1A7EDAull;
    const uint32_t kBombCount = 16u;

    uint32_t text_target_rva = 0;
    for (const auto& s : pe.sections) {
        if ((s.characteristics & IMAGE_SCN_MEM_EXECUTE) != 0u && s.virtual_size > 0u) {
            text_target_rva = s.virtual_address;
            break;
        }
    }

    std::vector<size_t> block_starts;
    std::vector<size_t> jmp_out_offsets;
    std::vector<size_t> body_patches;

    for (uint32_t b = 0; b < kBombCount; ++b) {
        block_starts.push_back(code.size());
        symexec_bomb_detail::emit_push_regs(code);
        size_t body_patch = 0;
        symexec_bomb_detail::emit_opaque_always_false_prologue(code, st, body_patch);
        size_t after_jcc = code.size();
        size_t jmp_epilogue_offset = code.size();
        code.push_back(0xE9u);
        code.push_back(0x00u); code.push_back(0x00u); code.push_back(0x00u); code.push_back(0x00u);
        size_t body_start = code.size();
        int32_t body_rel = static_cast<int32_t>(static_cast<int64_t>(body_start) - static_cast<int64_t>(after_jcc));
        for (int i = 0; i < 4; ++i) {
            code[body_patch + i] = static_cast<uint8_t>((body_rel >> (8 * i)) & 0xFFu);
        }
        body_patches.push_back(body_patch);
        symexec_bomb_detail::emit_sha_body(code, st);
        symexec_bomb_detail::emit_pop_regs(code);
        size_t epilogue_start = code.size();
        int32_t epi_rel = static_cast<int32_t>(static_cast<int64_t>(epilogue_start) - static_cast<int64_t>(jmp_epilogue_offset + 5));
        for (int i = 0; i < 4; ++i) {
            code[jmp_epilogue_offset + 1 + i] = static_cast<uint8_t>((epi_rel >> (8 * i)) & 0xFFu);
        }
        symexec_bomb_detail::emit_pop_regs(code);
        jmp_out_offsets.push_back(code.size());
        code.push_back(0xE9u);
        code.push_back(0x00u); code.push_back(0x00u); code.push_back(0x00u); code.push_back(0x00u);
    }

    (void)body_patches;

    while (code.size() < 0x2000u) { code.push_back(0x90u); }

    uint32_t current_entropy = symexec_bomb_detail::shannon_entropy_milli(code.data(), code.size());
    if (current_entropy < 6400u || current_entropy > 7300u) {
        size_t pad_start = code.size();
        while (code.size() < pad_start + 0x400u) {
            uint64_t x = symexec_bomb_detail::splitmix(st);
            for (int i = 0; i < 8 && code.size() < pad_start + 0x400u; ++i) {
                code.push_back(static_cast<uint8_t>((x >> (8 * i)) & 0xFFu));
            }
        }
    }

    char sec_name[8] = { '.','e','p','h','e','m','e',0 };
    pe_file::section_t& sec = pe_file::add_section(
        pe, sec_name,
        IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_CNT_CODE,
        code);

    uint32_t bomb_rva_base = sec.virtual_address;
    uint32_t target_rva = (text_target_rva != 0u) ? text_target_rva : bomb_rva_base;

    for (size_t i = 0; i < jmp_out_offsets.size(); ++i) {
        size_t off = jmp_out_offsets[i];
        uint32_t here_rva = bomb_rva_base + static_cast<uint32_t>(off + 5u);
        int32_t rel = static_cast<int32_t>(static_cast<int64_t>(target_rva) - static_cast<int64_t>(here_rva));
        for (int j = 0; j < 4; ++j) {
            sec.data[off + 1 + j] = static_cast<uint8_t>((rel >> (8 * j)) & 0xFFu);
        }
    }

    return kBombCount;
}

namespace deep_steal_detail {

constexpr uint32_t kMinStolenBytes = 5u;
constexpr uint32_t kMaxStolenBytes = 16u;
constexpr uint32_t kThunkSlotSize = 96u;
constexpr uint32_t kScratchSlotSize = 32u;
constexpr uint32_t kMaxTargets = 64u;

#pragma pack(push, 1)
struct stolen_entry_t {
    uint32_t func_rva;
    uint32_t stolen_byte_count;
    uint8_t  stolen_bytes[16];
    uint64_t fnv_check;
};
#pragma pack(pop)

static_assert(sizeof(stolen_entry_t) == 32, "stolen_entry_t must be 32 bytes");

inline bool decode_unwind_prolog_size(const pe_file::pe_image_t& pe,
                                       uint32_t unwind_info_rva,
                                       uint32_t& out_size) {
    out_size = 0u;
    if (unwind_info_rva == 0u) { return false; }
    const uint8_t* p = pe.rva_ptr(unwind_info_rva);
    if (p == nullptr) { return false; }
    const uint8_t version = static_cast<uint8_t>(p[0] & 0x07u);
    const uint8_t flags = static_cast<uint8_t>((p[0] >> 3) & 0x1Fu);
    if (version != 1u) { return false; }
    if ((flags & 0x04u) != 0u) { return false; }
    out_size = static_cast<uint32_t>(p[1]);
    return true;
}

inline bool is_relocatable_prologue(const uint8_t* p, uint32_t count) {
    if (p == nullptr || count < 3u) { return false; }
    for (uint32_t i = 0; i < count; ++i) {
        const uint8_t b = p[i];
        if (b == 0xE8u) { return false; }
        if (b == 0xE9u) { return false; }
        if (b == 0xEBu) { return false; }
        if (b == 0xE0u || b == 0xE1u || b == 0xE2u) { return false; }
        if (b >= 0x70u && b <= 0x7Fu) { return false; }
        if (b == 0x0Fu && i + 1u < count) {
            const uint8_t nb = p[i + 1u];
            if (nb >= 0x80u && nb <= 0x8Fu) { return false; }
        }
        if (b == 0xFFu && i + 1u < count) {
            const uint8_t nb = p[i + 1u];
            const uint8_t mod = static_cast<uint8_t>((nb >> 6u) & 0x3u);
            const uint8_t reg = static_cast<uint8_t>((nb >> 3u) & 0x7u);
            const uint8_t rm  = static_cast<uint8_t>(nb & 0x7u);
            if ((reg == 2u || reg == 3u || reg == 4u || reg == 5u) && mod == 0u && rm == 5u) {
                return false;
            }
        }
        if ((b == 0x48u || b == 0x4Cu || b == 0x49u || b == 0x4Du) && i + 2u < count) {
            const uint8_t opc = p[i + 1u];
            const uint8_t mrm = p[i + 2u];
            const uint8_t mod = static_cast<uint8_t>((mrm >> 6u) & 0x3u);
            const uint8_t rm  = static_cast<uint8_t>(mrm & 0x7u);
            if (mod == 0u && rm == 5u) {
                if (opc == 0x8Bu || opc == 0x89u || opc == 0x8Du || opc == 0x03u || opc == 0x01u) {
                    return false;
                }
            }
        }
    }
    return true;
}

inline uint64_t derive_target_key(const uint8_t master[32], uint32_t func_rva, uint32_t section_index) {
    uint8_t info[32] = {0};
    std::memcpy(info, "deep_steal_target", 17);
    std::memcpy(info + 17, &func_rva, 4);
    std::memcpy(info + 21, &section_index, 4);
    uint8_t prk[32];
    sha256_detail::hkdf_extract(nullptr, 0, master, 32, prk);
    uint8_t okm[8];
    sha256_detail::hkdf_expand(prk, info, 25, okm, 8);
    uint64_t key = 0;
    std::memcpy(&key, okm, 8);
    if (key == 0ull) { key = 0xDEEFADDEEFADDEEFull; }
    return key;
}

inline void derive_section_iv(const uint8_t master[32], uint32_t section_index, uint8_t iv[16]) {
    uint8_t info[32] = {0};
    std::memcpy(info, "deep_steal_iv", 13);
    std::memcpy(info + 13, &section_index, 4);
    uint8_t prk[32];
    sha256_detail::hkdf_extract(nullptr, 0, master, 32, prk);
    sha256_detail::hkdf_expand(prk, info, 17, iv, 16);
}

inline void emit_u8(std::vector<uint8_t>& out, uint8_t b) { out.push_back(b); }

inline void emit_u32(std::vector<uint8_t>& out, uint32_t v) {
    for (int i = 0; i < 4; ++i) {
        out.push_back(static_cast<uint8_t>((v >> (8 * i)) & 0xFFu));
    }
}

inline void emit_u64(std::vector<uint8_t>& out, uint64_t v) {
    for (int i = 0; i < 8; ++i) {
        out.push_back(static_cast<uint8_t>((v >> (8 * i)) & 0xFFu));
    }
}

inline void write_u32_at(std::vector<uint8_t>& out, size_t at, uint32_t v) {
    for (int i = 0; i < 4; ++i) {
        out[at + i] = static_cast<uint8_t>((v >> (8 * i)) & 0xFFu);
    }
}

inline void build_thunk_code(std::vector<uint8_t>& out,
                              uint32_t thunk_rva,
                              uint32_t dseal_entry_rva,
                              uint32_t scratch_rva,
                              uint32_t stolen_count,
                              uint64_t target_key) {
    const size_t start = out.size();

    emit_u8(out, 0x50u);
    emit_u8(out, 0x51u);
    emit_u8(out, 0x57u);
    emit_u8(out, 0x56u);
    emit_u8(out, 0x53u);

    emit_u8(out, 0x48u); emit_u8(out, 0x8Du); emit_u8(out, 0x35u);
    const size_t lea_rsi_disp_pos = out.size();
    emit_u32(out, 0u);

    emit_u8(out, 0x48u); emit_u8(out, 0x8Du); emit_u8(out, 0x3Du);
    const size_t lea_rdi_disp_pos = out.size();
    emit_u32(out, 0u);

    emit_u8(out, 0x48u); emit_u8(out, 0xC7u); emit_u8(out, 0xC1u);
    emit_u32(out, stolen_count);

    emit_u8(out, 0x48u); emit_u8(out, 0xBBu);
    emit_u64(out, target_key);

    const size_t loop_start = out.size();
    emit_u8(out, 0x8Au); emit_u8(out, 0x06u);
    emit_u8(out, 0x30u); emit_u8(out, 0xD8u);
    emit_u8(out, 0x48u); emit_u8(out, 0xC1u); emit_u8(out, 0xCBu); emit_u8(out, 0x08u);
    emit_u8(out, 0x88u); emit_u8(out, 0x07u);
    emit_u8(out, 0x48u); emit_u8(out, 0xFFu); emit_u8(out, 0xC6u);
    emit_u8(out, 0x48u); emit_u8(out, 0xFFu); emit_u8(out, 0xC7u);
    emit_u8(out, 0x48u); emit_u8(out, 0xFFu); emit_u8(out, 0xC9u);
    emit_u8(out, 0x75u);
    const size_t loop_back_pos = out.size();
    emit_u8(out, 0u);
    const int64_t loop_end = static_cast<int64_t>(out.size());
    const int64_t loop_back_rel = static_cast<int64_t>(loop_start) - loop_end;
    out[loop_back_pos] = static_cast<uint8_t>(static_cast<int8_t>(loop_back_rel));

    emit_u8(out, 0x5Bu);
    emit_u8(out, 0x5Eu);
    emit_u8(out, 0x5Fu);
    emit_u8(out, 0x59u);
    emit_u8(out, 0x58u);

    emit_u8(out, 0xE9u);
    const size_t jmp_disp_pos = out.size();
    emit_u32(out, 0u);

    const uint32_t lea_rsi_next_rva = thunk_rva + static_cast<uint32_t>(lea_rsi_disp_pos - start) + 4u;
    write_u32_at(out, lea_rsi_disp_pos,
                 static_cast<uint32_t>(static_cast<int32_t>(static_cast<int64_t>(dseal_entry_rva) - static_cast<int64_t>(lea_rsi_next_rva))));

    const uint32_t lea_rdi_next_rva = thunk_rva + static_cast<uint32_t>(lea_rdi_disp_pos - start) + 4u;
    write_u32_at(out, lea_rdi_disp_pos,
                 static_cast<uint32_t>(static_cast<int32_t>(static_cast<int64_t>(scratch_rva) - static_cast<int64_t>(lea_rdi_next_rva))));

    const uint32_t jmp_next_rva = thunk_rva + static_cast<uint32_t>(jmp_disp_pos - start) + 4u;
    write_u32_at(out, jmp_disp_pos,
                 static_cast<uint32_t>(static_cast<int32_t>(static_cast<int64_t>(scratch_rva) - static_cast<int64_t>(jmp_next_rva))));
}

}

inline bool apply_deep_steal(pe_file::pe_image_t& pe,
                              aux_block_t& aux,
                              const uint8_t master[32],
                              uint32_t exception_rva_fallback,
                              uint32_t exception_size_fallback) {
    using namespace deep_steal_detail;

    aux.stolen_block_count = 0u;
    aux.stolen_block_table_rva = 0u;
    aux.stolen_block_table_size = 0u;

    pe_file::section_t* text_sec = nullptr;
    for (auto& s : pe.sections) {
        if ((s.characteristics & IMAGE_SCN_MEM_EXECUTE) != 0u && s.virtual_size > 0u && !s.data.empty()) {
            text_sec = &s;
            break;
        }
    }
    if (text_sec == nullptr) { return false; }

    std::vector<pe_file::exception_entry_t> entries;
    if (!pe.exceptions.empty()) {
        entries = pe.exceptions;
    } else if (exception_rva_fallback != 0u && exception_size_fallback >= 12u) {
        const uint32_t count = exception_size_fallback / 12u;
        for (uint32_t i = 0; i < count; ++i) {
            const uint8_t* ptr = pe.rva_ptr(exception_rva_fallback + i * 12u);
            if (ptr == nullptr) { break; }
            pe_file::exception_entry_t e{};
            std::memcpy(&e.begin_address, ptr, 4);
            std::memcpy(&e.end_address, ptr + 4, 4);
            std::memcpy(&e.unwind_info, ptr + 8, 4);
            entries.push_back(e);
        }
    }
    if (entries.empty()) { return false; }

    const uint32_t text_start = text_sec->virtual_address;
    const uint32_t text_end = text_sec->virtual_address + text_sec->virtual_size;

    struct chosen_t {
        uint32_t func_rva;
        uint32_t stolen_count;
        uint8_t  bytes[16];
    };
    std::vector<chosen_t> chosen;
    chosen.reserve(kMaxTargets);

    for (const auto& e : entries) {
        if (chosen.size() >= kMaxTargets) { break; }
        if (e.begin_address < text_start || e.begin_address >= text_end) { continue; }
        uint32_t prolog_size = 0u;
        if (!decode_unwind_prolog_size(pe, e.unwind_info, prolog_size)) { continue; }
        if (prolog_size < kMinStolenBytes || prolog_size > kMaxStolenBytes) { continue; }
        const uint32_t span = (e.end_address > e.begin_address) ? (e.end_address - e.begin_address) : 0u;
        if (span < prolog_size + kMinStolenBytes) { continue; }
        const uint8_t* ip = pe.rva_ptr(e.begin_address);
        if (ip == nullptr) { continue; }
        if (!is_relocatable_prologue(ip, prolog_size)) { continue; }
        bool dup = false;
        for (const auto& c : chosen) {
            if (c.func_rva == e.begin_address) { dup = true; break; }
        }
        if (dup) { continue; }
        chosen_t c{};
        c.func_rva = e.begin_address;
        c.stolen_count = prolog_size;
        std::memcpy(c.bytes, ip, prolog_size);
        for (uint32_t fill = prolog_size; fill < 16u; ++fill) { c.bytes[fill] = 0xCCu; }
        chosen.push_back(c);
    }

    if (chosen.empty()) { return false; }

    const uint32_t target_count = static_cast<uint32_t>(chosen.size());
    const uint32_t text_va = text_sec->virtual_address;

    std::vector<uint8_t> dseal_data;
    uint8_t iv[16];
    derive_section_iv(master, 0u, iv);
    dseal_data.insert(dseal_data.end(), iv, iv + 16);
    const uint32_t dseal_entries_offset = static_cast<uint32_t>(dseal_data.size());
    dseal_data.resize(dseal_entries_offset + target_count * sizeof(stolen_entry_t), 0u);

    char dseal_name[8] = { '.','d','s','e','a','l',0,0 };
    const uint32_t dseal_rva = pe_file::add_section(
        pe, dseal_name,
        IMAGE_SCN_MEM_READ | IMAGE_SCN_CNT_INITIALIZED_DATA,
        dseal_data).virtual_address;

    std::vector<uint64_t> target_keys(target_count, 0ull);
    {
        pe_file::section_t* dseal_sec_local = nullptr;
        for (auto& s : pe.sections) {
            if (s.virtual_address == dseal_rva) { dseal_sec_local = &s; break; }
        }
        if (dseal_sec_local == nullptr) { return false; }
        for (uint32_t i = 0; i < target_count; ++i) {
            target_keys[i] = deep_steal_detail::derive_target_key(master, chosen[i].func_rva, 0u);
            stolen_entry_t entry{};
            entry.func_rva = chosen[i].func_rva;
            entry.stolen_byte_count = chosen[i].stolen_count;
            uint64_t k = target_keys[i];
            for (uint32_t b = 0; b < 16u; ++b) {
                const uint8_t plain = chosen[i].bytes[b];
                const uint8_t key_byte = static_cast<uint8_t>(k & 0xFFu);
                entry.stolen_bytes[b] = static_cast<uint8_t>(plain ^ key_byte);
                k = (k >> 8) | (k << 56);
            }
            uint8_t fnv_input[8 + 16];
            std::memcpy(fnv_input, &entry.func_rva, 4);
            std::memcpy(fnv_input + 4, &entry.stolen_byte_count, 4);
            std::memcpy(fnv_input + 8, chosen[i].bytes, 16);
            entry.fnv_check = fnv1a64(fnv_input, sizeof(fnv_input));
            const size_t off = dseal_entries_offset + i * sizeof(stolen_entry_t);
            std::memcpy(dseal_sec_local->data.data() + off, &entry, sizeof(stolen_entry_t));
        }
    }

    const uint32_t thunk_block_size = kThunkSlotSize;
    const uint32_t scratch_block_size = kScratchSlotSize;
    const uint32_t thunk_section_size = target_count * (thunk_block_size + scratch_block_size);

    std::vector<uint8_t> dthunk_data(thunk_section_size, 0xCCu);
    char dthunk_name[8] = { '.','d','t','h','u','n','k',0 };
    const uint32_t dthunk_rva = pe_file::add_section(
        pe, dthunk_name,
        IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE | IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_CNT_CODE,
        dthunk_data).virtual_address;

    pe_file::section_t* dthunk_sec_local = nullptr;
    pe_file::section_t* text_sec_local = nullptr;
    uint32_t dseal_size_after_alloc = 0u;
    for (auto& s : pe.sections) {
        if (s.virtual_address == dthunk_rva) { dthunk_sec_local = &s; }
        if (s.virtual_address == text_va) { text_sec_local = &s; }
        if (s.virtual_address == dseal_rva) { dseal_size_after_alloc = static_cast<uint32_t>(s.data.size()); }
    }
    if (dthunk_sec_local == nullptr || text_sec_local == nullptr) { return false; }

    for (uint32_t i = 0; i < target_count; ++i) {
        const uint32_t thunk_rva = dthunk_rva + i * thunk_block_size;
        const uint32_t scratch_rva = dthunk_rva + target_count * thunk_block_size + i * scratch_block_size;
        const uint32_t entry_data_rva = dseal_rva + dseal_entries_offset + i * sizeof(stolen_entry_t) + 8u;

        std::vector<uint8_t> thunk_code;
        deep_steal_detail::build_thunk_code(thunk_code, thunk_rva, entry_data_rva, scratch_rva,
                                            chosen[i].stolen_count, target_keys[i]);
        if (thunk_code.size() > thunk_block_size) { return false; }
        const uint32_t thunk_off = i * thunk_block_size;
        for (size_t k = 0; k < thunk_code.size(); ++k) {
            dthunk_sec_local->data[thunk_off + k] = thunk_code[k];
        }
        for (size_t k = thunk_code.size(); k < thunk_block_size; ++k) {
            dthunk_sec_local->data[thunk_off + k] = 0xCCu;
        }

        const uint32_t scratch_off = target_count * thunk_block_size + i * scratch_block_size;
        for (uint32_t k = 0; k < chosen[i].stolen_count; ++k) {
            dthunk_sec_local->data[scratch_off + k] = 0xCCu;
        }
        const uint32_t tail_off = scratch_off + chosen[i].stolen_count;
        dthunk_sec_local->data[tail_off + 0] = 0xE9u;
        const uint32_t tail_next_rva = scratch_rva + chosen[i].stolen_count + 5u;
        const uint32_t tail_target_rva = chosen[i].func_rva + chosen[i].stolen_count;
        const int32_t tail_rel32 = static_cast<int32_t>(static_cast<int64_t>(tail_target_rva) - static_cast<int64_t>(tail_next_rva));
        const uint32_t tail_rel32_u = static_cast<uint32_t>(tail_rel32);
        dthunk_sec_local->data[tail_off + 1] = static_cast<uint8_t>(tail_rel32_u & 0xFFu);
        dthunk_sec_local->data[tail_off + 2] = static_cast<uint8_t>((tail_rel32_u >> 8) & 0xFFu);
        dthunk_sec_local->data[tail_off + 3] = static_cast<uint8_t>((tail_rel32_u >> 16) & 0xFFu);
        dthunk_sec_local->data[tail_off + 4] = static_cast<uint8_t>((tail_rel32_u >> 24) & 0xFFu);

        const uint32_t patch_off = chosen[i].func_rva - text_sec_local->virtual_address;
        if (patch_off + chosen[i].stolen_count > text_sec_local->data.size()) { return false; }
        text_sec_local->data[patch_off + 0] = 0xE9u;
        const uint32_t patch_next_rva = chosen[i].func_rva + 5u;
        const int32_t patch_rel32 = static_cast<int32_t>(static_cast<int64_t>(thunk_rva) - static_cast<int64_t>(patch_next_rva));
        const uint32_t patch_rel32_u = static_cast<uint32_t>(patch_rel32);
        text_sec_local->data[patch_off + 1] = static_cast<uint8_t>(patch_rel32_u & 0xFFu);
        text_sec_local->data[patch_off + 2] = static_cast<uint8_t>((patch_rel32_u >> 8) & 0xFFu);
        text_sec_local->data[patch_off + 3] = static_cast<uint8_t>((patch_rel32_u >> 16) & 0xFFu);
        text_sec_local->data[patch_off + 4] = static_cast<uint8_t>((patch_rel32_u >> 24) & 0xFFu);
        for (uint32_t k = 5u; k < chosen[i].stolen_count; ++k) {
            text_sec_local->data[patch_off + k] = 0xCCu;
        }
    }

    aux.stolen_block_count = target_count;
    aux.stolen_block_table_rva = dseal_rva;
    aux.stolen_block_table_size = dseal_size_after_alloc;
    return true;
}

inline transform_result_t protect_pe(pe_file::pe_image_t& pe, const protect_options_t& opt) {
    transform_result_t result{};

    if (pe.sections.empty()) {
        result.success = false;
        result.error = "pe has no sections";
        return result;
    }
    if (pe.optional_header.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC) {
        result.success = false;
        result.error = "pe is not PE32+";
        return result;
    }

    result.original_entry_point = pe.optional_header.AddressOfEntryPoint;
    result.master_key_pe_timestamp = pe.file_header.TimeDateStamp;
    result.master_key_pe_size_of_code = pe.optional_header.SizeOfCode;

    const uint32_t original_exception_rva = pe.data_directories[IMAGE_DIRECTORY_ENTRY_EXCEPTION].rva;
    const uint32_t original_exception_size = pe.data_directories[IMAGE_DIRECTORY_ENTRY_EXCEPTION].size;

    const uint32_t original_load_config_rva = pe.data_directories[IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG].rva;
    const uint32_t original_load_config_size = pe.data_directories[IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG].size;
    const uint64_t image_base_for_lc = pe.optional_header.ImageBase;

    struct cfg_pointer_range_t {
        uint32_t rva;
        uint32_t size;
    };
    std::vector<cfg_pointer_range_t> cfg_pointer_ranges;
    if (original_load_config_rva != 0u && original_load_config_size >= 0x80u) {
        const uint8_t* lc_ptr = pe.rva_ptr(original_load_config_rva);
        if (lc_ptr != nullptr) {
            auto add_pointer_target = [&](uint32_t struct_offset) {
                if (struct_offset + 8u > original_load_config_size) return;
                uint64_t va = 0;
                std::memcpy(&va, lc_ptr + struct_offset, 8);
                if (va < image_base_for_lc) return;
                const uint64_t r64 = va - image_base_for_lc;
                if (r64 >= 0x80000000ULL) return;
                cfg_pointer_ranges.push_back({static_cast<uint32_t>(r64), 8u});
            };
            add_pointer_target(0x58u);
            add_pointer_target(0x70u);
            add_pointer_target(0x78u);
            add_pointer_target(0xD0u);
            add_pointer_target(0xD8u);
            add_pointer_target(0xE8u);
            add_pointer_target(0xF0u);
            add_pointer_target(0xF8u);
            add_pointer_target(0x100u);
            add_pointer_target(0x108u);
            add_pointer_target(0x118u);
            add_pointer_target(0x120u);
            add_pointer_target(0x128u);
            add_pointer_target(0x138u);
        }
    }

    rng_detail::rng_source rng;
    rng_detail::init_from_u64_seed(rng, opt.seed, opt.seed_provided);

    uint64_t rng_seed = opt.seed;
    if (!opt.seed_provided) {
        uint8_t rb[8];
        (void)BCryptGenRandom(nullptr, rb, 8u, BCRYPT_USE_SYSTEM_PREFERRED_RNG);
        std::memcpy(&rng_seed, rb, 8);
    }
    rng_state_t hdr_rng = make_rng(rng_seed ^ 0xA5A5A5A5A5A5A5A5ull);

    uint8_t outer[32];
    rng.get(outer, 32);
    uint8_t inner[32];
    aes_detail::compute_inner_master(outer, inner);
    uint8_t master[32];
    for (int i = 0; i < 32; ++i) {
        master[i] = static_cast<uint8_t>(outer[i] ^ inner[i]);
    }

    uint32_t bind_flags = 0;
    uint8_t  bind_salt[16] = {0};
    uint8_t  fingerprint_hash[32] = {0};
    uint32_t cpuid_fp = 0;
    if (opt.bind_machine) {
        rng.get(bind_salt, 16);
        cpuid_fp = collect_cpuid_fingerprint();
        uint8_t fp_bytes[20];
        std::memcpy(fp_bytes, &cpuid_fp, 4);
        std::memcpy(fp_bytes + 4, bind_salt, 16);
        sha256_detail::sha256(fp_bytes, sizeof(fp_bytes), fingerprint_hash);
        bind_flags |= kBindFlagCpuid;
    }
    std::memcpy(result.bind_salt, bind_salt, 16);
    result.bind_flags = bind_flags;
    std::memcpy(result.fingerprint_hash, fingerprint_hash, 32);

    uint8_t master_for_obfuscation[32];
    std::memcpy(master_for_obfuscation, master, 32);
    if (opt.bind_machine) {
        apply_machine_binding_xor(master_for_obfuscation, bind_salt, cpuid_fp);
    }

    rng.get(result.key_obfuscation_mask, 32);
    obfuscate_master_key_with_mask(master_for_obfuscation,
                                    result.key_obfuscation_mask,
                                    result.master_key_pe_timestamp,
                                    result.master_key_pe_size_of_code,
                                    result.obfuscated_master_key);

    aux_block_t aux{};
    aux.magic = kAuxMagic;
    aux.version = kAuxVersion;
    aux.bind_flags = bind_flags;
    aux.tamper_response_level = opt.tamper_response_level;
    {
        uint8_t seed_src[8];
        rng.get(seed_src, 8);
        uint32_t spread_seed = 0;
        std::memcpy(&spread_seed, seed_src, 4);
        if (spread_seed == 0u) { spread_seed = 0xA5A5A5A5u; }
        aux.spread_seed = spread_seed;
        result.watermark_spread_seed = spread_seed;
    }
    std::memcpy(aux.watermark, opt.license_hash, 16);
    sha256_detail::sha256(aux.watermark, 16, aux.watermark_hash);
    std::memcpy(result.watermark_hash, aux.watermark_hash, 32);
    std::memcpy(aux.fingerprint_hash, fingerprint_hash, 32);
    std::memcpy(aux.bind_salt, bind_salt, 16);
    {
        uint32_t pf = 0u;
        if (opt.polymorphic_stub)   { pf |= 0x1u; }
        if (opt.merge_sections)     { pf |= 0x2u; }
        if (opt.flatten_entropy)    { pf |= 0x4u; }
        if (opt.deep_steal)         { pf |= 0x8u; }
        if (opt.ghost_veh)          { pf |= 0x10u; }
        if (opt.rdtsc_entangle)     { pf |= 0x20u; }
        if (opt.opaque_predicates)  { pf |= 0x40u; }
        if (opt.ast_poison)         { pf |= 0x80u; }
        if (opt.symexec_bombs)      { pf |= 0x100u; }
        if (opt.llm_poison)         { pf |= 0x200u; }
        if (opt.jit)                { pf |= 0x400u; }
        aux.phase_flags = pf;
    }
    std::memcpy(aux.spki_pins[0], opt.spki_pin_primary,   32);
    std::memcpy(aux.spki_pins[1], opt.spki_pin_secondary, 32);
    std::memset(aux.primary_host,   0, sizeof(aux.primary_host));
    std::memset(aux.secondary_host, 0, sizeof(aux.secondary_host));
    {
        const size_t primary_cap = sizeof(aux.primary_host);
        size_t primary_n = 0;
        while (primary_n < primary_cap && opt.primary_host[primary_n] != '\0') { ++primary_n; }
        if (primary_n > 0u) {
            std::memcpy(aux.primary_host, opt.primary_host, primary_n);
        }
        const size_t secondary_cap = sizeof(aux.secondary_host);
        size_t secondary_n = 0;
        while (secondary_n < secondary_cap && opt.secondary_host[secondary_n] != '\0') { ++secondary_n; }
        if (secondary_n > 0u) {
            std::memcpy(aux.secondary_host, opt.secondary_host, secondary_n);
        }
    }
    aux.pin_reserved[0] = 0u;
    aux.pin_reserved[1] = 0u;
    aux.pin_reserved[2] = 0u;
    aux.pin_reserved[3] = 0u;
    result.aux_size = static_cast<uint32_t>(sizeof(aux_block_t));

    import_hash_table_t imports{};
    string_fixup_table_t strings{};
    resource_fixup_table_t resources{};

    if (opt.encrypt_imports) {
        imports = destroy_imports(pe, master);
    }
    if (opt.encrypt_strings) {
        std::vector<preserve_string_range_t> preserve_string_ranges =
            collect_loader_string_ranges(pe, !opt.encrypt_imports);
        strings = encrypt_strings(pe, master, preserve_string_ranges);
    }
    if (opt.encrypt_resources) {
        resources = encrypt_resources(pe, master);
    }
    if (opt.mangle_headers) {
        mangle_header(pe, hdr_rng);
    } else {
        if (opt.strip_rich) {
            strip_rich_header(pe);
        }
        if (opt.strip_debug) {
            strip_debug_directory(pe);
        }
    }
    if (opt.randomize_section_names) {
        randomize_section_names(pe, hdr_rng);
    }

    if (opt.ast_poison) {
        inject_ast_poison(pe, rng_seed ^ 0xA57C0DE70150AECDull);
    }
    if (opt.symexec_bombs) {
        (void)inject_symexec_bombs(pe, rng_seed ^ 0x5E7EC0BB1E1A7EDAull);
    }
    if (opt.llm_poison) {
        (void)llm_poison::inject_llm_poison(pe, rng_seed ^ 0x11AB1E1A7EC0FFEEull);
    }
    if (opt.deep_steal) {
        (void)apply_deep_steal(pe, aux, master, original_exception_rva, original_exception_size);
    }

    std::vector<uint32_t> keep_intact_section_rvas;
    if (!opt.encrypt_imports) {
        const uint32_t imp_dir_rva = pe.data_directories[IMAGE_DIRECTORY_ENTRY_IMPORT].rva;
        if (imp_dir_rva != 0u) {
            const pe_file::section_t* s_imp = pe.section_from_rva(imp_dir_rva);
            if (s_imp != nullptr) {
                bool already = false;
                for (uint32_t v : keep_intact_section_rvas) {
                    if (v == s_imp->virtual_address) { already = true; break; }
                }
                if (!already) {
                    keep_intact_section_rvas.push_back(s_imp->virtual_address);
                }
            }
        }
        const uint32_t iat_dir_rva = pe.data_directories[IMAGE_DIRECTORY_ENTRY_IAT].rva;
        if (iat_dir_rva != 0u) {
            const pe_file::section_t* s_iat = pe.section_from_rva(iat_dir_rva);
            if (s_iat != nullptr) {
                bool already = false;
                for (uint32_t v : keep_intact_section_rvas) {
                    if (v == s_iat->virtual_address) { already = true; break; }
                }
                if (!already) {
                    keep_intact_section_rvas.push_back(s_iat->virtual_address);
                }
            }
        }
        const uint32_t delay_dir_rva = pe.data_directories[IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT].rva;
        if (delay_dir_rva != 0u) {
            const pe_file::section_t* s_dly = pe.section_from_rva(delay_dir_rva);
            if (s_dly != nullptr) {
                bool already = false;
                for (uint32_t v : keep_intact_section_rvas) {
                    if (v == s_dly->virtual_address) { already = true; break; }
                }
                if (!already) {
                    keep_intact_section_rvas.push_back(s_dly->virtual_address);
                }
            }
        }
    }

    std::vector<packed_section_blob_t> blobs;
    if (opt.pack_sections) {
        blobs = pack_sections(pe, master, original_exception_rva, original_exception_size, keep_intact_section_rvas, opt.matryoshka_layers);
    }

    std::vector<uint8_t> stub_code;
    std::vector<uint8_t> tls_stub_code;
    stub_code.resize(kReservedMainStubSize, 0);
    tls_stub_code.resize(kReservedTlsStubSize, 0);
    result.reserved_main_stub_size = kReservedMainStubSize;
    result.reserved_tls_stub_size = kReservedTlsStubSize;
    result.seed_used = rng_seed;

    result.layout = build_packed_section(pe,
                                          result.obfuscated_master_key,
                                          result.key_obfuscation_mask,
                                          result.master_key_pe_timestamp,
                                          result.master_key_pe_size_of_code,
                                          blobs,
                                          imports,
                                          strings,
                                          resources,
                                          stub_code,
                                          tls_stub_code,
                                          bind_flags,
                                          bind_salt,
                                          aux,
                                          rng);
    result.packed_section_rva = pe.sections.back().virtual_address;

    struct tls_preserve_range_t {
        uint32_t rva;
        uint32_t size;
    };
    std::vector<tls_preserve_range_t> tls_preserve_ranges;
    if (original_exception_rva != 0u && original_exception_size != 0u) {
        tls_preserve_ranges.push_back({original_exception_rva, original_exception_size});
    }
    if (original_load_config_rva != 0u && original_load_config_size != 0u) {
        tls_preserve_ranges.push_back({original_load_config_rva, original_load_config_size});
    }
    for (const auto& cpr : cfg_pointer_ranges) {
        tls_preserve_ranges.push_back({cpr.rva, cpr.size});
    }
    if (pe.has_tls) {
        const uint64_t image_base = pe.optional_header.ImageBase;
        const uint32_t dir_rva = pe.data_directories[IMAGE_DIRECTORY_ENTRY_TLS].rva;
        const uint32_t dir_size = pe.data_directories[IMAGE_DIRECTORY_ENTRY_TLS].size;
        if (dir_rva != 0u && dir_size != 0u) {
            tls_preserve_ranges.push_back({dir_rva, dir_size});
        }
        if (pe.tls.address_of_index >= image_base) {
            const uint64_t r = pe.tls.address_of_index - image_base;
            if (r < 0x80000000ULL) {
                tls_preserve_ranges.push_back({static_cast<uint32_t>(r), 8u});
            }
        }
        if (pe.tls.address_of_callbacks >= image_base) {
            const uint64_t r = pe.tls.address_of_callbacks - image_base;
            if (r < 0x80000000ULL) {
                const size_t entries = pe.tls.callback_rvas.size() + 1u;
                tls_preserve_ranges.push_back({
                    static_cast<uint32_t>(r),
                    static_cast<uint32_t>(entries * 8u)
                });
            }
        }
        if (pe.tls.raw_data_start >= image_base
            && pe.tls.raw_data_end > pe.tls.raw_data_start) {
            const uint64_t s = pe.tls.raw_data_start - image_base;
            const uint64_t e = pe.tls.raw_data_end - image_base;
            if (e > s && e < 0x80000000ULL) {
                tls_preserve_ranges.push_back({
                    static_cast<uint32_t>(s),
                    static_cast<uint32_t>(e - s)
                });
            }
        }
    }

    if (opt.pack_sections) {
        for (auto& sec : pe.sections) {
            if (section_skip_list::is_skipped(sec.name)) {
                continue;
            }
            if (sec.data.empty()) {
                continue;
            }
            if (sec.virtual_address == result.packed_section_rva) {
                continue;
            }
            bool keep_intact_hit = false;
            for (uint32_t kva : keep_intact_section_rvas) {
                if (kva != 0u && sec.virtual_address == kva) {
                    keep_intact_hit = true;
                    break;
                }
            }
            if (keep_intact_hit) {
                continue;
            }

            const uint32_t s_start = sec.virtual_address;
            const uint32_t s_end = sec.virtual_address + sec.virtual_size;
            bool has_preserve = false;
            for (const auto& pr : tls_preserve_ranges) {
                const uint32_t p_end = pr.rva + pr.size;
                if (pr.rva < s_end && p_end > s_start) {
                    has_preserve = true;
                    break;
                }
            }

            if (!has_preserve) {
                std::memset(sec.data.data(), 0, sec.data.size());
                sec.data.clear();
                sec.raw_size = 0;
                sec.raw_offset = 0;
            } else {
                std::vector<uint8_t> keep(sec.data.size(), 0u);
                for (const auto& pr : tls_preserve_ranges) {
                    const uint32_t p_end = pr.rva + pr.size;
                    if (pr.rva >= s_end || p_end <= s_start) {
                        continue;
                    }
                    const uint32_t ov_start = (pr.rva > s_start) ? pr.rva : s_start;
                    const uint32_t ov_end = (p_end < s_end) ? p_end : s_end;
                    const size_t off_start = static_cast<size_t>(ov_start - s_start);
                    const size_t off_end_raw = static_cast<size_t>(ov_end - s_start);
                    const size_t off_end = (off_end_raw > sec.data.size())
                        ? sec.data.size() : off_end_raw;
                    for (size_t i = off_start; i < off_end; ++i) {
                        keep[i] = 1u;
                    }
                }
                for (size_t i = 0; i < sec.data.size(); ++i) {
                    if (keep[i] == 0u) {
                        sec.data[i] = 0u;
                    }
                }
            }
        }
        pe.optional_header.DllCharacteristics &= static_cast<uint16_t>(~0x4160u);
        if (opt.encrypt_imports) {
            pe.data_directories[1].rva = 0;
            pe.data_directories[1].size = 0;
            pe.optional_header.DataDirectory[1].VirtualAddress = 0;
            pe.optional_header.DataDirectory[1].Size = 0;
            pe.data_directories[12].rva = 0;
            pe.data_directories[12].size = 0;
            pe.optional_header.DataDirectory[12].VirtualAddress = 0;
            pe.optional_header.DataDirectory[12].Size = 0;
        }
        pe.data_directories[10].rva = 0;
        pe.data_directories[10].size = 0;
        pe.optional_header.DataDirectory[10].VirtualAddress = 0;
        pe.optional_header.DataDirectory[10].Size = 0;
        pe.data_directories[6].rva = 0;
        pe.data_directories[6].size = 0;
        pe.optional_header.DataDirectory[6].VirtualAddress = 0;
        pe.optional_header.DataDirectory[6].Size = 0;
        pe.data_directories[5].rva = 0;
        pe.data_directories[5].size = 0;
        pe.optional_header.DataDirectory[5].VirtualAddress = 0;
        pe.optional_header.DataDirectory[5].Size = 0;
        pe.file_header.Characteristics |= 0x0001u;
    }

    result.imports = std::move(imports);
    result.strings = std::move(strings);
    result.resources = std::move(resources);

    finalize_headers(pe);

    if (opt.ast_poison) {
        fixup_ast_poison_debug_pointer(pe);
    }

    if (opt.embed_watermark) {
        uint8_t wm_id[8];
        std::memcpy(wm_id, result.watermark_hash, 8);
        uint32_t lo = 0, hi = 0;
        std::memcpy(&lo, wm_id + 0, 4);
        std::memcpy(&hi, wm_id + 4, 4);
        pe.optional_header.Win32VersionValue = lo;
        pe.optional_header.LoaderFlags = hi;
    }

    if (opt.verbose) {
        (void)opt.verbose;
    }

    result.success = true;
    return result;
}

inline bool apply_flatten_entropy_band(pe_file::pe_image_t& pe,
                                        uint32_t packed_section_rva,
                                        uint64_t seed,
                                        bool verbose,
                                        uint32_t target_max,
                                        uint32_t target_min,
                                        uint32_t noise_entropy) {
    pe_file::section_t* psec = pe.section_from_rva(packed_section_rva);
    if (psec == nullptr || psec->data.empty()) {
        return false;
    }
    uint32_t cur_ent = pe_file::compute_section_entropy_fixed(psec->data.data(), psec->data.size());
    if (verbose) {
        std::fprintf(stdout, "[+] flatten_entropy: start size=%zu ent=%u band=%u..%u\n",
                     psec->data.size(), cur_ent, target_min, target_max);
    }
    size_t step = 2048;
    size_t iter = 0;
    size_t cap = psec->data.size() * 4u + 0x40000u;
    while (cur_ent > target_max && psec->data.size() < cap) {
        size_t size_before = psec->data.size();
        uint32_t ent_before = cur_ent;
        std::vector<uint8_t> noise = noise_sections::generate_structured_noise(
            step, noise_entropy, seed ^ (0xE17D0u + static_cast<uint64_t>(iter) * 0x9E37u));
        psec->data.insert(psec->data.end(), noise.begin(), noise.end());
        cur_ent = pe_file::compute_section_entropy_fixed(psec->data.data(), psec->data.size());
        if (verbose) {
            std::fprintf(stdout, "[+] flatten_entropy: iter=%zu step=%zu size=%zu ent=%u\n",
                         iter, step, psec->data.size(), cur_ent);
        }
        if (cur_ent < target_min) {
            psec->data.resize(size_before);
            cur_ent = ent_before;
            if (step > 64) { step /= 2; } else { break; }
        }
        ++iter;
        if (iter > 128) { break; }
    }
    uint32_t fa = pe.file_alignment();
    uint32_t padded = pe_file::align_up(static_cast<uint32_t>(psec->data.size()), fa);
    if (padded > psec->data.size()) {
        psec->data.resize(padded, 0);
    }
    psec->virtual_size = static_cast<uint32_t>(psec->data.size());
    psec->raw_size = static_cast<uint32_t>(psec->data.size());
    pe_file::recalculate_headers(pe);
    return true;
}

inline bool apply_flatten_entropy(pe_file::pe_image_t& pe,
                                   uint32_t packed_section_rva,
                                   uint64_t seed,
                                   bool verbose) {
    return apply_flatten_entropy_band(pe, packed_section_rva, seed, verbose,
                                       7100u, 6700u, 6500u);
}

inline bool apply_merge_sections(pe_file::pe_image_t& pe, uint64_t seed) {
    if (pe.sections.size() < 2) {
        return false;
    }
    const auto& last = pe.sections[pe.sections.size() - 1];
    const auto& prev = pe.sections[pe.sections.size() - 2];
    uint32_t last_magic = 0;
    if (last.data.size() >= sizeof(last_magic)) {
        std::memcpy(&last_magic, last.data.data(), sizeof(last_magic));
    }
    if (section_skip_list::name_equals(last.name, ".packed") ||
        last_magic == kPackedMagic ||
        section_skip_list::name_equals(last.name, ".dseal") ||
        section_skip_list::name_equals(last.name, ".dthunk") ||
        section_skip_list::name_equals(last.name, ".licbind") ||
        section_skip_list::name_equals(last.name, ".feat") ||
        section_skip_list::name_equals(prev.name, ".packed") ||
        section_skip_list::name_equals(prev.name, ".dseal") ||
        section_skip_list::name_equals(prev.name, ".dthunk") ||
        section_skip_list::name_equals(prev.name, ".licbind") ||
        section_skip_list::name_equals(prev.name, ".feat")) {
        return false;
    }
    std::string new_name = pe_file::pick_plausible_section_name(seed ^ 0x9E3779B97F4A7C15ULL, pe);
    return pe_file::merge_last_section_into(pe, new_name);
}

inline bool protect_pe(pe_file::pe_image_t& pe, const protect_options_t& opt, std::string* error_out) {
    auto r = protect_pe(pe, opt);
    if (error_out != nullptr) {
        *error_out = r.error;
    }
    return r.success;
}

#ifdef PROTECTOR_SELFTEST
inline bool protector_selftest() {
    const uint8_t kernel32[] = { 'K','E','R','N','E','L','3','2','.','D','L','L' };
    uint32_t h = crc32c(kernel32, 12);
    return h == 0xD4F13C17u;
}
#endif

inline void redirect_entry_point(pe_file::pe_image_t& pe, uint32_t new_entry_rva) {
    pe.optional_header.AddressOfEntryPoint = new_entry_rva;
}

inline bool install_tls_callback(pe_file::pe_image_t& pe, uint32_t tls_stub_rva) {
    if (tls_stub_rva == 0u) {
        return false;
    }
    if (!pe.has_tls) {
        return false;
    }
    if (pe.tls.address_of_callbacks == 0u) {
        return false;
    }
    uint64_t image_base = pe.optional_header.ImageBase;
    uint64_t cb_va = pe.tls.address_of_callbacks;
    if (cb_va < image_base) {
        return false;
    }
    uint32_t cb_rva = static_cast<uint32_t>(cb_va - image_base);
    pe_file::section_t* sec = pe.section_from_rva(cb_rva);
    if (sec == nullptr) {
        return false;
    }
    uint32_t off = cb_rva - sec->virtual_address;
    if (off + 8u > sec->data.size()) {
        return false;
    }
    uint64_t new_cb_va = image_base + tls_stub_rva;
    std::vector<uint64_t> new_list;
    new_list.push_back(new_cb_va);
    for (uint64_t existing : pe.tls.callback_rvas) {
        if (existing != 0u) {
            new_list.push_back(image_base + existing);
        }
    }
    new_list.push_back(0u);
    size_t bytes_needed = new_list.size() * 8u;
    if (off + bytes_needed > sec->data.size()) {
        return false;
    }
    for (size_t i = 0; i < new_list.size(); ++i) {
        uint64_t v = new_list[i];
        std::memcpy(sec->data.data() + off + i * 8u, &v, 8u);
    }
    pe.tls.callback_rvas.clear();
    pe.tls.callback_rvas.push_back(tls_stub_rva);
    return true;
}

inline bool write_stub_into_packed(pe_file::pe_image_t& pe,
                                     uint32_t packed_section_rva,
                                     const packed_section_layout_t& layout,
                                     const std::vector<uint8_t>& main_stub,
                                     const std::vector<uint8_t>& tls_stub) {
    pe_file::section_t* sec = pe.section_from_rva(packed_section_rva);
    if (sec == nullptr) {
        return false;
    }
    if (!main_stub.empty()) {
        if (layout.stub_offset == 0u) {
            return false;
        }
        if (static_cast<size_t>(layout.stub_offset) + main_stub.size() > sec->data.size()) {
            return false;
        }
        std::memcpy(sec->data.data() + layout.stub_offset,
                    main_stub.data(), main_stub.size());
    }
    if (!tls_stub.empty()) {
        if (layout.tls_stub_offset == 0u) {
            return false;
        }
        if (static_cast<size_t>(layout.tls_stub_offset) + tls_stub.size() > sec->data.size()) {
            return false;
        }
        std::memcpy(sec->data.data() + layout.tls_stub_offset,
                    tls_stub.data(), tls_stub.size());
    }
    return true;
}

inline bool patch_aux_signature(pe_file::pe_image_t& pe,
                                 uint32_t packed_section_rva,
                                 const packed_section_layout_t& layout,
                                 uint64_t build_nonce,
                                 uint32_t stub_signature_tag) {
    pe_file::section_t* sec = pe.section_from_rva(packed_section_rva);
    if (sec == nullptr) {
        return false;
    }
    if (layout.aux_offset == 0u) {
        return false;
    }
    if (static_cast<size_t>(layout.aux_offset) + sizeof(aux_block_t) > sec->data.size()) {
        return false;
    }
    aux_block_t aux{};
    std::memcpy(&aux, sec->data.data() + layout.aux_offset, sizeof(aux_block_t));
    aux.polymorphic_build_nonce = build_nonce;
    aux.stub_signature_tag = stub_signature_tag;
    std::memcpy(sec->data.data() + layout.aux_offset, &aux, sizeof(aux_block_t));
    return true;
}

inline bool patch_aux_phase_flags(pe_file::pe_image_t& pe,
                                  uint32_t packed_section_rva,
                                  const packed_section_layout_t& layout,
                                  uint32_t clear_mask,
                                  uint32_t set_mask) {
    pe_file::section_t* sec = pe.section_from_rva(packed_section_rva);
    if (sec == nullptr) {
        return false;
    }
    if (layout.aux_offset == 0u) {
        return false;
    }
    if (static_cast<size_t>(layout.aux_offset) + sizeof(aux_block_t) > sec->data.size()) {
        return false;
    }
    aux_block_t aux{};
    std::memcpy(&aux, sec->data.data() + layout.aux_offset, sizeof(aux_block_t));
    if (aux.magic != kAuxMagic || aux.version != kAuxVersion) {
        return false;
    }
    aux.phase_flags = (aux.phase_flags & ~clear_mask) | set_mask;
    std::memcpy(sec->data.data() + layout.aux_offset, &aux, sizeof(aux_block_t));
    return true;
}

}
