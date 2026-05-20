#ifndef NOMINMAX
#define NOMINMAX
#endif
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <bcrypt.h>
#include <intrin.h>
#include <wmmintrin.h>
#include <emmintrin.h>

#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <vector>
#include <array>
#include <random>

#include "transforms.hpp"

#pragma comment(lib, "bcrypt.lib")

namespace mirror {

static __m128i aes128_assist_mirror(__m128i a, __m128i b) {
    b = _mm_shuffle_epi32(b, 0xFF);
    __m128i t = _mm_slli_si128(a, 4);
    a = _mm_xor_si128(a, t);
    t = _mm_slli_si128(t, 4);
    a = _mm_xor_si128(a, t);
    t = _mm_slli_si128(t, 4);
    a = _mm_xor_si128(a, t);
    return _mm_xor_si128(a, b);
}

static void aes128_expand_mirror(const uint8_t key[16], __m128i rk[11]) {
    rk[0] = _mm_loadu_si128((const __m128i*)key);
    rk[1]  = aes128_assist_mirror(rk[0],  _mm_aeskeygenassist_si128(rk[0],  0x01));
    rk[2]  = aes128_assist_mirror(rk[1],  _mm_aeskeygenassist_si128(rk[1],  0x02));
    rk[3]  = aes128_assist_mirror(rk[2],  _mm_aeskeygenassist_si128(rk[2],  0x04));
    rk[4]  = aes128_assist_mirror(rk[3],  _mm_aeskeygenassist_si128(rk[3],  0x08));
    rk[5]  = aes128_assist_mirror(rk[4],  _mm_aeskeygenassist_si128(rk[4],  0x10));
    rk[6]  = aes128_assist_mirror(rk[5],  _mm_aeskeygenassist_si128(rk[5],  0x20));
    rk[7]  = aes128_assist_mirror(rk[6],  _mm_aeskeygenassist_si128(rk[6],  0x40));
    rk[8]  = aes128_assist_mirror(rk[7],  _mm_aeskeygenassist_si128(rk[7],  0x80));
    rk[9]  = aes128_assist_mirror(rk[8],  _mm_aeskeygenassist_si128(rk[8],  0x1B));
    rk[10] = aes128_assist_mirror(rk[9],  _mm_aeskeygenassist_si128(rk[9],  0x36));
}

static __m128i aes128_enc_mirror(__m128i blk, const __m128i rk[11]) {
    blk = _mm_xor_si128(blk, rk[0]);
    blk = _mm_aesenc_si128(blk, rk[1]);
    blk = _mm_aesenc_si128(blk, rk[2]);
    blk = _mm_aesenc_si128(blk, rk[3]);
    blk = _mm_aesenc_si128(blk, rk[4]);
    blk = _mm_aesenc_si128(blk, rk[5]);
    blk = _mm_aesenc_si128(blk, rk[6]);
    blk = _mm_aesenc_si128(blk, rk[7]);
    blk = _mm_aesenc_si128(blk, rk[8]);
    blk = _mm_aesenc_si128(blk, rk[9]);
    blk = _mm_aesenclast_si128(blk, rk[10]);
    return blk;
}

inline void aes128_ctr_xor(const uint8_t key[16], const uint8_t iv[16],
                           uint8_t* buf, size_t len) {
    __m128i rk[11];
    aes128_expand_mirror(key, rk);
    uint8_t counter[16];
    std::memcpy(counter, iv, 16);
    size_t off = 0;
    while (off < len) {
        __m128i ctr = _mm_loadu_si128((const __m128i*)counter);
        __m128i ks = aes128_enc_mirror(ctr, rk);
        uint8_t ksb[16];
        _mm_storeu_si128((__m128i*)ksb, ks);
        for (int i = 15; i >= 0; --i) {
            counter[i] = static_cast<uint8_t>(counter[i] + 1u);
            if (counter[i] != 0) {
                break;
            }
        }
        size_t bl = (len - off < 16u) ? (len - off) : 16u;
        for (size_t i = 0; i < bl; ++i) {
            buf[off + i] = static_cast<uint8_t>(buf[off + i] ^ ksb[i]);
        }
        off += bl;
    }
}

inline uint32_t cc20_rotl32(uint32_t a, unsigned b) {
    return (a << b) | (a >> (32u - b));
}

inline void cc20_qr(uint32_t& a, uint32_t& b, uint32_t& c, uint32_t& d) {
    a += b; d ^= a; d = cc20_rotl32(d, 16);
    c += d; b ^= c; b = cc20_rotl32(b, 12);
    a += b; d ^= a; d = cc20_rotl32(d, 8);
    c += d; b ^= c; b = cc20_rotl32(b, 7);
}

inline void cc20_block(const uint32_t state[16], uint8_t out[64]) {
    uint32_t x[16];
    for (int i = 0; i < 16; ++i) { x[i] = state[i]; }
    for (int i = 0; i < 10; ++i) {
        cc20_qr(x[0], x[4], x[8],  x[12]);
        cc20_qr(x[1], x[5], x[9],  x[13]);
        cc20_qr(x[2], x[6], x[10], x[14]);
        cc20_qr(x[3], x[7], x[11], x[15]);
        cc20_qr(x[0], x[5], x[10], x[15]);
        cc20_qr(x[1], x[6], x[11], x[12]);
        cc20_qr(x[2], x[7], x[8],  x[13]);
        cc20_qr(x[3], x[4], x[9],  x[14]);
    }
    for (int i = 0; i < 16; ++i) {
        uint32_t v = x[i] + state[i];
        out[4 * i + 0] = static_cast<uint8_t>(v & 0xFFu);
        out[4 * i + 1] = static_cast<uint8_t>((v >> 8) & 0xFFu);
        out[4 * i + 2] = static_cast<uint8_t>((v >> 16) & 0xFFu);
        out[4 * i + 3] = static_cast<uint8_t>((v >> 24) & 0xFFu);
    }
}

inline void chacha20_xor(const uint8_t key[32], const uint8_t nonce[12],
                         uint8_t* buf, size_t len) {
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
        cc20_block(state, ks);
        ++state[12];
        size_t bl = (len - off < 64u) ? (len - off) : 64u;
        for (size_t i = 0; i < bl; ++i) {
            buf[off + i] = static_cast<uint8_t>(buf[off + i] ^ ks[i]);
        }
        off += bl;
    }
}

inline void xtea_block_encrypt(const uint32_t key[4], uint32_t& v0, uint32_t& v1) {
    uint32_t sum = 0;
    const uint32_t delta = 0x9E3779B9u;
    for (int i = 0; i < 64; ++i) {
        v0 += (((v1 << 4) ^ (v1 >> 5)) + v1) ^ (sum + key[sum & 3u]);
        sum += delta;
        v1 += (((v0 << 4) ^ (v0 >> 5)) + v0) ^ (sum + key[(sum >> 11) & 3u]);
    }
}

inline void xtea_ctr_xor(const uint8_t key[16], const uint8_t iv[8],
                         uint8_t* buf, size_t len) {
    uint32_t kw[4];
    for (int i = 0; i < 4; ++i) {
        kw[i] = static_cast<uint32_t>(key[4 * i]) |
                (static_cast<uint32_t>(key[4 * i + 1]) << 8) |
                (static_cast<uint32_t>(key[4 * i + 2]) << 16) |
                (static_cast<uint32_t>(key[4 * i + 3]) << 24);
    }
    uint8_t counter[8];
    std::memcpy(counter, iv, 8);
    size_t off = 0;
    while (off < len) {
        uint32_t v0 = static_cast<uint32_t>(counter[0]) |
                      (static_cast<uint32_t>(counter[1]) << 8) |
                      (static_cast<uint32_t>(counter[2]) << 16) |
                      (static_cast<uint32_t>(counter[3]) << 24);
        uint32_t v1 = static_cast<uint32_t>(counter[4]) |
                      (static_cast<uint32_t>(counter[5]) << 8) |
                      (static_cast<uint32_t>(counter[6]) << 16) |
                      (static_cast<uint32_t>(counter[7]) << 24);
        xtea_block_encrypt(kw, v0, v1);
        uint8_t ks[8];
        ks[0] = static_cast<uint8_t>(v0 & 0xFFu);
        ks[1] = static_cast<uint8_t>((v0 >> 8) & 0xFFu);
        ks[2] = static_cast<uint8_t>((v0 >> 16) & 0xFFu);
        ks[3] = static_cast<uint8_t>((v0 >> 24) & 0xFFu);
        ks[4] = static_cast<uint8_t>(v1 & 0xFFu);
        ks[5] = static_cast<uint8_t>((v1 >> 8) & 0xFFu);
        ks[6] = static_cast<uint8_t>((v1 >> 16) & 0xFFu);
        ks[7] = static_cast<uint8_t>((v1 >> 24) & 0xFFu);
        for (int i = 0; i < 8; ++i) {
            counter[i] = static_cast<uint8_t>(counter[i] + 1u);
            if (counter[i] != 0) {
                break;
            }
        }
        size_t bl = (len - off < 8u) ? (len - off) : 8u;
        for (size_t i = 0; i < bl; ++i) {
            buf[off + i] = static_cast<uint8_t>(buf[off + i] ^ ks[i]);
        }
        off += bl;
    }
}

inline uint32_t sha_rotr32(uint32_t x, unsigned n) {
    return (x >> n) | (x << (32u - n));
}

inline void sha256_compress_pl(uint32_t H[8], const uint8_t block[64]) {
    uint32_t k0  = 0x428a2f98u; uint32_t k1  = 0x71374491u; uint32_t k2  = 0xb5c0fbcfu; uint32_t k3  = 0xe9b5dba5u;
    uint32_t k4  = 0x3956c25bu; uint32_t k5  = 0x59f111f1u; uint32_t k6  = 0x923f82a4u; uint32_t k7  = 0xab1c5ed5u;
    uint32_t k8  = 0xd807aa98u; uint32_t k9  = 0x12835b01u; uint32_t k10 = 0x243185beu; uint32_t k11 = 0x550c7dc3u;
    uint32_t k12 = 0x72be5d74u; uint32_t k13 = 0x80deb1feu; uint32_t k14 = 0x9bdc06a7u; uint32_t k15 = 0xc19bf174u;
    uint32_t k16 = 0xe49b69c1u; uint32_t k17 = 0xefbe4786u; uint32_t k18 = 0x0fc19dc6u; uint32_t k19 = 0x240ca1ccu;
    uint32_t k20 = 0x2de92c6fu; uint32_t k21 = 0x4a7484aau; uint32_t k22 = 0x5cb0a9dcu; uint32_t k23 = 0x76f988dau;
    uint32_t k24 = 0x983e5152u; uint32_t k25 = 0xa831c66du; uint32_t k26 = 0xb00327c8u; uint32_t k27 = 0xbf597fc7u;
    uint32_t k28 = 0xc6e00bf3u; uint32_t k29 = 0xd5a79147u; uint32_t k30 = 0x06ca6351u; uint32_t k31 = 0x14292967u;
    uint32_t k32 = 0x27b70a85u; uint32_t k33 = 0x2e1b2138u; uint32_t k34 = 0x4d2c6dfcu; uint32_t k35 = 0x53380d13u;
    uint32_t k36 = 0x650a7354u; uint32_t k37 = 0x766a0abbu; uint32_t k38 = 0x81c2c92eu; uint32_t k39 = 0x92722c85u;
    uint32_t k40 = 0xa2bfe8a1u; uint32_t k41 = 0xa81a664bu; uint32_t k42 = 0xc24b8b70u; uint32_t k43 = 0xc76c51a3u;
    uint32_t k44 = 0xd192e819u; uint32_t k45 = 0xd6990624u; uint32_t k46 = 0xf40e3585u; uint32_t k47 = 0x106aa070u;
    uint32_t k48 = 0x19a4c116u; uint32_t k49 = 0x1e376c08u; uint32_t k50 = 0x2748774cu; uint32_t k51 = 0x34b0bcb5u;
    uint32_t k52 = 0x391c0cb3u; uint32_t k53 = 0x4ed8aa4au; uint32_t k54 = 0x5b9cca4fu; uint32_t k55 = 0x682e6ff3u;
    uint32_t k56 = 0x748f82eeu; uint32_t k57 = 0x78a5636fu; uint32_t k58 = 0x84c87814u; uint32_t k59 = 0x8cc70208u;
    uint32_t k60 = 0x90befffau; uint32_t k61 = 0xa4506cebu; uint32_t k62 = 0xbef9a3f7u; uint32_t k63 = 0xc67178f2u;
    uint32_t K[64];
    K[0]=k0;K[1]=k1;K[2]=k2;K[3]=k3;K[4]=k4;K[5]=k5;K[6]=k6;K[7]=k7;
    K[8]=k8;K[9]=k9;K[10]=k10;K[11]=k11;K[12]=k12;K[13]=k13;K[14]=k14;K[15]=k15;
    K[16]=k16;K[17]=k17;K[18]=k18;K[19]=k19;K[20]=k20;K[21]=k21;K[22]=k22;K[23]=k23;
    K[24]=k24;K[25]=k25;K[26]=k26;K[27]=k27;K[28]=k28;K[29]=k29;K[30]=k30;K[31]=k31;
    K[32]=k32;K[33]=k33;K[34]=k34;K[35]=k35;K[36]=k36;K[37]=k37;K[38]=k38;K[39]=k39;
    K[40]=k40;K[41]=k41;K[42]=k42;K[43]=k43;K[44]=k44;K[45]=k45;K[46]=k46;K[47]=k47;
    K[48]=k48;K[49]=k49;K[50]=k50;K[51]=k51;K[52]=k52;K[53]=k53;K[54]=k54;K[55]=k55;
    K[56]=k56;K[57]=k57;K[58]=k58;K[59]=k59;K[60]=k60;K[61]=k61;K[62]=k62;K[63]=k63;
    uint32_t W[64];
    for (int i = 0; i < 16; ++i) {
        W[i] = (static_cast<uint32_t>(block[4 * i + 0]) << 24) |
               (static_cast<uint32_t>(block[4 * i + 1]) << 16) |
               (static_cast<uint32_t>(block[4 * i + 2]) << 8) |
                static_cast<uint32_t>(block[4 * i + 3]);
    }
    for (int i = 16; i < 64; ++i) {
        uint32_t s0 = sha_rotr32(W[i - 15], 7) ^ sha_rotr32(W[i - 15], 18) ^ (W[i - 15] >> 3);
        uint32_t s1 = sha_rotr32(W[i - 2], 17) ^ sha_rotr32(W[i - 2], 19) ^ (W[i - 2] >> 10);
        W[i] = W[i - 16] + s0 + W[i - 7] + s1;
    }
    uint32_t a = H[0], b = H[1], c = H[2], d = H[3];
    uint32_t e = H[4], f = H[5], g = H[6], h = H[7];
    for (int i = 0; i < 64; ++i) {
        uint32_t S1 = sha_rotr32(e, 6) ^ sha_rotr32(e, 11) ^ sha_rotr32(e, 25);
        uint32_t ch = (e & f) ^ (~e & g);
        uint32_t t1 = h + S1 + ch + K[i] + W[i];
        uint32_t S0 = sha_rotr32(a, 2) ^ sha_rotr32(a, 13) ^ sha_rotr32(a, 22);
        uint32_t mj = (a & b) ^ (a & c) ^ (b & c);
        uint32_t t2 = S0 + mj;
        h = g; g = f; f = e; e = d + t1; d = c; c = b; b = a; a = t1 + t2;
    }
    H[0] += a; H[1] += b; H[2] += c; H[3] += d;
    H[4] += e; H[5] += f; H[6] += g; H[7] += h;
}

inline void sha256_compute(const uint8_t* data, size_t len, uint8_t out[32]) {
    uint32_t H[8] = {
        0x6a09e667u, 0xbb67ae85u, 0x3c6ef372u, 0xa54ff53au,
        0x510e527fu, 0x9b05688cu, 0x1f83d9abu, 0x5be0cd19u
    };
    uint64_t bitlen = static_cast<uint64_t>(len) * 8ull;
    size_t off = 0;
    while (len - off >= 64) {
        sha256_compress_pl(H, data + off);
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
        sha256_compress_pl(H, block);
        std::memset(block, 0, 56);
    } else {
        std::memset(block + rem + 1, 0, 56 - rem - 1);
    }
    for (int i = 0; i < 8; ++i) {
        block[56 + i] = static_cast<uint8_t>((bitlen >> (56 - 8 * i)) & 0xFFull);
    }
    sha256_compress_pl(H, block);
    for (int i = 0; i < 8; ++i) {
        out[4 * i + 0] = static_cast<uint8_t>((H[i] >> 24) & 0xFFu);
        out[4 * i + 1] = static_cast<uint8_t>((H[i] >> 16) & 0xFFu);
        out[4 * i + 2] = static_cast<uint8_t>((H[i] >> 8) & 0xFFu);
        out[4 * i + 3] = static_cast<uint8_t>(H[i] & 0xFFu);
    }
}

}

static std::string s_last_error;

inline const std::string& last_error() {
    return s_last_error;
}

inline void hex_dump(const uint8_t* p, size_t n) {
    for (size_t i = 0; i < n; ++i) {
        std::fprintf(stdout, "%02x", p[i]);
        if (i + 1u < n) {
            std::fprintf(stdout, ((i & 15u) == 15u) ? "\n" : " ");
        }
    }
    std::fprintf(stdout, "\n");
}

inline std::vector<uint8_t> random_bytes(size_t n, uint64_t seed) {
    std::mt19937_64 rng(seed);
    std::vector<uint8_t> out(n);
    for (size_t i = 0; i < n; ++i) {
        out[i] = static_cast<uint8_t>(rng() & 0xFFu);
    }
    return out;
}

inline double byte_entropy_bits(const uint8_t* data, size_t n) {
    if (n == 0) {
        return 0.0;
    }
    std::array<uint64_t, 256> hist{};
    for (size_t i = 0; i < n; ++i) {
        ++hist[data[i]];
    }
    double total = static_cast<double>(n);
    double h = 0.0;
    for (size_t i = 0; i < 256; ++i) {
        if (hist[i] == 0u) {
            continue;
        }
        double p = static_cast<double>(hist[i]) / total;
        h -= p * (log(p) / log(2.0));
    }
    return h;
}

inline bool encrypt_three_layers(const uint8_t* plain, size_t n,
                                  uint32_t section_rva, uint32_t section_index,
                                  const uint8_t master[32],
                                  uint8_t l1_iv[16],
                                  uint8_t l2_nonce[12],
                                  uint8_t l3_iv[8],
                                  std::vector<uint8_t>& out_blob) {
    uint8_t hwid[32];
    uint8_t tpm[32];
    uint8_t srv[32];
    uint8_t build_seed[32];
    protector::matryoshka_detail::compute_hwid_anchor(hwid);
    protector::matryoshka_detail::compute_tpm_anchor(tpm);
    protector::matryoshka_detail::compute_server_anchor(srv);
    protector::matryoshka_detail::derive_build_seed_from_master(master, build_seed);

    uint8_t l1_key[16];
    uint8_t l2_key[32];
    uint8_t l3_key[16];
    protector::matryoshka_detail::derive_layer1_key(hwid, build_seed, section_rva, section_index, l1_key);
    protector::matryoshka_detail::derive_layer2_key(tpm,  build_seed, section_rva, section_index, l2_key);
    protector::matryoshka_detail::derive_layer3_key(srv,  build_seed, section_rva, section_index, l3_key);

    if (BCryptGenRandom(nullptr, l1_iv, 16, BCRYPT_USE_SYSTEM_PREFERRED_RNG) != 0) {
        s_last_error = "BCryptGenRandom failed for layer1 iv";
        return false;
    }
    if (BCryptGenRandom(nullptr, l2_nonce, 12, BCRYPT_USE_SYSTEM_PREFERRED_RNG) != 0) {
        s_last_error = "BCryptGenRandom failed for layer2 nonce";
        return false;
    }
    if (BCryptGenRandom(nullptr, l3_iv, 8, BCRYPT_USE_SYSTEM_PREFERRED_RNG) != 0) {
        s_last_error = "BCryptGenRandom failed for layer3 iv";
        return false;
    }

    out_blob.assign(plain, plain + n);
    protector::aes_detail::aes128_ctr(l1_key, l1_iv, out_blob.data(), out_blob.data(), n);

    std::vector<uint8_t> tmp(n);
    protector::chacha_detail::chacha20_xor(l2_key, l2_nonce, out_blob.data(), tmp.data(), n);
    out_blob.swap(tmp);

    std::vector<uint8_t> tmp2(n);
    protector::xtea_ctr(l3_key, l3_iv, out_blob.data(), tmp2.data(), n);
    out_blob.swap(tmp2);

    return true;
}

inline bool decrypt_three_layers_payload_path(uint8_t* blob, size_t n,
                                              uint32_t section_rva, uint32_t section_index,
                                              const uint8_t master[32],
                                              const uint8_t l1_iv[16],
                                              const uint8_t l2_nonce[12],
                                              const uint8_t l3_iv[8]) {
    uint8_t hwid[32];
    uint8_t tpm[32];
    uint8_t srv[32];
    uint8_t build_seed[32];
    protector::matryoshka_detail::compute_hwid_anchor(hwid);
    protector::matryoshka_detail::compute_tpm_anchor(tpm);
    protector::matryoshka_detail::compute_server_anchor(srv);
    protector::matryoshka_detail::derive_build_seed_from_master(master, build_seed);

    uint8_t l1_key[16];
    uint8_t l2_key[32];
    uint8_t l3_key[16];
    protector::matryoshka_detail::derive_layer1_key(hwid, build_seed, section_rva, section_index, l1_key);
    protector::matryoshka_detail::derive_layer2_key(tpm,  build_seed, section_rva, section_index, l2_key);
    protector::matryoshka_detail::derive_layer3_key(srv,  build_seed, section_rva, section_index, l3_key);

    mirror::xtea_ctr_xor(l3_key, l3_iv, blob, n);
    mirror::chacha20_xor(l2_key, l2_nonce, blob, n);
    mirror::aes128_ctr_xor(l1_key, l1_iv, blob, n);
    return true;
}

inline bool kat_test() {
    std::fprintf(stdout, "[KAT] starting matryoshka KAT\n");

    const size_t kSize = 256;
    auto plain = random_bytes(kSize, 0xC0FFEEDEADBEEF42ull);

    uint8_t master[32];
    for (int i = 0; i < 32; ++i) {
        master[i] = static_cast<uint8_t>(i ^ 0xA5u);
    }

    std::vector<uint8_t> blob;
    uint8_t l1_iv[16];
    uint8_t l2_nonce[12];
    uint8_t l3_iv[8];
    if (!encrypt_three_layers(plain.data(), kSize, 0x12340u, 4u, master,
                              l1_iv, l2_nonce, l3_iv, blob)) {
        std::fprintf(stderr, "[KAT] encrypt_three_layers failed: %s\n", last_error().c_str());
        return false;
    }
    if (blob.size() != kSize) {
        std::fprintf(stderr, "[KAT] blob size mismatch: got=%zu expected=%zu\n", blob.size(), kSize);
        return false;
    }
    if (std::memcmp(plain.data(), blob.data(), kSize) == 0) {
        std::fprintf(stderr, "[KAT] ciphertext equals plaintext\n");
        return false;
    }

    std::vector<uint8_t> recovered = blob;
    if (!decrypt_three_layers_payload_path(recovered.data(), kSize, 0x12340u, 4u, master,
                                            l1_iv, l2_nonce, l3_iv)) {
        std::fprintf(stderr, "[KAT] decrypt_three_layers_payload_path failed\n");
        return false;
    }
    if (std::memcmp(plain.data(), recovered.data(), kSize) != 0) {
        std::fprintf(stderr, "[KAT] roundtrip mismatch at first byte\n");
        return false;
    }
    std::fprintf(stdout, "[KAT] PASS bytes=%zu\n", kSize);
    return true;
}

inline bool layer_isolation_test() {
    std::fprintf(stdout, "[ISO] starting layer isolation test\n");
    const size_t kSize = 8192;
    auto plain = random_bytes(kSize, 0xBADF00D17ull);
    uint8_t master[32];
    for (int i = 0; i < 32; ++i) {
        master[i] = static_cast<uint8_t>((i * 13 + 7) & 0xFFu);
    }

    std::vector<uint8_t> blob;
    uint8_t l1_iv[16];
    uint8_t l2_nonce[12];
    uint8_t l3_iv[8];
    if (!encrypt_three_layers(plain.data(), kSize, 0x55550u, 9u, master,
                              l1_iv, l2_nonce, l3_iv, blob)) {
        std::fprintf(stderr, "[ISO] encrypt failed\n");
        return false;
    }

    double e_blob = byte_entropy_bits(blob.data(), blob.size());
    if (e_blob < 7.5) {
        std::fprintf(stderr, "[ISO] full-stack entropy too low: %.4f bits/byte\n", e_blob);
        return false;
    }

    uint8_t hwid[32];
    uint8_t tpm[32];
    uint8_t srv[32];
    uint8_t build_seed[32];
    protector::matryoshka_detail::compute_hwid_anchor(hwid);
    protector::matryoshka_detail::compute_tpm_anchor(tpm);
    protector::matryoshka_detail::compute_server_anchor(srv);
    protector::matryoshka_detail::derive_build_seed_from_master(master, build_seed);

    uint8_t l3_key[16];
    protector::matryoshka_detail::derive_layer3_key(srv, build_seed, 0x55550u, 9u, l3_key);

    std::vector<uint8_t> after_l3 = blob;
    mirror::xtea_ctr_xor(l3_key, l3_iv, after_l3.data(), after_l3.size());
    double e_after_l3 = byte_entropy_bits(after_l3.data(), after_l3.size());
    if (e_after_l3 < 7.5) {
        std::fprintf(stderr, "[ISO] post-L3-peel entropy too low: %.4f bits/byte\n", e_after_l3);
        return false;
    }

    uint8_t l2_key[32];
    protector::matryoshka_detail::derive_layer2_key(tpm, build_seed, 0x55550u, 9u, l2_key);
    std::vector<uint8_t> after_l2 = after_l3;
    mirror::chacha20_xor(l2_key, l2_nonce, after_l2.data(), after_l2.size());
    double e_after_l2 = byte_entropy_bits(after_l2.data(), after_l2.size());
    if (e_after_l2 < 7.5) {
        std::fprintf(stderr, "[ISO] post-L2-peel entropy too low: %.4f bits/byte\n", e_after_l2);
        return false;
    }

    std::fprintf(stdout, "[ISO] entropy bits/byte full=%.4f post_l3=%.4f post_l2=%.4f\n",
                 e_blob, e_after_l3, e_after_l2);
    std::fprintf(stdout, "[ISO] PASS\n");
    return true;
}

inline bool wrong_key_test() {
    std::fprintf(stdout, "[WRONG] starting wrong-L3-key test\n");
    const size_t kSize = 1024;
    auto plain = random_bytes(kSize, 0x1010101010101010ull);
    uint8_t master[32];
    for (int i = 0; i < 32; ++i) {
        master[i] = static_cast<uint8_t>(0x42 ^ i);
    }
    std::vector<uint8_t> blob;
    uint8_t l1_iv[16];
    uint8_t l2_nonce[12];
    uint8_t l3_iv[8];
    if (!encrypt_three_layers(plain.data(), kSize, 0x80000u, 13u, master,
                              l1_iv, l2_nonce, l3_iv, blob)) {
        std::fprintf(stderr, "[WRONG] encrypt failed\n");
        return false;
    }

    uint8_t hwid[32];
    uint8_t tpm[32];
    uint8_t srv[32];
    uint8_t build_seed[32];
    protector::matryoshka_detail::compute_hwid_anchor(hwid);
    protector::matryoshka_detail::compute_tpm_anchor(tpm);
    protector::matryoshka_detail::compute_server_anchor(srv);
    protector::matryoshka_detail::derive_build_seed_from_master(master, build_seed);
    uint8_t l3_key[16];
    protector::matryoshka_detail::derive_layer3_key(srv, build_seed, 0x80000u, 13u, l3_key);
    for (int i = 0; i < 16; ++i) {
        l3_key[i] ^= 0xFFu;
    }
    std::vector<uint8_t> blob_attacked = blob;
    mirror::xtea_ctr_xor(l3_key, l3_iv, blob_attacked.data(), blob_attacked.size());
    uint8_t l2_key[32];
    protector::matryoshka_detail::derive_layer2_key(tpm, build_seed, 0x80000u, 13u, l2_key);
    mirror::chacha20_xor(l2_key, l2_nonce, blob_attacked.data(), blob_attacked.size());
    uint8_t l1_key[16];
    protector::matryoshka_detail::derive_layer1_key(hwid, build_seed, 0x80000u, 13u, l1_key);
    mirror::aes128_ctr_xor(l1_key, l1_iv, blob_attacked.data(), blob_attacked.size());

    if (std::memcmp(plain.data(), blob_attacked.data(), kSize) == 0) {
        std::fprintf(stderr, "[WRONG] decrypted plaintext with WRONG L3 key\n");
        return false;
    }
    size_t mismatches = 0;
    for (size_t i = 0; i < kSize; ++i) {
        if (plain[i] != blob_attacked[i]) {
            ++mismatches;
        }
    }
    if (mismatches < kSize / 2u) {
        std::fprintf(stderr, "[WRONG] only %zu/%zu mismatches with wrong key\n", mismatches, kSize);
        return false;
    }
    std::fprintf(stdout, "[WRONG] PASS mismatches=%zu/%zu\n", mismatches, kSize);
    return true;
}

inline bool section_roundtrip_test() {
    std::fprintf(stdout, "[ROUND] starting 4 KiB section roundtrip\n");
    const size_t kSize = 4096;
    auto plain = random_bytes(kSize, 0xDEADC0DEC0FFFEED);
    uint8_t master[32];
    for (int i = 0; i < 32; ++i) {
        master[i] = static_cast<uint8_t>((i * 31 + 5) & 0xFFu);
    }
    std::vector<uint8_t> blob;
    uint8_t l1_iv[16];
    uint8_t l2_nonce[12];
    uint8_t l3_iv[8];
    if (!encrypt_three_layers(plain.data(), kSize, 0x90000u, 22u, master,
                              l1_iv, l2_nonce, l3_iv, blob)) {
        std::fprintf(stderr, "[ROUND] encrypt failed\n");
        return false;
    }
    std::vector<uint8_t> recovered = blob;
    decrypt_three_layers_payload_path(recovered.data(), kSize, 0x90000u, 22u, master,
                                       l1_iv, l2_nonce, l3_iv);
    if (std::memcmp(plain.data(), recovered.data(), kSize) != 0) {
        std::fprintf(stderr, "[ROUND] mismatch in 4 KiB roundtrip\n");
        return false;
    }
    std::fprintf(stdout, "[ROUND] PASS bytes=%zu\n", kSize);
    return true;
}

inline bool legacy_compat_test() {
    std::fprintf(stdout, "[LEGACY] starting legacy single-AES roundtrip\n");
    const size_t kSize = 512;
    auto plain = random_bytes(kSize, 0xC1C1C1C1C1C1C1C1ull);
    uint8_t master[32];
    for (int i = 0; i < 32; ++i) {
        master[i] = static_cast<uint8_t>(0x99 ^ (i * 7));
    }
    uint8_t section_key[32];
    uint8_t section_iv[16];
    protector::derive_section_key(master, 0x77770u, 33u, section_key, section_iv);

    std::vector<uint8_t> ct(kSize);
    protector::aes_detail::aes256_ctr(section_key, section_iv, plain.data(), ct.data(), kSize);

    std::vector<uint8_t> pt2 = ct;
    protector::aes_detail::aes256_ctr(section_key, section_iv, pt2.data(), pt2.data(), kSize);
    if (std::memcmp(plain.data(), pt2.data(), kSize) != 0) {
        std::fprintf(stderr, "[LEGACY] AES-256 self-roundtrip failed\n");
        return false;
    }
    std::fprintf(stdout, "[LEGACY] PASS bytes=%zu\n", kSize);
    return true;
}

inline bool xtea_kat_test() {
    std::fprintf(stdout, "[XTEA] starting host vs mirror KAT\n");
    const size_t kSize = 64;
    auto plain = random_bytes(kSize, 0x4242424242424242ull);
    uint8_t key[16];
    for (int i = 0; i < 16; ++i) {
        key[i] = static_cast<uint8_t>(i * 17u);
    }
    uint8_t iv[8];
    for (int i = 0; i < 8; ++i) {
        iv[i] = static_cast<uint8_t>(i * 7u + 1u);
    }
    std::vector<uint8_t> host_ct(kSize);
    protector::xtea_ctr(key, iv, plain.data(), host_ct.data(), kSize);

    std::vector<uint8_t> mirror_ct = plain;
    mirror::xtea_ctr_xor(key, iv, mirror_ct.data(), kSize);

    if (std::memcmp(host_ct.data(), mirror_ct.data(), kSize) != 0) {
        std::fprintf(stderr, "[XTEA] host vs mirror disagree:\n");
        std::fprintf(stdout, "host: ");
        hex_dump(host_ct.data(), 16);
        std::fprintf(stdout, "mirror: ");
        hex_dump(mirror_ct.data(), 16);
        return false;
    }

    std::vector<uint8_t> rt = host_ct;
    mirror::xtea_ctr_xor(key, iv, rt.data(), kSize);
    if (std::memcmp(plain.data(), rt.data(), kSize) != 0) {
        std::fprintf(stderr, "[XTEA] roundtrip failed\n");
        return false;
    }
    std::fprintf(stdout, "[XTEA] PASS bytes=%zu\n", kSize);
    return true;
}

inline void mirror_compute_hwid_anchor(uint8_t out[32]) {
    uint8_t a[25];
    a[ 0]='a'; a[ 1]='i'; a[ 2]='d'; a[ 3]='a'; a[ 4]='-';
    a[ 5]='b'; a[ 6]='u'; a[ 7]='i'; a[ 8]='l'; a[ 9]='d';
    a[10]='-'; a[11]='h'; a[12]='w'; a[13]='i'; a[14]='d';
    a[15]='-'; a[16]='a'; a[17]='n'; a[18]='c'; a[19]='h';
    a[20]='o'; a[21]='r'; a[22]='-'; a[23]='v'; a[24]='1';
    mirror::sha256_compute(a, 25, out);
}

inline void mirror_compute_tpm_anchor(uint8_t out[32]) {
    uint8_t a[24];
    a[ 0]='a'; a[ 1]='i'; a[ 2]='d'; a[ 3]='a'; a[ 4]='-';
    a[ 5]='b'; a[ 6]='u'; a[ 7]='i'; a[ 8]='l'; a[ 9]='d';
    a[10]='-'; a[11]='t'; a[12]='p'; a[13]='m'; a[14]='-';
    a[15]='a'; a[16]='n'; a[17]='c'; a[18]='h'; a[19]='o';
    a[20]='r'; a[21]='-'; a[22]='v'; a[23]='1';
    mirror::sha256_compute(a, 24, out);
}

inline void mirror_compute_server_anchor(uint8_t out[32]) {
    uint8_t a[34];
    a[ 0]='a'; a[ 1]='i'; a[ 2]='d'; a[ 3]='a'; a[ 4]='-';
    a[ 5]='b'; a[ 6]='u'; a[ 7]='i'; a[ 8]='l'; a[ 9]='d';
    a[10]='-'; a[11]='s'; a[12]='r'; a[13]='v'; a[14]='-';
    a[15]='h'; a[16]='e'; a[17]='a'; a[18]='r'; a[19]='t';
    a[20]='b'; a[21]='e'; a[22]='a'; a[23]='t'; a[24]='-';
    a[25]='a'; a[26]='n'; a[27]='c'; a[28]='h'; a[29]='o';
    a[30]='r'; a[31]='-'; a[32]='v'; a[33]='1';
    mirror::sha256_compute(a, 34, out);
}

inline void mirror_hkdf_extract(const uint8_t* salt, size_t salt_len,
                                 const uint8_t* ikm, size_t ikm_len,
                                 uint8_t prk[32]) {
    uint8_t k[64];
    if (salt_len == 0) {
        std::memset(k, 0, 64);
        for (int i = 0; i < 64; ++i) {
            uint8_t ipad = static_cast<uint8_t>(k[i] ^ 0x36u);
            uint8_t opad = static_cast<uint8_t>(k[i] ^ 0x5Cu);
            (void)ipad; (void)opad;
        }
    }
    uint8_t zero[32] = {0};
    if (salt_len == 0) {
        salt = zero;
        salt_len = 32;
    }
    uint8_t kk[64];
    if (salt_len > 64) {
        mirror::sha256_compute(salt, salt_len, kk);
        std::memset(kk + 32, 0, 32);
    } else {
        std::memcpy(kk, salt, salt_len);
        std::memset(kk + salt_len, 0, 64 - salt_len);
    }
    uint8_t ipad[64], opad[64];
    for (int i = 0; i < 64; ++i) {
        ipad[i] = static_cast<uint8_t>(kk[i] ^ 0x36u);
        opad[i] = static_cast<uint8_t>(kk[i] ^ 0x5Cu);
    }
    std::vector<uint8_t> inner(64 + ikm_len);
    std::memcpy(inner.data(), ipad, 64);
    if (ikm_len > 0) std::memcpy(inner.data() + 64, ikm, ikm_len);
    uint8_t inner_h[32];
    mirror::sha256_compute(inner.data(), inner.size(), inner_h);
    uint8_t outer[96];
    std::memcpy(outer, opad, 64);
    std::memcpy(outer + 64, inner_h, 32);
    mirror::sha256_compute(outer, 96, prk);
}

inline void mirror_hkdf_expand(const uint8_t prk[32],
                                const uint8_t* info, size_t info_len,
                                uint8_t* out, size_t out_len) {
    uint8_t t[32];
    size_t t_len = 0;
    size_t produced = 0;
    uint8_t counter = 1;
    while (produced < out_len) {
        std::vector<uint8_t> buf;
        buf.reserve(t_len + info_len + 1);
        if (t_len > 0) buf.insert(buf.end(), t, t + t_len);
        if (info_len > 0) buf.insert(buf.end(), info, info + info_len);
        buf.push_back(counter);
        uint8_t kk[64];
        std::memcpy(kk, prk, 32);
        std::memset(kk + 32, 0, 32);
        uint8_t ipad[64], opad[64];
        for (int i = 0; i < 64; ++i) {
            ipad[i] = static_cast<uint8_t>(kk[i] ^ 0x36u);
            opad[i] = static_cast<uint8_t>(kk[i] ^ 0x5Cu);
        }
        std::vector<uint8_t> inner(64 + buf.size());
        std::memcpy(inner.data(), ipad, 64);
        std::memcpy(inner.data() + 64, buf.data(), buf.size());
        uint8_t inner_h[32];
        mirror::sha256_compute(inner.data(), inner.size(), inner_h);
        uint8_t outer[96];
        std::memcpy(outer, opad, 64);
        std::memcpy(outer + 64, inner_h, 32);
        mirror::sha256_compute(outer, 96, t);
        t_len = 32;
        size_t copy = (out_len - produced < 32u) ? (out_len - produced) : 32u;
        std::memcpy(out + produced, t, copy);
        produced += copy;
        ++counter;
    }
}

inline void mirror_derive_layer1_key(const uint8_t hwid[32], const uint8_t bs[32],
                                      uint32_t rva, uint32_t idx, uint8_t out[16]) {
    uint8_t ikm[64];
    std::memcpy(ikm, hwid, 32);
    std::memcpy(ikm + 32, bs, 32);
    uint8_t info[64];
    size_t pos = 0;
    info[pos++]='m'; info[pos++]='a'; info[pos++]='t'; info[pos++]='r';
    info[pos++]='y'; info[pos++]='o'; info[pos++]='s'; info[pos++]='h';
    info[pos++]='k'; info[pos++]='a'; info[pos++]='-'; info[pos++]='l';
    info[pos++]='1'; info[pos++]='-'; info[pos++]='h'; info[pos++]='w';
    info[pos++]='i'; info[pos++]='d';
    info[pos++] = static_cast<uint8_t>(rva & 0xFFu);
    info[pos++] = static_cast<uint8_t>((rva >> 8) & 0xFFu);
    info[pos++] = static_cast<uint8_t>((rva >> 16) & 0xFFu);
    info[pos++] = static_cast<uint8_t>((rva >> 24) & 0xFFu);
    info[pos++] = static_cast<uint8_t>(idx & 0xFFu);
    info[pos++] = static_cast<uint8_t>((idx >> 8) & 0xFFu);
    info[pos++] = static_cast<uint8_t>((idx >> 16) & 0xFFu);
    info[pos++] = static_cast<uint8_t>((idx >> 24) & 0xFFu);
    uint8_t prk[32];
    mirror_hkdf_extract(nullptr, 0, ikm, 64, prk);
    mirror_hkdf_expand(prk, info, pos, out, 16);
}

inline bool key_derivation_match_test() {
    std::fprintf(stdout, "[KEYDERIV] starting host vs mirror key derivation match\n");
    uint8_t master[32];
    for (int i = 0; i < 32; ++i) master[i] = static_cast<uint8_t>(i ^ 0x42u);
    uint8_t host_hwid[32], host_bs[32];
    protector::matryoshka_detail::compute_hwid_anchor(host_hwid);
    protector::matryoshka_detail::derive_build_seed_from_master(master, host_bs);
    uint8_t mirror_hwid[32], mirror_bs[32];
    mirror_compute_hwid_anchor(mirror_hwid);
    {
        uint8_t info[29];
        info[ 0]='a'; info[ 1]='i'; info[ 2]='d'; info[ 3]='a'; info[ 4]='-';
        info[ 5]='m'; info[ 6]='a'; info[ 7]='t'; info[ 8]='r'; info[ 9]='y';
        info[10]='o'; info[11]='s'; info[12]='h'; info[13]='k'; info[14]='a';
        info[15]='-'; info[16]='b'; info[17]='u'; info[18]='i'; info[19]='l';
        info[20]='d'; info[21]='-'; info[22]='s'; info[23]='e'; info[24]='e';
        info[25]='d'; info[26]='-'; info[27]='v'; info[28]='1';
        uint8_t prk[32];
        mirror_hkdf_extract(nullptr, 0, master, 32, prk);
        mirror_hkdf_expand(prk, info, 29, mirror_bs, 32);
    }
    if (std::memcmp(host_bs, mirror_bs, 32) != 0) {
        std::fprintf(stderr, "[KEYDERIV] build_seed mismatch\n");
        std::fprintf(stdout, "host:   "); hex_dump(host_bs, 32);
        std::fprintf(stdout, "mirror: "); hex_dump(mirror_bs, 32);
        return false;
    }
    uint8_t host_l1[16], mirror_l1[16];
    protector::matryoshka_detail::derive_layer1_key(host_hwid, host_bs, 0x1000u, 0u, host_l1);
    mirror_derive_layer1_key(mirror_hwid, mirror_bs, 0x1000u, 0u, mirror_l1);
    if (std::memcmp(host_l1, mirror_l1, 16) != 0) {
        std::fprintf(stderr, "[KEYDERIV] layer1 key mismatch\n");
        std::fprintf(stdout, "host:   "); hex_dump(host_l1, 16);
        std::fprintf(stdout, "mirror: "); hex_dump(mirror_l1, 16);
        return false;
    }
    std::fprintf(stdout, "[KEYDERIV] PASS host_l1=");
    hex_dump(host_l1, 16);
    return true;
}

inline bool anchor_match_test() {
    std::fprintf(stdout, "[ANCHOR] starting host vs mirror anchor KAT\n");
    uint8_t host_h[32], mirror_h[32];
    protector::matryoshka_detail::compute_hwid_anchor(host_h);
    mirror_compute_hwid_anchor(mirror_h);
    if (std::memcmp(host_h, mirror_h, 32) != 0) {
        std::fprintf(stderr, "[ANCHOR] hwid host vs mirror diverge\n");
        std::fprintf(stdout, "host:   "); hex_dump(host_h, 32);
        std::fprintf(stdout, "mirror: "); hex_dump(mirror_h, 32);
        return false;
    }
    uint8_t host_t[32], mirror_t[32];
    protector::matryoshka_detail::compute_tpm_anchor(host_t);
    mirror_compute_tpm_anchor(mirror_t);
    if (std::memcmp(host_t, mirror_t, 32) != 0) {
        std::fprintf(stderr, "[ANCHOR] tpm host vs mirror diverge\n");
        return false;
    }
    uint8_t host_s[32], mirror_s[32];
    protector::matryoshka_detail::compute_server_anchor(host_s);
    mirror_compute_server_anchor(mirror_s);
    if (std::memcmp(host_s, mirror_s, 32) != 0) {
        std::fprintf(stderr, "[ANCHOR] server host vs mirror diverge\n");
        return false;
    }
    std::fprintf(stdout, "[ANCHOR] PASS\n");
    return true;
}

inline bool sha256_kat_test() {
    std::fprintf(stdout, "[SHA256] starting host vs mirror SHA-256 KAT\n");
    std::vector<uint8_t> sample = random_bytes(2048, 0x55AA55AA55AA55AAull);
    uint8_t host_hash[32];
    uint8_t mirror_hash[32];
    protector::sha256_detail::sha256(sample.data(), sample.size(), host_hash);
    mirror::sha256_compute(sample.data(), sample.size(), mirror_hash);
    if (std::memcmp(host_hash, mirror_hash, 32) != 0) {
        std::fprintf(stderr, "[SHA256] host vs mirror disagree:\n");
        std::fprintf(stdout, "host:   ");
        hex_dump(host_hash, 32);
        std::fprintf(stdout, "mirror: ");
        hex_dump(mirror_hash, 32);
        return false;
    }
    uint8_t empty[1] = {0};
    uint8_t h1[32], h2[32];
    protector::sha256_detail::sha256(empty, 0, h1);
    mirror::sha256_compute(empty, 0, h2);
    if (std::memcmp(h1, h2, 32) != 0) {
        std::fprintf(stderr, "[SHA256] empty-input disagrees\n");
        return false;
    }
    std::fprintf(stdout, "[SHA256] PASS\n");
    return true;
}

inline bool aes128_kat_test() {
    std::fprintf(stdout, "[AES128] starting host vs mirror KAT\n");
    const size_t kSize = 128;
    auto plain = random_bytes(kSize, 0x9999999999999999ull);
    uint8_t key[16];
    for (int i = 0; i < 16; ++i) {
        key[i] = static_cast<uint8_t>(i * 11u + 3u);
    }
    uint8_t iv[16];
    for (int i = 0; i < 16; ++i) {
        iv[i] = static_cast<uint8_t>(i * 5u + 9u);
    }
    std::vector<uint8_t> host_ct(kSize);
    protector::aes_detail::aes128_ctr(key, iv, plain.data(), host_ct.data(), kSize);

    std::vector<uint8_t> mirror_ct = plain;
    mirror::aes128_ctr_xor(key, iv, mirror_ct.data(), kSize);
    if (std::memcmp(host_ct.data(), mirror_ct.data(), kSize) != 0) {
        std::fprintf(stderr, "[AES128] host vs mirror disagree\n");
        std::fprintf(stdout, "host: ");
        hex_dump(host_ct.data(), 16);
        std::fprintf(stdout, "mirror: ");
        hex_dump(mirror_ct.data(), 16);
        return false;
    }
    uint8_t zero_key[16] = { 0 };
    uint8_t zero_iv[16] = { 0 };
    uint8_t zero_in[16] = { 0 };
    uint8_t host_zero[16];
    uint8_t mirror_zero[16] = { 0 };
    protector::aes_detail::aes128_ctr(zero_key, zero_iv, zero_in, host_zero, 16);
    mirror::aes128_ctr_xor(zero_key, zero_iv, mirror_zero, 16);
    if (std::memcmp(host_zero, mirror_zero, 16) != 0) {
        std::fprintf(stderr, "[AES128] zero-key zero-iv disagree\n");
        std::fprintf(stdout, "host:   "); hex_dump(host_zero, 16);
        std::fprintf(stdout, "mirror: "); hex_dump(mirror_zero, 16);
        return false;
    }
    std::fprintf(stdout, "[AES128] zero-key zero-iv ks: ");
    hex_dump(host_zero, 16);
    std::fprintf(stdout, "[AES128] PASS bytes=%zu\n", kSize);
    return true;
}

inline bool chacha_kat_test() {
    std::fprintf(stdout, "[CC20] starting host vs mirror KAT\n");
    const size_t kSize = 200;
    auto plain = random_bytes(kSize, 0xABCDEF1234567890ull);
    uint8_t key[32];
    for (int i = 0; i < 32; ++i) {
        key[i] = static_cast<uint8_t>(i * 3u + 5u);
    }
    uint8_t nonce[12];
    for (int i = 0; i < 12; ++i) {
        nonce[i] = static_cast<uint8_t>(i * 17u + 1u);
    }
    std::vector<uint8_t> host_ct(kSize);
    protector::chacha_detail::chacha20_xor(key, nonce, plain.data(), host_ct.data(), kSize);
    std::vector<uint8_t> mirror_ct = plain;
    mirror::chacha20_xor(key, nonce, mirror_ct.data(), kSize);
    if (std::memcmp(host_ct.data(), mirror_ct.data(), kSize) != 0) {
        std::fprintf(stderr, "[CC20] host vs mirror disagree\n");
        return false;
    }
    std::fprintf(stdout, "[CC20] PASS bytes=%zu\n", kSize);
    return true;
}

int main(int argc, char** argv) {
    (void)argc;
    (void)argv;
    std::fprintf(stdout, "MATRYOSHKA_TEST_BEGIN\n");

    if (!sha256_kat_test()) {
        std::fprintf(stderr, "MATRYOSHKA_TEST_FAILED at sha256_kat_test\n");
        return 1;
    }
    if (!anchor_match_test()) {
        std::fprintf(stderr, "MATRYOSHKA_TEST_FAILED at anchor_match_test\n");
        return 1;
    }
    if (!key_derivation_match_test()) {
        std::fprintf(stderr, "MATRYOSHKA_TEST_FAILED at key_derivation_match_test\n");
        return 1;
    }
    if (!aes128_kat_test()) {
        std::fprintf(stderr, "MATRYOSHKA_TEST_FAILED at aes128_kat_test\n");
        return 1;
    }
    if (!chacha_kat_test()) {
        std::fprintf(stderr, "MATRYOSHKA_TEST_FAILED at chacha_kat_test\n");
        return 1;
    }
    if (!xtea_kat_test()) {
        std::fprintf(stderr, "MATRYOSHKA_TEST_FAILED at xtea_kat_test\n");
        return 1;
    }
    if (!kat_test()) {
        std::fprintf(stderr, "MATRYOSHKA_TEST_FAILED at kat_test\n");
        return 1;
    }
    if (!layer_isolation_test()) {
        std::fprintf(stderr, "MATRYOSHKA_TEST_FAILED at layer_isolation_test\n");
        return 1;
    }
    if (!wrong_key_test()) {
        std::fprintf(stderr, "MATRYOSHKA_TEST_FAILED at wrong_key_test\n");
        return 1;
    }
    if (!section_roundtrip_test()) {
        std::fprintf(stderr, "MATRYOSHKA_TEST_FAILED at section_roundtrip_test\n");
        return 1;
    }
    if (!legacy_compat_test()) {
        std::fprintf(stderr, "MATRYOSHKA_TEST_FAILED at legacy_compat_test\n");
        return 1;
    }

    std::fprintf(stdout, "MATRYOSHKA_TEST_PASSED\n");
    return 0;
}
