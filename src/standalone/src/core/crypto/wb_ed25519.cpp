#include "wb_ed25519.hpp"

#include "../anti-tamper/dr_check.hpp"
#include "../../helpers/diag_log.hpp"

#include <atomic>
#include <cstring>

#pragma section(".aida_v", read, execute)

namespace
{
    std::atomic<const char*> s_last_error{nullptr};

    void set_err(const char* e) noexcept
    {
        s_last_error.store(e, std::memory_order_release);
        diag::log_tagged_fmt("wb_ed25519", "error=%s", e ? e : "");
    }

    const char* current_err() noexcept
    {
        const char* e = s_last_error.load(std::memory_order_acquire);
        return e ? e : "";
    }

    using u8  = uint8_t;
    using u32 = uint32_t;
    using u64 = uint64_t;
    using i8  = int8_t;
    using i32 = int32_t;
    using i64 = int64_t;

    static __forceinline u64 rotr64(u64 x, unsigned n) noexcept
    {
        return (x >> n) | (x << (64 - n));
    }

    static __forceinline u64 fnv1a64_bytes(const u8* data, size_t len) noexcept
    {
        u64 h = 14695981039346656037ULL;
        if (!data) return h;
        for (size_t i = 0; i < len; ++i)
        {
            h ^= static_cast<u64>(data[i]);
            h *= 1099511628211ULL;
        }
        return h;
    }

    static __forceinline u64 load_be64(const u8* p) noexcept
    {
        return (static_cast<u64>(p[0]) << 56) | (static_cast<u64>(p[1]) << 48) |
               (static_cast<u64>(p[2]) << 40) | (static_cast<u64>(p[3]) << 32) |
               (static_cast<u64>(p[4]) << 24) | (static_cast<u64>(p[5]) << 16) |
               (static_cast<u64>(p[6]) << 8)  |  static_cast<u64>(p[7]);
    }

    static __forceinline void store_be64(u8* p, u64 v) noexcept
    {
        p[0] = static_cast<u8>(v >> 56);
        p[1] = static_cast<u8>(v >> 48);
        p[2] = static_cast<u8>(v >> 40);
        p[3] = static_cast<u8>(v >> 32);
        p[4] = static_cast<u8>(v >> 24);
        p[5] = static_cast<u8>(v >> 16);
        p[6] = static_cast<u8>(v >> 8);
        p[7] = static_cast<u8>(v);
    }

    struct sha512_ctx_t
    {
        u64 state[8];
        u64 bitlen;
        u8  buf[128];
        u32 buflen;
    };

    static const u64 k_sha512_k[80] = {
        0x428a2f98d728ae22ULL,0x7137449123ef65cdULL,0xb5c0fbcfec4d3b2fULL,0xe9b5dba58189dbbcULL,
        0x3956c25bf348b538ULL,0x59f111f1b605d019ULL,0x923f82a4af194f9bULL,0xab1c5ed5da6d8118ULL,
        0xd807aa98a3030242ULL,0x12835b0145706fbeULL,0x243185be4ee4b28cULL,0x550c7dc3d5ffb4e2ULL,
        0x72be5d74f27b896fULL,0x80deb1fe3b1696b1ULL,0x9bdc06a725c71235ULL,0xc19bf174cf692694ULL,
        0xe49b69c19ef14ad2ULL,0xefbe4786384f25e3ULL,0x0fc19dc68b8cd5b5ULL,0x240ca1cc77ac9c65ULL,
        0x2de92c6f592b0275ULL,0x4a7484aa6ea6e483ULL,0x5cb0a9dcbd41fbd4ULL,0x76f988da831153b5ULL,
        0x983e5152ee66dfabULL,0xa831c66d2db43210ULL,0xb00327c898fb213fULL,0xbf597fc7beef0ee4ULL,
        0xc6e00bf33da88fc2ULL,0xd5a79147930aa725ULL,0x06ca6351e003826fULL,0x142929670a0e6e70ULL,
        0x27b70a8546d22ffcULL,0x2e1b21385c26c926ULL,0x4d2c6dfc5ac42aedULL,0x53380d139d95b3dfULL,
        0x650a73548baf63deULL,0x766a0abb3c77b2a8ULL,0x81c2c92e47edaee6ULL,0x92722c851482353bULL,
        0xa2bfe8a14cf10364ULL,0xa81a664bbc423001ULL,0xc24b8b70d0f89791ULL,0xc76c51a30654be30ULL,
        0xd192e819d6ef5218ULL,0xd69906245565a910ULL,0xf40e35855771202aULL,0x106aa07032bbd1b8ULL,
        0x19a4c116b8d2d0c8ULL,0x1e376c085141ab53ULL,0x2748774cdf8eeb99ULL,0x34b0bcb5e19b48a8ULL,
        0x391c0cb3c5c95a63ULL,0x4ed8aa4ae3418acbULL,0x5b9cca4f7763e373ULL,0x682e6ff3d6b2b8a3ULL,
        0x748f82ee5defb2fcULL,0x78a5636f43172f60ULL,0x84c87814a1f0ab72ULL,0x8cc702081a6439ecULL,
        0x90befffa23631e28ULL,0xa4506cebde82bde9ULL,0xbef9a3f7b2c67915ULL,0xc67178f2e372532bULL,
        0xca273eceea26619cULL,0xd186b8c721c0c207ULL,0xeada7dd6cde0eb1eULL,0xf57d4f7fee6ed178ULL,
        0x06f067aa72176fbaULL,0x0a637dc5a2c898a6ULL,0x113f9804bef90daeULL,0x1b710b35131c471bULL,
        0x28db77f523047d84ULL,0x32caab7b40c72493ULL,0x3c9ebe0a15c9bebcULL,0x431d67c49c100d4cULL,
        0x4cc5d4becb3e42b6ULL,0x597f299cfc657e2aULL,0x5fcb6fab3ad6faecULL,0x6c44198c4a475817ULL
    };

    static __forceinline void sha512_compress(sha512_ctx_t* c, const u8* block) noexcept
    {
        u64 w[80];
        for (u32 i = 0; i < 16; ++i) w[i] = load_be64(block + i * 8);
        for (u32 i = 16; i < 80; ++i)
        {
            u64 s0 = rotr64(w[i - 15], 1) ^ rotr64(w[i - 15], 8) ^ (w[i - 15] >> 7);
            u64 s1 = rotr64(w[i - 2], 19) ^ rotr64(w[i - 2], 61) ^ (w[i - 2] >> 6);
            w[i] = w[i - 16] + s0 + w[i - 7] + s1;
        }
        u64 a = c->state[0], b = c->state[1], cc = c->state[2], d = c->state[3];
        u64 e = c->state[4], f = c->state[5], g = c->state[6], h = c->state[7];
        for (u32 i = 0; i < 80; ++i)
        {
            u64 S1 = rotr64(e, 14) ^ rotr64(e, 18) ^ rotr64(e, 41);
            u64 ch = (e & f) ^ ((~e) & g);
            u64 t1 = h + S1 + ch + k_sha512_k[i] + w[i];
            u64 S0 = rotr64(a, 28) ^ rotr64(a, 34) ^ rotr64(a, 39);
            u64 mj = (a & b) ^ (a & cc) ^ (b & cc);
            u64 t2 = S0 + mj;
            h = g; g = f; f = e; e = d + t1;
            d = cc; cc = b; b = a; a = t1 + t2;
        }
        c->state[0] += a; c->state[1] += b; c->state[2] += cc; c->state[3] += d;
        c->state[4] += e; c->state[5] += f; c->state[6] += g; c->state[7] += h;
    }

    static __forceinline void sha512_init(sha512_ctx_t* c) noexcept
    {
        c->state[0] = 0x6a09e667f3bcc908ULL;
        c->state[1] = 0xbb67ae8584caa73bULL;
        c->state[2] = 0x3c6ef372fe94f82bULL;
        c->state[3] = 0xa54ff53a5f1d36f1ULL;
        c->state[4] = 0x510e527fade682d1ULL;
        c->state[5] = 0x9b05688c2b3e6c1fULL;
        c->state[6] = 0x1f83d9abfb41bd6bULL;
        c->state[7] = 0x5be0cd19137e2179ULL;
        c->bitlen = 0;
        c->buflen = 0;
    }

    static __forceinline void sha512_update(sha512_ctx_t* c, const u8* data, size_t len) noexcept
    {
        c->bitlen += static_cast<u64>(len) * 8ULL;
        while (len > 0)
        {
            u32 take = 128u - c->buflen;
            if (take > len) take = static_cast<u32>(len);
            std::memcpy(c->buf + c->buflen, data, take);
            c->buflen += take;
            data += take;
            len  -= take;
            if (c->buflen == 128u)
            {
                sha512_compress(c, c->buf);
                c->buflen = 0;
            }
        }
    }

    static __forceinline void sha512_final(sha512_ctx_t* c, u8 out[64]) noexcept
    {
        u64 bits = c->bitlen;
        c->buf[c->buflen++] = 0x80;
        if (c->buflen > 112u)
        {
            while (c->buflen < 128u) c->buf[c->buflen++] = 0;
            sha512_compress(c, c->buf);
            c->buflen = 0;
        }
        while (c->buflen < 112u) c->buf[c->buflen++] = 0;
        for (u32 i = 0; i < 8; ++i) c->buf[112 + i] = 0;
        store_be64(c->buf + 120, bits);
        sha512_compress(c, c->buf);
        for (u32 i = 0; i < 8; ++i) store_be64(out + i * 8, c->state[i]);
    }

    static __forceinline void sha512_one_shot(const u8* d1, size_t l1,
                                              const u8* d2, size_t l2,
                                              const u8* d3, size_t l3,
                                              u8 out[64]) noexcept
    {
        sha512_ctx_t c;
        sha512_init(&c);
        if (l1) sha512_update(&c, d1, l1);
        if (l2) sha512_update(&c, d2, l2);
        if (l3) sha512_update(&c, d3, l3);
        sha512_final(&c, out);
    }

    using fe_t = i32[10];

    static __forceinline void fe_0(fe_t h) noexcept
    {
        for (i32 i = 0; i < 10; ++i) h[i] = 0;
    }

    static __forceinline void fe_1(fe_t h) noexcept
    {
        h[0] = 1;
        for (i32 i = 1; i < 10; ++i) h[i] = 0;
    }

    static __forceinline void fe_copy(fe_t h, const fe_t f) noexcept
    {
        for (i32 i = 0; i < 10; ++i) h[i] = f[i];
    }

    static __forceinline void fe_add(fe_t h, const fe_t f, const fe_t g) noexcept
    {
        for (i32 i = 0; i < 10; ++i) h[i] = f[i] + g[i];
    }

    static __forceinline void fe_sub(fe_t h, const fe_t f, const fe_t g) noexcept
    {
        for (i32 i = 0; i < 10; ++i) h[i] = f[i] - g[i];
    }

    static __forceinline void fe_neg(fe_t h, const fe_t f) noexcept
    {
        for (i32 i = 0; i < 10; ++i) h[i] = -f[i];
    }

    static __forceinline void fe_cmov(fe_t f, const fe_t g, u32 b) noexcept
    {
        u32 mask = static_cast<u32>(-static_cast<i32>(b));
        for (i32 i = 0; i < 10; ++i)
        {
            u32 x = static_cast<u32>(f[i] ^ g[i]) & mask;
            f[i] = static_cast<i32>(static_cast<u32>(f[i]) ^ x);
        }
    }

    static __forceinline u64 load_3(const u8* in) noexcept
    {
        u64 r = static_cast<u64>(in[0]);
        r |= static_cast<u64>(in[1]) << 8;
        r |= static_cast<u64>(in[2]) << 16;
        return r;
    }

    static __forceinline u64 load_4(const u8* in) noexcept
    {
        u64 r = static_cast<u64>(in[0]);
        r |= static_cast<u64>(in[1]) << 8;
        r |= static_cast<u64>(in[2]) << 16;
        r |= static_cast<u64>(in[3]) << 24;
        return r;
    }

    static __forceinline void fe_frombytes(fe_t h, const u8 s[32]) noexcept
    {
        i64 h0 = static_cast<i64>(load_4(s));
        i64 h1 = static_cast<i64>(load_3(s + 4)) << 6;
        i64 h2 = static_cast<i64>(load_3(s + 7)) << 5;
        i64 h3 = static_cast<i64>(load_3(s + 10)) << 3;
        i64 h4 = static_cast<i64>(load_3(s + 13)) << 2;
        i64 h5 = static_cast<i64>(load_4(s + 16));
        i64 h6 = static_cast<i64>(load_3(s + 20)) << 7;
        i64 h7 = static_cast<i64>(load_3(s + 23)) << 5;
        i64 h8 = static_cast<i64>(load_3(s + 26)) << 4;
        i64 h9 = static_cast<i64>(load_3(s + 29) & 0x7FFFFFu) << 2;

        i64 c9 = (h9 + (1LL << 24)) >> 25; h0 += c9 * 19; h9 -= c9 << 25;
        i64 c1 = (h1 + (1LL << 24)) >> 25; h2 += c1; h1 -= c1 << 25;
        i64 c3 = (h3 + (1LL << 24)) >> 25; h4 += c3; h3 -= c3 << 25;
        i64 c5 = (h5 + (1LL << 24)) >> 25; h6 += c5; h5 -= c5 << 25;
        i64 c7 = (h7 + (1LL << 24)) >> 25; h8 += c7; h7 -= c7 << 25;

        i64 c0 = (h0 + (1LL << 25)) >> 26; h1 += c0; h0 -= c0 << 26;
        i64 c2 = (h2 + (1LL << 25)) >> 26; h3 += c2; h2 -= c2 << 26;
        i64 c4 = (h4 + (1LL << 25)) >> 26; h5 += c4; h4 -= c4 << 26;
        i64 c6 = (h6 + (1LL << 25)) >> 26; h7 += c6; h6 -= c6 << 26;
        i64 c8 = (h8 + (1LL << 25)) >> 26; h9 += c8; h8 -= c8 << 26;

        h[0] = static_cast<i32>(h0); h[1] = static_cast<i32>(h1);
        h[2] = static_cast<i32>(h2); h[3] = static_cast<i32>(h3);
        h[4] = static_cast<i32>(h4); h[5] = static_cast<i32>(h5);
        h[6] = static_cast<i32>(h6); h[7] = static_cast<i32>(h7);
        h[8] = static_cast<i32>(h8); h[9] = static_cast<i32>(h9);
    }

    static __forceinline void fe_tobytes(u8 s[32], const fe_t h_in) noexcept
    {
        i32 h[10];
        for (i32 i = 0; i < 10; ++i) h[i] = h_in[i];

        i32 q = (19 * h[9] + (1 << 24)) >> 25;
        q = (h[0] + q) >> 26;
        q = (h[1] + q) >> 25;
        q = (h[2] + q) >> 26;
        q = (h[3] + q) >> 25;
        q = (h[4] + q) >> 26;
        q = (h[5] + q) >> 25;
        q = (h[6] + q) >> 26;
        q = (h[7] + q) >> 25;
        q = (h[8] + q) >> 26;
        q = (h[9] + q) >> 25;

        h[0] += 19 * q;

        i32 c0 = h[0] >> 26; h[1] += c0; h[0] -= c0 << 26;
        i32 c1 = h[1] >> 25; h[2] += c1; h[1] -= c1 << 25;
        i32 c2 = h[2] >> 26; h[3] += c2; h[2] -= c2 << 26;
        i32 c3 = h[3] >> 25; h[4] += c3; h[3] -= c3 << 25;
        i32 c4 = h[4] >> 26; h[5] += c4; h[4] -= c4 << 26;
        i32 c5 = h[5] >> 25; h[6] += c5; h[5] -= c5 << 25;
        i32 c6 = h[6] >> 26; h[7] += c6; h[6] -= c6 << 26;
        i32 c7 = h[7] >> 25; h[8] += c7; h[7] -= c7 << 25;
        i32 c8 = h[8] >> 26; h[9] += c8; h[8] -= c8 << 26;
        i32 c9 = h[9] >> 25; h[9] -= c9 << 25;

        s[0]  = static_cast<u8>(h[0] >> 0);
        s[1]  = static_cast<u8>(h[0] >> 8);
        s[2]  = static_cast<u8>(h[0] >> 16);
        s[3]  = static_cast<u8>((h[0] >> 24) | (h[1] << 2));
        s[4]  = static_cast<u8>(h[1] >> 6);
        s[5]  = static_cast<u8>(h[1] >> 14);
        s[6]  = static_cast<u8>((h[1] >> 22) | (h[2] << 3));
        s[7]  = static_cast<u8>(h[2] >> 5);
        s[8]  = static_cast<u8>(h[2] >> 13);
        s[9]  = static_cast<u8>((h[2] >> 21) | (h[3] << 5));
        s[10] = static_cast<u8>(h[3] >> 3);
        s[11] = static_cast<u8>(h[3] >> 11);
        s[12] = static_cast<u8>((h[3] >> 19) | (h[4] << 6));
        s[13] = static_cast<u8>(h[4] >> 2);
        s[14] = static_cast<u8>(h[4] >> 10);
        s[15] = static_cast<u8>(h[4] >> 18);
        s[16] = static_cast<u8>(h[5] >> 0);
        s[17] = static_cast<u8>(h[5] >> 8);
        s[18] = static_cast<u8>(h[5] >> 16);
        s[19] = static_cast<u8>((h[5] >> 24) | (h[6] << 1));
        s[20] = static_cast<u8>(h[6] >> 7);
        s[21] = static_cast<u8>(h[6] >> 15);
        s[22] = static_cast<u8>((h[6] >> 23) | (h[7] << 3));
        s[23] = static_cast<u8>(h[7] >> 5);
        s[24] = static_cast<u8>(h[7] >> 13);
        s[25] = static_cast<u8>((h[7] >> 21) | (h[8] << 4));
        s[26] = static_cast<u8>(h[8] >> 4);
        s[27] = static_cast<u8>(h[8] >> 12);
        s[28] = static_cast<u8>((h[8] >> 20) | (h[9] << 6));
        s[29] = static_cast<u8>(h[9] >> 2);
        s[30] = static_cast<u8>(h[9] >> 10);
        s[31] = static_cast<u8>(h[9] >> 18);
    }

    static __forceinline i32 fe_isnegative(const fe_t f) noexcept
    {
        u8 s[32];
        fe_tobytes(s, f);
        return s[0] & 1;
    }

    static __forceinline i32 fe_isnonzero(const fe_t f) noexcept
    {
        u8 s[32];
        fe_tobytes(s, f);
        u8 r = 0;
        for (i32 i = 0; i < 32; ++i) r |= s[i];
        return r;
    }

    static __forceinline void fe_mul(fe_t h, const fe_t f, const fe_t g) noexcept
    {
        i64 f0 = f[0], f1 = f[1], f2 = f[2], f3 = f[3], f4 = f[4];
        i64 f5 = f[5], f6 = f[6], f7 = f[7], f8 = f[8], f9 = f[9];
        i64 g0 = g[0], g1 = g[1], g2 = g[2], g3 = g[3], g4 = g[4];
        i64 g5 = g[5], g6 = g[6], g7 = g[7], g8 = g[8], g9 = g[9];

        i64 g1_19 = 19 * g1, g2_19 = 19 * g2, g3_19 = 19 * g3, g4_19 = 19 * g4;
        i64 g5_19 = 19 * g5, g6_19 = 19 * g6, g7_19 = 19 * g7, g8_19 = 19 * g8, g9_19 = 19 * g9;
        i64 f1_2 = 2 * f1, f3_2 = 2 * f3, f5_2 = 2 * f5, f7_2 = 2 * f7, f9_2 = 2 * f9;

        i64 h0 = f0*g0 + f1_2*g9_19 + f2*g8_19 + f3_2*g7_19 + f4*g6_19 + f5_2*g5_19 + f6*g4_19 + f7_2*g3_19 + f8*g2_19 + f9_2*g1_19;
        i64 h1 = f0*g1 + f1*g0     + f2*g9_19 + f3*g8_19   + f4*g7_19 + f5*g6_19   + f6*g5_19 + f7*g4_19   + f8*g3_19 + f9*g2_19;
        i64 h2 = f0*g2 + f1_2*g1   + f2*g0    + f3_2*g9_19 + f4*g8_19 + f5_2*g7_19 + f6*g6_19 + f7_2*g5_19 + f8*g4_19 + f9_2*g3_19;
        i64 h3 = f0*g3 + f1*g2     + f2*g1    + f3*g0      + f4*g9_19 + f5*g8_19   + f6*g7_19 + f7*g6_19   + f8*g5_19 + f9*g4_19;
        i64 h4 = f0*g4 + f1_2*g3   + f2*g2    + f3_2*g1    + f4*g0    + f5_2*g9_19 + f6*g8_19 + f7_2*g7_19 + f8*g6_19 + f9_2*g5_19;
        i64 h5 = f0*g5 + f1*g4     + f2*g3    + f3*g2      + f4*g1    + f5*g0      + f6*g9_19 + f7*g8_19   + f8*g7_19 + f9*g6_19;
        i64 h6 = f0*g6 + f1_2*g5   + f2*g4    + f3_2*g3    + f4*g2    + f5_2*g1    + f6*g0    + f7_2*g9_19 + f8*g8_19 + f9_2*g7_19;
        i64 h7 = f0*g7 + f1*g6     + f2*g5    + f3*g4      + f4*g3    + f5*g2      + f6*g1    + f7*g0      + f8*g9_19 + f9*g8_19;
        i64 h8 = f0*g8 + f1_2*g7   + f2*g6    + f3_2*g5    + f4*g4    + f5_2*g3    + f6*g2    + f7_2*g1    + f8*g0    + f9_2*g9_19;
        i64 h9 = f0*g9 + f1*g8     + f2*g7    + f3*g6      + f4*g5    + f5*g4      + f6*g3    + f7*g2      + f8*g1    + f9*g0;

        i64 c0 = (h0 + (1LL << 25)) >> 26; h1 += c0; h0 -= c0 << 26;
        i64 c4 = (h4 + (1LL << 25)) >> 26; h5 += c4; h4 -= c4 << 26;
        i64 c1 = (h1 + (1LL << 24)) >> 25; h2 += c1; h1 -= c1 << 25;
        i64 c5 = (h5 + (1LL << 24)) >> 25; h6 += c5; h5 -= c5 << 25;
        i64 c2 = (h2 + (1LL << 25)) >> 26; h3 += c2; h2 -= c2 << 26;
        i64 c6 = (h6 + (1LL << 25)) >> 26; h7 += c6; h6 -= c6 << 26;
        i64 c3 = (h3 + (1LL << 24)) >> 25; h4 += c3; h3 -= c3 << 25;
        i64 c7 = (h7 + (1LL << 24)) >> 25; h8 += c7; h7 -= c7 << 25;
        i64 c4b= (h4 + (1LL << 25)) >> 26; h5 += c4b; h4 -= c4b << 26;
        i64 c8 = (h8 + (1LL << 25)) >> 26; h9 += c8; h8 -= c8 << 26;
        i64 c9 = (h9 + (1LL << 24)) >> 25; h0 += c9 * 19; h9 -= c9 << 25;
        i64 c0b= (h0 + (1LL << 25)) >> 26; h1 += c0b; h0 -= c0b << 26;

        h[0] = static_cast<i32>(h0); h[1] = static_cast<i32>(h1);
        h[2] = static_cast<i32>(h2); h[3] = static_cast<i32>(h3);
        h[4] = static_cast<i32>(h4); h[5] = static_cast<i32>(h5);
        h[6] = static_cast<i32>(h6); h[7] = static_cast<i32>(h7);
        h[8] = static_cast<i32>(h8); h[9] = static_cast<i32>(h9);
    }

    static __forceinline void fe_sq(fe_t h, const fe_t f) noexcept
    {
        i64 f0 = f[0], f1 = f[1], f2 = f[2], f3 = f[3], f4 = f[4];
        i64 f5 = f[5], f6 = f[6], f7 = f[7], f8 = f[8], f9 = f[9];

        i64 f0_2 = 2*f0, f1_2 = 2*f1, f2_2 = 2*f2, f3_2 = 2*f3, f4_2 = 2*f4;
        i64 f5_2 = 2*f5, f6_2 = 2*f6, f7_2 = 2*f7;
        i64 f5_38 = 38*f5, f6_19 = 19*f6, f7_38 = 38*f7, f8_19 = 19*f8, f9_38 = 38*f9;

        i64 h0 = f0*f0 + f1_2*f9_38 + f2_2*f8_19 + f3_2*f7_38 + f4_2*f6_19 + f5*f5_38;
        i64 h1 = f0_2*f1 + f2*f9_38 + f3_2*f8_19 + f4*f7_38 + f5_2*f6_19;
        i64 h2 = f0_2*f2 + f1_2*f1 + f3_2*f9_38 + f4_2*f8_19 + f5_2*f7_38 + f6*f6_19;
        i64 h3 = f0_2*f3 + f1_2*f2 + f4*f9_38 + f5_2*f8_19 + f6*f7_38;
        i64 h4 = f0_2*f4 + f1_2*f3_2 + f2*f2 + f5_2*f9_38 + f6_2*f8_19 + f7*f7_38;
        i64 h5 = f0_2*f5 + f1_2*f4 + f2_2*f3 + f6*f9_38 + f7_2*f8_19;
        i64 h6 = f0_2*f6 + f1_2*f5_2 + f2_2*f4 + f3_2*f3 + f7_2*f9_38 + f8*f8_19;
        i64 h7 = f0_2*f7 + f1_2*f6 + f2_2*f5 + f3_2*f4 + f8*f9_38;
        i64 h8 = f0_2*f8 + f1_2*f7_2 + f2_2*f6 + f3_2*f5_2 + f4*f4 + f9*f9_38;
        i64 h9 = f0_2*f9 + f1_2*f8 + f2_2*f7 + f3_2*f6 + f4_2*f5;

        i64 c0 = (h0 + (1LL << 25)) >> 26; h1 += c0; h0 -= c0 << 26;
        i64 c4 = (h4 + (1LL << 25)) >> 26; h5 += c4; h4 -= c4 << 26;
        i64 c1 = (h1 + (1LL << 24)) >> 25; h2 += c1; h1 -= c1 << 25;
        i64 c5 = (h5 + (1LL << 24)) >> 25; h6 += c5; h5 -= c5 << 25;
        i64 c2 = (h2 + (1LL << 25)) >> 26; h3 += c2; h2 -= c2 << 26;
        i64 c6 = (h6 + (1LL << 25)) >> 26; h7 += c6; h6 -= c6 << 26;
        i64 c3 = (h3 + (1LL << 24)) >> 25; h4 += c3; h3 -= c3 << 25;
        i64 c7 = (h7 + (1LL << 24)) >> 25; h8 += c7; h7 -= c7 << 25;
        i64 c4b= (h4 + (1LL << 25)) >> 26; h5 += c4b; h4 -= c4b << 26;
        i64 c8 = (h8 + (1LL << 25)) >> 26; h9 += c8; h8 -= c8 << 26;
        i64 c9 = (h9 + (1LL << 24)) >> 25; h0 += c9 * 19; h9 -= c9 << 25;
        i64 c0b= (h0 + (1LL << 25)) >> 26; h1 += c0b; h0 -= c0b << 26;

        h[0] = static_cast<i32>(h0); h[1] = static_cast<i32>(h1);
        h[2] = static_cast<i32>(h2); h[3] = static_cast<i32>(h3);
        h[4] = static_cast<i32>(h4); h[5] = static_cast<i32>(h5);
        h[6] = static_cast<i32>(h6); h[7] = static_cast<i32>(h7);
        h[8] = static_cast<i32>(h8); h[9] = static_cast<i32>(h9);
    }

    static __forceinline void fe_sq2(fe_t h, const fe_t f) noexcept
    {
        fe_sq(h, f);
        for (i32 i = 0; i < 10; ++i) h[i] += h[i];
    }

    static __forceinline void fe_pow22523(fe_t out, const fe_t z) noexcept
    {
        fe_t t0, t1, t2;
        fe_sq(t0, z);
        for (i32 i = 1; i < 1; ++i) fe_sq(t0, t0);
        fe_sq(t1, t0); for (i32 i = 1; i < 2; ++i) fe_sq(t1, t1);
        fe_mul(t1, z, t1);
        fe_mul(t0, t0, t1);
        fe_sq(t0, t0);
        for (i32 i = 1; i < 1; ++i) fe_sq(t0, t0);
        fe_mul(t0, t1, t0);
        fe_sq(t1, t0); for (i32 i = 1; i < 5; ++i) fe_sq(t1, t1);
        fe_mul(t0, t1, t0);
        fe_sq(t1, t0); for (i32 i = 1; i < 10; ++i) fe_sq(t1, t1);
        fe_mul(t1, t1, t0);
        fe_sq(t2, t1); for (i32 i = 1; i < 20; ++i) fe_sq(t2, t2);
        fe_mul(t1, t2, t1);
        fe_sq(t1, t1); for (i32 i = 1; i < 10; ++i) fe_sq(t1, t1);
        fe_mul(t0, t1, t0);
        fe_sq(t1, t0); for (i32 i = 1; i < 50; ++i) fe_sq(t1, t1);
        fe_mul(t1, t1, t0);
        fe_sq(t2, t1); for (i32 i = 1; i < 100; ++i) fe_sq(t2, t2);
        fe_mul(t1, t2, t1);
        fe_sq(t1, t1); for (i32 i = 1; i < 50; ++i) fe_sq(t1, t1);
        fe_mul(t0, t1, t0);
        fe_sq(t0, t0); for (i32 i = 1; i < 2; ++i) fe_sq(t0, t0);
        fe_mul(out, t0, z);
    }

    static __forceinline void fe_invert(fe_t out, const fe_t z) noexcept
    {
        fe_t t0, t1, t2, t3;
        fe_sq(t0, z);
        fe_sq(t1, t0); fe_sq(t1, t1);
        fe_mul(t1, z, t1);
        fe_mul(t0, t0, t1);
        fe_sq(t2, t0);
        fe_mul(t1, t1, t2);
        fe_sq(t2, t1); for (i32 i = 1; i < 5; ++i) fe_sq(t2, t2);
        fe_mul(t1, t2, t1);
        fe_sq(t2, t1); for (i32 i = 1; i < 10; ++i) fe_sq(t2, t2);
        fe_mul(t2, t2, t1);
        fe_sq(t3, t2); for (i32 i = 1; i < 20; ++i) fe_sq(t3, t3);
        fe_mul(t2, t3, t2);
        fe_sq(t2, t2); for (i32 i = 1; i < 10; ++i) fe_sq(t2, t2);
        fe_mul(t1, t2, t1);
        fe_sq(t2, t1); for (i32 i = 1; i < 50; ++i) fe_sq(t2, t2);
        fe_mul(t2, t2, t1);
        fe_sq(t3, t2); for (i32 i = 1; i < 100; ++i) fe_sq(t3, t3);
        fe_mul(t2, t3, t2);
        fe_sq(t2, t2); for (i32 i = 1; i < 50; ++i) fe_sq(t2, t2);
        fe_mul(t1, t2, t1);
        fe_sq(t1, t1); for (i32 i = 1; i < 5; ++i) fe_sq(t1, t1);
        fe_mul(out, t1, t0);
    }

    struct ge_p2_t  { fe_t X, Y, Z; };
    struct ge_p3_t  { fe_t X, Y, Z, T; };
    struct ge_p1p1_t{ fe_t X, Y, Z, T; };
    struct ge_precomp_t  { fe_t yplusx, yminusx, xy2d; };
    struct ge_cached_t   { fe_t YplusX, YminusX, Z, T2d; };

    static const u8 k_d_bytes[32] = {
        0xa3,0x78,0x59,0x13,0xca,0x4d,0xeb,0x75,
        0xab,0xd8,0x41,0x41,0x4d,0x0a,0x70,0x00,
        0x98,0xe8,0x79,0x77,0x79,0x40,0xc7,0x8c,
        0x73,0xfe,0x6f,0x2b,0xee,0x6c,0x03,0x52
    };
    static const u8 k_sqrtm1_bytes[32] = {
        0xb0,0xa0,0x0e,0x4a,0x27,0x1b,0xee,0xc4,
        0x78,0xe4,0x2f,0xad,0x06,0x18,0x43,0x2f,
        0xa7,0xd7,0xfb,0x3d,0x99,0x00,0x4d,0x2b,
        0x0b,0xdf,0xc1,0x4f,0x80,0x24,0x83,0x2b
    };

    static __forceinline void ge_p3_0(ge_p3_t* h) noexcept
    {
        fe_0(h->X); fe_1(h->Y); fe_1(h->Z); fe_0(h->T);
    }

    static __forceinline void ge_p2_0(ge_p2_t* h) noexcept
    {
        fe_0(h->X); fe_1(h->Y); fe_1(h->Z);
    }

    static __forceinline void ge_p3_to_p2(ge_p2_t* r, const ge_p3_t* p) noexcept
    {
        fe_copy(r->X, p->X); fe_copy(r->Y, p->Y); fe_copy(r->Z, p->Z);
    }

    static __forceinline void ge_p3_tobytes(u8 s[32], const ge_p3_t* h) noexcept
    {
        fe_t recip, x, y;
        fe_invert(recip, h->Z);
        fe_mul(x, h->X, recip);
        fe_mul(y, h->Y, recip);
        fe_tobytes(s, y);
        s[31] ^= static_cast<u8>(fe_isnegative(x) << 7);
    }

    static __forceinline void ge_p2_tobytes(u8 s[32], const ge_p2_t* h) noexcept
    {
        fe_t recip, x, y;
        fe_invert(recip, h->Z);
        fe_mul(x, h->X, recip);
        fe_mul(y, h->Y, recip);
        fe_tobytes(s, y);
        s[31] ^= static_cast<u8>(fe_isnegative(x) << 7);
    }

    static __forceinline void ge_p1p1_to_p2(ge_p2_t* r, const ge_p1p1_t* p) noexcept
    {
        fe_mul(r->X, p->X, p->T);
        fe_mul(r->Y, p->Y, p->Z);
        fe_mul(r->Z, p->Z, p->T);
    }

    static __forceinline void ge_p1p1_to_p3(ge_p3_t* r, const ge_p1p1_t* p) noexcept
    {
        fe_mul(r->X, p->X, p->T);
        fe_mul(r->Y, p->Y, p->Z);
        fe_mul(r->Z, p->Z, p->T);
        fe_mul(r->T, p->X, p->Y);
    }

    static __forceinline void ge_p3_to_cached(ge_cached_t* r, const ge_p3_t* p) noexcept
    {
        static const u8 k_d2_bytes[32] = {
            0x59,0xf1,0xb2,0x26,0x94,0x9b,0xd6,0xeb,
            0x56,0xb1,0x83,0x82,0x9a,0x14,0xe0,0x00,
            0x30,0xd1,0xf3,0xee,0xf2,0x80,0x8e,0x19,
            0xe7,0xfc,0xdf,0x56,0xdc,0xd9,0x06,0x24
        };
        fe_t d2;
        fe_frombytes(d2, k_d2_bytes);
        fe_add(r->YplusX,  p->Y, p->X);
        fe_sub(r->YminusX, p->Y, p->X);
        fe_copy(r->Z, p->Z);
        fe_mul(r->T2d, p->T, d2);
    }

    static __forceinline void ge_p2_dbl(ge_p1p1_t* r, const ge_p2_t* p) noexcept
    {
        fe_t t0;
        fe_sq(r->X, p->X);
        fe_sq(r->Z, p->Y);
        fe_sq2(r->T, p->Z);
        fe_add(r->Y, p->X, p->Y);
        fe_sq(t0, r->Y);
        fe_add(r->Y, r->Z, r->X);
        fe_sub(r->Z, r->Z, r->X);
        fe_sub(r->X, t0, r->Y);
        fe_sub(r->T, r->T, r->Z);
    }

    static __forceinline void ge_p3_dbl(ge_p1p1_t* r, const ge_p3_t* p) noexcept
    {
        ge_p2_t q; ge_p3_to_p2(&q, p);
        ge_p2_dbl(r, &q);
    }

    static __forceinline void ge_add(ge_p1p1_t* r, const ge_p3_t* p, const ge_cached_t* q) noexcept
    {
        fe_t t0;
        fe_add(r->X, p->Y, p->X);
        fe_sub(r->Y, p->Y, p->X);
        fe_mul(r->Z, r->X, q->YplusX);
        fe_mul(r->Y, r->Y, q->YminusX);
        fe_mul(r->T, q->T2d, p->T);
        fe_mul(r->X, p->Z, q->Z);
        fe_add(t0, r->X, r->X);
        fe_sub(r->X, r->Z, r->Y);
        fe_add(r->Y, r->Z, r->Y);
        fe_add(r->Z, t0, r->T);
        fe_sub(r->T, t0, r->T);
    }

    static __forceinline void ge_sub(ge_p1p1_t* r, const ge_p3_t* p, const ge_cached_t* q) noexcept
    {
        fe_t t0;
        fe_add(r->X, p->Y, p->X);
        fe_sub(r->Y, p->Y, p->X);
        fe_mul(r->Z, r->X, q->YminusX);
        fe_mul(r->Y, r->Y, q->YplusX);
        fe_mul(r->T, q->T2d, p->T);
        fe_mul(r->X, p->Z, q->Z);
        fe_add(t0, r->X, r->X);
        fe_sub(r->X, r->Z, r->Y);
        fe_add(r->Y, r->Z, r->Y);
        fe_sub(r->Z, t0, r->T);
        fe_add(r->T, t0, r->T);
    }

    static __forceinline bool ge_frombytes_negate_vartime(ge_p3_t* h, const u8 s[32]) noexcept
    {
        fe_t u, v, v3, vxx, check, d_fe, sqrtm1;
        fe_frombytes(h->Y, s);
        fe_1(h->Z);
        fe_sq(u, h->Y);
        fe_frombytes(d_fe, k_d_bytes);
        fe_mul(v, u, d_fe);
        fe_sub(u, u, h->Z);
        fe_add(v, v, h->Z);

        fe_sq(v3, v);
        fe_mul(v3, v3, v);
        fe_sq(h->X, v3);
        fe_mul(h->X, h->X, v);
        fe_mul(h->X, h->X, u);

        fe_pow22523(h->X, h->X);
        fe_mul(h->X, h->X, v3);
        fe_mul(h->X, h->X, u);

        fe_sq(vxx, h->X);
        fe_mul(vxx, vxx, v);
        fe_sub(check, vxx, u);
        if (fe_isnonzero(check))
        {
            fe_add(check, vxx, u);
            if (fe_isnonzero(check)) return false;
            fe_frombytes(sqrtm1, k_sqrtm1_bytes);
            fe_mul(h->X, h->X, sqrtm1);
        }

        if (fe_isnegative(h->X) == ((s[31] >> 7) & 1))
        {
            fe_neg(h->X, h->X);
        }
        fe_mul(h->T, h->X, h->Y);
        return true;
    }

    static __forceinline void sc_reduce(u8 s[64]) noexcept
    {
        i64 s0  = 2097151 & static_cast<i64>(load_3(s));
        i64 s1  = 2097151 & static_cast<i64>(load_4(s + 2) >> 5);
        i64 s2  = 2097151 & static_cast<i64>(load_3(s + 5) >> 2);
        i64 s3  = 2097151 & static_cast<i64>(load_4(s + 7) >> 7);
        i64 s4  = 2097151 & static_cast<i64>(load_4(s + 10) >> 4);
        i64 s5  = 2097151 & static_cast<i64>(load_3(s + 13) >> 1);
        i64 s6  = 2097151 & static_cast<i64>(load_4(s + 15) >> 6);
        i64 s7  = 2097151 & static_cast<i64>(load_3(s + 18) >> 3);
        i64 s8  = 2097151 & static_cast<i64>(load_3(s + 21));
        i64 s9  = 2097151 & static_cast<i64>(load_4(s + 23) >> 5);
        i64 s10 = 2097151 & static_cast<i64>(load_3(s + 26) >> 2);
        i64 s11 = 2097151 & static_cast<i64>(load_4(s + 28) >> 7);
        i64 s12 = 2097151 & static_cast<i64>(load_4(s + 31) >> 4);
        i64 s13 = 2097151 & static_cast<i64>(load_3(s + 34) >> 1);
        i64 s14 = 2097151 & static_cast<i64>(load_4(s + 36) >> 6);
        i64 s15 = 2097151 & static_cast<i64>(load_3(s + 39) >> 3);
        i64 s16 = 2097151 & static_cast<i64>(load_3(s + 42));
        i64 s17 = 2097151 & static_cast<i64>(load_4(s + 44) >> 5);
        i64 s18 = 2097151 & static_cast<i64>(load_3(s + 47) >> 2);
        i64 s19 = 2097151 & static_cast<i64>(load_4(s + 49) >> 7);
        i64 s20 = 2097151 & static_cast<i64>(load_4(s + 52) >> 4);
        i64 s21 = 2097151 & static_cast<i64>(load_3(s + 55) >> 1);
        i64 s22 = 2097151 & static_cast<i64>(load_4(s + 57) >> 6);
        i64 s23 = static_cast<i64>(load_4(s + 60) >> 3);

        i64 carry[17];

        s11 += s23 * 666643;
        s12 += s23 * 470296;
        s13 += s23 * 654183;
        s14 -= s23 * 997805;
        s15 += s23 * 136657;
        s16 -= s23 * 683901;

        s10 += s22 * 666643;
        s11 += s22 * 470296;
        s12 += s22 * 654183;
        s13 -= s22 * 997805;
        s14 += s22 * 136657;
        s15 -= s22 * 683901;

        s9  += s21 * 666643;
        s10 += s21 * 470296;
        s11 += s21 * 654183;
        s12 -= s21 * 997805;
        s13 += s21 * 136657;
        s14 -= s21 * 683901;

        s8  += s20 * 666643;
        s9  += s20 * 470296;
        s10 += s20 * 654183;
        s11 -= s20 * 997805;
        s12 += s20 * 136657;
        s13 -= s20 * 683901;

        s7  += s19 * 666643;
        s8  += s19 * 470296;
        s9  += s19 * 654183;
        s10 -= s19 * 997805;
        s11 += s19 * 136657;
        s12 -= s19 * 683901;

        s6  += s18 * 666643;
        s7  += s18 * 470296;
        s8  += s18 * 654183;
        s9  -= s18 * 997805;
        s10 += s18 * 136657;
        s11 -= s18 * 683901;

        carry[6]  = (s6 + (1LL << 20)) >> 21; s7 += carry[6]; s6 -= carry[6] << 21;
        carry[8]  = (s8 + (1LL << 20)) >> 21; s9 += carry[8]; s8 -= carry[8] << 21;
        carry[10] = (s10 + (1LL << 20)) >> 21; s11 += carry[10]; s10 -= carry[10] << 21;
        carry[12] = (s12 + (1LL << 20)) >> 21; s13 += carry[12]; s12 -= carry[12] << 21;
        carry[14] = (s14 + (1LL << 20)) >> 21; s15 += carry[14]; s14 -= carry[14] << 21;
        carry[16] = (s16 + (1LL << 20)) >> 21; s17 += carry[16]; s16 -= carry[16] << 21;

        carry[7]  = (s7 + (1LL << 20)) >> 21; s8 += carry[7]; s7 -= carry[7] << 21;
        carry[9]  = (s9 + (1LL << 20)) >> 21; s10 += carry[9]; s9 -= carry[9] << 21;
        carry[11] = (s11 + (1LL << 20)) >> 21; s12 += carry[11]; s11 -= carry[11] << 21;
        carry[13] = (s13 + (1LL << 20)) >> 21; s14 += carry[13]; s13 -= carry[13] << 21;
        carry[15] = (s15 + (1LL << 20)) >> 21; s16 += carry[15]; s15 -= carry[15] << 21;

        s5  += s17 * 666643;
        s6  += s17 * 470296;
        s7  += s17 * 654183;
        s8  -= s17 * 997805;
        s9  += s17 * 136657;
        s10 -= s17 * 683901;

        s4  += s16 * 666643;
        s5  += s16 * 470296;
        s6  += s16 * 654183;
        s7  -= s16 * 997805;
        s8  += s16 * 136657;
        s9  -= s16 * 683901;

        s3  += s15 * 666643;
        s4  += s15 * 470296;
        s5  += s15 * 654183;
        s6  -= s15 * 997805;
        s7  += s15 * 136657;
        s8  -= s15 * 683901;

        s2  += s14 * 666643;
        s3  += s14 * 470296;
        s4  += s14 * 654183;
        s5  -= s14 * 997805;
        s6  += s14 * 136657;
        s7  -= s14 * 683901;

        s1  += s13 * 666643;
        s2  += s13 * 470296;
        s3  += s13 * 654183;
        s4  -= s13 * 997805;
        s5  += s13 * 136657;
        s6  -= s13 * 683901;

        s0  += s12 * 666643;
        s1  += s12 * 470296;
        s2  += s12 * 654183;
        s3  -= s12 * 997805;
        s4  += s12 * 136657;
        s5  -= s12 * 683901;
        s12 = 0;

        carry[0]  = (s0 + (1LL << 20)) >> 21; s1 += carry[0]; s0 -= carry[0] << 21;
        carry[2]  = (s2 + (1LL << 20)) >> 21; s3 += carry[2]; s2 -= carry[2] << 21;
        carry[4]  = (s4 + (1LL << 20)) >> 21; s5 += carry[4]; s4 -= carry[4] << 21;
        carry[6]  = (s6 + (1LL << 20)) >> 21; s7 += carry[6]; s6 -= carry[6] << 21;
        carry[8]  = (s8 + (1LL << 20)) >> 21; s9 += carry[8]; s8 -= carry[8] << 21;
        carry[10] = (s10 + (1LL << 20)) >> 21; s11 += carry[10]; s10 -= carry[10] << 21;

        carry[1]  = (s1 + (1LL << 20)) >> 21; s2 += carry[1]; s1 -= carry[1] << 21;
        carry[3]  = (s3 + (1LL << 20)) >> 21; s4 += carry[3]; s3 -= carry[3] << 21;
        carry[5]  = (s5 + (1LL << 20)) >> 21; s6 += carry[5]; s5 -= carry[5] << 21;
        carry[7]  = (s7 + (1LL << 20)) >> 21; s8 += carry[7]; s7 -= carry[7] << 21;
        carry[9]  = (s9 + (1LL << 20)) >> 21; s10 += carry[9]; s9 -= carry[9] << 21;
        carry[11] = (s11 + (1LL << 20)) >> 21; s12 += carry[11]; s11 -= carry[11] << 21;

        s0  += s12 * 666643;
        s1  += s12 * 470296;
        s2  += s12 * 654183;
        s3  -= s12 * 997805;
        s4  += s12 * 136657;
        s5  -= s12 * 683901;
        s12 = 0;

        carry[0]  = s0 >> 21; s1 += carry[0]; s0 -= carry[0] << 21;
        carry[1]  = s1 >> 21; s2 += carry[1]; s1 -= carry[1] << 21;
        carry[2]  = s2 >> 21; s3 += carry[2]; s2 -= carry[2] << 21;
        carry[3]  = s3 >> 21; s4 += carry[3]; s3 -= carry[3] << 21;
        carry[4]  = s4 >> 21; s5 += carry[4]; s4 -= carry[4] << 21;
        carry[5]  = s5 >> 21; s6 += carry[5]; s5 -= carry[5] << 21;
        carry[6]  = s6 >> 21; s7 += carry[6]; s6 -= carry[6] << 21;
        carry[7]  = s7 >> 21; s8 += carry[7]; s7 -= carry[7] << 21;
        carry[8]  = s8 >> 21; s9 += carry[8]; s8 -= carry[8] << 21;
        carry[9]  = s9 >> 21; s10 += carry[9]; s9 -= carry[9] << 21;
        carry[10] = s10 >> 21; s11 += carry[10]; s10 -= carry[10] << 21;
        carry[11] = s11 >> 21; s12 += carry[11]; s11 -= carry[11] << 21;

        s0  += s12 * 666643;
        s1  += s12 * 470296;
        s2  += s12 * 654183;
        s3  -= s12 * 997805;
        s4  += s12 * 136657;
        s5  -= s12 * 683901;

        carry[0]  = s0 >> 21; s1 += carry[0]; s0 -= carry[0] << 21;
        carry[1]  = s1 >> 21; s2 += carry[1]; s1 -= carry[1] << 21;
        carry[2]  = s2 >> 21; s3 += carry[2]; s2 -= carry[2] << 21;
        carry[3]  = s3 >> 21; s4 += carry[3]; s3 -= carry[3] << 21;
        carry[4]  = s4 >> 21; s5 += carry[4]; s4 -= carry[4] << 21;
        carry[5]  = s5 >> 21; s6 += carry[5]; s5 -= carry[5] << 21;
        carry[6]  = s6 >> 21; s7 += carry[6]; s6 -= carry[6] << 21;
        carry[7]  = s7 >> 21; s8 += carry[7]; s7 -= carry[7] << 21;
        carry[8]  = s8 >> 21; s9 += carry[8]; s8 -= carry[8] << 21;
        carry[9]  = s9 >> 21; s10 += carry[9]; s9 -= carry[9] << 21;
        carry[10] = s10 >> 21; s11 += carry[10]; s10 -= carry[10] << 21;

        s[0]  = static_cast<u8>(s0 >> 0);
        s[1]  = static_cast<u8>(s0 >> 8);
        s[2]  = static_cast<u8>((s0 >> 16) | (s1 << 5));
        s[3]  = static_cast<u8>(s1 >> 3);
        s[4]  = static_cast<u8>(s1 >> 11);
        s[5]  = static_cast<u8>((s1 >> 19) | (s2 << 2));
        s[6]  = static_cast<u8>(s2 >> 6);
        s[7]  = static_cast<u8>((s2 >> 14) | (s3 << 7));
        s[8]  = static_cast<u8>(s3 >> 1);
        s[9]  = static_cast<u8>(s3 >> 9);
        s[10] = static_cast<u8>((s3 >> 17) | (s4 << 4));
        s[11] = static_cast<u8>(s4 >> 4);
        s[12] = static_cast<u8>(s4 >> 12);
        s[13] = static_cast<u8>((s4 >> 20) | (s5 << 1));
        s[14] = static_cast<u8>(s5 >> 7);
        s[15] = static_cast<u8>((s5 >> 15) | (s6 << 6));
        s[16] = static_cast<u8>(s6 >> 2);
        s[17] = static_cast<u8>(s6 >> 10);
        s[18] = static_cast<u8>((s6 >> 18) | (s7 << 3));
        s[19] = static_cast<u8>(s7 >> 5);
        s[20] = static_cast<u8>(s7 >> 13);
        s[21] = static_cast<u8>(s8 >> 0);
        s[22] = static_cast<u8>(s8 >> 8);
        s[23] = static_cast<u8>((s8 >> 16) | (s9 << 5));
        s[24] = static_cast<u8>(s9 >> 3);
        s[25] = static_cast<u8>(s9 >> 11);
        s[26] = static_cast<u8>((s9 >> 19) | (s10 << 2));
        s[27] = static_cast<u8>(s10 >> 6);
        s[28] = static_cast<u8>((s10 >> 14) | (s11 << 7));
        s[29] = static_cast<u8>(s11 >> 1);
        s[30] = static_cast<u8>(s11 >> 9);
        s[31] = static_cast<u8>(s11 >> 17);
    }

    static __forceinline i8 ed25519_signed_radix16_byte(const u8 a[32], i32 i) noexcept
    {
        i8 e[64];
        for (i32 j = 0; j < 32; ++j)
        {
            e[2*j]   = static_cast<i8>(a[j] & 15);
            e[2*j+1] = static_cast<i8>((a[j] >> 4) & 15);
        }
        i8 carry = 0;
        for (i32 j = 0; j < 63; ++j)
        {
            e[j] = static_cast<i8>(e[j] + carry);
            carry = static_cast<i8>((e[j] + 8) >> 4);
            e[j] = static_cast<i8>(e[j] - (carry << 4));
        }
        e[63] = static_cast<i8>(e[63] + carry);
        return e[i];
    }

    static __forceinline void slide(i8 r[256], const u8 a[32]) noexcept
    {
        for (i32 i = 0; i < 256; ++i)
        {
            r[i] = static_cast<i8>(1 & (a[i >> 3] >> (i & 7)));
        }
        for (i32 i = 0; i < 256; ++i)
        {
            if (r[i])
            {
                for (i32 b = 1; b <= 6 && i + b < 256; ++b)
                {
                    if (r[i + b])
                    {
                        if (r[i] + (r[i + b] << b) <= 15)
                        {
                            r[i] = static_cast<i8>(r[i] + (r[i + b] << b));
                            r[i + b] = 0;
                        }
                        else if (r[i] - (r[i + b] << b) >= -15)
                        {
                            r[i] = static_cast<i8>(r[i] - (r[i + b] << b));
                            for (i32 k = i + b; k < 256; ++k)
                            {
                                if (!r[k])
                                {
                                    r[k] = 1;
                                    break;
                                }
                                r[k] = 0;
                            }
                        }
                        else break;
                    }
                }
            }
        }
    }

    extern const ge_precomp_t (&k_base)[32][8];
    extern const ge_precomp_t (&k_Bi)[8];

    static __forceinline void ge_precomp_0(ge_precomp_t* h) noexcept
    {
        fe_1(h->yplusx); fe_1(h->yminusx); fe_0(h->xy2d);
    }

    static __forceinline u8 negative_b(i8 b) noexcept
    {
        u64 x = static_cast<u64>(static_cast<i64>(b));
        return static_cast<u8>((x >> 63) & 1u);
    }

    static __forceinline u8 equal_b(i8 b, i8 c) noexcept
    {
        u8 ub = static_cast<u8>(b ^ c);
        u32 y = ub;
        y -= 1; y >>= 31;
        return static_cast<u8>(y);
    }

    static __forceinline void cmov_precomp(ge_precomp_t* t, const ge_precomp_t* u, u8 b) noexcept
    {
        fe_cmov(t->yplusx, u->yplusx, b);
        fe_cmov(t->yminusx, u->yminusx, b);
        fe_cmov(t->xy2d, u->xy2d, b);
    }

    static __forceinline void select_precomp(ge_precomp_t* t, i32 pos, i8 b) noexcept
    {
        u8 bneg = negative_b(b);
        i8 babs = static_cast<i8>(b - (((-bneg) & b) << 1));
        ge_precomp_0(t);
        cmov_precomp(t, &k_base[pos][0], equal_b(babs, 1));
        cmov_precomp(t, &k_base[pos][1], equal_b(babs, 2));
        cmov_precomp(t, &k_base[pos][2], equal_b(babs, 3));
        cmov_precomp(t, &k_base[pos][3], equal_b(babs, 4));
        cmov_precomp(t, &k_base[pos][4], equal_b(babs, 5));
        cmov_precomp(t, &k_base[pos][5], equal_b(babs, 6));
        cmov_precomp(t, &k_base[pos][6], equal_b(babs, 7));
        cmov_precomp(t, &k_base[pos][7], equal_b(babs, 8));
        ge_precomp_t minus_t;
        fe_copy(minus_t.yplusx, t->yminusx);
        fe_copy(minus_t.yminusx, t->yplusx);
        fe_neg(minus_t.xy2d, t->xy2d);
        cmov_precomp(t, &minus_t, bneg);
    }

    static __forceinline void ge_madd(ge_p1p1_t* r, const ge_p3_t* p, const ge_precomp_t* q) noexcept
    {
        fe_t t0;
        fe_add(r->X, p->Y, p->X);
        fe_sub(r->Y, p->Y, p->X);
        fe_mul(r->Z, r->X, q->yplusx);
        fe_mul(r->Y, r->Y, q->yminusx);
        fe_mul(r->T, q->xy2d, p->T);
        fe_add(t0, p->Z, p->Z);
        fe_sub(r->X, r->Z, r->Y);
        fe_add(r->Y, r->Z, r->Y);
        fe_add(r->Z, t0, r->T);
        fe_sub(r->T, t0, r->T);
    }

    static __forceinline void ge_msub(ge_p1p1_t* r, const ge_p3_t* p, const ge_precomp_t* q) noexcept
    {
        fe_t t0;
        fe_add(r->X, p->Y, p->X);
        fe_sub(r->Y, p->Y, p->X);
        fe_mul(r->Z, r->X, q->yminusx);
        fe_mul(r->Y, r->Y, q->yplusx);
        fe_mul(r->T, q->xy2d, p->T);
        fe_add(t0, p->Z, p->Z);
        fe_sub(r->X, r->Z, r->Y);
        fe_add(r->Y, r->Z, r->Y);
        fe_sub(r->Z, t0, r->T);
        fe_add(r->T, t0, r->T);
    }

    static __forceinline void ge_scalarmult_base(ge_p3_t* h, const u8 a[32]) noexcept
    {
        i8 e[64];
        for (i32 i = 0; i < 32; ++i)
        {
            e[2*i]   = static_cast<i8>(a[i] & 15);
            e[2*i+1] = static_cast<i8>((a[i] >> 4) & 15);
        }
        i8 carry = 0;
        for (i32 i = 0; i < 63; ++i)
        {
            e[i] = static_cast<i8>(e[i] + carry);
            carry = static_cast<i8>((e[i] + 8) >> 4);
            e[i] = static_cast<i8>(e[i] - (carry << 4));
        }
        e[63] = static_cast<i8>(e[63] + carry);

        ge_p3_0(h);
        ge_precomp_t t;
        ge_p1p1_t r;
        for (i32 i = 1; i < 64; i += 2)
        {
            select_precomp(&t, i / 2, e[i]);
            ge_madd(&r, h, &t);
            ge_p1p1_to_p3(h, &r);
        }
        ge_p3_dbl(&r, h); ge_p1p1_to_p2(reinterpret_cast<ge_p2_t*>(h), &r);
        {
            ge_p2_t* p2 = reinterpret_cast<ge_p2_t*>(h);
            ge_p2_dbl(&r, p2); ge_p1p1_to_p2(p2, &r);
            ge_p2_dbl(&r, p2); ge_p1p1_to_p2(p2, &r);
            ge_p2_dbl(&r, p2); ge_p1p1_to_p3(h, &r);
        }
        for (i32 i = 0; i < 64; i += 2)
        {
            select_precomp(&t, i / 2, e[i]);
            ge_madd(&r, h, &t);
            ge_p1p1_to_p3(h, &r);
        }
    }

    static __forceinline void ge_double_scalarmult_vartime(ge_p2_t* r,
                                                           const u8 a[32],
                                                           const ge_p3_t* A,
                                                           const u8 b[32]) noexcept
    {
        i8 aslide[256];
        i8 bslide[256];
        slide(aslide, a);
        slide(bslide, b);

        ge_cached_t Ai[8];
        ge_p1p1_t t;
        ge_p3_t u, A2;
        ge_p3_to_cached(&Ai[0], A);
        ge_p3_dbl(&t, A); ge_p1p1_to_p3(&A2, &t);
        ge_add(&t, &A2, &Ai[0]); ge_p1p1_to_p3(&u, &t); ge_p3_to_cached(&Ai[1], &u);
        ge_add(&t, &A2, &Ai[1]); ge_p1p1_to_p3(&u, &t); ge_p3_to_cached(&Ai[2], &u);
        ge_add(&t, &A2, &Ai[2]); ge_p1p1_to_p3(&u, &t); ge_p3_to_cached(&Ai[3], &u);
        ge_add(&t, &A2, &Ai[3]); ge_p1p1_to_p3(&u, &t); ge_p3_to_cached(&Ai[4], &u);
        ge_add(&t, &A2, &Ai[4]); ge_p1p1_to_p3(&u, &t); ge_p3_to_cached(&Ai[5], &u);
        ge_add(&t, &A2, &Ai[5]); ge_p1p1_to_p3(&u, &t); ge_p3_to_cached(&Ai[6], &u);
        ge_add(&t, &A2, &Ai[6]); ge_p1p1_to_p3(&u, &t); ge_p3_to_cached(&Ai[7], &u);

        ge_p2_0(r);
        i32 i = 255;
        for (; i >= 0; --i)
        {
            if (aslide[i] || bslide[i]) break;
        }
        for (; i >= 0; --i)
        {
            ge_p2_dbl(&t, r);
            if (aslide[i] > 0)
            {
                ge_p1p1_to_p3(&u, &t);
                ge_add(&t, &u, &Ai[aslide[i] / 2]);
            }
            else if (aslide[i] < 0)
            {
                ge_p1p1_to_p3(&u, &t);
                ge_sub(&t, &u, &Ai[(-aslide[i]) / 2]);
            }
            if (bslide[i] > 0)
            {
                ge_p1p1_to_p3(&u, &t);
                ge_madd(&t, &u, &k_Bi[bslide[i] / 2]);
            }
            else if (bslide[i] < 0)
            {
                ge_p1p1_to_p3(&u, &t);
                ge_msub(&t, &u, &k_Bi[(-bslide[i]) / 2]);
            }
            ge_p1p1_to_p2(r, &t);
        }
    }

    static __forceinline void fe_from_bytes_array(fe_t out, const u8 in[32]) noexcept
    {
        fe_frombytes(out, in);
    }

    struct precomp_init_t
    {
        u8 yplusx[32];
        u8 yminusx[32];
        u8 xy2d[32];
    };

    static __forceinline void precomp_from_init(ge_precomp_t* out, const precomp_init_t* in) noexcept
    {
        fe_from_bytes_array(out->yplusx,  in->yplusx);
        fe_from_bytes_array(out->yminusx, in->yminusx);
        fe_from_bytes_array(out->xy2d,    in->xy2d);
    }

    struct base_tables_t
    {
        ge_precomp_t base[32][8];
        ge_precomp_t Bi[8];
        bool initialized;
    };

    static base_tables_t& tables() noexcept
    {
        static base_tables_t t{};
        return t;
    }

    static __forceinline void ge_p3_to_precomp(ge_precomp_t* out, const ge_p3_t* p) noexcept
    {
        fe_t recip, x, y, xy, d2;
        static const u8 k_d2_bytes[32] = {
            0x59,0xf1,0xb2,0x26,0x94,0x9b,0xd6,0xeb,
            0x56,0xb1,0x83,0x82,0x9a,0x14,0xe0,0x00,
            0x30,0xd1,0xf3,0xee,0xf2,0x80,0x8e,0x19,
            0xe7,0xfc,0xdf,0x56,0xdc,0xd9,0x06,0x24
        };
        fe_invert(recip, p->Z);
        fe_mul(x, p->X, recip);
        fe_mul(y, p->Y, recip);
        fe_add(out->yplusx, y, x);
        fe_sub(out->yminusx, y, x);
        fe_frombytes(d2, k_d2_bytes);
        fe_mul(xy, x, y);
        fe_mul(out->xy2d, xy, d2);
    }

    static __forceinline void p3_neg(ge_p3_t* h) noexcept
    {
        fe_neg(h->X, h->X);
        fe_neg(h->T, h->T);
    }

    static __forceinline void init_base_tables_locked() noexcept
    {
        base_tables_t& tb = tables();
        if (tb.initialized) return;

        ge_p3_t B;
        static const u8 k_By_bytes[32] = {
            0x58,0x66,0x66,0x66,0x66,0x66,0x66,0x66,
            0x66,0x66,0x66,0x66,0x66,0x66,0x66,0x66,
            0x66,0x66,0x66,0x66,0x66,0x66,0x66,0x66,
            0x66,0x66,0x66,0x66,0x66,0x66,0x66,0x66
        };
        ge_frombytes_negate_vartime(&B, k_By_bytes);
        p3_neg(&B);

        ge_p3_t cur; cur = B;
        for (i32 i = 0; i < 32; ++i)
        {
            ge_p3_t row_base = cur;
            ge_p3_t acc = row_base;
            ge_p3_to_precomp(&tb.base[i][0], &acc);
            for (i32 j = 1; j < 8; ++j)
            {
                ge_cached_t cached;
                ge_p3_to_cached(&cached, &row_base);
                ge_p1p1_t t;
                ge_add(&t, &acc, &cached);
                ge_p3_t next;
                ge_p1p1_to_p3(&next, &t);
                ge_p3_to_precomp(&tb.base[i][j], &next);
                acc = next;
            }
            ge_p3_t doubled = cur;
            for (i32 k = 0; k < 8; ++k)
            {
                ge_p1p1_t t; ge_p3_dbl(&t, &doubled);
                ge_p3_t nx; ge_p1p1_to_p3(&nx, &t);
                doubled = nx;
            }
            cur = doubled;
        }

        ge_p3_t Bi_p3[8];
        Bi_p3[0] = B;
        ge_p3_t B2;
        {
            ge_p1p1_t t; ge_p3_dbl(&t, &B); ge_p1p1_to_p3(&B2, &t);
        }
        for (i32 i = 1; i < 8; ++i)
        {
            ge_cached_t cached;
            ge_p3_to_cached(&cached, &B2);
            ge_p1p1_t t;
            ge_add(&t, &Bi_p3[i - 1], &cached);
            ge_p1p1_to_p3(&Bi_p3[i], &t);
        }
        for (i32 i = 0; i < 8; ++i)
        {
            ge_p3_to_precomp(&tb.Bi[i], &Bi_p3[i]);
        }
        tb.initialized = true;
    }

    const ge_precomp_t (&k_base)[32][8] = tables().base;
    const ge_precomp_t (&k_Bi)[8]       = tables().Bi;

    static __forceinline bool verify_inner(const u8* msg, size_t msg_len,
                                           const u8 sig[64], const u8 pk[32]) noexcept
    {
        if (sig[63] & 0xE0)
        {
            set_err("wb_ed25519_sig_high_bits_set");
            return false;
        }

        ge_p3_t A;
        if (!ge_frombytes_negate_vartime(&A, pk))
        {
            set_err("wb_ed25519_pubkey_decode_failed");
            return false;
        }

        u8 h_full[64];
        sha512_one_shot(sig, 32, pk, 32, msg, msg_len, h_full);
        sc_reduce(h_full);

        ge_p2_t R;
        u8 s_scalar[32];
        std::memcpy(s_scalar, sig + 32, 32);
        ge_double_scalarmult_vartime(&R, h_full, &A, s_scalar);

        u8 r_check[32];
        ge_p2_tobytes(r_check, &R);

        u8 diff = 0;
        for (i32 i = 0; i < 32; ++i) diff |= static_cast<u8>(r_check[i] ^ sig[i]);
        if (diff != 0)
        {
            set_err("wb_ed25519_R_mismatch");
            return false;
        }
        return true;
    }

    struct self_test_state_t
    {
        std::atomic<bool> attempted{false};
        std::atomic<bool> ok{false};
    };

    static self_test_state_t& self_test_state() noexcept
    {
        static self_test_state_t s;
        return s;
    }

    static const u8 k_kat_pk[32] = {
        0xd7,0x5a,0x98,0x01,0x82,0xb1,0x0a,0xb7,
        0xd5,0x4b,0xfe,0xd3,0xc9,0x64,0x07,0x3a,
        0x0e,0xe1,0x72,0xf3,0xda,0xa6,0x23,0x25,
        0xaf,0x02,0x1a,0x68,0xf7,0x07,0x51,0x1a
    };
    static const u8 k_kat_sig[64] = {
        0xe5,0x56,0x43,0x00,0xc3,0x60,0xac,0x72,
        0x90,0x86,0xe2,0xcc,0x80,0x6e,0x82,0x8a,
        0x84,0x87,0x7f,0x1e,0xb8,0xe5,0xd9,0x74,
        0xd8,0x73,0xe0,0x65,0x22,0x49,0x01,0x55,
        0x5f,0xb8,0x82,0x15,0x90,0xa3,0x3b,0xac,
        0xc6,0x1e,0x39,0x70,0x1c,0xf9,0xb4,0x6b,
        0xd2,0x5b,0xf5,0xf0,0x59,0x5b,0xbe,0x24,
        0x65,0x51,0x41,0x43,0x8e,0x7a,0x10,0x0b
    };

    static __forceinline bool run_self_test_once() noexcept
    {
        auto& st = self_test_state();
        if (st.attempted.load(std::memory_order_acquire))
        {
            bool cached = st.ok.load(std::memory_order_acquire);
            diag::log_tagged_fmt("wb_ed25519",
                "self_test cached=%d err=%s",
                cached ? 1 : 0,
                current_err());
            return cached;
        }
        diag::log_tagged_fmt("wb_ed25519",
            "self_test begin kat_msg_len=0 sig_hash=0x%016llX pk_hash=0x%016llX",
            static_cast<unsigned long long>(fnv1a64_bytes(k_kat_sig, sizeof(k_kat_sig))),
            static_cast<unsigned long long>(fnv1a64_bytes(k_kat_pk, sizeof(k_kat_pk))));
        init_base_tables_locked();
        bool r = verify_inner(nullptr, 0, k_kat_sig, k_kat_pk);
        st.ok.store(r, std::memory_order_release);
        st.attempted.store(true, std::memory_order_release);
        if (!r) set_err("wb_ed25519_self_test_failed");
        diag::log_tagged_fmt("wb_ed25519",
            "self_test result=%d err=%s",
            r ? 1 : 0,
            current_err());
        return r;
    }

    struct kat_initializer_t
    {
        kat_initializer_t() noexcept
        {
            run_self_test_once();
        }
    };
    static kat_initializer_t s_kat_initializer{};
}

__declspec(allocate(".aida_v"))
static const uint8_t k_aida_v_anchor[16] = {
    0x41,0x49,0x44,0x41,0x5F,0x56,0x45,0x52,
    0x49,0x46,0x59,0x5F,0x42,0x4C,0x4B,0x00
};

namespace aida::wb_ed25519
{
    bool verify(const uint8_t* msg, size_t msg_len,
                const uint8_t* sig_64bytes,
                const uint8_t* pubkey_32bytes) noexcept
    {
        diag::log_tagged_fmt("wb_ed25519",
            "verify enter msg_len=%zu msg_hash=0x%016llX sig_hash=0x%016llX pk_hash=0x%016llX",
            msg_len,
            static_cast<unsigned long long>(fnv1a64_bytes(msg, msg_len)),
            static_cast<unsigned long long>(fnv1a64_bytes(sig_64bytes, sig_64bytes ? 64 : 0)),
            static_cast<unsigned long long>(fnv1a64_bytes(pubkey_32bytes, pubkey_32bytes ? 32 : 0)));
        if (anti_tamper::dr_check::any_hw_breakpoint_set())
        {
            set_err("hw_breakpoint_at_verify");
            diag::log_tagged("wb_ed25519", "verify rejected reason=hw_breakpoint");
            return false;
        }
        if ((void)k_aida_v_anchor[0], sig_64bytes == nullptr || pubkey_32bytes == nullptr)
        {
            set_err("wb_ed25519_null_input");
            diag::log_tagged("wb_ed25519", "verify rejected reason=null_input");
            return false;
        }
        if (msg == nullptr && msg_len != 0)
        {
            set_err("wb_ed25519_null_msg_with_len");
            diag::log_tagged("wb_ed25519", "verify rejected reason=null_msg_with_len");
            return false;
        }
        if (!run_self_test_once())
        {
            diag::log_tagged_fmt("wb_ed25519", "verify rejected reason=self_test err=%s",
                current_err());
            return false;
        }
        bool ok = verify_inner(msg, msg_len, sig_64bytes, pubkey_32bytes);
        diag::log_tagged_fmt("wb_ed25519", "verify result=%d err=%s",
            ok ? 1 : 0,
            ok ? "" : current_err());
        return ok;
    }

    const char* last_error() noexcept
    {
        const char* e = s_last_error.load(std::memory_order_acquire);
        return e ? e : "";
    }

    bool self_test_ok() noexcept
    {
        bool ok = run_self_test_once();
        diag::log_tagged_fmt("wb_ed25519", "self_test_ok return=%d err=%s",
            ok ? 1 : 0,
            ok ? "" : last_error());
        return ok;
    }
}
