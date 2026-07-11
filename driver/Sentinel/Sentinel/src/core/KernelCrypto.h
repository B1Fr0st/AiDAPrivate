#pragma once

#include <ntddk.h>
#include <bcrypt.h>

namespace kernel_crypto
{
    constexpr ULONG SHA256_BLOCK_SIZE  = 64;
    constexpr ULONG SHA256_DIGEST_SIZE = 32;
    constexpr ULONG AES_BLOCK_SIZE     = 16;
    constexpr ULONG AES256_KEY_SIZE    = 32;
    constexpr ULONG GCM_NONCE_SIZE     = 12;
    constexpr ULONG GCM_TAG_SIZE       = 16;

    struct sha256_ctx_t {
        UINT32 state[8];
        UINT64 bit_count;
        UINT8  buffer[SHA256_BLOCK_SIZE];
        ULONG  buffer_len;
    };

    __forceinline UINT32 rotr32(UINT32 x, UINT32 n) {
        return (x >> n) | (x << (32 - n));
    }

    static const UINT32 kSha256K[64] = {
        0x428a2f98u,0x71374491u,0xb5c0fbcfu,0xe9b5dba5u,0x3956c25bu,0x59f111f1u,0x923f82a4u,0xab1c5ed5u,
        0xd807aa98u,0x12835b01u,0x243185beu,0x550c7dc3u,0x72be5d74u,0x80deb1feu,0x9bdc06a7u,0xc19bf174u,
        0xe49b69c1u,0xefbe4786u,0x0fc19dc6u,0x240ca1ccu,0x2de92c6fu,0x4a7484aau,0x5cb0a9dcu,0x76f988dau,
        0x983e5152u,0xa831c66du,0xb00327c8u,0xbf597fc7u,0xc6e00bf3u,0xd5a79147u,0x06ca6351u,0x14292967u,
        0x27b70a85u,0x2e1b2138u,0x4d2c6dfcu,0x53380d13u,0x650a7354u,0x766a0abbu,0x81c2c92eu,0x92722c85u,
        0xa2bfe8a1u,0xa81a664bu,0xc24b8b70u,0xc76c51a3u,0xd192e819u,0xd6990624u,0xf40e3585u,0x106aa070u,
        0x19a4c116u,0x1e376c08u,0x2748774cu,0x34b0bcb5u,0x391c0cb3u,0x4ed8aa4au,0x5b9cca4fu,0x682e6ff3u,
        0x748f82eeu,0x78a5636fu,0x84c87814u,0x8cc70208u,0x90befffau,0xa4506cebu,0xbef9a3f7u,0xc67178f2u
    };

    __forceinline void sha256_init(sha256_ctx_t* ctx) {
        ctx->state[0] = 0x6a09e667u;
        ctx->state[1] = 0xbb67ae85u;
        ctx->state[2] = 0x3c6ef372u;
        ctx->state[3] = 0xa54ff53au;
        ctx->state[4] = 0x510e527fu;
        ctx->state[5] = 0x9b05688cu;
        ctx->state[6] = 0x1f83d9abu;
        ctx->state[7] = 0x5be0cd19u;
        ctx->bit_count = 0;
        ctx->buffer_len = 0;
    }

    __forceinline void sha256_compress(sha256_ctx_t* ctx, const UINT8* block) {
        UINT32 w[64];
        for (ULONG i = 0; i < 16; ++i) {
            w[i] = (static_cast<UINT32>(block[i * 4 + 0]) << 24) |
                   (static_cast<UINT32>(block[i * 4 + 1]) << 16) |
                   (static_cast<UINT32>(block[i * 4 + 2]) << 8)  |
                   (static_cast<UINT32>(block[i * 4 + 3]));
        }
        for (ULONG i = 16; i < 64; ++i) {
            UINT32 s0 = rotr32(w[i - 15], 7) ^ rotr32(w[i - 15], 18) ^ (w[i - 15] >> 3);
            UINT32 s1 = rotr32(w[i - 2], 17) ^ rotr32(w[i - 2], 19) ^ (w[i - 2] >> 10);
            w[i] = w[i - 16] + s0 + w[i - 7] + s1;
        }
        UINT32 a = ctx->state[0];
        UINT32 b = ctx->state[1];
        UINT32 c = ctx->state[2];
        UINT32 d = ctx->state[3];
        UINT32 e = ctx->state[4];
        UINT32 f = ctx->state[5];
        UINT32 g = ctx->state[6];
        UINT32 h = ctx->state[7];
        for (ULONG i = 0; i < 64; ++i) {
            UINT32 S1 = rotr32(e, 6) ^ rotr32(e, 11) ^ rotr32(e, 25);
            UINT32 ch = (e & f) ^ ((~e) & g);
            UINT32 t1 = h + S1 + ch + kSha256K[i] + w[i];
            UINT32 S0 = rotr32(a, 2) ^ rotr32(a, 13) ^ rotr32(a, 22);
            UINT32 mj = (a & b) ^ (a & c) ^ (b & c);
            UINT32 t2 = S0 + mj;
            h = g;
            g = f;
            f = e;
            e = d + t1;
            d = c;
            c = b;
            b = a;
            a = t1 + t2;
        }
        ctx->state[0] += a;
        ctx->state[1] += b;
        ctx->state[2] += c;
        ctx->state[3] += d;
        ctx->state[4] += e;
        ctx->state[5] += f;
        ctx->state[6] += g;
        ctx->state[7] += h;
    }

    __forceinline void sha256_update(sha256_ctx_t* ctx, const UINT8* data, ULONG len) {
        if (!data || len == 0) return;
        ctx->bit_count += static_cast<UINT64>(len) * 8;
        while (len > 0) {
            ULONG room = SHA256_BLOCK_SIZE - ctx->buffer_len;
            ULONG take = (len < room) ? len : room;
            for (ULONG i = 0; i < take; ++i)
                ctx->buffer[ctx->buffer_len + i] = data[i];
            ctx->buffer_len += take;
            data += take;
            len -= take;
            if (ctx->buffer_len == SHA256_BLOCK_SIZE) {
                sha256_compress(ctx, ctx->buffer);
                ctx->buffer_len = 0;
            }
        }
    }

    __forceinline void sha256_final(sha256_ctx_t* ctx, UINT8 out[SHA256_DIGEST_SIZE]) {
        UINT64 total_bits = ctx->bit_count;
        ctx->buffer[ctx->buffer_len++] = 0x80;
        if (ctx->buffer_len > 56) {
            while (ctx->buffer_len < SHA256_BLOCK_SIZE)
                ctx->buffer[ctx->buffer_len++] = 0;
            sha256_compress(ctx, ctx->buffer);
            ctx->buffer_len = 0;
        }
        while (ctx->buffer_len < 56)
            ctx->buffer[ctx->buffer_len++] = 0;
        for (int i = 7; i >= 0; --i)
            ctx->buffer[ctx->buffer_len++] = static_cast<UINT8>(total_bits >> (i * 8));
        sha256_compress(ctx, ctx->buffer);
        for (ULONG i = 0; i < 8; ++i) {
            out[i * 4 + 0] = static_cast<UINT8>(ctx->state[i] >> 24);
            out[i * 4 + 1] = static_cast<UINT8>(ctx->state[i] >> 16);
            out[i * 4 + 2] = static_cast<UINT8>(ctx->state[i] >> 8);
            out[i * 4 + 3] = static_cast<UINT8>(ctx->state[i]);
        }
        RtlSecureZeroMemory(ctx->buffer, sizeof(ctx->buffer));
    }

    __forceinline void sw_sha256(const UINT8* data, ULONG len, UINT8 out[SHA256_DIGEST_SIZE]) {
        sha256_ctx_t ctx;
        sha256_init(&ctx);
        sha256_update(&ctx, data, len);
        sha256_final(&ctx, out);
    }

    __forceinline void sw_hmac_sha256(
        const UINT8* key, ULONG key_len,
        const UINT8* data, ULONG data_len,
        UINT8 out[SHA256_DIGEST_SIZE])
    {
        UINT8 k[SHA256_BLOCK_SIZE];
        UINT8 ipad[SHA256_BLOCK_SIZE];
        UINT8 opad[SHA256_BLOCK_SIZE];
        UINT8 inner[SHA256_DIGEST_SIZE];

        if (key_len > SHA256_BLOCK_SIZE) {
            sw_sha256(key, key_len, k);
            for (ULONG i = SHA256_DIGEST_SIZE; i < SHA256_BLOCK_SIZE; ++i) k[i] = 0;
        } else {
            for (ULONG i = 0; i < key_len; ++i) k[i] = key[i];
            for (ULONG i = key_len; i < SHA256_BLOCK_SIZE; ++i) k[i] = 0;
        }

        for (ULONG i = 0; i < SHA256_BLOCK_SIZE; ++i) {
            ipad[i] = k[i] ^ 0x36u;
            opad[i] = k[i] ^ 0x5Cu;
        }

        sha256_ctx_t ctx;
        sha256_init(&ctx);
        sha256_update(&ctx, ipad, SHA256_BLOCK_SIZE);
        sha256_update(&ctx, data, data_len);
        sha256_final(&ctx, inner);

        sha256_init(&ctx);
        sha256_update(&ctx, opad, SHA256_BLOCK_SIZE);
        sha256_update(&ctx, inner, SHA256_DIGEST_SIZE);
        sha256_final(&ctx, out);

        RtlSecureZeroMemory(k, SHA256_BLOCK_SIZE);
        RtlSecureZeroMemory(ipad, SHA256_BLOCK_SIZE);
        RtlSecureZeroMemory(opad, SHA256_BLOCK_SIZE);
        RtlSecureZeroMemory(inner, SHA256_DIGEST_SIZE);
    }

    __forceinline void sw_hkdf_sha256(
        const UINT8* salt, ULONG salt_len,
        const UINT8* ikm, ULONG ikm_len,
        const UINT8* info, ULONG info_len,
        UINT8* okm, ULONG okm_len)
    {
        UINT8 zero_salt[SHA256_DIGEST_SIZE] = { 0 };
        if (!salt || salt_len == 0) {
            salt = zero_salt;
            salt_len = SHA256_DIGEST_SIZE;
        }

        UINT8 prk[SHA256_DIGEST_SIZE];
        sw_hmac_sha256(salt, salt_len, ikm, ikm_len, prk);

        UINT8 t[SHA256_DIGEST_SIZE] = { 0 };
        ULONG t_len = 0;
        ULONG written = 0;
        UINT8 counter = 1;

        while (written < okm_len) {
            sha256_ctx_t ictx;
            UINT8 k_block[SHA256_BLOCK_SIZE];
            UINT8 ipad[SHA256_BLOCK_SIZE];
            UINT8 opad[SHA256_BLOCK_SIZE];

            for (ULONG i = 0; i < SHA256_DIGEST_SIZE; ++i) k_block[i] = prk[i];
            for (ULONG i = SHA256_DIGEST_SIZE; i < SHA256_BLOCK_SIZE; ++i) k_block[i] = 0;
            for (ULONG i = 0; i < SHA256_BLOCK_SIZE; ++i) {
                ipad[i] = k_block[i] ^ 0x36u;
                opad[i] = k_block[i] ^ 0x5Cu;
            }

            sha256_init(&ictx);
            sha256_update(&ictx, ipad, SHA256_BLOCK_SIZE);
            if (t_len) sha256_update(&ictx, t, t_len);
            if (info_len) sha256_update(&ictx, info, info_len);
            sha256_update(&ictx, &counter, 1);
            UINT8 inner[SHA256_DIGEST_SIZE];
            sha256_final(&ictx, inner);

            sha256_init(&ictx);
            sha256_update(&ictx, opad, SHA256_BLOCK_SIZE);
            sha256_update(&ictx, inner, SHA256_DIGEST_SIZE);
            sha256_final(&ictx, t);
            t_len = SHA256_DIGEST_SIZE;

            ULONG copy = ((okm_len - written) < SHA256_DIGEST_SIZE) ? (okm_len - written) : SHA256_DIGEST_SIZE;
            for (ULONG i = 0; i < copy; ++i) okm[written + i] = t[i];
            written += copy;
            ++counter;

            RtlSecureZeroMemory(k_block, SHA256_BLOCK_SIZE);
            RtlSecureZeroMemory(ipad, SHA256_BLOCK_SIZE);
            RtlSecureZeroMemory(opad, SHA256_BLOCK_SIZE);
            RtlSecureZeroMemory(inner, SHA256_DIGEST_SIZE);
        }

        RtlSecureZeroMemory(prk, sizeof(prk));
        RtlSecureZeroMemory(t, sizeof(t));
    }

    __forceinline UINT8 aes_gf_mul(UINT8 a, UINT8 b) {
        UINT8 p = 0;
        for (int i = 0; i < 8; ++i) {
            if (b & 1u) p ^= a;
            UINT8 hi = a & 0x80u;
            a = static_cast<UINT8>(a << 1);
            if (hi) a ^= 0x1Bu;
            b >>= 1;
        }
        return p;
    }

    __forceinline UINT8 aes_gf_inv(UINT8 a) {
        if (a == 0) return 0;
        for (UINT8 b = 1; b != 0; ++b) {
            if (aes_gf_mul(a, b) == 1) return b;
        }
        return 0;
    }

    __forceinline UINT8 compute_sbox_entry(UINT8 input) {
        UINT8 inv = aes_gf_inv(input);
        UINT8 result = 0;
        for (int i = 0; i < 8; ++i) {
            UINT8 bit = static_cast<UINT8>(
                ((inv >> i) & 1u) ^
                ((inv >> ((i + 4) % 8)) & 1u) ^
                ((inv >> ((i + 5) % 8)) & 1u) ^
                ((inv >> ((i + 6) % 8)) & 1u) ^
                ((inv >> ((i + 7) % 8)) & 1u) ^
                ((0x63u >> i) & 1u));
            result |= static_cast<UINT8>(bit << i);
        }
        return result;
    }

    __forceinline void compute_sbox(UINT8 out[256]) {
        for (ULONG i = 0; i < 256; ++i)
            out[i] = compute_sbox_entry(static_cast<UINT8>(i));
    }

    __forceinline UINT8 compute_rcon(UINT8 round) {
        if (round == 0) return 0;
        UINT8 r = 1;
        for (UINT8 j = 1; j < round; ++j) {
            UINT8 hi = r & 0x80u;
            r = static_cast<UINT8>(r << 1);
            if (hi) r ^= 0x1Bu;
        }
        return r;
    }

    constexpr ULONG AES256_NR = 14;
    constexpr ULONG AES256_NK = 8;
    constexpr ULONG AES256_NB = 4;
    constexpr ULONG AES256_RK_WORDS = AES256_NB * (AES256_NR + 1);

    struct aes256_ctx_t {
        UINT32 rk[AES256_RK_WORDS];
    };

    __forceinline UINT32 aes_subword(UINT32 x, const UINT8* sbox) {
        return (static_cast<UINT32>(sbox[(x >> 24) & 0xFF]) << 24) |
               (static_cast<UINT32>(sbox[(x >> 16) & 0xFF]) << 16) |
               (static_cast<UINT32>(sbox[(x >> 8)  & 0xFF]) << 8)  |
               (static_cast<UINT32>(sbox[x & 0xFF]));
    }

    __forceinline UINT32 aes_rotword(UINT32 x) {
        return (x << 8) | (x >> 24);
    }

    __forceinline void aes256_set_encrypt_key(const UINT8 key[AES256_KEY_SIZE], aes256_ctx_t* ctx) {
        UINT8 sbox[256];
        compute_sbox(sbox);

        UINT32* rk = ctx->rk;
        for (ULONG i = 0; i < AES256_NK; ++i) {
            rk[i] = (static_cast<UINT32>(key[i * 4 + 0]) << 24) |
                    (static_cast<UINT32>(key[i * 4 + 1]) << 16) |
                    (static_cast<UINT32>(key[i * 4 + 2]) << 8)  |
                    (static_cast<UINT32>(key[i * 4 + 3]));
        }
        for (ULONG i = AES256_NK; i < AES256_RK_WORDS; ++i) {
            UINT32 t = rk[i - 1];
            if ((i % AES256_NK) == 0) {
                t = aes_subword(aes_rotword(t), sbox) ^ (static_cast<UINT32>(compute_rcon(static_cast<UINT8>(i / AES256_NK))) << 24);
            } else if (AES256_NK > 6 && (i % AES256_NK) == 4) {
                t = aes_subword(t, sbox);
            }
            rk[i] = rk[i - AES256_NK] ^ t;
        }

        RtlSecureZeroMemory(sbox, sizeof(sbox));
    }

    __forceinline UINT8 aes_xtime(UINT8 x) {
        return static_cast<UINT8>((x << 1) ^ (((x >> 7) & 1) * 0x1B));
    }

    __forceinline void aes256_encrypt_block(const aes256_ctx_t* ctx, const UINT8 in[16], UINT8 out[16]) {
        UINT8 sbox[256];
        compute_sbox(sbox);

        UINT8 s[16];
        for (ULONG i = 0; i < 16; ++i) s[i] = in[i];

        for (ULONG i = 0; i < 4; ++i) {
            UINT32 rk = ctx->rk[i];
            s[i * 4 + 0] ^= static_cast<UINT8>(rk >> 24);
            s[i * 4 + 1] ^= static_cast<UINT8>(rk >> 16);
            s[i * 4 + 2] ^= static_cast<UINT8>(rk >> 8);
            s[i * 4 + 3] ^= static_cast<UINT8>(rk);
        }

        for (ULONG round = 1; round < AES256_NR; ++round) {
            UINT8 t[16];
            for (ULONG i = 0; i < 16; ++i) t[i] = sbox[s[i]];

            UINT8 r[16];
            r[0]  = t[0];  r[1]  = t[5];  r[2]  = t[10]; r[3]  = t[15];
            r[4]  = t[4];  r[5]  = t[9];  r[6]  = t[14]; r[7]  = t[3];
            r[8]  = t[8];  r[9]  = t[13]; r[10] = t[2];  r[11] = t[7];
            r[12] = t[12]; r[13] = t[1];  r[14] = t[6];  r[15] = t[11];

            for (ULONG c = 0; c < 4; ++c) {
                UINT8 a0 = r[c * 4 + 0];
                UINT8 a1 = r[c * 4 + 1];
                UINT8 a2 = r[c * 4 + 2];
                UINT8 a3 = r[c * 4 + 3];
                UINT8 t0 = a0 ^ a1 ^ a2 ^ a3;
                s[c * 4 + 0] = a0 ^ t0 ^ aes_xtime(static_cast<UINT8>(a0 ^ a1));
                s[c * 4 + 1] = a1 ^ t0 ^ aes_xtime(static_cast<UINT8>(a1 ^ a2));
                s[c * 4 + 2] = a2 ^ t0 ^ aes_xtime(static_cast<UINT8>(a2 ^ a3));
                s[c * 4 + 3] = a3 ^ t0 ^ aes_xtime(static_cast<UINT8>(a3 ^ a0));
            }

            for (ULONG i = 0; i < 4; ++i) {
                UINT32 rk = ctx->rk[round * 4 + i];
                s[i * 4 + 0] ^= static_cast<UINT8>(rk >> 24);
                s[i * 4 + 1] ^= static_cast<UINT8>(rk >> 16);
                s[i * 4 + 2] ^= static_cast<UINT8>(rk >> 8);
                s[i * 4 + 3] ^= static_cast<UINT8>(rk);
            }
        }

        UINT8 t[16];
        for (ULONG i = 0; i < 16; ++i) t[i] = sbox[s[i]];

        UINT8 r[16];
        r[0]  = t[0];  r[1]  = t[5];  r[2]  = t[10]; r[3]  = t[15];
        r[4]  = t[4];  r[5]  = t[9];  r[6]  = t[14]; r[7]  = t[3];
        r[8]  = t[8];  r[9]  = t[13]; r[10] = t[2];  r[11] = t[7];
        r[12] = t[12]; r[13] = t[1];  r[14] = t[6];  r[15] = t[11];

        for (ULONG i = 0; i < 4; ++i) {
            UINT32 rk = ctx->rk[AES256_NR * 4 + i];
            r[i * 4 + 0] ^= static_cast<UINT8>(rk >> 24);
            r[i * 4 + 1] ^= static_cast<UINT8>(rk >> 16);
            r[i * 4 + 2] ^= static_cast<UINT8>(rk >> 8);
            r[i * 4 + 3] ^= static_cast<UINT8>(rk);
        }

        for (ULONG i = 0; i < 16; ++i) out[i] = r[i];

        RtlSecureZeroMemory(sbox, sizeof(sbox));
    }

    __forceinline void gcm_gf_mul(const UINT8 x[16], const UINT8 y[16], UINT8 z_out[16]) {
        UINT8 z[16] = { 0 };
        UINT8 v[16];
        for (ULONG i = 0; i < 16; ++i) v[i] = y[i];

        for (ULONG i = 0; i < 128; ++i) {
            UINT8 bit = static_cast<UINT8>((x[i >> 3] >> (7 - (i & 7))) & 1);
            if (bit) {
                for (ULONG j = 0; j < 16; ++j) z[j] ^= v[j];
            }
            UINT8 lsb = static_cast<UINT8>(v[15] & 1);
            for (int j = 15; j > 0; --j) {
                v[j] = static_cast<UINT8>((v[j] >> 1) | ((v[j - 1] & 1) << 7));
            }
            v[0] >>= 1;
            if (lsb) v[0] ^= 0xE1u;
        }
        for (ULONG i = 0; i < 16; ++i) z_out[i] = z[i];
    }

    __forceinline void gcm_inc32(UINT8 ctr[16]) {
        UINT32 c = (static_cast<UINT32>(ctr[12]) << 24) |
                   (static_cast<UINT32>(ctr[13]) << 16) |
                   (static_cast<UINT32>(ctr[14]) << 8)  |
                   (static_cast<UINT32>(ctr[15]));
        c += 1;
        ctr[12] = static_cast<UINT8>(c >> 24);
        ctr[13] = static_cast<UINT8>(c >> 16);
        ctr[14] = static_cast<UINT8>(c >> 8);
        ctr[15] = static_cast<UINT8>(c);
    }

    __forceinline void ghash_update(const UINT8 H[16], const UINT8* data, ULONG len, UINT8 y[16]) {
        ULONG full = len / 16;
        for (ULONG i = 0; i < full; ++i) {
            for (ULONG j = 0; j < 16; ++j) y[j] ^= data[i * 16 + j];
            UINT8 t[16];
            gcm_gf_mul(y, H, t);
            for (ULONG j = 0; j < 16; ++j) y[j] = t[j];
        }
        ULONG rem = len % 16;
        if (rem) {
            UINT8 last[16] = { 0 };
            for (ULONG j = 0; j < rem; ++j) last[j] = data[full * 16 + j];
            for (ULONG j = 0; j < 16; ++j) y[j] ^= last[j];
            UINT8 t[16];
            gcm_gf_mul(y, H, t);
            for (ULONG j = 0; j < 16; ++j) y[j] = t[j];
        }
    }

    __forceinline void sw_aes256_gcm_encrypt(
        const UINT8 key[AES256_KEY_SIZE],
        const UINT8 nonce[GCM_NONCE_SIZE],
        const UINT8* aad, ULONG aad_len,
        const UINT8* plaintext, ULONG plaintext_len,
        UINT8* ciphertext_out,
        UINT8 tag_out[GCM_TAG_SIZE])
    {
        aes256_ctx_t ctx;
        aes256_set_encrypt_key(key, &ctx);

        UINT8 H[16] = { 0 };
        UINT8 zero_block[16] = { 0 };
        aes256_encrypt_block(&ctx, zero_block, H);

        UINT8 j0[16] = { 0 };
        for (ULONG i = 0; i < GCM_NONCE_SIZE; ++i) j0[i] = nonce[i];
        j0[15] = 1;

        UINT8 ctr[16];
        for (ULONG i = 0; i < 16; ++i) ctr[i] = j0[i];
        gcm_inc32(ctr);

        ULONG full = plaintext_len / 16;
        ULONG rem = plaintext_len % 16;
        for (ULONG i = 0; i < full; ++i) {
            UINT8 ks[16];
            aes256_encrypt_block(&ctx, ctr, ks);
            for (ULONG j = 0; j < 16; ++j)
                ciphertext_out[i * 16 + j] = plaintext[i * 16 + j] ^ ks[j];
            gcm_inc32(ctr);
        }
        if (rem) {
            UINT8 ks[16];
            aes256_encrypt_block(&ctx, ctr, ks);
            for (ULONG j = 0; j < rem; ++j)
                ciphertext_out[full * 16 + j] = plaintext[full * 16 + j] ^ ks[j];
        }

        UINT8 y[16] = { 0 };
        if (aad_len) ghash_update(H, aad, aad_len, y);
        if (plaintext_len) ghash_update(H, ciphertext_out, plaintext_len, y);

        UINT8 length_block[16];
        UINT64 aad_bits = static_cast<UINT64>(aad_len) * 8;
        UINT64 ct_bits  = static_cast<UINT64>(plaintext_len) * 8;
        for (int i = 7; i >= 0; --i) length_block[7 - i]     = static_cast<UINT8>(aad_bits >> (i * 8));
        for (int i = 7; i >= 0; --i) length_block[15 - i]    = static_cast<UINT8>(ct_bits  >> (i * 8));
        for (ULONG j = 0; j < 16; ++j) y[j] ^= length_block[j];
        UINT8 t[16];
        gcm_gf_mul(y, H, t);
        for (ULONG j = 0; j < 16; ++j) y[j] = t[j];

        UINT8 ej0[16];
        aes256_encrypt_block(&ctx, j0, ej0);
        for (ULONG j = 0; j < GCM_TAG_SIZE; ++j) tag_out[j] = y[j] ^ ej0[j];

        RtlSecureZeroMemory(&ctx, sizeof(ctx));
        RtlSecureZeroMemory(H, sizeof(H));
        RtlSecureZeroMemory(j0, sizeof(j0));
        RtlSecureZeroMemory(y, sizeof(y));
    }

    __forceinline BOOLEAN sw_aes256_gcm_decrypt(
        const UINT8 key[AES256_KEY_SIZE],
        const UINT8 nonce[GCM_NONCE_SIZE],
        const UINT8* aad, ULONG aad_len,
        const UINT8* ciphertext, ULONG ciphertext_len,
        const UINT8 tag[GCM_TAG_SIZE],
        UINT8* plaintext_out)
    {
        aes256_ctx_t ctx;
        aes256_set_encrypt_key(key, &ctx);

        UINT8 H[16] = { 0 };
        UINT8 zero_block[16] = { 0 };
        aes256_encrypt_block(&ctx, zero_block, H);

        UINT8 j0[16] = { 0 };
        for (ULONG i = 0; i < GCM_NONCE_SIZE; ++i) j0[i] = nonce[i];
        j0[15] = 1;

        UINT8 y[16] = { 0 };
        if (aad_len) ghash_update(H, aad, aad_len, y);
        if (ciphertext_len) ghash_update(H, ciphertext, ciphertext_len, y);

        UINT8 length_block[16];
        UINT64 aad_bits = static_cast<UINT64>(aad_len) * 8;
        UINT64 ct_bits  = static_cast<UINT64>(ciphertext_len) * 8;
        for (int i = 7; i >= 0; --i) length_block[7 - i]   = static_cast<UINT8>(aad_bits >> (i * 8));
        for (int i = 7; i >= 0; --i) length_block[15 - i]  = static_cast<UINT8>(ct_bits  >> (i * 8));
        for (ULONG j = 0; j < 16; ++j) y[j] ^= length_block[j];
        UINT8 t[16];
        gcm_gf_mul(y, H, t);
        for (ULONG j = 0; j < 16; ++j) y[j] = t[j];

        UINT8 ej0[16];
        aes256_encrypt_block(&ctx, j0, ej0);
        UINT8 expected_tag[GCM_TAG_SIZE];
        for (ULONG j = 0; j < GCM_TAG_SIZE; ++j) expected_tag[j] = y[j] ^ ej0[j];

        volatile UINT8 diff = 0;
        for (ULONG j = 0; j < GCM_TAG_SIZE; ++j) diff |= expected_tag[j] ^ tag[j];

        if (diff != 0) {
            RtlSecureZeroMemory(&ctx, sizeof(ctx));
            RtlSecureZeroMemory(H, sizeof(H));
            RtlSecureZeroMemory(j0, sizeof(j0));
            RtlSecureZeroMemory(y, sizeof(y));
            return FALSE;
        }

        UINT8 ctr[16];
        for (ULONG i = 0; i < 16; ++i) ctr[i] = j0[i];
        gcm_inc32(ctr);

        ULONG full = ciphertext_len / 16;
        ULONG rem = ciphertext_len % 16;
        for (ULONG i = 0; i < full; ++i) {
            UINT8 ks[16];
            aes256_encrypt_block(&ctx, ctr, ks);
            for (ULONG j = 0; j < 16; ++j)
                plaintext_out[i * 16 + j] = ciphertext[i * 16 + j] ^ ks[j];
            gcm_inc32(ctr);
        }
        if (rem) {
            UINT8 ks[16];
            aes256_encrypt_block(&ctx, ctr, ks);
            for (ULONG j = 0; j < rem; ++j)
                plaintext_out[full * 16 + j] = ciphertext[full * 16 + j] ^ ks[j];
        }

        RtlSecureZeroMemory(&ctx, sizeof(ctx));
        RtlSecureZeroMemory(H, sizeof(H));
        RtlSecureZeroMemory(j0, sizeof(j0));
        RtlSecureZeroMemory(y, sizeof(y));
        return TRUE;
    }

    __forceinline NTSTATUS hmac_sha256(
        const UINT8* key, ULONG key_len,
        const UINT8* data, ULONG data_len,
        UINT8 hash_out[32])
    {
        BCRYPT_ALG_HANDLE alg = nullptr;
        NTSTATUS status = BCryptOpenAlgorithmProvider(
            &alg, BCRYPT_SHA256_ALGORITHM, nullptr, BCRYPT_ALG_HANDLE_HMAC_FLAG);
        if (!NT_SUCCESS(status)) return status;

        BCRYPT_HASH_HANDLE hh = nullptr;
        status = BCryptCreateHash(alg, &hh, nullptr, 0,
            const_cast<UINT8*>(key), key_len, 0);
        if (!NT_SUCCESS(status)) { BCryptCloseAlgorithmProvider(alg, 0); return status; }

        status = BCryptHashData(hh, const_cast<UINT8*>(data), data_len, 0);
        if (NT_SUCCESS(status))
            status = BCryptFinishHash(hh, hash_out, 32, 0);

        BCryptDestroyHash(hh);
        BCryptCloseAlgorithmProvider(alg, 0);
        return status;
    }

    __forceinline NTSTATUS sha256(
        const UINT8* data, ULONG data_len,
        UINT8 hash_out[32])
    {
        BCRYPT_ALG_HANDLE alg = nullptr;
        NTSTATUS status = BCryptOpenAlgorithmProvider(
            &alg, BCRYPT_SHA256_ALGORITHM, nullptr, 0);
        if (!NT_SUCCESS(status)) return status;

        BCRYPT_HASH_HANDLE hh = nullptr;
        status = BCryptCreateHash(alg, &hh, nullptr, 0, nullptr, 0, 0);
        if (!NT_SUCCESS(status)) { BCryptCloseAlgorithmProvider(alg, 0); return status; }

        status = BCryptHashData(hh, const_cast<UINT8*>(data), data_len, 0);
        if (NT_SUCCESS(status))
            status = BCryptFinishHash(hh, hash_out, 32, 0);

        BCryptDestroyHash(hh);
        BCryptCloseAlgorithmProvider(alg, 0);
        return status;
    }

    __forceinline NTSTATUS gen_random(UINT8* buf, ULONG len)
    {
        BCRYPT_ALG_HANDLE alg = nullptr;
        NTSTATUS status = BCryptOpenAlgorithmProvider(
            &alg, BCRYPT_RNG_ALGORITHM, nullptr, 0);
        if (!NT_SUCCESS(status)) return status;

        status = BCryptGenRandom(alg, buf, len, 0);
        BCryptCloseAlgorithmProvider(alg, 0);
        return status;
    }
}
