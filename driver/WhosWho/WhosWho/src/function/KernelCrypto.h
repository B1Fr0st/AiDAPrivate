#pragma once

#include <ntifs.h>
#include <bcrypt.h>

namespace kernel_crypto {

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

    __forceinline NTSTATUS bcrypt_hmac_sha256(
        const UINT8* key, ULONG key_len,
        const UINT8* data, ULONG data_len,
        UINT8 hash_out[SHA256_DIGEST_SIZE])
    {
        BCRYPT_ALG_HANDLE alg = nullptr;
        NTSTATUS status = BCryptOpenAlgorithmProvider(
            &alg, BCRYPT_SHA256_ALGORITHM, nullptr, BCRYPT_ALG_HANDLE_HMAC_FLAG);
        if (!NT_SUCCESS(status)) return status;

        BCRYPT_HASH_HANDLE hh = nullptr;
        status = BCryptCreateHash(alg, &hh, nullptr, 0,
            const_cast<UINT8*>(key), key_len, 0);
        if (!NT_SUCCESS(status)) {
            BCryptCloseAlgorithmProvider(alg, 0);
            return status;
        }

        status = BCryptHashData(hh, const_cast<UINT8*>(data), data_len, 0);
        if (NT_SUCCESS(status))
            status = BCryptFinishHash(hh, hash_out, SHA256_DIGEST_SIZE, 0);

        BCryptDestroyHash(hh);
        BCryptCloseAlgorithmProvider(alg, 0);
        return status;
    }

    __forceinline NTSTATUS bcrypt_aes256_gcm_encrypt(
        const UINT8 key[AES256_KEY_SIZE],
        const UINT8 nonce[GCM_NONCE_SIZE],
        const UINT8* aad, ULONG aad_len,
        const UINT8* plaintext, ULONG plaintext_len,
        UINT8* ciphertext_out,
        UINT8 tag_out[GCM_TAG_SIZE])
    {
        BCRYPT_ALG_HANDLE alg = nullptr;
        BCRYPT_KEY_HANDLE hk  = nullptr;

        NTSTATUS status = BCryptOpenAlgorithmProvider(
            &alg, BCRYPT_AES_ALGORITHM, nullptr, 0);
        if (!NT_SUCCESS(status)) return status;

        status = BCryptSetProperty(
            alg, BCRYPT_CHAINING_MODE,
            reinterpret_cast<PUCHAR>(const_cast<wchar_t*>(BCRYPT_CHAIN_MODE_GCM)),
            static_cast<ULONG>((wcslen(BCRYPT_CHAIN_MODE_GCM) + 1) * sizeof(wchar_t)),
            0);
        if (!NT_SUCCESS(status)) {
            BCryptCloseAlgorithmProvider(alg, 0);
            return status;
        }

        status = BCryptGenerateSymmetricKey(
            alg, &hk, nullptr, 0,
            const_cast<PUCHAR>(key), AES256_KEY_SIZE, 0);
        if (!NT_SUCCESS(status)) {
            BCryptCloseAlgorithmProvider(alg, 0);
            return status;
        }

        BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO info;
        BCRYPT_INIT_AUTH_MODE_INFO(info);
        info.pbNonce       = const_cast<PUCHAR>(nonce);
        info.cbNonce       = GCM_NONCE_SIZE;
        info.pbAuthData    = const_cast<PUCHAR>(aad);
        info.cbAuthData    = aad_len;
        info.pbTag         = tag_out;
        info.cbTag         = GCM_TAG_SIZE;

        ULONG bytes_done = 0;
        status = BCryptEncrypt(
            hk,
            const_cast<PUCHAR>(plaintext), plaintext_len,
            &info,
            nullptr, 0,
            ciphertext_out, plaintext_len,
            &bytes_done, 0);

        BCryptDestroyKey(hk);
        BCryptCloseAlgorithmProvider(alg, 0);
        return status;
    }

    __forceinline NTSTATUS bcrypt_aes256_gcm_decrypt(
        const UINT8 key[AES256_KEY_SIZE],
        const UINT8 nonce[GCM_NONCE_SIZE],
        const UINT8* aad, ULONG aad_len,
        const UINT8* ciphertext, ULONG ciphertext_len,
        const UINT8 tag[GCM_TAG_SIZE],
        UINT8* plaintext_out)
    {
        BCRYPT_ALG_HANDLE alg = nullptr;
        BCRYPT_KEY_HANDLE hk  = nullptr;

        NTSTATUS status = BCryptOpenAlgorithmProvider(
            &alg, BCRYPT_AES_ALGORITHM, nullptr, 0);
        if (!NT_SUCCESS(status)) return status;

        status = BCryptSetProperty(
            alg, BCRYPT_CHAINING_MODE,
            reinterpret_cast<PUCHAR>(const_cast<wchar_t*>(BCRYPT_CHAIN_MODE_GCM)),
            static_cast<ULONG>((wcslen(BCRYPT_CHAIN_MODE_GCM) + 1) * sizeof(wchar_t)),
            0);
        if (!NT_SUCCESS(status)) {
            BCryptCloseAlgorithmProvider(alg, 0);
            return status;
        }

        status = BCryptGenerateSymmetricKey(
            alg, &hk, nullptr, 0,
            const_cast<PUCHAR>(key), AES256_KEY_SIZE, 0);
        if (!NT_SUCCESS(status)) {
            BCryptCloseAlgorithmProvider(alg, 0);
            return status;
        }

        BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO info;
        BCRYPT_INIT_AUTH_MODE_INFO(info);
        info.pbNonce       = const_cast<PUCHAR>(nonce);
        info.cbNonce       = GCM_NONCE_SIZE;
        info.pbAuthData    = const_cast<PUCHAR>(aad);
        info.cbAuthData    = aad_len;
        info.pbTag         = const_cast<PUCHAR>(tag);
        info.cbTag         = GCM_TAG_SIZE;

        ULONG bytes_done = 0;
        status = BCryptDecrypt(
            hk,
            const_cast<PUCHAR>(ciphertext), ciphertext_len,
            &info,
            nullptr, 0,
            plaintext_out, ciphertext_len,
            &bytes_done, 0);

        BCryptDestroyKey(hk);
        BCryptCloseAlgorithmProvider(alg, 0);
        return status;
    }

}
