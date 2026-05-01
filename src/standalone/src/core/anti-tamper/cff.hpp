#pragma once


#include <cstdint>
#include <cstring>
#include <intrin.h>
#include <windows.h>

#include <openssl/hmac.h>
#include <openssl/evp.h>
#include <openssl/sha.h>

namespace anti_tamper {
namespace cff {

namespace detail {


    constexpr uint64_t fnv1a_seed = 0xCBF29CE484222325ULL;
    constexpr uint64_t fnv1a_prime = 0x100000001B3ULL;

    constexpr uint64_t ct_fnv1a(const char* s, uint64_t h = fnv1a_seed)
    {
        return *s ? ct_fnv1a(s + 1, (h ^ static_cast<uint64_t>(*s)) * fnv1a_prime) : h;
    }


    static constexpr uint32_t cff_max_states = 64;


    struct cff_ctx_t
    {
        uint8_t  state_key[32];
        uint64_t counter;
        uint64_t tag_hash;
    };


    inline uint64_t cff_session_root_seed()
    {
        static uint64_t s_root = 0;
        static bool     s_init = false;
        if (!s_init)
        {
            uint8_t buf[32] = {};
            BCryptGenRandom(nullptr, buf, sizeof(buf), BCRYPT_USE_SYSTEM_PREFERRED_RNG);
            uint64_t a = 0, b = 0, c = 0, d = 0;
            memcpy(&a, buf,      8);
            memcpy(&b, buf +  8, 8);
            memcpy(&c, buf + 16, 8);
            memcpy(&d, buf + 24, 8);
            uint64_t mix = a ^ _rotl64(b, 17) ^ _rotr64(c, 13) ^ _rotl64(d, 29);
            mix ^= __rdtsc();
            mix ^= static_cast<uint64_t>(GetCurrentProcessId()) << 32;
            s_root = mix ? mix : 0x9E3779B97F4A7C15ULL;
            s_init = true;
        }
        return s_root;
    }

    __forceinline bool cff_hmac_sha256(const uint8_t* key, uint32_t key_len,
                                       const uint8_t* data, uint32_t data_len,
                                       uint8_t out[32])
    {
        unsigned int olen = 0;
        const uint8_t* r = ::HMAC(EVP_sha256(), key, static_cast<int>(key_len),
                                  data, static_cast<size_t>(data_len),
                                  out, &olen);
        return r != nullptr && olen == 32;
    }

    __forceinline cff_ctx_t init_ctx(uint64_t tag_hash)
    {
        cff_ctx_t ctx{};
        ctx.tag_hash = tag_hash;
        ctx.counter  = 0;

        uint64_t root  = cff_session_root_seed();
        uint8_t  ikm[24];
        memcpy(ikm,      &root,     8);
        memcpy(ikm + 8,  &tag_hash, 8);
        static const uint8_t info_lit[8] = {
            'a','i','d','a','C','F','F','k'
        };
        memcpy(ikm + 16, info_lit, 8);

        uint8_t zero_salt[32] = {};
        uint8_t prk[32];
        cff_hmac_sha256(zero_salt, sizeof(zero_salt), ikm, sizeof(ikm), prk);

        uint8_t expand[33];
        memcpy(expand, info_lit, 8);
        memcpy(expand + 8, &tag_hash, 8);
        memcpy(expand + 16, &root, 8);
        expand[24] = 0x73;
        expand[25] = 0x6B;
        expand[26] = 0x65;
        expand[27] = 0x79;
        expand[28] = 0x5F;
        expand[29] = 0x76;
        expand[30] = 0x32;
        expand[31] = 0x00;
        expand[32] = 0x01;
        cff_hmac_sha256(prk, 32, expand, sizeof(expand), ctx.state_key);

        SecureZeroMemory(prk,    sizeof(prk));
        SecureZeroMemory(ikm,    sizeof(ikm));
        SecureZeroMemory(expand, sizeof(expand));
        return ctx;
    }

    __forceinline uint64_t cff_compute_tag(const cff_ctx_t& ctx,
                                           uint64_t plain_state,
                                           uint64_t counter)
    {
        uint8_t msg[24];
        memcpy(msg,      &plain_state, 8);
        memcpy(msg + 8,  &counter,     8);
        memcpy(msg + 16, &ctx.tag_hash, 8);
        uint8_t mac[32];
        cff_hmac_sha256(ctx.state_key, 32, msg, sizeof(msg), mac);
        uint64_t tag;
        memcpy(&tag, mac, 8);
        SecureZeroMemory(mac, sizeof(mac));
        SecureZeroMemory(msg, sizeof(msg));
        return tag;
    }

    __forceinline uint64_t encrypt_state(cff_ctx_t& ctx, uint64_t real_state)
    {
        uint64_t enc = cff_compute_tag(ctx, real_state, ctx.counter);
        ctx.counter += 1;
        return enc;
    }

    __forceinline uint64_t decrypt_state(cff_ctx_t& ctx, uint64_t enc_state)
    {
        if (ctx.counter == 0)
            return UINT64_MAX;
        uint64_t used_counter = ctx.counter - 1;
        for (uint32_t s = 0; s < cff_max_states; ++s)
        {
            uint64_t cand = cff_compute_tag(ctx, static_cast<uint64_t>(s), used_counter);
            if (cand == enc_state)
                return static_cast<uint64_t>(s);
        }
        return UINT64_MAX;
    }

    __forceinline uint64_t encrypt_state_iv(cff_ctx_t& ctx,
                                             uint64_t real_state,
                                             uint64_t iteration_iv)
    {
        uint8_t msg[32];
        memcpy(msg,      &real_state,     8);
        memcpy(msg + 8,  &ctx.counter,    8);
        memcpy(msg + 16, &ctx.tag_hash,   8);
        memcpy(msg + 24, &iteration_iv,   8);
        uint8_t mac[32];
        cff_hmac_sha256(ctx.state_key, 32, msg, sizeof(msg), mac);
        uint64_t enc;
        memcpy(&enc, mac, 8);
        SecureZeroMemory(mac, sizeof(mac));
        SecureZeroMemory(msg, sizeof(msg));
        ctx.counter += 1;
        return enc;
    }

    __forceinline uint64_t decrypt_state_iv(cff_ctx_t& ctx,
                                             uint64_t enc_state,
                                             uint64_t iteration_iv)
    {
        if (ctx.counter == 0)
            return UINT64_MAX;
        uint64_t used_counter = ctx.counter - 1;
        for (uint32_t s = 0; s < cff_max_states; ++s)
        {
            uint8_t msg[32];
            uint64_t plain = static_cast<uint64_t>(s);
            memcpy(msg,      &plain,         8);
            memcpy(msg + 8,  &used_counter,  8);
            memcpy(msg + 16, &ctx.tag_hash,  8);
            memcpy(msg + 24, &iteration_iv,  8);
            uint8_t mac[32];
            cff_hmac_sha256(ctx.state_key, 32, msg, sizeof(msg), mac);
            uint64_t cand;
            memcpy(&cand, mac, 8);
            SecureZeroMemory(mac, sizeof(mac));
            SecureZeroMemory(msg, sizeof(msg));
            if (cand == enc_state)
                return static_cast<uint64_t>(s);
        }
        return UINT64_MAX;
    }

    __forceinline uint64_t fresh_iteration_iv()
    {
        uint64_t iv = __rdtsc();
        volatile uint64_t local_anchor = 0;
        iv ^= reinterpret_cast<uint64_t>(&local_anchor);
        iv ^= static_cast<uint64_t>(__readgsqword(0x48));
        iv = _rotl64(iv, 31);
        iv *= 0x9E3779B97F4A7C15ULL;
        iv ^= iv >> 33;
        iv *= 0xBF58476D1CE4E5B9ULL;
        iv ^= iv >> 27;
        return iv;
    }

    __forceinline uint64_t pointer_xor_token(const cff_ctx_t& ctx)
    {
        uint8_t msg[16];
        uint64_t lit = 0x53'74'61'63'6B'50'74'72ULL;
        memcpy(msg,     &ctx.tag_hash, 8);
        memcpy(msg + 8, &lit,           8);
        uint8_t mac[32];
        cff_hmac_sha256(ctx.state_key, 32, msg, sizeof(msg), mac);
        uint64_t out;
        memcpy(&out, mac, 8);
        SecureZeroMemory(mac, sizeof(mac));
        SecureZeroMemory(msg, sizeof(msg));
        return out;
    }

    __forceinline uint64_t nested_dispatch_step(const cff_ctx_t& ctx,
                                                  uint64_t plain_state,
                                                  uint64_t iteration_iv)
    {
        uint8_t msg[24];
        uint64_t domain = 0x4E'45'53'54'45'44'56'4DULL;
        memcpy(msg,      &domain,        8);
        memcpy(msg + 8,  &plain_state,   8);
        memcpy(msg + 16, &iteration_iv,  8);
        uint8_t mac[32];
        cff_hmac_sha256(ctx.state_key, 32, msg, sizeof(msg), mac);
        uint64_t r;
        memcpy(&r, mac, 8);
        SecureZeroMemory(mac, sizeof(mac));
        SecureZeroMemory(msg, sizeof(msg));
        return r ^ ctx.tag_hash;
    }

    __forceinline uint64_t multi_tag_fnv1a(const char* file_str,
                                            int line_num,
                                            const char* fn_str)
    {
        uint64_t h = fnv1a_seed;
        while (*file_str)
        {
            h ^= static_cast<uint64_t>(*file_str++);
            h *= fnv1a_prime;
        }
        h ^= static_cast<uint64_t>(':');
        h *= fnv1a_prime;
        uint64_t l = static_cast<uint64_t>(line_num);
        for (int i = 0; i < 8; ++i)
        {
            h ^= (l >> (i * 8)) & 0xFFu;
            h *= fnv1a_prime;
        }
        h ^= static_cast<uint64_t>(':');
        h *= fnv1a_prime;
        while (*fn_str)
        {
            h ^= static_cast<uint64_t>(*fn_str++);
            h *= fnv1a_prime;
        }
        return h;
    }

}

}
}


#define CFF_TAG_HASH_(tag)                                                       \
    (::anti_tamper::cff::detail::multi_tag_fnv1a(__FILE__, __LINE__, #tag))

#define CFF_BEGIN(tag)                                                           \
    {                                                                            \
        auto _cff_ctx_##tag = ::anti_tamper::cff::detail::init_ctx(              \
            CFF_TAG_HASH_(tag));                                                 \
        volatile uint64_t _cff_iv_##tag =                                        \
            ::anti_tamper::cff::detail::fresh_iteration_iv();                    \
        volatile uint64_t _cff_xor_##tag =                                       \
            ::anti_tamper::cff::detail::pointer_xor_token(_cff_ctx_##tag);       \
        volatile uint64_t _cff_sv_raw_##tag =                                    \
            ::anti_tamper::cff::detail::encrypt_state_iv(                        \
                _cff_ctx_##tag, 0, _cff_iv_##tag);                               \
        volatile uint64_t _cff_sv_##tag =                                        \
            _cff_sv_raw_##tag ^ _cff_xor_##tag;                                  \
        volatile bool _cff_run_##tag = true;                                     \
        while (_cff_run_##tag) {                                                 \
            uint64_t _cff_dec_blob_##tag =                                       \
                static_cast<uint64_t>(_cff_sv_##tag) ^                           \
                static_cast<uint64_t>(_cff_xor_##tag);                           \
            uint64_t _cff_dec_##tag =                                            \
                ::anti_tamper::cff::detail::decrypt_state_iv(                    \
                    _cff_ctx_##tag, _cff_dec_blob_##tag,                         \
                    static_cast<uint64_t>(_cff_iv_##tag));                       \
            volatile uint64_t _cff_nest_##tag =                                  \
                ::anti_tamper::cff::detail::nested_dispatch_step(                \
                    _cff_ctx_##tag, _cff_dec_##tag,                              \
                    static_cast<uint64_t>(_cff_iv_##tag));                       \
            (void)_cff_nest_##tag;                                               \
            _cff_iv_##tag =                                                      \
                ::anti_tamper::cff::detail::fresh_iteration_iv();                \
            _cff_xor_##tag =                                                     \
                ::anti_tamper::cff::detail::pointer_xor_token(_cff_ctx_##tag) ^  \
                static_cast<uint64_t>(_cff_iv_##tag);                            \
            switch (_cff_dec_##tag) {

#define CFF_STATE(tag, N)                                                        \
            break;                                                               \
            case static_cast<uint64_t>(N):

#define CFF_GOTO(tag, N)                                                         \
            {                                                                    \
                uint64_t _cff_raw_##tag =                                        \
                    ::anti_tamper::cff::detail::encrypt_state_iv(                \
                        _cff_ctx_##tag, static_cast<uint64_t>(N),                \
                        static_cast<uint64_t>(_cff_iv_##tag));                   \
                _cff_sv_##tag = _cff_raw_##tag ^                                 \
                                 static_cast<uint64_t>(_cff_xor_##tag);          \
            }                                                                    \
            continue

#define CFF_END(tag)                                                             \
            break;                                                               \
            default:                                                             \
                _cff_run_##tag = false;                                           \
                break;                                                           \
            }                                                                    \
        }                                                                        \
        ::SecureZeroMemory(_cff_ctx_##tag.state_key,                             \
                           sizeof(_cff_ctx_##tag.state_key));                    \
    }


#define CFF_EXIT(tag)                                                            \
            _cff_run_##tag = false;                                              \
            break
