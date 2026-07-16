#pragma once


#include <cstdint>
#include <cstring>
#include <intrin.h>
#include <windows.h>

#include <openssl/hmac.h>
#include <openssl/evp.h>
#include <openssl/sha.h>

#include "anti_symbolic.hpp"

namespace anti_tamper {
namespace cff {

namespace detail {


    constexpr uint64_t fnv1a_seed = 0xCBF29CE484222325ULL;
    constexpr uint64_t fnv1a_prime = 0x100000001B3ULL;

    constexpr uint64_t ct_fnv1a(const char* s, uint64_t h = fnv1a_seed)
    {
        return *s ? ct_fnv1a(s + 1, (h ^ static_cast<uint64_t>(*s)) * fnv1a_prime) : h;
    }


    static constexpr uint32_t cff_max_states = 256;


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


namespace anti_tamper {
namespace path_explosion {

    constexpr uint32_t DISPATCH_TABLE_SIZE = 256;
    constexpr uint32_t DISPATCH_DEPTH = 4;

    struct dispatch_entry_t
    {
        uint64_t (*handler)(uint64_t state, const anti_symbolic::env_bundle_t& env);
        uint64_t next_state_encrypt_key;
        uint8_t  handler_index;
        uint8_t  _pad[7];
    };

    struct dispatch_table_t
    {
        dispatch_entry_t entries[DISPATCH_TABLE_SIZE];
        uint64_t table_seed;
        uint64_t server_nonce;
    };

namespace detail_pe {

    constexpr uint32_t NUM_DISTINCT_HANDLERS = 32;

    __forceinline uint64_t handler_real_00(uint64_t state, const anti_symbolic::env_bundle_t& env)
    {
        uint64_t a = (state ^ env.server_hmac) + env.kernel_attestation;
        uint64_t b = a ^ (a >> 23);
        return b + 0x9E3779B97F4A7C15ULL;
    }

    __forceinline uint64_t handler_real_01(uint64_t state, const anti_symbolic::env_bundle_t& env)
    {
        uint64_t a = state + env.rdtsc_delta;
        uint64_t b = a ^ (a << 13);
        b ^= b >> 7;
        b ^= b << 17;
        return b ^ env.process_state;
    }

    __forceinline uint64_t handler_real_02(uint64_t state, const anti_symbolic::env_bundle_t& env)
    {
        uint64_t a = (state | env.filesystem_state) - (state & env.filesystem_state);
        uint64_t b = (a ^ env.server_hmac) + 2 * (a & env.server_hmac);
        return b;
    }

    __forceinline uint64_t handler_real_03(uint64_t state, const anti_symbolic::env_bundle_t& env)
    {
        uint64_t a = (state + env.kernel_attestation) - (state | env.kernel_attestation);
        uint64_t b = (a + env.rdtsc_delta) - (a & env.rdtsc_delta);
        return b;
    }

    __forceinline uint64_t handler_real_04(uint64_t state, const anti_symbolic::env_bundle_t& env)
    {
        uint64_t a = state ^ env.aggregate;
        a = _rotl64(a, 17);
        a *= 0xBF58476D1CE4E5B9ULL;
        a ^= a >> 31;
        return a;
    }

    __forceinline uint64_t handler_real_05(uint64_t state, const anti_symbolic::env_bundle_t& env)
    {
        uint64_t a = (state | env.process_state) - (state & env.process_state);
        a = (a + env.server_hmac) - (a | env.server_hmac);
        return a;
    }

    __forceinline uint64_t handler_real_06(uint64_t state, const anti_symbolic::env_bundle_t& env)
    {
        uint64_t a = state ^ _rotl64(env.rdtsc_delta, 23);
        a = (a ^ env.kernel_attestation) + 2 * (a & env.kernel_attestation);
        return a;
    }

    __forceinline uint64_t handler_real_07(uint64_t state, const anti_symbolic::env_bundle_t& env)
    {
        uint64_t a = (state + env.filesystem_state) - (state | env.filesystem_state);
        a ^= _rotr64(env.aggregate, 11);
        return a;
    }

    __forceinline uint64_t handler_decoy_08(uint64_t state, const anti_symbolic::env_bundle_t& env)
    {
        volatile uint64_t s = state ^ env.process_state;
        s = _rotl64(s, 13) * 0x100000001B3ULL;
        s ^= s >> 33;
        return s;
    }

    __forceinline uint64_t handler_decoy_09(uint64_t state, const anti_symbolic::env_bundle_t& env)
    {
        volatile uint64_t s = state + env.rdtsc_delta;
        s = _rotr64(s, 7) ^ 0x9E3779B97F4A7C15ULL;
        return s;
    }

    __forceinline uint64_t handler_decoy_10(uint64_t state, const anti_symbolic::env_bundle_t& env)
    {
        volatile uint64_t s = state ^ env.kernel_attestation;
        s ^= s << 13;
        s ^= s >> 7;
        s ^= s << 17;
        return s;
    }

    __forceinline uint64_t handler_decoy_11(uint64_t state, const anti_symbolic::env_bundle_t& env)
    {
        volatile uint64_t s = (state | env.server_hmac) + (state & env.server_hmac);
        s = _rotl64(s, 31);
        return s;
    }

    __forceinline uint64_t handler_decoy_12(uint64_t state, const anti_symbolic::env_bundle_t& env)
    {
        volatile uint64_t s = state * 0xBF58476D1CE4E5B9ULL;
        s ^= env.filesystem_state;
        s ^= s >> 27;
        return s;
    }

    __forceinline uint64_t handler_decoy_13(uint64_t state, const anti_symbolic::env_bundle_t& env)
    {
        volatile uint64_t s = state ^ env.aggregate;
        s *= 0x94D049BB133111EBULL;
        s ^= s >> 31;
        return s;
    }

    __forceinline uint64_t handler_decoy_14(uint64_t state, const anti_symbolic::env_bundle_t& env)
    {
        volatile uint64_t s = (state ^ env.rdtsc_delta) + env.process_state;
        s = _rotr64(s, 23);
        return s;
    }

    __forceinline uint64_t handler_decoy_15(uint64_t state, const anti_symbolic::env_bundle_t& env)
    {
        volatile uint64_t s = state + (env.server_hmac << 1);
        s ^= env.kernel_attestation;
        return s;
    }

    __forceinline uint64_t handler_decoy_16(uint64_t state, const anti_symbolic::env_bundle_t& env)
    {
        volatile uint64_t s = state ^ _rotl64(env.filesystem_state, 19);
        s = s * 0x100000001B3ULL;
        return s;
    }

    __forceinline uint64_t handler_decoy_17(uint64_t state, const anti_symbolic::env_bundle_t& env)
    {
        volatile uint64_t s = state - env.process_state;
        s ^= _rotr64(env.aggregate, 13);
        return s;
    }

    __forceinline uint64_t handler_decoy_18(uint64_t state, const anti_symbolic::env_bundle_t& env)
    {
        volatile uint64_t s = (state & env.rdtsc_delta) | (~state & env.kernel_attestation);
        return s;
    }

    __forceinline uint64_t handler_decoy_19(uint64_t state, const anti_symbolic::env_bundle_t& env)
    {
        volatile uint64_t s = state ^ (env.server_hmac >> 17);
        s = _rotl64(s, 29);
        return s;
    }

    __forceinline uint64_t handler_decoy_20(uint64_t state, const anti_symbolic::env_bundle_t& env)
    {
        volatile uint64_t s = state + env.aggregate;
        s = (s ^ (s >> 30)) * 0xBF58476D1CE4E5B9ULL;
        return s;
    }

    __forceinline uint64_t handler_decoy_21(uint64_t state, const anti_symbolic::env_bundle_t& env)
    {
        volatile uint64_t s = state ^ (env.process_state << 7);
        s ^= env.rdtsc_delta;
        return s;
    }

    __forceinline uint64_t handler_decoy_22(uint64_t state, const anti_symbolic::env_bundle_t& env)
    {
        volatile uint64_t s = (state + env.kernel_attestation) ^ env.filesystem_state;
        s = _rotr64(s, 5);
        return s;
    }

    __forceinline uint64_t handler_decoy_23(uint64_t state, const anti_symbolic::env_bundle_t& env)
    {
        volatile uint64_t s = state * (env.server_hmac | 1ULL);
        s ^= s >> 33;
        return s;
    }

    __forceinline uint64_t handler_decoy_24(uint64_t state, const anti_symbolic::env_bundle_t& env)
    {
        volatile uint64_t s = state ^ _rotl64(env.aggregate, 37);
        s += env.rdtsc_delta;
        return s;
    }

    __forceinline uint64_t handler_decoy_25(uint64_t state, const anti_symbolic::env_bundle_t& env)
    {
        volatile uint64_t s = (state | env.process_state) ^ env.server_hmac;
        s *= 0x9E3779B97F4A7C15ULL;
        return s;
    }

    __forceinline uint64_t handler_decoy_26(uint64_t state, const anti_symbolic::env_bundle_t& env)
    {
        volatile uint64_t s = state ^ (env.filesystem_state >> 11);
        s = _rotl64(s, 43);
        return s;
    }

    __forceinline uint64_t handler_decoy_27(uint64_t state, const anti_symbolic::env_bundle_t& env)
    {
        volatile uint64_t s = state + (env.kernel_attestation ^ env.process_state);
        s ^= s << 13;
        s ^= s >> 7;
        return s;
    }

    __forceinline uint64_t handler_decoy_28(uint64_t state, const anti_symbolic::env_bundle_t& env)
    {
        volatile uint64_t s = state ^ (env.rdtsc_delta << 3);
        s = (s | env.aggregate) - (s & env.aggregate);
        return s;
    }

    __forceinline uint64_t handler_decoy_29(uint64_t state, const anti_symbolic::env_bundle_t& env)
    {
        volatile uint64_t s = state * 0x94D049BB133111EBULL;
        s += (env.server_hmac ^ env.filesystem_state);
        return s;
    }

    __forceinline uint64_t handler_decoy_30(uint64_t state, const anti_symbolic::env_bundle_t& env)
    {
        volatile uint64_t s = state ^ env.aggregate;
        s = _rotr64(s, 19) * 0xBF58476D1CE4E5B9ULL;
        s ^= s >> 31;
        return s;
    }

    __forceinline uint64_t handler_decoy_31(uint64_t state, const anti_symbolic::env_bundle_t& env)
    {
        volatile uint64_t s = (state + env.process_state) ^ env.kernel_attestation;
        s ^= s >> 27;
        s *= 0x100000001B3ULL;
        return s;
    }

    using handler_fn_t = uint64_t (*)(uint64_t, const anti_symbolic::env_bundle_t&);

    inline handler_fn_t g_handler_table[NUM_DISTINCT_HANDLERS] = {
        handler_real_00, handler_real_01, handler_real_02, handler_real_03,
        handler_real_04, handler_real_05, handler_real_06, handler_real_07,
        handler_decoy_08, handler_decoy_09, handler_decoy_10, handler_decoy_11,
        handler_decoy_12, handler_decoy_13, handler_decoy_14, handler_decoy_15,
        handler_decoy_16, handler_decoy_17, handler_decoy_18, handler_decoy_19,
        handler_decoy_20, handler_decoy_21, handler_decoy_22, handler_decoy_23,
        handler_decoy_24, handler_decoy_25, handler_decoy_26, handler_decoy_27,
        handler_decoy_28, handler_decoy_29, handler_decoy_30, handler_decoy_31,
    };

    __forceinline uint64_t encrypt_state_simple(uint64_t state, uint64_t key)
    {
        uint8_t msg[16];
        std::memcpy(msg, &state, 8);
        std::memcpy(msg + 8, &key, 8);
        uint8_t hash[32] = {};
        anti_symbolic::detail::bcrypt_sha256(msg, sizeof(msg), hash);
        uint64_t enc;
        std::memcpy(&enc, hash, 8);
        SecureZeroMemory(hash, sizeof(hash));
        SecureZeroMemory(msg, sizeof(msg));
        return enc;
    }

    __forceinline void fisher_yates_shuffle(
        uint8_t arr[DISPATCH_TABLE_SIZE],
        uint64_t seed)
    {
        for (uint32_t i = 0; i < DISPATCH_TABLE_SIZE; ++i)
            arr[i] = static_cast<uint8_t>(i);

        uint64_t st = seed;
        for (int i = DISPATCH_TABLE_SIZE - 1; i > 0; --i)
        {
            st ^= st << 13;
            st ^= st >> 7;
            st ^= st << 17;
            int j = static_cast<int>(st % static_cast<uint64_t>(i + 1));
            uint8_t tmp = arr[i];
            arr[i] = arr[j];
            arr[j] = tmp;
        }
    }

}

    inline void generate_dispatch_table(
        dispatch_table_t& table,
        uint64_t seed,
        uint64_t server_nonce)
    {
        table.table_seed = seed;
        table.server_nonce = server_nonce;

        uint8_t handler_assignments[DISPATCH_TABLE_SIZE];
        detail_pe::fisher_yates_shuffle(handler_assignments, seed ^ server_nonce);

        for (uint32_t i = 0; i < DISPATCH_TABLE_SIZE; ++i)
        {
            uint8_t hidx = handler_assignments[i] % detail_pe::NUM_DISTINCT_HANDLERS;
            table.entries[i].handler = detail_pe::g_handler_table[hidx];
            table.entries[i].handler_index = hidx;
            table.entries[i]._pad[0] = 0;
            table.entries[i]._pad[1] = 0;
            table.entries[i]._pad[2] = 0;
            table.entries[i]._pad[3] = 0;
            table.entries[i]._pad[4] = 0;
            table.entries[i]._pad[5] = 0;
            table.entries[i]._pad[6] = 0;

            uint8_t key_bytes[8];
            if (key_pipeline::derive_with_info(
                    "aida.path_explosion.dispatch",
                    nullptr, 0,
                    reinterpret_cast<const uint8_t*>(&i), sizeof(i),
                    key_bytes, sizeof(key_bytes)))
            {
                std::memcpy(&table.entries[i].next_state_encrypt_key, key_bytes, 8);
                SecureZeroMemory(key_bytes, sizeof(key_bytes));
            }
            else
            {
                table.entries[i].next_state_encrypt_key =
                    0x9E3779B97F4A7C15ULL ^ (static_cast<uint64_t>(i) * 0x100000001B3ULL);
            }
        }

        SecureZeroMemory(handler_assignments, sizeof(handler_assignments));
    }

    inline uint64_t run_nested_dispatch(
        dispatch_table_t tables[DISPATCH_DEPTH],
        uint64_t initial_state,
        const anti_symbolic::env_bundle_t& env)
    {
        uint64_t client_secret = anti_symbolic::derive_client_secret();
        uint64_t state = initial_state;

        for (uint32_t d = 0; d < DISPATCH_DEPTH; ++d)
        {
            uint8_t block = anti_symbolic::hash_select_block(
                tables[d].server_nonce, client_secret, state);

            if (block >= DISPATCH_TABLE_SIZE)
                block = block % DISPATCH_TABLE_SIZE;

            uint64_t new_state = tables[d].entries[block].handler(state, env);
            new_state = detail_pe::encrypt_state_simple(
                new_state, tables[d].entries[block].next_state_encrypt_key);
            state = new_state;
        }

        return state;
    }

    constexpr uint32_t NON_CRITICAL_TABLE_SIZE = 16;
    constexpr uint32_t NON_CRITICAL_DEPTH = 2;

    inline uint64_t nc_handler_0(uint64_t s)  { return s ^ 0x9E3779B97F4A7C15ULL; }
    inline uint64_t nc_handler_1(uint64_t s)  { return s + 0xBF58476D1CE4E5B9ULL; }
    inline uint64_t nc_handler_2(uint64_t s)  { return _rotl64(s, 13); }
    inline uint64_t nc_handler_3(uint64_t s)  { return _rotr64(s, 7); }
    inline uint64_t nc_handler_4(uint64_t s)  { return s ^ (s >> 17); }
    inline uint64_t nc_handler_5(uint64_t s)  { return s * 0x94D049BB133111EBULL; }
    inline uint64_t nc_handler_6(uint64_t s)  { return s ^ 0x100000001B3ULL; }
    inline uint64_t nc_handler_7(uint64_t s)  { return (s | s) - (s & s); }
    inline uint64_t nc_handler_8(uint64_t s)  { return s + s; }
    inline uint64_t nc_handler_9(uint64_t s)  { return s ^ (s << 13); }
    inline uint64_t nc_handler_10(uint64_t s) { return s ^ (s >> 7); }
    inline uint64_t nc_handler_11(uint64_t s) { return s ^ (s << 17); }
    inline uint64_t nc_handler_12(uint64_t s) { return _rotl64(s, 31); }
    inline uint64_t nc_handler_13(uint64_t s) { return _rotr64(s, 23); }
    inline uint64_t nc_handler_14(uint64_t s) { return s ^ 0xDEADBEEFULL; }
    inline uint64_t nc_handler_15(uint64_t s) { return s + 0xCAFEBABEULL; }

    using nc_handler_fn_t = uint64_t (*)(uint64_t);

    inline nc_handler_fn_t g_nc_handlers[NON_CRITICAL_TABLE_SIZE] = {
        nc_handler_0, nc_handler_1, nc_handler_2, nc_handler_3,
        nc_handler_4, nc_handler_5, nc_handler_6, nc_handler_7,
        nc_handler_8, nc_handler_9, nc_handler_10, nc_handler_11,
        nc_handler_12, nc_handler_13, nc_handler_14, nc_handler_15,
    };

    inline uint64_t run_non_critical_dispatch(
        uint64_t initial_state,
        uint64_t server_nonce,
        uint64_t client_secret)
    {
        uint64_t state = initial_state;
        for (uint32_t d = 0; d < NON_CRITICAL_DEPTH; ++d)
        {
            uint8_t block = anti_symbolic::hash_select_block(
                server_nonce, client_secret, state) & 0x0F;
            state = g_nc_handlers[block](state);
        }
        return state;
    }

}


}
