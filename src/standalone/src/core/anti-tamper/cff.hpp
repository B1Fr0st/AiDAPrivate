#pragma once


#include <cstdint>
#include <intrin.h>

namespace anti_tamper {
namespace cff {

namespace detail {


    constexpr uint64_t fnv1a_seed = 0xCBF29CE484222325ULL;
    constexpr uint64_t fnv1a_prime = 0x100000001B3ULL;

    constexpr uint64_t ct_fnv1a(const char* s, uint64_t h = fnv1a_seed)
    {
        return *s ? ct_fnv1a(s + 1, (h ^ static_cast<uint64_t>(*s)) * fnv1a_prime) : h;
    }


    struct cff_ctx_t
    {
        uint64_t key;
        uint64_t scramble;
        uint64_t noise;
        uint64_t inv_scramble;
    };


    constexpr uint64_t mod_inverse_64(uint64_t a)
    {
        uint64_t x = a;
        for (int i = 0; i < 6; ++i)
            x *= 2 - a * x;
        return x;
    }

    __forceinline cff_ctx_t init_ctx(uint64_t tag_hash)
    {
        cff_ctx_t ctx{};
        uint64_t entropy = __rdtsc() ^ tag_hash;


        entropy += 0x9E3779B97F4A7C15ULL;
        uint64_t z = entropy;
        z = (z ^ (z >> 30)) * 0xBF58476D1CE4E5B9ULL;
        z = (z ^ (z >> 27)) * 0x94D049BB133111EBULL;
        ctx.key = z ^ (z >> 31);

        entropy += 0x9E3779B97F4A7C15ULL;
        z = entropy;
        z = (z ^ (z >> 30)) * 0xBF58476D1CE4E5B9ULL;
        z = (z ^ (z >> 27)) * 0x94D049BB133111EBULL;
        ctx.scramble = (z ^ (z >> 31)) | 1ULL;

        entropy += 0x9E3779B97F4A7C15ULL;
        z = entropy;
        z = (z ^ (z >> 30)) * 0xBF58476D1CE4E5B9ULL;
        z = (z ^ (z >> 27)) * 0x94D049BB133111EBULL;
        ctx.noise = z ^ (z >> 31);

        ctx.inv_scramble = mod_inverse_64(ctx.scramble);
        return ctx;
    }

    __forceinline uint64_t encrypt_state(const cff_ctx_t& ctx, uint64_t real_state)
    {
        return ((real_state ^ ctx.key) * ctx.scramble) + ctx.noise;
    }

    __forceinline uint64_t decrypt_state(const cff_ctx_t& ctx, uint64_t enc_state)
    {
        return ((enc_state - ctx.noise) * ctx.inv_scramble) ^ ctx.key;
    }

}

}
}


#define CFF_TAG_HASH_(tag) (::anti_tamper::cff::detail::ct_fnv1a(#tag))

#define CFF_BEGIN(tag)                                                           \
    {                                                                            \
        auto _cff_ctx_##tag = ::anti_tamper::cff::detail::init_ctx(              \
            CFF_TAG_HASH_(tag));                                                 \
        volatile uint64_t _cff_sv_##tag =                                        \
            ::anti_tamper::cff::detail::encrypt_state(_cff_ctx_##tag, 0);        \
        volatile bool _cff_run_##tag = true;                                     \
        while (_cff_run_##tag) {                                                 \
            uint64_t _cff_dec_##tag =                                            \
                ::anti_tamper::cff::detail::decrypt_state(                       \
                    _cff_ctx_##tag, _cff_sv_##tag);                              \
            switch (_cff_dec_##tag) {

#define CFF_STATE(tag, N)                                                        \
            break;                                                               \
            case static_cast<uint64_t>(N):

#define CFF_GOTO(tag, N)                                                         \
            _cff_sv_##tag = ::anti_tamper::cff::detail::encrypt_state(           \
                _cff_ctx_##tag, static_cast<uint64_t>(N));                       \
            continue

#define CFF_END(tag)                                                             \
            break;                                                               \
            default:                                                             \
                _cff_run_##tag = false;                                           \
                break;                                                           \
            }                                                                    \
        }                                                                        \
    }


#define CFF_EXIT(tag)                                                            \
            _cff_run_##tag = false;                                              \
            break
