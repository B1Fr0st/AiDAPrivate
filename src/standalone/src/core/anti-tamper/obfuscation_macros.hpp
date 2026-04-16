#pragma once

#include <cstdint>
#include <intrin.h>
#include "cff.hpp"
#include "metamorphic.hpp"

namespace anti_tamper {
namespace obfuscation {

namespace detail {

    constexpr uint64_t compile_seed(const char* file, int line)
    {
        uint64_t h = 0xCBF29CE484222325ULL;
        while (*file) {
            h ^= static_cast<uint64_t>(*file++);
            h *= 0x100000001B3ULL;
        }
        h ^= static_cast<uint64_t>(line) * 0x9E3779B97F4A7C15ULL;
        return h;
    }

    __forceinline void junk_compute(volatile uint64_t& sink, uint64_t seed)
    {
        volatile uint64_t a = seed ^ __rdtsc();
        volatile uint64_t b = a * 0x5DEECE66DULL + 0xBULL;
        volatile uint64_t c = (b >> 16) ^ (a << 3);
        sink = c ^ (b + a);
    }

    __forceinline bool opaque_true(uint64_t seed)
    {
        volatile uint64_t x = seed | 1;
        return ((x * x) & 1) != 0;
    }

    __forceinline bool opaque_false(uint64_t seed)
    {
        volatile uint64_t x = (seed | 2) & ~1ULL;
        return (x & 1) != 0;
    }

}

}
}


#define OBFUSCATE_JUNK(tag)                                                      \
    do {                                                                          \
        volatile uint64_t _jnk_sink_##tag = 0;                                   \
        ::anti_tamper::obfuscation::detail::junk_compute(                         \
            _jnk_sink_##tag,                                                     \
            ::anti_tamper::obfuscation::detail::compile_seed(__FILE__, __LINE__));\
        if (::anti_tamper::obfuscation::detail::opaque_false(                     \
                _jnk_sink_##tag)) {                                              \
            volatile int _dead_##tag = 0;                                        \
            _dead_##tag = static_cast<int>(_jnk_sink_##tag);                     \
            (void)_dead_##tag;                                                   \
        }                                                                        \
    } while (0)


#define MBA_TRANSFORM(a, b)                                                      \
    ::anti_tamper::metamorphic::mba::keyed_xor(                                  \
        static_cast<uint64_t>(a),                                                \
        static_cast<uint64_t>(b),                                                \
        static_cast<uint64_t>(__rdtsc()))


#define OBFUSCATE_FUNCTION_BEGIN(tag)                                             \
    OBFUSCATE_JUNK(tag##_pre);                                                   \
    CFF_BEGIN(tag)                                                               \

#define OBFUSCATE_FUNCTION_STATE(tag, N)                                          \
    OBFUSCATE_JUNK(tag##_s##N);                                                  \
    CFF_STATE(tag, N)

#define OBFUSCATE_FUNCTION_GOTO(tag, N)                                           \
    CFF_GOTO(tag, N)

#define OBFUSCATE_FUNCTION_END(tag)                                               \
    CFF_END(tag)                                                                 \
    OBFUSCATE_JUNK(tag##_post);


#define OPAQUE_GUARD(tag, code)                                                   \
    do {                                                                          \
        uint64_t _og_seed_##tag =                                                \
            ::anti_tamper::obfuscation::detail::compile_seed(__FILE__, __LINE__); \
        if (::anti_tamper::obfuscation::detail::opaque_true(_og_seed_##tag)) {   \
            code;                                                                \
        }                                                                        \
    } while (0)


#define DEAD_BRANCH(tag)                                                          \
    if (::anti_tamper::obfuscation::detail::opaque_false(                         \
            ::anti_tamper::obfuscation::detail::compile_seed(                     \
                __FILE__, __LINE__)))


#define MBA_ADD(a, b)                                                             \
    (static_cast<uint64_t>(a) + static_cast<uint64_t>(b) +                       \
     (MBA_TRANSFORM(a, b) & 0) )

#define MBA_SUB(a, b)                                                             \
    (static_cast<uint64_t>(a) - static_cast<uint64_t>(b) +                       \
     (MBA_TRANSFORM(a, b) & 0) )
