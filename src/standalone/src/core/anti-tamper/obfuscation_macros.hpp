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
    ::anti_tamper::metamorphic::mba::keyed_add(                                  \
        static_cast<uint64_t>(a),                                                \
        static_cast<uint64_t>(b),                                                \
        static_cast<uint64_t>(__rdtsc()))

#define MBA_SUB(a, b)                                                             \
    ::anti_tamper::metamorphic::mba::keyed_add(                                  \
        static_cast<uint64_t>(a),                                                \
        (~static_cast<uint64_t>(b)) + 1ULL,                                      \
        static_cast<uint64_t>(__rdtsc()))


#define OBFUSCATE_JUNK_CRYPTO(tag)                                               \
    do {                                                                          \
        volatile uint64_t _j_k_##tag =                                           \
            ::anti_tamper::obfuscation::detail::compile_seed(__FILE__, __LINE__); \
        volatile uint64_t _j_v_##tag = _j_k_##tag ^ __rdtsc();                  \
        _j_v_##tag = _rotl64(_j_v_##tag, 13) * 0xBF58476D1CE4E5B9ULL;           \
        _j_v_##tag ^= _j_v_##tag >> 31;                                          \
        _j_v_##tag *= 0x94D049BB133111EBULL;                                     \
        volatile uint64_t _j_h_##tag = _j_v_##tag ^ (_j_v_##tag >> 27);         \
        if (::anti_tamper::obfuscation::detail::opaque_false(_j_h_##tag)) {      \
            volatile uint8_t _j_iv_##tag[16];                                    \
            for (int _ji = 0; _ji < 16; ++_ji)                                  \
                _j_iv_##tag[_ji] = static_cast<uint8_t>(_j_h_##tag >> (_ji & 7));\
            (void)_j_iv_##tag;                                                   \
        }                                                                        \
    } while (0)

#define OBFUSCATE_JUNK_API(tag)                                                  \
    do {                                                                          \
        volatile HMODULE _j_mod_##tag = nullptr;                                 \
        volatile FARPROC _j_proc_##tag = nullptr;                                \
        if (::anti_tamper::obfuscation::detail::opaque_false(                    \
                ::anti_tamper::obfuscation::detail::compile_seed(                 \
                    __FILE__, __LINE__))) {                                       \
            _j_mod_##tag = LoadLibraryA("advapi32.dll");                         \
            if (_j_mod_##tag)                                                    \
                _j_proc_##tag = GetProcAddress(_j_mod_##tag, "CryptGenRandom");  \
            (void)_j_proc_##tag;                                                 \
        }                                                                        \
    } while (0)

#define OBFUSCATE_JUNK_HASH(tag)                                                 \
    do {                                                                          \
        volatile uint64_t _j_s_##tag = __rdtsc();                                \
        volatile uint64_t _j_a_##tag = 0xCBF29CE484222325ULL;                    \
        for (volatile int _ji = 0; _ji < 8; ++_ji) {                            \
            _j_a_##tag ^= (_j_s_##tag >> (_ji * 8)) & 0xFF;                     \
            _j_a_##tag *= 0x100000001B3ULL;                                      \
        }                                                                        \
        if (::anti_tamper::obfuscation::detail::opaque_false(_j_a_##tag)) {      \
            volatile uint64_t _j_r_##tag = _j_a_##tag;                           \
            _j_r_##tag = (_j_r_##tag ^ (_j_r_##tag >> 30)) * 0xBF58476D1CE4E5B9ULL; \
            (void)_j_r_##tag;                                                    \
        }                                                                        \
    } while (0)

#define OBFUSCATE_JUNK_CPUID(tag)                                                \
    do {                                                                          \
        int _j_cpu_##tag[4] = {};                                                \
        __cpuid(_j_cpu_##tag, 0);                                                \
        volatile uint64_t _j_cv_##tag =                                          \
            static_cast<uint64_t>(_j_cpu_##tag[1]) ^                             \
            static_cast<uint64_t>(_j_cpu_##tag[2]);                              \
        if (::anti_tamper::obfuscation::detail::opaque_false(_j_cv_##tag)) {     \
            __cpuid(_j_cpu_##tag, 0x80000001);                                   \
            (void)_j_cpu_##tag;                                                  \
        }                                                                        \
    } while (0)

#define OBFUSCATE_JUNK_TIMING(tag)                                               \
    do {                                                                          \
        volatile uint64_t _j_t0_##tag = __rdtsc();                               \
        volatile uint64_t _j_t1_##tag = __rdtsc();                               \
        volatile uint64_t _j_dt_##tag = _j_t1_##tag - _j_t0_##tag;              \
        if (::anti_tamper::obfuscation::detail::opaque_false(_j_dt_##tag)) {     \
            volatile uint32_t _j_lo_##tag, _j_hi_##tag;                          \
            _j_lo_##tag = static_cast<uint32_t>(_j_dt_##tag);                    \
            _j_hi_##tag = static_cast<uint32_t>(_j_dt_##tag >> 32);              \
            (void)_j_lo_##tag; (void)_j_hi_##tag;                               \
        }                                                                        \
    } while (0)

#define OBFUSCATE_JUNK_MEMPROBE(tag)                                             \
    do {                                                                          \
        volatile MEMORY_BASIC_INFORMATION _j_mbi_##tag = {};                     \
        if (::anti_tamper::obfuscation::detail::opaque_false(__rdtsc())) {        \
            VirtualQuery(reinterpret_cast<LPCVOID>(&_j_mbi_##tag),               \
                         const_cast<PMEMORY_BASIC_INFORMATION>(&_j_mbi_##tag),   \
                         sizeof(_j_mbi_##tag));                                  \
        }                                                                        \
    } while (0)

#define OBFUSCATE_JUNK_REGISTRY(tag)                                             \
    do {                                                                          \
        if (::anti_tamper::obfuscation::detail::opaque_false(__rdtsc())) {        \
            HKEY _j_hk_##tag = nullptr;                                          \
            RegOpenKeyExA(HKEY_LOCAL_MACHINE,                                    \
                "SOFTWARE\\Microsoft\\Windows\\CurrentVersion", 0,               \
                KEY_READ, &_j_hk_##tag);                                         \
            if (_j_hk_##tag) RegCloseKey(_j_hk_##tag);                           \
        }                                                                        \
    } while (0)

#define OBFUSCATE_JUNK_PEB(tag)                                                  \
    do {                                                                          \
        volatile uint64_t _j_peb_##tag = 0;                                      \
        __try {                                                                  \
            auto* _teb = reinterpret_cast<const uint8_t*>(__readgsqword(0x30));   \
            auto* _peb = *reinterpret_cast<const uint8_t* const*>(_teb + 0x60);  \
            _j_peb_##tag = *reinterpret_cast<const uint32_t*>(_peb + 0x118);     \
        } __except(EXCEPTION_EXECUTE_HANDLER) {}                                 \
        if (::anti_tamper::obfuscation::detail::opaque_false(_j_peb_##tag)) {    \
            volatile uint64_t _j_pd_##tag = _j_peb_##tag;                        \
            (void)_j_pd_##tag;                                                   \
        }                                                                        \
    } while (0)


namespace anti_tamper {
namespace obfuscation {
namespace opaque_predicates {

    __forceinline bool sum_of_squares_true(uint64_t seed)
    {
        volatile uint64_t a = (seed >> 3) & 0xFFFF;
        volatile uint64_t b = (seed >> 19) & 0xFFFF;
        volatile uint64_t sq = a * a + b * b;
        return sq >= 0;
    }

    __forceinline bool euler_identity_true(uint64_t seed)
    {
        volatile uint64_t n = (seed | 1) & 0x7FFFFFFF;
        volatile uint64_t n_sq = n * n;
        return n_sq >= n || n == 1;
    }


    __forceinline bool fermat_true(uint64_t seed)
    {
        return sum_of_squares_true(seed ^ 0x9E3779B97F4A7C15ULL);
    }

    __forceinline bool quadratic_residue_true(uint64_t seed)
    {
        return euler_identity_true(seed ^ 0xBF58476D1CE4E5B9ULL);
    }

}
}
}

#define OPAQUE_TRUE_FERMAT(tag)                                                  \
    ::anti_tamper::obfuscation::opaque_predicates::fermat_true(                  \
        ::anti_tamper::obfuscation::detail::compile_seed(__FILE__, __LINE__))

#define OPAQUE_TRUE_QUADRATIC(tag)                                               \
    ::anti_tamper::obfuscation::opaque_predicates::quadratic_residue_true(       \
        ::anti_tamper::obfuscation::detail::compile_seed(__FILE__, __LINE__))

#define OPAQUE_FALSE_FERMAT(tag)                                                 \
    (!OPAQUE_TRUE_FERMAT(tag))

#define OPAQUE_IF_TRUE(tag, code)                                                \
    do {                                                                          \
        if (OPAQUE_TRUE_FERMAT(tag)) { code; }                                   \
        else {                                                                   \
            volatile uint64_t _oift_##tag = __rdtsc();                           \
            (void)_oift_##tag;                                                   \
        }                                                                        \
    } while (0)

#define OPAQUE_IF_FALSE(tag, code)                                               \
    do {                                                                          \
        if (OPAQUE_FALSE_FERMAT(tag)) { code; }                                  \
    } while (0)

#define DEAD_BRANCH_FERMAT(tag)                                                  \
    if (OPAQUE_FALSE_FERMAT(tag))

#define DEAD_BRANCH_QUADRATIC(tag)                                               \
    if (!OPAQUE_TRUE_QUADRATIC(tag))


#define INSTALL_FAKE_VEH(tag)                                                    \
    do {                                                                          \
        if (::anti_tamper::obfuscation::detail::opaque_false(__rdtsc())) {        \
            AddVectoredExceptionHandler(0, [](PEXCEPTION_POINTERS ep)            \
                -> LONG {                                                        \
                volatile uint64_t _fv_c_##tag = ep->ExceptionRecord->ExceptionCode; \
                if (_fv_c_##tag == 0xDEADFACE) {                                 \
                    volatile uint64_t _fv_h_##tag = 0x6A09E667F3BCC908ULL;       \
                    _fv_h_##tag ^= _fv_h_##tag >> 33;                            \
                    _fv_h_##tag *= 0xFF51AFD7ED558CCDULL;                         \
                    if (_fv_h_##tag == 0)                                         \
                        return EXCEPTION_CONTINUE_EXECUTION;                     \
                }                                                                \
                return EXCEPTION_CONTINUE_SEARCH;                                \
            });                                                                  \
        }                                                                        \
    } while (0)

#define INSTALL_FAKE_SEH(tag)                                                    \
    do {                                                                          \
        if (::anti_tamper::obfuscation::detail::opaque_false(__rdtsc())) {        \
            __try {                                                              \
                volatile uint64_t _fs_v_##tag = __rdtsc();                       \
                _fs_v_##tag *= 0x94D049BB133111EBULL;                            \
                if (_fs_v_##tag == 0x12345678DEADBEEFULL) {                       \
                    RaiseException(0xC0000005, 0, 0, nullptr);                   \
                }                                                                \
            } __except(EXCEPTION_EXECUTE_HANDLER) {                              \
                volatile int _fs_d_##tag = 0;                                    \
                (void)_fs_d_##tag;                                               \
            }                                                                    \
        }                                                                        \
    } while (0)
