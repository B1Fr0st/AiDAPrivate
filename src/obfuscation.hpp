#pragma once
#include <string>
#include <cstdint>
#include <cstddef>
#ifdef _MSC_VER
#include <intrin.h>
#endif

namespace obf {
namespace detail {

constexpr uint32_t fnv1a(const char* s) noexcept
{
    uint32_t h = 0x811c9dc5u;
    while (*s != '\0') {
        h = (h ^ static_cast<uint8_t>(*s)) * 0x01000193u;
        ++s;
    }
    return h;
}

constexpr uint32_t site_seed(uint32_t file_hash, uint32_t line, uint32_t salt) noexcept
{
    uint32_t h = file_hash ^ (line * 0x9e3779b9u) ^ salt;
    h = ((h >> 16) ^ h) * 0x45d9f3bu;
    h = ((h >> 16) ^ h) * 0x45d9f3bu;
    h = (h >> 16) ^ h;
    return h;
}

constexpr uint64_t derive_key64(uint32_t seed) noexcept
{
    uint64_t k = seed;
    k += 0x9e3779b97f4a7c15ULL;
    k = (k ^ (k >> 30)) * 0xbf58476d1ce4e5b9ULL;
    k = (k ^ (k >> 27)) * 0x94d049bb133111ebULL;
    k = k ^ (k >> 31);
    return k;
}

constexpr uint8_t rotr8(uint8_t v, unsigned n) noexcept
{
    n &= 7u;
    return static_cast<uint8_t>((v >> n) | (v << (8u - n)));
}

constexpr uint8_t rotl8(uint8_t v, unsigned n) noexcept
{
    n &= 7u;
    return static_cast<uint8_t>((v << n) | (v >> (8u - n)));
}

constexpr uint8_t rk(uint64_t key, size_t idx, uint8_t salt) noexcept
{
    return static_cast<uint8_t>(
        ((key >> (((idx + salt) & 7u) * 8u)) & 0xFFu)
        ^ ((idx * static_cast<size_t>(salt) + 0x9Bu) & 0xFFu)
    );
}

constexpr uint8_t encrypt_byte(uint8_t c, uint64_t key, size_t idx) noexcept
{
    uint8_t b = c;
    b ^= rk(key, idx, 13);  b = rotl8(b, 3);
    b = static_cast<uint8_t>((b + rk(key, idx, 29)) & 0xFFu);  b ^= rk(key, idx, 47);
    b = rotr8(b, 5);        b ^= rk(key, idx, 61);
    b = static_cast<uint8_t>(((b * 173u) + 71u) & 0xFFu);
    return b;
}

constexpr uint8_t decrypt_byte(uint8_t b, uint64_t key, size_t idx) noexcept
{
    b = static_cast<uint8_t>(((b - 71u) & 0xFFu) * 37u);
    b ^= rk(key, idx, 61);  b = rotl8(b, 5);
    b ^= rk(key, idx, 47);  b = static_cast<uint8_t>((b - rk(key, idx, 29)) & 0xFFu);
    b = rotr8(b, 3);        b ^= rk(key, idx, 13);
    return b;
}

constexpr wchar_t encrypt_wchar(wchar_t c, uint64_t key, size_t idx) noexcept
{
    uint16_t v = static_cast<uint16_t>(c);
    uint8_t lo = encrypt_byte(static_cast<uint8_t>(v & 0xFFu), key, idx * 2);
    uint8_t hi = encrypt_byte(static_cast<uint8_t>((v >> 8) & 0xFFu), key, idx * 2 + 1);
    return static_cast<wchar_t>(static_cast<uint16_t>(hi) << 8 | lo);
}

constexpr wchar_t decrypt_wchar(wchar_t c, uint64_t key, size_t idx) noexcept
{
    uint16_t v = static_cast<uint16_t>(c);
    uint8_t lo = decrypt_byte(static_cast<uint8_t>(v & 0xFFu), key, idx * 2);
    uint8_t hi = decrypt_byte(static_cast<uint8_t>((v >> 8) & 0xFFu), key, idx * 2 + 1);
    return static_cast<wchar_t>(static_cast<uint16_t>(hi) << 8 | lo);
}

constexpr uint32_t checksum_bytes(const uint8_t* data, size_t len, uint32_t seed) noexcept
{
    uint32_t h = seed ^ 0x5F3759DFu;
    for (size_t i = 0; i < len; ++i) {
        h ^= static_cast<uint32_t>(data[i]) << ((i & 3u) * 8u);
        h = ((h >> 13) ^ h) * 0x1B873593u;
        h ^= h >> 16;
    }
    return h;
}

constexpr uint32_t checksum_wchars(const wchar_t* data, size_t len, uint32_t seed) noexcept
{
    uint32_t h = seed ^ 0x5F3759DFu;
    for (size_t i = 0; i < len; ++i) {
        uint16_t v = static_cast<uint16_t>(data[i]);
        h ^= static_cast<uint32_t>(v & 0xFFu) << (((i * 2) & 3u) * 8u);
        h = ((h >> 13) ^ h) * 0x1B873593u;
        h ^= static_cast<uint32_t>((v >> 8) & 0xFFu) << (((i * 2 + 1) & 3u) * 8u);
        h = ((h >> 13) ^ h) * 0x1B873593u;
        h ^= h >> 16;
    }
    return h;
}

#ifdef _MSC_VER
__forceinline
#else
__attribute__((always_inline)) inline
#endif
bool runtime_tamper_check() noexcept
{
#if defined(_M_X64) && defined(_MSC_VER)
    const auto peb = __readgsqword(0x60);
    if (*reinterpret_cast<const uint8_t*>(peb + 2) != 0)
        return false;
    if (*reinterpret_cast<const uint32_t*>(peb + 0xBC) & 0x70u)
        return false;
#elif defined(_M_IX86) && defined(_MSC_VER)
    const auto peb = static_cast<uintptr_t>(__readfsdword(0x30));
    if (*reinterpret_cast<const uint8_t*>(peb + 2) != 0)
        return false;
    if (*reinterpret_cast<const uint32_t*>(peb + 0x68) & 0x70u)
        return false;
#endif
    return true;
}

template<size_t N, uint32_t SEED>
class encrypted_string
{
    uint8_t m_data[N];
    uint32_t m_checksum;
    static constexpr uint64_t KEY = derive_key64(SEED);

public:
    constexpr encrypted_string(const char (&str)[N]) noexcept : m_data{}, m_checksum(0)
    {
        for (size_t i = 0; i < N; ++i)
            m_data[i] = encrypt_byte(static_cast<uint8_t>(str[i]), KEY, i);
        uint32_t h = SEED ^ 0x5F3759DFu;
        for (size_t i = 0; i < N; ++i) {
            h ^= static_cast<uint32_t>(m_data[i]) << ((i & 3u) * 8u);
            h = ((h >> 13) ^ h) * 0x1B873593u;
            h ^= h >> 16;
        }
        m_checksum = h;
    }

#ifdef _MSC_VER
    __forceinline
#else
    __attribute__((always_inline))
#endif
    std::string decrypt() const
    {
        volatile bool intact = (checksum_bytes(m_data, N, SEED) == m_checksum);
        const uint64_t k = intact ? KEY : (KEY ^ 0xC0FFEEC0FFEE1234ULL);

        std::string result(N - 1, '\0');
        volatile char* rp = &result[0];
        for (size_t i = 0; i < N - 1; ++i)
            rp[i] = static_cast<char>(decrypt_byte(m_data[i], k, i));
        return result;
    }
};

template<size_t N, uint32_t SEED>
class encrypted_wstring
{
    wchar_t m_data[N];
    uint32_t m_checksum;
    static constexpr uint64_t KEY = derive_key64(SEED);

public:
    constexpr encrypted_wstring(const wchar_t (&str)[N]) noexcept : m_data{}, m_checksum(0)
    {
        for (size_t i = 0; i < N; ++i)
            m_data[i] = encrypt_wchar(str[i], KEY, i);
        uint32_t h = SEED ^ 0x5F3759DFu;
        for (size_t i = 0; i < N; ++i) {
            uint16_t v = static_cast<uint16_t>(m_data[i]);
            h ^= static_cast<uint32_t>(v & 0xFFu) << (((i * 2) & 3u) * 8u);
            h = ((h >> 13) ^ h) * 0x1B873593u;
            h ^= static_cast<uint32_t>((v >> 8) & 0xFFu) << (((i * 2 + 1) & 3u) * 8u);
            h = ((h >> 13) ^ h) * 0x1B873593u;
            h ^= h >> 16;
        }
        m_checksum = h;
    }

#ifdef _MSC_VER
    __forceinline
#else
    __attribute__((always_inline))
#endif
    std::wstring decrypt() const
    {
        volatile bool intact = (checksum_wchars(m_data, N, SEED) == m_checksum);
        const uint64_t k = intact ? KEY : (KEY ^ 0xC0FFEEC0FFEE1234ULL);

        std::wstring result(N - 1, L'\0');
        volatile wchar_t* rp = &result[0];
        for (size_t i = 0; i < N - 1; ++i)
            rp[i] = decrypt_wchar(m_data[i], k, i);
        return result;
    }
};

template<size_t N, uint32_t SEED>
class encrypted_secret
{
    uint8_t m_data[N];
    uint32_t m_checksum;
    static constexpr uint64_t KEY = derive_key64(SEED);

public:
    constexpr encrypted_secret(const char (&str)[N]) noexcept : m_data{}, m_checksum(0)
    {
        for (size_t i = 0; i < N; ++i)
            m_data[i] = encrypt_byte(static_cast<uint8_t>(str[i]), KEY, i);
        uint32_t h = SEED ^ 0x5F3759DFu;
        for (size_t i = 0; i < N; ++i) {
            h ^= static_cast<uint32_t>(m_data[i]) << ((i & 3u) * 8u);
            h = ((h >> 13) ^ h) * 0x1B873593u;
            h ^= h >> 16;
        }
        m_checksum = h;
    }

#ifdef _MSC_VER
    __declspec(noinline)
#else
    __attribute__((noinline))
#endif
    std::string decrypt() const
    {
        volatile bool intact = (checksum_bytes(m_data, N, SEED) == m_checksum);
        volatile bool clean = runtime_tamper_check();
        const uint64_t k = (intact && clean) ? KEY : (KEY ^ 0xDEADC0DEBADC0DEULL);

        std::string result(N - 1, '\0');
        volatile char* rp = &result[0];
        for (size_t i = 0; i < N - 1; ++i)
            rp[i] = static_cast<char>(decrypt_byte(m_data[i], k, i));
        return result;
    }
};

}
}

#define _OBF_SEED(salt) (::obf::detail::site_seed(                         \
    ::obf::detail::fnv1a(__FILE__),                                         \
    static_cast<uint32_t>(__LINE__),                                        \
    (salt) ^ static_cast<uint32_t>(__COUNTER__)))

#define OBFSTR(s) ([]() -> std::string {                                    \
    constexpr uint32_t _seed = _OBF_SEED(0xB3A7u);                         \
    static constexpr ::obf::detail::encrypted_string<                       \
        sizeof(s), _seed> _enc(s);                                          \
    return _enc.decrypt();                                                  \
}())

#define OBFSTR_C(s) (OBFSTR(s).c_str())

#define WOBFSTR(s) ([]() -> std::wstring {                                  \
    constexpr uint32_t _seed = _OBF_SEED(0xC7D9u);                         \
    static constexpr ::obf::detail::encrypted_wstring<                      \
        sizeof(s) / sizeof(wchar_t), _seed> _enc(s);                       \
    return _enc.decrypt();                                                  \
}())

#define WOBFSTR_C(s) (WOBFSTR(s).c_str())

namespace obf {

inline void secure_wipe_string(std::string& s)
{
    if (!s.empty())
    {
        volatile char* p = &s[0];
        for (size_t i = 0; i < s.size(); ++i)
            p[i] = 0;
        s.clear();
    }
}

}

#define OBFBYTES(s) ([]() -> std::string {                                  \
    constexpr uint32_t _seed = _OBF_SEED(0xE5A3u);                         \
    static constexpr ::obf::detail::encrypted_secret<                       \
        sizeof(s), _seed> _enc(s);                                          \
    return _enc.decrypt();                                                  \
}())
