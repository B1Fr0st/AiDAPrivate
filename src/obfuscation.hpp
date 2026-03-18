#pragma once

#include <string>
#include <cstdint>
#include <cstddef>

namespace obf {
namespace detail {

constexpr uint8_t derive_key(uint32_t seed) noexcept
{
    seed = ((seed >> 16) ^ seed) * 0x45d9f3bu;
    seed = ((seed >> 16) ^ seed) * 0x45d9f3bu;
    seed = (seed >> 16) ^ seed;
    return static_cast<uint8_t>(seed & 0xFFu);
}

constexpr char cipher_byte(char c, uint8_t key, size_t idx) noexcept
{
    const uint8_t effective_key = static_cast<uint8_t>(
        (key ^ static_cast<uint8_t>((idx * 7u + 3u) & 0xFFu)) & 0xFFu);
    return static_cast<char>(static_cast<uint8_t>(c) ^ effective_key);
}

template<size_t N, uint8_t K>
class encrypted_string
{
    char m_data[N];
public:
    constexpr encrypted_string(const char (&str)[N]) noexcept : m_data{}
    {
        for (size_t i = 0; i < N; ++i)
            m_data[i] = cipher_byte(str[i], K, i);
    }

#ifdef _MSC_VER
    __forceinline
#else
    __attribute__((always_inline))
#endif
    std::string decrypt() const
    {
        std::string result(N - 1, '\0');
        for (size_t i = 0; i < N - 1; ++i)
            result[i] = cipher_byte(m_data[i], K, i);
        return result;
    }
};

}
}

#define OBFSTR(s) ([]() -> std::string {                                   \
    static constexpr ::obf::detail::encrypted_string<                      \
        sizeof(s),                                                         \
        ::obf::detail::derive_key(                                         \
            static_cast<uint32_t>(__LINE__) ^ 0xB3A7u)> _enc_data(s);     \
    return _enc_data.decrypt();                                            \
}())

#define OBFSTR_C(s) (OBFSTR(s).c_str())

namespace obf {
namespace detail {

constexpr wchar_t cipher_wbyte(wchar_t c, uint8_t key, size_t idx) noexcept
{
    const uint16_t effective_key = static_cast<uint16_t>(
        (static_cast<uint16_t>(key) ^ static_cast<uint16_t>((idx * 11u + 7u) & 0xFFu)) & 0xFFFFu);
    return static_cast<wchar_t>(static_cast<uint16_t>(c) ^ effective_key);
}

template<size_t N, uint8_t K>
class encrypted_wstring
{
    wchar_t m_data[N];
public:
    constexpr encrypted_wstring(const wchar_t (&str)[N]) noexcept : m_data{}
    {
        for (size_t i = 0; i < N; ++i)
            m_data[i] = cipher_wbyte(str[i], K, i);
    }

#ifdef _MSC_VER
    __forceinline
#else
    __attribute__((always_inline))
#endif
    std::wstring decrypt() const
    {
        std::wstring result(N - 1, L'\0');
        for (size_t i = 0; i < N - 1; ++i)
            result[i] = cipher_wbyte(m_data[i], K, i);
        return result;
    }
};

}
}

#define WOBFSTR(s) ([]() -> std::wstring {                                 \
    static constexpr ::obf::detail::encrypted_wstring<                     \
        sizeof(s) / sizeof(wchar_t),                                       \
        ::obf::detail::derive_key(                                         \
            static_cast<uint32_t>(__LINE__) ^ 0xC7D9u)> _enc_wdata(s);    \
    return _enc_wdata.decrypt();                                           \
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

namespace detail {

constexpr uint8_t cipher_secret_byte(uint8_t c, uint8_t key, size_t idx) noexcept
{
    uint8_t k1 = static_cast<uint8_t>((key ^ (idx * 13u + 17u)) & 0xFFu);
    uint8_t k2 = static_cast<uint8_t>(((key >> 4) ^ (idx * 7u + 3u)) & 0xFFu);
    uint8_t k3 = static_cast<uint8_t>(((idx + key) * 11u) & 0xFFu);
    return c ^ k1 ^ k2 ^ k3;
}

template<size_t N, uint8_t K>
class encrypted_secret
{
    uint8_t m_data[N];
public:
    constexpr encrypted_secret(const char (&str)[N]) noexcept : m_data{}
    {
        for (size_t i = 0; i < N; ++i)
            m_data[i] = cipher_secret_byte(static_cast<uint8_t>(str[i]), K, i);
    }

#ifdef _MSC_VER
    __declspec(noinline) __forceinline
#else
    __attribute__((noinline, always_inline))
#endif
    std::string decrypt() const
    {
        std::string result(N - 1, '\0');
        for (size_t i = 0; i < N - 1; ++i)
            result[i] = static_cast<char>(cipher_secret_byte(m_data[i], K, i));
        return result;
    }
};

}
}

#define OBFBYTES(s) ([]() -> std::string {                                 \
    static constexpr ::obf::detail::encrypted_secret<                      \
        sizeof(s),                                                         \
        ::obf::detail::derive_key(                                         \
            static_cast<uint32_t>(__LINE__) ^ 0xE5A3u                       \
            ^ static_cast<uint32_t>(__COUNTER__))> _enc_secret(s);        \
    return _enc_secret.decrypt();                                          \
}())
