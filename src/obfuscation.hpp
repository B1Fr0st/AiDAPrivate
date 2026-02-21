#pragma once

// ============================================================================
// Compile-Time String Encryption (XOR-based Obfuscation)
// ============================================================================
//
// Purpose: Prevent static string analysis of the compiled binary.
// Every string wrapped with OBFSTR("...") is XOR-encrypted at compile time
// and decrypted at runtime. This means tools like `strings`, IDA's string
// view, or hex editors will NOT find plaintext "AiDA", "AI Assistant", etc.
//
// How it works:
//   1. derive_key(__LINE__) produces a unique uint8_t key per source line.
//   2. encrypted_string<N,K> XOR-encrypts each byte at compile time using
//      a position-dependent cipher: byte[i] ^= (K ^ (i*7+3)) & 0xFF.
//   3. OBFSTR(s) expands to a lambda that holds the encrypted bytes as a
//      'static constexpr' (forces compile-time evaluation), then decrypts
//      into a std::string at runtime.
//   4. The returned std::string temporary lives until the end of the
//      full-expression, so  msg(OBFSTR("fmt %s").c_str(), arg)  is safe.
//
// Verified against IDA SDK:
//   - msg(), warning(), info() take  const char *format  (kernwin.hpp L7226)
//   - OBFSTR("...").c_str() returns a valid const char* for the lifetime
//     of the enclosing full-expression per C++17 [class.temporary]/6.
// ============================================================================

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

} // namespace detail
} // namespace obf

#define OBFSTR(s) ([]() -> std::string {                                   \
    static constexpr ::obf::detail::encrypted_string<                      \
        sizeof(s),                                                         \
        ::obf::detail::derive_key(                                         \
            static_cast<uint32_t>(__LINE__) ^ 0xB3A7u)> _enc_data(s);     \
    return _enc_data.decrypt();                                            \
}())

#define OBFSTR_C(s) (OBFSTR(s).c_str())
