#pragma once

#include <windows.h>
#include <intrin.h>

#include <cstdint>
#include <cstring>
#include <mutex>
#include <vector>

#include "integrity.hpp"
#include "metamorphic.hpp"
#include "obfuscation.hpp"

namespace anti_tamper {
namespace cloakwork {

namespace mba_rt {

    __forceinline uint64_t obfuscate_constant(uint64_t value, uint64_t entropy)
    {
        return metamorphic::mba::obfuscate_constant(value, entropy);
    }

    __forceinline uint64_t obfuscate_comparison(uint64_t a, uint64_t b, uint64_t entropy)
    {
        return metamorphic::mba::obfuscate_comparison(a, b, entropy);
    }

    __forceinline uint64_t session_encrypt(uint64_t value, uint64_t session_key)
    {
        uint8_t buf[16];
        memcpy(buf, &value, 8);
        memcpy(buf + 8, &session_key, 8);
        uint64_t h = integrity::siphash::hash(buf, 16, session_key, value ^ 0xBB67AE8584CAA73BULL);
        return value ^ h ^ _rotl64(h, 17);
    }

    __forceinline uint64_t session_decrypt(uint64_t encrypted, uint64_t session_key, uint64_t original)
    {
        uint8_t buf[16];
        memcpy(buf, &original, 8);
        memcpy(buf + 8, &session_key, 8);
        uint64_t h = integrity::siphash::hash(buf, 16, session_key, original ^ 0xBB67AE8584CAA73BULL);
        return encrypted ^ h ^ _rotl64(h, 17);
    }

}

namespace string_table {

    struct encrypted_entry_t
    {
        uint32_t offset;
        uint32_t length;
    };

    struct table_t
    {
        std::vector<uint8_t> blob;
        std::vector<encrypted_entry_t> entries;
        uint64_t key;
        uint64_t session_key;
        std::mutex mtx;
    };

    inline table_t& get()
    {
        static table_t t;
        return t;
    }

    inline void initialize(uint64_t code_hash)
    {
        auto& t = get();
        t.key = code_hash ^ 0x5DEECE66DULL ^ __rdtsc();
        uint64_t k0 = 0, k1 = 0;
        integrity::get_session_keys(k0, k1);
        t.session_key = k0 ^ k1;
    }

    inline uint32_t add_string(const char* str, size_t len)
    {
        auto& t = get();
        std::lock_guard<std::mutex> lk(t.mtx);

        uint32_t offset = static_cast<uint32_t>(t.blob.size());
        t.blob.resize(offset + len);

        uint64_t rolling = t.key ^ offset ^ t.session_key;
        for (size_t i = 0; i < len; ++i)
        {
            t.blob[offset + i] = static_cast<uint8_t>(str[i]) ^ static_cast<uint8_t>(rolling);
            rolling ^= rolling << 13;
            rolling ^= rolling >> 7;
            rolling ^= rolling << 17;
        }

        t.entries.push_back({offset, static_cast<uint32_t>(len)});
        return static_cast<uint32_t>(t.entries.size() - 1);
    }

    inline std::string decrypt_string(uint32_t index)
    {
        auto& t = get();
        std::lock_guard<std::mutex> lk(t.mtx);

        if (index >= t.entries.size()) return "";
        auto& e = t.entries[index];

        std::string result(e.length, '\0');
        uint64_t rolling = t.key ^ e.offset ^ t.session_key;
        for (uint32_t i = 0; i < e.length; ++i)
        {
            result[i] = static_cast<char>(t.blob[e.offset + i] ^ static_cast<uint8_t>(rolling));
            rolling ^= rolling << 13;
            rolling ^= rolling >> 7;
            rolling ^= rolling << 17;
        }
        return result;
    }

}

namespace opaque {

    __forceinline uint64_t teb_entropy()
    {
#if defined(_M_X64)
        uint64_t teb = __readgsqword(0x30);
        uint64_t pid = __readgsqword(0x40);
        uint64_t tid = __readgsqword(0x48);
#else
        uint64_t teb = __readfsdword(0x18);
        uint64_t pid = __readfsdword(0x20);
        uint64_t tid = __readfsdword(0x24);
#endif
        return teb ^ _rotl64(pid, 17) ^ _rotr64(tid, 23);
    }

    __forceinline uint64_t kuser_entropy()
    {
        volatile auto* kuser = reinterpret_cast<volatile uint8_t*>(0x7FFE0000ULL);
        uint64_t tick = *reinterpret_cast<volatile const uint64_t*>(kuser + 0x320);
        uint64_t interrupt = *reinterpret_cast<volatile const uint64_t*>(kuser + 0x008);
        uint64_t cookie = *reinterpret_cast<volatile const uint32_t*>(kuser + 0x330);
        return tick ^ _rotl64(interrupt, 29) ^ (cookie * 0x9E3779B97F4A7C15ULL);
    }

    __forceinline uint64_t state_hash(uint64_t a, uint64_t b)
    {
        uint8_t buf[16];
        memcpy(buf, &a, 8);
        memcpy(buf + 8, &b, 8);
        return integrity::siphash::hash(buf, 16,
            a ^ 0x736970686173684BULL, b ^ 0x646F72616E64311ULL);
    }

    __forceinline bool predicate_runtime_true(uint64_t x, uint64_t entropy)
    {
        uint64_t env = teb_entropy() ^ kuser_entropy() ^ __rdtsc();
        uint64_t h = state_hash(x ^ env, entropy ^ env);


        constexpr uint64_t p = 257;
        uint64_t a = (h % (p - 1)) + 1;


        uint64_t exp = p - 1;
        uint64_t result = 1;
        uint64_t base = a % p;
        while (exp > 0)
        {
            if (exp & 1) result = (result * base) % p;
            base = (base * base) % p;
            exp >>= 1;
        }


        uint64_t qr_base = ((h >> 32) % (p - 1)) + 1;
        uint64_t euler = 1;
        uint64_t qr_exp = (p - 1) / 2;
        uint64_t qr_b = qr_base % p;
        while (qr_exp > 0)
        {
            if (qr_exp & 1) euler = (euler * qr_b) % p;
            qr_b = (qr_b * qr_b) % p;
            qr_exp >>= 1;
        }

        uint64_t euler_sq = (euler * euler) % p;

        return (result == 1) && (euler_sq == 1);
    }

    __forceinline bool predicate_runtime_false(uint64_t x, uint64_t entropy)
    {

        return !predicate_runtime_true(x, entropy);
    }

    __forceinline uint64_t opaque_zero_keyed(uint64_t noise, uint64_t session_key)
    {
        uint64_t env = teb_entropy();
        uint64_t h = state_hash(noise ^ env, session_key ^ env);
        return h ^ h;
    }

    __forceinline uint64_t opaque_constant_keyed(uint64_t val, uint64_t noise, uint64_t session_key)
    {
        uint64_t zero = opaque_zero_keyed(noise, session_key);
        return val + zero;
    }

    __forceinline bool predicate_teb_consistent()
    {
        uint64_t e1 = teb_entropy();
        uint64_t e2 = teb_entropy();
        uint64_t h = state_hash(e1, e2);
        return ((h ^ h) == 0);
    }

}

inline void initialize(uint64_t code_hash)
{
    string_table::initialize(code_hash);
}

}
}
