#pragma once

#include <cstdint>
#include <cstring>

namespace anti_tamper {
namespace xxhash {

constexpr uint64_t kPrime1 = 0x9E3779B185EBCA87ULL;
constexpr uint64_t kPrime2 = 0xC2B2AE3D27D4EB4FULL;
constexpr uint64_t kPrime3 = 0x165667B19E3779F9ULL;
constexpr uint64_t kPrime4 = 0x85EBCA77C2B2AE63ULL;
constexpr uint64_t kPrime5 = 0x27D4EB2F165667C5ULL;

__forceinline uint64_t rotl64(uint64_t x, int r)
{
    return (x << r) | (x >> (64 - r));
}

__forceinline uint64_t mul64(uint64_t a, uint64_t b)
{
    return a * b;
}

__forceinline uint64_t round_accum(uint64_t acc, uint64_t input)
{
    acc = mul64(acc + mul64(input, kPrime2), kPrime1);
    acc ^= rotl64(acc, 31) * kPrime1;
    return acc + kPrime4;
}

__forceinline uint64_t merge_round(uint64_t acc, uint64_t val)
{
    val = round_accum(0, val);
    acc ^= val;
    acc = mul64(acc, kPrime1) + kPrime4;
    return acc;
}

inline __declspec(noinline) uint64_t hash(const void* data, size_t len, uint64_t seed = 0)
{
    const auto* p = static_cast<const uint8_t*>(data);
    const uint64_t length = static_cast<uint64_t>(len);

    uint64_t h64;
    const uint8_t* end = p + len;

    if (len >= 32)
    {
        uint64_t v1 = seed + kPrime1 + kPrime2;
        uint64_t v2 = seed + kPrime2;
        uint64_t v3 = seed;
        uint64_t v4 = seed - kPrime1;

        const uint8_t* limit = end - 32;
        do
        {
            uint64_t k;
            memcpy(&k, p, 8); v1 = round_accum(v1, k); p += 8;
            memcpy(&k, p, 8); v2 = round_accum(v2, k); p += 8;
            memcpy(&k, p, 8); v3 = round_accum(v3, k); p += 8;
            memcpy(&k, p, 8); v4 = round_accum(v4, k); p += 8;
        } while (p <= limit);

        h64 = rotl64(v1, 1) + rotl64(v2, 7) + rotl64(v3, 12) + rotl64(v4, 18);
        h64 = merge_round(h64, v1);
        h64 = merge_round(h64, v2);
        h64 = merge_round(h64, v3);
        h64 = merge_round(h64, v4);
    }
    else
    {
        h64 = seed + kPrime5;
    }

    h64 += length;

    while (p + 8 <= end)
    {
        uint64_t k;
        memcpy(&k, p, 8);
        k = mul64(k, kPrime2);
        k = rotl64(k, 31);
        k = mul64(k, kPrime1);
        h64 ^= k;
        h64 = mul64(rotl64(h64, 27), kPrime1) + kPrime4;
        p += 8;
    }

    if (p + 4 <= end)
    {
        uint32_t k32;
        memcpy(&k32, p, 4);
        h64 ^= mul64(static_cast<uint64_t>(k32), kPrime1);
        h64 = mul64(rotl64(h64, 23), kPrime2) + kPrime3;
        p += 4;
    }

    while (p < end)
    {
        h64 ^= mul64(static_cast<uint64_t>(*p), kPrime5);
        h64 = mul64(rotl64(h64, 11), kPrime1);
        ++p;
    }

    h64 ^= h64 >> 33;
    h64 = mul64(h64, kPrime2);
    h64 ^= h64 >> 29;
    h64 = mul64(h64, kPrime3);
    h64 ^= h64 >> 32;

    return h64;
}

inline __declspec(noinline) void hash_32(const void* data, size_t len, uint8_t out[32])
{
    uint64_t h = hash(data, len, 0);
    memcpy(out, &h, 8);

    uint64_t h2 = hash(data, len, 0xA1DA0123456789ULL);
    memcpy(out + 8, &h2, 8);

    uint64_t h3 = hash(data, len, 0xDEADBEEFCAFEBABEULL);
    memcpy(out + 16, &h3, 8);

    uint64_t h4 = hash(data, len, 0x0BADF00D13371337ULL);
    memcpy(out + 24, &h4, 8);
}

}
}
