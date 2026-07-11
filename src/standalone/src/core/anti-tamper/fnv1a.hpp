#pragma once

#include <cstdint>
#include <cstring>

namespace anti_tamper {
namespace fnv1a {

constexpr uint64_t kOffset = 0xcbf29ce484222325ULL;
constexpr uint64_t kPrime  = 0x100000001b3ULL;

__declspec(noinline) uint64_t hash(const void* data, size_t len)
{
    const auto* p = static_cast<const uint8_t*>(data);
    uint64_t h = kOffset;
    for (size_t i = 0; i < len; ++i)
    {
        h ^= p[i];
        h *= kPrime;
    }
    return h;
}

__declspec(noinline) void hash_32(const void* data, size_t len, uint8_t out[32])
{
    const auto* p = static_cast<const uint8_t*>(data);
    uint64_t h = kOffset;
    for (size_t i = 0; i < len; ++i)
    {
        h ^= p[i];
        h *= kPrime;
    }
    for (int round = 0; round < 4; ++round)
    {
        h ^= static_cast<uint64_t>(round) << 56;
        h *= kPrime;
        memcpy(out + round * 8, &h, 8);
    }
}

}
}
