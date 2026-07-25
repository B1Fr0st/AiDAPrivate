#pragma once

#include <cstdint>
#include <cstring>

namespace anti_tamper {
namespace sha1 {

constexpr uint32_t kHashSize = 20;

__forceinline uint32_t rotl32(uint32_t x, int n)
{
    return (x << n) | (x >> (32 - n));
}

inline __declspec(noinline) void hash(const void* data, size_t len, uint8_t out[20])
{
    uint32_t h0 = 0x67452301;
    uint32_t h1 = 0xEFCDAB89;
    uint32_t h2 = 0x98BADCFE;
    uint32_t h3 = 0x10325476;
    uint32_t h4 = 0xC3D2E1F0;

    const auto* msg = static_cast<const uint8_t*>(data);

    size_t padded_len = ((len + 9 + 63) / 64) * 64;
    uint8_t* buf = static_cast<uint8_t*>(_alloca(padded_len > 0 ? padded_len : 64));
    memcpy(buf, msg, len);
    buf[len] = 0x80;
    memset(buf + len + 1, 0, padded_len - len - 9);

    uint64_t bit_len = static_cast<uint64_t>(len) * 8ULL;
    for (int i = 0; i < 8; ++i)
        buf[padded_len - 1 - i] = static_cast<uint8_t>((bit_len >> (i * 8)) & 0xFF);

    for (size_t chunk = 0; chunk < padded_len; chunk += 64)
    {
        uint32_t w[80];
        for (int i = 0; i < 16; ++i)
        {
            w[i] = (static_cast<uint32_t>(buf[chunk + i*4]) << 24) |
                   (static_cast<uint32_t>(buf[chunk + i*4 + 1]) << 16) |
                   (static_cast<uint32_t>(buf[chunk + i*4 + 2]) << 8) |
                   (static_cast<uint32_t>(buf[chunk + i*4 + 3]));
        }
        for (int i = 16; i < 80; ++i)
        {
            w[i] = rotl32(w[i-3] ^ w[i-8] ^ w[i-14] ^ w[i-16], 1);
        }

        uint32_t a = h0, b = h1, c = h2, d = h3, e = h4;

        for (int i = 0; i < 80; ++i)
        {
            uint32_t f, k;
            if (i < 20)
            {
                f = (b & c) | ((~b) & d);
                k = 0x5A827999;
            }
            else if (i < 40)
            {
                f = b ^ c ^ d;
                k = 0x6ED9EBA1;
            }
            else if (i < 60)
            {
                f = (b & c) | (b & d) | (c & d);
                k = 0x8F1BBCDC;
            }
            else
            {
                f = b ^ c ^ d;
                k = 0xCA62C1D6;
            }

            uint32_t temp = rotl32(a, 5) + f + e + k + w[i];
            e = d;
            d = c;
            c = rotl32(b, 30);
            b = a;
            a = temp;
        }

        h0 += a; h1 += b; h2 += c; h3 += d; h4 += e;
    }

    uint32_t hs[5] = { h0, h1, h2, h3, h4 };
    for (int i = 0; i < 5; ++i)
    {
        out[i*4]   = static_cast<uint8_t>((hs[i] >> 24) & 0xFF);
        out[i*4+1] = static_cast<uint8_t>((hs[i] >> 16) & 0xFF);
        out[i*4+2] = static_cast<uint8_t>((hs[i] >> 8) & 0xFF);
        out[i*4+3] = static_cast<uint8_t>(hs[i] & 0xFF);
    }
}

inline __declspec(noinline) void hash_32(const void* data, size_t len, uint8_t out[32])
{
    uint8_t digest[20];
    hash(data, len, digest);
    memcpy(out, digest, 20);
    for (int i = 20; i < 32; ++i)
        out[i] = static_cast<uint8_t>(digest[i % 20] ^ digest[(i + 3) % 20] ^ 0xA5);
}

}
}
