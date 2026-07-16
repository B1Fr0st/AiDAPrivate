#pragma once

#include <cstdint>
#include <cstring>
#include <cstddef>
#include <vector>

namespace anti_tamper {
namespace blake3 {

constexpr int kBlockSize = 64;
constexpr int kChunkSize = 1024;
constexpr int kOutLen = 32;

constexpr uint32_t kIV[8] = {
    0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A,
    0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19
};

constexpr uint8_t kMsgSchedule[7][16] = {
    { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9,10,11,12,13,14,15},
    { 2, 6, 3,10, 7, 0, 4,13, 1,11,12, 5, 9,14,15, 8},
    { 3, 4,10,12,13, 2, 7,14, 6, 5, 9, 0,11,15, 8, 1},
    {10, 7,12, 9,14, 3,13,15, 4, 0,11, 5, 2, 8, 1, 6},
    {12,13, 9,14, 8,15, 0, 4, 3, 5, 6, 1, 7, 2,10,11},
    { 9,14, 5, 7, 0, 3, 2,12,11, 4, 8,13,15, 6,10, 1},
    {11,13, 7,14,12, 1, 3, 9, 5, 0,15, 4, 8, 6, 2,10},
};

constexpr uint32_t kFlag_ChunkStart        = 4;
constexpr uint32_t kFlag_ChunkEnd          = 8;
constexpr uint32_t kFlag_Parent            = 2;
constexpr uint32_t kFlag_Root              = 1;
constexpr uint32_t kFlag_KeyedHash         = 16;
constexpr uint32_t kFlag_DeriveKeyContext  = 32;
constexpr uint32_t kFlag_DeriveKeyMaterial = 64;

__forceinline uint32_t rotr32(uint32_t x, int n)
{
    return (x >> n) | (x << (32 - n));
}

__forceinline void g_round(uint32_t& a, uint32_t& b, uint32_t& c, uint32_t& d,
                           uint32_t mx, uint32_t my)
{
    a = a + b + mx;
    d = rotr32(d ^ a, 16);
    c = c + d;
    b = rotr32(b ^ c, 12);
    a = a + b + my;
    d = rotr32(d ^ a, 8);
    c = c + d;
    b = rotr32(b ^ c, 7);
}

__forceinline void compress(
    uint32_t out[16],
    const uint32_t chaining[8],
    const uint32_t block_words[16],
    uint64_t counter,
    uint32_t block_len,
    uint32_t flags)
{
    uint32_t state[16];
    memcpy(state, chaining, 32);
    memcpy(state + 8, kIV, 32);
    state[12] ^= static_cast<uint32_t>(counter);
    state[13] ^= static_cast<uint32_t>(counter >> 32);
    state[14] ^= block_len;
    state[15] ^= flags;

    uint32_t m[16];
    memcpy(m, block_words, 64);

    for (int round = 0; round < 7; ++round)
    {
        const uint8_t* s = kMsgSchedule[round];
        g_round(state[0], state[4], state[8],  state[12], m[s[0]],  m[s[1]]);
        g_round(state[1], state[5], state[9],  state[13], m[s[2]],  m[s[3]]);
        g_round(state[2], state[6], state[10], state[14], m[s[4]],  m[s[5]]);
        g_round(state[3], state[7], state[11], state[15], m[s[6]],  m[s[7]]);
        g_round(state[0], state[5], state[10], state[15], m[s[8]],  m[s[9]]);
        g_round(state[1], state[6], state[11], state[12], m[s[10]], m[s[11]]);
        g_round(state[2], state[7], state[8],  state[13], m[s[12]], m[s[13]]);
        g_round(state[3], state[4], state[9],  state[14], m[s[14]], m[s[15]]);
    }

    for (int i = 0; i < 8; ++i)
    {
        out[i]     = state[i]     ^ state[i + 8];
        out[i + 8] = chaining[i]  ^ state[i + 8];
    }
}

struct chunk_state_t
{
    uint32_t cv[8];
    uint64_t chunk_counter;
    uint8_t  block[kBlockSize];
    size_t   block_len;
    size_t   blocks_compressed;
    uint32_t flags;
};

__forceinline void chunk_state_init(chunk_state_t& cs, const uint32_t key[8],
                                     uint32_t flags)
{
    memcpy(cs.cv, key, 32);
    cs.chunk_counter = 0;
    cs.block_len = 0;
    cs.blocks_compressed = 0;
    cs.flags = flags;
}

__forceinline uint32_t chunk_start_flag(const chunk_state_t& cs)
{
    return cs.blocks_compressed == 0 ? kFlag_ChunkStart : 0;
}

__forceinline void chunk_state_update(chunk_state_t& cs, const uint8_t* input,
                                       size_t len)
{
    while (len > 0)
    {
        if (cs.block_len == kBlockSize)
        {
            uint32_t words[16];
            for (int i = 0; i < 16; ++i)
                memcpy(&words[i], cs.block + i * 4, 4);

            uint32_t out_cv[16];
            uint32_t flags = cs.flags | chunk_start_flag(cs);
            compress(out_cv, cs.cv, words,
                     cs.chunk_counter,
                     kBlockSize, flags);

            memcpy(cs.cv, out_cv, 32);
            cs.blocks_compressed += 1;
            cs.block_len = 0;
        }

        size_t take = kBlockSize - cs.block_len;
        if (take > len) take = len;
        memcpy(cs.block + cs.block_len, input, take);
        cs.block_len += take;
        input += take;
        len -= take;
    }
}

__forceinline void chunk_state_finalize_cv(const chunk_state_t& cs,
                                            uint32_t out[8])
{
    uint8_t block[kBlockSize];
    memcpy(block, cs.block, cs.block_len);
    memset(block + cs.block_len, 0, kBlockSize - cs.block_len);

    uint32_t words[16];
    for (int i = 0; i < 16; ++i)
        memcpy(&words[i], block + i * 4, 4);

    uint32_t out16[16];
    uint32_t flags = cs.flags | chunk_start_flag(cs) | kFlag_ChunkEnd;
    compress(out16, cs.cv, words,
             cs.chunk_counter,
             static_cast<uint32_t>(cs.block_len), flags);
    memcpy(out, out16, 32);
}

__forceinline void parent_cv(const uint32_t left[8], const uint32_t right[8],
                              const uint32_t key[8], uint32_t flags,
                              uint32_t out[8])
{
    uint32_t block_words[16];
    memcpy(block_words, left, 32);
    memcpy(block_words + 8, right, 32);

    uint32_t out16[16];
    compress(out16, key, block_words, 0, kBlockSize,
             flags | kFlag_Parent);
    memcpy(out, out16, 32);
}

__forceinline void root_output(const uint32_t chaining[8],
                                const uint8_t* block, size_t block_len,
                                uint64_t counter, uint32_t flags,
                                uint8_t out[32])
{
    uint8_t padded[kBlockSize];
    memcpy(padded, block, block_len);
    memset(padded + block_len, 0, kBlockSize - block_len);

    uint32_t words[16];
    for (int i = 0; i < 16; ++i)
        memcpy(&words[i], padded + i * 4, 4);

    uint32_t out16[16];
    compress(out16, chaining, words, counter,
             static_cast<uint32_t>(block_len),
             flags | kFlag_Root);

    memcpy(out, out16, 32);
}

inline void hash_with_iv(const uint8_t* data, size_t len,
                         const uint32_t iv[8], uint8_t out[32])
{
    if (len <= static_cast<size_t>(kChunkSize))
    {
        chunk_state_t cs;
        chunk_state_init(cs, iv, 0);
        if (len > 0)
            chunk_state_update(cs, data, len);

        root_output(cs.cv, cs.block, cs.block_len, cs.chunk_counter,
                    chunk_start_flag(cs) | kFlag_ChunkEnd, out);
        return;
    }

    struct cv_t { uint32_t v[8]; };
    std::vector<cv_t> cvs;

    size_t pos = 0;
    while (pos < len)
    {
        size_t chunk_len = static_cast<size_t>(kChunkSize);
        if (chunk_len > len - pos)
            chunk_len = len - pos;

        chunk_state_t cs;
        chunk_state_init(cs, iv, 0);
        chunk_state_update(cs, data + pos, chunk_len);

        cv_t cv;
        chunk_state_finalize_cv(cs, cv.v);
        cvs.push_back(cv);

        pos += chunk_len;
    }

    while (cvs.size() > 2)
    {
        std::vector<cv_t> next;
        for (size_t i = 0; i < cvs.size(); i += 2)
        {
            if (i + 1 < cvs.size())
            {
                cv_t parent;
                parent_cv(cvs[i].v, cvs[i + 1].v, iv, 0, parent.v);
                next.push_back(parent);
            }
            else
            {
                next.push_back(cvs[i]);
            }
        }
        cvs = std::move(next);
    }

    uint32_t block_words[16];
    memcpy(block_words, cvs[0].v, 32);
    memcpy(block_words + 8, cvs[1].v, 32);

    uint32_t out16[16];
    compress(out16, iv, block_words, 0, kBlockSize,
             kFlag_Parent | kFlag_Root);
    memcpy(out, out16, 32);
}

inline void hash(const uint8_t* data, size_t len, uint8_t out[32])
{
    hash_with_iv(data, len, kIV, out);
}

inline void hash(const void* data, size_t len, uint8_t out[32])
{
    hash_with_iv(static_cast<const uint8_t*>(data), len, kIV, out);
}

}
}
