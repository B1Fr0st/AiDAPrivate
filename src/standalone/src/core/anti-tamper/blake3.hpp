#pragma once

#include <cstdint>
#include <cstring>

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

constexpr uint32_t kFlags_ChunkStart    = 1u << 0;
constexpr uint32_t kFlags_ChunkEnd      = 1u << 1;
constexpr uint32_t kFlags_Tree          = 1u << 2;
constexpr uint32_t kFlags_Parent        = 1u << 3;
constexpr uint32_t kFlags_Root          = 1u << 4;

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
    uint32_t counter,
    uint32_t block_len,
    uint32_t flags)
{
    uint32_t state[16];
    memcpy(state, chaining, 32);
    memcpy(state + 8, kIV, 32);
    state[12] ^= counter & 0xFFFFFFFF;
    state[13] ^= counter >> 32;
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

__forceinline size_t chunk_state_len(const chunk_state_t& cs)
{
    return cs.blocks_compressed * kBlockSize + cs.block_len;
}

__forceinline uint32_t chunk_start_flag(const chunk_state_t& cs)
{
    return cs.blocks_compressed == 0 ? kFlags_ChunkStart : 0;
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
            {
                memcpy(&words[i], cs.block + i * 4, 4);
            }

            uint32_t out_cv[16];
            uint32_t flags = cs.flags | chunk_start_flag(cs);
            compress(out_cv, cs.cv, words,
                     static_cast<uint32_t>(cs.chunk_counter),
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

__forceinline void chunk_state_finalize(const chunk_state_t& cs,
                                         uint32_t out[8])
{
    uint8_t block[kBlockSize];
    memcpy(block, cs.block, cs.block_len);
    memset(block + cs.block_len, 0, kBlockSize - cs.block_len);

    uint32_t words[16];
    for (int i = 0; i < 16; ++i)
        memcpy(&words[i], block + i * 4, 4);

    uint32_t out16[16];
    uint32_t flags = cs.flags | chunk_start_flag(cs) | kFlags_ChunkEnd;
    compress(out16, cs.cv, words,
             static_cast<uint32_t>(cs.chunk_counter),
             static_cast<uint32_t>(cs.block_len), flags);
    memcpy(out, out16, 32);
}

__forceinline void parent_output(const uint32_t left_cv[8],
                                  const uint32_t right_cv[8],
                                  const uint32_t key[8],
                                  uint32_t flags,
                                  uint32_t out[8])
{
    uint32_t block_words[16];
    memcpy(block_words, left_cv, 32);
    memcpy(block_words + 8, right_cv, 32);

    uint32_t out16[16];
    compress(out16, key, block_words, 0, kBlockSize,
             flags | kFlags_Parent);
    memcpy(out, out16, 32);
}

__forceinline void root_output(const uint32_t cv[8],
                                const uint8_t* block, size_t block_len,
                                uint64_t chunk_counter, uint32_t flags,
                                uint8_t out[32])
{
    uint8_t padded[kBlockSize];
    memcpy(padded, block, block_len);
    memset(padded + block_len, 0, kBlockSize - block_len);

    uint32_t words[16];
    for (int i = 0; i < 16; ++i)
        memcpy(&words[i], padded + i * 4, 4);

    uint32_t out16[16];
    compress(out16, cv, words,
             static_cast<uint32_t>(chunk_counter),
             static_cast<uint32_t>(block_len),
             flags | kFlags_Root);

    for (int i = 0; i < 8; ++i)
    {
        out[i * 4]     = static_cast<uint8_t>((out16[i] >> 24) & 0xFF);
        out[i * 4 + 1] = static_cast<uint8_t>((out16[i] >> 16) & 0xFF);
        out[i * 4 + 2] = static_cast<uint8_t>((out16[i] >> 8) & 0xFF);
        out[i * 4 + 3] = static_cast<uint8_t>(out16[i] & 0xFF);
    }
}

__declspec(noinline) void hash(const void* data, size_t len, uint8_t out[32])
{
    const auto* input = static_cast<const uint8_t*>(data);
    const uint32_t key[8] = {
        kIV[0], kIV[1], kIV[2], kIV[3],
        kIV[4], kIV[5], kIV[6], kIV[7]
    };
    const uint32_t flags = 0;

    if (len <= kChunkSize)
    {
        chunk_state_t cs;
        chunk_state_init(cs, key, flags);
        chunk_state_update(cs, input, len);
        uint32_t cv[8];
        chunk_state_finalize(cs, cv);
        root_output(cv, cs.block, cs.block_len, cs.chunk_counter,
                    cs.flags | chunk_start_flag(cs) | kFlags_ChunkEnd, out);
        return;
    }

    size_t chunks_remaining = (len + kChunkSize - 1) / kChunkSize;
    chunk_state_t cs;
    chunk_state_init(cs, key, flags);
    size_t pos = 0;

    while (chunks_remaining > 1)
    {
        size_t take = kChunkSize - chunk_state_len(cs);
        if (take > len - pos) take = len - pos;

        chunk_state_update(cs, input + pos, take);
        pos += take;

        if (chunk_state_len(cs) == kChunkSize)
        {
            uint32_t cv[8];
            chunk_state_finalize(cs, cv);
            chunk_state_init(cs, key, flags);
            cs.cv[0] = cv[0]; cs.cv[1] = cv[1]; cs.cv[2] = cv[2]; cs.cv[3] = cv[3];
            cs.cv[4] = cv[4]; cs.cv[5] = cv[5]; cs.cv[6] = cv[6]; cs.cv[7] = cv[7];
            cs.chunk_counter += 1;
            chunks_remaining -= 1;
        }
    }

    uint32_t final_cv[8];
    chunk_state_update(cs, input + pos, len - pos);
    chunk_state_finalize(cs, final_cv);

    root_output(final_cv, cs.block, cs.block_len, cs.chunk_counter,
                cs.flags | chunk_start_flag(cs) | kFlags_ChunkEnd, out);
}

}
}
