#pragma once

#include <windows.h>
#include <psapi.h>
#include <bcrypt.h>
#include <intrin.h>
#include <immintrin.h>
#include <wmmintrin.h>

#include <atomic>
#include <chrono>
#include <cstdint>
#include <cstring>
#include <exception>
#include <mutex>
#include <thread>
#include <vector>

#include "state.hpp"
#include "key_pipeline.hpp"
#include "tpm_attest.hpp"
#include "webhook.hpp"
#include "../infra/executor.hpp"

#pragma comment(lib, "bcrypt.lib")

namespace anti_tamper {
namespace integrity {

namespace diag {

    __forceinline void hex_encode(char* out, size_t out_cap,
                                   const uint8_t* data, size_t len)
    {
        static const char hex[] = "0123456789ABCDEF";
        size_t pos = 0;
        for (size_t i = 0; i < len && pos + 2 < out_cap; ++i)
        {
            out[pos++] = hex[(data[i] >> 4) & 0xF];
            out[pos++] = hex[data[i] & 0xF];
        }
        if (pos < out_cap)
            out[pos] = '\0';
        else if (out_cap > 0)
            out[out_cap - 1] = '\0';
    }

}

namespace siphash {

    __forceinline uint64_t rotl(uint64_t x, int b) { return (x << b) | (x >> (64 - b)); }

    __forceinline void sipround(uint64_t& v0, uint64_t& v1, uint64_t& v2, uint64_t& v3)
    {
        v0 += v1; v1 = rotl(v1, 13); v1 ^= v0; v0 = rotl(v0, 32);
        v2 += v3; v3 = rotl(v3, 16); v3 ^= v2;
        v0 += v3; v3 = rotl(v3, 21); v3 ^= v0;
        v2 += v1; v1 = rotl(v1, 17); v1 ^= v2; v2 = rotl(v2, 32);
    }

    __forceinline uint64_t hash(const uint8_t* data, size_t len,
                                uint64_t k0, uint64_t k1)
    {
        uint64_t v0 = 0x736F6D6570736575ULL ^ k0;
        uint64_t v1 = 0x646F72616E646F6DULL ^ k1;
        uint64_t v2 = 0x6C7967656E657261ULL ^ k0;
        uint64_t v3 = 0x7465646279746573ULL ^ k1;

        const uint8_t* end = data + len - (len % 8);
        const int left = static_cast<int>(len & 7);
        uint64_t b = static_cast<uint64_t>(len) << 56;

        for (; data != end; data += 8)
        {
            uint64_t m;
            memcpy(&m, data, 8);
            v3 ^= m;
            sipround(v0, v1, v2, v3);
            sipround(v0, v1, v2, v3);
            v0 ^= m;
        }

        switch (left)
        {
        case 7: b |= static_cast<uint64_t>(data[6]) << 48; [[fallthrough]];
        case 6: b |= static_cast<uint64_t>(data[5]) << 40; [[fallthrough]];
        case 5: b |= static_cast<uint64_t>(data[4]) << 32; [[fallthrough]];
        case 4: b |= static_cast<uint64_t>(data[3]) << 24; [[fallthrough]];
        case 3: b |= static_cast<uint64_t>(data[2]) << 16; [[fallthrough]];
        case 2: b |= static_cast<uint64_t>(data[1]) << 8;  [[fallthrough]];
        case 1: b |= static_cast<uint64_t>(data[0]);        break;
        case 0: break;
        }

        v3 ^= b;
        sipround(v0, v1, v2, v3);
        sipround(v0, v1, v2, v3);
        v0 ^= b;
        v2 ^= 0xFF;
        sipround(v0, v1, v2, v3);
        sipround(v0, v1, v2, v3);
        sipround(v0, v1, v2, v3);
        sipround(v0, v1, v2, v3);

        return v0 ^ v1 ^ v2 ^ v3;
    }

    __forceinline uint64_t siphash_3u64(uint64_t a, uint64_t b, uint64_t c)
    {
        uint8_t buf[24];
        memcpy(buf, &a, 8);
        memcpy(buf + 8, &b, 8);
        memcpy(buf + 16, &c, 8);
        return hash(buf, 24, a ^ 0x736F6D6570736575ULL, c ^ 0x646F72616E646F6DULL);
    }

}

namespace sha256 {

    inline BCRYPT_ALG_HANDLE get_hash_alg()
    {
        thread_local BCRYPT_ALG_HANDLE h = nullptr;
        if (!h)
        {
            if (BCryptOpenAlgorithmProvider(&h, BCRYPT_SHA256_ALGORITHM,
                                            nullptr, 0) != 0)
            {
                h = nullptr;
            }
        }
        return h;
    }

    inline BCRYPT_ALG_HANDLE get_hmac_alg()
    {
        thread_local BCRYPT_ALG_HANDLE h = nullptr;
        if (!h)
        {
            if (BCryptOpenAlgorithmProvider(&h, BCRYPT_SHA256_ALGORITHM,
                                            nullptr, BCRYPT_ALG_HANDLE_HMAC_FLAG) != 0)
            {
                h = nullptr;
            }
        }
        return h;
    }

    inline bool hash(const void* data, size_t size, uint8_t out[32])
    {
        BCRYPT_ALG_HANDLE hAlg = get_hash_alg();
        if (!hAlg) return false;
        BCRYPT_HASH_HANDLE hHash = nullptr;
        bool ok = false;

        if (BCryptCreateHash(hAlg, &hHash, nullptr, 0, nullptr, 0, 0) != 0)
        {
            return false;
        }

        if (BCryptHashData(hHash, const_cast<PUCHAR>(
                static_cast<const uint8_t*>(data)), static_cast<ULONG>(size), 0) == 0)
        {
            ok = (BCryptFinishHash(hHash, out, 32, 0) == 0);
        }

        BCryptDestroyHash(hHash);
        return ok;
    }

    inline bool hmac(const uint8_t* key, size_t key_len,
                     const uint8_t* data, size_t data_len,
                     uint8_t out[32])
    {
        BCRYPT_ALG_HANDLE hAlg = get_hmac_alg();
        if (!hAlg) return false;
        BCRYPT_HASH_HANDLE hHash = nullptr;
        bool ok = false;
        if (BCryptCreateHash(hAlg, &hHash, nullptr, 0,
                             const_cast<PUCHAR>(key),
                             static_cast<ULONG>(key_len), 0) == 0)
        {
            if (BCryptHashData(hHash, const_cast<PUCHAR>(data),
                               static_cast<ULONG>(data_len), 0) == 0)
            {
                ok = (BCryptFinishHash(hHash, out, 32, 0) == 0);
            }
            BCryptDestroyHash(hHash);
        }
        return ok;
    }

    inline bool hkdf_expand(const uint8_t* prk, size_t prk_len,
                            const uint8_t* info, size_t info_len,
                            uint8_t* out, size_t out_len)
    {
        if (out_len > 32 * 255) return false;
        uint8_t t[32] = {};
        size_t pos = 0;
        uint8_t counter = 1;
        size_t t_len = 0;
        std::vector<uint8_t> buf;
        buf.reserve(32 + info_len + 1);
        while (pos < out_len)
        {
            buf.clear();
            if (t_len > 0) buf.insert(buf.end(), t, t + t_len);
            if (info && info_len) buf.insert(buf.end(), info, info + info_len);
            buf.push_back(counter);
            if (!hmac(prk, prk_len, buf.data(), buf.size(), t)) return false;
            t_len = 32;
            size_t copy_len = (out_len - pos) < 32 ? (out_len - pos) : 32;
            memcpy(out + pos, t, copy_len);
            pos += copy_len;
            ++counter;
        }
        SecureZeroMemory(t, sizeof(t));
        return true;
    }

}

namespace detail {

    inline std::atomic<uint64_t> s_siphash_k0_obf{0};
    inline std::atomic<uint64_t> s_siphash_k1_obf{0};
    inline std::atomic<uint64_t> s_siphash_xor_mask{0};
    inline std::atomic<bool>     s_keys_initialized{false};

    inline std::atomic<uint64_t> s_session_secret_lo{0};
    inline std::atomic<uint64_t> s_session_secret_hi{0};

    inline std::atomic<uint64_t> s_self_chain_seed{0};
    inline std::atomic<uint64_t> s_self_chain_anchor{0};

    inline std::atomic<uint64_t> s_text_chain_anchor{0};

    inline std::mutex& self_chain_mtx()
    {
        static std::mutex m;
        return m;
    }

    inline bool rdseed_u64(uint64_t& out)
    {
        for (int attempt = 0; attempt < 32; ++attempt)
        {
            unsigned __int64 r = 0;
            if (_rdseed64_step(&r) != 0) { out = static_cast<uint64_t>(r); return true; }
            _mm_pause();
        }
        return false;
    }

    inline bool rdrand_u64(uint64_t& out)
    {
        for (int attempt = 0; attempt < 32; ++attempt)
        {
            unsigned __int64 r = 0;
            if (_rdrand64_step(&r) != 0) { out = static_cast<uint64_t>(r); return true; }
            _mm_pause();
        }
        return false;
    }

    inline uint64_t fresh_entropy()
    {
        uint64_t a = 0, b = 0;
        if (!rdseed_u64(a)) rdrand_u64(a);
        if (!rdseed_u64(b)) rdrand_u64(b);
        LARGE_INTEGER qpc{};
        QueryPerformanceCounter(&qpc);
        FILETIME ft{};
        GetSystemTimePreciseAsFileTime(&ft);
        uint64_t ts = (static_cast<uint64_t>(ft.dwHighDateTime) << 32) | ft.dwLowDateTime;
        uint8_t bcrypt_buf[16] = {};
        BCryptGenRandom(nullptr, bcrypt_buf, sizeof(bcrypt_buf), BCRYPT_USE_SYSTEM_PREFERRED_RNG);
        uint64_t bcrypt_lo, bcrypt_hi;
        memcpy(&bcrypt_lo, bcrypt_buf, 8);
        memcpy(&bcrypt_hi, bcrypt_buf + 8, 8);
        return a ^ b ^ static_cast<uint64_t>(qpc.QuadPart) ^ ts ^ bcrypt_lo ^ bcrypt_hi;
    }

    __forceinline uint64_t load_k0()
    {
        return s_siphash_k0_obf.load(std::memory_order_acquire)
             ^ s_siphash_xor_mask.load(std::memory_order_acquire);
    }

    __forceinline uint64_t load_k1()
    {
        uint64_t mask = s_siphash_xor_mask.load(std::memory_order_acquire);
        return s_siphash_k1_obf.load(std::memory_order_acquire)
             ^ ((mask << 17) | (mask >> 47));
    }

    inline void derive_session_keys(const uint8_t* text_start, size_t text_size)
    {
        size_t prefix_len = (text_size > 256) ? 256 : text_size;
        uint8_t sha[32] = {};
        sha256::hash(text_start, prefix_len, sha);

        uint64_t sha_lo, sha_hi;
        memcpy(&sha_lo, sha, 8);
        memcpy(&sha_hi, sha + 8, 8);
        uint64_t sha_lo2, sha_hi2;
        memcpy(&sha_lo2, sha + 16, 8);
        memcpy(&sha_hi2, sha + 24, 8);

        int cpu_info[4] = {};
        __cpuid(cpu_info, 1);
        uint64_t cpuid_val = static_cast<uint64_t>(cpu_info[0]) |
                             (static_cast<uint64_t>(cpu_info[3]) << 32);

        uint64_t entropy_a = fresh_entropy();
        uint64_t entropy_b = fresh_entropy();
        uint64_t mask = fresh_entropy();
        if (mask == 0) mask = 0xA1DAA0E2C0DECAFEULL;

        uint64_t k0 = sha_lo ^ cpuid_val ^ entropy_a;
        uint64_t k1 = sha_hi ^ (cpuid_val >> 17) ^ (entropy_a << 23);

        s_siphash_xor_mask.store(mask, std::memory_order_release);
        s_siphash_k0_obf.store(k0 ^ mask, std::memory_order_release);
        s_siphash_k1_obf.store(k1 ^ ((mask << 17) | (mask >> 47)), std::memory_order_release);
        s_session_secret_lo.store(sha_lo2 ^ entropy_b, std::memory_order_release);
        s_session_secret_hi.store(sha_hi2 ^ (entropy_b << 11) ^ entropy_a, std::memory_order_release);
        s_keys_initialized.store(true, std::memory_order_release);
    }

    inline void rotate_session_secret()
    {
        uint64_t e1 = fresh_entropy();
        uint64_t e2 = fresh_entropy();
        s_session_secret_lo.fetch_xor(e1, std::memory_order_acq_rel);
        s_session_secret_hi.fetch_xor(e2, std::memory_order_acq_rel);
    }

    inline uint64_t self_hash_siphash_impl()
    {
        auto func_start = reinterpret_cast<const uint8_t*>(&siphash::hash);

        MEMORY_BASIC_INFORMATION mbi{};
        if (VirtualQuery(func_start, &mbi, sizeof(mbi)) == 0)
            return 0;

        size_t check_size = 128;
        uint64_t region_end = reinterpret_cast<uint64_t>(mbi.BaseAddress) + mbi.RegionSize;
        uint64_t func_addr = reinterpret_cast<uint64_t>(func_start);
        if (func_addr + check_size > region_end)
            check_size = static_cast<size_t>(region_end - func_addr);

        return siphash::hash(func_start, check_size, load_k0(), load_k1());
    }

    inline uint64_t derive_per_call_key()
    {
        uint64_t e = fresh_entropy();
        return siphash::siphash_3u64(e, load_k0(), load_k1());
    }

    inline uint64_t self_hash_chain_compute(uint64_t per_call_key)
    {
        auto func_start = reinterpret_cast<const uint8_t*>(&siphash::hash);
        MEMORY_BASIC_INFORMATION mbi{};
        if (VirtualQuery(func_start, &mbi, sizeof(mbi)) == 0)
            return 0;

        size_t check_size = 128;
        uint64_t region_end = reinterpret_cast<uint64_t>(mbi.BaseAddress) + mbi.RegionSize;
        uint64_t func_addr = reinterpret_cast<uint64_t>(func_start);
        if (func_addr + check_size > region_end)
            check_size = static_cast<size_t>(region_end - func_addr);

        uint64_t base_chain = s_self_chain_seed.load(std::memory_order_acquire);
        uint64_t k0 = per_call_key;
        uint64_t k1 = ~per_call_key ^ 0x9E3779B97F4A7C15ULL;
        constexpr size_t kStride = 32;
        size_t pos = 0;
        uint8_t buf[kStride + 16];
        while (pos < check_size)
        {
            size_t this_chunk = (check_size - pos < kStride) ? (check_size - pos) : kStride;
            memcpy(buf, func_start + pos, this_chunk);
            memcpy(buf + this_chunk, &base_chain, 8);
            uint64_t mix = static_cast<uint64_t>(pos) ^ check_size;
            memcpy(buf + this_chunk + 8, &mix, 8);
            base_chain = siphash::hash(buf, this_chunk + 16, k0, k1);
            pos += this_chunk;
        }
        SecureZeroMemory(buf, sizeof(buf));
        return base_chain;
    }

    constexpr uint32_t kPageSize = 4096;
    constexpr uint32_t kKeyRotationSec = 60;

    struct page_mac_t
    {
        uint8_t  tag[8];
        uint8_t  full_tag[16];
        uint64_t seq;
        uint64_t baseline_siphash;
    };

    struct page_table_t
    {
        std::vector<page_mac_t> entries;
        uint64_t                base = 0;
        uint32_t                size = 0;
        std::atomic<uint64_t>   key_epoch{0};
        std::atomic<uint64_t>   last_rotation_qpc{0};
        std::atomic<uint64_t>   last_full_pass_ms{0};
        std::atomic<uint32_t>   verifier_quorum_failures{0};
        std::mutex              mtx;
    };

    inline page_table_t& page_table()
    {
        static page_table_t p;
        return p;
    }

    inline std::atomic<bool>& periodic_running_flag()
    {
        static std::atomic<bool> v{false};
        return v;
    }

    inline std::atomic<bool>& periodic_violation_flag()
    {
        static std::atomic<bool> v{false};
        return v;
    }

    inline std::atomic<uint64_t>& periodic_pass_counter()
    {
        static std::atomic<uint64_t> v{0};
        return v;
    }

    inline LARGE_INTEGER qpc_freq_cached()
    {
        static LARGE_INTEGER f{};
        if (f.QuadPart == 0) QueryPerformanceFrequency(&f);
        return f;
    }

    inline uint64_t qpc_now_ms()
    {
        LARGE_INTEGER q{};
        QueryPerformanceCounter(&q);
        LARGE_INTEGER f = qpc_freq_cached();
        if (f.QuadPart == 0) return 0;
        return static_cast<uint64_t>((q.QuadPart * 1000ULL) / f.QuadPart);
    }

    inline void aes128_expand_key(const uint8_t key[16], __m128i round_keys[11])
    {
        round_keys[0] = _mm_loadu_si128(reinterpret_cast<const __m128i*>(key));
        auto exp = [&](__m128i k, __m128i ka) {
            ka = _mm_shuffle_epi32(ka, 0xFF);
            __m128i t = _mm_slli_si128(k, 4);
            k = _mm_xor_si128(k, t);
            t = _mm_slli_si128(t, 4);
            k = _mm_xor_si128(k, t);
            t = _mm_slli_si128(t, 4);
            k = _mm_xor_si128(k, t);
            return _mm_xor_si128(k, ka);
        };
        round_keys[1]  = exp(round_keys[0],  _mm_aeskeygenassist_si128(round_keys[0],  0x01));
        round_keys[2]  = exp(round_keys[1],  _mm_aeskeygenassist_si128(round_keys[1],  0x02));
        round_keys[3]  = exp(round_keys[2],  _mm_aeskeygenassist_si128(round_keys[2],  0x04));
        round_keys[4]  = exp(round_keys[3],  _mm_aeskeygenassist_si128(round_keys[3],  0x08));
        round_keys[5]  = exp(round_keys[4],  _mm_aeskeygenassist_si128(round_keys[4],  0x10));
        round_keys[6]  = exp(round_keys[5],  _mm_aeskeygenassist_si128(round_keys[5],  0x20));
        round_keys[7]  = exp(round_keys[6],  _mm_aeskeygenassist_si128(round_keys[6],  0x40));
        round_keys[8]  = exp(round_keys[7],  _mm_aeskeygenassist_si128(round_keys[7],  0x80));
        round_keys[9]  = exp(round_keys[8],  _mm_aeskeygenassist_si128(round_keys[8],  0x1B));
        round_keys[10] = exp(round_keys[9],  _mm_aeskeygenassist_si128(round_keys[9],  0x36));
    }

    __forceinline __m128i aes128_encrypt_block(const __m128i round_keys[11], __m128i in)
    {
        __m128i x = _mm_xor_si128(in, round_keys[0]);
        x = _mm_aesenc_si128(x, round_keys[1]);
        x = _mm_aesenc_si128(x, round_keys[2]);
        x = _mm_aesenc_si128(x, round_keys[3]);
        x = _mm_aesenc_si128(x, round_keys[4]);
        x = _mm_aesenc_si128(x, round_keys[5]);
        x = _mm_aesenc_si128(x, round_keys[6]);
        x = _mm_aesenc_si128(x, round_keys[7]);
        x = _mm_aesenc_si128(x, round_keys[8]);
        x = _mm_aesenc_si128(x, round_keys[9]);
        return _mm_aesenclast_si128(x, round_keys[10]);
    }

    __forceinline __m128i bswap128(__m128i x)
    {
        const __m128i mask = _mm_set_epi8(0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15);
        return _mm_shuffle_epi8(x, mask);
    }

    __forceinline __m128i ghash_mul(__m128i a, __m128i b)
    {
        __m128i T0 = _mm_clmulepi64_si128(a, b, 0x00);
        __m128i T1 = _mm_clmulepi64_si128(a, b, 0x10);
        __m128i T2 = _mm_clmulepi64_si128(a, b, 0x01);
        __m128i T3 = _mm_clmulepi64_si128(a, b, 0x11);
        T1 = _mm_xor_si128(T1, T2);
        T2 = _mm_slli_si128(T1, 8);
        T1 = _mm_srli_si128(T1, 8);
        T0 = _mm_xor_si128(T0, T2);
        T3 = _mm_xor_si128(T3, T1);
        __m128i tmp7 = _mm_srli_epi32(T0, 31);
        __m128i tmp8 = _mm_srli_epi32(T3, 31);
        T0 = _mm_slli_epi32(T0, 1);
        T3 = _mm_slli_epi32(T3, 1);
        __m128i tmp9 = _mm_srli_si128(tmp7, 12);
        tmp8 = _mm_slli_si128(tmp8, 4);
        tmp7 = _mm_slli_si128(tmp7, 4);
        T0 = _mm_or_si128(T0, tmp7);
        T3 = _mm_or_si128(T3, tmp8);
        T3 = _mm_or_si128(T3, tmp9);
        __m128i tmp10 = _mm_slli_epi32(T0, 31);
        __m128i tmp11 = _mm_slli_epi32(T0, 30);
        __m128i tmp12 = _mm_slli_epi32(T0, 25);
        tmp10 = _mm_xor_si128(tmp10, tmp11);
        tmp10 = _mm_xor_si128(tmp10, tmp12);
        __m128i tmp13 = _mm_srli_si128(tmp10, 4);
        tmp10 = _mm_slli_si128(tmp10, 12);
        T0 = _mm_xor_si128(T0, tmp10);
        __m128i tmp14 = _mm_srli_epi32(T0, 1);
        __m128i tmp15 = _mm_srli_epi32(T0, 2);
        __m128i tmp16 = _mm_srli_epi32(T0, 7);
        tmp14 = _mm_xor_si128(tmp14, tmp15);
        tmp14 = _mm_xor_si128(tmp14, tmp16);
        tmp14 = _mm_xor_si128(tmp14, tmp13);
        T0 = _mm_xor_si128(T0, tmp14);
        return _mm_xor_si128(T3, T0);
    }

    inline void compute_aes_gmac_tag(const uint8_t key[16], const uint8_t iv[12],
                                     const uint8_t* aad, size_t aad_len,
                                     uint8_t tag_out[16])
    {
        __m128i round_keys[11];
        aes128_expand_key(key, round_keys);
        __m128i H = aes128_encrypt_block(round_keys, _mm_setzero_si128());
        H = bswap128(H);

        uint8_t j0_buf[16] = {};
        memcpy(j0_buf, iv, 12);
        j0_buf[15] = 0x01;
        __m128i j0 = _mm_loadu_si128(reinterpret_cast<const __m128i*>(j0_buf));

        __m128i Y = _mm_setzero_si128();
        size_t pos = 0;
        while (pos < aad_len)
        {
            uint8_t blk[16] = {};
            size_t this_len = (aad_len - pos < 16) ? (aad_len - pos) : 16;
            memcpy(blk, aad + pos, this_len);
            __m128i in = bswap128(_mm_loadu_si128(reinterpret_cast<const __m128i*>(blk)));
            Y = _mm_xor_si128(Y, in);
            Y = ghash_mul(Y, H);
            pos += this_len;
        }

        uint64_t aad_bits = static_cast<uint64_t>(aad_len) * 8ULL;
        uint8_t lenblk[16] = {};
        for (int i = 0; i < 8; ++i)
            lenblk[7 - i] = static_cast<uint8_t>((aad_bits >> (i * 8)) & 0xFF);
        __m128i len_be = bswap128(_mm_loadu_si128(reinterpret_cast<const __m128i*>(lenblk)));
        Y = _mm_xor_si128(Y, len_be);
        Y = ghash_mul(Y, H);

        __m128i E_j0 = aes128_encrypt_block(round_keys, j0);
        __m128i T = _mm_xor_si128(bswap128(Y), E_j0);
        _mm_storeu_si128(reinterpret_cast<__m128i*>(tag_out), T);
    }

    inline void derive_page_key(const uint8_t base_secret[32], uint64_t epoch,
                                uint8_t out_key[16])
    {
        uint8_t info[24];
        memcpy(info, "aida-page-mac/v1", 16);
        for (int i = 0; i < 8; ++i)
            info[16 + i] = static_cast<uint8_t>((epoch >> (i * 8)) & 0xFF);
        uint8_t expanded[16];
        sha256::hkdf_expand(base_secret, 32, info, sizeof(info), expanded, 16);
        memcpy(out_key, expanded, 16);
        SecureZeroMemory(expanded, sizeof(expanded));
    }

    inline bool compute_session_secret(uint8_t out[32])
    {
        uint64_t lo = s_session_secret_lo.load(std::memory_order_acquire);
        uint64_t hi = s_session_secret_hi.load(std::memory_order_acquire);
        uint64_t k0 = load_k0();
        uint64_t k1 = load_k1();
        uint8_t mat[32];
        memcpy(mat + 0,  &lo, 8);
        memcpy(mat + 8,  &hi, 8);
        memcpy(mat + 16, &k0, 8);
        memcpy(mat + 24, &k1, 8);
        memset(out, 0, 32);
        bool ok = sha256::hash(mat, sizeof(mat), out);
        SecureZeroMemory(mat, sizeof(mat));
        return ok;
    }

    inline bool build_iv_for_page(uint64_t base, uint32_t page_index, uint64_t epoch,
                                  uint8_t iv[12])
    {
        uint8_t mat[24];
        for (int i = 0; i < 8; ++i)
            mat[i] = static_cast<uint8_t>((base >> (i * 8)) & 0xFF);
        for (int i = 0; i < 4; ++i)
            mat[8 + i] = static_cast<uint8_t>((page_index >> (i * 8)) & 0xFF);
        for (int i = 0; i < 8; ++i)
            mat[12 + i] = static_cast<uint8_t>((epoch >> (i * 8)) & 0xFF);
        mat[20] = 'A'; mat[21] = 'i'; mat[22] = 'D'; mat[23] = 'A';
        uint8_t hash[32];
        if (!sha256::hash(mat, sizeof(mat), hash)) return false;
        memcpy(iv, hash, 12);
        SecureZeroMemory(hash, sizeof(hash));
        return true;
    }

    inline bool compute_page_full_tag(const page_table_t& pt, uint32_t page_index,
                                      const uint8_t* page_data, uint32_t page_size,
                                      const uint8_t key[16], uint8_t tag_out[16])
    {
        uint8_t iv[12];
        if (!build_iv_for_page(pt.base, page_index, pt.key_epoch.load(), iv)) return false;
        compute_aes_gmac_tag(key, iv, page_data, page_size, tag_out);
        SecureZeroMemory(iv, sizeof(iv));
        return true;
    }

    inline bool rebuild_page_table_locked(page_table_t& pt, uint64_t base, uint32_t size)
    {
        if (base == 0 || size == 0) return false;
        uint64_t started_ms = GetTickCount64();
        MEMORY_BASIC_INFORMATION entry_mbi{};
        SIZE_T entry_vq = VirtualQuery(reinterpret_cast<const void*>(base), &entry_mbi, sizeof(entry_mbi));
        pt.base = base;
        pt.size = size;
        uint32_t pages = (size + kPageSize - 1) / kPageSize;
        size_t old_entries = pt.entries.size();
        uint64_t epoch = pt.key_epoch.load();
        webhook::write_log_critical_fmt("page_mac",
            "rebuild_entry pid=%lu tid=%lu tick=%llu base=0x%llX size=0x%X pages=%u old_entries=%zu epoch=%llu vq=%llu mbi_base=0x%llX alloc_base=0x%llX region=0x%llX state=0x%lX protect=0x%lX type=0x%lX",
            GetCurrentProcessId(),
            GetCurrentThreadId(),
            static_cast<unsigned long long>(started_ms),
            static_cast<unsigned long long>(base),
            size,
            pages,
            old_entries,
            static_cast<unsigned long long>(epoch),
            static_cast<unsigned long long>(entry_vq),
            static_cast<unsigned long long>(reinterpret_cast<uintptr_t>(entry_mbi.BaseAddress)),
            static_cast<unsigned long long>(reinterpret_cast<uintptr_t>(entry_mbi.AllocationBase)),
            static_cast<unsigned long long>(entry_mbi.RegionSize),
            static_cast<unsigned long>(entry_mbi.State),
            static_cast<unsigned long>(entry_mbi.Protect),
            static_cast<unsigned long>(entry_mbi.Type));
        pt.entries.assign(pages, page_mac_t{});
        webhook::write_log_critical_fmt("page_mac",
            "rebuild_entries_assigned pages=%u entries=%zu elapsed_ms=%llu",
            pages,
            pt.entries.size(),
            static_cast<unsigned long long>(GetTickCount64() - started_ms));

        uint8_t base_secret[32];
        bool base_secret_ok = compute_session_secret(base_secret);
        uint8_t key[16];
        derive_page_key(base_secret, epoch, key);
        webhook::write_log_critical_fmt("page_mac",
            "rebuild_secret_ready secret_ok=%d epoch=%llu elapsed_ms=%llu",
            base_secret_ok ? 1 : 0,
            static_cast<unsigned long long>(epoch),
            static_cast<unsigned long long>(GetTickCount64() - started_ms));

        uint64_t first_pass_tick = GetTickCount64();
        const uint32_t progress_stride = pages >= 8192 ? 2048u : (pages >= 2048 ? 512u : (pages >= 256 ? 128u : 1u));
        webhook::write_log_critical_fmt("page_mac",
            "rebuild_first_pass_begin pages=%u stride=%u base=0x%llX size=0x%X",
            pages,
            progress_stride,
            static_cast<unsigned long long>(base),
            size);
        for (uint32_t i = 0; i < pages; ++i)
        {
            uint32_t this_size = kPageSize;
            uint32_t offset = i * kPageSize;
            if (offset + this_size > size) this_size = size - offset;
            const uint8_t* page = reinterpret_cast<const uint8_t*>(base + offset);
            uint8_t tag[16];
            if (!compute_page_full_tag(pt, i, page, this_size, key, tag))
            {
                webhook::write_log_critical_fmt("page_mac",
                    "rebuild_first_pass_tag_failed page=%u/%u offset=0x%X this_size=0x%X elapsed_ms=%llu",
                    i,
                    pages,
                    offset,
                    this_size,
                    static_cast<unsigned long long>(GetTickCount64() - first_pass_tick));
                SecureZeroMemory(base_secret, sizeof(base_secret));
                SecureZeroMemory(key, sizeof(key));
                return false;
            }
            memcpy(pt.entries[i].full_tag, tag, 16);
            memcpy(pt.entries[i].tag, tag, 8);
            pt.entries[i].seq = i;
            pt.entries[i].baseline_siphash = siphash::hash(
                page, this_size,
                load_k0() ^ static_cast<uint64_t>(i),
                load_k1() ^ static_cast<uint64_t>(i + 1));
            if (i == 0 || i + 1 == pages || ((i + 1) % progress_stride) == 0)
            {
                webhook::write_log_critical_fmt("page_mac",
                    "rebuild_first_pass_progress page=%u/%u offset=0x%X this_size=0x%X elapsed_ms=%llu baseline=0x%016llX",
                    i + 1,
                    pages,
                    offset,
                    this_size,
                    static_cast<unsigned long long>(GetTickCount64() - first_pass_tick),
                    static_cast<unsigned long long>(pt.entries[i].baseline_siphash));
            }
        }
        webhook::write_log_critical_fmt("page_mac",
            "rebuild_first_pass_done pages=%u elapsed_ms=%llu total_elapsed_ms=%llu",
            pages,
            static_cast<unsigned long long>(GetTickCount64() - first_pass_tick),
            static_cast<unsigned long long>(GetTickCount64() - started_ms));

        if (pages > 0)
        {
            const uint8_t* page0 = reinterpret_cast<const uint8_t*>(base);
            uint32_t page0_size = (kPageSize > size) ? size : kPageSize;
            char hex_tag0[33];
            diag::hex_encode(hex_tag0, sizeof(hex_tag0), pt.entries[0].full_tag, 16);
            uint64_t page0_head_hash = siphash::hash(page0,
                page0_size < 64 ? page0_size : 64,
                load_k0() ^ 0xA1DA1001ULL,
                load_k1() ^ 0xA1DA1002ULL);
            uint64_t secret_hash = siphash::hash(base_secret, sizeof(base_secret),
                load_k0() ^ 0xA1DA1003ULL,
                load_k1() ^ 0xA1DA1004ULL);
            webhook::write_log_critical_fmt("page_mac",
                "rebuild_baseline pages=%u epoch=%llu base=0x%llX size=0x%X "
                "page0_head64_hash=0x%016llX page0_tag=%s page0_baseline_siphash=0x%016llX session_secret_hash=0x%016llX",
                pages,
                static_cast<unsigned long long>(epoch),
                static_cast<unsigned long long>(base),
                size,
                static_cast<unsigned long long>(page0_head_hash),
                hex_tag0,
                static_cast<unsigned long long>(pt.entries[0].baseline_siphash),
                static_cast<unsigned long long>(secret_hash));
        }
        SecureZeroMemory(base_secret, sizeof(base_secret));
        SecureZeroMemory(key, sizeof(key));
        webhook::write_log_critical_fmt("page_mac",
            "rebuild_first_secret_zeroed elapsed_ms=%llu",
            static_cast<unsigned long long>(GetTickCount64() - started_ms));

        uint64_t anchor = 0;
        uint8_t accum[32];
        bool accum_secret_ok = compute_session_secret(accum);
        uint64_t anchor_tick = GetTickCount64();
        webhook::write_log_critical_fmt("page_mac",
            "rebuild_anchor_begin pages=%u secret_ok=%d elapsed_ms=%llu",
            pages,
            accum_secret_ok ? 1 : 0,
            static_cast<unsigned long long>(anchor_tick - started_ms));
        for (uint32_t i = 0; i < pages; ++i)
        {
            uint8_t buf[16 + 16];
            memcpy(buf, pt.entries[i].full_tag, 16);
            memcpy(buf + 16, accum, 16);
            uint8_t mac[32] = {};
            bool hmac_ok = sha256::hmac(accum, 32, buf, sizeof(buf), mac);
            if (!hmac_ok)
            {
                webhook::write_log_critical_fmt("page_mac",
                    "rebuild_anchor_hmac_failed page=%u/%u elapsed_ms=%llu",
                    i,
                    pages,
                    static_cast<unsigned long long>(GetTickCount64() - anchor_tick));
            }
            memcpy(accum, mac, 32);
            anchor ^= reinterpret_cast<const uint64_t*>(mac)[0];
            SecureZeroMemory(buf, sizeof(buf));
            if (i == 0 || i + 1 == pages || ((i + 1) % progress_stride) == 0)
            {
                webhook::write_log_critical_fmt("page_mac",
                    "rebuild_anchor_progress page=%u/%u elapsed_ms=%llu anchor_nonzero=%d hmac_ok=%d",
                    i + 1,
                    pages,
                    static_cast<unsigned long long>(GetTickCount64() - anchor_tick),
                    anchor != 0 ? 1 : 0,
                    hmac_ok ? 1 : 0);
            }
        }
        s_text_chain_anchor.store(anchor, std::memory_order_release);
        webhook::write_log_critical_fmt("page_mac",
            "rebuild_anchor_done pages=%u elapsed_ms=%llu total_elapsed_ms=%llu anchor_nonzero=%d",
            pages,
            static_cast<unsigned long long>(GetTickCount64() - anchor_tick),
            static_cast<unsigned long long>(GetTickCount64() - started_ms),
            anchor != 0 ? 1 : 0);
        SecureZeroMemory(accum, sizeof(accum));

        uint64_t last_rotation = qpc_now_ms();
        pt.last_rotation_qpc.store(last_rotation, std::memory_order_release);
        webhook::write_log_critical_fmt("page_mac",
            "rebuild_done pages=%u last_rotation_qpc=%llu total_elapsed_ms=%llu",
            pages,
            static_cast<unsigned long long>(last_rotation),
            static_cast<unsigned long long>(GetTickCount64() - started_ms));
        return true;
    }

    inline bool rotate_page_keys_locked(page_table_t& pt)
    {
        if (pt.entries.empty()) return false;
        uint64_t old_epoch = pt.key_epoch.load();
        uint64_t new_epoch = old_epoch + 1;

        uint8_t base_secret[32];
        compute_session_secret(base_secret);
        uint8_t new_key[16];
        derive_page_key(base_secret, new_epoch, new_key);

        pt.key_epoch.store(new_epoch, std::memory_order_release);

        for (uint32_t i = 0; i < pt.entries.size(); ++i)
        {
            uint32_t this_size = kPageSize;
            uint32_t offset = i * kPageSize;
            if (offset + this_size > pt.size) this_size = pt.size - offset;
            const uint8_t* page = reinterpret_cast<const uint8_t*>(pt.base + offset);
            uint8_t tag[16];
            if (!compute_page_full_tag(pt, i, page, this_size, new_key, tag))
            {
                SecureZeroMemory(base_secret, sizeof(base_secret));
                SecureZeroMemory(new_key, sizeof(new_key));
                return false;
            }
            memcpy(pt.entries[i].full_tag, tag, 16);
            memcpy(pt.entries[i].tag, tag, 8);
        }

        if (!pt.entries.empty() && pt.size > 0)
        {
            const uint8_t* page0 = reinterpret_cast<const uint8_t*>(pt.base);
            uint32_t page0_size = (kPageSize > pt.size) ? pt.size : kPageSize;
            uint64_t live_siphash = siphash::hash(
                page0, page0_size, load_k0(), load_k1() ^ 1ULL);
            char hex_tag0[33];
            diag::hex_encode(hex_tag0, sizeof(hex_tag0), pt.entries[0].full_tag, 16);
            uint64_t page0_head_hash = siphash::hash(page0,
                page0_size < 64 ? page0_size : 64,
                load_k0() ^ 0xA1DA2001ULL,
                load_k1() ^ 0xA1DA2002ULL);
            uint64_t secret_hash = siphash::hash(base_secret, sizeof(base_secret),
                load_k0() ^ 0xA1DA2003ULL,
                load_k1() ^ 0xA1DA2004ULL);
            webhook::write_log_critical_fmt("page_mac",
                "rotate old_epoch=%llu new_epoch=%llu pages=%zu "
                "page0_head64_hash=0x%016llX page0_new_tag=%s page0_baseline_siphash=0x%016llX "
                "page0_live_siphash=0x%016llX session_secret_hash=0x%016llX",
                static_cast<unsigned long long>(old_epoch),
                static_cast<unsigned long long>(new_epoch),
                pt.entries.size(),
                static_cast<unsigned long long>(page0_head_hash),
                hex_tag0,
                static_cast<unsigned long long>(pt.entries[0].baseline_siphash),
                static_cast<unsigned long long>(live_siphash),
                static_cast<unsigned long long>(secret_hash));
        }
        SecureZeroMemory(base_secret, sizeof(base_secret));
        SecureZeroMemory(new_key, sizeof(new_key));
        pt.last_rotation_qpc.store(qpc_now_ms(), std::memory_order_release);
        return true;
    }

    inline bool verify_page_locked(page_table_t& pt, uint32_t page_index)
    {
        if (page_index >= pt.entries.size())
        {
            webhook::write_log_critical_fmt("page_mac",
                "verify_page_locked_FAIL_path_A page_index=%u entries_size=%zu pt_base=0x%llX pt_size=0x%X",
                page_index,
                pt.entries.size(),
                static_cast<unsigned long long>(pt.base),
                pt.size);
            return false;
        }
        uint32_t this_size = kPageSize;
        uint32_t offset = page_index * kPageSize;
        if (offset + this_size > pt.size) this_size = pt.size - offset;
        const uint8_t* page = reinterpret_cast<const uint8_t*>(pt.base + offset);

        uint8_t base_secret[32];
        bool secret_ok = compute_session_secret(base_secret);
        uint8_t key[16];
        uint64_t cur_epoch = pt.key_epoch.load();
        derive_page_key(base_secret, cur_epoch, key);

        uint8_t tag[16];
        if (!compute_page_full_tag(pt, page_index, page, this_size, key, tag))
        {
            uint64_t secret_hash = siphash::hash(base_secret, sizeof(base_secret),
                load_k0() ^ 0xA1DA3001ULL,
                load_k1() ^ 0xA1DA3002ULL);
            uint64_t key_hash = siphash::hash(key, sizeof(key),
                load_k0() ^ 0xA1DA3003ULL,
                load_k1() ^ 0xA1DA3004ULL);
            webhook::write_log_critical_fmt("page_mac",
                "verify_page_locked_FAIL_path_B page=%u offset=0x%X size=0x%X epoch=%llu "
                "secret_ok=%d session_secret_hash=0x%016llX derived_key_hash=0x%016llX pt_base=0x%llX pt_size=0x%X",
                page_index,
                offset,
                this_size,
                static_cast<unsigned long long>(cur_epoch),
                secret_ok ? 1 : 0,
                static_cast<unsigned long long>(secret_hash),
                static_cast<unsigned long long>(key_hash),
                static_cast<unsigned long long>(pt.base),
                pt.size);
            SecureZeroMemory(base_secret, sizeof(base_secret));
            SecureZeroMemory(key, sizeof(key));
            return false;
        }
        bool ok = (memcmp(tag, pt.entries[page_index].full_tag, 16) == 0);
        if (!ok)
        {
            uint64_t baseline = pt.entries[page_index].baseline_siphash;
            uint64_t live_siphash = siphash::hash(
                page, this_size,
                load_k0() ^ static_cast<uint64_t>(page_index),
                load_k1() ^ static_cast<uint64_t>(page_index + 1));
            char hex_expected[33];
            char hex_computed[33];
            uint32_t tail_off = (this_size > 32) ? this_size - 32 : 0;
            uint32_t tail_len = (this_size > 32) ? 32 : this_size;
            diag::hex_encode(hex_expected, sizeof(hex_expected),
                             pt.entries[page_index].full_tag, 16);
            diag::hex_encode(hex_computed, sizeof(hex_computed), tag, 16);
            uint64_t first_hash = siphash::hash(page,
                this_size < 64 ? this_size : 64,
                load_k0() ^ 0xA1DA4001ULL,
                load_k1() ^ 0xA1DA4002ULL);
            uint64_t last_hash = siphash::hash(page + tail_off, tail_len,
                load_k0() ^ 0xA1DA4003ULL,
                load_k1() ^ 0xA1DA4004ULL);
            uint64_t secret_hash = siphash::hash(base_secret, sizeof(base_secret),
                load_k0() ^ 0xA1DA4005ULL,
                load_k1() ^ 0xA1DA4006ULL);
            uint64_t key_hash = siphash::hash(key, sizeof(key),
                load_k0() ^ 0xA1DA4007ULL,
                load_k1() ^ 0xA1DA4008ULL);
            const char* diagnosis =
                (live_siphash == baseline) ? "key_or_iv_mismatch"
                                           : "page_contents_changed";
            webhook::write_log_critical_fmt("page_mac",
                "verify_FAIL page=%u offset=0x%X size=0x%X epoch=%llu "
                "diagnosis=%s live_siphash=0x%016llX baseline_siphash=0x%016llX "
                "expected_tag=%s computed_tag=%s "
                "session_secret_hash=0x%016llX derived_key_hash=0x%016llX "
                "first64_hash=0x%016llX last32_hash=0x%016llX",
                page_index,
                offset,
                this_size,
                static_cast<unsigned long long>(cur_epoch),
                diagnosis,
                static_cast<unsigned long long>(live_siphash),
                static_cast<unsigned long long>(baseline),
                hex_expected,
                hex_computed,
                static_cast<unsigned long long>(secret_hash),
                static_cast<unsigned long long>(key_hash),
                static_cast<unsigned long long>(first_hash),
                static_cast<unsigned long long>(last_hash));
        }
        SecureZeroMemory(base_secret, sizeof(base_secret));
        SecureZeroMemory(key, sizeof(key));
        SecureZeroMemory(tag, sizeof(tag));
        return ok;
    }

}

__forceinline uint64_t hash_memory(const void* data, size_t size)
{
    return siphash::hash(static_cast<const uint8_t*>(data), size,
                         detail::load_k0(), detail::load_k1());
}

__forceinline uint64_t hash_memory_fixed_key(const void* data, size_t size,
                                              uint64_t k0, uint64_t k1)
{
    return siphash::hash(static_cast<const uint8_t*>(data), size, k0, k1);
}

namespace detail {

struct cached_code_layout_t
{
    std::mutex mtx;
    bool valid = false;
    uint64_t module_base = 0;
    uint64_t module_end = 0;
    uint64_t text_base = 0;
    uint32_t text_size = 0;
    uint32_t section_index = 0;
    uint32_t section_count = 0;
    uint32_t section_characteristics = 0;
    uint8_t text_sha256[32] = {};
};

inline cached_code_layout_t& code_layout_cache()
{
    static cached_code_layout_t v;
    return v;
}

inline void store_code_layout_cache(uint64_t module_base,
                                    uint64_t module_end,
                                    uint64_t text_base,
                                    uint32_t text_size,
                                    uint32_t section_index,
                                    uint32_t section_count,
                                    uint32_t section_characteristics,
                                    const uint8_t text_sha256[32])
{
    auto& cache = code_layout_cache();
    std::lock_guard<std::mutex> lk(cache.mtx);
    cache.valid = true;
    cache.module_base = module_base;
    cache.module_end = module_end;
    cache.text_base = text_base;
    cache.text_size = text_size;
    cache.section_index = section_index;
    cache.section_count = section_count;
    cache.section_characteristics = section_characteristics;
    memcpy(cache.text_sha256, text_sha256, 32);
}

inline bool load_code_layout_cache(uint64_t module_base,
                                   cached_code_layout_t& out)
{
    auto& cache = code_layout_cache();
    std::lock_guard<std::mutex> lk(cache.mtx);
    if (!cache.valid || cache.module_base != module_base)
        return false;
    out.valid = cache.valid;
    out.module_base = cache.module_base;
    out.module_end = cache.module_end;
    out.text_base = cache.text_base;
    out.text_size = cache.text_size;
    out.section_index = cache.section_index;
    out.section_count = cache.section_count;
    out.section_characteristics = cache.section_characteristics;
    memcpy(out.text_sha256, cache.text_sha256, 32);
    return true;
}

inline bool snapshot_code_from_layout(state::code_snapshot_t& snap,
                                      uint64_t module_base,
                                      uint64_t module_end,
                                      uint64_t text_base,
                                      uint32_t text_size,
                                      uint32_t section_index,
                                      uint32_t section_count,
                                      uint32_t section_characteristics,
                                      const char* source,
                                      const uint8_t* expected_sha256,
                                      bool update_cache)
{
    if (module_base == 0 || text_base == 0 || text_size == 0)
    {
        webhook::write_log_critical_fmt("integrity",
            "snapshot_code_%s_invalid_layout module_base=0x%llX module_end=0x%llX text_base=0x%llX text_size=0x%X",
            source,
            static_cast<unsigned long long>(module_base),
            static_cast<unsigned long long>(module_end),
            static_cast<unsigned long long>(text_base),
            text_size);
        return false;
    }

    if (module_end != 0 && (text_base < module_base || text_base + text_size > module_end || text_base + text_size < text_base))
    {
        webhook::write_log_critical_fmt("integrity",
            "snapshot_code_%s_text_out_of_image module_base=0x%llX module_end=0x%llX text_base=0x%llX text_size=0x%X",
            source,
            static_cast<unsigned long long>(module_base),
            static_cast<unsigned long long>(module_end),
            static_cast<unsigned long long>(text_base),
            text_size);
        return false;
    }

    MEMORY_BASIC_INFORMATION mbi{};
    SIZE_T vq = VirtualQuery(reinterpret_cast<const void*>(text_base), &mbi, sizeof(mbi));
    if (vq == 0 || mbi.State != MEM_COMMIT)
    {
        webhook::write_log_critical_fmt("integrity",
            "snapshot_code_%s_text_vq_failed vq=%zu state=0x%lX protect=0x%lX err=%lu text_base=0x%llX text_size=0x%X",
            source,
            static_cast<size_t>(vq),
            static_cast<unsigned long>(mbi.State),
            static_cast<unsigned long>(mbi.Protect),
            vq == 0 ? GetLastError() : 0,
            static_cast<unsigned long long>(text_base),
            text_size);
        return false;
    }

    uint8_t stable_sha256[32] = {};
    if (!sha256::hash(reinterpret_cast<const void*>(text_base), text_size, stable_sha256))
    {
        webhook::write_log_critical_fmt("integrity",
            "snapshot_code_%s_sha256_failed text_base=0x%llX text_size=0x%X",
            source,
            static_cast<unsigned long long>(text_base),
            text_size);
        return false;
    }

    if (expected_sha256 && memcmp(stable_sha256, expected_sha256, 32) != 0)
    {
        char expected_hex[65];
        char actual_hex[65];
        diag::hex_encode(expected_hex, sizeof(expected_hex), expected_sha256, 32);
        diag::hex_encode(actual_hex, sizeof(actual_hex), stable_sha256, 32);
        webhook::write_log_critical_fmt("integrity",
            "snapshot_code_%s_cached_text_sha_mismatch module_base=0x%llX text_base=0x%llX text_size=0x%X expected=%s actual=%s",
            source,
            static_cast<unsigned long long>(module_base),
            static_cast<unsigned long long>(text_base),
            text_size,
            expected_hex,
            actual_hex);
        return false;
    }

    state::code_snapshot_t next{};
    next.module_base = module_base;
    next.module_end = module_end;
    next.text_base = text_base;
    next.text_size = text_size;
    memcpy(next.text_sha256, stable_sha256, 32);

    {
        std::lock_guard<std::mutex> chain_lk(self_chain_mtx());
        derive_session_keys(reinterpret_cast<const uint8_t*>(next.text_base), next.text_size);
        next.text_hash = hash_memory(reinterpret_cast<const void*>(next.text_base), next.text_size);

        uint64_t seed_value = fresh_entropy();
        if (seed_value == 0) seed_value = 0xA1DAA0E2DEADBEEFULL;
        s_self_chain_seed.store(seed_value, std::memory_order_release);
        uint64_t per_call = siphash::siphash_3u64(seed_value, load_k0(), load_k1());
        uint64_t chain = self_hash_chain_compute(per_call);
        if (chain != 0)
        {
            uint8_t mat[16];
            memcpy(mat + 0, &chain, 8);
            memcpy(mat + 8, &per_call, 8);
            uint8_t mac[32] = {};
            uint8_t base_secret[32] = {};
            bool secret_ok = compute_session_secret(base_secret);
            bool hmac_ok = secret_ok && sha256::hmac(base_secret, 32, mat, sizeof(mat), mac);
            SecureZeroMemory(base_secret, sizeof(base_secret));
            if (hmac_ok)
            {
                uint64_t anchor = 0;
                memcpy(&anchor, mac, 8);
                s_self_chain_anchor.store(anchor ^ seed_value, std::memory_order_release);
            }
            else
            {
                s_self_chain_anchor.store(0, std::memory_order_release);
            }
            SecureZeroMemory(mac, sizeof(mac));
            SecureZeroMemory(mat, sizeof(mat));
        }
        else
        {
            s_self_chain_anchor.store(0, std::memory_order_release);
        }
    }

    {
        auto& pt = page_table();
        std::lock_guard<std::mutex> lk(pt.mtx);
        uint64_t rebuild_tick = GetTickCount64();
        webhook::write_log_critical_fmt("integrity",
            "snapshot_code_%s_page_table_rebuild_enter pid=%lu tid=%lu tick=%llu text_base=0x%llX text_size=0x%X",
            source,
            GetCurrentProcessId(),
            GetCurrentThreadId(),
            static_cast<unsigned long long>(rebuild_tick),
            static_cast<unsigned long long>(next.text_base),
            next.text_size);
        bool rebuilt = rebuild_page_table_locked(pt, next.text_base, next.text_size);
        webhook::write_log_critical_fmt("integrity",
            "snapshot_code_%s_page_table_rebuild_exit rebuilt=%d elapsed_ms=%llu text_base=0x%llX text_size=0x%X",
            source,
            rebuilt ? 1 : 0,
            static_cast<unsigned long long>(GetTickCount64() - rebuild_tick),
            static_cast<unsigned long long>(next.text_base),
            next.text_size);
        if (!rebuilt)
        {
            webhook::write_log_critical_fmt("integrity",
                "snapshot_code_%s_page_table_rebuild_failed text_base=0x%llX text_size=0x%X",
                source,
                static_cast<unsigned long long>(next.text_base),
                next.text_size);
            return false;
        }
    }

    if (tpm_attest::is_available())
        tpm_attest::extend_version_pcr(next.text_sha256);

    if (next.text_hash == 0)
    {
        webhook::write_log_critical_fmt("integrity",
            "snapshot_code_%s_zero_text_hash text_base=0x%llX text_size=0x%X",
            source,
            static_cast<unsigned long long>(next.text_base),
            next.text_size);
        return false;
    }

    snap = next;
    if (update_cache)
        store_code_layout_cache(module_base, module_end, text_base, text_size,
            section_index, section_count, section_characteristics, next.text_sha256);

    webhook::write_log_critical_fmt("integrity",
        "snapshot_code_%s_ok module_base=0x%llX module_end=0x%llX text_base=0x%llX text_size=0x%X text_hash=0x%016llX section=%u/%u chars=0x%X cache_update=%d",
        source,
        static_cast<unsigned long long>(snap.module_base),
        static_cast<unsigned long long>(snap.module_end),
        static_cast<unsigned long long>(snap.text_base),
        snap.text_size,
        static_cast<unsigned long long>(snap.text_hash),
        section_index,
        section_count,
        section_characteristics,
        update_cache ? 1 : 0);
    return true;
}

struct live_pe_layout_t
{
    const char* fail_reason = "unknown";
    DWORD seh_code = 0;
    uint16_t dos_magic = 0;
    LONG e_lfanew = 0;
    DWORD nt_signature = 0;
    WORD opt_magic = 0;
    WORD section_count = 0;
    DWORD size_of_image = 0;
    uint64_t text_base = 0;
    uint32_t text_size = 0;
    uint32_t section_index = 0;
    uint32_t section_characteristics = 0;
    bool parsed = false;
};

__declspec(noinline) static void read_live_pe_layout_seh(HMODULE mod,
                                                         uint64_t module_base,
                                                         live_pe_layout_t& out)
{
    __try
    {
        const auto* dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(mod);
        out.dos_magic = dos->e_magic;
        out.e_lfanew = dos->e_lfanew;
        if (out.dos_magic != IMAGE_DOS_SIGNATURE)
        {
            out.fail_reason = "bad_dos_magic";
        }
        else if (out.e_lfanew <= 0 || static_cast<uint32_t>(out.e_lfanew) > 0x10000u)
        {
            out.fail_reason = "bad_e_lfanew";
        }
        else
        {
            const auto* nt = reinterpret_cast<const IMAGE_NT_HEADERS64*>(
                reinterpret_cast<const uint8_t*>(mod) + out.e_lfanew);
            out.nt_signature = nt->Signature;
            out.opt_magic = nt->OptionalHeader.Magic;
            out.section_count = nt->FileHeader.NumberOfSections;
            out.size_of_image = nt->OptionalHeader.SizeOfImage;
            if (out.nt_signature != IMAGE_NT_SIGNATURE)
            {
                out.fail_reason = "bad_nt_signature";
            }
            else if (out.opt_magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC)
            {
                out.fail_reason = "bad_optional_magic";
            }
            else if (out.section_count == 0 || out.section_count > 96)
            {
                out.fail_reason = "bad_section_count";
            }
            else
            {
                const auto* sec = IMAGE_FIRST_SECTION(nt);
                for (WORD i = 0; i < out.section_count; ++i)
                {
                    if ((sec[i].Characteristics & IMAGE_SCN_CNT_CODE) != 0
                        && sec[i].Misc.VirtualSize > 0)
                    {
                        out.text_base = module_base + sec[i].VirtualAddress;
                        out.text_size = sec[i].Misc.VirtualSize;
                        out.section_index = i;
                        out.section_characteristics = sec[i].Characteristics;
                        out.parsed = true;
                        out.fail_reason = "none";
                        break;
                    }
                }
                if (!out.parsed)
                    out.fail_reason = "no_code_section";
            }
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        out.seh_code = GetExceptionCode();
        out.fail_reason = "seh";
    }
}

}

struct block_chain_verify_result_t
{
    uint32_t block_index = 0;
    uint32_t chain_count = 0;
    uint64_t block_base = 0;
    uint32_t block_size = 0;
    uint64_t expected_hash = 0;
    uint64_t actual_hash = 0;
    uint64_t prev_hash = 0;
    bool checked = false;
    bool layout_mismatch = false;
};

inline bool build_block_chain(const state::code_snapshot_t& snap,
                              std::vector<state::block_hash_t>& chain)
{
    if (snap.text_base == 0 || snap.text_size == 0) return false;

    chain.clear();
    constexpr uint32_t BLOCK_SIZE = 4096;
    uint32_t offset = 0;
    uint64_t prev_hash = 0;

    uint64_t k0 = detail::load_k0();
    uint64_t k1 = detail::load_k1();

    while (offset < snap.text_size)
    {
        uint32_t this_block = (snap.text_size - offset < BLOCK_SIZE)
            ? (snap.text_size - offset) : BLOCK_SIZE;

        const auto* block_ptr = reinterpret_cast<const uint8_t*>(snap.text_base + offset);

        uint8_t buf[4096 + 8];
        memcpy(buf, block_ptr, this_block);
        memcpy(buf + this_block, &prev_hash, 8);

        uint64_t h = siphash::hash(buf, this_block + 8, k0, k1);

        chain.push_back({snap.text_base + offset, this_block, h});
        prev_hash = h;
        offset += this_block;
    }

    return !chain.empty();
}

inline bool verify_block_chain(const state::code_snapshot_t& snap,
                               const std::vector<state::block_hash_t>& chain,
                               block_chain_verify_result_t* result = nullptr)
{
    if (result) *result = {};
    if (chain.empty()) return true;

    uint64_t k0 = detail::load_k0();
    uint64_t k1 = detail::load_k1();
    uint64_t prev_hash = 0;
    uint32_t index = 0;
    for (const auto& block : chain)
    {
        const bool block_inside_snapshot =
            snap.text_base == 0 || snap.text_size == 0 ||
            (block.block_base >= snap.text_base &&
             block.block_base + block.block_size <= snap.text_base + snap.text_size);
        if (block.block_size > 4096 || !block_inside_snapshot)
        {
            if (result)
            {
                result->block_index = index;
                result->chain_count = static_cast<uint32_t>(chain.size());
                result->block_base = block.block_base;
                result->block_size = block.block_size;
                result->expected_hash = block.chained_hash;
                result->actual_hash = 0;
                result->prev_hash = prev_hash;
                result->checked = true;
                result->layout_mismatch = true;
            }
            return false;
        }
        const auto* block_ptr = reinterpret_cast<const uint8_t*>(block.block_base);

        uint8_t buf[4096 + 8];
        memcpy(buf, block_ptr, block.block_size);
        memcpy(buf + block.block_size, &prev_hash, 8);

        uint64_t h = siphash::hash(buf, block.block_size + 8, k0, k1);

        if (h != block.chained_hash)
        {
            if (result)
            {
                result->block_index = index;
                result->chain_count = static_cast<uint32_t>(chain.size());
                result->block_base = block.block_base;
                result->block_size = block.block_size;
                result->expected_hash = block.chained_hash;
                result->actual_hash = h;
                result->prev_hash = prev_hash;
                result->checked = true;
                result->layout_mismatch = false;
            }
            return false;
        }

        prev_hash = h;
        ++index;
    }
    return true;
}

inline bool verify_self_hash()
{
    std::lock_guard<std::mutex> chain_lk(detail::self_chain_mtx());
    uint64_t expected = detail::s_self_chain_anchor.load(std::memory_order_acquire);
    if (expected == 0) return true;
    uint64_t self_seed = detail::s_self_chain_seed.load(std::memory_order_acquire);
    if (self_seed == 0) return true;
    uint64_t per_call = siphash::siphash_3u64(self_seed, detail::load_k0(), detail::load_k1());
    uint64_t computed = detail::self_hash_chain_compute(per_call);
    if (computed == 0) return true;
    uint8_t mat[16];
    memcpy(mat + 0, &computed, 8);
    memcpy(mat + 8, &per_call, 8);
    uint8_t mac[32] = {};
    uint8_t base_secret[32] = {};
    if (!detail::compute_session_secret(base_secret))
    {
        SecureZeroMemory(base_secret, sizeof(base_secret));
        SecureZeroMemory(mat, sizeof(mat));
        return true;
    }
    if (!sha256::hmac(base_secret, 32, mat, sizeof(mat), mac))
    {
        SecureZeroMemory(base_secret, sizeof(base_secret));
        SecureZeroMemory(mac, sizeof(mac));
        SecureZeroMemory(mat, sizeof(mat));
        return true;
    }
    SecureZeroMemory(base_secret, sizeof(base_secret));
    uint64_t anchor_recomputed = 0;
    memcpy(&anchor_recomputed, mac, 8);
    SecureZeroMemory(mac, sizeof(mac));
    SecureZeroMemory(mat, sizeof(mat));

    return (anchor_recomputed ^ self_seed) == expected;
}

inline bool snapshot_code(state::code_snapshot_t& snap)
{
    const uint64_t enter_tick = GetTickCount64();
    webhook::write_log_critical_fmt("integrity",
        "snapshot_code_enter pid=%lu tid=%lu tick=%llu prior_base=0x%llX prior_size=0x%X prior_hash=0x%016llX",
        GetCurrentProcessId(),
        GetCurrentThreadId(),
        static_cast<unsigned long long>(enter_tick),
        static_cast<unsigned long long>(snap.text_base),
        snap.text_size,
        static_cast<unsigned long long>(snap.text_hash));
    HMODULE mod = GetModuleHandleW(nullptr);
    if (!mod)
    {
        webhook::write_log_critical("integrity", "snapshot_code_failed_no_module");
        return false;
    }

    uint64_t module_base = reinterpret_cast<uint64_t>(mod);
    uint64_t module_end = 0;
    uint32_t module_size = 0;
    MODULEINFO mi{};
    SetLastError(ERROR_SUCCESS);
    webhook::write_log_critical_fmt("integrity",
        "snapshot_code_module_info_pre module_base=0x%llX elapsed_ms=%llu",
        static_cast<unsigned long long>(module_base),
        static_cast<unsigned long long>(GetTickCount64() - enter_tick));
    BOOL module_info_ok = GetModuleInformation(GetCurrentProcess(), mod, &mi, sizeof(mi));
    DWORD module_info_err = module_info_ok ? ERROR_SUCCESS : GetLastError();
    webhook::write_log_critical_fmt("integrity",
        "snapshot_code_module_info_post ok=%d err=%lu size=0x%lX base=0x%llX elapsed_ms=%llu",
        module_info_ok ? 1 : 0,
        static_cast<unsigned long>(module_info_err),
        module_info_ok ? static_cast<unsigned long>(mi.SizeOfImage) : 0ul,
        static_cast<unsigned long long>(reinterpret_cast<uint64_t>(module_info_ok ? mi.lpBaseOfDll : nullptr)),
        static_cast<unsigned long long>(GetTickCount64() - enter_tick));
    if (module_info_ok)
    {
        module_size = mi.SizeOfImage;
        module_end = module_base + mi.SizeOfImage;
    }

    detail::live_pe_layout_t live{};
    webhook::write_log_critical_fmt("integrity",
        "snapshot_code_live_pe_pre module_base=0x%llX module_end=0x%llX elapsed_ms=%llu",
        static_cast<unsigned long long>(module_base),
        static_cast<unsigned long long>(module_end),
        static_cast<unsigned long long>(GetTickCount64() - enter_tick));
    detail::read_live_pe_layout_seh(mod, module_base, live);
    webhook::write_log_critical_fmt("integrity",
        "snapshot_code_live_pe_post parsed=%d reason=%s dos=0x%04X e_lfanew=0x%lX nt=0x%08lX opt=0x%04X sections=%u image=0x%lX text=0x%llX size=0x%X seh=0x%08lX elapsed_ms=%llu",
        live.parsed ? 1 : 0,
        live.fail_reason,
        live.dos_magic,
        static_cast<unsigned long>(live.e_lfanew),
        static_cast<unsigned long>(live.nt_signature),
        live.opt_magic,
        live.section_count,
        static_cast<unsigned long>(live.size_of_image),
        static_cast<unsigned long long>(live.text_base),
        live.text_size,
        static_cast<unsigned long>(live.seh_code),
        static_cast<unsigned long long>(GetTickCount64() - enter_tick));

    if (module_end == 0 && live.size_of_image != 0)
        module_end = module_base + live.size_of_image;

    if (live.parsed)
    {
        return detail::snapshot_code_from_layout(snap,
            module_base,
            module_end,
            live.text_base,
            live.text_size,
            live.section_index,
            live.section_count,
            live.section_characteristics,
            "live_pe",
            nullptr,
            true);
    }

    webhook::write_log_critical_fmt("integrity",
        "snapshot_code_live_pe_failed reason=%s module_base=0x%llX module_size=0x%X module_end=0x%llX dos_magic=0x%04X e_lfanew=0x%lX nt_sig=0x%08lX opt_magic=0x%04X sections=%u sizeof_image=0x%lX seh=0x%08lX prior_base=0x%llX prior_size=0x%X prior_hash=0x%016llX",
        live.fail_reason,
        static_cast<unsigned long long>(module_base),
        module_size,
        static_cast<unsigned long long>(module_end),
        live.dos_magic,
        static_cast<unsigned long>(live.e_lfanew),
        static_cast<unsigned long>(live.nt_signature),
        live.opt_magic,
        live.section_count,
        static_cast<unsigned long>(live.size_of_image),
        static_cast<unsigned long>(live.seh_code),
        static_cast<unsigned long long>(snap.text_base),
        snap.text_size,
        static_cast<unsigned long long>(snap.text_hash));

    if (snap.text_base != 0 && snap.text_size != 0 && snap.text_hash != 0)
    {
        uint8_t current_sha[32] = {};
        MEMORY_BASIC_INFORMATION prior_mbi{};
        SIZE_T prior_vq = VirtualQuery(reinterpret_cast<const void*>(snap.text_base), &prior_mbi, sizeof(prior_mbi));
        uint64_t prior_hash_tick = GetTickCount64();
        webhook::write_log_critical_fmt("integrity",
            "snapshot_code_prior_baseline_hash_pre pid=%lu tid=%lu tick=%llu text_base=0x%llX text_size=0x%X hash=0x%016llX vq=%llu mbi_base=0x%llX alloc_base=0x%llX region=0x%llX state=0x%lX protect=0x%lX type=0x%lX",
            GetCurrentProcessId(),
            GetCurrentThreadId(),
            static_cast<unsigned long long>(prior_hash_tick),
            static_cast<unsigned long long>(snap.text_base),
            snap.text_size,
            static_cast<unsigned long long>(snap.text_hash),
            static_cast<unsigned long long>(prior_vq),
            static_cast<unsigned long long>(reinterpret_cast<uintptr_t>(prior_mbi.BaseAddress)),
            static_cast<unsigned long long>(reinterpret_cast<uintptr_t>(prior_mbi.AllocationBase)),
            static_cast<unsigned long long>(prior_mbi.RegionSize),
            static_cast<unsigned long>(prior_mbi.State),
            static_cast<unsigned long>(prior_mbi.Protect),
            static_cast<unsigned long>(prior_mbi.Type));
        bool prior_hash_ok = sha256::hash(reinterpret_cast<const void*>(snap.text_base), snap.text_size, current_sha);
        bool prior_match = prior_hash_ok && memcmp(current_sha, snap.text_sha256, 32) == 0;
        webhook::write_log_critical_fmt("integrity",
            "snapshot_code_prior_baseline_hash_post hash_ok=%d match=%d elapsed_ms=%llu text_base=0x%llX text_size=0x%X",
            prior_hash_ok ? 1 : 0,
            prior_match ? 1 : 0,
            static_cast<unsigned long long>(GetTickCount64() - prior_hash_tick),
            static_cast<unsigned long long>(snap.text_base),
            snap.text_size);
        if (prior_match)
        {
            webhook::write_log_critical_fmt("integrity",
                "snapshot_code_prior_baseline_reuse module_base=0x%llX text_base=0x%llX text_size=0x%X hash=0x%016llX",
                static_cast<unsigned long long>(snap.module_base),
                static_cast<unsigned long long>(snap.text_base),
                snap.text_size,
                static_cast<unsigned long long>(snap.text_hash));
            bool rebuilt = false;
            uint64_t rebuild_tick = GetTickCount64();
            webhook::write_log_critical_fmt("integrity",
                "snapshot_code_prior_baseline_rebuild_enter pid=%lu tid=%lu tick=%llu text_base=0x%llX text_size=0x%X",
                GetCurrentProcessId(),
                GetCurrentThreadId(),
                static_cast<unsigned long long>(rebuild_tick),
                static_cast<unsigned long long>(snap.text_base),
                snap.text_size);
            {
                auto& pt = detail::page_table();
                std::lock_guard<std::mutex> lk(pt.mtx);
                rebuilt = detail::rebuild_page_table_locked(pt, snap.text_base, snap.text_size);
            }
            webhook::write_log_critical_fmt("integrity",
                "snapshot_code_prior_baseline_rebuild_exit rebuilt=%d elapsed_ms=%llu text_base=0x%llX text_size=0x%X",
                rebuilt ? 1 : 0,
                static_cast<unsigned long long>(GetTickCount64() - rebuild_tick),
                static_cast<unsigned long long>(snap.text_base),
                snap.text_size);
            if (rebuilt)
            {
                webhook::write_log_critical("integrity", "snapshot_code_prior_baseline_reuse_return_true");
                return true;
            }
            webhook::write_log_critical("integrity", "snapshot_code_prior_baseline_page_table_rebuild_failed");
        }
        else
        {
            webhook::write_log_critical_fmt("integrity",
                "snapshot_code_prior_baseline_sha_failed_or_mismatch hash_ok=%d match=%d text_base=0x%llX text_size=0x%X",
                prior_hash_ok ? 1 : 0,
                prior_match ? 1 : 0,
                static_cast<unsigned long long>(snap.text_base),
                snap.text_size);
        }
    }

    detail::cached_code_layout_t cache{};
    if (!detail::load_code_layout_cache(module_base, cache))
    {
        webhook::write_log_critical_fmt("integrity",
            "snapshot_code_cached_layout_unavailable module_base=0x%llX",
            static_cast<unsigned long long>(module_base));
        return false;
    }

    webhook::write_log_critical_fmt("integrity",
        "snapshot_code_cached_layout_attempt module_base=0x%llX module_end=0x%llX text_base=0x%llX text_size=0x%X section=%u/%u chars=0x%X",
        static_cast<unsigned long long>(cache.module_base),
        static_cast<unsigned long long>(cache.module_end),
        static_cast<unsigned long long>(cache.text_base),
        cache.text_size,
        cache.section_index,
        cache.section_count,
        cache.section_characteristics);
    return detail::snapshot_code_from_layout(snap,
        cache.module_base,
        cache.module_end,
        cache.text_base,
        cache.text_size,
        cache.section_index,
        cache.section_count,
        cache.section_characteristics,
        "cached_layout",
        cache.text_sha256,
        false);
}

inline bool verify_usermode(const state::code_snapshot_t& snap)
{
    if (snap.text_base == 0 || snap.text_size == 0 || snap.text_hash == 0)
        return true;

    if (!verify_self_hash())
        return false;

    uint64_t current = hash_memory(
        reinterpret_cast<const void*>(snap.text_base), snap.text_size);
    if (current != snap.text_hash)
        return false;

    uint8_t current_sha[32];
    sha256::hash(reinterpret_cast<const void*>(snap.text_base),
                 snap.text_size, current_sha);
    if (memcmp(current_sha, snap.text_sha256, 32) != 0)
        return false;

    return true;
}

inline void snapshot_iat(std::vector<state::iat_entry_t>& snap)
{
    const uint64_t started = GetTickCount64();
    webhook::write_log_critical_fmt("integrity",
        "snapshot_iat_enter pid=%lu tid=%lu tick=%llu prior_entries=%zu",
        GetCurrentProcessId(),
        GetCurrentThreadId(),
        static_cast<unsigned long long>(started),
        snap.size());
    snap.clear();

    HMODULE mod = GetModuleHandleW(nullptr);
    if (!mod) {
        webhook::write_log_critical_fmt("integrity",
            "snapshot_iat_exit reason=no_module err=%lu elapsed_ms=%llu",
            static_cast<unsigned long>(GetLastError()),
            static_cast<unsigned long long>(GetTickCount64() - started));
        return;
    }

    const auto* base = reinterpret_cast<const uint8_t*>(mod);
    const auto* dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(base);
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) {
        webhook::write_log_critical_fmt("integrity",
            "snapshot_iat_exit reason=bad_dos module=0x%llX dos=0x%04X elapsed_ms=%llu",
            static_cast<unsigned long long>(reinterpret_cast<uintptr_t>(mod)),
            dos->e_magic,
            static_cast<unsigned long long>(GetTickCount64() - started));
        return;
    }

    const auto* nt = reinterpret_cast<const IMAGE_NT_HEADERS64*>(base + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) {
        webhook::write_log_critical_fmt("integrity",
            "snapshot_iat_exit reason=bad_nt module=0x%llX e_lfanew=0x%lX sig=0x%08lX elapsed_ms=%llu",
            static_cast<unsigned long long>(reinterpret_cast<uintptr_t>(mod)),
            static_cast<unsigned long>(dos->e_lfanew),
            static_cast<unsigned long>(nt->Signature),
            static_cast<unsigned long long>(GetTickCount64() - started));
        return;
    }

    const auto& imp_dir = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
    if (imp_dir.VirtualAddress == 0 || imp_dir.Size == 0) {
        webhook::write_log_critical_fmt("integrity",
            "snapshot_iat_exit reason=no_import_dir module=0x%llX import_rva=0x%lX import_size=0x%lX elapsed_ms=%llu",
            static_cast<unsigned long long>(reinterpret_cast<uintptr_t>(mod)),
            static_cast<unsigned long>(imp_dir.VirtualAddress),
            static_cast<unsigned long>(imp_dir.Size),
            static_cast<unsigned long long>(GetTickCount64() - started));
        return;
    }

    auto* imp = reinterpret_cast<const IMAGE_IMPORT_DESCRIPTOR*>(
        base + imp_dir.VirtualAddress);

    uint32_t descriptor_count = 0;
    for (; imp->Name != 0; ++imp)
    {
        ++descriptor_count;
        auto* thunk = reinterpret_cast<const IMAGE_THUNK_DATA64*>(
            base + imp->FirstThunk);

        for (; thunk->u1.Function != 0; ++thunk)
        {
            snap.push_back({
                reinterpret_cast<uint64_t>(&thunk->u1.Function),
                thunk->u1.Function
            });
        }
    }
    webhook::write_log_critical_fmt("integrity",
        "snapshot_iat_exit reason=ok module=0x%llX descriptors=%u entries=%zu import_rva=0x%lX import_size=0x%lX elapsed_ms=%llu",
        static_cast<unsigned long long>(reinterpret_cast<uintptr_t>(mod)),
        descriptor_count,
        snap.size(),
        static_cast<unsigned long>(imp_dir.VirtualAddress),
        static_cast<unsigned long>(imp_dir.Size),
        static_cast<unsigned long long>(GetTickCount64() - started));
}

inline bool verify_iat(const std::vector<state::iat_entry_t>& snap)
{
    for (const auto& e : snap)
    {
        const auto cur = *reinterpret_cast<const volatile uint64_t*>(e.slot_va);
        if (cur != e.resolved_va)
            return false;
    }
    return true;
}

inline bool verify_page_protections(const state::code_snapshot_t& snap)
{
    if (snap.text_base == 0 || snap.text_size == 0)
    {
        webhook::write_log_critical_fmt("integrity",
            "verify_page_protections_exit reason=empty_snapshot base=0x%llX size=0x%X",
            static_cast<unsigned long long>(snap.text_base),
            snap.text_size);
        return true;
    }

    const uint64_t started = GetTickCount64();
    webhook::write_log_critical_fmt("integrity",
        "verify_page_protections_enter pid=%lu tid=%lu tick=%llu base=0x%llX size=0x%X",
        GetCurrentProcessId(),
        GetCurrentThreadId(),
        static_cast<unsigned long long>(started),
        static_cast<unsigned long long>(snap.text_base),
        snap.text_size);
    MEMORY_BASIC_INFORMATION mbi{};
    uint64_t addr = snap.text_base;
    const uint64_t end = snap.text_base + snap.text_size;
    uint32_t region_count = 0;

    while (addr < end)
    {
        SIZE_T vq = VirtualQuery(reinterpret_cast<LPCVOID>(addr), &mbi, sizeof(mbi));
        if (vq == 0)
        {
            webhook::write_log_critical_fmt("integrity",
                "verify_page_protections_exit reason=vq_failed addr=0x%llX err=%lu regions=%u elapsed_ms=%llu",
                static_cast<unsigned long long>(addr),
                static_cast<unsigned long>(GetLastError()),
                region_count,
                static_cast<unsigned long long>(GetTickCount64() - started));
            return false;
        }

        webhook::write_log_critical_fmt("integrity",
            "verify_page_protections_region idx=%u addr=0x%llX vq=%llu base=0x%llX alloc=0x%llX region=0x%llX state=0x%lX protect=0x%lX type=0x%lX elapsed_ms=%llu",
            region_count,
            static_cast<unsigned long long>(addr),
            static_cast<unsigned long long>(vq),
            static_cast<unsigned long long>(reinterpret_cast<uintptr_t>(mbi.BaseAddress)),
            static_cast<unsigned long long>(reinterpret_cast<uintptr_t>(mbi.AllocationBase)),
            static_cast<unsigned long long>(mbi.RegionSize),
            static_cast<unsigned long>(mbi.State),
            static_cast<unsigned long>(mbi.Protect),
            static_cast<unsigned long>(mbi.Type),
            static_cast<unsigned long long>(GetTickCount64() - started));

        if (mbi.Protect & (PAGE_READWRITE | PAGE_EXECUTE_READWRITE |
                           PAGE_WRITECOPY | PAGE_EXECUTE_WRITECOPY))
        {
            webhook::write_log_critical_fmt("integrity",
                "verify_page_protections_exit reason=writable_region idx=%u base=0x%llX region=0x%llX protect=0x%lX elapsed_ms=%llu",
                region_count,
                static_cast<unsigned long long>(reinterpret_cast<uintptr_t>(mbi.BaseAddress)),
                static_cast<unsigned long long>(mbi.RegionSize),
                static_cast<unsigned long>(mbi.Protect),
                static_cast<unsigned long long>(GetTickCount64() - started));
            return false;
        }

        addr = reinterpret_cast<uint64_t>(mbi.BaseAddress) + mbi.RegionSize;
        ++region_count;
    }
    webhook::write_log_critical_fmt("integrity",
        "verify_page_protections_exit reason=ok regions=%u elapsed_ms=%llu",
        region_count,
        static_cast<unsigned long long>(GetTickCount64() - started));
    return true;
}

inline void derive_session_keys_for_caller(uint64_t& k0, uint64_t& k1)
{
    if (!detail::s_keys_initialized.load(std::memory_order_acquire))
    {
        k0 = 0;
        k1 = 0;
        return;
    }
    uint64_t per_call = detail::derive_per_call_key();
    uint64_t base0 = detail::load_k0();
    uint64_t base1 = detail::load_k1();
    k0 = siphash::siphash_3u64(base0, per_call, base1);
    k1 = siphash::siphash_3u64(base1, per_call ^ 0x9E3779B97F4A7C15ULL, base0);
}

__forceinline void get_session_keys(uint64_t& k0, uint64_t& k1)
{
    derive_session_keys_for_caller(k0, k1);
}

inline bool verify_page_lazy(uintptr_t fault_addr)
{
    auto& pt = detail::page_table();
    std::lock_guard<std::mutex> lk(pt.mtx);
    if (pt.entries.empty()) return true;
    if (fault_addr < pt.base) return true;
    uint64_t off = fault_addr - pt.base;
    if (off >= pt.size) return true;
    uint32_t page_index = static_cast<uint32_t>(off / detail::kPageSize);
    bool ok = detail::verify_page_locked(pt, page_index);
    if (!ok) detail::periodic_violation_flag().store(true, std::memory_order_release);
    return ok;
}

inline bool verify_page_eager(uint32_t page_index)
{
    auto& pt = detail::page_table();
    std::lock_guard<std::mutex> lk(pt.mtx);
    return detail::verify_page_locked(pt, page_index);
}

inline bool is_page_expected_to_be_corrupted_u32(uint32_t page_index);

inline bool verify_full_text_eager(uint32_t* mismatched_page_out = nullptr)
{
    auto& pt = detail::page_table();
    std::lock_guard<std::mutex> lk(pt.mtx);
    for (uint32_t i = 0; i < pt.entries.size(); ++i)
    {
        if (is_page_expected_to_be_corrupted_u32(i))
            continue;
        if (!detail::verify_page_locked(pt, i))
        {
            if (mismatched_page_out) *mismatched_page_out = i;
            detail::periodic_violation_flag().store(true, std::memory_order_release);
            return false;
        }
    }
    return true;
}

inline uint64_t get_text_chain_anchor()
{
    return detail::s_text_chain_anchor.load(std::memory_order_acquire);
}

inline uint64_t get_periodic_pass_count()
{
    return detail::periodic_pass_counter().load(std::memory_order_acquire);
}

inline bool periodic_violation_latched()
{
    return detail::periodic_violation_flag().load(std::memory_order_acquire);
}

inline void clear_periodic_violation_flag()
{
    detail::periodic_violation_flag().store(false, std::memory_order_release);
}

namespace expected_corruption {

    constexpr uint32_t kMaskBitCount = 8192;
    constexpr uint32_t kMaskWordCount = kMaskBitCount / 64;

    inline std::atomic<uint64_t>* mask_array()
    {
        static std::atomic<uint64_t> arr[kMaskWordCount]{};
        return arr;
    }

    inline std::atomic<uint32_t>& active_count()
    {
        static std::atomic<uint32_t> v{0};
        return v;
    }

}

inline bool is_page_expected_to_be_corrupted(uint8_t page_index)
{
    if (expected_corruption::active_count().load(std::memory_order_acquire) == 0)
        return false;
    uint32_t idx = static_cast<uint32_t>(page_index);
    uint32_t word = idx / 64u;
    uint32_t bit = idx % 64u;
    if (word >= expected_corruption::kMaskWordCount) return false;
    uint64_t w = expected_corruption::mask_array()[word].load(std::memory_order_acquire);
    return (w & (1ULL << bit)) != 0;
}

inline bool is_page_expected_to_be_corrupted_u32(uint32_t page_index)
{
    if (expected_corruption::active_count().load(std::memory_order_acquire) == 0)
        return false;
    uint32_t word = page_index / 64u;
    uint32_t bit = page_index % 64u;
    if (word >= expected_corruption::kMaskWordCount) return false;
    uint64_t w = expected_corruption::mask_array()[word].load(std::memory_order_acquire);
    return (w & (1ULL << bit)) != 0;
}

inline void set_expected_corruption_mask(const uint8_t* page_indices, size_t count)
{
    if (!page_indices || count == 0) return;
    uint32_t added = 0;
    for (size_t i = 0; i < count; ++i)
    {
        uint32_t idx = static_cast<uint32_t>(page_indices[i]);
        uint32_t word = idx / 64u;
        uint32_t bit = idx % 64u;
        if (word >= expected_corruption::kMaskWordCount) continue;
        auto& w = expected_corruption::mask_array()[word];
        uint64_t prev = w.fetch_or(1ULL << bit, std::memory_order_acq_rel);
        if ((prev & (1ULL << bit)) == 0)
            ++added;
    }
    if (added > 0)
        expected_corruption::active_count().fetch_add(added, std::memory_order_acq_rel);
}

inline void clear_expected_corruption_mask(const uint8_t* page_indices, size_t count)
{
    if (!page_indices || count == 0) return;
    uint32_t removed = 0;
    for (size_t i = 0; i < count; ++i)
    {
        uint32_t idx = static_cast<uint32_t>(page_indices[i]);
        uint32_t word = idx / 64u;
        uint32_t bit = idx % 64u;
        if (word >= expected_corruption::kMaskWordCount) continue;
        auto& w = expected_corruption::mask_array()[word];
        uint64_t prev = w.fetch_and(~(1ULL << bit), std::memory_order_acq_rel);
        if ((prev & (1ULL << bit)) != 0)
            ++removed;
    }
    if (removed > 0)
    {
        uint32_t cur = expected_corruption::active_count().load(std::memory_order_acquire);
        uint32_t next = (removed >= cur) ? 0u : (cur - removed);
        expected_corruption::active_count().store(next, std::memory_order_release);
    }
}

inline void rebuild_self_chain_anchor_locked()
{
    uint64_t seed_value = detail::s_self_chain_seed.load(std::memory_order_acquire);
    if (seed_value == 0) return;
    uint64_t per_call = siphash::siphash_3u64(seed_value, detail::load_k0(), detail::load_k1());
    uint64_t chain = detail::self_hash_chain_compute(per_call);
    if (chain == 0)
    {
        detail::s_self_chain_anchor.store(0, std::memory_order_release);
        return;
    }
    uint8_t mat[16];
    memcpy(mat + 0, &chain, 8);
    memcpy(mat + 8, &per_call, 8);
    uint8_t mac[32] = {};
    uint8_t base_secret[32] = {};
    bool secret_ok = detail::compute_session_secret(base_secret);
    bool hmac_ok = secret_ok && sha256::hmac(base_secret, 32, mat, sizeof(mat), mac);
    SecureZeroMemory(base_secret, sizeof(base_secret));
    if (!hmac_ok)
    {
        SecureZeroMemory(mac, sizeof(mac));
        SecureZeroMemory(mat, sizeof(mat));
        detail::s_self_chain_anchor.store(0, std::memory_order_release);
        return;
    }
    uint64_t anchor = 0;
    memcpy(&anchor, mac, 8);
    SecureZeroMemory(mac, sizeof(mac));
    SecureZeroMemory(mat, sizeof(mat));
    detail::s_self_chain_anchor.store(anchor ^ seed_value, std::memory_order_release);
}

inline void rebuild_self_chain_anchor()
{
    std::lock_guard<std::mutex> chain_lk(detail::self_chain_mtx());
    rebuild_self_chain_anchor_locked();
}

inline LONG NTAPI page_mac_veh_handler(EXCEPTION_POINTERS* ep)
{
    if (!ep || !ep->ExceptionRecord) return EXCEPTION_CONTINUE_SEARCH;
    DWORD code = ep->ExceptionRecord->ExceptionCode;
    if (code != STATUS_GUARD_PAGE_VIOLATION) return EXCEPTION_CONTINUE_SEARCH;
    if (ep->ExceptionRecord->NumberParameters < 2) return EXCEPTION_CONTINUE_SEARCH;
    uintptr_t fault_addr = static_cast<uintptr_t>(ep->ExceptionRecord->ExceptionInformation[1]);
    auto& pt = detail::page_table();
    if (pt.base == 0 || pt.size == 0) return EXCEPTION_CONTINUE_SEARCH;
    if (fault_addr < pt.base || fault_addr >= pt.base + pt.size)
        return EXCEPTION_CONTINUE_SEARCH;
    verify_page_lazy(fault_addr);
    return EXCEPTION_CONTINUE_SEARCH;
}

inline void install_page_mac_veh()
{
    static std::atomic<bool> s_installed{false};
    bool expected = false;
    if (!s_installed.compare_exchange_strong(expected, true)) return;
    AddVectoredExceptionHandler(0, page_mac_veh_handler);
}

namespace periodic {
    inline void invalidate_all_slots();
}

inline void rotate_page_keys_if_due()
{
    auto& pt = detail::page_table();
    uint64_t now = detail::qpc_now_ms();
    uint64_t last = pt.last_rotation_qpc.load(std::memory_order_acquire);
    if (now - last < static_cast<uint64_t>(detail::kKeyRotationSec) * 1000ULL) return;
    std::lock_guard<std::mutex> chain_lk(detail::self_chain_mtx());
    std::lock_guard<std::mutex> lk(pt.mtx);
    if (pt.last_rotation_qpc.load(std::memory_order_acquire) != last) return;
    detail::rotate_session_secret();
    detail::rotate_page_keys_locked(pt);
    rebuild_self_chain_anchor_locked();
    periodic::invalidate_all_slots();
}

namespace periodic {

    constexpr uint32_t kCadenceMs = 5000;
    constexpr uint32_t kWorkerCount = 3;

    inline std::atomic<bool>& stop_flag()
    {
        static std::atomic<bool> v{false};
        return v;
    }

    inline std::atomic<uint64_t>& run_generation()
    {
        static std::atomic<uint64_t> v{0};
        return v;
    }

    inline std::atomic<uint64_t>* signature_array()
    {
        static std::atomic<uint64_t> v[kWorkerCount];
        return v;
    }

    inline std::atomic<uint64_t>* qpc_array()
    {
        static std::atomic<uint64_t> v[kWorkerCount];
        return v;
    }

    inline std::atomic<uint64_t>* epoch_array()
    {
        static std::atomic<uint64_t> v[kWorkerCount];
        return v;
    }

    inline std::atomic<uint64_t>& last_quorum_skip_log_ms()
    {
        static std::atomic<uint64_t> v{0};
        return v;
    }

    inline void invalidate_all_slots()
    {
        for (uint32_t w = 0; w < kWorkerCount; ++w)
        {
            qpc_array()[w].store(0, std::memory_order_release);
            signature_array()[w].store(0, std::memory_order_release);
            epoch_array()[w].store(0, std::memory_order_release);
        }
    }

    __forceinline uint64_t compute_text_signature_unlocked(uint64_t epoch,
                                                            uint64_t base,
                                                            uint32_t size,
                                                            uint32_t page_count)
    {
        uint64_t signature = epoch;
        signature ^= size;
        uint64_t k0 = detail::load_k0();
        uint64_t k1 = detail::load_k1();
        for (uint32_t i = 0; i < page_count; ++i)
        {
            uint32_t this_size = detail::kPageSize;
            uint32_t offset = i * detail::kPageSize;
            if (offset + this_size > size) this_size = size - offset;
            const uint8_t* page = reinterpret_cast<const uint8_t*>(base + offset);
            uint64_t live = siphash::hash(page, this_size,
                k0 ^ static_cast<uint64_t>(i), k1 ^ static_cast<uint64_t>(i + 1));
            signature ^= live;
            signature = (signature * 0x9E3779B97F4A7C15ULL) ^ (signature >> 27);
        }
        return signature;
    }

    inline void worker_loop(int worker_id, uint64_t generation)
    {
        Sleep(50 * worker_id);
        while (!stop_flag().load(std::memory_order_acquire)
            && run_generation().load(std::memory_order_acquire) == generation)
        {
            uint64_t start_ms = detail::qpc_now_ms();
            auto& pt = detail::page_table();
            uint64_t sig = 0;
            uint64_t snap_epoch = 0;
            uint64_t snap_base = 0;
            uint32_t snap_size = 0;
            uint32_t snap_page_count = 0;
            bool have_snapshot = false;
            {
                std::lock_guard<std::mutex> lk(pt.mtx);
                if (pt.entries.empty())
                {
                    Sleep(kCadenceMs);
                    continue;
                }
                snap_epoch = pt.key_epoch.load();
                snap_base = pt.base;
                snap_size = pt.size;
                snap_page_count = static_cast<uint32_t>(pt.entries.size());
                have_snapshot = true;
            }

            if (!have_snapshot)
            {
                Sleep(kCadenceMs);
                continue;
            }

            sig = compute_text_signature_unlocked(snap_epoch, snap_base, snap_size, snap_page_count);

            bool epoch_stable = false;
            {
                std::lock_guard<std::mutex> lk(pt.mtx);
                uint64_t cur_epoch = pt.key_epoch.load();
                epoch_stable = (cur_epoch == snap_epoch &&
                                pt.size == snap_size &&
                                pt.base == snap_base &&
                                pt.entries.size() == snap_page_count);
            }

            if (!epoch_stable)
            {
                Sleep(kCadenceMs);
                continue;
            }

            signature_array()[worker_id].store(sig, std::memory_order_release);
            epoch_array()[worker_id].store(snap_epoch, std::memory_order_release);
            qpc_array()[worker_id].store(start_ms, std::memory_order_release);
            detail::periodic_pass_counter().fetch_add(1, std::memory_order_acq_rel);

            if (worker_id == 0)
            {
                bool all_ready = true;
                bool same_epoch = true;
                uint64_t ref_sig = signature_array()[0].load(std::memory_order_acquire);
                uint64_t ref_epoch = epoch_array()[0].load(std::memory_order_acquire);
                for (uint32_t w = 0; w < kWorkerCount; ++w)
                {
                    uint64_t qw = qpc_array()[w].load(std::memory_order_acquire);
                    if (qw == 0)
                    {
                        all_ready = false;
                        break;
                    }
                    uint64_t ew = epoch_array()[w].load(std::memory_order_acquire);
                    if (ew != ref_epoch)
                    {
                        same_epoch = false;
                        break;
                    }
                }
                if (all_ready && same_epoch)
                {
                    bool quorum = true;
                    for (uint32_t w = 1; w < kWorkerCount; ++w)
                    {
                        uint64_t sw = signature_array()[w].load(std::memory_order_acquire);
                        if (sw != ref_sig)
                        {
                            quorum = false;
                            break;
                        }
                    }
                    bool corruption_active = expected_corruption::active_count().load(std::memory_order_acquire) != 0;
                    if (!quorum && corruption_active)
                    {
                        webhook::write_log_critical("page_mac",
                            "worker_quorum_skip_due_to_expected_corruption");
                        quorum = true;
                    }
                    if (!quorum)
                    {
                        uint64_t s1 = signature_array()[1].load(std::memory_order_acquire);
                        uint64_t s2 = (kWorkerCount > 2) ? signature_array()[2].load(std::memory_order_acquire) : 0;
                        webhook::write_log_critical_fmt("page_mac",
                            "worker_quorum_mismatch epoch=%llu sig0=0x%016llX sig1=0x%016llX sig2=0x%016llX",
                            static_cast<unsigned long long>(ref_epoch),
                            static_cast<unsigned long long>(ref_sig),
                            static_cast<unsigned long long>(s1),
                            static_cast<unsigned long long>(s2));
                        detail::periodic_violation_flag().store(true, std::memory_order_release);
                    }
                }
                else if (all_ready && !same_epoch)
                {
                    uint64_t now_ms = detail::qpc_now_ms();
                    uint64_t last_log = last_quorum_skip_log_ms().load(std::memory_order_acquire);
                    if (now_ms - last_log >= 5000)
                    {
                        last_quorum_skip_log_ms().store(now_ms, std::memory_order_release);
                        uint64_t e1 = epoch_array()[1].load(std::memory_order_acquire);
                        uint64_t e2 = (kWorkerCount > 2) ? epoch_array()[2].load(std::memory_order_acquire) : 0;
                        webhook::write_log_critical_fmt("page_mac",
                            "worker_quorum_skip_epoch_mismatch e0=%llu e1=%llu e2=%llu",
                            static_cast<unsigned long long>(ref_epoch),
                            static_cast<unsigned long long>(e1),
                            static_cast<unsigned long long>(e2));
                    }
                }
                rotate_page_keys_if_due();
            }

            uint64_t elapsed = detail::qpc_now_ms() - start_ms;
            if (elapsed < kCadenceMs)
            {
                Sleep(static_cast<DWORD>(kCadenceMs - elapsed));
            }
        }
    }

    inline bool start()
    {
        auto& running = detail::periodic_running_flag();
        bool expected = false;
        if (!running.compare_exchange_strong(expected, true))
        {
            webhook::write_log_critical("page_mac", "periodic_start_already_running");
            return true;
        }
        stop_flag().store(false, std::memory_order_release);
        uint64_t generation = run_generation().fetch_add(1, std::memory_order_acq_rel) + 1;
        uint32_t posted = 0;
        for (int i = 0; i < static_cast<int>(kWorkerCount); ++i)
        {
            try
            {
                aida::infra::executor::submission_t sub;
                sub.owner_subsystem = "anti_tamper_integrity";
                sub.label = "page_mac.periodic_worker";
                sub.thread_class = "security_loop";
                sub.domain = aida::infra::executor::domain_t::security_liveness;
                sub.priority = 0;
                sub.generation = generation;
                sub.body = [i, generation]() {
                    worker_loop(i, generation);
                };
                bool ok = aida::infra::executor::submit(std::move(sub)).submitted;
                if (!ok)
                {
                    webhook::write_log_critical_fmt("page_mac",
                        "periodic_worker_post_failed worker=%d posted=%u",
                        i,
                        posted);
                    continue;
                }
                ++posted;
                webhook::write_log_critical_fmt("page_mac",
                    "periodic_worker_post_ok worker=%d posted=%u generation=%llu",
                    i,
                    posted,
                    static_cast<unsigned long long>(generation));
            }
            catch (const std::exception& ex)
            {
                webhook::write_log_critical_fmt("page_mac",
                    "periodic_worker_post_exception worker=%d what=%.160s",
                    i,
                    ex.what());
            }
            catch (...)
            {
                webhook::write_log_critical_fmt("page_mac",
                    "periodic_worker_post_unknown_exception worker=%d",
                    i);
            }
        }
        if (posted != kWorkerCount)
        {
            stop_flag().store(true, std::memory_order_release);
            run_generation().fetch_add(1, std::memory_order_acq_rel);
            running.store(false, std::memory_order_release);
            webhook::write_log_critical_fmt("page_mac",
                "periodic_start_failed posted=%u expected=%u generation=%llu",
                posted,
                kWorkerCount,
                static_cast<unsigned long long>(generation));
            return false;
        }
        install_page_mac_veh();
        webhook::write_log_critical_fmt("page_mac",
            "periodic_start_ok workers=%u generation=%llu",
            posted,
            static_cast<unsigned long long>(generation));
        return true;
    }

    inline void stop()
    {
        stop_flag().store(true, std::memory_order_release);
        run_generation().fetch_add(1, std::memory_order_acq_rel);
        invalidate_all_slots();
        detail::periodic_running_flag().store(false, std::memory_order_release);
    }

}

}
}
