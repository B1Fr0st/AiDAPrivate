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
#include <mutex>
#include <thread>
#include <vector>

#include "state.hpp"
#include "key_pipeline.hpp"
#include "tpm_attest.hpp"

#pragma comment(lib, "bcrypt.lib")

namespace anti_tamper {
namespace integrity {

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

    inline void compute_session_secret(uint8_t out[32])
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
        sha256::hash(mat, sizeof(mat), out);
        SecureZeroMemory(mat, sizeof(mat));
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
        pt.base = base;
        pt.size = size;
        uint32_t pages = (size + kPageSize - 1) / kPageSize;
        pt.entries.assign(pages, page_mac_t{});
        uint64_t epoch = pt.key_epoch.load();

        uint8_t base_secret[32];
        compute_session_secret(base_secret);
        uint8_t key[16];
        derive_page_key(base_secret, epoch, key);
        SecureZeroMemory(base_secret, sizeof(base_secret));

        for (uint32_t i = 0; i < pages; ++i)
        {
            uint32_t this_size = kPageSize;
            uint32_t offset = i * kPageSize;
            if (offset + this_size > size) this_size = size - offset;
            const uint8_t* page = reinterpret_cast<const uint8_t*>(base + offset);
            uint8_t tag[16];
            if (!compute_page_full_tag(pt, i, page, this_size, key, tag))
            {
                SecureZeroMemory(key, sizeof(key));
                return false;
            }
            memcpy(pt.entries[i].full_tag, tag, 16);
            memcpy(pt.entries[i].tag, tag, 8);
            pt.entries[i].seq = i;
        }
        SecureZeroMemory(key, sizeof(key));

        uint64_t anchor = 0;
        uint8_t accum[32];
        compute_session_secret(accum);
        for (uint32_t i = 0; i < pages; ++i)
        {
            uint8_t buf[16 + 16];
            memcpy(buf, pt.entries[i].full_tag, 16);
            memcpy(buf + 16, accum, 16);
            uint8_t mac[32];
            sha256::hmac(accum, 32, buf, sizeof(buf), mac);
            memcpy(accum, mac, 32);
            anchor ^= reinterpret_cast<const uint64_t*>(mac)[0];
            SecureZeroMemory(buf, sizeof(buf));
        }
        s_text_chain_anchor.store(anchor, std::memory_order_release);
        SecureZeroMemory(accum, sizeof(accum));

        pt.last_rotation_qpc.store(qpc_now_ms(), std::memory_order_release);
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
        SecureZeroMemory(base_secret, sizeof(base_secret));

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
                SecureZeroMemory(new_key, sizeof(new_key));
                return false;
            }
            memcpy(pt.entries[i].full_tag, tag, 16);
            memcpy(pt.entries[i].tag, tag, 8);
        }
        SecureZeroMemory(new_key, sizeof(new_key));
        pt.last_rotation_qpc.store(qpc_now_ms(), std::memory_order_release);
        return true;
    }

    inline bool verify_page_locked(page_table_t& pt, uint32_t page_index)
    {
        if (page_index >= pt.entries.size()) return false;
        uint32_t this_size = kPageSize;
        uint32_t offset = page_index * kPageSize;
        if (offset + this_size > pt.size) this_size = pt.size - offset;
        const uint8_t* page = reinterpret_cast<const uint8_t*>(pt.base + offset);

        uint8_t base_secret[32];
        compute_session_secret(base_secret);
        uint8_t key[16];
        derive_page_key(base_secret, pt.key_epoch.load(), key);
        SecureZeroMemory(base_secret, sizeof(base_secret));

        uint8_t tag[16];
        if (!compute_page_full_tag(pt, page_index, page, this_size, key, tag))
        {
            SecureZeroMemory(key, sizeof(key));
            return false;
        }
        SecureZeroMemory(key, sizeof(key));
        bool ok = (memcmp(tag, pt.entries[page_index].full_tag, 16) == 0);
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
                               const std::vector<state::block_hash_t>& chain)
{
    if (chain.empty()) return true;

    uint64_t k0 = detail::load_k0();
    uint64_t k1 = detail::load_k1();
    uint64_t prev_hash = 0;
    for (const auto& block : chain)
    {
        const auto* block_ptr = reinterpret_cast<const uint8_t*>(block.block_base);

        uint8_t buf[4096 + 8];
        memcpy(buf, block_ptr, block.block_size);
        memcpy(buf + block.block_size, &prev_hash, 8);

        uint64_t h = siphash::hash(buf, block.block_size + 8, k0, k1);

        if (h != block.chained_hash)
            return false;

        prev_hash = h;
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
    uint8_t mat[16];
    memcpy(mat + 0, &computed, 8);
    memcpy(mat + 8, &per_call, 8);
    uint8_t mac[32] = {};
    uint8_t base_secret[32];
    detail::compute_session_secret(base_secret);
    sha256::hmac(base_secret, 32, mat, sizeof(mat), mac);
    SecureZeroMemory(base_secret, sizeof(base_secret));
    uint64_t anchor_recomputed = 0;
    memcpy(&anchor_recomputed, mac, 8);
    SecureZeroMemory(mac, sizeof(mac));
    SecureZeroMemory(mat, sizeof(mat));

    return (anchor_recomputed ^ self_seed) == expected;
}

inline bool snapshot_code(state::code_snapshot_t& snap)
{
    HMODULE mod = GetModuleHandleW(nullptr);
    if (!mod) return false;

    const auto* dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(mod);
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return false;

    const auto* nt = reinterpret_cast<const IMAGE_NT_HEADERS64*>(
        reinterpret_cast<const uint8_t*>(mod) + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) return false;

    const auto* sec = IMAGE_FIRST_SECTION(nt);
    for (WORD i = 0; i < nt->FileHeader.NumberOfSections; ++i)
    {
        if ((sec[i].Characteristics & IMAGE_SCN_CNT_CODE) != 0
            && sec[i].Misc.VirtualSize > 0)
        {
            snap.text_base = reinterpret_cast<uint64_t>(mod) + sec[i].VirtualAddress;
            snap.text_size = sec[i].Misc.VirtualSize;
            break;
        }
    }

    MODULEINFO mi{};
    if (GetModuleInformation(GetCurrentProcess(), mod, &mi, sizeof(mi)))
    {
        snap.module_base = reinterpret_cast<uint64_t>(mod);
        snap.module_end = snap.module_base + mi.SizeOfImage;
    }

    if (snap.text_base == 0 || snap.text_size == 0) return false;

    detail::derive_session_keys(
        reinterpret_cast<const uint8_t*>(snap.text_base), snap.text_size);

    snap.text_hash = hash_memory(
        reinterpret_cast<const void*>(snap.text_base), snap.text_size);

    sha256::hash(reinterpret_cast<const void*>(snap.text_base),
                 snap.text_size, snap.text_sha256);

    uint64_t seed_value = detail::fresh_entropy();
    if (seed_value == 0) seed_value = 0xA1DAA0E2DEADBEEFULL;
    detail::s_self_chain_seed.store(seed_value, std::memory_order_release);
    uint64_t per_call = siphash::siphash_3u64(seed_value, detail::load_k0(), detail::load_k1());
    uint64_t chain = detail::self_hash_chain_compute(per_call);
    uint8_t mat[16];
    memcpy(mat + 0, &chain, 8);
    memcpy(mat + 8, &per_call, 8);
    uint8_t mac[32] = {};
    uint8_t base_secret[32];
    detail::compute_session_secret(base_secret);
    sha256::hmac(base_secret, 32, mat, sizeof(mat), mac);
    SecureZeroMemory(base_secret, sizeof(base_secret));
    uint64_t anchor = 0;
    memcpy(&anchor, mac, 8);
    SecureZeroMemory(mac, sizeof(mac));
    SecureZeroMemory(mat, sizeof(mat));
    detail::s_self_chain_anchor.store(anchor ^ seed_value, std::memory_order_release);

    {
        auto& pt = detail::page_table();
        std::lock_guard<std::mutex> lk(pt.mtx);
        if (!detail::rebuild_page_table_locked(pt, snap.text_base, snap.text_size))
            return false;
    }

    if (tpm_attest::is_available())
        tpm_attest::extend_version_pcr(snap.text_sha256);

    return snap.text_hash != 0;
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
    snap.clear();

    HMODULE mod = GetModuleHandleW(nullptr);
    if (!mod) return;

    const auto* base = reinterpret_cast<const uint8_t*>(mod);
    const auto* dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(base);
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return;

    const auto* nt = reinterpret_cast<const IMAGE_NT_HEADERS64*>(base + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) return;

    const auto& imp_dir = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
    if (imp_dir.VirtualAddress == 0 || imp_dir.Size == 0) return;

    auto* imp = reinterpret_cast<const IMAGE_IMPORT_DESCRIPTOR*>(
        base + imp_dir.VirtualAddress);

    for (; imp->Name != 0; ++imp)
    {
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
        return true;

    MEMORY_BASIC_INFORMATION mbi{};
    uint64_t addr = snap.text_base;
    const uint64_t end = snap.text_base + snap.text_size;

    while (addr < end)
    {
        if (VirtualQuery(reinterpret_cast<LPCVOID>(addr), &mbi, sizeof(mbi)) == 0)
            return false;

        if (mbi.Protect & (PAGE_READWRITE | PAGE_EXECUTE_READWRITE |
                           PAGE_WRITECOPY | PAGE_EXECUTE_WRITECOPY))
            return false;

        addr = reinterpret_cast<uint64_t>(mbi.BaseAddress) + mbi.RegionSize;
    }
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

inline bool verify_full_text_eager(uint32_t* mismatched_page_out = nullptr)
{
    auto& pt = detail::page_table();
    std::lock_guard<std::mutex> lk(pt.mtx);
    for (uint32_t i = 0; i < pt.entries.size(); ++i)
    {
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

inline void rebuild_self_chain_anchor_locked()
{
    uint64_t seed_value = detail::s_self_chain_seed.load(std::memory_order_acquire);
    if (seed_value == 0) return;
    uint64_t per_call = siphash::siphash_3u64(seed_value, detail::load_k0(), detail::load_k1());
    uint64_t chain = detail::self_hash_chain_compute(per_call);
    uint8_t mat[16];
    memcpy(mat + 0, &chain, 8);
    memcpy(mat + 8, &per_call, 8);
    uint8_t mac[32] = {};
    uint8_t base_secret[32];
    detail::compute_session_secret(base_secret);
    sha256::hmac(base_secret, 32, mat, sizeof(mat), mac);
    SecureZeroMemory(base_secret, sizeof(base_secret));
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
}

namespace periodic {

    constexpr uint32_t kCadenceMs = 100;
    constexpr uint32_t kWorkerCount = 3;

    inline std::atomic<bool>& stop_flag()
    {
        static std::atomic<bool> v{false};
        return v;
    }

    inline std::vector<std::thread>& worker_threads()
    {
        static std::vector<std::thread> v;
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

    inline void worker_loop(int worker_id)
    {
        Sleep(50 * worker_id);
        while (!stop_flag().load(std::memory_order_acquire))
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
            qpc_array()[worker_id].store(start_ms, std::memory_order_release);
            detail::periodic_pass_counter().fetch_add(1, std::memory_order_acq_rel);

            if (worker_id == 0)
            {
                bool all_ready = true;
                uint64_t ref_sig = signature_array()[0].load(std::memory_order_acquire);
                for (uint32_t w = 0; w < kWorkerCount; ++w)
                {
                    uint64_t qw = qpc_array()[w].load(std::memory_order_acquire);
                    if (qw == 0)
                    {
                        all_ready = false;
                        break;
                    }
                }
                if (all_ready)
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
                    if (!quorum)
                    {
                        detail::periodic_violation_flag().store(true, std::memory_order_release);
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

    inline void start()
    {
        auto& running = detail::periodic_running_flag();
        bool expected = false;
        if (!running.compare_exchange_strong(expected, true)) return;
        stop_flag().store(false, std::memory_order_release);
        for (int i = 0; i < static_cast<int>(kWorkerCount); ++i)
        {
            try
            {
                worker_threads().emplace_back(worker_loop, i);
            }
            catch (...) {}
        }
        install_page_mac_veh();
    }

    inline void stop()
    {
        stop_flag().store(true, std::memory_order_release);
        for (auto& t : worker_threads())
        {
            if (t.joinable()) t.detach();
        }
        worker_threads().clear();
        detail::periodic_running_flag().store(false, std::memory_order_release);
    }

}

}
}
