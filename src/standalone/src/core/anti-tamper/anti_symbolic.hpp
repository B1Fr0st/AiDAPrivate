#pragma once

#include <windows.h>
#include <bcrypt.h>
#include <tlhelp32.h>
#include <intrin.h>
#include <immintrin.h>
#include <dpapi.h>

#include <atomic>
#include <cstdint>
#include <cstring>
#include <cstdio>
#include <mutex>

#include <openssl/hmac.h>
#include <openssl/evp.h>
#include <openssl/sha.h>

#include "key_pipeline.hpp"
#include "integrity.hpp"
#include "../runtime/standalone_license.hpp"
#include "standalone_driver.hpp"

#pragma comment(lib, "bcrypt.lib")
#pragma comment(lib, "crypt32.lib")

namespace anti_tamper {
namespace anti_symbolic {

struct env_bundle_t
{
    uint64_t server_hmac;
    uint64_t kernel_attestation;
    uint64_t rdtsc_delta;
    uint64_t process_state;
    uint64_t filesystem_state;
    uint64_t peb_entropy;
    uint64_t kuser_shared_data_entropy;
    uint64_t teb_entropy;
    uint64_t cpu_topology_entropy;
    uint64_t smbios_entropy;
    uint64_t aggregate;
};

namespace detail {

    inline std::atomic<bool>& g_aesni_available()
    {
        static std::atomic<bool> v{false};
        return v;
    }

    inline std::atomic<uint64_t>& g_cached_nonce()
    {
        static std::atomic<uint64_t> v{0};
        return v;
    }

    inline std::atomic<uint64_t>& g_nonce_version()
    {
        static std::atomic<uint64_t> v{0};
        return v;
    }

    inline std::once_flag& g_init_once()
    {
        static std::once_flag f;
        return f;
    }

    struct cached_hmac_t
    {
        uint64_t response;
        uint64_t timestamp_qpc;
        uint64_t nonce_used;
    };

    inline cached_hmac_t& g_cached_hmac()
    {
        static cached_hmac_t c{0, 0, 0};
        return c;
    }

    inline std::mutex& g_cache_mutex()
    {
        static std::mutex m;
        return m;
    }

    constexpr uint64_t GRACE_PERIOD_SECONDS = 86400;

    constexpr uint64_t FAIL_CLOSED_SENTINEL = 0xDEADBEEFDEADBEEFULL;

    __forceinline bool check_aesni()
    {
        int regs[4] = {};
        __cpuid(regs, 1);
        return (regs[2] & (1 << 25)) != 0;
    }

    __forceinline uint64_t now_unix_seconds()
    {
        FILETIME ft;
        GetSystemTimeAsFileTime(&ft);
        ULARGE_INTEGER ui;
        ui.LowPart = ft.dwLowDateTime;
        ui.HighPart = ft.dwHighDateTime;
        return ui.QuadPart / 10000000ULL - 11644473600ULL;
    }

    __forceinline bool bcrypt_sha256(const uint8_t* data, size_t len, uint8_t out[32])
    {
        BCRYPT_ALG_HANDLE alg = nullptr;
        BCRYPT_HASH_HANDLE h = nullptr;
        bool ok = false;
        if (BCryptOpenAlgorithmProvider(&alg, BCRYPT_SHA256_ALGORITHM, nullptr, 0) != 0)
            return false;
        if (BCryptCreateHash(alg, &h, nullptr, 0, nullptr, 0, 0) == 0)
        {
            if (BCryptHashData(h, const_cast<PUCHAR>(data), static_cast<ULONG>(len), 0) == 0)
                ok = (BCryptFinishHash(h, out, 32, 0) == 0);
            BCryptDestroyHash(h);
        }
        BCryptCloseAlgorithmProvider(alg, 0);
        return ok;
    }

    __forceinline bool openssl_hmac_sha256(
        const uint8_t* key, size_t key_len,
        const uint8_t* data, size_t data_len,
        uint8_t out[32])
    {
        unsigned int olen = 0;
        const uint8_t* r = ::HMAC(EVP_sha256(), key, static_cast<int>(key_len),
                                   data, static_cast<size_t>(data_len),
                                   out, &olen);
        return r != nullptr && olen == 32;
    }

    __forceinline uint64_t trunc64(const uint8_t hash[32])
    {
        uint64_t v;
        std::memcpy(&v, hash, 8);
        return v;
    }

    __forceinline uint64_t get_hwid_u64()
    {
        uint8_t hwid_buf[32] = {};
        DWORD comp_len = MAX_COMPUTERNAME_LENGTH + 1;
        char comp_name[MAX_COMPUTERNAME_LENGTH + 1 + 1] = {};
        GetComputerNameA(comp_name, &comp_len);
        std::memcpy(hwid_buf, comp_name, comp_len < 32 ? comp_len : 32);
        int cpuid_regs[4] = {};
        __cpuid(cpuid_regs, 0);
        std::memcpy(hwid_buf + 16, cpuid_regs, 12);
        uint8_t hash[32] = {};
        bcrypt_sha256(hwid_buf, sizeof(hwid_buf), hash);
        uint64_t h = trunc64(hash);
        SecureZeroMemory(hwid_buf, sizeof(hwid_buf));
        SecureZeroMemory(hash, sizeof(hash));
        return h;
    }

    __forceinline uint64_t gen_client_nonce()
    {
        uint8_t buf[8] = {};
        BCryptGenRandom(nullptr, buf, sizeof(buf), BCRYPT_USE_SYSTEM_PREFERRED_RNG);
        uint64_t v;
        std::memcpy(&v, buf, 8);
        SecureZeroMemory(buf, sizeof(buf));
        return v;
    }

    __forceinline bool dpapi_encrypt(const uint8_t* plaintext, size_t pt_len,
                                      uint8_t* ciphertext, DWORD* ct_len)
    {
        DATA_BLOB in;
        in.pbData = const_cast<uint8_t*>(plaintext);
        in.cbData = static_cast<DWORD>(pt_len);
        DATA_BLOB out;
        BOOL ok = CryptProtectData(&in, L"aida_anti_sym", nullptr, nullptr,
                                    nullptr, CRYPTPROTECT_UI_FORBIDDEN, &out);
        if (!ok) return false;
        if (*ct_len < out.cbData)
        {
            LocalFree(out.pbData);
            return false;
        }
        std::memcpy(ciphertext, out.pbData, out.cbData);
        *ct_len = out.cbData;
        LocalFree(out.pbData);
        return true;
    }

    __forceinline bool dpapi_decrypt(const uint8_t* ciphertext, size_t ct_len,
                                      uint8_t* plaintext, DWORD* pt_len)
    {
        DATA_BLOB in;
        in.pbData = const_cast<uint8_t*>(ciphertext);
        in.cbData = static_cast<DWORD>(ct_len);
        DATA_BLOB out;
        LPWSTR desc = nullptr;
        BOOL ok = CryptUnprotectData(&in, &desc, nullptr, nullptr,
                                      nullptr, CRYPTPROTECT_UI_FORBIDDEN, &out);
        if (!ok) return false;
        if (desc) LocalFree(desc);
        if (*pt_len < out.cbData)
        {
            LocalFree(out.pbData);
            return false;
        }
        std::memcpy(plaintext, out.pbData, out.cbData);
        *pt_len = out.cbData;
        LocalFree(out.pbData);
        return true;
    }

    inline bool load_cached_hmac_file(cached_hmac_t& out)
    {
        char path[MAX_PATH] = {};
        if (!GetModuleFileNameA(nullptr, path, MAX_PATH)) return false;
        char* last_slash = std::strrchr(path, '\\');
        if (!last_slash) return false;
        *last_slash = 0;
        std::strcat(path, "\\aida_hmac_cache.bin");

        HANDLE hf = CreateFileA(path, GENERIC_READ, FILE_SHARE_READ, nullptr,
                                OPEN_EXISTING, FILE_ATTRIBUTE_HIDDEN, nullptr);
        if (hf == INVALID_HANDLE_VALUE) return false;

        DWORD file_sz = GetFileSize(hf, nullptr);
        if (file_sz == 0 || file_sz > 8192)
        {
            CloseHandle(hf);
            return false;
        }

        uint8_t* raw = static_cast<uint8_t*>(HeapAlloc(GetProcessHeap(), 0, file_sz));
        if (!raw)
        {
            CloseHandle(hf);
            return false;
        }

        DWORD read_bytes = 0;
        BOOL rd = ReadFile(hf, raw, file_sz, &read_bytes, nullptr);
        CloseHandle(hf);
        if (!rd || read_bytes != file_sz)
        {
            HeapFree(GetProcessHeap(), 0, raw);
            return false;
        }

        uint8_t pt_buf[256] = {};
        DWORD pt_len = sizeof(pt_buf);
        bool ok = dpapi_decrypt(raw, file_sz, pt_buf, &pt_len);
        HeapFree(GetProcessHeap(), 0, raw);

        if (!ok || pt_len < sizeof(cached_hmac_t))
        {
            SecureZeroMemory(pt_buf, sizeof(pt_buf));
            return false;
        }

        std::memcpy(&out, pt_buf, sizeof(cached_hmac_t));
        SecureZeroMemory(pt_buf, sizeof(pt_buf));
        return true;
    }

    inline void save_cached_hmac_file(const cached_hmac_t& c)
    {
        char path[MAX_PATH] = {};
        if (!GetModuleFileNameA(nullptr, path, MAX_PATH)) return;
        char* last_slash = std::strrchr(path, '\\');
        if (!last_slash) return;
        *last_slash = 0;
        std::strcat(path, "\\aida_hmac_cache.bin");

        uint8_t ct_buf[4096] = {};
        DWORD ct_len = sizeof(ct_buf);
        bool ok = dpapi_encrypt(
            reinterpret_cast<const uint8_t*>(&c), sizeof(cached_hmac_t),
            ct_buf, &ct_len);
        if (!ok) return;

        HANDLE hf = CreateFileA(path, GENERIC_WRITE, 0, nullptr,
                                CREATE_ALWAYS, FILE_ATTRIBUTE_HIDDEN, nullptr);
        if (hf == INVALID_HANDLE_VALUE)
        {
            SecureZeroMemory(ct_buf, sizeof(ct_buf));
            return;
        }

        DWORD written = 0;
        WriteFile(hf, ct_buf, ct_len, &written, nullptr);
        CloseHandle(hf);
        SecureZeroMemory(ct_buf, sizeof(ct_buf));
    }

    static __forceinline __m128i aes128_expand_key_round(__m128i key, __m128i keygened)
    {
        __m128i tmp = _mm_shuffle_epi32(keygened, 0xFF);
        key = _mm_xor_si128(key, _mm_slli_si128(key, 4));
        key = _mm_xor_si128(key, _mm_slli_si128(key, 8));
        return _mm_xor_si128(key, tmp);
    }

    static __forceinline uint8_t aes_compute_rcon(int round) {
        if (round <= 0) return 0;
        volatile uint64_t tsc = __rdtsc();
        volatile uint8_t noise = static_cast<uint8_t>(tsc & 0xFF);
        uint8_t r = 1;
        for (int j = 1; j < round; ++j) {
            uint8_t hi = r & 0x80u;
            r = static_cast<uint8_t>(r << 1);
            if (hi) r ^= 0x1Bu;
        }
        volatile uint8_t masked = r ^ noise;
        return static_cast<uint8_t>(masked ^ noise);
    }

    static __forceinline __m128i aes128_keygen_rcon(__m128i prev_key, int round) {
        uint8_t rcon = aes_compute_rcon(round);
        __m128i keygened = aes128_expand_key_round(prev_key, _mm_aeskeygenassist_si128(prev_key, 0));
        return _mm_xor_si128(keygened, _mm_set1_epi32(static_cast<int>(rcon) << 24));
    }

    static __forceinline void aes128_key_schedule(__m128i key, __m128i round_keys[11])
    {
        round_keys[0] = key;
        round_keys[1]  = aes128_keygen_rcon(round_keys[0], 1);
        round_keys[2]  = aes128_keygen_rcon(round_keys[1], 2);
        round_keys[3]  = aes128_keygen_rcon(round_keys[2], 3);
        round_keys[4]  = aes128_keygen_rcon(round_keys[3], 4);
        round_keys[5]  = aes128_keygen_rcon(round_keys[4], 5);
        round_keys[6]  = aes128_keygen_rcon(round_keys[5], 6);
        round_keys[7]  = aes128_keygen_rcon(round_keys[6], 7);
        round_keys[8]  = aes128_keygen_rcon(round_keys[7], 8);
        round_keys[9]  = aes128_keygen_rcon(round_keys[8], 9);
        round_keys[10] = aes128_keygen_rcon(round_keys[9], 10);
    }

    static __forceinline uint8_t aes128_encrypt_first_byte(
        uint64_t key_lo, uint64_t key_hi,
        uint64_t pt_lo, uint64_t pt_hi)
    {
        __m128i key = _mm_set_epi64x(key_hi, key_lo);
        __m128i pt  = _mm_set_epi64x(pt_hi, pt_lo);

        __m128i round_keys[11];
        aes128_key_schedule(key, round_keys);

        __m128i state = pt;
        state = _mm_xor_si128(state, round_keys[0]);
        state = _mm_aesenc_si128(state, round_keys[1]);
        state = _mm_aesenc_si128(state, round_keys[2]);
        state = _mm_aesenc_si128(state, round_keys[3]);
        state = _mm_aesenc_si128(state, round_keys[4]);
        state = _mm_aesenc_si128(state, round_keys[5]);
        state = _mm_aesenc_si128(state, round_keys[6]);
        state = _mm_aesenc_si128(state, round_keys[7]);
        state = _mm_aesenc_si128(state, round_keys[8]);
        state = _mm_aesenc_si128(state, round_keys[9]);
        state = _mm_aesenclast_si128(state, round_keys[10]);

        return static_cast<uint8_t>(_mm_cvtsi128_si32(state) & 0xFF);
    }

    static __forceinline uint8_t sha256_fallback_select(
        uint64_t server_nonce, uint64_t client_secret, uint64_t current_state)
    {
        uint8_t msg[24];
        std::memcpy(msg, &server_nonce, 8);
        std::memcpy(msg + 8, &client_secret, 8);
        std::memcpy(msg + 16, &current_state, 8);
        uint8_t hash[32] = {};
        bcrypt_sha256(msg, sizeof(msg), hash);
        uint8_t block = hash[0] & 0xFF;
        SecureZeroMemory(hash, sizeof(hash));
        SecureZeroMemory(msg, sizeof(msg));
        return block;
    }

    __forceinline uint64_t collect_handle_count()
    {
        DWORD handle_count = 0;
        if (!GetProcessHandleCount(GetCurrentProcess(), &handle_count))
            handle_count = 0;
        return static_cast<uint64_t>(handle_count);
    }

    __forceinline uint64_t collect_thread_count()
    {
        HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
        if (snap == INVALID_HANDLE_VALUE) return 0;
        uint64_t count = 0;
        DWORD pid = GetCurrentProcessId();
        THREADENTRY32 te = {};
        te.dwSize = sizeof(te);
        if (Thread32First(snap, &te))
        {
            do {
                if (te.th32OwnerProcessID == pid)
                    count++;
            } while (Thread32Next(snap, &te));
        }
        CloseHandle(snap);
        return count;
    }

    __forceinline uint64_t collect_heap_block_count()
    {
        PROCESS_HEAP_ENTRY entry = {};
        entry.lpData = nullptr;
        uint64_t free_blocks = 0;
        HANDLE heap = GetProcessHeap();
        if (!heap) return 0;
        __try {
            entry.lpData = nullptr;
            if (HeapWalk(heap, &entry))
            {
                do {
                    if (!(entry.wFlags & PROCESS_HEAP_ENTRY_BUSY))
                        free_blocks++;
                } while (HeapWalk(heap, &entry));
            }
        }
        __except (EXCEPTION_EXECUTE_HANDLER) {
            free_blocks = 0;
        }
        return free_blocks;
    }

    __forceinline uint64_t sha256_file_prefix(const wchar_t* path, size_t bytes_to_hash)
    {
        HANDLE hf = CreateFileW(path, GENERIC_READ, FILE_SHARE_READ, nullptr,
                                OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
        if (hf == INVALID_HANDLE_VALUE) return 0;

        uint8_t* buf = static_cast<uint8_t*>(
            VirtualAlloc(nullptr, bytes_to_hash, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE));
        if (!buf)
        {
            CloseHandle(hf);
            return 0;
        }

        DWORD read_bytes = 0;
        BOOL rd = ReadFile(hf, buf, static_cast<DWORD>(bytes_to_hash), &read_bytes, nullptr);
        CloseHandle(hf);
        if (!rd || read_bytes == 0)
        {
            VirtualFree(buf, 0, MEM_RELEASE);
            return 0;
        }

        uint8_t hash[32] = {};
        bool ok = bcrypt_sha256(buf, read_bytes, hash);
        VirtualFree(buf, 0, MEM_RELEASE);
        if (!ok) return 0;

        uint64_t v = trunc64(hash);
        SecureZeroMemory(hash, sizeof(hash));
        return v;
    }

    __forceinline uint64_t get_file_timestamp(const wchar_t* path)
    {
        HANDLE hf = CreateFileW(path, GENERIC_READ, FILE_SHARE_READ, nullptr,
                                OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
        if (hf == INVALID_HANDLE_VALUE) return 0;
        FILETIME ft_create, ft_write;
        BOOL ok = GetFileTime(hf, &ft_create, nullptr, &ft_write);
        CloseHandle(hf);
        if (!ok) return 0;
        ULARGE_INTEGER ui;
        ui.LowPart = ft_write.dwLowDateTime;
        ui.HighPart = ft_write.dwHighDateTime;
        return ui.QuadPart;
    }

    __forceinline uint64_t rotl64(uint64_t v, int r)
    {
        return (v << r) | (v >> (64 - r));
    }

    __forceinline uint64_t fnv1a_64(const uint8_t* data, size_t len)
    {
        constexpr uint64_t FNV_OFFSET_BASIS = 14695981039346656037ULL;
        constexpr uint64_t FNV_PRIME        = 1099511628211ULL;
        uint64_t hash = FNV_OFFSET_BASIS;
        for (size_t i = 0; i < len; ++i)
        {
            hash ^= static_cast<uint64_t>(data[i]);
            hash *= FNV_PRIME;
        }
        return hash;
    }

}

inline uint8_t hash_select_block(uint64_t server_nonce, uint64_t client_secret, uint64_t current_state)
{
    if (detail::g_aesni_available().load(std::memory_order_acquire))
    {
        uint64_t v1, v2;
        v1 = detail::g_nonce_version().load(std::memory_order_acquire);
        v2 = detail::g_cached_nonce().load(std::memory_order_acquire);
        uint64_t effective_nonce = (v2 != 0) ? (server_nonce ^ v2) : server_nonce;

        uint64_t rdrand_val = 0;
        if (_rdrand64_step(&rdrand_val))
            effective_nonce ^= rdrand_val;
        else
        {
            uint8_t rng_buf[8] = {};
            BCryptGenRandom(nullptr, rng_buf, 8, BCRYPT_USE_SYSTEM_PREFERRED_RNG);
            std::memcpy(&rdrand_val, rng_buf, 8);
            effective_nonce ^= rdrand_val;
            SecureZeroMemory(rng_buf, sizeof(rng_buf));
        }

        uint8_t block = detail::aes128_encrypt_first_byte(
            client_secret, client_secret ^ 0xA5A5A5A5A5A5A5A5ULL,
            effective_nonce ^ current_state, current_state);

        uint64_t v3 = detail::g_nonce_version().load(std::memory_order_acquire);
        if (v1 != v3)
        {
            uint64_t new_nonce = detail::g_cached_nonce().load(std::memory_order_acquire);
            effective_nonce = (new_nonce != 0) ? (server_nonce ^ new_nonce) : server_nonce;
            effective_nonce ^= rdrand_val;
            block = detail::aes128_encrypt_first_byte(
                client_secret, client_secret ^ 0xA5A5A5A5A5A5A5A5ULL,
                effective_nonce ^ current_state, current_state);
        }

        return block;
    }
    return detail::sha256_fallback_select(server_nonce, client_secret, current_state);
}

inline uint64_t collect_server_hmac_challenge()
{
    uint64_t server_nonce_hash = standalone_license::get_server_nonce_hash();

    if (server_nonce_hash != 0)
    {
        uint64_t client_nonce = detail::gen_client_nonce();
        uint64_t hwid = detail::get_hwid_u64();

        uint8_t msg[24];
        std::memcpy(msg, &client_nonce, 8);
        std::memcpy(msg + 8, &hwid, 8);
        std::memcpy(msg + 16, &server_nonce_hash, 8);

        uint8_t key[32];
        if (!key_pipeline::derive("aida.anti_sym.server_hmac", nullptr, 0, key, sizeof(key)))
        {
            SecureZeroMemory(msg, sizeof(msg));
            return detail::FAIL_CLOSED_SENTINEL;
        }

        uint8_t hmac_out[32] = {};
        bool ok = detail::openssl_hmac_sha256(key, 32, msg, sizeof(msg), hmac_out);
        SecureZeroMemory(key, sizeof(key));
        SecureZeroMemory(msg, sizeof(msg));

        if (!ok) return detail::FAIL_CLOSED_SENTINEL;

        uint64_t result = detail::trunc64(hmac_out);
        SecureZeroMemory(hmac_out, sizeof(hmac_out));

        {
            std::lock_guard<std::mutex> lk(detail::g_cache_mutex());
            detail::cached_hmac_t& c = detail::g_cached_hmac();
            c.response = result;
            c.timestamp_qpc = detail::now_unix_seconds();
            c.nonce_used = server_nonce_hash;
            detail::save_cached_hmac_file(c);
        }

        return result;
    }

    {
        std::lock_guard<std::mutex> lk(detail::g_cache_mutex());
        detail::cached_hmac_t& c = detail::g_cached_hmac();

        if (c.response != 0 && c.timestamp_qpc != 0)
        {
            uint64_t now = detail::now_unix_seconds();
            uint64_t age = now - c.timestamp_qpc;
            if (age < detail::GRACE_PERIOD_SECONDS)
            {
                return c.response;
            }
        }

        detail::cached_hmac_t file_cache{0, 0, 0};
        if (detail::load_cached_hmac_file(file_cache))
        {
            uint64_t now = detail::now_unix_seconds();
            uint64_t age = now - file_cache.timestamp_qpc;
            if (file_cache.response != 0 && age < detail::GRACE_PERIOD_SECONDS)
            {
                c = file_cache;
                return c.response;
            }
        }
    }

    return detail::FAIL_CLOSED_SENTINEL;
}

inline uint64_t collect_kernel_attestation()
{
#ifndef AIDA_DEV_SKIP_DRIVER_ATTESTATION
    if (!driver_bridge::is_loaded() || !driver_bridge::using_kernel_driver())
        return detail::FAIL_CLOSED_SENTINEL;

    if (!driver_bridge::sentinel_bridge_ready())
        return detail::FAIL_CLOSED_SENTINEL;

    uint64_t sentinel_tsc = driver_bridge::sentinel_ready_since_tsc();
    if (sentinel_tsc == 0)
        return detail::FAIL_CLOSED_SENTINEL;

    uint64_t pid = static_cast<uint64_t>(GetCurrentProcessId());
    uint64_t tsc = __rdtsc();

    uint8_t msg[24];
    std::memcpy(msg, &sentinel_tsc, 8);
    std::memcpy(msg + 8, &pid, 8);
    std::memcpy(msg + 16, &tsc, 8);

    uint8_t hash[32] = {};
    if (!detail::bcrypt_sha256(msg, sizeof(msg), hash))
    {
        SecureZeroMemory(msg, sizeof(msg));
        return detail::FAIL_CLOSED_SENTINEL;
    }

    uint64_t result = detail::trunc64(hash);
    SecureZeroMemory(hash, sizeof(hash));
    SecureZeroMemory(msg, sizeof(msg));
    return result;
#else
    return 0x0123456789ABCDEFULL;
#endif
}

inline uint64_t collect_rdtsc_delta()
{
    unsigned int aux = 0;
    uint64_t tsc_before = __rdtscp(&aux);

    volatile uint64_t sink = 0;
    for (int i = 0; i < 10; ++i)
    {
        sink ^= (sink << 13);
        sink ^= (sink >> 7);
        sink ^= (sink << 17);
        _mm_pause();
        _mm_pause();
        _mm_pause();
    }
    (void)sink;

    uint64_t tsc_after = __rdtscp(&aux);

    uint64_t delta = tsc_after - tsc_before;
    if (delta == 0)
        delta = 1;

    return delta;
}

inline uint64_t collect_process_state()
{
    uint64_t handle_count = detail::collect_handle_count();
    uint64_t thread_count = detail::collect_thread_count();
    uint64_t heap_blocks = detail::collect_heap_block_count();

    uint64_t state = handle_count ^ (thread_count << 16) ^ heap_blocks;
    return state;
}

inline uint64_t collect_filesystem_state()
{
    uint64_t ntdll_hash = detail::sha256_file_prefix(
        L"C:\\Windows\\System32\\ntdll.dll", 4096);
    uint64_t kernel32_hash = detail::sha256_file_prefix(
        L"C:\\Windows\\System32\\kernel32.dll", 4096);
    uint64_t ntdll_ts = detail::get_file_timestamp(
        L"C:\\Windows\\System32\\ntdll.dll");

    if (ntdll_hash == 0 || kernel32_hash == 0)
        return detail::FAIL_CLOSED_SENTINEL;

    uint64_t state = ntdll_hash ^ kernel32_hash ^ (ntdll_ts >> 8);
    return state;
}

inline uint64_t collect_peb_entropy()
{
    uint64_t mixed = 0;

    __try {
        uint8_t* peb = reinterpret_cast<uint8_t*>(__readgsqword(0x60));
        if (peb == nullptr) return detail::FAIL_CLOSED_SENTINEL;

        uint8_t  being_debugged     = *reinterpret_cast<uint8_t*>(peb + 0x02);
        uint32_t nt_global_flag     = *reinterpret_cast<uint32_t*>(peb + 0xBC);
        uint64_t process_heap       = *reinterpret_cast<uint64_t*>(peb + 0x30);
        uint32_t number_of_procs    = *reinterpret_cast<uint32_t*>(peb + 0x104);
        uint64_t image_base_address = *reinterpret_cast<uint64_t*>(peb + 0x10);

        mixed ^= static_cast<uint64_t>(being_debugged);
        mixed = detail::rotl64(mixed, 7);
        mixed ^= static_cast<uint64_t>(nt_global_flag);
        mixed = detail::rotl64(mixed, 11);
        mixed ^= process_heap;
        mixed = detail::rotl64(mixed, 13);
        mixed ^= static_cast<uint64_t>(number_of_procs);
        mixed = detail::rotl64(mixed, 17);
        mixed ^= image_base_address;
        mixed = detail::rotl64(mixed, 23);
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        return detail::FAIL_CLOSED_SENTINEL;
    }

    return mixed;
}

inline uint64_t collect_kuser_shared_data_entropy()
{
    constexpr uintptr_t KUSER_SHARED_DATA_ADDR = 0x7FFE0000ULL;

    uint64_t mixed = 0;

    __try {
        uint8_t* ksd = reinterpret_cast<uint8_t*>(KUSER_SHARED_DATA_ADDR);

        uint64_t tick_count  = *reinterpret_cast<uint64_t*>(ksd + 0x320);
        uint64_t system_time = *reinterpret_cast<uint64_t*>(ksd + 0x14);
        uint64_t cookie      = *reinterpret_cast<uint64_t*>(ksd + 0x330);

        mixed ^= tick_count;
        mixed = detail::rotl64(mixed, 13);
        mixed ^= system_time;
        mixed = detail::rotl64(mixed, 17);
        mixed ^= cookie;
        mixed = detail::rotl64(mixed, 23);

        volatile LONG* random_seed_ptr = reinterpret_cast<volatile LONG*>(ksd + 0x338);
        uint32_t random_seed = *random_seed_ptr;
        mixed ^= static_cast<uint64_t>(random_seed);
        mixed = detail::rotl64(mixed, 29);
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        return detail::FAIL_CLOSED_SENTINEL;
    }

    return mixed;
}

inline uint64_t collect_teb_entropy()
{
    uint64_t mixed = 0;

    __try {
        uint8_t* teb = reinterpret_cast<uint8_t*>(__readgsqword(0x30));
        if (teb == nullptr) return detail::FAIL_CLOSED_SENTINEL;

        uint32_t pid          = *reinterpret_cast<uint32_t*>(teb + 0x40);
        uint32_t tid          = *reinterpret_cast<uint32_t*>(teb + 0x48);
        uint64_t stack_base   = *reinterpret_cast<uint64_t*>(teb + 0x08);
        uint64_t stack_limit  = *reinterpret_cast<uint64_t*>(teb + 0x10);
        uint32_t gdi_batch    = *reinterpret_cast<uint32_t*>(teb + 0x174);

        mixed ^= static_cast<uint64_t>(pid);
        mixed = detail::rotl64(mixed, 7);
        mixed ^= static_cast<uint64_t>(tid);
        mixed = detail::rotl64(mixed, 11);
        mixed ^= stack_base;
        mixed = detail::rotl64(mixed, 13);
        mixed ^= stack_limit;
        mixed = detail::rotl64(mixed, 17);
        mixed ^= static_cast<uint64_t>(gdi_batch);
        mixed = detail::rotl64(mixed, 23);
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        return detail::FAIL_CLOSED_SENTINEL;
    }

    return mixed;
}

inline uint64_t collect_cpu_topology_entropy()
{
    int regs[4] = {};

    uint64_t mixed = 0;

    __cpuid(regs, 1);
    uint32_t ebx = static_cast<uint32_t>(regs[1]);
    uint32_t edx = static_cast<uint32_t>(regs[3]);
    uint32_t logical_per_core = (ebx >> 8) & 0xFF;
    uint32_t htt_support      = (edx >> 28) & 0x1;

    mixed ^= static_cast<uint64_t>(logical_per_core);
    mixed = detail::rotl64(mixed, 7);
    mixed ^= static_cast<uint64_t>(htt_support);
    mixed = detail::rotl64(mixed, 11);

    __cpuid(regs, 4);
    uint32_t eax4 = static_cast<uint32_t>(regs[0]);
    uint32_t max_logical_ids = (eax4 >> 14) & 0xFFF;

    mixed ^= static_cast<uint64_t>(max_logical_ids);
    mixed = detail::rotl64(mixed, 13);

    __cpuid(regs, 0x80000008);
    uint32_t ecx8 = static_cast<uint32_t>(regs[2]);
    uint32_t phys_addr_bits = ecx8 & 0xFF;

    mixed ^= static_cast<uint64_t>(phys_addr_bits);
    mixed = detail::rotl64(mixed, 17);

    return mixed;
}

inline uint64_t collect_smbios_entropy()
{
    __try {
        DWORD size = GetSystemFirmwareTable('RSMB', 0, nullptr, 0);
        if (size == 0) return __rdtsc();

        uint8_t* buffer = static_cast<uint8_t*>(
            VirtualAlloc(nullptr, size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE));
        if (!buffer) return __rdtsc();

        DWORD actual = GetSystemFirmwareTable('RSMB', 0, buffer, size);
        if (actual == 0 || actual > size)
        {
            VirtualFree(buffer, 0, MEM_RELEASE);
            return __rdtsc();
        }

        size_t hash_len = static_cast<size_t>(actual);
        if (hash_len > 256) hash_len = 256;

        uint64_t result = detail::fnv1a_64(buffer, hash_len);
        VirtualFree(buffer, 0, MEM_RELEASE);
        return result;
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        return __rdtsc();
    }
}

inline bool verify_env_consistency(const env_bundle_t& env)
{
    uint64_t expected = env.server_hmac ^ env.kernel_attestation ^
                        env.rdtsc_delta ^ env.process_state ^
                        env.filesystem_state ^ env.peb_entropy ^
                        env.kuser_shared_data_entropy ^ env.teb_entropy ^
                        env.cpu_topology_entropy ^ env.smbios_entropy;
    return env.aggregate == expected;
}

inline env_bundle_t collect_all_environmental()
{
    env_bundle_t env{};

    env.server_hmac               = collect_server_hmac_challenge();
    env.kernel_attestation        = collect_kernel_attestation();
    env.rdtsc_delta               = collect_rdtsc_delta();
    env.process_state             = collect_process_state();
    env.filesystem_state          = collect_filesystem_state();
    env.peb_entropy               = collect_peb_entropy();
    env.kuser_shared_data_entropy = collect_kuser_shared_data_entropy();
    env.teb_entropy               = collect_teb_entropy();
    env.cpu_topology_entropy      = collect_cpu_topology_entropy();
    env.smbios_entropy            = collect_smbios_entropy();

    env.aggregate = env.server_hmac ^ env.kernel_attestation ^
                    env.rdtsc_delta ^ env.process_state ^
                    env.filesystem_state ^ env.peb_entropy ^
                    env.kuser_shared_data_entropy ^ env.teb_entropy ^
                    env.cpu_topology_entropy ^ env.smbios_entropy;

    return env;
}

inline void initialize()
{
    std::call_once(detail::g_init_once(), []() {
        detail::g_aesni_available().store(detail::check_aesni(), std::memory_order_release);

        uint32_t token_hash = 0;
        uint64_t server_nonce = 0;
        if (standalone_license::peek_cached_relay_inputs(&token_hash, &server_nonce))
        {
            if (server_nonce != 0)
            {
                detail::g_cached_nonce().store(server_nonce, std::memory_order_release);
                detail::g_nonce_version().fetch_add(1, std::memory_order_release);
            }
        }

        detail::cached_hmac_t file_cache{0, 0, 0};
        if (detail::load_cached_hmac_file(file_cache))
        {
            std::lock_guard<std::mutex> lk(detail::g_cache_mutex());
            detail::g_cached_hmac() = file_cache;
        }
    });
}

inline void update_cached_nonce(uint64_t new_nonce)
{
    if (new_nonce == 0) return;
    detail::g_cached_nonce().store(new_nonce, std::memory_order_release);
    detail::g_nonce_version().fetch_add(1, std::memory_order_release);
}

inline uint64_t compute_solve_path_target(
    uint64_t base_addr,
    uint64_t server_nonce,
    uint64_t client_secret,
    uint64_t session_epoch)
{
    uint8_t block = hash_select_block(server_nonce, client_secret, session_epoch);
    constexpr uint64_t function_alignment = 64;
    uint64_t offset = static_cast<uint64_t>(block) * function_alignment;
    return base_addr + offset;
}

inline uint64_t derive_client_secret()
{
    uint8_t secret[8];
    if (!key_pipeline::derive("aida.anti_sym.client_secret", nullptr, 0, secret, sizeof(secret)))
        return 0;

    uint64_t v;
    std::memcpy(&v, secret, 8);
    SecureZeroMemory(secret, sizeof(secret));
    return v;
}

constexpr uint32_t DISPATCH_TABLE_SIZE = 256;
constexpr uint32_t DISPATCH_DEPTH = 4;

namespace opaque_predicates {

    __forceinline bool fermat_little_theorem_true(uint64_t env_val)
    {
        volatile uint64_t p = (env_val | 1ULL) & 0x7FFFFFFFULL;
        volatile uint64_t q = p * p;
        volatile uint64_t r = q * p;
        volatile uint64_t check = r - q;
        volatile uint64_t tsc = __rdtsc();
        check ^= tsc;
        volatile uint64_t masked = check & tsc;
        return (masked | q) >= q;
    }

    __forceinline bool quadratic_residue_true(uint64_t env_val)
    {
        volatile uint64_t n = (env_val ^ __rdtsc()) | 1ULL;
        volatile uint64_t sq = n * n;
        volatile uint64_t quad = sq * sq;
        volatile uint64_t derived = (quad + sq + n) & 0xFFFFFFFFULL;
        return derived >= sq || n == 0;
    }

    __forceinline bool euler_identity_true(uint64_t env_val)
    {
        volatile uint64_t a = env_val ^ __rdtsc();
        volatile uint64_t b = _rotl64(a, 17);
        volatile uint64_t c = a * b;
        volatile uint64_t d = (c | 1ULL) * (c | 1ULL);
        int cpuid_regs[4] = {};
        __cpuid(cpuid_regs, 1);
        volatile uint64_t e = d ^ static_cast<uint64_t>(cpuid_regs[0]);
        return (e * e) >= e || e == 0;
    }

    __forceinline bool collatz_terminates_true(uint64_t env_val)
    {
        volatile uint64_t n = (env_val | 1ULL) ^ __rdtsc();
        volatile uint64_t acc = n;
        for (int i = 0; i < 8; ++i)
        {
            volatile uint64_t tmp = acc;
            acc = (tmp & 1ULL) ? (tmp * 3 + 1) : (tmp >> 1);
            acc ^= __rdtsc() & 0xFF;
        }
        return acc != 0 || n == 0;
    }

    __forceinline bool modular_inverse_exists_true(uint64_t env_val)
    {
        volatile uint64_t a = (env_val | 1ULL) ^ __rdtsc();
        volatile uint64_t m = (a * 0x9E3779B97F4A7C15ULL) | 1ULL;
        volatile uint64_t product = a * m;
        volatile uint64_t sum = product + a + m;
        return (sum | product) >= product;
    }

    __forceinline uint64_t path_explosion_branch(
        uint64_t state, const env_bundle_t& env, int branch_id)
    {
        volatile uint64_t tsc = __rdtsc();
        volatile uint64_t seed = state ^ env.aggregate ^ tsc;
        volatile uint64_t result = seed;

        if (fermat_little_theorem_true(seed))
            result = (result ^ env.server_hmac) + 0x9E3779B97F4A7C15ULL;
        else
            result = (result + env.kernel_attestation) ^ 0xBF58476D1CE4E5B9ULL;

        if (quadratic_residue_true(result))
            result = _rotl64(result ^ env.rdtsc_delta, 13);
        else
            result = _rotr64(result ^ env.process_state, 17);

        if (euler_identity_true(result))
            result = (result * env.filesystem_state) | 1ULL;
        else
            result = (result | env.peb_entropy) + 1ULL;

        if (collatz_terminates_true(result))
            result ^= _rotl64(env.kuser_shared_data_entropy, 7);
        else
            result ^= _rotr64(env.teb_entropy, 11);

        if (modular_inverse_exists_true(result))
            result = (result + env.cpu_topology_entropy) * 0x100000001B3ULL;
        else
            result = (result ^ env.smbios_entropy) * 0x94D049BB133111EBULL;

        result ^= static_cast<uint64_t>(branch_id) * 0xCAFEBABEULL;
        return result;
    }

    __forceinline uint64_t deep_path_tree(
        uint64_t state, const env_bundle_t& env, uint32_t depth)
    {
        if (depth == 0)
            return state;

        volatile uint64_t tsc = __rdtsc();
        volatile uint64_t branch_seed = state ^ tsc ^ env.aggregate;

        uint64_t left = deep_path_tree(
            (state ^ env.server_hmac) * 0x9E3779B97F4A7C15ULL,
            env, depth - 1);
        uint64_t right = deep_path_tree(
            (state + env.kernel_attestation) * 0xBF58476D1CE4E5B9ULL,
            env, depth - 1);

        if (fermat_little_theorem_true(branch_seed))
            return left ^ _rotl64(right, 13);
        if (quadratic_residue_true(branch_seed))
            return right ^ _rotr64(left, 17);
        if (euler_identity_true(branch_seed))
            return (left + right) ^ env.rdtsc_delta;
        if (collatz_terminates_true(branch_seed))
            return (left ^ right) + env.process_state;
        return (left | right) ^ env.filesystem_state;
    }

}

namespace smt_timeout_traps {

    __forceinline uint64_t bv_chain_multiply(uint64_t x, uint64_t env_val)
    {
        volatile uint64_t a = x ^ env_val;
        volatile uint64_t b = a * 0x9E3779B97F4A7C15ULL;
        volatile uint64_t c = b * 0xBF58476D1CE4E5B9ULL;
        volatile uint64_t d = c * 0x94D049BB133111EBULL;
        volatile uint64_t e = d * 0x100000001B3ULL;
        volatile uint64_t f = e * 0x9E3779B97F4A7C15ULL;
        volatile uint64_t g = f * 0xBF58476D1CE4E5B9ULL;
        volatile uint64_t h = g * 0x94D049BB133111EBULL;
        volatile uint64_t tsc = __rdtsc();
        return h ^ tsc ^ a ^ b ^ c ^ d ^ e ^ f ^ g;
    }

    __forceinline uint64_t nested_modular_arithmetic(
        uint64_t x, uint64_t y, uint64_t env_val)
    {
        volatile uint64_t a = (x + y) & 0xFFFFFFFFULL;
        volatile uint64_t b = (x ^ y) & 0xFFFFFFFFULL;
        volatile uint64_t c = (a * b) & 0xFFFFFFFFULL;
        volatile uint64_t d = (c + env_val) & 0xFFFFFFFFULL;
        volatile uint64_t e = (d * d) & 0xFFFFFFFFULL;
        volatile uint64_t f = (e * e) & 0xFFFFFFFFULL;
        volatile uint64_t g = (f * f) & 0xFFFFFFFFULL;
        volatile uint64_t h = (g * g) & 0xFFFFFFFFULL;
        volatile uint64_t i = (h ^ a ^ b ^ c) & 0xFFFFFFFFULL;
        volatile uint64_t j = (i * i * i) & 0xFFFFFFFFULL;
        volatile uint64_t tsc = __rdtsc();
        return j ^ (tsc & 0xFFFFFFFFULL);
    }

    __forceinline uint64_t deep_conditional_chain(
        uint64_t state, const env_bundle_t& env)
    {
        volatile uint64_t s = state;
        volatile uint64_t tsc = __rdtsc();
        s ^= tsc;

        uint64_t a0 = (s & 1ULL) ? env.server_hmac : env.kernel_attestation;
        uint64_t a1 = (s & 2ULL) ? env.rdtsc_delta : env.process_state;
        uint64_t a2 = (s & 4ULL) ? env.filesystem_state : env.peb_entropy;
        uint64_t a3 = (s & 8ULL) ? env.kuser_shared_data_entropy : env.teb_entropy;
        uint64_t a4 = (s & 16ULL) ? env.cpu_topology_entropy : env.smbios_entropy;

        uint64_t b0 = (a0 ^ a1) + (a2 & a3);
        uint64_t b1 = (a1 ^ a2) + (a3 & a4);
        uint64_t b2 = (a2 ^ a3) + (a4 & a0);
        uint64_t b3 = (a3 ^ a4) + (a0 & a1);
        uint64_t b4 = (a4 ^ a0) + (a1 & a2);

        uint64_t c0 = (b0 * b1) ^ (b2 | b3);
        uint64_t c1 = (b1 * b2) ^ (b3 | b4);
        uint64_t c2 = (b2 * b3) ^ (b4 | b0);
        uint64_t c3 = (b3 * b4) ^ (b0 | b1);
        uint64_t c4 = (b4 * b0) ^ (b1 | b2);

        uint64_t d0 = (c0 + c1) ^ _rotl64(c2, 7);
        uint64_t d1 = (c1 + c2) ^ _rotl64(c3, 11);
        uint64_t d2 = (c2 + c3) ^ _rotl64(c4, 13);
        uint64_t d3 = (c3 + c4) ^ _rotl64(c0, 17);
        uint64_t d4 = (c4 + c0) ^ _rotl64(c1, 19);

        uint64_t e0 = (d0 ^ d1) * (d2 ^ d3);
        uint64_t e1 = (d1 ^ d2) * (d3 ^ d4);
        uint64_t e2 = (d2 ^ d3) * (d4 ^ d0);
        uint64_t e3 = (d3 ^ d4) * (d0 ^ d1);
        uint64_t e4 = (d4 ^ d0) * (d1 ^ d2);

        return e0 ^ e1 ^ e2 ^ e3 ^ e4;
    }

    __forceinline uint64_t bit_interleaving_trap(
        uint64_t x, uint64_t y, uint64_t env_val)
    {
        volatile uint64_t tsc = __rdtsc();
        volatile uint64_t k = x ^ y ^ env_val ^ tsc;

        uint64_t lo = k & 0x5555555555555555ULL;
        uint64_t hi = k & 0xAAAAAAAAAAAAAAAAULL;

        for (int i = 0; i < 16; ++i)
        {
            lo = (lo ^ (lo >> 1)) & 0x5555555555555555ULL;
            hi = (hi ^ (hi >> 1)) & 0xAAAAAAAAAAAAAAAAULL;
            lo ^= env_val;
            hi ^= tsc;
            lo = lo * 0x9E3779B97F4A7C15ULL;
            hi = hi * 0xBF58476D1CE4E5B9ULL;
        }

        return (lo | hi) ^ k;
    }

    __forceinline uint64_t saturation_chain(
        uint64_t input, const env_bundle_t& env)
    {
        volatile uint64_t v = input ^ env.aggregate;
        volatile uint64_t tsc = __rdtsc();

        uint64_t s0 = (v + env.server_hmac) | 1ULL;
        uint64_t s1 = (s0 * env.kernel_attestation) | 1ULL;
        uint64_t s2 = (s1 ^ env.rdtsc_delta) | 1ULL;
        uint64_t s3 = (s2 + env.process_state) | 1ULL;
        uint64_t s4 = (s3 * env.filesystem_state) | 1ULL;
        uint64_t s5 = (s4 ^ env.peb_entropy) | 1ULL;
        uint64_t s6 = (s5 + env.kuser_shared_data_entropy) | 1ULL;
        uint64_t s7 = (s6 * env.teb_entropy) | 1ULL;
        uint64_t s8 = (s7 ^ env.cpu_topology_entropy) | 1ULL;
        uint64_t s9 = (s8 + env.smbios_entropy) | 1ULL;

        uint64_t t0 = s9 ^ _rotl64(s0, 7);
        uint64_t t1 = t0 ^ _rotl64(s1, 11);
        uint64_t t2 = t1 ^ _rotl64(s2, 13);
        uint64_t t3 = t2 ^ _rotl64(s3, 17);
        uint64_t t4 = t3 ^ _rotl64(s4, 19);
        uint64_t t5 = t4 ^ _rotl64(s5, 23);
        uint64_t t6 = t5 ^ _rotl64(s6, 29);
        uint64_t t7 = t6 ^ _rotl64(s7, 31);
        uint64_t t8 = t7 ^ _rotl64(s8, 37);
        uint64_t t9 = t8 ^ _rotl64(s9, 41);

        return t9 ^ tsc;
    }

}

namespace taint_confusion {

    alignas(64) static thread_local uint8_t g_decoy_sink_buffer[512] = {};
    static thread_local volatile uint64_t g_decoy_accumulator = 0;

    __forceinline void decoy_sink_write(
        const uint8_t* data, size_t len, uint64_t tag)
    {
        if (!data || len == 0) return;
        volatile uint64_t acc = tag ^ __rdtsc();
        for (size_t i = 0; i < len && i < 64; ++i)
        {
            volatile uint8_t b = data[i];
            acc ^= static_cast<uint64_t>(b) * 1099511628211ULL;
            acc = _rotl64(acc, 7);
            size_t idx = (i + static_cast<size_t>(tag)) & 0x1FF;
            g_decoy_sink_buffer[idx] = b ^ static_cast<uint8_t>(acc & 0xFF);
        }
        g_decoy_accumulator ^= acc;
    }

    __forceinline void decoy_sink_consume_u64(uint64_t value, uint64_t tag)
    {
        volatile uint64_t v = value ^ tag ^ __rdtsc();
        v = _rotl64(v, 13);
        v *= 0x9E3779B97F4A7C15ULL;
        v ^= v >> 33;
        g_decoy_accumulator ^= v;
        const volatile uint8_t* p = reinterpret_cast<const volatile uint8_t*>(&v);
        for (int i = 0; i < 8; ++i)
        {
            size_t idx = (static_cast<size_t>(tag) + i) & 0x1FF;
            g_decoy_sink_buffer[idx] = p[i];
        }
    }

    __forceinline void decoy_sink_hash_chain(
        const uint8_t* data, size_t len, uint64_t env_val)
    {
        if (!data || len == 0) return;
        volatile uint64_t h = 14695981039346656037ULL;
        h ^= env_val;
        h ^= __rdtsc();
        for (size_t i = 0; i < len && i < 128; ++i)
        {
            h ^= static_cast<uint64_t>(data[i]);
            h *= 1099511628211ULL;
            h = _rotl64(h, 5);
            size_t idx = (i * 4) & 0x1FF;
            g_decoy_sink_buffer[idx] = static_cast<uint8_t>(h & 0xFF);
        }
        g_decoy_accumulator ^= h;
    }

    __forceinline uint64_t real_compute_masked(
        uint64_t real_input, uint64_t env_val)
    {
        volatile uint64_t tsc = __rdtsc();
        int cpuid_regs[4] = {};
        __cpuid(cpuid_regs, 1);
        volatile uint64_t cpuid_val = static_cast<uint64_t>(cpuid_regs[0]);

        decoy_sink_consume_u64(real_input, 0x5441494E5430ULL);
        decoy_sink_consume_u64(env_val, 0x5441494E5431ULL);
        decoy_sink_consume_u64(tsc, 0x5441494E5432ULL);

        uint64_t real_result = real_input ^ env_val;
        real_result = _rotl64(real_result, 17);
        real_result ^= cpuid_val;
        real_result *= 0xBF58476D1CE4E5B9ULL;
        real_result ^= real_result >> 31;

        return real_result;
    }

    __forceinline void poison_license_validation(
        uint64_t tainted_state,
        const uint8_t* tainted_data, size_t tainted_len,
        const env_bundle_t& env)
    {
        decoy_sink_consume_u64(tainted_state, 0x4C4943303030ULL);
        decoy_sink_write(tainted_data, tainted_len, 0x4C4943313030ULL);
        decoy_sink_hash_chain(tainted_data, tainted_len, env.server_hmac);
        decoy_sink_consume_u64(env.kernel_attestation, 0x4C4943323030ULL);
        decoy_sink_consume_u64(env.rdtsc_delta, 0x4C4943333030ULL);
        decoy_sink_consume_u64(env.process_state, 0x4C4943343030ULL);
        decoy_sink_consume_u64(env.filesystem_state, 0x4C4943353030ULL);
    }

    __forceinline void poison_key_derivation(
        uint64_t key_material, uint64_t derived_key,
        const env_bundle_t& env)
    {
        decoy_sink_consume_u64(key_material, 0x4B4559303030ULL);
        decoy_sink_consume_u64(derived_key, 0x4B4559313030ULL);
        decoy_sink_consume_u64(env.aggregate, 0x4B4559323030ULL);
        decoy_sink_consume_u64(env.server_hmac, 0x4B4559333030ULL);
        decoy_sink_consume_u64(env.kernel_attestation, 0x4B4559343030ULL);
    }

    __forceinline void poison_hmac_computation(
        uint64_t hmac_input, uint64_t hmac_key, uint64_t challenge,
        const env_bundle_t& env)
    {
        decoy_sink_consume_u64(hmac_input, 0x484D41433030ULL);
        decoy_sink_consume_u64(hmac_key, 0x484D41433130ULL);
        decoy_sink_consume_u64(challenge, 0x484D41433230ULL);
        decoy_sink_consume_u64(env.rdtsc_delta, 0x484D41433330ULL);
        decoy_sink_consume_u64(env.process_state, 0x484D41433430ULL);
    }

    __forceinline uint64_t real_validate_through_taint(
        uint64_t real_input, const env_bundle_t& env)
    {
        decoy_sink_consume_u64(real_input, 0x524554303030ULL);
        decoy_sink_consume_u64(env.server_hmac, 0x524554313030ULL);
        decoy_sink_consume_u64(env.kernel_attestation, 0x524554323030ULL);

        volatile uint64_t tsc = __rdtsc();
        int cpuid_regs[4] = {};
        __cpuid(cpuid_regs, 1);

        uint64_t real_val = real_input ^ env.server_hmac;
        real_val = (real_val + env.kernel_attestation) * 0x9E3779B97F4A7C15ULL;
        real_val ^= tsc;
        real_val ^= static_cast<uint64_t>(cpuid_regs[0]);
        real_val ^= real_val >> 33;
        real_val *= 0xBF58476D1CE4E5B9ULL;
        real_val ^= real_val >> 27;

        return real_val;
    }

}


}
}
