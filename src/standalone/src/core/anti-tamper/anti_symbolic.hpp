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

    static __forceinline void aes128_key_schedule(__m128i key, __m128i round_keys[11])
    {
        round_keys[0] = key;
        round_keys[1]  = aes128_expand_key_round(round_keys[0],  _mm_aeskeygenassist_si128(round_keys[0],  0x01));
        round_keys[2]  = aes128_expand_key_round(round_keys[1],  _mm_aeskeygenassist_si128(round_keys[1],  0x02));
        round_keys[3]  = aes128_expand_key_round(round_keys[2],  _mm_aeskeygenassist_si128(round_keys[2],  0x04));
        round_keys[4]  = aes128_expand_key_round(round_keys[3],  _mm_aeskeygenassist_si128(round_keys[3],  0x08));
        round_keys[5]  = aes128_expand_key_round(round_keys[4],  _mm_aeskeygenassist_si128(round_keys[4],  0x10));
        round_keys[6]  = aes128_expand_key_round(round_keys[5],  _mm_aeskeygenassist_si128(round_keys[5],  0x20));
        round_keys[7]  = aes128_expand_key_round(round_keys[6],  _mm_aeskeygenassist_si128(round_keys[6],  0x40));
        round_keys[8]  = aes128_expand_key_round(round_keys[7],  _mm_aeskeygenassist_si128(round_keys[7],  0x80));
        round_keys[9]  = aes128_expand_key_round(round_keys[8],  _mm_aeskeygenassist_si128(round_keys[8],  0x1B));
        round_keys[10] = aes128_expand_key_round(round_keys[9],  _mm_aeskeygenassist_si128(round_keys[9],  0x36));
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

inline bool verify_env_consistency(const env_bundle_t& env)
{
    uint64_t expected = env.server_hmac ^ env.kernel_attestation ^
                        env.rdtsc_delta ^ env.process_state ^
                        env.filesystem_state;
    return env.aggregate == expected;
}

inline env_bundle_t collect_all_environmental()
{
    env_bundle_t env{};

    env.server_hmac        = collect_server_hmac_challenge();
    env.kernel_attestation = collect_kernel_attestation();
    env.rdtsc_delta        = collect_rdtsc_delta();
    env.process_state      = collect_process_state();
    env.filesystem_state   = collect_filesystem_state();

    env.aggregate = env.server_hmac ^ env.kernel_attestation ^
                    env.rdtsc_delta ^ env.process_state ^
                    env.filesystem_state;

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

}
}
