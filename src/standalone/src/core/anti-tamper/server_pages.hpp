#pragma once

#include <windows.h>
#include <bcrypt.h>
#include <intrin.h>
#include <nmmintrin.h>

#include <atomic>
#include <chrono>
#include <cstdint>
#include <cstring>
#include <mutex>
#include <string>
#include <unordered_map>
#include <vector>

#include "state.hpp"
#include "integrity.hpp"
#include "enforcement.hpp"
#include "webhook.hpp"
#include "../standalone_driver.hpp"
#include "../standalone_license.hpp"
#include "../../../../../libs/cpp-httplib/httplib.h"
#include "../../../../../libs/nlohmann/json.hpp"

namespace anti_tamper {
namespace server_pages {

namespace detail {

    constexpr uint32_t PAGE_SIZE = 4096;
    constexpr int64_t  PAGE_TTL_MS = 30000;
    constexpr uint32_t MAX_CACHED_PAGES = 64;
    constexpr uint32_t FETCH_TIMEOUT_SEC = 10;
    constexpr uint32_t SCRUB_PASSES = 3;

    struct cached_page_t
    {
        uint32_t page_index;
        uint8_t* mapped_addr;
        uint32_t mapped_size;
        int64_t  fetch_time_ms;
        uint64_t integrity_hash;
        DWORD    old_protect;
        bool     resident;
        uint64_t epoch;
    };

    inline std::mutex& page_mtx()
    {
        static std::mutex m;
        return m;
    }

    inline std::unordered_map<uint32_t, cached_page_t>& page_cache()
    {
        static std::unordered_map<uint32_t, cached_page_t> c;
        return c;
    }

    inline std::atomic<bool>& initialized()
    {
        static std::atomic<bool> a{false};
        return a;
    }

    inline std::atomic<uint64_t>& current_epoch()
    {
        static std::atomic<uint64_t> e{0};
        return e;
    }

    inline std::string& server_url()
    {
        static std::string u;
        return u;
    }

    inline uint32_t& total_pages()
    {
        static uint32_t t = 0;
        return t;
    }

    inline uint64_t& blob_size()
    {
        static uint64_t s = 0;
        return s;
    }

    inline int64_t now_ms()
    {
        return std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::steady_clock::now().time_since_epoch()).count();
    }

    inline uint64_t compute_page_hash(const uint8_t* data, uint32_t size)
    {
        return integrity::siphash::hash(data, size,
            0xA1DAC0DE7E57FA11ULL, 0x3B9ACA00DEADBEEFULL);
    }

    inline std::string get_api_host()
    {
#ifdef AIDA_LOCAL_LICENSE_SERVER
        return "http://localhost:3000";
#else
        return "https://aidapro.net";
#endif
    }

    inline void scrub_page(cached_page_t& page)
    {
        if (!page.mapped_addr || !page.resident) return;

        DWORD old_prot;
        VirtualProtect(page.mapped_addr, page.mapped_size, PAGE_READWRITE, &old_prot);

        for (uint32_t pass = 0; pass < SCRUB_PASSES; ++pass)
        {
            uint64_t pattern = __rdtsc() ^ (pass * 0x9E3779B97F4A7C15ULL);
            auto* p64 = reinterpret_cast<uint64_t*>(page.mapped_addr);
            for (uint32_t i = 0; i < page.mapped_size / 8; ++i)
            {
                p64[i] = pattern;
                pattern = _rotl64(pattern, 7) ^ p64[i];
            }
            _mm_mfence();
        }

        SecureZeroMemory(page.mapped_addr, page.mapped_size);
        VirtualProtect(page.mapped_addr, page.mapped_size, PAGE_NOACCESS, &old_prot);
        page.resident = false;
        page.integrity_hash = 0;
    }

    inline bool hex_decode(const std::string& hex, uint8_t* out, size_t out_len)
    {
        if (hex.size() != out_len * 2) return false;
        for (size_t i = 0; i < out_len; ++i)
        {
            auto nibble = [](char c) -> int {
                if (c >= '0' && c <= '9') return c - '0';
                if (c >= 'a' && c <= 'f') return c - 'a' + 10;
                if (c >= 'A' && c <= 'F') return c - 'A' + 10;
                return -1;
            };
            int hi = nibble(hex[i * 2]);
            int lo = nibble(hex[i * 2 + 1]);
            if (hi < 0 || lo < 0) return false;
            out[i] = static_cast<uint8_t>((hi << 4) | lo);
        }
        return true;
    }

    inline std::vector<uint8_t> base64_decode(const std::string& encoded)
    {
        static const uint8_t table[256] = {
            64,64,64,64,64,64,64,64,64,64,64,64,64,64,64,64,
            64,64,64,64,64,64,64,64,64,64,64,64,64,64,64,64,
            64,64,64,64,64,64,64,64,64,64,64,62,64,64,64,63,
            52,53,54,55,56,57,58,59,60,61,64,64,64,64,64,64,
            64, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9,10,11,12,13,14,
            15,16,17,18,19,20,21,22,23,24,25,64,64,64,64,64,
            64,26,27,28,29,30,31,32,33,34,35,36,37,38,39,40,
            41,42,43,44,45,46,47,48,49,50,51,64,64,64,64,64,
            64,64,64,64,64,64,64,64,64,64,64,64,64,64,64,64,
            64,64,64,64,64,64,64,64,64,64,64,64,64,64,64,64,
            64,64,64,64,64,64,64,64,64,64,64,64,64,64,64,64,
            64,64,64,64,64,64,64,64,64,64,64,64,64,64,64,64,
            64,64,64,64,64,64,64,64,64,64,64,64,64,64,64,64,
            64,64,64,64,64,64,64,64,64,64,64,64,64,64,64,64,
            64,64,64,64,64,64,64,64,64,64,64,64,64,64,64,64,
            64,64,64,64,64,64,64,64,64,64,64,64,64,64,64,64,
        };

        std::vector<uint8_t> out;
        out.reserve((encoded.size() * 3) / 4);
        uint32_t accum = 0;
        int bits = 0;
        for (unsigned char c : encoded)
        {
            if (table[c] >= 64) continue;
            accum = (accum << 6) | table[c];
            bits += 6;
            if (bits >= 8)
            {
                bits -= 8;
                out.push_back(static_cast<uint8_t>((accum >> bits) & 0xFF));
            }
        }
        return out;
    }

    inline bool aes_gcm_decrypt(const uint8_t* ciphertext, uint32_t ct_len,
                                const uint8_t* key, uint32_t key_len,
                                const uint8_t* iv, uint32_t iv_len,
                                const uint8_t* auth_tag, uint32_t tag_len,
                                uint8_t* plaintext)
    {
        BCRYPT_ALG_HANDLE hAlg = nullptr;
        BCRYPT_KEY_HANDLE hKey = nullptr;
        bool ok = false;

        NTSTATUS st = BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_AES_ALGORITHM, nullptr, 0);
        if (!BCRYPT_SUCCESS(st) || !hAlg) return false;

        st = BCryptSetProperty(hAlg, BCRYPT_CHAINING_MODE,
            (PUCHAR)BCRYPT_CHAIN_MODE_GCM, sizeof(BCRYPT_CHAIN_MODE_GCM), 0);
        if (!BCRYPT_SUCCESS(st)) { BCryptCloseAlgorithmProvider(hAlg, 0); return false; }

        st = BCryptGenerateSymmetricKey(hAlg, &hKey, nullptr, 0,
            const_cast<PUCHAR>(key), key_len, 0);
        if (!BCRYPT_SUCCESS(st) || !hKey) { BCryptCloseAlgorithmProvider(hAlg, 0); return false; }

        BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO authInfo;
        BCRYPT_INIT_AUTH_MODE_INFO(authInfo);
        authInfo.pbNonce = const_cast<PUCHAR>(iv);
        authInfo.cbNonce = iv_len;
        authInfo.pbTag = const_cast<PUCHAR>(auth_tag);
        authInfo.cbTag = tag_len;

        ULONG result_len = 0;
        st = BCryptDecrypt(hKey, const_cast<PUCHAR>(ciphertext), ct_len,
            &authInfo, nullptr, 0, plaintext, ct_len, &result_len, 0);

        ok = BCRYPT_SUCCESS(st) && result_len == ct_len;

        BCryptDestroyKey(hKey);
        BCryptCloseAlgorithmProvider(hAlg, 0);
        return ok;
    }

    inline bool derive_page_key(uint32_t page_index,
                                const std::string& session_token,
                                const std::string& hwid,
                                int64_t issued_at,
                                uint8_t* out_key_32)
    {
        std::string master_secret;
        char* env_val = nullptr;
        size_t len = 0;
        if (_dupenv_s(&env_val, &len, "ARC_MASTER_SECRET") == 0 && env_val)
        {
            master_secret = env_val;
            free(env_val);
        }
        if (master_secret.size() < 32) return false;

        std::string data = "page|" + std::to_string(page_index) + "|"
                         + session_token + "|" + hwid + "|"
                         + std::to_string(issued_at);

        BCRYPT_ALG_HANDLE hAlg = nullptr;
        BCRYPT_HASH_HANDLE hHash = nullptr;

        NTSTATUS st = BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_SHA256_ALGORITHM,
            nullptr, BCRYPT_ALG_HANDLE_HMAC_FLAG);
        if (!BCRYPT_SUCCESS(st) || !hAlg) return false;

        st = BCryptCreateHash(hAlg, &hHash, nullptr, 0,
            reinterpret_cast<PUCHAR>(master_secret.data()),
            static_cast<ULONG>(master_secret.size()), 0);
        if (!BCRYPT_SUCCESS(st) || !hHash)
        {
            BCryptCloseAlgorithmProvider(hAlg, 0);
            return false;
        }

        st = BCryptHashData(hHash,
            reinterpret_cast<PUCHAR>(const_cast<char*>(data.data())),
            static_cast<ULONG>(data.size()), 0);
        if (!BCRYPT_SUCCESS(st))
        {
            BCryptDestroyHash(hHash);
            BCryptCloseAlgorithmProvider(hAlg, 0);
            return false;
        }

        st = BCryptFinishHash(hHash, out_key_32, 32, 0);
        bool ok = BCRYPT_SUCCESS(st);

        BCryptDestroyHash(hHash);
        BCryptCloseAlgorithmProvider(hAlg, 0);
        return ok;
    }

    inline bool fetch_page_from_server(uint32_t page_index,
                                       const std::string& license_key,
                                       const std::string& session_token,
                                       const std::string& hwid,
                                       int64_t issued_at,
                                       std::vector<uint8_t>& out_plaintext)
    {
        httplib::Client cli(get_api_host());
        cli.set_connection_timeout(FETCH_TIMEOUT_SEC);
        cli.set_read_timeout(FETCH_TIMEOUT_SEC);
        cli.set_write_timeout(FETCH_TIMEOUT_SEC);
        cli.set_keep_alive(false);
        cli.set_tcp_nodelay(true);
        cli.set_decompress(true);
        cli.set_follow_location(true);
        cli.enable_server_certificate_verification(false);

        nlohmann::json body;
        body["license_key"] = license_key;
        body["session_token"] = session_token;
        body["hwid"] = hwid;

        std::string path = "/api/download/arc/page/" + std::to_string(page_index);
        auto res = cli.Post(path, body.dump(), "application/json");
        if (!res || res->status != 200) return false;

        auto j = nlohmann::json::parse(res->body, nullptr, false);
        if (!j.is_object() || j.value("status", "") != "ok") return false;

        std::string data_b64 = j.value("data", "");
        std::string iv_hex = j.value("iv", "");
        std::string tag_hex = j.value("auth_tag", "");

        if (data_b64.empty() || iv_hex.size() != 24 || tag_hex.size() != 32)
            return false;

        auto ciphertext = base64_decode(data_b64);
        if (ciphertext.empty()) return false;

        uint8_t iv[12];
        uint8_t auth_tag[16];
        if (!hex_decode(iv_hex, iv, 12)) return false;
        if (!hex_decode(tag_hex, auth_tag, 16)) return false;

        uint8_t page_key[32];
        if (!derive_page_key(page_index, session_token, hwid, issued_at, page_key))
            return false;

        out_plaintext.resize(ciphertext.size());
        bool ok = aes_gcm_decrypt(ciphertext.data(), static_cast<uint32_t>(ciphertext.size()),
                                  page_key, 32, iv, 12, auth_tag, 16, out_plaintext.data());

        SecureZeroMemory(page_key, 32);
        if (!ok) out_plaintext.clear();
        return ok;
    }
}

inline bool initialize()
{
    if (detail::initialized().load()) return true;

    detail::server_url() = detail::get_api_host();
    detail::initialized().store(true);
    return true;
}

inline bool query_page_count(const std::string& license_key,
                             const std::string& session_token,
                             const std::string& hwid)
{
    httplib::Client cli(detail::get_api_host());
    cli.set_connection_timeout(detail::FETCH_TIMEOUT_SEC);
    cli.set_read_timeout(detail::FETCH_TIMEOUT_SEC);
    cli.set_keep_alive(false);
    cli.set_tcp_nodelay(true);
    cli.set_decompress(true);
    cli.set_follow_location(true);
    cli.enable_server_certificate_verification(false);

    nlohmann::json body;
    body["license_key"] = license_key;
    body["session_token"] = session_token;
    body["hwid"] = hwid;

    auto res = cli.Post("/api/download/arc/pages", body.dump(), "application/json");
    if (!res || res->status != 200) return false;

    auto j = nlohmann::json::parse(res->body, nullptr, false);
    if (!j.is_object() || j.value("status", "") != "ok") return false;

    detail::total_pages() = j.value("total_pages", 0u);
    detail::blob_size() = j.value("blob_size", 0ull);
    return detail::total_pages() > 0;
}

inline bool fetch_page(uint32_t page_index,
                       const std::string& license_key,
                       const std::string& session_token,
                       const std::string& hwid,
                       int64_t issued_at)
{
    if (!detail::initialized().load()) return false;

    std::lock_guard<std::mutex> lk(detail::page_mtx());

    auto& cache = detail::page_cache();
    auto it = cache.find(page_index);
    if (it != cache.end() && it->second.resident)
    {
        int64_t age = detail::now_ms() - it->second.fetch_time_ms;
        bool epoch_stale = it->second.epoch != detail::current_epoch().load();
        if (age < detail::PAGE_TTL_MS && !epoch_stale)
        {
            uint64_t live_hash = detail::compute_page_hash(
                it->second.mapped_addr, it->second.mapped_size);
            if (live_hash == it->second.integrity_hash)
                return true;

            webhook::send_debug_log("server_pages", "page_integrity_fail_" + std::to_string(page_index), true);
            detail::scrub_page(it->second);
            enforce_violation("server_page_tampered");
            return false;
        }

        detail::scrub_page(it->second);
        if (epoch_stale)
            webhook::send_debug_log("server_pages", "page_epoch_stale_" + std::to_string(page_index), false);
    }

    std::vector<uint8_t> plaintext;
    if (!detail::fetch_page_from_server(page_index, license_key, session_token,
                                         hwid, issued_at, plaintext))
        return false;

    uint32_t alloc_size = static_cast<uint32_t>(
        ((plaintext.size() + detail::PAGE_SIZE - 1) / detail::PAGE_SIZE) * detail::PAGE_SIZE);

    uint8_t* addr = nullptr;
    if (it != cache.end() && it->second.mapped_addr)
    {
        DWORD old_prot;
        VirtualProtect(it->second.mapped_addr, it->second.mapped_size,
                       PAGE_READWRITE, &old_prot);
        addr = it->second.mapped_addr;
        if (it->second.mapped_size < alloc_size)
        {
            VirtualFree(addr, 0, MEM_RELEASE);
            addr = nullptr;
        }
    }

    if (!addr)
    {
        addr = static_cast<uint8_t*>(VirtualAlloc(nullptr, alloc_size,
            MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE));
        if (!addr) return false;
    }

    memcpy(addr, plaintext.data(), plaintext.size());
    SecureZeroMemory(plaintext.data(), plaintext.size());

    if (plaintext.size() < alloc_size)
        memset(addr + plaintext.size(), 0xCC, alloc_size - plaintext.size());

    uint64_t hash = detail::compute_page_hash(addr, static_cast<uint32_t>(plaintext.size()));

    DWORD old_prot;
    VirtualProtect(addr, alloc_size, PAGE_EXECUTE_READ, &old_prot);
    FlushInstructionCache(GetCurrentProcess(), addr, alloc_size);

    detail::cached_page_t entry{};
    entry.page_index = page_index;
    entry.mapped_addr = addr;
    entry.mapped_size = alloc_size;
    entry.fetch_time_ms = detail::now_ms();
    entry.integrity_hash = hash;
    entry.old_protect = old_prot;
    entry.resident = true;
    entry.epoch = detail::current_epoch().load();

    cache[page_index] = entry;
    return true;
}

inline uint8_t* get_page_addr(uint32_t page_index)
{
    std::lock_guard<std::mutex> lk(detail::page_mtx());
    auto& cache = detail::page_cache();
    auto it = cache.find(page_index);
    if (it == cache.end() || !it->second.resident) return nullptr;

    int64_t age = detail::now_ms() - it->second.fetch_time_ms;
    if (age >= detail::PAGE_TTL_MS)
    {
        detail::scrub_page(it->second);
        return nullptr;
    }

    return it->second.mapped_addr;
}

inline void evict_expired()
{
    std::lock_guard<std::mutex> lk(detail::page_mtx());
    int64_t now = detail::now_ms();

    for (auto& [idx, page] : detail::page_cache())
    {
        if (page.resident && (now - page.fetch_time_ms) >= detail::PAGE_TTL_MS)
            detail::scrub_page(page);
    }
}

inline void evict_all()
{
    std::lock_guard<std::mutex> lk(detail::page_mtx());
    for (auto& [idx, page] : detail::page_cache())
    {
        if (page.resident)
            detail::scrub_page(page);
    }
}

inline void advance_epoch(uint64_t new_epoch)
{
    uint64_t old_epoch = detail::current_epoch().exchange(new_epoch);
    if (new_epoch != old_epoch)
    {
        evict_all();
        webhook::write_log("server_pages", ("epoch_advanced_" + std::to_string(new_epoch)).c_str());
    }
}

inline void force_scrub_all()
{
    std::lock_guard<std::mutex> lk(detail::page_mtx());
    for (auto& [idx, page] : detail::page_cache())
    {
        if (page.mapped_addr)
        {
            DWORD old_prot;
            VirtualProtect(page.mapped_addr, page.mapped_size, PAGE_READWRITE, &old_prot);

            for (uint32_t pass = 0; pass < detail::SCRUB_PASSES + 2; ++pass)
            {
                uint64_t pattern = __rdtsc() ^ (pass * 0xDEADCAFEBEEF0000ULL);
                auto* p64 = reinterpret_cast<volatile uint64_t*>(page.mapped_addr);
                for (uint32_t i = 0; i < page.mapped_size / 8; ++i)
                {
                    p64[i] = pattern;
                    pattern = _rotl64(pattern, 13) ^ (pattern >> 7);
                }
                _mm_mfence();
            }
            SecureZeroMemory(page.mapped_addr, page.mapped_size);
            VirtualProtect(page.mapped_addr, page.mapped_size, PAGE_NOACCESS, &old_prot);
            page.resident = false;
            page.integrity_hash = 0;
            page.epoch = 0;
        }
    }
    detail::current_epoch().store(0);
    webhook::write_log("server_pages", "force_scrub_complete");
}

typedef uint64_t (*page_func_t)(uint64_t arg0, uint64_t arg1, uint64_t arg2, uint64_t arg3);

inline uint64_t execute_page_function(uint32_t page_index, uint32_t offset,
                                       uint64_t a0, uint64_t a1, uint64_t a2, uint64_t a3)
{
    uint8_t* base = get_page_addr(page_index);
    if (!base)
    {
        enforce_violation("page_not_resident");
        return 0;
    }

    {
        std::lock_guard<std::mutex> lk(detail::page_mtx());
        auto& cache = detail::page_cache();
        auto it = cache.find(page_index);
        if (it == cache.end() || offset >= it->second.mapped_size)
        {
            enforce_violation("page_offset_oob");
            return 0;
        }

        uint64_t live_hash = detail::compute_page_hash(
            it->second.mapped_addr, it->second.mapped_size);
        if (live_hash != it->second.integrity_hash)
        {
            detail::scrub_page(it->second);
            enforce_violation("page_exec_integrity_fail");
            return 0;
        }
    }

    page_func_t fn = reinterpret_cast<page_func_t>(base + offset);
    return fn(a0, a1, a2, a3);
}

inline void shutdown()
{
    evict_all();

    std::lock_guard<std::mutex> lk(detail::page_mtx());
    for (auto& [idx, page] : detail::page_cache())
    {
        if (page.mapped_addr)
        {
            VirtualFree(page.mapped_addr, 0, MEM_RELEASE);
            page.mapped_addr = nullptr;
        }
    }
    detail::page_cache().clear();
    detail::initialized().store(false);
}

}
}
