#pragma once

#include <windows.h>
#include <bcrypt.h>
#include <intrin.h>

#include <atomic>
#include <cstdint>
#include <cstring>
#include <mutex>
#include <vector>

#pragma comment(lib, "bcrypt.lib")

namespace anti_tamper {
namespace heap_encrypt {

struct secure_heap_header_t {
    uint32_t magic;
    uint32_t plaintext_size;
    uint32_t alloc_size;
    uint32_t key_index;
    uint64_t key_material;
    uint8_t  iv[12];
    uint8_t  tag[16];
};

constexpr uint32_t SHEAP_MAGIC = 0x53484550u;
constexpr uint32_t SHEAP_MAX_PLAINTEXT = 4096;

inline std::mutex& heap_mtx()
{
    static std::mutex m;
    return m;
}

inline std::vector<secure_heap_header_t*>& heap_allocations()
{
    static std::vector<secure_heap_header_t*> v;
    return v;
}

inline uint64_t derive_key_material()
{
    uint64_t tsc = __rdtsc();
    uint64_t tid = static_cast<uint64_t>(GetCurrentThreadId());
    uint64_t pid = static_cast<uint64_t>(GetCurrentProcessId());
    uint64_t mod = reinterpret_cast<uint64_t>(GetModuleHandleW(nullptr));
    return tsc ^ (tid << 32) ^ (pid << 16) ^ (mod & 0xFFFF);
}

inline bool aes_gcm_encrypt_simple(
    const uint8_t* plaintext, uint32_t pt_len,
    uint64_t key_material, uint8_t* iv,
    uint8_t* ciphertext, uint8_t* tag)
{
    if (!plaintext || pt_len == 0 || !iv || !ciphertext || !tag) return false;

    BCRYPT_ALG_HANDLE alg = nullptr;
    BCRYPT_KEY_HANDLE key = nullptr;
    bool encrypted = false;
    uint8_t key_bytes[32]{};
    memcpy(key_bytes, &key_material, sizeof(key_material));
    memcpy(key_bytes + 8, &key_material, sizeof(key_material));
    memcpy(key_bytes + 16, iv, 8);
    uint64_t pid = static_cast<uint64_t>(GetCurrentProcessId());
    memcpy(key_bytes + 24, &pid, sizeof(pid));

    if (BCryptOpenAlgorithmProvider(&alg, BCRYPT_AES_ALGORITHM, nullptr, 0) >= 0) {
        wchar_t chaining_mode[] = BCRYPT_CHAIN_MODE_GCM;
        if (BCryptSetProperty(alg, BCRYPT_CHAINING_MODE,
            reinterpret_cast<PUCHAR>(chaining_mode),
            static_cast<ULONG>(sizeof(chaining_mode)), 0) >= 0 &&
            BCryptGenerateSymmetricKey(alg, &key, nullptr, 0,
                key_bytes, static_cast<ULONG>(sizeof(key_bytes)), 0) >= 0) {
            BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO auth_info{};
            BCRYPT_INIT_AUTH_MODE_INFO(auth_info);
            auth_info.pbNonce = iv;
            auth_info.cbNonce = 12;
            auth_info.pbTag = tag;
            auth_info.cbTag = 16;

            ULONG cipher_len = 0;
            const NTSTATUS status = BCryptEncrypt(key,
                const_cast<PUCHAR>(plaintext), pt_len,
                &auth_info, nullptr, 0,
                ciphertext, pt_len, &cipher_len, 0);
            encrypted = status >= 0 && cipher_len == pt_len;
        }
        if (key) BCryptDestroyKey(key);
        BCryptCloseAlgorithmProvider(alg, 0);
    }

    SecureZeroMemory(key_bytes, sizeof(key_bytes));
    return encrypted;
}

inline bool aes_gcm_decrypt_simple(
    const uint8_t* ciphertext, uint32_t ct_len,
    uint64_t key_material, uint8_t* iv, uint8_t* tag,
    uint8_t* plaintext)
{
    if (!ciphertext || ct_len == 0 || !iv || !tag || !plaintext) return false;

    BCRYPT_ALG_HANDLE alg = nullptr;
    BCRYPT_KEY_HANDLE key = nullptr;
    bool decrypted = false;
    uint8_t key_bytes[32]{};
    memcpy(key_bytes, &key_material, sizeof(key_material));
    memcpy(key_bytes + 8, &key_material, sizeof(key_material));
    memcpy(key_bytes + 16, iv, 8);
    uint64_t pid = static_cast<uint64_t>(GetCurrentProcessId());
    memcpy(key_bytes + 24, &pid, sizeof(pid));

    if (BCryptOpenAlgorithmProvider(&alg, BCRYPT_AES_ALGORITHM, nullptr, 0) >= 0) {
        wchar_t chaining_mode[] = BCRYPT_CHAIN_MODE_GCM;
        if (BCryptSetProperty(alg, BCRYPT_CHAINING_MODE,
            reinterpret_cast<PUCHAR>(chaining_mode),
            static_cast<ULONG>(sizeof(chaining_mode)), 0) >= 0 &&
            BCryptGenerateSymmetricKey(alg, &key, nullptr, 0,
                key_bytes, static_cast<ULONG>(sizeof(key_bytes)), 0) >= 0) {
            BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO auth_info{};
            BCRYPT_INIT_AUTH_MODE_INFO(auth_info);
            auth_info.pbNonce = iv;
            auth_info.cbNonce = 12;
            auth_info.pbTag = tag;
            auth_info.cbTag = 16;

            ULONG plain_len = 0;
            const NTSTATUS status = BCryptDecrypt(key,
                const_cast<PUCHAR>(ciphertext), ct_len,
                &auth_info, nullptr, 0,
                plaintext, ct_len, &plain_len, 0);
            decrypted = status >= 0 && plain_len == ct_len;
        }
        if (key) BCryptDestroyKey(key);
        BCryptCloseAlgorithmProvider(alg, 0);
    }

    SecureZeroMemory(key_bytes, sizeof(key_bytes));
    return decrypted;
}

inline uint32_t round_up_16(uint32_t v)
{
    return ((v + 15u) / 16u) * 16u;
}

inline secure_heap_header_t* secure_alloc(uint32_t size)
{
    if (size == 0 || size > SHEAP_MAX_PLAINTEXT) return nullptr;

    uint32_t padded_size = round_up_16(size);
    uint32_t total_size = static_cast<uint32_t>(sizeof(secure_heap_header_t)) + padded_size;

    auto* header = reinterpret_cast<secure_heap_header_t*>(
        HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, total_size));
    if (!header) return nullptr;

    header->magic = SHEAP_MAGIC;
    header->plaintext_size = size;
    header->alloc_size = total_size;
    header->key_index = 0;
    header->key_material = derive_key_material();

    if (BCryptGenRandom(nullptr, header->iv, 12, BCRYPT_USE_SYSTEM_PREFERRED_RNG) < 0) {
        SecureZeroMemory(header, total_size);
        HeapFree(GetProcessHeap(), 0, header);
        return nullptr;
    }

    uint8_t* ciphertext = reinterpret_cast<uint8_t*>(header + 1);
    std::vector<uint8_t> plaintext(size, 0);

    if (!aes_gcm_encrypt_simple(plaintext.data(), size,
        header->key_material, header->iv, ciphertext, header->tag)) {
        SecureZeroMemory(header, total_size);
        HeapFree(GetProcessHeap(), 0, header);
        return nullptr;
    }

    {
        std::lock_guard<std::mutex> lk(heap_mtx());
        heap_allocations().push_back(header);
    }

    return header;
}

struct secure_accessor_t {
    uint8_t buffer[SHEAP_MAX_PLAINTEXT];
    uint32_t size;
    secure_heap_header_t* header;
    bool modified;

    explicit secure_accessor_t(secure_heap_header_t* h)
        : buffer{}, size(0), header(h), modified(false)
    {
        if (!header || header->magic != SHEAP_MAGIC) {
            header = nullptr;
            return;
        }

        size = header->plaintext_size;
        if (size > SHEAP_MAX_PLAINTEXT) {
            header = nullptr;
            return;
        }

        uint8_t* ciphertext = reinterpret_cast<uint8_t*>(header + 1);
        if (!aes_gcm_decrypt_simple(ciphertext, size,
            header->key_material, header->iv, header->tag, buffer)) {
            SecureZeroMemory(buffer, sizeof(buffer));
            size = 0;
            header = nullptr;
        }
    }

    ~secure_accessor_t()
    {
        if (!header) return;

        if (modified) {
            uint8_t* ciphertext = reinterpret_cast<uint8_t*>(header + 1);
            if (BCryptGenRandom(nullptr, header->iv, 12,
                BCRYPT_USE_SYSTEM_PREFERRED_RNG) < 0 ||
                !aes_gcm_encrypt_simple(buffer, size,
                    header->key_material, header->iv, ciphertext, header->tag)) {
                SecureZeroMemory(buffer, SHEAP_MAX_PLAINTEXT);
                __fastfail(FAST_FAIL_FATAL_APP_EXIT);
            }
        }

        SecureZeroMemory(buffer, SHEAP_MAX_PLAINTEXT);
    }

    void* data() { return header ? buffer : nullptr; }
    uint32_t data_size() const { return header ? size : 0; }
    void mark_modified() { modified = true; }
};

inline void secure_free(secure_heap_header_t* header)
{
    if (!header) return;

    {
        std::lock_guard<std::mutex> lk(heap_mtx());
        auto& v = heap_allocations();
        for (auto it = v.begin(); it != v.end(); ++it) {
            if (*it == header) {
                v.erase(it);
                break;
            }
        }
    }

    SecureZeroMemory(header, header->alloc_size);
    HeapFree(GetProcessHeap(), 0, header);
}

inline void secure_reencrypt_all()
{
    std::lock_guard<std::mutex> lk(heap_mtx());

    for (auto* header : heap_allocations()) {
        if (!header || header->magic != SHEAP_MAGIC) continue;

        secure_accessor_t acc(header);
        if (!acc.header) __fastfail(FAST_FAIL_FATAL_APP_EXIT);

        uint8_t* ciphertext = reinterpret_cast<uint8_t*>(header + 1);
        header->key_material = derive_key_material();
        if (BCryptGenRandom(nullptr, header->iv, 12,
            BCRYPT_USE_SYSTEM_PREFERRED_RNG) < 0 ||
            !aes_gcm_encrypt_simple(
            reinterpret_cast<const uint8_t*>(acc.data()),
            acc.data_size(),
            header->key_material, header->iv,
            ciphertext, header->tag)) {
            __fastfail(FAST_FAIL_FATAL_APP_EXIT);
        }
    }
}

}}
