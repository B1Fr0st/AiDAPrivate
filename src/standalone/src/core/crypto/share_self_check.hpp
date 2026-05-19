#pragma once

#include <Windows.h>
#include <bcrypt.h>
#include <cstdint>
#include <cstddef>

namespace aida::pubkeys::detail::share_self_check
{
    inline bool compute_self_fingerprint(uintptr_t code_addr, size_t length, uint8_t out_hash[32])
    {
        for (size_t i = 0; i < 32; ++i) out_hash[i] = 0u;
        if (code_addr == 0u || length == 0u) return false;
        MEMORY_BASIC_INFORMATION mbi{};
        if (VirtualQuery(reinterpret_cast<LPCVOID>(code_addr), &mbi, sizeof(mbi)) == 0) return false;
        if (mbi.State != MEM_COMMIT) return false;
        const DWORD readable_mask = PAGE_READONLY | PAGE_READWRITE | PAGE_WRITECOPY
            | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY;
        if ((mbi.Protect & readable_mask) == 0u) return false;
        uintptr_t region_end = reinterpret_cast<uintptr_t>(mbi.BaseAddress) + mbi.RegionSize;
        if (code_addr + length > region_end) return false;
        BCRYPT_ALG_HANDLE alg = nullptr;
        if (BCryptOpenAlgorithmProvider(&alg, BCRYPT_SHA256_ALGORITHM, nullptr, 0) != 0) return false;
        BCRYPT_HASH_HANDLE h = nullptr;
        if (BCryptCreateHash(alg, &h, nullptr, 0, nullptr, 0, 0) != 0)
        {
            BCryptCloseAlgorithmProvider(alg, 0);
            return false;
        }
        bool ok = false;
        const PUCHAR data_ptr = reinterpret_cast<PUCHAR>(code_addr);
        if (BCryptHashData(h, data_ptr, static_cast<ULONG>(length), 0) == 0)
        {
            ok = BCryptFinishHash(h, out_hash, 32u, 0) == 0;
        }
        BCryptDestroyHash(h);
        BCryptCloseAlgorithmProvider(alg, 0);
        if (!ok)
        {
            for (size_t i = 0; i < 32; ++i) out_hash[i] = 0u;
            return false;
        }
        return true;
    }

    inline bool constant_time_equal(const uint8_t* a, const uint8_t* b, size_t n)
    {
        if (a == nullptr || b == nullptr) return false;
        uint8_t diff = 0u;
        for (size_t i = 0; i < n; ++i)
        {
            diff = static_cast<uint8_t>(diff | static_cast<uint8_t>(a[i] ^ b[i]));
        }
        return diff == 0u;
    }

    inline bool sentinel_is_zero(const volatile uint8_t* fp, size_t n)
    {
        uint8_t acc = 0u;
        for (size_t i = 0; i < n; ++i)
        {
            acc = static_cast<uint8_t>(acc | static_cast<uint8_t>(fp[i]));
        }
        return acc == 0u;
    }
}
