#pragma once

#include <windows.h>
#include <psapi.h>
#include <bcrypt.h>
#include <intrin.h>

#include <cstdint>
#include <cstring>
#include <vector>

#include "state.hpp"

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

}

namespace sha256 {

    inline bool hash(const void* data, size_t size, uint8_t out[32])
    {
        BCRYPT_ALG_HANDLE hAlg = nullptr;
        BCRYPT_HASH_HANDLE hHash = nullptr;
        bool ok = false;

        if (BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_SHA256_ALGORITHM,
                                        nullptr, 0) != 0)
            return false;

        if (BCryptCreateHash(hAlg, &hHash, nullptr, 0, nullptr, 0, 0) != 0)
        {
            BCryptCloseAlgorithmProvider(hAlg, 0);
            return false;
        }

        if (BCryptHashData(hHash, const_cast<PUCHAR>(
                static_cast<const uint8_t*>(data)), static_cast<ULONG>(size), 0) == 0)
        {
            ok = (BCryptFinishHash(hHash, out, 32, 0) == 0);
        }

        BCryptDestroyHash(hHash);
        BCryptCloseAlgorithmProvider(hAlg, 0);
        return ok;
    }

}

namespace detail {

    inline uint64_t s_siphash_k0 = 0;
    inline uint64_t s_siphash_k1 = 0;
    inline bool     s_keys_initialized = false;

    inline void derive_session_keys(const uint8_t* text_start, size_t text_size)
    {
        size_t prefix_len = (text_size > 256) ? 256 : text_size;
        uint8_t sha[32] = {};
        sha256::hash(text_start, prefix_len, sha);

        uint64_t sha_lo, sha_hi;
        memcpy(&sha_lo, sha, 8);
        memcpy(&sha_hi, sha + 8, 8);

        int cpu_info[4] = {};
        __cpuid(cpu_info, 1);
        uint64_t cpuid_val = static_cast<uint64_t>(cpu_info[0]) |
                             (static_cast<uint64_t>(cpu_info[3]) << 32);

        uint64_t tsc = __rdtsc();

        s_siphash_k0 = sha_lo ^ cpuid_val ^ tsc;
        s_siphash_k1 = sha_hi ^ (cpuid_val >> 17) ^ (tsc << 23);
        s_keys_initialized = true;
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

        return siphash::hash(func_start, check_size,
                             0xDEADBEEFCAFEBABEULL, 0x0123456789ABCDEFULL);
    }

    inline uint64_t s_self_hash = 0;

}

__forceinline uint64_t hash_memory(const void* data, size_t size)
{
    return siphash::hash(static_cast<const uint8_t*>(data), size,
                         detail::s_siphash_k0, detail::s_siphash_k1);
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

    while (offset < snap.text_size)
    {
        uint32_t this_block = (snap.text_size - offset < BLOCK_SIZE)
            ? (snap.text_size - offset) : BLOCK_SIZE;

        const auto* block_ptr = reinterpret_cast<const uint8_t*>(snap.text_base + offset);

        uint8_t buf[4096 + 8];
        memcpy(buf, block_ptr, this_block);
        memcpy(buf + this_block, &prev_hash, 8);

        uint64_t h = siphash::hash(buf, this_block + 8,
                                   detail::s_siphash_k0, detail::s_siphash_k1);

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

    uint64_t prev_hash = 0;
    for (const auto& block : chain)
    {
        const auto* block_ptr = reinterpret_cast<const uint8_t*>(block.block_base);

        uint8_t buf[4096 + 8];
        memcpy(buf, block_ptr, block.block_size);
        memcpy(buf + block.block_size, &prev_hash, 8);

        uint64_t h = siphash::hash(buf, block.block_size + 8,
                                   detail::s_siphash_k0, detail::s_siphash_k1);

        if (h != block.chained_hash)
            return false;

        prev_hash = h;
    }
    return true;
}

inline bool verify_self_hash()
{
    if (detail::s_self_hash == 0) return true;
    return detail::self_hash_siphash_impl() == detail::s_self_hash;
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

    detail::s_self_hash = detail::self_hash_siphash_impl();

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

inline void get_session_keys(uint64_t& k0, uint64_t& k1)
{
    k0 = detail::s_siphash_k0;
    k1 = detail::s_siphash_k1;
}

}
}
