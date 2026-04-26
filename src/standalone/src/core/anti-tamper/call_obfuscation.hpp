#pragma once

#include <windows.h>
#include <intrin.h>

#include <atomic>
#include <cstdint>
#include <cstring>

#include "integrity.hpp"
#include "obfuscation.hpp"

namespace anti_tamper {
namespace call_obfuscation {

namespace detail
{
    static constexpr uint32_t TABLE_SLOTS      = 64;


    static constexpr uint32_t PROLOGUE_CHECK   = 32;
    static constexpr uint64_t POISON_MARKER    = 0xDEAD'FACE'CAFE'B0BAULL;

    struct call_entry_t
    {
        uint64_t    encrypted_ptr;
        uint64_t    prologue_hash;
        uint32_t    rot_amount;
        uint32_t    slot_id;
    };

    inline call_entry_t  g_table[TABLE_SLOTS]  = {};
    inline uint64_t      g_session_key          = 0;
    inline uint64_t      g_secondary_key        = 0;
    inline std::atomic<bool> g_initialized{false};
    inline std::atomic<uint64_t> g_call_counter{0};


    __forceinline uint64_t derive_slot_key(uint32_t slot_id)
    {
        uint64_t k = g_session_key ^ (static_cast<uint64_t>(slot_id) * 0x9E3779B97F4A7C15ULL);
        k ^= k >> 33;
        k *= 0xFF51AFD7ED558CCDULL;
        k ^= k >> 33;
        k *= 0xC4CEB9FE1A85EC53ULL;
        k ^= k >> 33;
        return k;
    }

    __forceinline uint64_t rotl64(uint64_t x, uint32_t r) { return (x << r) | (x >> (64 - r)); }
    __forceinline uint64_t rotr64(uint64_t x, uint32_t r) { return (x >> r) | (x << (64 - r)); }

    __forceinline uint64_t hash_prologue(const void* func_addr)
    {
        const uint8_t* p = reinterpret_cast<const uint8_t*>(func_addr);

        __try {
            return integrity::siphash::hash(p, PROLOGUE_CHECK,
                g_session_key, g_secondary_key);
        }
        __except (EXCEPTION_EXECUTE_HANDLER) {
            return POISON_MARKER;
        }
    }

    __forceinline uint64_t encrypt_pointer(uintptr_t ptr, uint32_t slot_id)
    {
        uint64_t key = derive_slot_key(slot_id);
        uint32_t rot = static_cast<uint32_t>((key >> 7) % 63) + 1;
        uint64_t enc = static_cast<uint64_t>(ptr) ^ key;
        enc = rotl64(enc, rot);
        enc ^= g_secondary_key;
        return enc;
    }

    __forceinline uintptr_t decrypt_pointer(uint64_t enc, uint32_t slot_id)
    {
        uint64_t key = derive_slot_key(slot_id);
        uint32_t rot = static_cast<uint32_t>((key >> 7) % 63) + 1;
        enc ^= g_secondary_key;
        enc = rotr64(enc, rot);
        enc ^= key;
        return static_cast<uintptr_t>(enc);
    }
}

inline void initialize(uint64_t text_hash)
{
    if (detail::g_initialized.load()) return;

    int cpu[4];
    __cpuid(cpu, 1);
    uint64_t cpuid_entropy = static_cast<uint64_t>(cpu[0]) |
                             (static_cast<uint64_t>(cpu[2]) << 32);

    detail::g_session_key   = text_hash ^ __rdtsc() ^ cpuid_entropy;
    detail::g_secondary_key = integrity::siphash::hash(
        reinterpret_cast<const uint8_t*>(&detail::g_session_key),
        sizeof(detail::g_session_key),
        0x0706050403020100ULL, 0x0F0E0D0C0B0A0908ULL);

    memset(detail::g_table, 0, sizeof(detail::g_table));
    detail::g_initialized.store(true);
}

inline uint32_t register_target(void* func_addr)
{
    if (!detail::g_initialized.load()) return UINT32_MAX;

    for (uint32_t i = 0; i < detail::TABLE_SLOTS; ++i)
    {
        if (detail::g_table[i].encrypted_ptr == 0)
        {
            uintptr_t raw = reinterpret_cast<uintptr_t>(func_addr);
            detail::g_table[i].slot_id       = i;
            detail::g_table[i].rot_amount    = static_cast<uint32_t>((detail::derive_slot_key(i) >> 7) % 63) + 1;
            detail::g_table[i].prologue_hash = detail::hash_prologue(func_addr);
            detail::g_table[i].encrypted_ptr = detail::encrypt_pointer(raw, i);
            return i;
        }
    }
    return UINT32_MAX;
}

__forceinline void* resolve(uint32_t slot_id)
{
    if (slot_id >= detail::TABLE_SLOTS) return nullptr;

    const auto& entry = detail::g_table[slot_id];
    if (entry.encrypted_ptr == 0) return nullptr;

    uintptr_t resolved = detail::decrypt_pointer(entry.encrypted_ptr, slot_id);
    void* func = reinterpret_cast<void*>(resolved);

    uint64_t current_hash = detail::hash_prologue(func);
    if (current_hash != entry.prologue_hash)
    {
        return nullptr;
    }

    detail::g_call_counter.fetch_add(1, std::memory_order_relaxed);
    return func;
}

template <typename Ret, typename... Args>
__forceinline Ret protected_call(uint32_t slot_id, Args... args)
{
    using fn_t = Ret(__cdecl*)(Args...);
    void* target = resolve(slot_id);

    if (!target)
    {
        if constexpr (std::is_pointer_v<Ret>)
            return nullptr;
        else if constexpr (std::is_integral_v<Ret>)
            return static_cast<Ret>(0);
        else if constexpr (std::is_void_v<Ret>)
            return;
        else
            return Ret{};
    }

    return reinterpret_cast<fn_t>(target)(args...);
}


inline void re_encrypt_all()
{
    if (!detail::g_initialized.load()) return;

    int cpu[4];
    __cpuid(cpu, 7);
    uint64_t fresh_entropy = __rdtsc() ^ static_cast<uint64_t>(cpu[1]);

    uint64_t old_session    = detail::g_session_key;
    uint64_t old_secondary  = detail::g_secondary_key;

    uintptr_t resolved[detail::TABLE_SLOTS];
    for (uint32_t i = 0; i < detail::TABLE_SLOTS; ++i)
    {
        if (detail::g_table[i].encrypted_ptr != 0)
            resolved[i] = detail::decrypt_pointer(detail::g_table[i].encrypted_ptr, i);
        else
            resolved[i] = 0;
    }

    detail::g_session_key   = old_session ^ fresh_entropy;
    detail::g_secondary_key = integrity::siphash::hash(
        reinterpret_cast<const uint8_t*>(&detail::g_session_key),
        sizeof(detail::g_session_key),
        0x0706050403020100ULL, 0x0F0E0D0C0B0A0908ULL);

    for (uint32_t i = 0; i < detail::TABLE_SLOTS; ++i)
    {
        if (resolved[i] != 0)
        {
            detail::g_table[i].encrypted_ptr = detail::encrypt_pointer(resolved[i], i);
            detail::g_table[i].rot_amount    = static_cast<uint32_t>((detail::derive_slot_key(i) >> 7) % 63) + 1;
        }
    }

    SecureZeroMemory(resolved, sizeof(resolved));
}

inline bool verify_table_integrity()
{
    if (!detail::g_initialized.load()) return false;

    for (uint32_t i = 0; i < detail::TABLE_SLOTS; ++i)
    {
        if (detail::g_table[i].encrypted_ptr == 0) continue;

        uintptr_t ptr = detail::decrypt_pointer(detail::g_table[i].encrypted_ptr, i);
        void* func = reinterpret_cast<void*>(ptr);

        uint64_t current_hash = detail::hash_prologue(func);
        if (current_hash != detail::g_table[i].prologue_hash)
            return false;
    }
    return true;
}

}
}
