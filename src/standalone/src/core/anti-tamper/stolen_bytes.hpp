#pragma once

#include <windows.h>
#include <intrin.h>

#include <cstdint>
#include <cstring>
#include <vector>

#include "integrity.hpp"

namespace anti_tamper {
namespace stolen_bytes {

namespace detail {

    static constexpr uint32_t MAX_STOLEN = 32;
    static constexpr uint32_t MAX_ENTRIES = 64;

    struct stolen_entry_t
    {
        uint64_t original_addr;
        uint8_t  encrypted_prologue[MAX_STOLEN];
        uint32_t prologue_len;
        uint64_t trampoline_addr;
        uint64_t encryption_key;
    };

    struct stolen_state_t
    {
        stolen_entry_t entries[MAX_ENTRIES];
        uint32_t count;
        void* trampoline_page;
        uint32_t trampoline_offset;
        uint64_t session_key[2];
        bool initialized;
    };

    inline stolen_state_t& get_state()
    {
        static stolen_state_t s{};
        return s;
    }

    inline uint32_t compute_prologue_length(const uint8_t* code, uint32_t min_bytes)
    {
        uint32_t len = 0;
        while (len < min_bytes && len < MAX_STOLEN)
        {
            uint8_t b = code[len];

            if (b == 0xCC || b == 0xC3)
                break;

            if (b == 0x90) { len += 1; continue; }

            if ((b & 0xF0) == 0x50 || (b & 0xF0) == 0x58)
            {
                len += 1;
                continue;
            }

            if (b == 0x48 || b == 0x4C || b == 0x49 || b == 0x4D)
            {
                uint8_t next = code[len + 1];
                if (next == 0x89 || next == 0x8B)
                {
                    uint8_t modrm = code[len + 2];
                    uint8_t mod = (modrm >> 6) & 3;
                    uint8_t rm = modrm & 7;
                    len += 3;
                    if (mod == 1) len += 1;
                    else if (mod == 2) len += 4;
                    if (rm == 4 && mod != 3) len += 1;
                    continue;
                }
                if (next == 0x83)
                {
                    uint8_t modrm = code[len + 2];
                    len += 4;
                    uint8_t rm = modrm & 7;
                    if (rm == 4) len += 1;
                    continue;
                }
                if (next == 0x8D)
                {
                    uint8_t modrm = code[len + 2];
                    uint8_t mod = (modrm >> 6) & 3;
                    len += 3;
                    if (mod == 1) len += 1;
                    else if (mod == 2) len += 4;
                    else if (mod == 0 && (modrm & 7) == 5) len += 4;
                    continue;
                }
            }

            if (b == 0x55 || b == 0x56 || b == 0x57)
            {
                len += 1;
                continue;
            }

            if (b == 0x41)
            {
                len += 1;
                continue;
            }

            len += 1;
        }

        return len;
    }

    inline void encrypt_prologue(uint8_t* dst, const uint8_t* src, uint32_t len, uint64_t key)
    {
        uint64_t rolling = key;
        for (uint32_t i = 0; i < len; ++i)
        {
            dst[i] = src[i] ^ static_cast<uint8_t>(rolling);
            rolling ^= rolling << 13;
            rolling ^= rolling >> 7;
            rolling ^= rolling << 17;
        }
    }

    inline void decrypt_prologue(uint8_t* dst, const uint8_t* src, uint32_t len, uint64_t key)
    {
        encrypt_prologue(dst, src, len, key);
    }

}

inline bool initialize()
{
    auto& s = detail::get_state();
    if (s.initialized) return true;

    integrity::get_session_keys(s.session_key[0], s.session_key[1]);

    s.trampoline_page = VirtualAlloc(nullptr, 4096,
        MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!s.trampoline_page) return false;

    s.trampoline_offset = 0;
    s.count = 0;
    s.initialized = true;
    return true;
}

inline bool steal_function_prologue(void* target_func)
{
    auto& s = detail::get_state();
    if (!s.initialized || s.count >= detail::MAX_ENTRIES)
        return false;

    auto* code = static_cast<uint8_t*>(target_func);
    uint32_t steal_len = detail::compute_prologue_length(code, 14);
    if (steal_len < 5 || steal_len > detail::MAX_STOLEN)
        return false;

    if (s.trampoline_offset + steal_len + 14 > 4096)
        return false;

    auto& entry = s.entries[s.count];
    entry.original_addr = reinterpret_cast<uint64_t>(code);
    entry.prologue_len = steal_len;

    uint8_t buf[16];
    uint64_t addr_val = reinterpret_cast<uint64_t>(code);
    memcpy(buf, &addr_val, 8);
    memcpy(buf + 8, &s.session_key[0], 8);
    entry.encryption_key = integrity::siphash::hash(
        buf, 16, s.session_key[0], s.session_key[1]);

    detail::encrypt_prologue(entry.encrypted_prologue, code, steal_len, entry.encryption_key);

    auto* tramp = static_cast<uint8_t*>(s.trampoline_page) + s.trampoline_offset;
    entry.trampoline_addr = reinterpret_cast<uint64_t>(tramp);

    memcpy(tramp, code, steal_len);

    uint64_t return_addr = reinterpret_cast<uint64_t>(code) + steal_len;
    tramp[steal_len]     = 0xFF;
    tramp[steal_len + 1] = 0x25;
    *reinterpret_cast<uint32_t*>(tramp + steal_len + 2) = 0;
    *reinterpret_cast<uint64_t*>(tramp + steal_len + 6) = return_addr;

    s.trampoline_offset += steal_len + 14;

    DWORD old_prot;
    VirtualProtect(code, steal_len, PAGE_EXECUTE_READWRITE, &old_prot);

    code[0] = 0xFF;
    code[1] = 0x25;
    *reinterpret_cast<uint32_t*>(code + 2) = 0;
    *reinterpret_cast<uint64_t*>(code + 6) = entry.trampoline_addr;

    for (uint32_t i = 14; i < steal_len; ++i)
        code[i] = 0xCC;

    VirtualProtect(code, steal_len, old_prot, &old_prot);
    FlushInstructionCache(GetCurrentProcess(), code, steal_len);

    ++s.count;
    return true;
}

inline bool verify_stolen_bytes()
{
    auto& s = detail::get_state();
    if (!s.initialized) return true;

    for (uint32_t i = 0; i < s.count; ++i)
    {
        auto& entry = s.entries[i];
        auto* tramp = reinterpret_cast<const uint8_t*>(entry.trampoline_addr);

        uint8_t decrypted[detail::MAX_STOLEN];
        detail::decrypt_prologue(decrypted, entry.encrypted_prologue,
                                  entry.prologue_len, entry.encryption_key);

        if (memcmp(tramp, decrypted, entry.prologue_len) != 0)
            return false;

        auto* original = reinterpret_cast<const uint8_t*>(entry.original_addr);
        if (original[0] != 0xFF || original[1] != 0x25)
            return false;
    }

    return true;
}

inline void shutdown()
{
    auto& s = detail::get_state();
    if (s.trampoline_page)
    {
        volatile uint8_t* p = static_cast<volatile uint8_t*>(s.trampoline_page);
        for (uint32_t i = 0; i < 4096; ++i) p[i] = 0xCC;
        VirtualFree(s.trampoline_page, 0, MEM_RELEASE);
        s.trampoline_page = nullptr;
    }
    s.initialized = false;
}

}
}
