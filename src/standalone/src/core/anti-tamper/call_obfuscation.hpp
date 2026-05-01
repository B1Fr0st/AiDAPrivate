#pragma once

#include <windows.h>
#include <bcrypt.h>
#include <intrin.h>

#include <atomic>
#include <cstdint>
#include <cstring>

#include "integrity.hpp"
#include "obfuscation.hpp"

#pragma comment(lib, "bcrypt.lib")

extern "C" uint64_t aida_read_ssp(void);

namespace anti_tamper {
namespace call_obfuscation {

namespace detail
{
    static constexpr uint32_t TABLE_SLOTS      = 64;

    static constexpr uint32_t PROLOGUE_CHECK   = 32;
    static constexpr uint64_t POISON_MARKER    = 0xDEAD'FACE'CAFE'B0BAULL;

    struct call_entry_t
    {
        uint64_t    encrypted_lo;
        uint64_t    encrypted_hi;
        uint64_t    prologue_hash;
        uint64_t    pad_nonce;
        uint32_t    slot_id;
        uint32_t    pad_size;
        uint64_t    enc_block_lo;
        uint64_t    enc_block_hi;
    };

    inline call_entry_t  g_table[TABLE_SLOTS]  = {};
    inline uint8_t       g_chacha_key[32]       = {};
    inline uint8_t       g_chacha_nonce[12]     = {};
    inline uint64_t      g_session_key          = 0;
    inline uint64_t      g_secondary_key        = 0;
    inline std::atomic<bool> g_initialized{false};
    inline std::atomic<uint64_t> g_call_counter{0};
    inline std::atomic<uint64_t> g_chained_token{0};
    inline std::atomic<bool> g_cet_enabled{false};
    inline uint64_t      g_legit_frame_va_a     = 0;
    inline uint64_t      g_legit_frame_va_b     = 0;

    __forceinline uint32_t cc_rotl32(uint32_t a, unsigned b)
    {
        return (a << b) | (a >> (32 - b));
    }

    __forceinline void cc_quarter(uint32_t& a, uint32_t& b, uint32_t& c, uint32_t& d)
    {
        a += b; d ^= a; d = cc_rotl32(d, 16);
        c += d; b ^= c; b = cc_rotl32(b, 12);
        a += b; d ^= a; d = cc_rotl32(d, 8);
        c += d; b ^= c; b = cc_rotl32(b, 7);
    }

    __forceinline void cc_block(const uint32_t state[16], uint8_t out[64])
    {
        uint32_t x[16];
        std::memcpy(x, state, 64);
        for (int i = 0; i < 10; ++i)
        {
            cc_quarter(x[0], x[4], x[8],  x[12]);
            cc_quarter(x[1], x[5], x[9],  x[13]);
            cc_quarter(x[2], x[6], x[10], x[14]);
            cc_quarter(x[3], x[7], x[11], x[15]);
            cc_quarter(x[0], x[5], x[10], x[15]);
            cc_quarter(x[1], x[6], x[11], x[12]);
            cc_quarter(x[2], x[7], x[8],  x[13]);
            cc_quarter(x[3], x[4], x[9],  x[14]);
        }
        for (int i = 0; i < 16; ++i)
        {
            uint32_t v = x[i] + state[i];
            out[4 * i]     = static_cast<uint8_t>(v & 0xFFu);
            out[4 * i + 1] = static_cast<uint8_t>((v >> 8)  & 0xFFu);
            out[4 * i + 2] = static_cast<uint8_t>((v >> 16) & 0xFFu);
            out[4 * i + 3] = static_cast<uint8_t>((v >> 24) & 0xFFu);
        }
    }

    __forceinline void chacha20_keystream(const uint8_t key[32],
                                          const uint8_t nonce[12],
                                          uint64_t counter,
                                          uint8_t out[64])
    {
        uint32_t state[16];
        state[0] = 0x61707865u;
        state[1] = 0x3320646eu;
        state[2] = 0x79622d32u;
        state[3] = 0x6b206574u;
        for (int i = 0; i < 8; ++i)
        {
            state[4 + i] =
                static_cast<uint32_t>(key[4 * i]) |
                (static_cast<uint32_t>(key[4 * i + 1]) << 8) |
                (static_cast<uint32_t>(key[4 * i + 2]) << 16) |
                (static_cast<uint32_t>(key[4 * i + 3]) << 24);
        }
        state[12] = static_cast<uint32_t>(counter & 0xFFFFFFFFu);
        state[13] =
            static_cast<uint32_t>(nonce[0]) |
            (static_cast<uint32_t>(nonce[1]) << 8) |
            (static_cast<uint32_t>(nonce[2]) << 16) |
            (static_cast<uint32_t>(nonce[3]) << 24);
        state[14] =
            static_cast<uint32_t>(nonce[4]) |
            (static_cast<uint32_t>(nonce[5]) << 8) |
            (static_cast<uint32_t>(nonce[6]) << 16) |
            (static_cast<uint32_t>(nonce[7]) << 24);
        state[15] =
            static_cast<uint32_t>(nonce[8]) |
            (static_cast<uint32_t>(nonce[9]) << 8) |
            (static_cast<uint32_t>(nonce[10]) << 16) |
            (static_cast<uint32_t>(nonce[11]) << 24);
        cc_block(state, out);
    }

    __forceinline void encrypt_block_chacha(uint64_t slot_id,
                                            uint64_t pad_nonce,
                                            const uint8_t* in,
                                            uint8_t* out,
                                            size_t n)
    {
        uint8_t derived_nonce[12];
        std::memcpy(derived_nonce, g_chacha_nonce, 12);
        for (int i = 0; i < 8; ++i)
            derived_nonce[i] ^= static_cast<uint8_t>(pad_nonce >> (i * 8));

        uint64_t counter = slot_id;
        size_t offset = 0;
        while (offset < n)
        {
            uint8_t ks[64];
            chacha20_keystream(g_chacha_key, derived_nonce, counter, ks);
            size_t chunk = (n - offset > 64) ? 64 : (n - offset);
            for (size_t i = 0; i < chunk; ++i)
                out[offset + i] = in[offset + i] ^ ks[i];
            offset += chunk;
            counter++;
        }
        SecureZeroMemory(derived_nonce, sizeof(derived_nonce));
    }

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

    inline bool gen_random(uint8_t* out, size_t n)
    {
        return BCryptGenRandom(nullptr, out, static_cast<ULONG>(n),
                               BCRYPT_USE_SYSTEM_PREFERRED_RNG) == 0;
    }

    inline uint64_t random_u64_fallback()
    {
        uint64_t v = 0;
        if (!gen_random(reinterpret_cast<uint8_t*>(&v), 8))
            v = __rdtsc() ^ (static_cast<uint64_t>(GetCurrentThreadId()) << 32);
        return v;
    }

    struct user_shadow_stack_policy_compat_t
    {
        DWORD Flags;
    };

    inline bool detect_cet_enabled()
    {
        using GetMitigationPolicy_t = BOOL (WINAPI*)(HANDLE, int,
                                                     PVOID, SIZE_T);
        HMODULE k32 = GetModuleHandleW(L"kernel32.dll");
        if (!k32) return false;
        auto fn = reinterpret_cast<GetMitigationPolicy_t>(
            GetProcAddress(k32, "GetProcessMitigationPolicy"));
        if (!fn) return false;

        constexpr int kProcessUserShadowStackPolicy = 17;
        user_shadow_stack_policy_compat_t pol{};
        if (!fn(GetCurrentProcess(), kProcessUserShadowStackPolicy,
                &pol, sizeof(pol)))
            return false;
        return (pol.Flags & 0x1u) != 0;
    }

    inline uint64_t pick_legit_module_va()
    {
        const wchar_t* mods[] = {
            L"kernel32.dll", L"user32.dll", L"advapi32.dll",
            L"shell32.dll", L"oleaut32.dll", L"gdi32.dll"
        };
        for (auto& mn : mods)
        {
            HMODULE h = GetModuleHandleW(mn);
            if (!h) continue;
            auto* base = reinterpret_cast<uint8_t*>(h);
            auto* dos  = reinterpret_cast<IMAGE_DOS_HEADER*>(base);
            if (dos->e_magic != IMAGE_DOS_SIGNATURE) continue;
            auto* nt   = reinterpret_cast<IMAGE_NT_HEADERS64*>(base + dos->e_lfanew);
            if (nt->Signature != IMAGE_NT_SIGNATURE) continue;
            auto* sec = IMAGE_FIRST_SECTION(nt);
            for (WORD i = 0; i < nt->FileHeader.NumberOfSections; ++i)
            {
                if (sec[i].Characteristics & IMAGE_SCN_MEM_EXECUTE)
                {
                    uint64_t off = static_cast<uint64_t>(__rdtsc()) %
                                   (sec[i].Misc.VirtualSize / 2);
                    return reinterpret_cast<uint64_t>(base) +
                           sec[i].VirtualAddress + off;
                }
            }
        }
        return 0;
    }

    __forceinline uint64_t encrypt_pointer_block(uintptr_t ptr,
                                                  uint32_t slot_id,
                                                  uint64_t pad_nonce,
                                                  uint64_t& enc_lo_out,
                                                  uint64_t& enc_hi_out,
                                                  uint64_t& blk_lo_out,
                                                  uint64_t& blk_hi_out)
    {
        uint8_t pt[16];
        std::memcpy(pt, &ptr, 8);
        std::memcpy(pt + 8, &pad_nonce, 8);

        uint8_t ct[16];
        encrypt_block_chacha(static_cast<uint64_t>(slot_id), pad_nonce,
                             pt, ct, 16);

        std::memcpy(&enc_lo_out, ct, 8);
        std::memcpy(&enc_hi_out, ct + 8, 8);

        uint8_t aux_pt[16];
        std::memcpy(aux_pt, &g_session_key, 8);
        std::memcpy(aux_pt + 8, &g_secondary_key, 8);

        uint8_t aux_ct[16];
        encrypt_block_chacha(static_cast<uint64_t>(slot_id) ^ 0xA1DA00C12345CAFEULL,
                             pad_nonce, aux_pt, aux_ct, 16);

        std::memcpy(&blk_lo_out, aux_ct, 8);
        std::memcpy(&blk_hi_out, aux_ct + 8, 8);

        SecureZeroMemory(pt, 16);
        SecureZeroMemory(ct, 16);
        SecureZeroMemory(aux_pt, 16);
        SecureZeroMemory(aux_ct, 16);
        return ptr;
    }

    __forceinline uintptr_t decrypt_pointer_block(uint64_t enc_lo,
                                                   uint64_t enc_hi,
                                                   uint32_t slot_id,
                                                   uint64_t pad_nonce)
    {
        uint8_t ct[16];
        std::memcpy(ct, &enc_lo, 8);
        std::memcpy(ct + 8, &enc_hi, 8);

        uint8_t pt[16];
        encrypt_block_chacha(static_cast<uint64_t>(slot_id), pad_nonce,
                             ct, pt, 16);

        uintptr_t out = 0;
        std::memcpy(&out, pt, 8);

        SecureZeroMemory(ct, 16);
        SecureZeroMemory(pt, 16);
        return out;
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

    if (!detail::gen_random(detail::g_chacha_key, 32))
    {
        for (int i = 0; i < 32; ++i)
            detail::g_chacha_key[i] =
                static_cast<uint8_t>(detail::g_session_key >> ((i & 7) * 8)) ^
                static_cast<uint8_t>(detail::g_secondary_key >> ((i & 7) * 8)) ^
                static_cast<uint8_t>(i * 0x9b);
    }
    if (!detail::gen_random(detail::g_chacha_nonce, 12))
    {
        for (int i = 0; i < 12; ++i)
            detail::g_chacha_nonce[i] =
                static_cast<uint8_t>(detail::g_session_key >> (i * 5)) ^
                static_cast<uint8_t>(text_hash >> (i * 3));
    }

    detail::g_cet_enabled.store(detail::detect_cet_enabled(),
                                std::memory_order_release);
    detail::g_legit_frame_va_a = detail::pick_legit_module_va();
    detail::g_legit_frame_va_b = detail::pick_legit_module_va();
    detail::g_chained_token.store(detail::random_u64_fallback(),
                                  std::memory_order_release);

    memset(detail::g_table, 0, sizeof(detail::g_table));
    detail::g_initialized.store(true);
}

inline uint32_t register_target(void* func_addr)
{
    if (!detail::g_initialized.load()) return UINT32_MAX;

    for (uint32_t i = 0; i < detail::TABLE_SLOTS; ++i)
    {
        if (detail::g_table[i].encrypted_lo == 0 &&
            detail::g_table[i].encrypted_hi == 0)
        {
            uintptr_t raw = reinterpret_cast<uintptr_t>(func_addr);
            uint64_t pad_nonce = detail::random_u64_fallback();
            uint32_t pad_size = 1u + static_cast<uint32_t>(pad_nonce & 0xF);

            detail::g_table[i].slot_id       = i;
            detail::g_table[i].pad_nonce     = pad_nonce;
            detail::g_table[i].pad_size      = pad_size;
            detail::g_table[i].prologue_hash = detail::hash_prologue(func_addr);

            uint64_t enc_lo = 0, enc_hi = 0, blk_lo = 0, blk_hi = 0;
            detail::encrypt_pointer_block(raw, i, pad_nonce,
                                          enc_lo, enc_hi, blk_lo, blk_hi);
            detail::g_table[i].encrypted_lo = enc_lo;
            detail::g_table[i].encrypted_hi = enc_hi;
            detail::g_table[i].enc_block_lo = blk_lo;
            detail::g_table[i].enc_block_hi = blk_hi;
            return i;
        }
    }
    return UINT32_MAX;
}

namespace detail {

    __forceinline uint64_t read_shadow_stack_pointer()
    {
        return aida_read_ssp();
    }

    __forceinline bool verify_shadow_stack_return(uint64_t expected_ra)
    {
        if (!g_cet_enabled.load(std::memory_order_acquire)) return true;
        uint64_t ssp = read_shadow_stack_pointer();
        if (ssp == 0) return true;
        __try {
            uint64_t shadow_ra = *reinterpret_cast<uint64_t*>(ssp);
            return shadow_ra == expected_ra;
        }
        __except (EXCEPTION_EXECUTE_HANDLER) {
            return true;
        }
    }
}

__forceinline void* resolve(uint32_t slot_id)
{
    if (slot_id >= detail::TABLE_SLOTS) return nullptr;

    const auto& entry = detail::g_table[slot_id];
    if (entry.encrypted_lo == 0 && entry.encrypted_hi == 0) return nullptr;

    uintptr_t resolved = detail::decrypt_pointer_block(
        entry.encrypted_lo, entry.encrypted_hi, slot_id, entry.pad_nonce);
    void* func = reinterpret_cast<void*>(resolved);

    uint64_t current_hash = detail::hash_prologue(func);
    if (current_hash != entry.prologue_hash)
    {
        return nullptr;
    }

    detail::g_call_counter.fetch_add(1, std::memory_order_relaxed);
    return func;
}

__forceinline uint64_t encrypt_chained_target(uint32_t slot_id,
                                               uintptr_t target,
                                               uint64_t per_call_nonce)
{
    uint8_t pt[8];
    std::memcpy(pt, &target, 8);
    uint8_t ct[8];
    detail::encrypt_block_chacha(
        static_cast<uint64_t>(slot_id) ^ detail::g_chained_token.load(),
        per_call_nonce, pt, ct, 8);
    uint64_t out = 0;
    std::memcpy(&out, ct, 8);
    SecureZeroMemory(pt, 8);
    SecureZeroMemory(ct, 8);
    return out;
}

__forceinline uintptr_t decrypt_chained_target(uint32_t slot_id,
                                                uint64_t encrypted,
                                                uint64_t per_call_nonce)
{
    uint8_t ct[8];
    std::memcpy(ct, &encrypted, 8);
    uint8_t pt[8];
    detail::encrypt_block_chacha(
        static_cast<uint64_t>(slot_id) ^ detail::g_chained_token.load(),
        per_call_nonce, ct, pt, 8);
    uintptr_t out = 0;
    std::memcpy(&out, pt, 8);
    SecureZeroMemory(ct, 8);
    SecureZeroMemory(pt, 8);
    return out;
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

    uint64_t expected_ra =
        reinterpret_cast<uint64_t>(_ReturnAddress());

    if constexpr (std::is_void_v<Ret>)
    {
        reinterpret_cast<fn_t>(target)(args...);
        if (!detail::verify_shadow_stack_return(expected_ra))
        {
            __fastfail(0xA1DA0CE7u);
        }
        return;
    }
    else
    {
        Ret rv = reinterpret_cast<fn_t>(target)(args...);
        if (!detail::verify_shadow_stack_return(expected_ra))
        {
            __fastfail(0xA1DA0CE7u);
        }
        return rv;
    }
}

template <typename Ret, typename... Args>
__forceinline Ret protected_call_chained(uint32_t slot_id,
                                          uint64_t per_call_nonce,
                                          Args... args)
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

    uint64_t enc_target = encrypt_chained_target(
        slot_id, reinterpret_cast<uintptr_t>(target), per_call_nonce);

    uintptr_t check = decrypt_chained_target(slot_id, enc_target, per_call_nonce);
    if (check != reinterpret_cast<uintptr_t>(target))
    {
        if constexpr (std::is_pointer_v<Ret>) return nullptr;
        else if constexpr (std::is_integral_v<Ret>) return static_cast<Ret>(0);
        else if constexpr (std::is_void_v<Ret>) return;
        else return Ret{};
    }

    uint64_t expected_ra =
        reinterpret_cast<uint64_t>(_ReturnAddress());

    if constexpr (std::is_void_v<Ret>)
    {
        reinterpret_cast<fn_t>(check)(args...);
        if (!detail::verify_shadow_stack_return(expected_ra))
        {
            __fastfail(0xA1DA0CE7u);
        }
        return;
    }
    else
    {
        Ret rv = reinterpret_cast<fn_t>(check)(args...);
        if (!detail::verify_shadow_stack_return(expected_ra))
        {
            __fastfail(0xA1DA0CE7u);
        }
        return rv;
    }
}

inline void install_legit_frame_spoofing()
{
#if defined(_MSC_VER)
    if (!detail::g_initialized.load()) return;

    if (detail::g_legit_frame_va_a == 0)
        detail::g_legit_frame_va_a = detail::pick_legit_module_va();
    if (detail::g_legit_frame_va_b == 0)
        detail::g_legit_frame_va_b = detail::pick_legit_module_va();

    volatile uint64_t* fake_anchor = reinterpret_cast<volatile uint64_t*>(
        _AddressOfReturnAddress());
    if (fake_anchor)
    {
        volatile uint64_t consume = *fake_anchor;
        (void)consume;
    }
#endif
}

inline void re_encrypt_all()
{
    if (!detail::g_initialized.load()) return;

    int cpu[4];
    __cpuid(cpu, 7);
    uint64_t fresh_entropy = __rdtsc() ^ static_cast<uint64_t>(cpu[1]);

    uint8_t fresh_key[32];
    if (!detail::gen_random(fresh_key, 32))
    {
        for (int i = 0; i < 32; ++i)
            fresh_key[i] = detail::g_chacha_key[i] ^
                           static_cast<uint8_t>(fresh_entropy >> ((i & 7) * 8));
    }
    uint8_t fresh_nonce[12];
    if (!detail::gen_random(fresh_nonce, 12))
    {
        for (int i = 0; i < 12; ++i)
            fresh_nonce[i] = detail::g_chacha_nonce[i] ^
                             static_cast<uint8_t>(fresh_entropy >> (i * 4));
    }

    uintptr_t resolved[detail::TABLE_SLOTS];
    for (uint32_t i = 0; i < detail::TABLE_SLOTS; ++i)
    {
        if (detail::g_table[i].encrypted_lo != 0 ||
            detail::g_table[i].encrypted_hi != 0)
        {
            resolved[i] = detail::decrypt_pointer_block(
                detail::g_table[i].encrypted_lo,
                detail::g_table[i].encrypted_hi,
                i,
                detail::g_table[i].pad_nonce);
        }
        else
        {
            resolved[i] = 0;
        }
    }

    std::memcpy(detail::g_chacha_key, fresh_key, 32);
    std::memcpy(detail::g_chacha_nonce, fresh_nonce, 12);
    SecureZeroMemory(fresh_key, 32);
    SecureZeroMemory(fresh_nonce, 12);

    detail::g_chained_token.store(detail::random_u64_fallback(),
                                  std::memory_order_release);

    for (uint32_t i = 0; i < detail::TABLE_SLOTS; ++i)
    {
        if (resolved[i] != 0)
        {
            uint64_t pad_nonce = detail::random_u64_fallback();
            uint32_t pad_size = 1u + static_cast<uint32_t>(pad_nonce & 0xF);

            uint64_t enc_lo = 0, enc_hi = 0, blk_lo = 0, blk_hi = 0;
            detail::encrypt_pointer_block(resolved[i], i, pad_nonce,
                                          enc_lo, enc_hi, blk_lo, blk_hi);
            detail::g_table[i].encrypted_lo = enc_lo;
            detail::g_table[i].encrypted_hi = enc_hi;
            detail::g_table[i].enc_block_lo = blk_lo;
            detail::g_table[i].enc_block_hi = blk_hi;
            detail::g_table[i].pad_nonce    = pad_nonce;
            detail::g_table[i].pad_size     = pad_size;
        }
    }

    SecureZeroMemory(resolved, sizeof(resolved));
}

inline bool verify_table_integrity()
{
    if (!detail::g_initialized.load()) return false;

    for (uint32_t i = 0; i < detail::TABLE_SLOTS; ++i)
    {
        if (detail::g_table[i].encrypted_lo == 0 &&
            detail::g_table[i].encrypted_hi == 0) continue;

        uintptr_t ptr = detail::decrypt_pointer_block(
            detail::g_table[i].encrypted_lo,
            detail::g_table[i].encrypted_hi,
            i,
            detail::g_table[i].pad_nonce);
        void* func = reinterpret_cast<void*>(ptr);

        uint64_t current_hash = detail::hash_prologue(func);
        if (current_hash != detail::g_table[i].prologue_hash)
            return false;
    }
    return true;
}

}
}
