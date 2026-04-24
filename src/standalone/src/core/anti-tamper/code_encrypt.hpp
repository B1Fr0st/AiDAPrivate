#pragma once

#include <windows.h>
#include <bcrypt.h>
#include <intrin.h>
#include <nmmintrin.h>

#include <atomic>
#include <cstdint>
#include <cstring>
#include <mutex>
#include <vector>

#include "state.hpp"
#include "integrity.hpp"
#include "ghost_veh.hpp"
#include "token_chain.hpp"
#include "enforcement.hpp"

#pragma comment(lib, "bcrypt.lib")

namespace anti_tamper {
namespace code_encrypt {

namespace detail {

    struct encrypted_page_t
    {
        uint64_t base;
        uint32_t size;
        uint64_t key;
        DWORD original_protect;
    };

    inline std::mutex& page_mtx()
    {
        static std::mutex m;
        return m;
    }

    inline std::vector<encrypted_page_t>& encrypted_pages()
    {
        static std::vector<encrypted_page_t> v;
        return v;
    }

    inline std::atomic<bool>& active()
    {
        static std::atomic<bool> a{false};
        return a;
    }

    inline uint8_t (&session_prk())[32]
    {
        static uint8_t prk[32] = {};
        return prk;
    }

    struct eop_trampoline_t
    {
        uint64_t trigger_addr;
        uint64_t target_addr;
        uint64_t decrypt_key;
        uint32_t target_size;
        uint8_t  exception_type;
        bool     armed;
    };

    inline std::vector<eop_trampoline_t>& eop_trampolines()
    {
        static std::vector<eop_trampoline_t> v;
        return v;
    }

    enum eop_exception_type : uint8_t
    {
        EOP_INT2D = 0,
        EOP_DIV_ZERO = 1,
        EOP_INT3 = 2,
        EOP_PRIV_INSN = 3,
    };

    inline void install_int2d_trigger(uint8_t* addr)
    {
        DWORD old;
        VirtualProtect(addr, 2, PAGE_EXECUTE_READWRITE, &old);
        addr[0] = 0xCD;
        addr[1] = 0x2D;
        VirtualProtect(addr, 2, old, &old);
        FlushInstructionCache(GetCurrentProcess(), addr, 2);
    }

    inline void install_div_zero_trigger(uint8_t* addr)
    {
        DWORD old;
        VirtualProtect(addr, 6, PAGE_EXECUTE_READWRITE, &old);
        addr[0] = 0x48; addr[1] = 0x31; addr[2] = 0xC9;
        addr[3] = 0x48; addr[4] = 0xF7; addr[5] = 0xF1;
        VirtualProtect(addr, 6, old, &old);
        FlushInstructionCache(GetCurrentProcess(), addr, 6);
    }

    inline bool hkdf_hmac_sha256(const uint8_t* key, uint32_t key_len,
                                  const uint8_t* data, uint32_t data_len,
                                  uint8_t out[32])
    {
        BCRYPT_ALG_HANDLE hAlg = nullptr;
        BCRYPT_HASH_HANDLE hHash = nullptr;
        bool ok = false;
        if (BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_SHA256_ALGORITHM,
                                        nullptr, BCRYPT_ALG_HANDLE_HMAC_FLAG) != 0)
            return false;
        if (BCryptCreateHash(hAlg, &hHash, nullptr, 0,
                             const_cast<PUCHAR>(key), key_len, 0) != 0)
        {
            BCryptCloseAlgorithmProvider(hAlg, 0);
            return false;
        }
        if (BCryptHashData(hHash, const_cast<PUCHAR>(data), data_len, 0) == 0)
            ok = (BCryptFinishHash(hHash, out, 32, 0) == 0);
        BCryptDestroyHash(hHash);
        BCryptCloseAlgorithmProvider(hAlg, 0);
        return ok;
    }

    inline void hkdf_expand(const uint8_t prk[32], const uint8_t* info,
                             uint32_t info_len, uint8_t* okm, uint32_t okm_len)
    {
        uint8_t t[32] = {};
        uint32_t t_len = 0;
        uint8_t counter = 1;
        uint32_t pos = 0;
        while (pos < okm_len)
        {
            uint32_t input_len = t_len + info_len + 1;
            auto* input = static_cast<uint8_t*>(_alloca(input_len));
            if (t_len > 0) memcpy(input, t, t_len);
            memcpy(input + t_len, info, info_len);
            input[t_len + info_len] = counter;
            hkdf_hmac_sha256(prk, 32, input, input_len, t);
            t_len = 32;
            uint32_t copy = (okm_len - pos < 32) ? (okm_len - pos) : 32;
            memcpy(okm + pos, t, copy);
            pos += copy;
            counter++;
        }
    }

    inline uint64_t derive_section_key(const char* section_name, const uint8_t prk[32])
    {
        const char label[] = "code_encrypt|section|";
        size_t name_len = strlen(section_name);
        uint32_t info_len = static_cast<uint32_t>(sizeof(label) - 1 + name_len);
        auto* info = static_cast<uint8_t*>(_alloca(info_len));
        memcpy(info, label, sizeof(label) - 1);
        memcpy(info + sizeof(label) - 1, section_name, name_len);

        uint8_t derived[8];
        hkdf_expand(prk, info, info_len, derived, 8);

        uint64_t key;
        memcpy(&key, derived, 8);
        return key;
    }

    inline uint64_t derive_page_key(uint64_t page_addr, uint64_t section_key,
                                     const uint8_t prk[32])
    {
        const char label[] = "code_encrypt|page|";
        uint8_t info[sizeof(label) - 1 + 16];
        memcpy(info, label, sizeof(label) - 1);
        memcpy(info + sizeof(label) - 1, &page_addr, 8);
        memcpy(info + sizeof(label) - 1 + 8, &section_key, 8);

        uint8_t derived[8];
        hkdf_expand(prk, info, static_cast<uint32_t>(sizeof(info)), derived, 8);

        uint64_t key;
        memcpy(&key, derived, 8);
        return key;
    }

    inline void xor_region(uint8_t* data, uint32_t size, uint64_t key)
    {
        uint64_t rolling = key;
        auto* ptr64 = reinterpret_cast<uint64_t*>(data);
        uint32_t chunks = size / 8;

        for (uint32_t i = 0; i < chunks; ++i)
        {
            ptr64[i] ^= rolling;
            rolling = _rotl64(rolling ^ ptr64[i], 13) + 0x9E3779B97F4A7C15ULL;
        }

        uint32_t remaining = size % 8;
        uint8_t* tail = data + chunks * 8;
        for (uint32_t i = 0; i < remaining; ++i)
        {
            tail[i] ^= static_cast<uint8_t>(rolling >> (i * 8));
        }
    }

}

inline PVOID veh_handle = nullptr;
inline ghost_veh::registration_t ghost_reg{ 0 };

inline LONG CALLBACK code_guard_handler(EXCEPTION_POINTERS* ep)
{
    if (ep->ExceptionRecord->ExceptionCode == STATUS_GUARD_PAGE_VIOLATION)
    {
        uint64_t fault_addr = static_cast<uint64_t>(
            ep->ExceptionRecord->ExceptionInformation[1]);

        std::lock_guard<std::mutex> lk(detail::page_mtx());
        for (auto& page : detail::encrypted_pages())
        {
            if (fault_addr >= page.base && fault_addr < page.base + page.size)
            {
                DWORD old_prot;
                VirtualProtect(reinterpret_cast<void*>(page.base), page.size,
                    PAGE_EXECUTE_READWRITE, &old_prot);
                detail::xor_region(reinterpret_cast<uint8_t*>(page.base),
                    page.size, page.key);

                ep->ContextRecord->EFlags |= 0x100;
                return EXCEPTION_CONTINUE_EXECUTION;
            }
        }
    }

    if (ep->ExceptionRecord->ExceptionCode == STATUS_SINGLE_STEP)
    {
        std::lock_guard<std::mutex> lk(detail::page_mtx());
        for (auto& page : detail::encrypted_pages())
        {
            uint64_t rip = ep->ContextRecord->Rip;
            if (rip >= page.base && rip < page.base + page.size)
            {
                detail::xor_region(reinterpret_cast<uint8_t*>(page.base),
                    page.size, page.key);

                DWORD old_prot;
                VirtualProtect(reinterpret_cast<void*>(page.base), page.size,
                    PAGE_EXECUTE_READ | PAGE_GUARD, &old_prot);
                return EXCEPTION_CONTINUE_EXECUTION;
            }
        }
    }

    if (ep->ExceptionRecord->ExceptionCode == STATUS_BREAKPOINT ||
        ep->ExceptionRecord->ExceptionCode == 0x4000001F)
    {
        uint64_t rip = ep->ContextRecord->Rip;
        std::lock_guard<std::mutex> lk(detail::page_mtx());
        for (auto& tramp : detail::eop_trampolines())
        {
            if (!tramp.armed) continue;
            if (tramp.exception_type != detail::EOP_INT2D &&
                tramp.exception_type != detail::EOP_INT3) continue;
            if (rip >= tramp.trigger_addr && rip <= tramp.trigger_addr + 2)
            {
                if (tramp.decrypt_key != 0 && tramp.target_size != 0)
                {
                    DWORD old_prot;
                    VirtualProtect(reinterpret_cast<void*>(tramp.target_addr), tramp.target_size,
                        PAGE_EXECUTE_READWRITE, &old_prot);
                    detail::xor_region(reinterpret_cast<uint8_t*>(tramp.target_addr),
                        tramp.target_size, tramp.decrypt_key);
                    VirtualProtect(reinterpret_cast<void*>(tramp.target_addr), tramp.target_size,
                        PAGE_EXECUTE_READ, &old_prot);
                    FlushInstructionCache(GetCurrentProcess(),
                        reinterpret_cast<void*>(tramp.target_addr), tramp.target_size);
                }
                ep->ContextRecord->Rip = tramp.target_addr;
                return EXCEPTION_CONTINUE_EXECUTION;
            }
        }
    }

    if (ep->ExceptionRecord->ExceptionCode == STATUS_INTEGER_DIVIDE_BY_ZERO)
    {
        uint64_t rip = ep->ContextRecord->Rip;
        std::lock_guard<std::mutex> lk(detail::page_mtx());
        for (auto& tramp : detail::eop_trampolines())
        {
            if (!tramp.armed) continue;
            if (tramp.exception_type != detail::EOP_DIV_ZERO) continue;
            if (rip >= tramp.trigger_addr && rip <= tramp.trigger_addr + 6)
            {
                if (tramp.decrypt_key != 0 && tramp.target_size != 0)
                {
                    DWORD old_prot;
                    VirtualProtect(reinterpret_cast<void*>(tramp.target_addr), tramp.target_size,
                        PAGE_EXECUTE_READWRITE, &old_prot);
                    detail::xor_region(reinterpret_cast<uint8_t*>(tramp.target_addr),
                        tramp.target_size, tramp.decrypt_key);
                    VirtualProtect(reinterpret_cast<void*>(tramp.target_addr), tramp.target_size,
                        PAGE_EXECUTE_READ, &old_prot);
                    FlushInstructionCache(GetCurrentProcess(),
                        reinterpret_cast<void*>(tramp.target_addr), tramp.target_size);
                }
                ep->ContextRecord->Rip = tramp.target_addr;
                return EXCEPTION_CONTINUE_EXECUTION;
            }
        }
    }

    return EXCEPTION_CONTINUE_SEARCH;
}

inline long code_guard_ghost_handler(PEXCEPTION_POINTERS ep, void*)
{
    return code_guard_handler(ep);
}

inline bool initialize(uint64_t code_hash)
{
    if (detail::active().load()) return true;

#pragma region RDTSC_ENTANGLE
    if (token_chain::is_rdtsc_entangle_enabled())
    {
        uint64_t e_samples[4];
        for (int i = 0; i < 4; ++i)
            e_samples[i] = token_chain::detail::rdtsc_entangle_sample();

        uint8_t buf[32];
        memcpy(buf, e_samples, 32);
        uint64_t k0 = 0, k1 = 0;
        integrity::get_session_keys(k0, k1);
        uint64_t entangle_hmac = integrity::siphash::hash(buf, 32, k0, k1);
        (void)entangle_hmac;

        if (token_chain::rdtsc_entangle_violation_observed())
        {
            auto& rt = state::get();
            rt.violation_latched.store(true, std::memory_order_release);
            rt.violation_reason = "rdtsc_entangle_hv_spoof";
            enforcement_detail::silent_corrupt_text(1);
            return false;
        }
    }
#pragma endregion

    uint8_t ikm[32];
    if (BCryptGenRandom(nullptr, ikm, 32, BCRYPT_USE_SYSTEM_PREFERRED_RNG) != 0)
        return false;

    uint8_t salt[8];
    memcpy(salt, &code_hash, 8);
    detail::hkdf_hmac_sha256(salt, 8, ikm, 32, detail::session_prk());
    SecureZeroMemory(ikm, 32);

    if (ghost_veh::is_active())
    {
        ghost_reg = ghost_veh::register_handler(
            ghost_veh::ex_kind::kAny, code_guard_ghost_handler, nullptr);
        if (ghost_reg.id == 0)
        {
            veh_handle = AddVectoredExceptionHandler(1, code_guard_handler);
            if (!veh_handle) return false;
        }
    }
    else
    {
        veh_handle = AddVectoredExceptionHandler(1, code_guard_handler);
        if (!veh_handle) return false;
    }

    detail::active().store(true);
    return true;
}

inline void encrypt_region(uint64_t base, uint32_t size, const char* section_name)
{
    if (!detail::active().load()) return;

    uint64_t sec_key = detail::derive_section_key(section_name, detail::session_prk());
    uint64_t page_key = detail::derive_page_key(base, sec_key, detail::session_prk());

    DWORD old_prot;
    if (!VirtualProtect(reinterpret_cast<void*>(base), size,
        PAGE_EXECUTE_READWRITE, &old_prot))
        return;

    detail::xor_region(reinterpret_cast<uint8_t*>(base), size, page_key);

    VirtualProtect(reinterpret_cast<void*>(base), size,
        PAGE_EXECUTE_READ | PAGE_GUARD, &old_prot);

    std::lock_guard<std::mutex> lk(detail::page_mtx());
    detail::encrypted_pages().push_back({base, size, page_key, old_prot});
}

inline void rotate_keys()
{
    std::lock_guard<std::mutex> lk(detail::page_mtx());

    uint8_t new_ikm[32];
    BCryptGenRandom(nullptr, new_ikm, 32, BCRYPT_USE_SYSTEM_PREFERRED_RNG);
    uint8_t new_prk[32];
    detail::hkdf_hmac_sha256(detail::session_prk(), 32, new_ikm, 32, new_prk);
    SecureZeroMemory(new_ikm, 32);
    memcpy(detail::session_prk(), new_prk, 32);
    SecureZeroMemory(new_prk, 32);

    for (auto& page : detail::encrypted_pages())
    {
        DWORD old_prot;
        if (!VirtualProtect(reinterpret_cast<void*>(page.base), page.size,
            PAGE_EXECUTE_READWRITE, &old_prot))
            continue;

        detail::xor_region(reinterpret_cast<uint8_t*>(page.base), page.size, page.key);

        uint64_t new_key = detail::derive_page_key(page.base,
            detail::derive_section_key(".text", detail::session_prk()),
            detail::session_prk());
        detail::xor_region(reinterpret_cast<uint8_t*>(page.base), page.size, new_key);

        page.key = new_key;

        VirtualProtect(reinterpret_cast<void*>(page.base), page.size,
            PAGE_EXECUTE_READ | PAGE_GUARD, &old_prot);
    }
}

inline void register_eop_trampoline(uint64_t trigger_addr, uint64_t target_addr,
    uint64_t decrypt_key, uint32_t target_size, detail::eop_exception_type type)
{
    if (!detail::active().load()) return;

    std::lock_guard<std::mutex> lk(detail::page_mtx());
    detail::eop_trampolines().push_back({trigger_addr, target_addr, decrypt_key,
        target_size, static_cast<uint8_t>(type), true});

    switch (type)
    {
    case detail::EOP_INT2D:
        detail::install_int2d_trigger(reinterpret_cast<uint8_t*>(trigger_addr));
        break;
    case detail::EOP_DIV_ZERO:
        detail::install_div_zero_trigger(reinterpret_cast<uint8_t*>(trigger_addr));
        break;
    default:
        break;
    }
}

inline void shutdown()
{
    detail::active().store(false);
    if (veh_handle)
    {
        RemoveVectoredExceptionHandler(veh_handle);
        veh_handle = nullptr;
    }

    std::lock_guard<std::mutex> lk(detail::page_mtx());
    for (auto& page : detail::encrypted_pages())
    {
        DWORD old_prot;
        VirtualProtect(reinterpret_cast<void*>(page.base), page.size,
            PAGE_EXECUTE_READWRITE, &old_prot);
        detail::xor_region(reinterpret_cast<uint8_t*>(page.base), page.size, page.key);
        VirtualProtect(reinterpret_cast<void*>(page.base), page.size,
            page.original_protect, &old_prot);
    }
    detail::encrypted_pages().clear();
    SecureZeroMemory(detail::session_prk(), 32);
}

}
}
