#pragma once

#include <windows.h>
#include <intrin.h>
#include <nmmintrin.h>

#include <atomic>
#include <cstdint>
#include <cstring>
#include <mutex>
#include <vector>

#include "state.hpp"
#include "integrity.hpp"

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

    inline uint64_t& session_seed()
    {
        static uint64_t s = 0;
        return s;
    }

    struct eop_trampoline_t
    {
        uint64_t trigger_addr;
        uint64_t target_addr;
        uint64_t decrypt_key;
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

    inline uint64_t fnv1a_hash(const void* data, size_t len)
    {
        uint64_t h = 0xCBF29CE484222325ULL;
        const auto* p = static_cast<const uint8_t*>(data);
        for (size_t i = 0; i < len; ++i)
        {
            h ^= p[i];
            h *= 0x100000001B3ULL;
        }
        return h;
    }

    inline uint64_t derive_section_key(const char* section_name, uint64_t seed)
    {
        uint64_t name_hash = fnv1a_hash(section_name, strlen(section_name));
        return name_hash ^ seed ^ _rotl64(seed, 17);
    }

    inline uint64_t derive_page_key(uint64_t page_addr, uint64_t section_key)
    {
        uint8_t buf[16];
        memcpy(buf, &page_addr, 8);
        memcpy(buf + 8, &section_key, 8);
        return integrity::siphash::hash(buf, 16, section_key, page_addr ^ 0x7A3E1F9DC5B28A04ULL);
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
                if (tramp.decrypt_key != 0)
                {
                    DWORD old_prot;
                    VirtualProtect(reinterpret_cast<void*>(tramp.target_addr), 64,
                        PAGE_EXECUTE_READWRITE, &old_prot);
                    detail::xor_region(reinterpret_cast<uint8_t*>(tramp.target_addr),
                        64, tramp.decrypt_key);
                    VirtualProtect(reinterpret_cast<void*>(tramp.target_addr), 64,
                        PAGE_EXECUTE_READ, &old_prot);
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
                if (tramp.decrypt_key != 0)
                {
                    DWORD old_prot;
                    VirtualProtect(reinterpret_cast<void*>(tramp.target_addr), 64,
                        PAGE_EXECUTE_READWRITE, &old_prot);
                    detail::xor_region(reinterpret_cast<uint8_t*>(tramp.target_addr),
                        64, tramp.decrypt_key);
                    VirtualProtect(reinterpret_cast<void*>(tramp.target_addr), 64,
                        PAGE_EXECUTE_READ, &old_prot);
                }
                ep->ContextRecord->Rip = tramp.target_addr;
                return EXCEPTION_CONTINUE_EXECUTION;
            }
        }
    }

    return EXCEPTION_CONTINUE_SEARCH;
}

inline bool initialize(uint64_t code_hash)
{
    if (detail::active().load()) return true;

    detail::session_seed() = __rdtsc() ^ code_hash ^ GetCurrentProcessId();

    veh_handle = AddVectoredExceptionHandler(1, code_guard_handler);
    if (!veh_handle) return false;

    detail::active().store(true);
    return true;
}

inline void encrypt_region(uint64_t base, uint32_t size, const char* section_name)
{
    if (!detail::active().load()) return;

    uint64_t sec_key = detail::derive_section_key(section_name, detail::session_seed());
    uint64_t page_key = detail::derive_page_key(base, sec_key);

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

    uint64_t new_seed = __rdtsc() ^ detail::session_seed();
    detail::session_seed() = new_seed;

    for (auto& page : detail::encrypted_pages())
    {
        DWORD old_prot;
        if (!VirtualProtect(reinterpret_cast<void*>(page.base), page.size,
            PAGE_EXECUTE_READWRITE, &old_prot))
            continue;

        detail::xor_region(reinterpret_cast<uint8_t*>(page.base), page.size, page.key);

        uint64_t new_key = detail::derive_page_key(page.base,
            detail::derive_section_key(".text", new_seed));
        detail::xor_region(reinterpret_cast<uint8_t*>(page.base), page.size, new_key);

        page.key = new_key;

        VirtualProtect(reinterpret_cast<void*>(page.base), page.size,
            PAGE_EXECUTE_READ | PAGE_GUARD, &old_prot);
    }
}

inline void register_eop_trampoline(uint64_t trigger_addr, uint64_t target_addr,
    uint64_t decrypt_key, detail::eop_exception_type type)
{
    if (!detail::active().load()) return;

    std::lock_guard<std::mutex> lk(detail::page_mtx());
    detail::eop_trampolines().push_back({trigger_addr, target_addr, decrypt_key,
        static_cast<uint8_t>(type), true});

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
}

}
}
