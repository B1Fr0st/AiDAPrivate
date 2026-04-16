#pragma once


#include <windows.h>
#include <intrin.h>

#include <cstdint>
#include <cstring>
#include <mutex>
#include <atomic>
#include <vector>

#include "integrity.hpp"
#include "cff.hpp"

namespace anti_tamper {
namespace nanomites {

namespace detail {


    enum condition_code_t : uint8_t
    {
        CC_O   = 0x00,
        CC_NO  = 0x01,
        CC_B   = 0x02,
        CC_NB  = 0x03,
        CC_E   = 0x04,
        CC_NE  = 0x05,
        CC_BE  = 0x06,
        CC_A   = 0x07,
        CC_S   = 0x08,
        CC_NS  = 0x09,
        CC_P   = 0x0A,
        CC_NP  = 0x0B,
        CC_L   = 0x0C,
        CC_GE  = 0x0D,
        CC_LE  = 0x0E,
        CC_G   = 0x0F,
        CC_JMP = 0xFF,
    };


    static constexpr uint64_t FLAG_CF = 1ULL << 0;
    static constexpr uint64_t FLAG_PF = 1ULL << 2;
    static constexpr uint64_t FLAG_ZF = 1ULL << 6;
    static constexpr uint64_t FLAG_SF = 1ULL << 7;
    static constexpr uint64_t FLAG_OF = 1ULL << 11;


    static constexpr uint32_t MAX_NANOMITES = 512;

    struct nanomite_entry_t
    {
        uint64_t         int3_addr;
        uint64_t         taken_target;
        uint64_t         fall_through;
        condition_code_t condition;
        uint8_t          original_insn_len;
        uint16_t         _pad;
        uint64_t         guard_hash;
    };

    struct nanomite_state_t
    {
        nanomite_entry_t entries[MAX_NANOMITES];
        uint32_t         count;
        uint64_t         session_key[2];
        uint64_t         encryption_key;
        PVOID            veh_handle;
        std::mutex       mtx;
        std::atomic<bool> initialized{false};
        std::atomic<uint64_t> dispatch_count{0};
        std::atomic<uint64_t> miss_count{0};
    };

    inline nanomite_state_t& state()
    {
        static nanomite_state_t s{};
        return s;
    }


    inline bool evaluate_condition(condition_code_t cc, uint64_t rflags)
    {
        bool cf = (rflags & FLAG_CF) != 0;
        bool zf = (rflags & FLAG_ZF) != 0;
        bool sf = (rflags & FLAG_SF) != 0;
        bool of = (rflags & FLAG_OF) != 0;
        bool pf = (rflags & FLAG_PF) != 0;

        switch (cc)
        {
        case CC_O:   return of;
        case CC_NO:  return !of;
        case CC_B:   return cf;
        case CC_NB:  return !cf;
        case CC_E:   return zf;
        case CC_NE:  return !zf;
        case CC_BE:  return cf || zf;
        case CC_A:   return !cf && !zf;
        case CC_S:   return sf;
        case CC_NS:  return !sf;
        case CC_P:   return pf;
        case CC_NP:  return !pf;
        case CC_L:   return sf != of;
        case CC_GE:  return sf == of;
        case CC_LE:  return zf || (sf != of);
        case CC_G:   return !zf && (sf == of);
        case CC_JMP: return true;
        default:     return false;
        }
    }


    inline void encrypt_entry(nanomite_entry_t& e, uint64_t key)
    {
        e.int3_addr    ^= key;
        e.taken_target ^= _rotl64(key, 13);
        e.fall_through ^= _rotl64(key, 29);
    }

    inline void decrypt_entry(nanomite_entry_t& e, uint64_t key)
    {
        e.int3_addr    ^= key;
        e.taken_target ^= _rotl64(key, 13);
        e.fall_through ^= _rotl64(key, 29);
    }

    inline uint64_t compute_guard_hash(uint64_t addr, uint64_t target, uint8_t cc,
                                       const uint64_t sip_key[2])
    {
        uint64_t data = addr ^ target ^ (static_cast<uint64_t>(cc) << 48);
        return integrity::siphash::hash(
            reinterpret_cast<const uint8_t*>(&data), sizeof(data),
            sip_key[0], sip_key[1]);
    }


    inline const nanomite_entry_t* lookup(uint64_t rip)
    {
        auto& s = state();


        for (uint32_t i = 0; i < s.count; ++i)
        {
            nanomite_entry_t tmp = s.entries[i];
            decrypt_entry(tmp, s.encryption_key);
            if (tmp.int3_addr == rip)
            {

                uint64_t expected = compute_guard_hash(
                    tmp.int3_addr, tmp.taken_target, tmp.condition, s.session_key);
                if (tmp.guard_hash != expected)
                {

                    return nullptr;
                }


                thread_local nanomite_entry_t tl_entry;
                tl_entry = tmp;
                return &tl_entry;
            }
        }
        return nullptr;
    }


    inline LONG CALLBACK nanomite_veh_handler(PEXCEPTION_POINTERS info)
    {
        if (info->ExceptionRecord->ExceptionCode != EXCEPTION_BREAKPOINT)
            return EXCEPTION_CONTINUE_SEARCH;

        auto& s = state();
        if (!s.initialized.load(std::memory_order_acquire))
            return EXCEPTION_CONTINUE_SEARCH;

        uint64_t rip = static_cast<uint64_t>(info->ContextRecord->Rip);

        const nanomite_entry_t* entry = lookup(rip);
        if (!entry)
            return EXCEPTION_CONTINUE_SEARCH;

        s.dispatch_count.fetch_add(1, std::memory_order_relaxed);


        uint64_t rflags = static_cast<uint64_t>(info->ContextRecord->EFlags);
        bool take_branch = evaluate_condition(entry->condition, rflags);


        if (take_branch)
            info->ContextRecord->Rip = entry->taken_target;
        else
            info->ContextRecord->Rip = entry->fall_through;

        return EXCEPTION_CONTINUE_EXECUTION;
    }


    struct jcc_info_t
    {
        uint64_t         addr;
        uint64_t         target;
        uint64_t         fall_through;
        condition_code_t cc;
        uint8_t          insn_len;
    };

    inline bool decode_jcc_at(const uint8_t* code, uint64_t addr, jcc_info_t& out)
    {
        uint8_t op = code[0];


        if (op >= 0x70 && op <= 0x7F)
        {
            out.cc = static_cast<condition_code_t>(op - 0x70);
            out.insn_len = 2;
            int8_t rel = static_cast<int8_t>(code[1]);
            out.addr = addr;
            out.target = addr + 2 + rel;
            out.fall_through = addr + 2;
            return true;
        }


        if (op == 0x0F && code[1] >= 0x80 && code[1] <= 0x8F)
        {
            out.cc = static_cast<condition_code_t>(code[1] - 0x80);
            out.insn_len = 6;
            int32_t rel;
            memcpy(&rel, &code[2], 4);
            out.addr = addr;
            out.target = addr + 6 + rel;
            out.fall_through = addr + 6;
            return true;
        }


        if (op == 0xEB)
        {
            out.cc = CC_JMP;
            out.insn_len = 2;
            int8_t rel = static_cast<int8_t>(code[1]);
            out.addr = addr;
            out.target = addr + 2 + rel;
            out.fall_through = addr + 2;
            return true;
        }


        if (op == 0xE9)
        {
            out.cc = CC_JMP;
            out.insn_len = 5;
            int32_t rel;
            memcpy(&rel, &code[1], 4);
            out.addr = addr;
            out.target = addr + 5 + rel;
            out.fall_through = addr + 5;
            return true;
        }

        return false;
    }

}


inline bool initialize()
{
    auto& s = detail::state();
    if (s.initialized.load()) return true;

    std::lock_guard<std::mutex> lk(s.mtx);
    if (s.initialized.load()) return true;


    uint64_t tsc = __rdtsc();
    int cpuid_out[4];
    __cpuid(cpuid_out, 1);

    s.session_key[0] = tsc ^ static_cast<uint64_t>(cpuid_out[0]) << 32;
    s.session_key[1] = _rotl64(tsc, 17) ^ static_cast<uint64_t>(cpuid_out[2]);
    s.encryption_key = tsc * 6364136223846793005ULL + 1442695040888963407ULL;
    s.count = 0;
    s.dispatch_count.store(0);
    s.miss_count.store(0);


    s.veh_handle = AddVectoredExceptionHandler(1, detail::nanomite_veh_handler);
    if (!s.veh_handle)
        return false;

    s.initialized.store(true, std::memory_order_release);
    return true;
}


inline uint32_t protect_function(uintptr_t func_addr, size_t func_size)
{
    auto& s = detail::state();
    if (!s.initialized.load()) return 0;

    std::lock_guard<std::mutex> lk(s.mtx);

    const uint8_t* code = reinterpret_cast<const uint8_t*>(func_addr);
    uint32_t replaced = 0;


    DWORD old_protect = 0;
    VirtualProtect(reinterpret_cast<LPVOID>(func_addr),
        func_size, PAGE_EXECUTE_READWRITE, &old_protect);

    for (size_t offset = 0; offset < func_size && s.count < detail::MAX_NANOMITES; )
    {
        detail::jcc_info_t jcc{};
        if (detail::decode_jcc_at(&code[offset], func_addr + offset, jcc))
        {

            int64_t distance = static_cast<int64_t>(jcc.target) -
                               static_cast<int64_t>(jcc.fall_through);
            if (distance == 0)
            {
                offset += jcc.insn_len;
                continue;
            }


            detail::nanomite_entry_t entry{};
            entry.int3_addr         = jcc.addr;
            entry.taken_target      = jcc.target;
            entry.fall_through      = jcc.fall_through;
            entry.condition         = jcc.cc;
            entry.original_insn_len = jcc.insn_len;


            entry.guard_hash = detail::compute_guard_hash(
                entry.int3_addr, entry.taken_target, entry.condition, s.session_key);


            detail::encrypt_entry(entry, s.encryption_key);


            s.entries[s.count++] = entry;


            uint8_t* patch_site = const_cast<uint8_t*>(&code[offset]);
            patch_site[0] = 0xCC;
            for (uint8_t i = 1; i < jcc.insn_len; ++i)
                patch_site[i] = 0x90;

            replaced++;
            offset += jcc.insn_len;
        }
        else
        {


            offset++;
        }
    }


    VirtualProtect(reinterpret_cast<LPVOID>(func_addr),
        func_size, old_protect, &old_protect);

    FlushInstructionCache(GetCurrentProcess(),
        reinterpret_cast<LPCVOID>(func_addr), func_size);

    return replaced;
}


inline void rotate_keys()
{
    auto& s = detail::state();
    if (!s.initialized.load()) return;

    std::lock_guard<std::mutex> lk(s.mtx);

    uint64_t new_key = __rdtsc() * 6364136223846793005ULL + 1442695040888963407ULL;

    for (uint32_t i = 0; i < s.count; ++i)
    {

        detail::decrypt_entry(s.entries[i], s.encryption_key);

        detail::encrypt_entry(s.entries[i], new_key);
    }

    s.encryption_key = new_key;
}


inline bool verify_table_integrity()
{
    auto& s = detail::state();
    if (!s.initialized.load()) return true;

    std::lock_guard<std::mutex> lk(s.mtx);

    for (uint32_t i = 0; i < s.count; ++i)
    {
        detail::nanomite_entry_t tmp = s.entries[i];
        detail::decrypt_entry(tmp, s.encryption_key);

        uint64_t expected = detail::compute_guard_hash(
            tmp.int3_addr, tmp.taken_target, tmp.condition, s.session_key);
        if (tmp.guard_hash != expected)
            return false;
    }
    return true;
}


inline uint64_t dispatch_count()
{
    return detail::state().dispatch_count.load(std::memory_order_relaxed);
}


inline void shutdown()
{
    auto& s = detail::state();
    if (!s.initialized.load()) return;

    std::lock_guard<std::mutex> lk(s.mtx);

    if (s.veh_handle)
    {
        RemoveVectoredExceptionHandler(s.veh_handle);
        s.veh_handle = nullptr;
    }


    SecureZeroMemory(s.entries, sizeof(s.entries));
    s.count = 0;
    s.initialized.store(false, std::memory_order_release);
}

}
}
