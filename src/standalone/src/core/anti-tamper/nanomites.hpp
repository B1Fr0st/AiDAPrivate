#pragma once


#include <windows.h>
#include <tlhelp32.h>
#include <intrin.h>

#include <cstdint>
#include <cstring>
#include <mutex>
#include <atomic>
#include <thread>
#include <chrono>
#include <array>
#include <string>
#include <system_error>

#include "ghost_veh.hpp"
#include "../infra/win_thread.hpp"

namespace anti_tamper {
namespace nanomites {

namespace siphash_detail {

    __forceinline uint64_t rotl(uint64_t x, int b) { return (x << b) | (x >> (64 - b)); }

    __forceinline void sipround(uint64_t& v0, uint64_t& v1, uint64_t& v2, uint64_t& v3)
    {
        v0 += v1; v1 = rotl(v1, 13); v1 ^= v0; v0 = rotl(v0, 32);
        v2 += v3; v3 = rotl(v3, 16); v3 ^= v2;
        v0 += v3; v3 = rotl(v3, 21); v3 ^= v0;
        v2 += v1; v1 = rotl(v1, 17); v1 ^= v2; v2 = rotl(v2, 32);
    }

}

enum class nano_trap_t : uint8_t
{
    kHwBp = 0
};

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
    static constexpr uint32_t kDrxSlots     = 4;

    struct nanomite_entry_t
    {
        uint64_t         int3_addr;
        uint64_t         taken_target;
        uint64_t         fall_through;
        condition_code_t condition;
        uint8_t          original_insn_len;
        uint8_t          trap_kind;
        uint8_t          _pad;
        uint64_t         guard_hash[2];
    };

    struct nanomite_state_t
    {
        nanomite_entry_t entries[MAX_NANOMITES];
        uint32_t         count;
        uint64_t         session_key[2];
        uint64_t         encryption_key;
        PVOID            veh_handle;
        ghost_veh::registration_t ghost_reg{0};
        std::mutex       mtx;
        std::atomic<bool> initialized{false};
        std::atomic<uint64_t> dispatch_count{0};
        std::atomic<uint64_t> miss_count{0};

        std::atomic<uint64_t> drx_addr[kDrxSlots]{};
        std::atomic<uint32_t> drx_index[kDrxSlots]{};
        std::atomic<uint32_t> rotation_cursor{0};
        std::atomic<bool>     refresher_running{false};
        std::atomic<bool>     refresher_stop{false};
        std::atomic<bool>     refresher_degraded{false};
        std::atomic<uint32_t> refresher_start_error{0};
        aida::infra::win_thread::joinable_thread_t refresher_thread;
        DWORD                 owner_pid{0};
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

    inline void siphash_128(const uint8_t* data, size_t len,
                           uint64_t k0, uint64_t k1,
                           uint64_t& out0, uint64_t& out1)
    {
        uint64_t v0 = 0x736F6D6570736575ULL ^ k0;
        uint64_t v1 = 0x646F72616E646F6DULL ^ k1;
        uint64_t v2 = 0x6C7967656E657261ULL ^ k0;
        uint64_t v3 = 0x7465646279746573ULL ^ k1;
        v1 ^= 0xEE;

        const uint8_t* end = data + len - (len % 8);
        const int left = static_cast<int>(len & 7);
        uint64_t b = static_cast<uint64_t>(len) << 56;

        for (; data != end; data += 8)
        {
            uint64_t m;
            memcpy(&m, data, 8);
            v3 ^= m;
            siphash_detail::sipround(v0, v1, v2, v3);
            siphash_detail::sipround(v0, v1, v2, v3);
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
        siphash_detail::sipround(v0, v1, v2, v3);
        siphash_detail::sipround(v0, v1, v2, v3);
        v0 ^= b;

        v2 ^= 0xEE;
        siphash_detail::sipround(v0, v1, v2, v3);
        siphash_detail::sipround(v0, v1, v2, v3);
        siphash_detail::sipround(v0, v1, v2, v3);
        siphash_detail::sipround(v0, v1, v2, v3);
        out0 = v0 ^ v1 ^ v2 ^ v3;

        v1 ^= 0xDD;
        siphash_detail::sipround(v0, v1, v2, v3);
        siphash_detail::sipround(v0, v1, v2, v3);
        siphash_detail::sipround(v0, v1, v2, v3);
        siphash_detail::sipround(v0, v1, v2, v3);
        out1 = v0 ^ v1 ^ v2 ^ v3;
    }

    inline void compute_guard_hash(uint64_t addr, uint64_t target,
                                   uint64_t fall_through, uint8_t cc,
                                   uint8_t trap_kind,
                                   const uint64_t sip_key[2],
                                   uint64_t out[2])
    {
        uint8_t data[40];
        memcpy(data, &addr, 8);
        memcpy(data + 8, &target, 8);
        memcpy(data + 16, &fall_through, 8);
        uint64_t cc_packed = static_cast<uint64_t>(cc);
        memcpy(data + 24, &cc_packed, 8);
        uint64_t tk_packed = static_cast<uint64_t>(trap_kind);
        memcpy(data + 32, &tk_packed, 8);
        siphash_128(data, 40, sip_key[0], sip_key[1], out[0], out[1]);
    }


    inline bool lookup_decrypted(uint64_t rip, nanomite_entry_t& out_entry, uint32_t& out_index)
    {
        auto& s = state();

        for (uint32_t i = 0; i < s.count; ++i)
        {
            nanomite_entry_t tmp = s.entries[i];
            decrypt_entry(tmp, s.encryption_key);
            if (tmp.int3_addr == rip)
            {
                uint64_t expected[2];
                compute_guard_hash(
                    tmp.int3_addr, tmp.taken_target, tmp.fall_through,
                    tmp.condition, tmp.trap_kind, s.session_key, expected);
                if (tmp.guard_hash[0] != expected[0] || tmp.guard_hash[1] != expected[1])
                    return false;

                out_entry = tmp;
                out_index = i;
                return true;
            }
        }
        return false;
    }


    inline bool lookup_decrypted_by_index(uint32_t idx, nanomite_entry_t& out_entry)
    {
        auto& s = state();
        if (idx >= s.count) return false;

        nanomite_entry_t tmp = s.entries[idx];
        decrypt_entry(tmp, s.encryption_key);

        uint64_t expected[2];
        compute_guard_hash(
            tmp.int3_addr, tmp.taken_target, tmp.fall_through,
            tmp.condition, tmp.trap_kind, s.session_key, expected);
        if (tmp.guard_hash[0] != expected[0] || tmp.guard_hash[1] != expected[1])
            return false;

        out_entry = tmp;
        return true;
    }


    inline DWORD64 build_dr7(const uint64_t addrs[kDrxSlots], uint8_t count)
    {
        DWORD64 dr7 = 0;
        for (uint8_t i = 0; i < count && i < kDrxSlots; ++i)
        {
            if (addrs[i] == 0) continue;
            dr7 |= (DWORD64{1} << (i * 2));
        }
        dr7 |= (DWORD64{1} << 8);
        dr7 |= (DWORD64{1} << 9);
        return dr7;
    }


    struct drx_apply_args_t
    {
        HANDLE   target;
        uint64_t addrs[kDrxSlots];
        uint8_t  count;
        BOOL     ok;
    };

    inline DWORD WINAPI drx_apply_proc(LPVOID p)
    {
        drx_apply_args_t* a = reinterpret_cast<drx_apply_args_t*>(p);
        a->ok = FALSE;

        DWORD susp = SuspendThread(a->target);
        if (susp == static_cast<DWORD>(-1)) return 0;

        CONTEXT ctx{};
        ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
        if (!GetThreadContext(a->target, &ctx))
        {
            ResumeThread(a->target);
            return 0;
        }

        ctx.Dr0 = (a->count > 0) ? static_cast<DWORD64>(a->addrs[0]) : 0;
        ctx.Dr1 = (a->count > 1) ? static_cast<DWORD64>(a->addrs[1]) : 0;
        ctx.Dr2 = (a->count > 2) ? static_cast<DWORD64>(a->addrs[2]) : 0;
        ctx.Dr3 = (a->count > 3) ? static_cast<DWORD64>(a->addrs[3]) : 0;

        DWORD64 dr7 = 0;
        for (uint8_t i = 0; i < a->count && i < kDrxSlots; ++i)
        {
            if (a->addrs[i] == 0) continue;
            dr7 |= (DWORD64{1} << (i * 2));
        }
        dr7 |= (DWORD64{1} << 8);
        dr7 |= (DWORD64{1} << 9);

        ctx.Dr7 = dr7;
        ctx.Dr6 = 0;
        ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;

        a->ok = SetThreadContext(a->target, &ctx);
        ResumeThread(a->target);
        return 0;
    }

    inline bool apply_drx_to_thread(HANDLE hThread, const uint64_t addrs[kDrxSlots], uint8_t count)
    {
        if (hThread == nullptr || hThread == INVALID_HANDLE_VALUE) return false;

        bool is_self = (GetThreadId(hThread) == GetCurrentThreadId());

        if (!is_self)
        {
            CONTEXT ctx{};
            ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;

            DWORD suspend = SuspendThread(hThread);
            if (suspend == static_cast<DWORD>(-1)) return false;

            if (!GetThreadContext(hThread, &ctx))
            {
                ResumeThread(hThread);
                return false;
            }

            ctx.Dr0 = (count > 0) ? static_cast<DWORD64>(addrs[0]) : 0;
            ctx.Dr1 = (count > 1) ? static_cast<DWORD64>(addrs[1]) : 0;
            ctx.Dr2 = (count > 2) ? static_cast<DWORD64>(addrs[2]) : 0;
            ctx.Dr3 = (count > 3) ? static_cast<DWORD64>(addrs[3]) : 0;

            ctx.Dr7 = build_dr7(addrs, count);
            ctx.Dr6 = 0;
            ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;

            BOOL ok = SetThreadContext(hThread, &ctx);
            ResumeThread(hThread);
            return ok != FALSE;
        }

        HANDLE real_handle = nullptr;
        if (!DuplicateHandle(GetCurrentProcess(), GetCurrentThread(),
                             GetCurrentProcess(), &real_handle,
                             THREAD_GET_CONTEXT | THREAD_SET_CONTEXT | THREAD_SUSPEND_RESUME,
                             FALSE, 0))
        {
            return false;
        }

        drx_apply_args_t args{};
        args.target = real_handle;
        for (uint8_t i = 0; i < kDrxSlots; ++i) args.addrs[i] = (i < count) ? addrs[i] : 0;
        args.count = count;
        args.ok = FALSE;

        HANDLE worker = CreateThread(nullptr, 0, drx_apply_proc, &args, 0, nullptr);
        if (worker == nullptr)
        {
            CloseHandle(real_handle);
            return false;
        }
        WaitForSingleObject(worker, INFINITE);
        CloseHandle(worker);
        CloseHandle(real_handle);
        return args.ok != FALSE;
    }


    inline void choose_active_addresses(uint64_t out_addrs[kDrxSlots],
                                        uint32_t out_indices[kDrxSlots],
                                        uint8_t& out_count)
    {
        auto& s = state();
        out_count = 0;

        if (s.count == 0)
        {
            for (uint32_t i = 0; i < kDrxSlots; ++i)
            {
                out_addrs[i] = 0;
                out_indices[i] = 0xFFFFFFFFu;
            }
            return;
        }

        uint32_t cursor = s.rotation_cursor.load(std::memory_order_relaxed);
        uint8_t  picked = 0;
        uint32_t scanned = 0;
        uint32_t total = s.count;

        while (picked < kDrxSlots && scanned < total)
        {
            uint32_t idx = (cursor + scanned) % total;
            scanned++;

            nanomite_entry_t tmp;
            if (!lookup_decrypted_by_index(idx, tmp))
                continue;

            out_addrs[picked]   = tmp.int3_addr;
            out_indices[picked] = idx;
            picked++;
        }

        for (uint8_t j = picked; j < kDrxSlots; ++j)
        {
            out_addrs[j] = 0;
            out_indices[j] = 0xFFFFFFFFu;
        }
        out_count = picked;
    }


    inline void publish_active_slots(const uint64_t addrs[kDrxSlots],
                                     const uint32_t indices[kDrxSlots])
    {
        auto& s = state();
        for (uint32_t i = 0; i < kDrxSlots; ++i)
        {
            s.drx_addr[i].store(addrs[i], std::memory_order_release);
            s.drx_index[i].store(indices[i], std::memory_order_release);
        }
    }


    inline LONG CALLBACK nanomite_veh_handler(PEXCEPTION_POINTERS info)
    {
        auto& s = state();
        if (!s.initialized.load(std::memory_order_acquire))
            return EXCEPTION_CONTINUE_SEARCH;

        DWORD ec = info->ExceptionRecord->ExceptionCode;
        if (ec != static_cast<DWORD>(EXCEPTION_SINGLE_STEP))
            return EXCEPTION_CONTINUE_SEARCH;

        DWORD64 dr6 = info->ContextRecord->Dr6;
        DWORD64 hit_mask = dr6 & 0xFULL;
        if (hit_mask == 0)
            return EXCEPTION_CONTINUE_SEARCH;

        uint64_t rip = static_cast<uint64_t>(info->ContextRecord->Rip);

        uint8_t hit_slot = 0xFF;
        for (uint8_t i = 0; i < kDrxSlots; ++i)
        {
            if (((hit_mask >> i) & 0x1ULL) != 0)
            {
                DWORD64 dr_val = 0;
                switch (i)
                {
                case 0: dr_val = info->ContextRecord->Dr0; break;
                case 1: dr_val = info->ContextRecord->Dr1; break;
                case 2: dr_val = info->ContextRecord->Dr2; break;
                case 3: dr_val = info->ContextRecord->Dr3; break;
                }
                if (dr_val == rip)
                {
                    hit_slot = i;
                    break;
                }
            }
        }

        if (hit_slot == 0xFF)
            return EXCEPTION_CONTINUE_SEARCH;

        nanomite_entry_t entry{};
        bool found = false;
        {
            std::lock_guard<std::mutex> lk(s.mtx);
            uint32_t cached_idx = s.drx_index[hit_slot].load(std::memory_order_acquire);
            uint64_t cached_addr = s.drx_addr[hit_slot].load(std::memory_order_acquire);
            if (cached_addr == rip && cached_idx != 0xFFFFFFFFu)
            {
                if (lookup_decrypted_by_index(cached_idx, entry))
                    found = true;
            }
            if (!found)
            {
                uint32_t any_idx = 0;
                if (lookup_decrypted(rip, entry, any_idx))
                    found = true;
            }
        }

        if (!found)
        {
            s.miss_count.fetch_add(1, std::memory_order_relaxed);
            return EXCEPTION_CONTINUE_SEARCH;
        }

        s.dispatch_count.fetch_add(1, std::memory_order_relaxed);

        uint64_t rflags = static_cast<uint64_t>(info->ContextRecord->EFlags);
        bool take_branch = evaluate_condition(entry.condition, rflags);

        if (take_branch)
            info->ContextRecord->Rip = entry.taken_target;
        else
            info->ContextRecord->Rip = entry.fall_through;

        info->ContextRecord->Dr6 = dr6 & ~static_cast<DWORD64>(0xFULL);
        info->ContextRecord->EFlags &= ~static_cast<DWORD>(0x10000);

        s.rotation_cursor.fetch_add(1, std::memory_order_relaxed);

        return EXCEPTION_CONTINUE_EXECUTION;
    }

    inline long nanomite_ghost_handler(PEXCEPTION_POINTERS info, void*)
    {
        return nanomite_veh_handler(info);
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


namespace detail {

    inline std::array<uint64_t, kDrxSlots>& last_drx_addrs_ref()
    {
        static std::array<uint64_t, kDrxSlots> g{ 0, 0, 0, 0 };
        return g;
    }

    inline std::atomic<bool>& last_drx_addrs_valid_ref()
    {
        static std::atomic<bool> v{ false };
        return v;
    }

}

inline bool refresh_all_threads()
{
    auto& s = detail::state();
    if (!s.initialized.load(std::memory_order_acquire)) return false;

    uint64_t addrs[detail::kDrxSlots] = {0, 0, 0, 0};
    uint32_t indices[detail::kDrxSlots] = {0xFFFFFFFFu, 0xFFFFFFFFu, 0xFFFFFFFFu, 0xFFFFFFFFu};
    uint8_t  count = 0;

    {
        std::lock_guard<std::mutex> lk(s.mtx);
        detail::choose_active_addresses(addrs, indices, count);
        detail::publish_active_slots(addrs, indices);
    }

    if (count == 0) return true;

    auto& last = detail::last_drx_addrs_ref();
    auto& last_valid = detail::last_drx_addrs_valid_ref();
    bool unchanged = last_valid.load(std::memory_order_acquire)
        && last[0] == addrs[0]
        && last[1] == addrs[1]
        && last[2] == addrs[2]
        && last[3] == addrs[3];
    if (unchanged) return true;

    DWORD owner_pid = s.owner_pid != 0 ? s.owner_pid : GetCurrentProcessId();
    DWORD self_tid  = GetCurrentThreadId();

    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (snap == INVALID_HANDLE_VALUE) return false;

    THREADENTRY32 te{};
    te.dwSize = sizeof(te);

    bool overall_ok = true;
    if (Thread32First(snap, &te))
    {
        do
        {
            if (te.th32OwnerProcessID != owner_pid) continue;
            if (te.th32ThreadID == self_tid) continue;

            HANDLE hThread = OpenThread(
                THREAD_GET_CONTEXT | THREAD_SET_CONTEXT | THREAD_SUSPEND_RESUME,
                FALSE, te.th32ThreadID);
            if (hThread == nullptr) continue;

            if (!detail::apply_drx_to_thread(hThread, addrs, count))
                overall_ok = false;

            CloseHandle(hThread);
            te.dwSize = sizeof(te);
        } while (Thread32Next(snap, &te));
    }

    CloseHandle(snap);

    if (overall_ok)
    {
        last[0] = addrs[0];
        last[1] = addrs[1];
        last[2] = addrs[2];
        last[3] = addrs[3];
        last_valid.store(true, std::memory_order_release);
    }

    return overall_ok;
}


inline bool install_drx_for_thread(HANDLE hThread, uint64_t selected_addrs[detail::kDrxSlots], uint8_t count)
{
    auto& s = detail::state();
    if (!s.initialized.load(std::memory_order_acquire)) return false;
    if (count > detail::kDrxSlots) count = detail::kDrxSlots;
    return detail::apply_drx_to_thread(hThread, selected_addrs, count);
}


inline void rotate_drx_assignment()
{
    auto& s = detail::state();
    if (!s.initialized.load(std::memory_order_acquire)) return;

    uint32_t step = (s.count == 0) ? 1 : (1 + (s.count / detail::kDrxSlots));
    s.rotation_cursor.fetch_add(step, std::memory_order_relaxed);
    refresh_all_threads();
}


namespace detail {

    inline void refresher_thread_proc()
    {
        auto& s = state();
        s.refresher_running.store(true, std::memory_order_release);
        while (!s.refresher_stop.load(std::memory_order_acquire))
        {
            refresh_all_threads();
            for (int i = 0; i < 5; ++i)
            {
                if (s.refresher_stop.load(std::memory_order_acquire)) break;
                std::this_thread::sleep_for(std::chrono::milliseconds(50));
            }
        }
        s.refresher_running.store(false, std::memory_order_release);
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
    s.rotation_cursor.store(0);
    s.owner_pid = GetCurrentProcessId();
    for (uint32_t i = 0; i < detail::kDrxSlots; ++i)
    {
        s.drx_addr[i].store(0);
        s.drx_index[i].store(0xFFFFFFFFu);
    }


    if (ghost_veh::is_active())
    {
        s.ghost_reg = ghost_veh::register_handler(
            ghost_veh::ex_kind::kSingleStep,
            detail::nanomite_ghost_handler, nullptr);
        if (s.ghost_reg.id == 0)
        {
            s.veh_handle = AddVectoredExceptionHandler(1, detail::nanomite_veh_handler);
            if (!s.veh_handle)
                return false;
        }
        else
        {
            s.veh_handle = nullptr;
        }
    }
    else
    {
        s.veh_handle = AddVectoredExceptionHandler(1, detail::nanomite_veh_handler);
        if (!s.veh_handle)
            return false;
    }

    s.initialized.store(true, std::memory_order_release);

    s.refresher_stop.store(false, std::memory_order_release);
    s.refresher_degraded.store(false, std::memory_order_release);
    s.refresher_start_error.store(0, std::memory_order_release);
    try
    {
        std::string err;
        if (!s.refresher_thread.start(detail::refresher_thread_proc,
                &err,
                aida::infra::win_thread::default_stack_reserve,
                "nanomite_refresher"))
        {
            s.refresher_degraded.store(true, std::memory_order_release);
            s.refresher_running.store(false, std::memory_order_release);
            s.refresher_start_error.store(GetLastError(), std::memory_order_release);
            diag::log_tagged_fmt("nanomite",
                "refresher_thread_start_failed err=%s",
                err.empty() ? "<none>" : err.c_str());
        }
    }
    catch (const std::system_error& ex)
    {
        s.refresher_degraded.store(true, std::memory_order_release);
        s.refresher_running.store(false, std::memory_order_release);
        s.refresher_start_error.store(static_cast<uint32_t>(ex.code().value()), std::memory_order_release);
    }
    catch (const std::exception&)
    {
        s.refresher_degraded.store(true, std::memory_order_release);
        s.refresher_running.store(false, std::memory_order_release);
        s.refresher_start_error.store(GetLastError(), std::memory_order_release);
    }
    catch (...)
    {
        s.refresher_degraded.store(true, std::memory_order_release);
        s.refresher_running.store(false, std::memory_order_release);
        s.refresher_start_error.store(GetLastError(), std::memory_order_release);
    }

    return true;
}


inline uint32_t protect_function(uintptr_t func_addr, size_t func_size)
{
    auto& s = detail::state();
    if (!s.initialized.load()) return 0;

    std::lock_guard<std::mutex> lk(s.mtx);

    const uint8_t* code = reinterpret_cast<const uint8_t*>(func_addr);
    uint32_t replaced = 0;

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
            entry.trap_kind         = static_cast<uint8_t>(nano_trap_t::kHwBp);

            detail::compute_guard_hash(
                entry.int3_addr, entry.taken_target, entry.fall_through,
                entry.condition, entry.trap_kind, s.session_key, entry.guard_hash);

            detail::encrypt_entry(entry, s.encryption_key);

            s.entries[s.count++] = entry;

            replaced++;
            offset += jcc.insn_len;
        }
        else
        {
            offset++;
        }
    }

    if (replaced > 0)
    {
        uint64_t addrs[detail::kDrxSlots] = {0, 0, 0, 0};
        uint32_t indices[detail::kDrxSlots] = {0xFFFFFFFFu, 0xFFFFFFFFu, 0xFFFFFFFFu, 0xFFFFFFFFu};
        uint8_t  count = 0;
        detail::choose_active_addresses(addrs, indices, count);
        detail::publish_active_slots(addrs, indices);

        uint64_t local_addrs[detail::kDrxSlots] = {addrs[0], addrs[1], addrs[2], addrs[3]};
        HANDLE me = GetCurrentThread();
        detail::apply_drx_to_thread(me, local_addrs, count);
    }

    return replaced;
}


inline void rotate_keys()
{
    auto& s = detail::state();
    if (!s.initialized.load()) return;

    {
        std::lock_guard<std::mutex> lk(s.mtx);

        uint64_t new_key = __rdtsc() * 6364136223846793005ULL + 1442695040888963407ULL;

        for (uint32_t i = 0; i < s.count; ++i)
        {
            detail::decrypt_entry(s.entries[i], s.encryption_key);
            detail::encrypt_entry(s.entries[i], new_key);
        }

        s.encryption_key = new_key;
    }

    if (s.refresher_degraded.load(std::memory_order_acquire))
        refresh_all_threads();
}

inline bool refresher_degraded()
{
    return detail::state().refresher_degraded.load(std::memory_order_acquire);
}

inline bool refresher_running()
{
    return detail::state().refresher_running.load(std::memory_order_acquire);
}

inline uint32_t refresher_start_error()
{
    return detail::state().refresher_start_error.load(std::memory_order_acquire);
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

        uint64_t expected[2];
        detail::compute_guard_hash(
            tmp.int3_addr, tmp.taken_target, tmp.fall_through,
            tmp.condition, tmp.trap_kind, s.session_key, expected);
        if (expected[0] != tmp.guard_hash[0] || expected[1] != tmp.guard_hash[1])
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

    s.refresher_stop.store(true, std::memory_order_release);
    if (s.refresher_thread.joinable())
        s.refresher_thread.join();

    {
        std::lock_guard<std::mutex> lk(s.mtx);

        uint64_t zero_addrs[detail::kDrxSlots] = {0, 0, 0, 0};
        DWORD owner_pid = s.owner_pid != 0 ? s.owner_pid : GetCurrentProcessId();
        DWORD self_tid  = GetCurrentThreadId();
        HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
        if (snap != INVALID_HANDLE_VALUE)
        {
            THREADENTRY32 te{};
            te.dwSize = sizeof(te);
            if (Thread32First(snap, &te))
            {
                do
                {
                    if (te.th32OwnerProcessID != owner_pid) { te.dwSize = sizeof(te); continue; }
                    if (te.th32ThreadID == self_tid) { te.dwSize = sizeof(te); continue; }
                    HANDLE hThread = OpenThread(
                        THREAD_GET_CONTEXT | THREAD_SET_CONTEXT | THREAD_SUSPEND_RESUME,
                        FALSE, te.th32ThreadID);
                    if (hThread != nullptr)
                    {
                        detail::apply_drx_to_thread(hThread, zero_addrs, 0);
                        CloseHandle(hThread);
                    }
                    te.dwSize = sizeof(te);
                } while (Thread32Next(snap, &te));
            }
            CloseHandle(snap);
        }
        detail::apply_drx_to_thread(GetCurrentThread(), zero_addrs, 0);

        if (s.veh_handle)
        {
            RemoveVectoredExceptionHandler(s.veh_handle);
            s.veh_handle = nullptr;
        }
        if (s.ghost_reg.id != 0)
        {
            ghost_veh::unregister_handler(s.ghost_reg);
            s.ghost_reg.id = 0;
        }

        SecureZeroMemory(s.entries, sizeof(s.entries));
        s.count = 0;
        for (uint32_t i = 0; i < detail::kDrxSlots; ++i)
        {
            s.drx_addr[i].store(0);
            s.drx_index[i].store(0xFFFFFFFFu);
        }
        s.initialized.store(false, std::memory_order_release);
    }
}

}
}
