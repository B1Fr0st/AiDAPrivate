#pragma once

#include <windows.h>
#include <intrin.h>

#include <atomic>
#include <cstdint>
#include <cstring>
#include <mutex>

#ifdef AIDA_STANDALONE
#include <Zydis/Zydis.h>
#endif

namespace anti_tamper {
namespace ghost_veh {

enum class ex_kind : uint32_t
{
    kBreakpoint = 0,
    kIllegal    = 1,
    kAccess     = 2,
    kSingleStep = 3,
    kInt2d      = 4,
    kAny        = 0xFFFFFFFFu
};

using handler_fn = long (*)(PEXCEPTION_POINTERS ep, void* user);

struct registration_t
{
    uint32_t id;
};

namespace detail {

    constexpr uint32_t kMaxHandlers = 32;
    constexpr size_t   kDetourSize  = 14;
    constexpr size_t   kMaxSavedLen = 32;

    struct slot_t
    {
        uint32_t kind;
        uint32_t active;
        uint64_t fn_xor;
        uint64_t user_xor;
        uint64_t nonce;
    };

    struct state_t
    {
        std::mutex        mtx;
        std::atomic<bool> initialized{false};
        std::atomic<bool> active{false};
        uint64_t          session_key[2]{};
        slot_t            slots[kMaxHandlers]{};
        uint32_t          next_id{1};

        uint8_t*          dispatcher{nullptr};
        uint8_t           saved_bytes[kMaxSavedLen]{};
        size_t            saved_len{0};
        uint8_t*          trampoline{nullptr};
        size_t            trampoline_size{0};
        uint64_t          detour_hash{0};
    };

    inline state_t& state()
    {
        static state_t s{};
        return s;
    }

    inline std::atomic<uint32_t>& ghost_flags_ref()
    {
        static std::atomic<uint32_t> g{0};
        return g;
    }

    inline uint64_t mix_key(uint64_t a, uint64_t b, uint64_t k0, uint64_t k1)
    {
        uint64_t v = a ^ k0;
        v  = _rotl64(v, 13) + (b ^ k1);
        v ^= _rotl64(v, 29) * 0x9E3779B97F4A7C15ULL;
        v  = _rotl64(v, 17) + 0xD6E8FEB86659FD93ULL;
        return v;
    }

    inline uint64_t hash_bytes(const uint8_t* p, size_t n)
    {
        uint64_t h = 0xCBF29CE484222325ULL;
        for (size_t i = 0; i < n; ++i)
        {
            h ^= p[i];
            h *= 0x100000001B3ULL;
        }
        return h;
    }

    inline uint8_t* resolve_export(HMODULE mod, const char* name)
    {
        if (!mod) return nullptr;
        auto* base = reinterpret_cast<uint8_t*>(mod);
        auto* dos  = reinterpret_cast<IMAGE_DOS_HEADER*>(base);
        if (dos->e_magic != IMAGE_DOS_SIGNATURE) return nullptr;
        auto* nt = reinterpret_cast<IMAGE_NT_HEADERS*>(base + dos->e_lfanew);
        if (nt->Signature != IMAGE_NT_SIGNATURE) return nullptr;
        auto& dir = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
        if (dir.Size == 0) return nullptr;
        auto* exp   = reinterpret_cast<IMAGE_EXPORT_DIRECTORY*>(base + dir.VirtualAddress);
        auto* funcs = reinterpret_cast<uint32_t*>(base + exp->AddressOfFunctions);
        auto* names = reinterpret_cast<uint32_t*>(base + exp->AddressOfNames);
        auto* ords  = reinterpret_cast<uint16_t*>(base + exp->AddressOfNameOrdinals);
        for (uint32_t i = 0; i < exp->NumberOfNames; ++i)
        {
            const char* n = reinterpret_cast<const char*>(base + names[i]);
            if (strcmp(n, name) == 0)
                return base + funcs[ords[i]];
        }
        return nullptr;
    }

    inline uint8_t* find_dispatcher()
    {
        HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
        if (!ntdll) return nullptr;
        uint8_t* p = resolve_export(ntdll, "KiUserExceptionDispatcher");
        if (p) return p;

        auto* base = reinterpret_cast<uint8_t*>(ntdll);
        auto* dos  = reinterpret_cast<IMAGE_DOS_HEADER*>(base);
        if (dos->e_magic != IMAGE_DOS_SIGNATURE) return nullptr;
        auto* nt = reinterpret_cast<IMAGE_NT_HEADERS*>(base + dos->e_lfanew);
        if (nt->Signature != IMAGE_NT_SIGNATURE) return nullptr;

        const uint8_t pat[] = { 0x48, 0x8B, 0x0C, 0x24, 0x48, 0x8B, 0x04, 0x24, 0xE8 };
        uint8_t* scan     = base + nt->OptionalHeader.BaseOfCode;
        size_t   scan_len = nt->OptionalHeader.SizeOfCode;
        if (scan_len > 0x200) scan_len = 0x200;
        for (size_t i = 0; i + sizeof(pat) < scan_len; ++i)
        {
            if (memcmp(scan + i, pat, sizeof(pat)) == 0)
                return scan + i;
        }
        return nullptr;
    }

#ifdef AIDA_STANDALONE
    inline bool measure_prolog(const uint8_t* code, size_t min_bytes, size_t& out_len)
    {
        ZydisDecoder dec;
        if (!ZYAN_SUCCESS(ZydisDecoderInit(&dec, ZYDIS_MACHINE_MODE_LONG_64,
                                           ZYDIS_STACK_WIDTH_64)))
            return false;

        size_t pos = 0;
        while (pos < min_bytes)
        {
            ZydisDecodedInstruction ins;
            ZydisDecodedOperand     ops[ZYDIS_MAX_OPERAND_COUNT];
            if (!ZYAN_SUCCESS(ZydisDecoderDecodeFull(
                    &dec, code + pos, 16, &ins, ops)))
                return false;

            for (uint8_t i = 0; i < ins.operand_count; ++i)
            {
                if (ops[i].type == ZYDIS_OPERAND_TYPE_MEMORY &&
                    ops[i].mem.base == ZYDIS_REGISTER_RIP)
                    return false;
            }

            switch (ins.meta.category)
            {
            case ZYDIS_CATEGORY_CALL:
            case ZYDIS_CATEGORY_COND_BR:
            case ZYDIS_CATEGORY_UNCOND_BR:
            case ZYDIS_CATEGORY_RET:
            case ZYDIS_CATEGORY_INTERRUPT:
                return false;
            default:
                break;
            }

            pos += ins.length;
            if (pos > kMaxSavedLen) return false;
        }
        out_len = pos;
        return true;
    }
#else
    inline bool measure_prolog(const uint8_t*, size_t, size_t&) { return false; }
#endif

    inline long dispatch(PEXCEPTION_POINTERS ep);

    inline __declspec(noinline) long ghost_veh_thunk(PEXCEPTION_POINTERS ep)
    {
        return dispatch(ep);
    }

    inline uint8_t* build_trampoline(uint8_t* dispatcher,
                                     const uint8_t* saved, size_t saved_len)
    {
        HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
        uint8_t* nt_continue = resolve_export(ntdll, "NtContinue");
        if (!nt_continue) return nullptr;

        size_t sz = 256 + saved_len;
        uint8_t* mem = static_cast<uint8_t*>(
            VirtualAlloc(nullptr, sz, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE));
        if (!mem) return nullptr;

        uint8_t* p = mem;
        auto emit1 = [&](uint8_t b) { *p++ = b; };
        auto emit2 = [&](uint8_t a, uint8_t b) { *p++ = a; *p++ = b; };
        auto emit_qword = [&](uint64_t v) { std::memcpy(p, &v, 8); p += 8; };
        auto emit_dword = [&](uint32_t v) { std::memcpy(p, &v, 4); p += 4; };

        emit1(0x48); emit1(0x83); emit1(0xEC); emit1(0x38);

        emit1(0x48); emit1(0x8D); emit1(0x54); emit1(0x24); emit1(0x38);

        emit1(0x48); emit1(0x8D); emit1(0x8C); emit1(0x24);
        emit_dword(0x38u + static_cast<uint32_t>(sizeof(CONTEXT)));

        emit1(0x48); emit1(0x89); emit1(0x4C); emit1(0x24); emit1(0x20);
        emit1(0x48); emit1(0x89); emit1(0x54); emit1(0x24); emit1(0x28);

        emit1(0x48); emit1(0x8D); emit1(0x4C); emit1(0x24); emit1(0x20);

        emit2(0x48, 0xB8);
        emit_qword(reinterpret_cast<uint64_t>(&ghost_veh_thunk));

        emit2(0xFF, 0xD0);

        emit1(0x83); emit1(0xF8); emit1(0xFF);

        emit1(0x75);
        uint8_t* jne_fix = p;
        emit1(0x00);

        emit1(0x48); emit1(0x8B); emit1(0x4C); emit1(0x24); emit1(0x28);
        emit2(0x31, 0xD2);
        emit1(0x48); emit1(0x83); emit1(0xC4); emit1(0x38);
        emit2(0x48, 0xB8);
        emit_qword(reinterpret_cast<uint64_t>(nt_continue));
        emit2(0xFF, 0xE0);

        *jne_fix = static_cast<uint8_t>(p - (jne_fix + 1));

        emit1(0x48); emit1(0x83); emit1(0xC4); emit1(0x38);

        std::memcpy(p, saved, saved_len);
        p += saved_len;

        emit2(0x48, 0xB8);
        emit_qword(reinterpret_cast<uint64_t>(dispatcher + saved_len));
        emit2(0xFF, 0xE0);

        DWORD old = 0;
        VirtualProtect(mem, sz, PAGE_EXECUTE_READ, &old);
        FlushInstructionCache(GetCurrentProcess(), mem, sz);
        return mem;
    }

    inline bool matches_kind(uint32_t slot_kind, PEXCEPTION_POINTERS ep)
    {
        if (slot_kind == static_cast<uint32_t>(ex_kind::kAny)) return true;
        DWORD code = ep->ExceptionRecord->ExceptionCode;
        switch (static_cast<ex_kind>(slot_kind))
        {
        case ex_kind::kBreakpoint: return code == EXCEPTION_BREAKPOINT;
        case ex_kind::kIllegal:    return code == EXCEPTION_ILLEGAL_INSTRUCTION;
        case ex_kind::kAccess:     return code == EXCEPTION_ACCESS_VIOLATION;
        case ex_kind::kSingleStep: return code == EXCEPTION_SINGLE_STEP;
        case ex_kind::kInt2d:      return code == EXCEPTION_BREAKPOINT;
        default: return false;
        }
    }

    inline long dispatch(PEXCEPTION_POINTERS ep)
    {
        auto& s = state();
        if (!s.active.load(std::memory_order_acquire))
            return EXCEPTION_CONTINUE_SEARCH;

        for (uint32_t i = 0; i < kMaxHandlers; ++i)
        {
            slot_t slot;
            std::memcpy(&slot, &s.slots[i], sizeof(slot));
            if (!slot.active) continue;
            if (!matches_kind(slot.kind, ep)) continue;

            auto fn = reinterpret_cast<handler_fn>(slot.fn_xor ^ slot.nonce);
            void* user = reinterpret_cast<void*>(
                slot.user_xor ^ _rotl64(slot.nonce, 13));
            long r = fn(ep, user);
            if (r == EXCEPTION_CONTINUE_EXECUTION) return r;
        }
        return EXCEPTION_CONTINUE_SEARCH;
    }

}

inline bool is_active()
{
    return detail::state().active.load(std::memory_order_acquire);
}

inline uint32_t get_flags()
{
    return detail::ghost_flags_ref().load(std::memory_order_acquire);
}

inline bool initialize()
{
    auto& s = detail::state();
    if (s.initialized.load(std::memory_order_acquire))
        return s.active.load(std::memory_order_acquire);

    std::lock_guard<std::mutex> lk(s.mtx);
    if (s.initialized.load(std::memory_order_relaxed))
        return s.active.load(std::memory_order_relaxed);

    s.initialized.store(true, std::memory_order_release);

    uint64_t tsc = __rdtsc();
    int cpuid_out[4];
    __cpuid(cpuid_out, 1);
    s.session_key[0] = tsc ^ (static_cast<uint64_t>(cpuid_out[0]) << 32);
    s.session_key[1] = _rotl64(tsc, 17) ^ static_cast<uint64_t>(cpuid_out[2]);
    s.next_id = 1;

    uint8_t* disp = detail::find_dispatcher();
    if (!disp) return false;

    size_t prolog_len = 0;
    if (!detail::measure_prolog(disp, detail::kDetourSize, prolog_len))
        return false;
    if (prolog_len < detail::kDetourSize || prolog_len > detail::kMaxSavedLen)
        return false;

    std::memcpy(s.saved_bytes, disp, prolog_len);
    s.saved_len  = prolog_len;
    s.dispatcher = disp;

    uint8_t* tramp = detail::build_trampoline(disp, s.saved_bytes, prolog_len);
    if (!tramp) return false;
    s.trampoline      = tramp;
    s.trampoline_size = 256 + prolog_len;

    DWORD old = 0;
    if (!VirtualProtect(disp, prolog_len, PAGE_EXECUTE_READWRITE, &old))
    {
        VirtualFree(tramp, 0, MEM_RELEASE);
        s.trampoline = nullptr;
        return false;
    }

    uint8_t detour[detail::kDetourSize];
    detour[0] = 0xFF; detour[1] = 0x25;
    detour[2] = 0; detour[3] = 0; detour[4] = 0; detour[5] = 0;
    uint64_t target = reinterpret_cast<uint64_t>(tramp);
    std::memcpy(detour + 6, &target, 8);
    std::memcpy(disp, detour, detail::kDetourSize);
    for (size_t i = detail::kDetourSize; i < prolog_len; ++i)
        disp[i] = 0x90;

    DWORD tmp = 0;
    VirtualProtect(disp, prolog_len, old, &tmp);
    FlushInstructionCache(GetCurrentProcess(), disp, prolog_len);

    s.detour_hash = detail::hash_bytes(disp, detail::kDetourSize);
    s.active.store(true, std::memory_order_release);
    detail::ghost_flags_ref().store(0x1u, std::memory_order_release);
    return true;
}

inline registration_t register_handler(ex_kind kind, handler_fn fn, void* user)
{
    registration_t out{ 0 };
    if (!fn) return out;
    auto& s = detail::state();
    if (!s.active.load(std::memory_order_acquire)) return out;

    std::lock_guard<std::mutex> lk(s.mtx);
    for (uint32_t i = 0; i < detail::kMaxHandlers; ++i)
    {
        if (!s.slots[i].active)
        {
            uint64_t nonce = detail::mix_key(
                static_cast<uint64_t>(s.next_id),
                static_cast<uint64_t>(i),
                s.session_key[0], s.session_key[1]);
            s.slots[i].kind     = static_cast<uint32_t>(kind);
            s.slots[i].nonce    = nonce;
            s.slots[i].fn_xor   = reinterpret_cast<uint64_t>(fn) ^ nonce;
            s.slots[i].user_xor = reinterpret_cast<uint64_t>(user)
                                  ^ _rotl64(nonce, 13);
            s.slots[i].active   = 1;
            uint32_t id = s.next_id++;
            out.id = (id << 8) | (i & 0xFFu);
            return out;
        }
    }
    return out;
}

inline void unregister_handler(registration_t reg)
{
    if (reg.id == 0) return;
    auto& s = detail::state();
    std::lock_guard<std::mutex> lk(s.mtx);
    uint32_t idx = reg.id & 0xFFu;
    if (idx >= detail::kMaxHandlers) return;
    SecureZeroMemory(&s.slots[idx], sizeof(detail::slot_t));
}

inline bool verify_detour()
{
    auto& s = detail::state();
    if (!s.active.load(std::memory_order_acquire)) return true;
    if (!s.dispatcher) return true;
    uint64_t h = detail::hash_bytes(s.dispatcher, detail::kDetourSize);
    return h == s.detour_hash;
}

inline void shutdown()
{
    auto& s = detail::state();
    if (!s.active.load(std::memory_order_acquire)) return;

    std::lock_guard<std::mutex> lk(s.mtx);
    if (s.dispatcher && s.saved_len)
    {
        DWORD old = 0;
        if (VirtualProtect(s.dispatcher, s.saved_len,
                           PAGE_EXECUTE_READWRITE, &old))
        {
            std::memcpy(s.dispatcher, s.saved_bytes, s.saved_len);
            DWORD tmp = 0;
            VirtualProtect(s.dispatcher, s.saved_len, old, &tmp);
            FlushInstructionCache(GetCurrentProcess(),
                                  s.dispatcher, s.saved_len);
        }
    }

    if (s.trampoline)
    {
        VirtualFree(s.trampoline, 0, MEM_RELEASE);
        s.trampoline = nullptr;
    }

    SecureZeroMemory(s.slots, sizeof(s.slots));
    s.active.store(false, std::memory_order_release);
    detail::ghost_flags_ref().store(0u, std::memory_order_release);
}

}
}
