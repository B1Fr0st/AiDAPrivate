#pragma once

#include <windows.h>
#include <bcrypt.h>
#include <intrin.h>

#include <atomic>
#include <chrono>
#include <cstdint>
#include <cstring>
#include <mutex>
#include <thread>

#ifdef AIDA_STANDALONE
#include <Zydis/Zydis.h>
#endif

#pragma comment(lib, "bcrypt.lib")

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
    constexpr size_t   kMaxOffsets  = 3;
    constexpr size_t   kSectionSize = 8192;
    constexpr int64_t  kRegenIntervalMs = 30000;

    struct slot_t
    {
        uint32_t kind;
        uint32_t active;
        uint64_t fn_xor;
        uint64_t user_xor;
        uint64_t nonce;
    };

    struct candidate_offset_t
    {
        uint8_t* dispatcher;
        uint8_t  saved_bytes[kMaxSavedLen];
        size_t   saved_len;
    };

    struct state_t
    {
        std::mutex        mtx;
        std::atomic<bool> initialized{false};
        std::atomic<bool> active{false};
        uint64_t          session_key[2]{};
        slot_t            slots[kMaxHandlers]{};
        uint32_t          next_id{1};

        candidate_offset_t candidates[kMaxOffsets]{};
        uint32_t           candidate_count{0};
        uint32_t           selected_offset{0};

        HANDLE             section_handle{nullptr};
        uint8_t*           tramp_rw{nullptr};
        uint8_t*           tramp_rx{nullptr};
        SIZE_T             section_size{0};

        uint64_t          detour_hash{0};
        uint64_t          current_nonce{0};
        std::atomic<int64_t> last_regen_ms{0};

        std::atomic<bool> regen_thread_running{false};
        std::thread       regen_thread;
        HANDLE            regen_stop_event{nullptr};

        uint64_t          fake_ntdll_ra{0};
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

    inline int64_t now_ms()
    {
        FILETIME ft;
        GetSystemTimeAsFileTime(&ft);
        ULARGE_INTEGER ui;
        ui.LowPart  = ft.dwLowDateTime;
        ui.HighPart = ft.dwHighDateTime;
        return static_cast<int64_t>(ui.QuadPart / 10000ULL);
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

    inline bool gen_random(uint8_t* out, size_t n)
    {
        return BCryptGenRandom(nullptr, out, static_cast<ULONG>(n),
                               BCRYPT_USE_SYSTEM_PREFERRED_RNG) == 0;
    }

    inline uint64_t fresh_nonce()
    {
        uint64_t v = 0;
        if (!gen_random(reinterpret_cast<uint8_t*>(&v), 8))
            v = __rdtsc() ^ (static_cast<uint64_t>(GetCurrentThreadId()) << 32);
        return v ? v : 0xA1DA0CABABCDABCDULL;
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

    inline uint64_t pick_ntdll_text_ra()
    {
        HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
        if (!ntdll) return 0;
        auto* base = reinterpret_cast<uint8_t*>(ntdll);
        auto* dos  = reinterpret_cast<IMAGE_DOS_HEADER*>(base);
        if (dos->e_magic != IMAGE_DOS_SIGNATURE) return 0;
        auto* nt = reinterpret_cast<IMAGE_NT_HEADERS*>(base + dos->e_lfanew);
        if (nt->Signature != IMAGE_NT_SIGNATURE) return 0;
        auto* sec = IMAGE_FIRST_SECTION(nt);
        for (WORD i = 0; i < nt->FileHeader.NumberOfSections; ++i)
        {
            if (sec[i].Characteristics & IMAGE_SCN_MEM_EXECUTE)
            {
                uint8_t* fn = resolve_export(ntdll, "RtlExitUserThread");
                if (fn)
                    return reinterpret_cast<uint64_t>(fn) + 8;
                return reinterpret_cast<uint64_t>(base) +
                       sec[i].VirtualAddress + 0x100;
            }
        }
        return 0;
    }

    inline uint8_t* find_dispatcher_primary()
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
    inline bool measure_prolog_at(const uint8_t* code, size_t min_bytes, size_t& out_len)
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
    inline bool measure_prolog_at(const uint8_t*, size_t, size_t&) { return false; }
#endif

    inline bool collect_candidate_offsets(state_t& s)
    {
        uint8_t* primary = find_dispatcher_primary();
        if (!primary) return false;

        s.candidate_count = 0;

        size_t prolog_len = 0;
        if (measure_prolog_at(primary, kDetourSize, prolog_len) &&
            prolog_len >= kDetourSize && prolog_len <= kMaxSavedLen)
        {
            auto& c = s.candidates[s.candidate_count];
            c.dispatcher = primary;
            c.saved_len  = prolog_len;
            std::memcpy(c.saved_bytes, primary, prolog_len);
            s.candidate_count++;
        }

#ifdef AIDA_STANDALONE
        ZydisDecoder dec;
        if (ZYAN_SUCCESS(ZydisDecoderInit(&dec, ZYDIS_MACHINE_MODE_LONG_64,
                                          ZYDIS_STACK_WIDTH_64)))
        {
            size_t pos = 0;
            int collected = static_cast<int>(s.candidate_count);
            while (pos < 0x80 && collected < static_cast<int>(kMaxOffsets))
            {
                ZydisDecodedInstruction ins;
                ZydisDecodedOperand     ops[ZYDIS_MAX_OPERAND_COUNT];
                if (!ZYAN_SUCCESS(ZydisDecoderDecodeFull(
                        &dec, primary + pos, 16, &ins, ops)))
                    break;
                pos += ins.length;
                if (pos == 0) break;

                size_t plen = 0;
                if (measure_prolog_at(primary + pos, kDetourSize, plen) &&
                    plen >= kDetourSize && plen <= kMaxSavedLen)
                {
                    auto& c = s.candidates[collected];
                    c.dispatcher = primary + pos;
                    c.saved_len  = plen;
                    std::memcpy(c.saved_bytes, primary + pos, plen);
                    collected++;
                }
            }
            s.candidate_count = static_cast<uint32_t>(collected);
        }
#endif
        return s.candidate_count > 0;
    }

    inline long dispatch(PEXCEPTION_POINTERS ep);

    inline __declspec(noinline) long ghost_veh_thunk(PEXCEPTION_POINTERS ep)
    {
        auto& s = state();
        volatile uint64_t fake_anchor = s.fake_ntdll_ra;
        (void)fake_anchor;
        return dispatch(ep);
    }

    using NtCreateSection_t = NTSTATUS(NTAPI*)(
        PHANDLE, ACCESS_MASK, void*, PLARGE_INTEGER, ULONG, ULONG, HANDLE);
    using NtMapViewOfSection_t = NTSTATUS(NTAPI*)(
        HANDLE, HANDLE, PVOID*, ULONG_PTR, SIZE_T, PLARGE_INTEGER,
        PSIZE_T, ULONG, ULONG, ULONG);
    using NtUnmapViewOfSection_t = NTSTATUS(NTAPI*)(HANDLE, PVOID);
    using NtClose_t = NTSTATUS(NTAPI*)(HANDLE);

    inline bool create_dual_mapping(state_t& s, SIZE_T size)
    {
        HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
        if (!ntdll) return false;

        auto pNtCreateSection = reinterpret_cast<NtCreateSection_t>(
            GetProcAddress(ntdll, "NtCreateSection"));
        auto pNtMapViewOfSection = reinterpret_cast<NtMapViewOfSection_t>(
            GetProcAddress(ntdll, "NtMapViewOfSection"));
        if (!pNtCreateSection || !pNtMapViewOfSection)
            return false;

        LARGE_INTEGER li;
        li.QuadPart = static_cast<LONGLONG>(size);

        HANDLE sec = nullptr;
        constexpr ULONG kSectionMapWrite   = 0x0002;
        constexpr ULONG kSectionMapRead    = 0x0004;
        constexpr ULONG kSectionMapExecute = 0x0008;
        constexpr ULONG kSectionAll = kSectionMapWrite | kSectionMapRead |
                                       kSectionMapExecute;
        constexpr ULONG kSecCommit = 0x08000000;

        NTSTATUS st = pNtCreateSection(&sec, kSectionAll, nullptr, &li,
                                       PAGE_EXECUTE_READWRITE,
                                       kSecCommit, nullptr);
        if (st < 0 || !sec) return false;

        PVOID rw_view = nullptr;
        SIZE_T view_size = 0;
        st = pNtMapViewOfSection(sec, GetCurrentProcess(), &rw_view, 0, 0,
                                 nullptr, &view_size, 1,
                                 0, PAGE_READWRITE);
        if (st < 0 || !rw_view)
        {
            CloseHandle(sec);
            return false;
        }

        PVOID rx_view = nullptr;
        SIZE_T rx_size = 0;
        st = pNtMapViewOfSection(sec, GetCurrentProcess(), &rx_view, 0, 0,
                                 nullptr, &rx_size, 1,
                                 0, PAGE_EXECUTE_READ);
        if (st < 0 || !rx_view)
        {
            auto pNtUnmap = reinterpret_cast<NtUnmapViewOfSection_t>(
                GetProcAddress(ntdll, "NtUnmapViewOfSection"));
            if (pNtUnmap) pNtUnmap(GetCurrentProcess(), rw_view);
            CloseHandle(sec);
            return false;
        }

        s.section_handle = sec;
        s.tramp_rw = static_cast<uint8_t*>(rw_view);
        s.tramp_rx = static_cast<uint8_t*>(rx_view);
        s.section_size = view_size;
        return true;
    }

    inline void destroy_dual_mapping(state_t& s)
    {
        HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
        auto pNtUnmap = ntdll ? reinterpret_cast<NtUnmapViewOfSection_t>(
            GetProcAddress(ntdll, "NtUnmapViewOfSection")) : nullptr;

        if (s.tramp_rx && pNtUnmap)
            pNtUnmap(GetCurrentProcess(), s.tramp_rx);
        if (s.tramp_rw && pNtUnmap)
            pNtUnmap(GetCurrentProcess(), s.tramp_rw);
        if (s.section_handle)
            CloseHandle(s.section_handle);

        s.tramp_rx = nullptr;
        s.tramp_rw = nullptr;
        s.section_handle = nullptr;
        s.section_size = 0;
    }

    inline bool emit_trampoline_into_rw(state_t& s, uint8_t* dispatcher,
                                         const uint8_t* saved, size_t saved_len,
                                         uint64_t nonce)
    {
        if (!s.tramp_rw || s.section_size < 256 + saved_len)
            return false;

        HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
        uint8_t* nt_continue = resolve_export(ntdll, "NtContinue");
        if (!nt_continue) return false;

        std::memset(s.tramp_rw, 0xCC, s.section_size);

        uint8_t* p = s.tramp_rw;
        auto emit1 = [&](uint8_t b) { *p++ = b; };
        auto emit2 = [&](uint8_t a, uint8_t b) { *p++ = a; *p++ = b; };
        auto emit_qword = [&](uint64_t v) { std::memcpy(p, &v, 8); p += 8; };
        auto emit_dword = [&](uint32_t v) { std::memcpy(p, &v, 4); p += 4; };

        emit2(0x48, 0xB8);
        emit_qword(nonce);
        emit1(0x48); emit1(0x31); emit1(0xC0);

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

        FlushInstructionCache(GetCurrentProcess(),
                              s.tramp_rx, s.section_size);
        return true;
    }

    inline bool install_detour_at(uint8_t* target, size_t saved_len, uint8_t* tramp_rx)
    {
        DWORD old = 0;
        if (!VirtualProtect(target, saved_len, PAGE_EXECUTE_READWRITE, &old))
            return false;

        uint8_t detour[kDetourSize];
        detour[0] = 0xFF; detour[1] = 0x25;
        detour[2] = 0; detour[3] = 0; detour[4] = 0; detour[5] = 0;
        uint64_t target_va = reinterpret_cast<uint64_t>(tramp_rx);
        std::memcpy(detour + 6, &target_va, 8);
        std::memcpy(target, detour, kDetourSize);
        for (size_t i = kDetourSize; i < saved_len; ++i)
            target[i] = 0x90;

        DWORD tmp = 0;
        VirtualProtect(target, saved_len, old, &tmp);
        FlushInstructionCache(GetCurrentProcess(), target, saved_len);
        return true;
    }

    inline bool restore_detour_at(uint8_t* target, const uint8_t* saved, size_t saved_len)
    {
        DWORD old = 0;
        if (!VirtualProtect(target, saved_len, PAGE_EXECUTE_READWRITE, &old))
            return false;
        std::memcpy(target, saved, saved_len);
        DWORD tmp = 0;
        VirtualProtect(target, saved_len, old, &tmp);
        FlushInstructionCache(GetCurrentProcess(), target, saved_len);
        return true;
    }

    inline bool select_and_install_offset(state_t& s)
    {
        if (s.candidate_count == 0) return false;

        uint8_t pick_byte = 0;
        if (!gen_random(&pick_byte, 1))
            pick_byte = static_cast<uint8_t>(__rdtsc() & 0xFF);
        uint32_t idx = static_cast<uint32_t>(pick_byte) % s.candidate_count;

        s.selected_offset = idx;
        s.current_nonce = fresh_nonce();

        const auto& c = s.candidates[idx];
        if (!emit_trampoline_into_rw(s, c.dispatcher, c.saved_bytes,
                                      c.saved_len, s.current_nonce))
            return false;
        if (!install_detour_at(c.dispatcher, c.saved_len, s.tramp_rx))
            return false;

        s.detour_hash = hash_bytes(c.dispatcher, kDetourSize);
        s.last_regen_ms.store(now_ms(), std::memory_order_release);
        return true;
    }

    inline void uninstall_current_offset(state_t& s)
    {
        if (s.selected_offset >= s.candidate_count) return;
        const auto& c = s.candidates[s.selected_offset];
        if (c.dispatcher && c.saved_len)
            restore_detour_at(c.dispatcher, c.saved_bytes, c.saved_len);
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

    inline void regen_loop()
    {
        auto& s = state();
        while (s.regen_thread_running.load(std::memory_order_acquire))
        {
            HANDLE ev = s.regen_stop_event;
            DWORD wait_rc = (ev != nullptr)
                ? WaitForSingleObject(ev, 30000)
                : (std::this_thread::sleep_for(std::chrono::milliseconds(30000)), static_cast<DWORD>(WAIT_TIMEOUT));
            if (wait_rc == WAIT_OBJECT_0) return;
            if (!s.regen_thread_running.load(std::memory_order_acquire)) return;

            std::lock_guard<std::mutex> lk(s.mtx);
            if (!s.active.load(std::memory_order_acquire)) continue;

            uninstall_current_offset(s);
            select_and_install_offset(s);
        }
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

    s.fake_ntdll_ra = detail::pick_ntdll_text_ra();

    if (!detail::collect_candidate_offsets(s))
        return false;

    if (!detail::create_dual_mapping(s, detail::kSectionSize))
        return false;

    if (!detail::select_and_install_offset(s))
    {
        detail::destroy_dual_mapping(s);
        return false;
    }

    s.active.store(true, std::memory_order_release);
    detail::ghost_flags_ref().store(0x1u, std::memory_order_release);

    if (s.regen_stop_event == nullptr)
        s.regen_stop_event = CreateEventW(nullptr, TRUE, FALSE, nullptr);

    s.regen_thread_running.store(true, std::memory_order_release);
    s.regen_thread = std::thread(detail::regen_loop);

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
    if (s.selected_offset >= s.candidate_count) return true;
    const auto& c = s.candidates[s.selected_offset];
    if (!c.dispatcher) return true;
    uint64_t h = detail::hash_bytes(c.dispatcher, detail::kDetourSize);
    return h == s.detour_hash;
}

inline int64_t last_regen_ms()
{
    return detail::state().last_regen_ms.load(std::memory_order_acquire);
}

inline uint32_t selected_offset()
{
    return detail::state().selected_offset;
}

inline uint64_t current_nonce()
{
    return detail::state().current_nonce;
}

inline bool trampoline_is_w_xor_x()
{
    auto& s = detail::state();
    if (!s.tramp_rx) return false;
    MEMORY_BASIC_INFORMATION mbi{};
    if (VirtualQuery(s.tramp_rx, &mbi, sizeof(mbi)) == 0) return false;
    if (mbi.Protect != PAGE_EXECUTE_READ) return false;
    if (!s.tramp_rw) return true;
    MEMORY_BASIC_INFORMATION mbi2{};
    if (VirtualQuery(s.tramp_rw, &mbi2, sizeof(mbi2)) == 0) return false;
    return (mbi2.Protect & PAGE_EXECUTE) == 0;
}

inline void shutdown()
{
    auto& s = detail::state();
    if (!s.active.load(std::memory_order_acquire)) return;

    s.regen_thread_running.store(false, std::memory_order_release);
    if (s.regen_stop_event != nullptr)
        SetEvent(s.regen_stop_event);
    if (s.regen_thread.joinable())
        s.regen_thread.join();
    if (s.regen_stop_event != nullptr)
    {
        CloseHandle(s.regen_stop_event);
        s.regen_stop_event = nullptr;
    }

    std::lock_guard<std::mutex> lk(s.mtx);
    detail::uninstall_current_offset(s);
    detail::destroy_dual_mapping(s);

    SecureZeroMemory(s.slots, sizeof(s.slots));
    s.active.store(false, std::memory_order_release);
    detail::ghost_flags_ref().store(0u, std::memory_order_release);
}

}
}
