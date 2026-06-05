#pragma once

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif

#include <Windows.h>

#include <algorithm>
#include <array>
#include <cstdint>
#include <cstring>
#include <mutex>

#include "../../helpers/diag_log.hpp"

namespace aida::runtime::loader_header_invariant {

inline constexpr std::size_t max_header_snapshot = 0x1000;

struct snapshot_t {
    uintptr_t base = 0;
    LONG e_lfanew = 0;
    DWORD header_size = 0;
    uint64_t key = 0;
    bool valid = false;
    std::array<uint8_t, max_header_snapshot> encoded{};
};

struct header_state_t {
    WORD magic = 0;
    LONG e_lfanew = 0;
    bool nt_valid = false;
};

inline snapshot_t& cached_snapshot()
{
    static snapshot_t snap{};
    return snap;
}

inline std::mutex& header_mutex()
{
    static std::mutex m;
    return m;
}

inline uint8_t snapshot_mask(uint64_t key, std::size_t index)
{
    uint64_t x = key + 0x9E3779B97F4A7C15ULL * (index + 1);
    x ^= x >> 30;
    x *= 0xBF58476D1CE4E5B9ULL;
    x ^= x >> 27;
    x *= 0x94D049BB133111EBULL;
    x ^= x >> 31;
    return static_cast<uint8_t>((x >> ((index & 7) * 8)) & 0xFFu);
}

inline uint64_t make_snapshot_key(uintptr_t base, LONG e_lfanew)
{
    uint64_t k = 0xA7D9C33B6E2F91D5ULL;
    k ^= static_cast<uint64_t>(base);
    k ^= static_cast<uint64_t>(static_cast<uint32_t>(e_lfanew)) << 17;
    k ^= static_cast<uint64_t>(GetCurrentProcessId()) << 29;
    k ^= static_cast<uint64_t>(GetTickCount64());
    if (k == 0)
        k = 0x4F1BBCDCBFA54001ULL;
    return k;
}

inline bool valid_lfanew(LONG e_lfanew)
{
    return e_lfanew >= static_cast<LONG>(sizeof(IMAGE_DOS_HEADER)) &&
           e_lfanew < static_cast<LONG>(0x1000);
}

inline bool valid_nt_at(const uint8_t* base, LONG e_lfanew)
{
    if (!base || !valid_lfanew(e_lfanew))
        return false;
    bool ok = false;
    __try {
        const auto* nt = reinterpret_cast<const IMAGE_NT_HEADERS64*>(base + e_lfanew);
        ok = nt->Signature == IMAGE_NT_SIGNATURE &&
             nt->FileHeader.Machine == IMAGE_FILE_MACHINE_AMD64 &&
             nt->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        ok = false;
    }
    return ok;
}

inline LONG scan_lfanew(const uint8_t* base)
{
    if (!base)
        return 0;
    for (LONG off = static_cast<LONG>(sizeof(IMAGE_DOS_HEADER)); off < static_cast<LONG>(0x1000); off += 8) {
        if (valid_nt_at(base, off))
            return off;
    }
    return 0;
}

inline DWORD compute_snapshot_size(const uint8_t* base, LONG e_lfanew)
{
    if (!base || !valid_lfanew(e_lfanew))
        return 0;
    DWORD out = 0;
    __try {
        const auto* nt = reinterpret_cast<const IMAGE_NT_HEADERS64*>(base + e_lfanew);
        if (nt->Signature != IMAGE_NT_SIGNATURE ||
            nt->FileHeader.Machine != IMAGE_FILE_MACHINE_AMD64 ||
            nt->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC)
            return 0;
        const uint64_t nt_end = static_cast<uint64_t>(e_lfanew) +
            sizeof(DWORD) +
            sizeof(IMAGE_FILE_HEADER) +
            nt->FileHeader.SizeOfOptionalHeader +
            static_cast<uint64_t>(nt->FileHeader.NumberOfSections) * sizeof(IMAGE_SECTION_HEADER);
        uint64_t required = std::max<uint64_t>(nt_end, sizeof(IMAGE_DOS_HEADER));
        if (nt->OptionalHeader.SizeOfHeaders != 0)
            required = std::max<uint64_t>(required, std::min<uint64_t>(nt->OptionalHeader.SizeOfHeaders, max_header_snapshot));
        if (required > max_header_snapshot)
            required = max_header_snapshot;
        out = static_cast<DWORD>(required);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        out = 0;
    }
    return out;
}

inline bool store_snapshot_bytes(snapshot_t& out, const uint8_t* base, DWORD size, uint64_t key)
{
    if (!base || size == 0 || size > max_header_snapshot)
        return false;
    bool ok = false;
    __try {
        for (DWORD i = 0; i < size; ++i)
            out.encoded[i] = static_cast<uint8_t>(base[i] ^ snapshot_mask(key, i));
        ok = true;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        ok = false;
    }
    return ok;
}

inline header_state_t read_header_state(uint8_t* base)
{
    header_state_t state{};
    if (!base)
        return state;
    __try {
        auto* dos = reinterpret_cast<IMAGE_DOS_HEADER*>(base);
        state.magic = dos->e_magic;
        state.e_lfanew = dos->e_lfanew;
        state.nt_valid = state.magic == IMAGE_DOS_SIGNATURE && valid_nt_at(base, state.e_lfanew);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        state = {};
    }
    return state;
}

inline bool copy_header_bytes(uint8_t* dst, const uint8_t* src, DWORD size)
{
    if (!dst || !src || size == 0 || size > max_header_snapshot)
        return false;
    bool ok = false;
    __try {
        std::memcpy(dst, src, size);
        ok = true;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        ok = false;
    }
    return ok;
}

inline bool write_bytes(uint8_t* base, const uint8_t* bytes, DWORD size, const char* phase, const char* tag, const char* action)
{
    if (!base || !bytes || size == 0 || size > max_header_snapshot)
        return false;
    DWORD old_protect = 0;
    SetLastError(0);
    BOOL protected_ok = VirtualProtect(base, size, PAGE_READWRITE, &old_protect);
    DWORD protect_error = protected_ok ? ERROR_SUCCESS : GetLastError();
    if (!protected_ok) {
        diag::log_tagged_fmt(tag ? tag : "loader_header",
            "%s phase=%s protect_failed base=0x%llX size=0x%lX gle=%lu",
            action ? action : "write",
            phase ? phase : "<null>",
            static_cast<unsigned long long>(reinterpret_cast<uintptr_t>(base)),
            static_cast<unsigned long>(size),
            static_cast<unsigned long>(protect_error));
        return false;
    }

    bool wrote = false;
    __try {
        std::memcpy(base, bytes, size);
        wrote = true;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        wrote = false;
    }

    DWORD discard = 0;
    VirtualProtect(base, size, old_protect, &discard);
    FlushInstructionCache(GetCurrentProcess(), base, size);
    return wrote;
}

inline bool decode_snapshot(const snapshot_t& snap, std::array<uint8_t, max_header_snapshot>& out)
{
    if (!snap.valid || snap.header_size == 0 || snap.header_size > max_header_snapshot)
        return false;
    for (DWORD i = 0; i < snap.header_size; ++i)
        out[i] = static_cast<uint8_t>(snap.encoded[i] ^ snapshot_mask(snap.key, i));
    return true;
}

inline snapshot_t capture(const char* phase, const char* tag)
{
    snapshot_t out{};
    HMODULE mod = GetModuleHandleW(nullptr);
    if (!mod) {
        diag::log_tagged_fmt(tag ? tag : "loader_header",
            "capture phase=%s mod=NULL gle=%lu",
            phase ? phase : "<null>",
            static_cast<unsigned long>(GetLastError()));
        return out;
    }

    const auto* base = reinterpret_cast<const uint8_t*>(mod);
    WORD magic = 0;
    LONG e_lfanew = 0;
    bool readable = false;
    __try {
        const auto* dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(base);
        magic = dos->e_magic;
        e_lfanew = dos->e_lfanew;
        readable = true;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        readable = false;
    }

    if (readable && magic == IMAGE_DOS_SIGNATURE && valid_nt_at(base, e_lfanew)) {
        out.base = reinterpret_cast<uintptr_t>(base);
        out.e_lfanew = e_lfanew;
        out.header_size = compute_snapshot_size(base, e_lfanew);
        out.key = make_snapshot_key(out.base, e_lfanew);
        out.valid = out.header_size != 0 && store_snapshot_bytes(out, base, out.header_size, out.key);
        cached_snapshot() = out;
        diag::log_tagged_fmt(tag ? tag : "loader_header",
            "capture phase=%s valid=%d base=0x%llX e_magic=0x%X e_lfanew=0x%X header_size=0x%lX",
            phase ? phase : "<null>",
            out.valid ? 1 : 0,
            static_cast<unsigned long long>(out.base),
            static_cast<unsigned>(magic),
            static_cast<unsigned>(e_lfanew),
            static_cast<unsigned long>(out.header_size));
        return out;
    }

    LONG scanned = scan_lfanew(base);
    if (scanned != 0) {
        out.base = reinterpret_cast<uintptr_t>(base);
        out.e_lfanew = scanned;
        out.header_size = compute_snapshot_size(base, scanned);
        out.key = make_snapshot_key(out.base, scanned);
        out.valid = out.header_size != 0 && store_snapshot_bytes(out, base, out.header_size, out.key);
        cached_snapshot() = out;
    }

    diag::log_tagged_fmt(tag ? tag : "loader_header",
        "capture phase=%s valid=%d readable=%d base=0x%llX e_magic=0x%X e_lfanew=0x%X scanned=0x%X header_size=0x%lX",
        phase ? phase : "<null>",
        out.valid ? 1 : 0,
        readable ? 1 : 0,
        static_cast<unsigned long long>(reinterpret_cast<uintptr_t>(base)),
        static_cast<unsigned>(magic),
        static_cast<unsigned>(e_lfanew),
        static_cast<unsigned>(scanned),
        static_cast<unsigned long>(out.header_size));
    return out;
}

inline bool ensure(const char* phase, const char* tag)
{
    HMODULE mod = GetModuleHandleW(nullptr);
    if (!mod) {
        diag::log_tagged_fmt(tag ? tag : "loader_header",
            "ensure phase=%s mod=NULL gle=%lu",
            phase ? phase : "<null>",
            static_cast<unsigned long>(GetLastError()));
        return false;
    }

    auto* base = reinterpret_cast<uint8_t*>(mod);
    auto& cache = cached_snapshot();
    WORD before_magic = 0;
    LONG before_lfanew = 0;
    bool readable = false;
    __try {
        auto* dos = reinterpret_cast<IMAGE_DOS_HEADER*>(base);
        before_magic = dos->e_magic;
        before_lfanew = dos->e_lfanew;
        readable = true;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        readable = false;
    }

    if (readable && before_magic == IMAGE_DOS_SIGNATURE && valid_nt_at(base, before_lfanew)) {
        cache.base = reinterpret_cast<uintptr_t>(base);
        cache.e_lfanew = before_lfanew;
        cache.header_size = compute_snapshot_size(base, before_lfanew);
        cache.key = make_snapshot_key(cache.base, before_lfanew);
        cache.valid = cache.header_size != 0 && store_snapshot_bytes(cache, base, cache.header_size, cache.key);
        diag::log_tagged_fmt(tag ? tag : "loader_header",
            "ensure phase=%s already_valid=1 base=0x%llX e_lfanew=0x%X header_size=0x%lX snapshot=%d",
            phase ? phase : "<null>",
            static_cast<unsigned long long>(cache.base),
            static_cast<unsigned>(before_lfanew),
            static_cast<unsigned long>(cache.header_size),
            cache.valid ? 1 : 0);
        return true;
    }

    LONG lfanew = 0;
    if (readable && valid_nt_at(base, before_lfanew))
        lfanew = before_lfanew;
    if (lfanew == 0 && cache.valid && cache.base == reinterpret_cast<uintptr_t>(base) && valid_nt_at(base, cache.e_lfanew))
        lfanew = cache.e_lfanew;
    if (lfanew == 0)
        lfanew = scan_lfanew(base);
    if (lfanew == 0) {
        diag::log_tagged_fmt(tag ? tag : "loader_header",
            "ensure phase=%s repair_unavailable readable=%d base=0x%llX e_magic=0x%X e_lfanew=0x%X cache_valid=%d cache_lfanew=0x%X",
            phase ? phase : "<null>",
            readable ? 1 : 0,
            static_cast<unsigned long long>(reinterpret_cast<uintptr_t>(base)),
            static_cast<unsigned>(before_magic),
            static_cast<unsigned>(before_lfanew),
            cache.valid ? 1 : 0,
            static_cast<unsigned>(cache.e_lfanew));
        return false;
    }

    DWORD old_protect = 0;
    SetLastError(0);
    BOOL protected_ok = VirtualProtect(base, sizeof(IMAGE_DOS_HEADER), PAGE_READWRITE, &old_protect);
    DWORD protect_error = protected_ok ? ERROR_SUCCESS : GetLastError();
    if (!protected_ok) {
        diag::log_tagged_fmt(tag ? tag : "loader_header",
            "ensure phase=%s protect_failed base=0x%llX gle=%lu",
            phase ? phase : "<null>",
            static_cast<unsigned long long>(reinterpret_cast<uintptr_t>(base)),
            static_cast<unsigned long>(protect_error));
        return false;
    }

    bool wrote = false;
    __try {
        auto* dos = reinterpret_cast<IMAGE_DOS_HEADER*>(base);
        dos->e_magic = IMAGE_DOS_SIGNATURE;
        dos->e_lfanew = lfanew;
        wrote = true;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        wrote = false;
    }

    DWORD discard = 0;
    VirtualProtect(base, sizeof(IMAGE_DOS_HEADER), old_protect, &discard);
    FlushInstructionCache(GetCurrentProcess(), base, sizeof(IMAGE_DOS_HEADER));

    WORD after_magic = 0;
    LONG after_lfanew = 0;
    bool after_valid = false;
    __try {
        auto* dos = reinterpret_cast<IMAGE_DOS_HEADER*>(base);
        after_magic = dos->e_magic;
        after_lfanew = dos->e_lfanew;
        after_valid = dos->e_magic == IMAGE_DOS_SIGNATURE && valid_nt_at(base, dos->e_lfanew);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        after_valid = false;
    }

    if (after_valid) {
        cache.base = reinterpret_cast<uintptr_t>(base);
        cache.e_lfanew = after_lfanew;
        cache.valid = true;
    }

    diag::log_tagged_fmt(tag ? tag : "loader_header",
        "ensure phase=%s repaired=%d wrote=%d base=0x%llX before_magic=0x%X before_lfanew=0x%X after_magic=0x%X after_lfanew=0x%X old_protect=0x%lX",
        phase ? phase : "<null>",
        after_valid ? 1 : 0,
        wrote ? 1 : 0,
        static_cast<unsigned long long>(reinterpret_cast<uintptr_t>(base)),
        static_cast<unsigned>(before_magic),
        static_cast<unsigned>(before_lfanew),
        static_cast<unsigned>(after_magic),
        static_cast<unsigned>(after_lfanew),
        static_cast<unsigned long>(old_protect));
    return after_valid;
}

class scoped_restore_t
{
public:
    scoped_restore_t(const char* phase, const char* tag)
        : lock_(header_mutex())
        , phase_(phase ? phase : "<null>")
        , tag_(tag ? tag : "loader_header")
    {
        HMODULE mod = GetModuleHandleW(nullptr);
        if (!mod) {
            diag::log_tagged_fmt(tag_, "scoped_restore phase=%s mod=NULL gle=%lu",
                phase_, static_cast<unsigned long>(GetLastError()));
            return;
        }
        mod_ = reinterpret_cast<uint8_t*>(mod);
        const header_state_t state = read_header_state(mod_);
        if (state.nt_valid) {
            diag::log_tagged_fmt(tag_, "scoped_restore phase=%s already_valid=1 base=0x%llX e_lfanew=0x%X",
                phase_, static_cast<unsigned long long>(reinterpret_cast<uintptr_t>(mod_)),
                static_cast<unsigned>(state.e_lfanew));
            return;
        }

        const snapshot_t snap = cached_snapshot();
        if (!snap.valid || snap.base != reinterpret_cast<uintptr_t>(mod_) ||
            snap.header_size == 0 || snap.header_size > max_header_snapshot) {
            diag::log_tagged_fmt(tag_,
                "scoped_restore phase=%s unavailable base=0x%llX e_magic=0x%X e_lfanew=0x%X snap_valid=%d snap_base=0x%llX snap_size=0x%lX",
                phase_,
                static_cast<unsigned long long>(reinterpret_cast<uintptr_t>(mod_)),
                static_cast<unsigned>(state.magic),
                static_cast<unsigned>(state.e_lfanew),
                snap.valid ? 1 : 0,
                static_cast<unsigned long long>(snap.base),
                static_cast<unsigned long>(snap.header_size));
            return;
        }

        size_ = snap.header_size;
        const bool saved_prior = copy_header_bytes(prior_.data(), mod_, size_);
        if (!saved_prior) {
            diag::log_tagged_fmt(tag_, "scoped_restore phase=%s save_prior_failed size=0x%lX",
                phase_, static_cast<unsigned long>(size_));
            return;
        }
        if (!decode_snapshot(snap, restored_)) {
            diag::log_tagged_fmt(tag_, "scoped_restore phase=%s decode_failed size=0x%lX",
                phase_, static_cast<unsigned long>(size_));
            return;
        }
        if (!write_bytes(mod_, restored_.data(), size_, phase_, tag_, "scoped_restore_write")) {
            diag::log_tagged_fmt(tag_, "scoped_restore phase=%s write_failed size=0x%lX",
                phase_, static_cast<unsigned long>(size_));
            return;
        }
        active_ = valid_nt_at(mod_, snap.e_lfanew);
        diag::log_tagged_fmt(tag_,
            "scoped_restore phase=%s active=%d base=0x%llX before_magic=0x%X before_lfanew=0x%X restored_lfanew=0x%X size=0x%lX",
            phase_,
            active_ ? 1 : 0,
            static_cast<unsigned long long>(reinterpret_cast<uintptr_t>(mod_)),
            static_cast<unsigned>(state.magic),
            static_cast<unsigned>(state.e_lfanew),
            static_cast<unsigned>(snap.e_lfanew),
            static_cast<unsigned long>(size_));
    }

    scoped_restore_t(const scoped_restore_t&) = delete;
    scoped_restore_t& operator=(const scoped_restore_t&) = delete;

    ~scoped_restore_t()
    {
        if (!active_ || !mod_ || size_ == 0)
            return;
        const bool ok = write_bytes(mod_, prior_.data(), size_, phase_, tag_, "scoped_restore_revert");
        diag::log_tagged_fmt(tag_,
            "scoped_restore_revert phase=%s ok=%d base=0x%llX size=0x%lX",
            phase_,
            ok ? 1 : 0,
            static_cast<unsigned long long>(reinterpret_cast<uintptr_t>(mod_)),
            static_cast<unsigned long>(size_));
    }

    bool active() const
    {
        return active_;
    }

private:
    std::unique_lock<std::mutex> lock_;
    const char* phase_ = "<null>";
    const char* tag_ = "loader_header";
    uint8_t* mod_ = nullptr;
    DWORD size_ = 0;
    bool active_ = false;
    std::array<uint8_t, max_header_snapshot> prior_{};
    std::array<uint8_t, max_header_snapshot> restored_{};
};

}
