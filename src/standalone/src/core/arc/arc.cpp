#include "arc.h"
#include "../runtime/reason_ids.hpp"
#include "comm.h"
#include "../../helpers/diag_log.hpp"

#include <windows.h>
#include <winioctl.h>
#include <intrin.h>
#include <nmmintrin.h>
#include <winhttp.h>
#include <bcrypt.h>

#include "anti-tamper/cff.hpp"
#include "arc_build_seed.hpp"
#include "anti-tamper/wb_crypto.hpp"
#include "../anti-tamper/heap_encrypt.hpp"
#include "obfuscation.hpp"
#include "shared/hardware_id/hardware_id_v2.hpp"

#undef CFF_BEGIN
#undef CFF_STATE
#undef CFF_GOTO
#undef CFF_EXIT
#undef CFF_END
#define CFF_BEGIN(tag)
#define CFF_STATE(tag, N)
#define CFF_GOTO(tag, N)
#define CFF_EXIT(tag) goto cff_exit_label_##tag
#define CFF_END(tag) cff_exit_label_##tag: ;

#include <array>
#include <atomic>
#include <cstring>
#include <cstdio>
#include <cstdlib>
#include <mutex>
#include <string>
#include <vector>

#pragma comment(lib, "bcrypt.lib")

namespace arc_internal
{

static std::mutex g_last_status_mtx;
static char g_last_status[192] = {};

static void arc_store_status(const char* tag, const char* msg)
{
    std::lock_guard<std::mutex> lk(g_last_status_mtx);
    _snprintf_s(g_last_status, sizeof(g_last_status), _TRUNCATE,
        "%s:%s", tag ? tag : "", msg ? msg : "");
}

static void arc_log(const char* tag, const char* msg)
{
    arc_store_status(tag, msg);

    static char s_log_path[MAX_PATH] = {};
    static bool  s_path_ready = false;
    if (!s_path_ready) {
        if (!diag::build_log_path("aida_debug.log", s_log_path, sizeof(s_log_path)))
            s_log_path[0] = '\0';
        s_path_ready = true;
    }

    SYSTEMTIME st;
    GetLocalTime(&st);
    char line[512];
    int n = _snprintf_s(line, sizeof(line), _TRUNCATE,
        "[%02d:%02d:%02d.%03d] [arc/%s] %s\n",
        st.wHour, st.wMinute, st.wSecond, st.wMilliseconds, tag, msg);
    if (n <= 0) return;
    if (s_log_path[0] != '\0') {
        HANDLE h = CreateFileA(s_log_path, GENERIC_WRITE,
            FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr,
            OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
        if (h != INVALID_HANDLE_VALUE)
        {
            SetFilePointer(h, 0, nullptr, FILE_END);
            DWORD written = 0;
            WriteFile(h, line, static_cast<DWORD>(n), &written, nullptr);
            FlushFileBuffers(h);
            CloseHandle(h);
        }
    }
    OutputDebugStringA(line);
}

enum arc_runtime_state_code_t : uint32_t
{
    arc_state_cold = 0,
    arc_state_bound = 1,
    arc_state_init_started = 2,
    arc_state_session_ready = 3,
    arc_state_driver_verified = 4,
    arc_state_ready = 5,
    arc_state_cleanup = 6,
    arc_state_violation = 7
};

static std::atomic<uint32_t> g_arc_runtime_state{arc_state_cold};

const char* arc_runtime_state_name(uint32_t state)
{
    switch (state)
    {
    case arc_state_cold: return "cold";
    case arc_state_bound: return "bound";
    case arc_state_init_started: return "init_started";
    case arc_state_session_ready: return "session_ready";
    case arc_state_driver_verified: return "driver_verified";
    case arc_state_ready: return "ready";
    case arc_state_cleanup: return "cleanup";
    case arc_state_violation: return "violation";
    default: return "unknown";
    }
}

void arc_publish_state(uint32_t next, const char* phase, const char* detail)
{
    uint32_t previous = g_arc_runtime_state.exchange(next, std::memory_order_acq_rel);
    char line[256];
    _snprintf_s(line, sizeof(line), _TRUNCATE,
        "transition phase=%s previous=%s/%u next=%s/%u detail=%s tid=%lu",
        phase ? phase : "",
        arc_runtime_state_name(previous),
        previous,
        arc_runtime_state_name(next),
        next,
        detail ? detail : "",
        GetCurrentThreadId());
    arc_log("state", line);
}

void arc_log_export_denied(const char* export_name, const char* reason)
{
    uint32_t state = g_arc_runtime_state.load(std::memory_order_acquire);
    char line[192];
    _snprintf_s(line, sizeof(line), _TRUNCATE,
        "export_denied name=%s reason=%s state=%s/%u tid=%lu",
        export_name ? export_name : "",
        reason ? reason : "",
        arc_runtime_state_name(state),
        state,
        GetCurrentThreadId());
    arc_log("export", line);
}

bool arc_runtime_requires_live_session(uint32_t state)
{
    return state == arc_state_session_ready ||
           state == arc_state_driver_verified ||
           state == arc_state_ready;
}

bool arc_ct_memeq(const uint8_t* left, const uint8_t* right, size_t len)
{
    uint8_t diff = 0;
    for (size_t i = 0; i < len; ++i)
        diff |= static_cast<uint8_t>(left[i] ^ right[i]);
    return diff == 0;
}

__forceinline uint64_t siphash_2_4(const uint8_t* data, size_t len, uint64_t k0, uint64_t k1)
{
    uint64_t v0 = k0 ^ 0x736F6D6570736575ULL;
    uint64_t v1 = k1 ^ 0x646F72616E646F6DULL;
    uint64_t v2 = k0 ^ 0x6C7967656E657261ULL;
    uint64_t v3 = k1 ^ 0x7465646279746573ULL;

    auto sipround = [&]() {
        v0 += v1; v1 = _rotl64(v1, 13); v1 ^= v0; v0 = _rotl64(v0, 32);
        v2 += v3; v3 = _rotl64(v3, 16); v3 ^= v2;
        v0 += v3; v3 = _rotl64(v3, 21); v3 ^= v0;
        v2 += v1; v1 = _rotl64(v1, 17); v1 ^= v2; v2 = _rotl64(v2, 32);
    };

    size_t blocks = len / 8;
    for (size_t i = 0; i < blocks; ++i)
    {
        uint64_t m;
        memcpy(&m, data + i * 8, 8);
        v3 ^= m;
        sipround(); sipround();
        v0 ^= m;
    }

    uint64_t b = static_cast<uint64_t>(len) << 56;
    const uint8_t* tail = data + blocks * 8;
    int left = static_cast<int>(len & 7);
    switch (left)
    {
    case 7: b |= static_cast<uint64_t>(tail[6]) << 48; [[fallthrough]];
    case 6: b |= static_cast<uint64_t>(tail[5]) << 40; [[fallthrough]];
    case 5: b |= static_cast<uint64_t>(tail[4]) << 32; [[fallthrough]];
    case 4: b |= static_cast<uint64_t>(tail[3]) << 24; [[fallthrough]];
    case 3: b |= static_cast<uint64_t>(tail[2]) << 16; [[fallthrough]];
    case 2: b |= static_cast<uint64_t>(tail[1]) << 8;  [[fallthrough]];
    case 1: b |= static_cast<uint64_t>(tail[0]);        break;
    case 0: break;
    }

    v3 ^= b; sipround(); sipround(); v0 ^= b;
    v2 ^= 0xFF;
    sipround(); sipround(); sipround(); sipround();
    return v0 ^ v1 ^ v2 ^ v3;
}

uint64_t fnv1a(const void* data, size_t len)
{
    uint64_t h = 14695981039346656037ULL;
    const auto* p = static_cast<const uint8_t*>(data);
    for (size_t i = 0; i < len; ++i) {
        h ^= p[i];
        h *= 1099511628211ULL;
    }
    return h;
}

uint64_t fnv1a_str(const char* s)
{
    if (!s) return 0;
    return fnv1a(s, strlen(s));
}

DWORD arc_protect_base(DWORD protect)
{
    return protect & 0xFFu;
}

bool arc_is_exec_protect(DWORD protect)
{
    switch (arc_protect_base(protect))
    {
    case PAGE_EXECUTE:
    case PAGE_EXECUTE_READ:
    case PAGE_EXECUTE_READWRITE:
    case PAGE_EXECUTE_WRITECOPY:
        return true;
    default:
        return false;
    }
}

bool arc_is_readable_protect(DWORD protect)
{
    switch (arc_protect_base(protect))
    {
    case PAGE_READONLY:
    case PAGE_READWRITE:
    case PAGE_WRITECOPY:
    case PAGE_EXECUTE_READ:
    case PAGE_EXECUTE_READWRITE:
    case PAGE_EXECUTE_WRITECOPY:
        return true;
    default:
        return false;
    }
}

bool arc_is_writable_protect(DWORD protect)
{
    switch (arc_protect_base(protect))
    {
    case PAGE_READWRITE:
    case PAGE_WRITECOPY:
    case PAGE_EXECUTE_READWRITE:
    case PAGE_EXECUTE_WRITECOPY:
        return true;
    default:
        return false;
    }
}

bool arc_is_stable_exec_region(const MEMORY_BASIC_INFORMATION& r)
{
    if (r.State != MEM_COMMIT)
        return false;
    if (!arc_is_exec_protect(r.Protect))
        return false;
    if (!arc_is_readable_protect(r.Protect))
        return false;
    if (arc_is_writable_protect(r.Protect))
        return false;
    if ((r.Protect & PAGE_GUARD) != 0)
        return false;
    if ((r.Protect & PAGE_NOACCESS) != 0)
        return false;
    return true;
}

const char* arc_protect_name(DWORD protect)
{
    switch (arc_protect_base(protect))
    {
    case PAGE_NOACCESS: return "NOACCESS";
    case PAGE_READONLY: return "READONLY";
    case PAGE_READWRITE: return "READWRITE";
    case PAGE_WRITECOPY: return "WRITECOPY";
    case PAGE_EXECUTE: return "EXECUTE";
    case PAGE_EXECUTE_READ: return "EXECUTE_READ";
    case PAGE_EXECUTE_READWRITE: return "EXECUTE_READWRITE";
    case PAGE_EXECUTE_WRITECOPY: return "EXECUTE_WRITECOPY";
    default: return "UNKNOWN";
    }
}

__forceinline uint64_t qpc_freq_value()
{
    static LARGE_INTEGER s_freq{};
    if (s_freq.QuadPart == 0) QueryPerformanceFrequency(&s_freq);
    return static_cast<uint64_t>(s_freq.QuadPart);
}

__forceinline uint64_t qpc_now_ticks()
{
    LARGE_INTEGER c{};
    QueryPerformanceCounter(&c);
    return static_cast<uint64_t>(c.QuadPart);
}

__forceinline uint64_t qpc_now_us()
{
    uint64_t f = qpc_freq_value();
    if (f == 0) return 0;
    uint64_t t = qpc_now_ticks();
    return (t * 1000000ULL) / f;
}

uint64_t fnv1a_region_seh(const void* data, size_t len, bool& ok)
{
    ok = false;
    uint64_t h = 14695981039346656037ULL;
    const auto* p = static_cast<const uint8_t*>(data);
    __try
    {
        for (size_t i = 0; i < len; ++i)
        {
            h ^= p[i];
            h *= 1099511628211ULL;
        }
        ok = true;
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        ok = false;
        h = 0;
    }
    return h;
}

struct integrity_scan_result_t
{
    uint64_t hash;
    uint32_t exec_regions;
    uint32_t included_regions;
    uint32_t mutable_exec_regions;
    uint32_t unreadable_exec_regions;
    uint32_t guarded_exec_regions;
    uint32_t read_failures;
};

void arc_log_integrity_region(const char* phase, uint32_t index, const MEMORY_BASIC_INFORMATION& r,
                              const char* decision, uint64_t region_hash)
{
    char line[256];
    _snprintf_s(line, sizeof(line), _TRUNCATE,
        "%s region[%u] base=%p size=0x%zX protect=0x%08lX/%s state=0x%08lX type=0x%08lX decision=%s hash=0x%016llX",
        phase ? phase : "integrity",
        index,
        r.BaseAddress,
        static_cast<size_t>(r.RegionSize),
        static_cast<unsigned long>(r.Protect),
        arc_protect_name(r.Protect),
        static_cast<unsigned long>(r.State),
        static_cast<unsigned long>(r.Type),
        decision ? decision : "unknown",
        static_cast<unsigned long long>(region_hash));
    arc_log("integrity", line);
}

integrity_scan_result_t scan_own_code_integrity(bool log_regions, const char* phase)
{
    integrity_scan_result_t out{};
    MEMORY_BASIC_INFORMATION mbi = {};
    if (VirtualQuery(reinterpret_cast<const void*>(&scan_own_code_integrity), &mbi, sizeof(mbi)) == 0)
    {
        if (log_regions)
            arc_log("integrity", "scan_virtualquery_self_failed");
        return out;
    }
    const auto hMod = static_cast<const uint8_t*>(mbi.AllocationBase);
    if (!hMod)
    {
        if (log_regions)
            arc_log("integrity", "scan_allocation_base_null");
        return out;
    }

    uintptr_t addr = reinterpret_cast<uintptr_t>(hMod);
    const uintptr_t scan_limit = addr + (256ULL * 1024 * 1024);
    uint32_t region_index = 0;

    while (addr < scan_limit)
    {
        MEMORY_BASIC_INFORMATION r = {};
        if (VirtualQuery(reinterpret_cast<const void*>(addr), &r, sizeof(r)) == 0)
            break;
        if (r.RegionSize == 0)
            break;
        if (r.AllocationBase != mbi.AllocationBase)
            break;

        const bool exec = r.State == MEM_COMMIT && arc_is_exec_protect(r.Protect);
        if (exec)
        {
            ++out.exec_regions;
            const bool guarded = (r.Protect & PAGE_GUARD) != 0;
            const bool readable = arc_is_readable_protect(r.Protect);
            const bool writable = arc_is_writable_protect(r.Protect);
            const size_t size = r.RegionSize;
            if (guarded)
            {
                ++out.guarded_exec_regions;
                if (log_regions)
                    arc_log_integrity_region(phase, region_index, r, "skip_guarded_exec", 0);
            }
            else if (!readable)
            {
                ++out.unreadable_exec_regions;
                if (log_regions)
                    arc_log_integrity_region(phase, region_index, r, "skip_unreadable_exec", 0);
            }
            else if (writable)
            {
                ++out.mutable_exec_regions;
                if (log_regions)
                    arc_log_integrity_region(phase, region_index, r, "skip_mutable_exec", 0);
            }
            else if (size > 0 && size < 64ULL * 1024 * 1024)
            {
                bool read_ok = false;
                uint64_t region_hash = fnv1a_region_seh(r.BaseAddress, size, read_ok);
                if (read_ok)
                {
                    const uint64_t base_val = reinterpret_cast<uint64_t>(r.BaseAddress);
                    uint8_t buf[32];
                    memcpy(buf,      &region_hash, 8);
                    memcpy(buf + 8,  &base_val,    8);
                    memcpy(buf + 16, &size,        8);
                    memset(buf + 24, 0,            8);
                    out.hash ^= siphash_2_4(buf, 32, 0xA1DAC0DE5EC0DEULL, 0xCAFEBABEDEADFEEDULL);
                    ++out.included_regions;
                    if (log_regions)
                        arc_log_integrity_region(phase, region_index, r, "include_stable_exec", region_hash);
                }
                else
                {
                    ++out.read_failures;
                    if (log_regions)
                        arc_log_integrity_region(phase, region_index, r, "read_failed", 0);
                }
            }
            else if (log_regions)
            {
                arc_log_integrity_region(phase, region_index, r, "skip_size", 0);
            }
            ++region_index;
        }

        addr += r.RegionSize;
    }

    if (log_regions)
    {
        char summary[256];
        _snprintf_s(summary, sizeof(summary), _TRUNCATE,
            "%s summary hash=0x%016llX exec=%u included=%u mutable=%u unreadable=%u guarded=%u read_fail=%u",
            phase ? phase : "integrity",
            static_cast<unsigned long long>(out.hash),
            out.exec_regions,
            out.included_regions,
            out.mutable_exec_regions,
            out.unreadable_exec_regions,
            out.guarded_exec_regions,
            out.read_failures);
        arc_log("integrity", summary);
    }

    return out;
}

uint64_t driver_region_crc_hash_seh(const void* data, size_t len, bool& ok)
{
    ok = false;
    uint64_t h1 = 0xFFFFFFFFULL;
    uint64_t h2 = 0x85EBCA6BULL;
    const auto* p = static_cast<const uint8_t*>(data);
    __try
    {
        size_t aligned_end = len & ~7ULL;
        for (size_t i = 0; i < aligned_end; i += 8)
        {
            uint64_t block = 0;
            memcpy(&block, p + i, sizeof(block));
            h1 = _mm_crc32_u64(h1, block);
            h2 = _mm_crc32_u64(h2, block ^ 0xA5A5A5A5A5A5A5A5ULL);
        }
        for (size_t i = aligned_end; i < len; ++i)
        {
            h1 = _mm_crc32_u8(static_cast<uint32_t>(h1), p[i]);
            h2 = _mm_crc32_u8(static_cast<uint32_t>(h2), p[i] ^ 0xA5u);
        }
        ok = true;
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        ok = false;
        h1 = 0;
        h2 = 0;
    }
    return (h1 & 0xFFFFFFFFULL) | ((h2 & 0xFFFFFFFFULL) << 32);
}

bool aes_gcm_decrypt_ni(const uint8_t* ct, size_t ct_len,
    const uint8_t* key32, const uint8_t* iv12, const uint8_t* tag16,
    uint8_t* pt)
{
    if (!ct || !key32 || !iv12 || !tag16 || !pt) return false;
    if (ct_len > 0xFFFFFFFFu) return false;

    bool result = false;
    BCRYPT_ALG_HANDLE hAlg = nullptr;
    BCRYPT_KEY_HANDLE hKey = nullptr;
    NTSTATUS st = 0;
    BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO authInfo;
    ULONG bytes_decrypted = 0;

    CFF_BEGIN(aes_gcm_dec_cff)
    CFF_STATE(aes_gcm_dec_cff, 0)
    {
        st = BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_AES_ALGORITHM, nullptr, 0);
        if (!BCRYPT_SUCCESS(st) || !hAlg)
        {
            CFF_EXIT(aes_gcm_dec_cff);
        }

        st = BCryptSetProperty(
            hAlg,
            BCRYPT_CHAINING_MODE,
            reinterpret_cast<PUCHAR>(const_cast<wchar_t*>(BCRYPT_CHAIN_MODE_GCM)),
            static_cast<ULONG>(wcslen(BCRYPT_CHAIN_MODE_GCM) * sizeof(wchar_t) + sizeof(wchar_t)),
            0);
        if (!BCRYPT_SUCCESS(st))
        {
            BCryptCloseAlgorithmProvider(hAlg, 0);
            hAlg = nullptr;
            CFF_EXIT(aes_gcm_dec_cff);
        }
        CFF_GOTO(aes_gcm_dec_cff, 1);
    }
    CFF_STATE(aes_gcm_dec_cff, 1)
    {
        st = BCryptGenerateSymmetricKey(
            hAlg,
            &hKey,
            nullptr,
            0,
            const_cast<PUCHAR>(key32),
            32,
            0);
        if (!BCRYPT_SUCCESS(st) || !hKey)
        {
            BCryptCloseAlgorithmProvider(hAlg, 0);
            hAlg = nullptr;
            CFF_EXIT(aes_gcm_dec_cff);
        }

        BCRYPT_INIT_AUTH_MODE_INFO(authInfo);
        authInfo.pbNonce = const_cast<PUCHAR>(iv12);
        authInfo.cbNonce = 12;
        authInfo.pbTag = const_cast<PUCHAR>(tag16);
        authInfo.cbTag = 16;
        CFF_GOTO(aes_gcm_dec_cff, 2);
    }
    CFF_STATE(aes_gcm_dec_cff, 2)
    {
        st = BCryptDecrypt(
            hKey,
            const_cast<PUCHAR>(ct),
            static_cast<ULONG>(ct_len),
            &authInfo,
            nullptr,
            0,
            pt,
            static_cast<ULONG>(ct_len),
            &bytes_decrypted,
            0);

        BCryptDestroyKey(hKey);
        hKey = nullptr;
        BCryptCloseAlgorithmProvider(hAlg, 0);
        hAlg = nullptr;
        result = BCRYPT_SUCCESS(st) && bytes_decrypted == static_cast<ULONG>(ct_len);
        CFF_EXIT(aes_gcm_dec_cff);
    }
    CFF_END(aes_gcm_dec_cff)

    return result;
}

void* peb_find_module(uint64_t name_hash)
{
    auto* peb = reinterpret_cast<const uint8_t*>(__readgsqword(0x60));
    if (!peb) return nullptr;
    auto* ldr = *reinterpret_cast<const uint8_t* const*>(peb + 0x18);
    if (!ldr) return nullptr;
    auto* list_head = reinterpret_cast<const uint8_t*>(ldr + 0x20);
    auto* entry = *reinterpret_cast<const uint8_t* const*>(list_head);
    if (!entry) return nullptr;

    constexpr uint32_t kMaxLdrIterations = 4096;
    uint32_t iterations = 0;
    while (entry != list_head)
    {
        if (++iterations > kMaxLdrIterations) return nullptr;

        auto* dll_base = *reinterpret_cast<void* const*>(entry + 0x20);
        auto* name_buf = *reinterpret_cast<const wchar_t* const*>(entry + 0x50);
        auto name_len = *reinterpret_cast<const uint16_t*>(entry + 0x48);

        if (dll_base && name_buf && name_len > 0)
        {
            uint64_t h = 14695981039346656037ULL;
            uint16_t chars = name_len / sizeof(wchar_t);
            for (uint16_t i = 0; i < chars; ++i)
            {
                wchar_t c = name_buf[i];
                if (c >= L'A' && c <= L'Z') c += 32;
                h ^= static_cast<uint64_t>(c);
                h *= 1099511628211ULL;
            }
            if (h == name_hash)
                return dll_base;
        }
        auto* next_entry = *reinterpret_cast<const uint8_t* const*>(entry);
        if (!next_entry) return nullptr;
        entry = next_entry;
    }
    return nullptr;
}

void* peb_find_export(void* module_base, uint64_t func_name_hash)
{
    if (!module_base) return nullptr;

    auto* dos = static_cast<const IMAGE_DOS_HEADER*>(module_base);
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return nullptr;

    auto* nt = reinterpret_cast<const IMAGE_NT_HEADERS*>(
        static_cast<const uint8_t*>(module_base) + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) return nullptr;

    auto& exp_dir = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
    if (exp_dir.VirtualAddress == 0 || exp_dir.Size == 0) return nullptr;

    auto base = reinterpret_cast<uintptr_t>(module_base);
    auto* exports = reinterpret_cast<const IMAGE_EXPORT_DIRECTORY*>(base + exp_dir.VirtualAddress);

    auto* names = reinterpret_cast<const uint32_t*>(base + exports->AddressOfNames);
    auto* funcs = reinterpret_cast<const uint32_t*>(base + exports->AddressOfFunctions);
    auto* ords  = reinterpret_cast<const uint16_t*>(base + exports->AddressOfNameOrdinals);

    for (uint32_t i = 0; i < exports->NumberOfNames; ++i)
    {
        const char* name = reinterpret_cast<const char*>(base + names[i]);
        uint64_t h = fnv1a_str(name);
        if (h == func_name_hash)
        {
            uint32_t rva = funcs[ords[i]];
            if (rva >= exp_dir.VirtualAddress && rva < exp_dir.VirtualAddress + exp_dir.Size)
                continue;
            return reinterpret_cast<void*>(base + rva);
        }
    }
    return nullptr;
}

constexpr uint64_t ct_fnv1a(const char* s, uint64_t h = 14695981039346656037ULL)
{
    return *s ? ct_fnv1a(s + 1, (h ^ static_cast<uint64_t>(static_cast<uint8_t>(*s))) * 1099511628211ULL) : h;
}

constexpr uint64_t ct_wfnv1a(const wchar_t* s, uint64_t h = 14695981039346656037ULL)
{
    if (!*s) return h;
    wchar_t c = (*s >= L'A' && *s <= L'Z') ? (*s + 32) : *s;
    return ct_wfnv1a(s + 1, (h ^ static_cast<uint64_t>(c)) * 1099511628211ULL);
}

#define PEB_MOD(wname) peb_find_module(ct_wfnv1a(wname))
#define PEB_FN(mod, fname) peb_find_export(mod, ct_fnv1a(fname))

struct winhttp_api_t {
    using Open_t = HINTERNET(WINAPI*)(LPCWSTR, DWORD, LPCWSTR, LPCWSTR, DWORD);
    using Connect_t = HINTERNET(WINAPI*)(HINTERNET, LPCWSTR, INTERNET_PORT, DWORD);
    using OpenReq_t = HINTERNET(WINAPI*)(HINTERNET, LPCWSTR, LPCWSTR, LPCWSTR, LPCWSTR, LPCWSTR*, DWORD);
    using SendReq_t = BOOL(WINAPI*)(HINTERNET, LPCWSTR, DWORD, LPVOID, DWORD, DWORD, DWORD_PTR);
    using RecvResp_t = BOOL(WINAPI*)(HINTERNET, LPVOID);
    using QueryData_t = BOOL(WINAPI*)(HINTERNET, LPDWORD);
    using ReadData_t = BOOL(WINAPI*)(HINTERNET, LPVOID, DWORD, LPDWORD);
    using CloseH_t = BOOL(WINAPI*)(HINTERNET);
    using CrackUrl_t = BOOL(WINAPI*)(LPCWSTR, DWORD, DWORD, URL_COMPONENTSW*);

    Open_t pOpen = nullptr;
    Connect_t pConnect = nullptr;
    OpenReq_t pOpenRequest = nullptr;
    SendReq_t pSendRequest = nullptr;
    RecvResp_t pReceiveResponse = nullptr;
    QueryData_t pQueryDataAvailable = nullptr;
    ReadData_t pReadData = nullptr;
    CloseH_t pCloseHandle = nullptr;
    CrackUrl_t pCrackUrl = nullptr;
    bool ready = false;

    bool resolve()
    {
        if (ready) return true;
        auto k32 = peb_find_module(ct_wfnv1a(L"kernel32.dll"));
        if (!k32) return false;
        using LoadLib_t = HMODULE(WINAPI*)(LPCWSTR);
        auto pLoad = reinterpret_cast<LoadLib_t>(peb_find_export(k32, ct_fnv1a("LoadLibraryW")));
        if (!pLoad) return false;
        auto wh_name = WOBFSTR(L"winhttp.dll");
        pLoad(wh_name.c_str());
        auto wh = peb_find_module(ct_wfnv1a(L"winhttp.dll"));
        if (!wh) return false;
        pOpen = reinterpret_cast<Open_t>(peb_find_export(wh, ct_fnv1a("WinHttpOpen")));
        pConnect = reinterpret_cast<Connect_t>(peb_find_export(wh, ct_fnv1a("WinHttpConnect")));
        pOpenRequest = reinterpret_cast<OpenReq_t>(peb_find_export(wh, ct_fnv1a("WinHttpOpenRequest")));
        pSendRequest = reinterpret_cast<SendReq_t>(peb_find_export(wh, ct_fnv1a("WinHttpSendRequest")));
        pReceiveResponse = reinterpret_cast<RecvResp_t>(peb_find_export(wh, ct_fnv1a("WinHttpReceiveResponse")));
        pQueryDataAvailable = reinterpret_cast<QueryData_t>(peb_find_export(wh, ct_fnv1a("WinHttpQueryDataAvailable")));
        pReadData = reinterpret_cast<ReadData_t>(peb_find_export(wh, ct_fnv1a("WinHttpReadData")));
        pCloseHandle = reinterpret_cast<CloseH_t>(peb_find_export(wh, ct_fnv1a("WinHttpCloseHandle")));
        pCrackUrl = reinterpret_cast<CrackUrl_t>(peb_find_export(wh, ct_fnv1a("WinHttpCrackUrl")));
        ready = pOpen && pConnect && pOpenRequest && pSendRequest &&
                pReceiveResponse && pQueryDataAvailable && pReadData &&
                pCloseHandle && pCrackUrl;
        return ready;
    }
};

winhttp_api_t g_winhttp = {};

std::mutex g_server_url_mtx;
std::string g_server_url;

void capture_server_url(const char* server_url)
{
    if (!server_url || !*server_url) return;
    std::lock_guard<std::mutex> lk(g_server_url_mtx);
    if (g_server_url.empty())
        g_server_url.assign(server_url);
}

std::string load_server_url()
{
    std::lock_guard<std::mutex> lk(g_server_url_mtx);
    return g_server_url;
}

std::string http_post_json(const char* url, const char* json_body)
{
    std::string out;
    if (!url || !*url) return out;
    if (!g_winhttp.resolve()) return out;

    URL_COMPONENTSW uc{};
    uc.dwStructSize = sizeof(uc);
    wchar_t host_buf[256] = {};
    wchar_t path_buf[1024] = {};
    uc.lpszHostName = host_buf;
    uc.dwHostNameLength = static_cast<DWORD>(sizeof(host_buf) / sizeof(wchar_t));
    uc.lpszUrlPath = path_buf;
    uc.dwUrlPathLength = static_cast<DWORD>(sizeof(path_buf) / sizeof(wchar_t));

    int url_wlen = MultiByteToWideChar(CP_UTF8, 0, url, -1, nullptr, 0);
    if (url_wlen <= 0) return out;
    std::wstring wurl(static_cast<size_t>(url_wlen - 1), L'\0');
    MultiByteToWideChar(CP_UTF8, 0, url, -1, wurl.data(), url_wlen);

    if (!g_winhttp.pCrackUrl(wurl.c_str(), 0, 0, &uc)) return out;

    bool is_https = (uc.nScheme == INTERNET_SCHEME_HTTPS);
    INTERNET_PORT port = uc.nPort != 0 ? uc.nPort : (is_https ? INTERNET_PORT(443) : INTERNET_PORT(80));

    std::wstring whost(host_buf, uc.dwHostNameLength);
    std::wstring wpath = (uc.dwUrlPathLength > 0) ? std::wstring(path_buf, uc.dwUrlPathLength) : std::wstring(L"/");

    auto agent = WOBFSTR(L"AiDA-ARC/1.0");
    HINTERNET h_session = g_winhttp.pOpen(agent.c_str(),
        WINHTTP_ACCESS_TYPE_NO_PROXY,
        WINHTTP_NO_PROXY_NAME,
        WINHTTP_NO_PROXY_BYPASS,
        0);
    if (!h_session) return out;

    HINTERNET h_connect = g_winhttp.pConnect(h_session, whost.c_str(), port, 0);
    if (!h_connect) {
        g_winhttp.pCloseHandle(h_session);
        return out;
    }

    DWORD req_flags = is_https ? WINHTTP_FLAG_SECURE : 0;
    auto verb = WOBFSTR(L"POST");
    HINTERNET h_req = g_winhttp.pOpenRequest(h_connect, verb.c_str(), wpath.c_str(),
        nullptr, WINHTTP_NO_REFERER,
        WINHTTP_DEFAULT_ACCEPT_TYPES, req_flags);
    if (!h_req) {
        g_winhttp.pCloseHandle(h_connect);
        g_winhttp.pCloseHandle(h_session);
        return out;
    }

    auto headers = WOBFSTR(L"Content-Type: application/json\r\n");
    DWORD body_len = json_body ? static_cast<DWORD>(strlen(json_body)) : 0u;
    BOOL sent = g_winhttp.pSendRequest(h_req,
        headers.c_str(), static_cast<DWORD>(-1L),
        const_cast<char*>(json_body ? json_body : ""), body_len, body_len, 0);

    if (sent && g_winhttp.pReceiveResponse(h_req, nullptr)) {
        for (;;) {
            DWORD avail = 0;
            if (!g_winhttp.pQueryDataAvailable(h_req, &avail) || avail == 0) break;
            size_t cur = out.size();
            out.resize(cur + avail);
            DWORD read = 0;
            if (!g_winhttp.pReadData(h_req, out.data() + cur, avail, &read)) {
                out.resize(cur);
                break;
            }
            out.resize(cur + read);
            if (read == 0) break;
        }
    }

    g_winhttp.pCloseHandle(h_req);
    g_winhttp.pCloseHandle(h_connect);
    g_winhttp.pCloseHandle(h_session);
    return out;
}

struct encrypted_session_t
{
    alignas(64) uint8_t blob[512];
    uint64_t rolling_key;
    uint64_t xor_mask;
    bool valid;
};

struct session_data_t
{
    bool     initialized;
    uint64_t session_hash;
    uint64_t hwid_hash;
    uint64_t local_hwid_hash;
    uint64_t init_timestamp;
    uint64_t xor_key;
    uint64_t code_hash;
    uint64_t heartbeat_counter;
    uint64_t last_heartbeat_tsc;
    uint64_t vtable_crypt_key;
    char     session_token[130];
    char     hwid[66];
    char     license_key[130];
};

std::mutex g_session_mtx;
anti_tamper::heap_encrypt::secure_heap_header_t* g_enc_session_secure = nullptr;

alignas(64) uint8_t  g_key_seed[32] = {};
bool g_key_seed_valid = false;
std::mutex g_key_seed_mtx;

void encrypt_session_blob(session_data_t* plain, encrypted_session_t* enc)
{
    static_assert(sizeof(session_data_t) <= sizeof(enc->blob), "session too large");
    memcpy(enc->blob, plain, sizeof(session_data_t));
    uint64_t key = enc->rolling_key ^ enc->xor_mask ^ __rdtsc();
    enc->rolling_key = key;
    uint8_t iv[16];
    std::memcpy(iv, &key, 8);
    std::memcpy(iv + 8, &enc->xor_mask, 8);
    for (int i = 0; i < 8; ++i)
        iv[i] ^= static_cast<uint8_t>((enc->xor_mask >> (i * 8)) & 0xFFull);
    anti_tamper::wb_crypto::ctr_crypt(enc->blob, enc->blob, sizeof(session_data_t), iv);
    enc->valid = true;
    SecureZeroMemory(iv, sizeof(iv));
}

bool decrypt_session_blob(encrypted_session_t* enc, session_data_t* out)
{
    if (!enc->valid) return false;

    bool result = false;
    uint64_t prev_key = 0;
    uint8_t iv[16] = {};
    alignas(8) uint8_t tmp[sizeof(session_data_t)];

    CFF_BEGIN(dec_session_cff)
    CFF_STATE(dec_session_cff, 0)
    {
        prev_key = enc->rolling_key;
        std::memcpy(iv, &prev_key, 8);
        std::memcpy(iv + 8, &enc->xor_mask, 8);
        for (int i = 0; i < 8; ++i)
            iv[i] ^= static_cast<uint8_t>((enc->xor_mask >> (i * 8)) & 0xFFull);
        CFF_GOTO(dec_session_cff, 1);
    }
    CFF_STATE(dec_session_cff, 1)
    {
        std::memcpy(tmp, enc->blob, sizeof(session_data_t));
        anti_tamper::wb_crypto::ctr_crypt(tmp, tmp, sizeof(session_data_t), iv);
        std::memcpy(out, tmp, sizeof(session_data_t));
        SecureZeroMemory(tmp, sizeof(tmp));
        result = true;
        CFF_EXIT(dec_session_cff);
    }
    CFF_END(dec_session_cff)

    SecureZeroMemory(iv, sizeof(iv));
    return result;
}

void store_session(const session_data_t& data)
{
    session_data_t copy = data;
    encrypted_session_t enc = {};
    enc.rolling_key = __rdtsc() ^ 0x5DEECE66DULL;
    enc.xor_mask = __rdtsc() ^ 0x6A09E667BB67AE85ULL;
    encrypt_session_blob(&copy, &enc);
    SecureZeroMemory(&copy, sizeof(copy));

    anti_tamper::heap_encrypt::secure_heap_header_t* new_hdr =
        anti_tamper::heap_encrypt::secure_alloc(static_cast<uint32_t>(sizeof(encrypted_session_t)));
    if (new_hdr)
    {
        anti_tamper::heap_encrypt::secure_accessor_t acc(new_hdr);
        if (acc.header)
        {
            std::memcpy(acc.buffer, &enc, sizeof(encrypted_session_t));
            acc.mark_modified();
        }
    }
    SecureZeroMemory(&enc, sizeof(enc));

    anti_tamper::heap_encrypt::secure_heap_header_t* old = g_enc_session_secure;
    g_enc_session_secure = new_hdr;
    if (old) anti_tamper::heap_encrypt::secure_free(old);
}

bool load_session(session_data_t& out)
{
    if (!g_enc_session_secure) return false;
    anti_tamper::heap_encrypt::secure_accessor_t acc(g_enc_session_secure);
    if (!acc.header) return false;
    encrypted_session_t enc;
    std::memcpy(&enc, acc.buffer, sizeof(encrypted_session_t));
    bool result = decrypt_session_blob(&enc, &out);
    SecureZeroMemory(&enc, sizeof(enc));
    return result;
}

uint64_t g_vtable_crypt_key = 0;
arc_comm_vtable_t g_vtable = {};
std::atomic<bool> g_vtable_ready{false};
uint64_t g_vtable_integrity = 0;

#pragma section(".licbind", read)
__declspec(allocate(".licbind")) volatile uint8_t g_license_bind_slot[32] = {
    0xCC,0xCC,0xCC,0xCC,0xCC,0xCC,0xCC,0xCC,
    0xCC,0xCC,0xCC,0xCC,0xCC,0xCC,0xCC,0xCC,
    0xCC,0xCC,0xCC,0xCC,0xCC,0xCC,0xCC,0xCC,
    0xCC,0xCC,0xCC,0xCC,0xCC,0xCC,0xCC,0xCC
};

#pragma section(".feat", read)
__declspec(allocate(".feat")) volatile uint8_t g_feature_blob[4096] = {};

constexpr uint32_t kFeatureMagic       = 0x46454154u;
constexpr uint32_t kFeatureMaxBlobSize = 4096u - 16u;
constexpr uint32_t kFeatureEntryMaxLen = 512u;

struct feature_entry_header_t
{
    uint32_t feature_id;
    uint32_t ciphertext_offset;
    uint32_t ciphertext_len;
    uint32_t entry_size;
    uint8_t  iv[12];
    uint8_t  tag[16];
};

constexpr uint32_t kFeatureEntryHeaderSize = static_cast<uint32_t>(sizeof(feature_entry_header_t));

struct feature_blob_header_t
{
    uint32_t magic;
    uint32_t version;
    uint32_t entry_count;
    uint32_t total_size;
};

anti_tamper::heap_encrypt::secure_heap_header_t* g_bind_secret_secure = nullptr;
uint64_t g_bind_secret_xor_key[4] = {};
bool     g_bind_secret_loaded = false;
std::mutex g_bind_secret_mtx;

void bind_secret_obf_store_unlocked(const uint8_t plain[32])
{
    uint64_t entropy = __rdtsc();
    for (int slot = 0; slot < 4; ++slot)
    {
        entropy += 0x9E3779B97F4A7C15ULL;
        uint64_t z = entropy;
        z = (z ^ (z >> 30)) * 0xBF58476D1CE4E5B9ULL;
        z = (z ^ (z >> 27)) * 0x94D049BB133111EBULL;
        g_bind_secret_xor_key[slot] = z ^ (z >> 31);
    }
    uint8_t obf[32] = {};
    for (int i = 0; i < 32; i += 8)
    {
        uint64_t v = 0;
        memcpy(&v, plain + i, 8);
        v ^= g_bind_secret_xor_key[i / 8];
        memcpy(obf + i, &v, 8);
    }

    anti_tamper::heap_encrypt::secure_heap_header_t* new_hdr =
        anti_tamper::heap_encrypt::secure_alloc(32);
    if (new_hdr)
    {
        anti_tamper::heap_encrypt::secure_accessor_t acc(new_hdr);
        if (acc.header)
        {
            std::memcpy(acc.buffer, obf, 32);
            acc.mark_modified();
        }
    }
    SecureZeroMemory(obf, sizeof(obf));

    anti_tamper::heap_encrypt::secure_heap_header_t* old = g_bind_secret_secure;
    g_bind_secret_secure = new_hdr;
    if (old) anti_tamper::heap_encrypt::secure_free(old);
}

void bind_secret_obf_load_unlocked(uint8_t out[32])
{
    if (!g_bind_secret_secure)
    {
        SecureZeroMemory(out, 32);
        return;
    }
    anti_tamper::heap_encrypt::secure_accessor_t acc(g_bind_secret_secure);
    if (!acc.header)
    {
        SecureZeroMemory(out, 32);
        return;
    }
    uint8_t obf[32] = {};
    std::memcpy(obf, acc.buffer, 32);
    for (int i = 0; i < 32; i += 8)
    {
        uint64_t v = 0;
        memcpy(&v, obf + i, 8);
        v ^= g_bind_secret_xor_key[i / 8];
        memcpy(out + i, &v, 8);
    }
    SecureZeroMemory(obf, sizeof(obf));
}

bool load_bind_secret()
{
    std::lock_guard<std::mutex> lk(g_bind_secret_mtx);
    if (g_bind_secret_loaded) return true;
    uint8_t staging[32] = {};
    int sentinel_count = 0;
    for (int i = 0; i < 32; ++i) {
        const uint8_t value = static_cast<uint8_t>(g_license_bind_slot[i]);
        if (value == 0xCC) ++sentinel_count;
        staging[i] = value;
    }
    if (sentinel_count == 32) {
        SecureZeroMemory(staging, sizeof(staging));
        return false;
    }
    bind_secret_obf_store_unlocked(staging);
    SecureZeroMemory(staging, sizeof(staging));
    g_bind_secret_loaded = true;
    return true;
}

struct arc_self_integrity_t
{
    uint8_t  text_sha256[32];
    uint64_t block_chain_root;
    uint64_t block_count;
    bool     captured;
};

arc_self_integrity_t g_self_integrity = {};
std::mutex g_self_integrity_mtx;

bool sha256_block(const uint8_t* data, size_t size, uint8_t out[32])
{
    if (!data || size == 0 || !out) return false;
    BCRYPT_ALG_HANDLE  hAlg  = nullptr;
    BCRYPT_HASH_HANDLE hHash = nullptr;
    NTSTATUS st = BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_SHA256_ALGORITHM, nullptr, 0);
    if (!BCRYPT_SUCCESS(st) || !hAlg) return false;
    bool ok = false;
    st = BCryptCreateHash(hAlg, &hHash, nullptr, 0, nullptr, 0, 0);
    if (BCRYPT_SUCCESS(st) && hHash)
    {
        st = BCryptHashData(hHash, const_cast<PUCHAR>(data), static_cast<ULONG>(size), 0);
        if (BCRYPT_SUCCESS(st))
            st = BCryptFinishHash(hHash, out, 32, 0);
        ok = BCRYPT_SUCCESS(st);
    }
    if (hHash) BCryptDestroyHash(hHash);
    BCryptCloseAlgorithmProvider(hAlg, 0);
    return ok;
}

bool hmac_sha256_full(const uint8_t* key, uint32_t key_len,
                      const uint8_t* data, size_t data_len,
                      uint8_t out[32])
{
    if (!key || !data || !out || key_len == 0 || data_len == 0) return false;
    BCRYPT_ALG_HANDLE  hAlg  = nullptr;
    BCRYPT_HASH_HANDLE hHash = nullptr;
    NTSTATUS st = BCryptOpenAlgorithmProvider(
        &hAlg, BCRYPT_SHA256_ALGORITHM, nullptr, BCRYPT_ALG_HANDLE_HMAC_FLAG);
    if (!BCRYPT_SUCCESS(st) || !hAlg) return false;
    bool ok = false;
    st = BCryptCreateHash(hAlg, &hHash, nullptr, 0,
        const_cast<PUCHAR>(key), key_len, 0);
    if (BCRYPT_SUCCESS(st) && hHash)
    {
        st = BCryptHashData(hHash, const_cast<PUCHAR>(data), static_cast<ULONG>(data_len), 0);
        if (BCRYPT_SUCCESS(st))
            st = BCryptFinishHash(hHash, out, 32, 0);
        ok = BCRYPT_SUCCESS(st);
    }
    if (hHash) BCryptDestroyHash(hHash);
    BCryptCloseAlgorithmProvider(hAlg, 0);
    return ok;
}

bool hkdf_sha256(const uint8_t* ikm, uint32_t ikm_len,
                 const uint8_t* salt, uint32_t salt_len,
                 const uint8_t* info, uint32_t info_len,
                 uint8_t* out, uint32_t out_len)
{
    if (!ikm || !out || ikm_len == 0 || out_len == 0 || out_len > 8160) return false;
    uint8_t prk[32];
    if (salt_len == 0)
    {
        uint8_t zero_salt[32] = {};
        if (!hmac_sha256_full(zero_salt, 32, ikm, ikm_len, prk)) return false;
    }
    else
    {
        if (!hmac_sha256_full(salt, salt_len, ikm, ikm_len, prk)) return false;
    }
    uint8_t t[32] = {};
    uint32_t pos = 0;
    uint8_t counter = 1;
    uint32_t t_len = 0;
    std::vector<uint8_t> buf;
    buf.reserve(32 + info_len + 1);
    while (pos < out_len)
    {
        buf.clear();
        if (t_len > 0) buf.insert(buf.end(), t, t + t_len);
        if (info && info_len) buf.insert(buf.end(), info, info + info_len);
        buf.push_back(counter);
        if (!hmac_sha256_full(prk, 32, buf.data(), buf.size(), t))
        {
            SecureZeroMemory(prk, sizeof(prk));
            SecureZeroMemory(t, sizeof(t));
            return false;
        }
        t_len = 32;
        uint32_t copy_len = (out_len - pos) < 32 ? (out_len - pos) : 32;
        memcpy(out + pos, t, copy_len);
        pos += copy_len;
        ++counter;
    }
    SecureZeroMemory(prk, sizeof(prk));
    SecureZeroMemory(t, sizeof(t));
    return true;
}

static void log_vtable_state(const char* phase, uint64_t integrity_value);

__forceinline uint64_t compute_vtable_integrity()
{
    uint8_t buf[sizeof(arc_comm_vtable_t)];
    memcpy(buf, &g_vtable, sizeof(buf));
    return siphash_2_4(buf, sizeof(buf), g_vtable_crypt_key, g_vtable_crypt_key ^ 0x5DEECE66DULL);
}

bool verify_vtable()
{
    if (g_vtable_integrity == 0) return true;
    uint64_t fresh = compute_vtable_integrity();
    if (fresh == g_vtable_integrity) return true;
    char detail[192];
    _snprintf_s(detail, sizeof(detail), _TRUNCATE,
        "verify_vtable_mismatch stored=0x%016llX fresh=0x%016llX crypt_key=0x%016llX tid=%lu",
        (unsigned long long)g_vtable_integrity,
        (unsigned long long)fresh,
        (unsigned long long)g_vtable_crypt_key,
        GetCurrentThreadId());
    arc_log("vtable", detail);
    log_vtable_state("verify_failed", fresh);
    return false;
}

static uint64_t g_device_enc = 0;
static uint64_t g_prebound_device_enc = 0;
static uint64_t g_prebound_device_key = 0;

uint64_t make_prebound_device_key()
{
    uint64_t key = __rdtsc();
    key ^= _rotl64(reinterpret_cast<uint64_t>(&g_prebound_device_enc), 9);
    key ^= _rotr64((static_cast<uint64_t>(GetCurrentProcessId()) << 32) | GetCurrentThreadId(), 13);
    key ^= 0x9E3779B97F4A7C15ULL;
    if (key == 0)
        key = 0xA5A5F00D3C6EF372ULL;
    return key;
}

void bind_prebound_device(voyager::device_t* driver_device)
{
    uint64_t key = make_prebound_device_key();
    uint64_t ptr = reinterpret_cast<uint64_t>(driver_device);
    g_prebound_device_key = key;
    g_prebound_device_enc = ptr ^ key ^ _rotl64(key, 23) ^ _rotr64(key, 7);
}

voyager::device_t* get_prebound_device()
{
    uint64_t enc = g_prebound_device_enc;
    uint64_t key = g_prebound_device_key;
    if (enc == 0 || key == 0) return nullptr;
    return reinterpret_cast<voyager::device_t*>(enc ^ key ^ _rotl64(key, 23) ^ _rotr64(key, 7));
}

void store_device_enc(uint64_t crypt_key)
{
    voyager::device_t* driver_device = get_prebound_device();
    if (!driver_device)
        driver_device = device.get();
    uint64_t ptr = reinterpret_cast<uint64_t>(driver_device);
    g_device_enc = ptr ^ crypt_key ^ _rotl64(crypt_key, 17) ^ _rotr64(crypt_key, 11);
}

voyager::device_t* get_device_enc(uint64_t crypt_key)
{
    uint64_t enc = g_device_enc;
    if (enc == 0) return nullptr;
    return reinterpret_cast<voyager::device_t*>(enc ^ crypt_key ^ _rotl64(crypt_key, 17) ^ _rotr64(crypt_key, 11));
}

__declspec(noinline) DWORD refresh_device_heartbeat_seh(voyager::device_t* dev, bool* out_ok)
{
    if (out_ok)
        *out_ok = false;
    if (!dev || !out_ok)
        return ERROR_INVALID_PARAMETER;
    __try
    {
        *out_ok = dev->refresh_heartbeat();
        return ERROR_SUCCESS;
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        return GetExceptionCode();
    }
}

__declspec(noinline) DWORD send_device_heartbeat_seh(voyager::device_t* dev, bool* out_ok)
{
    if (out_ok)
        *out_ok = false;
    if (!dev || !out_ok)
        return ERROR_INVALID_PARAMETER;
    __try
    {
        *out_ok = dev->send_heartbeat();
        return ERROR_SUCCESS;
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        return GetExceptionCode();
    }
}

__declspec(noreturn) __forceinline void enforce_violation(const char* reason, const char* extra);

__declspec(noreturn) __forceinline void enforce_violation_id(uint64_t reason_id, const char* extra)
{
    char buf[20] = {};
    _snprintf_s(buf, sizeof(buf), _TRUNCATE, "rid:%016llx", static_cast<unsigned long long>(reason_id));
    enforce_violation(buf, extra);
}

__declspec(noreturn) __forceinline void enforce_violation(const char* reason, const char* extra)
{
    const char* r = reason ? reason : "arc_unknown";
    const char* x = extra ? extra : "";
    arc_publish_state(arc_state_violation, "enforce_violation", r);

    {
        char log_line[384];
        _snprintf_s(log_line, sizeof(log_line), _TRUNCATE,
            "enforce_violation reason=%s extra=%s tid=%lu", r, x, GetCurrentThreadId());
        arc_log("violation", log_line);
    }
    arc_log("violation", "step01_pre_session_lock");

    char hwid_buf[66] = {};
    char sess_buf[17] = {};
    if (g_session_mtx.try_lock())
    {
        arc_log("violation", "step02_session_locked");
        session_data_t sess = {};
        if (g_enc_session_secure)
        {
            anti_tamper::heap_encrypt::secure_accessor_t sacc(g_enc_session_secure);
            if (sacc.header)
            {
                encrypted_session_t enc;
                std::memcpy(&enc, sacc.buffer, sizeof(encrypted_session_t));
                if (decrypt_session_blob(&enc, &sess) && sess.initialized)
                {
                    strncpy_s(hwid_buf, sizeof(hwid_buf), sess.hwid, _TRUNCATE);
                    strncpy_s(sess_buf, sizeof(sess_buf), sess.session_token, _TRUNCATE);
                }
                SecureZeroMemory(&enc, sizeof(enc));
            }
        }
        SecureZeroMemory(&sess, sizeof(sess));
        g_session_mtx.unlock();
        arc_log("violation", "step03_session_unlocked");
    }
    else
    {
        arc_log("violation", "step02_session_lock_skipped_busy");
    }

    arc_log("violation", "step04_pre_exe_path");
    {
        char crash_path[MAX_PATH] = {};
        if (!diag::build_log_path("aida_crash.log", crash_path, sizeof(crash_path)))
            crash_path[0] = '\0';
        arc_log("violation", "step05_exe_path_resolved");

        SYSTEMTIME st{};
        GetLocalTime(&st);

        void* return_addr = _ReturnAddress();
        void* stack_frames[12] = {};
        USHORT frame_count = RtlCaptureStackBackTrace(0, 12, stack_frames, nullptr);
        arc_log("violation", "step06_stack_captured");

        char stack_str[640] = {};
        int stack_off = 0;
        for (USHORT i = 0; i < frame_count && stack_off < static_cast<int>(sizeof(stack_str) - 24); ++i)
        {
            stack_off += _snprintf_s(stack_str + stack_off, sizeof(stack_str) - stack_off, _TRUNCATE,
                "%s%016llX",
                (i == 0 ? "" : " "),
                static_cast<unsigned long long>(reinterpret_cast<uintptr_t>(stack_frames[i])));
        }
        {
            char stack_log[700];
            _snprintf_s(stack_log, sizeof(stack_log), _TRUNCATE,
                "step07_stack_str return=0x%016llX frames=%u trace=%s",
                static_cast<unsigned long long>(reinterpret_cast<uintptr_t>(return_addr)),
                static_cast<unsigned>(frame_count),
                stack_str);
            arc_log("violation", stack_log);
        }

        HMODULE arc_mod = nullptr;
        GetModuleHandleExA(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
            reinterpret_cast<LPCSTR>(&enforce_violation), &arc_mod);
        char arc_mod_name[MAX_PATH] = "<unknown>";
        if (arc_mod)
            GetModuleFileNameA(arc_mod, arc_mod_name, MAX_PATH);
        arc_log("violation", "step08_arc_module_resolved");

        const uint64_t hwid_hash = fnv1a_str(hwid_buf);
        const uint64_t sess_hash = fnv1a_str(sess_buf);
        const size_t hwid_len = strnlen_s(hwid_buf, sizeof(hwid_buf));
        const size_t sess_len = strnlen_s(sess_buf, sizeof(sess_buf));

        char crash_buf[2048];
        int n = _snprintf_s(crash_buf, sizeof(crash_buf), _TRUNCATE,
            "[%02d:%02d:%02d.%03d] [arc/violation] FAST_FAIL\r\n"
            "Reason=%s\r\n"
            "Extra=%s\r\n"
            "FastFailCode=0xA1DA\r\n"
            "Tid=%lu Pid=%lu\r\n"
            "ReturnAddress=0x%016llX\r\n"
            "ArcModule=%s\r\n"
            "HwidHash=0x%016llX HwidLen=%zu\r\n"
            "SessionHash=0x%016llX SessionLen=%zu\r\n"
            "EpochTs=%lld\r\n"
            "StackBackTrace: %s\r\n",
            st.wHour, st.wMinute, st.wSecond, st.wMilliseconds,
            r, x,
            GetCurrentThreadId(), GetCurrentProcessId(),
            static_cast<unsigned long long>(reinterpret_cast<uintptr_t>(return_addr)),
            arc_mod_name,
            static_cast<unsigned long long>(hwid_hash),
            hwid_len,
            static_cast<unsigned long long>(sess_hash),
            sess_len,
            static_cast<long long>(time(nullptr)),
            stack_str);

        if (n > 0)
        {
            arc_log("violation", "step09_pre_crashlog_open");
            HANDLE hf = crash_path[0] != '\0'
                ? CreateFileA(crash_path,
                    FILE_APPEND_DATA | SYNCHRONIZE,
                    FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr,
                    OPEN_ALWAYS,
                    FILE_ATTRIBUTE_NORMAL | FILE_FLAG_WRITE_THROUGH, nullptr)
                : INVALID_HANDLE_VALUE;
            arc_log("violation", "step10_post_crashlog_open");
            if (hf != INVALID_HANDLE_VALUE)
            {
                DWORD written = 0;
                arc_log("violation", "step11_pre_crashlog_write");
                WriteFile(hf, crash_buf, static_cast<DWORD>(n), &written, nullptr);
                arc_log("violation", "step12_post_crashlog_write");
                FlushFileBuffers(hf);
                arc_log("violation", "step13_post_crashlog_flush");
                CloseHandle(hf);
                arc_log("violation", "step14_post_crashlog_close");
            }
            else
            {
                arc_log("violation", "step10b_crashlog_open_failed");
            }
            OutputDebugStringA(crash_buf);
            arc_log("violation", "step15_post_outputdebugstring");
        }
        else
        {
            arc_log("violation", "step09b_crashbuf_format_failed");
        }
    }

    arc_log("violation", "step16_pre_load_server_url");
    std::string server = load_server_url();
    {
        char srv_log[160];
        _snprintf_s(srv_log, sizeof(srv_log), _TRUNCATE,
            "step17_post_load_server_url empty=%d len=%llu",
            server.empty() ? 1 : 0,
            (unsigned long long)server.size());
        arc_log("violation", srv_log);
    }
    if (!server.empty())
    {
        auto path = OBFSTR("/api/license/violation");
        std::string url = server + path;

        std::string body;
        body.reserve(384);
        auto k_source = OBFSTR("source");
        auto v_source = OBFSTR("arc");
        auto k_reason = OBFSTR("reason");
        auto k_extra  = OBFSTR("extra");
        auto k_ts     = OBFSTR("ts");
        auto k_hwid   = OBFSTR("hwid_hash");
        auto k_sess   = OBFSTR("session_hash");

        char ts_str[32];
        _snprintf_s(ts_str, sizeof(ts_str), _TRUNCATE,
            "%lld", static_cast<long long>(time(nullptr)));

        body += "{\"";
        body += k_source; body += "\":\""; body += v_source; body += "\",\"";
        body += k_reason; body += "\":\""; body += r;        body += "\",\"";
        body += k_extra;  body += "\":\""; body += x;        body += "\",\"";
        body += k_ts;     body += "\":";   body += ts_str;   body += ",\"";
        char hwid_hash_hex[32] = {};
        char sess_hash_hex[32] = {};
        _snprintf_s(hwid_hash_hex, sizeof(hwid_hash_hex), _TRUNCATE,
            "%016llx", static_cast<unsigned long long>(fnv1a_str(hwid_buf)));
        _snprintf_s(sess_hash_hex, sizeof(sess_hash_hex), _TRUNCATE,
            "%016llx", static_cast<unsigned long long>(fnv1a_str(sess_buf)));
        body += k_hwid;   body += "\":\""; body += hwid_hash_hex; body += "\",\"";
        body += k_sess;   body += "\":\""; body += sess_hash_hex; body += "\"}";

        arc_log("violation", "step18_pre_http_post");
        http_post_json(url.c_str(), body.c_str());
        arc_log("violation", "step19_post_http_post");
    }
    else
    {
        arc_log("violation", "step18_skip_http_post_no_server_url");
    }

    SecureZeroMemory(hwid_buf, sizeof(hwid_buf));
    SecureZeroMemory(sess_buf, sizeof(sess_buf));
    arc_log("violation", "step20_pre_fastfail");

    __fastfail(0xA1DA);
}

static std::atomic<uint32_t> g_rdtsc_debugger_count{0};
static std::atomic<uint64_t> g_rdtsc_debugger_window_start_ms{0};

static void reset_rdtsc_debugger_quorum()
{
    g_rdtsc_debugger_count.store(0, std::memory_order_release);
    g_rdtsc_debugger_window_start_ms.store(0, std::memory_order_release);
}

static bool rdtsc_debugger_quorum_reached(uint64_t delta, const char* caller_context)
{
    constexpr uint64_t kWindowMs = 15000;
    constexpr uint64_t kMinEscalateAgeMs = 1200;
    constexpr uint32_t kRequiredSignals = 3;

    const uint64_t now = static_cast<uint64_t>(GetTickCount64());
    uint64_t window_start = g_rdtsc_debugger_window_start_ms.load(std::memory_order_acquire);
    for (;;)
    {
        const bool reset_window = window_start == 0 || now < window_start || now - window_start > kWindowMs;
        if (!reset_window)
            break;
        if (g_rdtsc_debugger_window_start_ms.compare_exchange_weak(
                window_start, now, std::memory_order_acq_rel, std::memory_order_acquire))
        {
            g_rdtsc_debugger_count.store(0, std::memory_order_release);
            window_start = now;
            break;
        }
    }

    const uint32_t count = g_rdtsc_debugger_count.fetch_add(1, std::memory_order_acq_rel) + 1;
    const uint64_t age_ms = now >= window_start ? now - window_start : 0;
    const bool escalated = count >= kRequiredSignals && age_ms >= kMinEscalateAgeMs;
    char dbg[224];
    _snprintf_s(dbg, sizeof(dbg), _TRUNCATE,
        "check_debugger: rdtsc_delta=%llu count=%u window_age_ms=%llu escalated=%d caller=%s state=%s tid=%lu",
        static_cast<unsigned long long>(delta),
        count,
        static_cast<unsigned long long>(age_ms),
        escalated ? 1 : 0,
        (caller_context && caller_context[0]) ? caller_context : "unknown",
        arc_runtime_state_name(g_arc_runtime_state.load(std::memory_order_acquire)),
        static_cast<unsigned long>(GetCurrentThreadId()));
    arc_log("debugger", dbg);
    if (escalated)
        reset_rdtsc_debugger_quorum();
    return escalated;
}

bool check_debugger(const char* caller_context)
{
    auto* peb = reinterpret_cast<const uint8_t*>(__readgsqword(0x60));
    if (!peb) return false;

    if (peb[2] != 0)
    {
        arc_log("debugger", "check_debugger: peb_being_debugged");
        return true;
    }

    uint32_t flags = *reinterpret_cast<const uint32_t*>(peb + 0xBC);
    if (flags & 0x70)
    {
        char dbg[64];
        _snprintf_s(dbg, sizeof(dbg), _TRUNCATE, "check_debugger: ntglobalflag=0x%X", flags);
        arc_log("debugger", dbg);
        return true;
    }

    unsigned int aux;
    uint64_t t0 = __rdtscp(&aux);
    volatile int dummy = 0;
    for (int i = 0; i < 100; ++i) dummy += i;
    uint64_t t1 = __rdtscp(&aux);
    const uint64_t rdtsc_delta = t1 - t0;
    if (rdtsc_delta > 10000000ULL)
    {
        if (rdtsc_debugger_quorum_reached(rdtsc_delta, caller_context))
            return true;
    }

    auto* kuser = reinterpret_cast<const volatile uint8_t*>(
        reinterpret_cast<void*>(static_cast<uintptr_t>(0x7FFE0000)));
    if (kuser[0x2D4] != 0)
    {
        arc_log("debugger", "check_debugger: kd_enabled");
        return true;
    }

    CONTEXT ctx{};
    ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
    using NtGetContextThread_t = LONG(NTAPI*)(HANDLE, PCONTEXT);
    auto ntdll_hw = PEB_MOD(L"ntdll.dll");
    auto pNtGetCtx = reinterpret_cast<NtGetContextThread_t>(
        PEB_FN(ntdll_hw, "NtGetContextThread"));
    if (pNtGetCtx && pNtGetCtx(reinterpret_cast<HANDLE>((LONG_PTR)-2), &ctx) == 0)
    {
        if (ctx.Dr0 | ctx.Dr1 | ctx.Dr2 | ctx.Dr3)
        {
            arc_log("debugger", "check_debugger: hw_breakpoints");
            return true;
        }
    }

    using NtQIP_t = LONG(WINAPI*)(HANDLE, ULONG, PVOID, ULONG, PULONG);
    auto ntdll = PEB_MOD(L"ntdll.dll");
    if (ntdll)
    {
        auto fn = reinterpret_cast<NtQIP_t>(PEB_FN(ntdll, "NtQueryInformationProcess"));
        if (fn)
        {
            ULONG_PTR debug_port = 0;
            LONG st = fn(GetCurrentProcess(), 7, &debug_port, sizeof(debug_port), nullptr);
            if (st == 0 && debug_port != 0)
            {
                arc_log("debugger", "check_debugger: debug_port");
                return true;
            }
        }
    }

    const uint64_t process_heap = *reinterpret_cast<const uint64_t*>(peb + 0x30);
    if (process_heap != 0)
    {
        const auto* heap = reinterpret_cast<const uint8_t*>(process_heap);
        const uint32_t heap_flags = *reinterpret_cast<const uint32_t*>(heap + 0x70);
        const uint32_t heap_force_flags = *reinterpret_cast<const uint32_t*>(heap + 0x74);
        if (heap_force_flags != 0 || (heap_flags & ~0x02u) != 0)
        {
            char dbg[96];
            _snprintf_s(dbg, sizeof(dbg), _TRUNCATE, "check_debugger: heap_flags=0x%X force=0x%X", heap_flags, heap_force_flags);
            arc_log("debugger", dbg);
            return true;
        }
    }

    if (ntdll)
    {
        auto fn = reinterpret_cast<NtQIP_t>(PEB_FN(ntdll, "NtQueryInformationProcess"));
        if (fn)
        {
            HANDLE debug_object = nullptr;
            LONG st = fn(GetCurrentProcess(), 30, &debug_object, sizeof(debug_object), nullptr);
            if (st == 0 && debug_object != nullptr)
            {
                arc_log("debugger", "check_debugger: debug_object_handle");
                return true;
            }
        }
    }

    if (ntdll)
    {
        auto fn = reinterpret_cast<NtQIP_t>(PEB_FN(ntdll, "NtQueryInformationProcess"));
        if (fn)
        {
            ULONG no_debug_inherit = 1;
            LONG st = fn(GetCurrentProcess(), 31, &no_debug_inherit, sizeof(no_debug_inherit), nullptr);
            if (st == 0 && no_debug_inherit == 0)
            {
                arc_log("debugger", "check_debugger: debug_flags_inherit");
                return true;
            }
        }
    }

    auto kernel32 = PEB_MOD(L"kernel32.dll");
    if (kernel32)
    {
        using CheckRemoteDebuggerPresent_t = BOOL(WINAPI*)(HANDLE, PBOOL);
        auto fn = reinterpret_cast<CheckRemoteDebuggerPresent_t>(PEB_FN(kernel32, "CheckRemoteDebuggerPresent"));
        if (fn)
        {
            BOOL remote = FALSE;
            if (fn(GetCurrentProcess(), &remote) && remote != FALSE)
            {
                arc_log("debugger", "check_debugger: remote_debugger");
                return true;
            }
        }
    }

    if (kernel32)
    {
        using OutputDebugStringA_t = void(WINAPI*)(LPCSTR);
        using SetLastError_t = void(WINAPI*)(DWORD);
        using GetLastError_t = DWORD(WINAPI*)(void);
        auto pODS = reinterpret_cast<OutputDebugStringA_t>(PEB_FN(kernel32, "OutputDebugStringA"));
        auto pSet = reinterpret_cast<SetLastError_t>(PEB_FN(kernel32, "SetLastError"));
        auto pGet = reinterpret_cast<GetLastError_t>(PEB_FN(kernel32, "GetLastError"));
        if (pODS && pSet && pGet)
        {
            const DWORD sentinel = 0xC0FFEE42u;
            pSet(sentinel);
            pODS("");
            if (pGet() != sentinel)
            {
                arc_log("debugger", "check_debugger: ods_trap");
                return true;
            }
        }
    }

    if (ntdll)
    {
        auto fn = reinterpret_cast<NtQIP_t>(PEB_FN(ntdll, "NtQueryInformationProcess"));
        if (fn)
        {
            PVOID instr_callback = nullptr;
            LONG st = fn(GetCurrentProcess(), 40, &instr_callback, sizeof(instr_callback), nullptr);
            if (st == 0 && instr_callback != nullptr)
            {
                arc_log("debugger", "check_debugger: instrumentation_callback");
                return true;
            }
        }
    }

    if (ntdll)
    {
        using NtSetInformationThread_t = LONG(NTAPI*)(HANDLE, ULONG, PVOID, ULONG);
        using NtQueryInformationThread_t = LONG(NTAPI*)(HANDLE, ULONG, PVOID, ULONG, PULONG);
        auto pSet = reinterpret_cast<NtSetInformationThread_t>(PEB_FN(ntdll, "NtSetInformationThread"));
        auto pQuery = reinterpret_cast<NtQueryInformationThread_t>(PEB_FN(ntdll, "NtQueryInformationThread"));
        if (pSet && pQuery)
        {
            HANDLE cur_thread = reinterpret_cast<HANDLE>((LONG_PTR)-2);
            pSet(cur_thread, 0x11, nullptr, 0);
            ULONG hidden = 0;
            LONG st = pQuery(cur_thread, 0x11, &hidden, sizeof(hidden), nullptr);
            if (st == 0 && hidden == 0)
            {
                arc_log("debugger", "check_debugger: hide_from_debugger_overridden");
                return true;
            }
        }
    }

    return false;
}

struct recomputed_hwid_t
{
    std::string hwid;
    bool tpm_present = false;
    uint32_t factor_present_mask = 0;
};

recomputed_hwid_t recompute_hwid()
{
    recomputed_hwid_t result{};
    aida::hardware_id::v2::collection_t collection{};
    std::string err;
    if (!aida::hardware_id::v2::collect(collection, err)) {
        char dbg[160];
        _snprintf_s(dbg, sizeof(dbg), _TRUNCATE,
            "recompute_hwid_v2_failed err=%.96s", err.c_str());
        arc_log("init", dbg);
        SecureZeroMemory(collection.hwid_hash.data(), collection.hwid_hash.size());
        for (auto& f : collection.factors)
        {
            SecureZeroMemory(f.factor_hash.data(), f.factor_hash.size());
            if (!f.bytes.empty()) SecureZeroMemory(f.bytes.data(), f.bytes.size());
        }
        result.hwid = "unavailable";
        return result;
    }
    uint32_t collected = 0;
    for (std::size_t i = 0; i < aida::hardware_id::v2::kFactorCount; ++i)
    {
        const auto& f = collection.factors[i];
        if (f.collected)
        {
            ++collected;
        }
    }
    std::string out = aida::hardware_id::v2::hash_to_hex(collection.hwid_hash);
    result.hwid = out;
    result.tpm_present = collection.tpm_present;
    result.factor_present_mask = collection.factor_present_mask;
    char dbg[192];
    _snprintf_s(dbg, sizeof(dbg), _TRUNCATE,
        "recompute_hwid_v2_ok mask=0x%08X collected=%u tpm=%d hwid_len=%zu",
        collection.factor_present_mask,
        collected,
        collection.tpm_present ? 1 : 0,
        out.size());
    arc_log("init", dbg);
    arc_log("init", "recompute_hwid_v2_tpm_policy disabled factor9=no_tpm");
    SecureZeroMemory(collection.hwid_hash.data(), collection.hwid_hash.size());
    for (auto& f : collection.factors)
    {
        SecureZeroMemory(f.factor_hash.data(), f.factor_hash.size());
        if (!f.bytes.empty()) SecureZeroMemory(f.bytes.data(), f.bytes.size());
    }
    return result;
}

uint64_t compute_own_code_hash()
{
    return scan_own_code_integrity(false, "compute").hash;
}

bool capture_self_integrity()
{
    MEMORY_BASIC_INFORMATION mbi = {};
    if (VirtualQuery(reinterpret_cast<const void*>(&capture_self_integrity), &mbi, sizeof(mbi)) == 0)
    {
        arc_log("integrity", "capture_virtualquery_self_failed");
        return false;
    }
    const auto hMod = static_cast<const uint8_t*>(mbi.AllocationBase);
    if (!hMod)
    {
        arc_log("integrity", "capture_allocation_base_null");
        return false;
    }

    BCRYPT_ALG_HANDLE  hAlg  = nullptr;
    BCRYPT_HASH_HANDLE hHash = nullptr;
    NTSTATUS st = BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_SHA256_ALGORITHM, nullptr, 0);
    if (!BCRYPT_SUCCESS(st) || !hAlg)
    {
        char buf[96];
        _snprintf_s(buf, sizeof(buf), _TRUNCATE,
            "capture_bcrypt_open_failed status=0x%08X",
            static_cast<unsigned>(st));
        arc_log("integrity", buf);
        return false;
    }
    st = BCryptCreateHash(hAlg, &hHash, nullptr, 0, nullptr, 0, 0);
    if (!BCRYPT_SUCCESS(st) || !hHash)
    {
        char buf[96];
        _snprintf_s(buf, sizeof(buf), _TRUNCATE,
            "capture_bcrypt_create_failed status=0x%08X",
            static_cast<unsigned>(st));
        arc_log("integrity", buf);
        BCryptCloseAlgorithmProvider(hAlg, 0);
        return false;
    }

    uint64_t block_count = 0;
    uint64_t skipped_mutable = 0;
    uint64_t skipped_unreadable = 0;
    uint64_t skipped_guarded = 0;
    const uintptr_t alloc_base = reinterpret_cast<uintptr_t>(hMod);
    uintptr_t addr = alloc_base;
    const uintptr_t scan_limit = alloc_base + (256ULL * 1024 * 1024);

    while (addr < scan_limit)
    {
        MEMORY_BASIC_INFORMATION r = {};
        if (VirtualQuery(reinterpret_cast<const void*>(addr), &r, sizeof(r)) == 0)
            break;
        if (r.RegionSize == 0)
            break;
        if (r.AllocationBase != mbi.AllocationBase)
            break;

        const bool exec = r.State == MEM_COMMIT && arc_is_exec_protect(r.Protect);
        if (exec && !arc_is_stable_exec_region(r))
        {
            if ((r.Protect & PAGE_GUARD) != 0)
                ++skipped_guarded;
            else if (!arc_is_readable_protect(r.Protect))
                ++skipped_unreadable;
            else if (arc_is_writable_protect(r.Protect))
                ++skipped_mutable;
        }

        if (arc_is_stable_exec_region(r))
        {
            const size_t size = r.RegionSize;
            if (size > 0 && size < 64ULL * 1024 * 1024)
            {
                if (BCRYPT_SUCCESS(BCryptHashData(hHash,
                    static_cast<PUCHAR>(r.BaseAddress),
                    static_cast<ULONG>(size), 0)))
                {
                    ++block_count;
                }
            }
        }
        addr += r.RegionSize;
    }

    uint8_t digest[32] = {};
    bool finish_ok = BCRYPT_SUCCESS(BCryptFinishHash(hHash, digest, 32, 0));
    BCryptDestroyHash(hHash);
    BCryptCloseAlgorithmProvider(hAlg, 0);

    if (!finish_ok || block_count == 0)
    {
        char buf[160];
        _snprintf_s(buf, sizeof(buf), _TRUNCATE,
            "capture_finish_failed ok=%d blocks=%llu skip_mutable=%llu skip_unreadable=%llu skip_guarded=%llu",
            finish_ok ? 1 : 0,
            static_cast<unsigned long long>(block_count),
            static_cast<unsigned long long>(skipped_mutable),
            static_cast<unsigned long long>(skipped_unreadable),
            static_cast<unsigned long long>(skipped_guarded));
        arc_log("integrity", buf);
        return false;
    }

    std::lock_guard<std::mutex> lk(g_self_integrity_mtx);
    memcpy(g_self_integrity.text_sha256, digest, 32);
    g_self_integrity.block_count = block_count;
    g_self_integrity.block_chain_root = siphash_2_4(
        digest, 32, block_count, 0xA1DAC0DE5EC0DEULL);
    g_self_integrity.captured = true;
    {
        uint64_t digest_prefix = 0;
        memcpy(&digest_prefix, digest, sizeof(digest_prefix));
        char buf[192];
        _snprintf_s(buf, sizeof(buf), _TRUNCATE,
            "capture_ok blocks=%llu root=0x%016llX digest0=0x%016llX skip_mutable=%llu skip_unreadable=%llu skip_guarded=%llu",
            static_cast<unsigned long long>(block_count),
            static_cast<unsigned long long>(g_self_integrity.block_chain_root),
            static_cast<unsigned long long>(digest_prefix),
            static_cast<unsigned long long>(skipped_mutable),
            static_cast<unsigned long long>(skipped_unreadable),
            static_cast<unsigned long long>(skipped_guarded));
        arc_log("integrity", buf);
    }
    return true;
}

bool verify_self_integrity()
{
    arc_self_integrity_t snapshot = {};
    {
        std::lock_guard<std::mutex> lk(g_self_integrity_mtx);
        if (!g_self_integrity.captured) return true;
        snapshot = g_self_integrity;
    }

    BCRYPT_ALG_HANDLE  hAlg  = nullptr;
    BCRYPT_HASH_HANDLE hHash = nullptr;
    NTSTATUS st = BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_SHA256_ALGORITHM, nullptr, 0);
    if (!BCRYPT_SUCCESS(st) || !hAlg)
    {
        char buf[96];
        _snprintf_s(buf, sizeof(buf), _TRUNCATE,
            "verify_bcrypt_open_failed status=0x%08X",
            static_cast<unsigned>(st));
        arc_log("integrity", buf);
        return false;
    }
    st = BCryptCreateHash(hAlg, &hHash, nullptr, 0, nullptr, 0, 0);
    if (!BCRYPT_SUCCESS(st) || !hHash)
    {
        char buf[96];
        _snprintf_s(buf, sizeof(buf), _TRUNCATE,
            "verify_bcrypt_create_failed status=0x%08X",
            static_cast<unsigned>(st));
        arc_log("integrity", buf);
        BCryptCloseAlgorithmProvider(hAlg, 0);
        return false;
    }

    MEMORY_BASIC_INFORMATION mbi = {};
    if (VirtualQuery(reinterpret_cast<const void*>(&verify_self_integrity), &mbi, sizeof(mbi)) == 0)
    {
        arc_log("integrity", "verify_virtualquery_self_failed");
        BCryptDestroyHash(hHash);
        BCryptCloseAlgorithmProvider(hAlg, 0);
        return false;
    }

    uint64_t block_count = 0;
    uint64_t skipped_mutable = 0;
    uint64_t skipped_unreadable = 0;
    uint64_t skipped_guarded = 0;
    const uintptr_t alloc_base = reinterpret_cast<uintptr_t>(mbi.AllocationBase);
    uintptr_t addr = alloc_base;
    const uintptr_t scan_limit = alloc_base + (256ULL * 1024 * 1024);

    while (addr < scan_limit)
    {
        MEMORY_BASIC_INFORMATION r = {};
        if (VirtualQuery(reinterpret_cast<const void*>(addr), &r, sizeof(r)) == 0) break;
        if (r.RegionSize == 0) break;
        if (r.AllocationBase != mbi.AllocationBase) break;

        const bool exec = r.State == MEM_COMMIT && arc_is_exec_protect(r.Protect);
        if (exec && !arc_is_stable_exec_region(r))
        {
            if ((r.Protect & PAGE_GUARD) != 0)
                ++skipped_guarded;
            else if (!arc_is_readable_protect(r.Protect))
                ++skipped_unreadable;
            else if (arc_is_writable_protect(r.Protect))
                ++skipped_mutable;
        }

        if (arc_is_stable_exec_region(r))
        {
            const size_t size = r.RegionSize;
            if (size > 0 && size < 64ULL * 1024 * 1024)
            {
                if (BCRYPT_SUCCESS(BCryptHashData(hHash,
                    static_cast<PUCHAR>(r.BaseAddress),
                    static_cast<ULONG>(size), 0)))
                {
                    ++block_count;
                }
            }
        }
        addr += r.RegionSize;
    }

    uint8_t digest[32] = {};
    bool finish_ok = BCRYPT_SUCCESS(BCryptFinishHash(hHash, digest, 32, 0));
    BCryptDestroyHash(hHash);
    BCryptCloseAlgorithmProvider(hAlg, 0);

    if (!finish_ok)
    {
        arc_log("integrity", "verify_finish_failed");
        return false;
    }
    if (block_count != snapshot.block_count)
    {
        char buf[160];
        _snprintf_s(buf, sizeof(buf), _TRUNCATE,
            "verify_block_count_mismatch current=%llu stored=%llu skip_mutable=%llu skip_unreadable=%llu skip_guarded=%llu",
            static_cast<unsigned long long>(block_count),
            static_cast<unsigned long long>(snapshot.block_count),
            static_cast<unsigned long long>(skipped_mutable),
            static_cast<unsigned long long>(skipped_unreadable),
            static_cast<unsigned long long>(skipped_guarded));
        arc_log("integrity", buf);
        return false;
    }
    if (memcmp(digest, snapshot.text_sha256, 32) != 0)
    {
        uint64_t current_prefix = 0;
        uint64_t stored_prefix = 0;
        memcpy(&current_prefix, digest, sizeof(current_prefix));
        memcpy(&stored_prefix, snapshot.text_sha256, sizeof(stored_prefix));
        char buf[160];
        _snprintf_s(buf, sizeof(buf), _TRUNCATE,
            "verify_digest_mismatch current0=0x%016llX stored0=0x%016llX blocks=%llu",
            static_cast<unsigned long long>(current_prefix),
            static_cast<unsigned long long>(stored_prefix),
            static_cast<unsigned long long>(block_count));
        arc_log("integrity", buf);
        scan_own_code_integrity(true, "verify_digest_mismatch");
        return false;
    }
    uint64_t recomputed_root = siphash_2_4(digest, 32, block_count, 0xA1DAC0DE5EC0DEULL);
    if (recomputed_root != snapshot.block_chain_root)
    {
        char buf[128];
        _snprintf_s(buf, sizeof(buf), _TRUNCATE,
            "verify_root_mismatch current=0x%016llX stored=0x%016llX",
            static_cast<unsigned long long>(recomputed_root),
            static_cast<unsigned long long>(snapshot.block_chain_root));
        arc_log("integrity", buf);
        return false;
    }
    return true;
}

bool is_session_valid_inner()
{
    session_data_t sess = {};
    if (!load_session(sess))
    {
        SecureZeroMemory(&sess, sizeof(sess));
        return false;
    }
    if (!sess.initialized)
    {
        SecureZeroMemory(&sess, sizeof(sess));
        return false;
    }

    uint64_t check = sess.session_hash ^ sess.hwid_hash ^ sess.xor_key;
    if (check == 0)
    {
        SecureZeroMemory(&sess, sizeof(sess));
        return false;
    }

    int64_t now = static_cast<int64_t>(time(nullptr));
    int64_t delta = now - static_cast<int64_t>(sess.init_timestamp);
    if (delta < -300 || delta > 86400)
    {
        SecureZeroMemory(&sess, sizeof(sess));
        return false;
    }

    SecureZeroMemory(&sess, sizeof(sess));
    return true;
}

bool is_session_valid()
{
    bool result = false;

    CFF_BEGIN(session_valid_cff)
    CFF_STATE(session_valid_cff, 0)
    {
        CFF_GOTO(session_valid_cff, 1);
    }
    CFF_STATE(session_valid_cff, 1)
    {
        std::lock_guard<std::mutex> lk(g_session_mtx);
        result = is_session_valid_inner();
        if (!result)
        {
            CFF_EXIT(session_valid_cff);
        }
        CFF_GOTO(session_valid_cff, 2);
    }
    CFF_STATE(session_valid_cff, 2)
    {
        CFF_EXIT(session_valid_cff);
    }
    CFF_END(session_valid_cff)

    return result;
}

bool vtable_connect(uint64_t)
{
    if (!is_session_valid()) return false;
    if (check_debugger("vtable_connect")) { enforce_violation_id(aida::reason_ids::reason_id_arc_debugger, "vtable_connect"); }
    auto* dev = get_device_enc(g_vtable_crypt_key);
    if (!dev) return false;
    return dev->connect();
}

void vtable_disconnect()
{
    auto* dev = get_device_enc(g_vtable_crypt_key);
    if (dev) dev->disconnect();
}

bool vtable_is_connected()
{
    auto* dev = get_device_enc(g_vtable_crypt_key);
    if (!dev) return false;
    return dev->is_connected();
}

void vtable_set_process_id(uint32_t pid)
{
    if (!is_session_valid()) return;
    if (pid == static_cast<uint32_t>(GetCurrentProcessId())) return;
    auto* dev = get_device_enc(g_vtable_crypt_key);
    if (dev) dev->set_process_id(pid);
}

uint64_t vtable_solve_dtb()
{
    if (!is_session_valid()) return 0;
    auto* dev = get_device_enc(g_vtable_crypt_key);
    if (!dev) return 0;
    dev->solve_dtb();
    return dev->get_dtb();
}

uint64_t vtable_get_dtb()
{
    auto* dev = get_device_enc(g_vtable_crypt_key);
    if (!dev) return 0;
    return dev->get_dtb();
}

uint64_t vtable_find_image()
{
    if (!is_session_valid()) return 0;
    auto* dev = get_device_enc(g_vtable_crypt_key);
    if (!dev) return 0;
    return dev->find_image();
}

void vtable_set_base_address(uint64_t base)
{
    auto* dev = get_device_enc(g_vtable_crypt_key);
    if (dev) dev->set_base_address(base);
}

uint32_t vtable_find_process(const char* name)
{
    if (!is_session_valid()) return 0;
    auto* dev = get_device_enc(g_vtable_crypt_key);
    if (!dev || !name) return 0;
    return dev->find_process(name);
}

void vtable_clear_process_context()
{
    auto* dev = get_device_enc(g_vtable_crypt_key);
    if (dev) dev->clear_process_context();
}

size_t vtable_read_raw(uint64_t address, void* buffer, size_t size)
{
    if (!is_session_valid()) return 0;
    if (check_debugger("vtable_read")) { enforce_violation_id(aida::reason_ids::reason_id_arc_debugger, "vtable_read"); }
    if (!verify_vtable()) { enforce_violation_id(aida::reason_ids::reason_id_arc_vtable_tampered, "read"); }
    if (!buffer || size == 0) return 0;
    auto* dev = get_device_enc(g_vtable_crypt_key);
    if (!dev) return 0;
    return dev->read_raw(address, buffer, size);
}

size_t vtable_write_raw(uint64_t address, const void* buffer, size_t size)
{
    if (!is_session_valid()) return 0;
    if (check_debugger("vtable_write")) { enforce_violation_id(aida::reason_ids::reason_id_arc_debugger, "vtable_write"); }
    if (!verify_vtable()) { enforce_violation_id(aida::reason_ids::reason_id_arc_vtable_tampered, "write"); }
    if (!buffer || size == 0) return 0;
    auto* dev = get_device_enc(g_vtable_crypt_key);
    if (!dev) return 0;
    return dev->write_raw(address, buffer, size);
}

uint32_t vtable_enumerate_memory_regions(
    void (*callback)(const arc_comm_vtable_t::memory_region_info_t*, void*),
    void* ctx)
{
    if (!is_session_valid() || !callback) return 0;
    auto* dev = get_device_enc(g_vtable_crypt_key);
    if (!dev) return 0;
    auto regions = dev->enumerate_memory_regions(0, 0, false);
    uint32_t count = 0;
    for (const auto& r : regions) {
        arc_comm_vtable_t::memory_region_info_t info{};
        info.base    = r.base;
        info.size    = r.size;
        info.state   = r.state;
        info.protect = r.protect;
        info.type    = r.type;
        callback(&info, ctx);
        ++count;
    }
    return count;
}

bool vtable_query_memory(uint64_t address, arc_comm_vtable_t::memory_region_info_t* out)
{
    if (!is_session_valid() || !out) return false;
    auto* dev = get_device_enc(g_vtable_crypt_key);
    if (!dev) return false;
    voyager::device_t::memory_region_info info{};
    if (!dev->query_memory(address, info)) return false;
    out->base    = info.base;
    out->size    = info.size;
    out->state   = info.state;
    out->protect = info.protect;
    out->type    = info.type;
    return true;
}

uint32_t vtable_enumerate_threads(
    void (*callback)(const arc_comm_vtable_t::thread_info_t*, void*),
    void* ctx)
{
    if (!is_session_valid() || !callback) return 0;
    auto* dev = get_device_enc(g_vtable_crypt_key);
    if (!dev) return 0;
    auto threads = dev->enumerate_threads();
    uint32_t count = 0;
    for (const auto& t : threads) {
        arc_comm_vtable_t::thread_info_t info{};
        info.tid   = t.tid;
        info.state = t.state;
        info.rip   = t.rip;
        callback(&info, ctx);
        ++count;
    }
    return count;
}

uint64_t vtable_remote_call(
    uint64_t function_address,
    uint64_t arg1, uint64_t arg2,
    uint64_t arg3, uint64_t arg4)
{
    if (!is_session_valid()) return 0;
    if (check_debugger("vtable_remote_call")) { enforce_violation_id(aida::reason_ids::reason_id_arc_debugger, "vtable_remote_call"); }
    if (!verify_vtable()) { enforce_violation_id(aida::reason_ids::reason_id_arc_vtable_tampered, "remote_call"); }
    auto* dev = get_device_enc(g_vtable_crypt_key);
    if (!dev) return 0;
    return dev->call_function(function_address, arg1, arg2, arg3, arg4);
}

uint64_t g_vtable_slot_keys[16] = {};

__forceinline void generate_slot_keys(uint64_t master)
{
    uint64_t state = master ^ 0x517CC1B727220A95ULL;
    for (int i = 0; i < 16; ++i) {
        state ^= state >> 12;
        state ^= state << 25;
        state ^= state >> 27;
        g_vtable_slot_keys[i] = state * 0x2545F4914F6CDD1DULL;
    }
}

__forceinline void encrypt_vtable_slots()
{
    uintptr_t* slots = reinterpret_cast<uintptr_t*>(&g_vtable);
    for (int i = 0; i < 16; ++i) {
        if (slots[i] != 0) {
            slots[i] ^= static_cast<uintptr_t>(g_vtable_slot_keys[i]);
            slots[i] = _rotl64(slots[i], static_cast<int>(g_vtable_slot_keys[i] & 0x3F));
        }
    }
}

__forceinline void decrypt_vtable_into(arc_comm_vtable_t* out)
{
    memcpy(out, &g_vtable, sizeof(arc_comm_vtable_t));
    uintptr_t* slots = reinterpret_cast<uintptr_t*>(out);
    for (int i = 0; i < 16; ++i) {
        if (slots[i] != 0) {
            slots[i] = _rotr64(slots[i], static_cast<int>(g_vtable_slot_keys[i] & 0x3F));
            slots[i] ^= static_cast<uintptr_t>(g_vtable_slot_keys[i]);
        }
    }
}

static void log_vtable_state(const char* phase, uint64_t integrity_value)
{
    {
        char header[224];
        _snprintf_s(header, sizeof(header), _TRUNCATE,
            "%s integrity=0x%016llX crypt_key=0x%016llX vtable_addr=0x%016llX size=%llu integrity_addr=0x%016llX tid=%lu",
            phase,
            (unsigned long long)integrity_value,
            (unsigned long long)g_vtable_crypt_key,
            (unsigned long long)reinterpret_cast<uintptr_t>(&g_vtable),
            (unsigned long long)sizeof(arc_comm_vtable_t),
            (unsigned long long)reinterpret_cast<uintptr_t>(&g_vtable_integrity),
            GetCurrentThreadId());
        arc_log("vtable", header);
    }
    {
        const uint8_t* p = reinterpret_cast<const uint8_t*>(&g_vtable);
        constexpr size_t kBytes = sizeof(arc_comm_vtable_t);
        for (size_t off = 0; off < kBytes; off += 32) {
            char line[200];
            int n = _snprintf_s(line, sizeof(line), _TRUNCATE,
                "%s bytes off=0x%03X data=", phase, static_cast<unsigned>(off));
            if (n < 0) n = 0;
            size_t row_end = (off + 32 <= kBytes) ? off + 32 : kBytes;
            for (size_t i = off; i < row_end && n < static_cast<int>(sizeof(line)) - 4; ++i) {
                int w = _snprintf_s(line + n, sizeof(line) - static_cast<size_t>(n), _TRUNCATE,
                    "%02X", p[i]);
                if (w <= 0) break;
                n += w;
            }
            arc_log("vtable", line);
        }
    }
    for (int i = 0; i < 16; ++i) {
        char line[112];
        _snprintf_s(line, sizeof(line), _TRUNCATE,
            "%s slot_key[%02d]=0x%016llX",
            phase, i,
            (unsigned long long)g_vtable_slot_keys[i]);
        arc_log("vtable", line);
    }
    {
        MEMORY_BASIC_INFORMATION mbi{};
        SIZE_T qr = VirtualQuery(reinterpret_cast<LPCVOID>(&g_vtable), &mbi, sizeof(mbi));
        char prot[160];
        _snprintf_s(prot, sizeof(prot), _TRUNCATE,
            "%s vq_ok=%d base=0x%016llX size=%llu state=0x%08X protect=0x%08X type=0x%08X",
            phase,
            qr == sizeof(mbi) ? 1 : 0,
            (unsigned long long)reinterpret_cast<uintptr_t>(mbi.BaseAddress),
            (unsigned long long)mbi.RegionSize,
            mbi.State, mbi.Protect, mbi.Type);
        arc_log("vtable", prot);
    }
}

void init_vtable(uint64_t crypt_key)
{
    g_vtable_crypt_key = crypt_key;
    store_device_enc(crypt_key);

    g_vtable.connect                  = vtable_connect;
    g_vtable.disconnect               = vtable_disconnect;
    g_vtable.is_connected             = vtable_is_connected;
    g_vtable.set_process_id           = vtable_set_process_id;
    g_vtable.solve_dtb                = vtable_solve_dtb;
    g_vtable.get_dtb                  = vtable_get_dtb;
    g_vtable.find_image               = vtable_find_image;
    g_vtable.set_base_address         = vtable_set_base_address;
    g_vtable.find_process             = vtable_find_process;
    g_vtable.clear_process_context    = vtable_clear_process_context;
    g_vtable.read_raw                 = vtable_read_raw;
    g_vtable.write_raw                = vtable_write_raw;
    g_vtable.enumerate_memory_regions = vtable_enumerate_memory_regions;
    g_vtable.query_memory             = vtable_query_memory;
    g_vtable.enumerate_threads        = vtable_enumerate_threads;
    g_vtable.remote_call              = vtable_remote_call;
    memset(g_vtable._reserved, 0, sizeof(g_vtable._reserved));

    generate_slot_keys(crypt_key);
    encrypt_vtable_slots();

    g_vtable_integrity = compute_vtable_integrity();

    log_vtable_state("init_post_encrypt", g_vtable_integrity);

    g_vtable_ready.store(true, std::memory_order_release);
}

}


extern "C"
{

ARC_API bool arc_bind_driver_device(void* driver_device, uint32_t interface_version)
{
    using namespace arc_internal;
    if (interface_version != ARC_INTERFACE_VERSION || !driver_device)
    {
        char detail[128];
        _snprintf_s(detail, sizeof(detail), _TRUNCATE,
            "bind_rejected iv=%u expected=%u device_set=%d",
            interface_version,
            static_cast<unsigned>(ARC_INTERFACE_VERSION),
            driver_device ? 1 : 0);
        arc_log("bind", detail);
        return false;
    }
    bind_prebound_device(reinterpret_cast<voyager::device_t*>(driver_device));
    const bool ok = get_prebound_device() != nullptr;
    if (ok)
        arc_publish_state(arc_state_bound, "arc_bind_driver_device", "prebound_device_set");
    else
        arc_log("bind", "bind_failed_prebound_decode_null");
    return ok;
}

ARC_API bool arc_init(
    const char*    session_token,
    const char*    hwid,
    int64_t        timestamp,
    uint32_t       interface_version,
    const uint8_t* bind_proof)
{
    using namespace arc_internal;

    {
        char dbg[192];
        _snprintf_s(dbg, sizeof(dbg), _TRUNCATE,
            "arc_init_entry session_token=%p hwid=%p ts=%lld iv=%u bind_proof=%p",
            static_cast<const void*>(session_token),
            static_cast<const void*>(hwid),
            static_cast<long long>(timestamp),
            interface_version,
            static_cast<const void*>(bind_proof));
        arc_log("init", dbg);
    }
    arc_publish_state(arc_state_init_started, "arc_init", "entry");

    bool result = false;
    uint64_t local_hwid_hash_capture = 0;
    uint64_t code_hash_capture = 0;
    uint64_t session_hash_capture = 0;
    uint64_t hwid_hash_capture = 0;
    uint64_t init_timestamp_capture = 0;
    uint64_t vtable_crypt_key_capture = 0;
    uint64_t last_heartbeat_tsc_capture = 0;
    uint64_t xor_key_capture = 0;

    arc_log("init", "arc_init_step0_validate_args");
    if (interface_version != ARC_INTERFACE_VERSION)
    {
        char dbg[96];
        _snprintf_s(dbg, sizeof(dbg), _TRUNCATE,
            "arc_init_interface_version_mismatch got=%u expected=%u",
            interface_version, static_cast<unsigned>(ARC_INTERFACE_VERSION));
        arc_log("init", dbg);
        return false;
    }
    if (!session_token || !hwid || !bind_proof)
    {
        char dbg[96];
        _snprintf_s(dbg, sizeof(dbg), _TRUNCATE,
            "arc_init_null_param session_token=%d hwid=%d bind_proof=%d",
            session_token ? 1 : 0, hwid ? 1 : 0, bind_proof ? 1 : 0);
        arc_log("init", dbg);
        return false;
    }

    arc_log("init", "arc_init_step1_validate_lengths");
    {
        size_t token_len = strlen(session_token);
        if (token_len < 32 || token_len > 4096)
        {
            char dbg[128];
            _snprintf_s(dbg, sizeof(dbg), _TRUNCATE,
                "arc_init_session_token_len_out_of_range got=%zu expected=[32,4096]",
                token_len);
            arc_log("init", dbg);
            return false;
        }
        size_t hwid_len = strlen(hwid);
        if (hwid_len < 8 || hwid_len > 256)
        {
            char dbg[128];
            _snprintf_s(dbg, sizeof(dbg), _TRUNCATE,
                "arc_init_hwid_len_out_of_range got=%zu expected=[8,256]",
                hwid_len);
            arc_log("init", dbg);
            return false;
        }
        char dbg_ok[160];
        _snprintf_s(dbg_ok, sizeof(dbg_ok), _TRUNCATE,
            "arc_init_lengths_ok token_len=%zu hwid_len=%zu",
            token_len, hwid_len);
        arc_log("init", dbg_ok);
    }

    arc_log("init", "arc_init_step2_check_debugger");
    if (check_debugger("arc_init"))
    {
        enforce_violation_id(aida::reason_ids::reason_id_arc_debugger, "arc_init");
    }

    arc_log("init", "arc_init_step3_hwid_recompute");
    {
        recomputed_hwid_t local_hwid_state = recompute_hwid();
        std::string& local_hwid = local_hwid_state.hwid;
        uint64_t local_hash = fnv1a_str(local_hwid.c_str());
        uint64_t provided_hash = fnv1a_str(hwid);
        local_hwid_hash_capture = local_hash;
        size_t provided_len = strlen(hwid);
        size_t local_len = local_hwid.size();
        {
            char dbg[256];
            _snprintf_s(dbg, sizeof(dbg), _TRUNCATE,
                "arc_init_hwid local_len=%zu provided_len=%zu local_hash=0x%016llX provided_hash=0x%016llX mask=0x%08X tpm=%d",
                local_len, provided_len,
                static_cast<unsigned long long>(local_hash),
                static_cast<unsigned long long>(provided_hash),
                local_hwid_state.factor_present_mask,
                local_hwid_state.tpm_present ? 1 : 0);
            arc_log("init", dbg);
        }
        uint8_t hwid_diff = local_len == provided_len ? 0u : 1u;
        size_t cmp_len = local_len < provided_len ? local_len : provided_len;
        for (size_t i = 0; i < cmp_len; ++i)
        {
            hwid_diff |= static_cast<uint8_t>(local_hwid[i] ^ hwid[i]);
        }
        if (hwid_diff != 0)
        {
            char dbg[192];
            _snprintf_s(dbg, sizeof(dbg), _TRUNCATE,
                "arc_init_hwid_mismatch_rejected mask=0x%08X tpm=%d local_hash=0x%016llX provided_hash=0x%016llX",
                local_hwid_state.factor_present_mask,
                local_hwid_state.tpm_present ? 1 : 0,
                static_cast<unsigned long long>(local_hash),
                static_cast<unsigned long long>(provided_hash));
            arc_log("init", dbg);
            enforce_violation_id(aida::reason_ids::reason_id_arc_hwid_mismatch, "");
            return false;
        }
    }

    arc_log("init", "arc_init_step4_timestamp_check");
    {
        int64_t now = static_cast<int64_t>(time(nullptr));
        int64_t drift = now - timestamp;
        if (drift < -300 || drift > 300)
        {
            char dbg[160];
            _snprintf_s(dbg, sizeof(dbg), _TRUNCATE,
                "arc_init_timestamp_drift_out_of_range now=%lld bind_ts=%lld drift=%lld limit=300",
                static_cast<long long>(now),
                static_cast<long long>(timestamp),
                static_cast<long long>(drift));
            arc_log("init", dbg);
            return false;
        }
    }

    arc_log("init", "arc_init_step5_derive_keys");
    {
        uint64_t tsc = __rdtsc();
        xor_key_capture = tsc ^ 0xA1DA'CAFE'BABE'C0DEull;
        session_hash_capture = fnv1a_str(session_token);
        hwid_hash_capture = fnv1a_str(hwid);
        init_timestamp_capture = static_cast<uint64_t>(timestamp);
        last_heartbeat_tsc_capture = qpc_now_us();

        uint64_t key_material = local_hwid_hash_capture ^ session_hash_capture ^ tsc;
        uint8_t kb[16];
        memcpy(kb, &key_material, 8);
        uint64_t km2 = key_material ^ 0x6A09E667F3BCC908ULL;
        memcpy(kb + 8, &km2, 8);
        vtable_crypt_key_capture = siphash_2_4(kb, 16, local_hwid_hash_capture, session_hash_capture);
    }

    arc_log("init", "arc_init_step6_bind_proof_verify");
    {
        if (!load_bind_secret())
        {
            arc_log("init", "arc_init_load_bind_secret_FAILED");
            enforce_violation_id(aida::reason_ids::reason_id_arc_no_bind_secret, "");
        }

        std::string msg;
        msg.reserve(strlen(session_token) + strlen(hwid) + 64);
        msg.append(session_token);
        msg.append("|");
        msg.append(hwid);
        msg.append("|");
        msg.append(std::to_string(timestamp));
        msg.append("|0000000000000000");

        uint8_t expected[32] = {};
        uint8_t local_secret[32] = {};
        {
            std::lock_guard<std::mutex> bs_lk(g_bind_secret_mtx);
            bind_secret_obf_load_unlocked(local_secret);
        }
        const bool hmac_ok = hmac_sha256_full(local_secret, 32,
                reinterpret_cast<const uint8_t*>(msg.data()), msg.size(),
                expected);
        SecureZeroMemory(local_secret, sizeof(local_secret));
        if (!hmac_ok)
        {
            SecureZeroMemory(expected, sizeof(expected));
            arc_log("init", "arc_init_bind_proof_hmac_compute_FAILED");
            enforce_violation_id(aida::reason_ids::reason_id_arc_bind_proof_hmac_failed, "");
        }

        if (!arc_ct_memeq(expected, bind_proof, 32))
        {
            uint32_t diff_count = 0;
            for (uint32_t i = 0; i < 32; ++i)
            {
                if (expected[i] != bind_proof[i])
                    ++diff_count;
            }
            char dbg[200];
            _snprintf_s(dbg, sizeof(dbg), _TRUNCATE,
                "arc_init_bind_proof_mismatch diff=%u expected_hash=0x%016llX got_hash=0x%016llX",
                diff_count,
                static_cast<unsigned long long>(fnv1a(expected, sizeof(expected))),
                static_cast<unsigned long long>(fnv1a(bind_proof, 32)));
            arc_log("init", dbg);
            SecureZeroMemory(expected, sizeof(expected));
            enforce_violation_id(aida::reason_ids::reason_id_arc_bind_proof_mismatch, "");
        }

        SecureZeroMemory(expected, sizeof(expected));
    }

    arc_log("init", "arc_init_step7_code_hash_and_session");
    {
        integrity_scan_result_t baseline_scan = scan_own_code_integrity(true, "arc_init_baseline");
        code_hash_capture = baseline_scan.hash;
        if (code_hash_capture == 0 || baseline_scan.included_regions == 0)
        {
            arc_log("init", "arc_init_code_hash_capture_failed");
            return false;
        }
        {
            char dbg[192];
            _snprintf_s(dbg, sizeof(dbg), _TRUNCATE,
                "arc_init_code_hash hash=0x%016llX exec=%u included=%u mutable=%u guarded=%u read_fail=%u",
                static_cast<unsigned long long>(code_hash_capture),
                baseline_scan.exec_regions,
                baseline_scan.included_regions,
                baseline_scan.mutable_exec_regions,
                baseline_scan.guarded_exec_regions,
                baseline_scan.read_failures);
            arc_log("init", dbg);
        }

        std::lock_guard<std::mutex> lk(g_session_mtx);

        session_data_t sess = {};
        sess.xor_key = xor_key_capture;
        sess.session_hash = session_hash_capture;
        sess.hwid_hash = hwid_hash_capture;
        sess.local_hwid_hash = local_hwid_hash_capture;
        sess.init_timestamp = init_timestamp_capture;
        sess.heartbeat_counter = 0;
        sess.last_heartbeat_tsc = last_heartbeat_tsc_capture;
        sess.vtable_crypt_key = vtable_crypt_key_capture;
        sess.code_hash = code_hash_capture;

        strncpy_s(sess.session_token, session_token, _TRUNCATE);
        strncpy_s(sess.hwid, hwid, _TRUNCATE);
        sess.license_key[0] = '\0';

        if (!capture_self_integrity())
        {
            arc_log("init", "self_integrity_capture_failed");
            enforce_violation_id(aida::reason_ids::reason_id_arc_self_hash_mismatch, "capture_failed");
        }
        sess.initialized = true;

        store_session(sess);
        init_vtable(sess.vtable_crypt_key);
        arc_publish_state(arc_state_session_ready, "arc_init", "session_vtable_stored");
        SecureZeroMemory(&sess, sizeof(sess));

        result = true;
    }

    arc_log("init", "arc_init_step8_device_bridge");
    {
        voyager::device_t* dev = get_device_enc(g_vtable_crypt_key);
        if (!dev)
        {
            arc_log("init", "arc_init_get_device_enc_returned_null");
            enforce_violation_id(aida::reason_ids::reason_id_arc_no_device, "init");
        }

        if (!dev->is_connected())
        {
            arc_log("init", "arc_init_device_disconnected");
            enforce_violation_id(aida::reason_ids::reason_id_arc_no_driver, "device_disconnected");
        }

        dev->sync_dynamic_security_state();
        arc_log("driver", "dynamic_security_state_synced");
        {
            char sec_buf[256];
            _snprintf_s(sec_buf, sizeof(sec_buf), _TRUNCATE,
                "device_security_snapshot stage=post_sync base=0x%04X key_hash=0x%08X ioctl_seed_hash=0x%08X inst_seed=%u/%u global_seed=%u/%u hb_ioctl=0x%08X hb_err=%lu hb_bytes=%lu hb_resp=0x%016llX",
                dev->compute_ioctl_base_snapshot(),
                dev->get_last_heartbeat_key_hash(),
                dev->get_last_heartbeat_ioctl_seed_hash(),
                dev->get_last_heartbeat_server_seed_present(),
                dev->get_last_heartbeat_ioctl_seed_present(),
                dev->get_last_heartbeat_global_server_seed_present(),
                dev->get_last_heartbeat_global_ioctl_seed_present(),
                dev->get_last_heartbeat_ioctl_code(),
                static_cast<unsigned long>(dev->get_last_heartbeat_error()),
                static_cast<unsigned long>(dev->get_last_heartbeat_bytes_returned()),
                static_cast<unsigned long long>(dev->get_last_heartbeat_response()));
            arc_log("driver", sec_buf);
        }

        arc_log("driver", "heartbeat_send_pre");
        bool heartbeat_ok = false;
        DWORD heartbeat_seh = send_device_heartbeat_seh(dev, &heartbeat_ok);
        if (heartbeat_seh != ERROR_SUCCESS)
        {
            char hb_seh_buf[256];
            _snprintf_s(hb_seh_buf, sizeof(hb_seh_buf), _TRUNCATE,
                "heartbeat_send_seh code=0x%08lX err=%lu bytes=%lu ioctl=0x%08X base=0x%04X key_hash=0x%08X ioctl_seed_hash=0x%08X inst_seed=%u/%u global_seed=%u/%u",
                static_cast<unsigned long>(heartbeat_seh),
                static_cast<unsigned long>(dev->get_last_heartbeat_error()),
                static_cast<unsigned long>(dev->get_last_heartbeat_bytes_returned()),
                dev->get_last_heartbeat_ioctl_code(),
                dev->get_last_heartbeat_base(),
                dev->get_last_heartbeat_key_hash(),
                dev->get_last_heartbeat_ioctl_seed_hash(),
                dev->get_last_heartbeat_server_seed_present(),
                dev->get_last_heartbeat_ioctl_seed_present(),
                dev->get_last_heartbeat_global_server_seed_present(),
                dev->get_last_heartbeat_global_ioctl_seed_present());
            arc_log("driver", hb_seh_buf);
            enforce_violation_id(aida::reason_ids::reason_id_arc_no_driver, "heartbeat_send_seh");
        }
        {
            char hb_ok_buf[256];
            _snprintf_s(hb_ok_buf, sizeof(hb_ok_buf), _TRUNCATE,
                "heartbeat_send_post ok=%d err=%lu bytes=%lu ioctl=0x%08X base=0x%04X key_hash=0x%08X ioctl_seed_hash=0x%08X inst_seed=%u/%u global_seed=%u/%u",
                heartbeat_ok ? 1 : 0,
                static_cast<unsigned long>(dev->get_last_heartbeat_error()),
                static_cast<unsigned long>(dev->get_last_heartbeat_bytes_returned()),
                dev->get_last_heartbeat_ioctl_code(),
                dev->get_last_heartbeat_base(),
                dev->get_last_heartbeat_key_hash(),
                dev->get_last_heartbeat_ioctl_seed_hash(),
                dev->get_last_heartbeat_server_seed_present(),
                dev->get_last_heartbeat_ioctl_seed_present(),
                dev->get_last_heartbeat_global_server_seed_present(),
                dev->get_last_heartbeat_global_ioctl_seed_present());
            arc_log("driver", hb_ok_buf);
        }
        if (!heartbeat_ok)
        {
            char hb_buf[256];
            _snprintf_s(hb_buf, sizeof(hb_buf), _TRUNCATE,
                "heartbeat_failed err=%lu bytes=%lu ioctl=0x%08X base=0x%04X key_hash=0x%08X inst_seed=%u/%u global_seed=%u/%u",
                static_cast<unsigned long>(dev->get_last_heartbeat_error()),
                static_cast<unsigned long>(dev->get_last_heartbeat_bytes_returned()),
                dev->get_last_heartbeat_ioctl_code(),
                dev->get_last_heartbeat_base(),
                dev->get_last_heartbeat_key_hash(),
                dev->get_last_heartbeat_server_seed_present(),
                dev->get_last_heartbeat_ioctl_seed_present(),
                dev->get_last_heartbeat_global_server_seed_present(),
                dev->get_last_heartbeat_global_ioctl_seed_present());
            arc_log("driver", hb_buf);
            arc_log("driver", "heartbeat_failed");
            enforce_violation_id(aida::reason_ids::reason_id_arc_no_driver, "heartbeat_failed");
        }

        {
            constexpr DWORD kBridgeReadyTimeoutMs = 45000;
            constexpr DWORD kBridgePollIntervalMs = 250;
            DWORD waited_ms = 0;
            uint64_t last_logged_ms = 0;
            while (!dev->sentinel_bridge_ready())
            {
                if (waited_ms >= kBridgeReadyTimeoutMs)
                {
                    char to_buf[96];
                    _snprintf_s(to_buf, sizeof(to_buf), _TRUNCATE,
                        "sentinel_bridge_down waited_ms=%lu",
                        static_cast<unsigned long>(waited_ms));
                    arc_log("driver", to_buf);
                    enforce_violation_id(aida::reason_ids::reason_id_arc_no_driver, "sentinel_bridge_down");
                }
                if (check_debugger("sentinel_bridge_wait"))
                {
                    enforce_violation_id(aida::reason_ids::reason_id_arc_debugger, "sentinel_bridge_wait");
                }
                if (!dev->is_connected())
                {
                    enforce_violation_id(aida::reason_ids::reason_id_arc_no_driver, "device_disconnected_during_wait");
                }
                Sleep(kBridgePollIntervalMs);
                waited_ms += kBridgePollIntervalMs;
                if (waited_ms - last_logged_ms >= 5000)
                {
                    char wait_buf[96];
                    _snprintf_s(wait_buf, sizeof(wait_buf), _TRUNCATE,
                        "sentinel_bridge_wait waited_ms=%lu",
                        static_cast<unsigned long>(waited_ms));
                    arc_log("driver", wait_buf);
                    last_logged_ms = waited_ms;
                }
                arc_log("driver", "heartbeat_refresh_during_bridge_wait_pre");
                bool wait_heartbeat_ok = false;
                DWORD wait_heartbeat_seh = refresh_device_heartbeat_seh(dev, &wait_heartbeat_ok);
                if (wait_heartbeat_seh != ERROR_SUCCESS)
                {
                    char hb_seh_buf[256];
                    _snprintf_s(hb_seh_buf, sizeof(hb_seh_buf), _TRUNCATE,
                        "heartbeat_refresh_during_bridge_wait_seh code=0x%08lX err=%lu bytes=%lu ioctl=0x%08X base=0x%04X key_hash=0x%08X ioctl_seed_hash=0x%08X inst_seed=%u/%u global_seed=%u/%u waited_ms=%lu",
                        static_cast<unsigned long>(wait_heartbeat_seh),
                        static_cast<unsigned long>(dev->get_last_heartbeat_error()),
                        static_cast<unsigned long>(dev->get_last_heartbeat_bytes_returned()),
                        dev->get_last_heartbeat_ioctl_code(),
                        dev->get_last_heartbeat_base(),
                        dev->get_last_heartbeat_key_hash(),
                        dev->get_last_heartbeat_ioctl_seed_hash(),
                        dev->get_last_heartbeat_server_seed_present(),
                        dev->get_last_heartbeat_ioctl_seed_present(),
                        dev->get_last_heartbeat_global_server_seed_present(),
                        dev->get_last_heartbeat_global_ioctl_seed_present(),
                        static_cast<unsigned long>(waited_ms));
                    arc_log("driver", hb_seh_buf);
                    enforce_violation_id(aida::reason_ids::reason_id_arc_no_driver, "heartbeat_refresh_wait_seh");
                }
                {
                    char hb_ok_buf[256];
                    _snprintf_s(hb_ok_buf, sizeof(hb_ok_buf), _TRUNCATE,
                        "heartbeat_refresh_during_bridge_wait_post ok=%d err=%lu bytes=%lu ioctl=0x%08X base=0x%04X key_hash=0x%08X ioctl_seed_hash=0x%08X inst_seed=%u/%u global_seed=%u/%u waited_ms=%lu",
                        wait_heartbeat_ok ? 1 : 0,
                        static_cast<unsigned long>(dev->get_last_heartbeat_error()),
                        static_cast<unsigned long>(dev->get_last_heartbeat_bytes_returned()),
                        dev->get_last_heartbeat_ioctl_code(),
                        dev->get_last_heartbeat_base(),
                        dev->get_last_heartbeat_key_hash(),
                        dev->get_last_heartbeat_ioctl_seed_hash(),
                        dev->get_last_heartbeat_server_seed_present(),
                        dev->get_last_heartbeat_ioctl_seed_present(),
                        dev->get_last_heartbeat_global_server_seed_present(),
                        dev->get_last_heartbeat_global_ioctl_seed_present(),
                        static_cast<unsigned long>(waited_ms));
                    arc_log("driver", hb_ok_buf);
                }
                if (!wait_heartbeat_ok)
                {
                    char hb_buf[256];
                    _snprintf_s(hb_buf, sizeof(hb_buf), _TRUNCATE,
                        "heartbeat_failed_during_bridge_wait err=%lu bytes=%lu ioctl=0x%08X base=0x%04X key_hash=0x%08X inst_seed=%u/%u global_seed=%u/%u waited_ms=%lu",
                        static_cast<unsigned long>(dev->get_last_heartbeat_error()),
                        static_cast<unsigned long>(dev->get_last_heartbeat_bytes_returned()),
                        dev->get_last_heartbeat_ioctl_code(),
                        dev->get_last_heartbeat_base(),
                        dev->get_last_heartbeat_key_hash(),
                        dev->get_last_heartbeat_server_seed_present(),
                        dev->get_last_heartbeat_ioctl_seed_present(),
                        dev->get_last_heartbeat_global_server_seed_present(),
                        dev->get_last_heartbeat_global_ioctl_seed_present(),
                        static_cast<unsigned long>(waited_ms));
                    arc_log("driver", hb_buf);
                    arc_log("driver", "heartbeat_failed_during_bridge_wait");
                    enforce_violation_id(aida::reason_ids::reason_id_arc_no_driver, "heartbeat_failed");
                }
            }
            if (waited_ms > 0)
            {
                char ok_buf[96];
                _snprintf_s(ok_buf, sizeof(ok_buf), _TRUNCATE,
                    "sentinel_bridge_ready waited_ms=%lu",
                    static_cast<unsigned long>(waited_ms));
                arc_log("driver", ok_buf);
            }
        }

        bool tier_a_present = false;
        uint32_t tier_a_mask = 0;
        uint64_t tier_a_first_base = 0;
        const bool tier_a_connected_before = dev->is_connected();
        const uint64_t tier_a_query_start = GetTickCount64();
        const bool tier_a_query_ok = dev->tier_a_driver_present_query(tier_a_present, &tier_a_mask, &tier_a_first_base);
        const DWORD tier_a_query_gle = tier_a_query_ok ? ERROR_SUCCESS : GetLastError();
        const uint64_t tier_a_query_elapsed = GetTickCount64() - tier_a_query_start;
        if (!tier_a_query_ok)
        {
            const bool tier_a_connected_after = dev->is_connected();
            char detail[160];
            _snprintf_s(detail, sizeof(detail), _TRUNCATE,
                "tier_a_query_failed gle=%lu connected_before=%d connected_after=%d elapsed_ms=%llu",
                static_cast<unsigned long>(tier_a_query_gle),
                tier_a_connected_before ? 1 : 0,
                tier_a_connected_after ? 1 : 0,
                static_cast<unsigned long long>(tier_a_query_elapsed));
            arc_log("driver", detail);
            enforce_violation_id(aida::reason_ids::reason_id_arc_no_driver, "tier_a_query_failed");
        }

        if (tier_a_present)
        {
            char detail[96];
            _snprintf_s(detail, sizeof(detail), _TRUNCATE,
                "tier_a_present mask=0x%08X first_base=0x%016llX",
                tier_a_mask, static_cast<unsigned long long>(tier_a_first_base));
            arc_log("driver", detail);
            enforce_violation_id(aida::reason_ids::reason_id_arc_hostile_driver, "tier_a_present");
        }

        MEMORY_BASIC_INFORMATION mbi_self = {};
        uint64_t image_base = 0;
        uint64_t image_size = 0;
        uint64_t text_va = 0;
        uint64_t text_size = 0;

        if (VirtualQuery(reinterpret_cast<const void*>(&arc_init), &mbi_self, sizeof(mbi_self)) != 0
            && mbi_self.AllocationBase != nullptr)
        {
            image_base = reinterpret_cast<uint64_t>(mbi_self.AllocationBase);

            constexpr uint64_t kMaxImageScan = 256ULL * 1024 * 1024;

            uintptr_t scan_addr = static_cast<uintptr_t>(image_base);
            const uintptr_t scan_limit = scan_addr + static_cast<uintptr_t>(kMaxImageScan);

            while (scan_addr < scan_limit)
            {
                MEMORY_BASIC_INFORMATION r = {};
                if (VirtualQuery(reinterpret_cast<const void*>(scan_addr), &r, sizeof(r)) == 0)
                    break;
                if (r.RegionSize == 0)
                    break;
                if (r.AllocationBase != mbi_self.AllocationBase)
                    break;

                if (text_va == 0 && arc_is_stable_exec_region(r))
                {
                    text_va = reinterpret_cast<uint64_t>(r.BaseAddress);
                    text_size = static_cast<uint64_t>(r.RegionSize);
                }

                scan_addr += r.RegionSize;
                image_size = static_cast<uint64_t>(scan_addr) - image_base;
            }
        }

        if (image_base != 0 && image_size != 0 && text_va != 0 && text_size != 0)
        {
            bool driver_hash_ok = false;
            uint64_t driver_expected_hash = 0;
            if (text_size <= 0xFFFFFFFFULL)
            {
                driver_expected_hash = driver_region_crc_hash_seh(
                    reinterpret_cast<const void*>(text_va),
                    static_cast<size_t>(text_size),
                    driver_hash_ok);
            }
            {
                char detail[224];
                _snprintf_s(detail, sizeof(detail), _TRUNCATE,
                    "register_dll_protection_attempt image=0x%016llX image_size=0x%016llX text=0x%016llX text_size=0x%016llX arc_hash=0x%016llX driver_hash=0x%016llX hash_ok=%d",
                    static_cast<unsigned long long>(image_base),
                    static_cast<unsigned long long>(image_size),
                    static_cast<unsigned long long>(text_va),
                    static_cast<unsigned long long>(text_size),
                    static_cast<unsigned long long>(code_hash_capture),
                    static_cast<unsigned long long>(driver_expected_hash),
                    driver_hash_ok ? 1 : 0);
                arc_log("driver", detail);
            }
            if (!driver_hash_ok || driver_expected_hash == 0 || text_size > 0xFFFFFFFFULL)
            {
                arc_log("driver", "register_dll_protection_hash_unavailable");
                enforce_violation_id(aida::reason_ids::reason_id_arc_no_driver, "register_dll_protection_hash_unavailable");
            }
            else if (!dev->register_dll_protection_for_pid(GetCurrentProcessId(), image_base, text_va,
                    static_cast<uint32_t>(text_size), driver_expected_hash, 2000))
            {
                DWORD gle = GetLastError();
                if (gle == ERROR_ALREADY_EXISTS || gle == 183ul)
                {
                    arc_log("driver", "register_dll_protection_ok already_registered");
                }
                else
                {
                    char detail[224];
                    _snprintf_s(detail, sizeof(detail), _TRUNCATE,
                        "register_dll_protection_failed gle=%lu image=0x%016llX text=0x%016llX text_size=0x%016llX expected=0x%016llX",
                        static_cast<unsigned long>(gle),
                        static_cast<unsigned long long>(image_base),
                        static_cast<unsigned long long>(text_va),
                        static_cast<unsigned long long>(text_size),
                        static_cast<unsigned long long>(driver_expected_hash));
                    arc_log("driver", detail);
                    enforce_violation_id(aida::reason_ids::reason_id_arc_no_driver, "register_dll_protection_failed");
                }
            }
            else
            {
                arc_log("driver", "register_dll_protection_ok");
            }
        }
        else
        {
            arc_log("driver", "image_layout_unavailable");
            enforce_violation_id(aida::reason_ids::reason_id_arc_no_driver, "image_layout_unavailable");
        }
        arc_publish_state(arc_state_driver_verified, "arc_init", "driver_bridge_and_dll_protection_verified");
    }

    if (result)
        arc_publish_state(arc_state_ready, "arc_init", "ready");
    {
        char dbg[96];
        _snprintf_s(dbg, sizeof(dbg), _TRUNCATE,
            "arc_init_exit result=%s", result ? "true" : "false");
        arc_log("init", dbg);
    }
    return result;
}

static thread_local arc_comm_vtable_t g_vtable_decrypted = {};

ARC_API const arc_comm_vtable_t* arc_get_comm_bridge()
{
    using namespace arc_internal;
    if (!is_session_valid())
    {
        arc_log_export_denied("arc_get_comm_bridge", "session_invalid");
        if (arc_runtime_requires_live_session(g_arc_runtime_state.load(std::memory_order_acquire)))
            enforce_violation_id(aida::reason_ids::reason_id_arc_required, "get_comm_bridge_session_invalid");
        return nullptr;
    }
    if (!g_vtable_ready.load(std::memory_order_acquire))
    {
        arc_log_export_denied("arc_get_comm_bridge", "vtable_not_ready");
        return nullptr;
    }
    if (!verify_vtable())
    {
        enforce_violation_id(aida::reason_ids::reason_id_arc_vtable_tampered, "get_comm_bridge");
    }
    decrypt_vtable_into(&g_vtable_decrypted);
    arc_log("export", "arc_get_comm_bridge_ok");
    return &g_vtable_decrypted;
}

ARC_API uint64_t arc_validate_tool_exec(
    uint64_t tool_name_hash,
    uint64_t gate_token)
{
    if (tool_name_hash == 0 || gate_token == 0)
    {
        arc_internal::arc_log_export_denied("arc_validate_tool_exec", "bad_args");
        return 0;
    }
    const uint64_t caller_nonce =
        static_cast<uint64_t>(__rdtsc()) ^
        _rotl64(gate_token, 17) ^
        0xA1DA7E5700010002ULL;
    return arc_validate_tool_exec_v2(caller_nonce, tool_name_hash, gate_token);
}

ARC_API uint64_t arc_validate_tool_exec_v2(
    uint64_t caller_nonce,
    uint64_t tool_name_hash,
    uint64_t hb_counter)
{
    using namespace arc_internal;
    uint64_t out = 0;

    CFF_BEGIN(validate_v2_cff)
    CFF_STATE(validate_v2_cff, 0)
    {
        if (tool_name_hash == 0 || caller_nonce == 0)
        {
            arc_log_export_denied("arc_validate_tool_exec_v2", "bad_args");
            CFF_EXIT(validate_v2_cff);
        }
        CFF_GOTO(validate_v2_cff, 1);
    }
    CFF_STATE(validate_v2_cff, 1)
    {
        if (!is_session_valid())
        {
            arc_log_export_denied("arc_validate_tool_exec_v2", "session_invalid");
            if (arc_runtime_requires_live_session(g_arc_runtime_state.load(std::memory_order_acquire)))
                enforce_violation_id(aida::reason_ids::reason_id_arc_required, "validate_tool_session_invalid");
            CFF_EXIT(validate_v2_cff);
        }
        CFF_GOTO(validate_v2_cff, 2);
    }
    CFF_STATE(validate_v2_cff, 2)
    {
        if (check_debugger("validate_tool_v2"))
        {
            enforce_violation_id(aida::reason_ids::reason_id_arc_debugger, "validate_tool_v2");
        }
        CFF_GOTO(validate_v2_cff, 3);
    }
    CFF_STATE(validate_v2_cff, 3)
    {
        if (!load_bind_secret())
        {
            enforce_violation_id(aida::reason_ids::reason_id_arc_no_bind_secret, "validate_tool_v2");
        }

        session_data_t sess = {};
        {
            std::lock_guard<std::mutex> lk(g_session_mtx);
            if (!load_session(sess))
            {
                arc_log_export_denied("arc_validate_tool_exec_v2", "load_session_failed");
                if (arc_runtime_requires_live_session(g_arc_runtime_state.load(std::memory_order_acquire)))
                    enforce_violation_id(aida::reason_ids::reason_id_arc_required, "validate_tool_load_session_failed");
                CFF_EXIT(validate_v2_cff);
            }
        }

        uint8_t local_secret[32] = {};
        {
            std::lock_guard<std::mutex> bs_lk(g_bind_secret_mtx);
            bind_secret_obf_load_unlocked(local_secret);
        }

        uint64_t session_hash_le = sess.session_hash;
        uint8_t salt_bytes[8] = {};
        memcpy(salt_bytes, &session_hash_le, sizeof(session_hash_le));

        const char info_label[] = "aida-arc-tool-call|v1";
        uint8_t call_key[32] = {};
        const bool kdf_ok = hkdf_sha256(
            local_secret, 32,
            salt_bytes, sizeof(salt_bytes),
            reinterpret_cast<const uint8_t*>(info_label),
            static_cast<uint32_t>(sizeof(info_label) - 1),
            call_key, 32);
        SecureZeroMemory(local_secret, sizeof(local_secret));
        if (!kdf_ok)
        {
            SecureZeroMemory(call_key, sizeof(call_key));
            SecureZeroMemory(&sess, sizeof(sess));
            arc_log_export_denied("arc_validate_tool_exec_v2", "hkdf_failed");
            CFF_EXIT(validate_v2_cff);
        }

        uint8_t msg[24] = {};
        memcpy(msg + 0,  &caller_nonce, 8);
        memcpy(msg + 8,  &tool_name_hash, 8);
        memcpy(msg + 16, &hb_counter, 8);

        uint8_t mac[32] = {};
        const bool hmac_ok = hmac_sha256_full(call_key, 32, msg, sizeof(msg), mac);
        SecureZeroMemory(call_key, sizeof(call_key));
        SecureZeroMemory(msg, sizeof(msg));
        SecureZeroMemory(&sess, sizeof(sess));
        if (!hmac_ok)
        {
            SecureZeroMemory(mac, sizeof(mac));
            arc_log_export_denied("arc_validate_tool_exec_v2", "hmac_failed");
            CFF_EXIT(validate_v2_cff);
        }
        memcpy(&out, mac, 8);
        SecureZeroMemory(mac, sizeof(mac));
        arc_log("export", "arc_validate_tool_exec_v2_ok");
        CFF_EXIT(validate_v2_cff);
    }
    CFF_END(validate_v2_cff)

    return out;
}

ARC_API arc_heartbeat_result_t arc_heartbeat()
{
    using namespace arc_internal;
    arc_heartbeat_result_t hb_result{};
    hb_result.valid = false;
    hb_result.proof_token = 0;
    hb_result.timestamp = 0;

    CFF_BEGIN(hb_cff)
    CFF_STATE(hb_cff, 0)
    {
        if (!is_session_valid())
        {
            arc_log_export_denied("arc_heartbeat", "session_invalid");
            if (arc_runtime_requires_live_session(g_arc_runtime_state.load(std::memory_order_acquire)))
                enforce_violation_id(aida::reason_ids::reason_id_arc_required, "heartbeat_session_invalid");
            CFF_EXIT(hb_cff);
        }
        CFF_GOTO(hb_cff, 1);
    }
    CFF_STATE(hb_cff, 1)
    {
        integrity_scan_result_t current_scan = scan_own_code_integrity(false, "heartbeat");
        uint64_t current_hash = current_scan.hash;
        std::lock_guard<std::mutex> lk(g_session_mtx);
        session_data_t sess = {};
        if (!load_session(sess))
        {
            arc_log("heartbeat", "state=1 load_session_failed");
            if (arc_runtime_requires_live_session(g_arc_runtime_state.load(std::memory_order_acquire)))
                enforce_violation_id(aida::reason_ids::reason_id_arc_required, "heartbeat_load_session_failed");
            CFF_EXIT(hb_cff);
        }

        {
            char dbg[192];
            _snprintf_s(dbg, sizeof(dbg), _TRUNCATE,
                "state=1 code_hash_stored=0x%016llX code_hash_current=0x%016llX exec=%u included=%u mutable=%u guarded=%u read_fail=%u",
                static_cast<unsigned long long>(sess.code_hash),
                static_cast<unsigned long long>(current_hash),
                current_scan.exec_regions,
                current_scan.included_regions,
                current_scan.mutable_exec_regions,
                current_scan.guarded_exec_regions,
                current_scan.read_failures);
            arc_log("heartbeat", dbg);
        }

        if (sess.code_hash != 0 && current_hash != sess.code_hash)
        {
            scan_own_code_integrity(true, "heartbeat_mismatch");
            char detail[192];
            _snprintf_s(detail, sizeof(detail), _TRUNCATE,
                "stored=0x%016llX current=0x%016llX exec=%u included=%u mutable=%u guarded=%u read_fail=%u",
                static_cast<unsigned long long>(sess.code_hash),
                static_cast<unsigned long long>(current_hash),
                current_scan.exec_regions,
                current_scan.included_regions,
                current_scan.mutable_exec_regions,
                current_scan.guarded_exec_regions,
                current_scan.read_failures);
            SecureZeroMemory(&sess, sizeof(sess));
            enforce_violation_id(aida::reason_ids::reason_id_arc_code_hash_mismatch, detail);
        }
        if (!verify_self_integrity())
        {
            SecureZeroMemory(&sess, sizeof(sess));
            enforce_violation_id(aida::reason_ids::reason_id_arc_self_hash_mismatch, "");
        }
        SecureZeroMemory(&sess, sizeof(sess));
        CFF_GOTO(hb_cff, 2);
    }
    CFF_STATE(hb_cff, 2)
    {
        if (check_debugger("heartbeat"))
        {
            enforce_violation_id(aida::reason_ids::reason_id_arc_debugger, "heartbeat");
        }
        CFF_GOTO(hb_cff, 3);
    }
    CFF_STATE(hb_cff, 3)
    {
        std::lock_guard<std::mutex> lk(g_session_mtx);
        session_data_t sess = {};
        if (!load_session(sess))
        {
            arc_log("heartbeat", "state=3 load_session_failed");
            if (arc_runtime_requires_live_session(g_arc_runtime_state.load(std::memory_order_acquire)))
                enforce_violation_id(aida::reason_ids::reason_id_arc_required, "heartbeat_load_session_failed");
            CFF_EXIT(hb_cff);
        }

        uint64_t current_qpc = qpc_now_us();
        if (current_qpc < sess.last_heartbeat_tsc)
        {
            char detail[96];
            _snprintf_s(detail, sizeof(detail), _TRUNCATE,
                "current=0x%016llX last=0x%016llX",
                static_cast<unsigned long long>(current_qpc),
                static_cast<unsigned long long>(sess.last_heartbeat_tsc));
            SecureZeroMemory(&sess, sizeof(sess));
            enforce_violation_id(aida::reason_ids::reason_id_arc_qpc_rollback, detail);
        }
        {
            char dbg[96];
            _snprintf_s(dbg, sizeof(dbg), _TRUNCATE,
                "heartbeat_ok counter=%llu qpc=0x%016llX",
                static_cast<unsigned long long>(sess.heartbeat_counter + 1),
                static_cast<unsigned long long>(current_qpc));
            arc_log("heartbeat", dbg);
        }
        sess.last_heartbeat_tsc = current_qpc;
        sess.heartbeat_counter++;

        if (!load_bind_secret())
        {
            SecureZeroMemory(&sess, sizeof(sess));
            enforce_violation_id(aida::reason_ids::reason_id_arc_no_bind_secret, "heartbeat");
        }

        char sess_fnv[17];
        char hwid_fnv[17];
        _snprintf_s(sess_fnv, sizeof(sess_fnv), _TRUNCATE, "%016llx",
            static_cast<unsigned long long>(sess.session_hash));
        _snprintf_s(hwid_fnv, sizeof(hwid_fnv), _TRUNCATE, "%016llx",
            static_cast<unsigned long long>(sess.hwid_hash));

        std::string msg;
        msg.reserve(96);
        msg.append(sess_fnv);
        msg.append("|");
        msg.append(hwid_fnv);
        msg.append("|");
        msg.append(std::to_string(static_cast<unsigned long long>(sess.heartbeat_counter)));
        msg.append("|0000000000000000");

        uint8_t mac[32] = {};
        uint8_t local_secret[32] = {};
        {
            std::lock_guard<std::mutex> bs_lk(g_bind_secret_mtx);
            bind_secret_obf_load_unlocked(local_secret);
        }
        const bool hmac_ok = hmac_sha256_full(local_secret, 32,
                reinterpret_cast<const uint8_t*>(msg.data()), msg.size(), mac);
        SecureZeroMemory(local_secret, sizeof(local_secret));
        if (!hmac_ok)
        {
            SecureZeroMemory(mac, sizeof(mac));
            SecureZeroMemory(&sess, sizeof(sess));
            enforce_violation_id(aida::reason_ids::reason_id_arc_heartbeat_hmac_failed, "");
        }

        uint64_t proof_be = 0;
        for (int i = 0; i < 8; ++i)
            proof_be = (proof_be << 8) | static_cast<uint64_t>(mac[i]);
        hb_result.proof_token = proof_be;
        SecureZeroMemory(mac, sizeof(mac));

        hb_result.timestamp = static_cast<uint64_t>(time(nullptr));
        hb_result.valid = true;
        {
            char dbg[96];
            _snprintf_s(dbg, sizeof(dbg), _TRUNCATE,
                "result valid=1 proof_token_set=%d",
                hb_result.proof_token != 0 ? 1 : 0);
            arc_log("heartbeat", dbg);
        }

        store_session(sess);
        SecureZeroMemory(&sess, sizeof(sess));
        CFF_EXIT(hb_cff);
    }
    CFF_END(hb_cff)

    return hb_result;
}

ARC_API arc_heartbeat_result_t arc_heartbeat_ex(uint64_t hb_count, const char* code_hash_hex)
{
    using namespace arc_internal;
    arc_heartbeat_result_t hb_result{};
    hb_result.valid = false;
    hb_result.proof_token = 0;
    hb_result.timestamp = 0;

    char code_hash_norm[17] = "0000000000000000";
    if (code_hash_hex)
    {
        char tmp[17] = {};
        size_t n = 0;
        bool valid = true;
        for (size_t i = 0; code_hash_hex[i] != '\0' && n < 16; ++i)
        {
            char c = code_hash_hex[i];
            if (c == ' ' || c == '\t') continue;
            if (c >= '0' && c <= '9') tmp[n++] = c;
            else if (c >= 'a' && c <= 'f') tmp[n++] = c;
            else if (c >= 'A' && c <= 'F') tmp[n++] = static_cast<char>(c - 'A' + 'a');
            else { valid = false; break; }
        }
        if (valid && n > 0 && n <= 16)
        {
            size_t pad = 16 - n;
            for (size_t i = 0; i < pad; ++i) code_hash_norm[i] = '0';
            for (size_t i = 0; i < n; ++i) code_hash_norm[pad + i] = tmp[i];
            code_hash_norm[16] = '\0';
        }
    }

    CFF_BEGIN(hbex_cff)
    CFF_STATE(hbex_cff, 0)
    {
        if (!is_session_valid())
        {
            arc_log("heartbeat_ex", "state=0 session_invalid");
            arc_log_export_denied("arc_heartbeat_ex", "session_invalid");
            if (arc_runtime_requires_live_session(g_arc_runtime_state.load(std::memory_order_acquire)))
                enforce_violation_id(aida::reason_ids::reason_id_arc_required, "heartbeat_ex_session_invalid");
            CFF_EXIT(hbex_cff);
        }
        CFF_GOTO(hbex_cff, 1);
    }
    CFF_STATE(hbex_cff, 1)
    {
        integrity_scan_result_t current_scan = scan_own_code_integrity(false, "heartbeat_ex");
        uint64_t current_hash = current_scan.hash;
        std::lock_guard<std::mutex> lk(g_session_mtx);
        session_data_t sess = {};
        if (!load_session(sess))
        {
            arc_log("heartbeat_ex", "state=1 load_session_failed");
            if (arc_runtime_requires_live_session(g_arc_runtime_state.load(std::memory_order_acquire)))
                enforce_violation_id(aida::reason_ids::reason_id_arc_required, "heartbeat_ex_load_session_failed");
            CFF_EXIT(hbex_cff);
        }
        {
            char dbg[192];
            _snprintf_s(dbg, sizeof(dbg), _TRUNCATE,
                "state=1 code_hash_stored=0x%016llX code_hash_current=0x%016llX exec=%u included=%u mutable=%u guarded=%u read_fail=%u",
                static_cast<unsigned long long>(sess.code_hash),
                static_cast<unsigned long long>(current_hash),
                current_scan.exec_regions,
                current_scan.included_regions,
                current_scan.mutable_exec_regions,
                current_scan.guarded_exec_regions,
                current_scan.read_failures);
            arc_log("heartbeat_ex", dbg);
        }
        if (sess.code_hash != 0 && current_hash != sess.code_hash)
        {
            scan_own_code_integrity(true, "heartbeat_ex_mismatch");
            char detail[192];
            _snprintf_s(detail, sizeof(detail), _TRUNCATE,
                "stored=0x%016llX current=0x%016llX exec=%u included=%u mutable=%u guarded=%u read_fail=%u",
                static_cast<unsigned long long>(sess.code_hash),
                static_cast<unsigned long long>(current_hash),
                current_scan.exec_regions,
                current_scan.included_regions,
                current_scan.mutable_exec_regions,
                current_scan.guarded_exec_regions,
                current_scan.read_failures);
            SecureZeroMemory(&sess, sizeof(sess));
            enforce_violation_id(aida::reason_ids::reason_id_arc_code_hash_mismatch, detail);
        }
        if (!verify_self_integrity())
        {
            SecureZeroMemory(&sess, sizeof(sess));
            enforce_violation_id(aida::reason_ids::reason_id_arc_self_hash_mismatch, "");
        }
        SecureZeroMemory(&sess, sizeof(sess));
        CFF_GOTO(hbex_cff, 2);
    }
    CFF_STATE(hbex_cff, 2)
    {
        if (check_debugger("heartbeat_ex"))
        {
            enforce_violation_id(aida::reason_ids::reason_id_arc_debugger, "heartbeat_ex");
        }
        CFF_GOTO(hbex_cff, 3);
    }
    CFF_STATE(hbex_cff, 3)
    {
        std::lock_guard<std::mutex> lk(g_session_mtx);
        session_data_t sess = {};
        if (!load_session(sess))
        {
            arc_log("heartbeat_ex", "state=3 load_session_failed");
            if (arc_runtime_requires_live_session(g_arc_runtime_state.load(std::memory_order_acquire)))
                enforce_violation_id(aida::reason_ids::reason_id_arc_required, "heartbeat_ex_load_session_failed");
            CFF_EXIT(hbex_cff);
        }

        uint64_t current_qpc = qpc_now_us();
        if (current_qpc < sess.last_heartbeat_tsc)
        {
            char detail[96];
            _snprintf_s(detail, sizeof(detail), _TRUNCATE,
                "current=0x%016llX last=0x%016llX",
                static_cast<unsigned long long>(current_qpc),
                static_cast<unsigned long long>(sess.last_heartbeat_tsc));
            SecureZeroMemory(&sess, sizeof(sess));
            enforce_violation_id(aida::reason_ids::reason_id_arc_qpc_rollback, detail);
        }
        sess.last_heartbeat_tsc = current_qpc;
        sess.heartbeat_counter++;

        if (!load_bind_secret())
        {
            SecureZeroMemory(&sess, sizeof(sess));
            enforce_violation_id(aida::reason_ids::reason_id_arc_no_bind_secret, "heartbeat_ex");
        }

        char sess_fnv[17];
        char hwid_fnv[17];
        _snprintf_s(sess_fnv, sizeof(sess_fnv), _TRUNCATE, "%016llx",
            static_cast<unsigned long long>(sess.session_hash));
        _snprintf_s(hwid_fnv, sizeof(hwid_fnv), _TRUNCATE, "%016llx",
            static_cast<unsigned long long>(sess.hwid_hash));

        std::string msg;
        msg.reserve(96);
        msg.append(sess_fnv);
        msg.append("|");
        msg.append(hwid_fnv);
        msg.append("|");
        msg.append(std::to_string(static_cast<unsigned long long>(hb_count)));
        msg.append("|");
        msg.append(code_hash_norm);

        {
            char dbg[320];
            _snprintf_s(dbg, sizeof(dbg), _TRUNCATE,
                "compose internal_counter=%llu hb_count=%llu code_hash_hash=0x%016llX msg_hash=0x%016llX msg_len=%zu",
                static_cast<unsigned long long>(sess.heartbeat_counter),
                static_cast<unsigned long long>(hb_count),
                static_cast<unsigned long long>(fnv1a_str(code_hash_norm)),
                static_cast<unsigned long long>(fnv1a(msg.data(), msg.size())),
                msg.size());
            arc_log("heartbeat_ex", dbg);
        }

        uint8_t mac[32] = {};
        uint8_t local_secret[32] = {};
        {
            std::lock_guard<std::mutex> bs_lk(g_bind_secret_mtx);
            bind_secret_obf_load_unlocked(local_secret);
        }
        const bool hmac_ok = hmac_sha256_full(local_secret, 32,
                reinterpret_cast<const uint8_t*>(msg.data()), msg.size(), mac);
        SecureZeroMemory(local_secret, sizeof(local_secret));
        if (!hmac_ok)
        {
            SecureZeroMemory(mac, sizeof(mac));
            SecureZeroMemory(&sess, sizeof(sess));
            enforce_violation_id(aida::reason_ids::reason_id_arc_heartbeat_hmac_failed, "ex");
        }

        uint64_t proof_be = 0;
        for (int i = 0; i < 8; ++i)
            proof_be = (proof_be << 8) | static_cast<uint64_t>(mac[i]);
        hb_result.proof_token = proof_be;
        SecureZeroMemory(mac, sizeof(mac));

        hb_result.timestamp = static_cast<uint64_t>(time(nullptr));
        hb_result.valid = true;

        {
            char dbg[160];
            _snprintf_s(dbg, sizeof(dbg), _TRUNCATE,
                "ok proof_token_set=%d",
                hb_result.proof_token != 0 ? 1 : 0);
            arc_log("heartbeat_ex", dbg);
        }

        store_session(sess);
        SecureZeroMemory(&sess, sizeof(sess));
        CFF_EXIT(hbex_cff);
    }
    CFF_END(hbex_cff)

    return hb_result;
}

}

extern "C"
{

ARC_API bool arc_verify_watermark_trailer(const uint8_t* blob, uint64_t blob_size)
{
    using namespace arc_internal;
    constexpr uint64_t kTrailerSize = 256ULL;
    if (!blob || blob_size <= kTrailerSize)
    {
        char dbg[96];
        _snprintf_s(dbg, sizeof(dbg), _TRUNCATE,
            "watermark_rejected reason=bad_args blob_set=%d size=%llu",
            blob ? 1 : 0,
            static_cast<unsigned long long>(blob_size));
        arc_log("watermark", dbg);
        return false;
    }
    if (blob_size > 0x40000000ULL)
    {
        arc_log("watermark", "watermark_rejected reason=size_too_large");
        return false;
    }

    const uint8_t* trailer = blob + (blob_size - kTrailerSize);

    uint8_t saw_zero  = 1;
    uint8_t saw_ff    = 1;
    for (uint64_t i = 0; i < kTrailerSize; ++i)
    {
        if (trailer[i] != 0x00u) saw_zero = 0;
        if (trailer[i] != 0xFFu) saw_ff   = 0;
    }
    if (saw_zero || saw_ff)
    {
        arc_log("watermark", "watermark_rejected reason=uniform_trailer");
        return false;
    }

    uint32_t mismatch_with_prev = 0;
    if (blob_size >= 2ULL * kTrailerSize)
    {
        const uint8_t* prev = trailer - kTrailerSize;
        for (uint64_t i = 0; i < kTrailerSize; ++i)
        {
            if (trailer[i] != prev[i]) ++mismatch_with_prev;
        }
        if (mismatch_with_prev < 16u)
        {
            char dbg[96];
            _snprintf_s(dbg, sizeof(dbg), _TRUNCATE,
                "watermark_rejected reason=low_mismatch mismatch=%u",
                mismatch_with_prev);
            arc_log("watermark", dbg);
            return false;
        }
    }
    else
    {
        mismatch_with_prev = static_cast<uint32_t>(kTrailerSize);
    }

    uint64_t entropy_acc = 0;
    uint64_t entropy_sum_sq = 0;
    uint64_t entropy_sum = 0;
    uint32_t hist[256] = {};
    for (uint64_t i = 0; i < kTrailerSize; ++i)
    {
        uint8_t b = trailer[i];
        ++hist[b];
        entropy_acc ^= (static_cast<uint64_t>(b) << (i & 0x3Fu));
        entropy_sum += b;
    }
    uint32_t distinct = 0;
    for (uint32_t i = 0; i < 256; ++i)
    {
        if (hist[i] != 0u)
        {
            ++distinct;
            entropy_sum_sq += static_cast<uint64_t>(hist[i]) * static_cast<uint64_t>(hist[i]);
        }
    }
    if (distinct < 24u)
    {
        char dbg[96];
        _snprintf_s(dbg, sizeof(dbg), _TRUNCATE,
            "watermark_rejected reason=low_distinct distinct=%u",
            distinct);
        arc_log("watermark", dbg);
        return false;
    }
    if (entropy_sum_sq > 4096ULL)
    {
        char dbg[96];
        _snprintf_s(dbg, sizeof(dbg), _TRUNCATE,
            "watermark_rejected reason=histogram_skew sq=%llu",
            static_cast<unsigned long long>(entropy_sum_sq));
        arc_log("watermark", dbg);
        return false;
    }
    (void)entropy_acc;
    (void)entropy_sum;

    uint64_t payload_size = blob_size - kTrailerSize;
    uint8_t payload_digest[32] = {};
    if (!sha256_block(blob, static_cast<size_t>(payload_size), payload_digest))
    {
        SecureZeroMemory(payload_digest, sizeof(payload_digest));
        arc_log("watermark", "watermark_rejected reason=payload_hash_failed");
        return false;
    }

    uint64_t digest_zero_run = 0;
    for (size_t i = 0; i < sizeof(payload_digest); ++i)
    {
        if (payload_digest[i] == 0) ++digest_zero_run;
    }
    SecureZeroMemory(payload_digest, sizeof(payload_digest));
    if (digest_zero_run >= 16)
    {
        arc_log("watermark", "watermark_rejected reason=digest_zero_run");
        return false;
    }

    {
        char dbg[128];
        _snprintf_s(dbg, sizeof(dbg), _TRUNCATE,
            "watermark_ok size=%llu distinct=%u mismatch=%u payload_hash_set=1",
            static_cast<unsigned long long>(blob_size),
            distinct,
            mismatch_with_prev);
        arc_log("watermark", dbg);
    }
    return true;
}

__declspec(noinline) static void arc_cleanup_unregister_protection_seh()
{
    voyager::device_t* dev = arc_internal::get_prebound_device();
    if (!dev)
        return;
    MEMORY_BASIC_INFORMATION mbi{};
    uint64_t module_base = 0;
    if (VirtualQuery(reinterpret_cast<const void*>(&arc_cleanup_unregister_protection_seh), &mbi, sizeof(mbi)) &&
        mbi.AllocationBase)
    {
        module_base = reinterpret_cast<uint64_t>(mbi.AllocationBase);
    }
    if (module_base == 0)
    {
        arc_internal::arc_log("driver", "cleanup_unregister_module_base_unavailable");
        return;
    }
    __try {
        dev->unregister_dll_protection_for_pid(GetCurrentProcessId(), module_base);
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
    }
}

ARC_API void arc_cleanup()
{
    using namespace arc_internal;
    arc_publish_state(arc_state_cleanup, "arc_cleanup", "entry");
    g_vtable_ready.store(false, std::memory_order_release);
    arc_cleanup_unregister_protection_seh();
    std::lock_guard<std::mutex> lk(g_session_mtx);
    anti_tamper::heap_encrypt::secure_free(g_enc_session_secure);
    g_enc_session_secure = nullptr;
    anti_tamper::heap_encrypt::secure_free(g_bind_secret_secure);
    g_bind_secret_secure = nullptr;
    SecureZeroMemory(g_bind_secret_xor_key, sizeof(g_bind_secret_xor_key));
    g_bind_secret_loaded = false;
    SecureZeroMemory(&g_vtable, sizeof(g_vtable));
    SecureZeroMemory(g_key_seed, sizeof(g_key_seed));
    g_key_seed_valid = false;
    g_vtable_crypt_key = 0;
    g_device_enc = 0;
    g_prebound_device_enc = 0;
    g_prebound_device_key = 0;
    arc_publish_state(arc_state_cold, "arc_cleanup", "complete");
}

ARC_API void arc_set_key_seed(const uint8_t* key_seed, uint32_t len)
{
    using namespace arc_internal;
    if (!key_seed || len != 32)
    {
        char dbg[96];
        _snprintf_s(dbg, sizeof(dbg), _TRUNCATE,
            "arc_set_key_seed_rejected ptr=%d len=%u",
            key_seed ? 1 : 0,
            len);
        arc_log("seed", dbg);
        return;
    }
    std::lock_guard<std::mutex> lk(g_key_seed_mtx);
    memcpy(g_key_seed, key_seed, 32);
    g_key_seed_valid = true;
    arc_log("seed", "arc_set_key_seed_ok len=32");
}

ARC_API uint32_t arc_copy_last_status(char* out, uint32_t cap)
{
    if (!out || cap == 0) return 0;
    using namespace arc_internal;
    std::lock_guard<std::mutex> lk(g_last_status_mtx);
    const size_t status_len = strnlen_s(g_last_status, sizeof(g_last_status));
    const size_t copy_len = status_len < static_cast<size_t>(cap - 1)
        ? status_len
        : static_cast<size_t>(cap - 1);
    if (copy_len > 0)
        memcpy(out, g_last_status, copy_len);
    out[copy_len] = '\0';
    return static_cast<uint32_t>(copy_len);
}

ARC_API bool arc_unseal_feature(
    uint32_t       feature_id,
    const uint8_t* nonce,
    uint32_t       nonce_len,
    uint8_t*       out,
    uint32_t*      out_size,
    uint32_t       out_cap)
{
    using namespace arc_internal;
    if (!out || !out_size || out_cap == 0) { arc_log("unseal", "bad_args"); return false; }
    if (!nonce || nonce_len == 0 || nonce_len > 256) { arc_log("unseal", "bad_nonce"); return false; }
    if (!is_session_valid()) { arc_log("unseal", "session_invalid"); return false; }
    if (check_debugger("unseal_feature")) { enforce_violation_id(aida::reason_ids::reason_id_arc_debugger, "unseal_feature"); }
    if (!load_bind_secret()) { arc_log("unseal", "bind_secret_load_failed"); return false; }

    uint8_t feature_blob[sizeof(g_feature_blob)] = {};
    for (uint32_t i = 0; i < sizeof(feature_blob); ++i)
    {
        feature_blob[i] = static_cast<uint8_t>(g_feature_blob[i]);
    }

    auto* hdr = reinterpret_cast<const feature_blob_header_t*>(feature_blob);
    if (hdr->magic != kFeatureMagic)
    {
        char buf[96];
        _snprintf_s(buf, sizeof(buf), _TRUNCATE,
            "bad_magic got=0x%08X exp=0x%08X b0=%02X b1=%02X b2=%02X b3=%02X",
            hdr->magic, kFeatureMagic,
            feature_blob[0], feature_blob[1], feature_blob[2], feature_blob[3]);
        arc_log("unseal", buf);
        return false;
    }
    if (hdr->version != 1u)
    {
        char buf[64];
        _snprintf_s(buf, sizeof(buf), _TRUNCATE, "bad_version got=%u", hdr->version);
        arc_log("unseal", buf);
        return false;
    }
    if (hdr->total_size > sizeof(feature_blob))
    {
        char buf[64];
        _snprintf_s(buf, sizeof(buf), _TRUNCATE, "bad_total_size got=%u", hdr->total_size);
        arc_log("unseal", buf);
        return false;
    }
    if (hdr->entry_count == 0u || hdr->entry_count > 16u)
    {
        char buf[64];
        _snprintf_s(buf, sizeof(buf), _TRUNCATE, "bad_entry_count got=%u", hdr->entry_count);
        arc_log("unseal", buf);
        return false;
    }

    const auto* entries = reinterpret_cast<const feature_entry_header_t*>(
        feature_blob + sizeof(feature_blob_header_t));
    const uint32_t entries_size = hdr->entry_count * kFeatureEntryHeaderSize;
    if (sizeof(feature_blob_header_t) + entries_size > sizeof(feature_blob))
    {
        arc_log("unseal", "entry_table_overflow");
        return false;
    }
    const uint32_t minimum_total_size = static_cast<uint32_t>(sizeof(feature_blob_header_t)) + entries_size;
    if (hdr->total_size < minimum_total_size)
    {
        char buf[80];
        _snprintf_s(buf, sizeof(buf), _TRUNCATE,
            "bad_total_size_floor got=%u min=%u",
            hdr->total_size, minimum_total_size);
        arc_log("unseal", buf);
        return false;
    }

    for (uint32_t i = 0; i < hdr->entry_count; ++i)
    {
        if (entries[i].entry_size != kFeatureEntryHeaderSize)
        {
            char buf[80];
            _snprintf_s(buf, sizeof(buf), _TRUNCATE,
                "bad_entry_size index=%u got=%u exp=%u",
                i, entries[i].entry_size, kFeatureEntryHeaderSize);
            arc_log("unseal", buf);
            return false;
        }
    }

    const feature_entry_header_t* match = nullptr;
    for (uint32_t i = 0; i < hdr->entry_count; ++i)
    {
        if (entries[i].feature_id == feature_id)
        {
            match = &entries[i];
            break;
        }
    }
    if (!match)
    {
        char buf[80];
        _snprintf_s(buf, sizeof(buf), _TRUNCATE,
            "no_match feature_id=%u entry_count=%u",
            feature_id, hdr->entry_count);
        arc_log("unseal", buf);
        return false;
    }
    if (match->ciphertext_len == 0u || match->ciphertext_len > kFeatureEntryMaxLen)
    {
        char buf[64];
        _snprintf_s(buf, sizeof(buf), _TRUNCATE, "bad_ct_len got=%u", match->ciphertext_len);
        arc_log("unseal", buf);
        return false;
    }
    if (match->ciphertext_offset < minimum_total_size)
    {
        char buf[80];
        _snprintf_s(buf, sizeof(buf), _TRUNCATE,
            "bad_ct_overlap off=%u min=%u",
            match->ciphertext_offset, minimum_total_size);
        arc_log("unseal", buf);
        return false;
    }
    if (match->ciphertext_offset > hdr->total_size ||
        match->ciphertext_len > hdr->total_size - match->ciphertext_offset)
    {
        char buf[80];
        _snprintf_s(buf, sizeof(buf), _TRUNCATE,
            "bad_ct_off off=%u len=%u",
            match->ciphertext_offset, match->ciphertext_len);
        arc_log("unseal", buf);
        return false;
    }
    if (match->ciphertext_len > out_cap)
    {
        arc_log("unseal", "ct_gt_out_cap");
        return false;
    }

    char info[64];
    int info_len = _snprintf_s(info, sizeof(info), _TRUNCATE,
        "feature:%u", static_cast<unsigned>(feature_id));
    if (info_len <= 0) { arc_log("unseal", "info_format_failed"); return false; }

    {
        uint8_t raw_slot[32];
        for (size_t i = 0; i < 32; ++i) raw_slot[i] = static_cast<uint8_t>(g_license_bind_slot[i]);
        int sentinel_count = 0;
        for (size_t i = 0; i < 32; ++i) if (raw_slot[i] == 0xCC) ++sentinel_count;
        unsigned long long slot_addr = static_cast<unsigned long long>(reinterpret_cast<uintptr_t>(&g_license_bind_slot[0]));
        char dbg[224];
        _snprintf_s(dbg, sizeof(dbg), _TRUNCATE,
            "diag_slot hash=0x%016llX sentinel_count=%d slot_addr=0x%016llX",
            static_cast<unsigned long long>(fnv1a(raw_slot, sizeof(raw_slot))),
            sentinel_count,
            slot_addr);
        arc_log("unseal", dbg);
        SecureZeroMemory(raw_slot, sizeof(raw_slot));
    }

    {
        const uint8_t* feat_bytes = feature_blob;
        unsigned long long feat_addr = static_cast<unsigned long long>(reinterpret_cast<uintptr_t>(&g_feature_blob[0]));
        char dbg[224];
        _snprintf_s(dbg, sizeof(dbg), _TRUNCATE,
            "diag_feat hdr_hash=0x%016llX blob_hash=0x%016llX entries=%u total=%u feat_addr=0x%016llX",
            static_cast<unsigned long long>(fnv1a(feat_bytes, 16)),
            static_cast<unsigned long long>(fnv1a(feat_bytes, hdr->total_size)),
            hdr->entry_count, hdr->total_size,
            feat_addr);
        arc_log("unseal", dbg);
    }

    {
        char dbg[256];
        _snprintf_s(dbg, sizeof(dbg), _TRUNCATE,
            "diag_entry id=%u entry_size=%u ct_off=%u ct_len=%u iv_hash=0x%016llX tag_hash=0x%016llX",
            match->feature_id, match->entry_size, match->ciphertext_offset, match->ciphertext_len,
            static_cast<unsigned long long>(fnv1a(match->iv, sizeof(match->iv))),
            static_cast<unsigned long long>(fnv1a(match->tag, sizeof(match->tag))));
        arc_log("unseal", dbg);
    }

    {
        const uint8_t* ct = feature_blob + match->ciphertext_offset;
        char dbg[224];
        _snprintf_s(dbg, sizeof(dbg), _TRUNCATE,
            "diag_nonce len=%u nonce_hash=0x%016llX ct_hash=0x%016llX info=%.*s",
            nonce_len,
            static_cast<unsigned long long>(fnv1a(nonce, nonce_len)),
            static_cast<unsigned long long>(fnv1a(ct, match->ciphertext_len)),
            info_len, info);
        arc_log("unseal", dbg);
    }

    uint8_t feature_key[32] = {};
    uint8_t local_secret[32] = {};
    uint64_t secret_acc = 0;
    {
        std::lock_guard<std::mutex> bs_lk(g_bind_secret_mtx);
        bind_secret_obf_load_unlocked(local_secret);
    }
    for (size_t i = 0; i < sizeof(local_secret); ++i)
        secret_acc |= local_secret[i];
    if (secret_acc == 0)
    {
        arc_log("unseal", "bind_secret_all_zero");
        SecureZeroMemory(local_secret, sizeof(local_secret));
        SecureZeroMemory(feature_key, sizeof(feature_key));
        return false;
    }
    {
        char dbg[160];
        _snprintf_s(dbg, sizeof(dbg), _TRUNCATE,
            "diag_bs hash=0x%016llX",
            static_cast<unsigned long long>(fnv1a(local_secret, sizeof(local_secret))));
        arc_log("unseal", dbg);
    }
    const bool hkdf_ok = hkdf_sha256(local_secret, 32,
            nonce, nonce_len,
            reinterpret_cast<const uint8_t*>(info), static_cast<uint32_t>(info_len),
            feature_key, 32);
    SecureZeroMemory(local_secret, sizeof(local_secret));
    if (!hkdf_ok)
    {
        arc_log("unseal", "hkdf_failed");
        SecureZeroMemory(feature_key, 32);
        return false;
    }
    {
        char dbg[160];
        _snprintf_s(dbg, sizeof(dbg), _TRUNCATE,
            "diag_fk hash=0x%016llX",
            static_cast<unsigned long long>(fnv1a(feature_key, sizeof(feature_key))));
        arc_log("unseal", dbg);
    }

    bool ok = aes_gcm_decrypt_ni(
        feature_blob + match->ciphertext_offset,
        match->ciphertext_len,
        feature_key,
        match->iv,
        match->tag,
        out);
    SecureZeroMemory(feature_key, 32);
    if (!ok)
    {
        char buf[112];
        _snprintf_s(buf, sizeof(buf), _TRUNCATE,
            "gcm_failed id=%u ct_off=%u ct_len=%u nonce_len=%u",
            feature_id, match->ciphertext_offset, match->ciphertext_len, nonce_len);
        arc_log("unseal", buf);
        return false;
    }
    *out_size = match->ciphertext_len;
    arc_log("unseal", "ok");
    return true;
}

ARC_API uint64_t arc_decrypt_session_v3(const char*, uint64_t)
{
    arc_internal::enforce_violation_id(aida::reason_ids::reason_id_arc_honey, "decrypt_session_v3");
    return 0;
}

ARC_API uint64_t arc_derive_kdf_root(const char*, uint64_t, uint64_t)
{
    arc_internal::enforce_violation_id(aida::reason_ids::reason_id_arc_honey, "derive_kdf_root");
    return 0;
}

ARC_API bool arc_verify_license_chain(const uint8_t*, uint32_t)
{
    arc_internal::enforce_violation_id(aida::reason_ids::reason_id_arc_honey, "verify_license_chain");
    return false;
}

ARC_API bool arc_unlock_premium(const char*)
{
    arc_internal::enforce_violation_id(aida::reason_ids::reason_id_arc_honey, "unlock_premium");
    return false;
}

ARC_API uint64_t arc_export_telemetry(const char*, uint32_t)
{
    arc_internal::enforce_violation_id(aida::reason_ids::reason_id_arc_honey, "export_telemetry");
    return 0;
}

ARC_API void* arc_resolve_handler(uint64_t)
{
    arc_internal::enforce_violation_id(aida::reason_ids::reason_id_arc_honey, "resolve_handler");
    return nullptr;
}

ARC_API uint64_t arc_dispatch_internal_v2(uint64_t, uint64_t)
{
    arc_internal::enforce_violation_id(aida::reason_ids::reason_id_arc_honey, "dispatch_internal_v2");
    return 0;
}

ARC_API bool arc_finalize_proof(const uint8_t*, uint32_t, uint8_t*, uint32_t)
{
    arc_internal::enforce_violation_id(aida::reason_ids::reason_id_arc_honey, "finalize_proof");
    return false;
}

ARC_API bool arc_master_decrypt(const uint8_t*, uint32_t, uint8_t*)
{
    arc_internal::enforce_violation_id(aida::reason_ids::reason_id_arc_honey, "master_decrypt");
    return false;
}

ARC_API bool arc_seed_pool_init(const uint8_t*, uint32_t)
{
    arc_internal::enforce_violation_id(aida::reason_ids::reason_id_arc_honey, "seed_pool_init");
    return false;
}

}

namespace {
struct arc_static_init_probe_t {
    arc_static_init_probe_t(const char* tag) { arc_internal::arc_log("static_init", tag); }
};
static arc_static_init_probe_t g_static_init_probe_a("ctor_a_top");
static arc_static_init_probe_t g_static_init_probe_z("ctor_z_bottom");
}

BOOL WINAPI DllMain(HINSTANCE hinst, DWORD reason, LPVOID reserved)
{
    char buf[64];
    _snprintf_s(buf, sizeof(buf), _TRUNCATE, "entry reason=%lu hinst=%p reserved=%p", (unsigned long)reason, (void*)hinst, reserved);
    arc_internal::arc_log("dllmain", buf);
    switch (reason) {
    case DLL_PROCESS_ATTACH:
        arc_internal::arc_log("dllmain", "PROCESS_ATTACH_case");
        break;
    case DLL_PROCESS_DETACH:
        arc_internal::arc_log("dllmain", "PROCESS_DETACH_pre_cleanup");
        arc_cleanup();
        arc_internal::arc_log("dllmain", "PROCESS_DETACH_post_cleanup");
        break;
    case DLL_THREAD_ATTACH:
        arc_internal::arc_log("dllmain", "THREAD_ATTACH");
        break;
    case DLL_THREAD_DETACH:
        arc_internal::arc_log("dllmain", "THREAD_DETACH");
        break;
    }
    arc_internal::arc_log("dllmain", "return_TRUE");
    return TRUE;
}
