#include "arc.h"
#include "comm.h"

#include <windows.h>
#include <intrin.h>
#include <wmmintrin.h>
#include <nmmintrin.h>
#include <winhttp.h>
#include <bcrypt.h>
#include <iphlpapi.h>

#include "anti-tamper/cff.hpp"
#include "arc_build_seed.hpp"
#include "obfuscation.hpp"

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

#include <atomic>
#include <cstring>
#include <cstdio>
#include <cstdlib>
#include <mutex>
#include <string>
#include <vector>

#pragma comment(lib, "bcrypt.lib")
#pragma comment(lib, "iphlpapi.lib")

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

    static WCHAR s_log_path[MAX_PATH] = {};
    static bool  s_path_ready = false;
    if (!s_path_ready) {
        WCHAR exe_path[MAX_PATH] = {};
        GetModuleFileNameW(nullptr, exe_path, MAX_PATH);
        WCHAR* last_sep = wcsrchr(exe_path, L'\\');
        if (last_sep) {
            last_sep[1] = L'\0';
            _snwprintf_s(s_log_path, MAX_PATH, _TRUNCATE, L"%saida_debug.log", exe_path);
        } else {
            wcscpy_s(s_log_path, MAX_PATH, L"aida_debug.log");
        }
        s_path_ready = true;
    }

    SYSTEMTIME st;
    GetLocalTime(&st);
    char line[512];
    int n = _snprintf_s(line, sizeof(line), _TRUNCATE,
        "[%02d:%02d:%02d.%03d] [arc/%s] %s\n",
        st.wHour, st.wMinute, st.wSecond, st.wMilliseconds, tag, msg);
    if (n <= 0) return;
    HANDLE h = CreateFileW(s_log_path, GENERIC_WRITE,
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
    OutputDebugStringA(line);
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

void fnv_mix_u64_value(uint64_t& hash, uint64_t value)
{
    for (int i = 0; i < 8; ++i) {
        hash ^= (value >> (i * 8)) & 0xFF;
        hash *= 1099511628211ULL;
    }
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

__forceinline __m128i aes_128_key_assist(__m128i t1, __m128i t2)
{
    t2 = _mm_shuffle_epi32(t2, 0xFF);
    __m128i t3 = _mm_slli_si128(t1, 4);
    t1 = _mm_xor_si128(t1, t3);
    t3 = _mm_slli_si128(t3, 4);
    t1 = _mm_xor_si128(t1, t3);
    t3 = _mm_slli_si128(t3, 4);
    t1 = _mm_xor_si128(t1, t3);
    return _mm_xor_si128(t1, t2);
}

void aes_128_expand_key(__m128i key, __m128i rk[11])
{
    rk[0] = key;
    rk[1]  = aes_128_key_assist(rk[0],  _mm_aeskeygenassist_si128(rk[0],  0x01));
    rk[2]  = aes_128_key_assist(rk[1],  _mm_aeskeygenassist_si128(rk[1],  0x02));
    rk[3]  = aes_128_key_assist(rk[2],  _mm_aeskeygenassist_si128(rk[2],  0x04));
    rk[4]  = aes_128_key_assist(rk[3],  _mm_aeskeygenassist_si128(rk[3],  0x08));
    rk[5]  = aes_128_key_assist(rk[4],  _mm_aeskeygenassist_si128(rk[4],  0x10));
    rk[6]  = aes_128_key_assist(rk[5],  _mm_aeskeygenassist_si128(rk[5],  0x20));
    rk[7]  = aes_128_key_assist(rk[6],  _mm_aeskeygenassist_si128(rk[6],  0x40));
    rk[8]  = aes_128_key_assist(rk[7],  _mm_aeskeygenassist_si128(rk[7],  0x80));
    rk[9]  = aes_128_key_assist(rk[8],  _mm_aeskeygenassist_si128(rk[8],  0x1B));
    rk[10] = aes_128_key_assist(rk[9],  _mm_aeskeygenassist_si128(rk[9],  0x36));
}

__forceinline __m128i aes_encrypt_block(__m128i block, const __m128i rk[11])
{
    block = _mm_xor_si128(block, rk[0]);
    block = _mm_aesenc_si128(block, rk[1]);
    block = _mm_aesenc_si128(block, rk[2]);
    block = _mm_aesenc_si128(block, rk[3]);
    block = _mm_aesenc_si128(block, rk[4]);
    block = _mm_aesenc_si128(block, rk[5]);
    block = _mm_aesenc_si128(block, rk[6]);
    block = _mm_aesenc_si128(block, rk[7]);
    block = _mm_aesenc_si128(block, rk[8]);
    block = _mm_aesenc_si128(block, rk[9]);
    block = _mm_aesenclast_si128(block, rk[10]);
    return block;
}

void aes_ctr_crypt(uint8_t* buf, size_t size, __m128i key, __m128i nonce)
{
    __m128i rk[11];
    aes_128_expand_key(key, rk);
    __m128i counter = nonce;
    const __m128i one = _mm_set_epi64x(0, 1);
    size_t full = size / 16;
    auto* blks = reinterpret_cast<__m128i*>(buf);
    for (size_t i = 0; i < full; ++i)
    {
        blks[i] = _mm_xor_si128(blks[i], aes_encrypt_block(counter, rk));
        counter = _mm_add_epi64(counter, one);
    }
    size_t tail_off = full * 16;
    size_t tail_len = size - tail_off;
    if (tail_len > 0)
    {
        alignas(16) uint8_t ks[16];
        _mm_store_si128(reinterpret_cast<__m128i*>(ks), aes_encrypt_block(counter, rk));
        for (size_t j = 0; j < tail_len; ++j)
            buf[tail_off + j] ^= ks[j];
    }
    SecureZeroMemory(rk, sizeof(rk));
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
    auto* ldr = *reinterpret_cast<const uint8_t* const*>(peb + 0x18);
    auto* list_head = reinterpret_cast<const uint8_t*>(ldr + 0x20);
    auto* entry = *reinterpret_cast<const uint8_t* const*>(list_head);

    while (entry != list_head)
    {
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
        entry = *reinterpret_cast<const uint8_t* const*>(entry);
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
encrypted_session_t g_enc_session = {};

alignas(64) uint8_t  g_key_seed[32] = {};
bool g_key_seed_valid = false;
std::mutex g_key_seed_mtx;

void encrypt_session_blob(session_data_t* plain, encrypted_session_t* enc)
{
    static_assert(sizeof(session_data_t) <= sizeof(enc->blob), "session too large");
    memcpy(enc->blob, plain, sizeof(session_data_t));
    uint64_t key = enc->rolling_key ^ enc->xor_mask ^ __rdtsc();
    __m128i aes_key = _mm_set_epi64x(
        static_cast<long long>(key),
        static_cast<long long>(key ^ 0xA1DA'CAFE'BABE'C0DEull));
    enc->rolling_key = key;
    __m128i nonce = _mm_set_epi64x(
        static_cast<long long>(enc->xor_mask),
        static_cast<long long>(key));
    aes_ctr_crypt(enc->blob, sizeof(session_data_t), aes_key, nonce);
    enc->valid = true;
}

bool decrypt_session_blob(encrypted_session_t* enc, session_data_t* out)
{
    if (!enc->valid) return false;

    bool result = false;
    uint64_t prev_key = 0;
    __m128i crypt_key = _mm_setzero_si128();
    __m128i nonce = _mm_setzero_si128();
    alignas(16) uint8_t tmp[sizeof(session_data_t)];

    CFF_BEGIN(dec_session_cff)
    CFF_STATE(dec_session_cff, 0)
    {
        prev_key = enc->rolling_key;
        crypt_key = _mm_set_epi64x(
            static_cast<long long>(prev_key),
            static_cast<long long>(prev_key ^ 0xA1DA'CAFE'BABE'C0DEull));
        nonce = _mm_set_epi64x(
            static_cast<long long>(enc->xor_mask),
            static_cast<long long>(prev_key));
        CFF_GOTO(dec_session_cff, 1);
    }
    CFF_STATE(dec_session_cff, 1)
    {
        memcpy(tmp, enc->blob, sizeof(session_data_t));
        aes_ctr_crypt(tmp, sizeof(session_data_t), crypt_key, nonce);
        memcpy(out, tmp, sizeof(session_data_t));
        SecureZeroMemory(tmp, sizeof(tmp));
        result = true;
        CFF_EXIT(dec_session_cff);
    }
    CFF_END(dec_session_cff)

    return result;
}

void store_session(const session_data_t& data)
{
    session_data_t copy = data;
    g_enc_session.rolling_key = __rdtsc() ^ 0x5DEECE66DULL;
    g_enc_session.xor_mask = __rdtsc() ^ 0x6A09E667BB67AE85ULL;
    encrypt_session_blob(&copy, &g_enc_session);
    SecureZeroMemory(&copy, sizeof(copy));
}

bool load_session(session_data_t& out)
{
    return decrypt_session_blob(&g_enc_session, &out);
}

uint64_t g_vtable_crypt_key = 0;
arc_comm_vtable_t g_vtable = {};
bool g_vtable_ready = false;
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

volatile uint8_t g_bind_secret_obf[32] = {};
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
    for (int i = 0; i < 32; i += 8)
    {
        uint64_t v = 0;
        memcpy(&v, plain + i, 8);
        v ^= g_bind_secret_xor_key[i / 8];
        memcpy(const_cast<uint8_t*>(g_bind_secret_obf + i), &v, 8);
    }
}

void bind_secret_obf_load_unlocked(uint8_t out[32])
{
    for (int i = 0; i < 32; i += 8)
    {
        uint64_t v = 0;
        memcpy(&v, const_cast<const uint8_t*>(g_bind_secret_obf + i), 8);
        v ^= g_bind_secret_xor_key[i / 8];
        memcpy(out + i, &v, 8);
    }
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

__forceinline uint64_t compute_vtable_integrity()
{
    uint8_t buf[sizeof(arc_comm_vtable_t)];
    memcpy(buf, &g_vtable, sizeof(buf));
    return siphash_2_4(buf, sizeof(buf), g_vtable_crypt_key, g_vtable_crypt_key ^ 0x5DEECE66DULL);
}

__forceinline bool verify_vtable()
{
    if (g_vtable_integrity == 0) return true;
    return compute_vtable_integrity() == g_vtable_integrity;
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

__declspec(noreturn) __forceinline void enforce_violation(const char* reason, const char* extra)
{
    const char* r = reason ? reason : "arc_unknown";
    const char* x = extra ? extra : "";

    {
        char log_line[384];
        _snprintf_s(log_line, sizeof(log_line), _TRUNCATE,
            "enforce_violation reason=%s extra=%s", r, x);
        arc_log("violation", log_line);
    }

    char hwid_buf[66] = {};
    char sess_buf[17] = {};
    if (g_session_mtx.try_lock())
    {
        session_data_t sess = {};
        if (decrypt_session_blob(&g_enc_session, &sess) && sess.initialized)
        {
            strncpy_s(hwid_buf, sizeof(hwid_buf), sess.hwid, _TRUNCATE);
            strncpy_s(sess_buf, sizeof(sess_buf), sess.session_token, _TRUNCATE);
        }
        SecureZeroMemory(&sess, sizeof(sess));
        g_session_mtx.unlock();
    }

    std::string server = load_server_url();
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
        auto k_hwid   = OBFSTR("hwid");
        auto k_sess   = OBFSTR("session");

        char ts_str[32];
        _snprintf_s(ts_str, sizeof(ts_str), _TRUNCATE,
            "%lld", static_cast<long long>(time(nullptr)));

        body += "{\"";
        body += k_source; body += "\":\""; body += v_source; body += "\",\"";
        body += k_reason; body += "\":\""; body += r;        body += "\",\"";
        body += k_extra;  body += "\":\""; body += x;        body += "\",\"";
        body += k_ts;     body += "\":";   body += ts_str;   body += ",\"";
        body += k_hwid;   body += "\":\""; body += hwid_buf; body += "\",\"";
        body += k_sess;   body += "\":\""; body += sess_buf; body += "\"}";

        http_post_json(url.c_str(), body.c_str());
    }

    SecureZeroMemory(hwid_buf, sizeof(hwid_buf));
    SecureZeroMemory(sess_buf, sizeof(sess_buf));

    __fastfail(0xA1DA);
}

bool check_debugger()
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
    if ((t1 - t0) > 10000000ULL)
    {
        char dbg[64];
        _snprintf_s(dbg, sizeof(dbg), _TRUNCATE, "check_debugger: rdtsc_delta=%llu", (unsigned long long)(t1 - t0));
        arc_log("debugger", dbg);
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

std::string recompute_hwid()
{
    uint64_t hash = 14695981039346656037ULL;
    auto mix = [&](uint64_t value) {
        fnv_mix_u64_value(hash, value);
    };

    DWORD volume_serial = 0;
    GetVolumeInformationW(L"C:\\", nullptr, 0, &volume_serial, nullptr, nullptr, nullptr, 0);

    wchar_t computer_name[MAX_COMPUTERNAME_LENGTH + 1] = {};
    DWORD name_size = MAX_COMPUTERNAME_LENGTH + 1;
    GetComputerNameW(computer_name, &name_size);

    int cpu_info[4] = {};
    __cpuid(cpu_info, 0);
    int cpu_info_ext[4] = {};
    __cpuid(cpu_info_ext, 1);

    mix(static_cast<uint64_t>(volume_serial));
    mix((static_cast<uint64_t>(cpu_info[0]) << 32) | static_cast<unsigned>(cpu_info[1]));
    mix((static_cast<uint64_t>(cpu_info[2]) << 32) | static_cast<unsigned>(cpu_info[3]));
    mix((static_cast<uint64_t>(cpu_info_ext[0]) << 32) | static_cast<unsigned>(cpu_info_ext[3]));
    for (DWORD i = 0; i < name_size; ++i)
        mix(static_cast<uint64_t>(computer_name[i]));

    ULONG len = 0;
    GetAdaptersInfo(nullptr, &len);
    if (len > 0) {
        std::vector<unsigned char> buffer(len);
        auto* adapter = reinterpret_cast<PIP_ADAPTER_INFO>(buffer.data());
        if (GetAdaptersInfo(adapter, &len) == NO_ERROR && adapter) {
            for (UINT i = 0; i < adapter->AddressLength; ++i)
                mix(static_cast<uint64_t>(adapter->Address[i]));
        }
    }

    char out[17];
    snprintf(out, sizeof(out), "%016llX", static_cast<unsigned long long>(hash));
    return out;
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
        return false;
    if (!sess.initialized)
        return false;

    uint64_t check = sess.session_hash ^ sess.hwid_hash ^ sess.xor_key;
    if (check == 0)
        return false;

    int64_t now = static_cast<int64_t>(time(nullptr));
    int64_t delta = now - static_cast<int64_t>(sess.init_timestamp);
    if (delta < -300 || delta > 86400)
        return false;

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
    if (check_debugger()) { enforce_violation("arc_debugger", "vtable_connect"); }
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
    if (check_debugger()) { enforce_violation("arc_debugger", "vtable_read"); }
    if (!verify_vtable()) { enforce_violation("arc_vtable_tampered", "read"); }
    if (!buffer || size == 0) return 0;
    auto* dev = get_device_enc(g_vtable_crypt_key);
    if (!dev) return 0;
    return dev->read_raw(address, buffer, size);
}

size_t vtable_write_raw(uint64_t address, const void* buffer, size_t size)
{
    if (!is_session_valid()) return 0;
    if (check_debugger()) { enforce_violation("arc_debugger", "vtable_write"); }
    if (!verify_vtable()) { enforce_violation("arc_vtable_tampered", "write"); }
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
    if (check_debugger()) { enforce_violation("arc_debugger", "vtable_remote_call"); }
    if (!verify_vtable()) { enforce_violation("arc_vtable_tampered", "remote_call"); }
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
    g_vtable_integrity = compute_vtable_integrity();

    generate_slot_keys(crypt_key);
    encrypt_vtable_slots();

    g_vtable_ready = true;
}

}


extern "C"
{

ARC_API bool arc_bind_driver_device(void* driver_device, uint32_t interface_version)
{
    using namespace arc_internal;
    if (interface_version != ARC_INTERFACE_VERSION || !driver_device)
        return false;
    bind_prebound_device(reinterpret_cast<voyager::device_t*>(driver_device));
    return get_prebound_device() != nullptr;
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
        if (token_len < 32 || token_len > 128)
        {
            char dbg[96];
            _snprintf_s(dbg, sizeof(dbg), _TRUNCATE,
                "arc_init_session_token_len_out_of_range got=%zu expected=[32,128]",
                token_len);
            arc_log("init", dbg);
            return false;
        }
        size_t hwid_len = strlen(hwid);
        if (hwid_len < 8 || hwid_len > 64)
        {
            char dbg[96];
            _snprintf_s(dbg, sizeof(dbg), _TRUNCATE,
                "arc_init_hwid_len_out_of_range got=%zu expected=[8,64]",
                hwid_len);
            arc_log("init", dbg);
            return false;
        }
    }

    arc_log("init", "arc_init_step2_check_debugger");
    if (check_debugger())
    {
        enforce_violation("arc_debugger", "arc_init");
    }

    arc_log("init", "arc_init_step3_hwid_recompute");
    {
        std::string local_hwid = recompute_hwid();
        uint64_t local_hash = fnv1a_str(local_hwid.c_str());
        uint64_t provided_hash = fnv1a_str(hwid);
        local_hwid_hash_capture = local_hash;
        {
            char dbg[160];
            _snprintf_s(dbg, sizeof(dbg), _TRUNCATE,
                "arc_init_hwid local=%s provided=%s local_hash=0x%016llX provided_hash=0x%016llX",
                local_hwid.c_str(), hwid,
                static_cast<unsigned long long>(local_hash),
                static_cast<unsigned long long>(provided_hash));
            arc_log("init", dbg);
        }
        if (local_hash != provided_hash)
        {
            enforce_violation("arc_hwid_mismatch", "");
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
            enforce_violation("arc_no_bind_secret", "");
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
            enforce_violation("arc_bind_proof_hmac_failed", "");
        }

        if (memcmp(expected, bind_proof, 32) != 0)
        {
            char dbg[200];
            _snprintf_s(dbg, sizeof(dbg), _TRUNCATE,
                "arc_init_bind_proof_mismatch expected[0..7]=%02X%02X%02X%02X%02X%02X%02X%02X got[0..7]=%02X%02X%02X%02X%02X%02X%02X%02X",
                expected[0], expected[1], expected[2], expected[3],
                expected[4], expected[5], expected[6], expected[7],
                bind_proof[0], bind_proof[1], bind_proof[2], bind_proof[3],
                bind_proof[4], bind_proof[5], bind_proof[6], bind_proof[7]);
            arc_log("init", dbg);
            SecureZeroMemory(expected, sizeof(expected));
            enforce_violation("arc_bind_proof_mismatch", "");
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
        }
        sess.initialized = true;

        store_session(sess);
        init_vtable(sess.vtable_crypt_key);
        SecureZeroMemory(&sess, sizeof(sess));

        result = true;
    }

    arc_log("init", "arc_init_step8_device_bridge");
    {
        voyager::device_t* dev = get_device_enc(g_vtable_crypt_key);
        if (!dev)
        {
            arc_log("init", "arc_init_get_device_enc_returned_null");
            enforce_violation("arc_no_device", "init");
        }

        if (!dev->is_connected())
        {
            arc_log("init", "arc_init_device_disconnected");
            enforce_violation("arc_no_driver", "device_disconnected");
        }

        if (!dev->refresh_heartbeat())
        {
            arc_log("driver", "heartbeat_failed");
            enforce_violation("arc_no_driver", "heartbeat_failed");
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
                    enforce_violation("arc_no_driver", "sentinel_bridge_down");
                }
                if (check_debugger())
                {
                    enforce_violation("arc_debugger", "sentinel_bridge_wait");
                }
                if (!dev->is_connected())
                {
                    enforce_violation("arc_no_driver", "device_disconnected_during_wait");
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
                if (!dev->refresh_heartbeat())
                {
                    arc_log("driver", "heartbeat_failed_during_bridge_wait");
                    enforce_violation("arc_no_driver", "heartbeat_failed");
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
        if (!dev->tier_a_driver_present_query(tier_a_present, &tier_a_mask, &tier_a_first_base))
        {
            arc_log("driver", "tier_a_query_failed");
            enforce_violation("arc_no_driver", "tier_a_query_failed");
        }

        if (tier_a_present)
        {
            char detail[96];
            _snprintf_s(detail, sizeof(detail), _TRUNCATE,
                "tier_a_present mask=0x%08X first_base=0x%016llX",
                tier_a_mask, static_cast<unsigned long long>(tier_a_first_base));
            arc_log("driver", detail);
            enforce_violation("arc_hostile_driver", "tier_a_present");
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
            }
            else if (!dev->register_dll_protection(image_base, text_va,
                    static_cast<uint32_t>(text_size), driver_expected_hash, 2000))
            {
                DWORD gle = GetLastError();
                char detail[224];
                _snprintf_s(detail, sizeof(detail), _TRUNCATE,
                    "register_dll_protection_failed gle=%lu image=0x%016llX text=0x%016llX text_size=0x%016llX expected=0x%016llX",
                    static_cast<unsigned long>(gle),
                    static_cast<unsigned long long>(image_base),
                    static_cast<unsigned long long>(text_va),
                    static_cast<unsigned long long>(text_size),
                    static_cast<unsigned long long>(driver_expected_hash));
                arc_log("driver", detail);
            }
            else
            {
                arc_log("driver", "register_dll_protection_ok");
            }
        }
        else
        {
            arc_log("driver", "image_layout_unavailable");
        }
    }

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
    if (!is_session_valid()) return nullptr;
    if (!g_vtable_ready) return nullptr;
    decrypt_vtable_into(&g_vtable_decrypted);
    return &g_vtable_decrypted;
}

ARC_API uint64_t arc_validate_tool_exec(
    uint64_t tool_name_hash,
    uint64_t gate_token)
{
    using namespace arc_internal;
    uint64_t out = 0;

    CFF_BEGIN(validate_cff)
    CFF_STATE(validate_cff, 0)
    {
        if (tool_name_hash == 0 || gate_token == 0)
        {
            CFF_EXIT(validate_cff);
        }
        CFF_GOTO(validate_cff, 1);
    }
    CFF_STATE(validate_cff, 1)
    {
        if (!is_session_valid())
        {
            CFF_EXIT(validate_cff);
        }
        CFF_GOTO(validate_cff, 2);
    }
    CFF_STATE(validate_cff, 2)
    {
        if (check_debugger())
        {
            enforce_violation("arc_debugger", "validate_tool");
        }
        CFF_GOTO(validate_cff, 3);
    }
    CFF_STATE(validate_cff, 3)
    {
        if (!load_bind_secret())
        {
            enforce_violation("arc_no_bind_secret", "validate_tool");
        }

        std::lock_guard<std::mutex> lk(g_session_mtx);
        session_data_t sess = {};
        if (!load_session(sess))
        {
            CFF_EXIT(validate_cff);
        }

        uint8_t buf[40];
        memcpy(buf, &tool_name_hash, 8);
        memcpy(buf + 8, &gate_token, 8);
        memcpy(buf + 16, &sess.session_hash, 8);
        uint64_t tick = static_cast<uint64_t>(GetTickCount64());
        memcpy(buf + 24, &tick, 8);
        memcpy(buf + 32, &sess.vtable_crypt_key, 8);

        uint8_t mac[32] = {};
        uint8_t local_secret[32] = {};
        {
            std::lock_guard<std::mutex> bs_lk(g_bind_secret_mtx);
            bind_secret_obf_load_unlocked(local_secret);
        }
        const bool hmac_ok = hmac_sha256_full(local_secret, 32, buf, sizeof(buf), mac);
        SecureZeroMemory(local_secret, sizeof(local_secret));
        if (!hmac_ok)
        {
            SecureZeroMemory(mac, sizeof(mac));
            SecureZeroMemory(&sess, sizeof(sess));
            CFF_EXIT(validate_cff);
        }
        memcpy(&out, mac, 8);
        SecureZeroMemory(mac, sizeof(mac));

        SecureZeroMemory(&sess, sizeof(sess));
        CFF_EXIT(validate_cff);
    }
    CFF_END(validate_cff)

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
            enforce_violation("arc_code_hash_mismatch", detail);
        }
        if (!verify_self_integrity())
        {
            enforce_violation("arc_self_hash_mismatch", "");
        }
        CFF_GOTO(hb_cff, 2);
    }
    CFF_STATE(hb_cff, 2)
    {
        if (check_debugger())
        {
            enforce_violation("arc_debugger", "heartbeat");
        }
        CFF_GOTO(hb_cff, 3);
    }
    CFF_STATE(hb_cff, 3)
    {
        std::lock_guard<std::mutex> lk(g_session_mtx);
        session_data_t sess = {};
        if (!load_session(sess))
        {
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
            enforce_violation("arc_qpc_rollback", detail);
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
            enforce_violation("arc_no_bind_secret", "heartbeat");
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
            enforce_violation("arc_heartbeat_hmac_failed", "");
        }

        uint64_t proof_be = 0;
        for (int i = 0; i < 8; ++i)
            proof_be = (proof_be << 8) | static_cast<uint64_t>(mac[i]);
        hb_result.proof_token = proof_be;
        SecureZeroMemory(mac, sizeof(mac));

        hb_result.timestamp = static_cast<uint64_t>(time(nullptr));
        hb_result.valid = true;

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
            CFF_EXIT(hbex_cff);
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
            enforce_violation("arc_code_hash_mismatch", detail);
        }
        if (!verify_self_integrity())
        {
            enforce_violation("arc_self_hash_mismatch", "");
        }
        CFF_GOTO(hbex_cff, 2);
    }
    CFF_STATE(hbex_cff, 2)
    {
        if (check_debugger())
        {
            enforce_violation("arc_debugger", "heartbeat_ex");
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
            enforce_violation("arc_qpc_rollback", detail);
        }
        sess.last_heartbeat_tsc = current_qpc;
        sess.heartbeat_counter++;

        if (!load_bind_secret())
        {
            SecureZeroMemory(&sess, sizeof(sess));
            enforce_violation("arc_no_bind_secret", "heartbeat_ex");
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
                "compose internal_counter=%llu hb_count=%llu code_hash=%s msg=%.200s",
                static_cast<unsigned long long>(sess.heartbeat_counter),
                static_cast<unsigned long long>(hb_count),
                code_hash_norm,
                msg.c_str());
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
            enforce_violation("arc_heartbeat_hmac_failed", "ex");
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
                "ok proof_token=0x%016llX",
                static_cast<unsigned long long>(hb_result.proof_token));
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

namespace {
    static constexpr uint32_t ARC_PAGE_SIZE = 4096;

    std::string json_get_string(const std::string& json, const char* key)
    {
        std::string needle = std::string("\"") + key + "\"";
        auto pos = json.find(needle);
        if (pos == std::string::npos) return "";
        pos = json.find(':', pos + needle.size());
        if (pos == std::string::npos) return "";
        pos = json.find('"', pos + 1);
        if (pos == std::string::npos) return "";
        auto end = json.find('"', pos + 1);
        if (end == std::string::npos) return "";
        return json.substr(pos + 1, end - pos - 1);
    }

    int64_t json_get_int(const std::string& json, const char* key)
    {
        std::string needle = std::string("\"") + key + "\"";
        auto pos = json.find(needle);
        if (pos == std::string::npos) return -1;
        pos = json.find(':', pos + needle.size());
        if (pos == std::string::npos) return -1;
        while (pos < json.size() && (json[pos] == ':' || json[pos] == ' ')) ++pos;
        return std::strtoll(json.c_str() + pos, nullptr, 10);
    }

    std::string build_session_json()
    {
        using namespace arc_internal;
        std::lock_guard<std::mutex> lk(g_session_mtx);
        session_data_t sess = {};
        if (!load_session(sess)) return "{}";
        auto k1 = OBFSTR("license_key");
        auto k2 = OBFSTR("session_token");
        auto k3 = OBFSTR("hwid");
        std::string r = "{\"";
        r += k1; r += "\":\""; r += sess.license_key;
        r += "\",\""; r += k2; r += "\":\""; r += sess.session_token;
        r += "\",\""; r += k3; r += "\":\""; r += sess.hwid;
        r += "\"}";
        SecureZeroMemory(&sess, sizeof(sess));
        return r;
    }

    bool hex_to_bytes(const std::string& hex, uint8_t* out, size_t max_len)
    {
        if (hex.size() / 2 > max_len) return false;
        for (size_t i = 0; i + 1 < hex.size(); i += 2) {
            char h[3] = { hex[i], hex[i + 1], 0 };
            out[i / 2] = static_cast<uint8_t>(strtoul(h, nullptr, 16));
        }
        return true;
    }

    static const uint8_t b64_table[] = {
        255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,
        255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,
        255,255,255,255,255,255,255,255,255,255,255, 62,255,255,255, 63,
         52, 53, 54, 55, 56, 57, 58, 59, 60, 61,255,255,255,  0,255,255,
        255,  0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14,
         15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25,255,255,255,255,255,
        255, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40,
         41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51,255,255,255,255,255
    };

    bool base64_decode(const std::string& in, std::vector<uint8_t>& out)
    {
        out.clear();
        if (in.empty()) return false;
        out.reserve((in.size() * 3) / 4);
        uint32_t accum = 0;
        int bits = 0;
        for (char c : in)
        {
            if (c == '=' || c == '\n' || c == '\r') continue;
            uint8_t idx = static_cast<uint8_t>(c);
            if (idx >= 128) return false;
            uint8_t val = b64_table[idx];
            if (val == 255) return false;
            accum = (accum << 6) | val;
            bits += 6;
            if (bits >= 8)
            {
                bits -= 8;
                out.push_back(static_cast<uint8_t>((accum >> bits) & 0xFF));
            }
        }
        return true;
    }

    void derive_page_key(uint32_t page_index, uint8_t out_key[32])
    {
        using namespace arc_internal;

        session_data_t sess = {};
        uint8_t ks[32];
        bool have_seed = false;
        std::string data;
        BCRYPT_ALG_HANDLE hAlg = nullptr;
        BCRYPT_HASH_HANDLE hHash = nullptr;
        NTSTATUS st = 0;
        bool early_exit = false;

        CFF_BEGIN(derive_page_key_cff)
        CFF_STATE(derive_page_key_cff, 0)
        {
            {
                std::lock_guard<std::mutex> lk(g_session_mtx);
                if (!load_session(sess))
                {
                    SecureZeroMemory(out_key, 32);
                    early_exit = true;
                    CFF_EXIT(derive_page_key_cff);
                }
            }
            {
                std::lock_guard<std::mutex> lk2(g_key_seed_mtx);
                if (g_key_seed_valid)
                {
                    memcpy(ks, g_key_seed, 32);
                    have_seed = true;
                }
            }
            CFF_GOTO(derive_page_key_cff, 1);
        }
        CFF_STATE(derive_page_key_cff, 1)
        {
            if (!have_seed)
            {
                SecureZeroMemory(out_key, 32);
                SecureZeroMemory(&sess, sizeof(sess));
                early_exit = true;
                CFF_EXIT(derive_page_key_cff);
            }

            data = "page|" + std::to_string(page_index) + "|"
                + std::string(sess.session_token) + "|"
                + std::string(sess.hwid) + "|"
                + std::to_string(static_cast<int64_t>(sess.init_timestamp)) + "|";

            st = BCryptOpenAlgorithmProvider(
                &hAlg, BCRYPT_SHA256_ALGORITHM, nullptr, BCRYPT_ALG_HANDLE_HMAC_FLAG);
            CFF_GOTO(derive_page_key_cff, 2);
        }
        CFF_STATE(derive_page_key_cff, 2)
        {
            if (BCRYPT_SUCCESS(st) && hAlg)
            {
                st = BCryptCreateHash(hAlg, &hHash, nullptr, 0, ks, 32, 0);
                if (BCRYPT_SUCCESS(st) && hHash)
                {
                    st = BCryptHashData(
                        hHash,
                        reinterpret_cast<PUCHAR>(const_cast<char*>(data.data())),
                        static_cast<ULONG>(data.size()),
                        0);
                    if (BCRYPT_SUCCESS(st))
                        st = BCryptFinishHash(hHash, out_key, 32, 0);
                }
            }

            if (hHash) BCryptDestroyHash(hHash);
            if (hAlg) BCryptCloseAlgorithmProvider(hAlg, 0);
            SecureZeroMemory(ks, sizeof(ks));
            SecureZeroMemory(&sess, sizeof(sess));

            if (!BCRYPT_SUCCESS(st))
                SecureZeroMemory(out_key, 32);
            CFF_EXIT(derive_page_key_cff);
        }
        CFF_END(derive_page_key_cff)

        (void)early_exit;
    }
}

extern "C"
{

ARC_API arc_page_result_t arc_request_page_count(const char* server_url)
{
    using namespace arc_internal;
    arc_page_result_t res{};
    if (!is_session_valid() || !server_url) return res;
    capture_server_url(server_url);
    if (check_debugger()) { enforce_violation("arc_debugger", "request_page_count"); }

    std::string url = std::string(server_url) + OBFSTR("/api/download/pages/count");
    std::string body = build_session_json();
    std::string resp = http_post_json(url.c_str(), body.c_str());

    auto status_str = OBFSTR("status");
    auto ok_str = OBFSTR("ok");
    if (json_get_string(resp, status_str.c_str()) != ok_str) return res;

    auto tp = OBFSTR("total_pages");
    auto ps = OBFSTR("page_size");
    auto bs = OBFSTR("blob_size");
    res.total_pages = static_cast<uint32_t>(json_get_int(resp, tp.c_str()));
    res.page_size   = static_cast<uint32_t>(json_get_int(resp, ps.c_str()));
    res.blob_size   = static_cast<uint64_t>(json_get_int(resp, bs.c_str()));
    res.valid       = (res.total_pages > 0);
    return res;
}

ARC_API bool arc_download_page(
    const char*  server_url,
    uint32_t     page_index,
    uint8_t*     out_decrypted,
    uint32_t*    out_size)
{
    using namespace arc_internal;
    if (!is_session_valid() || !server_url || !out_decrypted || !out_size) return false;
    capture_server_url(server_url);
    if (check_debugger()) { enforce_violation("arc_debugger", "download_page"); }

    char url_buf[512];
    auto page_path = OBFSTR("/api/download/pages/");
    snprintf(url_buf, sizeof(url_buf), "%s%s%u", server_url, page_path.c_str(), page_index);

    std::string body = build_session_json();
    std::string resp = http_post_json(url_buf, body.c_str());

    auto status_key = OBFSTR("status");
    auto ok_val = OBFSTR("ok");
    if (json_get_string(resp, status_key.c_str()) != ok_val) return false;

    auto data_key = OBFSTR("encrypted_page");
    auto iv_key = OBFSTR("iv");
    auto tag_key = OBFSTR("auth_tag");
    std::string b64_data = json_get_string(resp, data_key.c_str());
    std::string hex_iv   = json_get_string(resp, iv_key.c_str());
    std::string hex_tag  = json_get_string(resp, tag_key.c_str());

    if (b64_data.empty() || hex_iv.size() != 24 || hex_tag.size() != 32) return false;

    std::vector<uint8_t> ct;
    if (!base64_decode(b64_data, ct)) return false;

    uint8_t iv[12] = {}, tag[16] = {};
    hex_to_bytes(hex_iv, iv, 12);
    hex_to_bytes(hex_tag, tag, 16);

    uint8_t page_key[32];
    derive_page_key(page_index, page_key);

    if (!aes_gcm_decrypt_ni(ct.data(), ct.size(), page_key, iv, tag, out_decrypted))
    {
        SecureZeroMemory(page_key, 32);
        return false;
    }

    *out_size = static_cast<uint32_t>(ct.size());
    SecureZeroMemory(page_key, 32);
    return true;
}

ARC_API bool arc_download_all_pages(
    const char*  server_url,
    uint8_t*     out_blob,
    uint64_t     blob_buf_size,
    uint64_t*    out_total_size)
{
    using namespace arc_internal;
    if (!is_session_valid() || !server_url || !out_blob || !out_total_size) return false;
    capture_server_url(server_url);
    if (check_debugger()) { enforce_violation("arc_debugger", "download_all_pages"); }

    arc_page_result_t info = arc_request_page_count(server_url);
    if (!info.valid) return false;
    if (info.blob_size > blob_buf_size) return false;

    uint64_t offset = 0;
    for (uint32_t i = 0; i < info.total_pages; ++i)
    {
        uint8_t page_buf[ARC_PAGE_SIZE];
        uint32_t page_size = 0;
        if (!arc_download_page(server_url, i, page_buf, &page_size))
        {
            SecureZeroMemory(out_blob, static_cast<size_t>(offset));
            return false;
        }
        if (offset + page_size > blob_buf_size)
        {
            SecureZeroMemory(out_blob, static_cast<size_t>(offset));
            return false;
        }
        memcpy(out_blob + offset, page_buf, page_size);
        SecureZeroMemory(page_buf, sizeof(page_buf));
        offset += page_size;
    }

    *out_total_size = offset;
    return true;
}

ARC_API void arc_cleanup()
{
    using namespace arc_internal;
    std::lock_guard<std::mutex> lk(g_session_mtx);
    SecureZeroMemory(&g_enc_session, sizeof(g_enc_session));
    SecureZeroMemory(&g_vtable, sizeof(g_vtable));
    SecureZeroMemory(g_key_seed, sizeof(g_key_seed));
    g_key_seed_valid = false;
    g_vtable_ready = false;
    g_vtable_crypt_key = 0;
}

ARC_API void arc_set_key_seed(const uint8_t* key_seed, uint32_t len)
{
    using namespace arc_internal;
    if (!key_seed || len != 32) return;
    std::lock_guard<std::mutex> lk(g_key_seed_mtx);
    memcpy(g_key_seed, key_seed, 32);
    g_key_seed_valid = true;
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
    if (!is_session_valid()) { arc_log("unseal", "session_invalid"); return false; }
    if (check_debugger()) { enforce_violation("arc_debugger", "unseal_feature"); }
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
    arc_internal::enforce_violation("arc_honey", "decrypt_session_v3");
    return 0;
}

ARC_API uint64_t arc_derive_kdf_root(const char*, uint64_t, uint64_t)
{
    arc_internal::enforce_violation("arc_honey", "derive_kdf_root");
    return 0;
}

ARC_API bool arc_verify_license_chain(const uint8_t*, uint32_t)
{
    arc_internal::enforce_violation("arc_honey", "verify_license_chain");
    return false;
}

ARC_API bool arc_unlock_premium(const char*)
{
    arc_internal::enforce_violation("arc_honey", "unlock_premium");
    return false;
}

ARC_API uint64_t arc_export_telemetry(const char*, uint32_t)
{
    arc_internal::enforce_violation("arc_honey", "export_telemetry");
    return 0;
}

ARC_API void* arc_resolve_handler(uint64_t)
{
    arc_internal::enforce_violation("arc_honey", "resolve_handler");
    return nullptr;
}

ARC_API uint64_t arc_dispatch_internal_v2(uint64_t, uint64_t)
{
    arc_internal::enforce_violation("arc_honey", "dispatch_internal_v2");
    return 0;
}

ARC_API bool arc_finalize_proof(const uint8_t*, uint32_t, uint8_t*, uint32_t)
{
    arc_internal::enforce_violation("arc_honey", "finalize_proof");
    return false;
}

ARC_API bool arc_master_decrypt(const uint8_t*, uint32_t, uint8_t*)
{
    arc_internal::enforce_violation("arc_honey", "master_decrypt");
    return false;
}

ARC_API bool arc_seed_pool_init(const uint8_t*, uint32_t)
{
    arc_internal::enforce_violation("arc_honey", "seed_pool_init");
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
