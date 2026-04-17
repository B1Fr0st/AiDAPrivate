#define ARC_EXPORTS
#define WIN32_LEAN_AND_MEAN
#define NOMINMAX

#include "arc.h"
#include "comm.h"

#include <windows.h>
#include <intrin.h>
#include <wmmintrin.h>
#include <nmmintrin.h>
#include <winhttp.h>
#include <bcrypt.h>

#include "anti-tamper/cff.hpp"
#include "obfuscation.hpp"

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

    BCRYPT_ALG_HANDLE hAlg = nullptr;
    BCRYPT_KEY_HANDLE hKey = nullptr;

    NTSTATUS st = BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_AES_ALGORITHM, nullptr, 0);
    if (!BCRYPT_SUCCESS(st) || !hAlg) return false;

    st = BCryptSetProperty(
        hAlg,
        BCRYPT_CHAINING_MODE,
        reinterpret_cast<PUCHAR>(const_cast<wchar_t*>(BCRYPT_CHAIN_MODE_GCM)),
        static_cast<ULONG>(wcslen(BCRYPT_CHAIN_MODE_GCM) * sizeof(wchar_t) + sizeof(wchar_t)),
        0);
    if (!BCRYPT_SUCCESS(st))
    {
        BCryptCloseAlgorithmProvider(hAlg, 0);
        return false;
    }

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
        return false;
    }

    BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO authInfo;
    BCRYPT_INIT_AUTH_MODE_INFO(authInfo);
    authInfo.pbNonce = const_cast<PUCHAR>(iv12);
    authInfo.cbNonce = 12;
    authInfo.pbTag = const_cast<PUCHAR>(tag16);
    authInfo.cbTag = 16;

    ULONG bytes_decrypted = 0;
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
    BCryptCloseAlgorithmProvider(hAlg, 0);
    return BCRYPT_SUCCESS(st) && bytes_decrypted == static_cast<ULONG>(ct_len);
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

struct corruption_state_t
{
    std::atomic<uint64_t> poison_seed{0};
    std::atomic<int> kill_countdown{-1};
    std::atomic<bool> armed{false};
};

corruption_state_t g_corruption = {};

struct encrypted_session_t
{
    alignas(64) uint8_t blob[256];
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
    uint64_t prev_key = enc->rolling_key;
    __m128i crypt_key = _mm_set_epi64x(
        static_cast<long long>(prev_key),
        static_cast<long long>(prev_key ^ 0xA1DA'CAFE'BABE'C0DEull));
    __m128i nonce = _mm_set_epi64x(
        static_cast<long long>(enc->xor_mask),
        static_cast<long long>(prev_key));
    uint8_t tmp[256];
    memcpy(tmp, enc->blob, sizeof(session_data_t));
    aes_ctr_crypt(tmp, sizeof(session_data_t), crypt_key, nonce);
    memcpy(out, tmp, sizeof(session_data_t));
    SecureZeroMemory(tmp, sizeof(tmp));
    return true;
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

void store_device_enc(uint64_t crypt_key)
{
    uint64_t ptr = reinterpret_cast<uint64_t>(device.get());
    g_device_enc = ptr ^ crypt_key ^ _rotl64(crypt_key, 17) ^ _rotr64(crypt_key, 11);
}

voyager::device_t* get_device_enc(uint64_t crypt_key)
{
    uint64_t enc = g_device_enc;
    if (enc == 0) return nullptr;
    return reinterpret_cast<voyager::device_t*>(enc ^ crypt_key ^ _rotl64(crypt_key, 17) ^ _rotr64(crypt_key, 11));
}

void poison_vtable_key()
{
    uint64_t noise = __rdtsc() ^ 0xDEADBEEFCAFEBABEULL;
    g_vtable_crypt_key ^= _rotl64(noise, static_cast<int>(noise & 0x3F));
    g_corruption.poison_seed.store(noise, std::memory_order_relaxed);
}

void arm_silent_kill()
{
    if (g_corruption.armed.exchange(true))
        return;
    __fastfail(FAST_FAIL_FATAL_APP_EXIT);
}

void tick_corruption()
{
    if (!g_corruption.armed.load(std::memory_order_acquire))
        return;
    __fastfail(FAST_FAIL_FATAL_APP_EXIT);
}

bool check_debugger()
{
    auto* peb = reinterpret_cast<const uint8_t*>(__readgsqword(0x60));
    if (!peb) return false;

    if (peb[2] != 0)
        return true;

    uint32_t flags = *reinterpret_cast<const uint32_t*>(peb + 0xBC);
    if (flags & 0x70)
        return true;

    unsigned int aux;
    uint64_t t0 = __rdtscp(&aux);
    volatile int dummy = 0;
    for (int i = 0; i < 100; ++i) dummy += i;
    uint64_t t1 = __rdtscp(&aux);
    if ((t1 - t0) > 10000000ULL)
        return true;

    auto* kuser = reinterpret_cast<const volatile uint8_t*>(
        reinterpret_cast<void*>(static_cast<uintptr_t>(0x7FFE0000)));
    if (kuser[0x2D4] != 0)
        return true;

    CONTEXT ctx{};
    ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
    using NtGetContextThread_t = LONG(NTAPI*)(HANDLE, PCONTEXT);
    auto ntdll_hw = PEB_MOD(L"ntdll.dll");
    auto pNtGetCtx = reinterpret_cast<NtGetContextThread_t>(
        PEB_FN(ntdll_hw, "NtGetContextThread"));
    if (pNtGetCtx && pNtGetCtx(reinterpret_cast<HANDLE>((LONG_PTR)-2), &ctx) == 0)
    {
        if (ctx.Dr0 | ctx.Dr1 | ctx.Dr2 | ctx.Dr3)
            return true;
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
                return true;
        }
    }

    return false;
}

std::string recompute_hwid()
{
    uint64_t hash = 14695981039346656037ULL;
    auto mix = [&](uint64_t value) {
        hash ^= value;
        hash *= 1099511628211ULL;
    };

    using GetComputerNameW_t = BOOL(WINAPI*)(LPWSTR, LPDWORD);
    using GetVolumeInformationW_t = BOOL(WINAPI*)(LPCWSTR, LPWSTR, DWORD, LPDWORD, LPDWORD, LPDWORD, LPWSTR, DWORD);
    using RegOpenKeyExW_t = LONG(WINAPI*)(HKEY, LPCWSTR, DWORD, REGSAM, PHKEY);
    using RegQueryValueExW_t = LONG(WINAPI*)(HKEY, LPCWSTR, LPDWORD, LPDWORD, LPBYTE, LPDWORD);
    using RegCloseKey_t = LONG(WINAPI*)(HKEY);

    auto kernel32 = PEB_MOD(L"kernel32.dll");
    auto advapi32 = PEB_MOD(L"advapi32.dll");

    auto pGetComputerNameW = reinterpret_cast<GetComputerNameW_t>(
        PEB_FN(kernel32, "GetComputerNameW"));
    auto pGetVolumeInformationW = reinterpret_cast<GetVolumeInformationW_t>(
        PEB_FN(kernel32, "GetVolumeInformationW"));
    auto pRegOpenKeyExW = reinterpret_cast<RegOpenKeyExW_t>(
        PEB_FN(advapi32, "RegOpenKeyExW"));
    auto pRegQueryValueExW = reinterpret_cast<RegQueryValueExW_t>(
        PEB_FN(advapi32, "RegQueryValueExW"));
    auto pRegCloseKey = reinterpret_cast<RegCloseKey_t>(
        PEB_FN(advapi32, "RegCloseKey"));

    wchar_t computer_name[MAX_COMPUTERNAME_LENGTH + 1] = {};
    DWORD name_size = MAX_COMPUTERNAME_LENGTH + 1;
    if (pGetComputerNameW && pGetComputerNameW(computer_name, &name_size)) {
        for (DWORD i = 0; i < name_size; ++i)
            mix(static_cast<uint64_t>(computer_name[i]));
    } else {
        mix(0xDEADBEEF00000001ULL);
    }

    int cpu_info[4] = {};
    __cpuid(cpu_info, 1);
    mix((static_cast<uint64_t>(cpu_info[0]) << 32) | static_cast<unsigned>(cpu_info[1]));
    mix((static_cast<uint64_t>(cpu_info[2]) << 32) | static_cast<unsigned>(cpu_info[3]));

    DWORD volume_serial = 0;
    auto vol_path = WOBFSTR(L"C:\\");
    if (pGetVolumeInformationW &&
        pGetVolumeInformationW(vol_path.c_str(), nullptr, 0, &volume_serial, nullptr, nullptr, nullptr, 0)
        && volume_serial != 0) {
        mix(volume_serial);
    } else {
        mix(0xDEADBEEF00000002ULL);
    }

    bool got_guid = false;
    HKEY hKey = nullptr;
    auto reg_path = WOBFSTR(L"SOFTWARE\\Microsoft\\Cryptography");
    auto reg_value = WOBFSTR(L"MachineGuid");
    if (pRegOpenKeyExW && pRegQueryValueExW && pRegCloseKey &&
        pRegOpenKeyExW(HKEY_LOCAL_MACHINE, reg_path.c_str(),
            0, KEY_READ | KEY_WOW64_64KEY, &hKey) == ERROR_SUCCESS) {
        wchar_t guid[128] = {};
        DWORD size = sizeof(guid);
        DWORD type = 0;
        if (pRegQueryValueExW(hKey, reg_value.c_str(), nullptr, &type,
                reinterpret_cast<BYTE*>(guid), &size) == ERROR_SUCCESS
            && type == REG_SZ && guid[0] != L'\0') {
            for (size_t i = 0; guid[i] != L'\0'; ++i)
                mix(static_cast<uint64_t>(guid[i]));
            got_guid = true;
        }
        pRegCloseKey(hKey);
    }
    if (!got_guid)
        mix(0xDEADBEEF00000003ULL);

    char out[17];
    snprintf(out, sizeof(out), "%016llX", static_cast<unsigned long long>(hash));
    return out;
}

uint64_t compute_own_code_hash()
{
    MEMORY_BASIC_INFORMATION mbi = {};
    if (VirtualQuery(reinterpret_cast<const void*>(&compute_own_code_hash), &mbi, sizeof(mbi)) == 0)
        return 0;
    auto hMod = static_cast<HMODULE>(mbi.AllocationBase);
    if (!hMod) return 0;

    auto* dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(hMod);
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return 0;

    auto* nt = reinterpret_cast<const IMAGE_NT_HEADERS*>(
        reinterpret_cast<const uint8_t*>(hMod) + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) return 0;

    const auto* sec = IMAGE_FIRST_SECTION(nt);
    uint64_t combined = 0;
    for (WORD i = 0; i < nt->FileHeader.NumberOfSections; ++i) {
        if (sec[i].Characteristics & IMAGE_SCN_MEM_EXECUTE) {
            auto base = reinterpret_cast<uintptr_t>(hMod) + sec[i].VirtualAddress;
            size_t size = sec[i].Misc.VirtualSize;
            if (size > 0 && size < 64 * 1024 * 1024) {
                uint8_t buf[32];
                uint64_t h_val = fnv1a(reinterpret_cast<const void*>(base), size);
                memcpy(buf, &h_val, 8);
                memcpy(buf + 8, &base, 8);
                memcpy(buf + 16, &size, 8);
                memset(buf + 24, 0, 8);
                combined ^= siphash_2_4(buf, 32, 0xA1DAC0DE5EC0DEULL, 0xCAFEBABEDEADFEEDULL);
            }
        }
    }
    return combined;
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
        tick_corruption();
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
    if (check_debugger()) { arm_silent_kill(); return true; }
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
    if (check_debugger()) { arm_silent_kill(); return 0; }
    if (!verify_vtable()) { arm_silent_kill(); return 0; }
    if (!buffer || size == 0) return 0;
    auto* dev = get_device_enc(g_vtable_crypt_key);
    if (!dev) return 0;
    return dev->read_raw(address, buffer, size);
}

size_t vtable_write_raw(uint64_t address, const void* buffer, size_t size)
{
    if (!is_session_valid()) return 0;
    if (check_debugger()) { arm_silent_kill(); return 0; }
    if (!verify_vtable()) { arm_silent_kill(); return 0; }
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
    if (!is_session_valid() || check_debugger() || !verify_vtable()) { arm_silent_kill(); return 0; }
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

ARC_API bool arc_init(
    const char*  session_token,
    const char*  hwid,
    int64_t      timestamp,
    uint32_t     interface_version)
{
    using namespace arc_internal;

    bool result = false;
    uint64_t local_hwid_hash_capture = 0;

    CFF_BEGIN(arc_init_cff)
    CFF_STATE(arc_init_cff, 0)
    {
        if (interface_version != ARC_INTERFACE_VERSION)
        {
            CFF_EXIT(arc_init_cff);
        }
        if (!session_token || !hwid)
        {
            CFF_EXIT(arc_init_cff);
        }
        CFF_GOTO(arc_init_cff, 1);
    }
    CFF_STATE(arc_init_cff, 1)
    {
        size_t token_len = strlen(session_token);
        if (token_len < 32 || token_len > 128)
        {
            CFF_EXIT(arc_init_cff);
        }
        size_t hwid_len = strlen(hwid);
        if (hwid_len < 8 || hwid_len > 64)
        {
            CFF_EXIT(arc_init_cff);
        }
        CFF_GOTO(arc_init_cff, 2);
    }
    CFF_STATE(arc_init_cff, 2)
    {
        if (check_debugger())
        {
            arm_silent_kill();
            CFF_EXIT(arc_init_cff);
        }
        CFF_GOTO(arc_init_cff, 3);
    }
    CFF_STATE(arc_init_cff, 3)
    {
        std::string local_hwid = recompute_hwid();
        uint64_t local_hash = fnv1a_str(local_hwid.c_str());
        uint64_t provided_hash = fnv1a_str(hwid);
        local_hwid_hash_capture = local_hash;

        if (local_hash != provided_hash)
        {
            arm_silent_kill();
            result = true;
            CFF_EXIT(arc_init_cff);
        }
        CFF_GOTO(arc_init_cff, 4);
    }
    CFF_STATE(arc_init_cff, 4)
    {
        int64_t now = static_cast<int64_t>(time(nullptr));
        int64_t drift = now - timestamp;
        if (drift < -300 || drift > 300)
        {
            CFF_EXIT(arc_init_cff);
        }
        CFF_GOTO(arc_init_cff, 5);
    }
    CFF_STATE(arc_init_cff, 5)
    {
        std::lock_guard<std::mutex> lk(g_session_mtx);

        session_data_t sess = {};

        uint64_t tsc = __rdtsc();
        sess.xor_key = tsc ^ 0xA1DA'CAFE'BABE'C0DEull;
        sess.session_hash   = fnv1a_str(session_token);
        sess.hwid_hash      = fnv1a_str(hwid);
        sess.local_hwid_hash = local_hwid_hash_capture;
        sess.init_timestamp = static_cast<uint64_t>(timestamp);
        sess.heartbeat_counter = 0;
        sess.last_heartbeat_tsc = __rdtsc();

        uint64_t key_material = local_hwid_hash_capture ^ sess.session_hash ^ tsc;
        uint8_t kb[16];
        memcpy(kb, &key_material, 8);
        uint64_t km2 = key_material ^ 0x6A09E667F3BCC908ULL;
        memcpy(kb + 8, &km2, 8);
        sess.vtable_crypt_key = siphash_2_4(kb, 16, local_hwid_hash_capture, sess.session_hash);

        strncpy_s(sess.session_token, session_token, _TRUNCATE);
        strncpy_s(sess.hwid, hwid, _TRUNCATE);
        sess.license_key[0] = '\0';

        sess.code_hash = compute_own_code_hash();
        sess.initialized = true;

        store_session(sess);
        init_vtable(sess.vtable_crypt_key);
        SecureZeroMemory(&sess, sizeof(sess));

        result = true;
        CFF_EXIT(arc_init_cff);
    }
    CFF_END(arc_init_cff)

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
            arm_silent_kill();
            CFF_EXIT(validate_cff);
        }
        CFF_GOTO(validate_cff, 3);
    }
    CFF_STATE(validate_cff, 3)
    {
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
        out = siphash_2_4(buf, 40, sess.hwid_hash, sess.session_hash);

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
        uint64_t current_hash = compute_own_code_hash();
        std::lock_guard<std::mutex> lk(g_session_mtx);
        session_data_t sess = {};
        if (!load_session(sess))
        {
            CFF_EXIT(hb_cff);
        }

        if (sess.code_hash != 0 && current_hash != sess.code_hash)
        {
            arm_silent_kill();
            CFF_EXIT(hb_cff);
        }
        CFF_GOTO(hb_cff, 2);
    }
    CFF_STATE(hb_cff, 2)
    {
        if (check_debugger())
        {
            arm_silent_kill();
            CFF_EXIT(hb_cff);
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

        uint64_t current_tsc = __rdtsc();
        if (current_tsc < sess.last_heartbeat_tsc)
        {
            arm_silent_kill();
            CFF_EXIT(hb_cff);
        }
        sess.last_heartbeat_tsc = current_tsc;
        sess.heartbeat_counter++;

        uint8_t proof_data[48];
        memcpy(proof_data, &sess.session_hash, 8);
        memcpy(proof_data + 8, &sess.hwid_hash, 8);
        memcpy(proof_data + 16, &sess.heartbeat_counter, 8);
        memcpy(proof_data + 24, &sess.code_hash, 8);
        memcpy(proof_data + 32, &current_tsc, 8);
        memcpy(proof_data + 40, &sess.vtable_crypt_key, 8);

        hb_result.proof_token = siphash_2_4(proof_data, 48,
            sess.hwid_hash ^ 0xBB67AE8584CAA73BULL,
            sess.session_hash ^ 0x3C6EF372FE94F82BULL);
        hb_result.timestamp = static_cast<uint64_t>(time(nullptr));
        hb_result.valid = true;

        store_session(sess);
        SecureZeroMemory(&sess, sizeof(sess));
        CFF_EXIT(hb_cff);
    }
    CFF_END(hb_cff)

    return hb_result;
}

namespace {
    static constexpr uint32_t ARC_PAGE_SIZE = 4096;

    std::string http_post_json(const char* url, const char* json_body)
    {
        using namespace arc_internal;
        std::string result_str;
        if (!url || !json_body) return result_str;
        if (!g_winhttp.resolve()) return result_str;

        URL_COMPONENTSW uc = {};
        uc.dwStructSize = sizeof(uc);
        wchar_t host[256] = {}, path[1024] = {};
        uc.lpszHostName    = host;
        uc.dwHostNameLength= 256;
        uc.lpszUrlPath     = path;
        uc.dwUrlPathLength = 1024;

        int wlen = MultiByteToWideChar(CP_UTF8, 0, url, -1, nullptr, 0);
        std::vector<wchar_t> wurl(wlen);
        MultiByteToWideChar(CP_UTF8, 0, url, -1, wurl.data(), wlen);

        if (!g_winhttp.pCrackUrl(wurl.data(), 0, 0, &uc))
            return result_str;

        auto ua = WOBFSTR(L"Mozilla/5.0");
        HINTERNET hSession = g_winhttp.pOpen(ua.c_str(),
            WINHTTP_ACCESS_TYPE_DEFAULT_PROXY, nullptr, nullptr, 0);
        if (!hSession) return result_str;

        HINTERNET hConnect = g_winhttp.pConnect(hSession, host, uc.nPort, 0);
        if (!hConnect) { g_winhttp.pCloseHandle(hSession); return result_str; }

        DWORD flags = (uc.nScheme == INTERNET_SCHEME_HTTPS) ? WINHTTP_FLAG_SECURE : 0;
        auto post_verb = WOBFSTR(L"POST");
        HINTERNET hRequest = g_winhttp.pOpenRequest(hConnect, post_verb.c_str(), path,
            nullptr, WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES, flags);
        if (!hRequest) {
            g_winhttp.pCloseHandle(hConnect);
            g_winhttp.pCloseHandle(hSession);
            return result_str;
        }

        auto hdrs = WOBFSTR(L"Content-Type: application/json\r\n");
        DWORD body_len = static_cast<DWORD>(strlen(json_body));

        if (g_winhttp.pSendRequest(hRequest, hdrs.c_str(), (DWORD)-1L,
                const_cast<char*>(json_body), body_len, body_len, 0)
            && g_winhttp.pReceiveResponse(hRequest, nullptr))
        {
            DWORD bytes_available = 0;
            while (g_winhttp.pQueryDataAvailable(hRequest, &bytes_available) && bytes_available > 0) {
                std::vector<char> buf(bytes_available);
                DWORD bytes_read = 0;
                if (g_winhttp.pReadData(hRequest, buf.data(), bytes_available, &bytes_read))
                    result_str.append(buf.data(), bytes_read);
            }
        }

        g_winhttp.pCloseHandle(hRequest);
        g_winhttp.pCloseHandle(hConnect);
        g_winhttp.pCloseHandle(hSession);
        return result_str;
    }

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
        std::lock_guard<std::mutex> lk(g_session_mtx);
        session_data_t sess = {};
        if (!load_session(sess)) { SecureZeroMemory(out_key, 32); return; }

        uint8_t ks[32];
        bool have_seed = false;
        {
            std::lock_guard<std::mutex> lk2(g_key_seed_mtx);
            if (g_key_seed_valid)
            {
                memcpy(ks, g_key_seed, 32);
                have_seed = true;
            }
        }

        if (!have_seed)
        {
            SecureZeroMemory(out_key, 32);
            SecureZeroMemory(&sess, sizeof(sess));
            return;
        }

        std::string data = "page|" + std::to_string(page_index) + "|"
            + std::string(sess.session_token) + "|"
            + std::string(sess.hwid) + "|"
            + std::to_string(static_cast<int64_t>(sess.init_timestamp)) + "|";

        BCRYPT_ALG_HANDLE hAlg = nullptr;
        BCRYPT_HASH_HANDLE hHash = nullptr;

        NTSTATUS st = BCryptOpenAlgorithmProvider(
            &hAlg, BCRYPT_SHA256_ALGORITHM, nullptr, BCRYPT_ALG_HANDLE_HMAC_FLAG);

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
    }
}

ARC_API arc_page_result_t arc_request_page_count(const char* server_url)
{
    using namespace arc_internal;
    arc_page_result_t res{};
    if (!is_session_valid() || !server_url) return res;
    if (check_debugger()) { arm_silent_kill(); return res; }

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
    if (check_debugger()) { arm_silent_kill(); return false; }

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
    if (check_debugger()) { arm_silent_kill(); return false; }

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

}

BOOL WINAPI DllMain(HINSTANCE, DWORD reason, LPVOID)
{
    switch (reason) {
    case DLL_PROCESS_ATTACH:
        break;
    case DLL_PROCESS_DETACH:
        arc_cleanup();
        break;
    }
    return TRUE;
}
