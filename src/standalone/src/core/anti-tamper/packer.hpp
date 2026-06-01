#pragma once

#include <windows.h>
#include <intrin.h>
#include <nmmintrin.h>
#include <wmmintrin.h>

#include <atomic>
#include <algorithm>
#include <cstdio>
#include <cstdint>
#include <cstring>
#include <mutex>
#include <vector>

#include "obfuscation.hpp"
#include "key_pipeline.hpp"

namespace anti_tamper {
namespace packer {

namespace detail {

    inline uint64_t aes_material_salt_a()
    {
        static const uint64_t v = []() {
            uint8_t derived[8] = {};
            uint64_t out = 0;
            if (key_pipeline::derive(
                    "aida.packer.aes_material.a",
                    nullptr, 0, derived, sizeof(derived)))
            {
                std::memcpy(&out, derived, sizeof(out));
                SecureZeroMemory(derived, sizeof(derived));
            }
            return out;
        }();
        return v;
    }

    inline uint64_t aes_material_salt_b()
    {
        static const uint64_t v = []() {
            uint8_t derived[8] = {};
            uint64_t out = 0;
            if (key_pipeline::derive(
                    "aida.packer.aes_material.b",
                    nullptr, 0, derived, sizeof(derived)))
            {
                std::memcpy(&out, derived, sizeof(out));
                SecureZeroMemory(derived, sizeof(derived));
            }
            return out;
        }();
        return v;
    }

    inline uint64_t aes_material_salt_c()
    {
        static const uint64_t v = []() {
            uint8_t derived[8] = {};
            uint64_t out = 0;
            if (key_pipeline::derive(
                    "aida.packer.aes_material.c",
                    nullptr, 0, derived, sizeof(derived)))
            {
                std::memcpy(&out, derived, sizeof(out));
                SecureZeroMemory(derived, sizeof(derived));
            }
            return out;
        }();
        return v;
    }

    struct packed_section_t
    {
        uint64_t base;
        uint32_t size;
        __m128i  aes_key;
        __m128i  aes_nonce;
        uint64_t hmac;
        DWORD    original_protect;
        uint32_t original_crc;
        bool     decrypted;
    };

    struct import_redirect_t
    {
        uint64_t  original_iat_slot;
        uint64_t  trampoline_addr;
        uint64_t  real_target;
        uint32_t  obfuscation_key;
    };

    inline std::mutex& pack_mtx()
    {
        static std::mutex m;
        return m;
    }

    inline std::vector<packed_section_t>& sections()
    {
        static std::vector<packed_section_t> v;
        return v;
    }

    inline std::vector<import_redirect_t>& redirects()
    {
        static std::vector<import_redirect_t> v;
        return v;
    }

    inline std::atomic<bool>& initialized()
    {
        static std::atomic<bool> v{false};
        return v;
    }

    inline std::atomic<uint64_t>& unpack_start_tsc()
    {
        static std::atomic<uint64_t> v{0};
        return v;
    }

    inline uint64_t fnv1a_bytes(const void* data, size_t len)
    {
        uint64_t h = 14695981039346656037ULL;
        const auto* p = static_cast<const uint8_t*>(data);
        for (size_t i = 0; i < len; ++i)
        {
            h ^= p[i];
            h *= 1099511628211ULL;
        }
        return h;
    }

    inline uint64_t fnv1a_wstr(const wchar_t* s)
    {
        if (!s) return 0;
        uint64_t h = 14695981039346656037ULL;
        for (size_t i = 0; s[i]; ++i)
        {
            wchar_t c = s[i];
            h ^= static_cast<uint8_t>(c & 0xFF);
            h *= 1099511628211ULL;
            h ^= static_cast<uint8_t>((c >> 8) & 0xFF);
            h *= 1099511628211ULL;
        }
        return h;
    }

    inline void log_verify_event(const char* message)
    {
        char line[768];
        SYSTEMTIME st{};
        GetLocalTime(&st);
        _snprintf_s(line, sizeof(line), _TRUNCATE,
            "[%02u:%02u:%02u.%03u] [packer_verify] %s\r\n",
            static_cast<unsigned>(st.wHour),
            static_cast<unsigned>(st.wMinute),
            static_cast<unsigned>(st.wSecond),
            static_cast<unsigned>(st.wMilliseconds),
            message ? message : "event=<null>");

        char path[MAX_PATH];
        DWORD n = GetModuleFileNameA(nullptr, path, MAX_PATH);
        if (n != 0 && n < MAX_PATH)
        {
            char* slash = strrchr(path, '\\');
            if (slash)
            {
                slash[1] = '\0';
                strncat_s(path, MAX_PATH, "aida_debug.log", _TRUNCATE);
                HANDLE h = CreateFileA(path, FILE_APPEND_DATA, FILE_SHARE_READ | FILE_SHARE_WRITE,
                    nullptr, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
                if (h != INVALID_HANDLE_VALUE)
                {
                    DWORD wr = 0;
                    WriteFile(h, line, static_cast<DWORD>(strlen(line)), &wr, nullptr);
                    CloseHandle(h);
                }
            }
        }
        OutputDebugStringA(line);
    }

    template <typename... Args>
    inline void log_verify_event_fmt(const char* fmt, Args... args)
    {
        char buf[640];
        _snprintf_s(buf, sizeof(buf), _TRUNCATE, fmt, args...);
        log_verify_event(buf);
    }

    inline uint64_t derive_section_key(uint64_t section_base, uint32_t section_size, uint64_t master_seed)
    {
        uint64_t h = master_seed;
        h ^= section_base;
        h *= 0x9E3779B97F4A7C15ULL;
        h ^= h >> 27;
        h ^= static_cast<uint64_t>(section_size);
        h *= 0xBF58476D1CE4E5B9ULL;
        h ^= h >> 31;
        return h;
    }


    inline void derive_aes_material(uint64_t section_base, uint32_t section_size,
                                     uint64_t master_seed, __m128i& out_key, __m128i& out_nonce)
    {
        uint64_t h0 = derive_section_key(section_base, section_size, master_seed);
        uint64_t h1 = derive_section_key(section_base ^ aes_material_salt_a(), section_size, master_seed ^ h0);
        uint64_t n0 = derive_section_key(h0, section_size, h1 ^ aes_material_salt_b());
        uint64_t n1 = derive_section_key(h1, section_size, h0 ^ aes_material_salt_c());
        out_key   = _mm_set_epi64x(static_cast<long long>(h1), static_cast<long long>(h0));
        out_nonce = _mm_set_epi64x(static_cast<long long>(n1), static_cast<long long>(n0));
    }


    __forceinline __m128i aes_128_key_assist(__m128i temp1, __m128i temp2)
    {
        temp2 = _mm_shuffle_epi32(temp2, 0xFF);
        __m128i temp3 = _mm_slli_si128(temp1, 0x4);
        temp1 = _mm_xor_si128(temp1, temp3);
        temp3 = _mm_slli_si128(temp3, 0x4);
        temp1 = _mm_xor_si128(temp1, temp3);
        temp3 = _mm_slli_si128(temp3, 0x4);
        temp1 = _mm_xor_si128(temp1, temp3);
        return _mm_xor_si128(temp1, temp2);
    }


    inline void aes_128_expand_key(__m128i key, __m128i round_keys[11])
    {
        round_keys[0] = key;
        round_keys[1]  = aes_128_key_assist(round_keys[0],  _mm_aeskeygenassist_si128(round_keys[0],  0x01));
        round_keys[2]  = aes_128_key_assist(round_keys[1],  _mm_aeskeygenassist_si128(round_keys[1],  0x02));
        round_keys[3]  = aes_128_key_assist(round_keys[2],  _mm_aeskeygenassist_si128(round_keys[2],  0x04));
        round_keys[4]  = aes_128_key_assist(round_keys[3],  _mm_aeskeygenassist_si128(round_keys[3],  0x08));
        round_keys[5]  = aes_128_key_assist(round_keys[4],  _mm_aeskeygenassist_si128(round_keys[4],  0x10));
        round_keys[6]  = aes_128_key_assist(round_keys[5],  _mm_aeskeygenassist_si128(round_keys[5],  0x20));
        round_keys[7]  = aes_128_key_assist(round_keys[6],  _mm_aeskeygenassist_si128(round_keys[6],  0x40));
        round_keys[8]  = aes_128_key_assist(round_keys[7],  _mm_aeskeygenassist_si128(round_keys[7],  0x80));
        round_keys[9]  = aes_128_key_assist(round_keys[8],  _mm_aeskeygenassist_si128(round_keys[8],  0x1B));
        round_keys[10] = aes_128_key_assist(round_keys[9],  _mm_aeskeygenassist_si128(round_keys[9],  0x36));
    }


    __forceinline __m128i aes_encrypt_block(__m128i block, const __m128i round_keys[11])
    {
        block = _mm_xor_si128(block, round_keys[0]);
        block = _mm_aesenc_si128(block, round_keys[1]);
        block = _mm_aesenc_si128(block, round_keys[2]);
        block = _mm_aesenc_si128(block, round_keys[3]);
        block = _mm_aesenc_si128(block, round_keys[4]);
        block = _mm_aesenc_si128(block, round_keys[5]);
        block = _mm_aesenc_si128(block, round_keys[6]);
        block = _mm_aesenc_si128(block, round_keys[7]);
        block = _mm_aesenc_si128(block, round_keys[8]);
        block = _mm_aesenc_si128(block, round_keys[9]);
        block = _mm_aesenclast_si128(block, round_keys[10]);
        return block;
    }


    inline void aes_ctr_crypt_region(uint8_t* base, size_t size, __m128i key, __m128i nonce)
    {
        __m128i round_keys[11];
        aes_128_expand_key(key, round_keys);

        __m128i counter = nonce;
        const __m128i one = _mm_set_epi64x(0, 1);

        size_t full_blocks = size / 16;
        auto* blocks = reinterpret_cast<__m128i*>(base);

        for (size_t i = 0; i < full_blocks; ++i)
        {
            __m128i keystream = aes_encrypt_block(counter, round_keys);
            blocks[i] = _mm_xor_si128(blocks[i], keystream);
            counter = _mm_add_epi64(counter, one);
        }


        size_t tail_offset = full_blocks * 16;
        size_t tail_len = size - tail_offset;
        if (tail_len > 0)
        {
            __m128i keystream = aes_encrypt_block(counter, round_keys);
            alignas(16) uint8_t ks_bytes[16];
            _mm_store_si128(reinterpret_cast<__m128i*>(ks_bytes), keystream);
            for (size_t j = 0; j < tail_len; ++j)
                base[tail_offset + j] ^= ks_bytes[j];
        }


        SecureZeroMemory(round_keys, sizeof(round_keys));
    }


    inline uint64_t siphash_2_4(const uint8_t* data, size_t len, uint64_t k0, uint64_t k1)
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

        uint64_t last = static_cast<uint64_t>(len & 0xFF) << 56;
        const uint8_t* tail = data + blocks * 8;
        switch (len & 7)
        {
        case 7: last |= static_cast<uint64_t>(tail[6]) << 48; [[fallthrough]];
        case 6: last |= static_cast<uint64_t>(tail[5]) << 40; [[fallthrough]];
        case 5: last |= static_cast<uint64_t>(tail[4]) << 32; [[fallthrough]];
        case 4: last |= static_cast<uint64_t>(tail[3]) << 24; [[fallthrough]];
        case 3: last |= static_cast<uint64_t>(tail[2]) << 16; [[fallthrough]];
        case 2: last |= static_cast<uint64_t>(tail[1]) << 8;  [[fallthrough]];
        case 1: last |= static_cast<uint64_t>(tail[0]);        break;
        case 0: break;
        }

        v3 ^= last;
        sipround(); sipround();
        v0 ^= last;

        v2 ^= 0xFF;
        sipround(); sipround(); sipround(); sipround();

        return v0 ^ v1 ^ v2 ^ v3;
    }


    inline void xor_encrypt_region(uint8_t* base, size_t size, uint64_t key)
    {
        auto* qw = reinterpret_cast<uint64_t*>(base);
        size_t qw_count = size / 8;
        uint64_t rolling = key;
        for (size_t i = 0; i < qw_count; ++i) {
            qw[i] ^= rolling;
            rolling = _rotl64(rolling ^ qw[i], 13) * 0x9E3779B97F4A7C15ULL;
        }
        uint8_t* tail = base + (qw_count * 8);
        for (size_t i = 0; i < size % 8; ++i)
            tail[i] ^= static_cast<uint8_t>(rolling >> (i * 8));
    }

    inline uint32_t crc32_region(const void* data, size_t len)
    {
        uint32_t crc = 0xFFFFFFFF;
        auto* p = static_cast<const uint8_t*>(data);
        size_t i = 0;
        for (; i + 8 <= len; i += 8)
            crc = static_cast<uint32_t>(_mm_crc32_u64(crc, *reinterpret_cast<const uint64_t*>(p + i)));
        for (; i < len; ++i)
            crc = _mm_crc32_u8(crc, p[i]);
        return crc ^ 0xFFFFFFFF;
    }


    inline bool timing_check()
    {
        unsigned int aux;
        uint64_t t0 = __rdtscp(&aux);


        volatile uint64_t dummy = 0;
        for (int i = 0; i < 32; ++i)
            dummy ^= _rotl64(dummy + i, i & 63);

        uint64_t t1 = __rdtscp(&aux);
        uint64_t delta = t1 - t0;


        return delta < 5000;
    }


    inline bool constant_time_eq32(uint32_t a, uint32_t b)
    {
        volatile uint32_t diff = a ^ b;
        return diff == 0;
    }


    inline uint8_t* alloc_trampoline_page()
    {
        auto* page = static_cast<uint8_t*>(VirtualAlloc(
            nullptr, 4096, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE));
        if (page)
            memset(page, 0xCC, 4096);
        return page;
    }

    inline uint64_t build_trampoline(uint8_t*& cursor, uint64_t real_target, uint32_t obf_key)
    {
        uint64_t addr = reinterpret_cast<uint64_t>(cursor);


        uint64_t encoded = real_target ^ static_cast<uint64_t>(obf_key) * 0x100000001ULL;
        cursor[0] = 0x48; cursor[1] = 0xB8;
        memcpy(cursor + 2, &encoded, 8);
        cursor += 10;

        uint64_t key_expanded = static_cast<uint64_t>(obf_key) * 0x100000001ULL;
        cursor[0] = 0x49; cursor[1] = 0xBB;
        memcpy(cursor + 2, &key_expanded, 8);
        cursor += 10;

        cursor[0] = 0x4C; cursor[1] = 0x31; cursor[2] = 0xD8;
        cursor += 3;

        cursor[0] = 0xFF; cursor[1] = 0xE0;
        cursor += 2;


        while (reinterpret_cast<uintptr_t>(cursor) % 32 != 0) {
            *cursor++ = 0xCC;
        }

        return addr;
    }

}


inline bool encrypt_sections(uint64_t master_seed)
{
    if (detail::initialized().load())
        return false;

    HMODULE hMod = nullptr;
    MEMORY_BASIC_INFORMATION mbi = {};
    if (VirtualQuery(reinterpret_cast<const void*>(&encrypt_sections), &mbi, sizeof(mbi)) == 0)
        return false;
    hMod = static_cast<HMODULE>(mbi.AllocationBase);
    if (!hMod) return false;

    auto* dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(hMod);
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return false;
    auto* nt = reinterpret_cast<const IMAGE_NT_HEADERS*>(
        reinterpret_cast<const uint8_t*>(hMod) + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) return false;

    const auto* sec = IMAGE_FIRST_SECTION(nt);
    std::lock_guard<std::mutex> lk(detail::pack_mtx());

    for (WORD i = 0; i < nt->FileHeader.NumberOfSections; ++i)
    {
        if (!(sec[i].Characteristics & IMAGE_SCN_CNT_INITIALIZED_DATA))
            continue;
        if (sec[i].Characteristics & IMAGE_SCN_MEM_EXECUTE)
            continue;
        if (sec[i].Misc.VirtualSize < 64)
            continue;

        auto base = reinterpret_cast<uint64_t>(hMod) + sec[i].VirtualAddress;
        uint32_t size = sec[i].Misc.VirtualSize;


        __m128i aes_key, aes_nonce;
        detail::derive_aes_material(base, size, master_seed, aes_key, aes_nonce);

        uint32_t crc = detail::crc32_region(reinterpret_cast<const void*>(base), size);


        uint64_t hmac_k0 = detail::derive_section_key(base, size, master_seed);
        uint64_t hmac_k1 = detail::derive_section_key(base ^ 0xBADC0FFEE0DDF00DULL, size, master_seed);
        uint64_t hmac = detail::siphash_2_4(reinterpret_cast<const uint8_t*>(base), size, hmac_k0, hmac_k1);

        DWORD old_protect = 0;
        if (!VirtualProtect(reinterpret_cast<void*>(base), size, PAGE_READWRITE, &old_protect))
            continue;

        detail::aes_ctr_crypt_region(reinterpret_cast<uint8_t*>(base), size, aes_key, aes_nonce);

        DWORD dummy;
        VirtualProtect(reinterpret_cast<void*>(base), size, old_protect, &dummy);

        detail::packed_section_t entry{};
        entry.base             = base;
        entry.size             = size;
        entry.aes_key          = aes_key;
        entry.aes_nonce        = aes_nonce;
        entry.hmac             = hmac;
        entry.original_protect = old_protect;
        entry.original_crc     = crc;
        entry.decrypted        = false;

        detail::sections().push_back(entry);
    }

    detail::initialized().store(true);
    return !detail::sections().empty();
}


inline bool decrypt_section(uint32_t index)
{
    if (!detail::initialized().load())
        return false;

    std::lock_guard<std::mutex> lk(detail::pack_mtx());

    if (index >= detail::sections().size())
        return false;

    auto& sec = detail::sections()[index];
    if (sec.decrypted)
        return true;


    if (!detail::timing_check())
        return false;

    detail::unpack_start_tsc().store(__rdtsc());

    DWORD old_protect = 0;
    if (!VirtualProtect(reinterpret_cast<void*>(sec.base), sec.size, PAGE_READWRITE, &old_protect))
        return false;

    detail::aes_ctr_crypt_region(reinterpret_cast<uint8_t*>(sec.base), sec.size, sec.aes_key, sec.aes_nonce);

    DWORD dummy;
    VirtualProtect(reinterpret_cast<void*>(sec.base), sec.size, sec.original_protect, &dummy);


    uint32_t check = detail::crc32_region(reinterpret_cast<const void*>(sec.base), sec.size);
    if (!detail::constant_time_eq32(check, sec.original_crc))
    {

        VirtualProtect(reinterpret_cast<void*>(sec.base), sec.size, PAGE_READWRITE, &old_protect);
        detail::aes_ctr_crypt_region(reinterpret_cast<uint8_t*>(sec.base), sec.size, sec.aes_key, sec.aes_nonce);
        VirtualProtect(reinterpret_cast<void*>(sec.base), sec.size, sec.original_protect, &dummy);
        return false;
    }


    uint64_t hmac_k0 = detail::derive_section_key(sec.base, sec.size, 0);
    uint64_t hmac_k1 = detail::derive_section_key(sec.base ^ 0xBADC0FFEE0DDF00DULL, sec.size, 0);
    uint64_t check_hmac = detail::siphash_2_4(reinterpret_cast<const uint8_t*>(sec.base), sec.size, hmac_k0, hmac_k1);
    if (check_hmac != sec.hmac)
    {

        VirtualProtect(reinterpret_cast<void*>(sec.base), sec.size, PAGE_READWRITE, &old_protect);
        detail::aes_ctr_crypt_region(reinterpret_cast<uint8_t*>(sec.base), sec.size, sec.aes_key, sec.aes_nonce);
        VirtualProtect(reinterpret_cast<void*>(sec.base), sec.size, sec.original_protect, &dummy);
        return false;
    }

    sec.decrypted = true;
    return true;
}


inline bool decrypt_all_sections()
{
    if (!detail::initialized().load())
        return false;


    if (!detail::timing_check())
        return false;

    std::lock_guard<std::mutex> lk(detail::pack_mtx());

    for (uint32_t i = 0; i < detail::sections().size(); ++i)
    {
        auto& sec = detail::sections()[i];
        if (sec.decrypted) continue;

        DWORD old_protect = 0;
        if (!VirtualProtect(reinterpret_cast<void*>(sec.base), sec.size, PAGE_READWRITE, &old_protect))
            return false;

        detail::aes_ctr_crypt_region(reinterpret_cast<uint8_t*>(sec.base), sec.size, sec.aes_key, sec.aes_nonce);

        DWORD dummy;
        VirtualProtect(reinterpret_cast<void*>(sec.base), sec.size, sec.original_protect, &dummy);

        uint32_t check = detail::crc32_region(reinterpret_cast<const void*>(sec.base), sec.size);
        if (!detail::constant_time_eq32(check, sec.original_crc))
            return false;

        sec.decrypted = true;
    }

    return true;
}


inline bool obfuscate_imports(uint32_t obf_seed)
{
    HMODULE hMod = nullptr;
    MEMORY_BASIC_INFORMATION mbi = {};
    if (VirtualQuery(reinterpret_cast<const void*>(&obfuscate_imports), &mbi, sizeof(mbi)) == 0)
        return false;
    hMod = static_cast<HMODULE>(mbi.AllocationBase);
    if (!hMod) return false;

    auto* dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(hMod);
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return false;
    auto* nt = reinterpret_cast<const IMAGE_NT_HEADERS*>(
        reinterpret_cast<const uint8_t*>(hMod) + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) return false;

    auto& import_dir = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
    if (import_dir.VirtualAddress == 0 || import_dir.Size == 0)
        return true;

    auto base = reinterpret_cast<uintptr_t>(hMod);
    auto* desc = reinterpret_cast<IMAGE_IMPORT_DESCRIPTOR*>(base + import_dir.VirtualAddress);

    uint8_t* trampoline_page = detail::alloc_trampoline_page();
    if (!trampoline_page) return false;

    uint8_t* cursor = trampoline_page;
    uint32_t key = obf_seed;
    uint32_t redirect_count = 0;

    std::lock_guard<std::mutex> lk(detail::pack_mtx());

    for (; desc->Name != 0; ++desc)
    {
        auto* thunk = reinterpret_cast<uint64_t*>(base + desc->FirstThunk);

        for (; *thunk != 0; ++thunk)
        {

            key = _mm_crc32_u32(key, static_cast<uint32_t>(reinterpret_cast<uintptr_t>(thunk)));

            uint64_t real_target = *thunk;


            if (cursor + 32 > trampoline_page + 4096)
            {

                trampoline_page = detail::alloc_trampoline_page();
                if (!trampoline_page) break;
                cursor = trampoline_page;
            }

            uint64_t tramp = detail::build_trampoline(cursor, real_target, key);


            DWORD old_prot = 0;
            if (VirtualProtect(thunk, 8, PAGE_READWRITE, &old_prot))
            {
                *thunk = tramp;
                DWORD dummy;
                VirtualProtect(thunk, 8, old_prot, &dummy);

                detail::import_redirect_t redir{};
                redir.original_iat_slot = reinterpret_cast<uint64_t>(thunk);
                redir.trampoline_addr   = tramp;
                redir.real_target       = real_target;
                redir.obfuscation_key   = key;
                detail::redirects().push_back(redir);
                ++redirect_count;
            }
        }
    }

    return redirect_count > 0;
}


inline bool verify_unpack_timing()
{
    uint64_t start = detail::unpack_start_tsc().load();
    if (start == 0) return true;

    unsigned int aux;
    uint64_t now = __rdtscp(&aux);
    uint64_t elapsed = now - start;


    return elapsed < 150'000'000ULL;
}

struct build_protection_status_t
{
    bool packed_found = false;
    bool packed_version_ok = false;
    bool packed_has_imports = false;
    bool aux_found = false;
    bool dseal_found = false;
    bool dthunk_found = false;
    uint32_t section_count = 0;
    uint32_t import_count = 0;
    uint32_t string_fixup_count = 0;
    uint32_t resource_fixup_count = 0;
    uint32_t phase_flags = 0;
    uint32_t stolen_block_count = 0;
    uint32_t packed_header_offset = 0;
    uint32_t packed_section_rva = 0;
    uint32_t packed_section_size = 0;
    uint32_t header_scan_size = 0;
    uint32_t aux_offset = 0;
    uint32_t aux_size = 0;
    uint32_t aux_probe_error = 0;
    bool disk_backed = false;
    uint32_t failure_stage = 0;
    uint32_t last_error = 0;
    uint32_t exception_code = 0;
    uint32_t live_dos_magic = 0;
    uint32_t live_e_lfanew = 0;
    uint32_t live_nt_signature = 0;
    uint32_t live_section_count = 0;
    uint32_t live_image_size = 0;
    uint32_t live_sections_scanned = 0;
    uint32_t disk_dos_magic = 0;
    uint32_t disk_e_lfanew = 0;
    uint32_t disk_nt_signature = 0;
    uint32_t disk_section_count = 0;
    uint32_t disk_image_size = 0;
    uint64_t disk_path_hash = 0;
    uint32_t disk_path_len = 0;
    uint64_t disk_file_size = 0;
    uint32_t disk_candidate_count = 0;
    uint32_t disk_sections_scanned = 0;
    uint32_t last_section_index = 0;
    uint32_t last_raw_ptr = 0;
    uint32_t last_raw_size = 0;
    uint32_t last_scan_offset = 0;
    bool verifier_module_is_process_image = false;
};

inline bool verify_build_protection(build_protection_status_t& out)
{
    out = {};
    detail::log_verify_event("entry");
    HMODULE hMod = nullptr;
    MEMORY_BASIC_INFORMATION mbi = {};
    if (VirtualQuery(reinterpret_cast<const void*>(&verify_build_protection), &mbi, sizeof(mbi)) == 0)
    {
        out.failure_stage = 1;
        out.last_error = GetLastError();
        detail::log_verify_event_fmt("fail=virtualquery gle=%lu", static_cast<unsigned long>(out.last_error));
        return false;
    }
    HMODULE verifier_mod = static_cast<HMODULE>(mbi.AllocationBase);
    HMODULE process_mod = GetModuleHandleW(nullptr);
    out.verifier_module_is_process_image = verifier_mod != nullptr && verifier_mod == process_mod;
    hMod = process_mod;
    if (!verifier_mod || !hMod)
    {
        out.failure_stage = 2;
        out.last_error = GetLastError();
        detail::log_verify_event_fmt("fail=null_module verifier_base=%p process_base=%p protect=0x%lX state=0x%lX type=0x%lX",
            mbi.AllocationBase,
            process_mod,
            static_cast<unsigned long>(mbi.Protect),
            static_cast<unsigned long>(mbi.State),
            static_cast<unsigned long>(mbi.Type));
        return false;
    }
    detail::log_verify_event_fmt("module verifier_base=%p process_base=%p same=%d protect=0x%lX state=0x%lX type=0x%lX",
        verifier_mod,
        hMod,
        out.verifier_module_is_process_image ? 1 : 0,
        static_cast<unsigned long>(mbi.Protect),
        static_cast<unsigned long>(mbi.State),
        static_cast<unsigned long>(mbi.Type));

    const auto* base = reinterpret_cast<const uint8_t*>(hMod);
    const IMAGE_NT_HEADERS* nt = nullptr;
    bool live_headers_ok = false;
    uint16_t live_dos_magic = 0;
    int32_t live_e_lfanew = 0;
    uint32_t live_nt_sig = 0;
    uint16_t live_sections = 0;
    uint32_t live_image_size = 0;
    __try
    {
        const auto* dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(base);
        live_dos_magic = dos->e_magic;
        live_e_lfanew = dos->e_lfanew;
        if (live_dos_magic == IMAGE_DOS_SIGNATURE &&
            live_e_lfanew >= 64 &&
            live_e_lfanew <= 0x10000)
        {
            nt = reinterpret_cast<const IMAGE_NT_HEADERS*>(base + live_e_lfanew);
            live_nt_sig = nt->Signature;
            if (live_nt_sig == IMAGE_NT_SIGNATURE)
            {
                live_headers_ok = true;
                live_sections = nt->FileHeader.NumberOfSections;
                live_image_size = nt->OptionalHeader.SizeOfImage;
            }
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        nt = nullptr;
        live_headers_ok = false;
        out.exception_code = GetExceptionCode();
        detail::log_verify_event_fmt("live_header_exception code=0x%08lX", static_cast<unsigned long>(out.exception_code));
    }
    out.live_dos_magic = live_dos_magic;
    out.live_e_lfanew = static_cast<uint32_t>(live_e_lfanew);
    out.live_nt_signature = live_nt_sig;
    out.live_section_count = live_sections;
    out.live_image_size = live_image_size;
    detail::log_verify_event_fmt("live_header ok=%d dos=0x%04X e_lfanew=0x%08X nt=0x%08X sections=%u image=0x%X",
        live_headers_ok ? 1 : 0,
        static_cast<unsigned>(live_dos_magic),
        static_cast<unsigned>(live_e_lfanew),
        live_nt_sig,
        static_cast<unsigned>(live_sections),
        live_image_size);

    constexpr uint32_t kPackedMagic = 0x41504B44u;
    constexpr uint32_t kPackedVersion = 0x00030000u;
    constexpr uint32_t kAuxMagic = 0x4D585541u;
    constexpr uint32_t kAuxVersion = 0x00030000u;

    struct packed_header_probe_t
    {
        uint32_t magic;
        uint32_t version;
        uint32_t section_count;
        uint32_t import_count;
        uint32_t string_fixup_count;
        uint32_t resource_fixup_count;
        uint32_t section_table_offset;
        uint32_t import_table_offset;
        uint32_t string_table_offset;
        uint32_t resource_table_offset;
        uint32_t master_key_offset;
        uint32_t stub_code_offset;
        uint32_t master_key_pe_timestamp;
        uint32_t master_key_pe_size_of_code;
        uint32_t bind_flags;
        uint32_t aux_offset;
        uint32_t aux_size;
        uint8_t bind_salt[16];
        uint32_t reserved[3];
    };

    struct aux_probe_t
    {
        uint32_t magic;
        uint32_t version;
        uint32_t spread_seed;
        uint32_t tamper_response_level;
        uint32_t bind_flags;
        uint32_t reserved0;
        uint8_t  watermark[16];
        uint8_t  watermark_hash[32];
        uint8_t  fingerprint_hash[32];
        uint8_t  bind_salt[16];
        uint32_t phase_flags;
        uint32_t stolen_block_count;
    };

    if (live_headers_ok && nt != nullptr)
    {
        const auto* sec = IMAGE_FIRST_SECTION(nt);
        for (WORD i = 0; i < nt->FileHeader.NumberOfSections; ++i)
        {
            out.live_sections_scanned = static_cast<uint32_t>(i) + 1u;
            out.last_section_index = static_cast<uint32_t>(i);
            char name[9] = {};
            std::memcpy(name, sec[i].Name, 8);
            if (std::strcmp(name, ".dseal") == 0) out.dseal_found = true;
            if (std::strcmp(name, ".dthunk") == 0) out.dthunk_found = true;

            const uint32_t image_size = nt->OptionalHeader.SizeOfImage;
            detail::log_verify_event_fmt("live_section i=%u name_hash=0x%016llX va=0x%X vsize=0x%X raw_size=0x%X raw_ptr=0x%X chars=0x%X",
                static_cast<unsigned>(i),
                static_cast<unsigned long long>(detail::fnv1a_bytes(name, strlen(name))),
                sec[i].VirtualAddress,
                sec[i].Misc.VirtualSize,
                sec[i].SizeOfRawData,
                sec[i].PointerToRawData,
                sec[i].Characteristics);
            if (sec[i].VirtualAddress >= image_size)
            {
                detail::log_verify_event_fmt("live_section_skip i=%u reason=va_out_of_image image=0x%X",
                    static_cast<unsigned>(i), image_size);
                continue;
            }
            const uint32_t max_mapped = image_size - sec[i].VirtualAddress;
            uint32_t vsize = sec[i].Misc.VirtualSize;
            if (vsize == 0 || vsize > max_mapped)
                vsize = max_mapped;
            const uint32_t header_scan_size = vsize < 0x20000u ? vsize : 0x20000u;
            if (header_scan_size < sizeof(packed_header_probe_t))
            {
                detail::log_verify_event_fmt("live_section_skip i=%u reason=scan_too_small scan=0x%X need=0x%zX",
                    static_cast<unsigned>(i), header_scan_size, sizeof(packed_header_probe_t));
                continue;
            }

            const uint8_t* sbase = base + sec[i].VirtualAddress;
            out.packed_section_rva = sec[i].VirtualAddress;
            out.packed_section_size = vsize;
            out.header_scan_size = header_scan_size;
            for (uint32_t off = 0; off + sizeof(packed_header_probe_t) <= header_scan_size; off += 8)
            {
                out.last_scan_offset = off;
                packed_header_probe_t hdr{};
                __try
                {
                    std::memcpy(&hdr, sbase + off, sizeof(hdr));
                }
                __except (EXCEPTION_EXECUTE_HANDLER)
                {
                    detail::log_verify_event_fmt("live_scan_exception i=%u off=0x%X code=0x%08lX",
                        static_cast<unsigned>(i), off, GetExceptionCode());
                    break;
                }

                if (hdr.magic != kPackedMagic)
                    continue;

                ++out.disk_candidate_count;
                detail::log_verify_event_fmt("live_packed_candidate i=%u off=0x%X version=0x%X sections=%u imports=%u strings=%u resources=%u aux_off=0x%X aux_size=0x%X",
                    static_cast<unsigned>(i),
                    off,
                    hdr.version,
                    hdr.section_count,
                    hdr.import_count,
                    hdr.string_fixup_count,
                    hdr.resource_fixup_count,
                    hdr.aux_offset,
                    hdr.aux_size);
                out.packed_found = true;
                out.packed_version_ok = hdr.version == kPackedVersion;
                out.section_count = hdr.section_count;
                out.import_count = hdr.import_count;
                out.packed_has_imports = hdr.import_count != 0;
                out.string_fixup_count = hdr.string_fixup_count;
                out.resource_fixup_count = hdr.resource_fixup_count;
                out.packed_header_offset = off;
                out.aux_offset = hdr.aux_offset;
                out.aux_size = hdr.aux_size;

                const uint64_t aux_rva_in_section = static_cast<uint64_t>(off) + hdr.aux_offset;
                if (hdr.aux_offset != 0 &&
                    hdr.aux_size >= sizeof(aux_probe_t) &&
                    aux_rva_in_section + sizeof(aux_probe_t) <= vsize)
                {
                    aux_probe_t aux{};
                    __try
                    {
                        std::memcpy(&aux, sbase + off + hdr.aux_offset, sizeof(aux));
                    }
                    __except (EXCEPTION_EXECUTE_HANDLER)
                    {
                        aux = {};
                        out.aux_probe_error = 4;
                        detail::log_verify_event_fmt("live_aux_exception i=%u off=0x%X aux_off=0x%X code=0x%08lX",
                            static_cast<unsigned>(i), off, hdr.aux_offset, GetExceptionCode());
                    }
                    out.aux_found = aux.magic == kAuxMagic && aux.version == kAuxVersion;
                    if (out.aux_found)
                    {
                        out.phase_flags = aux.phase_flags;
                        out.stolen_block_count = aux.stolen_block_count;
                        detail::log_verify_event_fmt("live_aux_ok phase=0x%X stolen=%u",
                            out.phase_flags, out.stolen_block_count);
                    }
                    else
                    {
                        out.aux_probe_error = 5;
                        detail::log_verify_event_fmt("live_aux_bad magic=0x%08X version=0x%08X",
                            aux.magic, aux.version);
                    }
                }
                else if (hdr.aux_offset == 0)
                {
                    out.aux_probe_error = 1;
                    detail::log_verify_event("live_aux_missing reason=zero_offset");
                }
                else if (hdr.aux_size < sizeof(aux_probe_t))
                {
                    out.aux_probe_error = 2;
                    detail::log_verify_event_fmt("live_aux_missing reason=size_small aux_size=0x%X need=0x%zX",
                        hdr.aux_size, sizeof(aux_probe_t));
                }
                else
                {
                    out.aux_probe_error = 3;
                    detail::log_verify_event_fmt("live_aux_missing reason=out_of_range off=0x%X aux_off=0x%X aux_size=0x%X vsize=0x%X",
                        off, hdr.aux_offset, hdr.aux_size, vsize);
                }

                const bool has_payload_tables =
                    out.packed_has_imports ||
                    out.string_fixup_count != 0 ||
                    out.resource_fixup_count != 0;
                const bool has_phase_protection = (out.phase_flags & 0x7Fu) != 0;
                const bool deep_declared = (out.phase_flags & 0x8u) != 0;
                const bool deep_materialized =
                    !deep_declared ||
                    (out.stolen_block_count != 0 && out.dseal_found && out.dthunk_found);
                const bool memory_ok = out.packed_version_ok &&
                    out.section_count != 0 &&
                    out.aux_found &&
                    (has_payload_tables || has_phase_protection) &&
                    deep_materialized;
                detail::log_verify_event_fmt("live_decision ok=%d version=%d sections=%u aux=%d payload=%d phase=%d deep_declared=%d deep_materialized=%d dseal=%d dthunk=%d",
                    memory_ok ? 1 : 0,
                    out.packed_version_ok ? 1 : 0,
                    out.section_count,
                    out.aux_found ? 1 : 0,
                    has_payload_tables ? 1 : 0,
                    has_phase_protection ? 1 : 0,
                    deep_declared ? 1 : 0,
                    deep_materialized ? 1 : 0,
                    out.dseal_found ? 1 : 0,
                    out.dthunk_found ? 1 : 0);
                if (memory_ok)
                {
                    detail::log_verify_event("success=live");
                    return true;
                }
                break;
            }
        }
    }

    constexpr DWORD kPathCapacity = 32768;
    wchar_t path[kPathCapacity] = {};
    DWORD path_len = GetModuleFileNameW(nullptr, path, kPathCapacity);
    if (path_len == 0 || path_len >= kPathCapacity)
    {
        out.last_error = GetLastError();
        DWORD query_len = kPathCapacity;
        std::memset(path, 0, sizeof(path));
        if (!QueryFullProcessImageNameW(GetCurrentProcess(), 0, path, &query_len) ||
            query_len == 0 ||
            query_len >= kPathCapacity)
        {
            out.failure_stage = 3;
            if (out.last_error == 0)
                out.last_error = GetLastError();
            detail::log_verify_event_fmt("fail=get_process_filename gle=%lu",
                static_cast<unsigned long>(out.last_error));
            return false;
        }
        path_len = query_len;
        path[path_len] = L'\0';
    }
    if (path_len == 0)
    {
        out.failure_stage = 3;
        out.last_error = GetLastError();
        detail::log_verify_event_fmt("fail=get_process_filename_empty gle=%lu", static_cast<unsigned long>(out.last_error));
        return false;
    }
    out.disk_path_len = static_cast<uint32_t>(path_len);
    out.disk_path_hash = detail::fnv1a_wstr(path);
    detail::log_verify_event_fmt("disk_path len=%lu hash=0x%016llX",
        static_cast<unsigned long>(out.disk_path_len),
        static_cast<unsigned long long>(out.disk_path_hash));

    HANDLE file = CreateFileW(path, GENERIC_READ,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (file == INVALID_HANDLE_VALUE)
    {
        out.failure_stage = 4;
        out.last_error = GetLastError();
        detail::log_verify_event_fmt("fail=open_disk gle=%lu", static_cast<unsigned long>(out.last_error));
        return false;
    }
    LARGE_INTEGER file_size{};
    if (GetFileSizeEx(file, &file_size))
    {
        out.disk_file_size = static_cast<uint64_t>(file_size.QuadPart);
        detail::log_verify_event_fmt("disk_file_open size_high=0x%lX size_low=0x%08lX",
            static_cast<unsigned long>(file_size.HighPart),
            static_cast<unsigned long>(file_size.LowPart));
    }
    else
    {
        out.last_error = GetLastError();
        detail::log_verify_event_fmt("disk_file_size_failed gle=%lu", static_cast<unsigned long>(out.last_error));
    }

    HANDLE mapping = CreateFileMappingW(file, nullptr, PAGE_READONLY, 0, 0, nullptr);
    if (!mapping)
    {
        out.failure_stage = 5;
        out.last_error = GetLastError();
        detail::log_verify_event_fmt("fail=create_mapping gle=%lu", static_cast<unsigned long>(out.last_error));
        CloseHandle(file);
        return false;
    }

    const auto* disk_base = static_cast<const uint8_t*>(
        MapViewOfFile(mapping, FILE_MAP_READ, 0, 0, 0));
    if (!disk_base)
    {
        out.failure_stage = 6;
        out.last_error = GetLastError();
        detail::log_verify_event_fmt("fail=map_view gle=%lu", static_cast<unsigned long>(out.last_error));
        CloseHandle(mapping);
        CloseHandle(file);
        return false;
    }

    bool disk_ok = false;
    build_protection_status_t disk_last = out;
    disk_last.disk_backed = true;
    __try
    {
        const auto* disk_dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(disk_base);
        disk_last.disk_dos_magic = static_cast<uint32_t>(disk_dos->e_magic);
        disk_last.disk_e_lfanew = static_cast<uint32_t>(disk_dos->e_lfanew);
        detail::log_verify_event_fmt("disk_dos magic=0x%04X e_lfanew=0x%08X",
            static_cast<unsigned>(disk_dos->e_magic),
            static_cast<unsigned>(disk_dos->e_lfanew));
        if (disk_dos->e_magic == IMAGE_DOS_SIGNATURE)
        {
            const auto* disk_nt = reinterpret_cast<const IMAGE_NT_HEADERS*>(disk_base + disk_dos->e_lfanew);
            disk_last.disk_nt_signature = disk_nt->Signature;
            disk_last.disk_section_count = disk_nt->FileHeader.NumberOfSections;
            disk_last.disk_image_size = disk_nt->OptionalHeader.SizeOfImage;
            detail::log_verify_event_fmt("disk_nt sig=0x%08X sections=%u image=0x%X opt=0x%X",
                disk_nt->Signature,
                static_cast<unsigned>(disk_nt->FileHeader.NumberOfSections),
                disk_nt->OptionalHeader.SizeOfImage,
                static_cast<unsigned>(disk_nt->OptionalHeader.Magic));
            if (disk_nt->Signature == IMAGE_NT_SIGNATURE)
            {
                build_protection_status_t disk_status = disk_last;
                disk_status.disk_backed = true;
                const auto* disk_sec = IMAGE_FIRST_SECTION(disk_nt);
                for (WORD i = 0; i < disk_nt->FileHeader.NumberOfSections; ++i)
                {
                    disk_status.disk_sections_scanned = static_cast<uint32_t>(i) + 1u;
                    disk_status.last_section_index = static_cast<uint32_t>(i);
                    char name[9] = {};
                    std::memcpy(name, disk_sec[i].Name, 8);
                    if (std::strcmp(name, ".dseal") == 0) disk_status.dseal_found = true;
                    if (std::strcmp(name, ".dthunk") == 0) disk_status.dthunk_found = true;
                    detail::log_verify_event_fmt("disk_section i=%u name_hash=0x%016llX va=0x%X vsize=0x%X raw=0x%X ptr=0x%X chars=0x%X",
                        static_cast<unsigned>(i),
                        static_cast<unsigned long long>(detail::fnv1a_bytes(name, strlen(name))),
                        disk_sec[i].VirtualAddress,
                        disk_sec[i].Misc.VirtualSize,
                        disk_sec[i].SizeOfRawData,
                        disk_sec[i].PointerToRawData,
                        disk_sec[i].Characteristics);
                }
                disk_last = disk_status;

                for (WORD i = 0; i < disk_nt->FileHeader.NumberOfSections && !disk_ok; ++i)
                {
                    disk_status.disk_sections_scanned = static_cast<uint32_t>(i) + 1u;
                    disk_status.last_section_index = static_cast<uint32_t>(i);
                    const uint32_t raw_ptr = disk_sec[i].PointerToRawData;
                    const uint32_t raw_size = disk_sec[i].SizeOfRawData;
                    disk_status.last_raw_ptr = raw_ptr;
                    disk_status.last_raw_size = raw_size;
                    disk_last = disk_status;
                    if (raw_ptr == 0 || raw_size < sizeof(packed_header_probe_t))
                    {
                        detail::log_verify_event_fmt("disk_section_skip i=%u reason=raw_too_small raw_ptr=0x%X raw_size=0x%X need=0x%zX",
                            static_cast<unsigned>(i), raw_ptr, raw_size, sizeof(packed_header_probe_t));
                        continue;
                    }
                    const uint32_t scan_size = (std::min)(raw_size, 0x40000u);
                    const uint8_t* sbase = disk_base + raw_ptr;
                    detail::log_verify_event_fmt("disk_scan_begin i=%u raw_ptr=0x%X raw_size=0x%X scan=0x%X",
                        static_cast<unsigned>(i), raw_ptr, raw_size, scan_size);
                    for (uint32_t off = 0; off + sizeof(packed_header_probe_t) <= scan_size; off += 8)
                    {
                        disk_status.last_scan_offset = off;
                        disk_last = disk_status;
                        packed_header_probe_t hdr{};
                        std::memcpy(&hdr, sbase + off, sizeof(hdr));
                        if (hdr.magic != kPackedMagic)
                            continue;

                        ++disk_status.disk_candidate_count;
                        detail::log_verify_event_fmt("disk_packed_candidate i=%u raw_off=0x%X abs=0x%X version=0x%X sections=%u imports=%u strings=%u resources=%u aux_off=0x%X aux_size=0x%X",
                            static_cast<unsigned>(i),
                            off,
                            raw_ptr + off,
                            hdr.version,
                            hdr.section_count,
                            hdr.import_count,
                            hdr.string_fixup_count,
                            hdr.resource_fixup_count,
                            hdr.aux_offset,
                            hdr.aux_size);
                        disk_status.packed_found = true;
                        disk_status.packed_version_ok = hdr.version == kPackedVersion;
                        disk_status.section_count = hdr.section_count;
                        disk_status.import_count = hdr.import_count;
                        disk_status.packed_has_imports = hdr.import_count != 0;
                        disk_status.string_fixup_count = hdr.string_fixup_count;
                        disk_status.resource_fixup_count = hdr.resource_fixup_count;
                        disk_status.packed_header_offset = raw_ptr + off;
                        disk_status.packed_section_rva = disk_sec[i].VirtualAddress;
                        disk_status.packed_section_size = raw_size;
                        disk_status.header_scan_size = scan_size;
                        disk_status.aux_offset = hdr.aux_offset;
                        disk_status.aux_size = hdr.aux_size;

                        if (hdr.aux_offset != 0 &&
                            hdr.aux_size >= sizeof(aux_probe_t) &&
                            off + hdr.aux_offset + sizeof(aux_probe_t) <= raw_size)
                        {
                            aux_probe_t aux{};
                            std::memcpy(&aux, sbase + off + hdr.aux_offset, sizeof(aux));
                            disk_status.aux_found = aux.magic == kAuxMagic && aux.version == kAuxVersion;
                            if (disk_status.aux_found)
                            {
                                disk_status.phase_flags = aux.phase_flags;
                                disk_status.stolen_block_count = aux.stolen_block_count;
                                detail::log_verify_event_fmt("disk_aux_ok phase=0x%X stolen=%u aux_abs=0x%X",
                                    disk_status.phase_flags,
                                    disk_status.stolen_block_count,
                                    raw_ptr + off + hdr.aux_offset);
                            }
                            else
                            {
                                disk_status.aux_probe_error = 5;
                                detail::log_verify_event_fmt("disk_aux_bad magic=0x%08X version=0x%08X aux_abs=0x%X",
                                    aux.magic, aux.version, raw_ptr + off + hdr.aux_offset);
                            }
                        }
                        else if (hdr.aux_offset == 0)
                        {
                            disk_status.aux_probe_error = 1;
                            detail::log_verify_event("disk_aux_missing reason=zero_offset");
                        }
                        else if (hdr.aux_size < sizeof(aux_probe_t))
                        {
                            disk_status.aux_probe_error = 2;
                            detail::log_verify_event_fmt("disk_aux_missing reason=size_small aux_size=0x%X need=0x%zX",
                                hdr.aux_size, sizeof(aux_probe_t));
                        }
                        else
                        {
                            disk_status.aux_probe_error = 3;
                            detail::log_verify_event_fmt("disk_aux_missing reason=out_of_range off=0x%X aux_off=0x%X aux_size=0x%X raw_size=0x%X",
                                off, hdr.aux_offset, hdr.aux_size, raw_size);
                        }

                        const bool has_payload_tables =
                            disk_status.packed_has_imports ||
                            disk_status.string_fixup_count != 0 ||
                            disk_status.resource_fixup_count != 0;
                        const bool has_phase_protection = (disk_status.phase_flags & 0x7Fu) != 0;
                        const bool deep_declared = (disk_status.phase_flags & 0x8u) != 0;
                        const bool deep_materialized =
                            !deep_declared ||
                            (disk_status.stolen_block_count != 0 &&
                             disk_status.dseal_found &&
                             disk_status.dthunk_found);
                        disk_ok = disk_status.packed_version_ok &&
                            disk_status.section_count != 0 &&
                            disk_status.aux_found &&
                            (has_payload_tables || has_phase_protection) &&
                            deep_materialized;
                        disk_last = disk_status;
                        detail::log_verify_event_fmt("disk_decision ok=%d version=%d sections=%u aux=%d payload=%d phase=%d deep_declared=%d deep_materialized=%d dseal=%d dthunk=%d phase_flags=0x%X stolen=%u",
                            disk_ok ? 1 : 0,
                            disk_status.packed_version_ok ? 1 : 0,
                            disk_status.section_count,
                            disk_status.aux_found ? 1 : 0,
                            has_payload_tables ? 1 : 0,
                            has_phase_protection ? 1 : 0,
                            deep_declared ? 1 : 0,
                            deep_materialized ? 1 : 0,
                            disk_status.dseal_found ? 1 : 0,
                            disk_status.dthunk_found ? 1 : 0,
                            disk_status.phase_flags,
                            disk_status.stolen_block_count);
                        if (disk_ok)
                            out = disk_status;
                        break;
                    }
                }
            }
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        disk_last.failure_stage = 7;
        disk_last.exception_code = GetExceptionCode();
        detail::log_verify_event_fmt("disk_exception code=0x%08lX", static_cast<unsigned long>(disk_last.exception_code));
        disk_ok = false;
    }

    UnmapViewOfFile(disk_base);
    CloseHandle(mapping);
    CloseHandle(file);
    if (disk_ok)
    {
        detail::log_verify_event("success=disk");
        return true;
    }

    out = disk_last;
    out.failure_stage = out.failure_stage != 0 ? out.failure_stage : 8;
    detail::log_verify_event_fmt("fail=no_valid_protection_status packed=%d version=%d sections=%u aux=%d payload_counts=%u/%u/%u dseal=%d dthunk=%d disk=%d aux_err=%u",
        out.packed_found ? 1 : 0,
        out.packed_version_ok ? 1 : 0,
        out.section_count,
        out.aux_found ? 1 : 0,
        out.import_count,
        out.string_fixup_count,
        out.resource_fixup_count,
        out.dseal_found ? 1 : 0,
        out.dthunk_found ? 1 : 0,
        out.disk_backed ? 1 : 0,
        out.aux_probe_error);
    return false;
}

inline uint32_t get_packed_section_count()
{
    std::lock_guard<std::mutex> lk(detail::pack_mtx());
    return static_cast<uint32_t>(detail::sections().size());
}

inline uint32_t get_redirect_count()
{
    std::lock_guard<std::mutex> lk(detail::pack_mtx());
    return static_cast<uint32_t>(detail::redirects().size());
}


inline void re_encrypt_all()
{
    std::lock_guard<std::mutex> lk(detail::pack_mtx());
    for (auto& sec : detail::sections())
    {
        if (!sec.decrypted) continue;

        DWORD old_protect = 0;
        if (VirtualProtect(reinterpret_cast<void*>(sec.base), sec.size, PAGE_READWRITE, &old_protect))
        {
            detail::aes_ctr_crypt_region(reinterpret_cast<uint8_t*>(sec.base), sec.size, sec.aes_key, sec.aes_nonce);
            DWORD dummy;
            VirtualProtect(reinterpret_cast<void*>(sec.base), sec.size, sec.original_protect, &dummy);
            sec.decrypted = false;
        }
    }
}

inline void shutdown()
{
    re_encrypt_all();
    std::lock_guard<std::mutex> lk(detail::pack_mtx());
    detail::sections().clear();
    detail::redirects().clear();
    detail::initialized().store(false);
}

}
}
