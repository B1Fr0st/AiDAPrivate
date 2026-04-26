#pragma once

#include <windows.h>
#include <intrin.h>
#include <nmmintrin.h>
#include <wmmintrin.h>

#include <atomic>
#include <cstdint>
#include <cstring>
#include <mutex>
#include <vector>

#include "obfuscation.hpp"

namespace anti_tamper {
namespace packer {

namespace detail {

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
        uint64_t h1 = derive_section_key(section_base ^ 0xCAFEBABEDEADBEEFULL, section_size, master_seed ^ h0);
        uint64_t n0 = derive_section_key(h0, section_size, h1 ^ 0x0123456789ABCDEFULL);
        uint64_t n1 = derive_section_key(h1, section_size, h0 ^ 0xFEDCBA9876543210ULL);
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
