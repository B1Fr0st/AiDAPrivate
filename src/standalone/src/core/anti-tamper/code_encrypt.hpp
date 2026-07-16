#pragma once

#include <windows.h>
#include <bcrypt.h>
#include <intrin.h>
#include <nmmintrin.h>
#include <wmmintrin.h>

#include <atomic>
#include <cstdint>
#include <cstring>
#include <mutex>
#include <vector>

#include "state.hpp"
#include "integrity.hpp"
#include "ghost_veh.hpp"
#include "token_chain.hpp"
#include "enforcement.hpp"

#pragma comment(lib, "bcrypt.lib")

namespace anti_tamper {
namespace code_encrypt {

namespace detail {

    struct encrypted_page_t
    {
        uint64_t base;
        uint32_t size;
        uint64_t key;
        uint64_t encrypt_tsc;
        bool use_aes;
        char section_name[16];
        DWORD original_protect;
    };

    inline std::mutex& page_mtx()
    {
        static std::mutex m;
        return m;
    }

    inline std::vector<encrypted_page_t>& encrypted_pages()
    {
        static std::vector<encrypted_page_t> v;
        return v;
    }

    inline std::atomic<bool>& active()
    {
        static std::atomic<bool> a{false};
        return a;
    }

    inline uint8_t (&session_prk())[32]
    {
        static uint8_t prk[32] = {};
        return prk;
    }

    struct eop_trampoline_t
    {
        uint64_t trigger_addr;
        uint64_t target_addr;
        uint64_t decrypt_key;
        uint32_t target_size;
        uint8_t  exception_type;
        bool     armed;
    };

    inline std::vector<eop_trampoline_t>& eop_trampolines()
    {
        static std::vector<eop_trampoline_t> v;
        return v;
    }

    enum eop_exception_type : uint8_t
    {
        EOP_INT2D = 0,
        EOP_DIV_ZERO = 1,
        EOP_INT3 = 2,
        EOP_PRIV_INSN = 3,
    };

    inline void install_int2d_trigger(uint8_t* addr)
    {
        DWORD old;
        VirtualProtect(addr, 2, PAGE_EXECUTE_READWRITE, &old);
        addr[0] = 0xCD;
        addr[1] = 0x2D;
        VirtualProtect(addr, 2, old, &old);
        FlushInstructionCache(GetCurrentProcess(), addr, 2);
    }

    inline void install_div_zero_trigger(uint8_t* addr)
    {
        DWORD old;
        VirtualProtect(addr, 6, PAGE_EXECUTE_READWRITE, &old);
        addr[0] = 0x48; addr[1] = 0x31; addr[2] = 0xC9;
        addr[3] = 0x48; addr[4] = 0xF7; addr[5] = 0xF1;
        VirtualProtect(addr, 6, old, &old);
        FlushInstructionCache(GetCurrentProcess(), addr, 6);
    }

    inline bool hkdf_hmac_sha256(const uint8_t* key, uint32_t key_len,
                                  const uint8_t* data, uint32_t data_len,
                                  uint8_t out[32])
    {
        BCRYPT_ALG_HANDLE hAlg = nullptr;
        BCRYPT_HASH_HANDLE hHash = nullptr;
        bool ok = false;
        if (BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_SHA256_ALGORITHM,
                                        nullptr, BCRYPT_ALG_HANDLE_HMAC_FLAG) != 0)
            return false;
        if (BCryptCreateHash(hAlg, &hHash, nullptr, 0,
                             const_cast<PUCHAR>(key), key_len, 0) != 0)
        {
            BCryptCloseAlgorithmProvider(hAlg, 0);
            return false;
        }
        if (BCryptHashData(hHash, const_cast<PUCHAR>(data), data_len, 0) == 0)
            ok = (BCryptFinishHash(hHash, out, 32, 0) == 0);
        BCryptDestroyHash(hHash);
        BCryptCloseAlgorithmProvider(hAlg, 0);
        return ok;
    }

    inline void hkdf_expand(const uint8_t prk[32], const uint8_t* info,
                             uint32_t info_len, uint8_t* okm, uint32_t okm_len)
    {
        uint8_t t[32] = {};
        uint32_t t_len = 0;
        uint8_t counter = 1;
        uint32_t pos = 0;
        while (pos < okm_len)
        {
            uint32_t input_len = t_len + info_len + 1;
            auto* input = static_cast<uint8_t*>(_alloca(input_len));
            if (t_len > 0) memcpy(input, t, t_len);
            memcpy(input + t_len, info, info_len);
            input[t_len + info_len] = counter;
            hkdf_hmac_sha256(prk, 32, input, input_len, t);
            t_len = 32;
            uint32_t copy = (okm_len - pos < 32) ? (okm_len - pos) : 32;
            memcpy(okm + pos, t, copy);
            pos += copy;
            counter++;
        }
    }

    inline uint64_t derive_section_key(const char* section_name, const uint8_t prk[32])
    {
        const char label[] = "code_encrypt|section|";
        size_t name_len = strlen(section_name);
        uint32_t info_len = static_cast<uint32_t>(sizeof(label) - 1 + name_len);
        auto* info = static_cast<uint8_t*>(_alloca(info_len));
        memcpy(info, label, sizeof(label) - 1);
        memcpy(info + sizeof(label) - 1, section_name, name_len);

        uint8_t derived[8];
        hkdf_expand(prk, info, info_len, derived, 8);

        uint64_t key;
        memcpy(&key, derived, 8);
        return key;
    }

    inline uint64_t derive_page_key(uint64_t page_addr, uint64_t section_key,
                                     uint64_t tsc_value, const uint8_t prk[32])
    {
        const char label[] = "code_encrypt|page|";
        uint8_t info[sizeof(label) - 1 + 24];
        memcpy(info, label, sizeof(label) - 1);
        memcpy(info + sizeof(label) - 1, &page_addr, 8);
        memcpy(info + sizeof(label) - 1 + 8, &section_key, 8);
        memcpy(info + sizeof(label) - 1 + 16, &tsc_value, 8);

        uint8_t derived[8];
        hkdf_expand(prk, info, static_cast<uint32_t>(sizeof(info)), derived, 8);

        uint64_t key;
        memcpy(&key, derived, 8);
        return key;
    }

    inline void derive_page_aes_material(uint64_t page_addr, uint64_t section_key,
                                          uint64_t tsc_value, const uint8_t prk[32],
                                          __m128i& out_key, __m128i& out_nonce)
    {
        const char label[] = "code_encrypt|page|";
        uint8_t info[sizeof(label) - 1 + 24];
        memcpy(info, label, sizeof(label) - 1);
        memcpy(info + sizeof(label) - 1, &page_addr, 8);
        memcpy(info + sizeof(label) - 1 + 8, &section_key, 8);
        memcpy(info + sizeof(label) - 1 + 16, &tsc_value, 8);

        uint8_t derived[16];
        hkdf_expand(prk, info, static_cast<uint32_t>(sizeof(info)), derived, 16);
        out_key = _mm_loadu_si128(reinterpret_cast<const __m128i*>(derived));

        uint64_t nonce_parts[2] = { page_addr, tsc_value };
        out_nonce = _mm_loadu_si128(reinterpret_cast<const __m128i*>(nonce_parts));
    }

    inline void xor_region(uint8_t* data, uint32_t size, uint64_t key)
    {
        uint64_t rolling = key;
        auto* ptr64 = reinterpret_cast<uint64_t*>(data);
        uint32_t chunks = size / 8;

        for (uint32_t i = 0; i < chunks; ++i)
        {
            ptr64[i] ^= rolling;
            rolling = _rotl64(rolling ^ ptr64[i], 13) + 0x9E3779B97F4A7C15ULL;
        }

        uint32_t remaining = size % 8;
        uint8_t* tail = data + chunks * 8;
        for (uint32_t i = 0; i < remaining; ++i)
        {
            tail[i] ^= static_cast<uint8_t>(rolling >> (i * 8));
        }
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

    __forceinline uint8_t aes_compute_rcon(int round) {
        if (round <= 0) return 0;
        volatile uint64_t tsc = __rdtsc();
        volatile uint8_t noise = static_cast<uint8_t>(tsc & 0xFF);
        uint8_t r = 1;
        for (int j = 1; j < round; ++j) {
            uint8_t hi = r & 0x80u;
            r = static_cast<uint8_t>(r << 1);
            if (hi) r ^= 0x1Bu;
        }
        volatile uint8_t masked = r ^ noise;
        return static_cast<uint8_t>(masked ^ noise);
    }

    __forceinline __m128i aes_128_keygen_rcon(__m128i prev_key, int round) {
        uint8_t rcon = aes_compute_rcon(round);
        __m128i keygened = aes_128_key_assist(prev_key, _mm_aeskeygenassist_si128(prev_key, 0));
        return _mm_xor_si128(keygened, _mm_set1_epi32(static_cast<int>(rcon) << 24));
    }

    inline void aes_128_expand_key(__m128i key, __m128i round_keys[11])
    {
        round_keys[0] = key;
        round_keys[1]  = aes_128_keygen_rcon(round_keys[0], 1);
        round_keys[2]  = aes_128_keygen_rcon(round_keys[1], 2);
        round_keys[3]  = aes_128_keygen_rcon(round_keys[2], 3);
        round_keys[4]  = aes_128_keygen_rcon(round_keys[3], 4);
        round_keys[5]  = aes_128_keygen_rcon(round_keys[4], 5);
        round_keys[6]  = aes_128_keygen_rcon(round_keys[5], 6);
        round_keys[7]  = aes_128_keygen_rcon(round_keys[6], 7);
        round_keys[8]  = aes_128_keygen_rcon(round_keys[7], 8);
        round_keys[9]  = aes_128_keygen_rcon(round_keys[8], 9);
        round_keys[10] = aes_128_keygen_rcon(round_keys[9], 10);
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

    inline void aes_ctr_crypt_region(uint8_t* base, uint32_t size, __m128i key, __m128i nonce)
    {
        __m128i round_keys[11];
        aes_128_expand_key(key, round_keys);

        __m128i counter = nonce;
        const __m128i one = _mm_set_epi64x(0, 1);

        uint32_t full_blocks = size / 16;
        auto* blocks = reinterpret_cast<__m128i*>(base);

        for (uint32_t i = 0; i < full_blocks; ++i)
        {
            __m128i keystream = aes_encrypt_block(counter, round_keys);
            blocks[i] = _mm_xor_si128(blocks[i], keystream);
            counter = _mm_add_epi64(counter, one);
        }

        uint32_t tail_offset = full_blocks * 16;
        uint32_t tail_len = size - tail_offset;
        if (tail_len > 0)
        {
            __m128i keystream = aes_encrypt_block(counter, round_keys);
            alignas(16) uint8_t ks_bytes[16];
            _mm_store_si128(reinterpret_cast<__m128i*>(ks_bytes), keystream);
            for (uint32_t j = 0; j < tail_len; ++j)
                base[tail_offset + j] ^= ks_bytes[j];
        }

        SecureZeroMemory(round_keys, sizeof(round_keys));
    }

    inline void aes_ctr_crypt_region_offset(uint8_t* base, uint32_t size,
        __m128i key, __m128i nonce, uint32_t byte_offset)
    {
        __m128i round_keys[11];
        aes_128_expand_key(key, round_keys);

        uint32_t block_offset = byte_offset / 16;
        uint32_t byte_in_first = byte_offset % 16;

        __m128i counter = _mm_add_epi64(nonce, _mm_set_epi64x(0, static_cast<int64_t>(block_offset)));
        const __m128i one = _mm_set_epi64x(0, 1);

        uint32_t pos = 0;

        if (byte_in_first > 0 && size > 0)
        {
            __m128i keystream = aes_encrypt_block(counter, round_keys);
            alignas(16) uint8_t ks_bytes[16];
            _mm_store_si128(reinterpret_cast<__m128i*>(ks_bytes), keystream);
            uint32_t avail = 16 - byte_in_first;
            uint32_t copy = (size < avail) ? size : avail;
            for (uint32_t j = 0; j < copy; ++j)
                base[j] ^= ks_bytes[byte_in_first + j];
            pos += copy;
            counter = _mm_add_epi64(counter, one);
        }

        uint32_t remaining = size - pos;
        uint32_t full_blocks = remaining / 16;
        auto* blocks = reinterpret_cast<__m128i*>(base + pos);

        for (uint32_t i = 0; i < full_blocks; ++i)
        {
            __m128i keystream = aes_encrypt_block(counter, round_keys);
            blocks[i] = _mm_xor_si128(blocks[i], keystream);
            counter = _mm_add_epi64(counter, one);
        }

        pos += full_blocks * 16;
        remaining = size - pos;
        if (remaining > 0)
        {
            __m128i keystream = aes_encrypt_block(counter, round_keys);
            alignas(16) uint8_t ks_bytes[16];
            _mm_store_si128(reinterpret_cast<__m128i*>(ks_bytes), keystream);
            for (uint32_t j = 0; j < remaining; ++j)
                base[pos + j] ^= ks_bytes[j];
        }

        SecureZeroMemory(round_keys, sizeof(round_keys));
    }

    struct function_descriptor_t
    {
        uint64_t base_addr;
        uint32_t size;
        uint64_t name_hash;
        char section_name[16];
        uint64_t current_tsc;
        bool using_page_key;
    };

    inline std::vector<function_descriptor_t>& function_descriptors()
    {
        static std::vector<function_descriptor_t> v;
        return v;
    }

    inline std::mutex& function_descriptor_mtx()
    {
        static std::mutex m;
        return m;
    }

    struct function_window_t
    {
        uint64_t base_addr;
        uint32_t size;
        uint64_t decrypt_tsc;
        uint64_t key;
        bool active;
        DWORD thread_id;
        uint64_t start_tick;
    };

    inline function_window_t (&g_function_windows())[4]
    {
        static function_window_t w[4] = {};
        return w;
    }

    inline std::mutex& g_function_window_mtx()
    {
        static std::mutex m;
        return m;
    }

    inline function_descriptor_t* find_function_containing(uint64_t addr)
    {
        auto& descs = function_descriptors();
        for (auto& d : descs)
        {
            if (addr >= d.base_addr && addr < d.base_addr + d.size)
                return &d;
        }
        return nullptr;
    }

    inline int find_free_function_window_slot()
    {
        auto& wins = g_function_windows();
        DWORD tid = GetCurrentThreadId();
        for (int i = 0; i < 4; ++i)
        {
            if (!wins[i].active)
                return i;
        }
        for (int i = 0; i < 4; ++i)
        {
            if (wins[i].thread_id == tid && wins[i].active)
                return i;
        }
        return -1;
    }

    inline function_window_t* find_active_window_for_tid(DWORD tid)
    {
        auto& wins = g_function_windows();
        for (int i = 0; i < 4; ++i)
        {
            if (wins[i].active && wins[i].thread_id == tid)
                return &wins[i];
        }
        return nullptr;
    }

    inline void check_function_window_timeouts()
    {
        std::lock_guard<std::mutex> wlk(g_function_window_mtx());
        auto& wins = g_function_windows();
        uint64_t now = GetTickCount64();
        for (int i = 0; i < 4; ++i)
        {
            if (!wins[i].active)
                continue;
            if (now < wins[i].start_tick)
                continue;
            uint64_t elapsed = now - wins[i].start_tick;
            if (elapsed <= 5000)
                continue;

            uint64_t new_tsc = __rdtsc();
            uint64_t func_base = wins[i].base_addr;
            uint32_t func_size = wins[i].size;

            for (auto& page : encrypted_pages())
            {
                if (func_base >= page.base && func_base < page.base + page.size)
                {
                    DWORD old_prot;
                    VirtualProtect(reinterpret_cast<void*>(func_base),
                        func_size, PAGE_EXECUTE_READWRITE, &old_prot);

                    if (page.use_aes)
                    {
                        uint64_t sec_key = derive_section_key(page.section_name,
                            session_prk());
                        __m128i aes_key, aes_nonce;
                        derive_page_aes_material(func_base, sec_key,
                            new_tsc, session_prk(), aes_key, aes_nonce);
                        aes_ctr_crypt_region(
                            reinterpret_cast<uint8_t*>(func_base),
                            func_size, aes_key, aes_nonce);
                    }
                    else
                    {
                        uint64_t sec_key = derive_section_key(page.section_name,
                            session_prk());
                        uint64_t new_key = derive_page_key(
                            func_base, sec_key, new_tsc,
                            session_prk());
                        xor_region(reinterpret_cast<uint8_t*>(func_base),
                            func_size, new_key);
                    }

                    VirtualProtect(reinterpret_cast<void*>(page.base),
                        page.size, PAGE_EXECUTE_READ | PAGE_GUARD, &old_prot);

                    auto* desc = find_function_containing(func_base);
                    if (desc)
                    {
                        desc->current_tsc = new_tsc;
                        desc->using_page_key = false;
                    }
                    break;
                }
            }

            DWORD stale_tid = wins[i].thread_id;

            wins[i].active = false;
            wins[i].base_addr = 0;
            wins[i].size = 0;
            wins[i].key = 0;
            wins[i].decrypt_tsc = 0;
            wins[i].thread_id = 0;
            wins[i].start_tick = 0;

            diag::log_tagged_critical_fmt("code_encrypt",
                "stale_window_reencrypted slot=%d base=0x%llX size=%u elapsed=%llums tid=%u",
                i, (unsigned long long)func_base, func_size,
                (unsigned long long)elapsed, stale_tid);
            webhook::write_log_critical_fmt("code_encrypt",
                "stale_window_reencrypted slot=%d base=0x%llX size=%u elapsed=%llums tid=%u",
                i, (unsigned long long)func_base, func_size,
                (unsigned long long)elapsed, stale_tid);
        }
    }

}

inline PVOID veh_handle = nullptr;
inline ghost_veh::registration_t ghost_reg{ 0 };

inline void register_function(uint64_t base, uint32_t size, const char* name)
{
    if (!detail::active().load()) return;
    if (base == 0 || size == 0) return;

    detail::function_descriptor_t desc{};
    desc.base_addr = base;
    desc.size = size;
    desc.name_hash = _mm_crc32_u64(0, base) ^ _mm_crc32_u64(0, size);
    if (name)
    {
        for (const char* p = name; *p; ++p)
            desc.name_hash = _mm_crc32_u8(static_cast<uint32_t>(desc.name_hash),
                static_cast<uint8_t>(*p));
    }
    strncpy_s(desc.section_name, ".text", 16);

    uint64_t tsc = __rdtsc();
    desc.current_tsc = tsc;
    desc.using_page_key = true;

    std::lock_guard<std::mutex> lk(detail::function_descriptor_mtx());
    for (auto& existing : detail::function_descriptors())
    {
        if (existing.base_addr == base)
        {
            existing.size = size;
            existing.name_hash = desc.name_hash;
            existing.current_tsc = tsc;
            return;
        }
    }
    detail::function_descriptors().push_back(desc);
}

inline LONG CALLBACK code_guard_handler(EXCEPTION_POINTERS* ep)
{
    if (ep->ExceptionRecord->ExceptionCode == STATUS_GUARD_PAGE_VIOLATION)
    {
        uint64_t fault_addr = static_cast<uint64_t>(
            ep->ExceptionRecord->ExceptionInformation[1]);

        std::lock_guard<std::mutex> lk(detail::page_mtx());

        detail::encrypted_page_t* found_page = nullptr;
        for (auto& page : detail::encrypted_pages())
        {
            if (fault_addr >= page.base && fault_addr < page.base + page.size)
            {
                found_page = &page;
                break;
            }
        }

        if (found_page)
        {
            auto& p = *found_page;
            detail::function_descriptor_t* func =
                detail::find_function_containing(fault_addr);

            if (func && p.use_aes)
            {
                DWORD old_prot;
                VirtualProtect(reinterpret_cast<void*>(p.base), p.size,
                    PAGE_EXECUTE_READWRITE, &old_prot);

                uint64_t sec_key = detail::derive_section_key(p.section_name,
                    detail::session_prk());

                if (func->using_page_key)
                {
                    __m128i aes_key, aes_nonce;
                    detail::derive_page_aes_material(p.base, sec_key,
                        p.encrypt_tsc, detail::session_prk(), aes_key, aes_nonce);
                    uint32_t offset = static_cast<uint32_t>(func->base_addr - p.base);
                    detail::aes_ctr_crypt_region_offset(
                        reinterpret_cast<uint8_t*>(func->base_addr),
                        func->size, aes_key, aes_nonce, offset);
                }
                else
                {
                    __m128i aes_key, aes_nonce;
                    detail::derive_page_aes_material(func->base_addr, sec_key,
                        func->current_tsc, detail::session_prk(), aes_key, aes_nonce);
                    detail::aes_ctr_crypt_region(
                        reinterpret_cast<uint8_t*>(func->base_addr),
                        func->size, aes_key, aes_nonce);
                }

                std::lock_guard<std::mutex> wlk(detail::g_function_window_mtx());
                int slot = detail::find_free_function_window_slot();
                if (slot >= 0)
                {
                    auto& w = detail::g_function_windows()[slot];
                    w.base_addr = func->base_addr;
                    w.size = func->size;
                    w.decrypt_tsc = func->using_page_key ? p.encrypt_tsc : func->current_tsc;
                    w.key = p.key;
                    w.active = true;
                    w.thread_id = GetCurrentThreadId();
                    w.start_tick = GetTickCount64();
                }

                ep->ContextRecord->EFlags |= 0x100;
                return EXCEPTION_CONTINUE_EXECUTION;
            }

            DWORD old_prot;
            VirtualProtect(reinterpret_cast<void*>(p.base), p.size,
                PAGE_EXECUTE_READWRITE, &old_prot);

            if (p.use_aes)
            {
                uint64_t sec_key = detail::derive_section_key(p.section_name,
                    detail::session_prk());
                __m128i aes_key, aes_nonce;
                detail::derive_page_aes_material(p.base, sec_key,
                    p.encrypt_tsc, detail::session_prk(), aes_key, aes_nonce);
                detail::aes_ctr_crypt_region(
                    reinterpret_cast<uint8_t*>(p.base), p.size, aes_key, aes_nonce);
            }
            else
            {
                uint64_t sec_key = detail::derive_section_key(p.section_name,
                    detail::session_prk());
                uint64_t dec_key = detail::derive_page_key(p.base, sec_key,
                    p.encrypt_tsc, detail::session_prk());
                detail::xor_region(reinterpret_cast<uint8_t*>(p.base),
                    p.size, dec_key);
            }

            ep->ContextRecord->EFlags |= 0x100;
            return EXCEPTION_CONTINUE_EXECUTION;
        }
    }

    if (ep->ExceptionRecord->ExceptionCode == STATUS_SINGLE_STEP)
    {
        std::lock_guard<std::mutex> lk(detail::page_mtx());

        detail::check_function_window_timeouts();

        DWORD tid = GetCurrentThreadId();
        std::lock_guard<std::mutex> wlk(detail::g_function_window_mtx());
        detail::function_window_t* win = detail::find_active_window_for_tid(tid);

        if (win)
        {
            detail::encrypted_page_t* found_page = nullptr;
            for (auto& page : detail::encrypted_pages())
            {
                if (win->base_addr >= page.base && win->base_addr < page.base + page.size)
                {
                    found_page = &page;
                    break;
                }
            }

            if (found_page)
            {
                auto& p = *found_page;
                uint64_t new_tsc = __rdtsc();
                uint64_t sec_key = detail::derive_section_key(p.section_name,
                    detail::session_prk());

                DWORD old_prot;
                VirtualProtect(reinterpret_cast<void*>(win->base_addr),
                    win->size, PAGE_EXECUTE_READWRITE, &old_prot);

                if (p.use_aes)
                {
                    __m128i aes_key, aes_nonce;
                    detail::derive_page_aes_material(win->base_addr, sec_key,
                        new_tsc, detail::session_prk(), aes_key, aes_nonce);
                    detail::aes_ctr_crypt_region(
                        reinterpret_cast<uint8_t*>(win->base_addr),
                        win->size, aes_key, aes_nonce);
                }
                else
                {
                    uint64_t new_key = detail::derive_page_key(
                        win->base_addr, sec_key, new_tsc,
                        detail::session_prk());
                    detail::xor_region(reinterpret_cast<uint8_t*>(win->base_addr),
                        win->size, new_key);
                }

                VirtualProtect(reinterpret_cast<void*>(p.base), p.size,
                    PAGE_EXECUTE_READ | PAGE_GUARD, &old_prot);

                detail::function_descriptor_t* desc =
                    detail::find_function_containing(win->base_addr);
                if (desc)
                {
                    desc->current_tsc = new_tsc;
                    desc->using_page_key = false;
                }

                win->active = false;
                win->base_addr = 0;
                win->size = 0;
                win->key = 0;
                win->decrypt_tsc = 0;
                win->thread_id = 0;
                win->start_tick = 0;

                return EXCEPTION_CONTINUE_EXECUTION;
            }
        }

        uint64_t rip = ep->ContextRecord->Rip;
        for (auto& page : detail::encrypted_pages())
        {
            if (rip >= page.base && rip < page.base + page.size)
            {
                if (page.use_aes)
                {
                    uint64_t sec_key = detail::derive_section_key(page.section_name,
                        detail::session_prk());
                    __m128i aes_key, aes_nonce;
                    detail::derive_page_aes_material(page.base, sec_key,
                        page.encrypt_tsc, detail::session_prk(), aes_key, aes_nonce);
                    detail::aes_ctr_crypt_region(
                        reinterpret_cast<uint8_t*>(page.base), page.size,
                        aes_key, aes_nonce);
                }
                else
                {
                    detail::xor_region(reinterpret_cast<uint8_t*>(page.base),
                        page.size, page.key);
                }

                DWORD old_prot;
                VirtualProtect(reinterpret_cast<void*>(page.base), page.size,
                    PAGE_EXECUTE_READ | PAGE_GUARD, &old_prot);
                return EXCEPTION_CONTINUE_EXECUTION;
            }
        }
    }

    if (ep->ExceptionRecord->ExceptionCode == STATUS_BREAKPOINT ||
        ep->ExceptionRecord->ExceptionCode == 0x4000001F)
    {
        uint64_t rip = ep->ContextRecord->Rip;
        std::lock_guard<std::mutex> lk(detail::page_mtx());
        for (auto& tramp : detail::eop_trampolines())
        {
            if (!tramp.armed) continue;
            if (tramp.exception_type != detail::EOP_INT2D &&
                tramp.exception_type != detail::EOP_INT3) continue;
            if (rip >= tramp.trigger_addr && rip <= tramp.trigger_addr + 2)
            {
                if (tramp.decrypt_key != 0 && tramp.target_size != 0)
                {
                    DWORD old_prot;
                    VirtualProtect(reinterpret_cast<void*>(tramp.target_addr), tramp.target_size,
                        PAGE_EXECUTE_READWRITE, &old_prot);
                    detail::xor_region(reinterpret_cast<uint8_t*>(tramp.target_addr),
                        tramp.target_size, tramp.decrypt_key);
                    VirtualProtect(reinterpret_cast<void*>(tramp.target_addr), tramp.target_size,
                        PAGE_EXECUTE_READ, &old_prot);
                    FlushInstructionCache(GetCurrentProcess(),
                        reinterpret_cast<void*>(tramp.target_addr), tramp.target_size);
                }
                ep->ContextRecord->Rip = tramp.target_addr;
                return EXCEPTION_CONTINUE_EXECUTION;
            }
        }
    }

    if (ep->ExceptionRecord->ExceptionCode == STATUS_INTEGER_DIVIDE_BY_ZERO)
    {
        uint64_t rip = ep->ContextRecord->Rip;
        std::lock_guard<std::mutex> lk(detail::page_mtx());
        for (auto& tramp : detail::eop_trampolines())
        {
            if (!tramp.armed) continue;
            if (tramp.exception_type != detail::EOP_DIV_ZERO) continue;
            if (rip >= tramp.trigger_addr && rip <= tramp.trigger_addr + 6)
            {
                if (tramp.decrypt_key != 0 && tramp.target_size != 0)
                {
                    DWORD old_prot;
                    VirtualProtect(reinterpret_cast<void*>(tramp.target_addr), tramp.target_size,
                        PAGE_EXECUTE_READWRITE, &old_prot);
                    detail::xor_region(reinterpret_cast<uint8_t*>(tramp.target_addr),
                        tramp.target_size, tramp.decrypt_key);
                    VirtualProtect(reinterpret_cast<void*>(tramp.target_addr), tramp.target_size,
                        PAGE_EXECUTE_READ, &old_prot);
                    FlushInstructionCache(GetCurrentProcess(),
                        reinterpret_cast<void*>(tramp.target_addr), tramp.target_size);
                }
                ep->ContextRecord->Rip = tramp.target_addr;
                return EXCEPTION_CONTINUE_EXECUTION;
            }
        }
    }

    return EXCEPTION_CONTINUE_SEARCH;
}

inline long code_guard_ghost_handler(PEXCEPTION_POINTERS ep, void*)
{
    return code_guard_handler(ep);
}

inline bool initialize(uint64_t code_hash)
{
    if (detail::active().load()) return true;

#pragma region RDTSC_ENTANGLE
    if (token_chain::is_rdtsc_entangle_enabled())
    {
        uint64_t e_samples[4];
        for (int i = 0; i < 4; ++i)
            e_samples[i] = token_chain::detail::rdtsc_entangle_sample();

        uint8_t buf[32];
        memcpy(buf, e_samples, 32);
        uint64_t k0 = 0, k1 = 0;
        integrity::get_session_keys(k0, k1);
        uint64_t entangle_hmac = integrity::siphash::hash(buf, 32, k0, k1);
        (void)entangle_hmac;

        if (token_chain::rdtsc_entangle_violation_observed())
        {
            auto& rt = state::get();
            rt.violation_latched.store(true, std::memory_order_release);
            rt.violation_reason = "rdtsc_entangle_hv_spoof";
            enforcement_detail::silent_corrupt_text(1);
            return false;
        }
    }
#pragma endregion

    uint8_t ikm[32];
    if (BCryptGenRandom(nullptr, ikm, 32, BCRYPT_USE_SYSTEM_PREFERRED_RNG) != 0)
        return false;

    uint8_t salt[8];
    memcpy(salt, &code_hash, 8);
    detail::hkdf_hmac_sha256(salt, 8, ikm, 32, detail::session_prk());
    SecureZeroMemory(ikm, 32);

    if (ghost_veh::is_active())
    {
        ghost_reg = ghost_veh::register_handler(
            ghost_veh::ex_kind::kAny, code_guard_ghost_handler, nullptr);
        if (ghost_reg.id == 0)
        {
            veh_handle = AddVectoredExceptionHandler(1, code_guard_handler);
            if (!veh_handle) return false;
        }
    }
    else
    {
        veh_handle = AddVectoredExceptionHandler(1, code_guard_handler);
        if (!veh_handle) return false;
    }

    detail::active().store(true);
    return true;
}

inline void encrypt_region(uint64_t base, uint32_t size, const char* section_name)
{
    if (!detail::active().load()) return;

    uint64_t sec_key = detail::derive_section_key(section_name, detail::session_prk());
    uint64_t tsc_value = __rdtsc();
    bool is_text = (strcmp(section_name, ".text") == 0);
    uint64_t page_key = 0;

    DWORD old_prot;
    if (!VirtualProtect(reinterpret_cast<void*>(base), size,
        PAGE_EXECUTE_READWRITE, &old_prot))
        return;

    if (is_text)
    {
        __m128i aes_key, aes_nonce;
        detail::derive_page_aes_material(base, sec_key, tsc_value,
            detail::session_prk(), aes_key, aes_nonce);
        detail::aes_ctr_crypt_region(reinterpret_cast<uint8_t*>(base), size,
            aes_key, aes_nonce);
        page_key = 0;
    }
    else
    {
        page_key = detail::derive_page_key(base, sec_key, tsc_value,
            detail::session_prk());
        detail::xor_region(reinterpret_cast<uint8_t*>(base), size, page_key);
    }

    VirtualProtect(reinterpret_cast<void*>(base), size,
        PAGE_EXECUTE_READ | PAGE_GUARD, &old_prot);

    std::lock_guard<std::mutex> lk(detail::page_mtx());
    detail::encrypted_page_t entry{};
    entry.base = base;
    entry.size = size;
    entry.key = page_key;
    entry.encrypt_tsc = tsc_value;
    entry.use_aes = is_text;
    entry.original_protect = old_prot;
    strncpy_s(entry.section_name, section_name, 16);
    detail::encrypted_pages().push_back(entry);

    {
        std::lock_guard<std::mutex> flk(detail::function_descriptor_mtx());
        for (auto& desc : detail::function_descriptors())
        {
            if (desc.base_addr >= base && desc.base_addr < base + size)
            {
                desc.current_tsc = tsc_value;
                desc.using_page_key = true;
                strncpy_s(desc.section_name, section_name, 16);
            }
        }
    }
}

inline void rotate_keys()
{
    std::lock_guard<std::mutex> lk(detail::page_mtx());

    detail::check_function_window_timeouts();

    uint8_t new_ikm[32];
    BCryptGenRandom(nullptr, new_ikm, 32, BCRYPT_USE_SYSTEM_PREFERRED_RNG);
    uint8_t new_prk[32];
    detail::hkdf_hmac_sha256(detail::session_prk(), 32, new_ikm, 32, new_prk);
    SecureZeroMemory(new_ikm, 32);
    memcpy(detail::session_prk(), new_prk, 32);
    SecureZeroMemory(new_prk, 32);

    for (auto& page : detail::encrypted_pages())
    {
        DWORD old_prot;
        if (!VirtualProtect(reinterpret_cast<void*>(page.base), page.size,
            PAGE_EXECUTE_READWRITE, &old_prot))
            continue;

        if (page.use_aes)
        {
            uint64_t old_sec_key = detail::derive_section_key(page.section_name,
                detail::session_prk());
            (void)old_sec_key;

            uint64_t new_tsc = __rdtsc();
            uint64_t new_sec_key = detail::derive_section_key(page.section_name,
                detail::session_prk());
            __m128i new_aes_key, new_aes_nonce;
            detail::derive_page_aes_material(page.base, new_sec_key, new_tsc,
                detail::session_prk(), new_aes_key, new_aes_nonce);
            detail::aes_ctr_crypt_region(reinterpret_cast<uint8_t*>(page.base),
                page.size, new_aes_key, new_aes_nonce);

            page.encrypt_tsc = new_tsc;
            page.key = 0;
        }
        else
        {
            detail::xor_region(reinterpret_cast<uint8_t*>(page.base), page.size, page.key);

            uint64_t new_tsc = __rdtsc();
            uint64_t new_sec_key = detail::derive_section_key(page.section_name,
                detail::session_prk());
            uint64_t new_key = detail::derive_page_key(page.base, new_sec_key,
                new_tsc, detail::session_prk());
            detail::xor_region(reinterpret_cast<uint8_t*>(page.base), page.size, new_key);

            page.key = new_key;
            page.encrypt_tsc = new_tsc;
        }

        VirtualProtect(reinterpret_cast<void*>(page.base), page.size,
            PAGE_EXECUTE_READ | PAGE_GUARD, &old_prot);
    }

    {
        std::lock_guard<std::mutex> flk(detail::function_descriptor_mtx());
        for (auto& desc : detail::function_descriptors())
        {
            desc.current_tsc = __rdtsc();
            desc.using_page_key = true;
        }
    }

    {
        std::lock_guard<std::mutex> wlk(detail::g_function_window_mtx());
        for (int i = 0; i < 4; ++i)
        {
            auto& w = detail::g_function_windows()[i];
            w.active = false;
            w.base_addr = 0;
            w.size = 0;
            w.key = 0;
            w.decrypt_tsc = 0;
            w.thread_id = 0;
            w.start_tick = 0;
        }
    }
}

inline void register_eop_trampoline(uint64_t trigger_addr, uint64_t target_addr,
    uint64_t decrypt_key, uint32_t target_size, detail::eop_exception_type type)
{
    if (!detail::active().load()) return;

    std::lock_guard<std::mutex> lk(detail::page_mtx());
    detail::eop_trampolines().push_back({trigger_addr, target_addr, decrypt_key,
        target_size, static_cast<uint8_t>(type), true});

    switch (type)
    {
    case detail::EOP_INT2D:
        detail::install_int2d_trigger(reinterpret_cast<uint8_t*>(trigger_addr));
        break;
    case detail::EOP_DIV_ZERO:
        detail::install_div_zero_trigger(reinterpret_cast<uint8_t*>(trigger_addr));
        break;
    default:
        break;
    }
}

inline void shutdown()
{
    detail::active().store(false);
    if (veh_handle)
    {
        RemoveVectoredExceptionHandler(veh_handle);
        veh_handle = nullptr;
    }

    std::lock_guard<std::mutex> lk(detail::page_mtx());
    for (auto& page : detail::encrypted_pages())
    {
        DWORD old_prot;
        VirtualProtect(reinterpret_cast<void*>(page.base), page.size,
            PAGE_EXECUTE_READWRITE, &old_prot);

        if (page.use_aes)
        {
            uint64_t sec_key = detail::derive_section_key(page.section_name,
                detail::session_prk());
            __m128i aes_key, aes_nonce;
            detail::derive_page_aes_material(page.base, sec_key,
                page.encrypt_tsc, detail::session_prk(), aes_key, aes_nonce);
            detail::aes_ctr_crypt_region(reinterpret_cast<uint8_t*>(page.base),
                page.size, aes_key, aes_nonce);
        }
        else
        {
            detail::xor_region(reinterpret_cast<uint8_t*>(page.base), page.size, page.key);
        }

        VirtualProtect(reinterpret_cast<void*>(page.base), page.size,
            page.original_protect, &old_prot);
    }
    detail::encrypted_pages().clear();

    {
        std::lock_guard<std::mutex> flk(detail::function_descriptor_mtx());
        detail::function_descriptors().clear();
    }

    {
        std::lock_guard<std::mutex> wlk(detail::g_function_window_mtx());
        for (int i = 0; i < 4; ++i)
        {
            auto& w = detail::g_function_windows()[i];
            w.active = false;
            w.base_addr = 0;
            w.size = 0;
            w.key = 0;
            w.decrypt_tsc = 0;
            w.thread_id = 0;
            w.start_tick = 0;
        }
    }

    SecureZeroMemory(detail::session_prk(), 32);
}

}
}
