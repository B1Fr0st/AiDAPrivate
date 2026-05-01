#pragma once

#include <windows.h>
#include <intrin.h>

#include <atomic>
#include <cstdint>
#include <cstring>
#include <functional>
#include <mutex>
#include <string>
#include <vector>

#include "integrity.hpp"
#include "virtualizer.hpp"
#include "vm_compiler.hpp"
#include "cfg_extract.hpp"

namespace anti_tamper {
namespace stolen_bytes {

namespace detail {

    static constexpr uint32_t MAX_STOLEN = 32;
    static constexpr uint32_t MAX_ENTRIES = 64;

    struct fetch_oracle_request_t
    {
        uint64_t function_hash;
        uint64_t client_nonce;
        uint64_t requested_at;
    };

    struct fetch_oracle_response_t
    {
        std::vector<uint8_t> ciphertext;
        std::vector<uint8_t> aes_gcm_tag;
        std::vector<uint8_t> session_iv;
        std::vector<uint8_t> ephemeral_key;
        uint64_t prologue_len;
        uint64_t valid_until_tick;
        uint64_t fetch_id;
        bool ok;
        bool flagged;
        std::string status;
    };

    using oracle_fetch_fn = std::function<bool(const fetch_oracle_request_t&,
                                               fetch_oracle_response_t&)>;

    struct stolen_entry_t
    {
        uint64_t original_addr;
        uint64_t function_hash;
        uint32_t prologue_len;
        std::vector<uint8_t> cached_ciphertext;
        std::vector<uint8_t> cached_aes_gcm_tag;
        std::vector<uint8_t> cached_session_iv;
        uint64_t cached_fetch_id;
        uint64_t cached_at_tick;
        uint64_t valid_until_tick;
        bool     cached_present;
        std::vector<uint8_t> ephemeral_session_key;
        uint64_t trampoline_addr;
        std::vector<uint8_t> vm_bytecode;
        uint64_t vm_seed;
        uint64_t continuation_addr;
        anti_tamper::virtualizer::detail::handler_pool_t* pool;
    };

    struct stolen_state_t
    {
        stolen_entry_t entries[MAX_ENTRIES];
        uint32_t count;
        void* trampoline_page;
        uint32_t trampoline_offset;
        uint64_t session_key[2];
        uint64_t session_epoch;
        oracle_fetch_fn oracle_fn;
        std::mutex mtx;
        std::atomic<bool> initialized;
    };

    inline stolen_state_t& get_state()
    {
        static stolen_state_t s;
        return s;
    }

    inline void emit_vm_entry_stub(uint32_t func_rva, std::vector<uint8_t>& out)
    {
        uint8_t bytes[4];
        memcpy(bytes, &func_rva, 4);
        out.insert(out.begin(), bytes, bytes + 4);
    }

    static constexpr uint32_t MAX_BB_ENTRIES = 256;
    static constexpr uint32_t BB_TRAMPOLINE_PAGE_SIZE = 65536;
    static constexpr uint32_t BB_TRAMPOLINE_STRIDE = 96;
    static constexpr uint32_t MAX_BB_ORIGINAL = 64;

    struct bb_entry_t
    {
        uint64_t original_addr;
        uint64_t rva_end;
        uint32_t block_length;
        uint8_t  encrypted_original[MAX_BB_ORIGINAL];
        uint64_t encryption_key;
        std::vector<uint8_t> vm_bytecode;
        uint64_t vm_seed;
        uint64_t trampoline_addr;
        anti_tamper::virtualizer::detail::handler_pool_t* pool;
    };

    struct bb_state_t
    {
        bb_entry_t entries[MAX_BB_ENTRIES];
        uint32_t count;
        void* trampoline_page;
        uint32_t trampoline_offset;
        uint64_t session_key[2];
        bool initialized;
    };

    inline bb_state_t& get_bb_state()
    {
        static bb_state_t s{};
        return s;
    }

    inline void encrypt_buffer(uint8_t* dst, const uint8_t* src, uint32_t len, uint64_t key)
    {
        anti_tamper::virtualizer::detail::cipher_stream_t s;
        anti_tamper::virtualizer::detail::cipher_stream_init(s, key);
        for (uint32_t i = 0; i < len; ++i)
            dst[i] = anti_tamper::virtualizer::detail::cipher_stream_xcrypt(s, src[i], true);
        SecureZeroMemory(&s, sizeof(s));
    }

    inline void decrypt_buffer(uint8_t* dst, const uint8_t* src, uint32_t len, uint64_t key)
    {
        anti_tamper::virtualizer::detail::cipher_stream_t s;
        anti_tamper::virtualizer::detail::cipher_stream_init(s, key);
        for (uint32_t i = 0; i < len; ++i)
            dst[i] = anti_tamper::virtualizer::detail::cipher_stream_xcrypt(s, src[i], false);
        SecureZeroMemory(&s, sizeof(s));
    }

    inline uint64_t compute_function_hash(const void* code, uint32_t hint_len,
                                           uint64_t k0, uint64_t k1)
    {
        uint32_t scan = (hint_len < 64) ? hint_len : 64;
        return integrity::siphash::hash(static_cast<const uint8_t*>(code), scan, k0, k1);
    }

    inline uint32_t compute_prologue_length(const uint8_t* code, uint32_t min_bytes)
    {
        uint32_t len = 0;
        while (len < min_bytes && len < MAX_STOLEN)
        {
            uint8_t b = code[len];

            if (b == 0xCC || b == 0xC3)
                break;

            if (b == 0x90) { len += 1; continue; }

            if ((b & 0xF0) == 0x50 || (b & 0xF0) == 0x58)
            {
                len += 1;
                continue;
            }

            if (b == 0x48 || b == 0x4C || b == 0x49 || b == 0x4D)
            {
                uint8_t next = code[len + 1];
                if (next == 0x89 || next == 0x8B)
                {
                    uint8_t modrm = code[len + 2];
                    uint8_t mod = (modrm >> 6) & 3;
                    uint8_t rm = modrm & 7;
                    len += 3;
                    if (mod == 1) len += 1;
                    else if (mod == 2) len += 4;
                    if (rm == 4 && mod != 3) len += 1;
                    continue;
                }
                if (next == 0x83)
                {
                    uint8_t modrm = code[len + 2];
                    len += 4;
                    uint8_t rm = modrm & 7;
                    if (rm == 4) len += 1;
                    continue;
                }
                if (next == 0x8D)
                {
                    uint8_t modrm = code[len + 2];
                    uint8_t mod = (modrm >> 6) & 3;
                    len += 3;
                    if (mod == 1) len += 1;
                    else if (mod == 2) len += 4;
                    else if (mod == 0 && (modrm & 7) == 5) len += 4;
                    continue;
                }
            }

            if (b == 0x55 || b == 0x56 || b == 0x57)
            {
                len += 1;
                continue;
            }

            if (b == 0x41)
            {
                len += 1;
                continue;
            }

            len += 1;
        }

        return len;
    }

    inline bool aes_gcm_decrypt(const uint8_t* key, uint32_t key_len,
                                const uint8_t* iv, uint32_t iv_len,
                                const uint8_t* aad, uint32_t aad_len,
                                const uint8_t* ciphertext, uint32_t ct_len,
                                const uint8_t* tag, uint32_t tag_len,
                                uint8_t* plaintext_out)
    {
        BCRYPT_ALG_HANDLE hAlg = nullptr;
        BCRYPT_KEY_HANDLE hKey = nullptr;
        bool ok = false;

        if (BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_AES_ALGORITHM, nullptr, 0) != 0)
            return false;

        ULONG cb = 0;
        if (BCryptSetProperty(hAlg, BCRYPT_CHAINING_MODE,
                              reinterpret_cast<PUCHAR>(const_cast<wchar_t*>(BCRYPT_CHAIN_MODE_GCM)),
                              sizeof(BCRYPT_CHAIN_MODE_GCM), 0) != 0)
        {
            BCryptCloseAlgorithmProvider(hAlg, 0);
            return false;
        }

        if (BCryptGenerateSymmetricKey(hAlg, &hKey, nullptr, 0,
                                       const_cast<PUCHAR>(key), key_len, 0) != 0)
        {
            BCryptCloseAlgorithmProvider(hAlg, 0);
            return false;
        }

        BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO info{};
        BCRYPT_INIT_AUTH_MODE_INFO(info);
        info.pbNonce = const_cast<PUCHAR>(iv);
        info.cbNonce = iv_len;
        info.pbAuthData = const_cast<PUCHAR>(aad);
        info.cbAuthData = aad_len;
        info.pbTag = const_cast<PUCHAR>(tag);
        info.cbTag = tag_len;

        ULONG out_size = 0;
        if (BCryptDecrypt(hKey,
                          const_cast<PUCHAR>(ciphertext), ct_len,
                          &info, nullptr, 0,
                          plaintext_out, ct_len, &out_size, 0) == 0)
        {
            ok = (out_size == ct_len);
        }

        BCryptDestroyKey(hKey);
        BCryptCloseAlgorithmProvider(hAlg, 0);
        return ok;
    }

    inline bool aes_gcm_encrypt(const uint8_t* key, uint32_t key_len,
                                const uint8_t* iv, uint32_t iv_len,
                                const uint8_t* aad, uint32_t aad_len,
                                const uint8_t* plaintext, uint32_t pt_len,
                                uint8_t* ciphertext_out, uint8_t tag_out[16])
    {
        BCRYPT_ALG_HANDLE hAlg = nullptr;
        BCRYPT_KEY_HANDLE hKey = nullptr;
        bool ok = false;

        if (BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_AES_ALGORITHM, nullptr, 0) != 0)
            return false;

        if (BCryptSetProperty(hAlg, BCRYPT_CHAINING_MODE,
                              reinterpret_cast<PUCHAR>(const_cast<wchar_t*>(BCRYPT_CHAIN_MODE_GCM)),
                              sizeof(BCRYPT_CHAIN_MODE_GCM), 0) != 0)
        {
            BCryptCloseAlgorithmProvider(hAlg, 0);
            return false;
        }

        if (BCryptGenerateSymmetricKey(hAlg, &hKey, nullptr, 0,
                                       const_cast<PUCHAR>(key), key_len, 0) != 0)
        {
            BCryptCloseAlgorithmProvider(hAlg, 0);
            return false;
        }

        BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO info{};
        BCRYPT_INIT_AUTH_MODE_INFO(info);
        info.pbNonce = const_cast<PUCHAR>(iv);
        info.cbNonce = iv_len;
        info.pbAuthData = const_cast<PUCHAR>(aad);
        info.cbAuthData = aad_len;
        info.pbTag = tag_out;
        info.cbTag = 16;

        ULONG out_size = 0;
        if (BCryptEncrypt(hKey,
                          const_cast<PUCHAR>(plaintext), pt_len,
                          &info, nullptr, 0,
                          ciphertext_out, pt_len, &out_size, 0) == 0)
        {
            ok = (out_size == pt_len);
        }

        BCryptDestroyKey(hKey);
        BCryptCloseAlgorithmProvider(hAlg, 0);
        return ok;
    }

}

inline void install_oracle(detail::oracle_fetch_fn fn)
{
    auto& s = detail::get_state();
    std::lock_guard<std::mutex> lk(s.mtx);
    s.oracle_fn = std::move(fn);
}

inline void rotate_session(uint64_t new_epoch)
{
    auto& s = detail::get_state();
    std::lock_guard<std::mutex> lk(s.mtx);
    s.session_epoch = new_epoch;
    for (uint32_t i = 0; i < s.count; ++i)
    {
        auto& entry = s.entries[i];
        entry.cached_present = false;
        entry.cached_ciphertext.clear();
        entry.cached_aes_gcm_tag.clear();
        entry.cached_session_iv.clear();
        entry.cached_fetch_id = 0;
        entry.cached_at_tick = 0;
        entry.valid_until_tick = 0;
        if (!entry.ephemeral_session_key.empty())
        {
            volatile uint8_t* p = entry.ephemeral_session_key.data();
            for (size_t j = 0; j < entry.ephemeral_session_key.size(); ++j) p[j] = 0;
            entry.ephemeral_session_key.clear();
        }
    }
}

inline bool fetch_prologue_from_oracle(detail::stolen_entry_t& entry, uint64_t now_tick)
{
    auto& s = detail::get_state();
    if (!s.oracle_fn) return false;

    detail::fetch_oracle_request_t req{};
    req.function_hash = entry.function_hash;
    uint8_t nonce_buf[8];
    if (!virtualizer::detail::bcrypt_random(nonce_buf, 8))
    {
        uint64_t fb = __rdtsc() ^ entry.original_addr;
        memcpy(nonce_buf, &fb, 8);
    }
    memcpy(&req.client_nonce, nonce_buf, 8);
    req.requested_at = now_tick;

    detail::fetch_oracle_response_t resp{};
    if (!s.oracle_fn(req, resp))
        return false;
    if (!resp.ok || resp.ciphertext.empty() || resp.aes_gcm_tag.size() != 16
        || resp.session_iv.size() != 12 || resp.ephemeral_key.size() != 32)
        return false;
    if (resp.prologue_len != entry.prologue_len)
        return false;

    entry.cached_ciphertext = std::move(resp.ciphertext);
    entry.cached_aes_gcm_tag = std::move(resp.aes_gcm_tag);
    entry.cached_session_iv = std::move(resp.session_iv);
    entry.ephemeral_session_key = std::move(resp.ephemeral_key);
    entry.cached_fetch_id = resp.fetch_id;
    entry.cached_at_tick = now_tick;
    entry.valid_until_tick = resp.valid_until_tick;
    entry.cached_present = true;
    return true;
}

inline bool decrypt_and_execute_in_place(detail::stolen_entry_t& entry)
{
    auto& s = detail::get_state();
    if (!entry.cached_present) return false;
    if (entry.ephemeral_session_key.size() != 32) return false;
    if (entry.cached_session_iv.size() != 12) return false;
    if (entry.cached_aes_gcm_tag.size() != 16) return false;
    if (entry.cached_ciphertext.size() != entry.prologue_len) return false;

    uint8_t aad[24];
    memcpy(aad, &entry.function_hash, 8);
    memcpy(aad + 8, &entry.cached_fetch_id, 8);
    memcpy(aad + 16, &s.session_epoch, 8);

    std::vector<uint8_t> plaintext(entry.prologue_len);
    bool decrypted = detail::aes_gcm_decrypt(
        entry.ephemeral_session_key.data(), 32,
        entry.cached_session_iv.data(), 12,
        aad, 24,
        entry.cached_ciphertext.data(),
        static_cast<uint32_t>(entry.cached_ciphertext.size()),
        entry.cached_aes_gcm_tag.data(), 16,
        plaintext.data());
    if (!decrypted)
    {
        volatile uint8_t* p = plaintext.data();
        for (size_t i = 0; i < plaintext.size(); ++i) p[i] = 0;
        return false;
    }

    auto* code_ptr = reinterpret_cast<uint8_t*>(entry.original_addr);
    DWORD old_prot = 0;
    if (!VirtualProtect(code_ptr, entry.prologue_len, PAGE_EXECUTE_READWRITE, &old_prot))
    {
        volatile uint8_t* p = plaintext.data();
        for (size_t i = 0; i < plaintext.size(); ++i) p[i] = 0;
        return false;
    }
    memcpy(code_ptr, plaintext.data(), entry.prologue_len);
    FlushInstructionCache(GetCurrentProcess(), code_ptr, entry.prologue_len);

    auto cont = reinterpret_cast<void(*)()>(static_cast<uintptr_t>(entry.original_addr));
    cont();

    uint8_t indirect_jmp[14];
    indirect_jmp[0] = 0xFF;
    indirect_jmp[1] = 0x25;
    *reinterpret_cast<uint32_t*>(indirect_jmp + 2) = 0;
    *reinterpret_cast<uint64_t*>(indirect_jmp + 6) = entry.trampoline_addr;
    memcpy(code_ptr, indirect_jmp, 14);
    for (uint32_t i = 14; i < entry.prologue_len; ++i)
        code_ptr[i] = 0xCC;
    FlushInstructionCache(GetCurrentProcess(), code_ptr, entry.prologue_len);

    DWORD discard = 0;
    VirtualProtect(code_ptr, entry.prologue_len, old_prot, &discard);

    volatile uint8_t* pscrub = plaintext.data();
    for (size_t i = 0; i < plaintext.size(); ++i) pscrub[i] = 0;
    return true;
}

inline void vm_prologue_execute(detail::stolen_entry_t* entry)
{
    if (!entry) return;
    auto& s = detail::get_state();
    std::lock_guard<std::mutex> lk(s.mtx);
    uint64_t now = GetTickCount64();
    if (!entry->cached_present || (entry->valid_until_tick > 0 && now >= entry->valid_until_tick))
    {
        if (!fetch_prologue_from_oracle(*entry, now))
        {
            if (!entry->vm_bytecode.empty())
            {
                anti_tamper::virtualizer::detail::vm_state_t vm;
                anti_tamper::virtualizer::detail::init_vm(vm, entry->vm_seed, entry->pool);
                anti_tamper::virtualizer::detail::vm_execute(
                    vm, entry->vm_bytecode.data(),
                    static_cast<uint32_t>(entry->vm_bytecode.size()));
                anti_tamper::virtualizer::detail::destroy_vm(vm);
            }
            return;
        }
    }
    decrypt_and_execute_in_place(*entry);
}

inline bool initialize()
{
    auto& s = detail::get_state();
    if (s.initialized.load(std::memory_order_acquire)) return true;

    std::lock_guard<std::mutex> lk(s.mtx);
    if (s.initialized.load(std::memory_order_acquire)) return true;

    integrity::get_session_keys(s.session_key[0], s.session_key[1]);

    uint8_t epoch_buf[8];
    if (virtualizer::detail::bcrypt_random(epoch_buf, 8))
        memcpy(&s.session_epoch, epoch_buf, 8);
    else
        s.session_epoch = __rdtsc();

    s.trampoline_page = VirtualAlloc(nullptr, 4096,
        MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!s.trampoline_page) return false;

    s.trampoline_offset = 0;
    s.count = 0;
    s.initialized.store(true, std::memory_order_release);
    return true;
}

inline bool steal_function_prologue(void* target_func)
{
    auto& s = detail::get_state();
    if (!s.initialized.load(std::memory_order_acquire) || s.count >= detail::MAX_ENTRIES)
        return false;

    auto* code = static_cast<uint8_t*>(target_func);
    uint32_t steal_len = detail::compute_prologue_length(code, 14);
    if (steal_len < 5 || steal_len > detail::MAX_STOLEN)
        return false;

    std::lock_guard<std::mutex> lk(s.mtx);
    if (s.trampoline_offset + 64 > 4096)
        return false;

    auto& entry = s.entries[s.count];
    entry.original_addr = reinterpret_cast<uint64_t>(code);
    entry.prologue_len = steal_len;
    entry.continuation_addr = reinterpret_cast<uint64_t>(code) + steal_len;
    entry.function_hash = detail::compute_function_hash(code, steal_len,
                                                         s.session_key[0], s.session_key[1]);
    entry.cached_present = false;
    entry.cached_at_tick = 0;
    entry.valid_until_tick = 0;
    entry.cached_fetch_id = 0;

    uint64_t vm_seed = anti_tamper::virtualizer::detail::secure_seed();
    entry.vm_seed = vm_seed;

    entry.pool = anti_tamper::virtualizer::pool_manager::get_or_create(
        entry.original_addr,
        s.session_key[0] ^ s.session_key[1] ^ 0x9E3779B97F4A7C15ULL);

    anti_tamper::virtualizer::detail::vm_state_t tmp_vm;
    anti_tamper::virtualizer::detail::init_vm(tmp_vm, vm_seed, entry.pool);

#ifdef AIDA_STANDALONE
    auto lifted = vm_compiler::x86_lifter::compile_function(
        code, steal_len, reinterpret_cast<uint64_t>(code),
        vm_seed ^ 0x6A09E667F3BCC908ULL, tmp_vm.opcode_map, entry.pool);
    entry.vm_bytecode = lifted.bytecode;
#else
    vm_compiler::program_t prog;
    prog.set_key(vm_seed ^ 0x6A09E667F3BCC908ULL);
    prog.set_opcode_map(tmp_vm.opcode_map);
    for (uint32_t i = 0; i < steal_len; ++i)
        prog.emit_nop();
    prog.emit_halt();
    entry.vm_bytecode = prog.finalize();
#endif

    anti_tamper::virtualizer::detail::destroy_vm(tmp_vm);

    auto* tramp = static_cast<uint8_t*>(s.trampoline_page) + s.trampoline_offset;
    entry.trampoline_addr = reinterpret_cast<uint64_t>(tramp);

    uint64_t entry_ptr = reinterpret_cast<uint64_t>(&s.entries[s.count]);
    uint64_t exec_addr = reinterpret_cast<uint64_t>(&vm_prologue_execute);

    tramp[0] = 0x48; tramp[1] = 0xB9;
    memcpy(tramp + 2, &entry_ptr, 8);
    tramp[10] = 0x48; tramp[11] = 0xBA;
    memcpy(tramp + 12, &exec_addr, 8);
    tramp[20] = 0xFF; tramp[21] = 0xE2;

    s.trampoline_offset += 32;

    DWORD old_prot;
    VirtualProtect(code, steal_len, PAGE_EXECUTE_READWRITE, &old_prot);

    code[0] = 0xFF;
    code[1] = 0x25;
    *reinterpret_cast<uint32_t*>(code + 2) = 0;
    *reinterpret_cast<uint64_t*>(code + 6) = entry.trampoline_addr;

    for (uint32_t i = 14; i < steal_len; ++i)
        code[i] = 0xCC;

    VirtualProtect(code, steal_len, old_prot, &old_prot);
    FlushInstructionCache(GetCurrentProcess(), code, steal_len);

    ++s.count;
    return true;
}

inline bool verify_stolen_bytes()
{
    auto& s = detail::get_state();
    if (!s.initialized.load(std::memory_order_acquire)) return true;

    std::lock_guard<std::mutex> lk(s.mtx);
    for (uint32_t i = 0; i < s.count; ++i)
    {
        auto& entry = s.entries[i];

        if (entry.vm_bytecode.empty())
            return false;

        auto* original = reinterpret_cast<const uint8_t*>(entry.original_addr);
        if (original[0] != 0xFF || original[1] != 0x25)
            return false;

        if (entry.cached_present)
        {
            if (entry.cached_ciphertext.size() != entry.prologue_len)
                return false;
            if (entry.cached_aes_gcm_tag.size() != 16)
                return false;
            if (entry.cached_session_iv.size() != 12)
                return false;
            if (entry.ephemeral_session_key.size() != 32)
                return false;
        }
    }

    return true;
}

inline void shutdown()
{
    auto& s = detail::get_state();
    std::lock_guard<std::mutex> lk(s.mtx);
    for (uint32_t i = 0; i < s.count; ++i)
    {
        auto& entry = s.entries[i];
        if (!entry.ephemeral_session_key.empty())
        {
            volatile uint8_t* p = entry.ephemeral_session_key.data();
            for (size_t j = 0; j < entry.ephemeral_session_key.size(); ++j) p[j] = 0;
            entry.ephemeral_session_key.clear();
        }
        entry.cached_ciphertext.clear();
        entry.cached_aes_gcm_tag.clear();
        entry.cached_session_iv.clear();
        entry.cached_present = false;
    }
    if (s.trampoline_page)
    {
        volatile uint8_t* p = static_cast<volatile uint8_t*>(s.trampoline_page);
        for (uint32_t i = 0; i < 4096; ++i) p[i] = 0xCC;
        VirtualFree(s.trampoline_page, 0, MEM_RELEASE);
        s.trampoline_page = nullptr;
    }
    s.initialized.store(false, std::memory_order_release);

    auto& bb = detail::get_bb_state();
    if (bb.trampoline_page)
    {
        volatile uint8_t* p = static_cast<volatile uint8_t*>(bb.trampoline_page);
        for (uint32_t i = 0; i < detail::BB_TRAMPOLINE_PAGE_SIZE; ++i) p[i] = 0xCC;
        VirtualFree(bb.trampoline_page, 0, MEM_RELEASE);
        bb.trampoline_page = nullptr;
    }
    bb.initialized = false;
}

inline void vm_bb_execute(detail::bb_entry_t* entry)
{
    if (!entry || entry->vm_bytecode.empty())
        return;

    anti_tamper::virtualizer::detail::vm_state_t vm;
    anti_tamper::virtualizer::detail::init_vm(vm, entry->vm_seed, entry->pool);
    anti_tamper::virtualizer::detail::vm_execute(
        vm, entry->vm_bytecode.data(),
        static_cast<uint32_t>(entry->vm_bytecode.size()));
    anti_tamper::virtualizer::detail::destroy_vm(vm);
}

inline bool initialize_basic_blocks()
{
    auto& bb = detail::get_bb_state();
    if (bb.initialized) return true;

    integrity::get_session_keys(bb.session_key[0], bb.session_key[1]);

    bb.trampoline_page = VirtualAlloc(nullptr, detail::BB_TRAMPOLINE_PAGE_SIZE,
        MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!bb.trampoline_page) return false;

    bb.trampoline_offset = 0;
    bb.count = 0;
    bb.initialized = true;
    return true;
}

inline size_t basic_block_count()
{
    return static_cast<size_t>(detail::get_bb_state().count);
}

namespace detail {

    inline uint64_t bb_rng_next(uint64_t& state)
    {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        return state;
    }

    inline uint32_t emit_bb_trampoline(uint8_t* tramp,
                                       uint64_t entry_ptr,
                                       uint64_t exec_addr,
                                       uint64_t continuation_abs)
    {
        uint32_t o = 0;
        tramp[o++] = 0x50;
        tramp[o++] = 0x51;
        tramp[o++] = 0x52;
        tramp[o++] = 0x41; tramp[o++] = 0x50;
        tramp[o++] = 0x41; tramp[o++] = 0x51;
        tramp[o++] = 0x41; tramp[o++] = 0x52;
        tramp[o++] = 0x41; tramp[o++] = 0x53;
        tramp[o++] = 0x48; tramp[o++] = 0x83; tramp[o++] = 0xEC; tramp[o++] = 0x28;
        tramp[o++] = 0x48; tramp[o++] = 0xB9;
        memcpy(tramp + o, &entry_ptr, 8); o += 8;
        tramp[o++] = 0x48; tramp[o++] = 0xB8;
        memcpy(tramp + o, &exec_addr, 8); o += 8;
        tramp[o++] = 0xFF; tramp[o++] = 0xD0;
        tramp[o++] = 0x48; tramp[o++] = 0x83; tramp[o++] = 0xC4; tramp[o++] = 0x28;
        tramp[o++] = 0x41; tramp[o++] = 0x5B;
        tramp[o++] = 0x41; tramp[o++] = 0x5A;
        tramp[o++] = 0x41; tramp[o++] = 0x59;
        tramp[o++] = 0x41; tramp[o++] = 0x58;
        tramp[o++] = 0x5A;
        tramp[o++] = 0x59;
        tramp[o++] = 0x58;
        tramp[o++] = 0x48; tramp[o++] = 0x83; tramp[o++] = 0xC4; tramp[o++] = 0x08;
        tramp[o++] = 0x48; tramp[o++] = 0xB8;
        memcpy(tramp + o, &continuation_abs, 8); o += 8;
        tramp[o++] = 0xFF; tramp[o++] = 0xE0;
        return o;
    }

}

inline bool steal_basic_block(void* target_func_base, size_t func_size_hint)
{
    auto& bb = detail::get_bb_state();
    if (!bb.initialized) return false;
    if (bb.count >= detail::MAX_BB_ENTRIES) return false;
    if (target_func_base == nullptr || func_size_hint < 8) return false;

    auto blocks = cfg_extract::extract_blocks(
        target_func_base, func_size_hint,
        reinterpret_cast<uint64_t>(target_func_base), 256);

    if (blocks.size() < 2) return false;

    uint64_t base_u64 = reinterpret_cast<uint64_t>(target_func_base);
    uint8_t seed_buf[16];
    uint64_t tsc = __rdtsc();
    memcpy(seed_buf, &base_u64, 8);
    memcpy(seed_buf + 8, &tsc, 8);
    uint64_t rng_state = integrity::siphash::hash(
        seed_buf, 16, bb.session_key[0], bb.session_key[1]);
    if (rng_state == 0) rng_state = 0x9E3779B97F4A7C15ULL ^ tsc;

    std::vector<size_t> candidate_idx;
    candidate_idx.reserve(blocks.size());
    for (size_t i = 1; i < blocks.size(); ++i)
    {
        const auto& b = blocks[i];
        if (b.length < 6) continue;
        if (b.ends_with_call) continue;
        if (b.has_rip_relative) continue;
        if (b.touches_tls) continue;
        if (b.ends_with_ret) continue;
        candidate_idx.push_back(i);
    }
    if (candidate_idx.empty()) return false;

    uint32_t want = 1u + static_cast<uint32_t>(detail::bb_rng_next(rng_state) % 3u);
    if (want > candidate_idx.size())
        want = static_cast<uint32_t>(candidate_idx.size());

    for (uint32_t s = static_cast<uint32_t>(candidate_idx.size()) - 1; s > 0; --s)
    {
        uint32_t j = static_cast<uint32_t>(detail::bb_rng_next(rng_state) % (s + 1));
        std::swap(candidate_idx[s], candidate_idx[j]);
    }

    bool any_stolen = false;

    for (uint32_t pick = 0; pick < want; ++pick)
    {
        if (bb.count >= detail::MAX_BB_ENTRIES) break;
        if (bb.trampoline_offset + detail::BB_TRAMPOLINE_STRIDE >
            detail::BB_TRAMPOLINE_PAGE_SIZE) break;

        const auto& block = blocks[candidate_idx[pick]];
        if (block.length < 5) continue;
        if (block.length > detail::MAX_BB_ORIGINAL) continue;

        auto* code_ptr = reinterpret_cast<uint8_t*>(block.rva_start);

        auto& entry = bb.entries[bb.count];
        entry.original_addr = block.rva_start;
        entry.rva_end = block.rva_end;
        entry.block_length = block.length;

        uint8_t key_buf[16];
        uint64_t orig_u64 = block.rva_start;
        memcpy(key_buf, &orig_u64, 8);
        memcpy(key_buf + 8, &bb.session_key[0], 8);
        entry.encryption_key = integrity::siphash::hash(
            key_buf, 16, bb.session_key[0], bb.session_key[1]);

        detail::encrypt_buffer(entry.encrypted_original, code_ptr,
                               block.length, entry.encryption_key);

        uint64_t vm_seed = anti_tamper::virtualizer::detail::secure_seed();
        entry.vm_seed = vm_seed;

        entry.pool = anti_tamper::virtualizer::pool_manager::get_or_create(
            entry.original_addr,
            bb.session_key[0] ^ bb.session_key[1] ^ 0xBF58476D1CE4E5B9ULL);

        anti_tamper::virtualizer::detail::vm_state_t tmp_vm;
        anti_tamper::virtualizer::detail::init_vm(tmp_vm, vm_seed, entry.pool);

#ifdef AIDA_STANDALONE
        auto lifted = vm_compiler::x86_lifter::compile_basic_block(
            code_ptr, block.length, block.rva_start,
            vm_seed ^ 0x6A09E667F3BCC908ULL, tmp_vm.opcode_map, entry.pool);
        entry.vm_bytecode = lifted.bytecode;
#else
        vm_compiler::program_t prog;
        prog.set_key(vm_seed ^ 0x6A09E667F3BCC908ULL);
        prog.set_opcode_map(tmp_vm.opcode_map);
        prog.emit_vm_enter();
        prog.emit_vm_exit();
        prog.emit_halt();
        entry.vm_bytecode = prog.finalize();
#endif

        anti_tamper::virtualizer::detail::destroy_vm(tmp_vm);

        auto* tramp = static_cast<uint8_t*>(bb.trampoline_page) + bb.trampoline_offset;
        entry.trampoline_addr = reinterpret_cast<uint64_t>(tramp);

        uint64_t entry_ptr = reinterpret_cast<uint64_t>(&bb.entries[bb.count]);
        uint64_t exec_addr = reinterpret_cast<uint64_t>(&vm_bb_execute);

        uint32_t tramp_len = detail::emit_bb_trampoline(
            tramp, entry_ptr, exec_addr, block.rva_end);
        (void)tramp_len;

        bb.trampoline_offset += detail::BB_TRAMPOLINE_STRIDE;

        DWORD old_prot = 0;
        if (!VirtualProtect(code_ptr, block.length, PAGE_EXECUTE_READWRITE, &old_prot))
            continue;

        int64_t rel = static_cast<int64_t>(entry.trampoline_addr) -
                      static_cast<int64_t>(block.rva_start + 5);
        if (rel > 0x7FFFFFFFLL || rel < -0x80000000LL)
        {
            VirtualProtect(code_ptr, block.length, old_prot, &old_prot);
            continue;
        }

        code_ptr[0] = 0xE8;
        int32_t rel32 = static_cast<int32_t>(rel);
        memcpy(code_ptr + 1, &rel32, 4);
        for (uint32_t i = 5; i < block.length; ++i)
            code_ptr[i] = 0x90;

        VirtualProtect(code_ptr, block.length, old_prot, &old_prot);
        FlushInstructionCache(GetCurrentProcess(), code_ptr, block.length);

        ++bb.count;
        any_stolen = true;
    }

    return any_stolen;
}

inline bool verify_basic_blocks()
{
    auto& bb = detail::get_bb_state();
    if (!bb.initialized) return true;

    for (uint32_t i = 0; i < bb.count; ++i)
    {
        auto& entry = bb.entries[i];

        if (entry.vm_bytecode.empty())
            return false;

        uint8_t decrypted[detail::MAX_BB_ORIGINAL];
        detail::decrypt_buffer(decrypted, entry.encrypted_original,
                               entry.block_length, entry.encryption_key);

        uint64_t orig_hash = integrity::siphash::hash(
            decrypted, entry.block_length,
            bb.session_key[0], bb.session_key[1]);

        uint64_t bc_hash = integrity::siphash::hash(
            entry.vm_bytecode.data(),
            entry.vm_bytecode.size(),
            bb.session_key[0] ^ orig_hash,
            bb.session_key[1] ^ orig_hash);

        if (bc_hash == 0)
            return false;

        auto* original = reinterpret_cast<const uint8_t*>(entry.original_addr);
        if (original[0] != 0xE8)
            return false;

        int32_t rel32 = 0;
        memcpy(&rel32, original + 1, 4);
        uint64_t expected = entry.original_addr + 5 + static_cast<int64_t>(rel32);
        if (expected != entry.trampoline_addr)
            return false;
    }

    return true;
}

inline uint32_t auto_steal_from_self(uint32_t max_functions)
{
    uint32_t stolen = 0;

    HMODULE self_mod = GetModuleHandleW(nullptr);
    if (!self_mod) return 0;

    auto* dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(self_mod);
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return 0;
    auto* nt = reinterpret_cast<const IMAGE_NT_HEADERS*>(
        reinterpret_cast<const uint8_t*>(self_mod) + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) return 0;

    uint64_t text_base = 0;
    uint32_t text_size = 0;
    auto* sec = IMAGE_FIRST_SECTION(nt);
    for (uint32_t i = 0; i < nt->FileHeader.NumberOfSections; ++i)
    {
        if (memcmp(sec[i].Name, ".text", 5) == 0)
        {
            text_base = reinterpret_cast<uint64_t>(self_mod) + sec[i].VirtualAddress;
            text_size = sec[i].Misc.VirtualSize;
            break;
        }
    }
    if (text_base == 0 || text_size < 64) return 0;

    const uint8_t* scan = reinterpret_cast<const uint8_t*>(text_base);
    uint32_t end = text_size;
    uint32_t i = 0;
    while (i + 8 < end && stolen < max_functions)
    {
        bool match = false;
        if (scan[i] == 0x40 && scan[i + 1] == 0x53 &&
            scan[i + 2] == 0x48 && scan[i + 3] == 0x83 && scan[i + 4] == 0xEC)
            match = true;
        else if (scan[i] == 0x48 && scan[i + 1] == 0x89 && scan[i + 2] == 0x5C &&
                 scan[i + 3] == 0x24)
            match = true;
        else if (scan[i] == 0x48 && scan[i + 1] == 0x83 && scan[i + 2] == 0xEC)
            match = true;

        if (match)
        {
            uint64_t func_addr = text_base + i;
            uint32_t hint = 256;
            if (i + hint > end) hint = end - i;

            if (steal_basic_block(reinterpret_cast<void*>(func_addr), hint))
                ++stolen;

            i += hint;
            continue;
        }
        ++i;
    }

    return stolen;
}

}
}
