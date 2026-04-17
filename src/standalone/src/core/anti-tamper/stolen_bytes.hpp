#pragma once

#include <windows.h>
#include <intrin.h>

#include <cstdint>
#include <cstring>
#include <vector>

#include "integrity.hpp"
#include "virtualizer.hpp"
#include "vm_compiler.hpp"

namespace anti_tamper {
namespace stolen_bytes {

namespace detail {

    static constexpr uint32_t MAX_STOLEN = 32;
    static constexpr uint32_t MAX_ENTRIES = 64;

    struct stolen_entry_t
    {
        uint64_t original_addr;
        uint8_t  encrypted_prologue[MAX_STOLEN];
        uint32_t prologue_len;
        uint64_t trampoline_addr;
        uint64_t encryption_key;
        std::vector<uint8_t> vm_bytecode;
        uint64_t vm_seed;
        uint64_t continuation_addr;
    };

    struct stolen_state_t
    {
        stolen_entry_t entries[MAX_ENTRIES];
        uint32_t count;
        void* trampoline_page;
        uint32_t trampoline_offset;
        uint64_t session_key[2];
        bool initialized;
    };

    inline stolen_state_t& get_state()
    {
        static stolen_state_t s{};
        return s;
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

    inline void encrypt_prologue(uint8_t* dst, const uint8_t* src, uint32_t len, uint64_t key)
    {
        uint64_t rolling = key;
        for (uint32_t i = 0; i < len; ++i)
        {
            dst[i] = src[i] ^ static_cast<uint8_t>(rolling);
            rolling ^= rolling << 13;
            rolling ^= rolling >> 7;
            rolling ^= rolling << 17;
        }
    }

    inline void decrypt_prologue(uint8_t* dst, const uint8_t* src, uint32_t len, uint64_t key)
    {
        encrypt_prologue(dst, src, len, key);
    }

}

inline void vm_prologue_execute(detail::stolen_entry_t* entry)
{
    if (!entry || entry->vm_bytecode.empty())
        return;

    anti_tamper::virtualizer::detail::vm_state_t vm;
    anti_tamper::virtualizer::detail::init_vm(vm, entry->vm_seed);
    anti_tamper::virtualizer::detail::vm_execute(
        vm, entry->vm_bytecode.data(),
        static_cast<uint32_t>(entry->vm_bytecode.size()));
    anti_tamper::virtualizer::detail::destroy_vm(vm);

    auto cont = reinterpret_cast<void(*)()>(
        static_cast<uintptr_t>(entry->continuation_addr));
    cont();
}

inline bool initialize()
{
    auto& s = detail::get_state();
    if (s.initialized) return true;

    integrity::get_session_keys(s.session_key[0], s.session_key[1]);

    s.trampoline_page = VirtualAlloc(nullptr, 4096,
        MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!s.trampoline_page) return false;

    s.trampoline_offset = 0;
    s.count = 0;
    s.initialized = true;
    return true;
}

inline bool steal_function_prologue(void* target_func)
{
    auto& s = detail::get_state();
    if (!s.initialized || s.count >= detail::MAX_ENTRIES)
        return false;

    auto* code = static_cast<uint8_t*>(target_func);
    uint32_t steal_len = detail::compute_prologue_length(code, 14);
    if (steal_len < 5 || steal_len > detail::MAX_STOLEN)
        return false;

    if (s.trampoline_offset + 64 > 4096)
        return false;

    auto& entry = s.entries[s.count];
    entry.original_addr = reinterpret_cast<uint64_t>(code);
    entry.prologue_len = steal_len;
    entry.continuation_addr = reinterpret_cast<uint64_t>(code) + steal_len;

    uint8_t buf[16];
    uint64_t addr_val = reinterpret_cast<uint64_t>(code);
    memcpy(buf, &addr_val, 8);
    memcpy(buf + 8, &s.session_key[0], 8);
    entry.encryption_key = integrity::siphash::hash(
        buf, 16, s.session_key[0], s.session_key[1]);

    detail::encrypt_prologue(entry.encrypted_prologue, code, steal_len, entry.encryption_key);

    uint64_t vm_seed = anti_tamper::virtualizer::detail::secure_seed();
    entry.vm_seed = vm_seed;

    anti_tamper::virtualizer::detail::vm_state_t tmp_vm;
    anti_tamper::virtualizer::detail::init_vm(tmp_vm, vm_seed);

#ifdef AIDA_STANDALONE
    auto lifted = vm_compiler::x86_lifter::compile_function(
        code, steal_len, reinterpret_cast<uint64_t>(code),
        vm_seed ^ 0x6A09E667F3BCC908ULL, tmp_vm.opcode_map);
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
    if (!s.initialized) return true;

    for (uint32_t i = 0; i < s.count; ++i)
    {
        auto& entry = s.entries[i];

        if (entry.vm_bytecode.empty())
            return false;

        uint8_t decrypted[detail::MAX_STOLEN];
        detail::decrypt_prologue(decrypted, entry.encrypted_prologue,
                                  entry.prologue_len, entry.encryption_key);

        uint64_t prologue_hash = integrity::siphash::hash(
            decrypted, entry.prologue_len,
            s.session_key[0], s.session_key[1]);

        uint64_t bc_hash = integrity::siphash::hash(
            entry.vm_bytecode.data(),
            entry.vm_bytecode.size(),
            s.session_key[0] ^ prologue_hash,
            s.session_key[1] ^ prologue_hash);

        if (bc_hash == 0)
            return false;

        auto* original = reinterpret_cast<const uint8_t*>(entry.original_addr);
        if (original[0] != 0xFF || original[1] != 0x25)
            return false;
    }

    return true;
}

inline void shutdown()
{
    auto& s = detail::get_state();
    if (s.trampoline_page)
    {
        volatile uint8_t* p = static_cast<volatile uint8_t*>(s.trampoline_page);
        for (uint32_t i = 0; i < 4096; ++i) p[i] = 0xCC;
        VirtualFree(s.trampoline_page, 0, MEM_RELEASE);
        s.trampoline_page = nullptr;
    }
    s.initialized = false;
}

}
}
