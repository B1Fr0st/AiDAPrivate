#pragma once

#include <windows.h>
#include <intrin.h>

#include <cstdint>
#include <cstring>
#include <unordered_map>
#include <vector>

#include "virtualizer.hpp"
#include "metamorphic.hpp"

namespace anti_tamper {
namespace vm_jit {

#ifndef ATP_JIT_DISABLED

    static constexpr uint32_t JIT_THRESHOLD     = 256;
    static constexpr uint64_t JIT_CACHE_TTL_MS  = 5000;
    static constexpr uint32_t JIT_MAX_ENCLAVES  = 16;
    static constexpr uint32_t JIT_MAX_BLOCK_LEN = 128;

    struct jit_enclave_t
    {
        void*    base;
        size_t   size;
        uint64_t install_tick;
        uint32_t bc_offset;
        uint32_t bc_len;
        bool     active;
    };

    namespace detail {

        inline std::vector<jit_enclave_t>& enclaves_for(virtualizer::detail::handler_pool_t& pool)
        {
            static std::unordered_map<uint64_t, std::vector<jit_enclave_t>> s_map;
            static std::mutex s_mtx;
            std::lock_guard<std::mutex> lk(s_mtx);
            uint64_t k = reinterpret_cast<uint64_t>(&pool);
            return s_map[k];
        }

        inline std::mutex& enclaves_mutex()
        {
            static std::mutex m;
            return m;
        }

        inline bool integrity_gate()
        {
            if (IsDebuggerPresent())
                return false;
            BOOL remote = FALSE;
            if (CheckRemoteDebuggerPresent(GetCurrentProcess(), &remote) && remote)
                return false;
            return true;
        }

        inline void encode_mov_rax_imm64(std::vector<uint8_t>& buf, uint64_t v)
        {
            buf.push_back(0x48);
            buf.push_back(0xB8);
            uint8_t tmp[8];
            memcpy(tmp, &v, 8);
            buf.insert(buf.end(), tmp, tmp + 8);
        }

        inline void encode_mov_rcx_imm64(std::vector<uint8_t>& buf, uint64_t v)
        {
            buf.push_back(0x48);
            buf.push_back(0xB9);
            uint8_t tmp[8];
            memcpy(tmp, &v, 8);
            buf.insert(buf.end(), tmp, tmp + 8);
        }

        inline void encode_mov_mem_rax_at_rcx_disp(std::vector<uint8_t>& buf, int32_t disp)
        {
            buf.push_back(0x48);
            buf.push_back(0x89);
            buf.push_back(0x81);
            uint8_t tmp[4];
            memcpy(tmp, &disp, 4);
            buf.insert(buf.end(), tmp, tmp + 4);
        }

        inline void encode_mov_rax_from_rcx_disp(std::vector<uint8_t>& buf, int32_t disp)
        {
            buf.push_back(0x48);
            buf.push_back(0x8B);
            buf.push_back(0x81);
            uint8_t tmp[4];
            memcpy(tmp, &disp, 4);
            buf.insert(buf.end(), tmp, tmp + 4);
        }

        inline void encode_mov_rdx_from_rcx_disp(std::vector<uint8_t>& buf, int32_t disp)
        {
            buf.push_back(0x48);
            buf.push_back(0x8B);
            buf.push_back(0x91);
            uint8_t tmp[4];
            memcpy(tmp, &disp, 4);
            buf.insert(buf.end(), tmp, tmp + 4);
        }

        inline void encode_alu_rax_rdx(std::vector<uint8_t>& buf, uint8_t op_modrm_hi)
        {
            buf.push_back(0x48);
            buf.push_back(op_modrm_hi);
            buf.push_back(0xD0);
        }

        inline void encode_ret(std::vector<uint8_t>& buf)
        {
            buf.push_back(0xC3);
        }

        inline void encode_push_nonvol(std::vector<uint8_t>& buf)
        {
            buf.push_back(0x53);
            buf.push_back(0x56);
            buf.push_back(0x57);
            buf.push_back(0x55);
            buf.push_back(0x48); buf.push_back(0x83); buf.push_back(0xEC); buf.push_back(0x20);
        }

        inline void encode_pop_nonvol(std::vector<uint8_t>& buf)
        {
            buf.push_back(0x48); buf.push_back(0x83); buf.push_back(0xC4); buf.push_back(0x20);
            buf.push_back(0x5D);
            buf.push_back(0x5F);
            buf.push_back(0x5E);
            buf.push_back(0x5B);
        }

        inline uint32_t scan_block_len(virtualizer::detail::vm_state_t& vm,
                                       const uint8_t* bc, uint32_t bc_offset, uint32_t bc_size)
        {
            using namespace virtualizer::detail;

            if (bc_offset >= bc_size)
                return 0;

            uint32_t cap = bc_size - bc_offset;
            if (cap > JIT_MAX_BLOCK_LEN)
                cap = JIT_MAX_BLOCK_LEN;

            const uint8_t* reverse_map = vm.reverse_map;
            uint64_t rolling = vm.rolling_key;
            uint32_t p = bc_offset;
            uint32_t end = bc_offset + cap;

            auto fetch = [&](uint32_t& cursor) -> int {
                if (cursor >= end) return -1;
                uint8_t raw = bc[cursor++];
                uint8_t kb = static_cast<uint8_t>(rolling & 0xFF);
                rolling ^= rolling << 13;
                rolling ^= rolling >> 7;
                rolling ^= rolling << 17;
                return raw ^ kb;
            };

            auto skip_bytes = [&](uint32_t n) -> bool {
                for (uint32_t i = 0; i < n; ++i) {
                    if (fetch(p) < 0) return false;
                }
                return true;
            };

            while (p < end)
            {
                int opc = fetch(p);
                if (opc < 0) return 0;
                uint8_t raw_opc = reverse_map[opc];

                if (raw_opc == OP_LOAD_IMM)
                {
                    if (!skip_bytes(1)) return 0;
                    if (!skip_bytes(8)) return 0;
                }
                else if (raw_opc == OP_LOAD_REG || raw_opc == OP_STORE_REG)
                {
                    if (!skip_bytes(2)) return 0;
                }
                else if (raw_opc == OP_ADD || raw_opc == OP_SUB || raw_opc == OP_XOR
                      || raw_opc == OP_NAND || raw_opc == OP_NOR)
                {
                    if (!skip_bytes(3)) return 0;
                }
                else if (raw_opc == OP_SHL || raw_opc == OP_SHR)
                {
                    if (!skip_bytes(3)) return 0;
                }
                else if (raw_opc == OP_JMP || raw_opc == OP_JZ || raw_opc == OP_JNZ)
                {
                    if (!skip_bytes(4)) return 0;
                    return p - bc_offset;
                }
                else if (raw_opc == OP_VRET)
                {
                    return p - bc_offset;
                }
                else
                {
                    return 0;
                }
            }

            return 0;
        }

    }

    inline bool should_jit(virtualizer::detail::handler_pool_t& pool, uint32_t bc_offset)
    {
        if (!pool.hot_block_counts)
            pool.hot_block_counts = new std::unordered_map<uint32_t, uint32_t>();
        auto* m = pool.hot_block_counts;
        uint32_t& n = (*m)[bc_offset];
        ++n;
        return n >= JIT_THRESHOLD;
    }

    inline void expire_enclaves(virtualizer::detail::handler_pool_t& pool)
    {
        auto& vec = detail::enclaves_for(pool);
        uint64_t now = GetTickCount64();
        for (auto& e : vec)
        {
            if (!e.active) continue;
            if (now - e.install_tick > JIT_CACHE_TTL_MS)
            {
                if (e.base)
                {
                    RtlSecureZeroMemory(e.base, e.size);
                    VirtualFree(e.base, 0, MEM_RELEASE);
                }
                e.base = nullptr;
                e.size = 0;
                e.active = false;
            }
        }
    }

    inline bool compile_block(virtualizer::detail::vm_state_t& vm,
                              const uint8_t* bc, uint32_t bc_offset,
                              uint32_t bc_len, jit_enclave_t& out)
    {
        if (!detail::integrity_gate())
            return false;

        std::vector<uint8_t> code;
        code.reserve(256);
        detail::encode_push_nonvol(code);

        uint32_t rip = bc_offset;
        uint64_t rolling = vm.rolling_key;
        const uint8_t* opcode_map = vm.opcode_map;
        const uint8_t* reverse_map = vm.reverse_map;
        (void)opcode_map;

        auto fetch_decrypted = [&](uint32_t& p) -> int {
            if (p >= bc_offset + bc_len) return -1;
            uint8_t raw = bc[p++];
            uint8_t kb = static_cast<uint8_t>(rolling & 0xFF);
            rolling ^= rolling << 13;
            rolling ^= rolling >> 7;
            rolling ^= rolling << 17;
            return raw ^ kb;
        };

        auto fetch_u32 = [&](uint32_t& p, uint32_t& out_u) -> bool {
            uint8_t b[4];
            for (int i = 0; i < 4; ++i) {
                int v = fetch_decrypted(p);
                if (v < 0) return false;
                b[i] = static_cast<uint8_t>(v);
            }
            memcpy(&out_u, b, 4);
            return true;
        };

        bool terminated = false;

        while (rip < bc_offset + bc_len && !terminated)
        {
            int opc = fetch_decrypted(rip);
            if (opc < 0) return false;
            uint8_t raw_opc = reverse_map[opc];

            using namespace virtualizer::detail;

            if (raw_opc == OP_LOAD_IMM)
            {
                int rg = fetch_decrypted(rip);
                if (rg < 0) return false;
                uint8_t b[8];
                for (int i = 0; i < 8; ++i) {
                    int v = fetch_decrypted(rip);
                    if (v < 0) return false;
                    b[i] = static_cast<uint8_t>(v);
                }
                uint64_t imm;
                memcpy(&imm, b, 8);
                detail::encode_mov_rax_imm64(code, imm);
                detail::encode_mov_mem_rax_at_rcx_disp(code, static_cast<int32_t>((rg & 0x0F) * 8));
            }
            else if (raw_opc == OP_LOAD_REG || raw_opc == OP_STORE_REG)
            {
                int dst = fetch_decrypted(rip);
                int src = fetch_decrypted(rip);
                if (dst < 0 || src < 0) return false;
                detail::encode_mov_rax_from_rcx_disp(code, static_cast<int32_t>((src & 0x0F) * 8));
                detail::encode_mov_mem_rax_at_rcx_disp(code, static_cast<int32_t>((dst & 0x0F) * 8));
            }
            else if (raw_opc == OP_ADD || raw_opc == OP_SUB || raw_opc == OP_XOR
                  || raw_opc == OP_NAND || raw_opc == OP_NOR)
            {
                int dst = fetch_decrypted(rip);
                int a = fetch_decrypted(rip);
                int b = fetch_decrypted(rip);
                if (dst < 0 || a < 0 || b < 0) return false;
                detail::encode_mov_rax_from_rcx_disp(code, static_cast<int32_t>((a & 0x0F) * 8));
                detail::encode_mov_rdx_from_rcx_disp(code, static_cast<int32_t>((b & 0x0F) * 8));
                if (raw_opc == OP_ADD)
                    detail::encode_alu_rax_rdx(code, 0x01);
                else if (raw_opc == OP_SUB)
                    detail::encode_alu_rax_rdx(code, 0x29);
                else if (raw_opc == OP_XOR)
                    detail::encode_alu_rax_rdx(code, 0x31);
                else if (raw_opc == OP_NAND)
                {
                    detail::encode_alu_rax_rdx(code, 0x21);
                    code.push_back(0x48); code.push_back(0xF7); code.push_back(0xD0);
                }
                else
                {
                    detail::encode_alu_rax_rdx(code, 0x09);
                    code.push_back(0x48); code.push_back(0xF7); code.push_back(0xD0);
                }
                detail::encode_mov_mem_rax_at_rcx_disp(code, static_cast<int32_t>((dst & 0x0F) * 8));
            }
            else if (raw_opc == OP_SHL || raw_opc == OP_SHR)
            {
                int dst = fetch_decrypted(rip);
                int src = fetch_decrypted(rip);
                int amt = fetch_decrypted(rip);
                if (dst < 0 || src < 0 || amt < 0) return false;
                detail::encode_mov_rax_from_rcx_disp(code, static_cast<int32_t>((src & 0x0F) * 8));
                detail::encode_mov_rdx_from_rcx_disp(code, static_cast<int32_t>((amt & 0x0F) * 8));
                code.push_back(0x48); code.push_back(0x87); code.push_back(0xCA);
                if (raw_opc == OP_SHL)
                {
                    code.push_back(0x48); code.push_back(0xD3); code.push_back(0xE0);
                }
                else
                {
                    code.push_back(0x48); code.push_back(0xD3); code.push_back(0xE8);
                }
                code.push_back(0x48); code.push_back(0x87); code.push_back(0xCA);
                detail::encode_mov_mem_rax_at_rcx_disp(code, static_cast<int32_t>((dst & 0x0F) * 8));
            }
            else if (raw_opc == OP_JMP || raw_opc == OP_JZ || raw_opc == OP_JNZ)
            {
                uint32_t tgt = 0;
                if (!fetch_u32(rip, tgt)) return false;
                (void)tgt;
                terminated = true;
            }
            else if (raw_opc == OP_VRET)
            {
                terminated = true;
            }
            else
            {
                return false;
            }
        }

        detail::encode_pop_nonvol(code);
        detail::encode_ret(code);

        size_t sz = code.size();
        void* exec = VirtualAlloc(nullptr, sz, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        if (!exec) return false;
        memcpy(exec, code.data(), sz);
        DWORD old = 0;
        if (!VirtualProtect(exec, sz, PAGE_EXECUTE_READ, &old))
        {
            RtlSecureZeroMemory(exec, sz);
            VirtualFree(exec, 0, MEM_RELEASE);
            return false;
        }
        FlushInstructionCache(GetCurrentProcess(), exec, sz);

        out.base = exec;
        out.size = sz;
        out.install_tick = GetTickCount64();
        out.bc_offset = bc_offset;
        out.bc_len = bc_len;
        out.active = true;
        return true;
    }

    inline int64_t execute_enclave(jit_enclave_t& enclave, virtualizer::detail::vm_state_t& vm)
    {
        if (!enclave.active || !enclave.base)
            return 0;
        using fn_t = int64_t(*)(uint64_t*);
        auto fn = reinterpret_cast<fn_t>(enclave.base);
        return fn(&vm.regs[0]);
    }

    inline void advance_rip_and_count(virtualizer::detail::vm_state_t& vm,
                                      const jit_enclave_t& enclave,
                                      uint32_t bc_size)
    {
        uint64_t new_rip = static_cast<uint64_t>(enclave.bc_offset) + static_cast<uint64_t>(enclave.bc_len);
        if (new_rip > bc_size)
            new_rip = bc_size;
        vm.rip = new_rip;
        vm.insn_count += enclave.bc_len / 2;
    }

    inline bool attach_if_hot(virtualizer::detail::vm_state_t& vm,
                              const uint8_t* bc, uint32_t bc_offset, uint32_t bc_size)
    {
        virtualizer::detail::handler_pool_t& pool =
            vm.pool ? *vm.pool : virtualizer::detail::g_default_pool;

        if (!should_jit(pool, bc_offset))
            return false;

        auto& vec = detail::enclaves_for(pool);
        if (vec.size() >= JIT_MAX_ENCLAVES)
            return false;

        uint32_t bc_len = detail::scan_block_len(vm, bc, bc_offset, bc_size);
        if (bc_len == 0)
            return false;

        jit_enclave_t enc{};
        if (!compile_block(vm, bc, bc_offset, bc_len, enc))
            return false;

        vec.push_back(enc);
        jit_enclave_t& installed = vec.back();
        execute_enclave(installed, vm);
        advance_rip_and_count(vm, installed, bc_size);
        return true;
    }

    inline bool jit_entry(virtualizer::detail::vm_state_t& vm,
                          const uint8_t* bc, uint32_t bc_size)
    {
        if (vm.halted || vm.rip >= bc_size)
            return false;

        virtualizer::detail::handler_pool_t& pool =
            vm.pool ? *vm.pool : virtualizer::detail::g_default_pool;

        expire_enclaves(pool);

        uint32_t bc_offset = static_cast<uint32_t>(vm.rip);

        auto& vec = detail::enclaves_for(pool);
        for (auto& e : vec)
        {
            if (!e.active) continue;
            if (e.bc_offset != bc_offset) continue;
            if (!e.base) continue;
            execute_enclave(e, vm);
            advance_rip_and_count(vm, e, bc_size);
            return true;
        }

        return attach_if_hot(vm, bc, bc_offset, bc_size);
    }

    inline bool s_hook_installed = []() {
        virtualizer::detail::g_jit_hook = &jit_entry;
        return true;
    }();

#endif

}
}
