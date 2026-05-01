#pragma once

#include <windows.h>
#include <intrin.h>

#include <array>
#include <atomic>
#include <cstdint>
#include <cstring>
#include <mutex>
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
    static constexpr uint32_t JIT_SELF_ERASE_EXECUTIONS = 1024;
    static constexpr uint32_t JIT_DECOY_PERMILLE = 50;
    static constexpr uint64_t JIT_DECOY_KILL_DELAY_MS = 60000;

    struct jit_enclave_t
    {
        void*    base;
        size_t   size;
        uint64_t install_tick;
        uint32_t bc_offset;
        uint32_t bc_len;
        uint32_t exec_count;
        uint32_t shape_seed;
        uint8_t  hmac_tag[32];
        bool     active;
        bool     decoy;
    };

    struct decoy_violation_state_t
    {
        std::atomic<bool>     triggered;
        std::atomic<uint64_t> trigger_tick;
        std::atomic<uint32_t> hit_count;
    };

    namespace detail {

        inline decoy_violation_state_t& violation_state()
        {
            static decoy_violation_state_t s{ {false}, {0}, {0} };
            return s;
        }

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

        inline void compute_block_hmac(virtualizer::detail::handler_pool_t& pool,
                                        const void* code, size_t code_size,
                                        uint32_t bc_offset, uint32_t bc_len,
                                        uint32_t shape_seed,
                                        uint8_t out_tag[32])
        {
            uint8_t hmac_key[32];
            uint8_t key_input[24];
            memcpy(key_input, &pool.pool_seed, 8);
            uint64_t pool_addr = reinterpret_cast<uint64_t>(&pool);
            memcpy(key_input + 8, &pool_addr, 8);
            uint64_t magic = 0x6A09E667F3BCC908ULL;
            memcpy(key_input + 16, &magic, 8);
            virtualizer::detail::hmac_sha256(state::g_vm_master_key, 32,
                                              key_input, 24, hmac_key);

            std::vector<uint8_t> mac_input;
            mac_input.reserve(code_size + 16);
            mac_input.resize(code_size);
            memcpy(mac_input.data(), code, code_size);
            uint8_t footer[16];
            memcpy(footer, &bc_offset, 4);
            memcpy(footer + 4, &bc_len, 4);
            memcpy(footer + 8, &shape_seed, 4);
            uint32_t code_size_u32 = static_cast<uint32_t>(code_size);
            memcpy(footer + 12, &code_size_u32, 4);
            mac_input.insert(mac_input.end(), footer, footer + 16);

            virtualizer::detail::hmac_sha256(hmac_key, 32,
                                              mac_input.data(),
                                              static_cast<uint32_t>(mac_input.size()),
                                              out_tag);

            SecureZeroMemory(hmac_key, 32);
            SecureZeroMemory(key_input, 24);
        }

        inline bool verify_block_hmac(virtualizer::detail::handler_pool_t& pool,
                                       const jit_enclave_t& e)
        {
            if (!e.base || !e.active) return false;

            uint8_t expected[32];
            compute_block_hmac(pool, e.base, e.size, e.bc_offset, e.bc_len,
                               e.shape_seed, expected);

            uint8_t diff = 0;
            for (int i = 0; i < 32; ++i) diff |= (expected[i] ^ e.hmac_tag[i]);
            SecureZeroMemory(expected, 32);
            return diff == 0;
        }

        inline uint32_t derive_shape_seed()
        {
            uint8_t buf[4];
            if (!virtualizer::detail::bcrypt_random(buf, 4))
            {
                uint32_t fb = static_cast<uint32_t>(__rdtsc());
                memcpy(buf, &fb, 4);
            }
            uint32_t out;
            memcpy(&out, buf, 4);
            return out;
        }

        inline bool should_be_decoy(virtualizer::detail::handler_pool_t& pool,
                                     uint32_t bc_offset)
        {
            uint8_t draw[2];
            if (!virtualizer::detail::bcrypt_random(draw, 2))
            {
                uint64_t fb = __rdtsc() ^ static_cast<uint64_t>(bc_offset);
                memcpy(draw, &fb, 2);
            }
            uint16_t v;
            memcpy(&v, draw, 2);
            uint32_t bucket = static_cast<uint32_t>(v) % 1000u;
            (void)pool;
            return bucket < JIT_DECOY_PERMILLE;
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

        inline std::array<uint8_t, 4> derive_register_allocation(uint32_t shape_seed)
        {
            std::array<uint8_t, 4> regs{ 0xC1, 0x91, 0xC1, 0x81 };
            uint64_t state = static_cast<uint64_t>(shape_seed) * 0x9E3779B97F4A7C15ULL;
            state ^= state << 13; state ^= state >> 7; state ^= state << 17;
            uint8_t selector = static_cast<uint8_t>(state & 0xFF);
            switch (selector & 0x07)
            {
            case 0: regs = { 0xC1, 0x91, 0xC1, 0x81 }; break;
            case 1: regs = { 0xC1, 0x99, 0xC1, 0x89 }; break;
            case 2: regs = { 0xC8, 0x90, 0xC8, 0x80 }; break;
            case 3: regs = { 0xC1, 0x91, 0xC8, 0x88 }; break;
            case 4: regs = { 0xC1, 0x91, 0xC1, 0x81 }; break;
            case 5: regs = { 0xC1, 0x91, 0xC1, 0x89 }; break;
            case 6: regs = { 0xC1, 0x99, 0xC1, 0x81 }; break;
            default:regs = { 0xC1, 0x91, 0xC1, 0x81 }; break;
            }
            return regs;
        }

        inline void emit_decoy_payload(std::vector<uint8_t>& code, uint32_t shape_seed)
        {
            uint64_t marker_addr = reinterpret_cast<uint64_t>(&violation_state());
            encode_push_nonvol(code);
            encode_mov_rcx_imm64(code, marker_addr);
            uint64_t now_imm = static_cast<uint64_t>(shape_seed) | 0x8000000000000000ULL;
            encode_mov_rax_imm64(code, now_imm);
            code.push_back(0x48); code.push_back(0x89); code.push_back(0x01);
            encode_pop_nonvol(code);
            encode_ret(code);
        }

        inline uint32_t overlap_rng_step(uint64_t& s)
        {
            if (s == 0u) { s = 0x9E3779B97F4A7C15ULL; }
            uint64_t x = s;
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            s = x;
            return static_cast<uint32_t>(x);
        }

        inline void emit_overlap_pattern_a(std::vector<uint8_t>& code, uint64_t& s)
        {
            uint32_t r = overlap_rng_step(s);
            uint32_t emit_len = 4u + (r % 3u);
            static const uint8_t kPrefixSeeds[][3] = {
                { 0x48u, 0x8Bu, 0x05u },
                { 0x48u, 0x89u, 0x05u },
                { 0x48u, 0x83u, 0xC4u },
                { 0x66u, 0x0Fu, 0x6Eu },
                { 0x49u, 0xBAu, 0x90u },
                { 0xF3u, 0x48u, 0xA5u },
                { 0x48u, 0xC7u, 0xC0u },
                { 0x4Cu, 0x8Du, 0x35u }
            };
            uint32_t pick = (r >> 8) % static_cast<uint32_t>(sizeof(kPrefixSeeds) / sizeof(kPrefixSeeds[0]));
            uint8_t skip_off = static_cast<uint8_t>(emit_len);
            code.push_back(0xEBu);
            code.push_back(skip_off);
            code.push_back(kPrefixSeeds[pick][0]);
            code.push_back(kPrefixSeeds[pick][1]);
            code.push_back(kPrefixSeeds[pick][2]);
            code.push_back(static_cast<uint8_t>(overlap_rng_step(s) & 0xFFu));
            for (uint32_t i = 4u; i < emit_len; ++i) {
                code.push_back(static_cast<uint8_t>(overlap_rng_step(s) & 0xFFu));
            }
        }

        inline void emit_overlap_pattern_b(std::vector<uint8_t>& code, uint64_t& s)
        {
            uint32_t r = overlap_rng_step(s);
            uint32_t emit_len = 3u + (r % 5u);
            uint8_t skip_off = static_cast<uint8_t>(emit_len);
            code.push_back(0x9Cu);
            code.push_back(0x41u);
            code.push_back(0x52u);
            code.push_back(0x4Du);
            code.push_back(0x31u);
            code.push_back(0xD2u);
            code.push_back(0x74u);
            code.push_back(skip_off);
            static const uint8_t kFragmentSeeds[][2] = {
                { 0xC3u, 0x90u },
                { 0xCCu, 0xCCu },
                { 0x0Fu, 0x0Bu },
                { 0xCDu, 0x29u },
                { 0xF4u, 0x90u },
                { 0xEBu, 0xFEu }
            };
            uint32_t pick = (r >> 11) % static_cast<uint32_t>(sizeof(kFragmentSeeds) / sizeof(kFragmentSeeds[0]));
            code.push_back(kFragmentSeeds[pick][0]);
            code.push_back(kFragmentSeeds[pick][1]);
            for (uint32_t i = 2u; i < emit_len; ++i) {
                code.push_back(static_cast<uint8_t>(overlap_rng_step(s) & 0xFFu));
            }
            code.push_back(0x41u);
            code.push_back(0x5Au);
            code.push_back(0x9Du);
        }

        inline void emit_overlap_pattern_c(std::vector<uint8_t>& code, uint64_t& s)
        {
            code.push_back(0xEBu);
            code.push_back(0x09u);
            code.push_back(0x49u);
            code.push_back(0xBAu);
            code.push_back(0xEBu);
            code.push_back(0x05u);
            for (uint32_t i = 0u; i < 5u; ++i) {
                code.push_back(static_cast<uint8_t>(overlap_rng_step(s) & 0xFFu));
            }
            code.push_back(0xEBu);
            code.push_back(0x05u);
            code.push_back(0x90u);
            code.push_back(static_cast<uint8_t>(overlap_rng_step(s) & 0xFFu));
            code.push_back(static_cast<uint8_t>(overlap_rng_step(s) & 0xFFu));
            code.push_back(static_cast<uint8_t>(overlap_rng_step(s) & 0xFFu));
            code.push_back(static_cast<uint8_t>(overlap_rng_step(s) & 0xFFu));
        }

        inline void emit_overlap_dispatch(std::vector<uint8_t>& code, uint64_t& s)
        {
            uint32_t pick = overlap_rng_step(s) % 3u;
            switch (pick) {
                case 0: emit_overlap_pattern_a(code, s); break;
                case 1: emit_overlap_pattern_b(code, s); break;
                default: emit_overlap_pattern_c(code, s); break;
            }
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

        inline void self_erase_enclave(jit_enclave_t& e)
        {
            if (!e.base) return;
            DWORD old = 0;
            VirtualProtect(e.base, e.size, PAGE_READWRITE, &old);
            RtlSecureZeroMemory(e.base, e.size);
            VirtualFree(e.base, 0, MEM_RELEASE);
            e.base = nullptr;
            e.size = 0;
            e.active = false;
            SecureZeroMemory(e.hmac_tag, 32);
        }

    }

    inline bool decoy_violation_active()
    {
        return detail::violation_state().triggered.load(std::memory_order_acquire);
    }

    inline bool decoy_violation_should_terminate(uint64_t now_tick)
    {
        auto& v = detail::violation_state();
        if (!v.triggered.load(std::memory_order_acquire)) return false;
        uint64_t when = v.trigger_tick.load(std::memory_order_acquire);
        if (when == 0) return false;
        return now_tick >= when + JIT_DECOY_KILL_DELAY_MS;
    }

    inline uint32_t decoy_violation_hit_count()
    {
        return detail::violation_state().hit_count.load(std::memory_order_acquire);
    }

    inline void clear_decoy_violation()
    {
        auto& v = detail::violation_state();
        v.triggered.store(false, std::memory_order_release);
        v.trigger_tick.store(0, std::memory_order_release);
        v.hit_count.store(0, std::memory_order_release);
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
                detail::self_erase_enclave(e);
        }
    }

    inline bool compile_block(virtualizer::detail::vm_state_t& vm,
                              const uint8_t* bc, uint32_t bc_offset,
                              uint32_t bc_len, jit_enclave_t& out,
                              bool emit_as_decoy)
    {
        if (!detail::integrity_gate())
            return false;

        out.shape_seed = detail::derive_shape_seed();
        out.exec_count = 0;
        out.decoy = emit_as_decoy;

        std::vector<uint8_t> code;
        code.reserve(256);

        if (emit_as_decoy)
        {
            detail::emit_decoy_payload(code, out.shape_seed);
        }
        else
        {
            auto regs = detail::derive_register_allocation(out.shape_seed);
            (void)regs;

            detail::encode_push_nonvol(code);

            uint64_t overlap_state = static_cast<uint64_t>(out.shape_seed) * 0xC6BC279692B5C323ULL
                                   ^ static_cast<uint64_t>(bc_offset) * 0x9E3779B97F4A7C15ULL
                                   ^ 0x6A09E667F3BCC908ULL;
            detail::emit_overlap_dispatch(code, overlap_state);

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
            uint32_t overlap_phase = 0u;

            while (rip < bc_offset + bc_len && !terminated)
            {
                if (((overlap_phase ^ static_cast<uint32_t>(overlap_state)) & 0x03u) == 0u) {
                    detail::emit_overlap_dispatch(code, overlap_state);
                }
                ++overlap_phase;

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

            detail::emit_overlap_dispatch(code, overlap_state);
            detail::encode_pop_nonvol(code);
            detail::encode_ret(code);
        }

        size_t sz = code.size();
        void* exec = VirtualAlloc(nullptr, sz, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        if (!exec) return false;
        memcpy(exec, code.data(), sz);

        detail::compute_block_hmac(*vm.pool, exec, sz, bc_offset, bc_len,
                                    out.shape_seed, out.hmac_tag);

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

        if (!detail::verify_block_hmac(*vm.pool, enclave))
        {
            detail::self_erase_enclave(enclave);
            virtualizer::detail::write_vreg(vm, 0, 0xDEADBEEFDEADBEEFULL);
            vm.halted = true;
            return 0;
        }

        if (enclave.decoy)
        {
            auto& v = detail::violation_state();
            v.triggered.store(true, std::memory_order_release);
            uint64_t expected = 0;
            v.trigger_tick.compare_exchange_strong(expected, GetTickCount64());
            v.hit_count.fetch_add(1, std::memory_order_acq_rel);
        }

        using fn_t = int64_t(*)(uint64_t*);
        auto fn = reinterpret_cast<fn_t>(enclave.base);
        int64_t r = fn(&vm.regs[0]);

        ++enclave.exec_count;
        if (enclave.exec_count >= JIT_SELF_ERASE_EXECUTIONS)
            detail::self_erase_enclave(enclave);
        return r;
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

        bool make_decoy = detail::should_be_decoy(pool, bc_offset);

        jit_enclave_t enc{};
        if (!compile_block(vm, bc, bc_offset, bc_len, enc, make_decoy))
            return false;

        vec.push_back(enc);
        jit_enclave_t& installed = vec.back();
        execute_enclave(installed, vm);
        if (!installed.decoy)
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
            if (e.decoy) continue;
            execute_enclave(e, vm);
            if (e.active)
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
