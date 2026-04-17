#pragma once

#include <windows.h>
#include <bcrypt.h>
#include <intrin.h>

#include <atomic>
#include <cstdint>
#include <cstring>
#include <vector>

#include "integrity.hpp"
#include "metamorphic.hpp"
#include "../../../obfuscation.hpp"

namespace anti_tamper {
namespace virtualizer
{

namespace detail
{

    static constexpr uint32_t HANDLER_VARIANTS = 12;
    static constexpr uint32_t CONTEXT_SHUFFLE_INTERVAL = 64;
    static constexpr uint32_t HANDLER_POOL_SIZE = 4096;
    static constexpr uint64_t HANDLER_CRYPT_MAGIC = 0x3C6EF372FE94F82BULL;


    struct vm_continuation_t
    {
        uintptr_t   next_handler;
        uint64_t    chain_nonce;
    };


    struct context_crypt_t
    {
        uint64_t    reg_mask;
        uint64_t    flags_mask;
        uint64_t    rsp_mask;
        bool        encrypted;
    };

    struct vflags_t
    {
        uint8_t CF : 1;
        uint8_t ZF : 1;
        uint8_t SF : 1;
        uint8_t OF : 1;
        uint8_t PF : 1;
        uint8_t AF : 1;
        uint8_t _pad : 2;
    };

    struct vm_state_t
    {
        uint64_t regs[16];
        uint64_t rsp;
        uint64_t rip;
        vflags_t vflags;
        uint8_t* stack;
        uint32_t stack_size;
        uint8_t opcode_map[256];
        uint8_t reverse_map[256];
        uint64_t rolling_key;
        uint32_t insn_count;
        uint32_t max_insn;
        bool halted;

        uint8_t reg_shuffle[16];
        uint8_t reg_unshuffle[16];
        uint64_t reg_xor_key;
        uint64_t handler_chain_key;
        uint64_t context_entropy;
        uint32_t shuffle_counter;


        vm_continuation_t   continuation;
        context_crypt_t     ctx_crypt;
    };

    enum vm_ops : uint8_t
    {
        OP_NOP = 0x00,
        OP_LOAD_IMM = 0x01,
        OP_LOAD_REG = 0x02,
        OP_STORE_REG = 0x03,
        OP_NAND = 0x04,
        OP_NOR = 0x05,
        OP_XOR = 0x06,
        OP_SHL = 0x07,
        OP_SHR = 0x08,
        OP_NOT = 0x09,
        OP_CMP = 0x0A,
        OP_JMP = 0x0B,
        OP_JZ = 0x0C,
        OP_JNZ = 0x0D,
        OP_PUSH = 0x0E,
        OP_POP = 0x0F,
        OP_HASH = 0x10,
        OP_RDTSC = 0x11,
        OP_SIPHASH = 0x12,
        OP_HALT = 0x13,
        OP_TRAP = 0x14,
        OP_VERIFY = 0x15,
        OP_ROL = 0x16,
        OP_ROR = 0x17,
        OP_LOAD_MEM = 0x18,
        OP_STORE_MEM = 0x19,
        OP_ADD = 0x1A,
        OP_SUB = 0x1B,
        OP_VM_ENTER = 0x1C,
        OP_VM_EXIT  = 0x1D,
        OP_LOAD_IMM8  = 0x1E,
        OP_LOAD_IMM16 = 0x1F,
        OP_LOAD_IMM32 = 0x20,
        OP_MUL     = 0x21,
        OP_IMUL    = 0x22,
        OP_DIV     = 0x23,
        OP_IDIV    = 0x24,
        OP_CMOV    = 0x25,
        OP_SETCC   = 0x26,
        OP_VCALL   = 0x27,
        OP_VRET    = 0x28,
        OP_JL      = 0x29,
        OP_JLE     = 0x2A,
        OP_JG      = 0x2B,
        OP_JGE     = 0x2C,
        OP_JB      = 0x2D,
        OP_JBE     = 0x2E,
        OP_JS      = 0x2F,
        OP_JO      = 0x30,
        OP_LAHF    = 0x31,
        OP_SAHF    = 0x32,
        OP_JNB     = 0x33,
        OP_JNBE    = 0x34,
        OP_MAX
    };

    inline bool bcrypt_random(uint8_t* buf, uint32_t len)
    {
        return BCryptGenRandom(nullptr, buf, len, BCRYPT_USE_SYSTEM_PREFERRED_RNG) == 0;
    }

    inline bool hmac_sha256(const uint8_t* key, uint32_t key_len,
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

    inline void hkdf_expand_sha256(const uint8_t prk[32], const uint8_t* info,
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
            hmac_sha256(prk, 32, input, input_len, t);
            t_len = 32;
            uint32_t copy = (okm_len - pos < 32) ? (okm_len - pos) : 32;
            memcpy(okm + pos, t, copy);
            pos += copy;
            counter++;
        }
    }

    inline uint64_t secure_seed()
    {
        uint8_t buf[32];
        if (!bcrypt_random(buf, 32))
            return __rdtsc() ^ GetCurrentProcessId();
        uint64_t seed;
        memcpy(&seed, buf, 8);
        uint64_t mix;
        memcpy(&mix, buf + 8, 8);
        seed ^= mix;
        memcpy(&mix, buf + 16, 8);
        seed ^= _rotl64(mix, 17);
        memcpy(&mix, buf + 24, 8);
        seed ^= _rotr64(mix, 23);
        SecureZeroMemory(buf, 32);
        return seed;
    }

    using handler_fn = void(*)(vm_state_t& vm, const uint8_t* bc, uint32_t bc_size);

    struct handler_slot_t
    {
        handler_fn  fn;
        uint64_t    encrypted_next;
        uint64_t    decrypt_key;
        uint8_t     variant_id;
        bool        is_decrypted;
    };

    inline handler_slot_t g_handler_pool[HANDLER_POOL_SIZE] = {};
    inline uint32_t       g_active_slots = 0;
    inline uint64_t       g_pool_guard = 0;
    inline handler_fn     g_dispatch_table[256] = {};
    inline bool           g_poly_initialized = false;

    inline bool verify_handler_pool();
    inline void build_handler_pool(const uint8_t* reverse_map, uint64_t pool_seed);
    inline void build_poly_table();
    __forceinline handler_fn select_handler(vm_state_t& vm, uint8_t opcode);
    inline void init_vm(vm_state_t& vm, uint64_t seed);
    inline uint64_t vm_execute(vm_state_t& vm, const uint8_t* bytecode, uint32_t bc_size);
    inline void destroy_vm(vm_state_t& vm);

    inline uint64_t xorshift_advance(uint64_t& state)
    {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        return state;
    }

    inline void shuffle_registers(vm_state_t& vm)
    {
        uint64_t entropy = secure_seed() ^ vm.context_entropy;

        uint64_t old_xor = vm.reg_xor_key;
        for (int i = 0; i < 16; ++i)
            vm.regs[vm.reg_shuffle[i]] ^= old_xor;

        for (int i = 0; i < 16; ++i)
            vm.reg_shuffle[i] = static_cast<uint8_t>(i);

        uint64_t state = entropy;
        for (int i = 15; i > 0; --i)
        {
            xorshift_advance(state);
            int j = static_cast<int>(state % (i + 1));
            uint8_t tmp = vm.reg_shuffle[i];
            vm.reg_shuffle[i] = vm.reg_shuffle[j];
            vm.reg_shuffle[j] = tmp;
        }

        for (int i = 0; i < 16; ++i)
            vm.reg_unshuffle[vm.reg_shuffle[i]] = static_cast<uint8_t>(i);

        xorshift_advance(entropy);
        vm.reg_xor_key = entropy;
        vm.context_entropy = entropy;

        for (int i = 0; i < 16; ++i)
            vm.regs[vm.reg_shuffle[i]] ^= vm.reg_xor_key;

        vm.shuffle_counter = 0;
    }

    __forceinline uint64_t read_vreg(vm_state_t& vm, uint8_t logical)
    {
        return vm.regs[vm.reg_shuffle[logical & 0x0F]] ^ vm.reg_xor_key;
    }

    __forceinline void write_vreg(vm_state_t& vm, uint8_t logical, uint64_t val)
    {
        vm.regs[vm.reg_shuffle[logical & 0x0F]] = val ^ vm.reg_xor_key;
    }

    inline void generate_opcode_map(uint64_t seed, uint8_t* map, uint8_t* reverse)
    {
        for (int i = 0; i < 256; ++i)
            map[i] = static_cast<uint8_t>(i);

        uint64_t state = seed;
        for (int i = 255; i > 0; --i)
        {
            xorshift_advance(state);
            int j = static_cast<int>(state % (i + 1));
            uint8_t tmp = map[i];
            map[i] = map[j];
            map[j] = tmp;
        }

        for (int i = 0; i < 256; ++i)
            reverse[map[i]] = static_cast<uint8_t>(i);
    }

    inline void advance_rolling_key(vm_state_t& vm)
    {
        vm.rolling_key ^= vm.rolling_key << 13;
        vm.rolling_key ^= vm.rolling_key >> 7;
        vm.rolling_key ^= vm.rolling_key << 17;
    }

    inline uint8_t decrypt_byte(vm_state_t& vm, uint8_t raw)
    {
        uint8_t key_byte = static_cast<uint8_t>(vm.rolling_key & 0xFF);
        advance_rolling_key(vm);
        return raw ^ key_byte;
    }

    inline uint8_t fetch_byte(vm_state_t& vm, const uint8_t* bc, uint32_t bc_size)
    {
        if (vm.rip >= bc_size) { vm.halted = true; return 0; }
        return decrypt_byte(vm, bc[vm.rip++]);
    }

    inline uint64_t fetch_u64(vm_state_t& vm, const uint8_t* bc, uint32_t bc_size)
    {
        uint8_t buf[8];
        for (int i = 0; i < 8; ++i)
            buf[i] = fetch_byte(vm, bc, bc_size);
        uint64_t val;
        memcpy(&val, buf, 8);
        return val;
    }

    inline uint32_t fetch_u32(vm_state_t& vm, const uint8_t* bc, uint32_t bc_size)
    {
        uint8_t buf[4];
        for (int i = 0; i < 4; ++i)
            buf[i] = fetch_byte(vm, bc, bc_size);
        uint32_t val;
        memcpy(&val, buf, 4);
        return val;
    }

    __forceinline uint64_t nand_op(uint64_t a, uint64_t b) { return ~(a & b); }
    __forceinline uint64_t nor_op(uint64_t a, uint64_t b)  { return ~(a | b); }

    __forceinline uint64_t micro_add(uint64_t a, uint64_t b)
    {

        uint64_t sel = __rdtsc();
        if (sel & 2)
            return metamorphic::mba::keyed_add(a, b, sel);

        uint64_t carry;
        uint64_t result = a;
        uint64_t operand = b;
        for (int i = 0; i < 64; ++i)
        {
            carry = nand_op(nand_op(result, operand), nand_op(result, operand));
            carry = nand_op(~carry, ~carry);
            uint64_t xor_ab = nand_op(nand_op(result, nand_op(result, operand)),
                                       nand_op(operand, nand_op(result, operand)));
            result = xor_ab;
            operand = carry << 1;
            if (operand == 0) break;
        }
        return result;
    }

    __forceinline uint64_t micro_sub(uint64_t a, uint64_t b)
    {
        uint64_t sel = __rdtsc();
        if (sel & 4)
        {

            uint64_t neg_b = metamorphic::mba::keyed_add(~b, 1, sel);
            return metamorphic::mba::keyed_add(a, neg_b, sel ^ 0xDEAD);
        }
        return micro_add(a, micro_add(~b, 1));
    }

    __forceinline uint64_t micro_and(uint64_t a, uint64_t b)
    {
        uint64_t sel = __rdtsc();
        if (sel & 8)
            return metamorphic::mba::keyed_and(a, b, sel);
        return nand_op(nand_op(a, b), nand_op(a, b));
    }

    __forceinline uint64_t micro_or(uint64_t a, uint64_t b)
    {
        uint64_t sel = __rdtsc();
        if (sel & 16)
            return metamorphic::mba::keyed_or(a, b, sel);
        return nand_op(nand_op(a, a), nand_op(b, b));
    }

    __forceinline uint64_t micro_mul(uint64_t a, uint64_t b)
    {
        uint64_t result = 0;
        uint64_t multiplicand = a;
        uint64_t multiplier = b;
        while (multiplier != 0)
        {
            if (multiplier & 1)
                result = micro_add(result, multiplicand);
            multiplicand <<= 1;
            multiplier >>= 1;
        }
        return result;
    }

    __forceinline uint64_t micro_xor(uint64_t a, uint64_t b)
    {
        uint64_t sel = __rdtsc();
        if (sel & 32)
            return metamorphic::mba::keyed_xor(a, b, sel);
        uint64_t nand_ab = nand_op(a, b);
        return nand_op(nand_op(a, nand_ab), nand_op(b, nand_ab));
    }

    __forceinline uint8_t compute_parity(uint64_t val)
    {
        uint8_t low = static_cast<uint8_t>(val);
        low ^= low >> 4;
        low ^= low >> 2;
        low ^= low >> 1;
        return (~low) & 1;
    }

    __forceinline void update_flags_add(vm_state_t& vm, uint64_t a, uint64_t b, uint64_t result)
    {
        vm.vflags.CF = (result < a) ? 1 : 0;
        vm.vflags.ZF = (result == 0) ? 1 : 0;
        vm.vflags.SF = (result >> 63) & 1;
        vm.vflags.OF = (((a ^ result) & (b ^ result)) >> 63) & 1;
        vm.vflags.PF = compute_parity(result);
        vm.vflags.AF = (((a ^ b ^ result) >> 4) & 1);
    }

    __forceinline void update_flags_sub(vm_state_t& vm, uint64_t a, uint64_t b, uint64_t result)
    {
        vm.vflags.CF = (a < b) ? 1 : 0;
        vm.vflags.ZF = (result == 0) ? 1 : 0;
        vm.vflags.SF = (result >> 63) & 1;
        vm.vflags.OF = (((a ^ b) & (a ^ result)) >> 63) & 1;
        vm.vflags.PF = compute_parity(result);
        vm.vflags.AF = (((a ^ b ^ result) >> 4) & 1);
    }

    __forceinline void update_flags_logic(vm_state_t& vm, uint64_t result)
    {
        vm.vflags.CF = 0;
        vm.vflags.ZF = (result == 0) ? 1 : 0;
        vm.vflags.SF = (result >> 63) & 1;
        vm.vflags.OF = 0;
        vm.vflags.PF = compute_parity(result);
        vm.vflags.AF = 0;
    }

    __forceinline bool eval_condition(const vflags_t& f, uint8_t cc)
    {
        switch (cc & 0x0F)
        {
        case 0x00: return f.OF;
        case 0x01: return !f.OF;
        case 0x02: return f.CF;
        case 0x03: return !f.CF;
        case 0x04: return f.ZF;
        case 0x05: return !f.ZF;
        case 0x06: return f.CF || f.ZF;
        case 0x07: return !f.CF && !f.ZF;
        case 0x08: return f.SF;
        case 0x09: return !f.SF;
        case 0x0A: return f.PF;
        case 0x0B: return !f.PF;
        case 0x0C: return f.SF != f.OF;
        case 0x0D: return f.SF == f.OF;
        case 0x0E: return f.ZF || (f.SF != f.OF);
        case 0x0F: return !f.ZF && (f.SF == f.OF);
        default: return false;
        }
    }

    __forceinline uint64_t compute_handler_chain_addr(vm_state_t& vm, uint8_t opcode)
    {
        uint64_t chain = vm.handler_chain_key;
        chain ^= static_cast<uint64_t>(opcode) * 0x9E3779B97F4A7C15ULL;
        chain = _rotl64(chain, 13) ^ (chain >> 27);
        chain *= 0xBF58476D1CE4E5B9ULL;
        vm.handler_chain_key = chain;
        return chain;
    }


    __forceinline void derive_context_masks(vm_state_t& vm)
    {

        uint64_t seed = vm.handler_chain_key ^ secure_seed();
        seed ^= seed >> 30; seed *= 0xBF58476D1CE4E5B9ULL;
        seed ^= seed >> 27; seed *= 0x94D049BB133111EBULL;
        seed ^= seed >> 31;
        vm.ctx_crypt.reg_mask   = seed;
        vm.ctx_crypt.flags_mask = _rotl64(seed, 17) ^ 0x428A2F98D728AE22ULL;
        vm.ctx_crypt.rsp_mask   = _rotr64(seed, 23) ^ 0x7137449123EF65CDULL;
    }

    __forceinline void encrypt_context(vm_state_t& vm)
    {
        if (vm.ctx_crypt.encrypted) return;
        derive_context_masks(vm);
        for (int i = 0; i < 16; ++i)
            vm.regs[i] ^= _rotl64(vm.ctx_crypt.reg_mask, i * 4);
        uint8_t* fp = reinterpret_cast<uint8_t*>(&vm.vflags);
        *fp ^= static_cast<uint8_t>(vm.ctx_crypt.flags_mask & 0x3F);
        vm.rsp   ^= vm.ctx_crypt.rsp_mask;
        vm.ctx_crypt.encrypted = true;
    }

    __forceinline void decrypt_context(vm_state_t& vm)
    {
        if (!vm.ctx_crypt.encrypted) return;

        for (int i = 0; i < 16; ++i)
            vm.regs[i] ^= _rotl64(vm.ctx_crypt.reg_mask, i * 4);
        uint8_t* fp = reinterpret_cast<uint8_t*>(&vm.vflags);
        *fp ^= static_cast<uint8_t>(vm.ctx_crypt.flags_mask & 0x3F);
        vm.rsp   ^= vm.ctx_crypt.rsp_mask;
        vm.ctx_crypt.encrypted = false;
    }


    static constexpr uint32_t HANDLER_REGEN_INTERVAL = 512;
    static constexpr uint32_t VM_ANTIDEBUG_INTERVAL = 37;

    __forceinline bool vm_check_hardware_breakpoints(vm_state_t& vm)
    {
        uint64_t dr0 = 0, dr1 = 0, dr2 = 0, dr3 = 0, dr7 = 0;
        __try {
            CONTEXT ctx{};
            ctx.ContextFlags = 0x00100010;
            if (GetThreadContext(GetCurrentThread(), &ctx)) {
                dr0 = ctx.Dr0; dr1 = ctx.Dr1;
                dr2 = ctx.Dr2; dr3 = ctx.Dr3;
                dr7 = ctx.Dr7;
            }
        } __except (EXCEPTION_EXECUTE_HANDLER) {
            return true;
        }

        if ((dr7 & 0xFF) == 0 && dr0 == 0 && dr1 == 0 && dr2 == 0 && dr3 == 0)
            return false;

        uintptr_t pool_lo = reinterpret_cast<uintptr_t>(&g_handler_pool[0]);
        uintptr_t pool_hi = pool_lo + sizeof(g_handler_pool);
        uintptr_t dispatch_lo = reinterpret_cast<uintptr_t>(&g_dispatch_table[0]);
        uintptr_t dispatch_hi = dispatch_lo + sizeof(g_dispatch_table);

        auto in_range = [&](uint64_t addr) -> bool {
            if (addr == 0) return false;
            if (addr >= pool_lo && addr < pool_hi) return true;
            if (addr >= dispatch_lo && addr < dispatch_hi) return true;
            for (uint32_t i = 0; i < g_active_slots; ++i) {
                uintptr_t fn = reinterpret_cast<uintptr_t>(g_handler_pool[i].fn);
                if (addr >= fn && addr < fn + 256) return true;
            }
            return false;
        };

        if (in_range(dr0) || in_range(dr1) || in_range(dr2) || in_range(dr3)) {
            vm.rolling_key ^= 0xDEADDEADDEADDEADULL;
            vm.handler_chain_key = 0;
            for (int i = 0; i < 16; ++i) vm.regs[i] ^= __rdtsc();
            return true;
        }

        return (dr0 != 0 || dr1 != 0 || dr2 != 0 || dr3 != 0);
    }

    __forceinline void regenerate_handlers(vm_state_t& vm)
    {
        uint64_t new_seed = vm.rolling_key ^ vm.handler_chain_key ^ secure_seed();
        new_seed ^= vm.insn_count * 0x9E3779B97F4A7C15ULL;

        generate_opcode_map(new_seed, vm.opcode_map, vm.reverse_map);
        build_handler_pool(vm.reverse_map, new_seed ^ 0x428A2F98D728AE22ULL);

        if (g_poly_initialized) {
            g_poly_initialized = false;
            build_poly_table();
        }

        vm.context_entropy ^= new_seed;
    }


    __forceinline void dispatch_next(vm_state_t& vm, const uint8_t* bc, uint32_t bc_size)
    {

        encrypt_context(vm);

        if (vm.halted || vm.rip >= bc_size || vm.insn_count >= vm.max_insn)
            return;


        if ((vm.insn_count & 0xFF) == 0)
        {
            if (!verify_handler_pool())
            {
                decrypt_context(vm);
                write_vreg(vm, 0, 0xDEADBEEFDEADBEEFULL);
                vm.halted = true;
                return;
            }
        }

        if (vm.insn_count > 0 && (vm.insn_count % VM_ANTIDEBUG_INTERVAL) == 0)
        {
            decrypt_context(vm);
            if (vm_check_hardware_breakpoints(vm))
            {
                write_vreg(vm, 0, 0xDEADBEEFDEADBEEFULL);
                vm.halted = true;
                return;
            }
            encrypt_context(vm);
        }

        if (vm.insn_count > 0 && (vm.insn_count % HANDLER_REGEN_INTERVAL) == 0)
        {
            decrypt_context(vm);
            regenerate_handlers(vm);
            encrypt_context(vm);
        }


        ++vm.shuffle_counter;
        if (vm.shuffle_counter >= CONTEXT_SHUFFLE_INTERVAL)
        {
            decrypt_context(vm);
            shuffle_registers(vm);
            encrypt_context(vm);
        }


        decrypt_context(vm);

        uint8_t raw = bc[vm.rip];
        uint8_t decrypted = decrypt_byte(vm, raw);
        ++vm.rip;

        compute_handler_chain_addr(vm, decrypted);
        ++vm.insn_count;


        auto handler = g_poly_initialized ? select_handler(vm, decrypted) : g_dispatch_table[decrypted];
        handler(vm, bc, bc_size);
    }

#define VM_HANDLER(name) static void name(vm_state_t& vm, const uint8_t* bc, uint32_t bc_size)

    VM_HANDLER(h_nop) { (void)bc; (void)bc_size; dispatch_next(vm, bc, bc_size); }

    VM_HANDLER(h_load_imm)
    {
        uint8_t reg = fetch_byte(vm, bc, bc_size) & 0x0F;
        uint64_t val = fetch_u64(vm, bc, bc_size);
        write_vreg(vm, reg, val);
        dispatch_next(vm, bc, bc_size);
    }

    VM_HANDLER(h_load_reg)
    {
        uint8_t dst = fetch_byte(vm, bc, bc_size) & 0x0F;
        uint8_t src = fetch_byte(vm, bc, bc_size) & 0x0F;
        write_vreg(vm, dst, read_vreg(vm, src));
        dispatch_next(vm, bc, bc_size);
    }

    VM_HANDLER(h_store_reg)
    {
        uint8_t dst = fetch_byte(vm, bc, bc_size) & 0x0F;
        uint8_t src = fetch_byte(vm, bc, bc_size) & 0x0F;
        write_vreg(vm, dst, read_vreg(vm, src));
        dispatch_next(vm, bc, bc_size);
    }

    VM_HANDLER(h_nand)
    {
        uint8_t dst = fetch_byte(vm, bc, bc_size) & 0x0F;
        uint8_t a = fetch_byte(vm, bc, bc_size) & 0x0F;
        uint8_t b = fetch_byte(vm, bc, bc_size) & 0x0F;
        uint64_t va = read_vreg(vm, a);
        uint64_t vb = read_vreg(vm, b);
        uint64_t result = nand_op(va, vb);
        write_vreg(vm, dst, result);
        update_flags_logic(vm, result);
        dispatch_next(vm, bc, bc_size);
    }

    VM_HANDLER(h_nor)
    {
        uint8_t dst = fetch_byte(vm, bc, bc_size) & 0x0F;
        uint8_t a = fetch_byte(vm, bc, bc_size) & 0x0F;
        uint8_t b = fetch_byte(vm, bc, bc_size) & 0x0F;
        uint64_t va = read_vreg(vm, a);
        uint64_t vb = read_vreg(vm, b);
        uint64_t result = nor_op(va, vb);
        write_vreg(vm, dst, result);
        update_flags_logic(vm, result);
        dispatch_next(vm, bc, bc_size);
    }

    VM_HANDLER(h_xor)
    {
        uint8_t dst = fetch_byte(vm, bc, bc_size) & 0x0F;
        uint8_t a = fetch_byte(vm, bc, bc_size) & 0x0F;
        uint8_t b = fetch_byte(vm, bc, bc_size) & 0x0F;
        uint64_t va = read_vreg(vm, a);
        uint64_t vb = read_vreg(vm, b);
        uint64_t result = micro_xor(va, vb);
        write_vreg(vm, dst, result);
        update_flags_logic(vm, result);
        dispatch_next(vm, bc, bc_size);
    }

    VM_HANDLER(h_not)
    {
        uint8_t dst = fetch_byte(vm, bc, bc_size) & 0x0F;
        uint8_t src = fetch_byte(vm, bc, bc_size) & 0x0F;
        write_vreg(vm, dst, nand_op(read_vreg(vm, src), read_vreg(vm, src)));
        dispatch_next(vm, bc, bc_size);
    }

    VM_HANDLER(h_shl)
    {
        uint8_t dst = fetch_byte(vm, bc, bc_size) & 0x0F;
        uint8_t src = fetch_byte(vm, bc, bc_size) & 0x0F;
        uint8_t amt_reg = fetch_byte(vm, bc, bc_size) & 0x0F;
        uint64_t val = read_vreg(vm, src);
        uint8_t amt = static_cast<uint8_t>(read_vreg(vm, amt_reg)) & 0x3F;
        uint64_t result = val << amt;
        write_vreg(vm, dst, result);
        dispatch_next(vm, bc, bc_size);
    }

    VM_HANDLER(h_shr)
    {
        uint8_t dst = fetch_byte(vm, bc, bc_size) & 0x0F;
        uint8_t src = fetch_byte(vm, bc, bc_size) & 0x0F;
        uint8_t amt_reg = fetch_byte(vm, bc, bc_size) & 0x0F;
        uint64_t val = read_vreg(vm, src);
        uint8_t amt = static_cast<uint8_t>(read_vreg(vm, amt_reg)) & 0x3F;
        uint64_t result = val >> amt;
        write_vreg(vm, dst, result);
        dispatch_next(vm, bc, bc_size);
    }

    VM_HANDLER(h_rol)
    {
        uint8_t dst = fetch_byte(vm, bc, bc_size) & 0x0F;
        uint8_t src = fetch_byte(vm, bc, bc_size) & 0x0F;
        uint8_t amt_reg = fetch_byte(vm, bc, bc_size) & 0x0F;
        uint8_t amt = static_cast<uint8_t>(read_vreg(vm, amt_reg)) & 0x3F;
        write_vreg(vm, dst, _rotl64(read_vreg(vm, src), amt));
        dispatch_next(vm, bc, bc_size);
    }

    VM_HANDLER(h_ror)
    {
        uint8_t dst = fetch_byte(vm, bc, bc_size) & 0x0F;
        uint8_t src = fetch_byte(vm, bc, bc_size) & 0x0F;
        uint8_t amt_reg = fetch_byte(vm, bc, bc_size) & 0x0F;
        uint8_t amt = static_cast<uint8_t>(read_vreg(vm, amt_reg)) & 0x3F;
        write_vreg(vm, dst, _rotr64(read_vreg(vm, src), amt));
        dispatch_next(vm, bc, bc_size);
    }

    VM_HANDLER(h_cmp)
    {
        uint8_t a = fetch_byte(vm, bc, bc_size) & 0x0F;
        uint8_t b = fetch_byte(vm, bc, bc_size) & 0x0F;
        uint64_t va = read_vreg(vm, a);
        uint64_t vb = read_vreg(vm, b);
        uint64_t result = va - vb;
        update_flags_sub(vm, va, vb, result);
        dispatch_next(vm, bc, bc_size);
    }

    VM_HANDLER(h_jmp)
    {
        uint64_t saved_key = vm.rolling_key;
        uint32_t target = fetch_u32(vm, bc, bc_size);
        vm.rip = target;
        uint64_t block_key = saved_key ^ target;
        block_key ^= block_key >> 30;
        block_key *= 0xBF58476D1CE4E5B9ULL;
        block_key ^= block_key >> 27;
        block_key *= 0x94D049BB133111EBULL;
        block_key ^= block_key >> 31;
        vm.rolling_key = block_key;
        dispatch_next(vm, bc, bc_size);
    }

    VM_HANDLER(h_jz)
    {
        uint64_t saved_key = vm.rolling_key;
        uint32_t target = fetch_u32(vm, bc, bc_size);
        if (vm.vflags.ZF)
        {
            vm.rip = target;
            uint64_t block_key = saved_key ^ target;
            block_key ^= block_key >> 30;
            block_key *= 0xBF58476D1CE4E5B9ULL;
            block_key ^= block_key >> 27;
            block_key *= 0x94D049BB133111EBULL;
            block_key ^= block_key >> 31;
            vm.rolling_key = block_key;
        }
        dispatch_next(vm, bc, bc_size);
    }

    VM_HANDLER(h_jnz)
    {
        uint64_t saved_key = vm.rolling_key;
        uint32_t target = fetch_u32(vm, bc, bc_size);
        if (!vm.vflags.ZF)
        {
            vm.rip = target;
            uint64_t block_key = saved_key ^ target;
            block_key ^= block_key >> 30;
            block_key *= 0xBF58476D1CE4E5B9ULL;
            block_key ^= block_key >> 27;
            block_key *= 0x94D049BB133111EBULL;
            block_key ^= block_key >> 31;
            vm.rolling_key = block_key;
        }
        dispatch_next(vm, bc, bc_size);
    }

    VM_HANDLER(h_push)
    {
        uint8_t r = fetch_byte(vm, bc, bc_size) & 0x0F;
        if (vm.rsp < 8) { vm.halted = true; return; }
        vm.rsp -= 8;
        uint64_t val = read_vreg(vm, r);
        memcpy(vm.stack + vm.rsp, &val, 8);
        dispatch_next(vm, bc, bc_size);
    }

    VM_HANDLER(h_pop)
    {
        uint8_t r = fetch_byte(vm, bc, bc_size) & 0x0F;
        if (vm.rsp + 8 > vm.stack_size) { vm.halted = true; return; }
        uint64_t val;
        memcpy(&val, vm.stack + vm.rsp, 8);
        write_vreg(vm, r, val);
        vm.rsp += 8;
        dispatch_next(vm, bc, bc_size);
    }

    VM_HANDLER(h_rdtsc)
    {
        uint8_t r = fetch_byte(vm, bc, bc_size) & 0x0F;
        write_vreg(vm, r, __rdtsc());
        dispatch_next(vm, bc, bc_size);
    }

    VM_HANDLER(h_siphash)
    {
        uint8_t dst = fetch_byte(vm, bc, bc_size) & 0x0F;
        uint8_t src = fetch_byte(vm, bc, bc_size) & 0x0F;
        uint64_t vdst = read_vreg(vm, dst);
        uint64_t vsrc = read_vreg(vm, src);
        uint8_t buf[16];
        memcpy(buf, &vdst, 8);
        memcpy(buf + 8, &vsrc, 8);
        write_vreg(vm, dst, integrity::siphash::hash(
            buf, 16, vdst ^ 0x736970686173684BULL, vsrc ^ 0x646F72616E64311ULL));
        dispatch_next(vm, bc, bc_size);
    }

    VM_HANDLER(h_hash)
    {
        uint8_t dst = fetch_byte(vm, bc, bc_size) & 0x0F;
        uint8_t src = fetch_byte(vm, bc, bc_size) & 0x0F;
        uint64_t vdst = read_vreg(vm, dst);
        uint64_t vsrc = read_vreg(vm, src);
        vdst = micro_xor(vdst, vsrc);
        vdst = micro_mul(vdst, 0x100000001B3ULL);
        vdst ^= _rotl64(vdst, 27);
        write_vreg(vm, dst, vdst);
        dispatch_next(vm, bc, bc_size);
    }

    VM_HANDLER(h_verify)
    {
        uint8_t a = fetch_byte(vm, bc, bc_size) & 0x0F;
        uint8_t b = fetch_byte(vm, bc, bc_size) & 0x0F;
        if (read_vreg(vm, a) != read_vreg(vm, b))
        {
            write_vreg(vm, 0, 0xDEADBEEFDEADBEEFULL);
            vm.halted = true;
            return;
        }
        dispatch_next(vm, bc, bc_size);
    }


    VM_HANDLER(h_trap)
    {
        (void)bc; (void)bc_size;
        write_vreg(vm, 0, 0xDEADBEEFDEADBEEFULL);
        vm.halted = true;
    }

    VM_HANDLER(h_halt)
    {
        (void)bc; (void)bc_size;
        vm.halted = true;
    }

    VM_HANDLER(h_invalid)
    {
        (void)bc; (void)bc_size;
        write_vreg(vm, 0, 0xDEADBEEFDEADBEEFULL);
        vm.halted = true;
    }

    VM_HANDLER(h_add)
    {
        uint8_t dst = fetch_byte(vm, bc, bc_size) & 0x0F;
        uint8_t a = fetch_byte(vm, bc, bc_size) & 0x0F;
        uint8_t b = fetch_byte(vm, bc, bc_size) & 0x0F;
        uint64_t va = read_vreg(vm, a);
        uint64_t vb = read_vreg(vm, b);
        uint64_t result = micro_add(va, vb);
        write_vreg(vm, dst, result);
        update_flags_add(vm, va, vb, result);
        dispatch_next(vm, bc, bc_size);
    }

    VM_HANDLER(h_sub)
    {
        uint8_t dst = fetch_byte(vm, bc, bc_size) & 0x0F;
        uint8_t a = fetch_byte(vm, bc, bc_size) & 0x0F;
        uint8_t b = fetch_byte(vm, bc, bc_size) & 0x0F;
        uint64_t va = read_vreg(vm, a);
        uint64_t vb = read_vreg(vm, b);
        uint64_t result = micro_sub(va, vb);
        write_vreg(vm, dst, result);
        update_flags_sub(vm, va, vb, result);
        dispatch_next(vm, bc, bc_size);
    }


    VM_HANDLER(h_nand_v2)
    {
        uint8_t dst = fetch_byte(vm, bc, bc_size) & 0x0F;
        uint8_t a = fetch_byte(vm, bc, bc_size) & 0x0F;
        uint8_t b = fetch_byte(vm, bc, bc_size) & 0x0F;
        uint64_t va = read_vreg(vm, a);
        uint64_t vb = read_vreg(vm, b);
        uint64_t r = ~va;
        r = micro_or(r, ~vb);
        r = micro_xor(r, micro_and(~va, ~vb));
        r = nand_op(va, vb);
        write_vreg(vm, dst, r);
        update_flags_logic(vm, r);
        dispatch_next(vm, bc, bc_size);
    }

    VM_HANDLER(h_xor_v2)
    {
        uint8_t dst = fetch_byte(vm, bc, bc_size) & 0x0F;
        uint8_t a = fetch_byte(vm, bc, bc_size) & 0x0F;
        uint8_t b = fetch_byte(vm, bc, bc_size) & 0x0F;
        uint64_t va = read_vreg(vm, a);
        uint64_t vb = read_vreg(vm, b);
        uint64_t nand_ab = nand_op(va, vb);
        uint64_t r = nand_op(nand_op(va, nand_ab), nand_op(vb, nand_ab));
        write_vreg(vm, dst, r);
        update_flags_logic(vm, r);
        dispatch_next(vm, bc, bc_size);
    }

    VM_HANDLER(h_hash_v2)
    {
        uint8_t dst = fetch_byte(vm, bc, bc_size) & 0x0F;
        uint8_t src = fetch_byte(vm, bc, bc_size) & 0x0F;
        uint64_t vdst = read_vreg(vm, dst);
        uint64_t vsrc = read_vreg(vm, src);
        vdst ^= vsrc;
        vdst *= 0x100000001B3ULL;
        vdst = _rotl64(vdst, 31) ^ _rotr64(vdst, 17);
        write_vreg(vm, dst, vdst);
        dispatch_next(vm, bc, bc_size);
    }

    VM_HANDLER(h_cmp_v2)
    {
        uint8_t a = fetch_byte(vm, bc, bc_size) & 0x0F;
        uint8_t b = fetch_byte(vm, bc, bc_size) & 0x0F;
        uint64_t va = read_vreg(vm, a);
        uint64_t vb = read_vreg(vm, b);
        uint64_t result = va - vb;
        update_flags_sub(vm, va, vb, result);
        dispatch_next(vm, bc, bc_size);
    }

    VM_HANDLER(h_add_v3)
    {
        uint8_t dst = fetch_byte(vm, bc, bc_size) & 0x0F;
        uint8_t a = fetch_byte(vm, bc, bc_size) & 0x0F;
        uint8_t b = fetch_byte(vm, bc, bc_size) & 0x0F;
        uint64_t va = read_vreg(vm, a);
        uint64_t vb = read_vreg(vm, b);

        uint64_t xor_ab = micro_xor(va, vb);
        uint64_t and_ab = micro_and(va, vb);
        uint64_t result = micro_add(xor_ab, micro_add(and_ab, and_ab));
        write_vreg(vm, dst, result);
        update_flags_add(vm, va, vb, result);
        dispatch_next(vm, bc, bc_size);
    }

    VM_HANDLER(h_sub_v3)
    {
        uint8_t dst = fetch_byte(vm, bc, bc_size) & 0x0F;
        uint8_t a = fetch_byte(vm, bc, bc_size) & 0x0F;
        uint8_t b = fetch_byte(vm, bc, bc_size) & 0x0F;
        uint64_t va = read_vreg(vm, a);
        uint64_t vb = read_vreg(vm, b);

        uint64_t neg_b = nand_op(vb, vb);
        neg_b = micro_add(neg_b, 1);
        uint64_t result = micro_add(va, neg_b);
        write_vreg(vm, dst, result);
        update_flags_sub(vm, va, vb, result);
        dispatch_next(vm, bc, bc_size);
    }

    VM_HANDLER(h_xor_v3)
    {
        uint8_t dst = fetch_byte(vm, bc, bc_size) & 0x0F;
        uint8_t a = fetch_byte(vm, bc, bc_size) & 0x0F;
        uint8_t b = fetch_byte(vm, bc, bc_size) & 0x0F;
        uint64_t va = read_vreg(vm, a);
        uint64_t vb = read_vreg(vm, b);

        uint64_t or_ab  = micro_or(va, vb);
        uint64_t and_ab = micro_and(va, vb);
        uint64_t result = micro_sub(or_ab, and_ab);
        write_vreg(vm, dst, result);
        update_flags_logic(vm, result);
        dispatch_next(vm, bc, bc_size);
    }

    VM_HANDLER(h_nand_v3)
    {
        uint8_t dst = fetch_byte(vm, bc, bc_size) & 0x0F;
        uint8_t a = fetch_byte(vm, bc, bc_size) & 0x0F;
        uint8_t b = fetch_byte(vm, bc, bc_size) & 0x0F;
        uint64_t va = read_vreg(vm, a);
        uint64_t vb = read_vreg(vm, b);

        uint64_t na = nand_op(va, va);
        uint64_t nb = nand_op(vb, vb);
        uint64_t result = micro_or(na, nb);
        write_vreg(vm, dst, result);
        update_flags_logic(vm, result);
        dispatch_next(vm, bc, bc_size);
    }

    VM_HANDLER(h_load_mem_v2)
    {
        uint8_t dst = fetch_byte(vm, bc, bc_size) & 0x0F;
        uint8_t addr_reg = fetch_byte(vm, bc, bc_size) & 0x0F;
        uint64_t addr = read_vreg(vm, addr_reg);
        uint64_t val = 0;
        if (addr) memcpy(&val, reinterpret_cast<const void*>(static_cast<uintptr_t>(addr)), 8);

        write_vreg(vm, dst, val);
        dispatch_next(vm, bc, bc_size);
    }

    VM_HANDLER(h_shl_v2)
    {
        uint8_t dst = fetch_byte(vm, bc, bc_size) & 0x0F;
        uint8_t src = fetch_byte(vm, bc, bc_size) & 0x0F;
        uint8_t amt_reg = fetch_byte(vm, bc, bc_size) & 0x0F;
        uint64_t va = read_vreg(vm, src);
        uint8_t b = static_cast<uint8_t>(read_vreg(vm, amt_reg)) & 0x3F;

        for (uint8_t i = 0; i < b; ++i)
            va = micro_add(va, va);
        write_vreg(vm, dst, va);
        dispatch_next(vm, bc, bc_size);
    }

    VM_HANDLER(h_hash_v3)
    {
        uint8_t dst = fetch_byte(vm, bc, bc_size) & 0x0F;
        uint8_t src = fetch_byte(vm, bc, bc_size) & 0x0F;
        uint64_t vdst = read_vreg(vm, dst);
        uint64_t vsrc = read_vreg(vm, src);

        vdst ^= vsrc;
        vdst *= 0x01000193ULL;
        vdst = _rotl64(vdst, 13) ^ _rotr64(vdst, 29);
        vdst ^= vdst >> 16;
        write_vreg(vm, dst, vdst);
        dispatch_next(vm, bc, bc_size);
    }

    VM_HANDLER(h_shr_v2)
    {
        uint8_t dst = fetch_byte(vm, bc, bc_size) & 0x0F;
        uint8_t src = fetch_byte(vm, bc, bc_size) & 0x0F;
        uint8_t amt_reg = fetch_byte(vm, bc, bc_size) & 0x0F;
        uint64_t va = read_vreg(vm, src);
        uint8_t b = static_cast<uint8_t>(read_vreg(vm, amt_reg)) & 0x3F;
        uint64_t result = 0;
        for (int i = 63; i >= 0; --i) {
            uint64_t bit = (va >> i) & 1;
            int new_pos = i - static_cast<int>(b);
            if (new_pos >= 0)
                result |= (bit << new_pos);
        }
        write_vreg(vm, dst, result);
        update_flags_logic(vm, result);
        dispatch_next(vm, bc, bc_size);
    }

    VM_HANDLER(h_shr_v3)
    {
        uint8_t dst = fetch_byte(vm, bc, bc_size) & 0x0F;
        uint8_t src = fetch_byte(vm, bc, bc_size) & 0x0F;
        uint8_t amt_reg = fetch_byte(vm, bc, bc_size) & 0x0F;
        uint64_t va = read_vreg(vm, src);
        uint8_t b = static_cast<uint8_t>(read_vreg(vm, amt_reg)) & 0x3F;
        uint64_t mask = (b >= 64) ? 0 : (0xFFFFFFFFFFFFFFFFULL >> b);
        uint64_t result = (va >> b) & mask;
        write_vreg(vm, dst, result);
        update_flags_logic(vm, result);
        dispatch_next(vm, bc, bc_size);
    }

    VM_HANDLER(h_rol_v2)
    {
        uint8_t dst = fetch_byte(vm, bc, bc_size) & 0x0F;
        uint8_t src = fetch_byte(vm, bc, bc_size) & 0x0F;
        uint8_t amt_reg = fetch_byte(vm, bc, bc_size) & 0x0F;
        uint64_t va = read_vreg(vm, src);
        uint8_t b = static_cast<uint8_t>(read_vreg(vm, amt_reg)) & 0x3F;
        uint64_t left = va << b;
        uint64_t right = (b == 0) ? 0 : (va >> (64 - b));
        uint64_t result = micro_or(left, right);
        write_vreg(vm, dst, result);
        dispatch_next(vm, bc, bc_size);
    }

    VM_HANDLER(h_ror_v2)
    {
        uint8_t dst = fetch_byte(vm, bc, bc_size) & 0x0F;
        uint8_t src = fetch_byte(vm, bc, bc_size) & 0x0F;
        uint8_t amt_reg = fetch_byte(vm, bc, bc_size) & 0x0F;
        uint64_t va = read_vreg(vm, src);
        uint8_t b = static_cast<uint8_t>(read_vreg(vm, amt_reg)) & 0x3F;
        uint64_t right = va >> b;
        uint64_t left = (b == 0) ? 0 : (va << (64 - b));
        uint64_t result = micro_or(right, left);
        write_vreg(vm, dst, result);
        dispatch_next(vm, bc, bc_size);
    }

    VM_HANDLER(h_not_v2)
    {
        uint8_t dst = fetch_byte(vm, bc, bc_size) & 0x0F;
        uint8_t src = fetch_byte(vm, bc, bc_size) & 0x0F;
        uint64_t va = read_vreg(vm, src);
        uint64_t result = nand_op(va, va);
        write_vreg(vm, dst, result);
        update_flags_logic(vm, result);
        dispatch_next(vm, bc, bc_size);
    }

    VM_HANDLER(h_not_v3)
    {
        uint8_t dst = fetch_byte(vm, bc, bc_size) & 0x0F;
        uint8_t src = fetch_byte(vm, bc, bc_size) & 0x0F;
        uint64_t va = read_vreg(vm, src);
        uint64_t result = micro_xor(va, 0xFFFFFFFFFFFFFFFFULL);
        write_vreg(vm, dst, result);
        update_flags_logic(vm, result);
        dispatch_next(vm, bc, bc_size);
    }

    VM_HANDLER(h_mul_v2)
    {
        uint8_t a = fetch_byte(vm, bc, bc_size) & 0x0F;
        uint8_t b = fetch_byte(vm, bc, bc_size) & 0x0F;
        uint64_t va = read_vreg(vm, a);
        uint64_t vb = read_vreg(vm, b);
        uint64_t result = micro_mul(va, vb);
        write_vreg(vm, a, result);
        vm.vflags.ZF = (result == 0) ? 1 : 0;
        vm.vflags.SF = (result >> 63) & 1;
        vm.vflags.PF = compute_parity(result);
        dispatch_next(vm, bc, bc_size);
    }

    VM_HANDLER(h_push_v2)
    {
        uint8_t src = fetch_byte(vm, bc, bc_size) & 0x0F;
        uint64_t val = read_vreg(vm, src);
        if (vm.rsp < 8) { vm.halted = true; return; }
        vm.rsp = micro_sub(vm.rsp, 8);
        memcpy(vm.stack + vm.rsp, &val, 8);
        dispatch_next(vm, bc, bc_size);
    }

    VM_HANDLER(h_pop_v2)
    {
        uint8_t dst = fetch_byte(vm, bc, bc_size) & 0x0F;
        if (vm.rsp + 8 > vm.stack_size) { vm.halted = true; return; }
        uint64_t val;
        memcpy(&val, vm.stack + vm.rsp, 8);
        vm.rsp = micro_add(vm.rsp, 8);
        write_vreg(vm, dst, val);
        dispatch_next(vm, bc, bc_size);
    }

    VM_HANDLER(h_add_v2)
    {
        uint8_t dst = fetch_byte(vm, bc, bc_size) & 0x0F;
        uint8_t a = fetch_byte(vm, bc, bc_size) & 0x0F;
        uint8_t b = fetch_byte(vm, bc, bc_size) & 0x0F;
        uint64_t va = read_vreg(vm, a);
        uint64_t vb = read_vreg(vm, b);
        uint64_t result = micro_sub(va, micro_sub(0, vb));
        write_vreg(vm, dst, result);
        update_flags_add(vm, va, vb, result);
        dispatch_next(vm, bc, bc_size);
    }

    VM_HANDLER(h_sub_v2)
    {
        uint8_t dst = fetch_byte(vm, bc, bc_size) & 0x0F;
        uint8_t a = fetch_byte(vm, bc, bc_size) & 0x0F;
        uint8_t b = fetch_byte(vm, bc, bc_size) & 0x0F;
        uint64_t va = read_vreg(vm, a);
        uint64_t vb = read_vreg(vm, b);
        uint64_t not_b = nand_op(vb, vb);
        uint64_t one = micro_and(1ULL, 1ULL);
        uint64_t neg_b = micro_add(not_b, one);
        uint64_t xor_ab = micro_xor(va, neg_b);
        uint64_t and_ab = micro_and(va, neg_b);
        uint64_t result = micro_add(xor_ab, micro_add(and_ab, and_ab));
        write_vreg(vm, dst, result);
        update_flags_sub(vm, va, vb, result);
        dispatch_next(vm, bc, bc_size);
    }

    VM_HANDLER(h_store_mem_v2)
    {
        uint8_t src = fetch_byte(vm, bc, bc_size) & 0x0F;
        uint8_t addr_reg = fetch_byte(vm, bc, bc_size) & 0x0F;
        uint64_t addr = read_vreg(vm, addr_reg);
        uint64_t val = read_vreg(vm, src);
        if (addr) {
            volatile uint64_t guard = addr ^ vm.rolling_key;
            (void)guard;
            memcpy(reinterpret_cast<void*>(static_cast<uintptr_t>(addr)), &val, 8);
        }
        dispatch_next(vm, bc, bc_size);
    }

    VM_HANDLER(h_nor_v2)
    {
        uint8_t dst = fetch_byte(vm, bc, bc_size) & 0x0F;
        uint8_t a = fetch_byte(vm, bc, bc_size) & 0x0F;
        uint8_t b = fetch_byte(vm, bc, bc_size) & 0x0F;
        uint64_t va = read_vreg(vm, a);
        uint64_t vb = read_vreg(vm, b);
        uint64_t not_a = nand_op(va, va);
        uint64_t not_b = nand_op(vb, vb);
        uint64_t result = micro_and(not_a, not_b);
        write_vreg(vm, dst, result);
        update_flags_logic(vm, result);
        dispatch_next(vm, bc, bc_size);
    }

    VM_HANDLER(h_load_imm8)
    {
        uint8_t reg = fetch_byte(vm, bc, bc_size) & 0x0F;
        uint8_t val = fetch_byte(vm, bc, bc_size);
        uint64_t prev = read_vreg(vm, reg);
        write_vreg(vm, reg, (prev & 0xFFFFFFFFFFFFFF00ULL) | val);
        dispatch_next(vm, bc, bc_size);
    }

    VM_HANDLER(h_load_imm16)
    {
        uint8_t reg = fetch_byte(vm, bc, bc_size) & 0x0F;
        uint8_t lo = fetch_byte(vm, bc, bc_size);
        uint8_t hi = fetch_byte(vm, bc, bc_size);
        uint16_t val = static_cast<uint16_t>(lo) | (static_cast<uint16_t>(hi) << 8);
        uint64_t prev = read_vreg(vm, reg);
        write_vreg(vm, reg, (prev & 0xFFFFFFFFFFFF0000ULL) | val);
        dispatch_next(vm, bc, bc_size);
    }

    VM_HANDLER(h_load_imm32)
    {
        uint8_t reg = fetch_byte(vm, bc, bc_size) & 0x0F;
        uint32_t val = fetch_u32(vm, bc, bc_size);
        write_vreg(vm, reg, static_cast<uint64_t>(val));
        dispatch_next(vm, bc, bc_size);
    }

    VM_HANDLER(h_mul)
    {
        uint8_t a = fetch_byte(vm, bc, bc_size) & 0x0F;
        uint8_t b = fetch_byte(vm, bc, bc_size) & 0x0F;
        uint64_t va = read_vreg(vm, a);
        uint64_t vb = read_vreg(vm, b);
        uint64_t hi = 0;
        uint64_t lo = _umul128(va, vb, &hi);
        write_vreg(vm, a, lo);
        vm.vflags.CF = (hi != 0) ? 1 : 0;
        vm.vflags.OF = vm.vflags.CF;
        vm.vflags.ZF = (lo == 0) ? 1 : 0;
        vm.vflags.SF = (lo >> 63) & 1;
        vm.vflags.PF = compute_parity(lo);
        dispatch_next(vm, bc, bc_size);
    }

    VM_HANDLER(h_imul)
    {
        uint8_t a = fetch_byte(vm, bc, bc_size) & 0x0F;
        uint8_t b = fetch_byte(vm, bc, bc_size) & 0x0F;
        int64_t sa = static_cast<int64_t>(read_vreg(vm, a));
        int64_t sb = static_cast<int64_t>(read_vreg(vm, b));
        int64_t hi = 0;
        int64_t lo = _mul128(sa, sb, &hi);
        write_vreg(vm, a, static_cast<uint64_t>(lo));
        vm.vflags.CF = (hi != 0 && hi != -1) ? 1 : 0;
        vm.vflags.OF = vm.vflags.CF;
        vm.vflags.ZF = (lo == 0) ? 1 : 0;
        vm.vflags.SF = (static_cast<uint64_t>(lo) >> 63) & 1;
        vm.vflags.PF = compute_parity(static_cast<uint64_t>(lo));
        dispatch_next(vm, bc, bc_size);
    }

    VM_HANDLER(h_div)
    {
        uint8_t a = fetch_byte(vm, bc, bc_size) & 0x0F;
        uint8_t b = fetch_byte(vm, bc, bc_size) & 0x0F;
        uint64_t va = read_vreg(vm, a);
        uint64_t vb = read_vreg(vm, b);
        if (vb == 0) { vm.halted = true; write_vreg(vm, 0, 0xDEADBEEFDEADBEEFULL); return; }
        write_vreg(vm, a, va / vb);
        dispatch_next(vm, bc, bc_size);
    }

    VM_HANDLER(h_idiv)
    {
        uint8_t a = fetch_byte(vm, bc, bc_size) & 0x0F;
        uint8_t b = fetch_byte(vm, bc, bc_size) & 0x0F;
        int64_t sa = static_cast<int64_t>(read_vreg(vm, a));
        int64_t sb = static_cast<int64_t>(read_vreg(vm, b));
        if (sb == 0) { vm.halted = true; write_vreg(vm, 0, 0xDEADBEEFDEADBEEFULL); return; }
        write_vreg(vm, a, static_cast<uint64_t>(sa / sb));
        dispatch_next(vm, bc, bc_size);
    }

    VM_HANDLER(h_cmov)
    {
        uint8_t packed = fetch_byte(vm, bc, bc_size);
        uint8_t cc = (packed >> 4) & 0x0F;
        uint8_t dst = packed & 0x0F;
        uint8_t src = fetch_byte(vm, bc, bc_size) & 0x0F;
        if (eval_condition(vm.vflags, cc))
            write_vreg(vm, dst, read_vreg(vm, src));
        dispatch_next(vm, bc, bc_size);
    }

    VM_HANDLER(h_setcc)
    {
        uint8_t packed = fetch_byte(vm, bc, bc_size);
        uint8_t cc = (packed >> 4) & 0x0F;
        uint8_t dst = packed & 0x0F;
        write_vreg(vm, dst, eval_condition(vm.vflags, cc) ? 1ULL : 0ULL);
        dispatch_next(vm, bc, bc_size);
    }

    VM_HANDLER(h_vcall)
    {
        uint32_t target = fetch_u32(vm, bc, bc_size);
        if (vm.rsp < 8) { vm.halted = true; return; }
        vm.rsp -= 8;
        uint64_t ret_addr = vm.rip;
        memcpy(vm.stack + vm.rsp, &ret_addr, 8);
        uint64_t saved_key = vm.rolling_key;
        vm.rip = target;
        uint64_t block_key = saved_key ^ target;
        block_key ^= block_key >> 30;
        block_key *= 0xBF58476D1CE4E5B9ULL;
        block_key ^= block_key >> 27;
        block_key *= 0x94D049BB133111EBULL;
        block_key ^= block_key >> 31;
        vm.rolling_key = block_key;
        dispatch_next(vm, bc, bc_size);
    }

    VM_HANDLER(h_vret)
    {
        if (vm.rsp + 8 > vm.stack_size) { vm.halted = true; return; }
        uint64_t ret_addr;
        memcpy(&ret_addr, vm.stack + vm.rsp, 8);
        vm.rsp += 8;
        vm.rip = static_cast<uint32_t>(ret_addr);
        dispatch_next(vm, bc, bc_size);
    }

    __forceinline void branch_if(vm_state_t& vm, const uint8_t* bc, uint32_t bc_size, bool cond)
    {
        uint64_t saved_key = vm.rolling_key;
        uint32_t target = fetch_u32(vm, bc, bc_size);
        if (cond)
        {
            vm.rip = target;
            uint64_t block_key = saved_key ^ target;
            block_key ^= block_key >> 30;
            block_key *= 0xBF58476D1CE4E5B9ULL;
            block_key ^= block_key >> 27;
            block_key *= 0x94D049BB133111EBULL;
            block_key ^= block_key >> 31;
            vm.rolling_key = block_key;
        }
        dispatch_next(vm, bc, bc_size);
    }

    VM_HANDLER(h_jl)  { branch_if(vm, bc, bc_size, vm.vflags.SF != vm.vflags.OF); }
    VM_HANDLER(h_jle) { branch_if(vm, bc, bc_size, vm.vflags.ZF || (vm.vflags.SF != vm.vflags.OF)); }
    VM_HANDLER(h_jg)  { branch_if(vm, bc, bc_size, !vm.vflags.ZF && (vm.vflags.SF == vm.vflags.OF)); }
    VM_HANDLER(h_jge) { branch_if(vm, bc, bc_size, vm.vflags.SF == vm.vflags.OF); }
    VM_HANDLER(h_jb)  { branch_if(vm, bc, bc_size, vm.vflags.CF != 0); }
    VM_HANDLER(h_jbe) { branch_if(vm, bc, bc_size, vm.vflags.CF || vm.vflags.ZF); }
    VM_HANDLER(h_js)  { branch_if(vm, bc, bc_size, vm.vflags.SF != 0); }
    VM_HANDLER(h_jo)  { branch_if(vm, bc, bc_size, vm.vflags.OF != 0); }
    VM_HANDLER(h_jnb) { branch_if(vm, bc, bc_size, !vm.vflags.CF); }
    VM_HANDLER(h_jnbe){ branch_if(vm, bc, bc_size, !vm.vflags.CF && !vm.vflags.ZF); }

    VM_HANDLER(h_lahf)
    {
        uint8_t dst = fetch_byte(vm, bc, bc_size) & 0x0F;
        uint64_t packed = static_cast<uint64_t>(vm.vflags.CF)
                        | (static_cast<uint64_t>(vm.vflags.ZF) << 1)
                        | (static_cast<uint64_t>(vm.vflags.SF) << 2)
                        | (static_cast<uint64_t>(vm.vflags.OF) << 3)
                        | (static_cast<uint64_t>(vm.vflags.PF) << 4)
                        | (static_cast<uint64_t>(vm.vflags.AF) << 5);
        write_vreg(vm, dst, packed);
        dispatch_next(vm, bc, bc_size);
    }

    VM_HANDLER(h_sahf)
    {
        uint8_t src = fetch_byte(vm, bc, bc_size) & 0x0F;
        uint64_t packed = read_vreg(vm, src);
        vm.vflags.CF = (packed >> 0) & 1;
        vm.vflags.ZF = (packed >> 1) & 1;
        vm.vflags.SF = (packed >> 2) & 1;
        vm.vflags.OF = (packed >> 3) & 1;
        vm.vflags.PF = (packed >> 4) & 1;
        vm.vflags.AF = (packed >> 5) & 1;
        dispatch_next(vm, bc, bc_size);
    }


    static constexpr uint32_t MAX_VM_DEPTH = 3;
    inline thread_local uint32_t g_vm_depth = 0;

    VM_HANDLER(h_vm_enter)
    {
        if (g_vm_depth >= MAX_VM_DEPTH) {
            vm.halted = true;
            write_vreg(vm, 0, 0xDEADBEEFDEADBEEFULL);
            return;
        }

        uint32_t child_bc_offset = fetch_u32(vm, bc, bc_size);
        uint32_t child_bc_len    = fetch_u32(vm, bc, bc_size);

        if (child_bc_offset + child_bc_len > bc_size) {
            vm.halted = true;
            return;
        }

        uint64_t child_seed = vm.rolling_key ^ vm.handler_chain_key ^ secure_seed();

        vm_state_t child;
        init_vm(child, child_seed);

        for (int i = 0; i < 8; ++i)
            write_vreg(child, i, read_vreg(vm, i));

        g_vm_depth++;
        uint64_t result = vm_execute(child, bc + child_bc_offset, child_bc_len);
        g_vm_depth--;

        write_vreg(vm, 0, result);
        for (int i = 1; i < 4; ++i)
            write_vreg(vm, i, read_vreg(child, i));

        destroy_vm(child);
        dispatch_next(vm, bc, bc_size);
    }

    VM_HANDLER(h_vm_exit)
    {
        (void)bc; (void)bc_size;
        vm.halted = true;
    }


    __forceinline bool verify_environment(vm_state_t& vm)
    {
        uint64_t teb_pid = 0;
        __try {
            auto* teb = reinterpret_cast<uint8_t*>(__readgsqword(0x30));
            auto* peb = *reinterpret_cast<uint8_t**>(teb + 0x60);
            teb_pid = *reinterpret_cast<uint32_t*>(teb + 0x40);
        } __except (EXCEPTION_EXECUTE_HANDLER) {
            return false;
        }

        uint64_t expected_pid = vm.continuation.chain_nonce & 0xFFFFFFFF;
        if (expected_pid != 0 && teb_pid != expected_pid)
            return false;

        return true;
    }

    inline void bind_to_environment(vm_state_t& vm)
    {
        __try {
            auto* teb = reinterpret_cast<uint8_t*>(__readgsqword(0x30));
            uint32_t pid = *reinterpret_cast<uint32_t*>(teb + 0x40);
            vm.continuation.chain_nonce =
                (vm.continuation.chain_nonce & 0xFFFFFFFF00000000ULL) |
                static_cast<uint64_t>(pid);
        } __except (EXCEPTION_EXECUTE_HANDLER) {}
    }

    struct poly_dispatch_t
    {
        handler_fn variants[4];
        uint8_t    count;
    };

    inline poly_dispatch_t g_poly_table[256] = {};

    inline void build_poly_table()
    {
        for (int i = 0; i < 256; ++i) {
            g_poly_table[i].variants[0] = g_dispatch_table[i];
            g_poly_table[i].count = 1;
        }

        auto add_variant = [](uint8_t mapped_op, handler_fn alt) {
            auto& entry = g_poly_table[mapped_op];
            if (entry.count < 4) {
                entry.variants[entry.count] = alt;
                entry.count++;
            }
        };

        struct variant_pair_t { handler_fn base; handler_fn alt; };
        variant_pair_t pairs[] = {
            { h_nand,      h_nand_v2 },
            { h_nand,      h_nand_v3 },
            { h_xor,       h_xor_v2  },
            { h_xor,       h_xor_v3  },
            { h_hash,      h_hash_v2 },
            { h_hash,      h_hash_v3 },
            { h_cmp,       h_cmp_v2  },
            { h_add,       h_add_v2  },
            { h_add,       h_add_v3  },
            { h_sub,       h_sub_v2  },
            { h_sub,       h_sub_v3  },
            { h_shl,       h_shl_v2  },
            { h_shr,       h_shr_v2  },
            { h_shr,       h_shr_v3  },
            { h_rol,       h_rol_v2  },
            { h_ror,       h_ror_v2  },
            { h_not,       h_not_v2  },
            { h_not,       h_not_v3  },
            { h_nor,       h_nor_v2  },
            { h_mul,       h_mul_v2  },
            { h_push,      h_push_v2 },
            { h_pop,       h_pop_v2  },
            { h_load_mem_v2,  h_load_mem_v2 },
            { h_store_mem_v2, h_store_mem_v2 },
        };
        constexpr int num_pairs = sizeof(pairs) / sizeof(pairs[0]);

        for (int d = 0; d < 256; ++d) {
            if (g_dispatch_table[d] == h_invalid) continue;
            for (int p = 0; p < num_pairs; ++p) {
                if (g_dispatch_table[d] == pairs[p].base) {
                    add_variant(static_cast<uint8_t>(d), pairs[p].alt);
                }
            }
        }

        g_poly_initialized = true;
    }

    __forceinline handler_fn select_handler(vm_state_t& vm, uint8_t opcode)
    {
        if (!g_poly_initialized || !verify_environment(vm))
            return g_dispatch_table[opcode];

        auto& entry = g_poly_table[opcode];
        if (entry.count <= 1)
            return entry.variants[0];

        uint64_t sel = vm.rolling_key ^ vm.context_entropy ^ secure_seed();
        return entry.variants[sel % entry.count];
    }

#undef VM_HANDLER

    inline void build_handler_pool(const uint8_t* reverse_map, uint64_t pool_seed)
    {
        handler_fn base_handlers[OP_MAX] = {};
        base_handlers[OP_NOP]       = h_nop;
        base_handlers[OP_LOAD_IMM]  = h_load_imm;
        base_handlers[OP_LOAD_REG]  = h_load_reg;
        base_handlers[OP_STORE_REG] = h_store_reg;
        base_handlers[OP_NAND]      = h_nand;
        base_handlers[OP_NOR]       = h_nor;
        base_handlers[OP_XOR]       = h_xor;
        base_handlers[OP_SHL]       = h_shl;
        base_handlers[OP_SHR]       = h_shr;
        base_handlers[OP_NOT]       = h_not;
        base_handlers[OP_CMP]       = h_cmp;
        base_handlers[OP_JMP]       = h_jmp;
        base_handlers[OP_JZ]        = h_jz;
        base_handlers[OP_JNZ]       = h_jnz;
        base_handlers[OP_PUSH]      = h_push;
        base_handlers[OP_POP]       = h_pop;
        base_handlers[OP_HASH]      = h_hash;
        base_handlers[OP_RDTSC]     = h_rdtsc;
        base_handlers[OP_SIPHASH]   = h_siphash;
        base_handlers[OP_HALT]      = h_halt;
        base_handlers[OP_TRAP]      = h_trap;
        base_handlers[OP_VERIFY]    = h_verify;
        base_handlers[OP_ROL]       = h_rol;
        base_handlers[OP_ROR]       = h_ror;
        base_handlers[OP_ADD]       = h_add;
        base_handlers[OP_SUB]       = h_sub;
        base_handlers[OP_VM_ENTER]  = h_vm_enter;
        base_handlers[OP_VM_EXIT]   = h_vm_exit;
        base_handlers[OP_LOAD_IMM8]  = h_load_imm8;
        base_handlers[OP_LOAD_IMM16] = h_load_imm16;
        base_handlers[OP_LOAD_IMM32] = h_load_imm32;
        base_handlers[OP_MUL]       = h_mul;
        base_handlers[OP_IMUL]      = h_imul;
        base_handlers[OP_DIV]       = h_div;
        base_handlers[OP_IDIV]      = h_idiv;
        base_handlers[OP_CMOV]      = h_cmov;
        base_handlers[OP_SETCC]     = h_setcc;
        base_handlers[OP_VCALL]     = h_vcall;
        base_handlers[OP_VRET]      = h_vret;
        base_handlers[OP_JL]        = h_jl;
        base_handlers[OP_JLE]       = h_jle;
        base_handlers[OP_JG]        = h_jg;
        base_handlers[OP_JGE]       = h_jge;
        base_handlers[OP_JB]        = h_jb;
        base_handlers[OP_JBE]       = h_jbe;
        base_handlers[OP_JS]        = h_js;
        base_handlers[OP_JO]        = h_jo;
        base_handlers[OP_LAHF]      = h_lahf;
        base_handlers[OP_SAHF]      = h_sahf;
        base_handlers[OP_JNB]       = h_jnb;
        base_handlers[OP_JNBE]      = h_jnbe;

        handler_fn variant_table[] = {
            h_nand_v2, h_xor_v2, h_hash_v2, h_cmp_v2,
            h_nand_v3, h_xor_v3, h_hash_v3, h_cmp_v2,
            h_add_v3,  h_sub_v3, h_shl_v2,  h_load_mem_v2,
            h_shr_v2,  h_shr_v3, h_rol_v2,  h_ror_v2,
            h_not_v2,  h_not_v3, h_mul_v2,  h_push_v2,
            h_pop_v2,  h_add_v2, h_sub_v2,  h_store_mem_v2,
            h_nor_v2
        };
        uint8_t variant_ops[] = {
            OP_NAND, OP_XOR, OP_HASH, OP_CMP,
            OP_NAND, OP_XOR, OP_HASH, OP_CMP,
            OP_ADD,  OP_SUB, OP_SHL,  OP_LOAD_MEM,
            OP_SHR,  OP_SHR, OP_ROL,  OP_ROR,
            OP_NOT,  OP_NOT, OP_MUL,  OP_PUSH,
            OP_POP,  OP_ADD, OP_SUB,  OP_STORE_MEM,
            OP_NOR
        };
        constexpr int num_variants = sizeof(variant_ops) / sizeof(variant_ops[0]);

        uint64_t seed = pool_seed;
        g_active_slots = 0;

        for (int i = 0; i < 256; ++i)
            g_dispatch_table[i] = h_invalid;

        for (uint8_t op = 0; op < OP_MAX; ++op)
        {
            if (!base_handlers[op]) continue;

            uint8_t mapped = reverse_map[op];
            g_dispatch_table[mapped] = base_handlers[op];

            if (g_active_slots < HANDLER_POOL_SIZE)
            {
                auto& slot = g_handler_pool[g_active_slots];
                slot.fn = base_handlers[op];
                slot.variant_id = 0;
                xorshift_advance(seed);
                slot.decrypt_key = seed;
                slot.encrypted_next = 0;
                slot.is_decrypted = true;
                g_active_slots++;
            }

            for (int v = 0; v < num_variants; ++v)
            {
                if (variant_ops[v] == op && g_active_slots < HANDLER_POOL_SIZE)
                {
                    auto& slot = g_handler_pool[g_active_slots];
                    slot.fn = variant_table[v];
                    slot.variant_id = static_cast<uint8_t>(v + 1);
                    xorshift_advance(seed);
                    slot.decrypt_key = seed;
                    slot.encrypted_next = 0;
                    slot.is_decrypted = false;
                    g_active_slots++;
                }
            }
        }

        xorshift_advance(seed);
        for (uint32_t i = 0; i < g_active_slots; ++i)
        {
            uint32_t next_idx = (i + 1) % g_active_slots;
            uint64_t next_addr = reinterpret_cast<uint64_t>(g_handler_pool[next_idx].fn);
            g_handler_pool[i].encrypted_next = next_addr ^ g_handler_pool[i].decrypt_key ^ HANDLER_CRYPT_MAGIC;
        }

        uint64_t guard = 0;
        for (uint32_t i = 0; i < g_active_slots; ++i)
            guard ^= reinterpret_cast<uint64_t>(g_handler_pool[i].fn) * (i + 1);
        for (int i = 0; i < 256; ++i)
            guard ^= reinterpret_cast<uint64_t>(g_dispatch_table[i]) * (i + 1);
        g_pool_guard = guard;
    }

    inline bool verify_handler_pool()
    {
        uint64_t guard = 0;
        for (uint32_t i = 0; i < g_active_slots; ++i)
            guard ^= reinterpret_cast<uint64_t>(g_handler_pool[i].fn) * (i + 1);
        for (int i = 0; i < 256; ++i)
            guard ^= reinterpret_cast<uint64_t>(g_dispatch_table[i]) * (i + 1);
        return guard == g_pool_guard;
    }

    inline void init_vm(vm_state_t& vm, uint64_t seed)
    {
        memset(&vm, 0, sizeof(vm));
        vm.stack_size = 4096;
        vm.stack = new uint8_t[vm.stack_size];
        memset(vm.stack, 0, vm.stack_size);
        vm.rsp = vm.stack_size;
        vm.halted = false;
        vm.max_insn = 100000;
        vm.insn_count = 0;
        memset(&vm.vflags, 0, sizeof(vflags_t));
        vm.rolling_key = seed ^ 0x6A09E667F3BCC908ULL;
        vm.handler_chain_key = seed ^ 0xBB67AE8584CAA73BULL;
        vm.context_entropy = secure_seed() ^ seed;
        vm.shuffle_counter = 0;


        vm.continuation.next_handler = 0;
        vm.continuation.chain_nonce  = seed ^ 0x3C6EF372FE94F82BULL;
        vm.ctx_crypt.reg_mask   = 0;
        vm.ctx_crypt.flags_mask = 0;
        vm.ctx_crypt.rsp_mask   = 0;
        vm.ctx_crypt.encrypted  = false;

        for (int i = 0; i < 16; ++i)
        {
            vm.reg_shuffle[i] = static_cast<uint8_t>(i);
            vm.reg_unshuffle[i] = static_cast<uint8_t>(i);
        }
        vm.reg_xor_key = 0;

        generate_opcode_map(seed, vm.opcode_map, vm.reverse_map);
        build_handler_pool(vm.reverse_map, seed ^ 0x428A2F98D728AE22ULL);

        if (!g_poly_initialized)
            build_poly_table();

        bind_to_environment(vm);
        shuffle_registers(vm);
    }

    inline void destroy_vm(vm_state_t& vm)
    {
        if (vm.stack)
        {
            volatile uint8_t* vs = vm.stack;
            for (uint32_t i = 0; i < vm.stack_size; ++i)
                vs[i] = 0;
            delete[] vm.stack;
            vm.stack = nullptr;
        }
        volatile uint8_t* vr = reinterpret_cast<volatile uint8_t*>(vm.opcode_map);
        for (int i = 0; i < 256; ++i) vr[i] = 0;
        volatile uint8_t* vs = reinterpret_cast<volatile uint8_t*>(vm.reg_shuffle);
        for (int i = 0; i < 16; ++i) vs[i] = 0;
        vm.reg_xor_key = 0;
        vm.handler_chain_key = 0;
    }

    inline uint64_t vm_execute(vm_state_t& vm, const uint8_t* bytecode, uint32_t bc_size)
    {
        vm.rip = 0;
        vm.halted = false;
        vm.insn_count = 0;
        vm.ctx_crypt.encrypted = false;
        vm.ctx_crypt.reg_mask = 0;
        vm.ctx_crypt.flags_mask = 0;
        vm.ctx_crypt.rsp_mask = 0;


        dispatch_next(vm, bytecode, bc_size);


        decrypt_context(vm);

        return read_vreg(vm, 0);
    }

    inline void encrypt_bytecode(std::vector<uint8_t>& bc, uint64_t initial_key)
    {
        uint64_t key = initial_key ^ 0x6A09E667F3BCC908ULL;
        for (size_t i = 0; i < bc.size(); ++i)
        {
            uint8_t key_byte = static_cast<uint8_t>(key & 0xFF);
            bc[i] ^= key_byte;
            key ^= key << 13;
            key ^= key >> 7;
            key ^= key << 17;
        }
    }

}


namespace integrity_vm
{

    struct vm_check_t
    {
        detail::vm_state_t vm;
        std::vector<uint8_t> bytecode;
        uint64_t expected_result;
        uint64_t encryption_seed;
        bool initialized;
    };

    inline vm_check_t& get_checker()
    {
        static vm_check_t c{};
        return c;
    }

    inline void emit_encrypted(std::vector<uint8_t>& bc, uint8_t val)
    {
        bc.push_back(val);
    }

    inline void emit_load_imm(std::vector<uint8_t>& bc, uint8_t reg, uint64_t val)
    {
        emit_encrypted(bc, detail::OP_LOAD_IMM);
        emit_encrypted(bc, reg);
        uint8_t bytes[8];
        memcpy(bytes, &val, 8);
        for (int i = 0; i < 8; ++i)
            emit_encrypted(bc, bytes[i]);
    }

    inline void emit_op2(std::vector<uint8_t>& bc, uint8_t op, uint8_t a, uint8_t b)
    {
        emit_encrypted(bc, op);
        emit_encrypted(bc, a);
        emit_encrypted(bc, b);
    }

    inline void emit_op1(std::vector<uint8_t>& bc, uint8_t op, uint8_t a)
    {
        emit_encrypted(bc, op);
        emit_encrypted(bc, a);
    }

    inline bool build_integrity_check(uint64_t code_base, uint32_t code_size, uint64_t text_hash)
    {
        auto& c = get_checker();

        uint64_t seed = detail::secure_seed() ^ reinterpret_cast<uint64_t>(&c);
        c.encryption_seed = seed;
        detail::init_vm(c.vm, seed);
        c.bytecode.clear();

        auto& bc = c.bytecode;

        emit_load_imm(bc, 0, 0);
        emit_load_imm(bc, 1, code_base);
        emit_load_imm(bc, 2, static_cast<uint64_t>(code_size / 8));
        emit_load_imm(bc, 3, 0);
        emit_load_imm(bc, 4, 0xA5A5A5A5A5A5A5A5ULL);
        emit_load_imm(bc, 5, 8);

        uint32_t loop_start = static_cast<uint32_t>(bc.size());

        emit_op2(bc, detail::OP_CMP, 3, 2);
        uint32_t jz_pos = static_cast<uint32_t>(bc.size());
        emit_encrypted(bc, detail::OP_JZ);
        size_t jz_target_pos = bc.size();
        bc.push_back(0); bc.push_back(0); bc.push_back(0); bc.push_back(0);

        emit_load_imm(bc, 6, 0);
        emit_op2(bc, detail::OP_SIPHASH, 0, 6);

        emit_op2(bc, detail::OP_LOAD_REG, 7, 6);
        emit_op2(bc, detail::OP_XOR, 7, 4);
        emit_op2(bc, detail::OP_HASH, 0, 7);

        emit_load_imm(bc, 8, 1);
        emit_op2(bc, detail::OP_ADD, 3, 8);
        emit_op2(bc, detail::OP_ADD, 1, 5);

        emit_encrypted(bc, detail::OP_JMP);
        uint8_t ls_bytes[4];
        memcpy(ls_bytes, &loop_start, 4);
        for (int i = 0; i < 4; ++i) bc.push_back(ls_bytes[i]);

        uint32_t loop_end = static_cast<uint32_t>(bc.size());
        memcpy(bc.data() + jz_target_pos, &loop_end, 4);

        emit_encrypted(bc, detail::OP_HALT);

        detail::encrypt_bytecode(bc, seed);

        c.expected_result = text_hash;
        c.initialized = true;
        return true;
    }

    inline uint64_t run_check()
    {
        auto& c = get_checker();
        if (!c.initialized) return 0;

        memset(c.vm.regs, 0, sizeof(c.vm.regs));
        c.vm.rsp = c.vm.stack_size;
        c.vm.rip = 0;
        memset(&c.vm.vflags, 0, sizeof(detail::vflags_t));
        c.vm.halted = false;
        c.vm.insn_count = 0;
        c.vm.rolling_key = c.encryption_seed ^ 0x6A09E667F3BCC908ULL;

        return detail::vm_execute(c.vm, c.bytecode.data(),
            static_cast<uint32_t>(c.bytecode.size()));
    }

}


namespace opaque
{

    __forceinline uint64_t state_dependent_hash(uint64_t x)
    {
        uint8_t buf[8];
        memcpy(buf, &x, 8);
        return integrity::siphash::hash(buf, 8,
            x ^ 0x736970686173684BULL, x ^ 0x646F72616E64311ULL);
    }

    __forceinline bool predicate_always_true(uint64_t x)
    {
        uint64_t h = state_dependent_hash(x);


        constexpr uint64_t p = 257;
        uint64_t a = (h % (p - 1)) + 1;
        uint64_t exp = p - 1;
        uint64_t result = 1;
        uint64_t base = a % p;
        while (exp > 0)
        {
            if (exp & 1) result = (result * base) % p;
            base = (base * base) % p;
            exp >>= 1;
        }
        return result == 1;
    }

    __forceinline bool predicate_always_false(uint64_t x)
    {
        return !predicate_always_true(x);
    }

    __forceinline uint64_t opaque_constant(uint64_t val, uint64_t noise)
    {
        uint64_t h = state_dependent_hash(noise);
        uint64_t zero = h ^ h;
        return val + zero;
    }

    __forceinline uint64_t opaque_zero(uint64_t noise)
    {
        uint64_t h = state_dependent_hash(noise);
        return h ^ h;
    }

}


namespace junk
{

    inline __declspec(noinline) volatile int dead_computation_a(volatile int seed)
    {
        volatile int x = seed ^ 0x5A5A;
        for (volatile int i = 0; i < 1; ++i)
        {
            x = (x * 1103515245 + 12345) & 0x7FFFFFFF;
            x ^= x >> 16;
        }
        return x;
    }

    inline __declspec(noinline) volatile int dead_computation_b(volatile int seed)
    {
        volatile int x = seed;
        x = ((x << 13) ^ x) - (x >> 21);
        x = ((x << 5) ^ x) + (x >> 3);
        return x;
    }

    inline __declspec(noinline) void insert_junk_sled()
    {
        volatile int a = dead_computation_a(static_cast<int>(__rdtsc() & 0xFF));
        volatile int b = dead_computation_b(a);
        volatile int c = a ^ b;
        (void)c;
    }

}

inline uint64_t g_server_poly_seed = 0;

inline void reseed_from_server(uint64_t server_nonce)
{
    uint8_t nonce_hex[17];
    for (int i = 0; i < 8; ++i)
    {
        uint8_t nibble_hi = static_cast<uint8_t>((server_nonce >> (60 - i * 8)) & 0xF);
        uint8_t nibble_lo = static_cast<uint8_t>((server_nonce >> (56 - i * 8)) & 0xF);
        nonce_hex[i * 2]     = nibble_hi < 10 ? ('0' + nibble_hi) : ('a' + nibble_hi - 10);
        nonce_hex[i * 2 + 1] = nibble_lo < 10 ? ('0' + nibble_lo) : ('a' + nibble_lo - 10);
    }
    nonce_hex[16] = 0;

    const char prefix[] = "opcode_map|";
    uint8_t hmac_input[27];
    memcpy(hmac_input, prefix, 11);
    memcpy(hmac_input + 11, nonce_hex, 16);

    uint8_t key_seed[32];
    detail::bcrypt_random(key_seed, 32);

    uint8_t prk[32];
    detail::hmac_sha256(key_seed, 32, hmac_input, 27, prk);

    uint64_t derived[4];
    detail::hkdf_expand_sha256(prk, hmac_input, 27,
                                reinterpret_cast<uint8_t*>(derived), 32);

    g_server_poly_seed = derived[0] ^ derived[1];

    uint64_t opcode_seed = derived[2];
    uint64_t key_schedule = derived[3];

    auto& c = integrity_vm::get_checker();
    if (c.initialized)
    {
        c.encryption_seed = opcode_seed ^ key_schedule;
        c.vm.rolling_key = c.encryption_seed ^ 0x6A09E667F3BCC908ULL;
        c.vm.handler_chain_key = c.encryption_seed ^ 0xBB67AE8584CAA73BULL;
        c.vm.context_entropy = key_schedule ^ derived[0];

        detail::generate_opcode_map(c.encryption_seed, c.vm.opcode_map, c.vm.reverse_map);
        detail::build_handler_pool(c.vm.reverse_map,
            c.encryption_seed ^ 0x428A2F98D728AE22ULL);

        if (detail::g_poly_initialized)
        {
            detail::g_poly_initialized = false;
            detail::build_poly_table();
        }

        detail::shuffle_registers(c.vm);
    }

    SecureZeroMemory(key_seed, 32);
    SecureZeroMemory(prk, 32);
    SecureZeroMemory(derived, 32);
}


inline bool initialize(uint64_t code_base, uint32_t code_size, uint64_t text_hash)
{
    junk::insert_junk_sled();

    if (!integrity_vm::build_integrity_check(code_base, code_size, text_hash))
        return false;

    junk::insert_junk_sled();
    return true;
}

inline uint64_t run_vm_integrity_check()
{
    junk::insert_junk_sled();

    if (opaque::predicate_always_true(__rdtsc()))
    {
        return integrity_vm::run_check();
    }

    if (opaque::predicate_always_false(__rdtsc()))
    {
        __fastfail(0xDEAD);
    }

    return 0;
}

inline uint64_t get_expected_hash()
{
    return integrity_vm::get_checker().expected_result;
}


namespace protection {

    static constexpr uint32_t MAX_PROTECTED = 128;

    struct protected_func_t
    {
        uint64_t original_addr;
        uint32_t original_len;
        std::vector<uint8_t> bytecode;
        uint64_t vm_seed;
        void* trampoline;
        bool active;
    };

    struct protection_state_t
    {
        protected_func_t entries[MAX_PROTECTED];
        uint32_t count;
        void* trampoline_page;
        uint32_t trampoline_offset;
        bool initialized;
    };

    inline protection_state_t& get_state()
    {
        static protection_state_t s{};
        return s;
    }

    inline bool init_protection()
    {
        auto& s = get_state();
        if (s.initialized) return true;
        s.trampoline_page = VirtualAlloc(nullptr, 65536,
            MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
        if (!s.trampoline_page) return false;
        s.trampoline_offset = 0;
        s.count = 0;
        s.initialized = true;
        return true;
    }

    typedef uint64_t(*vm_entry_fn)(uint64_t, uint64_t, uint64_t, uint64_t);

    inline uint64_t vm_trampoline_execute(protected_func_t* entry,
                                          uint64_t arg0, uint64_t arg1,
                                          uint64_t arg2, uint64_t arg3)
    {
        detail::vm_state_t vm;
        detail::init_vm(vm, entry->vm_seed);
        detail::write_vreg(vm, 0, arg0);
        detail::write_vreg(vm, 1, arg1);
        detail::write_vreg(vm, 2, arg2);
        detail::write_vreg(vm, 3, arg3);
        return detail::vm_execute(vm, entry->bytecode.data(),
            static_cast<uint32_t>(entry->bytecode.size()));
    }

    inline bool protect_function(void* func, size_t func_len,
                                   const std::vector<uint8_t>& compiled_bytecode,
                                   uint64_t seed)
    {
        auto& s = get_state();
        if (!s.initialized) {
            if (!init_protection()) return false;
        }
        if (s.count >= MAX_PROTECTED) return false;
        if (compiled_bytecode.empty()) return false;

        uint64_t base_addr = reinterpret_cast<uint64_t>(func);

        auto& entry = s.entries[s.count];
        entry.original_addr = base_addr;
        entry.original_len = static_cast<uint32_t>(func_len);
        entry.vm_seed = seed;
        entry.bytecode = compiled_bytecode;

        auto* tramp = static_cast<uint8_t*>(s.trampoline_page) + s.trampoline_offset;
        entry.trampoline = tramp;

        uint64_t entry_ptr = reinterpret_cast<uint64_t>(&s.entries[s.count]);
        tramp[0] = 0x48; tramp[1] = 0xB9;
        memcpy(tramp + 2, &entry_ptr, 8);

        uint64_t exec_addr = reinterpret_cast<uint64_t>(&vm_trampoline_execute);
        tramp[10] = 0x48; tramp[11] = 0xBA;
        memcpy(tramp + 12, &exec_addr, 8);

        tramp[20] = 0xFF; tramp[21] = 0xE2;

        s.trampoline_offset += 32;

        DWORD old_prot;
        VirtualProtect(func, func_len > 14 ? func_len : 14,
            PAGE_EXECUTE_READWRITE, &old_prot);

        auto* target = static_cast<uint8_t*>(func);
        target[0] = 0xFF;
        target[1] = 0x25;
        *reinterpret_cast<uint32_t*>(target + 2) = 0;
        *reinterpret_cast<uint64_t*>(target + 6) = reinterpret_cast<uint64_t>(tramp);

        for (size_t i = 14; i < func_len && i < 64; ++i)
            target[i] = 0xCC;

        VirtualProtect(func, func_len > 14 ? func_len : 14, old_prot, &old_prot);

        entry.active = true;
        s.count++;
        return true;
    }

    inline void reencrypt_live_bytecode()
    {
        auto& s = get_state();
        for (uint32_t i = 0; i < s.count; ++i) {
            auto& entry = s.entries[i];
            if (!entry.active || entry.bytecode.empty()) continue;

            uint64_t old_key = entry.vm_seed ^ 0x6A09E667F3BCC908ULL;
            uint64_t new_seed = entry.vm_seed ^ detail::secure_seed() ^
                (static_cast<uint64_t>(i) * 0x9E3779B97F4A7C15ULL);

            std::vector<uint8_t> raw(entry.bytecode.size());
            uint64_t dk = old_key;
            for (size_t j = 0; j < entry.bytecode.size(); ++j) {
                uint8_t kb = static_cast<uint8_t>(dk & 0xFF);
                dk ^= dk << 13; dk ^= dk >> 7; dk ^= dk << 17;
                raw[j] = entry.bytecode[j] ^ kb;
            }

            entry.vm_seed = new_seed;
            uint64_t new_key = new_seed ^ 0x6A09E667F3BCC908ULL;
            uint64_t ek = new_key;
            for (size_t j = 0; j < raw.size(); ++j) {
                uint8_t kb = static_cast<uint8_t>(ek & 0xFF);
                ek ^= ek << 13; ek ^= ek >> 7; ek ^= ek << 17;
                entry.bytecode[j] = raw[j] ^ kb;
            }

            volatile uint8_t* vraw = raw.data();
            for (size_t j = 0; j < raw.size(); ++j) vraw[j] = 0;
        }
    }

}

}

}
